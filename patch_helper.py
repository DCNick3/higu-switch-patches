#!/usr/bin/env python3

import sys
import struct
import re
import tempfile
import subprocess
import itertools
import time
import shutil

from pprint import pprint
from os import path

TOOLCHAIN = 'aarch64-linux-gnu-'
AS = TOOLCHAIN + 'as'
LD = TOOLCHAIN + 'ld'
OBJDUMP = TOOLCHAIN + 'objdump'
OBJCOPY = TOOLCHAIN + 'objcopy'

def u32(b):
    return struct.unpack('<I', b)[0]

FLAGS = ['TextCompress', 'RoCompress', 'DataCompress', 'TextHash', 'RoHash', 'DataHash']

def is_inside_mem(section, start, size):
    return section['mem_offset'] < start and section['mem_offset'] + section['size'] >= start + size
def is_inside_file(section, start, size):
    return section['file_offset'] < start and section['file_offset'] + section['size'] >= start + size
def single(c):
    c = list(c)
    assert len(c) == 1
    return c[0]
def read_bytes(filename):
    with open(filename, 'rb') as f:
        return f.read()

class NsoFile:
    def __init__(self, nso_filename):
        self.nso_file = open(nso_filename, 'rb')

        self.nso_header = self.nso_file.read(0x100)
        assert self.nso_header[:4] == b'NSO0'
        flags = self.head_u32(0xc)
        self.flags = set(x for i, x in enumerate(FLAGS) if (flags & (1 << i)) != 0)
    
        self.module_name_offset = self.head_u32(0x1c)
        self.module_name_size = self.head_u32(0x2c)

        self.text = self.head_section(0x10)
        self.rodata = self.head_section(0x20)
        self.data = self.head_section(0x30)

        self.sections = [self.text, self.rodata, self.data]

    def head_u32(self, offset):
        return u32(self.nso_header[offset:offset+4])
    def head_section(self, offset):
        file_offset, mem_offset, size = struct.unpack('<III', self.nso_header[offset:offset+12])
        return {'file_offset':file_offset, 'mem_offset':mem_offset, 'size':size}

    def print_section_map(self):
        for x, nm in zip(self.sections, ['.text', '.rodata', '.data']):
            print('%09s: %06x-%06x -> %06x-%06x' % (nm, x['file_offset'], x['file_offset'] + x['size'], x['mem_offset'], x['mem_offset'] + x['size']))

    def mem_region_to_file(self, start, size):
        s = single(filter(lambda x: is_inside_mem(x, start, size), self.sections))
        return s['file_offset'] + start - s['mem_offset'], size

    def file_region_to_mem(self, start, size):
        s = single(filter(lambda x: is_inside_mem(x, start, size), self.sections))
        return s['mem_offset'] + start - s['file_offset'], size

    def read_section(self, sec, offset, size): # TODO: compression?
        assert sec['size'] >= offset + size
        file_offset = sec['file_offset'] + offset
        self.nso_file.seek(file_offset)
        return self.nso_file.read(size)

    def read_mem(self, offset, size):
        offset, size = self.mem_region_to_file(offset, size)
        self.nso_file.seek(offset)
        return self.nso_file.read(size)

    def get_module_info(self):
        module_path_data_size = 0x208
        module_path_data = self.read_section(self.rodata, 0, module_path_data_size)
        assert u32(module_path_data[:4]) == 0
        module_path_length = u32(module_path_data[4:8])
        module_path = str(module_path_data[8:8+module_path_length], 'utf8')
        module_name = module_path.split('\\')[-1].split('/')[-1]
        return (module_path, module_name)

    def get_buildid(self):
        rodata_end = self.read_section(self.rodata, self.rodata['size'] - 0x2000, 0x2000)
        offset = -1
        for x in range(0, 0x2000 - 4):
            if rodata_end[x:x+4] == b'GNU\x00':
                offset = x
                break
        else:
            raise RuntimeError("Can't find 'GNU\\x00' signature")
        buildid = rodata_end[offset+4:offset+4+0x20].hex()
        if len(buildid) < 0x40:
            return buildid + '0' * (0x40 - len(buildid))
        return buildid

WPF_LINE_REGEX = re.compile(
        r"^([0-9a-fA-F]*)\s*:\s*((\.\.\.)|((\?\?)+)|(([0-9a-fA-F]{2})+))\s*->\s*((\/([^\/]*)\/)|(b@([^\s]+))|(s@([^\s]+))|(\"(\\.|[^\"\\])*\")|(([0-9a-fA-F]{2})+))$"
    )

class WpfFile:
    labels = dict()
    sections = []
    base = None
    buildid = None
    def __init__(self, contents, base_directory):
        contents = [ x.strip() for x in contents.split('\n') if len(x.strip()) > 0 ]
        vars = []
        acts = []
        for i, x in enumerate(contents):
            if x[0].isdigit():
                vars = contents[:i]
                acts = contents[i:]
                break
        self.base_dir = base_directory
        self.parse_vars(vars)
        self.parse_act(acts)
    def parse_vars(self, vars):
        for x in vars:
            lval, rval = x.split('=', 1)
            lval = lval.strip()
            rval = rval.strip()
            if lval == 'buildid':
                self.buildid = rval
            elif lval == 'base':
                self.base = int(rval, 16)
            elif lval[0] == '@':
                self.labels[lval[1:]] = int(rval, 16)
            else:
                raise RuntimeError('unknown var: ' + lval)
        if self.base == None:
            raise RuntimeError('base is not defined')
        if self.buildid == None:
            raise RuntimeError('buildid is not defined')
    def parse_act(self, acts):
        section = None
        for x in acts:
            m = WPF_LINE_REGEX.match(x)
            if not m:
                raise RuntimeError('syntactic error in "' + x + '"')
            addr = m.group(1)
            lpart = None
            if m.group(3):
                lpart = None
            elif m.group(4):
                lpart = len(m.group(4)) // 2
            elif m.group(6):
                lpart = bytes.fromhex(m.group(6))
            else:
                raise RuntimeError("Eeeh?")
            rpart = None
            if m.group(10):
                rpart = ('asm', m.group(10))
            elif m.group(12):
                rpart = ('bfile', path.normpath(path.join(self.base_dir, m.group(12))))
            elif m.group(14):
                rpart = ('sfile', path.normpath(path.join(self.base_dir, m.group(14))))
            elif m.group(15):
                rpart = ('bytes', bytes(eval(m.group(15)), 'utf8'))
            elif m.group(17):
                rpart = ('bytes', bytes.fromhex(m.group(17)))
            else:
                raise RuntimeError("Eeeh?")
            if addr == '':
                section[1].append((lpart, rpart))
            else:
                if section != None:
                    self.sections.append(section)
                section = (int(addr, 16), [ (lpart, rpart) ])
    def make_link_script(self):
        res = "SECTIONS {\n"
        res += '  start = 0x0;'
        for x in self.labels:
            res += '  %s = 0x%x;\n' % (x, self.labels[x])
        for i, x in enumerate(self.sections):
            #res += '. = 0x%x;\n' % x[0]
            res += '  .sect%d 0x%x : { *(.sect%d) }\n' % (i, x[0], i)
        res += '}\n'
        return res
    def make_asm(self):
        res = ""
        for i, x in enumerate(self.sections):
            res += '.section .sect%d\n' % i
            for l, r in x[1]:
                t, arg = r
                if t == 'bytes':
                    res += '.byte %s\n' % ','.join(map(str, arg))
                elif t == 'asm':
                    res += arg + '\n'
                elif t == 'bfile':
                    res += '.incbin "%s"\n' % arg
                elif t == 'sfile':
                    res += '.include "%s"\n' % arg
                else:
                    raise RuntimeError("Eeeh?")
        return res
    def checklen(self, section, hunk_len):
        total_len = 0
        for lval, rval in section[1]:
            if lval == None:
                return
            if type(lval) == bytes:
                lval = len(lval)
            assert type(lval) == int
            total_len += lval
        if total_len != hunk_len:
            raise RuntimeError
    def to_hunkset(self, elfname=None):
        link_script = self.make_link_script()
        asm = self.make_asm()

        with tempfile.TemporaryDirectory() as dir:
            with open(dir + '/inj.ld', 'w') as f:
                f.write(link_script)
            with open(dir + '/inj.s', 'w') as f:
                f.write(asm)
            subprocess.check_call([AS, dir + '/inj.s', '-o', dir + '/inj.o'])
            subprocess.check_call([LD, '-T', dir + '/inj.ld', dir + '/inj.o', '-o', dir + '/inj.elf'])
            subprocess.check_call([OBJCOPY, dir + '/inj.elf'] + list(itertools.chain.from_iterable([ ['--dump-section', '.sect%d=%s/sect%d.bin' % (i, dir, i) ] for i in range(0, len(self.sections)) ])))
            hunks = [ (x[0], read_bytes('%s/sect%d.bin' % (dir, i))) for i, x in enumerate(self.sections) ]
            for h, s in zip(hunks, self.sections):
                self.checklen(s, len(h[1]))
            if elfname != None:
                shutil.copy(dir + '/inj.elf', elfname)
        return hunks
            
        
def dif_to_wpf(dif_patch):
    dif_patch = dif_patch.split('\n')
    assert dif_patch[0] == 'This difference file was created by IDA'
    assert dif_patch[1] == ''
    assert False
def ips32_to_wpf(nso, ips32_patch):
    assert ips32_patch[:5] == b'IPS32'
    ips32_patch = ips32_patch[5:]
    wpf = 'buildid=' + nso.get_buildid() + '\n'
    wpf += 'base=0x0\n'
    while not ips32_patch[:4] == b"EEOF":
        offset, size = struct.unpack('>IH', ips32_patch[:6])
        data = ips32_patch[6:6+size]
        offset, size = nso.file_region_to_mem(offset, size)
        orig_data = nso.read_mem(offset, size)
        #print(hex(offset), size)
        wpf += '%06x: %s -> %s\n' % (offset, orig_data.hex(), data.hex())
        ips32_patch=ips32_patch[6+size:]
    return wpf

def wpf_to_ips(nso, wpf, base_directory, elfname=None):
    wpf = WpfFile(wpf, base_directory)
    assert wpf.buildid == nso.get_buildid()

    # TODO: check left parts of actions against NSO (now it just ignores original bytes =))

    hunks = wpf.to_hunkset(elfname)

    ips = b'IPS32'

    for addr, data in hunks:
        addr, size = nso.mem_region_to_file(addr - wpf.base, len(data))
        assert addr != 0x45454f46 # TODO: implement workaround for the 'EOF' problem # https://github.com/leoetlino/sips/blob/5a896996251066820a09eac8d717be902871e54e/sips.cpp#L99
        ips += struct.pack('>IH', addr, size)
        ips += data
    ips += b'EEOF'
    return ips

    #pprint(hunks)


def cmd_load_nso(nso_filename):
    nso = NsoFile(nso_filename)

    #module_path, module_name = nso.get_module_info()
    #print('module_name =', module_name)
    #print('flags =', nso.flags)
    #nso.print_section_map()

    #build_id = nso.get_buildid()
    #print('build_id =', build_id)
    return nso
    

def cmd_ips_to_wpf(args):
    nso = cmd_load_nso(args[0])
    ips_filename = args[1]
    wpf_filename = args[2]

    with open(ips_filename, 'rb') as f:
        ips_patch = f.read()
    wpf = ips32_to_wpf(nso, ips_patch)
    with open(wpf_filename, 'w') as f:
        f.write(wpf)

def cmd_wpf_to_ips(args):
    nso = cmd_load_nso(args[0])
    wpf_filename = args[1]
    ips_dirname = args[2]
    base_dir = args[3]
    
    assert len([ x for x in nso.flags if 'Compress' in x ]) == 0, "executable is compressed"
    
    with open(wpf_filename, 'r') as f:
        wpf = f.read()
    ips = wpf_to_ips(nso, wpf, args[3], ips_dirname + '/patch.elf')
    with open(ips_dirname + '/' + nso.get_buildid() + '.ips', 'wb') as f:
        f.write(ips)

#cmd_ips_to_wpf(sys.argv[1:])
cmd_wpf_to_ips(sys.argv[1:])
