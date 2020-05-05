 
# Overview

Contains debug patches for Higurashi no Naku Koro ni visual novel released for Nintendo Switch.

Most of them are aided to ease the development of modifications for game. See `higu_debug_patchset.wps` for concrete things the patchset does. See `higu_patchset` directory for already compiled patches

# Build

This project uses a custom build system for patches for ease of maintaince. To build patches usable for the actual game you would need an actual game's files and a Linux environment. WSL or cygwin migh work, but not supported.

Build system requires a working set of [binutils](https://www.gnu.org/software/binutils/) for `aarch64`. The code assumes `aarch64-linux-gnu`, but other flavours should work too. Change the `TOOLCHAIN` variable in `patch_helper.py` for this.

Along with binutils, a c preprocessor (`cpp`) and `python3` are needed.

You will also need a game's uncompressed executable file. For this you would require game files along with custom firmware installed on your switch. Here's a summary on how to get it:

- Somehow dump the update program nca for the game (Title id - `0100F6A00A684000`, NcaId - `e739d24e6ec4d3e4cee8f8a215fd38b7`, sha1sum - `fd5464f0a093a4a6e4141cb5d34fdd535f1eabb5`)

- Get the titlekey to decrypt the game files (for example using [lockpick](https://github.com/shchmue/Lockpick))

- Extract exefs files from it (i. e. using [hactool](https://github.com/SciresM/hactool): `hactool e739d24e6ec4d3e4cee8f8a215fd38b7.nca --titlekey=[INSERT_TITLE_KEY_HERE] --exefsdir=exefs`)

- Get the `main` file from exefs (buildid - `0C28B121BAC7801C3DCFF93B81820BFA00000000000000000000000000000000`, sha1sum - `672183daf5438e8fe0a6986813188de30c3152b7`) and make an uncompressed version of it (i. e. `hactool -t nso main --uncompressed=main_uncompressed`)

- Put the uncompressed file to this directory with the name `main_uncompressed`

Then run `build.sh`. This should build a patchset (and output nothing on success).

# Usage

To use those patches you would need a game on your switch and an [Atmosphère](https://github.com/Atmosphere-NX/Atmosphere) custom firmware installed.

Put the `higu_patchset` directory into `/atmosphere/exefs_patches` on your switch's sd card.

