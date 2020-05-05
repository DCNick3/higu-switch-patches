
# input:
#   x0 - DEBUGOUT*
debug_out:
    # set pointer to DEBUGOUT_param
    add x1, x0, #0x18
    
    ldr x0, [x1]

    mov x2, #0
more:
    ldrb w3, [x0]
    add x2, x2, 1
    add x0, x0, 1
    cbnz w3, more
    
insert_debutout_breakpoint_here:
    nop
  
    mov w0, #1 
    ret
