/* Original minimal NSO header and ABI-preserving hook forwarding stubs. MIT. */
.section .text.header,"ax"
.global module_start
module_start:
    ret
    .word mod0 - module_start

.section .rodata.mod0,"a"
.balign 4
mod0:
    .ascii "MOD0"
    .word _DYNAMIC - mod0
    .word __bss_start - mod0
    .word __bss_end - mod0
    .word 0
    .word 0
    .word runtime_object - mod0

.section .bss,"aw",%nobits
.balign 8
runtime_object:
    .skip 0xD0

.section .text,"ax"
.global forward_add
.hidden original_add_tail
forward_add:
    sub sp,sp,#0x50
    str x23,[sp,#0x10]
    stp x22,x21,[sp,#0x20]
    stp x20,x19,[sp,#0x30]
    adrp x16,original_add_tail
    ldr x16,[x16,:lo12:original_add_tail]
    br x16

.global forward_frame
.hidden original_frame_tail
forward_frame:
    sub sp,sp,#0x70
    str d8,[sp,#0x10]
    str x27,[sp,#0x18]
    stp x26,x25,[sp,#0x20]
    adrp x16,original_frame_tail
    ldr x16,[x16,:lo12:original_frame_tail]
    br x16

.global forward_has
.hidden original_has_tail
forward_has:
    sub sp,sp,#0x30
    stp x20,x19,[sp,#0x10]
    stp x29,x30,[sp,#0x20]
    add x29,sp,#0x20
    adrp x16,original_has_tail
    ldr x16,[x16,:lo12:original_has_tail]
    br x16

.global forward_factory
.hidden original_factory_tail
forward_factory:
    stp x28,x27,[sp,#-0x60]!
    stp x26,x25,[sp,#0x10]
    stp x24,x23,[sp,#0x20]
    stp x22,x21,[sp,#0x30]
    adrp x16,original_factory_tail
    ldr x16,[x16,:lo12:original_factory_tail]
    br x16

.global forward_world_npc
.hidden original_world_npc_tail
forward_world_npc:
    sub sp,sp,#0x40
    stp xzr,x21,[sp,#8]
    stp x20,x19,[sp,#0x20]
    stp x29,x30,[sp,#0x30]
    adrp x16,original_world_npc_tail
    ldr x16,[x16,:lo12:original_world_npc_tail]
    br x16
