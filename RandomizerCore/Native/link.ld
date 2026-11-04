OUTPUT_FORMAT(elf64-littleaarch64)
OUTPUT_ARCH(aarch64)
ENTRY(module_start)
PHDRS {
  text PT_LOAD FLAGS(5);
  rodata PT_LOAD FLAGS(4);
  data PT_LOAD FLAGS(6);
  dynamic PT_DYNAMIC FLAGS(6);
}
SECTIONS {
  . = 0;
  .text : { KEEP(*(.text.header)) *(.text .text.*) } :text
  .plt : { *(.plt .plt.*) } :text
  . = ALIGN(0x1000);
  .rodata : { *(.rodata .rodata.*) } :rodata
  .hash : { *(.hash) } :rodata
  .gnu.hash : { *(.gnu.hash) } :rodata
  .dynsym : { *(.dynsym) } :rodata
  .dynstr : { *(.dynstr) } :rodata
  .rela.dyn : { *(.rela.dyn) } :rodata
  .rela.plt : { *(.rela.plt) } :rodata
  .note.gnu.build-id : { *(.note.gnu.build-id) } :rodata
  . = ALIGN(0x1000);
  .data : { *(.data .data.*) *(.data.rel.ro .data.rel.ro.*) } :data
  .got : { *(.got .got.*) } :data
  .dynamic : { *(.dynamic) } :data :dynamic
  . = ALIGN(16);
  .bss (NOLOAD) : {
    __bss_start = .;
    *(.bss .bss.*) *(COMMON)
    . = ALIGN(16);
    __bss_end = .;
  } :data
  /DISCARD/ : { *(.comment) *(.eh_frame*) *(.interp) }
}
