/*
 * Linker script for keeper built as GOOS=openbsd GOARCH=riscv64 and linked
 * against the libc shim in this directory, targeting the ZisK zkVM.
 *
 * ZisK memory map (see zisk/core/src/mem.rs):
 *
 *   0x4000_0000  input data (read-only, 8-byte LE length prefix + payload)
 *   0x8000_0000  ROM: program code and read-only data
 *   0x87F0_0000  ROM: ZisK float library (1MB, must not be overlapped)
 *   0xA000_0000  RAM: initial stack (4MB)
 *   0xA040_0000  RAM: system area (registers, UART at +0x200, CSRs)
 *   0xA041_0000  RAM: public output (128KB)
 *   0xA043_0000  RAM: .data/.bss, then the heap managed by libc.c
 *   0xBFFF_0000  RAM: ZisK float library RAM (64KB, must not be overlapped)
 *   0xC000_0000  end of RAM
 */

OUTPUT_ARCH("riscv")
ENTRY(_start)

MEMORY {
  rom (rx) : ORIGIN = 0x80000000, LENGTH = 0x07F00000
  ram (rw) : ORIGIN = 0xA0000000, LENGTH = 0x1FFF0000
}

PHDRS {
  text   PT_LOAD FLAGS(1);
  rodata PT_LOAD FLAGS(4);
  stack  PT_LOAD FLAGS(6);
  sys    PT_LOAD FLAGS(6);
  data   PT_LOAD FLAGS(6);
  bss    PT_LOAD FLAGS(6);
  tls    PT_TLS;
}

SECTIONS {
  .text : {
    KEEP(*(.text.init))
    *(.text .text.*)
  } >rom :text

  . = ALIGN(8);
  .rodata       : { *(.rodata .rodata.* .srodata .srodata.*) } >rom :rodata
  . = ALIGN(8);
  .typelink     : { *(.typelink) } >rom :rodata
  . = ALIGN(8);
  .itablink     : { *(.itablink) } >rom :rodata
  . = ALIGN(8);
  .gosymtab     : { *(.gosymtab) } >rom :rodata
  . = ALIGN(8);
  .gopclntab    : { *(.gopclntab) } >rom :rodata
  /* Go 1.27+ splits type and function metadata out of .rodata. */
  . = ALIGN(8);
  .go.type      : { *(.go.type) } >rom :rodata
  . = ALIGN(8);
  .go.func      : { *(.go.func) } >rom :rodata

  /* Stack used by the Go runtime as the g0 stack of m0. */
  .stack (NOLOAD) : {
    _init_stack_bottom = .;
    . += 0x400000;
    _init_stack_top = .;
  } >ram :stack

  /* ZisK system area and public output, reserved so nothing is placed there. */
  .zisk_sys (NOLOAD) : {
    . += 0x30000;
  } >ram :sys

  .go.buildinfo : { *(.go.buildinfo) } >ram :data
  .go.fipsinfo  : { *(.go.fipsinfo) } >ram :data
  .noptrdata    : { *(.noptrdata) } >ram :data
  .data : {
    *(.data .data.* .sdata .sdata.*)
    PROVIDE(__global_pointer$ = . + 0x800);
  } >ram :data
  .go.module    : { *(.go.module) } >ram :data

  /* Go emits a TLS slot (runtime.tls_g) that is only used when cgo is
   * present; it is still referenced, so give it a PT_TLS segment. */
  .tdata : { *(.tdata .tdata.*) } >ram :data :tls
  .tbss  : { *(.tbss .tbss.*) } >ram :data :tls

  .bss (NOLOAD) : {
    *(.bss .bss.* .sbss .sbss.*)
    *(COMMON)
  } >ram :bss
  .noptrbss (NOLOAD) : { *(.noptrbss) } >ram :bss

  . = ALIGN(4096);
  _heap_bottom = .;
  _heap_top = ORIGIN(ram) + LENGTH(ram);

  /DISCARD/ : { *(.note.GNU-stack) *(.comment) }
}
