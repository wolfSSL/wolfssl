ENTRY(_start)

/* qemu-system-aarch64 -machine virt loads -kernel at the base of RAM
 * (0x40000000). Give a generous heap for Falcon key generation. */
SECTIONS
{
    . = 0x40000000;

    .text : {
        KEEP(*(.text.boot))
        *(.text*)
        *(.rodata*)
    }

    .data : ALIGN(8) {
        *(.data*)
    }

    .bss : ALIGN(8) {
        _bss_start = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(8);
        _bss_end = .;
    }

    . = ALIGN(16);
    _heap_start = .;
    . = . + 64M;
    _heap_end = .;

    . = . + 1M;
    . = ALIGN(16);
    _stack_top = .;
}
