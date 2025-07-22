SECTIONS {
    . = ALIGN(4096);
    .text.wolfcrypt : {
        *(.text.wolfcrypt)
    }
    . = ALIGN(4096);
    .rodata.wolfcrypt : {
        *(.rodata.wolfcrypt)
    }
    . = ALIGN(4096);
    .data.wolfcrypt : {
        *(.data.wolfcrypt)
    }
    . = ALIGN(4096);
    .bss.wolfcrypt : {
        *(.bss.wolfcrypt)
    }
    . = ALIGN(4096);
}
