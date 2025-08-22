SECTIONS {
    . = ALIGN(4096);
    .text.wolfcrypt : {
        __wc_text_start = .;
        *(.text.wolfcrypt)
        __wc_text_end = .;
    }
    . = ALIGN(4096);
    .rodata.wolfcrypt : {
        __wc_rodata_start = .;
        *(.rodata.wolfcrypt)
        __wc_rodata_end = .;
    }
    . = ALIGN(4096);
    .data.wolfcrypt : {
        __wc_rwdata_start = .;
        *(.data.wolfcrypt)
        __wc_rwdata_end = .;
    }
    . = ALIGN(4096);
    .bss.wolfcrypt : {
        __wc_bss_start = .;
        *(.bss.wolfcrypt)
        __wc_bss_end = .;
    }
    . = ALIGN(4096);
}
