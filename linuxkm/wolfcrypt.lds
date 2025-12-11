SECTIONS {
    . = ALIGN(4096);
    .text_wolfcrypt : {
        __wc_text_start = .;
        *(.text_wolfcrypt)
	. = ALIGN(4096);
        __wc_text_end = .;
    }
    . = ALIGN(4096);
    .rodata_wolfcrypt : {
        __wc_rodata_start = .;
        *(.rodata_wolfcrypt)
        . = ALIGN(4096);
        __wc_rodata_end = .;
    }
    . = ALIGN(4096);
    .data_wolfcrypt : {
        __wc_rwdata_start = .;
        *(.data_wolfcrypt)
        . = ALIGN(4096);
        __wc_rwdata_end = .;
    }
    . = ALIGN(4096);
    .bss_wolfcrypt : {
        __wc_bss_start = .;
        *(.bss_wolfcrypt)
        . = ALIGN(4096);
        __wc_bss_end = .;
    }
    . = ALIGN(4096);
}
