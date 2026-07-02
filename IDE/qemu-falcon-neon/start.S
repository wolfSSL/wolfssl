/* Minimal AArch64 reset for qemu-system-aarch64 -machine virt. Sets exception
 * vectors, enables FP/SIMD, brings up a flat identity MMU (so unaligned
 * accesses in the crypto code do not fault), clears .bss and calls main().
 * Loaded via -kernel at 0x40000000. */
    .section .text.boot, "ax"
    .globl _start
_start:
    /* Exception vectors (report "EXC" instead of hanging on a fault). */
    ldr     x0, =_vectors
    msr     vbar_el1, x0
    isb

    /* Enable FP/Advanced SIMD at EL1 (clear CPACR_EL1.FPEN trap). */
    mov     x0, #(3 << 20)
    msr     cpacr_el1, x0
    isb

    /* Stack. */
    ldr     x0, =_stack_top
    mov     sp, x0

    /* Zero .bss (aligned stores, fine before the MMU is on). */
    ldr     x0, =_bss_start
    ldr     x1, =_bss_end
0:  cmp     x0, x1
    b.hs    1f
    str     xzr, [x0], #8
    b       0b
1:
    /* Identity MMU: one L1 table of 1GB block descriptors, all Normal WB
     * cacheable memory (bits: block=01, AF, SH=inner, AttrIndx0, AP=RW-EL1). */
    ldr     x0, =_page_table
    mov     x1, #0x701
    mov     x2, #0
2:  add     x3, x1, x2, lsl #30         /* desc = (i << 30) | attrs */
    str     x3, [x0, x2, lsl #3]
    add     x2, x2, #1
    cmp     x2, #4                      /* map 0..4GB (entries 0..3) */
    b.lt    2b

    mov     x0, #0xFF                   /* MAIR attr0 = Normal WB cacheable */
    msr     mair_el1, x0
    ldr     x0, =0x0000000100003520     /* TCR: T0SZ=32,4K,WB,inner-sh,IPS=36b */
    msr     tcr_el1, x0
    ldr     x0, =_page_table
    msr     ttbr0_el1, x0
    isb
    mrs     x0, sctlr_el1
    orr     x0, x0, #(1 << 0)           /* M: MMU enable */
    orr     x0, x0, #(1 << 2)           /* C: data cache */
    orr     x0, x0, #(1 << 12)          /* I: instruction cache */
    msr     sctlr_el1, x0
    isb

    bl      main
3:  wfe
    b       3b

/* Any exception: report "EXC\n" via semihosting and exit qemu. */
exc_handler:
    ldr     x1, =_exc_msg
    mov     x0, #0x04
    hlt     #0xF000
    ldr     x1, =_exit_block
    mov     x0, #0x18
    hlt     #0xF000
4:  wfe
    b       4b

    .align 11
_vectors:
    .rept 16
    .align 7
    b       exc_handler
    .endr

    .section .rodata
    .align 3
_exc_msg:
    .asciz "EXC\n"
    .align 3
_exit_block:
    .dword 0x20026
    .dword 1

    .section .bss
    .align 12
_page_table:
    .skip 4096
