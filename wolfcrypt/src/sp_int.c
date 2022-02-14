/* sp_int.c
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* Implementation by Sean Parkinson. */

/*
DESCRIPTION
This library provides single precision (SP) integer math functions.

*/
#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_SP_MATH) || defined(WOLFSSL_SP_MATH_ALL)

#include <wolfssl/wolfcrypt/error-crypt.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* SP Build Options:
 * WOLFSSL_HAVE_SP_RSA:         Enable SP RSA support
 * WOLFSSL_HAVE_SP_DH:          Enable SP DH support
 * WOLFSSL_HAVE_SP_ECC:         Enable SP ECC support
 * WOLFSSL_SP_MATH:             Use only single precision math and algorithms
 *      it supports (no fastmath tfm.c or normal integer.c)
 * WOLFSSL_SP_MATH_ALL          Implementation of all MP functions
 *      (replacement for tfm.c and integer.c)
 * WOLFSSL_SP_SMALL:            Use smaller version of code and avoid large
 *      stack variables
 * WOLFSSL_SP_NO_MALLOC:        Always use stack, no heap XMALLOC/XFREE allowed
 * WOLFSSL_SP_NO_2048:          Disable RSA/DH 2048-bit support
 * WOLFSSL_SP_NO_3072:          Disable RSA/DH 3072-bit support
 * WOLFSSL_SP_4096:             Enable RSA/RH 4096-bit support
 * WOLFSSL_SP_NO_256            Disable ECC 256-bit SECP256R1 support
 * WOLFSSL_SP_384               Enable ECC 384-bit SECP384R1 support
 * WOLFSSL_SP_ASM               Enable assembly speedups (detect platform)
 * WOLFSSL_SP_X86_64_ASM        Enable Intel x64 assembly implementation
 * WOLFSSL_SP_ARM32_ASM         Enable Aarch32 assembly implementation
 * WOLFSSL_SP_ARM64_ASM         Enable Aarch64 assembly implementation
 * WOLFSSL_SP_ARM_CORTEX_M_ASM  Enable Cortex-M assembly implementation
 * WOLFSSL_SP_ARM_THUMB_ASM     Enable ARM Thumb assembly implementation
 *      (used with -mthumb)
 * WOLFSSL_SP_X86_64            Enable Intel x86 64-bit assembly speedups
 * WOLFSSL_SP_X86               Enable Intel x86 assembly speedups
 * WOLFSSL_SP_ARM64             Enable Aarch64 assembly speedups
 * WOLFSSL_SP_ARM32             Enable ARM32 assembly speedups
 * WOLFSSL_SP_ARM32_UDIV        Enable word divide asm that uses UDIV instr
 * WOLFSSL_SP_ARM_THUMB         Enable ARM Thumb assembly speedups
 *                              (explicitly uses register 'r7')
 * WOLFSSL_SP_PPC64             Enable PPC64 assembly speedups
 * WOLFSSL_SP_PPC               Enable PPC assembly speedups
 * WOLFSSL_SP_MIPS64            Enable MIPS64 assembly speedups
 * WOLFSSL_SP_MIPS              Enable MIPS assembly speedups
 * WOLFSSL_SP_RISCV64           Enable RISCV64 assembly speedups
 * WOLFSSL_SP_RISCV32           Enable RISCV32 assembly speedups
 * WOLFSSL_SP_S390X             Enable S390X assembly speedups
 * SP_WORD_SIZE                 Force 32 or 64 bit mode
 * WOLFSSL_SP_NONBLOCK          Enables "non blocking" mode for SP math, which
 *      will return FP_WOULDBLOCK for long operations and function must be
 *      called again until complete.
 * WOLFSSL_SP_FAST_NCT_EXPTMOD  Enables the faster non-constant time modular
 *      exponentation implementation.
 * WOLFSSL_SP_INT_NEGATIVE      Enables negative values to be used.
 * WOLFSSL_SP_INT_DIGIT_ALIGN   Enable when unaligned access of sp_int_digit
 *                              pointer is not allowed.
 * WOLFSSL_SP_NO_DYN_STACK      Disable use of dynamic stack items.
 *                              Used with small code size and not small stack.
 * WOLFSSL_SP_FAST_MODEXP       Allow fast mod_exp with small C code
 */

/* TODO: WOLFSSL_SP_SMALL is incompatible with clang-12+ -Os. */
#if defined(__clang__) && defined(__clang_major__) && \
    (__clang_major__ >= 12) && defined(WOLFSSL_SP_SMALL)
    #undef WOLFSSL_SP_SMALL
#endif

#include <wolfssl/wolfcrypt/sp_int.h>

/* DECL_SP_INT: Declare one variable of type 'sp_int'. */
#if (defined(WOLFSSL_SMALL_STACK) || defined(SP_ALLOC)) && \
    !defined(WOLFSSL_SP_NO_MALLOC)
    /* Declare a variable that will be assigned a value on XMALLOC. */
    #define DECL_SP_INT(n, s)   \
        sp_int* n = NULL
#else
    #if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L) && \
        defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SP_NO_DYN_STACK)
        /* Declare a variable on the stack with the required data size. */
        #define DECL_SP_INT(n, s)               \
            byte    n##d[MP_INT_SIZEOF(s)];     \
            sp_int* n = (sp_int*)n##d
    #else
        /* Declare a variable on the stack. */
        #define DECL_SP_INT(n, s)               \
            sp_int n[1]
    #endif
#endif

/* ALLOC_SP_INT: Allocate an 'sp_int' of reqired size. */
#if (defined(WOLFSSL_SMALL_STACK) || defined(SP_ALLOC)) && \
    !defined(WOLFSSL_SP_NO_MALLOC)
    /* Dynamically allocate just enough data to support size. */
    #define ALLOC_SP_INT(n, s, err, h)                                         \
    do {                                                                       \
        if ((err) == MP_OKAY) {                                                \
            (n) = (sp_int*)XMALLOC(MP_INT_SIZEOF(s), (h), DYNAMIC_TYPE_BIGINT); \
            if ((n) == NULL) {                                                 \
                (err) = MP_MEM;                                                \
            }                                                                  \
        }                                                                      \
    }                                                                          \
    while (0)

    /* Dynamically allocate just enough data to support size - and set size. */
    #define ALLOC_SP_INT_SIZE(n, s, err, h)                                    \
    do {                                                                       \
        ALLOC_SP_INT(n, s, err, h);                                            \
        if ((err) == MP_OKAY) {                                                \
            (n)->size = (s);                                                   \
        }                                                                      \
    }                                                                          \
    while (0)
#else
    /* Array declared on stack - nothing to do. */
    #define ALLOC_SP_INT(n, s, err, h)
    /* Array declared on stack - set the size field. */
    #define ALLOC_SP_INT_SIZE(n, s, err, h)     \
        n->size = s;
#endif

/* FREE_SP_INT: Free an 'sp_int' variable. */
#if (defined(WOLFSSL_SMALL_STACK) || defined(SP_ALLOC)) && \
    !defined(WOLFSSL_SP_NO_MALLOC)
    /* Free dynamically allocated data. */
    #define FREE_SP_INT(n, h)                   \
    do {                                        \
        if ((n) != NULL) {                      \
            XFREE(n, h, DYNAMIC_TYPE_BIGINT);   \
        }                                       \
    }                                           \
    while (0)
#else
    /* Nothing to do as declared on stack. */
    #define FREE_SP_INT(n, h)
#endif


/* DECL_SP_INT_ARRAY: Declare array of 'sp_int'. */
#if (defined(WOLFSSL_SMALL_STACK) || defined(SP_ALLOC)) && \
    !defined(WOLFSSL_SP_NO_MALLOC)
    /* Declare a variable that will be assigned a value on XMALLOC. */
    #define DECL_SP_INT_ARRAY(n, s, c)  \
        sp_int* n##d = NULL;            \
        sp_int* (n)[c] = { NULL, }
#else
    #if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L) && \
        defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SP_NO_DYN_STACK)
        /* Declare a variable on the stack with the required data size. */
        #define DECL_SP_INT_ARRAY(n, s, c)          \
            byte    n##d[MP_INT_SIZEOF(s) * (c)];   \
            sp_int* (n)[c]
    #else
        /* Declare a variable on the stack. */
        #define DECL_SP_INT_ARRAY(n, s, c)      \
            sp_int n##d[c];                     \
            sp_int* (n)[c]
    #endif
#endif

/* ALLOC_SP_INT_ARRAY: Allocate an array of 'sp_int's of reqired size. */
#if (defined(WOLFSSL_SMALL_STACK) || defined(SP_ALLOC)) && \
    !defined(WOLFSSL_SP_NO_MALLOC)
    /* Dynamically allocate just enough data to support multiple sp_ints of the
     * required size. Use pointers into data to make up array and set sizes.
     */
    #define ALLOC_SP_INT_ARRAY(n, s, c, err, h)                                \
    do {                                                                       \
        if ((err) == MP_OKAY) {                                                \
            n##d = (sp_int*)XMALLOC(MP_INT_SIZEOF(s) * (c), (h),               \
                                                         DYNAMIC_TYPE_BIGINT); \
            if (n##d == NULL) {                                                \
                (err) = MP_MEM;                                                \
            }                                                                  \
            else {                                                             \
                int n##ii;                                                     \
                (n)[0] = n##d;                                                 \
                (n)[0]->size = (s);                                            \
                for (n##ii = 1; n##ii < (c); n##ii++) {                        \
                    (n)[n##ii] = MP_INT_NEXT((n)[n##ii-1], s);                 \
                    (n)[n##ii]->size = (s);                                    \
                }                                                              \
            }                                                                  \
        }                                                                      \
    }                                                                          \
    while (0)
#else
    #if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L) && \
        defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SP_NO_DYN_STACK)
        /* Data declared on stack that supports multiple sp_ints of the
         * required size. Use pointers into data to make up array and set sizes.
         */
        #define ALLOC_SP_INT_ARRAY(n, s, c, err, h)                            \
        do {                                                                   \
            if ((err) == MP_OKAY) {                                            \
                int n##ii;                                                     \
                (n)[0] = (sp_int*)n##d;                                        \
                (n)[0]->size = (s);                                            \
                for (n##ii = 1; n##ii < (c); n##ii++) {                        \
                    (n)[n##ii] = MP_INT_NEXT((n)[n##ii-1], s);                 \
                    (n)[n##ii]->size = (s);                                    \
                }                                                              \
            }                                                                  \
        }                                                                      \
        while (0)
    #else
        /* Data declared on stack that supports multiple sp_ints of the
         * required size. Set into array and set sizes.
         */
        #define ALLOC_SP_INT_ARRAY(n, s, c, err, h)                            \
        do {                                                                   \
            if ((err) == MP_OKAY) {                                            \
                int n##ii;                                                     \
                for (n##ii = 0; n##ii < (c); n##ii++) {                        \
                    (n)[n##ii] = &n##d[n##ii];                                 \
                    (n)[n##ii]->size = (s);                                    \
                }                                                              \
            }                                                                  \
        }                                                                      \
        while (0)
    #endif
#endif

/* FREE_SP_INT_ARRAY: Free an array of 'sp_int'. */
#if (defined(WOLFSSL_SMALL_STACK) || defined(SP_ALLOC)) && \
    !defined(WOLFSSL_SP_NO_MALLOC)
    /* Free data variable that was dynamically allocated. */
    #define FREE_SP_INT_ARRAY(n, h)                 \
    do {                                            \
        if (n##d != NULL) {                         \
            XFREE(n##d, h, DYNAMIC_TYPE_BIGINT);    \
        }                                           \
    }                                               \
    while (0)
#else
    /* Nothing to do as data declared on stack. */
    #define FREE_SP_INT_ARRAY(n, h)
#endif


#ifndef WOLFSSL_NO_ASM
    #ifdef __IAR_SYSTEMS_ICC__
        #define __asm__        asm
        #define __volatile__   volatile
    #endif /* __IAR_SYSTEMS_ICC__ */
    #ifdef __KEIL__
        #define __asm__        __asm
        #define __volatile__   volatile
    #endif

    #if defined(WOLFSSL_SP_X86_64) && SP_WORD_SIZE == 64
/*
 * CPU: x86_64
 */

/* Multiply va by vb and store double size result in: vh | vl */
#define SP_ASM_MUL(vl, vh, va, vb)                       \
    __asm__ __volatile__ (                               \
        "movq	%[b], %%rax	\n\t"                    \
        "mulq	%[a]		\n\t"                    \
        "movq	%%rax, %[l]	\n\t"                    \
        "movq	%%rdx, %[h]	\n\t"                    \
        : [h] "+r" (vh), [l] "+r" (vl)                   \
        : [a] "m" (va), [b] "m" (vb)                     \
        : "memory", "%rax", "%rdx", "cc"                 \
    )
/* Multiply va by vb and store double size result in: vo | vh | vl */
#define SP_ASM_MUL_SET(vl, vh, vo, va, vb)               \
    __asm__ __volatile__ (                               \
        "movq	%[b], %%rax	\n\t"                    \
        "mulq	%[a]		\n\t"                    \
        "movq	$0   , %[o]	\n\t"                    \
        "movq	%%rax, %[l]	\n\t"                    \
        "movq	%%rdx, %[h]	\n\t"                    \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "=r" (vo)    \
        : [a] "m" (va), [b] "m" (vb)                     \
        : "%rax", "%rdx", "cc"                           \
    )
/* Multiply va by vb and add double size result into: vo | vh | vl */
#define SP_ASM_MUL_ADD(vl, vh, vo, va, vb)               \
    __asm__ __volatile__ (                               \
        "movq	%[b], %%rax	\n\t"                    \
        "mulq	%[a]		\n\t"                    \
        "addq	%%rax, %[l]	\n\t"                    \
        "adcq	%%rdx, %[h]	\n\t"                    \
        "adcq	$0   , %[o]	\n\t"                    \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "m" (va), [b] "m" (vb)                     \
        : "%rax", "%rdx", "cc"                           \
    )
/* Multiply va by vb and add double size result into: vh | vl */
#define SP_ASM_MUL_ADD_NO(vl, vh, va, vb)                \
    __asm__ __volatile__ (                               \
        "movq	%[b], %%rax	\n\t"                    \
        "mulq	%[a]		\n\t"                    \
        "addq	%%rax, %[l]	\n\t"                    \
        "adcq	%%rdx, %[h]	\n\t"                    \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "m" (va), [b] "m" (vb)                     \
        : "%rax", "%rdx", "cc"                           \
    )
/* Multiply va by vb and add double size result twice into: vo | vh | vl */
#define SP_ASM_MUL_ADD2(vl, vh, vo, va, vb)              \
    __asm__ __volatile__ (                               \
        "movq	%[b], %%rax	\n\t"                    \
        "mulq	%[a]		\n\t"                    \
        "addq	%%rax, %[l]	\n\t"                    \
        "adcq	%%rdx, %[h]	\n\t"                    \
        "adcq	$0   , %[o]	\n\t"                    \
        "addq	%%rax, %[l]	\n\t"                    \
        "adcq	%%rdx, %[h]	\n\t"                    \
        "adcq	$0   , %[o]	\n\t"                    \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "m" (va), [b] "m" (vb)                     \
        : "%rax", "%rdx", "cc"                           \
    )
/* Multiply va by vb and add double size result twice into: vo | vh | vl
 * Assumes first add will not overflow vh | vl
 */
#define SP_ASM_MUL_ADD2_NO(vl, vh, vo, va, vb)           \
    __asm__ __volatile__ (                               \
        "movq	%[b], %%rax	\n\t"                    \
        "mulq	%[a]		\n\t"                    \
        "addq	%%rax, %[l]	\n\t"                    \
        "adcq	%%rdx, %[h]	\n\t"                    \
        "addq	%%rax, %[l]	\n\t"                    \
        "adcq	%%rdx, %[h]	\n\t"                    \
        "adcq	$0   , %[o]	\n\t"                    \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "m" (va), [b] "m" (vb)                     \
        : "%rax", "%rdx", "cc"                           \
    )
/* Square va and store double size result in: vh | vl */
#define SP_ASM_SQR(vl, vh, va)                           \
    __asm__ __volatile__ (                               \
        "movq	%[a], %%rax	\n\t"                    \
        "mulq	%%rax		\n\t"                    \
        "movq	%%rax, %[l]	\n\t"                    \
        "movq	%%rdx, %[h]	\n\t"                    \
        : [h] "+r" (vh), [l] "+r" (vl)                   \
        : [a] "m" (va)                                   \
        : "memory", "%rax", "%rdx", "cc"                 \
    )
/* Square va and add double size result into: vo | vh | vl */
#define SP_ASM_SQR_ADD(vl, vh, vo, va)                   \
    __asm__ __volatile__ (                               \
        "movq	%[a], %%rax	\n\t"                    \
        "mulq	%%rax		\n\t"                    \
        "addq	%%rax, %[l]	\n\t"                    \
        "adcq	%%rdx, %[h]	\n\t"                    \
        "adcq	$0   , %[o]	\n\t"                    \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "m" (va)                                   \
        : "%rax", "%rdx", "cc"                           \
    )
/* Square va and add double size result into: vh | vl */
#define SP_ASM_SQR_ADD_NO(vl, vh, va)                    \
    __asm__ __volatile__ (                               \
        "movq	%[a], %%rax	\n\t"                    \
        "mulq	%%rax		\n\t"                    \
        "addq	%%rax, %[l]	\n\t"                    \
        "adcq	%%rdx, %[h]	\n\t"                    \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "m" (va)                                   \
        : "%rax", "%rdx", "cc"                           \
    )
/* Add va into: vh | vl */
#define SP_ASM_ADDC(vl, vh, va)                          \
    __asm__ __volatile__ (                               \
        "addq	%[a], %[l]	\n\t"                    \
        "adcq	$0  , %[h]	\n\t"                    \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "m" (va)                                   \
        : "cc"                                           \
    )
/* Add va, variable in a register, into: vh | vl */
#define SP_ASM_ADDC_REG(vl, vh, va)                      \
    __asm__ __volatile__ (                               \
        "addq	%[a], %[l]	\n\t"                    \
        "adcq	$0  , %[h]	\n\t"                    \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "r" (va)                                   \
        : "cc"                                           \
    )
/* Sub va from: vh | vl */
#define SP_ASM_SUBC(vl, vh, va)                          \
    __asm__ __volatile__ (                               \
        "subq	%[a], %[l]	\n\t"                    \
        "sbbq	$0  , %[h]	\n\t"                    \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "m" (va)                                   \
        : "cc"                                           \
    )
/* Add two times vc | vb | va into vo | vh | vl */
#define SP_ASM_ADD_DBL_3(vl, vh, vo, va, vb, vc)         \
    __asm__ __volatile__ (                               \
        "addq	%[a], %[l]	\n\t"                    \
        "adcq	%[b], %[h]	\n\t"                    \
        "adcq	%[c], %[o]	\n\t"                    \
        "addq	%[a], %[l]	\n\t"                    \
        "adcq	%[b], %[h]	\n\t"                    \
        "adcq	%[c], %[o]	\n\t"                    \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va), [b] "r" (vb), [c] "r" (vc)       \
        : "%rax", "%rdx", "cc"                           \
    )

#ifndef WOLFSSL_SP_DIV_WORD_HALF
/* Divide a two digit number by a digit number and return. (hi | lo) / d
 *
 * Using divq instruction on Intel x64.
 *
 * @param  [in]  hi  SP integer digit. High digit of the dividend.
 * @param  [in]  lo  SP integer digit. Lower digit of the dividend.
 * @param  [in]  d   SP integer digit. Number to divide by.
 * @return  The division result.
 */
static WC_INLINE sp_int_digit sp_div_word(sp_int_digit hi, sp_int_digit lo,
                                          sp_int_digit d)
{
    __asm__ __volatile__ (
        "divq %2"
        : "+a" (lo)
        : "d" (hi), "r" (d)
        : "cc"
    );
    return lo;
}
#define SP_ASM_DIV_WORD
#endif

#define SP_INT_ASM_AVAILABLE

    #endif /* WOLFSSL_SP_X86_64 && SP_WORD_SIZE == 64 */

    #if defined(WOLFSSL_SP_X86) && SP_WORD_SIZE == 32
/*
 * CPU: x86
 */

/* Multiply va by vb and store double size result in: vh | vl */
#define SP_ASM_MUL(vl, vh, va, vb)                       \
    __asm__ __volatile__ (                               \
        "movl	%[b], %%eax	\n\t"                    \
        "mull	%[a]		\n\t"                    \
        "movl	%%eax, %[l]	\n\t"                    \
        "movl	%%edx, %[h]	\n\t"                    \
        : [h] "+r" (vh), [l] "+r" (vl)                   \
        : [a] "m" (va), [b] "m" (vb)                     \
        : "memory", "eax", "edx", "cc"                   \
    )
/* Multiply va by vb and store double size result in: vo | vh | vl */
#define SP_ASM_MUL_SET(vl, vh, vo, va, vb)               \
    __asm__ __volatile__ (                               \
        "movl	%[b], %%eax	\n\t"                    \
        "mull	%[a]		\n\t"                    \
        "movl	$0   , %[o]	\n\t"                    \
        "movl	%%eax, %[l]	\n\t"                    \
        "movl	%%edx, %[h]	\n\t"                    \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "=r" (vo)    \
        : [a] "m" (va), [b] "m" (vb)                     \
        : "eax", "edx", "cc"                             \
    )
/* Multiply va by vb and add double size result into: vo | vh | vl */
#define SP_ASM_MUL_ADD(vl, vh, vo, va, vb)               \
    __asm__ __volatile__ (                               \
        "movl	%[b], %%eax	\n\t"                    \
        "mull	%[a]		\n\t"                    \
        "addl	%%eax, %[l]	\n\t"                    \
        "adcl	%%edx, %[h]	\n\t"                    \
        "adcl	$0   , %[o]	\n\t"                    \
        : [l] "+rm" (vl), [h] "+rm" (vh), [o] "+rm" (vo) \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "eax", "edx", "cc"                             \
    )
/* Multiply va by vb and add double size result into: vh | vl */
#define SP_ASM_MUL_ADD_NO(vl, vh, va, vb)                \
    __asm__ __volatile__ (                               \
        "movl	%[b], %%eax	\n\t"                    \
        "mull	%[a]		\n\t"                    \
        "addl	%%eax, %[l]	\n\t"                    \
        "adcl	%%edx, %[h]	\n\t"                    \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "m" (va), [b] "m" (vb)                     \
        : "eax", "edx", "cc"                             \
    )
/* Multiply va by vb and add double size result twice into: vo | vh | vl */
#define SP_ASM_MUL_ADD2(vl, vh, vo, va, vb)              \
    __asm__ __volatile__ (                               \
        "movl	%[b], %%eax	\n\t"                    \
        "mull	%[a]		\n\t"                    \
        "addl	%%eax, %[l]	\n\t"                    \
        "adcl	%%edx, %[h]	\n\t"                    \
        "adcl	$0   , %[o]	\n\t"                    \
        "addl	%%eax, %[l]	\n\t"                    \
        "adcl	%%edx, %[h]	\n\t"                    \
        "adcl	$0   , %[o]	\n\t"                    \
        : [l] "+rm" (vl), [h] "+rm" (vh), [o] "+rm" (vo) \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "eax", "edx", "cc"                             \
    )
/* Multiply va by vb and add double size result twice into: vo | vh | vl
 * Assumes first add will not overflow vh | vl
 */
#define SP_ASM_MUL_ADD2_NO(vl, vh, vo, va, vb)           \
    __asm__ __volatile__ (                               \
        "movl	%[b], %%eax	\n\t"                    \
        "mull	%[a]		\n\t"                    \
        "addl	%%eax, %[l]	\n\t"                    \
        "adcl	%%edx, %[h]	\n\t"                    \
        "addl	%%eax, %[l]	\n\t"                    \
        "adcl	%%edx, %[h]	\n\t"                    \
        "adcl	$0   , %[o]	\n\t"                    \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "m" (va), [b] "m" (vb)                     \
        : "eax", "edx", "cc"                             \
    )
/* Square va and store double size result in: vh | vl */
#define SP_ASM_SQR(vl, vh, va)                           \
    __asm__ __volatile__ (                               \
        "movl	%[a], %%eax	\n\t"                    \
        "mull	%%eax		\n\t"                    \
        "movl	%%eax, %[l]	\n\t"                    \
        "movl	%%edx, %[h]	\n\t"                    \
        : [h] "+r" (vh), [l] "+r" (vl)                   \
        : [a] "m" (va)                                   \
        : "memory", "eax", "edx", "cc"                   \
    )
/* Square va and add double size result into: vo | vh | vl */
#define SP_ASM_SQR_ADD(vl, vh, vo, va)                   \
    __asm__ __volatile__ (                               \
        "movl	%[a], %%eax	\n\t"                    \
        "mull	%%eax		\n\t"                    \
        "addl	%%eax, %[l]	\n\t"                    \
        "adcl	%%edx, %[h]	\n\t"                    \
        "adcl	$0   , %[o]	\n\t"                    \
        : [l] "+rm" (vl), [h] "+rm" (vh), [o] "+rm" (vo) \
        : [a] "m" (va)                                   \
        : "eax", "edx", "cc"                             \
    )
/* Square va and add double size result into: vh | vl */
#define SP_ASM_SQR_ADD_NO(vl, vh, va)                    \
    __asm__ __volatile__ (                               \
        "movl	%[a], %%eax	\n\t"                    \
        "mull	%%eax		\n\t"                    \
        "addl	%%eax, %[l]	\n\t"                    \
        "adcl	%%edx, %[h]	\n\t"                    \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "m" (va)                                   \
        : "eax", "edx", "cc"                             \
    )
/* Add va into: vh | vl */
#define SP_ASM_ADDC(vl, vh, va)                          \
    __asm__ __volatile__ (                               \
        "addl	%[a], %[l]	\n\t"                    \
        "adcl	$0  , %[h]	\n\t"                    \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "m" (va)                                   \
        : "cc"                                           \
    )
/* Add va, variable in a register, into: vh | vl */
#define SP_ASM_ADDC_REG(vl, vh, va)                      \
    __asm__ __volatile__ (                               \
        "addl	%[a], %[l]	\n\t"                    \
        "adcl	$0  , %[h]	\n\t"                    \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "r" (va)                                   \
        : "cc"                                           \
    )
/* Sub va from: vh | vl */
#define SP_ASM_SUBC(vl, vh, va)                          \
    __asm__ __volatile__ (                               \
        "subl	%[a], %[l]	\n\t"                    \
        "sbbl	$0  , %[h]	\n\t"                    \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "m" (va)                                   \
        : "cc"                                           \
    )
/* Add two times vc | vb | va into vo | vh | vl */
#define SP_ASM_ADD_DBL_3(vl, vh, vo, va, vb, vc)         \
    __asm__ __volatile__ (                               \
        "addl	%[a], %[l]	\n\t"                    \
        "adcl	%[b], %[h]	\n\t"                    \
        "adcl	%[c], %[o]	\n\t"                    \
        "addl	%[a], %[l]	\n\t"                    \
        "adcl	%[b], %[h]	\n\t"                    \
        "adcl	%[c], %[o]	\n\t"                    \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va), [b] "r" (vb), [c] "r" (vc)       \
        : "cc"                                           \
    )

#ifndef WOLFSSL_SP_DIV_WORD_HALF
/* Divide a two digit number by a digit number and return. (hi | lo) / d
 *
 * Using divl instruction on Intel x64.
 *
 * @param  [in]  hi  SP integer digit. High digit of the dividend.
 * @param  [in]  lo  SP integer digit. Lower digit of the dividend.
 * @param  [in]  d   SP integer digit. Number to divide by.
 * @return  The division result.
 */
static WC_INLINE sp_int_digit sp_div_word(sp_int_digit hi, sp_int_digit lo,
                                          sp_int_digit d)
{
    __asm__ __volatile__ (
        "divl %2"
        : "+a" (lo)
        : "d" (hi), "r" (d)
        : "cc"
    );
    return lo;
}
#define SP_ASM_DIV_WORD
#endif

#define SP_INT_ASM_AVAILABLE

    #endif /* WOLFSSL_SP_X86 && SP_WORD_SIZE == 32 */

    #if defined(WOLFSSL_SP_ARM64) && SP_WORD_SIZE == 64
/*
 * CPU: Aarch64
 */

/* Multiply va by vb and store double size result in: vh | vl */
#define SP_ASM_MUL(vl, vh, va, vb)                       \
    __asm__ __volatile__ (                               \
        "mul	%[l], %[a], %[b]	\n\t"            \
        "umulh	%[h], %[a], %[b]	\n\t"            \
        : [h] "+r" (vh), [l] "+r" (vl)                   \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "memory", "cc"                                 \
    )
/* Multiply va by vb and store double size result in: vo | vh | vl */
#define SP_ASM_MUL_SET(vl, vh, vo, va, vb)               \
    __asm__ __volatile__ (                               \
        "mul	x8, %[a], %[b]		\n\t"            \
        "umulh	%[h], %[a], %[b]	\n\t"            \
        "mov	%[l], x8		\n\t"            \
        "mov	%[o], xzr		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "=r" (vo)    \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "x8"                                           \
    )
/* Multiply va by vb and add double size result into: vo | vh | vl */
#define SP_ASM_MUL_ADD(vl, vh, vo, va, vb)               \
    __asm__ __volatile__ (                               \
        "mul	x8, %[a], %[b]		\n\t"            \
        "umulh	x9, %[a], %[b]		\n\t"            \
        "adds	%[l], %[l], x8		\n\t"            \
        "adcs	%[h], %[h], x9		\n\t"            \
        "adc	%[o], %[o], xzr		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "x8", "x9", "cc"                               \
    )
/* Multiply va by vb and add double size result into: vh | vl */
#define SP_ASM_MUL_ADD_NO(vl, vh, va, vb)                \
    __asm__ __volatile__ (                               \
        "mul	x8, %[a], %[b]		\n\t"            \
        "umulh	x9, %[a], %[b]		\n\t"            \
        "adds	%[l], %[l], x8		\n\t"            \
        "adc	%[h], %[h], x9		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "x8", "x9", "cc"                               \
    )
/* Multiply va by vb and add double size result twice into: vo | vh | vl */
#define SP_ASM_MUL_ADD2(vl, vh, vo, va, vb)              \
    __asm__ __volatile__ (                               \
        "mul	x8, %[a], %[b]		\n\t"            \
        "umulh	x9, %[a], %[b]		\n\t"            \
        "adds	%[l], %[l], x8		\n\t"            \
        "adcs	%[h], %[h], x9		\n\t"            \
        "adc	%[o], %[o], xzr		\n\t"            \
        "adds	%[l], %[l], x8		\n\t"            \
        "adcs	%[h], %[h], x9		\n\t"            \
        "adc	%[o], %[o], xzr		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "x8", "x9", "cc"                               \
    )
/* Multiply va by vb and add double size result twice into: vo | vh | vl
 * Assumes first add will not overflow vh | vl
 */
#define SP_ASM_MUL_ADD2_NO(vl, vh, vo, va, vb)           \
    __asm__ __volatile__ (                               \
        "mul	x8, %[a], %[b]		\n\t"            \
        "umulh	x9, %[a], %[b]		\n\t"            \
        "adds	%[l], %[l], x8		\n\t"            \
        "adc	%[h], %[h], x9		\n\t"            \
        "adds	%[l], %[l], x8		\n\t"            \
        "adcs	%[h], %[h], x9		\n\t"            \
        "adc	%[o], %[o], xzr		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "x8", "x9", "cc"                               \
    )
/* Square va and store double size result in: vh | vl */
#define SP_ASM_SQR(vl, vh, va)                           \
    __asm__ __volatile__ (                               \
        "mul	%[l], %[a], %[a]	\n\t"            \
        "umulh	%[h], %[a], %[a]	\n\t"            \
        : [h] "+r" (vh), [l] "+r" (vl)                   \
        : [a] "r" (va)                                   \
        : "memory"                                       \
    )
/* Square va and add double size result into: vo | vh | vl */
#define SP_ASM_SQR_ADD(vl, vh, vo, va)                   \
    __asm__ __volatile__ (                               \
        "mul	x8, %[a], %[a]		\n\t"            \
        "umulh	x9, %[a], %[a]		\n\t"            \
        "adds	%[l], %[l], x8		\n\t"            \
        "adcs	%[h], %[h], x9		\n\t"            \
        "adc	%[o], %[o], xzr		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va)                                   \
        : "x8", "x9", "cc"                               \
    )
/* Square va and add double size result into: vh | vl */
#define SP_ASM_SQR_ADD_NO(vl, vh, va)                    \
    __asm__ __volatile__ (                               \
        "mul	x8, %[a], %[a]		\n\t"            \
        "umulh	x9, %[a], %[a]		\n\t"            \
        "adds	%[l], %[l], x8		\n\t"            \
        "adc	%[h], %[h], x9		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "r" (va)                                   \
        : "x8", "x9", "cc"                               \
    )
/* Add va into: vh | vl */
#define SP_ASM_ADDC(vl, vh, va)                          \
    __asm__ __volatile__ (                               \
        "adds	%[l], %[l], %[a]	\n\t"            \
        "adc	%[h], %[h], xzr		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "r" (va)                                   \
        : "cc"                                           \
    )
/* Sub va from: vh | vl */
#define SP_ASM_SUBC(vl, vh, va)                          \
    __asm__ __volatile__ (                               \
        "subs	%[l], %[l], %[a]	\n\t"            \
        "sbc	%[h], %[h], xzr		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "r" (va)                                   \
        : "cc"                                           \
    )
/* Add two times vc | vb | va into vo | vh | vl */
#define SP_ASM_ADD_DBL_3(vl, vh, vo, va, vb, vc)         \
    __asm__ __volatile__ (                               \
        "adds	%[l], %[l], %[a]	\n\t"            \
        "adcs	%[h], %[h], %[b]	\n\t"            \
        "adc	%[o], %[o], %[c]	\n\t"            \
        "adds	%[l], %[l], %[a]	\n\t"            \
        "adcs	%[h], %[h], %[b]	\n\t"            \
        "adc	%[o], %[o], %[c]	\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va), [b] "r" (vb), [c] "r" (vc)       \
        : "cc"                                           \
    )

#ifndef WOLFSSL_SP_DIV_WORD_HALF
/* Divide a two digit number by a digit number and return. (hi | lo) / d
 *
 * Using udiv instruction on Aarch64.
 * Constant time.
 *
 * @param  [in]  hi  SP integer digit. High digit of the dividend.
 * @param  [in]  lo  SP integer digit. Lower digit of the dividend.
 * @param  [in]  d   SP integer digit. Number to divide by.
 * @return  The division result.
 */
static WC_INLINE sp_int_digit sp_div_word(sp_int_digit hi, sp_int_digit lo,
                                          sp_int_digit d)
{
    __asm__ __volatile__ (
        "lsr	x3, %[d], 48\n\t"
        "mov	x5, 16\n\t"
        "cmp	x3, 0\n\t"
        "mov	x4, 63\n\t"
        "csel	x3, x5, xzr, eq\n\t"
        "sub	x4, x4, x3\n\t"
        "lsl	%[d], %[d], x3\n\t"
        "lsl	%[hi], %[hi], x3\n\t"
        "lsr	x5, %[lo], x4\n\t"
        "lsl	%[lo], %[lo], x3\n\t"
        "orr	%[hi], %[hi], x5, lsr 1\n\t"

        "lsr	x5, %[d], 32\n\t"
        "add	x5, x5, 1\n\t"

        "udiv	x3, %[hi], x5\n\t"
        "lsl	x6, x3, 32\n\t"
        "mul	x4, %[d], x6\n\t"
        "umulh	x3, %[d], x6\n\t"
        "subs	%[lo], %[lo], x4\n\t"
        "sbc	%[hi], %[hi], x3\n\t"

        "udiv	x3, %[hi], x5\n\t"
        "lsl	x3, x3, 32\n\t"
        "add	x6, x6, x3\n\t"
        "mul	x4, %[d], x3\n\t"
        "umulh	x3, %[d], x3\n\t"
        "subs	%[lo], %[lo], x4\n\t"
        "sbc	%[hi], %[hi], x3\n\t"

        "lsr	x3, %[lo], 32\n\t"
        "orr	x3, x3, %[hi], lsl 32\n\t"

        "udiv	x3, x3, x5\n\t"
        "add	x6, x6, x3\n\t"
        "mul	x4, %[d], x3\n\t"
        "umulh	x3, %[d], x3\n\t"
        "subs	%[lo], %[lo], x4\n\t"
        "sbc	%[hi], %[hi], x3\n\t"

        "lsr	x3, %[lo], 32\n\t"
        "orr	x3, x3, %[hi], lsl 32\n\t"

        "udiv	x3, x3, x5\n\t"
        "add	x6, x6, x3\n\t"
        "mul	x4, %[d], x3\n\t"
        "sub	%[lo], %[lo], x4\n\t"

        "udiv	x3, %[lo], %[d]\n\t"
        "add	%[hi], x6, x3\n\t"

        : [hi] "+r" (hi), [lo] "+r" (lo), [d] "+r" (d)
        :
        : "x3", "x4", "x5", "x6"
    );

    return hi;
}
#define SP_ASM_DIV_WORD
#endif

#define SP_INT_ASM_AVAILABLE

    #endif /* WOLFSSL_SP_ARM64 && SP_WORD_SIZE == 64 */

    #if (defined(WOLFSSL_SP_ARM32) || defined(WOLFSSL_SP_ARM_CORTEX_M)) && \
        SP_WORD_SIZE == 32
/*
 * CPU: ARM32 or Cortex-M4 and similar
 */

/* Multiply va by vb and store double size result in: vh | vl */
#define SP_ASM_MUL(vl, vh, va, vb)                       \
    __asm__ __volatile__ (                               \
        "umull	%[l], %[h], %[a], %[b]	\n\t"            \
        : [h] "+r" (vh), [l] "+r" (vl)                   \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "memory"                                       \
    )
/* Multiply va by vb and store double size result in: vo | vh | vl */
#define SP_ASM_MUL_SET(vl, vh, vo, va, vb)               \
    __asm__ __volatile__ (                               \
        "umull	%[l], %[h], %[a], %[b]	\n\t"            \
        "mov	%[o], #0		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "=r" (vo)    \
        : [a] "r" (va), [b] "r" (vb)                     \
        :                                                \
    )
/* Multiply va by vb and add double size result into: vo | vh | vl */
#define SP_ASM_MUL_ADD(vl, vh, vo, va, vb)               \
    __asm__ __volatile__ (                               \
        "umull	r8, r9, %[a], %[b]	\n\t"            \
        "adds	%[l], %[l], r8		\n\t"            \
        "adcs	%[h], %[h], r9		\n\t"            \
        "adc	%[o], %[o], #0		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "r8", "r9", "cc"                               \
    )
/* Multiply va by vb and add double size result into: vh | vl */
#define SP_ASM_MUL_ADD_NO(vl, vh, va, vb)                \
    __asm__ __volatile__ (                               \
        "umlal	%[l], %[h], %[a], %[b]	\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "r" (va), [b] "r" (vb)                     \
        :                                                \
    )
/* Multiply va by vb and add double size result twice into: vo | vh | vl */
#define SP_ASM_MUL_ADD2(vl, vh, vo, va, vb)              \
    __asm__ __volatile__ (                               \
        "umull	r8, r9, %[a], %[b]	\n\t"            \
        "adds	%[l], %[l], r8		\n\t"            \
        "adcs	%[h], %[h], r9		\n\t"            \
        "adc	%[o], %[o], #0		\n\t"            \
        "adds	%[l], %[l], r8		\n\t"            \
        "adcs	%[h], %[h], r9		\n\t"            \
        "adc	%[o], %[o], #0		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "r8", "r9", "cc"                               \
    )
/* Multiply va by vb and add double size result twice into: vo | vh | vl
 * Assumes first add will not overflow vh | vl
 */
#define SP_ASM_MUL_ADD2_NO(vl, vh, vo, va, vb)           \
    __asm__ __volatile__ (                               \
        "umull	r8, r9, %[a], %[b]	\n\t"            \
        "adds	%[l], %[l], r8		\n\t"            \
        "adc	%[h], %[h], r9		\n\t"            \
        "adds	%[l], %[l], r8		\n\t"            \
        "adcs	%[h], %[h], r9		\n\t"            \
        "adc	%[o], %[o], #0		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "r8", "r9", "cc"                               \
    )
/* Square va and store double size result in: vh | vl */
#define SP_ASM_SQR(vl, vh, va)                           \
    __asm__ __volatile__ (                               \
        "umull	%[l], %[h], %[a], %[a]	\n\t"            \
        : [h] "+r" (vh), [l] "+r" (vl)                   \
        : [a] "r" (va)                                   \
        : "memory"                                       \
    )
/* Square va and add double size result into: vo | vh | vl */
#define SP_ASM_SQR_ADD(vl, vh, vo, va)                   \
    __asm__ __volatile__ (                               \
        "umull	r8, r9, %[a], %[a]	\n\t"            \
        "adds	%[l], %[l], r8		\n\t"            \
        "adcs	%[h], %[h], r9		\n\t"            \
        "adc	%[o], %[o], #0		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va)                                   \
        : "r8", "r9", "cc"                               \
    )
/* Square va and add double size result into: vh | vl */
#define SP_ASM_SQR_ADD_NO(vl, vh, va)                    \
    __asm__ __volatile__ (                               \
        "umlal	%[l], %[h], %[a], %[a]	\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "r" (va)                                   \
        : "cc"                                           \
    )
/* Add va into: vh | vl */
#define SP_ASM_ADDC(vl, vh, va)                          \
    __asm__ __volatile__ (                               \
        "adds	%[l], %[l], %[a]	\n\t"            \
        "adc	%[h], %[h], #0		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "r" (va)                                   \
        : "cc"                                           \
    )
/* Sub va from: vh | vl */
#define SP_ASM_SUBC(vl, vh, va)                          \
    __asm__ __volatile__ (                               \
        "subs	%[l], %[l], %[a]	\n\t"            \
        "sbc	%[h], %[h], #0		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "r" (va)                                   \
        : "cc"                                           \
    )
/* Add two times vc | vb | va into vo | vh | vl */
#define SP_ASM_ADD_DBL_3(vl, vh, vo, va, vb, vc)         \
    __asm__ __volatile__ (                               \
        "adds	%[l], %[l], %[a]	\n\t"            \
        "adcs	%[h], %[h], %[b]	\n\t"            \
        "adc	%[o], %[o], %[c]	\n\t"            \
        "adds	%[l], %[l], %[a]	\n\t"            \
        "adcs	%[h], %[h], %[b]	\n\t"            \
        "adc	%[o], %[o], %[c]	\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va), [b] "r" (vb), [c] "r" (vc)       \
        : "cc"                                           \
    )

#ifndef WOLFSSL_SP_DIV_WORD_HALF
#ifndef WOLFSSL_SP_ARM32_UDIV
/* Divide a two digit number by a digit number and return. (hi | lo) / d
 *
 * No division instruction used - does operation bit by bit.
 * Constant time.
 *
 * @param  [in]  hi  SP integer digit. High digit of the dividend.
 * @param  [in]  lo  SP integer digit. Lower digit of the dividend.
 * @param  [in]  d   SP integer digit. Number to divide by.
 * @return  The division result.
 */
static WC_INLINE sp_int_digit sp_div_word(sp_int_digit hi, sp_int_digit lo,
                                          sp_int_digit d)
{
    sp_int_digit r = 0;

    __asm__ __volatile__ (
        "lsrs	r5, %[d], #24\n\t"
	"it	eq\n\t"
        "moveq	r5, #8\n\t"
	"it	ne\n\t"
        "movne	r5, #0\n\t"
        "rsb	r6, r5, #31\n\t"
        "lsl	%[d], %[d], r5\n\t"
        "lsl	%[hi], %[hi], r5\n\t"
        "lsr	r7, %[lo], r6\n\t"
        "lsl	%[lo], %[lo], r5\n\t"
        "orr	%[hi], %[hi], r7, lsr #1\n\t"

        "lsr	r5, %[d], #1\n\t"
        "add	r5, r5, #1\n\t"
        "mov	r6, %[lo]\n\t"
        "mov	r7, %[hi]\n\t"
        "# Do top 32\n\t"
        "subs	r8, r5, r7\n\t"
        "sbc	r8, r8, r8\n\t"
        "add	%[r], %[r], %[r]\n\t"
        "sub	%[r], %[r], r8\n\t"
        "and	r8, r8, r5\n\t"
        "subs	r7, r7, r8\n\t"
        "# Next 30 bits\n\t"
        "mov	r4, #29\n\t"
        "1:\n\t"
        "movs	r6, r6, lsl #1\n\t"
        "adc	r7, r7, r7\n\t"
        "subs	r8, r5, r7\n\t"
        "sbc	r8, r8, r8\n\t"
        "add	%[r], %[r], %[r]\n\t"
        "sub	%[r], %[r], r8\n\t"
        "and	r8, r8, r5\n\t"
        "subs	r7, r7, r8\n\t"
        "subs	r4, r4, #1\n\t"
        "bpl	1b\n\t"
        "add	%[r], %[r], %[r]\n\t"
        "add	%[r], %[r], #1\n\t"
        "umull	r4, r5, %[r], %[d]\n\t"
        "subs	r4, %[lo], r4\n\t"
        "sbc	r5, %[hi], r5\n\t"
        "add	%[r], %[r], r5\n\t"
        "umull	r4, r5, %[r], %[d]\n\t"
        "subs	r4, %[lo], r4\n\t"
        "sbc	r5, %[hi], r5\n\t"
        "add	%[r], %[r], r5\n\t"
        "umull	r4, r5, %[r], %[d]\n\t"
        "subs	r4, %[lo], r4\n\t"
        "sbc	r5, %[hi], r5\n\t"
        "add	%[r], %[r], r5\n\t"
        "subs	r8, %[d], r4\n\t"
        "sbc	r8, r8, r8\n\t"
        "sub	%[r], %[r], r8\n\t"
        : [r] "+r" (r), [hi] "+r" (hi), [lo] "+r" (lo), [d] "+r" (d)
        :
        : "r4", "r5", "r6", "r7", "r8"
    );

    return r;
}
#else
/* Divide a two digit number by a digit number and return. (hi | lo) / d
 *
 * Using udiv instruction on arm32
 * Constant time.
 *
 * @param  [in]  hi  SP integer digit. High digit of the dividend.
 * @param  [in]  lo  SP integer digit. Lower digit of the dividend.
 * @param  [in]  d   SP integer digit. Number to divide by.
 * @return  The division result.
 */
static WC_INLINE sp_int_digit sp_div_word(sp_int_digit hi, sp_int_digit lo,
                                          sp_int_digit d)
{
    __asm__ __volatile__ (
        "lsrs	r3, %[d], #24\n\t"
	"it	eq\n\t"
        "moveq	r3, #8\n\t"
	"it	ne\n\t"
        "movne	r3, #0\n\t"
        "rsb	r4, r3, #31\n\t"
        "lsl	%[d], %[d], r3\n\t"
        "lsl	%[hi], %[hi], r3\n\t"
        "lsr	r5, %[lo], r4\n\t"
        "lsl	%[lo], %[lo], r3\n\t"
        "orr	%[hi], %[hi], r5, lsr #1\n\t"

        "lsr	r5, %[d], 16\n\t"
        "add	r5, r5, 1\n\t"

        "udiv	r3, %[hi], r5\n\t"
        "lsl	r6, r3, 16\n\t"
        "umull	r4, r3, %[d], r6\n\t"
        "subs	%[lo], %[lo], r4\n\t"
        "sbc	%[hi], %[hi], r3\n\t"

        "udiv	r3, %[hi], r5\n\t"
        "lsl	r3, r3, 16\n\t"
        "add	r6, r6, r3\n\t"
        "umull	r4, r3, %[d], r3\n\t"
        "subs	%[lo], %[lo], r4\n\t"
        "sbc	%[hi], %[hi], r3\n\t"

        "lsr	r3, %[lo], 16\n\t"
        "orr	r3, r3, %[hi], lsl 16\n\t"

        "udiv	r3, r3, r5\n\t"
        "add	r6, r6, r3\n\t"
        "umull	r4, r3, %[d], r3\n\t"
        "subs	%[lo], %[lo], r4\n\t"
        "sbc	%[hi], %[hi], r3\n\t"

        "lsr	r3, %[lo], 16\n\t"
        "orr	r3, r3, %[hi], lsl 16\n\t"

        "udiv	r3, r3, r5\n\t"
        "add	r6, r6, r3\n\t"
        "mul	r4, %[d], r3\n\t"
        "sub	%[lo], %[lo], r4\n\t"

        "udiv	r3, %[lo], %[d]\n\t"
        "add	%[hi], r6, r3\n\t"

        : [hi] "+r" (hi), [lo] "+r" (lo), [d] "+r" (d)
        :
        : "r3", "r4", "r5", "r6"
    );

    return hi;
}
#endif

#define SP_ASM_DIV_WORD
#endif

#define SP_INT_ASM_AVAILABLE

    #endif /* (WOLFSSL_SP_ARM32 || ARM_CORTEX_M) && SP_WORD_SIZE == 32 */

    #if defined(WOLFSSL_SP_ARM_THUMB) && SP_WORD_SIZE == 32
/*
 * CPU: ARM Thumb (like Cortex-M0)
 */

/* Compile with -fomit-frame-pointer, or similar, if compiler complains about
 * usage of register 'r7'.
 */

#if defined(__clang__)

/* Multiply va by vb and store double size result in: vh | vl */
#define SP_ASM_MUL(vl, vh, va, vb)                       \
    __asm__ __volatile__ (                               \
        /* al * bl */                                    \
        "uxth	r6, %[a]		\n\t"            \
        "uxth	%[l], %[b]		\n\t"            \
        "muls	%[l], r6		\n\t"            \
        /* al * bh */                                    \
        "lsrs	r4, %[b], #16		\n\t"            \
        "muls	r6, r4			\n\t"            \
        "lsrs	%[h], r6, #16		\n\t"            \
        "lsls	r6, r6, #16		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "movs	r5, #0			\n\t"            \
        "adcs	%[h], r5		\n\t"            \
        /* ah * bh */                                    \
        "lsrs	r6, %[a], #16		\n\t"            \
        "muls	r4, r6			\n\t"            \
        "adds	%[h], %[h], r4		\n\t"            \
        /* ah * bl */                                    \
        "uxth	r4, %[b]		\n\t"            \
        "muls	r6, r4			\n\t"            \
        "lsrs	r4, r6, #16		\n\t"            \
        "lsls	r6, r6, #16		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], r4		\n\t"            \
        : [h] "+l" (vh), [l] "+l" (vl)                   \
        : [a] "l" (va), [b] "l" (vb)                     \
        : "r4", "r5", "r6", "cc"                         \
    )
/* Multiply va by vb and store double size result in: vo | vh | vl */
#define SP_ASM_MUL_SET(vl, vh, vo, va, vb)               \
    __asm__ __volatile__ (                               \
        /* al * bl */                                    \
        "uxth	r6, %[a]		\n\t"            \
        "uxth	%[l], %[b]		\n\t"            \
        "muls	%[l], r6		\n\t"            \
        /* al * bh */                                    \
        "lsrs	r7, %[b], #16		\n\t"            \
        "muls	r6, r7			\n\t"            \
        "lsrs	%[h], r6, #16		\n\t"            \
        "lsls	r6, r6, #16		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "movs	%[o], #0		\n\t"            \
        "adcs	%[h], %[o]		\n\t"            \
        /* ah * bh */                                    \
        "lsrs	r6, %[a], #16		\n\t"            \
        "muls	r7, r6			\n\t"            \
        "adds	%[h], %[h], r7		\n\t"            \
        /* ah * bl */                                    \
        "uxth	r7, %[b]		\n\t"            \
        "muls	r6, r7			\n\t"            \
        "lsrs	r7, r6, #16		\n\t"            \
        "lsls	r6, r6, #16		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], r7		\n\t"            \
        : [l] "+l" (vl), [h] "+l" (vh), [o] "+l" (vo)    \
        : [a] "l" (va), [b] "l" (vb)                     \
        : "r6", "r7", "cc"                               \
    )
#ifndef WOLFSSL_SP_SMALL
/* Multiply va by vb and add double size result into: vo | vh | vl */
#define SP_ASM_MUL_ADD(vl, vh, vo, va, vb)               \
    __asm__ __volatile__ (                               \
        /* al * bl */                                    \
        "uxth	r6, %[a]		\n\t"            \
        "uxth	r7, %[b]		\n\t"            \
        "muls	r7, r6			\n\t"            \
        "adds	%[l], %[l], r7		\n\t"            \
        "movs	r5, #0			\n\t"            \
        "adcs	%[h], r5		\n\t"            \
        "adcs	%[o], r5		\n\t"            \
        /* al * bh */                                    \
        "lsrs	r7, %[b], #16		\n\t"            \
        "muls	r6, r7			\n\t"            \
        "lsrs	r7, r6, #16		\n\t"            \
        "lsls	r6, r6, #16		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], r7		\n\t"            \
        "adcs	%[o], r5		\n\t"            \
        /* ah * bh */                                    \
        "lsrs	r6, %[a], #16		\n\t"            \
        "lsrs	r7, %[b], #16		\n\t"            \
        "muls	r7, r6			\n\t"            \
        "adds	%[h], %[h], r7		\n\t"            \
        "adcs	%[o], r5		\n\t"            \
        /* ah * bl */                                    \
        "uxth	r7, %[b]		\n\t"            \
        "muls	r6, r7			\n\t"            \
        "lsrs	r7, r6, #16		\n\t"            \
        "lsls	r6, r6, #16		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], r7		\n\t"            \
        "adcs	%[o], r5		\n\t"            \
        : [l] "+l" (vl), [h] "+l" (vh), [o] "+l" (vo)    \
        : [a] "l" (va), [b] "l" (vb)                     \
        : "r5", "r6", "r7", "cc"                         \
    )
#else
/* Multiply va by vb and add double size result into: vo | vh | vl */
#define SP_ASM_MUL_ADD(vl, vh, vo, va, vb)               \
    __asm__ __volatile__ (                               \
        /* al * bl */                                    \
        "uxth	r6, %[a]		\n\t"            \
        "uxth	r5, %[b]		\n\t"            \
        "muls	r5, r6			\n\t"            \
        "adds	%[l], %[l], r5		\n\t"            \
        "movs	r5, #0			\n\t"            \
        "adcs	%[h], r5		\n\t"            \
        "adcs	%[o], r5		\n\t"            \
        /* al * bh */                                    \
        "lsrs	r5, %[b], #16		\n\t"            \
        "muls	r6, r5			\n\t"            \
        "lsrs	r5, r6, #16		\n\t"            \
        "lsls	r6, r6, #16		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], r5		\n\t"            \
        "movs	r5, #0			\n\t"            \
        "adcs	%[o], r5		\n\t"            \
        /* ah * bh */                                    \
        "lsrs	r6, %[a], #16		\n\t"            \
        "lsrs	r5, %[b], #16		\n\t"            \
        "muls	r5, r6			\n\t"            \
        "adds	%[h], %[h], r5		\n\t"            \
        "movs	r5, #0			\n\t"            \
        "adcs	%[o], r5		\n\t"            \
        /* ah * bl */                                    \
        "uxth	r5, %[b]		\n\t"            \
        "muls	r6, r5			\n\t"            \
        "lsrs	r5, r6, #16		\n\t"            \
        "lsls	r6, r6, #16		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], r5		\n\t"            \
        "movs	r5, #0			\n\t"            \
        "adcs	%[o], r5		\n\t"            \
        : [l] "+l" (vl), [h] "+l" (vh), [o] "+l" (vo)    \
        : [a] "l" (va), [b] "l" (vb)                     \
        : "r5", "r6", "cc"                               \
    )
#endif
/* Multiply va by vb and add double size result into: vh | vl */
#define SP_ASM_MUL_ADD_NO(vl, vh, va, vb)                \
    __asm__ __volatile__ (                               \
        /* al * bl */                                    \
        "uxth	r6, %[a]		\n\t"            \
        "uxth	r4, %[b]		\n\t"            \
        "muls	r4, r6			\n\t"            \
        "adds	%[l], %[l], r4		\n\t"            \
        "movs	r5, #0			\n\t"            \
        "adcs	%[h], r5		\n\t"            \
        /* al * bh */                                    \
        "lsrs	r4, %[b], #16		\n\t"            \
        "muls	r6, r4			\n\t"            \
        "lsrs	r4, r6, #16		\n\t"            \
        "lsls	r6, r6, #16		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], r4		\n\t"            \
        /* ah * bh */                                    \
        "lsrs	r6, %[a], #16		\n\t"            \
        "lsrs	r4, %[b], #16		\n\t"            \
        "muls	r4, r6			\n\t"            \
        "adds	%[h], %[h], r4		\n\t"            \
        /* ah * bl */                                    \
        "uxth	r4, %[b]		\n\t"            \
        "muls	r6, r4			\n\t"            \
        "lsrs	r4, r6, #16		\n\t"            \
        "lsls	r6, r6, #16		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], r4		\n\t"            \
        : [l] "+l" (vl), [h] "+l" (vh)                   \
        : [a] "l" (va), [b] "l" (vb)                     \
        : "r4", "r5", "r6", "cc"                         \
    )
#ifndef WOLFSSL_SP_SMALL
/* Multiply va by vb and add double size result twice into: vo | vh | vl */
#define SP_ASM_MUL_ADD2(vl, vh, vo, va, vb)              \
    __asm__ __volatile__ (                               \
        /* al * bl */                                    \
        "uxth	r6, %[a]		\n\t"            \
        "uxth	r7, %[b]		\n\t"            \
        "muls	r7, r6			\n\t"            \
        "adds	%[l], %[l], r7		\n\t"            \
        "movs	r5, #0			\n\t"            \
        "adcs	%[h], r5		\n\t"            \
        "adcs	%[o], r5		\n\t"            \
        "adds	%[l], %[l], r7		\n\t"            \
        "adcs	%[h], r5		\n\t"            \
        "adcs	%[o], r5		\n\t"            \
        /* al * bh */                                    \
        "lsrs	r7, %[b], #16		\n\t"            \
        "muls	r6, r7			\n\t"            \
        "lsrs	r7, r6, #16		\n\t"            \
        "lsls	r6, r6, #16		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], r7		\n\t"            \
        "adcs	%[o], r5		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], r7		\n\t"            \
        "adcs	%[o], r5		\n\t"            \
        /* ah * bh */                                    \
        "lsrs	r6, %[a], #16		\n\t"            \
        "lsrs	r7, %[b], #16		\n\t"            \
        "muls	r7, r6			\n\t"            \
        "adds	%[h], %[h], r7		\n\t"            \
        "adcs	%[o], r5		\n\t"            \
        "adds	%[h], %[h], r7		\n\t"            \
        "adcs	%[o], r5		\n\t"            \
        /* ah * bl */                                    \
        "uxth	r7, %[b]		\n\t"            \
        "muls	r6, r7			\n\t"            \
        "lsrs	r7, r6, #16		\n\t"            \
        "lsls	r6, r6, #16		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], r7		\n\t"            \
        "adcs	%[o], r5		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], r7		\n\t"            \
        "adcs	%[o], r5		\n\t"            \
        : [l] "+l" (vl), [h] "+l" (vh), [o] "+l" (vo)    \
        : [a] "l" (va), [b] "l" (vb)                     \
        : "r5", "r6", "r7", "cc"                         \
    )
#else
/* Multiply va by vb and add double size result twice into: vo | vh | vl */
#define SP_ASM_MUL_ADD2(vl, vh, vo, va, vb)              \
    __asm__ __volatile__ (                               \
        "movs	r8, %[a]		\n\t"            \
        /* al * bl */                                    \
        "uxth	r6, %[a]		\n\t"            \
        "uxth	r5, %[b]		\n\t"            \
        "muls	r5, r6			\n\t"            \
        "adds	%[l], %[l], r5		\n\t"            \
        "movs	%[a], #0		\n\t"            \
        "adcs	%[h], %[a]		\n\t"            \
        "adcs	%[o], %[a]		\n\t"            \
        "adds	%[l], %[l], r5		\n\t"            \
        "adcs	%[h], %[a]		\n\t"            \
        "adcs	%[o], %[a]		\n\t"            \
        /* al * bh */                                    \
        "lsrs	r5, %[b], #16		\n\t"            \
        "muls	r6, r5			\n\t"            \
        "lsrs	r5, r6, #16		\n\t"            \
        "lsls	r6, r6, #16		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], r5		\n\t"            \
        "adcs	%[o], %[a]		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], r5		\n\t"            \
        "adcs	%[o], %[a]		\n\t"            \
        /* ah * bh */                                    \
        "movs	%[a], r8		\n\t"            \
        "lsrs	r6, %[a], #16		\n\t"            \
        "lsrs	r5, %[b], #16		\n\t"            \
        "muls	r5, r6			\n\t"            \
        "adds	%[h], %[h], r5		\n\t"            \
        "movs	%[a], #0		\n\t"            \
        "adcs	%[o], %[a]		\n\t"            \
        "adds	%[h], %[h], r5		\n\t"            \
        "adcs	%[o], %[a]		\n\t"            \
        /* ah * bl */                                    \
        "uxth	r5, %[b]		\n\t"            \
        "muls	r6, r5			\n\t"            \
        "lsrs	r5, r6, #16		\n\t"            \
        "lsls	r6, r6, #16		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], r5		\n\t"            \
        "adcs	%[o], %[a]		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], r5		\n\t"            \
        "adcs	%[o], %[a]		\n\t"            \
        "movs	%[a], r8		\n\t"            \
        : [l] "+l" (vl), [h] "+l" (vh), [o] "+l" (vo)    \
        : [a] "l" (va), [b] "l" (vb)                     \
        : "r5", "r6", "r8", "cc"                         \
    )
#endif
/* Multiply va by vb and add double size result twice into: vo | vh | vl
 * Assumes first add will not overflow vh | vl
 */
#define SP_ASM_MUL_ADD2_NO(vl, vh, vo, va, vb)           \
    __asm__ __volatile__ (                               \
        /* al * bl */                                    \
        "uxth	r6, %[a]		\n\t"            \
        "uxth	r7, %[b]		\n\t"            \
        "muls	r7, r6			\n\t"            \
        "adds	%[l], %[l], r7		\n\t"            \
        "movs	r5, #0			\n\t"            \
        "adcs	%[h], r5		\n\t"            \
        "adds	%[l], %[l], r7		\n\t"            \
        "adcs	%[h], r5		\n\t"            \
        /* al * bh */                                    \
        "lsrs	r7, %[b], #16		\n\t"            \
        "muls	r6, r7			\n\t"            \
        "lsrs	r7, r6, #16		\n\t"            \
        "lsls	r6, r6, #16		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], r7		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], r7		\n\t"            \
        "adcs	%[o], r5		\n\t"            \
        /* ah * bh */                                    \
        "lsrs	r6, %[a], #16		\n\t"            \
        "lsrs	r7, %[b], #16		\n\t"            \
        "muls	r7, r6			\n\t"            \
        "adds	%[h], %[h], r7		\n\t"            \
        "adcs	%[o], r5		\n\t"            \
        "adds	%[h], %[h], r7		\n\t"            \
        "adcs	%[o], r5		\n\t"            \
        /* ah * bl */                                    \
        "uxth	r7, %[b]		\n\t"            \
        "muls	r6, r7			\n\t"            \
        "lsrs	r7, r6, #16		\n\t"            \
        "lsls	r6, r6, #16		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], r7		\n\t"            \
        "adcs	%[o], r5		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], r7		\n\t"            \
        "adcs	%[o], r5		\n\t"            \
        : [l] "+l" (vl), [h] "+l" (vh), [o] "+l" (vo)    \
        : [a] "l" (va), [b] "l" (vb)                     \
        : "r5", "r6", "r7", "cc"                         \
    )
/* Square va and store double size result in: vh | vl */
#define SP_ASM_SQR(vl, vh, va)                           \
    __asm__ __volatile__ (                               \
        "lsrs	r5, %[a], #16		\n\t"            \
        "uxth	r6, %[a]		\n\t"            \
        "mov	%[l], r6		\n\t"            \
        "mov	%[h], r5		\n\t"            \
        /* al * al */                                    \
        "muls	%[l], %[l]		\n\t"            \
        /* ah * ah */                                    \
        "muls	%[h], %[h]		\n\t"            \
        /* 2 * al * ah */                                \
        "muls	r6, r5			\n\t"            \
        "lsrs	r5, r6, #15		\n\t"            \
        "lsls	r6, r6, #17		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], r5		\n\t"            \
        : [h] "+l" (vh), [l] "+l" (vl)                   \
        : [a] "l" (va)                                   \
        : "r5", "r6", "cc"                               \
    )
/* Square va and add double size result into: vo | vh | vl */
#define SP_ASM_SQR_ADD(vl, vh, vo, va)                   \
    __asm__ __volatile__ (                               \
        "lsrs	r4, %[a], #16		\n\t"            \
        "uxth	r6, %[a]		\n\t"            \
        /* al * al */                                    \
        "muls	r6, r6			\n\t"            \
        /* ah * ah */                                    \
        "muls	r4, r4			\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], r4		\n\t"            \
        "movs	r5, #0			\n\t"            \
        "adcs	%[o], r5		\n\t"            \
        "lsrs	r4, %[a], #16		\n\t"            \
        "uxth	r6, %[a]		\n\t"            \
        /* 2 * al * ah */                                \
        "muls	r6, r4			\n\t"            \
        "lsrs	r4, r6, #15		\n\t"            \
        "lsls	r6, r6, #17		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], r4		\n\t"            \
        "adcs	%[o], r5		\n\t"            \
        : [l] "+l" (vl), [h] "+l" (vh), [o] "+l" (vo)    \
        : [a] "l" (va)                                   \
        : "r4", "r5", "r6", "cc"                         \
    )
/* Square va and add double size result into: vh | vl */
#define SP_ASM_SQR_ADD_NO(vl, vh, va)                    \
    __asm__ __volatile__ (                               \
        "lsrs	r7, %[a], #16		\n\t"            \
        "uxth	r6, %[a]		\n\t"            \
        /* al * al */                                    \
        "muls	r6, r6			\n\t"            \
        /* ah * ah */                                    \
        "muls	r7, r7			\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], r7		\n\t"            \
        "lsrs	r7, %[a], #16		\n\t"            \
        "uxth	r6, %[a]		\n\t"            \
        /* 2 * al * ah */                                \
        "muls	r6, r7			\n\t"            \
        "lsrs	r7, r6, #15		\n\t"            \
        "lsls	r6, r6, #17		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], r7		\n\t"            \
        : [l] "+l" (vl), [h] "+l" (vh)                   \
        : [a] "l" (va)                                   \
        : "r6", "r7", "cc"                               \
    )
/* Add va into: vh | vl */
#define SP_ASM_ADDC(vl, vh, va)                          \
    __asm__ __volatile__ (                               \
        "adds	%[l], %[l], %[a]	\n\t"            \
        "movs	r5, #0			\n\t"            \
        "adcs	%[h], r5		\n\t"            \
        : [l] "+l" (vl), [h] "+l" (vh)                   \
        : [a] "l" (va)                                   \
        : "r5", "cc"                                     \
    )
/* Sub va from: vh | vl */
#define SP_ASM_SUBC(vl, vh, va)                          \
    __asm__ __volatile__ (                               \
        "subs	%[l], %[l], %[a]	\n\t"            \
        "movs	r5, #0			\n\t"            \
        "sbcs	%[h], r5		\n\t"            \
        : [l] "+l" (vl), [h] "+l" (vh)                   \
        : [a] "l" (va)                                   \
        : "r5", "cc"                                     \
    )
/* Add two times vc | vb | va into vo | vh | vl */
#define SP_ASM_ADD_DBL_3(vl, vh, vo, va, vb, vc)         \
    __asm__ __volatile__ (                               \
        "adds	%[l], %[l], %[a]	\n\t"            \
        "adcs	%[h], %[b]		\n\t"            \
        "adcs	%[o], %[c]		\n\t"            \
        "adds	%[l], %[l], %[a]	\n\t"            \
        "adcs	%[h], %[b]		\n\t"            \
        "adcs	%[o], %[c]		\n\t"            \
        : [l] "+l" (vl), [h] "+l" (vh), [o] "+l" (vo)    \
        : [a] "l" (va), [b] "l" (vb), [c] "l" (vc)       \
        : "cc"                                           \
    )

#elif defined(WOLFSSL_KEIL)

/* Multiply va by vb and store double size result in: vh | vl */
#define SP_ASM_MUL(vl, vh, va, vb)                       \
    __asm__ __volatile__ (                               \
        /* al * bl */                                    \
        "uxth	r6, %[a]		\n\t"            \
        "uxth	%[l], %[b]		\n\t"            \
        "muls	%[l], r6, %[l]		\n\t"            \
        /* al * bh */                                    \
        "lsrs	r4, %[b], #16		\n\t"            \
        "muls	r6, r4, r6		\n\t"            \
        "lsrs	%[h], r6, #16		\n\t"            \
        "lsls	r6, r6, #16		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "movs	r5, #0			\n\t"            \
        "adcs	%[h], %[h], r5		\n\t"            \
        /* ah * bh */                                    \
        "lsrs	r6, %[a], #16		\n\t"            \
        "muls	r4, r6, r4		\n\t"            \
        "adds	%[h], %[h], r4		\n\t"            \
        /* ah * bl */                                    \
        "uxth	r4, %[b]		\n\t"            \
        "muls	r6, r4, r6		\n\t"            \
        "lsrs	r4, r6, #16		\n\t"            \
        "lsls	r6, r6, #16		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], %[h], r4		\n\t"            \
        : [h] "+l" (vh), [l] "+l" (vl)                   \
        : [a] "l" (va), [b] "l" (vb)                     \
        : "r4", "r5", "r6", "cc"                         \
    )
/* Multiply va by vb and store double size result in: vo | vh | vl */
#define SP_ASM_MUL_SET(vl, vh, vo, va, vb)               \
    __asm__ __volatile__ (                               \
        /* al * bl */                                    \
        "uxth	r6, %[a]		\n\t"            \
        "uxth	%[l], %[b]		\n\t"            \
        "muls	%[l], r6, %[l]		\n\t"            \
        /* al * bh */                                    \
        "lsrs	r7, %[b], #16		\n\t"            \
        "muls	r6, r7, r6		\n\t"            \
        "lsrs	%[h], r6, #16		\n\t"            \
        "lsls	r6, r6, #16		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "movs	%[o], #0		\n\t"            \
        "adcs	%[h], %[h], %[o]	\n\t"            \
        /* ah * bh */                                    \
        "lsrs	r6, %[a], #16		\n\t"            \
        "muls	r7, r6, r7		\n\t"            \
        "adds	%[h], %[h], r7		\n\t"            \
        /* ah * bl */                                    \
        "uxth	r7, %[b]		\n\t"            \
        "muls	r6, r7, r6		\n\t"            \
        "lsrs	r7, r6, #16		\n\t"            \
        "lsls	r6, r6, #16		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], %[h], r7		\n\t"            \
        : [l] "+l" (vl), [h] "+l" (vh), [o] "+l" (vo)    \
        : [a] "l" (va), [b] "l" (vb)                     \
        : "r6", "r7", "cc"                               \
    )
#ifndef WOLFSSL_SP_SMALL
/* Multiply va by vb and add double size result into: vo | vh | vl */
#define SP_ASM_MUL_ADD(vl, vh, vo, va, vb)               \
    __asm__ __volatile__ (                               \
        /* al * bl */                                    \
        "uxth	r6, %[a]		\n\t"            \
        "uxth	r7, %[b]		\n\t"            \
        "muls	r7, r6, r7		\n\t"            \
        "adds	%[l], %[l], r7		\n\t"            \
        "movs	r5, #0			\n\t"            \
        "adcs	%[h], %[h], r5		\n\t"            \
        "adcs	%[o], %[o], r5		\n\t"            \
        /* al * bh */                                    \
        "lsrs	r7, %[b], #16		\n\t"            \
        "muls	r6, r7, r6		\n\t"            \
        "lsrs	r7, r6, #16		\n\t"            \
        "lsls	r6, r6, #16		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], %[h], r7		\n\t"            \
        "adcs	%[o], %[o], r5		\n\t"            \
        /* ah * bh */                                    \
        "lsrs	r6, %[a], #16		\n\t"            \
        "lsrs	r7, %[b], #16		\n\t"            \
        "muls	r7, r6, r7		\n\t"            \
        "adds	%[h], %[h], r7		\n\t"            \
        "adcs	%[o], %[o], r5		\n\t"            \
        /* ah * bl */                                    \
        "uxth	r7, %[b]		\n\t"            \
        "muls	r6, r7, r6		\n\t"            \
        "lsrs	r7, r6, #16		\n\t"            \
        "lsls	r6, r6, #16		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], %[h], r7		\n\t"            \
        "adcs	%[o], %[o], r5		\n\t"            \
        : [l] "+l" (vl), [h] "+l" (vh), [o] "+l" (vo)    \
        : [a] "l" (va), [b] "l" (vb)                     \
        : "r5", "r6", "r7", "cc"                         \
    )
#else
#define SP_ASM_MUL_ADD(vl, vh, vo, va, vb)               \
    __asm__ __volatile__ (                               \
        /* al * bl */                                    \
        "uxth   r6, %[a]                \n\t"            \
        "uxth   r5, %[b]                \n\t"            \
        "muls   r5, r6, r5              \n\t"            \
        "adds   %[l], %[l], r5          \n\t"            \
        "movs   r5, #0                  \n\t"            \
        "adcs   %[h], %[h], r5          \n\t"            \
        "adcs   %[o], %[o], r5          \n\t"            \
        /* al * bh */                                    \
        "lsrs   r5, %[b], #16           \n\t"            \
        "muls   r6, r5, r6              \n\t"            \
        "lsrs   r5, r6, #16             \n\t"            \
        "lsls   r6, r6, #16             \n\t"            \
        "adds   %[l], %[l], r6          \n\t"            \
        "adcs   %[h], %[h], r5          \n\t"            \
        "movs   r5, #0                  \n\t"            \
        "adcs   %[o], %[o], r5          \n\t"            \
        /* ah * bh */                                    \
        "lsrs   r6, %[a], #16           \n\t"            \
        "lsrs   r5, %[b], #16           \n\t"            \
        "muls   r5, r6, r5              \n\t"            \
        "adds   %[h], %[h], r5          \n\t"            \
        "movs   r5, #0                  \n\t"            \
        "adcs   %[o], %[o], r5          \n\t"            \
        /* ah * bl */                                    \
        "uxth   r5, %[b]                \n\t"            \
        "muls   r6, r5, r6              \n\t"            \
        "lsrs   r5, r6, #16             \n\t"            \
        "lsls   r6, r6, #16             \n\t"            \
        "adds   %[l], %[l], r6          \n\t"            \
        "adcs   %[h], %[h], r5          \n\t"            \
        "movs   r5, #0                  \n\t"            \
        "adcs   %[o], %[o], r5          \n\t"            \
        : [l] "+l" (vl), [h] "+l" (vh), [o] "+l" (vo)    \
        : [a] "l" (va), [b] "l" (vb)                     \
        : "r5", "r6", "cc"                               \
    )
#endif
/* Multiply va by vb and add double size result into: vh | vl */
#define SP_ASM_MUL_ADD_NO(vl, vh, va, vb)                \
    __asm__ __volatile__ (                               \
        /* al * bl */                                    \
        "uxth	r6, %[a]		\n\t"            \
        "uxth	r4, %[b]		\n\t"            \
        "muls	r4, r6, r4		\n\t"            \
        "adds	%[l], %[l], r4		\n\t"            \
        "movs	r5, #0			\n\t"            \
        "adcs	%[h], %[h], r5		\n\t"            \
        /* al * bh */                                    \
        "lsrs	r4, %[b], #16		\n\t"            \
        "muls	r6, r4, r6		\n\t"            \
        "lsrs	r4, r6, #16		\n\t"            \
        "lsls	r6, r6, #16		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], %[h], r4		\n\t"            \
        /* ah * bh */                                    \
        "lsrs	r6, %[a], #16		\n\t"            \
        "lsrs	r4, %[b], #16		\n\t"            \
        "muls	r4, r6, r4		\n\t"            \
        "adds	%[h], %[h], r4		\n\t"            \
        /* ah * bl */                                    \
        "uxth	r4, %[b]		\n\t"            \
        "muls	r6, r4, r6		\n\t"            \
        "lsrs	r4, r6, #16		\n\t"            \
        "lsls	r6, r6, #16		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], %[h], r4		\n\t"            \
        : [l] "+l" (vl), [h] "+l" (vh)                   \
        : [a] "l" (va), [b] "l" (vb)                     \
        : "r4", "r5", "r6", "cc"                         \
    )
#ifndef WOLFSSL_SP_SMALL
/* Multiply va by vb and add double size result twice into: vo | vh | vl */
#define SP_ASM_MUL_ADD2(vl, vh, vo, va, vb)              \
    __asm__ __volatile__ (                               \
        /* al * bl */                                    \
        "uxth	r6, %[a]		\n\t"            \
        "uxth	r7, %[b]		\n\t"            \
        "muls	r7, r6, r7		\n\t"            \
        "adds	%[l], %[l], r7		\n\t"            \
        "movs	r5, #0			\n\t"            \
        "adcs	%[h], %[h], r5		\n\t"            \
        "adcs	%[o], %[o], r5		\n\t"            \
        "adds	%[l], %[l], r7		\n\t"            \
        "adcs	%[h], %[h], r5		\n\t"            \
        "adcs	%[o], %[o], r5		\n\t"            \
        /* al * bh */                                    \
        "lsrs	r7, %[b], #16		\n\t"            \
        "muls	r6, r7, r6		\n\t"            \
        "lsrs	r7, r6, #16		\n\t"            \
        "lsls	r6, r6, #16		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], %[h], r7		\n\t"            \
        "adcs	%[o], %[o], r5		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], %[h], r7		\n\t"            \
        "adcs	%[o], %[o], r5		\n\t"            \
        /* ah * bh */                                    \
        "lsrs	r6, %[a], #16		\n\t"            \
        "lsrs	r7, %[b], #16		\n\t"            \
        "muls	r7, r6, r7		\n\t"            \
        "adds	%[h], %[h], r7		\n\t"            \
        "adcs	%[o], %[o], r5		\n\t"            \
        "adds	%[h], %[h], r7		\n\t"            \
        "adcs	%[o], %[o], r5		\n\t"            \
        /* ah * bl */                                    \
        "uxth	r7, %[b]		\n\t"            \
        "muls	r6, r7, r6		\n\t"            \
        "lsrs	r7, r6, #16		\n\t"            \
        "lsls	r6, r6, #16		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], %[h], r7		\n\t"            \
        "adcs	%[o], %[o], r5		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], %[h], r7		\n\t"            \
        "adcs	%[o], %[o], r5		\n\t"            \
        : [l] "+l" (vl), [h] "+l" (vh), [o] "+l" (vo)    \
        : [a] "l" (va), [b] "l" (vb)                     \
        : "r5", "r6", "r7", "cc"                         \
    )
#else
/* Multiply va by vb and add double size result twice into: vo | vh | vl */
#define SP_ASM_MUL_ADD2(vl, vh, vo, va, vb)              \
    __asm__ __volatile__ (                               \
        "movs	r8, %[a]		\n\t"            \
        /* al * bl */                                    \
        "uxth	r6, %[a]		\n\t"            \
        "uxth	r5, %[b]		\n\t"            \
        "muls	r5, r6, r5		\n\t"            \
        "adds	%[l], %[l], r5		\n\t"            \
        "movs	%[a], #0		\n\t"            \
        "adcs	%[h], %[h], %[a]	\n\t"            \
        "adcs	%[o], %[o], %[a]	\n\t"            \
        "adds	%[l], %[l], r5		\n\t"            \
        "adcs	%[h], %[h], %[a]	\n\t"            \
        "adcs	%[o], %[o], %[a]	\n\t"            \
        /* al * bh */                                    \
        "lsrs	r5, %[b], #16		\n\t"            \
        "muls	r6, r5, r6		\n\t"            \
        "lsrs	r5, r6, #16		\n\t"            \
        "lsls	r6, r6, #16		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], %[h], r5		\n\t"            \
        "adcs	%[o], %[o], %[a]	\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], %[h], r5		\n\t"            \
        "adcs	%[o], %[o], %[a]	\n\t"            \
        /* ah * bh */                                    \
        "movs	%[a], r8		\n\t"            \
        "lsrs	r6, %[a], #16		\n\t"            \
        "lsrs	r5, %[b], #16		\n\t"            \
        "muls	r5, r6, r5		\n\t"            \
        "adds	%[h], %[h], r5		\n\t"            \
        "movs	%[a], #0		\n\t"            \
        "adcs	%[o], %[o], %[a]	\n\t"            \
        "adds	%[h], %[h], r5		\n\t"            \
        "adcs	%[o], %[o], %[a]	\n\t"            \
        /* ah * bl */                                    \
        "uxth	r5, %[b]		\n\t"            \
        "muls	r6, r5, r6		\n\t"            \
        "lsrs	r5, r6, #16		\n\t"            \
        "lsls	r6, r6, #16		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], %[h], r5		\n\t"            \
        "adcs	%[o], %[o], %[a]	\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], %[h], r5		\n\t"            \
        "adcs	%[o], %[o], %[a]	\n\t"            \
        "movs	%[a], r8		\n\t"            \
        : [l] "+l" (vl), [h] "+l" (vh), [o] "+l" (vo)    \
        : [a] "l" (va), [b] "l" (vb)                     \
        : "r5", "r6", "r8", "cc"                         \
    )
#endif
/* Multiply va by vb and add double size result twice into: vo | vh | vl
 * Assumes first add will not overflow vh | vl
 */
#define SP_ASM_MUL_ADD2_NO(vl, vh, vo, va, vb)           \
    __asm__ __volatile__ (                               \
        /* al * bl */                                    \
        "uxth	r6, %[a]		\n\t"            \
        "uxth	r7, %[b]		\n\t"            \
        "muls	r7, r6, r7		\n\t"            \
        "adds	%[l], %[l], r7		\n\t"            \
        "movs	r5, #0			\n\t"            \
        "adcs	%[h], %[h], r5		\n\t"            \
        "adds	%[l], %[l], r7		\n\t"            \
        "adcs	%[h], %[h], r5		\n\t"            \
        /* al * bh */                                    \
        "lsrs	r7, %[b], #16		\n\t"            \
        "muls	r6, r7, r6		\n\t"            \
        "lsrs	r7, r6, #16		\n\t"            \
        "lsls	r6, r6, #16		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], %[h], r7		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], %[h], r7		\n\t"            \
        "adcs	%[o], %[o], r5		\n\t"            \
        /* ah * bh */                                    \
        "lsrs	r6, %[a], #16		\n\t"            \
        "lsrs	r7, %[b], #16		\n\t"            \
        "muls	r7, r6, r7		\n\t"            \
        "adds	%[h], %[h], r7		\n\t"            \
        "adcs	%[o], %[o], r5		\n\t"            \
        "adds	%[h], %[h], r7		\n\t"            \
        "adcs	%[o], %[o], r5		\n\t"            \
        /* ah * bl */                                    \
        "uxth	r7, %[b]		\n\t"            \
        "muls	r6, r7, r6		\n\t"            \
        "lsrs	r7, r6, #16		\n\t"            \
        "lsls	r6, r6, #16		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], %[h], r7		\n\t"            \
        "adcs	%[o], %[o], r5		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], %[h], r7		\n\t"            \
        "adcs	%[o], %[o], r5		\n\t"            \
        : [l] "+l" (vl), [h] "+l" (vh), [o] "+l" (vo)    \
        : [a] "l" (va), [b] "l" (vb)                     \
        : "r5", "r6", "r7", "cc"                         \
    )
/* Square va and store double size result in: vh | vl */
#define SP_ASM_SQR(vl, vh, va)                           \
    __asm__ __volatile__ (                               \
        "lsrs	r5, %[a], #16		\n\t"            \
        "uxth	r6, %[a]		\n\t"            \
        "mov	%[l], r6		\n\t"            \
        "mov	%[h], r5		\n\t"            \
        /* al * al */                                    \
        "muls	%[l], %[l], %[l]	\n\t"            \
        /* ah * ah */                                    \
        "muls	%[h], %[h], %[h]	\n\t"            \
        /* 2 * al * ah */                                \
        "muls	r6, r5, r6		\n\t"            \
        "lsrs	r5, r6, #15		\n\t"            \
        "lsls	r6, r6, #17		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], %[h], r5		\n\t"            \
        : [h] "+l" (vh), [l] "+l" (vl)                   \
        : [a] "l" (va)                                   \
        : "r5", "r6", "cc"                               \
    )
/* Square va and add double size result into: vo | vh | vl */
#define SP_ASM_SQR_ADD(vl, vh, vo, va)                   \
    __asm__ __volatile__ (                               \
        "lsrs	r4, %[a], #16		\n\t"            \
        "uxth	r6, %[a]		\n\t"            \
        /* al * al */                                    \
        "muls	r6, r6, r6		\n\t"            \
        /* ah * ah */                                    \
        "muls	r4, r4, r4		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], %[h], r4		\n\t"            \
        "movs	r5, #0			\n\t"            \
        "adcs	%[o], %[o], r5		\n\t"            \
        "lsrs	r4, %[a], #16		\n\t"            \
        "uxth	r6, %[a]		\n\t"            \
        /* 2 * al * ah */                                \
        "muls	r6, r4, r6		\n\t"            \
        "lsrs	r4, r6, #15		\n\t"            \
        "lsls	r6, r6, #17		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], %[h], r4		\n\t"            \
        "adcs	%[o], %[o], r5		\n\t"            \
        : [l] "+l" (vl), [h] "+l" (vh), [o] "+l" (vo)    \
        : [a] "l" (va)                                   \
        : "r4", "r5", "r6", "cc"                         \
    )
/* Square va and add double size result into: vh | vl */
#define SP_ASM_SQR_ADD_NO(vl, vh, va)                    \
    __asm__ __volatile__ (                               \
        "lsrs	r7, %[a], #16		\n\t"            \
        "uxth	r6, %[a]		\n\t"            \
        /* al * al */                                    \
        "muls	r6, r6, r6		\n\t"            \
        /* ah * ah */                                    \
        "muls	r7, r7, r7		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], %[h], r7		\n\t"            \
        "lsrs	r7, %[a], #16		\n\t"            \
        "uxth	r6, %[a]		\n\t"            \
        /* 2 * al * ah */                                \
        "muls	r6, r7, r6		\n\t"            \
        "lsrs	r7, r6, #15		\n\t"            \
        "lsls	r6, r6, #17		\n\t"            \
        "adds	%[l], %[l], r6		\n\t"            \
        "adcs	%[h], %[h], r7		\n\t"            \
        : [l] "+l" (vl), [h] "+l" (vh)                   \
        : [a] "l" (va)                                   \
        : "r6", "r7", "cc"                               \
    )
/* Add va into: vh | vl */
#define SP_ASM_ADDC(vl, vh, va)                          \
    __asm__ __volatile__ (                               \
        "adds	%[l], %[l], %[a]	\n\t"            \
        "movs	r5, #0			\n\t"            \
        "adcs	%[h], %[h], r5		\n\t"            \
        : [l] "+l" (vl), [h] "+l" (vh)                   \
        : [a] "l" (va)                                   \
        : "r5", "cc"                                     \
    )
/* Sub va from: vh | vl */
#define SP_ASM_SUBC(vl, vh, va)                          \
    __asm__ __volatile__ (                               \
        "subs	%[l], %[l], %[a]	\n\t"            \
        "movs	r5, #0			\n\t"            \
        "sbcs	%[h], %[h], r5		\n\t"            \
        : [l] "+l" (vl), [h] "+l" (vh)                   \
        : [a] "l" (va)                                   \
        : "r5", "cc"                                     \
    )
/* Add two times vc | vb | va into vo | vh | vl */
#define SP_ASM_ADD_DBL_3(vl, vh, vo, va, vb, vc)         \
    __asm__ __volatile__ (                               \
        "adds	%[l], %[l], %[a]	\n\t"            \
        "adcs	%[h], %[h], %[b]	\n\t"            \
        "adcs	%[o], %[o], %[c]	\n\t"            \
        "adds	%[l], %[l], %[a]	\n\t"            \
        "adcs	%[h], %[h], %[b]	\n\t"            \
        "adcs	%[o], %[o], %[c]	\n\t"            \
        : [l] "+l" (vl), [h] "+l" (vh), [o] "+l" (vo)    \
        : [a] "l" (va), [b] "l" (vb), [c] "l" (vc)       \
        : "cc"                                           \
    )

#elif defined(__GNUC__)

/* Multiply va by vb and store double size result in: vh | vl */
#define SP_ASM_MUL(vl, vh, va, vb)                       \
    __asm__ __volatile__ (                               \
        /* al * bl */                                    \
        "uxth	r6, %[a]		\n\t"            \
        "uxth	%[l], %[b]		\n\t"            \
        "mul	%[l], r6		\n\t"            \
        /* al * bh */                                    \
        "lsr	r4, %[b], #16		\n\t"            \
        "mul	r6, r4			\n\t"            \
        "lsr	%[h], r6, #16		\n\t"            \
        "lsl	r6, r6, #16		\n\t"            \
        "add	%[l], %[l], r6		\n\t"            \
        "mov	r5, #0			\n\t"            \
        "adc	%[h], r5		\n\t"            \
        /* ah * bh */                                    \
        "lsr	r6, %[a], #16		\n\t"            \
        "mul	r4, r6			\n\t"            \
        "add	%[h], %[h], r4		\n\t"            \
        /* ah * bl */                                    \
        "uxth	r4, %[b]		\n\t"            \
        "mul	r6, r4			\n\t"            \
        "lsr	r4, r6, #16		\n\t"            \
        "lsl	r6, r6, #16		\n\t"            \
        "add	%[l], %[l], r6		\n\t"            \
        "adc	%[h], r4		\n\t"            \
        : [h] "+l" (vh), [l] "+l" (vl)                   \
        : [a] "l" (va), [b] "l" (vb)                     \
        : "r4", "r5", "r6", "cc"                         \
    )
/* Multiply va by vb and store double size result in: vo | vh | vl */
#define SP_ASM_MUL_SET(vl, vh, vo, va, vb)               \
    __asm__ __volatile__ (                               \
        /* al * bl */                                    \
        "uxth	r6, %[a]		\n\t"            \
        "uxth	%[l], %[b]		\n\t"            \
        "mul	%[l], r6		\n\t"            \
        /* al * bh */                                    \
        "lsr	r7, %[b], #16		\n\t"            \
        "mul	r6, r7			\n\t"            \
        "lsr	%[h], r6, #16		\n\t"            \
        "lsl	r6, r6, #16		\n\t"            \
        "add	%[l], %[l], r6		\n\t"            \
        "mov	%[o], #0		\n\t"            \
        "adc	%[h], %[o]		\n\t"            \
        /* ah * bh */                                    \
        "lsr	r6, %[a], #16		\n\t"            \
        "mul	r7, r6			\n\t"            \
        "add	%[h], %[h], r7		\n\t"            \
        /* ah * bl */                                    \
        "uxth	r7, %[b]		\n\t"            \
        "mul	r6, r7			\n\t"            \
        "lsr	r7, r6, #16		\n\t"            \
        "lsl	r6, r6, #16		\n\t"            \
        "add	%[l], %[l], r6		\n\t"            \
        "adc	%[h], r7		\n\t"            \
        : [l] "+l" (vl), [h] "+l" (vh), [o] "+l" (vo)    \
        : [a] "l" (va), [b] "l" (vb)                     \
        : "r6", "r7", "cc"                               \
    )
#ifndef WOLFSSL_SP_SMALL
/* Multiply va by vb and add double size result into: vo | vh | vl */
#define SP_ASM_MUL_ADD(vl, vh, vo, va, vb)               \
    __asm__ __volatile__ (                               \
        /* al * bl */                                    \
        "uxth	r6, %[a]		\n\t"            \
        "uxth	r7, %[b]		\n\t"            \
        "mul	r7, r6			\n\t"            \
        "add	%[l], %[l], r7		\n\t"            \
        "mov	r5, #0			\n\t"            \
        "adc	%[h], r5		\n\t"            \
        "adc	%[o], r5		\n\t"            \
        /* al * bh */                                    \
        "lsr	r7, %[b], #16		\n\t"            \
        "mul	r6, r7			\n\t"            \
        "lsr	r7, r6, #16		\n\t"            \
        "lsl	r6, r6, #16		\n\t"            \
        "add	%[l], %[l], r6		\n\t"            \
        "adc	%[h], r7		\n\t"            \
        "adc	%[o], r5		\n\t"            \
        /* ah * bh */                                    \
        "lsr	r6, %[a], #16		\n\t"            \
        "lsr	r7, %[b], #16		\n\t"            \
        "mul	r7, r6			\n\t"            \
        "add	%[h], %[h], r7		\n\t"            \
        "adc	%[o], r5		\n\t"            \
        /* ah * bl */                                    \
        "uxth	r7, %[b]		\n\t"            \
        "mul	r6, r7			\n\t"            \
        "lsr	r7, r6, #16		\n\t"            \
        "lsl	r6, r6, #16		\n\t"            \
        "add	%[l], %[l], r6		\n\t"            \
        "adc	%[h], r7		\n\t"            \
        "adc	%[o], r5		\n\t"            \
        : [l] "+l" (vl), [h] "+l" (vh), [o] "+l" (vo)    \
        : [a] "l" (va), [b] "l" (vb)                     \
        : "r5", "r6", "r7", "cc"                         \
    )
#else
/* Multiply va by vb and add double size result into: vo | vh | vl */
#define SP_ASM_MUL_ADD(vl, vh, vo, va, vb)               \
    __asm__ __volatile__ (                               \
        /* al * bl */                                    \
        "uxth   r6, %[a]                \n\t"            \
        "uxth   r5, %[b]                \n\t"            \
        "mul    r5, r6                  \n\t"            \
        "add    %[l], %[l], r5          \n\t"            \
        "mov    r5, #0                  \n\t"            \
        "adc    %[h], r5                \n\t"            \
        "adc    %[o], r5                \n\t"            \
        /* al * bh */                                    \
        "lsr    r5, %[b], #16           \n\t"            \
        "mul    r6, r5                  \n\t"            \
        "lsr    r5, r6, #16             \n\t"            \
        "lsl    r6, r6, #16             \n\t"            \
        "add    %[l], %[l], r6          \n\t"            \
        "adc    %[h], r5                \n\t"            \
        "mov    r5, #0                  \n\t"            \
        "adc    %[o], r5                \n\t"            \
        /* ah * bh */                                    \
        "lsr    r6, %[a], #16           \n\t"            \
        "lsr    r5, %[b], #16           \n\t"            \
        "mul    r5, r6                  \n\t"            \
        "add    %[h], %[h], r5          \n\t"            \
        "mov    r5, #0                  \n\t"            \
        "adc    %[o], r5                \n\t"            \
        /* ah * bl */                                    \
        "uxth   r5, %[b]                \n\t"            \
        "mul    r6, r5                  \n\t"            \
        "lsr    r5, r6, #16             \n\t"            \
        "lsl    r6, r6, #16             \n\t"            \
        "add    %[l], %[l], r6          \n\t"            \
        "adc    %[h], r5                \n\t"            \
        "mov    r5, #0                  \n\t"            \
        "adc    %[o], r5                \n\t"            \
        : [l] "+l" (vl), [h] "+l" (vh), [o] "+l" (vo)    \
        : [a] "l" (va), [b] "l" (vb)                     \
        : "r5", "r6", "cc"                               \
    )
#endif
/* Multiply va by vb and add double size result into: vh | vl */
#define SP_ASM_MUL_ADD_NO(vl, vh, va, vb)                \
    __asm__ __volatile__ (                               \
        /* al * bl */                                    \
        "uxth	r6, %[a]		\n\t"            \
        "uxth	r4, %[b]		\n\t"            \
        "mul	r4, r6			\n\t"            \
        "add	%[l], %[l], r4		\n\t"            \
        "mov	r5, #0			\n\t"            \
        "adc	%[h], r5		\n\t"            \
        /* al * bh */                                    \
        "lsr	r4, %[b], #16		\n\t"            \
        "mul	r6, r4			\n\t"            \
        "lsr	r4, r6, #16		\n\t"            \
        "lsl	r6, r6, #16		\n\t"            \
        "add	%[l], %[l], r6		\n\t"            \
        "adc	%[h], r4		\n\t"            \
        /* ah * bh */                                    \
        "lsr	r6, %[a], #16		\n\t"            \
        "lsr	r4, %[b], #16		\n\t"            \
        "mul	r4, r6			\n\t"            \
        "add	%[h], %[h], r4		\n\t"            \
        /* ah * bl */                                    \
        "uxth	r4, %[b]		\n\t"            \
        "mul	r6, r4			\n\t"            \
        "lsr	r4, r6, #16		\n\t"            \
        "lsl	r6, r6, #16		\n\t"            \
        "add	%[l], %[l], r6		\n\t"            \
        "adc	%[h], r4		\n\t"            \
        : [l] "+l" (vl), [h] "+l" (vh)                   \
        : [a] "l" (va), [b] "l" (vb)                     \
        : "r4", "r5", "r6", "cc"                         \
    )
#ifndef WOLFSSL_SP_SMALL
/* Multiply va by vb and add double size result twice into: vo | vh | vl */
#define SP_ASM_MUL_ADD2(vl, vh, vo, va, vb)              \
    __asm__ __volatile__ (                               \
        /* al * bl */                                    \
        "uxth	r6, %[a]		\n\t"            \
        "uxth	r7, %[b]		\n\t"            \
        "mul	r7, r6			\n\t"            \
        "add	%[l], %[l], r7		\n\t"            \
        "mov	r5, #0			\n\t"            \
        "adc	%[h], r5		\n\t"            \
        "adc	%[o], r5		\n\t"            \
        "add	%[l], %[l], r7		\n\t"            \
        "adc	%[h], r5		\n\t"            \
        "adc	%[o], r5		\n\t"            \
        /* al * bh */                                    \
        "lsr	r7, %[b], #16		\n\t"            \
        "mul	r6, r7			\n\t"            \
        "lsr	r7, r6, #16		\n\t"            \
        "lsl	r6, r6, #16		\n\t"            \
        "add	%[l], %[l], r6		\n\t"            \
        "adc	%[h], r7		\n\t"            \
        "adc	%[o], r5		\n\t"            \
        "add	%[l], %[l], r6		\n\t"            \
        "adc	%[h], r7		\n\t"            \
        "adc	%[o], r5		\n\t"            \
        /* ah * bh */                                    \
        "lsr	r6, %[a], #16		\n\t"            \
        "lsr	r7, %[b], #16		\n\t"            \
        "mul	r7, r6			\n\t"            \
        "add	%[h], %[h], r7		\n\t"            \
        "adc	%[o], r5		\n\t"            \
        "add	%[h], %[h], r7		\n\t"            \
        "adc	%[o], r5		\n\t"            \
        /* ah * bl */                                    \
        "uxth	r7, %[b]		\n\t"            \
        "mul	r6, r7			\n\t"            \
        "lsr	r7, r6, #16		\n\t"            \
        "lsl	r6, r6, #16		\n\t"            \
        "add	%[l], %[l], r6		\n\t"            \
        "adc	%[h], r7		\n\t"            \
        "adc	%[o], r5		\n\t"            \
        "add	%[l], %[l], r6		\n\t"            \
        "adc	%[h], r7		\n\t"            \
        "adc	%[o], r5		\n\t"            \
        : [l] "+l" (vl), [h] "+l" (vh), [o] "+l" (vo)    \
        : [a] "l" (va), [b] "l" (vb)                     \
        : "r5", "r6", "r7", "cc"                         \
    )
#else
/* Multiply va by vb and add double size result twice into: vo | vh | vl */
#define SP_ASM_MUL_ADD2(vl, vh, vo, va, vb)              \
    __asm__ __volatile__ (                               \
        "mov    r8, %[a]                \n\t"            \
        /* al * bl */                                    \
        "uxth   r6, %[a]                \n\t"            \
        "uxth   r5, %[b]                \n\t"            \
        "mul    r5, r6                  \n\t"            \
        "add    %[l], %[l], r5          \n\t"            \
        "mov    %[a], #0                \n\t"            \
        "adc    %[h], %[a]              \n\t"            \
        "adc    %[o], %[a]              \n\t"            \
        "add    %[l], %[l], r5          \n\t"            \
        "adc    %[h], %[a]              \n\t"            \
        "adc    %[o], %[a]              \n\t"            \
        /* al * bh */                                    \
        "lsr    r5, %[b], #16           \n\t"            \
        "mul    r6, r5                  \n\t"            \
        "lsr    r5, r6, #16             \n\t"            \
        "lsl    r6, r6, #16             \n\t"            \
        "add    %[l], %[l], r6          \n\t"            \
        "adc    %[h], r5                \n\t"            \
        "adc    %[o], %[a]              \n\t"            \
        "add    %[l], %[l], r6          \n\t"            \
        "adc    %[h], r5                \n\t"            \
        "adc    %[o], %[a]              \n\t"            \
        /* ah * bh */                                    \
        "mov    %[a], r8                \n\t"            \
        "lsr    r6, %[a], #16           \n\t"            \
        "lsr    r5, %[b], #16           \n\t"            \
        "mul    r5, r6                  \n\t"            \
        "add    %[h], %[h], r5          \n\t"            \
        "mov    %[a], #0                \n\t"            \
        "adc    %[o], %[a]              \n\t"            \
        "add    %[h], %[h], r5          \n\t"            \
        "adc    %[o], %[a]              \n\t"            \
        /* ah * bl */                                    \
        "uxth   r5, %[b]                \n\t"            \
        "mul    r6, r5                  \n\t"            \
        "lsr    r5, r6, #16             \n\t"            \
        "lsl    r6, r6, #16             \n\t"            \
        "add    %[l], %[l], r6          \n\t"            \
        "adc    %[h], r5                \n\t"            \
        "adc    %[o], %[a]              \n\t"            \
        "add    %[l], %[l], r6          \n\t"            \
        "adc    %[h], r5                \n\t"            \
        "adc    %[o], %[a]              \n\t"            \
        "mov    %[a], r8                \n\t"            \
        : [l] "+l" (vl), [h] "+l" (vh), [o] "+l" (vo)    \
        : [a] "l" (va), [b] "l" (vb)                     \
        : "r5", "r6", "r8", "cc"                         \
    )
#endif
/* Multiply va by vb and add double size result twice into: vo | vh | vl
 * Assumes first add will not overflow vh | vl
 */
#define SP_ASM_MUL_ADD2_NO(vl, vh, vo, va, vb)           \
    __asm__ __volatile__ (                               \
        /* al * bl */                                    \
        "uxth	r6, %[a]		\n\t"            \
        "uxth	r7, %[b]		\n\t"            \
        "mul	r7, r6			\n\t"            \
        "add	%[l], %[l], r7		\n\t"            \
        "mov	r5, #0			\n\t"            \
        "adc	%[h], r5		\n\t"            \
        "add	%[l], %[l], r7		\n\t"            \
        "adc	%[h], r5		\n\t"            \
        /* al * bh */                                    \
        "lsr	r7, %[b], #16		\n\t"            \
        "mul	r6, r7			\n\t"            \
        "lsr	r7, r6, #16		\n\t"            \
        "lsl	r6, r6, #16		\n\t"            \
        "add	%[l], %[l], r6		\n\t"            \
        "adc	%[h], r7		\n\t"            \
        "add	%[l], %[l], r6		\n\t"            \
        "adc	%[h], r7		\n\t"            \
        "adc	%[o], r5		\n\t"            \
        /* ah * bh */                                    \
        "lsr	r6, %[a], #16		\n\t"            \
        "lsr	r7, %[b], #16		\n\t"            \
        "mul	r7, r6			\n\t"            \
        "add	%[h], %[h], r7		\n\t"            \
        "adc	%[o], r5		\n\t"            \
        "add	%[h], %[h], r7		\n\t"            \
        "adc	%[o], r5		\n\t"            \
        /* ah * bl */                                    \
        "uxth	r7, %[b]		\n\t"            \
        "mul	r6, r7			\n\t"            \
        "lsr	r7, r6, #16		\n\t"            \
        "lsl	r6, r6, #16		\n\t"            \
        "add	%[l], %[l], r6		\n\t"            \
        "adc	%[h], r7		\n\t"            \
        "adc	%[o], r5		\n\t"            \
        "add	%[l], %[l], r6		\n\t"            \
        "adc	%[h], r7		\n\t"            \
        "adc	%[o], r5		\n\t"            \
        : [l] "+l" (vl), [h] "+l" (vh), [o] "+l" (vo)    \
        : [a] "l" (va), [b] "l" (vb)                     \
        : "r5", "r6", "r7", "cc"                         \
    )
/* Square va and store double size result in: vh | vl */
#define SP_ASM_SQR(vl, vh, va)                           \
    __asm__ __volatile__ (                               \
        "lsr	r5, %[a], #16		\n\t"            \
        "uxth	r6, %[a]		\n\t"            \
        "mov	%[l], r6		\n\t"            \
        "mov	%[h], r5		\n\t"            \
        /* al * al */                                    \
        "mul	%[l], %[l]		\n\t"            \
        /* ah * ah */                                    \
        "mul	%[h], %[h]		\n\t"            \
        /* 2 * al * ah */                                \
        "mul	r6, r5			\n\t"            \
        "lsr	r5, r6, #15		\n\t"            \
        "lsl	r6, r6, #17		\n\t"            \
        "add	%[l], %[l], r6		\n\t"            \
        "adc	%[h], r5		\n\t"            \
        : [h] "+l" (vh), [l] "+l" (vl)                   \
        : [a] "l" (va)                                   \
        : "r5", "r6", "cc"                               \
    )
/* Square va and add double size result into: vo | vh | vl */
#define SP_ASM_SQR_ADD(vl, vh, vo, va)                   \
    __asm__ __volatile__ (                               \
        "lsr	r4, %[a], #16		\n\t"            \
        "uxth	r6, %[a]		\n\t"            \
        /* al * al */                                    \
        "mul	r6, r6			\n\t"            \
        /* ah * ah */                                    \
        "mul	r4, r4			\n\t"            \
        "add	%[l], %[l], r6		\n\t"            \
        "adc	%[h], r4		\n\t"            \
        "mov	r5, #0			\n\t"            \
        "adc	%[o], r5		\n\t"            \
        "lsr	r4, %[a], #16		\n\t"            \
        "uxth	r6, %[a]		\n\t"            \
        /* 2 * al * ah */                                \
        "mul	r6, r4			\n\t"            \
        "lsr	r4, r6, #15		\n\t"            \
        "lsl	r6, r6, #17		\n\t"            \
        "add	%[l], %[l], r6		\n\t"            \
        "adc	%[h], r4		\n\t"            \
        "adc	%[o], r5		\n\t"            \
        : [l] "+l" (vl), [h] "+l" (vh), [o] "+l" (vo)    \
        : [a] "l" (va)                                   \
        : "r4", "r5", "r6", "cc"                         \
    )
/* Square va and add double size result into: vh | vl */
#define SP_ASM_SQR_ADD_NO(vl, vh, va)                    \
    __asm__ __volatile__ (                               \
        "lsr	r7, %[a], #16		\n\t"            \
        "uxth	r6, %[a]		\n\t"            \
        /* al * al */                                    \
        "mul	r6, r6			\n\t"            \
        /* ah * ah */                                    \
        "mul	r7, r7			\n\t"            \
        "add	%[l], %[l], r6		\n\t"            \
        "adc	%[h], r7		\n\t"            \
        "lsr	r7, %[a], #16		\n\t"            \
        "uxth	r6, %[a]		\n\t"            \
        /* 2 * al * ah */                                \
        "mul	r6, r7			\n\t"            \
        "lsr	r7, r6, #15		\n\t"            \
        "lsl	r6, r6, #17		\n\t"            \
        "add	%[l], %[l], r6		\n\t"            \
        "adc	%[h], r7		\n\t"            \
        : [l] "+l" (vl), [h] "+l" (vh)                   \
        : [a] "l" (va)                                   \
        : "r6", "r7", "cc"                               \
    )
/* Add va into: vh | vl */
#define SP_ASM_ADDC(vl, vh, va)                          \
    __asm__ __volatile__ (                               \
        "add	%[l], %[l], %[a]	\n\t"            \
        "mov	r5, #0			\n\t"            \
        "adc	%[h], r5		\n\t"            \
        : [l] "+l" (vl), [h] "+l" (vh)                   \
        : [a] "l" (va)                                   \
        : "r5", "cc"                                     \
    )
/* Sub va from: vh | vl */
#define SP_ASM_SUBC(vl, vh, va)                          \
    __asm__ __volatile__ (                               \
        "sub	%[l], %[l], %[a]	\n\t"            \
        "mov	r5, #0			\n\t"            \
        "sbc	%[h], r5		\n\t"            \
        : [l] "+l" (vl), [h] "+l" (vh)                   \
        : [a] "l" (va)                                   \
        : "r5", "cc"                                     \
    )
/* Add two times vc | vb | va into vo | vh | vl */
#define SP_ASM_ADD_DBL_3(vl, vh, vo, va, vb, vc)         \
    __asm__ __volatile__ (                               \
        "add	%[l], %[l], %[a]	\n\t"            \
        "adc	%[h], %[b]		\n\t"            \
        "adc	%[o], %[c]		\n\t"            \
        "add	%[l], %[l], %[a]	\n\t"            \
        "adc	%[h], %[b]		\n\t"            \
        "adc	%[o], %[c]		\n\t"            \
        : [l] "+l" (vl), [h] "+l" (vh), [o] "+l" (vo)    \
        : [a] "l" (va), [b] "l" (vb), [c] "l" (vc)       \
        : "cc"                                           \
    )

#endif

#ifdef WOLFSSL_SP_DIV_WORD_HALF
/* Divide a two digit number by a digit number and return. (hi | lo) / d
 *
 * No division instruction used - does operation bit by bit.
 * Constant time.
 *
 * @param  [in]  hi  SP integer digit. High digit of the dividend.
 * @param  [in]  lo  SP integer digit. Lower digit of the dividend.
 * @param  [in]  d   SP integer digit. Number to divide by.
 * @return  The division result.
 */
static WC_INLINE sp_int_digit sp_div_word(sp_int_digit hi, sp_int_digit lo,
                                          sp_int_digit d)
{
    __asm__ __volatile__ (
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r3, %[d], #24\n\t"
#else
        "lsr	r3, %[d], #24\n\t"
#endif
        "beq	2%=f\n\t"
	"1%=:\n\t"
        "movs	r3, #0\n\t"
        "b	3%=f\n\t"
	"2%=:\n\t"
        "mov	r3, #8\n\t"
	"3%=:\n\t"
        "movs	r4, #31\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs	r4, r4, r3\n\t"
#else
        "sub	r4, r4, r3\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls	%[d], %[d], r3\n\t"
#else
        "lsl	%[d], %[d], r3\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls	%[hi], %[hi], r3\n\t"
#else
        "lsl	%[hi], %[hi], r3\n\t"
#endif
        "mov	r5, %[lo]\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r5, r5, r4\n\t"
#else
        "lsr	r5, r5, r4\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls	%[lo], %[lo], r3\n\t"
#else
        "lsl	%[lo], %[lo], r3\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs	r5, r5, #1\n\t"
#else
        "lsr	r5, r5, #1\n\t"
#endif
#if defined(WOLFSSL_KEIL)
        "orrs	%[hi], %[hi], r5\n\t"
#elif defined(__clang__)
        "orrs	%[hi], r5\n\t"
#else
        "orr	%[hi], r5\n\t"
#endif

        "movs   r3, #0\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs   r5, %[d], #1\n\t"
#else
        "lsr    r5, %[d], #1\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds   r5, r5, #1\n\t"
#else
        "add    r5, r5, #1\n\t"
#endif
        "mov    r8, %[lo]\n\t"
        "mov    r9, %[hi]\n\t"
        "# Do top 32\n\t"
        "movs   r6, r5\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs   r6, r6, %[hi]\n\t"
#else
        "sub    r6, r6, %[hi]\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs   r6, r6, r6\n\t"
#elif defined(__clang__)
        "sbcs   r6, r6\n\t"
#else
        "sbc    r6, r6\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds   r3, r3, r3\n\t"
#else
        "add    r3, r3, r3\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs   r3, r3, r6\n\t"
#else
        "sub    r3, r3, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "ands   r6, r6, r5\n\t"
#elif defined(__clang__)
        "ands   r6, r5\n\t"
#else
        "and    r6, r5\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs   %[hi], %[hi], r6\n\t"
#else
        "sub    %[hi], %[hi], r6\n\t"
#endif
        "movs   r4, #29\n\t"
        "\n"
    "L_sp_div_word_loop%=:\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls   %[lo], %[lo], #1\n\t"
#else
        "lsl    %[lo], %[lo], #1\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs   %[hi], %[hi], %[hi]\n\t"
#elif defined(__clang__)
        "adcs   %[hi], %[hi]\n\t"
#else
        "adc    %[hi], %[hi]\n\t"
#endif
        "movs   r6, r5\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs   r6, r6, %[hi]\n\t"
#else
        "sub    r6, r6, %[hi]\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs   r6, r6, r6\n\t"
#elif defined(__clang__)
        "sbcs   r6, r6\n\t"
#else
        "sbc    r6, r6\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds   r3, r3, r3\n\t"
#else
        "add    r3, r3, r3\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs   r3, r3, r6\n\t"
#else
        "sub    r3, r3, r6\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "ands   r6, r6, r5\n\t"
#elif defined(__clang__)
        "ands   r6, r5\n\t"
#else
        "and    r6, r5\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs   %[hi], %[hi], r6\n\t"
#else
        "sub    %[hi], %[hi], r6\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs   r4, r4, #1\n\t"
#else
        "sub    r4, r4, #1\n\t"
#endif
        "bpl    L_sp_div_word_loop%=\n\t"
        "movs   r7, #0\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds   r3, r3, r3\n\t"
#else
        "add    r3, r3, r3\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds   r3, r3, #1\n\t"
#else
        "add    r3, r3, #1\n\t"
#endif
        "# r * d - Start\n\t"
        "uxth   %[hi], r3\n\t"
        "uxth   r4, %[d]\n\t"
#ifdef WOLFSSL_KEIL
        "muls   r4, %[hi], r4\n\t"
#elif defined(__clang__)
        "muls   r4, %[hi]\n\t"
#else
        "mul    r4, %[hi]\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs   r6, %[d], #16\n\t"
#else
        "lsr    r6, %[d], #16\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "muls   %[hi], r6, %[hi]\n\t"
#elif defined(__clang__)
        "muls   %[hi], r6\n\t"
#else
        "mul    %[hi], r6\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs   r5, %[hi], #16\n\t"
#else
        "lsr    r5, %[hi], #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls   %[hi], %[hi], #16\n\t"
#else
        "lsl    %[hi], %[hi], #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds   r4, r4, %[hi]\n\t"
#else
        "add    r4, r4, %[hi]\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs   r5, r5, r7\n\t"
#elif defined(__clang__)
        "adcs   r5, r7\n\t"
#else
        "adc    r5, r7\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs   %[hi], r3, #16\n\t"
#else
        "lsr    %[hi], r3, #16\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "muls   r6, %[hi], r6\n\t"
#elif defined(__clang__)
        "muls   r6, %[hi]\n\t"
#else
        "mul    r6, %[hi]\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds   r5, r5, r6\n\t"
#else
        "add    r5, r5, r6\n\t"
#endif
        "uxth   r6, %[d]\n\t"
#ifdef WOLFSSL_KEIL
        "muls   %[hi], r6, %[hi]\n\t"
#elif defined(__clang__)
        "muls   %[hi], r6\n\t"
#else
        "mul    %[hi], r6\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs   r6, %[hi], #16\n\t"
#else
        "lsr    r6, %[hi], #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls   %[hi], %[hi], #16\n\t"
#else
        "lsl    %[hi], %[hi], #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds   r4, r4, %[hi]\n\t"
#else
        "add    r4, r4, %[hi]\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs   r5, r5, r6\n\t"
#elif defined(__clang__)
        "adcs   r5, r6\n\t"
#else
        "adc    r5, r6\n\t"
#endif
        "# r * d - Done\n\t"
        "mov    %[hi], r8\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs   %[hi], %[hi], r4\n\t"
#else
        "sub    %[hi], %[hi], r4\n\t"
#endif
        "movs   r4, %[hi]\n\t"
        "mov    %[hi], r9\n\t"
#ifdef WOLFSSL_KEIL
        "sbcs   %[hi], %[hi], r5\n\t"
#elif defined(__clang__)
        "sbcs   %[hi], r5\n\t"
#else
        "sbc    %[hi], r5\n\t"
#endif
        "movs   r5, %[hi]\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds   r3, r3, r5\n\t"
#else
        "add    r3, r3, r5\n\t"
#endif
        "# r * d - Start\n\t"
        "uxth   %[hi], r3\n\t"
        "uxth   r4, %[d]\n\t"
#ifdef WOLFSSL_KEIL
        "muls   r4, %[hi], r4\n\t"
#elif defined(__clang__)
        "muls   r4, %[hi]\n\t"
#else
        "mul    r4, %[hi]\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs   r6, %[d], #16\n\t"
#else
        "lsr    r6, %[d], #16\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "muls   %[hi], r6, %[hi]\n\t"
#elif defined(__clang__)
        "muls   %[hi], r6\n\t"
#else
        "mul    %[hi], r6\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs   r5, %[hi], #16\n\t"
#else
        "lsr    r5, %[hi], #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls   %[hi], %[hi], #16\n\t"
#else
        "lsl    %[hi], %[hi], #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds   r4, r4, %[hi]\n\t"
#else
        "add    r4, r4, %[hi]\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs   r5, r5, r7\n\t"
#elif defined(__clang__)
        "adcs   r5, r7\n\t"
#else
        "adc    r5, r7\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs   %[hi], r3, #16\n\t"
#else
        "lsr    %[hi], r3, #16\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "muls   r6, %[hi], r6\n\t"
#elif defined(__clang__)
        "muls   r6, %[hi]\n\t"
#else
        "mul    r6, %[hi]\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds   r5, r5, r6\n\t"
#else
        "add    r5, r5, r6\n\t"
#endif
        "uxth   r6, %[d]\n\t"
#ifdef WOLFSSL_KEIL
        "muls   %[hi], r6, %[hi]\n\t"
#elif defined(__clang__)
        "muls   %[hi], r6\n\t"
#else
        "mul    %[hi], r6\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs   r6, %[hi], #16\n\t"
#else
        "lsr    r6, %[hi], #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls   %[hi], %[hi], #16\n\t"
#else
        "lsl    %[hi], %[hi], #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds   r4, r4, %[hi]\n\t"
#else
        "add    r4, r4, %[hi]\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs   r5, r5, r6\n\t"
#elif defined(__clang__)
        "adcs   r5, r6\n\t"
#else
        "adc    r5, r6\n\t"
#endif
        "# r * d - Done\n\t"
        "mov    %[hi], r8\n\t"
        "mov    r6, r9\n\t"
#ifdef WOLFSSL_KEIL
        "subs   r4, %[hi], r4\n\t"
#else
#ifdef __clang__
        "subs   r4, %[hi], r4\n\t"
#else
        "sub    r4, %[hi], r4\n\t"
#endif
#endif
#ifdef WOLFSSL_KEIL
        "sbcs   r6, r6, r5\n\t"
#elif defined(__clang__)
        "sbcs   r6, r5\n\t"
#else
        "sbc    r6, r5\n\t"
#endif
        "movs   r5, r6\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds   r3, r3, r5\n\t"
#else
        "add    r3, r3, r5\n\t"
#endif
        "# r * d - Start\n\t"
        "uxth   %[hi], r3\n\t"
        "uxth   r4, %[d]\n\t"
#ifdef WOLFSSL_KEIL
        "muls   r4, %[hi], r4\n\t"
#elif defined(__clang__)
        "muls   r4, %[hi]\n\t"
#else
        "mul    r4, %[hi]\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs   r6, %[d], #16\n\t"
#else
        "lsr    r6, %[d], #16\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "muls   %[hi], r6, %[hi]\n\t"
#elif defined(__clang__)
        "muls   %[hi], r6\n\t"
#else
        "mul    %[hi], r6\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs   r5, %[hi], #16\n\t"
#else
        "lsr    r5, %[hi], #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls   %[hi], %[hi], #16\n\t"
#else
        "lsl    %[hi], %[hi], #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds   r4, r4, %[hi]\n\t"
#else
        "add    r4, r4, %[hi]\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs   r5, r5, r7\n\t"
#elif defined(__clang__)
        "adcs   r5, r7\n\t"
#else
        "adc    r5, r7\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs   %[hi], r3, #16\n\t"
#else
        "lsr    %[hi], r3, #16\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "muls   r6, %[hi], r6\n\t"
#elif defined(__clang__)
        "muls   r6, %[hi]\n\t"
#else
        "mul    r6, %[hi]\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds   r5, r5, r6\n\t"
#else
        "add    r5, r5, r6\n\t"
#endif
        "uxth   r6, %[d]\n\t"
#ifdef WOLFSSL_KEIL
        "muls   %[hi], r6, %[hi]\n\t"
#elif defined(__clang__)
        "muls   %[hi], r6\n\t"
#else
        "mul    %[hi], r6\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsrs   r6, %[hi], #16\n\t"
#else
        "lsr    r6, %[hi], #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "lsls   %[hi], %[hi], #16\n\t"
#else
        "lsl    %[hi], %[hi], #16\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds   r4, r4, %[hi]\n\t"
#else
        "add    r4, r4, %[hi]\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "adcs   r5, r5, r6\n\t"
#elif defined(__clang__)
        "adcs   r5, r6\n\t"
#else
        "adc    r5, r6\n\t"
#endif
        "# r * d - Done\n\t"
        "mov    %[hi], r8\n\t"
        "mov    r6, r9\n\t"
#ifdef WOLFSSL_KEIL
        "subs   r4, %[hi], r4\n\t"
#else
#ifdef __clang__
        "subs   r4, %[hi], r4\n\t"
#else
        "sub    r4, %[hi], r4\n\t"
#endif
#endif
#ifdef WOLFSSL_KEIL
        "sbcs   r6, r6, r5\n\t"
#elif defined(__clang__)
        "sbcs   r6, r5\n\t"
#else
        "sbc    r6, r5\n\t"
#endif
        "movs   r5, r6\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "adds   r3, r3, r5\n\t"
#else
        "add    r3, r3, r5\n\t"
#endif
        "movs   r6, %[d]\n\t"
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs   r6, r6, r4\n\t"
#else
        "sub    r6, r6, r4\n\t"
#endif
#ifdef WOLFSSL_KEIL
        "sbcs   r6, r6, r6\n\t"
#elif defined(__clang__)
        "sbcs   r6, r6\n\t"
#else
        "sbc    r6, r6\n\t"
#endif
#if defined(__clang__) || defined(WOLFSSL_KEIL)
        "subs   r3, r3, r6\n\t"
#else
        "sub    r3, r3, r6\n\t"
#endif
        "movs   %[hi], r3\n\t"
        : [hi] "+l" (hi), [lo] "+l" (lo), [d] "+l" (d)
        :
        : "r3", "r4", "r5", "r6", "r7", "r8", "r9"
    );
    return (uint32_t)(size_t)hi;
}

#define SP_ASM_DIV_WORD
#endif /* !WOLFSSL_SP_DIV_WORD_HALF */

#define SP_INT_ASM_AVAILABLE

    #endif /* WOLFSSL_SP_ARM_THUMB && SP_WORD_SIZE == 32 */

    #if defined(WOLFSSL_SP_PPC64) && SP_WORD_SIZE == 64
/*
 * CPU: PPC64
 */

/* Multiply va by vb and store double size result in: vh | vl */
#define SP_ASM_MUL(vl, vh, va, vb)                       \
    __asm__ __volatile__ (                               \
        "mulld	%[l], %[a], %[b]	\n\t"            \
        "mulhdu	%[h], %[a], %[b]	\n\t"            \
        : [h] "+r" (vh), [l] "+r" (vl)                   \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "memory"                                       \
    )
/* Multiply va by vb and store double size result in: vo | vh | vl */
#define SP_ASM_MUL_SET(vl, vh, vo, va, vb)               \
    __asm__ __volatile__ (                               \
        "mulhdu	%[h], %[a], %[b]	\n\t"            \
        "mulld	%[l], %[a], %[b]	\n\t"            \
        "li	%[o], 0			\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "=r" (vo)    \
        : [a] "r" (va), [b] "r" (vb)                     \
        :                                                \
    )
/* Multiply va by vb and add double size result into: vo | vh | vl */
#define SP_ASM_MUL_ADD(vl, vh, vo, va, vb)               \
    __asm__ __volatile__ (                               \
        "mulld	16, %[a], %[b]		\n\t"            \
        "mulhdu	17, %[a], %[b]		\n\t"            \
        "addc	%[l], %[l], 16		\n\t"            \
        "adde	%[h], %[h], 17		\n\t"            \
        "addze	%[o], %[o]		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "16", "17", "cc"                               \
    )
/* Multiply va by vb and add double size result into: vh | vl */
#define SP_ASM_MUL_ADD_NO(vl, vh, va, vb)                \
    __asm__ __volatile__ (                               \
        "mulld	16, %[a], %[b]		\n\t"            \
        "mulhdu	17, %[a], %[b]		\n\t"            \
        "addc	%[l], %[l], 16		\n\t"            \
        "adde	%[h], %[h], 17		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "16", "17", "cc"                               \
    )
/* Multiply va by vb and add double size result twice into: vo | vh | vl */
#define SP_ASM_MUL_ADD2(vl, vh, vo, va, vb)              \
    __asm__ __volatile__ (                               \
        "mulld	16, %[a], %[b]		\n\t"            \
        "mulhdu	17, %[a], %[b]		\n\t"            \
        "addc	%[l], %[l], 16		\n\t"            \
        "adde	%[h], %[h], 17		\n\t"            \
        "addze	%[o], %[o]		\n\t"            \
        "addc	%[l], %[l], 16		\n\t"            \
        "adde	%[h], %[h], 17		\n\t"            \
        "addze	%[o], %[o]		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "16", "17", "cc"                               \
    )
/* Multiply va by vb and add double size result twice into: vo | vh | vl
 * Assumes first add will not overflow vh | vl
 */
#define SP_ASM_MUL_ADD2_NO(vl, vh, vo, va, vb)           \
    __asm__ __volatile__ (                               \
        "mulld	16, %[a], %[b]		\n\t"            \
        "mulhdu	17, %[a], %[b]		\n\t"            \
        "addc	%[l], %[l], 16		\n\t"            \
        "adde	%[h], %[h], 17		\n\t"            \
        "addc	%[l], %[l], 16		\n\t"            \
        "adde	%[h], %[h], 17		\n\t"            \
        "addze	%[o], %[o]		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "16", "17", "cc"                               \
    )
/* Square va and store double size result in: vh | vl */
#define SP_ASM_SQR(vl, vh, va)                           \
    __asm__ __volatile__ (                               \
        "mulld	%[l], %[a], %[a]	\n\t"            \
        "mulhdu	%[h], %[a], %[a]	\n\t"            \
        : [h] "+r" (vh), [l] "+r" (vl)                   \
        : [a] "r" (va)                                   \
        : "memory"                                       \
    )
/* Square va and add double size result into: vo | vh | vl */
#define SP_ASM_SQR_ADD(vl, vh, vo, va)                   \
    __asm__ __volatile__ (                               \
        "mulld	16, %[a], %[a]		\n\t"            \
        "mulhdu	17, %[a], %[a]		\n\t"            \
        "addc	%[l], %[l], 16		\n\t"            \
        "adde	%[h], %[h], 17		\n\t"            \
        "addze	%[o], %[o]		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va)                                   \
        : "16", "17", "cc"                               \
    )
/* Square va and add double size result into: vh | vl */
#define SP_ASM_SQR_ADD_NO(vl, vh, va)                    \
    __asm__ __volatile__ (                               \
        "mulld	16, %[a], %[a]		\n\t"            \
        "mulhdu	17, %[a], %[a]		\n\t"            \
        "addc	%[l], %[l], 16		\n\t"            \
        "adde	%[h], %[h], 17		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "r" (va)                                   \
        : "16", "17", "cc"                               \
    )
/* Add va into: vh | vl */
#define SP_ASM_ADDC(vl, vh, va)                          \
    __asm__ __volatile__ (                               \
        "addc	%[l], %[l], %[a]	\n\t"            \
        "addze	%[h], %[h]		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "r" (va)                                   \
        : "cc"                                           \
    )
/* Sub va from: vh | vl */
#define SP_ASM_SUBC(vl, vh, va)                          \
    __asm__ __volatile__ (                               \
        "subfc	%[l], %[a], %[l]	\n\t"            \
        "li    16, 0			\n\t"            \
        "subfe %[h], 16, %[h]		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "r" (va)                                   \
        : "16", "cc"                                     \
    )
/* Add two times vc | vb | va into vo | vh | vl */
#define SP_ASM_ADD_DBL_3(vl, vh, vo, va, vb, vc)         \
    __asm__ __volatile__ (                               \
        "addc	%[l], %[l], %[a]	\n\t"            \
        "adde	%[h], %[h], %[b]	\n\t"            \
        "adde	%[o], %[o], %[c]	\n\t"            \
        "addc	%[l], %[l], %[a]	\n\t"            \
        "adde	%[h], %[h], %[b]	\n\t"            \
        "adde	%[o], %[o], %[c]	\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va), [b] "r" (vb), [c] "r" (vc)       \
        : "cc"                                           \
    )

#define SP_INT_ASM_AVAILABLE

    #endif /* WOLFSSL_SP_PPC64 && SP_WORD_SIZE == 64 */

    #if defined(WOLFSSL_SP_PPC) && SP_WORD_SIZE == 32
/*
 * CPU: PPC 32-bit
 */

/* Multiply va by vb and store double size result in: vh | vl */
#define SP_ASM_MUL(vl, vh, va, vb)                       \
    __asm__ __volatile__ (                               \
        "mullw	%[l], %[a], %[b]	\n\t"            \
        "mulhwu	%[h], %[a], %[b]	\n\t"            \
        : [h] "+r" (vh), [l] "+r" (vl)                   \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "memory"                                       \
    )
/* Multiply va by vb and store double size result in: vo | vh | vl */
#define SP_ASM_MUL_SET(vl, vh, vo, va, vb)               \
    __asm__ __volatile__ (                               \
        "mulhwu	%[h], %[a], %[b]	\n\t"            \
        "mullw	%[l], %[a], %[b]	\n\t"            \
        "li	%[o], 0			\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "=r" (vo)    \
        : [a] "r" (va), [b] "r" (vb)                     \
        :                                                \
    )
/* Multiply va by vb and add double size result into: vo | vh | vl */
#define SP_ASM_MUL_ADD(vl, vh, vo, va, vb)               \
    __asm__ __volatile__ (                               \
        "mullw	16, %[a], %[b]		\n\t"            \
        "mulhwu	17, %[a], %[b]		\n\t"            \
        "addc	%[l], %[l], 16		\n\t"            \
        "adde	%[h], %[h], 17		\n\t"            \
        "addze	%[o], %[o]		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "16", "17", "cc"                               \
    )
/* Multiply va by vb and add double size result into: vh | vl */
#define SP_ASM_MUL_ADD_NO(vl, vh, va, vb)                \
    __asm__ __volatile__ (                               \
        "mullw	16, %[a], %[b]		\n\t"            \
        "mulhwu	17, %[a], %[b]		\n\t"            \
        "addc	%[l], %[l], 16		\n\t"            \
        "adde	%[h], %[h], 17		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "16", "17", "cc"                               \
    )
/* Multiply va by vb and add double size result twice into: vo | vh | vl */
#define SP_ASM_MUL_ADD2(vl, vh, vo, va, vb)              \
    __asm__ __volatile__ (                               \
        "mullw	16, %[a], %[b]		\n\t"            \
        "mulhwu	17, %[a], %[b]		\n\t"            \
        "addc	%[l], %[l], 16		\n\t"            \
        "adde	%[h], %[h], 17		\n\t"            \
        "addze	%[o], %[o]		\n\t"            \
        "addc	%[l], %[l], 16		\n\t"            \
        "adde	%[h], %[h], 17		\n\t"            \
        "addze	%[o], %[o]		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "16", "17", "cc"                               \
    )
/* Multiply va by vb and add double size result twice into: vo | vh | vl
 * Assumes first add will not overflow vh | vl
 */
#define SP_ASM_MUL_ADD2_NO(vl, vh, vo, va, vb)           \
    __asm__ __volatile__ (                               \
        "mullw	16, %[a], %[b]		\n\t"            \
        "mulhwu	17, %[a], %[b]		\n\t"            \
        "addc	%[l], %[l], 16		\n\t"            \
        "adde	%[h], %[h], 17		\n\t"            \
        "addc	%[l], %[l], 16		\n\t"            \
        "adde	%[h], %[h], 17		\n\t"            \
        "addze	%[o], %[o]		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "16", "17", "cc"                               \
    )
/* Square va and store double size result in: vh | vl */
#define SP_ASM_SQR(vl, vh, va)                           \
    __asm__ __volatile__ (                               \
        "mullw	%[l], %[a], %[a]	\n\t"            \
        "mulhwu	%[h], %[a], %[a]	\n\t"            \
        : [h] "+r" (vh), [l] "+r" (vl)                   \
        : [a] "r" (va)                                   \
        : "memory"                                       \
    )
/* Square va and add double size result into: vo | vh | vl */
#define SP_ASM_SQR_ADD(vl, vh, vo, va)                   \
    __asm__ __volatile__ (                               \
        "mullw	16, %[a], %[a]		\n\t"            \
        "mulhwu	17, %[a], %[a]		\n\t"            \
        "addc	%[l], %[l], 16		\n\t"            \
        "adde	%[h], %[h], 17		\n\t"            \
        "addze	%[o], %[o]		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va)                                   \
        : "16", "17", "cc"                               \
    )
/* Square va and add double size result into: vh | vl */
#define SP_ASM_SQR_ADD_NO(vl, vh, va)                    \
    __asm__ __volatile__ (                               \
        "mullw	16, %[a], %[a]		\n\t"            \
        "mulhwu	17, %[a], %[a]		\n\t"            \
        "addc	%[l], %[l], 16		\n\t"            \
        "adde	%[h], %[h], 17		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "r" (va)                                   \
        : "16", "17", "cc"                               \
    )
/* Add va into: vh | vl */
#define SP_ASM_ADDC(vl, vh, va)                          \
    __asm__ __volatile__ (                               \
        "addc	%[l], %[l], %[a]	\n\t"            \
        "addze	%[h], %[h]		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "r" (va)                                   \
        : "cc"                                           \
    )
/* Sub va from: vh | vl */
#define SP_ASM_SUBC(vl, vh, va)                          \
    __asm__ __volatile__ (                               \
        "subfc	%[l], %[a], %[l]	\n\t"            \
        "li	16, 0			\n\t"            \
        "subfe	%[h], 16, %[h]		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "r" (va)                                   \
        : "16", "cc"                                     \
    )
/* Add two times vc | vb | va into vo | vh | vl */
#define SP_ASM_ADD_DBL_3(vl, vh, vo, va, vb, vc)         \
    __asm__ __volatile__ (                               \
        "addc	%[l], %[l], %[a]	\n\t"            \
        "adde	%[h], %[h], %[b]	\n\t"            \
        "adde	%[o], %[o], %[c]	\n\t"            \
        "addc	%[l], %[l], %[a]	\n\t"            \
        "adde	%[h], %[h], %[b]	\n\t"            \
        "adde	%[o], %[o], %[c]	\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va), [b] "r" (vb), [c] "r" (vc)       \
        : "cc"                                           \
    )

#define SP_INT_ASM_AVAILABLE

    #endif /* WOLFSSL_SP_PPC && SP_WORD_SIZE == 64 */

    #if defined(WOLFSSL_SP_MIPS64) && SP_WORD_SIZE == 64
/*
 * CPU: MIPS 64-bit
 */

/* Multiply va by vb and store double size result in: vh | vl */
#define SP_ASM_MUL(vl, vh, va, vb)                       \
    __asm__ __volatile__ (                               \
        "dmultu	%[a], %[b]		\n\t"            \
        "mflo	%[l]			\n\t"            \
        "mfhi	%[h]			\n\t"            \
        : [h] "+r" (vh), [l] "+r" (vl)                   \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "memory", "$lo", "$hi"                         \
    )
/* Multiply va by vb and store double size result in: vo | vh | vl */
#define SP_ASM_MUL_SET(vl, vh, vo, va, vb)               \
    __asm__ __volatile__ (                               \
        "dmultu	%[a], %[b]		\n\t"            \
        "mflo	%[l]			\n\t"            \
        "mfhi	%[h]			\n\t"            \
        "move	%[o], $0		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "=r" (vo)    \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "$lo", "$hi"                                   \
    )
/* Multiply va by vb and add double size result into: vo | vh | vl */
#define SP_ASM_MUL_ADD(vl, vh, vo, va, vb)               \
    __asm__ __volatile__ (                               \
        "dmultu	%[a], %[b]		\n\t"            \
        "mflo	$10			\n\t"            \
        "mfhi	$11			\n\t"            \
        "daddu	%[l], %[l], $10		\n\t"            \
        "sltu	$12, %[l], $10		\n\t"            \
        "daddu	%[h], %[h], $12		\n\t"            \
        "sltu	$12, %[h], $12		\n\t"            \
        "daddu	%[o], %[o], $12		\n\t"            \
        "daddu	%[h], %[h], $11		\n\t"            \
        "sltu	$12, %[h], $11		\n\t"            \
        "daddu	%[o], %[o], $12		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "$10", "$11", "$12", "$lo", "$hi"              \
    )
/* Multiply va by vb and add double size result into: vh | vl */
#define SP_ASM_MUL_ADD_NO(vl, vh, va, vb)                \
    __asm__ __volatile__ (                               \
        "dmultu	%[a], %[b]		\n\t"            \
        "mflo	$10			\n\t"            \
        "mfhi	$11			\n\t"            \
        "daddu	%[l], %[l], $10		\n\t"            \
        "sltu	$12, %[l], $10		\n\t"            \
        "daddu	%[h], %[h], $11		\n\t"            \
        "daddu	%[h], %[h], $12		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "$10", "$11", "$12", "$lo", "$hi"              \
    )
/* Multiply va by vb and add double size result twice into: vo | vh | vl */
#define SP_ASM_MUL_ADD2(vl, vh, vo, va, vb)              \
    __asm__ __volatile__ (                               \
        "dmultu	%[a], %[b]		\n\t"            \
        "mflo	$10			\n\t"            \
        "mfhi	$11			\n\t"            \
        "daddu	%[l], %[l], $10		\n\t"            \
        "sltu	$12, %[l], $10		\n\t"            \
        "daddu	%[h], %[h], $12		\n\t"            \
        "sltu	$12, %[h], $12		\n\t"            \
        "daddu	%[o], %[o], $12		\n\t"            \
        "daddu	%[h], %[h], $11		\n\t"            \
        "sltu	$12, %[h], $11		\n\t"            \
        "daddu	%[o], %[o], $12		\n\t"            \
        "daddu	%[l], %[l], $10		\n\t"            \
        "sltu	$12, %[l], $10		\n\t"            \
        "daddu	%[h], %[h], $12		\n\t"            \
        "sltu	$12, %[h], $12		\n\t"            \
        "daddu	%[o], %[o], $12		\n\t"            \
        "daddu	%[h], %[h], $11		\n\t"            \
        "sltu	$12, %[h], $11		\n\t"            \
        "daddu	%[o], %[o], $12		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "$10", "$11", "$12", "$lo", "$hi"              \
    )
/* Multiply va by vb and add double size result twice into: vo | vh | vl
 * Assumes first add will not overflow vh | vl
 */
#define SP_ASM_MUL_ADD2_NO(vl, vh, vo, va, vb)           \
    __asm__ __volatile__ (                               \
        "dmultu	%[a], %[b]		\n\t"            \
        "mflo	$10			\n\t"            \
        "mfhi	$11			\n\t"            \
        "daddu	%[l], %[l], $10		\n\t"            \
        "sltu	$12, %[l], $10		\n\t"            \
        "daddu	%[h], %[h], $11		\n\t"            \
        "daddu	%[h], %[h], $12		\n\t"            \
        "daddu	%[l], %[l], $10		\n\t"            \
        "sltu	$12, %[l], $10		\n\t"            \
        "daddu	%[h], %[h], $12		\n\t"            \
        "sltu	$12, %[h], $12		\n\t"            \
        "daddu	%[o], %[o], $12		\n\t"            \
        "daddu	%[h], %[h], $11		\n\t"            \
        "sltu	$12, %[h], $11		\n\t"            \
        "daddu	%[o], %[o], $12		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "$10", "$11", "$12", "$lo", "$hi"              \
    )
/* Square va and store double size result in: vh | vl */
#define SP_ASM_SQR(vl, vh, va)                           \
    __asm__ __volatile__ (                               \
        "dmultu	%[a], %[a]		\n\t"            \
        "mflo	%[l]			\n\t"            \
        "mfhi	%[h]			\n\t"            \
        : [h] "+r" (vh), [l] "+r" (vl)                   \
        : [a] "r" (va)                                   \
        : "memory", "$lo", "$hi"                         \
    )
/* Square va and add double size result into: vo | vh | vl */
#define SP_ASM_SQR_ADD(vl, vh, vo, va)                   \
    __asm__ __volatile__ (                               \
        "dmultu	%[a], %[a]		\n\t"            \
        "mflo	$10			\n\t"            \
        "mfhi	$11			\n\t"            \
        "daddu	%[l], %[l], $10		\n\t"            \
        "sltu	$12, %[l], $10		\n\t"            \
        "daddu	%[h], %[h], $12		\n\t"            \
        "sltu	$12, %[h], $12		\n\t"            \
        "daddu	%[o], %[o], $12		\n\t"            \
        "daddu	%[h], %[h], $11		\n\t"            \
        "sltu	$12, %[h], $11		\n\t"            \
        "daddu	%[o], %[o], $12		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va)                                   \
        : "$10", "$11", "$12", "$lo", "$hi"              \
    )
/* Square va and add double size result into: vh | vl */
#define SP_ASM_SQR_ADD_NO(vl, vh, va)                    \
    __asm__ __volatile__ (                               \
        "dmultu	%[a], %[a]		\n\t"            \
        "mflo	$10			\n\t"            \
        "mfhi	$11			\n\t"            \
        "daddu	%[l], %[l], $10		\n\t"            \
        "sltu	$12, %[l], $10		\n\t"            \
        "daddu	%[h], %[h], $11		\n\t"            \
        "daddu	%[h], %[h], $12		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "r" (va)                                   \
        : "$10", "$11", "$12", "$lo", "$hi"              \
    )
/* Add va into: vh | vl */
#define SP_ASM_ADDC(vl, vh, va)                          \
    __asm__ __volatile__ (                               \
        "daddu	%[l], %[l], %[a]	\n\t"            \
        "sltu	$12, %[l], %[a]		\n\t"            \
        "daddu	%[h], %[h], $12		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "r" (va)                                   \
        : "$12"                                          \
    )
/* Sub va from: vh | vl */
#define SP_ASM_SUBC(vl, vh, va)                          \
    __asm__ __volatile__ (                               \
        "move	$12, %[l]		\n\t"            \
        "dsubu	%[l], $12, %[a]		\n\t"            \
        "sltu	$12, $12, %[l]		\n\t"            \
        "dsubu	%[h], %[h], $12		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "r" (va)                                   \
        : "$12"                                          \
    )
/* Add two times vc | vb | va into vo | vh | vl */
#define SP_ASM_ADD_DBL_3(vl, vh, vo, va, vb, vc)         \
    __asm__ __volatile__ (                               \
        "daddu	%[l], %[l], %[a]	\n\t"            \
        "sltu	$12, %[l], %[a]		\n\t"            \
        "daddu	%[h], %[h], $12		\n\t"            \
        "sltu	$12, %[h], $12		\n\t"            \
        "daddu	%[o], %[o], $12		\n\t"            \
        "daddu	%[h], %[h], %[b]	\n\t"            \
        "sltu	$12, %[h], %[b]		\n\t"            \
        "daddu	%[o], %[o], %[c]	\n\t"            \
        "daddu	%[o], %[o], $12		\n\t"            \
        "daddu	%[l], %[l], %[a]	\n\t"            \
        "sltu	$12, %[l], %[a]		\n\t"            \
        "daddu	%[h], %[h], $12		\n\t"            \
        "sltu	$12, %[h], $12		\n\t"            \
        "daddu	%[o], %[o], $12		\n\t"            \
        "daddu	%[h], %[h], %[b]	\n\t"            \
        "sltu	$12, %[h], %[b]		\n\t"            \
        "daddu	%[o], %[o], %[c]	\n\t"            \
        "daddu	%[o], %[o], $12		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va), [b] "r" (vb), [c] "r" (vc)       \
        : "$12"                                          \
    )

#define SP_INT_ASM_AVAILABLE

    #endif /* WOLFSSL_SP_MIPS64 && SP_WORD_SIZE == 64 */

    #if defined(WOLFSSL_SP_MIPS) && SP_WORD_SIZE == 32
/*
 * CPU: MIPS 32-bit
 */

/* Multiply va by vb and store double size result in: vh | vl */
#define SP_ASM_MUL(vl, vh, va, vb)                       \
    __asm__ __volatile__ (                               \
        "multu	%[a], %[b]		\n\t"            \
        "mflo	%[l]			\n\t"            \
        "mfhi	%[h]			\n\t"            \
        : [h] "+r" (vh), [l] "+r" (vl)                   \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "memory", "%lo", "%hi"                         \
    )
/* Multiply va by vb and store double size result in: vo | vh | vl */
#define SP_ASM_MUL_SET(vl, vh, vo, va, vb)               \
    __asm__ __volatile__ (                               \
        "multu	%[a], %[b]		\n\t"            \
        "mflo	%[l]			\n\t"            \
        "mfhi	%[h]			\n\t"            \
        "move	%[o], $0		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "=r" (vo)    \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "%lo", "%hi"                                   \
    )
/* Multiply va by vb and add double size result into: vo | vh | vl */
#define SP_ASM_MUL_ADD(vl, vh, vo, va, vb)               \
    __asm__ __volatile__ (                               \
        "multu	%[a], %[b]		\n\t"            \
        "mflo	$10			\n\t"            \
        "mfhi	$11			\n\t"            \
        "addu	%[l], %[l], $10		\n\t"            \
        "sltu	$12, %[l], $10		\n\t"            \
        "addu	%[h], %[h], $12		\n\t"            \
        "sltu	$12, %[h], $12		\n\t"            \
        "addu	%[o], %[o], $12		\n\t"            \
        "addu	%[h], %[h], $11		\n\t"            \
        "sltu	$12, %[h], $11		\n\t"            \
        "addu	%[o], %[o], $12		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "$10", "$11", "$12", "%lo", "%hi"              \
    )
/* Multiply va by vb and add double size result into: vh | vl */
#define SP_ASM_MUL_ADD_NO(vl, vh, va, vb)                \
    __asm__ __volatile__ (                               \
        "multu	%[a], %[b]		\n\t"            \
        "mflo	$10			\n\t"            \
        "mfhi	$11			\n\t"            \
        "addu	%[l], %[l], $10		\n\t"            \
        "sltu	$12, %[l], $10		\n\t"            \
        "addu	%[h], %[h], $11		\n\t"            \
        "addu	%[h], %[h], $12		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "$10", "$11", "$12", "%lo", "%hi"              \
    )
/* Multiply va by vb and add double size result twice into: vo | vh | vl */
#define SP_ASM_MUL_ADD2(vl, vh, vo, va, vb)              \
    __asm__ __volatile__ (                               \
        "multu	%[a], %[b]		\n\t"            \
        "mflo	$10			\n\t"            \
        "mfhi	$11			\n\t"            \
        "addu	%[l], %[l], $10		\n\t"            \
        "sltu	$12, %[l], $10		\n\t"            \
        "addu	%[h], %[h], $12		\n\t"            \
        "sltu	$12, %[h], $12		\n\t"            \
        "addu	%[o], %[o], $12		\n\t"            \
        "addu	%[h], %[h], $11		\n\t"            \
        "sltu	$12, %[h], $11		\n\t"            \
        "addu	%[o], %[o], $12		\n\t"            \
        "addu	%[l], %[l], $10		\n\t"            \
        "sltu	$12, %[l], $10		\n\t"            \
        "addu	%[h], %[h], $12		\n\t"            \
        "sltu	$12, %[h], $12		\n\t"            \
        "addu	%[o], %[o], $12		\n\t"            \
        "addu	%[h], %[h], $11		\n\t"            \
        "sltu	$12, %[h], $11		\n\t"            \
        "addu	%[o], %[o], $12		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "$10", "$11", "$12", "%lo", "%hi"              \
    )
/* Multiply va by vb and add double size result twice into: vo | vh | vl
 * Assumes first add will not overflow vh | vl
 */
#define SP_ASM_MUL_ADD2_NO(vl, vh, vo, va, vb)           \
    __asm__ __volatile__ (                               \
        "multu	%[a], %[b]		\n\t"            \
        "mflo	$10			\n\t"            \
        "mfhi	$11			\n\t"            \
        "addu	%[l], %[l], $10		\n\t"            \
        "sltu	$12, %[l], $10		\n\t"            \
        "addu	%[h], %[h], $11		\n\t"            \
        "addu	%[h], %[h], $12		\n\t"            \
        "addu	%[l], %[l], $10		\n\t"            \
        "sltu	$12, %[l], $10		\n\t"            \
        "addu	%[h], %[h], $12		\n\t"            \
        "sltu	$12, %[h], $12		\n\t"            \
        "addu	%[o], %[o], $12		\n\t"            \
        "addu	%[h], %[h], $11		\n\t"            \
        "sltu	$12, %[h], $11		\n\t"            \
        "addu	%[o], %[o], $12		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "$10", "$11", "$12", "%lo", "%hi"              \
    )
/* Square va and store double size result in: vh | vl */
#define SP_ASM_SQR(vl, vh, va)                           \
    __asm__ __volatile__ (                               \
        "multu	%[a], %[a]		\n\t"            \
        "mflo	%[l]			\n\t"            \
        "mfhi	%[h]			\n\t"            \
        : [h] "+r" (vh), [l] "+r" (vl)                   \
        : [a] "r" (va)                                   \
        : "memory", "%lo", "%hi"                         \
    )
/* Square va and add double size result into: vo | vh | vl */
#define SP_ASM_SQR_ADD(vl, vh, vo, va)                   \
    __asm__ __volatile__ (                               \
        "multu	%[a], %[a]		\n\t"            \
        "mflo	$10			\n\t"            \
        "mfhi	$11			\n\t"            \
        "addu	%[l], %[l], $10		\n\t"            \
        "sltu	$12, %[l], $10		\n\t"            \
        "addu	%[h], %[h], $12		\n\t"            \
        "sltu	$12, %[h], $12		\n\t"            \
        "addu	%[o], %[o], $12		\n\t"            \
        "addu	%[h], %[h], $11		\n\t"            \
        "sltu	$12, %[h], $11		\n\t"            \
        "addu	%[o], %[o], $12		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va)                                   \
        : "$10", "$11", "$12", "%lo", "%hi"              \
    )
/* Square va and add double size result into: vh | vl */
#define SP_ASM_SQR_ADD_NO(vl, vh, va)                    \
    __asm__ __volatile__ (                               \
        "multu	%[a], %[a]		\n\t"            \
        "mflo	$10			\n\t"            \
        "mfhi	$11			\n\t"            \
        "addu	%[l], %[l], $10		\n\t"            \
        "sltu	$12, %[l], $10		\n\t"            \
        "addu	%[h], %[h], $11		\n\t"            \
        "addu	%[h], %[h], $12		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "r" (va)                                   \
        : "$10", "$11", "$12", "%lo", "%hi"              \
    )
/* Add va into: vh | vl */
#define SP_ASM_ADDC(vl, vh, va)                          \
    __asm__ __volatile__ (                               \
        "addu	%[l], %[l], %[a]	\n\t"            \
        "sltu	$12, %[l], %[a]		\n\t"            \
        "addu	%[h], %[h], $12		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "r" (va)                                   \
        : "$12"                                          \
    )
/* Sub va from: vh | vl */
#define SP_ASM_SUBC(vl, vh, va)                          \
    __asm__ __volatile__ (                               \
        "move	$12, %[l]		\n\t"            \
        "subu	%[l], $12, %[a]		\n\t"            \
        "sltu	$12, $12, %[l]		\n\t"            \
        "subu	%[h], %[h], $12		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "r" (va)                                   \
        : "$12"                                          \
    )
/* Add two times vc | vb | va into vo | vh | vl */
#define SP_ASM_ADD_DBL_3(vl, vh, vo, va, vb, vc)         \
    __asm__ __volatile__ (                               \
        "addu	%[l], %[l], %[a]	\n\t"            \
        "sltu	$12, %[l], %[a]		\n\t"            \
        "addu	%[h], %[h], $12		\n\t"            \
        "sltu	$12, %[h], $12		\n\t"            \
        "addu	%[o], %[o], $12		\n\t"            \
        "addu	%[h], %[h], %[b]	\n\t"            \
        "sltu	$12, %[h], %[b]		\n\t"            \
        "addu	%[o], %[o], %[c]	\n\t"            \
        "addu	%[o], %[o], $12		\n\t"            \
        "addu	%[l], %[l], %[a]	\n\t"            \
        "sltu	$12, %[l], %[a]		\n\t"            \
        "addu	%[h], %[h], $12		\n\t"            \
        "sltu	$12, %[h], $12		\n\t"            \
        "addu	%[o], %[o], $12		\n\t"            \
        "addu	%[h], %[h], %[b]	\n\t"            \
        "sltu	$12, %[h], %[b]		\n\t"            \
        "addu	%[o], %[o], %[c]	\n\t"            \
        "addu	%[o], %[o], $12		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va), [b] "r" (vb), [c] "r" (vc)       \
        : "$12"                                          \
    )

#define SP_INT_ASM_AVAILABLE

    #endif /* WOLFSSL_SP_MIPS && SP_WORD_SIZE == 32 */

    #if defined(WOLFSSL_SP_RISCV64) && SP_WORD_SIZE == 64
/*
 * CPU: RISCV 64-bit
 */

/* Multiply va by vb and store double size result in: vh | vl */
#define SP_ASM_MUL(vl, vh, va, vb)                       \
    __asm__ __volatile__ (                               \
        "mul	%[l], %[a], %[b]	\n\t"            \
        "mulhu	%[h], %[a], %[b]	\n\t"            \
        : [h] "+r" (vh), [l] "+r" (vl)                   \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "memory"                                       \
    )
/* Multiply va by vb and store double size result in: vo | vh | vl */
#define SP_ASM_MUL_SET(vl, vh, vo, va, vb)               \
    __asm__ __volatile__ (                               \
        "mulhu	%[h], %[a], %[b]	\n\t"            \
        "mul	%[l], %[a], %[b]	\n\t"            \
        "add	%[o], zero, zero	\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "=r" (vo)    \
        : [a] "r" (va), [b] "r" (vb)                     \
        :                                                \
    )
/* Multiply va by vb and add double size result into: vo | vh | vl */
#define SP_ASM_MUL_ADD(vl, vh, vo, va, vb)               \
    __asm__ __volatile__ (                               \
        "mul	a5, %[a], %[b]		\n\t"            \
        "mulhu	a6, %[a], %[b]		\n\t"            \
        "add	%[l], %[l], a5		\n\t"            \
        "sltu	a7, %[l], a5		\n\t"            \
        "add	%[h], %[h], a7		\n\t"            \
        "sltu	a7, %[h], a7		\n\t"            \
        "add	%[o], %[o], a7		\n\t"            \
        "add	%[h], %[h], a6		\n\t"            \
        "sltu	a7, %[h], a6		\n\t"            \
        "add	%[o], %[o], a7		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "a5", "a6", "a7"                               \
    )
/* Multiply va by vb and add double size result into: vh | vl */
#define SP_ASM_MUL_ADD_NO(vl, vh, va, vb)                \
    __asm__ __volatile__ (                               \
        "mul	a5, %[a], %[b]		\n\t"            \
        "mulhu	a6, %[a], %[b]		\n\t"            \
        "add	%[l], %[l], a5		\n\t"            \
        "sltu	a7, %[l], a5		\n\t"            \
        "add	%[h], %[h], a6		\n\t"            \
        "add	%[h], %[h], a7		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "a5", "a6", "a7"                               \
    )
/* Multiply va by vb and add double size result twice into: vo | vh | vl */
#define SP_ASM_MUL_ADD2(vl, vh, vo, va, vb)              \
    __asm__ __volatile__ (                               \
        "mul	a5, %[a], %[b]		\n\t"            \
        "mulhu	a6, %[a], %[b]		\n\t"            \
        "add	%[l], %[l], a5		\n\t"            \
        "sltu	a7, %[l], a5		\n\t"            \
        "add	%[h], %[h], a7		\n\t"            \
        "sltu	a7, %[h], a7		\n\t"            \
        "add	%[o], %[o], a7		\n\t"            \
        "add	%[h], %[h], a6		\n\t"            \
        "sltu	a7, %[h], a6		\n\t"            \
        "add	%[o], %[o], a7		\n\t"            \
        "add	%[l], %[l], a5		\n\t"            \
        "sltu	a7, %[l], a5		\n\t"            \
        "add	%[h], %[h], a7		\n\t"            \
        "sltu	a7, %[h], a7		\n\t"            \
        "add	%[o], %[o], a7		\n\t"            \
        "add	%[h], %[h], a6		\n\t"            \
        "sltu	a7, %[h], a6		\n\t"            \
        "add	%[o], %[o], a7		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "a5", "a6", "a7"                               \
    )
/* Multiply va by vb and add double size result twice into: vo | vh | vl
 * Assumes first add will not overflow vh | vl
 */
#define SP_ASM_MUL_ADD2_NO(vl, vh, vo, va, vb)           \
    __asm__ __volatile__ (                               \
        "mul	a5, %[a], %[b]		\n\t"            \
        "mulhu	a6, %[a], %[b]		\n\t"            \
        "add	%[l], %[l], a5		\n\t"            \
        "sltu	a7, %[l], a5		\n\t"            \
        "add	%[h], %[h], a6		\n\t"            \
        "add	%[h], %[h], a7		\n\t"            \
        "add	%[l], %[l], a5		\n\t"            \
        "sltu	a7, %[l], a5		\n\t"            \
        "add	%[h], %[h], a7		\n\t"            \
        "sltu	a7, %[h], a7		\n\t"            \
        "add	%[o], %[o], a7		\n\t"            \
        "add	%[h], %[h], a6		\n\t"            \
        "sltu	a7, %[h], a6		\n\t"            \
        "add	%[o], %[o], a7		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "a5", "a6", "a7"                               \
    )
/* Square va and store double size result in: vh | vl */
#define SP_ASM_SQR(vl, vh, va)                           \
    __asm__ __volatile__ (                               \
        "mul	%[l], %[a], %[a]	\n\t"            \
        "mulhu	%[h], %[a], %[a]	\n\t"            \
        : [h] "+r" (vh), [l] "+r" (vl)                   \
        : [a] "r" (va)                                   \
        : "memory"                                       \
    )
/* Square va and add double size result into: vo | vh | vl */
#define SP_ASM_SQR_ADD(vl, vh, vo, va)                   \
    __asm__ __volatile__ (                               \
        "mul	a5, %[a], %[a]		\n\t"            \
        "mulhu	a6, %[a], %[a]		\n\t"            \
        "add	%[l], %[l], a5		\n\t"            \
        "sltu	a7, %[l], a5		\n\t"            \
        "add	%[h], %[h], a7		\n\t"            \
        "sltu	a7, %[h], a7		\n\t"            \
        "add	%[o], %[o], a7		\n\t"            \
        "add	%[h], %[h], a6		\n\t"            \
        "sltu	a7, %[h], a6		\n\t"            \
        "add	%[o], %[o], a7		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va)                                   \
        : "a5", "a6", "a7"                               \
    )
/* Square va and add double size result into: vh | vl */
#define SP_ASM_SQR_ADD_NO(vl, vh, va)                    \
    __asm__ __volatile__ (                               \
        "mul	a5, %[a], %[a]		\n\t"            \
        "mulhu	a6, %[a], %[a]		\n\t"            \
        "add	%[l], %[l], a5		\n\t"            \
        "sltu	a7, %[l], a5		\n\t"            \
        "add	%[h], %[h], a6		\n\t"            \
        "add	%[h], %[h], a7		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "r" (va)                                   \
        : "a5", "a6", "a7"                               \
    )
/* Add va into: vh | vl */
#define SP_ASM_ADDC(vl, vh, va)                          \
    __asm__ __volatile__ (                               \
        "add	%[l], %[l], %[a]	\n\t"            \
        "sltu	a7, %[l], %[a]		\n\t"            \
        "add	%[h], %[h], a7		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "r" (va)                                   \
        : "a7"                                           \
    )
/* Sub va from: vh | vl */
#define SP_ASM_SUBC(vl, vh, va)                          \
    __asm__ __volatile__ (                               \
        "add	a7, %[l], zero		\n\t"            \
        "sub	%[l], a7, %[a]		\n\t"            \
        "sltu	a7, a7, %[l]		\n\t"            \
        "sub	%[h], %[h], a7		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "r" (va)                                   \
        : "a7"                                           \
    )
/* Add two times vc | vb | va into vo | vh | vl */
#define SP_ASM_ADD_DBL_3(vl, vh, vo, va, vb, vc)         \
    __asm__ __volatile__ (                               \
        "add	%[l], %[l], %[a]	\n\t"            \
        "sltu	a7, %[l], %[a]		\n\t"            \
        "add	%[h], %[h], a7		\n\t"            \
        "sltu	a7, %[h], a7		\n\t"            \
        "add	%[o], %[o], a7		\n\t"            \
        "add	%[h], %[h], %[b]	\n\t"            \
        "sltu	a7, %[h], %[b]		\n\t"            \
        "add	%[o], %[o], %[c]	\n\t"            \
        "add	%[o], %[o], a7		\n\t"            \
        "add	%[l], %[l], %[a]	\n\t"            \
        "sltu	a7, %[l], %[a]		\n\t"            \
        "add	%[h], %[h], a7		\n\t"            \
        "sltu	a7, %[h], a7		\n\t"            \
        "add	%[o], %[o], a7		\n\t"            \
        "add	%[h], %[h], %[b]	\n\t"            \
        "sltu	a7, %[h], %[b]		\n\t"            \
        "add	%[o], %[o], %[c]	\n\t"            \
        "add	%[o], %[o], a7		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va), [b] "r" (vb), [c] "r" (vc)       \
        : "a7"                                           \
    )

#define SP_INT_ASM_AVAILABLE

    #endif /* WOLFSSL_SP_RISCV64 && SP_WORD_SIZE == 64 */

    #if defined(WOLFSSL_SP_RISCV32) && SP_WORD_SIZE == 32
/*
 * CPU: RISCV 32-bit
 */

/* Multiply va by vb and store double size result in: vh | vl */
#define SP_ASM_MUL(vl, vh, va, vb)                       \
    __asm__ __volatile__ (                               \
        "mul	%[l], %[a], %[b]	\n\t"            \
        "mulhu	%[h], %[a], %[b]	\n\t"            \
        : [h] "+r" (vh), [l] "+r" (vl)                   \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "memory"                                       \
    )
/* Multiply va by vb and store double size result in: vo | vh | vl */
#define SP_ASM_MUL_SET(vl, vh, vo, va, vb)               \
    __asm__ __volatile__ (                               \
        "mulhu	%[h], %[a], %[b]	\n\t"            \
        "mul	%[l], %[a], %[b]	\n\t"            \
        "add	%[o], zero, zero	\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "=r" (vo)    \
        : [a] "r" (va), [b] "r" (vb)                     \
        :                                                \
    )
/* Multiply va by vb and add double size result into: vo | vh | vl */
#define SP_ASM_MUL_ADD(vl, vh, vo, va, vb)               \
    __asm__ __volatile__ (                               \
        "mul	a5, %[a], %[b]		\n\t"            \
        "mulhu	a6, %[a], %[b]		\n\t"            \
        "add	%[l], %[l], a5		\n\t"            \
        "sltu	a7, %[l], a5		\n\t"            \
        "add	%[h], %[h], a7		\n\t"            \
        "sltu	a7, %[h], a7		\n\t"            \
        "add	%[o], %[o], a7		\n\t"            \
        "add	%[h], %[h], a6		\n\t"            \
        "sltu	a7, %[h], a6		\n\t"            \
        "add	%[o], %[o], a7		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "a5", "a6", "a7"                               \
    )
/* Multiply va by vb and add double size result into: vh | vl */
#define SP_ASM_MUL_ADD_NO(vl, vh, va, vb)                \
    __asm__ __volatile__ (                               \
        "mul	a5, %[a], %[b]		\n\t"            \
        "mulhu	a6, %[a], %[b]		\n\t"            \
        "add	%[l], %[l], a5		\n\t"            \
        "sltu	a7, %[l], a5		\n\t"            \
        "add	%[h], %[h], a6		\n\t"            \
        "add	%[h], %[h], a7		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "a5", "a6", "a7"                               \
    )
/* Multiply va by vb and add double size result twice into: vo | vh | vl */
#define SP_ASM_MUL_ADD2(vl, vh, vo, va, vb)              \
    __asm__ __volatile__ (                               \
        "mul	a5, %[a], %[b]		\n\t"            \
        "mulhu	a6, %[a], %[b]		\n\t"            \
        "add	%[l], %[l], a5		\n\t"            \
        "sltu	a7, %[l], a5		\n\t"            \
        "add	%[h], %[h], a7		\n\t"            \
        "sltu	a7, %[h], a7		\n\t"            \
        "add	%[o], %[o], a7		\n\t"            \
        "add	%[h], %[h], a6		\n\t"            \
        "sltu	a7, %[h], a6		\n\t"            \
        "add	%[o], %[o], a7		\n\t"            \
        "add	%[l], %[l], a5		\n\t"            \
        "sltu	a7, %[l], a5		\n\t"            \
        "add	%[h], %[h], a7		\n\t"            \
        "sltu	a7, %[h], a7		\n\t"            \
        "add	%[o], %[o], a7		\n\t"            \
        "add	%[h], %[h], a6		\n\t"            \
        "sltu	a7, %[h], a6		\n\t"            \
        "add	%[o], %[o], a7		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "a5", "a6", "a7"                               \
    )
/* Multiply va by vb and add double size result twice into: vo | vh | vl
 * Assumes first add will not overflow vh | vl
 */
#define SP_ASM_MUL_ADD2_NO(vl, vh, vo, va, vb)           \
    __asm__ __volatile__ (                               \
        "mul	a5, %[a], %[b]		\n\t"            \
        "mulhu	a6, %[a], %[b]		\n\t"            \
        "add	%[l], %[l], a5		\n\t"            \
        "sltu	a7, %[l], a5		\n\t"            \
        "add	%[h], %[h], a6		\n\t"            \
        "add	%[h], %[h], a7		\n\t"            \
        "add	%[l], %[l], a5		\n\t"            \
        "sltu	a7, %[l], a5		\n\t"            \
        "add	%[h], %[h], a7		\n\t"            \
        "sltu	a7, %[h], a7		\n\t"            \
        "add	%[o], %[o], a7		\n\t"            \
        "add	%[h], %[h], a6		\n\t"            \
        "sltu	a7, %[h], a6		\n\t"            \
        "add	%[o], %[o], a7		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "a5", "a6", "a7"                               \
    )
/* Square va and store double size result in: vh | vl */
#define SP_ASM_SQR(vl, vh, va)                           \
    __asm__ __volatile__ (                               \
        "mul	%[l], %[a], %[a]	\n\t"            \
        "mulhu	%[h], %[a], %[a]	\n\t"            \
        : [h] "+r" (vh), [l] "+r" (vl)                   \
        : [a] "r" (va)                                   \
        : "memory"                                       \
    )
/* Square va and add double size result into: vo | vh | vl */
#define SP_ASM_SQR_ADD(vl, vh, vo, va)                   \
    __asm__ __volatile__ (                               \
        "mul	a5, %[a], %[a]		\n\t"            \
        "mulhu	a6, %[a], %[a]		\n\t"            \
        "add	%[l], %[l], a5		\n\t"            \
        "sltu	a7, %[l], a5		\n\t"            \
        "add	%[h], %[h], a7		\n\t"            \
        "sltu	a7, %[h], a7		\n\t"            \
        "add	%[o], %[o], a7		\n\t"            \
        "add	%[h], %[h], a6		\n\t"            \
        "sltu	a7, %[h], a6		\n\t"            \
        "add	%[o], %[o], a7		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va)                                   \
        : "a5", "a6", "a7"                               \
    )
/* Square va and add double size result into: vh | vl */
#define SP_ASM_SQR_ADD_NO(vl, vh, va)                    \
    __asm__ __volatile__ (                               \
        "mul	a5, %[a], %[a]		\n\t"            \
        "mulhu	a6, %[a], %[a]		\n\t"            \
        "add	%[l], %[l], a5		\n\t"            \
        "sltu	a7, %[l], a5		\n\t"            \
        "add	%[h], %[h], a6		\n\t"            \
        "add	%[h], %[h], a7		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "r" (va)                                   \
        : "a5", "a6", "a7"                               \
    )
/* Add va into: vh | vl */
#define SP_ASM_ADDC(vl, vh, va)                          \
    __asm__ __volatile__ (                               \
        "add	%[l], %[l], %[a]	\n\t"            \
        "sltu	a7, %[l], %[a]		\n\t"            \
        "add	%[h], %[h], a7		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "r" (va)                                   \
        : "a7"                                           \
    )
/* Sub va from: vh | vl */
#define SP_ASM_SUBC(vl, vh, va)                          \
    __asm__ __volatile__ (                               \
        "add	a7, %[l], zero		\n\t"            \
        "sub	%[l], a7, %[a]		\n\t"            \
        "sltu	a7, a7, %[l]		\n\t"            \
        "sub	%[h], %[h], a7		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "r" (va)                                   \
        : "a7"                                           \
    )
/* Add two times vc | vb | va into vo | vh | vl */
#define SP_ASM_ADD_DBL_3(vl, vh, vo, va, vb, vc)         \
    __asm__ __volatile__ (                               \
        "add	%[l], %[l], %[a]	\n\t"            \
        "sltu	a7, %[l], %[a]		\n\t"            \
        "add	%[h], %[h], a7		\n\t"            \
        "sltu	a7, %[h], a7		\n\t"            \
        "add	%[o], %[o], a7		\n\t"            \
        "add	%[h], %[h], %[b]	\n\t"            \
        "sltu	a7, %[h], %[b]		\n\t"            \
        "add	%[o], %[o], %[c]	\n\t"            \
        "add	%[o], %[o], a7		\n\t"            \
        "add	%[l], %[l], %[a]	\n\t"            \
        "sltu	a7, %[l], %[a]		\n\t"            \
        "add	%[h], %[h], a7		\n\t"            \
        "sltu	a7, %[h], a7		\n\t"            \
        "add	%[o], %[o], a7		\n\t"            \
        "add	%[h], %[h], %[b]	\n\t"            \
        "sltu	a7, %[h], %[b]		\n\t"            \
        "add	%[o], %[o], %[c]	\n\t"            \
        "add	%[o], %[o], a7		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va), [b] "r" (vb), [c] "r" (vc)       \
        : "a7"                                           \
    )

#define SP_INT_ASM_AVAILABLE

    #endif /* WOLFSSL_SP_RISCV32 && SP_WORD_SIZE == 32 */

    #if defined(WOLFSSL_SP_S390X) && SP_WORD_SIZE == 64
/*
 * CPU: Intel s390x
 */

/* Multiply va by vb and store double size result in: vh | vl */
#define SP_ASM_MUL(vl, vh, va, vb)                       \
    __asm__ __volatile__ (                               \
        "lgr	%%r1, %[a]		\n\t"            \
        "mlgr	%%r0, %[b]		\n\t"            \
        "lgr	%[l], %%r1		\n\t"            \
        "lgr	%[h], %%r0		\n\t"            \
        : [h] "+r" (vh), [l] "+r" (vl)                   \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "memory", "r0", "r1"                           \
    )
/* Multiply va by vb and store double size result in: vo | vh | vl */
#define SP_ASM_MUL_SET(vl, vh, vo, va, vb)               \
    __asm__ __volatile__ (                               \
        "lgr	%%r1, %[a]		\n\t"            \
        "mlgr	%%r0, %[b]		\n\t"            \
        "lghi	%[o], 0			\n\t"            \
        "lgr	%[l], %%r1		\n\t"            \
        "lgr	%[h], %%r0		\n\t"            \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "=r" (vo)    \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "r0", "r1"                                     \
    )
/* Multiply va by vb and add double size result into: vo | vh | vl */
#define SP_ASM_MUL_ADD(vl, vh, vo, va, vb)               \
    __asm__ __volatile__ (                               \
        "lghi	%%r10, 0	\n\t"                    \
        "lgr	%%r1, %[a]		\n\t"            \
        "mlgr	%%r0, %[b]		\n\t"            \
        "algr	%[l], %%r1	\n\t"                    \
        "alcgr	%[h], %%r0	\n\t"                    \
        "alcgr	%[o], %%r10	\n\t"                    \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "r0", "r1", "r10", "cc"                        \
    )
/* Multiply va by vb and add double size result into: vh | vl */
#define SP_ASM_MUL_ADD_NO(vl, vh, va, vb)                \
    __asm__ __volatile__ (                               \
        "lgr	%%r1, %[a]		\n\t"            \
        "mlgr	%%r0, %[b]		\n\t"            \
        "algr	%[l], %%r1	\n\t"                    \
        "alcgr	%[h], %%r0	\n\t"                    \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "r0", "r1", "cc"                               \
    )
/* Multiply va by vb and add double size result twice into: vo | vh | vl */
#define SP_ASM_MUL_ADD2(vl, vh, vo, va, vb)              \
    __asm__ __volatile__ (                               \
        "lghi	%%r10, 0	\n\t"                    \
        "lgr	%%r1, %[a]		\n\t"            \
        "mlgr	%%r0, %[b]		\n\t"            \
        "algr	%[l], %%r1	\n\t"                    \
        "alcgr	%[h], %%r0	\n\t"                    \
        "alcgr	%[o], %%r10	\n\t"                    \
        "algr	%[l], %%r1	\n\t"                    \
        "alcgr	%[h], %%r0	\n\t"                    \
        "alcgr	%[o], %%r10	\n\t"                    \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "r0", "r1", "r10", "cc"                        \
    )
/* Multiply va by vb and add double size result twice into: vo | vh | vl
 * Assumes first add will not overflow vh | vl
 */
#define SP_ASM_MUL_ADD2_NO(vl, vh, vo, va, vb)           \
    __asm__ __volatile__ (                               \
        "lghi	%%r10, 0	\n\t"                    \
        "lgr	%%r1, %[a]		\n\t"            \
        "mlgr	%%r0, %[b]		\n\t"            \
        "algr	%[l], %%r1	\n\t"                    \
        "alcgr	%[h], %%r0	\n\t"                    \
        "algr	%[l], %%r1	\n\t"                    \
        "alcgr	%[h], %%r0	\n\t"                    \
        "alcgr	%[o], %%r10	\n\t"                    \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va), [b] "r" (vb)                     \
        : "r0", "r1", "r10", "cc"                        \
    )
/* Square va and store double size result in: vh | vl */
#define SP_ASM_SQR(vl, vh, va)                           \
    __asm__ __volatile__ (                               \
        "lgr	%%r1, %[a]		\n\t"            \
        "mlgr	%%r0, %%r1		\n\t"            \
        "lgr	%[l], %%r1		\n\t"            \
        "lgr	%[h], %%r0		\n\t"            \
        : [h] "+r" (vh), [l] "+r" (vl)                   \
        : [a] "r" (va)                                   \
        : "memory", "r0", "r1"                           \
    )
/* Square va and add double size result into: vo | vh | vl */
#define SP_ASM_SQR_ADD(vl, vh, vo, va)                   \
    __asm__ __volatile__ (                               \
        "lghi	%%r10, 0	\n\t"                    \
        "lgr	%%r1, %[a]		\n\t"            \
        "mlgr	%%r0, %%r1		\n\t"            \
        "algr	%[l], %%r1	\n\t"                    \
        "alcgr	%[h], %%r0	\n\t"                    \
        "alcgr	%[o], %%r10	\n\t"                    \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va)                                   \
        : "r0", "r1", "r10", "cc"                        \
    )
/* Square va and add double size result into: vh | vl */
#define SP_ASM_SQR_ADD_NO(vl, vh, va)                    \
    __asm__ __volatile__ (                               \
        "lgr	%%r1, %[a]		\n\t"            \
        "mlgr	%%r0, %%r1		\n\t"            \
        "algr	%[l], %%r1	\n\t"                    \
        "alcgr	%[h], %%r0	\n\t"                    \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "r" (va)                                   \
        : "r0", "r1", "cc"                               \
    )
/* Add va into: vh | vl */
#define SP_ASM_ADDC(vl, vh, va)                          \
    __asm__ __volatile__ (                               \
        "lghi	%%r10, 0	\n\t"                    \
        "algr	%[l], %[a]	\n\t"                    \
        "alcgr	%[h], %%r10	\n\t"                    \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "r" (va)                                   \
        : "r10", "cc"                                    \
    )
/* Sub va from: vh | vl */
#define SP_ASM_SUBC(vl, vh, va)                          \
    __asm__ __volatile__ (                               \
        "lghi	%%r10, 0	\n\t"                    \
        "slgr	%[l], %[a]	\n\t"                    \
        "slbgr	%[h], %%r10	\n\t"                    \
        : [l] "+r" (vl), [h] "+r" (vh)                   \
        : [a] "r" (va)                                   \
        : "r10", "cc"                                    \
    )
/* Add two times vc | vb | va into vo | vh | vl */
#define SP_ASM_ADD_DBL_3(vl, vh, vo, va, vb, vc)         \
    __asm__ __volatile__ (                               \
        "algr	%[l], %[a]	\n\t"                    \
        "alcgr	%[h], %[b]	\n\t"                    \
        "alcgr	%[o], %[c]	\n\t"                    \
        "algr	%[l], %[a]	\n\t"                    \
        "alcgr	%[h], %[b]	\n\t"                    \
        "alcgr	%[o], %[c]	\n\t"                    \
        : [l] "+r" (vl), [h] "+r" (vh), [o] "+r" (vo)    \
        : [a] "r" (va), [b] "r" (vb), [c] "r" (vc)       \
        : "cc"                                           \
    )

#define SP_INT_ASM_AVAILABLE

    #endif /* WOLFSSL_SP_S390X && SP_WORD_SIZE == 64 */

#ifdef SP_INT_ASM_AVAILABLE
    #ifndef SP_INT_NO_ASM
        #define SQR_MUL_ASM
    #endif
    #ifndef SP_ASM_ADDC_REG
        #define SP_ASM_ADDC_REG  SP_ASM_ADDC
    #endif /* SP_ASM_ADDC_REG */
#endif /* SQR_MUL_ASM */

#endif /* !WOLFSSL_NO_ASM */


#if (!defined(NO_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || \
    !defined(NO_DSA) || !defined(NO_DH) || \
    (defined(HAVE_ECC) && defined(HAVE_COMP_KEY)) || defined(OPENSSL_EXTRA) || \
    (defined(WOLFSSL_SP_MATH_ALL) && !defined(WOLFSSL_RSA_PUBLIC_ONLY))
#ifndef WC_NO_CACHE_RESISTANT
    /* Mask of address for constant time operations. */
    const size_t sp_off_on_addr[2] =
    {
        (size_t) 0,
        (size_t)-1
    };
#endif
#endif


#if defined(WOLFSSL_HAVE_SP_DH) || defined(WOLFSSL_HAVE_SP_RSA)

#ifdef __cplusplus
extern "C" {
#endif

/* Modular exponentiation implementations using Single Precision. */
WOLFSSL_LOCAL int sp_ModExp_1024(sp_int* base, sp_int* exp, sp_int* mod,
    sp_int* res);
WOLFSSL_LOCAL int sp_ModExp_1536(sp_int* base, sp_int* exp, sp_int* mod,
    sp_int* res);
WOLFSSL_LOCAL int sp_ModExp_2048(sp_int* base, sp_int* exp, sp_int* mod,
    sp_int* res);
WOLFSSL_LOCAL int sp_ModExp_3072(sp_int* base, sp_int* exp, sp_int* mod,
    sp_int* res);
WOLFSSL_LOCAL int sp_ModExp_4096(sp_int* base, sp_int* exp, sp_int* mod,
    sp_int* res);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* WOLFSSL_HAVE_SP_DH || WOLFSSL_HAVE_SP_RSA */


#if defined(WOLFSSL_SP_MATH_ALL) || defined(WOLFSSL_HAVE_SP_DH)
static int _sp_mont_red(sp_int* a, sp_int* m, sp_int_digit mp);
#endif

/* Set the multi-precision number to zero.
 *
 * Assumes a is not NULL.
 *
 * @param  [out]  a  SP integer to set to zero.
 */
static void _sp_zero(sp_int* a)
{
    a->used = 0;
    a->dp[0] = 0;
#ifdef WOLFSSL_SP_INT_NEGATIVE
    a->sign = MP_ZPOS;
#endif
}

/* Initialize the multi-precision number to be zero.
 *
 * @param  [out]  a  SP integer.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a is NULL.
 */
int sp_init(sp_int* a)
{
    int err = MP_OKAY;

    if (a == NULL) {
        err = MP_VAL;
    }
    if (err == MP_OKAY) {
        _sp_zero(a);
        a->size = SP_INT_DIGITS;
    #ifdef HAVE_WOLF_BIGINT
        wc_bigint_init(&a->raw);
    #endif
    }

    return err;
}

int sp_init_size(sp_int* a, int size)
{
    int err = sp_init(a);

    if (err == MP_OKAY) {
        a->size = size;
    }

    return err;
}

#if !defined(WOLFSSL_RSA_PUBLIC_ONLY) || !defined(NO_DH) || defined(HAVE_ECC)
/* Initialize up to six multi-precision numbers to be zero.
 *
 * @param  [out]  n1  SP integer.
 * @param  [out]  n2  SP integer.
 * @param  [out]  n3  SP integer.
 * @param  [out]  n4  SP integer.
 * @param  [out]  n5  SP integer.
 * @param  [out]  n6  SP integer.
 *
 * @return  MP_OKAY on success.
 */
int sp_init_multi(sp_int* n1, sp_int* n2, sp_int* n3, sp_int* n4, sp_int* n5,
                  sp_int* n6)
{
    if (n1 != NULL) {
        _sp_zero(n1);
        n1->dp[0] = 0;
        n1->size = SP_INT_DIGITS;
    }
    if (n2 != NULL) {
        _sp_zero(n2);
        n2->dp[0] = 0;
        n2->size = SP_INT_DIGITS;
    }
    if (n3 != NULL) {
        _sp_zero(n3);
        n3->dp[0] = 0;
        n3->size = SP_INT_DIGITS;
    }
    if (n4 != NULL) {
        _sp_zero(n4);
        n4->dp[0] = 0;
        n4->size = SP_INT_DIGITS;
    }
    if (n5 != NULL) {
        _sp_zero(n5);
        n5->dp[0] = 0;
        n5->size = SP_INT_DIGITS;
    }
    if (n6 != NULL) {
        _sp_zero(n6);
        n6->dp[0] = 0;
        n6->size = SP_INT_DIGITS;
    }

    return MP_OKAY;
}
#endif /* !WOLFSSL_RSA_PUBLIC_ONLY || !NO_DH || HAVE_ECC */

/* Free the memory allocated in the multi-precision number.
 *
 * @param  [in]  a  SP integer.
 */
void sp_free(sp_int* a)
{
    if (a != NULL) {
    #ifdef HAVE_WOLF_BIGINT
        wc_bigint_free(&a->raw);
    #endif
    }
}

#if !defined(WOLFSSL_RSA_VERIFY_ONLY) || !defined(NO_DH) || defined(HAVE_ECC)
/* Grow multi-precision number to be able to hold l digits.
 * This function does nothing as the number of digits is fixed.
 *
 * @param  [in,out]  a  SP integer.
 * @param  [in]      l  Number of digits to grow to.
 *
 * @return  MP_OKAY on success
 * @return  MP_MEM if the number of digits requested is more than available.
 */
int sp_grow(sp_int* a, int l)
{
    int err = MP_OKAY;

    if (a == NULL) {
        err = MP_VAL;
    }
    if ((err == MP_OKAY) && (l > a->size)) {
        err = MP_MEM;
    }
    if (err == MP_OKAY) {
        int i;

        for (i = a->used; i < l; i++) {
            a->dp[i] = 0;
        }
    }

    return err;
}
#endif /* !WOLFSSL_RSA_VERIFY_ONLY || !NO_DH || HAVE_ECC */

#if !defined(WOLFSSL_RSA_VERIFY_ONLY) || defined(HAVE_ECC)
/* Set the multi-precision number to zero.
 *
 * @param  [out]  a  SP integer to set to zero.
 */
void sp_zero(sp_int* a)
{
    if (a != NULL) {
        _sp_zero(a);
    }
}
#endif /* !WOLFSSL_RSA_VERIFY_ONLY */

/* Clear the data from the multi-precision number and set to zero.
 *
 * @param  [out]  a  SP integer.
 */
void sp_clear(sp_int* a)
{
    if (a != NULL) {
        int i;

        for (i = 0; i < a->used; i++) {
            a->dp[i] = 0;
        }
        _sp_zero(a);
    }
}

#if !defined(WOLFSSL_RSA_PUBLIC_ONLY) || !defined(NO_DH) || defined(HAVE_ECC)
/* Ensure the data in the multi-precision number is zeroed.
 *
 * Use when security sensitive data needs to be wiped.
 *
 * @param  [in]  a  SP integer.
 */
void sp_forcezero(sp_int* a)
{
    ForceZero(a->dp, a->used * sizeof(sp_int_digit));
    _sp_zero(a);
#ifdef HAVE_WOLF_BIGINT
    wc_bigint_zero(&a->raw);
#endif
}
#endif /* !WOLFSSL_RSA_VERIFY_ONLY || !NO_DH || HAVE_ECC */

#if defined(WOLFSSL_SP_MATH_ALL) || !defined(NO_DH) || defined(HAVE_ECC) || \
    !defined(NO_RSA) || defined(WOLFSSL_KEY_GEN) || defined(HAVE_COMP_KEY)
/* Copy value of multi-precision number a into r.
 *
 * @param  [in]   a  SP integer - source.
 * @param  [out]  r  SP integer - destination.
 *
 * @return  MP_OKAY on success.
 */
int sp_copy(const sp_int* a, sp_int* r)
{
    int err = MP_OKAY;

    if ((a == NULL) || (r == NULL)) {
        err = MP_VAL;
    }
    else if (a != r) {
        XMEMCPY(r->dp, a->dp, a->used * sizeof(sp_int_digit));
        if (a->used == 0)
            r->dp[0] = 0;
        r->used = a->used;
#ifdef WOLFSSL_SP_INT_NEGATIVE
        r->sign = a->sign;
#endif
    }

    return err;
}
#endif

#if defined(WOLFSSL_SP_MATH_ALL) || (defined(HAVE_ECC) && defined(FP_ECC))
/* Initializes r and copies in value from a.
 *
 * @param  [out]  r  SP integer - destination.
 * @param  [in]   a  SP integer - source.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a or r is NULL.
 */
int sp_init_copy(sp_int* r, sp_int* a)
{
    int err;

    err = sp_init(r);
    if (err == MP_OKAY) {
        err = sp_copy(a, r);
    }
    return err;
}
#endif /* WOLFSSL_SP_MATH_ALL || (HAVE_ECC && FP_ECC) */

#if (defined(WOLFSSL_SP_MATH_ALL) && !defined(WOLFSSL_RSA_VERIFY_ONLY)) || \
    !defined(NO_DH) || !defined(NO_DSA)
/* Exchange the values in a and b.
 *
 * @param  [in,out]  a  SP integer to swap.
 * @param  [in,out]  b  SP integer to swap.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a or b is NULL.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
int sp_exch(sp_int* a, sp_int* b)
{
    int err = MP_OKAY;
    DECL_SP_INT(t, (a != NULL) ? a->used : 1);

    if ((a == NULL) || (b == NULL)) {
        err = MP_VAL;
    }
    if ((err == MP_OKAY) && ((a->size < b->used) || (b->size < a->used))) {
        err = MP_VAL;
    }

    ALLOC_SP_INT(t, a->used, err, NULL);
    if (err == MP_OKAY) {
        int asize = a->size;
        int bsize = b->size;
        XMEMCPY(t, a, MP_INT_SIZEOF(a->used));
        XMEMCPY(a, b, MP_INT_SIZEOF(b->used));
        XMEMCPY(b, t, MP_INT_SIZEOF(t->used));
        a->size = asize;
        b->size = bsize;
    }

    FREE_SP_INT(t, NULL);
    return err;
}
#endif /* (WOLFSSL_SP_MATH_ALL && !WOLFSSL_RSA_VERIFY_ONLY) || !NO_DH ||
        * !NO_DSA */

#if defined(HAVE_ECC) && defined(ECC_TIMING_RESISTANT) && \
    !defined(WC_NO_CACHE_RESISTANT)
int sp_cond_swap_ct(sp_int * a, sp_int * b, int c, int m)
{
    int i;
    int err = MP_OKAY;
    sp_digit mask = (sp_digit)0 - m;
    DECL_SP_INT(t, c);

    ALLOC_SP_INT(t, c, err, NULL);
    if (err == MP_OKAY) {
        t->used = (int)((a->used ^ b->used) & mask);
    #ifdef WOLFSSL_SP_INT_NEGATIVE
        t->sign = (int)((a->sign ^ b->sign) & mask);
    #endif
        for (i = 0; i < c; i++) {
            t->dp[i] = (a->dp[i] ^ b->dp[i]) & mask;
        }
        a->used ^= t->used;
    #ifdef WOLFSSL_SP_INT_NEGATIVE
        a->sign ^= t->sign;
    #endif
        for (i = 0; i < c; i++) {
            a->dp[i] ^= t->dp[i];
        }
        b->used ^= t->used;
    #ifdef WOLFSSL_SP_INT_NEGATIVE
        b->sign ^= b->sign;
    #endif
        for (i = 0; i < c; i++) {
            b->dp[i] ^= t->dp[i];
        }
    }

    FREE_SP_INT(t, NULL);
    return err;
}
#endif /* HAVE_ECC && ECC_TIMING_RESISTANT && !WC_NO_CACHE_RESISTANT */

#ifdef WOLFSSL_SP_INT_NEGATIVE
/* Calculate the absolute value of the multi-precision number.
 *
 * @param  [in]   a  SP integer to calculate absolute value of.
 * @param  [out]  r  SP integer to hold result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a or r is NULL.
 */
int sp_abs(sp_int* a, sp_int* r)
{
    int err;

    err = sp_copy(a, r);
    if (r != NULL) {
        r->sign = MP_ZPOS;
    }

    return err;
}
#endif /* WOLFSSL_SP_INT_NEGATIVE */

#if defined(WOLFSSL_SP_MATH_ALL) || !defined(NO_DH) || defined(HAVE_ECC) || \
    (!defined(NO_RSA) && !defined(WOLFSSL_RSA_VERIFY_ONLY))
/* Compare absolute value of two multi-precision numbers.
 *
 * @param  [in]  a  SP integer.
 * @param  [in]  b  SP integer.
 *
 * @return  MP_GT when a is greater than b.
 * @return  MP_LT when a is less than b.
 * @return  MP_EQ when a is equals b.
 */
static int _sp_cmp_abs(sp_int* a, sp_int* b)
{
    int ret = MP_EQ;

    if (a->used > b->used) {
        ret = MP_GT;
    }
    else if (a->used < b->used) {
        ret = MP_LT;
    }
    else {
        int i;

        for (i = a->used - 1; i >= 0; i--) {
            if (a->dp[i] > b->dp[i]) {
                ret = MP_GT;
                break;
            }
            else if (a->dp[i] < b->dp[i]) {
                ret = MP_LT;
                break;
            }
        }
    }

    return ret;
}
#endif

#if defined(WOLFSSL_SP_MATH_ALL) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)
/* Compare absolute value of two multi-precision numbers.
 *
 * @param  [in]  a  SP integer.
 * @param  [in]  b  SP integer.
 *
 * @return  MP_GT when a is greater than b.
 * @return  MP_LT when a is less than b.
 * @return  MP_EQ when a is equals b.
 */
int sp_cmp_mag(sp_int* a, sp_int* b)
{
    int ret;

    if (a == b) {
        ret = MP_EQ;
    }
    else if (a == NULL) {
        ret = MP_LT;
    }
    else if (b == NULL) {
        ret = MP_GT;
    }
    else
    {
        ret = _sp_cmp_abs(a, b);
    }

    return ret;
}
#endif

#if defined(WOLFSSL_SP_MATH_ALL) || defined(HAVE_ECC) || !defined(NO_DSA) || \
    defined(OPENSSL_EXTRA) || !defined(NO_DH) || \
    (!defined(NO_RSA) && !defined(WOLFSSL_RSA_VERIFY_ONLY))
/* Compare two multi-precision numbers.
 *
 * Assumes a and b are not NULL.
 *
 * @param  [in]  a  SP integer.
 * @param  [in]  a  SP integer.
 *
 * @return  MP_GT when a is greater than b.
 * @return  MP_LT when a is less than b.
 * @return  MP_EQ when a is equals b.
 */
static int _sp_cmp(sp_int* a, sp_int* b)
{
    int ret;

#ifdef WOLFSSL_SP_INT_NEGATIVE
    if (a->sign == b->sign) {
#endif
        ret = _sp_cmp_abs(a, b);
#ifdef WOLFSSL_SP_INT_NEGATIVE
        if (a->sign == MP_NEG) {
            /* MP_GT = 1, MP_LT = -1, MP_EQ = 0
             * Swapping MP_GT and MP_LT results.
             */
            ret = -ret;
        }
    }
    else if (a->sign > b->sign) {
        ret = MP_LT;
    }
    else /* (a->sign < b->sign) */ {
        ret = MP_GT;
    }
#endif

    return ret;
}
#endif

#if (!defined(NO_RSA) && !defined(WOLFSSL_RSA_VERIFY_ONLY)) || \
    !defined(NO_DSA) || defined(HAVE_ECC) || !defined(NO_DH) || \
    defined(WOLFSSL_SP_MATH_ALL)
/* Compare two multi-precision numbers.
 *
 * Pointers are compared such that NULL is less than not NULL.
 *
 * @param  [in]  a  SP integer.
 * @param  [in]  a  SP integer.
 *
 * @return  MP_GT when a is greater than b.
 * @return  MP_LT when a is less than b.
 * @return  MP_EQ when a is equals b.
 */
int sp_cmp(sp_int* a, sp_int* b)
{
    int ret;

    if (a == b) {
        ret = MP_EQ;
    }
    else if (a == NULL) {
        ret = MP_LT;
    }
    else if (b == NULL) {
        ret = MP_GT;
    }
    else
    {
        ret = _sp_cmp(a, b);
    }

    return ret;
}
#endif

/*************************
 * Bit check/set functions
 *************************/

#if !defined(WOLFSSL_RSA_VERIFY_ONLY)
/* Check if a bit is set
 *
 * When a is NULL, result is 0.
 *
 * @param  [in]  a  SP integer.
 * @param  [in]  b  Bit position to check.
 *
 * @return  0 when bit is not set.
 * @return  1 when bit is set.
 */
int sp_is_bit_set(sp_int* a, unsigned int b)
{
    int ret = 0;
    int i = (int)(b >> SP_WORD_SHIFT);
    int s = (int)(b & SP_WORD_MASK);

    if ((a != NULL) && (i < a->used)) {
        ret = (int)((a->dp[i] >> s) & (sp_int_digit)1);
    }

    return ret;
}
#endif /* WOLFSSL_RSA_VERIFY_ONLY */

/* Count the number of bits in the multi-precision number.
 *
 * When a is not NULL, result is 0.
 *
 * @param  [in]  a  SP integer.
 *
 * @return  The number of bits in the number.
 */
int sp_count_bits(const sp_int* a)
{
    int r = 0;

    if (a != NULL) {
        r = a->used - 1;
        while ((r >= 0) && (a->dp[r] == 0)) {
            r--;
        }
        if (r < 0) {
            r = 0;
        }
        else {
            sp_int_digit d;

            d = a->dp[r];
            r *= SP_WORD_SIZE;
            if (d > SP_HALF_MAX) {
                r += SP_WORD_SIZE;
                while ((d & ((sp_digit)1 << (SP_WORD_SIZE - 1))) == 0) {
                    r--;
                    d <<= 1;
                }
            }
            else {
                while (d != 0) {
                    r++;
                    d >>= 1;
                }
            }
        }
    }

    return r;
}

#if (defined(WOLFSSL_SP_MATH_ALL) && !defined(WOLFSSL_RSA_VERIFY_ONLY) && \
    !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH) || \
    (defined(HAVE_ECC) && defined(FP_ECC)) || \
    (!defined(NO_RSA) && defined(WOLFSSL_KEY_GEN))

/* Number of entries in array of number of least significant zero bits. */
#define SP_LNZ_CNT      16
/* Number of bits the array checks. */
#define SP_LNZ_BITS     4
/* Mask to apply to check with array. */
#define SP_LNZ_MASK     0xf
/* Number of least significant zero bits in first SP_LNZ_CNT numbers. */
static const int sp_lnz[SP_LNZ_CNT] = {
   4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0
};

/* Count the number of least significant zero bits.
 *
 * When a is not NULL, result is 0.
 *
 * @param  [in]   a  SP integer to use.
 *
 * @return  Number of leas significant zero bits.
 */
#if !defined(HAVE_ECC) || !defined(HAVE_COMP_KEY)
static
#endif /* !HAVE_ECC || HAVE_COMP_KEY */
int sp_cnt_lsb(sp_int* a)
{
    int bc = 0;

    if ((a != NULL) && (!sp_iszero(a))) {
        int i;
        int j;
        int cnt = 0;

        for (i = 0; i < a->used && a->dp[i] == 0; i++, cnt += SP_WORD_SIZE) {
        }

        for (j = 0; j < SP_WORD_SIZE; j += SP_LNZ_BITS) {
            bc = sp_lnz[(a->dp[i] >> j) & SP_LNZ_MASK];
            if (bc != 4) {
                bc += cnt + j;
                break;
            }
        }
    }

    return bc;
}
#endif /* WOLFSSL_SP_MATH_ALL || WOLFSSL_HAVE_SP_DH || (HAVE_ECC && FP_ECC) */

#if !defined(WOLFSSL_RSA_VERIFY_ONLY)
/* Determine if the most significant byte of the encoded multi-precision number
 * has the top bit set.
 *
 * When A is NULL, result is 0.
 *
 * @param  [in]  a  SP integer.
 *
 * @return  1 when the top bit of top byte is set.
 * @return  0 when the top bit of top byte is not set.
 */
int sp_leading_bit(sp_int* a)
{
    int bit = 0;

    if ((a != NULL) && (a->used > 0)) {
        sp_int_digit d = a->dp[a->used - 1];
    #if SP_WORD_SIZE > 8
        while (d > (sp_int_digit)0xff) {
            d >>= 8;
        }
    #endif
        bit = (int)(d >> 7);
    }

    return bit;
}
#endif /* !WOLFSSL_RSA_VERIFY_ONLY */

#if defined(WOLFSSL_SP_MATH_ALL) || defined(WOLFSSL_HAVE_SP_DH) || \
    defined(HAVE_ECC) || defined(WOLFSSL_KEY_GEN) || defined(OPENSSL_EXTRA) || \
    !defined(NO_RSA)
/* Set a bit of a: a |= 1 << i
 * The field 'used' is updated in a.
 *
 * @param  [in,out]  a  SP integer to set bit into.
 * @param  [in]      i  Index of bit to set.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a is NULL or index is too large.
 */
int sp_set_bit(sp_int* a, int i)
{
    int err = MP_OKAY;
    int w = (int)(i >> SP_WORD_SHIFT);

    if ((a == NULL) || (w >= a->size)) {
        err = MP_VAL;
    }
    else {
        int s = (int)(i & (SP_WORD_SIZE - 1));
        int j;

        for (j = a->used; j <= w; j++) {
            a->dp[j] = 0;
        }
        a->dp[w] |= (sp_int_digit)1 << s;
        if (a->used <= w) {
            a->used = w + 1;
        }
    }
    return err;
}
#endif /* WOLFSSL_SP_MATH_ALL || WOLFSSL_HAVE_SP_DH || HAVE_ECC ||
        * WOLFSSL_KEY_GEN || OPENSSL_EXTRA || !NO_RSA */

#if (defined(WOLFSSL_SP_MATH_ALL) && !defined(WOLFSSL_RSA_VERIFY_ONLY)) || \
    defined(WOLFSSL_KEY_GEN) || !defined(NO_DH)
/* Exponentiate 2 to the power of e: a = 2^e
 * This is done by setting the 'e'th bit.
 *
 * @param  [out]  a  SP integer to hold result.
 * @param  [in]   e  Exponent.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a is NULL or 2^exponent is too large.
 */
int sp_2expt(sp_int* a, int e)
{
    int err = MP_OKAY;

    if (a == NULL) {
        err = MP_VAL;
    }
    if (err == MP_OKAY) {
        _sp_zero(a);
        err = sp_set_bit(a, e);
    }

    return err;
}
#endif /* (WOLFSSL_SP_MATH_ALL && !WOLFSSL_RSA_VERIFY_ONLY) ||
        * WOLFSSL_KEY_GEN || !NO_DH */

/**********************
 * Digit/Long functions
 **********************/

/* Set the multi-precision number to be the value of the digit.
 *
 * @param  [out]  a  SP integer to become number.
 * @param  [in]   d  Digit to be set.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a is NULL.
 */
int sp_set(sp_int* a, sp_int_digit d)
{
    int err = MP_OKAY;

    if (a == NULL) {
        err = MP_VAL;
    }
    if (err == MP_OKAY) {
        /* gcc-11 reports out-of-bounds array access if the byte array backing
         * the sp_int* is smaller than sizeof(sp_int), as occurs when
         * WOLFSSL_SP_SMALL.
         */
        PRAGMA_GCC_DIAG_PUSH;
        PRAGMA_GCC("GCC diagnostic ignored \"-Warray-bounds\"");
        a->dp[0] = d;
        a->used = d > 0;
    #ifdef WOLFSSL_SP_INT_NEGATIVE
        a->sign = MP_ZPOS;
    #endif
        PRAGMA_GCC_DIAG_POP;
    }

    return err;
}

#if defined(WOLFSSL_SP_MATH_ALL) || !defined(NO_RSA)
/* Set a number into the multi-precision number.
 *
 * Number may be larger than the size of a digit.
 *
 * @param  [out]  a  SP integer to set.
 * @param  [in]   n  Long value to set.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a is NULL.
 */
int sp_set_int(sp_int* a, unsigned long n)
{
    int err = MP_OKAY;

    if (a == NULL) {
        err = MP_VAL;
    }

    if (err == MP_OKAY) {
    #if SP_WORD_SIZE < SP_ULONG_BITS
        if (n <= (sp_int_digit)SP_DIGIT_MAX) {
    #endif
            a->dp[0] = (sp_int_digit)n;
            a->used = (n != 0);
    #if SP_WORD_SIZE < SP_ULONG_BITS
        }
        else {
            int i;

            for (i = 0; n > 0; i++,n >>= SP_WORD_SIZE) {
                a->dp[i] = (sp_int_digit)n;
            }
            a->used = i;
        }
    #endif
    #ifdef WOLFSSL_SP_INT_NEGATIVE
        a->sign = MP_ZPOS;
    #endif
    }

    return err;
}
#endif /* WOLFSSL_SP_MATH_ALL || !NO_RSA  */

#ifndef WOLFSSL_RSA_VERIFY_ONLY
/* Compare a one digit number with a multi-precision number.
 *
 * When a is NULL, MP_LT is returned.
 *
 * @param  [in]  a  SP integer to compare.
 * @param  [in]  d  Digit to compare with.
 *
 * @return  MP_GT when a is greater than d.
 * @return  MP_LT when a is less than d.
 * @return  MP_EQ when a is equals d.
 */
int sp_cmp_d(sp_int* a, sp_int_digit d)
{
    int ret = MP_EQ;

    if (a == NULL) {
        ret = MP_LT;
    }
    else
#ifdef WOLFSSL_SP_INT_NEGATIVE
    if (a->sign == MP_NEG) {
        ret = MP_LT;
    }
    else
#endif
    {
        /* special case for zero*/
        if (a->used == 0) {
            if (d == 0) {
                ret = MP_EQ;
            }
            else {
                ret = MP_LT;
            }
        }
        else if (a->used > 1) {
            ret = MP_GT;
        }
        else {
            if (a->dp[0] > d) {
                ret = MP_GT;
            }
            else if (a->dp[0] < d) {
                ret = MP_LT;
            }
        }
    }

    return ret;
}
#endif

#if !defined(NO_PWDBASED) || defined(WOLFSSL_KEY_GEN) || !defined(NO_DH) || \
    !defined(NO_DSA) || (!defined(NO_RSA) && !defined(WOLFSSL_RSA_VERIFY_ONLY))
#define WOLFSSL_SP_ADD_D
#endif
#if (!defined(NO_RSA) && !defined(WOLFSSL_RSA_VERIFY_ONLY)) || \
    !defined(NO_DH) || defined(HAVE_ECC) || !defined(NO_DSA)
#define WOLFSSL_SP_SUB_D
#endif
#if defined(WOLFSSL_SP_MATH_ALL) && !defined(NO_RSA) && \
    !defined(WOLFSSL_RSA_VERIFY_ONLY)
#define WOLFSSL_SP_READ_RADIX_10
#endif
#if defined(HAVE_ECC) || !defined(NO_DSA) || defined(OPENSSL_EXTRA) || \
    (!defined(NO_RSA) && !defined(WOLFSSL_RSA_VERIFY_ONLY) && \
     !defined(WOLFSSL_RSA_PUBLIC_ONLY))
#define WOLFSSL_SP_INVMOD
#endif
#if defined(WOLFSSL_SP_MATH_ALL) && defined(HAVE_ECC)
#define WOLFSSL_SP_INVMOD_MONT_CT
#endif
#if (defined(WOLFSSL_SP_MATH_ALL) && !defined(WOLFSSL_RSA_VERIFY_ONLY) && \
    !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH) || \
    (!defined(NO_RSA) && defined(WOLFSSL_KEY_GEN))
#define WOLFSSL_SP_PRIME_GEN
#endif

#if defined(WOLFSSL_SP_ADD_D) || (defined(WOLFSSL_SP_INT_NEGATIVE) && \
    defined(WOLFSSL_SP_SUB_D)) || defined(WOLFSSL_SP_READ_RADIX_10)
/* Add a one digit number to the multi-precision number.
 *
 * @param  [in]   a  SP integer be added to.
 * @param  [in]   d  Digit to add.
 * @param  [out]  r  SP integer to store result in.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when result is too large for fixed size dp array.
 */
static int _sp_add_d(sp_int* a, sp_int_digit d, sp_int* r)
{
    int err = MP_OKAY;
    int i = 0;
    sp_int_digit t;

    r->used = a->used;
    if (a->used == 0) {
        r->used = d > 0;
    }
    t = a->dp[0] + d;
    if (t < a->dp[0]) {
        for (++i; i < a->used; i++) {
            r->dp[i] = a->dp[i] + 1;
            if (r->dp[i] != 0) {
               break;
            }
        }
        if (i == a->used) {
            r->used++;
            if (i < r->size)
                r->dp[i] = 1;
            else
                err = MP_VAL;
        }
    }
    if (err == MP_OKAY) {
        r->dp[0] = t;
        if (r != a) {
            for (++i; i < a->used; i++) {
                r->dp[i] = a->dp[i];
            }
        }
    }

    return err;
}
#endif /* WOLFSSL_SP_ADD_D || (WOLFSSL_SP_INT_NEGATIVE && WOLFSSL_SP_SUB_D) ||
        * defined(WOLFSSL_SP_READ_RADIX_10) */

#if (defined(WOLFSSL_SP_INT_NEGATIVE) && defined(WOLFSSL_SP_ADD_D)) || \
    defined(WOLFSSL_SP_SUB_D) || defined(WOLFSSL_SP_INVMOD) || \
    defined(WOLFSSL_SP_INVMOD_MONT_CT) || defined(WOLFSSL_SP_PRIME_GEN)
/* Sub a one digit number from the multi-precision number.
 *
 * returns MP_OKAY always.
 * @param  [in]   a  SP integer be subtracted from.
 * @param  [in]   d  Digit to subtract.
 * @param  [out]  r  SP integer to store result in.
 */
static void _sp_sub_d(sp_int* a, sp_int_digit d, sp_int* r)
{
    int i = 0;
    sp_int_digit t;

    r->used = a->used;
    if (a->used == 0) {
        r->dp[0] = 0;
    }
    else {
        t = a->dp[0] - d;
        if (t > a->dp[0]) {
            for (++i; i < a->used; i++) {
                r->dp[i] = a->dp[i] - 1;
                if (r->dp[i] != SP_DIGIT_MAX) {
                   break;
                }
            }
        }
        r->dp[0] = t;
        if (r != a) {
            for (++i; i < a->used; i++) {
                r->dp[i] = a->dp[i];
            }
        }
        sp_clamp(r);
    }
}
#endif /* (WOLFSSL_SP_INT_NEGATIVE && WOLFSSL_SP_ADD_D) || WOLFSSL_SP_SUB_D
        * WOLFSSL_SP_INVMOD || WOLFSSL_SP_INVMOD_MONT_CT ||
        * WOLFSSL_SP_PRIME_GEN */

#ifdef WOLFSSL_SP_ADD_D
/* Add a one digit number to the multi-precision number.
 *
 * @param  [in]   a  SP integer be added to.
 * @param  [in]   d  Digit to add.
 * @param  [out]  r  SP integer to store result in.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when result is too large for fixed size dp array.
 */
int sp_add_d(sp_int* a, sp_int_digit d, sp_int* r)
{
    int err = MP_OKAY;

    /* Check validity of parameters. */
    if ((a == NULL) || (r == NULL)) {
        err = MP_VAL;
    }
    else
    {
    #ifndef WOLFSSL_SP_INT_NEGATIVE
        /* Positive only so just use internal function. */
        err = _sp_add_d(a, d, r);
    #else
        if (a->sign == MP_ZPOS) {
            /* Positive so use interal function. */
            r->sign = MP_ZPOS;
            err = _sp_add_d(a, d, r);
        }
        else if ((a->used > 1) || (a->dp[0] > d)) {
            /* Negative value bigger than digit so subtract digit. */
            r->sign = MP_NEG;
            _sp_sub_d(a, d, r);
        }
        else {
            /* Negative value smaller or equal to digit. */
            r->sign = MP_ZPOS;
            /* Subtract negative value from digit. */
            r->dp[0] = d - a->dp[0];
            /* Result is a digit equal to or greater than zero. */
            r->used = ((r->dp[0] == 0) ? 0 : 1);
        }
    #endif
    }

    return err;
}
#endif /* WOLFSSL_SP_ADD_D */

#ifdef WOLFSSL_SP_SUB_D
/* Sub a one digit number from the multi-precision number.
 *
 * @param  [in]   a  SP integer be subtracted from.
 * @param  [in]   d  Digit to subtract.
 * @param  [out]  r  SP integer to store result in.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a or r is NULL.
 */
int sp_sub_d(sp_int* a, sp_int_digit d, sp_int* r)
{
    int err = MP_OKAY;

    /* Check validity of parameters. */
    if ((a == NULL) || (r == NULL)) {
        err = MP_VAL;
    }
    else {
    #ifndef WOLFSSL_SP_INT_NEGATIVE
        /* Positive only so just use internal function. */
        _sp_sub_d(a, d, r);
    #else
        if (a->sign == MP_NEG) {
            /* Subtracting from negative use interal add. */
            r->sign = MP_NEG;
            err = _sp_add_d(a, d, r);
        }
        else if ((a->used > 1) || (a->dp[0] >= d)) {
            /* Positive number greater than digit so add digit. */
            r->sign = MP_ZPOS;
            _sp_sub_d(a, d, r);
        }
        else {
            /* Negative value smaller than digit. */
            r->sign = MP_NEG;
            /* Subtract positive value from digit. */
            r->dp[0] = d - a->dp[0];
            /* Result is a digit equal to or greater than zero. */
            r->used = 1;
        }
    #endif
    }

    return err;
}
#endif /* WOLFSSL_SP_SUB_D */

#if (defined(WOLFSSL_SP_MATH_ALL) && !defined(WOLFSSL_RSA_VERIFY_ONLY)) || \
    defined(WOLFSSL_SP_SMALL) && (defined(WOLFSSL_SP_MATH_ALL) || \
    !defined(NO_DH) || defined(HAVE_ECC) || \
    (!defined(NO_RSA) && !defined(WOLFSSL_RSA_VERIFY_ONLY) && \
     !defined(WOLFSSL_RSA_PUBLIC_ONLY))) || \
    (defined(WOLFSSL_KEY_GEN) && !defined(NO_RSA))
/* Multiply a by digit n and put result into r shifting up o digits.
 *   r = (a * n) << (o * SP_WORD_SIZE)
 *
 * @param  [in]   a  SP integer to be multiplied.
 * @param  [in]   n  Number (SP digit) to multiply by.
 * @param  [out]  r  SP integer result.
 * @param  [in]   o  Number of digits to move result up by.
 * @return  MP_OKAY on success.
 * @return  MP_VAL when result is too large for sp_int.
 */
static int _sp_mul_d(sp_int* a, sp_int_digit n, sp_int* r, int o)
{
    int err = MP_OKAY;
    int i;
    sp_int_word t = 0;

#ifdef WOLFSSL_SP_SMALL
    for (i = 0; i < o; i++) {
        r->dp[i] = 0;
    }
#else
    /* Don't use the offset. Only when doing small code size div. */
    (void)o;
#endif

    for (i = 0; i < a->used; i++, o++) {
        t += (sp_int_word)a->dp[i] * n;
        r->dp[o] = (sp_int_digit)t;
        t >>= SP_WORD_SIZE;
    }

    if (t > 0) {
        if (o == r->size) {
            err = MP_VAL;
        }
        else {
            r->dp[o++] = (sp_int_digit)t;
        }
    }
    r->used = o;
    sp_clamp(r);

    return err;
}
#endif /* (WOLFSSL_SP_MATH_ALL && !WOLFSSL_RSA_VERIFY_ONLY) ||
        *  WOLFSSL_SP_SMALL || (WOLFSSL_KEY_GEN && !NO_RSA) */

#if (defined(WOLFSSL_SP_MATH_ALL) && !defined(WOLFSSL_RSA_VERIFY_ONLY)) || \
    (defined(WOLFSSL_KEY_GEN) && !defined(NO_RSA))
/* Multiply a by digit n and put result into r. r = a * n
 *
 * @param  [in]   a  SP integer to multiply.
 * @param  [in]   n  Digit to multiply by.
 * @param  [out]  r  SP integer to hold result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a or b is NULL, or a has maximum number of digits used.
 */
int sp_mul_d(sp_int* a, sp_int_digit d, sp_int* r)
{
    int err = MP_OKAY;

    if ((a == NULL) || (r == NULL)) {
        err = MP_VAL;
    }
    if ((err == MP_OKAY) && (a->used + 1 > r->size)) {
        err = MP_VAL;
    }

    if (err == MP_OKAY) {
        err = _sp_mul_d(a, d, r, 0);
    #ifdef WOLFSSL_SP_INT_NEGATIVE
        if (d == 0) {
            r->sign = MP_ZPOS;
        }
        else {
            r->sign = a->sign;
        }
    #endif
    }

    return err;
}
#endif /* (WOLFSSL_SP_MATH_ALL && !WOLFSSL_RSA_VERIFY_ONLY) ||
        * (WOLFSSL_KEY_GEN && !NO_RSA) */

/* Predefine complicated rules of when to compile in sp_div_d and sp_mod_d. */
#if (defined(WOLFSSL_SP_MATH_ALL) && !defined(WOLFSSL_RSA_VERIFY_ONLY)) || \
    defined(WOLFSSL_KEY_GEN) || defined(HAVE_COMP_KEY) || \
    defined(WC_MP_TO_RADIX)
#define WOLFSSL_SP_DIV_D
#endif
#if (defined(WOLFSSL_SP_MATH_ALL) && !defined(WOLFSSL_RSA_VERIFY_ONLY)) || \
    defined(WOLFSSL_HAVE_SP_DH) || \
    (defined(HAVE_ECC) && (defined(FP_ECC) || defined(HAVE_COMP_KEY))) || \
    (!defined(NO_RSA) && defined(WOLFSSL_KEY_GEN))
#define WOLFSSL_SP_MOD_D
#endif

#if (defined(WOLFSSL_SP_MATH_ALL) || !defined(NO_DH) || defined(HAVE_ECC) || \
     (!defined(NO_RSA) && !defined(WOLFSSL_RSA_VERIFY_ONLY) && \
      !defined(WOLFSSL_RSA_PUBLIC_ONLY))) || \
    defined(WOLFSSL_SP_DIV_D) || defined(WOLFSSL_SP_MOD_D)
#ifndef SP_ASM_DIV_WORD
/* Divide a two digit number by a digit number and return. (hi | lo) / d
 *
 * @param  [in]  hi  SP integer digit. High digit of the dividend.
 * @param  [in]  lo  SP integer digit. Lower digit of the dividend.
 * @param  [in]  d   SP integer digit. Number to divide by.
 * @return  The division result.
 */
static WC_INLINE sp_int_digit sp_div_word(sp_int_digit hi, sp_int_digit lo,
                                          sp_int_digit d)
{
#ifdef WOLFSSL_SP_DIV_WORD_HALF
    sp_int_digit r;

    if (hi != 0) {
        sp_int_digit divsz = d >> SP_HALF_SIZE;
        sp_int_digit r2;
        sp_int_word w = ((sp_int_word)hi << SP_WORD_SIZE) | lo;
        sp_int_word trial;

        r = hi / divsz;
        if (r > SP_HALF_MAX) {
            r = SP_HALF_MAX;
        }
        r <<= SP_HALF_SIZE;
        trial = r * (sp_int_word)d;
        while (trial > w) {
            r -= (sp_int_digit)1 << SP_HALF_SIZE;
            trial -= (sp_int_word)d << SP_HALF_SIZE;
        }
        w -= trial;
        r2 = ((sp_int_digit)(w >> SP_HALF_SIZE)) / divsz;
        trial = r2 * (sp_int_word)d;
        while (trial > w) {
            r2--;
            trial -= d;
        }
        w -= trial;
        r += r2;
        r2 = ((sp_int_digit)w) / d;
        r += r2;
    }
    else {
        r = lo / d;
    }

    return r;
#else
    sp_int_word w;
    sp_int_digit r;

    w = ((sp_int_word)hi << SP_WORD_SIZE) | lo;
    w /= d;
    r = (sp_int_digit)w;

    return r;
#endif /* WOLFSSL_SP_DIV_WORD_HALF */
}
#endif /* !SP_ASM_DIV_WORD */
#endif /* WOLFSSL_SP_MATH_ALL || !NO_DH || HAVE_ECC ||
        * (!NO_RSA && !WOLFSSL_RSA_VERIFY_ONLY) */

#if (defined(WOLFSSL_SP_DIV_D) || defined(WOLFSSL_SP_MOD_D)) && \
    !defined(WOLFSSL_SP_SMALL)
/* Divide by 3: r = a / 3 and rem = a % 3
 *
 * @param  [in]   a    SP integer to be divided.
 * @param  [out]  r    SP integer that is the quotient. May be NULL.
 * @param  [out]  rem  SP integer that is the remainder. May be NULL.
 */
static void _sp_div_3(sp_int* a, sp_int* r, sp_int_digit* rem)
{
    int i;
    sp_int_word t;
    sp_int_digit tr = 0;
    sp_int_digit tt;
    static const unsigned char sp_r6[6] = { 0, 0, 0, 1, 1, 1 };
    static const unsigned char sp_rem6[6] = { 0, 1, 2, 0, 1, 2 };

    if (r == NULL) {
        for (i = a->used - 1; i >= 0; i--) {
            t = ((sp_int_word)tr << SP_WORD_SIZE) | a->dp[i];
        #if SP_WORD_SIZE == 64
            tt = (t * 0x5555555555555555L) >> 64;
        #elif SP_WORD_SIZE == 32
            tt = (t * 0x55555555) >> 32;
        #elif SP_WORD_SIZE == 16
            tt = (t * 0x5555) >> 16;
        #elif SP_WORD_SIZE == 8
            tt = (t * 0x55) >> 8;
        #endif
            tr = (sp_int_digit)(t - (sp_int_word)tt * 3);
            tr = sp_rem6[tr];
        }
        *rem = tr;
    }
    else {
        for (i = a->used - 1; i >= 0; i--) {
            t = ((sp_int_word)tr << SP_WORD_SIZE) | a->dp[i];
        #if SP_WORD_SIZE == 64
            tt = (t * 0x5555555555555555L) >> 64;
        #elif SP_WORD_SIZE == 32
            tt = (t * 0x55555555) >> 32;
        #elif SP_WORD_SIZE == 16
            tt = (t * 0x5555) >> 16;
        #elif SP_WORD_SIZE == 8
            tt = (t * 0x55) >> 8;
        #endif
            tr = (sp_int_digit)(t - (sp_int_word)tt * 3);
            tt += sp_r6[tr];
            tr = sp_rem6[tr];
            r->dp[i] = tt;
        }
        r->used = a->used;
        sp_clamp(r);
        if (rem != NULL) {
            *rem = tr;
        }
    }
}

/* Divide by 10: r = a / 10 and rem = a % 10
 *
 * @param  [in]   a    SP integer to be divided.
 * @param  [out]  r    SP integer that is the quotient. May be NULL.
 * @param  [out]  rem  SP integer that is the remainder. May be NULL.
 */
static void _sp_div_10(sp_int* a, sp_int* r, sp_int_digit* rem)
{
    int i;
    sp_int_word t;
    sp_int_digit tr = 0;
    sp_int_digit tt;

    if (r == NULL) {
        for (i = a->used - 1; i >= 0; i--) {
            t = ((sp_int_word)tr << SP_WORD_SIZE) | a->dp[i];
        #if SP_WORD_SIZE == 64
            tt = (t * 0x1999999999999999L) >> 64;
        #elif SP_WORD_SIZE == 32
            tt = (t * 0x19999999) >> 32;
        #elif SP_WORD_SIZE == 16
            tt = (t * 0x1999) >> 16;
        #elif SP_WORD_SIZE == 8
            tt = (t * 0x19) >> 8;
        #endif
            tr = (sp_int_digit)(t - (sp_int_word)tt * 10);
            tr = tr % 10;
        }
        *rem = tr;
    }
    else {
        for (i = a->used - 1; i >= 0; i--) {
            t = ((sp_int_word)tr << SP_WORD_SIZE) | a->dp[i];
        #if SP_WORD_SIZE == 64
            tt = (t * 0x1999999999999999L) >> 64;
        #elif SP_WORD_SIZE == 32
            tt = (t * 0x19999999) >> 32;
        #elif SP_WORD_SIZE == 16
            tt = (t * 0x1999) >> 16;
        #elif SP_WORD_SIZE == 8
            tt = (t * 0x19) >> 8;
        #endif
            tr = (sp_int_digit)(t - (sp_int_word)tt * 10);
            tt += tr / 10;
            tr = tr % 10;
            r->dp[i] = tt;
        }
        r->used = a->used;
        sp_clamp(r);
        if (rem != NULL) {
            *rem = tr;
        }
    }
}
#endif /* (WOLFSSL_SP_DIV_D || WOLFSSL_SP_MOD_D) && !WOLFSSL_SP_SMALL */

#if defined(WOLFSSL_SP_DIV_D) || defined(WOLFSSL_SP_MOD_D)
/* Divide by small number: r = a / d and rem = a % d
 *
 * @param  [in]   a    SP integer to be divided.
 * @param  [in]   d    Digit to divide by.
 * @param  [out]  r    SP integer that is the quotient. May be NULL.
 * @param  [out]  rem  SP integer that is the remainder. May be NULL.
 */
static void _sp_div_small(sp_int* a, sp_int_digit d, sp_int* r,
                         sp_int_digit* rem)
{
    int i;
    sp_int_word t;
    sp_int_digit tr = 0;
    sp_int_digit tt;
    sp_int_digit m;

    if (r == NULL) {
        m = SP_DIGIT_MAX / d;
        for (i = a->used - 1; i >= 0; i--) {
            t = ((sp_int_word)tr << SP_WORD_SIZE) | a->dp[i];
            tt = (t * m) >> SP_WORD_SIZE;
            tr = (sp_int_digit)(t - tt * d);
            tr = tr % d;
        }
        *rem = tr;
    }
    else {
        m = SP_DIGIT_MAX / d;
        for (i = a->used - 1; i >= 0; i--) {
            t = ((sp_int_word)tr << SP_WORD_SIZE) | a->dp[i];
            tt = (t * m) >> SP_WORD_SIZE;
            tr = (sp_int_digit)(t - tt * d);
            tt += tr / d;
            tr = tr % d;
            r->dp[i] = tt;
        }
        r->used = a->used;
        sp_clamp(r);
        if (rem != NULL) {
            *rem = tr;
        }
    }
}
#endif

#ifdef WOLFSSL_SP_DIV_D
/* Divide a multi-precision number by a digit size number and calculate
 * remainder.
 *   r = a / d; rem = a % d
 *
 * @param  [in]   a    SP integer to be divided.
 * @param  [in]   d    Digit to divide by.
 * @param  [out]  r    SP integer that is the quotient. May be NULL.
 * @param  [out]  rem  Digit that is the remainder. May be NULL.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a is NULL or d is 0.
 */
int sp_div_d(sp_int* a, sp_int_digit d, sp_int* r, sp_int_digit* rem)
{
    int err = MP_OKAY;

    if ((a == NULL) || (d == 0)) {
        err = MP_VAL;
    }

    if (err == MP_OKAY) {
    #if !defined(WOLFSSL_SP_SMALL)
        if (d == 3) {
            _sp_div_3(a, r, rem);
        }
        else if (d == 10) {
            _sp_div_10(a, r, rem);
        }
        else
    #endif
        if (d <= SP_HALF_MAX) {
            _sp_div_small(a, d, r, rem);
        }
        else
        {
            int i;
            sp_int_word w = 0;
            sp_int_digit t;

            for (i = a->used - 1; i >= 0; i--) {
                t = sp_div_word((sp_int_digit)w, a->dp[i], d);
                w = (w << SP_WORD_SIZE) | a->dp[i];
                w -= (sp_int_word)t * d;
                if (r != NULL) {
                    r->dp[i] = t;
                }
            }
            if (r != NULL) {
                r->used = a->used;
                sp_clamp(r);
            }

            if (rem != NULL) {
                *rem = (sp_int_digit)w;
            }
        }

    #ifdef WOLFSSL_SP_INT_NEGATIVE
        if (r != NULL) {
            r->sign = a->sign;
        }
    #endif
    }

    return err;
}
#endif /* WOLFSSL_SP_DIV_D */

#ifdef WOLFSSL_SP_MOD_D
/* Calculate a modulo the digit d into r: r = a mod d
 *
 * @param  [in]   a  SP integer to reduce.
 * @param  [in]   d  Digit to that is the modulus.
 * @param  [out]  r  Digit that is the result..
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a is NULL or d is 0.
 */
#if !defined(WOLFSSL_SP_MATH_ALL) && (!defined(HAVE_ECC) || \
    !defined(HAVE_COMP_KEY))
static
#endif /* !WOLFSSL_SP_MATH_ALL && (!HAVE_ECC || !HAVE_COMP_KEY) */
int sp_mod_d(sp_int* a, const sp_int_digit d, sp_int_digit* r)
{
    int err = MP_OKAY;

    if ((a == NULL) || (r == NULL) || (d == 0)) {
        err = MP_VAL;
    }

#if 0
    sp_print(a, "a");
    sp_print_digit(d, "m");
#endif

    if (err == MP_OKAY) {
        /* Check whether d is a power of 2. */
        if ((d & (d - 1)) == 0) {
            if (a->used == 0) {
                *r = 0;
            }
            else {
                *r = a->dp[0] & (d - 1);
            }
        }
    #if !defined(WOLFSSL_SP_SMALL)
        else if (d == 3) {
            _sp_div_3(a, NULL, r);
        }
        else if (d == 10) {
            _sp_div_10(a, NULL, r);
        }
    #endif
        else if (d <= SP_HALF_MAX) {
            _sp_div_small(a, d, NULL, r);
        }
        else {
            int i;
            sp_int_word w = 0;
            sp_int_digit t;

            for (i = a->used - 1; i >= 0; i--) {
                t = sp_div_word((sp_int_digit)w, a->dp[i], d);
                w = (w << SP_WORD_SIZE) | a->dp[i];
                w -= (sp_int_word)t * d;
            }

            *r = (sp_int_digit)w;
        }

    #ifdef WOLFSSL_SP_INT_NEGATIVE
        if (a->sign == MP_NEG) {
            *r = d - *r;
        }
    #endif
    }

#if 0
    sp_print_digit(*r, "rmod");
#endif

    return err;
}
#endif /* WOLFSSL_SP_MOD_D */

#if defined(WOLFSSL_SP_MATH_ALL) && defined(HAVE_ECC)
/* Divides a by 2 mod m and stores in r: r = (a / 2) mod m
 *
 * r = a / 2 (mod m) - constant time (a < m and positive)
 *
 * @param  [in]   a  SP integer to divide.
 * @param  [in]   m  SP integer that is modulus.
 * @param  [out]  r  SP integer to hold result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a, m or r is NULL.
 */
int sp_div_2_mod_ct(sp_int* a, sp_int* m, sp_int* r)
{
    int err = MP_OKAY;

    if ((a == NULL) || (m == NULL) || (r == NULL)) {
        err = MP_VAL;
    }
    if ((err == MP_OKAY) && (r->size < m->used + 1)) {
        err = MP_VAL;
    }

    if (err == MP_OKAY) {
        sp_int_word  w = 0;
        sp_int_digit mask;
        int i;

    #if 0
        sp_print(a, "a");
        sp_print(m, "m");
    #endif

        mask = 0 - (a->dp[0] & 1);
        for (i = 0; i < m->used; i++) {
            sp_int_digit mask_a = 0 - (i < a->used);

            w         += m->dp[i] & mask;
            w         += a->dp[i] & mask_a;
            r->dp[i]   = (sp_int_digit)w;
            w        >>= DIGIT_BIT;
        }
        r->dp[i] = (sp_int_digit)w;
        r->used = i + 1;
    #ifdef WOLFSSL_SP_INT_NEGATIVE
        r->sign = MP_ZPOS;
    #endif
        sp_clamp(r);
        sp_div_2(r, r);

    #if 0
        sp_print(r, "rd2");
    #endif
    }

    return err;
}
#endif /* WOLFSSL_SP_MATH_ALL && HAVE_ECC */

#if defined(HAVE_ECC) || !defined(NO_DSA) || defined(OPENSSL_EXTRA) || \
    (!defined(NO_RSA) && !defined(WOLFSSL_RSA_VERIFY_ONLY) && \
     !defined(WOLFSSL_RSA_PUBLIC_ONLY))
/* Divides a by 2 and stores in r: r = a >> 1
 *
 * @param  [in]   a  SP integer to divide.
 * @param  [out]  r  SP integer to hold result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a or r is NULL.
 */
#if !(defined(WOLFSSL_SP_MATH_ALL) && defined(HAVE_ECC))
static
#endif
int sp_div_2(sp_int* a, sp_int* r)
{
    int err = MP_OKAY;

#if defined(WOLFSSL_SP_MATH_ALL) && defined(HAVE_ECC)
    /* Only when a public API. */
    if ((a == NULL) || (r == NULL)) {
        err = MP_VAL;
    }
#endif

    if (err == MP_OKAY) {
        int i;

        r->used = a->used;
        for (i = 0; i < a->used - 1; i++) {
            r->dp[i] = (a->dp[i] >> 1) | (a->dp[i+1] << (SP_WORD_SIZE - 1));
        }
        r->dp[i] = a->dp[i] >> 1;
        r->used = i + 1;
        sp_clamp(r);
    #ifdef WOLFSSL_SP_INT_NEGATIVE
        r->sign = a->sign;
    #endif
    }

    return err;
}
#endif /* HAVE_ECC || !NO_DSA || OPENSSL_EXTRA ||
        * (!NO_RSA && !WOLFSSL_RSA_VERIFY_ONLY) */

/************************
 * Add/Subtract Functions
 ************************/

#if !defined(WOLFSSL_RSA_VERIFY_ONLY) || defined(WOLFSSL_SP_INVMOD)
/* Add offset b to a into r: r = a + (b << (o * SP_WORD_SIZEOF))
 *
 * @param  [in]   a  SP integer to add to.
 * @param  [in]   b  SP integer to add.
 * @param  [out]  r  SP integer to store result in.
 * @param  [in]   o  Number of digits to offset b.
 *
 * @return  MP_OKAY on success.
 */
static int _sp_add_off(sp_int* a, sp_int* b, sp_int* r, int o)
{
    int i;
    int j;
    sp_int_word t = 0;

#if 0
    sp_print(a, "a");
    sp_print(b, "b");
#endif

#ifdef SP_MATH_NEED_ADD_OFF
    for (i = 0; (i < o) && (i < a->used); i++) {
        r->dp[i] = a->dp[i];
    }
    for (; i < o; i++) {
        r->dp[i] = 0;
    }
#else
    i = 0;
    (void)o;
#endif

    for (j = 0; (i < a->used) && (j < b->used); i++, j++) {
        t += a->dp[i];
        t += b->dp[j];
        r->dp[i] = (sp_int_digit)t;
        t >>= SP_WORD_SIZE;
    }
    for (; i < a->used; i++) {
        t += a->dp[i];
        r->dp[i] = (sp_int_digit)t;
        t >>= SP_WORD_SIZE;
    }
    for (; j < b->used; i++, j++) {
        t += b->dp[j];
        r->dp[i] = (sp_int_digit)t;
        t >>= SP_WORD_SIZE;
    }
    r->used = i;
    if (t != 0) {
       r->dp[i] = (sp_int_digit)t;
       r->used++;
    }

    sp_clamp(r);

#if 0
    sp_print(r, "radd");
#endif

    return MP_OKAY;
}
#endif /* !WOLFSSL_RSA_VERIFY_ONLY */

#if defined(WOLFSSL_SP_MATH_ALL) || defined(WOLFSSL_SP_INT_NEGATIVE) || \
    !defined(NO_DH) || defined(HAVE_ECC) || (!defined(NO_RSA) && \
    !defined(WOLFSSL_RSA_VERIFY_ONLY))
/* Sub offset b from a into r: r = a - (b << (o * SP_WORD_SIZEOF))
 * a must be greater than b.
 *
 * @param  [in]   a  SP integer to subtract from.
 * @param  [in]   b  SP integer to subtract.
 * @param  [out]  r  SP integer to store result in.
 * @param  [in]   o  Number of digits to offset b.
 *
 * @return  MP_OKAY on success.
 */
static int _sp_sub_off(sp_int* a, sp_int* b, sp_int* r, int o)
{
    int i;
    int j;
    sp_int_sword t = 0;

    for (i = 0; (i < o) && (i < a->used); i++) {
        r->dp[i] = a->dp[i];
    }
    for (j = 0; (i < a->used) && (j < b->used); i++, j++) {
        t += a->dp[i];
        t -= b->dp[j];
        r->dp[i] = (sp_int_digit)t;
        t >>= SP_WORD_SIZE;
    }
    for (; i < a->used; i++) {
        t += a->dp[i];
        r->dp[i] = (sp_int_digit)t;
        t >>= SP_WORD_SIZE;
    }
    r->used = i;
    sp_clamp(r);

    return MP_OKAY;
}
#endif /* WOLFSSL_SP_MATH_ALL || WOLFSSL_SP_INT_NEGATIVE || !NO_DH ||
        * HAVE_ECC || (!NO_RSA && !WOLFSSL_RSA_VERIFY_ONLY) */

#if !defined(WOLFSSL_RSA_VERIFY_ONLY) || defined(WOLFSSL_SP_INVMOD)
/* Add b to a into r: r = a + b
 *
 * @param  [in]   a  SP integer to add to.
 * @param  [in]   b  SP integer to add.
 * @param  [out]  r  SP integer to store result in.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a, b, or r is NULL.
 */
int sp_add(sp_int* a, sp_int* b, sp_int* r)
{
    int err = MP_OKAY;

    if ((a == NULL) || (b == NULL) || (r == NULL)) {
        err = MP_VAL;
    }
    if ((err == MP_OKAY) && ((a->used >= r->size) || (b->used >= r->size))) {
        err = MP_VAL;
    }
    if (err == MP_OKAY) {
    #ifndef WOLFSSL_SP_INT_NEGATIVE
        err = _sp_add_off(a, b, r, 0);
    #else
        if (a->sign == b->sign) {
            r->sign = a->sign;
            err = _sp_add_off(a, b, r, 0);
        }
        else if (_sp_cmp_abs(a, b) != MP_LT) {
            err = _sp_sub_off(a, b, r, 0);
            if (sp_iszero(r)) {
                r->sign = MP_ZPOS;
            }
            else {
                r->sign = a->sign;
            }
        }
        else {
            err = _sp_sub_off(b, a, r, 0);
            if (sp_iszero(r)) {
                r->sign = MP_ZPOS;
            }
            else {
                r->sign = b->sign;
            }
        }
    #endif
    }

    return err;
}
#endif /* !WOLFSSL_RSA_VERIFY_ONLY */

#if defined(WOLFSSL_SP_MATH_ALL) || !defined(NO_DH) || defined(HAVE_ECC) || \
    (!defined(NO_RSA) && !defined(WOLFSSL_RSA_VERIFY_ONLY))
/* Subtract b from a into r: r = a - b
 *
 * a must be greater than b unless WOLFSSL_SP_INT_NEGATIVE is defined.
 *
 * @param  [in]   a  SP integer to subtract from.
 * @param  [in]   b  SP integer to subtract.
 * @param  [out]  r  SP integer to store result in.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a, b, or r is NULL.
 */
int sp_sub(sp_int* a, sp_int* b, sp_int* r)
{
    int err = MP_OKAY;

    if ((a == NULL) || (b == NULL) || (r == NULL)) {
        err = MP_VAL;
    }
    else {
    #ifndef WOLFSSL_SP_INT_NEGATIVE
        err = _sp_sub_off(a, b, r, 0);
    #else
        if (a->sign != b->sign) {
            r->sign = a->sign;
            err = _sp_add_off(a, b, r, 0);
        }
        else if (_sp_cmp_abs(a, b) != MP_LT) {
            err = _sp_sub_off(a, b, r, 0);
            if (sp_iszero(r)) {
                r->sign = MP_ZPOS;
            }
            else {
                r->sign = a->sign;
            }
        }
        else {
            err = _sp_sub_off(b, a, r, 0);
            if (sp_iszero(r)) {
                r->sign = MP_ZPOS;
            }
            else {
                r->sign = 1 - a->sign;
            }
        }
    #endif
    }

    return err;
}
#endif /* WOLFSSL_SP_MATH_ALL || !NO_DH || HAVE_ECC ||
        * (!NO_RSA && !WOLFSSL_RSA_VERIFY_ONLY)*/

/****************************
 * Add/Subtract mod functions
 ****************************/

#if (defined(WOLFSSL_SP_MATH_ALL) && !defined(WOLFSSL_RSA_VERIFY_ONLY)) || \
    (!defined(WOLFSSL_SP_MATH) && defined(WOLFSSL_CUSTOM_CURVES)) || \
    defined(WOLFCRYPT_HAVE_ECCSI) || defined(WOLFCRYPT_HAVE_SAKKE)
/* Add two value and reduce: r = (a + b) % m
 *
 * @param  [in]   a  SP integer to add.
 * @param  [in]   b  SP integer to add with.
 * @param  [in]   m  SP integer that is the modulus.
 * @param  [out]  r  SP integer to hold result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a, b, m or r is NULL.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
int sp_addmod(sp_int* a, sp_int* b, sp_int* m, sp_int* r)
{
    int err = MP_OKAY;
    int used = ((a == NULL) || (b == NULL)) ? 1 :
                   ((a->used >= b->used) ? a->used + 1 : b->used + 1);
    DECL_SP_INT(t, used);

    if ((a == NULL) || (b == NULL) || (m == NULL) || (r == NULL)) {
        err = MP_VAL;
    }

    ALLOC_SP_INT_SIZE(t, used, err, NULL);
#if 0
    if (err == MP_OKAY) {
        sp_print(a, "a");
        sp_print(b, "b");
        sp_print(m, "m");
    }
#endif

    if (err == MP_OKAY) {
        err = sp_add(a, b, t);
    }
    if (err == MP_OKAY) {
        err = sp_mod(t, m, r);
    }

#if 0
    if (err == MP_OKAY) {
        sp_print(r, "rma");
    }
#endif

    FREE_SP_INT(t, NULL);
    return err;
}
#endif /* WOLFSSL_SP_MATH_ALL || WOLFSSL_CUSTOM_CURVES) ||
        * WOLFCRYPT_HAVE_ECCSI || WOLFCRYPT_HAVE_SAKKE */

#if defined(WOLFSSL_SP_MATH_ALL) && !defined(WOLFSSL_RSA_VERIFY_ONLY)
/* Sub b from a and reduce: r = (a - b) % m
 * Result is always positive.
 *
 * @param  [in]   a  SP integer to subtract from
 * @param  [in]   b  SP integer to subtract.
 * @param  [in]   m  SP integer that is the modulus.
 * @param  [out]  r  SP integer to hold result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a, b, m or r is NULL.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
int sp_submod(sp_int* a, sp_int* b, sp_int* m, sp_int* r)
{
#ifndef WOLFSSL_SP_INT_NEGATIVE
    int err = MP_OKAY;
    int used = ((a == NULL) || (b == NULL) || (m == NULL)) ? 1 :
                   ((a->used >= m->used) ?
                       ((a->used >= b->used) ? (a->used + 1) : (b->used + 1)) :
                   ((b->used >= m->used)) ? (b->used + 1) : (m->used + 1));
    DECL_SP_INT_ARRAY(t, used, 2);

    if ((a == NULL) || (b == NULL) || (m == NULL) || (r == NULL)) {
        err = MP_VAL;
    }

#if 0
    if (err == MP_OKAY) {
        sp_print(a, "a");
        sp_print(b, "b");
        sp_print(m, "m");
    }
#endif

    ALLOC_SP_INT_ARRAY(t, used, 2, err, NULL);
    if (err == MP_OKAY) {
        if (_sp_cmp(a, m) == MP_GT) {
            err = sp_mod(a, m, t[0]);
            a = t[0];
        }
    }
    if (err == MP_OKAY) {
        if (_sp_cmp(b, m) == MP_GT) {
            err = sp_mod(b, m, t[1]);
            b = t[1];
        }
    }
    if (err == MP_OKAY) {
        if (_sp_cmp(a, b) == MP_LT) {
            err = sp_add(a, m, t[0]);
            if (err == MP_OKAY) {
                err = sp_sub(t[0], b, r);
            }
        }
        else {
            err = sp_sub(a, b, r);
        }
    }

#if 0
    if (err == MP_OKAY) {
        sp_print(r, "rms");
    }
#endif

    FREE_SP_INT_ARRAY(t, NULL);
    return err;

#else /* WOLFSSL_SP_INT_NEGATIVE */

    int err = MP_OKAY;
    int used = ((a == NULL) || (b == NULL)) ? 1 :
                   ((a->used >= b->used) ? a->used + 1 : b->used + 1);
    DECL_SP_INT(t, used);

    if ((a == NULL) || (b == NULL) || (m == NULL) || (r == NULL)) {
        err = MP_VAL;
    }

#if 0
    if (err == MP_OKAY) {
        sp_print(a, "a");
        sp_print(b, "b");
        sp_print(m, "m");
    }
#endif

    ALLOC_SP_INT_SIZE(t, used, err, NULL);
    if (err == MP_OKAY) {
        err = sp_sub(a, b, t);
    }
    if (err == MP_OKAY) {
        err = sp_mod(t, m, r);
    }

#if 0
    if (err == MP_OKAY) {
        sp_print(r, "rms");
    }
#endif

    FREE_SP_INT(t, NULL);
    return err;
#endif /* WOLFSSL_SP_INT_NEGATIVE */
}
#endif /* WOLFSSL_SP_MATH_ALL */

#if defined(WOLFSSL_SP_MATH_ALL) && defined(HAVE_ECC)
/* Add two value and reduce: r = (a + b) % m
 *
 * r = a + b (mod m) - constant time (a < m and b < m, a, b and m are positive)
 *
 * Assumes a, b, m and r are not NULL.
 * m and r must not be the same pointer.
 *
 * @param  [in]   a  SP integer to add.
 * @param  [in]   b  SP integer to add with.
 * @param  [in]   m  SP integer that is the modulus.
 * @param  [out]  r  SP integer to hold result.
 *
 * @return  MP_OKAY on success.
 */
int sp_addmod_ct(sp_int* a, sp_int* b, sp_int* m, sp_int* r)
{
    int err = MP_OKAY;
    sp_int_sword w;
    sp_int_sword s;
    sp_int_digit mask;
    int i;

    if (r->size < m->used) {
        err = MP_VAL;
    }
    if ((err == MP_OKAY) && (r == m)) {
        err = MP_VAL;
    }

    if (err == MP_OKAY) {
        if (0) {
            sp_print(a, "a");
            sp_print(b, "b");
            sp_print(m, "m");
        }

        /* Add a to b into r. Do the subtract of modulus but don't store result.
         * When subtract result is negative, the overflow will be negative.
         * Only need to subtract mod when result is positive - overflow is
         * positive.
         */
        w = 0;
        s = 0;
        for (i = 0; i < m->used; i++) {
            /* Values past 'used' are not initialized. */
            sp_int_digit mask_a = (sp_int_digit)0 - (i < a->used);
            sp_int_digit mask_b = (sp_int_digit)0 - (i < b->used);

            w         += a->dp[i] & mask_a;
            w         += b->dp[i] & mask_b;
            r->dp[i]   = (sp_int_digit)w;
            s         += (sp_int_digit)w;
            s         -= m->dp[i];
            s        >>= DIGIT_BIT;
            w        >>= DIGIT_BIT;
        }
        s += (sp_int_digit)w;
        /* s will be positive when subtracting modulus is needed. */
        mask = (sp_int_digit)0 - (s >= 0);

        /* Constant time, conditionally, subtract modulus from sum. */
        w = 0;
        for (i = 0; i < m->used; i++) {
            w         += r->dp[i];
            w         -= m->dp[i] & mask;
            r->dp[i]   = (sp_int_digit)w;
            w        >>= DIGIT_BIT;
        }
        /* Result will always have digits equal to or less than those in
         * modulus. */
        r->used = i;
    #ifdef WOLFSSL_SP_INT_NEGATIVE
        r->sign = MP_ZPOS;
    #endif /* WOLFSSL_SP_INT_NEGATIVE */
        sp_clamp(r);

        if (0) {
            sp_print(r, "rma");
        }
    }

    return err;
}
#endif /* WOLFSSL_SP_MATH_ALL && HAVE_ECC */

#if defined(WOLFSSL_SP_MATH_ALL) && defined(HAVE_ECC)
/* Sub b from a and reduce: r = (a - b) % m
 * Result is always positive.
 *
 * r = a - b (mod m) - constant time (a < m and b < m, a, b and m are positive)
 *
 * Assumes a, b, m and r are not NULL.
 * m and r must not be the same pointer.
 *
 * @param  [in]   a  SP integer to subtract from
 * @param  [in]   b  SP integer to subtract.
 * @param  [in]   m  SP integer that is the modulus.
 * @param  [out]  r  SP integer to hold result.
 *
 * @return  MP_OKAY on success.
 */
int sp_submod_ct(sp_int* a, sp_int* b, sp_int* m, sp_int* r)
{
    int err = MP_OKAY;
    sp_int_sword w;
    sp_int_digit mask;
    int i;

    if (r->size < m->used + 1) {
        err = MP_VAL;
    }
    if ((err == MP_OKAY) && (r == m)) {
        err = MP_VAL;
    }

    if (err == MP_OKAY) {
        if (0) {
            sp_print(a, "a");
            sp_print(b, "b");
            sp_print(m, "m");
        }

        /* In constant time, subtract b from a putting result in r. */
        w = 0;
        for (i = 0; i < m->used; i++) {
            /* Values past 'used' are not initialized. */
            sp_int_digit mask_a = (sp_int_digit)0 - (i < a->used);
            sp_int_digit mask_b = (sp_int_digit)0 - (i < b->used);

            w         += a->dp[i] & mask_a;
            w         -= b->dp[i] & mask_b;
            r->dp[i]   = (sp_int_digit)w;
            w        >>= DIGIT_BIT;
        }
        /* When w is negative then we need to add modulus to make result
         * positive. */
        mask = (sp_int_digit)0 - (w < 0);
        /* Constant time, conditionally, add modulus to difference. */
        w = 0;
        for (i = 0; i < m->used; i++) {
            w         += r->dp[i];
            w         += m->dp[i] & mask;
            r->dp[i]   = (sp_int_digit)w;
            w        >>= DIGIT_BIT;
        }
        r->used = i;
    #ifdef WOLFSSL_SP_INT_NEGATIVE
        r->sign = MP_ZPOS;
    #endif /* WOLFSSL_SP_INT_NEGATIVE */
        sp_clamp(r);

        if (0) {
            sp_print(r, "rms");
        }
    }

    return err;
}
#endif /* WOLFSSL_SP_MATH_ALL && HAVE_ECC */

/********************
 * Shifting functoins
 ********************/

#if !defined(NO_DH) || defined(HAVE_ECC) || (defined(WC_RSA_BLINDING) && \
    !defined(WOLFSSL_RSA_VERIFY_ONLY))
/* Left shift the multi-precision number by a number of digits.
 *
 * @param  [in,out]  a  SP integer to shift.
 * @param  [in]      s  Number of digits to shift.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a is NULL or the result is too big to fit in an SP.
 */
int sp_lshd(sp_int* a, int s)
{
    int err = MP_OKAY;

    if (a == NULL) {
        err = MP_VAL;
    }
    if ((err == MP_OKAY) && (a->used + s > a->size)) {
        err = MP_VAL;
    }
    if (err == MP_OKAY) {
        XMEMMOVE(a->dp + s, a->dp, a->used * sizeof(sp_int_digit));
        a->used += s;
        XMEMSET(a->dp, 0, s * sizeof(sp_int_digit));
        sp_clamp(a);
    }

    return err;
}
#endif

#if defined(WOLFSSL_SP_MATH_ALL) || !defined(NO_DH) || defined(HAVE_ECC) || \
    (!defined(NO_RSA) && !defined(WOLFSSL_RSA_VERIFY_ONLY) && \
     !defined(WOLFSSL_RSA_PUBLIC_ONLY))
/* Left shift the multi-precision number by n bits.
 * Bits may be larger than the word size.
 *
 * @param  [in,out]  a  SP integer to shift.
 * @param  [in]      n  Number of bits to shift left.
 *
 * @return  MP_OKAY on success.
 */
static int sp_lshb(sp_int* a, int n)
{
    int err = MP_OKAY;

    if (a->used != 0) {
        int s = n >> SP_WORD_SHIFT;
        int i;

        if (a->used + s >= a->size) {
            err = MP_VAL;
        }
        if (err == MP_OKAY) {
            n &= SP_WORD_MASK;
            if (n != 0) {
                sp_int_digit v;

                v = a->dp[a->used - 1] >> (SP_WORD_SIZE - n);
                a->dp[a->used - 1 + s] = a->dp[a->used - 1] << n;
                for (i = a->used - 2; i >= 0; i--) {
                    a->dp[i + 1 + s] |= a->dp[i] >> (SP_WORD_SIZE - n);
                    a->dp[i     + s] = a->dp[i] << n;
                }
                if (v != 0) {
                    a->dp[a->used + s] = v;
                    a->used++;
                }
            }
            else if (s > 0) {
                for (i = a->used - 1; i >= 0; i--) {
                    a->dp[i + s] = a->dp[i];
                }
            }
            a->used += s;
            XMEMSET(a->dp, 0, SP_WORD_SIZEOF * s);
        }
    }

    return err;
}
#endif /* WOLFSSL_SP_MATH_ALL || !NO_DH || HAVE_ECC ||
        * (!NO_RSA && !WOLFSSL_RSA_VERIFY_ONLY) */

#if (defined(WOLFSSL_SP_MATH_ALL) && !defined(WOLFSSL_RSA_VERIFY_ONLY)) || \
    !defined(NO_DH) || defined(HAVE_ECC) || \
    (!defined(NO_RSA) && !defined(WOLFSSL_RSA_VERIFY_ONLY))
/* Shift a right by n digits into r: r = a >> (n * SP_WORD_SIZE)
 *
 * @param  [in]   a  SP integer to shift.
 * @param  [in]   n  Number of digits to shift.
 * @param  [out]  r  SP integer to store result in.
 */
void sp_rshd(sp_int* a, int c)
{
    if (a != NULL) {
        int i;
        int j;

        if (c >= a->used) {
            _sp_zero(a);
        }
        else {
            for (i = c, j = 0; i < a->used; i++, j++) {
                a->dp[j] = a->dp[i];
            }
            a->used -= c;
        }
    }
}
#endif /* (WOLFSSL_SP_MATH_ALL && !WOLFSSL_RSA_VERIFY_ONLY) || !NO_DH ||
        * HAVE_ECC || (!NO_RSA && !WOLFSSL_RSA_VERIFY_ONLY) */

#if defined(WOLFSSL_SP_MATH_ALL) || !defined(NO_DH) || defined(HAVE_ECC) || \
    (!defined(NO_RSA) && !defined(WOLFSSL_RSA_VERIFY_ONLY)) || \
    defined(WOLFSSL_HAVE_SP_DH)
/* Shift a right by n bits into r: r = a >> n
 *
 * @param  [in]   a  SP integer to shift.
 * @param  [in]   n  Number of bits to shift.
 * @param  [out]  r  SP integer to store result in.
 */
void sp_rshb(sp_int* a, int n, sp_int* r)
{
    int i = n >> SP_WORD_SHIFT;

    if (i >= a->used) {
        _sp_zero(r);
    }
    else {
        int j;

        n &= SP_WORD_SIZE - 1;
        if (n == 0) {
            for (j = 0; i < a->used; i++, j++)
                r->dp[j] = a->dp[i];
            r->used = j;
        }
        else if (n > 0) {
            for (j = 0; i < a->used-1; i++, j++)
                r->dp[j] = (a->dp[i] >> n) | (a->dp[i+1] << (SP_WORD_SIZE - n));
            r->dp[j] = a->dp[i] >> n;
            r->used = j + 1;
            sp_clamp(r);
        }
#ifdef WOLFSSL_SP_INT_NEGATIVE
        if (sp_iszero(r)) {
            r->sign = MP_ZPOS;
        }
        else {
            r->sign = a->sign;
        }
#endif
    }
}
#endif /* WOLFSSL_SP_MATH_ALL || !NO_DH || HAVE_ECC ||
        * (!NO_RSA && !WOLFSSL_RSA_VERIFY_ONLY) || WOLFSSL_HAVE_SP_DH */

#if defined(WOLFSSL_SP_MATH_ALL) || !defined(NO_DH) || defined(HAVE_ECC) || \
    (!defined(NO_RSA) && !defined(WOLFSSL_RSA_VERIFY_ONLY) && \
     !defined(WOLFSSL_RSA_PUBLIC_ONLY))
/* Divide a by d and return the quotient in r and the remainder in rem.
 *   r = a / d; rem = a % d
 *
 * @param  [in]   a    SP integer to be divided.
 * @param  [in]   d    SP integer to divide by.
 * @param  [out]  r    SP integer that is the quotient.
 * @param  [out]  rem  SP integer that is the remainder.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a or d is NULL, r and rem are NULL, or d is 0.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
#ifndef WOLFSSL_SP_MATH_ALL
static
#endif
int sp_div(sp_int* a, sp_int* d, sp_int* r, sp_int* rem)
{
    int err = MP_OKAY;
    int ret;
    int done = 0;
    int i;
    int s = 0;
    sp_int_digit dt;
    sp_int_digit t;
    sp_int* sa = NULL;
    sp_int* sd = NULL;
    sp_int* tr = NULL;
    sp_int* trial = NULL;
#ifdef WOLFSSL_SP_INT_NEGATIVE
    int aSign = MP_ZPOS;
    int dSign = MP_ZPOS;
#endif /* WOLFSSL_SP_INT_NEGATIVE */
    DECL_SP_INT_ARRAY(td, (a == NULL) ? 1 : a->used + 1, 4);

    if ((a == NULL) || (d == NULL) || ((r == NULL) && (rem == NULL))) {
        err = MP_VAL;
    }
    if ((err == MP_OKAY) && sp_iszero(d)) {
        err = MP_VAL;
    }
    if ((err == MP_OKAY) && (r != NULL) && (r->size < a->used - d->used + 2)) {
        err = MP_VAL;
    }
    if ((err == MP_OKAY) && (rem != NULL) && (rem->size < a->used + 1)) {
        err = MP_VAL;
    }
    /* May need to shift number being divided left into a new word. */
    if ((err == MP_OKAY) && (a->used == SP_INT_DIGITS)) {
        err = MP_VAL;
    }

#if 0
    if (err == MP_OKAY) {
        sp_print(a, "a");
        sp_print(d, "b");
    }
#endif

    if (err == MP_OKAY) {
    #ifdef WOLFSSL_SP_INT_NEGATIVE
        aSign = a->sign;
        dSign = d->sign;
    #endif /* WOLFSSL_SP_INT_NEGATIVE */

        ret = _sp_cmp_abs(a, d);
        if (ret == MP_LT) {
            if (rem != NULL) {
                sp_copy(a, rem);
            }
            if (r != NULL) {
                sp_set(r, 0);
            }
            done = 1;
        }
        else if (ret == MP_EQ) {
            if (rem != NULL) {
                sp_set(rem, 0);
            }
            if (r != NULL) {
                sp_set(r, 1);
            #ifdef WOLFSSL_SP_INT_NEGATIVE
                r->sign = (aSign == dSign) ? MP_ZPOS : MP_NEG;
            #endif /* WOLFSSL_SP_INT_NEGATIVE */
            }
            done = 1;
        }
        else if (sp_count_bits(a) == sp_count_bits(d)) {
            /* a is greater than d but same bit length */
            if (rem != NULL) {
                _sp_sub_off(a, d, rem, 0);
            #ifdef WOLFSSL_SP_INT_NEGATIVE
                rem->sign = aSign;
            #endif
            }
            if (r != NULL) {
                sp_set(r, 1);
            #ifdef WOLFSSL_SP_INT_NEGATIVE
                r->sign = (aSign == dSign) ? MP_ZPOS : MP_NEG;
            #endif /* WOLFSSL_SP_INT_NEGATIVE */
            }
            done = 1;
        }
    }

    if (!done) {
        /* Macro always has code associated with it and checks err first. */
        ALLOC_SP_INT_ARRAY(td, a->used + 1, 4, err, NULL);
    }

    if ((!done) && (err == MP_OKAY)) {
        sa    = td[0];
        sd    = td[1];
        tr    = td[2];
        trial = td[3];

        sp_init_size(sa, a->used + 1);
        sp_init_size(sd, d->used + 1);
        sp_init_size(tr, a->used - d->used + 2);
        sp_init_size(trial, a->used + 1);

        s = sp_count_bits(d);
        s = SP_WORD_SIZE - (s & SP_WORD_MASK);
        sp_copy(a, sa);
        if (s != SP_WORD_SIZE) {
            err = sp_lshb(sa, s);
            if (err == MP_OKAY) {
                sp_copy(d, sd);
                d = sd;
                err = sp_lshb(sd, s);
            }
        }
    }
    if ((!done) && (err == MP_OKAY) && (d->used > 0)) {
#ifdef WOLFSSL_SP_SMALL
        int c;
#else
        int j;
        int o;
        sp_int_sword sw;
#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_INT_NEGATIVE
        sa->sign = MP_ZPOS;
        sd->sign = MP_ZPOS;
#endif /* WOLFSSL_SP_INT_NEGATIVE */

        tr->used = sa->used - d->used + 1;
        sp_clear(tr);
        tr->used = sa->used - d->used + 1;
        dt = d->dp[d->used-1];

        for (i = d->used - 1; i > 0; i--) {
            if (sa->dp[sa->used - d->used + i] != d->dp[i]) {
                break;
            }
        }
        if (sa->dp[sa->used - d->used + i] >= d->dp[i]) {
            i = sa->used;
            _sp_sub_off(sa, d, sa, sa->used - d->used);
            /* Keep the same used so that 0 zeros will be put in. */
            sa->used = i;
            if (r != NULL) {
                tr->dp[sa->used - d->used] = 1;
            }
        }
        for (i = sa->used - 1; i >= d->used; i--) {
            if (sa->dp[i] == dt) {
                t = SP_DIGIT_MAX;
            }
            else {
                t = sp_div_word(sa->dp[i], sa->dp[i-1], dt);
            }

#ifdef WOLFSSL_SP_SMALL
            do {
                err = _sp_mul_d(d, t, trial, i - d->used);
                if (err != MP_OKAY) {
                    break;
                }
                c = _sp_cmp_abs(trial, sa);
                if (c == MP_GT) {
                    t--;
                }
            }
            while (c == MP_GT);

            if (err != MP_OKAY) {
                break;
            }

            _sp_sub_off(sa, trial, sa, 0);
            tr->dp[i - d->used] += t;
            if (tr->dp[i - d->used] < t) {
                tr->dp[i + 1 - d->used]++;
            }
#else
            o = i - d->used;
            do {
                sp_int_word tw = 0;
                for (j = 0; j < d->used; j++) {
                    tw += (sp_int_word)d->dp[j] * t;
                    trial->dp[j] = (sp_int_digit)tw;
                    tw >>= SP_WORD_SIZE;
                }
                trial->dp[j] = (sp_int_digit)tw;

                for (j = d->used; j > 0; j--) {
                    if (trial->dp[j] != sa->dp[j + o]) {
                        break;
                    }
                }
                if (trial->dp[j] > sa->dp[j + o]) {
                    t--;
                }
            }
            while (trial->dp[j] > sa->dp[j + o]);

            sw = 0;
            for (j = 0; j <= d->used; j++) {
                sw += sa->dp[j + o];
                sw -= trial->dp[j];
                sa->dp[j + o] = (sp_int_digit)sw;
                sw >>= SP_WORD_SIZE;
            }

            tr->dp[o] = t;
#endif /* WOLFSSL_SP_SMALL */
        }
        sa->used = i + 1;

        if ((err == MP_OKAY) && (rem != NULL)) {
#ifdef WOLFSSL_SP_INT_NEGATIVE
            sa->sign = (sa->used == 0) ? MP_ZPOS : aSign;
#endif /* WOLFSSL_SP_INT_NEGATIVE */
            if (s != SP_WORD_SIZE) {
                sp_rshb(sa, s, sa);
            }
            sp_copy(sa, rem);
            sp_clamp(rem);
#ifdef WOLFSSL_SP_INT_NEGATIVE
            if (sp_iszero(rem)) {
                rem->sign = MP_ZPOS;
            }
#endif
        }
        if ((err == MP_OKAY) && (r != NULL)) {
            sp_copy(tr, r);
            sp_clamp(r);
#ifdef WOLFSSL_SP_INT_NEGATIVE
            if (sp_iszero(r)) {
                r->sign = MP_ZPOS;
            }
            else {
                r->sign = (aSign == dSign) ? MP_ZPOS : MP_NEG;
            }
#endif /* WOLFSSL_SP_INT_NEGATIVE */
        }
    }

#if 0
    if (err == MP_OKAY) {
        if (rem != NULL) {
            sp_print(rem, "rdr");
        }
        if (r != NULL) {
            sp_print(r, "rdw");
        }
    }
#endif

    FREE_SP_INT_ARRAY(td, NULL);
    return err;
}
#endif /* WOLFSSL_SP_MATH_ALL || !NO_DH || HAVE_ECC || \
        * (!NO_RSA && !WOLFSSL_RSA_VERIFY_ONLY) */

#if defined(WOLFSSL_SP_MATH_ALL) || !defined(NO_DH) || defined(HAVE_ECC) || \
    (!defined(NO_RSA) && !defined(WOLFSSL_RSA_VERIFY_ONLY) && \
     !defined(WOLFSSL_RSA_PUBLIC_ONLY))
#ifndef FREESCALE_LTC_TFM
/* Calculate the remainder of dividing a by m: r = a mod m.
 *
 * @param  [in]   a  SP integer to reduce.
 * @param  [in]   m  SP integer that is the modulus.
 * @param  [out]  r  SP integer to store result in.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a, m or r is NULL or m is 0.
 */
int sp_mod(sp_int* a, sp_int* m, sp_int* r)
{
    int err = MP_OKAY;
#ifdef WOLFSSL_SP_INT_NEGATIVE
    DECL_SP_INT(t, (a == NULL) ? 1 : a->used + 1);
#endif /* WOLFSSL_SP_INT_NEGATIVE */

    if ((a == NULL) || (m == NULL) || (r == NULL)) {
        err = MP_VAL;
    }
#ifdef WOLFSSL_SP_INT_NEGATIVE
    if ((err == MP_OKAY) && (a->used >= SP_INT_DIGITS)) {
        err = MP_VAL;
    }
#endif

#ifndef WOLFSSL_SP_INT_NEGATIVE
    if (err == MP_OKAY) {
        err = sp_div(a, m, NULL, r);
    }
#else
    ALLOC_SP_INT(t, a->used + 1, err, NULL);
    if (err == MP_OKAY) {
        sp_init_size(t, a->used + 1);
        err = sp_div(a, m, NULL, t);
    }
    if (err == MP_OKAY) {
        if ((!sp_iszero(t)) && (t->sign != m->sign)) {
            err = sp_add(t, m, r);
        }
        else {
            err = sp_copy(t, r);
        }
    }

    FREE_SP_INT(t, NULL);
#endif /* WOLFSSL_SP_INT_NEGATIVE */

    return err;
}
#endif /* !FREESCALE_LTC_TFM */
#endif /* WOLFSSL_SP_MATH_ALL || !NO_DH || HAVE_ECC || \
        * (!NO_RSA && !WOLFSSL_RSA_VERIFY_ONLY) */

/* START SP_MUL implementations. */
/* This code is generated.
 * To generate:
 *   cd scripts/sp/sp_int
 *   ./gen.sh
 * File sp_mul.c contains code.
 */

#ifdef SQR_MUL_ASM
/* Multiply a by b into r where a and b have same no. digits. r = a * b
 *
 * Optimised code for when number of digits in a and b are the same.
 *
 * @param  [in]   a    SP integer to mulitply.
 * @param  [in]   b    SP integer to mulitply by.
 * @param  [out]  r    SP integer to hod reult.
 *
 * @return  MP_OKAY otherwise.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
static int _sp_mul_nxn(sp_int* a, sp_int* b, sp_int* r)
{
    int err = MP_OKAY;
    int i;
    int j;
    int k;
#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_SP_NO_MALLOC)
    sp_int_digit* t = NULL;
#elif defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L) && \
    defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SP_NO_DYN_STACK)
    sp_int_digit t[a->used * 2];
#else
    sp_int_digit t[SP_INT_DIGITS];
#endif

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_SP_NO_MALLOC)
    t = (sp_int_digit*)XMALLOC(sizeof(sp_int_digit) * (a->used * 2), NULL,
        DYNAMIC_TYPE_BIGINT);
    if (t == NULL) {
        err = MP_MEM;
    }
#endif
    if (err == MP_OKAY) {
        sp_int_digit l, h, o;
        sp_int_digit* dp;

        h = 0;
        l = 0;
        SP_ASM_MUL(h, l, a->dp[0], b->dp[0]);
        t[0] = h;
        h = 0;
        o = 0;
        for (k = 1; k <= a->used - 1; k++) {
            j = k;
            dp = a->dp;
            for (; j >= 0; dp++, j--) {
                SP_ASM_MUL_ADD(l, h, o, dp[0], b->dp[j]);
            }
            t[k] = l;
            l = h;
            h = o;
            o = 0;
        }
        for (; k <= (a->used - 1) * 2; k++) {
            i = k - (b->used - 1);
            dp = &b->dp[b->used - 1];
            for (; i < a->used; i++, dp--) {
                SP_ASM_MUL_ADD(l, h, o, a->dp[i], dp[0]);
            }
            t[k] = l;
            l = h;
            h = o;
            o = 0;
        }
        t[k] = l;
        r->used = k + 1;
        XMEMCPY(r->dp, t, r->used * sizeof(sp_int_digit));
        sp_clamp(r);
    }

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (t != NULL) {
        XFREE(t, NULL, DYNAMIC_TYPE_BIGINT);
    }
#endif
    return err;
}

/* Multiply a by b into r. r = a * b
 *
 * @param  [in]   a    SP integer to mulitply.
 * @param  [in]   b    SP integer to mulitply by.
 * @param  [out]  r    SP integer to hod reult.
 *
 * @return  MP_OKAY otherwise.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
static int _sp_mul(sp_int* a, sp_int* b, sp_int* r)
{
    int err = MP_OKAY;
    int i;
    int j;
    int k;
#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_SP_NO_MALLOC)
    sp_int_digit* t = NULL;
#elif defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L) && \
    defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SP_NO_DYN_STACK)
    sp_int_digit t[a->used + b->used];
#else
    sp_int_digit t[SP_INT_DIGITS];
#endif

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_SP_NO_MALLOC)
    t = (sp_int_digit*)XMALLOC(sizeof(sp_int_digit) * (a->used + b->used), NULL,
        DYNAMIC_TYPE_BIGINT);
    if (t == NULL) {
        err = MP_MEM;
    }
#endif
    if (err == MP_OKAY) {
        sp_int_digit l;
        sp_int_digit h;
        sp_int_digit o;

        h = 0;
        l = 0;
        SP_ASM_MUL(h, l, a->dp[0], b->dp[0]);
        t[0] = h;
        h = 0;
        o = 0;
        for (k = 1; k <= b->used - 1; k++) {
            i = 0;
            j = k;
            for (; (i < a->used) && (j >= 0); i++, j--) {
                SP_ASM_MUL_ADD(l, h, o, a->dp[i], b->dp[j]);
            }
            t[k] = l;
            l = h;
            h = o;
            o = 0;
        }
        for (; k <= (a->used - 1) + (b->used - 1); k++) {
            j = b->used - 1;
            i = k - j;
            for (; (i < a->used) && (j >= 0); i++, j--) {
                SP_ASM_MUL_ADD(l, h, o, a->dp[i], b->dp[j]);
            }
            t[k] = l;
            l = h;
            h = o;
            o = 0;
        }
        t[k] = l;
        r->used = k + 1;
        XMEMCPY(r->dp, t, r->used * sizeof(sp_int_digit));
        sp_clamp(r);
    }

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (t != NULL) {
        XFREE(t, NULL, DYNAMIC_TYPE_BIGINT);
    }
#endif
    return err;
}
#else
/* Multiply a by b into r. r = a * b
 *
 * @param  [in]   a    SP integer to mulitply.
 * @param  [in]   b    SP integer to mulitply by.
 * @param  [out]  r    SP integer to hod reult.
 *
 * @return  MP_OKAY otherwise.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
static int _sp_mul(sp_int* a, sp_int* b, sp_int* r)
{
    int err = MP_OKAY;
    int i;
    int j;
    int k;
#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_SP_NO_MALLOC)
    sp_int_digit* t = NULL;
#elif defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L) && \
    defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SP_NO_DYN_STACK)
    sp_int_digit t[a->used + b->used];
#else
    sp_int_digit t[SP_INT_DIGITS];
#endif

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_SP_NO_MALLOC)
    t = (sp_int_digit*)XMALLOC(sizeof(sp_int_digit) * (a->used + b->used), NULL,
        DYNAMIC_TYPE_BIGINT);
    if (t == NULL) {
        err = MP_MEM;
    }
#endif
    if (err == MP_OKAY) {
        sp_int_word w;
        sp_int_word l;
        sp_int_word h;
    #ifdef SP_WORD_OVERFLOW
        sp_int_word o;
    #endif

        w = (sp_int_word)a->dp[0] * b->dp[0];
        t[0] = (sp_int_digit)w;
        l = (sp_int_digit)(w >> SP_WORD_SIZE);
        h = 0;
    #ifdef SP_WORD_OVERFLOW
        o = 0;
    #endif
        for (k = 1; k <= (a->used - 1) + (b->used - 1); k++) {
            i = k - (b->used - 1);
            i &= ~(i >> (sizeof(i) * 8 - 1));
            j = k - i;
            for (; (i < a->used) && (j >= 0); i++, j--) {
                w = (sp_int_word)a->dp[i] * b->dp[j];
                l += (sp_int_digit)w;
                h += (sp_int_digit)(w >> SP_WORD_SIZE);
            #ifdef SP_WORD_OVERFLOW
                h += (sp_int_digit)(l >> SP_WORD_SIZE);
                l &= SP_MASK;
                o += (sp_int_digit)(h >> SP_WORD_SIZE);
                h &= SP_MASK;
            #endif
            }
            t[k] = (sp_int_digit)l;
            l >>= SP_WORD_SIZE;
            l += (sp_int_digit)h;
            h >>= SP_WORD_SIZE;
        #ifdef SP_WORD_OVERFLOW
            h += o & SP_MASK;
            o >>= SP_WORD_SIZE;
        #endif
        }
        t[k] = (sp_int_digit)l;
        r->used = k + 1;
        XMEMCPY(r->dp, t, r->used * sizeof(sp_int_digit));
        sp_clamp(r);
    }

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (t != NULL) {
        XFREE(t, NULL, DYNAMIC_TYPE_BIGINT);
    }
#endif
    return err;
}
#endif

#ifndef WOLFSSL_SP_SMALL
#if !defined(WOLFSSL_HAVE_SP_ECC) && defined(HAVE_ECC)
#if SP_WORD_SIZE == 64
#ifndef SQR_MUL_ASM
/* Multiply a by b and store in r: r = a * b
 *
 * Long-hand implementation.
 *
 * @param  [in]   a  SP integer to multiply.
 * @param  [in]   b  SP integer to multiply.
 * @param  [out]  r  SP integer result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
static int _sp_mul_4(sp_int* a, sp_int* b, sp_int* r)
{
    int err = MP_OKAY;
#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_SP_NO_MALLOC)
    sp_int_word* w = NULL;
#else
    sp_int_word w[16];
#endif
    sp_int_digit* da = a->dp;
    sp_int_digit* db = b->dp;

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_SP_NO_MALLOC)
    w = (sp_int_word*)XMALLOC(sizeof(sp_int_word) * 16, NULL,
        DYNAMIC_TYPE_BIGINT);
    if (w == NULL) {
        err = MP_MEM;
    }
#endif

    if (err == MP_OKAY) {
        w[0] = (sp_int_word)da[0] * db[0];
        w[1] = (sp_int_word)da[0] * db[1];
        w[2] = (sp_int_word)da[1] * db[0];
        w[3] = (sp_int_word)da[0] * db[2];
        w[4] = (sp_int_word)da[1] * db[1];
        w[5] = (sp_int_word)da[2] * db[0];
        w[6] = (sp_int_word)da[0] * db[3];
        w[7] = (sp_int_word)da[1] * db[2];
        w[8] = (sp_int_word)da[2] * db[1];
        w[9] = (sp_int_word)da[3] * db[0];
        w[10] = (sp_int_word)da[1] * db[3];
        w[11] = (sp_int_word)da[2] * db[2];
        w[12] = (sp_int_word)da[3] * db[1];
        w[13] = (sp_int_word)da[2] * db[3];
        w[14] = (sp_int_word)da[3] * db[2];
        w[15] = (sp_int_word)da[3] * db[3];

        r->dp[0] = w[0];
        w[0] >>= SP_WORD_SIZE;
        w[0] += (sp_int_digit)w[1];
        w[0] += (sp_int_digit)w[2];
        r->dp[1] = w[0];
        w[0] >>= SP_WORD_SIZE;
        w[1] >>= SP_WORD_SIZE;
        w[0] += (sp_int_digit)w[1];
        w[2] >>= SP_WORD_SIZE;
        w[0] += (sp_int_digit)w[2];
        w[0] += (sp_int_digit)w[3];
        w[0] += (sp_int_digit)w[4];
        w[0] += (sp_int_digit)w[5];
        r->dp[2] = w[0];
        w[0] >>= SP_WORD_SIZE;
        w[3] >>= SP_WORD_SIZE;
        w[0] += (sp_int_digit)w[3];
        w[4] >>= SP_WORD_SIZE;
        w[0] += (sp_int_digit)w[4];
        w[5] >>= SP_WORD_SIZE;
        w[0] += (sp_int_digit)w[5];
        w[0] += (sp_int_digit)w[6];
        w[0] += (sp_int_digit)w[7];
        w[0] += (sp_int_digit)w[8];
        w[0] += (sp_int_digit)w[9];
        r->dp[3] = w[0];
        w[0] >>= SP_WORD_SIZE;
        w[6] >>= SP_WORD_SIZE;
        w[0] += (sp_int_digit)w[6];
        w[7] >>= SP_WORD_SIZE;
        w[0] += (sp_int_digit)w[7];
        w[8] >>= SP_WORD_SIZE;
        w[0] += (sp_int_digit)w[8];
        w[9] >>= SP_WORD_SIZE;
        w[0] += (sp_int_digit)w[9];
        w[0] += (sp_int_digit)w[10];
        w[0] += (sp_int_digit)w[11];
        w[0] += (sp_int_digit)w[12];
        r->dp[4] = w[0];
        w[0] >>= SP_WORD_SIZE;
        w[10] >>= SP_WORD_SIZE;
        w[0] += (sp_int_digit)w[10];
        w[11] >>= SP_WORD_SIZE;
        w[0] += (sp_int_digit)w[11];
        w[12] >>= SP_WORD_SIZE;
        w[0] += (sp_int_digit)w[12];
        w[0] += (sp_int_digit)w[13];
        w[0] += (sp_int_digit)w[14];
        r->dp[5] = w[0];
        w[0] >>= SP_WORD_SIZE;
        w[13] >>= SP_WORD_SIZE;
        w[0] += (sp_int_digit)w[13];
        w[14] >>= SP_WORD_SIZE;
        w[0] += (sp_int_digit)w[14];
        w[0] += (sp_int_digit)w[15];
        r->dp[6] = w[0];
        w[0] >>= SP_WORD_SIZE;
        w[15] >>= SP_WORD_SIZE;
        w[0] += (sp_int_digit)w[15];
        r->dp[7] = w[0];

        r->used = 8;
        sp_clamp(r);
    }

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (w != NULL) {
        XFREE(w, NULL, DYNAMIC_TYPE_BIGINT);
    }
#endif
    return err;
}
#else /* SQR_MUL_ASM */
/* Multiply a by b and store in r: r = a * b
 *
 * Comba implementation.
 *
 * @param  [in]   a  SP integer to multiply.
 * @param  [in]   b  SP integer to multiply.
 * @param  [out]  r  SP integer result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
static int _sp_mul_4(sp_int* a, sp_int* b, sp_int* r)
{
    sp_int_digit l = 0;
    sp_int_digit h = 0;
    sp_int_digit o = 0;
    sp_int_digit t[4];

    SP_ASM_MUL(h, l, a->dp[0], b->dp[0]);
    t[0] = h;
    h = 0;
    SP_ASM_MUL_ADD_NO(l, h, a->dp[0], b->dp[1]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[0]);
    t[1] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD_NO(l, h, a->dp[0], b->dp[2]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[1]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[0]);
    t[2] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[3]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[2]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[1]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[0]);
    t[3] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[3]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[2]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[1]);
    r->dp[4] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[3]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[2]);
    r->dp[5] = l;
    l = h;
    h = o;
    SP_ASM_MUL_ADD_NO(l, h, a->dp[3], b->dp[3]);
    r->dp[6] = l;
    r->dp[7] = h;
    XMEMCPY(r->dp, t, 4 * sizeof(sp_int_digit));
    r->used = 8;
    sp_clamp(r);

    return MP_OKAY;
}
#endif /* SQR_MUL_ASM */
#endif /* SP_WORD_SIZE == 64 */
#if SP_WORD_SIZE == 64
#ifdef SQR_MUL_ASM
/* Multiply a by b and store in r: r = a * b
 *
 * Comba implementation.
 *
 * @param  [in]   a  SP integer to multiply.
 * @param  [in]   b  SP integer to multiply.
 * @param  [out]  r  SP integer result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
static int _sp_mul_6(sp_int* a, sp_int* b, sp_int* r)
{
    sp_int_digit l = 0;
    sp_int_digit h = 0;
    sp_int_digit o = 0;
    sp_int_digit t[6];

    SP_ASM_MUL(h, l, a->dp[0], b->dp[0]);
    t[0] = h;
    h = 0;
    SP_ASM_MUL_ADD_NO(l, h, a->dp[0], b->dp[1]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[0]);
    t[1] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD_NO(l, h, a->dp[0], b->dp[2]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[1]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[0]);
    t[2] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[3]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[2]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[1]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[0]);
    t[3] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[4]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[3]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[2]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[1]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[0]);
    t[4] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[5]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[4]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[3]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[2]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[1]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[0]);
    t[5] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[5]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[4]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[3]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[2]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[1]);
    r->dp[6] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[5]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[4]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[3]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[2]);
    r->dp[7] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[5]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[4]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[3]);
    r->dp[8] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[5]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[4]);
    r->dp[9] = l;
    l = h;
    h = o;
    SP_ASM_MUL_ADD_NO(l, h, a->dp[5], b->dp[5]);
    r->dp[10] = l;
    r->dp[11] = h;
    XMEMCPY(r->dp, t, 6 * sizeof(sp_int_digit));
    r->used = 12;
    sp_clamp(r);

    return MP_OKAY;
}
#endif /* SQR_MUL_ASM */
#endif /* SP_WORD_SIZE == 64 */
#if SP_WORD_SIZE == 32
#ifdef SQR_MUL_ASM
/* Multiply a by b and store in r: r = a * b
 *
 * Comba implementation.
 *
 * @param  [in]   a  SP integer to multiply.
 * @param  [in]   b  SP integer to multiply.
 * @param  [out]  r  SP integer result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
static int _sp_mul_8(sp_int* a, sp_int* b, sp_int* r)
{
    sp_int_digit l = 0;
    sp_int_digit h = 0;
    sp_int_digit o = 0;
    sp_int_digit t[8];

    SP_ASM_MUL(h, l, a->dp[0], b->dp[0]);
    t[0] = h;
    h = 0;
    SP_ASM_MUL_ADD_NO(l, h, a->dp[0], b->dp[1]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[0]);
    t[1] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD_NO(l, h, a->dp[0], b->dp[2]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[1]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[0]);
    t[2] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[3]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[2]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[1]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[0]);
    t[3] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[4]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[3]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[2]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[1]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[0]);
    t[4] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[5]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[4]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[3]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[2]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[1]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[0]);
    t[5] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[6]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[5]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[4]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[3]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[2]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[1]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[0]);
    t[6] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[7]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[6]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[5]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[4]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[3]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[2]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[1]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[0]);
    t[7] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[7]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[6]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[5]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[4]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[3]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[2]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[1]);
    r->dp[8] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[7]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[6]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[5]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[4]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[3]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[2]);
    r->dp[9] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[7]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[6]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[5]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[4]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[3]);
    r->dp[10] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[7]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[6]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[5]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[4]);
    r->dp[11] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[7]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[6]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[5]);
    r->dp[12] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[7]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[6]);
    r->dp[13] = l;
    l = h;
    h = o;
    SP_ASM_MUL_ADD_NO(l, h, a->dp[7], b->dp[7]);
    r->dp[14] = l;
    r->dp[15] = h;
    XMEMCPY(r->dp, t, 8 * sizeof(sp_int_digit));
    r->used = 16;
    sp_clamp(r);

    return MP_OKAY;
}
#endif /* SQR_MUL_ASM */
#endif /* SP_WORD_SIZE == 32 */
#if SP_WORD_SIZE == 32
#ifdef SQR_MUL_ASM
/* Multiply a by b and store in r: r = a * b
 *
 * Comba implementation.
 *
 * @param  [in]   a  SP integer to multiply.
 * @param  [in]   b  SP integer to multiply.
 * @param  [out]  r  SP integer result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
static int _sp_mul_12(sp_int* a, sp_int* b, sp_int* r)
{
    sp_int_digit l = 0;
    sp_int_digit h = 0;
    sp_int_digit o = 0;
    sp_int_digit t[12];

    SP_ASM_MUL(h, l, a->dp[0], b->dp[0]);
    t[0] = h;
    h = 0;
    SP_ASM_MUL_ADD_NO(l, h, a->dp[0], b->dp[1]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[0]);
    t[1] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD_NO(l, h, a->dp[0], b->dp[2]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[1]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[0]);
    t[2] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[3]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[2]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[1]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[0]);
    t[3] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[4]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[3]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[2]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[1]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[0]);
    t[4] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[5]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[4]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[3]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[2]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[1]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[0]);
    t[5] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[6]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[5]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[4]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[3]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[2]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[1]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[0]);
    t[6] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[7]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[6]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[5]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[4]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[3]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[2]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[1]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[0]);
    t[7] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[8]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[7]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[6]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[5]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[4]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[3]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[2]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[1]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[0]);
    t[8] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[9]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[8]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[7]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[6]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[5]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[4]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[3]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[2]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[1]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[0]);
    t[9] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[10]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[9]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[8]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[7]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[6]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[5]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[4]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[3]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[2]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[1]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[0]);
    t[10] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[11]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[10]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[9]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[8]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[7]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[6]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[5]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[4]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[3]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[2]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[1]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[0]);
    t[11] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[11]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[10]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[9]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[8]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[7]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[6]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[5]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[4]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[3]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[2]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[1]);
    r->dp[12] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[11]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[10]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[9]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[8]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[7]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[6]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[5]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[4]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[3]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[2]);
    r->dp[13] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[11]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[10]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[9]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[8]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[7]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[6]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[5]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[4]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[3]);
    r->dp[14] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[11]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[10]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[9]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[8]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[7]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[6]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[5]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[4]);
    r->dp[15] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[11]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[10]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[9]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[8]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[7]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[6]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[5]);
    r->dp[16] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[11]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[10]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[9]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[8]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[7]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[6]);
    r->dp[17] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[11]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[10]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[9]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[8]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[7]);
    r->dp[18] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[11]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[10]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[9]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[8]);
    r->dp[19] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[11]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[10]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[9]);
    r->dp[20] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[11]);
    SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[10]);
    r->dp[21] = l;
    l = h;
    h = o;
    SP_ASM_MUL_ADD_NO(l, h, a->dp[11], b->dp[11]);
    r->dp[22] = l;
    r->dp[23] = h;
    XMEMCPY(r->dp, t, 12 * sizeof(sp_int_digit));
    r->used = 24;
    sp_clamp(r);

    return MP_OKAY;
}
#endif /* SQR_MUL_ASM */
#endif /* SP_WORD_SIZE == 32 */
#endif /* !WOLFSSL_HAVE_SP_ECC && HAVE_ECC */

#if defined(SQR_MUL_ASM) && defined(WOLFSSL_SP_INT_LARGE_COMBA)
    #if SP_INT_DIGITS >= 32
/* Multiply a by b and store in r: r = a * b
 *
 * Comba implementation.
 *
 * @param  [in]   a  SP integer to multiply.
 * @param  [in]   b  SP integer to multiply.
 * @param  [out]  r  SP integer result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
static int _sp_mul_16(sp_int* a, sp_int* b, sp_int* r)
{
    int err = MP_OKAY;
    sp_int_digit l = 0;
    sp_int_digit h = 0;
    sp_int_digit o = 0;
#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_SP_NO_MALLOC)
    sp_int_digit* t = NULL;
#else
    sp_int_digit t[16];
#endif

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_SP_NO_MALLOC)
     t = (sp_int_digit*)XMALLOC(sizeof(sp_int_digit) * 16, NULL,
         DYNAMIC_TYPE_BIGINT);
     if (t == NULL) {
         err = MP_MEM;
     }
#endif
    if (err == MP_OKAY) {
        SP_ASM_MUL(h, l, a->dp[0], b->dp[0]);
        t[0] = h;
        h = 0;
        SP_ASM_MUL_ADD_NO(l, h, a->dp[0], b->dp[1]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[0]);
        t[1] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD_NO(l, h, a->dp[0], b->dp[2]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[1]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[0]);
        t[2] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[3]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[2]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[1]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[0]);
        t[3] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[4]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[3]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[2]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[1]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[0]);
        t[4] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[5]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[4]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[3]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[2]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[1]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[0]);
        t[5] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[6]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[5]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[4]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[3]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[2]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[1]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[0]);
        t[6] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[7]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[6]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[5]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[4]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[3]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[2]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[1]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[0]);
        t[7] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[8]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[7]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[6]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[5]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[4]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[3]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[2]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[1]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[0]);
        t[8] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[9]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[8]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[7]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[6]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[5]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[4]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[3]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[2]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[1]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[0]);
        t[9] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[10]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[9]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[8]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[7]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[6]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[5]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[4]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[3]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[2]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[1]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[0]);
        t[10] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[11]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[10]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[9]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[8]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[7]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[6]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[5]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[4]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[3]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[2]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[1]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[0]);
        t[11] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[12]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[11]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[10]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[9]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[8]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[7]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[6]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[5]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[4]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[3]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[2]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[1]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[12], b->dp[0]);
        t[12] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[13]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[12]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[11]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[10]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[9]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[8]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[7]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[6]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[5]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[4]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[3]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[2]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[12], b->dp[1]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[13], b->dp[0]);
        t[13] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[14]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[13]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[12]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[11]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[10]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[9]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[8]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[7]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[6]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[5]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[4]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[3]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[12], b->dp[2]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[13], b->dp[1]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[14], b->dp[0]);
        t[14] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[15]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[14]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[13]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[12]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[11]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[10]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[9]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[8]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[7]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[6]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[5]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[4]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[12], b->dp[3]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[13], b->dp[2]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[14], b->dp[1]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[15], b->dp[0]);
        t[15] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[15]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[14]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[13]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[12]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[11]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[10]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[9]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[8]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[7]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[6]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[5]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[12], b->dp[4]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[13], b->dp[3]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[14], b->dp[2]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[15], b->dp[1]);
        r->dp[16] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[15]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[14]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[13]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[12]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[11]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[10]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[9]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[8]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[7]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[6]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[12], b->dp[5]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[13], b->dp[4]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[14], b->dp[3]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[15], b->dp[2]);
        r->dp[17] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[15]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[14]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[13]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[12]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[11]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[10]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[9]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[8]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[7]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[12], b->dp[6]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[13], b->dp[5]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[14], b->dp[4]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[15], b->dp[3]);
        r->dp[18] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[15]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[14]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[13]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[12]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[11]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[10]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[9]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[8]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[12], b->dp[7]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[13], b->dp[6]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[14], b->dp[5]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[15], b->dp[4]);
        r->dp[19] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[15]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[14]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[13]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[12]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[11]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[10]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[9]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[12], b->dp[8]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[13], b->dp[7]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[14], b->dp[6]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[15], b->dp[5]);
        r->dp[20] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[15]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[14]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[13]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[12]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[11]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[10]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[12], b->dp[9]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[13], b->dp[8]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[14], b->dp[7]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[15], b->dp[6]);
        r->dp[21] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[15]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[14]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[13]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[12]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[11]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[12], b->dp[10]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[13], b->dp[9]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[14], b->dp[8]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[15], b->dp[7]);
        r->dp[22] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[15]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[14]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[13]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[12]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[12], b->dp[11]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[13], b->dp[10]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[14], b->dp[9]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[15], b->dp[8]);
        r->dp[23] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[15]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[14]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[13]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[12], b->dp[12]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[13], b->dp[11]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[14], b->dp[10]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[15], b->dp[9]);
        r->dp[24] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[15]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[14]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[12], b->dp[13]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[13], b->dp[12]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[14], b->dp[11]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[15], b->dp[10]);
        r->dp[25] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[15]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[12], b->dp[14]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[13], b->dp[13]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[14], b->dp[12]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[15], b->dp[11]);
        r->dp[26] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[12], b->dp[15]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[13], b->dp[14]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[14], b->dp[13]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[15], b->dp[12]);
        r->dp[27] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[13], b->dp[15]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[14], b->dp[14]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[15], b->dp[13]);
        r->dp[28] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[14], b->dp[15]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[15], b->dp[14]);
        r->dp[29] = l;
        l = h;
        h = o;
        SP_ASM_MUL_ADD_NO(l, h, a->dp[15], b->dp[15]);
        r->dp[30] = l;
        r->dp[31] = h;
        XMEMCPY(r->dp, t, 16 * sizeof(sp_int_digit));
        r->used = 32;
        sp_clamp(r);
    }

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (t != NULL) {
        XFREE(t, NULL, DYNAMIC_TYPE_BIGINT);
    }
#endif
    return err;
}
    #endif /* SP_INT_DIGITS >= 32 */

    #if SP_INT_DIGITS >= 48
/* Multiply a by b and store in r: r = a * b
 *
 * Comba implementation.
 *
 * @param  [in]   a  SP integer to multiply.
 * @param  [in]   b  SP integer to multiply.
 * @param  [out]  r  SP integer result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
static int _sp_mul_24(sp_int* a, sp_int* b, sp_int* r)
{
    int err = MP_OKAY;
    sp_int_digit l = 0;
    sp_int_digit h = 0;
    sp_int_digit o = 0;
#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_SP_NO_MALLOC)
    sp_int_digit* t = NULL;
#else
    sp_int_digit t[24];
#endif

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_SP_NO_MALLOC)
     t = (sp_int_digit*)XMALLOC(sizeof(sp_int_digit) * 24, NULL,
         DYNAMIC_TYPE_BIGINT);
     if (t == NULL) {
         err = MP_MEM;
     }
#endif
    if (err == MP_OKAY) {
        SP_ASM_MUL(h, l, a->dp[0], b->dp[0]);
        t[0] = h;
        h = 0;
        SP_ASM_MUL_ADD_NO(l, h, a->dp[0], b->dp[1]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[0]);
        t[1] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD_NO(l, h, a->dp[0], b->dp[2]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[1]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[0]);
        t[2] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[3]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[2]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[1]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[0]);
        t[3] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[4]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[3]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[2]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[1]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[0]);
        t[4] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[5]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[4]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[3]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[2]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[1]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[0]);
        t[5] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[6]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[5]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[4]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[3]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[2]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[1]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[0]);
        t[6] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[7]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[6]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[5]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[4]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[3]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[2]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[1]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[0]);
        t[7] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[8]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[7]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[6]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[5]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[4]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[3]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[2]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[1]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[0]);
        t[8] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[9]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[8]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[7]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[6]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[5]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[4]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[3]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[2]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[1]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[0]);
        t[9] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[10]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[9]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[8]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[7]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[6]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[5]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[4]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[3]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[2]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[1]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[0]);
        t[10] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[11]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[10]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[9]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[8]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[7]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[6]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[5]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[4]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[3]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[2]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[1]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[0]);
        t[11] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[12]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[11]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[10]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[9]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[8]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[7]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[6]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[5]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[4]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[3]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[2]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[1]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[12], b->dp[0]);
        t[12] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[13]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[12]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[11]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[10]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[9]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[8]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[7]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[6]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[5]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[4]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[3]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[2]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[12], b->dp[1]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[13], b->dp[0]);
        t[13] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[14]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[13]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[12]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[11]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[10]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[9]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[8]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[7]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[6]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[5]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[4]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[3]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[12], b->dp[2]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[13], b->dp[1]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[14], b->dp[0]);
        t[14] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[15]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[14]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[13]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[12]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[11]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[10]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[9]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[8]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[7]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[6]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[5]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[4]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[12], b->dp[3]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[13], b->dp[2]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[14], b->dp[1]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[15], b->dp[0]);
        t[15] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[16]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[15]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[14]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[13]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[12]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[11]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[10]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[9]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[8]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[7]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[6]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[5]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[12], b->dp[4]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[13], b->dp[3]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[14], b->dp[2]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[15], b->dp[1]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[16], b->dp[0]);
        t[16] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[17]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[16]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[15]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[14]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[13]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[12]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[11]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[10]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[9]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[8]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[7]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[6]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[12], b->dp[5]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[13], b->dp[4]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[14], b->dp[3]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[15], b->dp[2]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[16], b->dp[1]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[17], b->dp[0]);
        t[17] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[18]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[17]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[16]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[15]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[14]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[13]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[12]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[11]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[10]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[9]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[8]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[7]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[12], b->dp[6]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[13], b->dp[5]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[14], b->dp[4]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[15], b->dp[3]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[16], b->dp[2]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[17], b->dp[1]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[18], b->dp[0]);
        t[18] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[19]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[18]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[17]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[16]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[15]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[14]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[13]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[12]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[11]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[10]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[9]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[8]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[12], b->dp[7]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[13], b->dp[6]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[14], b->dp[5]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[15], b->dp[4]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[16], b->dp[3]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[17], b->dp[2]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[18], b->dp[1]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[19], b->dp[0]);
        t[19] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[20]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[19]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[18]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[17]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[16]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[15]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[14]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[13]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[12]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[11]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[10]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[9]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[12], b->dp[8]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[13], b->dp[7]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[14], b->dp[6]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[15], b->dp[5]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[16], b->dp[4]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[17], b->dp[3]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[18], b->dp[2]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[19], b->dp[1]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[20], b->dp[0]);
        t[20] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[21]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[20]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[19]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[18]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[17]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[16]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[15]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[14]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[13]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[12]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[11]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[10]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[12], b->dp[9]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[13], b->dp[8]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[14], b->dp[7]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[15], b->dp[6]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[16], b->dp[5]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[17], b->dp[4]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[18], b->dp[3]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[19], b->dp[2]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[20], b->dp[1]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[21], b->dp[0]);
        t[21] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[22]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[21]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[20]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[19]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[18]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[17]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[16]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[15]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[14]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[13]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[12]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[11]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[12], b->dp[10]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[13], b->dp[9]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[14], b->dp[8]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[15], b->dp[7]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[16], b->dp[6]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[17], b->dp[5]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[18], b->dp[4]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[19], b->dp[3]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[20], b->dp[2]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[21], b->dp[1]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[22], b->dp[0]);
        t[22] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[0], b->dp[23]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[22]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[21]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[20]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[19]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[18]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[17]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[16]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[15]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[14]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[13]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[12]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[12], b->dp[11]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[13], b->dp[10]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[14], b->dp[9]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[15], b->dp[8]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[16], b->dp[7]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[17], b->dp[6]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[18], b->dp[5]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[19], b->dp[4]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[20], b->dp[3]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[21], b->dp[2]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[22], b->dp[1]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[23], b->dp[0]);
        t[23] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[1], b->dp[23]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[22]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[21]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[20]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[19]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[18]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[17]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[16]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[15]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[14]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[13]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[12], b->dp[12]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[13], b->dp[11]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[14], b->dp[10]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[15], b->dp[9]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[16], b->dp[8]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[17], b->dp[7]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[18], b->dp[6]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[19], b->dp[5]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[20], b->dp[4]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[21], b->dp[3]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[22], b->dp[2]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[23], b->dp[1]);
        r->dp[24] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[2], b->dp[23]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[22]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[21]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[20]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[19]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[18]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[17]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[16]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[15]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[14]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[12], b->dp[13]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[13], b->dp[12]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[14], b->dp[11]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[15], b->dp[10]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[16], b->dp[9]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[17], b->dp[8]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[18], b->dp[7]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[19], b->dp[6]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[20], b->dp[5]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[21], b->dp[4]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[22], b->dp[3]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[23], b->dp[2]);
        r->dp[25] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[3], b->dp[23]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[22]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[21]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[20]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[19]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[18]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[17]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[16]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[15]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[12], b->dp[14]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[13], b->dp[13]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[14], b->dp[12]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[15], b->dp[11]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[16], b->dp[10]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[17], b->dp[9]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[18], b->dp[8]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[19], b->dp[7]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[20], b->dp[6]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[21], b->dp[5]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[22], b->dp[4]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[23], b->dp[3]);
        r->dp[26] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[4], b->dp[23]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[22]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[21]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[20]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[19]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[18]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[17]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[16]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[12], b->dp[15]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[13], b->dp[14]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[14], b->dp[13]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[15], b->dp[12]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[16], b->dp[11]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[17], b->dp[10]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[18], b->dp[9]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[19], b->dp[8]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[20], b->dp[7]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[21], b->dp[6]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[22], b->dp[5]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[23], b->dp[4]);
        r->dp[27] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[5], b->dp[23]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[22]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[21]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[20]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[19]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[18]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[17]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[12], b->dp[16]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[13], b->dp[15]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[14], b->dp[14]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[15], b->dp[13]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[16], b->dp[12]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[17], b->dp[11]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[18], b->dp[10]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[19], b->dp[9]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[20], b->dp[8]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[21], b->dp[7]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[22], b->dp[6]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[23], b->dp[5]);
        r->dp[28] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[6], b->dp[23]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[22]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[21]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[20]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[19]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[18]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[12], b->dp[17]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[13], b->dp[16]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[14], b->dp[15]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[15], b->dp[14]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[16], b->dp[13]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[17], b->dp[12]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[18], b->dp[11]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[19], b->dp[10]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[20], b->dp[9]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[21], b->dp[8]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[22], b->dp[7]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[23], b->dp[6]);
        r->dp[29] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[7], b->dp[23]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[22]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[21]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[20]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[19]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[12], b->dp[18]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[13], b->dp[17]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[14], b->dp[16]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[15], b->dp[15]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[16], b->dp[14]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[17], b->dp[13]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[18], b->dp[12]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[19], b->dp[11]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[20], b->dp[10]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[21], b->dp[9]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[22], b->dp[8]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[23], b->dp[7]);
        r->dp[30] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[8], b->dp[23]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[22]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[21]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[20]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[12], b->dp[19]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[13], b->dp[18]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[14], b->dp[17]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[15], b->dp[16]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[16], b->dp[15]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[17], b->dp[14]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[18], b->dp[13]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[19], b->dp[12]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[20], b->dp[11]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[21], b->dp[10]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[22], b->dp[9]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[23], b->dp[8]);
        r->dp[31] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[9], b->dp[23]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[22]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[21]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[12], b->dp[20]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[13], b->dp[19]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[14], b->dp[18]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[15], b->dp[17]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[16], b->dp[16]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[17], b->dp[15]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[18], b->dp[14]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[19], b->dp[13]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[20], b->dp[12]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[21], b->dp[11]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[22], b->dp[10]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[23], b->dp[9]);
        r->dp[32] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[10], b->dp[23]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[22]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[12], b->dp[21]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[13], b->dp[20]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[14], b->dp[19]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[15], b->dp[18]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[16], b->dp[17]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[17], b->dp[16]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[18], b->dp[15]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[19], b->dp[14]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[20], b->dp[13]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[21], b->dp[12]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[22], b->dp[11]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[23], b->dp[10]);
        r->dp[33] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[11], b->dp[23]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[12], b->dp[22]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[13], b->dp[21]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[14], b->dp[20]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[15], b->dp[19]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[16], b->dp[18]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[17], b->dp[17]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[18], b->dp[16]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[19], b->dp[15]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[20], b->dp[14]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[21], b->dp[13]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[22], b->dp[12]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[23], b->dp[11]);
        r->dp[34] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[12], b->dp[23]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[13], b->dp[22]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[14], b->dp[21]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[15], b->dp[20]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[16], b->dp[19]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[17], b->dp[18]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[18], b->dp[17]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[19], b->dp[16]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[20], b->dp[15]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[21], b->dp[14]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[22], b->dp[13]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[23], b->dp[12]);
        r->dp[35] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[13], b->dp[23]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[14], b->dp[22]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[15], b->dp[21]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[16], b->dp[20]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[17], b->dp[19]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[18], b->dp[18]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[19], b->dp[17]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[20], b->dp[16]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[21], b->dp[15]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[22], b->dp[14]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[23], b->dp[13]);
        r->dp[36] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[14], b->dp[23]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[15], b->dp[22]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[16], b->dp[21]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[17], b->dp[20]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[18], b->dp[19]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[19], b->dp[18]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[20], b->dp[17]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[21], b->dp[16]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[22], b->dp[15]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[23], b->dp[14]);
        r->dp[37] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[15], b->dp[23]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[16], b->dp[22]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[17], b->dp[21]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[18], b->dp[20]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[19], b->dp[19]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[20], b->dp[18]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[21], b->dp[17]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[22], b->dp[16]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[23], b->dp[15]);
        r->dp[38] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[16], b->dp[23]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[17], b->dp[22]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[18], b->dp[21]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[19], b->dp[20]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[20], b->dp[19]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[21], b->dp[18]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[22], b->dp[17]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[23], b->dp[16]);
        r->dp[39] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[17], b->dp[23]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[18], b->dp[22]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[19], b->dp[21]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[20], b->dp[20]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[21], b->dp[19]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[22], b->dp[18]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[23], b->dp[17]);
        r->dp[40] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[18], b->dp[23]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[19], b->dp[22]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[20], b->dp[21]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[21], b->dp[20]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[22], b->dp[19]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[23], b->dp[18]);
        r->dp[41] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[19], b->dp[23]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[20], b->dp[22]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[21], b->dp[21]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[22], b->dp[20]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[23], b->dp[19]);
        r->dp[42] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[20], b->dp[23]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[21], b->dp[22]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[22], b->dp[21]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[23], b->dp[20]);
        r->dp[43] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[21], b->dp[23]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[22], b->dp[22]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[23], b->dp[21]);
        r->dp[44] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD(l, h, o, a->dp[22], b->dp[23]);
        SP_ASM_MUL_ADD(l, h, o, a->dp[23], b->dp[22]);
        r->dp[45] = l;
        l = h;
        h = o;
        SP_ASM_MUL_ADD_NO(l, h, a->dp[23], b->dp[23]);
        r->dp[46] = l;
        r->dp[47] = h;
        XMEMCPY(r->dp, t, 24 * sizeof(sp_int_digit));
        r->used = 48;
        sp_clamp(r);
    }

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (t != NULL) {
        XFREE(t, NULL, DYNAMIC_TYPE_BIGINT);
    }
#endif
    return err;
}
    #endif /* SP_INT_DIGITS >= 48 */

    #if SP_INT_DIGITS >= 64
/* Multiply a by b and store in r: r = a * b
 *
 * Karatsuba implementaiton.
 *
 * @param  [in]   a  SP integer to multiply.
 * @param  [in]   b  SP integer to multiply.
 * @param  [out]  r  SP integer result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
static int _sp_mul_32(sp_int* a, sp_int* b, sp_int* r)
{
    int err = MP_OKAY;
    int i;
    sp_int_digit l;
    sp_int_digit h;
    sp_int* a1;
    sp_int* b1;
    sp_int* z0;
    sp_int* z1;
    sp_int* z2;
    sp_int_digit ca;
    sp_int_digit cb;
    DECL_SP_INT_ARRAY(t, 16, 2);
    DECL_SP_INT_ARRAY(z, 33, 2);

    ALLOC_SP_INT_ARRAY(t, 16, 2, err, NULL);
    ALLOC_SP_INT_ARRAY(z, 33, 2, err, NULL);
    if (err == MP_OKAY) {
        a1 = t[0];
        b1 = t[1];
        z1 = z[0];
        z2 = z[1];
        z0 = r;

        XMEMCPY(a1->dp, &a->dp[16], sizeof(sp_int_digit) * 16);
        a1->used = 16;
        XMEMCPY(b1->dp, &b->dp[16], sizeof(sp_int_digit) * 16);
        b1->used = 16;

        /* z2 = a1 * b1 */
        err = _sp_mul_16(a1, b1, z2);
    }
    if (err == MP_OKAY) {
        l = a1->dp[0];
        h = 0;
        SP_ASM_ADDC(l, h, a->dp[0]);
        a1->dp[0] = l;
        l = h;
        h = 0;
        for (i = 1; i < 16; i++) {
            SP_ASM_ADDC(l, h, a1->dp[i]);
            SP_ASM_ADDC(l, h, a->dp[i]);
            a1->dp[i] = l;
            l = h;
            h = 0;
        }
        ca = l;
        /* b01 = b0 + b1 */
        l = b1->dp[0];
        h = 0;
        SP_ASM_ADDC(l, h, b->dp[0]);
        b1->dp[0] = l;
        l = h;
        h = 0;
        for (i = 1; i < 16; i++) {
            SP_ASM_ADDC(l, h, b1->dp[i]);
            SP_ASM_ADDC(l, h, b->dp[i]);
            b1->dp[i] = l;
            l = h;
            h = 0;
        }
        cb = l;

        /* z0 = a0 * b0 */
        err = _sp_mul_16(a, b, z0);
    }
    if (err == MP_OKAY) {
        /* z1 = (a0 + a1) * (b0 + b1) */
        err = _sp_mul_16(a1, b1, z1);
    }
    if (err == MP_OKAY) {
        /* r = (z2 << 32) + (z1 - z0 - z2) << 16) + z0 */
        /* r = z0 */
        /* r += (z1 - z0 - z2) << 16 */
        z1->dp[32] = ca & cb;
        l = 0;
        if (ca) {
            h = 0;
            for (i = 0; i < 16; i++) {
                SP_ASM_ADDC(l, h, z1->dp[i + 16]);
                SP_ASM_ADDC(l, h, b1->dp[i]);
                z1->dp[i + 16] = l;
                l = h;
                h = 0;
            }
        }
        z1->dp[32] += l;
        l = 0;
        if (cb) {
            h = 0;
            for (i = 0; i < 16; i++) {
                SP_ASM_ADDC(l, h, z1->dp[i + 16]);
                SP_ASM_ADDC(l, h, a1->dp[i]);
                z1->dp[i + 16] = l;
                l = h;
                h = 0;
            }
        }
        z1->dp[32] += l;
        /* z1 = z1 - z0 - z1 */
        l = 0;
        h = 0;
        for (i = 0; i < 32; i++) {
            l += z1->dp[i];
            SP_ASM_SUBC(l, h, z0->dp[i]);
            SP_ASM_SUBC(l, h, z2->dp[i]);
            z1->dp[i] = l;
            l = h;
            h = 0;
        }
        z1->dp[i] += l;
        /* r += z1 << 16 */
        l = 0;
        h = 0;
        for (i = 0; i < 16; i++) {
            SP_ASM_ADDC(l, h, r->dp[i + 16]);
            SP_ASM_ADDC(l, h, z1->dp[i]);
            r->dp[i + 16] = l;
            l = h;
            h = 0;
        }
        for (; i < 33; i++) {
            SP_ASM_ADDC(l, h, z1->dp[i]);
            r->dp[i + 16] = l;
            l = h;
            h = 0;
        }
        /* r += z2 << 32  */
        l = 0;
        h = 0;
        for (i = 0; i < 17; i++) {
            SP_ASM_ADDC(l, h, r->dp[i + 32]);
            SP_ASM_ADDC(l, h, z2->dp[i]);
            r->dp[i + 32] = l;
            l = h;
            h = 0;
        }
        for (; i < 32; i++) {
            SP_ASM_ADDC(l, h, z2->dp[i]);
            r->dp[i + 32] = l;
            l = h;
            h = 0;
        }
        r->used = 64;
        sp_clamp(r);
    }

    FREE_SP_INT_ARRAY(z, NULL);
    FREE_SP_INT_ARRAY(t, NULL);
    return err;
}
    #endif /* SP_INT_DIGITS >= 64 */

    #if SP_INT_DIGITS >= 96
/* Multiply a by b and store in r: r = a * b
 *
 * Karatsuba implementaiton.
 *
 * @param  [in]   a  SP integer to multiply.
 * @param  [in]   b  SP integer to multiply.
 * @param  [out]  r  SP integer result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
static int _sp_mul_48(sp_int* a, sp_int* b, sp_int* r)
{
    int err = MP_OKAY;
    int i;
    sp_int_digit l;
    sp_int_digit h;
    sp_int* a1;
    sp_int* b1;
    sp_int* z0;
    sp_int* z1;
    sp_int* z2;
    sp_int_digit ca;
    sp_int_digit cb;
    DECL_SP_INT_ARRAY(t, 24, 2);
    DECL_SP_INT_ARRAY(z, 49, 2);

    ALLOC_SP_INT_ARRAY(t, 24, 2, err, NULL);
    ALLOC_SP_INT_ARRAY(z, 49, 2, err, NULL);
    if (err == MP_OKAY) {
        a1 = t[0];
        b1 = t[1];
        z1 = z[0];
        z2 = z[1];
        z0 = r;

        XMEMCPY(a1->dp, &a->dp[24], sizeof(sp_int_digit) * 24);
        a1->used = 24;
        XMEMCPY(b1->dp, &b->dp[24], sizeof(sp_int_digit) * 24);
        b1->used = 24;

        /* z2 = a1 * b1 */
        err = _sp_mul_24(a1, b1, z2);
    }
    if (err == MP_OKAY) {
        l = a1->dp[0];
        h = 0;
        SP_ASM_ADDC(l, h, a->dp[0]);
        a1->dp[0] = l;
        l = h;
        h = 0;
        for (i = 1; i < 24; i++) {
            SP_ASM_ADDC(l, h, a1->dp[i]);
            SP_ASM_ADDC(l, h, a->dp[i]);
            a1->dp[i] = l;
            l = h;
            h = 0;
        }
        ca = l;
        /* b01 = b0 + b1 */
        l = b1->dp[0];
        h = 0;
        SP_ASM_ADDC(l, h, b->dp[0]);
        b1->dp[0] = l;
        l = h;
        h = 0;
        for (i = 1; i < 24; i++) {
            SP_ASM_ADDC(l, h, b1->dp[i]);
            SP_ASM_ADDC(l, h, b->dp[i]);
            b1->dp[i] = l;
            l = h;
            h = 0;
        }
        cb = l;

        /* z0 = a0 * b0 */
        err = _sp_mul_24(a, b, z0);
    }
    if (err == MP_OKAY) {
        /* z1 = (a0 + a1) * (b0 + b1) */
        err = _sp_mul_24(a1, b1, z1);
    }
    if (err == MP_OKAY) {
        /* r = (z2 << 48) + (z1 - z0 - z2) << 24) + z0 */
        /* r = z0 */
        /* r += (z1 - z0 - z2) << 24 */
        z1->dp[48] = ca & cb;
        l = 0;
        if (ca) {
            h = 0;
            for (i = 0; i < 24; i++) {
                SP_ASM_ADDC(l, h, z1->dp[i + 24]);
                SP_ASM_ADDC(l, h, b1->dp[i]);
                z1->dp[i + 24] = l;
                l = h;
                h = 0;
            }
        }
        z1->dp[48] += l;
        l = 0;
        if (cb) {
            h = 0;
            for (i = 0; i < 24; i++) {
                SP_ASM_ADDC(l, h, z1->dp[i + 24]);
                SP_ASM_ADDC(l, h, a1->dp[i]);
                z1->dp[i + 24] = l;
                l = h;
                h = 0;
            }
        }
        z1->dp[48] += l;
        /* z1 = z1 - z0 - z1 */
        l = 0;
        h = 0;
        for (i = 0; i < 48; i++) {
            l += z1->dp[i];
            SP_ASM_SUBC(l, h, z0->dp[i]);
            SP_ASM_SUBC(l, h, z2->dp[i]);
            z1->dp[i] = l;
            l = h;
            h = 0;
        }
        z1->dp[i] += l;
        /* r += z1 << 16 */
        l = 0;
        h = 0;
        for (i = 0; i < 24; i++) {
            SP_ASM_ADDC(l, h, r->dp[i + 24]);
            SP_ASM_ADDC(l, h, z1->dp[i]);
            r->dp[i + 24] = l;
            l = h;
            h = 0;
        }
        for (; i < 49; i++) {
            SP_ASM_ADDC(l, h, z1->dp[i]);
            r->dp[i + 24] = l;
            l = h;
            h = 0;
        }
        /* r += z2 << 48  */
        l = 0;
        h = 0;
        for (i = 0; i < 25; i++) {
            SP_ASM_ADDC(l, h, r->dp[i + 48]);
            SP_ASM_ADDC(l, h, z2->dp[i]);
            r->dp[i + 48] = l;
            l = h;
            h = 0;
        }
        for (; i < 48; i++) {
            SP_ASM_ADDC(l, h, z2->dp[i]);
            r->dp[i + 48] = l;
            l = h;
            h = 0;
        }
        r->used = 96;
        sp_clamp(r);
    }

    FREE_SP_INT_ARRAY(z, NULL);
    FREE_SP_INT_ARRAY(t, NULL);
    return err;
}
    #endif /* SP_INT_DIGITS >= 96 */

    #if SP_INT_DIGITS >= 128
/* Multiply a by b and store in r: r = a * b
 *
 * Karatsuba implementaiton.
 *
 * @param  [in]   a  SP integer to multiply.
 * @param  [in]   b  SP integer to multiply.
 * @param  [out]  r  SP integer result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
static int _sp_mul_64(sp_int* a, sp_int* b, sp_int* r)
{
    int err = MP_OKAY;
    int i;
    sp_int_digit l;
    sp_int_digit h;
    sp_int* a1;
    sp_int* b1;
    sp_int* z0;
    sp_int* z1;
    sp_int* z2;
    sp_int_digit ca;
    sp_int_digit cb;
    DECL_SP_INT_ARRAY(t, 32, 2);
    DECL_SP_INT_ARRAY(z, 65, 2);

    ALLOC_SP_INT_ARRAY(t, 32, 2, err, NULL);
    ALLOC_SP_INT_ARRAY(z, 65, 2, err, NULL);
    if (err == MP_OKAY) {
        a1 = t[0];
        b1 = t[1];
        z1 = z[0];
        z2 = z[1];
        z0 = r;

        XMEMCPY(a1->dp, &a->dp[32], sizeof(sp_int_digit) * 32);
        a1->used = 32;
        XMEMCPY(b1->dp, &b->dp[32], sizeof(sp_int_digit) * 32);
        b1->used = 32;

        /* z2 = a1 * b1 */
        err = _sp_mul_32(a1, b1, z2);
    }
    if (err == MP_OKAY) {
        l = a1->dp[0];
        h = 0;
        SP_ASM_ADDC(l, h, a->dp[0]);
        a1->dp[0] = l;
        l = h;
        h = 0;
        for (i = 1; i < 32; i++) {
            SP_ASM_ADDC(l, h, a1->dp[i]);
            SP_ASM_ADDC(l, h, a->dp[i]);
            a1->dp[i] = l;
            l = h;
            h = 0;
        }
        ca = l;
        /* b01 = b0 + b1 */
        l = b1->dp[0];
        h = 0;
        SP_ASM_ADDC(l, h, b->dp[0]);
        b1->dp[0] = l;
        l = h;
        h = 0;
        for (i = 1; i < 32; i++) {
            SP_ASM_ADDC(l, h, b1->dp[i]);
            SP_ASM_ADDC(l, h, b->dp[i]);
            b1->dp[i] = l;
            l = h;
            h = 0;
        }
        cb = l;

        /* z0 = a0 * b0 */
        err = _sp_mul_32(a, b, z0);
    }
    if (err == MP_OKAY) {
        /* z1 = (a0 + a1) * (b0 + b1) */
        err = _sp_mul_32(a1, b1, z1);
    }
    if (err == MP_OKAY) {
        /* r = (z2 << 64) + (z1 - z0 - z2) << 32) + z0 */
        /* r = z0 */
        /* r += (z1 - z0 - z2) << 32 */
        z1->dp[64] = ca & cb;
        l = 0;
        if (ca) {
            h = 0;
            for (i = 0; i < 32; i++) {
                SP_ASM_ADDC(l, h, z1->dp[i + 32]);
                SP_ASM_ADDC(l, h, b1->dp[i]);
                z1->dp[i + 32] = l;
                l = h;
                h = 0;
            }
        }
        z1->dp[64] += l;
        l = 0;
        if (cb) {
            h = 0;
            for (i = 0; i < 32; i++) {
                SP_ASM_ADDC(l, h, z1->dp[i + 32]);
                SP_ASM_ADDC(l, h, a1->dp[i]);
                z1->dp[i + 32] = l;
                l = h;
                h = 0;
            }
        }
        z1->dp[64] += l;
        /* z1 = z1 - z0 - z1 */
        l = 0;
        h = 0;
        for (i = 0; i < 64; i++) {
            l += z1->dp[i];
            SP_ASM_SUBC(l, h, z0->dp[i]);
            SP_ASM_SUBC(l, h, z2->dp[i]);
            z1->dp[i] = l;
            l = h;
            h = 0;
        }
        z1->dp[i] += l;
        /* r += z1 << 16 */
        l = 0;
        h = 0;
        for (i = 0; i < 32; i++) {
            SP_ASM_ADDC(l, h, r->dp[i + 32]);
            SP_ASM_ADDC(l, h, z1->dp[i]);
            r->dp[i + 32] = l;
            l = h;
            h = 0;
        }
        for (; i < 65; i++) {
            SP_ASM_ADDC(l, h, z1->dp[i]);
            r->dp[i + 32] = l;
            l = h;
            h = 0;
        }
        /* r += z2 << 64  */
        l = 0;
        h = 0;
        for (i = 0; i < 33; i++) {
            SP_ASM_ADDC(l, h, r->dp[i + 64]);
            SP_ASM_ADDC(l, h, z2->dp[i]);
            r->dp[i + 64] = l;
            l = h;
            h = 0;
        }
        for (; i < 64; i++) {
            SP_ASM_ADDC(l, h, z2->dp[i]);
            r->dp[i + 64] = l;
            l = h;
            h = 0;
        }
        r->used = 128;
        sp_clamp(r);
    }

    FREE_SP_INT_ARRAY(z, NULL);
    FREE_SP_INT_ARRAY(t, NULL);
    return err;
}
    #endif /* SP_INT_DIGITS >= 128 */

    #if SP_INT_DIGITS >= 192
/* Multiply a by b and store in r: r = a * b
 *
 * Karatsuba implementaiton.
 *
 * @param  [in]   a  SP integer to multiply.
 * @param  [in]   b  SP integer to multiply.
 * @param  [out]  r  SP integer result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
static int _sp_mul_96(sp_int* a, sp_int* b, sp_int* r)
{
    int err = MP_OKAY;
    int i;
    sp_int_digit l;
    sp_int_digit h;
    sp_int* a1;
    sp_int* b1;
    sp_int* z0;
    sp_int* z1;
    sp_int* z2;
    sp_int_digit ca;
    sp_int_digit cb;
    DECL_SP_INT_ARRAY(t, 48, 2);
    DECL_SP_INT_ARRAY(z, 97, 2);

    ALLOC_SP_INT_ARRAY(t, 48, 2, err, NULL);
    ALLOC_SP_INT_ARRAY(z, 97, 2, err, NULL);
    if (err == MP_OKAY) {
        a1 = t[0];
        b1 = t[1];
        z1 = z[0];
        z2 = z[1];
        z0 = r;

        XMEMCPY(a1->dp, &a->dp[48], sizeof(sp_int_digit) * 48);
        a1->used = 48;
        XMEMCPY(b1->dp, &b->dp[48], sizeof(sp_int_digit) * 48);
        b1->used = 48;

        /* z2 = a1 * b1 */
        err = _sp_mul_48(a1, b1, z2);
    }
    if (err == MP_OKAY) {
        l = a1->dp[0];
        h = 0;
        SP_ASM_ADDC(l, h, a->dp[0]);
        a1->dp[0] = l;
        l = h;
        h = 0;
        for (i = 1; i < 48; i++) {
            SP_ASM_ADDC(l, h, a1->dp[i]);
            SP_ASM_ADDC(l, h, a->dp[i]);
            a1->dp[i] = l;
            l = h;
            h = 0;
        }
        ca = l;
        /* b01 = b0 + b1 */
        l = b1->dp[0];
        h = 0;
        SP_ASM_ADDC(l, h, b->dp[0]);
        b1->dp[0] = l;
        l = h;
        h = 0;
        for (i = 1; i < 48; i++) {
            SP_ASM_ADDC(l, h, b1->dp[i]);
            SP_ASM_ADDC(l, h, b->dp[i]);
            b1->dp[i] = l;
            l = h;
            h = 0;
        }
        cb = l;

        /* z0 = a0 * b0 */
        err = _sp_mul_48(a, b, z0);
    }
    if (err == MP_OKAY) {
        /* z1 = (a0 + a1) * (b0 + b1) */
        err = _sp_mul_48(a1, b1, z1);
    }
    if (err == MP_OKAY) {
        /* r = (z2 << 96) + (z1 - z0 - z2) << 48) + z0 */
        /* r = z0 */
        /* r += (z1 - z0 - z2) << 48 */
        z1->dp[96] = ca & cb;
        l = 0;
        if (ca) {
            h = 0;
            for (i = 0; i < 48; i++) {
                SP_ASM_ADDC(l, h, z1->dp[i + 48]);
                SP_ASM_ADDC(l, h, b1->dp[i]);
                z1->dp[i + 48] = l;
                l = h;
                h = 0;
            }
        }
        z1->dp[96] += l;
        l = 0;
        if (cb) {
            h = 0;
            for (i = 0; i < 48; i++) {
                SP_ASM_ADDC(l, h, z1->dp[i + 48]);
                SP_ASM_ADDC(l, h, a1->dp[i]);
                z1->dp[i + 48] = l;
                l = h;
                h = 0;
            }
        }
        z1->dp[96] += l;
        /* z1 = z1 - z0 - z1 */
        l = 0;
        h = 0;
        for (i = 0; i < 96; i++) {
            l += z1->dp[i];
            SP_ASM_SUBC(l, h, z0->dp[i]);
            SP_ASM_SUBC(l, h, z2->dp[i]);
            z1->dp[i] = l;
            l = h;
            h = 0;
        }
        z1->dp[i] += l;
        /* r += z1 << 16 */
        l = 0;
        h = 0;
        for (i = 0; i < 48; i++) {
            SP_ASM_ADDC(l, h, r->dp[i + 48]);
            SP_ASM_ADDC(l, h, z1->dp[i]);
            r->dp[i + 48] = l;
            l = h;
            h = 0;
        }
        for (; i < 97; i++) {
            SP_ASM_ADDC(l, h, z1->dp[i]);
            r->dp[i + 48] = l;
            l = h;
            h = 0;
        }
        /* r += z2 << 96  */
        l = 0;
        h = 0;
        for (i = 0; i < 49; i++) {
            SP_ASM_ADDC(l, h, r->dp[i + 96]);
            SP_ASM_ADDC(l, h, z2->dp[i]);
            r->dp[i + 96] = l;
            l = h;
            h = 0;
        }
        for (; i < 96; i++) {
            SP_ASM_ADDC(l, h, z2->dp[i]);
            r->dp[i + 96] = l;
            l = h;
            h = 0;
        }
        r->used = 192;
        sp_clamp(r);
    }

    FREE_SP_INT_ARRAY(z, NULL);
    FREE_SP_INT_ARRAY(t, NULL);
    return err;
}
    #endif /* SP_INT_DIGITS >= 192 */

#endif /* SQR_MUL_ASM && WOLFSSL_SP_INT_LARGE_COMBA */
#endif /* !WOLFSSL_SP_SMALL */

/* Multiply a by b and store in r: r = a * b
 *
 * @param  [in]   a  SP integer to multiply.
 * @param  [in]   b  SP integer to multiply.
 * @param  [out]  r  SP integer result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a, b or is NULL; or the result will be too big for fixed
 *          data length.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
int sp_mul(sp_int* a, sp_int* b, sp_int* r)
{
    int err = MP_OKAY;
#ifdef WOLFSSL_SP_INT_NEGATIVE
    int sign;
#endif

    if ((a == NULL) || (b == NULL) || (r == NULL)) {
        err = MP_VAL;
    }

    /* Need extra digit during calculation. */
    if ((err == MP_OKAY) && (a->used + b->used > r->size)) {
        err = MP_VAL;
    }

#if 0
    if (err == MP_OKAY) {
        sp_print(a, "a");
        sp_print(b, "b");
    }
#endif

    if (err == MP_OKAY) {
    #ifdef WOLFSSL_SP_INT_NEGATIVE
        sign = a->sign ^ b->sign;
    #endif

        if ((a->used == 0) || (b->used == 0)) {
            _sp_zero(r);
        }
        else
#ifndef WOLFSSL_SP_SMALL
#if !defined(WOLFSSL_HAVE_SP_ECC) && defined(HAVE_ECC)
#if SP_WORD_SIZE == 64
        if ((a->used == 4) && (b->used == 4)) {
            err = _sp_mul_4(a, b, r);
        }
        else
#endif /* SP_WORD_SIZE == 64 */
#if SP_WORD_SIZE == 64
#ifdef SQR_MUL_ASM
        if ((a->used == 6) && (b->used == 6)) {
            err = _sp_mul_6(a, b, r);
        }
        else
#endif /* SQR_MUL_ASM */
#endif /* SP_WORD_SIZE == 64 */
#if SP_WORD_SIZE == 32
#ifdef SQR_MUL_ASM
        if ((a->used == 8) && (b->used == 8)) {
            err = _sp_mul_8(a, b, r);
        }
        else
#endif /* SQR_MUL_ASM */
#endif /* SP_WORD_SIZE == 32 */
#if SP_WORD_SIZE == 32
#ifdef SQR_MUL_ASM
        if ((a->used == 12) && (b->used == 12)) {
            err = _sp_mul_12(a, b, r);
        }
        else
#endif /* SQR_MUL_ASM */
#endif /* SP_WORD_SIZE == 32 */
#endif /* !WOLFSSL_HAVE_SP_ECC && HAVE_ECC */
#if defined(SQR_MUL_ASM) && defined(WOLFSSL_SP_INT_LARGE_COMBA)
    #if SP_INT_DIGITS >= 32
        if ((a->used == 16) && (b->used == 16)) {
            err = _sp_mul_16(a, b, r);
        }
        else
    #endif /* SP_INT_DIGITS >= 32 */
    #if SP_INT_DIGITS >= 48
        if ((a->used == 24) && (b->used == 24)) {
            err = _sp_mul_24(a, b, r);
        }
        else
    #endif /* SP_INT_DIGITS >= 48 */
    #if SP_INT_DIGITS >= 64
        if ((a->used == 32) && (b->used == 32)) {
            err = _sp_mul_32(a, b, r);
        }
        else
    #endif /* SP_INT_DIGITS >= 64 */
    #if SP_INT_DIGITS >= 96
        if ((a->used == 48) && (b->used == 48)) {
            err = _sp_mul_48(a, b, r);
        }
        else
    #endif /* SP_INT_DIGITS >= 96 */
    #if SP_INT_DIGITS >= 128
        if ((a->used == 64) && (b->used == 64)) {
            err = _sp_mul_64(a, b, r);
        }
        else
    #endif /* SP_INT_DIGITS >= 128 */
    #if SP_INT_DIGITS >= 192
        if ((a->used == 96) && (b->used == 96)) {
            err = _sp_mul_96(a, b, r);
        }
        else
    #endif /* SP_INT_DIGITS >= 192 */
#endif /* SQR_MUL_ASM && WOLFSSL_SP_INT_LARGE_COMBA */
#endif /* !WOLFSSL_SP_SMALL */

#ifdef SQR_MUL_ASM
        if (a->used == b->used) {
            err = _sp_mul_nxn(a, b, r);
        }
        else
#endif
        {
            err = _sp_mul(a, b, r);
        }
    }

#ifdef WOLFSSL_SP_INT_NEGATIVE
    if (err == MP_OKAY) {
        r->sign = (r->used == 0) ? MP_ZPOS : sign;
    }
#endif

#if 0
    if (err == MP_OKAY) {
        sp_print(r, "rmul");
    }
#endif

    return err;
}
/* END SP_MUL implementations. */

#if defined(WOLFSSL_SP_MATH_ALL) || defined(WOLFSSL_HAVE_SP_DH) || \
    defined(WOLFCRYPT_HAVE_ECCSI) || \
    (!defined(NO_RSA) && defined(WOLFSSL_KEY_GEN))
/* Multiply a by b mod m and store in r: r = (a * b) mod m
 *
 * @param  [in]   a  SP integer to multiply.
 * @param  [in]   b  SP integer to multiply.
 * @param  [in]   m  SP integer that is the modulus.
 * @param  [out]  r  SP integer result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a, b, m or r is NULL; m is 0; or a * b is too big for
 *          fixed data length.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
int sp_mulmod(sp_int* a, sp_int* b, sp_int* m, sp_int* r)
{
    int err = MP_OKAY;
    DECL_SP_INT(t, ((a == NULL) || (b == NULL)) ? 1 : a->used + b->used);

    if ((a == NULL) || (b == NULL) || (m == NULL) || (r == NULL)) {
        err = MP_VAL;
    }
    if ((err == MP_OKAY) && (a->used + b->used > r->size)) {
        err = MP_VAL;
    }

    ALLOC_SP_INT(t, a->used + b->used, err, NULL);
    if (err == MP_OKAY) {
        err = sp_init_size(t, a->used + b->used);
    }
    if (err == MP_OKAY) {
        err = sp_mul(a, b, t);
    }
    if (err == MP_OKAY) {
        err = sp_mod(t, m, r);
    }

    FREE_SP_INT(t, NULL);
    return err;
}
#endif

#ifdef WOLFSSL_SP_INVMOD
/* Calculates the multiplicative inverse in the field.
 *
 * @param  [in]   a  SP integer to find inverse of.
 * @param  [in]   m  SP integer this is the modulus.
 * @param  [out]  r  SP integer to hold result. r cannot be m.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a, m or r is NULL; a or m is zero; a and m are even or
 *          m is negative.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
int sp_invmod(sp_int* a, sp_int* m, sp_int* r)
{
    int err = MP_OKAY;
    sp_int* u = NULL;
    sp_int* v = NULL;
    sp_int* b = NULL;
    sp_int* mm;
    int evenMod = 0;
    DECL_SP_INT_ARRAY(t, (m == NULL) ? 1 : (m->used + 1), 3);
    DECL_SP_INT(c, (m == NULL) ? 1 : (2 * m->used + 1));

    if ((a == NULL) || (m == NULL) || (r == NULL) || (r == m)) {
        err = MP_VAL;
    }
    if ((err == MP_OKAY) && (m->used * 2 > r->size)) {
        err = MP_VAL;
    }

#ifdef WOLFSSL_SP_INT_NEGATIVE
    if ((err == MP_OKAY) && (m->sign == MP_NEG)) {
        err = MP_VAL;
    }
#endif

    ALLOC_SP_INT_ARRAY(t, m->used + 1, 3, err, NULL);
    ALLOC_SP_INT(c, 2 * m->used + 1, err, NULL);
    if (err == MP_OKAY) {
        u = t[0];
        v = t[1];
        b = t[2];
        /* c allocated separately and larger for even mod case. */

        if (_sp_cmp_abs(a, m) != MP_LT) {
            err = sp_mod(a, m, r);
            a = r;
        }
    }

#ifdef WOLFSSL_SP_INT_NEGATIVE
    if ((err == MP_OKAY) && (a->sign == MP_NEG)) {
        /* Make 'a' positive */
        err = sp_add(m, a, r);
        a = r;
    }
#endif

    /* 0 != n*m + 1 (+ve m), r*a mod 0 is always 0 (never 1)  */
    if ((err == MP_OKAY) && (sp_iszero(a) || sp_iszero(m))) {
        err = MP_VAL;
    }
    /* r*2*x != n*2*y + 1 for integer x,y */
    if ((err == MP_OKAY) && sp_iseven(a) && sp_iseven(m)) {
        err = MP_VAL;
    }

    /* 1*1 = 0*m + 1  */
    if ((err == MP_OKAY) && sp_isone(a)) {
        sp_set(r, 1);
    }
    else if (err != MP_OKAY) {
    }
    else {
        sp_init_size(u, m->used + 1);
        sp_init_size(v, m->used + 1);
        sp_init_size(b, m->used + 1);
        sp_init_size(c, 2 * m->used + 1);

        if (sp_iseven(m)) {
            /* a^-1 mod m = m + ((1 - m*(m^-1 % a)) / a) */
            mm = a;
            sp_copy(a, u);
            sp_mod(m, a, v);
            /* v == 0 when a divides m evenly - no inverse.  */
            if (sp_iszero(v)) {
                /* Force u to no inverse answer. */
                sp_set(u, 0);
            }
            evenMod = 1;
        }
        else {
            mm = m;
            sp_copy(m, u);
            sp_copy(a, v);
        }
        _sp_zero(b);
        sp_set(c, 1);

        while (!sp_isone(v) && !sp_iszero(u)) {
            if (sp_iseven(u)) {
                sp_div_2(u, u);
                if (sp_isodd(b)) {
                    _sp_add_off(b, mm, b, 0);
                }
                sp_div_2(b, b);
            }
            else if (sp_iseven(v)) {
                sp_div_2(v, v);
                if (sp_isodd(c)) {
                    _sp_add_off(c, mm, c, 0);
                }
                sp_div_2(c, c);
            }
            else if (_sp_cmp(u, v) != MP_LT) {
                _sp_sub_off(u, v, u, 0);
                if (_sp_cmp(b, c) == MP_LT) {
                    _sp_add_off(b, mm, b, 0);
                }
                _sp_sub_off(b, c, b, 0);
            }
            else {
                _sp_sub_off(v, u, v, 0);
                if (_sp_cmp(c, b) == MP_LT) {
                    _sp_add_off(c, mm, c, 0);
                }
                _sp_sub_off(c, b, c, 0);
            }
        }
        if (sp_iszero(u)) {
            err = MP_VAL;
        }
        else if (evenMod) {
            /* Finish operation.
             *    a^-1 mod m = m + ((1 - m*c) / a)
             * => a^-1 mod m = m - ((m*c - 1) / a)
             */
            err = sp_mul(c, m, c);
            if (err == MP_OKAY) {
                _sp_sub_d(c, 1, c);
                err = sp_div(c, a, c, NULL);
            }
            if (err == MP_OKAY) {
                sp_sub(m, c, r);
            }
        }
        else {
            err = sp_copy(c, r);
        }
    }

    FREE_SP_INT(c, NULL);
    FREE_SP_INT_ARRAY(t, NULL);
    return err;
}
#endif /* WOLFSSL_SP_INVMOD */

#ifdef WOLFSSL_SP_INVMOD_MONT_CT

#define CT_INV_MOD_PRE_CNT      8

/* Calculates the multiplicative inverse in the field - constant time.
 *
 * Modulus (m) must be a prime and greater than 2.
 *
 * @param  [in]   a   SP integer, Montgomery form, to find inverse of.
 * @param  [in]   m   SP integer this is the modulus.
 * @param  [out]  r   SP integer to hold result.
 * @param  [in]   mp  SP integer digit that is the bottom digit of inv(-m).
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a, m or r is NULL; a is 0 or m is less than 3.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
int sp_invmod_mont_ct(sp_int* a, sp_int* m, sp_int* r, sp_int_digit mp)
{
    int err = MP_OKAY;
    int i;
    int j = 0;
    sp_int* t = NULL;
    sp_int* e = NULL;
    DECL_SP_INT_ARRAY(pre, (m == NULL) ? 1 : m->used * 2 + 1,
                                                        CT_INV_MOD_PRE_CNT + 2);

    if ((a == NULL) || (m == NULL) || (r == NULL)) {
        err = MP_VAL;
    }

    /* 0 != n*m + 1 (+ve m), r*a mod 0 is always 0 (never 1) */
    if ((err == MP_OKAY) && (sp_iszero(a) || sp_iszero(m) ||
                                              (m->used == 1 && m->dp[0] < 3))) {
        err = MP_VAL;
    }

    ALLOC_SP_INT_ARRAY(pre, m->used * 2 + 1, CT_INV_MOD_PRE_CNT + 2, err, NULL);
    if (err == MP_OKAY) {
        t = pre[CT_INV_MOD_PRE_CNT + 0];
        e = pre[CT_INV_MOD_PRE_CNT + 1];
        sp_init_size(t, m->used * 2 + 1);
        sp_init_size(e, m->used * 2 + 1);

        sp_init_size(pre[0], m->used * 2 + 1);
        err = sp_copy(a, pre[0]);
        for (i = 1; (err == MP_OKAY) && (i < CT_INV_MOD_PRE_CNT); i++) {
            sp_init_size(pre[i], m->used * 2 + 1);
            err = sp_sqr(pre[i-1], pre[i]);
            if (err == MP_OKAY) {
                err = _sp_mont_red(pre[i], m, mp);
            }
            if (err == MP_OKAY) {
                err = sp_mul(pre[i], a, pre[i]);
            }
            if (err == MP_OKAY) {
                err = _sp_mont_red(pre[i], m, mp);
            }
        }
    }

    if (err == MP_OKAY) {
        _sp_sub_d(m, 2, e);
        for (i = sp_count_bits(e)-1, j = 0; i >= 0; i--, j++) {
              if ((!sp_is_bit_set(e, i)) || (j == CT_INV_MOD_PRE_CNT)) {
                  break;
              }
        }
        err = sp_copy(pre[j-1], t);
        for (j = 0; (err == MP_OKAY) && (i >= 0); i--) {
            int set = sp_is_bit_set(e, i);

            if ((j == CT_INV_MOD_PRE_CNT) || ((!set) && j > 0)) {
                err = sp_mul(t, pre[j-1], t);
                if (err == MP_OKAY) {
                    err = _sp_mont_red(t, m, mp);
                }
                j = 0;
            }
            if (err == MP_OKAY) {
                err = sp_sqr(t, t);
                if (err == MP_OKAY) {
                    err = _sp_mont_red(t, m, mp);
                }
            }
            j += set;
        }
    }
    if (err == MP_OKAY) {
        if (j > 0) {
            err = sp_mul(t, pre[j-1], r);
            if (err == MP_OKAY) {
                err = _sp_mont_red(r, m, mp);
            }
        }
        else {
            err = sp_copy(t, r);
        }
    }

    FREE_SP_INT_ARRAY(pre, NULL);
    return err;
}

#endif /* WOLFSSL_SP_INVMOD_MONT_CT */


/**************************
 * Exponentiation functions
 **************************/

#if (defined(WOLFSSL_SP_MATH_ALL) && !defined(WOLFSSL_RSA_VERIFY_ONLY) && \
    !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || defined(WOLFSSL_HAVE_SP_DH)
/* Internal. Exponentiates b to the power of e modulo m into r: r = b ^ e mod m
 * Process the exponent one bit at a time.
 * Is constant time and can be cache attack resistant.
 *
 * @param  [in]   b     SP integer that is the base.
 * @param  [in]   e     SP integer that is the exponent.
 * @param  [in]   bits  Number of bits in base to use. May be greater than
 *                      count of bits in b.
 * @param  [in]   m     SP integer that is the modulus.
 * @param  [out]  r     SP integer to hold result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
static int _sp_exptmod_ex(sp_int* b, sp_int* e, int bits, sp_int* m, sp_int* r)
{
    int i;
    int err = MP_OKAY;
    int done = 0;
    int j;
    int y;
    int seenTopBit = 0;
#ifdef WC_NO_CACHE_RESISTANT
    DECL_SP_INT_ARRAY(t, 2 * m->used + 1, 2);
#else
    DECL_SP_INT_ARRAY(t, 2 * m->used + 1, 3);
#endif

#ifdef WC_NO_CACHE_RESISTANT
    ALLOC_SP_INT_ARRAY(t, 2 * m->used + 1, 2, err, NULL);
#else
    ALLOC_SP_INT_ARRAY(t, 2 * m->used + 1, 3, err, NULL);
#endif
    if (err == MP_OKAY) {
        sp_init_size(t[0], 2 * m->used + 1);
        sp_init_size(t[1], 2 * m->used + 1);
    #ifndef WC_NO_CACHE_RESISTANT
        sp_init_size(t[2], 2 * m->used + 1);
    #endif

        /* Ensure base is less than exponent. */
        if (_sp_cmp_abs(b, m) != MP_LT) {
            err = sp_mod(b, m, t[0]);
            if ((err == MP_OKAY) && sp_iszero(t[0])) {
                sp_set(r, 0);
                done = 1;
            }
        }
        else {
            err = sp_copy(b, t[0]);
        }
    }

    if ((!done) && (err == MP_OKAY)) {
        /* t[0] is dummy value and t[1] is result */
        err = sp_copy(t[0], t[1]);

        for (i = bits - 1; (err == MP_OKAY) && (i >= 0); i--) {
#ifdef WC_NO_CACHE_RESISTANT
            /* Square real result if seen the top bit. */
            err = sp_sqrmod(t[seenTopBit], m, t[seenTopBit]);
            if (err == MP_OKAY) {
                y = (e->dp[i >> SP_WORD_SHIFT] >> (i & SP_WORD_MASK)) & 1;
                j = y & seenTopBit;
                seenTopBit |= y;
                /* Multiply real result if bit is set and seen the top bit. */
                err = sp_mulmod(t[j], b, m, t[j]);
            }
#else
            /* Square real result if seen the top bit. */
            sp_copy((sp_int*)(((size_t)t[0] & sp_off_on_addr[seenTopBit^1]) +
                              ((size_t)t[1] & sp_off_on_addr[seenTopBit  ])),
                    t[2]);
            err = sp_sqrmod(t[2], m, t[2]);
            sp_copy(t[2],
                    (sp_int*)(((size_t)t[0] & sp_off_on_addr[seenTopBit^1]) +
                              ((size_t)t[1] & sp_off_on_addr[seenTopBit  ])));
            if (err == MP_OKAY) {
                y = (e->dp[i >> SP_WORD_SHIFT] >> (i & SP_WORD_MASK)) & 1;
                j = y & seenTopBit;
                seenTopBit |= y;
                /* Multiply real result if bit is set and seen the top bit. */
                sp_copy((sp_int*)(((size_t)t[0] & sp_off_on_addr[j^1]) +
                                  ((size_t)t[1] & sp_off_on_addr[j  ])),
                        t[2]);
                err = sp_mulmod(t[2], b, m, t[2]);
                sp_copy(t[2],
                        (sp_int*)(((size_t)t[0] & sp_off_on_addr[j^1]) +
                                  ((size_t)t[1] & sp_off_on_addr[j  ])));
            }
#endif
        }
    }
    if ((!done) && (err == MP_OKAY)) {
        err = sp_copy(t[1], r);
    }

    FREE_SP_INT_ARRAY(t, NULL);
    return err;
}
#endif /* (WOLFSSL_SP_MATH_ALL && !WOLFSSL_RSA_VERIFY_ONLY) ||
        * WOLFSSL_HAVE_SP_DH */

#if defined(WOLFSSL_SP_MATH_ALL) && !defined(WOLFSSL_RSA_VERIFY_ONLY) && \
    !defined(WOLFSSL_RSA_PUBLIC_ONLY)
#ifndef WC_NO_HARDEN
#if !defined(WC_NO_CACHE_RESISTANT)
/* Internal. Exponentiates b to the power of e modulo m into r: r = b ^ e mod m
 * Process the exponent one bit at a time with base in montgomery form.
 * Is constant time and cache attack resistant.
 *
 * @param  [in]   b     SP integer that is the base.
 * @param  [in]   e     SP integer that is the exponent.
 * @param  [in]   bits  Number of bits in base to use. May be greater than
 *                      count of bits in b.
 * @param  [in]   m     SP integer that is the modulus.
 * @param  [out]  r     SP integer to hold result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
static int _sp_exptmod_mont_ex(sp_int* b, sp_int* e, int bits, sp_int* m,
                               sp_int* r)
{
    int i;
    int err = MP_OKAY;
    int done = 0;
    int j;
    int y;
    int seenTopBit = 0;
    sp_int_digit mp;
    DECL_SP_INT_ARRAY(t, m->used * 2 + 1, 4);

    ALLOC_SP_INT_ARRAY(t, m->used * 2 + 1, 4, err, NULL);
    if (err == MP_OKAY) {
        sp_init_size(t[0], m->used * 2 + 1);
        sp_init_size(t[1], m->used * 2 + 1);
        sp_init_size(t[2], m->used * 2 + 1);
        sp_init_size(t[3], m->used * 2 + 1);

        /* Ensure base is less than exponent. */
        if (_sp_cmp_abs(b, m) != MP_LT) {
            err = sp_mod(b, m, t[0]);
            if ((err == MP_OKAY) && sp_iszero(t[0])) {
                sp_set(r, 0);
                done = 1;
            }
        }
        else {
            err = sp_copy(b, t[0]);
        }
    }


    if ((!done) && (err == MP_OKAY)) {
        err = sp_mont_setup(m, &mp);
        if (err == MP_OKAY) {
            err = sp_mont_norm(t[1], m);
        }
        if (err == MP_OKAY) {
            /* Convert to montgomery form. */
            err = sp_mulmod(t[0], t[1], m, t[0]);
        }
        if (err == MP_OKAY) {
            /* t[0] is fake working value and t[1] is real working value. */
            sp_copy(t[0], t[1]);
            /* Montgomert form of base to multiply by. */
            sp_copy(t[0], t[2]);
        }

        for (i = bits - 1; (err == MP_OKAY) && (i >= 0); i--) {
            /* Square real working value if seen the top bit. */
            sp_copy((sp_int*)(((size_t)t[0] & sp_off_on_addr[seenTopBit^1]) +
                              ((size_t)t[1] & sp_off_on_addr[seenTopBit  ])),
                    t[3]);
            err = sp_sqr(t[3], t[3]);
            if (err == MP_OKAY) {
                err = _sp_mont_red(t[3], m, mp);
            }
            sp_copy(t[3],
                    (sp_int*)(((size_t)t[0] & sp_off_on_addr[seenTopBit^1]) +
                              ((size_t)t[1] & sp_off_on_addr[seenTopBit  ])));
            if (err == MP_OKAY) {
                y = (e->dp[i >> SP_WORD_SHIFT] >> (i & SP_WORD_MASK)) & 1;
                j = y & seenTopBit;
                seenTopBit |= y;
                /* Multiply real value if bit is set and seen the top bit. */
                sp_copy((sp_int*)(((size_t)t[0] & sp_off_on_addr[j^1]) +
                                  ((size_t)t[1] & sp_off_on_addr[j  ])),
                        t[3]);
                err = sp_mul(t[3], t[2], t[3]);
                if (err == MP_OKAY) {
                    err = _sp_mont_red(t[3], m, mp);
                }
                sp_copy(t[3],
                        (sp_int*)(((size_t)t[0] & sp_off_on_addr[j^1]) +
                                  ((size_t)t[1] & sp_off_on_addr[j  ])));
            }
        }
        if (err == MP_OKAY) {
            /* Convert from montgomery form. */
            err = _sp_mont_red(t[1], m, mp);
            /* Reduction implementation returns number to range < m. */
        }
    }
    if ((!done) && (err == MP_OKAY)) {
        err = sp_copy(t[1], r);
    }

    FREE_SP_INT_ARRAY(t, NULL);
    return err;
}
#else

/* Always allocate large array of sp_ints unless defined WOLFSSL_SP_NO_MALLOC */
#define SP_ALLOC

/* Internal. Exponentiates b to the power of e modulo m into r: r = b ^ e mod m
 * Creates a window of precalculated exponents with base in montgomery form.
 * Is constant time but NOT cache attack resistant.
 *
 * @param  [in]   b     SP integer that is the base.
 * @param  [in]   e     SP integer that is the exponent.
 * @param  [in]   bits  Number of bits in base to use. May be greater than
 *                      count of bits in b.
 * @param  [in]   m     SP integer that is the modulus.
 * @param  [out]  r     SP integer to hold result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
static int _sp_exptmod_mont_ex(sp_int* b, sp_int* e, int bits, sp_int* m,
                               sp_int* r)
{
    int i;
    int j;
    int c;
    int y;
    int winBits;
    int preCnt;
    int err = MP_OKAY;
    int done = 0;
    sp_int_digit mp;
    sp_int_digit n;
    sp_int_digit mask;
    sp_int* tr = NULL;
    DECL_SP_INT_ARRAY(t, m->used * 2 + 1, (1 << 6) + 1);

    if (bits > 450) {
        winBits = 6;
    }
    else if (bits <= 21) {
        winBits = 1;
    }
    else if (bits <= 36) {
        winBits = 3;
    }
    else if (bits <= 140) {
        winBits = 4;
    }
    else {
        winBits = 5;
    }
    preCnt = 1 << winBits;
    mask = preCnt - 1;

    ALLOC_SP_INT_ARRAY(t, m->used * 2 + 1, preCnt + 1, err, NULL);
    if (err == MP_OKAY) {
        tr = t[preCnt];

        for (i = 0; i < preCnt; i++) {
            sp_init_size(t[i], m->used * 2 + 1);
        }
        sp_init_size(tr, m->used * 2 + 1);

        /* Ensure base is less than exponent. */
        if (_sp_cmp_abs(b, m) != MP_LT) {
            err = sp_mod(b, m, t[1]);
            if ((err == MP_OKAY) && sp_iszero(t[1])) {
                sp_set(r, 0);
                done = 1;
            }
        }
        else {
            err = sp_copy(b, t[1]);
        }
    }

    if ((!done) && (err == MP_OKAY)) {
        err = sp_mont_setup(m, &mp);
        if (err == MP_OKAY) {
            /* Norm value is 1 in montgomery form. */
            err = sp_mont_norm(t[0], m);
        }
        if (err == MP_OKAY) {
            /* Convert base to montgomery form. */
            err = sp_mulmod(t[1], t[0], m, t[1]);
        }

        /* Pre-calculate values */
        for (i = 2; (i < preCnt) && (err == MP_OKAY); i++) {
            if ((i & 1) == 0) {
                err = sp_sqr(t[i/2], t[i]);
            }
            else {
                err = sp_mul(t[i-1], t[1], t[i]);
            }
            if (err == MP_OKAY) {
                err = _sp_mont_red(t[i], m, mp);
            }
        }

        if (err == MP_OKAY) {
            /* Bits from the top that - possibly left over. */
            i = (bits - 1) >> SP_WORD_SHIFT;
            n = e->dp[i--];
            c = bits & (SP_WORD_SIZE - 1);
            if (c == 0) {
                c = SP_WORD_SIZE;
            }
            c -= bits % winBits;
            y = (int)(n >> c);
            n <<= SP_WORD_SIZE - c;
            /* Copy window number for top bits. */
            sp_copy(t[y], tr);
            for (; (i >= 0) || (c >= winBits); ) {
                if (c == 0) {
                    /* Bits up to end of digit */
                    n = e->dp[i--];
                    y = (int)(n >> (SP_WORD_SIZE - winBits));
                    n <<= winBits;
                    c = SP_WORD_SIZE - winBits;
                }
                else if (c < winBits) {
                    /* Bits to end of digit and part of next */
                    y = (int)(n >> (SP_WORD_SIZE - winBits));
                    n = e->dp[i--];
                    c = winBits - c;
                    y |= (int)(n >> (SP_WORD_SIZE - c));
                    n <<= c;
                    c = SP_WORD_SIZE - c;
                }
                else {
                    /* Bits from middle of digit */
                    y = (int)((n >> (SP_WORD_SIZE - winBits)) & mask);
                    n <<= winBits;
                    c -= winBits;
                }

                /* Square for number of bits in window. */
                for (j = 0; (j < winBits) && (err == MP_OKAY); j++) {
                    err = sp_sqr(tr, tr);
                    if (err == MP_OKAY) {
                        err = _sp_mont_red(tr, m, mp);
                    }
                }
                /* Multiply by window number for next set of bits. */
                if (err == MP_OKAY) {
                    err = sp_mul(tr, t[y], tr);
                }
                if (err == MP_OKAY) {
                    err = _sp_mont_red(tr, m, mp);
                }
            }
        }

        if (err == MP_OKAY) {
            /* Convert from montgomery form. */
            err = _sp_mont_red(tr, m, mp);
            /* Reduction implementation returns number to range < m. */
        }
    }
    if ((!done) && (err == MP_OKAY)) {
        err = sp_copy(tr, r);
    }

    FREE_SP_INT_ARRAY(t, NULL);
    return err;
}

#undef SP_ALLOC

#endif /* !WC_NO_CACHE_RESISTANT */
#endif /* !WC_NO_HARDEN */

#if SP_WORD_SIZE <= 16
    #define EXP2_WINSIZE    2
#elif SP_WORD_SIZE <= 32
    #define EXP2_WINSIZE    3
#elif SP_WORD_SIZE <= 64
    #define EXP2_WINSIZE    4
#elif SP_WORD_SIZE <= 128
    #define EXP2_WINSIZE    5
#endif

/* Internal. Exponentiates 2 to the power of e modulo m into r: r = 2 ^ e mod m
 * Is constant time and cache attack resistant.
 *
 * @param  [in]   e       SP integer that is the exponent.
 * @param  [in]   digits  Number of digits in base to use. May be greater than
 *                        count of bits in b.
 * @param  [in]   m       SP integer that is the modulus.
 * @param  [out]  r       SP integer to hold result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
static int _sp_exptmod_base_2(sp_int* e, int digits, sp_int* m, sp_int* r)
{
    int i = 0;
    int j;
    int c = 0;
    int y;
    int err = MP_OKAY;
    sp_int* t = NULL;
    sp_int* tr = NULL;
    sp_int_digit mp = 0, n = 0;
    DECL_SP_INT_ARRAY(d, m->used * 2 + 1, 2);

    if (0) {
        sp_print_int(2, "a");
        sp_print(e, "b");
        sp_print(m, "m");
    }

    ALLOC_SP_INT_ARRAY(d, m->used * 2 + 1, 2, err, NULL);
    if (err == MP_OKAY) {
        t  = d[0];
        tr = d[1];

        sp_init_size(t, m->used * 2 + 1);
        sp_init_size(tr, m->used * 2 + 1);

        if (m->used > 1) {
            err = sp_mont_setup(m, &mp);
            if (err == MP_OKAY) {
                /* Norm value is 1 in montgomery form. */
                err = sp_mont_norm(tr, m);
            }
            if (err == MP_OKAY) {
                err = sp_mul_2d(m, 1 << EXP2_WINSIZE, t);
            }
        }
        else {
            err = sp_set(tr, 1);
        }

        if (err == MP_OKAY) {
            /* Bits from the top. */
            i = digits - 1;
            n = e->dp[i--];
            c = SP_WORD_SIZE;
#if (EXP2_WINSIZE != 1) && (EXP2_WINSIZE != 2) && (EXP2_WINSIZE != 4)
            c -= (digits * SP_WORD_SIZE) % EXP2_WINSIZE;
            if (c != SP_WORD_SIZE) {
                y = (int)(n >> c);
                n <<= SP_WORD_SIZE - c;
            }
            else
#endif
            {
                y = 0;
            }

            /* Multiply montgomery representation of 1 by 2 ^ top */
            err = sp_mul_2d(tr, y, tr);
        }
        if ((err == MP_OKAY) && (m->used > 1)) {
            err = sp_add(tr, t, tr);
        }
        if (err == MP_OKAY) {
            err = sp_mod(tr, m, tr);
        }
        if (err == MP_OKAY) {
            for (; (i >= 0) || (c >= EXP2_WINSIZE); ) {
                if (c == 0) {
                    /* Bits up to end of digit */
                    n = e->dp[i--];
                    y = (int)(n >> (SP_WORD_SIZE - EXP2_WINSIZE));
                    n <<= EXP2_WINSIZE;
                    c = SP_WORD_SIZE - EXP2_WINSIZE;
                }
#if (EXP2_WINSIZE != 1) && (EXP2_WINSIZE != 2) && (EXP2_WINSIZE != 4)
                else if (c < EXP2_WINSIZE) {
                    /* Bits to end of digit and part of next */
                    y = (int)(n >> (SP_WORD_SIZE - EXP2_WINSIZE));
                    n = e->dp[i--];
                    c = EXP2_WINSIZE - c;
                    y |= (int)(n >> (SP_WORD_SIZE - c));
                    n <<= c;
                    c = SP_WORD_SIZE - c;
                }
#endif
                else {
                    /* Bits from middle of digit */
                    y = (int)((n >> (SP_WORD_SIZE - EXP2_WINSIZE)) &
                              ((1 << EXP2_WINSIZE) - 1));
                    n <<= EXP2_WINSIZE;
                    c -= EXP2_WINSIZE;
                }

                /* Square for number of bits in window. */
                for (j = 0; (j < EXP2_WINSIZE) && (err == MP_OKAY); j++) {
                    err = sp_sqr(tr, tr);
                    if (err != MP_OKAY) {
                        break;
                    }
                    if (m->used > 1) {
                        err = _sp_mont_red(tr, m, mp);
                    }
                    else {
                        err = sp_mod(tr, m, tr);
                    }
                }

                if (err == MP_OKAY) {
                    /* then multiply by 2^y */
                    err = sp_mul_2d(tr, y, tr);
                }
                if ((err == MP_OKAY) && (m->used > 1)) {
                    /* Add in value to make mod operation take same time */
                    err = sp_add(tr, t, tr);
                }
                if (err == MP_OKAY) {
                    err = sp_mod(tr, m, tr);
                }
                if (err != MP_OKAY) {
                    break;
                }
            }
        }

        if ((err == MP_OKAY) && (m->used > 1)) {
            /* Convert from montgomery form. */
            err = _sp_mont_red(tr, m, mp);
            /* Reduction implementation returns number to range < m. */
        }
    }
    if (err == MP_OKAY) {
        err = sp_copy(tr, r);
    }

    if (0) {
        sp_print(r, "rme");
    }

    FREE_SP_INT_ARRAY(d, NULL);
    return err;
}
#endif /* WOLFSSL_SP_MATH_ALL && !WOLFSSL_RSA_VERIFY_ONLY */

#if (defined(WOLFSSL_SP_MATH_ALL) && !defined(WOLFSSL_RSA_VERIFY_ONLY)) || \
    defined(WOLFSSL_HAVE_SP_DH) || \
    (!defined(NO_RSA) && defined(WOLFSSL_KEY_GEN))
/* Exponentiates b to the power of e modulo m into r: r = b ^ e mod m
 *
 * @param  [in]   b     SP integer that is the base.
 * @param  [in]   e     SP integer that is the exponent.
 * @param  [in]   bits  Number of bits in base to use. May be greater than
 *                      count of bits in b.
 * @param  [in]   m     SP integer that is the modulus.
 * @param  [out]  r     SP integer to hold result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when b, e, m or r is NULL; or m <= 0 or e is negative.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
int sp_exptmod_ex(sp_int* b, sp_int* e, int digits, sp_int* m, sp_int* r)
{
    int err = MP_OKAY;
    int done = 0;
    int mBits = sp_count_bits(m);
    int bBits = sp_count_bits(b);
    int eBits = sp_count_bits(e);

    if ((b == NULL) || (e == NULL) || (m == NULL) || (r == NULL)) {
        err = MP_VAL;
    }

#if 0
    if (err == MP_OKAY) {
        sp_print(b, "a");
        sp_print(e, "b");
        sp_print(m, "m");
    }
#endif

    if (err != MP_OKAY) {
    }
    /* Handle special cases. */
    else if (sp_iszero(m)) {
        err = MP_VAL;
    }
#ifdef WOLFSSL_SP_INT_NEGATIVE
    else if ((e->sign == MP_NEG) || (m->sign == MP_NEG)) {
        err = MP_VAL;
    }
#endif
    else if (sp_isone(m)) {
        sp_set(r, 0);
        done = 1;
    }
    else if (sp_iszero(e)) {
        sp_set(r, 1);
        done = 1;
    }
    else if (sp_iszero(b)) {
        sp_set(r, 0);
        done = 1;
    }
    /* Ensure SP integers have space for intermediate values. */
    else if (m->used * 2 >= r->size) {
        err = MP_VAL;
    }

    if ((!done) && (err == MP_OKAY)) {
        /* Use code optimized for specific sizes if possible */
#if (defined(WOLFSSL_SP_MATH) || defined(WOLFSSL_SP_MATH_ALL)) && \
    (defined(WOLFSSL_HAVE_SP_RSA) || defined(WOLFSSL_HAVE_SP_DH))
    #ifndef WOLFSSL_SP_NO_2048
        if ((mBits == 1024) && sp_isodd(m) && (bBits <= 1024) &&
            (eBits <= 1024)) {
            err = sp_ModExp_1024(b, e, m, r);
            done = 1;
        }
        else if ((mBits == 2048) && sp_isodd(m) && (bBits <= 2048) &&
                 (eBits <= 2048)) {
            err = sp_ModExp_2048(b, e, m, r);
            done = 1;
        }
        else
    #endif
    #ifndef WOLFSSL_SP_NO_3072
        if ((mBits == 1536) && sp_isodd(m) && (bBits <= 1536) &&
            (eBits <= 1536)) {
            err = sp_ModExp_1536(b, e, m, r);
            done = 1;
        }
        else if ((mBits == 3072) && sp_isodd(m) && (bBits <= 3072) &&
                 (eBits <= 3072)) {
            err = sp_ModExp_3072(b, e, m, r);
            done = 1;
        }
        else
    #endif
    #ifdef WOLFSSL_SP_4096
        if ((mBits == 4096) && sp_isodd(m) && (bBits <= 4096) &&
            (eBits <= 4096)) {
            err = sp_ModExp_4096(b, e, m, r);
            done = 1;
        }
        else
    #endif
#endif
        {
        }
    }
#if defined(WOLFSSL_SP_MATH_ALL) || defined(WOLFSSL_HAVE_SP_DH)
#if defined(WOLFSSL_RSA_VERIFY_ONLY) || defined(WOLFSSL_RSA_PUBLIC_ONLY)
    if ((!done) && (err == MP_OKAY))
        err = sp_exptmod_nct(b, e, m, r);
    }
#else
#if defined(WOLFSSL_SP_MATH_ALL)
    if ((!done) && (err == MP_OKAY) && (b->used == 1) && (b->dp[0] == 2) &&
         mp_isodd(m)) {
        /* Use the generic base 2 implementation. */
        err = _sp_exptmod_base_2(e, digits, m, r);
    }
    else if ((!done) && (err == MP_OKAY) && ((m->used > 1) && mp_isodd(m))) {
    #ifndef WC_NO_HARDEN
        err = _sp_exptmod_mont_ex(b, e, digits * SP_WORD_SIZE, m, r);
    #else
        err = sp_exptmod_nct(b, e, m, r);
    #endif
    }
    else
#endif /* WOLFSSL_SP_MATH_ALL */
    if ((!done) && (err == MP_OKAY)) {
        /* Otherwise use the generic implementation. */
        err = _sp_exptmod_ex(b, e, digits * SP_WORD_SIZE, m, r);
    }
#endif /* WOLFSSL_RSA_VERIFY_ONLY || WOLFSSL_RSA_PUBLIC_ONLY */
#else
    if ((!done) && (err == MP_OKAY)) {
        err = MP_VAL;
    }
#endif /* WOLFSSL_SP_MATH_ALL || WOLFSSL_HAVE_SP_DH */

    (void)mBits;
    (void)bBits;
    (void)eBits;
    (void)digits;

#if 0
    if (err == MP_OKAY) {
        sp_print(r, "rme");
    }
#endif
    return err;
}
#endif /* WOLFSSL_SP_MATH_ALL || WOLFSSL_HAVE_SP_DH */

#if (defined(WOLFSSL_SP_MATH_ALL) && !defined(WOLFSSL_RSA_VERIFY_ONLY)) || \
    defined(WOLFSSL_HAVE_SP_DH) || \
    (!defined(NO_RSA) && defined(WOLFSSL_KEY_GEN))
/* Exponentiates b to the power of e modulo m into r: r = b ^ e mod m
 *
 * @param  [in]   b  SP integer that is the base.
 * @param  [in]   e  SP integer that is the exponent.
 * @param  [in]   m  SP integer that is the modulus.
 * @param  [out]  r  SP integer to hold result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when b, e, m or r is NULL; or m <= 0 or e is negative.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
int sp_exptmod(sp_int* b, sp_int* e, sp_int* m, sp_int* r)
{
    int err = MP_OKAY;

    if ((b == NULL) || (e == NULL) || (m == NULL) || (r == NULL)) {
        err = MP_VAL;
    }
    SAVE_VECTOR_REGISTERS(err = _svr_ret;);
    if (err == MP_OKAY) {
        err = sp_exptmod_ex(b, e, e->used, m, r);
    }
    RESTORE_VECTOR_REGISTERS();
    return err;
}
#endif /* (WOLFSSL_SP_MATH_ALL && !WOLFSSL_RSA_VERIFY_ONLY) ||
        * WOLFSSL_HAVE_SP_DH */

#if defined(WOLFSSL_SP_MATH_ALL) || defined(WOLFSSL_HAVE_SP_DH)
#if defined(WOLFSSL_SP_FAST_NCT_EXPTMOD) || !defined(WOLFSSL_SP_SMALL)

/* Always allocate large array of sp_ints unless defined WOLFSSL_SP_NO_MALLOC */
#define SP_ALLOC

/* Internal. Exponentiates b to the power of e modulo m into r: r = b ^ e mod m
 * Creates a window of precalculated exponents with base in montgomery form.
 * Sliding window and is NOT constant time.
 *
 * @param  [in]   b     SP integer that is the base.
 * @param  [in]   e     SP integer that is the exponent.
 * @param  [in]   bits  Number of bits in base to use. May be greater than
 *                      count of bits in b.
 * @param  [in]   m     SP integer that is the modulus.
 * @param  [out]  r     SP integer to hold result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
static int _sp_exptmod_nct(sp_int* b, sp_int* e, sp_int* m, sp_int* r)
{
    int i = 0;
    int j = 0;
    int c = 0;
    int y = 0;
    int bits;
    int winBits;
    int preCnt;
    int err = MP_OKAY;
    int done = 0;
    sp_int* tr = NULL;
    sp_int* bm = NULL;
    sp_int_digit mask;
    /* Maximum winBits is 6 and preCnt is (1 << (winBits - 1)). */
    DECL_SP_INT_ARRAY(t, m->used * 2 + 1, (1 << 5) + 2);

    bits = sp_count_bits(e);

    if (bits > 450) {
        winBits = 6;
    }
    else if (bits <= 21) {
        winBits = 1;
    }
    else if (bits <= 36) {
        winBits = 3;
    }
    else if (bits <= 140) {
        winBits = 4;
    }
    else {
        winBits = 5;
    }
    preCnt = 1 << (winBits - 1);
    mask = preCnt - 1;

    ALLOC_SP_INT_ARRAY(t, m->used * 2 + 1, preCnt + 2, err, NULL);
    if (err == MP_OKAY) {
        /* Initialize window numbers and temporary result. */
        tr = t[preCnt + 0];
        bm = t[preCnt + 1];

        for (i = 0; i < preCnt; i++) {
            sp_init_size(t[i], m->used * 2 + 1);
        }
        sp_init_size(tr, m->used * 2 + 1);
        sp_init_size(bm, m->used * 2 + 1);

        /* Ensure base is less than exponent. */
        if (_sp_cmp_abs(b, m) != MP_LT) {
            err = sp_mod(b, m, bm);
            if ((err == MP_OKAY) && sp_iszero(bm)) {
                sp_set(r, 0);
                done = 1;
            }
        }
        else {
            err = sp_copy(b, bm);
        }
    }

    if ((!done) && (err == MP_OKAY)) {
        sp_int_digit mp;
        sp_int_digit n;

        err = sp_mont_setup(m, &mp);
        if (err == MP_OKAY) {
            err = sp_mont_norm(t[0], m);
        }
        if (err == MP_OKAY) {
            err = sp_mulmod(bm, t[0], m, bm);
        }
        if (err == MP_OKAY) {
            err = sp_copy(bm, t[0]);
        }
        for (i = 1; (i < winBits) && (err == MP_OKAY); i++) {
            err = sp_sqr(t[0], t[0]);
            if (err == MP_OKAY) {
                err = _sp_mont_red(t[0], m, mp);
            }
        }
        for (i = 1; (i < preCnt) && (err == MP_OKAY); i++) {
            err = sp_mul(t[i-1], bm, t[i]);
            if (err == MP_OKAY) {
                err = _sp_mont_red(t[i], m, mp);
            }
        }

        if (err == MP_OKAY) {
            /* Find the top bit. */
            i = (bits - 1) >> SP_WORD_SHIFT;
            n = e->dp[i--];
            c = bits % SP_WORD_SIZE;
            if (c == 0) {
                c = SP_WORD_SIZE;
            }
            /* Put top bit at highest offset in digit. */
            n <<= SP_WORD_SIZE - c;

            if (bits >= winBits) {
                /* Top bit set. Copy from window. */
                if (c < winBits) {
                    /* Bits to end of digit and part of next */
                    y = (int)((n >> (SP_WORD_SIZE - winBits)) & mask);
                    n = e->dp[i--];
                    c = winBits - c;
                    y |= (int)(n >> (SP_WORD_SIZE - c));
                    n <<= c;
                    c = SP_WORD_SIZE - c;
                }
                else {
                    /* Bits from middle of digit */
                    y = (int)((n >> (SP_WORD_SIZE - winBits)) & mask);
                    n <<= winBits;
                    c -= winBits;
                }
                err = sp_copy(t[y], tr);
            }
            else {
                /* 1 in Montgomery form. */
                err = sp_mont_norm(tr, m);
            }
            while (err == MP_OKAY) {
                /* Sqaure until we find bit that is 1 or there's less than a
                 * window of bits left.
                 */
                while (err == MP_OKAY && ((i >= 0) || (c >= winBits))) {
                    sp_digit n2 = n;
                    int c2 = c;
                    int i2 = i;

                    /* Make sure n2 has bits from the right digit. */
                    if (c2 == 0) {
                        n2 = e->dp[i2--];
                        c2 = SP_WORD_SIZE;
                    }
                    /* Mask off the next bit. */
                    y = (int)((n2 >> (SP_WORD_SIZE - 1)) & 1);
                    if (y == 1) {
                        break;
                    }

                    /* Square and update position. */
                    err = sp_sqr(tr, tr);
                    if (err == MP_OKAY) {
                        err = _sp_mont_red(tr, m, mp);
                    }
                    n = n2 << 1;
                    c = c2 - 1;
                    i = i2;
                }

                if (err == MP_OKAY) {
                    /* Check we have enough bits left for a window. */
                    if ((i < 0) && (c < winBits)) {
                        break;
                    }

                    if (c == 0) {
                        /* Bits up to end of digit */
                        n = e->dp[i--];
                        y = (int)(n >> (SP_WORD_SIZE - winBits));
                        n <<= winBits;
                        c = SP_WORD_SIZE - winBits;
                    }
                    else if (c < winBits) {
                        /* Bits to end of digit and part of next */
                        y = (int)(n >> (SP_WORD_SIZE - winBits));
                        n = e->dp[i--];
                        c = winBits - c;
                        y |= (int)(n >> (SP_WORD_SIZE - c));
                        n <<= c;
                        c = SP_WORD_SIZE - c;
                    }
                    else {
                        /* Bits from middle of digit */
                        y = (int)(n >> (SP_WORD_SIZE - winBits));
                        n <<= winBits;
                        c -= winBits;
                    }
                    y &= mask;
                }

                /* Square for number of bits in window. */
                for (j = 0; (j < winBits) && (err == MP_OKAY); j++) {
                    err = sp_sqr(tr, tr);
                    if (err == MP_OKAY) {
                        err = _sp_mont_red(tr, m, mp);
                    }
                }
                /* Multiply by window number for next set of bits. */
                if (err == MP_OKAY) {
                    err = sp_mul(tr, t[y], tr);
                }
                if (err == MP_OKAY) {
                    err = _sp_mont_red(tr, m, mp);
                }
            }
            if ((err == MP_OKAY) && (c > 0)) {
                /* Handle remaining bits.
                 * Window values have top bit set and can't be used. */
                n = e->dp[0];
                for (--c; (err == MP_OKAY) && (c >= 0); c--) {
                    err = sp_sqr(tr, tr);
                    if (err == MP_OKAY) {
                        err = _sp_mont_red(tr, m, mp);
                    }
                    if ((err == MP_OKAY) && ((n >> c) & 1)) {
                        err = sp_mul(tr, bm, tr);
                        if (err == MP_OKAY) {
                            err = _sp_mont_red(tr, m, mp);
                        }
                    }
                }
            }
        }

        if (err == MP_OKAY) {
            /* Convert from montgomery form. */
            err = _sp_mont_red(tr, m, mp);
            /* Reduction implementation returns number to range < m. */
        }
    }
    if ((!done) && (err == MP_OKAY)) {
        err = sp_copy(tr, r);
    }

    FREE_SP_INT_ARRAY(t, NULL);
    return err;
}

#undef SP_ALLOC

#else
/* Exponentiates b to the power of e modulo m into r: r = b ^ e mod m
 * Non-constant time implementation.
 *
 * @param  [in]   b  SP integer that is the base.
 * @param  [in]   e  SP integer that is the exponent.
 * @param  [in]   m  SP integer that is the modulus.
 * @param  [out]  r  SP integer to hold result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when b, e, m or r is NULL; or m <= 0 or e is negative.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
static int _sp_exptmod_nct(sp_int* b, sp_int* e, sp_int* m, sp_int* r)
{
    int i;
    int err = MP_OKAY;
    int done = 0;
    int y = 0;
    int bits = sp_count_bits(e);
    sp_int_digit mp;
    DECL_SP_INT_ARRAY(t, m->used * 2 + 1, 2);

    ALLOC_SP_INT_ARRAY(t, m->used * 2 + 1, 2, err, NULL);
    if (err == MP_OKAY) {
        sp_init_size(t[0], m->used * 2 + 1);
        sp_init_size(t[1], m->used * 2 + 1);

        /* Ensure base is less than exponent. */
        if (_sp_cmp_abs(b, m) != MP_LT) {
            err = sp_mod(b, m, t[0]);
            if ((err == MP_OKAY) && sp_iszero(t[0])) {
                sp_set(r, 0);
                done = 1;
            }
        }
        else {
            err = sp_copy(b, t[0]);
        }
    }

    if ((!done) && (err == MP_OKAY)) {
        err = sp_mont_setup(m, &mp);
        if (err == MP_OKAY) {
            err = sp_mont_norm(t[1], m);
        }
        if (err == MP_OKAY) {
            /* Convert to montgomery form. */
            err = sp_mulmod(t[0], t[1], m, t[0]);
        }
        if (err == MP_OKAY) {
            /* Montgomert form of base to multiply by. */
            sp_copy(t[0], t[1]);
        }

        for (i = bits - 2; (err == MP_OKAY) && (i >= 0); i--) {
            err = sp_sqr(t[0], t[0]);
            if (err == MP_OKAY) {
                err = _sp_mont_red(t[0], m, mp);
            }
            if (err == MP_OKAY) {
                y = (e->dp[i >> SP_WORD_SHIFT] >> (i & SP_WORD_MASK)) & 1;
                if (y != 0) {
                    err = sp_mul(t[0], t[1], t[0]);
                    if (err == MP_OKAY) {
                        err = _sp_mont_red(t[0], m, mp);
                    }
                }
            }
        }
        if (err == MP_OKAY) {
            /* Convert from montgomery form. */
            err = _sp_mont_red(t[0], m, mp);
            /* Reduction implementation returns number to range < m. */
        }
    }
    if ((!done) && (err == MP_OKAY)) {
        err = sp_copy(t[0], r);
    }

    FREE_SP_INT_ARRAY(t, NULL);
    return err;
}
#endif /* WOLFSSL_SP_FAST_NCT_EXPTMOD || !WOLFSSL_SP_SMALL */

/* Exponentiates b to the power of e modulo m into r: r = b ^ e mod m
 * Non-constant time implementation.
 *
 * @param  [in]   b  SP integer that is the base.
 * @param  [in]   e  SP integer that is the exponent.
 * @param  [in]   m  SP integer that is the modulus.
 * @param  [out]  r  SP integer to hold result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when b, e, m or r is NULL; or m <= 0 or e is negative.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
int sp_exptmod_nct(sp_int* b, sp_int* e, sp_int* m, sp_int* r)
{
    int err = MP_OKAY;

    if ((b == NULL) || (e == NULL) || (m == NULL) || (r == NULL)) {
        err = MP_VAL;
    }

#if 0
    if (err == MP_OKAY) {
        sp_print(b, "a");
        sp_print(e, "b");
        sp_print(m, "m");
    }
#endif

    if (err != MP_OKAY) {
    }
    /* Handle special cases. */
    else if (sp_iszero(m)) {
        err = MP_VAL;
    }
#ifdef WOLFSSL_SP_INT_NEGATIVE
    else if ((e->sign == MP_NEG) || (m->sign == MP_NEG)) {
        err = MP_VAL;
    }
#endif
    else if (sp_isone(m)) {
        sp_set(r, 0);
    }
    else if (sp_iszero(e)) {
        sp_set(r, 1);
    }
    else if (sp_iszero(b)) {
        sp_set(r, 0);
    }
    /* Ensure SP integers have space for intermediate values. */
    else if (m->used * 2 >= r->size) {
        err = MP_VAL;
    }
#if !defined(WOLFSSL_RSA_VERIFY_ONLY) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)
    else if (mp_iseven(m)) {
        err = _sp_exptmod_ex(b, e, e->used * SP_WORD_SIZE, m, r);
    }
#endif
    else {
        err = _sp_exptmod_nct(b, e, m, r);
    }

#if 0
    if (err == MP_OKAY) {
        sp_print(r, "rme");
    }
#endif

    return err;
}
#endif /* WOLFSSL_SP_MATH_ALL || WOLFSSL_HAVE_SP_DH */

/***************
 * 2^e functions
 ***************/

#if defined(WOLFSSL_SP_MATH_ALL) && !defined(WOLFSSL_RSA_VERIFY_ONLY)
/* Divide by 2^e: r = a >> e and rem = bits shifted out
 *
 * @param  [in]   a    SP integer to divide.
 * @param  [in]   e    Exponent bits (dividing by 2^e).
 * @param  [in]   m    SP integer that is the modulus.
 * @param  [out]  r    SP integer to hold result.
 * @param  [out]  rem  SP integer to hold remainder.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a is NULL.
 */
int sp_div_2d(sp_int* a, int e, sp_int* r, sp_int* rem)
{
    int err = MP_OKAY;

    if (a == NULL) {
        err = MP_VAL;
    }

    if (err == MP_OKAY) {
        int remBits = sp_count_bits(a) - e;

        if (remBits <= 0) {
            /* Shifting down by more bits than in number. */
            _sp_zero(r);
            sp_copy(a, rem);
        }
        else {
            if (rem != NULL) {
                /* Copy a in to remainder. */
                err = sp_copy(a, rem);
            }
            /* Shift a down by into result. */
            sp_rshb(a, e, r);
            if (rem != NULL) {
                /* Set used and mask off top digit of remainder. */
                rem->used = (e + SP_WORD_SIZE - 1) >> SP_WORD_SHIFT;
                e &= SP_WORD_MASK;
                if (e > 0) {
                    rem->dp[rem->used - 1] &= ((sp_int_digit)1 << e) - 1;
                }
                sp_clamp(rem);
            #ifdef WOLFSSL_SP_INT_NEGATIVE
                rem->sign = MP_ZPOS;
            #endif
            }
        }
    }

    return err;
}
#endif /* WOLFSSL_SP_MATH_ALL && !WOLFSSL_RSA_VERIFY_ONLY */

#if defined(WOLFSSL_SP_MATH_ALL) && !defined(WOLFSSL_RSA_VERIFY_ONLY)
/* The bottom e bits: r = a & ((1 << e) - 1)
 *
 * @param  [in]   a  SP integer to reduce.
 * @param  [in]   e  Modulus bits (modulus equals 2^e).
 * @param  [out]  r  SP integer to hold result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a or r is NULL.
 */
int sp_mod_2d(sp_int* a, int e, sp_int* r)
{
    int err = MP_OKAY;

    if ((a == NULL) || (r == NULL)) {
        err = MP_VAL;
    }

    if (err == MP_OKAY) {
        int digits = (e + SP_WORD_SIZE - 1) >> SP_WORD_SHIFT;
        if (a != r) {
            XMEMCPY(r->dp, a->dp, digits * sizeof(sp_int_digit));
            r->used = a->used;
        }
    #ifndef WOLFSSL_SP_INT_NEGATIVE
        if (digits <= a->used)
    #else
        if ((a->sign != MP_ZPOS) || (digits <= a->used))
    #endif
        {
        #ifdef WOLFSSL_SP_INT_NEGATIVE
            if (a->sign == MP_NEG) {
                int i;
                sp_int_digit carry = 0;

                /* Negate value. */
                for (i = 0; i < r->used; i++) {
                    sp_int_digit next = r->dp[i] > 0;
                    r->dp[i] = (sp_int_digit)0 - r->dp[i] - carry;
                    carry |= next;
                }
                for (; i < digits; i++) {
                    r->dp[i] = (sp_int_digit)0 - carry;
                }
                r->sign = MP_ZPOS;
            }
        #endif
            /* Set used and mask off top digit of result. */
            r->used = digits;
            e &= SP_WORD_MASK;
            if (e > 0) {
                r->dp[r->used - 1] &= ((sp_int_digit)1 << e) - 1;
            }
            sp_clamp(r);
        }
    }

    return err;
}
#endif /* WOLFSSL_SP_MATH_ALL && !WOLFSSL_RSA_VERIFY_ONLY */

#if defined(WOLFSSL_SP_MATH_ALL) && !defined(WOLFSSL_RSA_VERIFY_ONLY)
/* Multiply by 2^e: r = a << e
 *
 * @param  [in]   a  SP integer to multiply.
 * @param  [in]   e  Multiplier bits (multiplier equals 2^e).
 * @param  [out]  r  SP integer to hold result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a or r is NULL, or result is too big for fixed data
 *          length.
 */
int sp_mul_2d(sp_int* a, int e, sp_int* r)
{
    int err = MP_OKAY;

    if ((a == NULL) || (r == NULL)) {
        err = MP_VAL;
    }

    if ((err == MP_OKAY) && (sp_count_bits(a) + e > r->size * SP_WORD_SIZE)) {
        err = MP_VAL;
    }

    if (err == MP_OKAY) {
        /* Copy a into r as left shift function works on the number. */
        if (a != r) {
            err = sp_copy(a, r);
        }
    }

    if (err == MP_OKAY) {
        if (0) {
            sp_print(a, "a");
            sp_print_int(e, "n");
        }
        err = sp_lshb(r, e);
        if (0) {
            sp_print(r, "rsl");
        }
    }

    return err;
}
#endif /* WOLFSSL_SP_MATH_ALL && !WOLFSSL_RSA_VERIFY_ONLY */

#if defined(WOLFSSL_SP_MATH_ALL) || defined(WOLFSSL_HAVE_SP_DH) || \
    defined(HAVE_ECC) || (!defined(NO_RSA) && !defined(WOLFSSL_RSA_VERIFY_ONLY))

/* START SP_SQR implementations */
/* This code is generated.
 * To generate:
 *   cd scripts/sp/sp_int
 *   ./gen.sh
 * File sp_sqr.c contains code.
 */

#if !defined(WOLFSSL_SP_MATH) || !defined(WOLFSSL_SP_SMALL)
#ifdef SQR_MUL_ASM
/* Square a and store in r. r = a * a
 *
 * @param  [in]   a  SP integer to square.
 * @param  [out]  r  SP integer result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
static int _sp_sqr(sp_int* a, sp_int* r)
{
    int err = MP_OKAY;
    int i;
    int j;
    int k;
#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_SP_NO_MALLOC)
    sp_int_digit* t = NULL;
#elif defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L) && \
    defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SP_NO_DYN_STACK)
    sp_int_digit t[a->used * 2];
#else
    sp_int_digit t[SP_INT_DIGITS];
#endif

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_SP_NO_MALLOC)
    t = (sp_int_digit*)XMALLOC(sizeof(sp_int_digit) * (a->used * 2), NULL,
        DYNAMIC_TYPE_BIGINT);
    if (t == NULL) {
        err = MP_MEM;
    }
#endif
    if ((err == MP_OKAY) && (a->used <= 1)) {
        sp_int_digit l, h;

        h = 0;
        l = 0;
        SP_ASM_SQR(h, l, a->dp[0]);
        t[0] = h;
        t[1] = l;
    }
    else if (err == MP_OKAY) {
        sp_int_digit l, h, o;

        h = 0;
        l = 0;
        SP_ASM_SQR(h, l, a->dp[0]);
        t[0] = h;
        h = 0;
        o = 0;
        for (k = 1; k < (a->used + 1) / 2; k++) {
            i = k;
            j = k - 1;
            for (; (j >= 0); i++, j--) {
                SP_ASM_MUL_ADD2(l, h, o, a->dp[i], a->dp[j]);
            }
            t[k * 2 - 1] = l;
            l = h;
            h = o;
            o = 0;

            SP_ASM_SQR_ADD(l, h, o, a->dp[k]);
            i = k + 1;
            j = k - 1;
            for (; (j >= 0); i++, j--) {
                SP_ASM_MUL_ADD2(l, h, o, a->dp[i], a->dp[j]);
            }
            t[k * 2] = l;
            l = h;
            h = o;
            o = 0;
        }
        for (; k < a->used; k++) {
            i = k;
            j = k - 1;
            for (; (i < a->used); i++, j--) {
                SP_ASM_MUL_ADD2(l, h, o, a->dp[i], a->dp[j]);
            }
            t[k * 2 - 1] = l;
            l = h;
            h = o;
            o = 0;

            SP_ASM_SQR_ADD(l, h, o, a->dp[k]);
            i = k + 1;
            j = k - 1;
            for (; (i < a->used); i++, j--) {
                SP_ASM_MUL_ADD2(l, h, o, a->dp[i], a->dp[j]);
            }
            t[k * 2] = l;
            l = h;
            h = o;
            o = 0;
        }
        t[k * 2 - 1] = l;
    }

    if (err == MP_OKAY) {
        r->used = a->used * 2;
        XMEMCPY(r->dp, t, r->used * sizeof(sp_int_digit));
        sp_clamp(r);
    }

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (t != NULL) {
        XFREE(t, NULL, DYNAMIC_TYPE_BIGINT);
    }
#endif
    return err;
}
#else /* !SQR_MUL_ASM */
/* Square a and store in r. r = a * a
 *
 * @param  [in]   a  SP integer to square.
 * @param  [out]  r  SP integer result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
static int _sp_sqr(sp_int* a, sp_int* r)
{
    int err = MP_OKAY;
    int i;
    int j;
    int k;
#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_SP_NO_MALLOC)
    sp_int_digit* t = NULL;
#elif defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L) && \
    defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SP_NO_DYN_STACK)
    sp_int_digit t[a->used * 2];
#else
    sp_int_digit t[SP_INT_DIGITS];
#endif

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_SP_NO_MALLOC)
    t = (sp_int_digit*)XMALLOC(sizeof(sp_int_digit) * (a->used * 2), NULL,
        DYNAMIC_TYPE_BIGINT);
    if (t == NULL) {
        err = MP_MEM;
    }
#endif
    if (err == MP_OKAY) {
        sp_int_word w;
        sp_int_word l;
        sp_int_word h;
    #ifdef SP_WORD_OVERFLOW
        sp_int_word o;
    #endif

        w = (sp_int_word)a->dp[0] * a->dp[0];
        t[0] = (sp_int_digit)w;
        l = (sp_int_digit)(w >> SP_WORD_SIZE);
        h = 0;
    #ifdef SP_WORD_OVERFLOW
        o = 0;
    #endif
        for (k = 1; k <= (a->used - 1) * 2; k++) {
            i = k / 2;
            j = k - i;
            if (i == j) {
                w = (sp_int_word)a->dp[i] * a->dp[j];
                l += (sp_int_digit)w;
                h += (sp_int_digit)(w >> SP_WORD_SIZE);
            #ifdef SP_WORD_OVERFLOW
                h += (sp_int_digit)(l >> SP_WORD_SIZE);
                l &= SP_MASK;
                o += (sp_int_digit)(h >> SP_WORD_SIZE);
                h &= SP_MASK;
            #endif
            }
            for (++i, --j; (i < a->used) && (j >= 0); i++, j--) {
                w = (sp_int_word)a->dp[i] * a->dp[j];
                l += (sp_int_digit)w;
                h += (sp_int_digit)(w >> SP_WORD_SIZE);
            #ifdef SP_WORD_OVERFLOW
                h += (sp_int_digit)(l >> SP_WORD_SIZE);
                l &= SP_MASK;
                o += (sp_int_digit)(h >> SP_WORD_SIZE);
                h &= SP_MASK;
            #endif
                l += (sp_int_digit)w;
                h += (sp_int_digit)(w >> SP_WORD_SIZE);
            #ifdef SP_WORD_OVERFLOW
                h += (sp_int_digit)(l >> SP_WORD_SIZE);
                l &= SP_MASK;
                o += (sp_int_digit)(h >> SP_WORD_SIZE);
                h &= SP_MASK;
            #endif
            }
            t[k] = (sp_int_digit)l;
            l >>= SP_WORD_SIZE;
            l += (sp_int_digit)h;
            h >>= SP_WORD_SIZE;
        #ifdef SP_WORD_OVERFLOW
            h += o & SP_MASK;
            o >>= SP_WORD_SIZE;
        #endif
        }
        t[k] = (sp_int_digit)l;
        r->used = k + 1;
        XMEMCPY(r->dp, t, r->used * sizeof(sp_int_digit));
        sp_clamp(r);
    }

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (t != NULL) {
        XFREE(t, NULL, DYNAMIC_TYPE_BIGINT);
    }
#endif
    return err;
}
#endif /* SQR_MUL_ASM */
#endif /* !WOLFSSL_SP_MATH || !WOLFSSL_SP_SMALL */

#ifndef WOLFSSL_SP_SMALL
#if !defined(WOLFSSL_HAVE_SP_ECC) && defined(HAVE_ECC)
#if SP_WORD_SIZE == 64
#ifndef SQR_MUL_ASM
/* Square a and store in r. r = a * a
 *
 * Long-hand implementation.
 *
 * @param  [in]   a  SP integer to square.
 * @param  [out]  r  SP integer result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
static int _sp_sqr_4(sp_int* a, sp_int* r)
{
    int err = MP_OKAY;
#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_SP_NO_MALLOC)
    sp_int_word* w = NULL;
#else
    sp_int_word w[10];
#endif
    sp_int_digit* da = a->dp;

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_SP_NO_MALLOC)
    w = (sp_int_word*)XMALLOC(sizeof(sp_int_word) * 10, NULL,
        DYNAMIC_TYPE_BIGINT);
    if (w == NULL) {
        err = MP_MEM;
    }
#endif


    if (err == MP_OKAY) {
        w[0] = (sp_int_word)da[0] * da[0];
        w[1] = (sp_int_word)da[0] * da[1];
        w[2] = (sp_int_word)da[0] * da[2];
        w[3] = (sp_int_word)da[1] * da[1];
        w[4] = (sp_int_word)da[0] * da[3];
        w[5] = (sp_int_word)da[1] * da[2];
        w[6] = (sp_int_word)da[1] * da[3];
        w[7] = (sp_int_word)da[2] * da[2];
        w[8] = (sp_int_word)da[2] * da[3];
        w[9] = (sp_int_word)da[3] * da[3];

        r->dp[0] = w[0];
        w[0] >>= SP_WORD_SIZE;
        w[0] += (sp_int_digit)w[1];
        w[0] += (sp_int_digit)w[1];
        r->dp[1] = w[0];
        w[0] >>= SP_WORD_SIZE;
        w[1] >>= SP_WORD_SIZE;
        w[0] += (sp_int_digit)w[1];
        w[0] += (sp_int_digit)w[1];
        w[0] += (sp_int_digit)w[2];
        w[0] += (sp_int_digit)w[2];
        w[0] += (sp_int_digit)w[3];
        r->dp[2] = w[0];
        w[0] >>= SP_WORD_SIZE;
        w[2] >>= SP_WORD_SIZE;
        w[0] += (sp_int_digit)w[2];
        w[0] += (sp_int_digit)w[2];
        w[3] >>= SP_WORD_SIZE;
        w[0] += (sp_int_digit)w[3];
        w[0] += (sp_int_digit)w[4];
        w[0] += (sp_int_digit)w[4];
        w[0] += (sp_int_digit)w[5];
        w[0] += (sp_int_digit)w[5];
        r->dp[3] = w[0];
        w[0] >>= SP_WORD_SIZE;
        w[4] >>= SP_WORD_SIZE;
        w[0] += (sp_int_digit)w[4];
        w[0] += (sp_int_digit)w[4];
        w[5] >>= SP_WORD_SIZE;
        w[0] += (sp_int_digit)w[5];
        w[0] += (sp_int_digit)w[5];
        w[0] += (sp_int_digit)w[6];
        w[0] += (sp_int_digit)w[6];
        w[0] += (sp_int_digit)w[7];
        r->dp[4] = w[0];
        w[0] >>= SP_WORD_SIZE;
        w[6] >>= SP_WORD_SIZE;
        w[0] += (sp_int_digit)w[6];
        w[0] += (sp_int_digit)w[6];
        w[7] >>= SP_WORD_SIZE;
        w[0] += (sp_int_digit)w[7];
        w[0] += (sp_int_digit)w[8];
        w[0] += (sp_int_digit)w[8];
        r->dp[5] = w[0];
        w[0] >>= SP_WORD_SIZE;
        w[8] >>= SP_WORD_SIZE;
        w[0] += (sp_int_digit)w[8];
        w[0] += (sp_int_digit)w[8];
        w[0] += (sp_int_digit)w[9];
        r->dp[6] = w[0];
        w[0] >>= SP_WORD_SIZE;
        w[9] >>= SP_WORD_SIZE;
        w[0] += (sp_int_digit)w[9];
        r->dp[7] = w[0];

        r->used = 8;
        sp_clamp(r);
    }

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (w != NULL) {
        XFREE(w, NULL, DYNAMIC_TYPE_BIGINT);
    }
#endif
    return err;
}
#else /* SQR_MUL_ASM */
/* Square a and store in r. r = a * a
 *
 * Comba implementation.
 *
 * @param  [in]   a  SP integer to square.
 * @param  [out]  r  SP integer result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
static int _sp_sqr_4(sp_int* a, sp_int* r)
{
    sp_int_digit l = 0;
    sp_int_digit h = 0;
    sp_int_digit o = 0;
    sp_int_digit t[4];

    SP_ASM_SQR(h, l, a->dp[0]);
    t[0] = h;
    h = 0;
    SP_ASM_MUL_ADD2_NO(l, h, o, a->dp[0], a->dp[1]);
    t[1] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD2_NO(l, h, o, a->dp[0], a->dp[2]);
    SP_ASM_SQR_ADD(l, h, o, a->dp[1]);
    t[2] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD2(l, h, o, a->dp[0], a->dp[3]);
    SP_ASM_MUL_ADD2(l, h, o, a->dp[1], a->dp[2]);
    t[3] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD2(l, h, o, a->dp[1], a->dp[3]);
    SP_ASM_SQR_ADD(l, h, o, a->dp[2]);
    r->dp[4] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD2(l, h, o, a->dp[2], a->dp[3]);
    r->dp[5] = l;
    l = h;
    h = o;
    SP_ASM_SQR_ADD_NO(l, h, a->dp[3]);
    r->dp[6] = l;
    r->dp[7] = h;
    XMEMCPY(r->dp, t, 4 * sizeof(sp_int_digit));
    r->used = 8;
    sp_clamp(r);

    return MP_OKAY;
}
#endif /* SQR_MUL_ASM */
#endif /* SP_WORD_SIZE == 64 */
#if SP_WORD_SIZE == 64
#ifdef SQR_MUL_ASM
/* Square a and store in r. r = a * a
 *
 * Comba implementation.
 *
 * @param  [in]   a  SP integer to square.
 * @param  [out]  r  SP integer result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
static int _sp_sqr_6(sp_int* a, sp_int* r)
{
    sp_int_digit l = 0;
    sp_int_digit h = 0;
    sp_int_digit o = 0;
    sp_int_digit tl = 0;
    sp_int_digit th = 0;
    sp_int_digit to;
    sp_int_digit t[6];

#if defined(WOLFSSL_SP_ARM_THUMB) && SP_WORD_SIZE == 32
    to = 0;
#endif

    SP_ASM_SQR(h, l, a->dp[0]);
    t[0] = h;
    h = 0;
    SP_ASM_MUL_ADD2_NO(l, h, o, a->dp[0], a->dp[1]);
    t[1] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD2_NO(l, h, o, a->dp[0], a->dp[2]);
    SP_ASM_SQR_ADD(l, h, o, a->dp[1]);
    t[2] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD2(l, h, o, a->dp[0], a->dp[3]);
    SP_ASM_MUL_ADD2(l, h, o, a->dp[1], a->dp[2]);
    t[3] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD2(l, h, o, a->dp[0], a->dp[4]);
    SP_ASM_MUL_ADD2(l, h, o, a->dp[1], a->dp[3]);
    SP_ASM_SQR_ADD(l, h, o, a->dp[2]);
    t[4] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_SET(tl, th, to, a->dp[0], a->dp[5]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[1], a->dp[4]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[3]);
    SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
    t[5] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD2(l, h, o, a->dp[1], a->dp[5]);
    SP_ASM_MUL_ADD2(l, h, o, a->dp[2], a->dp[4]);
    SP_ASM_SQR_ADD(l, h, o, a->dp[3]);
    r->dp[6] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD2(l, h, o, a->dp[2], a->dp[5]);
    SP_ASM_MUL_ADD2(l, h, o, a->dp[3], a->dp[4]);
    r->dp[7] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD2(l, h, o, a->dp[3], a->dp[5]);
    SP_ASM_SQR_ADD(l, h, o, a->dp[4]);
    r->dp[8] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD2(l, h, o, a->dp[4], a->dp[5]);
    r->dp[9] = l;
    l = h;
    h = o;
    SP_ASM_SQR_ADD_NO(l, h, a->dp[5]);
    r->dp[10] = l;
    r->dp[11] = h;
    XMEMCPY(r->dp, t, 6 * sizeof(sp_int_digit));
    r->used = 12;
    sp_clamp(r);

    return MP_OKAY;
}
#endif /* SQR_MUL_ASM */
#endif /* SP_WORD_SIZE == 64 */
#if SP_WORD_SIZE == 32
#ifdef SQR_MUL_ASM
/* Square a and store in r. r = a * a
 *
 * Comba implementation.
 *
 * @param  [in]   a  SP integer to square.
 * @param  [out]  r  SP integer result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
static int _sp_sqr_8(sp_int* a, sp_int* r)
{
    sp_int_digit l = 0;
    sp_int_digit h = 0;
    sp_int_digit o = 0;
    sp_int_digit tl = 0;
    sp_int_digit th = 0;
    sp_int_digit to;
    sp_int_digit t[8];

#if defined(WOLFSSL_SP_ARM_THUMB) && SP_WORD_SIZE == 32
    to = 0;
#endif

    SP_ASM_SQR(h, l, a->dp[0]);
    t[0] = h;
    h = 0;
    SP_ASM_MUL_ADD2_NO(l, h, o, a->dp[0], a->dp[1]);
    t[1] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD2_NO(l, h, o, a->dp[0], a->dp[2]);
    SP_ASM_SQR_ADD(l, h, o, a->dp[1]);
    t[2] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD2(l, h, o, a->dp[0], a->dp[3]);
    SP_ASM_MUL_ADD2(l, h, o, a->dp[1], a->dp[2]);
    t[3] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD2(l, h, o, a->dp[0], a->dp[4]);
    SP_ASM_MUL_ADD2(l, h, o, a->dp[1], a->dp[3]);
    SP_ASM_SQR_ADD(l, h, o, a->dp[2]);
    t[4] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_SET(tl, th, to, a->dp[0], a->dp[5]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[1], a->dp[4]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[3]);
    SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
    t[5] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_SET(tl, th, to, a->dp[0], a->dp[6]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[1], a->dp[5]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[4]);
    SP_ASM_SQR_ADD(l, h, o, a->dp[3]);
    SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
    t[6] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_SET(tl, th, to, a->dp[0], a->dp[7]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[1], a->dp[6]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[5]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[3], a->dp[4]);
    SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
    t[7] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_SET(tl, th, to, a->dp[1], a->dp[7]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[6]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[3], a->dp[5]);
    SP_ASM_SQR_ADD(l, h, o, a->dp[4]);
    SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
    r->dp[8] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_SET(tl, th, to, a->dp[2], a->dp[7]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[3], a->dp[6]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[4], a->dp[5]);
    SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
    r->dp[9] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD2(l, h, o, a->dp[3], a->dp[7]);
    SP_ASM_MUL_ADD2(l, h, o, a->dp[4], a->dp[6]);
    SP_ASM_SQR_ADD(l, h, o, a->dp[5]);
    r->dp[10] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD2(l, h, o, a->dp[4], a->dp[7]);
    SP_ASM_MUL_ADD2(l, h, o, a->dp[5], a->dp[6]);
    r->dp[11] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD2(l, h, o, a->dp[5], a->dp[7]);
    SP_ASM_SQR_ADD(l, h, o, a->dp[6]);
    r->dp[12] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD2(l, h, o, a->dp[6], a->dp[7]);
    r->dp[13] = l;
    l = h;
    h = o;
    SP_ASM_SQR_ADD_NO(l, h, a->dp[7]);
    r->dp[14] = l;
    r->dp[15] = h;
    XMEMCPY(r->dp, t, 8 * sizeof(sp_int_digit));
    r->used = 16;
    sp_clamp(r);

    return MP_OKAY;
}
#endif /* SQR_MUL_ASM */
#endif /* SP_WORD_SIZE == 32 */
#if SP_WORD_SIZE == 32
#ifdef SQR_MUL_ASM
/* Square a and store in r. r = a * a
 *
 * Comba implementation.
 *
 * @param  [in]   a  SP integer to square.
 * @param  [out]  r  SP integer result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
static int _sp_sqr_12(sp_int* a, sp_int* r)
{
    sp_int_digit l = 0;
    sp_int_digit h = 0;
    sp_int_digit o = 0;
    sp_int_digit tl = 0;
    sp_int_digit th = 0;
    sp_int_digit to;
    sp_int_digit t[12];

#if defined(WOLFSSL_SP_ARM_THUMB) && SP_WORD_SIZE == 32
    to = 0;
#endif

    SP_ASM_SQR(h, l, a->dp[0]);
    t[0] = h;
    h = 0;
    SP_ASM_MUL_ADD2_NO(l, h, o, a->dp[0], a->dp[1]);
    t[1] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD2_NO(l, h, o, a->dp[0], a->dp[2]);
    SP_ASM_SQR_ADD(l, h, o, a->dp[1]);
    t[2] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD2(l, h, o, a->dp[0], a->dp[3]);
    SP_ASM_MUL_ADD2(l, h, o, a->dp[1], a->dp[2]);
    t[3] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD2(l, h, o, a->dp[0], a->dp[4]);
    SP_ASM_MUL_ADD2(l, h, o, a->dp[1], a->dp[3]);
    SP_ASM_SQR_ADD(l, h, o, a->dp[2]);
    t[4] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_SET(tl, th, to, a->dp[0], a->dp[5]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[1], a->dp[4]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[3]);
    SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
    t[5] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_SET(tl, th, to, a->dp[0], a->dp[6]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[1], a->dp[5]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[4]);
    SP_ASM_SQR_ADD(l, h, o, a->dp[3]);
    SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
    t[6] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_SET(tl, th, to, a->dp[0], a->dp[7]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[1], a->dp[6]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[5]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[3], a->dp[4]);
    SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
    t[7] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_SET(tl, th, to, a->dp[0], a->dp[8]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[1], a->dp[7]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[6]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[3], a->dp[5]);
    SP_ASM_SQR_ADD(l, h, o, a->dp[4]);
    SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
    t[8] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_SET(tl, th, to, a->dp[0], a->dp[9]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[1], a->dp[8]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[7]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[3], a->dp[6]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[4], a->dp[5]);
    SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
    t[9] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_SET(tl, th, to, a->dp[0], a->dp[10]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[1], a->dp[9]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[8]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[3], a->dp[7]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[4], a->dp[6]);
    SP_ASM_SQR_ADD(l, h, o, a->dp[5]);
    SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
    t[10] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_SET(tl, th, to, a->dp[0], a->dp[11]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[1], a->dp[10]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[9]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[3], a->dp[8]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[4], a->dp[7]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[5], a->dp[6]);
    SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
    t[11] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_SET(tl, th, to, a->dp[1], a->dp[11]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[10]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[3], a->dp[9]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[4], a->dp[8]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[5], a->dp[7]);
    SP_ASM_SQR_ADD(l, h, o, a->dp[6]);
    SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
    r->dp[12] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_SET(tl, th, to, a->dp[2], a->dp[11]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[3], a->dp[10]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[4], a->dp[9]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[5], a->dp[8]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[6], a->dp[7]);
    SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
    r->dp[13] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_SET(tl, th, to, a->dp[3], a->dp[11]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[4], a->dp[10]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[5], a->dp[9]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[6], a->dp[8]);
    SP_ASM_SQR_ADD(l, h, o, a->dp[7]);
    SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
    r->dp[14] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_SET(tl, th, to, a->dp[4], a->dp[11]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[5], a->dp[10]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[6], a->dp[9]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[7], a->dp[8]);
    SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
    r->dp[15] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_SET(tl, th, to, a->dp[5], a->dp[11]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[6], a->dp[10]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[7], a->dp[9]);
    SP_ASM_SQR_ADD(l, h, o, a->dp[8]);
    SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
    r->dp[16] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_SET(tl, th, to, a->dp[6], a->dp[11]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[7], a->dp[10]);
    SP_ASM_MUL_ADD(tl, th, to, a->dp[8], a->dp[9]);
    SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
    r->dp[17] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD2(l, h, o, a->dp[7], a->dp[11]);
    SP_ASM_MUL_ADD2(l, h, o, a->dp[8], a->dp[10]);
    SP_ASM_SQR_ADD(l, h, o, a->dp[9]);
    r->dp[18] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD2(l, h, o, a->dp[8], a->dp[11]);
    SP_ASM_MUL_ADD2(l, h, o, a->dp[9], a->dp[10]);
    r->dp[19] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD2(l, h, o, a->dp[9], a->dp[11]);
    SP_ASM_SQR_ADD(l, h, o, a->dp[10]);
    r->dp[20] = l;
    l = h;
    h = o;
    o = 0;
    SP_ASM_MUL_ADD2(l, h, o, a->dp[10], a->dp[11]);
    r->dp[21] = l;
    l = h;
    h = o;
    SP_ASM_SQR_ADD_NO(l, h, a->dp[11]);
    r->dp[22] = l;
    r->dp[23] = h;
    XMEMCPY(r->dp, t, 12 * sizeof(sp_int_digit));
    r->used = 24;
    sp_clamp(r);

    return MP_OKAY;
}
#endif /* SQR_MUL_ASM */
#endif /* SP_WORD_SIZE == 32 */
#endif /* !WOLFSSL_HAVE_SP_ECC && HAVE_ECC */

#if defined(SQR_MUL_ASM) && defined(WOLFSSL_SP_INT_LARGE_COMBA)
    #if SP_INT_DIGITS >= 32
/* Square a and store in r. r = a * a
 *
 * Comba implementation.
 *
 * @param  [in]   a  SP integer to square.
 * @param  [out]  r  SP integer result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
static int _sp_sqr_16(sp_int* a, sp_int* r)
{
    int err = MP_OKAY;
    sp_int_digit l = 0;
    sp_int_digit h = 0;
    sp_int_digit o = 0;
    sp_int_digit tl = 0;
    sp_int_digit th = 0;
    sp_int_digit to;
#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_SP_NO_MALLOC)
    sp_int_digit* t = NULL;
#else
    sp_int_digit t[16];
#endif

#if defined(WOLFSSL_SP_ARM_THUMB) && SP_WORD_SIZE == 32
    to = 0;
#endif

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_SP_NO_MALLOC)
     t = (sp_int_digit*)XMALLOC(sizeof(sp_int_digit) * 16, NULL,
         DYNAMIC_TYPE_BIGINT);
     if (t == NULL) {
         err = MP_MEM;
     }
#endif
    if (err == MP_OKAY) {
        SP_ASM_SQR(h, l, a->dp[0]);
        t[0] = h;
        h = 0;
        SP_ASM_MUL_ADD2_NO(l, h, o, a->dp[0], a->dp[1]);
        t[1] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD2_NO(l, h, o, a->dp[0], a->dp[2]);
        SP_ASM_SQR_ADD(l, h, o, a->dp[1]);
        t[2] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD2(l, h, o, a->dp[0], a->dp[3]);
        SP_ASM_MUL_ADD2(l, h, o, a->dp[1], a->dp[2]);
        t[3] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD2(l, h, o, a->dp[0], a->dp[4]);
        SP_ASM_MUL_ADD2(l, h, o, a->dp[1], a->dp[3]);
        SP_ASM_SQR_ADD(l, h, o, a->dp[2]);
        t[4] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[0], a->dp[5]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[1], a->dp[4]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[3]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        t[5] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[0], a->dp[6]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[1], a->dp[5]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[4]);
        SP_ASM_SQR_ADD(l, h, o, a->dp[3]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        t[6] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[0], a->dp[7]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[1], a->dp[6]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[5]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[3], a->dp[4]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        t[7] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[0], a->dp[8]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[1], a->dp[7]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[6]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[3], a->dp[5]);
        SP_ASM_SQR_ADD(l, h, o, a->dp[4]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        t[8] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[0], a->dp[9]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[1], a->dp[8]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[7]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[3], a->dp[6]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[4], a->dp[5]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        t[9] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[0], a->dp[10]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[1], a->dp[9]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[8]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[3], a->dp[7]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[4], a->dp[6]);
        SP_ASM_SQR_ADD(l, h, o, a->dp[5]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        t[10] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[0], a->dp[11]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[1], a->dp[10]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[9]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[3], a->dp[8]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[4], a->dp[7]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[5], a->dp[6]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        t[11] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[0], a->dp[12]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[1], a->dp[11]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[10]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[3], a->dp[9]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[4], a->dp[8]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[5], a->dp[7]);
        SP_ASM_SQR_ADD(l, h, o, a->dp[6]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        t[12] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[0], a->dp[13]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[1], a->dp[12]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[11]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[3], a->dp[10]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[4], a->dp[9]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[5], a->dp[8]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[6], a->dp[7]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        t[13] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[0], a->dp[14]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[1], a->dp[13]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[12]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[3], a->dp[11]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[4], a->dp[10]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[5], a->dp[9]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[6], a->dp[8]);
        SP_ASM_SQR_ADD(l, h, o, a->dp[7]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        t[14] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[0], a->dp[15]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[1], a->dp[14]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[13]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[3], a->dp[12]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[4], a->dp[11]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[5], a->dp[10]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[6], a->dp[9]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[7], a->dp[8]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        t[15] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[1], a->dp[15]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[14]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[3], a->dp[13]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[4], a->dp[12]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[5], a->dp[11]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[6], a->dp[10]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[7], a->dp[9]);
        SP_ASM_SQR_ADD(l, h, o, a->dp[8]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        r->dp[16] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[2], a->dp[15]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[3], a->dp[14]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[4], a->dp[13]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[5], a->dp[12]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[6], a->dp[11]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[7], a->dp[10]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[8], a->dp[9]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        r->dp[17] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[3], a->dp[15]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[4], a->dp[14]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[5], a->dp[13]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[6], a->dp[12]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[7], a->dp[11]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[8], a->dp[10]);
        SP_ASM_SQR_ADD(l, h, o, a->dp[9]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        r->dp[18] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[4], a->dp[15]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[5], a->dp[14]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[6], a->dp[13]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[7], a->dp[12]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[8], a->dp[11]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[9], a->dp[10]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        r->dp[19] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[5], a->dp[15]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[6], a->dp[14]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[7], a->dp[13]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[8], a->dp[12]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[9], a->dp[11]);
        SP_ASM_SQR_ADD(l, h, o, a->dp[10]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        r->dp[20] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[6], a->dp[15]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[7], a->dp[14]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[8], a->dp[13]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[9], a->dp[12]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[10], a->dp[11]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        r->dp[21] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[7], a->dp[15]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[8], a->dp[14]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[9], a->dp[13]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[10], a->dp[12]);
        SP_ASM_SQR_ADD(l, h, o, a->dp[11]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        r->dp[22] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[8], a->dp[15]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[9], a->dp[14]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[10], a->dp[13]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[11], a->dp[12]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        r->dp[23] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[9], a->dp[15]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[10], a->dp[14]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[11], a->dp[13]);
        SP_ASM_SQR_ADD(l, h, o, a->dp[12]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        r->dp[24] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[10], a->dp[15]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[11], a->dp[14]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[12], a->dp[13]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        r->dp[25] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD2(l, h, o, a->dp[11], a->dp[15]);
        SP_ASM_MUL_ADD2(l, h, o, a->dp[12], a->dp[14]);
        SP_ASM_SQR_ADD(l, h, o, a->dp[13]);
        r->dp[26] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD2(l, h, o, a->dp[12], a->dp[15]);
        SP_ASM_MUL_ADD2(l, h, o, a->dp[13], a->dp[14]);
        r->dp[27] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD2(l, h, o, a->dp[13], a->dp[15]);
        SP_ASM_SQR_ADD(l, h, o, a->dp[14]);
        r->dp[28] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD2(l, h, o, a->dp[14], a->dp[15]);
        r->dp[29] = l;
        l = h;
        h = o;
        SP_ASM_SQR_ADD_NO(l, h, a->dp[15]);
        r->dp[30] = l;
        r->dp[31] = h;
        XMEMCPY(r->dp, t, 16 * sizeof(sp_int_digit));
        r->used = 32;
        sp_clamp(r);
    }

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (t != NULL) {
        XFREE(t, NULL, DYNAMIC_TYPE_BIGINT);
    }
#endif
    return err;
}
    #endif /* SP_INT_DIGITS >= 32 */

    #if SP_INT_DIGITS >= 48
/* Square a and store in r. r = a * a
 *
 * Comba implementation.
 *
 * @param  [in]   a  SP integer to square.
 * @param  [out]  r  SP integer result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
static int _sp_sqr_24(sp_int* a, sp_int* r)
{
    int err = MP_OKAY;
    sp_int_digit l = 0;
    sp_int_digit h = 0;
    sp_int_digit o = 0;
    sp_int_digit tl = 0;
    sp_int_digit th = 0;
    sp_int_digit to;
#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_SP_NO_MALLOC)
    sp_int_digit* t = NULL;
#else
    sp_int_digit t[24];
#endif

#if defined(WOLFSSL_SP_ARM_THUMB) && SP_WORD_SIZE == 32
    to = 0;
#endif

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_SP_NO_MALLOC)
     t = (sp_int_digit*)XMALLOC(sizeof(sp_int_digit) * 24, NULL,
         DYNAMIC_TYPE_BIGINT);
     if (t == NULL) {
         err = MP_MEM;
     }
#endif
    if (err == MP_OKAY) {
        SP_ASM_SQR(h, l, a->dp[0]);
        t[0] = h;
        h = 0;
        SP_ASM_MUL_ADD2_NO(l, h, o, a->dp[0], a->dp[1]);
        t[1] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD2_NO(l, h, o, a->dp[0], a->dp[2]);
        SP_ASM_SQR_ADD(l, h, o, a->dp[1]);
        t[2] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD2(l, h, o, a->dp[0], a->dp[3]);
        SP_ASM_MUL_ADD2(l, h, o, a->dp[1], a->dp[2]);
        t[3] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD2(l, h, o, a->dp[0], a->dp[4]);
        SP_ASM_MUL_ADD2(l, h, o, a->dp[1], a->dp[3]);
        SP_ASM_SQR_ADD(l, h, o, a->dp[2]);
        t[4] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[0], a->dp[5]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[1], a->dp[4]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[3]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        t[5] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[0], a->dp[6]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[1], a->dp[5]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[4]);
        SP_ASM_SQR_ADD(l, h, o, a->dp[3]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        t[6] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[0], a->dp[7]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[1], a->dp[6]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[5]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[3], a->dp[4]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        t[7] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[0], a->dp[8]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[1], a->dp[7]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[6]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[3], a->dp[5]);
        SP_ASM_SQR_ADD(l, h, o, a->dp[4]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        t[8] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[0], a->dp[9]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[1], a->dp[8]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[7]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[3], a->dp[6]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[4], a->dp[5]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        t[9] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[0], a->dp[10]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[1], a->dp[9]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[8]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[3], a->dp[7]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[4], a->dp[6]);
        SP_ASM_SQR_ADD(l, h, o, a->dp[5]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        t[10] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[0], a->dp[11]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[1], a->dp[10]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[9]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[3], a->dp[8]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[4], a->dp[7]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[5], a->dp[6]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        t[11] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[0], a->dp[12]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[1], a->dp[11]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[10]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[3], a->dp[9]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[4], a->dp[8]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[5], a->dp[7]);
        SP_ASM_SQR_ADD(l, h, o, a->dp[6]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        t[12] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[0], a->dp[13]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[1], a->dp[12]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[11]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[3], a->dp[10]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[4], a->dp[9]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[5], a->dp[8]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[6], a->dp[7]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        t[13] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[0], a->dp[14]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[1], a->dp[13]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[12]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[3], a->dp[11]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[4], a->dp[10]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[5], a->dp[9]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[6], a->dp[8]);
        SP_ASM_SQR_ADD(l, h, o, a->dp[7]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        t[14] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[0], a->dp[15]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[1], a->dp[14]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[13]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[3], a->dp[12]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[4], a->dp[11]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[5], a->dp[10]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[6], a->dp[9]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[7], a->dp[8]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        t[15] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[0], a->dp[16]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[1], a->dp[15]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[14]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[3], a->dp[13]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[4], a->dp[12]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[5], a->dp[11]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[6], a->dp[10]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[7], a->dp[9]);
        SP_ASM_SQR_ADD(l, h, o, a->dp[8]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        t[16] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[0], a->dp[17]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[1], a->dp[16]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[15]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[3], a->dp[14]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[4], a->dp[13]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[5], a->dp[12]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[6], a->dp[11]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[7], a->dp[10]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[8], a->dp[9]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        t[17] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[0], a->dp[18]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[1], a->dp[17]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[16]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[3], a->dp[15]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[4], a->dp[14]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[5], a->dp[13]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[6], a->dp[12]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[7], a->dp[11]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[8], a->dp[10]);
        SP_ASM_SQR_ADD(l, h, o, a->dp[9]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        t[18] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[0], a->dp[19]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[1], a->dp[18]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[17]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[3], a->dp[16]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[4], a->dp[15]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[5], a->dp[14]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[6], a->dp[13]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[7], a->dp[12]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[8], a->dp[11]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[9], a->dp[10]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        t[19] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[0], a->dp[20]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[1], a->dp[19]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[18]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[3], a->dp[17]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[4], a->dp[16]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[5], a->dp[15]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[6], a->dp[14]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[7], a->dp[13]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[8], a->dp[12]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[9], a->dp[11]);
        SP_ASM_SQR_ADD(l, h, o, a->dp[10]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        t[20] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[0], a->dp[21]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[1], a->dp[20]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[19]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[3], a->dp[18]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[4], a->dp[17]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[5], a->dp[16]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[6], a->dp[15]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[7], a->dp[14]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[8], a->dp[13]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[9], a->dp[12]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[10], a->dp[11]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        t[21] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[0], a->dp[22]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[1], a->dp[21]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[20]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[3], a->dp[19]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[4], a->dp[18]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[5], a->dp[17]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[6], a->dp[16]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[7], a->dp[15]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[8], a->dp[14]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[9], a->dp[13]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[10], a->dp[12]);
        SP_ASM_SQR_ADD(l, h, o, a->dp[11]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        t[22] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[0], a->dp[23]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[1], a->dp[22]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[21]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[3], a->dp[20]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[4], a->dp[19]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[5], a->dp[18]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[6], a->dp[17]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[7], a->dp[16]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[8], a->dp[15]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[9], a->dp[14]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[10], a->dp[13]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[11], a->dp[12]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        t[23] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[1], a->dp[23]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[2], a->dp[22]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[3], a->dp[21]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[4], a->dp[20]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[5], a->dp[19]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[6], a->dp[18]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[7], a->dp[17]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[8], a->dp[16]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[9], a->dp[15]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[10], a->dp[14]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[11], a->dp[13]);
        SP_ASM_SQR_ADD(l, h, o, a->dp[12]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        r->dp[24] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[2], a->dp[23]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[3], a->dp[22]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[4], a->dp[21]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[5], a->dp[20]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[6], a->dp[19]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[7], a->dp[18]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[8], a->dp[17]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[9], a->dp[16]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[10], a->dp[15]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[11], a->dp[14]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[12], a->dp[13]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        r->dp[25] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[3], a->dp[23]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[4], a->dp[22]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[5], a->dp[21]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[6], a->dp[20]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[7], a->dp[19]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[8], a->dp[18]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[9], a->dp[17]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[10], a->dp[16]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[11], a->dp[15]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[12], a->dp[14]);
        SP_ASM_SQR_ADD(l, h, o, a->dp[13]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        r->dp[26] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[4], a->dp[23]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[5], a->dp[22]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[6], a->dp[21]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[7], a->dp[20]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[8], a->dp[19]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[9], a->dp[18]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[10], a->dp[17]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[11], a->dp[16]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[12], a->dp[15]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[13], a->dp[14]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        r->dp[27] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[5], a->dp[23]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[6], a->dp[22]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[7], a->dp[21]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[8], a->dp[20]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[9], a->dp[19]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[10], a->dp[18]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[11], a->dp[17]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[12], a->dp[16]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[13], a->dp[15]);
        SP_ASM_SQR_ADD(l, h, o, a->dp[14]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        r->dp[28] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[6], a->dp[23]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[7], a->dp[22]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[8], a->dp[21]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[9], a->dp[20]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[10], a->dp[19]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[11], a->dp[18]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[12], a->dp[17]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[13], a->dp[16]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[14], a->dp[15]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        r->dp[29] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[7], a->dp[23]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[8], a->dp[22]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[9], a->dp[21]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[10], a->dp[20]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[11], a->dp[19]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[12], a->dp[18]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[13], a->dp[17]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[14], a->dp[16]);
        SP_ASM_SQR_ADD(l, h, o, a->dp[15]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        r->dp[30] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[8], a->dp[23]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[9], a->dp[22]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[10], a->dp[21]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[11], a->dp[20]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[12], a->dp[19]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[13], a->dp[18]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[14], a->dp[17]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[15], a->dp[16]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        r->dp[31] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[9], a->dp[23]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[10], a->dp[22]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[11], a->dp[21]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[12], a->dp[20]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[13], a->dp[19]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[14], a->dp[18]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[15], a->dp[17]);
        SP_ASM_SQR_ADD(l, h, o, a->dp[16]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        r->dp[32] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[10], a->dp[23]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[11], a->dp[22]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[12], a->dp[21]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[13], a->dp[20]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[14], a->dp[19]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[15], a->dp[18]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[16], a->dp[17]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        r->dp[33] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[11], a->dp[23]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[12], a->dp[22]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[13], a->dp[21]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[14], a->dp[20]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[15], a->dp[19]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[16], a->dp[18]);
        SP_ASM_SQR_ADD(l, h, o, a->dp[17]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        r->dp[34] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[12], a->dp[23]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[13], a->dp[22]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[14], a->dp[21]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[15], a->dp[20]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[16], a->dp[19]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[17], a->dp[18]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        r->dp[35] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[13], a->dp[23]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[14], a->dp[22]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[15], a->dp[21]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[16], a->dp[20]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[17], a->dp[19]);
        SP_ASM_SQR_ADD(l, h, o, a->dp[18]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        r->dp[36] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[14], a->dp[23]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[15], a->dp[22]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[16], a->dp[21]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[17], a->dp[20]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[18], a->dp[19]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        r->dp[37] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[15], a->dp[23]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[16], a->dp[22]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[17], a->dp[21]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[18], a->dp[20]);
        SP_ASM_SQR_ADD(l, h, o, a->dp[19]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        r->dp[38] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[16], a->dp[23]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[17], a->dp[22]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[18], a->dp[21]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[19], a->dp[20]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        r->dp[39] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[17], a->dp[23]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[18], a->dp[22]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[19], a->dp[21]);
        SP_ASM_SQR_ADD(l, h, o, a->dp[20]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        r->dp[40] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_SET(tl, th, to, a->dp[18], a->dp[23]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[19], a->dp[22]);
        SP_ASM_MUL_ADD(tl, th, to, a->dp[20], a->dp[21]);
        SP_ASM_ADD_DBL_3(l, h, o, tl, th, to);
        r->dp[41] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD2(l, h, o, a->dp[19], a->dp[23]);
        SP_ASM_MUL_ADD2(l, h, o, a->dp[20], a->dp[22]);
        SP_ASM_SQR_ADD(l, h, o, a->dp[21]);
        r->dp[42] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD2(l, h, o, a->dp[20], a->dp[23]);
        SP_ASM_MUL_ADD2(l, h, o, a->dp[21], a->dp[22]);
        r->dp[43] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD2(l, h, o, a->dp[21], a->dp[23]);
        SP_ASM_SQR_ADD(l, h, o, a->dp[22]);
        r->dp[44] = l;
        l = h;
        h = o;
        o = 0;
        SP_ASM_MUL_ADD2(l, h, o, a->dp[22], a->dp[23]);
        r->dp[45] = l;
        l = h;
        h = o;
        SP_ASM_SQR_ADD_NO(l, h, a->dp[23]);
        r->dp[46] = l;
        r->dp[47] = h;
        XMEMCPY(r->dp, t, 24 * sizeof(sp_int_digit));
        r->used = 48;
        sp_clamp(r);
    }

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (t != NULL) {
        XFREE(t, NULL, DYNAMIC_TYPE_BIGINT);
    }
#endif
    return err;
}
    #endif /* SP_INT_DIGITS >= 48 */

    #if SP_INT_DIGITS >= 64
/* Square a and store in r. r = a * a
 *
 * Karatsuba implementation.
 *
 * @param  [in]   a  SP integer to square.
 * @param  [out]  r  SP integer result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
static int _sp_sqr_32(sp_int* a, sp_int* r)
{
    int err = MP_OKAY;
    int i;
    sp_int_digit l;
    sp_int_digit h;
    sp_int* z0;
    sp_int* z1;
    sp_int* z2;
    sp_int_digit ca;
    DECL_SP_INT(a1, 16);
    DECL_SP_INT_ARRAY(z, 33, 2);

    ALLOC_SP_INT(a1, 16, err, NULL);
    ALLOC_SP_INT_ARRAY(z, 33, 2, err, NULL);
    if (err == MP_OKAY) {
        z1 = z[0];
        z2 = z[1];
        z0 = r;

        XMEMCPY(a1->dp, &a->dp[16], sizeof(sp_int_digit) * 16);
        a1->used = 16;

        /* z2 = a1 ^ 2 */
        err = _sp_sqr_16(a1, z2);
    }
    if (err == MP_OKAY) {
        l = 0;
        h = 0;
        for (i = 0; i < 16; i++) {
            SP_ASM_ADDC(l, h, a1->dp[i]);
            SP_ASM_ADDC(l, h, a->dp[i]);
            a1->dp[i] = l;
            l = h;
            h = 0;
        }
        ca = l;

        /* z0 = a0 ^ 2 */
        err = _sp_sqr_16(a, z0);
    }
    if (err == MP_OKAY) {
        /* z1 = (a0 + a1) ^ 2 */
        err = _sp_sqr_16(a1, z1);
    }
    if (err == MP_OKAY) {
        /* r = (z2 << 32) + (z1 - z0 - z2) << 16) + z0 */
        /* r = z0 */
        /* r += (z1 - z0 - z2) << 16 */
        z1->dp[32] = ca;
        l = 0;
        if (ca) {
            l = z1->dp[0 + 16];
            h = 0;
            SP_ASM_ADDC(l, h, a1->dp[0]);
            SP_ASM_ADDC(l, h, a1->dp[0]);
            z1->dp[0 + 16] = l;
            l = h;
            h = 0;
            for (i = 1; i < 16; i++) {
                SP_ASM_ADDC(l, h, z1->dp[i + 16]);
                SP_ASM_ADDC(l, h, a1->dp[i]);
                SP_ASM_ADDC(l, h, a1->dp[i]);
                z1->dp[i + 16] = l;
                l = h;
                h = 0;
            }
        }
        z1->dp[32] += l;
        /* z1 = z1 - z0 - z1 */
        l = z1->dp[0];
        h = 0;
        SP_ASM_SUBC(l, h, z0->dp[0]);
        SP_ASM_SUBC(l, h, z2->dp[0]);
        z1->dp[0] = l;
        l = h;
        h = 0;
        for (i = 1; i < 32; i++) {
            l += z1->dp[i];
            SP_ASM_SUBC(l, h, z0->dp[i]);
            SP_ASM_SUBC(l, h, z2->dp[i]);
            z1->dp[i] = l;
            l = h;
            h = 0;
        }
        z1->dp[i] += l;
        /* r += z1 << 16 */
        l = 0;
        h = 0;
        for (i = 0; i < 16; i++) {
            SP_ASM_ADDC(l, h, r->dp[i + 16]);
            SP_ASM_ADDC(l, h, z1->dp[i]);
            r->dp[i + 16] = l;
            l = h;
            h = 0;
        }
        for (; i < 33; i++) {
            SP_ASM_ADDC(l, h, z1->dp[i]);
            r->dp[i + 16] = l;
            l = h;
            h = 0;
        }
        /* r += z2 << 32  */
        l = 0;
        h = 0;
        for (i = 0; i < 17; i++) {
            SP_ASM_ADDC(l, h, r->dp[i + 32]);
            SP_ASM_ADDC(l, h, z2->dp[i]);
            r->dp[i + 32] = l;
            l = h;
            h = 0;
        }
        for (; i < 32; i++) {
            SP_ASM_ADDC(l, h, z2->dp[i]);
            r->dp[i + 32] = l;
            l = h;
            h = 0;
        }
        r->used = 64;
        sp_clamp(r);
    }

    FREE_SP_INT_ARRAY(z, NULL);
    FREE_SP_INT(a1, NULL);
    return err;
}
    #endif /* SP_INT_DIGITS >= 64 */

    #if SP_INT_DIGITS >= 96
/* Square a and store in r. r = a * a
 *
 * Karatsuba implementation.
 *
 * @param  [in]   a  SP integer to square.
 * @param  [out]  r  SP integer result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
static int _sp_sqr_48(sp_int* a, sp_int* r)
{
    int err = MP_OKAY;
    int i;
    sp_int_digit l;
    sp_int_digit h;
    sp_int* z0;
    sp_int* z1;
    sp_int* z2;
    sp_int_digit ca;
    DECL_SP_INT(a1, 24);
    DECL_SP_INT_ARRAY(z, 49, 2);

    ALLOC_SP_INT(a1, 24, err, NULL);
    ALLOC_SP_INT_ARRAY(z, 49, 2, err, NULL);
    if (err == MP_OKAY) {
        z1 = z[0];
        z2 = z[1];
        z0 = r;

        XMEMCPY(a1->dp, &a->dp[24], sizeof(sp_int_digit) * 24);
        a1->used = 24;

        /* z2 = a1 ^ 2 */
        err = _sp_sqr_24(a1, z2);
    }
    if (err == MP_OKAY) {
        l = 0;
        h = 0;
        for (i = 0; i < 24; i++) {
            SP_ASM_ADDC(l, h, a1->dp[i]);
            SP_ASM_ADDC(l, h, a->dp[i]);
            a1->dp[i] = l;
            l = h;
            h = 0;
        }
        ca = l;

        /* z0 = a0 ^ 2 */
        err = _sp_sqr_24(a, z0);
    }
    if (err == MP_OKAY) {
        /* z1 = (a0 + a1) ^ 2 */
        err = _sp_sqr_24(a1, z1);
    }
    if (err == MP_OKAY) {
        /* r = (z2 << 48) + (z1 - z0 - z2) << 24) + z0 */
        /* r = z0 */
        /* r += (z1 - z0 - z2) << 24 */
        z1->dp[48] = ca;
        l = 0;
        if (ca) {
            l = z1->dp[0 + 24];
            h = 0;
            SP_ASM_ADDC(l, h, a1->dp[0]);
            SP_ASM_ADDC(l, h, a1->dp[0]);
            z1->dp[0 + 24] = l;
            l = h;
            h = 0;
            for (i = 1; i < 24; i++) {
                SP_ASM_ADDC(l, h, z1->dp[i + 24]);
                SP_ASM_ADDC(l, h, a1->dp[i]);
                SP_ASM_ADDC(l, h, a1->dp[i]);
                z1->dp[i + 24] = l;
                l = h;
                h = 0;
            }
        }
        z1->dp[48] += l;
        /* z1 = z1 - z0 - z1 */
        l = z1->dp[0];
        h = 0;
        SP_ASM_SUBC(l, h, z0->dp[0]);
        SP_ASM_SUBC(l, h, z2->dp[0]);
        z1->dp[0] = l;
        l = h;
        h = 0;
        for (i = 1; i < 48; i++) {
            l += z1->dp[i];
            SP_ASM_SUBC(l, h, z0->dp[i]);
            SP_ASM_SUBC(l, h, z2->dp[i]);
            z1->dp[i] = l;
            l = h;
            h = 0;
        }
        z1->dp[i] += l;
        /* r += z1 << 16 */
        l = 0;
        h = 0;
        for (i = 0; i < 24; i++) {
            SP_ASM_ADDC(l, h, r->dp[i + 24]);
            SP_ASM_ADDC(l, h, z1->dp[i]);
            r->dp[i + 24] = l;
            l = h;
            h = 0;
        }
        for (; i < 49; i++) {
            SP_ASM_ADDC(l, h, z1->dp[i]);
            r->dp[i + 24] = l;
            l = h;
            h = 0;
        }
        /* r += z2 << 48  */
        l = 0;
        h = 0;
        for (i = 0; i < 25; i++) {
            SP_ASM_ADDC(l, h, r->dp[i + 48]);
            SP_ASM_ADDC(l, h, z2->dp[i]);
            r->dp[i + 48] = l;
            l = h;
            h = 0;
        }
        for (; i < 48; i++) {
            SP_ASM_ADDC(l, h, z2->dp[i]);
            r->dp[i + 48] = l;
            l = h;
            h = 0;
        }
        r->used = 96;
        sp_clamp(r);
    }

    FREE_SP_INT_ARRAY(z, NULL);
    FREE_SP_INT(a1, NULL);
    return err;
}
    #endif /* SP_INT_DIGITS >= 96 */

    #if SP_INT_DIGITS >= 128
/* Square a and store in r. r = a * a
 *
 * Karatsuba implementation.
 *
 * @param  [in]   a  SP integer to square.
 * @param  [out]  r  SP integer result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
static int _sp_sqr_64(sp_int* a, sp_int* r)
{
    int err = MP_OKAY;
    int i;
    sp_int_digit l;
    sp_int_digit h;
    sp_int* z0;
    sp_int* z1;
    sp_int* z2;
    sp_int_digit ca;
    DECL_SP_INT(a1, 32);
    DECL_SP_INT_ARRAY(z, 65, 2);

    ALLOC_SP_INT(a1, 32, err, NULL);
    ALLOC_SP_INT_ARRAY(z, 65, 2, err, NULL);
    if (err == MP_OKAY) {
        z1 = z[0];
        z2 = z[1];
        z0 = r;

        XMEMCPY(a1->dp, &a->dp[32], sizeof(sp_int_digit) * 32);
        a1->used = 32;

        /* z2 = a1 ^ 2 */
        err = _sp_sqr_32(a1, z2);
    }
    if (err == MP_OKAY) {
        l = 0;
        h = 0;
        for (i = 0; i < 32; i++) {
            SP_ASM_ADDC(l, h, a1->dp[i]);
            SP_ASM_ADDC(l, h, a->dp[i]);
            a1->dp[i] = l;
            l = h;
            h = 0;
        }
        ca = l;

        /* z0 = a0 ^ 2 */
        err = _sp_sqr_32(a, z0);
    }
    if (err == MP_OKAY) {
        /* z1 = (a0 + a1) ^ 2 */
        err = _sp_sqr_32(a1, z1);
    }
    if (err == MP_OKAY) {
        /* r = (z2 << 64) + (z1 - z0 - z2) << 32) + z0 */
        /* r = z0 */
        /* r += (z1 - z0 - z2) << 32 */
        z1->dp[64] = ca;
        l = 0;
        if (ca) {
            l = z1->dp[0 + 32];
            h = 0;
            SP_ASM_ADDC(l, h, a1->dp[0]);
            SP_ASM_ADDC(l, h, a1->dp[0]);
            z1->dp[0 + 32] = l;
            l = h;
            h = 0;
            for (i = 1; i < 32; i++) {
                SP_ASM_ADDC(l, h, z1->dp[i + 32]);
                SP_ASM_ADDC(l, h, a1->dp[i]);
                SP_ASM_ADDC(l, h, a1->dp[i]);
                z1->dp[i + 32] = l;
                l = h;
                h = 0;
            }
        }
        z1->dp[64] += l;
        /* z1 = z1 - z0 - z1 */
        l = z1->dp[0];
        h = 0;
        SP_ASM_SUBC(l, h, z0->dp[0]);
        SP_ASM_SUBC(l, h, z2->dp[0]);
        z1->dp[0] = l;
        l = h;
        h = 0;
        for (i = 1; i < 64; i++) {
            l += z1->dp[i];
            SP_ASM_SUBC(l, h, z0->dp[i]);
            SP_ASM_SUBC(l, h, z2->dp[i]);
            z1->dp[i] = l;
            l = h;
            h = 0;
        }
        z1->dp[i] += l;
        /* r += z1 << 16 */
        l = 0;
        h = 0;
        for (i = 0; i < 32; i++) {
            SP_ASM_ADDC(l, h, r->dp[i + 32]);
            SP_ASM_ADDC(l, h, z1->dp[i]);
            r->dp[i + 32] = l;
            l = h;
            h = 0;
        }
        for (; i < 65; i++) {
            SP_ASM_ADDC(l, h, z1->dp[i]);
            r->dp[i + 32] = l;
            l = h;
            h = 0;
        }
        /* r += z2 << 64  */
        l = 0;
        h = 0;
        for (i = 0; i < 33; i++) {
            SP_ASM_ADDC(l, h, r->dp[i + 64]);
            SP_ASM_ADDC(l, h, z2->dp[i]);
            r->dp[i + 64] = l;
            l = h;
            h = 0;
        }
        for (; i < 64; i++) {
            SP_ASM_ADDC(l, h, z2->dp[i]);
            r->dp[i + 64] = l;
            l = h;
            h = 0;
        }
        r->used = 128;
        sp_clamp(r);
    }

    FREE_SP_INT_ARRAY(z, NULL);
    FREE_SP_INT(a1, NULL);
    return err;
}
    #endif /* SP_INT_DIGITS >= 128 */

    #if SP_INT_DIGITS >= 192
/* Square a and store in r. r = a * a
 *
 * Karatsuba implementation.
 *
 * @param  [in]   a  SP integer to square.
 * @param  [out]  r  SP integer result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
static int _sp_sqr_96(sp_int* a, sp_int* r)
{
    int err = MP_OKAY;
    int i;
    sp_int_digit l;
    sp_int_digit h;
    sp_int* z0;
    sp_int* z1;
    sp_int* z2;
    sp_int_digit ca;
    DECL_SP_INT(a1, 48);
    DECL_SP_INT_ARRAY(z, 97, 2);

    ALLOC_SP_INT(a1, 48, err, NULL);
    ALLOC_SP_INT_ARRAY(z, 97, 2, err, NULL);
    if (err == MP_OKAY) {
        z1 = z[0];
        z2 = z[1];
        z0 = r;

        XMEMCPY(a1->dp, &a->dp[48], sizeof(sp_int_digit) * 48);
        a1->used = 48;

        /* z2 = a1 ^ 2 */
        err = _sp_sqr_48(a1, z2);
    }
    if (err == MP_OKAY) {
        l = 0;
        h = 0;
        for (i = 0; i < 48; i++) {
            SP_ASM_ADDC(l, h, a1->dp[i]);
            SP_ASM_ADDC(l, h, a->dp[i]);
            a1->dp[i] = l;
            l = h;
            h = 0;
        }
        ca = l;

        /* z0 = a0 ^ 2 */
        err = _sp_sqr_48(a, z0);
    }
    if (err == MP_OKAY) {
        /* z1 = (a0 + a1) ^ 2 */
        err = _sp_sqr_48(a1, z1);
    }
    if (err == MP_OKAY) {
        /* r = (z2 << 96) + (z1 - z0 - z2) << 48) + z0 */
        /* r = z0 */
        /* r += (z1 - z0 - z2) << 48 */
        z1->dp[96] = ca;
        l = 0;
        if (ca) {
            l = z1->dp[0 + 48];
            h = 0;
            SP_ASM_ADDC(l, h, a1->dp[0]);
            SP_ASM_ADDC(l, h, a1->dp[0]);
            z1->dp[0 + 48] = l;
            l = h;
            h = 0;
            for (i = 1; i < 48; i++) {
                SP_ASM_ADDC(l, h, z1->dp[i + 48]);
                SP_ASM_ADDC(l, h, a1->dp[i]);
                SP_ASM_ADDC(l, h, a1->dp[i]);
                z1->dp[i + 48] = l;
                l = h;
                h = 0;
            }
        }
        z1->dp[96] += l;
        /* z1 = z1 - z0 - z1 */
        l = z1->dp[0];
        h = 0;
        SP_ASM_SUBC(l, h, z0->dp[0]);
        SP_ASM_SUBC(l, h, z2->dp[0]);
        z1->dp[0] = l;
        l = h;
        h = 0;
        for (i = 1; i < 96; i++) {
            l += z1->dp[i];
            SP_ASM_SUBC(l, h, z0->dp[i]);
            SP_ASM_SUBC(l, h, z2->dp[i]);
            z1->dp[i] = l;
            l = h;
            h = 0;
        }
        z1->dp[i] += l;
        /* r += z1 << 16 */
        l = 0;
        h = 0;
        for (i = 0; i < 48; i++) {
            SP_ASM_ADDC(l, h, r->dp[i + 48]);
            SP_ASM_ADDC(l, h, z1->dp[i]);
            r->dp[i + 48] = l;
            l = h;
            h = 0;
        }
        for (; i < 97; i++) {
            SP_ASM_ADDC(l, h, z1->dp[i]);
            r->dp[i + 48] = l;
            l = h;
            h = 0;
        }
        /* r += z2 << 96  */
        l = 0;
        h = 0;
        for (i = 0; i < 49; i++) {
            SP_ASM_ADDC(l, h, r->dp[i + 96]);
            SP_ASM_ADDC(l, h, z2->dp[i]);
            r->dp[i + 96] = l;
            l = h;
            h = 0;
        }
        for (; i < 96; i++) {
            SP_ASM_ADDC(l, h, z2->dp[i]);
            r->dp[i + 96] = l;
            l = h;
            h = 0;
        }
        r->used = 192;
        sp_clamp(r);
    }

    FREE_SP_INT_ARRAY(z, NULL);
    FREE_SP_INT(a1, NULL);
    return err;
}
    #endif /* SP_INT_DIGITS >= 192 */

#endif /* SQR_MUL_ASM && WOLFSSL_SP_INT_LARGE_COMBA */
#endif /* !WOLFSSL_SP_SMALL */

/* Square a and store in r. r = a * a
 *
 * @param  [in]   a  SP integer to square.
 * @param  [out]  r  SP integer result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a or r is NULL, or the result will be too big for fixed
 *          data length.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
int sp_sqr(sp_int* a, sp_int* r)
{
#if defined(WOLFSSL_SP_MATH) && defined(WOLFSSL_SP_SMALL)
    return sp_mul(a, a, r);
#else
    int err = MP_OKAY;

    if ((a == NULL) || (r == NULL)) {
        err = MP_VAL;
    }
    /* Need extra digit during calculation. */
    if ((err == MP_OKAY) && (a->used * 2 > r->size)) {
        err = MP_VAL;
    }

#if 0
    if (err == MP_OKAY) {
        sp_print(a, "a");
    }
#endif

    if (err == MP_OKAY) {
        if (a->used == 0) {
            _sp_zero(r);
        }
    else
#ifndef WOLFSSL_SP_SMALL
#if !defined(WOLFSSL_HAVE_SP_ECC) && defined(HAVE_ECC)
#if SP_WORD_SIZE == 64
        if (a->used == 4) {
            err = _sp_sqr_4(a, r);
        }
        else
#endif /* SP_WORD_SIZE == 64 */
#if SP_WORD_SIZE == 64
#ifdef SQR_MUL_ASM
        if (a->used == 6) {
            err = _sp_sqr_6(a, r);
        }
        else
#endif /* SQR_MUL_ASM */
#endif /* SP_WORD_SIZE == 64 */
#if SP_WORD_SIZE == 32
#ifdef SQR_MUL_ASM
        if (a->used == 8) {
            err = _sp_sqr_8(a, r);
        }
        else
#endif /* SQR_MUL_ASM */
#endif /* SP_WORD_SIZE == 32 */
#if SP_WORD_SIZE == 32
#ifdef SQR_MUL_ASM
        if (a->used == 12) {
            err = _sp_sqr_12(a, r);
        }
        else
#endif /* SQR_MUL_ASM */
#endif /* SP_WORD_SIZE == 32 */
#endif /* !WOLFSSL_HAVE_SP_ECC && HAVE_ECC */
#if defined(SQR_MUL_ASM) && defined(WOLFSSL_SP_INT_LARGE_COMBA)
    #if SP_INT_DIGITS >= 32
        if (a->used == 16) {
            err = _sp_sqr_16(a, r);
        }
        else
    #endif /* SP_INT_DIGITS >= 32 */
    #if SP_INT_DIGITS >= 48
        if (a->used == 24) {
            err = _sp_sqr_24(a, r);
        }
        else
    #endif /* SP_INT_DIGITS >= 48 */
    #if SP_INT_DIGITS >= 64
        if (a->used == 32) {
            err = _sp_sqr_32(a, r);
        }
        else
    #endif /* SP_INT_DIGITS >= 64 */
    #if SP_INT_DIGITS >= 96
        if (a->used == 48) {
            err = _sp_sqr_48(a, r);
        }
        else
    #endif /* SP_INT_DIGITS >= 96 */
    #if SP_INT_DIGITS >= 128
        if (a->used == 64) {
            err = _sp_sqr_64(a, r);
        }
        else
    #endif /* SP_INT_DIGITS >= 128 */
    #if SP_INT_DIGITS >= 192
        if (a->used == 96) {
            err = _sp_sqr_96(a, r);
        }
        else
    #endif /* SP_INT_DIGITS >= 192 */
#endif /* SQR_MUL_ASM && WOLFSSL_SP_INT_LARGE_COMBA */
#endif /* !WOLFSSL_SP_SMALL */
        {
            err = _sp_sqr(a, r);
        }
    }

#ifdef WOLFSSL_SP_INT_NEGATIVE
    if (err == MP_OKAY) {
        r->sign = MP_ZPOS;
    }
#endif

#if 0
    if (err == MP_OKAY) {
        sp_print(r, "rsqr");
    }
#endif

    return err;
#endif /* WOLFSSL_SP_MATH && WOLFSSL_SP_SMALL */
}
/* END SP_SQR implementations */

#endif /* WOLFSSL_SP_MATH_ALL || WOLFSSL_HAVE_SP_DH || HAVE_ECC ||
        * (!NO_RSA && !WOLFSSL_RSA_VERIFY_ONLY) */

#if !defined(WOLFSSL_RSA_VERIFY_ONLY) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)
/* Square a mod m and store in r: r = (a * a) mod m
 *
 * @param  [in]   a  SP integer to square.
 * @param  [in]   m  SP integer that is the modulus.
 * @param  [out]  r  SP integer result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a, m or r is NULL; or m is 0; or a squared is too big
 *          for fixed data length.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
int sp_sqrmod(sp_int* a, sp_int* m, sp_int* r)
{
    int err = MP_OKAY;

    if ((a == NULL) || (m == NULL) || (r == NULL)) {
        err = MP_VAL;
    }
    if ((err == MP_OKAY) && (a->used * 2 > r->size)) {
        err = MP_VAL;
    }

    if (err == MP_OKAY) {
        err = sp_sqr(a, r);
    }
    if (err == MP_OKAY) {
        err = sp_mod(r, m, r);
    }

    return err;
}
#endif /* !WOLFSSL_RSA_VERIFY_ONLY */

/**********************
 * Montgomery functions
 **********************/

#if defined(WOLFSSL_SP_MATH_ALL) || defined(WOLFSSL_HAVE_SP_DH) || \
    defined(WOLFCRYPT_HAVE_ECCSI) || defined(WOLFCRYPT_HAVE_SAKKE)
/* Reduce a number in montgomery form.
 *
 * Assumes a and m are not NULL and m is not 0.
 *
 * @param  [in,out]  a   SP integer to Montgomery reduce.
 * @param  [in]      m   SP integer that is the modulus.
 * @param  [in]      mp  SP integer digit that is the bottom digit of inv(-m).
 *
 * @return  MP_OKAY on success.
 */
static int _sp_mont_red(sp_int* a, sp_int* m, sp_int_digit mp)
{
#if !defined(SQR_MUL_ASM)
    int i;
    int bits;
    sp_int_word w;
    sp_int_digit mu;

    if (0) {
        sp_print(a, "a");
        sp_print(m, "m");
    }

    bits = sp_count_bits(m);

    for (i = a->used; i < m->used * 2; i++) {
        a->dp[i] = 0;
    }

    if (m->used == 1) {
        mu = mp * a->dp[0];
        w = a->dp[0];
        w += (sp_int_word)mu * m->dp[0];
        a->dp[0] = (sp_int_digit)w;
        w >>= SP_WORD_SIZE;
        w += a->dp[1];
        a->dp[1] = (sp_int_digit)w;
        w >>= SP_WORD_SIZE;
        a->dp[2] = (sp_int_digit)w;
        a->used = 3;
        /* mp is SP_WORD_SIZE */
        bits = SP_WORD_SIZE;
    }
    else {
        sp_int_digit mask = (sp_int_digit)
                            ((1UL << (bits & (SP_WORD_SIZE - 1))) - 1);
        sp_int_word o = 0;
        for (i = 0; i < m->used; i++) {
            int j;

            mu = mp * a->dp[i];
            if ((i == m->used - 1) && (mask != 0)) {
                mu &= mask;
            }
            w = a->dp[i];
            w += (sp_int_word)mu * m->dp[0];
            a->dp[i] = (sp_int_digit)w;
            w >>= SP_WORD_SIZE;
            for (j = 1; j < m->used - 1; j++) {
                w += a->dp[i + j];
                w += (sp_int_word)mu * m->dp[j];
                a->dp[i + j] = (sp_int_digit)w;
                w >>= SP_WORD_SIZE;
            }
            w += o;
            w += a->dp[i + j];
            o = (sp_int_digit)(w >> SP_WORD_SIZE);
            w = ((sp_int_word)mu * m->dp[j]) + (sp_int_digit)w;
            a->dp[i + j] = (sp_int_digit)w;
            w >>= SP_WORD_SIZE;
            o += w;
        }
        o += a->dp[m->used * 2 - 1];
        a->dp[m->used * 2 - 1] = (sp_int_digit)o;
        o >>= SP_WORD_SIZE;
        a->dp[m->used * 2] = (sp_int_digit)o;
        a->used = m->used * 2 + 1;
    }

    sp_clamp(a);
    sp_rshb(a, bits, a);

    if (_sp_cmp_abs(a, m) != MP_LT) {
        _sp_sub_off(a, m, a, 0);
    }

    if (0) {
        sp_print(a, "rr");
    }

    return MP_OKAY;
#else /* !SQR_MUL_ASM */
    int i;
    int j;
    int bits;
    sp_int_digit mu;
    sp_int_digit o;
    sp_int_digit mask;

    bits = sp_count_bits(m);
    mask = ((sp_int_digit)1 << (bits & (SP_WORD_SIZE - 1))) - 1;

    for (i = a->used; i < m->used * 2; i++) {
        a->dp[i] = 0;
    }

    if (m->used <= 1) {
        sp_int_word w;

        mu = mp * a->dp[0];
        w = a->dp[0];
        w += (sp_int_word)mu * m->dp[0];
        a->dp[0] = (sp_int_digit)w;
        w >>= SP_WORD_SIZE;
        w += a->dp[1];
        a->dp[1] = (sp_int_digit)w;
        w >>= SP_WORD_SIZE;
        a->dp[2] = (sp_int_digit)w;
        a->used = m->used * 2 + 1;
        /* mp is SP_WORD_SIZE */
        bits = SP_WORD_SIZE;
    }
#ifndef WOLFSSL_HAVE_SP_ECC
#if SP_WORD_SIZE == 64
    else if (m->used == 4) {
        sp_int_digit l;
        sp_int_digit h;
        sp_int_digit o2;

        l = 0;
        h = 0;
        o = 0;
        o2 = 0;
        for (i = 0; i < 4; i++) {
            mu = mp * a->dp[i];
            if ((i == 3) && (mask != 0)) {
                mu &= mask;
            }
            l = a->dp[i];
            SP_ASM_MUL_ADD_NO(l, h, mu, m->dp[0]);
            a->dp[i] = l;
            l = h;
            h = 0;
            SP_ASM_ADDC(l, h, a->dp[i + 1]);
            SP_ASM_MUL_ADD_NO(l, h, mu, m->dp[1]);
            a->dp[i + 1] = l;
            l = h;
            h = 0;
            SP_ASM_ADDC(l, h, a->dp[i + 2]);
            SP_ASM_MUL_ADD_NO(l, h, mu, m->dp[2]);
            a->dp[i + 2] = l;
            l = h;
            h = o2;
            o2 = 0;
            SP_ASM_ADDC_REG(l, h, o);
            SP_ASM_ADDC(l, h, a->dp[i + 3]);
            SP_ASM_MUL_ADD(l, h, o2, mu, m->dp[3]);
            a->dp[i + 3] = l;
            o = h;
            l = h;
            h = 0;
        }
        h = o2;
        SP_ASM_ADDC(l, h, a->dp[7]);
        a->dp[7] = l;
        a->dp[8] = h;
        a->used = 9;
    }
    else if (m->used == 6) {
        sp_int_digit l;
        sp_int_digit h;
        sp_int_digit o2;

        l = 0;
        h = 0;
        o = 0;
        o2 = 0;
        for (i = 0; i < 6; i++) {
            mu = mp * a->dp[i];
            if ((i == 5) && (mask != 0)) {
                mu &= mask;
            }
            l = a->dp[i];
            SP_ASM_MUL_ADD_NO(l, h, mu, m->dp[0]);
            a->dp[i] = l;
            l = h;
            h = 0;
            SP_ASM_ADDC(l, h, a->dp[i + 1]);
            SP_ASM_MUL_ADD_NO(l, h, mu, m->dp[1]);
            a->dp[i + 1] = l;
            l = h;
            h = 0;
            SP_ASM_ADDC(l, h, a->dp[i + 2]);
            SP_ASM_MUL_ADD_NO(l, h, mu, m->dp[2]);
            a->dp[i + 2] = l;
            l = h;
            h = 0;
            SP_ASM_ADDC(l, h, a->dp[i + 3]);
            SP_ASM_MUL_ADD_NO(l, h, mu, m->dp[3]);
            a->dp[i + 3] = l;
            l = h;
            h = 0;
            SP_ASM_ADDC(l, h, a->dp[i + 4]);
            SP_ASM_MUL_ADD_NO(l, h, mu, m->dp[4]);
            a->dp[i + 4] = l;
            l = h;
            h = o2;
            o2 = 0;
            SP_ASM_ADDC_REG(l, h, o);
            SP_ASM_ADDC(l, h, a->dp[i + 5]);
            SP_ASM_MUL_ADD(l, h, o2, mu, m->dp[5]);
            a->dp[i + 5] = l;
            o = h;
            l = h;
            h = 0;
        }
        h = o2;
        SP_ASM_ADDC(l, h, a->dp[11]);
        a->dp[11] = l;
        a->dp[12] = h;
        a->used = 13;
    }
#endif /* SP_WORD_SIZE == 64 */
#endif /* WOLFSSL_HAVE_SP_ECC */
    else {
        sp_int_digit l;
        sp_int_digit h;
        sp_int_digit o2;
        sp_int_digit* ad;
        sp_int_digit* md;

        o = 0;
        o2 = 0;
        ad = a->dp;
        for (i = 0; i < m->used; i++, ad++) {
            md = m->dp;
            mu = mp * ad[0];
            if ((i == m->used - 1) && (mask != 0)) {
                mu &= mask;
            }
            l = ad[0];
            h = 0;
            SP_ASM_MUL_ADD_NO(l, h, mu, *(md++));
            ad[0] = l;
            l = h;
            for (j = 1; j + 1 < m->used - 1; j += 2) {
                h = 0;
                SP_ASM_ADDC(l, h, ad[j + 0]);
                SP_ASM_MUL_ADD_NO(l, h, mu, *(md++));
                ad[j + 0] = l;
                l = 0;
                SP_ASM_ADDC(h, l, ad[j + 1]);
                SP_ASM_MUL_ADD_NO(h, l, mu, *(md++));
                ad[j + 1] = h;
            }
            for (; j < m->used - 1; j++) {
                h = 0;
                SP_ASM_ADDC(l, h, ad[j]);
                SP_ASM_MUL_ADD_NO(l, h, mu, *(md++));
                ad[j] = l;
                l = h;
            }
            h = o2;
            o2 = 0;
            SP_ASM_ADDC_REG(l, h, o);
            SP_ASM_ADDC(l, h, ad[j]);
            SP_ASM_MUL_ADD(l, h, o2, mu, *md);
            ad[j] = l;
            o = h;
        }
        l = o;
        h = o2;
        SP_ASM_ADDC(l, h, a->dp[m->used * 2 - 1]);
        a->dp[m->used * 2 - 1] = l;
        a->dp[m->used * 2] = h;
        a->used = m->used * 2 + 1;
    }

    sp_clamp(a);
    sp_rshb(a, bits, a);

    if (_sp_cmp_abs(a, m) != MP_LT) {
        sp_sub(a, m, a);
    }

    return MP_OKAY;
#endif /* !SQR_MUL_ASM */
}

#ifndef WOLFSSL_RSA_VERIFY_ONLY
/* Reduce a number in montgomery form.
 *
 * @param  [in,out]  a   SP integer to Montgomery reduce.
 * @param  [in]      m   SP integer that is the modulus.
 * @param  [in]      mp  SP integer digit that is the bottom digit of inv(-m).
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a or m is NULL or m is zero.
 */
int sp_mont_red(sp_int* a, sp_int* m, sp_int_digit mp)
{
    int err;

    if ((a == NULL) || (m == NULL) || sp_iszero(m)) {
        err = MP_VAL;
    }
    else if (a->size < m->used * 2 + 1) {
        err = MP_VAL;
    }
    else {
        err = _sp_mont_red(a, m, mp);
    }

    return err;
}
#endif

/* Calculate the bottom digit of the inverse of negative m.
 *
 * Used when performing Montgomery Reduction.
 *
 * @param  [in]   m   SP integer that is the modulus.
 * @param  [out]  mp  SP integer digit that is the bottom digit of inv(-m).
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when m or rho is NULL.
 */
int sp_mont_setup(sp_int* m, sp_int_digit* rho)
{
    int err = MP_OKAY;

    if ((m == NULL) || (rho == NULL)) {
        err = MP_VAL;
    }
    if ((err == MP_OKAY) && !sp_isodd(m)) {
        err = MP_VAL;
    }

    if (err == MP_OKAY) {
        sp_int_digit x;
        sp_int_digit b;

        b = m->dp[0];
        x = (((b + 2) & 4) << 1) + b; /* here x*a==1 mod 2**4 */
        x *= 2 - b * x;               /* here x*a==1 mod 2**8 */
    #if SP_WORD_SIZE >= 16
        x *= 2 - b * x;               /* here x*a==1 mod 2**16 */
    #if SP_WORD_SIZE >= 32
        x *= 2 - b * x;               /* here x*a==1 mod 2**32 */
    #if SP_WORD_SIZE >= 64
        x *= 2 - b * x;               /* here x*a==1 mod 2**64 */
    #endif /* SP_WORD_SIZE >= 64 */
    #endif /* SP_WORD_SIZE >= 32 */
    #endif /* SP_WORD_SIZE >= 16 */

        /* rho = -1/m mod b */
        *rho = -x;
    }

    return err;
}

/* Calculate the normalization value of m.
 *   norm = 2^k - m, where k is the number of bits in m
 *
 * @param  [out]  norm   SP integer that normalises numbers into Montgomery
 *                       form.
 * @param  [in]   m      SP integer that is the modulus.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when norm or m is NULL, or number of bits in m is maximual.
 */
int sp_mont_norm(sp_int* norm, sp_int* m)
{
    int err = MP_OKAY;
    int bits = 0;

    if ((norm == NULL) || (m == NULL)) {
        err = MP_VAL;
    }
    if (err == MP_OKAY) {
        bits = sp_count_bits(m);
        if (bits == m->size * SP_WORD_SIZE) {
            err = MP_VAL;
        }
    }
    if (err == MP_OKAY) {
        if (bits < SP_WORD_SIZE) {
            bits = SP_WORD_SIZE;
        }
        _sp_zero(norm);
        sp_set_bit(norm, bits);
        err = sp_sub(norm, m, norm);
    }
    if ((err == MP_OKAY) && (bits == SP_WORD_SIZE)) {
        norm->dp[0] %= m->dp[0];
    }
    if (err == MP_OKAY) {
        sp_clamp(norm);
    }

    return err;
}
#endif /* WOLFSSL_SP_MATH_ALL || WOLFSSL_HAVE_SP_DH ||
        * WOLFCRYPT_HAVE_ECCSI || WOLFCRYPT_HAVE_SAKKE */

/*********************************
 * To and from binary and strings.
 *********************************/

/* Calculate the number of 8-bit values required to represent the
 * multi-precision number.
 *
 * When a is NULL, return s 0.
 *
 * @param  [in]  a  SP integer.
 *
 * @return  The count of 8-bit values.
 */
int sp_unsigned_bin_size(const sp_int* a)
{
    int cnt = 0;

    if (a != NULL) {
        cnt = (sp_count_bits(a) + 7) / 8;
    }

    return cnt;
}

/* Convert a number as an array of bytes in big-endian format to a
 * multi-precision number.
 *
 * @param  [out]  a     SP integer.
 * @param  [in]   in    Array of bytes.
 * @param  [in]   inSz  Number of data bytes in array.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when the number is too big to fit in an SP.
 */
int sp_read_unsigned_bin(sp_int* a, const byte* in, word32 inSz)
{
    int err = MP_OKAY;

    if ((a == NULL) || ((in == NULL) && (inSz > 0))) {
        err = MP_VAL;
    }

    if ((err == MP_OKAY) && (inSz > (word32)a->size * SP_WORD_SIZEOF)) {
        err = MP_VAL;
    }

#ifndef LITTLE_ENDIAN_ORDER
    if (err == MP_OKAY) {
        int i;
        int j;
        int s;

        a->used = (inSz + SP_WORD_SIZEOF - 1) / SP_WORD_SIZEOF;

    #ifndef WOLFSSL_SP_INT_DIGIT_ALIGN
        for (i = inSz-1,j = 0; i > SP_WORD_SIZEOF-1; i -= SP_WORD_SIZEOF,j++) {
            a->dp[j] = *(sp_int_digit*)(in + i - (SP_WORD_SIZEOF - 1));
        }
    #else
        for (i = inSz-1, j = 0; i >= SP_WORD_SIZEOF - 1; i -= SP_WORD_SIZEOF) {
            a->dp[j]  = ((sp_int_digit)in[i - 0] <<  0);
        #if SP_WORD_SIZE >= 16
            a->dp[j] |= ((sp_int_digit)in[i - 1] <<  8);
        #endif
        #if SP_WORD_SIZE >= 32
            a->dp[j] |= ((sp_int_digit)in[i - 2] << 16) |
                        ((sp_int_digit)in[i - 3] << 24);
        #endif
        #if SP_WORD_SIZE >= 64
            a->dp[j] |= ((sp_int_digit)in[i - 4] << 32) |
                        ((sp_int_digit)in[i - 5] << 40) |
                        ((sp_int_digit)in[i - 6] << 48) |
                        ((sp_int_digit)in[i - 7] << 56);
        #endif
            j++;
        }
    #endif
        if (i >= 0) {
            a->dp[a->used - 1] = 0;
            for (s = 0; i >= 0; i--,s += 8) {
                a->dp[j] |= ((sp_int_digit)in[i]) << s;
            }
        }

        sp_clamp(a);
    }
#else
    if (err == MP_OKAY) {
        int i;
        int j;

        a->used = (inSz + SP_WORD_SIZEOF - 1) / SP_WORD_SIZEOF;

        for (i = inSz-1, j = 0; i >= SP_WORD_SIZEOF - 1; i -= SP_WORD_SIZEOF) {
            a->dp[j]  = ((sp_int_digit)in[i - 0] <<  0);
        #if SP_WORD_SIZE >= 16
            a->dp[j] |= ((sp_int_digit)in[i - 1] <<  8);
        #endif
        #if SP_WORD_SIZE >= 32
            a->dp[j] |= ((sp_int_digit)in[i - 2] << 16) |
                        ((sp_int_digit)in[i - 3] << 24);
        #endif
        #if SP_WORD_SIZE >= 64
            a->dp[j] |= ((sp_int_digit)in[i - 4] << 32) |
                        ((sp_int_digit)in[i - 5] << 40) |
                        ((sp_int_digit)in[i - 6] << 48) |
                        ((sp_int_digit)in[i - 7] << 56);
        #endif
            j++;
        }

    #if SP_WORD_SIZE >= 16
        if (i >= 0) {
            byte *d = (byte*)a->dp;

            a->dp[a->used - 1] = 0;
            switch (i) {
                case 6: d[inSz - 1 - 6] = in[6]; FALL_THROUGH;
                case 5: d[inSz - 1 - 5] = in[5]; FALL_THROUGH;
                case 4: d[inSz - 1 - 4] = in[4]; FALL_THROUGH;
                case 3: d[inSz - 1 - 3] = in[3]; FALL_THROUGH;
                case 2: d[inSz - 1 - 2] = in[2]; FALL_THROUGH;
                case 1: d[inSz - 1 - 1] = in[1]; FALL_THROUGH;
                case 0: d[inSz - 1 - 0] = in[0];
            }
        }
    #endif

        sp_clamp(a);
    }
#endif /* LITTLE_ENDIAN_ORDER */

    return err;
}

/* Convert the multi-precision number to an array of bytes in big-endian format.
 *
 * The array must be large enough for encoded number - use mp_unsigned_bin_size
 * to calculate the number of bytes required.
 *
 * @param  [in]   a    SP integer.
 * @param  [out]  out  Array to put encoding into.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a or out is NULL.
 */
int sp_to_unsigned_bin(sp_int* a, byte* out)
{
    return sp_to_unsigned_bin_len(a, out, sp_unsigned_bin_size(a));
}

/* Convert the multi-precision number to an array of bytes in big-endian format.
 *
 * The array must be large enough for encoded number - use mp_unsigned_bin_size
 * to calculate the number of bytes required.
 * Front-pads the output array with zeros make number the size of the array.
 *
 * @param  [in]   a      SP integer.
 * @param  [out]  out    Array to put encoding into.
 * @param  [in]   outSz  Size of the array in bytes.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a or out is NULL.
 */
int sp_to_unsigned_bin_len(sp_int* a, byte* out, int outSz)
{
    int err = MP_OKAY;

    if ((a == NULL) || (out == NULL)) {
        err = MP_VAL;
    }
    if (err == MP_OKAY) {
        int j = outSz - 1;

        if (!sp_iszero(a)) {
            int i;
            for (i = 0; (j >= 0) && (i < a->used); i++) {
                int b;
                for (b = 0; b < SP_WORD_SIZE; b += 8) {
                    out[j--] = a->dp[i] >> b;
                    if (j < 0) {
                        break;
                    }
                }
            }
        }
        for (; j >= 0; j--) {
            out[j] = 0;
        }
    }

    return err;
}

#if defined(WOLFSSL_SP_MATH_ALL) && !defined(NO_RSA) && !defined(WOLFSSL_RSA_VERIFY_ONLY)
/* Store the number in big-endian format in array at an offset.
 * The array must be large enough for encoded number - use mp_unsigned_bin_size
 * to calculate the number of bytes required.
 *
 * @param  [in]   o    Offset into array o start encoding.
 * @param  [in]   a    SP integer.
 * @param  [out]  out  Array to put encoding into.
 *
 * @return  Index of next byte after data.
 * @return  MP_VAL when a or out is NULL.
 */
int sp_to_unsigned_bin_at_pos(int o, sp_int*a, unsigned char* out)
{
    int ret = sp_to_unsigned_bin(a, out + o);

    if (ret == MP_OKAY) {
        ret = o + sp_unsigned_bin_size(a);
    }

    return ret;
}
#endif /* WOLFSSL_SP_MATH_ALL && !NO_RSA && !WOLFSSL_RSA_VERIFY_ONLY */

#if (defined(WOLFSSL_SP_MATH_ALL) && !defined(NO_RSA) && !defined(WOLFSSL_RSA_VERIFY_ONLY)) || \
    defined(HAVE_ECC) || !defined(NO_DSA)
/* Convert hexadecimal number as string in big-endian format to a
 * multi-precision number.
 *
 * Negative values supported when compiled with WOLFSSL_SP_INT_NEGATIVE.
 *
 * @param  [out]  a   SP integer.
 * @param  [in]   in  NUL terminated string.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when radix not supported, value is negative, or a character
 *          is not valid.
 */
static int _sp_read_radix_16(sp_int* a, const char* in)
{
    int  err = MP_OKAY;
    int  i;
    int  s = 0;
    int  j = 0;

#ifdef WOLFSSL_SP_INT_NEGATIVE
    if (*in == '-') {
        a->sign = MP_NEG;
        in++;
    }
#endif

    while (*in == '0') {
        in++;
    }

    a->dp[0] = 0;
    for (i = (int)(XSTRLEN(in) - 1); i >= 0; i--) {
        int ch = (int)HexCharToByte(in[i]);
        if (ch < 0) {
            err = MP_VAL;
            break;
        }

        if (s == SP_WORD_SIZE) {
            j++;
            if (j >= a->size) {
                err = MP_VAL;
                break;
            }
            s = 0;
            a->dp[j] = 0;
        }

        a->dp[j] |= ((sp_int_digit)ch) << s;
        s += 4;
    }

    if (err == MP_OKAY) {
        a->used = j + 1;
        sp_clamp(a);
    #ifdef WOLFSSL_SP_INT_NEGATIVE
        if (sp_iszero(a)) {
            a->sign = MP_ZPOS;
        }
    #endif
    }
    return err;
}
#endif /* (WOLFSSL_SP_MATH_ALL && !NO_RSA && !WOLFSSL_RSA_VERIFY_ONLY) || HAVE_ECC */

#ifdef WOLFSSL_SP_READ_RADIX_10
/* Convert decimal number as string in big-endian format to a multi-precision
 * number.
 *
 * Negative values supported when compiled with WOLFSSL_SP_INT_NEGATIVE.
 *
 * @param  [out]  a   SP integer.
 * @param  [in]   in  NUL terminated string.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when radix not supported, value is negative, or a character
 *          is not valid.
 */
static int _sp_read_radix_10(sp_int* a, const char* in)
{
    int  err = MP_OKAY;
    int  i;
    int  len;
    char ch;

    _sp_zero(a);
#ifdef WOLFSSL_SP_INT_NEGATIVE
    if (*in == '-') {
        a->sign = MP_NEG;
        in++;
    }
#endif /* WOLFSSL_SP_INT_NEGATIVE */

    while (*in == '0') {
        in++;
    }

    len = (int)XSTRLEN(in);
    for (i = 0; i < len; i++) {
        ch = in[i];
        if ((ch >= '0') && (ch <= '9')) {
            ch -= '0';
        }
        else {
            err = MP_VAL;
            break;
        }
        err = _sp_mul_d(a, 10, a, 0);
        if (err != MP_OKAY) {
            break;
        }
        (void)_sp_add_d(a, ch, a);
    }
#ifdef WOLFSSL_SP_INT_NEGATIVE
    if ((err == MP_OKAY) && sp_iszero(a)) {
        a->sign = MP_ZPOS;
    }
#endif

    return err;
}
#endif /* WOLFSSL_SP_READ_RADIX_10 */

#if (defined(WOLFSSL_SP_MATH_ALL) && !defined(NO_RSA) && \
    !defined(WOLFSSL_RSA_VERIFY_ONLY)) || defined(HAVE_ECC) || !defined(NO_DSA)
/* Convert a number as string in big-endian format to a big number.
 * Only supports base-16 (hexadecimal) and base-10 (decimal).
 *
 * Negative values supported when WOLFSSL_SP_INT_NEGATIVE is defined.
 *
 * @param  [out]  a      SP integer.
 * @param  [in]   in     NUL terminated string.
 * @param  [in]   radix  Number of values in a digit.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a or in is NULL, radix not supported, value is negative,
 *          or a character is not valid.
 */
int sp_read_radix(sp_int* a, const char* in, int radix)
{
    int err = MP_OKAY;

    if ((a == NULL) || (in == NULL)) {
        err = MP_VAL;
    }

    if (err == MP_OKAY) {
    #ifndef WOLFSSL_SP_INT_NEGATIVE
        if (*in == '-') {
            err = MP_VAL;
        }
        else
    #endif
        if (radix == 16) {
            err = _sp_read_radix_16(a, in);
        }
    #ifdef WOLFSSL_SP_READ_RADIX_10
        else if (radix == 10) {
            err = _sp_read_radix_10(a, in);
        }
    #endif
        else {
            err = MP_VAL;
        }
    }

    return err;
}
#endif /* (WOLFSSL_SP_MATH_ALL && !NO_RSA && !WOLFSSL_RSA_VERIFY_ONLY) || HAVE_ECC */

#if (defined(WOLFSSL_SP_MATH_ALL) && !defined(WOLFSSL_RSA_VERIFY_ONLY)) || \
    defined(WC_MP_TO_RADIX)

/* Put the big-endian, hex string encoding of a into str.
 *
 * Assumes str is large enough for result.
 * Use sp_radix_size() to calculate required length.
 *
 * @param  [in]   a    SP integer to convert.
 * @param  [out]  str  String to hold hex string result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a or str is NULL.
 */
int sp_tohex(sp_int* a, char* str)
{
    int err = MP_OKAY;
    int i;
    int j;

    if ((a == NULL) || (str == NULL)) {
        err = MP_VAL;
    }
    if (err == MP_OKAY) {
        /* quick out if its zero */
        if (sp_iszero(a) == MP_YES) {
    #ifndef WC_DISABLE_RADIX_ZERO_PAD
            *str++ = '0';
    #endif /* WC_DISABLE_RADIX_ZERO_PAD */
            *str++ = '0';
            *str = '\0';
        }
        else {
    #ifdef WOLFSSL_SP_INT_NEGATIVE
            if (a->sign == MP_NEG) {
                *str = '-';
                str++;
            }
    #endif /* WOLFSSL_SP_INT_NEGATIVE */

            i = a->used - 1;
    #ifndef WC_DISABLE_RADIX_ZERO_PAD
            /* Find highest non-zero byte in most-significant word. */
            for (j = SP_WORD_SIZE - 8; j >= 0; j -= 8) {
                if (((a->dp[i] >> j) & 0xff) != 0) {
                    break;
                }
                else if (j == 0) {
                    j = SP_WORD_SIZE - 8;
                    --i;
                }
            }
            /* Start with high nibble of byte. */
            j += 4;
    #else
            /* Find highest non-zero nibble in most-significant word. */
            for (j = SP_WORD_SIZE - 4; j >= 0; j -= 4) {
                if (((a->dp[i] >> j) & 0xf) != 0) {
                    break;
                }
                else if (j == 0) {
                    j = SP_WORD_SIZE - 4;
                    --i;
                }
            }
    #endif /* WC_DISABLE_RADIX_ZERO_PAD */
            /* Most-significant word. */
            for (; j >= 0; j -= 4) {
                *(str++) = ByteToHex(a->dp[i] >> j);
            }
            for (--i; i >= 0; i--) {
                for (j = SP_WORD_SIZE - 4; j >= 0; j -= 4) {
                    *(str++) = ByteToHex(a->dp[i] >> j);
                }
            }
            *str = '\0';
        }
    }

    return err;
}
#endif /* (WOLFSSL_SP_MATH_ALL && !WOLFSSL_RSA_VERIFY_ONLY) || WC_MP_TO_RADIX */

#if (defined(WOLFSSL_SP_MATH_ALL) && !defined(WOLFSSL_RSA_VERIFY_ONLY)) || \
    defined(WOLFSSL_KEY_GEN) || defined(HAVE_COMP_KEY) || \
    defined(WC_MP_TO_RADIX)
/* Put the big-endian, decimal string encoding of a into str.
 *
 * Assumes str is large enough for result.
 * Use sp_radix_size() to calculate required length.
 *
 * @param  [in]   a    SP integer to convert.
 * @param  [out]  str  String to hold hex string result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a or str is NULL.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
int sp_todecimal(sp_int* a, char* str)
{
    int err = MP_OKAY;
    int i;
    int j;
    sp_int_digit d;

    if ((a == NULL) || (str == NULL)) {
        err = MP_VAL;
    }
    /* quick out if its zero */
    else if (sp_iszero(a) == MP_YES) {
        *str++ = '0';
        *str = '\0';
    }
    else {
        DECL_SP_INT(t, a->used + 1);

        ALLOC_SP_INT_SIZE(t, a->used + 1, err, NULL);
        if (err == MP_OKAY) {
            err = sp_copy(a, t);
        }
        if (err == MP_OKAY) {

        #ifdef WOLFSSL_SP_INT_NEGATIVE
            if (a->sign == MP_NEG) {
                *str = '-';
                str++;
            }
        #endif /* WOLFSSL_SP_INT_NEGATIVE */

            i = 0;
            while (!sp_iszero(t)) {
                sp_div_d(t, 10, t, &d);
                str[i++] = '0' + d;
            }
            str[i] = '\0';

            for (j = 0; j <= (i - 1) / 2; j++) {
                int c = (unsigned char)str[j];
                str[j] = str[i - 1 - j];
                str[i - 1 - j] = c;
            }
        }

        FREE_SP_INT(t, NULL);
    }

    return err;
}
#endif /* WOLFSSL_SP_MATH_ALL || WOLFSSL_KEY_GEN || HAVE_COMP_KEY */

#if (defined(WOLFSSL_SP_MATH_ALL) && !defined(WOLFSSL_RSA_VERIFY_ONLY)) || \
    defined(WC_MP_TO_RADIX)
/* Put the string version, big-endian, of a in str using the given radix.
 *
 * @param  [in]   a      SP integer to convert.
 * @param  [out]  str    String to hold hex string result.
 * @param  [in]   radix  Base of character.
 *                       Valid values: MP_RADIX_HEX, MP_RADIX_DEC.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a or str is NULL, or radix not supported.
 */
int sp_toradix(sp_int* a, char* str, int radix)
{
    int err = MP_OKAY;

    if ((a == NULL) || (str == NULL)) {
        err = MP_VAL;
    }
    else if (radix == MP_RADIX_HEX) {
        err = sp_tohex(a, str);
    }
#if defined(WOLFSSL_SP_MATH_ALL) || defined(WOLFSSL_KEY_GEN) || \
    defined(HAVE_COMP_KEY)
    else if (radix == MP_RADIX_DEC) {
        err = sp_todecimal(a, str);
    }
#endif /* WOLFSSL_SP_MATH_ALL || WOLFSSL_KEY_GEN || HAVE_COMP_KEY */
    else {
        err = MP_VAL;
    }

    return err;
}
#endif /* (WOLFSSL_SP_MATH_ALL && !WOLFSSL_RSA_VERIFY_ONLY) || WC_MP_TO_RADIX */

#if (defined(WOLFSSL_SP_MATH_ALL) && !defined(WOLFSSL_RSA_VERIFY_ONLY)) || \
    defined(WC_MP_TO_RADIX)
/* Calculate the length of the string version, big-endian, of a using the given
 * radix.
 *
 * @param  [in]   a      SP integer to convert.
 * @param  [in]   radix  Base of character.
 *                       Valid values: MP_RADIX_HEX, MP_RADIX_DEC.
 * @param  [out]  size   The number of characters in encoding.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a or size is NULL, or radix not supported.
 */
int sp_radix_size(sp_int* a, int radix, int* size)
{
    int err = MP_OKAY;

    if ((a == NULL) || (size == NULL)) {
        err = MP_VAL;
    }
    else if (radix == MP_RADIX_HEX) {
        if (a->used == 0) {
        #ifndef WC_DISABLE_RADIX_ZERO_PAD
            /* 00 and '\0' */
            *size = 2 + 1;
        #else
            /* Zero and '\0' */
            *size = 1 + 1;
        #endif /* WC_DISABLE_RADIX_ZERO_PAD */
        }
        else {
            int nibbles = (sp_count_bits(a) + 3) / 4;
        #ifndef WC_DISABLE_RADIX_ZERO_PAD
            if (nibbles & 1) {
                nibbles++;
            }
        #endif /* WC_DISABLE_RADIX_ZERO_PAD */
        #ifdef WOLFSSL_SP_INT_NEGATIVE
            if (a->sign == MP_NEG) {
                nibbles++;
            }
        #endif /* WOLFSSL_SP_INT_NEGATIVE */
            /* One more for \0 */
            *size = nibbles + 1;
        }
    }
#if defined(WOLFSSL_SP_MATH_ALL) || defined(WOLFSSL_KEY_GEN) || \
    defined(HAVE_COMP_KEY)
    else if (radix == MP_RADIX_DEC) {
        int i;
        sp_int_digit d;

        /* quick out if its zero */
        if (sp_iszero(a) == MP_YES) {
            /* Zero and '\0' */
            *size = 1 + 1;
        }
        else {
            DECL_SP_INT(t, a->used + 1);

            ALLOC_SP_INT(t, a->used + 1, err, NULL);
            if (err == MP_OKAY) {
        #if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_SP_NO_MALLOC)
                t->size = a->used + 1;
        #endif /* WOLFSSL_SMALL_STACK && !WOLFSSL_SP_NO_MALLOC */
                err = sp_copy(a, t);
            }

            if (err == MP_OKAY) {

                for (i = 0; !sp_iszero(t); i++) {
                    sp_div_d(t, 10, t, &d);
                }
            #ifdef WOLFSSL_SP_INT_NEGATIVE
                if (a->sign == MP_NEG) {
                    i++;
                }
            #endif /* WOLFSSL_SP_INT_NEGATIVE */
                /* One more for \0 */
                *size = i + 1;
            }

            FREE_SP_INT(t, NULL);
        }
    }
#endif /* WOLFSSL_SP_MATH_ALL || WOLFSSL_KEY_GEN || HAVE_COMP_KEY */
    else {
        err = MP_VAL;
    }

    return err;
}
#endif /* (WOLFSSL_SP_MATH_ALL && !WOLFSSL_RSA_VERIFY_ONLY) || WC_MP_TO_RADIX */

/***************************************
 * Prime number generation and checking.
 ***************************************/

#if defined(WOLFSSL_KEY_GEN) && (!defined(NO_DH) || !defined(NO_DSA)) && \
    !defined(WC_NO_RNG)
/* Generate a random prime for RSA only.
 *
 * @param  [out]  r     SP integer to hold result.
 * @param  [in]   len   Number of bytes in prime.
 * @param  [in]   rng   Random number generator.
 * @param  [in]   heap  Heap hint. Unused.
 *
 * @return  MP_OKAY on success
 * @return  MP_VAL when r or rng is NULL, length is not supported or random
 *          number generator fails.
 */
int sp_rand_prime(sp_int* r, int len, WC_RNG* rng, void* heap)
{
    static const int USE_BBS = 1;
    int   err = MP_OKAY;
    int   type = 0;
    int   isPrime = MP_NO;
#ifdef WOLFSSL_SP_MATH_ALL
    int   bits = 0;
#endif /* WOLFSSL_SP_MATH_ALL */

    (void)heap;

    /* Check NULL parameters and 0 is not prime so 0 bytes is invalid. */
    if ((r == NULL) || (rng == NULL) || (len == 0)) {
        err = MP_VAL;
    }

    if (err == MP_OKAY) {
        /* get type */
        if (len < 0) {
            type = USE_BBS;
            len = -len;
        }

    #ifndef WOLFSSL_SP_MATH_ALL
        /* For minimal maths, support only what's in SP and needed for DH. */
    #if defined(WOLFSSL_HAVE_SP_DH) && defined(WOLFSSL_KEY_GEN)
        if (len == 32) {
        }
        else
    #endif /* WOLFSSL_HAVE_SP_DH && WOLFSSL_KEY_GEN */
        /* Generate RSA primes that are half the modulus length. */
    #ifndef WOLFSSL_SP_NO_3072
        if ((len != 128) && (len != 192))
    #else
        if (len != 128)
    #endif /* WOLFSSL_SP_NO_3072 */
        {
            err = MP_VAL;
        }
    #endif /* !WOLFSSL_SP_MATH_ALL */

    #ifdef WOLFSSL_SP_INT_NEGATIVE
        r->sign = MP_ZPOS;
    #endif /* WOLFSSL_SP_INT_NEGATIVE */
        r->used = (len + SP_WORD_SIZEOF - 1) / SP_WORD_SIZEOF;
    #ifdef WOLFSSL_SP_MATH_ALL
        bits = (len * 8) & SP_WORD_MASK;
    #endif /* WOLFSSL_SP_MATH_ALL */
    }

    /* Assume the candidate is probably prime and then test until
     * it is proven composite. */
    while (err == MP_OKAY && isPrime == MP_NO) {
#ifdef SHOW_GEN
        printf(".");
        fflush(stdout);
#endif /* SHOW_GEN */
        /* generate value */
        err = wc_RNG_GenerateBlock(rng, (byte*)r->dp, len);
        if (err != 0) {
            err = MP_VAL;
            break;
        }

        /* munge bits */
#ifndef LITTLE_ENDIAN_ORDER
        ((byte*)(r->dp + r->used - 1))[0] |= 0x80 | 0x40;
#else
        ((byte*)r->dp)[len-1] |= 0x80 | 0x40;
#endif /* LITTLE_ENDIAN_ORDER */
        r->dp[0]              |= 0x01 | ((type & USE_BBS) ? 0x02 : 0x00);

#ifndef LITTLE_ENDIAN_ORDER
        if (((len * 8) & SP_WORD_MASK) != 0) {
            r->dp[r->used-1] >>= SP_WORD_SIZE - ((len * 8) & SP_WORD_MASK);
        }
#endif /* LITTLE_ENDIAN_ORDER */
#ifdef WOLFSSL_SP_MATH_ALL
        if (bits > 0) {
            r->dp[r->used - 1] &= ((sp_digit)1 << bits) - 1;
        }
#endif /* WOLFSSL_SP_MATH_ALL */

        /* test */
        /* Running Miller-Rabin up to 3 times gives us a 2^{-80} chance
         * of a 1024-bit candidate being a false positive, when it is our
         * prime candidate. (Note 4.49 of Handbook of Applied Cryptography.)
         * Using 8 because we've always used 8 */
        sp_prime_is_prime_ex(r, 8, &isPrime, rng);
    }

    return err;
}
#endif /* WOLFSSL_KEY_GEN && (!NO_DH || !NO_DSA) && !WC_NO_RNG */

#ifdef WOLFSSL_SP_PRIME_GEN
/* Miller-Rabin test of "a" to the base of "b" as described in
 * HAC pp. 139 Algorithm 4.24
 *
 * Sets result to 0 if definitely composite or 1 if probably prime.
 * Randomly the chance of error is no more than 1/4 and often
 * very much lower.
 *
 * @param  [in]   a       SP integer to check.
 * @param  [in]   b       SP integer that is a small prime.
 * @param  [out]  result  MP_YES when number is likey prime.
 *                        MP_NO otherwise.
 * @param  [in]   n1      SP integer temporary.
 * @param  [in]   y       SP integer temporary.
 * @param  [in]   r       SP integer temporary.
 *
 * @return  MP_OKAY on success.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
static int sp_prime_miller_rabin_ex(sp_int* a, sp_int* b, int* result,
                                    sp_int* n1, sp_int* y, sp_int* r)
{
    int s;
    int j;
    int err = MP_OKAY;

    /* default */
    *result = MP_NO;

    /* ensure b > 1 */
    if (sp_cmp_d(b, 1) == MP_GT) {
        /* get n1 = a - 1 */
        (void)sp_copy(a, n1);
        _sp_sub_d(n1, 1, n1);
        /* set 2**s * r = n1 */
        (void)sp_copy(n1, r);

        /* count the number of least significant bits
         * which are zero
         */
        s = sp_cnt_lsb(r);

        /* now divide n - 1 by 2**s */
        sp_rshb(r, s, r);

        /* compute y = b**r mod a */
        err = sp_exptmod(b, r, a, y);

        if (err == MP_OKAY) {
            /* probably prime until shown otherwise */
            *result = MP_YES;

            /* if y != 1 and y != n1 do */
            if ((sp_cmp_d(y, 1) != MP_EQ) && (_sp_cmp(y, n1) != MP_EQ)) {
                j = 1;
                /* while j <= s-1 and y != n1 */
                while ((j <= (s - 1)) && (_sp_cmp(y, n1) != MP_EQ)) {
                    err = sp_sqrmod(y, a, y);
                    if (err != MP_OKAY) {
                        break;
                    }

                    /* if y == 1 then composite */
                    if (sp_cmp_d(y, 1) == MP_EQ) {
                        *result = MP_NO;
                        break;
                    }
                    ++j;
                }

                /* if y != n1 then composite */
                if ((*result == MP_YES) && (_sp_cmp(y, n1) != MP_EQ)) {
                    *result = MP_NO;
                }
            }
        }
    }

    return err;
}

/* Miller-Rabin test of "a" to the base of "b" as described in
 * HAC pp. 139 Algorithm 4.24
 *
 * Sets result to 0 if definitely composite or 1 if probably prime.
 * Randomly the chance of error is no more than 1/4 and often
 * very much lower.
 *
 * @param  [in]   a       SP integer to check.
 * @param  [in]   b       SP integer that is a small prime.
 * @param  [out]  result  MP_YES when number is likey prime.
 *                        MP_NO otherwise.
 *
 * @return  MP_OKAY on success.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
static int sp_prime_miller_rabin(sp_int* a, sp_int* b, int* result)
{
    int err = MP_OKAY;
    sp_int *n1;
    sp_int *y;
    sp_int *r;
    DECL_SP_INT_ARRAY(t, a->used * 2 + 1, 3);

    ALLOC_SP_INT_ARRAY(t, a->used * 2 + 1, 3, err, NULL);
    if (err == MP_OKAY) {
        n1 = t[0];
        y  = t[1];
        r  = t[2];

        /* Only 'y' needs to be twice as big. */
        sp_init_size(n1, a->used * 2 + 1);
        sp_init_size(y, a->used * 2 + 1);
        sp_init_size(r, a->used * 2 + 1);

        err = sp_prime_miller_rabin_ex(a, b, result, n1, y, r);

        sp_clear(n1);
        sp_clear(y);
        sp_clear(r);
    }

    FREE_SP_INT_ARRAY(t, NULL);
    return err;
}

#if SP_WORD_SIZE == 8
/* Number of pre-computed primes. First n primes - fitting in a digit. */
#define SP_PRIME_SIZE      54

static const sp_int_digit sp_primes[SP_PRIME_SIZE] = {
    0x02, 0x03, 0x05, 0x07, 0x0B, 0x0D, 0x11, 0x13,
    0x17, 0x1D, 0x1F, 0x25, 0x29, 0x2B, 0x2F, 0x35,
    0x3B, 0x3D, 0x43, 0x47, 0x49, 0x4F, 0x53, 0x59,
    0x61, 0x65, 0x67, 0x6B, 0x6D, 0x71, 0x7F, 0x83,
    0x89, 0x8B, 0x95, 0x97, 0x9D, 0xA3, 0xA7, 0xAD,
    0xB3, 0xB5, 0xBF, 0xC1, 0xC5, 0xC7, 0xD3, 0xDF,
    0xE3, 0xE5, 0xE9, 0xEF, 0xF1, 0xFB
};
#else
/* Number of pre-computed primes. First n primes. */
#define SP_PRIME_SIZE      256

/* The first 256 primes. */
static const sp_int_digit sp_primes[SP_PRIME_SIZE] = {
    0x0002, 0x0003, 0x0005, 0x0007, 0x000B, 0x000D, 0x0011, 0x0013,
    0x0017, 0x001D, 0x001F, 0x0025, 0x0029, 0x002B, 0x002F, 0x0035,
    0x003B, 0x003D, 0x0043, 0x0047, 0x0049, 0x004F, 0x0053, 0x0059,
    0x0061, 0x0065, 0x0067, 0x006B, 0x006D, 0x0071, 0x007F, 0x0083,
    0x0089, 0x008B, 0x0095, 0x0097, 0x009D, 0x00A3, 0x00A7, 0x00AD,
    0x00B3, 0x00B5, 0x00BF, 0x00C1, 0x00C5, 0x00C7, 0x00D3, 0x00DF,
    0x00E3, 0x00E5, 0x00E9, 0x00EF, 0x00F1, 0x00FB, 0x0101, 0x0107,
    0x010D, 0x010F, 0x0115, 0x0119, 0x011B, 0x0125, 0x0133, 0x0137,

    0x0139, 0x013D, 0x014B, 0x0151, 0x015B, 0x015D, 0x0161, 0x0167,
    0x016F, 0x0175, 0x017B, 0x017F, 0x0185, 0x018D, 0x0191, 0x0199,
    0x01A3, 0x01A5, 0x01AF, 0x01B1, 0x01B7, 0x01BB, 0x01C1, 0x01C9,
    0x01CD, 0x01CF, 0x01D3, 0x01DF, 0x01E7, 0x01EB, 0x01F3, 0x01F7,
    0x01FD, 0x0209, 0x020B, 0x021D, 0x0223, 0x022D, 0x0233, 0x0239,
    0x023B, 0x0241, 0x024B, 0x0251, 0x0257, 0x0259, 0x025F, 0x0265,
    0x0269, 0x026B, 0x0277, 0x0281, 0x0283, 0x0287, 0x028D, 0x0293,
    0x0295, 0x02A1, 0x02A5, 0x02AB, 0x02B3, 0x02BD, 0x02C5, 0x02CF,

    0x02D7, 0x02DD, 0x02E3, 0x02E7, 0x02EF, 0x02F5, 0x02F9, 0x0301,
    0x0305, 0x0313, 0x031D, 0x0329, 0x032B, 0x0335, 0x0337, 0x033B,
    0x033D, 0x0347, 0x0355, 0x0359, 0x035B, 0x035F, 0x036D, 0x0371,
    0x0373, 0x0377, 0x038B, 0x038F, 0x0397, 0x03A1, 0x03A9, 0x03AD,
    0x03B3, 0x03B9, 0x03C7, 0x03CB, 0x03D1, 0x03D7, 0x03DF, 0x03E5,
    0x03F1, 0x03F5, 0x03FB, 0x03FD, 0x0407, 0x0409, 0x040F, 0x0419,
    0x041B, 0x0425, 0x0427, 0x042D, 0x043F, 0x0443, 0x0445, 0x0449,
    0x044F, 0x0455, 0x045D, 0x0463, 0x0469, 0x047F, 0x0481, 0x048B,

    0x0493, 0x049D, 0x04A3, 0x04A9, 0x04B1, 0x04BD, 0x04C1, 0x04C7,
    0x04CD, 0x04CF, 0x04D5, 0x04E1, 0x04EB, 0x04FD, 0x04FF, 0x0503,
    0x0509, 0x050B, 0x0511, 0x0515, 0x0517, 0x051B, 0x0527, 0x0529,
    0x052F, 0x0551, 0x0557, 0x055D, 0x0565, 0x0577, 0x0581, 0x058F,
    0x0593, 0x0595, 0x0599, 0x059F, 0x05A7, 0x05AB, 0x05AD, 0x05B3,
    0x05BF, 0x05C9, 0x05CB, 0x05CF, 0x05D1, 0x05D5, 0x05DB, 0x05E7,
    0x05F3, 0x05FB, 0x0607, 0x060D, 0x0611, 0x0617, 0x061F, 0x0623,
    0x062B, 0x062F, 0x063D, 0x0641, 0x0647, 0x0649, 0x064D, 0x0653
};
#endif

/* Check whether a is prime.
 * Checks against a number of small primes and does t iterations of
 * Miller-Rabin.
 *
 * @param  [in]   a       SP integer to check.
 * @param  [in]   t       Number of iterations of Miller-Rabin test to perform.
 * @param  [out]  result  MP_YES when number is prime.
 *                        MP_NO otherwise.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a or result is NULL, or t is out of range.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
int sp_prime_is_prime(sp_int* a, int t, int* result)
{
    int         err = MP_OKAY;
    int         i;
    int         haveRes = 0;
    sp_int_digit d;
    DECL_SP_INT(b, 2);

    if ((a == NULL) || (result == NULL)) {
        if (result != NULL) {
            *result = MP_NO;
        }
        err = MP_VAL;
    }

    if ((err == MP_OKAY) && ((t <= 0) || (t > SP_PRIME_SIZE))) {
        *result = MP_NO;
        err = MP_VAL;
    }

    if ((err == MP_OKAY) && sp_isone(a)) {
        *result = MP_NO;
        haveRes = 1;
    }

    SAVE_VECTOR_REGISTERS(err = _svr_ret;);

    if ((err == MP_OKAY) && (!haveRes) && (a->used == 1)) {
        /* check against primes table */
        for (i = 0; i < SP_PRIME_SIZE; i++) {
            if (sp_cmp_d(a, sp_primes[i]) == MP_EQ) {
                *result = MP_YES;
                haveRes = 1;
                break;
            }
        }
    }

    if ((err == MP_OKAY) && (!haveRes)) {
        /* do trial division */
        for (i = 0; i < SP_PRIME_SIZE; i++) {
            err = sp_mod_d(a, sp_primes[i], &d);
            if ((err != MP_OKAY) || (d == 0)) {
                *result = MP_NO;
                haveRes = 1;
                break;
            }
        }
    }

    if ((err == MP_OKAY) && (!haveRes)) {
        ALLOC_SP_INT(b, 1, err, NULL);
        if (err == MP_OKAY) {
            /* now do 't' miller rabins */
            sp_init_size(b, 1);
            for (i = 0; i < t; i++) {
                sp_set(b, sp_primes[i]);
                err = sp_prime_miller_rabin(a, b, result);
                if ((err != MP_OKAY) || (*result == MP_NO)) {
                    break;
                }
            }
        }
     }

     RESTORE_VECTOR_REGISTERS();

     FREE_SP_INT(b, NULL);
     return err;
}

/* Check whether a is prime.
 * Checks against a number of small primes and does t iterations of
 * Miller-Rabin.
 *
 * @param  [in]   a       SP integer to check.
 * @param  [in]   t       Number of iterations of Miller-Rabin test to perform.
 * @param  [out]  result  MP_YES when number is prime.
 *                        MP_NO otherwise.
 * @param  [in]   rng     Random number generator for Miller-Rabin testing.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a, result or rng is NULL.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
int sp_prime_is_prime_ex(sp_int* a, int t, int* result, WC_RNG* rng)
{
    int err = MP_OKAY;
    int ret = MP_YES;
    int haveRes = 0;
    int i;
#ifndef WC_NO_RNG
    sp_int *b = NULL;
    sp_int *c = NULL;
    sp_int *n1 = NULL;
    sp_int *y = NULL;
    sp_int *r = NULL;
#endif /* WC_NO_RNG */

    if ((a == NULL) || (result == NULL) || (rng == NULL)) {
        err = MP_VAL;
    }

    if ((err == MP_OKAY) && sp_isone(a)) {
        ret = MP_NO;
        haveRes = 1;
    }

    SAVE_VECTOR_REGISTERS(err = _svr_ret;);

    if ((err == MP_OKAY) && (!haveRes) && (a->used == 1)) {
        /* check against primes table */
        for (i = 0; i < SP_PRIME_SIZE; i++) {
            if (sp_cmp_d(a, sp_primes[i]) == MP_EQ) {
                ret = MP_YES;
                haveRes = 1;
                break;
            }
        }
    }

    if ((err == MP_OKAY) && (!haveRes)) {
        sp_int_digit d;

        /* do trial division */
        for (i = 0; i < SP_PRIME_SIZE; i++) {
            err = sp_mod_d(a, sp_primes[i], &d);
            if ((err != MP_OKAY) || (d == 0)) {
                ret = MP_NO;
                haveRes = 1;
                break;
            }
        }
    }

#ifndef WC_NO_RNG
    /* now do a miller rabin with up to t random numbers, this should
     * give a (1/4)^t chance of a false prime. */
    if ((err == MP_OKAY) && (!haveRes)) {
        int bits = sp_count_bits(a);
        word32 baseSz = (bits + 7) / 8;
        DECL_SP_INT_ARRAY(d, a->used * 2 + 1, 5);

        ALLOC_SP_INT_ARRAY(d, a->used * 2 + 1, 5, err, NULL);
        if (err == MP_OKAY) {
            b  = d[0];
            c  = d[1];
            n1 = d[2];
            y  = d[3];
            r  = d[4];

            /* Only 'y' needs to be twice as big. */
            sp_init_size(b , a->used * 2 + 1);
            sp_init_size(c , a->used * 2 + 1);
            sp_init_size(n1, a->used * 2 + 1);
            sp_init_size(y , a->used * 2 + 1);
            sp_init_size(r , a->used * 2 + 1);

            _sp_sub_d(a, 2, c);

            bits &= SP_WORD_MASK;

            while (t > 0) {
                err = wc_RNG_GenerateBlock(rng, (byte*)b->dp, baseSz);
                if (err != MP_OKAY) {
                    break;
                }
                b->used = a->used;
                /* Ensure the top word has no more bits than necessary. */
                if (bits > 0) {
                    b->dp[b->used - 1] &= ((sp_digit)1 << bits) - 1;
                }

                if ((sp_cmp_d(b, 2) != MP_GT) || (_sp_cmp(b, c) != MP_LT)) {
                    continue;
                }

                err = sp_prime_miller_rabin_ex(a, b, &ret, n1, y, r);
                if ((err != MP_OKAY) || (ret == MP_NO)) {
                    break;
                }

                t--;
            }

            sp_clear(n1);
            sp_clear(y);
            sp_clear(r);
            sp_clear(b);
            sp_clear(c);
        }

        FREE_SP_INT_ARRAY(d, NULL);
    }
#else
    (void)t;
#endif /* !WC_NO_RNG */

    if (result != NULL) {
        *result = ret;
    }

    RESTORE_VECTOR_REGISTERS();

    return err;
}
#endif /* WOLFSSL_SP_PRIME_GEN */

#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)

/* Calculates the Greatest Common Denominator (GCD) of a and b into r.
 *
 * a and b are positive integers.
 *
 * @param  [in]   a  SP integer of first operand.
 * @param  [in]   b  SP integer of second operand.
 * @param  [out]  r  SP integer to hold result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a, b or r is NULL or too large.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
int sp_gcd(sp_int* a, sp_int* b, sp_int* r)
{
    int err = MP_OKAY;

    if ((a == NULL) || (b == NULL) || (r == NULL)) {
        err = MP_VAL;
    }
    else if (a->used >= SP_INT_DIGITS || b->used >= SP_INT_DIGITS) {
        err = MP_VAL;
    }
    else if (sp_iszero(a)) {
        /* GCD of 0 and 0 is undefined as all integers divide 0. */
        if (sp_iszero(b)) {
            err = MP_VAL;
        }
        else {
            err = sp_copy(b, r);
        }
    }
    else if (sp_iszero(b)) {
        err = sp_copy(a, r);
    }
    else {
        sp_int* u = NULL;
        sp_int* v = NULL;
        sp_int* t = NULL;
        int used = (a->used >= b->used) ? a->used + 1 : b->used + 1;
        DECL_SP_INT_ARRAY(d, used, 3);

        SAVE_VECTOR_REGISTERS(err = _svr_ret;);

        ALLOC_SP_INT_ARRAY(d, used, 3, err, NULL);

        if (err == MP_OKAY) {
            u = d[0];
            v = d[1];
            t = d[2];
            sp_init_size(u, used);
            sp_init_size(v, used);
            sp_init_size(t, used);

            if (_sp_cmp(a, b) != MP_LT) {
                sp_copy(b, u);
                /* First iteration - u = a, v = b */
                if (b->used == 1) {
                    err = sp_mod_d(a, b->dp[0], &v->dp[0]);
                    if (err == MP_OKAY) {
                        v->used = (v->dp[0] != 0);
                    }
                }
                else {
                    err = sp_mod(a, b, v);
                }
            }
            else {
                sp_copy(a, u);
                /* First iteration - u = b, v = a */
                if (a->used == 1) {
                    err = sp_mod_d(b, a->dp[0], &v->dp[0]);
                    if (err == MP_OKAY) {
                        v->used = (v->dp[0] != 0);
                    }
                }
                else {
                    err = sp_mod(b, a, v);
                }
            }
        }

        if (err == MP_OKAY) {
#ifdef WOLFSSL_SP_INT_NEGATIVE
            u->sign = MP_ZPOS;
            v->sign = MP_ZPOS;
#endif /* WOLFSSL_SP_INT_NEGATIVE */

            while (!sp_iszero(v)) {
                if (v->used == 1) {
                    err = sp_mod_d(u, v->dp[0], &t->dp[0]);
                    if (err == MP_OKAY) {
                        t->used = (t->dp[0] != 0);
                    }
                }
                else {
                    err = sp_mod(u, v, t);
                }
                if (err != MP_OKAY) {
                    break;
                }
                sp_copy(v, u);
                sp_copy(t, v);
            }
            if (err == MP_OKAY)
                err = sp_copy(u, r);
        }

        FREE_SP_INT_ARRAY(d, NULL);

        RESTORE_VECTOR_REGISTERS();
    }

    return err;
}

#endif /* WOLFSSL_SP_MATH_ALL && !NO_RSA && WOLFSSL_KEY_GEN */

#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN) && !defined(WC_RSA_BLINDING)

/* Calculates the Lowest Common Multiple (LCM) of a and b and stores in r.
 *
 * a and b are positive integers.
 *
 * @param  [in]   a  SP integer of first operand.
 * @param  [in]   b  SP integer of second operand.
 * @param  [out]  r  SP integer to hold result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a, b or r is NULL; or a or b is zero.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
int sp_lcm(sp_int* a, sp_int* b, sp_int* r)
{
    int err = MP_OKAY;
    int used = ((a == NULL) || (b == NULL)) ? 1 :
                   (a->used >= b->used ? a->used + 1: b->used + 1);
    DECL_SP_INT_ARRAY(t, used, 2);

    if ((a == NULL) || (b == NULL) || (r == NULL)) {
        err = MP_VAL;
    }

    /* LCM of 0 and any number is undefined as 0 is not in the set of values
     * being used.
     */
    if ((err == MP_OKAY) && (mp_iszero(a) || mp_iszero(b))) {
        err = MP_VAL;
    }

    ALLOC_SP_INT_ARRAY(t, used, 2, err, NULL);

    if (err == MP_OKAY) {
        sp_init_size(t[0], used);
        sp_init_size(t[1], used);

        SAVE_VECTOR_REGISTERS(err = _svr_ret;);

        if (err == MP_OKAY)
            err = sp_gcd(a, b, t[0]);

        if (err == MP_OKAY) {
            if (_sp_cmp_abs(a, b) == MP_GT) {
                err = sp_div(a, t[0], t[1], NULL);
                if (err == MP_OKAY) {
                    err = sp_mul(b, t[1], r);
                }
            }
            else {
                err = sp_div(b, t[0], t[1], NULL);
                if (err == MP_OKAY) {
                    err = sp_mul(a, t[1], r);
                }
            }
        }

        RESTORE_VECTOR_REGISTERS();
    }

    FREE_SP_INT_ARRAY(t, NULL);
    return err;
}

#endif /* WOLFSSL_SP_MATH_ALL && !NO_RSA && WOLFSSL_KEY_GEN */

/* Returns the run time settings.
 *
 * @return  Settings value.
 */
word32 CheckRunTimeSettings(void)
{
    return CTC_SETTINGS;
}

/* Returns the fast math settings.
 *
 * @return  Setting - number of bits in a digit.
 */
word32 CheckRunTimeFastMath(void)
{
    return SP_WORD_SIZE;
}

#endif /* WOLFSSL_SP_MATH || WOLFSSL_SP_MATH_ALL */
