/* armv8-32-frodokem-asm
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

/* Generated using (from wolfssl):
 *   cd ../scripts
 *   ruby ./frodokem/frodokem.rb arm32 \
 *       ../wolfssl/wolfcrypt/src/port/arm/armv8-32-frodokem-asm.c
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources_asm.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifdef WOLFSSL_ARMASM
#if !defined(__aarch64__) && !defined(WOLFSSL_ARMASM_THUMB2)
#ifdef WOLFSSL_ARMASM_INLINE

#ifdef __IAR_SYSTEMS_ICC__
#define __asm__        asm
#define __volatile__   volatile
#define WOLFSSL_NO_VAR_ASSIGN_REG
#endif /* __IAR_SYSTEMS_ICC__ */
#ifdef __KEIL__
#define __asm__        __asm
#define __volatile__   volatile
#endif /* __KEIL__ */
#ifdef __ghs__
#define __asm__        __asm
#define __volatile__
#define WOLFSSL_NO_VAR_ASSIGN_REG
#endif /* __ghs__ */

#include <wolfssl/wolfcrypt/wc_frodokem_mat.h>

#ifdef WOLFSSL_HAVE_FRODOKEM
#ifndef WOLFSSL_ARMASM_NO_NEON
void frodokem_add_neon(word16* a_p, const word16* b_p, int qmask_p);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void frodokem_add_neon(word16* a_p, const word16* b_p,
    int qmask_p)
#else
WC_OMIT_FRAME_POINTER void frodokem_add_neon(word16* a, const word16* b,
    int qmask)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word16* a __asm__ ("r0") = (word16*)a_p;
    register const word16* b __asm__ ("r1") = (const word16*)b_p;
    register int qmask __asm__ ("r2") = (int)qmask_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "vdup.16	q2, %[qmask]\n\t"
        "mov	r3, #8\n\t"
        "\n"
    "L_frodokem_add_neon_blk_%=:\n\t"
        "vld1.16	{d0-d1}, [%[a]]\n\t"
        "vld1.16	{d2-d3}, [%[b]]!\n\t"
        "vadd.i16	q0, q0, q1\n\t"
        "vand	q0, q0, q2\n\t"
        "vst1.16	{d0-d1}, [%[a]]!\n\t"
        "subs	r3, r3, #1\n\t"
        "bne	L_frodokem_add_neon_blk_%=\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [a] "+r" (a), [b] "+r" (b), [qmask] "+r" (qmask)
        :
#else
        :
        : [a] "r" (a), [b] "r" (b), [qmask] "r" (qmask)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r3", "q0", "q1", "q2"
    );
}

void frodokem_sample_neon(word16* mat_p, int cnt_p, const word16* cdf_p,
    int cdflen_p);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void frodokem_sample_neon(word16* mat_p, int cnt_p,
    const word16* cdf_p, int cdflen_p)
#else
WC_OMIT_FRAME_POINTER void frodokem_sample_neon(word16* mat, int cnt,
    const word16* cdf, int cdflen)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word16* mat __asm__ ("r0") = (word16*)mat_p;
    register int cnt __asm__ ("r1") = (int)cnt_p;
    register const word16* cdf __asm__ ("r2") = (const word16*)cdf_p;
    register int cdflen __asm__ ("r3") = (int)cdflen_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "\n"
    "L_frodokem_sample_neon_blk_%=:\n\t"
        "vld1.16	{d0-d1}, [%[mat]]\n\t"
        "vshr.u16	q1, q0, #1\n\t"
        "vmov.i16	q2, #1\n\t"
        "vand	q2, q2, q0\n\t"
        "vmov.i16	q3, #0\n\t"
        "mov	r12, %[cdf]\n\t"
        "mov	lr, %[cdflen]\n\t"
        "\n"
    "L_frodokem_sample_neon_cdf_%=:\n\t"
        "ldrh	r4, [r12]\n\t"
        "add	r12, r12, #2\n\t"
        "vdup.16	q4, r4\n\t"
        "vsub.i16	q4, q4, q1\n\t"
        "vshr.u16	q4, q4, #15\n\t"
        "vadd.i16	q3, q3, q4\n\t"
        "subs	lr, lr, #1\n\t"
        "bne	L_frodokem_sample_neon_cdf_%=\n\t"
        "vneg.s16	q5, q2\n\t"
        "veor	q3, q3, q5\n\t"
        "vadd.i16	q3, q3, q2\n\t"
        "vst1.16	{d6-d7}, [%[mat]]!\n\t"
        "subs	%[cnt], %[cnt], #8\n\t"
        "bne	L_frodokem_sample_neon_blk_%=\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [mat] "+r" (mat), [cnt] "+r" (cnt), [cdf] "+r" (cdf),
          [cdflen] "+r" (cdflen)
        :
#else
        :
        : [mat] "r" (mat), [cnt] "r" (cnt), [cdf] "r" (cdf),
          [cdflen] "r" (cdflen)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r12", "lr", "r4", "q0", "q1", "q2", "q3", "q4", "q5"
    );
}

void frodokem_sa_accum_neon(word16* out_p, const word16* s_p,
    const word16* row_p, int j_p, int n_p);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void frodokem_sa_accum_neon(word16* out_p,
    const word16* s_p, const word16* row_p, int j_p, int n_p)
#else
WC_OMIT_FRAME_POINTER void frodokem_sa_accum_neon(word16* out, const word16* s,
    const word16* row, int j, int n)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word16* out __asm__ ("r0") = (word16*)out_p;
    register const word16* s __asm__ ("r1") = (const word16*)s_p;
    register const word16* row __asm__ ("r2") = (const word16*)row_p;
    register int j __asm__ ("r3") = (int)j_p;
    register int n __asm__ ("r12") = (int)n_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "push	{%[n]}\n\t"
        "ldr	r12, [sp]\n\t"
        "lsl	lr, r12, #1\n\t"
        "add	r4, %[s], %[j], lsl #1\n\t"
        "mov	r7, #8\n\t"
        "\n"
    "L_frodokem_sa_accum_neon_i_%=:\n\t"
        "ldrh	r8, [r4]\n\t"
        "vdup.16	q0, r8\n\t"
        "add	r4, r4, lr\n\t"
        "mov	r5, %[row]\n\t"
        "lsr	r6, lr, #4\n\t"
        "\n"
    "L_frodokem_sa_accum_neon_k_%=:\n\t"
        "vld1.16	{d2-d3}, [%[out]]\n\t"
        "vld1.16	{d4-d5}, [r5]!\n\t"
        "vmla.i16	q1, q2, q0\n\t"
        "vst1.16	{d2-d3}, [%[out]]!\n\t"
        "subs	r6, r6, #1\n\t"
        "bne	L_frodokem_sa_accum_neon_k_%=\n\t"
        "subs	r7, r7, #1\n\t"
        "bne	L_frodokem_sa_accum_neon_i_%=\n\t"
        "pop	{%[n]}\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [out] "+r" (out), [s] "+r" (s), [row] "+r" (row), [j] "+r" (j),
          [n] "+r" (n)
        :
#else
        :
        : [out] "r" (out), [s] "r" (s), [row] "r" (row), [j] "r" (j),
          [n] "r" (n)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "lr", "r4", "r5", "r6", "r7", "r8", "q0", "q1", "q2"
    );
}

void frodokem_as_accum_neon(word16* out_p, const word16* s_p,
    const word16* row_p, int i_p, int n_p);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void frodokem_as_accum_neon(word16* out_p,
    const word16* s_p, const word16* row_p, int i_p, int n_p)
#else
WC_OMIT_FRAME_POINTER void frodokem_as_accum_neon(word16* out, const word16* s,
    const word16* row, int i, int n)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word16* out __asm__ ("r0") = (word16*)out_p;
    register const word16* s __asm__ ("r1") = (const word16*)s_p;
    register const word16* row __asm__ ("r2") = (const word16*)row_p;
    register int i __asm__ ("r3") = (int)i_p;
    register int n __asm__ ("r12") = (int)n_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "push	{%[n]}\n\t"
        "ldr	r12, [sp]\n\t"
        "lsl	lr, r12, #1\n\t"
        "add	r7, %[out], %[i], lsl #4\n\t"
        "mov	r6, %[row]\n\t"
        "mov	r4, %[s]\n\t"
        "veor	q0, q0, q0\n\t"
        "veor	q1, q1, q1\n\t"
        "veor	q2, q2, q2\n\t"
        "veor	q3, q3, q3\n\t"
        "veor	q4, q4, q4\n\t"
        "veor	q5, q5, q5\n\t"
        "veor	q6, q6, q6\n\t"
        "veor	q7, q7, q7\n\t"
        "lsr	r8, lr, #4\n\t"
        "\n"
    "L_frodokem_as_accum_neon_k_%=:\n\t"
        "vld1.16	{d16-d17}, [r6]!\n\t"
        "mov	r5, r4\n\t"
        "vld1.16	{d18-d19}, [r5]\n\t"
        "vmla.i16	q0, q8, q9\n\t"
        "add	r5, r5, lr\n\t"
        "vld1.16	{d18-d19}, [r5]\n\t"
        "vmla.i16	q1, q8, q9\n\t"
        "add	r5, r5, lr\n\t"
        "vld1.16	{d18-d19}, [r5]\n\t"
        "vmla.i16	q2, q8, q9\n\t"
        "add	r5, r5, lr\n\t"
        "vld1.16	{d18-d19}, [r5]\n\t"
        "vmla.i16	q3, q8, q9\n\t"
        "add	r5, r5, lr\n\t"
        "vld1.16	{d18-d19}, [r5]\n\t"
        "vmla.i16	q4, q8, q9\n\t"
        "add	r5, r5, lr\n\t"
        "vld1.16	{d18-d19}, [r5]\n\t"
        "vmla.i16	q5, q8, q9\n\t"
        "add	r5, r5, lr\n\t"
        "vld1.16	{d18-d19}, [r5]\n\t"
        "vmla.i16	q6, q8, q9\n\t"
        "add	r5, r5, lr\n\t"
        "vld1.16	{d18-d19}, [r5]\n\t"
        "vmla.i16	q7, q8, q9\n\t"
        "add	r5, r5, lr\n\t"
        "add	r4, r4, #16\n\t"
        "subs	r8, r8, #1\n\t"
        "bne	L_frodokem_as_accum_neon_k_%=\n\t"
        "vadd.i16	d18, d0, d1\n\t"
        "vpadd.i16	d18, d18, d18\n\t"
        "vpadd.i16	d18, d18, d18\n\t"
        "vmov.u16	r9, d18[0]\n\t"
        "vmov.16	d20[0], r9\n\t"
        "vadd.i16	d18, d2, d3\n\t"
        "vpadd.i16	d18, d18, d18\n\t"
        "vpadd.i16	d18, d18, d18\n\t"
        "vmov.u16	r9, d18[0]\n\t"
        "vmov.16	d20[1], r9\n\t"
        "vadd.i16	d18, d4, d5\n\t"
        "vpadd.i16	d18, d18, d18\n\t"
        "vpadd.i16	d18, d18, d18\n\t"
        "vmov.u16	r9, d18[0]\n\t"
        "vmov.16	d20[2], r9\n\t"
        "vadd.i16	d18, d6, d7\n\t"
        "vpadd.i16	d18, d18, d18\n\t"
        "vpadd.i16	d18, d18, d18\n\t"
        "vmov.u16	r9, d18[0]\n\t"
        "vmov.16	d20[3], r9\n\t"
        "vadd.i16	d18, d8, d9\n\t"
        "vpadd.i16	d18, d18, d18\n\t"
        "vpadd.i16	d18, d18, d18\n\t"
        "vmov.u16	r9, d18[0]\n\t"
        "vmov.16	d21[0], r9\n\t"
        "vadd.i16	d18, d10, d11\n\t"
        "vpadd.i16	d18, d18, d18\n\t"
        "vpadd.i16	d18, d18, d18\n\t"
        "vmov.u16	r9, d18[0]\n\t"
        "vmov.16	d21[1], r9\n\t"
        "vadd.i16	d18, d12, d13\n\t"
        "vpadd.i16	d18, d18, d18\n\t"
        "vpadd.i16	d18, d18, d18\n\t"
        "vmov.u16	r9, d18[0]\n\t"
        "vmov.16	d21[2], r9\n\t"
        "vadd.i16	d18, d14, d15\n\t"
        "vpadd.i16	d18, d18, d18\n\t"
        "vpadd.i16	d18, d18, d18\n\t"
        "vmov.u16	r9, d18[0]\n\t"
        "vmov.16	d21[3], r9\n\t"
        "vld1.16	{d22-d23}, [r7]\n\t"
        "vadd.i16	q10, q10, q11\n\t"
        "vst1.16	{d20-d21}, [r7]\n\t"
        "pop	{%[n]}\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [out] "+r" (out), [s] "+r" (s), [row] "+r" (row), [i] "+r" (i),
          [n] "+r" (n)
        :
#else
        :
        : [out] "r" (out), [s] "r" (s), [row] "r" (row), [i] "r" (i),
          [n] "r" (n)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "lr", "r4", "r5", "r6", "r7", "r8", "r9", "q0", "q1",
            "q2", "q3", "q4", "q5", "q6", "q7", "q8", "q9", "q10", "q11"
    );
}

void frodokem_mul_bs_neon(word16* out_p, const word16* b_p, const word16* s_p,
    int n_p, int qmask_p);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void frodokem_mul_bs_neon(word16* out_p,
    const word16* b_p, const word16* s_p, int n_p, int qmask_p)
#else
WC_OMIT_FRAME_POINTER void frodokem_mul_bs_neon(word16* out, const word16* b,
    const word16* s, int n, int qmask)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word16* out __asm__ ("r0") = (word16*)out_p;
    register const word16* b __asm__ ("r1") = (const word16*)b_p;
    register const word16* s __asm__ ("r2") = (const word16*)s_p;
    register int n __asm__ ("r3") = (int)n_p;
    register int qmask __asm__ ("r12") = (int)qmask_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "push	{%[qmask]}\n\t"
        "ldr	lr, [sp]\n\t"
        "lsl	r12, %[n], #1\n\t"
        "vdup.16	q11, lr\n\t"
        "mov	r7, %[out]\n\t"
        "mov	r4, %[b]\n\t"
        "mov	r9, #8\n\t"
        "\n"
    "L_frodokem_mul_bs_neon_r_%=:\n\t"
        "mov	r5, %[s]\n\t"
        "veor	q0, q0, q0\n\t"
        "veor	q1, q1, q1\n\t"
        "veor	q2, q2, q2\n\t"
        "veor	q3, q3, q3\n\t"
        "veor	q4, q4, q4\n\t"
        "veor	q5, q5, q5\n\t"
        "veor	q6, q6, q6\n\t"
        "veor	q7, q7, q7\n\t"
        "lsr	r8, r12, #4\n\t"
        "\n"
    "L_frodokem_mul_bs_neon_k_%=:\n\t"
        "vld1.16	{d16-d17}, [r4]!\n\t"
        "mov	r6, r5\n\t"
        "vld1.16	{d18-d19}, [r6]\n\t"
        "vmla.i16	q0, q8, q9\n\t"
        "add	r6, r6, r12\n\t"
        "vld1.16	{d18-d19}, [r6]\n\t"
        "vmla.i16	q1, q8, q9\n\t"
        "add	r6, r6, r12\n\t"
        "vld1.16	{d18-d19}, [r6]\n\t"
        "vmla.i16	q2, q8, q9\n\t"
        "add	r6, r6, r12\n\t"
        "vld1.16	{d18-d19}, [r6]\n\t"
        "vmla.i16	q3, q8, q9\n\t"
        "add	r6, r6, r12\n\t"
        "vld1.16	{d18-d19}, [r6]\n\t"
        "vmla.i16	q4, q8, q9\n\t"
        "add	r6, r6, r12\n\t"
        "vld1.16	{d18-d19}, [r6]\n\t"
        "vmla.i16	q5, q8, q9\n\t"
        "add	r6, r6, r12\n\t"
        "vld1.16	{d18-d19}, [r6]\n\t"
        "vmla.i16	q6, q8, q9\n\t"
        "add	r6, r6, r12\n\t"
        "vld1.16	{d18-d19}, [r6]\n\t"
        "vmla.i16	q7, q8, q9\n\t"
        "add	r6, r6, r12\n\t"
        "add	r5, r5, #16\n\t"
        "subs	r8, r8, #1\n\t"
        "bne	L_frodokem_mul_bs_neon_k_%=\n\t"
        "vadd.i16	d18, d0, d1\n\t"
        "vpadd.i16	d18, d18, d18\n\t"
        "vpadd.i16	d18, d18, d18\n\t"
        "vmov.u16	r10, d18[0]\n\t"
        "vmov.16	d20[0], r10\n\t"
        "vadd.i16	d18, d2, d3\n\t"
        "vpadd.i16	d18, d18, d18\n\t"
        "vpadd.i16	d18, d18, d18\n\t"
        "vmov.u16	r10, d18[0]\n\t"
        "vmov.16	d20[1], r10\n\t"
        "vadd.i16	d18, d4, d5\n\t"
        "vpadd.i16	d18, d18, d18\n\t"
        "vpadd.i16	d18, d18, d18\n\t"
        "vmov.u16	r10, d18[0]\n\t"
        "vmov.16	d20[2], r10\n\t"
        "vadd.i16	d18, d6, d7\n\t"
        "vpadd.i16	d18, d18, d18\n\t"
        "vpadd.i16	d18, d18, d18\n\t"
        "vmov.u16	r10, d18[0]\n\t"
        "vmov.16	d20[3], r10\n\t"
        "vadd.i16	d18, d8, d9\n\t"
        "vpadd.i16	d18, d18, d18\n\t"
        "vpadd.i16	d18, d18, d18\n\t"
        "vmov.u16	r10, d18[0]\n\t"
        "vmov.16	d21[0], r10\n\t"
        "vadd.i16	d18, d10, d11\n\t"
        "vpadd.i16	d18, d18, d18\n\t"
        "vpadd.i16	d18, d18, d18\n\t"
        "vmov.u16	r10, d18[0]\n\t"
        "vmov.16	d21[1], r10\n\t"
        "vadd.i16	d18, d12, d13\n\t"
        "vpadd.i16	d18, d18, d18\n\t"
        "vpadd.i16	d18, d18, d18\n\t"
        "vmov.u16	r10, d18[0]\n\t"
        "vmov.16	d21[2], r10\n\t"
        "vadd.i16	d18, d14, d15\n\t"
        "vpadd.i16	d18, d18, d18\n\t"
        "vpadd.i16	d18, d18, d18\n\t"
        "vmov.u16	r10, d18[0]\n\t"
        "vmov.16	d21[3], r10\n\t"
        "vand	q10, q10, q11\n\t"
        "vst1.16	{d20-d21}, [r7]!\n\t"
        "subs	r9, r9, #1\n\t"
        "bne	L_frodokem_mul_bs_neon_r_%=\n\t"
        "pop	{%[qmask]}\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [out] "+r" (out), [b] "+r" (b), [s] "+r" (s), [n] "+r" (n),
          [qmask] "+r" (qmask)
        :
#else
        :
        : [out] "r" (out), [b] "r" (b), [s] "r" (s), [n] "r" (n),
          [qmask] "r" (qmask)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "lr", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "q0",
            "q1", "q2", "q3", "q4", "q5", "q6", "q7", "q8", "q9", "q10", "q11"
    );
}

void frodokem_mul_add_sb_plus_e_neon(word16* out_p, const word16* b_p,
    const word16* s_p, int n_p, int qmask_p);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void frodokem_mul_add_sb_plus_e_neon(word16* out_p,
    const word16* b_p, const word16* s_p, int n_p, int qmask_p)
#else
WC_OMIT_FRAME_POINTER void frodokem_mul_add_sb_plus_e_neon(word16* out,
    const word16* b, const word16* s, int n, int qmask)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word16* out __asm__ ("r0") = (word16*)out_p;
    register const word16* b __asm__ ("r1") = (const word16*)b_p;
    register const word16* s __asm__ ("r2") = (const word16*)s_p;
    register int n __asm__ ("r3") = (int)n_p;
    register int qmask __asm__ ("r12") = (int)qmask_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "push	{%[qmask]}\n\t"
        "ldr	lr, [sp]\n\t"
        "lsl	r12, %[n], #1\n\t"
        "vdup.16	q10, lr\n\t"
        "mov	r4, %[b]\n\t"
        "mov	r5, %[s]\n\t"
        "mov	r7, %[out]\n\t"
        "vld1.16	{d0-d1}, [r7]!\n\t"
        "vld1.16	{d2-d3}, [r7]!\n\t"
        "vld1.16	{d4-d5}, [r7]!\n\t"
        "vld1.16	{d6-d7}, [r7]!\n\t"
        "vld1.16	{d8-d9}, [r7]!\n\t"
        "vld1.16	{d10-d11}, [r7]!\n\t"
        "vld1.16	{d12-d13}, [r7]!\n\t"
        "vld1.16	{d14-d15}, [r7]!\n\t"
        "mov	r8, %[n]\n\t"
        "\n"
    "L_frodokem_mul_add_sb_plus_e_neon_j_%=:\n\t"
        "vld1.16	{d16-d17}, [r4]!\n\t"
        "mov	r6, r5\n\t"
        "ldrh	r9, [r6]\n\t"
        "vdup.16	q9, r9\n\t"
        "vmla.i16	q0, q8, q9\n\t"
        "add	r6, r6, r12\n\t"
        "ldrh	r9, [r6]\n\t"
        "vdup.16	q9, r9\n\t"
        "vmla.i16	q1, q8, q9\n\t"
        "add	r6, r6, r12\n\t"
        "ldrh	r9, [r6]\n\t"
        "vdup.16	q9, r9\n\t"
        "vmla.i16	q2, q8, q9\n\t"
        "add	r6, r6, r12\n\t"
        "ldrh	r9, [r6]\n\t"
        "vdup.16	q9, r9\n\t"
        "vmla.i16	q3, q8, q9\n\t"
        "add	r6, r6, r12\n\t"
        "ldrh	r9, [r6]\n\t"
        "vdup.16	q9, r9\n\t"
        "vmla.i16	q4, q8, q9\n\t"
        "add	r6, r6, r12\n\t"
        "ldrh	r9, [r6]\n\t"
        "vdup.16	q9, r9\n\t"
        "vmla.i16	q5, q8, q9\n\t"
        "add	r6, r6, r12\n\t"
        "ldrh	r9, [r6]\n\t"
        "vdup.16	q9, r9\n\t"
        "vmla.i16	q6, q8, q9\n\t"
        "add	r6, r6, r12\n\t"
        "ldrh	r9, [r6]\n\t"
        "vdup.16	q9, r9\n\t"
        "vmla.i16	q7, q8, q9\n\t"
        "add	r6, r6, r12\n\t"
        "add	r5, r5, #2\n\t"
        "subs	r8, r8, #1\n\t"
        "bne	L_frodokem_mul_add_sb_plus_e_neon_j_%=\n\t"
        "mov	r7, %[out]\n\t"
        "vand	q0, q0, q10\n\t"
        "vst1.16	{d0-d1}, [r7]!\n\t"
        "vand	q1, q1, q10\n\t"
        "vst1.16	{d2-d3}, [r7]!\n\t"
        "vand	q2, q2, q10\n\t"
        "vst1.16	{d4-d5}, [r7]!\n\t"
        "vand	q3, q3, q10\n\t"
        "vst1.16	{d6-d7}, [r7]!\n\t"
        "vand	q4, q4, q10\n\t"
        "vst1.16	{d8-d9}, [r7]!\n\t"
        "vand	q5, q5, q10\n\t"
        "vst1.16	{d10-d11}, [r7]!\n\t"
        "vand	q6, q6, q10\n\t"
        "vst1.16	{d12-d13}, [r7]!\n\t"
        "vand	q7, q7, q10\n\t"
        "vst1.16	{d14-d15}, [r7]!\n\t"
        "pop	{%[qmask]}\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [out] "+r" (out), [b] "+r" (b), [s] "+r" (s), [n] "+r" (n),
          [qmask] "+r" (qmask)
        :
#else
        :
        : [out] "r" (out), [b] "r" (b), [s] "r" (s), [n] "r" (n),
          [qmask] "r" (qmask)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "lr", "r4", "r5", "r6", "r7", "r8", "r9", "q0", "q1",
            "q2", "q3", "q4", "q5", "q6", "q7", "q8", "q9", "q10"
    );
}

#endif /* WOLFSSL_ARMASM_NO_NEON */
#endif /* WOLFSSL_HAVE_FRODOKEM */
#ifdef WOLFSSL_HAVE_FRODOKEM
#ifdef __ARM_FEATURE_SIMD32
#if (!defined(__ARM_NEON) && !defined(__ARM_NEON__)) || \
        defined(WOLFSSL_ARMASM_NO_NEON)
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void frodokem_add_simd32(word16* a_p, const word16* b_p,
    int qmask_p)
#else
WC_OMIT_FRAME_POINTER void frodokem_add_simd32(word16* a, const word16* b,
    int qmask)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word16* a __asm__ ("r0") = (word16*)a_p;
    register const word16* b __asm__ ("r1") = (const word16*)b_p;
    register int qmask __asm__ ("r2") = (int)qmask_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "orr	%[qmask], %[qmask], %[qmask], lsl #16\n\t"
        "mov	r3, #32\n\t"
        "\n"
    "L_frodokem_add_simd32_blk_%=:\n\t"
        "ldr	r12, [%[a]]\n\t"
        "ldr	lr, [%[b]], #4\n\t"
        "sadd16	r12, r12, lr\n\t"
        "and	r12, r12, %[qmask]\n\t"
        "str	r12, [%[a]], #4\n\t"
        "subs	r3, r3, #1\n\t"
        "bne	L_frodokem_add_simd32_blk_%=\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [a] "+r" (a), [b] "+r" (b), [qmask] "+r" (qmask)
        :
#else
        :
        : [a] "r" (a), [b] "r" (b), [qmask] "r" (qmask)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r3", "r12", "lr"
    );
}

#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void frodokem_sa_accum_simd32(word16* out_p,
    const word16* s_p, const word16* row_p, int j_p, int n_p)
#else
WC_OMIT_FRAME_POINTER void frodokem_sa_accum_simd32(word16* out,
    const word16* s, const word16* row, int j, int n)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word16* out __asm__ ("r0") = (word16*)out_p;
    register const word16* s __asm__ ("r1") = (const word16*)s_p;
    register const word16* row __asm__ ("r2") = (const word16*)row_p;
    register int j __asm__ ("r3") = (int)j_p;
    register int n __asm__ ("r12") = (int)n_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "push	{%[n]}\n\t"
        "ldr	r12, [sp]\n\t"
        "lsl	r12, r12, #1\n\t"
        "add	lr, %[s], %[j], lsl #1\n\t"
        "mov	r6, #8\n\t"
        "\n"
    "L_frodokem_sa_accum_simd32_i_%=:\n\t"
        "ldrh	r7, [lr]\n\t"
        "add	lr, lr, r12\n\t"
        "mov	r4, %[row]\n\t"
        "lsr	r5, r12, #2\n\t"
        "\n"
    "L_frodokem_sa_accum_simd32_k_%=:\n\t"
        "ldr	r9, [%[out]]\n\t"
        "ldr	r8, [r4], #4\n\t"
        "smulbb	r10, r7, r8\n\t"
        "smulbt	r11, r7, r8\n\t"
        "pkhbt	r10, r10, r11, LSL #16\n\t"
        "sadd16	r9, r9, r10\n\t"
        "str	r9, [%[out]], #4\n\t"
        "subs	r5, r5, #1\n\t"
        "bne	L_frodokem_sa_accum_simd32_k_%=\n\t"
        "subs	r6, r6, #1\n\t"
        "bne	L_frodokem_sa_accum_simd32_i_%=\n\t"
        "pop	{%[n]}\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [out] "+r" (out), [s] "+r" (s), [row] "+r" (row), [j] "+r" (j),
          [n] "+r" (n)
        :
#else
        :
        : [out] "r" (out), [s] "r" (s), [row] "r" (row), [j] "r" (j),
          [n] "r" (n)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "lr", "r4", "r5", "r6", "r7", "r8", "r9", "r10",
            "r11"
    );
}

#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void frodokem_as_accum_simd32(word16* out_p,
    const word16* s_p, const word16* row_p, int i_p, int n_p)
#else
WC_OMIT_FRAME_POINTER void frodokem_as_accum_simd32(word16* out,
    const word16* s, const word16* row, int i, int n)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word16* out __asm__ ("r0") = (word16*)out_p;
    register const word16* s __asm__ ("r1") = (const word16*)s_p;
    register const word16* row __asm__ ("r2") = (const word16*)row_p;
    register int i __asm__ ("r3") = (int)i_p;
    register int n __asm__ ("r12") = (int)n_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "push	{%[n]}\n\t"
        "ldr	r12, [sp]\n\t"
        "lsl	r12, r12, #1\n\t"
        "add	lr, %[out], %[i], lsl #4\n\t"
        "mov	r4, %[s]\n\t"
        "mov	r7, #8\n\t"
        "\n"
    "L_frodokem_as_accum_simd32_c_%=:\n\t"
        "mov	r9, #0\n\t"
        "mov	r5, %[row]\n\t"
        "mov	r6, r4\n\t"
        "lsr	r8, r12, #2\n\t"
        "\n"
    "L_frodokem_as_accum_simd32_j_%=:\n\t"
        "ldr	r10, [r5], #4\n\t"
        "ldr	r11, [r6], #4\n\t"
        "smlad	r9, r10, r11, r9\n\t"
        "subs	r8, r8, #1\n\t"
        "bne	L_frodokem_as_accum_simd32_j_%=\n\t"
        "ldrh	r10, [lr]\n\t"
        "add	r10, r10, r9\n\t"
        "strh	r10, [lr]\n\t"
        "add	lr, lr, #2\n\t"
        "add	r4, r4, r12\n\t"
        "subs	r7, r7, #1\n\t"
        "bne	L_frodokem_as_accum_simd32_c_%=\n\t"
        "pop	{%[n]}\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [out] "+r" (out), [s] "+r" (s), [row] "+r" (row), [i] "+r" (i),
          [n] "+r" (n)
        :
#else
        :
        : [out] "r" (out), [s] "r" (s), [row] "r" (row), [i] "r" (i),
          [n] "r" (n)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "lr", "r4", "r5", "r6", "r7", "r8", "r9", "r10",
            "r11"
    );
}

#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void frodokem_mul_bs_simd32(word16* out_p,
    const word16* b_p, const word16* s_p, int n_p, int qmask_p)
#else
WC_OMIT_FRAME_POINTER void frodokem_mul_bs_simd32(word16* out, const word16* b,
    const word16* s, int n, int qmask)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word16* out __asm__ ("r0") = (word16*)out_p;
    register const word16* b __asm__ ("r1") = (const word16*)b_p;
    register const word16* s __asm__ ("r2") = (const word16*)s_p;
    register int n __asm__ ("r3") = (int)n_p;
    register int qmask __asm__ ("r12") = (int)qmask_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "push	{%[qmask]}\n\t"
        "mov	r12, %[b]\n\t"
        "mov	r6, #8\n\t"
        "\n"
    "L_frodokem_mul_bs_simd32_i_%=:\n\t"
        "mov	lr, %[s]\n\t"
        "mov	r7, #8\n\t"
        "\n"
    "L_frodokem_mul_bs_simd32_c_%=:\n\t"
        "mov	r9, #0\n\t"
        "mov	r4, r12\n\t"
        "mov	r5, lr\n\t"
        "lsr	r8, %[n], #1\n\t"
        "\n"
    "L_frodokem_mul_bs_simd32_j_%=:\n\t"
        "ldr	r10, [r4], #4\n\t"
        "ldr	r11, [r5], #4\n\t"
        "smlad	r9, r10, r11, r9\n\t"
        "subs	r8, r8, #1\n\t"
        "bne	L_frodokem_mul_bs_simd32_j_%=\n\t"
        "ldr	r10, [sp]\n\t"
        "orr	r10, r10, r10, lsl #16\n\t"
        "and	r9, r9, r10\n\t"
        "strh	r9, [%[out]]\n\t"
        "add	%[out], %[out], #2\n\t"
        "add	lr, lr, %[n], lsl #1\n\t"
        "subs	r7, r7, #1\n\t"
        "bne	L_frodokem_mul_bs_simd32_c_%=\n\t"
        "add	r12, r12, %[n], lsl #1\n\t"
        "subs	r6, r6, #1\n\t"
        "bne	L_frodokem_mul_bs_simd32_i_%=\n\t"
        "pop	{%[qmask]}\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [out] "+r" (out), [b] "+r" (b), [s] "+r" (s), [n] "+r" (n),
          [qmask] "+r" (qmask)
        :
#else
        :
        : [out] "r" (out), [b] "r" (b), [s] "r" (s), [n] "r" (n),
          [qmask] "r" (qmask)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "lr", "r4", "r5", "r6", "r7", "r8", "r9", "r10",
            "r11"
    );
}

#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void frodokem_mul_add_sb_plus_e_simd32(word16* out_p,
    const word16* b_p, const word16* s_p, int n_p, int qmask_p)
#else
WC_OMIT_FRAME_POINTER void frodokem_mul_add_sb_plus_e_simd32(word16* out,
    const word16* b, const word16* s, int n, int qmask)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word16* out __asm__ ("r0") = (word16*)out_p;
    register const word16* b __asm__ ("r1") = (const word16*)b_p;
    register const word16* s __asm__ ("r2") = (const word16*)s_p;
    register int n __asm__ ("r3") = (int)n_p;
    register int qmask __asm__ ("r12") = (int)qmask_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "push	{%[qmask]}\n\t"
        "sub	sp, sp, #8\n\t"
        "lsl	r9, %[n], #1\n\t"
        "str	r9, [sp, #4]\n\t"
        "str	%[b], [sp]\n\t"
        "mov	r12, #8\n\t"
        "\n"
    "L_frodokem_mul_add_sb_plus_e_simd32_i_%=:\n\t"
        "ldr	r9, [sp, #4]\n\t"
        "add	%[n], %[s], r9\n\t"
        "ldr	%[b], [sp]\n\t"
        "mov	lr, %[s]\n\t"
        "ldr	r4, [%[out]]\n\t"
        "ldr	r5, [%[out], #4]\n\t"
        "ldr	r6, [%[out], #8]\n\t"
        "ldr	r7, [%[out], #12]\n\t"
        "\n"
    "L_frodokem_mul_add_sb_plus_e_simd32_j_%=:\n\t"
        "ldrh	r8, [lr]\n\t"
        "add	lr, lr, #2\n\t"
        "ldr	r9, [%[b]]\n\t"
        "smulbb	r10, r8, r9\n\t"
        "smulbt	r11, r8, r9\n\t"
        "pkhbt	r10, r10, r11, LSL #16\n\t"
        "sadd16	r4, r4, r10\n\t"
        "ldr	r9, [%[b], #4]\n\t"
        "smulbb	r10, r8, r9\n\t"
        "smulbt	r11, r8, r9\n\t"
        "pkhbt	r10, r10, r11, LSL #16\n\t"
        "sadd16	r5, r5, r10\n\t"
        "ldr	r9, [%[b], #8]\n\t"
        "smulbb	r10, r8, r9\n\t"
        "smulbt	r11, r8, r9\n\t"
        "pkhbt	r10, r10, r11, LSL #16\n\t"
        "sadd16	r6, r6, r10\n\t"
        "ldr	r9, [%[b], #12]\n\t"
        "smulbb	r10, r8, r9\n\t"
        "smulbt	r11, r8, r9\n\t"
        "pkhbt	r10, r10, r11, LSL #16\n\t"
        "sadd16	r7, r7, r10\n\t"
        "add	%[b], %[b], #16\n\t"
        "cmp	lr, %[n]\n\t"
        "bne	L_frodokem_mul_add_sb_plus_e_simd32_j_%=\n\t"
        "ldr	r9, [sp, #8]\n\t"
        "orr	r9, r9, r9, lsl #16\n\t"
        "and	r4, r4, r9\n\t"
        "and	r5, r5, r9\n\t"
        "and	r6, r6, r9\n\t"
        "and	r7, r7, r9\n\t"
        "str	r4, [%[out]]\n\t"
        "str	r5, [%[out], #4]\n\t"
        "str	r6, [%[out], #8]\n\t"
        "str	r7, [%[out], #12]\n\t"
        "add	%[out], %[out], #16\n\t"
        "mov	%[s], %[n]\n\t"
        "subs	r12, r12, #1\n\t"
        "bne	L_frodokem_mul_add_sb_plus_e_simd32_i_%=\n\t"
        "add	sp, sp, #8\n\t"
        "pop	{%[qmask]}\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [out] "+r" (out), [b] "+r" (b), [s] "+r" (s), [n] "+r" (n),
          [qmask] "+r" (qmask)
        :
#else
        :
        : [out] "r" (out), [b] "r" (b), [s] "r" (s), [n] "r" (n),
          [qmask] "r" (qmask)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "lr", "r4", "r5", "r6", "r7", "r8", "r9", "r10",
            "r11"
    );
}

#endif /* (!defined(__ARM_NEON) && !defined(__ARM_NEON__)) ||
        * defined(WOLFSSL_ARMASM_NO_NEON) */
#endif /* __ARM_FEATURE_SIMD32 */
#endif /* WOLFSSL_HAVE_FRODOKEM */

#endif /* WOLFSSL_ARMASM_INLINE */
#endif /* !__aarch64__ && !WOLFSSL_ARMASM_THUMB2 */
#endif /* WOLFSSL_ARMASM */
