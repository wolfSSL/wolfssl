/* sha512_asm.S */
/*
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

#define WC_FIPS_LL_CRYPTO
#define _WC_BUILDING_SHA512_ASM_S

#include <wolfssl/wolfcrypt/libwolfssl_sources_asm.h>

#ifndef HAVE_INTEL_AVX1
#define HAVE_INTEL_AVX1
#endif /* HAVE_INTEL_AVX1 */
#ifndef NO_AVX2_SUPPORT
#ifndef HAVE_INTEL_AVX2
#define HAVE_INTEL_AVX2
#endif /* HAVE_INTEL_AVX2 */
#endif /* NO_AVX2_SUPPORT */
#ifndef NO_VAES_SUPPORT
#ifndef HAVE_INTEL_VAES
#define HAVE_INTEL_VAES
#endif /* HAVE_INTEL_VAES */
#endif /* NO_VAES_SUPPORT */
#ifndef NO_AVX512_SUPPORT
#ifndef HAVE_INTEL_AVX512
#define HAVE_INTEL_AVX512
#endif /* HAVE_INTEL_AVX512 */
#endif /* NO_AVX512_SUPPORT */

#ifdef HAVE_INTEL_AVX1
#ifndef __APPLE__
.data
#else
.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
.align	32
#else
.p2align	5
#endif /* __APPLE__ */
L_avx1_sha512_k:
.quad	0x428a2f98d728ae22,0x7137449123ef65cd
.quad	0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc
.quad	0x3956c25bf348b538,0x59f111f1b605d019
.quad	0x923f82a4af194f9b,0xab1c5ed5da6d8118
.quad	0xd807aa98a3030242,0x12835b0145706fbe
.quad	0x243185be4ee4b28c,0x550c7dc3d5ffb4e2
.quad	0x72be5d74f27b896f,0x80deb1fe3b1696b1
.quad	0x9bdc06a725c71235,0xc19bf174cf692694
.quad	0xe49b69c19ef14ad2,0xefbe4786384f25e3
.quad	0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65
.quad	0x2de92c6f592b0275,0x4a7484aa6ea6e483
.quad	0x5cb0a9dcbd41fbd4,0x76f988da831153b5
.quad	0x983e5152ee66dfab,0xa831c66d2db43210
.quad	0xb00327c898fb213f,0xbf597fc7beef0ee4
.quad	0xc6e00bf33da88fc2,0xd5a79147930aa725
.quad	0x06ca6351e003826f,0x142929670a0e6e70
.quad	0x27b70a8546d22ffc,0x2e1b21385c26c926
.quad	0x4d2c6dfc5ac42aed,0x53380d139d95b3df
.quad	0x650a73548baf63de,0x766a0abb3c77b2a8
.quad	0x81c2c92e47edaee6,0x92722c851482353b
.quad	0xa2bfe8a14cf10364,0xa81a664bbc423001
.quad	0xc24b8b70d0f89791,0xc76c51a30654be30
.quad	0xd192e819d6ef5218,0xd69906245565a910
.quad	0xf40e35855771202a,0x106aa07032bbd1b8
.quad	0x19a4c116b8d2d0c8,0x1e376c085141ab53
.quad	0x2748774cdf8eeb99,0x34b0bcb5e19b48a8
.quad	0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb
.quad	0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3
.quad	0x748f82ee5defb2fc,0x78a5636f43172f60
.quad	0x84c87814a1f0ab72,0x8cc702081a6439ec
.quad	0x90befffa23631e28,0xa4506cebde82bde9
.quad	0xbef9a3f7b2c67915,0xc67178f2e372532b
.quad	0xca273eceea26619c,0xd186b8c721c0c207
.quad	0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178
.quad	0x06f067aa72176fba,0x0a637dc5a2c898a6
.quad	0x113f9804bef90dae,0x1b710b35131c471b
.quad	0x28db77f523047d84,0x32caab7b40c72493
.quad	0x3c9ebe0a15c9bebc,0x431d67c49c100d4c
.quad	0x4cc5d4becb3e42b6,0x597f299cfc657e2a
.quad	0x5fcb6fab3ad6faec,0x6c44198c4a475817
#ifndef __APPLE__
.data
#else
.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
.align	16
#else
.p2align	4
#endif /* __APPLE__ */
L_avx1_sha512_flip_mask:
.quad	0x0001020304050607,0x08090a0b0c0d0e0f
#ifndef __APPLE__
.text
.globl	Transform_Sha512_AVX1
WC_ASM_ATT_HIDDEN(Transform_Sha512_AVX1)
.type	Transform_Sha512_AVX1,@function
.align	16
Transform_Sha512_AVX1:
#else
.section	__TEXT,__text
.globl	_Transform_Sha512_AVX1
WC_ASM_ATT_HIDDEN(_Transform_Sha512_AVX1)
.p2align	4
_Transform_Sha512_AVX1:
#endif /* __APPLE__ */
        pushq	%rbx
        pushq	%r12
        pushq	%r13
        pushq	%r14
        pushq	%r15
        subq	$0x90, %rsp
        leaq	64(%rdi), %rax
        vmovdqa	L_avx1_sha512_flip_mask(%rip), %xmm14
        movq	(%rdi), %r8
        movq	8(%rdi), %r9
        movq	16(%rdi), %r10
        movq	24(%rdi), %r11
        movq	32(%rdi), %r12
        movq	40(%rdi), %r13
        movq	48(%rdi), %r14
        movq	56(%rdi), %r15
        vmovdqu	(%rax), %xmm0
        vmovdqu	16(%rax), %xmm1
        vpshufb	%xmm14, %xmm0, %xmm0
        vpshufb	%xmm14, %xmm1, %xmm1
        vmovdqu	32(%rax), %xmm2
        vmovdqu	48(%rax), %xmm3
        vpshufb	%xmm14, %xmm2, %xmm2
        vpshufb	%xmm14, %xmm3, %xmm3
        vmovdqu	64(%rax), %xmm4
        vmovdqu	80(%rax), %xmm5
        vpshufb	%xmm14, %xmm4, %xmm4
        vpshufb	%xmm14, %xmm5, %xmm5
        vmovdqu	96(%rax), %xmm6
        vmovdqu	112(%rax), %xmm7
        vpshufb	%xmm14, %xmm6, %xmm6
        vpshufb	%xmm14, %xmm7, %xmm7
        movl	$4, 128(%rsp)
        leaq	L_avx1_sha512_k(%rip), %rsi
        movq	%r9, %rbx
        movq	%r12, %rax
        xorq	%r10, %rbx
        # Start of 16 rounds
L_transform_sha512_avx1_start:
        vpaddq	(%rsi), %xmm0, %xmm8
        vpaddq	16(%rsi), %xmm1, %xmm9
        vmovdqu	%xmm8, (%rsp)
        vmovdqu	%xmm9, 16(%rsp)
        vpaddq	32(%rsi), %xmm2, %xmm8
        vpaddq	48(%rsi), %xmm3, %xmm9
        vmovdqu	%xmm8, 32(%rsp)
        vmovdqu	%xmm9, 48(%rsp)
        vpaddq	64(%rsi), %xmm4, %xmm8
        vpaddq	80(%rsi), %xmm5, %xmm9
        vmovdqu	%xmm8, 64(%rsp)
        vmovdqu	%xmm9, 80(%rsp)
        vpaddq	96(%rsi), %xmm6, %xmm8
        vpaddq	112(%rsi), %xmm7, %xmm9
        vmovdqu	%xmm8, 96(%rsp)
        vmovdqu	%xmm9, 112(%rsp)
        addq	$0x80, %rsi
        # msg_sched: 0-1
        # rnd_0: 0 - 0
        rorq	$23, %rax
        vpalignr	$8, %xmm0, %xmm1, %xmm12
        vpalignr	$8, %xmm4, %xmm5, %xmm13
        # rnd_0: 1 - 1
        movq	%r8, %rdx
        movq	%r13, %rcx
        addq	(%rsp), %r15
        xorq	%r14, %rcx
        vpsrlq	$0x01, %xmm12, %xmm8
        vpsllq	$63, %xmm12, %xmm9
        # rnd_0: 2 - 3
        xorq	%r12, %rax
        andq	%r12, %rcx
        rorq	$4, %rax
        xorq	%r14, %rcx
        vpsrlq	$8, %xmm12, %xmm10
        vpsllq	$56, %xmm12, %xmm11
        # rnd_0: 4 - 5
        xorq	%r12, %rax
        addq	%rcx, %r15
        rorq	$14, %rax
        xorq	%r9, %rdx
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_0: 6 - 7
        addq	%rax, %r15
        movq	%r8, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        vpsrlq	$7, %xmm12, %xmm11
        vpxor	%xmm10, %xmm8, %xmm8
        # rnd_0: 8 - 9
        xorq	%r8, %rcx
        xorq	%r9, %rbx
        rorq	$6, %rcx
        addq	%r15, %r11
        vpxor	%xmm11, %xmm8, %xmm8
        vpaddq	%xmm0, %xmm13, %xmm0
        # rnd_0: 10 - 11
        xorq	%r8, %rcx
        addq	%rbx, %r15
        rorq	$28, %rcx
        movq	%r11, %rax
        addq	%rcx, %r15
        # rnd_1: 0 - 0
        rorq	$23, %rax
        vpaddq	%xmm0, %xmm8, %xmm0
        # rnd_1: 1 - 1
        movq	%r15, %rbx
        movq	%r12, %rcx
        addq	8(%rsp), %r14
        xorq	%r13, %rcx
        vpsrlq	$19, %xmm7, %xmm8
        vpsllq	$45, %xmm7, %xmm9
        # rnd_1: 2 - 3
        xorq	%r11, %rax
        andq	%r11, %rcx
        rorq	$4, %rax
        xorq	%r13, %rcx
        vpsrlq	$61, %xmm7, %xmm10
        vpsllq	$3, %xmm7, %xmm11
        # rnd_1: 4 - 6
        xorq	%r11, %rax
        addq	%rcx, %r14
        rorq	$14, %rax
        xorq	%r8, %rbx
        addq	%rax, %r14
        movq	%r15, %rcx
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_1: 7 - 8
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r15, %rcx
        xorq	%r8, %rdx
        vpxor	%xmm10, %xmm8, %xmm8
        vpsrlq	$6, %xmm7, %xmm11
        # rnd_1: 9 - 10
        rorq	$6, %rcx
        addq	%r14, %r10
        xorq	%r15, %rcx
        addq	%rdx, %r14
        vpxor	%xmm11, %xmm8, %xmm8
        # rnd_1: 11 - 11
        rorq	$28, %rcx
        movq	%r10, %rax
        addq	%rcx, %r14
        vpaddq	%xmm0, %xmm8, %xmm0
        # msg_sched done: 0-1
        # msg_sched: 2-3
        # rnd_0: 0 - 0
        rorq	$23, %rax
        vpalignr	$8, %xmm1, %xmm2, %xmm12
        vpalignr	$8, %xmm5, %xmm6, %xmm13
        # rnd_0: 1 - 1
        movq	%r14, %rdx
        movq	%r11, %rcx
        addq	16(%rsp), %r13
        xorq	%r12, %rcx
        vpsrlq	$0x01, %xmm12, %xmm8
        vpsllq	$63, %xmm12, %xmm9
        # rnd_0: 2 - 3
        xorq	%r10, %rax
        andq	%r10, %rcx
        rorq	$4, %rax
        xorq	%r12, %rcx
        vpsrlq	$8, %xmm12, %xmm10
        vpsllq	$56, %xmm12, %xmm11
        # rnd_0: 4 - 5
        xorq	%r10, %rax
        addq	%rcx, %r13
        rorq	$14, %rax
        xorq	%r15, %rdx
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_0: 6 - 7
        addq	%rax, %r13
        movq	%r14, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        vpsrlq	$7, %xmm12, %xmm11
        vpxor	%xmm10, %xmm8, %xmm8
        # rnd_0: 8 - 9
        xorq	%r14, %rcx
        xorq	%r15, %rbx
        rorq	$6, %rcx
        addq	%r13, %r9
        vpxor	%xmm11, %xmm8, %xmm8
        vpaddq	%xmm1, %xmm13, %xmm1
        # rnd_0: 10 - 11
        xorq	%r14, %rcx
        addq	%rbx, %r13
        rorq	$28, %rcx
        movq	%r9, %rax
        addq	%rcx, %r13
        # rnd_1: 0 - 0
        rorq	$23, %rax
        vpaddq	%xmm1, %xmm8, %xmm1
        # rnd_1: 1 - 1
        movq	%r13, %rbx
        movq	%r10, %rcx
        addq	24(%rsp), %r12
        xorq	%r11, %rcx
        vpsrlq	$19, %xmm0, %xmm8
        vpsllq	$45, %xmm0, %xmm9
        # rnd_1: 2 - 3
        xorq	%r9, %rax
        andq	%r9, %rcx
        rorq	$4, %rax
        xorq	%r11, %rcx
        vpsrlq	$61, %xmm0, %xmm10
        vpsllq	$3, %xmm0, %xmm11
        # rnd_1: 4 - 6
        xorq	%r9, %rax
        addq	%rcx, %r12
        rorq	$14, %rax
        xorq	%r14, %rbx
        addq	%rax, %r12
        movq	%r13, %rcx
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_1: 7 - 8
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r13, %rcx
        xorq	%r14, %rdx
        vpxor	%xmm10, %xmm8, %xmm8
        vpsrlq	$6, %xmm0, %xmm11
        # rnd_1: 9 - 10
        rorq	$6, %rcx
        addq	%r12, %r8
        xorq	%r13, %rcx
        addq	%rdx, %r12
        vpxor	%xmm11, %xmm8, %xmm8
        # rnd_1: 11 - 11
        rorq	$28, %rcx
        movq	%r8, %rax
        addq	%rcx, %r12
        vpaddq	%xmm1, %xmm8, %xmm1
        # msg_sched done: 2-3
        # msg_sched: 4-5
        # rnd_0: 0 - 0
        rorq	$23, %rax
        vpalignr	$8, %xmm2, %xmm3, %xmm12
        vpalignr	$8, %xmm6, %xmm7, %xmm13
        # rnd_0: 1 - 1
        movq	%r12, %rdx
        movq	%r9, %rcx
        addq	32(%rsp), %r11
        xorq	%r10, %rcx
        vpsrlq	$0x01, %xmm12, %xmm8
        vpsllq	$63, %xmm12, %xmm9
        # rnd_0: 2 - 3
        xorq	%r8, %rax
        andq	%r8, %rcx
        rorq	$4, %rax
        xorq	%r10, %rcx
        vpsrlq	$8, %xmm12, %xmm10
        vpsllq	$56, %xmm12, %xmm11
        # rnd_0: 4 - 5
        xorq	%r8, %rax
        addq	%rcx, %r11
        rorq	$14, %rax
        xorq	%r13, %rdx
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_0: 6 - 7
        addq	%rax, %r11
        movq	%r12, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        vpsrlq	$7, %xmm12, %xmm11
        vpxor	%xmm10, %xmm8, %xmm8
        # rnd_0: 8 - 9
        xorq	%r12, %rcx
        xorq	%r13, %rbx
        rorq	$6, %rcx
        addq	%r11, %r15
        vpxor	%xmm11, %xmm8, %xmm8
        vpaddq	%xmm2, %xmm13, %xmm2
        # rnd_0: 10 - 11
        xorq	%r12, %rcx
        addq	%rbx, %r11
        rorq	$28, %rcx
        movq	%r15, %rax
        addq	%rcx, %r11
        # rnd_1: 0 - 0
        rorq	$23, %rax
        vpaddq	%xmm2, %xmm8, %xmm2
        # rnd_1: 1 - 1
        movq	%r11, %rbx
        movq	%r8, %rcx
        addq	40(%rsp), %r10
        xorq	%r9, %rcx
        vpsrlq	$19, %xmm1, %xmm8
        vpsllq	$45, %xmm1, %xmm9
        # rnd_1: 2 - 3
        xorq	%r15, %rax
        andq	%r15, %rcx
        rorq	$4, %rax
        xorq	%r9, %rcx
        vpsrlq	$61, %xmm1, %xmm10
        vpsllq	$3, %xmm1, %xmm11
        # rnd_1: 4 - 6
        xorq	%r15, %rax
        addq	%rcx, %r10
        rorq	$14, %rax
        xorq	%r12, %rbx
        addq	%rax, %r10
        movq	%r11, %rcx
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_1: 7 - 8
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r11, %rcx
        xorq	%r12, %rdx
        vpxor	%xmm10, %xmm8, %xmm8
        vpsrlq	$6, %xmm1, %xmm11
        # rnd_1: 9 - 10
        rorq	$6, %rcx
        addq	%r10, %r14
        xorq	%r11, %rcx
        addq	%rdx, %r10
        vpxor	%xmm11, %xmm8, %xmm8
        # rnd_1: 11 - 11
        rorq	$28, %rcx
        movq	%r14, %rax
        addq	%rcx, %r10
        vpaddq	%xmm2, %xmm8, %xmm2
        # msg_sched done: 4-5
        # msg_sched: 6-7
        # rnd_0: 0 - 0
        rorq	$23, %rax
        vpalignr	$8, %xmm3, %xmm4, %xmm12
        vpalignr	$8, %xmm7, %xmm0, %xmm13
        # rnd_0: 1 - 1
        movq	%r10, %rdx
        movq	%r15, %rcx
        addq	48(%rsp), %r9
        xorq	%r8, %rcx
        vpsrlq	$0x01, %xmm12, %xmm8
        vpsllq	$63, %xmm12, %xmm9
        # rnd_0: 2 - 3
        xorq	%r14, %rax
        andq	%r14, %rcx
        rorq	$4, %rax
        xorq	%r8, %rcx
        vpsrlq	$8, %xmm12, %xmm10
        vpsllq	$56, %xmm12, %xmm11
        # rnd_0: 4 - 5
        xorq	%r14, %rax
        addq	%rcx, %r9
        rorq	$14, %rax
        xorq	%r11, %rdx
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_0: 6 - 7
        addq	%rax, %r9
        movq	%r10, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        vpsrlq	$7, %xmm12, %xmm11
        vpxor	%xmm10, %xmm8, %xmm8
        # rnd_0: 8 - 9
        xorq	%r10, %rcx
        xorq	%r11, %rbx
        rorq	$6, %rcx
        addq	%r9, %r13
        vpxor	%xmm11, %xmm8, %xmm8
        vpaddq	%xmm3, %xmm13, %xmm3
        # rnd_0: 10 - 11
        xorq	%r10, %rcx
        addq	%rbx, %r9
        rorq	$28, %rcx
        movq	%r13, %rax
        addq	%rcx, %r9
        # rnd_1: 0 - 0
        rorq	$23, %rax
        vpaddq	%xmm3, %xmm8, %xmm3
        # rnd_1: 1 - 1
        movq	%r9, %rbx
        movq	%r14, %rcx
        addq	56(%rsp), %r8
        xorq	%r15, %rcx
        vpsrlq	$19, %xmm2, %xmm8
        vpsllq	$45, %xmm2, %xmm9
        # rnd_1: 2 - 3
        xorq	%r13, %rax
        andq	%r13, %rcx
        rorq	$4, %rax
        xorq	%r15, %rcx
        vpsrlq	$61, %xmm2, %xmm10
        vpsllq	$3, %xmm2, %xmm11
        # rnd_1: 4 - 6
        xorq	%r13, %rax
        addq	%rcx, %r8
        rorq	$14, %rax
        xorq	%r10, %rbx
        addq	%rax, %r8
        movq	%r9, %rcx
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_1: 7 - 8
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r9, %rcx
        xorq	%r10, %rdx
        vpxor	%xmm10, %xmm8, %xmm8
        vpsrlq	$6, %xmm2, %xmm11
        # rnd_1: 9 - 10
        rorq	$6, %rcx
        addq	%r8, %r12
        xorq	%r9, %rcx
        addq	%rdx, %r8
        vpxor	%xmm11, %xmm8, %xmm8
        # rnd_1: 11 - 11
        rorq	$28, %rcx
        movq	%r12, %rax
        addq	%rcx, %r8
        vpaddq	%xmm3, %xmm8, %xmm3
        # msg_sched done: 6-7
        # msg_sched: 8-9
        # rnd_0: 0 - 0
        rorq	$23, %rax
        vpalignr	$8, %xmm4, %xmm5, %xmm12
        vpalignr	$8, %xmm0, %xmm1, %xmm13
        # rnd_0: 1 - 1
        movq	%r8, %rdx
        movq	%r13, %rcx
        addq	64(%rsp), %r15
        xorq	%r14, %rcx
        vpsrlq	$0x01, %xmm12, %xmm8
        vpsllq	$63, %xmm12, %xmm9
        # rnd_0: 2 - 3
        xorq	%r12, %rax
        andq	%r12, %rcx
        rorq	$4, %rax
        xorq	%r14, %rcx
        vpsrlq	$8, %xmm12, %xmm10
        vpsllq	$56, %xmm12, %xmm11
        # rnd_0: 4 - 5
        xorq	%r12, %rax
        addq	%rcx, %r15
        rorq	$14, %rax
        xorq	%r9, %rdx
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_0: 6 - 7
        addq	%rax, %r15
        movq	%r8, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        vpsrlq	$7, %xmm12, %xmm11
        vpxor	%xmm10, %xmm8, %xmm8
        # rnd_0: 8 - 9
        xorq	%r8, %rcx
        xorq	%r9, %rbx
        rorq	$6, %rcx
        addq	%r15, %r11
        vpxor	%xmm11, %xmm8, %xmm8
        vpaddq	%xmm4, %xmm13, %xmm4
        # rnd_0: 10 - 11
        xorq	%r8, %rcx
        addq	%rbx, %r15
        rorq	$28, %rcx
        movq	%r11, %rax
        addq	%rcx, %r15
        # rnd_1: 0 - 0
        rorq	$23, %rax
        vpaddq	%xmm4, %xmm8, %xmm4
        # rnd_1: 1 - 1
        movq	%r15, %rbx
        movq	%r12, %rcx
        addq	72(%rsp), %r14
        xorq	%r13, %rcx
        vpsrlq	$19, %xmm3, %xmm8
        vpsllq	$45, %xmm3, %xmm9
        # rnd_1: 2 - 3
        xorq	%r11, %rax
        andq	%r11, %rcx
        rorq	$4, %rax
        xorq	%r13, %rcx
        vpsrlq	$61, %xmm3, %xmm10
        vpsllq	$3, %xmm3, %xmm11
        # rnd_1: 4 - 6
        xorq	%r11, %rax
        addq	%rcx, %r14
        rorq	$14, %rax
        xorq	%r8, %rbx
        addq	%rax, %r14
        movq	%r15, %rcx
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_1: 7 - 8
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r15, %rcx
        xorq	%r8, %rdx
        vpxor	%xmm10, %xmm8, %xmm8
        vpsrlq	$6, %xmm3, %xmm11
        # rnd_1: 9 - 10
        rorq	$6, %rcx
        addq	%r14, %r10
        xorq	%r15, %rcx
        addq	%rdx, %r14
        vpxor	%xmm11, %xmm8, %xmm8
        # rnd_1: 11 - 11
        rorq	$28, %rcx
        movq	%r10, %rax
        addq	%rcx, %r14
        vpaddq	%xmm4, %xmm8, %xmm4
        # msg_sched done: 8-9
        # msg_sched: 10-11
        # rnd_0: 0 - 0
        rorq	$23, %rax
        vpalignr	$8, %xmm5, %xmm6, %xmm12
        vpalignr	$8, %xmm1, %xmm2, %xmm13
        # rnd_0: 1 - 1
        movq	%r14, %rdx
        movq	%r11, %rcx
        addq	80(%rsp), %r13
        xorq	%r12, %rcx
        vpsrlq	$0x01, %xmm12, %xmm8
        vpsllq	$63, %xmm12, %xmm9
        # rnd_0: 2 - 3
        xorq	%r10, %rax
        andq	%r10, %rcx
        rorq	$4, %rax
        xorq	%r12, %rcx
        vpsrlq	$8, %xmm12, %xmm10
        vpsllq	$56, %xmm12, %xmm11
        # rnd_0: 4 - 5
        xorq	%r10, %rax
        addq	%rcx, %r13
        rorq	$14, %rax
        xorq	%r15, %rdx
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_0: 6 - 7
        addq	%rax, %r13
        movq	%r14, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        vpsrlq	$7, %xmm12, %xmm11
        vpxor	%xmm10, %xmm8, %xmm8
        # rnd_0: 8 - 9
        xorq	%r14, %rcx
        xorq	%r15, %rbx
        rorq	$6, %rcx
        addq	%r13, %r9
        vpxor	%xmm11, %xmm8, %xmm8
        vpaddq	%xmm5, %xmm13, %xmm5
        # rnd_0: 10 - 11
        xorq	%r14, %rcx
        addq	%rbx, %r13
        rorq	$28, %rcx
        movq	%r9, %rax
        addq	%rcx, %r13
        # rnd_1: 0 - 0
        rorq	$23, %rax
        vpaddq	%xmm5, %xmm8, %xmm5
        # rnd_1: 1 - 1
        movq	%r13, %rbx
        movq	%r10, %rcx
        addq	88(%rsp), %r12
        xorq	%r11, %rcx
        vpsrlq	$19, %xmm4, %xmm8
        vpsllq	$45, %xmm4, %xmm9
        # rnd_1: 2 - 3
        xorq	%r9, %rax
        andq	%r9, %rcx
        rorq	$4, %rax
        xorq	%r11, %rcx
        vpsrlq	$61, %xmm4, %xmm10
        vpsllq	$3, %xmm4, %xmm11
        # rnd_1: 4 - 6
        xorq	%r9, %rax
        addq	%rcx, %r12
        rorq	$14, %rax
        xorq	%r14, %rbx
        addq	%rax, %r12
        movq	%r13, %rcx
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_1: 7 - 8
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r13, %rcx
        xorq	%r14, %rdx
        vpxor	%xmm10, %xmm8, %xmm8
        vpsrlq	$6, %xmm4, %xmm11
        # rnd_1: 9 - 10
        rorq	$6, %rcx
        addq	%r12, %r8
        xorq	%r13, %rcx
        addq	%rdx, %r12
        vpxor	%xmm11, %xmm8, %xmm8
        # rnd_1: 11 - 11
        rorq	$28, %rcx
        movq	%r8, %rax
        addq	%rcx, %r12
        vpaddq	%xmm5, %xmm8, %xmm5
        # msg_sched done: 10-11
        # msg_sched: 12-13
        # rnd_0: 0 - 0
        rorq	$23, %rax
        vpalignr	$8, %xmm6, %xmm7, %xmm12
        vpalignr	$8, %xmm2, %xmm3, %xmm13
        # rnd_0: 1 - 1
        movq	%r12, %rdx
        movq	%r9, %rcx
        addq	96(%rsp), %r11
        xorq	%r10, %rcx
        vpsrlq	$0x01, %xmm12, %xmm8
        vpsllq	$63, %xmm12, %xmm9
        # rnd_0: 2 - 3
        xorq	%r8, %rax
        andq	%r8, %rcx
        rorq	$4, %rax
        xorq	%r10, %rcx
        vpsrlq	$8, %xmm12, %xmm10
        vpsllq	$56, %xmm12, %xmm11
        # rnd_0: 4 - 5
        xorq	%r8, %rax
        addq	%rcx, %r11
        rorq	$14, %rax
        xorq	%r13, %rdx
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_0: 6 - 7
        addq	%rax, %r11
        movq	%r12, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        vpsrlq	$7, %xmm12, %xmm11
        vpxor	%xmm10, %xmm8, %xmm8
        # rnd_0: 8 - 9
        xorq	%r12, %rcx
        xorq	%r13, %rbx
        rorq	$6, %rcx
        addq	%r11, %r15
        vpxor	%xmm11, %xmm8, %xmm8
        vpaddq	%xmm6, %xmm13, %xmm6
        # rnd_0: 10 - 11
        xorq	%r12, %rcx
        addq	%rbx, %r11
        rorq	$28, %rcx
        movq	%r15, %rax
        addq	%rcx, %r11
        # rnd_1: 0 - 0
        rorq	$23, %rax
        vpaddq	%xmm6, %xmm8, %xmm6
        # rnd_1: 1 - 1
        movq	%r11, %rbx
        movq	%r8, %rcx
        addq	104(%rsp), %r10
        xorq	%r9, %rcx
        vpsrlq	$19, %xmm5, %xmm8
        vpsllq	$45, %xmm5, %xmm9
        # rnd_1: 2 - 3
        xorq	%r15, %rax
        andq	%r15, %rcx
        rorq	$4, %rax
        xorq	%r9, %rcx
        vpsrlq	$61, %xmm5, %xmm10
        vpsllq	$3, %xmm5, %xmm11
        # rnd_1: 4 - 6
        xorq	%r15, %rax
        addq	%rcx, %r10
        rorq	$14, %rax
        xorq	%r12, %rbx
        addq	%rax, %r10
        movq	%r11, %rcx
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_1: 7 - 8
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r11, %rcx
        xorq	%r12, %rdx
        vpxor	%xmm10, %xmm8, %xmm8
        vpsrlq	$6, %xmm5, %xmm11
        # rnd_1: 9 - 10
        rorq	$6, %rcx
        addq	%r10, %r14
        xorq	%r11, %rcx
        addq	%rdx, %r10
        vpxor	%xmm11, %xmm8, %xmm8
        # rnd_1: 11 - 11
        rorq	$28, %rcx
        movq	%r14, %rax
        addq	%rcx, %r10
        vpaddq	%xmm6, %xmm8, %xmm6
        # msg_sched done: 12-13
        # msg_sched: 14-15
        # rnd_0: 0 - 0
        rorq	$23, %rax
        vpalignr	$8, %xmm7, %xmm0, %xmm12
        vpalignr	$8, %xmm3, %xmm4, %xmm13
        # rnd_0: 1 - 1
        movq	%r10, %rdx
        movq	%r15, %rcx
        addq	112(%rsp), %r9
        xorq	%r8, %rcx
        vpsrlq	$0x01, %xmm12, %xmm8
        vpsllq	$63, %xmm12, %xmm9
        # rnd_0: 2 - 3
        xorq	%r14, %rax
        andq	%r14, %rcx
        rorq	$4, %rax
        xorq	%r8, %rcx
        vpsrlq	$8, %xmm12, %xmm10
        vpsllq	$56, %xmm12, %xmm11
        # rnd_0: 4 - 5
        xorq	%r14, %rax
        addq	%rcx, %r9
        rorq	$14, %rax
        xorq	%r11, %rdx
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_0: 6 - 7
        addq	%rax, %r9
        movq	%r10, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        vpsrlq	$7, %xmm12, %xmm11
        vpxor	%xmm10, %xmm8, %xmm8
        # rnd_0: 8 - 9
        xorq	%r10, %rcx
        xorq	%r11, %rbx
        rorq	$6, %rcx
        addq	%r9, %r13
        vpxor	%xmm11, %xmm8, %xmm8
        vpaddq	%xmm7, %xmm13, %xmm7
        # rnd_0: 10 - 11
        xorq	%r10, %rcx
        addq	%rbx, %r9
        rorq	$28, %rcx
        movq	%r13, %rax
        addq	%rcx, %r9
        # rnd_1: 0 - 0
        rorq	$23, %rax
        vpaddq	%xmm7, %xmm8, %xmm7
        # rnd_1: 1 - 1
        movq	%r9, %rbx
        movq	%r14, %rcx
        addq	120(%rsp), %r8
        xorq	%r15, %rcx
        vpsrlq	$19, %xmm6, %xmm8
        vpsllq	$45, %xmm6, %xmm9
        # rnd_1: 2 - 3
        xorq	%r13, %rax
        andq	%r13, %rcx
        rorq	$4, %rax
        xorq	%r15, %rcx
        vpsrlq	$61, %xmm6, %xmm10
        vpsllq	$3, %xmm6, %xmm11
        # rnd_1: 4 - 6
        xorq	%r13, %rax
        addq	%rcx, %r8
        rorq	$14, %rax
        xorq	%r10, %rbx
        addq	%rax, %r8
        movq	%r9, %rcx
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_1: 7 - 8
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r9, %rcx
        xorq	%r10, %rdx
        vpxor	%xmm10, %xmm8, %xmm8
        vpsrlq	$6, %xmm6, %xmm11
        # rnd_1: 9 - 10
        rorq	$6, %rcx
        addq	%r8, %r12
        xorq	%r9, %rcx
        addq	%rdx, %r8
        vpxor	%xmm11, %xmm8, %xmm8
        # rnd_1: 11 - 11
        rorq	$28, %rcx
        movq	%r12, %rax
        addq	%rcx, %r8
        vpaddq	%xmm7, %xmm8, %xmm7
        # msg_sched done: 14-15
        subl	$0x01, 128(%rsp)
        jne	L_transform_sha512_avx1_start
        vpaddq	(%rsi), %xmm0, %xmm8
        vpaddq	16(%rsi), %xmm1, %xmm9
        vmovdqu	%xmm8, (%rsp)
        vmovdqu	%xmm9, 16(%rsp)
        vpaddq	32(%rsi), %xmm2, %xmm8
        vpaddq	48(%rsi), %xmm3, %xmm9
        vmovdqu	%xmm8, 32(%rsp)
        vmovdqu	%xmm9, 48(%rsp)
        vpaddq	64(%rsi), %xmm4, %xmm8
        vpaddq	80(%rsi), %xmm5, %xmm9
        vmovdqu	%xmm8, 64(%rsp)
        vmovdqu	%xmm9, 80(%rsp)
        vpaddq	96(%rsi), %xmm6, %xmm8
        vpaddq	112(%rsi), %xmm7, %xmm9
        vmovdqu	%xmm8, 96(%rsp)
        vmovdqu	%xmm9, 112(%rsp)
        # rnd_all_2: 0-1
        # rnd_0: 0 - 11
        rorq	$23, %rax
        movq	%r8, %rdx
        movq	%r13, %rcx
        addq	(%rsp), %r15
        xorq	%r14, %rcx
        xorq	%r12, %rax
        andq	%r12, %rcx
        rorq	$4, %rax
        xorq	%r14, %rcx
        xorq	%r12, %rax
        addq	%rcx, %r15
        rorq	$14, %rax
        xorq	%r9, %rdx
        addq	%rax, %r15
        movq	%r8, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        xorq	%r8, %rcx
        xorq	%r9, %rbx
        rorq	$6, %rcx
        addq	%r15, %r11
        xorq	%r8, %rcx
        addq	%rbx, %r15
        rorq	$28, %rcx
        movq	%r11, %rax
        addq	%rcx, %r15
        # rnd_1: 0 - 11
        rorq	$23, %rax
        movq	%r15, %rbx
        movq	%r12, %rcx
        addq	8(%rsp), %r14
        xorq	%r13, %rcx
        xorq	%r11, %rax
        andq	%r11, %rcx
        rorq	$4, %rax
        xorq	%r13, %rcx
        xorq	%r11, %rax
        addq	%rcx, %r14
        rorq	$14, %rax
        xorq	%r8, %rbx
        addq	%rax, %r14
        movq	%r15, %rcx
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r15, %rcx
        xorq	%r8, %rdx
        rorq	$6, %rcx
        addq	%r14, %r10
        xorq	%r15, %rcx
        addq	%rdx, %r14
        rorq	$28, %rcx
        movq	%r10, %rax
        addq	%rcx, %r14
        # rnd_all_2: 2-3
        # rnd_0: 0 - 11
        rorq	$23, %rax
        movq	%r14, %rdx
        movq	%r11, %rcx
        addq	16(%rsp), %r13
        xorq	%r12, %rcx
        xorq	%r10, %rax
        andq	%r10, %rcx
        rorq	$4, %rax
        xorq	%r12, %rcx
        xorq	%r10, %rax
        addq	%rcx, %r13
        rorq	$14, %rax
        xorq	%r15, %rdx
        addq	%rax, %r13
        movq	%r14, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        xorq	%r14, %rcx
        xorq	%r15, %rbx
        rorq	$6, %rcx
        addq	%r13, %r9
        xorq	%r14, %rcx
        addq	%rbx, %r13
        rorq	$28, %rcx
        movq	%r9, %rax
        addq	%rcx, %r13
        # rnd_1: 0 - 11
        rorq	$23, %rax
        movq	%r13, %rbx
        movq	%r10, %rcx
        addq	24(%rsp), %r12
        xorq	%r11, %rcx
        xorq	%r9, %rax
        andq	%r9, %rcx
        rorq	$4, %rax
        xorq	%r11, %rcx
        xorq	%r9, %rax
        addq	%rcx, %r12
        rorq	$14, %rax
        xorq	%r14, %rbx
        addq	%rax, %r12
        movq	%r13, %rcx
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r13, %rcx
        xorq	%r14, %rdx
        rorq	$6, %rcx
        addq	%r12, %r8
        xorq	%r13, %rcx
        addq	%rdx, %r12
        rorq	$28, %rcx
        movq	%r8, %rax
        addq	%rcx, %r12
        # rnd_all_2: 4-5
        # rnd_0: 0 - 11
        rorq	$23, %rax
        movq	%r12, %rdx
        movq	%r9, %rcx
        addq	32(%rsp), %r11
        xorq	%r10, %rcx
        xorq	%r8, %rax
        andq	%r8, %rcx
        rorq	$4, %rax
        xorq	%r10, %rcx
        xorq	%r8, %rax
        addq	%rcx, %r11
        rorq	$14, %rax
        xorq	%r13, %rdx
        addq	%rax, %r11
        movq	%r12, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        xorq	%r12, %rcx
        xorq	%r13, %rbx
        rorq	$6, %rcx
        addq	%r11, %r15
        xorq	%r12, %rcx
        addq	%rbx, %r11
        rorq	$28, %rcx
        movq	%r15, %rax
        addq	%rcx, %r11
        # rnd_1: 0 - 11
        rorq	$23, %rax
        movq	%r11, %rbx
        movq	%r8, %rcx
        addq	40(%rsp), %r10
        xorq	%r9, %rcx
        xorq	%r15, %rax
        andq	%r15, %rcx
        rorq	$4, %rax
        xorq	%r9, %rcx
        xorq	%r15, %rax
        addq	%rcx, %r10
        rorq	$14, %rax
        xorq	%r12, %rbx
        addq	%rax, %r10
        movq	%r11, %rcx
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r11, %rcx
        xorq	%r12, %rdx
        rorq	$6, %rcx
        addq	%r10, %r14
        xorq	%r11, %rcx
        addq	%rdx, %r10
        rorq	$28, %rcx
        movq	%r14, %rax
        addq	%rcx, %r10
        # rnd_all_2: 6-7
        # rnd_0: 0 - 11
        rorq	$23, %rax
        movq	%r10, %rdx
        movq	%r15, %rcx
        addq	48(%rsp), %r9
        xorq	%r8, %rcx
        xorq	%r14, %rax
        andq	%r14, %rcx
        rorq	$4, %rax
        xorq	%r8, %rcx
        xorq	%r14, %rax
        addq	%rcx, %r9
        rorq	$14, %rax
        xorq	%r11, %rdx
        addq	%rax, %r9
        movq	%r10, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        xorq	%r10, %rcx
        xorq	%r11, %rbx
        rorq	$6, %rcx
        addq	%r9, %r13
        xorq	%r10, %rcx
        addq	%rbx, %r9
        rorq	$28, %rcx
        movq	%r13, %rax
        addq	%rcx, %r9
        # rnd_1: 0 - 11
        rorq	$23, %rax
        movq	%r9, %rbx
        movq	%r14, %rcx
        addq	56(%rsp), %r8
        xorq	%r15, %rcx
        xorq	%r13, %rax
        andq	%r13, %rcx
        rorq	$4, %rax
        xorq	%r15, %rcx
        xorq	%r13, %rax
        addq	%rcx, %r8
        rorq	$14, %rax
        xorq	%r10, %rbx
        addq	%rax, %r8
        movq	%r9, %rcx
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r9, %rcx
        xorq	%r10, %rdx
        rorq	$6, %rcx
        addq	%r8, %r12
        xorq	%r9, %rcx
        addq	%rdx, %r8
        rorq	$28, %rcx
        movq	%r12, %rax
        addq	%rcx, %r8
        # rnd_all_2: 8-9
        # rnd_0: 0 - 11
        rorq	$23, %rax
        movq	%r8, %rdx
        movq	%r13, %rcx
        addq	64(%rsp), %r15
        xorq	%r14, %rcx
        xorq	%r12, %rax
        andq	%r12, %rcx
        rorq	$4, %rax
        xorq	%r14, %rcx
        xorq	%r12, %rax
        addq	%rcx, %r15
        rorq	$14, %rax
        xorq	%r9, %rdx
        addq	%rax, %r15
        movq	%r8, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        xorq	%r8, %rcx
        xorq	%r9, %rbx
        rorq	$6, %rcx
        addq	%r15, %r11
        xorq	%r8, %rcx
        addq	%rbx, %r15
        rorq	$28, %rcx
        movq	%r11, %rax
        addq	%rcx, %r15
        # rnd_1: 0 - 11
        rorq	$23, %rax
        movq	%r15, %rbx
        movq	%r12, %rcx
        addq	72(%rsp), %r14
        xorq	%r13, %rcx
        xorq	%r11, %rax
        andq	%r11, %rcx
        rorq	$4, %rax
        xorq	%r13, %rcx
        xorq	%r11, %rax
        addq	%rcx, %r14
        rorq	$14, %rax
        xorq	%r8, %rbx
        addq	%rax, %r14
        movq	%r15, %rcx
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r15, %rcx
        xorq	%r8, %rdx
        rorq	$6, %rcx
        addq	%r14, %r10
        xorq	%r15, %rcx
        addq	%rdx, %r14
        rorq	$28, %rcx
        movq	%r10, %rax
        addq	%rcx, %r14
        # rnd_all_2: 10-11
        # rnd_0: 0 - 11
        rorq	$23, %rax
        movq	%r14, %rdx
        movq	%r11, %rcx
        addq	80(%rsp), %r13
        xorq	%r12, %rcx
        xorq	%r10, %rax
        andq	%r10, %rcx
        rorq	$4, %rax
        xorq	%r12, %rcx
        xorq	%r10, %rax
        addq	%rcx, %r13
        rorq	$14, %rax
        xorq	%r15, %rdx
        addq	%rax, %r13
        movq	%r14, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        xorq	%r14, %rcx
        xorq	%r15, %rbx
        rorq	$6, %rcx
        addq	%r13, %r9
        xorq	%r14, %rcx
        addq	%rbx, %r13
        rorq	$28, %rcx
        movq	%r9, %rax
        addq	%rcx, %r13
        # rnd_1: 0 - 11
        rorq	$23, %rax
        movq	%r13, %rbx
        movq	%r10, %rcx
        addq	88(%rsp), %r12
        xorq	%r11, %rcx
        xorq	%r9, %rax
        andq	%r9, %rcx
        rorq	$4, %rax
        xorq	%r11, %rcx
        xorq	%r9, %rax
        addq	%rcx, %r12
        rorq	$14, %rax
        xorq	%r14, %rbx
        addq	%rax, %r12
        movq	%r13, %rcx
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r13, %rcx
        xorq	%r14, %rdx
        rorq	$6, %rcx
        addq	%r12, %r8
        xorq	%r13, %rcx
        addq	%rdx, %r12
        rorq	$28, %rcx
        movq	%r8, %rax
        addq	%rcx, %r12
        # rnd_all_2: 12-13
        # rnd_0: 0 - 11
        rorq	$23, %rax
        movq	%r12, %rdx
        movq	%r9, %rcx
        addq	96(%rsp), %r11
        xorq	%r10, %rcx
        xorq	%r8, %rax
        andq	%r8, %rcx
        rorq	$4, %rax
        xorq	%r10, %rcx
        xorq	%r8, %rax
        addq	%rcx, %r11
        rorq	$14, %rax
        xorq	%r13, %rdx
        addq	%rax, %r11
        movq	%r12, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        xorq	%r12, %rcx
        xorq	%r13, %rbx
        rorq	$6, %rcx
        addq	%r11, %r15
        xorq	%r12, %rcx
        addq	%rbx, %r11
        rorq	$28, %rcx
        movq	%r15, %rax
        addq	%rcx, %r11
        # rnd_1: 0 - 11
        rorq	$23, %rax
        movq	%r11, %rbx
        movq	%r8, %rcx
        addq	104(%rsp), %r10
        xorq	%r9, %rcx
        xorq	%r15, %rax
        andq	%r15, %rcx
        rorq	$4, %rax
        xorq	%r9, %rcx
        xorq	%r15, %rax
        addq	%rcx, %r10
        rorq	$14, %rax
        xorq	%r12, %rbx
        addq	%rax, %r10
        movq	%r11, %rcx
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r11, %rcx
        xorq	%r12, %rdx
        rorq	$6, %rcx
        addq	%r10, %r14
        xorq	%r11, %rcx
        addq	%rdx, %r10
        rorq	$28, %rcx
        movq	%r14, %rax
        addq	%rcx, %r10
        # rnd_all_2: 14-15
        # rnd_0: 0 - 11
        rorq	$23, %rax
        movq	%r10, %rdx
        movq	%r15, %rcx
        addq	112(%rsp), %r9
        xorq	%r8, %rcx
        xorq	%r14, %rax
        andq	%r14, %rcx
        rorq	$4, %rax
        xorq	%r8, %rcx
        xorq	%r14, %rax
        addq	%rcx, %r9
        rorq	$14, %rax
        xorq	%r11, %rdx
        addq	%rax, %r9
        movq	%r10, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        xorq	%r10, %rcx
        xorq	%r11, %rbx
        rorq	$6, %rcx
        addq	%r9, %r13
        xorq	%r10, %rcx
        addq	%rbx, %r9
        rorq	$28, %rcx
        movq	%r13, %rax
        addq	%rcx, %r9
        # rnd_1: 0 - 11
        rorq	$23, %rax
        movq	%r9, %rbx
        movq	%r14, %rcx
        addq	120(%rsp), %r8
        xorq	%r15, %rcx
        xorq	%r13, %rax
        andq	%r13, %rcx
        rorq	$4, %rax
        xorq	%r15, %rcx
        xorq	%r13, %rax
        addq	%rcx, %r8
        rorq	$14, %rax
        xorq	%r10, %rbx
        addq	%rax, %r8
        movq	%r9, %rcx
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r9, %rcx
        xorq	%r10, %rdx
        rorq	$6, %rcx
        addq	%r8, %r12
        xorq	%r9, %rcx
        addq	%rdx, %r8
        rorq	$28, %rcx
        movq	%r12, %rax
        addq	%rcx, %r8
        addq	%r8, (%rdi)
        addq	%r9, 8(%rdi)
        addq	%r10, 16(%rdi)
        addq	%r11, 24(%rdi)
        addq	%r12, 32(%rdi)
        addq	%r13, 40(%rdi)
        addq	%r14, 48(%rdi)
        addq	%r15, 56(%rdi)
        xorq	%rax, %rax
        addq	$0x90, %rsp
        popq	%r15
        popq	%r14
        popq	%r13
        popq	%r12
        popq	%rbx
        repz retq
#ifndef __APPLE__
.size	Transform_Sha512_AVX1,.-Transform_Sha512_AVX1
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	Transform_Sha512_AVX1_Len
WC_ASM_ATT_HIDDEN(Transform_Sha512_AVX1_Len)
.type	Transform_Sha512_AVX1_Len,@function
.align	16
Transform_Sha512_AVX1_Len:
#else
.section	__TEXT,__text
.globl	_Transform_Sha512_AVX1_Len
WC_ASM_ATT_HIDDEN(_Transform_Sha512_AVX1_Len)
.p2align	4
_Transform_Sha512_AVX1_Len:
#endif /* __APPLE__ */
        pushq	%rbx
        pushq	%r12
        pushq	%r13
        pushq	%r14
        pushq	%r15
        pushq	%rbp
        movq	%rsi, %rbp
        subq	$0x98, %rsp
        movq	224(%rdi), %rsi
        leaq	L_avx1_sha512_k(%rip), %rdx
        vmovdqa	L_avx1_sha512_flip_mask(%rip), %xmm14
        movq	(%rdi), %r8
        movq	8(%rdi), %r9
        movq	16(%rdi), %r10
        movq	24(%rdi), %r11
        movq	32(%rdi), %r12
        movq	40(%rdi), %r13
        movq	48(%rdi), %r14
        movq	56(%rdi), %r15
        # Start of loop processing a block
L_sha512_len_avx1_begin:
        vmovdqu	(%rsi), %xmm0
        vmovdqu	16(%rsi), %xmm1
        vpshufb	%xmm14, %xmm0, %xmm0
        vpshufb	%xmm14, %xmm1, %xmm1
        vmovdqu	32(%rsi), %xmm2
        vmovdqu	48(%rsi), %xmm3
        vpshufb	%xmm14, %xmm2, %xmm2
        vpshufb	%xmm14, %xmm3, %xmm3
        vmovdqu	64(%rsi), %xmm4
        vmovdqu	80(%rsi), %xmm5
        vpshufb	%xmm14, %xmm4, %xmm4
        vpshufb	%xmm14, %xmm5, %xmm5
        vmovdqu	96(%rsi), %xmm6
        vmovdqu	112(%rsi), %xmm7
        vpshufb	%xmm14, %xmm6, %xmm6
        vpshufb	%xmm14, %xmm7, %xmm7
        movl	$4, 128(%rsp)
        movq	%r9, %rbx
        movq	%r12, %rax
        xorq	%r10, %rbx
        vpaddq	(%rdx), %xmm0, %xmm8
        vpaddq	16(%rdx), %xmm1, %xmm9
        vmovdqu	%xmm8, (%rsp)
        vmovdqu	%xmm9, 16(%rsp)
        vpaddq	32(%rdx), %xmm2, %xmm8
        vpaddq	48(%rdx), %xmm3, %xmm9
        vmovdqu	%xmm8, 32(%rsp)
        vmovdqu	%xmm9, 48(%rsp)
        vpaddq	64(%rdx), %xmm4, %xmm8
        vpaddq	80(%rdx), %xmm5, %xmm9
        vmovdqu	%xmm8, 64(%rsp)
        vmovdqu	%xmm9, 80(%rsp)
        vpaddq	96(%rdx), %xmm6, %xmm8
        vpaddq	112(%rdx), %xmm7, %xmm9
        vmovdqu	%xmm8, 96(%rsp)
        vmovdqu	%xmm9, 112(%rsp)
        # Start of 16 rounds
L_sha512_len_avx1_start:
        addq	$0x80, %rdx
        movq	%rdx, 136(%rsp)
        # msg_sched: 0-1
        # rnd_0: 0 - 0
        rorq	$23, %rax
        vpalignr	$8, %xmm0, %xmm1, %xmm12
        vpalignr	$8, %xmm4, %xmm5, %xmm13
        # rnd_0: 1 - 1
        movq	%r8, %rdx
        movq	%r13, %rcx
        addq	(%rsp), %r15
        xorq	%r14, %rcx
        vpsrlq	$0x01, %xmm12, %xmm8
        vpsllq	$63, %xmm12, %xmm9
        # rnd_0: 2 - 3
        xorq	%r12, %rax
        andq	%r12, %rcx
        rorq	$4, %rax
        xorq	%r14, %rcx
        vpsrlq	$8, %xmm12, %xmm10
        vpsllq	$56, %xmm12, %xmm11
        # rnd_0: 4 - 5
        xorq	%r12, %rax
        addq	%rcx, %r15
        rorq	$14, %rax
        xorq	%r9, %rdx
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_0: 6 - 7
        addq	%rax, %r15
        movq	%r8, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        vpsrlq	$7, %xmm12, %xmm11
        vpxor	%xmm10, %xmm8, %xmm8
        # rnd_0: 8 - 9
        xorq	%r8, %rcx
        xorq	%r9, %rbx
        rorq	$6, %rcx
        addq	%r15, %r11
        vpxor	%xmm11, %xmm8, %xmm8
        vpaddq	%xmm0, %xmm13, %xmm0
        # rnd_0: 10 - 11
        xorq	%r8, %rcx
        addq	%rbx, %r15
        rorq	$28, %rcx
        movq	%r11, %rax
        addq	%rcx, %r15
        # rnd_1: 0 - 0
        rorq	$23, %rax
        vpaddq	%xmm0, %xmm8, %xmm0
        # rnd_1: 1 - 1
        movq	%r15, %rbx
        movq	%r12, %rcx
        addq	8(%rsp), %r14
        xorq	%r13, %rcx
        vpsrlq	$19, %xmm7, %xmm8
        vpsllq	$45, %xmm7, %xmm9
        # rnd_1: 2 - 3
        xorq	%r11, %rax
        andq	%r11, %rcx
        rorq	$4, %rax
        xorq	%r13, %rcx
        vpsrlq	$61, %xmm7, %xmm10
        vpsllq	$3, %xmm7, %xmm11
        # rnd_1: 4 - 6
        xorq	%r11, %rax
        addq	%rcx, %r14
        rorq	$14, %rax
        xorq	%r8, %rbx
        addq	%rax, %r14
        movq	%r15, %rcx
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_1: 7 - 8
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r15, %rcx
        xorq	%r8, %rdx
        vpxor	%xmm10, %xmm8, %xmm8
        vpsrlq	$6, %xmm7, %xmm11
        # rnd_1: 9 - 10
        rorq	$6, %rcx
        addq	%r14, %r10
        xorq	%r15, %rcx
        addq	%rdx, %r14
        vpxor	%xmm11, %xmm8, %xmm8
        # rnd_1: 11 - 11
        rorq	$28, %rcx
        movq	%r10, %rax
        addq	%rcx, %r14
        vpaddq	%xmm0, %xmm8, %xmm0
        # msg_sched done: 0-1
        # msg_sched: 2-3
        # rnd_0: 0 - 0
        rorq	$23, %rax
        vpalignr	$8, %xmm1, %xmm2, %xmm12
        vpalignr	$8, %xmm5, %xmm6, %xmm13
        # rnd_0: 1 - 1
        movq	%r14, %rdx
        movq	%r11, %rcx
        addq	16(%rsp), %r13
        xorq	%r12, %rcx
        vpsrlq	$0x01, %xmm12, %xmm8
        vpsllq	$63, %xmm12, %xmm9
        # rnd_0: 2 - 3
        xorq	%r10, %rax
        andq	%r10, %rcx
        rorq	$4, %rax
        xorq	%r12, %rcx
        vpsrlq	$8, %xmm12, %xmm10
        vpsllq	$56, %xmm12, %xmm11
        # rnd_0: 4 - 5
        xorq	%r10, %rax
        addq	%rcx, %r13
        rorq	$14, %rax
        xorq	%r15, %rdx
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_0: 6 - 7
        addq	%rax, %r13
        movq	%r14, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        vpsrlq	$7, %xmm12, %xmm11
        vpxor	%xmm10, %xmm8, %xmm8
        # rnd_0: 8 - 9
        xorq	%r14, %rcx
        xorq	%r15, %rbx
        rorq	$6, %rcx
        addq	%r13, %r9
        vpxor	%xmm11, %xmm8, %xmm8
        vpaddq	%xmm1, %xmm13, %xmm1
        # rnd_0: 10 - 11
        xorq	%r14, %rcx
        addq	%rbx, %r13
        rorq	$28, %rcx
        movq	%r9, %rax
        addq	%rcx, %r13
        # rnd_1: 0 - 0
        rorq	$23, %rax
        vpaddq	%xmm1, %xmm8, %xmm1
        # rnd_1: 1 - 1
        movq	%r13, %rbx
        movq	%r10, %rcx
        addq	24(%rsp), %r12
        xorq	%r11, %rcx
        vpsrlq	$19, %xmm0, %xmm8
        vpsllq	$45, %xmm0, %xmm9
        # rnd_1: 2 - 3
        xorq	%r9, %rax
        andq	%r9, %rcx
        rorq	$4, %rax
        xorq	%r11, %rcx
        vpsrlq	$61, %xmm0, %xmm10
        vpsllq	$3, %xmm0, %xmm11
        # rnd_1: 4 - 6
        xorq	%r9, %rax
        addq	%rcx, %r12
        rorq	$14, %rax
        xorq	%r14, %rbx
        addq	%rax, %r12
        movq	%r13, %rcx
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_1: 7 - 8
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r13, %rcx
        xorq	%r14, %rdx
        vpxor	%xmm10, %xmm8, %xmm8
        vpsrlq	$6, %xmm0, %xmm11
        # rnd_1: 9 - 10
        rorq	$6, %rcx
        addq	%r12, %r8
        xorq	%r13, %rcx
        addq	%rdx, %r12
        vpxor	%xmm11, %xmm8, %xmm8
        # rnd_1: 11 - 11
        rorq	$28, %rcx
        movq	%r8, %rax
        addq	%rcx, %r12
        vpaddq	%xmm1, %xmm8, %xmm1
        # msg_sched done: 2-3
        # msg_sched: 4-5
        # rnd_0: 0 - 0
        rorq	$23, %rax
        vpalignr	$8, %xmm2, %xmm3, %xmm12
        vpalignr	$8, %xmm6, %xmm7, %xmm13
        # rnd_0: 1 - 1
        movq	%r12, %rdx
        movq	%r9, %rcx
        addq	32(%rsp), %r11
        xorq	%r10, %rcx
        vpsrlq	$0x01, %xmm12, %xmm8
        vpsllq	$63, %xmm12, %xmm9
        # rnd_0: 2 - 3
        xorq	%r8, %rax
        andq	%r8, %rcx
        rorq	$4, %rax
        xorq	%r10, %rcx
        vpsrlq	$8, %xmm12, %xmm10
        vpsllq	$56, %xmm12, %xmm11
        # rnd_0: 4 - 5
        xorq	%r8, %rax
        addq	%rcx, %r11
        rorq	$14, %rax
        xorq	%r13, %rdx
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_0: 6 - 7
        addq	%rax, %r11
        movq	%r12, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        vpsrlq	$7, %xmm12, %xmm11
        vpxor	%xmm10, %xmm8, %xmm8
        # rnd_0: 8 - 9
        xorq	%r12, %rcx
        xorq	%r13, %rbx
        rorq	$6, %rcx
        addq	%r11, %r15
        vpxor	%xmm11, %xmm8, %xmm8
        vpaddq	%xmm2, %xmm13, %xmm2
        # rnd_0: 10 - 11
        xorq	%r12, %rcx
        addq	%rbx, %r11
        rorq	$28, %rcx
        movq	%r15, %rax
        addq	%rcx, %r11
        # rnd_1: 0 - 0
        rorq	$23, %rax
        vpaddq	%xmm2, %xmm8, %xmm2
        # rnd_1: 1 - 1
        movq	%r11, %rbx
        movq	%r8, %rcx
        addq	40(%rsp), %r10
        xorq	%r9, %rcx
        vpsrlq	$19, %xmm1, %xmm8
        vpsllq	$45, %xmm1, %xmm9
        # rnd_1: 2 - 3
        xorq	%r15, %rax
        andq	%r15, %rcx
        rorq	$4, %rax
        xorq	%r9, %rcx
        vpsrlq	$61, %xmm1, %xmm10
        vpsllq	$3, %xmm1, %xmm11
        # rnd_1: 4 - 6
        xorq	%r15, %rax
        addq	%rcx, %r10
        rorq	$14, %rax
        xorq	%r12, %rbx
        addq	%rax, %r10
        movq	%r11, %rcx
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_1: 7 - 8
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r11, %rcx
        xorq	%r12, %rdx
        vpxor	%xmm10, %xmm8, %xmm8
        vpsrlq	$6, %xmm1, %xmm11
        # rnd_1: 9 - 10
        rorq	$6, %rcx
        addq	%r10, %r14
        xorq	%r11, %rcx
        addq	%rdx, %r10
        vpxor	%xmm11, %xmm8, %xmm8
        # rnd_1: 11 - 11
        rorq	$28, %rcx
        movq	%r14, %rax
        addq	%rcx, %r10
        vpaddq	%xmm2, %xmm8, %xmm2
        # msg_sched done: 4-5
        # msg_sched: 6-7
        # rnd_0: 0 - 0
        rorq	$23, %rax
        vpalignr	$8, %xmm3, %xmm4, %xmm12
        vpalignr	$8, %xmm7, %xmm0, %xmm13
        # rnd_0: 1 - 1
        movq	%r10, %rdx
        movq	%r15, %rcx
        addq	48(%rsp), %r9
        xorq	%r8, %rcx
        vpsrlq	$0x01, %xmm12, %xmm8
        vpsllq	$63, %xmm12, %xmm9
        # rnd_0: 2 - 3
        xorq	%r14, %rax
        andq	%r14, %rcx
        rorq	$4, %rax
        xorq	%r8, %rcx
        vpsrlq	$8, %xmm12, %xmm10
        vpsllq	$56, %xmm12, %xmm11
        # rnd_0: 4 - 5
        xorq	%r14, %rax
        addq	%rcx, %r9
        rorq	$14, %rax
        xorq	%r11, %rdx
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_0: 6 - 7
        addq	%rax, %r9
        movq	%r10, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        vpsrlq	$7, %xmm12, %xmm11
        vpxor	%xmm10, %xmm8, %xmm8
        # rnd_0: 8 - 9
        xorq	%r10, %rcx
        xorq	%r11, %rbx
        rorq	$6, %rcx
        addq	%r9, %r13
        vpxor	%xmm11, %xmm8, %xmm8
        vpaddq	%xmm3, %xmm13, %xmm3
        # rnd_0: 10 - 11
        xorq	%r10, %rcx
        addq	%rbx, %r9
        rorq	$28, %rcx
        movq	%r13, %rax
        addq	%rcx, %r9
        # rnd_1: 0 - 0
        rorq	$23, %rax
        vpaddq	%xmm3, %xmm8, %xmm3
        # rnd_1: 1 - 1
        movq	%r9, %rbx
        movq	%r14, %rcx
        addq	56(%rsp), %r8
        xorq	%r15, %rcx
        vpsrlq	$19, %xmm2, %xmm8
        vpsllq	$45, %xmm2, %xmm9
        # rnd_1: 2 - 3
        xorq	%r13, %rax
        andq	%r13, %rcx
        rorq	$4, %rax
        xorq	%r15, %rcx
        vpsrlq	$61, %xmm2, %xmm10
        vpsllq	$3, %xmm2, %xmm11
        # rnd_1: 4 - 6
        xorq	%r13, %rax
        addq	%rcx, %r8
        rorq	$14, %rax
        xorq	%r10, %rbx
        addq	%rax, %r8
        movq	%r9, %rcx
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_1: 7 - 8
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r9, %rcx
        xorq	%r10, %rdx
        vpxor	%xmm10, %xmm8, %xmm8
        vpsrlq	$6, %xmm2, %xmm11
        # rnd_1: 9 - 10
        rorq	$6, %rcx
        addq	%r8, %r12
        xorq	%r9, %rcx
        addq	%rdx, %r8
        vpxor	%xmm11, %xmm8, %xmm8
        # rnd_1: 11 - 11
        rorq	$28, %rcx
        movq	%r12, %rax
        addq	%rcx, %r8
        vpaddq	%xmm3, %xmm8, %xmm3
        # msg_sched done: 6-7
        # msg_sched: 8-9
        # rnd_0: 0 - 0
        rorq	$23, %rax
        vpalignr	$8, %xmm4, %xmm5, %xmm12
        vpalignr	$8, %xmm0, %xmm1, %xmm13
        # rnd_0: 1 - 1
        movq	%r8, %rdx
        movq	%r13, %rcx
        addq	64(%rsp), %r15
        xorq	%r14, %rcx
        vpsrlq	$0x01, %xmm12, %xmm8
        vpsllq	$63, %xmm12, %xmm9
        # rnd_0: 2 - 3
        xorq	%r12, %rax
        andq	%r12, %rcx
        rorq	$4, %rax
        xorq	%r14, %rcx
        vpsrlq	$8, %xmm12, %xmm10
        vpsllq	$56, %xmm12, %xmm11
        # rnd_0: 4 - 5
        xorq	%r12, %rax
        addq	%rcx, %r15
        rorq	$14, %rax
        xorq	%r9, %rdx
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_0: 6 - 7
        addq	%rax, %r15
        movq	%r8, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        vpsrlq	$7, %xmm12, %xmm11
        vpxor	%xmm10, %xmm8, %xmm8
        # rnd_0: 8 - 9
        xorq	%r8, %rcx
        xorq	%r9, %rbx
        rorq	$6, %rcx
        addq	%r15, %r11
        vpxor	%xmm11, %xmm8, %xmm8
        vpaddq	%xmm4, %xmm13, %xmm4
        # rnd_0: 10 - 11
        xorq	%r8, %rcx
        addq	%rbx, %r15
        rorq	$28, %rcx
        movq	%r11, %rax
        addq	%rcx, %r15
        # rnd_1: 0 - 0
        rorq	$23, %rax
        vpaddq	%xmm4, %xmm8, %xmm4
        # rnd_1: 1 - 1
        movq	%r15, %rbx
        movq	%r12, %rcx
        addq	72(%rsp), %r14
        xorq	%r13, %rcx
        vpsrlq	$19, %xmm3, %xmm8
        vpsllq	$45, %xmm3, %xmm9
        # rnd_1: 2 - 3
        xorq	%r11, %rax
        andq	%r11, %rcx
        rorq	$4, %rax
        xorq	%r13, %rcx
        vpsrlq	$61, %xmm3, %xmm10
        vpsllq	$3, %xmm3, %xmm11
        # rnd_1: 4 - 6
        xorq	%r11, %rax
        addq	%rcx, %r14
        rorq	$14, %rax
        xorq	%r8, %rbx
        addq	%rax, %r14
        movq	%r15, %rcx
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_1: 7 - 8
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r15, %rcx
        xorq	%r8, %rdx
        vpxor	%xmm10, %xmm8, %xmm8
        vpsrlq	$6, %xmm3, %xmm11
        # rnd_1: 9 - 10
        rorq	$6, %rcx
        addq	%r14, %r10
        xorq	%r15, %rcx
        addq	%rdx, %r14
        vpxor	%xmm11, %xmm8, %xmm8
        # rnd_1: 11 - 11
        rorq	$28, %rcx
        movq	%r10, %rax
        addq	%rcx, %r14
        vpaddq	%xmm4, %xmm8, %xmm4
        # msg_sched done: 8-9
        # msg_sched: 10-11
        # rnd_0: 0 - 0
        rorq	$23, %rax
        vpalignr	$8, %xmm5, %xmm6, %xmm12
        vpalignr	$8, %xmm1, %xmm2, %xmm13
        # rnd_0: 1 - 1
        movq	%r14, %rdx
        movq	%r11, %rcx
        addq	80(%rsp), %r13
        xorq	%r12, %rcx
        vpsrlq	$0x01, %xmm12, %xmm8
        vpsllq	$63, %xmm12, %xmm9
        # rnd_0: 2 - 3
        xorq	%r10, %rax
        andq	%r10, %rcx
        rorq	$4, %rax
        xorq	%r12, %rcx
        vpsrlq	$8, %xmm12, %xmm10
        vpsllq	$56, %xmm12, %xmm11
        # rnd_0: 4 - 5
        xorq	%r10, %rax
        addq	%rcx, %r13
        rorq	$14, %rax
        xorq	%r15, %rdx
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_0: 6 - 7
        addq	%rax, %r13
        movq	%r14, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        vpsrlq	$7, %xmm12, %xmm11
        vpxor	%xmm10, %xmm8, %xmm8
        # rnd_0: 8 - 9
        xorq	%r14, %rcx
        xorq	%r15, %rbx
        rorq	$6, %rcx
        addq	%r13, %r9
        vpxor	%xmm11, %xmm8, %xmm8
        vpaddq	%xmm5, %xmm13, %xmm5
        # rnd_0: 10 - 11
        xorq	%r14, %rcx
        addq	%rbx, %r13
        rorq	$28, %rcx
        movq	%r9, %rax
        addq	%rcx, %r13
        # rnd_1: 0 - 0
        rorq	$23, %rax
        vpaddq	%xmm5, %xmm8, %xmm5
        # rnd_1: 1 - 1
        movq	%r13, %rbx
        movq	%r10, %rcx
        addq	88(%rsp), %r12
        xorq	%r11, %rcx
        vpsrlq	$19, %xmm4, %xmm8
        vpsllq	$45, %xmm4, %xmm9
        # rnd_1: 2 - 3
        xorq	%r9, %rax
        andq	%r9, %rcx
        rorq	$4, %rax
        xorq	%r11, %rcx
        vpsrlq	$61, %xmm4, %xmm10
        vpsllq	$3, %xmm4, %xmm11
        # rnd_1: 4 - 6
        xorq	%r9, %rax
        addq	%rcx, %r12
        rorq	$14, %rax
        xorq	%r14, %rbx
        addq	%rax, %r12
        movq	%r13, %rcx
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_1: 7 - 8
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r13, %rcx
        xorq	%r14, %rdx
        vpxor	%xmm10, %xmm8, %xmm8
        vpsrlq	$6, %xmm4, %xmm11
        # rnd_1: 9 - 10
        rorq	$6, %rcx
        addq	%r12, %r8
        xorq	%r13, %rcx
        addq	%rdx, %r12
        vpxor	%xmm11, %xmm8, %xmm8
        # rnd_1: 11 - 11
        rorq	$28, %rcx
        movq	%r8, %rax
        addq	%rcx, %r12
        vpaddq	%xmm5, %xmm8, %xmm5
        # msg_sched done: 10-11
        # msg_sched: 12-13
        # rnd_0: 0 - 0
        rorq	$23, %rax
        vpalignr	$8, %xmm6, %xmm7, %xmm12
        vpalignr	$8, %xmm2, %xmm3, %xmm13
        # rnd_0: 1 - 1
        movq	%r12, %rdx
        movq	%r9, %rcx
        addq	96(%rsp), %r11
        xorq	%r10, %rcx
        vpsrlq	$0x01, %xmm12, %xmm8
        vpsllq	$63, %xmm12, %xmm9
        # rnd_0: 2 - 3
        xorq	%r8, %rax
        andq	%r8, %rcx
        rorq	$4, %rax
        xorq	%r10, %rcx
        vpsrlq	$8, %xmm12, %xmm10
        vpsllq	$56, %xmm12, %xmm11
        # rnd_0: 4 - 5
        xorq	%r8, %rax
        addq	%rcx, %r11
        rorq	$14, %rax
        xorq	%r13, %rdx
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_0: 6 - 7
        addq	%rax, %r11
        movq	%r12, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        vpsrlq	$7, %xmm12, %xmm11
        vpxor	%xmm10, %xmm8, %xmm8
        # rnd_0: 8 - 9
        xorq	%r12, %rcx
        xorq	%r13, %rbx
        rorq	$6, %rcx
        addq	%r11, %r15
        vpxor	%xmm11, %xmm8, %xmm8
        vpaddq	%xmm6, %xmm13, %xmm6
        # rnd_0: 10 - 11
        xorq	%r12, %rcx
        addq	%rbx, %r11
        rorq	$28, %rcx
        movq	%r15, %rax
        addq	%rcx, %r11
        # rnd_1: 0 - 0
        rorq	$23, %rax
        vpaddq	%xmm6, %xmm8, %xmm6
        # rnd_1: 1 - 1
        movq	%r11, %rbx
        movq	%r8, %rcx
        addq	104(%rsp), %r10
        xorq	%r9, %rcx
        vpsrlq	$19, %xmm5, %xmm8
        vpsllq	$45, %xmm5, %xmm9
        # rnd_1: 2 - 3
        xorq	%r15, %rax
        andq	%r15, %rcx
        rorq	$4, %rax
        xorq	%r9, %rcx
        vpsrlq	$61, %xmm5, %xmm10
        vpsllq	$3, %xmm5, %xmm11
        # rnd_1: 4 - 6
        xorq	%r15, %rax
        addq	%rcx, %r10
        rorq	$14, %rax
        xorq	%r12, %rbx
        addq	%rax, %r10
        movq	%r11, %rcx
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_1: 7 - 8
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r11, %rcx
        xorq	%r12, %rdx
        vpxor	%xmm10, %xmm8, %xmm8
        vpsrlq	$6, %xmm5, %xmm11
        # rnd_1: 9 - 10
        rorq	$6, %rcx
        addq	%r10, %r14
        xorq	%r11, %rcx
        addq	%rdx, %r10
        vpxor	%xmm11, %xmm8, %xmm8
        # rnd_1: 11 - 11
        rorq	$28, %rcx
        movq	%r14, %rax
        addq	%rcx, %r10
        vpaddq	%xmm6, %xmm8, %xmm6
        # msg_sched done: 12-13
        # msg_sched: 14-15
        # rnd_0: 0 - 0
        rorq	$23, %rax
        vpalignr	$8, %xmm7, %xmm0, %xmm12
        vpalignr	$8, %xmm3, %xmm4, %xmm13
        # rnd_0: 1 - 1
        movq	%r10, %rdx
        movq	%r15, %rcx
        addq	112(%rsp), %r9
        xorq	%r8, %rcx
        vpsrlq	$0x01, %xmm12, %xmm8
        vpsllq	$63, %xmm12, %xmm9
        # rnd_0: 2 - 3
        xorq	%r14, %rax
        andq	%r14, %rcx
        rorq	$4, %rax
        xorq	%r8, %rcx
        vpsrlq	$8, %xmm12, %xmm10
        vpsllq	$56, %xmm12, %xmm11
        # rnd_0: 4 - 5
        xorq	%r14, %rax
        addq	%rcx, %r9
        rorq	$14, %rax
        xorq	%r11, %rdx
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_0: 6 - 7
        addq	%rax, %r9
        movq	%r10, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        vpsrlq	$7, %xmm12, %xmm11
        vpxor	%xmm10, %xmm8, %xmm8
        # rnd_0: 8 - 9
        xorq	%r10, %rcx
        xorq	%r11, %rbx
        rorq	$6, %rcx
        addq	%r9, %r13
        vpxor	%xmm11, %xmm8, %xmm8
        vpaddq	%xmm7, %xmm13, %xmm7
        # rnd_0: 10 - 11
        xorq	%r10, %rcx
        addq	%rbx, %r9
        rorq	$28, %rcx
        movq	%r13, %rax
        addq	%rcx, %r9
        # rnd_1: 0 - 0
        rorq	$23, %rax
        vpaddq	%xmm7, %xmm8, %xmm7
        # rnd_1: 1 - 1
        movq	%r9, %rbx
        movq	%r14, %rcx
        addq	120(%rsp), %r8
        xorq	%r15, %rcx
        vpsrlq	$19, %xmm6, %xmm8
        vpsllq	$45, %xmm6, %xmm9
        # rnd_1: 2 - 3
        xorq	%r13, %rax
        andq	%r13, %rcx
        rorq	$4, %rax
        xorq	%r15, %rcx
        vpsrlq	$61, %xmm6, %xmm10
        vpsllq	$3, %xmm6, %xmm11
        # rnd_1: 4 - 6
        xorq	%r13, %rax
        addq	%rcx, %r8
        rorq	$14, %rax
        xorq	%r10, %rbx
        addq	%rax, %r8
        movq	%r9, %rcx
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_1: 7 - 8
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r9, %rcx
        xorq	%r10, %rdx
        vpxor	%xmm10, %xmm8, %xmm8
        vpsrlq	$6, %xmm6, %xmm11
        # rnd_1: 9 - 10
        rorq	$6, %rcx
        addq	%r8, %r12
        xorq	%r9, %rcx
        addq	%rdx, %r8
        vpxor	%xmm11, %xmm8, %xmm8
        # rnd_1: 11 - 11
        rorq	$28, %rcx
        movq	%r12, %rax
        addq	%rcx, %r8
        vpaddq	%xmm7, %xmm8, %xmm7
        # msg_sched done: 14-15
        movq	136(%rsp), %rdx
        vpaddq	(%rdx), %xmm0, %xmm8
        vpaddq	16(%rdx), %xmm1, %xmm9
        vmovdqu	%xmm8, (%rsp)
        vmovdqu	%xmm9, 16(%rsp)
        vpaddq	32(%rdx), %xmm2, %xmm8
        vpaddq	48(%rdx), %xmm3, %xmm9
        vmovdqu	%xmm8, 32(%rsp)
        vmovdqu	%xmm9, 48(%rsp)
        vpaddq	64(%rdx), %xmm4, %xmm8
        vpaddq	80(%rdx), %xmm5, %xmm9
        vmovdqu	%xmm8, 64(%rsp)
        vmovdqu	%xmm9, 80(%rsp)
        vpaddq	96(%rdx), %xmm6, %xmm8
        vpaddq	112(%rdx), %xmm7, %xmm9
        vmovdqu	%xmm8, 96(%rsp)
        vmovdqu	%xmm9, 112(%rsp)
        subl	$0x01, 128(%rsp)
        jne	L_sha512_len_avx1_start
        # rnd_all_2: 0-1
        # rnd_0: 0 - 11
        rorq	$23, %rax
        movq	%r8, %rdx
        movq	%r13, %rcx
        addq	(%rsp), %r15
        xorq	%r14, %rcx
        xorq	%r12, %rax
        andq	%r12, %rcx
        rorq	$4, %rax
        xorq	%r14, %rcx
        xorq	%r12, %rax
        addq	%rcx, %r15
        rorq	$14, %rax
        xorq	%r9, %rdx
        addq	%rax, %r15
        movq	%r8, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        xorq	%r8, %rcx
        xorq	%r9, %rbx
        rorq	$6, %rcx
        addq	%r15, %r11
        xorq	%r8, %rcx
        addq	%rbx, %r15
        rorq	$28, %rcx
        movq	%r11, %rax
        addq	%rcx, %r15
        # rnd_1: 0 - 11
        rorq	$23, %rax
        movq	%r15, %rbx
        movq	%r12, %rcx
        addq	8(%rsp), %r14
        xorq	%r13, %rcx
        xorq	%r11, %rax
        andq	%r11, %rcx
        rorq	$4, %rax
        xorq	%r13, %rcx
        xorq	%r11, %rax
        addq	%rcx, %r14
        rorq	$14, %rax
        xorq	%r8, %rbx
        addq	%rax, %r14
        movq	%r15, %rcx
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r15, %rcx
        xorq	%r8, %rdx
        rorq	$6, %rcx
        addq	%r14, %r10
        xorq	%r15, %rcx
        addq	%rdx, %r14
        rorq	$28, %rcx
        movq	%r10, %rax
        addq	%rcx, %r14
        # rnd_all_2: 2-3
        # rnd_0: 0 - 11
        rorq	$23, %rax
        movq	%r14, %rdx
        movq	%r11, %rcx
        addq	16(%rsp), %r13
        xorq	%r12, %rcx
        xorq	%r10, %rax
        andq	%r10, %rcx
        rorq	$4, %rax
        xorq	%r12, %rcx
        xorq	%r10, %rax
        addq	%rcx, %r13
        rorq	$14, %rax
        xorq	%r15, %rdx
        addq	%rax, %r13
        movq	%r14, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        xorq	%r14, %rcx
        xorq	%r15, %rbx
        rorq	$6, %rcx
        addq	%r13, %r9
        xorq	%r14, %rcx
        addq	%rbx, %r13
        rorq	$28, %rcx
        movq	%r9, %rax
        addq	%rcx, %r13
        # rnd_1: 0 - 11
        rorq	$23, %rax
        movq	%r13, %rbx
        movq	%r10, %rcx
        addq	24(%rsp), %r12
        xorq	%r11, %rcx
        xorq	%r9, %rax
        andq	%r9, %rcx
        rorq	$4, %rax
        xorq	%r11, %rcx
        xorq	%r9, %rax
        addq	%rcx, %r12
        rorq	$14, %rax
        xorq	%r14, %rbx
        addq	%rax, %r12
        movq	%r13, %rcx
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r13, %rcx
        xorq	%r14, %rdx
        rorq	$6, %rcx
        addq	%r12, %r8
        xorq	%r13, %rcx
        addq	%rdx, %r12
        rorq	$28, %rcx
        movq	%r8, %rax
        addq	%rcx, %r12
        # rnd_all_2: 4-5
        # rnd_0: 0 - 11
        rorq	$23, %rax
        movq	%r12, %rdx
        movq	%r9, %rcx
        addq	32(%rsp), %r11
        xorq	%r10, %rcx
        xorq	%r8, %rax
        andq	%r8, %rcx
        rorq	$4, %rax
        xorq	%r10, %rcx
        xorq	%r8, %rax
        addq	%rcx, %r11
        rorq	$14, %rax
        xorq	%r13, %rdx
        addq	%rax, %r11
        movq	%r12, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        xorq	%r12, %rcx
        xorq	%r13, %rbx
        rorq	$6, %rcx
        addq	%r11, %r15
        xorq	%r12, %rcx
        addq	%rbx, %r11
        rorq	$28, %rcx
        movq	%r15, %rax
        addq	%rcx, %r11
        # rnd_1: 0 - 11
        rorq	$23, %rax
        movq	%r11, %rbx
        movq	%r8, %rcx
        addq	40(%rsp), %r10
        xorq	%r9, %rcx
        xorq	%r15, %rax
        andq	%r15, %rcx
        rorq	$4, %rax
        xorq	%r9, %rcx
        xorq	%r15, %rax
        addq	%rcx, %r10
        rorq	$14, %rax
        xorq	%r12, %rbx
        addq	%rax, %r10
        movq	%r11, %rcx
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r11, %rcx
        xorq	%r12, %rdx
        rorq	$6, %rcx
        addq	%r10, %r14
        xorq	%r11, %rcx
        addq	%rdx, %r10
        rorq	$28, %rcx
        movq	%r14, %rax
        addq	%rcx, %r10
        # rnd_all_2: 6-7
        # rnd_0: 0 - 11
        rorq	$23, %rax
        movq	%r10, %rdx
        movq	%r15, %rcx
        addq	48(%rsp), %r9
        xorq	%r8, %rcx
        xorq	%r14, %rax
        andq	%r14, %rcx
        rorq	$4, %rax
        xorq	%r8, %rcx
        xorq	%r14, %rax
        addq	%rcx, %r9
        rorq	$14, %rax
        xorq	%r11, %rdx
        addq	%rax, %r9
        movq	%r10, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        xorq	%r10, %rcx
        xorq	%r11, %rbx
        rorq	$6, %rcx
        addq	%r9, %r13
        xorq	%r10, %rcx
        addq	%rbx, %r9
        rorq	$28, %rcx
        movq	%r13, %rax
        addq	%rcx, %r9
        # rnd_1: 0 - 11
        rorq	$23, %rax
        movq	%r9, %rbx
        movq	%r14, %rcx
        addq	56(%rsp), %r8
        xorq	%r15, %rcx
        xorq	%r13, %rax
        andq	%r13, %rcx
        rorq	$4, %rax
        xorq	%r15, %rcx
        xorq	%r13, %rax
        addq	%rcx, %r8
        rorq	$14, %rax
        xorq	%r10, %rbx
        addq	%rax, %r8
        movq	%r9, %rcx
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r9, %rcx
        xorq	%r10, %rdx
        rorq	$6, %rcx
        addq	%r8, %r12
        xorq	%r9, %rcx
        addq	%rdx, %r8
        rorq	$28, %rcx
        movq	%r12, %rax
        addq	%rcx, %r8
        # rnd_all_2: 8-9
        # rnd_0: 0 - 11
        rorq	$23, %rax
        movq	%r8, %rdx
        movq	%r13, %rcx
        addq	64(%rsp), %r15
        xorq	%r14, %rcx
        xorq	%r12, %rax
        andq	%r12, %rcx
        rorq	$4, %rax
        xorq	%r14, %rcx
        xorq	%r12, %rax
        addq	%rcx, %r15
        rorq	$14, %rax
        xorq	%r9, %rdx
        addq	%rax, %r15
        movq	%r8, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        xorq	%r8, %rcx
        xorq	%r9, %rbx
        rorq	$6, %rcx
        addq	%r15, %r11
        xorq	%r8, %rcx
        addq	%rbx, %r15
        rorq	$28, %rcx
        movq	%r11, %rax
        addq	%rcx, %r15
        # rnd_1: 0 - 11
        rorq	$23, %rax
        movq	%r15, %rbx
        movq	%r12, %rcx
        addq	72(%rsp), %r14
        xorq	%r13, %rcx
        xorq	%r11, %rax
        andq	%r11, %rcx
        rorq	$4, %rax
        xorq	%r13, %rcx
        xorq	%r11, %rax
        addq	%rcx, %r14
        rorq	$14, %rax
        xorq	%r8, %rbx
        addq	%rax, %r14
        movq	%r15, %rcx
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r15, %rcx
        xorq	%r8, %rdx
        rorq	$6, %rcx
        addq	%r14, %r10
        xorq	%r15, %rcx
        addq	%rdx, %r14
        rorq	$28, %rcx
        movq	%r10, %rax
        addq	%rcx, %r14
        # rnd_all_2: 10-11
        # rnd_0: 0 - 11
        rorq	$23, %rax
        movq	%r14, %rdx
        movq	%r11, %rcx
        addq	80(%rsp), %r13
        xorq	%r12, %rcx
        xorq	%r10, %rax
        andq	%r10, %rcx
        rorq	$4, %rax
        xorq	%r12, %rcx
        xorq	%r10, %rax
        addq	%rcx, %r13
        rorq	$14, %rax
        xorq	%r15, %rdx
        addq	%rax, %r13
        movq	%r14, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        xorq	%r14, %rcx
        xorq	%r15, %rbx
        rorq	$6, %rcx
        addq	%r13, %r9
        xorq	%r14, %rcx
        addq	%rbx, %r13
        rorq	$28, %rcx
        movq	%r9, %rax
        addq	%rcx, %r13
        # rnd_1: 0 - 11
        rorq	$23, %rax
        movq	%r13, %rbx
        movq	%r10, %rcx
        addq	88(%rsp), %r12
        xorq	%r11, %rcx
        xorq	%r9, %rax
        andq	%r9, %rcx
        rorq	$4, %rax
        xorq	%r11, %rcx
        xorq	%r9, %rax
        addq	%rcx, %r12
        rorq	$14, %rax
        xorq	%r14, %rbx
        addq	%rax, %r12
        movq	%r13, %rcx
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r13, %rcx
        xorq	%r14, %rdx
        rorq	$6, %rcx
        addq	%r12, %r8
        xorq	%r13, %rcx
        addq	%rdx, %r12
        rorq	$28, %rcx
        movq	%r8, %rax
        addq	%rcx, %r12
        # rnd_all_2: 12-13
        # rnd_0: 0 - 11
        rorq	$23, %rax
        movq	%r12, %rdx
        movq	%r9, %rcx
        addq	96(%rsp), %r11
        xorq	%r10, %rcx
        xorq	%r8, %rax
        andq	%r8, %rcx
        rorq	$4, %rax
        xorq	%r10, %rcx
        xorq	%r8, %rax
        addq	%rcx, %r11
        rorq	$14, %rax
        xorq	%r13, %rdx
        addq	%rax, %r11
        movq	%r12, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        xorq	%r12, %rcx
        xorq	%r13, %rbx
        rorq	$6, %rcx
        addq	%r11, %r15
        xorq	%r12, %rcx
        addq	%rbx, %r11
        rorq	$28, %rcx
        movq	%r15, %rax
        addq	%rcx, %r11
        # rnd_1: 0 - 11
        rorq	$23, %rax
        movq	%r11, %rbx
        movq	%r8, %rcx
        addq	104(%rsp), %r10
        xorq	%r9, %rcx
        xorq	%r15, %rax
        andq	%r15, %rcx
        rorq	$4, %rax
        xorq	%r9, %rcx
        xorq	%r15, %rax
        addq	%rcx, %r10
        rorq	$14, %rax
        xorq	%r12, %rbx
        addq	%rax, %r10
        movq	%r11, %rcx
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r11, %rcx
        xorq	%r12, %rdx
        rorq	$6, %rcx
        addq	%r10, %r14
        xorq	%r11, %rcx
        addq	%rdx, %r10
        rorq	$28, %rcx
        movq	%r14, %rax
        addq	%rcx, %r10
        # rnd_all_2: 14-15
        # rnd_0: 0 - 11
        rorq	$23, %rax
        movq	%r10, %rdx
        movq	%r15, %rcx
        addq	112(%rsp), %r9
        xorq	%r8, %rcx
        xorq	%r14, %rax
        andq	%r14, %rcx
        rorq	$4, %rax
        xorq	%r8, %rcx
        xorq	%r14, %rax
        addq	%rcx, %r9
        rorq	$14, %rax
        xorq	%r11, %rdx
        addq	%rax, %r9
        movq	%r10, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        xorq	%r10, %rcx
        xorq	%r11, %rbx
        rorq	$6, %rcx
        addq	%r9, %r13
        xorq	%r10, %rcx
        addq	%rbx, %r9
        rorq	$28, %rcx
        movq	%r13, %rax
        addq	%rcx, %r9
        # rnd_1: 0 - 11
        rorq	$23, %rax
        movq	%r9, %rbx
        movq	%r14, %rcx
        addq	120(%rsp), %r8
        xorq	%r15, %rcx
        xorq	%r13, %rax
        andq	%r13, %rcx
        rorq	$4, %rax
        xorq	%r15, %rcx
        xorq	%r13, %rax
        addq	%rcx, %r8
        rorq	$14, %rax
        xorq	%r10, %rbx
        addq	%rax, %r8
        movq	%r9, %rcx
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r9, %rcx
        xorq	%r10, %rdx
        rorq	$6, %rcx
        addq	%r8, %r12
        xorq	%r9, %rcx
        addq	%rdx, %r8
        rorq	$28, %rcx
        movq	%r12, %rax
        addq	%rcx, %r8
        addq	(%rdi), %r8
        addq	8(%rdi), %r9
        addq	16(%rdi), %r10
        addq	24(%rdi), %r11
        addq	32(%rdi), %r12
        addq	40(%rdi), %r13
        addq	48(%rdi), %r14
        addq	56(%rdi), %r15
        leaq	L_avx1_sha512_k(%rip), %rdx
        addq	$0x80, %rsi
        subl	$0x80, %ebp
        movq	%r8, (%rdi)
        movq	%r9, 8(%rdi)
        movq	%r10, 16(%rdi)
        movq	%r11, 24(%rdi)
        movq	%r12, 32(%rdi)
        movq	%r13, 40(%rdi)
        movq	%r14, 48(%rdi)
        movq	%r15, 56(%rdi)
        jnz	L_sha512_len_avx1_begin
        xorq	%rax, %rax
        addq	$0x98, %rsp
        popq	%rbp
        popq	%r15
        popq	%r14
        popq	%r13
        popq	%r12
        popq	%rbx
        repz retq
#ifndef __APPLE__
.size	Transform_Sha512_AVX1_Len,.-Transform_Sha512_AVX1_Len
#endif /* __APPLE__ */
#ifndef __APPLE__
.data
#else
.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
.align	32
#else
.p2align	5
#endif /* __APPLE__ */
L_avx1_rorx_sha512_k:
.quad	0x428a2f98d728ae22,0x7137449123ef65cd
.quad	0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc
.quad	0x3956c25bf348b538,0x59f111f1b605d019
.quad	0x923f82a4af194f9b,0xab1c5ed5da6d8118
.quad	0xd807aa98a3030242,0x12835b0145706fbe
.quad	0x243185be4ee4b28c,0x550c7dc3d5ffb4e2
.quad	0x72be5d74f27b896f,0x80deb1fe3b1696b1
.quad	0x9bdc06a725c71235,0xc19bf174cf692694
.quad	0xe49b69c19ef14ad2,0xefbe4786384f25e3
.quad	0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65
.quad	0x2de92c6f592b0275,0x4a7484aa6ea6e483
.quad	0x5cb0a9dcbd41fbd4,0x76f988da831153b5
.quad	0x983e5152ee66dfab,0xa831c66d2db43210
.quad	0xb00327c898fb213f,0xbf597fc7beef0ee4
.quad	0xc6e00bf33da88fc2,0xd5a79147930aa725
.quad	0x06ca6351e003826f,0x142929670a0e6e70
.quad	0x27b70a8546d22ffc,0x2e1b21385c26c926
.quad	0x4d2c6dfc5ac42aed,0x53380d139d95b3df
.quad	0x650a73548baf63de,0x766a0abb3c77b2a8
.quad	0x81c2c92e47edaee6,0x92722c851482353b
.quad	0xa2bfe8a14cf10364,0xa81a664bbc423001
.quad	0xc24b8b70d0f89791,0xc76c51a30654be30
.quad	0xd192e819d6ef5218,0xd69906245565a910
.quad	0xf40e35855771202a,0x106aa07032bbd1b8
.quad	0x19a4c116b8d2d0c8,0x1e376c085141ab53
.quad	0x2748774cdf8eeb99,0x34b0bcb5e19b48a8
.quad	0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb
.quad	0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3
.quad	0x748f82ee5defb2fc,0x78a5636f43172f60
.quad	0x84c87814a1f0ab72,0x8cc702081a6439ec
.quad	0x90befffa23631e28,0xa4506cebde82bde9
.quad	0xbef9a3f7b2c67915,0xc67178f2e372532b
.quad	0xca273eceea26619c,0xd186b8c721c0c207
.quad	0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178
.quad	0x06f067aa72176fba,0x0a637dc5a2c898a6
.quad	0x113f9804bef90dae,0x1b710b35131c471b
.quad	0x28db77f523047d84,0x32caab7b40c72493
.quad	0x3c9ebe0a15c9bebc,0x431d67c49c100d4c
.quad	0x4cc5d4becb3e42b6,0x597f299cfc657e2a
.quad	0x5fcb6fab3ad6faec,0x6c44198c4a475817
#ifndef __APPLE__
.data
#else
.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
.align	16
#else
.p2align	4
#endif /* __APPLE__ */
L_avx1_rorx_sha512_flip_mask:
.quad	0x0001020304050607,0x08090a0b0c0d0e0f
#ifndef __APPLE__
.text
.globl	Transform_Sha512_AVX1_RORX
WC_ASM_ATT_HIDDEN(Transform_Sha512_AVX1_RORX)
.type	Transform_Sha512_AVX1_RORX,@function
.align	16
Transform_Sha512_AVX1_RORX:
#else
.section	__TEXT,__text
.globl	_Transform_Sha512_AVX1_RORX
WC_ASM_ATT_HIDDEN(_Transform_Sha512_AVX1_RORX)
.p2align	4
_Transform_Sha512_AVX1_RORX:
#endif /* __APPLE__ */
        pushq	%rbx
        pushq	%r12
        pushq	%r13
        pushq	%r14
        pushq	%r15
        subq	$0x90, %rsp
        leaq	64(%rdi), %rax
        vmovdqa	L_avx1_rorx_sha512_flip_mask(%rip), %xmm14
        movq	(%rdi), %r8
        movq	8(%rdi), %r9
        movq	16(%rdi), %r10
        movq	24(%rdi), %r11
        movq	32(%rdi), %r12
        movq	40(%rdi), %r13
        movq	48(%rdi), %r14
        movq	56(%rdi), %r15
        vmovdqu	(%rax), %xmm0
        vmovdqu	16(%rax), %xmm1
        vpshufb	%xmm14, %xmm0, %xmm0
        vpshufb	%xmm14, %xmm1, %xmm1
        vmovdqu	32(%rax), %xmm2
        vmovdqu	48(%rax), %xmm3
        vpshufb	%xmm14, %xmm2, %xmm2
        vpshufb	%xmm14, %xmm3, %xmm3
        vmovdqu	64(%rax), %xmm4
        vmovdqu	80(%rax), %xmm5
        vpshufb	%xmm14, %xmm4, %xmm4
        vpshufb	%xmm14, %xmm5, %xmm5
        vmovdqu	96(%rax), %xmm6
        vmovdqu	112(%rax), %xmm7
        vpshufb	%xmm14, %xmm6, %xmm6
        vpshufb	%xmm14, %xmm7, %xmm7
        movl	$4, 128(%rsp)
        leaq	L_avx1_rorx_sha512_k(%rip), %rsi
        movq	%r9, %rbx
        xorq	%rdx, %rdx
        xorq	%r10, %rbx
        vpaddq	(%rsi), %xmm0, %xmm8
        vpaddq	16(%rsi), %xmm1, %xmm9
        vmovdqu	%xmm8, (%rsp)
        vmovdqu	%xmm9, 16(%rsp)
        vpaddq	32(%rsi), %xmm2, %xmm8
        vpaddq	48(%rsi), %xmm3, %xmm9
        vmovdqu	%xmm8, 32(%rsp)
        vmovdqu	%xmm9, 48(%rsp)
        vpaddq	64(%rsi), %xmm4, %xmm8
        vpaddq	80(%rsi), %xmm5, %xmm9
        vmovdqu	%xmm8, 64(%rsp)
        vmovdqu	%xmm9, 80(%rsp)
        vpaddq	96(%rsi), %xmm6, %xmm8
        vpaddq	112(%rsi), %xmm7, %xmm9
        vmovdqu	%xmm8, 96(%rsp)
        vmovdqu	%xmm9, 112(%rsp)
        # Start of 16 rounds
L_transform_sha512_avx1_rorx_start:
        addq	$0x80, %rsi
        # msg_sched: 0-1
        # rnd_0: 0 - 0
        rorxq	$14, %r12, %rax
        rorxq	$18, %r12, %rcx
        addq	%rdx, %r8
        vpalignr	$8, %xmm0, %xmm1, %xmm12
        vpalignr	$8, %xmm4, %xmm5, %xmm13
        # rnd_0: 1 - 1
        addq	(%rsp), %r15
        movq	%r13, %rdx
        xorq	%rax, %rcx
        vpsrlq	$0x01, %xmm12, %xmm8
        vpsllq	$63, %xmm12, %xmm9
        # rnd_0: 2 - 2
        xorq	%r14, %rdx
        rorxq	$41, %r12, %rax
        xorq	%rcx, %rax
        vpsrlq	$8, %xmm12, %xmm10
        vpsllq	$56, %xmm12, %xmm11
        # rnd_0: 3 - 3
        andq	%r12, %rdx
        addq	%rax, %r15
        rorxq	$28, %r8, %rax
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_0: 4 - 4
        rorxq	$34, %r8, %rcx
        xorq	%r14, %rdx
        xorq	%rax, %rcx
        vpsrlq	$7, %xmm12, %xmm11
        vpxor	%xmm10, %xmm8, %xmm8
        # rnd_0: 5 - 5
        rorxq	$39, %r8, %rax
        addq	%rdx, %r15
        xorq	%rcx, %rax
        vpxor	%xmm11, %xmm8, %xmm8
        vpaddq	%xmm0, %xmm13, %xmm0
        # rnd_0: 6 - 7
        movq	%r9, %rdx
        addq	%r15, %r11
        xorq	%r8, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r15
        xorq	%r9, %rbx
        vpaddq	%xmm0, %xmm8, %xmm0
        # rnd_1: 0 - 0
        rorxq	$14, %r11, %rax
        rorxq	$18, %r11, %rcx
        addq	%rbx, %r15
        vpsrlq	$19, %xmm7, %xmm8
        vpsllq	$45, %xmm7, %xmm9
        # rnd_1: 1 - 1
        addq	8(%rsp), %r14
        movq	%r12, %rbx
        xorq	%rax, %rcx
        vpsrlq	$61, %xmm7, %xmm10
        vpsllq	$3, %xmm7, %xmm11
        # rnd_1: 2 - 2
        xorq	%r13, %rbx
        rorxq	$41, %r11, %rax
        xorq	%rcx, %rax
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_1: 3 - 4
        andq	%r11, %rbx
        addq	%rax, %r14
        rorxq	$28, %r15, %rax
        rorxq	$34, %r15, %rcx
        xorq	%r13, %rbx
        xorq	%rax, %rcx
        vpxor	%xmm10, %xmm8, %xmm8
        vpsrlq	$6, %xmm7, %xmm11
        # rnd_1: 5 - 6
        rorxq	$39, %r15, %rax
        addq	%rbx, %r14
        xorq	%rcx, %rax
        movq	%r8, %rbx
        addq	%r14, %r10
        xorq	%r15, %rbx
        vpxor	%xmm11, %xmm8, %xmm8
        # rnd_1: 7 - 7
        andq	%rbx, %rdx
        addq	%rax, %r14
        xorq	%r8, %rdx
        vpaddq	%xmm0, %xmm8, %xmm0
        # msg_sched done: 0-1
        # msg_sched: 2-3
        # rnd_0: 0 - 0
        rorxq	$14, %r10, %rax
        rorxq	$18, %r10, %rcx
        addq	%rdx, %r14
        vpalignr	$8, %xmm1, %xmm2, %xmm12
        vpalignr	$8, %xmm5, %xmm6, %xmm13
        # rnd_0: 1 - 1
        addq	16(%rsp), %r13
        movq	%r11, %rdx
        xorq	%rax, %rcx
        vpsrlq	$0x01, %xmm12, %xmm8
        vpsllq	$63, %xmm12, %xmm9
        # rnd_0: 2 - 2
        xorq	%r12, %rdx
        rorxq	$41, %r10, %rax
        xorq	%rcx, %rax
        vpsrlq	$8, %xmm12, %xmm10
        vpsllq	$56, %xmm12, %xmm11
        # rnd_0: 3 - 3
        andq	%r10, %rdx
        addq	%rax, %r13
        rorxq	$28, %r14, %rax
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_0: 4 - 4
        rorxq	$34, %r14, %rcx
        xorq	%r12, %rdx
        xorq	%rax, %rcx
        vpsrlq	$7, %xmm12, %xmm11
        vpxor	%xmm10, %xmm8, %xmm8
        # rnd_0: 5 - 5
        rorxq	$39, %r14, %rax
        addq	%rdx, %r13
        xorq	%rcx, %rax
        vpxor	%xmm11, %xmm8, %xmm8
        vpaddq	%xmm1, %xmm13, %xmm1
        # rnd_0: 6 - 7
        movq	%r15, %rdx
        addq	%r13, %r9
        xorq	%r14, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r13
        xorq	%r15, %rbx
        vpaddq	%xmm1, %xmm8, %xmm1
        # rnd_1: 0 - 0
        rorxq	$14, %r9, %rax
        rorxq	$18, %r9, %rcx
        addq	%rbx, %r13
        vpsrlq	$19, %xmm0, %xmm8
        vpsllq	$45, %xmm0, %xmm9
        # rnd_1: 1 - 1
        addq	24(%rsp), %r12
        movq	%r10, %rbx
        xorq	%rax, %rcx
        vpsrlq	$61, %xmm0, %xmm10
        vpsllq	$3, %xmm0, %xmm11
        # rnd_1: 2 - 2
        xorq	%r11, %rbx
        rorxq	$41, %r9, %rax
        xorq	%rcx, %rax
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_1: 3 - 4
        andq	%r9, %rbx
        addq	%rax, %r12
        rorxq	$28, %r13, %rax
        rorxq	$34, %r13, %rcx
        xorq	%r11, %rbx
        xorq	%rax, %rcx
        vpxor	%xmm10, %xmm8, %xmm8
        vpsrlq	$6, %xmm0, %xmm11
        # rnd_1: 5 - 6
        rorxq	$39, %r13, %rax
        addq	%rbx, %r12
        xorq	%rcx, %rax
        movq	%r14, %rbx
        addq	%r12, %r8
        xorq	%r13, %rbx
        vpxor	%xmm11, %xmm8, %xmm8
        # rnd_1: 7 - 7
        andq	%rbx, %rdx
        addq	%rax, %r12
        xorq	%r14, %rdx
        vpaddq	%xmm1, %xmm8, %xmm1
        # msg_sched done: 2-3
        # msg_sched: 4-5
        # rnd_0: 0 - 0
        rorxq	$14, %r8, %rax
        rorxq	$18, %r8, %rcx
        addq	%rdx, %r12
        vpalignr	$8, %xmm2, %xmm3, %xmm12
        vpalignr	$8, %xmm6, %xmm7, %xmm13
        # rnd_0: 1 - 1
        addq	32(%rsp), %r11
        movq	%r9, %rdx
        xorq	%rax, %rcx
        vpsrlq	$0x01, %xmm12, %xmm8
        vpsllq	$63, %xmm12, %xmm9
        # rnd_0: 2 - 2
        xorq	%r10, %rdx
        rorxq	$41, %r8, %rax
        xorq	%rcx, %rax
        vpsrlq	$8, %xmm12, %xmm10
        vpsllq	$56, %xmm12, %xmm11
        # rnd_0: 3 - 3
        andq	%r8, %rdx
        addq	%rax, %r11
        rorxq	$28, %r12, %rax
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_0: 4 - 4
        rorxq	$34, %r12, %rcx
        xorq	%r10, %rdx
        xorq	%rax, %rcx
        vpsrlq	$7, %xmm12, %xmm11
        vpxor	%xmm10, %xmm8, %xmm8
        # rnd_0: 5 - 5
        rorxq	$39, %r12, %rax
        addq	%rdx, %r11
        xorq	%rcx, %rax
        vpxor	%xmm11, %xmm8, %xmm8
        vpaddq	%xmm2, %xmm13, %xmm2
        # rnd_0: 6 - 7
        movq	%r13, %rdx
        addq	%r11, %r15
        xorq	%r12, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r11
        xorq	%r13, %rbx
        vpaddq	%xmm2, %xmm8, %xmm2
        # rnd_1: 0 - 0
        rorxq	$14, %r15, %rax
        rorxq	$18, %r15, %rcx
        addq	%rbx, %r11
        vpsrlq	$19, %xmm1, %xmm8
        vpsllq	$45, %xmm1, %xmm9
        # rnd_1: 1 - 1
        addq	40(%rsp), %r10
        movq	%r8, %rbx
        xorq	%rax, %rcx
        vpsrlq	$61, %xmm1, %xmm10
        vpsllq	$3, %xmm1, %xmm11
        # rnd_1: 2 - 2
        xorq	%r9, %rbx
        rorxq	$41, %r15, %rax
        xorq	%rcx, %rax
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_1: 3 - 4
        andq	%r15, %rbx
        addq	%rax, %r10
        rorxq	$28, %r11, %rax
        rorxq	$34, %r11, %rcx
        xorq	%r9, %rbx
        xorq	%rax, %rcx
        vpxor	%xmm10, %xmm8, %xmm8
        vpsrlq	$6, %xmm1, %xmm11
        # rnd_1: 5 - 6
        rorxq	$39, %r11, %rax
        addq	%rbx, %r10
        xorq	%rcx, %rax
        movq	%r12, %rbx
        addq	%r10, %r14
        xorq	%r11, %rbx
        vpxor	%xmm11, %xmm8, %xmm8
        # rnd_1: 7 - 7
        andq	%rbx, %rdx
        addq	%rax, %r10
        xorq	%r12, %rdx
        vpaddq	%xmm2, %xmm8, %xmm2
        # msg_sched done: 4-5
        # msg_sched: 6-7
        # rnd_0: 0 - 0
        rorxq	$14, %r14, %rax
        rorxq	$18, %r14, %rcx
        addq	%rdx, %r10
        vpalignr	$8, %xmm3, %xmm4, %xmm12
        vpalignr	$8, %xmm7, %xmm0, %xmm13
        # rnd_0: 1 - 1
        addq	48(%rsp), %r9
        movq	%r15, %rdx
        xorq	%rax, %rcx
        vpsrlq	$0x01, %xmm12, %xmm8
        vpsllq	$63, %xmm12, %xmm9
        # rnd_0: 2 - 2
        xorq	%r8, %rdx
        rorxq	$41, %r14, %rax
        xorq	%rcx, %rax
        vpsrlq	$8, %xmm12, %xmm10
        vpsllq	$56, %xmm12, %xmm11
        # rnd_0: 3 - 3
        andq	%r14, %rdx
        addq	%rax, %r9
        rorxq	$28, %r10, %rax
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_0: 4 - 4
        rorxq	$34, %r10, %rcx
        xorq	%r8, %rdx
        xorq	%rax, %rcx
        vpsrlq	$7, %xmm12, %xmm11
        vpxor	%xmm10, %xmm8, %xmm8
        # rnd_0: 5 - 5
        rorxq	$39, %r10, %rax
        addq	%rdx, %r9
        xorq	%rcx, %rax
        vpxor	%xmm11, %xmm8, %xmm8
        vpaddq	%xmm3, %xmm13, %xmm3
        # rnd_0: 6 - 7
        movq	%r11, %rdx
        addq	%r9, %r13
        xorq	%r10, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r9
        xorq	%r11, %rbx
        vpaddq	%xmm3, %xmm8, %xmm3
        # rnd_1: 0 - 0
        rorxq	$14, %r13, %rax
        rorxq	$18, %r13, %rcx
        addq	%rbx, %r9
        vpsrlq	$19, %xmm2, %xmm8
        vpsllq	$45, %xmm2, %xmm9
        # rnd_1: 1 - 1
        addq	56(%rsp), %r8
        movq	%r14, %rbx
        xorq	%rax, %rcx
        vpsrlq	$61, %xmm2, %xmm10
        vpsllq	$3, %xmm2, %xmm11
        # rnd_1: 2 - 2
        xorq	%r15, %rbx
        rorxq	$41, %r13, %rax
        xorq	%rcx, %rax
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_1: 3 - 4
        andq	%r13, %rbx
        addq	%rax, %r8
        rorxq	$28, %r9, %rax
        rorxq	$34, %r9, %rcx
        xorq	%r15, %rbx
        xorq	%rax, %rcx
        vpxor	%xmm10, %xmm8, %xmm8
        vpsrlq	$6, %xmm2, %xmm11
        # rnd_1: 5 - 6
        rorxq	$39, %r9, %rax
        addq	%rbx, %r8
        xorq	%rcx, %rax
        movq	%r10, %rbx
        addq	%r8, %r12
        xorq	%r9, %rbx
        vpxor	%xmm11, %xmm8, %xmm8
        # rnd_1: 7 - 7
        andq	%rbx, %rdx
        addq	%rax, %r8
        xorq	%r10, %rdx
        vpaddq	%xmm3, %xmm8, %xmm3
        # msg_sched done: 6-7
        # msg_sched: 8-9
        # rnd_0: 0 - 0
        rorxq	$14, %r12, %rax
        rorxq	$18, %r12, %rcx
        addq	%rdx, %r8
        vpalignr	$8, %xmm4, %xmm5, %xmm12
        vpalignr	$8, %xmm0, %xmm1, %xmm13
        # rnd_0: 1 - 1
        addq	64(%rsp), %r15
        movq	%r13, %rdx
        xorq	%rax, %rcx
        vpsrlq	$0x01, %xmm12, %xmm8
        vpsllq	$63, %xmm12, %xmm9
        # rnd_0: 2 - 2
        xorq	%r14, %rdx
        rorxq	$41, %r12, %rax
        xorq	%rcx, %rax
        vpsrlq	$8, %xmm12, %xmm10
        vpsllq	$56, %xmm12, %xmm11
        # rnd_0: 3 - 3
        andq	%r12, %rdx
        addq	%rax, %r15
        rorxq	$28, %r8, %rax
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_0: 4 - 4
        rorxq	$34, %r8, %rcx
        xorq	%r14, %rdx
        xorq	%rax, %rcx
        vpsrlq	$7, %xmm12, %xmm11
        vpxor	%xmm10, %xmm8, %xmm8
        # rnd_0: 5 - 5
        rorxq	$39, %r8, %rax
        addq	%rdx, %r15
        xorq	%rcx, %rax
        vpxor	%xmm11, %xmm8, %xmm8
        vpaddq	%xmm4, %xmm13, %xmm4
        # rnd_0: 6 - 7
        movq	%r9, %rdx
        addq	%r15, %r11
        xorq	%r8, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r15
        xorq	%r9, %rbx
        vpaddq	%xmm4, %xmm8, %xmm4
        # rnd_1: 0 - 0
        rorxq	$14, %r11, %rax
        rorxq	$18, %r11, %rcx
        addq	%rbx, %r15
        vpsrlq	$19, %xmm3, %xmm8
        vpsllq	$45, %xmm3, %xmm9
        # rnd_1: 1 - 1
        addq	72(%rsp), %r14
        movq	%r12, %rbx
        xorq	%rax, %rcx
        vpsrlq	$61, %xmm3, %xmm10
        vpsllq	$3, %xmm3, %xmm11
        # rnd_1: 2 - 2
        xorq	%r13, %rbx
        rorxq	$41, %r11, %rax
        xorq	%rcx, %rax
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_1: 3 - 4
        andq	%r11, %rbx
        addq	%rax, %r14
        rorxq	$28, %r15, %rax
        rorxq	$34, %r15, %rcx
        xorq	%r13, %rbx
        xorq	%rax, %rcx
        vpxor	%xmm10, %xmm8, %xmm8
        vpsrlq	$6, %xmm3, %xmm11
        # rnd_1: 5 - 6
        rorxq	$39, %r15, %rax
        addq	%rbx, %r14
        xorq	%rcx, %rax
        movq	%r8, %rbx
        addq	%r14, %r10
        xorq	%r15, %rbx
        vpxor	%xmm11, %xmm8, %xmm8
        # rnd_1: 7 - 7
        andq	%rbx, %rdx
        addq	%rax, %r14
        xorq	%r8, %rdx
        vpaddq	%xmm4, %xmm8, %xmm4
        # msg_sched done: 8-9
        # msg_sched: 10-11
        # rnd_0: 0 - 0
        rorxq	$14, %r10, %rax
        rorxq	$18, %r10, %rcx
        addq	%rdx, %r14
        vpalignr	$8, %xmm5, %xmm6, %xmm12
        vpalignr	$8, %xmm1, %xmm2, %xmm13
        # rnd_0: 1 - 1
        addq	80(%rsp), %r13
        movq	%r11, %rdx
        xorq	%rax, %rcx
        vpsrlq	$0x01, %xmm12, %xmm8
        vpsllq	$63, %xmm12, %xmm9
        # rnd_0: 2 - 2
        xorq	%r12, %rdx
        rorxq	$41, %r10, %rax
        xorq	%rcx, %rax
        vpsrlq	$8, %xmm12, %xmm10
        vpsllq	$56, %xmm12, %xmm11
        # rnd_0: 3 - 3
        andq	%r10, %rdx
        addq	%rax, %r13
        rorxq	$28, %r14, %rax
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_0: 4 - 4
        rorxq	$34, %r14, %rcx
        xorq	%r12, %rdx
        xorq	%rax, %rcx
        vpsrlq	$7, %xmm12, %xmm11
        vpxor	%xmm10, %xmm8, %xmm8
        # rnd_0: 5 - 5
        rorxq	$39, %r14, %rax
        addq	%rdx, %r13
        xorq	%rcx, %rax
        vpxor	%xmm11, %xmm8, %xmm8
        vpaddq	%xmm5, %xmm13, %xmm5
        # rnd_0: 6 - 7
        movq	%r15, %rdx
        addq	%r13, %r9
        xorq	%r14, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r13
        xorq	%r15, %rbx
        vpaddq	%xmm5, %xmm8, %xmm5
        # rnd_1: 0 - 0
        rorxq	$14, %r9, %rax
        rorxq	$18, %r9, %rcx
        addq	%rbx, %r13
        vpsrlq	$19, %xmm4, %xmm8
        vpsllq	$45, %xmm4, %xmm9
        # rnd_1: 1 - 1
        addq	88(%rsp), %r12
        movq	%r10, %rbx
        xorq	%rax, %rcx
        vpsrlq	$61, %xmm4, %xmm10
        vpsllq	$3, %xmm4, %xmm11
        # rnd_1: 2 - 2
        xorq	%r11, %rbx
        rorxq	$41, %r9, %rax
        xorq	%rcx, %rax
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_1: 3 - 4
        andq	%r9, %rbx
        addq	%rax, %r12
        rorxq	$28, %r13, %rax
        rorxq	$34, %r13, %rcx
        xorq	%r11, %rbx
        xorq	%rax, %rcx
        vpxor	%xmm10, %xmm8, %xmm8
        vpsrlq	$6, %xmm4, %xmm11
        # rnd_1: 5 - 6
        rorxq	$39, %r13, %rax
        addq	%rbx, %r12
        xorq	%rcx, %rax
        movq	%r14, %rbx
        addq	%r12, %r8
        xorq	%r13, %rbx
        vpxor	%xmm11, %xmm8, %xmm8
        # rnd_1: 7 - 7
        andq	%rbx, %rdx
        addq	%rax, %r12
        xorq	%r14, %rdx
        vpaddq	%xmm5, %xmm8, %xmm5
        # msg_sched done: 10-11
        # msg_sched: 12-13
        # rnd_0: 0 - 0
        rorxq	$14, %r8, %rax
        rorxq	$18, %r8, %rcx
        addq	%rdx, %r12
        vpalignr	$8, %xmm6, %xmm7, %xmm12
        vpalignr	$8, %xmm2, %xmm3, %xmm13
        # rnd_0: 1 - 1
        addq	96(%rsp), %r11
        movq	%r9, %rdx
        xorq	%rax, %rcx
        vpsrlq	$0x01, %xmm12, %xmm8
        vpsllq	$63, %xmm12, %xmm9
        # rnd_0: 2 - 2
        xorq	%r10, %rdx
        rorxq	$41, %r8, %rax
        xorq	%rcx, %rax
        vpsrlq	$8, %xmm12, %xmm10
        vpsllq	$56, %xmm12, %xmm11
        # rnd_0: 3 - 3
        andq	%r8, %rdx
        addq	%rax, %r11
        rorxq	$28, %r12, %rax
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_0: 4 - 4
        rorxq	$34, %r12, %rcx
        xorq	%r10, %rdx
        xorq	%rax, %rcx
        vpsrlq	$7, %xmm12, %xmm11
        vpxor	%xmm10, %xmm8, %xmm8
        # rnd_0: 5 - 5
        rorxq	$39, %r12, %rax
        addq	%rdx, %r11
        xorq	%rcx, %rax
        vpxor	%xmm11, %xmm8, %xmm8
        vpaddq	%xmm6, %xmm13, %xmm6
        # rnd_0: 6 - 7
        movq	%r13, %rdx
        addq	%r11, %r15
        xorq	%r12, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r11
        xorq	%r13, %rbx
        vpaddq	%xmm6, %xmm8, %xmm6
        # rnd_1: 0 - 0
        rorxq	$14, %r15, %rax
        rorxq	$18, %r15, %rcx
        addq	%rbx, %r11
        vpsrlq	$19, %xmm5, %xmm8
        vpsllq	$45, %xmm5, %xmm9
        # rnd_1: 1 - 1
        addq	104(%rsp), %r10
        movq	%r8, %rbx
        xorq	%rax, %rcx
        vpsrlq	$61, %xmm5, %xmm10
        vpsllq	$3, %xmm5, %xmm11
        # rnd_1: 2 - 2
        xorq	%r9, %rbx
        rorxq	$41, %r15, %rax
        xorq	%rcx, %rax
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_1: 3 - 4
        andq	%r15, %rbx
        addq	%rax, %r10
        rorxq	$28, %r11, %rax
        rorxq	$34, %r11, %rcx
        xorq	%r9, %rbx
        xorq	%rax, %rcx
        vpxor	%xmm10, %xmm8, %xmm8
        vpsrlq	$6, %xmm5, %xmm11
        # rnd_1: 5 - 6
        rorxq	$39, %r11, %rax
        addq	%rbx, %r10
        xorq	%rcx, %rax
        movq	%r12, %rbx
        addq	%r10, %r14
        xorq	%r11, %rbx
        vpxor	%xmm11, %xmm8, %xmm8
        # rnd_1: 7 - 7
        andq	%rbx, %rdx
        addq	%rax, %r10
        xorq	%r12, %rdx
        vpaddq	%xmm6, %xmm8, %xmm6
        # msg_sched done: 12-13
        # msg_sched: 14-15
        # rnd_0: 0 - 0
        rorxq	$14, %r14, %rax
        rorxq	$18, %r14, %rcx
        addq	%rdx, %r10
        vpalignr	$8, %xmm7, %xmm0, %xmm12
        vpalignr	$8, %xmm3, %xmm4, %xmm13
        # rnd_0: 1 - 1
        addq	112(%rsp), %r9
        movq	%r15, %rdx
        xorq	%rax, %rcx
        vpsrlq	$0x01, %xmm12, %xmm8
        vpsllq	$63, %xmm12, %xmm9
        # rnd_0: 2 - 2
        xorq	%r8, %rdx
        rorxq	$41, %r14, %rax
        xorq	%rcx, %rax
        vpsrlq	$8, %xmm12, %xmm10
        vpsllq	$56, %xmm12, %xmm11
        # rnd_0: 3 - 3
        andq	%r14, %rdx
        addq	%rax, %r9
        rorxq	$28, %r10, %rax
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_0: 4 - 4
        rorxq	$34, %r10, %rcx
        xorq	%r8, %rdx
        xorq	%rax, %rcx
        vpsrlq	$7, %xmm12, %xmm11
        vpxor	%xmm10, %xmm8, %xmm8
        # rnd_0: 5 - 5
        rorxq	$39, %r10, %rax
        addq	%rdx, %r9
        xorq	%rcx, %rax
        vpxor	%xmm11, %xmm8, %xmm8
        vpaddq	%xmm7, %xmm13, %xmm7
        # rnd_0: 6 - 7
        movq	%r11, %rdx
        addq	%r9, %r13
        xorq	%r10, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r9
        xorq	%r11, %rbx
        vpaddq	%xmm7, %xmm8, %xmm7
        # rnd_1: 0 - 0
        rorxq	$14, %r13, %rax
        rorxq	$18, %r13, %rcx
        addq	%rbx, %r9
        vpsrlq	$19, %xmm6, %xmm8
        vpsllq	$45, %xmm6, %xmm9
        # rnd_1: 1 - 1
        addq	120(%rsp), %r8
        movq	%r14, %rbx
        xorq	%rax, %rcx
        vpsrlq	$61, %xmm6, %xmm10
        vpsllq	$3, %xmm6, %xmm11
        # rnd_1: 2 - 2
        xorq	%r15, %rbx
        rorxq	$41, %r13, %rax
        xorq	%rcx, %rax
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_1: 3 - 4
        andq	%r13, %rbx
        addq	%rax, %r8
        rorxq	$28, %r9, %rax
        rorxq	$34, %r9, %rcx
        xorq	%r15, %rbx
        xorq	%rax, %rcx
        vpxor	%xmm10, %xmm8, %xmm8
        vpsrlq	$6, %xmm6, %xmm11
        # rnd_1: 5 - 6
        rorxq	$39, %r9, %rax
        addq	%rbx, %r8
        xorq	%rcx, %rax
        movq	%r10, %rbx
        addq	%r8, %r12
        xorq	%r9, %rbx
        vpxor	%xmm11, %xmm8, %xmm8
        # rnd_1: 7 - 7
        andq	%rbx, %rdx
        addq	%rax, %r8
        xorq	%r10, %rdx
        vpaddq	%xmm7, %xmm8, %xmm7
        # msg_sched done: 14-15
        vpaddq	(%rsi), %xmm0, %xmm8
        vpaddq	16(%rsi), %xmm1, %xmm9
        vmovdqu	%xmm8, (%rsp)
        vmovdqu	%xmm9, 16(%rsp)
        vpaddq	32(%rsi), %xmm2, %xmm8
        vpaddq	48(%rsi), %xmm3, %xmm9
        vmovdqu	%xmm8, 32(%rsp)
        vmovdqu	%xmm9, 48(%rsp)
        vpaddq	64(%rsi), %xmm4, %xmm8
        vpaddq	80(%rsi), %xmm5, %xmm9
        vmovdqu	%xmm8, 64(%rsp)
        vmovdqu	%xmm9, 80(%rsp)
        vpaddq	96(%rsi), %xmm6, %xmm8
        vpaddq	112(%rsi), %xmm7, %xmm9
        vmovdqu	%xmm8, 96(%rsp)
        vmovdqu	%xmm9, 112(%rsp)
        subl	$0x01, 128(%rsp)
        jne	L_transform_sha512_avx1_rorx_start
        # rnd_all_2: 0-1
        # rnd_0: 0 - 7
        rorxq	$14, %r12, %rax
        rorxq	$18, %r12, %rcx
        addq	%rdx, %r8
        addq	(%rsp), %r15
        movq	%r13, %rdx
        xorq	%rax, %rcx
        xorq	%r14, %rdx
        rorxq	$41, %r12, %rax
        xorq	%rcx, %rax
        andq	%r12, %rdx
        addq	%rax, %r15
        rorxq	$28, %r8, %rax
        rorxq	$34, %r8, %rcx
        xorq	%r14, %rdx
        xorq	%rax, %rcx
        rorxq	$39, %r8, %rax
        addq	%rdx, %r15
        xorq	%rcx, %rax
        movq	%r9, %rdx
        addq	%r15, %r11
        xorq	%r8, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r15
        xorq	%r9, %rbx
        # rnd_1: 0 - 7
        rorxq	$14, %r11, %rax
        rorxq	$18, %r11, %rcx
        addq	%rbx, %r15
        addq	8(%rsp), %r14
        movq	%r12, %rbx
        xorq	%rax, %rcx
        xorq	%r13, %rbx
        rorxq	$41, %r11, %rax
        xorq	%rcx, %rax
        andq	%r11, %rbx
        addq	%rax, %r14
        rorxq	$28, %r15, %rax
        rorxq	$34, %r15, %rcx
        xorq	%r13, %rbx
        xorq	%rax, %rcx
        rorxq	$39, %r15, %rax
        addq	%rbx, %r14
        xorq	%rcx, %rax
        movq	%r8, %rbx
        addq	%r14, %r10
        xorq	%r15, %rbx
        andq	%rbx, %rdx
        addq	%rax, %r14
        xorq	%r8, %rdx
        # rnd_all_2: 2-3
        # rnd_0: 0 - 7
        rorxq	$14, %r10, %rax
        rorxq	$18, %r10, %rcx
        addq	%rdx, %r14
        addq	16(%rsp), %r13
        movq	%r11, %rdx
        xorq	%rax, %rcx
        xorq	%r12, %rdx
        rorxq	$41, %r10, %rax
        xorq	%rcx, %rax
        andq	%r10, %rdx
        addq	%rax, %r13
        rorxq	$28, %r14, %rax
        rorxq	$34, %r14, %rcx
        xorq	%r12, %rdx
        xorq	%rax, %rcx
        rorxq	$39, %r14, %rax
        addq	%rdx, %r13
        xorq	%rcx, %rax
        movq	%r15, %rdx
        addq	%r13, %r9
        xorq	%r14, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r13
        xorq	%r15, %rbx
        # rnd_1: 0 - 7
        rorxq	$14, %r9, %rax
        rorxq	$18, %r9, %rcx
        addq	%rbx, %r13
        addq	24(%rsp), %r12
        movq	%r10, %rbx
        xorq	%rax, %rcx
        xorq	%r11, %rbx
        rorxq	$41, %r9, %rax
        xorq	%rcx, %rax
        andq	%r9, %rbx
        addq	%rax, %r12
        rorxq	$28, %r13, %rax
        rorxq	$34, %r13, %rcx
        xorq	%r11, %rbx
        xorq	%rax, %rcx
        rorxq	$39, %r13, %rax
        addq	%rbx, %r12
        xorq	%rcx, %rax
        movq	%r14, %rbx
        addq	%r12, %r8
        xorq	%r13, %rbx
        andq	%rbx, %rdx
        addq	%rax, %r12
        xorq	%r14, %rdx
        # rnd_all_2: 4-5
        # rnd_0: 0 - 7
        rorxq	$14, %r8, %rax
        rorxq	$18, %r8, %rcx
        addq	%rdx, %r12
        addq	32(%rsp), %r11
        movq	%r9, %rdx
        xorq	%rax, %rcx
        xorq	%r10, %rdx
        rorxq	$41, %r8, %rax
        xorq	%rcx, %rax
        andq	%r8, %rdx
        addq	%rax, %r11
        rorxq	$28, %r12, %rax
        rorxq	$34, %r12, %rcx
        xorq	%r10, %rdx
        xorq	%rax, %rcx
        rorxq	$39, %r12, %rax
        addq	%rdx, %r11
        xorq	%rcx, %rax
        movq	%r13, %rdx
        addq	%r11, %r15
        xorq	%r12, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r11
        xorq	%r13, %rbx
        # rnd_1: 0 - 7
        rorxq	$14, %r15, %rax
        rorxq	$18, %r15, %rcx
        addq	%rbx, %r11
        addq	40(%rsp), %r10
        movq	%r8, %rbx
        xorq	%rax, %rcx
        xorq	%r9, %rbx
        rorxq	$41, %r15, %rax
        xorq	%rcx, %rax
        andq	%r15, %rbx
        addq	%rax, %r10
        rorxq	$28, %r11, %rax
        rorxq	$34, %r11, %rcx
        xorq	%r9, %rbx
        xorq	%rax, %rcx
        rorxq	$39, %r11, %rax
        addq	%rbx, %r10
        xorq	%rcx, %rax
        movq	%r12, %rbx
        addq	%r10, %r14
        xorq	%r11, %rbx
        andq	%rbx, %rdx
        addq	%rax, %r10
        xorq	%r12, %rdx
        # rnd_all_2: 6-7
        # rnd_0: 0 - 7
        rorxq	$14, %r14, %rax
        rorxq	$18, %r14, %rcx
        addq	%rdx, %r10
        addq	48(%rsp), %r9
        movq	%r15, %rdx
        xorq	%rax, %rcx
        xorq	%r8, %rdx
        rorxq	$41, %r14, %rax
        xorq	%rcx, %rax
        andq	%r14, %rdx
        addq	%rax, %r9
        rorxq	$28, %r10, %rax
        rorxq	$34, %r10, %rcx
        xorq	%r8, %rdx
        xorq	%rax, %rcx
        rorxq	$39, %r10, %rax
        addq	%rdx, %r9
        xorq	%rcx, %rax
        movq	%r11, %rdx
        addq	%r9, %r13
        xorq	%r10, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r9
        xorq	%r11, %rbx
        # rnd_1: 0 - 7
        rorxq	$14, %r13, %rax
        rorxq	$18, %r13, %rcx
        addq	%rbx, %r9
        addq	56(%rsp), %r8
        movq	%r14, %rbx
        xorq	%rax, %rcx
        xorq	%r15, %rbx
        rorxq	$41, %r13, %rax
        xorq	%rcx, %rax
        andq	%r13, %rbx
        addq	%rax, %r8
        rorxq	$28, %r9, %rax
        rorxq	$34, %r9, %rcx
        xorq	%r15, %rbx
        xorq	%rax, %rcx
        rorxq	$39, %r9, %rax
        addq	%rbx, %r8
        xorq	%rcx, %rax
        movq	%r10, %rbx
        addq	%r8, %r12
        xorq	%r9, %rbx
        andq	%rbx, %rdx
        addq	%rax, %r8
        xorq	%r10, %rdx
        # rnd_all_2: 8-9
        # rnd_0: 0 - 7
        rorxq	$14, %r12, %rax
        rorxq	$18, %r12, %rcx
        addq	%rdx, %r8
        addq	64(%rsp), %r15
        movq	%r13, %rdx
        xorq	%rax, %rcx
        xorq	%r14, %rdx
        rorxq	$41, %r12, %rax
        xorq	%rcx, %rax
        andq	%r12, %rdx
        addq	%rax, %r15
        rorxq	$28, %r8, %rax
        rorxq	$34, %r8, %rcx
        xorq	%r14, %rdx
        xorq	%rax, %rcx
        rorxq	$39, %r8, %rax
        addq	%rdx, %r15
        xorq	%rcx, %rax
        movq	%r9, %rdx
        addq	%r15, %r11
        xorq	%r8, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r15
        xorq	%r9, %rbx
        # rnd_1: 0 - 7
        rorxq	$14, %r11, %rax
        rorxq	$18, %r11, %rcx
        addq	%rbx, %r15
        addq	72(%rsp), %r14
        movq	%r12, %rbx
        xorq	%rax, %rcx
        xorq	%r13, %rbx
        rorxq	$41, %r11, %rax
        xorq	%rcx, %rax
        andq	%r11, %rbx
        addq	%rax, %r14
        rorxq	$28, %r15, %rax
        rorxq	$34, %r15, %rcx
        xorq	%r13, %rbx
        xorq	%rax, %rcx
        rorxq	$39, %r15, %rax
        addq	%rbx, %r14
        xorq	%rcx, %rax
        movq	%r8, %rbx
        addq	%r14, %r10
        xorq	%r15, %rbx
        andq	%rbx, %rdx
        addq	%rax, %r14
        xorq	%r8, %rdx
        # rnd_all_2: 10-11
        # rnd_0: 0 - 7
        rorxq	$14, %r10, %rax
        rorxq	$18, %r10, %rcx
        addq	%rdx, %r14
        addq	80(%rsp), %r13
        movq	%r11, %rdx
        xorq	%rax, %rcx
        xorq	%r12, %rdx
        rorxq	$41, %r10, %rax
        xorq	%rcx, %rax
        andq	%r10, %rdx
        addq	%rax, %r13
        rorxq	$28, %r14, %rax
        rorxq	$34, %r14, %rcx
        xorq	%r12, %rdx
        xorq	%rax, %rcx
        rorxq	$39, %r14, %rax
        addq	%rdx, %r13
        xorq	%rcx, %rax
        movq	%r15, %rdx
        addq	%r13, %r9
        xorq	%r14, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r13
        xorq	%r15, %rbx
        # rnd_1: 0 - 7
        rorxq	$14, %r9, %rax
        rorxq	$18, %r9, %rcx
        addq	%rbx, %r13
        addq	88(%rsp), %r12
        movq	%r10, %rbx
        xorq	%rax, %rcx
        xorq	%r11, %rbx
        rorxq	$41, %r9, %rax
        xorq	%rcx, %rax
        andq	%r9, %rbx
        addq	%rax, %r12
        rorxq	$28, %r13, %rax
        rorxq	$34, %r13, %rcx
        xorq	%r11, %rbx
        xorq	%rax, %rcx
        rorxq	$39, %r13, %rax
        addq	%rbx, %r12
        xorq	%rcx, %rax
        movq	%r14, %rbx
        addq	%r12, %r8
        xorq	%r13, %rbx
        andq	%rbx, %rdx
        addq	%rax, %r12
        xorq	%r14, %rdx
        # rnd_all_2: 12-13
        # rnd_0: 0 - 7
        rorxq	$14, %r8, %rax
        rorxq	$18, %r8, %rcx
        addq	%rdx, %r12
        addq	96(%rsp), %r11
        movq	%r9, %rdx
        xorq	%rax, %rcx
        xorq	%r10, %rdx
        rorxq	$41, %r8, %rax
        xorq	%rcx, %rax
        andq	%r8, %rdx
        addq	%rax, %r11
        rorxq	$28, %r12, %rax
        rorxq	$34, %r12, %rcx
        xorq	%r10, %rdx
        xorq	%rax, %rcx
        rorxq	$39, %r12, %rax
        addq	%rdx, %r11
        xorq	%rcx, %rax
        movq	%r13, %rdx
        addq	%r11, %r15
        xorq	%r12, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r11
        xorq	%r13, %rbx
        # rnd_1: 0 - 7
        rorxq	$14, %r15, %rax
        rorxq	$18, %r15, %rcx
        addq	%rbx, %r11
        addq	104(%rsp), %r10
        movq	%r8, %rbx
        xorq	%rax, %rcx
        xorq	%r9, %rbx
        rorxq	$41, %r15, %rax
        xorq	%rcx, %rax
        andq	%r15, %rbx
        addq	%rax, %r10
        rorxq	$28, %r11, %rax
        rorxq	$34, %r11, %rcx
        xorq	%r9, %rbx
        xorq	%rax, %rcx
        rorxq	$39, %r11, %rax
        addq	%rbx, %r10
        xorq	%rcx, %rax
        movq	%r12, %rbx
        addq	%r10, %r14
        xorq	%r11, %rbx
        andq	%rbx, %rdx
        addq	%rax, %r10
        xorq	%r12, %rdx
        # rnd_all_2: 14-15
        # rnd_0: 0 - 7
        rorxq	$14, %r14, %rax
        rorxq	$18, %r14, %rcx
        addq	%rdx, %r10
        addq	112(%rsp), %r9
        movq	%r15, %rdx
        xorq	%rax, %rcx
        xorq	%r8, %rdx
        rorxq	$41, %r14, %rax
        xorq	%rcx, %rax
        andq	%r14, %rdx
        addq	%rax, %r9
        rorxq	$28, %r10, %rax
        rorxq	$34, %r10, %rcx
        xorq	%r8, %rdx
        xorq	%rax, %rcx
        rorxq	$39, %r10, %rax
        addq	%rdx, %r9
        xorq	%rcx, %rax
        movq	%r11, %rdx
        addq	%r9, %r13
        xorq	%r10, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r9
        xorq	%r11, %rbx
        # rnd_1: 0 - 7
        rorxq	$14, %r13, %rax
        rorxq	$18, %r13, %rcx
        addq	%rbx, %r9
        addq	120(%rsp), %r8
        movq	%r14, %rbx
        xorq	%rax, %rcx
        xorq	%r15, %rbx
        rorxq	$41, %r13, %rax
        xorq	%rcx, %rax
        andq	%r13, %rbx
        addq	%rax, %r8
        rorxq	$28, %r9, %rax
        rorxq	$34, %r9, %rcx
        xorq	%r15, %rbx
        xorq	%rax, %rcx
        rorxq	$39, %r9, %rax
        addq	%rbx, %r8
        xorq	%rcx, %rax
        movq	%r10, %rbx
        addq	%r8, %r12
        xorq	%r9, %rbx
        andq	%rbx, %rdx
        addq	%rax, %r8
        xorq	%r10, %rdx
        addq	%rdx, %r8
        addq	%r8, (%rdi)
        addq	%r9, 8(%rdi)
        addq	%r10, 16(%rdi)
        addq	%r11, 24(%rdi)
        addq	%r12, 32(%rdi)
        addq	%r13, 40(%rdi)
        addq	%r14, 48(%rdi)
        addq	%r15, 56(%rdi)
        xorq	%rax, %rax
        addq	$0x90, %rsp
        popq	%r15
        popq	%r14
        popq	%r13
        popq	%r12
        popq	%rbx
        repz retq
#ifndef __APPLE__
.size	Transform_Sha512_AVX1_RORX,.-Transform_Sha512_AVX1_RORX
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	Transform_Sha512_AVX1_RORX_Len
WC_ASM_ATT_HIDDEN(Transform_Sha512_AVX1_RORX_Len)
.type	Transform_Sha512_AVX1_RORX_Len,@function
.align	16
Transform_Sha512_AVX1_RORX_Len:
#else
.section	__TEXT,__text
.globl	_Transform_Sha512_AVX1_RORX_Len
WC_ASM_ATT_HIDDEN(_Transform_Sha512_AVX1_RORX_Len)
.p2align	4
_Transform_Sha512_AVX1_RORX_Len:
#endif /* __APPLE__ */
        pushq	%rbx
        pushq	%r12
        pushq	%r13
        pushq	%r14
        pushq	%r15
        pushq	%rbp
        movq	%rsi, %rbp
        subq	$0x98, %rsp
        movq	224(%rdi), %rsi
        leaq	L_avx1_rorx_sha512_k(%rip), %rcx
        vmovdqa	L_avx1_rorx_sha512_flip_mask(%rip), %xmm14
        movq	(%rdi), %r8
        movq	8(%rdi), %r9
        movq	16(%rdi), %r10
        movq	24(%rdi), %r11
        movq	32(%rdi), %r12
        movq	40(%rdi), %r13
        movq	48(%rdi), %r14
        movq	56(%rdi), %r15
        # Start of loop processing a block
L_sha512_len_avx1_rorx_begin:
        vmovdqu	(%rsi), %xmm0
        vmovdqu	16(%rsi), %xmm1
        vpshufb	%xmm14, %xmm0, %xmm0
        vpshufb	%xmm14, %xmm1, %xmm1
        vmovdqu	32(%rsi), %xmm2
        vmovdqu	48(%rsi), %xmm3
        vpshufb	%xmm14, %xmm2, %xmm2
        vpshufb	%xmm14, %xmm3, %xmm3
        vmovdqu	64(%rsi), %xmm4
        vmovdqu	80(%rsi), %xmm5
        vpshufb	%xmm14, %xmm4, %xmm4
        vpshufb	%xmm14, %xmm5, %xmm5
        vmovdqu	96(%rsi), %xmm6
        vmovdqu	112(%rsi), %xmm7
        vpshufb	%xmm14, %xmm6, %xmm6
        vpshufb	%xmm14, %xmm7, %xmm7
        movl	$4, 128(%rsp)
        movq	%r9, %rbx
        xorq	%rdx, %rdx
        xorq	%r10, %rbx
        vpaddq	(%rcx), %xmm0, %xmm8
        vpaddq	16(%rcx), %xmm1, %xmm9
        vmovdqu	%xmm8, (%rsp)
        vmovdqu	%xmm9, 16(%rsp)
        vpaddq	32(%rcx), %xmm2, %xmm8
        vpaddq	48(%rcx), %xmm3, %xmm9
        vmovdqu	%xmm8, 32(%rsp)
        vmovdqu	%xmm9, 48(%rsp)
        vpaddq	64(%rcx), %xmm4, %xmm8
        vpaddq	80(%rcx), %xmm5, %xmm9
        vmovdqu	%xmm8, 64(%rsp)
        vmovdqu	%xmm9, 80(%rsp)
        vpaddq	96(%rcx), %xmm6, %xmm8
        vpaddq	112(%rcx), %xmm7, %xmm9
        vmovdqu	%xmm8, 96(%rsp)
        vmovdqu	%xmm9, 112(%rsp)
        # Start of 16 rounds
L_sha512_len_avx1_rorx_start:
        addq	$0x80, %rcx
        movq	%rcx, 136(%rsp)
        # msg_sched: 0-1
        # rnd_0: 0 - 0
        rorxq	$14, %r12, %rax
        rorxq	$18, %r12, %rcx
        addq	%rdx, %r8
        vpalignr	$8, %xmm0, %xmm1, %xmm12
        vpalignr	$8, %xmm4, %xmm5, %xmm13
        # rnd_0: 1 - 1
        addq	(%rsp), %r15
        movq	%r13, %rdx
        xorq	%rax, %rcx
        vpsrlq	$0x01, %xmm12, %xmm8
        vpsllq	$63, %xmm12, %xmm9
        # rnd_0: 2 - 2
        xorq	%r14, %rdx
        rorxq	$41, %r12, %rax
        xorq	%rcx, %rax
        vpsrlq	$8, %xmm12, %xmm10
        vpsllq	$56, %xmm12, %xmm11
        # rnd_0: 3 - 3
        andq	%r12, %rdx
        addq	%rax, %r15
        rorxq	$28, %r8, %rax
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_0: 4 - 4
        rorxq	$34, %r8, %rcx
        xorq	%r14, %rdx
        xorq	%rax, %rcx
        vpsrlq	$7, %xmm12, %xmm11
        vpxor	%xmm10, %xmm8, %xmm8
        # rnd_0: 5 - 5
        rorxq	$39, %r8, %rax
        addq	%rdx, %r15
        xorq	%rcx, %rax
        vpxor	%xmm11, %xmm8, %xmm8
        vpaddq	%xmm0, %xmm13, %xmm0
        # rnd_0: 6 - 7
        movq	%r9, %rdx
        addq	%r15, %r11
        xorq	%r8, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r15
        xorq	%r9, %rbx
        vpaddq	%xmm0, %xmm8, %xmm0
        # rnd_1: 0 - 0
        rorxq	$14, %r11, %rax
        rorxq	$18, %r11, %rcx
        addq	%rbx, %r15
        vpsrlq	$19, %xmm7, %xmm8
        vpsllq	$45, %xmm7, %xmm9
        # rnd_1: 1 - 1
        addq	8(%rsp), %r14
        movq	%r12, %rbx
        xorq	%rax, %rcx
        vpsrlq	$61, %xmm7, %xmm10
        vpsllq	$3, %xmm7, %xmm11
        # rnd_1: 2 - 2
        xorq	%r13, %rbx
        rorxq	$41, %r11, %rax
        xorq	%rcx, %rax
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_1: 3 - 4
        andq	%r11, %rbx
        addq	%rax, %r14
        rorxq	$28, %r15, %rax
        rorxq	$34, %r15, %rcx
        xorq	%r13, %rbx
        xorq	%rax, %rcx
        vpxor	%xmm10, %xmm8, %xmm8
        vpsrlq	$6, %xmm7, %xmm11
        # rnd_1: 5 - 6
        rorxq	$39, %r15, %rax
        addq	%rbx, %r14
        xorq	%rcx, %rax
        movq	%r8, %rbx
        addq	%r14, %r10
        xorq	%r15, %rbx
        vpxor	%xmm11, %xmm8, %xmm8
        # rnd_1: 7 - 7
        andq	%rbx, %rdx
        addq	%rax, %r14
        xorq	%r8, %rdx
        vpaddq	%xmm0, %xmm8, %xmm0
        # msg_sched done: 0-1
        # msg_sched: 2-3
        # rnd_0: 0 - 0
        rorxq	$14, %r10, %rax
        rorxq	$18, %r10, %rcx
        addq	%rdx, %r14
        vpalignr	$8, %xmm1, %xmm2, %xmm12
        vpalignr	$8, %xmm5, %xmm6, %xmm13
        # rnd_0: 1 - 1
        addq	16(%rsp), %r13
        movq	%r11, %rdx
        xorq	%rax, %rcx
        vpsrlq	$0x01, %xmm12, %xmm8
        vpsllq	$63, %xmm12, %xmm9
        # rnd_0: 2 - 2
        xorq	%r12, %rdx
        rorxq	$41, %r10, %rax
        xorq	%rcx, %rax
        vpsrlq	$8, %xmm12, %xmm10
        vpsllq	$56, %xmm12, %xmm11
        # rnd_0: 3 - 3
        andq	%r10, %rdx
        addq	%rax, %r13
        rorxq	$28, %r14, %rax
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_0: 4 - 4
        rorxq	$34, %r14, %rcx
        xorq	%r12, %rdx
        xorq	%rax, %rcx
        vpsrlq	$7, %xmm12, %xmm11
        vpxor	%xmm10, %xmm8, %xmm8
        # rnd_0: 5 - 5
        rorxq	$39, %r14, %rax
        addq	%rdx, %r13
        xorq	%rcx, %rax
        vpxor	%xmm11, %xmm8, %xmm8
        vpaddq	%xmm1, %xmm13, %xmm1
        # rnd_0: 6 - 7
        movq	%r15, %rdx
        addq	%r13, %r9
        xorq	%r14, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r13
        xorq	%r15, %rbx
        vpaddq	%xmm1, %xmm8, %xmm1
        # rnd_1: 0 - 0
        rorxq	$14, %r9, %rax
        rorxq	$18, %r9, %rcx
        addq	%rbx, %r13
        vpsrlq	$19, %xmm0, %xmm8
        vpsllq	$45, %xmm0, %xmm9
        # rnd_1: 1 - 1
        addq	24(%rsp), %r12
        movq	%r10, %rbx
        xorq	%rax, %rcx
        vpsrlq	$61, %xmm0, %xmm10
        vpsllq	$3, %xmm0, %xmm11
        # rnd_1: 2 - 2
        xorq	%r11, %rbx
        rorxq	$41, %r9, %rax
        xorq	%rcx, %rax
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_1: 3 - 4
        andq	%r9, %rbx
        addq	%rax, %r12
        rorxq	$28, %r13, %rax
        rorxq	$34, %r13, %rcx
        xorq	%r11, %rbx
        xorq	%rax, %rcx
        vpxor	%xmm10, %xmm8, %xmm8
        vpsrlq	$6, %xmm0, %xmm11
        # rnd_1: 5 - 6
        rorxq	$39, %r13, %rax
        addq	%rbx, %r12
        xorq	%rcx, %rax
        movq	%r14, %rbx
        addq	%r12, %r8
        xorq	%r13, %rbx
        vpxor	%xmm11, %xmm8, %xmm8
        # rnd_1: 7 - 7
        andq	%rbx, %rdx
        addq	%rax, %r12
        xorq	%r14, %rdx
        vpaddq	%xmm1, %xmm8, %xmm1
        # msg_sched done: 2-3
        # msg_sched: 4-5
        # rnd_0: 0 - 0
        rorxq	$14, %r8, %rax
        rorxq	$18, %r8, %rcx
        addq	%rdx, %r12
        vpalignr	$8, %xmm2, %xmm3, %xmm12
        vpalignr	$8, %xmm6, %xmm7, %xmm13
        # rnd_0: 1 - 1
        addq	32(%rsp), %r11
        movq	%r9, %rdx
        xorq	%rax, %rcx
        vpsrlq	$0x01, %xmm12, %xmm8
        vpsllq	$63, %xmm12, %xmm9
        # rnd_0: 2 - 2
        xorq	%r10, %rdx
        rorxq	$41, %r8, %rax
        xorq	%rcx, %rax
        vpsrlq	$8, %xmm12, %xmm10
        vpsllq	$56, %xmm12, %xmm11
        # rnd_0: 3 - 3
        andq	%r8, %rdx
        addq	%rax, %r11
        rorxq	$28, %r12, %rax
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_0: 4 - 4
        rorxq	$34, %r12, %rcx
        xorq	%r10, %rdx
        xorq	%rax, %rcx
        vpsrlq	$7, %xmm12, %xmm11
        vpxor	%xmm10, %xmm8, %xmm8
        # rnd_0: 5 - 5
        rorxq	$39, %r12, %rax
        addq	%rdx, %r11
        xorq	%rcx, %rax
        vpxor	%xmm11, %xmm8, %xmm8
        vpaddq	%xmm2, %xmm13, %xmm2
        # rnd_0: 6 - 7
        movq	%r13, %rdx
        addq	%r11, %r15
        xorq	%r12, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r11
        xorq	%r13, %rbx
        vpaddq	%xmm2, %xmm8, %xmm2
        # rnd_1: 0 - 0
        rorxq	$14, %r15, %rax
        rorxq	$18, %r15, %rcx
        addq	%rbx, %r11
        vpsrlq	$19, %xmm1, %xmm8
        vpsllq	$45, %xmm1, %xmm9
        # rnd_1: 1 - 1
        addq	40(%rsp), %r10
        movq	%r8, %rbx
        xorq	%rax, %rcx
        vpsrlq	$61, %xmm1, %xmm10
        vpsllq	$3, %xmm1, %xmm11
        # rnd_1: 2 - 2
        xorq	%r9, %rbx
        rorxq	$41, %r15, %rax
        xorq	%rcx, %rax
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_1: 3 - 4
        andq	%r15, %rbx
        addq	%rax, %r10
        rorxq	$28, %r11, %rax
        rorxq	$34, %r11, %rcx
        xorq	%r9, %rbx
        xorq	%rax, %rcx
        vpxor	%xmm10, %xmm8, %xmm8
        vpsrlq	$6, %xmm1, %xmm11
        # rnd_1: 5 - 6
        rorxq	$39, %r11, %rax
        addq	%rbx, %r10
        xorq	%rcx, %rax
        movq	%r12, %rbx
        addq	%r10, %r14
        xorq	%r11, %rbx
        vpxor	%xmm11, %xmm8, %xmm8
        # rnd_1: 7 - 7
        andq	%rbx, %rdx
        addq	%rax, %r10
        xorq	%r12, %rdx
        vpaddq	%xmm2, %xmm8, %xmm2
        # msg_sched done: 4-5
        # msg_sched: 6-7
        # rnd_0: 0 - 0
        rorxq	$14, %r14, %rax
        rorxq	$18, %r14, %rcx
        addq	%rdx, %r10
        vpalignr	$8, %xmm3, %xmm4, %xmm12
        vpalignr	$8, %xmm7, %xmm0, %xmm13
        # rnd_0: 1 - 1
        addq	48(%rsp), %r9
        movq	%r15, %rdx
        xorq	%rax, %rcx
        vpsrlq	$0x01, %xmm12, %xmm8
        vpsllq	$63, %xmm12, %xmm9
        # rnd_0: 2 - 2
        xorq	%r8, %rdx
        rorxq	$41, %r14, %rax
        xorq	%rcx, %rax
        vpsrlq	$8, %xmm12, %xmm10
        vpsllq	$56, %xmm12, %xmm11
        # rnd_0: 3 - 3
        andq	%r14, %rdx
        addq	%rax, %r9
        rorxq	$28, %r10, %rax
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_0: 4 - 4
        rorxq	$34, %r10, %rcx
        xorq	%r8, %rdx
        xorq	%rax, %rcx
        vpsrlq	$7, %xmm12, %xmm11
        vpxor	%xmm10, %xmm8, %xmm8
        # rnd_0: 5 - 5
        rorxq	$39, %r10, %rax
        addq	%rdx, %r9
        xorq	%rcx, %rax
        vpxor	%xmm11, %xmm8, %xmm8
        vpaddq	%xmm3, %xmm13, %xmm3
        # rnd_0: 6 - 7
        movq	%r11, %rdx
        addq	%r9, %r13
        xorq	%r10, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r9
        xorq	%r11, %rbx
        vpaddq	%xmm3, %xmm8, %xmm3
        # rnd_1: 0 - 0
        rorxq	$14, %r13, %rax
        rorxq	$18, %r13, %rcx
        addq	%rbx, %r9
        vpsrlq	$19, %xmm2, %xmm8
        vpsllq	$45, %xmm2, %xmm9
        # rnd_1: 1 - 1
        addq	56(%rsp), %r8
        movq	%r14, %rbx
        xorq	%rax, %rcx
        vpsrlq	$61, %xmm2, %xmm10
        vpsllq	$3, %xmm2, %xmm11
        # rnd_1: 2 - 2
        xorq	%r15, %rbx
        rorxq	$41, %r13, %rax
        xorq	%rcx, %rax
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_1: 3 - 4
        andq	%r13, %rbx
        addq	%rax, %r8
        rorxq	$28, %r9, %rax
        rorxq	$34, %r9, %rcx
        xorq	%r15, %rbx
        xorq	%rax, %rcx
        vpxor	%xmm10, %xmm8, %xmm8
        vpsrlq	$6, %xmm2, %xmm11
        # rnd_1: 5 - 6
        rorxq	$39, %r9, %rax
        addq	%rbx, %r8
        xorq	%rcx, %rax
        movq	%r10, %rbx
        addq	%r8, %r12
        xorq	%r9, %rbx
        vpxor	%xmm11, %xmm8, %xmm8
        # rnd_1: 7 - 7
        andq	%rbx, %rdx
        addq	%rax, %r8
        xorq	%r10, %rdx
        vpaddq	%xmm3, %xmm8, %xmm3
        # msg_sched done: 6-7
        # msg_sched: 8-9
        # rnd_0: 0 - 0
        rorxq	$14, %r12, %rax
        rorxq	$18, %r12, %rcx
        addq	%rdx, %r8
        vpalignr	$8, %xmm4, %xmm5, %xmm12
        vpalignr	$8, %xmm0, %xmm1, %xmm13
        # rnd_0: 1 - 1
        addq	64(%rsp), %r15
        movq	%r13, %rdx
        xorq	%rax, %rcx
        vpsrlq	$0x01, %xmm12, %xmm8
        vpsllq	$63, %xmm12, %xmm9
        # rnd_0: 2 - 2
        xorq	%r14, %rdx
        rorxq	$41, %r12, %rax
        xorq	%rcx, %rax
        vpsrlq	$8, %xmm12, %xmm10
        vpsllq	$56, %xmm12, %xmm11
        # rnd_0: 3 - 3
        andq	%r12, %rdx
        addq	%rax, %r15
        rorxq	$28, %r8, %rax
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_0: 4 - 4
        rorxq	$34, %r8, %rcx
        xorq	%r14, %rdx
        xorq	%rax, %rcx
        vpsrlq	$7, %xmm12, %xmm11
        vpxor	%xmm10, %xmm8, %xmm8
        # rnd_0: 5 - 5
        rorxq	$39, %r8, %rax
        addq	%rdx, %r15
        xorq	%rcx, %rax
        vpxor	%xmm11, %xmm8, %xmm8
        vpaddq	%xmm4, %xmm13, %xmm4
        # rnd_0: 6 - 7
        movq	%r9, %rdx
        addq	%r15, %r11
        xorq	%r8, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r15
        xorq	%r9, %rbx
        vpaddq	%xmm4, %xmm8, %xmm4
        # rnd_1: 0 - 0
        rorxq	$14, %r11, %rax
        rorxq	$18, %r11, %rcx
        addq	%rbx, %r15
        vpsrlq	$19, %xmm3, %xmm8
        vpsllq	$45, %xmm3, %xmm9
        # rnd_1: 1 - 1
        addq	72(%rsp), %r14
        movq	%r12, %rbx
        xorq	%rax, %rcx
        vpsrlq	$61, %xmm3, %xmm10
        vpsllq	$3, %xmm3, %xmm11
        # rnd_1: 2 - 2
        xorq	%r13, %rbx
        rorxq	$41, %r11, %rax
        xorq	%rcx, %rax
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_1: 3 - 4
        andq	%r11, %rbx
        addq	%rax, %r14
        rorxq	$28, %r15, %rax
        rorxq	$34, %r15, %rcx
        xorq	%r13, %rbx
        xorq	%rax, %rcx
        vpxor	%xmm10, %xmm8, %xmm8
        vpsrlq	$6, %xmm3, %xmm11
        # rnd_1: 5 - 6
        rorxq	$39, %r15, %rax
        addq	%rbx, %r14
        xorq	%rcx, %rax
        movq	%r8, %rbx
        addq	%r14, %r10
        xorq	%r15, %rbx
        vpxor	%xmm11, %xmm8, %xmm8
        # rnd_1: 7 - 7
        andq	%rbx, %rdx
        addq	%rax, %r14
        xorq	%r8, %rdx
        vpaddq	%xmm4, %xmm8, %xmm4
        # msg_sched done: 8-9
        # msg_sched: 10-11
        # rnd_0: 0 - 0
        rorxq	$14, %r10, %rax
        rorxq	$18, %r10, %rcx
        addq	%rdx, %r14
        vpalignr	$8, %xmm5, %xmm6, %xmm12
        vpalignr	$8, %xmm1, %xmm2, %xmm13
        # rnd_0: 1 - 1
        addq	80(%rsp), %r13
        movq	%r11, %rdx
        xorq	%rax, %rcx
        vpsrlq	$0x01, %xmm12, %xmm8
        vpsllq	$63, %xmm12, %xmm9
        # rnd_0: 2 - 2
        xorq	%r12, %rdx
        rorxq	$41, %r10, %rax
        xorq	%rcx, %rax
        vpsrlq	$8, %xmm12, %xmm10
        vpsllq	$56, %xmm12, %xmm11
        # rnd_0: 3 - 3
        andq	%r10, %rdx
        addq	%rax, %r13
        rorxq	$28, %r14, %rax
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_0: 4 - 4
        rorxq	$34, %r14, %rcx
        xorq	%r12, %rdx
        xorq	%rax, %rcx
        vpsrlq	$7, %xmm12, %xmm11
        vpxor	%xmm10, %xmm8, %xmm8
        # rnd_0: 5 - 5
        rorxq	$39, %r14, %rax
        addq	%rdx, %r13
        xorq	%rcx, %rax
        vpxor	%xmm11, %xmm8, %xmm8
        vpaddq	%xmm5, %xmm13, %xmm5
        # rnd_0: 6 - 7
        movq	%r15, %rdx
        addq	%r13, %r9
        xorq	%r14, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r13
        xorq	%r15, %rbx
        vpaddq	%xmm5, %xmm8, %xmm5
        # rnd_1: 0 - 0
        rorxq	$14, %r9, %rax
        rorxq	$18, %r9, %rcx
        addq	%rbx, %r13
        vpsrlq	$19, %xmm4, %xmm8
        vpsllq	$45, %xmm4, %xmm9
        # rnd_1: 1 - 1
        addq	88(%rsp), %r12
        movq	%r10, %rbx
        xorq	%rax, %rcx
        vpsrlq	$61, %xmm4, %xmm10
        vpsllq	$3, %xmm4, %xmm11
        # rnd_1: 2 - 2
        xorq	%r11, %rbx
        rorxq	$41, %r9, %rax
        xorq	%rcx, %rax
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_1: 3 - 4
        andq	%r9, %rbx
        addq	%rax, %r12
        rorxq	$28, %r13, %rax
        rorxq	$34, %r13, %rcx
        xorq	%r11, %rbx
        xorq	%rax, %rcx
        vpxor	%xmm10, %xmm8, %xmm8
        vpsrlq	$6, %xmm4, %xmm11
        # rnd_1: 5 - 6
        rorxq	$39, %r13, %rax
        addq	%rbx, %r12
        xorq	%rcx, %rax
        movq	%r14, %rbx
        addq	%r12, %r8
        xorq	%r13, %rbx
        vpxor	%xmm11, %xmm8, %xmm8
        # rnd_1: 7 - 7
        andq	%rbx, %rdx
        addq	%rax, %r12
        xorq	%r14, %rdx
        vpaddq	%xmm5, %xmm8, %xmm5
        # msg_sched done: 10-11
        # msg_sched: 12-13
        # rnd_0: 0 - 0
        rorxq	$14, %r8, %rax
        rorxq	$18, %r8, %rcx
        addq	%rdx, %r12
        vpalignr	$8, %xmm6, %xmm7, %xmm12
        vpalignr	$8, %xmm2, %xmm3, %xmm13
        # rnd_0: 1 - 1
        addq	96(%rsp), %r11
        movq	%r9, %rdx
        xorq	%rax, %rcx
        vpsrlq	$0x01, %xmm12, %xmm8
        vpsllq	$63, %xmm12, %xmm9
        # rnd_0: 2 - 2
        xorq	%r10, %rdx
        rorxq	$41, %r8, %rax
        xorq	%rcx, %rax
        vpsrlq	$8, %xmm12, %xmm10
        vpsllq	$56, %xmm12, %xmm11
        # rnd_0: 3 - 3
        andq	%r8, %rdx
        addq	%rax, %r11
        rorxq	$28, %r12, %rax
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_0: 4 - 4
        rorxq	$34, %r12, %rcx
        xorq	%r10, %rdx
        xorq	%rax, %rcx
        vpsrlq	$7, %xmm12, %xmm11
        vpxor	%xmm10, %xmm8, %xmm8
        # rnd_0: 5 - 5
        rorxq	$39, %r12, %rax
        addq	%rdx, %r11
        xorq	%rcx, %rax
        vpxor	%xmm11, %xmm8, %xmm8
        vpaddq	%xmm6, %xmm13, %xmm6
        # rnd_0: 6 - 7
        movq	%r13, %rdx
        addq	%r11, %r15
        xorq	%r12, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r11
        xorq	%r13, %rbx
        vpaddq	%xmm6, %xmm8, %xmm6
        # rnd_1: 0 - 0
        rorxq	$14, %r15, %rax
        rorxq	$18, %r15, %rcx
        addq	%rbx, %r11
        vpsrlq	$19, %xmm5, %xmm8
        vpsllq	$45, %xmm5, %xmm9
        # rnd_1: 1 - 1
        addq	104(%rsp), %r10
        movq	%r8, %rbx
        xorq	%rax, %rcx
        vpsrlq	$61, %xmm5, %xmm10
        vpsllq	$3, %xmm5, %xmm11
        # rnd_1: 2 - 2
        xorq	%r9, %rbx
        rorxq	$41, %r15, %rax
        xorq	%rcx, %rax
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_1: 3 - 4
        andq	%r15, %rbx
        addq	%rax, %r10
        rorxq	$28, %r11, %rax
        rorxq	$34, %r11, %rcx
        xorq	%r9, %rbx
        xorq	%rax, %rcx
        vpxor	%xmm10, %xmm8, %xmm8
        vpsrlq	$6, %xmm5, %xmm11
        # rnd_1: 5 - 6
        rorxq	$39, %r11, %rax
        addq	%rbx, %r10
        xorq	%rcx, %rax
        movq	%r12, %rbx
        addq	%r10, %r14
        xorq	%r11, %rbx
        vpxor	%xmm11, %xmm8, %xmm8
        # rnd_1: 7 - 7
        andq	%rbx, %rdx
        addq	%rax, %r10
        xorq	%r12, %rdx
        vpaddq	%xmm6, %xmm8, %xmm6
        # msg_sched done: 12-13
        # msg_sched: 14-15
        # rnd_0: 0 - 0
        rorxq	$14, %r14, %rax
        rorxq	$18, %r14, %rcx
        addq	%rdx, %r10
        vpalignr	$8, %xmm7, %xmm0, %xmm12
        vpalignr	$8, %xmm3, %xmm4, %xmm13
        # rnd_0: 1 - 1
        addq	112(%rsp), %r9
        movq	%r15, %rdx
        xorq	%rax, %rcx
        vpsrlq	$0x01, %xmm12, %xmm8
        vpsllq	$63, %xmm12, %xmm9
        # rnd_0: 2 - 2
        xorq	%r8, %rdx
        rorxq	$41, %r14, %rax
        xorq	%rcx, %rax
        vpsrlq	$8, %xmm12, %xmm10
        vpsllq	$56, %xmm12, %xmm11
        # rnd_0: 3 - 3
        andq	%r14, %rdx
        addq	%rax, %r9
        rorxq	$28, %r10, %rax
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_0: 4 - 4
        rorxq	$34, %r10, %rcx
        xorq	%r8, %rdx
        xorq	%rax, %rcx
        vpsrlq	$7, %xmm12, %xmm11
        vpxor	%xmm10, %xmm8, %xmm8
        # rnd_0: 5 - 5
        rorxq	$39, %r10, %rax
        addq	%rdx, %r9
        xorq	%rcx, %rax
        vpxor	%xmm11, %xmm8, %xmm8
        vpaddq	%xmm7, %xmm13, %xmm7
        # rnd_0: 6 - 7
        movq	%r11, %rdx
        addq	%r9, %r13
        xorq	%r10, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r9
        xorq	%r11, %rbx
        vpaddq	%xmm7, %xmm8, %xmm7
        # rnd_1: 0 - 0
        rorxq	$14, %r13, %rax
        rorxq	$18, %r13, %rcx
        addq	%rbx, %r9
        vpsrlq	$19, %xmm6, %xmm8
        vpsllq	$45, %xmm6, %xmm9
        # rnd_1: 1 - 1
        addq	120(%rsp), %r8
        movq	%r14, %rbx
        xorq	%rax, %rcx
        vpsrlq	$61, %xmm6, %xmm10
        vpsllq	$3, %xmm6, %xmm11
        # rnd_1: 2 - 2
        xorq	%r15, %rbx
        rorxq	$41, %r13, %rax
        xorq	%rcx, %rax
        vpor	%xmm9, %xmm8, %xmm8
        vpor	%xmm11, %xmm10, %xmm10
        # rnd_1: 3 - 4
        andq	%r13, %rbx
        addq	%rax, %r8
        rorxq	$28, %r9, %rax
        rorxq	$34, %r9, %rcx
        xorq	%r15, %rbx
        xorq	%rax, %rcx
        vpxor	%xmm10, %xmm8, %xmm8
        vpsrlq	$6, %xmm6, %xmm11
        # rnd_1: 5 - 6
        rorxq	$39, %r9, %rax
        addq	%rbx, %r8
        xorq	%rcx, %rax
        movq	%r10, %rbx
        addq	%r8, %r12
        xorq	%r9, %rbx
        vpxor	%xmm11, %xmm8, %xmm8
        # rnd_1: 7 - 7
        andq	%rbx, %rdx
        addq	%rax, %r8
        xorq	%r10, %rdx
        vpaddq	%xmm7, %xmm8, %xmm7
        # msg_sched done: 14-15
        movq	136(%rsp), %rcx
        vpaddq	(%rcx), %xmm0, %xmm8
        vpaddq	16(%rcx), %xmm1, %xmm9
        vmovdqu	%xmm8, (%rsp)
        vmovdqu	%xmm9, 16(%rsp)
        vpaddq	32(%rcx), %xmm2, %xmm8
        vpaddq	48(%rcx), %xmm3, %xmm9
        vmovdqu	%xmm8, 32(%rsp)
        vmovdqu	%xmm9, 48(%rsp)
        vpaddq	64(%rcx), %xmm4, %xmm8
        vpaddq	80(%rcx), %xmm5, %xmm9
        vmovdqu	%xmm8, 64(%rsp)
        vmovdqu	%xmm9, 80(%rsp)
        vpaddq	96(%rcx), %xmm6, %xmm8
        vpaddq	112(%rcx), %xmm7, %xmm9
        vmovdqu	%xmm8, 96(%rsp)
        vmovdqu	%xmm9, 112(%rsp)
        subl	$0x01, 128(%rsp)
        jne	L_sha512_len_avx1_rorx_start
        vpaddq	(%rcx), %xmm0, %xmm8
        vpaddq	16(%rcx), %xmm1, %xmm9
        vmovdqu	%xmm8, (%rsp)
        vmovdqu	%xmm9, 16(%rsp)
        vpaddq	32(%rcx), %xmm2, %xmm8
        vpaddq	48(%rcx), %xmm3, %xmm9
        vmovdqu	%xmm8, 32(%rsp)
        vmovdqu	%xmm9, 48(%rsp)
        vpaddq	64(%rcx), %xmm4, %xmm8
        vpaddq	80(%rcx), %xmm5, %xmm9
        vmovdqu	%xmm8, 64(%rsp)
        vmovdqu	%xmm9, 80(%rsp)
        vpaddq	96(%rcx), %xmm6, %xmm8
        vpaddq	112(%rcx), %xmm7, %xmm9
        vmovdqu	%xmm8, 96(%rsp)
        vmovdqu	%xmm9, 112(%rsp)
        # rnd_all_2: 0-1
        # rnd_0: 0 - 7
        rorxq	$14, %r12, %rax
        rorxq	$18, %r12, %rcx
        addq	%rdx, %r8
        addq	(%rsp), %r15
        movq	%r13, %rdx
        xorq	%rax, %rcx
        xorq	%r14, %rdx
        rorxq	$41, %r12, %rax
        xorq	%rcx, %rax
        andq	%r12, %rdx
        addq	%rax, %r15
        rorxq	$28, %r8, %rax
        rorxq	$34, %r8, %rcx
        xorq	%r14, %rdx
        xorq	%rax, %rcx
        rorxq	$39, %r8, %rax
        addq	%rdx, %r15
        xorq	%rcx, %rax
        movq	%r9, %rdx
        addq	%r15, %r11
        xorq	%r8, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r15
        xorq	%r9, %rbx
        # rnd_1: 0 - 7
        rorxq	$14, %r11, %rax
        rorxq	$18, %r11, %rcx
        addq	%rbx, %r15
        addq	8(%rsp), %r14
        movq	%r12, %rbx
        xorq	%rax, %rcx
        xorq	%r13, %rbx
        rorxq	$41, %r11, %rax
        xorq	%rcx, %rax
        andq	%r11, %rbx
        addq	%rax, %r14
        rorxq	$28, %r15, %rax
        rorxq	$34, %r15, %rcx
        xorq	%r13, %rbx
        xorq	%rax, %rcx
        rorxq	$39, %r15, %rax
        addq	%rbx, %r14
        xorq	%rcx, %rax
        movq	%r8, %rbx
        addq	%r14, %r10
        xorq	%r15, %rbx
        andq	%rbx, %rdx
        addq	%rax, %r14
        xorq	%r8, %rdx
        # rnd_all_2: 2-3
        # rnd_0: 0 - 7
        rorxq	$14, %r10, %rax
        rorxq	$18, %r10, %rcx
        addq	%rdx, %r14
        addq	16(%rsp), %r13
        movq	%r11, %rdx
        xorq	%rax, %rcx
        xorq	%r12, %rdx
        rorxq	$41, %r10, %rax
        xorq	%rcx, %rax
        andq	%r10, %rdx
        addq	%rax, %r13
        rorxq	$28, %r14, %rax
        rorxq	$34, %r14, %rcx
        xorq	%r12, %rdx
        xorq	%rax, %rcx
        rorxq	$39, %r14, %rax
        addq	%rdx, %r13
        xorq	%rcx, %rax
        movq	%r15, %rdx
        addq	%r13, %r9
        xorq	%r14, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r13
        xorq	%r15, %rbx
        # rnd_1: 0 - 7
        rorxq	$14, %r9, %rax
        rorxq	$18, %r9, %rcx
        addq	%rbx, %r13
        addq	24(%rsp), %r12
        movq	%r10, %rbx
        xorq	%rax, %rcx
        xorq	%r11, %rbx
        rorxq	$41, %r9, %rax
        xorq	%rcx, %rax
        andq	%r9, %rbx
        addq	%rax, %r12
        rorxq	$28, %r13, %rax
        rorxq	$34, %r13, %rcx
        xorq	%r11, %rbx
        xorq	%rax, %rcx
        rorxq	$39, %r13, %rax
        addq	%rbx, %r12
        xorq	%rcx, %rax
        movq	%r14, %rbx
        addq	%r12, %r8
        xorq	%r13, %rbx
        andq	%rbx, %rdx
        addq	%rax, %r12
        xorq	%r14, %rdx
        # rnd_all_2: 4-5
        # rnd_0: 0 - 7
        rorxq	$14, %r8, %rax
        rorxq	$18, %r8, %rcx
        addq	%rdx, %r12
        addq	32(%rsp), %r11
        movq	%r9, %rdx
        xorq	%rax, %rcx
        xorq	%r10, %rdx
        rorxq	$41, %r8, %rax
        xorq	%rcx, %rax
        andq	%r8, %rdx
        addq	%rax, %r11
        rorxq	$28, %r12, %rax
        rorxq	$34, %r12, %rcx
        xorq	%r10, %rdx
        xorq	%rax, %rcx
        rorxq	$39, %r12, %rax
        addq	%rdx, %r11
        xorq	%rcx, %rax
        movq	%r13, %rdx
        addq	%r11, %r15
        xorq	%r12, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r11
        xorq	%r13, %rbx
        # rnd_1: 0 - 7
        rorxq	$14, %r15, %rax
        rorxq	$18, %r15, %rcx
        addq	%rbx, %r11
        addq	40(%rsp), %r10
        movq	%r8, %rbx
        xorq	%rax, %rcx
        xorq	%r9, %rbx
        rorxq	$41, %r15, %rax
        xorq	%rcx, %rax
        andq	%r15, %rbx
        addq	%rax, %r10
        rorxq	$28, %r11, %rax
        rorxq	$34, %r11, %rcx
        xorq	%r9, %rbx
        xorq	%rax, %rcx
        rorxq	$39, %r11, %rax
        addq	%rbx, %r10
        xorq	%rcx, %rax
        movq	%r12, %rbx
        addq	%r10, %r14
        xorq	%r11, %rbx
        andq	%rbx, %rdx
        addq	%rax, %r10
        xorq	%r12, %rdx
        # rnd_all_2: 6-7
        # rnd_0: 0 - 7
        rorxq	$14, %r14, %rax
        rorxq	$18, %r14, %rcx
        addq	%rdx, %r10
        addq	48(%rsp), %r9
        movq	%r15, %rdx
        xorq	%rax, %rcx
        xorq	%r8, %rdx
        rorxq	$41, %r14, %rax
        xorq	%rcx, %rax
        andq	%r14, %rdx
        addq	%rax, %r9
        rorxq	$28, %r10, %rax
        rorxq	$34, %r10, %rcx
        xorq	%r8, %rdx
        xorq	%rax, %rcx
        rorxq	$39, %r10, %rax
        addq	%rdx, %r9
        xorq	%rcx, %rax
        movq	%r11, %rdx
        addq	%r9, %r13
        xorq	%r10, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r9
        xorq	%r11, %rbx
        # rnd_1: 0 - 7
        rorxq	$14, %r13, %rax
        rorxq	$18, %r13, %rcx
        addq	%rbx, %r9
        addq	56(%rsp), %r8
        movq	%r14, %rbx
        xorq	%rax, %rcx
        xorq	%r15, %rbx
        rorxq	$41, %r13, %rax
        xorq	%rcx, %rax
        andq	%r13, %rbx
        addq	%rax, %r8
        rorxq	$28, %r9, %rax
        rorxq	$34, %r9, %rcx
        xorq	%r15, %rbx
        xorq	%rax, %rcx
        rorxq	$39, %r9, %rax
        addq	%rbx, %r8
        xorq	%rcx, %rax
        movq	%r10, %rbx
        addq	%r8, %r12
        xorq	%r9, %rbx
        andq	%rbx, %rdx
        addq	%rax, %r8
        xorq	%r10, %rdx
        # rnd_all_2: 8-9
        # rnd_0: 0 - 7
        rorxq	$14, %r12, %rax
        rorxq	$18, %r12, %rcx
        addq	%rdx, %r8
        addq	64(%rsp), %r15
        movq	%r13, %rdx
        xorq	%rax, %rcx
        xorq	%r14, %rdx
        rorxq	$41, %r12, %rax
        xorq	%rcx, %rax
        andq	%r12, %rdx
        addq	%rax, %r15
        rorxq	$28, %r8, %rax
        rorxq	$34, %r8, %rcx
        xorq	%r14, %rdx
        xorq	%rax, %rcx
        rorxq	$39, %r8, %rax
        addq	%rdx, %r15
        xorq	%rcx, %rax
        movq	%r9, %rdx
        addq	%r15, %r11
        xorq	%r8, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r15
        xorq	%r9, %rbx
        # rnd_1: 0 - 7
        rorxq	$14, %r11, %rax
        rorxq	$18, %r11, %rcx
        addq	%rbx, %r15
        addq	72(%rsp), %r14
        movq	%r12, %rbx
        xorq	%rax, %rcx
        xorq	%r13, %rbx
        rorxq	$41, %r11, %rax
        xorq	%rcx, %rax
        andq	%r11, %rbx
        addq	%rax, %r14
        rorxq	$28, %r15, %rax
        rorxq	$34, %r15, %rcx
        xorq	%r13, %rbx
        xorq	%rax, %rcx
        rorxq	$39, %r15, %rax
        addq	%rbx, %r14
        xorq	%rcx, %rax
        movq	%r8, %rbx
        addq	%r14, %r10
        xorq	%r15, %rbx
        andq	%rbx, %rdx
        addq	%rax, %r14
        xorq	%r8, %rdx
        # rnd_all_2: 10-11
        # rnd_0: 0 - 7
        rorxq	$14, %r10, %rax
        rorxq	$18, %r10, %rcx
        addq	%rdx, %r14
        addq	80(%rsp), %r13
        movq	%r11, %rdx
        xorq	%rax, %rcx
        xorq	%r12, %rdx
        rorxq	$41, %r10, %rax
        xorq	%rcx, %rax
        andq	%r10, %rdx
        addq	%rax, %r13
        rorxq	$28, %r14, %rax
        rorxq	$34, %r14, %rcx
        xorq	%r12, %rdx
        xorq	%rax, %rcx
        rorxq	$39, %r14, %rax
        addq	%rdx, %r13
        xorq	%rcx, %rax
        movq	%r15, %rdx
        addq	%r13, %r9
        xorq	%r14, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r13
        xorq	%r15, %rbx
        # rnd_1: 0 - 7
        rorxq	$14, %r9, %rax
        rorxq	$18, %r9, %rcx
        addq	%rbx, %r13
        addq	88(%rsp), %r12
        movq	%r10, %rbx
        xorq	%rax, %rcx
        xorq	%r11, %rbx
        rorxq	$41, %r9, %rax
        xorq	%rcx, %rax
        andq	%r9, %rbx
        addq	%rax, %r12
        rorxq	$28, %r13, %rax
        rorxq	$34, %r13, %rcx
        xorq	%r11, %rbx
        xorq	%rax, %rcx
        rorxq	$39, %r13, %rax
        addq	%rbx, %r12
        xorq	%rcx, %rax
        movq	%r14, %rbx
        addq	%r12, %r8
        xorq	%r13, %rbx
        andq	%rbx, %rdx
        addq	%rax, %r12
        xorq	%r14, %rdx
        # rnd_all_2: 12-13
        # rnd_0: 0 - 7
        rorxq	$14, %r8, %rax
        rorxq	$18, %r8, %rcx
        addq	%rdx, %r12
        addq	96(%rsp), %r11
        movq	%r9, %rdx
        xorq	%rax, %rcx
        xorq	%r10, %rdx
        rorxq	$41, %r8, %rax
        xorq	%rcx, %rax
        andq	%r8, %rdx
        addq	%rax, %r11
        rorxq	$28, %r12, %rax
        rorxq	$34, %r12, %rcx
        xorq	%r10, %rdx
        xorq	%rax, %rcx
        rorxq	$39, %r12, %rax
        addq	%rdx, %r11
        xorq	%rcx, %rax
        movq	%r13, %rdx
        addq	%r11, %r15
        xorq	%r12, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r11
        xorq	%r13, %rbx
        # rnd_1: 0 - 7
        rorxq	$14, %r15, %rax
        rorxq	$18, %r15, %rcx
        addq	%rbx, %r11
        addq	104(%rsp), %r10
        movq	%r8, %rbx
        xorq	%rax, %rcx
        xorq	%r9, %rbx
        rorxq	$41, %r15, %rax
        xorq	%rcx, %rax
        andq	%r15, %rbx
        addq	%rax, %r10
        rorxq	$28, %r11, %rax
        rorxq	$34, %r11, %rcx
        xorq	%r9, %rbx
        xorq	%rax, %rcx
        rorxq	$39, %r11, %rax
        addq	%rbx, %r10
        xorq	%rcx, %rax
        movq	%r12, %rbx
        addq	%r10, %r14
        xorq	%r11, %rbx
        andq	%rbx, %rdx
        addq	%rax, %r10
        xorq	%r12, %rdx
        # rnd_all_2: 14-15
        # rnd_0: 0 - 7
        rorxq	$14, %r14, %rax
        rorxq	$18, %r14, %rcx
        addq	%rdx, %r10
        addq	112(%rsp), %r9
        movq	%r15, %rdx
        xorq	%rax, %rcx
        xorq	%r8, %rdx
        rorxq	$41, %r14, %rax
        xorq	%rcx, %rax
        andq	%r14, %rdx
        addq	%rax, %r9
        rorxq	$28, %r10, %rax
        rorxq	$34, %r10, %rcx
        xorq	%r8, %rdx
        xorq	%rax, %rcx
        rorxq	$39, %r10, %rax
        addq	%rdx, %r9
        xorq	%rcx, %rax
        movq	%r11, %rdx
        addq	%r9, %r13
        xorq	%r10, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r9
        xorq	%r11, %rbx
        # rnd_1: 0 - 7
        rorxq	$14, %r13, %rax
        rorxq	$18, %r13, %rcx
        addq	%rbx, %r9
        addq	120(%rsp), %r8
        movq	%r14, %rbx
        xorq	%rax, %rcx
        xorq	%r15, %rbx
        rorxq	$41, %r13, %rax
        xorq	%rcx, %rax
        andq	%r13, %rbx
        addq	%rax, %r8
        rorxq	$28, %r9, %rax
        rorxq	$34, %r9, %rcx
        xorq	%r15, %rbx
        xorq	%rax, %rcx
        rorxq	$39, %r9, %rax
        addq	%rbx, %r8
        xorq	%rcx, %rax
        movq	%r10, %rbx
        addq	%r8, %r12
        xorq	%r9, %rbx
        andq	%rbx, %rdx
        addq	%rax, %r8
        xorq	%r10, %rdx
        addq	%rdx, %r8
        addq	(%rdi), %r8
        addq	8(%rdi), %r9
        addq	16(%rdi), %r10
        addq	24(%rdi), %r11
        addq	32(%rdi), %r12
        addq	40(%rdi), %r13
        addq	48(%rdi), %r14
        addq	56(%rdi), %r15
        leaq	L_avx1_rorx_sha512_k(%rip), %rcx
        addq	$0x80, %rsi
        subl	$0x80, %ebp
        movq	%r8, (%rdi)
        movq	%r9, 8(%rdi)
        movq	%r10, 16(%rdi)
        movq	%r11, 24(%rdi)
        movq	%r12, 32(%rdi)
        movq	%r13, 40(%rdi)
        movq	%r14, 48(%rdi)
        movq	%r15, 56(%rdi)
        jnz	L_sha512_len_avx1_rorx_begin
        xorq	%rax, %rax
        addq	$0x98, %rsp
        popq	%rbp
        popq	%r15
        popq	%r14
        popq	%r13
        popq	%r12
        popq	%rbx
        repz retq
#ifndef __APPLE__
.size	Transform_Sha512_AVX1_RORX_Len,.-Transform_Sha512_AVX1_RORX_Len
#endif /* __APPLE__ */
#endif /* HAVE_INTEL_AVX1 */
#ifdef HAVE_INTEL_AVX2
#ifndef __APPLE__
.data
#else
.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
.align	32
#else
.p2align	5
#endif /* __APPLE__ */
L_avx2_sha512_k:
.quad	0x428a2f98d728ae22,0x7137449123ef65cd
.quad	0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc
.quad	0x3956c25bf348b538,0x59f111f1b605d019
.quad	0x923f82a4af194f9b,0xab1c5ed5da6d8118
.quad	0xd807aa98a3030242,0x12835b0145706fbe
.quad	0x243185be4ee4b28c,0x550c7dc3d5ffb4e2
.quad	0x72be5d74f27b896f,0x80deb1fe3b1696b1
.quad	0x9bdc06a725c71235,0xc19bf174cf692694
.quad	0xe49b69c19ef14ad2,0xefbe4786384f25e3
.quad	0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65
.quad	0x2de92c6f592b0275,0x4a7484aa6ea6e483
.quad	0x5cb0a9dcbd41fbd4,0x76f988da831153b5
.quad	0x983e5152ee66dfab,0xa831c66d2db43210
.quad	0xb00327c898fb213f,0xbf597fc7beef0ee4
.quad	0xc6e00bf33da88fc2,0xd5a79147930aa725
.quad	0x06ca6351e003826f,0x142929670a0e6e70
.quad	0x27b70a8546d22ffc,0x2e1b21385c26c926
.quad	0x4d2c6dfc5ac42aed,0x53380d139d95b3df
.quad	0x650a73548baf63de,0x766a0abb3c77b2a8
.quad	0x81c2c92e47edaee6,0x92722c851482353b
.quad	0xa2bfe8a14cf10364,0xa81a664bbc423001
.quad	0xc24b8b70d0f89791,0xc76c51a30654be30
.quad	0xd192e819d6ef5218,0xd69906245565a910
.quad	0xf40e35855771202a,0x106aa07032bbd1b8
.quad	0x19a4c116b8d2d0c8,0x1e376c085141ab53
.quad	0x2748774cdf8eeb99,0x34b0bcb5e19b48a8
.quad	0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb
.quad	0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3
.quad	0x748f82ee5defb2fc,0x78a5636f43172f60
.quad	0x84c87814a1f0ab72,0x8cc702081a6439ec
.quad	0x90befffa23631e28,0xa4506cebde82bde9
.quad	0xbef9a3f7b2c67915,0xc67178f2e372532b
.quad	0xca273eceea26619c,0xd186b8c721c0c207
.quad	0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178
.quad	0x06f067aa72176fba,0x0a637dc5a2c898a6
.quad	0x113f9804bef90dae,0x1b710b35131c471b
.quad	0x28db77f523047d84,0x32caab7b40c72493
.quad	0x3c9ebe0a15c9bebc,0x431d67c49c100d4c
.quad	0x4cc5d4becb3e42b6,0x597f299cfc657e2a
.quad	0x5fcb6fab3ad6faec,0x6c44198c4a475817
#ifndef __APPLE__
.data
#else
.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
.align	32
#else
.p2align	5
#endif /* __APPLE__ */
L_avx2_sha512_k_2:
.quad	0x428a2f98d728ae22,0x7137449123ef65cd
.quad	0x428a2f98d728ae22,0x7137449123ef65cd
.quad	0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc
.quad	0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc
.quad	0x3956c25bf348b538,0x59f111f1b605d019
.quad	0x3956c25bf348b538,0x59f111f1b605d019
.quad	0x923f82a4af194f9b,0xab1c5ed5da6d8118
.quad	0x923f82a4af194f9b,0xab1c5ed5da6d8118
.quad	0xd807aa98a3030242,0x12835b0145706fbe
.quad	0xd807aa98a3030242,0x12835b0145706fbe
.quad	0x243185be4ee4b28c,0x550c7dc3d5ffb4e2
.quad	0x243185be4ee4b28c,0x550c7dc3d5ffb4e2
.quad	0x72be5d74f27b896f,0x80deb1fe3b1696b1
.quad	0x72be5d74f27b896f,0x80deb1fe3b1696b1
.quad	0x9bdc06a725c71235,0xc19bf174cf692694
.quad	0x9bdc06a725c71235,0xc19bf174cf692694
.quad	0xe49b69c19ef14ad2,0xefbe4786384f25e3
.quad	0xe49b69c19ef14ad2,0xefbe4786384f25e3
.quad	0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65
.quad	0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65
.quad	0x2de92c6f592b0275,0x4a7484aa6ea6e483
.quad	0x2de92c6f592b0275,0x4a7484aa6ea6e483
.quad	0x5cb0a9dcbd41fbd4,0x76f988da831153b5
.quad	0x5cb0a9dcbd41fbd4,0x76f988da831153b5
.quad	0x983e5152ee66dfab,0xa831c66d2db43210
.quad	0x983e5152ee66dfab,0xa831c66d2db43210
.quad	0xb00327c898fb213f,0xbf597fc7beef0ee4
.quad	0xb00327c898fb213f,0xbf597fc7beef0ee4
.quad	0xc6e00bf33da88fc2,0xd5a79147930aa725
.quad	0xc6e00bf33da88fc2,0xd5a79147930aa725
.quad	0x06ca6351e003826f,0x142929670a0e6e70
.quad	0x06ca6351e003826f,0x142929670a0e6e70
.quad	0x27b70a8546d22ffc,0x2e1b21385c26c926
.quad	0x27b70a8546d22ffc,0x2e1b21385c26c926
.quad	0x4d2c6dfc5ac42aed,0x53380d139d95b3df
.quad	0x4d2c6dfc5ac42aed,0x53380d139d95b3df
.quad	0x650a73548baf63de,0x766a0abb3c77b2a8
.quad	0x650a73548baf63de,0x766a0abb3c77b2a8
.quad	0x81c2c92e47edaee6,0x92722c851482353b
.quad	0x81c2c92e47edaee6,0x92722c851482353b
.quad	0xa2bfe8a14cf10364,0xa81a664bbc423001
.quad	0xa2bfe8a14cf10364,0xa81a664bbc423001
.quad	0xc24b8b70d0f89791,0xc76c51a30654be30
.quad	0xc24b8b70d0f89791,0xc76c51a30654be30
.quad	0xd192e819d6ef5218,0xd69906245565a910
.quad	0xd192e819d6ef5218,0xd69906245565a910
.quad	0xf40e35855771202a,0x106aa07032bbd1b8
.quad	0xf40e35855771202a,0x106aa07032bbd1b8
.quad	0x19a4c116b8d2d0c8,0x1e376c085141ab53
.quad	0x19a4c116b8d2d0c8,0x1e376c085141ab53
.quad	0x2748774cdf8eeb99,0x34b0bcb5e19b48a8
.quad	0x2748774cdf8eeb99,0x34b0bcb5e19b48a8
.quad	0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb
.quad	0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb
.quad	0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3
.quad	0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3
.quad	0x748f82ee5defb2fc,0x78a5636f43172f60
.quad	0x748f82ee5defb2fc,0x78a5636f43172f60
.quad	0x84c87814a1f0ab72,0x8cc702081a6439ec
.quad	0x84c87814a1f0ab72,0x8cc702081a6439ec
.quad	0x90befffa23631e28,0xa4506cebde82bde9
.quad	0x90befffa23631e28,0xa4506cebde82bde9
.quad	0xbef9a3f7b2c67915,0xc67178f2e372532b
.quad	0xbef9a3f7b2c67915,0xc67178f2e372532b
.quad	0xca273eceea26619c,0xd186b8c721c0c207
.quad	0xca273eceea26619c,0xd186b8c721c0c207
.quad	0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178
.quad	0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178
.quad	0x06f067aa72176fba,0x0a637dc5a2c898a6
.quad	0x06f067aa72176fba,0x0a637dc5a2c898a6
.quad	0x113f9804bef90dae,0x1b710b35131c471b
.quad	0x113f9804bef90dae,0x1b710b35131c471b
.quad	0x28db77f523047d84,0x32caab7b40c72493
.quad	0x28db77f523047d84,0x32caab7b40c72493
.quad	0x3c9ebe0a15c9bebc,0x431d67c49c100d4c
.quad	0x3c9ebe0a15c9bebc,0x431d67c49c100d4c
.quad	0x4cc5d4becb3e42b6,0x597f299cfc657e2a
.quad	0x4cc5d4becb3e42b6,0x597f299cfc657e2a
.quad	0x5fcb6fab3ad6faec,0x6c44198c4a475817
.quad	0x5fcb6fab3ad6faec,0x6c44198c4a475817
#ifndef __APPLE__
.data
#else
.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
.align	8
#else
.p2align	3
#endif /* __APPLE__ */
L_avx2_sha512_k_2_end:
.quad	1024+L_avx2_sha512_k_2
#ifndef __APPLE__
.data
#else
.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
.align	32
#else
.p2align	5
#endif /* __APPLE__ */
L_avx2_sha512_flip_mask:
.quad	0x0001020304050607,0x08090a0b0c0d0e0f
.quad	0x0001020304050607,0x08090a0b0c0d0e0f
#ifndef __APPLE__
.text
.globl	Transform_Sha512_AVX2
WC_ASM_ATT_HIDDEN(Transform_Sha512_AVX2)
.type	Transform_Sha512_AVX2,@function
.align	16
Transform_Sha512_AVX2:
#else
.section	__TEXT,__text
.globl	_Transform_Sha512_AVX2
WC_ASM_ATT_HIDDEN(_Transform_Sha512_AVX2)
.p2align	4
_Transform_Sha512_AVX2:
#endif /* __APPLE__ */
        pushq	%rbx
        pushq	%r12
        pushq	%r13
        pushq	%r14
        pushq	%r15
        subq	$0x90, %rsp
        leaq	64(%rdi), %rax
        vmovdqa	L_avx2_sha512_flip_mask(%rip), %ymm15
        movq	(%rdi), %r8
        movq	8(%rdi), %r9
        movq	16(%rdi), %r10
        movq	24(%rdi), %r11
        movq	32(%rdi), %r12
        movq	40(%rdi), %r13
        movq	48(%rdi), %r14
        movq	56(%rdi), %r15
        vmovdqu	(%rax), %ymm0
        vmovdqu	32(%rax), %ymm1
        vpshufb	%ymm15, %ymm0, %ymm0
        vpshufb	%ymm15, %ymm1, %ymm1
        vmovdqu	64(%rax), %ymm2
        vmovdqu	96(%rax), %ymm3
        vpshufb	%ymm15, %ymm2, %ymm2
        vpshufb	%ymm15, %ymm3, %ymm3
        movl	$4, 128(%rsp)
        leaq	L_avx2_sha512_k(%rip), %rsi
        movq	%r9, %rbx
        movq	%r12, %rax
        xorq	%r10, %rbx
        vpaddq	(%rsi), %ymm0, %ymm8
        vpaddq	32(%rsi), %ymm1, %ymm9
        vmovdqu	%ymm8, (%rsp)
        vmovdqu	%ymm9, 32(%rsp)
        vpaddq	64(%rsi), %ymm2, %ymm8
        vpaddq	96(%rsi), %ymm3, %ymm9
        vmovdqu	%ymm8, 64(%rsp)
        vmovdqu	%ymm9, 96(%rsp)
        # Start of 16 rounds
L_sha256_avx2_start:
        addq	$0x80, %rsi
        rorq	$23, %rax
        vpblendd	$3, %ymm1, %ymm0, %ymm12
        vpblendd	$3, %ymm3, %ymm2, %ymm13
        movq	%r8, %rdx
        movq	%r13, %rcx
        addq	(%rsp), %r15
        xorq	%r14, %rcx
        xorq	%r12, %rax
        andq	%r12, %rcx
        vpermq	$57, %ymm12, %ymm12
        rorq	$4, %rax
        xorq	%r14, %rcx
        vpermq	$57, %ymm13, %ymm13
        xorq	%r12, %rax
        addq	%rcx, %r15
        rorq	$14, %rax
        xorq	%r9, %rdx
        vpsrlq	$0x01, %ymm12, %ymm8
        addq	%rax, %r15
        movq	%r8, %rcx
        vpsllq	$63, %ymm12, %ymm9
        andq	%rdx, %rbx
        rorq	$5, %rcx
        vpsrlq	$8, %ymm12, %ymm10
        xorq	%r8, %rcx
        xorq	%r9, %rbx
        vpsllq	$56, %ymm12, %ymm11
        rorq	$6, %rcx
        addq	%r15, %r11
        vpor	%ymm9, %ymm8, %ymm8
        xorq	%r8, %rcx
        addq	%rbx, %r15
        vpor	%ymm11, %ymm10, %ymm10
        rorq	$28, %rcx
        movq	%r11, %rax
        addq	%rcx, %r15
        rorq	$23, %rax
        vpsrlq	$7, %ymm12, %ymm11
        movq	%r15, %rbx
        movq	%r12, %rcx
        vpxor	%ymm10, %ymm8, %ymm8
        addq	8(%rsp), %r14
        xorq	%r13, %rcx
        vpxor	%ymm11, %ymm8, %ymm8
        xorq	%r11, %rax
        andq	%r11, %rcx
        vpaddq	%ymm0, %ymm13, %ymm0
        rorq	$4, %rax
        xorq	%r13, %rcx
        vpaddq	%ymm0, %ymm8, %ymm0
        xorq	%r11, %rax
        addq	%rcx, %r14
        vperm2I128	$0x81, %ymm3, %ymm3, %ymm14
        rorq	$14, %rax
        xorq	%r8, %rbx
        addq	%rax, %r14
        movq	%r15, %rcx
        andq	%rbx, %rdx
        rorq	$5, %rcx
        vpsrlq	$19, %ymm14, %ymm8
        xorq	%r15, %rcx
        xorq	%r8, %rdx
        vpsllq	$45, %ymm14, %ymm9
        rorq	$6, %rcx
        addq	%r14, %r10
        vpsrlq	$61, %ymm14, %ymm10
        xorq	%r15, %rcx
        addq	%rdx, %r14
        vpsllq	$3, %ymm14, %ymm11
        rorq	$28, %rcx
        movq	%r10, %rax
        addq	%rcx, %r14
        rorq	$23, %rax
        vpor	%ymm9, %ymm8, %ymm8
        movq	%r14, %rdx
        movq	%r11, %rcx
        addq	16(%rsp), %r13
        xorq	%r12, %rcx
        vpor	%ymm11, %ymm10, %ymm10
        xorq	%r10, %rax
        andq	%r10, %rcx
        vpxor	%ymm10, %ymm8, %ymm8
        rorq	$4, %rax
        xorq	%r12, %rcx
        vpsrlq	$6, %ymm14, %ymm11
        xorq	%r10, %rax
        addq	%rcx, %r13
        vpxor	%ymm11, %ymm8, %ymm8
        rorq	$14, %rax
        xorq	%r15, %rdx
        vpaddq	%ymm0, %ymm8, %ymm0
        addq	%rax, %r13
        movq	%r14, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        vperm2I128	$8, %ymm0, %ymm0, %ymm14
        xorq	%r14, %rcx
        xorq	%r15, %rbx
        rorq	$6, %rcx
        addq	%r13, %r9
        vpsrlq	$19, %ymm14, %ymm8
        xorq	%r14, %rcx
        addq	%rbx, %r13
        vpsllq	$45, %ymm14, %ymm9
        rorq	$28, %rcx
        movq	%r9, %rax
        addq	%rcx, %r13
        rorq	$23, %rax
        vpsrlq	$61, %ymm14, %ymm10
        movq	%r13, %rbx
        movq	%r10, %rcx
        addq	24(%rsp), %r12
        xorq	%r11, %rcx
        vpsllq	$3, %ymm14, %ymm11
        xorq	%r9, %rax
        andq	%r9, %rcx
        vpor	%ymm9, %ymm8, %ymm8
        rorq	$4, %rax
        xorq	%r11, %rcx
        vpor	%ymm11, %ymm10, %ymm10
        xorq	%r9, %rax
        addq	%rcx, %r12
        vpxor	%ymm10, %ymm8, %ymm8
        rorq	$14, %rax
        xorq	%r14, %rbx
        vpsrlq	$6, %ymm14, %ymm11
        addq	%rax, %r12
        movq	%r13, %rcx
        vpxor	%ymm11, %ymm8, %ymm8
        andq	%rbx, %rdx
        rorq	$5, %rcx
        vpaddq	%ymm0, %ymm8, %ymm0
        xorq	%r13, %rcx
        xorq	%r14, %rdx
        rorq	$6, %rcx
        addq	%r12, %r8
        xorq	%r13, %rcx
        addq	%rdx, %r12
        rorq	$28, %rcx
        movq	%r8, %rax
        addq	%rcx, %r12
        rorq	$23, %rax
        vpblendd	$3, %ymm2, %ymm1, %ymm12
        vpblendd	$3, %ymm0, %ymm3, %ymm13
        movq	%r12, %rdx
        movq	%r9, %rcx
        addq	32(%rsp), %r11
        xorq	%r10, %rcx
        xorq	%r8, %rax
        andq	%r8, %rcx
        vpermq	$57, %ymm12, %ymm12
        rorq	$4, %rax
        xorq	%r10, %rcx
        vpermq	$57, %ymm13, %ymm13
        xorq	%r8, %rax
        addq	%rcx, %r11
        rorq	$14, %rax
        xorq	%r13, %rdx
        vpsrlq	$0x01, %ymm12, %ymm8
        addq	%rax, %r11
        movq	%r12, %rcx
        vpsllq	$63, %ymm12, %ymm9
        andq	%rdx, %rbx
        rorq	$5, %rcx
        vpsrlq	$8, %ymm12, %ymm10
        xorq	%r12, %rcx
        xorq	%r13, %rbx
        vpsllq	$56, %ymm12, %ymm11
        rorq	$6, %rcx
        addq	%r11, %r15
        vpor	%ymm9, %ymm8, %ymm8
        xorq	%r12, %rcx
        addq	%rbx, %r11
        vpor	%ymm11, %ymm10, %ymm10
        rorq	$28, %rcx
        movq	%r15, %rax
        addq	%rcx, %r11
        rorq	$23, %rax
        vpsrlq	$7, %ymm12, %ymm11
        movq	%r11, %rbx
        movq	%r8, %rcx
        vpxor	%ymm10, %ymm8, %ymm8
        addq	40(%rsp), %r10
        xorq	%r9, %rcx
        vpxor	%ymm11, %ymm8, %ymm8
        xorq	%r15, %rax
        andq	%r15, %rcx
        vpaddq	%ymm1, %ymm13, %ymm1
        rorq	$4, %rax
        xorq	%r9, %rcx
        vpaddq	%ymm1, %ymm8, %ymm1
        xorq	%r15, %rax
        addq	%rcx, %r10
        vperm2I128	$0x81, %ymm0, %ymm0, %ymm14
        rorq	$14, %rax
        xorq	%r12, %rbx
        addq	%rax, %r10
        movq	%r11, %rcx
        andq	%rbx, %rdx
        rorq	$5, %rcx
        vpsrlq	$19, %ymm14, %ymm8
        xorq	%r11, %rcx
        xorq	%r12, %rdx
        vpsllq	$45, %ymm14, %ymm9
        rorq	$6, %rcx
        addq	%r10, %r14
        vpsrlq	$61, %ymm14, %ymm10
        xorq	%r11, %rcx
        addq	%rdx, %r10
        vpsllq	$3, %ymm14, %ymm11
        rorq	$28, %rcx
        movq	%r14, %rax
        addq	%rcx, %r10
        rorq	$23, %rax
        vpor	%ymm9, %ymm8, %ymm8
        movq	%r10, %rdx
        movq	%r15, %rcx
        addq	48(%rsp), %r9
        xorq	%r8, %rcx
        vpor	%ymm11, %ymm10, %ymm10
        xorq	%r14, %rax
        andq	%r14, %rcx
        vpxor	%ymm10, %ymm8, %ymm8
        rorq	$4, %rax
        xorq	%r8, %rcx
        vpsrlq	$6, %ymm14, %ymm11
        xorq	%r14, %rax
        addq	%rcx, %r9
        vpxor	%ymm11, %ymm8, %ymm8
        rorq	$14, %rax
        xorq	%r11, %rdx
        vpaddq	%ymm1, %ymm8, %ymm1
        addq	%rax, %r9
        movq	%r10, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        vperm2I128	$8, %ymm1, %ymm1, %ymm14
        xorq	%r10, %rcx
        xorq	%r11, %rbx
        rorq	$6, %rcx
        addq	%r9, %r13
        vpsrlq	$19, %ymm14, %ymm8
        xorq	%r10, %rcx
        addq	%rbx, %r9
        vpsllq	$45, %ymm14, %ymm9
        rorq	$28, %rcx
        movq	%r13, %rax
        addq	%rcx, %r9
        rorq	$23, %rax
        vpsrlq	$61, %ymm14, %ymm10
        movq	%r9, %rbx
        movq	%r14, %rcx
        addq	56(%rsp), %r8
        xorq	%r15, %rcx
        vpsllq	$3, %ymm14, %ymm11
        xorq	%r13, %rax
        andq	%r13, %rcx
        vpor	%ymm9, %ymm8, %ymm8
        rorq	$4, %rax
        xorq	%r15, %rcx
        vpor	%ymm11, %ymm10, %ymm10
        xorq	%r13, %rax
        addq	%rcx, %r8
        vpxor	%ymm10, %ymm8, %ymm8
        rorq	$14, %rax
        xorq	%r10, %rbx
        vpsrlq	$6, %ymm14, %ymm11
        addq	%rax, %r8
        movq	%r9, %rcx
        vpxor	%ymm11, %ymm8, %ymm8
        andq	%rbx, %rdx
        rorq	$5, %rcx
        vpaddq	%ymm1, %ymm8, %ymm1
        xorq	%r9, %rcx
        xorq	%r10, %rdx
        rorq	$6, %rcx
        addq	%r8, %r12
        xorq	%r9, %rcx
        addq	%rdx, %r8
        rorq	$28, %rcx
        movq	%r12, %rax
        addq	%rcx, %r8
        rorq	$23, %rax
        vpblendd	$3, %ymm3, %ymm2, %ymm12
        vpblendd	$3, %ymm1, %ymm0, %ymm13
        movq	%r8, %rdx
        movq	%r13, %rcx
        addq	64(%rsp), %r15
        xorq	%r14, %rcx
        xorq	%r12, %rax
        andq	%r12, %rcx
        vpermq	$57, %ymm12, %ymm12
        rorq	$4, %rax
        xorq	%r14, %rcx
        vpermq	$57, %ymm13, %ymm13
        xorq	%r12, %rax
        addq	%rcx, %r15
        rorq	$14, %rax
        xorq	%r9, %rdx
        vpsrlq	$0x01, %ymm12, %ymm8
        addq	%rax, %r15
        movq	%r8, %rcx
        vpsllq	$63, %ymm12, %ymm9
        andq	%rdx, %rbx
        rorq	$5, %rcx
        vpsrlq	$8, %ymm12, %ymm10
        xorq	%r8, %rcx
        xorq	%r9, %rbx
        vpsllq	$56, %ymm12, %ymm11
        rorq	$6, %rcx
        addq	%r15, %r11
        vpor	%ymm9, %ymm8, %ymm8
        xorq	%r8, %rcx
        addq	%rbx, %r15
        vpor	%ymm11, %ymm10, %ymm10
        rorq	$28, %rcx
        movq	%r11, %rax
        addq	%rcx, %r15
        rorq	$23, %rax
        vpsrlq	$7, %ymm12, %ymm11
        movq	%r15, %rbx
        movq	%r12, %rcx
        vpxor	%ymm10, %ymm8, %ymm8
        addq	72(%rsp), %r14
        xorq	%r13, %rcx
        vpxor	%ymm11, %ymm8, %ymm8
        xorq	%r11, %rax
        andq	%r11, %rcx
        vpaddq	%ymm2, %ymm13, %ymm2
        rorq	$4, %rax
        xorq	%r13, %rcx
        vpaddq	%ymm2, %ymm8, %ymm2
        xorq	%r11, %rax
        addq	%rcx, %r14
        vperm2I128	$0x81, %ymm1, %ymm1, %ymm14
        rorq	$14, %rax
        xorq	%r8, %rbx
        addq	%rax, %r14
        movq	%r15, %rcx
        andq	%rbx, %rdx
        rorq	$5, %rcx
        vpsrlq	$19, %ymm14, %ymm8
        xorq	%r15, %rcx
        xorq	%r8, %rdx
        vpsllq	$45, %ymm14, %ymm9
        rorq	$6, %rcx
        addq	%r14, %r10
        vpsrlq	$61, %ymm14, %ymm10
        xorq	%r15, %rcx
        addq	%rdx, %r14
        vpsllq	$3, %ymm14, %ymm11
        rorq	$28, %rcx
        movq	%r10, %rax
        addq	%rcx, %r14
        rorq	$23, %rax
        vpor	%ymm9, %ymm8, %ymm8
        movq	%r14, %rdx
        movq	%r11, %rcx
        addq	80(%rsp), %r13
        xorq	%r12, %rcx
        vpor	%ymm11, %ymm10, %ymm10
        xorq	%r10, %rax
        andq	%r10, %rcx
        vpxor	%ymm10, %ymm8, %ymm8
        rorq	$4, %rax
        xorq	%r12, %rcx
        vpsrlq	$6, %ymm14, %ymm11
        xorq	%r10, %rax
        addq	%rcx, %r13
        vpxor	%ymm11, %ymm8, %ymm8
        rorq	$14, %rax
        xorq	%r15, %rdx
        vpaddq	%ymm2, %ymm8, %ymm2
        addq	%rax, %r13
        movq	%r14, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        vperm2I128	$8, %ymm2, %ymm2, %ymm14
        xorq	%r14, %rcx
        xorq	%r15, %rbx
        rorq	$6, %rcx
        addq	%r13, %r9
        vpsrlq	$19, %ymm14, %ymm8
        xorq	%r14, %rcx
        addq	%rbx, %r13
        vpsllq	$45, %ymm14, %ymm9
        rorq	$28, %rcx
        movq	%r9, %rax
        addq	%rcx, %r13
        rorq	$23, %rax
        vpsrlq	$61, %ymm14, %ymm10
        movq	%r13, %rbx
        movq	%r10, %rcx
        addq	88(%rsp), %r12
        xorq	%r11, %rcx
        vpsllq	$3, %ymm14, %ymm11
        xorq	%r9, %rax
        andq	%r9, %rcx
        vpor	%ymm9, %ymm8, %ymm8
        rorq	$4, %rax
        xorq	%r11, %rcx
        vpor	%ymm11, %ymm10, %ymm10
        xorq	%r9, %rax
        addq	%rcx, %r12
        vpxor	%ymm10, %ymm8, %ymm8
        rorq	$14, %rax
        xorq	%r14, %rbx
        vpsrlq	$6, %ymm14, %ymm11
        addq	%rax, %r12
        movq	%r13, %rcx
        vpxor	%ymm11, %ymm8, %ymm8
        andq	%rbx, %rdx
        rorq	$5, %rcx
        vpaddq	%ymm2, %ymm8, %ymm2
        xorq	%r13, %rcx
        xorq	%r14, %rdx
        rorq	$6, %rcx
        addq	%r12, %r8
        xorq	%r13, %rcx
        addq	%rdx, %r12
        rorq	$28, %rcx
        movq	%r8, %rax
        addq	%rcx, %r12
        rorq	$23, %rax
        vpblendd	$3, %ymm0, %ymm3, %ymm12
        vpblendd	$3, %ymm2, %ymm1, %ymm13
        movq	%r12, %rdx
        movq	%r9, %rcx
        addq	96(%rsp), %r11
        xorq	%r10, %rcx
        xorq	%r8, %rax
        andq	%r8, %rcx
        vpermq	$57, %ymm12, %ymm12
        rorq	$4, %rax
        xorq	%r10, %rcx
        vpermq	$57, %ymm13, %ymm13
        xorq	%r8, %rax
        addq	%rcx, %r11
        rorq	$14, %rax
        xorq	%r13, %rdx
        vpsrlq	$0x01, %ymm12, %ymm8
        addq	%rax, %r11
        movq	%r12, %rcx
        vpsllq	$63, %ymm12, %ymm9
        andq	%rdx, %rbx
        rorq	$5, %rcx
        vpsrlq	$8, %ymm12, %ymm10
        xorq	%r12, %rcx
        xorq	%r13, %rbx
        vpsllq	$56, %ymm12, %ymm11
        rorq	$6, %rcx
        addq	%r11, %r15
        vpor	%ymm9, %ymm8, %ymm8
        xorq	%r12, %rcx
        addq	%rbx, %r11
        vpor	%ymm11, %ymm10, %ymm10
        rorq	$28, %rcx
        movq	%r15, %rax
        addq	%rcx, %r11
        rorq	$23, %rax
        vpsrlq	$7, %ymm12, %ymm11
        movq	%r11, %rbx
        movq	%r8, %rcx
        vpxor	%ymm10, %ymm8, %ymm8
        addq	104(%rsp), %r10
        xorq	%r9, %rcx
        vpxor	%ymm11, %ymm8, %ymm8
        xorq	%r15, %rax
        andq	%r15, %rcx
        vpaddq	%ymm3, %ymm13, %ymm3
        rorq	$4, %rax
        xorq	%r9, %rcx
        vpaddq	%ymm3, %ymm8, %ymm3
        xorq	%r15, %rax
        addq	%rcx, %r10
        vperm2I128	$0x81, %ymm2, %ymm2, %ymm14
        rorq	$14, %rax
        xorq	%r12, %rbx
        addq	%rax, %r10
        movq	%r11, %rcx
        andq	%rbx, %rdx
        rorq	$5, %rcx
        vpsrlq	$19, %ymm14, %ymm8
        xorq	%r11, %rcx
        xorq	%r12, %rdx
        vpsllq	$45, %ymm14, %ymm9
        rorq	$6, %rcx
        addq	%r10, %r14
        vpsrlq	$61, %ymm14, %ymm10
        xorq	%r11, %rcx
        addq	%rdx, %r10
        vpsllq	$3, %ymm14, %ymm11
        rorq	$28, %rcx
        movq	%r14, %rax
        addq	%rcx, %r10
        rorq	$23, %rax
        vpor	%ymm9, %ymm8, %ymm8
        movq	%r10, %rdx
        movq	%r15, %rcx
        addq	112(%rsp), %r9
        xorq	%r8, %rcx
        vpor	%ymm11, %ymm10, %ymm10
        xorq	%r14, %rax
        andq	%r14, %rcx
        vpxor	%ymm10, %ymm8, %ymm8
        rorq	$4, %rax
        xorq	%r8, %rcx
        vpsrlq	$6, %ymm14, %ymm11
        xorq	%r14, %rax
        addq	%rcx, %r9
        vpxor	%ymm11, %ymm8, %ymm8
        rorq	$14, %rax
        xorq	%r11, %rdx
        vpaddq	%ymm3, %ymm8, %ymm3
        addq	%rax, %r9
        movq	%r10, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        vperm2I128	$8, %ymm3, %ymm3, %ymm14
        xorq	%r10, %rcx
        xorq	%r11, %rbx
        rorq	$6, %rcx
        addq	%r9, %r13
        vpsrlq	$19, %ymm14, %ymm8
        xorq	%r10, %rcx
        addq	%rbx, %r9
        vpsllq	$45, %ymm14, %ymm9
        rorq	$28, %rcx
        movq	%r13, %rax
        addq	%rcx, %r9
        rorq	$23, %rax
        vpsrlq	$61, %ymm14, %ymm10
        movq	%r9, %rbx
        movq	%r14, %rcx
        addq	120(%rsp), %r8
        xorq	%r15, %rcx
        vpsllq	$3, %ymm14, %ymm11
        xorq	%r13, %rax
        andq	%r13, %rcx
        vpor	%ymm9, %ymm8, %ymm8
        rorq	$4, %rax
        xorq	%r15, %rcx
        vpor	%ymm11, %ymm10, %ymm10
        xorq	%r13, %rax
        addq	%rcx, %r8
        vpxor	%ymm10, %ymm8, %ymm8
        rorq	$14, %rax
        xorq	%r10, %rbx
        vpsrlq	$6, %ymm14, %ymm11
        addq	%rax, %r8
        movq	%r9, %rcx
        vpxor	%ymm11, %ymm8, %ymm8
        andq	%rbx, %rdx
        rorq	$5, %rcx
        vpaddq	%ymm3, %ymm8, %ymm3
        xorq	%r9, %rcx
        xorq	%r10, %rdx
        rorq	$6, %rcx
        addq	%r8, %r12
        xorq	%r9, %rcx
        addq	%rdx, %r8
        rorq	$28, %rcx
        movq	%r12, %rax
        addq	%rcx, %r8
        vpaddq	(%rsi), %ymm0, %ymm8
        vpaddq	32(%rsi), %ymm1, %ymm9
        vmovdqu	%ymm8, (%rsp)
        vmovdqu	%ymm9, 32(%rsp)
        vpaddq	64(%rsi), %ymm2, %ymm8
        vpaddq	96(%rsi), %ymm3, %ymm9
        vmovdqu	%ymm8, 64(%rsp)
        vmovdqu	%ymm9, 96(%rsp)
        subl	$0x01, 128(%rsp)
        jne	L_sha256_avx2_start
        rorq	$23, %rax
        movq	%r8, %rdx
        movq	%r13, %rcx
        addq	(%rsp), %r15
        xorq	%r14, %rcx
        xorq	%r12, %rax
        andq	%r12, %rcx
        rorq	$4, %rax
        xorq	%r14, %rcx
        xorq	%r12, %rax
        addq	%rcx, %r15
        rorq	$14, %rax
        xorq	%r9, %rdx
        addq	%rax, %r15
        movq	%r8, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        xorq	%r8, %rcx
        xorq	%r9, %rbx
        rorq	$6, %rcx
        addq	%r15, %r11
        xorq	%r8, %rcx
        addq	%rbx, %r15
        rorq	$28, %rcx
        movq	%r11, %rax
        addq	%rcx, %r15
        rorq	$23, %rax
        movq	%r15, %rbx
        movq	%r12, %rcx
        addq	8(%rsp), %r14
        xorq	%r13, %rcx
        xorq	%r11, %rax
        andq	%r11, %rcx
        rorq	$4, %rax
        xorq	%r13, %rcx
        xorq	%r11, %rax
        addq	%rcx, %r14
        rorq	$14, %rax
        xorq	%r8, %rbx
        addq	%rax, %r14
        movq	%r15, %rcx
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r15, %rcx
        xorq	%r8, %rdx
        rorq	$6, %rcx
        addq	%r14, %r10
        xorq	%r15, %rcx
        addq	%rdx, %r14
        rorq	$28, %rcx
        movq	%r10, %rax
        addq	%rcx, %r14
        rorq	$23, %rax
        movq	%r14, %rdx
        movq	%r11, %rcx
        addq	16(%rsp), %r13
        xorq	%r12, %rcx
        xorq	%r10, %rax
        andq	%r10, %rcx
        rorq	$4, %rax
        xorq	%r12, %rcx
        xorq	%r10, %rax
        addq	%rcx, %r13
        rorq	$14, %rax
        xorq	%r15, %rdx
        addq	%rax, %r13
        movq	%r14, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        xorq	%r14, %rcx
        xorq	%r15, %rbx
        rorq	$6, %rcx
        addq	%r13, %r9
        xorq	%r14, %rcx
        addq	%rbx, %r13
        rorq	$28, %rcx
        movq	%r9, %rax
        addq	%rcx, %r13
        rorq	$23, %rax
        movq	%r13, %rbx
        movq	%r10, %rcx
        addq	24(%rsp), %r12
        xorq	%r11, %rcx
        xorq	%r9, %rax
        andq	%r9, %rcx
        rorq	$4, %rax
        xorq	%r11, %rcx
        xorq	%r9, %rax
        addq	%rcx, %r12
        rorq	$14, %rax
        xorq	%r14, %rbx
        addq	%rax, %r12
        movq	%r13, %rcx
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r13, %rcx
        xorq	%r14, %rdx
        rorq	$6, %rcx
        addq	%r12, %r8
        xorq	%r13, %rcx
        addq	%rdx, %r12
        rorq	$28, %rcx
        movq	%r8, %rax
        addq	%rcx, %r12
        rorq	$23, %rax
        movq	%r12, %rdx
        movq	%r9, %rcx
        addq	32(%rsp), %r11
        xorq	%r10, %rcx
        xorq	%r8, %rax
        andq	%r8, %rcx
        rorq	$4, %rax
        xorq	%r10, %rcx
        xorq	%r8, %rax
        addq	%rcx, %r11
        rorq	$14, %rax
        xorq	%r13, %rdx
        addq	%rax, %r11
        movq	%r12, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        xorq	%r12, %rcx
        xorq	%r13, %rbx
        rorq	$6, %rcx
        addq	%r11, %r15
        xorq	%r12, %rcx
        addq	%rbx, %r11
        rorq	$28, %rcx
        movq	%r15, %rax
        addq	%rcx, %r11
        rorq	$23, %rax
        movq	%r11, %rbx
        movq	%r8, %rcx
        addq	40(%rsp), %r10
        xorq	%r9, %rcx
        xorq	%r15, %rax
        andq	%r15, %rcx
        rorq	$4, %rax
        xorq	%r9, %rcx
        xorq	%r15, %rax
        addq	%rcx, %r10
        rorq	$14, %rax
        xorq	%r12, %rbx
        addq	%rax, %r10
        movq	%r11, %rcx
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r11, %rcx
        xorq	%r12, %rdx
        rorq	$6, %rcx
        addq	%r10, %r14
        xorq	%r11, %rcx
        addq	%rdx, %r10
        rorq	$28, %rcx
        movq	%r14, %rax
        addq	%rcx, %r10
        rorq	$23, %rax
        movq	%r10, %rdx
        movq	%r15, %rcx
        addq	48(%rsp), %r9
        xorq	%r8, %rcx
        xorq	%r14, %rax
        andq	%r14, %rcx
        rorq	$4, %rax
        xorq	%r8, %rcx
        xorq	%r14, %rax
        addq	%rcx, %r9
        rorq	$14, %rax
        xorq	%r11, %rdx
        addq	%rax, %r9
        movq	%r10, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        xorq	%r10, %rcx
        xorq	%r11, %rbx
        rorq	$6, %rcx
        addq	%r9, %r13
        xorq	%r10, %rcx
        addq	%rbx, %r9
        rorq	$28, %rcx
        movq	%r13, %rax
        addq	%rcx, %r9
        rorq	$23, %rax
        movq	%r9, %rbx
        movq	%r14, %rcx
        addq	56(%rsp), %r8
        xorq	%r15, %rcx
        xorq	%r13, %rax
        andq	%r13, %rcx
        rorq	$4, %rax
        xorq	%r15, %rcx
        xorq	%r13, %rax
        addq	%rcx, %r8
        rorq	$14, %rax
        xorq	%r10, %rbx
        addq	%rax, %r8
        movq	%r9, %rcx
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r9, %rcx
        xorq	%r10, %rdx
        rorq	$6, %rcx
        addq	%r8, %r12
        xorq	%r9, %rcx
        addq	%rdx, %r8
        rorq	$28, %rcx
        movq	%r12, %rax
        addq	%rcx, %r8
        rorq	$23, %rax
        movq	%r8, %rdx
        movq	%r13, %rcx
        addq	64(%rsp), %r15
        xorq	%r14, %rcx
        xorq	%r12, %rax
        andq	%r12, %rcx
        rorq	$4, %rax
        xorq	%r14, %rcx
        xorq	%r12, %rax
        addq	%rcx, %r15
        rorq	$14, %rax
        xorq	%r9, %rdx
        addq	%rax, %r15
        movq	%r8, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        xorq	%r8, %rcx
        xorq	%r9, %rbx
        rorq	$6, %rcx
        addq	%r15, %r11
        xorq	%r8, %rcx
        addq	%rbx, %r15
        rorq	$28, %rcx
        movq	%r11, %rax
        addq	%rcx, %r15
        rorq	$23, %rax
        movq	%r15, %rbx
        movq	%r12, %rcx
        addq	72(%rsp), %r14
        xorq	%r13, %rcx
        xorq	%r11, %rax
        andq	%r11, %rcx
        rorq	$4, %rax
        xorq	%r13, %rcx
        xorq	%r11, %rax
        addq	%rcx, %r14
        rorq	$14, %rax
        xorq	%r8, %rbx
        addq	%rax, %r14
        movq	%r15, %rcx
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r15, %rcx
        xorq	%r8, %rdx
        rorq	$6, %rcx
        addq	%r14, %r10
        xorq	%r15, %rcx
        addq	%rdx, %r14
        rorq	$28, %rcx
        movq	%r10, %rax
        addq	%rcx, %r14
        rorq	$23, %rax
        movq	%r14, %rdx
        movq	%r11, %rcx
        addq	80(%rsp), %r13
        xorq	%r12, %rcx
        xorq	%r10, %rax
        andq	%r10, %rcx
        rorq	$4, %rax
        xorq	%r12, %rcx
        xorq	%r10, %rax
        addq	%rcx, %r13
        rorq	$14, %rax
        xorq	%r15, %rdx
        addq	%rax, %r13
        movq	%r14, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        xorq	%r14, %rcx
        xorq	%r15, %rbx
        rorq	$6, %rcx
        addq	%r13, %r9
        xorq	%r14, %rcx
        addq	%rbx, %r13
        rorq	$28, %rcx
        movq	%r9, %rax
        addq	%rcx, %r13
        rorq	$23, %rax
        movq	%r13, %rbx
        movq	%r10, %rcx
        addq	88(%rsp), %r12
        xorq	%r11, %rcx
        xorq	%r9, %rax
        andq	%r9, %rcx
        rorq	$4, %rax
        xorq	%r11, %rcx
        xorq	%r9, %rax
        addq	%rcx, %r12
        rorq	$14, %rax
        xorq	%r14, %rbx
        addq	%rax, %r12
        movq	%r13, %rcx
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r13, %rcx
        xorq	%r14, %rdx
        rorq	$6, %rcx
        addq	%r12, %r8
        xorq	%r13, %rcx
        addq	%rdx, %r12
        rorq	$28, %rcx
        movq	%r8, %rax
        addq	%rcx, %r12
        rorq	$23, %rax
        movq	%r12, %rdx
        movq	%r9, %rcx
        addq	96(%rsp), %r11
        xorq	%r10, %rcx
        xorq	%r8, %rax
        andq	%r8, %rcx
        rorq	$4, %rax
        xorq	%r10, %rcx
        xorq	%r8, %rax
        addq	%rcx, %r11
        rorq	$14, %rax
        xorq	%r13, %rdx
        addq	%rax, %r11
        movq	%r12, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        xorq	%r12, %rcx
        xorq	%r13, %rbx
        rorq	$6, %rcx
        addq	%r11, %r15
        xorq	%r12, %rcx
        addq	%rbx, %r11
        rorq	$28, %rcx
        movq	%r15, %rax
        addq	%rcx, %r11
        rorq	$23, %rax
        movq	%r11, %rbx
        movq	%r8, %rcx
        addq	104(%rsp), %r10
        xorq	%r9, %rcx
        xorq	%r15, %rax
        andq	%r15, %rcx
        rorq	$4, %rax
        xorq	%r9, %rcx
        xorq	%r15, %rax
        addq	%rcx, %r10
        rorq	$14, %rax
        xorq	%r12, %rbx
        addq	%rax, %r10
        movq	%r11, %rcx
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r11, %rcx
        xorq	%r12, %rdx
        rorq	$6, %rcx
        addq	%r10, %r14
        xorq	%r11, %rcx
        addq	%rdx, %r10
        rorq	$28, %rcx
        movq	%r14, %rax
        addq	%rcx, %r10
        rorq	$23, %rax
        movq	%r10, %rdx
        movq	%r15, %rcx
        addq	112(%rsp), %r9
        xorq	%r8, %rcx
        xorq	%r14, %rax
        andq	%r14, %rcx
        rorq	$4, %rax
        xorq	%r8, %rcx
        xorq	%r14, %rax
        addq	%rcx, %r9
        rorq	$14, %rax
        xorq	%r11, %rdx
        addq	%rax, %r9
        movq	%r10, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        xorq	%r10, %rcx
        xorq	%r11, %rbx
        rorq	$6, %rcx
        addq	%r9, %r13
        xorq	%r10, %rcx
        addq	%rbx, %r9
        rorq	$28, %rcx
        movq	%r13, %rax
        addq	%rcx, %r9
        rorq	$23, %rax
        movq	%r9, %rbx
        movq	%r14, %rcx
        addq	120(%rsp), %r8
        xorq	%r15, %rcx
        xorq	%r13, %rax
        andq	%r13, %rcx
        rorq	$4, %rax
        xorq	%r15, %rcx
        xorq	%r13, %rax
        addq	%rcx, %r8
        rorq	$14, %rax
        xorq	%r10, %rbx
        addq	%rax, %r8
        movq	%r9, %rcx
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r9, %rcx
        xorq	%r10, %rdx
        rorq	$6, %rcx
        addq	%r8, %r12
        xorq	%r9, %rcx
        addq	%rdx, %r8
        rorq	$28, %rcx
        movq	%r12, %rax
        addq	%rcx, %r8
        addq	%r8, (%rdi)
        addq	%r9, 8(%rdi)
        addq	%r10, 16(%rdi)
        addq	%r11, 24(%rdi)
        addq	%r12, 32(%rdi)
        addq	%r13, 40(%rdi)
        addq	%r14, 48(%rdi)
        addq	%r15, 56(%rdi)
        xorq	%rax, %rax
        vzeroupper
        addq	$0x90, %rsp
        popq	%r15
        popq	%r14
        popq	%r13
        popq	%r12
        popq	%rbx
        repz retq
#ifndef __APPLE__
.size	Transform_Sha512_AVX2,.-Transform_Sha512_AVX2
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	Transform_Sha512_AVX2_Len
WC_ASM_ATT_HIDDEN(Transform_Sha512_AVX2_Len)
.type	Transform_Sha512_AVX2_Len,@function
.align	16
Transform_Sha512_AVX2_Len:
#else
.section	__TEXT,__text
.globl	_Transform_Sha512_AVX2_Len
WC_ASM_ATT_HIDDEN(_Transform_Sha512_AVX2_Len)
.p2align	4
_Transform_Sha512_AVX2_Len:
#endif /* __APPLE__ */
        pushq	%rbx
        pushq	%r12
        pushq	%r13
        pushq	%r14
        pushq	%r15
        pushq	%rbp
        movq	%rsi, %rbp
        testb	$0x80, %bpl
        je	L_sha512_len_avx2_block
        movq	224(%rdi), %rbx
        vmovdqu	(%rbx), %ymm0
        vmovdqu	32(%rbx), %ymm1
        vmovdqu	64(%rbx), %ymm2
        vmovdqu	96(%rbx), %ymm3
        vmovups	%ymm0, 64(%rdi)
        vmovups	%ymm1, 96(%rdi)
        vmovups	%ymm2, 128(%rdi)
        vmovups	%ymm3, 160(%rdi)
        subq	$8, %rsp
#ifndef __APPLE__
        call	Transform_Sha512_AVX2@plt
#else
        call	_Transform_Sha512_AVX2
#endif /* __APPLE__ */
        addq	$8, %rsp
        addq	$0x80, 224(%rdi)
        subl	$0x80, %ebp
        jz	L_sha512_len_avx2_done
L_sha512_len_avx2_block:
        subq	$0x548, %rsp
        movq	224(%rdi), %rcx
        vmovdqa	L_avx2_sha512_flip_mask(%rip), %ymm15
        movq	(%rdi), %r8
        movq	8(%rdi), %r9
        movq	16(%rdi), %r10
        movq	24(%rdi), %r11
        movq	32(%rdi), %r12
        movq	40(%rdi), %r13
        movq	48(%rdi), %r14
        movq	56(%rdi), %r15
        movq	%rbp, 1344(%rsp)
        # Start of loop processing two blocks
L_sha512_len_avx2_begin:
        movq	%rsp, %rbp
        leaq	L_avx2_sha512_k_2(%rip), %rsi
        movq	%r9, %rbx
        movq	%r12, %rax
        vmovdqu	(%rcx), %xmm0
        vmovdqu	16(%rcx), %xmm1
        vinserti128	$0x01, 128(%rcx), %ymm0, %ymm0
        vinserti128	$0x01, 144(%rcx), %ymm1, %ymm1
        vpshufb	%ymm15, %ymm0, %ymm0
        vpshufb	%ymm15, %ymm1, %ymm1
        vmovdqu	32(%rcx), %xmm2
        vmovdqu	48(%rcx), %xmm3
        vinserti128	$0x01, 160(%rcx), %ymm2, %ymm2
        vinserti128	$0x01, 176(%rcx), %ymm3, %ymm3
        vpshufb	%ymm15, %ymm2, %ymm2
        vpshufb	%ymm15, %ymm3, %ymm3
        vmovdqu	64(%rcx), %xmm4
        vmovdqu	80(%rcx), %xmm5
        vinserti128	$0x01, 192(%rcx), %ymm4, %ymm4
        vinserti128	$0x01, 208(%rcx), %ymm5, %ymm5
        vpshufb	%ymm15, %ymm4, %ymm4
        vpshufb	%ymm15, %ymm5, %ymm5
        vmovdqu	96(%rcx), %xmm6
        vmovdqu	112(%rcx), %xmm7
        vinserti128	$0x01, 224(%rcx), %ymm6, %ymm6
        vinserti128	$0x01, 240(%rcx), %ymm7, %ymm7
        vpshufb	%ymm15, %ymm6, %ymm6
        vpshufb	%ymm15, %ymm7, %ymm7
        xorq	%r10, %rbx
        # Start of 16 rounds
L_sha512_len_avx2_start:
        vpaddq	(%rsi), %ymm0, %ymm8
        vpaddq	32(%rsi), %ymm1, %ymm9
        vmovdqu	%ymm8, (%rbp)
        vmovdqu	%ymm9, 32(%rbp)
        vpaddq	64(%rsi), %ymm2, %ymm8
        vpaddq	96(%rsi), %ymm3, %ymm9
        vmovdqu	%ymm8, 64(%rbp)
        vmovdqu	%ymm9, 96(%rbp)
        vpaddq	128(%rsi), %ymm4, %ymm8
        vpaddq	160(%rsi), %ymm5, %ymm9
        vmovdqu	%ymm8, 128(%rbp)
        vmovdqu	%ymm9, 160(%rbp)
        vpaddq	192(%rsi), %ymm6, %ymm8
        vpaddq	224(%rsi), %ymm7, %ymm9
        vmovdqu	%ymm8, 192(%rbp)
        vmovdqu	%ymm9, 224(%rbp)
        # msg_sched: 0-1
        rorq	$23, %rax
        vpalignr	$8, %ymm0, %ymm1, %ymm12
        vpalignr	$8, %ymm4, %ymm5, %ymm13
        movq	%r8, %rdx
        movq	%r13, %rcx
        addq	(%rbp), %r15
        xorq	%r14, %rcx
        vpsrlq	$0x01, %ymm12, %ymm8
        vpsllq	$63, %ymm12, %ymm9
        xorq	%r12, %rax
        andq	%r12, %rcx
        rorq	$4, %rax
        xorq	%r14, %rcx
        vpsrlq	$8, %ymm12, %ymm10
        vpsllq	$56, %ymm12, %ymm11
        xorq	%r12, %rax
        addq	%rcx, %r15
        rorq	$14, %rax
        xorq	%r9, %rdx
        vpor	%ymm9, %ymm8, %ymm8
        vpor	%ymm11, %ymm10, %ymm10
        addq	%rax, %r15
        movq	%r8, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        vpsrlq	$7, %ymm12, %ymm11
        vpxor	%ymm10, %ymm8, %ymm8
        xorq	%r8, %rcx
        xorq	%r9, %rbx
        rorq	$6, %rcx
        addq	%r15, %r11
        vpxor	%ymm11, %ymm8, %ymm8
        vpaddq	%ymm0, %ymm13, %ymm0
        xorq	%r8, %rcx
        addq	%rbx, %r15
        rorq	$28, %rcx
        movq	%r11, %rax
        addq	%rcx, %r15
        rorq	$23, %rax
        vpaddq	%ymm0, %ymm8, %ymm0
        movq	%r15, %rbx
        movq	%r12, %rcx
        addq	8(%rbp), %r14
        xorq	%r13, %rcx
        vpsrlq	$19, %ymm7, %ymm8
        vpsllq	$45, %ymm7, %ymm9
        xorq	%r11, %rax
        andq	%r11, %rcx
        rorq	$4, %rax
        xorq	%r13, %rcx
        vpsrlq	$61, %ymm7, %ymm10
        vpsllq	$3, %ymm7, %ymm11
        xorq	%r11, %rax
        addq	%rcx, %r14
        rorq	$14, %rax
        xorq	%r8, %rbx
        addq	%rax, %r14
        movq	%r15, %rcx
        vpor	%ymm9, %ymm8, %ymm8
        vpor	%ymm11, %ymm10, %ymm10
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r15, %rcx
        xorq	%r8, %rdx
        vpxor	%ymm10, %ymm8, %ymm8
        vpsrlq	$6, %ymm7, %ymm11
        rorq	$6, %rcx
        addq	%r14, %r10
        xorq	%r15, %rcx
        addq	%rdx, %r14
        vpxor	%ymm11, %ymm8, %ymm8
        rorq	$28, %rcx
        movq	%r10, %rax
        addq	%rcx, %r14
        vpaddq	%ymm0, %ymm8, %ymm0
        # msg_sched done: 0-1
        # msg_sched: 4-5
        rorq	$23, %rax
        vpalignr	$8, %ymm1, %ymm2, %ymm12
        vpalignr	$8, %ymm5, %ymm6, %ymm13
        movq	%r14, %rdx
        movq	%r11, %rcx
        addq	32(%rbp), %r13
        xorq	%r12, %rcx
        vpsrlq	$0x01, %ymm12, %ymm8
        vpsllq	$63, %ymm12, %ymm9
        xorq	%r10, %rax
        andq	%r10, %rcx
        rorq	$4, %rax
        xorq	%r12, %rcx
        vpsrlq	$8, %ymm12, %ymm10
        vpsllq	$56, %ymm12, %ymm11
        xorq	%r10, %rax
        addq	%rcx, %r13
        rorq	$14, %rax
        xorq	%r15, %rdx
        vpor	%ymm9, %ymm8, %ymm8
        vpor	%ymm11, %ymm10, %ymm10
        addq	%rax, %r13
        movq	%r14, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        vpsrlq	$7, %ymm12, %ymm11
        vpxor	%ymm10, %ymm8, %ymm8
        xorq	%r14, %rcx
        xorq	%r15, %rbx
        rorq	$6, %rcx
        addq	%r13, %r9
        vpxor	%ymm11, %ymm8, %ymm8
        vpaddq	%ymm1, %ymm13, %ymm1
        xorq	%r14, %rcx
        addq	%rbx, %r13
        rorq	$28, %rcx
        movq	%r9, %rax
        addq	%rcx, %r13
        rorq	$23, %rax
        vpaddq	%ymm1, %ymm8, %ymm1
        movq	%r13, %rbx
        movq	%r10, %rcx
        addq	40(%rbp), %r12
        xorq	%r11, %rcx
        vpsrlq	$19, %ymm0, %ymm8
        vpsllq	$45, %ymm0, %ymm9
        xorq	%r9, %rax
        andq	%r9, %rcx
        rorq	$4, %rax
        xorq	%r11, %rcx
        vpsrlq	$61, %ymm0, %ymm10
        vpsllq	$3, %ymm0, %ymm11
        xorq	%r9, %rax
        addq	%rcx, %r12
        rorq	$14, %rax
        xorq	%r14, %rbx
        addq	%rax, %r12
        movq	%r13, %rcx
        vpor	%ymm9, %ymm8, %ymm8
        vpor	%ymm11, %ymm10, %ymm10
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r13, %rcx
        xorq	%r14, %rdx
        vpxor	%ymm10, %ymm8, %ymm8
        vpsrlq	$6, %ymm0, %ymm11
        rorq	$6, %rcx
        addq	%r12, %r8
        xorq	%r13, %rcx
        addq	%rdx, %r12
        vpxor	%ymm11, %ymm8, %ymm8
        rorq	$28, %rcx
        movq	%r8, %rax
        addq	%rcx, %r12
        vpaddq	%ymm1, %ymm8, %ymm1
        # msg_sched done: 4-5
        # msg_sched: 8-9
        rorq	$23, %rax
        vpalignr	$8, %ymm2, %ymm3, %ymm12
        vpalignr	$8, %ymm6, %ymm7, %ymm13
        movq	%r12, %rdx
        movq	%r9, %rcx
        addq	64(%rbp), %r11
        xorq	%r10, %rcx
        vpsrlq	$0x01, %ymm12, %ymm8
        vpsllq	$63, %ymm12, %ymm9
        xorq	%r8, %rax
        andq	%r8, %rcx
        rorq	$4, %rax
        xorq	%r10, %rcx
        vpsrlq	$8, %ymm12, %ymm10
        vpsllq	$56, %ymm12, %ymm11
        xorq	%r8, %rax
        addq	%rcx, %r11
        rorq	$14, %rax
        xorq	%r13, %rdx
        vpor	%ymm9, %ymm8, %ymm8
        vpor	%ymm11, %ymm10, %ymm10
        addq	%rax, %r11
        movq	%r12, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        vpsrlq	$7, %ymm12, %ymm11
        vpxor	%ymm10, %ymm8, %ymm8
        xorq	%r12, %rcx
        xorq	%r13, %rbx
        rorq	$6, %rcx
        addq	%r11, %r15
        vpxor	%ymm11, %ymm8, %ymm8
        vpaddq	%ymm2, %ymm13, %ymm2
        xorq	%r12, %rcx
        addq	%rbx, %r11
        rorq	$28, %rcx
        movq	%r15, %rax
        addq	%rcx, %r11
        rorq	$23, %rax
        vpaddq	%ymm2, %ymm8, %ymm2
        movq	%r11, %rbx
        movq	%r8, %rcx
        addq	72(%rbp), %r10
        xorq	%r9, %rcx
        vpsrlq	$19, %ymm1, %ymm8
        vpsllq	$45, %ymm1, %ymm9
        xorq	%r15, %rax
        andq	%r15, %rcx
        rorq	$4, %rax
        xorq	%r9, %rcx
        vpsrlq	$61, %ymm1, %ymm10
        vpsllq	$3, %ymm1, %ymm11
        xorq	%r15, %rax
        addq	%rcx, %r10
        rorq	$14, %rax
        xorq	%r12, %rbx
        addq	%rax, %r10
        movq	%r11, %rcx
        vpor	%ymm9, %ymm8, %ymm8
        vpor	%ymm11, %ymm10, %ymm10
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r11, %rcx
        xorq	%r12, %rdx
        vpxor	%ymm10, %ymm8, %ymm8
        vpsrlq	$6, %ymm1, %ymm11
        rorq	$6, %rcx
        addq	%r10, %r14
        xorq	%r11, %rcx
        addq	%rdx, %r10
        vpxor	%ymm11, %ymm8, %ymm8
        rorq	$28, %rcx
        movq	%r14, %rax
        addq	%rcx, %r10
        vpaddq	%ymm2, %ymm8, %ymm2
        # msg_sched done: 8-9
        # msg_sched: 12-13
        rorq	$23, %rax
        vpalignr	$8, %ymm3, %ymm4, %ymm12
        vpalignr	$8, %ymm7, %ymm0, %ymm13
        movq	%r10, %rdx
        movq	%r15, %rcx
        addq	96(%rbp), %r9
        xorq	%r8, %rcx
        vpsrlq	$0x01, %ymm12, %ymm8
        vpsllq	$63, %ymm12, %ymm9
        xorq	%r14, %rax
        andq	%r14, %rcx
        rorq	$4, %rax
        xorq	%r8, %rcx
        vpsrlq	$8, %ymm12, %ymm10
        vpsllq	$56, %ymm12, %ymm11
        xorq	%r14, %rax
        addq	%rcx, %r9
        rorq	$14, %rax
        xorq	%r11, %rdx
        vpor	%ymm9, %ymm8, %ymm8
        vpor	%ymm11, %ymm10, %ymm10
        addq	%rax, %r9
        movq	%r10, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        vpsrlq	$7, %ymm12, %ymm11
        vpxor	%ymm10, %ymm8, %ymm8
        xorq	%r10, %rcx
        xorq	%r11, %rbx
        rorq	$6, %rcx
        addq	%r9, %r13
        vpxor	%ymm11, %ymm8, %ymm8
        vpaddq	%ymm3, %ymm13, %ymm3
        xorq	%r10, %rcx
        addq	%rbx, %r9
        rorq	$28, %rcx
        movq	%r13, %rax
        addq	%rcx, %r9
        rorq	$23, %rax
        vpaddq	%ymm3, %ymm8, %ymm3
        movq	%r9, %rbx
        movq	%r14, %rcx
        addq	104(%rbp), %r8
        xorq	%r15, %rcx
        vpsrlq	$19, %ymm2, %ymm8
        vpsllq	$45, %ymm2, %ymm9
        xorq	%r13, %rax
        andq	%r13, %rcx
        rorq	$4, %rax
        xorq	%r15, %rcx
        vpsrlq	$61, %ymm2, %ymm10
        vpsllq	$3, %ymm2, %ymm11
        xorq	%r13, %rax
        addq	%rcx, %r8
        rorq	$14, %rax
        xorq	%r10, %rbx
        addq	%rax, %r8
        movq	%r9, %rcx
        vpor	%ymm9, %ymm8, %ymm8
        vpor	%ymm11, %ymm10, %ymm10
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r9, %rcx
        xorq	%r10, %rdx
        vpxor	%ymm10, %ymm8, %ymm8
        vpsrlq	$6, %ymm2, %ymm11
        rorq	$6, %rcx
        addq	%r8, %r12
        xorq	%r9, %rcx
        addq	%rdx, %r8
        vpxor	%ymm11, %ymm8, %ymm8
        rorq	$28, %rcx
        movq	%r12, %rax
        addq	%rcx, %r8
        vpaddq	%ymm3, %ymm8, %ymm3
        # msg_sched done: 12-13
        # msg_sched: 16-17
        rorq	$23, %rax
        vpalignr	$8, %ymm4, %ymm5, %ymm12
        vpalignr	$8, %ymm0, %ymm1, %ymm13
        movq	%r8, %rdx
        movq	%r13, %rcx
        addq	128(%rbp), %r15
        xorq	%r14, %rcx
        vpsrlq	$0x01, %ymm12, %ymm8
        vpsllq	$63, %ymm12, %ymm9
        xorq	%r12, %rax
        andq	%r12, %rcx
        rorq	$4, %rax
        xorq	%r14, %rcx
        vpsrlq	$8, %ymm12, %ymm10
        vpsllq	$56, %ymm12, %ymm11
        xorq	%r12, %rax
        addq	%rcx, %r15
        rorq	$14, %rax
        xorq	%r9, %rdx
        vpor	%ymm9, %ymm8, %ymm8
        vpor	%ymm11, %ymm10, %ymm10
        addq	%rax, %r15
        movq	%r8, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        vpsrlq	$7, %ymm12, %ymm11
        vpxor	%ymm10, %ymm8, %ymm8
        xorq	%r8, %rcx
        xorq	%r9, %rbx
        rorq	$6, %rcx
        addq	%r15, %r11
        vpxor	%ymm11, %ymm8, %ymm8
        vpaddq	%ymm4, %ymm13, %ymm4
        xorq	%r8, %rcx
        addq	%rbx, %r15
        rorq	$28, %rcx
        movq	%r11, %rax
        addq	%rcx, %r15
        rorq	$23, %rax
        vpaddq	%ymm4, %ymm8, %ymm4
        movq	%r15, %rbx
        movq	%r12, %rcx
        addq	136(%rbp), %r14
        xorq	%r13, %rcx
        vpsrlq	$19, %ymm3, %ymm8
        vpsllq	$45, %ymm3, %ymm9
        xorq	%r11, %rax
        andq	%r11, %rcx
        rorq	$4, %rax
        xorq	%r13, %rcx
        vpsrlq	$61, %ymm3, %ymm10
        vpsllq	$3, %ymm3, %ymm11
        xorq	%r11, %rax
        addq	%rcx, %r14
        rorq	$14, %rax
        xorq	%r8, %rbx
        addq	%rax, %r14
        movq	%r15, %rcx
        vpor	%ymm9, %ymm8, %ymm8
        vpor	%ymm11, %ymm10, %ymm10
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r15, %rcx
        xorq	%r8, %rdx
        vpxor	%ymm10, %ymm8, %ymm8
        vpsrlq	$6, %ymm3, %ymm11
        rorq	$6, %rcx
        addq	%r14, %r10
        xorq	%r15, %rcx
        addq	%rdx, %r14
        vpxor	%ymm11, %ymm8, %ymm8
        rorq	$28, %rcx
        movq	%r10, %rax
        addq	%rcx, %r14
        vpaddq	%ymm4, %ymm8, %ymm4
        # msg_sched done: 16-17
        # msg_sched: 20-21
        rorq	$23, %rax
        vpalignr	$8, %ymm5, %ymm6, %ymm12
        vpalignr	$8, %ymm1, %ymm2, %ymm13
        movq	%r14, %rdx
        movq	%r11, %rcx
        addq	160(%rbp), %r13
        xorq	%r12, %rcx
        vpsrlq	$0x01, %ymm12, %ymm8
        vpsllq	$63, %ymm12, %ymm9
        xorq	%r10, %rax
        andq	%r10, %rcx
        rorq	$4, %rax
        xorq	%r12, %rcx
        vpsrlq	$8, %ymm12, %ymm10
        vpsllq	$56, %ymm12, %ymm11
        xorq	%r10, %rax
        addq	%rcx, %r13
        rorq	$14, %rax
        xorq	%r15, %rdx
        vpor	%ymm9, %ymm8, %ymm8
        vpor	%ymm11, %ymm10, %ymm10
        addq	%rax, %r13
        movq	%r14, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        vpsrlq	$7, %ymm12, %ymm11
        vpxor	%ymm10, %ymm8, %ymm8
        xorq	%r14, %rcx
        xorq	%r15, %rbx
        rorq	$6, %rcx
        addq	%r13, %r9
        vpxor	%ymm11, %ymm8, %ymm8
        vpaddq	%ymm5, %ymm13, %ymm5
        xorq	%r14, %rcx
        addq	%rbx, %r13
        rorq	$28, %rcx
        movq	%r9, %rax
        addq	%rcx, %r13
        rorq	$23, %rax
        vpaddq	%ymm5, %ymm8, %ymm5
        movq	%r13, %rbx
        movq	%r10, %rcx
        addq	168(%rbp), %r12
        xorq	%r11, %rcx
        vpsrlq	$19, %ymm4, %ymm8
        vpsllq	$45, %ymm4, %ymm9
        xorq	%r9, %rax
        andq	%r9, %rcx
        rorq	$4, %rax
        xorq	%r11, %rcx
        vpsrlq	$61, %ymm4, %ymm10
        vpsllq	$3, %ymm4, %ymm11
        xorq	%r9, %rax
        addq	%rcx, %r12
        rorq	$14, %rax
        xorq	%r14, %rbx
        addq	%rax, %r12
        movq	%r13, %rcx
        vpor	%ymm9, %ymm8, %ymm8
        vpor	%ymm11, %ymm10, %ymm10
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r13, %rcx
        xorq	%r14, %rdx
        vpxor	%ymm10, %ymm8, %ymm8
        vpsrlq	$6, %ymm4, %ymm11
        rorq	$6, %rcx
        addq	%r12, %r8
        xorq	%r13, %rcx
        addq	%rdx, %r12
        vpxor	%ymm11, %ymm8, %ymm8
        rorq	$28, %rcx
        movq	%r8, %rax
        addq	%rcx, %r12
        vpaddq	%ymm5, %ymm8, %ymm5
        # msg_sched done: 20-21
        # msg_sched: 24-25
        rorq	$23, %rax
        vpalignr	$8, %ymm6, %ymm7, %ymm12
        vpalignr	$8, %ymm2, %ymm3, %ymm13
        movq	%r12, %rdx
        movq	%r9, %rcx
        addq	192(%rbp), %r11
        xorq	%r10, %rcx
        vpsrlq	$0x01, %ymm12, %ymm8
        vpsllq	$63, %ymm12, %ymm9
        xorq	%r8, %rax
        andq	%r8, %rcx
        rorq	$4, %rax
        xorq	%r10, %rcx
        vpsrlq	$8, %ymm12, %ymm10
        vpsllq	$56, %ymm12, %ymm11
        xorq	%r8, %rax
        addq	%rcx, %r11
        rorq	$14, %rax
        xorq	%r13, %rdx
        vpor	%ymm9, %ymm8, %ymm8
        vpor	%ymm11, %ymm10, %ymm10
        addq	%rax, %r11
        movq	%r12, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        vpsrlq	$7, %ymm12, %ymm11
        vpxor	%ymm10, %ymm8, %ymm8
        xorq	%r12, %rcx
        xorq	%r13, %rbx
        rorq	$6, %rcx
        addq	%r11, %r15
        vpxor	%ymm11, %ymm8, %ymm8
        vpaddq	%ymm6, %ymm13, %ymm6
        xorq	%r12, %rcx
        addq	%rbx, %r11
        rorq	$28, %rcx
        movq	%r15, %rax
        addq	%rcx, %r11
        rorq	$23, %rax
        vpaddq	%ymm6, %ymm8, %ymm6
        movq	%r11, %rbx
        movq	%r8, %rcx
        addq	200(%rbp), %r10
        xorq	%r9, %rcx
        vpsrlq	$19, %ymm5, %ymm8
        vpsllq	$45, %ymm5, %ymm9
        xorq	%r15, %rax
        andq	%r15, %rcx
        rorq	$4, %rax
        xorq	%r9, %rcx
        vpsrlq	$61, %ymm5, %ymm10
        vpsllq	$3, %ymm5, %ymm11
        xorq	%r15, %rax
        addq	%rcx, %r10
        rorq	$14, %rax
        xorq	%r12, %rbx
        addq	%rax, %r10
        movq	%r11, %rcx
        vpor	%ymm9, %ymm8, %ymm8
        vpor	%ymm11, %ymm10, %ymm10
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r11, %rcx
        xorq	%r12, %rdx
        vpxor	%ymm10, %ymm8, %ymm8
        vpsrlq	$6, %ymm5, %ymm11
        rorq	$6, %rcx
        addq	%r10, %r14
        xorq	%r11, %rcx
        addq	%rdx, %r10
        vpxor	%ymm11, %ymm8, %ymm8
        rorq	$28, %rcx
        movq	%r14, %rax
        addq	%rcx, %r10
        vpaddq	%ymm6, %ymm8, %ymm6
        # msg_sched done: 24-25
        # msg_sched: 28-29
        rorq	$23, %rax
        vpalignr	$8, %ymm7, %ymm0, %ymm12
        vpalignr	$8, %ymm3, %ymm4, %ymm13
        movq	%r10, %rdx
        movq	%r15, %rcx
        addq	224(%rbp), %r9
        xorq	%r8, %rcx
        vpsrlq	$0x01, %ymm12, %ymm8
        vpsllq	$63, %ymm12, %ymm9
        xorq	%r14, %rax
        andq	%r14, %rcx
        rorq	$4, %rax
        xorq	%r8, %rcx
        vpsrlq	$8, %ymm12, %ymm10
        vpsllq	$56, %ymm12, %ymm11
        xorq	%r14, %rax
        addq	%rcx, %r9
        rorq	$14, %rax
        xorq	%r11, %rdx
        vpor	%ymm9, %ymm8, %ymm8
        vpor	%ymm11, %ymm10, %ymm10
        addq	%rax, %r9
        movq	%r10, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        vpsrlq	$7, %ymm12, %ymm11
        vpxor	%ymm10, %ymm8, %ymm8
        xorq	%r10, %rcx
        xorq	%r11, %rbx
        rorq	$6, %rcx
        addq	%r9, %r13
        vpxor	%ymm11, %ymm8, %ymm8
        vpaddq	%ymm7, %ymm13, %ymm7
        xorq	%r10, %rcx
        addq	%rbx, %r9
        rorq	$28, %rcx
        movq	%r13, %rax
        addq	%rcx, %r9
        rorq	$23, %rax
        vpaddq	%ymm7, %ymm8, %ymm7
        movq	%r9, %rbx
        movq	%r14, %rcx
        addq	232(%rbp), %r8
        xorq	%r15, %rcx
        vpsrlq	$19, %ymm6, %ymm8
        vpsllq	$45, %ymm6, %ymm9
        xorq	%r13, %rax
        andq	%r13, %rcx
        rorq	$4, %rax
        xorq	%r15, %rcx
        vpsrlq	$61, %ymm6, %ymm10
        vpsllq	$3, %ymm6, %ymm11
        xorq	%r13, %rax
        addq	%rcx, %r8
        rorq	$14, %rax
        xorq	%r10, %rbx
        addq	%rax, %r8
        movq	%r9, %rcx
        vpor	%ymm9, %ymm8, %ymm8
        vpor	%ymm11, %ymm10, %ymm10
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r9, %rcx
        xorq	%r10, %rdx
        vpxor	%ymm10, %ymm8, %ymm8
        vpsrlq	$6, %ymm6, %ymm11
        rorq	$6, %rcx
        addq	%r8, %r12
        xorq	%r9, %rcx
        addq	%rdx, %r8
        vpxor	%ymm11, %ymm8, %ymm8
        rorq	$28, %rcx
        movq	%r12, %rax
        addq	%rcx, %r8
        vpaddq	%ymm7, %ymm8, %ymm7
        # msg_sched done: 28-29
        addq	$0x100, %rsi
        addq	$0x100, %rbp
        cmpq	L_avx2_sha512_k_2_end(%rip), %rsi
        jne	L_sha512_len_avx2_start
        vpaddq	(%rsi), %ymm0, %ymm8
        vpaddq	32(%rsi), %ymm1, %ymm9
        vmovdqu	%ymm8, (%rbp)
        vmovdqu	%ymm9, 32(%rbp)
        vpaddq	64(%rsi), %ymm2, %ymm8
        vpaddq	96(%rsi), %ymm3, %ymm9
        vmovdqu	%ymm8, 64(%rbp)
        vmovdqu	%ymm9, 96(%rbp)
        vpaddq	128(%rsi), %ymm4, %ymm8
        vpaddq	160(%rsi), %ymm5, %ymm9
        vmovdqu	%ymm8, 128(%rbp)
        vmovdqu	%ymm9, 160(%rbp)
        vpaddq	192(%rsi), %ymm6, %ymm8
        vpaddq	224(%rsi), %ymm7, %ymm9
        vmovdqu	%ymm8, 192(%rbp)
        vmovdqu	%ymm9, 224(%rbp)
        rorq	$23, %rax
        movq	%r8, %rdx
        movq	%r13, %rcx
        addq	(%rbp), %r15
        xorq	%r14, %rcx
        xorq	%r12, %rax
        andq	%r12, %rcx
        rorq	$4, %rax
        xorq	%r14, %rcx
        xorq	%r12, %rax
        addq	%rcx, %r15
        rorq	$14, %rax
        xorq	%r9, %rdx
        addq	%rax, %r15
        movq	%r8, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        xorq	%r8, %rcx
        xorq	%r9, %rbx
        rorq	$6, %rcx
        addq	%r15, %r11
        xorq	%r8, %rcx
        addq	%rbx, %r15
        rorq	$28, %rcx
        movq	%r11, %rax
        addq	%rcx, %r15
        rorq	$23, %rax
        movq	%r15, %rbx
        movq	%r12, %rcx
        addq	8(%rbp), %r14
        xorq	%r13, %rcx
        xorq	%r11, %rax
        andq	%r11, %rcx
        rorq	$4, %rax
        xorq	%r13, %rcx
        xorq	%r11, %rax
        addq	%rcx, %r14
        rorq	$14, %rax
        xorq	%r8, %rbx
        addq	%rax, %r14
        movq	%r15, %rcx
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r15, %rcx
        xorq	%r8, %rdx
        rorq	$6, %rcx
        addq	%r14, %r10
        xorq	%r15, %rcx
        addq	%rdx, %r14
        rorq	$28, %rcx
        movq	%r10, %rax
        addq	%rcx, %r14
        rorq	$23, %rax
        movq	%r14, %rdx
        movq	%r11, %rcx
        addq	32(%rbp), %r13
        xorq	%r12, %rcx
        xorq	%r10, %rax
        andq	%r10, %rcx
        rorq	$4, %rax
        xorq	%r12, %rcx
        xorq	%r10, %rax
        addq	%rcx, %r13
        rorq	$14, %rax
        xorq	%r15, %rdx
        addq	%rax, %r13
        movq	%r14, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        xorq	%r14, %rcx
        xorq	%r15, %rbx
        rorq	$6, %rcx
        addq	%r13, %r9
        xorq	%r14, %rcx
        addq	%rbx, %r13
        rorq	$28, %rcx
        movq	%r9, %rax
        addq	%rcx, %r13
        rorq	$23, %rax
        movq	%r13, %rbx
        movq	%r10, %rcx
        addq	40(%rbp), %r12
        xorq	%r11, %rcx
        xorq	%r9, %rax
        andq	%r9, %rcx
        rorq	$4, %rax
        xorq	%r11, %rcx
        xorq	%r9, %rax
        addq	%rcx, %r12
        rorq	$14, %rax
        xorq	%r14, %rbx
        addq	%rax, %r12
        movq	%r13, %rcx
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r13, %rcx
        xorq	%r14, %rdx
        rorq	$6, %rcx
        addq	%r12, %r8
        xorq	%r13, %rcx
        addq	%rdx, %r12
        rorq	$28, %rcx
        movq	%r8, %rax
        addq	%rcx, %r12
        rorq	$23, %rax
        movq	%r12, %rdx
        movq	%r9, %rcx
        addq	64(%rbp), %r11
        xorq	%r10, %rcx
        xorq	%r8, %rax
        andq	%r8, %rcx
        rorq	$4, %rax
        xorq	%r10, %rcx
        xorq	%r8, %rax
        addq	%rcx, %r11
        rorq	$14, %rax
        xorq	%r13, %rdx
        addq	%rax, %r11
        movq	%r12, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        xorq	%r12, %rcx
        xorq	%r13, %rbx
        rorq	$6, %rcx
        addq	%r11, %r15
        xorq	%r12, %rcx
        addq	%rbx, %r11
        rorq	$28, %rcx
        movq	%r15, %rax
        addq	%rcx, %r11
        rorq	$23, %rax
        movq	%r11, %rbx
        movq	%r8, %rcx
        addq	72(%rbp), %r10
        xorq	%r9, %rcx
        xorq	%r15, %rax
        andq	%r15, %rcx
        rorq	$4, %rax
        xorq	%r9, %rcx
        xorq	%r15, %rax
        addq	%rcx, %r10
        rorq	$14, %rax
        xorq	%r12, %rbx
        addq	%rax, %r10
        movq	%r11, %rcx
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r11, %rcx
        xorq	%r12, %rdx
        rorq	$6, %rcx
        addq	%r10, %r14
        xorq	%r11, %rcx
        addq	%rdx, %r10
        rorq	$28, %rcx
        movq	%r14, %rax
        addq	%rcx, %r10
        rorq	$23, %rax
        movq	%r10, %rdx
        movq	%r15, %rcx
        addq	96(%rbp), %r9
        xorq	%r8, %rcx
        xorq	%r14, %rax
        andq	%r14, %rcx
        rorq	$4, %rax
        xorq	%r8, %rcx
        xorq	%r14, %rax
        addq	%rcx, %r9
        rorq	$14, %rax
        xorq	%r11, %rdx
        addq	%rax, %r9
        movq	%r10, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        xorq	%r10, %rcx
        xorq	%r11, %rbx
        rorq	$6, %rcx
        addq	%r9, %r13
        xorq	%r10, %rcx
        addq	%rbx, %r9
        rorq	$28, %rcx
        movq	%r13, %rax
        addq	%rcx, %r9
        rorq	$23, %rax
        movq	%r9, %rbx
        movq	%r14, %rcx
        addq	104(%rbp), %r8
        xorq	%r15, %rcx
        xorq	%r13, %rax
        andq	%r13, %rcx
        rorq	$4, %rax
        xorq	%r15, %rcx
        xorq	%r13, %rax
        addq	%rcx, %r8
        rorq	$14, %rax
        xorq	%r10, %rbx
        addq	%rax, %r8
        movq	%r9, %rcx
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r9, %rcx
        xorq	%r10, %rdx
        rorq	$6, %rcx
        addq	%r8, %r12
        xorq	%r9, %rcx
        addq	%rdx, %r8
        rorq	$28, %rcx
        movq	%r12, %rax
        addq	%rcx, %r8
        rorq	$23, %rax
        movq	%r8, %rdx
        movq	%r13, %rcx
        addq	128(%rbp), %r15
        xorq	%r14, %rcx
        xorq	%r12, %rax
        andq	%r12, %rcx
        rorq	$4, %rax
        xorq	%r14, %rcx
        xorq	%r12, %rax
        addq	%rcx, %r15
        rorq	$14, %rax
        xorq	%r9, %rdx
        addq	%rax, %r15
        movq	%r8, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        xorq	%r8, %rcx
        xorq	%r9, %rbx
        rorq	$6, %rcx
        addq	%r15, %r11
        xorq	%r8, %rcx
        addq	%rbx, %r15
        rorq	$28, %rcx
        movq	%r11, %rax
        addq	%rcx, %r15
        rorq	$23, %rax
        movq	%r15, %rbx
        movq	%r12, %rcx
        addq	136(%rbp), %r14
        xorq	%r13, %rcx
        xorq	%r11, %rax
        andq	%r11, %rcx
        rorq	$4, %rax
        xorq	%r13, %rcx
        xorq	%r11, %rax
        addq	%rcx, %r14
        rorq	$14, %rax
        xorq	%r8, %rbx
        addq	%rax, %r14
        movq	%r15, %rcx
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r15, %rcx
        xorq	%r8, %rdx
        rorq	$6, %rcx
        addq	%r14, %r10
        xorq	%r15, %rcx
        addq	%rdx, %r14
        rorq	$28, %rcx
        movq	%r10, %rax
        addq	%rcx, %r14
        rorq	$23, %rax
        movq	%r14, %rdx
        movq	%r11, %rcx
        addq	160(%rbp), %r13
        xorq	%r12, %rcx
        xorq	%r10, %rax
        andq	%r10, %rcx
        rorq	$4, %rax
        xorq	%r12, %rcx
        xorq	%r10, %rax
        addq	%rcx, %r13
        rorq	$14, %rax
        xorq	%r15, %rdx
        addq	%rax, %r13
        movq	%r14, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        xorq	%r14, %rcx
        xorq	%r15, %rbx
        rorq	$6, %rcx
        addq	%r13, %r9
        xorq	%r14, %rcx
        addq	%rbx, %r13
        rorq	$28, %rcx
        movq	%r9, %rax
        addq	%rcx, %r13
        rorq	$23, %rax
        movq	%r13, %rbx
        movq	%r10, %rcx
        addq	168(%rbp), %r12
        xorq	%r11, %rcx
        xorq	%r9, %rax
        andq	%r9, %rcx
        rorq	$4, %rax
        xorq	%r11, %rcx
        xorq	%r9, %rax
        addq	%rcx, %r12
        rorq	$14, %rax
        xorq	%r14, %rbx
        addq	%rax, %r12
        movq	%r13, %rcx
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r13, %rcx
        xorq	%r14, %rdx
        rorq	$6, %rcx
        addq	%r12, %r8
        xorq	%r13, %rcx
        addq	%rdx, %r12
        rorq	$28, %rcx
        movq	%r8, %rax
        addq	%rcx, %r12
        rorq	$23, %rax
        movq	%r12, %rdx
        movq	%r9, %rcx
        addq	192(%rbp), %r11
        xorq	%r10, %rcx
        xorq	%r8, %rax
        andq	%r8, %rcx
        rorq	$4, %rax
        xorq	%r10, %rcx
        xorq	%r8, %rax
        addq	%rcx, %r11
        rorq	$14, %rax
        xorq	%r13, %rdx
        addq	%rax, %r11
        movq	%r12, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        xorq	%r12, %rcx
        xorq	%r13, %rbx
        rorq	$6, %rcx
        addq	%r11, %r15
        xorq	%r12, %rcx
        addq	%rbx, %r11
        rorq	$28, %rcx
        movq	%r15, %rax
        addq	%rcx, %r11
        rorq	$23, %rax
        movq	%r11, %rbx
        movq	%r8, %rcx
        addq	200(%rbp), %r10
        xorq	%r9, %rcx
        xorq	%r15, %rax
        andq	%r15, %rcx
        rorq	$4, %rax
        xorq	%r9, %rcx
        xorq	%r15, %rax
        addq	%rcx, %r10
        rorq	$14, %rax
        xorq	%r12, %rbx
        addq	%rax, %r10
        movq	%r11, %rcx
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r11, %rcx
        xorq	%r12, %rdx
        rorq	$6, %rcx
        addq	%r10, %r14
        xorq	%r11, %rcx
        addq	%rdx, %r10
        rorq	$28, %rcx
        movq	%r14, %rax
        addq	%rcx, %r10
        rorq	$23, %rax
        movq	%r10, %rdx
        movq	%r15, %rcx
        addq	224(%rbp), %r9
        xorq	%r8, %rcx
        xorq	%r14, %rax
        andq	%r14, %rcx
        rorq	$4, %rax
        xorq	%r8, %rcx
        xorq	%r14, %rax
        addq	%rcx, %r9
        rorq	$14, %rax
        xorq	%r11, %rdx
        addq	%rax, %r9
        movq	%r10, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        xorq	%r10, %rcx
        xorq	%r11, %rbx
        rorq	$6, %rcx
        addq	%r9, %r13
        xorq	%r10, %rcx
        addq	%rbx, %r9
        rorq	$28, %rcx
        movq	%r13, %rax
        addq	%rcx, %r9
        rorq	$23, %rax
        movq	%r9, %rbx
        movq	%r14, %rcx
        addq	232(%rbp), %r8
        xorq	%r15, %rcx
        xorq	%r13, %rax
        andq	%r13, %rcx
        rorq	$4, %rax
        xorq	%r15, %rcx
        xorq	%r13, %rax
        addq	%rcx, %r8
        rorq	$14, %rax
        xorq	%r10, %rbx
        addq	%rax, %r8
        movq	%r9, %rcx
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r9, %rcx
        xorq	%r10, %rdx
        rorq	$6, %rcx
        addq	%r8, %r12
        xorq	%r9, %rcx
        addq	%rdx, %r8
        rorq	$28, %rcx
        movq	%r12, %rax
        addq	%rcx, %r8
        subq	$0x400, %rbp
        addq	(%rdi), %r8
        addq	8(%rdi), %r9
        addq	16(%rdi), %r10
        addq	24(%rdi), %r11
        addq	32(%rdi), %r12
        addq	40(%rdi), %r13
        addq	48(%rdi), %r14
        addq	56(%rdi), %r15
        movq	%r8, (%rdi)
        movq	%r9, 8(%rdi)
        movq	%r10, 16(%rdi)
        movq	%r11, 24(%rdi)
        movq	%r12, 32(%rdi)
        movq	%r13, 40(%rdi)
        movq	%r14, 48(%rdi)
        movq	%r15, 56(%rdi)
        movq	%r9, %rbx
        movq	%r12, %rax
        xorq	%r10, %rbx
        movq	$5, %rsi
L_sha512_len_avx2_tail:
        rorq	$23, %rax
        movq	%r8, %rdx
        movq	%r13, %rcx
        addq	16(%rbp), %r15
        xorq	%r14, %rcx
        xorq	%r12, %rax
        andq	%r12, %rcx
        rorq	$4, %rax
        xorq	%r14, %rcx
        xorq	%r12, %rax
        addq	%rcx, %r15
        rorq	$14, %rax
        xorq	%r9, %rdx
        addq	%rax, %r15
        movq	%r8, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        xorq	%r8, %rcx
        xorq	%r9, %rbx
        rorq	$6, %rcx
        addq	%r15, %r11
        xorq	%r8, %rcx
        addq	%rbx, %r15
        rorq	$28, %rcx
        movq	%r11, %rax
        addq	%rcx, %r15
        rorq	$23, %rax
        movq	%r15, %rbx
        movq	%r12, %rcx
        addq	24(%rbp), %r14
        xorq	%r13, %rcx
        xorq	%r11, %rax
        andq	%r11, %rcx
        rorq	$4, %rax
        xorq	%r13, %rcx
        xorq	%r11, %rax
        addq	%rcx, %r14
        rorq	$14, %rax
        xorq	%r8, %rbx
        addq	%rax, %r14
        movq	%r15, %rcx
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r15, %rcx
        xorq	%r8, %rdx
        rorq	$6, %rcx
        addq	%r14, %r10
        xorq	%r15, %rcx
        addq	%rdx, %r14
        rorq	$28, %rcx
        movq	%r10, %rax
        addq	%rcx, %r14
        rorq	$23, %rax
        movq	%r14, %rdx
        movq	%r11, %rcx
        addq	48(%rbp), %r13
        xorq	%r12, %rcx
        xorq	%r10, %rax
        andq	%r10, %rcx
        rorq	$4, %rax
        xorq	%r12, %rcx
        xorq	%r10, %rax
        addq	%rcx, %r13
        rorq	$14, %rax
        xorq	%r15, %rdx
        addq	%rax, %r13
        movq	%r14, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        xorq	%r14, %rcx
        xorq	%r15, %rbx
        rorq	$6, %rcx
        addq	%r13, %r9
        xorq	%r14, %rcx
        addq	%rbx, %r13
        rorq	$28, %rcx
        movq	%r9, %rax
        addq	%rcx, %r13
        rorq	$23, %rax
        movq	%r13, %rbx
        movq	%r10, %rcx
        addq	56(%rbp), %r12
        xorq	%r11, %rcx
        xorq	%r9, %rax
        andq	%r9, %rcx
        rorq	$4, %rax
        xorq	%r11, %rcx
        xorq	%r9, %rax
        addq	%rcx, %r12
        rorq	$14, %rax
        xorq	%r14, %rbx
        addq	%rax, %r12
        movq	%r13, %rcx
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r13, %rcx
        xorq	%r14, %rdx
        rorq	$6, %rcx
        addq	%r12, %r8
        xorq	%r13, %rcx
        addq	%rdx, %r12
        rorq	$28, %rcx
        movq	%r8, %rax
        addq	%rcx, %r12
        rorq	$23, %rax
        movq	%r12, %rdx
        movq	%r9, %rcx
        addq	80(%rbp), %r11
        xorq	%r10, %rcx
        xorq	%r8, %rax
        andq	%r8, %rcx
        rorq	$4, %rax
        xorq	%r10, %rcx
        xorq	%r8, %rax
        addq	%rcx, %r11
        rorq	$14, %rax
        xorq	%r13, %rdx
        addq	%rax, %r11
        movq	%r12, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        xorq	%r12, %rcx
        xorq	%r13, %rbx
        rorq	$6, %rcx
        addq	%r11, %r15
        xorq	%r12, %rcx
        addq	%rbx, %r11
        rorq	$28, %rcx
        movq	%r15, %rax
        addq	%rcx, %r11
        rorq	$23, %rax
        movq	%r11, %rbx
        movq	%r8, %rcx
        addq	88(%rbp), %r10
        xorq	%r9, %rcx
        xorq	%r15, %rax
        andq	%r15, %rcx
        rorq	$4, %rax
        xorq	%r9, %rcx
        xorq	%r15, %rax
        addq	%rcx, %r10
        rorq	$14, %rax
        xorq	%r12, %rbx
        addq	%rax, %r10
        movq	%r11, %rcx
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r11, %rcx
        xorq	%r12, %rdx
        rorq	$6, %rcx
        addq	%r10, %r14
        xorq	%r11, %rcx
        addq	%rdx, %r10
        rorq	$28, %rcx
        movq	%r14, %rax
        addq	%rcx, %r10
        rorq	$23, %rax
        movq	%r10, %rdx
        movq	%r15, %rcx
        addq	112(%rbp), %r9
        xorq	%r8, %rcx
        xorq	%r14, %rax
        andq	%r14, %rcx
        rorq	$4, %rax
        xorq	%r8, %rcx
        xorq	%r14, %rax
        addq	%rcx, %r9
        rorq	$14, %rax
        xorq	%r11, %rdx
        addq	%rax, %r9
        movq	%r10, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        xorq	%r10, %rcx
        xorq	%r11, %rbx
        rorq	$6, %rcx
        addq	%r9, %r13
        xorq	%r10, %rcx
        addq	%rbx, %r9
        rorq	$28, %rcx
        movq	%r13, %rax
        addq	%rcx, %r9
        rorq	$23, %rax
        movq	%r9, %rbx
        movq	%r14, %rcx
        addq	120(%rbp), %r8
        xorq	%r15, %rcx
        xorq	%r13, %rax
        andq	%r13, %rcx
        rorq	$4, %rax
        xorq	%r15, %rcx
        xorq	%r13, %rax
        addq	%rcx, %r8
        rorq	$14, %rax
        xorq	%r10, %rbx
        addq	%rax, %r8
        movq	%r9, %rcx
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r9, %rcx
        xorq	%r10, %rdx
        rorq	$6, %rcx
        addq	%r8, %r12
        xorq	%r9, %rcx
        addq	%rdx, %r8
        rorq	$28, %rcx
        movq	%r12, %rax
        addq	%rcx, %r8
        rorq	$23, %rax
        movq	%r8, %rdx
        movq	%r13, %rcx
        addq	144(%rbp), %r15
        xorq	%r14, %rcx
        xorq	%r12, %rax
        andq	%r12, %rcx
        rorq	$4, %rax
        xorq	%r14, %rcx
        xorq	%r12, %rax
        addq	%rcx, %r15
        rorq	$14, %rax
        xorq	%r9, %rdx
        addq	%rax, %r15
        movq	%r8, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        xorq	%r8, %rcx
        xorq	%r9, %rbx
        rorq	$6, %rcx
        addq	%r15, %r11
        xorq	%r8, %rcx
        addq	%rbx, %r15
        rorq	$28, %rcx
        movq	%r11, %rax
        addq	%rcx, %r15
        rorq	$23, %rax
        movq	%r15, %rbx
        movq	%r12, %rcx
        addq	152(%rbp), %r14
        xorq	%r13, %rcx
        xorq	%r11, %rax
        andq	%r11, %rcx
        rorq	$4, %rax
        xorq	%r13, %rcx
        xorq	%r11, %rax
        addq	%rcx, %r14
        rorq	$14, %rax
        xorq	%r8, %rbx
        addq	%rax, %r14
        movq	%r15, %rcx
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r15, %rcx
        xorq	%r8, %rdx
        rorq	$6, %rcx
        addq	%r14, %r10
        xorq	%r15, %rcx
        addq	%rdx, %r14
        rorq	$28, %rcx
        movq	%r10, %rax
        addq	%rcx, %r14
        rorq	$23, %rax
        movq	%r14, %rdx
        movq	%r11, %rcx
        addq	176(%rbp), %r13
        xorq	%r12, %rcx
        xorq	%r10, %rax
        andq	%r10, %rcx
        rorq	$4, %rax
        xorq	%r12, %rcx
        xorq	%r10, %rax
        addq	%rcx, %r13
        rorq	$14, %rax
        xorq	%r15, %rdx
        addq	%rax, %r13
        movq	%r14, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        xorq	%r14, %rcx
        xorq	%r15, %rbx
        rorq	$6, %rcx
        addq	%r13, %r9
        xorq	%r14, %rcx
        addq	%rbx, %r13
        rorq	$28, %rcx
        movq	%r9, %rax
        addq	%rcx, %r13
        rorq	$23, %rax
        movq	%r13, %rbx
        movq	%r10, %rcx
        addq	184(%rbp), %r12
        xorq	%r11, %rcx
        xorq	%r9, %rax
        andq	%r9, %rcx
        rorq	$4, %rax
        xorq	%r11, %rcx
        xorq	%r9, %rax
        addq	%rcx, %r12
        rorq	$14, %rax
        xorq	%r14, %rbx
        addq	%rax, %r12
        movq	%r13, %rcx
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r13, %rcx
        xorq	%r14, %rdx
        rorq	$6, %rcx
        addq	%r12, %r8
        xorq	%r13, %rcx
        addq	%rdx, %r12
        rorq	$28, %rcx
        movq	%r8, %rax
        addq	%rcx, %r12
        rorq	$23, %rax
        movq	%r12, %rdx
        movq	%r9, %rcx
        addq	208(%rbp), %r11
        xorq	%r10, %rcx
        xorq	%r8, %rax
        andq	%r8, %rcx
        rorq	$4, %rax
        xorq	%r10, %rcx
        xorq	%r8, %rax
        addq	%rcx, %r11
        rorq	$14, %rax
        xorq	%r13, %rdx
        addq	%rax, %r11
        movq	%r12, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        xorq	%r12, %rcx
        xorq	%r13, %rbx
        rorq	$6, %rcx
        addq	%r11, %r15
        xorq	%r12, %rcx
        addq	%rbx, %r11
        rorq	$28, %rcx
        movq	%r15, %rax
        addq	%rcx, %r11
        rorq	$23, %rax
        movq	%r11, %rbx
        movq	%r8, %rcx
        addq	216(%rbp), %r10
        xorq	%r9, %rcx
        xorq	%r15, %rax
        andq	%r15, %rcx
        rorq	$4, %rax
        xorq	%r9, %rcx
        xorq	%r15, %rax
        addq	%rcx, %r10
        rorq	$14, %rax
        xorq	%r12, %rbx
        addq	%rax, %r10
        movq	%r11, %rcx
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r11, %rcx
        xorq	%r12, %rdx
        rorq	$6, %rcx
        addq	%r10, %r14
        xorq	%r11, %rcx
        addq	%rdx, %r10
        rorq	$28, %rcx
        movq	%r14, %rax
        addq	%rcx, %r10
        rorq	$23, %rax
        movq	%r10, %rdx
        movq	%r15, %rcx
        addq	240(%rbp), %r9
        xorq	%r8, %rcx
        xorq	%r14, %rax
        andq	%r14, %rcx
        rorq	$4, %rax
        xorq	%r8, %rcx
        xorq	%r14, %rax
        addq	%rcx, %r9
        rorq	$14, %rax
        xorq	%r11, %rdx
        addq	%rax, %r9
        movq	%r10, %rcx
        andq	%rdx, %rbx
        rorq	$5, %rcx
        xorq	%r10, %rcx
        xorq	%r11, %rbx
        rorq	$6, %rcx
        addq	%r9, %r13
        xorq	%r10, %rcx
        addq	%rbx, %r9
        rorq	$28, %rcx
        movq	%r13, %rax
        addq	%rcx, %r9
        rorq	$23, %rax
        movq	%r9, %rbx
        movq	%r14, %rcx
        addq	248(%rbp), %r8
        xorq	%r15, %rcx
        xorq	%r13, %rax
        andq	%r13, %rcx
        rorq	$4, %rax
        xorq	%r15, %rcx
        xorq	%r13, %rax
        addq	%rcx, %r8
        rorq	$14, %rax
        xorq	%r10, %rbx
        addq	%rax, %r8
        movq	%r9, %rcx
        andq	%rbx, %rdx
        rorq	$5, %rcx
        xorq	%r9, %rcx
        xorq	%r10, %rdx
        rorq	$6, %rcx
        addq	%r8, %r12
        xorq	%r9, %rcx
        addq	%rdx, %r8
        rorq	$28, %rcx
        movq	%r12, %rax
        addq	%rcx, %r8
        addq	$0x100, %rbp
        subq	$0x01, %rsi
        jnz	L_sha512_len_avx2_tail
        addq	(%rdi), %r8
        addq	8(%rdi), %r9
        addq	16(%rdi), %r10
        addq	24(%rdi), %r11
        addq	32(%rdi), %r12
        addq	40(%rdi), %r13
        addq	48(%rdi), %r14
        addq	56(%rdi), %r15
        movq	224(%rdi), %rcx
        addq	$0x100, %rcx
        subl	$0x100, 1344(%rsp)
        movq	%rcx, 224(%rdi)
        movq	%r8, (%rdi)
        movq	%r9, 8(%rdi)
        movq	%r10, 16(%rdi)
        movq	%r11, 24(%rdi)
        movq	%r12, 32(%rdi)
        movq	%r13, 40(%rdi)
        movq	%r14, 48(%rdi)
        movq	%r15, 56(%rdi)
        jnz	L_sha512_len_avx2_begin
        addq	$0x548, %rsp
L_sha512_len_avx2_done:
        xorq	%rax, %rax
        vzeroupper
        popq	%rbp
        popq	%r15
        popq	%r14
        popq	%r13
        popq	%r12
        popq	%rbx
        repz retq
#ifndef __APPLE__
.size	Transform_Sha512_AVX2_Len,.-Transform_Sha512_AVX2_Len
#endif /* __APPLE__ */
#ifndef __APPLE__
.data
#else
.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
.align	32
#else
.p2align	5
#endif /* __APPLE__ */
L_avx2_rorx_sha512_k:
.quad	0x428a2f98d728ae22,0x7137449123ef65cd
.quad	0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc
.quad	0x3956c25bf348b538,0x59f111f1b605d019
.quad	0x923f82a4af194f9b,0xab1c5ed5da6d8118
.quad	0xd807aa98a3030242,0x12835b0145706fbe
.quad	0x243185be4ee4b28c,0x550c7dc3d5ffb4e2
.quad	0x72be5d74f27b896f,0x80deb1fe3b1696b1
.quad	0x9bdc06a725c71235,0xc19bf174cf692694
.quad	0xe49b69c19ef14ad2,0xefbe4786384f25e3
.quad	0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65
.quad	0x2de92c6f592b0275,0x4a7484aa6ea6e483
.quad	0x5cb0a9dcbd41fbd4,0x76f988da831153b5
.quad	0x983e5152ee66dfab,0xa831c66d2db43210
.quad	0xb00327c898fb213f,0xbf597fc7beef0ee4
.quad	0xc6e00bf33da88fc2,0xd5a79147930aa725
.quad	0x06ca6351e003826f,0x142929670a0e6e70
.quad	0x27b70a8546d22ffc,0x2e1b21385c26c926
.quad	0x4d2c6dfc5ac42aed,0x53380d139d95b3df
.quad	0x650a73548baf63de,0x766a0abb3c77b2a8
.quad	0x81c2c92e47edaee6,0x92722c851482353b
.quad	0xa2bfe8a14cf10364,0xa81a664bbc423001
.quad	0xc24b8b70d0f89791,0xc76c51a30654be30
.quad	0xd192e819d6ef5218,0xd69906245565a910
.quad	0xf40e35855771202a,0x106aa07032bbd1b8
.quad	0x19a4c116b8d2d0c8,0x1e376c085141ab53
.quad	0x2748774cdf8eeb99,0x34b0bcb5e19b48a8
.quad	0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb
.quad	0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3
.quad	0x748f82ee5defb2fc,0x78a5636f43172f60
.quad	0x84c87814a1f0ab72,0x8cc702081a6439ec
.quad	0x90befffa23631e28,0xa4506cebde82bde9
.quad	0xbef9a3f7b2c67915,0xc67178f2e372532b
.quad	0xca273eceea26619c,0xd186b8c721c0c207
.quad	0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178
.quad	0x06f067aa72176fba,0x0a637dc5a2c898a6
.quad	0x113f9804bef90dae,0x1b710b35131c471b
.quad	0x28db77f523047d84,0x32caab7b40c72493
.quad	0x3c9ebe0a15c9bebc,0x431d67c49c100d4c
.quad	0x4cc5d4becb3e42b6,0x597f299cfc657e2a
.quad	0x5fcb6fab3ad6faec,0x6c44198c4a475817
#ifndef __APPLE__
.data
#else
.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
.align	32
#else
.p2align	5
#endif /* __APPLE__ */
L_avx2_rorx_sha512_k_2:
.quad	0x428a2f98d728ae22,0x7137449123ef65cd
.quad	0x428a2f98d728ae22,0x7137449123ef65cd
.quad	0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc
.quad	0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc
.quad	0x3956c25bf348b538,0x59f111f1b605d019
.quad	0x3956c25bf348b538,0x59f111f1b605d019
.quad	0x923f82a4af194f9b,0xab1c5ed5da6d8118
.quad	0x923f82a4af194f9b,0xab1c5ed5da6d8118
.quad	0xd807aa98a3030242,0x12835b0145706fbe
.quad	0xd807aa98a3030242,0x12835b0145706fbe
.quad	0x243185be4ee4b28c,0x550c7dc3d5ffb4e2
.quad	0x243185be4ee4b28c,0x550c7dc3d5ffb4e2
.quad	0x72be5d74f27b896f,0x80deb1fe3b1696b1
.quad	0x72be5d74f27b896f,0x80deb1fe3b1696b1
.quad	0x9bdc06a725c71235,0xc19bf174cf692694
.quad	0x9bdc06a725c71235,0xc19bf174cf692694
.quad	0xe49b69c19ef14ad2,0xefbe4786384f25e3
.quad	0xe49b69c19ef14ad2,0xefbe4786384f25e3
.quad	0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65
.quad	0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65
.quad	0x2de92c6f592b0275,0x4a7484aa6ea6e483
.quad	0x2de92c6f592b0275,0x4a7484aa6ea6e483
.quad	0x5cb0a9dcbd41fbd4,0x76f988da831153b5
.quad	0x5cb0a9dcbd41fbd4,0x76f988da831153b5
.quad	0x983e5152ee66dfab,0xa831c66d2db43210
.quad	0x983e5152ee66dfab,0xa831c66d2db43210
.quad	0xb00327c898fb213f,0xbf597fc7beef0ee4
.quad	0xb00327c898fb213f,0xbf597fc7beef0ee4
.quad	0xc6e00bf33da88fc2,0xd5a79147930aa725
.quad	0xc6e00bf33da88fc2,0xd5a79147930aa725
.quad	0x06ca6351e003826f,0x142929670a0e6e70
.quad	0x06ca6351e003826f,0x142929670a0e6e70
.quad	0x27b70a8546d22ffc,0x2e1b21385c26c926
.quad	0x27b70a8546d22ffc,0x2e1b21385c26c926
.quad	0x4d2c6dfc5ac42aed,0x53380d139d95b3df
.quad	0x4d2c6dfc5ac42aed,0x53380d139d95b3df
.quad	0x650a73548baf63de,0x766a0abb3c77b2a8
.quad	0x650a73548baf63de,0x766a0abb3c77b2a8
.quad	0x81c2c92e47edaee6,0x92722c851482353b
.quad	0x81c2c92e47edaee6,0x92722c851482353b
.quad	0xa2bfe8a14cf10364,0xa81a664bbc423001
.quad	0xa2bfe8a14cf10364,0xa81a664bbc423001
.quad	0xc24b8b70d0f89791,0xc76c51a30654be30
.quad	0xc24b8b70d0f89791,0xc76c51a30654be30
.quad	0xd192e819d6ef5218,0xd69906245565a910
.quad	0xd192e819d6ef5218,0xd69906245565a910
.quad	0xf40e35855771202a,0x106aa07032bbd1b8
.quad	0xf40e35855771202a,0x106aa07032bbd1b8
.quad	0x19a4c116b8d2d0c8,0x1e376c085141ab53
.quad	0x19a4c116b8d2d0c8,0x1e376c085141ab53
.quad	0x2748774cdf8eeb99,0x34b0bcb5e19b48a8
.quad	0x2748774cdf8eeb99,0x34b0bcb5e19b48a8
.quad	0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb
.quad	0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb
.quad	0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3
.quad	0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3
.quad	0x748f82ee5defb2fc,0x78a5636f43172f60
.quad	0x748f82ee5defb2fc,0x78a5636f43172f60
.quad	0x84c87814a1f0ab72,0x8cc702081a6439ec
.quad	0x84c87814a1f0ab72,0x8cc702081a6439ec
.quad	0x90befffa23631e28,0xa4506cebde82bde9
.quad	0x90befffa23631e28,0xa4506cebde82bde9
.quad	0xbef9a3f7b2c67915,0xc67178f2e372532b
.quad	0xbef9a3f7b2c67915,0xc67178f2e372532b
.quad	0xca273eceea26619c,0xd186b8c721c0c207
.quad	0xca273eceea26619c,0xd186b8c721c0c207
.quad	0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178
.quad	0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178
.quad	0x06f067aa72176fba,0x0a637dc5a2c898a6
.quad	0x06f067aa72176fba,0x0a637dc5a2c898a6
.quad	0x113f9804bef90dae,0x1b710b35131c471b
.quad	0x113f9804bef90dae,0x1b710b35131c471b
.quad	0x28db77f523047d84,0x32caab7b40c72493
.quad	0x28db77f523047d84,0x32caab7b40c72493
.quad	0x3c9ebe0a15c9bebc,0x431d67c49c100d4c
.quad	0x3c9ebe0a15c9bebc,0x431d67c49c100d4c
.quad	0x4cc5d4becb3e42b6,0x597f299cfc657e2a
.quad	0x4cc5d4becb3e42b6,0x597f299cfc657e2a
.quad	0x5fcb6fab3ad6faec,0x6c44198c4a475817
.quad	0x5fcb6fab3ad6faec,0x6c44198c4a475817
#ifndef __APPLE__
.data
#else
.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
.align	8
#else
.p2align	3
#endif /* __APPLE__ */
L_avx2_rorx_sha512_k_2_end:
.quad	1024+L_avx2_rorx_sha512_k_2
#ifndef __APPLE__
.data
#else
.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
.align	32
#else
.p2align	5
#endif /* __APPLE__ */
L_avx2_rorx_sha512_flip_mask:
.quad	0x0001020304050607,0x08090a0b0c0d0e0f
.quad	0x0001020304050607,0x08090a0b0c0d0e0f
#ifndef __APPLE__
.text
.globl	Transform_Sha512_AVX2_RORX
WC_ASM_ATT_HIDDEN(Transform_Sha512_AVX2_RORX)
.type	Transform_Sha512_AVX2_RORX,@function
.align	16
Transform_Sha512_AVX2_RORX:
#else
.section	__TEXT,__text
.globl	_Transform_Sha512_AVX2_RORX
WC_ASM_ATT_HIDDEN(_Transform_Sha512_AVX2_RORX)
.p2align	4
_Transform_Sha512_AVX2_RORX:
#endif /* __APPLE__ */
        pushq	%rbx
        pushq	%r12
        pushq	%r13
        pushq	%r14
        pushq	%r15
        subq	$0x90, %rsp
        leaq	64(%rdi), %rcx
        vmovdqa	L_avx2_rorx_sha512_flip_mask(%rip), %ymm15
        movq	(%rdi), %r8
        movq	8(%rdi), %r9
        movq	16(%rdi), %r10
        movq	24(%rdi), %r11
        movq	32(%rdi), %r12
        movq	40(%rdi), %r13
        movq	48(%rdi), %r14
        movq	56(%rdi), %r15
        vmovdqu	(%rcx), %ymm0
        vmovdqu	32(%rcx), %ymm1
        vpshufb	%ymm15, %ymm0, %ymm0
        vpshufb	%ymm15, %ymm1, %ymm1
        vmovdqu	64(%rcx), %ymm2
        vmovdqu	96(%rcx), %ymm3
        vpshufb	%ymm15, %ymm2, %ymm2
        vpshufb	%ymm15, %ymm3, %ymm3
        movl	$4, 128(%rsp)
        leaq	L_avx2_rorx_sha512_k(%rip), %rsi
        movq	%r9, %rbx
        xorq	%rdx, %rdx
        xorq	%r10, %rbx
        # set_w_k: 0
        vpaddq	(%rsi), %ymm0, %ymm8
        vpaddq	32(%rsi), %ymm1, %ymm9
        vmovdqu	%ymm8, (%rsp)
        vmovdqu	%ymm9, 32(%rsp)
        vpaddq	64(%rsi), %ymm2, %ymm8
        vpaddq	96(%rsi), %ymm3, %ymm9
        vmovdqu	%ymm8, 64(%rsp)
        vmovdqu	%ymm9, 96(%rsp)
        # Start of 16 rounds
L_sha256_len_avx2_rorx_start:
        addq	$0x80, %rsi
        rorxq	$14, %r12, %rax
        rorxq	$18, %r12, %rcx
        addq	%rdx, %r8
        vpblendd	$3, %ymm1, %ymm0, %ymm12
        vpblendd	$3, %ymm3, %ymm2, %ymm13
        addq	(%rsp), %r15
        movq	%r13, %rdx
        xorq	%rax, %rcx
        vpermq	$57, %ymm12, %ymm12
        xorq	%r14, %rdx
        rorxq	$41, %r12, %rax
        xorq	%rcx, %rax
        vpermq	$57, %ymm13, %ymm13
        andq	%r12, %rdx
        addq	%rax, %r15
        rorxq	$28, %r8, %rax
        vpsrlq	$0x01, %ymm12, %ymm8
        vpsllq	$63, %ymm12, %ymm9
        rorxq	$34, %r8, %rcx
        xorq	%r14, %rdx
        xorq	%rax, %rcx
        vpsrlq	$8, %ymm12, %ymm10
        vpsllq	$56, %ymm12, %ymm11
        vpor	%ymm9, %ymm8, %ymm8
        vpor	%ymm11, %ymm10, %ymm10
        rorxq	$39, %r8, %rax
        addq	%rdx, %r15
        xorq	%rcx, %rax
        vpsrlq	$7, %ymm12, %ymm11
        movq	%r9, %rdx
        addq	%r15, %r11
        xorq	%r8, %rdx
        vperm2I128	$0x81, %ymm3, %ymm3, %ymm14
        andq	%rdx, %rbx
        addq	%rax, %r15
        xorq	%r9, %rbx
        rorxq	$14, %r11, %rax
        rorxq	$18, %r11, %rcx
        addq	%rbx, %r15
        vpxor	%ymm10, %ymm8, %ymm8
        addq	8(%rsp), %r14
        movq	%r12, %rbx
        xorq	%rax, %rcx
        vpxor	%ymm11, %ymm8, %ymm8
        xorq	%r13, %rbx
        rorxq	$41, %r11, %rax
        xorq	%rcx, %rax
        vpaddq	%ymm0, %ymm13, %ymm0
        vpaddq	%ymm0, %ymm8, %ymm0
        andq	%r11, %rbx
        addq	%rax, %r14
        rorxq	$28, %r15, %rax
        vpsrlq	$19, %ymm14, %ymm8
        vpsllq	$45, %ymm14, %ymm9
        rorxq	$34, %r15, %rcx
        xorq	%r13, %rbx
        xorq	%rax, %rcx
        vpsrlq	$61, %ymm14, %ymm10
        vpsllq	$3, %ymm14, %ymm11
        vpor	%ymm9, %ymm8, %ymm8
        rorxq	$39, %r15, %rax
        addq	%rbx, %r14
        xorq	%rcx, %rax
        vpor	%ymm11, %ymm10, %ymm10
        movq	%r8, %rbx
        leaq	(%r10,%r14,1), %r10
        xorq	%r15, %rbx
        vpxor	%ymm10, %ymm8, %ymm8
        andq	%rbx, %rdx
        addq	%rax, %r14
        xorq	%r8, %rdx
        vpsrlq	$6, %ymm14, %ymm11
        rorxq	$14, %r10, %rax
        rorxq	$18, %r10, %rcx
        addq	%rdx, %r14
        vpxor	%ymm11, %ymm8, %ymm8
        addq	16(%rsp), %r13
        movq	%r11, %rdx
        xorq	%rax, %rcx
        vpaddq	%ymm0, %ymm8, %ymm0
        xorq	%r12, %rdx
        rorxq	$41, %r10, %rax
        xorq	%rcx, %rax
        vperm2I128	$8, %ymm0, %ymm0, %ymm14
        andq	%r10, %rdx
        addq	%rax, %r13
        rorxq	$28, %r14, %rax
        rorxq	$34, %r14, %rcx
        xorq	%r12, %rdx
        xorq	%rax, %rcx
        vpsrlq	$19, %ymm14, %ymm8
        vpsllq	$45, %ymm14, %ymm9
        rorxq	$39, %r14, %rax
        addq	%rdx, %r13
        xorq	%rcx, %rax
        vpsrlq	$61, %ymm14, %ymm10
        vpsllq	$3, %ymm14, %ymm11
        vpor	%ymm9, %ymm8, %ymm8
        movq	%r15, %rdx
        addq	%r13, %r9
        xorq	%r14, %rdx
        vpor	%ymm11, %ymm10, %ymm10
        andq	%rdx, %rbx
        addq	%rax, %r13
        xorq	%r15, %rbx
        vpxor	%ymm10, %ymm8, %ymm8
        rorxq	$14, %r9, %rax
        rorxq	$18, %r9, %rcx
        addq	%rbx, %r13
        vpsrlq	$6, %ymm14, %ymm11
        addq	24(%rsp), %r12
        movq	%r10, %rbx
        xorq	%rax, %rcx
        xorq	%r11, %rbx
        rorxq	$41, %r9, %rax
        xorq	%rcx, %rax
        vpxor	%ymm11, %ymm8, %ymm8
        andq	%r9, %rbx
        addq	%rax, %r12
        rorxq	$28, %r13, %rax
        rorxq	$34, %r13, %rcx
        xorq	%r11, %rbx
        xorq	%rax, %rcx
        vpaddq	%ymm0, %ymm8, %ymm0
        rorxq	$39, %r13, %rax
        addq	%rbx, %r12
        xorq	%rcx, %rax
        vpaddq	(%rsi), %ymm0, %ymm8
        movq	%r14, %rbx
        leaq	(%r8,%r12,1), %r8
        xorq	%r13, %rbx
        andq	%rbx, %rdx
        addq	%rax, %r12
        xorq	%r14, %rdx
        vmovdqu	%ymm8, (%rsp)
        rorxq	$14, %r8, %rax
        rorxq	$18, %r8, %rcx
        addq	%rdx, %r12
        vpblendd	$3, %ymm2, %ymm1, %ymm12
        vpblendd	$3, %ymm0, %ymm3, %ymm13
        addq	32(%rsp), %r11
        movq	%r9, %rdx
        xorq	%rax, %rcx
        vpermq	$57, %ymm12, %ymm12
        xorq	%r10, %rdx
        rorxq	$41, %r8, %rax
        xorq	%rcx, %rax
        vpermq	$57, %ymm13, %ymm13
        andq	%r8, %rdx
        addq	%rax, %r11
        rorxq	$28, %r12, %rax
        vpsrlq	$0x01, %ymm12, %ymm8
        vpsllq	$63, %ymm12, %ymm9
        rorxq	$34, %r12, %rcx
        xorq	%r10, %rdx
        xorq	%rax, %rcx
        vpsrlq	$8, %ymm12, %ymm10
        vpsllq	$56, %ymm12, %ymm11
        vpor	%ymm9, %ymm8, %ymm8
        vpor	%ymm11, %ymm10, %ymm10
        rorxq	$39, %r12, %rax
        addq	%rdx, %r11
        xorq	%rcx, %rax
        vpsrlq	$7, %ymm12, %ymm11
        movq	%r13, %rdx
        addq	%r11, %r15
        xorq	%r12, %rdx
        vperm2I128	$0x81, %ymm0, %ymm0, %ymm14
        andq	%rdx, %rbx
        addq	%rax, %r11
        xorq	%r13, %rbx
        rorxq	$14, %r15, %rax
        rorxq	$18, %r15, %rcx
        addq	%rbx, %r11
        vpxor	%ymm10, %ymm8, %ymm8
        addq	40(%rsp), %r10
        movq	%r8, %rbx
        xorq	%rax, %rcx
        vpxor	%ymm11, %ymm8, %ymm8
        xorq	%r9, %rbx
        rorxq	$41, %r15, %rax
        xorq	%rcx, %rax
        vpaddq	%ymm1, %ymm13, %ymm1
        vpaddq	%ymm1, %ymm8, %ymm1
        andq	%r15, %rbx
        addq	%rax, %r10
        rorxq	$28, %r11, %rax
        vpsrlq	$19, %ymm14, %ymm8
        vpsllq	$45, %ymm14, %ymm9
        rorxq	$34, %r11, %rcx
        xorq	%r9, %rbx
        xorq	%rax, %rcx
        vpsrlq	$61, %ymm14, %ymm10
        vpsllq	$3, %ymm14, %ymm11
        vpor	%ymm9, %ymm8, %ymm8
        rorxq	$39, %r11, %rax
        addq	%rbx, %r10
        xorq	%rcx, %rax
        vpor	%ymm11, %ymm10, %ymm10
        movq	%r12, %rbx
        leaq	(%r14,%r10,1), %r14
        xorq	%r11, %rbx
        vpxor	%ymm10, %ymm8, %ymm8
        andq	%rbx, %rdx
        addq	%rax, %r10
        xorq	%r12, %rdx
        vpsrlq	$6, %ymm14, %ymm11
        rorxq	$14, %r14, %rax
        rorxq	$18, %r14, %rcx
        addq	%rdx, %r10
        vpxor	%ymm11, %ymm8, %ymm8
        addq	48(%rsp), %r9
        movq	%r15, %rdx
        xorq	%rax, %rcx
        vpaddq	%ymm1, %ymm8, %ymm1
        xorq	%r8, %rdx
        rorxq	$41, %r14, %rax
        xorq	%rcx, %rax
        vperm2I128	$8, %ymm1, %ymm1, %ymm14
        andq	%r14, %rdx
        addq	%rax, %r9
        rorxq	$28, %r10, %rax
        rorxq	$34, %r10, %rcx
        xorq	%r8, %rdx
        xorq	%rax, %rcx
        vpsrlq	$19, %ymm14, %ymm8
        vpsllq	$45, %ymm14, %ymm9
        rorxq	$39, %r10, %rax
        addq	%rdx, %r9
        xorq	%rcx, %rax
        vpsrlq	$61, %ymm14, %ymm10
        vpsllq	$3, %ymm14, %ymm11
        vpor	%ymm9, %ymm8, %ymm8
        movq	%r11, %rdx
        addq	%r9, %r13
        xorq	%r10, %rdx
        vpor	%ymm11, %ymm10, %ymm10
        andq	%rdx, %rbx
        addq	%rax, %r9
        xorq	%r11, %rbx
        vpxor	%ymm10, %ymm8, %ymm8
        rorxq	$14, %r13, %rax
        rorxq	$18, %r13, %rcx
        addq	%rbx, %r9
        vpsrlq	$6, %ymm14, %ymm11
        addq	56(%rsp), %r8
        movq	%r14, %rbx
        xorq	%rax, %rcx
        xorq	%r15, %rbx
        rorxq	$41, %r13, %rax
        xorq	%rcx, %rax
        vpxor	%ymm11, %ymm8, %ymm8
        andq	%r13, %rbx
        addq	%rax, %r8
        rorxq	$28, %r9, %rax
        rorxq	$34, %r9, %rcx
        xorq	%r15, %rbx
        xorq	%rax, %rcx
        vpaddq	%ymm1, %ymm8, %ymm1
        rorxq	$39, %r9, %rax
        addq	%rbx, %r8
        xorq	%rcx, %rax
        vpaddq	32(%rsi), %ymm1, %ymm8
        movq	%r10, %rbx
        leaq	(%r12,%r8,1), %r12
        xorq	%r9, %rbx
        andq	%rbx, %rdx
        addq	%rax, %r8
        xorq	%r10, %rdx
        vmovdqu	%ymm8, 32(%rsp)
        rorxq	$14, %r12, %rax
        rorxq	$18, %r12, %rcx
        addq	%rdx, %r8
        vpblendd	$3, %ymm3, %ymm2, %ymm12
        vpblendd	$3, %ymm1, %ymm0, %ymm13
        addq	64(%rsp), %r15
        movq	%r13, %rdx
        xorq	%rax, %rcx
        vpermq	$57, %ymm12, %ymm12
        xorq	%r14, %rdx
        rorxq	$41, %r12, %rax
        xorq	%rcx, %rax
        vpermq	$57, %ymm13, %ymm13
        andq	%r12, %rdx
        addq	%rax, %r15
        rorxq	$28, %r8, %rax
        vpsrlq	$0x01, %ymm12, %ymm8
        vpsllq	$63, %ymm12, %ymm9
        rorxq	$34, %r8, %rcx
        xorq	%r14, %rdx
        xorq	%rax, %rcx
        vpsrlq	$8, %ymm12, %ymm10
        vpsllq	$56, %ymm12, %ymm11
        vpor	%ymm9, %ymm8, %ymm8
        vpor	%ymm11, %ymm10, %ymm10
        rorxq	$39, %r8, %rax
        addq	%rdx, %r15
        xorq	%rcx, %rax
        vpsrlq	$7, %ymm12, %ymm11
        movq	%r9, %rdx
        addq	%r15, %r11
        xorq	%r8, %rdx
        vperm2I128	$0x81, %ymm1, %ymm1, %ymm14
        andq	%rdx, %rbx
        addq	%rax, %r15
        xorq	%r9, %rbx
        rorxq	$14, %r11, %rax
        rorxq	$18, %r11, %rcx
        addq	%rbx, %r15
        vpxor	%ymm10, %ymm8, %ymm8
        addq	72(%rsp), %r14
        movq	%r12, %rbx
        xorq	%rax, %rcx
        vpxor	%ymm11, %ymm8, %ymm8
        xorq	%r13, %rbx
        rorxq	$41, %r11, %rax
        xorq	%rcx, %rax
        vpaddq	%ymm2, %ymm13, %ymm2
        vpaddq	%ymm2, %ymm8, %ymm2
        andq	%r11, %rbx
        addq	%rax, %r14
        rorxq	$28, %r15, %rax
        vpsrlq	$19, %ymm14, %ymm8
        vpsllq	$45, %ymm14, %ymm9
        rorxq	$34, %r15, %rcx
        xorq	%r13, %rbx
        xorq	%rax, %rcx
        vpsrlq	$61, %ymm14, %ymm10
        vpsllq	$3, %ymm14, %ymm11
        vpor	%ymm9, %ymm8, %ymm8
        rorxq	$39, %r15, %rax
        addq	%rbx, %r14
        xorq	%rcx, %rax
        vpor	%ymm11, %ymm10, %ymm10
        movq	%r8, %rbx
        leaq	(%r10,%r14,1), %r10
        xorq	%r15, %rbx
        vpxor	%ymm10, %ymm8, %ymm8
        andq	%rbx, %rdx
        addq	%rax, %r14
        xorq	%r8, %rdx
        vpsrlq	$6, %ymm14, %ymm11
        rorxq	$14, %r10, %rax
        rorxq	$18, %r10, %rcx
        addq	%rdx, %r14
        vpxor	%ymm11, %ymm8, %ymm8
        addq	80(%rsp), %r13
        movq	%r11, %rdx
        xorq	%rax, %rcx
        vpaddq	%ymm2, %ymm8, %ymm2
        xorq	%r12, %rdx
        rorxq	$41, %r10, %rax
        xorq	%rcx, %rax
        vperm2I128	$8, %ymm2, %ymm2, %ymm14
        andq	%r10, %rdx
        addq	%rax, %r13
        rorxq	$28, %r14, %rax
        rorxq	$34, %r14, %rcx
        xorq	%r12, %rdx
        xorq	%rax, %rcx
        vpsrlq	$19, %ymm14, %ymm8
        vpsllq	$45, %ymm14, %ymm9
        rorxq	$39, %r14, %rax
        addq	%rdx, %r13
        xorq	%rcx, %rax
        vpsrlq	$61, %ymm14, %ymm10
        vpsllq	$3, %ymm14, %ymm11
        vpor	%ymm9, %ymm8, %ymm8
        movq	%r15, %rdx
        addq	%r13, %r9
        xorq	%r14, %rdx
        vpor	%ymm11, %ymm10, %ymm10
        andq	%rdx, %rbx
        addq	%rax, %r13
        xorq	%r15, %rbx
        vpxor	%ymm10, %ymm8, %ymm8
        rorxq	$14, %r9, %rax
        rorxq	$18, %r9, %rcx
        addq	%rbx, %r13
        vpsrlq	$6, %ymm14, %ymm11
        addq	88(%rsp), %r12
        movq	%r10, %rbx
        xorq	%rax, %rcx
        xorq	%r11, %rbx
        rorxq	$41, %r9, %rax
        xorq	%rcx, %rax
        vpxor	%ymm11, %ymm8, %ymm8
        andq	%r9, %rbx
        addq	%rax, %r12
        rorxq	$28, %r13, %rax
        rorxq	$34, %r13, %rcx
        xorq	%r11, %rbx
        xorq	%rax, %rcx
        vpaddq	%ymm2, %ymm8, %ymm2
        rorxq	$39, %r13, %rax
        addq	%rbx, %r12
        xorq	%rcx, %rax
        vpaddq	64(%rsi), %ymm2, %ymm8
        movq	%r14, %rbx
        leaq	(%r8,%r12,1), %r8
        xorq	%r13, %rbx
        andq	%rbx, %rdx
        addq	%rax, %r12
        xorq	%r14, %rdx
        vmovdqu	%ymm8, 64(%rsp)
        rorxq	$14, %r8, %rax
        rorxq	$18, %r8, %rcx
        addq	%rdx, %r12
        vpblendd	$3, %ymm0, %ymm3, %ymm12
        vpblendd	$3, %ymm2, %ymm1, %ymm13
        addq	96(%rsp), %r11
        movq	%r9, %rdx
        xorq	%rax, %rcx
        vpermq	$57, %ymm12, %ymm12
        xorq	%r10, %rdx
        rorxq	$41, %r8, %rax
        xorq	%rcx, %rax
        vpermq	$57, %ymm13, %ymm13
        andq	%r8, %rdx
        addq	%rax, %r11
        rorxq	$28, %r12, %rax
        vpsrlq	$0x01, %ymm12, %ymm8
        vpsllq	$63, %ymm12, %ymm9
        rorxq	$34, %r12, %rcx
        xorq	%r10, %rdx
        xorq	%rax, %rcx
        vpsrlq	$8, %ymm12, %ymm10
        vpsllq	$56, %ymm12, %ymm11
        vpor	%ymm9, %ymm8, %ymm8
        vpor	%ymm11, %ymm10, %ymm10
        rorxq	$39, %r12, %rax
        addq	%rdx, %r11
        xorq	%rcx, %rax
        vpsrlq	$7, %ymm12, %ymm11
        movq	%r13, %rdx
        addq	%r11, %r15
        xorq	%r12, %rdx
        vperm2I128	$0x81, %ymm2, %ymm2, %ymm14
        andq	%rdx, %rbx
        addq	%rax, %r11
        xorq	%r13, %rbx
        rorxq	$14, %r15, %rax
        rorxq	$18, %r15, %rcx
        addq	%rbx, %r11
        vpxor	%ymm10, %ymm8, %ymm8
        addq	104(%rsp), %r10
        movq	%r8, %rbx
        xorq	%rax, %rcx
        vpxor	%ymm11, %ymm8, %ymm8
        xorq	%r9, %rbx
        rorxq	$41, %r15, %rax
        xorq	%rcx, %rax
        vpaddq	%ymm3, %ymm13, %ymm3
        vpaddq	%ymm3, %ymm8, %ymm3
        andq	%r15, %rbx
        addq	%rax, %r10
        rorxq	$28, %r11, %rax
        vpsrlq	$19, %ymm14, %ymm8
        vpsllq	$45, %ymm14, %ymm9
        rorxq	$34, %r11, %rcx
        xorq	%r9, %rbx
        xorq	%rax, %rcx
        vpsrlq	$61, %ymm14, %ymm10
        vpsllq	$3, %ymm14, %ymm11
        vpor	%ymm9, %ymm8, %ymm8
        rorxq	$39, %r11, %rax
        addq	%rbx, %r10
        xorq	%rcx, %rax
        vpor	%ymm11, %ymm10, %ymm10
        movq	%r12, %rbx
        leaq	(%r14,%r10,1), %r14
        xorq	%r11, %rbx
        vpxor	%ymm10, %ymm8, %ymm8
        andq	%rbx, %rdx
        addq	%rax, %r10
        xorq	%r12, %rdx
        vpsrlq	$6, %ymm14, %ymm11
        rorxq	$14, %r14, %rax
        rorxq	$18, %r14, %rcx
        addq	%rdx, %r10
        vpxor	%ymm11, %ymm8, %ymm8
        addq	112(%rsp), %r9
        movq	%r15, %rdx
        xorq	%rax, %rcx
        vpaddq	%ymm3, %ymm8, %ymm3
        xorq	%r8, %rdx
        rorxq	$41, %r14, %rax
        xorq	%rcx, %rax
        vperm2I128	$8, %ymm3, %ymm3, %ymm14
        andq	%r14, %rdx
        addq	%rax, %r9
        rorxq	$28, %r10, %rax
        rorxq	$34, %r10, %rcx
        xorq	%r8, %rdx
        xorq	%rax, %rcx
        vpsrlq	$19, %ymm14, %ymm8
        vpsllq	$45, %ymm14, %ymm9
        rorxq	$39, %r10, %rax
        addq	%rdx, %r9
        xorq	%rcx, %rax
        vpsrlq	$61, %ymm14, %ymm10
        vpsllq	$3, %ymm14, %ymm11
        vpor	%ymm9, %ymm8, %ymm8
        movq	%r11, %rdx
        addq	%r9, %r13
        xorq	%r10, %rdx
        vpor	%ymm11, %ymm10, %ymm10
        andq	%rdx, %rbx
        addq	%rax, %r9
        xorq	%r11, %rbx
        vpxor	%ymm10, %ymm8, %ymm8
        rorxq	$14, %r13, %rax
        rorxq	$18, %r13, %rcx
        addq	%rbx, %r9
        vpsrlq	$6, %ymm14, %ymm11
        addq	120(%rsp), %r8
        movq	%r14, %rbx
        xorq	%rax, %rcx
        xorq	%r15, %rbx
        rorxq	$41, %r13, %rax
        xorq	%rcx, %rax
        vpxor	%ymm11, %ymm8, %ymm8
        andq	%r13, %rbx
        addq	%rax, %r8
        rorxq	$28, %r9, %rax
        rorxq	$34, %r9, %rcx
        xorq	%r15, %rbx
        xorq	%rax, %rcx
        vpaddq	%ymm3, %ymm8, %ymm3
        rorxq	$39, %r9, %rax
        addq	%rbx, %r8
        xorq	%rcx, %rax
        vpaddq	96(%rsi), %ymm3, %ymm8
        movq	%r10, %rbx
        leaq	(%r12,%r8,1), %r12
        xorq	%r9, %rbx
        andq	%rbx, %rdx
        addq	%rax, %r8
        xorq	%r10, %rdx
        vmovdqu	%ymm8, 96(%rsp)
        subl	$0x01, 128(%rsp)
        jne	L_sha256_len_avx2_rorx_start
        # rnd_all_4: 0-3
        rorxq	$14, %r12, %rax
        rorxq	$18, %r12, %rcx
        addq	%rdx, %r8
        addq	(%rsp), %r15
        movq	%r13, %rdx
        xorq	%rax, %rcx
        xorq	%r14, %rdx
        rorxq	$41, %r12, %rax
        xorq	%rcx, %rax
        andq	%r12, %rdx
        addq	%rax, %r15
        rorxq	$28, %r8, %rax
        rorxq	$34, %r8, %rcx
        xorq	%r14, %rdx
        xorq	%rax, %rcx
        rorxq	$39, %r8, %rax
        addq	%rdx, %r15
        xorq	%rcx, %rax
        movq	%r9, %rdx
        addq	%r15, %r11
        xorq	%r8, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r15
        xorq	%r9, %rbx
        rorxq	$14, %r11, %rax
        rorxq	$18, %r11, %rcx
        addq	%rbx, %r15
        addq	8(%rsp), %r14
        movq	%r12, %rbx
        xorq	%rax, %rcx
        xorq	%r13, %rbx
        rorxq	$41, %r11, %rax
        xorq	%rcx, %rax
        andq	%r11, %rbx
        addq	%rax, %r14
        rorxq	$28, %r15, %rax
        rorxq	$34, %r15, %rcx
        xorq	%r13, %rbx
        xorq	%rax, %rcx
        rorxq	$39, %r15, %rax
        addq	%rbx, %r14
        xorq	%rcx, %rax
        movq	%r8, %rbx
        leaq	(%r10,%r14,1), %r10
        xorq	%r15, %rbx
        andq	%rbx, %rdx
        addq	%rax, %r14
        xorq	%r8, %rdx
        rorxq	$14, %r10, %rax
        rorxq	$18, %r10, %rcx
        addq	%rdx, %r14
        addq	16(%rsp), %r13
        movq	%r11, %rdx
        xorq	%rax, %rcx
        xorq	%r12, %rdx
        rorxq	$41, %r10, %rax
        xorq	%rcx, %rax
        andq	%r10, %rdx
        addq	%rax, %r13
        rorxq	$28, %r14, %rax
        rorxq	$34, %r14, %rcx
        xorq	%r12, %rdx
        xorq	%rax, %rcx
        rorxq	$39, %r14, %rax
        addq	%rdx, %r13
        xorq	%rcx, %rax
        movq	%r15, %rdx
        addq	%r13, %r9
        xorq	%r14, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r13
        xorq	%r15, %rbx
        rorxq	$14, %r9, %rax
        rorxq	$18, %r9, %rcx
        addq	%rbx, %r13
        addq	24(%rsp), %r12
        movq	%r10, %rbx
        xorq	%rax, %rcx
        xorq	%r11, %rbx
        rorxq	$41, %r9, %rax
        xorq	%rcx, %rax
        andq	%r9, %rbx
        addq	%rax, %r12
        rorxq	$28, %r13, %rax
        rorxq	$34, %r13, %rcx
        xorq	%r11, %rbx
        xorq	%rax, %rcx
        rorxq	$39, %r13, %rax
        addq	%rbx, %r12
        xorq	%rcx, %rax
        movq	%r14, %rbx
        leaq	(%r8,%r12,1), %r8
        xorq	%r13, %rbx
        andq	%rbx, %rdx
        addq	%rax, %r12
        xorq	%r14, %rdx
        # rnd_all_4: 4-7
        rorxq	$14, %r8, %rax
        rorxq	$18, %r8, %rcx
        addq	%rdx, %r12
        addq	32(%rsp), %r11
        movq	%r9, %rdx
        xorq	%rax, %rcx
        xorq	%r10, %rdx
        rorxq	$41, %r8, %rax
        xorq	%rcx, %rax
        andq	%r8, %rdx
        addq	%rax, %r11
        rorxq	$28, %r12, %rax
        rorxq	$34, %r12, %rcx
        xorq	%r10, %rdx
        xorq	%rax, %rcx
        rorxq	$39, %r12, %rax
        addq	%rdx, %r11
        xorq	%rcx, %rax
        movq	%r13, %rdx
        addq	%r11, %r15
        xorq	%r12, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r11
        xorq	%r13, %rbx
        rorxq	$14, %r15, %rax
        rorxq	$18, %r15, %rcx
        addq	%rbx, %r11
        addq	40(%rsp), %r10
        movq	%r8, %rbx
        xorq	%rax, %rcx
        xorq	%r9, %rbx
        rorxq	$41, %r15, %rax
        xorq	%rcx, %rax
        andq	%r15, %rbx
        addq	%rax, %r10
        rorxq	$28, %r11, %rax
        rorxq	$34, %r11, %rcx
        xorq	%r9, %rbx
        xorq	%rax, %rcx
        rorxq	$39, %r11, %rax
        addq	%rbx, %r10
        xorq	%rcx, %rax
        movq	%r12, %rbx
        leaq	(%r14,%r10,1), %r14
        xorq	%r11, %rbx
        andq	%rbx, %rdx
        addq	%rax, %r10
        xorq	%r12, %rdx
        rorxq	$14, %r14, %rax
        rorxq	$18, %r14, %rcx
        addq	%rdx, %r10
        addq	48(%rsp), %r9
        movq	%r15, %rdx
        xorq	%rax, %rcx
        xorq	%r8, %rdx
        rorxq	$41, %r14, %rax
        xorq	%rcx, %rax
        andq	%r14, %rdx
        addq	%rax, %r9
        rorxq	$28, %r10, %rax
        rorxq	$34, %r10, %rcx
        xorq	%r8, %rdx
        xorq	%rax, %rcx
        rorxq	$39, %r10, %rax
        addq	%rdx, %r9
        xorq	%rcx, %rax
        movq	%r11, %rdx
        addq	%r9, %r13
        xorq	%r10, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r9
        xorq	%r11, %rbx
        rorxq	$14, %r13, %rax
        rorxq	$18, %r13, %rcx
        addq	%rbx, %r9
        addq	56(%rsp), %r8
        movq	%r14, %rbx
        xorq	%rax, %rcx
        xorq	%r15, %rbx
        rorxq	$41, %r13, %rax
        xorq	%rcx, %rax
        andq	%r13, %rbx
        addq	%rax, %r8
        rorxq	$28, %r9, %rax
        rorxq	$34, %r9, %rcx
        xorq	%r15, %rbx
        xorq	%rax, %rcx
        rorxq	$39, %r9, %rax
        addq	%rbx, %r8
        xorq	%rcx, %rax
        movq	%r10, %rbx
        leaq	(%r12,%r8,1), %r12
        xorq	%r9, %rbx
        andq	%rbx, %rdx
        addq	%rax, %r8
        xorq	%r10, %rdx
        # rnd_all_4: 8-11
        rorxq	$14, %r12, %rax
        rorxq	$18, %r12, %rcx
        addq	%rdx, %r8
        addq	64(%rsp), %r15
        movq	%r13, %rdx
        xorq	%rax, %rcx
        xorq	%r14, %rdx
        rorxq	$41, %r12, %rax
        xorq	%rcx, %rax
        andq	%r12, %rdx
        addq	%rax, %r15
        rorxq	$28, %r8, %rax
        rorxq	$34, %r8, %rcx
        xorq	%r14, %rdx
        xorq	%rax, %rcx
        rorxq	$39, %r8, %rax
        addq	%rdx, %r15
        xorq	%rcx, %rax
        movq	%r9, %rdx
        addq	%r15, %r11
        xorq	%r8, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r15
        xorq	%r9, %rbx
        rorxq	$14, %r11, %rax
        rorxq	$18, %r11, %rcx
        addq	%rbx, %r15
        addq	72(%rsp), %r14
        movq	%r12, %rbx
        xorq	%rax, %rcx
        xorq	%r13, %rbx
        rorxq	$41, %r11, %rax
        xorq	%rcx, %rax
        andq	%r11, %rbx
        addq	%rax, %r14
        rorxq	$28, %r15, %rax
        rorxq	$34, %r15, %rcx
        xorq	%r13, %rbx
        xorq	%rax, %rcx
        rorxq	$39, %r15, %rax
        addq	%rbx, %r14
        xorq	%rcx, %rax
        movq	%r8, %rbx
        leaq	(%r10,%r14,1), %r10
        xorq	%r15, %rbx
        andq	%rbx, %rdx
        addq	%rax, %r14
        xorq	%r8, %rdx
        rorxq	$14, %r10, %rax
        rorxq	$18, %r10, %rcx
        addq	%rdx, %r14
        addq	80(%rsp), %r13
        movq	%r11, %rdx
        xorq	%rax, %rcx
        xorq	%r12, %rdx
        rorxq	$41, %r10, %rax
        xorq	%rcx, %rax
        andq	%r10, %rdx
        addq	%rax, %r13
        rorxq	$28, %r14, %rax
        rorxq	$34, %r14, %rcx
        xorq	%r12, %rdx
        xorq	%rax, %rcx
        rorxq	$39, %r14, %rax
        addq	%rdx, %r13
        xorq	%rcx, %rax
        movq	%r15, %rdx
        addq	%r13, %r9
        xorq	%r14, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r13
        xorq	%r15, %rbx
        rorxq	$14, %r9, %rax
        rorxq	$18, %r9, %rcx
        addq	%rbx, %r13
        addq	88(%rsp), %r12
        movq	%r10, %rbx
        xorq	%rax, %rcx
        xorq	%r11, %rbx
        rorxq	$41, %r9, %rax
        xorq	%rcx, %rax
        andq	%r9, %rbx
        addq	%rax, %r12
        rorxq	$28, %r13, %rax
        rorxq	$34, %r13, %rcx
        xorq	%r11, %rbx
        xorq	%rax, %rcx
        rorxq	$39, %r13, %rax
        addq	%rbx, %r12
        xorq	%rcx, %rax
        movq	%r14, %rbx
        leaq	(%r8,%r12,1), %r8
        xorq	%r13, %rbx
        andq	%rbx, %rdx
        addq	%rax, %r12
        xorq	%r14, %rdx
        # rnd_all_4: 12-15
        rorxq	$14, %r8, %rax
        rorxq	$18, %r8, %rcx
        addq	%rdx, %r12
        addq	96(%rsp), %r11
        movq	%r9, %rdx
        xorq	%rax, %rcx
        xorq	%r10, %rdx
        rorxq	$41, %r8, %rax
        xorq	%rcx, %rax
        andq	%r8, %rdx
        addq	%rax, %r11
        rorxq	$28, %r12, %rax
        rorxq	$34, %r12, %rcx
        xorq	%r10, %rdx
        xorq	%rax, %rcx
        rorxq	$39, %r12, %rax
        addq	%rdx, %r11
        xorq	%rcx, %rax
        movq	%r13, %rdx
        addq	%r11, %r15
        xorq	%r12, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r11
        xorq	%r13, %rbx
        rorxq	$14, %r15, %rax
        rorxq	$18, %r15, %rcx
        addq	%rbx, %r11
        addq	104(%rsp), %r10
        movq	%r8, %rbx
        xorq	%rax, %rcx
        xorq	%r9, %rbx
        rorxq	$41, %r15, %rax
        xorq	%rcx, %rax
        andq	%r15, %rbx
        addq	%rax, %r10
        rorxq	$28, %r11, %rax
        rorxq	$34, %r11, %rcx
        xorq	%r9, %rbx
        xorq	%rax, %rcx
        rorxq	$39, %r11, %rax
        addq	%rbx, %r10
        xorq	%rcx, %rax
        movq	%r12, %rbx
        leaq	(%r14,%r10,1), %r14
        xorq	%r11, %rbx
        andq	%rbx, %rdx
        addq	%rax, %r10
        xorq	%r12, %rdx
        rorxq	$14, %r14, %rax
        rorxq	$18, %r14, %rcx
        addq	%rdx, %r10
        addq	112(%rsp), %r9
        movq	%r15, %rdx
        xorq	%rax, %rcx
        xorq	%r8, %rdx
        rorxq	$41, %r14, %rax
        xorq	%rcx, %rax
        andq	%r14, %rdx
        addq	%rax, %r9
        rorxq	$28, %r10, %rax
        rorxq	$34, %r10, %rcx
        xorq	%r8, %rdx
        xorq	%rax, %rcx
        rorxq	$39, %r10, %rax
        addq	%rdx, %r9
        xorq	%rcx, %rax
        movq	%r11, %rdx
        addq	%r9, %r13
        xorq	%r10, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r9
        xorq	%r11, %rbx
        rorxq	$14, %r13, %rax
        rorxq	$18, %r13, %rcx
        addq	%rbx, %r9
        addq	120(%rsp), %r8
        movq	%r14, %rbx
        xorq	%rax, %rcx
        xorq	%r15, %rbx
        rorxq	$41, %r13, %rax
        xorq	%rcx, %rax
        andq	%r13, %rbx
        addq	%rax, %r8
        rorxq	$28, %r9, %rax
        rorxq	$34, %r9, %rcx
        xorq	%r15, %rbx
        xorq	%rax, %rcx
        rorxq	$39, %r9, %rax
        addq	%rbx, %r8
        xorq	%rcx, %rax
        movq	%r10, %rbx
        leaq	(%r12,%r8,1), %r12
        xorq	%r9, %rbx
        andq	%rbx, %rdx
        addq	%rax, %r8
        xorq	%r10, %rdx
        addq	%rdx, %r8
        addq	%r8, (%rdi)
        addq	%r9, 8(%rdi)
        addq	%r10, 16(%rdi)
        addq	%r11, 24(%rdi)
        addq	%r12, 32(%rdi)
        addq	%r13, 40(%rdi)
        addq	%r14, 48(%rdi)
        addq	%r15, 56(%rdi)
        xorq	%rax, %rax
        vzeroupper
        addq	$0x90, %rsp
        popq	%r15
        popq	%r14
        popq	%r13
        popq	%r12
        popq	%rbx
        repz retq
#ifndef __APPLE__
.size	Transform_Sha512_AVX2_RORX,.-Transform_Sha512_AVX2_RORX
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	Transform_Sha512_AVX2_RORX_Len
WC_ASM_ATT_HIDDEN(Transform_Sha512_AVX2_RORX_Len)
.type	Transform_Sha512_AVX2_RORX_Len,@function
.align	16
Transform_Sha512_AVX2_RORX_Len:
#else
.section	__TEXT,__text
.globl	_Transform_Sha512_AVX2_RORX_Len
WC_ASM_ATT_HIDDEN(_Transform_Sha512_AVX2_RORX_Len)
.p2align	4
_Transform_Sha512_AVX2_RORX_Len:
#endif /* __APPLE__ */
        pushq	%rbx
        pushq	%r12
        pushq	%r13
        pushq	%r14
        pushq	%r15
        pushq	%rbp
        testb	$0x80, %sil
        je	L_sha512_len_avx2_rorx_block
        movq	224(%rdi), %rax
        pushq	%rsi
        vmovdqu	(%rax), %ymm0
        vmovdqu	32(%rax), %ymm1
        vmovdqu	64(%rax), %ymm2
        vmovdqu	96(%rax), %ymm3
        vmovups	%ymm0, 64(%rdi)
        vmovups	%ymm1, 96(%rdi)
        vmovups	%ymm2, 128(%rdi)
        vmovups	%ymm3, 160(%rdi)
#ifndef __APPLE__
        call	Transform_Sha512_AVX2_RORX@plt
#else
        call	_Transform_Sha512_AVX2_RORX
#endif /* __APPLE__ */
        popq	%rsi
        addq	$0x80, 224(%rdi)
        subl	$0x80, %esi
        jz	L_sha512_len_avx2_rorx_done
L_sha512_len_avx2_rorx_block:
        subq	$0x548, %rsp
        movq	224(%rdi), %rax
        vmovdqa	L_avx2_rorx_sha512_flip_mask(%rip), %ymm15
        movq	(%rdi), %r8
        movq	8(%rdi), %r9
        movq	16(%rdi), %r10
        movq	24(%rdi), %r11
        movq	32(%rdi), %r12
        movq	40(%rdi), %r13
        movq	48(%rdi), %r14
        movq	56(%rdi), %r15
        movl	%esi, 1344(%rsp)
        # Start of loop processing two blocks
L_sha512_len_avx2_rorx_begin:
        movq	%rsp, %rsi
        leaq	L_avx2_rorx_sha512_k_2(%rip), %rbp
        movq	%r9, %rbx
        xorq	%rdx, %rdx
        vmovdqu	(%rax), %xmm0
        vmovdqu	16(%rax), %xmm1
        vinserti128	$0x01, 128(%rax), %ymm0, %ymm0
        vinserti128	$0x01, 144(%rax), %ymm1, %ymm1
        vpshufb	%ymm15, %ymm0, %ymm0
        vpshufb	%ymm15, %ymm1, %ymm1
        vmovdqu	32(%rax), %xmm2
        vmovdqu	48(%rax), %xmm3
        vinserti128	$0x01, 160(%rax), %ymm2, %ymm2
        vinserti128	$0x01, 176(%rax), %ymm3, %ymm3
        vpshufb	%ymm15, %ymm2, %ymm2
        vpshufb	%ymm15, %ymm3, %ymm3
        vmovdqu	64(%rax), %xmm4
        vmovdqu	80(%rax), %xmm5
        vinserti128	$0x01, 192(%rax), %ymm4, %ymm4
        vinserti128	$0x01, 208(%rax), %ymm5, %ymm5
        vpshufb	%ymm15, %ymm4, %ymm4
        vpshufb	%ymm15, %ymm5, %ymm5
        vmovdqu	96(%rax), %xmm6
        vmovdqu	112(%rax), %xmm7
        vinserti128	$0x01, 224(%rax), %ymm6, %ymm6
        vinserti128	$0x01, 240(%rax), %ymm7, %ymm7
        vpshufb	%ymm15, %ymm6, %ymm6
        vpshufb	%ymm15, %ymm7, %ymm7
        xorq	%r10, %rbx
        # Start of 16 rounds
L_sha512_len_avx2_rorx_start:
        vpaddq	(%rbp), %ymm0, %ymm8
        vpaddq	32(%rbp), %ymm1, %ymm9
        vmovdqu	%ymm8, (%rsi)
        vmovdqu	%ymm9, 32(%rsi)
        vpaddq	64(%rbp), %ymm2, %ymm8
        vpaddq	96(%rbp), %ymm3, %ymm9
        vmovdqu	%ymm8, 64(%rsi)
        vmovdqu	%ymm9, 96(%rsi)
        vpaddq	128(%rbp), %ymm4, %ymm8
        vpaddq	160(%rbp), %ymm5, %ymm9
        vmovdqu	%ymm8, 128(%rsi)
        vmovdqu	%ymm9, 160(%rsi)
        vpaddq	192(%rbp), %ymm6, %ymm8
        vpaddq	224(%rbp), %ymm7, %ymm9
        vmovdqu	%ymm8, 192(%rsi)
        vmovdqu	%ymm9, 224(%rsi)
        # msg_sched: 0-1
        rorxq	$14, %r12, %rax
        rorxq	$18, %r12, %rcx
        addq	%rdx, %r8
        vpalignr	$8, %ymm0, %ymm1, %ymm12
        addq	(%rsi), %r15
        movq	%r13, %rdx
        xorq	%rax, %rcx
        vpalignr	$8, %ymm4, %ymm5, %ymm13
        xorq	%r14, %rdx
        rorxq	$41, %r12, %rax
        xorq	%rcx, %rax
        vpsrlq	$0x01, %ymm12, %ymm8
        vpsllq	$63, %ymm12, %ymm9
        andq	%r12, %rdx
        addq	%rax, %r15
        rorxq	$28, %r8, %rax
        vpsrlq	$8, %ymm12, %ymm10
        vpsllq	$56, %ymm12, %ymm11
        rorxq	$34, %r8, %rcx
        xorq	%r14, %rdx
        xorq	%rax, %rcx
        vpor	%ymm9, %ymm8, %ymm8
        vpor	%ymm11, %ymm10, %ymm10
        rorxq	$39, %r8, %rax
        addq	%rdx, %r15
        xorq	%rcx, %rax
        vpsrlq	$7, %ymm12, %ymm11
        vpxor	%ymm10, %ymm8, %ymm8
        movq	%r9, %rdx
        addq	%r15, %r11
        xorq	%r8, %rdx
        vpxor	%ymm11, %ymm8, %ymm8
        vpaddq	%ymm0, %ymm13, %ymm0
        andq	%rdx, %rbx
        addq	%rax, %r15
        xorq	%r9, %rbx
        vpaddq	%ymm0, %ymm8, %ymm0
        rorxq	$14, %r11, %rax
        rorxq	$18, %r11, %rcx
        addq	%rbx, %r15
        vpsrlq	$19, %ymm7, %ymm8
        vpsllq	$45, %ymm7, %ymm9
        addq	8(%rsi), %r14
        movq	%r12, %rbx
        xorq	%rax, %rcx
        vpsrlq	$61, %ymm7, %ymm10
        vpsllq	$3, %ymm7, %ymm11
        xorq	%r13, %rbx
        rorxq	$41, %r11, %rax
        xorq	%rcx, %rax
        vpor	%ymm9, %ymm8, %ymm8
        vpor	%ymm11, %ymm10, %ymm10
        andq	%r11, %rbx
        addq	%rax, %r14
        rorxq	$28, %r15, %rax
        rorxq	$34, %r15, %rcx
        xorq	%r13, %rbx
        xorq	%rax, %rcx
        vpxor	%ymm10, %ymm8, %ymm8
        vpsrlq	$6, %ymm7, %ymm11
        rorxq	$39, %r15, %rax
        addq	%rbx, %r14
        xorq	%rcx, %rax
        movq	%r8, %rbx
        leaq	(%r10,%r14,1), %r10
        xorq	%r15, %rbx
        vpxor	%ymm11, %ymm8, %ymm8
        andq	%rbx, %rdx
        addq	%rax, %r14
        xorq	%r8, %rdx
        vpaddq	%ymm0, %ymm8, %ymm0
        # msg_sched done: 0-1
        # msg_sched: 4-5
        rorxq	$14, %r10, %rax
        rorxq	$18, %r10, %rcx
        addq	%rdx, %r14
        vpalignr	$8, %ymm1, %ymm2, %ymm12
        addq	32(%rsi), %r13
        movq	%r11, %rdx
        xorq	%rax, %rcx
        vpalignr	$8, %ymm5, %ymm6, %ymm13
        xorq	%r12, %rdx
        rorxq	$41, %r10, %rax
        xorq	%rcx, %rax
        vpsrlq	$0x01, %ymm12, %ymm8
        vpsllq	$63, %ymm12, %ymm9
        andq	%r10, %rdx
        addq	%rax, %r13
        rorxq	$28, %r14, %rax
        vpsrlq	$8, %ymm12, %ymm10
        vpsllq	$56, %ymm12, %ymm11
        rorxq	$34, %r14, %rcx
        xorq	%r12, %rdx
        xorq	%rax, %rcx
        vpor	%ymm9, %ymm8, %ymm8
        vpor	%ymm11, %ymm10, %ymm10
        rorxq	$39, %r14, %rax
        addq	%rdx, %r13
        xorq	%rcx, %rax
        vpsrlq	$7, %ymm12, %ymm11
        vpxor	%ymm10, %ymm8, %ymm8
        movq	%r15, %rdx
        addq	%r13, %r9
        xorq	%r14, %rdx
        vpxor	%ymm11, %ymm8, %ymm8
        vpaddq	%ymm1, %ymm13, %ymm1
        andq	%rdx, %rbx
        addq	%rax, %r13
        xorq	%r15, %rbx
        vpaddq	%ymm1, %ymm8, %ymm1
        rorxq	$14, %r9, %rax
        rorxq	$18, %r9, %rcx
        addq	%rbx, %r13
        vpsrlq	$19, %ymm0, %ymm8
        vpsllq	$45, %ymm0, %ymm9
        addq	40(%rsi), %r12
        movq	%r10, %rbx
        xorq	%rax, %rcx
        vpsrlq	$61, %ymm0, %ymm10
        vpsllq	$3, %ymm0, %ymm11
        xorq	%r11, %rbx
        rorxq	$41, %r9, %rax
        xorq	%rcx, %rax
        vpor	%ymm9, %ymm8, %ymm8
        vpor	%ymm11, %ymm10, %ymm10
        andq	%r9, %rbx
        addq	%rax, %r12
        rorxq	$28, %r13, %rax
        rorxq	$34, %r13, %rcx
        xorq	%r11, %rbx
        xorq	%rax, %rcx
        vpxor	%ymm10, %ymm8, %ymm8
        vpsrlq	$6, %ymm0, %ymm11
        rorxq	$39, %r13, %rax
        addq	%rbx, %r12
        xorq	%rcx, %rax
        movq	%r14, %rbx
        leaq	(%r8,%r12,1), %r8
        xorq	%r13, %rbx
        vpxor	%ymm11, %ymm8, %ymm8
        andq	%rbx, %rdx
        addq	%rax, %r12
        xorq	%r14, %rdx
        vpaddq	%ymm1, %ymm8, %ymm1
        # msg_sched done: 4-5
        # msg_sched: 8-9
        rorxq	$14, %r8, %rax
        rorxq	$18, %r8, %rcx
        addq	%rdx, %r12
        vpalignr	$8, %ymm2, %ymm3, %ymm12
        addq	64(%rsi), %r11
        movq	%r9, %rdx
        xorq	%rax, %rcx
        vpalignr	$8, %ymm6, %ymm7, %ymm13
        xorq	%r10, %rdx
        rorxq	$41, %r8, %rax
        xorq	%rcx, %rax
        vpsrlq	$0x01, %ymm12, %ymm8
        vpsllq	$63, %ymm12, %ymm9
        andq	%r8, %rdx
        addq	%rax, %r11
        rorxq	$28, %r12, %rax
        vpsrlq	$8, %ymm12, %ymm10
        vpsllq	$56, %ymm12, %ymm11
        rorxq	$34, %r12, %rcx
        xorq	%r10, %rdx
        xorq	%rax, %rcx
        vpor	%ymm9, %ymm8, %ymm8
        vpor	%ymm11, %ymm10, %ymm10
        rorxq	$39, %r12, %rax
        addq	%rdx, %r11
        xorq	%rcx, %rax
        vpsrlq	$7, %ymm12, %ymm11
        vpxor	%ymm10, %ymm8, %ymm8
        movq	%r13, %rdx
        addq	%r11, %r15
        xorq	%r12, %rdx
        vpxor	%ymm11, %ymm8, %ymm8
        vpaddq	%ymm2, %ymm13, %ymm2
        andq	%rdx, %rbx
        addq	%rax, %r11
        xorq	%r13, %rbx
        vpaddq	%ymm2, %ymm8, %ymm2
        rorxq	$14, %r15, %rax
        rorxq	$18, %r15, %rcx
        addq	%rbx, %r11
        vpsrlq	$19, %ymm1, %ymm8
        vpsllq	$45, %ymm1, %ymm9
        addq	72(%rsi), %r10
        movq	%r8, %rbx
        xorq	%rax, %rcx
        vpsrlq	$61, %ymm1, %ymm10
        vpsllq	$3, %ymm1, %ymm11
        xorq	%r9, %rbx
        rorxq	$41, %r15, %rax
        xorq	%rcx, %rax
        vpor	%ymm9, %ymm8, %ymm8
        vpor	%ymm11, %ymm10, %ymm10
        andq	%r15, %rbx
        addq	%rax, %r10
        rorxq	$28, %r11, %rax
        rorxq	$34, %r11, %rcx
        xorq	%r9, %rbx
        xorq	%rax, %rcx
        vpxor	%ymm10, %ymm8, %ymm8
        vpsrlq	$6, %ymm1, %ymm11
        rorxq	$39, %r11, %rax
        addq	%rbx, %r10
        xorq	%rcx, %rax
        movq	%r12, %rbx
        leaq	(%r14,%r10,1), %r14
        xorq	%r11, %rbx
        vpxor	%ymm11, %ymm8, %ymm8
        andq	%rbx, %rdx
        addq	%rax, %r10
        xorq	%r12, %rdx
        vpaddq	%ymm2, %ymm8, %ymm2
        # msg_sched done: 8-9
        # msg_sched: 12-13
        rorxq	$14, %r14, %rax
        rorxq	$18, %r14, %rcx
        addq	%rdx, %r10
        vpalignr	$8, %ymm3, %ymm4, %ymm12
        addq	96(%rsi), %r9
        movq	%r15, %rdx
        xorq	%rax, %rcx
        vpalignr	$8, %ymm7, %ymm0, %ymm13
        xorq	%r8, %rdx
        rorxq	$41, %r14, %rax
        xorq	%rcx, %rax
        vpsrlq	$0x01, %ymm12, %ymm8
        vpsllq	$63, %ymm12, %ymm9
        andq	%r14, %rdx
        addq	%rax, %r9
        rorxq	$28, %r10, %rax
        vpsrlq	$8, %ymm12, %ymm10
        vpsllq	$56, %ymm12, %ymm11
        rorxq	$34, %r10, %rcx
        xorq	%r8, %rdx
        xorq	%rax, %rcx
        vpor	%ymm9, %ymm8, %ymm8
        vpor	%ymm11, %ymm10, %ymm10
        rorxq	$39, %r10, %rax
        addq	%rdx, %r9
        xorq	%rcx, %rax
        vpsrlq	$7, %ymm12, %ymm11
        vpxor	%ymm10, %ymm8, %ymm8
        movq	%r11, %rdx
        addq	%r9, %r13
        xorq	%r10, %rdx
        vpxor	%ymm11, %ymm8, %ymm8
        vpaddq	%ymm3, %ymm13, %ymm3
        andq	%rdx, %rbx
        addq	%rax, %r9
        xorq	%r11, %rbx
        vpaddq	%ymm3, %ymm8, %ymm3
        rorxq	$14, %r13, %rax
        rorxq	$18, %r13, %rcx
        addq	%rbx, %r9
        vpsrlq	$19, %ymm2, %ymm8
        vpsllq	$45, %ymm2, %ymm9
        addq	104(%rsi), %r8
        movq	%r14, %rbx
        xorq	%rax, %rcx
        vpsrlq	$61, %ymm2, %ymm10
        vpsllq	$3, %ymm2, %ymm11
        xorq	%r15, %rbx
        rorxq	$41, %r13, %rax
        xorq	%rcx, %rax
        vpor	%ymm9, %ymm8, %ymm8
        vpor	%ymm11, %ymm10, %ymm10
        andq	%r13, %rbx
        addq	%rax, %r8
        rorxq	$28, %r9, %rax
        rorxq	$34, %r9, %rcx
        xorq	%r15, %rbx
        xorq	%rax, %rcx
        vpxor	%ymm10, %ymm8, %ymm8
        vpsrlq	$6, %ymm2, %ymm11
        rorxq	$39, %r9, %rax
        addq	%rbx, %r8
        xorq	%rcx, %rax
        movq	%r10, %rbx
        leaq	(%r12,%r8,1), %r12
        xorq	%r9, %rbx
        vpxor	%ymm11, %ymm8, %ymm8
        andq	%rbx, %rdx
        addq	%rax, %r8
        xorq	%r10, %rdx
        vpaddq	%ymm3, %ymm8, %ymm3
        # msg_sched done: 12-13
        # msg_sched: 16-17
        rorxq	$14, %r12, %rax
        rorxq	$18, %r12, %rcx
        addq	%rdx, %r8
        vpalignr	$8, %ymm4, %ymm5, %ymm12
        addq	128(%rsi), %r15
        movq	%r13, %rdx
        xorq	%rax, %rcx
        vpalignr	$8, %ymm0, %ymm1, %ymm13
        xorq	%r14, %rdx
        rorxq	$41, %r12, %rax
        xorq	%rcx, %rax
        vpsrlq	$0x01, %ymm12, %ymm8
        vpsllq	$63, %ymm12, %ymm9
        andq	%r12, %rdx
        addq	%rax, %r15
        rorxq	$28, %r8, %rax
        vpsrlq	$8, %ymm12, %ymm10
        vpsllq	$56, %ymm12, %ymm11
        rorxq	$34, %r8, %rcx
        xorq	%r14, %rdx
        xorq	%rax, %rcx
        vpor	%ymm9, %ymm8, %ymm8
        vpor	%ymm11, %ymm10, %ymm10
        rorxq	$39, %r8, %rax
        addq	%rdx, %r15
        xorq	%rcx, %rax
        vpsrlq	$7, %ymm12, %ymm11
        vpxor	%ymm10, %ymm8, %ymm8
        movq	%r9, %rdx
        addq	%r15, %r11
        xorq	%r8, %rdx
        vpxor	%ymm11, %ymm8, %ymm8
        vpaddq	%ymm4, %ymm13, %ymm4
        andq	%rdx, %rbx
        addq	%rax, %r15
        xorq	%r9, %rbx
        vpaddq	%ymm4, %ymm8, %ymm4
        rorxq	$14, %r11, %rax
        rorxq	$18, %r11, %rcx
        addq	%rbx, %r15
        vpsrlq	$19, %ymm3, %ymm8
        vpsllq	$45, %ymm3, %ymm9
        addq	136(%rsi), %r14
        movq	%r12, %rbx
        xorq	%rax, %rcx
        vpsrlq	$61, %ymm3, %ymm10
        vpsllq	$3, %ymm3, %ymm11
        xorq	%r13, %rbx
        rorxq	$41, %r11, %rax
        xorq	%rcx, %rax
        vpor	%ymm9, %ymm8, %ymm8
        vpor	%ymm11, %ymm10, %ymm10
        andq	%r11, %rbx
        addq	%rax, %r14
        rorxq	$28, %r15, %rax
        rorxq	$34, %r15, %rcx
        xorq	%r13, %rbx
        xorq	%rax, %rcx
        vpxor	%ymm10, %ymm8, %ymm8
        vpsrlq	$6, %ymm3, %ymm11
        rorxq	$39, %r15, %rax
        addq	%rbx, %r14
        xorq	%rcx, %rax
        movq	%r8, %rbx
        leaq	(%r10,%r14,1), %r10
        xorq	%r15, %rbx
        vpxor	%ymm11, %ymm8, %ymm8
        andq	%rbx, %rdx
        addq	%rax, %r14
        xorq	%r8, %rdx
        vpaddq	%ymm4, %ymm8, %ymm4
        # msg_sched done: 16-17
        # msg_sched: 20-21
        rorxq	$14, %r10, %rax
        rorxq	$18, %r10, %rcx
        addq	%rdx, %r14
        vpalignr	$8, %ymm5, %ymm6, %ymm12
        addq	160(%rsi), %r13
        movq	%r11, %rdx
        xorq	%rax, %rcx
        vpalignr	$8, %ymm1, %ymm2, %ymm13
        xorq	%r12, %rdx
        rorxq	$41, %r10, %rax
        xorq	%rcx, %rax
        vpsrlq	$0x01, %ymm12, %ymm8
        vpsllq	$63, %ymm12, %ymm9
        andq	%r10, %rdx
        addq	%rax, %r13
        rorxq	$28, %r14, %rax
        vpsrlq	$8, %ymm12, %ymm10
        vpsllq	$56, %ymm12, %ymm11
        rorxq	$34, %r14, %rcx
        xorq	%r12, %rdx
        xorq	%rax, %rcx
        vpor	%ymm9, %ymm8, %ymm8
        vpor	%ymm11, %ymm10, %ymm10
        rorxq	$39, %r14, %rax
        addq	%rdx, %r13
        xorq	%rcx, %rax
        vpsrlq	$7, %ymm12, %ymm11
        vpxor	%ymm10, %ymm8, %ymm8
        movq	%r15, %rdx
        addq	%r13, %r9
        xorq	%r14, %rdx
        vpxor	%ymm11, %ymm8, %ymm8
        vpaddq	%ymm5, %ymm13, %ymm5
        andq	%rdx, %rbx
        addq	%rax, %r13
        xorq	%r15, %rbx
        vpaddq	%ymm5, %ymm8, %ymm5
        rorxq	$14, %r9, %rax
        rorxq	$18, %r9, %rcx
        addq	%rbx, %r13
        vpsrlq	$19, %ymm4, %ymm8
        vpsllq	$45, %ymm4, %ymm9
        addq	168(%rsi), %r12
        movq	%r10, %rbx
        xorq	%rax, %rcx
        vpsrlq	$61, %ymm4, %ymm10
        vpsllq	$3, %ymm4, %ymm11
        xorq	%r11, %rbx
        rorxq	$41, %r9, %rax
        xorq	%rcx, %rax
        vpor	%ymm9, %ymm8, %ymm8
        vpor	%ymm11, %ymm10, %ymm10
        andq	%r9, %rbx
        addq	%rax, %r12
        rorxq	$28, %r13, %rax
        rorxq	$34, %r13, %rcx
        xorq	%r11, %rbx
        xorq	%rax, %rcx
        vpxor	%ymm10, %ymm8, %ymm8
        vpsrlq	$6, %ymm4, %ymm11
        rorxq	$39, %r13, %rax
        addq	%rbx, %r12
        xorq	%rcx, %rax
        movq	%r14, %rbx
        leaq	(%r8,%r12,1), %r8
        xorq	%r13, %rbx
        vpxor	%ymm11, %ymm8, %ymm8
        andq	%rbx, %rdx
        addq	%rax, %r12
        xorq	%r14, %rdx
        vpaddq	%ymm5, %ymm8, %ymm5
        # msg_sched done: 20-21
        # msg_sched: 24-25
        rorxq	$14, %r8, %rax
        rorxq	$18, %r8, %rcx
        addq	%rdx, %r12
        vpalignr	$8, %ymm6, %ymm7, %ymm12
        addq	192(%rsi), %r11
        movq	%r9, %rdx
        xorq	%rax, %rcx
        vpalignr	$8, %ymm2, %ymm3, %ymm13
        xorq	%r10, %rdx
        rorxq	$41, %r8, %rax
        xorq	%rcx, %rax
        vpsrlq	$0x01, %ymm12, %ymm8
        vpsllq	$63, %ymm12, %ymm9
        andq	%r8, %rdx
        addq	%rax, %r11
        rorxq	$28, %r12, %rax
        vpsrlq	$8, %ymm12, %ymm10
        vpsllq	$56, %ymm12, %ymm11
        rorxq	$34, %r12, %rcx
        xorq	%r10, %rdx
        xorq	%rax, %rcx
        vpor	%ymm9, %ymm8, %ymm8
        vpor	%ymm11, %ymm10, %ymm10
        rorxq	$39, %r12, %rax
        addq	%rdx, %r11
        xorq	%rcx, %rax
        vpsrlq	$7, %ymm12, %ymm11
        vpxor	%ymm10, %ymm8, %ymm8
        movq	%r13, %rdx
        addq	%r11, %r15
        xorq	%r12, %rdx
        vpxor	%ymm11, %ymm8, %ymm8
        vpaddq	%ymm6, %ymm13, %ymm6
        andq	%rdx, %rbx
        addq	%rax, %r11
        xorq	%r13, %rbx
        vpaddq	%ymm6, %ymm8, %ymm6
        rorxq	$14, %r15, %rax
        rorxq	$18, %r15, %rcx
        addq	%rbx, %r11
        vpsrlq	$19, %ymm5, %ymm8
        vpsllq	$45, %ymm5, %ymm9
        addq	200(%rsi), %r10
        movq	%r8, %rbx
        xorq	%rax, %rcx
        vpsrlq	$61, %ymm5, %ymm10
        vpsllq	$3, %ymm5, %ymm11
        xorq	%r9, %rbx
        rorxq	$41, %r15, %rax
        xorq	%rcx, %rax
        vpor	%ymm9, %ymm8, %ymm8
        vpor	%ymm11, %ymm10, %ymm10
        andq	%r15, %rbx
        addq	%rax, %r10
        rorxq	$28, %r11, %rax
        rorxq	$34, %r11, %rcx
        xorq	%r9, %rbx
        xorq	%rax, %rcx
        vpxor	%ymm10, %ymm8, %ymm8
        vpsrlq	$6, %ymm5, %ymm11
        rorxq	$39, %r11, %rax
        addq	%rbx, %r10
        xorq	%rcx, %rax
        movq	%r12, %rbx
        leaq	(%r14,%r10,1), %r14
        xorq	%r11, %rbx
        vpxor	%ymm11, %ymm8, %ymm8
        andq	%rbx, %rdx
        addq	%rax, %r10
        xorq	%r12, %rdx
        vpaddq	%ymm6, %ymm8, %ymm6
        # msg_sched done: 24-25
        # msg_sched: 28-29
        rorxq	$14, %r14, %rax
        rorxq	$18, %r14, %rcx
        addq	%rdx, %r10
        vpalignr	$8, %ymm7, %ymm0, %ymm12
        addq	224(%rsi), %r9
        movq	%r15, %rdx
        xorq	%rax, %rcx
        vpalignr	$8, %ymm3, %ymm4, %ymm13
        xorq	%r8, %rdx
        rorxq	$41, %r14, %rax
        xorq	%rcx, %rax
        vpsrlq	$0x01, %ymm12, %ymm8
        vpsllq	$63, %ymm12, %ymm9
        andq	%r14, %rdx
        addq	%rax, %r9
        rorxq	$28, %r10, %rax
        vpsrlq	$8, %ymm12, %ymm10
        vpsllq	$56, %ymm12, %ymm11
        rorxq	$34, %r10, %rcx
        xorq	%r8, %rdx
        xorq	%rax, %rcx
        vpor	%ymm9, %ymm8, %ymm8
        vpor	%ymm11, %ymm10, %ymm10
        rorxq	$39, %r10, %rax
        addq	%rdx, %r9
        xorq	%rcx, %rax
        vpsrlq	$7, %ymm12, %ymm11
        vpxor	%ymm10, %ymm8, %ymm8
        movq	%r11, %rdx
        addq	%r9, %r13
        xorq	%r10, %rdx
        vpxor	%ymm11, %ymm8, %ymm8
        vpaddq	%ymm7, %ymm13, %ymm7
        andq	%rdx, %rbx
        addq	%rax, %r9
        xorq	%r11, %rbx
        vpaddq	%ymm7, %ymm8, %ymm7
        rorxq	$14, %r13, %rax
        rorxq	$18, %r13, %rcx
        addq	%rbx, %r9
        vpsrlq	$19, %ymm6, %ymm8
        vpsllq	$45, %ymm6, %ymm9
        addq	232(%rsi), %r8
        movq	%r14, %rbx
        xorq	%rax, %rcx
        vpsrlq	$61, %ymm6, %ymm10
        vpsllq	$3, %ymm6, %ymm11
        xorq	%r15, %rbx
        rorxq	$41, %r13, %rax
        xorq	%rcx, %rax
        vpor	%ymm9, %ymm8, %ymm8
        vpor	%ymm11, %ymm10, %ymm10
        andq	%r13, %rbx
        addq	%rax, %r8
        rorxq	$28, %r9, %rax
        rorxq	$34, %r9, %rcx
        xorq	%r15, %rbx
        xorq	%rax, %rcx
        vpxor	%ymm10, %ymm8, %ymm8
        vpsrlq	$6, %ymm6, %ymm11
        rorxq	$39, %r9, %rax
        addq	%rbx, %r8
        xorq	%rcx, %rax
        movq	%r10, %rbx
        leaq	(%r12,%r8,1), %r12
        xorq	%r9, %rbx
        vpxor	%ymm11, %ymm8, %ymm8
        andq	%rbx, %rdx
        addq	%rax, %r8
        xorq	%r10, %rdx
        vpaddq	%ymm7, %ymm8, %ymm7
        # msg_sched done: 28-29
        addq	$0x100, %rbp
        addq	$0x100, %rsi
        cmpq	L_avx2_rorx_sha512_k_2_end(%rip), %rbp
        jne	L_sha512_len_avx2_rorx_start
        vpaddq	(%rbp), %ymm0, %ymm8
        vpaddq	32(%rbp), %ymm1, %ymm9
        vmovdqu	%ymm8, (%rsi)
        vmovdqu	%ymm9, 32(%rsi)
        vpaddq	64(%rbp), %ymm2, %ymm8
        vpaddq	96(%rbp), %ymm3, %ymm9
        vmovdqu	%ymm8, 64(%rsi)
        vmovdqu	%ymm9, 96(%rsi)
        vpaddq	128(%rbp), %ymm4, %ymm8
        vpaddq	160(%rbp), %ymm5, %ymm9
        vmovdqu	%ymm8, 128(%rsi)
        vmovdqu	%ymm9, 160(%rsi)
        vpaddq	192(%rbp), %ymm6, %ymm8
        vpaddq	224(%rbp), %ymm7, %ymm9
        vmovdqu	%ymm8, 192(%rsi)
        vmovdqu	%ymm9, 224(%rsi)
        # rnd_all_2: 0-1
        rorxq	$14, %r12, %rax
        rorxq	$18, %r12, %rcx
        addq	%rdx, %r8
        addq	(%rsi), %r15
        movq	%r13, %rdx
        xorq	%rax, %rcx
        xorq	%r14, %rdx
        rorxq	$41, %r12, %rax
        xorq	%rcx, %rax
        andq	%r12, %rdx
        addq	%rax, %r15
        rorxq	$28, %r8, %rax
        rorxq	$34, %r8, %rcx
        xorq	%r14, %rdx
        xorq	%rax, %rcx
        rorxq	$39, %r8, %rax
        addq	%rdx, %r15
        xorq	%rcx, %rax
        movq	%r9, %rdx
        addq	%r15, %r11
        xorq	%r8, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r15
        xorq	%r9, %rbx
        rorxq	$14, %r11, %rax
        rorxq	$18, %r11, %rcx
        addq	%rbx, %r15
        addq	8(%rsi), %r14
        movq	%r12, %rbx
        xorq	%rax, %rcx
        xorq	%r13, %rbx
        rorxq	$41, %r11, %rax
        xorq	%rcx, %rax
        andq	%r11, %rbx
        addq	%rax, %r14
        rorxq	$28, %r15, %rax
        rorxq	$34, %r15, %rcx
        xorq	%r13, %rbx
        xorq	%rax, %rcx
        rorxq	$39, %r15, %rax
        addq	%rbx, %r14
        xorq	%rcx, %rax
        movq	%r8, %rbx
        leaq	(%r10,%r14,1), %r10
        xorq	%r15, %rbx
        andq	%rbx, %rdx
        addq	%rax, %r14
        xorq	%r8, %rdx
        # rnd_all_2: 4-5
        rorxq	$14, %r10, %rax
        rorxq	$18, %r10, %rcx
        addq	%rdx, %r14
        addq	32(%rsi), %r13
        movq	%r11, %rdx
        xorq	%rax, %rcx
        xorq	%r12, %rdx
        rorxq	$41, %r10, %rax
        xorq	%rcx, %rax
        andq	%r10, %rdx
        addq	%rax, %r13
        rorxq	$28, %r14, %rax
        rorxq	$34, %r14, %rcx
        xorq	%r12, %rdx
        xorq	%rax, %rcx
        rorxq	$39, %r14, %rax
        addq	%rdx, %r13
        xorq	%rcx, %rax
        movq	%r15, %rdx
        addq	%r13, %r9
        xorq	%r14, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r13
        xorq	%r15, %rbx
        rorxq	$14, %r9, %rax
        rorxq	$18, %r9, %rcx
        addq	%rbx, %r13
        addq	40(%rsi), %r12
        movq	%r10, %rbx
        xorq	%rax, %rcx
        xorq	%r11, %rbx
        rorxq	$41, %r9, %rax
        xorq	%rcx, %rax
        andq	%r9, %rbx
        addq	%rax, %r12
        rorxq	$28, %r13, %rax
        rorxq	$34, %r13, %rcx
        xorq	%r11, %rbx
        xorq	%rax, %rcx
        rorxq	$39, %r13, %rax
        addq	%rbx, %r12
        xorq	%rcx, %rax
        movq	%r14, %rbx
        leaq	(%r8,%r12,1), %r8
        xorq	%r13, %rbx
        andq	%rbx, %rdx
        addq	%rax, %r12
        xorq	%r14, %rdx
        # rnd_all_2: 8-9
        rorxq	$14, %r8, %rax
        rorxq	$18, %r8, %rcx
        addq	%rdx, %r12
        addq	64(%rsi), %r11
        movq	%r9, %rdx
        xorq	%rax, %rcx
        xorq	%r10, %rdx
        rorxq	$41, %r8, %rax
        xorq	%rcx, %rax
        andq	%r8, %rdx
        addq	%rax, %r11
        rorxq	$28, %r12, %rax
        rorxq	$34, %r12, %rcx
        xorq	%r10, %rdx
        xorq	%rax, %rcx
        rorxq	$39, %r12, %rax
        addq	%rdx, %r11
        xorq	%rcx, %rax
        movq	%r13, %rdx
        addq	%r11, %r15
        xorq	%r12, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r11
        xorq	%r13, %rbx
        rorxq	$14, %r15, %rax
        rorxq	$18, %r15, %rcx
        addq	%rbx, %r11
        addq	72(%rsi), %r10
        movq	%r8, %rbx
        xorq	%rax, %rcx
        xorq	%r9, %rbx
        rorxq	$41, %r15, %rax
        xorq	%rcx, %rax
        andq	%r15, %rbx
        addq	%rax, %r10
        rorxq	$28, %r11, %rax
        rorxq	$34, %r11, %rcx
        xorq	%r9, %rbx
        xorq	%rax, %rcx
        rorxq	$39, %r11, %rax
        addq	%rbx, %r10
        xorq	%rcx, %rax
        movq	%r12, %rbx
        leaq	(%r14,%r10,1), %r14
        xorq	%r11, %rbx
        andq	%rbx, %rdx
        addq	%rax, %r10
        xorq	%r12, %rdx
        # rnd_all_2: 12-13
        rorxq	$14, %r14, %rax
        rorxq	$18, %r14, %rcx
        addq	%rdx, %r10
        addq	96(%rsi), %r9
        movq	%r15, %rdx
        xorq	%rax, %rcx
        xorq	%r8, %rdx
        rorxq	$41, %r14, %rax
        xorq	%rcx, %rax
        andq	%r14, %rdx
        addq	%rax, %r9
        rorxq	$28, %r10, %rax
        rorxq	$34, %r10, %rcx
        xorq	%r8, %rdx
        xorq	%rax, %rcx
        rorxq	$39, %r10, %rax
        addq	%rdx, %r9
        xorq	%rcx, %rax
        movq	%r11, %rdx
        addq	%r9, %r13
        xorq	%r10, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r9
        xorq	%r11, %rbx
        rorxq	$14, %r13, %rax
        rorxq	$18, %r13, %rcx
        addq	%rbx, %r9
        addq	104(%rsi), %r8
        movq	%r14, %rbx
        xorq	%rax, %rcx
        xorq	%r15, %rbx
        rorxq	$41, %r13, %rax
        xorq	%rcx, %rax
        andq	%r13, %rbx
        addq	%rax, %r8
        rorxq	$28, %r9, %rax
        rorxq	$34, %r9, %rcx
        xorq	%r15, %rbx
        xorq	%rax, %rcx
        rorxq	$39, %r9, %rax
        addq	%rbx, %r8
        xorq	%rcx, %rax
        movq	%r10, %rbx
        leaq	(%r12,%r8,1), %r12
        xorq	%r9, %rbx
        andq	%rbx, %rdx
        addq	%rax, %r8
        xorq	%r10, %rdx
        # rnd_all_2: 16-17
        rorxq	$14, %r12, %rax
        rorxq	$18, %r12, %rcx
        addq	%rdx, %r8
        addq	128(%rsi), %r15
        movq	%r13, %rdx
        xorq	%rax, %rcx
        xorq	%r14, %rdx
        rorxq	$41, %r12, %rax
        xorq	%rcx, %rax
        andq	%r12, %rdx
        addq	%rax, %r15
        rorxq	$28, %r8, %rax
        rorxq	$34, %r8, %rcx
        xorq	%r14, %rdx
        xorq	%rax, %rcx
        rorxq	$39, %r8, %rax
        addq	%rdx, %r15
        xorq	%rcx, %rax
        movq	%r9, %rdx
        addq	%r15, %r11
        xorq	%r8, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r15
        xorq	%r9, %rbx
        rorxq	$14, %r11, %rax
        rorxq	$18, %r11, %rcx
        addq	%rbx, %r15
        addq	136(%rsi), %r14
        movq	%r12, %rbx
        xorq	%rax, %rcx
        xorq	%r13, %rbx
        rorxq	$41, %r11, %rax
        xorq	%rcx, %rax
        andq	%r11, %rbx
        addq	%rax, %r14
        rorxq	$28, %r15, %rax
        rorxq	$34, %r15, %rcx
        xorq	%r13, %rbx
        xorq	%rax, %rcx
        rorxq	$39, %r15, %rax
        addq	%rbx, %r14
        xorq	%rcx, %rax
        movq	%r8, %rbx
        leaq	(%r10,%r14,1), %r10
        xorq	%r15, %rbx
        andq	%rbx, %rdx
        addq	%rax, %r14
        xorq	%r8, %rdx
        # rnd_all_2: 20-21
        rorxq	$14, %r10, %rax
        rorxq	$18, %r10, %rcx
        addq	%rdx, %r14
        addq	160(%rsi), %r13
        movq	%r11, %rdx
        xorq	%rax, %rcx
        xorq	%r12, %rdx
        rorxq	$41, %r10, %rax
        xorq	%rcx, %rax
        andq	%r10, %rdx
        addq	%rax, %r13
        rorxq	$28, %r14, %rax
        rorxq	$34, %r14, %rcx
        xorq	%r12, %rdx
        xorq	%rax, %rcx
        rorxq	$39, %r14, %rax
        addq	%rdx, %r13
        xorq	%rcx, %rax
        movq	%r15, %rdx
        addq	%r13, %r9
        xorq	%r14, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r13
        xorq	%r15, %rbx
        rorxq	$14, %r9, %rax
        rorxq	$18, %r9, %rcx
        addq	%rbx, %r13
        addq	168(%rsi), %r12
        movq	%r10, %rbx
        xorq	%rax, %rcx
        xorq	%r11, %rbx
        rorxq	$41, %r9, %rax
        xorq	%rcx, %rax
        andq	%r9, %rbx
        addq	%rax, %r12
        rorxq	$28, %r13, %rax
        rorxq	$34, %r13, %rcx
        xorq	%r11, %rbx
        xorq	%rax, %rcx
        rorxq	$39, %r13, %rax
        addq	%rbx, %r12
        xorq	%rcx, %rax
        movq	%r14, %rbx
        leaq	(%r8,%r12,1), %r8
        xorq	%r13, %rbx
        andq	%rbx, %rdx
        addq	%rax, %r12
        xorq	%r14, %rdx
        # rnd_all_2: 24-25
        rorxq	$14, %r8, %rax
        rorxq	$18, %r8, %rcx
        addq	%rdx, %r12
        addq	192(%rsi), %r11
        movq	%r9, %rdx
        xorq	%rax, %rcx
        xorq	%r10, %rdx
        rorxq	$41, %r8, %rax
        xorq	%rcx, %rax
        andq	%r8, %rdx
        addq	%rax, %r11
        rorxq	$28, %r12, %rax
        rorxq	$34, %r12, %rcx
        xorq	%r10, %rdx
        xorq	%rax, %rcx
        rorxq	$39, %r12, %rax
        addq	%rdx, %r11
        xorq	%rcx, %rax
        movq	%r13, %rdx
        addq	%r11, %r15
        xorq	%r12, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r11
        xorq	%r13, %rbx
        rorxq	$14, %r15, %rax
        rorxq	$18, %r15, %rcx
        addq	%rbx, %r11
        addq	200(%rsi), %r10
        movq	%r8, %rbx
        xorq	%rax, %rcx
        xorq	%r9, %rbx
        rorxq	$41, %r15, %rax
        xorq	%rcx, %rax
        andq	%r15, %rbx
        addq	%rax, %r10
        rorxq	$28, %r11, %rax
        rorxq	$34, %r11, %rcx
        xorq	%r9, %rbx
        xorq	%rax, %rcx
        rorxq	$39, %r11, %rax
        addq	%rbx, %r10
        xorq	%rcx, %rax
        movq	%r12, %rbx
        leaq	(%r14,%r10,1), %r14
        xorq	%r11, %rbx
        andq	%rbx, %rdx
        addq	%rax, %r10
        xorq	%r12, %rdx
        # rnd_all_2: 28-29
        rorxq	$14, %r14, %rax
        rorxq	$18, %r14, %rcx
        addq	%rdx, %r10
        addq	224(%rsi), %r9
        movq	%r15, %rdx
        xorq	%rax, %rcx
        xorq	%r8, %rdx
        rorxq	$41, %r14, %rax
        xorq	%rcx, %rax
        andq	%r14, %rdx
        addq	%rax, %r9
        rorxq	$28, %r10, %rax
        rorxq	$34, %r10, %rcx
        xorq	%r8, %rdx
        xorq	%rax, %rcx
        rorxq	$39, %r10, %rax
        addq	%rdx, %r9
        xorq	%rcx, %rax
        movq	%r11, %rdx
        addq	%r9, %r13
        xorq	%r10, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r9
        xorq	%r11, %rbx
        rorxq	$14, %r13, %rax
        rorxq	$18, %r13, %rcx
        addq	%rbx, %r9
        addq	232(%rsi), %r8
        movq	%r14, %rbx
        xorq	%rax, %rcx
        xorq	%r15, %rbx
        rorxq	$41, %r13, %rax
        xorq	%rcx, %rax
        andq	%r13, %rbx
        addq	%rax, %r8
        rorxq	$28, %r9, %rax
        rorxq	$34, %r9, %rcx
        xorq	%r15, %rbx
        xorq	%rax, %rcx
        rorxq	$39, %r9, %rax
        addq	%rbx, %r8
        xorq	%rcx, %rax
        movq	%r10, %rbx
        leaq	(%r12,%r8,1), %r12
        xorq	%r9, %rbx
        andq	%rbx, %rdx
        addq	%rax, %r8
        xorq	%r10, %rdx
        addq	%rdx, %r8
        subq	$0x400, %rsi
        addq	(%rdi), %r8
        addq	8(%rdi), %r9
        addq	16(%rdi), %r10
        addq	24(%rdi), %r11
        addq	32(%rdi), %r12
        addq	40(%rdi), %r13
        addq	48(%rdi), %r14
        addq	56(%rdi), %r15
        movq	%r8, (%rdi)
        movq	%r9, 8(%rdi)
        movq	%r10, 16(%rdi)
        movq	%r11, 24(%rdi)
        movq	%r12, 32(%rdi)
        movq	%r13, 40(%rdi)
        movq	%r14, 48(%rdi)
        movq	%r15, 56(%rdi)
        movq	%r9, %rbx
        xorq	%rdx, %rdx
        xorq	%r10, %rbx
        movq	$5, %rbp
L_sha512_len_avx2_rorx_tail:
        # rnd_all_2: 2-3
        rorxq	$14, %r12, %rax
        rorxq	$18, %r12, %rcx
        addq	%rdx, %r8
        addq	16(%rsi), %r15
        movq	%r13, %rdx
        xorq	%rax, %rcx
        xorq	%r14, %rdx
        rorxq	$41, %r12, %rax
        xorq	%rcx, %rax
        andq	%r12, %rdx
        addq	%rax, %r15
        rorxq	$28, %r8, %rax
        rorxq	$34, %r8, %rcx
        xorq	%r14, %rdx
        xorq	%rax, %rcx
        rorxq	$39, %r8, %rax
        addq	%rdx, %r15
        xorq	%rcx, %rax
        movq	%r9, %rdx
        addq	%r15, %r11
        xorq	%r8, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r15
        xorq	%r9, %rbx
        rorxq	$14, %r11, %rax
        rorxq	$18, %r11, %rcx
        addq	%rbx, %r15
        addq	24(%rsi), %r14
        movq	%r12, %rbx
        xorq	%rax, %rcx
        xorq	%r13, %rbx
        rorxq	$41, %r11, %rax
        xorq	%rcx, %rax
        andq	%r11, %rbx
        addq	%rax, %r14
        rorxq	$28, %r15, %rax
        rorxq	$34, %r15, %rcx
        xorq	%r13, %rbx
        xorq	%rax, %rcx
        rorxq	$39, %r15, %rax
        addq	%rbx, %r14
        xorq	%rcx, %rax
        movq	%r8, %rbx
        leaq	(%r10,%r14,1), %r10
        xorq	%r15, %rbx
        andq	%rbx, %rdx
        addq	%rax, %r14
        xorq	%r8, %rdx
        # rnd_all_2: 6-7
        rorxq	$14, %r10, %rax
        rorxq	$18, %r10, %rcx
        addq	%rdx, %r14
        addq	48(%rsi), %r13
        movq	%r11, %rdx
        xorq	%rax, %rcx
        xorq	%r12, %rdx
        rorxq	$41, %r10, %rax
        xorq	%rcx, %rax
        andq	%r10, %rdx
        addq	%rax, %r13
        rorxq	$28, %r14, %rax
        rorxq	$34, %r14, %rcx
        xorq	%r12, %rdx
        xorq	%rax, %rcx
        rorxq	$39, %r14, %rax
        addq	%rdx, %r13
        xorq	%rcx, %rax
        movq	%r15, %rdx
        addq	%r13, %r9
        xorq	%r14, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r13
        xorq	%r15, %rbx
        rorxq	$14, %r9, %rax
        rorxq	$18, %r9, %rcx
        addq	%rbx, %r13
        addq	56(%rsi), %r12
        movq	%r10, %rbx
        xorq	%rax, %rcx
        xorq	%r11, %rbx
        rorxq	$41, %r9, %rax
        xorq	%rcx, %rax
        andq	%r9, %rbx
        addq	%rax, %r12
        rorxq	$28, %r13, %rax
        rorxq	$34, %r13, %rcx
        xorq	%r11, %rbx
        xorq	%rax, %rcx
        rorxq	$39, %r13, %rax
        addq	%rbx, %r12
        xorq	%rcx, %rax
        movq	%r14, %rbx
        leaq	(%r8,%r12,1), %r8
        xorq	%r13, %rbx
        andq	%rbx, %rdx
        addq	%rax, %r12
        xorq	%r14, %rdx
        # rnd_all_2: 10-11
        rorxq	$14, %r8, %rax
        rorxq	$18, %r8, %rcx
        addq	%rdx, %r12
        addq	80(%rsi), %r11
        movq	%r9, %rdx
        xorq	%rax, %rcx
        xorq	%r10, %rdx
        rorxq	$41, %r8, %rax
        xorq	%rcx, %rax
        andq	%r8, %rdx
        addq	%rax, %r11
        rorxq	$28, %r12, %rax
        rorxq	$34, %r12, %rcx
        xorq	%r10, %rdx
        xorq	%rax, %rcx
        rorxq	$39, %r12, %rax
        addq	%rdx, %r11
        xorq	%rcx, %rax
        movq	%r13, %rdx
        addq	%r11, %r15
        xorq	%r12, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r11
        xorq	%r13, %rbx
        rorxq	$14, %r15, %rax
        rorxq	$18, %r15, %rcx
        addq	%rbx, %r11
        addq	88(%rsi), %r10
        movq	%r8, %rbx
        xorq	%rax, %rcx
        xorq	%r9, %rbx
        rorxq	$41, %r15, %rax
        xorq	%rcx, %rax
        andq	%r15, %rbx
        addq	%rax, %r10
        rorxq	$28, %r11, %rax
        rorxq	$34, %r11, %rcx
        xorq	%r9, %rbx
        xorq	%rax, %rcx
        rorxq	$39, %r11, %rax
        addq	%rbx, %r10
        xorq	%rcx, %rax
        movq	%r12, %rbx
        leaq	(%r14,%r10,1), %r14
        xorq	%r11, %rbx
        andq	%rbx, %rdx
        addq	%rax, %r10
        xorq	%r12, %rdx
        # rnd_all_2: 14-15
        rorxq	$14, %r14, %rax
        rorxq	$18, %r14, %rcx
        addq	%rdx, %r10
        addq	112(%rsi), %r9
        movq	%r15, %rdx
        xorq	%rax, %rcx
        xorq	%r8, %rdx
        rorxq	$41, %r14, %rax
        xorq	%rcx, %rax
        andq	%r14, %rdx
        addq	%rax, %r9
        rorxq	$28, %r10, %rax
        rorxq	$34, %r10, %rcx
        xorq	%r8, %rdx
        xorq	%rax, %rcx
        rorxq	$39, %r10, %rax
        addq	%rdx, %r9
        xorq	%rcx, %rax
        movq	%r11, %rdx
        addq	%r9, %r13
        xorq	%r10, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r9
        xorq	%r11, %rbx
        rorxq	$14, %r13, %rax
        rorxq	$18, %r13, %rcx
        addq	%rbx, %r9
        addq	120(%rsi), %r8
        movq	%r14, %rbx
        xorq	%rax, %rcx
        xorq	%r15, %rbx
        rorxq	$41, %r13, %rax
        xorq	%rcx, %rax
        andq	%r13, %rbx
        addq	%rax, %r8
        rorxq	$28, %r9, %rax
        rorxq	$34, %r9, %rcx
        xorq	%r15, %rbx
        xorq	%rax, %rcx
        rorxq	$39, %r9, %rax
        addq	%rbx, %r8
        xorq	%rcx, %rax
        movq	%r10, %rbx
        leaq	(%r12,%r8,1), %r12
        xorq	%r9, %rbx
        andq	%rbx, %rdx
        addq	%rax, %r8
        xorq	%r10, %rdx
        # rnd_all_2: 18-19
        rorxq	$14, %r12, %rax
        rorxq	$18, %r12, %rcx
        addq	%rdx, %r8
        addq	144(%rsi), %r15
        movq	%r13, %rdx
        xorq	%rax, %rcx
        xorq	%r14, %rdx
        rorxq	$41, %r12, %rax
        xorq	%rcx, %rax
        andq	%r12, %rdx
        addq	%rax, %r15
        rorxq	$28, %r8, %rax
        rorxq	$34, %r8, %rcx
        xorq	%r14, %rdx
        xorq	%rax, %rcx
        rorxq	$39, %r8, %rax
        addq	%rdx, %r15
        xorq	%rcx, %rax
        movq	%r9, %rdx
        addq	%r15, %r11
        xorq	%r8, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r15
        xorq	%r9, %rbx
        rorxq	$14, %r11, %rax
        rorxq	$18, %r11, %rcx
        addq	%rbx, %r15
        addq	152(%rsi), %r14
        movq	%r12, %rbx
        xorq	%rax, %rcx
        xorq	%r13, %rbx
        rorxq	$41, %r11, %rax
        xorq	%rcx, %rax
        andq	%r11, %rbx
        addq	%rax, %r14
        rorxq	$28, %r15, %rax
        rorxq	$34, %r15, %rcx
        xorq	%r13, %rbx
        xorq	%rax, %rcx
        rorxq	$39, %r15, %rax
        addq	%rbx, %r14
        xorq	%rcx, %rax
        movq	%r8, %rbx
        leaq	(%r10,%r14,1), %r10
        xorq	%r15, %rbx
        andq	%rbx, %rdx
        addq	%rax, %r14
        xorq	%r8, %rdx
        # rnd_all_2: 22-23
        rorxq	$14, %r10, %rax
        rorxq	$18, %r10, %rcx
        addq	%rdx, %r14
        addq	176(%rsi), %r13
        movq	%r11, %rdx
        xorq	%rax, %rcx
        xorq	%r12, %rdx
        rorxq	$41, %r10, %rax
        xorq	%rcx, %rax
        andq	%r10, %rdx
        addq	%rax, %r13
        rorxq	$28, %r14, %rax
        rorxq	$34, %r14, %rcx
        xorq	%r12, %rdx
        xorq	%rax, %rcx
        rorxq	$39, %r14, %rax
        addq	%rdx, %r13
        xorq	%rcx, %rax
        movq	%r15, %rdx
        addq	%r13, %r9
        xorq	%r14, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r13
        xorq	%r15, %rbx
        rorxq	$14, %r9, %rax
        rorxq	$18, %r9, %rcx
        addq	%rbx, %r13
        addq	184(%rsi), %r12
        movq	%r10, %rbx
        xorq	%rax, %rcx
        xorq	%r11, %rbx
        rorxq	$41, %r9, %rax
        xorq	%rcx, %rax
        andq	%r9, %rbx
        addq	%rax, %r12
        rorxq	$28, %r13, %rax
        rorxq	$34, %r13, %rcx
        xorq	%r11, %rbx
        xorq	%rax, %rcx
        rorxq	$39, %r13, %rax
        addq	%rbx, %r12
        xorq	%rcx, %rax
        movq	%r14, %rbx
        leaq	(%r8,%r12,1), %r8
        xorq	%r13, %rbx
        andq	%rbx, %rdx
        addq	%rax, %r12
        xorq	%r14, %rdx
        # rnd_all_2: 26-27
        rorxq	$14, %r8, %rax
        rorxq	$18, %r8, %rcx
        addq	%rdx, %r12
        addq	208(%rsi), %r11
        movq	%r9, %rdx
        xorq	%rax, %rcx
        xorq	%r10, %rdx
        rorxq	$41, %r8, %rax
        xorq	%rcx, %rax
        andq	%r8, %rdx
        addq	%rax, %r11
        rorxq	$28, %r12, %rax
        rorxq	$34, %r12, %rcx
        xorq	%r10, %rdx
        xorq	%rax, %rcx
        rorxq	$39, %r12, %rax
        addq	%rdx, %r11
        xorq	%rcx, %rax
        movq	%r13, %rdx
        addq	%r11, %r15
        xorq	%r12, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r11
        xorq	%r13, %rbx
        rorxq	$14, %r15, %rax
        rorxq	$18, %r15, %rcx
        addq	%rbx, %r11
        addq	216(%rsi), %r10
        movq	%r8, %rbx
        xorq	%rax, %rcx
        xorq	%r9, %rbx
        rorxq	$41, %r15, %rax
        xorq	%rcx, %rax
        andq	%r15, %rbx
        addq	%rax, %r10
        rorxq	$28, %r11, %rax
        rorxq	$34, %r11, %rcx
        xorq	%r9, %rbx
        xorq	%rax, %rcx
        rorxq	$39, %r11, %rax
        addq	%rbx, %r10
        xorq	%rcx, %rax
        movq	%r12, %rbx
        leaq	(%r14,%r10,1), %r14
        xorq	%r11, %rbx
        andq	%rbx, %rdx
        addq	%rax, %r10
        xorq	%r12, %rdx
        # rnd_all_2: 30-31
        rorxq	$14, %r14, %rax
        rorxq	$18, %r14, %rcx
        addq	%rdx, %r10
        addq	240(%rsi), %r9
        movq	%r15, %rdx
        xorq	%rax, %rcx
        xorq	%r8, %rdx
        rorxq	$41, %r14, %rax
        xorq	%rcx, %rax
        andq	%r14, %rdx
        addq	%rax, %r9
        rorxq	$28, %r10, %rax
        rorxq	$34, %r10, %rcx
        xorq	%r8, %rdx
        xorq	%rax, %rcx
        rorxq	$39, %r10, %rax
        addq	%rdx, %r9
        xorq	%rcx, %rax
        movq	%r11, %rdx
        addq	%r9, %r13
        xorq	%r10, %rdx
        andq	%rdx, %rbx
        addq	%rax, %r9
        xorq	%r11, %rbx
        rorxq	$14, %r13, %rax
        rorxq	$18, %r13, %rcx
        addq	%rbx, %r9
        addq	248(%rsi), %r8
        movq	%r14, %rbx
        xorq	%rax, %rcx
        xorq	%r15, %rbx
        rorxq	$41, %r13, %rax
        xorq	%rcx, %rax
        andq	%r13, %rbx
        addq	%rax, %r8
        rorxq	$28, %r9, %rax
        rorxq	$34, %r9, %rcx
        xorq	%r15, %rbx
        xorq	%rax, %rcx
        rorxq	$39, %r9, %rax
        addq	%rbx, %r8
        xorq	%rcx, %rax
        movq	%r10, %rbx
        leaq	(%r12,%r8,1), %r12
        xorq	%r9, %rbx
        andq	%rbx, %rdx
        addq	%rax, %r8
        xorq	%r10, %rdx
        addq	$0x100, %rsi
        subq	$0x01, %rbp
        jnz	L_sha512_len_avx2_rorx_tail
        addq	%rdx, %r8
        addq	(%rdi), %r8
        addq	8(%rdi), %r9
        addq	16(%rdi), %r10
        addq	24(%rdi), %r11
        addq	32(%rdi), %r12
        addq	40(%rdi), %r13
        addq	48(%rdi), %r14
        addq	56(%rdi), %r15
        movq	224(%rdi), %rax
        addq	$0x100, %rax
        subl	$0x100, 1344(%rsp)
        movq	%rax, 224(%rdi)
        movq	%r8, (%rdi)
        movq	%r9, 8(%rdi)
        movq	%r10, 16(%rdi)
        movq	%r11, 24(%rdi)
        movq	%r12, 32(%rdi)
        movq	%r13, 40(%rdi)
        movq	%r14, 48(%rdi)
        movq	%r15, 56(%rdi)
        jnz	L_sha512_len_avx2_rorx_begin
        addq	$0x548, %rsp
L_sha512_len_avx2_rorx_done:
        xorq	%rax, %rax
        vzeroupper
        popq	%rbp
        popq	%r15
        popq	%r14
        popq	%r13
        popq	%r12
        popq	%rbx
        repz retq
#ifndef __APPLE__
.size	Transform_Sha512_AVX2_RORX_Len,.-Transform_Sha512_AVX2_RORX_Len
#endif /* __APPLE__ */
#ifdef WOLFSSL_HAVE_XMSS
#ifndef NO_AVX512_SUPPORT
#ifndef HAVE_INTEL_AVX512
#define HAVE_INTEL_AVX512
#endif /* HAVE_INTEL_AVX512 */
#endif /* NO_AVX512_SUPPORT */
#ifdef HAVE_INTEL_AVX512
#ifndef __APPLE__
.data
#else
.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
.align	16
#else
.p2align	4
#endif /* __APPLE__ */
L_avx512_sha512_x8_bswap_mask:
.long	0xff00ff00,0xff00ff00,0xff00ff00,0xff00ff00
.long	0xff00ff00,0xff00ff00,0xff00ff00,0xff00ff00
.long	0xff00ff00,0xff00ff00,0xff00ff00,0xff00ff00
.long	0xff00ff00,0xff00ff00,0xff00ff00,0xff00ff00
#ifndef __APPLE__
.data
#else
.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
.align	32
#else
.p2align	5
#endif /* __APPLE__ */
L_avx512_sha512_x8_k:
.quad	0x428a2f98d728ae22,0x7137449123ef65cd
.quad	0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc
.quad	0x3956c25bf348b538,0x59f111f1b605d019
.quad	0x923f82a4af194f9b,0xab1c5ed5da6d8118
.quad	0xd807aa98a3030242,0x12835b0145706fbe
.quad	0x243185be4ee4b28c,0x550c7dc3d5ffb4e2
.quad	0x72be5d74f27b896f,0x80deb1fe3b1696b1
.quad	0x9bdc06a725c71235,0xc19bf174cf692694
.quad	0xe49b69c19ef14ad2,0xefbe4786384f25e3
.quad	0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65
.quad	0x2de92c6f592b0275,0x4a7484aa6ea6e483
.quad	0x5cb0a9dcbd41fbd4,0x76f988da831153b5
.quad	0x983e5152ee66dfab,0xa831c66d2db43210
.quad	0xb00327c898fb213f,0xbf597fc7beef0ee4
.quad	0xc6e00bf33da88fc2,0xd5a79147930aa725
.quad	0x06ca6351e003826f,0x142929670a0e6e70
.quad	0x27b70a8546d22ffc,0x2e1b21385c26c926
.quad	0x4d2c6dfc5ac42aed,0x53380d139d95b3df
.quad	0x650a73548baf63de,0x766a0abb3c77b2a8
.quad	0x81c2c92e47edaee6,0x92722c851482353b
.quad	0xa2bfe8a14cf10364,0xa81a664bbc423001
.quad	0xc24b8b70d0f89791,0xc76c51a30654be30
.quad	0xd192e819d6ef5218,0xd69906245565a910
.quad	0xf40e35855771202a,0x106aa07032bbd1b8
.quad	0x19a4c116b8d2d0c8,0x1e376c085141ab53
.quad	0x2748774cdf8eeb99,0x34b0bcb5e19b48a8
.quad	0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb
.quad	0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3
.quad	0x748f82ee5defb2fc,0x78a5636f43172f60
.quad	0x84c87814a1f0ab72,0x8cc702081a6439ec
.quad	0x90befffa23631e28,0xa4506cebde82bde9
.quad	0xbef9a3f7b2c67915,0xc67178f2e372532b
.quad	0xca273eceea26619c,0xd186b8c721c0c207
.quad	0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178
.quad	0x06f067aa72176fba,0x0a637dc5a2c898a6
.quad	0x113f9804bef90dae,0x1b710b35131c471b
.quad	0x28db77f523047d84,0x32caab7b40c72493
.quad	0x3c9ebe0a15c9bebc,0x431d67c49c100d4c
.quad	0x4cc5d4becb3e42b6,0x597f299cfc657e2a
.quad	0x5fcb6fab3ad6faec,0x6c44198c4a475817
#ifndef __APPLE__
.text
.globl	Transform_Sha512_x8_AVX512
WC_ASM_ATT_HIDDEN(Transform_Sha512_x8_AVX512)
.type	Transform_Sha512_x8_AVX512,@function
.align	16
Transform_Sha512_x8_AVX512:
#else
.section	__TEXT,__text
.globl	_Transform_Sha512_x8_AVX512
WC_ASM_ATT_HIDDEN(_Transform_Sha512_x8_AVX512)
.p2align	4
_Transform_Sha512_x8_AVX512:
#endif /* __APPLE__ */
        pushq	%rbp
        vmovdqu64	L_avx512_sha512_x8_bswap_mask(%rip), %zmm28
        # W[0..7] of all eight blocks
        vmovdqu64	(%rsi), %zmm8
        vpshufd	$0xb1, %zmm8, %zmm8
        vprord	$8, %zmm8, %zmm29
        vprold	$8, %zmm8, %zmm8
        vpternlogd	$0xd8, %zmm28, %zmm29, %zmm8
        vmovdqu64	128(%rsi), %zmm9
        vpshufd	$0xb1, %zmm9, %zmm9
        vprord	$8, %zmm9, %zmm29
        vprold	$8, %zmm9, %zmm9
        vpternlogd	$0xd8, %zmm28, %zmm29, %zmm9
        vmovdqu64	256(%rsi), %zmm10
        vpshufd	$0xb1, %zmm10, %zmm10
        vprord	$8, %zmm10, %zmm29
        vprold	$8, %zmm10, %zmm10
        vpternlogd	$0xd8, %zmm28, %zmm29, %zmm10
        vmovdqu64	384(%rsi), %zmm11
        vpshufd	$0xb1, %zmm11, %zmm11
        vprord	$8, %zmm11, %zmm29
        vprold	$8, %zmm11, %zmm11
        vpternlogd	$0xd8, %zmm28, %zmm29, %zmm11
        vmovdqu64	512(%rsi), %zmm12
        vpshufd	$0xb1, %zmm12, %zmm12
        vprord	$8, %zmm12, %zmm29
        vprold	$8, %zmm12, %zmm12
        vpternlogd	$0xd8, %zmm28, %zmm29, %zmm12
        vmovdqu64	640(%rsi), %zmm13
        vpshufd	$0xb1, %zmm13, %zmm13
        vprord	$8, %zmm13, %zmm29
        vprold	$8, %zmm13, %zmm13
        vpternlogd	$0xd8, %zmm28, %zmm29, %zmm13
        vmovdqu64	768(%rsi), %zmm14
        vpshufd	$0xb1, %zmm14, %zmm14
        vprord	$8, %zmm14, %zmm29
        vprold	$8, %zmm14, %zmm14
        vpternlogd	$0xd8, %zmm28, %zmm29, %zmm14
        vmovdqu64	896(%rsi), %zmm15
        vpshufd	$0xb1, %zmm15, %zmm15
        vprord	$8, %zmm15, %zmm29
        vprold	$8, %zmm15, %zmm15
        vpternlogd	$0xd8, %zmm28, %zmm29, %zmm15
        vpunpcklqdq	%zmm9, %zmm8, %zmm29
        vpunpckhqdq	%zmm9, %zmm8, %zmm9
        vmovdqa64	%zmm29, %zmm8
        vpunpcklqdq	%zmm11, %zmm10, %zmm29
        vpunpckhqdq	%zmm11, %zmm10, %zmm11
        vmovdqa64	%zmm29, %zmm10
        vpunpcklqdq	%zmm13, %zmm12, %zmm29
        vpunpckhqdq	%zmm13, %zmm12, %zmm13
        vmovdqa64	%zmm29, %zmm12
        vpunpcklqdq	%zmm15, %zmm14, %zmm29
        vpunpckhqdq	%zmm15, %zmm14, %zmm15
        vmovdqa64	%zmm29, %zmm14
        vshufi64x2	$0x88, %zmm10, %zmm8, %zmm29
        vshufi64x2	$0xdd, %zmm10, %zmm8, %zmm10
        vmovdqa64	%zmm29, %zmm8
        vshufi64x2	$0x88, %zmm11, %zmm9, %zmm29
        vshufi64x2	$0xdd, %zmm11, %zmm9, %zmm11
        vmovdqa64	%zmm29, %zmm9
        vshufi64x2	$0x88, %zmm14, %zmm12, %zmm29
        vshufi64x2	$0xdd, %zmm14, %zmm12, %zmm14
        vmovdqa64	%zmm29, %zmm12
        vshufi64x2	$0x88, %zmm15, %zmm13, %zmm29
        vshufi64x2	$0xdd, %zmm15, %zmm13, %zmm15
        vmovdqa64	%zmm29, %zmm13
        vshufi64x2	$0x88, %zmm12, %zmm8, %zmm29
        vshufi64x2	$0xdd, %zmm12, %zmm8, %zmm12
        vmovdqa64	%zmm29, %zmm8
        vshufi64x2	$0x88, %zmm13, %zmm9, %zmm29
        vshufi64x2	$0xdd, %zmm13, %zmm9, %zmm13
        vmovdqa64	%zmm29, %zmm9
        vshufi64x2	$0x88, %zmm14, %zmm10, %zmm29
        vshufi64x2	$0xdd, %zmm14, %zmm10, %zmm14
        vmovdqa64	%zmm29, %zmm10
        vshufi64x2	$0x88, %zmm15, %zmm11, %zmm29
        vshufi64x2	$0xdd, %zmm15, %zmm11, %zmm15
        vmovdqa64	%zmm29, %zmm11
        # W[8..15] of all eight blocks
        vmovdqu64	64(%rsi), %zmm16
        vpshufd	$0xb1, %zmm16, %zmm16
        vprord	$8, %zmm16, %zmm29
        vprold	$8, %zmm16, %zmm16
        vpternlogd	$0xd8, %zmm28, %zmm29, %zmm16
        vmovdqu64	192(%rsi), %zmm17
        vpshufd	$0xb1, %zmm17, %zmm17
        vprord	$8, %zmm17, %zmm29
        vprold	$8, %zmm17, %zmm17
        vpternlogd	$0xd8, %zmm28, %zmm29, %zmm17
        vmovdqu64	320(%rsi), %zmm18
        vpshufd	$0xb1, %zmm18, %zmm18
        vprord	$8, %zmm18, %zmm29
        vprold	$8, %zmm18, %zmm18
        vpternlogd	$0xd8, %zmm28, %zmm29, %zmm18
        vmovdqu64	448(%rsi), %zmm19
        vpshufd	$0xb1, %zmm19, %zmm19
        vprord	$8, %zmm19, %zmm29
        vprold	$8, %zmm19, %zmm19
        vpternlogd	$0xd8, %zmm28, %zmm29, %zmm19
        vmovdqu64	576(%rsi), %zmm20
        vpshufd	$0xb1, %zmm20, %zmm20
        vprord	$8, %zmm20, %zmm29
        vprold	$8, %zmm20, %zmm20
        vpternlogd	$0xd8, %zmm28, %zmm29, %zmm20
        vmovdqu64	704(%rsi), %zmm21
        vpshufd	$0xb1, %zmm21, %zmm21
        vprord	$8, %zmm21, %zmm29
        vprold	$8, %zmm21, %zmm21
        vpternlogd	$0xd8, %zmm28, %zmm29, %zmm21
        vmovdqu64	832(%rsi), %zmm22
        vpshufd	$0xb1, %zmm22, %zmm22
        vprord	$8, %zmm22, %zmm29
        vprold	$8, %zmm22, %zmm22
        vpternlogd	$0xd8, %zmm28, %zmm29, %zmm22
        vmovdqu64	960(%rsi), %zmm23
        vpshufd	$0xb1, %zmm23, %zmm23
        vprord	$8, %zmm23, %zmm29
        vprold	$8, %zmm23, %zmm23
        vpternlogd	$0xd8, %zmm28, %zmm29, %zmm23
        vpunpcklqdq	%zmm17, %zmm16, %zmm29
        vpunpckhqdq	%zmm17, %zmm16, %zmm17
        vmovdqa64	%zmm29, %zmm16
        vpunpcklqdq	%zmm19, %zmm18, %zmm29
        vpunpckhqdq	%zmm19, %zmm18, %zmm19
        vmovdqa64	%zmm29, %zmm18
        vpunpcklqdq	%zmm21, %zmm20, %zmm29
        vpunpckhqdq	%zmm21, %zmm20, %zmm21
        vmovdqa64	%zmm29, %zmm20
        vpunpcklqdq	%zmm23, %zmm22, %zmm29
        vpunpckhqdq	%zmm23, %zmm22, %zmm23
        vmovdqa64	%zmm29, %zmm22
        vshufi64x2	$0x88, %zmm18, %zmm16, %zmm29
        vshufi64x2	$0xdd, %zmm18, %zmm16, %zmm18
        vmovdqa64	%zmm29, %zmm16
        vshufi64x2	$0x88, %zmm19, %zmm17, %zmm29
        vshufi64x2	$0xdd, %zmm19, %zmm17, %zmm19
        vmovdqa64	%zmm29, %zmm17
        vshufi64x2	$0x88, %zmm22, %zmm20, %zmm29
        vshufi64x2	$0xdd, %zmm22, %zmm20, %zmm22
        vmovdqa64	%zmm29, %zmm20
        vshufi64x2	$0x88, %zmm23, %zmm21, %zmm29
        vshufi64x2	$0xdd, %zmm23, %zmm21, %zmm23
        vmovdqa64	%zmm29, %zmm21
        vshufi64x2	$0x88, %zmm20, %zmm16, %zmm29
        vshufi64x2	$0xdd, %zmm20, %zmm16, %zmm20
        vmovdqa64	%zmm29, %zmm16
        vshufi64x2	$0x88, %zmm21, %zmm17, %zmm29
        vshufi64x2	$0xdd, %zmm21, %zmm17, %zmm21
        vmovdqa64	%zmm29, %zmm17
        vshufi64x2	$0x88, %zmm22, %zmm18, %zmm29
        vshufi64x2	$0xdd, %zmm22, %zmm18, %zmm22
        vmovdqa64	%zmm29, %zmm18
        vshufi64x2	$0x88, %zmm23, %zmm19, %zmm29
        vshufi64x2	$0xdd, %zmm23, %zmm19, %zmm23
        vmovdqa64	%zmm29, %zmm19
        # Load the eight lane-interleaved states
        vmovdqu64	(%rdi), %zmm0
        vmovdqu64	64(%rdi), %zmm1
        vmovdqu64	128(%rdi), %zmm2
        vmovdqu64	192(%rdi), %zmm3
        vmovdqu64	256(%rdi), %zmm4
        vmovdqu64	320(%rdi), %zmm5
        vmovdqu64	384(%rdi), %zmm6
        vmovdqu64	448(%rdi), %zmm7
        leaq	L_avx512_sha512_x8_k(%rip), %rbp
        # Rounds 0-15: the schedule is the message block itself
        vpaddq	(%rbp){1to8}, %zmm7, %zmm7
        vpaddq	%zmm8, %zmm7, %zmm7
        vpaddq	%zmm7, %zmm3, %zmm3
        vmovdqa64	%zmm5, %zmm27
        vpternlogq	$0xe2, %zmm6, %zmm4, %zmm27
        vprorq	$14, %zmm4, %zmm24
        vprorq	$18, %zmm4, %zmm25
        vprorq	$41, %zmm4, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm7, %zmm7
        vprorq	$28, %zmm0, %zmm24
        vprorq	$34, %zmm0, %zmm25
        vprorq	$39, %zmm0, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm1, %zmm27
        vpternlogq	$0xe8, %zmm2, %zmm0, %zmm27
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm7, %zmm7
        vpaddq	8(%rbp){1to8}, %zmm6, %zmm6
        vpaddq	%zmm9, %zmm6, %zmm6
        vpaddq	%zmm6, %zmm2, %zmm2
        vmovdqa64	%zmm4, %zmm27
        vpternlogq	$0xe2, %zmm5, %zmm3, %zmm27
        vprorq	$14, %zmm3, %zmm24
        vprorq	$18, %zmm3, %zmm25
        vprorq	$41, %zmm3, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm6, %zmm6
        vprorq	$28, %zmm7, %zmm24
        vprorq	$34, %zmm7, %zmm25
        vprorq	$39, %zmm7, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm0, %zmm27
        vpternlogq	$0xe8, %zmm1, %zmm7, %zmm27
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm6, %zmm6
        vpaddq	16(%rbp){1to8}, %zmm5, %zmm5
        vpaddq	%zmm10, %zmm5, %zmm5
        vpaddq	%zmm5, %zmm1, %zmm1
        vmovdqa64	%zmm3, %zmm27
        vpternlogq	$0xe2, %zmm4, %zmm2, %zmm27
        vprorq	$14, %zmm2, %zmm24
        vprorq	$18, %zmm2, %zmm25
        vprorq	$41, %zmm2, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm5, %zmm5
        vprorq	$28, %zmm6, %zmm24
        vprorq	$34, %zmm6, %zmm25
        vprorq	$39, %zmm6, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm7, %zmm27
        vpternlogq	$0xe8, %zmm0, %zmm6, %zmm27
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm5, %zmm5
        vpaddq	24(%rbp){1to8}, %zmm4, %zmm4
        vpaddq	%zmm11, %zmm4, %zmm4
        vpaddq	%zmm4, %zmm0, %zmm0
        vmovdqa64	%zmm2, %zmm27
        vpternlogq	$0xe2, %zmm3, %zmm1, %zmm27
        vprorq	$14, %zmm1, %zmm24
        vprorq	$18, %zmm1, %zmm25
        vprorq	$41, %zmm1, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm4, %zmm4
        vprorq	$28, %zmm5, %zmm24
        vprorq	$34, %zmm5, %zmm25
        vprorq	$39, %zmm5, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm6, %zmm27
        vpternlogq	$0xe8, %zmm7, %zmm5, %zmm27
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm4, %zmm4
        vpaddq	32(%rbp){1to8}, %zmm3, %zmm3
        vpaddq	%zmm12, %zmm3, %zmm3
        vpaddq	%zmm3, %zmm7, %zmm7
        vmovdqa64	%zmm1, %zmm27
        vpternlogq	$0xe2, %zmm2, %zmm0, %zmm27
        vprorq	$14, %zmm0, %zmm24
        vprorq	$18, %zmm0, %zmm25
        vprorq	$41, %zmm0, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm3, %zmm3
        vprorq	$28, %zmm4, %zmm24
        vprorq	$34, %zmm4, %zmm25
        vprorq	$39, %zmm4, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm5, %zmm27
        vpternlogq	$0xe8, %zmm6, %zmm4, %zmm27
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm3, %zmm3
        vpaddq	40(%rbp){1to8}, %zmm2, %zmm2
        vpaddq	%zmm13, %zmm2, %zmm2
        vpaddq	%zmm2, %zmm6, %zmm6
        vmovdqa64	%zmm0, %zmm27
        vpternlogq	$0xe2, %zmm1, %zmm7, %zmm27
        vprorq	$14, %zmm7, %zmm24
        vprorq	$18, %zmm7, %zmm25
        vprorq	$41, %zmm7, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm2, %zmm2
        vprorq	$28, %zmm3, %zmm24
        vprorq	$34, %zmm3, %zmm25
        vprorq	$39, %zmm3, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm4, %zmm27
        vpternlogq	$0xe8, %zmm5, %zmm3, %zmm27
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm2, %zmm2
        vpaddq	48(%rbp){1to8}, %zmm1, %zmm1
        vpaddq	%zmm14, %zmm1, %zmm1
        vpaddq	%zmm1, %zmm5, %zmm5
        vmovdqa64	%zmm7, %zmm27
        vpternlogq	$0xe2, %zmm0, %zmm6, %zmm27
        vprorq	$14, %zmm6, %zmm24
        vprorq	$18, %zmm6, %zmm25
        vprorq	$41, %zmm6, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm1, %zmm1
        vprorq	$28, %zmm2, %zmm24
        vprorq	$34, %zmm2, %zmm25
        vprorq	$39, %zmm2, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm3, %zmm27
        vpternlogq	$0xe8, %zmm4, %zmm2, %zmm27
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm1, %zmm1
        vpaddq	56(%rbp){1to8}, %zmm0, %zmm0
        vpaddq	%zmm15, %zmm0, %zmm0
        vpaddq	%zmm0, %zmm4, %zmm4
        vmovdqa64	%zmm6, %zmm27
        vpternlogq	$0xe2, %zmm7, %zmm5, %zmm27
        vprorq	$14, %zmm5, %zmm24
        vprorq	$18, %zmm5, %zmm25
        vprorq	$41, %zmm5, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm0, %zmm0
        vprorq	$28, %zmm1, %zmm24
        vprorq	$34, %zmm1, %zmm25
        vprorq	$39, %zmm1, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm2, %zmm27
        vpternlogq	$0xe8, %zmm3, %zmm1, %zmm27
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm0, %zmm0
        vpaddq	64(%rbp){1to8}, %zmm7, %zmm7
        vpaddq	%zmm16, %zmm7, %zmm7
        vpaddq	%zmm7, %zmm3, %zmm3
        vmovdqa64	%zmm5, %zmm27
        vpternlogq	$0xe2, %zmm6, %zmm4, %zmm27
        vprorq	$14, %zmm4, %zmm24
        vprorq	$18, %zmm4, %zmm25
        vprorq	$41, %zmm4, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm7, %zmm7
        vprorq	$28, %zmm0, %zmm24
        vprorq	$34, %zmm0, %zmm25
        vprorq	$39, %zmm0, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm1, %zmm27
        vpternlogq	$0xe8, %zmm2, %zmm0, %zmm27
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm7, %zmm7
        vpaddq	72(%rbp){1to8}, %zmm6, %zmm6
        vpaddq	%zmm17, %zmm6, %zmm6
        vpaddq	%zmm6, %zmm2, %zmm2
        vmovdqa64	%zmm4, %zmm27
        vpternlogq	$0xe2, %zmm5, %zmm3, %zmm27
        vprorq	$14, %zmm3, %zmm24
        vprorq	$18, %zmm3, %zmm25
        vprorq	$41, %zmm3, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm6, %zmm6
        vprorq	$28, %zmm7, %zmm24
        vprorq	$34, %zmm7, %zmm25
        vprorq	$39, %zmm7, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm0, %zmm27
        vpternlogq	$0xe8, %zmm1, %zmm7, %zmm27
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm6, %zmm6
        vpaddq	80(%rbp){1to8}, %zmm5, %zmm5
        vpaddq	%zmm18, %zmm5, %zmm5
        vpaddq	%zmm5, %zmm1, %zmm1
        vmovdqa64	%zmm3, %zmm27
        vpternlogq	$0xe2, %zmm4, %zmm2, %zmm27
        vprorq	$14, %zmm2, %zmm24
        vprorq	$18, %zmm2, %zmm25
        vprorq	$41, %zmm2, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm5, %zmm5
        vprorq	$28, %zmm6, %zmm24
        vprorq	$34, %zmm6, %zmm25
        vprorq	$39, %zmm6, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm7, %zmm27
        vpternlogq	$0xe8, %zmm0, %zmm6, %zmm27
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm5, %zmm5
        vpaddq	88(%rbp){1to8}, %zmm4, %zmm4
        vpaddq	%zmm19, %zmm4, %zmm4
        vpaddq	%zmm4, %zmm0, %zmm0
        vmovdqa64	%zmm2, %zmm27
        vpternlogq	$0xe2, %zmm3, %zmm1, %zmm27
        vprorq	$14, %zmm1, %zmm24
        vprorq	$18, %zmm1, %zmm25
        vprorq	$41, %zmm1, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm4, %zmm4
        vprorq	$28, %zmm5, %zmm24
        vprorq	$34, %zmm5, %zmm25
        vprorq	$39, %zmm5, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm6, %zmm27
        vpternlogq	$0xe8, %zmm7, %zmm5, %zmm27
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm4, %zmm4
        vpaddq	96(%rbp){1to8}, %zmm3, %zmm3
        vpaddq	%zmm20, %zmm3, %zmm3
        vpaddq	%zmm3, %zmm7, %zmm7
        vmovdqa64	%zmm1, %zmm27
        vpternlogq	$0xe2, %zmm2, %zmm0, %zmm27
        vprorq	$14, %zmm0, %zmm24
        vprorq	$18, %zmm0, %zmm25
        vprorq	$41, %zmm0, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm3, %zmm3
        vprorq	$28, %zmm4, %zmm24
        vprorq	$34, %zmm4, %zmm25
        vprorq	$39, %zmm4, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm5, %zmm27
        vpternlogq	$0xe8, %zmm6, %zmm4, %zmm27
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm3, %zmm3
        vpaddq	104(%rbp){1to8}, %zmm2, %zmm2
        vpaddq	%zmm21, %zmm2, %zmm2
        vpaddq	%zmm2, %zmm6, %zmm6
        vmovdqa64	%zmm0, %zmm27
        vpternlogq	$0xe2, %zmm1, %zmm7, %zmm27
        vprorq	$14, %zmm7, %zmm24
        vprorq	$18, %zmm7, %zmm25
        vprorq	$41, %zmm7, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm2, %zmm2
        vprorq	$28, %zmm3, %zmm24
        vprorq	$34, %zmm3, %zmm25
        vprorq	$39, %zmm3, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm4, %zmm27
        vpternlogq	$0xe8, %zmm5, %zmm3, %zmm27
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm2, %zmm2
        vpaddq	112(%rbp){1to8}, %zmm1, %zmm1
        vpaddq	%zmm22, %zmm1, %zmm1
        vpaddq	%zmm1, %zmm5, %zmm5
        vmovdqa64	%zmm7, %zmm27
        vpternlogq	$0xe2, %zmm0, %zmm6, %zmm27
        vprorq	$14, %zmm6, %zmm24
        vprorq	$18, %zmm6, %zmm25
        vprorq	$41, %zmm6, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm1, %zmm1
        vprorq	$28, %zmm2, %zmm24
        vprorq	$34, %zmm2, %zmm25
        vprorq	$39, %zmm2, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm3, %zmm27
        vpternlogq	$0xe8, %zmm4, %zmm2, %zmm27
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm1, %zmm1
        vpaddq	120(%rbp){1to8}, %zmm0, %zmm0
        vpaddq	%zmm23, %zmm0, %zmm0
        vpaddq	%zmm0, %zmm4, %zmm4
        vmovdqa64	%zmm6, %zmm27
        vpternlogq	$0xe2, %zmm7, %zmm5, %zmm27
        vprorq	$14, %zmm5, %zmm24
        vprorq	$18, %zmm5, %zmm25
        vprorq	$41, %zmm5, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm0, %zmm0
        vprorq	$28, %zmm1, %zmm24
        vprorq	$34, %zmm1, %zmm25
        vprorq	$39, %zmm1, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm2, %zmm27
        vpternlogq	$0xe8, %zmm3, %zmm1, %zmm27
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm0, %zmm0
        addq	$0x80, %rbp
        movl	$4, %eax
L_sha512_x8_avx512_start:
        vprorq	$0x01, %zmm9, %zmm24
        vprorq	$8, %zmm9, %zmm25
        vpsrlq	$7, %zmm9, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm22, %zmm25
        vprorq	$61, %zmm22, %zmm26
        vpsrlq	$6, %zmm22, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm8, %zmm8
        vpaddq	%zmm25, %zmm8, %zmm8
        vpaddq	%zmm17, %zmm8, %zmm8
        vpaddq	(%rbp){1to8}, %zmm7, %zmm7
        vpaddq	%zmm8, %zmm7, %zmm7
        vpaddq	%zmm7, %zmm3, %zmm3
        vmovdqa64	%zmm5, %zmm27
        vpternlogq	$0xe2, %zmm6, %zmm4, %zmm27
        vprorq	$14, %zmm4, %zmm24
        vprorq	$18, %zmm4, %zmm25
        vprorq	$41, %zmm4, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm7, %zmm7
        vprorq	$28, %zmm0, %zmm24
        vprorq	$34, %zmm0, %zmm25
        vprorq	$39, %zmm0, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm1, %zmm27
        vpternlogq	$0xe8, %zmm2, %zmm0, %zmm27
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm7, %zmm7
        vprorq	$0x01, %zmm10, %zmm24
        vprorq	$8, %zmm10, %zmm25
        vpsrlq	$7, %zmm10, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm23, %zmm25
        vprorq	$61, %zmm23, %zmm26
        vpsrlq	$6, %zmm23, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm9, %zmm9
        vpaddq	%zmm25, %zmm9, %zmm9
        vpaddq	%zmm18, %zmm9, %zmm9
        vpaddq	8(%rbp){1to8}, %zmm6, %zmm6
        vpaddq	%zmm9, %zmm6, %zmm6
        vpaddq	%zmm6, %zmm2, %zmm2
        vmovdqa64	%zmm4, %zmm27
        vpternlogq	$0xe2, %zmm5, %zmm3, %zmm27
        vprorq	$14, %zmm3, %zmm24
        vprorq	$18, %zmm3, %zmm25
        vprorq	$41, %zmm3, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm6, %zmm6
        vprorq	$28, %zmm7, %zmm24
        vprorq	$34, %zmm7, %zmm25
        vprorq	$39, %zmm7, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm0, %zmm27
        vpternlogq	$0xe8, %zmm1, %zmm7, %zmm27
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm6, %zmm6
        vprorq	$0x01, %zmm11, %zmm24
        vprorq	$8, %zmm11, %zmm25
        vpsrlq	$7, %zmm11, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm8, %zmm25
        vprorq	$61, %zmm8, %zmm26
        vpsrlq	$6, %zmm8, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm10, %zmm10
        vpaddq	%zmm25, %zmm10, %zmm10
        vpaddq	%zmm19, %zmm10, %zmm10
        vpaddq	16(%rbp){1to8}, %zmm5, %zmm5
        vpaddq	%zmm10, %zmm5, %zmm5
        vpaddq	%zmm5, %zmm1, %zmm1
        vmovdqa64	%zmm3, %zmm27
        vpternlogq	$0xe2, %zmm4, %zmm2, %zmm27
        vprorq	$14, %zmm2, %zmm24
        vprorq	$18, %zmm2, %zmm25
        vprorq	$41, %zmm2, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm5, %zmm5
        vprorq	$28, %zmm6, %zmm24
        vprorq	$34, %zmm6, %zmm25
        vprorq	$39, %zmm6, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm7, %zmm27
        vpternlogq	$0xe8, %zmm0, %zmm6, %zmm27
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm5, %zmm5
        vprorq	$0x01, %zmm12, %zmm24
        vprorq	$8, %zmm12, %zmm25
        vpsrlq	$7, %zmm12, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm9, %zmm25
        vprorq	$61, %zmm9, %zmm26
        vpsrlq	$6, %zmm9, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm11, %zmm11
        vpaddq	%zmm25, %zmm11, %zmm11
        vpaddq	%zmm20, %zmm11, %zmm11
        vpaddq	24(%rbp){1to8}, %zmm4, %zmm4
        vpaddq	%zmm11, %zmm4, %zmm4
        vpaddq	%zmm4, %zmm0, %zmm0
        vmovdqa64	%zmm2, %zmm27
        vpternlogq	$0xe2, %zmm3, %zmm1, %zmm27
        vprorq	$14, %zmm1, %zmm24
        vprorq	$18, %zmm1, %zmm25
        vprorq	$41, %zmm1, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm4, %zmm4
        vprorq	$28, %zmm5, %zmm24
        vprorq	$34, %zmm5, %zmm25
        vprorq	$39, %zmm5, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm6, %zmm27
        vpternlogq	$0xe8, %zmm7, %zmm5, %zmm27
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm4, %zmm4
        vprorq	$0x01, %zmm13, %zmm24
        vprorq	$8, %zmm13, %zmm25
        vpsrlq	$7, %zmm13, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm10, %zmm25
        vprorq	$61, %zmm10, %zmm26
        vpsrlq	$6, %zmm10, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm12, %zmm12
        vpaddq	%zmm25, %zmm12, %zmm12
        vpaddq	%zmm21, %zmm12, %zmm12
        vpaddq	32(%rbp){1to8}, %zmm3, %zmm3
        vpaddq	%zmm12, %zmm3, %zmm3
        vpaddq	%zmm3, %zmm7, %zmm7
        vmovdqa64	%zmm1, %zmm27
        vpternlogq	$0xe2, %zmm2, %zmm0, %zmm27
        vprorq	$14, %zmm0, %zmm24
        vprorq	$18, %zmm0, %zmm25
        vprorq	$41, %zmm0, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm3, %zmm3
        vprorq	$28, %zmm4, %zmm24
        vprorq	$34, %zmm4, %zmm25
        vprorq	$39, %zmm4, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm5, %zmm27
        vpternlogq	$0xe8, %zmm6, %zmm4, %zmm27
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm3, %zmm3
        vprorq	$0x01, %zmm14, %zmm24
        vprorq	$8, %zmm14, %zmm25
        vpsrlq	$7, %zmm14, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm11, %zmm25
        vprorq	$61, %zmm11, %zmm26
        vpsrlq	$6, %zmm11, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm13, %zmm13
        vpaddq	%zmm25, %zmm13, %zmm13
        vpaddq	%zmm22, %zmm13, %zmm13
        vpaddq	40(%rbp){1to8}, %zmm2, %zmm2
        vpaddq	%zmm13, %zmm2, %zmm2
        vpaddq	%zmm2, %zmm6, %zmm6
        vmovdqa64	%zmm0, %zmm27
        vpternlogq	$0xe2, %zmm1, %zmm7, %zmm27
        vprorq	$14, %zmm7, %zmm24
        vprorq	$18, %zmm7, %zmm25
        vprorq	$41, %zmm7, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm2, %zmm2
        vprorq	$28, %zmm3, %zmm24
        vprorq	$34, %zmm3, %zmm25
        vprorq	$39, %zmm3, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm4, %zmm27
        vpternlogq	$0xe8, %zmm5, %zmm3, %zmm27
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm2, %zmm2
        vprorq	$0x01, %zmm15, %zmm24
        vprorq	$8, %zmm15, %zmm25
        vpsrlq	$7, %zmm15, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm12, %zmm25
        vprorq	$61, %zmm12, %zmm26
        vpsrlq	$6, %zmm12, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm14, %zmm14
        vpaddq	%zmm25, %zmm14, %zmm14
        vpaddq	%zmm23, %zmm14, %zmm14
        vpaddq	48(%rbp){1to8}, %zmm1, %zmm1
        vpaddq	%zmm14, %zmm1, %zmm1
        vpaddq	%zmm1, %zmm5, %zmm5
        vmovdqa64	%zmm7, %zmm27
        vpternlogq	$0xe2, %zmm0, %zmm6, %zmm27
        vprorq	$14, %zmm6, %zmm24
        vprorq	$18, %zmm6, %zmm25
        vprorq	$41, %zmm6, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm1, %zmm1
        vprorq	$28, %zmm2, %zmm24
        vprorq	$34, %zmm2, %zmm25
        vprorq	$39, %zmm2, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm3, %zmm27
        vpternlogq	$0xe8, %zmm4, %zmm2, %zmm27
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm1, %zmm1
        vprorq	$0x01, %zmm16, %zmm24
        vprorq	$8, %zmm16, %zmm25
        vpsrlq	$7, %zmm16, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm13, %zmm25
        vprorq	$61, %zmm13, %zmm26
        vpsrlq	$6, %zmm13, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm15, %zmm15
        vpaddq	%zmm25, %zmm15, %zmm15
        vpaddq	%zmm8, %zmm15, %zmm15
        vpaddq	56(%rbp){1to8}, %zmm0, %zmm0
        vpaddq	%zmm15, %zmm0, %zmm0
        vpaddq	%zmm0, %zmm4, %zmm4
        vmovdqa64	%zmm6, %zmm27
        vpternlogq	$0xe2, %zmm7, %zmm5, %zmm27
        vprorq	$14, %zmm5, %zmm24
        vprorq	$18, %zmm5, %zmm25
        vprorq	$41, %zmm5, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm0, %zmm0
        vprorq	$28, %zmm1, %zmm24
        vprorq	$34, %zmm1, %zmm25
        vprorq	$39, %zmm1, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm2, %zmm27
        vpternlogq	$0xe8, %zmm3, %zmm1, %zmm27
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm0, %zmm0
        vprorq	$0x01, %zmm17, %zmm24
        vprorq	$8, %zmm17, %zmm25
        vpsrlq	$7, %zmm17, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm14, %zmm25
        vprorq	$61, %zmm14, %zmm26
        vpsrlq	$6, %zmm14, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm16, %zmm16
        vpaddq	%zmm25, %zmm16, %zmm16
        vpaddq	%zmm9, %zmm16, %zmm16
        vpaddq	64(%rbp){1to8}, %zmm7, %zmm7
        vpaddq	%zmm16, %zmm7, %zmm7
        vpaddq	%zmm7, %zmm3, %zmm3
        vmovdqa64	%zmm5, %zmm27
        vpternlogq	$0xe2, %zmm6, %zmm4, %zmm27
        vprorq	$14, %zmm4, %zmm24
        vprorq	$18, %zmm4, %zmm25
        vprorq	$41, %zmm4, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm7, %zmm7
        vprorq	$28, %zmm0, %zmm24
        vprorq	$34, %zmm0, %zmm25
        vprorq	$39, %zmm0, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm1, %zmm27
        vpternlogq	$0xe8, %zmm2, %zmm0, %zmm27
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm7, %zmm7
        vprorq	$0x01, %zmm18, %zmm24
        vprorq	$8, %zmm18, %zmm25
        vpsrlq	$7, %zmm18, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm15, %zmm25
        vprorq	$61, %zmm15, %zmm26
        vpsrlq	$6, %zmm15, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm17, %zmm17
        vpaddq	%zmm25, %zmm17, %zmm17
        vpaddq	%zmm10, %zmm17, %zmm17
        vpaddq	72(%rbp){1to8}, %zmm6, %zmm6
        vpaddq	%zmm17, %zmm6, %zmm6
        vpaddq	%zmm6, %zmm2, %zmm2
        vmovdqa64	%zmm4, %zmm27
        vpternlogq	$0xe2, %zmm5, %zmm3, %zmm27
        vprorq	$14, %zmm3, %zmm24
        vprorq	$18, %zmm3, %zmm25
        vprorq	$41, %zmm3, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm6, %zmm6
        vprorq	$28, %zmm7, %zmm24
        vprorq	$34, %zmm7, %zmm25
        vprorq	$39, %zmm7, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm0, %zmm27
        vpternlogq	$0xe8, %zmm1, %zmm7, %zmm27
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm6, %zmm6
        vprorq	$0x01, %zmm19, %zmm24
        vprorq	$8, %zmm19, %zmm25
        vpsrlq	$7, %zmm19, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm16, %zmm25
        vprorq	$61, %zmm16, %zmm26
        vpsrlq	$6, %zmm16, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm18, %zmm18
        vpaddq	%zmm25, %zmm18, %zmm18
        vpaddq	%zmm11, %zmm18, %zmm18
        vpaddq	80(%rbp){1to8}, %zmm5, %zmm5
        vpaddq	%zmm18, %zmm5, %zmm5
        vpaddq	%zmm5, %zmm1, %zmm1
        vmovdqa64	%zmm3, %zmm27
        vpternlogq	$0xe2, %zmm4, %zmm2, %zmm27
        vprorq	$14, %zmm2, %zmm24
        vprorq	$18, %zmm2, %zmm25
        vprorq	$41, %zmm2, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm5, %zmm5
        vprorq	$28, %zmm6, %zmm24
        vprorq	$34, %zmm6, %zmm25
        vprorq	$39, %zmm6, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm7, %zmm27
        vpternlogq	$0xe8, %zmm0, %zmm6, %zmm27
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm5, %zmm5
        vprorq	$0x01, %zmm20, %zmm24
        vprorq	$8, %zmm20, %zmm25
        vpsrlq	$7, %zmm20, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm17, %zmm25
        vprorq	$61, %zmm17, %zmm26
        vpsrlq	$6, %zmm17, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm19, %zmm19
        vpaddq	%zmm25, %zmm19, %zmm19
        vpaddq	%zmm12, %zmm19, %zmm19
        vpaddq	88(%rbp){1to8}, %zmm4, %zmm4
        vpaddq	%zmm19, %zmm4, %zmm4
        vpaddq	%zmm4, %zmm0, %zmm0
        vmovdqa64	%zmm2, %zmm27
        vpternlogq	$0xe2, %zmm3, %zmm1, %zmm27
        vprorq	$14, %zmm1, %zmm24
        vprorq	$18, %zmm1, %zmm25
        vprorq	$41, %zmm1, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm4, %zmm4
        vprorq	$28, %zmm5, %zmm24
        vprorq	$34, %zmm5, %zmm25
        vprorq	$39, %zmm5, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm6, %zmm27
        vpternlogq	$0xe8, %zmm7, %zmm5, %zmm27
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm4, %zmm4
        vprorq	$0x01, %zmm21, %zmm24
        vprorq	$8, %zmm21, %zmm25
        vpsrlq	$7, %zmm21, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm18, %zmm25
        vprorq	$61, %zmm18, %zmm26
        vpsrlq	$6, %zmm18, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm20, %zmm20
        vpaddq	%zmm25, %zmm20, %zmm20
        vpaddq	%zmm13, %zmm20, %zmm20
        vpaddq	96(%rbp){1to8}, %zmm3, %zmm3
        vpaddq	%zmm20, %zmm3, %zmm3
        vpaddq	%zmm3, %zmm7, %zmm7
        vmovdqa64	%zmm1, %zmm27
        vpternlogq	$0xe2, %zmm2, %zmm0, %zmm27
        vprorq	$14, %zmm0, %zmm24
        vprorq	$18, %zmm0, %zmm25
        vprorq	$41, %zmm0, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm3, %zmm3
        vprorq	$28, %zmm4, %zmm24
        vprorq	$34, %zmm4, %zmm25
        vprorq	$39, %zmm4, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm5, %zmm27
        vpternlogq	$0xe8, %zmm6, %zmm4, %zmm27
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm3, %zmm3
        vprorq	$0x01, %zmm22, %zmm24
        vprorq	$8, %zmm22, %zmm25
        vpsrlq	$7, %zmm22, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm19, %zmm25
        vprorq	$61, %zmm19, %zmm26
        vpsrlq	$6, %zmm19, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm21, %zmm21
        vpaddq	%zmm25, %zmm21, %zmm21
        vpaddq	%zmm14, %zmm21, %zmm21
        vpaddq	104(%rbp){1to8}, %zmm2, %zmm2
        vpaddq	%zmm21, %zmm2, %zmm2
        vpaddq	%zmm2, %zmm6, %zmm6
        vmovdqa64	%zmm0, %zmm27
        vpternlogq	$0xe2, %zmm1, %zmm7, %zmm27
        vprorq	$14, %zmm7, %zmm24
        vprorq	$18, %zmm7, %zmm25
        vprorq	$41, %zmm7, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm2, %zmm2
        vprorq	$28, %zmm3, %zmm24
        vprorq	$34, %zmm3, %zmm25
        vprorq	$39, %zmm3, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm4, %zmm27
        vpternlogq	$0xe8, %zmm5, %zmm3, %zmm27
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm2, %zmm2
        vprorq	$0x01, %zmm23, %zmm24
        vprorq	$8, %zmm23, %zmm25
        vpsrlq	$7, %zmm23, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm20, %zmm25
        vprorq	$61, %zmm20, %zmm26
        vpsrlq	$6, %zmm20, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm22, %zmm22
        vpaddq	%zmm25, %zmm22, %zmm22
        vpaddq	%zmm15, %zmm22, %zmm22
        vpaddq	112(%rbp){1to8}, %zmm1, %zmm1
        vpaddq	%zmm22, %zmm1, %zmm1
        vpaddq	%zmm1, %zmm5, %zmm5
        vmovdqa64	%zmm7, %zmm27
        vpternlogq	$0xe2, %zmm0, %zmm6, %zmm27
        vprorq	$14, %zmm6, %zmm24
        vprorq	$18, %zmm6, %zmm25
        vprorq	$41, %zmm6, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm1, %zmm1
        vprorq	$28, %zmm2, %zmm24
        vprorq	$34, %zmm2, %zmm25
        vprorq	$39, %zmm2, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm3, %zmm27
        vpternlogq	$0xe8, %zmm4, %zmm2, %zmm27
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm1, %zmm1
        vprorq	$0x01, %zmm8, %zmm24
        vprorq	$8, %zmm8, %zmm25
        vpsrlq	$7, %zmm8, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm21, %zmm25
        vprorq	$61, %zmm21, %zmm26
        vpsrlq	$6, %zmm21, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm23, %zmm23
        vpaddq	%zmm25, %zmm23, %zmm23
        vpaddq	%zmm16, %zmm23, %zmm23
        vpaddq	120(%rbp){1to8}, %zmm0, %zmm0
        vpaddq	%zmm23, %zmm0, %zmm0
        vpaddq	%zmm0, %zmm4, %zmm4
        vmovdqa64	%zmm6, %zmm27
        vpternlogq	$0xe2, %zmm7, %zmm5, %zmm27
        vprorq	$14, %zmm5, %zmm24
        vprorq	$18, %zmm5, %zmm25
        vprorq	$41, %zmm5, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm0, %zmm0
        vprorq	$28, %zmm1, %zmm24
        vprorq	$34, %zmm1, %zmm25
        vprorq	$39, %zmm1, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm2, %zmm27
        vpternlogq	$0xe8, %zmm3, %zmm1, %zmm27
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm0, %zmm0
        addq	$0x80, %rbp
        subl	$0x01, %eax
        jnz	L_sha512_x8_avx512_start
        # Add the compressed block into the states
        vpaddq	(%rdi), %zmm0, %zmm0
        vmovdqu64	%zmm0, (%rdi)
        vpaddq	64(%rdi), %zmm1, %zmm1
        vmovdqu64	%zmm1, 64(%rdi)
        vpaddq	128(%rdi), %zmm2, %zmm2
        vmovdqu64	%zmm2, 128(%rdi)
        vpaddq	192(%rdi), %zmm3, %zmm3
        vmovdqu64	%zmm3, 192(%rdi)
        vpaddq	256(%rdi), %zmm4, %zmm4
        vmovdqu64	%zmm4, 256(%rdi)
        vpaddq	320(%rdi), %zmm5, %zmm5
        vmovdqu64	%zmm5, 320(%rdi)
        vpaddq	384(%rdi), %zmm6, %zmm6
        vmovdqu64	%zmm6, 384(%rdi)
        vpaddq	448(%rdi), %zmm7, %zmm7
        vmovdqu64	%zmm7, 448(%rdi)
        vzeroupper
        popq	%rbp
        repz retq
#ifndef __APPLE__
.size	Transform_Sha512_x8_AVX512,.-Transform_Sha512_x8_AVX512
#endif /* __APPLE__ */
#if !defined(NO_AVX512BW_SUPPORT)
#ifndef __APPLE__
.data
#else
.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
.align	32
#else
.p2align	5
#endif /* __APPLE__ */
L_avx512_sha512_x8_flip_mask:
.quad	0x0001020304050607,0x08090a0b0c0d0e0f
.quad	0x0001020304050607,0x08090a0b0c0d0e0f
.quad	0x0001020304050607,0x08090a0b0c0d0e0f
.quad	0x0001020304050607,0x08090a0b0c0d0e0f
#ifndef __APPLE__
.text
.globl	Transform_Sha512_x8_AVX512_BW
WC_ASM_ATT_HIDDEN(Transform_Sha512_x8_AVX512_BW)
.type	Transform_Sha512_x8_AVX512_BW,@function
.align	16
Transform_Sha512_x8_AVX512_BW:
#else
.section	__TEXT,__text
.globl	_Transform_Sha512_x8_AVX512_BW
WC_ASM_ATT_HIDDEN(_Transform_Sha512_x8_AVX512_BW)
.p2align	4
_Transform_Sha512_x8_AVX512_BW:
#endif /* __APPLE__ */
        pushq	%rbp
        vmovdqu64	L_avx512_sha512_x8_flip_mask(%rip), %zmm28
        # W[0..7] of all eight blocks
        vmovdqu64	(%rsi), %zmm8
        vpshufb	%zmm28, %zmm8, %zmm8
        vmovdqu64	128(%rsi), %zmm9
        vpshufb	%zmm28, %zmm9, %zmm9
        vmovdqu64	256(%rsi), %zmm10
        vpshufb	%zmm28, %zmm10, %zmm10
        vmovdqu64	384(%rsi), %zmm11
        vpshufb	%zmm28, %zmm11, %zmm11
        vmovdqu64	512(%rsi), %zmm12
        vpshufb	%zmm28, %zmm12, %zmm12
        vmovdqu64	640(%rsi), %zmm13
        vpshufb	%zmm28, %zmm13, %zmm13
        vmovdqu64	768(%rsi), %zmm14
        vpshufb	%zmm28, %zmm14, %zmm14
        vmovdqu64	896(%rsi), %zmm15
        vpshufb	%zmm28, %zmm15, %zmm15
        vpunpcklqdq	%zmm9, %zmm8, %zmm29
        vpunpckhqdq	%zmm9, %zmm8, %zmm9
        vmovdqa64	%zmm29, %zmm8
        vpunpcklqdq	%zmm11, %zmm10, %zmm29
        vpunpckhqdq	%zmm11, %zmm10, %zmm11
        vmovdqa64	%zmm29, %zmm10
        vpunpcklqdq	%zmm13, %zmm12, %zmm29
        vpunpckhqdq	%zmm13, %zmm12, %zmm13
        vmovdqa64	%zmm29, %zmm12
        vpunpcklqdq	%zmm15, %zmm14, %zmm29
        vpunpckhqdq	%zmm15, %zmm14, %zmm15
        vmovdqa64	%zmm29, %zmm14
        vshufi64x2	$0x88, %zmm10, %zmm8, %zmm29
        vshufi64x2	$0xdd, %zmm10, %zmm8, %zmm10
        vmovdqa64	%zmm29, %zmm8
        vshufi64x2	$0x88, %zmm11, %zmm9, %zmm29
        vshufi64x2	$0xdd, %zmm11, %zmm9, %zmm11
        vmovdqa64	%zmm29, %zmm9
        vshufi64x2	$0x88, %zmm14, %zmm12, %zmm29
        vshufi64x2	$0xdd, %zmm14, %zmm12, %zmm14
        vmovdqa64	%zmm29, %zmm12
        vshufi64x2	$0x88, %zmm15, %zmm13, %zmm29
        vshufi64x2	$0xdd, %zmm15, %zmm13, %zmm15
        vmovdqa64	%zmm29, %zmm13
        vshufi64x2	$0x88, %zmm12, %zmm8, %zmm29
        vshufi64x2	$0xdd, %zmm12, %zmm8, %zmm12
        vmovdqa64	%zmm29, %zmm8
        vshufi64x2	$0x88, %zmm13, %zmm9, %zmm29
        vshufi64x2	$0xdd, %zmm13, %zmm9, %zmm13
        vmovdqa64	%zmm29, %zmm9
        vshufi64x2	$0x88, %zmm14, %zmm10, %zmm29
        vshufi64x2	$0xdd, %zmm14, %zmm10, %zmm14
        vmovdqa64	%zmm29, %zmm10
        vshufi64x2	$0x88, %zmm15, %zmm11, %zmm29
        vshufi64x2	$0xdd, %zmm15, %zmm11, %zmm15
        vmovdqa64	%zmm29, %zmm11
        # W[8..15] of all eight blocks
        vmovdqu64	64(%rsi), %zmm16
        vpshufb	%zmm28, %zmm16, %zmm16
        vmovdqu64	192(%rsi), %zmm17
        vpshufb	%zmm28, %zmm17, %zmm17
        vmovdqu64	320(%rsi), %zmm18
        vpshufb	%zmm28, %zmm18, %zmm18
        vmovdqu64	448(%rsi), %zmm19
        vpshufb	%zmm28, %zmm19, %zmm19
        vmovdqu64	576(%rsi), %zmm20
        vpshufb	%zmm28, %zmm20, %zmm20
        vmovdqu64	704(%rsi), %zmm21
        vpshufb	%zmm28, %zmm21, %zmm21
        vmovdqu64	832(%rsi), %zmm22
        vpshufb	%zmm28, %zmm22, %zmm22
        vmovdqu64	960(%rsi), %zmm23
        vpshufb	%zmm28, %zmm23, %zmm23
        vpunpcklqdq	%zmm17, %zmm16, %zmm29
        vpunpckhqdq	%zmm17, %zmm16, %zmm17
        vmovdqa64	%zmm29, %zmm16
        vpunpcklqdq	%zmm19, %zmm18, %zmm29
        vpunpckhqdq	%zmm19, %zmm18, %zmm19
        vmovdqa64	%zmm29, %zmm18
        vpunpcklqdq	%zmm21, %zmm20, %zmm29
        vpunpckhqdq	%zmm21, %zmm20, %zmm21
        vmovdqa64	%zmm29, %zmm20
        vpunpcklqdq	%zmm23, %zmm22, %zmm29
        vpunpckhqdq	%zmm23, %zmm22, %zmm23
        vmovdqa64	%zmm29, %zmm22
        vshufi64x2	$0x88, %zmm18, %zmm16, %zmm29
        vshufi64x2	$0xdd, %zmm18, %zmm16, %zmm18
        vmovdqa64	%zmm29, %zmm16
        vshufi64x2	$0x88, %zmm19, %zmm17, %zmm29
        vshufi64x2	$0xdd, %zmm19, %zmm17, %zmm19
        vmovdqa64	%zmm29, %zmm17
        vshufi64x2	$0x88, %zmm22, %zmm20, %zmm29
        vshufi64x2	$0xdd, %zmm22, %zmm20, %zmm22
        vmovdqa64	%zmm29, %zmm20
        vshufi64x2	$0x88, %zmm23, %zmm21, %zmm29
        vshufi64x2	$0xdd, %zmm23, %zmm21, %zmm23
        vmovdqa64	%zmm29, %zmm21
        vshufi64x2	$0x88, %zmm20, %zmm16, %zmm29
        vshufi64x2	$0xdd, %zmm20, %zmm16, %zmm20
        vmovdqa64	%zmm29, %zmm16
        vshufi64x2	$0x88, %zmm21, %zmm17, %zmm29
        vshufi64x2	$0xdd, %zmm21, %zmm17, %zmm21
        vmovdqa64	%zmm29, %zmm17
        vshufi64x2	$0x88, %zmm22, %zmm18, %zmm29
        vshufi64x2	$0xdd, %zmm22, %zmm18, %zmm22
        vmovdqa64	%zmm29, %zmm18
        vshufi64x2	$0x88, %zmm23, %zmm19, %zmm29
        vshufi64x2	$0xdd, %zmm23, %zmm19, %zmm23
        vmovdqa64	%zmm29, %zmm19
        # Load the eight lane-interleaved states
        vmovdqu64	(%rdi), %zmm0
        vmovdqu64	64(%rdi), %zmm1
        vmovdqu64	128(%rdi), %zmm2
        vmovdqu64	192(%rdi), %zmm3
        vmovdqu64	256(%rdi), %zmm4
        vmovdqu64	320(%rdi), %zmm5
        vmovdqu64	384(%rdi), %zmm6
        vmovdqu64	448(%rdi), %zmm7
        leaq	L_avx512_sha512_x8_k(%rip), %rbp
        # Rounds 0-15: the schedule is the message block itself
        vpaddq	(%rbp){1to8}, %zmm7, %zmm7
        vpaddq	%zmm8, %zmm7, %zmm7
        vpaddq	%zmm7, %zmm3, %zmm3
        vmovdqa64	%zmm5, %zmm27
        vpternlogq	$0xe2, %zmm6, %zmm4, %zmm27
        vprorq	$14, %zmm4, %zmm24
        vprorq	$18, %zmm4, %zmm25
        vprorq	$41, %zmm4, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm7, %zmm7
        vprorq	$28, %zmm0, %zmm24
        vprorq	$34, %zmm0, %zmm25
        vprorq	$39, %zmm0, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm1, %zmm27
        vpternlogq	$0xe8, %zmm2, %zmm0, %zmm27
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm7, %zmm7
        vpaddq	8(%rbp){1to8}, %zmm6, %zmm6
        vpaddq	%zmm9, %zmm6, %zmm6
        vpaddq	%zmm6, %zmm2, %zmm2
        vmovdqa64	%zmm4, %zmm27
        vpternlogq	$0xe2, %zmm5, %zmm3, %zmm27
        vprorq	$14, %zmm3, %zmm24
        vprorq	$18, %zmm3, %zmm25
        vprorq	$41, %zmm3, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm6, %zmm6
        vprorq	$28, %zmm7, %zmm24
        vprorq	$34, %zmm7, %zmm25
        vprorq	$39, %zmm7, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm0, %zmm27
        vpternlogq	$0xe8, %zmm1, %zmm7, %zmm27
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm6, %zmm6
        vpaddq	16(%rbp){1to8}, %zmm5, %zmm5
        vpaddq	%zmm10, %zmm5, %zmm5
        vpaddq	%zmm5, %zmm1, %zmm1
        vmovdqa64	%zmm3, %zmm27
        vpternlogq	$0xe2, %zmm4, %zmm2, %zmm27
        vprorq	$14, %zmm2, %zmm24
        vprorq	$18, %zmm2, %zmm25
        vprorq	$41, %zmm2, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm5, %zmm5
        vprorq	$28, %zmm6, %zmm24
        vprorq	$34, %zmm6, %zmm25
        vprorq	$39, %zmm6, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm7, %zmm27
        vpternlogq	$0xe8, %zmm0, %zmm6, %zmm27
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm5, %zmm5
        vpaddq	24(%rbp){1to8}, %zmm4, %zmm4
        vpaddq	%zmm11, %zmm4, %zmm4
        vpaddq	%zmm4, %zmm0, %zmm0
        vmovdqa64	%zmm2, %zmm27
        vpternlogq	$0xe2, %zmm3, %zmm1, %zmm27
        vprorq	$14, %zmm1, %zmm24
        vprorq	$18, %zmm1, %zmm25
        vprorq	$41, %zmm1, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm4, %zmm4
        vprorq	$28, %zmm5, %zmm24
        vprorq	$34, %zmm5, %zmm25
        vprorq	$39, %zmm5, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm6, %zmm27
        vpternlogq	$0xe8, %zmm7, %zmm5, %zmm27
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm4, %zmm4
        vpaddq	32(%rbp){1to8}, %zmm3, %zmm3
        vpaddq	%zmm12, %zmm3, %zmm3
        vpaddq	%zmm3, %zmm7, %zmm7
        vmovdqa64	%zmm1, %zmm27
        vpternlogq	$0xe2, %zmm2, %zmm0, %zmm27
        vprorq	$14, %zmm0, %zmm24
        vprorq	$18, %zmm0, %zmm25
        vprorq	$41, %zmm0, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm3, %zmm3
        vprorq	$28, %zmm4, %zmm24
        vprorq	$34, %zmm4, %zmm25
        vprorq	$39, %zmm4, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm5, %zmm27
        vpternlogq	$0xe8, %zmm6, %zmm4, %zmm27
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm3, %zmm3
        vpaddq	40(%rbp){1to8}, %zmm2, %zmm2
        vpaddq	%zmm13, %zmm2, %zmm2
        vpaddq	%zmm2, %zmm6, %zmm6
        vmovdqa64	%zmm0, %zmm27
        vpternlogq	$0xe2, %zmm1, %zmm7, %zmm27
        vprorq	$14, %zmm7, %zmm24
        vprorq	$18, %zmm7, %zmm25
        vprorq	$41, %zmm7, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm2, %zmm2
        vprorq	$28, %zmm3, %zmm24
        vprorq	$34, %zmm3, %zmm25
        vprorq	$39, %zmm3, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm4, %zmm27
        vpternlogq	$0xe8, %zmm5, %zmm3, %zmm27
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm2, %zmm2
        vpaddq	48(%rbp){1to8}, %zmm1, %zmm1
        vpaddq	%zmm14, %zmm1, %zmm1
        vpaddq	%zmm1, %zmm5, %zmm5
        vmovdqa64	%zmm7, %zmm27
        vpternlogq	$0xe2, %zmm0, %zmm6, %zmm27
        vprorq	$14, %zmm6, %zmm24
        vprorq	$18, %zmm6, %zmm25
        vprorq	$41, %zmm6, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm1, %zmm1
        vprorq	$28, %zmm2, %zmm24
        vprorq	$34, %zmm2, %zmm25
        vprorq	$39, %zmm2, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm3, %zmm27
        vpternlogq	$0xe8, %zmm4, %zmm2, %zmm27
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm1, %zmm1
        vpaddq	56(%rbp){1to8}, %zmm0, %zmm0
        vpaddq	%zmm15, %zmm0, %zmm0
        vpaddq	%zmm0, %zmm4, %zmm4
        vmovdqa64	%zmm6, %zmm27
        vpternlogq	$0xe2, %zmm7, %zmm5, %zmm27
        vprorq	$14, %zmm5, %zmm24
        vprorq	$18, %zmm5, %zmm25
        vprorq	$41, %zmm5, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm0, %zmm0
        vprorq	$28, %zmm1, %zmm24
        vprorq	$34, %zmm1, %zmm25
        vprorq	$39, %zmm1, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm2, %zmm27
        vpternlogq	$0xe8, %zmm3, %zmm1, %zmm27
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm0, %zmm0
        vpaddq	64(%rbp){1to8}, %zmm7, %zmm7
        vpaddq	%zmm16, %zmm7, %zmm7
        vpaddq	%zmm7, %zmm3, %zmm3
        vmovdqa64	%zmm5, %zmm27
        vpternlogq	$0xe2, %zmm6, %zmm4, %zmm27
        vprorq	$14, %zmm4, %zmm24
        vprorq	$18, %zmm4, %zmm25
        vprorq	$41, %zmm4, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm7, %zmm7
        vprorq	$28, %zmm0, %zmm24
        vprorq	$34, %zmm0, %zmm25
        vprorq	$39, %zmm0, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm1, %zmm27
        vpternlogq	$0xe8, %zmm2, %zmm0, %zmm27
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm7, %zmm7
        vpaddq	72(%rbp){1to8}, %zmm6, %zmm6
        vpaddq	%zmm17, %zmm6, %zmm6
        vpaddq	%zmm6, %zmm2, %zmm2
        vmovdqa64	%zmm4, %zmm27
        vpternlogq	$0xe2, %zmm5, %zmm3, %zmm27
        vprorq	$14, %zmm3, %zmm24
        vprorq	$18, %zmm3, %zmm25
        vprorq	$41, %zmm3, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm6, %zmm6
        vprorq	$28, %zmm7, %zmm24
        vprorq	$34, %zmm7, %zmm25
        vprorq	$39, %zmm7, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm0, %zmm27
        vpternlogq	$0xe8, %zmm1, %zmm7, %zmm27
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm6, %zmm6
        vpaddq	80(%rbp){1to8}, %zmm5, %zmm5
        vpaddq	%zmm18, %zmm5, %zmm5
        vpaddq	%zmm5, %zmm1, %zmm1
        vmovdqa64	%zmm3, %zmm27
        vpternlogq	$0xe2, %zmm4, %zmm2, %zmm27
        vprorq	$14, %zmm2, %zmm24
        vprorq	$18, %zmm2, %zmm25
        vprorq	$41, %zmm2, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm5, %zmm5
        vprorq	$28, %zmm6, %zmm24
        vprorq	$34, %zmm6, %zmm25
        vprorq	$39, %zmm6, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm7, %zmm27
        vpternlogq	$0xe8, %zmm0, %zmm6, %zmm27
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm5, %zmm5
        vpaddq	88(%rbp){1to8}, %zmm4, %zmm4
        vpaddq	%zmm19, %zmm4, %zmm4
        vpaddq	%zmm4, %zmm0, %zmm0
        vmovdqa64	%zmm2, %zmm27
        vpternlogq	$0xe2, %zmm3, %zmm1, %zmm27
        vprorq	$14, %zmm1, %zmm24
        vprorq	$18, %zmm1, %zmm25
        vprorq	$41, %zmm1, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm4, %zmm4
        vprorq	$28, %zmm5, %zmm24
        vprorq	$34, %zmm5, %zmm25
        vprorq	$39, %zmm5, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm6, %zmm27
        vpternlogq	$0xe8, %zmm7, %zmm5, %zmm27
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm4, %zmm4
        vpaddq	96(%rbp){1to8}, %zmm3, %zmm3
        vpaddq	%zmm20, %zmm3, %zmm3
        vpaddq	%zmm3, %zmm7, %zmm7
        vmovdqa64	%zmm1, %zmm27
        vpternlogq	$0xe2, %zmm2, %zmm0, %zmm27
        vprorq	$14, %zmm0, %zmm24
        vprorq	$18, %zmm0, %zmm25
        vprorq	$41, %zmm0, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm3, %zmm3
        vprorq	$28, %zmm4, %zmm24
        vprorq	$34, %zmm4, %zmm25
        vprorq	$39, %zmm4, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm5, %zmm27
        vpternlogq	$0xe8, %zmm6, %zmm4, %zmm27
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm3, %zmm3
        vpaddq	104(%rbp){1to8}, %zmm2, %zmm2
        vpaddq	%zmm21, %zmm2, %zmm2
        vpaddq	%zmm2, %zmm6, %zmm6
        vmovdqa64	%zmm0, %zmm27
        vpternlogq	$0xe2, %zmm1, %zmm7, %zmm27
        vprorq	$14, %zmm7, %zmm24
        vprorq	$18, %zmm7, %zmm25
        vprorq	$41, %zmm7, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm2, %zmm2
        vprorq	$28, %zmm3, %zmm24
        vprorq	$34, %zmm3, %zmm25
        vprorq	$39, %zmm3, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm4, %zmm27
        vpternlogq	$0xe8, %zmm5, %zmm3, %zmm27
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm2, %zmm2
        vpaddq	112(%rbp){1to8}, %zmm1, %zmm1
        vpaddq	%zmm22, %zmm1, %zmm1
        vpaddq	%zmm1, %zmm5, %zmm5
        vmovdqa64	%zmm7, %zmm27
        vpternlogq	$0xe2, %zmm0, %zmm6, %zmm27
        vprorq	$14, %zmm6, %zmm24
        vprorq	$18, %zmm6, %zmm25
        vprorq	$41, %zmm6, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm1, %zmm1
        vprorq	$28, %zmm2, %zmm24
        vprorq	$34, %zmm2, %zmm25
        vprorq	$39, %zmm2, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm3, %zmm27
        vpternlogq	$0xe8, %zmm4, %zmm2, %zmm27
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm1, %zmm1
        vpaddq	120(%rbp){1to8}, %zmm0, %zmm0
        vpaddq	%zmm23, %zmm0, %zmm0
        vpaddq	%zmm0, %zmm4, %zmm4
        vmovdqa64	%zmm6, %zmm27
        vpternlogq	$0xe2, %zmm7, %zmm5, %zmm27
        vprorq	$14, %zmm5, %zmm24
        vprorq	$18, %zmm5, %zmm25
        vprorq	$41, %zmm5, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm0, %zmm0
        vprorq	$28, %zmm1, %zmm24
        vprorq	$34, %zmm1, %zmm25
        vprorq	$39, %zmm1, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm2, %zmm27
        vpternlogq	$0xe8, %zmm3, %zmm1, %zmm27
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm0, %zmm0
        addq	$0x80, %rbp
        movl	$4, %eax
L_sha512_x8_avx512_bw_start:
        vprorq	$0x01, %zmm9, %zmm24
        vprorq	$8, %zmm9, %zmm25
        vpsrlq	$7, %zmm9, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm22, %zmm25
        vprorq	$61, %zmm22, %zmm26
        vpsrlq	$6, %zmm22, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm8, %zmm8
        vpaddq	%zmm25, %zmm8, %zmm8
        vpaddq	%zmm17, %zmm8, %zmm8
        vpaddq	(%rbp){1to8}, %zmm7, %zmm7
        vpaddq	%zmm8, %zmm7, %zmm7
        vpaddq	%zmm7, %zmm3, %zmm3
        vmovdqa64	%zmm5, %zmm27
        vpternlogq	$0xe2, %zmm6, %zmm4, %zmm27
        vprorq	$14, %zmm4, %zmm24
        vprorq	$18, %zmm4, %zmm25
        vprorq	$41, %zmm4, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm7, %zmm7
        vprorq	$28, %zmm0, %zmm24
        vprorq	$34, %zmm0, %zmm25
        vprorq	$39, %zmm0, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm1, %zmm27
        vpternlogq	$0xe8, %zmm2, %zmm0, %zmm27
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm7, %zmm7
        vprorq	$0x01, %zmm10, %zmm24
        vprorq	$8, %zmm10, %zmm25
        vpsrlq	$7, %zmm10, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm23, %zmm25
        vprorq	$61, %zmm23, %zmm26
        vpsrlq	$6, %zmm23, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm9, %zmm9
        vpaddq	%zmm25, %zmm9, %zmm9
        vpaddq	%zmm18, %zmm9, %zmm9
        vpaddq	8(%rbp){1to8}, %zmm6, %zmm6
        vpaddq	%zmm9, %zmm6, %zmm6
        vpaddq	%zmm6, %zmm2, %zmm2
        vmovdqa64	%zmm4, %zmm27
        vpternlogq	$0xe2, %zmm5, %zmm3, %zmm27
        vprorq	$14, %zmm3, %zmm24
        vprorq	$18, %zmm3, %zmm25
        vprorq	$41, %zmm3, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm6, %zmm6
        vprorq	$28, %zmm7, %zmm24
        vprorq	$34, %zmm7, %zmm25
        vprorq	$39, %zmm7, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm0, %zmm27
        vpternlogq	$0xe8, %zmm1, %zmm7, %zmm27
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm6, %zmm6
        vprorq	$0x01, %zmm11, %zmm24
        vprorq	$8, %zmm11, %zmm25
        vpsrlq	$7, %zmm11, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm8, %zmm25
        vprorq	$61, %zmm8, %zmm26
        vpsrlq	$6, %zmm8, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm10, %zmm10
        vpaddq	%zmm25, %zmm10, %zmm10
        vpaddq	%zmm19, %zmm10, %zmm10
        vpaddq	16(%rbp){1to8}, %zmm5, %zmm5
        vpaddq	%zmm10, %zmm5, %zmm5
        vpaddq	%zmm5, %zmm1, %zmm1
        vmovdqa64	%zmm3, %zmm27
        vpternlogq	$0xe2, %zmm4, %zmm2, %zmm27
        vprorq	$14, %zmm2, %zmm24
        vprorq	$18, %zmm2, %zmm25
        vprorq	$41, %zmm2, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm5, %zmm5
        vprorq	$28, %zmm6, %zmm24
        vprorq	$34, %zmm6, %zmm25
        vprorq	$39, %zmm6, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm7, %zmm27
        vpternlogq	$0xe8, %zmm0, %zmm6, %zmm27
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm5, %zmm5
        vprorq	$0x01, %zmm12, %zmm24
        vprorq	$8, %zmm12, %zmm25
        vpsrlq	$7, %zmm12, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm9, %zmm25
        vprorq	$61, %zmm9, %zmm26
        vpsrlq	$6, %zmm9, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm11, %zmm11
        vpaddq	%zmm25, %zmm11, %zmm11
        vpaddq	%zmm20, %zmm11, %zmm11
        vpaddq	24(%rbp){1to8}, %zmm4, %zmm4
        vpaddq	%zmm11, %zmm4, %zmm4
        vpaddq	%zmm4, %zmm0, %zmm0
        vmovdqa64	%zmm2, %zmm27
        vpternlogq	$0xe2, %zmm3, %zmm1, %zmm27
        vprorq	$14, %zmm1, %zmm24
        vprorq	$18, %zmm1, %zmm25
        vprorq	$41, %zmm1, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm4, %zmm4
        vprorq	$28, %zmm5, %zmm24
        vprorq	$34, %zmm5, %zmm25
        vprorq	$39, %zmm5, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm6, %zmm27
        vpternlogq	$0xe8, %zmm7, %zmm5, %zmm27
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm4, %zmm4
        vprorq	$0x01, %zmm13, %zmm24
        vprorq	$8, %zmm13, %zmm25
        vpsrlq	$7, %zmm13, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm10, %zmm25
        vprorq	$61, %zmm10, %zmm26
        vpsrlq	$6, %zmm10, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm12, %zmm12
        vpaddq	%zmm25, %zmm12, %zmm12
        vpaddq	%zmm21, %zmm12, %zmm12
        vpaddq	32(%rbp){1to8}, %zmm3, %zmm3
        vpaddq	%zmm12, %zmm3, %zmm3
        vpaddq	%zmm3, %zmm7, %zmm7
        vmovdqa64	%zmm1, %zmm27
        vpternlogq	$0xe2, %zmm2, %zmm0, %zmm27
        vprorq	$14, %zmm0, %zmm24
        vprorq	$18, %zmm0, %zmm25
        vprorq	$41, %zmm0, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm3, %zmm3
        vprorq	$28, %zmm4, %zmm24
        vprorq	$34, %zmm4, %zmm25
        vprorq	$39, %zmm4, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm5, %zmm27
        vpternlogq	$0xe8, %zmm6, %zmm4, %zmm27
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm3, %zmm3
        vprorq	$0x01, %zmm14, %zmm24
        vprorq	$8, %zmm14, %zmm25
        vpsrlq	$7, %zmm14, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm11, %zmm25
        vprorq	$61, %zmm11, %zmm26
        vpsrlq	$6, %zmm11, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm13, %zmm13
        vpaddq	%zmm25, %zmm13, %zmm13
        vpaddq	%zmm22, %zmm13, %zmm13
        vpaddq	40(%rbp){1to8}, %zmm2, %zmm2
        vpaddq	%zmm13, %zmm2, %zmm2
        vpaddq	%zmm2, %zmm6, %zmm6
        vmovdqa64	%zmm0, %zmm27
        vpternlogq	$0xe2, %zmm1, %zmm7, %zmm27
        vprorq	$14, %zmm7, %zmm24
        vprorq	$18, %zmm7, %zmm25
        vprorq	$41, %zmm7, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm2, %zmm2
        vprorq	$28, %zmm3, %zmm24
        vprorq	$34, %zmm3, %zmm25
        vprorq	$39, %zmm3, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm4, %zmm27
        vpternlogq	$0xe8, %zmm5, %zmm3, %zmm27
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm2, %zmm2
        vprorq	$0x01, %zmm15, %zmm24
        vprorq	$8, %zmm15, %zmm25
        vpsrlq	$7, %zmm15, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm12, %zmm25
        vprorq	$61, %zmm12, %zmm26
        vpsrlq	$6, %zmm12, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm14, %zmm14
        vpaddq	%zmm25, %zmm14, %zmm14
        vpaddq	%zmm23, %zmm14, %zmm14
        vpaddq	48(%rbp){1to8}, %zmm1, %zmm1
        vpaddq	%zmm14, %zmm1, %zmm1
        vpaddq	%zmm1, %zmm5, %zmm5
        vmovdqa64	%zmm7, %zmm27
        vpternlogq	$0xe2, %zmm0, %zmm6, %zmm27
        vprorq	$14, %zmm6, %zmm24
        vprorq	$18, %zmm6, %zmm25
        vprorq	$41, %zmm6, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm1, %zmm1
        vprorq	$28, %zmm2, %zmm24
        vprorq	$34, %zmm2, %zmm25
        vprorq	$39, %zmm2, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm3, %zmm27
        vpternlogq	$0xe8, %zmm4, %zmm2, %zmm27
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm1, %zmm1
        vprorq	$0x01, %zmm16, %zmm24
        vprorq	$8, %zmm16, %zmm25
        vpsrlq	$7, %zmm16, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm13, %zmm25
        vprorq	$61, %zmm13, %zmm26
        vpsrlq	$6, %zmm13, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm15, %zmm15
        vpaddq	%zmm25, %zmm15, %zmm15
        vpaddq	%zmm8, %zmm15, %zmm15
        vpaddq	56(%rbp){1to8}, %zmm0, %zmm0
        vpaddq	%zmm15, %zmm0, %zmm0
        vpaddq	%zmm0, %zmm4, %zmm4
        vmovdqa64	%zmm6, %zmm27
        vpternlogq	$0xe2, %zmm7, %zmm5, %zmm27
        vprorq	$14, %zmm5, %zmm24
        vprorq	$18, %zmm5, %zmm25
        vprorq	$41, %zmm5, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm0, %zmm0
        vprorq	$28, %zmm1, %zmm24
        vprorq	$34, %zmm1, %zmm25
        vprorq	$39, %zmm1, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm2, %zmm27
        vpternlogq	$0xe8, %zmm3, %zmm1, %zmm27
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm0, %zmm0
        vprorq	$0x01, %zmm17, %zmm24
        vprorq	$8, %zmm17, %zmm25
        vpsrlq	$7, %zmm17, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm14, %zmm25
        vprorq	$61, %zmm14, %zmm26
        vpsrlq	$6, %zmm14, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm16, %zmm16
        vpaddq	%zmm25, %zmm16, %zmm16
        vpaddq	%zmm9, %zmm16, %zmm16
        vpaddq	64(%rbp){1to8}, %zmm7, %zmm7
        vpaddq	%zmm16, %zmm7, %zmm7
        vpaddq	%zmm7, %zmm3, %zmm3
        vmovdqa64	%zmm5, %zmm27
        vpternlogq	$0xe2, %zmm6, %zmm4, %zmm27
        vprorq	$14, %zmm4, %zmm24
        vprorq	$18, %zmm4, %zmm25
        vprorq	$41, %zmm4, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm7, %zmm7
        vprorq	$28, %zmm0, %zmm24
        vprorq	$34, %zmm0, %zmm25
        vprorq	$39, %zmm0, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm1, %zmm27
        vpternlogq	$0xe8, %zmm2, %zmm0, %zmm27
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm7, %zmm7
        vprorq	$0x01, %zmm18, %zmm24
        vprorq	$8, %zmm18, %zmm25
        vpsrlq	$7, %zmm18, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm15, %zmm25
        vprorq	$61, %zmm15, %zmm26
        vpsrlq	$6, %zmm15, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm17, %zmm17
        vpaddq	%zmm25, %zmm17, %zmm17
        vpaddq	%zmm10, %zmm17, %zmm17
        vpaddq	72(%rbp){1to8}, %zmm6, %zmm6
        vpaddq	%zmm17, %zmm6, %zmm6
        vpaddq	%zmm6, %zmm2, %zmm2
        vmovdqa64	%zmm4, %zmm27
        vpternlogq	$0xe2, %zmm5, %zmm3, %zmm27
        vprorq	$14, %zmm3, %zmm24
        vprorq	$18, %zmm3, %zmm25
        vprorq	$41, %zmm3, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm6, %zmm6
        vprorq	$28, %zmm7, %zmm24
        vprorq	$34, %zmm7, %zmm25
        vprorq	$39, %zmm7, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm0, %zmm27
        vpternlogq	$0xe8, %zmm1, %zmm7, %zmm27
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm6, %zmm6
        vprorq	$0x01, %zmm19, %zmm24
        vprorq	$8, %zmm19, %zmm25
        vpsrlq	$7, %zmm19, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm16, %zmm25
        vprorq	$61, %zmm16, %zmm26
        vpsrlq	$6, %zmm16, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm18, %zmm18
        vpaddq	%zmm25, %zmm18, %zmm18
        vpaddq	%zmm11, %zmm18, %zmm18
        vpaddq	80(%rbp){1to8}, %zmm5, %zmm5
        vpaddq	%zmm18, %zmm5, %zmm5
        vpaddq	%zmm5, %zmm1, %zmm1
        vmovdqa64	%zmm3, %zmm27
        vpternlogq	$0xe2, %zmm4, %zmm2, %zmm27
        vprorq	$14, %zmm2, %zmm24
        vprorq	$18, %zmm2, %zmm25
        vprorq	$41, %zmm2, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm5, %zmm5
        vprorq	$28, %zmm6, %zmm24
        vprorq	$34, %zmm6, %zmm25
        vprorq	$39, %zmm6, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm7, %zmm27
        vpternlogq	$0xe8, %zmm0, %zmm6, %zmm27
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm5, %zmm5
        vprorq	$0x01, %zmm20, %zmm24
        vprorq	$8, %zmm20, %zmm25
        vpsrlq	$7, %zmm20, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm17, %zmm25
        vprorq	$61, %zmm17, %zmm26
        vpsrlq	$6, %zmm17, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm19, %zmm19
        vpaddq	%zmm25, %zmm19, %zmm19
        vpaddq	%zmm12, %zmm19, %zmm19
        vpaddq	88(%rbp){1to8}, %zmm4, %zmm4
        vpaddq	%zmm19, %zmm4, %zmm4
        vpaddq	%zmm4, %zmm0, %zmm0
        vmovdqa64	%zmm2, %zmm27
        vpternlogq	$0xe2, %zmm3, %zmm1, %zmm27
        vprorq	$14, %zmm1, %zmm24
        vprorq	$18, %zmm1, %zmm25
        vprorq	$41, %zmm1, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm4, %zmm4
        vprorq	$28, %zmm5, %zmm24
        vprorq	$34, %zmm5, %zmm25
        vprorq	$39, %zmm5, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm6, %zmm27
        vpternlogq	$0xe8, %zmm7, %zmm5, %zmm27
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm4, %zmm4
        vprorq	$0x01, %zmm21, %zmm24
        vprorq	$8, %zmm21, %zmm25
        vpsrlq	$7, %zmm21, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm18, %zmm25
        vprorq	$61, %zmm18, %zmm26
        vpsrlq	$6, %zmm18, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm20, %zmm20
        vpaddq	%zmm25, %zmm20, %zmm20
        vpaddq	%zmm13, %zmm20, %zmm20
        vpaddq	96(%rbp){1to8}, %zmm3, %zmm3
        vpaddq	%zmm20, %zmm3, %zmm3
        vpaddq	%zmm3, %zmm7, %zmm7
        vmovdqa64	%zmm1, %zmm27
        vpternlogq	$0xe2, %zmm2, %zmm0, %zmm27
        vprorq	$14, %zmm0, %zmm24
        vprorq	$18, %zmm0, %zmm25
        vprorq	$41, %zmm0, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm3, %zmm3
        vprorq	$28, %zmm4, %zmm24
        vprorq	$34, %zmm4, %zmm25
        vprorq	$39, %zmm4, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm5, %zmm27
        vpternlogq	$0xe8, %zmm6, %zmm4, %zmm27
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm3, %zmm3
        vprorq	$0x01, %zmm22, %zmm24
        vprorq	$8, %zmm22, %zmm25
        vpsrlq	$7, %zmm22, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm19, %zmm25
        vprorq	$61, %zmm19, %zmm26
        vpsrlq	$6, %zmm19, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm21, %zmm21
        vpaddq	%zmm25, %zmm21, %zmm21
        vpaddq	%zmm14, %zmm21, %zmm21
        vpaddq	104(%rbp){1to8}, %zmm2, %zmm2
        vpaddq	%zmm21, %zmm2, %zmm2
        vpaddq	%zmm2, %zmm6, %zmm6
        vmovdqa64	%zmm0, %zmm27
        vpternlogq	$0xe2, %zmm1, %zmm7, %zmm27
        vprorq	$14, %zmm7, %zmm24
        vprorq	$18, %zmm7, %zmm25
        vprorq	$41, %zmm7, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm2, %zmm2
        vprorq	$28, %zmm3, %zmm24
        vprorq	$34, %zmm3, %zmm25
        vprorq	$39, %zmm3, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm4, %zmm27
        vpternlogq	$0xe8, %zmm5, %zmm3, %zmm27
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm2, %zmm2
        vprorq	$0x01, %zmm23, %zmm24
        vprorq	$8, %zmm23, %zmm25
        vpsrlq	$7, %zmm23, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm20, %zmm25
        vprorq	$61, %zmm20, %zmm26
        vpsrlq	$6, %zmm20, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm22, %zmm22
        vpaddq	%zmm25, %zmm22, %zmm22
        vpaddq	%zmm15, %zmm22, %zmm22
        vpaddq	112(%rbp){1to8}, %zmm1, %zmm1
        vpaddq	%zmm22, %zmm1, %zmm1
        vpaddq	%zmm1, %zmm5, %zmm5
        vmovdqa64	%zmm7, %zmm27
        vpternlogq	$0xe2, %zmm0, %zmm6, %zmm27
        vprorq	$14, %zmm6, %zmm24
        vprorq	$18, %zmm6, %zmm25
        vprorq	$41, %zmm6, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm1, %zmm1
        vprorq	$28, %zmm2, %zmm24
        vprorq	$34, %zmm2, %zmm25
        vprorq	$39, %zmm2, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm3, %zmm27
        vpternlogq	$0xe8, %zmm4, %zmm2, %zmm27
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm1, %zmm1
        vprorq	$0x01, %zmm8, %zmm24
        vprorq	$8, %zmm8, %zmm25
        vpsrlq	$7, %zmm8, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm21, %zmm25
        vprorq	$61, %zmm21, %zmm26
        vpsrlq	$6, %zmm21, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm23, %zmm23
        vpaddq	%zmm25, %zmm23, %zmm23
        vpaddq	%zmm16, %zmm23, %zmm23
        vpaddq	120(%rbp){1to8}, %zmm0, %zmm0
        vpaddq	%zmm23, %zmm0, %zmm0
        vpaddq	%zmm0, %zmm4, %zmm4
        vmovdqa64	%zmm6, %zmm27
        vpternlogq	$0xe2, %zmm7, %zmm5, %zmm27
        vprorq	$14, %zmm5, %zmm24
        vprorq	$18, %zmm5, %zmm25
        vprorq	$41, %zmm5, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm0, %zmm0
        vprorq	$28, %zmm1, %zmm24
        vprorq	$34, %zmm1, %zmm25
        vprorq	$39, %zmm1, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm2, %zmm27
        vpternlogq	$0xe8, %zmm3, %zmm1, %zmm27
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm0, %zmm0
        addq	$0x80, %rbp
        subl	$0x01, %eax
        jnz	L_sha512_x8_avx512_bw_start
        # Add the compressed block into the states
        vpaddq	(%rdi), %zmm0, %zmm0
        vmovdqu64	%zmm0, (%rdi)
        vpaddq	64(%rdi), %zmm1, %zmm1
        vmovdqu64	%zmm1, 64(%rdi)
        vpaddq	128(%rdi), %zmm2, %zmm2
        vmovdqu64	%zmm2, 128(%rdi)
        vpaddq	192(%rdi), %zmm3, %zmm3
        vmovdqu64	%zmm3, 192(%rdi)
        vpaddq	256(%rdi), %zmm4, %zmm4
        vmovdqu64	%zmm4, 256(%rdi)
        vpaddq	320(%rdi), %zmm5, %zmm5
        vmovdqu64	%zmm5, 320(%rdi)
        vpaddq	384(%rdi), %zmm6, %zmm6
        vmovdqu64	%zmm6, 384(%rdi)
        vpaddq	448(%rdi), %zmm7, %zmm7
        vmovdqu64	%zmm7, 448(%rdi)
        vzeroupper
        popq	%rbp
        repz retq
#ifndef __APPLE__
.size	Transform_Sha512_x8_AVX512_BW,.-Transform_Sha512_x8_AVX512_BW
#endif /* __APPLE__ */
#endif /* !defined(NO_AVX512BW_SUPPORT) */
#ifdef WOLFSSL_HAVE_XMSS
#ifndef __APPLE__
.data
#else
.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
.align	32
#else
.p2align	5
#endif /* __APPLE__ */
L_avx512_sha512_x8_iv:
.quad	0x6a09e667f3bcc908,0xbb67ae8584caa73b
.quad	0x3c6ef372fe94f82b,0xa54ff53a5f1d36f1
.quad	0x510e527fade682d1,0x9b05688c2b3e6c1f
.quad	0x1f83d9abfb41bd6b,0x5be0cd19137e2179
#ifndef __APPLE__
.data
#else
.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
.align	32
#else
.p2align	5
#endif /* __APPLE__ */
L_avx512_sha512_x8_pad80q:
.quad	0x8000000000000000
#ifndef __APPLE__
.data
#else
.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
.align	32
#else
.p2align	5
#endif /* __APPLE__ */
L_avx512_sha512_x8_len1280:
.quad	0x0000000000000500
#ifndef __APPLE__
.data
#else
.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
.align	32
#else
.p2align	5
#endif /* __APPLE__ */
L_avx512_sha512_x8_len1536:
.quad	0x0000000000000600
#ifndef __APPLE__
.data
#else
.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
.align	32
#else
.p2align	5
#endif /* __APPLE__ */
L_avx512_sha512_x8_hi32:
.quad	0xffffffff00000000
#ifndef __APPLE__
.data
#else
.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
.align	32
#else
.p2align	5
#endif /* __APPLE__ */
L_avx512_sha512_x8_lo32:
.quad	0x00000000ffffffff
#ifndef __APPLE__
.text
.globl	Transform_Sha512_x8_XmssPrf_AVX512
WC_ASM_ATT_HIDDEN(Transform_Sha512_x8_XmssPrf_AVX512)
.type	Transform_Sha512_x8_XmssPrf_AVX512,@function
.align	16
Transform_Sha512_x8_XmssPrf_AVX512:
#else
.section	__TEXT,__text
.globl	_Transform_Sha512_x8_XmssPrf_AVX512
WC_ASM_ATT_HIDDEN(_Transform_Sha512_x8_XmssPrf_AVX512)
.p2align	4
_Transform_Sha512_x8_XmssPrf_AVX512:
#endif /* __APPLE__ */
        pushq	%rbp
        leaq	L_avx512_sha512_x8_k(%rip), %rbp
        vpbroadcastq	(%rdx), %zmm8
        vpbroadcastq	8(%rdx), %zmm9
        # Word 2: the OTS address, then the chain address under it
        vpbroadcastq	16(%rdx), %zmm10
        vpbroadcastq	L_avx512_sha512_x8_hi32(%rip), %zmm25
        vpandq	%zmm25, %zmm10, %zmm10
        vpmovzxdq	(%rcx), %zmm24
        vporq	%zmm24, %zmm10, %zmm10
        # Word 3: the key-and-mask word, then the hash address over it
        vpbroadcastq	24(%rdx), %zmm11
        vpbroadcastq	L_avx512_sha512_x8_lo32(%rip), %zmm25
        vpandq	%zmm25, %zmm11, %zmm11
        vpmovzxdq	(%r8), %zmm24
        vpsllq	$32, %zmm24, %zmm24
        vporq	%zmm24, %zmm11, %zmm11
        # Padding for a 160-byte message, the last 128 of it this block
        vpbroadcastq	L_avx512_sha512_x8_pad80q(%rip), %zmm12
        vpxorq	%zmm13, %zmm13, %zmm13
        vpxorq	%zmm14, %zmm14, %zmm14
        vpxorq	%zmm15, %zmm15, %zmm15
        vpxorq	%zmm16, %zmm16, %zmm16
        vpxorq	%zmm17, %zmm17, %zmm17
        vpxorq	%zmm18, %zmm18, %zmm18
        vpxorq	%zmm19, %zmm19, %zmm19
        vpxorq	%zmm20, %zmm20, %zmm20
        vpxorq	%zmm21, %zmm21, %zmm21
        vpxorq	%zmm22, %zmm22, %zmm22
        vpbroadcastq	L_avx512_sha512_x8_len1280(%rip), %zmm23
        # Carry on from the state padding || SEED left behind
        vpbroadcastq	(%rsi), %zmm0
        vpbroadcastq	8(%rsi), %zmm1
        vpbroadcastq	16(%rsi), %zmm2
        vpbroadcastq	24(%rsi), %zmm3
        vpbroadcastq	32(%rsi), %zmm4
        vpbroadcastq	40(%rsi), %zmm5
        vpbroadcastq	48(%rsi), %zmm6
        vpbroadcastq	56(%rsi), %zmm7
        # Rounds 0-15: the schedule is the message block itself
        vpaddq	(%rbp){1to8}, %zmm7, %zmm7
        vpaddq	%zmm8, %zmm7, %zmm7
        vpaddq	%zmm7, %zmm3, %zmm3
        vmovdqa64	%zmm5, %zmm27
        vpternlogq	$0xe2, %zmm6, %zmm4, %zmm27
        vprorq	$14, %zmm4, %zmm24
        vprorq	$18, %zmm4, %zmm25
        vprorq	$41, %zmm4, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm7, %zmm7
        vprorq	$28, %zmm0, %zmm24
        vprorq	$34, %zmm0, %zmm25
        vprorq	$39, %zmm0, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm1, %zmm27
        vpternlogq	$0xe8, %zmm2, %zmm0, %zmm27
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm7, %zmm7
        vpaddq	8(%rbp){1to8}, %zmm6, %zmm6
        vpaddq	%zmm9, %zmm6, %zmm6
        vpaddq	%zmm6, %zmm2, %zmm2
        vmovdqa64	%zmm4, %zmm27
        vpternlogq	$0xe2, %zmm5, %zmm3, %zmm27
        vprorq	$14, %zmm3, %zmm24
        vprorq	$18, %zmm3, %zmm25
        vprorq	$41, %zmm3, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm6, %zmm6
        vprorq	$28, %zmm7, %zmm24
        vprorq	$34, %zmm7, %zmm25
        vprorq	$39, %zmm7, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm0, %zmm27
        vpternlogq	$0xe8, %zmm1, %zmm7, %zmm27
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm6, %zmm6
        vpaddq	16(%rbp){1to8}, %zmm5, %zmm5
        vpaddq	%zmm10, %zmm5, %zmm5
        vpaddq	%zmm5, %zmm1, %zmm1
        vmovdqa64	%zmm3, %zmm27
        vpternlogq	$0xe2, %zmm4, %zmm2, %zmm27
        vprorq	$14, %zmm2, %zmm24
        vprorq	$18, %zmm2, %zmm25
        vprorq	$41, %zmm2, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm5, %zmm5
        vprorq	$28, %zmm6, %zmm24
        vprorq	$34, %zmm6, %zmm25
        vprorq	$39, %zmm6, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm7, %zmm27
        vpternlogq	$0xe8, %zmm0, %zmm6, %zmm27
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm5, %zmm5
        vpaddq	24(%rbp){1to8}, %zmm4, %zmm4
        vpaddq	%zmm11, %zmm4, %zmm4
        vpaddq	%zmm4, %zmm0, %zmm0
        vmovdqa64	%zmm2, %zmm27
        vpternlogq	$0xe2, %zmm3, %zmm1, %zmm27
        vprorq	$14, %zmm1, %zmm24
        vprorq	$18, %zmm1, %zmm25
        vprorq	$41, %zmm1, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm4, %zmm4
        vprorq	$28, %zmm5, %zmm24
        vprorq	$34, %zmm5, %zmm25
        vprorq	$39, %zmm5, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm6, %zmm27
        vpternlogq	$0xe8, %zmm7, %zmm5, %zmm27
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm4, %zmm4
        vpaddq	32(%rbp){1to8}, %zmm3, %zmm3
        vpaddq	%zmm12, %zmm3, %zmm3
        vpaddq	%zmm3, %zmm7, %zmm7
        vmovdqa64	%zmm1, %zmm27
        vpternlogq	$0xe2, %zmm2, %zmm0, %zmm27
        vprorq	$14, %zmm0, %zmm24
        vprorq	$18, %zmm0, %zmm25
        vprorq	$41, %zmm0, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm3, %zmm3
        vprorq	$28, %zmm4, %zmm24
        vprorq	$34, %zmm4, %zmm25
        vprorq	$39, %zmm4, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm5, %zmm27
        vpternlogq	$0xe8, %zmm6, %zmm4, %zmm27
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm3, %zmm3
        vpaddq	40(%rbp){1to8}, %zmm2, %zmm2
        vpaddq	%zmm13, %zmm2, %zmm2
        vpaddq	%zmm2, %zmm6, %zmm6
        vmovdqa64	%zmm0, %zmm27
        vpternlogq	$0xe2, %zmm1, %zmm7, %zmm27
        vprorq	$14, %zmm7, %zmm24
        vprorq	$18, %zmm7, %zmm25
        vprorq	$41, %zmm7, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm2, %zmm2
        vprorq	$28, %zmm3, %zmm24
        vprorq	$34, %zmm3, %zmm25
        vprorq	$39, %zmm3, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm4, %zmm27
        vpternlogq	$0xe8, %zmm5, %zmm3, %zmm27
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm2, %zmm2
        vpaddq	48(%rbp){1to8}, %zmm1, %zmm1
        vpaddq	%zmm14, %zmm1, %zmm1
        vpaddq	%zmm1, %zmm5, %zmm5
        vmovdqa64	%zmm7, %zmm27
        vpternlogq	$0xe2, %zmm0, %zmm6, %zmm27
        vprorq	$14, %zmm6, %zmm24
        vprorq	$18, %zmm6, %zmm25
        vprorq	$41, %zmm6, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm1, %zmm1
        vprorq	$28, %zmm2, %zmm24
        vprorq	$34, %zmm2, %zmm25
        vprorq	$39, %zmm2, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm3, %zmm27
        vpternlogq	$0xe8, %zmm4, %zmm2, %zmm27
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm1, %zmm1
        vpaddq	56(%rbp){1to8}, %zmm0, %zmm0
        vpaddq	%zmm15, %zmm0, %zmm0
        vpaddq	%zmm0, %zmm4, %zmm4
        vmovdqa64	%zmm6, %zmm27
        vpternlogq	$0xe2, %zmm7, %zmm5, %zmm27
        vprorq	$14, %zmm5, %zmm24
        vprorq	$18, %zmm5, %zmm25
        vprorq	$41, %zmm5, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm0, %zmm0
        vprorq	$28, %zmm1, %zmm24
        vprorq	$34, %zmm1, %zmm25
        vprorq	$39, %zmm1, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm2, %zmm27
        vpternlogq	$0xe8, %zmm3, %zmm1, %zmm27
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm0, %zmm0
        vpaddq	64(%rbp){1to8}, %zmm7, %zmm7
        vpaddq	%zmm16, %zmm7, %zmm7
        vpaddq	%zmm7, %zmm3, %zmm3
        vmovdqa64	%zmm5, %zmm27
        vpternlogq	$0xe2, %zmm6, %zmm4, %zmm27
        vprorq	$14, %zmm4, %zmm24
        vprorq	$18, %zmm4, %zmm25
        vprorq	$41, %zmm4, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm7, %zmm7
        vprorq	$28, %zmm0, %zmm24
        vprorq	$34, %zmm0, %zmm25
        vprorq	$39, %zmm0, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm1, %zmm27
        vpternlogq	$0xe8, %zmm2, %zmm0, %zmm27
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm7, %zmm7
        vpaddq	72(%rbp){1to8}, %zmm6, %zmm6
        vpaddq	%zmm17, %zmm6, %zmm6
        vpaddq	%zmm6, %zmm2, %zmm2
        vmovdqa64	%zmm4, %zmm27
        vpternlogq	$0xe2, %zmm5, %zmm3, %zmm27
        vprorq	$14, %zmm3, %zmm24
        vprorq	$18, %zmm3, %zmm25
        vprorq	$41, %zmm3, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm6, %zmm6
        vprorq	$28, %zmm7, %zmm24
        vprorq	$34, %zmm7, %zmm25
        vprorq	$39, %zmm7, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm0, %zmm27
        vpternlogq	$0xe8, %zmm1, %zmm7, %zmm27
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm6, %zmm6
        vpaddq	80(%rbp){1to8}, %zmm5, %zmm5
        vpaddq	%zmm18, %zmm5, %zmm5
        vpaddq	%zmm5, %zmm1, %zmm1
        vmovdqa64	%zmm3, %zmm27
        vpternlogq	$0xe2, %zmm4, %zmm2, %zmm27
        vprorq	$14, %zmm2, %zmm24
        vprorq	$18, %zmm2, %zmm25
        vprorq	$41, %zmm2, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm5, %zmm5
        vprorq	$28, %zmm6, %zmm24
        vprorq	$34, %zmm6, %zmm25
        vprorq	$39, %zmm6, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm7, %zmm27
        vpternlogq	$0xe8, %zmm0, %zmm6, %zmm27
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm5, %zmm5
        vpaddq	88(%rbp){1to8}, %zmm4, %zmm4
        vpaddq	%zmm19, %zmm4, %zmm4
        vpaddq	%zmm4, %zmm0, %zmm0
        vmovdqa64	%zmm2, %zmm27
        vpternlogq	$0xe2, %zmm3, %zmm1, %zmm27
        vprorq	$14, %zmm1, %zmm24
        vprorq	$18, %zmm1, %zmm25
        vprorq	$41, %zmm1, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm4, %zmm4
        vprorq	$28, %zmm5, %zmm24
        vprorq	$34, %zmm5, %zmm25
        vprorq	$39, %zmm5, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm6, %zmm27
        vpternlogq	$0xe8, %zmm7, %zmm5, %zmm27
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm4, %zmm4
        vpaddq	96(%rbp){1to8}, %zmm3, %zmm3
        vpaddq	%zmm20, %zmm3, %zmm3
        vpaddq	%zmm3, %zmm7, %zmm7
        vmovdqa64	%zmm1, %zmm27
        vpternlogq	$0xe2, %zmm2, %zmm0, %zmm27
        vprorq	$14, %zmm0, %zmm24
        vprorq	$18, %zmm0, %zmm25
        vprorq	$41, %zmm0, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm3, %zmm3
        vprorq	$28, %zmm4, %zmm24
        vprorq	$34, %zmm4, %zmm25
        vprorq	$39, %zmm4, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm5, %zmm27
        vpternlogq	$0xe8, %zmm6, %zmm4, %zmm27
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm3, %zmm3
        vpaddq	104(%rbp){1to8}, %zmm2, %zmm2
        vpaddq	%zmm21, %zmm2, %zmm2
        vpaddq	%zmm2, %zmm6, %zmm6
        vmovdqa64	%zmm0, %zmm27
        vpternlogq	$0xe2, %zmm1, %zmm7, %zmm27
        vprorq	$14, %zmm7, %zmm24
        vprorq	$18, %zmm7, %zmm25
        vprorq	$41, %zmm7, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm2, %zmm2
        vprorq	$28, %zmm3, %zmm24
        vprorq	$34, %zmm3, %zmm25
        vprorq	$39, %zmm3, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm4, %zmm27
        vpternlogq	$0xe8, %zmm5, %zmm3, %zmm27
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm2, %zmm2
        vpaddq	112(%rbp){1to8}, %zmm1, %zmm1
        vpaddq	%zmm22, %zmm1, %zmm1
        vpaddq	%zmm1, %zmm5, %zmm5
        vmovdqa64	%zmm7, %zmm27
        vpternlogq	$0xe2, %zmm0, %zmm6, %zmm27
        vprorq	$14, %zmm6, %zmm24
        vprorq	$18, %zmm6, %zmm25
        vprorq	$41, %zmm6, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm1, %zmm1
        vprorq	$28, %zmm2, %zmm24
        vprorq	$34, %zmm2, %zmm25
        vprorq	$39, %zmm2, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm3, %zmm27
        vpternlogq	$0xe8, %zmm4, %zmm2, %zmm27
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm1, %zmm1
        vpaddq	120(%rbp){1to8}, %zmm0, %zmm0
        vpaddq	%zmm23, %zmm0, %zmm0
        vpaddq	%zmm0, %zmm4, %zmm4
        vmovdqa64	%zmm6, %zmm27
        vpternlogq	$0xe2, %zmm7, %zmm5, %zmm27
        vprorq	$14, %zmm5, %zmm24
        vprorq	$18, %zmm5, %zmm25
        vprorq	$41, %zmm5, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm0, %zmm0
        vprorq	$28, %zmm1, %zmm24
        vprorq	$34, %zmm1, %zmm25
        vprorq	$39, %zmm1, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm2, %zmm27
        vpternlogq	$0xe8, %zmm3, %zmm1, %zmm27
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm0, %zmm0
        addq	$0x80, %rbp
        movl	$4, %eax
L_sha512_x8_xmss_prf_start:
        vprorq	$0x01, %zmm9, %zmm24
        vprorq	$8, %zmm9, %zmm25
        vpsrlq	$7, %zmm9, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm22, %zmm25
        vprorq	$61, %zmm22, %zmm26
        vpsrlq	$6, %zmm22, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm8, %zmm8
        vpaddq	%zmm25, %zmm8, %zmm8
        vpaddq	%zmm17, %zmm8, %zmm8
        vpaddq	(%rbp){1to8}, %zmm7, %zmm7
        vpaddq	%zmm8, %zmm7, %zmm7
        vpaddq	%zmm7, %zmm3, %zmm3
        vmovdqa64	%zmm5, %zmm27
        vpternlogq	$0xe2, %zmm6, %zmm4, %zmm27
        vprorq	$14, %zmm4, %zmm24
        vprorq	$18, %zmm4, %zmm25
        vprorq	$41, %zmm4, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm7, %zmm7
        vprorq	$28, %zmm0, %zmm24
        vprorq	$34, %zmm0, %zmm25
        vprorq	$39, %zmm0, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm1, %zmm27
        vpternlogq	$0xe8, %zmm2, %zmm0, %zmm27
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm7, %zmm7
        vprorq	$0x01, %zmm10, %zmm24
        vprorq	$8, %zmm10, %zmm25
        vpsrlq	$7, %zmm10, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm23, %zmm25
        vprorq	$61, %zmm23, %zmm26
        vpsrlq	$6, %zmm23, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm9, %zmm9
        vpaddq	%zmm25, %zmm9, %zmm9
        vpaddq	%zmm18, %zmm9, %zmm9
        vpaddq	8(%rbp){1to8}, %zmm6, %zmm6
        vpaddq	%zmm9, %zmm6, %zmm6
        vpaddq	%zmm6, %zmm2, %zmm2
        vmovdqa64	%zmm4, %zmm27
        vpternlogq	$0xe2, %zmm5, %zmm3, %zmm27
        vprorq	$14, %zmm3, %zmm24
        vprorq	$18, %zmm3, %zmm25
        vprorq	$41, %zmm3, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm6, %zmm6
        vprorq	$28, %zmm7, %zmm24
        vprorq	$34, %zmm7, %zmm25
        vprorq	$39, %zmm7, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm0, %zmm27
        vpternlogq	$0xe8, %zmm1, %zmm7, %zmm27
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm6, %zmm6
        vprorq	$0x01, %zmm11, %zmm24
        vprorq	$8, %zmm11, %zmm25
        vpsrlq	$7, %zmm11, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm8, %zmm25
        vprorq	$61, %zmm8, %zmm26
        vpsrlq	$6, %zmm8, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm10, %zmm10
        vpaddq	%zmm25, %zmm10, %zmm10
        vpaddq	%zmm19, %zmm10, %zmm10
        vpaddq	16(%rbp){1to8}, %zmm5, %zmm5
        vpaddq	%zmm10, %zmm5, %zmm5
        vpaddq	%zmm5, %zmm1, %zmm1
        vmovdqa64	%zmm3, %zmm27
        vpternlogq	$0xe2, %zmm4, %zmm2, %zmm27
        vprorq	$14, %zmm2, %zmm24
        vprorq	$18, %zmm2, %zmm25
        vprorq	$41, %zmm2, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm5, %zmm5
        vprorq	$28, %zmm6, %zmm24
        vprorq	$34, %zmm6, %zmm25
        vprorq	$39, %zmm6, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm7, %zmm27
        vpternlogq	$0xe8, %zmm0, %zmm6, %zmm27
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm5, %zmm5
        vprorq	$0x01, %zmm12, %zmm24
        vprorq	$8, %zmm12, %zmm25
        vpsrlq	$7, %zmm12, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm9, %zmm25
        vprorq	$61, %zmm9, %zmm26
        vpsrlq	$6, %zmm9, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm11, %zmm11
        vpaddq	%zmm25, %zmm11, %zmm11
        vpaddq	%zmm20, %zmm11, %zmm11
        vpaddq	24(%rbp){1to8}, %zmm4, %zmm4
        vpaddq	%zmm11, %zmm4, %zmm4
        vpaddq	%zmm4, %zmm0, %zmm0
        vmovdqa64	%zmm2, %zmm27
        vpternlogq	$0xe2, %zmm3, %zmm1, %zmm27
        vprorq	$14, %zmm1, %zmm24
        vprorq	$18, %zmm1, %zmm25
        vprorq	$41, %zmm1, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm4, %zmm4
        vprorq	$28, %zmm5, %zmm24
        vprorq	$34, %zmm5, %zmm25
        vprorq	$39, %zmm5, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm6, %zmm27
        vpternlogq	$0xe8, %zmm7, %zmm5, %zmm27
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm4, %zmm4
        vprorq	$0x01, %zmm13, %zmm24
        vprorq	$8, %zmm13, %zmm25
        vpsrlq	$7, %zmm13, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm10, %zmm25
        vprorq	$61, %zmm10, %zmm26
        vpsrlq	$6, %zmm10, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm12, %zmm12
        vpaddq	%zmm25, %zmm12, %zmm12
        vpaddq	%zmm21, %zmm12, %zmm12
        vpaddq	32(%rbp){1to8}, %zmm3, %zmm3
        vpaddq	%zmm12, %zmm3, %zmm3
        vpaddq	%zmm3, %zmm7, %zmm7
        vmovdqa64	%zmm1, %zmm27
        vpternlogq	$0xe2, %zmm2, %zmm0, %zmm27
        vprorq	$14, %zmm0, %zmm24
        vprorq	$18, %zmm0, %zmm25
        vprorq	$41, %zmm0, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm3, %zmm3
        vprorq	$28, %zmm4, %zmm24
        vprorq	$34, %zmm4, %zmm25
        vprorq	$39, %zmm4, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm5, %zmm27
        vpternlogq	$0xe8, %zmm6, %zmm4, %zmm27
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm3, %zmm3
        vprorq	$0x01, %zmm14, %zmm24
        vprorq	$8, %zmm14, %zmm25
        vpsrlq	$7, %zmm14, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm11, %zmm25
        vprorq	$61, %zmm11, %zmm26
        vpsrlq	$6, %zmm11, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm13, %zmm13
        vpaddq	%zmm25, %zmm13, %zmm13
        vpaddq	%zmm22, %zmm13, %zmm13
        vpaddq	40(%rbp){1to8}, %zmm2, %zmm2
        vpaddq	%zmm13, %zmm2, %zmm2
        vpaddq	%zmm2, %zmm6, %zmm6
        vmovdqa64	%zmm0, %zmm27
        vpternlogq	$0xe2, %zmm1, %zmm7, %zmm27
        vprorq	$14, %zmm7, %zmm24
        vprorq	$18, %zmm7, %zmm25
        vprorq	$41, %zmm7, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm2, %zmm2
        vprorq	$28, %zmm3, %zmm24
        vprorq	$34, %zmm3, %zmm25
        vprorq	$39, %zmm3, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm4, %zmm27
        vpternlogq	$0xe8, %zmm5, %zmm3, %zmm27
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm2, %zmm2
        vprorq	$0x01, %zmm15, %zmm24
        vprorq	$8, %zmm15, %zmm25
        vpsrlq	$7, %zmm15, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm12, %zmm25
        vprorq	$61, %zmm12, %zmm26
        vpsrlq	$6, %zmm12, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm14, %zmm14
        vpaddq	%zmm25, %zmm14, %zmm14
        vpaddq	%zmm23, %zmm14, %zmm14
        vpaddq	48(%rbp){1to8}, %zmm1, %zmm1
        vpaddq	%zmm14, %zmm1, %zmm1
        vpaddq	%zmm1, %zmm5, %zmm5
        vmovdqa64	%zmm7, %zmm27
        vpternlogq	$0xe2, %zmm0, %zmm6, %zmm27
        vprorq	$14, %zmm6, %zmm24
        vprorq	$18, %zmm6, %zmm25
        vprorq	$41, %zmm6, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm1, %zmm1
        vprorq	$28, %zmm2, %zmm24
        vprorq	$34, %zmm2, %zmm25
        vprorq	$39, %zmm2, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm3, %zmm27
        vpternlogq	$0xe8, %zmm4, %zmm2, %zmm27
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm1, %zmm1
        vprorq	$0x01, %zmm16, %zmm24
        vprorq	$8, %zmm16, %zmm25
        vpsrlq	$7, %zmm16, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm13, %zmm25
        vprorq	$61, %zmm13, %zmm26
        vpsrlq	$6, %zmm13, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm15, %zmm15
        vpaddq	%zmm25, %zmm15, %zmm15
        vpaddq	%zmm8, %zmm15, %zmm15
        vpaddq	56(%rbp){1to8}, %zmm0, %zmm0
        vpaddq	%zmm15, %zmm0, %zmm0
        vpaddq	%zmm0, %zmm4, %zmm4
        vmovdqa64	%zmm6, %zmm27
        vpternlogq	$0xe2, %zmm7, %zmm5, %zmm27
        vprorq	$14, %zmm5, %zmm24
        vprorq	$18, %zmm5, %zmm25
        vprorq	$41, %zmm5, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm0, %zmm0
        vprorq	$28, %zmm1, %zmm24
        vprorq	$34, %zmm1, %zmm25
        vprorq	$39, %zmm1, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm2, %zmm27
        vpternlogq	$0xe8, %zmm3, %zmm1, %zmm27
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm0, %zmm0
        vprorq	$0x01, %zmm17, %zmm24
        vprorq	$8, %zmm17, %zmm25
        vpsrlq	$7, %zmm17, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm14, %zmm25
        vprorq	$61, %zmm14, %zmm26
        vpsrlq	$6, %zmm14, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm16, %zmm16
        vpaddq	%zmm25, %zmm16, %zmm16
        vpaddq	%zmm9, %zmm16, %zmm16
        vpaddq	64(%rbp){1to8}, %zmm7, %zmm7
        vpaddq	%zmm16, %zmm7, %zmm7
        vpaddq	%zmm7, %zmm3, %zmm3
        vmovdqa64	%zmm5, %zmm27
        vpternlogq	$0xe2, %zmm6, %zmm4, %zmm27
        vprorq	$14, %zmm4, %zmm24
        vprorq	$18, %zmm4, %zmm25
        vprorq	$41, %zmm4, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm7, %zmm7
        vprorq	$28, %zmm0, %zmm24
        vprorq	$34, %zmm0, %zmm25
        vprorq	$39, %zmm0, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm1, %zmm27
        vpternlogq	$0xe8, %zmm2, %zmm0, %zmm27
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm7, %zmm7
        vprorq	$0x01, %zmm18, %zmm24
        vprorq	$8, %zmm18, %zmm25
        vpsrlq	$7, %zmm18, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm15, %zmm25
        vprorq	$61, %zmm15, %zmm26
        vpsrlq	$6, %zmm15, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm17, %zmm17
        vpaddq	%zmm25, %zmm17, %zmm17
        vpaddq	%zmm10, %zmm17, %zmm17
        vpaddq	72(%rbp){1to8}, %zmm6, %zmm6
        vpaddq	%zmm17, %zmm6, %zmm6
        vpaddq	%zmm6, %zmm2, %zmm2
        vmovdqa64	%zmm4, %zmm27
        vpternlogq	$0xe2, %zmm5, %zmm3, %zmm27
        vprorq	$14, %zmm3, %zmm24
        vprorq	$18, %zmm3, %zmm25
        vprorq	$41, %zmm3, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm6, %zmm6
        vprorq	$28, %zmm7, %zmm24
        vprorq	$34, %zmm7, %zmm25
        vprorq	$39, %zmm7, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm0, %zmm27
        vpternlogq	$0xe8, %zmm1, %zmm7, %zmm27
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm6, %zmm6
        vprorq	$0x01, %zmm19, %zmm24
        vprorq	$8, %zmm19, %zmm25
        vpsrlq	$7, %zmm19, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm16, %zmm25
        vprorq	$61, %zmm16, %zmm26
        vpsrlq	$6, %zmm16, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm18, %zmm18
        vpaddq	%zmm25, %zmm18, %zmm18
        vpaddq	%zmm11, %zmm18, %zmm18
        vpaddq	80(%rbp){1to8}, %zmm5, %zmm5
        vpaddq	%zmm18, %zmm5, %zmm5
        vpaddq	%zmm5, %zmm1, %zmm1
        vmovdqa64	%zmm3, %zmm27
        vpternlogq	$0xe2, %zmm4, %zmm2, %zmm27
        vprorq	$14, %zmm2, %zmm24
        vprorq	$18, %zmm2, %zmm25
        vprorq	$41, %zmm2, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm5, %zmm5
        vprorq	$28, %zmm6, %zmm24
        vprorq	$34, %zmm6, %zmm25
        vprorq	$39, %zmm6, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm7, %zmm27
        vpternlogq	$0xe8, %zmm0, %zmm6, %zmm27
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm5, %zmm5
        vprorq	$0x01, %zmm20, %zmm24
        vprorq	$8, %zmm20, %zmm25
        vpsrlq	$7, %zmm20, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm17, %zmm25
        vprorq	$61, %zmm17, %zmm26
        vpsrlq	$6, %zmm17, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm19, %zmm19
        vpaddq	%zmm25, %zmm19, %zmm19
        vpaddq	%zmm12, %zmm19, %zmm19
        vpaddq	88(%rbp){1to8}, %zmm4, %zmm4
        vpaddq	%zmm19, %zmm4, %zmm4
        vpaddq	%zmm4, %zmm0, %zmm0
        vmovdqa64	%zmm2, %zmm27
        vpternlogq	$0xe2, %zmm3, %zmm1, %zmm27
        vprorq	$14, %zmm1, %zmm24
        vprorq	$18, %zmm1, %zmm25
        vprorq	$41, %zmm1, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm4, %zmm4
        vprorq	$28, %zmm5, %zmm24
        vprorq	$34, %zmm5, %zmm25
        vprorq	$39, %zmm5, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm6, %zmm27
        vpternlogq	$0xe8, %zmm7, %zmm5, %zmm27
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm4, %zmm4
        vprorq	$0x01, %zmm21, %zmm24
        vprorq	$8, %zmm21, %zmm25
        vpsrlq	$7, %zmm21, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm18, %zmm25
        vprorq	$61, %zmm18, %zmm26
        vpsrlq	$6, %zmm18, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm20, %zmm20
        vpaddq	%zmm25, %zmm20, %zmm20
        vpaddq	%zmm13, %zmm20, %zmm20
        vpaddq	96(%rbp){1to8}, %zmm3, %zmm3
        vpaddq	%zmm20, %zmm3, %zmm3
        vpaddq	%zmm3, %zmm7, %zmm7
        vmovdqa64	%zmm1, %zmm27
        vpternlogq	$0xe2, %zmm2, %zmm0, %zmm27
        vprorq	$14, %zmm0, %zmm24
        vprorq	$18, %zmm0, %zmm25
        vprorq	$41, %zmm0, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm3, %zmm3
        vprorq	$28, %zmm4, %zmm24
        vprorq	$34, %zmm4, %zmm25
        vprorq	$39, %zmm4, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm5, %zmm27
        vpternlogq	$0xe8, %zmm6, %zmm4, %zmm27
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm3, %zmm3
        vprorq	$0x01, %zmm22, %zmm24
        vprorq	$8, %zmm22, %zmm25
        vpsrlq	$7, %zmm22, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm19, %zmm25
        vprorq	$61, %zmm19, %zmm26
        vpsrlq	$6, %zmm19, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm21, %zmm21
        vpaddq	%zmm25, %zmm21, %zmm21
        vpaddq	%zmm14, %zmm21, %zmm21
        vpaddq	104(%rbp){1to8}, %zmm2, %zmm2
        vpaddq	%zmm21, %zmm2, %zmm2
        vpaddq	%zmm2, %zmm6, %zmm6
        vmovdqa64	%zmm0, %zmm27
        vpternlogq	$0xe2, %zmm1, %zmm7, %zmm27
        vprorq	$14, %zmm7, %zmm24
        vprorq	$18, %zmm7, %zmm25
        vprorq	$41, %zmm7, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm2, %zmm2
        vprorq	$28, %zmm3, %zmm24
        vprorq	$34, %zmm3, %zmm25
        vprorq	$39, %zmm3, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm4, %zmm27
        vpternlogq	$0xe8, %zmm5, %zmm3, %zmm27
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm2, %zmm2
        vprorq	$0x01, %zmm23, %zmm24
        vprorq	$8, %zmm23, %zmm25
        vpsrlq	$7, %zmm23, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm20, %zmm25
        vprorq	$61, %zmm20, %zmm26
        vpsrlq	$6, %zmm20, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm22, %zmm22
        vpaddq	%zmm25, %zmm22, %zmm22
        vpaddq	%zmm15, %zmm22, %zmm22
        vpaddq	112(%rbp){1to8}, %zmm1, %zmm1
        vpaddq	%zmm22, %zmm1, %zmm1
        vpaddq	%zmm1, %zmm5, %zmm5
        vmovdqa64	%zmm7, %zmm27
        vpternlogq	$0xe2, %zmm0, %zmm6, %zmm27
        vprorq	$14, %zmm6, %zmm24
        vprorq	$18, %zmm6, %zmm25
        vprorq	$41, %zmm6, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm1, %zmm1
        vprorq	$28, %zmm2, %zmm24
        vprorq	$34, %zmm2, %zmm25
        vprorq	$39, %zmm2, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm3, %zmm27
        vpternlogq	$0xe8, %zmm4, %zmm2, %zmm27
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm1, %zmm1
        vprorq	$0x01, %zmm8, %zmm24
        vprorq	$8, %zmm8, %zmm25
        vpsrlq	$7, %zmm8, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm21, %zmm25
        vprorq	$61, %zmm21, %zmm26
        vpsrlq	$6, %zmm21, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm23, %zmm23
        vpaddq	%zmm25, %zmm23, %zmm23
        vpaddq	%zmm16, %zmm23, %zmm23
        vpaddq	120(%rbp){1to8}, %zmm0, %zmm0
        vpaddq	%zmm23, %zmm0, %zmm0
        vpaddq	%zmm0, %zmm4, %zmm4
        vmovdqa64	%zmm6, %zmm27
        vpternlogq	$0xe2, %zmm7, %zmm5, %zmm27
        vprorq	$14, %zmm5, %zmm24
        vprorq	$18, %zmm5, %zmm25
        vprorq	$41, %zmm5, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm0, %zmm0
        vprorq	$28, %zmm1, %zmm24
        vprorq	$34, %zmm1, %zmm25
        vprorq	$39, %zmm1, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm2, %zmm27
        vpternlogq	$0xe8, %zmm3, %zmm1, %zmm27
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm0, %zmm0
        addq	$0x80, %rbp
        subl	$0x01, %eax
        jnz	L_sha512_x8_xmss_prf_start
        # Add the midstate back; the digest stays interleaved for F
        vpbroadcastq	(%rsi), %zmm24
        vpaddq	%zmm24, %zmm0, %zmm0
        vmovdqu64	%zmm0, (%rdi)
        vpbroadcastq	8(%rsi), %zmm24
        vpaddq	%zmm24, %zmm1, %zmm1
        vmovdqu64	%zmm1, 64(%rdi)
        vpbroadcastq	16(%rsi), %zmm24
        vpaddq	%zmm24, %zmm2, %zmm2
        vmovdqu64	%zmm2, 128(%rdi)
        vpbroadcastq	24(%rsi), %zmm24
        vpaddq	%zmm24, %zmm3, %zmm3
        vmovdqu64	%zmm3, 192(%rdi)
        vpbroadcastq	32(%rsi), %zmm24
        vpaddq	%zmm24, %zmm4, %zmm4
        vmovdqu64	%zmm4, 256(%rdi)
        vpbroadcastq	40(%rsi), %zmm24
        vpaddq	%zmm24, %zmm5, %zmm5
        vmovdqu64	%zmm5, 320(%rdi)
        vpbroadcastq	48(%rsi), %zmm24
        vpaddq	%zmm24, %zmm6, %zmm6
        vmovdqu64	%zmm6, 384(%rdi)
        vpbroadcastq	56(%rsi), %zmm24
        vpaddq	%zmm24, %zmm7, %zmm7
        vmovdqu64	%zmm7, 448(%rdi)
        vzeroupper
        popq	%rbp
        repz retq
#ifndef __APPLE__
.size	Transform_Sha512_x8_XmssPrf_AVX512,.-Transform_Sha512_x8_XmssPrf_AVX512
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	Transform_Sha512_x8_XmssF_AVX512
WC_ASM_ATT_HIDDEN(Transform_Sha512_x8_XmssF_AVX512)
.type	Transform_Sha512_x8_XmssF_AVX512,@function
.align	16
Transform_Sha512_x8_XmssF_AVX512:
#else
.section	__TEXT,__text
.globl	_Transform_Sha512_x8_XmssF_AVX512
WC_ASM_ATT_HIDDEN(_Transform_Sha512_x8_XmssF_AVX512)
.p2align	4
_Transform_Sha512_x8_XmssF_AVX512:
#endif /* __APPLE__ */
        pushq	%rbp
        subq	$0x200, %rsp
        leaq	L_avx512_sha512_x8_iv(%rip), %r9
        # First block: the padding for F is zero, and then KEY
        vpxorq	%zmm8, %zmm8, %zmm8
        vpxorq	%zmm9, %zmm9, %zmm9
        vpxorq	%zmm10, %zmm10, %zmm10
        vpxorq	%zmm11, %zmm11, %zmm11
        vpxorq	%zmm12, %zmm12, %zmm12
        vpxorq	%zmm13, %zmm13, %zmm13
        vpxorq	%zmm14, %zmm14, %zmm14
        vpxorq	%zmm15, %zmm15, %zmm15
        vmovdqu64	(%rsi), %zmm16
        vmovdqu64	64(%rsi), %zmm17
        vmovdqu64	128(%rsi), %zmm18
        vmovdqu64	192(%rsi), %zmm19
        vmovdqu64	256(%rsi), %zmm20
        vmovdqu64	320(%rsi), %zmm21
        vmovdqu64	384(%rsi), %zmm22
        vmovdqu64	448(%rsi), %zmm23
        vpbroadcastq	(%r9), %zmm0
        vpbroadcastq	8(%r9), %zmm1
        vpbroadcastq	16(%r9), %zmm2
        vpbroadcastq	24(%r9), %zmm3
        vpbroadcastq	32(%r9), %zmm4
        vpbroadcastq	40(%r9), %zmm5
        vpbroadcastq	48(%r9), %zmm6
        vpbroadcastq	56(%r9), %zmm7
        leaq	L_avx512_sha512_x8_k(%rip), %rbp
        # Rounds 0-15: the schedule is the message block itself
        vpaddq	(%rbp){1to8}, %zmm7, %zmm7
        vpaddq	%zmm8, %zmm7, %zmm7
        vpaddq	%zmm7, %zmm3, %zmm3
        vmovdqa64	%zmm5, %zmm27
        vpternlogq	$0xe2, %zmm6, %zmm4, %zmm27
        vprorq	$14, %zmm4, %zmm24
        vprorq	$18, %zmm4, %zmm25
        vprorq	$41, %zmm4, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm7, %zmm7
        vprorq	$28, %zmm0, %zmm24
        vprorq	$34, %zmm0, %zmm25
        vprorq	$39, %zmm0, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm1, %zmm27
        vpternlogq	$0xe8, %zmm2, %zmm0, %zmm27
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm7, %zmm7
        vpaddq	8(%rbp){1to8}, %zmm6, %zmm6
        vpaddq	%zmm9, %zmm6, %zmm6
        vpaddq	%zmm6, %zmm2, %zmm2
        vmovdqa64	%zmm4, %zmm27
        vpternlogq	$0xe2, %zmm5, %zmm3, %zmm27
        vprorq	$14, %zmm3, %zmm24
        vprorq	$18, %zmm3, %zmm25
        vprorq	$41, %zmm3, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm6, %zmm6
        vprorq	$28, %zmm7, %zmm24
        vprorq	$34, %zmm7, %zmm25
        vprorq	$39, %zmm7, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm0, %zmm27
        vpternlogq	$0xe8, %zmm1, %zmm7, %zmm27
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm6, %zmm6
        vpaddq	16(%rbp){1to8}, %zmm5, %zmm5
        vpaddq	%zmm10, %zmm5, %zmm5
        vpaddq	%zmm5, %zmm1, %zmm1
        vmovdqa64	%zmm3, %zmm27
        vpternlogq	$0xe2, %zmm4, %zmm2, %zmm27
        vprorq	$14, %zmm2, %zmm24
        vprorq	$18, %zmm2, %zmm25
        vprorq	$41, %zmm2, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm5, %zmm5
        vprorq	$28, %zmm6, %zmm24
        vprorq	$34, %zmm6, %zmm25
        vprorq	$39, %zmm6, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm7, %zmm27
        vpternlogq	$0xe8, %zmm0, %zmm6, %zmm27
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm5, %zmm5
        vpaddq	24(%rbp){1to8}, %zmm4, %zmm4
        vpaddq	%zmm11, %zmm4, %zmm4
        vpaddq	%zmm4, %zmm0, %zmm0
        vmovdqa64	%zmm2, %zmm27
        vpternlogq	$0xe2, %zmm3, %zmm1, %zmm27
        vprorq	$14, %zmm1, %zmm24
        vprorq	$18, %zmm1, %zmm25
        vprorq	$41, %zmm1, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm4, %zmm4
        vprorq	$28, %zmm5, %zmm24
        vprorq	$34, %zmm5, %zmm25
        vprorq	$39, %zmm5, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm6, %zmm27
        vpternlogq	$0xe8, %zmm7, %zmm5, %zmm27
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm4, %zmm4
        vpaddq	32(%rbp){1to8}, %zmm3, %zmm3
        vpaddq	%zmm12, %zmm3, %zmm3
        vpaddq	%zmm3, %zmm7, %zmm7
        vmovdqa64	%zmm1, %zmm27
        vpternlogq	$0xe2, %zmm2, %zmm0, %zmm27
        vprorq	$14, %zmm0, %zmm24
        vprorq	$18, %zmm0, %zmm25
        vprorq	$41, %zmm0, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm3, %zmm3
        vprorq	$28, %zmm4, %zmm24
        vprorq	$34, %zmm4, %zmm25
        vprorq	$39, %zmm4, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm5, %zmm27
        vpternlogq	$0xe8, %zmm6, %zmm4, %zmm27
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm3, %zmm3
        vpaddq	40(%rbp){1to8}, %zmm2, %zmm2
        vpaddq	%zmm13, %zmm2, %zmm2
        vpaddq	%zmm2, %zmm6, %zmm6
        vmovdqa64	%zmm0, %zmm27
        vpternlogq	$0xe2, %zmm1, %zmm7, %zmm27
        vprorq	$14, %zmm7, %zmm24
        vprorq	$18, %zmm7, %zmm25
        vprorq	$41, %zmm7, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm2, %zmm2
        vprorq	$28, %zmm3, %zmm24
        vprorq	$34, %zmm3, %zmm25
        vprorq	$39, %zmm3, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm4, %zmm27
        vpternlogq	$0xe8, %zmm5, %zmm3, %zmm27
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm2, %zmm2
        vpaddq	48(%rbp){1to8}, %zmm1, %zmm1
        vpaddq	%zmm14, %zmm1, %zmm1
        vpaddq	%zmm1, %zmm5, %zmm5
        vmovdqa64	%zmm7, %zmm27
        vpternlogq	$0xe2, %zmm0, %zmm6, %zmm27
        vprorq	$14, %zmm6, %zmm24
        vprorq	$18, %zmm6, %zmm25
        vprorq	$41, %zmm6, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm1, %zmm1
        vprorq	$28, %zmm2, %zmm24
        vprorq	$34, %zmm2, %zmm25
        vprorq	$39, %zmm2, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm3, %zmm27
        vpternlogq	$0xe8, %zmm4, %zmm2, %zmm27
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm1, %zmm1
        vpaddq	56(%rbp){1to8}, %zmm0, %zmm0
        vpaddq	%zmm15, %zmm0, %zmm0
        vpaddq	%zmm0, %zmm4, %zmm4
        vmovdqa64	%zmm6, %zmm27
        vpternlogq	$0xe2, %zmm7, %zmm5, %zmm27
        vprorq	$14, %zmm5, %zmm24
        vprorq	$18, %zmm5, %zmm25
        vprorq	$41, %zmm5, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm0, %zmm0
        vprorq	$28, %zmm1, %zmm24
        vprorq	$34, %zmm1, %zmm25
        vprorq	$39, %zmm1, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm2, %zmm27
        vpternlogq	$0xe8, %zmm3, %zmm1, %zmm27
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm0, %zmm0
        vpaddq	64(%rbp){1to8}, %zmm7, %zmm7
        vpaddq	%zmm16, %zmm7, %zmm7
        vpaddq	%zmm7, %zmm3, %zmm3
        vmovdqa64	%zmm5, %zmm27
        vpternlogq	$0xe2, %zmm6, %zmm4, %zmm27
        vprorq	$14, %zmm4, %zmm24
        vprorq	$18, %zmm4, %zmm25
        vprorq	$41, %zmm4, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm7, %zmm7
        vprorq	$28, %zmm0, %zmm24
        vprorq	$34, %zmm0, %zmm25
        vprorq	$39, %zmm0, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm1, %zmm27
        vpternlogq	$0xe8, %zmm2, %zmm0, %zmm27
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm7, %zmm7
        vpaddq	72(%rbp){1to8}, %zmm6, %zmm6
        vpaddq	%zmm17, %zmm6, %zmm6
        vpaddq	%zmm6, %zmm2, %zmm2
        vmovdqa64	%zmm4, %zmm27
        vpternlogq	$0xe2, %zmm5, %zmm3, %zmm27
        vprorq	$14, %zmm3, %zmm24
        vprorq	$18, %zmm3, %zmm25
        vprorq	$41, %zmm3, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm6, %zmm6
        vprorq	$28, %zmm7, %zmm24
        vprorq	$34, %zmm7, %zmm25
        vprorq	$39, %zmm7, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm0, %zmm27
        vpternlogq	$0xe8, %zmm1, %zmm7, %zmm27
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm6, %zmm6
        vpaddq	80(%rbp){1to8}, %zmm5, %zmm5
        vpaddq	%zmm18, %zmm5, %zmm5
        vpaddq	%zmm5, %zmm1, %zmm1
        vmovdqa64	%zmm3, %zmm27
        vpternlogq	$0xe2, %zmm4, %zmm2, %zmm27
        vprorq	$14, %zmm2, %zmm24
        vprorq	$18, %zmm2, %zmm25
        vprorq	$41, %zmm2, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm5, %zmm5
        vprorq	$28, %zmm6, %zmm24
        vprorq	$34, %zmm6, %zmm25
        vprorq	$39, %zmm6, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm7, %zmm27
        vpternlogq	$0xe8, %zmm0, %zmm6, %zmm27
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm5, %zmm5
        vpaddq	88(%rbp){1to8}, %zmm4, %zmm4
        vpaddq	%zmm19, %zmm4, %zmm4
        vpaddq	%zmm4, %zmm0, %zmm0
        vmovdqa64	%zmm2, %zmm27
        vpternlogq	$0xe2, %zmm3, %zmm1, %zmm27
        vprorq	$14, %zmm1, %zmm24
        vprorq	$18, %zmm1, %zmm25
        vprorq	$41, %zmm1, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm4, %zmm4
        vprorq	$28, %zmm5, %zmm24
        vprorq	$34, %zmm5, %zmm25
        vprorq	$39, %zmm5, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm6, %zmm27
        vpternlogq	$0xe8, %zmm7, %zmm5, %zmm27
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm4, %zmm4
        vpaddq	96(%rbp){1to8}, %zmm3, %zmm3
        vpaddq	%zmm20, %zmm3, %zmm3
        vpaddq	%zmm3, %zmm7, %zmm7
        vmovdqa64	%zmm1, %zmm27
        vpternlogq	$0xe2, %zmm2, %zmm0, %zmm27
        vprorq	$14, %zmm0, %zmm24
        vprorq	$18, %zmm0, %zmm25
        vprorq	$41, %zmm0, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm3, %zmm3
        vprorq	$28, %zmm4, %zmm24
        vprorq	$34, %zmm4, %zmm25
        vprorq	$39, %zmm4, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm5, %zmm27
        vpternlogq	$0xe8, %zmm6, %zmm4, %zmm27
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm3, %zmm3
        vpaddq	104(%rbp){1to8}, %zmm2, %zmm2
        vpaddq	%zmm21, %zmm2, %zmm2
        vpaddq	%zmm2, %zmm6, %zmm6
        vmovdqa64	%zmm0, %zmm27
        vpternlogq	$0xe2, %zmm1, %zmm7, %zmm27
        vprorq	$14, %zmm7, %zmm24
        vprorq	$18, %zmm7, %zmm25
        vprorq	$41, %zmm7, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm2, %zmm2
        vprorq	$28, %zmm3, %zmm24
        vprorq	$34, %zmm3, %zmm25
        vprorq	$39, %zmm3, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm4, %zmm27
        vpternlogq	$0xe8, %zmm5, %zmm3, %zmm27
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm2, %zmm2
        vpaddq	112(%rbp){1to8}, %zmm1, %zmm1
        vpaddq	%zmm22, %zmm1, %zmm1
        vpaddq	%zmm1, %zmm5, %zmm5
        vmovdqa64	%zmm7, %zmm27
        vpternlogq	$0xe2, %zmm0, %zmm6, %zmm27
        vprorq	$14, %zmm6, %zmm24
        vprorq	$18, %zmm6, %zmm25
        vprorq	$41, %zmm6, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm1, %zmm1
        vprorq	$28, %zmm2, %zmm24
        vprorq	$34, %zmm2, %zmm25
        vprorq	$39, %zmm2, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm3, %zmm27
        vpternlogq	$0xe8, %zmm4, %zmm2, %zmm27
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm1, %zmm1
        vpaddq	120(%rbp){1to8}, %zmm0, %zmm0
        vpaddq	%zmm23, %zmm0, %zmm0
        vpaddq	%zmm0, %zmm4, %zmm4
        vmovdqa64	%zmm6, %zmm27
        vpternlogq	$0xe2, %zmm7, %zmm5, %zmm27
        vprorq	$14, %zmm5, %zmm24
        vprorq	$18, %zmm5, %zmm25
        vprorq	$41, %zmm5, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm0, %zmm0
        vprorq	$28, %zmm1, %zmm24
        vprorq	$34, %zmm1, %zmm25
        vprorq	$39, %zmm1, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm2, %zmm27
        vpternlogq	$0xe8, %zmm3, %zmm1, %zmm27
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm0, %zmm0
        addq	$0x80, %rbp
        movl	$4, %eax
L_sha512_x8_xmss_f_blk1:
        vprorq	$0x01, %zmm9, %zmm24
        vprorq	$8, %zmm9, %zmm25
        vpsrlq	$7, %zmm9, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm22, %zmm25
        vprorq	$61, %zmm22, %zmm26
        vpsrlq	$6, %zmm22, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm8, %zmm8
        vpaddq	%zmm25, %zmm8, %zmm8
        vpaddq	%zmm17, %zmm8, %zmm8
        vpaddq	(%rbp){1to8}, %zmm7, %zmm7
        vpaddq	%zmm8, %zmm7, %zmm7
        vpaddq	%zmm7, %zmm3, %zmm3
        vmovdqa64	%zmm5, %zmm27
        vpternlogq	$0xe2, %zmm6, %zmm4, %zmm27
        vprorq	$14, %zmm4, %zmm24
        vprorq	$18, %zmm4, %zmm25
        vprorq	$41, %zmm4, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm7, %zmm7
        vprorq	$28, %zmm0, %zmm24
        vprorq	$34, %zmm0, %zmm25
        vprorq	$39, %zmm0, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm1, %zmm27
        vpternlogq	$0xe8, %zmm2, %zmm0, %zmm27
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm7, %zmm7
        vprorq	$0x01, %zmm10, %zmm24
        vprorq	$8, %zmm10, %zmm25
        vpsrlq	$7, %zmm10, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm23, %zmm25
        vprorq	$61, %zmm23, %zmm26
        vpsrlq	$6, %zmm23, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm9, %zmm9
        vpaddq	%zmm25, %zmm9, %zmm9
        vpaddq	%zmm18, %zmm9, %zmm9
        vpaddq	8(%rbp){1to8}, %zmm6, %zmm6
        vpaddq	%zmm9, %zmm6, %zmm6
        vpaddq	%zmm6, %zmm2, %zmm2
        vmovdqa64	%zmm4, %zmm27
        vpternlogq	$0xe2, %zmm5, %zmm3, %zmm27
        vprorq	$14, %zmm3, %zmm24
        vprorq	$18, %zmm3, %zmm25
        vprorq	$41, %zmm3, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm6, %zmm6
        vprorq	$28, %zmm7, %zmm24
        vprorq	$34, %zmm7, %zmm25
        vprorq	$39, %zmm7, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm0, %zmm27
        vpternlogq	$0xe8, %zmm1, %zmm7, %zmm27
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm6, %zmm6
        vprorq	$0x01, %zmm11, %zmm24
        vprorq	$8, %zmm11, %zmm25
        vpsrlq	$7, %zmm11, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm8, %zmm25
        vprorq	$61, %zmm8, %zmm26
        vpsrlq	$6, %zmm8, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm10, %zmm10
        vpaddq	%zmm25, %zmm10, %zmm10
        vpaddq	%zmm19, %zmm10, %zmm10
        vpaddq	16(%rbp){1to8}, %zmm5, %zmm5
        vpaddq	%zmm10, %zmm5, %zmm5
        vpaddq	%zmm5, %zmm1, %zmm1
        vmovdqa64	%zmm3, %zmm27
        vpternlogq	$0xe2, %zmm4, %zmm2, %zmm27
        vprorq	$14, %zmm2, %zmm24
        vprorq	$18, %zmm2, %zmm25
        vprorq	$41, %zmm2, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm5, %zmm5
        vprorq	$28, %zmm6, %zmm24
        vprorq	$34, %zmm6, %zmm25
        vprorq	$39, %zmm6, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm7, %zmm27
        vpternlogq	$0xe8, %zmm0, %zmm6, %zmm27
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm5, %zmm5
        vprorq	$0x01, %zmm12, %zmm24
        vprorq	$8, %zmm12, %zmm25
        vpsrlq	$7, %zmm12, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm9, %zmm25
        vprorq	$61, %zmm9, %zmm26
        vpsrlq	$6, %zmm9, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm11, %zmm11
        vpaddq	%zmm25, %zmm11, %zmm11
        vpaddq	%zmm20, %zmm11, %zmm11
        vpaddq	24(%rbp){1to8}, %zmm4, %zmm4
        vpaddq	%zmm11, %zmm4, %zmm4
        vpaddq	%zmm4, %zmm0, %zmm0
        vmovdqa64	%zmm2, %zmm27
        vpternlogq	$0xe2, %zmm3, %zmm1, %zmm27
        vprorq	$14, %zmm1, %zmm24
        vprorq	$18, %zmm1, %zmm25
        vprorq	$41, %zmm1, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm4, %zmm4
        vprorq	$28, %zmm5, %zmm24
        vprorq	$34, %zmm5, %zmm25
        vprorq	$39, %zmm5, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm6, %zmm27
        vpternlogq	$0xe8, %zmm7, %zmm5, %zmm27
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm4, %zmm4
        vprorq	$0x01, %zmm13, %zmm24
        vprorq	$8, %zmm13, %zmm25
        vpsrlq	$7, %zmm13, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm10, %zmm25
        vprorq	$61, %zmm10, %zmm26
        vpsrlq	$6, %zmm10, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm12, %zmm12
        vpaddq	%zmm25, %zmm12, %zmm12
        vpaddq	%zmm21, %zmm12, %zmm12
        vpaddq	32(%rbp){1to8}, %zmm3, %zmm3
        vpaddq	%zmm12, %zmm3, %zmm3
        vpaddq	%zmm3, %zmm7, %zmm7
        vmovdqa64	%zmm1, %zmm27
        vpternlogq	$0xe2, %zmm2, %zmm0, %zmm27
        vprorq	$14, %zmm0, %zmm24
        vprorq	$18, %zmm0, %zmm25
        vprorq	$41, %zmm0, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm3, %zmm3
        vprorq	$28, %zmm4, %zmm24
        vprorq	$34, %zmm4, %zmm25
        vprorq	$39, %zmm4, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm5, %zmm27
        vpternlogq	$0xe8, %zmm6, %zmm4, %zmm27
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm3, %zmm3
        vprorq	$0x01, %zmm14, %zmm24
        vprorq	$8, %zmm14, %zmm25
        vpsrlq	$7, %zmm14, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm11, %zmm25
        vprorq	$61, %zmm11, %zmm26
        vpsrlq	$6, %zmm11, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm13, %zmm13
        vpaddq	%zmm25, %zmm13, %zmm13
        vpaddq	%zmm22, %zmm13, %zmm13
        vpaddq	40(%rbp){1to8}, %zmm2, %zmm2
        vpaddq	%zmm13, %zmm2, %zmm2
        vpaddq	%zmm2, %zmm6, %zmm6
        vmovdqa64	%zmm0, %zmm27
        vpternlogq	$0xe2, %zmm1, %zmm7, %zmm27
        vprorq	$14, %zmm7, %zmm24
        vprorq	$18, %zmm7, %zmm25
        vprorq	$41, %zmm7, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm2, %zmm2
        vprorq	$28, %zmm3, %zmm24
        vprorq	$34, %zmm3, %zmm25
        vprorq	$39, %zmm3, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm4, %zmm27
        vpternlogq	$0xe8, %zmm5, %zmm3, %zmm27
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm2, %zmm2
        vprorq	$0x01, %zmm15, %zmm24
        vprorq	$8, %zmm15, %zmm25
        vpsrlq	$7, %zmm15, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm12, %zmm25
        vprorq	$61, %zmm12, %zmm26
        vpsrlq	$6, %zmm12, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm14, %zmm14
        vpaddq	%zmm25, %zmm14, %zmm14
        vpaddq	%zmm23, %zmm14, %zmm14
        vpaddq	48(%rbp){1to8}, %zmm1, %zmm1
        vpaddq	%zmm14, %zmm1, %zmm1
        vpaddq	%zmm1, %zmm5, %zmm5
        vmovdqa64	%zmm7, %zmm27
        vpternlogq	$0xe2, %zmm0, %zmm6, %zmm27
        vprorq	$14, %zmm6, %zmm24
        vprorq	$18, %zmm6, %zmm25
        vprorq	$41, %zmm6, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm1, %zmm1
        vprorq	$28, %zmm2, %zmm24
        vprorq	$34, %zmm2, %zmm25
        vprorq	$39, %zmm2, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm3, %zmm27
        vpternlogq	$0xe8, %zmm4, %zmm2, %zmm27
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm1, %zmm1
        vprorq	$0x01, %zmm16, %zmm24
        vprorq	$8, %zmm16, %zmm25
        vpsrlq	$7, %zmm16, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm13, %zmm25
        vprorq	$61, %zmm13, %zmm26
        vpsrlq	$6, %zmm13, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm15, %zmm15
        vpaddq	%zmm25, %zmm15, %zmm15
        vpaddq	%zmm8, %zmm15, %zmm15
        vpaddq	56(%rbp){1to8}, %zmm0, %zmm0
        vpaddq	%zmm15, %zmm0, %zmm0
        vpaddq	%zmm0, %zmm4, %zmm4
        vmovdqa64	%zmm6, %zmm27
        vpternlogq	$0xe2, %zmm7, %zmm5, %zmm27
        vprorq	$14, %zmm5, %zmm24
        vprorq	$18, %zmm5, %zmm25
        vprorq	$41, %zmm5, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm0, %zmm0
        vprorq	$28, %zmm1, %zmm24
        vprorq	$34, %zmm1, %zmm25
        vprorq	$39, %zmm1, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm2, %zmm27
        vpternlogq	$0xe8, %zmm3, %zmm1, %zmm27
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm0, %zmm0
        vprorq	$0x01, %zmm17, %zmm24
        vprorq	$8, %zmm17, %zmm25
        vpsrlq	$7, %zmm17, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm14, %zmm25
        vprorq	$61, %zmm14, %zmm26
        vpsrlq	$6, %zmm14, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm16, %zmm16
        vpaddq	%zmm25, %zmm16, %zmm16
        vpaddq	%zmm9, %zmm16, %zmm16
        vpaddq	64(%rbp){1to8}, %zmm7, %zmm7
        vpaddq	%zmm16, %zmm7, %zmm7
        vpaddq	%zmm7, %zmm3, %zmm3
        vmovdqa64	%zmm5, %zmm27
        vpternlogq	$0xe2, %zmm6, %zmm4, %zmm27
        vprorq	$14, %zmm4, %zmm24
        vprorq	$18, %zmm4, %zmm25
        vprorq	$41, %zmm4, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm7, %zmm7
        vprorq	$28, %zmm0, %zmm24
        vprorq	$34, %zmm0, %zmm25
        vprorq	$39, %zmm0, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm1, %zmm27
        vpternlogq	$0xe8, %zmm2, %zmm0, %zmm27
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm7, %zmm7
        vprorq	$0x01, %zmm18, %zmm24
        vprorq	$8, %zmm18, %zmm25
        vpsrlq	$7, %zmm18, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm15, %zmm25
        vprorq	$61, %zmm15, %zmm26
        vpsrlq	$6, %zmm15, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm17, %zmm17
        vpaddq	%zmm25, %zmm17, %zmm17
        vpaddq	%zmm10, %zmm17, %zmm17
        vpaddq	72(%rbp){1to8}, %zmm6, %zmm6
        vpaddq	%zmm17, %zmm6, %zmm6
        vpaddq	%zmm6, %zmm2, %zmm2
        vmovdqa64	%zmm4, %zmm27
        vpternlogq	$0xe2, %zmm5, %zmm3, %zmm27
        vprorq	$14, %zmm3, %zmm24
        vprorq	$18, %zmm3, %zmm25
        vprorq	$41, %zmm3, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm6, %zmm6
        vprorq	$28, %zmm7, %zmm24
        vprorq	$34, %zmm7, %zmm25
        vprorq	$39, %zmm7, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm0, %zmm27
        vpternlogq	$0xe8, %zmm1, %zmm7, %zmm27
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm6, %zmm6
        vprorq	$0x01, %zmm19, %zmm24
        vprorq	$8, %zmm19, %zmm25
        vpsrlq	$7, %zmm19, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm16, %zmm25
        vprorq	$61, %zmm16, %zmm26
        vpsrlq	$6, %zmm16, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm18, %zmm18
        vpaddq	%zmm25, %zmm18, %zmm18
        vpaddq	%zmm11, %zmm18, %zmm18
        vpaddq	80(%rbp){1to8}, %zmm5, %zmm5
        vpaddq	%zmm18, %zmm5, %zmm5
        vpaddq	%zmm5, %zmm1, %zmm1
        vmovdqa64	%zmm3, %zmm27
        vpternlogq	$0xe2, %zmm4, %zmm2, %zmm27
        vprorq	$14, %zmm2, %zmm24
        vprorq	$18, %zmm2, %zmm25
        vprorq	$41, %zmm2, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm5, %zmm5
        vprorq	$28, %zmm6, %zmm24
        vprorq	$34, %zmm6, %zmm25
        vprorq	$39, %zmm6, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm7, %zmm27
        vpternlogq	$0xe8, %zmm0, %zmm6, %zmm27
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm5, %zmm5
        vprorq	$0x01, %zmm20, %zmm24
        vprorq	$8, %zmm20, %zmm25
        vpsrlq	$7, %zmm20, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm17, %zmm25
        vprorq	$61, %zmm17, %zmm26
        vpsrlq	$6, %zmm17, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm19, %zmm19
        vpaddq	%zmm25, %zmm19, %zmm19
        vpaddq	%zmm12, %zmm19, %zmm19
        vpaddq	88(%rbp){1to8}, %zmm4, %zmm4
        vpaddq	%zmm19, %zmm4, %zmm4
        vpaddq	%zmm4, %zmm0, %zmm0
        vmovdqa64	%zmm2, %zmm27
        vpternlogq	$0xe2, %zmm3, %zmm1, %zmm27
        vprorq	$14, %zmm1, %zmm24
        vprorq	$18, %zmm1, %zmm25
        vprorq	$41, %zmm1, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm4, %zmm4
        vprorq	$28, %zmm5, %zmm24
        vprorq	$34, %zmm5, %zmm25
        vprorq	$39, %zmm5, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm6, %zmm27
        vpternlogq	$0xe8, %zmm7, %zmm5, %zmm27
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm4, %zmm4
        vprorq	$0x01, %zmm21, %zmm24
        vprorq	$8, %zmm21, %zmm25
        vpsrlq	$7, %zmm21, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm18, %zmm25
        vprorq	$61, %zmm18, %zmm26
        vpsrlq	$6, %zmm18, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm20, %zmm20
        vpaddq	%zmm25, %zmm20, %zmm20
        vpaddq	%zmm13, %zmm20, %zmm20
        vpaddq	96(%rbp){1to8}, %zmm3, %zmm3
        vpaddq	%zmm20, %zmm3, %zmm3
        vpaddq	%zmm3, %zmm7, %zmm7
        vmovdqa64	%zmm1, %zmm27
        vpternlogq	$0xe2, %zmm2, %zmm0, %zmm27
        vprorq	$14, %zmm0, %zmm24
        vprorq	$18, %zmm0, %zmm25
        vprorq	$41, %zmm0, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm3, %zmm3
        vprorq	$28, %zmm4, %zmm24
        vprorq	$34, %zmm4, %zmm25
        vprorq	$39, %zmm4, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm5, %zmm27
        vpternlogq	$0xe8, %zmm6, %zmm4, %zmm27
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm3, %zmm3
        vprorq	$0x01, %zmm22, %zmm24
        vprorq	$8, %zmm22, %zmm25
        vpsrlq	$7, %zmm22, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm19, %zmm25
        vprorq	$61, %zmm19, %zmm26
        vpsrlq	$6, %zmm19, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm21, %zmm21
        vpaddq	%zmm25, %zmm21, %zmm21
        vpaddq	%zmm14, %zmm21, %zmm21
        vpaddq	104(%rbp){1to8}, %zmm2, %zmm2
        vpaddq	%zmm21, %zmm2, %zmm2
        vpaddq	%zmm2, %zmm6, %zmm6
        vmovdqa64	%zmm0, %zmm27
        vpternlogq	$0xe2, %zmm1, %zmm7, %zmm27
        vprorq	$14, %zmm7, %zmm24
        vprorq	$18, %zmm7, %zmm25
        vprorq	$41, %zmm7, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm2, %zmm2
        vprorq	$28, %zmm3, %zmm24
        vprorq	$34, %zmm3, %zmm25
        vprorq	$39, %zmm3, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm4, %zmm27
        vpternlogq	$0xe8, %zmm5, %zmm3, %zmm27
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm2, %zmm2
        vprorq	$0x01, %zmm23, %zmm24
        vprorq	$8, %zmm23, %zmm25
        vpsrlq	$7, %zmm23, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm20, %zmm25
        vprorq	$61, %zmm20, %zmm26
        vpsrlq	$6, %zmm20, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm22, %zmm22
        vpaddq	%zmm25, %zmm22, %zmm22
        vpaddq	%zmm15, %zmm22, %zmm22
        vpaddq	112(%rbp){1to8}, %zmm1, %zmm1
        vpaddq	%zmm22, %zmm1, %zmm1
        vpaddq	%zmm1, %zmm5, %zmm5
        vmovdqa64	%zmm7, %zmm27
        vpternlogq	$0xe2, %zmm0, %zmm6, %zmm27
        vprorq	$14, %zmm6, %zmm24
        vprorq	$18, %zmm6, %zmm25
        vprorq	$41, %zmm6, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm1, %zmm1
        vprorq	$28, %zmm2, %zmm24
        vprorq	$34, %zmm2, %zmm25
        vprorq	$39, %zmm2, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm3, %zmm27
        vpternlogq	$0xe8, %zmm4, %zmm2, %zmm27
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm1, %zmm1
        vprorq	$0x01, %zmm8, %zmm24
        vprorq	$8, %zmm8, %zmm25
        vpsrlq	$7, %zmm8, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm21, %zmm25
        vprorq	$61, %zmm21, %zmm26
        vpsrlq	$6, %zmm21, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm23, %zmm23
        vpaddq	%zmm25, %zmm23, %zmm23
        vpaddq	%zmm16, %zmm23, %zmm23
        vpaddq	120(%rbp){1to8}, %zmm0, %zmm0
        vpaddq	%zmm23, %zmm0, %zmm0
        vpaddq	%zmm0, %zmm4, %zmm4
        vmovdqa64	%zmm6, %zmm27
        vpternlogq	$0xe2, %zmm7, %zmm5, %zmm27
        vprorq	$14, %zmm5, %zmm24
        vprorq	$18, %zmm5, %zmm25
        vprorq	$41, %zmm5, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm0, %zmm0
        vprorq	$28, %zmm1, %zmm24
        vprorq	$34, %zmm1, %zmm25
        vprorq	$39, %zmm1, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm2, %zmm27
        vpternlogq	$0xe8, %zmm3, %zmm1, %zmm27
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm0, %zmm0
        addq	$0x80, %rbp
        subl	$0x01, %eax
        jnz	L_sha512_x8_xmss_f_blk1
        # Hold on to the chaining value: it is needed again at the end
        vpbroadcastq	(%r9), %zmm24
        vpaddq	%zmm24, %zmm0, %zmm0
        vmovdqu64	%zmm0, (%rsp)
        vpbroadcastq	8(%r9), %zmm24
        vpaddq	%zmm24, %zmm1, %zmm1
        vmovdqu64	%zmm1, 64(%rsp)
        vpbroadcastq	16(%r9), %zmm24
        vpaddq	%zmm24, %zmm2, %zmm2
        vmovdqu64	%zmm2, 128(%rsp)
        vpbroadcastq	24(%r9), %zmm24
        vpaddq	%zmm24, %zmm3, %zmm3
        vmovdqu64	%zmm3, 192(%rsp)
        vpbroadcastq	32(%r9), %zmm24
        vpaddq	%zmm24, %zmm4, %zmm4
        vmovdqu64	%zmm4, 256(%rsp)
        vpbroadcastq	40(%r9), %zmm24
        vpaddq	%zmm24, %zmm5, %zmm5
        vmovdqu64	%zmm5, 320(%rsp)
        vpbroadcastq	48(%r9), %zmm24
        vpaddq	%zmm24, %zmm6, %zmm6
        vmovdqu64	%zmm6, 384(%rsp)
        vpbroadcastq	56(%r9), %zmm24
        vpaddq	%zmm24, %zmm7, %zmm7
        vmovdqu64	%zmm7, 448(%rsp)
        # Second block: tmp ^ BM, then the padding for 192 bytes
        vmovdqu64	(%rdi), %zmm24
        vpxorq	(%rdx), %zmm24, %zmm8
        vmovdqu64	64(%rdi), %zmm24
        vpxorq	64(%rdx), %zmm24, %zmm9
        vmovdqu64	128(%rdi), %zmm24
        vpxorq	128(%rdx), %zmm24, %zmm10
        vmovdqu64	192(%rdi), %zmm24
        vpxorq	192(%rdx), %zmm24, %zmm11
        vmovdqu64	256(%rdi), %zmm24
        vpxorq	256(%rdx), %zmm24, %zmm12
        vmovdqu64	320(%rdi), %zmm24
        vpxorq	320(%rdx), %zmm24, %zmm13
        vmovdqu64	384(%rdi), %zmm24
        vpxorq	384(%rdx), %zmm24, %zmm14
        vmovdqu64	448(%rdi), %zmm24
        vpxorq	448(%rdx), %zmm24, %zmm15
        vpbroadcastq	L_avx512_sha512_x8_pad80q(%rip), %zmm16
        vpxorq	%zmm17, %zmm17, %zmm17
        vpxorq	%zmm18, %zmm18, %zmm18
        vpxorq	%zmm19, %zmm19, %zmm19
        vpxorq	%zmm20, %zmm20, %zmm20
        vpxorq	%zmm21, %zmm21, %zmm21
        vpxorq	%zmm22, %zmm22, %zmm22
        vpbroadcastq	L_avx512_sha512_x8_len1536(%rip), %zmm23
        leaq	L_avx512_sha512_x8_k(%rip), %rbp
        # Rounds 0-15: the schedule is the message block itself
        vpaddq	(%rbp){1to8}, %zmm7, %zmm7
        vpaddq	%zmm8, %zmm7, %zmm7
        vpaddq	%zmm7, %zmm3, %zmm3
        vmovdqa64	%zmm5, %zmm27
        vpternlogq	$0xe2, %zmm6, %zmm4, %zmm27
        vprorq	$14, %zmm4, %zmm24
        vprorq	$18, %zmm4, %zmm25
        vprorq	$41, %zmm4, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm7, %zmm7
        vprorq	$28, %zmm0, %zmm24
        vprorq	$34, %zmm0, %zmm25
        vprorq	$39, %zmm0, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm1, %zmm27
        vpternlogq	$0xe8, %zmm2, %zmm0, %zmm27
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm7, %zmm7
        vpaddq	8(%rbp){1to8}, %zmm6, %zmm6
        vpaddq	%zmm9, %zmm6, %zmm6
        vpaddq	%zmm6, %zmm2, %zmm2
        vmovdqa64	%zmm4, %zmm27
        vpternlogq	$0xe2, %zmm5, %zmm3, %zmm27
        vprorq	$14, %zmm3, %zmm24
        vprorq	$18, %zmm3, %zmm25
        vprorq	$41, %zmm3, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm6, %zmm6
        vprorq	$28, %zmm7, %zmm24
        vprorq	$34, %zmm7, %zmm25
        vprorq	$39, %zmm7, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm0, %zmm27
        vpternlogq	$0xe8, %zmm1, %zmm7, %zmm27
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm6, %zmm6
        vpaddq	16(%rbp){1to8}, %zmm5, %zmm5
        vpaddq	%zmm10, %zmm5, %zmm5
        vpaddq	%zmm5, %zmm1, %zmm1
        vmovdqa64	%zmm3, %zmm27
        vpternlogq	$0xe2, %zmm4, %zmm2, %zmm27
        vprorq	$14, %zmm2, %zmm24
        vprorq	$18, %zmm2, %zmm25
        vprorq	$41, %zmm2, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm5, %zmm5
        vprorq	$28, %zmm6, %zmm24
        vprorq	$34, %zmm6, %zmm25
        vprorq	$39, %zmm6, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm7, %zmm27
        vpternlogq	$0xe8, %zmm0, %zmm6, %zmm27
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm5, %zmm5
        vpaddq	24(%rbp){1to8}, %zmm4, %zmm4
        vpaddq	%zmm11, %zmm4, %zmm4
        vpaddq	%zmm4, %zmm0, %zmm0
        vmovdqa64	%zmm2, %zmm27
        vpternlogq	$0xe2, %zmm3, %zmm1, %zmm27
        vprorq	$14, %zmm1, %zmm24
        vprorq	$18, %zmm1, %zmm25
        vprorq	$41, %zmm1, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm4, %zmm4
        vprorq	$28, %zmm5, %zmm24
        vprorq	$34, %zmm5, %zmm25
        vprorq	$39, %zmm5, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm6, %zmm27
        vpternlogq	$0xe8, %zmm7, %zmm5, %zmm27
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm4, %zmm4
        vpaddq	32(%rbp){1to8}, %zmm3, %zmm3
        vpaddq	%zmm12, %zmm3, %zmm3
        vpaddq	%zmm3, %zmm7, %zmm7
        vmovdqa64	%zmm1, %zmm27
        vpternlogq	$0xe2, %zmm2, %zmm0, %zmm27
        vprorq	$14, %zmm0, %zmm24
        vprorq	$18, %zmm0, %zmm25
        vprorq	$41, %zmm0, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm3, %zmm3
        vprorq	$28, %zmm4, %zmm24
        vprorq	$34, %zmm4, %zmm25
        vprorq	$39, %zmm4, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm5, %zmm27
        vpternlogq	$0xe8, %zmm6, %zmm4, %zmm27
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm3, %zmm3
        vpaddq	40(%rbp){1to8}, %zmm2, %zmm2
        vpaddq	%zmm13, %zmm2, %zmm2
        vpaddq	%zmm2, %zmm6, %zmm6
        vmovdqa64	%zmm0, %zmm27
        vpternlogq	$0xe2, %zmm1, %zmm7, %zmm27
        vprorq	$14, %zmm7, %zmm24
        vprorq	$18, %zmm7, %zmm25
        vprorq	$41, %zmm7, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm2, %zmm2
        vprorq	$28, %zmm3, %zmm24
        vprorq	$34, %zmm3, %zmm25
        vprorq	$39, %zmm3, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm4, %zmm27
        vpternlogq	$0xe8, %zmm5, %zmm3, %zmm27
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm2, %zmm2
        vpaddq	48(%rbp){1to8}, %zmm1, %zmm1
        vpaddq	%zmm14, %zmm1, %zmm1
        vpaddq	%zmm1, %zmm5, %zmm5
        vmovdqa64	%zmm7, %zmm27
        vpternlogq	$0xe2, %zmm0, %zmm6, %zmm27
        vprorq	$14, %zmm6, %zmm24
        vprorq	$18, %zmm6, %zmm25
        vprorq	$41, %zmm6, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm1, %zmm1
        vprorq	$28, %zmm2, %zmm24
        vprorq	$34, %zmm2, %zmm25
        vprorq	$39, %zmm2, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm3, %zmm27
        vpternlogq	$0xe8, %zmm4, %zmm2, %zmm27
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm1, %zmm1
        vpaddq	56(%rbp){1to8}, %zmm0, %zmm0
        vpaddq	%zmm15, %zmm0, %zmm0
        vpaddq	%zmm0, %zmm4, %zmm4
        vmovdqa64	%zmm6, %zmm27
        vpternlogq	$0xe2, %zmm7, %zmm5, %zmm27
        vprorq	$14, %zmm5, %zmm24
        vprorq	$18, %zmm5, %zmm25
        vprorq	$41, %zmm5, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm0, %zmm0
        vprorq	$28, %zmm1, %zmm24
        vprorq	$34, %zmm1, %zmm25
        vprorq	$39, %zmm1, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm2, %zmm27
        vpternlogq	$0xe8, %zmm3, %zmm1, %zmm27
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm0, %zmm0
        vpaddq	64(%rbp){1to8}, %zmm7, %zmm7
        vpaddq	%zmm16, %zmm7, %zmm7
        vpaddq	%zmm7, %zmm3, %zmm3
        vmovdqa64	%zmm5, %zmm27
        vpternlogq	$0xe2, %zmm6, %zmm4, %zmm27
        vprorq	$14, %zmm4, %zmm24
        vprorq	$18, %zmm4, %zmm25
        vprorq	$41, %zmm4, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm7, %zmm7
        vprorq	$28, %zmm0, %zmm24
        vprorq	$34, %zmm0, %zmm25
        vprorq	$39, %zmm0, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm1, %zmm27
        vpternlogq	$0xe8, %zmm2, %zmm0, %zmm27
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm7, %zmm7
        vpaddq	72(%rbp){1to8}, %zmm6, %zmm6
        vpaddq	%zmm17, %zmm6, %zmm6
        vpaddq	%zmm6, %zmm2, %zmm2
        vmovdqa64	%zmm4, %zmm27
        vpternlogq	$0xe2, %zmm5, %zmm3, %zmm27
        vprorq	$14, %zmm3, %zmm24
        vprorq	$18, %zmm3, %zmm25
        vprorq	$41, %zmm3, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm6, %zmm6
        vprorq	$28, %zmm7, %zmm24
        vprorq	$34, %zmm7, %zmm25
        vprorq	$39, %zmm7, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm0, %zmm27
        vpternlogq	$0xe8, %zmm1, %zmm7, %zmm27
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm6, %zmm6
        vpaddq	80(%rbp){1to8}, %zmm5, %zmm5
        vpaddq	%zmm18, %zmm5, %zmm5
        vpaddq	%zmm5, %zmm1, %zmm1
        vmovdqa64	%zmm3, %zmm27
        vpternlogq	$0xe2, %zmm4, %zmm2, %zmm27
        vprorq	$14, %zmm2, %zmm24
        vprorq	$18, %zmm2, %zmm25
        vprorq	$41, %zmm2, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm5, %zmm5
        vprorq	$28, %zmm6, %zmm24
        vprorq	$34, %zmm6, %zmm25
        vprorq	$39, %zmm6, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm7, %zmm27
        vpternlogq	$0xe8, %zmm0, %zmm6, %zmm27
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm5, %zmm5
        vpaddq	88(%rbp){1to8}, %zmm4, %zmm4
        vpaddq	%zmm19, %zmm4, %zmm4
        vpaddq	%zmm4, %zmm0, %zmm0
        vmovdqa64	%zmm2, %zmm27
        vpternlogq	$0xe2, %zmm3, %zmm1, %zmm27
        vprorq	$14, %zmm1, %zmm24
        vprorq	$18, %zmm1, %zmm25
        vprorq	$41, %zmm1, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm4, %zmm4
        vprorq	$28, %zmm5, %zmm24
        vprorq	$34, %zmm5, %zmm25
        vprorq	$39, %zmm5, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm6, %zmm27
        vpternlogq	$0xe8, %zmm7, %zmm5, %zmm27
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm4, %zmm4
        vpaddq	96(%rbp){1to8}, %zmm3, %zmm3
        vpaddq	%zmm20, %zmm3, %zmm3
        vpaddq	%zmm3, %zmm7, %zmm7
        vmovdqa64	%zmm1, %zmm27
        vpternlogq	$0xe2, %zmm2, %zmm0, %zmm27
        vprorq	$14, %zmm0, %zmm24
        vprorq	$18, %zmm0, %zmm25
        vprorq	$41, %zmm0, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm3, %zmm3
        vprorq	$28, %zmm4, %zmm24
        vprorq	$34, %zmm4, %zmm25
        vprorq	$39, %zmm4, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm5, %zmm27
        vpternlogq	$0xe8, %zmm6, %zmm4, %zmm27
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm3, %zmm3
        vpaddq	104(%rbp){1to8}, %zmm2, %zmm2
        vpaddq	%zmm21, %zmm2, %zmm2
        vpaddq	%zmm2, %zmm6, %zmm6
        vmovdqa64	%zmm0, %zmm27
        vpternlogq	$0xe2, %zmm1, %zmm7, %zmm27
        vprorq	$14, %zmm7, %zmm24
        vprorq	$18, %zmm7, %zmm25
        vprorq	$41, %zmm7, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm2, %zmm2
        vprorq	$28, %zmm3, %zmm24
        vprorq	$34, %zmm3, %zmm25
        vprorq	$39, %zmm3, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm4, %zmm27
        vpternlogq	$0xe8, %zmm5, %zmm3, %zmm27
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm2, %zmm2
        vpaddq	112(%rbp){1to8}, %zmm1, %zmm1
        vpaddq	%zmm22, %zmm1, %zmm1
        vpaddq	%zmm1, %zmm5, %zmm5
        vmovdqa64	%zmm7, %zmm27
        vpternlogq	$0xe2, %zmm0, %zmm6, %zmm27
        vprorq	$14, %zmm6, %zmm24
        vprorq	$18, %zmm6, %zmm25
        vprorq	$41, %zmm6, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm1, %zmm1
        vprorq	$28, %zmm2, %zmm24
        vprorq	$34, %zmm2, %zmm25
        vprorq	$39, %zmm2, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm3, %zmm27
        vpternlogq	$0xe8, %zmm4, %zmm2, %zmm27
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm1, %zmm1
        vpaddq	120(%rbp){1to8}, %zmm0, %zmm0
        vpaddq	%zmm23, %zmm0, %zmm0
        vpaddq	%zmm0, %zmm4, %zmm4
        vmovdqa64	%zmm6, %zmm27
        vpternlogq	$0xe2, %zmm7, %zmm5, %zmm27
        vprorq	$14, %zmm5, %zmm24
        vprorq	$18, %zmm5, %zmm25
        vprorq	$41, %zmm5, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm0, %zmm0
        vprorq	$28, %zmm1, %zmm24
        vprorq	$34, %zmm1, %zmm25
        vprorq	$39, %zmm1, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm2, %zmm27
        vpternlogq	$0xe8, %zmm3, %zmm1, %zmm27
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm0, %zmm0
        addq	$0x80, %rbp
        movl	$4, %eax
L_sha512_x8_xmss_f_blk2:
        vprorq	$0x01, %zmm9, %zmm24
        vprorq	$8, %zmm9, %zmm25
        vpsrlq	$7, %zmm9, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm22, %zmm25
        vprorq	$61, %zmm22, %zmm26
        vpsrlq	$6, %zmm22, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm8, %zmm8
        vpaddq	%zmm25, %zmm8, %zmm8
        vpaddq	%zmm17, %zmm8, %zmm8
        vpaddq	(%rbp){1to8}, %zmm7, %zmm7
        vpaddq	%zmm8, %zmm7, %zmm7
        vpaddq	%zmm7, %zmm3, %zmm3
        vmovdqa64	%zmm5, %zmm27
        vpternlogq	$0xe2, %zmm6, %zmm4, %zmm27
        vprorq	$14, %zmm4, %zmm24
        vprorq	$18, %zmm4, %zmm25
        vprorq	$41, %zmm4, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm7, %zmm7
        vprorq	$28, %zmm0, %zmm24
        vprorq	$34, %zmm0, %zmm25
        vprorq	$39, %zmm0, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm1, %zmm27
        vpternlogq	$0xe8, %zmm2, %zmm0, %zmm27
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm7, %zmm7
        vprorq	$0x01, %zmm10, %zmm24
        vprorq	$8, %zmm10, %zmm25
        vpsrlq	$7, %zmm10, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm23, %zmm25
        vprorq	$61, %zmm23, %zmm26
        vpsrlq	$6, %zmm23, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm9, %zmm9
        vpaddq	%zmm25, %zmm9, %zmm9
        vpaddq	%zmm18, %zmm9, %zmm9
        vpaddq	8(%rbp){1to8}, %zmm6, %zmm6
        vpaddq	%zmm9, %zmm6, %zmm6
        vpaddq	%zmm6, %zmm2, %zmm2
        vmovdqa64	%zmm4, %zmm27
        vpternlogq	$0xe2, %zmm5, %zmm3, %zmm27
        vprorq	$14, %zmm3, %zmm24
        vprorq	$18, %zmm3, %zmm25
        vprorq	$41, %zmm3, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm6, %zmm6
        vprorq	$28, %zmm7, %zmm24
        vprorq	$34, %zmm7, %zmm25
        vprorq	$39, %zmm7, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm0, %zmm27
        vpternlogq	$0xe8, %zmm1, %zmm7, %zmm27
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm6, %zmm6
        vprorq	$0x01, %zmm11, %zmm24
        vprorq	$8, %zmm11, %zmm25
        vpsrlq	$7, %zmm11, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm8, %zmm25
        vprorq	$61, %zmm8, %zmm26
        vpsrlq	$6, %zmm8, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm10, %zmm10
        vpaddq	%zmm25, %zmm10, %zmm10
        vpaddq	%zmm19, %zmm10, %zmm10
        vpaddq	16(%rbp){1to8}, %zmm5, %zmm5
        vpaddq	%zmm10, %zmm5, %zmm5
        vpaddq	%zmm5, %zmm1, %zmm1
        vmovdqa64	%zmm3, %zmm27
        vpternlogq	$0xe2, %zmm4, %zmm2, %zmm27
        vprorq	$14, %zmm2, %zmm24
        vprorq	$18, %zmm2, %zmm25
        vprorq	$41, %zmm2, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm5, %zmm5
        vprorq	$28, %zmm6, %zmm24
        vprorq	$34, %zmm6, %zmm25
        vprorq	$39, %zmm6, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm7, %zmm27
        vpternlogq	$0xe8, %zmm0, %zmm6, %zmm27
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm5, %zmm5
        vprorq	$0x01, %zmm12, %zmm24
        vprorq	$8, %zmm12, %zmm25
        vpsrlq	$7, %zmm12, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm9, %zmm25
        vprorq	$61, %zmm9, %zmm26
        vpsrlq	$6, %zmm9, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm11, %zmm11
        vpaddq	%zmm25, %zmm11, %zmm11
        vpaddq	%zmm20, %zmm11, %zmm11
        vpaddq	24(%rbp){1to8}, %zmm4, %zmm4
        vpaddq	%zmm11, %zmm4, %zmm4
        vpaddq	%zmm4, %zmm0, %zmm0
        vmovdqa64	%zmm2, %zmm27
        vpternlogq	$0xe2, %zmm3, %zmm1, %zmm27
        vprorq	$14, %zmm1, %zmm24
        vprorq	$18, %zmm1, %zmm25
        vprorq	$41, %zmm1, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm4, %zmm4
        vprorq	$28, %zmm5, %zmm24
        vprorq	$34, %zmm5, %zmm25
        vprorq	$39, %zmm5, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm6, %zmm27
        vpternlogq	$0xe8, %zmm7, %zmm5, %zmm27
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm4, %zmm4
        vprorq	$0x01, %zmm13, %zmm24
        vprorq	$8, %zmm13, %zmm25
        vpsrlq	$7, %zmm13, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm10, %zmm25
        vprorq	$61, %zmm10, %zmm26
        vpsrlq	$6, %zmm10, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm12, %zmm12
        vpaddq	%zmm25, %zmm12, %zmm12
        vpaddq	%zmm21, %zmm12, %zmm12
        vpaddq	32(%rbp){1to8}, %zmm3, %zmm3
        vpaddq	%zmm12, %zmm3, %zmm3
        vpaddq	%zmm3, %zmm7, %zmm7
        vmovdqa64	%zmm1, %zmm27
        vpternlogq	$0xe2, %zmm2, %zmm0, %zmm27
        vprorq	$14, %zmm0, %zmm24
        vprorq	$18, %zmm0, %zmm25
        vprorq	$41, %zmm0, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm3, %zmm3
        vprorq	$28, %zmm4, %zmm24
        vprorq	$34, %zmm4, %zmm25
        vprorq	$39, %zmm4, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm5, %zmm27
        vpternlogq	$0xe8, %zmm6, %zmm4, %zmm27
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm3, %zmm3
        vprorq	$0x01, %zmm14, %zmm24
        vprorq	$8, %zmm14, %zmm25
        vpsrlq	$7, %zmm14, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm11, %zmm25
        vprorq	$61, %zmm11, %zmm26
        vpsrlq	$6, %zmm11, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm13, %zmm13
        vpaddq	%zmm25, %zmm13, %zmm13
        vpaddq	%zmm22, %zmm13, %zmm13
        vpaddq	40(%rbp){1to8}, %zmm2, %zmm2
        vpaddq	%zmm13, %zmm2, %zmm2
        vpaddq	%zmm2, %zmm6, %zmm6
        vmovdqa64	%zmm0, %zmm27
        vpternlogq	$0xe2, %zmm1, %zmm7, %zmm27
        vprorq	$14, %zmm7, %zmm24
        vprorq	$18, %zmm7, %zmm25
        vprorq	$41, %zmm7, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm2, %zmm2
        vprorq	$28, %zmm3, %zmm24
        vprorq	$34, %zmm3, %zmm25
        vprorq	$39, %zmm3, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm4, %zmm27
        vpternlogq	$0xe8, %zmm5, %zmm3, %zmm27
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm2, %zmm2
        vprorq	$0x01, %zmm15, %zmm24
        vprorq	$8, %zmm15, %zmm25
        vpsrlq	$7, %zmm15, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm12, %zmm25
        vprorq	$61, %zmm12, %zmm26
        vpsrlq	$6, %zmm12, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm14, %zmm14
        vpaddq	%zmm25, %zmm14, %zmm14
        vpaddq	%zmm23, %zmm14, %zmm14
        vpaddq	48(%rbp){1to8}, %zmm1, %zmm1
        vpaddq	%zmm14, %zmm1, %zmm1
        vpaddq	%zmm1, %zmm5, %zmm5
        vmovdqa64	%zmm7, %zmm27
        vpternlogq	$0xe2, %zmm0, %zmm6, %zmm27
        vprorq	$14, %zmm6, %zmm24
        vprorq	$18, %zmm6, %zmm25
        vprorq	$41, %zmm6, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm1, %zmm1
        vprorq	$28, %zmm2, %zmm24
        vprorq	$34, %zmm2, %zmm25
        vprorq	$39, %zmm2, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm3, %zmm27
        vpternlogq	$0xe8, %zmm4, %zmm2, %zmm27
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm1, %zmm1
        vprorq	$0x01, %zmm16, %zmm24
        vprorq	$8, %zmm16, %zmm25
        vpsrlq	$7, %zmm16, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm13, %zmm25
        vprorq	$61, %zmm13, %zmm26
        vpsrlq	$6, %zmm13, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm15, %zmm15
        vpaddq	%zmm25, %zmm15, %zmm15
        vpaddq	%zmm8, %zmm15, %zmm15
        vpaddq	56(%rbp){1to8}, %zmm0, %zmm0
        vpaddq	%zmm15, %zmm0, %zmm0
        vpaddq	%zmm0, %zmm4, %zmm4
        vmovdqa64	%zmm6, %zmm27
        vpternlogq	$0xe2, %zmm7, %zmm5, %zmm27
        vprorq	$14, %zmm5, %zmm24
        vprorq	$18, %zmm5, %zmm25
        vprorq	$41, %zmm5, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm0, %zmm0
        vprorq	$28, %zmm1, %zmm24
        vprorq	$34, %zmm1, %zmm25
        vprorq	$39, %zmm1, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm2, %zmm27
        vpternlogq	$0xe8, %zmm3, %zmm1, %zmm27
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm0, %zmm0
        vprorq	$0x01, %zmm17, %zmm24
        vprorq	$8, %zmm17, %zmm25
        vpsrlq	$7, %zmm17, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm14, %zmm25
        vprorq	$61, %zmm14, %zmm26
        vpsrlq	$6, %zmm14, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm16, %zmm16
        vpaddq	%zmm25, %zmm16, %zmm16
        vpaddq	%zmm9, %zmm16, %zmm16
        vpaddq	64(%rbp){1to8}, %zmm7, %zmm7
        vpaddq	%zmm16, %zmm7, %zmm7
        vpaddq	%zmm7, %zmm3, %zmm3
        vmovdqa64	%zmm5, %zmm27
        vpternlogq	$0xe2, %zmm6, %zmm4, %zmm27
        vprorq	$14, %zmm4, %zmm24
        vprorq	$18, %zmm4, %zmm25
        vprorq	$41, %zmm4, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm7, %zmm7
        vprorq	$28, %zmm0, %zmm24
        vprorq	$34, %zmm0, %zmm25
        vprorq	$39, %zmm0, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm1, %zmm27
        vpternlogq	$0xe8, %zmm2, %zmm0, %zmm27
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm7, %zmm7
        vprorq	$0x01, %zmm18, %zmm24
        vprorq	$8, %zmm18, %zmm25
        vpsrlq	$7, %zmm18, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm15, %zmm25
        vprorq	$61, %zmm15, %zmm26
        vpsrlq	$6, %zmm15, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm17, %zmm17
        vpaddq	%zmm25, %zmm17, %zmm17
        vpaddq	%zmm10, %zmm17, %zmm17
        vpaddq	72(%rbp){1to8}, %zmm6, %zmm6
        vpaddq	%zmm17, %zmm6, %zmm6
        vpaddq	%zmm6, %zmm2, %zmm2
        vmovdqa64	%zmm4, %zmm27
        vpternlogq	$0xe2, %zmm5, %zmm3, %zmm27
        vprorq	$14, %zmm3, %zmm24
        vprorq	$18, %zmm3, %zmm25
        vprorq	$41, %zmm3, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm6, %zmm6
        vprorq	$28, %zmm7, %zmm24
        vprorq	$34, %zmm7, %zmm25
        vprorq	$39, %zmm7, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm0, %zmm27
        vpternlogq	$0xe8, %zmm1, %zmm7, %zmm27
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm6, %zmm6
        vprorq	$0x01, %zmm19, %zmm24
        vprorq	$8, %zmm19, %zmm25
        vpsrlq	$7, %zmm19, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm16, %zmm25
        vprorq	$61, %zmm16, %zmm26
        vpsrlq	$6, %zmm16, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm18, %zmm18
        vpaddq	%zmm25, %zmm18, %zmm18
        vpaddq	%zmm11, %zmm18, %zmm18
        vpaddq	80(%rbp){1to8}, %zmm5, %zmm5
        vpaddq	%zmm18, %zmm5, %zmm5
        vpaddq	%zmm5, %zmm1, %zmm1
        vmovdqa64	%zmm3, %zmm27
        vpternlogq	$0xe2, %zmm4, %zmm2, %zmm27
        vprorq	$14, %zmm2, %zmm24
        vprorq	$18, %zmm2, %zmm25
        vprorq	$41, %zmm2, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm5, %zmm5
        vprorq	$28, %zmm6, %zmm24
        vprorq	$34, %zmm6, %zmm25
        vprorq	$39, %zmm6, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm7, %zmm27
        vpternlogq	$0xe8, %zmm0, %zmm6, %zmm27
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm5, %zmm5
        vprorq	$0x01, %zmm20, %zmm24
        vprorq	$8, %zmm20, %zmm25
        vpsrlq	$7, %zmm20, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm17, %zmm25
        vprorq	$61, %zmm17, %zmm26
        vpsrlq	$6, %zmm17, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm19, %zmm19
        vpaddq	%zmm25, %zmm19, %zmm19
        vpaddq	%zmm12, %zmm19, %zmm19
        vpaddq	88(%rbp){1to8}, %zmm4, %zmm4
        vpaddq	%zmm19, %zmm4, %zmm4
        vpaddq	%zmm4, %zmm0, %zmm0
        vmovdqa64	%zmm2, %zmm27
        vpternlogq	$0xe2, %zmm3, %zmm1, %zmm27
        vprorq	$14, %zmm1, %zmm24
        vprorq	$18, %zmm1, %zmm25
        vprorq	$41, %zmm1, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm4, %zmm4
        vprorq	$28, %zmm5, %zmm24
        vprorq	$34, %zmm5, %zmm25
        vprorq	$39, %zmm5, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm6, %zmm27
        vpternlogq	$0xe8, %zmm7, %zmm5, %zmm27
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm4, %zmm4
        vprorq	$0x01, %zmm21, %zmm24
        vprorq	$8, %zmm21, %zmm25
        vpsrlq	$7, %zmm21, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm18, %zmm25
        vprorq	$61, %zmm18, %zmm26
        vpsrlq	$6, %zmm18, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm20, %zmm20
        vpaddq	%zmm25, %zmm20, %zmm20
        vpaddq	%zmm13, %zmm20, %zmm20
        vpaddq	96(%rbp){1to8}, %zmm3, %zmm3
        vpaddq	%zmm20, %zmm3, %zmm3
        vpaddq	%zmm3, %zmm7, %zmm7
        vmovdqa64	%zmm1, %zmm27
        vpternlogq	$0xe2, %zmm2, %zmm0, %zmm27
        vprorq	$14, %zmm0, %zmm24
        vprorq	$18, %zmm0, %zmm25
        vprorq	$41, %zmm0, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm7, %zmm7
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm7, %zmm7
        vpaddq	%zmm24, %zmm3, %zmm3
        vprorq	$28, %zmm4, %zmm24
        vprorq	$34, %zmm4, %zmm25
        vprorq	$39, %zmm4, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm5, %zmm27
        vpternlogq	$0xe8, %zmm6, %zmm4, %zmm27
        vpaddq	%zmm27, %zmm3, %zmm3
        vpaddq	%zmm24, %zmm3, %zmm3
        vprorq	$0x01, %zmm22, %zmm24
        vprorq	$8, %zmm22, %zmm25
        vpsrlq	$7, %zmm22, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm19, %zmm25
        vprorq	$61, %zmm19, %zmm26
        vpsrlq	$6, %zmm19, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm21, %zmm21
        vpaddq	%zmm25, %zmm21, %zmm21
        vpaddq	%zmm14, %zmm21, %zmm21
        vpaddq	104(%rbp){1to8}, %zmm2, %zmm2
        vpaddq	%zmm21, %zmm2, %zmm2
        vpaddq	%zmm2, %zmm6, %zmm6
        vmovdqa64	%zmm0, %zmm27
        vpternlogq	$0xe2, %zmm1, %zmm7, %zmm27
        vprorq	$14, %zmm7, %zmm24
        vprorq	$18, %zmm7, %zmm25
        vprorq	$41, %zmm7, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm6, %zmm6
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm6, %zmm6
        vpaddq	%zmm24, %zmm2, %zmm2
        vprorq	$28, %zmm3, %zmm24
        vprorq	$34, %zmm3, %zmm25
        vprorq	$39, %zmm3, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm4, %zmm27
        vpternlogq	$0xe8, %zmm5, %zmm3, %zmm27
        vpaddq	%zmm27, %zmm2, %zmm2
        vpaddq	%zmm24, %zmm2, %zmm2
        vprorq	$0x01, %zmm23, %zmm24
        vprorq	$8, %zmm23, %zmm25
        vpsrlq	$7, %zmm23, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm20, %zmm25
        vprorq	$61, %zmm20, %zmm26
        vpsrlq	$6, %zmm20, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm22, %zmm22
        vpaddq	%zmm25, %zmm22, %zmm22
        vpaddq	%zmm15, %zmm22, %zmm22
        vpaddq	112(%rbp){1to8}, %zmm1, %zmm1
        vpaddq	%zmm22, %zmm1, %zmm1
        vpaddq	%zmm1, %zmm5, %zmm5
        vmovdqa64	%zmm7, %zmm27
        vpternlogq	$0xe2, %zmm0, %zmm6, %zmm27
        vprorq	$14, %zmm6, %zmm24
        vprorq	$18, %zmm6, %zmm25
        vprorq	$41, %zmm6, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm5, %zmm5
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm5, %zmm5
        vpaddq	%zmm24, %zmm1, %zmm1
        vprorq	$28, %zmm2, %zmm24
        vprorq	$34, %zmm2, %zmm25
        vprorq	$39, %zmm2, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm3, %zmm27
        vpternlogq	$0xe8, %zmm4, %zmm2, %zmm27
        vpaddq	%zmm27, %zmm1, %zmm1
        vpaddq	%zmm24, %zmm1, %zmm1
        vprorq	$0x01, %zmm8, %zmm24
        vprorq	$8, %zmm8, %zmm25
        vpsrlq	$7, %zmm8, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vprorq	$19, %zmm21, %zmm25
        vprorq	$61, %zmm21, %zmm26
        vpsrlq	$6, %zmm21, %zmm27
        vpternlogq	$0x96, %zmm27, %zmm26, %zmm25
        vpaddq	%zmm24, %zmm23, %zmm23
        vpaddq	%zmm25, %zmm23, %zmm23
        vpaddq	%zmm16, %zmm23, %zmm23
        vpaddq	120(%rbp){1to8}, %zmm0, %zmm0
        vpaddq	%zmm23, %zmm0, %zmm0
        vpaddq	%zmm0, %zmm4, %zmm4
        vmovdqa64	%zmm6, %zmm27
        vpternlogq	$0xe2, %zmm7, %zmm5, %zmm27
        vprorq	$14, %zmm5, %zmm24
        vprorq	$18, %zmm5, %zmm25
        vprorq	$41, %zmm5, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vpaddq	%zmm27, %zmm4, %zmm4
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm4, %zmm4
        vpaddq	%zmm24, %zmm0, %zmm0
        vprorq	$28, %zmm1, %zmm24
        vprorq	$34, %zmm1, %zmm25
        vprorq	$39, %zmm1, %zmm26
        vpternlogq	$0x96, %zmm26, %zmm25, %zmm24
        vmovdqa64	%zmm2, %zmm27
        vpternlogq	$0xe8, %zmm3, %zmm1, %zmm27
        vpaddq	%zmm27, %zmm0, %zmm0
        vpaddq	%zmm24, %zmm0, %zmm0
        addq	$0x80, %rbp
        subl	$0x01, %eax
        jnz	L_sha512_x8_xmss_f_blk2
        # Add the chaining value back, leaving the chain value in place
        vpaddq	(%rsp), %zmm0, %zmm0
        vmovdqu64	%zmm0, (%rdi)
        vpaddq	64(%rsp), %zmm1, %zmm1
        vmovdqu64	%zmm1, 64(%rdi)
        vpaddq	128(%rsp), %zmm2, %zmm2
        vmovdqu64	%zmm2, 128(%rdi)
        vpaddq	192(%rsp), %zmm3, %zmm3
        vmovdqu64	%zmm3, 192(%rdi)
        vpaddq	256(%rsp), %zmm4, %zmm4
        vmovdqu64	%zmm4, 256(%rdi)
        vpaddq	320(%rsp), %zmm5, %zmm5
        vmovdqu64	%zmm5, 320(%rdi)
        vpaddq	384(%rsp), %zmm6, %zmm6
        vmovdqu64	%zmm6, 384(%rdi)
        vpaddq	448(%rsp), %zmm7, %zmm7
        vmovdqu64	%zmm7, 448(%rdi)
        vzeroupper
        addq	$0x200, %rsp
        popq	%rbp
        repz retq
#ifndef __APPLE__
.size	Transform_Sha512_x8_XmssF_AVX512,.-Transform_Sha512_x8_XmssF_AVX512
#endif /* __APPLE__ */
#endif /* WOLFSSL_HAVE_XMSS */
#endif /* HAVE_INTEL_AVX512 */
#endif /* WOLFSSL_HAVE_XMSS */
#endif /* HAVE_INTEL_AVX2 */

#if defined(__linux__) && defined(__ELF__)
.section	.note.GNU-stack,"",%progbits
#endif
