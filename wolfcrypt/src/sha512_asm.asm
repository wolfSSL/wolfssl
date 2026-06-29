; /* sha512_asm.asm */
; /*
;  * Copyright (C) 2006-2026 wolfSSL Inc.
;  *
;  * This file is part of wolfSSL.
;  *
;  * wolfSSL is free software; you can redistribute it and/or modify
;  * it under the terms of the GNU General Public License as published by
;  * the Free Software Foundation; either version 3 of the License, or
;  * (at your option) any later version.
;  *
;  * wolfSSL is distributed in the hope that it will be useful,
;  * but WITHOUT ANY WARRANTY; without even the implied warranty of
;  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;  * GNU General Public License for more details.
;  *
;  * You should have received a copy of the GNU General Public License
;  * along with this program; if not, write to the Free Software
;  * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
;  */

IF @Version LT 1200
; AVX2 instructions not recognized by old versions of MASM
IFNDEF NO_AVX2_SUPPORT
NO_AVX2_SUPPORT = 1
ENDIF
; MOVBE instruction not recognized by old versions of MASM
IFNDEF NO_MOVBE_SUPPORT
NO_MOVBE_SUPPORT = 1
ENDIF
ENDIF

IFNDEF HAVE_INTEL_AVX1
HAVE_INTEL_AVX1 = 1
ENDIF
IFNDEF NO_AVX2_SUPPORT
HAVE_INTEL_AVX2 = 1
ENDIF

IFNDEF _WIN64
_WIN64 = 1
ENDIF

IFDEF HAVE_INTEL_AVX1
_DATA SEGMENT
ALIGN 16
L_avx1_sha512_k QWORD 428a2f98d728ae22h, 7137449123ef65cdh
        QWORD 0b5c0fbcfec4d3b2fh, 0e9b5dba58189dbbch
        QWORD 3956c25bf348b538h, 59f111f1b605d019h
        QWORD 923f82a4af194f9bh, 0ab1c5ed5da6d8118h
        QWORD 0d807aa98a3030242h, 12835b0145706fbeh
        QWORD 243185be4ee4b28ch, 550c7dc3d5ffb4e2h
        QWORD 72be5d74f27b896fh, 80deb1fe3b1696b1h
        QWORD 9bdc06a725c71235h, 0c19bf174cf692694h
        QWORD 0e49b69c19ef14ad2h, 0efbe4786384f25e3h
        QWORD 0fc19dc68b8cd5b5h, 240ca1cc77ac9c65h
        QWORD 2de92c6f592b0275h, 4a7484aa6ea6e483h
        QWORD 5cb0a9dcbd41fbd4h, 76f988da831153b5h
        QWORD 983e5152ee66dfabh, 0a831c66d2db43210h
        QWORD 0b00327c898fb213fh, 0bf597fc7beef0ee4h
        QWORD 0c6e00bf33da88fc2h, 0d5a79147930aa725h
        QWORD 06ca6351e003826fh, 142929670a0e6e70h
        QWORD 27b70a8546d22ffch, 2e1b21385c26c926h
        QWORD 4d2c6dfc5ac42aedh, 53380d139d95b3dfh
        QWORD 650a73548baf63deh, 766a0abb3c77b2a8h
        QWORD 81c2c92e47edaee6h, 92722c851482353bh
        QWORD 0a2bfe8a14cf10364h, 0a81a664bbc423001h
        QWORD 0c24b8b70d0f89791h, 0c76c51a30654be30h
        QWORD 0d192e819d6ef5218h, 0d69906245565a910h
        QWORD 0f40e35855771202ah, 106aa07032bbd1b8h
        QWORD 19a4c116b8d2d0c8h, 1e376c085141ab53h
        QWORD 2748774cdf8eeb99h, 34b0bcb5e19b48a8h
        QWORD 391c0cb3c5c95a63h, 4ed8aa4ae3418acbh
        QWORD 5b9cca4f7763e373h, 682e6ff3d6b2b8a3h
        QWORD 748f82ee5defb2fch, 78a5636f43172f60h
        QWORD 84c87814a1f0ab72h, 8cc702081a6439ech
        QWORD 90befffa23631e28h, 0a4506cebde82bde9h
        QWORD 0bef9a3f7b2c67915h, 0c67178f2e372532bh
        QWORD 0ca273eceea26619ch, 0d186b8c721c0c207h
        QWORD 0eada7dd6cde0eb1eh, 0f57d4f7fee6ed178h
        QWORD 06f067aa72176fbah, 0a637dc5a2c898a6h
        QWORD 113f9804bef90daeh, 1b710b35131c471bh
        QWORD 28db77f523047d84h, 32caab7b40c72493h
        QWORD 3c9ebe0a15c9bebch, 431d67c49c100d4ch
        QWORD 4cc5d4becb3e42b6h, 597f299cfc657e2ah
        QWORD 5fcb6fab3ad6faech, 6c44198c4a475817h
ptr_L_avx1_sha512_k QWORD L_avx1_sha512_k
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_avx1_sha512_flip_mask QWORD 0001020304050607h, 08090a0b0c0d0e0fh
ptr_L_avx1_sha512_flip_mask QWORD L_avx1_sha512_flip_mask
_DATA ENDS
_TEXT SEGMENT READONLY PARA
Transform_Sha512_AVX1 PROC
        push	rbx
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        mov	rdi, rcx
        sub	rsp, 280
        vmovdqu	OWORD PTR [rsp+136], xmm6
        vmovdqu	OWORD PTR [rsp+152], xmm7
        vmovdqu	OWORD PTR [rsp+168], xmm8
        vmovdqu	OWORD PTR [rsp+184], xmm9
        vmovdqu	OWORD PTR [rsp+200], xmm10
        vmovdqu	OWORD PTR [rsp+216], xmm11
        vmovdqu	OWORD PTR [rsp+232], xmm13
        vmovdqu	OWORD PTR [rsp+248], xmm12
        vmovdqu	OWORD PTR [rsp+264], xmm14
        lea	rax, QWORD PTR [rdi+64]
        vmovdqa	xmm14, OWORD PTR L_avx1_sha512_flip_mask
        mov	r8, QWORD PTR [rdi]
        mov	r9, QWORD PTR [rdi+8]
        mov	r10, QWORD PTR [rdi+16]
        mov	r11, QWORD PTR [rdi+24]
        mov	r12, QWORD PTR [rdi+32]
        mov	r13, QWORD PTR [rdi+40]
        mov	r14, QWORD PTR [rdi+48]
        mov	r15, QWORD PTR [rdi+56]
        vmovdqu	xmm0, OWORD PTR [rax]
        vmovdqu	xmm1, OWORD PTR [rax+16]
        vpshufb	xmm0, xmm0, xmm14
        vpshufb	xmm1, xmm1, xmm14
        vmovdqu	xmm2, OWORD PTR [rax+32]
        vmovdqu	xmm3, OWORD PTR [rax+48]
        vpshufb	xmm2, xmm2, xmm14
        vpshufb	xmm3, xmm3, xmm14
        vmovdqu	xmm4, OWORD PTR [rax+64]
        vmovdqu	xmm5, OWORD PTR [rax+80]
        vpshufb	xmm4, xmm4, xmm14
        vpshufb	xmm5, xmm5, xmm14
        vmovdqu	xmm6, OWORD PTR [rax+96]
        vmovdqu	xmm7, OWORD PTR [rax+112]
        vpshufb	xmm6, xmm6, xmm14
        vpshufb	xmm7, xmm7, xmm14
        mov	DWORD PTR [rsp+128], 4
        mov	rsi, QWORD PTR [ptr_L_avx1_sha512_k]
        mov	rbx, r9
        mov	rax, r12
        xor	rbx, r10
        ; Start of 16 rounds
L_transform_sha512_avx1_start:
        vpaddq	xmm8, xmm0, [rsi]
        vpaddq	xmm9, xmm1, [rsi+16]
        vmovdqu	OWORD PTR [rsp], xmm8
        vmovdqu	OWORD PTR [rsp+16], xmm9
        vpaddq	xmm8, xmm2, [rsi+32]
        vpaddq	xmm9, xmm3, [rsi+48]
        vmovdqu	OWORD PTR [rsp+32], xmm8
        vmovdqu	OWORD PTR [rsp+48], xmm9
        vpaddq	xmm8, xmm4, [rsi+64]
        vpaddq	xmm9, xmm5, [rsi+80]
        vmovdqu	OWORD PTR [rsp+64], xmm8
        vmovdqu	OWORD PTR [rsp+80], xmm9
        vpaddq	xmm8, xmm6, [rsi+96]
        vpaddq	xmm9, xmm7, [rsi+112]
        vmovdqu	OWORD PTR [rsp+96], xmm8
        vmovdqu	OWORD PTR [rsp+112], xmm9
        add	rsi, 128
        ; msg_sched: 0-1
        ; rnd_0: 0 - 0
        ror	rax, 23
        vpalignr	xmm12, xmm1, xmm0, 8
        vpalignr	xmm13, xmm5, xmm4, 8
        ; rnd_0: 1 - 1
        mov	rdx, r8
        mov	rcx, r13
        add	r15, QWORD PTR [rsp]
        xor	rcx, r14
        vpsrlq	xmm8, xmm12, 1
        vpsllq	xmm9, xmm12, 63
        ; rnd_0: 2 - 3
        xor	rax, r12
        and	rcx, r12
        ror	rax, 4
        xor	rcx, r14
        vpsrlq	xmm10, xmm12, 8
        vpsllq	xmm11, xmm12, 56
        ; rnd_0: 4 - 5
        xor	rax, r12
        add	r15, rcx
        ror	rax, 14
        xor	rdx, r9
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_0: 6 - 7
        add	r15, rax
        mov	rcx, r8
        and	rbx, rdx
        ror	rcx, 5
        vpsrlq	xmm11, xmm12, 7
        vpxor	xmm8, xmm8, xmm10
        ; rnd_0: 8 - 9
        xor	rcx, r8
        xor	rbx, r9
        ror	rcx, 6
        add	r11, r15
        vpxor	xmm8, xmm8, xmm11
        vpaddq	xmm0, xmm13, xmm0
        ; rnd_0: 10 - 11
        xor	rcx, r8
        add	r15, rbx
        ror	rcx, 28
        mov	rax, r11
        add	r15, rcx
        ; rnd_1: 0 - 0
        ror	rax, 23
        vpaddq	xmm0, xmm8, xmm0
        ; rnd_1: 1 - 1
        mov	rbx, r15
        mov	rcx, r12
        add	r14, QWORD PTR [rsp+8]
        xor	rcx, r13
        vpsrlq	xmm8, xmm7, 19
        vpsllq	xmm9, xmm7, 45
        ; rnd_1: 2 - 3
        xor	rax, r11
        and	rcx, r11
        ror	rax, 4
        xor	rcx, r13
        vpsrlq	xmm10, xmm7, 61
        vpsllq	xmm11, xmm7, 3
        ; rnd_1: 4 - 6
        xor	rax, r11
        add	r14, rcx
        ror	rax, 14
        xor	rbx, r8
        add	r14, rax
        mov	rcx, r15
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_1: 7 - 8
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r15
        xor	rdx, r8
        vpxor	xmm8, xmm8, xmm10
        vpsrlq	xmm11, xmm7, 6
        ; rnd_1: 9 - 10
        ror	rcx, 6
        add	r10, r14
        xor	rcx, r15
        add	r14, rdx
        vpxor	xmm8, xmm8, xmm11
        ; rnd_1: 11 - 11
        ror	rcx, 28
        mov	rax, r10
        add	r14, rcx
        vpaddq	xmm0, xmm8, xmm0
        ; msg_sched done: 0-1
        ; msg_sched: 2-3
        ; rnd_0: 0 - 0
        ror	rax, 23
        vpalignr	xmm12, xmm2, xmm1, 8
        vpalignr	xmm13, xmm6, xmm5, 8
        ; rnd_0: 1 - 1
        mov	rdx, r14
        mov	rcx, r11
        add	r13, QWORD PTR [rsp+16]
        xor	rcx, r12
        vpsrlq	xmm8, xmm12, 1
        vpsllq	xmm9, xmm12, 63
        ; rnd_0: 2 - 3
        xor	rax, r10
        and	rcx, r10
        ror	rax, 4
        xor	rcx, r12
        vpsrlq	xmm10, xmm12, 8
        vpsllq	xmm11, xmm12, 56
        ; rnd_0: 4 - 5
        xor	rax, r10
        add	r13, rcx
        ror	rax, 14
        xor	rdx, r15
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_0: 6 - 7
        add	r13, rax
        mov	rcx, r14
        and	rbx, rdx
        ror	rcx, 5
        vpsrlq	xmm11, xmm12, 7
        vpxor	xmm8, xmm8, xmm10
        ; rnd_0: 8 - 9
        xor	rcx, r14
        xor	rbx, r15
        ror	rcx, 6
        add	r9, r13
        vpxor	xmm8, xmm8, xmm11
        vpaddq	xmm1, xmm13, xmm1
        ; rnd_0: 10 - 11
        xor	rcx, r14
        add	r13, rbx
        ror	rcx, 28
        mov	rax, r9
        add	r13, rcx
        ; rnd_1: 0 - 0
        ror	rax, 23
        vpaddq	xmm1, xmm8, xmm1
        ; rnd_1: 1 - 1
        mov	rbx, r13
        mov	rcx, r10
        add	r12, QWORD PTR [rsp+24]
        xor	rcx, r11
        vpsrlq	xmm8, xmm0, 19
        vpsllq	xmm9, xmm0, 45
        ; rnd_1: 2 - 3
        xor	rax, r9
        and	rcx, r9
        ror	rax, 4
        xor	rcx, r11
        vpsrlq	xmm10, xmm0, 61
        vpsllq	xmm11, xmm0, 3
        ; rnd_1: 4 - 6
        xor	rax, r9
        add	r12, rcx
        ror	rax, 14
        xor	rbx, r14
        add	r12, rax
        mov	rcx, r13
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_1: 7 - 8
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r13
        xor	rdx, r14
        vpxor	xmm8, xmm8, xmm10
        vpsrlq	xmm11, xmm0, 6
        ; rnd_1: 9 - 10
        ror	rcx, 6
        add	r8, r12
        xor	rcx, r13
        add	r12, rdx
        vpxor	xmm8, xmm8, xmm11
        ; rnd_1: 11 - 11
        ror	rcx, 28
        mov	rax, r8
        add	r12, rcx
        vpaddq	xmm1, xmm8, xmm1
        ; msg_sched done: 2-3
        ; msg_sched: 4-5
        ; rnd_0: 0 - 0
        ror	rax, 23
        vpalignr	xmm12, xmm3, xmm2, 8
        vpalignr	xmm13, xmm7, xmm6, 8
        ; rnd_0: 1 - 1
        mov	rdx, r12
        mov	rcx, r9
        add	r11, QWORD PTR [rsp+32]
        xor	rcx, r10
        vpsrlq	xmm8, xmm12, 1
        vpsllq	xmm9, xmm12, 63
        ; rnd_0: 2 - 3
        xor	rax, r8
        and	rcx, r8
        ror	rax, 4
        xor	rcx, r10
        vpsrlq	xmm10, xmm12, 8
        vpsllq	xmm11, xmm12, 56
        ; rnd_0: 4 - 5
        xor	rax, r8
        add	r11, rcx
        ror	rax, 14
        xor	rdx, r13
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_0: 6 - 7
        add	r11, rax
        mov	rcx, r12
        and	rbx, rdx
        ror	rcx, 5
        vpsrlq	xmm11, xmm12, 7
        vpxor	xmm8, xmm8, xmm10
        ; rnd_0: 8 - 9
        xor	rcx, r12
        xor	rbx, r13
        ror	rcx, 6
        add	r15, r11
        vpxor	xmm8, xmm8, xmm11
        vpaddq	xmm2, xmm13, xmm2
        ; rnd_0: 10 - 11
        xor	rcx, r12
        add	r11, rbx
        ror	rcx, 28
        mov	rax, r15
        add	r11, rcx
        ; rnd_1: 0 - 0
        ror	rax, 23
        vpaddq	xmm2, xmm8, xmm2
        ; rnd_1: 1 - 1
        mov	rbx, r11
        mov	rcx, r8
        add	r10, QWORD PTR [rsp+40]
        xor	rcx, r9
        vpsrlq	xmm8, xmm1, 19
        vpsllq	xmm9, xmm1, 45
        ; rnd_1: 2 - 3
        xor	rax, r15
        and	rcx, r15
        ror	rax, 4
        xor	rcx, r9
        vpsrlq	xmm10, xmm1, 61
        vpsllq	xmm11, xmm1, 3
        ; rnd_1: 4 - 6
        xor	rax, r15
        add	r10, rcx
        ror	rax, 14
        xor	rbx, r12
        add	r10, rax
        mov	rcx, r11
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_1: 7 - 8
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r11
        xor	rdx, r12
        vpxor	xmm8, xmm8, xmm10
        vpsrlq	xmm11, xmm1, 6
        ; rnd_1: 9 - 10
        ror	rcx, 6
        add	r14, r10
        xor	rcx, r11
        add	r10, rdx
        vpxor	xmm8, xmm8, xmm11
        ; rnd_1: 11 - 11
        ror	rcx, 28
        mov	rax, r14
        add	r10, rcx
        vpaddq	xmm2, xmm8, xmm2
        ; msg_sched done: 4-5
        ; msg_sched: 6-7
        ; rnd_0: 0 - 0
        ror	rax, 23
        vpalignr	xmm12, xmm4, xmm3, 8
        vpalignr	xmm13, xmm0, xmm7, 8
        ; rnd_0: 1 - 1
        mov	rdx, r10
        mov	rcx, r15
        add	r9, QWORD PTR [rsp+48]
        xor	rcx, r8
        vpsrlq	xmm8, xmm12, 1
        vpsllq	xmm9, xmm12, 63
        ; rnd_0: 2 - 3
        xor	rax, r14
        and	rcx, r14
        ror	rax, 4
        xor	rcx, r8
        vpsrlq	xmm10, xmm12, 8
        vpsllq	xmm11, xmm12, 56
        ; rnd_0: 4 - 5
        xor	rax, r14
        add	r9, rcx
        ror	rax, 14
        xor	rdx, r11
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_0: 6 - 7
        add	r9, rax
        mov	rcx, r10
        and	rbx, rdx
        ror	rcx, 5
        vpsrlq	xmm11, xmm12, 7
        vpxor	xmm8, xmm8, xmm10
        ; rnd_0: 8 - 9
        xor	rcx, r10
        xor	rbx, r11
        ror	rcx, 6
        add	r13, r9
        vpxor	xmm8, xmm8, xmm11
        vpaddq	xmm3, xmm13, xmm3
        ; rnd_0: 10 - 11
        xor	rcx, r10
        add	r9, rbx
        ror	rcx, 28
        mov	rax, r13
        add	r9, rcx
        ; rnd_1: 0 - 0
        ror	rax, 23
        vpaddq	xmm3, xmm8, xmm3
        ; rnd_1: 1 - 1
        mov	rbx, r9
        mov	rcx, r14
        add	r8, QWORD PTR [rsp+56]
        xor	rcx, r15
        vpsrlq	xmm8, xmm2, 19
        vpsllq	xmm9, xmm2, 45
        ; rnd_1: 2 - 3
        xor	rax, r13
        and	rcx, r13
        ror	rax, 4
        xor	rcx, r15
        vpsrlq	xmm10, xmm2, 61
        vpsllq	xmm11, xmm2, 3
        ; rnd_1: 4 - 6
        xor	rax, r13
        add	r8, rcx
        ror	rax, 14
        xor	rbx, r10
        add	r8, rax
        mov	rcx, r9
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_1: 7 - 8
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r9
        xor	rdx, r10
        vpxor	xmm8, xmm8, xmm10
        vpsrlq	xmm11, xmm2, 6
        ; rnd_1: 9 - 10
        ror	rcx, 6
        add	r12, r8
        xor	rcx, r9
        add	r8, rdx
        vpxor	xmm8, xmm8, xmm11
        ; rnd_1: 11 - 11
        ror	rcx, 28
        mov	rax, r12
        add	r8, rcx
        vpaddq	xmm3, xmm8, xmm3
        ; msg_sched done: 6-7
        ; msg_sched: 8-9
        ; rnd_0: 0 - 0
        ror	rax, 23
        vpalignr	xmm12, xmm5, xmm4, 8
        vpalignr	xmm13, xmm1, xmm0, 8
        ; rnd_0: 1 - 1
        mov	rdx, r8
        mov	rcx, r13
        add	r15, QWORD PTR [rsp+64]
        xor	rcx, r14
        vpsrlq	xmm8, xmm12, 1
        vpsllq	xmm9, xmm12, 63
        ; rnd_0: 2 - 3
        xor	rax, r12
        and	rcx, r12
        ror	rax, 4
        xor	rcx, r14
        vpsrlq	xmm10, xmm12, 8
        vpsllq	xmm11, xmm12, 56
        ; rnd_0: 4 - 5
        xor	rax, r12
        add	r15, rcx
        ror	rax, 14
        xor	rdx, r9
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_0: 6 - 7
        add	r15, rax
        mov	rcx, r8
        and	rbx, rdx
        ror	rcx, 5
        vpsrlq	xmm11, xmm12, 7
        vpxor	xmm8, xmm8, xmm10
        ; rnd_0: 8 - 9
        xor	rcx, r8
        xor	rbx, r9
        ror	rcx, 6
        add	r11, r15
        vpxor	xmm8, xmm8, xmm11
        vpaddq	xmm4, xmm13, xmm4
        ; rnd_0: 10 - 11
        xor	rcx, r8
        add	r15, rbx
        ror	rcx, 28
        mov	rax, r11
        add	r15, rcx
        ; rnd_1: 0 - 0
        ror	rax, 23
        vpaddq	xmm4, xmm8, xmm4
        ; rnd_1: 1 - 1
        mov	rbx, r15
        mov	rcx, r12
        add	r14, QWORD PTR [rsp+72]
        xor	rcx, r13
        vpsrlq	xmm8, xmm3, 19
        vpsllq	xmm9, xmm3, 45
        ; rnd_1: 2 - 3
        xor	rax, r11
        and	rcx, r11
        ror	rax, 4
        xor	rcx, r13
        vpsrlq	xmm10, xmm3, 61
        vpsllq	xmm11, xmm3, 3
        ; rnd_1: 4 - 6
        xor	rax, r11
        add	r14, rcx
        ror	rax, 14
        xor	rbx, r8
        add	r14, rax
        mov	rcx, r15
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_1: 7 - 8
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r15
        xor	rdx, r8
        vpxor	xmm8, xmm8, xmm10
        vpsrlq	xmm11, xmm3, 6
        ; rnd_1: 9 - 10
        ror	rcx, 6
        add	r10, r14
        xor	rcx, r15
        add	r14, rdx
        vpxor	xmm8, xmm8, xmm11
        ; rnd_1: 11 - 11
        ror	rcx, 28
        mov	rax, r10
        add	r14, rcx
        vpaddq	xmm4, xmm8, xmm4
        ; msg_sched done: 8-9
        ; msg_sched: 10-11
        ; rnd_0: 0 - 0
        ror	rax, 23
        vpalignr	xmm12, xmm6, xmm5, 8
        vpalignr	xmm13, xmm2, xmm1, 8
        ; rnd_0: 1 - 1
        mov	rdx, r14
        mov	rcx, r11
        add	r13, QWORD PTR [rsp+80]
        xor	rcx, r12
        vpsrlq	xmm8, xmm12, 1
        vpsllq	xmm9, xmm12, 63
        ; rnd_0: 2 - 3
        xor	rax, r10
        and	rcx, r10
        ror	rax, 4
        xor	rcx, r12
        vpsrlq	xmm10, xmm12, 8
        vpsllq	xmm11, xmm12, 56
        ; rnd_0: 4 - 5
        xor	rax, r10
        add	r13, rcx
        ror	rax, 14
        xor	rdx, r15
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_0: 6 - 7
        add	r13, rax
        mov	rcx, r14
        and	rbx, rdx
        ror	rcx, 5
        vpsrlq	xmm11, xmm12, 7
        vpxor	xmm8, xmm8, xmm10
        ; rnd_0: 8 - 9
        xor	rcx, r14
        xor	rbx, r15
        ror	rcx, 6
        add	r9, r13
        vpxor	xmm8, xmm8, xmm11
        vpaddq	xmm5, xmm13, xmm5
        ; rnd_0: 10 - 11
        xor	rcx, r14
        add	r13, rbx
        ror	rcx, 28
        mov	rax, r9
        add	r13, rcx
        ; rnd_1: 0 - 0
        ror	rax, 23
        vpaddq	xmm5, xmm8, xmm5
        ; rnd_1: 1 - 1
        mov	rbx, r13
        mov	rcx, r10
        add	r12, QWORD PTR [rsp+88]
        xor	rcx, r11
        vpsrlq	xmm8, xmm4, 19
        vpsllq	xmm9, xmm4, 45
        ; rnd_1: 2 - 3
        xor	rax, r9
        and	rcx, r9
        ror	rax, 4
        xor	rcx, r11
        vpsrlq	xmm10, xmm4, 61
        vpsllq	xmm11, xmm4, 3
        ; rnd_1: 4 - 6
        xor	rax, r9
        add	r12, rcx
        ror	rax, 14
        xor	rbx, r14
        add	r12, rax
        mov	rcx, r13
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_1: 7 - 8
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r13
        xor	rdx, r14
        vpxor	xmm8, xmm8, xmm10
        vpsrlq	xmm11, xmm4, 6
        ; rnd_1: 9 - 10
        ror	rcx, 6
        add	r8, r12
        xor	rcx, r13
        add	r12, rdx
        vpxor	xmm8, xmm8, xmm11
        ; rnd_1: 11 - 11
        ror	rcx, 28
        mov	rax, r8
        add	r12, rcx
        vpaddq	xmm5, xmm8, xmm5
        ; msg_sched done: 10-11
        ; msg_sched: 12-13
        ; rnd_0: 0 - 0
        ror	rax, 23
        vpalignr	xmm12, xmm7, xmm6, 8
        vpalignr	xmm13, xmm3, xmm2, 8
        ; rnd_0: 1 - 1
        mov	rdx, r12
        mov	rcx, r9
        add	r11, QWORD PTR [rsp+96]
        xor	rcx, r10
        vpsrlq	xmm8, xmm12, 1
        vpsllq	xmm9, xmm12, 63
        ; rnd_0: 2 - 3
        xor	rax, r8
        and	rcx, r8
        ror	rax, 4
        xor	rcx, r10
        vpsrlq	xmm10, xmm12, 8
        vpsllq	xmm11, xmm12, 56
        ; rnd_0: 4 - 5
        xor	rax, r8
        add	r11, rcx
        ror	rax, 14
        xor	rdx, r13
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_0: 6 - 7
        add	r11, rax
        mov	rcx, r12
        and	rbx, rdx
        ror	rcx, 5
        vpsrlq	xmm11, xmm12, 7
        vpxor	xmm8, xmm8, xmm10
        ; rnd_0: 8 - 9
        xor	rcx, r12
        xor	rbx, r13
        ror	rcx, 6
        add	r15, r11
        vpxor	xmm8, xmm8, xmm11
        vpaddq	xmm6, xmm13, xmm6
        ; rnd_0: 10 - 11
        xor	rcx, r12
        add	r11, rbx
        ror	rcx, 28
        mov	rax, r15
        add	r11, rcx
        ; rnd_1: 0 - 0
        ror	rax, 23
        vpaddq	xmm6, xmm8, xmm6
        ; rnd_1: 1 - 1
        mov	rbx, r11
        mov	rcx, r8
        add	r10, QWORD PTR [rsp+104]
        xor	rcx, r9
        vpsrlq	xmm8, xmm5, 19
        vpsllq	xmm9, xmm5, 45
        ; rnd_1: 2 - 3
        xor	rax, r15
        and	rcx, r15
        ror	rax, 4
        xor	rcx, r9
        vpsrlq	xmm10, xmm5, 61
        vpsllq	xmm11, xmm5, 3
        ; rnd_1: 4 - 6
        xor	rax, r15
        add	r10, rcx
        ror	rax, 14
        xor	rbx, r12
        add	r10, rax
        mov	rcx, r11
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_1: 7 - 8
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r11
        xor	rdx, r12
        vpxor	xmm8, xmm8, xmm10
        vpsrlq	xmm11, xmm5, 6
        ; rnd_1: 9 - 10
        ror	rcx, 6
        add	r14, r10
        xor	rcx, r11
        add	r10, rdx
        vpxor	xmm8, xmm8, xmm11
        ; rnd_1: 11 - 11
        ror	rcx, 28
        mov	rax, r14
        add	r10, rcx
        vpaddq	xmm6, xmm8, xmm6
        ; msg_sched done: 12-13
        ; msg_sched: 14-15
        ; rnd_0: 0 - 0
        ror	rax, 23
        vpalignr	xmm12, xmm0, xmm7, 8
        vpalignr	xmm13, xmm4, xmm3, 8
        ; rnd_0: 1 - 1
        mov	rdx, r10
        mov	rcx, r15
        add	r9, QWORD PTR [rsp+112]
        xor	rcx, r8
        vpsrlq	xmm8, xmm12, 1
        vpsllq	xmm9, xmm12, 63
        ; rnd_0: 2 - 3
        xor	rax, r14
        and	rcx, r14
        ror	rax, 4
        xor	rcx, r8
        vpsrlq	xmm10, xmm12, 8
        vpsllq	xmm11, xmm12, 56
        ; rnd_0: 4 - 5
        xor	rax, r14
        add	r9, rcx
        ror	rax, 14
        xor	rdx, r11
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_0: 6 - 7
        add	r9, rax
        mov	rcx, r10
        and	rbx, rdx
        ror	rcx, 5
        vpsrlq	xmm11, xmm12, 7
        vpxor	xmm8, xmm8, xmm10
        ; rnd_0: 8 - 9
        xor	rcx, r10
        xor	rbx, r11
        ror	rcx, 6
        add	r13, r9
        vpxor	xmm8, xmm8, xmm11
        vpaddq	xmm7, xmm13, xmm7
        ; rnd_0: 10 - 11
        xor	rcx, r10
        add	r9, rbx
        ror	rcx, 28
        mov	rax, r13
        add	r9, rcx
        ; rnd_1: 0 - 0
        ror	rax, 23
        vpaddq	xmm7, xmm8, xmm7
        ; rnd_1: 1 - 1
        mov	rbx, r9
        mov	rcx, r14
        add	r8, QWORD PTR [rsp+120]
        xor	rcx, r15
        vpsrlq	xmm8, xmm6, 19
        vpsllq	xmm9, xmm6, 45
        ; rnd_1: 2 - 3
        xor	rax, r13
        and	rcx, r13
        ror	rax, 4
        xor	rcx, r15
        vpsrlq	xmm10, xmm6, 61
        vpsllq	xmm11, xmm6, 3
        ; rnd_1: 4 - 6
        xor	rax, r13
        add	r8, rcx
        ror	rax, 14
        xor	rbx, r10
        add	r8, rax
        mov	rcx, r9
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_1: 7 - 8
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r9
        xor	rdx, r10
        vpxor	xmm8, xmm8, xmm10
        vpsrlq	xmm11, xmm6, 6
        ; rnd_1: 9 - 10
        ror	rcx, 6
        add	r12, r8
        xor	rcx, r9
        add	r8, rdx
        vpxor	xmm8, xmm8, xmm11
        ; rnd_1: 11 - 11
        ror	rcx, 28
        mov	rax, r12
        add	r8, rcx
        vpaddq	xmm7, xmm8, xmm7
        ; msg_sched done: 14-15
        sub	DWORD PTR [rsp+128], 1
        jne	L_transform_sha512_avx1_start
        vpaddq	xmm8, xmm0, [rsi]
        vpaddq	xmm9, xmm1, [rsi+16]
        vmovdqu	OWORD PTR [rsp], xmm8
        vmovdqu	OWORD PTR [rsp+16], xmm9
        vpaddq	xmm8, xmm2, [rsi+32]
        vpaddq	xmm9, xmm3, [rsi+48]
        vmovdqu	OWORD PTR [rsp+32], xmm8
        vmovdqu	OWORD PTR [rsp+48], xmm9
        vpaddq	xmm8, xmm4, [rsi+64]
        vpaddq	xmm9, xmm5, [rsi+80]
        vmovdqu	OWORD PTR [rsp+64], xmm8
        vmovdqu	OWORD PTR [rsp+80], xmm9
        vpaddq	xmm8, xmm6, [rsi+96]
        vpaddq	xmm9, xmm7, [rsi+112]
        vmovdqu	OWORD PTR [rsp+96], xmm8
        vmovdqu	OWORD PTR [rsp+112], xmm9
        ; rnd_all_2: 0-1
        ; rnd_0: 0 - 11
        ror	rax, 23
        mov	rdx, r8
        mov	rcx, r13
        add	r15, QWORD PTR [rsp]
        xor	rcx, r14
        xor	rax, r12
        and	rcx, r12
        ror	rax, 4
        xor	rcx, r14
        xor	rax, r12
        add	r15, rcx
        ror	rax, 14
        xor	rdx, r9
        add	r15, rax
        mov	rcx, r8
        and	rbx, rdx
        ror	rcx, 5
        xor	rcx, r8
        xor	rbx, r9
        ror	rcx, 6
        add	r11, r15
        xor	rcx, r8
        add	r15, rbx
        ror	rcx, 28
        mov	rax, r11
        add	r15, rcx
        ; rnd_1: 0 - 11
        ror	rax, 23
        mov	rbx, r15
        mov	rcx, r12
        add	r14, QWORD PTR [rsp+8]
        xor	rcx, r13
        xor	rax, r11
        and	rcx, r11
        ror	rax, 4
        xor	rcx, r13
        xor	rax, r11
        add	r14, rcx
        ror	rax, 14
        xor	rbx, r8
        add	r14, rax
        mov	rcx, r15
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r15
        xor	rdx, r8
        ror	rcx, 6
        add	r10, r14
        xor	rcx, r15
        add	r14, rdx
        ror	rcx, 28
        mov	rax, r10
        add	r14, rcx
        ; rnd_all_2: 2-3
        ; rnd_0: 0 - 11
        ror	rax, 23
        mov	rdx, r14
        mov	rcx, r11
        add	r13, QWORD PTR [rsp+16]
        xor	rcx, r12
        xor	rax, r10
        and	rcx, r10
        ror	rax, 4
        xor	rcx, r12
        xor	rax, r10
        add	r13, rcx
        ror	rax, 14
        xor	rdx, r15
        add	r13, rax
        mov	rcx, r14
        and	rbx, rdx
        ror	rcx, 5
        xor	rcx, r14
        xor	rbx, r15
        ror	rcx, 6
        add	r9, r13
        xor	rcx, r14
        add	r13, rbx
        ror	rcx, 28
        mov	rax, r9
        add	r13, rcx
        ; rnd_1: 0 - 11
        ror	rax, 23
        mov	rbx, r13
        mov	rcx, r10
        add	r12, QWORD PTR [rsp+24]
        xor	rcx, r11
        xor	rax, r9
        and	rcx, r9
        ror	rax, 4
        xor	rcx, r11
        xor	rax, r9
        add	r12, rcx
        ror	rax, 14
        xor	rbx, r14
        add	r12, rax
        mov	rcx, r13
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r13
        xor	rdx, r14
        ror	rcx, 6
        add	r8, r12
        xor	rcx, r13
        add	r12, rdx
        ror	rcx, 28
        mov	rax, r8
        add	r12, rcx
        ; rnd_all_2: 4-5
        ; rnd_0: 0 - 11
        ror	rax, 23
        mov	rdx, r12
        mov	rcx, r9
        add	r11, QWORD PTR [rsp+32]
        xor	rcx, r10
        xor	rax, r8
        and	rcx, r8
        ror	rax, 4
        xor	rcx, r10
        xor	rax, r8
        add	r11, rcx
        ror	rax, 14
        xor	rdx, r13
        add	r11, rax
        mov	rcx, r12
        and	rbx, rdx
        ror	rcx, 5
        xor	rcx, r12
        xor	rbx, r13
        ror	rcx, 6
        add	r15, r11
        xor	rcx, r12
        add	r11, rbx
        ror	rcx, 28
        mov	rax, r15
        add	r11, rcx
        ; rnd_1: 0 - 11
        ror	rax, 23
        mov	rbx, r11
        mov	rcx, r8
        add	r10, QWORD PTR [rsp+40]
        xor	rcx, r9
        xor	rax, r15
        and	rcx, r15
        ror	rax, 4
        xor	rcx, r9
        xor	rax, r15
        add	r10, rcx
        ror	rax, 14
        xor	rbx, r12
        add	r10, rax
        mov	rcx, r11
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r11
        xor	rdx, r12
        ror	rcx, 6
        add	r14, r10
        xor	rcx, r11
        add	r10, rdx
        ror	rcx, 28
        mov	rax, r14
        add	r10, rcx
        ; rnd_all_2: 6-7
        ; rnd_0: 0 - 11
        ror	rax, 23
        mov	rdx, r10
        mov	rcx, r15
        add	r9, QWORD PTR [rsp+48]
        xor	rcx, r8
        xor	rax, r14
        and	rcx, r14
        ror	rax, 4
        xor	rcx, r8
        xor	rax, r14
        add	r9, rcx
        ror	rax, 14
        xor	rdx, r11
        add	r9, rax
        mov	rcx, r10
        and	rbx, rdx
        ror	rcx, 5
        xor	rcx, r10
        xor	rbx, r11
        ror	rcx, 6
        add	r13, r9
        xor	rcx, r10
        add	r9, rbx
        ror	rcx, 28
        mov	rax, r13
        add	r9, rcx
        ; rnd_1: 0 - 11
        ror	rax, 23
        mov	rbx, r9
        mov	rcx, r14
        add	r8, QWORD PTR [rsp+56]
        xor	rcx, r15
        xor	rax, r13
        and	rcx, r13
        ror	rax, 4
        xor	rcx, r15
        xor	rax, r13
        add	r8, rcx
        ror	rax, 14
        xor	rbx, r10
        add	r8, rax
        mov	rcx, r9
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r9
        xor	rdx, r10
        ror	rcx, 6
        add	r12, r8
        xor	rcx, r9
        add	r8, rdx
        ror	rcx, 28
        mov	rax, r12
        add	r8, rcx
        ; rnd_all_2: 8-9
        ; rnd_0: 0 - 11
        ror	rax, 23
        mov	rdx, r8
        mov	rcx, r13
        add	r15, QWORD PTR [rsp+64]
        xor	rcx, r14
        xor	rax, r12
        and	rcx, r12
        ror	rax, 4
        xor	rcx, r14
        xor	rax, r12
        add	r15, rcx
        ror	rax, 14
        xor	rdx, r9
        add	r15, rax
        mov	rcx, r8
        and	rbx, rdx
        ror	rcx, 5
        xor	rcx, r8
        xor	rbx, r9
        ror	rcx, 6
        add	r11, r15
        xor	rcx, r8
        add	r15, rbx
        ror	rcx, 28
        mov	rax, r11
        add	r15, rcx
        ; rnd_1: 0 - 11
        ror	rax, 23
        mov	rbx, r15
        mov	rcx, r12
        add	r14, QWORD PTR [rsp+72]
        xor	rcx, r13
        xor	rax, r11
        and	rcx, r11
        ror	rax, 4
        xor	rcx, r13
        xor	rax, r11
        add	r14, rcx
        ror	rax, 14
        xor	rbx, r8
        add	r14, rax
        mov	rcx, r15
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r15
        xor	rdx, r8
        ror	rcx, 6
        add	r10, r14
        xor	rcx, r15
        add	r14, rdx
        ror	rcx, 28
        mov	rax, r10
        add	r14, rcx
        ; rnd_all_2: 10-11
        ; rnd_0: 0 - 11
        ror	rax, 23
        mov	rdx, r14
        mov	rcx, r11
        add	r13, QWORD PTR [rsp+80]
        xor	rcx, r12
        xor	rax, r10
        and	rcx, r10
        ror	rax, 4
        xor	rcx, r12
        xor	rax, r10
        add	r13, rcx
        ror	rax, 14
        xor	rdx, r15
        add	r13, rax
        mov	rcx, r14
        and	rbx, rdx
        ror	rcx, 5
        xor	rcx, r14
        xor	rbx, r15
        ror	rcx, 6
        add	r9, r13
        xor	rcx, r14
        add	r13, rbx
        ror	rcx, 28
        mov	rax, r9
        add	r13, rcx
        ; rnd_1: 0 - 11
        ror	rax, 23
        mov	rbx, r13
        mov	rcx, r10
        add	r12, QWORD PTR [rsp+88]
        xor	rcx, r11
        xor	rax, r9
        and	rcx, r9
        ror	rax, 4
        xor	rcx, r11
        xor	rax, r9
        add	r12, rcx
        ror	rax, 14
        xor	rbx, r14
        add	r12, rax
        mov	rcx, r13
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r13
        xor	rdx, r14
        ror	rcx, 6
        add	r8, r12
        xor	rcx, r13
        add	r12, rdx
        ror	rcx, 28
        mov	rax, r8
        add	r12, rcx
        ; rnd_all_2: 12-13
        ; rnd_0: 0 - 11
        ror	rax, 23
        mov	rdx, r12
        mov	rcx, r9
        add	r11, QWORD PTR [rsp+96]
        xor	rcx, r10
        xor	rax, r8
        and	rcx, r8
        ror	rax, 4
        xor	rcx, r10
        xor	rax, r8
        add	r11, rcx
        ror	rax, 14
        xor	rdx, r13
        add	r11, rax
        mov	rcx, r12
        and	rbx, rdx
        ror	rcx, 5
        xor	rcx, r12
        xor	rbx, r13
        ror	rcx, 6
        add	r15, r11
        xor	rcx, r12
        add	r11, rbx
        ror	rcx, 28
        mov	rax, r15
        add	r11, rcx
        ; rnd_1: 0 - 11
        ror	rax, 23
        mov	rbx, r11
        mov	rcx, r8
        add	r10, QWORD PTR [rsp+104]
        xor	rcx, r9
        xor	rax, r15
        and	rcx, r15
        ror	rax, 4
        xor	rcx, r9
        xor	rax, r15
        add	r10, rcx
        ror	rax, 14
        xor	rbx, r12
        add	r10, rax
        mov	rcx, r11
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r11
        xor	rdx, r12
        ror	rcx, 6
        add	r14, r10
        xor	rcx, r11
        add	r10, rdx
        ror	rcx, 28
        mov	rax, r14
        add	r10, rcx
        ; rnd_all_2: 14-15
        ; rnd_0: 0 - 11
        ror	rax, 23
        mov	rdx, r10
        mov	rcx, r15
        add	r9, QWORD PTR [rsp+112]
        xor	rcx, r8
        xor	rax, r14
        and	rcx, r14
        ror	rax, 4
        xor	rcx, r8
        xor	rax, r14
        add	r9, rcx
        ror	rax, 14
        xor	rdx, r11
        add	r9, rax
        mov	rcx, r10
        and	rbx, rdx
        ror	rcx, 5
        xor	rcx, r10
        xor	rbx, r11
        ror	rcx, 6
        add	r13, r9
        xor	rcx, r10
        add	r9, rbx
        ror	rcx, 28
        mov	rax, r13
        add	r9, rcx
        ; rnd_1: 0 - 11
        ror	rax, 23
        mov	rbx, r9
        mov	rcx, r14
        add	r8, QWORD PTR [rsp+120]
        xor	rcx, r15
        xor	rax, r13
        and	rcx, r13
        ror	rax, 4
        xor	rcx, r15
        xor	rax, r13
        add	r8, rcx
        ror	rax, 14
        xor	rbx, r10
        add	r8, rax
        mov	rcx, r9
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r9
        xor	rdx, r10
        ror	rcx, 6
        add	r12, r8
        xor	rcx, r9
        add	r8, rdx
        ror	rcx, 28
        mov	rax, r12
        add	r8, rcx
        add	QWORD PTR [rdi], r8
        add	QWORD PTR [rdi+8], r9
        add	QWORD PTR [rdi+16], r10
        add	QWORD PTR [rdi+24], r11
        add	QWORD PTR [rdi+32], r12
        add	QWORD PTR [rdi+40], r13
        add	QWORD PTR [rdi+48], r14
        add	QWORD PTR [rdi+56], r15
        xor	rax, rax
        vmovdqu	xmm6, OWORD PTR [rsp+136]
        vmovdqu	xmm7, OWORD PTR [rsp+152]
        vmovdqu	xmm8, OWORD PTR [rsp+168]
        vmovdqu	xmm9, OWORD PTR [rsp+184]
        vmovdqu	xmm10, OWORD PTR [rsp+200]
        vmovdqu	xmm11, OWORD PTR [rsp+216]
        vmovdqu	xmm13, OWORD PTR [rsp+232]
        vmovdqu	xmm12, OWORD PTR [rsp+248]
        vmovdqu	xmm14, OWORD PTR [rsp+264]
        add	rsp, 280
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        pop	rbx
        ret
Transform_Sha512_AVX1 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
Transform_Sha512_AVX1_Len PROC
        push	rbx
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbp
        mov	rdi, rcx
        mov	rbp, rdx
        sub	rsp, 288
        vmovdqu	OWORD PTR [rsp+144], xmm6
        vmovdqu	OWORD PTR [rsp+160], xmm7
        vmovdqu	OWORD PTR [rsp+176], xmm8
        vmovdqu	OWORD PTR [rsp+192], xmm9
        vmovdqu	OWORD PTR [rsp+208], xmm10
        vmovdqu	OWORD PTR [rsp+224], xmm11
        vmovdqu	OWORD PTR [rsp+240], xmm13
        vmovdqu	OWORD PTR [rsp+256], xmm12
        vmovdqu	OWORD PTR [rsp+272], xmm14
        mov	rsi, QWORD PTR [rdi+224]
        mov	rdx, QWORD PTR [ptr_L_avx1_sha512_k]
        vmovdqa	xmm14, OWORD PTR L_avx1_sha512_flip_mask
        mov	r8, QWORD PTR [rdi]
        mov	r9, QWORD PTR [rdi+8]
        mov	r10, QWORD PTR [rdi+16]
        mov	r11, QWORD PTR [rdi+24]
        mov	r12, QWORD PTR [rdi+32]
        mov	r13, QWORD PTR [rdi+40]
        mov	r14, QWORD PTR [rdi+48]
        mov	r15, QWORD PTR [rdi+56]
        ; Start of loop processing a block
L_sha512_len_avx1_begin:
        vmovdqu	xmm0, OWORD PTR [rsi]
        vmovdqu	xmm1, OWORD PTR [rsi+16]
        vpshufb	xmm0, xmm0, xmm14
        vpshufb	xmm1, xmm1, xmm14
        vmovdqu	xmm2, OWORD PTR [rsi+32]
        vmovdqu	xmm3, OWORD PTR [rsi+48]
        vpshufb	xmm2, xmm2, xmm14
        vpshufb	xmm3, xmm3, xmm14
        vmovdqu	xmm4, OWORD PTR [rsi+64]
        vmovdqu	xmm5, OWORD PTR [rsi+80]
        vpshufb	xmm4, xmm4, xmm14
        vpshufb	xmm5, xmm5, xmm14
        vmovdqu	xmm6, OWORD PTR [rsi+96]
        vmovdqu	xmm7, OWORD PTR [rsi+112]
        vpshufb	xmm6, xmm6, xmm14
        vpshufb	xmm7, xmm7, xmm14
        mov	DWORD PTR [rsp+128], 4
        mov	rbx, r9
        mov	rax, r12
        xor	rbx, r10
        vpaddq	xmm8, xmm0, [rdx]
        vpaddq	xmm9, xmm1, [rdx+16]
        vmovdqu	OWORD PTR [rsp], xmm8
        vmovdqu	OWORD PTR [rsp+16], xmm9
        vpaddq	xmm8, xmm2, [rdx+32]
        vpaddq	xmm9, xmm3, [rdx+48]
        vmovdqu	OWORD PTR [rsp+32], xmm8
        vmovdqu	OWORD PTR [rsp+48], xmm9
        vpaddq	xmm8, xmm4, [rdx+64]
        vpaddq	xmm9, xmm5, [rdx+80]
        vmovdqu	OWORD PTR [rsp+64], xmm8
        vmovdqu	OWORD PTR [rsp+80], xmm9
        vpaddq	xmm8, xmm6, [rdx+96]
        vpaddq	xmm9, xmm7, [rdx+112]
        vmovdqu	OWORD PTR [rsp+96], xmm8
        vmovdqu	OWORD PTR [rsp+112], xmm9
        ; Start of 16 rounds
L_sha512_len_avx1_start:
        add	rdx, 128
        mov	QWORD PTR [rsp+136], rdx
        ; msg_sched: 0-1
        ; rnd_0: 0 - 0
        ror	rax, 23
        vpalignr	xmm12, xmm1, xmm0, 8
        vpalignr	xmm13, xmm5, xmm4, 8
        ; rnd_0: 1 - 1
        mov	rdx, r8
        mov	rcx, r13
        add	r15, QWORD PTR [rsp]
        xor	rcx, r14
        vpsrlq	xmm8, xmm12, 1
        vpsllq	xmm9, xmm12, 63
        ; rnd_0: 2 - 3
        xor	rax, r12
        and	rcx, r12
        ror	rax, 4
        xor	rcx, r14
        vpsrlq	xmm10, xmm12, 8
        vpsllq	xmm11, xmm12, 56
        ; rnd_0: 4 - 5
        xor	rax, r12
        add	r15, rcx
        ror	rax, 14
        xor	rdx, r9
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_0: 6 - 7
        add	r15, rax
        mov	rcx, r8
        and	rbx, rdx
        ror	rcx, 5
        vpsrlq	xmm11, xmm12, 7
        vpxor	xmm8, xmm8, xmm10
        ; rnd_0: 8 - 9
        xor	rcx, r8
        xor	rbx, r9
        ror	rcx, 6
        add	r11, r15
        vpxor	xmm8, xmm8, xmm11
        vpaddq	xmm0, xmm13, xmm0
        ; rnd_0: 10 - 11
        xor	rcx, r8
        add	r15, rbx
        ror	rcx, 28
        mov	rax, r11
        add	r15, rcx
        ; rnd_1: 0 - 0
        ror	rax, 23
        vpaddq	xmm0, xmm8, xmm0
        ; rnd_1: 1 - 1
        mov	rbx, r15
        mov	rcx, r12
        add	r14, QWORD PTR [rsp+8]
        xor	rcx, r13
        vpsrlq	xmm8, xmm7, 19
        vpsllq	xmm9, xmm7, 45
        ; rnd_1: 2 - 3
        xor	rax, r11
        and	rcx, r11
        ror	rax, 4
        xor	rcx, r13
        vpsrlq	xmm10, xmm7, 61
        vpsllq	xmm11, xmm7, 3
        ; rnd_1: 4 - 6
        xor	rax, r11
        add	r14, rcx
        ror	rax, 14
        xor	rbx, r8
        add	r14, rax
        mov	rcx, r15
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_1: 7 - 8
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r15
        xor	rdx, r8
        vpxor	xmm8, xmm8, xmm10
        vpsrlq	xmm11, xmm7, 6
        ; rnd_1: 9 - 10
        ror	rcx, 6
        add	r10, r14
        xor	rcx, r15
        add	r14, rdx
        vpxor	xmm8, xmm8, xmm11
        ; rnd_1: 11 - 11
        ror	rcx, 28
        mov	rax, r10
        add	r14, rcx
        vpaddq	xmm0, xmm8, xmm0
        ; msg_sched done: 0-1
        ; msg_sched: 2-3
        ; rnd_0: 0 - 0
        ror	rax, 23
        vpalignr	xmm12, xmm2, xmm1, 8
        vpalignr	xmm13, xmm6, xmm5, 8
        ; rnd_0: 1 - 1
        mov	rdx, r14
        mov	rcx, r11
        add	r13, QWORD PTR [rsp+16]
        xor	rcx, r12
        vpsrlq	xmm8, xmm12, 1
        vpsllq	xmm9, xmm12, 63
        ; rnd_0: 2 - 3
        xor	rax, r10
        and	rcx, r10
        ror	rax, 4
        xor	rcx, r12
        vpsrlq	xmm10, xmm12, 8
        vpsllq	xmm11, xmm12, 56
        ; rnd_0: 4 - 5
        xor	rax, r10
        add	r13, rcx
        ror	rax, 14
        xor	rdx, r15
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_0: 6 - 7
        add	r13, rax
        mov	rcx, r14
        and	rbx, rdx
        ror	rcx, 5
        vpsrlq	xmm11, xmm12, 7
        vpxor	xmm8, xmm8, xmm10
        ; rnd_0: 8 - 9
        xor	rcx, r14
        xor	rbx, r15
        ror	rcx, 6
        add	r9, r13
        vpxor	xmm8, xmm8, xmm11
        vpaddq	xmm1, xmm13, xmm1
        ; rnd_0: 10 - 11
        xor	rcx, r14
        add	r13, rbx
        ror	rcx, 28
        mov	rax, r9
        add	r13, rcx
        ; rnd_1: 0 - 0
        ror	rax, 23
        vpaddq	xmm1, xmm8, xmm1
        ; rnd_1: 1 - 1
        mov	rbx, r13
        mov	rcx, r10
        add	r12, QWORD PTR [rsp+24]
        xor	rcx, r11
        vpsrlq	xmm8, xmm0, 19
        vpsllq	xmm9, xmm0, 45
        ; rnd_1: 2 - 3
        xor	rax, r9
        and	rcx, r9
        ror	rax, 4
        xor	rcx, r11
        vpsrlq	xmm10, xmm0, 61
        vpsllq	xmm11, xmm0, 3
        ; rnd_1: 4 - 6
        xor	rax, r9
        add	r12, rcx
        ror	rax, 14
        xor	rbx, r14
        add	r12, rax
        mov	rcx, r13
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_1: 7 - 8
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r13
        xor	rdx, r14
        vpxor	xmm8, xmm8, xmm10
        vpsrlq	xmm11, xmm0, 6
        ; rnd_1: 9 - 10
        ror	rcx, 6
        add	r8, r12
        xor	rcx, r13
        add	r12, rdx
        vpxor	xmm8, xmm8, xmm11
        ; rnd_1: 11 - 11
        ror	rcx, 28
        mov	rax, r8
        add	r12, rcx
        vpaddq	xmm1, xmm8, xmm1
        ; msg_sched done: 2-3
        ; msg_sched: 4-5
        ; rnd_0: 0 - 0
        ror	rax, 23
        vpalignr	xmm12, xmm3, xmm2, 8
        vpalignr	xmm13, xmm7, xmm6, 8
        ; rnd_0: 1 - 1
        mov	rdx, r12
        mov	rcx, r9
        add	r11, QWORD PTR [rsp+32]
        xor	rcx, r10
        vpsrlq	xmm8, xmm12, 1
        vpsllq	xmm9, xmm12, 63
        ; rnd_0: 2 - 3
        xor	rax, r8
        and	rcx, r8
        ror	rax, 4
        xor	rcx, r10
        vpsrlq	xmm10, xmm12, 8
        vpsllq	xmm11, xmm12, 56
        ; rnd_0: 4 - 5
        xor	rax, r8
        add	r11, rcx
        ror	rax, 14
        xor	rdx, r13
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_0: 6 - 7
        add	r11, rax
        mov	rcx, r12
        and	rbx, rdx
        ror	rcx, 5
        vpsrlq	xmm11, xmm12, 7
        vpxor	xmm8, xmm8, xmm10
        ; rnd_0: 8 - 9
        xor	rcx, r12
        xor	rbx, r13
        ror	rcx, 6
        add	r15, r11
        vpxor	xmm8, xmm8, xmm11
        vpaddq	xmm2, xmm13, xmm2
        ; rnd_0: 10 - 11
        xor	rcx, r12
        add	r11, rbx
        ror	rcx, 28
        mov	rax, r15
        add	r11, rcx
        ; rnd_1: 0 - 0
        ror	rax, 23
        vpaddq	xmm2, xmm8, xmm2
        ; rnd_1: 1 - 1
        mov	rbx, r11
        mov	rcx, r8
        add	r10, QWORD PTR [rsp+40]
        xor	rcx, r9
        vpsrlq	xmm8, xmm1, 19
        vpsllq	xmm9, xmm1, 45
        ; rnd_1: 2 - 3
        xor	rax, r15
        and	rcx, r15
        ror	rax, 4
        xor	rcx, r9
        vpsrlq	xmm10, xmm1, 61
        vpsllq	xmm11, xmm1, 3
        ; rnd_1: 4 - 6
        xor	rax, r15
        add	r10, rcx
        ror	rax, 14
        xor	rbx, r12
        add	r10, rax
        mov	rcx, r11
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_1: 7 - 8
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r11
        xor	rdx, r12
        vpxor	xmm8, xmm8, xmm10
        vpsrlq	xmm11, xmm1, 6
        ; rnd_1: 9 - 10
        ror	rcx, 6
        add	r14, r10
        xor	rcx, r11
        add	r10, rdx
        vpxor	xmm8, xmm8, xmm11
        ; rnd_1: 11 - 11
        ror	rcx, 28
        mov	rax, r14
        add	r10, rcx
        vpaddq	xmm2, xmm8, xmm2
        ; msg_sched done: 4-5
        ; msg_sched: 6-7
        ; rnd_0: 0 - 0
        ror	rax, 23
        vpalignr	xmm12, xmm4, xmm3, 8
        vpalignr	xmm13, xmm0, xmm7, 8
        ; rnd_0: 1 - 1
        mov	rdx, r10
        mov	rcx, r15
        add	r9, QWORD PTR [rsp+48]
        xor	rcx, r8
        vpsrlq	xmm8, xmm12, 1
        vpsllq	xmm9, xmm12, 63
        ; rnd_0: 2 - 3
        xor	rax, r14
        and	rcx, r14
        ror	rax, 4
        xor	rcx, r8
        vpsrlq	xmm10, xmm12, 8
        vpsllq	xmm11, xmm12, 56
        ; rnd_0: 4 - 5
        xor	rax, r14
        add	r9, rcx
        ror	rax, 14
        xor	rdx, r11
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_0: 6 - 7
        add	r9, rax
        mov	rcx, r10
        and	rbx, rdx
        ror	rcx, 5
        vpsrlq	xmm11, xmm12, 7
        vpxor	xmm8, xmm8, xmm10
        ; rnd_0: 8 - 9
        xor	rcx, r10
        xor	rbx, r11
        ror	rcx, 6
        add	r13, r9
        vpxor	xmm8, xmm8, xmm11
        vpaddq	xmm3, xmm13, xmm3
        ; rnd_0: 10 - 11
        xor	rcx, r10
        add	r9, rbx
        ror	rcx, 28
        mov	rax, r13
        add	r9, rcx
        ; rnd_1: 0 - 0
        ror	rax, 23
        vpaddq	xmm3, xmm8, xmm3
        ; rnd_1: 1 - 1
        mov	rbx, r9
        mov	rcx, r14
        add	r8, QWORD PTR [rsp+56]
        xor	rcx, r15
        vpsrlq	xmm8, xmm2, 19
        vpsllq	xmm9, xmm2, 45
        ; rnd_1: 2 - 3
        xor	rax, r13
        and	rcx, r13
        ror	rax, 4
        xor	rcx, r15
        vpsrlq	xmm10, xmm2, 61
        vpsllq	xmm11, xmm2, 3
        ; rnd_1: 4 - 6
        xor	rax, r13
        add	r8, rcx
        ror	rax, 14
        xor	rbx, r10
        add	r8, rax
        mov	rcx, r9
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_1: 7 - 8
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r9
        xor	rdx, r10
        vpxor	xmm8, xmm8, xmm10
        vpsrlq	xmm11, xmm2, 6
        ; rnd_1: 9 - 10
        ror	rcx, 6
        add	r12, r8
        xor	rcx, r9
        add	r8, rdx
        vpxor	xmm8, xmm8, xmm11
        ; rnd_1: 11 - 11
        ror	rcx, 28
        mov	rax, r12
        add	r8, rcx
        vpaddq	xmm3, xmm8, xmm3
        ; msg_sched done: 6-7
        ; msg_sched: 8-9
        ; rnd_0: 0 - 0
        ror	rax, 23
        vpalignr	xmm12, xmm5, xmm4, 8
        vpalignr	xmm13, xmm1, xmm0, 8
        ; rnd_0: 1 - 1
        mov	rdx, r8
        mov	rcx, r13
        add	r15, QWORD PTR [rsp+64]
        xor	rcx, r14
        vpsrlq	xmm8, xmm12, 1
        vpsllq	xmm9, xmm12, 63
        ; rnd_0: 2 - 3
        xor	rax, r12
        and	rcx, r12
        ror	rax, 4
        xor	rcx, r14
        vpsrlq	xmm10, xmm12, 8
        vpsllq	xmm11, xmm12, 56
        ; rnd_0: 4 - 5
        xor	rax, r12
        add	r15, rcx
        ror	rax, 14
        xor	rdx, r9
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_0: 6 - 7
        add	r15, rax
        mov	rcx, r8
        and	rbx, rdx
        ror	rcx, 5
        vpsrlq	xmm11, xmm12, 7
        vpxor	xmm8, xmm8, xmm10
        ; rnd_0: 8 - 9
        xor	rcx, r8
        xor	rbx, r9
        ror	rcx, 6
        add	r11, r15
        vpxor	xmm8, xmm8, xmm11
        vpaddq	xmm4, xmm13, xmm4
        ; rnd_0: 10 - 11
        xor	rcx, r8
        add	r15, rbx
        ror	rcx, 28
        mov	rax, r11
        add	r15, rcx
        ; rnd_1: 0 - 0
        ror	rax, 23
        vpaddq	xmm4, xmm8, xmm4
        ; rnd_1: 1 - 1
        mov	rbx, r15
        mov	rcx, r12
        add	r14, QWORD PTR [rsp+72]
        xor	rcx, r13
        vpsrlq	xmm8, xmm3, 19
        vpsllq	xmm9, xmm3, 45
        ; rnd_1: 2 - 3
        xor	rax, r11
        and	rcx, r11
        ror	rax, 4
        xor	rcx, r13
        vpsrlq	xmm10, xmm3, 61
        vpsllq	xmm11, xmm3, 3
        ; rnd_1: 4 - 6
        xor	rax, r11
        add	r14, rcx
        ror	rax, 14
        xor	rbx, r8
        add	r14, rax
        mov	rcx, r15
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_1: 7 - 8
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r15
        xor	rdx, r8
        vpxor	xmm8, xmm8, xmm10
        vpsrlq	xmm11, xmm3, 6
        ; rnd_1: 9 - 10
        ror	rcx, 6
        add	r10, r14
        xor	rcx, r15
        add	r14, rdx
        vpxor	xmm8, xmm8, xmm11
        ; rnd_1: 11 - 11
        ror	rcx, 28
        mov	rax, r10
        add	r14, rcx
        vpaddq	xmm4, xmm8, xmm4
        ; msg_sched done: 8-9
        ; msg_sched: 10-11
        ; rnd_0: 0 - 0
        ror	rax, 23
        vpalignr	xmm12, xmm6, xmm5, 8
        vpalignr	xmm13, xmm2, xmm1, 8
        ; rnd_0: 1 - 1
        mov	rdx, r14
        mov	rcx, r11
        add	r13, QWORD PTR [rsp+80]
        xor	rcx, r12
        vpsrlq	xmm8, xmm12, 1
        vpsllq	xmm9, xmm12, 63
        ; rnd_0: 2 - 3
        xor	rax, r10
        and	rcx, r10
        ror	rax, 4
        xor	rcx, r12
        vpsrlq	xmm10, xmm12, 8
        vpsllq	xmm11, xmm12, 56
        ; rnd_0: 4 - 5
        xor	rax, r10
        add	r13, rcx
        ror	rax, 14
        xor	rdx, r15
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_0: 6 - 7
        add	r13, rax
        mov	rcx, r14
        and	rbx, rdx
        ror	rcx, 5
        vpsrlq	xmm11, xmm12, 7
        vpxor	xmm8, xmm8, xmm10
        ; rnd_0: 8 - 9
        xor	rcx, r14
        xor	rbx, r15
        ror	rcx, 6
        add	r9, r13
        vpxor	xmm8, xmm8, xmm11
        vpaddq	xmm5, xmm13, xmm5
        ; rnd_0: 10 - 11
        xor	rcx, r14
        add	r13, rbx
        ror	rcx, 28
        mov	rax, r9
        add	r13, rcx
        ; rnd_1: 0 - 0
        ror	rax, 23
        vpaddq	xmm5, xmm8, xmm5
        ; rnd_1: 1 - 1
        mov	rbx, r13
        mov	rcx, r10
        add	r12, QWORD PTR [rsp+88]
        xor	rcx, r11
        vpsrlq	xmm8, xmm4, 19
        vpsllq	xmm9, xmm4, 45
        ; rnd_1: 2 - 3
        xor	rax, r9
        and	rcx, r9
        ror	rax, 4
        xor	rcx, r11
        vpsrlq	xmm10, xmm4, 61
        vpsllq	xmm11, xmm4, 3
        ; rnd_1: 4 - 6
        xor	rax, r9
        add	r12, rcx
        ror	rax, 14
        xor	rbx, r14
        add	r12, rax
        mov	rcx, r13
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_1: 7 - 8
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r13
        xor	rdx, r14
        vpxor	xmm8, xmm8, xmm10
        vpsrlq	xmm11, xmm4, 6
        ; rnd_1: 9 - 10
        ror	rcx, 6
        add	r8, r12
        xor	rcx, r13
        add	r12, rdx
        vpxor	xmm8, xmm8, xmm11
        ; rnd_1: 11 - 11
        ror	rcx, 28
        mov	rax, r8
        add	r12, rcx
        vpaddq	xmm5, xmm8, xmm5
        ; msg_sched done: 10-11
        ; msg_sched: 12-13
        ; rnd_0: 0 - 0
        ror	rax, 23
        vpalignr	xmm12, xmm7, xmm6, 8
        vpalignr	xmm13, xmm3, xmm2, 8
        ; rnd_0: 1 - 1
        mov	rdx, r12
        mov	rcx, r9
        add	r11, QWORD PTR [rsp+96]
        xor	rcx, r10
        vpsrlq	xmm8, xmm12, 1
        vpsllq	xmm9, xmm12, 63
        ; rnd_0: 2 - 3
        xor	rax, r8
        and	rcx, r8
        ror	rax, 4
        xor	rcx, r10
        vpsrlq	xmm10, xmm12, 8
        vpsllq	xmm11, xmm12, 56
        ; rnd_0: 4 - 5
        xor	rax, r8
        add	r11, rcx
        ror	rax, 14
        xor	rdx, r13
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_0: 6 - 7
        add	r11, rax
        mov	rcx, r12
        and	rbx, rdx
        ror	rcx, 5
        vpsrlq	xmm11, xmm12, 7
        vpxor	xmm8, xmm8, xmm10
        ; rnd_0: 8 - 9
        xor	rcx, r12
        xor	rbx, r13
        ror	rcx, 6
        add	r15, r11
        vpxor	xmm8, xmm8, xmm11
        vpaddq	xmm6, xmm13, xmm6
        ; rnd_0: 10 - 11
        xor	rcx, r12
        add	r11, rbx
        ror	rcx, 28
        mov	rax, r15
        add	r11, rcx
        ; rnd_1: 0 - 0
        ror	rax, 23
        vpaddq	xmm6, xmm8, xmm6
        ; rnd_1: 1 - 1
        mov	rbx, r11
        mov	rcx, r8
        add	r10, QWORD PTR [rsp+104]
        xor	rcx, r9
        vpsrlq	xmm8, xmm5, 19
        vpsllq	xmm9, xmm5, 45
        ; rnd_1: 2 - 3
        xor	rax, r15
        and	rcx, r15
        ror	rax, 4
        xor	rcx, r9
        vpsrlq	xmm10, xmm5, 61
        vpsllq	xmm11, xmm5, 3
        ; rnd_1: 4 - 6
        xor	rax, r15
        add	r10, rcx
        ror	rax, 14
        xor	rbx, r12
        add	r10, rax
        mov	rcx, r11
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_1: 7 - 8
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r11
        xor	rdx, r12
        vpxor	xmm8, xmm8, xmm10
        vpsrlq	xmm11, xmm5, 6
        ; rnd_1: 9 - 10
        ror	rcx, 6
        add	r14, r10
        xor	rcx, r11
        add	r10, rdx
        vpxor	xmm8, xmm8, xmm11
        ; rnd_1: 11 - 11
        ror	rcx, 28
        mov	rax, r14
        add	r10, rcx
        vpaddq	xmm6, xmm8, xmm6
        ; msg_sched done: 12-13
        ; msg_sched: 14-15
        ; rnd_0: 0 - 0
        ror	rax, 23
        vpalignr	xmm12, xmm0, xmm7, 8
        vpalignr	xmm13, xmm4, xmm3, 8
        ; rnd_0: 1 - 1
        mov	rdx, r10
        mov	rcx, r15
        add	r9, QWORD PTR [rsp+112]
        xor	rcx, r8
        vpsrlq	xmm8, xmm12, 1
        vpsllq	xmm9, xmm12, 63
        ; rnd_0: 2 - 3
        xor	rax, r14
        and	rcx, r14
        ror	rax, 4
        xor	rcx, r8
        vpsrlq	xmm10, xmm12, 8
        vpsllq	xmm11, xmm12, 56
        ; rnd_0: 4 - 5
        xor	rax, r14
        add	r9, rcx
        ror	rax, 14
        xor	rdx, r11
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_0: 6 - 7
        add	r9, rax
        mov	rcx, r10
        and	rbx, rdx
        ror	rcx, 5
        vpsrlq	xmm11, xmm12, 7
        vpxor	xmm8, xmm8, xmm10
        ; rnd_0: 8 - 9
        xor	rcx, r10
        xor	rbx, r11
        ror	rcx, 6
        add	r13, r9
        vpxor	xmm8, xmm8, xmm11
        vpaddq	xmm7, xmm13, xmm7
        ; rnd_0: 10 - 11
        xor	rcx, r10
        add	r9, rbx
        ror	rcx, 28
        mov	rax, r13
        add	r9, rcx
        ; rnd_1: 0 - 0
        ror	rax, 23
        vpaddq	xmm7, xmm8, xmm7
        ; rnd_1: 1 - 1
        mov	rbx, r9
        mov	rcx, r14
        add	r8, QWORD PTR [rsp+120]
        xor	rcx, r15
        vpsrlq	xmm8, xmm6, 19
        vpsllq	xmm9, xmm6, 45
        ; rnd_1: 2 - 3
        xor	rax, r13
        and	rcx, r13
        ror	rax, 4
        xor	rcx, r15
        vpsrlq	xmm10, xmm6, 61
        vpsllq	xmm11, xmm6, 3
        ; rnd_1: 4 - 6
        xor	rax, r13
        add	r8, rcx
        ror	rax, 14
        xor	rbx, r10
        add	r8, rax
        mov	rcx, r9
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_1: 7 - 8
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r9
        xor	rdx, r10
        vpxor	xmm8, xmm8, xmm10
        vpsrlq	xmm11, xmm6, 6
        ; rnd_1: 9 - 10
        ror	rcx, 6
        add	r12, r8
        xor	rcx, r9
        add	r8, rdx
        vpxor	xmm8, xmm8, xmm11
        ; rnd_1: 11 - 11
        ror	rcx, 28
        mov	rax, r12
        add	r8, rcx
        vpaddq	xmm7, xmm8, xmm7
        ; msg_sched done: 14-15
        mov	rdx, QWORD PTR [rsp+136]
        vpaddq	xmm8, xmm0, [rdx]
        vpaddq	xmm9, xmm1, [rdx+16]
        vmovdqu	OWORD PTR [rsp], xmm8
        vmovdqu	OWORD PTR [rsp+16], xmm9
        vpaddq	xmm8, xmm2, [rdx+32]
        vpaddq	xmm9, xmm3, [rdx+48]
        vmovdqu	OWORD PTR [rsp+32], xmm8
        vmovdqu	OWORD PTR [rsp+48], xmm9
        vpaddq	xmm8, xmm4, [rdx+64]
        vpaddq	xmm9, xmm5, [rdx+80]
        vmovdqu	OWORD PTR [rsp+64], xmm8
        vmovdqu	OWORD PTR [rsp+80], xmm9
        vpaddq	xmm8, xmm6, [rdx+96]
        vpaddq	xmm9, xmm7, [rdx+112]
        vmovdqu	OWORD PTR [rsp+96], xmm8
        vmovdqu	OWORD PTR [rsp+112], xmm9
        sub	DWORD PTR [rsp+128], 1
        jne	L_sha512_len_avx1_start
        ; rnd_all_2: 0-1
        ; rnd_0: 0 - 11
        ror	rax, 23
        mov	rdx, r8
        mov	rcx, r13
        add	r15, QWORD PTR [rsp]
        xor	rcx, r14
        xor	rax, r12
        and	rcx, r12
        ror	rax, 4
        xor	rcx, r14
        xor	rax, r12
        add	r15, rcx
        ror	rax, 14
        xor	rdx, r9
        add	r15, rax
        mov	rcx, r8
        and	rbx, rdx
        ror	rcx, 5
        xor	rcx, r8
        xor	rbx, r9
        ror	rcx, 6
        add	r11, r15
        xor	rcx, r8
        add	r15, rbx
        ror	rcx, 28
        mov	rax, r11
        add	r15, rcx
        ; rnd_1: 0 - 11
        ror	rax, 23
        mov	rbx, r15
        mov	rcx, r12
        add	r14, QWORD PTR [rsp+8]
        xor	rcx, r13
        xor	rax, r11
        and	rcx, r11
        ror	rax, 4
        xor	rcx, r13
        xor	rax, r11
        add	r14, rcx
        ror	rax, 14
        xor	rbx, r8
        add	r14, rax
        mov	rcx, r15
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r15
        xor	rdx, r8
        ror	rcx, 6
        add	r10, r14
        xor	rcx, r15
        add	r14, rdx
        ror	rcx, 28
        mov	rax, r10
        add	r14, rcx
        ; rnd_all_2: 2-3
        ; rnd_0: 0 - 11
        ror	rax, 23
        mov	rdx, r14
        mov	rcx, r11
        add	r13, QWORD PTR [rsp+16]
        xor	rcx, r12
        xor	rax, r10
        and	rcx, r10
        ror	rax, 4
        xor	rcx, r12
        xor	rax, r10
        add	r13, rcx
        ror	rax, 14
        xor	rdx, r15
        add	r13, rax
        mov	rcx, r14
        and	rbx, rdx
        ror	rcx, 5
        xor	rcx, r14
        xor	rbx, r15
        ror	rcx, 6
        add	r9, r13
        xor	rcx, r14
        add	r13, rbx
        ror	rcx, 28
        mov	rax, r9
        add	r13, rcx
        ; rnd_1: 0 - 11
        ror	rax, 23
        mov	rbx, r13
        mov	rcx, r10
        add	r12, QWORD PTR [rsp+24]
        xor	rcx, r11
        xor	rax, r9
        and	rcx, r9
        ror	rax, 4
        xor	rcx, r11
        xor	rax, r9
        add	r12, rcx
        ror	rax, 14
        xor	rbx, r14
        add	r12, rax
        mov	rcx, r13
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r13
        xor	rdx, r14
        ror	rcx, 6
        add	r8, r12
        xor	rcx, r13
        add	r12, rdx
        ror	rcx, 28
        mov	rax, r8
        add	r12, rcx
        ; rnd_all_2: 4-5
        ; rnd_0: 0 - 11
        ror	rax, 23
        mov	rdx, r12
        mov	rcx, r9
        add	r11, QWORD PTR [rsp+32]
        xor	rcx, r10
        xor	rax, r8
        and	rcx, r8
        ror	rax, 4
        xor	rcx, r10
        xor	rax, r8
        add	r11, rcx
        ror	rax, 14
        xor	rdx, r13
        add	r11, rax
        mov	rcx, r12
        and	rbx, rdx
        ror	rcx, 5
        xor	rcx, r12
        xor	rbx, r13
        ror	rcx, 6
        add	r15, r11
        xor	rcx, r12
        add	r11, rbx
        ror	rcx, 28
        mov	rax, r15
        add	r11, rcx
        ; rnd_1: 0 - 11
        ror	rax, 23
        mov	rbx, r11
        mov	rcx, r8
        add	r10, QWORD PTR [rsp+40]
        xor	rcx, r9
        xor	rax, r15
        and	rcx, r15
        ror	rax, 4
        xor	rcx, r9
        xor	rax, r15
        add	r10, rcx
        ror	rax, 14
        xor	rbx, r12
        add	r10, rax
        mov	rcx, r11
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r11
        xor	rdx, r12
        ror	rcx, 6
        add	r14, r10
        xor	rcx, r11
        add	r10, rdx
        ror	rcx, 28
        mov	rax, r14
        add	r10, rcx
        ; rnd_all_2: 6-7
        ; rnd_0: 0 - 11
        ror	rax, 23
        mov	rdx, r10
        mov	rcx, r15
        add	r9, QWORD PTR [rsp+48]
        xor	rcx, r8
        xor	rax, r14
        and	rcx, r14
        ror	rax, 4
        xor	rcx, r8
        xor	rax, r14
        add	r9, rcx
        ror	rax, 14
        xor	rdx, r11
        add	r9, rax
        mov	rcx, r10
        and	rbx, rdx
        ror	rcx, 5
        xor	rcx, r10
        xor	rbx, r11
        ror	rcx, 6
        add	r13, r9
        xor	rcx, r10
        add	r9, rbx
        ror	rcx, 28
        mov	rax, r13
        add	r9, rcx
        ; rnd_1: 0 - 11
        ror	rax, 23
        mov	rbx, r9
        mov	rcx, r14
        add	r8, QWORD PTR [rsp+56]
        xor	rcx, r15
        xor	rax, r13
        and	rcx, r13
        ror	rax, 4
        xor	rcx, r15
        xor	rax, r13
        add	r8, rcx
        ror	rax, 14
        xor	rbx, r10
        add	r8, rax
        mov	rcx, r9
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r9
        xor	rdx, r10
        ror	rcx, 6
        add	r12, r8
        xor	rcx, r9
        add	r8, rdx
        ror	rcx, 28
        mov	rax, r12
        add	r8, rcx
        ; rnd_all_2: 8-9
        ; rnd_0: 0 - 11
        ror	rax, 23
        mov	rdx, r8
        mov	rcx, r13
        add	r15, QWORD PTR [rsp+64]
        xor	rcx, r14
        xor	rax, r12
        and	rcx, r12
        ror	rax, 4
        xor	rcx, r14
        xor	rax, r12
        add	r15, rcx
        ror	rax, 14
        xor	rdx, r9
        add	r15, rax
        mov	rcx, r8
        and	rbx, rdx
        ror	rcx, 5
        xor	rcx, r8
        xor	rbx, r9
        ror	rcx, 6
        add	r11, r15
        xor	rcx, r8
        add	r15, rbx
        ror	rcx, 28
        mov	rax, r11
        add	r15, rcx
        ; rnd_1: 0 - 11
        ror	rax, 23
        mov	rbx, r15
        mov	rcx, r12
        add	r14, QWORD PTR [rsp+72]
        xor	rcx, r13
        xor	rax, r11
        and	rcx, r11
        ror	rax, 4
        xor	rcx, r13
        xor	rax, r11
        add	r14, rcx
        ror	rax, 14
        xor	rbx, r8
        add	r14, rax
        mov	rcx, r15
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r15
        xor	rdx, r8
        ror	rcx, 6
        add	r10, r14
        xor	rcx, r15
        add	r14, rdx
        ror	rcx, 28
        mov	rax, r10
        add	r14, rcx
        ; rnd_all_2: 10-11
        ; rnd_0: 0 - 11
        ror	rax, 23
        mov	rdx, r14
        mov	rcx, r11
        add	r13, QWORD PTR [rsp+80]
        xor	rcx, r12
        xor	rax, r10
        and	rcx, r10
        ror	rax, 4
        xor	rcx, r12
        xor	rax, r10
        add	r13, rcx
        ror	rax, 14
        xor	rdx, r15
        add	r13, rax
        mov	rcx, r14
        and	rbx, rdx
        ror	rcx, 5
        xor	rcx, r14
        xor	rbx, r15
        ror	rcx, 6
        add	r9, r13
        xor	rcx, r14
        add	r13, rbx
        ror	rcx, 28
        mov	rax, r9
        add	r13, rcx
        ; rnd_1: 0 - 11
        ror	rax, 23
        mov	rbx, r13
        mov	rcx, r10
        add	r12, QWORD PTR [rsp+88]
        xor	rcx, r11
        xor	rax, r9
        and	rcx, r9
        ror	rax, 4
        xor	rcx, r11
        xor	rax, r9
        add	r12, rcx
        ror	rax, 14
        xor	rbx, r14
        add	r12, rax
        mov	rcx, r13
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r13
        xor	rdx, r14
        ror	rcx, 6
        add	r8, r12
        xor	rcx, r13
        add	r12, rdx
        ror	rcx, 28
        mov	rax, r8
        add	r12, rcx
        ; rnd_all_2: 12-13
        ; rnd_0: 0 - 11
        ror	rax, 23
        mov	rdx, r12
        mov	rcx, r9
        add	r11, QWORD PTR [rsp+96]
        xor	rcx, r10
        xor	rax, r8
        and	rcx, r8
        ror	rax, 4
        xor	rcx, r10
        xor	rax, r8
        add	r11, rcx
        ror	rax, 14
        xor	rdx, r13
        add	r11, rax
        mov	rcx, r12
        and	rbx, rdx
        ror	rcx, 5
        xor	rcx, r12
        xor	rbx, r13
        ror	rcx, 6
        add	r15, r11
        xor	rcx, r12
        add	r11, rbx
        ror	rcx, 28
        mov	rax, r15
        add	r11, rcx
        ; rnd_1: 0 - 11
        ror	rax, 23
        mov	rbx, r11
        mov	rcx, r8
        add	r10, QWORD PTR [rsp+104]
        xor	rcx, r9
        xor	rax, r15
        and	rcx, r15
        ror	rax, 4
        xor	rcx, r9
        xor	rax, r15
        add	r10, rcx
        ror	rax, 14
        xor	rbx, r12
        add	r10, rax
        mov	rcx, r11
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r11
        xor	rdx, r12
        ror	rcx, 6
        add	r14, r10
        xor	rcx, r11
        add	r10, rdx
        ror	rcx, 28
        mov	rax, r14
        add	r10, rcx
        ; rnd_all_2: 14-15
        ; rnd_0: 0 - 11
        ror	rax, 23
        mov	rdx, r10
        mov	rcx, r15
        add	r9, QWORD PTR [rsp+112]
        xor	rcx, r8
        xor	rax, r14
        and	rcx, r14
        ror	rax, 4
        xor	rcx, r8
        xor	rax, r14
        add	r9, rcx
        ror	rax, 14
        xor	rdx, r11
        add	r9, rax
        mov	rcx, r10
        and	rbx, rdx
        ror	rcx, 5
        xor	rcx, r10
        xor	rbx, r11
        ror	rcx, 6
        add	r13, r9
        xor	rcx, r10
        add	r9, rbx
        ror	rcx, 28
        mov	rax, r13
        add	r9, rcx
        ; rnd_1: 0 - 11
        ror	rax, 23
        mov	rbx, r9
        mov	rcx, r14
        add	r8, QWORD PTR [rsp+120]
        xor	rcx, r15
        xor	rax, r13
        and	rcx, r13
        ror	rax, 4
        xor	rcx, r15
        xor	rax, r13
        add	r8, rcx
        ror	rax, 14
        xor	rbx, r10
        add	r8, rax
        mov	rcx, r9
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r9
        xor	rdx, r10
        ror	rcx, 6
        add	r12, r8
        xor	rcx, r9
        add	r8, rdx
        ror	rcx, 28
        mov	rax, r12
        add	r8, rcx
        add	r8, QWORD PTR [rdi]
        add	r9, QWORD PTR [rdi+8]
        add	r10, QWORD PTR [rdi+16]
        add	r11, QWORD PTR [rdi+24]
        add	r12, QWORD PTR [rdi+32]
        add	r13, QWORD PTR [rdi+40]
        add	r14, QWORD PTR [rdi+48]
        add	r15, QWORD PTR [rdi+56]
        mov	rdx, QWORD PTR [ptr_L_avx1_sha512_k]
        add	rsi, 128
        sub	ebp, 128
        mov	QWORD PTR [rdi], r8
        mov	QWORD PTR [rdi+8], r9
        mov	QWORD PTR [rdi+16], r10
        mov	QWORD PTR [rdi+24], r11
        mov	QWORD PTR [rdi+32], r12
        mov	QWORD PTR [rdi+40], r13
        mov	QWORD PTR [rdi+48], r14
        mov	QWORD PTR [rdi+56], r15
        jnz	L_sha512_len_avx1_begin
        xor	rax, rax
        vmovdqu	xmm6, OWORD PTR [rsp+144]
        vmovdqu	xmm7, OWORD PTR [rsp+160]
        vmovdqu	xmm8, OWORD PTR [rsp+176]
        vmovdqu	xmm9, OWORD PTR [rsp+192]
        vmovdqu	xmm10, OWORD PTR [rsp+208]
        vmovdqu	xmm11, OWORD PTR [rsp+224]
        vmovdqu	xmm13, OWORD PTR [rsp+240]
        vmovdqu	xmm12, OWORD PTR [rsp+256]
        vmovdqu	xmm14, OWORD PTR [rsp+272]
        add	rsp, 288
        pop	rbp
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        pop	rbx
        ret
Transform_Sha512_AVX1_Len ENDP
_TEXT ENDS
_DATA SEGMENT
ALIGN 16
L_avx1_rorx_sha512_k QWORD 428a2f98d728ae22h, 7137449123ef65cdh
        QWORD 0b5c0fbcfec4d3b2fh, 0e9b5dba58189dbbch
        QWORD 3956c25bf348b538h, 59f111f1b605d019h
        QWORD 923f82a4af194f9bh, 0ab1c5ed5da6d8118h
        QWORD 0d807aa98a3030242h, 12835b0145706fbeh
        QWORD 243185be4ee4b28ch, 550c7dc3d5ffb4e2h
        QWORD 72be5d74f27b896fh, 80deb1fe3b1696b1h
        QWORD 9bdc06a725c71235h, 0c19bf174cf692694h
        QWORD 0e49b69c19ef14ad2h, 0efbe4786384f25e3h
        QWORD 0fc19dc68b8cd5b5h, 240ca1cc77ac9c65h
        QWORD 2de92c6f592b0275h, 4a7484aa6ea6e483h
        QWORD 5cb0a9dcbd41fbd4h, 76f988da831153b5h
        QWORD 983e5152ee66dfabh, 0a831c66d2db43210h
        QWORD 0b00327c898fb213fh, 0bf597fc7beef0ee4h
        QWORD 0c6e00bf33da88fc2h, 0d5a79147930aa725h
        QWORD 06ca6351e003826fh, 142929670a0e6e70h
        QWORD 27b70a8546d22ffch, 2e1b21385c26c926h
        QWORD 4d2c6dfc5ac42aedh, 53380d139d95b3dfh
        QWORD 650a73548baf63deh, 766a0abb3c77b2a8h
        QWORD 81c2c92e47edaee6h, 92722c851482353bh
        QWORD 0a2bfe8a14cf10364h, 0a81a664bbc423001h
        QWORD 0c24b8b70d0f89791h, 0c76c51a30654be30h
        QWORD 0d192e819d6ef5218h, 0d69906245565a910h
        QWORD 0f40e35855771202ah, 106aa07032bbd1b8h
        QWORD 19a4c116b8d2d0c8h, 1e376c085141ab53h
        QWORD 2748774cdf8eeb99h, 34b0bcb5e19b48a8h
        QWORD 391c0cb3c5c95a63h, 4ed8aa4ae3418acbh
        QWORD 5b9cca4f7763e373h, 682e6ff3d6b2b8a3h
        QWORD 748f82ee5defb2fch, 78a5636f43172f60h
        QWORD 84c87814a1f0ab72h, 8cc702081a6439ech
        QWORD 90befffa23631e28h, 0a4506cebde82bde9h
        QWORD 0bef9a3f7b2c67915h, 0c67178f2e372532bh
        QWORD 0ca273eceea26619ch, 0d186b8c721c0c207h
        QWORD 0eada7dd6cde0eb1eh, 0f57d4f7fee6ed178h
        QWORD 06f067aa72176fbah, 0a637dc5a2c898a6h
        QWORD 113f9804bef90daeh, 1b710b35131c471bh
        QWORD 28db77f523047d84h, 32caab7b40c72493h
        QWORD 3c9ebe0a15c9bebch, 431d67c49c100d4ch
        QWORD 4cc5d4becb3e42b6h, 597f299cfc657e2ah
        QWORD 5fcb6fab3ad6faech, 6c44198c4a475817h
ptr_L_avx1_rorx_sha512_k QWORD L_avx1_rorx_sha512_k
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_avx1_rorx_sha512_flip_mask QWORD 0001020304050607h, 08090a0b0c0d0e0fh
ptr_L_avx1_rorx_sha512_flip_mask QWORD L_avx1_rorx_sha512_flip_mask
_DATA ENDS
_TEXT SEGMENT READONLY PARA
Transform_Sha512_AVX1_RORX PROC
        push	rbx
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        mov	rdi, rcx
        sub	rsp, 280
        vmovdqu	OWORD PTR [rsp+136], xmm6
        vmovdqu	OWORD PTR [rsp+152], xmm7
        vmovdqu	OWORD PTR [rsp+168], xmm8
        vmovdqu	OWORD PTR [rsp+184], xmm9
        vmovdqu	OWORD PTR [rsp+200], xmm10
        vmovdqu	OWORD PTR [rsp+216], xmm11
        vmovdqu	OWORD PTR [rsp+232], xmm13
        vmovdqu	OWORD PTR [rsp+248], xmm12
        vmovdqu	OWORD PTR [rsp+264], xmm14
        lea	rax, QWORD PTR [rdi+64]
        vmovdqa	xmm14, OWORD PTR L_avx1_rorx_sha512_flip_mask
        mov	r8, QWORD PTR [rdi]
        mov	r9, QWORD PTR [rdi+8]
        mov	r10, QWORD PTR [rdi+16]
        mov	r11, QWORD PTR [rdi+24]
        mov	r12, QWORD PTR [rdi+32]
        mov	r13, QWORD PTR [rdi+40]
        mov	r14, QWORD PTR [rdi+48]
        mov	r15, QWORD PTR [rdi+56]
        vmovdqu	xmm0, OWORD PTR [rax]
        vmovdqu	xmm1, OWORD PTR [rax+16]
        vpshufb	xmm0, xmm0, xmm14
        vpshufb	xmm1, xmm1, xmm14
        vmovdqu	xmm2, OWORD PTR [rax+32]
        vmovdqu	xmm3, OWORD PTR [rax+48]
        vpshufb	xmm2, xmm2, xmm14
        vpshufb	xmm3, xmm3, xmm14
        vmovdqu	xmm4, OWORD PTR [rax+64]
        vmovdqu	xmm5, OWORD PTR [rax+80]
        vpshufb	xmm4, xmm4, xmm14
        vpshufb	xmm5, xmm5, xmm14
        vmovdqu	xmm6, OWORD PTR [rax+96]
        vmovdqu	xmm7, OWORD PTR [rax+112]
        vpshufb	xmm6, xmm6, xmm14
        vpshufb	xmm7, xmm7, xmm14
        mov	DWORD PTR [rsp+128], 4
        mov	rsi, QWORD PTR [ptr_L_avx1_rorx_sha512_k]
        mov	rbx, r9
        xor	rdx, rdx
        xor	rbx, r10
        vpaddq	xmm8, xmm0, [rsi]
        vpaddq	xmm9, xmm1, [rsi+16]
        vmovdqu	OWORD PTR [rsp], xmm8
        vmovdqu	OWORD PTR [rsp+16], xmm9
        vpaddq	xmm8, xmm2, [rsi+32]
        vpaddq	xmm9, xmm3, [rsi+48]
        vmovdqu	OWORD PTR [rsp+32], xmm8
        vmovdqu	OWORD PTR [rsp+48], xmm9
        vpaddq	xmm8, xmm4, [rsi+64]
        vpaddq	xmm9, xmm5, [rsi+80]
        vmovdqu	OWORD PTR [rsp+64], xmm8
        vmovdqu	OWORD PTR [rsp+80], xmm9
        vpaddq	xmm8, xmm6, [rsi+96]
        vpaddq	xmm9, xmm7, [rsi+112]
        vmovdqu	OWORD PTR [rsp+96], xmm8
        vmovdqu	OWORD PTR [rsp+112], xmm9
        ; Start of 16 rounds
L_transform_sha512_avx1_rorx_start:
        add	rsi, 128
        ; msg_sched: 0-1
        ; rnd_0: 0 - 0
        rorx	rax, r12, 14
        rorx	rcx, r12, 18
        add	r8, rdx
        vpalignr	xmm12, xmm1, xmm0, 8
        vpalignr	xmm13, xmm5, xmm4, 8
        ; rnd_0: 1 - 1
        add	r15, QWORD PTR [rsp]
        mov	rdx, r13
        xor	rcx, rax
        vpsrlq	xmm8, xmm12, 1
        vpsllq	xmm9, xmm12, 63
        ; rnd_0: 2 - 2
        xor	rdx, r14
        rorx	rax, r12, 41
        xor	rax, rcx
        vpsrlq	xmm10, xmm12, 8
        vpsllq	xmm11, xmm12, 56
        ; rnd_0: 3 - 3
        and	rdx, r12
        add	r15, rax
        rorx	rax, r8, 28
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_0: 4 - 4
        rorx	rcx, r8, 34
        xor	rdx, r14
        xor	rcx, rax
        vpsrlq	xmm11, xmm12, 7
        vpxor	xmm8, xmm8, xmm10
        ; rnd_0: 5 - 5
        rorx	rax, r8, 39
        add	r15, rdx
        xor	rax, rcx
        vpxor	xmm8, xmm8, xmm11
        vpaddq	xmm0, xmm13, xmm0
        ; rnd_0: 6 - 7
        mov	rdx, r9
        add	r11, r15
        xor	rdx, r8
        and	rbx, rdx
        add	r15, rax
        xor	rbx, r9
        vpaddq	xmm0, xmm8, xmm0
        ; rnd_1: 0 - 0
        rorx	rax, r11, 14
        rorx	rcx, r11, 18
        add	r15, rbx
        vpsrlq	xmm8, xmm7, 19
        vpsllq	xmm9, xmm7, 45
        ; rnd_1: 1 - 1
        add	r14, QWORD PTR [rsp+8]
        mov	rbx, r12
        xor	rcx, rax
        vpsrlq	xmm10, xmm7, 61
        vpsllq	xmm11, xmm7, 3
        ; rnd_1: 2 - 2
        xor	rbx, r13
        rorx	rax, r11, 41
        xor	rax, rcx
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_1: 3 - 4
        and	rbx, r11
        add	r14, rax
        rorx	rax, r15, 28
        rorx	rcx, r15, 34
        xor	rbx, r13
        xor	rcx, rax
        vpxor	xmm8, xmm8, xmm10
        vpsrlq	xmm11, xmm7, 6
        ; rnd_1: 5 - 6
        rorx	rax, r15, 39
        add	r14, rbx
        xor	rax, rcx
        mov	rbx, r8
        add	r10, r14
        xor	rbx, r15
        vpxor	xmm8, xmm8, xmm11
        ; rnd_1: 7 - 7
        and	rdx, rbx
        add	r14, rax
        xor	rdx, r8
        vpaddq	xmm0, xmm8, xmm0
        ; msg_sched done: 0-1
        ; msg_sched: 2-3
        ; rnd_0: 0 - 0
        rorx	rax, r10, 14
        rorx	rcx, r10, 18
        add	r14, rdx
        vpalignr	xmm12, xmm2, xmm1, 8
        vpalignr	xmm13, xmm6, xmm5, 8
        ; rnd_0: 1 - 1
        add	r13, QWORD PTR [rsp+16]
        mov	rdx, r11
        xor	rcx, rax
        vpsrlq	xmm8, xmm12, 1
        vpsllq	xmm9, xmm12, 63
        ; rnd_0: 2 - 2
        xor	rdx, r12
        rorx	rax, r10, 41
        xor	rax, rcx
        vpsrlq	xmm10, xmm12, 8
        vpsllq	xmm11, xmm12, 56
        ; rnd_0: 3 - 3
        and	rdx, r10
        add	r13, rax
        rorx	rax, r14, 28
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_0: 4 - 4
        rorx	rcx, r14, 34
        xor	rdx, r12
        xor	rcx, rax
        vpsrlq	xmm11, xmm12, 7
        vpxor	xmm8, xmm8, xmm10
        ; rnd_0: 5 - 5
        rorx	rax, r14, 39
        add	r13, rdx
        xor	rax, rcx
        vpxor	xmm8, xmm8, xmm11
        vpaddq	xmm1, xmm13, xmm1
        ; rnd_0: 6 - 7
        mov	rdx, r15
        add	r9, r13
        xor	rdx, r14
        and	rbx, rdx
        add	r13, rax
        xor	rbx, r15
        vpaddq	xmm1, xmm8, xmm1
        ; rnd_1: 0 - 0
        rorx	rax, r9, 14
        rorx	rcx, r9, 18
        add	r13, rbx
        vpsrlq	xmm8, xmm0, 19
        vpsllq	xmm9, xmm0, 45
        ; rnd_1: 1 - 1
        add	r12, QWORD PTR [rsp+24]
        mov	rbx, r10
        xor	rcx, rax
        vpsrlq	xmm10, xmm0, 61
        vpsllq	xmm11, xmm0, 3
        ; rnd_1: 2 - 2
        xor	rbx, r11
        rorx	rax, r9, 41
        xor	rax, rcx
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_1: 3 - 4
        and	rbx, r9
        add	r12, rax
        rorx	rax, r13, 28
        rorx	rcx, r13, 34
        xor	rbx, r11
        xor	rcx, rax
        vpxor	xmm8, xmm8, xmm10
        vpsrlq	xmm11, xmm0, 6
        ; rnd_1: 5 - 6
        rorx	rax, r13, 39
        add	r12, rbx
        xor	rax, rcx
        mov	rbx, r14
        add	r8, r12
        xor	rbx, r13
        vpxor	xmm8, xmm8, xmm11
        ; rnd_1: 7 - 7
        and	rdx, rbx
        add	r12, rax
        xor	rdx, r14
        vpaddq	xmm1, xmm8, xmm1
        ; msg_sched done: 2-3
        ; msg_sched: 4-5
        ; rnd_0: 0 - 0
        rorx	rax, r8, 14
        rorx	rcx, r8, 18
        add	r12, rdx
        vpalignr	xmm12, xmm3, xmm2, 8
        vpalignr	xmm13, xmm7, xmm6, 8
        ; rnd_0: 1 - 1
        add	r11, QWORD PTR [rsp+32]
        mov	rdx, r9
        xor	rcx, rax
        vpsrlq	xmm8, xmm12, 1
        vpsllq	xmm9, xmm12, 63
        ; rnd_0: 2 - 2
        xor	rdx, r10
        rorx	rax, r8, 41
        xor	rax, rcx
        vpsrlq	xmm10, xmm12, 8
        vpsllq	xmm11, xmm12, 56
        ; rnd_0: 3 - 3
        and	rdx, r8
        add	r11, rax
        rorx	rax, r12, 28
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_0: 4 - 4
        rorx	rcx, r12, 34
        xor	rdx, r10
        xor	rcx, rax
        vpsrlq	xmm11, xmm12, 7
        vpxor	xmm8, xmm8, xmm10
        ; rnd_0: 5 - 5
        rorx	rax, r12, 39
        add	r11, rdx
        xor	rax, rcx
        vpxor	xmm8, xmm8, xmm11
        vpaddq	xmm2, xmm13, xmm2
        ; rnd_0: 6 - 7
        mov	rdx, r13
        add	r15, r11
        xor	rdx, r12
        and	rbx, rdx
        add	r11, rax
        xor	rbx, r13
        vpaddq	xmm2, xmm8, xmm2
        ; rnd_1: 0 - 0
        rorx	rax, r15, 14
        rorx	rcx, r15, 18
        add	r11, rbx
        vpsrlq	xmm8, xmm1, 19
        vpsllq	xmm9, xmm1, 45
        ; rnd_1: 1 - 1
        add	r10, QWORD PTR [rsp+40]
        mov	rbx, r8
        xor	rcx, rax
        vpsrlq	xmm10, xmm1, 61
        vpsllq	xmm11, xmm1, 3
        ; rnd_1: 2 - 2
        xor	rbx, r9
        rorx	rax, r15, 41
        xor	rax, rcx
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_1: 3 - 4
        and	rbx, r15
        add	r10, rax
        rorx	rax, r11, 28
        rorx	rcx, r11, 34
        xor	rbx, r9
        xor	rcx, rax
        vpxor	xmm8, xmm8, xmm10
        vpsrlq	xmm11, xmm1, 6
        ; rnd_1: 5 - 6
        rorx	rax, r11, 39
        add	r10, rbx
        xor	rax, rcx
        mov	rbx, r12
        add	r14, r10
        xor	rbx, r11
        vpxor	xmm8, xmm8, xmm11
        ; rnd_1: 7 - 7
        and	rdx, rbx
        add	r10, rax
        xor	rdx, r12
        vpaddq	xmm2, xmm8, xmm2
        ; msg_sched done: 4-5
        ; msg_sched: 6-7
        ; rnd_0: 0 - 0
        rorx	rax, r14, 14
        rorx	rcx, r14, 18
        add	r10, rdx
        vpalignr	xmm12, xmm4, xmm3, 8
        vpalignr	xmm13, xmm0, xmm7, 8
        ; rnd_0: 1 - 1
        add	r9, QWORD PTR [rsp+48]
        mov	rdx, r15
        xor	rcx, rax
        vpsrlq	xmm8, xmm12, 1
        vpsllq	xmm9, xmm12, 63
        ; rnd_0: 2 - 2
        xor	rdx, r8
        rorx	rax, r14, 41
        xor	rax, rcx
        vpsrlq	xmm10, xmm12, 8
        vpsllq	xmm11, xmm12, 56
        ; rnd_0: 3 - 3
        and	rdx, r14
        add	r9, rax
        rorx	rax, r10, 28
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_0: 4 - 4
        rorx	rcx, r10, 34
        xor	rdx, r8
        xor	rcx, rax
        vpsrlq	xmm11, xmm12, 7
        vpxor	xmm8, xmm8, xmm10
        ; rnd_0: 5 - 5
        rorx	rax, r10, 39
        add	r9, rdx
        xor	rax, rcx
        vpxor	xmm8, xmm8, xmm11
        vpaddq	xmm3, xmm13, xmm3
        ; rnd_0: 6 - 7
        mov	rdx, r11
        add	r13, r9
        xor	rdx, r10
        and	rbx, rdx
        add	r9, rax
        xor	rbx, r11
        vpaddq	xmm3, xmm8, xmm3
        ; rnd_1: 0 - 0
        rorx	rax, r13, 14
        rorx	rcx, r13, 18
        add	r9, rbx
        vpsrlq	xmm8, xmm2, 19
        vpsllq	xmm9, xmm2, 45
        ; rnd_1: 1 - 1
        add	r8, QWORD PTR [rsp+56]
        mov	rbx, r14
        xor	rcx, rax
        vpsrlq	xmm10, xmm2, 61
        vpsllq	xmm11, xmm2, 3
        ; rnd_1: 2 - 2
        xor	rbx, r15
        rorx	rax, r13, 41
        xor	rax, rcx
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_1: 3 - 4
        and	rbx, r13
        add	r8, rax
        rorx	rax, r9, 28
        rorx	rcx, r9, 34
        xor	rbx, r15
        xor	rcx, rax
        vpxor	xmm8, xmm8, xmm10
        vpsrlq	xmm11, xmm2, 6
        ; rnd_1: 5 - 6
        rorx	rax, r9, 39
        add	r8, rbx
        xor	rax, rcx
        mov	rbx, r10
        add	r12, r8
        xor	rbx, r9
        vpxor	xmm8, xmm8, xmm11
        ; rnd_1: 7 - 7
        and	rdx, rbx
        add	r8, rax
        xor	rdx, r10
        vpaddq	xmm3, xmm8, xmm3
        ; msg_sched done: 6-7
        ; msg_sched: 8-9
        ; rnd_0: 0 - 0
        rorx	rax, r12, 14
        rorx	rcx, r12, 18
        add	r8, rdx
        vpalignr	xmm12, xmm5, xmm4, 8
        vpalignr	xmm13, xmm1, xmm0, 8
        ; rnd_0: 1 - 1
        add	r15, QWORD PTR [rsp+64]
        mov	rdx, r13
        xor	rcx, rax
        vpsrlq	xmm8, xmm12, 1
        vpsllq	xmm9, xmm12, 63
        ; rnd_0: 2 - 2
        xor	rdx, r14
        rorx	rax, r12, 41
        xor	rax, rcx
        vpsrlq	xmm10, xmm12, 8
        vpsllq	xmm11, xmm12, 56
        ; rnd_0: 3 - 3
        and	rdx, r12
        add	r15, rax
        rorx	rax, r8, 28
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_0: 4 - 4
        rorx	rcx, r8, 34
        xor	rdx, r14
        xor	rcx, rax
        vpsrlq	xmm11, xmm12, 7
        vpxor	xmm8, xmm8, xmm10
        ; rnd_0: 5 - 5
        rorx	rax, r8, 39
        add	r15, rdx
        xor	rax, rcx
        vpxor	xmm8, xmm8, xmm11
        vpaddq	xmm4, xmm13, xmm4
        ; rnd_0: 6 - 7
        mov	rdx, r9
        add	r11, r15
        xor	rdx, r8
        and	rbx, rdx
        add	r15, rax
        xor	rbx, r9
        vpaddq	xmm4, xmm8, xmm4
        ; rnd_1: 0 - 0
        rorx	rax, r11, 14
        rorx	rcx, r11, 18
        add	r15, rbx
        vpsrlq	xmm8, xmm3, 19
        vpsllq	xmm9, xmm3, 45
        ; rnd_1: 1 - 1
        add	r14, QWORD PTR [rsp+72]
        mov	rbx, r12
        xor	rcx, rax
        vpsrlq	xmm10, xmm3, 61
        vpsllq	xmm11, xmm3, 3
        ; rnd_1: 2 - 2
        xor	rbx, r13
        rorx	rax, r11, 41
        xor	rax, rcx
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_1: 3 - 4
        and	rbx, r11
        add	r14, rax
        rorx	rax, r15, 28
        rorx	rcx, r15, 34
        xor	rbx, r13
        xor	rcx, rax
        vpxor	xmm8, xmm8, xmm10
        vpsrlq	xmm11, xmm3, 6
        ; rnd_1: 5 - 6
        rorx	rax, r15, 39
        add	r14, rbx
        xor	rax, rcx
        mov	rbx, r8
        add	r10, r14
        xor	rbx, r15
        vpxor	xmm8, xmm8, xmm11
        ; rnd_1: 7 - 7
        and	rdx, rbx
        add	r14, rax
        xor	rdx, r8
        vpaddq	xmm4, xmm8, xmm4
        ; msg_sched done: 8-9
        ; msg_sched: 10-11
        ; rnd_0: 0 - 0
        rorx	rax, r10, 14
        rorx	rcx, r10, 18
        add	r14, rdx
        vpalignr	xmm12, xmm6, xmm5, 8
        vpalignr	xmm13, xmm2, xmm1, 8
        ; rnd_0: 1 - 1
        add	r13, QWORD PTR [rsp+80]
        mov	rdx, r11
        xor	rcx, rax
        vpsrlq	xmm8, xmm12, 1
        vpsllq	xmm9, xmm12, 63
        ; rnd_0: 2 - 2
        xor	rdx, r12
        rorx	rax, r10, 41
        xor	rax, rcx
        vpsrlq	xmm10, xmm12, 8
        vpsllq	xmm11, xmm12, 56
        ; rnd_0: 3 - 3
        and	rdx, r10
        add	r13, rax
        rorx	rax, r14, 28
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_0: 4 - 4
        rorx	rcx, r14, 34
        xor	rdx, r12
        xor	rcx, rax
        vpsrlq	xmm11, xmm12, 7
        vpxor	xmm8, xmm8, xmm10
        ; rnd_0: 5 - 5
        rorx	rax, r14, 39
        add	r13, rdx
        xor	rax, rcx
        vpxor	xmm8, xmm8, xmm11
        vpaddq	xmm5, xmm13, xmm5
        ; rnd_0: 6 - 7
        mov	rdx, r15
        add	r9, r13
        xor	rdx, r14
        and	rbx, rdx
        add	r13, rax
        xor	rbx, r15
        vpaddq	xmm5, xmm8, xmm5
        ; rnd_1: 0 - 0
        rorx	rax, r9, 14
        rorx	rcx, r9, 18
        add	r13, rbx
        vpsrlq	xmm8, xmm4, 19
        vpsllq	xmm9, xmm4, 45
        ; rnd_1: 1 - 1
        add	r12, QWORD PTR [rsp+88]
        mov	rbx, r10
        xor	rcx, rax
        vpsrlq	xmm10, xmm4, 61
        vpsllq	xmm11, xmm4, 3
        ; rnd_1: 2 - 2
        xor	rbx, r11
        rorx	rax, r9, 41
        xor	rax, rcx
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_1: 3 - 4
        and	rbx, r9
        add	r12, rax
        rorx	rax, r13, 28
        rorx	rcx, r13, 34
        xor	rbx, r11
        xor	rcx, rax
        vpxor	xmm8, xmm8, xmm10
        vpsrlq	xmm11, xmm4, 6
        ; rnd_1: 5 - 6
        rorx	rax, r13, 39
        add	r12, rbx
        xor	rax, rcx
        mov	rbx, r14
        add	r8, r12
        xor	rbx, r13
        vpxor	xmm8, xmm8, xmm11
        ; rnd_1: 7 - 7
        and	rdx, rbx
        add	r12, rax
        xor	rdx, r14
        vpaddq	xmm5, xmm8, xmm5
        ; msg_sched done: 10-11
        ; msg_sched: 12-13
        ; rnd_0: 0 - 0
        rorx	rax, r8, 14
        rorx	rcx, r8, 18
        add	r12, rdx
        vpalignr	xmm12, xmm7, xmm6, 8
        vpalignr	xmm13, xmm3, xmm2, 8
        ; rnd_0: 1 - 1
        add	r11, QWORD PTR [rsp+96]
        mov	rdx, r9
        xor	rcx, rax
        vpsrlq	xmm8, xmm12, 1
        vpsllq	xmm9, xmm12, 63
        ; rnd_0: 2 - 2
        xor	rdx, r10
        rorx	rax, r8, 41
        xor	rax, rcx
        vpsrlq	xmm10, xmm12, 8
        vpsllq	xmm11, xmm12, 56
        ; rnd_0: 3 - 3
        and	rdx, r8
        add	r11, rax
        rorx	rax, r12, 28
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_0: 4 - 4
        rorx	rcx, r12, 34
        xor	rdx, r10
        xor	rcx, rax
        vpsrlq	xmm11, xmm12, 7
        vpxor	xmm8, xmm8, xmm10
        ; rnd_0: 5 - 5
        rorx	rax, r12, 39
        add	r11, rdx
        xor	rax, rcx
        vpxor	xmm8, xmm8, xmm11
        vpaddq	xmm6, xmm13, xmm6
        ; rnd_0: 6 - 7
        mov	rdx, r13
        add	r15, r11
        xor	rdx, r12
        and	rbx, rdx
        add	r11, rax
        xor	rbx, r13
        vpaddq	xmm6, xmm8, xmm6
        ; rnd_1: 0 - 0
        rorx	rax, r15, 14
        rorx	rcx, r15, 18
        add	r11, rbx
        vpsrlq	xmm8, xmm5, 19
        vpsllq	xmm9, xmm5, 45
        ; rnd_1: 1 - 1
        add	r10, QWORD PTR [rsp+104]
        mov	rbx, r8
        xor	rcx, rax
        vpsrlq	xmm10, xmm5, 61
        vpsllq	xmm11, xmm5, 3
        ; rnd_1: 2 - 2
        xor	rbx, r9
        rorx	rax, r15, 41
        xor	rax, rcx
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_1: 3 - 4
        and	rbx, r15
        add	r10, rax
        rorx	rax, r11, 28
        rorx	rcx, r11, 34
        xor	rbx, r9
        xor	rcx, rax
        vpxor	xmm8, xmm8, xmm10
        vpsrlq	xmm11, xmm5, 6
        ; rnd_1: 5 - 6
        rorx	rax, r11, 39
        add	r10, rbx
        xor	rax, rcx
        mov	rbx, r12
        add	r14, r10
        xor	rbx, r11
        vpxor	xmm8, xmm8, xmm11
        ; rnd_1: 7 - 7
        and	rdx, rbx
        add	r10, rax
        xor	rdx, r12
        vpaddq	xmm6, xmm8, xmm6
        ; msg_sched done: 12-13
        ; msg_sched: 14-15
        ; rnd_0: 0 - 0
        rorx	rax, r14, 14
        rorx	rcx, r14, 18
        add	r10, rdx
        vpalignr	xmm12, xmm0, xmm7, 8
        vpalignr	xmm13, xmm4, xmm3, 8
        ; rnd_0: 1 - 1
        add	r9, QWORD PTR [rsp+112]
        mov	rdx, r15
        xor	rcx, rax
        vpsrlq	xmm8, xmm12, 1
        vpsllq	xmm9, xmm12, 63
        ; rnd_0: 2 - 2
        xor	rdx, r8
        rorx	rax, r14, 41
        xor	rax, rcx
        vpsrlq	xmm10, xmm12, 8
        vpsllq	xmm11, xmm12, 56
        ; rnd_0: 3 - 3
        and	rdx, r14
        add	r9, rax
        rorx	rax, r10, 28
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_0: 4 - 4
        rorx	rcx, r10, 34
        xor	rdx, r8
        xor	rcx, rax
        vpsrlq	xmm11, xmm12, 7
        vpxor	xmm8, xmm8, xmm10
        ; rnd_0: 5 - 5
        rorx	rax, r10, 39
        add	r9, rdx
        xor	rax, rcx
        vpxor	xmm8, xmm8, xmm11
        vpaddq	xmm7, xmm13, xmm7
        ; rnd_0: 6 - 7
        mov	rdx, r11
        add	r13, r9
        xor	rdx, r10
        and	rbx, rdx
        add	r9, rax
        xor	rbx, r11
        vpaddq	xmm7, xmm8, xmm7
        ; rnd_1: 0 - 0
        rorx	rax, r13, 14
        rorx	rcx, r13, 18
        add	r9, rbx
        vpsrlq	xmm8, xmm6, 19
        vpsllq	xmm9, xmm6, 45
        ; rnd_1: 1 - 1
        add	r8, QWORD PTR [rsp+120]
        mov	rbx, r14
        xor	rcx, rax
        vpsrlq	xmm10, xmm6, 61
        vpsllq	xmm11, xmm6, 3
        ; rnd_1: 2 - 2
        xor	rbx, r15
        rorx	rax, r13, 41
        xor	rax, rcx
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_1: 3 - 4
        and	rbx, r13
        add	r8, rax
        rorx	rax, r9, 28
        rorx	rcx, r9, 34
        xor	rbx, r15
        xor	rcx, rax
        vpxor	xmm8, xmm8, xmm10
        vpsrlq	xmm11, xmm6, 6
        ; rnd_1: 5 - 6
        rorx	rax, r9, 39
        add	r8, rbx
        xor	rax, rcx
        mov	rbx, r10
        add	r12, r8
        xor	rbx, r9
        vpxor	xmm8, xmm8, xmm11
        ; rnd_1: 7 - 7
        and	rdx, rbx
        add	r8, rax
        xor	rdx, r10
        vpaddq	xmm7, xmm8, xmm7
        ; msg_sched done: 14-15
        vpaddq	xmm8, xmm0, [rsi]
        vpaddq	xmm9, xmm1, [rsi+16]
        vmovdqu	OWORD PTR [rsp], xmm8
        vmovdqu	OWORD PTR [rsp+16], xmm9
        vpaddq	xmm8, xmm2, [rsi+32]
        vpaddq	xmm9, xmm3, [rsi+48]
        vmovdqu	OWORD PTR [rsp+32], xmm8
        vmovdqu	OWORD PTR [rsp+48], xmm9
        vpaddq	xmm8, xmm4, [rsi+64]
        vpaddq	xmm9, xmm5, [rsi+80]
        vmovdqu	OWORD PTR [rsp+64], xmm8
        vmovdqu	OWORD PTR [rsp+80], xmm9
        vpaddq	xmm8, xmm6, [rsi+96]
        vpaddq	xmm9, xmm7, [rsi+112]
        vmovdqu	OWORD PTR [rsp+96], xmm8
        vmovdqu	OWORD PTR [rsp+112], xmm9
        sub	DWORD PTR [rsp+128], 1
        jne	L_transform_sha512_avx1_rorx_start
        ; rnd_all_2: 0-1
        ; rnd_0: 0 - 7
        rorx	rax, r12, 14
        rorx	rcx, r12, 18
        add	r8, rdx
        add	r15, QWORD PTR [rsp]
        mov	rdx, r13
        xor	rcx, rax
        xor	rdx, r14
        rorx	rax, r12, 41
        xor	rax, rcx
        and	rdx, r12
        add	r15, rax
        rorx	rax, r8, 28
        rorx	rcx, r8, 34
        xor	rdx, r14
        xor	rcx, rax
        rorx	rax, r8, 39
        add	r15, rdx
        xor	rax, rcx
        mov	rdx, r9
        add	r11, r15
        xor	rdx, r8
        and	rbx, rdx
        add	r15, rax
        xor	rbx, r9
        ; rnd_1: 0 - 7
        rorx	rax, r11, 14
        rorx	rcx, r11, 18
        add	r15, rbx
        add	r14, QWORD PTR [rsp+8]
        mov	rbx, r12
        xor	rcx, rax
        xor	rbx, r13
        rorx	rax, r11, 41
        xor	rax, rcx
        and	rbx, r11
        add	r14, rax
        rorx	rax, r15, 28
        rorx	rcx, r15, 34
        xor	rbx, r13
        xor	rcx, rax
        rorx	rax, r15, 39
        add	r14, rbx
        xor	rax, rcx
        mov	rbx, r8
        add	r10, r14
        xor	rbx, r15
        and	rdx, rbx
        add	r14, rax
        xor	rdx, r8
        ; rnd_all_2: 2-3
        ; rnd_0: 0 - 7
        rorx	rax, r10, 14
        rorx	rcx, r10, 18
        add	r14, rdx
        add	r13, QWORD PTR [rsp+16]
        mov	rdx, r11
        xor	rcx, rax
        xor	rdx, r12
        rorx	rax, r10, 41
        xor	rax, rcx
        and	rdx, r10
        add	r13, rax
        rorx	rax, r14, 28
        rorx	rcx, r14, 34
        xor	rdx, r12
        xor	rcx, rax
        rorx	rax, r14, 39
        add	r13, rdx
        xor	rax, rcx
        mov	rdx, r15
        add	r9, r13
        xor	rdx, r14
        and	rbx, rdx
        add	r13, rax
        xor	rbx, r15
        ; rnd_1: 0 - 7
        rorx	rax, r9, 14
        rorx	rcx, r9, 18
        add	r13, rbx
        add	r12, QWORD PTR [rsp+24]
        mov	rbx, r10
        xor	rcx, rax
        xor	rbx, r11
        rorx	rax, r9, 41
        xor	rax, rcx
        and	rbx, r9
        add	r12, rax
        rorx	rax, r13, 28
        rorx	rcx, r13, 34
        xor	rbx, r11
        xor	rcx, rax
        rorx	rax, r13, 39
        add	r12, rbx
        xor	rax, rcx
        mov	rbx, r14
        add	r8, r12
        xor	rbx, r13
        and	rdx, rbx
        add	r12, rax
        xor	rdx, r14
        ; rnd_all_2: 4-5
        ; rnd_0: 0 - 7
        rorx	rax, r8, 14
        rorx	rcx, r8, 18
        add	r12, rdx
        add	r11, QWORD PTR [rsp+32]
        mov	rdx, r9
        xor	rcx, rax
        xor	rdx, r10
        rorx	rax, r8, 41
        xor	rax, rcx
        and	rdx, r8
        add	r11, rax
        rorx	rax, r12, 28
        rorx	rcx, r12, 34
        xor	rdx, r10
        xor	rcx, rax
        rorx	rax, r12, 39
        add	r11, rdx
        xor	rax, rcx
        mov	rdx, r13
        add	r15, r11
        xor	rdx, r12
        and	rbx, rdx
        add	r11, rax
        xor	rbx, r13
        ; rnd_1: 0 - 7
        rorx	rax, r15, 14
        rorx	rcx, r15, 18
        add	r11, rbx
        add	r10, QWORD PTR [rsp+40]
        mov	rbx, r8
        xor	rcx, rax
        xor	rbx, r9
        rorx	rax, r15, 41
        xor	rax, rcx
        and	rbx, r15
        add	r10, rax
        rorx	rax, r11, 28
        rorx	rcx, r11, 34
        xor	rbx, r9
        xor	rcx, rax
        rorx	rax, r11, 39
        add	r10, rbx
        xor	rax, rcx
        mov	rbx, r12
        add	r14, r10
        xor	rbx, r11
        and	rdx, rbx
        add	r10, rax
        xor	rdx, r12
        ; rnd_all_2: 6-7
        ; rnd_0: 0 - 7
        rorx	rax, r14, 14
        rorx	rcx, r14, 18
        add	r10, rdx
        add	r9, QWORD PTR [rsp+48]
        mov	rdx, r15
        xor	rcx, rax
        xor	rdx, r8
        rorx	rax, r14, 41
        xor	rax, rcx
        and	rdx, r14
        add	r9, rax
        rorx	rax, r10, 28
        rorx	rcx, r10, 34
        xor	rdx, r8
        xor	rcx, rax
        rorx	rax, r10, 39
        add	r9, rdx
        xor	rax, rcx
        mov	rdx, r11
        add	r13, r9
        xor	rdx, r10
        and	rbx, rdx
        add	r9, rax
        xor	rbx, r11
        ; rnd_1: 0 - 7
        rorx	rax, r13, 14
        rorx	rcx, r13, 18
        add	r9, rbx
        add	r8, QWORD PTR [rsp+56]
        mov	rbx, r14
        xor	rcx, rax
        xor	rbx, r15
        rorx	rax, r13, 41
        xor	rax, rcx
        and	rbx, r13
        add	r8, rax
        rorx	rax, r9, 28
        rorx	rcx, r9, 34
        xor	rbx, r15
        xor	rcx, rax
        rorx	rax, r9, 39
        add	r8, rbx
        xor	rax, rcx
        mov	rbx, r10
        add	r12, r8
        xor	rbx, r9
        and	rdx, rbx
        add	r8, rax
        xor	rdx, r10
        ; rnd_all_2: 8-9
        ; rnd_0: 0 - 7
        rorx	rax, r12, 14
        rorx	rcx, r12, 18
        add	r8, rdx
        add	r15, QWORD PTR [rsp+64]
        mov	rdx, r13
        xor	rcx, rax
        xor	rdx, r14
        rorx	rax, r12, 41
        xor	rax, rcx
        and	rdx, r12
        add	r15, rax
        rorx	rax, r8, 28
        rorx	rcx, r8, 34
        xor	rdx, r14
        xor	rcx, rax
        rorx	rax, r8, 39
        add	r15, rdx
        xor	rax, rcx
        mov	rdx, r9
        add	r11, r15
        xor	rdx, r8
        and	rbx, rdx
        add	r15, rax
        xor	rbx, r9
        ; rnd_1: 0 - 7
        rorx	rax, r11, 14
        rorx	rcx, r11, 18
        add	r15, rbx
        add	r14, QWORD PTR [rsp+72]
        mov	rbx, r12
        xor	rcx, rax
        xor	rbx, r13
        rorx	rax, r11, 41
        xor	rax, rcx
        and	rbx, r11
        add	r14, rax
        rorx	rax, r15, 28
        rorx	rcx, r15, 34
        xor	rbx, r13
        xor	rcx, rax
        rorx	rax, r15, 39
        add	r14, rbx
        xor	rax, rcx
        mov	rbx, r8
        add	r10, r14
        xor	rbx, r15
        and	rdx, rbx
        add	r14, rax
        xor	rdx, r8
        ; rnd_all_2: 10-11
        ; rnd_0: 0 - 7
        rorx	rax, r10, 14
        rorx	rcx, r10, 18
        add	r14, rdx
        add	r13, QWORD PTR [rsp+80]
        mov	rdx, r11
        xor	rcx, rax
        xor	rdx, r12
        rorx	rax, r10, 41
        xor	rax, rcx
        and	rdx, r10
        add	r13, rax
        rorx	rax, r14, 28
        rorx	rcx, r14, 34
        xor	rdx, r12
        xor	rcx, rax
        rorx	rax, r14, 39
        add	r13, rdx
        xor	rax, rcx
        mov	rdx, r15
        add	r9, r13
        xor	rdx, r14
        and	rbx, rdx
        add	r13, rax
        xor	rbx, r15
        ; rnd_1: 0 - 7
        rorx	rax, r9, 14
        rorx	rcx, r9, 18
        add	r13, rbx
        add	r12, QWORD PTR [rsp+88]
        mov	rbx, r10
        xor	rcx, rax
        xor	rbx, r11
        rorx	rax, r9, 41
        xor	rax, rcx
        and	rbx, r9
        add	r12, rax
        rorx	rax, r13, 28
        rorx	rcx, r13, 34
        xor	rbx, r11
        xor	rcx, rax
        rorx	rax, r13, 39
        add	r12, rbx
        xor	rax, rcx
        mov	rbx, r14
        add	r8, r12
        xor	rbx, r13
        and	rdx, rbx
        add	r12, rax
        xor	rdx, r14
        ; rnd_all_2: 12-13
        ; rnd_0: 0 - 7
        rorx	rax, r8, 14
        rorx	rcx, r8, 18
        add	r12, rdx
        add	r11, QWORD PTR [rsp+96]
        mov	rdx, r9
        xor	rcx, rax
        xor	rdx, r10
        rorx	rax, r8, 41
        xor	rax, rcx
        and	rdx, r8
        add	r11, rax
        rorx	rax, r12, 28
        rorx	rcx, r12, 34
        xor	rdx, r10
        xor	rcx, rax
        rorx	rax, r12, 39
        add	r11, rdx
        xor	rax, rcx
        mov	rdx, r13
        add	r15, r11
        xor	rdx, r12
        and	rbx, rdx
        add	r11, rax
        xor	rbx, r13
        ; rnd_1: 0 - 7
        rorx	rax, r15, 14
        rorx	rcx, r15, 18
        add	r11, rbx
        add	r10, QWORD PTR [rsp+104]
        mov	rbx, r8
        xor	rcx, rax
        xor	rbx, r9
        rorx	rax, r15, 41
        xor	rax, rcx
        and	rbx, r15
        add	r10, rax
        rorx	rax, r11, 28
        rorx	rcx, r11, 34
        xor	rbx, r9
        xor	rcx, rax
        rorx	rax, r11, 39
        add	r10, rbx
        xor	rax, rcx
        mov	rbx, r12
        add	r14, r10
        xor	rbx, r11
        and	rdx, rbx
        add	r10, rax
        xor	rdx, r12
        ; rnd_all_2: 14-15
        ; rnd_0: 0 - 7
        rorx	rax, r14, 14
        rorx	rcx, r14, 18
        add	r10, rdx
        add	r9, QWORD PTR [rsp+112]
        mov	rdx, r15
        xor	rcx, rax
        xor	rdx, r8
        rorx	rax, r14, 41
        xor	rax, rcx
        and	rdx, r14
        add	r9, rax
        rorx	rax, r10, 28
        rorx	rcx, r10, 34
        xor	rdx, r8
        xor	rcx, rax
        rorx	rax, r10, 39
        add	r9, rdx
        xor	rax, rcx
        mov	rdx, r11
        add	r13, r9
        xor	rdx, r10
        and	rbx, rdx
        add	r9, rax
        xor	rbx, r11
        ; rnd_1: 0 - 7
        rorx	rax, r13, 14
        rorx	rcx, r13, 18
        add	r9, rbx
        add	r8, QWORD PTR [rsp+120]
        mov	rbx, r14
        xor	rcx, rax
        xor	rbx, r15
        rorx	rax, r13, 41
        xor	rax, rcx
        and	rbx, r13
        add	r8, rax
        rorx	rax, r9, 28
        rorx	rcx, r9, 34
        xor	rbx, r15
        xor	rcx, rax
        rorx	rax, r9, 39
        add	r8, rbx
        xor	rax, rcx
        mov	rbx, r10
        add	r12, r8
        xor	rbx, r9
        and	rdx, rbx
        add	r8, rax
        xor	rdx, r10
        add	r8, rdx
        add	QWORD PTR [rdi], r8
        add	QWORD PTR [rdi+8], r9
        add	QWORD PTR [rdi+16], r10
        add	QWORD PTR [rdi+24], r11
        add	QWORD PTR [rdi+32], r12
        add	QWORD PTR [rdi+40], r13
        add	QWORD PTR [rdi+48], r14
        add	QWORD PTR [rdi+56], r15
        xor	rax, rax
        vmovdqu	xmm6, OWORD PTR [rsp+136]
        vmovdqu	xmm7, OWORD PTR [rsp+152]
        vmovdqu	xmm8, OWORD PTR [rsp+168]
        vmovdqu	xmm9, OWORD PTR [rsp+184]
        vmovdqu	xmm10, OWORD PTR [rsp+200]
        vmovdqu	xmm11, OWORD PTR [rsp+216]
        vmovdqu	xmm13, OWORD PTR [rsp+232]
        vmovdqu	xmm12, OWORD PTR [rsp+248]
        vmovdqu	xmm14, OWORD PTR [rsp+264]
        add	rsp, 280
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        pop	rbx
        ret
Transform_Sha512_AVX1_RORX ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
Transform_Sha512_AVX1_RORX_Len PROC
        push	rbx
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbp
        mov	rdi, rcx
        mov	rbp, rdx
        sub	rsp, 288
        vmovdqu	OWORD PTR [rsp+144], xmm6
        vmovdqu	OWORD PTR [rsp+160], xmm7
        vmovdqu	OWORD PTR [rsp+176], xmm8
        vmovdqu	OWORD PTR [rsp+192], xmm9
        vmovdqu	OWORD PTR [rsp+208], xmm10
        vmovdqu	OWORD PTR [rsp+224], xmm11
        vmovdqu	OWORD PTR [rsp+240], xmm13
        vmovdqu	OWORD PTR [rsp+256], xmm12
        vmovdqu	OWORD PTR [rsp+272], xmm14
        mov	rsi, QWORD PTR [rdi+224]
        mov	rcx, QWORD PTR [ptr_L_avx1_rorx_sha512_k]
        vmovdqa	xmm14, OWORD PTR L_avx1_rorx_sha512_flip_mask
        mov	r8, QWORD PTR [rdi]
        mov	r9, QWORD PTR [rdi+8]
        mov	r10, QWORD PTR [rdi+16]
        mov	r11, QWORD PTR [rdi+24]
        mov	r12, QWORD PTR [rdi+32]
        mov	r13, QWORD PTR [rdi+40]
        mov	r14, QWORD PTR [rdi+48]
        mov	r15, QWORD PTR [rdi+56]
        ; Start of loop processing a block
L_sha512_len_avx1_rorx_begin:
        vmovdqu	xmm0, OWORD PTR [rsi]
        vmovdqu	xmm1, OWORD PTR [rsi+16]
        vpshufb	xmm0, xmm0, xmm14
        vpshufb	xmm1, xmm1, xmm14
        vmovdqu	xmm2, OWORD PTR [rsi+32]
        vmovdqu	xmm3, OWORD PTR [rsi+48]
        vpshufb	xmm2, xmm2, xmm14
        vpshufb	xmm3, xmm3, xmm14
        vmovdqu	xmm4, OWORD PTR [rsi+64]
        vmovdqu	xmm5, OWORD PTR [rsi+80]
        vpshufb	xmm4, xmm4, xmm14
        vpshufb	xmm5, xmm5, xmm14
        vmovdqu	xmm6, OWORD PTR [rsi+96]
        vmovdqu	xmm7, OWORD PTR [rsi+112]
        vpshufb	xmm6, xmm6, xmm14
        vpshufb	xmm7, xmm7, xmm14
        mov	DWORD PTR [rsp+128], 4
        mov	rbx, r9
        xor	rdx, rdx
        xor	rbx, r10
        vpaddq	xmm8, xmm0, [rcx]
        vpaddq	xmm9, xmm1, [rcx+16]
        vmovdqu	OWORD PTR [rsp], xmm8
        vmovdqu	OWORD PTR [rsp+16], xmm9
        vpaddq	xmm8, xmm2, [rcx+32]
        vpaddq	xmm9, xmm3, [rcx+48]
        vmovdqu	OWORD PTR [rsp+32], xmm8
        vmovdqu	OWORD PTR [rsp+48], xmm9
        vpaddq	xmm8, xmm4, [rcx+64]
        vpaddq	xmm9, xmm5, [rcx+80]
        vmovdqu	OWORD PTR [rsp+64], xmm8
        vmovdqu	OWORD PTR [rsp+80], xmm9
        vpaddq	xmm8, xmm6, [rcx+96]
        vpaddq	xmm9, xmm7, [rcx+112]
        vmovdqu	OWORD PTR [rsp+96], xmm8
        vmovdqu	OWORD PTR [rsp+112], xmm9
        ; Start of 16 rounds
L_sha512_len_avx1_rorx_start:
        add	rcx, 128
        mov	QWORD PTR [rsp+136], rcx
        ; msg_sched: 0-1
        ; rnd_0: 0 - 0
        rorx	rax, r12, 14
        rorx	rcx, r12, 18
        add	r8, rdx
        vpalignr	xmm12, xmm1, xmm0, 8
        vpalignr	xmm13, xmm5, xmm4, 8
        ; rnd_0: 1 - 1
        add	r15, QWORD PTR [rsp]
        mov	rdx, r13
        xor	rcx, rax
        vpsrlq	xmm8, xmm12, 1
        vpsllq	xmm9, xmm12, 63
        ; rnd_0: 2 - 2
        xor	rdx, r14
        rorx	rax, r12, 41
        xor	rax, rcx
        vpsrlq	xmm10, xmm12, 8
        vpsllq	xmm11, xmm12, 56
        ; rnd_0: 3 - 3
        and	rdx, r12
        add	r15, rax
        rorx	rax, r8, 28
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_0: 4 - 4
        rorx	rcx, r8, 34
        xor	rdx, r14
        xor	rcx, rax
        vpsrlq	xmm11, xmm12, 7
        vpxor	xmm8, xmm8, xmm10
        ; rnd_0: 5 - 5
        rorx	rax, r8, 39
        add	r15, rdx
        xor	rax, rcx
        vpxor	xmm8, xmm8, xmm11
        vpaddq	xmm0, xmm13, xmm0
        ; rnd_0: 6 - 7
        mov	rdx, r9
        add	r11, r15
        xor	rdx, r8
        and	rbx, rdx
        add	r15, rax
        xor	rbx, r9
        vpaddq	xmm0, xmm8, xmm0
        ; rnd_1: 0 - 0
        rorx	rax, r11, 14
        rorx	rcx, r11, 18
        add	r15, rbx
        vpsrlq	xmm8, xmm7, 19
        vpsllq	xmm9, xmm7, 45
        ; rnd_1: 1 - 1
        add	r14, QWORD PTR [rsp+8]
        mov	rbx, r12
        xor	rcx, rax
        vpsrlq	xmm10, xmm7, 61
        vpsllq	xmm11, xmm7, 3
        ; rnd_1: 2 - 2
        xor	rbx, r13
        rorx	rax, r11, 41
        xor	rax, rcx
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_1: 3 - 4
        and	rbx, r11
        add	r14, rax
        rorx	rax, r15, 28
        rorx	rcx, r15, 34
        xor	rbx, r13
        xor	rcx, rax
        vpxor	xmm8, xmm8, xmm10
        vpsrlq	xmm11, xmm7, 6
        ; rnd_1: 5 - 6
        rorx	rax, r15, 39
        add	r14, rbx
        xor	rax, rcx
        mov	rbx, r8
        add	r10, r14
        xor	rbx, r15
        vpxor	xmm8, xmm8, xmm11
        ; rnd_1: 7 - 7
        and	rdx, rbx
        add	r14, rax
        xor	rdx, r8
        vpaddq	xmm0, xmm8, xmm0
        ; msg_sched done: 0-1
        ; msg_sched: 2-3
        ; rnd_0: 0 - 0
        rorx	rax, r10, 14
        rorx	rcx, r10, 18
        add	r14, rdx
        vpalignr	xmm12, xmm2, xmm1, 8
        vpalignr	xmm13, xmm6, xmm5, 8
        ; rnd_0: 1 - 1
        add	r13, QWORD PTR [rsp+16]
        mov	rdx, r11
        xor	rcx, rax
        vpsrlq	xmm8, xmm12, 1
        vpsllq	xmm9, xmm12, 63
        ; rnd_0: 2 - 2
        xor	rdx, r12
        rorx	rax, r10, 41
        xor	rax, rcx
        vpsrlq	xmm10, xmm12, 8
        vpsllq	xmm11, xmm12, 56
        ; rnd_0: 3 - 3
        and	rdx, r10
        add	r13, rax
        rorx	rax, r14, 28
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_0: 4 - 4
        rorx	rcx, r14, 34
        xor	rdx, r12
        xor	rcx, rax
        vpsrlq	xmm11, xmm12, 7
        vpxor	xmm8, xmm8, xmm10
        ; rnd_0: 5 - 5
        rorx	rax, r14, 39
        add	r13, rdx
        xor	rax, rcx
        vpxor	xmm8, xmm8, xmm11
        vpaddq	xmm1, xmm13, xmm1
        ; rnd_0: 6 - 7
        mov	rdx, r15
        add	r9, r13
        xor	rdx, r14
        and	rbx, rdx
        add	r13, rax
        xor	rbx, r15
        vpaddq	xmm1, xmm8, xmm1
        ; rnd_1: 0 - 0
        rorx	rax, r9, 14
        rorx	rcx, r9, 18
        add	r13, rbx
        vpsrlq	xmm8, xmm0, 19
        vpsllq	xmm9, xmm0, 45
        ; rnd_1: 1 - 1
        add	r12, QWORD PTR [rsp+24]
        mov	rbx, r10
        xor	rcx, rax
        vpsrlq	xmm10, xmm0, 61
        vpsllq	xmm11, xmm0, 3
        ; rnd_1: 2 - 2
        xor	rbx, r11
        rorx	rax, r9, 41
        xor	rax, rcx
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_1: 3 - 4
        and	rbx, r9
        add	r12, rax
        rorx	rax, r13, 28
        rorx	rcx, r13, 34
        xor	rbx, r11
        xor	rcx, rax
        vpxor	xmm8, xmm8, xmm10
        vpsrlq	xmm11, xmm0, 6
        ; rnd_1: 5 - 6
        rorx	rax, r13, 39
        add	r12, rbx
        xor	rax, rcx
        mov	rbx, r14
        add	r8, r12
        xor	rbx, r13
        vpxor	xmm8, xmm8, xmm11
        ; rnd_1: 7 - 7
        and	rdx, rbx
        add	r12, rax
        xor	rdx, r14
        vpaddq	xmm1, xmm8, xmm1
        ; msg_sched done: 2-3
        ; msg_sched: 4-5
        ; rnd_0: 0 - 0
        rorx	rax, r8, 14
        rorx	rcx, r8, 18
        add	r12, rdx
        vpalignr	xmm12, xmm3, xmm2, 8
        vpalignr	xmm13, xmm7, xmm6, 8
        ; rnd_0: 1 - 1
        add	r11, QWORD PTR [rsp+32]
        mov	rdx, r9
        xor	rcx, rax
        vpsrlq	xmm8, xmm12, 1
        vpsllq	xmm9, xmm12, 63
        ; rnd_0: 2 - 2
        xor	rdx, r10
        rorx	rax, r8, 41
        xor	rax, rcx
        vpsrlq	xmm10, xmm12, 8
        vpsllq	xmm11, xmm12, 56
        ; rnd_0: 3 - 3
        and	rdx, r8
        add	r11, rax
        rorx	rax, r12, 28
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_0: 4 - 4
        rorx	rcx, r12, 34
        xor	rdx, r10
        xor	rcx, rax
        vpsrlq	xmm11, xmm12, 7
        vpxor	xmm8, xmm8, xmm10
        ; rnd_0: 5 - 5
        rorx	rax, r12, 39
        add	r11, rdx
        xor	rax, rcx
        vpxor	xmm8, xmm8, xmm11
        vpaddq	xmm2, xmm13, xmm2
        ; rnd_0: 6 - 7
        mov	rdx, r13
        add	r15, r11
        xor	rdx, r12
        and	rbx, rdx
        add	r11, rax
        xor	rbx, r13
        vpaddq	xmm2, xmm8, xmm2
        ; rnd_1: 0 - 0
        rorx	rax, r15, 14
        rorx	rcx, r15, 18
        add	r11, rbx
        vpsrlq	xmm8, xmm1, 19
        vpsllq	xmm9, xmm1, 45
        ; rnd_1: 1 - 1
        add	r10, QWORD PTR [rsp+40]
        mov	rbx, r8
        xor	rcx, rax
        vpsrlq	xmm10, xmm1, 61
        vpsllq	xmm11, xmm1, 3
        ; rnd_1: 2 - 2
        xor	rbx, r9
        rorx	rax, r15, 41
        xor	rax, rcx
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_1: 3 - 4
        and	rbx, r15
        add	r10, rax
        rorx	rax, r11, 28
        rorx	rcx, r11, 34
        xor	rbx, r9
        xor	rcx, rax
        vpxor	xmm8, xmm8, xmm10
        vpsrlq	xmm11, xmm1, 6
        ; rnd_1: 5 - 6
        rorx	rax, r11, 39
        add	r10, rbx
        xor	rax, rcx
        mov	rbx, r12
        add	r14, r10
        xor	rbx, r11
        vpxor	xmm8, xmm8, xmm11
        ; rnd_1: 7 - 7
        and	rdx, rbx
        add	r10, rax
        xor	rdx, r12
        vpaddq	xmm2, xmm8, xmm2
        ; msg_sched done: 4-5
        ; msg_sched: 6-7
        ; rnd_0: 0 - 0
        rorx	rax, r14, 14
        rorx	rcx, r14, 18
        add	r10, rdx
        vpalignr	xmm12, xmm4, xmm3, 8
        vpalignr	xmm13, xmm0, xmm7, 8
        ; rnd_0: 1 - 1
        add	r9, QWORD PTR [rsp+48]
        mov	rdx, r15
        xor	rcx, rax
        vpsrlq	xmm8, xmm12, 1
        vpsllq	xmm9, xmm12, 63
        ; rnd_0: 2 - 2
        xor	rdx, r8
        rorx	rax, r14, 41
        xor	rax, rcx
        vpsrlq	xmm10, xmm12, 8
        vpsllq	xmm11, xmm12, 56
        ; rnd_0: 3 - 3
        and	rdx, r14
        add	r9, rax
        rorx	rax, r10, 28
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_0: 4 - 4
        rorx	rcx, r10, 34
        xor	rdx, r8
        xor	rcx, rax
        vpsrlq	xmm11, xmm12, 7
        vpxor	xmm8, xmm8, xmm10
        ; rnd_0: 5 - 5
        rorx	rax, r10, 39
        add	r9, rdx
        xor	rax, rcx
        vpxor	xmm8, xmm8, xmm11
        vpaddq	xmm3, xmm13, xmm3
        ; rnd_0: 6 - 7
        mov	rdx, r11
        add	r13, r9
        xor	rdx, r10
        and	rbx, rdx
        add	r9, rax
        xor	rbx, r11
        vpaddq	xmm3, xmm8, xmm3
        ; rnd_1: 0 - 0
        rorx	rax, r13, 14
        rorx	rcx, r13, 18
        add	r9, rbx
        vpsrlq	xmm8, xmm2, 19
        vpsllq	xmm9, xmm2, 45
        ; rnd_1: 1 - 1
        add	r8, QWORD PTR [rsp+56]
        mov	rbx, r14
        xor	rcx, rax
        vpsrlq	xmm10, xmm2, 61
        vpsllq	xmm11, xmm2, 3
        ; rnd_1: 2 - 2
        xor	rbx, r15
        rorx	rax, r13, 41
        xor	rax, rcx
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_1: 3 - 4
        and	rbx, r13
        add	r8, rax
        rorx	rax, r9, 28
        rorx	rcx, r9, 34
        xor	rbx, r15
        xor	rcx, rax
        vpxor	xmm8, xmm8, xmm10
        vpsrlq	xmm11, xmm2, 6
        ; rnd_1: 5 - 6
        rorx	rax, r9, 39
        add	r8, rbx
        xor	rax, rcx
        mov	rbx, r10
        add	r12, r8
        xor	rbx, r9
        vpxor	xmm8, xmm8, xmm11
        ; rnd_1: 7 - 7
        and	rdx, rbx
        add	r8, rax
        xor	rdx, r10
        vpaddq	xmm3, xmm8, xmm3
        ; msg_sched done: 6-7
        ; msg_sched: 8-9
        ; rnd_0: 0 - 0
        rorx	rax, r12, 14
        rorx	rcx, r12, 18
        add	r8, rdx
        vpalignr	xmm12, xmm5, xmm4, 8
        vpalignr	xmm13, xmm1, xmm0, 8
        ; rnd_0: 1 - 1
        add	r15, QWORD PTR [rsp+64]
        mov	rdx, r13
        xor	rcx, rax
        vpsrlq	xmm8, xmm12, 1
        vpsllq	xmm9, xmm12, 63
        ; rnd_0: 2 - 2
        xor	rdx, r14
        rorx	rax, r12, 41
        xor	rax, rcx
        vpsrlq	xmm10, xmm12, 8
        vpsllq	xmm11, xmm12, 56
        ; rnd_0: 3 - 3
        and	rdx, r12
        add	r15, rax
        rorx	rax, r8, 28
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_0: 4 - 4
        rorx	rcx, r8, 34
        xor	rdx, r14
        xor	rcx, rax
        vpsrlq	xmm11, xmm12, 7
        vpxor	xmm8, xmm8, xmm10
        ; rnd_0: 5 - 5
        rorx	rax, r8, 39
        add	r15, rdx
        xor	rax, rcx
        vpxor	xmm8, xmm8, xmm11
        vpaddq	xmm4, xmm13, xmm4
        ; rnd_0: 6 - 7
        mov	rdx, r9
        add	r11, r15
        xor	rdx, r8
        and	rbx, rdx
        add	r15, rax
        xor	rbx, r9
        vpaddq	xmm4, xmm8, xmm4
        ; rnd_1: 0 - 0
        rorx	rax, r11, 14
        rorx	rcx, r11, 18
        add	r15, rbx
        vpsrlq	xmm8, xmm3, 19
        vpsllq	xmm9, xmm3, 45
        ; rnd_1: 1 - 1
        add	r14, QWORD PTR [rsp+72]
        mov	rbx, r12
        xor	rcx, rax
        vpsrlq	xmm10, xmm3, 61
        vpsllq	xmm11, xmm3, 3
        ; rnd_1: 2 - 2
        xor	rbx, r13
        rorx	rax, r11, 41
        xor	rax, rcx
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_1: 3 - 4
        and	rbx, r11
        add	r14, rax
        rorx	rax, r15, 28
        rorx	rcx, r15, 34
        xor	rbx, r13
        xor	rcx, rax
        vpxor	xmm8, xmm8, xmm10
        vpsrlq	xmm11, xmm3, 6
        ; rnd_1: 5 - 6
        rorx	rax, r15, 39
        add	r14, rbx
        xor	rax, rcx
        mov	rbx, r8
        add	r10, r14
        xor	rbx, r15
        vpxor	xmm8, xmm8, xmm11
        ; rnd_1: 7 - 7
        and	rdx, rbx
        add	r14, rax
        xor	rdx, r8
        vpaddq	xmm4, xmm8, xmm4
        ; msg_sched done: 8-9
        ; msg_sched: 10-11
        ; rnd_0: 0 - 0
        rorx	rax, r10, 14
        rorx	rcx, r10, 18
        add	r14, rdx
        vpalignr	xmm12, xmm6, xmm5, 8
        vpalignr	xmm13, xmm2, xmm1, 8
        ; rnd_0: 1 - 1
        add	r13, QWORD PTR [rsp+80]
        mov	rdx, r11
        xor	rcx, rax
        vpsrlq	xmm8, xmm12, 1
        vpsllq	xmm9, xmm12, 63
        ; rnd_0: 2 - 2
        xor	rdx, r12
        rorx	rax, r10, 41
        xor	rax, rcx
        vpsrlq	xmm10, xmm12, 8
        vpsllq	xmm11, xmm12, 56
        ; rnd_0: 3 - 3
        and	rdx, r10
        add	r13, rax
        rorx	rax, r14, 28
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_0: 4 - 4
        rorx	rcx, r14, 34
        xor	rdx, r12
        xor	rcx, rax
        vpsrlq	xmm11, xmm12, 7
        vpxor	xmm8, xmm8, xmm10
        ; rnd_0: 5 - 5
        rorx	rax, r14, 39
        add	r13, rdx
        xor	rax, rcx
        vpxor	xmm8, xmm8, xmm11
        vpaddq	xmm5, xmm13, xmm5
        ; rnd_0: 6 - 7
        mov	rdx, r15
        add	r9, r13
        xor	rdx, r14
        and	rbx, rdx
        add	r13, rax
        xor	rbx, r15
        vpaddq	xmm5, xmm8, xmm5
        ; rnd_1: 0 - 0
        rorx	rax, r9, 14
        rorx	rcx, r9, 18
        add	r13, rbx
        vpsrlq	xmm8, xmm4, 19
        vpsllq	xmm9, xmm4, 45
        ; rnd_1: 1 - 1
        add	r12, QWORD PTR [rsp+88]
        mov	rbx, r10
        xor	rcx, rax
        vpsrlq	xmm10, xmm4, 61
        vpsllq	xmm11, xmm4, 3
        ; rnd_1: 2 - 2
        xor	rbx, r11
        rorx	rax, r9, 41
        xor	rax, rcx
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_1: 3 - 4
        and	rbx, r9
        add	r12, rax
        rorx	rax, r13, 28
        rorx	rcx, r13, 34
        xor	rbx, r11
        xor	rcx, rax
        vpxor	xmm8, xmm8, xmm10
        vpsrlq	xmm11, xmm4, 6
        ; rnd_1: 5 - 6
        rorx	rax, r13, 39
        add	r12, rbx
        xor	rax, rcx
        mov	rbx, r14
        add	r8, r12
        xor	rbx, r13
        vpxor	xmm8, xmm8, xmm11
        ; rnd_1: 7 - 7
        and	rdx, rbx
        add	r12, rax
        xor	rdx, r14
        vpaddq	xmm5, xmm8, xmm5
        ; msg_sched done: 10-11
        ; msg_sched: 12-13
        ; rnd_0: 0 - 0
        rorx	rax, r8, 14
        rorx	rcx, r8, 18
        add	r12, rdx
        vpalignr	xmm12, xmm7, xmm6, 8
        vpalignr	xmm13, xmm3, xmm2, 8
        ; rnd_0: 1 - 1
        add	r11, QWORD PTR [rsp+96]
        mov	rdx, r9
        xor	rcx, rax
        vpsrlq	xmm8, xmm12, 1
        vpsllq	xmm9, xmm12, 63
        ; rnd_0: 2 - 2
        xor	rdx, r10
        rorx	rax, r8, 41
        xor	rax, rcx
        vpsrlq	xmm10, xmm12, 8
        vpsllq	xmm11, xmm12, 56
        ; rnd_0: 3 - 3
        and	rdx, r8
        add	r11, rax
        rorx	rax, r12, 28
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_0: 4 - 4
        rorx	rcx, r12, 34
        xor	rdx, r10
        xor	rcx, rax
        vpsrlq	xmm11, xmm12, 7
        vpxor	xmm8, xmm8, xmm10
        ; rnd_0: 5 - 5
        rorx	rax, r12, 39
        add	r11, rdx
        xor	rax, rcx
        vpxor	xmm8, xmm8, xmm11
        vpaddq	xmm6, xmm13, xmm6
        ; rnd_0: 6 - 7
        mov	rdx, r13
        add	r15, r11
        xor	rdx, r12
        and	rbx, rdx
        add	r11, rax
        xor	rbx, r13
        vpaddq	xmm6, xmm8, xmm6
        ; rnd_1: 0 - 0
        rorx	rax, r15, 14
        rorx	rcx, r15, 18
        add	r11, rbx
        vpsrlq	xmm8, xmm5, 19
        vpsllq	xmm9, xmm5, 45
        ; rnd_1: 1 - 1
        add	r10, QWORD PTR [rsp+104]
        mov	rbx, r8
        xor	rcx, rax
        vpsrlq	xmm10, xmm5, 61
        vpsllq	xmm11, xmm5, 3
        ; rnd_1: 2 - 2
        xor	rbx, r9
        rorx	rax, r15, 41
        xor	rax, rcx
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_1: 3 - 4
        and	rbx, r15
        add	r10, rax
        rorx	rax, r11, 28
        rorx	rcx, r11, 34
        xor	rbx, r9
        xor	rcx, rax
        vpxor	xmm8, xmm8, xmm10
        vpsrlq	xmm11, xmm5, 6
        ; rnd_1: 5 - 6
        rorx	rax, r11, 39
        add	r10, rbx
        xor	rax, rcx
        mov	rbx, r12
        add	r14, r10
        xor	rbx, r11
        vpxor	xmm8, xmm8, xmm11
        ; rnd_1: 7 - 7
        and	rdx, rbx
        add	r10, rax
        xor	rdx, r12
        vpaddq	xmm6, xmm8, xmm6
        ; msg_sched done: 12-13
        ; msg_sched: 14-15
        ; rnd_0: 0 - 0
        rorx	rax, r14, 14
        rorx	rcx, r14, 18
        add	r10, rdx
        vpalignr	xmm12, xmm0, xmm7, 8
        vpalignr	xmm13, xmm4, xmm3, 8
        ; rnd_0: 1 - 1
        add	r9, QWORD PTR [rsp+112]
        mov	rdx, r15
        xor	rcx, rax
        vpsrlq	xmm8, xmm12, 1
        vpsllq	xmm9, xmm12, 63
        ; rnd_0: 2 - 2
        xor	rdx, r8
        rorx	rax, r14, 41
        xor	rax, rcx
        vpsrlq	xmm10, xmm12, 8
        vpsllq	xmm11, xmm12, 56
        ; rnd_0: 3 - 3
        and	rdx, r14
        add	r9, rax
        rorx	rax, r10, 28
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_0: 4 - 4
        rorx	rcx, r10, 34
        xor	rdx, r8
        xor	rcx, rax
        vpsrlq	xmm11, xmm12, 7
        vpxor	xmm8, xmm8, xmm10
        ; rnd_0: 5 - 5
        rorx	rax, r10, 39
        add	r9, rdx
        xor	rax, rcx
        vpxor	xmm8, xmm8, xmm11
        vpaddq	xmm7, xmm13, xmm7
        ; rnd_0: 6 - 7
        mov	rdx, r11
        add	r13, r9
        xor	rdx, r10
        and	rbx, rdx
        add	r9, rax
        xor	rbx, r11
        vpaddq	xmm7, xmm8, xmm7
        ; rnd_1: 0 - 0
        rorx	rax, r13, 14
        rorx	rcx, r13, 18
        add	r9, rbx
        vpsrlq	xmm8, xmm6, 19
        vpsllq	xmm9, xmm6, 45
        ; rnd_1: 1 - 1
        add	r8, QWORD PTR [rsp+120]
        mov	rbx, r14
        xor	rcx, rax
        vpsrlq	xmm10, xmm6, 61
        vpsllq	xmm11, xmm6, 3
        ; rnd_1: 2 - 2
        xor	rbx, r15
        rorx	rax, r13, 41
        xor	rax, rcx
        vpor	xmm8, xmm8, xmm9
        vpor	xmm10, xmm10, xmm11
        ; rnd_1: 3 - 4
        and	rbx, r13
        add	r8, rax
        rorx	rax, r9, 28
        rorx	rcx, r9, 34
        xor	rbx, r15
        xor	rcx, rax
        vpxor	xmm8, xmm8, xmm10
        vpsrlq	xmm11, xmm6, 6
        ; rnd_1: 5 - 6
        rorx	rax, r9, 39
        add	r8, rbx
        xor	rax, rcx
        mov	rbx, r10
        add	r12, r8
        xor	rbx, r9
        vpxor	xmm8, xmm8, xmm11
        ; rnd_1: 7 - 7
        and	rdx, rbx
        add	r8, rax
        xor	rdx, r10
        vpaddq	xmm7, xmm8, xmm7
        ; msg_sched done: 14-15
        mov	rcx, QWORD PTR [rsp+136]
        vpaddq	xmm8, xmm0, [rcx]
        vpaddq	xmm9, xmm1, [rcx+16]
        vmovdqu	OWORD PTR [rsp], xmm8
        vmovdqu	OWORD PTR [rsp+16], xmm9
        vpaddq	xmm8, xmm2, [rcx+32]
        vpaddq	xmm9, xmm3, [rcx+48]
        vmovdqu	OWORD PTR [rsp+32], xmm8
        vmovdqu	OWORD PTR [rsp+48], xmm9
        vpaddq	xmm8, xmm4, [rcx+64]
        vpaddq	xmm9, xmm5, [rcx+80]
        vmovdqu	OWORD PTR [rsp+64], xmm8
        vmovdqu	OWORD PTR [rsp+80], xmm9
        vpaddq	xmm8, xmm6, [rcx+96]
        vpaddq	xmm9, xmm7, [rcx+112]
        vmovdqu	OWORD PTR [rsp+96], xmm8
        vmovdqu	OWORD PTR [rsp+112], xmm9
        sub	DWORD PTR [rsp+128], 1
        jne	L_sha512_len_avx1_rorx_start
        vpaddq	xmm8, xmm0, [rcx]
        vpaddq	xmm9, xmm1, [rcx+16]
        vmovdqu	OWORD PTR [rsp], xmm8
        vmovdqu	OWORD PTR [rsp+16], xmm9
        vpaddq	xmm8, xmm2, [rcx+32]
        vpaddq	xmm9, xmm3, [rcx+48]
        vmovdqu	OWORD PTR [rsp+32], xmm8
        vmovdqu	OWORD PTR [rsp+48], xmm9
        vpaddq	xmm8, xmm4, [rcx+64]
        vpaddq	xmm9, xmm5, [rcx+80]
        vmovdqu	OWORD PTR [rsp+64], xmm8
        vmovdqu	OWORD PTR [rsp+80], xmm9
        vpaddq	xmm8, xmm6, [rcx+96]
        vpaddq	xmm9, xmm7, [rcx+112]
        vmovdqu	OWORD PTR [rsp+96], xmm8
        vmovdqu	OWORD PTR [rsp+112], xmm9
        ; rnd_all_2: 0-1
        ; rnd_0: 0 - 7
        rorx	rax, r12, 14
        rorx	rcx, r12, 18
        add	r8, rdx
        add	r15, QWORD PTR [rsp]
        mov	rdx, r13
        xor	rcx, rax
        xor	rdx, r14
        rorx	rax, r12, 41
        xor	rax, rcx
        and	rdx, r12
        add	r15, rax
        rorx	rax, r8, 28
        rorx	rcx, r8, 34
        xor	rdx, r14
        xor	rcx, rax
        rorx	rax, r8, 39
        add	r15, rdx
        xor	rax, rcx
        mov	rdx, r9
        add	r11, r15
        xor	rdx, r8
        and	rbx, rdx
        add	r15, rax
        xor	rbx, r9
        ; rnd_1: 0 - 7
        rorx	rax, r11, 14
        rorx	rcx, r11, 18
        add	r15, rbx
        add	r14, QWORD PTR [rsp+8]
        mov	rbx, r12
        xor	rcx, rax
        xor	rbx, r13
        rorx	rax, r11, 41
        xor	rax, rcx
        and	rbx, r11
        add	r14, rax
        rorx	rax, r15, 28
        rorx	rcx, r15, 34
        xor	rbx, r13
        xor	rcx, rax
        rorx	rax, r15, 39
        add	r14, rbx
        xor	rax, rcx
        mov	rbx, r8
        add	r10, r14
        xor	rbx, r15
        and	rdx, rbx
        add	r14, rax
        xor	rdx, r8
        ; rnd_all_2: 2-3
        ; rnd_0: 0 - 7
        rorx	rax, r10, 14
        rorx	rcx, r10, 18
        add	r14, rdx
        add	r13, QWORD PTR [rsp+16]
        mov	rdx, r11
        xor	rcx, rax
        xor	rdx, r12
        rorx	rax, r10, 41
        xor	rax, rcx
        and	rdx, r10
        add	r13, rax
        rorx	rax, r14, 28
        rorx	rcx, r14, 34
        xor	rdx, r12
        xor	rcx, rax
        rorx	rax, r14, 39
        add	r13, rdx
        xor	rax, rcx
        mov	rdx, r15
        add	r9, r13
        xor	rdx, r14
        and	rbx, rdx
        add	r13, rax
        xor	rbx, r15
        ; rnd_1: 0 - 7
        rorx	rax, r9, 14
        rorx	rcx, r9, 18
        add	r13, rbx
        add	r12, QWORD PTR [rsp+24]
        mov	rbx, r10
        xor	rcx, rax
        xor	rbx, r11
        rorx	rax, r9, 41
        xor	rax, rcx
        and	rbx, r9
        add	r12, rax
        rorx	rax, r13, 28
        rorx	rcx, r13, 34
        xor	rbx, r11
        xor	rcx, rax
        rorx	rax, r13, 39
        add	r12, rbx
        xor	rax, rcx
        mov	rbx, r14
        add	r8, r12
        xor	rbx, r13
        and	rdx, rbx
        add	r12, rax
        xor	rdx, r14
        ; rnd_all_2: 4-5
        ; rnd_0: 0 - 7
        rorx	rax, r8, 14
        rorx	rcx, r8, 18
        add	r12, rdx
        add	r11, QWORD PTR [rsp+32]
        mov	rdx, r9
        xor	rcx, rax
        xor	rdx, r10
        rorx	rax, r8, 41
        xor	rax, rcx
        and	rdx, r8
        add	r11, rax
        rorx	rax, r12, 28
        rorx	rcx, r12, 34
        xor	rdx, r10
        xor	rcx, rax
        rorx	rax, r12, 39
        add	r11, rdx
        xor	rax, rcx
        mov	rdx, r13
        add	r15, r11
        xor	rdx, r12
        and	rbx, rdx
        add	r11, rax
        xor	rbx, r13
        ; rnd_1: 0 - 7
        rorx	rax, r15, 14
        rorx	rcx, r15, 18
        add	r11, rbx
        add	r10, QWORD PTR [rsp+40]
        mov	rbx, r8
        xor	rcx, rax
        xor	rbx, r9
        rorx	rax, r15, 41
        xor	rax, rcx
        and	rbx, r15
        add	r10, rax
        rorx	rax, r11, 28
        rorx	rcx, r11, 34
        xor	rbx, r9
        xor	rcx, rax
        rorx	rax, r11, 39
        add	r10, rbx
        xor	rax, rcx
        mov	rbx, r12
        add	r14, r10
        xor	rbx, r11
        and	rdx, rbx
        add	r10, rax
        xor	rdx, r12
        ; rnd_all_2: 6-7
        ; rnd_0: 0 - 7
        rorx	rax, r14, 14
        rorx	rcx, r14, 18
        add	r10, rdx
        add	r9, QWORD PTR [rsp+48]
        mov	rdx, r15
        xor	rcx, rax
        xor	rdx, r8
        rorx	rax, r14, 41
        xor	rax, rcx
        and	rdx, r14
        add	r9, rax
        rorx	rax, r10, 28
        rorx	rcx, r10, 34
        xor	rdx, r8
        xor	rcx, rax
        rorx	rax, r10, 39
        add	r9, rdx
        xor	rax, rcx
        mov	rdx, r11
        add	r13, r9
        xor	rdx, r10
        and	rbx, rdx
        add	r9, rax
        xor	rbx, r11
        ; rnd_1: 0 - 7
        rorx	rax, r13, 14
        rorx	rcx, r13, 18
        add	r9, rbx
        add	r8, QWORD PTR [rsp+56]
        mov	rbx, r14
        xor	rcx, rax
        xor	rbx, r15
        rorx	rax, r13, 41
        xor	rax, rcx
        and	rbx, r13
        add	r8, rax
        rorx	rax, r9, 28
        rorx	rcx, r9, 34
        xor	rbx, r15
        xor	rcx, rax
        rorx	rax, r9, 39
        add	r8, rbx
        xor	rax, rcx
        mov	rbx, r10
        add	r12, r8
        xor	rbx, r9
        and	rdx, rbx
        add	r8, rax
        xor	rdx, r10
        ; rnd_all_2: 8-9
        ; rnd_0: 0 - 7
        rorx	rax, r12, 14
        rorx	rcx, r12, 18
        add	r8, rdx
        add	r15, QWORD PTR [rsp+64]
        mov	rdx, r13
        xor	rcx, rax
        xor	rdx, r14
        rorx	rax, r12, 41
        xor	rax, rcx
        and	rdx, r12
        add	r15, rax
        rorx	rax, r8, 28
        rorx	rcx, r8, 34
        xor	rdx, r14
        xor	rcx, rax
        rorx	rax, r8, 39
        add	r15, rdx
        xor	rax, rcx
        mov	rdx, r9
        add	r11, r15
        xor	rdx, r8
        and	rbx, rdx
        add	r15, rax
        xor	rbx, r9
        ; rnd_1: 0 - 7
        rorx	rax, r11, 14
        rorx	rcx, r11, 18
        add	r15, rbx
        add	r14, QWORD PTR [rsp+72]
        mov	rbx, r12
        xor	rcx, rax
        xor	rbx, r13
        rorx	rax, r11, 41
        xor	rax, rcx
        and	rbx, r11
        add	r14, rax
        rorx	rax, r15, 28
        rorx	rcx, r15, 34
        xor	rbx, r13
        xor	rcx, rax
        rorx	rax, r15, 39
        add	r14, rbx
        xor	rax, rcx
        mov	rbx, r8
        add	r10, r14
        xor	rbx, r15
        and	rdx, rbx
        add	r14, rax
        xor	rdx, r8
        ; rnd_all_2: 10-11
        ; rnd_0: 0 - 7
        rorx	rax, r10, 14
        rorx	rcx, r10, 18
        add	r14, rdx
        add	r13, QWORD PTR [rsp+80]
        mov	rdx, r11
        xor	rcx, rax
        xor	rdx, r12
        rorx	rax, r10, 41
        xor	rax, rcx
        and	rdx, r10
        add	r13, rax
        rorx	rax, r14, 28
        rorx	rcx, r14, 34
        xor	rdx, r12
        xor	rcx, rax
        rorx	rax, r14, 39
        add	r13, rdx
        xor	rax, rcx
        mov	rdx, r15
        add	r9, r13
        xor	rdx, r14
        and	rbx, rdx
        add	r13, rax
        xor	rbx, r15
        ; rnd_1: 0 - 7
        rorx	rax, r9, 14
        rorx	rcx, r9, 18
        add	r13, rbx
        add	r12, QWORD PTR [rsp+88]
        mov	rbx, r10
        xor	rcx, rax
        xor	rbx, r11
        rorx	rax, r9, 41
        xor	rax, rcx
        and	rbx, r9
        add	r12, rax
        rorx	rax, r13, 28
        rorx	rcx, r13, 34
        xor	rbx, r11
        xor	rcx, rax
        rorx	rax, r13, 39
        add	r12, rbx
        xor	rax, rcx
        mov	rbx, r14
        add	r8, r12
        xor	rbx, r13
        and	rdx, rbx
        add	r12, rax
        xor	rdx, r14
        ; rnd_all_2: 12-13
        ; rnd_0: 0 - 7
        rorx	rax, r8, 14
        rorx	rcx, r8, 18
        add	r12, rdx
        add	r11, QWORD PTR [rsp+96]
        mov	rdx, r9
        xor	rcx, rax
        xor	rdx, r10
        rorx	rax, r8, 41
        xor	rax, rcx
        and	rdx, r8
        add	r11, rax
        rorx	rax, r12, 28
        rorx	rcx, r12, 34
        xor	rdx, r10
        xor	rcx, rax
        rorx	rax, r12, 39
        add	r11, rdx
        xor	rax, rcx
        mov	rdx, r13
        add	r15, r11
        xor	rdx, r12
        and	rbx, rdx
        add	r11, rax
        xor	rbx, r13
        ; rnd_1: 0 - 7
        rorx	rax, r15, 14
        rorx	rcx, r15, 18
        add	r11, rbx
        add	r10, QWORD PTR [rsp+104]
        mov	rbx, r8
        xor	rcx, rax
        xor	rbx, r9
        rorx	rax, r15, 41
        xor	rax, rcx
        and	rbx, r15
        add	r10, rax
        rorx	rax, r11, 28
        rorx	rcx, r11, 34
        xor	rbx, r9
        xor	rcx, rax
        rorx	rax, r11, 39
        add	r10, rbx
        xor	rax, rcx
        mov	rbx, r12
        add	r14, r10
        xor	rbx, r11
        and	rdx, rbx
        add	r10, rax
        xor	rdx, r12
        ; rnd_all_2: 14-15
        ; rnd_0: 0 - 7
        rorx	rax, r14, 14
        rorx	rcx, r14, 18
        add	r10, rdx
        add	r9, QWORD PTR [rsp+112]
        mov	rdx, r15
        xor	rcx, rax
        xor	rdx, r8
        rorx	rax, r14, 41
        xor	rax, rcx
        and	rdx, r14
        add	r9, rax
        rorx	rax, r10, 28
        rorx	rcx, r10, 34
        xor	rdx, r8
        xor	rcx, rax
        rorx	rax, r10, 39
        add	r9, rdx
        xor	rax, rcx
        mov	rdx, r11
        add	r13, r9
        xor	rdx, r10
        and	rbx, rdx
        add	r9, rax
        xor	rbx, r11
        ; rnd_1: 0 - 7
        rorx	rax, r13, 14
        rorx	rcx, r13, 18
        add	r9, rbx
        add	r8, QWORD PTR [rsp+120]
        mov	rbx, r14
        xor	rcx, rax
        xor	rbx, r15
        rorx	rax, r13, 41
        xor	rax, rcx
        and	rbx, r13
        add	r8, rax
        rorx	rax, r9, 28
        rorx	rcx, r9, 34
        xor	rbx, r15
        xor	rcx, rax
        rorx	rax, r9, 39
        add	r8, rbx
        xor	rax, rcx
        mov	rbx, r10
        add	r12, r8
        xor	rbx, r9
        and	rdx, rbx
        add	r8, rax
        xor	rdx, r10
        add	r8, rdx
        add	r8, QWORD PTR [rdi]
        add	r9, QWORD PTR [rdi+8]
        add	r10, QWORD PTR [rdi+16]
        add	r11, QWORD PTR [rdi+24]
        add	r12, QWORD PTR [rdi+32]
        add	r13, QWORD PTR [rdi+40]
        add	r14, QWORD PTR [rdi+48]
        add	r15, QWORD PTR [rdi+56]
        mov	rcx, QWORD PTR [ptr_L_avx1_rorx_sha512_k]
        add	rsi, 128
        sub	ebp, 128
        mov	QWORD PTR [rdi], r8
        mov	QWORD PTR [rdi+8], r9
        mov	QWORD PTR [rdi+16], r10
        mov	QWORD PTR [rdi+24], r11
        mov	QWORD PTR [rdi+32], r12
        mov	QWORD PTR [rdi+40], r13
        mov	QWORD PTR [rdi+48], r14
        mov	QWORD PTR [rdi+56], r15
        jnz	L_sha512_len_avx1_rorx_begin
        xor	rax, rax
        vmovdqu	xmm6, OWORD PTR [rsp+144]
        vmovdqu	xmm7, OWORD PTR [rsp+160]
        vmovdqu	xmm8, OWORD PTR [rsp+176]
        vmovdqu	xmm9, OWORD PTR [rsp+192]
        vmovdqu	xmm10, OWORD PTR [rsp+208]
        vmovdqu	xmm11, OWORD PTR [rsp+224]
        vmovdqu	xmm13, OWORD PTR [rsp+240]
        vmovdqu	xmm12, OWORD PTR [rsp+256]
        vmovdqu	xmm14, OWORD PTR [rsp+272]
        add	rsp, 288
        pop	rbp
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        pop	rbx
        ret
Transform_Sha512_AVX1_RORX_Len ENDP
_TEXT ENDS
ENDIF
IFDEF HAVE_INTEL_AVX2
_DATA SEGMENT
ALIGN 16
L_avx2_sha512_k QWORD 428a2f98d728ae22h, 7137449123ef65cdh
        QWORD 0b5c0fbcfec4d3b2fh, 0e9b5dba58189dbbch
        QWORD 3956c25bf348b538h, 59f111f1b605d019h
        QWORD 923f82a4af194f9bh, 0ab1c5ed5da6d8118h
        QWORD 0d807aa98a3030242h, 12835b0145706fbeh
        QWORD 243185be4ee4b28ch, 550c7dc3d5ffb4e2h
        QWORD 72be5d74f27b896fh, 80deb1fe3b1696b1h
        QWORD 9bdc06a725c71235h, 0c19bf174cf692694h
        QWORD 0e49b69c19ef14ad2h, 0efbe4786384f25e3h
        QWORD 0fc19dc68b8cd5b5h, 240ca1cc77ac9c65h
        QWORD 2de92c6f592b0275h, 4a7484aa6ea6e483h
        QWORD 5cb0a9dcbd41fbd4h, 76f988da831153b5h
        QWORD 983e5152ee66dfabh, 0a831c66d2db43210h
        QWORD 0b00327c898fb213fh, 0bf597fc7beef0ee4h
        QWORD 0c6e00bf33da88fc2h, 0d5a79147930aa725h
        QWORD 06ca6351e003826fh, 142929670a0e6e70h
        QWORD 27b70a8546d22ffch, 2e1b21385c26c926h
        QWORD 4d2c6dfc5ac42aedh, 53380d139d95b3dfh
        QWORD 650a73548baf63deh, 766a0abb3c77b2a8h
        QWORD 81c2c92e47edaee6h, 92722c851482353bh
        QWORD 0a2bfe8a14cf10364h, 0a81a664bbc423001h
        QWORD 0c24b8b70d0f89791h, 0c76c51a30654be30h
        QWORD 0d192e819d6ef5218h, 0d69906245565a910h
        QWORD 0f40e35855771202ah, 106aa07032bbd1b8h
        QWORD 19a4c116b8d2d0c8h, 1e376c085141ab53h
        QWORD 2748774cdf8eeb99h, 34b0bcb5e19b48a8h
        QWORD 391c0cb3c5c95a63h, 4ed8aa4ae3418acbh
        QWORD 5b9cca4f7763e373h, 682e6ff3d6b2b8a3h
        QWORD 748f82ee5defb2fch, 78a5636f43172f60h
        QWORD 84c87814a1f0ab72h, 8cc702081a6439ech
        QWORD 90befffa23631e28h, 0a4506cebde82bde9h
        QWORD 0bef9a3f7b2c67915h, 0c67178f2e372532bh
        QWORD 0ca273eceea26619ch, 0d186b8c721c0c207h
        QWORD 0eada7dd6cde0eb1eh, 0f57d4f7fee6ed178h
        QWORD 06f067aa72176fbah, 0a637dc5a2c898a6h
        QWORD 113f9804bef90daeh, 1b710b35131c471bh
        QWORD 28db77f523047d84h, 32caab7b40c72493h
        QWORD 3c9ebe0a15c9bebch, 431d67c49c100d4ch
        QWORD 4cc5d4becb3e42b6h, 597f299cfc657e2ah
        QWORD 5fcb6fab3ad6faech, 6c44198c4a475817h
ptr_L_avx2_sha512_k QWORD L_avx2_sha512_k
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_avx2_sha512_k_2 QWORD 428a2f98d728ae22h, 7137449123ef65cdh
        QWORD 428a2f98d728ae22h, 7137449123ef65cdh
        QWORD 0b5c0fbcfec4d3b2fh, 0e9b5dba58189dbbch
        QWORD 0b5c0fbcfec4d3b2fh, 0e9b5dba58189dbbch
        QWORD 3956c25bf348b538h, 59f111f1b605d019h
        QWORD 3956c25bf348b538h, 59f111f1b605d019h
        QWORD 923f82a4af194f9bh, 0ab1c5ed5da6d8118h
        QWORD 923f82a4af194f9bh, 0ab1c5ed5da6d8118h
        QWORD 0d807aa98a3030242h, 12835b0145706fbeh
        QWORD 0d807aa98a3030242h, 12835b0145706fbeh
        QWORD 243185be4ee4b28ch, 550c7dc3d5ffb4e2h
        QWORD 243185be4ee4b28ch, 550c7dc3d5ffb4e2h
        QWORD 72be5d74f27b896fh, 80deb1fe3b1696b1h
        QWORD 72be5d74f27b896fh, 80deb1fe3b1696b1h
        QWORD 9bdc06a725c71235h, 0c19bf174cf692694h
        QWORD 9bdc06a725c71235h, 0c19bf174cf692694h
        QWORD 0e49b69c19ef14ad2h, 0efbe4786384f25e3h
        QWORD 0e49b69c19ef14ad2h, 0efbe4786384f25e3h
        QWORD 0fc19dc68b8cd5b5h, 240ca1cc77ac9c65h
        QWORD 0fc19dc68b8cd5b5h, 240ca1cc77ac9c65h
        QWORD 2de92c6f592b0275h, 4a7484aa6ea6e483h
        QWORD 2de92c6f592b0275h, 4a7484aa6ea6e483h
        QWORD 5cb0a9dcbd41fbd4h, 76f988da831153b5h
        QWORD 5cb0a9dcbd41fbd4h, 76f988da831153b5h
        QWORD 983e5152ee66dfabh, 0a831c66d2db43210h
        QWORD 983e5152ee66dfabh, 0a831c66d2db43210h
        QWORD 0b00327c898fb213fh, 0bf597fc7beef0ee4h
        QWORD 0b00327c898fb213fh, 0bf597fc7beef0ee4h
        QWORD 0c6e00bf33da88fc2h, 0d5a79147930aa725h
        QWORD 0c6e00bf33da88fc2h, 0d5a79147930aa725h
        QWORD 06ca6351e003826fh, 142929670a0e6e70h
        QWORD 06ca6351e003826fh, 142929670a0e6e70h
        QWORD 27b70a8546d22ffch, 2e1b21385c26c926h
        QWORD 27b70a8546d22ffch, 2e1b21385c26c926h
        QWORD 4d2c6dfc5ac42aedh, 53380d139d95b3dfh
        QWORD 4d2c6dfc5ac42aedh, 53380d139d95b3dfh
        QWORD 650a73548baf63deh, 766a0abb3c77b2a8h
        QWORD 650a73548baf63deh, 766a0abb3c77b2a8h
        QWORD 81c2c92e47edaee6h, 92722c851482353bh
        QWORD 81c2c92e47edaee6h, 92722c851482353bh
        QWORD 0a2bfe8a14cf10364h, 0a81a664bbc423001h
        QWORD 0a2bfe8a14cf10364h, 0a81a664bbc423001h
        QWORD 0c24b8b70d0f89791h, 0c76c51a30654be30h
        QWORD 0c24b8b70d0f89791h, 0c76c51a30654be30h
        QWORD 0d192e819d6ef5218h, 0d69906245565a910h
        QWORD 0d192e819d6ef5218h, 0d69906245565a910h
        QWORD 0f40e35855771202ah, 106aa07032bbd1b8h
        QWORD 0f40e35855771202ah, 106aa07032bbd1b8h
        QWORD 19a4c116b8d2d0c8h, 1e376c085141ab53h
        QWORD 19a4c116b8d2d0c8h, 1e376c085141ab53h
        QWORD 2748774cdf8eeb99h, 34b0bcb5e19b48a8h
        QWORD 2748774cdf8eeb99h, 34b0bcb5e19b48a8h
        QWORD 391c0cb3c5c95a63h, 4ed8aa4ae3418acbh
        QWORD 391c0cb3c5c95a63h, 4ed8aa4ae3418acbh
        QWORD 5b9cca4f7763e373h, 682e6ff3d6b2b8a3h
        QWORD 5b9cca4f7763e373h, 682e6ff3d6b2b8a3h
        QWORD 748f82ee5defb2fch, 78a5636f43172f60h
        QWORD 748f82ee5defb2fch, 78a5636f43172f60h
        QWORD 84c87814a1f0ab72h, 8cc702081a6439ech
        QWORD 84c87814a1f0ab72h, 8cc702081a6439ech
        QWORD 90befffa23631e28h, 0a4506cebde82bde9h
        QWORD 90befffa23631e28h, 0a4506cebde82bde9h
        QWORD 0bef9a3f7b2c67915h, 0c67178f2e372532bh
        QWORD 0bef9a3f7b2c67915h, 0c67178f2e372532bh
        QWORD 0ca273eceea26619ch, 0d186b8c721c0c207h
        QWORD 0ca273eceea26619ch, 0d186b8c721c0c207h
        QWORD 0eada7dd6cde0eb1eh, 0f57d4f7fee6ed178h
        QWORD 0eada7dd6cde0eb1eh, 0f57d4f7fee6ed178h
        QWORD 06f067aa72176fbah, 0a637dc5a2c898a6h
        QWORD 06f067aa72176fbah, 0a637dc5a2c898a6h
        QWORD 113f9804bef90daeh, 1b710b35131c471bh
        QWORD 113f9804bef90daeh, 1b710b35131c471bh
        QWORD 28db77f523047d84h, 32caab7b40c72493h
        QWORD 28db77f523047d84h, 32caab7b40c72493h
        QWORD 3c9ebe0a15c9bebch, 431d67c49c100d4ch
        QWORD 3c9ebe0a15c9bebch, 431d67c49c100d4ch
        QWORD 4cc5d4becb3e42b6h, 597f299cfc657e2ah
        QWORD 4cc5d4becb3e42b6h, 597f299cfc657e2ah
        QWORD 5fcb6fab3ad6faech, 6c44198c4a475817h
        QWORD 5fcb6fab3ad6faech, 6c44198c4a475817h
ptr_L_avx2_sha512_k_2 QWORD L_avx2_sha512_k_2
_DATA ENDS
_DATA SEGMENT
ALIGN 8
L_avx2_sha512_k_2_end QWORD 1024+L_avx2_sha512_k_2
ptr_L_avx2_sha512_k_2_end QWORD L_avx2_sha512_k_2_end
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_avx2_sha512_flip_mask QWORD 0001020304050607h, 08090a0b0c0d0e0fh
        QWORD 0001020304050607h, 08090a0b0c0d0e0fh
ptr_L_avx2_sha512_flip_mask QWORD L_avx2_sha512_flip_mask
_DATA ENDS
_TEXT SEGMENT READONLY PARA
Transform_Sha512_AVX2 PROC
        push	rbx
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        mov	rdi, rcx
        sub	rsp, 296
        vmovdqu	OWORD PTR [rsp+136], xmm6
        vmovdqu	OWORD PTR [rsp+152], xmm7
        vmovdqu	OWORD PTR [rsp+168], xmm8
        vmovdqu	OWORD PTR [rsp+184], xmm9
        vmovdqu	OWORD PTR [rsp+200], xmm10
        vmovdqu	OWORD PTR [rsp+216], xmm11
        vmovdqu	OWORD PTR [rsp+232], xmm14
        vmovdqu	OWORD PTR [rsp+248], xmm13
        vmovdqu	OWORD PTR [rsp+264], xmm12
        vmovdqu	OWORD PTR [rsp+280], xmm15
        lea	rax, QWORD PTR [rdi+64]
        vmovdqu	ymm15, YMMWORD PTR L_avx2_sha512_flip_mask
        mov	r8, QWORD PTR [rdi]
        mov	r9, QWORD PTR [rdi+8]
        mov	r10, QWORD PTR [rdi+16]
        mov	r11, QWORD PTR [rdi+24]
        mov	r12, QWORD PTR [rdi+32]
        mov	r13, QWORD PTR [rdi+40]
        mov	r14, QWORD PTR [rdi+48]
        mov	r15, QWORD PTR [rdi+56]
        vmovdqu	ymm0, YMMWORD PTR [rax]
        vmovdqu	ymm1, YMMWORD PTR [rax+32]
        vpshufb	ymm0, ymm0, ymm15
        vpshufb	ymm1, ymm1, ymm15
        vmovdqu	ymm2, YMMWORD PTR [rax+64]
        vmovdqu	ymm3, YMMWORD PTR [rax+96]
        vpshufb	ymm2, ymm2, ymm15
        vpshufb	ymm3, ymm3, ymm15
        mov	DWORD PTR [rsp+128], 4
        mov	rsi, QWORD PTR [ptr_L_avx2_sha512_k]
        mov	rbx, r9
        mov	rax, r12
        xor	rbx, r10
        vpaddq	ymm8, ymm0, [rsi]
        vpaddq	ymm9, ymm1, [rsi+32]
        vmovdqu	YMMWORD PTR [rsp], ymm8
        vmovdqu	YMMWORD PTR [rsp+32], ymm9
        vpaddq	ymm8, ymm2, [rsi+64]
        vpaddq	ymm9, ymm3, [rsi+96]
        vmovdqu	YMMWORD PTR [rsp+64], ymm8
        vmovdqu	YMMWORD PTR [rsp+96], ymm9
        ; Start of 16 rounds
L_sha256_avx2_start:
        add	rsi, 128
        ror	rax, 23
        vpblendd	ymm12, ymm0, ymm1, 3
        vpblendd	ymm13, ymm2, ymm3, 3
        mov	rdx, r8
        mov	rcx, r13
        add	r15, QWORD PTR [rsp]
        xor	rcx, r14
        xor	rax, r12
        and	rcx, r12
        vpermq	ymm12, ymm12, 57
        ror	rax, 4
        xor	rcx, r14
        vpermq	ymm13, ymm13, 57
        xor	rax, r12
        add	r15, rcx
        ror	rax, 14
        xor	rdx, r9
        vpsrlq	ymm8, ymm12, 1
        add	r15, rax
        mov	rcx, r8
        vpsllq	ymm9, ymm12, 63
        and	rbx, rdx
        ror	rcx, 5
        vpsrlq	ymm10, ymm12, 8
        xor	rcx, r8
        xor	rbx, r9
        vpsllq	ymm11, ymm12, 56
        ror	rcx, 6
        add	r11, r15
        vpor	ymm8, ymm8, ymm9
        xor	rcx, r8
        add	r15, rbx
        vpor	ymm10, ymm10, ymm11
        ror	rcx, 28
        mov	rax, r11
        add	r15, rcx
        ror	rax, 23
        vpsrlq	ymm11, ymm12, 7
        mov	rbx, r15
        mov	rcx, r12
        vpxor	ymm8, ymm8, ymm10
        add	r14, QWORD PTR [rsp+8]
        xor	rcx, r13
        vpxor	ymm8, ymm8, ymm11
        xor	rax, r11
        and	rcx, r11
        vpaddq	ymm0, ymm13, ymm0
        ror	rax, 4
        xor	rcx, r13
        vpaddq	ymm0, ymm8, ymm0
        xor	rax, r11
        add	r14, rcx
        vperm2I128	ymm14, ymm3, ymm3, 129
        ror	rax, 14
        xor	rbx, r8
        add	r14, rax
        mov	rcx, r15
        and	rdx, rbx
        ror	rcx, 5
        vpsrlq	ymm8, ymm14, 19
        xor	rcx, r15
        xor	rdx, r8
        vpsllq	ymm9, ymm14, 45
        ror	rcx, 6
        add	r10, r14
        vpsrlq	ymm10, ymm14, 61
        xor	rcx, r15
        add	r14, rdx
        vpsllq	ymm11, ymm14, 3
        ror	rcx, 28
        mov	rax, r10
        add	r14, rcx
        ror	rax, 23
        vpor	ymm8, ymm8, ymm9
        mov	rdx, r14
        mov	rcx, r11
        add	r13, QWORD PTR [rsp+16]
        xor	rcx, r12
        vpor	ymm10, ymm10, ymm11
        xor	rax, r10
        and	rcx, r10
        vpxor	ymm8, ymm8, ymm10
        ror	rax, 4
        xor	rcx, r12
        vpsrlq	ymm11, ymm14, 6
        xor	rax, r10
        add	r13, rcx
        vpxor	ymm8, ymm8, ymm11
        ror	rax, 14
        xor	rdx, r15
        vpaddq	ymm0, ymm8, ymm0
        add	r13, rax
        mov	rcx, r14
        and	rbx, rdx
        ror	rcx, 5
        vperm2I128	ymm14, ymm0, ymm0, 8
        xor	rcx, r14
        xor	rbx, r15
        ror	rcx, 6
        add	r9, r13
        vpsrlq	ymm8, ymm14, 19
        xor	rcx, r14
        add	r13, rbx
        vpsllq	ymm9, ymm14, 45
        ror	rcx, 28
        mov	rax, r9
        add	r13, rcx
        ror	rax, 23
        vpsrlq	ymm10, ymm14, 61
        mov	rbx, r13
        mov	rcx, r10
        add	r12, QWORD PTR [rsp+24]
        xor	rcx, r11
        vpsllq	ymm11, ymm14, 3
        xor	rax, r9
        and	rcx, r9
        vpor	ymm8, ymm8, ymm9
        ror	rax, 4
        xor	rcx, r11
        vpor	ymm10, ymm10, ymm11
        xor	rax, r9
        add	r12, rcx
        vpxor	ymm8, ymm8, ymm10
        ror	rax, 14
        xor	rbx, r14
        vpsrlq	ymm11, ymm14, 6
        add	r12, rax
        mov	rcx, r13
        vpxor	ymm8, ymm8, ymm11
        and	rdx, rbx
        ror	rcx, 5
        vpaddq	ymm0, ymm8, ymm0
        xor	rcx, r13
        xor	rdx, r14
        ror	rcx, 6
        add	r8, r12
        xor	rcx, r13
        add	r12, rdx
        ror	rcx, 28
        mov	rax, r8
        add	r12, rcx
        ror	rax, 23
        vpblendd	ymm12, ymm1, ymm2, 3
        vpblendd	ymm13, ymm3, ymm0, 3
        mov	rdx, r12
        mov	rcx, r9
        add	r11, QWORD PTR [rsp+32]
        xor	rcx, r10
        xor	rax, r8
        and	rcx, r8
        vpermq	ymm12, ymm12, 57
        ror	rax, 4
        xor	rcx, r10
        vpermq	ymm13, ymm13, 57
        xor	rax, r8
        add	r11, rcx
        ror	rax, 14
        xor	rdx, r13
        vpsrlq	ymm8, ymm12, 1
        add	r11, rax
        mov	rcx, r12
        vpsllq	ymm9, ymm12, 63
        and	rbx, rdx
        ror	rcx, 5
        vpsrlq	ymm10, ymm12, 8
        xor	rcx, r12
        xor	rbx, r13
        vpsllq	ymm11, ymm12, 56
        ror	rcx, 6
        add	r15, r11
        vpor	ymm8, ymm8, ymm9
        xor	rcx, r12
        add	r11, rbx
        vpor	ymm10, ymm10, ymm11
        ror	rcx, 28
        mov	rax, r15
        add	r11, rcx
        ror	rax, 23
        vpsrlq	ymm11, ymm12, 7
        mov	rbx, r11
        mov	rcx, r8
        vpxor	ymm8, ymm8, ymm10
        add	r10, QWORD PTR [rsp+40]
        xor	rcx, r9
        vpxor	ymm8, ymm8, ymm11
        xor	rax, r15
        and	rcx, r15
        vpaddq	ymm1, ymm13, ymm1
        ror	rax, 4
        xor	rcx, r9
        vpaddq	ymm1, ymm8, ymm1
        xor	rax, r15
        add	r10, rcx
        vperm2I128	ymm14, ymm0, ymm0, 129
        ror	rax, 14
        xor	rbx, r12
        add	r10, rax
        mov	rcx, r11
        and	rdx, rbx
        ror	rcx, 5
        vpsrlq	ymm8, ymm14, 19
        xor	rcx, r11
        xor	rdx, r12
        vpsllq	ymm9, ymm14, 45
        ror	rcx, 6
        add	r14, r10
        vpsrlq	ymm10, ymm14, 61
        xor	rcx, r11
        add	r10, rdx
        vpsllq	ymm11, ymm14, 3
        ror	rcx, 28
        mov	rax, r14
        add	r10, rcx
        ror	rax, 23
        vpor	ymm8, ymm8, ymm9
        mov	rdx, r10
        mov	rcx, r15
        add	r9, QWORD PTR [rsp+48]
        xor	rcx, r8
        vpor	ymm10, ymm10, ymm11
        xor	rax, r14
        and	rcx, r14
        vpxor	ymm8, ymm8, ymm10
        ror	rax, 4
        xor	rcx, r8
        vpsrlq	ymm11, ymm14, 6
        xor	rax, r14
        add	r9, rcx
        vpxor	ymm8, ymm8, ymm11
        ror	rax, 14
        xor	rdx, r11
        vpaddq	ymm1, ymm8, ymm1
        add	r9, rax
        mov	rcx, r10
        and	rbx, rdx
        ror	rcx, 5
        vperm2I128	ymm14, ymm1, ymm1, 8
        xor	rcx, r10
        xor	rbx, r11
        ror	rcx, 6
        add	r13, r9
        vpsrlq	ymm8, ymm14, 19
        xor	rcx, r10
        add	r9, rbx
        vpsllq	ymm9, ymm14, 45
        ror	rcx, 28
        mov	rax, r13
        add	r9, rcx
        ror	rax, 23
        vpsrlq	ymm10, ymm14, 61
        mov	rbx, r9
        mov	rcx, r14
        add	r8, QWORD PTR [rsp+56]
        xor	rcx, r15
        vpsllq	ymm11, ymm14, 3
        xor	rax, r13
        and	rcx, r13
        vpor	ymm8, ymm8, ymm9
        ror	rax, 4
        xor	rcx, r15
        vpor	ymm10, ymm10, ymm11
        xor	rax, r13
        add	r8, rcx
        vpxor	ymm8, ymm8, ymm10
        ror	rax, 14
        xor	rbx, r10
        vpsrlq	ymm11, ymm14, 6
        add	r8, rax
        mov	rcx, r9
        vpxor	ymm8, ymm8, ymm11
        and	rdx, rbx
        ror	rcx, 5
        vpaddq	ymm1, ymm8, ymm1
        xor	rcx, r9
        xor	rdx, r10
        ror	rcx, 6
        add	r12, r8
        xor	rcx, r9
        add	r8, rdx
        ror	rcx, 28
        mov	rax, r12
        add	r8, rcx
        ror	rax, 23
        vpblendd	ymm12, ymm2, ymm3, 3
        vpblendd	ymm13, ymm0, ymm1, 3
        mov	rdx, r8
        mov	rcx, r13
        add	r15, QWORD PTR [rsp+64]
        xor	rcx, r14
        xor	rax, r12
        and	rcx, r12
        vpermq	ymm12, ymm12, 57
        ror	rax, 4
        xor	rcx, r14
        vpermq	ymm13, ymm13, 57
        xor	rax, r12
        add	r15, rcx
        ror	rax, 14
        xor	rdx, r9
        vpsrlq	ymm8, ymm12, 1
        add	r15, rax
        mov	rcx, r8
        vpsllq	ymm9, ymm12, 63
        and	rbx, rdx
        ror	rcx, 5
        vpsrlq	ymm10, ymm12, 8
        xor	rcx, r8
        xor	rbx, r9
        vpsllq	ymm11, ymm12, 56
        ror	rcx, 6
        add	r11, r15
        vpor	ymm8, ymm8, ymm9
        xor	rcx, r8
        add	r15, rbx
        vpor	ymm10, ymm10, ymm11
        ror	rcx, 28
        mov	rax, r11
        add	r15, rcx
        ror	rax, 23
        vpsrlq	ymm11, ymm12, 7
        mov	rbx, r15
        mov	rcx, r12
        vpxor	ymm8, ymm8, ymm10
        add	r14, QWORD PTR [rsp+72]
        xor	rcx, r13
        vpxor	ymm8, ymm8, ymm11
        xor	rax, r11
        and	rcx, r11
        vpaddq	ymm2, ymm13, ymm2
        ror	rax, 4
        xor	rcx, r13
        vpaddq	ymm2, ymm8, ymm2
        xor	rax, r11
        add	r14, rcx
        vperm2I128	ymm14, ymm1, ymm1, 129
        ror	rax, 14
        xor	rbx, r8
        add	r14, rax
        mov	rcx, r15
        and	rdx, rbx
        ror	rcx, 5
        vpsrlq	ymm8, ymm14, 19
        xor	rcx, r15
        xor	rdx, r8
        vpsllq	ymm9, ymm14, 45
        ror	rcx, 6
        add	r10, r14
        vpsrlq	ymm10, ymm14, 61
        xor	rcx, r15
        add	r14, rdx
        vpsllq	ymm11, ymm14, 3
        ror	rcx, 28
        mov	rax, r10
        add	r14, rcx
        ror	rax, 23
        vpor	ymm8, ymm8, ymm9
        mov	rdx, r14
        mov	rcx, r11
        add	r13, QWORD PTR [rsp+80]
        xor	rcx, r12
        vpor	ymm10, ymm10, ymm11
        xor	rax, r10
        and	rcx, r10
        vpxor	ymm8, ymm8, ymm10
        ror	rax, 4
        xor	rcx, r12
        vpsrlq	ymm11, ymm14, 6
        xor	rax, r10
        add	r13, rcx
        vpxor	ymm8, ymm8, ymm11
        ror	rax, 14
        xor	rdx, r15
        vpaddq	ymm2, ymm8, ymm2
        add	r13, rax
        mov	rcx, r14
        and	rbx, rdx
        ror	rcx, 5
        vperm2I128	ymm14, ymm2, ymm2, 8
        xor	rcx, r14
        xor	rbx, r15
        ror	rcx, 6
        add	r9, r13
        vpsrlq	ymm8, ymm14, 19
        xor	rcx, r14
        add	r13, rbx
        vpsllq	ymm9, ymm14, 45
        ror	rcx, 28
        mov	rax, r9
        add	r13, rcx
        ror	rax, 23
        vpsrlq	ymm10, ymm14, 61
        mov	rbx, r13
        mov	rcx, r10
        add	r12, QWORD PTR [rsp+88]
        xor	rcx, r11
        vpsllq	ymm11, ymm14, 3
        xor	rax, r9
        and	rcx, r9
        vpor	ymm8, ymm8, ymm9
        ror	rax, 4
        xor	rcx, r11
        vpor	ymm10, ymm10, ymm11
        xor	rax, r9
        add	r12, rcx
        vpxor	ymm8, ymm8, ymm10
        ror	rax, 14
        xor	rbx, r14
        vpsrlq	ymm11, ymm14, 6
        add	r12, rax
        mov	rcx, r13
        vpxor	ymm8, ymm8, ymm11
        and	rdx, rbx
        ror	rcx, 5
        vpaddq	ymm2, ymm8, ymm2
        xor	rcx, r13
        xor	rdx, r14
        ror	rcx, 6
        add	r8, r12
        xor	rcx, r13
        add	r12, rdx
        ror	rcx, 28
        mov	rax, r8
        add	r12, rcx
        ror	rax, 23
        vpblendd	ymm12, ymm3, ymm0, 3
        vpblendd	ymm13, ymm1, ymm2, 3
        mov	rdx, r12
        mov	rcx, r9
        add	r11, QWORD PTR [rsp+96]
        xor	rcx, r10
        xor	rax, r8
        and	rcx, r8
        vpermq	ymm12, ymm12, 57
        ror	rax, 4
        xor	rcx, r10
        vpermq	ymm13, ymm13, 57
        xor	rax, r8
        add	r11, rcx
        ror	rax, 14
        xor	rdx, r13
        vpsrlq	ymm8, ymm12, 1
        add	r11, rax
        mov	rcx, r12
        vpsllq	ymm9, ymm12, 63
        and	rbx, rdx
        ror	rcx, 5
        vpsrlq	ymm10, ymm12, 8
        xor	rcx, r12
        xor	rbx, r13
        vpsllq	ymm11, ymm12, 56
        ror	rcx, 6
        add	r15, r11
        vpor	ymm8, ymm8, ymm9
        xor	rcx, r12
        add	r11, rbx
        vpor	ymm10, ymm10, ymm11
        ror	rcx, 28
        mov	rax, r15
        add	r11, rcx
        ror	rax, 23
        vpsrlq	ymm11, ymm12, 7
        mov	rbx, r11
        mov	rcx, r8
        vpxor	ymm8, ymm8, ymm10
        add	r10, QWORD PTR [rsp+104]
        xor	rcx, r9
        vpxor	ymm8, ymm8, ymm11
        xor	rax, r15
        and	rcx, r15
        vpaddq	ymm3, ymm13, ymm3
        ror	rax, 4
        xor	rcx, r9
        vpaddq	ymm3, ymm8, ymm3
        xor	rax, r15
        add	r10, rcx
        vperm2I128	ymm14, ymm2, ymm2, 129
        ror	rax, 14
        xor	rbx, r12
        add	r10, rax
        mov	rcx, r11
        and	rdx, rbx
        ror	rcx, 5
        vpsrlq	ymm8, ymm14, 19
        xor	rcx, r11
        xor	rdx, r12
        vpsllq	ymm9, ymm14, 45
        ror	rcx, 6
        add	r14, r10
        vpsrlq	ymm10, ymm14, 61
        xor	rcx, r11
        add	r10, rdx
        vpsllq	ymm11, ymm14, 3
        ror	rcx, 28
        mov	rax, r14
        add	r10, rcx
        ror	rax, 23
        vpor	ymm8, ymm8, ymm9
        mov	rdx, r10
        mov	rcx, r15
        add	r9, QWORD PTR [rsp+112]
        xor	rcx, r8
        vpor	ymm10, ymm10, ymm11
        xor	rax, r14
        and	rcx, r14
        vpxor	ymm8, ymm8, ymm10
        ror	rax, 4
        xor	rcx, r8
        vpsrlq	ymm11, ymm14, 6
        xor	rax, r14
        add	r9, rcx
        vpxor	ymm8, ymm8, ymm11
        ror	rax, 14
        xor	rdx, r11
        vpaddq	ymm3, ymm8, ymm3
        add	r9, rax
        mov	rcx, r10
        and	rbx, rdx
        ror	rcx, 5
        vperm2I128	ymm14, ymm3, ymm3, 8
        xor	rcx, r10
        xor	rbx, r11
        ror	rcx, 6
        add	r13, r9
        vpsrlq	ymm8, ymm14, 19
        xor	rcx, r10
        add	r9, rbx
        vpsllq	ymm9, ymm14, 45
        ror	rcx, 28
        mov	rax, r13
        add	r9, rcx
        ror	rax, 23
        vpsrlq	ymm10, ymm14, 61
        mov	rbx, r9
        mov	rcx, r14
        add	r8, QWORD PTR [rsp+120]
        xor	rcx, r15
        vpsllq	ymm11, ymm14, 3
        xor	rax, r13
        and	rcx, r13
        vpor	ymm8, ymm8, ymm9
        ror	rax, 4
        xor	rcx, r15
        vpor	ymm10, ymm10, ymm11
        xor	rax, r13
        add	r8, rcx
        vpxor	ymm8, ymm8, ymm10
        ror	rax, 14
        xor	rbx, r10
        vpsrlq	ymm11, ymm14, 6
        add	r8, rax
        mov	rcx, r9
        vpxor	ymm8, ymm8, ymm11
        and	rdx, rbx
        ror	rcx, 5
        vpaddq	ymm3, ymm8, ymm3
        xor	rcx, r9
        xor	rdx, r10
        ror	rcx, 6
        add	r12, r8
        xor	rcx, r9
        add	r8, rdx
        ror	rcx, 28
        mov	rax, r12
        add	r8, rcx
        vpaddq	ymm8, ymm0, [rsi]
        vpaddq	ymm9, ymm1, [rsi+32]
        vmovdqu	YMMWORD PTR [rsp], ymm8
        vmovdqu	YMMWORD PTR [rsp+32], ymm9
        vpaddq	ymm8, ymm2, [rsi+64]
        vpaddq	ymm9, ymm3, [rsi+96]
        vmovdqu	YMMWORD PTR [rsp+64], ymm8
        vmovdqu	YMMWORD PTR [rsp+96], ymm9
        sub	DWORD PTR [rsp+128], 1
        jne	L_sha256_avx2_start
        ror	rax, 23
        mov	rdx, r8
        mov	rcx, r13
        add	r15, QWORD PTR [rsp]
        xor	rcx, r14
        xor	rax, r12
        and	rcx, r12
        ror	rax, 4
        xor	rcx, r14
        xor	rax, r12
        add	r15, rcx
        ror	rax, 14
        xor	rdx, r9
        add	r15, rax
        mov	rcx, r8
        and	rbx, rdx
        ror	rcx, 5
        xor	rcx, r8
        xor	rbx, r9
        ror	rcx, 6
        add	r11, r15
        xor	rcx, r8
        add	r15, rbx
        ror	rcx, 28
        mov	rax, r11
        add	r15, rcx
        ror	rax, 23
        mov	rbx, r15
        mov	rcx, r12
        add	r14, QWORD PTR [rsp+8]
        xor	rcx, r13
        xor	rax, r11
        and	rcx, r11
        ror	rax, 4
        xor	rcx, r13
        xor	rax, r11
        add	r14, rcx
        ror	rax, 14
        xor	rbx, r8
        add	r14, rax
        mov	rcx, r15
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r15
        xor	rdx, r8
        ror	rcx, 6
        add	r10, r14
        xor	rcx, r15
        add	r14, rdx
        ror	rcx, 28
        mov	rax, r10
        add	r14, rcx
        ror	rax, 23
        mov	rdx, r14
        mov	rcx, r11
        add	r13, QWORD PTR [rsp+16]
        xor	rcx, r12
        xor	rax, r10
        and	rcx, r10
        ror	rax, 4
        xor	rcx, r12
        xor	rax, r10
        add	r13, rcx
        ror	rax, 14
        xor	rdx, r15
        add	r13, rax
        mov	rcx, r14
        and	rbx, rdx
        ror	rcx, 5
        xor	rcx, r14
        xor	rbx, r15
        ror	rcx, 6
        add	r9, r13
        xor	rcx, r14
        add	r13, rbx
        ror	rcx, 28
        mov	rax, r9
        add	r13, rcx
        ror	rax, 23
        mov	rbx, r13
        mov	rcx, r10
        add	r12, QWORD PTR [rsp+24]
        xor	rcx, r11
        xor	rax, r9
        and	rcx, r9
        ror	rax, 4
        xor	rcx, r11
        xor	rax, r9
        add	r12, rcx
        ror	rax, 14
        xor	rbx, r14
        add	r12, rax
        mov	rcx, r13
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r13
        xor	rdx, r14
        ror	rcx, 6
        add	r8, r12
        xor	rcx, r13
        add	r12, rdx
        ror	rcx, 28
        mov	rax, r8
        add	r12, rcx
        ror	rax, 23
        mov	rdx, r12
        mov	rcx, r9
        add	r11, QWORD PTR [rsp+32]
        xor	rcx, r10
        xor	rax, r8
        and	rcx, r8
        ror	rax, 4
        xor	rcx, r10
        xor	rax, r8
        add	r11, rcx
        ror	rax, 14
        xor	rdx, r13
        add	r11, rax
        mov	rcx, r12
        and	rbx, rdx
        ror	rcx, 5
        xor	rcx, r12
        xor	rbx, r13
        ror	rcx, 6
        add	r15, r11
        xor	rcx, r12
        add	r11, rbx
        ror	rcx, 28
        mov	rax, r15
        add	r11, rcx
        ror	rax, 23
        mov	rbx, r11
        mov	rcx, r8
        add	r10, QWORD PTR [rsp+40]
        xor	rcx, r9
        xor	rax, r15
        and	rcx, r15
        ror	rax, 4
        xor	rcx, r9
        xor	rax, r15
        add	r10, rcx
        ror	rax, 14
        xor	rbx, r12
        add	r10, rax
        mov	rcx, r11
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r11
        xor	rdx, r12
        ror	rcx, 6
        add	r14, r10
        xor	rcx, r11
        add	r10, rdx
        ror	rcx, 28
        mov	rax, r14
        add	r10, rcx
        ror	rax, 23
        mov	rdx, r10
        mov	rcx, r15
        add	r9, QWORD PTR [rsp+48]
        xor	rcx, r8
        xor	rax, r14
        and	rcx, r14
        ror	rax, 4
        xor	rcx, r8
        xor	rax, r14
        add	r9, rcx
        ror	rax, 14
        xor	rdx, r11
        add	r9, rax
        mov	rcx, r10
        and	rbx, rdx
        ror	rcx, 5
        xor	rcx, r10
        xor	rbx, r11
        ror	rcx, 6
        add	r13, r9
        xor	rcx, r10
        add	r9, rbx
        ror	rcx, 28
        mov	rax, r13
        add	r9, rcx
        ror	rax, 23
        mov	rbx, r9
        mov	rcx, r14
        add	r8, QWORD PTR [rsp+56]
        xor	rcx, r15
        xor	rax, r13
        and	rcx, r13
        ror	rax, 4
        xor	rcx, r15
        xor	rax, r13
        add	r8, rcx
        ror	rax, 14
        xor	rbx, r10
        add	r8, rax
        mov	rcx, r9
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r9
        xor	rdx, r10
        ror	rcx, 6
        add	r12, r8
        xor	rcx, r9
        add	r8, rdx
        ror	rcx, 28
        mov	rax, r12
        add	r8, rcx
        ror	rax, 23
        mov	rdx, r8
        mov	rcx, r13
        add	r15, QWORD PTR [rsp+64]
        xor	rcx, r14
        xor	rax, r12
        and	rcx, r12
        ror	rax, 4
        xor	rcx, r14
        xor	rax, r12
        add	r15, rcx
        ror	rax, 14
        xor	rdx, r9
        add	r15, rax
        mov	rcx, r8
        and	rbx, rdx
        ror	rcx, 5
        xor	rcx, r8
        xor	rbx, r9
        ror	rcx, 6
        add	r11, r15
        xor	rcx, r8
        add	r15, rbx
        ror	rcx, 28
        mov	rax, r11
        add	r15, rcx
        ror	rax, 23
        mov	rbx, r15
        mov	rcx, r12
        add	r14, QWORD PTR [rsp+72]
        xor	rcx, r13
        xor	rax, r11
        and	rcx, r11
        ror	rax, 4
        xor	rcx, r13
        xor	rax, r11
        add	r14, rcx
        ror	rax, 14
        xor	rbx, r8
        add	r14, rax
        mov	rcx, r15
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r15
        xor	rdx, r8
        ror	rcx, 6
        add	r10, r14
        xor	rcx, r15
        add	r14, rdx
        ror	rcx, 28
        mov	rax, r10
        add	r14, rcx
        ror	rax, 23
        mov	rdx, r14
        mov	rcx, r11
        add	r13, QWORD PTR [rsp+80]
        xor	rcx, r12
        xor	rax, r10
        and	rcx, r10
        ror	rax, 4
        xor	rcx, r12
        xor	rax, r10
        add	r13, rcx
        ror	rax, 14
        xor	rdx, r15
        add	r13, rax
        mov	rcx, r14
        and	rbx, rdx
        ror	rcx, 5
        xor	rcx, r14
        xor	rbx, r15
        ror	rcx, 6
        add	r9, r13
        xor	rcx, r14
        add	r13, rbx
        ror	rcx, 28
        mov	rax, r9
        add	r13, rcx
        ror	rax, 23
        mov	rbx, r13
        mov	rcx, r10
        add	r12, QWORD PTR [rsp+88]
        xor	rcx, r11
        xor	rax, r9
        and	rcx, r9
        ror	rax, 4
        xor	rcx, r11
        xor	rax, r9
        add	r12, rcx
        ror	rax, 14
        xor	rbx, r14
        add	r12, rax
        mov	rcx, r13
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r13
        xor	rdx, r14
        ror	rcx, 6
        add	r8, r12
        xor	rcx, r13
        add	r12, rdx
        ror	rcx, 28
        mov	rax, r8
        add	r12, rcx
        ror	rax, 23
        mov	rdx, r12
        mov	rcx, r9
        add	r11, QWORD PTR [rsp+96]
        xor	rcx, r10
        xor	rax, r8
        and	rcx, r8
        ror	rax, 4
        xor	rcx, r10
        xor	rax, r8
        add	r11, rcx
        ror	rax, 14
        xor	rdx, r13
        add	r11, rax
        mov	rcx, r12
        and	rbx, rdx
        ror	rcx, 5
        xor	rcx, r12
        xor	rbx, r13
        ror	rcx, 6
        add	r15, r11
        xor	rcx, r12
        add	r11, rbx
        ror	rcx, 28
        mov	rax, r15
        add	r11, rcx
        ror	rax, 23
        mov	rbx, r11
        mov	rcx, r8
        add	r10, QWORD PTR [rsp+104]
        xor	rcx, r9
        xor	rax, r15
        and	rcx, r15
        ror	rax, 4
        xor	rcx, r9
        xor	rax, r15
        add	r10, rcx
        ror	rax, 14
        xor	rbx, r12
        add	r10, rax
        mov	rcx, r11
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r11
        xor	rdx, r12
        ror	rcx, 6
        add	r14, r10
        xor	rcx, r11
        add	r10, rdx
        ror	rcx, 28
        mov	rax, r14
        add	r10, rcx
        ror	rax, 23
        mov	rdx, r10
        mov	rcx, r15
        add	r9, QWORD PTR [rsp+112]
        xor	rcx, r8
        xor	rax, r14
        and	rcx, r14
        ror	rax, 4
        xor	rcx, r8
        xor	rax, r14
        add	r9, rcx
        ror	rax, 14
        xor	rdx, r11
        add	r9, rax
        mov	rcx, r10
        and	rbx, rdx
        ror	rcx, 5
        xor	rcx, r10
        xor	rbx, r11
        ror	rcx, 6
        add	r13, r9
        xor	rcx, r10
        add	r9, rbx
        ror	rcx, 28
        mov	rax, r13
        add	r9, rcx
        ror	rax, 23
        mov	rbx, r9
        mov	rcx, r14
        add	r8, QWORD PTR [rsp+120]
        xor	rcx, r15
        xor	rax, r13
        and	rcx, r13
        ror	rax, 4
        xor	rcx, r15
        xor	rax, r13
        add	r8, rcx
        ror	rax, 14
        xor	rbx, r10
        add	r8, rax
        mov	rcx, r9
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r9
        xor	rdx, r10
        ror	rcx, 6
        add	r12, r8
        xor	rcx, r9
        add	r8, rdx
        ror	rcx, 28
        mov	rax, r12
        add	r8, rcx
        add	QWORD PTR [rdi], r8
        add	QWORD PTR [rdi+8], r9
        add	QWORD PTR [rdi+16], r10
        add	QWORD PTR [rdi+24], r11
        add	QWORD PTR [rdi+32], r12
        add	QWORD PTR [rdi+40], r13
        add	QWORD PTR [rdi+48], r14
        add	QWORD PTR [rdi+56], r15
        xor	rax, rax
        vzeroupper
        vmovdqu	xmm6, OWORD PTR [rsp+136]
        vmovdqu	xmm7, OWORD PTR [rsp+152]
        vmovdqu	xmm8, OWORD PTR [rsp+168]
        vmovdqu	xmm9, OWORD PTR [rsp+184]
        vmovdqu	xmm10, OWORD PTR [rsp+200]
        vmovdqu	xmm11, OWORD PTR [rsp+216]
        vmovdqu	xmm14, OWORD PTR [rsp+232]
        vmovdqu	xmm13, OWORD PTR [rsp+248]
        vmovdqu	xmm12, OWORD PTR [rsp+264]
        vmovdqu	xmm15, OWORD PTR [rsp+280]
        add	rsp, 296
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        pop	rbx
        ret
Transform_Sha512_AVX2 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
Transform_Sha512_AVX2_Len PROC
        push	rbx
        push	r12
        push	r13
        push	r14
        push	r15
        push	rsi
        push	rdi
        push	rbp
        mov	rdi, rcx
        mov	rbp, rdx
        sub	rsp, 160
        vmovdqu	OWORD PTR [rsp], xmm6
        vmovdqu	OWORD PTR [rsp+16], xmm7
        vmovdqu	OWORD PTR [rsp+32], xmm8
        vmovdqu	OWORD PTR [rsp+48], xmm9
        vmovdqu	OWORD PTR [rsp+64], xmm10
        vmovdqu	OWORD PTR [rsp+80], xmm11
        vmovdqu	OWORD PTR [rsp+96], xmm14
        vmovdqu	OWORD PTR [rsp+112], xmm13
        vmovdqu	OWORD PTR [rsp+128], xmm12
        vmovdqu	OWORD PTR [rsp+144], xmm15
        test	bpl, 128
        je	L_sha512_len_avx2_block
        mov	rbx, QWORD PTR [rdi+224]
        vmovdqu	ymm0, YMMWORD PTR [rbx]
        vmovdqu	ymm1, YMMWORD PTR [rbx+32]
        vmovdqu	ymm2, YMMWORD PTR [rbx+64]
        vmovdqu	ymm3, YMMWORD PTR [rbx+96]
        vmovups	YMMWORD PTR [rdi+64], ymm0
        vmovups	YMMWORD PTR [rdi+96], ymm1
        vmovups	YMMWORD PTR [rdi+128], ymm2
        vmovups	YMMWORD PTR [rdi+160], ymm3
        call	Transform_Sha512_AVX2
        add	QWORD PTR [rdi+224], 128
        sub	ebp, 128
        jz	L_sha512_len_avx2_done
L_sha512_len_avx2_block:
        sub	rsp, 1352
        mov	rcx, QWORD PTR [rdi+224]
        vmovdqu	ymm15, YMMWORD PTR L_avx2_sha512_flip_mask
        mov	r8, QWORD PTR [rdi]
        mov	r9, QWORD PTR [rdi+8]
        mov	r10, QWORD PTR [rdi+16]
        mov	r11, QWORD PTR [rdi+24]
        mov	r12, QWORD PTR [rdi+32]
        mov	r13, QWORD PTR [rdi+40]
        mov	r14, QWORD PTR [rdi+48]
        mov	r15, QWORD PTR [rdi+56]
        mov	QWORD PTR [rsp+1344], rbp
        ; Start of loop processing two blocks
L_sha512_len_avx2_begin:
        mov	rbp, rsp
        mov	rsi, QWORD PTR [ptr_L_avx2_sha512_k_2]
        mov	rbx, r9
        mov	rax, r12
        vmovdqu	xmm0, OWORD PTR [rcx]
        vmovdqu	xmm1, OWORD PTR [rcx+16]
        vinserti128	ymm0, ymm0, OWORD PTR [rcx+128], 1
        vinserti128	ymm1, ymm1, OWORD PTR [rcx+144], 1
        vpshufb	ymm0, ymm0, ymm15
        vpshufb	ymm1, ymm1, ymm15
        vmovdqu	xmm2, OWORD PTR [rcx+32]
        vmovdqu	xmm3, OWORD PTR [rcx+48]
        vinserti128	ymm2, ymm2, OWORD PTR [rcx+160], 1
        vinserti128	ymm3, ymm3, OWORD PTR [rcx+176], 1
        vpshufb	ymm2, ymm2, ymm15
        vpshufb	ymm3, ymm3, ymm15
        vmovdqu	xmm4, OWORD PTR [rcx+64]
        vmovdqu	xmm5, OWORD PTR [rcx+80]
        vinserti128	ymm4, ymm4, OWORD PTR [rcx+192], 1
        vinserti128	ymm5, ymm5, OWORD PTR [rcx+208], 1
        vpshufb	ymm4, ymm4, ymm15
        vpshufb	ymm5, ymm5, ymm15
        vmovdqu	xmm6, OWORD PTR [rcx+96]
        vmovdqu	xmm7, OWORD PTR [rcx+112]
        vinserti128	ymm6, ymm6, OWORD PTR [rcx+224], 1
        vinserti128	ymm7, ymm7, OWORD PTR [rcx+240], 1
        vpshufb	ymm6, ymm6, ymm15
        vpshufb	ymm7, ymm7, ymm15
        xor	rbx, r10
        ; Start of 16 rounds
L_sha512_len_avx2_start:
        vpaddq	ymm8, ymm0, [rsi]
        vpaddq	ymm9, ymm1, [rsi+32]
        vmovdqu	YMMWORD PTR [rbp], ymm8
        vmovdqu	YMMWORD PTR [rbp+32], ymm9
        vpaddq	ymm8, ymm2, [rsi+64]
        vpaddq	ymm9, ymm3, [rsi+96]
        vmovdqu	YMMWORD PTR [rbp+64], ymm8
        vmovdqu	YMMWORD PTR [rbp+96], ymm9
        vpaddq	ymm8, ymm4, [rsi+128]
        vpaddq	ymm9, ymm5, [rsi+160]
        vmovdqu	YMMWORD PTR [rbp+128], ymm8
        vmovdqu	YMMWORD PTR [rbp+160], ymm9
        vpaddq	ymm8, ymm6, [rsi+192]
        vpaddq	ymm9, ymm7, [rsi+224]
        vmovdqu	YMMWORD PTR [rbp+192], ymm8
        vmovdqu	YMMWORD PTR [rbp+224], ymm9
        ; msg_sched: 0-1
        ror	rax, 23
        vpalignr	ymm12, ymm1, ymm0, 8
        vpalignr	ymm13, ymm5, ymm4, 8
        mov	rdx, r8
        mov	rcx, r13
        add	r15, QWORD PTR [rbp]
        xor	rcx, r14
        vpsrlq	ymm8, ymm12, 1
        vpsllq	ymm9, ymm12, 63
        xor	rax, r12
        and	rcx, r12
        ror	rax, 4
        xor	rcx, r14
        vpsrlq	ymm10, ymm12, 8
        vpsllq	ymm11, ymm12, 56
        xor	rax, r12
        add	r15, rcx
        ror	rax, 14
        xor	rdx, r9
        vpor	ymm8, ymm8, ymm9
        vpor	ymm10, ymm10, ymm11
        add	r15, rax
        mov	rcx, r8
        and	rbx, rdx
        ror	rcx, 5
        vpsrlq	ymm11, ymm12, 7
        vpxor	ymm8, ymm8, ymm10
        xor	rcx, r8
        xor	rbx, r9
        ror	rcx, 6
        add	r11, r15
        vpxor	ymm8, ymm8, ymm11
        vpaddq	ymm0, ymm13, ymm0
        xor	rcx, r8
        add	r15, rbx
        ror	rcx, 28
        mov	rax, r11
        add	r15, rcx
        ror	rax, 23
        vpaddq	ymm0, ymm8, ymm0
        mov	rbx, r15
        mov	rcx, r12
        add	r14, QWORD PTR [rbp+8]
        xor	rcx, r13
        vpsrlq	ymm8, ymm7, 19
        vpsllq	ymm9, ymm7, 45
        xor	rax, r11
        and	rcx, r11
        ror	rax, 4
        xor	rcx, r13
        vpsrlq	ymm10, ymm7, 61
        vpsllq	ymm11, ymm7, 3
        xor	rax, r11
        add	r14, rcx
        ror	rax, 14
        xor	rbx, r8
        add	r14, rax
        mov	rcx, r15
        vpor	ymm8, ymm8, ymm9
        vpor	ymm10, ymm10, ymm11
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r15
        xor	rdx, r8
        vpxor	ymm8, ymm8, ymm10
        vpsrlq	ymm11, ymm7, 6
        ror	rcx, 6
        add	r10, r14
        xor	rcx, r15
        add	r14, rdx
        vpxor	ymm8, ymm8, ymm11
        ror	rcx, 28
        mov	rax, r10
        add	r14, rcx
        vpaddq	ymm0, ymm8, ymm0
        ; msg_sched done: 0-1
        ; msg_sched: 4-5
        ror	rax, 23
        vpalignr	ymm12, ymm2, ymm1, 8
        vpalignr	ymm13, ymm6, ymm5, 8
        mov	rdx, r14
        mov	rcx, r11
        add	r13, QWORD PTR [rbp+32]
        xor	rcx, r12
        vpsrlq	ymm8, ymm12, 1
        vpsllq	ymm9, ymm12, 63
        xor	rax, r10
        and	rcx, r10
        ror	rax, 4
        xor	rcx, r12
        vpsrlq	ymm10, ymm12, 8
        vpsllq	ymm11, ymm12, 56
        xor	rax, r10
        add	r13, rcx
        ror	rax, 14
        xor	rdx, r15
        vpor	ymm8, ymm8, ymm9
        vpor	ymm10, ymm10, ymm11
        add	r13, rax
        mov	rcx, r14
        and	rbx, rdx
        ror	rcx, 5
        vpsrlq	ymm11, ymm12, 7
        vpxor	ymm8, ymm8, ymm10
        xor	rcx, r14
        xor	rbx, r15
        ror	rcx, 6
        add	r9, r13
        vpxor	ymm8, ymm8, ymm11
        vpaddq	ymm1, ymm13, ymm1
        xor	rcx, r14
        add	r13, rbx
        ror	rcx, 28
        mov	rax, r9
        add	r13, rcx
        ror	rax, 23
        vpaddq	ymm1, ymm8, ymm1
        mov	rbx, r13
        mov	rcx, r10
        add	r12, QWORD PTR [rbp+40]
        xor	rcx, r11
        vpsrlq	ymm8, ymm0, 19
        vpsllq	ymm9, ymm0, 45
        xor	rax, r9
        and	rcx, r9
        ror	rax, 4
        xor	rcx, r11
        vpsrlq	ymm10, ymm0, 61
        vpsllq	ymm11, ymm0, 3
        xor	rax, r9
        add	r12, rcx
        ror	rax, 14
        xor	rbx, r14
        add	r12, rax
        mov	rcx, r13
        vpor	ymm8, ymm8, ymm9
        vpor	ymm10, ymm10, ymm11
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r13
        xor	rdx, r14
        vpxor	ymm8, ymm8, ymm10
        vpsrlq	ymm11, ymm0, 6
        ror	rcx, 6
        add	r8, r12
        xor	rcx, r13
        add	r12, rdx
        vpxor	ymm8, ymm8, ymm11
        ror	rcx, 28
        mov	rax, r8
        add	r12, rcx
        vpaddq	ymm1, ymm8, ymm1
        ; msg_sched done: 4-5
        ; msg_sched: 8-9
        ror	rax, 23
        vpalignr	ymm12, ymm3, ymm2, 8
        vpalignr	ymm13, ymm7, ymm6, 8
        mov	rdx, r12
        mov	rcx, r9
        add	r11, QWORD PTR [rbp+64]
        xor	rcx, r10
        vpsrlq	ymm8, ymm12, 1
        vpsllq	ymm9, ymm12, 63
        xor	rax, r8
        and	rcx, r8
        ror	rax, 4
        xor	rcx, r10
        vpsrlq	ymm10, ymm12, 8
        vpsllq	ymm11, ymm12, 56
        xor	rax, r8
        add	r11, rcx
        ror	rax, 14
        xor	rdx, r13
        vpor	ymm8, ymm8, ymm9
        vpor	ymm10, ymm10, ymm11
        add	r11, rax
        mov	rcx, r12
        and	rbx, rdx
        ror	rcx, 5
        vpsrlq	ymm11, ymm12, 7
        vpxor	ymm8, ymm8, ymm10
        xor	rcx, r12
        xor	rbx, r13
        ror	rcx, 6
        add	r15, r11
        vpxor	ymm8, ymm8, ymm11
        vpaddq	ymm2, ymm13, ymm2
        xor	rcx, r12
        add	r11, rbx
        ror	rcx, 28
        mov	rax, r15
        add	r11, rcx
        ror	rax, 23
        vpaddq	ymm2, ymm8, ymm2
        mov	rbx, r11
        mov	rcx, r8
        add	r10, QWORD PTR [rbp+72]
        xor	rcx, r9
        vpsrlq	ymm8, ymm1, 19
        vpsllq	ymm9, ymm1, 45
        xor	rax, r15
        and	rcx, r15
        ror	rax, 4
        xor	rcx, r9
        vpsrlq	ymm10, ymm1, 61
        vpsllq	ymm11, ymm1, 3
        xor	rax, r15
        add	r10, rcx
        ror	rax, 14
        xor	rbx, r12
        add	r10, rax
        mov	rcx, r11
        vpor	ymm8, ymm8, ymm9
        vpor	ymm10, ymm10, ymm11
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r11
        xor	rdx, r12
        vpxor	ymm8, ymm8, ymm10
        vpsrlq	ymm11, ymm1, 6
        ror	rcx, 6
        add	r14, r10
        xor	rcx, r11
        add	r10, rdx
        vpxor	ymm8, ymm8, ymm11
        ror	rcx, 28
        mov	rax, r14
        add	r10, rcx
        vpaddq	ymm2, ymm8, ymm2
        ; msg_sched done: 8-9
        ; msg_sched: 12-13
        ror	rax, 23
        vpalignr	ymm12, ymm4, ymm3, 8
        vpalignr	ymm13, ymm0, ymm7, 8
        mov	rdx, r10
        mov	rcx, r15
        add	r9, QWORD PTR [rbp+96]
        xor	rcx, r8
        vpsrlq	ymm8, ymm12, 1
        vpsllq	ymm9, ymm12, 63
        xor	rax, r14
        and	rcx, r14
        ror	rax, 4
        xor	rcx, r8
        vpsrlq	ymm10, ymm12, 8
        vpsllq	ymm11, ymm12, 56
        xor	rax, r14
        add	r9, rcx
        ror	rax, 14
        xor	rdx, r11
        vpor	ymm8, ymm8, ymm9
        vpor	ymm10, ymm10, ymm11
        add	r9, rax
        mov	rcx, r10
        and	rbx, rdx
        ror	rcx, 5
        vpsrlq	ymm11, ymm12, 7
        vpxor	ymm8, ymm8, ymm10
        xor	rcx, r10
        xor	rbx, r11
        ror	rcx, 6
        add	r13, r9
        vpxor	ymm8, ymm8, ymm11
        vpaddq	ymm3, ymm13, ymm3
        xor	rcx, r10
        add	r9, rbx
        ror	rcx, 28
        mov	rax, r13
        add	r9, rcx
        ror	rax, 23
        vpaddq	ymm3, ymm8, ymm3
        mov	rbx, r9
        mov	rcx, r14
        add	r8, QWORD PTR [rbp+104]
        xor	rcx, r15
        vpsrlq	ymm8, ymm2, 19
        vpsllq	ymm9, ymm2, 45
        xor	rax, r13
        and	rcx, r13
        ror	rax, 4
        xor	rcx, r15
        vpsrlq	ymm10, ymm2, 61
        vpsllq	ymm11, ymm2, 3
        xor	rax, r13
        add	r8, rcx
        ror	rax, 14
        xor	rbx, r10
        add	r8, rax
        mov	rcx, r9
        vpor	ymm8, ymm8, ymm9
        vpor	ymm10, ymm10, ymm11
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r9
        xor	rdx, r10
        vpxor	ymm8, ymm8, ymm10
        vpsrlq	ymm11, ymm2, 6
        ror	rcx, 6
        add	r12, r8
        xor	rcx, r9
        add	r8, rdx
        vpxor	ymm8, ymm8, ymm11
        ror	rcx, 28
        mov	rax, r12
        add	r8, rcx
        vpaddq	ymm3, ymm8, ymm3
        ; msg_sched done: 12-13
        ; msg_sched: 16-17
        ror	rax, 23
        vpalignr	ymm12, ymm5, ymm4, 8
        vpalignr	ymm13, ymm1, ymm0, 8
        mov	rdx, r8
        mov	rcx, r13
        add	r15, QWORD PTR [rbp+128]
        xor	rcx, r14
        vpsrlq	ymm8, ymm12, 1
        vpsllq	ymm9, ymm12, 63
        xor	rax, r12
        and	rcx, r12
        ror	rax, 4
        xor	rcx, r14
        vpsrlq	ymm10, ymm12, 8
        vpsllq	ymm11, ymm12, 56
        xor	rax, r12
        add	r15, rcx
        ror	rax, 14
        xor	rdx, r9
        vpor	ymm8, ymm8, ymm9
        vpor	ymm10, ymm10, ymm11
        add	r15, rax
        mov	rcx, r8
        and	rbx, rdx
        ror	rcx, 5
        vpsrlq	ymm11, ymm12, 7
        vpxor	ymm8, ymm8, ymm10
        xor	rcx, r8
        xor	rbx, r9
        ror	rcx, 6
        add	r11, r15
        vpxor	ymm8, ymm8, ymm11
        vpaddq	ymm4, ymm13, ymm4
        xor	rcx, r8
        add	r15, rbx
        ror	rcx, 28
        mov	rax, r11
        add	r15, rcx
        ror	rax, 23
        vpaddq	ymm4, ymm8, ymm4
        mov	rbx, r15
        mov	rcx, r12
        add	r14, QWORD PTR [rbp+136]
        xor	rcx, r13
        vpsrlq	ymm8, ymm3, 19
        vpsllq	ymm9, ymm3, 45
        xor	rax, r11
        and	rcx, r11
        ror	rax, 4
        xor	rcx, r13
        vpsrlq	ymm10, ymm3, 61
        vpsllq	ymm11, ymm3, 3
        xor	rax, r11
        add	r14, rcx
        ror	rax, 14
        xor	rbx, r8
        add	r14, rax
        mov	rcx, r15
        vpor	ymm8, ymm8, ymm9
        vpor	ymm10, ymm10, ymm11
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r15
        xor	rdx, r8
        vpxor	ymm8, ymm8, ymm10
        vpsrlq	ymm11, ymm3, 6
        ror	rcx, 6
        add	r10, r14
        xor	rcx, r15
        add	r14, rdx
        vpxor	ymm8, ymm8, ymm11
        ror	rcx, 28
        mov	rax, r10
        add	r14, rcx
        vpaddq	ymm4, ymm8, ymm4
        ; msg_sched done: 16-17
        ; msg_sched: 20-21
        ror	rax, 23
        vpalignr	ymm12, ymm6, ymm5, 8
        vpalignr	ymm13, ymm2, ymm1, 8
        mov	rdx, r14
        mov	rcx, r11
        add	r13, QWORD PTR [rbp+160]
        xor	rcx, r12
        vpsrlq	ymm8, ymm12, 1
        vpsllq	ymm9, ymm12, 63
        xor	rax, r10
        and	rcx, r10
        ror	rax, 4
        xor	rcx, r12
        vpsrlq	ymm10, ymm12, 8
        vpsllq	ymm11, ymm12, 56
        xor	rax, r10
        add	r13, rcx
        ror	rax, 14
        xor	rdx, r15
        vpor	ymm8, ymm8, ymm9
        vpor	ymm10, ymm10, ymm11
        add	r13, rax
        mov	rcx, r14
        and	rbx, rdx
        ror	rcx, 5
        vpsrlq	ymm11, ymm12, 7
        vpxor	ymm8, ymm8, ymm10
        xor	rcx, r14
        xor	rbx, r15
        ror	rcx, 6
        add	r9, r13
        vpxor	ymm8, ymm8, ymm11
        vpaddq	ymm5, ymm13, ymm5
        xor	rcx, r14
        add	r13, rbx
        ror	rcx, 28
        mov	rax, r9
        add	r13, rcx
        ror	rax, 23
        vpaddq	ymm5, ymm8, ymm5
        mov	rbx, r13
        mov	rcx, r10
        add	r12, QWORD PTR [rbp+168]
        xor	rcx, r11
        vpsrlq	ymm8, ymm4, 19
        vpsllq	ymm9, ymm4, 45
        xor	rax, r9
        and	rcx, r9
        ror	rax, 4
        xor	rcx, r11
        vpsrlq	ymm10, ymm4, 61
        vpsllq	ymm11, ymm4, 3
        xor	rax, r9
        add	r12, rcx
        ror	rax, 14
        xor	rbx, r14
        add	r12, rax
        mov	rcx, r13
        vpor	ymm8, ymm8, ymm9
        vpor	ymm10, ymm10, ymm11
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r13
        xor	rdx, r14
        vpxor	ymm8, ymm8, ymm10
        vpsrlq	ymm11, ymm4, 6
        ror	rcx, 6
        add	r8, r12
        xor	rcx, r13
        add	r12, rdx
        vpxor	ymm8, ymm8, ymm11
        ror	rcx, 28
        mov	rax, r8
        add	r12, rcx
        vpaddq	ymm5, ymm8, ymm5
        ; msg_sched done: 20-21
        ; msg_sched: 24-25
        ror	rax, 23
        vpalignr	ymm12, ymm7, ymm6, 8
        vpalignr	ymm13, ymm3, ymm2, 8
        mov	rdx, r12
        mov	rcx, r9
        add	r11, QWORD PTR [rbp+192]
        xor	rcx, r10
        vpsrlq	ymm8, ymm12, 1
        vpsllq	ymm9, ymm12, 63
        xor	rax, r8
        and	rcx, r8
        ror	rax, 4
        xor	rcx, r10
        vpsrlq	ymm10, ymm12, 8
        vpsllq	ymm11, ymm12, 56
        xor	rax, r8
        add	r11, rcx
        ror	rax, 14
        xor	rdx, r13
        vpor	ymm8, ymm8, ymm9
        vpor	ymm10, ymm10, ymm11
        add	r11, rax
        mov	rcx, r12
        and	rbx, rdx
        ror	rcx, 5
        vpsrlq	ymm11, ymm12, 7
        vpxor	ymm8, ymm8, ymm10
        xor	rcx, r12
        xor	rbx, r13
        ror	rcx, 6
        add	r15, r11
        vpxor	ymm8, ymm8, ymm11
        vpaddq	ymm6, ymm13, ymm6
        xor	rcx, r12
        add	r11, rbx
        ror	rcx, 28
        mov	rax, r15
        add	r11, rcx
        ror	rax, 23
        vpaddq	ymm6, ymm8, ymm6
        mov	rbx, r11
        mov	rcx, r8
        add	r10, QWORD PTR [rbp+200]
        xor	rcx, r9
        vpsrlq	ymm8, ymm5, 19
        vpsllq	ymm9, ymm5, 45
        xor	rax, r15
        and	rcx, r15
        ror	rax, 4
        xor	rcx, r9
        vpsrlq	ymm10, ymm5, 61
        vpsllq	ymm11, ymm5, 3
        xor	rax, r15
        add	r10, rcx
        ror	rax, 14
        xor	rbx, r12
        add	r10, rax
        mov	rcx, r11
        vpor	ymm8, ymm8, ymm9
        vpor	ymm10, ymm10, ymm11
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r11
        xor	rdx, r12
        vpxor	ymm8, ymm8, ymm10
        vpsrlq	ymm11, ymm5, 6
        ror	rcx, 6
        add	r14, r10
        xor	rcx, r11
        add	r10, rdx
        vpxor	ymm8, ymm8, ymm11
        ror	rcx, 28
        mov	rax, r14
        add	r10, rcx
        vpaddq	ymm6, ymm8, ymm6
        ; msg_sched done: 24-25
        ; msg_sched: 28-29
        ror	rax, 23
        vpalignr	ymm12, ymm0, ymm7, 8
        vpalignr	ymm13, ymm4, ymm3, 8
        mov	rdx, r10
        mov	rcx, r15
        add	r9, QWORD PTR [rbp+224]
        xor	rcx, r8
        vpsrlq	ymm8, ymm12, 1
        vpsllq	ymm9, ymm12, 63
        xor	rax, r14
        and	rcx, r14
        ror	rax, 4
        xor	rcx, r8
        vpsrlq	ymm10, ymm12, 8
        vpsllq	ymm11, ymm12, 56
        xor	rax, r14
        add	r9, rcx
        ror	rax, 14
        xor	rdx, r11
        vpor	ymm8, ymm8, ymm9
        vpor	ymm10, ymm10, ymm11
        add	r9, rax
        mov	rcx, r10
        and	rbx, rdx
        ror	rcx, 5
        vpsrlq	ymm11, ymm12, 7
        vpxor	ymm8, ymm8, ymm10
        xor	rcx, r10
        xor	rbx, r11
        ror	rcx, 6
        add	r13, r9
        vpxor	ymm8, ymm8, ymm11
        vpaddq	ymm7, ymm13, ymm7
        xor	rcx, r10
        add	r9, rbx
        ror	rcx, 28
        mov	rax, r13
        add	r9, rcx
        ror	rax, 23
        vpaddq	ymm7, ymm8, ymm7
        mov	rbx, r9
        mov	rcx, r14
        add	r8, QWORD PTR [rbp+232]
        xor	rcx, r15
        vpsrlq	ymm8, ymm6, 19
        vpsllq	ymm9, ymm6, 45
        xor	rax, r13
        and	rcx, r13
        ror	rax, 4
        xor	rcx, r15
        vpsrlq	ymm10, ymm6, 61
        vpsllq	ymm11, ymm6, 3
        xor	rax, r13
        add	r8, rcx
        ror	rax, 14
        xor	rbx, r10
        add	r8, rax
        mov	rcx, r9
        vpor	ymm8, ymm8, ymm9
        vpor	ymm10, ymm10, ymm11
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r9
        xor	rdx, r10
        vpxor	ymm8, ymm8, ymm10
        vpsrlq	ymm11, ymm6, 6
        ror	rcx, 6
        add	r12, r8
        xor	rcx, r9
        add	r8, rdx
        vpxor	ymm8, ymm8, ymm11
        ror	rcx, 28
        mov	rax, r12
        add	r8, rcx
        vpaddq	ymm7, ymm8, ymm7
        ; msg_sched done: 28-29
        add	rsi, 256
        add	rbp, 256
        cmp	rsi, QWORD PTR [L_avx2_sha512_k_2_end]
        jne	L_sha512_len_avx2_start
        vpaddq	ymm8, ymm0, [rsi]
        vpaddq	ymm9, ymm1, [rsi+32]
        vmovdqu	YMMWORD PTR [rbp], ymm8
        vmovdqu	YMMWORD PTR [rbp+32], ymm9
        vpaddq	ymm8, ymm2, [rsi+64]
        vpaddq	ymm9, ymm3, [rsi+96]
        vmovdqu	YMMWORD PTR [rbp+64], ymm8
        vmovdqu	YMMWORD PTR [rbp+96], ymm9
        vpaddq	ymm8, ymm4, [rsi+128]
        vpaddq	ymm9, ymm5, [rsi+160]
        vmovdqu	YMMWORD PTR [rbp+128], ymm8
        vmovdqu	YMMWORD PTR [rbp+160], ymm9
        vpaddq	ymm8, ymm6, [rsi+192]
        vpaddq	ymm9, ymm7, [rsi+224]
        vmovdqu	YMMWORD PTR [rbp+192], ymm8
        vmovdqu	YMMWORD PTR [rbp+224], ymm9
        ror	rax, 23
        mov	rdx, r8
        mov	rcx, r13
        add	r15, QWORD PTR [rbp]
        xor	rcx, r14
        xor	rax, r12
        and	rcx, r12
        ror	rax, 4
        xor	rcx, r14
        xor	rax, r12
        add	r15, rcx
        ror	rax, 14
        xor	rdx, r9
        add	r15, rax
        mov	rcx, r8
        and	rbx, rdx
        ror	rcx, 5
        xor	rcx, r8
        xor	rbx, r9
        ror	rcx, 6
        add	r11, r15
        xor	rcx, r8
        add	r15, rbx
        ror	rcx, 28
        mov	rax, r11
        add	r15, rcx
        ror	rax, 23
        mov	rbx, r15
        mov	rcx, r12
        add	r14, QWORD PTR [rbp+8]
        xor	rcx, r13
        xor	rax, r11
        and	rcx, r11
        ror	rax, 4
        xor	rcx, r13
        xor	rax, r11
        add	r14, rcx
        ror	rax, 14
        xor	rbx, r8
        add	r14, rax
        mov	rcx, r15
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r15
        xor	rdx, r8
        ror	rcx, 6
        add	r10, r14
        xor	rcx, r15
        add	r14, rdx
        ror	rcx, 28
        mov	rax, r10
        add	r14, rcx
        ror	rax, 23
        mov	rdx, r14
        mov	rcx, r11
        add	r13, QWORD PTR [rbp+32]
        xor	rcx, r12
        xor	rax, r10
        and	rcx, r10
        ror	rax, 4
        xor	rcx, r12
        xor	rax, r10
        add	r13, rcx
        ror	rax, 14
        xor	rdx, r15
        add	r13, rax
        mov	rcx, r14
        and	rbx, rdx
        ror	rcx, 5
        xor	rcx, r14
        xor	rbx, r15
        ror	rcx, 6
        add	r9, r13
        xor	rcx, r14
        add	r13, rbx
        ror	rcx, 28
        mov	rax, r9
        add	r13, rcx
        ror	rax, 23
        mov	rbx, r13
        mov	rcx, r10
        add	r12, QWORD PTR [rbp+40]
        xor	rcx, r11
        xor	rax, r9
        and	rcx, r9
        ror	rax, 4
        xor	rcx, r11
        xor	rax, r9
        add	r12, rcx
        ror	rax, 14
        xor	rbx, r14
        add	r12, rax
        mov	rcx, r13
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r13
        xor	rdx, r14
        ror	rcx, 6
        add	r8, r12
        xor	rcx, r13
        add	r12, rdx
        ror	rcx, 28
        mov	rax, r8
        add	r12, rcx
        ror	rax, 23
        mov	rdx, r12
        mov	rcx, r9
        add	r11, QWORD PTR [rbp+64]
        xor	rcx, r10
        xor	rax, r8
        and	rcx, r8
        ror	rax, 4
        xor	rcx, r10
        xor	rax, r8
        add	r11, rcx
        ror	rax, 14
        xor	rdx, r13
        add	r11, rax
        mov	rcx, r12
        and	rbx, rdx
        ror	rcx, 5
        xor	rcx, r12
        xor	rbx, r13
        ror	rcx, 6
        add	r15, r11
        xor	rcx, r12
        add	r11, rbx
        ror	rcx, 28
        mov	rax, r15
        add	r11, rcx
        ror	rax, 23
        mov	rbx, r11
        mov	rcx, r8
        add	r10, QWORD PTR [rbp+72]
        xor	rcx, r9
        xor	rax, r15
        and	rcx, r15
        ror	rax, 4
        xor	rcx, r9
        xor	rax, r15
        add	r10, rcx
        ror	rax, 14
        xor	rbx, r12
        add	r10, rax
        mov	rcx, r11
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r11
        xor	rdx, r12
        ror	rcx, 6
        add	r14, r10
        xor	rcx, r11
        add	r10, rdx
        ror	rcx, 28
        mov	rax, r14
        add	r10, rcx
        ror	rax, 23
        mov	rdx, r10
        mov	rcx, r15
        add	r9, QWORD PTR [rbp+96]
        xor	rcx, r8
        xor	rax, r14
        and	rcx, r14
        ror	rax, 4
        xor	rcx, r8
        xor	rax, r14
        add	r9, rcx
        ror	rax, 14
        xor	rdx, r11
        add	r9, rax
        mov	rcx, r10
        and	rbx, rdx
        ror	rcx, 5
        xor	rcx, r10
        xor	rbx, r11
        ror	rcx, 6
        add	r13, r9
        xor	rcx, r10
        add	r9, rbx
        ror	rcx, 28
        mov	rax, r13
        add	r9, rcx
        ror	rax, 23
        mov	rbx, r9
        mov	rcx, r14
        add	r8, QWORD PTR [rbp+104]
        xor	rcx, r15
        xor	rax, r13
        and	rcx, r13
        ror	rax, 4
        xor	rcx, r15
        xor	rax, r13
        add	r8, rcx
        ror	rax, 14
        xor	rbx, r10
        add	r8, rax
        mov	rcx, r9
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r9
        xor	rdx, r10
        ror	rcx, 6
        add	r12, r8
        xor	rcx, r9
        add	r8, rdx
        ror	rcx, 28
        mov	rax, r12
        add	r8, rcx
        ror	rax, 23
        mov	rdx, r8
        mov	rcx, r13
        add	r15, QWORD PTR [rbp+128]
        xor	rcx, r14
        xor	rax, r12
        and	rcx, r12
        ror	rax, 4
        xor	rcx, r14
        xor	rax, r12
        add	r15, rcx
        ror	rax, 14
        xor	rdx, r9
        add	r15, rax
        mov	rcx, r8
        and	rbx, rdx
        ror	rcx, 5
        xor	rcx, r8
        xor	rbx, r9
        ror	rcx, 6
        add	r11, r15
        xor	rcx, r8
        add	r15, rbx
        ror	rcx, 28
        mov	rax, r11
        add	r15, rcx
        ror	rax, 23
        mov	rbx, r15
        mov	rcx, r12
        add	r14, QWORD PTR [rbp+136]
        xor	rcx, r13
        xor	rax, r11
        and	rcx, r11
        ror	rax, 4
        xor	rcx, r13
        xor	rax, r11
        add	r14, rcx
        ror	rax, 14
        xor	rbx, r8
        add	r14, rax
        mov	rcx, r15
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r15
        xor	rdx, r8
        ror	rcx, 6
        add	r10, r14
        xor	rcx, r15
        add	r14, rdx
        ror	rcx, 28
        mov	rax, r10
        add	r14, rcx
        ror	rax, 23
        mov	rdx, r14
        mov	rcx, r11
        add	r13, QWORD PTR [rbp+160]
        xor	rcx, r12
        xor	rax, r10
        and	rcx, r10
        ror	rax, 4
        xor	rcx, r12
        xor	rax, r10
        add	r13, rcx
        ror	rax, 14
        xor	rdx, r15
        add	r13, rax
        mov	rcx, r14
        and	rbx, rdx
        ror	rcx, 5
        xor	rcx, r14
        xor	rbx, r15
        ror	rcx, 6
        add	r9, r13
        xor	rcx, r14
        add	r13, rbx
        ror	rcx, 28
        mov	rax, r9
        add	r13, rcx
        ror	rax, 23
        mov	rbx, r13
        mov	rcx, r10
        add	r12, QWORD PTR [rbp+168]
        xor	rcx, r11
        xor	rax, r9
        and	rcx, r9
        ror	rax, 4
        xor	rcx, r11
        xor	rax, r9
        add	r12, rcx
        ror	rax, 14
        xor	rbx, r14
        add	r12, rax
        mov	rcx, r13
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r13
        xor	rdx, r14
        ror	rcx, 6
        add	r8, r12
        xor	rcx, r13
        add	r12, rdx
        ror	rcx, 28
        mov	rax, r8
        add	r12, rcx
        ror	rax, 23
        mov	rdx, r12
        mov	rcx, r9
        add	r11, QWORD PTR [rbp+192]
        xor	rcx, r10
        xor	rax, r8
        and	rcx, r8
        ror	rax, 4
        xor	rcx, r10
        xor	rax, r8
        add	r11, rcx
        ror	rax, 14
        xor	rdx, r13
        add	r11, rax
        mov	rcx, r12
        and	rbx, rdx
        ror	rcx, 5
        xor	rcx, r12
        xor	rbx, r13
        ror	rcx, 6
        add	r15, r11
        xor	rcx, r12
        add	r11, rbx
        ror	rcx, 28
        mov	rax, r15
        add	r11, rcx
        ror	rax, 23
        mov	rbx, r11
        mov	rcx, r8
        add	r10, QWORD PTR [rbp+200]
        xor	rcx, r9
        xor	rax, r15
        and	rcx, r15
        ror	rax, 4
        xor	rcx, r9
        xor	rax, r15
        add	r10, rcx
        ror	rax, 14
        xor	rbx, r12
        add	r10, rax
        mov	rcx, r11
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r11
        xor	rdx, r12
        ror	rcx, 6
        add	r14, r10
        xor	rcx, r11
        add	r10, rdx
        ror	rcx, 28
        mov	rax, r14
        add	r10, rcx
        ror	rax, 23
        mov	rdx, r10
        mov	rcx, r15
        add	r9, QWORD PTR [rbp+224]
        xor	rcx, r8
        xor	rax, r14
        and	rcx, r14
        ror	rax, 4
        xor	rcx, r8
        xor	rax, r14
        add	r9, rcx
        ror	rax, 14
        xor	rdx, r11
        add	r9, rax
        mov	rcx, r10
        and	rbx, rdx
        ror	rcx, 5
        xor	rcx, r10
        xor	rbx, r11
        ror	rcx, 6
        add	r13, r9
        xor	rcx, r10
        add	r9, rbx
        ror	rcx, 28
        mov	rax, r13
        add	r9, rcx
        ror	rax, 23
        mov	rbx, r9
        mov	rcx, r14
        add	r8, QWORD PTR [rbp+232]
        xor	rcx, r15
        xor	rax, r13
        and	rcx, r13
        ror	rax, 4
        xor	rcx, r15
        xor	rax, r13
        add	r8, rcx
        ror	rax, 14
        xor	rbx, r10
        add	r8, rax
        mov	rcx, r9
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r9
        xor	rdx, r10
        ror	rcx, 6
        add	r12, r8
        xor	rcx, r9
        add	r8, rdx
        ror	rcx, 28
        mov	rax, r12
        add	r8, rcx
        sub	rbp, 1024
        add	r8, QWORD PTR [rdi]
        add	r9, QWORD PTR [rdi+8]
        add	r10, QWORD PTR [rdi+16]
        add	r11, QWORD PTR [rdi+24]
        add	r12, QWORD PTR [rdi+32]
        add	r13, QWORD PTR [rdi+40]
        add	r14, QWORD PTR [rdi+48]
        add	r15, QWORD PTR [rdi+56]
        mov	QWORD PTR [rdi], r8
        mov	QWORD PTR [rdi+8], r9
        mov	QWORD PTR [rdi+16], r10
        mov	QWORD PTR [rdi+24], r11
        mov	QWORD PTR [rdi+32], r12
        mov	QWORD PTR [rdi+40], r13
        mov	QWORD PTR [rdi+48], r14
        mov	QWORD PTR [rdi+56], r15
        mov	rbx, r9
        mov	rax, r12
        xor	rbx, r10
        mov	rsi, 5
L_sha512_len_avx2_tail:
        ror	rax, 23
        mov	rdx, r8
        mov	rcx, r13
        add	r15, QWORD PTR [rbp+16]
        xor	rcx, r14
        xor	rax, r12
        and	rcx, r12
        ror	rax, 4
        xor	rcx, r14
        xor	rax, r12
        add	r15, rcx
        ror	rax, 14
        xor	rdx, r9
        add	r15, rax
        mov	rcx, r8
        and	rbx, rdx
        ror	rcx, 5
        xor	rcx, r8
        xor	rbx, r9
        ror	rcx, 6
        add	r11, r15
        xor	rcx, r8
        add	r15, rbx
        ror	rcx, 28
        mov	rax, r11
        add	r15, rcx
        ror	rax, 23
        mov	rbx, r15
        mov	rcx, r12
        add	r14, QWORD PTR [rbp+24]
        xor	rcx, r13
        xor	rax, r11
        and	rcx, r11
        ror	rax, 4
        xor	rcx, r13
        xor	rax, r11
        add	r14, rcx
        ror	rax, 14
        xor	rbx, r8
        add	r14, rax
        mov	rcx, r15
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r15
        xor	rdx, r8
        ror	rcx, 6
        add	r10, r14
        xor	rcx, r15
        add	r14, rdx
        ror	rcx, 28
        mov	rax, r10
        add	r14, rcx
        ror	rax, 23
        mov	rdx, r14
        mov	rcx, r11
        add	r13, QWORD PTR [rbp+48]
        xor	rcx, r12
        xor	rax, r10
        and	rcx, r10
        ror	rax, 4
        xor	rcx, r12
        xor	rax, r10
        add	r13, rcx
        ror	rax, 14
        xor	rdx, r15
        add	r13, rax
        mov	rcx, r14
        and	rbx, rdx
        ror	rcx, 5
        xor	rcx, r14
        xor	rbx, r15
        ror	rcx, 6
        add	r9, r13
        xor	rcx, r14
        add	r13, rbx
        ror	rcx, 28
        mov	rax, r9
        add	r13, rcx
        ror	rax, 23
        mov	rbx, r13
        mov	rcx, r10
        add	r12, QWORD PTR [rbp+56]
        xor	rcx, r11
        xor	rax, r9
        and	rcx, r9
        ror	rax, 4
        xor	rcx, r11
        xor	rax, r9
        add	r12, rcx
        ror	rax, 14
        xor	rbx, r14
        add	r12, rax
        mov	rcx, r13
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r13
        xor	rdx, r14
        ror	rcx, 6
        add	r8, r12
        xor	rcx, r13
        add	r12, rdx
        ror	rcx, 28
        mov	rax, r8
        add	r12, rcx
        ror	rax, 23
        mov	rdx, r12
        mov	rcx, r9
        add	r11, QWORD PTR [rbp+80]
        xor	rcx, r10
        xor	rax, r8
        and	rcx, r8
        ror	rax, 4
        xor	rcx, r10
        xor	rax, r8
        add	r11, rcx
        ror	rax, 14
        xor	rdx, r13
        add	r11, rax
        mov	rcx, r12
        and	rbx, rdx
        ror	rcx, 5
        xor	rcx, r12
        xor	rbx, r13
        ror	rcx, 6
        add	r15, r11
        xor	rcx, r12
        add	r11, rbx
        ror	rcx, 28
        mov	rax, r15
        add	r11, rcx
        ror	rax, 23
        mov	rbx, r11
        mov	rcx, r8
        add	r10, QWORD PTR [rbp+88]
        xor	rcx, r9
        xor	rax, r15
        and	rcx, r15
        ror	rax, 4
        xor	rcx, r9
        xor	rax, r15
        add	r10, rcx
        ror	rax, 14
        xor	rbx, r12
        add	r10, rax
        mov	rcx, r11
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r11
        xor	rdx, r12
        ror	rcx, 6
        add	r14, r10
        xor	rcx, r11
        add	r10, rdx
        ror	rcx, 28
        mov	rax, r14
        add	r10, rcx
        ror	rax, 23
        mov	rdx, r10
        mov	rcx, r15
        add	r9, QWORD PTR [rbp+112]
        xor	rcx, r8
        xor	rax, r14
        and	rcx, r14
        ror	rax, 4
        xor	rcx, r8
        xor	rax, r14
        add	r9, rcx
        ror	rax, 14
        xor	rdx, r11
        add	r9, rax
        mov	rcx, r10
        and	rbx, rdx
        ror	rcx, 5
        xor	rcx, r10
        xor	rbx, r11
        ror	rcx, 6
        add	r13, r9
        xor	rcx, r10
        add	r9, rbx
        ror	rcx, 28
        mov	rax, r13
        add	r9, rcx
        ror	rax, 23
        mov	rbx, r9
        mov	rcx, r14
        add	r8, QWORD PTR [rbp+120]
        xor	rcx, r15
        xor	rax, r13
        and	rcx, r13
        ror	rax, 4
        xor	rcx, r15
        xor	rax, r13
        add	r8, rcx
        ror	rax, 14
        xor	rbx, r10
        add	r8, rax
        mov	rcx, r9
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r9
        xor	rdx, r10
        ror	rcx, 6
        add	r12, r8
        xor	rcx, r9
        add	r8, rdx
        ror	rcx, 28
        mov	rax, r12
        add	r8, rcx
        ror	rax, 23
        mov	rdx, r8
        mov	rcx, r13
        add	r15, QWORD PTR [rbp+144]
        xor	rcx, r14
        xor	rax, r12
        and	rcx, r12
        ror	rax, 4
        xor	rcx, r14
        xor	rax, r12
        add	r15, rcx
        ror	rax, 14
        xor	rdx, r9
        add	r15, rax
        mov	rcx, r8
        and	rbx, rdx
        ror	rcx, 5
        xor	rcx, r8
        xor	rbx, r9
        ror	rcx, 6
        add	r11, r15
        xor	rcx, r8
        add	r15, rbx
        ror	rcx, 28
        mov	rax, r11
        add	r15, rcx
        ror	rax, 23
        mov	rbx, r15
        mov	rcx, r12
        add	r14, QWORD PTR [rbp+152]
        xor	rcx, r13
        xor	rax, r11
        and	rcx, r11
        ror	rax, 4
        xor	rcx, r13
        xor	rax, r11
        add	r14, rcx
        ror	rax, 14
        xor	rbx, r8
        add	r14, rax
        mov	rcx, r15
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r15
        xor	rdx, r8
        ror	rcx, 6
        add	r10, r14
        xor	rcx, r15
        add	r14, rdx
        ror	rcx, 28
        mov	rax, r10
        add	r14, rcx
        ror	rax, 23
        mov	rdx, r14
        mov	rcx, r11
        add	r13, QWORD PTR [rbp+176]
        xor	rcx, r12
        xor	rax, r10
        and	rcx, r10
        ror	rax, 4
        xor	rcx, r12
        xor	rax, r10
        add	r13, rcx
        ror	rax, 14
        xor	rdx, r15
        add	r13, rax
        mov	rcx, r14
        and	rbx, rdx
        ror	rcx, 5
        xor	rcx, r14
        xor	rbx, r15
        ror	rcx, 6
        add	r9, r13
        xor	rcx, r14
        add	r13, rbx
        ror	rcx, 28
        mov	rax, r9
        add	r13, rcx
        ror	rax, 23
        mov	rbx, r13
        mov	rcx, r10
        add	r12, QWORD PTR [rbp+184]
        xor	rcx, r11
        xor	rax, r9
        and	rcx, r9
        ror	rax, 4
        xor	rcx, r11
        xor	rax, r9
        add	r12, rcx
        ror	rax, 14
        xor	rbx, r14
        add	r12, rax
        mov	rcx, r13
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r13
        xor	rdx, r14
        ror	rcx, 6
        add	r8, r12
        xor	rcx, r13
        add	r12, rdx
        ror	rcx, 28
        mov	rax, r8
        add	r12, rcx
        ror	rax, 23
        mov	rdx, r12
        mov	rcx, r9
        add	r11, QWORD PTR [rbp+208]
        xor	rcx, r10
        xor	rax, r8
        and	rcx, r8
        ror	rax, 4
        xor	rcx, r10
        xor	rax, r8
        add	r11, rcx
        ror	rax, 14
        xor	rdx, r13
        add	r11, rax
        mov	rcx, r12
        and	rbx, rdx
        ror	rcx, 5
        xor	rcx, r12
        xor	rbx, r13
        ror	rcx, 6
        add	r15, r11
        xor	rcx, r12
        add	r11, rbx
        ror	rcx, 28
        mov	rax, r15
        add	r11, rcx
        ror	rax, 23
        mov	rbx, r11
        mov	rcx, r8
        add	r10, QWORD PTR [rbp+216]
        xor	rcx, r9
        xor	rax, r15
        and	rcx, r15
        ror	rax, 4
        xor	rcx, r9
        xor	rax, r15
        add	r10, rcx
        ror	rax, 14
        xor	rbx, r12
        add	r10, rax
        mov	rcx, r11
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r11
        xor	rdx, r12
        ror	rcx, 6
        add	r14, r10
        xor	rcx, r11
        add	r10, rdx
        ror	rcx, 28
        mov	rax, r14
        add	r10, rcx
        ror	rax, 23
        mov	rdx, r10
        mov	rcx, r15
        add	r9, QWORD PTR [rbp+240]
        xor	rcx, r8
        xor	rax, r14
        and	rcx, r14
        ror	rax, 4
        xor	rcx, r8
        xor	rax, r14
        add	r9, rcx
        ror	rax, 14
        xor	rdx, r11
        add	r9, rax
        mov	rcx, r10
        and	rbx, rdx
        ror	rcx, 5
        xor	rcx, r10
        xor	rbx, r11
        ror	rcx, 6
        add	r13, r9
        xor	rcx, r10
        add	r9, rbx
        ror	rcx, 28
        mov	rax, r13
        add	r9, rcx
        ror	rax, 23
        mov	rbx, r9
        mov	rcx, r14
        add	r8, QWORD PTR [rbp+248]
        xor	rcx, r15
        xor	rax, r13
        and	rcx, r13
        ror	rax, 4
        xor	rcx, r15
        xor	rax, r13
        add	r8, rcx
        ror	rax, 14
        xor	rbx, r10
        add	r8, rax
        mov	rcx, r9
        and	rdx, rbx
        ror	rcx, 5
        xor	rcx, r9
        xor	rdx, r10
        ror	rcx, 6
        add	r12, r8
        xor	rcx, r9
        add	r8, rdx
        ror	rcx, 28
        mov	rax, r12
        add	r8, rcx
        add	rbp, 256
        sub	rsi, 1
        jnz	L_sha512_len_avx2_tail
        add	r8, QWORD PTR [rdi]
        add	r9, QWORD PTR [rdi+8]
        add	r10, QWORD PTR [rdi+16]
        add	r11, QWORD PTR [rdi+24]
        add	r12, QWORD PTR [rdi+32]
        add	r13, QWORD PTR [rdi+40]
        add	r14, QWORD PTR [rdi+48]
        add	r15, QWORD PTR [rdi+56]
        mov	rcx, QWORD PTR [rdi+224]
        add	rcx, 256
        sub	DWORD PTR [rsp+1344], 256
        mov	QWORD PTR [rdi+224], rcx
        mov	QWORD PTR [rdi], r8
        mov	QWORD PTR [rdi+8], r9
        mov	QWORD PTR [rdi+16], r10
        mov	QWORD PTR [rdi+24], r11
        mov	QWORD PTR [rdi+32], r12
        mov	QWORD PTR [rdi+40], r13
        mov	QWORD PTR [rdi+48], r14
        mov	QWORD PTR [rdi+56], r15
        jnz	L_sha512_len_avx2_begin
        add	rsp, 1352
L_sha512_len_avx2_done:
        xor	rax, rax
        vzeroupper
        vmovdqu	xmm6, OWORD PTR [rsp]
        vmovdqu	xmm7, OWORD PTR [rsp+16]
        vmovdqu	xmm8, OWORD PTR [rsp+32]
        vmovdqu	xmm9, OWORD PTR [rsp+48]
        vmovdqu	xmm10, OWORD PTR [rsp+64]
        vmovdqu	xmm11, OWORD PTR [rsp+80]
        vmovdqu	xmm14, OWORD PTR [rsp+96]
        vmovdqu	xmm13, OWORD PTR [rsp+112]
        vmovdqu	xmm12, OWORD PTR [rsp+128]
        vmovdqu	xmm15, OWORD PTR [rsp+144]
        add	rsp, 160
        pop	rbp
        pop	rdi
        pop	rsi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        pop	rbx
        ret
Transform_Sha512_AVX2_Len ENDP
_TEXT ENDS
_DATA SEGMENT
ALIGN 16
L_avx2_rorx_sha512_k QWORD 428a2f98d728ae22h, 7137449123ef65cdh
        QWORD 0b5c0fbcfec4d3b2fh, 0e9b5dba58189dbbch
        QWORD 3956c25bf348b538h, 59f111f1b605d019h
        QWORD 923f82a4af194f9bh, 0ab1c5ed5da6d8118h
        QWORD 0d807aa98a3030242h, 12835b0145706fbeh
        QWORD 243185be4ee4b28ch, 550c7dc3d5ffb4e2h
        QWORD 72be5d74f27b896fh, 80deb1fe3b1696b1h
        QWORD 9bdc06a725c71235h, 0c19bf174cf692694h
        QWORD 0e49b69c19ef14ad2h, 0efbe4786384f25e3h
        QWORD 0fc19dc68b8cd5b5h, 240ca1cc77ac9c65h
        QWORD 2de92c6f592b0275h, 4a7484aa6ea6e483h
        QWORD 5cb0a9dcbd41fbd4h, 76f988da831153b5h
        QWORD 983e5152ee66dfabh, 0a831c66d2db43210h
        QWORD 0b00327c898fb213fh, 0bf597fc7beef0ee4h
        QWORD 0c6e00bf33da88fc2h, 0d5a79147930aa725h
        QWORD 06ca6351e003826fh, 142929670a0e6e70h
        QWORD 27b70a8546d22ffch, 2e1b21385c26c926h
        QWORD 4d2c6dfc5ac42aedh, 53380d139d95b3dfh
        QWORD 650a73548baf63deh, 766a0abb3c77b2a8h
        QWORD 81c2c92e47edaee6h, 92722c851482353bh
        QWORD 0a2bfe8a14cf10364h, 0a81a664bbc423001h
        QWORD 0c24b8b70d0f89791h, 0c76c51a30654be30h
        QWORD 0d192e819d6ef5218h, 0d69906245565a910h
        QWORD 0f40e35855771202ah, 106aa07032bbd1b8h
        QWORD 19a4c116b8d2d0c8h, 1e376c085141ab53h
        QWORD 2748774cdf8eeb99h, 34b0bcb5e19b48a8h
        QWORD 391c0cb3c5c95a63h, 4ed8aa4ae3418acbh
        QWORD 5b9cca4f7763e373h, 682e6ff3d6b2b8a3h
        QWORD 748f82ee5defb2fch, 78a5636f43172f60h
        QWORD 84c87814a1f0ab72h, 8cc702081a6439ech
        QWORD 90befffa23631e28h, 0a4506cebde82bde9h
        QWORD 0bef9a3f7b2c67915h, 0c67178f2e372532bh
        QWORD 0ca273eceea26619ch, 0d186b8c721c0c207h
        QWORD 0eada7dd6cde0eb1eh, 0f57d4f7fee6ed178h
        QWORD 06f067aa72176fbah, 0a637dc5a2c898a6h
        QWORD 113f9804bef90daeh, 1b710b35131c471bh
        QWORD 28db77f523047d84h, 32caab7b40c72493h
        QWORD 3c9ebe0a15c9bebch, 431d67c49c100d4ch
        QWORD 4cc5d4becb3e42b6h, 597f299cfc657e2ah
        QWORD 5fcb6fab3ad6faech, 6c44198c4a475817h
ptr_L_avx2_rorx_sha512_k QWORD L_avx2_rorx_sha512_k
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_avx2_rorx_sha512_k_2 QWORD 428a2f98d728ae22h, 7137449123ef65cdh
        QWORD 428a2f98d728ae22h, 7137449123ef65cdh
        QWORD 0b5c0fbcfec4d3b2fh, 0e9b5dba58189dbbch
        QWORD 0b5c0fbcfec4d3b2fh, 0e9b5dba58189dbbch
        QWORD 3956c25bf348b538h, 59f111f1b605d019h
        QWORD 3956c25bf348b538h, 59f111f1b605d019h
        QWORD 923f82a4af194f9bh, 0ab1c5ed5da6d8118h
        QWORD 923f82a4af194f9bh, 0ab1c5ed5da6d8118h
        QWORD 0d807aa98a3030242h, 12835b0145706fbeh
        QWORD 0d807aa98a3030242h, 12835b0145706fbeh
        QWORD 243185be4ee4b28ch, 550c7dc3d5ffb4e2h
        QWORD 243185be4ee4b28ch, 550c7dc3d5ffb4e2h
        QWORD 72be5d74f27b896fh, 80deb1fe3b1696b1h
        QWORD 72be5d74f27b896fh, 80deb1fe3b1696b1h
        QWORD 9bdc06a725c71235h, 0c19bf174cf692694h
        QWORD 9bdc06a725c71235h, 0c19bf174cf692694h
        QWORD 0e49b69c19ef14ad2h, 0efbe4786384f25e3h
        QWORD 0e49b69c19ef14ad2h, 0efbe4786384f25e3h
        QWORD 0fc19dc68b8cd5b5h, 240ca1cc77ac9c65h
        QWORD 0fc19dc68b8cd5b5h, 240ca1cc77ac9c65h
        QWORD 2de92c6f592b0275h, 4a7484aa6ea6e483h
        QWORD 2de92c6f592b0275h, 4a7484aa6ea6e483h
        QWORD 5cb0a9dcbd41fbd4h, 76f988da831153b5h
        QWORD 5cb0a9dcbd41fbd4h, 76f988da831153b5h
        QWORD 983e5152ee66dfabh, 0a831c66d2db43210h
        QWORD 983e5152ee66dfabh, 0a831c66d2db43210h
        QWORD 0b00327c898fb213fh, 0bf597fc7beef0ee4h
        QWORD 0b00327c898fb213fh, 0bf597fc7beef0ee4h
        QWORD 0c6e00bf33da88fc2h, 0d5a79147930aa725h
        QWORD 0c6e00bf33da88fc2h, 0d5a79147930aa725h
        QWORD 06ca6351e003826fh, 142929670a0e6e70h
        QWORD 06ca6351e003826fh, 142929670a0e6e70h
        QWORD 27b70a8546d22ffch, 2e1b21385c26c926h
        QWORD 27b70a8546d22ffch, 2e1b21385c26c926h
        QWORD 4d2c6dfc5ac42aedh, 53380d139d95b3dfh
        QWORD 4d2c6dfc5ac42aedh, 53380d139d95b3dfh
        QWORD 650a73548baf63deh, 766a0abb3c77b2a8h
        QWORD 650a73548baf63deh, 766a0abb3c77b2a8h
        QWORD 81c2c92e47edaee6h, 92722c851482353bh
        QWORD 81c2c92e47edaee6h, 92722c851482353bh
        QWORD 0a2bfe8a14cf10364h, 0a81a664bbc423001h
        QWORD 0a2bfe8a14cf10364h, 0a81a664bbc423001h
        QWORD 0c24b8b70d0f89791h, 0c76c51a30654be30h
        QWORD 0c24b8b70d0f89791h, 0c76c51a30654be30h
        QWORD 0d192e819d6ef5218h, 0d69906245565a910h
        QWORD 0d192e819d6ef5218h, 0d69906245565a910h
        QWORD 0f40e35855771202ah, 106aa07032bbd1b8h
        QWORD 0f40e35855771202ah, 106aa07032bbd1b8h
        QWORD 19a4c116b8d2d0c8h, 1e376c085141ab53h
        QWORD 19a4c116b8d2d0c8h, 1e376c085141ab53h
        QWORD 2748774cdf8eeb99h, 34b0bcb5e19b48a8h
        QWORD 2748774cdf8eeb99h, 34b0bcb5e19b48a8h
        QWORD 391c0cb3c5c95a63h, 4ed8aa4ae3418acbh
        QWORD 391c0cb3c5c95a63h, 4ed8aa4ae3418acbh
        QWORD 5b9cca4f7763e373h, 682e6ff3d6b2b8a3h
        QWORD 5b9cca4f7763e373h, 682e6ff3d6b2b8a3h
        QWORD 748f82ee5defb2fch, 78a5636f43172f60h
        QWORD 748f82ee5defb2fch, 78a5636f43172f60h
        QWORD 84c87814a1f0ab72h, 8cc702081a6439ech
        QWORD 84c87814a1f0ab72h, 8cc702081a6439ech
        QWORD 90befffa23631e28h, 0a4506cebde82bde9h
        QWORD 90befffa23631e28h, 0a4506cebde82bde9h
        QWORD 0bef9a3f7b2c67915h, 0c67178f2e372532bh
        QWORD 0bef9a3f7b2c67915h, 0c67178f2e372532bh
        QWORD 0ca273eceea26619ch, 0d186b8c721c0c207h
        QWORD 0ca273eceea26619ch, 0d186b8c721c0c207h
        QWORD 0eada7dd6cde0eb1eh, 0f57d4f7fee6ed178h
        QWORD 0eada7dd6cde0eb1eh, 0f57d4f7fee6ed178h
        QWORD 06f067aa72176fbah, 0a637dc5a2c898a6h
        QWORD 06f067aa72176fbah, 0a637dc5a2c898a6h
        QWORD 113f9804bef90daeh, 1b710b35131c471bh
        QWORD 113f9804bef90daeh, 1b710b35131c471bh
        QWORD 28db77f523047d84h, 32caab7b40c72493h
        QWORD 28db77f523047d84h, 32caab7b40c72493h
        QWORD 3c9ebe0a15c9bebch, 431d67c49c100d4ch
        QWORD 3c9ebe0a15c9bebch, 431d67c49c100d4ch
        QWORD 4cc5d4becb3e42b6h, 597f299cfc657e2ah
        QWORD 4cc5d4becb3e42b6h, 597f299cfc657e2ah
        QWORD 5fcb6fab3ad6faech, 6c44198c4a475817h
        QWORD 5fcb6fab3ad6faech, 6c44198c4a475817h
ptr_L_avx2_rorx_sha512_k_2 QWORD L_avx2_rorx_sha512_k_2
_DATA ENDS
_DATA SEGMENT
ALIGN 8
L_avx2_rorx_sha512_k_2_end QWORD 1024+L_avx2_rorx_sha512_k_2
ptr_L_avx2_rorx_sha512_k_2_end QWORD L_avx2_rorx_sha512_k_2_end
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_avx2_rorx_sha512_flip_mask QWORD 0001020304050607h, 08090a0b0c0d0e0fh
        QWORD 0001020304050607h, 08090a0b0c0d0e0fh
ptr_L_avx2_rorx_sha512_flip_mask QWORD L_avx2_rorx_sha512_flip_mask
_DATA ENDS
_TEXT SEGMENT READONLY PARA
Transform_Sha512_AVX2_RORX PROC
        push	rbx
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        mov	rdi, rcx
        sub	rsp, 296
        vmovdqu	OWORD PTR [rsp+136], xmm6
        vmovdqu	OWORD PTR [rsp+152], xmm7
        vmovdqu	OWORD PTR [rsp+168], xmm8
        vmovdqu	OWORD PTR [rsp+184], xmm9
        vmovdqu	OWORD PTR [rsp+200], xmm10
        vmovdqu	OWORD PTR [rsp+216], xmm11
        vmovdqu	OWORD PTR [rsp+232], xmm14
        vmovdqu	OWORD PTR [rsp+248], xmm13
        vmovdqu	OWORD PTR [rsp+264], xmm12
        vmovdqu	OWORD PTR [rsp+280], xmm15
        lea	rcx, QWORD PTR [rdi+64]
        vmovdqu	ymm15, YMMWORD PTR L_avx2_rorx_sha512_flip_mask
        mov	r8, QWORD PTR [rdi]
        mov	r9, QWORD PTR [rdi+8]
        mov	r10, QWORD PTR [rdi+16]
        mov	r11, QWORD PTR [rdi+24]
        mov	r12, QWORD PTR [rdi+32]
        mov	r13, QWORD PTR [rdi+40]
        mov	r14, QWORD PTR [rdi+48]
        mov	r15, QWORD PTR [rdi+56]
        vmovdqu	ymm0, YMMWORD PTR [rcx]
        vmovdqu	ymm1, YMMWORD PTR [rcx+32]
        vpshufb	ymm0, ymm0, ymm15
        vpshufb	ymm1, ymm1, ymm15
        vmovdqu	ymm2, YMMWORD PTR [rcx+64]
        vmovdqu	ymm3, YMMWORD PTR [rcx+96]
        vpshufb	ymm2, ymm2, ymm15
        vpshufb	ymm3, ymm3, ymm15
        mov	DWORD PTR [rsp+128], 4
        mov	rsi, QWORD PTR [ptr_L_avx2_rorx_sha512_k]
        mov	rbx, r9
        xor	rdx, rdx
        xor	rbx, r10
        ; set_w_k: 0
        vpaddq	ymm8, ymm0, [rsi]
        vpaddq	ymm9, ymm1, [rsi+32]
        vmovdqu	YMMWORD PTR [rsp], ymm8
        vmovdqu	YMMWORD PTR [rsp+32], ymm9
        vpaddq	ymm8, ymm2, [rsi+64]
        vpaddq	ymm9, ymm3, [rsi+96]
        vmovdqu	YMMWORD PTR [rsp+64], ymm8
        vmovdqu	YMMWORD PTR [rsp+96], ymm9
        ; Start of 16 rounds
L_sha256_len_avx2_rorx_start:
        add	rsi, 128
        rorx	rax, r12, 14
        rorx	rcx, r12, 18
        add	r8, rdx
        vpblendd	ymm12, ymm0, ymm1, 3
        vpblendd	ymm13, ymm2, ymm3, 3
        add	r15, QWORD PTR [rsp]
        mov	rdx, r13
        xor	rcx, rax
        vpermq	ymm12, ymm12, 57
        xor	rdx, r14
        rorx	rax, r12, 41
        xor	rax, rcx
        vpermq	ymm13, ymm13, 57
        and	rdx, r12
        add	r15, rax
        rorx	rax, r8, 28
        vpsrlq	ymm8, ymm12, 1
        vpsllq	ymm9, ymm12, 63
        rorx	rcx, r8, 34
        xor	rdx, r14
        xor	rcx, rax
        vpsrlq	ymm10, ymm12, 8
        vpsllq	ymm11, ymm12, 56
        vpor	ymm8, ymm8, ymm9
        vpor	ymm10, ymm10, ymm11
        rorx	rax, r8, 39
        add	r15, rdx
        xor	rax, rcx
        vpsrlq	ymm11, ymm12, 7
        mov	rdx, r9
        add	r11, r15
        xor	rdx, r8
        vperm2I128	ymm14, ymm3, ymm3, 129
        and	rbx, rdx
        add	r15, rax
        xor	rbx, r9
        rorx	rax, r11, 14
        rorx	rcx, r11, 18
        add	r15, rbx
        vpxor	ymm8, ymm8, ymm10
        add	r14, QWORD PTR [rsp+8]
        mov	rbx, r12
        xor	rcx, rax
        vpxor	ymm8, ymm8, ymm11
        xor	rbx, r13
        rorx	rax, r11, 41
        xor	rax, rcx
        vpaddq	ymm0, ymm13, ymm0
        vpaddq	ymm0, ymm8, ymm0
        and	rbx, r11
        add	r14, rax
        rorx	rax, r15, 28
        vpsrlq	ymm8, ymm14, 19
        vpsllq	ymm9, ymm14, 45
        rorx	rcx, r15, 34
        xor	rbx, r13
        xor	rcx, rax
        vpsrlq	ymm10, ymm14, 61
        vpsllq	ymm11, ymm14, 3
        vpor	ymm8, ymm8, ymm9
        rorx	rax, r15, 39
        add	r14, rbx
        xor	rax, rcx
        vpor	ymm10, ymm10, ymm11
        mov	rbx, r8
        lea	r10, QWORD PTR [r10+r14]
        xor	rbx, r15
        vpxor	ymm8, ymm8, ymm10
        and	rdx, rbx
        add	r14, rax
        xor	rdx, r8
        vpsrlq	ymm11, ymm14, 6
        rorx	rax, r10, 14
        rorx	rcx, r10, 18
        add	r14, rdx
        vpxor	ymm8, ymm8, ymm11
        add	r13, QWORD PTR [rsp+16]
        mov	rdx, r11
        xor	rcx, rax
        vpaddq	ymm0, ymm8, ymm0
        xor	rdx, r12
        rorx	rax, r10, 41
        xor	rax, rcx
        vperm2I128	ymm14, ymm0, ymm0, 8
        and	rdx, r10
        add	r13, rax
        rorx	rax, r14, 28
        rorx	rcx, r14, 34
        xor	rdx, r12
        xor	rcx, rax
        vpsrlq	ymm8, ymm14, 19
        vpsllq	ymm9, ymm14, 45
        rorx	rax, r14, 39
        add	r13, rdx
        xor	rax, rcx
        vpsrlq	ymm10, ymm14, 61
        vpsllq	ymm11, ymm14, 3
        vpor	ymm8, ymm8, ymm9
        mov	rdx, r15
        add	r9, r13
        xor	rdx, r14
        vpor	ymm10, ymm10, ymm11
        and	rbx, rdx
        add	r13, rax
        xor	rbx, r15
        vpxor	ymm8, ymm8, ymm10
        rorx	rax, r9, 14
        rorx	rcx, r9, 18
        add	r13, rbx
        vpsrlq	ymm11, ymm14, 6
        add	r12, QWORD PTR [rsp+24]
        mov	rbx, r10
        xor	rcx, rax
        xor	rbx, r11
        rorx	rax, r9, 41
        xor	rax, rcx
        vpxor	ymm8, ymm8, ymm11
        and	rbx, r9
        add	r12, rax
        rorx	rax, r13, 28
        rorx	rcx, r13, 34
        xor	rbx, r11
        xor	rcx, rax
        vpaddq	ymm0, ymm8, ymm0
        rorx	rax, r13, 39
        add	r12, rbx
        xor	rax, rcx
        vpaddq	ymm8, ymm0, [rsi]
        mov	rbx, r14
        lea	r8, QWORD PTR [r8+r12]
        xor	rbx, r13
        and	rdx, rbx
        add	r12, rax
        xor	rdx, r14
        vmovdqu	YMMWORD PTR [rsp], ymm8
        rorx	rax, r8, 14
        rorx	rcx, r8, 18
        add	r12, rdx
        vpblendd	ymm12, ymm1, ymm2, 3
        vpblendd	ymm13, ymm3, ymm0, 3
        add	r11, QWORD PTR [rsp+32]
        mov	rdx, r9
        xor	rcx, rax
        vpermq	ymm12, ymm12, 57
        xor	rdx, r10
        rorx	rax, r8, 41
        xor	rax, rcx
        vpermq	ymm13, ymm13, 57
        and	rdx, r8
        add	r11, rax
        rorx	rax, r12, 28
        vpsrlq	ymm8, ymm12, 1
        vpsllq	ymm9, ymm12, 63
        rorx	rcx, r12, 34
        xor	rdx, r10
        xor	rcx, rax
        vpsrlq	ymm10, ymm12, 8
        vpsllq	ymm11, ymm12, 56
        vpor	ymm8, ymm8, ymm9
        vpor	ymm10, ymm10, ymm11
        rorx	rax, r12, 39
        add	r11, rdx
        xor	rax, rcx
        vpsrlq	ymm11, ymm12, 7
        mov	rdx, r13
        add	r15, r11
        xor	rdx, r12
        vperm2I128	ymm14, ymm0, ymm0, 129
        and	rbx, rdx
        add	r11, rax
        xor	rbx, r13
        rorx	rax, r15, 14
        rorx	rcx, r15, 18
        add	r11, rbx
        vpxor	ymm8, ymm8, ymm10
        add	r10, QWORD PTR [rsp+40]
        mov	rbx, r8
        xor	rcx, rax
        vpxor	ymm8, ymm8, ymm11
        xor	rbx, r9
        rorx	rax, r15, 41
        xor	rax, rcx
        vpaddq	ymm1, ymm13, ymm1
        vpaddq	ymm1, ymm8, ymm1
        and	rbx, r15
        add	r10, rax
        rorx	rax, r11, 28
        vpsrlq	ymm8, ymm14, 19
        vpsllq	ymm9, ymm14, 45
        rorx	rcx, r11, 34
        xor	rbx, r9
        xor	rcx, rax
        vpsrlq	ymm10, ymm14, 61
        vpsllq	ymm11, ymm14, 3
        vpor	ymm8, ymm8, ymm9
        rorx	rax, r11, 39
        add	r10, rbx
        xor	rax, rcx
        vpor	ymm10, ymm10, ymm11
        mov	rbx, r12
        lea	r14, QWORD PTR [r14+r10]
        xor	rbx, r11
        vpxor	ymm8, ymm8, ymm10
        and	rdx, rbx
        add	r10, rax
        xor	rdx, r12
        vpsrlq	ymm11, ymm14, 6
        rorx	rax, r14, 14
        rorx	rcx, r14, 18
        add	r10, rdx
        vpxor	ymm8, ymm8, ymm11
        add	r9, QWORD PTR [rsp+48]
        mov	rdx, r15
        xor	rcx, rax
        vpaddq	ymm1, ymm8, ymm1
        xor	rdx, r8
        rorx	rax, r14, 41
        xor	rax, rcx
        vperm2I128	ymm14, ymm1, ymm1, 8
        and	rdx, r14
        add	r9, rax
        rorx	rax, r10, 28
        rorx	rcx, r10, 34
        xor	rdx, r8
        xor	rcx, rax
        vpsrlq	ymm8, ymm14, 19
        vpsllq	ymm9, ymm14, 45
        rorx	rax, r10, 39
        add	r9, rdx
        xor	rax, rcx
        vpsrlq	ymm10, ymm14, 61
        vpsllq	ymm11, ymm14, 3
        vpor	ymm8, ymm8, ymm9
        mov	rdx, r11
        add	r13, r9
        xor	rdx, r10
        vpor	ymm10, ymm10, ymm11
        and	rbx, rdx
        add	r9, rax
        xor	rbx, r11
        vpxor	ymm8, ymm8, ymm10
        rorx	rax, r13, 14
        rorx	rcx, r13, 18
        add	r9, rbx
        vpsrlq	ymm11, ymm14, 6
        add	r8, QWORD PTR [rsp+56]
        mov	rbx, r14
        xor	rcx, rax
        xor	rbx, r15
        rorx	rax, r13, 41
        xor	rax, rcx
        vpxor	ymm8, ymm8, ymm11
        and	rbx, r13
        add	r8, rax
        rorx	rax, r9, 28
        rorx	rcx, r9, 34
        xor	rbx, r15
        xor	rcx, rax
        vpaddq	ymm1, ymm8, ymm1
        rorx	rax, r9, 39
        add	r8, rbx
        xor	rax, rcx
        vpaddq	ymm8, ymm1, [rsi+32]
        mov	rbx, r10
        lea	r12, QWORD PTR [r12+r8]
        xor	rbx, r9
        and	rdx, rbx
        add	r8, rax
        xor	rdx, r10
        vmovdqu	YMMWORD PTR [rsp+32], ymm8
        rorx	rax, r12, 14
        rorx	rcx, r12, 18
        add	r8, rdx
        vpblendd	ymm12, ymm2, ymm3, 3
        vpblendd	ymm13, ymm0, ymm1, 3
        add	r15, QWORD PTR [rsp+64]
        mov	rdx, r13
        xor	rcx, rax
        vpermq	ymm12, ymm12, 57
        xor	rdx, r14
        rorx	rax, r12, 41
        xor	rax, rcx
        vpermq	ymm13, ymm13, 57
        and	rdx, r12
        add	r15, rax
        rorx	rax, r8, 28
        vpsrlq	ymm8, ymm12, 1
        vpsllq	ymm9, ymm12, 63
        rorx	rcx, r8, 34
        xor	rdx, r14
        xor	rcx, rax
        vpsrlq	ymm10, ymm12, 8
        vpsllq	ymm11, ymm12, 56
        vpor	ymm8, ymm8, ymm9
        vpor	ymm10, ymm10, ymm11
        rorx	rax, r8, 39
        add	r15, rdx
        xor	rax, rcx
        vpsrlq	ymm11, ymm12, 7
        mov	rdx, r9
        add	r11, r15
        xor	rdx, r8
        vperm2I128	ymm14, ymm1, ymm1, 129
        and	rbx, rdx
        add	r15, rax
        xor	rbx, r9
        rorx	rax, r11, 14
        rorx	rcx, r11, 18
        add	r15, rbx
        vpxor	ymm8, ymm8, ymm10
        add	r14, QWORD PTR [rsp+72]
        mov	rbx, r12
        xor	rcx, rax
        vpxor	ymm8, ymm8, ymm11
        xor	rbx, r13
        rorx	rax, r11, 41
        xor	rax, rcx
        vpaddq	ymm2, ymm13, ymm2
        vpaddq	ymm2, ymm8, ymm2
        and	rbx, r11
        add	r14, rax
        rorx	rax, r15, 28
        vpsrlq	ymm8, ymm14, 19
        vpsllq	ymm9, ymm14, 45
        rorx	rcx, r15, 34
        xor	rbx, r13
        xor	rcx, rax
        vpsrlq	ymm10, ymm14, 61
        vpsllq	ymm11, ymm14, 3
        vpor	ymm8, ymm8, ymm9
        rorx	rax, r15, 39
        add	r14, rbx
        xor	rax, rcx
        vpor	ymm10, ymm10, ymm11
        mov	rbx, r8
        lea	r10, QWORD PTR [r10+r14]
        xor	rbx, r15
        vpxor	ymm8, ymm8, ymm10
        and	rdx, rbx
        add	r14, rax
        xor	rdx, r8
        vpsrlq	ymm11, ymm14, 6
        rorx	rax, r10, 14
        rorx	rcx, r10, 18
        add	r14, rdx
        vpxor	ymm8, ymm8, ymm11
        add	r13, QWORD PTR [rsp+80]
        mov	rdx, r11
        xor	rcx, rax
        vpaddq	ymm2, ymm8, ymm2
        xor	rdx, r12
        rorx	rax, r10, 41
        xor	rax, rcx
        vperm2I128	ymm14, ymm2, ymm2, 8
        and	rdx, r10
        add	r13, rax
        rorx	rax, r14, 28
        rorx	rcx, r14, 34
        xor	rdx, r12
        xor	rcx, rax
        vpsrlq	ymm8, ymm14, 19
        vpsllq	ymm9, ymm14, 45
        rorx	rax, r14, 39
        add	r13, rdx
        xor	rax, rcx
        vpsrlq	ymm10, ymm14, 61
        vpsllq	ymm11, ymm14, 3
        vpor	ymm8, ymm8, ymm9
        mov	rdx, r15
        add	r9, r13
        xor	rdx, r14
        vpor	ymm10, ymm10, ymm11
        and	rbx, rdx
        add	r13, rax
        xor	rbx, r15
        vpxor	ymm8, ymm8, ymm10
        rorx	rax, r9, 14
        rorx	rcx, r9, 18
        add	r13, rbx
        vpsrlq	ymm11, ymm14, 6
        add	r12, QWORD PTR [rsp+88]
        mov	rbx, r10
        xor	rcx, rax
        xor	rbx, r11
        rorx	rax, r9, 41
        xor	rax, rcx
        vpxor	ymm8, ymm8, ymm11
        and	rbx, r9
        add	r12, rax
        rorx	rax, r13, 28
        rorx	rcx, r13, 34
        xor	rbx, r11
        xor	rcx, rax
        vpaddq	ymm2, ymm8, ymm2
        rorx	rax, r13, 39
        add	r12, rbx
        xor	rax, rcx
        vpaddq	ymm8, ymm2, [rsi+64]
        mov	rbx, r14
        lea	r8, QWORD PTR [r8+r12]
        xor	rbx, r13
        and	rdx, rbx
        add	r12, rax
        xor	rdx, r14
        vmovdqu	YMMWORD PTR [rsp+64], ymm8
        rorx	rax, r8, 14
        rorx	rcx, r8, 18
        add	r12, rdx
        vpblendd	ymm12, ymm3, ymm0, 3
        vpblendd	ymm13, ymm1, ymm2, 3
        add	r11, QWORD PTR [rsp+96]
        mov	rdx, r9
        xor	rcx, rax
        vpermq	ymm12, ymm12, 57
        xor	rdx, r10
        rorx	rax, r8, 41
        xor	rax, rcx
        vpermq	ymm13, ymm13, 57
        and	rdx, r8
        add	r11, rax
        rorx	rax, r12, 28
        vpsrlq	ymm8, ymm12, 1
        vpsllq	ymm9, ymm12, 63
        rorx	rcx, r12, 34
        xor	rdx, r10
        xor	rcx, rax
        vpsrlq	ymm10, ymm12, 8
        vpsllq	ymm11, ymm12, 56
        vpor	ymm8, ymm8, ymm9
        vpor	ymm10, ymm10, ymm11
        rorx	rax, r12, 39
        add	r11, rdx
        xor	rax, rcx
        vpsrlq	ymm11, ymm12, 7
        mov	rdx, r13
        add	r15, r11
        xor	rdx, r12
        vperm2I128	ymm14, ymm2, ymm2, 129
        and	rbx, rdx
        add	r11, rax
        xor	rbx, r13
        rorx	rax, r15, 14
        rorx	rcx, r15, 18
        add	r11, rbx
        vpxor	ymm8, ymm8, ymm10
        add	r10, QWORD PTR [rsp+104]
        mov	rbx, r8
        xor	rcx, rax
        vpxor	ymm8, ymm8, ymm11
        xor	rbx, r9
        rorx	rax, r15, 41
        xor	rax, rcx
        vpaddq	ymm3, ymm13, ymm3
        vpaddq	ymm3, ymm8, ymm3
        and	rbx, r15
        add	r10, rax
        rorx	rax, r11, 28
        vpsrlq	ymm8, ymm14, 19
        vpsllq	ymm9, ymm14, 45
        rorx	rcx, r11, 34
        xor	rbx, r9
        xor	rcx, rax
        vpsrlq	ymm10, ymm14, 61
        vpsllq	ymm11, ymm14, 3
        vpor	ymm8, ymm8, ymm9
        rorx	rax, r11, 39
        add	r10, rbx
        xor	rax, rcx
        vpor	ymm10, ymm10, ymm11
        mov	rbx, r12
        lea	r14, QWORD PTR [r14+r10]
        xor	rbx, r11
        vpxor	ymm8, ymm8, ymm10
        and	rdx, rbx
        add	r10, rax
        xor	rdx, r12
        vpsrlq	ymm11, ymm14, 6
        rorx	rax, r14, 14
        rorx	rcx, r14, 18
        add	r10, rdx
        vpxor	ymm8, ymm8, ymm11
        add	r9, QWORD PTR [rsp+112]
        mov	rdx, r15
        xor	rcx, rax
        vpaddq	ymm3, ymm8, ymm3
        xor	rdx, r8
        rorx	rax, r14, 41
        xor	rax, rcx
        vperm2I128	ymm14, ymm3, ymm3, 8
        and	rdx, r14
        add	r9, rax
        rorx	rax, r10, 28
        rorx	rcx, r10, 34
        xor	rdx, r8
        xor	rcx, rax
        vpsrlq	ymm8, ymm14, 19
        vpsllq	ymm9, ymm14, 45
        rorx	rax, r10, 39
        add	r9, rdx
        xor	rax, rcx
        vpsrlq	ymm10, ymm14, 61
        vpsllq	ymm11, ymm14, 3
        vpor	ymm8, ymm8, ymm9
        mov	rdx, r11
        add	r13, r9
        xor	rdx, r10
        vpor	ymm10, ymm10, ymm11
        and	rbx, rdx
        add	r9, rax
        xor	rbx, r11
        vpxor	ymm8, ymm8, ymm10
        rorx	rax, r13, 14
        rorx	rcx, r13, 18
        add	r9, rbx
        vpsrlq	ymm11, ymm14, 6
        add	r8, QWORD PTR [rsp+120]
        mov	rbx, r14
        xor	rcx, rax
        xor	rbx, r15
        rorx	rax, r13, 41
        xor	rax, rcx
        vpxor	ymm8, ymm8, ymm11
        and	rbx, r13
        add	r8, rax
        rorx	rax, r9, 28
        rorx	rcx, r9, 34
        xor	rbx, r15
        xor	rcx, rax
        vpaddq	ymm3, ymm8, ymm3
        rorx	rax, r9, 39
        add	r8, rbx
        xor	rax, rcx
        vpaddq	ymm8, ymm3, [rsi+96]
        mov	rbx, r10
        lea	r12, QWORD PTR [r12+r8]
        xor	rbx, r9
        and	rdx, rbx
        add	r8, rax
        xor	rdx, r10
        vmovdqu	YMMWORD PTR [rsp+96], ymm8
        sub	DWORD PTR [rsp+128], 1
        jne	L_sha256_len_avx2_rorx_start
        ; rnd_all_4: 0-3
        rorx	rax, r12, 14
        rorx	rcx, r12, 18
        add	r8, rdx
        add	r15, QWORD PTR [rsp]
        mov	rdx, r13
        xor	rcx, rax
        xor	rdx, r14
        rorx	rax, r12, 41
        xor	rax, rcx
        and	rdx, r12
        add	r15, rax
        rorx	rax, r8, 28
        rorx	rcx, r8, 34
        xor	rdx, r14
        xor	rcx, rax
        rorx	rax, r8, 39
        add	r15, rdx
        xor	rax, rcx
        mov	rdx, r9
        add	r11, r15
        xor	rdx, r8
        and	rbx, rdx
        add	r15, rax
        xor	rbx, r9
        rorx	rax, r11, 14
        rorx	rcx, r11, 18
        add	r15, rbx
        add	r14, QWORD PTR [rsp+8]
        mov	rbx, r12
        xor	rcx, rax
        xor	rbx, r13
        rorx	rax, r11, 41
        xor	rax, rcx
        and	rbx, r11
        add	r14, rax
        rorx	rax, r15, 28
        rorx	rcx, r15, 34
        xor	rbx, r13
        xor	rcx, rax
        rorx	rax, r15, 39
        add	r14, rbx
        xor	rax, rcx
        mov	rbx, r8
        lea	r10, QWORD PTR [r10+r14]
        xor	rbx, r15
        and	rdx, rbx
        add	r14, rax
        xor	rdx, r8
        rorx	rax, r10, 14
        rorx	rcx, r10, 18
        add	r14, rdx
        add	r13, QWORD PTR [rsp+16]
        mov	rdx, r11
        xor	rcx, rax
        xor	rdx, r12
        rorx	rax, r10, 41
        xor	rax, rcx
        and	rdx, r10
        add	r13, rax
        rorx	rax, r14, 28
        rorx	rcx, r14, 34
        xor	rdx, r12
        xor	rcx, rax
        rorx	rax, r14, 39
        add	r13, rdx
        xor	rax, rcx
        mov	rdx, r15
        add	r9, r13
        xor	rdx, r14
        and	rbx, rdx
        add	r13, rax
        xor	rbx, r15
        rorx	rax, r9, 14
        rorx	rcx, r9, 18
        add	r13, rbx
        add	r12, QWORD PTR [rsp+24]
        mov	rbx, r10
        xor	rcx, rax
        xor	rbx, r11
        rorx	rax, r9, 41
        xor	rax, rcx
        and	rbx, r9
        add	r12, rax
        rorx	rax, r13, 28
        rorx	rcx, r13, 34
        xor	rbx, r11
        xor	rcx, rax
        rorx	rax, r13, 39
        add	r12, rbx
        xor	rax, rcx
        mov	rbx, r14
        lea	r8, QWORD PTR [r8+r12]
        xor	rbx, r13
        and	rdx, rbx
        add	r12, rax
        xor	rdx, r14
        ; rnd_all_4: 4-7
        rorx	rax, r8, 14
        rorx	rcx, r8, 18
        add	r12, rdx
        add	r11, QWORD PTR [rsp+32]
        mov	rdx, r9
        xor	rcx, rax
        xor	rdx, r10
        rorx	rax, r8, 41
        xor	rax, rcx
        and	rdx, r8
        add	r11, rax
        rorx	rax, r12, 28
        rorx	rcx, r12, 34
        xor	rdx, r10
        xor	rcx, rax
        rorx	rax, r12, 39
        add	r11, rdx
        xor	rax, rcx
        mov	rdx, r13
        add	r15, r11
        xor	rdx, r12
        and	rbx, rdx
        add	r11, rax
        xor	rbx, r13
        rorx	rax, r15, 14
        rorx	rcx, r15, 18
        add	r11, rbx
        add	r10, QWORD PTR [rsp+40]
        mov	rbx, r8
        xor	rcx, rax
        xor	rbx, r9
        rorx	rax, r15, 41
        xor	rax, rcx
        and	rbx, r15
        add	r10, rax
        rorx	rax, r11, 28
        rorx	rcx, r11, 34
        xor	rbx, r9
        xor	rcx, rax
        rorx	rax, r11, 39
        add	r10, rbx
        xor	rax, rcx
        mov	rbx, r12
        lea	r14, QWORD PTR [r14+r10]
        xor	rbx, r11
        and	rdx, rbx
        add	r10, rax
        xor	rdx, r12
        rorx	rax, r14, 14
        rorx	rcx, r14, 18
        add	r10, rdx
        add	r9, QWORD PTR [rsp+48]
        mov	rdx, r15
        xor	rcx, rax
        xor	rdx, r8
        rorx	rax, r14, 41
        xor	rax, rcx
        and	rdx, r14
        add	r9, rax
        rorx	rax, r10, 28
        rorx	rcx, r10, 34
        xor	rdx, r8
        xor	rcx, rax
        rorx	rax, r10, 39
        add	r9, rdx
        xor	rax, rcx
        mov	rdx, r11
        add	r13, r9
        xor	rdx, r10
        and	rbx, rdx
        add	r9, rax
        xor	rbx, r11
        rorx	rax, r13, 14
        rorx	rcx, r13, 18
        add	r9, rbx
        add	r8, QWORD PTR [rsp+56]
        mov	rbx, r14
        xor	rcx, rax
        xor	rbx, r15
        rorx	rax, r13, 41
        xor	rax, rcx
        and	rbx, r13
        add	r8, rax
        rorx	rax, r9, 28
        rorx	rcx, r9, 34
        xor	rbx, r15
        xor	rcx, rax
        rorx	rax, r9, 39
        add	r8, rbx
        xor	rax, rcx
        mov	rbx, r10
        lea	r12, QWORD PTR [r12+r8]
        xor	rbx, r9
        and	rdx, rbx
        add	r8, rax
        xor	rdx, r10
        ; rnd_all_4: 8-11
        rorx	rax, r12, 14
        rorx	rcx, r12, 18
        add	r8, rdx
        add	r15, QWORD PTR [rsp+64]
        mov	rdx, r13
        xor	rcx, rax
        xor	rdx, r14
        rorx	rax, r12, 41
        xor	rax, rcx
        and	rdx, r12
        add	r15, rax
        rorx	rax, r8, 28
        rorx	rcx, r8, 34
        xor	rdx, r14
        xor	rcx, rax
        rorx	rax, r8, 39
        add	r15, rdx
        xor	rax, rcx
        mov	rdx, r9
        add	r11, r15
        xor	rdx, r8
        and	rbx, rdx
        add	r15, rax
        xor	rbx, r9
        rorx	rax, r11, 14
        rorx	rcx, r11, 18
        add	r15, rbx
        add	r14, QWORD PTR [rsp+72]
        mov	rbx, r12
        xor	rcx, rax
        xor	rbx, r13
        rorx	rax, r11, 41
        xor	rax, rcx
        and	rbx, r11
        add	r14, rax
        rorx	rax, r15, 28
        rorx	rcx, r15, 34
        xor	rbx, r13
        xor	rcx, rax
        rorx	rax, r15, 39
        add	r14, rbx
        xor	rax, rcx
        mov	rbx, r8
        lea	r10, QWORD PTR [r10+r14]
        xor	rbx, r15
        and	rdx, rbx
        add	r14, rax
        xor	rdx, r8
        rorx	rax, r10, 14
        rorx	rcx, r10, 18
        add	r14, rdx
        add	r13, QWORD PTR [rsp+80]
        mov	rdx, r11
        xor	rcx, rax
        xor	rdx, r12
        rorx	rax, r10, 41
        xor	rax, rcx
        and	rdx, r10
        add	r13, rax
        rorx	rax, r14, 28
        rorx	rcx, r14, 34
        xor	rdx, r12
        xor	rcx, rax
        rorx	rax, r14, 39
        add	r13, rdx
        xor	rax, rcx
        mov	rdx, r15
        add	r9, r13
        xor	rdx, r14
        and	rbx, rdx
        add	r13, rax
        xor	rbx, r15
        rorx	rax, r9, 14
        rorx	rcx, r9, 18
        add	r13, rbx
        add	r12, QWORD PTR [rsp+88]
        mov	rbx, r10
        xor	rcx, rax
        xor	rbx, r11
        rorx	rax, r9, 41
        xor	rax, rcx
        and	rbx, r9
        add	r12, rax
        rorx	rax, r13, 28
        rorx	rcx, r13, 34
        xor	rbx, r11
        xor	rcx, rax
        rorx	rax, r13, 39
        add	r12, rbx
        xor	rax, rcx
        mov	rbx, r14
        lea	r8, QWORD PTR [r8+r12]
        xor	rbx, r13
        and	rdx, rbx
        add	r12, rax
        xor	rdx, r14
        ; rnd_all_4: 12-15
        rorx	rax, r8, 14
        rorx	rcx, r8, 18
        add	r12, rdx
        add	r11, QWORD PTR [rsp+96]
        mov	rdx, r9
        xor	rcx, rax
        xor	rdx, r10
        rorx	rax, r8, 41
        xor	rax, rcx
        and	rdx, r8
        add	r11, rax
        rorx	rax, r12, 28
        rorx	rcx, r12, 34
        xor	rdx, r10
        xor	rcx, rax
        rorx	rax, r12, 39
        add	r11, rdx
        xor	rax, rcx
        mov	rdx, r13
        add	r15, r11
        xor	rdx, r12
        and	rbx, rdx
        add	r11, rax
        xor	rbx, r13
        rorx	rax, r15, 14
        rorx	rcx, r15, 18
        add	r11, rbx
        add	r10, QWORD PTR [rsp+104]
        mov	rbx, r8
        xor	rcx, rax
        xor	rbx, r9
        rorx	rax, r15, 41
        xor	rax, rcx
        and	rbx, r15
        add	r10, rax
        rorx	rax, r11, 28
        rorx	rcx, r11, 34
        xor	rbx, r9
        xor	rcx, rax
        rorx	rax, r11, 39
        add	r10, rbx
        xor	rax, rcx
        mov	rbx, r12
        lea	r14, QWORD PTR [r14+r10]
        xor	rbx, r11
        and	rdx, rbx
        add	r10, rax
        xor	rdx, r12
        rorx	rax, r14, 14
        rorx	rcx, r14, 18
        add	r10, rdx
        add	r9, QWORD PTR [rsp+112]
        mov	rdx, r15
        xor	rcx, rax
        xor	rdx, r8
        rorx	rax, r14, 41
        xor	rax, rcx
        and	rdx, r14
        add	r9, rax
        rorx	rax, r10, 28
        rorx	rcx, r10, 34
        xor	rdx, r8
        xor	rcx, rax
        rorx	rax, r10, 39
        add	r9, rdx
        xor	rax, rcx
        mov	rdx, r11
        add	r13, r9
        xor	rdx, r10
        and	rbx, rdx
        add	r9, rax
        xor	rbx, r11
        rorx	rax, r13, 14
        rorx	rcx, r13, 18
        add	r9, rbx
        add	r8, QWORD PTR [rsp+120]
        mov	rbx, r14
        xor	rcx, rax
        xor	rbx, r15
        rorx	rax, r13, 41
        xor	rax, rcx
        and	rbx, r13
        add	r8, rax
        rorx	rax, r9, 28
        rorx	rcx, r9, 34
        xor	rbx, r15
        xor	rcx, rax
        rorx	rax, r9, 39
        add	r8, rbx
        xor	rax, rcx
        mov	rbx, r10
        lea	r12, QWORD PTR [r12+r8]
        xor	rbx, r9
        and	rdx, rbx
        add	r8, rax
        xor	rdx, r10
        add	r8, rdx
        add	QWORD PTR [rdi], r8
        add	QWORD PTR [rdi+8], r9
        add	QWORD PTR [rdi+16], r10
        add	QWORD PTR [rdi+24], r11
        add	QWORD PTR [rdi+32], r12
        add	QWORD PTR [rdi+40], r13
        add	QWORD PTR [rdi+48], r14
        add	QWORD PTR [rdi+56], r15
        xor	rax, rax
        vzeroupper
        vmovdqu	xmm6, OWORD PTR [rsp+136]
        vmovdqu	xmm7, OWORD PTR [rsp+152]
        vmovdqu	xmm8, OWORD PTR [rsp+168]
        vmovdqu	xmm9, OWORD PTR [rsp+184]
        vmovdqu	xmm10, OWORD PTR [rsp+200]
        vmovdqu	xmm11, OWORD PTR [rsp+216]
        vmovdqu	xmm14, OWORD PTR [rsp+232]
        vmovdqu	xmm13, OWORD PTR [rsp+248]
        vmovdqu	xmm12, OWORD PTR [rsp+264]
        vmovdqu	xmm15, OWORD PTR [rsp+280]
        add	rsp, 296
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        pop	rbx
        ret
Transform_Sha512_AVX2_RORX ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
Transform_Sha512_AVX2_RORX_Len PROC
        push	rbx
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbp
        mov	rdi, rcx
        mov	rsi, rdx
        sub	rsp, 160
        vmovdqu	OWORD PTR [rsp], xmm6
        vmovdqu	OWORD PTR [rsp+16], xmm7
        vmovdqu	OWORD PTR [rsp+32], xmm8
        vmovdqu	OWORD PTR [rsp+48], xmm9
        vmovdqu	OWORD PTR [rsp+64], xmm10
        vmovdqu	OWORD PTR [rsp+80], xmm11
        vmovdqu	OWORD PTR [rsp+96], xmm14
        vmovdqu	OWORD PTR [rsp+112], xmm13
        vmovdqu	OWORD PTR [rsp+128], xmm12
        vmovdqu	OWORD PTR [rsp+144], xmm15
        test	sil, 128
        je	L_sha512_len_avx2_rorx_block
        mov	rax, QWORD PTR [rdi+224]
        push	rsi
        vmovdqu	ymm0, YMMWORD PTR [rax]
        vmovdqu	ymm1, YMMWORD PTR [rax+32]
        vmovdqu	ymm2, YMMWORD PTR [rax+64]
        vmovdqu	ymm3, YMMWORD PTR [rax+96]
        vmovups	YMMWORD PTR [rdi+64], ymm0
        vmovups	YMMWORD PTR [rdi+96], ymm1
        vmovups	YMMWORD PTR [rdi+128], ymm2
        vmovups	YMMWORD PTR [rdi+160], ymm3
        call	Transform_Sha512_AVX2_RORX
        pop	rsi
        add	QWORD PTR [rdi+224], 128
        sub	esi, 128
        jz	L_sha512_len_avx2_rorx_done
L_sha512_len_avx2_rorx_block:
        sub	rsp, 1352
        mov	rax, QWORD PTR [rdi+224]
        vmovdqu	ymm15, YMMWORD PTR L_avx2_rorx_sha512_flip_mask
        mov	r8, QWORD PTR [rdi]
        mov	r9, QWORD PTR [rdi+8]
        mov	r10, QWORD PTR [rdi+16]
        mov	r11, QWORD PTR [rdi+24]
        mov	r12, QWORD PTR [rdi+32]
        mov	r13, QWORD PTR [rdi+40]
        mov	r14, QWORD PTR [rdi+48]
        mov	r15, QWORD PTR [rdi+56]
        mov	DWORD PTR [rsp+1344], esi
        ; Start of loop processing two blocks
L_sha512_len_avx2_rorx_begin:
        mov	rsi, rsp
        mov	rbp, QWORD PTR [ptr_L_avx2_rorx_sha512_k_2]
        mov	rbx, r9
        xor	rdx, rdx
        vmovdqu	xmm0, OWORD PTR [rax]
        vmovdqu	xmm1, OWORD PTR [rax+16]
        vinserti128	ymm0, ymm0, OWORD PTR [rax+128], 1
        vinserti128	ymm1, ymm1, OWORD PTR [rax+144], 1
        vpshufb	ymm0, ymm0, ymm15
        vpshufb	ymm1, ymm1, ymm15
        vmovdqu	xmm2, OWORD PTR [rax+32]
        vmovdqu	xmm3, OWORD PTR [rax+48]
        vinserti128	ymm2, ymm2, OWORD PTR [rax+160], 1
        vinserti128	ymm3, ymm3, OWORD PTR [rax+176], 1
        vpshufb	ymm2, ymm2, ymm15
        vpshufb	ymm3, ymm3, ymm15
        vmovdqu	xmm4, OWORD PTR [rax+64]
        vmovdqu	xmm5, OWORD PTR [rax+80]
        vinserti128	ymm4, ymm4, OWORD PTR [rax+192], 1
        vinserti128	ymm5, ymm5, OWORD PTR [rax+208], 1
        vpshufb	ymm4, ymm4, ymm15
        vpshufb	ymm5, ymm5, ymm15
        vmovdqu	xmm6, OWORD PTR [rax+96]
        vmovdqu	xmm7, OWORD PTR [rax+112]
        vinserti128	ymm6, ymm6, OWORD PTR [rax+224], 1
        vinserti128	ymm7, ymm7, OWORD PTR [rax+240], 1
        vpshufb	ymm6, ymm6, ymm15
        vpshufb	ymm7, ymm7, ymm15
        xor	rbx, r10
        ; Start of 16 rounds
L_sha512_len_avx2_rorx_start:
        vpaddq	ymm8, ymm0, [rbp]
        vpaddq	ymm9, ymm1, [rbp+32]
        vmovdqu	YMMWORD PTR [rsi], ymm8
        vmovdqu	YMMWORD PTR [rsi+32], ymm9
        vpaddq	ymm8, ymm2, [rbp+64]
        vpaddq	ymm9, ymm3, [rbp+96]
        vmovdqu	YMMWORD PTR [rsi+64], ymm8
        vmovdqu	YMMWORD PTR [rsi+96], ymm9
        vpaddq	ymm8, ymm4, [rbp+128]
        vpaddq	ymm9, ymm5, [rbp+160]
        vmovdqu	YMMWORD PTR [rsi+128], ymm8
        vmovdqu	YMMWORD PTR [rsi+160], ymm9
        vpaddq	ymm8, ymm6, [rbp+192]
        vpaddq	ymm9, ymm7, [rbp+224]
        vmovdqu	YMMWORD PTR [rsi+192], ymm8
        vmovdqu	YMMWORD PTR [rsi+224], ymm9
        ; msg_sched: 0-1
        rorx	rax, r12, 14
        rorx	rcx, r12, 18
        add	r8, rdx
        vpalignr	ymm12, ymm1, ymm0, 8
        add	r15, QWORD PTR [rsi]
        mov	rdx, r13
        xor	rcx, rax
        vpalignr	ymm13, ymm5, ymm4, 8
        xor	rdx, r14
        rorx	rax, r12, 41
        xor	rax, rcx
        vpsrlq	ymm8, ymm12, 1
        vpsllq	ymm9, ymm12, 63
        and	rdx, r12
        add	r15, rax
        rorx	rax, r8, 28
        vpsrlq	ymm10, ymm12, 8
        vpsllq	ymm11, ymm12, 56
        rorx	rcx, r8, 34
        xor	rdx, r14
        xor	rcx, rax
        vpor	ymm8, ymm8, ymm9
        vpor	ymm10, ymm10, ymm11
        rorx	rax, r8, 39
        add	r15, rdx
        xor	rax, rcx
        vpsrlq	ymm11, ymm12, 7
        vpxor	ymm8, ymm8, ymm10
        mov	rdx, r9
        add	r11, r15
        xor	rdx, r8
        vpxor	ymm8, ymm8, ymm11
        vpaddq	ymm0, ymm13, ymm0
        and	rbx, rdx
        add	r15, rax
        xor	rbx, r9
        vpaddq	ymm0, ymm8, ymm0
        rorx	rax, r11, 14
        rorx	rcx, r11, 18
        add	r15, rbx
        vpsrlq	ymm8, ymm7, 19
        vpsllq	ymm9, ymm7, 45
        add	r14, QWORD PTR [rsi+8]
        mov	rbx, r12
        xor	rcx, rax
        vpsrlq	ymm10, ymm7, 61
        vpsllq	ymm11, ymm7, 3
        xor	rbx, r13
        rorx	rax, r11, 41
        xor	rax, rcx
        vpor	ymm8, ymm8, ymm9
        vpor	ymm10, ymm10, ymm11
        and	rbx, r11
        add	r14, rax
        rorx	rax, r15, 28
        rorx	rcx, r15, 34
        xor	rbx, r13
        xor	rcx, rax
        vpxor	ymm8, ymm8, ymm10
        vpsrlq	ymm11, ymm7, 6
        rorx	rax, r15, 39
        add	r14, rbx
        xor	rax, rcx
        mov	rbx, r8
        lea	r10, QWORD PTR [r10+r14]
        xor	rbx, r15
        vpxor	ymm8, ymm8, ymm11
        and	rdx, rbx
        add	r14, rax
        xor	rdx, r8
        vpaddq	ymm0, ymm8, ymm0
        ; msg_sched done: 0-1
        ; msg_sched: 4-5
        rorx	rax, r10, 14
        rorx	rcx, r10, 18
        add	r14, rdx
        vpalignr	ymm12, ymm2, ymm1, 8
        add	r13, QWORD PTR [rsi+32]
        mov	rdx, r11
        xor	rcx, rax
        vpalignr	ymm13, ymm6, ymm5, 8
        xor	rdx, r12
        rorx	rax, r10, 41
        xor	rax, rcx
        vpsrlq	ymm8, ymm12, 1
        vpsllq	ymm9, ymm12, 63
        and	rdx, r10
        add	r13, rax
        rorx	rax, r14, 28
        vpsrlq	ymm10, ymm12, 8
        vpsllq	ymm11, ymm12, 56
        rorx	rcx, r14, 34
        xor	rdx, r12
        xor	rcx, rax
        vpor	ymm8, ymm8, ymm9
        vpor	ymm10, ymm10, ymm11
        rorx	rax, r14, 39
        add	r13, rdx
        xor	rax, rcx
        vpsrlq	ymm11, ymm12, 7
        vpxor	ymm8, ymm8, ymm10
        mov	rdx, r15
        add	r9, r13
        xor	rdx, r14
        vpxor	ymm8, ymm8, ymm11
        vpaddq	ymm1, ymm13, ymm1
        and	rbx, rdx
        add	r13, rax
        xor	rbx, r15
        vpaddq	ymm1, ymm8, ymm1
        rorx	rax, r9, 14
        rorx	rcx, r9, 18
        add	r13, rbx
        vpsrlq	ymm8, ymm0, 19
        vpsllq	ymm9, ymm0, 45
        add	r12, QWORD PTR [rsi+40]
        mov	rbx, r10
        xor	rcx, rax
        vpsrlq	ymm10, ymm0, 61
        vpsllq	ymm11, ymm0, 3
        xor	rbx, r11
        rorx	rax, r9, 41
        xor	rax, rcx
        vpor	ymm8, ymm8, ymm9
        vpor	ymm10, ymm10, ymm11
        and	rbx, r9
        add	r12, rax
        rorx	rax, r13, 28
        rorx	rcx, r13, 34
        xor	rbx, r11
        xor	rcx, rax
        vpxor	ymm8, ymm8, ymm10
        vpsrlq	ymm11, ymm0, 6
        rorx	rax, r13, 39
        add	r12, rbx
        xor	rax, rcx
        mov	rbx, r14
        lea	r8, QWORD PTR [r8+r12]
        xor	rbx, r13
        vpxor	ymm8, ymm8, ymm11
        and	rdx, rbx
        add	r12, rax
        xor	rdx, r14
        vpaddq	ymm1, ymm8, ymm1
        ; msg_sched done: 4-5
        ; msg_sched: 8-9
        rorx	rax, r8, 14
        rorx	rcx, r8, 18
        add	r12, rdx
        vpalignr	ymm12, ymm3, ymm2, 8
        add	r11, QWORD PTR [rsi+64]
        mov	rdx, r9
        xor	rcx, rax
        vpalignr	ymm13, ymm7, ymm6, 8
        xor	rdx, r10
        rorx	rax, r8, 41
        xor	rax, rcx
        vpsrlq	ymm8, ymm12, 1
        vpsllq	ymm9, ymm12, 63
        and	rdx, r8
        add	r11, rax
        rorx	rax, r12, 28
        vpsrlq	ymm10, ymm12, 8
        vpsllq	ymm11, ymm12, 56
        rorx	rcx, r12, 34
        xor	rdx, r10
        xor	rcx, rax
        vpor	ymm8, ymm8, ymm9
        vpor	ymm10, ymm10, ymm11
        rorx	rax, r12, 39
        add	r11, rdx
        xor	rax, rcx
        vpsrlq	ymm11, ymm12, 7
        vpxor	ymm8, ymm8, ymm10
        mov	rdx, r13
        add	r15, r11
        xor	rdx, r12
        vpxor	ymm8, ymm8, ymm11
        vpaddq	ymm2, ymm13, ymm2
        and	rbx, rdx
        add	r11, rax
        xor	rbx, r13
        vpaddq	ymm2, ymm8, ymm2
        rorx	rax, r15, 14
        rorx	rcx, r15, 18
        add	r11, rbx
        vpsrlq	ymm8, ymm1, 19
        vpsllq	ymm9, ymm1, 45
        add	r10, QWORD PTR [rsi+72]
        mov	rbx, r8
        xor	rcx, rax
        vpsrlq	ymm10, ymm1, 61
        vpsllq	ymm11, ymm1, 3
        xor	rbx, r9
        rorx	rax, r15, 41
        xor	rax, rcx
        vpor	ymm8, ymm8, ymm9
        vpor	ymm10, ymm10, ymm11
        and	rbx, r15
        add	r10, rax
        rorx	rax, r11, 28
        rorx	rcx, r11, 34
        xor	rbx, r9
        xor	rcx, rax
        vpxor	ymm8, ymm8, ymm10
        vpsrlq	ymm11, ymm1, 6
        rorx	rax, r11, 39
        add	r10, rbx
        xor	rax, rcx
        mov	rbx, r12
        lea	r14, QWORD PTR [r14+r10]
        xor	rbx, r11
        vpxor	ymm8, ymm8, ymm11
        and	rdx, rbx
        add	r10, rax
        xor	rdx, r12
        vpaddq	ymm2, ymm8, ymm2
        ; msg_sched done: 8-9
        ; msg_sched: 12-13
        rorx	rax, r14, 14
        rorx	rcx, r14, 18
        add	r10, rdx
        vpalignr	ymm12, ymm4, ymm3, 8
        add	r9, QWORD PTR [rsi+96]
        mov	rdx, r15
        xor	rcx, rax
        vpalignr	ymm13, ymm0, ymm7, 8
        xor	rdx, r8
        rorx	rax, r14, 41
        xor	rax, rcx
        vpsrlq	ymm8, ymm12, 1
        vpsllq	ymm9, ymm12, 63
        and	rdx, r14
        add	r9, rax
        rorx	rax, r10, 28
        vpsrlq	ymm10, ymm12, 8
        vpsllq	ymm11, ymm12, 56
        rorx	rcx, r10, 34
        xor	rdx, r8
        xor	rcx, rax
        vpor	ymm8, ymm8, ymm9
        vpor	ymm10, ymm10, ymm11
        rorx	rax, r10, 39
        add	r9, rdx
        xor	rax, rcx
        vpsrlq	ymm11, ymm12, 7
        vpxor	ymm8, ymm8, ymm10
        mov	rdx, r11
        add	r13, r9
        xor	rdx, r10
        vpxor	ymm8, ymm8, ymm11
        vpaddq	ymm3, ymm13, ymm3
        and	rbx, rdx
        add	r9, rax
        xor	rbx, r11
        vpaddq	ymm3, ymm8, ymm3
        rorx	rax, r13, 14
        rorx	rcx, r13, 18
        add	r9, rbx
        vpsrlq	ymm8, ymm2, 19
        vpsllq	ymm9, ymm2, 45
        add	r8, QWORD PTR [rsi+104]
        mov	rbx, r14
        xor	rcx, rax
        vpsrlq	ymm10, ymm2, 61
        vpsllq	ymm11, ymm2, 3
        xor	rbx, r15
        rorx	rax, r13, 41
        xor	rax, rcx
        vpor	ymm8, ymm8, ymm9
        vpor	ymm10, ymm10, ymm11
        and	rbx, r13
        add	r8, rax
        rorx	rax, r9, 28
        rorx	rcx, r9, 34
        xor	rbx, r15
        xor	rcx, rax
        vpxor	ymm8, ymm8, ymm10
        vpsrlq	ymm11, ymm2, 6
        rorx	rax, r9, 39
        add	r8, rbx
        xor	rax, rcx
        mov	rbx, r10
        lea	r12, QWORD PTR [r12+r8]
        xor	rbx, r9
        vpxor	ymm8, ymm8, ymm11
        and	rdx, rbx
        add	r8, rax
        xor	rdx, r10
        vpaddq	ymm3, ymm8, ymm3
        ; msg_sched done: 12-13
        ; msg_sched: 16-17
        rorx	rax, r12, 14
        rorx	rcx, r12, 18
        add	r8, rdx
        vpalignr	ymm12, ymm5, ymm4, 8
        add	r15, QWORD PTR [rsi+128]
        mov	rdx, r13
        xor	rcx, rax
        vpalignr	ymm13, ymm1, ymm0, 8
        xor	rdx, r14
        rorx	rax, r12, 41
        xor	rax, rcx
        vpsrlq	ymm8, ymm12, 1
        vpsllq	ymm9, ymm12, 63
        and	rdx, r12
        add	r15, rax
        rorx	rax, r8, 28
        vpsrlq	ymm10, ymm12, 8
        vpsllq	ymm11, ymm12, 56
        rorx	rcx, r8, 34
        xor	rdx, r14
        xor	rcx, rax
        vpor	ymm8, ymm8, ymm9
        vpor	ymm10, ymm10, ymm11
        rorx	rax, r8, 39
        add	r15, rdx
        xor	rax, rcx
        vpsrlq	ymm11, ymm12, 7
        vpxor	ymm8, ymm8, ymm10
        mov	rdx, r9
        add	r11, r15
        xor	rdx, r8
        vpxor	ymm8, ymm8, ymm11
        vpaddq	ymm4, ymm13, ymm4
        and	rbx, rdx
        add	r15, rax
        xor	rbx, r9
        vpaddq	ymm4, ymm8, ymm4
        rorx	rax, r11, 14
        rorx	rcx, r11, 18
        add	r15, rbx
        vpsrlq	ymm8, ymm3, 19
        vpsllq	ymm9, ymm3, 45
        add	r14, QWORD PTR [rsi+136]
        mov	rbx, r12
        xor	rcx, rax
        vpsrlq	ymm10, ymm3, 61
        vpsllq	ymm11, ymm3, 3
        xor	rbx, r13
        rorx	rax, r11, 41
        xor	rax, rcx
        vpor	ymm8, ymm8, ymm9
        vpor	ymm10, ymm10, ymm11
        and	rbx, r11
        add	r14, rax
        rorx	rax, r15, 28
        rorx	rcx, r15, 34
        xor	rbx, r13
        xor	rcx, rax
        vpxor	ymm8, ymm8, ymm10
        vpsrlq	ymm11, ymm3, 6
        rorx	rax, r15, 39
        add	r14, rbx
        xor	rax, rcx
        mov	rbx, r8
        lea	r10, QWORD PTR [r10+r14]
        xor	rbx, r15
        vpxor	ymm8, ymm8, ymm11
        and	rdx, rbx
        add	r14, rax
        xor	rdx, r8
        vpaddq	ymm4, ymm8, ymm4
        ; msg_sched done: 16-17
        ; msg_sched: 20-21
        rorx	rax, r10, 14
        rorx	rcx, r10, 18
        add	r14, rdx
        vpalignr	ymm12, ymm6, ymm5, 8
        add	r13, QWORD PTR [rsi+160]
        mov	rdx, r11
        xor	rcx, rax
        vpalignr	ymm13, ymm2, ymm1, 8
        xor	rdx, r12
        rorx	rax, r10, 41
        xor	rax, rcx
        vpsrlq	ymm8, ymm12, 1
        vpsllq	ymm9, ymm12, 63
        and	rdx, r10
        add	r13, rax
        rorx	rax, r14, 28
        vpsrlq	ymm10, ymm12, 8
        vpsllq	ymm11, ymm12, 56
        rorx	rcx, r14, 34
        xor	rdx, r12
        xor	rcx, rax
        vpor	ymm8, ymm8, ymm9
        vpor	ymm10, ymm10, ymm11
        rorx	rax, r14, 39
        add	r13, rdx
        xor	rax, rcx
        vpsrlq	ymm11, ymm12, 7
        vpxor	ymm8, ymm8, ymm10
        mov	rdx, r15
        add	r9, r13
        xor	rdx, r14
        vpxor	ymm8, ymm8, ymm11
        vpaddq	ymm5, ymm13, ymm5
        and	rbx, rdx
        add	r13, rax
        xor	rbx, r15
        vpaddq	ymm5, ymm8, ymm5
        rorx	rax, r9, 14
        rorx	rcx, r9, 18
        add	r13, rbx
        vpsrlq	ymm8, ymm4, 19
        vpsllq	ymm9, ymm4, 45
        add	r12, QWORD PTR [rsi+168]
        mov	rbx, r10
        xor	rcx, rax
        vpsrlq	ymm10, ymm4, 61
        vpsllq	ymm11, ymm4, 3
        xor	rbx, r11
        rorx	rax, r9, 41
        xor	rax, rcx
        vpor	ymm8, ymm8, ymm9
        vpor	ymm10, ymm10, ymm11
        and	rbx, r9
        add	r12, rax
        rorx	rax, r13, 28
        rorx	rcx, r13, 34
        xor	rbx, r11
        xor	rcx, rax
        vpxor	ymm8, ymm8, ymm10
        vpsrlq	ymm11, ymm4, 6
        rorx	rax, r13, 39
        add	r12, rbx
        xor	rax, rcx
        mov	rbx, r14
        lea	r8, QWORD PTR [r8+r12]
        xor	rbx, r13
        vpxor	ymm8, ymm8, ymm11
        and	rdx, rbx
        add	r12, rax
        xor	rdx, r14
        vpaddq	ymm5, ymm8, ymm5
        ; msg_sched done: 20-21
        ; msg_sched: 24-25
        rorx	rax, r8, 14
        rorx	rcx, r8, 18
        add	r12, rdx
        vpalignr	ymm12, ymm7, ymm6, 8
        add	r11, QWORD PTR [rsi+192]
        mov	rdx, r9
        xor	rcx, rax
        vpalignr	ymm13, ymm3, ymm2, 8
        xor	rdx, r10
        rorx	rax, r8, 41
        xor	rax, rcx
        vpsrlq	ymm8, ymm12, 1
        vpsllq	ymm9, ymm12, 63
        and	rdx, r8
        add	r11, rax
        rorx	rax, r12, 28
        vpsrlq	ymm10, ymm12, 8
        vpsllq	ymm11, ymm12, 56
        rorx	rcx, r12, 34
        xor	rdx, r10
        xor	rcx, rax
        vpor	ymm8, ymm8, ymm9
        vpor	ymm10, ymm10, ymm11
        rorx	rax, r12, 39
        add	r11, rdx
        xor	rax, rcx
        vpsrlq	ymm11, ymm12, 7
        vpxor	ymm8, ymm8, ymm10
        mov	rdx, r13
        add	r15, r11
        xor	rdx, r12
        vpxor	ymm8, ymm8, ymm11
        vpaddq	ymm6, ymm13, ymm6
        and	rbx, rdx
        add	r11, rax
        xor	rbx, r13
        vpaddq	ymm6, ymm8, ymm6
        rorx	rax, r15, 14
        rorx	rcx, r15, 18
        add	r11, rbx
        vpsrlq	ymm8, ymm5, 19
        vpsllq	ymm9, ymm5, 45
        add	r10, QWORD PTR [rsi+200]
        mov	rbx, r8
        xor	rcx, rax
        vpsrlq	ymm10, ymm5, 61
        vpsllq	ymm11, ymm5, 3
        xor	rbx, r9
        rorx	rax, r15, 41
        xor	rax, rcx
        vpor	ymm8, ymm8, ymm9
        vpor	ymm10, ymm10, ymm11
        and	rbx, r15
        add	r10, rax
        rorx	rax, r11, 28
        rorx	rcx, r11, 34
        xor	rbx, r9
        xor	rcx, rax
        vpxor	ymm8, ymm8, ymm10
        vpsrlq	ymm11, ymm5, 6
        rorx	rax, r11, 39
        add	r10, rbx
        xor	rax, rcx
        mov	rbx, r12
        lea	r14, QWORD PTR [r14+r10]
        xor	rbx, r11
        vpxor	ymm8, ymm8, ymm11
        and	rdx, rbx
        add	r10, rax
        xor	rdx, r12
        vpaddq	ymm6, ymm8, ymm6
        ; msg_sched done: 24-25
        ; msg_sched: 28-29
        rorx	rax, r14, 14
        rorx	rcx, r14, 18
        add	r10, rdx
        vpalignr	ymm12, ymm0, ymm7, 8
        add	r9, QWORD PTR [rsi+224]
        mov	rdx, r15
        xor	rcx, rax
        vpalignr	ymm13, ymm4, ymm3, 8
        xor	rdx, r8
        rorx	rax, r14, 41
        xor	rax, rcx
        vpsrlq	ymm8, ymm12, 1
        vpsllq	ymm9, ymm12, 63
        and	rdx, r14
        add	r9, rax
        rorx	rax, r10, 28
        vpsrlq	ymm10, ymm12, 8
        vpsllq	ymm11, ymm12, 56
        rorx	rcx, r10, 34
        xor	rdx, r8
        xor	rcx, rax
        vpor	ymm8, ymm8, ymm9
        vpor	ymm10, ymm10, ymm11
        rorx	rax, r10, 39
        add	r9, rdx
        xor	rax, rcx
        vpsrlq	ymm11, ymm12, 7
        vpxor	ymm8, ymm8, ymm10
        mov	rdx, r11
        add	r13, r9
        xor	rdx, r10
        vpxor	ymm8, ymm8, ymm11
        vpaddq	ymm7, ymm13, ymm7
        and	rbx, rdx
        add	r9, rax
        xor	rbx, r11
        vpaddq	ymm7, ymm8, ymm7
        rorx	rax, r13, 14
        rorx	rcx, r13, 18
        add	r9, rbx
        vpsrlq	ymm8, ymm6, 19
        vpsllq	ymm9, ymm6, 45
        add	r8, QWORD PTR [rsi+232]
        mov	rbx, r14
        xor	rcx, rax
        vpsrlq	ymm10, ymm6, 61
        vpsllq	ymm11, ymm6, 3
        xor	rbx, r15
        rorx	rax, r13, 41
        xor	rax, rcx
        vpor	ymm8, ymm8, ymm9
        vpor	ymm10, ymm10, ymm11
        and	rbx, r13
        add	r8, rax
        rorx	rax, r9, 28
        rorx	rcx, r9, 34
        xor	rbx, r15
        xor	rcx, rax
        vpxor	ymm8, ymm8, ymm10
        vpsrlq	ymm11, ymm6, 6
        rorx	rax, r9, 39
        add	r8, rbx
        xor	rax, rcx
        mov	rbx, r10
        lea	r12, QWORD PTR [r12+r8]
        xor	rbx, r9
        vpxor	ymm8, ymm8, ymm11
        and	rdx, rbx
        add	r8, rax
        xor	rdx, r10
        vpaddq	ymm7, ymm8, ymm7
        ; msg_sched done: 28-29
        add	rbp, 256
        add	rsi, 256
        cmp	rbp, QWORD PTR [L_avx2_rorx_sha512_k_2_end]
        jne	L_sha512_len_avx2_rorx_start
        vpaddq	ymm8, ymm0, [rbp]
        vpaddq	ymm9, ymm1, [rbp+32]
        vmovdqu	YMMWORD PTR [rsi], ymm8
        vmovdqu	YMMWORD PTR [rsi+32], ymm9
        vpaddq	ymm8, ymm2, [rbp+64]
        vpaddq	ymm9, ymm3, [rbp+96]
        vmovdqu	YMMWORD PTR [rsi+64], ymm8
        vmovdqu	YMMWORD PTR [rsi+96], ymm9
        vpaddq	ymm8, ymm4, [rbp+128]
        vpaddq	ymm9, ymm5, [rbp+160]
        vmovdqu	YMMWORD PTR [rsi+128], ymm8
        vmovdqu	YMMWORD PTR [rsi+160], ymm9
        vpaddq	ymm8, ymm6, [rbp+192]
        vpaddq	ymm9, ymm7, [rbp+224]
        vmovdqu	YMMWORD PTR [rsi+192], ymm8
        vmovdqu	YMMWORD PTR [rsi+224], ymm9
        ; rnd_all_2: 0-1
        rorx	rax, r12, 14
        rorx	rcx, r12, 18
        add	r8, rdx
        add	r15, QWORD PTR [rsi]
        mov	rdx, r13
        xor	rcx, rax
        xor	rdx, r14
        rorx	rax, r12, 41
        xor	rax, rcx
        and	rdx, r12
        add	r15, rax
        rorx	rax, r8, 28
        rorx	rcx, r8, 34
        xor	rdx, r14
        xor	rcx, rax
        rorx	rax, r8, 39
        add	r15, rdx
        xor	rax, rcx
        mov	rdx, r9
        add	r11, r15
        xor	rdx, r8
        and	rbx, rdx
        add	r15, rax
        xor	rbx, r9
        rorx	rax, r11, 14
        rorx	rcx, r11, 18
        add	r15, rbx
        add	r14, QWORD PTR [rsi+8]
        mov	rbx, r12
        xor	rcx, rax
        xor	rbx, r13
        rorx	rax, r11, 41
        xor	rax, rcx
        and	rbx, r11
        add	r14, rax
        rorx	rax, r15, 28
        rorx	rcx, r15, 34
        xor	rbx, r13
        xor	rcx, rax
        rorx	rax, r15, 39
        add	r14, rbx
        xor	rax, rcx
        mov	rbx, r8
        lea	r10, QWORD PTR [r10+r14]
        xor	rbx, r15
        and	rdx, rbx
        add	r14, rax
        xor	rdx, r8
        ; rnd_all_2: 4-5
        rorx	rax, r10, 14
        rorx	rcx, r10, 18
        add	r14, rdx
        add	r13, QWORD PTR [rsi+32]
        mov	rdx, r11
        xor	rcx, rax
        xor	rdx, r12
        rorx	rax, r10, 41
        xor	rax, rcx
        and	rdx, r10
        add	r13, rax
        rorx	rax, r14, 28
        rorx	rcx, r14, 34
        xor	rdx, r12
        xor	rcx, rax
        rorx	rax, r14, 39
        add	r13, rdx
        xor	rax, rcx
        mov	rdx, r15
        add	r9, r13
        xor	rdx, r14
        and	rbx, rdx
        add	r13, rax
        xor	rbx, r15
        rorx	rax, r9, 14
        rorx	rcx, r9, 18
        add	r13, rbx
        add	r12, QWORD PTR [rsi+40]
        mov	rbx, r10
        xor	rcx, rax
        xor	rbx, r11
        rorx	rax, r9, 41
        xor	rax, rcx
        and	rbx, r9
        add	r12, rax
        rorx	rax, r13, 28
        rorx	rcx, r13, 34
        xor	rbx, r11
        xor	rcx, rax
        rorx	rax, r13, 39
        add	r12, rbx
        xor	rax, rcx
        mov	rbx, r14
        lea	r8, QWORD PTR [r8+r12]
        xor	rbx, r13
        and	rdx, rbx
        add	r12, rax
        xor	rdx, r14
        ; rnd_all_2: 8-9
        rorx	rax, r8, 14
        rorx	rcx, r8, 18
        add	r12, rdx
        add	r11, QWORD PTR [rsi+64]
        mov	rdx, r9
        xor	rcx, rax
        xor	rdx, r10
        rorx	rax, r8, 41
        xor	rax, rcx
        and	rdx, r8
        add	r11, rax
        rorx	rax, r12, 28
        rorx	rcx, r12, 34
        xor	rdx, r10
        xor	rcx, rax
        rorx	rax, r12, 39
        add	r11, rdx
        xor	rax, rcx
        mov	rdx, r13
        add	r15, r11
        xor	rdx, r12
        and	rbx, rdx
        add	r11, rax
        xor	rbx, r13
        rorx	rax, r15, 14
        rorx	rcx, r15, 18
        add	r11, rbx
        add	r10, QWORD PTR [rsi+72]
        mov	rbx, r8
        xor	rcx, rax
        xor	rbx, r9
        rorx	rax, r15, 41
        xor	rax, rcx
        and	rbx, r15
        add	r10, rax
        rorx	rax, r11, 28
        rorx	rcx, r11, 34
        xor	rbx, r9
        xor	rcx, rax
        rorx	rax, r11, 39
        add	r10, rbx
        xor	rax, rcx
        mov	rbx, r12
        lea	r14, QWORD PTR [r14+r10]
        xor	rbx, r11
        and	rdx, rbx
        add	r10, rax
        xor	rdx, r12
        ; rnd_all_2: 12-13
        rorx	rax, r14, 14
        rorx	rcx, r14, 18
        add	r10, rdx
        add	r9, QWORD PTR [rsi+96]
        mov	rdx, r15
        xor	rcx, rax
        xor	rdx, r8
        rorx	rax, r14, 41
        xor	rax, rcx
        and	rdx, r14
        add	r9, rax
        rorx	rax, r10, 28
        rorx	rcx, r10, 34
        xor	rdx, r8
        xor	rcx, rax
        rorx	rax, r10, 39
        add	r9, rdx
        xor	rax, rcx
        mov	rdx, r11
        add	r13, r9
        xor	rdx, r10
        and	rbx, rdx
        add	r9, rax
        xor	rbx, r11
        rorx	rax, r13, 14
        rorx	rcx, r13, 18
        add	r9, rbx
        add	r8, QWORD PTR [rsi+104]
        mov	rbx, r14
        xor	rcx, rax
        xor	rbx, r15
        rorx	rax, r13, 41
        xor	rax, rcx
        and	rbx, r13
        add	r8, rax
        rorx	rax, r9, 28
        rorx	rcx, r9, 34
        xor	rbx, r15
        xor	rcx, rax
        rorx	rax, r9, 39
        add	r8, rbx
        xor	rax, rcx
        mov	rbx, r10
        lea	r12, QWORD PTR [r12+r8]
        xor	rbx, r9
        and	rdx, rbx
        add	r8, rax
        xor	rdx, r10
        ; rnd_all_2: 16-17
        rorx	rax, r12, 14
        rorx	rcx, r12, 18
        add	r8, rdx
        add	r15, QWORD PTR [rsi+128]
        mov	rdx, r13
        xor	rcx, rax
        xor	rdx, r14
        rorx	rax, r12, 41
        xor	rax, rcx
        and	rdx, r12
        add	r15, rax
        rorx	rax, r8, 28
        rorx	rcx, r8, 34
        xor	rdx, r14
        xor	rcx, rax
        rorx	rax, r8, 39
        add	r15, rdx
        xor	rax, rcx
        mov	rdx, r9
        add	r11, r15
        xor	rdx, r8
        and	rbx, rdx
        add	r15, rax
        xor	rbx, r9
        rorx	rax, r11, 14
        rorx	rcx, r11, 18
        add	r15, rbx
        add	r14, QWORD PTR [rsi+136]
        mov	rbx, r12
        xor	rcx, rax
        xor	rbx, r13
        rorx	rax, r11, 41
        xor	rax, rcx
        and	rbx, r11
        add	r14, rax
        rorx	rax, r15, 28
        rorx	rcx, r15, 34
        xor	rbx, r13
        xor	rcx, rax
        rorx	rax, r15, 39
        add	r14, rbx
        xor	rax, rcx
        mov	rbx, r8
        lea	r10, QWORD PTR [r10+r14]
        xor	rbx, r15
        and	rdx, rbx
        add	r14, rax
        xor	rdx, r8
        ; rnd_all_2: 20-21
        rorx	rax, r10, 14
        rorx	rcx, r10, 18
        add	r14, rdx
        add	r13, QWORD PTR [rsi+160]
        mov	rdx, r11
        xor	rcx, rax
        xor	rdx, r12
        rorx	rax, r10, 41
        xor	rax, rcx
        and	rdx, r10
        add	r13, rax
        rorx	rax, r14, 28
        rorx	rcx, r14, 34
        xor	rdx, r12
        xor	rcx, rax
        rorx	rax, r14, 39
        add	r13, rdx
        xor	rax, rcx
        mov	rdx, r15
        add	r9, r13
        xor	rdx, r14
        and	rbx, rdx
        add	r13, rax
        xor	rbx, r15
        rorx	rax, r9, 14
        rorx	rcx, r9, 18
        add	r13, rbx
        add	r12, QWORD PTR [rsi+168]
        mov	rbx, r10
        xor	rcx, rax
        xor	rbx, r11
        rorx	rax, r9, 41
        xor	rax, rcx
        and	rbx, r9
        add	r12, rax
        rorx	rax, r13, 28
        rorx	rcx, r13, 34
        xor	rbx, r11
        xor	rcx, rax
        rorx	rax, r13, 39
        add	r12, rbx
        xor	rax, rcx
        mov	rbx, r14
        lea	r8, QWORD PTR [r8+r12]
        xor	rbx, r13
        and	rdx, rbx
        add	r12, rax
        xor	rdx, r14
        ; rnd_all_2: 24-25
        rorx	rax, r8, 14
        rorx	rcx, r8, 18
        add	r12, rdx
        add	r11, QWORD PTR [rsi+192]
        mov	rdx, r9
        xor	rcx, rax
        xor	rdx, r10
        rorx	rax, r8, 41
        xor	rax, rcx
        and	rdx, r8
        add	r11, rax
        rorx	rax, r12, 28
        rorx	rcx, r12, 34
        xor	rdx, r10
        xor	rcx, rax
        rorx	rax, r12, 39
        add	r11, rdx
        xor	rax, rcx
        mov	rdx, r13
        add	r15, r11
        xor	rdx, r12
        and	rbx, rdx
        add	r11, rax
        xor	rbx, r13
        rorx	rax, r15, 14
        rorx	rcx, r15, 18
        add	r11, rbx
        add	r10, QWORD PTR [rsi+200]
        mov	rbx, r8
        xor	rcx, rax
        xor	rbx, r9
        rorx	rax, r15, 41
        xor	rax, rcx
        and	rbx, r15
        add	r10, rax
        rorx	rax, r11, 28
        rorx	rcx, r11, 34
        xor	rbx, r9
        xor	rcx, rax
        rorx	rax, r11, 39
        add	r10, rbx
        xor	rax, rcx
        mov	rbx, r12
        lea	r14, QWORD PTR [r14+r10]
        xor	rbx, r11
        and	rdx, rbx
        add	r10, rax
        xor	rdx, r12
        ; rnd_all_2: 28-29
        rorx	rax, r14, 14
        rorx	rcx, r14, 18
        add	r10, rdx
        add	r9, QWORD PTR [rsi+224]
        mov	rdx, r15
        xor	rcx, rax
        xor	rdx, r8
        rorx	rax, r14, 41
        xor	rax, rcx
        and	rdx, r14
        add	r9, rax
        rorx	rax, r10, 28
        rorx	rcx, r10, 34
        xor	rdx, r8
        xor	rcx, rax
        rorx	rax, r10, 39
        add	r9, rdx
        xor	rax, rcx
        mov	rdx, r11
        add	r13, r9
        xor	rdx, r10
        and	rbx, rdx
        add	r9, rax
        xor	rbx, r11
        rorx	rax, r13, 14
        rorx	rcx, r13, 18
        add	r9, rbx
        add	r8, QWORD PTR [rsi+232]
        mov	rbx, r14
        xor	rcx, rax
        xor	rbx, r15
        rorx	rax, r13, 41
        xor	rax, rcx
        and	rbx, r13
        add	r8, rax
        rorx	rax, r9, 28
        rorx	rcx, r9, 34
        xor	rbx, r15
        xor	rcx, rax
        rorx	rax, r9, 39
        add	r8, rbx
        xor	rax, rcx
        mov	rbx, r10
        lea	r12, QWORD PTR [r12+r8]
        xor	rbx, r9
        and	rdx, rbx
        add	r8, rax
        xor	rdx, r10
        add	r8, rdx
        sub	rsi, 1024
        add	r8, QWORD PTR [rdi]
        add	r9, QWORD PTR [rdi+8]
        add	r10, QWORD PTR [rdi+16]
        add	r11, QWORD PTR [rdi+24]
        add	r12, QWORD PTR [rdi+32]
        add	r13, QWORD PTR [rdi+40]
        add	r14, QWORD PTR [rdi+48]
        add	r15, QWORD PTR [rdi+56]
        mov	QWORD PTR [rdi], r8
        mov	QWORD PTR [rdi+8], r9
        mov	QWORD PTR [rdi+16], r10
        mov	QWORD PTR [rdi+24], r11
        mov	QWORD PTR [rdi+32], r12
        mov	QWORD PTR [rdi+40], r13
        mov	QWORD PTR [rdi+48], r14
        mov	QWORD PTR [rdi+56], r15
        mov	rbx, r9
        xor	rdx, rdx
        xor	rbx, r10
        mov	rbp, 5
L_sha512_len_avx2_rorx_tail:
        ; rnd_all_2: 2-3
        rorx	rax, r12, 14
        rorx	rcx, r12, 18
        add	r8, rdx
        add	r15, QWORD PTR [rsi+16]
        mov	rdx, r13
        xor	rcx, rax
        xor	rdx, r14
        rorx	rax, r12, 41
        xor	rax, rcx
        and	rdx, r12
        add	r15, rax
        rorx	rax, r8, 28
        rorx	rcx, r8, 34
        xor	rdx, r14
        xor	rcx, rax
        rorx	rax, r8, 39
        add	r15, rdx
        xor	rax, rcx
        mov	rdx, r9
        add	r11, r15
        xor	rdx, r8
        and	rbx, rdx
        add	r15, rax
        xor	rbx, r9
        rorx	rax, r11, 14
        rorx	rcx, r11, 18
        add	r15, rbx
        add	r14, QWORD PTR [rsi+24]
        mov	rbx, r12
        xor	rcx, rax
        xor	rbx, r13
        rorx	rax, r11, 41
        xor	rax, rcx
        and	rbx, r11
        add	r14, rax
        rorx	rax, r15, 28
        rorx	rcx, r15, 34
        xor	rbx, r13
        xor	rcx, rax
        rorx	rax, r15, 39
        add	r14, rbx
        xor	rax, rcx
        mov	rbx, r8
        lea	r10, QWORD PTR [r10+r14]
        xor	rbx, r15
        and	rdx, rbx
        add	r14, rax
        xor	rdx, r8
        ; rnd_all_2: 6-7
        rorx	rax, r10, 14
        rorx	rcx, r10, 18
        add	r14, rdx
        add	r13, QWORD PTR [rsi+48]
        mov	rdx, r11
        xor	rcx, rax
        xor	rdx, r12
        rorx	rax, r10, 41
        xor	rax, rcx
        and	rdx, r10
        add	r13, rax
        rorx	rax, r14, 28
        rorx	rcx, r14, 34
        xor	rdx, r12
        xor	rcx, rax
        rorx	rax, r14, 39
        add	r13, rdx
        xor	rax, rcx
        mov	rdx, r15
        add	r9, r13
        xor	rdx, r14
        and	rbx, rdx
        add	r13, rax
        xor	rbx, r15
        rorx	rax, r9, 14
        rorx	rcx, r9, 18
        add	r13, rbx
        add	r12, QWORD PTR [rsi+56]
        mov	rbx, r10
        xor	rcx, rax
        xor	rbx, r11
        rorx	rax, r9, 41
        xor	rax, rcx
        and	rbx, r9
        add	r12, rax
        rorx	rax, r13, 28
        rorx	rcx, r13, 34
        xor	rbx, r11
        xor	rcx, rax
        rorx	rax, r13, 39
        add	r12, rbx
        xor	rax, rcx
        mov	rbx, r14
        lea	r8, QWORD PTR [r8+r12]
        xor	rbx, r13
        and	rdx, rbx
        add	r12, rax
        xor	rdx, r14
        ; rnd_all_2: 10-11
        rorx	rax, r8, 14
        rorx	rcx, r8, 18
        add	r12, rdx
        add	r11, QWORD PTR [rsi+80]
        mov	rdx, r9
        xor	rcx, rax
        xor	rdx, r10
        rorx	rax, r8, 41
        xor	rax, rcx
        and	rdx, r8
        add	r11, rax
        rorx	rax, r12, 28
        rorx	rcx, r12, 34
        xor	rdx, r10
        xor	rcx, rax
        rorx	rax, r12, 39
        add	r11, rdx
        xor	rax, rcx
        mov	rdx, r13
        add	r15, r11
        xor	rdx, r12
        and	rbx, rdx
        add	r11, rax
        xor	rbx, r13
        rorx	rax, r15, 14
        rorx	rcx, r15, 18
        add	r11, rbx
        add	r10, QWORD PTR [rsi+88]
        mov	rbx, r8
        xor	rcx, rax
        xor	rbx, r9
        rorx	rax, r15, 41
        xor	rax, rcx
        and	rbx, r15
        add	r10, rax
        rorx	rax, r11, 28
        rorx	rcx, r11, 34
        xor	rbx, r9
        xor	rcx, rax
        rorx	rax, r11, 39
        add	r10, rbx
        xor	rax, rcx
        mov	rbx, r12
        lea	r14, QWORD PTR [r14+r10]
        xor	rbx, r11
        and	rdx, rbx
        add	r10, rax
        xor	rdx, r12
        ; rnd_all_2: 14-15
        rorx	rax, r14, 14
        rorx	rcx, r14, 18
        add	r10, rdx
        add	r9, QWORD PTR [rsi+112]
        mov	rdx, r15
        xor	rcx, rax
        xor	rdx, r8
        rorx	rax, r14, 41
        xor	rax, rcx
        and	rdx, r14
        add	r9, rax
        rorx	rax, r10, 28
        rorx	rcx, r10, 34
        xor	rdx, r8
        xor	rcx, rax
        rorx	rax, r10, 39
        add	r9, rdx
        xor	rax, rcx
        mov	rdx, r11
        add	r13, r9
        xor	rdx, r10
        and	rbx, rdx
        add	r9, rax
        xor	rbx, r11
        rorx	rax, r13, 14
        rorx	rcx, r13, 18
        add	r9, rbx
        add	r8, QWORD PTR [rsi+120]
        mov	rbx, r14
        xor	rcx, rax
        xor	rbx, r15
        rorx	rax, r13, 41
        xor	rax, rcx
        and	rbx, r13
        add	r8, rax
        rorx	rax, r9, 28
        rorx	rcx, r9, 34
        xor	rbx, r15
        xor	rcx, rax
        rorx	rax, r9, 39
        add	r8, rbx
        xor	rax, rcx
        mov	rbx, r10
        lea	r12, QWORD PTR [r12+r8]
        xor	rbx, r9
        and	rdx, rbx
        add	r8, rax
        xor	rdx, r10
        ; rnd_all_2: 18-19
        rorx	rax, r12, 14
        rorx	rcx, r12, 18
        add	r8, rdx
        add	r15, QWORD PTR [rsi+144]
        mov	rdx, r13
        xor	rcx, rax
        xor	rdx, r14
        rorx	rax, r12, 41
        xor	rax, rcx
        and	rdx, r12
        add	r15, rax
        rorx	rax, r8, 28
        rorx	rcx, r8, 34
        xor	rdx, r14
        xor	rcx, rax
        rorx	rax, r8, 39
        add	r15, rdx
        xor	rax, rcx
        mov	rdx, r9
        add	r11, r15
        xor	rdx, r8
        and	rbx, rdx
        add	r15, rax
        xor	rbx, r9
        rorx	rax, r11, 14
        rorx	rcx, r11, 18
        add	r15, rbx
        add	r14, QWORD PTR [rsi+152]
        mov	rbx, r12
        xor	rcx, rax
        xor	rbx, r13
        rorx	rax, r11, 41
        xor	rax, rcx
        and	rbx, r11
        add	r14, rax
        rorx	rax, r15, 28
        rorx	rcx, r15, 34
        xor	rbx, r13
        xor	rcx, rax
        rorx	rax, r15, 39
        add	r14, rbx
        xor	rax, rcx
        mov	rbx, r8
        lea	r10, QWORD PTR [r10+r14]
        xor	rbx, r15
        and	rdx, rbx
        add	r14, rax
        xor	rdx, r8
        ; rnd_all_2: 22-23
        rorx	rax, r10, 14
        rorx	rcx, r10, 18
        add	r14, rdx
        add	r13, QWORD PTR [rsi+176]
        mov	rdx, r11
        xor	rcx, rax
        xor	rdx, r12
        rorx	rax, r10, 41
        xor	rax, rcx
        and	rdx, r10
        add	r13, rax
        rorx	rax, r14, 28
        rorx	rcx, r14, 34
        xor	rdx, r12
        xor	rcx, rax
        rorx	rax, r14, 39
        add	r13, rdx
        xor	rax, rcx
        mov	rdx, r15
        add	r9, r13
        xor	rdx, r14
        and	rbx, rdx
        add	r13, rax
        xor	rbx, r15
        rorx	rax, r9, 14
        rorx	rcx, r9, 18
        add	r13, rbx
        add	r12, QWORD PTR [rsi+184]
        mov	rbx, r10
        xor	rcx, rax
        xor	rbx, r11
        rorx	rax, r9, 41
        xor	rax, rcx
        and	rbx, r9
        add	r12, rax
        rorx	rax, r13, 28
        rorx	rcx, r13, 34
        xor	rbx, r11
        xor	rcx, rax
        rorx	rax, r13, 39
        add	r12, rbx
        xor	rax, rcx
        mov	rbx, r14
        lea	r8, QWORD PTR [r8+r12]
        xor	rbx, r13
        and	rdx, rbx
        add	r12, rax
        xor	rdx, r14
        ; rnd_all_2: 26-27
        rorx	rax, r8, 14
        rorx	rcx, r8, 18
        add	r12, rdx
        add	r11, QWORD PTR [rsi+208]
        mov	rdx, r9
        xor	rcx, rax
        xor	rdx, r10
        rorx	rax, r8, 41
        xor	rax, rcx
        and	rdx, r8
        add	r11, rax
        rorx	rax, r12, 28
        rorx	rcx, r12, 34
        xor	rdx, r10
        xor	rcx, rax
        rorx	rax, r12, 39
        add	r11, rdx
        xor	rax, rcx
        mov	rdx, r13
        add	r15, r11
        xor	rdx, r12
        and	rbx, rdx
        add	r11, rax
        xor	rbx, r13
        rorx	rax, r15, 14
        rorx	rcx, r15, 18
        add	r11, rbx
        add	r10, QWORD PTR [rsi+216]
        mov	rbx, r8
        xor	rcx, rax
        xor	rbx, r9
        rorx	rax, r15, 41
        xor	rax, rcx
        and	rbx, r15
        add	r10, rax
        rorx	rax, r11, 28
        rorx	rcx, r11, 34
        xor	rbx, r9
        xor	rcx, rax
        rorx	rax, r11, 39
        add	r10, rbx
        xor	rax, rcx
        mov	rbx, r12
        lea	r14, QWORD PTR [r14+r10]
        xor	rbx, r11
        and	rdx, rbx
        add	r10, rax
        xor	rdx, r12
        ; rnd_all_2: 30-31
        rorx	rax, r14, 14
        rorx	rcx, r14, 18
        add	r10, rdx
        add	r9, QWORD PTR [rsi+240]
        mov	rdx, r15
        xor	rcx, rax
        xor	rdx, r8
        rorx	rax, r14, 41
        xor	rax, rcx
        and	rdx, r14
        add	r9, rax
        rorx	rax, r10, 28
        rorx	rcx, r10, 34
        xor	rdx, r8
        xor	rcx, rax
        rorx	rax, r10, 39
        add	r9, rdx
        xor	rax, rcx
        mov	rdx, r11
        add	r13, r9
        xor	rdx, r10
        and	rbx, rdx
        add	r9, rax
        xor	rbx, r11
        rorx	rax, r13, 14
        rorx	rcx, r13, 18
        add	r9, rbx
        add	r8, QWORD PTR [rsi+248]
        mov	rbx, r14
        xor	rcx, rax
        xor	rbx, r15
        rorx	rax, r13, 41
        xor	rax, rcx
        and	rbx, r13
        add	r8, rax
        rorx	rax, r9, 28
        rorx	rcx, r9, 34
        xor	rbx, r15
        xor	rcx, rax
        rorx	rax, r9, 39
        add	r8, rbx
        xor	rax, rcx
        mov	rbx, r10
        lea	r12, QWORD PTR [r12+r8]
        xor	rbx, r9
        and	rdx, rbx
        add	r8, rax
        xor	rdx, r10
        add	rsi, 256
        sub	rbp, 1
        jnz	L_sha512_len_avx2_rorx_tail
        add	r8, rdx
        add	r8, QWORD PTR [rdi]
        add	r9, QWORD PTR [rdi+8]
        add	r10, QWORD PTR [rdi+16]
        add	r11, QWORD PTR [rdi+24]
        add	r12, QWORD PTR [rdi+32]
        add	r13, QWORD PTR [rdi+40]
        add	r14, QWORD PTR [rdi+48]
        add	r15, QWORD PTR [rdi+56]
        mov	rax, QWORD PTR [rdi+224]
        add	rax, 256
        sub	DWORD PTR [rsp+1344], 256
        mov	QWORD PTR [rdi+224], rax
        mov	QWORD PTR [rdi], r8
        mov	QWORD PTR [rdi+8], r9
        mov	QWORD PTR [rdi+16], r10
        mov	QWORD PTR [rdi+24], r11
        mov	QWORD PTR [rdi+32], r12
        mov	QWORD PTR [rdi+40], r13
        mov	QWORD PTR [rdi+48], r14
        mov	QWORD PTR [rdi+56], r15
        jnz	L_sha512_len_avx2_rorx_begin
        add	rsp, 1352
L_sha512_len_avx2_rorx_done:
        xor	rax, rax
        vzeroupper
        vmovdqu	xmm6, OWORD PTR [rsp]
        vmovdqu	xmm7, OWORD PTR [rsp+16]
        vmovdqu	xmm8, OWORD PTR [rsp+32]
        vmovdqu	xmm9, OWORD PTR [rsp+48]
        vmovdqu	xmm10, OWORD PTR [rsp+64]
        vmovdqu	xmm11, OWORD PTR [rsp+80]
        vmovdqu	xmm14, OWORD PTR [rsp+96]
        vmovdqu	xmm13, OWORD PTR [rsp+112]
        vmovdqu	xmm12, OWORD PTR [rsp+128]
        vmovdqu	xmm15, OWORD PTR [rsp+144]
        add	rsp, 160
        pop	rbp
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        pop	rbx
        ret
Transform_Sha512_AVX2_RORX_Len ENDP
_TEXT ENDS
ENDIF
END
