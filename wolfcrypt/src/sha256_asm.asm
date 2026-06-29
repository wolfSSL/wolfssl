; /* sha256_asm.asm */
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

IFDEF WOLFSSL_X86_64_BUILD
_DATA SEGMENT
ALIGN 16
L_sse2_sha256_sha_k DWORD 428a2f98h, 71374491h, 0b5c0fbcfh, 0e9b5dba5h
        DWORD 3956c25bh, 59f111f1h, 923f82a4h, 0ab1c5ed5h
        DWORD 0d807aa98h, 12835b01h, 243185beh, 550c7dc3h
        DWORD 72be5d74h, 80deb1feh, 9bdc06a7h, 0c19bf174h
        DWORD 0e49b69c1h, 0efbe4786h, 0fc19dc6h, 240ca1cch
        DWORD 2de92c6fh, 4a7484aah, 5cb0a9dch, 76f988dah
        DWORD 983e5152h, 0a831c66dh, 0b00327c8h, 0bf597fc7h
        DWORD 0c6e00bf3h, 0d5a79147h, 06ca6351h, 14292967h
        DWORD 27b70a85h, 2e1b2138h, 4d2c6dfch, 53380d13h
        DWORD 650a7354h, 766a0abbh, 81c2c92eh, 92722c85h
        DWORD 0a2bfe8a1h, 0a81a664bh, 0c24b8b70h, 0c76c51a3h
        DWORD 0d192e819h, 0d6990624h, 0f40e3585h, 106aa070h
        DWORD 19a4c116h, 1e376c08h, 2748774ch, 34b0bcb5h
        DWORD 391c0cb3h, 4ed8aa4ah, 5b9cca4fh, 682e6ff3h
        DWORD 748f82eeh, 78a5636fh, 84c87814h, 8cc70208h
        DWORD 90befffah, 0a4506cebh, 0bef9a3f7h, 0c67178f2h
ptr_L_sse2_sha256_sha_k QWORD L_sse2_sha256_sha_k
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_sse2_sha256_shuf_mask QWORD 0405060700010203h, 0c0d0e0f08090a0bh
ptr_L_sse2_sha256_shuf_mask QWORD L_sse2_sha256_shuf_mask
_DATA ENDS
_TEXT SEGMENT READONLY PARA
Transform_Sha256_SSE2_Sha PROC
        sub	rsp, 80
        vmovdqu	OWORD PTR [rsp], xmm6
        vmovdqu	OWORD PTR [rsp+16], xmm7
        vmovdqu	OWORD PTR [rsp+32], xmm8
        vmovdqu	OWORD PTR [rsp+48], xmm9
        vmovdqu	OWORD PTR [rsp+64], xmm10
        mov	rax, QWORD PTR [ptr_L_sse2_sha256_sha_k]
        movdqa	xmm10, OWORD PTR L_sse2_sha256_shuf_mask
        movq	xmm1, QWORD PTR [rcx]
        movq	xmm2, QWORD PTR [rcx+8]
        movhpd	xmm1, QWORD PTR [rcx+16]
        movhpd	xmm2, QWORD PTR [rcx+24]
        pshufd	xmm1, xmm1, 27
        pshufd	xmm2, xmm2, 27
        movdqu	xmm3, OWORD PTR [rdx]
        movdqu	xmm4, OWORD PTR [rdx+16]
        movdqu	xmm5, OWORD PTR [rdx+32]
        movdqu	xmm6, OWORD PTR [rdx+48]
        pshufb	xmm3, xmm10
        movdqa	xmm8, xmm1
        movdqa	xmm9, xmm2
        ; Rounds: 0-3
        movdqa	xmm0, xmm3
        paddd	xmm0, OWORD PTR [rax]
        sha256rnds2	xmm2, xmm1, xmm0
        pshufd	xmm0, xmm0, 14
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 4-7
        pshufb	xmm4, xmm10
        movdqa	xmm0, xmm4
        paddd	xmm0, OWORD PTR [rax+16]
        sha256rnds2	xmm2, xmm1, xmm0
        pshufd	xmm0, xmm0, 14
        sha256msg1	xmm3, xmm4
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 8-11
        pshufb	xmm5, xmm10
        movdqa	xmm0, xmm5
        paddd	xmm0, OWORD PTR [rax+32]
        sha256rnds2	xmm2, xmm1, xmm0
        pshufd	xmm0, xmm0, 14
        sha256msg1	xmm4, xmm5
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 12-15
        pshufb	xmm6, xmm10
        movdqa	xmm0, xmm6
        paddd	xmm0, OWORD PTR [rax+48]
        sha256rnds2	xmm2, xmm1, xmm0
        movdqa	xmm7, xmm6
        palignr	xmm7, xmm5, 4
        paddd	xmm3, xmm7
        sha256msg2	xmm3, xmm6
        pshufd	xmm0, xmm0, 14
        sha256msg1	xmm5, xmm6
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 16-19
        movdqa	xmm0, xmm3
        paddd	xmm0, OWORD PTR [rax+64]
        sha256rnds2	xmm2, xmm1, xmm0
        movdqa	xmm7, xmm3
        palignr	xmm7, xmm6, 4
        paddd	xmm4, xmm7
        sha256msg2	xmm4, xmm3
        pshufd	xmm0, xmm0, 14
        sha256msg1	xmm6, xmm3
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 20-23
        movdqa	xmm0, xmm4
        paddd	xmm0, OWORD PTR [rax+80]
        sha256rnds2	xmm2, xmm1, xmm0
        movdqa	xmm7, xmm4
        palignr	xmm7, xmm3, 4
        paddd	xmm5, xmm7
        sha256msg2	xmm5, xmm4
        pshufd	xmm0, xmm0, 14
        sha256msg1	xmm3, xmm4
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 24-27
        movdqa	xmm0, xmm5
        paddd	xmm0, OWORD PTR [rax+96]
        sha256rnds2	xmm2, xmm1, xmm0
        movdqa	xmm7, xmm5
        palignr	xmm7, xmm4, 4
        paddd	xmm6, xmm7
        sha256msg2	xmm6, xmm5
        pshufd	xmm0, xmm0, 14
        sha256msg1	xmm4, xmm5
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 28-31
        movdqa	xmm0, xmm6
        paddd	xmm0, OWORD PTR [rax+112]
        sha256rnds2	xmm2, xmm1, xmm0
        movdqa	xmm7, xmm6
        palignr	xmm7, xmm5, 4
        paddd	xmm3, xmm7
        sha256msg2	xmm3, xmm6
        pshufd	xmm0, xmm0, 14
        sha256msg1	xmm5, xmm6
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 32-35
        movdqa	xmm0, xmm3
        paddd	xmm0, OWORD PTR [rax+128]
        sha256rnds2	xmm2, xmm1, xmm0
        movdqa	xmm7, xmm3
        palignr	xmm7, xmm6, 4
        paddd	xmm4, xmm7
        sha256msg2	xmm4, xmm3
        pshufd	xmm0, xmm0, 14
        sha256msg1	xmm6, xmm3
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 36-39
        movdqa	xmm0, xmm4
        paddd	xmm0, OWORD PTR [rax+144]
        sha256rnds2	xmm2, xmm1, xmm0
        movdqa	xmm7, xmm4
        palignr	xmm7, xmm3, 4
        paddd	xmm5, xmm7
        sha256msg2	xmm5, xmm4
        pshufd	xmm0, xmm0, 14
        sha256msg1	xmm3, xmm4
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 40-43
        movdqa	xmm0, xmm5
        paddd	xmm0, OWORD PTR [rax+160]
        sha256rnds2	xmm2, xmm1, xmm0
        movdqa	xmm7, xmm5
        palignr	xmm7, xmm4, 4
        paddd	xmm6, xmm7
        sha256msg2	xmm6, xmm5
        pshufd	xmm0, xmm0, 14
        sha256msg1	xmm4, xmm5
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 44-47
        movdqa	xmm0, xmm6
        paddd	xmm0, OWORD PTR [rax+176]
        sha256rnds2	xmm2, xmm1, xmm0
        movdqa	xmm7, xmm6
        palignr	xmm7, xmm5, 4
        paddd	xmm3, xmm7
        sha256msg2	xmm3, xmm6
        pshufd	xmm0, xmm0, 14
        sha256msg1	xmm5, xmm6
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 48-51
        movdqa	xmm0, xmm3
        paddd	xmm0, OWORD PTR [rax+192]
        sha256rnds2	xmm2, xmm1, xmm0
        movdqa	xmm7, xmm3
        palignr	xmm7, xmm6, 4
        paddd	xmm4, xmm7
        sha256msg2	xmm4, xmm3
        pshufd	xmm0, xmm0, 14
        sha256msg1	xmm6, xmm3
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 52-63
        movdqa	xmm0, xmm4
        paddd	xmm0, OWORD PTR [rax+208]
        sha256rnds2	xmm2, xmm1, xmm0
        movdqa	xmm7, xmm4
        palignr	xmm7, xmm3, 4
        paddd	xmm5, xmm7
        sha256msg2	xmm5, xmm4
        pshufd	xmm0, xmm0, 14
        sha256rnds2	xmm1, xmm2, xmm0
        movdqa	xmm0, xmm5
        paddd	xmm0, OWORD PTR [rax+224]
        sha256rnds2	xmm2, xmm1, xmm0
        movdqa	xmm7, xmm5
        palignr	xmm7, xmm4, 4
        paddd	xmm6, xmm7
        sha256msg2	xmm6, xmm5
        pshufd	xmm0, xmm0, 14
        sha256rnds2	xmm1, xmm2, xmm0
        movdqa	xmm0, xmm6
        paddd	xmm0, OWORD PTR [rax+240]
        sha256rnds2	xmm2, xmm1, xmm0
        pshufd	xmm0, xmm0, 14
        sha256rnds2	xmm1, xmm2, xmm0
        paddd	xmm1, xmm8
        paddd	xmm2, xmm9
        pshufd	xmm1, xmm1, 27
        pshufd	xmm2, xmm2, 27
        movq	QWORD PTR [rcx], xmm1
        movq	QWORD PTR [rcx+8], xmm2
        movhpd	QWORD PTR [rcx+16], xmm1
        movhpd	QWORD PTR [rcx+24], xmm2
        xor	rax, rax
        vmovdqu	xmm6, OWORD PTR [rsp]
        vmovdqu	xmm7, OWORD PTR [rsp+16]
        vmovdqu	xmm8, OWORD PTR [rsp+32]
        vmovdqu	xmm9, OWORD PTR [rsp+48]
        vmovdqu	xmm10, OWORD PTR [rsp+64]
        add	rsp, 80
        ret
Transform_Sha256_SSE2_Sha ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
Transform_Sha256_SSE2_Sha_Len PROC
        sub	rsp, 80
        vmovdqu	OWORD PTR [rsp], xmm6
        vmovdqu	OWORD PTR [rsp+16], xmm7
        vmovdqu	OWORD PTR [rsp+32], xmm8
        vmovdqu	OWORD PTR [rsp+48], xmm9
        vmovdqu	OWORD PTR [rsp+64], xmm10
        mov	rax, QWORD PTR [ptr_L_sse2_sha256_sha_k]
        movdqa	xmm10, OWORD PTR L_sse2_sha256_shuf_mask
        movq	xmm1, QWORD PTR [rcx]
        movq	xmm2, QWORD PTR [rcx+8]
        movhpd	xmm1, QWORD PTR [rcx+16]
        movhpd	xmm2, QWORD PTR [rcx+24]
        pshufd	xmm1, xmm1, 27
        pshufd	xmm2, xmm2, 27
        ; Start of loop processing a block
L_sha256_sha_len_sse2_start:
        movdqu	xmm3, OWORD PTR [rdx]
        movdqu	xmm4, OWORD PTR [rdx+16]
        movdqu	xmm5, OWORD PTR [rdx+32]
        movdqu	xmm6, OWORD PTR [rdx+48]
        pshufb	xmm3, xmm10
        movdqa	xmm8, xmm1
        movdqa	xmm9, xmm2
        ; Rounds: 0-3
        movdqa	xmm0, xmm3
        paddd	xmm0, OWORD PTR [rax]
        sha256rnds2	xmm2, xmm1, xmm0
        pshufd	xmm0, xmm0, 14
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 4-7
        pshufb	xmm4, xmm10
        movdqa	xmm0, xmm4
        paddd	xmm0, OWORD PTR [rax+16]
        sha256rnds2	xmm2, xmm1, xmm0
        pshufd	xmm0, xmm0, 14
        sha256msg1	xmm3, xmm4
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 8-11
        pshufb	xmm5, xmm10
        movdqa	xmm0, xmm5
        paddd	xmm0, OWORD PTR [rax+32]
        sha256rnds2	xmm2, xmm1, xmm0
        pshufd	xmm0, xmm0, 14
        sha256msg1	xmm4, xmm5
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 12-15
        pshufb	xmm6, xmm10
        movdqa	xmm0, xmm6
        paddd	xmm0, OWORD PTR [rax+48]
        sha256rnds2	xmm2, xmm1, xmm0
        movdqa	xmm7, xmm6
        palignr	xmm7, xmm5, 4
        paddd	xmm3, xmm7
        sha256msg2	xmm3, xmm6
        pshufd	xmm0, xmm0, 14
        sha256msg1	xmm5, xmm6
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 16-19
        movdqa	xmm0, xmm3
        paddd	xmm0, OWORD PTR [rax+64]
        sha256rnds2	xmm2, xmm1, xmm0
        movdqa	xmm7, xmm3
        palignr	xmm7, xmm6, 4
        paddd	xmm4, xmm7
        sha256msg2	xmm4, xmm3
        pshufd	xmm0, xmm0, 14
        sha256msg1	xmm6, xmm3
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 20-23
        movdqa	xmm0, xmm4
        paddd	xmm0, OWORD PTR [rax+80]
        sha256rnds2	xmm2, xmm1, xmm0
        movdqa	xmm7, xmm4
        palignr	xmm7, xmm3, 4
        paddd	xmm5, xmm7
        sha256msg2	xmm5, xmm4
        pshufd	xmm0, xmm0, 14
        sha256msg1	xmm3, xmm4
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 24-27
        movdqa	xmm0, xmm5
        paddd	xmm0, OWORD PTR [rax+96]
        sha256rnds2	xmm2, xmm1, xmm0
        movdqa	xmm7, xmm5
        palignr	xmm7, xmm4, 4
        paddd	xmm6, xmm7
        sha256msg2	xmm6, xmm5
        pshufd	xmm0, xmm0, 14
        sha256msg1	xmm4, xmm5
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 28-31
        movdqa	xmm0, xmm6
        paddd	xmm0, OWORD PTR [rax+112]
        sha256rnds2	xmm2, xmm1, xmm0
        movdqa	xmm7, xmm6
        palignr	xmm7, xmm5, 4
        paddd	xmm3, xmm7
        sha256msg2	xmm3, xmm6
        pshufd	xmm0, xmm0, 14
        sha256msg1	xmm5, xmm6
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 32-35
        movdqa	xmm0, xmm3
        paddd	xmm0, OWORD PTR [rax+128]
        sha256rnds2	xmm2, xmm1, xmm0
        movdqa	xmm7, xmm3
        palignr	xmm7, xmm6, 4
        paddd	xmm4, xmm7
        sha256msg2	xmm4, xmm3
        pshufd	xmm0, xmm0, 14
        sha256msg1	xmm6, xmm3
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 36-39
        movdqa	xmm0, xmm4
        paddd	xmm0, OWORD PTR [rax+144]
        sha256rnds2	xmm2, xmm1, xmm0
        movdqa	xmm7, xmm4
        palignr	xmm7, xmm3, 4
        paddd	xmm5, xmm7
        sha256msg2	xmm5, xmm4
        pshufd	xmm0, xmm0, 14
        sha256msg1	xmm3, xmm4
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 40-43
        movdqa	xmm0, xmm5
        paddd	xmm0, OWORD PTR [rax+160]
        sha256rnds2	xmm2, xmm1, xmm0
        movdqa	xmm7, xmm5
        palignr	xmm7, xmm4, 4
        paddd	xmm6, xmm7
        sha256msg2	xmm6, xmm5
        pshufd	xmm0, xmm0, 14
        sha256msg1	xmm4, xmm5
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 44-47
        movdqa	xmm0, xmm6
        paddd	xmm0, OWORD PTR [rax+176]
        sha256rnds2	xmm2, xmm1, xmm0
        movdqa	xmm7, xmm6
        palignr	xmm7, xmm5, 4
        paddd	xmm3, xmm7
        sha256msg2	xmm3, xmm6
        pshufd	xmm0, xmm0, 14
        sha256msg1	xmm5, xmm6
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 48-51
        movdqa	xmm0, xmm3
        paddd	xmm0, OWORD PTR [rax+192]
        sha256rnds2	xmm2, xmm1, xmm0
        movdqa	xmm7, xmm3
        palignr	xmm7, xmm6, 4
        paddd	xmm4, xmm7
        sha256msg2	xmm4, xmm3
        pshufd	xmm0, xmm0, 14
        sha256msg1	xmm6, xmm3
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 52-63
        movdqa	xmm0, xmm4
        paddd	xmm0, OWORD PTR [rax+208]
        sha256rnds2	xmm2, xmm1, xmm0
        movdqa	xmm7, xmm4
        palignr	xmm7, xmm3, 4
        paddd	xmm5, xmm7
        sha256msg2	xmm5, xmm4
        pshufd	xmm0, xmm0, 14
        sha256rnds2	xmm1, xmm2, xmm0
        movdqa	xmm0, xmm5
        paddd	xmm0, OWORD PTR [rax+224]
        sha256rnds2	xmm2, xmm1, xmm0
        movdqa	xmm7, xmm5
        palignr	xmm7, xmm4, 4
        paddd	xmm6, xmm7
        sha256msg2	xmm6, xmm5
        pshufd	xmm0, xmm0, 14
        sha256rnds2	xmm1, xmm2, xmm0
        movdqa	xmm0, xmm6
        paddd	xmm0, OWORD PTR [rax+240]
        sha256rnds2	xmm2, xmm1, xmm0
        pshufd	xmm0, xmm0, 14
        sha256rnds2	xmm1, xmm2, xmm0
        add	rdx, 64
        sub	r8d, 64
        paddd	xmm1, xmm8
        paddd	xmm2, xmm9
        jnz	L_sha256_sha_len_sse2_start
        pshufd	xmm1, xmm1, 27
        pshufd	xmm2, xmm2, 27
        movq	QWORD PTR [rcx], xmm1
        movq	QWORD PTR [rcx+8], xmm2
        movhpd	QWORD PTR [rcx+16], xmm1
        movhpd	QWORD PTR [rcx+24], xmm2
        xor	rax, rax
        vmovdqu	xmm6, OWORD PTR [rsp]
        vmovdqu	xmm7, OWORD PTR [rsp+16]
        vmovdqu	xmm8, OWORD PTR [rsp+32]
        vmovdqu	xmm9, OWORD PTR [rsp+48]
        vmovdqu	xmm10, OWORD PTR [rsp+64]
        add	rsp, 80
        ret
Transform_Sha256_SSE2_Sha_Len ENDP
_TEXT ENDS
IFDEF HAVE_INTEL_AVX1
_DATA SEGMENT
ALIGN 16
L_avx1_sha256_k DWORD 428a2f98h, 71374491h, 0b5c0fbcfh, 0e9b5dba5h
        DWORD 3956c25bh, 59f111f1h, 923f82a4h, 0ab1c5ed5h
        DWORD 0d807aa98h, 12835b01h, 243185beh, 550c7dc3h
        DWORD 72be5d74h, 80deb1feh, 9bdc06a7h, 0c19bf174h
        DWORD 0e49b69c1h, 0efbe4786h, 0fc19dc6h, 240ca1cch
        DWORD 2de92c6fh, 4a7484aah, 5cb0a9dch, 76f988dah
        DWORD 983e5152h, 0a831c66dh, 0b00327c8h, 0bf597fc7h
        DWORD 0c6e00bf3h, 0d5a79147h, 06ca6351h, 14292967h
        DWORD 27b70a85h, 2e1b2138h, 4d2c6dfch, 53380d13h
        DWORD 650a7354h, 766a0abbh, 81c2c92eh, 92722c85h
        DWORD 0a2bfe8a1h, 0a81a664bh, 0c24b8b70h, 0c76c51a3h
        DWORD 0d192e819h, 0d6990624h, 0f40e3585h, 106aa070h
        DWORD 19a4c116h, 1e376c08h, 2748774ch, 34b0bcb5h
        DWORD 391c0cb3h, 4ed8aa4ah, 5b9cca4fh, 682e6ff3h
        DWORD 748f82eeh, 78a5636fh, 84c87814h, 8cc70208h
        DWORD 90befffah, 0a4506cebh, 0bef9a3f7h, 0c67178f2h
ptr_L_avx1_sha256_k QWORD L_avx1_sha256_k
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_avx1_sha256_shuf_00BA QWORD 0b0a090803020100h, 0ffffffffffffffffh
ptr_L_avx1_sha256_shuf_00BA QWORD L_avx1_sha256_shuf_00BA
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_avx1_sha256_shuf_DC00 QWORD 0ffffffffffffffffh, 0b0a090803020100h
ptr_L_avx1_sha256_shuf_DC00 QWORD L_avx1_sha256_shuf_DC00
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_avx1_sha256_flip_mask QWORD 0405060700010203h, 0c0d0e0f08090a0bh
ptr_L_avx1_sha256_flip_mask QWORD L_avx1_sha256_flip_mask
_DATA ENDS
_TEXT SEGMENT READONLY PARA
Transform_Sha256_AVX1 PROC
        push	rbx
        push	r12
        push	r13
        push	r14
        push	r15
        push	rbp
        push	rdi
        push	rsi
        mov	rdi, rcx
        mov	rsi, rdx
        sub	rsp, 192
        vmovdqu	OWORD PTR [rsp+64], xmm6
        vmovdqu	OWORD PTR [rsp+80], xmm7
        vmovdqu	OWORD PTR [rsp+96], xmm8
        vmovdqu	OWORD PTR [rsp+112], xmm9
        vmovdqu	OWORD PTR [rsp+128], xmm10
        vmovdqu	OWORD PTR [rsp+144], xmm11
        vmovdqu	OWORD PTR [rsp+160], xmm12
        vmovdqu	OWORD PTR [rsp+176], xmm13
        mov	rbp, QWORD PTR [ptr_L_avx1_sha256_k]
        vmovdqa	xmm13, OWORD PTR L_avx1_sha256_flip_mask
        vmovdqa	xmm11, OWORD PTR L_avx1_sha256_shuf_00BA
        vmovdqa	xmm12, OWORD PTR L_avx1_sha256_shuf_DC00
        mov	r8d, DWORD PTR [rdi]
        mov	r9d, DWORD PTR [rdi+4]
        mov	r10d, DWORD PTR [rdi+8]
        mov	r11d, DWORD PTR [rdi+12]
        mov	r12d, DWORD PTR [rdi+16]
        mov	r13d, DWORD PTR [rdi+20]
        mov	r14d, DWORD PTR [rdi+24]
        mov	r15d, DWORD PTR [rdi+28]
        ; X0, X1, X2, X3 = W[0..15]
        vmovdqu	xmm0, OWORD PTR [rsi]
        vmovdqu	xmm1, OWORD PTR [rsi+16]
        vpshufb	xmm0, xmm0, xmm13
        vpshufb	xmm1, xmm1, xmm13
        vmovdqu	xmm2, OWORD PTR [rsi+32]
        vmovdqu	xmm3, OWORD PTR [rsi+48]
        vpshufb	xmm2, xmm2, xmm13
        vpshufb	xmm3, xmm3, xmm13
        mov	ebx, r9d
        mov	edx, r12d
        xor	ebx, r10d
        ; set_w_k_xfer_4: 0
        vpaddd	xmm4, xmm0, OWORD PTR [rbp]
        vpaddd	xmm5, xmm1, OWORD PTR [rbp+16]
        vmovdqu	OWORD PTR [rsp], xmm4
        vmovdqu	OWORD PTR [rsp+16], xmm5
        vpaddd	xmm6, xmm2, OWORD PTR [rbp+32]
        vpaddd	xmm7, xmm3, OWORD PTR [rbp+48]
        vmovdqu	OWORD PTR [rsp+32], xmm6
        vmovdqu	OWORD PTR [rsp+48], xmm7
        ; msg_sched: 0-3
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	xmm5, xmm1, xmm0, 4
        vpalignr	xmm4, xmm3, xmm2, 4
        ; rnd_0: 1 - 2
        mov	eax, r9d
        mov	ecx, r13d
        add	r15d, DWORD PTR [rsp]
        xor	ecx, r14d
        xor	edx, r12d
        and	ecx, r12d
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r14d
        xor	edx, r12d
        add	r15d, ecx
        ror	edx, 6
        xor	eax, r8d
        add	r15d, edx
        mov	ecx, r8d
        vpsrld	xmm8, xmm5, 18
        vpslld	xmm9, xmm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r8d
        xor	ebx, r9d
        ror	ecx, 11
        add	r11d, r15d
        xor	ecx, r8d
        add	r15d, ebx
        vpor	xmm6, xmm7, xmm6
        vpor	xmm8, xmm9, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r11d
        add	r15d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r8d
        mov	ecx, r12d
        add	r14d, DWORD PTR [rsp+4]
        xor	ecx, r13d
        vpsrld	xmm9, xmm5, 3
        vpxor	xmm6, xmm8, xmm6
        ; rnd_1: 2 - 3
        xor	edx, r11d
        and	ecx, r11d
        ror	edx, 5
        xor	ecx, r13d
        xor	edx, r11d
        add	r14d, ecx
        vpxor	xmm5, xmm9, xmm6
        vpshufd	xmm6, xmm3, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r15d
        add	r14d, edx
        mov	ecx, r15d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r15d
        xor	eax, r8d
        vpsrld	xmm8, xmm6, 10
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r10d, r14d
        xor	ecx, r15d
        add	r14d, eax
        ror	ecx, 2
        mov	edx, r10d
        add	r14d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm0
        ; rnd_0: 1 - 3
        mov	eax, r15d
        mov	ecx, r11d
        add	r13d, DWORD PTR [rsp+8]
        xor	ecx, r12d
        xor	edx, r10d
        and	ecx, r10d
        ror	edx, 5
        xor	ecx, r12d
        xor	edx, r10d
        add	r13d, ecx
        vpxor	xmm6, xmm7, xmm6
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r14d
        add	r13d, edx
        mov	ecx, r14d
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r14d
        xor	ebx, r15d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r9d, r13d
        xor	ecx, r14d
        add	r13d, ebx
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r9d
        add	r13d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r14d
        mov	ecx, r10d
        add	r12d, DWORD PTR [rsp+12]
        xor	ecx, r11d
        vpsrlq	xmm8, xmm6, 17
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r9d
        and	ecx, r9d
        ror	edx, 5
        xor	ecx, r11d
        xor	edx, r9d
        add	r12d, ecx
        vpsrld	xmm9, xmm6, 10
        vpxor	xmm8, xmm7, xmm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r13d
        add	r12d, edx
        mov	ecx, r13d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r13d
        xor	eax, r14d
        vpxor	xmm9, xmm8, xmm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r8d, r12d
        xor	ecx, r13d
        add	r12d, eax
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r8d
        add	r12d, ecx
        vpaddd	xmm0, xmm9, xmm4
        ; msg_sched done: 0-3
        ; msg_sched: 4-7
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	xmm5, xmm2, xmm1, 4
        vpalignr	xmm4, xmm0, xmm3, 4
        ; rnd_0: 1 - 2
        mov	eax, r13d
        mov	ecx, r9d
        add	r11d, DWORD PTR [rsp+16]
        xor	ecx, r10d
        xor	edx, r8d
        and	ecx, r8d
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r10d
        xor	edx, r8d
        add	r11d, ecx
        ror	edx, 6
        xor	eax, r12d
        add	r11d, edx
        mov	ecx, r12d
        vpsrld	xmm8, xmm5, 18
        vpslld	xmm9, xmm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r12d
        xor	ebx, r13d
        ror	ecx, 11
        add	r15d, r11d
        xor	ecx, r12d
        add	r11d, ebx
        vpor	xmm6, xmm7, xmm6
        vpor	xmm8, xmm9, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r15d
        add	r11d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r12d
        mov	ecx, r8d
        add	r10d, DWORD PTR [rsp+20]
        xor	ecx, r9d
        vpsrld	xmm9, xmm5, 3
        vpxor	xmm6, xmm8, xmm6
        ; rnd_1: 2 - 3
        xor	edx, r15d
        and	ecx, r15d
        ror	edx, 5
        xor	ecx, r9d
        xor	edx, r15d
        add	r10d, ecx
        vpxor	xmm5, xmm9, xmm6
        vpshufd	xmm6, xmm0, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r11d
        add	r10d, edx
        mov	ecx, r11d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r11d
        xor	eax, r12d
        vpsrld	xmm8, xmm6, 10
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r14d, r10d
        xor	ecx, r11d
        add	r10d, eax
        ror	ecx, 2
        mov	edx, r14d
        add	r10d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm1
        ; rnd_0: 1 - 3
        mov	eax, r11d
        mov	ecx, r15d
        add	r9d, DWORD PTR [rsp+24]
        xor	ecx, r8d
        xor	edx, r14d
        and	ecx, r14d
        ror	edx, 5
        xor	ecx, r8d
        xor	edx, r14d
        add	r9d, ecx
        vpxor	xmm6, xmm7, xmm6
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r10d
        add	r9d, edx
        mov	ecx, r10d
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r10d
        xor	ebx, r11d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r13d, r9d
        xor	ecx, r10d
        add	r9d, ebx
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r13d
        add	r9d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r10d
        mov	ecx, r14d
        add	r8d, DWORD PTR [rsp+28]
        xor	ecx, r15d
        vpsrlq	xmm8, xmm6, 17
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r13d
        and	ecx, r13d
        ror	edx, 5
        xor	ecx, r15d
        xor	edx, r13d
        add	r8d, ecx
        vpsrld	xmm9, xmm6, 10
        vpxor	xmm8, xmm7, xmm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r9d
        add	r8d, edx
        mov	ecx, r9d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r9d
        xor	eax, r10d
        vpxor	xmm9, xmm8, xmm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r12d, r8d
        xor	ecx, r9d
        add	r8d, eax
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r12d
        add	r8d, ecx
        vpaddd	xmm1, xmm9, xmm4
        ; msg_sched done: 4-7
        ; msg_sched: 8-11
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	xmm5, xmm3, xmm2, 4
        vpalignr	xmm4, xmm1, xmm0, 4
        ; rnd_0: 1 - 2
        mov	eax, r9d
        mov	ecx, r13d
        add	r15d, DWORD PTR [rsp+32]
        xor	ecx, r14d
        xor	edx, r12d
        and	ecx, r12d
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r14d
        xor	edx, r12d
        add	r15d, ecx
        ror	edx, 6
        xor	eax, r8d
        add	r15d, edx
        mov	ecx, r8d
        vpsrld	xmm8, xmm5, 18
        vpslld	xmm9, xmm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r8d
        xor	ebx, r9d
        ror	ecx, 11
        add	r11d, r15d
        xor	ecx, r8d
        add	r15d, ebx
        vpor	xmm6, xmm7, xmm6
        vpor	xmm8, xmm9, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r11d
        add	r15d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r8d
        mov	ecx, r12d
        add	r14d, DWORD PTR [rsp+36]
        xor	ecx, r13d
        vpsrld	xmm9, xmm5, 3
        vpxor	xmm6, xmm8, xmm6
        ; rnd_1: 2 - 3
        xor	edx, r11d
        and	ecx, r11d
        ror	edx, 5
        xor	ecx, r13d
        xor	edx, r11d
        add	r14d, ecx
        vpxor	xmm5, xmm9, xmm6
        vpshufd	xmm6, xmm1, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r15d
        add	r14d, edx
        mov	ecx, r15d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r15d
        xor	eax, r8d
        vpsrld	xmm8, xmm6, 10
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r10d, r14d
        xor	ecx, r15d
        add	r14d, eax
        ror	ecx, 2
        mov	edx, r10d
        add	r14d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm2
        ; rnd_0: 1 - 3
        mov	eax, r15d
        mov	ecx, r11d
        add	r13d, DWORD PTR [rsp+40]
        xor	ecx, r12d
        xor	edx, r10d
        and	ecx, r10d
        ror	edx, 5
        xor	ecx, r12d
        xor	edx, r10d
        add	r13d, ecx
        vpxor	xmm6, xmm7, xmm6
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r14d
        add	r13d, edx
        mov	ecx, r14d
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r14d
        xor	ebx, r15d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r9d, r13d
        xor	ecx, r14d
        add	r13d, ebx
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r9d
        add	r13d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r14d
        mov	ecx, r10d
        add	r12d, DWORD PTR [rsp+44]
        xor	ecx, r11d
        vpsrlq	xmm8, xmm6, 17
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r9d
        and	ecx, r9d
        ror	edx, 5
        xor	ecx, r11d
        xor	edx, r9d
        add	r12d, ecx
        vpsrld	xmm9, xmm6, 10
        vpxor	xmm8, xmm7, xmm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r13d
        add	r12d, edx
        mov	ecx, r13d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r13d
        xor	eax, r14d
        vpxor	xmm9, xmm8, xmm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r8d, r12d
        xor	ecx, r13d
        add	r12d, eax
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r8d
        add	r12d, ecx
        vpaddd	xmm2, xmm9, xmm4
        ; msg_sched done: 8-11
        ; msg_sched: 12-15
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	xmm5, xmm0, xmm3, 4
        vpalignr	xmm4, xmm2, xmm1, 4
        ; rnd_0: 1 - 2
        mov	eax, r13d
        mov	ecx, r9d
        add	r11d, DWORD PTR [rsp+48]
        xor	ecx, r10d
        xor	edx, r8d
        and	ecx, r8d
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r10d
        xor	edx, r8d
        add	r11d, ecx
        ror	edx, 6
        xor	eax, r12d
        add	r11d, edx
        mov	ecx, r12d
        vpsrld	xmm8, xmm5, 18
        vpslld	xmm9, xmm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r12d
        xor	ebx, r13d
        ror	ecx, 11
        add	r15d, r11d
        xor	ecx, r12d
        add	r11d, ebx
        vpor	xmm6, xmm7, xmm6
        vpor	xmm8, xmm9, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r15d
        add	r11d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r12d
        mov	ecx, r8d
        add	r10d, DWORD PTR [rsp+52]
        xor	ecx, r9d
        vpsrld	xmm9, xmm5, 3
        vpxor	xmm6, xmm8, xmm6
        ; rnd_1: 2 - 3
        xor	edx, r15d
        and	ecx, r15d
        ror	edx, 5
        xor	ecx, r9d
        xor	edx, r15d
        add	r10d, ecx
        vpxor	xmm5, xmm9, xmm6
        vpshufd	xmm6, xmm2, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r11d
        add	r10d, edx
        mov	ecx, r11d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r11d
        xor	eax, r12d
        vpsrld	xmm8, xmm6, 10
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r14d, r10d
        xor	ecx, r11d
        add	r10d, eax
        ror	ecx, 2
        mov	edx, r14d
        add	r10d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm3
        ; rnd_0: 1 - 3
        mov	eax, r11d
        mov	ecx, r15d
        add	r9d, DWORD PTR [rsp+56]
        xor	ecx, r8d
        xor	edx, r14d
        and	ecx, r14d
        ror	edx, 5
        xor	ecx, r8d
        xor	edx, r14d
        add	r9d, ecx
        vpxor	xmm6, xmm7, xmm6
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r10d
        add	r9d, edx
        mov	ecx, r10d
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r10d
        xor	ebx, r11d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r13d, r9d
        xor	ecx, r10d
        add	r9d, ebx
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r13d
        add	r9d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r10d
        mov	ecx, r14d
        add	r8d, DWORD PTR [rsp+60]
        xor	ecx, r15d
        vpsrlq	xmm8, xmm6, 17
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r13d
        and	ecx, r13d
        ror	edx, 5
        xor	ecx, r15d
        xor	edx, r13d
        add	r8d, ecx
        vpsrld	xmm9, xmm6, 10
        vpxor	xmm8, xmm7, xmm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r9d
        add	r8d, edx
        mov	ecx, r9d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r9d
        xor	eax, r10d
        vpxor	xmm9, xmm8, xmm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r12d, r8d
        xor	ecx, r9d
        add	r8d, eax
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r12d
        add	r8d, ecx
        vpaddd	xmm3, xmm9, xmm4
        ; msg_sched done: 12-15
        ; set_w_k_xfer_4: 4
        vpaddd	xmm4, xmm0, OWORD PTR [rbp+64]
        vpaddd	xmm5, xmm1, OWORD PTR [rbp+80]
        vmovdqu	OWORD PTR [rsp], xmm4
        vmovdqu	OWORD PTR [rsp+16], xmm5
        vpaddd	xmm6, xmm2, OWORD PTR [rbp+96]
        vpaddd	xmm7, xmm3, OWORD PTR [rbp+112]
        vmovdqu	OWORD PTR [rsp+32], xmm6
        vmovdqu	OWORD PTR [rsp+48], xmm7
        ; msg_sched: 0-3
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	xmm5, xmm1, xmm0, 4
        vpalignr	xmm4, xmm3, xmm2, 4
        ; rnd_0: 1 - 2
        mov	eax, r9d
        mov	ecx, r13d
        add	r15d, DWORD PTR [rsp]
        xor	ecx, r14d
        xor	edx, r12d
        and	ecx, r12d
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r14d
        xor	edx, r12d
        add	r15d, ecx
        ror	edx, 6
        xor	eax, r8d
        add	r15d, edx
        mov	ecx, r8d
        vpsrld	xmm8, xmm5, 18
        vpslld	xmm9, xmm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r8d
        xor	ebx, r9d
        ror	ecx, 11
        add	r11d, r15d
        xor	ecx, r8d
        add	r15d, ebx
        vpor	xmm6, xmm7, xmm6
        vpor	xmm8, xmm9, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r11d
        add	r15d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r8d
        mov	ecx, r12d
        add	r14d, DWORD PTR [rsp+4]
        xor	ecx, r13d
        vpsrld	xmm9, xmm5, 3
        vpxor	xmm6, xmm8, xmm6
        ; rnd_1: 2 - 3
        xor	edx, r11d
        and	ecx, r11d
        ror	edx, 5
        xor	ecx, r13d
        xor	edx, r11d
        add	r14d, ecx
        vpxor	xmm5, xmm9, xmm6
        vpshufd	xmm6, xmm3, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r15d
        add	r14d, edx
        mov	ecx, r15d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r15d
        xor	eax, r8d
        vpsrld	xmm8, xmm6, 10
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r10d, r14d
        xor	ecx, r15d
        add	r14d, eax
        ror	ecx, 2
        mov	edx, r10d
        add	r14d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm0
        ; rnd_0: 1 - 3
        mov	eax, r15d
        mov	ecx, r11d
        add	r13d, DWORD PTR [rsp+8]
        xor	ecx, r12d
        xor	edx, r10d
        and	ecx, r10d
        ror	edx, 5
        xor	ecx, r12d
        xor	edx, r10d
        add	r13d, ecx
        vpxor	xmm6, xmm7, xmm6
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r14d
        add	r13d, edx
        mov	ecx, r14d
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r14d
        xor	ebx, r15d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r9d, r13d
        xor	ecx, r14d
        add	r13d, ebx
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r9d
        add	r13d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r14d
        mov	ecx, r10d
        add	r12d, DWORD PTR [rsp+12]
        xor	ecx, r11d
        vpsrlq	xmm8, xmm6, 17
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r9d
        and	ecx, r9d
        ror	edx, 5
        xor	ecx, r11d
        xor	edx, r9d
        add	r12d, ecx
        vpsrld	xmm9, xmm6, 10
        vpxor	xmm8, xmm7, xmm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r13d
        add	r12d, edx
        mov	ecx, r13d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r13d
        xor	eax, r14d
        vpxor	xmm9, xmm8, xmm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r8d, r12d
        xor	ecx, r13d
        add	r12d, eax
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r8d
        add	r12d, ecx
        vpaddd	xmm0, xmm9, xmm4
        ; msg_sched done: 0-3
        ; msg_sched: 4-7
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	xmm5, xmm2, xmm1, 4
        vpalignr	xmm4, xmm0, xmm3, 4
        ; rnd_0: 1 - 2
        mov	eax, r13d
        mov	ecx, r9d
        add	r11d, DWORD PTR [rsp+16]
        xor	ecx, r10d
        xor	edx, r8d
        and	ecx, r8d
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r10d
        xor	edx, r8d
        add	r11d, ecx
        ror	edx, 6
        xor	eax, r12d
        add	r11d, edx
        mov	ecx, r12d
        vpsrld	xmm8, xmm5, 18
        vpslld	xmm9, xmm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r12d
        xor	ebx, r13d
        ror	ecx, 11
        add	r15d, r11d
        xor	ecx, r12d
        add	r11d, ebx
        vpor	xmm6, xmm7, xmm6
        vpor	xmm8, xmm9, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r15d
        add	r11d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r12d
        mov	ecx, r8d
        add	r10d, DWORD PTR [rsp+20]
        xor	ecx, r9d
        vpsrld	xmm9, xmm5, 3
        vpxor	xmm6, xmm8, xmm6
        ; rnd_1: 2 - 3
        xor	edx, r15d
        and	ecx, r15d
        ror	edx, 5
        xor	ecx, r9d
        xor	edx, r15d
        add	r10d, ecx
        vpxor	xmm5, xmm9, xmm6
        vpshufd	xmm6, xmm0, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r11d
        add	r10d, edx
        mov	ecx, r11d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r11d
        xor	eax, r12d
        vpsrld	xmm8, xmm6, 10
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r14d, r10d
        xor	ecx, r11d
        add	r10d, eax
        ror	ecx, 2
        mov	edx, r14d
        add	r10d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm1
        ; rnd_0: 1 - 3
        mov	eax, r11d
        mov	ecx, r15d
        add	r9d, DWORD PTR [rsp+24]
        xor	ecx, r8d
        xor	edx, r14d
        and	ecx, r14d
        ror	edx, 5
        xor	ecx, r8d
        xor	edx, r14d
        add	r9d, ecx
        vpxor	xmm6, xmm7, xmm6
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r10d
        add	r9d, edx
        mov	ecx, r10d
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r10d
        xor	ebx, r11d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r13d, r9d
        xor	ecx, r10d
        add	r9d, ebx
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r13d
        add	r9d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r10d
        mov	ecx, r14d
        add	r8d, DWORD PTR [rsp+28]
        xor	ecx, r15d
        vpsrlq	xmm8, xmm6, 17
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r13d
        and	ecx, r13d
        ror	edx, 5
        xor	ecx, r15d
        xor	edx, r13d
        add	r8d, ecx
        vpsrld	xmm9, xmm6, 10
        vpxor	xmm8, xmm7, xmm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r9d
        add	r8d, edx
        mov	ecx, r9d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r9d
        xor	eax, r10d
        vpxor	xmm9, xmm8, xmm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r12d, r8d
        xor	ecx, r9d
        add	r8d, eax
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r12d
        add	r8d, ecx
        vpaddd	xmm1, xmm9, xmm4
        ; msg_sched done: 4-7
        ; msg_sched: 8-11
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	xmm5, xmm3, xmm2, 4
        vpalignr	xmm4, xmm1, xmm0, 4
        ; rnd_0: 1 - 2
        mov	eax, r9d
        mov	ecx, r13d
        add	r15d, DWORD PTR [rsp+32]
        xor	ecx, r14d
        xor	edx, r12d
        and	ecx, r12d
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r14d
        xor	edx, r12d
        add	r15d, ecx
        ror	edx, 6
        xor	eax, r8d
        add	r15d, edx
        mov	ecx, r8d
        vpsrld	xmm8, xmm5, 18
        vpslld	xmm9, xmm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r8d
        xor	ebx, r9d
        ror	ecx, 11
        add	r11d, r15d
        xor	ecx, r8d
        add	r15d, ebx
        vpor	xmm6, xmm7, xmm6
        vpor	xmm8, xmm9, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r11d
        add	r15d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r8d
        mov	ecx, r12d
        add	r14d, DWORD PTR [rsp+36]
        xor	ecx, r13d
        vpsrld	xmm9, xmm5, 3
        vpxor	xmm6, xmm8, xmm6
        ; rnd_1: 2 - 3
        xor	edx, r11d
        and	ecx, r11d
        ror	edx, 5
        xor	ecx, r13d
        xor	edx, r11d
        add	r14d, ecx
        vpxor	xmm5, xmm9, xmm6
        vpshufd	xmm6, xmm1, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r15d
        add	r14d, edx
        mov	ecx, r15d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r15d
        xor	eax, r8d
        vpsrld	xmm8, xmm6, 10
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r10d, r14d
        xor	ecx, r15d
        add	r14d, eax
        ror	ecx, 2
        mov	edx, r10d
        add	r14d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm2
        ; rnd_0: 1 - 3
        mov	eax, r15d
        mov	ecx, r11d
        add	r13d, DWORD PTR [rsp+40]
        xor	ecx, r12d
        xor	edx, r10d
        and	ecx, r10d
        ror	edx, 5
        xor	ecx, r12d
        xor	edx, r10d
        add	r13d, ecx
        vpxor	xmm6, xmm7, xmm6
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r14d
        add	r13d, edx
        mov	ecx, r14d
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r14d
        xor	ebx, r15d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r9d, r13d
        xor	ecx, r14d
        add	r13d, ebx
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r9d
        add	r13d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r14d
        mov	ecx, r10d
        add	r12d, DWORD PTR [rsp+44]
        xor	ecx, r11d
        vpsrlq	xmm8, xmm6, 17
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r9d
        and	ecx, r9d
        ror	edx, 5
        xor	ecx, r11d
        xor	edx, r9d
        add	r12d, ecx
        vpsrld	xmm9, xmm6, 10
        vpxor	xmm8, xmm7, xmm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r13d
        add	r12d, edx
        mov	ecx, r13d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r13d
        xor	eax, r14d
        vpxor	xmm9, xmm8, xmm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r8d, r12d
        xor	ecx, r13d
        add	r12d, eax
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r8d
        add	r12d, ecx
        vpaddd	xmm2, xmm9, xmm4
        ; msg_sched done: 8-11
        ; msg_sched: 12-15
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	xmm5, xmm0, xmm3, 4
        vpalignr	xmm4, xmm2, xmm1, 4
        ; rnd_0: 1 - 2
        mov	eax, r13d
        mov	ecx, r9d
        add	r11d, DWORD PTR [rsp+48]
        xor	ecx, r10d
        xor	edx, r8d
        and	ecx, r8d
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r10d
        xor	edx, r8d
        add	r11d, ecx
        ror	edx, 6
        xor	eax, r12d
        add	r11d, edx
        mov	ecx, r12d
        vpsrld	xmm8, xmm5, 18
        vpslld	xmm9, xmm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r12d
        xor	ebx, r13d
        ror	ecx, 11
        add	r15d, r11d
        xor	ecx, r12d
        add	r11d, ebx
        vpor	xmm6, xmm7, xmm6
        vpor	xmm8, xmm9, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r15d
        add	r11d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r12d
        mov	ecx, r8d
        add	r10d, DWORD PTR [rsp+52]
        xor	ecx, r9d
        vpsrld	xmm9, xmm5, 3
        vpxor	xmm6, xmm8, xmm6
        ; rnd_1: 2 - 3
        xor	edx, r15d
        and	ecx, r15d
        ror	edx, 5
        xor	ecx, r9d
        xor	edx, r15d
        add	r10d, ecx
        vpxor	xmm5, xmm9, xmm6
        vpshufd	xmm6, xmm2, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r11d
        add	r10d, edx
        mov	ecx, r11d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r11d
        xor	eax, r12d
        vpsrld	xmm8, xmm6, 10
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r14d, r10d
        xor	ecx, r11d
        add	r10d, eax
        ror	ecx, 2
        mov	edx, r14d
        add	r10d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm3
        ; rnd_0: 1 - 3
        mov	eax, r11d
        mov	ecx, r15d
        add	r9d, DWORD PTR [rsp+56]
        xor	ecx, r8d
        xor	edx, r14d
        and	ecx, r14d
        ror	edx, 5
        xor	ecx, r8d
        xor	edx, r14d
        add	r9d, ecx
        vpxor	xmm6, xmm7, xmm6
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r10d
        add	r9d, edx
        mov	ecx, r10d
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r10d
        xor	ebx, r11d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r13d, r9d
        xor	ecx, r10d
        add	r9d, ebx
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r13d
        add	r9d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r10d
        mov	ecx, r14d
        add	r8d, DWORD PTR [rsp+60]
        xor	ecx, r15d
        vpsrlq	xmm8, xmm6, 17
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r13d
        and	ecx, r13d
        ror	edx, 5
        xor	ecx, r15d
        xor	edx, r13d
        add	r8d, ecx
        vpsrld	xmm9, xmm6, 10
        vpxor	xmm8, xmm7, xmm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r9d
        add	r8d, edx
        mov	ecx, r9d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r9d
        xor	eax, r10d
        vpxor	xmm9, xmm8, xmm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r12d, r8d
        xor	ecx, r9d
        add	r8d, eax
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r12d
        add	r8d, ecx
        vpaddd	xmm3, xmm9, xmm4
        ; msg_sched done: 12-15
        ; set_w_k_xfer_4: 8
        vpaddd	xmm4, xmm0, OWORD PTR [rbp+128]
        vpaddd	xmm5, xmm1, OWORD PTR [rbp+144]
        vmovdqu	OWORD PTR [rsp], xmm4
        vmovdqu	OWORD PTR [rsp+16], xmm5
        vpaddd	xmm6, xmm2, OWORD PTR [rbp+160]
        vpaddd	xmm7, xmm3, OWORD PTR [rbp+176]
        vmovdqu	OWORD PTR [rsp+32], xmm6
        vmovdqu	OWORD PTR [rsp+48], xmm7
        ; msg_sched: 0-3
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	xmm5, xmm1, xmm0, 4
        vpalignr	xmm4, xmm3, xmm2, 4
        ; rnd_0: 1 - 2
        mov	eax, r9d
        mov	ecx, r13d
        add	r15d, DWORD PTR [rsp]
        xor	ecx, r14d
        xor	edx, r12d
        and	ecx, r12d
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r14d
        xor	edx, r12d
        add	r15d, ecx
        ror	edx, 6
        xor	eax, r8d
        add	r15d, edx
        mov	ecx, r8d
        vpsrld	xmm8, xmm5, 18
        vpslld	xmm9, xmm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r8d
        xor	ebx, r9d
        ror	ecx, 11
        add	r11d, r15d
        xor	ecx, r8d
        add	r15d, ebx
        vpor	xmm6, xmm7, xmm6
        vpor	xmm8, xmm9, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r11d
        add	r15d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r8d
        mov	ecx, r12d
        add	r14d, DWORD PTR [rsp+4]
        xor	ecx, r13d
        vpsrld	xmm9, xmm5, 3
        vpxor	xmm6, xmm8, xmm6
        ; rnd_1: 2 - 3
        xor	edx, r11d
        and	ecx, r11d
        ror	edx, 5
        xor	ecx, r13d
        xor	edx, r11d
        add	r14d, ecx
        vpxor	xmm5, xmm9, xmm6
        vpshufd	xmm6, xmm3, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r15d
        add	r14d, edx
        mov	ecx, r15d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r15d
        xor	eax, r8d
        vpsrld	xmm8, xmm6, 10
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r10d, r14d
        xor	ecx, r15d
        add	r14d, eax
        ror	ecx, 2
        mov	edx, r10d
        add	r14d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm0
        ; rnd_0: 1 - 3
        mov	eax, r15d
        mov	ecx, r11d
        add	r13d, DWORD PTR [rsp+8]
        xor	ecx, r12d
        xor	edx, r10d
        and	ecx, r10d
        ror	edx, 5
        xor	ecx, r12d
        xor	edx, r10d
        add	r13d, ecx
        vpxor	xmm6, xmm7, xmm6
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r14d
        add	r13d, edx
        mov	ecx, r14d
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r14d
        xor	ebx, r15d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r9d, r13d
        xor	ecx, r14d
        add	r13d, ebx
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r9d
        add	r13d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r14d
        mov	ecx, r10d
        add	r12d, DWORD PTR [rsp+12]
        xor	ecx, r11d
        vpsrlq	xmm8, xmm6, 17
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r9d
        and	ecx, r9d
        ror	edx, 5
        xor	ecx, r11d
        xor	edx, r9d
        add	r12d, ecx
        vpsrld	xmm9, xmm6, 10
        vpxor	xmm8, xmm7, xmm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r13d
        add	r12d, edx
        mov	ecx, r13d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r13d
        xor	eax, r14d
        vpxor	xmm9, xmm8, xmm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r8d, r12d
        xor	ecx, r13d
        add	r12d, eax
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r8d
        add	r12d, ecx
        vpaddd	xmm0, xmm9, xmm4
        ; msg_sched done: 0-3
        ; msg_sched: 4-7
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	xmm5, xmm2, xmm1, 4
        vpalignr	xmm4, xmm0, xmm3, 4
        ; rnd_0: 1 - 2
        mov	eax, r13d
        mov	ecx, r9d
        add	r11d, DWORD PTR [rsp+16]
        xor	ecx, r10d
        xor	edx, r8d
        and	ecx, r8d
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r10d
        xor	edx, r8d
        add	r11d, ecx
        ror	edx, 6
        xor	eax, r12d
        add	r11d, edx
        mov	ecx, r12d
        vpsrld	xmm8, xmm5, 18
        vpslld	xmm9, xmm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r12d
        xor	ebx, r13d
        ror	ecx, 11
        add	r15d, r11d
        xor	ecx, r12d
        add	r11d, ebx
        vpor	xmm6, xmm7, xmm6
        vpor	xmm8, xmm9, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r15d
        add	r11d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r12d
        mov	ecx, r8d
        add	r10d, DWORD PTR [rsp+20]
        xor	ecx, r9d
        vpsrld	xmm9, xmm5, 3
        vpxor	xmm6, xmm8, xmm6
        ; rnd_1: 2 - 3
        xor	edx, r15d
        and	ecx, r15d
        ror	edx, 5
        xor	ecx, r9d
        xor	edx, r15d
        add	r10d, ecx
        vpxor	xmm5, xmm9, xmm6
        vpshufd	xmm6, xmm0, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r11d
        add	r10d, edx
        mov	ecx, r11d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r11d
        xor	eax, r12d
        vpsrld	xmm8, xmm6, 10
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r14d, r10d
        xor	ecx, r11d
        add	r10d, eax
        ror	ecx, 2
        mov	edx, r14d
        add	r10d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm1
        ; rnd_0: 1 - 3
        mov	eax, r11d
        mov	ecx, r15d
        add	r9d, DWORD PTR [rsp+24]
        xor	ecx, r8d
        xor	edx, r14d
        and	ecx, r14d
        ror	edx, 5
        xor	ecx, r8d
        xor	edx, r14d
        add	r9d, ecx
        vpxor	xmm6, xmm7, xmm6
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r10d
        add	r9d, edx
        mov	ecx, r10d
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r10d
        xor	ebx, r11d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r13d, r9d
        xor	ecx, r10d
        add	r9d, ebx
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r13d
        add	r9d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r10d
        mov	ecx, r14d
        add	r8d, DWORD PTR [rsp+28]
        xor	ecx, r15d
        vpsrlq	xmm8, xmm6, 17
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r13d
        and	ecx, r13d
        ror	edx, 5
        xor	ecx, r15d
        xor	edx, r13d
        add	r8d, ecx
        vpsrld	xmm9, xmm6, 10
        vpxor	xmm8, xmm7, xmm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r9d
        add	r8d, edx
        mov	ecx, r9d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r9d
        xor	eax, r10d
        vpxor	xmm9, xmm8, xmm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r12d, r8d
        xor	ecx, r9d
        add	r8d, eax
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r12d
        add	r8d, ecx
        vpaddd	xmm1, xmm9, xmm4
        ; msg_sched done: 4-7
        ; msg_sched: 8-11
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	xmm5, xmm3, xmm2, 4
        vpalignr	xmm4, xmm1, xmm0, 4
        ; rnd_0: 1 - 2
        mov	eax, r9d
        mov	ecx, r13d
        add	r15d, DWORD PTR [rsp+32]
        xor	ecx, r14d
        xor	edx, r12d
        and	ecx, r12d
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r14d
        xor	edx, r12d
        add	r15d, ecx
        ror	edx, 6
        xor	eax, r8d
        add	r15d, edx
        mov	ecx, r8d
        vpsrld	xmm8, xmm5, 18
        vpslld	xmm9, xmm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r8d
        xor	ebx, r9d
        ror	ecx, 11
        add	r11d, r15d
        xor	ecx, r8d
        add	r15d, ebx
        vpor	xmm6, xmm7, xmm6
        vpor	xmm8, xmm9, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r11d
        add	r15d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r8d
        mov	ecx, r12d
        add	r14d, DWORD PTR [rsp+36]
        xor	ecx, r13d
        vpsrld	xmm9, xmm5, 3
        vpxor	xmm6, xmm8, xmm6
        ; rnd_1: 2 - 3
        xor	edx, r11d
        and	ecx, r11d
        ror	edx, 5
        xor	ecx, r13d
        xor	edx, r11d
        add	r14d, ecx
        vpxor	xmm5, xmm9, xmm6
        vpshufd	xmm6, xmm1, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r15d
        add	r14d, edx
        mov	ecx, r15d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r15d
        xor	eax, r8d
        vpsrld	xmm8, xmm6, 10
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r10d, r14d
        xor	ecx, r15d
        add	r14d, eax
        ror	ecx, 2
        mov	edx, r10d
        add	r14d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm2
        ; rnd_0: 1 - 3
        mov	eax, r15d
        mov	ecx, r11d
        add	r13d, DWORD PTR [rsp+40]
        xor	ecx, r12d
        xor	edx, r10d
        and	ecx, r10d
        ror	edx, 5
        xor	ecx, r12d
        xor	edx, r10d
        add	r13d, ecx
        vpxor	xmm6, xmm7, xmm6
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r14d
        add	r13d, edx
        mov	ecx, r14d
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r14d
        xor	ebx, r15d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r9d, r13d
        xor	ecx, r14d
        add	r13d, ebx
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r9d
        add	r13d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r14d
        mov	ecx, r10d
        add	r12d, DWORD PTR [rsp+44]
        xor	ecx, r11d
        vpsrlq	xmm8, xmm6, 17
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r9d
        and	ecx, r9d
        ror	edx, 5
        xor	ecx, r11d
        xor	edx, r9d
        add	r12d, ecx
        vpsrld	xmm9, xmm6, 10
        vpxor	xmm8, xmm7, xmm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r13d
        add	r12d, edx
        mov	ecx, r13d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r13d
        xor	eax, r14d
        vpxor	xmm9, xmm8, xmm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r8d, r12d
        xor	ecx, r13d
        add	r12d, eax
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r8d
        add	r12d, ecx
        vpaddd	xmm2, xmm9, xmm4
        ; msg_sched done: 8-11
        ; msg_sched: 12-15
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	xmm5, xmm0, xmm3, 4
        vpalignr	xmm4, xmm2, xmm1, 4
        ; rnd_0: 1 - 2
        mov	eax, r13d
        mov	ecx, r9d
        add	r11d, DWORD PTR [rsp+48]
        xor	ecx, r10d
        xor	edx, r8d
        and	ecx, r8d
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r10d
        xor	edx, r8d
        add	r11d, ecx
        ror	edx, 6
        xor	eax, r12d
        add	r11d, edx
        mov	ecx, r12d
        vpsrld	xmm8, xmm5, 18
        vpslld	xmm9, xmm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r12d
        xor	ebx, r13d
        ror	ecx, 11
        add	r15d, r11d
        xor	ecx, r12d
        add	r11d, ebx
        vpor	xmm6, xmm7, xmm6
        vpor	xmm8, xmm9, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r15d
        add	r11d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r12d
        mov	ecx, r8d
        add	r10d, DWORD PTR [rsp+52]
        xor	ecx, r9d
        vpsrld	xmm9, xmm5, 3
        vpxor	xmm6, xmm8, xmm6
        ; rnd_1: 2 - 3
        xor	edx, r15d
        and	ecx, r15d
        ror	edx, 5
        xor	ecx, r9d
        xor	edx, r15d
        add	r10d, ecx
        vpxor	xmm5, xmm9, xmm6
        vpshufd	xmm6, xmm2, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r11d
        add	r10d, edx
        mov	ecx, r11d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r11d
        xor	eax, r12d
        vpsrld	xmm8, xmm6, 10
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r14d, r10d
        xor	ecx, r11d
        add	r10d, eax
        ror	ecx, 2
        mov	edx, r14d
        add	r10d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm3
        ; rnd_0: 1 - 3
        mov	eax, r11d
        mov	ecx, r15d
        add	r9d, DWORD PTR [rsp+56]
        xor	ecx, r8d
        xor	edx, r14d
        and	ecx, r14d
        ror	edx, 5
        xor	ecx, r8d
        xor	edx, r14d
        add	r9d, ecx
        vpxor	xmm6, xmm7, xmm6
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r10d
        add	r9d, edx
        mov	ecx, r10d
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r10d
        xor	ebx, r11d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r13d, r9d
        xor	ecx, r10d
        add	r9d, ebx
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r13d
        add	r9d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r10d
        mov	ecx, r14d
        add	r8d, DWORD PTR [rsp+60]
        xor	ecx, r15d
        vpsrlq	xmm8, xmm6, 17
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r13d
        and	ecx, r13d
        ror	edx, 5
        xor	ecx, r15d
        xor	edx, r13d
        add	r8d, ecx
        vpsrld	xmm9, xmm6, 10
        vpxor	xmm8, xmm7, xmm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r9d
        add	r8d, edx
        mov	ecx, r9d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r9d
        xor	eax, r10d
        vpxor	xmm9, xmm8, xmm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r12d, r8d
        xor	ecx, r9d
        add	r8d, eax
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r12d
        add	r8d, ecx
        vpaddd	xmm3, xmm9, xmm4
        ; msg_sched done: 12-15
        ; set_w_k_xfer_4: 12
        vpaddd	xmm4, xmm0, OWORD PTR [rbp+192]
        vpaddd	xmm5, xmm1, OWORD PTR [rbp+208]
        vmovdqu	OWORD PTR [rsp], xmm4
        vmovdqu	OWORD PTR [rsp+16], xmm5
        vpaddd	xmm6, xmm2, OWORD PTR [rbp+224]
        vpaddd	xmm7, xmm3, OWORD PTR [rbp+240]
        vmovdqu	OWORD PTR [rsp+32], xmm6
        vmovdqu	OWORD PTR [rsp+48], xmm7
        ; rnd_all_4: 0-3
        add	r15d, DWORD PTR [rsp]
        mov	ecx, r13d
        mov	eax, r9d
        xor	ecx, r14d
        ror	edx, 14
        and	ecx, r12d
        xor	edx, r12d
        xor	ecx, r14d
        ror	edx, 5
        add	r15d, ecx
        xor	edx, r12d
        xor	eax, r8d
        ror	edx, 6
        mov	ecx, r8d
        add	r15d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r8d
        xor	ebx, r9d
        ror	ecx, 11
        add	r11d, r15d
        xor	ecx, r8d
        add	r15d, ebx
        ror	ecx, 2
        mov	edx, r11d
        add	r15d, ecx
        add	r14d, DWORD PTR [rsp+4]
        mov	ecx, r12d
        mov	ebx, r8d
        xor	ecx, r13d
        ror	edx, 14
        and	ecx, r11d
        xor	edx, r11d
        xor	ecx, r13d
        ror	edx, 5
        add	r14d, ecx
        xor	edx, r11d
        xor	ebx, r15d
        ror	edx, 6
        mov	ecx, r15d
        add	r14d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r15d
        xor	eax, r8d
        ror	ecx, 11
        add	r10d, r14d
        xor	ecx, r15d
        add	r14d, eax
        ror	ecx, 2
        mov	edx, r10d
        add	r14d, ecx
        add	r13d, DWORD PTR [rsp+8]
        mov	ecx, r11d
        mov	eax, r15d
        xor	ecx, r12d
        ror	edx, 14
        and	ecx, r10d
        xor	edx, r10d
        xor	ecx, r12d
        ror	edx, 5
        add	r13d, ecx
        xor	edx, r10d
        xor	eax, r14d
        ror	edx, 6
        mov	ecx, r14d
        add	r13d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r14d
        xor	ebx, r15d
        ror	ecx, 11
        add	r9d, r13d
        xor	ecx, r14d
        add	r13d, ebx
        ror	ecx, 2
        mov	edx, r9d
        add	r13d, ecx
        add	r12d, DWORD PTR [rsp+12]
        mov	ecx, r10d
        mov	ebx, r14d
        xor	ecx, r11d
        ror	edx, 14
        and	ecx, r9d
        xor	edx, r9d
        xor	ecx, r11d
        ror	edx, 5
        add	r12d, ecx
        xor	edx, r9d
        xor	ebx, r13d
        ror	edx, 6
        mov	ecx, r13d
        add	r12d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r13d
        xor	eax, r14d
        ror	ecx, 11
        add	r8d, r12d
        xor	ecx, r13d
        add	r12d, eax
        ror	ecx, 2
        mov	edx, r8d
        add	r12d, ecx
        ; rnd_all_4: 1-4
        add	r11d, DWORD PTR [rsp+16]
        mov	ecx, r9d
        mov	eax, r13d
        xor	ecx, r10d
        ror	edx, 14
        and	ecx, r8d
        xor	edx, r8d
        xor	ecx, r10d
        ror	edx, 5
        add	r11d, ecx
        xor	edx, r8d
        xor	eax, r12d
        ror	edx, 6
        mov	ecx, r12d
        add	r11d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r12d
        xor	ebx, r13d
        ror	ecx, 11
        add	r15d, r11d
        xor	ecx, r12d
        add	r11d, ebx
        ror	ecx, 2
        mov	edx, r15d
        add	r11d, ecx
        add	r10d, DWORD PTR [rsp+20]
        mov	ecx, r8d
        mov	ebx, r12d
        xor	ecx, r9d
        ror	edx, 14
        and	ecx, r15d
        xor	edx, r15d
        xor	ecx, r9d
        ror	edx, 5
        add	r10d, ecx
        xor	edx, r15d
        xor	ebx, r11d
        ror	edx, 6
        mov	ecx, r11d
        add	r10d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r11d
        xor	eax, r12d
        ror	ecx, 11
        add	r14d, r10d
        xor	ecx, r11d
        add	r10d, eax
        ror	ecx, 2
        mov	edx, r14d
        add	r10d, ecx
        add	r9d, DWORD PTR [rsp+24]
        mov	ecx, r15d
        mov	eax, r11d
        xor	ecx, r8d
        ror	edx, 14
        and	ecx, r14d
        xor	edx, r14d
        xor	ecx, r8d
        ror	edx, 5
        add	r9d, ecx
        xor	edx, r14d
        xor	eax, r10d
        ror	edx, 6
        mov	ecx, r10d
        add	r9d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r10d
        xor	ebx, r11d
        ror	ecx, 11
        add	r13d, r9d
        xor	ecx, r10d
        add	r9d, ebx
        ror	ecx, 2
        mov	edx, r13d
        add	r9d, ecx
        add	r8d, DWORD PTR [rsp+28]
        mov	ecx, r14d
        mov	ebx, r10d
        xor	ecx, r15d
        ror	edx, 14
        and	ecx, r13d
        xor	edx, r13d
        xor	ecx, r15d
        ror	edx, 5
        add	r8d, ecx
        xor	edx, r13d
        xor	ebx, r9d
        ror	edx, 6
        mov	ecx, r9d
        add	r8d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r9d
        xor	eax, r10d
        ror	ecx, 11
        add	r12d, r8d
        xor	ecx, r9d
        add	r8d, eax
        ror	ecx, 2
        mov	edx, r12d
        add	r8d, ecx
        ; rnd_all_4: 2-5
        add	r15d, DWORD PTR [rsp+32]
        mov	ecx, r13d
        mov	eax, r9d
        xor	ecx, r14d
        ror	edx, 14
        and	ecx, r12d
        xor	edx, r12d
        xor	ecx, r14d
        ror	edx, 5
        add	r15d, ecx
        xor	edx, r12d
        xor	eax, r8d
        ror	edx, 6
        mov	ecx, r8d
        add	r15d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r8d
        xor	ebx, r9d
        ror	ecx, 11
        add	r11d, r15d
        xor	ecx, r8d
        add	r15d, ebx
        ror	ecx, 2
        mov	edx, r11d
        add	r15d, ecx
        add	r14d, DWORD PTR [rsp+36]
        mov	ecx, r12d
        mov	ebx, r8d
        xor	ecx, r13d
        ror	edx, 14
        and	ecx, r11d
        xor	edx, r11d
        xor	ecx, r13d
        ror	edx, 5
        add	r14d, ecx
        xor	edx, r11d
        xor	ebx, r15d
        ror	edx, 6
        mov	ecx, r15d
        add	r14d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r15d
        xor	eax, r8d
        ror	ecx, 11
        add	r10d, r14d
        xor	ecx, r15d
        add	r14d, eax
        ror	ecx, 2
        mov	edx, r10d
        add	r14d, ecx
        add	r13d, DWORD PTR [rsp+40]
        mov	ecx, r11d
        mov	eax, r15d
        xor	ecx, r12d
        ror	edx, 14
        and	ecx, r10d
        xor	edx, r10d
        xor	ecx, r12d
        ror	edx, 5
        add	r13d, ecx
        xor	edx, r10d
        xor	eax, r14d
        ror	edx, 6
        mov	ecx, r14d
        add	r13d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r14d
        xor	ebx, r15d
        ror	ecx, 11
        add	r9d, r13d
        xor	ecx, r14d
        add	r13d, ebx
        ror	ecx, 2
        mov	edx, r9d
        add	r13d, ecx
        add	r12d, DWORD PTR [rsp+44]
        mov	ecx, r10d
        mov	ebx, r14d
        xor	ecx, r11d
        ror	edx, 14
        and	ecx, r9d
        xor	edx, r9d
        xor	ecx, r11d
        ror	edx, 5
        add	r12d, ecx
        xor	edx, r9d
        xor	ebx, r13d
        ror	edx, 6
        mov	ecx, r13d
        add	r12d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r13d
        xor	eax, r14d
        ror	ecx, 11
        add	r8d, r12d
        xor	ecx, r13d
        add	r12d, eax
        ror	ecx, 2
        mov	edx, r8d
        add	r12d, ecx
        ; rnd_all_4: 3-6
        add	r11d, DWORD PTR [rsp+48]
        mov	ecx, r9d
        mov	eax, r13d
        xor	ecx, r10d
        ror	edx, 14
        and	ecx, r8d
        xor	edx, r8d
        xor	ecx, r10d
        ror	edx, 5
        add	r11d, ecx
        xor	edx, r8d
        xor	eax, r12d
        ror	edx, 6
        mov	ecx, r12d
        add	r11d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r12d
        xor	ebx, r13d
        ror	ecx, 11
        add	r15d, r11d
        xor	ecx, r12d
        add	r11d, ebx
        ror	ecx, 2
        mov	edx, r15d
        add	r11d, ecx
        add	r10d, DWORD PTR [rsp+52]
        mov	ecx, r8d
        mov	ebx, r12d
        xor	ecx, r9d
        ror	edx, 14
        and	ecx, r15d
        xor	edx, r15d
        xor	ecx, r9d
        ror	edx, 5
        add	r10d, ecx
        xor	edx, r15d
        xor	ebx, r11d
        ror	edx, 6
        mov	ecx, r11d
        add	r10d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r11d
        xor	eax, r12d
        ror	ecx, 11
        add	r14d, r10d
        xor	ecx, r11d
        add	r10d, eax
        ror	ecx, 2
        mov	edx, r14d
        add	r10d, ecx
        add	r9d, DWORD PTR [rsp+56]
        mov	ecx, r15d
        mov	eax, r11d
        xor	ecx, r8d
        ror	edx, 14
        and	ecx, r14d
        xor	edx, r14d
        xor	ecx, r8d
        ror	edx, 5
        add	r9d, ecx
        xor	edx, r14d
        xor	eax, r10d
        ror	edx, 6
        mov	ecx, r10d
        add	r9d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r10d
        xor	ebx, r11d
        ror	ecx, 11
        add	r13d, r9d
        xor	ecx, r10d
        add	r9d, ebx
        ror	ecx, 2
        mov	edx, r13d
        add	r9d, ecx
        add	r8d, DWORD PTR [rsp+60]
        mov	ecx, r14d
        mov	ebx, r10d
        xor	ecx, r15d
        ror	edx, 14
        and	ecx, r13d
        xor	edx, r13d
        xor	ecx, r15d
        ror	edx, 5
        add	r8d, ecx
        xor	edx, r13d
        xor	ebx, r9d
        ror	edx, 6
        mov	ecx, r9d
        add	r8d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r9d
        xor	eax, r10d
        ror	ecx, 11
        add	r12d, r8d
        xor	ecx, r9d
        add	r8d, eax
        ror	ecx, 2
        mov	edx, r12d
        add	r8d, ecx
        add	DWORD PTR [rdi], r8d
        add	DWORD PTR [rdi+4], r9d
        add	DWORD PTR [rdi+8], r10d
        add	DWORD PTR [rdi+12], r11d
        add	DWORD PTR [rdi+16], r12d
        add	DWORD PTR [rdi+20], r13d
        add	DWORD PTR [rdi+24], r14d
        add	DWORD PTR [rdi+28], r15d
        xor	rax, rax
        vmovdqu	xmm6, OWORD PTR [rsp+64]
        vmovdqu	xmm7, OWORD PTR [rsp+80]
        vmovdqu	xmm8, OWORD PTR [rsp+96]
        vmovdqu	xmm9, OWORD PTR [rsp+112]
        vmovdqu	xmm10, OWORD PTR [rsp+128]
        vmovdqu	xmm11, OWORD PTR [rsp+144]
        vmovdqu	xmm12, OWORD PTR [rsp+160]
        vmovdqu	xmm13, OWORD PTR [rsp+176]
        add	rsp, 192
        pop	rsi
        pop	rdi
        pop	rbp
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        pop	rbx
        ret
Transform_Sha256_AVX1 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
Transform_Sha256_AVX1_Len PROC
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
        mov	rbp, r8
        sub	rsp, 196
        vmovdqu	OWORD PTR [rsp+64], xmm6
        vmovdqu	OWORD PTR [rsp+80], xmm7
        vmovdqu	OWORD PTR [rsp+96], xmm8
        vmovdqu	OWORD PTR [rsp+112], xmm9
        vmovdqu	OWORD PTR [rsp+128], xmm10
        vmovdqu	OWORD PTR [rsp+144], xmm11
        vmovdqu	OWORD PTR [rsp+160], xmm12
        vmovdqu	OWORD PTR [rsp+176], xmm13
        mov	DWORD PTR [rsp+64], ebp
        mov	rbp, QWORD PTR [ptr_L_avx1_sha256_k]
        vmovdqa	xmm13, OWORD PTR L_avx1_sha256_flip_mask
        vmovdqa	xmm11, OWORD PTR L_avx1_sha256_shuf_00BA
        vmovdqa	xmm12, OWORD PTR L_avx1_sha256_shuf_DC00
        mov	r8d, DWORD PTR [rdi]
        mov	r9d, DWORD PTR [rdi+4]
        mov	r10d, DWORD PTR [rdi+8]
        mov	r11d, DWORD PTR [rdi+12]
        mov	r12d, DWORD PTR [rdi+16]
        mov	r13d, DWORD PTR [rdi+20]
        mov	r14d, DWORD PTR [rdi+24]
        mov	r15d, DWORD PTR [rdi+28]
        ; Start of loop processing a block
L_sha256_len_avx1_start:
        ; X0, X1, X2, X3 = W[0..15]
        vmovdqu	xmm0, OWORD PTR [rsi]
        vmovdqu	xmm1, OWORD PTR [rsi+16]
        vpshufb	xmm0, xmm0, xmm13
        vpshufb	xmm1, xmm1, xmm13
        vmovdqu	xmm2, OWORD PTR [rsi+32]
        vmovdqu	xmm3, OWORD PTR [rsi+48]
        vpshufb	xmm2, xmm2, xmm13
        vpshufb	xmm3, xmm3, xmm13
        mov	ebx, r9d
        mov	edx, r12d
        xor	ebx, r10d
        ; set_w_k_xfer_4: 0
        vpaddd	xmm4, xmm0, OWORD PTR [rbp]
        vpaddd	xmm5, xmm1, OWORD PTR [rbp+16]
        vmovdqu	OWORD PTR [rsp], xmm4
        vmovdqu	OWORD PTR [rsp+16], xmm5
        vpaddd	xmm6, xmm2, OWORD PTR [rbp+32]
        vpaddd	xmm7, xmm3, OWORD PTR [rbp+48]
        vmovdqu	OWORD PTR [rsp+32], xmm6
        vmovdqu	OWORD PTR [rsp+48], xmm7
        ; msg_sched: 0-3
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	xmm5, xmm1, xmm0, 4
        vpalignr	xmm4, xmm3, xmm2, 4
        ; rnd_0: 1 - 2
        mov	eax, r9d
        mov	ecx, r13d
        add	r15d, DWORD PTR [rsp]
        xor	ecx, r14d
        xor	edx, r12d
        and	ecx, r12d
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r14d
        xor	edx, r12d
        add	r15d, ecx
        ror	edx, 6
        xor	eax, r8d
        add	r15d, edx
        mov	ecx, r8d
        vpsrld	xmm8, xmm5, 18
        vpslld	xmm9, xmm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r8d
        xor	ebx, r9d
        ror	ecx, 11
        add	r11d, r15d
        xor	ecx, r8d
        add	r15d, ebx
        vpor	xmm6, xmm7, xmm6
        vpor	xmm8, xmm9, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r11d
        add	r15d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r8d
        mov	ecx, r12d
        add	r14d, DWORD PTR [rsp+4]
        xor	ecx, r13d
        vpsrld	xmm9, xmm5, 3
        vpxor	xmm6, xmm8, xmm6
        ; rnd_1: 2 - 3
        xor	edx, r11d
        and	ecx, r11d
        ror	edx, 5
        xor	ecx, r13d
        xor	edx, r11d
        add	r14d, ecx
        vpxor	xmm5, xmm9, xmm6
        vpshufd	xmm6, xmm3, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r15d
        add	r14d, edx
        mov	ecx, r15d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r15d
        xor	eax, r8d
        vpsrld	xmm8, xmm6, 10
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r10d, r14d
        xor	ecx, r15d
        add	r14d, eax
        ror	ecx, 2
        mov	edx, r10d
        add	r14d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm0
        ; rnd_0: 1 - 3
        mov	eax, r15d
        mov	ecx, r11d
        add	r13d, DWORD PTR [rsp+8]
        xor	ecx, r12d
        xor	edx, r10d
        and	ecx, r10d
        ror	edx, 5
        xor	ecx, r12d
        xor	edx, r10d
        add	r13d, ecx
        vpxor	xmm6, xmm7, xmm6
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r14d
        add	r13d, edx
        mov	ecx, r14d
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r14d
        xor	ebx, r15d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r9d, r13d
        xor	ecx, r14d
        add	r13d, ebx
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r9d
        add	r13d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r14d
        mov	ecx, r10d
        add	r12d, DWORD PTR [rsp+12]
        xor	ecx, r11d
        vpsrlq	xmm8, xmm6, 17
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r9d
        and	ecx, r9d
        ror	edx, 5
        xor	ecx, r11d
        xor	edx, r9d
        add	r12d, ecx
        vpsrld	xmm9, xmm6, 10
        vpxor	xmm8, xmm7, xmm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r13d
        add	r12d, edx
        mov	ecx, r13d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r13d
        xor	eax, r14d
        vpxor	xmm9, xmm8, xmm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r8d, r12d
        xor	ecx, r13d
        add	r12d, eax
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r8d
        add	r12d, ecx
        vpaddd	xmm0, xmm9, xmm4
        ; msg_sched done: 0-3
        ; msg_sched: 4-7
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	xmm5, xmm2, xmm1, 4
        vpalignr	xmm4, xmm0, xmm3, 4
        ; rnd_0: 1 - 2
        mov	eax, r13d
        mov	ecx, r9d
        add	r11d, DWORD PTR [rsp+16]
        xor	ecx, r10d
        xor	edx, r8d
        and	ecx, r8d
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r10d
        xor	edx, r8d
        add	r11d, ecx
        ror	edx, 6
        xor	eax, r12d
        add	r11d, edx
        mov	ecx, r12d
        vpsrld	xmm8, xmm5, 18
        vpslld	xmm9, xmm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r12d
        xor	ebx, r13d
        ror	ecx, 11
        add	r15d, r11d
        xor	ecx, r12d
        add	r11d, ebx
        vpor	xmm6, xmm7, xmm6
        vpor	xmm8, xmm9, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r15d
        add	r11d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r12d
        mov	ecx, r8d
        add	r10d, DWORD PTR [rsp+20]
        xor	ecx, r9d
        vpsrld	xmm9, xmm5, 3
        vpxor	xmm6, xmm8, xmm6
        ; rnd_1: 2 - 3
        xor	edx, r15d
        and	ecx, r15d
        ror	edx, 5
        xor	ecx, r9d
        xor	edx, r15d
        add	r10d, ecx
        vpxor	xmm5, xmm9, xmm6
        vpshufd	xmm6, xmm0, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r11d
        add	r10d, edx
        mov	ecx, r11d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r11d
        xor	eax, r12d
        vpsrld	xmm8, xmm6, 10
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r14d, r10d
        xor	ecx, r11d
        add	r10d, eax
        ror	ecx, 2
        mov	edx, r14d
        add	r10d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm1
        ; rnd_0: 1 - 3
        mov	eax, r11d
        mov	ecx, r15d
        add	r9d, DWORD PTR [rsp+24]
        xor	ecx, r8d
        xor	edx, r14d
        and	ecx, r14d
        ror	edx, 5
        xor	ecx, r8d
        xor	edx, r14d
        add	r9d, ecx
        vpxor	xmm6, xmm7, xmm6
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r10d
        add	r9d, edx
        mov	ecx, r10d
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r10d
        xor	ebx, r11d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r13d, r9d
        xor	ecx, r10d
        add	r9d, ebx
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r13d
        add	r9d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r10d
        mov	ecx, r14d
        add	r8d, DWORD PTR [rsp+28]
        xor	ecx, r15d
        vpsrlq	xmm8, xmm6, 17
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r13d
        and	ecx, r13d
        ror	edx, 5
        xor	ecx, r15d
        xor	edx, r13d
        add	r8d, ecx
        vpsrld	xmm9, xmm6, 10
        vpxor	xmm8, xmm7, xmm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r9d
        add	r8d, edx
        mov	ecx, r9d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r9d
        xor	eax, r10d
        vpxor	xmm9, xmm8, xmm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r12d, r8d
        xor	ecx, r9d
        add	r8d, eax
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r12d
        add	r8d, ecx
        vpaddd	xmm1, xmm9, xmm4
        ; msg_sched done: 4-7
        ; msg_sched: 8-11
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	xmm5, xmm3, xmm2, 4
        vpalignr	xmm4, xmm1, xmm0, 4
        ; rnd_0: 1 - 2
        mov	eax, r9d
        mov	ecx, r13d
        add	r15d, DWORD PTR [rsp+32]
        xor	ecx, r14d
        xor	edx, r12d
        and	ecx, r12d
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r14d
        xor	edx, r12d
        add	r15d, ecx
        ror	edx, 6
        xor	eax, r8d
        add	r15d, edx
        mov	ecx, r8d
        vpsrld	xmm8, xmm5, 18
        vpslld	xmm9, xmm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r8d
        xor	ebx, r9d
        ror	ecx, 11
        add	r11d, r15d
        xor	ecx, r8d
        add	r15d, ebx
        vpor	xmm6, xmm7, xmm6
        vpor	xmm8, xmm9, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r11d
        add	r15d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r8d
        mov	ecx, r12d
        add	r14d, DWORD PTR [rsp+36]
        xor	ecx, r13d
        vpsrld	xmm9, xmm5, 3
        vpxor	xmm6, xmm8, xmm6
        ; rnd_1: 2 - 3
        xor	edx, r11d
        and	ecx, r11d
        ror	edx, 5
        xor	ecx, r13d
        xor	edx, r11d
        add	r14d, ecx
        vpxor	xmm5, xmm9, xmm6
        vpshufd	xmm6, xmm1, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r15d
        add	r14d, edx
        mov	ecx, r15d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r15d
        xor	eax, r8d
        vpsrld	xmm8, xmm6, 10
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r10d, r14d
        xor	ecx, r15d
        add	r14d, eax
        ror	ecx, 2
        mov	edx, r10d
        add	r14d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm2
        ; rnd_0: 1 - 3
        mov	eax, r15d
        mov	ecx, r11d
        add	r13d, DWORD PTR [rsp+40]
        xor	ecx, r12d
        xor	edx, r10d
        and	ecx, r10d
        ror	edx, 5
        xor	ecx, r12d
        xor	edx, r10d
        add	r13d, ecx
        vpxor	xmm6, xmm7, xmm6
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r14d
        add	r13d, edx
        mov	ecx, r14d
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r14d
        xor	ebx, r15d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r9d, r13d
        xor	ecx, r14d
        add	r13d, ebx
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r9d
        add	r13d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r14d
        mov	ecx, r10d
        add	r12d, DWORD PTR [rsp+44]
        xor	ecx, r11d
        vpsrlq	xmm8, xmm6, 17
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r9d
        and	ecx, r9d
        ror	edx, 5
        xor	ecx, r11d
        xor	edx, r9d
        add	r12d, ecx
        vpsrld	xmm9, xmm6, 10
        vpxor	xmm8, xmm7, xmm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r13d
        add	r12d, edx
        mov	ecx, r13d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r13d
        xor	eax, r14d
        vpxor	xmm9, xmm8, xmm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r8d, r12d
        xor	ecx, r13d
        add	r12d, eax
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r8d
        add	r12d, ecx
        vpaddd	xmm2, xmm9, xmm4
        ; msg_sched done: 8-11
        ; msg_sched: 12-15
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	xmm5, xmm0, xmm3, 4
        vpalignr	xmm4, xmm2, xmm1, 4
        ; rnd_0: 1 - 2
        mov	eax, r13d
        mov	ecx, r9d
        add	r11d, DWORD PTR [rsp+48]
        xor	ecx, r10d
        xor	edx, r8d
        and	ecx, r8d
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r10d
        xor	edx, r8d
        add	r11d, ecx
        ror	edx, 6
        xor	eax, r12d
        add	r11d, edx
        mov	ecx, r12d
        vpsrld	xmm8, xmm5, 18
        vpslld	xmm9, xmm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r12d
        xor	ebx, r13d
        ror	ecx, 11
        add	r15d, r11d
        xor	ecx, r12d
        add	r11d, ebx
        vpor	xmm6, xmm7, xmm6
        vpor	xmm8, xmm9, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r15d
        add	r11d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r12d
        mov	ecx, r8d
        add	r10d, DWORD PTR [rsp+52]
        xor	ecx, r9d
        vpsrld	xmm9, xmm5, 3
        vpxor	xmm6, xmm8, xmm6
        ; rnd_1: 2 - 3
        xor	edx, r15d
        and	ecx, r15d
        ror	edx, 5
        xor	ecx, r9d
        xor	edx, r15d
        add	r10d, ecx
        vpxor	xmm5, xmm9, xmm6
        vpshufd	xmm6, xmm2, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r11d
        add	r10d, edx
        mov	ecx, r11d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r11d
        xor	eax, r12d
        vpsrld	xmm8, xmm6, 10
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r14d, r10d
        xor	ecx, r11d
        add	r10d, eax
        ror	ecx, 2
        mov	edx, r14d
        add	r10d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm3
        ; rnd_0: 1 - 3
        mov	eax, r11d
        mov	ecx, r15d
        add	r9d, DWORD PTR [rsp+56]
        xor	ecx, r8d
        xor	edx, r14d
        and	ecx, r14d
        ror	edx, 5
        xor	ecx, r8d
        xor	edx, r14d
        add	r9d, ecx
        vpxor	xmm6, xmm7, xmm6
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r10d
        add	r9d, edx
        mov	ecx, r10d
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r10d
        xor	ebx, r11d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r13d, r9d
        xor	ecx, r10d
        add	r9d, ebx
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r13d
        add	r9d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r10d
        mov	ecx, r14d
        add	r8d, DWORD PTR [rsp+60]
        xor	ecx, r15d
        vpsrlq	xmm8, xmm6, 17
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r13d
        and	ecx, r13d
        ror	edx, 5
        xor	ecx, r15d
        xor	edx, r13d
        add	r8d, ecx
        vpsrld	xmm9, xmm6, 10
        vpxor	xmm8, xmm7, xmm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r9d
        add	r8d, edx
        mov	ecx, r9d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r9d
        xor	eax, r10d
        vpxor	xmm9, xmm8, xmm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r12d, r8d
        xor	ecx, r9d
        add	r8d, eax
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r12d
        add	r8d, ecx
        vpaddd	xmm3, xmm9, xmm4
        ; msg_sched done: 12-15
        ; set_w_k_xfer_4: 4
        vpaddd	xmm4, xmm0, OWORD PTR [rbp+64]
        vpaddd	xmm5, xmm1, OWORD PTR [rbp+80]
        vmovdqu	OWORD PTR [rsp], xmm4
        vmovdqu	OWORD PTR [rsp+16], xmm5
        vpaddd	xmm6, xmm2, OWORD PTR [rbp+96]
        vpaddd	xmm7, xmm3, OWORD PTR [rbp+112]
        vmovdqu	OWORD PTR [rsp+32], xmm6
        vmovdqu	OWORD PTR [rsp+48], xmm7
        ; msg_sched: 0-3
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	xmm5, xmm1, xmm0, 4
        vpalignr	xmm4, xmm3, xmm2, 4
        ; rnd_0: 1 - 2
        mov	eax, r9d
        mov	ecx, r13d
        add	r15d, DWORD PTR [rsp]
        xor	ecx, r14d
        xor	edx, r12d
        and	ecx, r12d
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r14d
        xor	edx, r12d
        add	r15d, ecx
        ror	edx, 6
        xor	eax, r8d
        add	r15d, edx
        mov	ecx, r8d
        vpsrld	xmm8, xmm5, 18
        vpslld	xmm9, xmm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r8d
        xor	ebx, r9d
        ror	ecx, 11
        add	r11d, r15d
        xor	ecx, r8d
        add	r15d, ebx
        vpor	xmm6, xmm7, xmm6
        vpor	xmm8, xmm9, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r11d
        add	r15d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r8d
        mov	ecx, r12d
        add	r14d, DWORD PTR [rsp+4]
        xor	ecx, r13d
        vpsrld	xmm9, xmm5, 3
        vpxor	xmm6, xmm8, xmm6
        ; rnd_1: 2 - 3
        xor	edx, r11d
        and	ecx, r11d
        ror	edx, 5
        xor	ecx, r13d
        xor	edx, r11d
        add	r14d, ecx
        vpxor	xmm5, xmm9, xmm6
        vpshufd	xmm6, xmm3, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r15d
        add	r14d, edx
        mov	ecx, r15d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r15d
        xor	eax, r8d
        vpsrld	xmm8, xmm6, 10
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r10d, r14d
        xor	ecx, r15d
        add	r14d, eax
        ror	ecx, 2
        mov	edx, r10d
        add	r14d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm0
        ; rnd_0: 1 - 3
        mov	eax, r15d
        mov	ecx, r11d
        add	r13d, DWORD PTR [rsp+8]
        xor	ecx, r12d
        xor	edx, r10d
        and	ecx, r10d
        ror	edx, 5
        xor	ecx, r12d
        xor	edx, r10d
        add	r13d, ecx
        vpxor	xmm6, xmm7, xmm6
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r14d
        add	r13d, edx
        mov	ecx, r14d
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r14d
        xor	ebx, r15d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r9d, r13d
        xor	ecx, r14d
        add	r13d, ebx
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r9d
        add	r13d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r14d
        mov	ecx, r10d
        add	r12d, DWORD PTR [rsp+12]
        xor	ecx, r11d
        vpsrlq	xmm8, xmm6, 17
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r9d
        and	ecx, r9d
        ror	edx, 5
        xor	ecx, r11d
        xor	edx, r9d
        add	r12d, ecx
        vpsrld	xmm9, xmm6, 10
        vpxor	xmm8, xmm7, xmm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r13d
        add	r12d, edx
        mov	ecx, r13d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r13d
        xor	eax, r14d
        vpxor	xmm9, xmm8, xmm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r8d, r12d
        xor	ecx, r13d
        add	r12d, eax
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r8d
        add	r12d, ecx
        vpaddd	xmm0, xmm9, xmm4
        ; msg_sched done: 0-3
        ; msg_sched: 4-7
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	xmm5, xmm2, xmm1, 4
        vpalignr	xmm4, xmm0, xmm3, 4
        ; rnd_0: 1 - 2
        mov	eax, r13d
        mov	ecx, r9d
        add	r11d, DWORD PTR [rsp+16]
        xor	ecx, r10d
        xor	edx, r8d
        and	ecx, r8d
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r10d
        xor	edx, r8d
        add	r11d, ecx
        ror	edx, 6
        xor	eax, r12d
        add	r11d, edx
        mov	ecx, r12d
        vpsrld	xmm8, xmm5, 18
        vpslld	xmm9, xmm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r12d
        xor	ebx, r13d
        ror	ecx, 11
        add	r15d, r11d
        xor	ecx, r12d
        add	r11d, ebx
        vpor	xmm6, xmm7, xmm6
        vpor	xmm8, xmm9, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r15d
        add	r11d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r12d
        mov	ecx, r8d
        add	r10d, DWORD PTR [rsp+20]
        xor	ecx, r9d
        vpsrld	xmm9, xmm5, 3
        vpxor	xmm6, xmm8, xmm6
        ; rnd_1: 2 - 3
        xor	edx, r15d
        and	ecx, r15d
        ror	edx, 5
        xor	ecx, r9d
        xor	edx, r15d
        add	r10d, ecx
        vpxor	xmm5, xmm9, xmm6
        vpshufd	xmm6, xmm0, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r11d
        add	r10d, edx
        mov	ecx, r11d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r11d
        xor	eax, r12d
        vpsrld	xmm8, xmm6, 10
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r14d, r10d
        xor	ecx, r11d
        add	r10d, eax
        ror	ecx, 2
        mov	edx, r14d
        add	r10d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm1
        ; rnd_0: 1 - 3
        mov	eax, r11d
        mov	ecx, r15d
        add	r9d, DWORD PTR [rsp+24]
        xor	ecx, r8d
        xor	edx, r14d
        and	ecx, r14d
        ror	edx, 5
        xor	ecx, r8d
        xor	edx, r14d
        add	r9d, ecx
        vpxor	xmm6, xmm7, xmm6
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r10d
        add	r9d, edx
        mov	ecx, r10d
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r10d
        xor	ebx, r11d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r13d, r9d
        xor	ecx, r10d
        add	r9d, ebx
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r13d
        add	r9d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r10d
        mov	ecx, r14d
        add	r8d, DWORD PTR [rsp+28]
        xor	ecx, r15d
        vpsrlq	xmm8, xmm6, 17
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r13d
        and	ecx, r13d
        ror	edx, 5
        xor	ecx, r15d
        xor	edx, r13d
        add	r8d, ecx
        vpsrld	xmm9, xmm6, 10
        vpxor	xmm8, xmm7, xmm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r9d
        add	r8d, edx
        mov	ecx, r9d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r9d
        xor	eax, r10d
        vpxor	xmm9, xmm8, xmm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r12d, r8d
        xor	ecx, r9d
        add	r8d, eax
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r12d
        add	r8d, ecx
        vpaddd	xmm1, xmm9, xmm4
        ; msg_sched done: 4-7
        ; msg_sched: 8-11
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	xmm5, xmm3, xmm2, 4
        vpalignr	xmm4, xmm1, xmm0, 4
        ; rnd_0: 1 - 2
        mov	eax, r9d
        mov	ecx, r13d
        add	r15d, DWORD PTR [rsp+32]
        xor	ecx, r14d
        xor	edx, r12d
        and	ecx, r12d
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r14d
        xor	edx, r12d
        add	r15d, ecx
        ror	edx, 6
        xor	eax, r8d
        add	r15d, edx
        mov	ecx, r8d
        vpsrld	xmm8, xmm5, 18
        vpslld	xmm9, xmm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r8d
        xor	ebx, r9d
        ror	ecx, 11
        add	r11d, r15d
        xor	ecx, r8d
        add	r15d, ebx
        vpor	xmm6, xmm7, xmm6
        vpor	xmm8, xmm9, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r11d
        add	r15d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r8d
        mov	ecx, r12d
        add	r14d, DWORD PTR [rsp+36]
        xor	ecx, r13d
        vpsrld	xmm9, xmm5, 3
        vpxor	xmm6, xmm8, xmm6
        ; rnd_1: 2 - 3
        xor	edx, r11d
        and	ecx, r11d
        ror	edx, 5
        xor	ecx, r13d
        xor	edx, r11d
        add	r14d, ecx
        vpxor	xmm5, xmm9, xmm6
        vpshufd	xmm6, xmm1, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r15d
        add	r14d, edx
        mov	ecx, r15d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r15d
        xor	eax, r8d
        vpsrld	xmm8, xmm6, 10
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r10d, r14d
        xor	ecx, r15d
        add	r14d, eax
        ror	ecx, 2
        mov	edx, r10d
        add	r14d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm2
        ; rnd_0: 1 - 3
        mov	eax, r15d
        mov	ecx, r11d
        add	r13d, DWORD PTR [rsp+40]
        xor	ecx, r12d
        xor	edx, r10d
        and	ecx, r10d
        ror	edx, 5
        xor	ecx, r12d
        xor	edx, r10d
        add	r13d, ecx
        vpxor	xmm6, xmm7, xmm6
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r14d
        add	r13d, edx
        mov	ecx, r14d
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r14d
        xor	ebx, r15d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r9d, r13d
        xor	ecx, r14d
        add	r13d, ebx
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r9d
        add	r13d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r14d
        mov	ecx, r10d
        add	r12d, DWORD PTR [rsp+44]
        xor	ecx, r11d
        vpsrlq	xmm8, xmm6, 17
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r9d
        and	ecx, r9d
        ror	edx, 5
        xor	ecx, r11d
        xor	edx, r9d
        add	r12d, ecx
        vpsrld	xmm9, xmm6, 10
        vpxor	xmm8, xmm7, xmm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r13d
        add	r12d, edx
        mov	ecx, r13d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r13d
        xor	eax, r14d
        vpxor	xmm9, xmm8, xmm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r8d, r12d
        xor	ecx, r13d
        add	r12d, eax
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r8d
        add	r12d, ecx
        vpaddd	xmm2, xmm9, xmm4
        ; msg_sched done: 8-11
        ; msg_sched: 12-15
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	xmm5, xmm0, xmm3, 4
        vpalignr	xmm4, xmm2, xmm1, 4
        ; rnd_0: 1 - 2
        mov	eax, r13d
        mov	ecx, r9d
        add	r11d, DWORD PTR [rsp+48]
        xor	ecx, r10d
        xor	edx, r8d
        and	ecx, r8d
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r10d
        xor	edx, r8d
        add	r11d, ecx
        ror	edx, 6
        xor	eax, r12d
        add	r11d, edx
        mov	ecx, r12d
        vpsrld	xmm8, xmm5, 18
        vpslld	xmm9, xmm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r12d
        xor	ebx, r13d
        ror	ecx, 11
        add	r15d, r11d
        xor	ecx, r12d
        add	r11d, ebx
        vpor	xmm6, xmm7, xmm6
        vpor	xmm8, xmm9, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r15d
        add	r11d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r12d
        mov	ecx, r8d
        add	r10d, DWORD PTR [rsp+52]
        xor	ecx, r9d
        vpsrld	xmm9, xmm5, 3
        vpxor	xmm6, xmm8, xmm6
        ; rnd_1: 2 - 3
        xor	edx, r15d
        and	ecx, r15d
        ror	edx, 5
        xor	ecx, r9d
        xor	edx, r15d
        add	r10d, ecx
        vpxor	xmm5, xmm9, xmm6
        vpshufd	xmm6, xmm2, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r11d
        add	r10d, edx
        mov	ecx, r11d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r11d
        xor	eax, r12d
        vpsrld	xmm8, xmm6, 10
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r14d, r10d
        xor	ecx, r11d
        add	r10d, eax
        ror	ecx, 2
        mov	edx, r14d
        add	r10d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm3
        ; rnd_0: 1 - 3
        mov	eax, r11d
        mov	ecx, r15d
        add	r9d, DWORD PTR [rsp+56]
        xor	ecx, r8d
        xor	edx, r14d
        and	ecx, r14d
        ror	edx, 5
        xor	ecx, r8d
        xor	edx, r14d
        add	r9d, ecx
        vpxor	xmm6, xmm7, xmm6
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r10d
        add	r9d, edx
        mov	ecx, r10d
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r10d
        xor	ebx, r11d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r13d, r9d
        xor	ecx, r10d
        add	r9d, ebx
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r13d
        add	r9d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r10d
        mov	ecx, r14d
        add	r8d, DWORD PTR [rsp+60]
        xor	ecx, r15d
        vpsrlq	xmm8, xmm6, 17
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r13d
        and	ecx, r13d
        ror	edx, 5
        xor	ecx, r15d
        xor	edx, r13d
        add	r8d, ecx
        vpsrld	xmm9, xmm6, 10
        vpxor	xmm8, xmm7, xmm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r9d
        add	r8d, edx
        mov	ecx, r9d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r9d
        xor	eax, r10d
        vpxor	xmm9, xmm8, xmm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r12d, r8d
        xor	ecx, r9d
        add	r8d, eax
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r12d
        add	r8d, ecx
        vpaddd	xmm3, xmm9, xmm4
        ; msg_sched done: 12-15
        ; set_w_k_xfer_4: 8
        vpaddd	xmm4, xmm0, OWORD PTR [rbp+128]
        vpaddd	xmm5, xmm1, OWORD PTR [rbp+144]
        vmovdqu	OWORD PTR [rsp], xmm4
        vmovdqu	OWORD PTR [rsp+16], xmm5
        vpaddd	xmm6, xmm2, OWORD PTR [rbp+160]
        vpaddd	xmm7, xmm3, OWORD PTR [rbp+176]
        vmovdqu	OWORD PTR [rsp+32], xmm6
        vmovdqu	OWORD PTR [rsp+48], xmm7
        ; msg_sched: 0-3
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	xmm5, xmm1, xmm0, 4
        vpalignr	xmm4, xmm3, xmm2, 4
        ; rnd_0: 1 - 2
        mov	eax, r9d
        mov	ecx, r13d
        add	r15d, DWORD PTR [rsp]
        xor	ecx, r14d
        xor	edx, r12d
        and	ecx, r12d
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r14d
        xor	edx, r12d
        add	r15d, ecx
        ror	edx, 6
        xor	eax, r8d
        add	r15d, edx
        mov	ecx, r8d
        vpsrld	xmm8, xmm5, 18
        vpslld	xmm9, xmm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r8d
        xor	ebx, r9d
        ror	ecx, 11
        add	r11d, r15d
        xor	ecx, r8d
        add	r15d, ebx
        vpor	xmm6, xmm7, xmm6
        vpor	xmm8, xmm9, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r11d
        add	r15d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r8d
        mov	ecx, r12d
        add	r14d, DWORD PTR [rsp+4]
        xor	ecx, r13d
        vpsrld	xmm9, xmm5, 3
        vpxor	xmm6, xmm8, xmm6
        ; rnd_1: 2 - 3
        xor	edx, r11d
        and	ecx, r11d
        ror	edx, 5
        xor	ecx, r13d
        xor	edx, r11d
        add	r14d, ecx
        vpxor	xmm5, xmm9, xmm6
        vpshufd	xmm6, xmm3, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r15d
        add	r14d, edx
        mov	ecx, r15d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r15d
        xor	eax, r8d
        vpsrld	xmm8, xmm6, 10
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r10d, r14d
        xor	ecx, r15d
        add	r14d, eax
        ror	ecx, 2
        mov	edx, r10d
        add	r14d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm0
        ; rnd_0: 1 - 3
        mov	eax, r15d
        mov	ecx, r11d
        add	r13d, DWORD PTR [rsp+8]
        xor	ecx, r12d
        xor	edx, r10d
        and	ecx, r10d
        ror	edx, 5
        xor	ecx, r12d
        xor	edx, r10d
        add	r13d, ecx
        vpxor	xmm6, xmm7, xmm6
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r14d
        add	r13d, edx
        mov	ecx, r14d
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r14d
        xor	ebx, r15d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r9d, r13d
        xor	ecx, r14d
        add	r13d, ebx
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r9d
        add	r13d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r14d
        mov	ecx, r10d
        add	r12d, DWORD PTR [rsp+12]
        xor	ecx, r11d
        vpsrlq	xmm8, xmm6, 17
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r9d
        and	ecx, r9d
        ror	edx, 5
        xor	ecx, r11d
        xor	edx, r9d
        add	r12d, ecx
        vpsrld	xmm9, xmm6, 10
        vpxor	xmm8, xmm7, xmm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r13d
        add	r12d, edx
        mov	ecx, r13d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r13d
        xor	eax, r14d
        vpxor	xmm9, xmm8, xmm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r8d, r12d
        xor	ecx, r13d
        add	r12d, eax
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r8d
        add	r12d, ecx
        vpaddd	xmm0, xmm9, xmm4
        ; msg_sched done: 0-3
        ; msg_sched: 4-7
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	xmm5, xmm2, xmm1, 4
        vpalignr	xmm4, xmm0, xmm3, 4
        ; rnd_0: 1 - 2
        mov	eax, r13d
        mov	ecx, r9d
        add	r11d, DWORD PTR [rsp+16]
        xor	ecx, r10d
        xor	edx, r8d
        and	ecx, r8d
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r10d
        xor	edx, r8d
        add	r11d, ecx
        ror	edx, 6
        xor	eax, r12d
        add	r11d, edx
        mov	ecx, r12d
        vpsrld	xmm8, xmm5, 18
        vpslld	xmm9, xmm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r12d
        xor	ebx, r13d
        ror	ecx, 11
        add	r15d, r11d
        xor	ecx, r12d
        add	r11d, ebx
        vpor	xmm6, xmm7, xmm6
        vpor	xmm8, xmm9, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r15d
        add	r11d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r12d
        mov	ecx, r8d
        add	r10d, DWORD PTR [rsp+20]
        xor	ecx, r9d
        vpsrld	xmm9, xmm5, 3
        vpxor	xmm6, xmm8, xmm6
        ; rnd_1: 2 - 3
        xor	edx, r15d
        and	ecx, r15d
        ror	edx, 5
        xor	ecx, r9d
        xor	edx, r15d
        add	r10d, ecx
        vpxor	xmm5, xmm9, xmm6
        vpshufd	xmm6, xmm0, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r11d
        add	r10d, edx
        mov	ecx, r11d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r11d
        xor	eax, r12d
        vpsrld	xmm8, xmm6, 10
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r14d, r10d
        xor	ecx, r11d
        add	r10d, eax
        ror	ecx, 2
        mov	edx, r14d
        add	r10d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm1
        ; rnd_0: 1 - 3
        mov	eax, r11d
        mov	ecx, r15d
        add	r9d, DWORD PTR [rsp+24]
        xor	ecx, r8d
        xor	edx, r14d
        and	ecx, r14d
        ror	edx, 5
        xor	ecx, r8d
        xor	edx, r14d
        add	r9d, ecx
        vpxor	xmm6, xmm7, xmm6
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r10d
        add	r9d, edx
        mov	ecx, r10d
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r10d
        xor	ebx, r11d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r13d, r9d
        xor	ecx, r10d
        add	r9d, ebx
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r13d
        add	r9d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r10d
        mov	ecx, r14d
        add	r8d, DWORD PTR [rsp+28]
        xor	ecx, r15d
        vpsrlq	xmm8, xmm6, 17
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r13d
        and	ecx, r13d
        ror	edx, 5
        xor	ecx, r15d
        xor	edx, r13d
        add	r8d, ecx
        vpsrld	xmm9, xmm6, 10
        vpxor	xmm8, xmm7, xmm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r9d
        add	r8d, edx
        mov	ecx, r9d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r9d
        xor	eax, r10d
        vpxor	xmm9, xmm8, xmm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r12d, r8d
        xor	ecx, r9d
        add	r8d, eax
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r12d
        add	r8d, ecx
        vpaddd	xmm1, xmm9, xmm4
        ; msg_sched done: 4-7
        ; msg_sched: 8-11
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	xmm5, xmm3, xmm2, 4
        vpalignr	xmm4, xmm1, xmm0, 4
        ; rnd_0: 1 - 2
        mov	eax, r9d
        mov	ecx, r13d
        add	r15d, DWORD PTR [rsp+32]
        xor	ecx, r14d
        xor	edx, r12d
        and	ecx, r12d
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r14d
        xor	edx, r12d
        add	r15d, ecx
        ror	edx, 6
        xor	eax, r8d
        add	r15d, edx
        mov	ecx, r8d
        vpsrld	xmm8, xmm5, 18
        vpslld	xmm9, xmm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r8d
        xor	ebx, r9d
        ror	ecx, 11
        add	r11d, r15d
        xor	ecx, r8d
        add	r15d, ebx
        vpor	xmm6, xmm7, xmm6
        vpor	xmm8, xmm9, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r11d
        add	r15d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r8d
        mov	ecx, r12d
        add	r14d, DWORD PTR [rsp+36]
        xor	ecx, r13d
        vpsrld	xmm9, xmm5, 3
        vpxor	xmm6, xmm8, xmm6
        ; rnd_1: 2 - 3
        xor	edx, r11d
        and	ecx, r11d
        ror	edx, 5
        xor	ecx, r13d
        xor	edx, r11d
        add	r14d, ecx
        vpxor	xmm5, xmm9, xmm6
        vpshufd	xmm6, xmm1, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r15d
        add	r14d, edx
        mov	ecx, r15d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r15d
        xor	eax, r8d
        vpsrld	xmm8, xmm6, 10
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r10d, r14d
        xor	ecx, r15d
        add	r14d, eax
        ror	ecx, 2
        mov	edx, r10d
        add	r14d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm2
        ; rnd_0: 1 - 3
        mov	eax, r15d
        mov	ecx, r11d
        add	r13d, DWORD PTR [rsp+40]
        xor	ecx, r12d
        xor	edx, r10d
        and	ecx, r10d
        ror	edx, 5
        xor	ecx, r12d
        xor	edx, r10d
        add	r13d, ecx
        vpxor	xmm6, xmm7, xmm6
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r14d
        add	r13d, edx
        mov	ecx, r14d
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r14d
        xor	ebx, r15d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r9d, r13d
        xor	ecx, r14d
        add	r13d, ebx
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r9d
        add	r13d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r14d
        mov	ecx, r10d
        add	r12d, DWORD PTR [rsp+44]
        xor	ecx, r11d
        vpsrlq	xmm8, xmm6, 17
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r9d
        and	ecx, r9d
        ror	edx, 5
        xor	ecx, r11d
        xor	edx, r9d
        add	r12d, ecx
        vpsrld	xmm9, xmm6, 10
        vpxor	xmm8, xmm7, xmm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r13d
        add	r12d, edx
        mov	ecx, r13d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r13d
        xor	eax, r14d
        vpxor	xmm9, xmm8, xmm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r8d, r12d
        xor	ecx, r13d
        add	r12d, eax
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r8d
        add	r12d, ecx
        vpaddd	xmm2, xmm9, xmm4
        ; msg_sched done: 8-11
        ; msg_sched: 12-15
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	xmm5, xmm0, xmm3, 4
        vpalignr	xmm4, xmm2, xmm1, 4
        ; rnd_0: 1 - 2
        mov	eax, r13d
        mov	ecx, r9d
        add	r11d, DWORD PTR [rsp+48]
        xor	ecx, r10d
        xor	edx, r8d
        and	ecx, r8d
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r10d
        xor	edx, r8d
        add	r11d, ecx
        ror	edx, 6
        xor	eax, r12d
        add	r11d, edx
        mov	ecx, r12d
        vpsrld	xmm8, xmm5, 18
        vpslld	xmm9, xmm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r12d
        xor	ebx, r13d
        ror	ecx, 11
        add	r15d, r11d
        xor	ecx, r12d
        add	r11d, ebx
        vpor	xmm6, xmm7, xmm6
        vpor	xmm8, xmm9, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r15d
        add	r11d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r12d
        mov	ecx, r8d
        add	r10d, DWORD PTR [rsp+52]
        xor	ecx, r9d
        vpsrld	xmm9, xmm5, 3
        vpxor	xmm6, xmm8, xmm6
        ; rnd_1: 2 - 3
        xor	edx, r15d
        and	ecx, r15d
        ror	edx, 5
        xor	ecx, r9d
        xor	edx, r15d
        add	r10d, ecx
        vpxor	xmm5, xmm9, xmm6
        vpshufd	xmm6, xmm2, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r11d
        add	r10d, edx
        mov	ecx, r11d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r11d
        xor	eax, r12d
        vpsrld	xmm8, xmm6, 10
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r14d, r10d
        xor	ecx, r11d
        add	r10d, eax
        ror	ecx, 2
        mov	edx, r14d
        add	r10d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm3
        ; rnd_0: 1 - 3
        mov	eax, r11d
        mov	ecx, r15d
        add	r9d, DWORD PTR [rsp+56]
        xor	ecx, r8d
        xor	edx, r14d
        and	ecx, r14d
        ror	edx, 5
        xor	ecx, r8d
        xor	edx, r14d
        add	r9d, ecx
        vpxor	xmm6, xmm7, xmm6
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r10d
        add	r9d, edx
        mov	ecx, r10d
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r10d
        xor	ebx, r11d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r13d, r9d
        xor	ecx, r10d
        add	r9d, ebx
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r13d
        add	r9d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r10d
        mov	ecx, r14d
        add	r8d, DWORD PTR [rsp+60]
        xor	ecx, r15d
        vpsrlq	xmm8, xmm6, 17
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r13d
        and	ecx, r13d
        ror	edx, 5
        xor	ecx, r15d
        xor	edx, r13d
        add	r8d, ecx
        vpsrld	xmm9, xmm6, 10
        vpxor	xmm8, xmm7, xmm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r9d
        add	r8d, edx
        mov	ecx, r9d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r9d
        xor	eax, r10d
        vpxor	xmm9, xmm8, xmm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r12d, r8d
        xor	ecx, r9d
        add	r8d, eax
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r12d
        add	r8d, ecx
        vpaddd	xmm3, xmm9, xmm4
        ; msg_sched done: 12-15
        ; set_w_k_xfer_4: 12
        vpaddd	xmm4, xmm0, OWORD PTR [rbp+192]
        vpaddd	xmm5, xmm1, OWORD PTR [rbp+208]
        vmovdqu	OWORD PTR [rsp], xmm4
        vmovdqu	OWORD PTR [rsp+16], xmm5
        vpaddd	xmm6, xmm2, OWORD PTR [rbp+224]
        vpaddd	xmm7, xmm3, OWORD PTR [rbp+240]
        vmovdqu	OWORD PTR [rsp+32], xmm6
        vmovdqu	OWORD PTR [rsp+48], xmm7
        ; rnd_all_4: 0-3
        add	r15d, DWORD PTR [rsp]
        mov	ecx, r13d
        mov	eax, r9d
        xor	ecx, r14d
        ror	edx, 14
        and	ecx, r12d
        xor	edx, r12d
        xor	ecx, r14d
        ror	edx, 5
        add	r15d, ecx
        xor	edx, r12d
        xor	eax, r8d
        ror	edx, 6
        mov	ecx, r8d
        add	r15d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r8d
        xor	ebx, r9d
        ror	ecx, 11
        add	r11d, r15d
        xor	ecx, r8d
        add	r15d, ebx
        ror	ecx, 2
        mov	edx, r11d
        add	r15d, ecx
        add	r14d, DWORD PTR [rsp+4]
        mov	ecx, r12d
        mov	ebx, r8d
        xor	ecx, r13d
        ror	edx, 14
        and	ecx, r11d
        xor	edx, r11d
        xor	ecx, r13d
        ror	edx, 5
        add	r14d, ecx
        xor	edx, r11d
        xor	ebx, r15d
        ror	edx, 6
        mov	ecx, r15d
        add	r14d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r15d
        xor	eax, r8d
        ror	ecx, 11
        add	r10d, r14d
        xor	ecx, r15d
        add	r14d, eax
        ror	ecx, 2
        mov	edx, r10d
        add	r14d, ecx
        add	r13d, DWORD PTR [rsp+8]
        mov	ecx, r11d
        mov	eax, r15d
        xor	ecx, r12d
        ror	edx, 14
        and	ecx, r10d
        xor	edx, r10d
        xor	ecx, r12d
        ror	edx, 5
        add	r13d, ecx
        xor	edx, r10d
        xor	eax, r14d
        ror	edx, 6
        mov	ecx, r14d
        add	r13d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r14d
        xor	ebx, r15d
        ror	ecx, 11
        add	r9d, r13d
        xor	ecx, r14d
        add	r13d, ebx
        ror	ecx, 2
        mov	edx, r9d
        add	r13d, ecx
        add	r12d, DWORD PTR [rsp+12]
        mov	ecx, r10d
        mov	ebx, r14d
        xor	ecx, r11d
        ror	edx, 14
        and	ecx, r9d
        xor	edx, r9d
        xor	ecx, r11d
        ror	edx, 5
        add	r12d, ecx
        xor	edx, r9d
        xor	ebx, r13d
        ror	edx, 6
        mov	ecx, r13d
        add	r12d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r13d
        xor	eax, r14d
        ror	ecx, 11
        add	r8d, r12d
        xor	ecx, r13d
        add	r12d, eax
        ror	ecx, 2
        mov	edx, r8d
        add	r12d, ecx
        ; rnd_all_4: 1-4
        add	r11d, DWORD PTR [rsp+16]
        mov	ecx, r9d
        mov	eax, r13d
        xor	ecx, r10d
        ror	edx, 14
        and	ecx, r8d
        xor	edx, r8d
        xor	ecx, r10d
        ror	edx, 5
        add	r11d, ecx
        xor	edx, r8d
        xor	eax, r12d
        ror	edx, 6
        mov	ecx, r12d
        add	r11d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r12d
        xor	ebx, r13d
        ror	ecx, 11
        add	r15d, r11d
        xor	ecx, r12d
        add	r11d, ebx
        ror	ecx, 2
        mov	edx, r15d
        add	r11d, ecx
        add	r10d, DWORD PTR [rsp+20]
        mov	ecx, r8d
        mov	ebx, r12d
        xor	ecx, r9d
        ror	edx, 14
        and	ecx, r15d
        xor	edx, r15d
        xor	ecx, r9d
        ror	edx, 5
        add	r10d, ecx
        xor	edx, r15d
        xor	ebx, r11d
        ror	edx, 6
        mov	ecx, r11d
        add	r10d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r11d
        xor	eax, r12d
        ror	ecx, 11
        add	r14d, r10d
        xor	ecx, r11d
        add	r10d, eax
        ror	ecx, 2
        mov	edx, r14d
        add	r10d, ecx
        add	r9d, DWORD PTR [rsp+24]
        mov	ecx, r15d
        mov	eax, r11d
        xor	ecx, r8d
        ror	edx, 14
        and	ecx, r14d
        xor	edx, r14d
        xor	ecx, r8d
        ror	edx, 5
        add	r9d, ecx
        xor	edx, r14d
        xor	eax, r10d
        ror	edx, 6
        mov	ecx, r10d
        add	r9d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r10d
        xor	ebx, r11d
        ror	ecx, 11
        add	r13d, r9d
        xor	ecx, r10d
        add	r9d, ebx
        ror	ecx, 2
        mov	edx, r13d
        add	r9d, ecx
        add	r8d, DWORD PTR [rsp+28]
        mov	ecx, r14d
        mov	ebx, r10d
        xor	ecx, r15d
        ror	edx, 14
        and	ecx, r13d
        xor	edx, r13d
        xor	ecx, r15d
        ror	edx, 5
        add	r8d, ecx
        xor	edx, r13d
        xor	ebx, r9d
        ror	edx, 6
        mov	ecx, r9d
        add	r8d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r9d
        xor	eax, r10d
        ror	ecx, 11
        add	r12d, r8d
        xor	ecx, r9d
        add	r8d, eax
        ror	ecx, 2
        mov	edx, r12d
        add	r8d, ecx
        ; rnd_all_4: 2-5
        add	r15d, DWORD PTR [rsp+32]
        mov	ecx, r13d
        mov	eax, r9d
        xor	ecx, r14d
        ror	edx, 14
        and	ecx, r12d
        xor	edx, r12d
        xor	ecx, r14d
        ror	edx, 5
        add	r15d, ecx
        xor	edx, r12d
        xor	eax, r8d
        ror	edx, 6
        mov	ecx, r8d
        add	r15d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r8d
        xor	ebx, r9d
        ror	ecx, 11
        add	r11d, r15d
        xor	ecx, r8d
        add	r15d, ebx
        ror	ecx, 2
        mov	edx, r11d
        add	r15d, ecx
        add	r14d, DWORD PTR [rsp+36]
        mov	ecx, r12d
        mov	ebx, r8d
        xor	ecx, r13d
        ror	edx, 14
        and	ecx, r11d
        xor	edx, r11d
        xor	ecx, r13d
        ror	edx, 5
        add	r14d, ecx
        xor	edx, r11d
        xor	ebx, r15d
        ror	edx, 6
        mov	ecx, r15d
        add	r14d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r15d
        xor	eax, r8d
        ror	ecx, 11
        add	r10d, r14d
        xor	ecx, r15d
        add	r14d, eax
        ror	ecx, 2
        mov	edx, r10d
        add	r14d, ecx
        add	r13d, DWORD PTR [rsp+40]
        mov	ecx, r11d
        mov	eax, r15d
        xor	ecx, r12d
        ror	edx, 14
        and	ecx, r10d
        xor	edx, r10d
        xor	ecx, r12d
        ror	edx, 5
        add	r13d, ecx
        xor	edx, r10d
        xor	eax, r14d
        ror	edx, 6
        mov	ecx, r14d
        add	r13d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r14d
        xor	ebx, r15d
        ror	ecx, 11
        add	r9d, r13d
        xor	ecx, r14d
        add	r13d, ebx
        ror	ecx, 2
        mov	edx, r9d
        add	r13d, ecx
        add	r12d, DWORD PTR [rsp+44]
        mov	ecx, r10d
        mov	ebx, r14d
        xor	ecx, r11d
        ror	edx, 14
        and	ecx, r9d
        xor	edx, r9d
        xor	ecx, r11d
        ror	edx, 5
        add	r12d, ecx
        xor	edx, r9d
        xor	ebx, r13d
        ror	edx, 6
        mov	ecx, r13d
        add	r12d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r13d
        xor	eax, r14d
        ror	ecx, 11
        add	r8d, r12d
        xor	ecx, r13d
        add	r12d, eax
        ror	ecx, 2
        mov	edx, r8d
        add	r12d, ecx
        ; rnd_all_4: 3-6
        add	r11d, DWORD PTR [rsp+48]
        mov	ecx, r9d
        mov	eax, r13d
        xor	ecx, r10d
        ror	edx, 14
        and	ecx, r8d
        xor	edx, r8d
        xor	ecx, r10d
        ror	edx, 5
        add	r11d, ecx
        xor	edx, r8d
        xor	eax, r12d
        ror	edx, 6
        mov	ecx, r12d
        add	r11d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r12d
        xor	ebx, r13d
        ror	ecx, 11
        add	r15d, r11d
        xor	ecx, r12d
        add	r11d, ebx
        ror	ecx, 2
        mov	edx, r15d
        add	r11d, ecx
        add	r10d, DWORD PTR [rsp+52]
        mov	ecx, r8d
        mov	ebx, r12d
        xor	ecx, r9d
        ror	edx, 14
        and	ecx, r15d
        xor	edx, r15d
        xor	ecx, r9d
        ror	edx, 5
        add	r10d, ecx
        xor	edx, r15d
        xor	ebx, r11d
        ror	edx, 6
        mov	ecx, r11d
        add	r10d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r11d
        xor	eax, r12d
        ror	ecx, 11
        add	r14d, r10d
        xor	ecx, r11d
        add	r10d, eax
        ror	ecx, 2
        mov	edx, r14d
        add	r10d, ecx
        add	r9d, DWORD PTR [rsp+56]
        mov	ecx, r15d
        mov	eax, r11d
        xor	ecx, r8d
        ror	edx, 14
        and	ecx, r14d
        xor	edx, r14d
        xor	ecx, r8d
        ror	edx, 5
        add	r9d, ecx
        xor	edx, r14d
        xor	eax, r10d
        ror	edx, 6
        mov	ecx, r10d
        add	r9d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r10d
        xor	ebx, r11d
        ror	ecx, 11
        add	r13d, r9d
        xor	ecx, r10d
        add	r9d, ebx
        ror	ecx, 2
        mov	edx, r13d
        add	r9d, ecx
        add	r8d, DWORD PTR [rsp+60]
        mov	ecx, r14d
        mov	ebx, r10d
        xor	ecx, r15d
        ror	edx, 14
        and	ecx, r13d
        xor	edx, r13d
        xor	ecx, r15d
        ror	edx, 5
        add	r8d, ecx
        xor	edx, r13d
        xor	ebx, r9d
        ror	edx, 6
        mov	ecx, r9d
        add	r8d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r9d
        xor	eax, r10d
        ror	ecx, 11
        add	r12d, r8d
        xor	ecx, r9d
        add	r8d, eax
        ror	ecx, 2
        mov	edx, r12d
        add	r8d, ecx
        add	r8d, DWORD PTR [rdi]
        add	r9d, DWORD PTR [rdi+4]
        add	r10d, DWORD PTR [rdi+8]
        add	r11d, DWORD PTR [rdi+12]
        add	r12d, DWORD PTR [rdi+16]
        add	r13d, DWORD PTR [rdi+20]
        add	r14d, DWORD PTR [rdi+24]
        add	r15d, DWORD PTR [rdi+28]
        add	rsi, 64
        sub	DWORD PTR [rsp+64], 64
        mov	DWORD PTR [rdi], r8d
        mov	DWORD PTR [rdi+4], r9d
        mov	DWORD PTR [rdi+8], r10d
        mov	DWORD PTR [rdi+12], r11d
        mov	DWORD PTR [rdi+16], r12d
        mov	DWORD PTR [rdi+20], r13d
        mov	DWORD PTR [rdi+24], r14d
        mov	DWORD PTR [rdi+28], r15d
        jnz	L_sha256_len_avx1_start
        xor	rax, rax
        vmovdqu	xmm6, OWORD PTR [rsp+64]
        vmovdqu	xmm7, OWORD PTR [rsp+80]
        vmovdqu	xmm8, OWORD PTR [rsp+96]
        vmovdqu	xmm9, OWORD PTR [rsp+112]
        vmovdqu	xmm10, OWORD PTR [rsp+128]
        vmovdqu	xmm11, OWORD PTR [rsp+144]
        vmovdqu	xmm12, OWORD PTR [rsp+160]
        vmovdqu	xmm13, OWORD PTR [rsp+176]
        add	rsp, 196
        pop	rbp
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        pop	rbx
        ret
Transform_Sha256_AVX1_Len ENDP
_TEXT ENDS
_DATA SEGMENT
ALIGN 16
L_avx1_rorx_sha256_k DWORD 428a2f98h, 71374491h, 0b5c0fbcfh, 0e9b5dba5h
        DWORD 3956c25bh, 59f111f1h, 923f82a4h, 0ab1c5ed5h
        DWORD 0d807aa98h, 12835b01h, 243185beh, 550c7dc3h
        DWORD 72be5d74h, 80deb1feh, 9bdc06a7h, 0c19bf174h
        DWORD 0e49b69c1h, 0efbe4786h, 0fc19dc6h, 240ca1cch
        DWORD 2de92c6fh, 4a7484aah, 5cb0a9dch, 76f988dah
        DWORD 983e5152h, 0a831c66dh, 0b00327c8h, 0bf597fc7h
        DWORD 0c6e00bf3h, 0d5a79147h, 06ca6351h, 14292967h
        DWORD 27b70a85h, 2e1b2138h, 4d2c6dfch, 53380d13h
        DWORD 650a7354h, 766a0abbh, 81c2c92eh, 92722c85h
        DWORD 0a2bfe8a1h, 0a81a664bh, 0c24b8b70h, 0c76c51a3h
        DWORD 0d192e819h, 0d6990624h, 0f40e3585h, 106aa070h
        DWORD 19a4c116h, 1e376c08h, 2748774ch, 34b0bcb5h
        DWORD 391c0cb3h, 4ed8aa4ah, 5b9cca4fh, 682e6ff3h
        DWORD 748f82eeh, 78a5636fh, 84c87814h, 8cc70208h
        DWORD 90befffah, 0a4506cebh, 0bef9a3f7h, 0c67178f2h
ptr_L_avx1_rorx_sha256_k QWORD L_avx1_rorx_sha256_k
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_avx1_rorx_sha256_shuf_00BA QWORD 0b0a090803020100h, 0ffffffffffffffffh
ptr_L_avx1_rorx_sha256_shuf_00BA QWORD L_avx1_rorx_sha256_shuf_00BA
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_avx1_rorx_sha256_shuf_DC00 QWORD 0ffffffffffffffffh, 0b0a090803020100h
ptr_L_avx1_rorx_sha256_shuf_DC00 QWORD L_avx1_rorx_sha256_shuf_DC00
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_avx1_rorx_sha256_flip_mask QWORD 0405060700010203h, 0c0d0e0f08090a0bh
ptr_L_avx1_rorx_sha256_flip_mask QWORD L_avx1_rorx_sha256_flip_mask
_DATA ENDS
_TEXT SEGMENT READONLY PARA
Transform_Sha256_AVX1_RORX PROC
        push	rbx
        push	r12
        push	r13
        push	r14
        push	r15
        push	rbp
        push	rdi
        push	rsi
        mov	rdi, rcx
        mov	rsi, rdx
        sub	rsp, 192
        vmovdqu	OWORD PTR [rsp+64], xmm6
        vmovdqu	OWORD PTR [rsp+80], xmm7
        vmovdqu	OWORD PTR [rsp+96], xmm8
        vmovdqu	OWORD PTR [rsp+112], xmm9
        vmovdqu	OWORD PTR [rsp+128], xmm10
        vmovdqu	OWORD PTR [rsp+144], xmm11
        vmovdqu	OWORD PTR [rsp+160], xmm12
        vmovdqu	OWORD PTR [rsp+176], xmm13
        mov	rbp, QWORD PTR [ptr_L_avx1_rorx_sha256_k]
        vmovdqa	xmm13, OWORD PTR L_avx1_rorx_sha256_flip_mask
        vmovdqa	xmm11, OWORD PTR L_avx1_rorx_sha256_shuf_00BA
        vmovdqa	xmm12, OWORD PTR L_avx1_rorx_sha256_shuf_DC00
        ; X0, X1, X2, X3 = W[0..15]
        vmovdqu	xmm0, OWORD PTR [rsi]
        vmovdqu	xmm1, OWORD PTR [rsi+16]
        vpshufb	xmm0, xmm0, xmm13
        vpshufb	xmm1, xmm1, xmm13
        vmovdqu	xmm2, OWORD PTR [rsi+32]
        vmovdqu	xmm3, OWORD PTR [rsi+48]
        vpshufb	xmm2, xmm2, xmm13
        vpshufb	xmm3, xmm3, xmm13
        mov	r8d, DWORD PTR [rdi]
        mov	r9d, DWORD PTR [rdi+4]
        mov	r10d, DWORD PTR [rdi+8]
        mov	r11d, DWORD PTR [rdi+12]
        mov	r12d, DWORD PTR [rdi+16]
        mov	r13d, DWORD PTR [rdi+20]
        mov	r14d, DWORD PTR [rdi+24]
        mov	r15d, DWORD PTR [rdi+28]
        ; set_w_k_xfer_4: 0
        vpaddd	xmm4, xmm0, OWORD PTR [rbp]
        vpaddd	xmm5, xmm1, OWORD PTR [rbp+16]
        vmovdqu	OWORD PTR [rsp], xmm4
        vmovdqu	OWORD PTR [rsp+16], xmm5
        vpaddd	xmm6, xmm2, OWORD PTR [rbp+32]
        vpaddd	xmm7, xmm3, OWORD PTR [rbp+48]
        vmovdqu	OWORD PTR [rsp+32], xmm6
        vmovdqu	OWORD PTR [rsp+48], xmm7
        mov	ebx, r9d
        rorx	edx, r12d, 6
        xor	ebx, r10d
        ; msg_sched: 0-3
        ; rnd_0: 0 - 0
        mov	eax, r13d
        rorx	ecx, r12d, 11
        add	r15d, DWORD PTR [rsp]
        vpalignr	xmm4, xmm3, xmm2, 4
        vpalignr	xmm5, xmm1, xmm0, 4
        ; rnd_0: 1 - 2
        xor	ecx, edx
        xor	eax, r14d
        rorx	edx, r12d, 25
        and	eax, r12d
        xor	edx, ecx
        rorx	ecx, r8d, 13
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        add	r15d, edx
        rorx	edx, r8d, 2
        xor	eax, r14d
        xor	ecx, edx
        rorx	edx, r8d, 22
        add	r15d, eax
        vpsrld	xmm8, xmm5, 3
        vpor	xmm7, xmm7, xmm6
        ; rnd_0: 5 - 7
        xor	edx, ecx
        mov	eax, r9d
        add	r11d, r15d
        xor	eax, r8d
        add	r15d, edx
        and	ebx, eax
        xor	ebx, r9d
        rorx	edx, r11d, 6
        add	r15d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r12d
        rorx	ecx, r11d, 11
        add	r14d, DWORD PTR [rsp+4]
        vpsrld	xmm6, xmm5, 18
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r13d
        rorx	edx, r11d, 25
        vpslld	xmm5, xmm5, 14
        ; rnd_1: 2 - 2
        and	ebx, r11d
        xor	edx, ecx
        rorx	ecx, r15d, 13
        vpxor	xmm7, xmm7, xmm5
        ; rnd_1: 3 - 3
        add	r14d, edx
        rorx	edx, r15d, 2
        xor	ebx, r13d
        vpxor	xmm7, xmm7, xmm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r15d, 22
        add	r14d, ebx
        vpshufd	xmm6, xmm3, 250
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r8d
        add	r10d, r14d
        vpxor	xmm5, xmm7, xmm8
        ; rnd_1: 6 - 6
        xor	ebx, r15d
        add	r14d, edx
        and	eax, ebx
        vpsrld	xmm8, xmm6, 10
        ; rnd_1: 7 - 7
        xor	eax, r8d
        rorx	edx, r10d, 6
        add	r14d, eax
        ; rnd_0: 0 - 0
        mov	eax, r11d
        rorx	ecx, r10d, 11
        add	r13d, DWORD PTR [rsp+8]
        vpsrlq	xmm7, xmm6, 19
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r12d
        rorx	edx, r10d, 25
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm0
        ; rnd_0: 2 - 2
        and	eax, r10d
        xor	edx, ecx
        rorx	ecx, r14d, 13
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 3 - 3
        add	r13d, edx
        rorx	edx, r14d, 2
        xor	eax, r12d
        vpxor	xmm6, xmm6, xmm7
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r14d, 22
        add	r13d, eax
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r15d
        add	r9d, r13d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        xor	eax, r14d
        add	r13d, edx
        and	ebx, eax
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        xor	ebx, r15d
        rorx	edx, r9d, 6
        add	r13d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r10d
        rorx	ecx, r9d, 11
        add	r12d, DWORD PTR [rsp+12]
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r11d
        rorx	edx, r9d, 25
        vpsrld	xmm9, xmm6, 10
        ; rnd_1: 2 - 2
        and	ebx, r9d
        xor	edx, ecx
        rorx	ecx, r13d, 13
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 3 - 3
        add	r12d, edx
        rorx	edx, r13d, 2
        xor	ebx, r11d
        vpsrlq	xmm6, xmm6, 17
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r13d, 22
        add	r12d, ebx
        vpxor	xmm6, xmm6, xmm7
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r14d
        add	r8d, r12d
        vpxor	xmm9, xmm9, xmm6
        ; rnd_1: 6 - 6
        xor	ebx, r13d
        add	r12d, edx
        and	eax, ebx
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        xor	eax, r14d
        rorx	edx, r8d, 6
        add	r12d, eax
        vpaddd	xmm0, xmm9, xmm4
        ; msg_sched done: 0-3
        ; msg_sched: 4-7
        ; rnd_0: 0 - 0
        mov	eax, r9d
        rorx	ecx, r8d, 11
        add	r11d, DWORD PTR [rsp+16]
        vpalignr	xmm4, xmm0, xmm3, 4
        vpalignr	xmm5, xmm2, xmm1, 4
        ; rnd_0: 1 - 2
        xor	ecx, edx
        xor	eax, r10d
        rorx	edx, r8d, 25
        and	eax, r8d
        xor	edx, ecx
        rorx	ecx, r12d, 13
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        add	r11d, edx
        rorx	edx, r12d, 2
        xor	eax, r10d
        xor	ecx, edx
        rorx	edx, r12d, 22
        add	r11d, eax
        vpsrld	xmm8, xmm5, 3
        vpor	xmm7, xmm7, xmm6
        ; rnd_0: 5 - 7
        xor	edx, ecx
        mov	eax, r13d
        add	r15d, r11d
        xor	eax, r12d
        add	r11d, edx
        and	ebx, eax
        xor	ebx, r13d
        rorx	edx, r15d, 6
        add	r11d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r8d
        rorx	ecx, r15d, 11
        add	r10d, DWORD PTR [rsp+20]
        vpsrld	xmm6, xmm5, 18
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r9d
        rorx	edx, r15d, 25
        vpslld	xmm5, xmm5, 14
        ; rnd_1: 2 - 2
        and	ebx, r15d
        xor	edx, ecx
        rorx	ecx, r11d, 13
        vpxor	xmm7, xmm7, xmm5
        ; rnd_1: 3 - 3
        add	r10d, edx
        rorx	edx, r11d, 2
        xor	ebx, r9d
        vpxor	xmm7, xmm7, xmm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r11d, 22
        add	r10d, ebx
        vpshufd	xmm6, xmm0, 250
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r12d
        add	r14d, r10d
        vpxor	xmm5, xmm7, xmm8
        ; rnd_1: 6 - 6
        xor	ebx, r11d
        add	r10d, edx
        and	eax, ebx
        vpsrld	xmm8, xmm6, 10
        ; rnd_1: 7 - 7
        xor	eax, r12d
        rorx	edx, r14d, 6
        add	r10d, eax
        ; rnd_0: 0 - 0
        mov	eax, r15d
        rorx	ecx, r14d, 11
        add	r9d, DWORD PTR [rsp+24]
        vpsrlq	xmm7, xmm6, 19
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r8d
        rorx	edx, r14d, 25
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm1
        ; rnd_0: 2 - 2
        and	eax, r14d
        xor	edx, ecx
        rorx	ecx, r10d, 13
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 3 - 3
        add	r9d, edx
        rorx	edx, r10d, 2
        xor	eax, r8d
        vpxor	xmm6, xmm6, xmm7
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r10d, 22
        add	r9d, eax
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r11d
        add	r13d, r9d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        xor	eax, r10d
        add	r9d, edx
        and	ebx, eax
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        xor	ebx, r11d
        rorx	edx, r13d, 6
        add	r9d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r14d
        rorx	ecx, r13d, 11
        add	r8d, DWORD PTR [rsp+28]
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r15d
        rorx	edx, r13d, 25
        vpsrld	xmm9, xmm6, 10
        ; rnd_1: 2 - 2
        and	ebx, r13d
        xor	edx, ecx
        rorx	ecx, r9d, 13
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 3 - 3
        add	r8d, edx
        rorx	edx, r9d, 2
        xor	ebx, r15d
        vpsrlq	xmm6, xmm6, 17
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r9d, 22
        add	r8d, ebx
        vpxor	xmm6, xmm6, xmm7
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r10d
        add	r12d, r8d
        vpxor	xmm9, xmm9, xmm6
        ; rnd_1: 6 - 6
        xor	ebx, r9d
        add	r8d, edx
        and	eax, ebx
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        xor	eax, r10d
        rorx	edx, r12d, 6
        add	r8d, eax
        vpaddd	xmm1, xmm9, xmm4
        ; msg_sched done: 4-7
        ; msg_sched: 8-11
        ; rnd_0: 0 - 0
        mov	eax, r13d
        rorx	ecx, r12d, 11
        add	r15d, DWORD PTR [rsp+32]
        vpalignr	xmm4, xmm1, xmm0, 4
        vpalignr	xmm5, xmm3, xmm2, 4
        ; rnd_0: 1 - 2
        xor	ecx, edx
        xor	eax, r14d
        rorx	edx, r12d, 25
        and	eax, r12d
        xor	edx, ecx
        rorx	ecx, r8d, 13
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        add	r15d, edx
        rorx	edx, r8d, 2
        xor	eax, r14d
        xor	ecx, edx
        rorx	edx, r8d, 22
        add	r15d, eax
        vpsrld	xmm8, xmm5, 3
        vpor	xmm7, xmm7, xmm6
        ; rnd_0: 5 - 7
        xor	edx, ecx
        mov	eax, r9d
        add	r11d, r15d
        xor	eax, r8d
        add	r15d, edx
        and	ebx, eax
        xor	ebx, r9d
        rorx	edx, r11d, 6
        add	r15d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r12d
        rorx	ecx, r11d, 11
        add	r14d, DWORD PTR [rsp+36]
        vpsrld	xmm6, xmm5, 18
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r13d
        rorx	edx, r11d, 25
        vpslld	xmm5, xmm5, 14
        ; rnd_1: 2 - 2
        and	ebx, r11d
        xor	edx, ecx
        rorx	ecx, r15d, 13
        vpxor	xmm7, xmm7, xmm5
        ; rnd_1: 3 - 3
        add	r14d, edx
        rorx	edx, r15d, 2
        xor	ebx, r13d
        vpxor	xmm7, xmm7, xmm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r15d, 22
        add	r14d, ebx
        vpshufd	xmm6, xmm1, 250
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r8d
        add	r10d, r14d
        vpxor	xmm5, xmm7, xmm8
        ; rnd_1: 6 - 6
        xor	ebx, r15d
        add	r14d, edx
        and	eax, ebx
        vpsrld	xmm8, xmm6, 10
        ; rnd_1: 7 - 7
        xor	eax, r8d
        rorx	edx, r10d, 6
        add	r14d, eax
        ; rnd_0: 0 - 0
        mov	eax, r11d
        rorx	ecx, r10d, 11
        add	r13d, DWORD PTR [rsp+40]
        vpsrlq	xmm7, xmm6, 19
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r12d
        rorx	edx, r10d, 25
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm2
        ; rnd_0: 2 - 2
        and	eax, r10d
        xor	edx, ecx
        rorx	ecx, r14d, 13
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 3 - 3
        add	r13d, edx
        rorx	edx, r14d, 2
        xor	eax, r12d
        vpxor	xmm6, xmm6, xmm7
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r14d, 22
        add	r13d, eax
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r15d
        add	r9d, r13d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        xor	eax, r14d
        add	r13d, edx
        and	ebx, eax
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        xor	ebx, r15d
        rorx	edx, r9d, 6
        add	r13d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r10d
        rorx	ecx, r9d, 11
        add	r12d, DWORD PTR [rsp+44]
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r11d
        rorx	edx, r9d, 25
        vpsrld	xmm9, xmm6, 10
        ; rnd_1: 2 - 2
        and	ebx, r9d
        xor	edx, ecx
        rorx	ecx, r13d, 13
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 3 - 3
        add	r12d, edx
        rorx	edx, r13d, 2
        xor	ebx, r11d
        vpsrlq	xmm6, xmm6, 17
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r13d, 22
        add	r12d, ebx
        vpxor	xmm6, xmm6, xmm7
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r14d
        add	r8d, r12d
        vpxor	xmm9, xmm9, xmm6
        ; rnd_1: 6 - 6
        xor	ebx, r13d
        add	r12d, edx
        and	eax, ebx
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        xor	eax, r14d
        rorx	edx, r8d, 6
        add	r12d, eax
        vpaddd	xmm2, xmm9, xmm4
        ; msg_sched done: 8-11
        ; msg_sched: 12-15
        ; rnd_0: 0 - 0
        mov	eax, r9d
        rorx	ecx, r8d, 11
        add	r11d, DWORD PTR [rsp+48]
        vpalignr	xmm4, xmm2, xmm1, 4
        vpalignr	xmm5, xmm0, xmm3, 4
        ; rnd_0: 1 - 2
        xor	ecx, edx
        xor	eax, r10d
        rorx	edx, r8d, 25
        and	eax, r8d
        xor	edx, ecx
        rorx	ecx, r12d, 13
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        add	r11d, edx
        rorx	edx, r12d, 2
        xor	eax, r10d
        xor	ecx, edx
        rorx	edx, r12d, 22
        add	r11d, eax
        vpsrld	xmm8, xmm5, 3
        vpor	xmm7, xmm7, xmm6
        ; rnd_0: 5 - 7
        xor	edx, ecx
        mov	eax, r13d
        add	r15d, r11d
        xor	eax, r12d
        add	r11d, edx
        and	ebx, eax
        xor	ebx, r13d
        rorx	edx, r15d, 6
        add	r11d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r8d
        rorx	ecx, r15d, 11
        add	r10d, DWORD PTR [rsp+52]
        vpsrld	xmm6, xmm5, 18
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r9d
        rorx	edx, r15d, 25
        vpslld	xmm5, xmm5, 14
        ; rnd_1: 2 - 2
        and	ebx, r15d
        xor	edx, ecx
        rorx	ecx, r11d, 13
        vpxor	xmm7, xmm7, xmm5
        ; rnd_1: 3 - 3
        add	r10d, edx
        rorx	edx, r11d, 2
        xor	ebx, r9d
        vpxor	xmm7, xmm7, xmm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r11d, 22
        add	r10d, ebx
        vpshufd	xmm6, xmm2, 250
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r12d
        add	r14d, r10d
        vpxor	xmm5, xmm7, xmm8
        ; rnd_1: 6 - 6
        xor	ebx, r11d
        add	r10d, edx
        and	eax, ebx
        vpsrld	xmm8, xmm6, 10
        ; rnd_1: 7 - 7
        xor	eax, r12d
        rorx	edx, r14d, 6
        add	r10d, eax
        ; rnd_0: 0 - 0
        mov	eax, r15d
        rorx	ecx, r14d, 11
        add	r9d, DWORD PTR [rsp+56]
        vpsrlq	xmm7, xmm6, 19
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r8d
        rorx	edx, r14d, 25
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm3
        ; rnd_0: 2 - 2
        and	eax, r14d
        xor	edx, ecx
        rorx	ecx, r10d, 13
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 3 - 3
        add	r9d, edx
        rorx	edx, r10d, 2
        xor	eax, r8d
        vpxor	xmm6, xmm6, xmm7
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r10d, 22
        add	r9d, eax
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r11d
        add	r13d, r9d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        xor	eax, r10d
        add	r9d, edx
        and	ebx, eax
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        xor	ebx, r11d
        rorx	edx, r13d, 6
        add	r9d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r14d
        rorx	ecx, r13d, 11
        add	r8d, DWORD PTR [rsp+60]
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r15d
        rorx	edx, r13d, 25
        vpsrld	xmm9, xmm6, 10
        ; rnd_1: 2 - 2
        and	ebx, r13d
        xor	edx, ecx
        rorx	ecx, r9d, 13
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 3 - 3
        add	r8d, edx
        rorx	edx, r9d, 2
        xor	ebx, r15d
        vpsrlq	xmm6, xmm6, 17
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r9d, 22
        add	r8d, ebx
        vpxor	xmm6, xmm6, xmm7
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r10d
        add	r12d, r8d
        vpxor	xmm9, xmm9, xmm6
        ; rnd_1: 6 - 6
        xor	ebx, r9d
        add	r8d, edx
        and	eax, ebx
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        xor	eax, r10d
        rorx	edx, r12d, 6
        add	r8d, eax
        vpaddd	xmm3, xmm9, xmm4
        ; msg_sched done: 12-15
        ; set_w_k_xfer_4: 4
        vpaddd	xmm4, xmm0, OWORD PTR [rbp+64]
        vpaddd	xmm5, xmm1, OWORD PTR [rbp+80]
        vmovdqu	OWORD PTR [rsp], xmm4
        vmovdqu	OWORD PTR [rsp+16], xmm5
        vpaddd	xmm6, xmm2, OWORD PTR [rbp+96]
        vpaddd	xmm7, xmm3, OWORD PTR [rbp+112]
        vmovdqu	OWORD PTR [rsp+32], xmm6
        vmovdqu	OWORD PTR [rsp+48], xmm7
        ; msg_sched: 0-3
        ; rnd_0: 0 - 0
        mov	eax, r13d
        rorx	ecx, r12d, 11
        add	r15d, DWORD PTR [rsp]
        vpalignr	xmm4, xmm3, xmm2, 4
        vpalignr	xmm5, xmm1, xmm0, 4
        ; rnd_0: 1 - 2
        xor	ecx, edx
        xor	eax, r14d
        rorx	edx, r12d, 25
        and	eax, r12d
        xor	edx, ecx
        rorx	ecx, r8d, 13
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        add	r15d, edx
        rorx	edx, r8d, 2
        xor	eax, r14d
        xor	ecx, edx
        rorx	edx, r8d, 22
        add	r15d, eax
        vpsrld	xmm8, xmm5, 3
        vpor	xmm7, xmm7, xmm6
        ; rnd_0: 5 - 7
        xor	edx, ecx
        mov	eax, r9d
        add	r11d, r15d
        xor	eax, r8d
        add	r15d, edx
        and	ebx, eax
        xor	ebx, r9d
        rorx	edx, r11d, 6
        add	r15d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r12d
        rorx	ecx, r11d, 11
        add	r14d, DWORD PTR [rsp+4]
        vpsrld	xmm6, xmm5, 18
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r13d
        rorx	edx, r11d, 25
        vpslld	xmm5, xmm5, 14
        ; rnd_1: 2 - 2
        and	ebx, r11d
        xor	edx, ecx
        rorx	ecx, r15d, 13
        vpxor	xmm7, xmm7, xmm5
        ; rnd_1: 3 - 3
        add	r14d, edx
        rorx	edx, r15d, 2
        xor	ebx, r13d
        vpxor	xmm7, xmm7, xmm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r15d, 22
        add	r14d, ebx
        vpshufd	xmm6, xmm3, 250
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r8d
        add	r10d, r14d
        vpxor	xmm5, xmm7, xmm8
        ; rnd_1: 6 - 6
        xor	ebx, r15d
        add	r14d, edx
        and	eax, ebx
        vpsrld	xmm8, xmm6, 10
        ; rnd_1: 7 - 7
        xor	eax, r8d
        rorx	edx, r10d, 6
        add	r14d, eax
        ; rnd_0: 0 - 0
        mov	eax, r11d
        rorx	ecx, r10d, 11
        add	r13d, DWORD PTR [rsp+8]
        vpsrlq	xmm7, xmm6, 19
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r12d
        rorx	edx, r10d, 25
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm0
        ; rnd_0: 2 - 2
        and	eax, r10d
        xor	edx, ecx
        rorx	ecx, r14d, 13
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 3 - 3
        add	r13d, edx
        rorx	edx, r14d, 2
        xor	eax, r12d
        vpxor	xmm6, xmm6, xmm7
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r14d, 22
        add	r13d, eax
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r15d
        add	r9d, r13d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        xor	eax, r14d
        add	r13d, edx
        and	ebx, eax
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        xor	ebx, r15d
        rorx	edx, r9d, 6
        add	r13d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r10d
        rorx	ecx, r9d, 11
        add	r12d, DWORD PTR [rsp+12]
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r11d
        rorx	edx, r9d, 25
        vpsrld	xmm9, xmm6, 10
        ; rnd_1: 2 - 2
        and	ebx, r9d
        xor	edx, ecx
        rorx	ecx, r13d, 13
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 3 - 3
        add	r12d, edx
        rorx	edx, r13d, 2
        xor	ebx, r11d
        vpsrlq	xmm6, xmm6, 17
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r13d, 22
        add	r12d, ebx
        vpxor	xmm6, xmm6, xmm7
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r14d
        add	r8d, r12d
        vpxor	xmm9, xmm9, xmm6
        ; rnd_1: 6 - 6
        xor	ebx, r13d
        add	r12d, edx
        and	eax, ebx
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        xor	eax, r14d
        rorx	edx, r8d, 6
        add	r12d, eax
        vpaddd	xmm0, xmm9, xmm4
        ; msg_sched done: 0-3
        ; msg_sched: 4-7
        ; rnd_0: 0 - 0
        mov	eax, r9d
        rorx	ecx, r8d, 11
        add	r11d, DWORD PTR [rsp+16]
        vpalignr	xmm4, xmm0, xmm3, 4
        vpalignr	xmm5, xmm2, xmm1, 4
        ; rnd_0: 1 - 2
        xor	ecx, edx
        xor	eax, r10d
        rorx	edx, r8d, 25
        and	eax, r8d
        xor	edx, ecx
        rorx	ecx, r12d, 13
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        add	r11d, edx
        rorx	edx, r12d, 2
        xor	eax, r10d
        xor	ecx, edx
        rorx	edx, r12d, 22
        add	r11d, eax
        vpsrld	xmm8, xmm5, 3
        vpor	xmm7, xmm7, xmm6
        ; rnd_0: 5 - 7
        xor	edx, ecx
        mov	eax, r13d
        add	r15d, r11d
        xor	eax, r12d
        add	r11d, edx
        and	ebx, eax
        xor	ebx, r13d
        rorx	edx, r15d, 6
        add	r11d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r8d
        rorx	ecx, r15d, 11
        add	r10d, DWORD PTR [rsp+20]
        vpsrld	xmm6, xmm5, 18
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r9d
        rorx	edx, r15d, 25
        vpslld	xmm5, xmm5, 14
        ; rnd_1: 2 - 2
        and	ebx, r15d
        xor	edx, ecx
        rorx	ecx, r11d, 13
        vpxor	xmm7, xmm7, xmm5
        ; rnd_1: 3 - 3
        add	r10d, edx
        rorx	edx, r11d, 2
        xor	ebx, r9d
        vpxor	xmm7, xmm7, xmm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r11d, 22
        add	r10d, ebx
        vpshufd	xmm6, xmm0, 250
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r12d
        add	r14d, r10d
        vpxor	xmm5, xmm7, xmm8
        ; rnd_1: 6 - 6
        xor	ebx, r11d
        add	r10d, edx
        and	eax, ebx
        vpsrld	xmm8, xmm6, 10
        ; rnd_1: 7 - 7
        xor	eax, r12d
        rorx	edx, r14d, 6
        add	r10d, eax
        ; rnd_0: 0 - 0
        mov	eax, r15d
        rorx	ecx, r14d, 11
        add	r9d, DWORD PTR [rsp+24]
        vpsrlq	xmm7, xmm6, 19
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r8d
        rorx	edx, r14d, 25
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm1
        ; rnd_0: 2 - 2
        and	eax, r14d
        xor	edx, ecx
        rorx	ecx, r10d, 13
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 3 - 3
        add	r9d, edx
        rorx	edx, r10d, 2
        xor	eax, r8d
        vpxor	xmm6, xmm6, xmm7
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r10d, 22
        add	r9d, eax
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r11d
        add	r13d, r9d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        xor	eax, r10d
        add	r9d, edx
        and	ebx, eax
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        xor	ebx, r11d
        rorx	edx, r13d, 6
        add	r9d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r14d
        rorx	ecx, r13d, 11
        add	r8d, DWORD PTR [rsp+28]
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r15d
        rorx	edx, r13d, 25
        vpsrld	xmm9, xmm6, 10
        ; rnd_1: 2 - 2
        and	ebx, r13d
        xor	edx, ecx
        rorx	ecx, r9d, 13
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 3 - 3
        add	r8d, edx
        rorx	edx, r9d, 2
        xor	ebx, r15d
        vpsrlq	xmm6, xmm6, 17
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r9d, 22
        add	r8d, ebx
        vpxor	xmm6, xmm6, xmm7
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r10d
        add	r12d, r8d
        vpxor	xmm9, xmm9, xmm6
        ; rnd_1: 6 - 6
        xor	ebx, r9d
        add	r8d, edx
        and	eax, ebx
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        xor	eax, r10d
        rorx	edx, r12d, 6
        add	r8d, eax
        vpaddd	xmm1, xmm9, xmm4
        ; msg_sched done: 4-7
        ; msg_sched: 8-11
        ; rnd_0: 0 - 0
        mov	eax, r13d
        rorx	ecx, r12d, 11
        add	r15d, DWORD PTR [rsp+32]
        vpalignr	xmm4, xmm1, xmm0, 4
        vpalignr	xmm5, xmm3, xmm2, 4
        ; rnd_0: 1 - 2
        xor	ecx, edx
        xor	eax, r14d
        rorx	edx, r12d, 25
        and	eax, r12d
        xor	edx, ecx
        rorx	ecx, r8d, 13
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        add	r15d, edx
        rorx	edx, r8d, 2
        xor	eax, r14d
        xor	ecx, edx
        rorx	edx, r8d, 22
        add	r15d, eax
        vpsrld	xmm8, xmm5, 3
        vpor	xmm7, xmm7, xmm6
        ; rnd_0: 5 - 7
        xor	edx, ecx
        mov	eax, r9d
        add	r11d, r15d
        xor	eax, r8d
        add	r15d, edx
        and	ebx, eax
        xor	ebx, r9d
        rorx	edx, r11d, 6
        add	r15d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r12d
        rorx	ecx, r11d, 11
        add	r14d, DWORD PTR [rsp+36]
        vpsrld	xmm6, xmm5, 18
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r13d
        rorx	edx, r11d, 25
        vpslld	xmm5, xmm5, 14
        ; rnd_1: 2 - 2
        and	ebx, r11d
        xor	edx, ecx
        rorx	ecx, r15d, 13
        vpxor	xmm7, xmm7, xmm5
        ; rnd_1: 3 - 3
        add	r14d, edx
        rorx	edx, r15d, 2
        xor	ebx, r13d
        vpxor	xmm7, xmm7, xmm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r15d, 22
        add	r14d, ebx
        vpshufd	xmm6, xmm1, 250
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r8d
        add	r10d, r14d
        vpxor	xmm5, xmm7, xmm8
        ; rnd_1: 6 - 6
        xor	ebx, r15d
        add	r14d, edx
        and	eax, ebx
        vpsrld	xmm8, xmm6, 10
        ; rnd_1: 7 - 7
        xor	eax, r8d
        rorx	edx, r10d, 6
        add	r14d, eax
        ; rnd_0: 0 - 0
        mov	eax, r11d
        rorx	ecx, r10d, 11
        add	r13d, DWORD PTR [rsp+40]
        vpsrlq	xmm7, xmm6, 19
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r12d
        rorx	edx, r10d, 25
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm2
        ; rnd_0: 2 - 2
        and	eax, r10d
        xor	edx, ecx
        rorx	ecx, r14d, 13
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 3 - 3
        add	r13d, edx
        rorx	edx, r14d, 2
        xor	eax, r12d
        vpxor	xmm6, xmm6, xmm7
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r14d, 22
        add	r13d, eax
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r15d
        add	r9d, r13d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        xor	eax, r14d
        add	r13d, edx
        and	ebx, eax
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        xor	ebx, r15d
        rorx	edx, r9d, 6
        add	r13d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r10d
        rorx	ecx, r9d, 11
        add	r12d, DWORD PTR [rsp+44]
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r11d
        rorx	edx, r9d, 25
        vpsrld	xmm9, xmm6, 10
        ; rnd_1: 2 - 2
        and	ebx, r9d
        xor	edx, ecx
        rorx	ecx, r13d, 13
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 3 - 3
        add	r12d, edx
        rorx	edx, r13d, 2
        xor	ebx, r11d
        vpsrlq	xmm6, xmm6, 17
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r13d, 22
        add	r12d, ebx
        vpxor	xmm6, xmm6, xmm7
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r14d
        add	r8d, r12d
        vpxor	xmm9, xmm9, xmm6
        ; rnd_1: 6 - 6
        xor	ebx, r13d
        add	r12d, edx
        and	eax, ebx
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        xor	eax, r14d
        rorx	edx, r8d, 6
        add	r12d, eax
        vpaddd	xmm2, xmm9, xmm4
        ; msg_sched done: 8-11
        ; msg_sched: 12-15
        ; rnd_0: 0 - 0
        mov	eax, r9d
        rorx	ecx, r8d, 11
        add	r11d, DWORD PTR [rsp+48]
        vpalignr	xmm4, xmm2, xmm1, 4
        vpalignr	xmm5, xmm0, xmm3, 4
        ; rnd_0: 1 - 2
        xor	ecx, edx
        xor	eax, r10d
        rorx	edx, r8d, 25
        and	eax, r8d
        xor	edx, ecx
        rorx	ecx, r12d, 13
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        add	r11d, edx
        rorx	edx, r12d, 2
        xor	eax, r10d
        xor	ecx, edx
        rorx	edx, r12d, 22
        add	r11d, eax
        vpsrld	xmm8, xmm5, 3
        vpor	xmm7, xmm7, xmm6
        ; rnd_0: 5 - 7
        xor	edx, ecx
        mov	eax, r13d
        add	r15d, r11d
        xor	eax, r12d
        add	r11d, edx
        and	ebx, eax
        xor	ebx, r13d
        rorx	edx, r15d, 6
        add	r11d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r8d
        rorx	ecx, r15d, 11
        add	r10d, DWORD PTR [rsp+52]
        vpsrld	xmm6, xmm5, 18
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r9d
        rorx	edx, r15d, 25
        vpslld	xmm5, xmm5, 14
        ; rnd_1: 2 - 2
        and	ebx, r15d
        xor	edx, ecx
        rorx	ecx, r11d, 13
        vpxor	xmm7, xmm7, xmm5
        ; rnd_1: 3 - 3
        add	r10d, edx
        rorx	edx, r11d, 2
        xor	ebx, r9d
        vpxor	xmm7, xmm7, xmm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r11d, 22
        add	r10d, ebx
        vpshufd	xmm6, xmm2, 250
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r12d
        add	r14d, r10d
        vpxor	xmm5, xmm7, xmm8
        ; rnd_1: 6 - 6
        xor	ebx, r11d
        add	r10d, edx
        and	eax, ebx
        vpsrld	xmm8, xmm6, 10
        ; rnd_1: 7 - 7
        xor	eax, r12d
        rorx	edx, r14d, 6
        add	r10d, eax
        ; rnd_0: 0 - 0
        mov	eax, r15d
        rorx	ecx, r14d, 11
        add	r9d, DWORD PTR [rsp+56]
        vpsrlq	xmm7, xmm6, 19
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r8d
        rorx	edx, r14d, 25
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm3
        ; rnd_0: 2 - 2
        and	eax, r14d
        xor	edx, ecx
        rorx	ecx, r10d, 13
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 3 - 3
        add	r9d, edx
        rorx	edx, r10d, 2
        xor	eax, r8d
        vpxor	xmm6, xmm6, xmm7
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r10d, 22
        add	r9d, eax
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r11d
        add	r13d, r9d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        xor	eax, r10d
        add	r9d, edx
        and	ebx, eax
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        xor	ebx, r11d
        rorx	edx, r13d, 6
        add	r9d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r14d
        rorx	ecx, r13d, 11
        add	r8d, DWORD PTR [rsp+60]
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r15d
        rorx	edx, r13d, 25
        vpsrld	xmm9, xmm6, 10
        ; rnd_1: 2 - 2
        and	ebx, r13d
        xor	edx, ecx
        rorx	ecx, r9d, 13
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 3 - 3
        add	r8d, edx
        rorx	edx, r9d, 2
        xor	ebx, r15d
        vpsrlq	xmm6, xmm6, 17
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r9d, 22
        add	r8d, ebx
        vpxor	xmm6, xmm6, xmm7
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r10d
        add	r12d, r8d
        vpxor	xmm9, xmm9, xmm6
        ; rnd_1: 6 - 6
        xor	ebx, r9d
        add	r8d, edx
        and	eax, ebx
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        xor	eax, r10d
        rorx	edx, r12d, 6
        add	r8d, eax
        vpaddd	xmm3, xmm9, xmm4
        ; msg_sched done: 12-15
        ; set_w_k_xfer_4: 8
        vpaddd	xmm4, xmm0, OWORD PTR [rbp+128]
        vpaddd	xmm5, xmm1, OWORD PTR [rbp+144]
        vmovdqu	OWORD PTR [rsp], xmm4
        vmovdqu	OWORD PTR [rsp+16], xmm5
        vpaddd	xmm6, xmm2, OWORD PTR [rbp+160]
        vpaddd	xmm7, xmm3, OWORD PTR [rbp+176]
        vmovdqu	OWORD PTR [rsp+32], xmm6
        vmovdqu	OWORD PTR [rsp+48], xmm7
        ; msg_sched: 0-3
        ; rnd_0: 0 - 0
        mov	eax, r13d
        rorx	ecx, r12d, 11
        add	r15d, DWORD PTR [rsp]
        vpalignr	xmm4, xmm3, xmm2, 4
        vpalignr	xmm5, xmm1, xmm0, 4
        ; rnd_0: 1 - 2
        xor	ecx, edx
        xor	eax, r14d
        rorx	edx, r12d, 25
        and	eax, r12d
        xor	edx, ecx
        rorx	ecx, r8d, 13
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        add	r15d, edx
        rorx	edx, r8d, 2
        xor	eax, r14d
        xor	ecx, edx
        rorx	edx, r8d, 22
        add	r15d, eax
        vpsrld	xmm8, xmm5, 3
        vpor	xmm7, xmm7, xmm6
        ; rnd_0: 5 - 7
        xor	edx, ecx
        mov	eax, r9d
        add	r11d, r15d
        xor	eax, r8d
        add	r15d, edx
        and	ebx, eax
        xor	ebx, r9d
        rorx	edx, r11d, 6
        add	r15d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r12d
        rorx	ecx, r11d, 11
        add	r14d, DWORD PTR [rsp+4]
        vpsrld	xmm6, xmm5, 18
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r13d
        rorx	edx, r11d, 25
        vpslld	xmm5, xmm5, 14
        ; rnd_1: 2 - 2
        and	ebx, r11d
        xor	edx, ecx
        rorx	ecx, r15d, 13
        vpxor	xmm7, xmm7, xmm5
        ; rnd_1: 3 - 3
        add	r14d, edx
        rorx	edx, r15d, 2
        xor	ebx, r13d
        vpxor	xmm7, xmm7, xmm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r15d, 22
        add	r14d, ebx
        vpshufd	xmm6, xmm3, 250
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r8d
        add	r10d, r14d
        vpxor	xmm5, xmm7, xmm8
        ; rnd_1: 6 - 6
        xor	ebx, r15d
        add	r14d, edx
        and	eax, ebx
        vpsrld	xmm8, xmm6, 10
        ; rnd_1: 7 - 7
        xor	eax, r8d
        rorx	edx, r10d, 6
        add	r14d, eax
        ; rnd_0: 0 - 0
        mov	eax, r11d
        rorx	ecx, r10d, 11
        add	r13d, DWORD PTR [rsp+8]
        vpsrlq	xmm7, xmm6, 19
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r12d
        rorx	edx, r10d, 25
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm0
        ; rnd_0: 2 - 2
        and	eax, r10d
        xor	edx, ecx
        rorx	ecx, r14d, 13
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 3 - 3
        add	r13d, edx
        rorx	edx, r14d, 2
        xor	eax, r12d
        vpxor	xmm6, xmm6, xmm7
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r14d, 22
        add	r13d, eax
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r15d
        add	r9d, r13d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        xor	eax, r14d
        add	r13d, edx
        and	ebx, eax
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        xor	ebx, r15d
        rorx	edx, r9d, 6
        add	r13d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r10d
        rorx	ecx, r9d, 11
        add	r12d, DWORD PTR [rsp+12]
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r11d
        rorx	edx, r9d, 25
        vpsrld	xmm9, xmm6, 10
        ; rnd_1: 2 - 2
        and	ebx, r9d
        xor	edx, ecx
        rorx	ecx, r13d, 13
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 3 - 3
        add	r12d, edx
        rorx	edx, r13d, 2
        xor	ebx, r11d
        vpsrlq	xmm6, xmm6, 17
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r13d, 22
        add	r12d, ebx
        vpxor	xmm6, xmm6, xmm7
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r14d
        add	r8d, r12d
        vpxor	xmm9, xmm9, xmm6
        ; rnd_1: 6 - 6
        xor	ebx, r13d
        add	r12d, edx
        and	eax, ebx
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        xor	eax, r14d
        rorx	edx, r8d, 6
        add	r12d, eax
        vpaddd	xmm0, xmm9, xmm4
        ; msg_sched done: 0-3
        ; msg_sched: 4-7
        ; rnd_0: 0 - 0
        mov	eax, r9d
        rorx	ecx, r8d, 11
        add	r11d, DWORD PTR [rsp+16]
        vpalignr	xmm4, xmm0, xmm3, 4
        vpalignr	xmm5, xmm2, xmm1, 4
        ; rnd_0: 1 - 2
        xor	ecx, edx
        xor	eax, r10d
        rorx	edx, r8d, 25
        and	eax, r8d
        xor	edx, ecx
        rorx	ecx, r12d, 13
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        add	r11d, edx
        rorx	edx, r12d, 2
        xor	eax, r10d
        xor	ecx, edx
        rorx	edx, r12d, 22
        add	r11d, eax
        vpsrld	xmm8, xmm5, 3
        vpor	xmm7, xmm7, xmm6
        ; rnd_0: 5 - 7
        xor	edx, ecx
        mov	eax, r13d
        add	r15d, r11d
        xor	eax, r12d
        add	r11d, edx
        and	ebx, eax
        xor	ebx, r13d
        rorx	edx, r15d, 6
        add	r11d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r8d
        rorx	ecx, r15d, 11
        add	r10d, DWORD PTR [rsp+20]
        vpsrld	xmm6, xmm5, 18
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r9d
        rorx	edx, r15d, 25
        vpslld	xmm5, xmm5, 14
        ; rnd_1: 2 - 2
        and	ebx, r15d
        xor	edx, ecx
        rorx	ecx, r11d, 13
        vpxor	xmm7, xmm7, xmm5
        ; rnd_1: 3 - 3
        add	r10d, edx
        rorx	edx, r11d, 2
        xor	ebx, r9d
        vpxor	xmm7, xmm7, xmm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r11d, 22
        add	r10d, ebx
        vpshufd	xmm6, xmm0, 250
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r12d
        add	r14d, r10d
        vpxor	xmm5, xmm7, xmm8
        ; rnd_1: 6 - 6
        xor	ebx, r11d
        add	r10d, edx
        and	eax, ebx
        vpsrld	xmm8, xmm6, 10
        ; rnd_1: 7 - 7
        xor	eax, r12d
        rorx	edx, r14d, 6
        add	r10d, eax
        ; rnd_0: 0 - 0
        mov	eax, r15d
        rorx	ecx, r14d, 11
        add	r9d, DWORD PTR [rsp+24]
        vpsrlq	xmm7, xmm6, 19
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r8d
        rorx	edx, r14d, 25
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm1
        ; rnd_0: 2 - 2
        and	eax, r14d
        xor	edx, ecx
        rorx	ecx, r10d, 13
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 3 - 3
        add	r9d, edx
        rorx	edx, r10d, 2
        xor	eax, r8d
        vpxor	xmm6, xmm6, xmm7
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r10d, 22
        add	r9d, eax
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r11d
        add	r13d, r9d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        xor	eax, r10d
        add	r9d, edx
        and	ebx, eax
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        xor	ebx, r11d
        rorx	edx, r13d, 6
        add	r9d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r14d
        rorx	ecx, r13d, 11
        add	r8d, DWORD PTR [rsp+28]
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r15d
        rorx	edx, r13d, 25
        vpsrld	xmm9, xmm6, 10
        ; rnd_1: 2 - 2
        and	ebx, r13d
        xor	edx, ecx
        rorx	ecx, r9d, 13
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 3 - 3
        add	r8d, edx
        rorx	edx, r9d, 2
        xor	ebx, r15d
        vpsrlq	xmm6, xmm6, 17
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r9d, 22
        add	r8d, ebx
        vpxor	xmm6, xmm6, xmm7
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r10d
        add	r12d, r8d
        vpxor	xmm9, xmm9, xmm6
        ; rnd_1: 6 - 6
        xor	ebx, r9d
        add	r8d, edx
        and	eax, ebx
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        xor	eax, r10d
        rorx	edx, r12d, 6
        add	r8d, eax
        vpaddd	xmm1, xmm9, xmm4
        ; msg_sched done: 4-7
        ; msg_sched: 8-11
        ; rnd_0: 0 - 0
        mov	eax, r13d
        rorx	ecx, r12d, 11
        add	r15d, DWORD PTR [rsp+32]
        vpalignr	xmm4, xmm1, xmm0, 4
        vpalignr	xmm5, xmm3, xmm2, 4
        ; rnd_0: 1 - 2
        xor	ecx, edx
        xor	eax, r14d
        rorx	edx, r12d, 25
        and	eax, r12d
        xor	edx, ecx
        rorx	ecx, r8d, 13
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        add	r15d, edx
        rorx	edx, r8d, 2
        xor	eax, r14d
        xor	ecx, edx
        rorx	edx, r8d, 22
        add	r15d, eax
        vpsrld	xmm8, xmm5, 3
        vpor	xmm7, xmm7, xmm6
        ; rnd_0: 5 - 7
        xor	edx, ecx
        mov	eax, r9d
        add	r11d, r15d
        xor	eax, r8d
        add	r15d, edx
        and	ebx, eax
        xor	ebx, r9d
        rorx	edx, r11d, 6
        add	r15d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r12d
        rorx	ecx, r11d, 11
        add	r14d, DWORD PTR [rsp+36]
        vpsrld	xmm6, xmm5, 18
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r13d
        rorx	edx, r11d, 25
        vpslld	xmm5, xmm5, 14
        ; rnd_1: 2 - 2
        and	ebx, r11d
        xor	edx, ecx
        rorx	ecx, r15d, 13
        vpxor	xmm7, xmm7, xmm5
        ; rnd_1: 3 - 3
        add	r14d, edx
        rorx	edx, r15d, 2
        xor	ebx, r13d
        vpxor	xmm7, xmm7, xmm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r15d, 22
        add	r14d, ebx
        vpshufd	xmm6, xmm1, 250
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r8d
        add	r10d, r14d
        vpxor	xmm5, xmm7, xmm8
        ; rnd_1: 6 - 6
        xor	ebx, r15d
        add	r14d, edx
        and	eax, ebx
        vpsrld	xmm8, xmm6, 10
        ; rnd_1: 7 - 7
        xor	eax, r8d
        rorx	edx, r10d, 6
        add	r14d, eax
        ; rnd_0: 0 - 0
        mov	eax, r11d
        rorx	ecx, r10d, 11
        add	r13d, DWORD PTR [rsp+40]
        vpsrlq	xmm7, xmm6, 19
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r12d
        rorx	edx, r10d, 25
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm2
        ; rnd_0: 2 - 2
        and	eax, r10d
        xor	edx, ecx
        rorx	ecx, r14d, 13
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 3 - 3
        add	r13d, edx
        rorx	edx, r14d, 2
        xor	eax, r12d
        vpxor	xmm6, xmm6, xmm7
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r14d, 22
        add	r13d, eax
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r15d
        add	r9d, r13d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        xor	eax, r14d
        add	r13d, edx
        and	ebx, eax
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        xor	ebx, r15d
        rorx	edx, r9d, 6
        add	r13d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r10d
        rorx	ecx, r9d, 11
        add	r12d, DWORD PTR [rsp+44]
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r11d
        rorx	edx, r9d, 25
        vpsrld	xmm9, xmm6, 10
        ; rnd_1: 2 - 2
        and	ebx, r9d
        xor	edx, ecx
        rorx	ecx, r13d, 13
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 3 - 3
        add	r12d, edx
        rorx	edx, r13d, 2
        xor	ebx, r11d
        vpsrlq	xmm6, xmm6, 17
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r13d, 22
        add	r12d, ebx
        vpxor	xmm6, xmm6, xmm7
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r14d
        add	r8d, r12d
        vpxor	xmm9, xmm9, xmm6
        ; rnd_1: 6 - 6
        xor	ebx, r13d
        add	r12d, edx
        and	eax, ebx
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        xor	eax, r14d
        rorx	edx, r8d, 6
        add	r12d, eax
        vpaddd	xmm2, xmm9, xmm4
        ; msg_sched done: 8-11
        ; msg_sched: 12-15
        ; rnd_0: 0 - 0
        mov	eax, r9d
        rorx	ecx, r8d, 11
        add	r11d, DWORD PTR [rsp+48]
        vpalignr	xmm4, xmm2, xmm1, 4
        vpalignr	xmm5, xmm0, xmm3, 4
        ; rnd_0: 1 - 2
        xor	ecx, edx
        xor	eax, r10d
        rorx	edx, r8d, 25
        and	eax, r8d
        xor	edx, ecx
        rorx	ecx, r12d, 13
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        add	r11d, edx
        rorx	edx, r12d, 2
        xor	eax, r10d
        xor	ecx, edx
        rorx	edx, r12d, 22
        add	r11d, eax
        vpsrld	xmm8, xmm5, 3
        vpor	xmm7, xmm7, xmm6
        ; rnd_0: 5 - 7
        xor	edx, ecx
        mov	eax, r13d
        add	r15d, r11d
        xor	eax, r12d
        add	r11d, edx
        and	ebx, eax
        xor	ebx, r13d
        rorx	edx, r15d, 6
        add	r11d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r8d
        rorx	ecx, r15d, 11
        add	r10d, DWORD PTR [rsp+52]
        vpsrld	xmm6, xmm5, 18
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r9d
        rorx	edx, r15d, 25
        vpslld	xmm5, xmm5, 14
        ; rnd_1: 2 - 2
        and	ebx, r15d
        xor	edx, ecx
        rorx	ecx, r11d, 13
        vpxor	xmm7, xmm7, xmm5
        ; rnd_1: 3 - 3
        add	r10d, edx
        rorx	edx, r11d, 2
        xor	ebx, r9d
        vpxor	xmm7, xmm7, xmm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r11d, 22
        add	r10d, ebx
        vpshufd	xmm6, xmm2, 250
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r12d
        add	r14d, r10d
        vpxor	xmm5, xmm7, xmm8
        ; rnd_1: 6 - 6
        xor	ebx, r11d
        add	r10d, edx
        and	eax, ebx
        vpsrld	xmm8, xmm6, 10
        ; rnd_1: 7 - 7
        xor	eax, r12d
        rorx	edx, r14d, 6
        add	r10d, eax
        ; rnd_0: 0 - 0
        mov	eax, r15d
        rorx	ecx, r14d, 11
        add	r9d, DWORD PTR [rsp+56]
        vpsrlq	xmm7, xmm6, 19
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r8d
        rorx	edx, r14d, 25
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm3
        ; rnd_0: 2 - 2
        and	eax, r14d
        xor	edx, ecx
        rorx	ecx, r10d, 13
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 3 - 3
        add	r9d, edx
        rorx	edx, r10d, 2
        xor	eax, r8d
        vpxor	xmm6, xmm6, xmm7
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r10d, 22
        add	r9d, eax
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r11d
        add	r13d, r9d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        xor	eax, r10d
        add	r9d, edx
        and	ebx, eax
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        xor	ebx, r11d
        rorx	edx, r13d, 6
        add	r9d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r14d
        rorx	ecx, r13d, 11
        add	r8d, DWORD PTR [rsp+60]
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r15d
        rorx	edx, r13d, 25
        vpsrld	xmm9, xmm6, 10
        ; rnd_1: 2 - 2
        and	ebx, r13d
        xor	edx, ecx
        rorx	ecx, r9d, 13
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 3 - 3
        add	r8d, edx
        rorx	edx, r9d, 2
        xor	ebx, r15d
        vpsrlq	xmm6, xmm6, 17
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r9d, 22
        add	r8d, ebx
        vpxor	xmm6, xmm6, xmm7
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r10d
        add	r12d, r8d
        vpxor	xmm9, xmm9, xmm6
        ; rnd_1: 6 - 6
        xor	ebx, r9d
        add	r8d, edx
        and	eax, ebx
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        xor	eax, r10d
        rorx	edx, r12d, 6
        add	r8d, eax
        vpaddd	xmm3, xmm9, xmm4
        ; msg_sched done: 12-15
        ; set_w_k_xfer_4: 12
        vpaddd	xmm4, xmm0, OWORD PTR [rbp+192]
        vpaddd	xmm5, xmm1, OWORD PTR [rbp+208]
        vmovdqu	OWORD PTR [rsp], xmm4
        vmovdqu	OWORD PTR [rsp+16], xmm5
        vpaddd	xmm6, xmm2, OWORD PTR [rbp+224]
        vpaddd	xmm7, xmm3, OWORD PTR [rbp+240]
        vmovdqu	OWORD PTR [rsp+32], xmm6
        vmovdqu	OWORD PTR [rsp+48], xmm7
        xor	eax, eax
        ; rnd_all_4: 0-3
        rorx	edx, r12d, 6
        rorx	ecx, r12d, 11
        add	r8d, eax
        add	r15d, DWORD PTR [rsp]
        mov	eax, r13d
        xor	ecx, edx
        xor	eax, r14d
        rorx	edx, r12d, 25
        xor	edx, ecx
        and	eax, r12d
        add	r15d, edx
        rorx	edx, r8d, 2
        rorx	ecx, r8d, 13
        xor	eax, r14d
        xor	ecx, edx
        rorx	edx, r8d, 22
        add	r15d, eax
        xor	edx, ecx
        mov	eax, r9d
        add	r11d, r15d
        xor	eax, r8d
        and	ebx, eax
        add	r15d, edx
        xor	ebx, r9d
        rorx	edx, r11d, 6
        rorx	ecx, r11d, 11
        add	r15d, ebx
        add	r14d, DWORD PTR [rsp+4]
        mov	ebx, r12d
        xor	ecx, edx
        xor	ebx, r13d
        rorx	edx, r11d, 25
        xor	edx, ecx
        and	ebx, r11d
        add	r14d, edx
        rorx	edx, r15d, 2
        rorx	ecx, r15d, 13
        xor	ebx, r13d
        xor	ecx, edx
        rorx	edx, r15d, 22
        add	r14d, ebx
        xor	edx, ecx
        mov	ebx, r8d
        add	r10d, r14d
        xor	ebx, r15d
        and	eax, ebx
        add	r14d, edx
        xor	eax, r8d
        rorx	edx, r10d, 6
        rorx	ecx, r10d, 11
        add	r14d, eax
        add	r13d, DWORD PTR [rsp+8]
        mov	eax, r11d
        xor	ecx, edx
        xor	eax, r12d
        rorx	edx, r10d, 25
        xor	edx, ecx
        and	eax, r10d
        add	r13d, edx
        rorx	edx, r14d, 2
        rorx	ecx, r14d, 13
        xor	eax, r12d
        xor	ecx, edx
        rorx	edx, r14d, 22
        add	r13d, eax
        xor	edx, ecx
        mov	eax, r15d
        add	r9d, r13d
        xor	eax, r14d
        and	ebx, eax
        add	r13d, edx
        xor	ebx, r15d
        rorx	edx, r9d, 6
        rorx	ecx, r9d, 11
        add	r13d, ebx
        add	r12d, DWORD PTR [rsp+12]
        mov	ebx, r10d
        xor	ecx, edx
        xor	ebx, r11d
        rorx	edx, r9d, 25
        xor	edx, ecx
        and	ebx, r9d
        add	r12d, edx
        rorx	edx, r13d, 2
        rorx	ecx, r13d, 13
        xor	ebx, r11d
        xor	ecx, edx
        rorx	edx, r13d, 22
        add	r12d, ebx
        xor	edx, ecx
        mov	ebx, r14d
        add	r8d, r12d
        xor	ebx, r13d
        and	eax, ebx
        add	r12d, edx
        xor	eax, r14d
        ; rnd_all_4: 1-4
        rorx	edx, r8d, 6
        rorx	ecx, r8d, 11
        add	r12d, eax
        add	r11d, DWORD PTR [rsp+16]
        mov	eax, r9d
        xor	ecx, edx
        xor	eax, r10d
        rorx	edx, r8d, 25
        xor	edx, ecx
        and	eax, r8d
        add	r11d, edx
        rorx	edx, r12d, 2
        rorx	ecx, r12d, 13
        xor	eax, r10d
        xor	ecx, edx
        rorx	edx, r12d, 22
        add	r11d, eax
        xor	edx, ecx
        mov	eax, r13d
        add	r15d, r11d
        xor	eax, r12d
        and	ebx, eax
        add	r11d, edx
        xor	ebx, r13d
        rorx	edx, r15d, 6
        rorx	ecx, r15d, 11
        add	r11d, ebx
        add	r10d, DWORD PTR [rsp+20]
        mov	ebx, r8d
        xor	ecx, edx
        xor	ebx, r9d
        rorx	edx, r15d, 25
        xor	edx, ecx
        and	ebx, r15d
        add	r10d, edx
        rorx	edx, r11d, 2
        rorx	ecx, r11d, 13
        xor	ebx, r9d
        xor	ecx, edx
        rorx	edx, r11d, 22
        add	r10d, ebx
        xor	edx, ecx
        mov	ebx, r12d
        add	r14d, r10d
        xor	ebx, r11d
        and	eax, ebx
        add	r10d, edx
        xor	eax, r12d
        rorx	edx, r14d, 6
        rorx	ecx, r14d, 11
        add	r10d, eax
        add	r9d, DWORD PTR [rsp+24]
        mov	eax, r15d
        xor	ecx, edx
        xor	eax, r8d
        rorx	edx, r14d, 25
        xor	edx, ecx
        and	eax, r14d
        add	r9d, edx
        rorx	edx, r10d, 2
        rorx	ecx, r10d, 13
        xor	eax, r8d
        xor	ecx, edx
        rorx	edx, r10d, 22
        add	r9d, eax
        xor	edx, ecx
        mov	eax, r11d
        add	r13d, r9d
        xor	eax, r10d
        and	ebx, eax
        add	r9d, edx
        xor	ebx, r11d
        rorx	edx, r13d, 6
        rorx	ecx, r13d, 11
        add	r9d, ebx
        add	r8d, DWORD PTR [rsp+28]
        mov	ebx, r14d
        xor	ecx, edx
        xor	ebx, r15d
        rorx	edx, r13d, 25
        xor	edx, ecx
        and	ebx, r13d
        add	r8d, edx
        rorx	edx, r9d, 2
        rorx	ecx, r9d, 13
        xor	ebx, r15d
        xor	ecx, edx
        rorx	edx, r9d, 22
        add	r8d, ebx
        xor	edx, ecx
        mov	ebx, r10d
        add	r12d, r8d
        xor	ebx, r9d
        and	eax, ebx
        add	r8d, edx
        xor	eax, r10d
        ; rnd_all_4: 2-5
        rorx	edx, r12d, 6
        rorx	ecx, r12d, 11
        add	r8d, eax
        add	r15d, DWORD PTR [rsp+32]
        mov	eax, r13d
        xor	ecx, edx
        xor	eax, r14d
        rorx	edx, r12d, 25
        xor	edx, ecx
        and	eax, r12d
        add	r15d, edx
        rorx	edx, r8d, 2
        rorx	ecx, r8d, 13
        xor	eax, r14d
        xor	ecx, edx
        rorx	edx, r8d, 22
        add	r15d, eax
        xor	edx, ecx
        mov	eax, r9d
        add	r11d, r15d
        xor	eax, r8d
        and	ebx, eax
        add	r15d, edx
        xor	ebx, r9d
        rorx	edx, r11d, 6
        rorx	ecx, r11d, 11
        add	r15d, ebx
        add	r14d, DWORD PTR [rsp+36]
        mov	ebx, r12d
        xor	ecx, edx
        xor	ebx, r13d
        rorx	edx, r11d, 25
        xor	edx, ecx
        and	ebx, r11d
        add	r14d, edx
        rorx	edx, r15d, 2
        rorx	ecx, r15d, 13
        xor	ebx, r13d
        xor	ecx, edx
        rorx	edx, r15d, 22
        add	r14d, ebx
        xor	edx, ecx
        mov	ebx, r8d
        add	r10d, r14d
        xor	ebx, r15d
        and	eax, ebx
        add	r14d, edx
        xor	eax, r8d
        rorx	edx, r10d, 6
        rorx	ecx, r10d, 11
        add	r14d, eax
        add	r13d, DWORD PTR [rsp+40]
        mov	eax, r11d
        xor	ecx, edx
        xor	eax, r12d
        rorx	edx, r10d, 25
        xor	edx, ecx
        and	eax, r10d
        add	r13d, edx
        rorx	edx, r14d, 2
        rorx	ecx, r14d, 13
        xor	eax, r12d
        xor	ecx, edx
        rorx	edx, r14d, 22
        add	r13d, eax
        xor	edx, ecx
        mov	eax, r15d
        add	r9d, r13d
        xor	eax, r14d
        and	ebx, eax
        add	r13d, edx
        xor	ebx, r15d
        rorx	edx, r9d, 6
        rorx	ecx, r9d, 11
        add	r13d, ebx
        add	r12d, DWORD PTR [rsp+44]
        mov	ebx, r10d
        xor	ecx, edx
        xor	ebx, r11d
        rorx	edx, r9d, 25
        xor	edx, ecx
        and	ebx, r9d
        add	r12d, edx
        rorx	edx, r13d, 2
        rorx	ecx, r13d, 13
        xor	ebx, r11d
        xor	ecx, edx
        rorx	edx, r13d, 22
        add	r12d, ebx
        xor	edx, ecx
        mov	ebx, r14d
        add	r8d, r12d
        xor	ebx, r13d
        and	eax, ebx
        add	r12d, edx
        xor	eax, r14d
        ; rnd_all_4: 3-6
        rorx	edx, r8d, 6
        rorx	ecx, r8d, 11
        add	r12d, eax
        add	r11d, DWORD PTR [rsp+48]
        mov	eax, r9d
        xor	ecx, edx
        xor	eax, r10d
        rorx	edx, r8d, 25
        xor	edx, ecx
        and	eax, r8d
        add	r11d, edx
        rorx	edx, r12d, 2
        rorx	ecx, r12d, 13
        xor	eax, r10d
        xor	ecx, edx
        rorx	edx, r12d, 22
        add	r11d, eax
        xor	edx, ecx
        mov	eax, r13d
        add	r15d, r11d
        xor	eax, r12d
        and	ebx, eax
        add	r11d, edx
        xor	ebx, r13d
        rorx	edx, r15d, 6
        rorx	ecx, r15d, 11
        add	r11d, ebx
        add	r10d, DWORD PTR [rsp+52]
        mov	ebx, r8d
        xor	ecx, edx
        xor	ebx, r9d
        rorx	edx, r15d, 25
        xor	edx, ecx
        and	ebx, r15d
        add	r10d, edx
        rorx	edx, r11d, 2
        rorx	ecx, r11d, 13
        xor	ebx, r9d
        xor	ecx, edx
        rorx	edx, r11d, 22
        add	r10d, ebx
        xor	edx, ecx
        mov	ebx, r12d
        add	r14d, r10d
        xor	ebx, r11d
        and	eax, ebx
        add	r10d, edx
        xor	eax, r12d
        rorx	edx, r14d, 6
        rorx	ecx, r14d, 11
        add	r10d, eax
        add	r9d, DWORD PTR [rsp+56]
        mov	eax, r15d
        xor	ecx, edx
        xor	eax, r8d
        rorx	edx, r14d, 25
        xor	edx, ecx
        and	eax, r14d
        add	r9d, edx
        rorx	edx, r10d, 2
        rorx	ecx, r10d, 13
        xor	eax, r8d
        xor	ecx, edx
        rorx	edx, r10d, 22
        add	r9d, eax
        xor	edx, ecx
        mov	eax, r11d
        add	r13d, r9d
        xor	eax, r10d
        and	ebx, eax
        add	r9d, edx
        xor	ebx, r11d
        rorx	edx, r13d, 6
        rorx	ecx, r13d, 11
        add	r9d, ebx
        add	r8d, DWORD PTR [rsp+60]
        mov	ebx, r14d
        xor	ecx, edx
        xor	ebx, r15d
        rorx	edx, r13d, 25
        xor	edx, ecx
        and	ebx, r13d
        add	r8d, edx
        rorx	edx, r9d, 2
        rorx	ecx, r9d, 13
        xor	ebx, r15d
        xor	ecx, edx
        rorx	edx, r9d, 22
        add	r8d, ebx
        xor	edx, ecx
        mov	ebx, r10d
        add	r12d, r8d
        xor	ebx, r9d
        and	eax, ebx
        add	r8d, edx
        xor	eax, r10d
        add	r8d, eax
        add	DWORD PTR [rdi], r8d
        add	DWORD PTR [rdi+4], r9d
        add	DWORD PTR [rdi+8], r10d
        add	DWORD PTR [rdi+12], r11d
        add	DWORD PTR [rdi+16], r12d
        add	DWORD PTR [rdi+20], r13d
        add	DWORD PTR [rdi+24], r14d
        add	DWORD PTR [rdi+28], r15d
        xor	rax, rax
        vmovdqu	xmm6, OWORD PTR [rsp+64]
        vmovdqu	xmm7, OWORD PTR [rsp+80]
        vmovdqu	xmm8, OWORD PTR [rsp+96]
        vmovdqu	xmm9, OWORD PTR [rsp+112]
        vmovdqu	xmm10, OWORD PTR [rsp+128]
        vmovdqu	xmm11, OWORD PTR [rsp+144]
        vmovdqu	xmm12, OWORD PTR [rsp+160]
        vmovdqu	xmm13, OWORD PTR [rsp+176]
        add	rsp, 192
        pop	rsi
        pop	rdi
        pop	rbp
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        pop	rbx
        ret
Transform_Sha256_AVX1_RORX ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
Transform_Sha256_AVX1_RORX_Len PROC
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
        mov	rbp, r8
        sub	rsp, 196
        vmovdqu	OWORD PTR [rsp+64], xmm6
        vmovdqu	OWORD PTR [rsp+80], xmm7
        vmovdqu	OWORD PTR [rsp+96], xmm8
        vmovdqu	OWORD PTR [rsp+112], xmm9
        vmovdqu	OWORD PTR [rsp+128], xmm10
        vmovdqu	OWORD PTR [rsp+144], xmm11
        vmovdqu	OWORD PTR [rsp+160], xmm12
        vmovdqu	OWORD PTR [rsp+176], xmm13
        mov	DWORD PTR [rsp+64], ebp
        mov	rbp, QWORD PTR [ptr_L_avx1_rorx_sha256_k]
        vmovdqa	xmm13, OWORD PTR L_avx1_rorx_sha256_flip_mask
        vmovdqa	xmm11, OWORD PTR L_avx1_rorx_sha256_shuf_00BA
        vmovdqa	xmm12, OWORD PTR L_avx1_rorx_sha256_shuf_DC00
        mov	r8d, DWORD PTR [rdi]
        mov	r9d, DWORD PTR [rdi+4]
        mov	r10d, DWORD PTR [rdi+8]
        mov	r11d, DWORD PTR [rdi+12]
        mov	r12d, DWORD PTR [rdi+16]
        mov	r13d, DWORD PTR [rdi+20]
        mov	r14d, DWORD PTR [rdi+24]
        mov	r15d, DWORD PTR [rdi+28]
        ; Start of loop processing a block
L_sha256_len_avx1_len_rorx_start:
        ; X0, X1, X2, X3 = W[0..15]
        vmovdqu	xmm0, OWORD PTR [rsi]
        vmovdqu	xmm1, OWORD PTR [rsi+16]
        vpshufb	xmm0, xmm0, xmm13
        vpshufb	xmm1, xmm1, xmm13
        vmovdqu	xmm2, OWORD PTR [rsi+32]
        vmovdqu	xmm3, OWORD PTR [rsi+48]
        vpshufb	xmm2, xmm2, xmm13
        vpshufb	xmm3, xmm3, xmm13
        ; set_w_k_xfer_4: 0
        vpaddd	xmm4, xmm0, OWORD PTR [rbp]
        vpaddd	xmm5, xmm1, OWORD PTR [rbp+16]
        vmovdqu	OWORD PTR [rsp], xmm4
        vmovdqu	OWORD PTR [rsp+16], xmm5
        vpaddd	xmm6, xmm2, OWORD PTR [rbp+32]
        vpaddd	xmm7, xmm3, OWORD PTR [rbp+48]
        vmovdqu	OWORD PTR [rsp+32], xmm6
        vmovdqu	OWORD PTR [rsp+48], xmm7
        mov	ebx, r9d
        rorx	edx, r12d, 6
        xor	ebx, r10d
        ; msg_sched: 0-3
        ; rnd_0: 0 - 0
        mov	eax, r13d
        rorx	ecx, r12d, 11
        add	r15d, DWORD PTR [rsp]
        vpalignr	xmm4, xmm3, xmm2, 4
        vpalignr	xmm5, xmm1, xmm0, 4
        ; rnd_0: 1 - 2
        xor	ecx, edx
        xor	eax, r14d
        rorx	edx, r12d, 25
        and	eax, r12d
        xor	edx, ecx
        rorx	ecx, r8d, 13
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        add	r15d, edx
        rorx	edx, r8d, 2
        xor	eax, r14d
        xor	ecx, edx
        rorx	edx, r8d, 22
        add	r15d, eax
        vpsrld	xmm8, xmm5, 3
        vpor	xmm7, xmm7, xmm6
        ; rnd_0: 5 - 7
        xor	edx, ecx
        mov	eax, r9d
        add	r11d, r15d
        xor	eax, r8d
        add	r15d, edx
        and	ebx, eax
        xor	ebx, r9d
        rorx	edx, r11d, 6
        add	r15d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r12d
        rorx	ecx, r11d, 11
        add	r14d, DWORD PTR [rsp+4]
        vpsrld	xmm6, xmm5, 18
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r13d
        rorx	edx, r11d, 25
        vpslld	xmm5, xmm5, 14
        ; rnd_1: 2 - 2
        and	ebx, r11d
        xor	edx, ecx
        rorx	ecx, r15d, 13
        vpxor	xmm7, xmm7, xmm5
        ; rnd_1: 3 - 3
        add	r14d, edx
        rorx	edx, r15d, 2
        xor	ebx, r13d
        vpxor	xmm7, xmm7, xmm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r15d, 22
        add	r14d, ebx
        vpshufd	xmm6, xmm3, 250
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r8d
        add	r10d, r14d
        vpxor	xmm5, xmm7, xmm8
        ; rnd_1: 6 - 6
        xor	ebx, r15d
        add	r14d, edx
        and	eax, ebx
        vpsrld	xmm8, xmm6, 10
        ; rnd_1: 7 - 7
        xor	eax, r8d
        rorx	edx, r10d, 6
        add	r14d, eax
        ; rnd_0: 0 - 0
        mov	eax, r11d
        rorx	ecx, r10d, 11
        add	r13d, DWORD PTR [rsp+8]
        vpsrlq	xmm7, xmm6, 19
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r12d
        rorx	edx, r10d, 25
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm0
        ; rnd_0: 2 - 2
        and	eax, r10d
        xor	edx, ecx
        rorx	ecx, r14d, 13
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 3 - 3
        add	r13d, edx
        rorx	edx, r14d, 2
        xor	eax, r12d
        vpxor	xmm6, xmm6, xmm7
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r14d, 22
        add	r13d, eax
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r15d
        add	r9d, r13d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        xor	eax, r14d
        add	r13d, edx
        and	ebx, eax
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        xor	ebx, r15d
        rorx	edx, r9d, 6
        add	r13d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r10d
        rorx	ecx, r9d, 11
        add	r12d, DWORD PTR [rsp+12]
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r11d
        rorx	edx, r9d, 25
        vpsrld	xmm9, xmm6, 10
        ; rnd_1: 2 - 2
        and	ebx, r9d
        xor	edx, ecx
        rorx	ecx, r13d, 13
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 3 - 3
        add	r12d, edx
        rorx	edx, r13d, 2
        xor	ebx, r11d
        vpsrlq	xmm6, xmm6, 17
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r13d, 22
        add	r12d, ebx
        vpxor	xmm6, xmm6, xmm7
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r14d
        add	r8d, r12d
        vpxor	xmm9, xmm9, xmm6
        ; rnd_1: 6 - 6
        xor	ebx, r13d
        add	r12d, edx
        and	eax, ebx
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        xor	eax, r14d
        rorx	edx, r8d, 6
        add	r12d, eax
        vpaddd	xmm0, xmm9, xmm4
        ; msg_sched done: 0-3
        ; msg_sched: 4-7
        ; rnd_0: 0 - 0
        mov	eax, r9d
        rorx	ecx, r8d, 11
        add	r11d, DWORD PTR [rsp+16]
        vpalignr	xmm4, xmm0, xmm3, 4
        vpalignr	xmm5, xmm2, xmm1, 4
        ; rnd_0: 1 - 2
        xor	ecx, edx
        xor	eax, r10d
        rorx	edx, r8d, 25
        and	eax, r8d
        xor	edx, ecx
        rorx	ecx, r12d, 13
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        add	r11d, edx
        rorx	edx, r12d, 2
        xor	eax, r10d
        xor	ecx, edx
        rorx	edx, r12d, 22
        add	r11d, eax
        vpsrld	xmm8, xmm5, 3
        vpor	xmm7, xmm7, xmm6
        ; rnd_0: 5 - 7
        xor	edx, ecx
        mov	eax, r13d
        add	r15d, r11d
        xor	eax, r12d
        add	r11d, edx
        and	ebx, eax
        xor	ebx, r13d
        rorx	edx, r15d, 6
        add	r11d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r8d
        rorx	ecx, r15d, 11
        add	r10d, DWORD PTR [rsp+20]
        vpsrld	xmm6, xmm5, 18
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r9d
        rorx	edx, r15d, 25
        vpslld	xmm5, xmm5, 14
        ; rnd_1: 2 - 2
        and	ebx, r15d
        xor	edx, ecx
        rorx	ecx, r11d, 13
        vpxor	xmm7, xmm7, xmm5
        ; rnd_1: 3 - 3
        add	r10d, edx
        rorx	edx, r11d, 2
        xor	ebx, r9d
        vpxor	xmm7, xmm7, xmm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r11d, 22
        add	r10d, ebx
        vpshufd	xmm6, xmm0, 250
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r12d
        add	r14d, r10d
        vpxor	xmm5, xmm7, xmm8
        ; rnd_1: 6 - 6
        xor	ebx, r11d
        add	r10d, edx
        and	eax, ebx
        vpsrld	xmm8, xmm6, 10
        ; rnd_1: 7 - 7
        xor	eax, r12d
        rorx	edx, r14d, 6
        add	r10d, eax
        ; rnd_0: 0 - 0
        mov	eax, r15d
        rorx	ecx, r14d, 11
        add	r9d, DWORD PTR [rsp+24]
        vpsrlq	xmm7, xmm6, 19
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r8d
        rorx	edx, r14d, 25
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm1
        ; rnd_0: 2 - 2
        and	eax, r14d
        xor	edx, ecx
        rorx	ecx, r10d, 13
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 3 - 3
        add	r9d, edx
        rorx	edx, r10d, 2
        xor	eax, r8d
        vpxor	xmm6, xmm6, xmm7
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r10d, 22
        add	r9d, eax
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r11d
        add	r13d, r9d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        xor	eax, r10d
        add	r9d, edx
        and	ebx, eax
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        xor	ebx, r11d
        rorx	edx, r13d, 6
        add	r9d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r14d
        rorx	ecx, r13d, 11
        add	r8d, DWORD PTR [rsp+28]
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r15d
        rorx	edx, r13d, 25
        vpsrld	xmm9, xmm6, 10
        ; rnd_1: 2 - 2
        and	ebx, r13d
        xor	edx, ecx
        rorx	ecx, r9d, 13
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 3 - 3
        add	r8d, edx
        rorx	edx, r9d, 2
        xor	ebx, r15d
        vpsrlq	xmm6, xmm6, 17
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r9d, 22
        add	r8d, ebx
        vpxor	xmm6, xmm6, xmm7
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r10d
        add	r12d, r8d
        vpxor	xmm9, xmm9, xmm6
        ; rnd_1: 6 - 6
        xor	ebx, r9d
        add	r8d, edx
        and	eax, ebx
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        xor	eax, r10d
        rorx	edx, r12d, 6
        add	r8d, eax
        vpaddd	xmm1, xmm9, xmm4
        ; msg_sched done: 4-7
        ; msg_sched: 8-11
        ; rnd_0: 0 - 0
        mov	eax, r13d
        rorx	ecx, r12d, 11
        add	r15d, DWORD PTR [rsp+32]
        vpalignr	xmm4, xmm1, xmm0, 4
        vpalignr	xmm5, xmm3, xmm2, 4
        ; rnd_0: 1 - 2
        xor	ecx, edx
        xor	eax, r14d
        rorx	edx, r12d, 25
        and	eax, r12d
        xor	edx, ecx
        rorx	ecx, r8d, 13
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        add	r15d, edx
        rorx	edx, r8d, 2
        xor	eax, r14d
        xor	ecx, edx
        rorx	edx, r8d, 22
        add	r15d, eax
        vpsrld	xmm8, xmm5, 3
        vpor	xmm7, xmm7, xmm6
        ; rnd_0: 5 - 7
        xor	edx, ecx
        mov	eax, r9d
        add	r11d, r15d
        xor	eax, r8d
        add	r15d, edx
        and	ebx, eax
        xor	ebx, r9d
        rorx	edx, r11d, 6
        add	r15d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r12d
        rorx	ecx, r11d, 11
        add	r14d, DWORD PTR [rsp+36]
        vpsrld	xmm6, xmm5, 18
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r13d
        rorx	edx, r11d, 25
        vpslld	xmm5, xmm5, 14
        ; rnd_1: 2 - 2
        and	ebx, r11d
        xor	edx, ecx
        rorx	ecx, r15d, 13
        vpxor	xmm7, xmm7, xmm5
        ; rnd_1: 3 - 3
        add	r14d, edx
        rorx	edx, r15d, 2
        xor	ebx, r13d
        vpxor	xmm7, xmm7, xmm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r15d, 22
        add	r14d, ebx
        vpshufd	xmm6, xmm1, 250
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r8d
        add	r10d, r14d
        vpxor	xmm5, xmm7, xmm8
        ; rnd_1: 6 - 6
        xor	ebx, r15d
        add	r14d, edx
        and	eax, ebx
        vpsrld	xmm8, xmm6, 10
        ; rnd_1: 7 - 7
        xor	eax, r8d
        rorx	edx, r10d, 6
        add	r14d, eax
        ; rnd_0: 0 - 0
        mov	eax, r11d
        rorx	ecx, r10d, 11
        add	r13d, DWORD PTR [rsp+40]
        vpsrlq	xmm7, xmm6, 19
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r12d
        rorx	edx, r10d, 25
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm2
        ; rnd_0: 2 - 2
        and	eax, r10d
        xor	edx, ecx
        rorx	ecx, r14d, 13
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 3 - 3
        add	r13d, edx
        rorx	edx, r14d, 2
        xor	eax, r12d
        vpxor	xmm6, xmm6, xmm7
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r14d, 22
        add	r13d, eax
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r15d
        add	r9d, r13d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        xor	eax, r14d
        add	r13d, edx
        and	ebx, eax
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        xor	ebx, r15d
        rorx	edx, r9d, 6
        add	r13d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r10d
        rorx	ecx, r9d, 11
        add	r12d, DWORD PTR [rsp+44]
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r11d
        rorx	edx, r9d, 25
        vpsrld	xmm9, xmm6, 10
        ; rnd_1: 2 - 2
        and	ebx, r9d
        xor	edx, ecx
        rorx	ecx, r13d, 13
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 3 - 3
        add	r12d, edx
        rorx	edx, r13d, 2
        xor	ebx, r11d
        vpsrlq	xmm6, xmm6, 17
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r13d, 22
        add	r12d, ebx
        vpxor	xmm6, xmm6, xmm7
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r14d
        add	r8d, r12d
        vpxor	xmm9, xmm9, xmm6
        ; rnd_1: 6 - 6
        xor	ebx, r13d
        add	r12d, edx
        and	eax, ebx
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        xor	eax, r14d
        rorx	edx, r8d, 6
        add	r12d, eax
        vpaddd	xmm2, xmm9, xmm4
        ; msg_sched done: 8-11
        ; msg_sched: 12-15
        ; rnd_0: 0 - 0
        mov	eax, r9d
        rorx	ecx, r8d, 11
        add	r11d, DWORD PTR [rsp+48]
        vpalignr	xmm4, xmm2, xmm1, 4
        vpalignr	xmm5, xmm0, xmm3, 4
        ; rnd_0: 1 - 2
        xor	ecx, edx
        xor	eax, r10d
        rorx	edx, r8d, 25
        and	eax, r8d
        xor	edx, ecx
        rorx	ecx, r12d, 13
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        add	r11d, edx
        rorx	edx, r12d, 2
        xor	eax, r10d
        xor	ecx, edx
        rorx	edx, r12d, 22
        add	r11d, eax
        vpsrld	xmm8, xmm5, 3
        vpor	xmm7, xmm7, xmm6
        ; rnd_0: 5 - 7
        xor	edx, ecx
        mov	eax, r13d
        add	r15d, r11d
        xor	eax, r12d
        add	r11d, edx
        and	ebx, eax
        xor	ebx, r13d
        rorx	edx, r15d, 6
        add	r11d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r8d
        rorx	ecx, r15d, 11
        add	r10d, DWORD PTR [rsp+52]
        vpsrld	xmm6, xmm5, 18
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r9d
        rorx	edx, r15d, 25
        vpslld	xmm5, xmm5, 14
        ; rnd_1: 2 - 2
        and	ebx, r15d
        xor	edx, ecx
        rorx	ecx, r11d, 13
        vpxor	xmm7, xmm7, xmm5
        ; rnd_1: 3 - 3
        add	r10d, edx
        rorx	edx, r11d, 2
        xor	ebx, r9d
        vpxor	xmm7, xmm7, xmm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r11d, 22
        add	r10d, ebx
        vpshufd	xmm6, xmm2, 250
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r12d
        add	r14d, r10d
        vpxor	xmm5, xmm7, xmm8
        ; rnd_1: 6 - 6
        xor	ebx, r11d
        add	r10d, edx
        and	eax, ebx
        vpsrld	xmm8, xmm6, 10
        ; rnd_1: 7 - 7
        xor	eax, r12d
        rorx	edx, r14d, 6
        add	r10d, eax
        ; rnd_0: 0 - 0
        mov	eax, r15d
        rorx	ecx, r14d, 11
        add	r9d, DWORD PTR [rsp+56]
        vpsrlq	xmm7, xmm6, 19
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r8d
        rorx	edx, r14d, 25
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm3
        ; rnd_0: 2 - 2
        and	eax, r14d
        xor	edx, ecx
        rorx	ecx, r10d, 13
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 3 - 3
        add	r9d, edx
        rorx	edx, r10d, 2
        xor	eax, r8d
        vpxor	xmm6, xmm6, xmm7
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r10d, 22
        add	r9d, eax
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r11d
        add	r13d, r9d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        xor	eax, r10d
        add	r9d, edx
        and	ebx, eax
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        xor	ebx, r11d
        rorx	edx, r13d, 6
        add	r9d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r14d
        rorx	ecx, r13d, 11
        add	r8d, DWORD PTR [rsp+60]
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r15d
        rorx	edx, r13d, 25
        vpsrld	xmm9, xmm6, 10
        ; rnd_1: 2 - 2
        and	ebx, r13d
        xor	edx, ecx
        rorx	ecx, r9d, 13
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 3 - 3
        add	r8d, edx
        rorx	edx, r9d, 2
        xor	ebx, r15d
        vpsrlq	xmm6, xmm6, 17
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r9d, 22
        add	r8d, ebx
        vpxor	xmm6, xmm6, xmm7
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r10d
        add	r12d, r8d
        vpxor	xmm9, xmm9, xmm6
        ; rnd_1: 6 - 6
        xor	ebx, r9d
        add	r8d, edx
        and	eax, ebx
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        xor	eax, r10d
        rorx	edx, r12d, 6
        add	r8d, eax
        vpaddd	xmm3, xmm9, xmm4
        ; msg_sched done: 12-15
        ; set_w_k_xfer_4: 4
        vpaddd	xmm4, xmm0, OWORD PTR [rbp+64]
        vpaddd	xmm5, xmm1, OWORD PTR [rbp+80]
        vmovdqu	OWORD PTR [rsp], xmm4
        vmovdqu	OWORD PTR [rsp+16], xmm5
        vpaddd	xmm6, xmm2, OWORD PTR [rbp+96]
        vpaddd	xmm7, xmm3, OWORD PTR [rbp+112]
        vmovdqu	OWORD PTR [rsp+32], xmm6
        vmovdqu	OWORD PTR [rsp+48], xmm7
        ; msg_sched: 0-3
        ; rnd_0: 0 - 0
        mov	eax, r13d
        rorx	ecx, r12d, 11
        add	r15d, DWORD PTR [rsp]
        vpalignr	xmm4, xmm3, xmm2, 4
        vpalignr	xmm5, xmm1, xmm0, 4
        ; rnd_0: 1 - 2
        xor	ecx, edx
        xor	eax, r14d
        rorx	edx, r12d, 25
        and	eax, r12d
        xor	edx, ecx
        rorx	ecx, r8d, 13
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        add	r15d, edx
        rorx	edx, r8d, 2
        xor	eax, r14d
        xor	ecx, edx
        rorx	edx, r8d, 22
        add	r15d, eax
        vpsrld	xmm8, xmm5, 3
        vpor	xmm7, xmm7, xmm6
        ; rnd_0: 5 - 7
        xor	edx, ecx
        mov	eax, r9d
        add	r11d, r15d
        xor	eax, r8d
        add	r15d, edx
        and	ebx, eax
        xor	ebx, r9d
        rorx	edx, r11d, 6
        add	r15d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r12d
        rorx	ecx, r11d, 11
        add	r14d, DWORD PTR [rsp+4]
        vpsrld	xmm6, xmm5, 18
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r13d
        rorx	edx, r11d, 25
        vpslld	xmm5, xmm5, 14
        ; rnd_1: 2 - 2
        and	ebx, r11d
        xor	edx, ecx
        rorx	ecx, r15d, 13
        vpxor	xmm7, xmm7, xmm5
        ; rnd_1: 3 - 3
        add	r14d, edx
        rorx	edx, r15d, 2
        xor	ebx, r13d
        vpxor	xmm7, xmm7, xmm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r15d, 22
        add	r14d, ebx
        vpshufd	xmm6, xmm3, 250
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r8d
        add	r10d, r14d
        vpxor	xmm5, xmm7, xmm8
        ; rnd_1: 6 - 6
        xor	ebx, r15d
        add	r14d, edx
        and	eax, ebx
        vpsrld	xmm8, xmm6, 10
        ; rnd_1: 7 - 7
        xor	eax, r8d
        rorx	edx, r10d, 6
        add	r14d, eax
        ; rnd_0: 0 - 0
        mov	eax, r11d
        rorx	ecx, r10d, 11
        add	r13d, DWORD PTR [rsp+8]
        vpsrlq	xmm7, xmm6, 19
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r12d
        rorx	edx, r10d, 25
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm0
        ; rnd_0: 2 - 2
        and	eax, r10d
        xor	edx, ecx
        rorx	ecx, r14d, 13
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 3 - 3
        add	r13d, edx
        rorx	edx, r14d, 2
        xor	eax, r12d
        vpxor	xmm6, xmm6, xmm7
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r14d, 22
        add	r13d, eax
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r15d
        add	r9d, r13d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        xor	eax, r14d
        add	r13d, edx
        and	ebx, eax
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        xor	ebx, r15d
        rorx	edx, r9d, 6
        add	r13d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r10d
        rorx	ecx, r9d, 11
        add	r12d, DWORD PTR [rsp+12]
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r11d
        rorx	edx, r9d, 25
        vpsrld	xmm9, xmm6, 10
        ; rnd_1: 2 - 2
        and	ebx, r9d
        xor	edx, ecx
        rorx	ecx, r13d, 13
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 3 - 3
        add	r12d, edx
        rorx	edx, r13d, 2
        xor	ebx, r11d
        vpsrlq	xmm6, xmm6, 17
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r13d, 22
        add	r12d, ebx
        vpxor	xmm6, xmm6, xmm7
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r14d
        add	r8d, r12d
        vpxor	xmm9, xmm9, xmm6
        ; rnd_1: 6 - 6
        xor	ebx, r13d
        add	r12d, edx
        and	eax, ebx
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        xor	eax, r14d
        rorx	edx, r8d, 6
        add	r12d, eax
        vpaddd	xmm0, xmm9, xmm4
        ; msg_sched done: 0-3
        ; msg_sched: 4-7
        ; rnd_0: 0 - 0
        mov	eax, r9d
        rorx	ecx, r8d, 11
        add	r11d, DWORD PTR [rsp+16]
        vpalignr	xmm4, xmm0, xmm3, 4
        vpalignr	xmm5, xmm2, xmm1, 4
        ; rnd_0: 1 - 2
        xor	ecx, edx
        xor	eax, r10d
        rorx	edx, r8d, 25
        and	eax, r8d
        xor	edx, ecx
        rorx	ecx, r12d, 13
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        add	r11d, edx
        rorx	edx, r12d, 2
        xor	eax, r10d
        xor	ecx, edx
        rorx	edx, r12d, 22
        add	r11d, eax
        vpsrld	xmm8, xmm5, 3
        vpor	xmm7, xmm7, xmm6
        ; rnd_0: 5 - 7
        xor	edx, ecx
        mov	eax, r13d
        add	r15d, r11d
        xor	eax, r12d
        add	r11d, edx
        and	ebx, eax
        xor	ebx, r13d
        rorx	edx, r15d, 6
        add	r11d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r8d
        rorx	ecx, r15d, 11
        add	r10d, DWORD PTR [rsp+20]
        vpsrld	xmm6, xmm5, 18
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r9d
        rorx	edx, r15d, 25
        vpslld	xmm5, xmm5, 14
        ; rnd_1: 2 - 2
        and	ebx, r15d
        xor	edx, ecx
        rorx	ecx, r11d, 13
        vpxor	xmm7, xmm7, xmm5
        ; rnd_1: 3 - 3
        add	r10d, edx
        rorx	edx, r11d, 2
        xor	ebx, r9d
        vpxor	xmm7, xmm7, xmm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r11d, 22
        add	r10d, ebx
        vpshufd	xmm6, xmm0, 250
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r12d
        add	r14d, r10d
        vpxor	xmm5, xmm7, xmm8
        ; rnd_1: 6 - 6
        xor	ebx, r11d
        add	r10d, edx
        and	eax, ebx
        vpsrld	xmm8, xmm6, 10
        ; rnd_1: 7 - 7
        xor	eax, r12d
        rorx	edx, r14d, 6
        add	r10d, eax
        ; rnd_0: 0 - 0
        mov	eax, r15d
        rorx	ecx, r14d, 11
        add	r9d, DWORD PTR [rsp+24]
        vpsrlq	xmm7, xmm6, 19
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r8d
        rorx	edx, r14d, 25
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm1
        ; rnd_0: 2 - 2
        and	eax, r14d
        xor	edx, ecx
        rorx	ecx, r10d, 13
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 3 - 3
        add	r9d, edx
        rorx	edx, r10d, 2
        xor	eax, r8d
        vpxor	xmm6, xmm6, xmm7
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r10d, 22
        add	r9d, eax
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r11d
        add	r13d, r9d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        xor	eax, r10d
        add	r9d, edx
        and	ebx, eax
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        xor	ebx, r11d
        rorx	edx, r13d, 6
        add	r9d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r14d
        rorx	ecx, r13d, 11
        add	r8d, DWORD PTR [rsp+28]
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r15d
        rorx	edx, r13d, 25
        vpsrld	xmm9, xmm6, 10
        ; rnd_1: 2 - 2
        and	ebx, r13d
        xor	edx, ecx
        rorx	ecx, r9d, 13
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 3 - 3
        add	r8d, edx
        rorx	edx, r9d, 2
        xor	ebx, r15d
        vpsrlq	xmm6, xmm6, 17
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r9d, 22
        add	r8d, ebx
        vpxor	xmm6, xmm6, xmm7
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r10d
        add	r12d, r8d
        vpxor	xmm9, xmm9, xmm6
        ; rnd_1: 6 - 6
        xor	ebx, r9d
        add	r8d, edx
        and	eax, ebx
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        xor	eax, r10d
        rorx	edx, r12d, 6
        add	r8d, eax
        vpaddd	xmm1, xmm9, xmm4
        ; msg_sched done: 4-7
        ; msg_sched: 8-11
        ; rnd_0: 0 - 0
        mov	eax, r13d
        rorx	ecx, r12d, 11
        add	r15d, DWORD PTR [rsp+32]
        vpalignr	xmm4, xmm1, xmm0, 4
        vpalignr	xmm5, xmm3, xmm2, 4
        ; rnd_0: 1 - 2
        xor	ecx, edx
        xor	eax, r14d
        rorx	edx, r12d, 25
        and	eax, r12d
        xor	edx, ecx
        rorx	ecx, r8d, 13
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        add	r15d, edx
        rorx	edx, r8d, 2
        xor	eax, r14d
        xor	ecx, edx
        rorx	edx, r8d, 22
        add	r15d, eax
        vpsrld	xmm8, xmm5, 3
        vpor	xmm7, xmm7, xmm6
        ; rnd_0: 5 - 7
        xor	edx, ecx
        mov	eax, r9d
        add	r11d, r15d
        xor	eax, r8d
        add	r15d, edx
        and	ebx, eax
        xor	ebx, r9d
        rorx	edx, r11d, 6
        add	r15d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r12d
        rorx	ecx, r11d, 11
        add	r14d, DWORD PTR [rsp+36]
        vpsrld	xmm6, xmm5, 18
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r13d
        rorx	edx, r11d, 25
        vpslld	xmm5, xmm5, 14
        ; rnd_1: 2 - 2
        and	ebx, r11d
        xor	edx, ecx
        rorx	ecx, r15d, 13
        vpxor	xmm7, xmm7, xmm5
        ; rnd_1: 3 - 3
        add	r14d, edx
        rorx	edx, r15d, 2
        xor	ebx, r13d
        vpxor	xmm7, xmm7, xmm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r15d, 22
        add	r14d, ebx
        vpshufd	xmm6, xmm1, 250
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r8d
        add	r10d, r14d
        vpxor	xmm5, xmm7, xmm8
        ; rnd_1: 6 - 6
        xor	ebx, r15d
        add	r14d, edx
        and	eax, ebx
        vpsrld	xmm8, xmm6, 10
        ; rnd_1: 7 - 7
        xor	eax, r8d
        rorx	edx, r10d, 6
        add	r14d, eax
        ; rnd_0: 0 - 0
        mov	eax, r11d
        rorx	ecx, r10d, 11
        add	r13d, DWORD PTR [rsp+40]
        vpsrlq	xmm7, xmm6, 19
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r12d
        rorx	edx, r10d, 25
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm2
        ; rnd_0: 2 - 2
        and	eax, r10d
        xor	edx, ecx
        rorx	ecx, r14d, 13
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 3 - 3
        add	r13d, edx
        rorx	edx, r14d, 2
        xor	eax, r12d
        vpxor	xmm6, xmm6, xmm7
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r14d, 22
        add	r13d, eax
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r15d
        add	r9d, r13d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        xor	eax, r14d
        add	r13d, edx
        and	ebx, eax
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        xor	ebx, r15d
        rorx	edx, r9d, 6
        add	r13d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r10d
        rorx	ecx, r9d, 11
        add	r12d, DWORD PTR [rsp+44]
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r11d
        rorx	edx, r9d, 25
        vpsrld	xmm9, xmm6, 10
        ; rnd_1: 2 - 2
        and	ebx, r9d
        xor	edx, ecx
        rorx	ecx, r13d, 13
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 3 - 3
        add	r12d, edx
        rorx	edx, r13d, 2
        xor	ebx, r11d
        vpsrlq	xmm6, xmm6, 17
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r13d, 22
        add	r12d, ebx
        vpxor	xmm6, xmm6, xmm7
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r14d
        add	r8d, r12d
        vpxor	xmm9, xmm9, xmm6
        ; rnd_1: 6 - 6
        xor	ebx, r13d
        add	r12d, edx
        and	eax, ebx
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        xor	eax, r14d
        rorx	edx, r8d, 6
        add	r12d, eax
        vpaddd	xmm2, xmm9, xmm4
        ; msg_sched done: 8-11
        ; msg_sched: 12-15
        ; rnd_0: 0 - 0
        mov	eax, r9d
        rorx	ecx, r8d, 11
        add	r11d, DWORD PTR [rsp+48]
        vpalignr	xmm4, xmm2, xmm1, 4
        vpalignr	xmm5, xmm0, xmm3, 4
        ; rnd_0: 1 - 2
        xor	ecx, edx
        xor	eax, r10d
        rorx	edx, r8d, 25
        and	eax, r8d
        xor	edx, ecx
        rorx	ecx, r12d, 13
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        add	r11d, edx
        rorx	edx, r12d, 2
        xor	eax, r10d
        xor	ecx, edx
        rorx	edx, r12d, 22
        add	r11d, eax
        vpsrld	xmm8, xmm5, 3
        vpor	xmm7, xmm7, xmm6
        ; rnd_0: 5 - 7
        xor	edx, ecx
        mov	eax, r13d
        add	r15d, r11d
        xor	eax, r12d
        add	r11d, edx
        and	ebx, eax
        xor	ebx, r13d
        rorx	edx, r15d, 6
        add	r11d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r8d
        rorx	ecx, r15d, 11
        add	r10d, DWORD PTR [rsp+52]
        vpsrld	xmm6, xmm5, 18
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r9d
        rorx	edx, r15d, 25
        vpslld	xmm5, xmm5, 14
        ; rnd_1: 2 - 2
        and	ebx, r15d
        xor	edx, ecx
        rorx	ecx, r11d, 13
        vpxor	xmm7, xmm7, xmm5
        ; rnd_1: 3 - 3
        add	r10d, edx
        rorx	edx, r11d, 2
        xor	ebx, r9d
        vpxor	xmm7, xmm7, xmm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r11d, 22
        add	r10d, ebx
        vpshufd	xmm6, xmm2, 250
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r12d
        add	r14d, r10d
        vpxor	xmm5, xmm7, xmm8
        ; rnd_1: 6 - 6
        xor	ebx, r11d
        add	r10d, edx
        and	eax, ebx
        vpsrld	xmm8, xmm6, 10
        ; rnd_1: 7 - 7
        xor	eax, r12d
        rorx	edx, r14d, 6
        add	r10d, eax
        ; rnd_0: 0 - 0
        mov	eax, r15d
        rorx	ecx, r14d, 11
        add	r9d, DWORD PTR [rsp+56]
        vpsrlq	xmm7, xmm6, 19
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r8d
        rorx	edx, r14d, 25
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm3
        ; rnd_0: 2 - 2
        and	eax, r14d
        xor	edx, ecx
        rorx	ecx, r10d, 13
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 3 - 3
        add	r9d, edx
        rorx	edx, r10d, 2
        xor	eax, r8d
        vpxor	xmm6, xmm6, xmm7
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r10d, 22
        add	r9d, eax
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r11d
        add	r13d, r9d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        xor	eax, r10d
        add	r9d, edx
        and	ebx, eax
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        xor	ebx, r11d
        rorx	edx, r13d, 6
        add	r9d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r14d
        rorx	ecx, r13d, 11
        add	r8d, DWORD PTR [rsp+60]
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r15d
        rorx	edx, r13d, 25
        vpsrld	xmm9, xmm6, 10
        ; rnd_1: 2 - 2
        and	ebx, r13d
        xor	edx, ecx
        rorx	ecx, r9d, 13
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 3 - 3
        add	r8d, edx
        rorx	edx, r9d, 2
        xor	ebx, r15d
        vpsrlq	xmm6, xmm6, 17
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r9d, 22
        add	r8d, ebx
        vpxor	xmm6, xmm6, xmm7
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r10d
        add	r12d, r8d
        vpxor	xmm9, xmm9, xmm6
        ; rnd_1: 6 - 6
        xor	ebx, r9d
        add	r8d, edx
        and	eax, ebx
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        xor	eax, r10d
        rorx	edx, r12d, 6
        add	r8d, eax
        vpaddd	xmm3, xmm9, xmm4
        ; msg_sched done: 12-15
        ; set_w_k_xfer_4: 8
        vpaddd	xmm4, xmm0, OWORD PTR [rbp+128]
        vpaddd	xmm5, xmm1, OWORD PTR [rbp+144]
        vmovdqu	OWORD PTR [rsp], xmm4
        vmovdqu	OWORD PTR [rsp+16], xmm5
        vpaddd	xmm6, xmm2, OWORD PTR [rbp+160]
        vpaddd	xmm7, xmm3, OWORD PTR [rbp+176]
        vmovdqu	OWORD PTR [rsp+32], xmm6
        vmovdqu	OWORD PTR [rsp+48], xmm7
        ; msg_sched: 0-3
        ; rnd_0: 0 - 0
        mov	eax, r13d
        rorx	ecx, r12d, 11
        add	r15d, DWORD PTR [rsp]
        vpalignr	xmm4, xmm3, xmm2, 4
        vpalignr	xmm5, xmm1, xmm0, 4
        ; rnd_0: 1 - 2
        xor	ecx, edx
        xor	eax, r14d
        rorx	edx, r12d, 25
        and	eax, r12d
        xor	edx, ecx
        rorx	ecx, r8d, 13
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        add	r15d, edx
        rorx	edx, r8d, 2
        xor	eax, r14d
        xor	ecx, edx
        rorx	edx, r8d, 22
        add	r15d, eax
        vpsrld	xmm8, xmm5, 3
        vpor	xmm7, xmm7, xmm6
        ; rnd_0: 5 - 7
        xor	edx, ecx
        mov	eax, r9d
        add	r11d, r15d
        xor	eax, r8d
        add	r15d, edx
        and	ebx, eax
        xor	ebx, r9d
        rorx	edx, r11d, 6
        add	r15d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r12d
        rorx	ecx, r11d, 11
        add	r14d, DWORD PTR [rsp+4]
        vpsrld	xmm6, xmm5, 18
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r13d
        rorx	edx, r11d, 25
        vpslld	xmm5, xmm5, 14
        ; rnd_1: 2 - 2
        and	ebx, r11d
        xor	edx, ecx
        rorx	ecx, r15d, 13
        vpxor	xmm7, xmm7, xmm5
        ; rnd_1: 3 - 3
        add	r14d, edx
        rorx	edx, r15d, 2
        xor	ebx, r13d
        vpxor	xmm7, xmm7, xmm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r15d, 22
        add	r14d, ebx
        vpshufd	xmm6, xmm3, 250
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r8d
        add	r10d, r14d
        vpxor	xmm5, xmm7, xmm8
        ; rnd_1: 6 - 6
        xor	ebx, r15d
        add	r14d, edx
        and	eax, ebx
        vpsrld	xmm8, xmm6, 10
        ; rnd_1: 7 - 7
        xor	eax, r8d
        rorx	edx, r10d, 6
        add	r14d, eax
        ; rnd_0: 0 - 0
        mov	eax, r11d
        rorx	ecx, r10d, 11
        add	r13d, DWORD PTR [rsp+8]
        vpsrlq	xmm7, xmm6, 19
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r12d
        rorx	edx, r10d, 25
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm0
        ; rnd_0: 2 - 2
        and	eax, r10d
        xor	edx, ecx
        rorx	ecx, r14d, 13
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 3 - 3
        add	r13d, edx
        rorx	edx, r14d, 2
        xor	eax, r12d
        vpxor	xmm6, xmm6, xmm7
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r14d, 22
        add	r13d, eax
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r15d
        add	r9d, r13d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        xor	eax, r14d
        add	r13d, edx
        and	ebx, eax
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        xor	ebx, r15d
        rorx	edx, r9d, 6
        add	r13d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r10d
        rorx	ecx, r9d, 11
        add	r12d, DWORD PTR [rsp+12]
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r11d
        rorx	edx, r9d, 25
        vpsrld	xmm9, xmm6, 10
        ; rnd_1: 2 - 2
        and	ebx, r9d
        xor	edx, ecx
        rorx	ecx, r13d, 13
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 3 - 3
        add	r12d, edx
        rorx	edx, r13d, 2
        xor	ebx, r11d
        vpsrlq	xmm6, xmm6, 17
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r13d, 22
        add	r12d, ebx
        vpxor	xmm6, xmm6, xmm7
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r14d
        add	r8d, r12d
        vpxor	xmm9, xmm9, xmm6
        ; rnd_1: 6 - 6
        xor	ebx, r13d
        add	r12d, edx
        and	eax, ebx
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        xor	eax, r14d
        rorx	edx, r8d, 6
        add	r12d, eax
        vpaddd	xmm0, xmm9, xmm4
        ; msg_sched done: 0-3
        ; msg_sched: 4-7
        ; rnd_0: 0 - 0
        mov	eax, r9d
        rorx	ecx, r8d, 11
        add	r11d, DWORD PTR [rsp+16]
        vpalignr	xmm4, xmm0, xmm3, 4
        vpalignr	xmm5, xmm2, xmm1, 4
        ; rnd_0: 1 - 2
        xor	ecx, edx
        xor	eax, r10d
        rorx	edx, r8d, 25
        and	eax, r8d
        xor	edx, ecx
        rorx	ecx, r12d, 13
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        add	r11d, edx
        rorx	edx, r12d, 2
        xor	eax, r10d
        xor	ecx, edx
        rorx	edx, r12d, 22
        add	r11d, eax
        vpsrld	xmm8, xmm5, 3
        vpor	xmm7, xmm7, xmm6
        ; rnd_0: 5 - 7
        xor	edx, ecx
        mov	eax, r13d
        add	r15d, r11d
        xor	eax, r12d
        add	r11d, edx
        and	ebx, eax
        xor	ebx, r13d
        rorx	edx, r15d, 6
        add	r11d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r8d
        rorx	ecx, r15d, 11
        add	r10d, DWORD PTR [rsp+20]
        vpsrld	xmm6, xmm5, 18
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r9d
        rorx	edx, r15d, 25
        vpslld	xmm5, xmm5, 14
        ; rnd_1: 2 - 2
        and	ebx, r15d
        xor	edx, ecx
        rorx	ecx, r11d, 13
        vpxor	xmm7, xmm7, xmm5
        ; rnd_1: 3 - 3
        add	r10d, edx
        rorx	edx, r11d, 2
        xor	ebx, r9d
        vpxor	xmm7, xmm7, xmm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r11d, 22
        add	r10d, ebx
        vpshufd	xmm6, xmm0, 250
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r12d
        add	r14d, r10d
        vpxor	xmm5, xmm7, xmm8
        ; rnd_1: 6 - 6
        xor	ebx, r11d
        add	r10d, edx
        and	eax, ebx
        vpsrld	xmm8, xmm6, 10
        ; rnd_1: 7 - 7
        xor	eax, r12d
        rorx	edx, r14d, 6
        add	r10d, eax
        ; rnd_0: 0 - 0
        mov	eax, r15d
        rorx	ecx, r14d, 11
        add	r9d, DWORD PTR [rsp+24]
        vpsrlq	xmm7, xmm6, 19
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r8d
        rorx	edx, r14d, 25
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm1
        ; rnd_0: 2 - 2
        and	eax, r14d
        xor	edx, ecx
        rorx	ecx, r10d, 13
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 3 - 3
        add	r9d, edx
        rorx	edx, r10d, 2
        xor	eax, r8d
        vpxor	xmm6, xmm6, xmm7
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r10d, 22
        add	r9d, eax
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r11d
        add	r13d, r9d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        xor	eax, r10d
        add	r9d, edx
        and	ebx, eax
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        xor	ebx, r11d
        rorx	edx, r13d, 6
        add	r9d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r14d
        rorx	ecx, r13d, 11
        add	r8d, DWORD PTR [rsp+28]
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r15d
        rorx	edx, r13d, 25
        vpsrld	xmm9, xmm6, 10
        ; rnd_1: 2 - 2
        and	ebx, r13d
        xor	edx, ecx
        rorx	ecx, r9d, 13
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 3 - 3
        add	r8d, edx
        rorx	edx, r9d, 2
        xor	ebx, r15d
        vpsrlq	xmm6, xmm6, 17
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r9d, 22
        add	r8d, ebx
        vpxor	xmm6, xmm6, xmm7
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r10d
        add	r12d, r8d
        vpxor	xmm9, xmm9, xmm6
        ; rnd_1: 6 - 6
        xor	ebx, r9d
        add	r8d, edx
        and	eax, ebx
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        xor	eax, r10d
        rorx	edx, r12d, 6
        add	r8d, eax
        vpaddd	xmm1, xmm9, xmm4
        ; msg_sched done: 4-7
        ; msg_sched: 8-11
        ; rnd_0: 0 - 0
        mov	eax, r13d
        rorx	ecx, r12d, 11
        add	r15d, DWORD PTR [rsp+32]
        vpalignr	xmm4, xmm1, xmm0, 4
        vpalignr	xmm5, xmm3, xmm2, 4
        ; rnd_0: 1 - 2
        xor	ecx, edx
        xor	eax, r14d
        rorx	edx, r12d, 25
        and	eax, r12d
        xor	edx, ecx
        rorx	ecx, r8d, 13
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        add	r15d, edx
        rorx	edx, r8d, 2
        xor	eax, r14d
        xor	ecx, edx
        rorx	edx, r8d, 22
        add	r15d, eax
        vpsrld	xmm8, xmm5, 3
        vpor	xmm7, xmm7, xmm6
        ; rnd_0: 5 - 7
        xor	edx, ecx
        mov	eax, r9d
        add	r11d, r15d
        xor	eax, r8d
        add	r15d, edx
        and	ebx, eax
        xor	ebx, r9d
        rorx	edx, r11d, 6
        add	r15d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r12d
        rorx	ecx, r11d, 11
        add	r14d, DWORD PTR [rsp+36]
        vpsrld	xmm6, xmm5, 18
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r13d
        rorx	edx, r11d, 25
        vpslld	xmm5, xmm5, 14
        ; rnd_1: 2 - 2
        and	ebx, r11d
        xor	edx, ecx
        rorx	ecx, r15d, 13
        vpxor	xmm7, xmm7, xmm5
        ; rnd_1: 3 - 3
        add	r14d, edx
        rorx	edx, r15d, 2
        xor	ebx, r13d
        vpxor	xmm7, xmm7, xmm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r15d, 22
        add	r14d, ebx
        vpshufd	xmm6, xmm1, 250
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r8d
        add	r10d, r14d
        vpxor	xmm5, xmm7, xmm8
        ; rnd_1: 6 - 6
        xor	ebx, r15d
        add	r14d, edx
        and	eax, ebx
        vpsrld	xmm8, xmm6, 10
        ; rnd_1: 7 - 7
        xor	eax, r8d
        rorx	edx, r10d, 6
        add	r14d, eax
        ; rnd_0: 0 - 0
        mov	eax, r11d
        rorx	ecx, r10d, 11
        add	r13d, DWORD PTR [rsp+40]
        vpsrlq	xmm7, xmm6, 19
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r12d
        rorx	edx, r10d, 25
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm2
        ; rnd_0: 2 - 2
        and	eax, r10d
        xor	edx, ecx
        rorx	ecx, r14d, 13
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 3 - 3
        add	r13d, edx
        rorx	edx, r14d, 2
        xor	eax, r12d
        vpxor	xmm6, xmm6, xmm7
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r14d, 22
        add	r13d, eax
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r15d
        add	r9d, r13d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        xor	eax, r14d
        add	r13d, edx
        and	ebx, eax
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        xor	ebx, r15d
        rorx	edx, r9d, 6
        add	r13d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r10d
        rorx	ecx, r9d, 11
        add	r12d, DWORD PTR [rsp+44]
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r11d
        rorx	edx, r9d, 25
        vpsrld	xmm9, xmm6, 10
        ; rnd_1: 2 - 2
        and	ebx, r9d
        xor	edx, ecx
        rorx	ecx, r13d, 13
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 3 - 3
        add	r12d, edx
        rorx	edx, r13d, 2
        xor	ebx, r11d
        vpsrlq	xmm6, xmm6, 17
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r13d, 22
        add	r12d, ebx
        vpxor	xmm6, xmm6, xmm7
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r14d
        add	r8d, r12d
        vpxor	xmm9, xmm9, xmm6
        ; rnd_1: 6 - 6
        xor	ebx, r13d
        add	r12d, edx
        and	eax, ebx
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        xor	eax, r14d
        rorx	edx, r8d, 6
        add	r12d, eax
        vpaddd	xmm2, xmm9, xmm4
        ; msg_sched done: 8-11
        ; msg_sched: 12-15
        ; rnd_0: 0 - 0
        mov	eax, r9d
        rorx	ecx, r8d, 11
        add	r11d, DWORD PTR [rsp+48]
        vpalignr	xmm4, xmm2, xmm1, 4
        vpalignr	xmm5, xmm0, xmm3, 4
        ; rnd_0: 1 - 2
        xor	ecx, edx
        xor	eax, r10d
        rorx	edx, r8d, 25
        and	eax, r8d
        xor	edx, ecx
        rorx	ecx, r12d, 13
        vpsrld	xmm6, xmm5, 7
        vpslld	xmm7, xmm5, 25
        ; rnd_0: 3 - 4
        add	r11d, edx
        rorx	edx, r12d, 2
        xor	eax, r10d
        xor	ecx, edx
        rorx	edx, r12d, 22
        add	r11d, eax
        vpsrld	xmm8, xmm5, 3
        vpor	xmm7, xmm7, xmm6
        ; rnd_0: 5 - 7
        xor	edx, ecx
        mov	eax, r13d
        add	r15d, r11d
        xor	eax, r12d
        add	r11d, edx
        and	ebx, eax
        xor	ebx, r13d
        rorx	edx, r15d, 6
        add	r11d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r8d
        rorx	ecx, r15d, 11
        add	r10d, DWORD PTR [rsp+52]
        vpsrld	xmm6, xmm5, 18
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r9d
        rorx	edx, r15d, 25
        vpslld	xmm5, xmm5, 14
        ; rnd_1: 2 - 2
        and	ebx, r15d
        xor	edx, ecx
        rorx	ecx, r11d, 13
        vpxor	xmm7, xmm7, xmm5
        ; rnd_1: 3 - 3
        add	r10d, edx
        rorx	edx, r11d, 2
        xor	ebx, r9d
        vpxor	xmm7, xmm7, xmm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r11d, 22
        add	r10d, ebx
        vpshufd	xmm6, xmm2, 250
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r12d
        add	r14d, r10d
        vpxor	xmm5, xmm7, xmm8
        ; rnd_1: 6 - 6
        xor	ebx, r11d
        add	r10d, edx
        and	eax, ebx
        vpsrld	xmm8, xmm6, 10
        ; rnd_1: 7 - 7
        xor	eax, r12d
        rorx	edx, r14d, 6
        add	r10d, eax
        ; rnd_0: 0 - 0
        mov	eax, r15d
        rorx	ecx, r14d, 11
        add	r9d, DWORD PTR [rsp+56]
        vpsrlq	xmm7, xmm6, 19
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r8d
        rorx	edx, r14d, 25
        vpsrlq	xmm6, xmm6, 17
        vpaddd	xmm4, xmm4, xmm3
        ; rnd_0: 2 - 2
        and	eax, r14d
        xor	edx, ecx
        rorx	ecx, r10d, 13
        vpaddd	xmm4, xmm4, xmm5
        ; rnd_0: 3 - 3
        add	r9d, edx
        rorx	edx, r10d, 2
        xor	eax, r8d
        vpxor	xmm6, xmm6, xmm7
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r10d, 22
        add	r9d, eax
        vpxor	xmm8, xmm8, xmm6
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r11d
        add	r13d, r9d
        vpshufb	xmm8, xmm8, xmm11
        ; rnd_0: 6 - 6
        xor	eax, r10d
        add	r9d, edx
        and	ebx, eax
        vpaddd	xmm4, xmm4, xmm8
        ; rnd_0: 7 - 7
        xor	ebx, r11d
        rorx	edx, r13d, 6
        add	r9d, ebx
        ; rnd_1: 0 - 0
        mov	ebx, r14d
        rorx	ecx, r13d, 11
        add	r8d, DWORD PTR [rsp+60]
        vpshufd	xmm6, xmm4, 80
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r15d
        rorx	edx, r13d, 25
        vpsrld	xmm9, xmm6, 10
        ; rnd_1: 2 - 2
        and	ebx, r13d
        xor	edx, ecx
        rorx	ecx, r9d, 13
        vpsrlq	xmm7, xmm6, 19
        ; rnd_1: 3 - 3
        add	r8d, edx
        rorx	edx, r9d, 2
        xor	ebx, r15d
        vpsrlq	xmm6, xmm6, 17
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r9d, 22
        add	r8d, ebx
        vpxor	xmm6, xmm6, xmm7
        ; rnd_1: 5 - 5
        xor	edx, ecx
        mov	ebx, r10d
        add	r12d, r8d
        vpxor	xmm9, xmm9, xmm6
        ; rnd_1: 6 - 6
        xor	ebx, r9d
        add	r8d, edx
        and	eax, ebx
        vpshufb	xmm9, xmm9, xmm12
        ; rnd_1: 7 - 7
        xor	eax, r10d
        rorx	edx, r12d, 6
        add	r8d, eax
        vpaddd	xmm3, xmm9, xmm4
        ; msg_sched done: 12-15
        ; set_w_k_xfer_4: 12
        vpaddd	xmm4, xmm0, OWORD PTR [rbp+192]
        vpaddd	xmm5, xmm1, OWORD PTR [rbp+208]
        vmovdqu	OWORD PTR [rsp], xmm4
        vmovdqu	OWORD PTR [rsp+16], xmm5
        vpaddd	xmm6, xmm2, OWORD PTR [rbp+224]
        vpaddd	xmm7, xmm3, OWORD PTR [rbp+240]
        vmovdqu	OWORD PTR [rsp+32], xmm6
        vmovdqu	OWORD PTR [rsp+48], xmm7
        xor	eax, eax
        xor	ecx, ecx
        ; rnd_all_4: 0-3
        rorx	edx, r12d, 6
        rorx	ecx, r12d, 11
        add	r8d, eax
        add	r15d, DWORD PTR [rsp]
        mov	eax, r13d
        xor	ecx, edx
        xor	eax, r14d
        rorx	edx, r12d, 25
        xor	edx, ecx
        and	eax, r12d
        add	r15d, edx
        rorx	edx, r8d, 2
        rorx	ecx, r8d, 13
        xor	eax, r14d
        xor	ecx, edx
        rorx	edx, r8d, 22
        add	r15d, eax
        xor	edx, ecx
        mov	eax, r9d
        add	r11d, r15d
        xor	eax, r8d
        and	ebx, eax
        add	r15d, edx
        xor	ebx, r9d
        rorx	edx, r11d, 6
        rorx	ecx, r11d, 11
        add	r15d, ebx
        add	r14d, DWORD PTR [rsp+4]
        mov	ebx, r12d
        xor	ecx, edx
        xor	ebx, r13d
        rorx	edx, r11d, 25
        xor	edx, ecx
        and	ebx, r11d
        add	r14d, edx
        rorx	edx, r15d, 2
        rorx	ecx, r15d, 13
        xor	ebx, r13d
        xor	ecx, edx
        rorx	edx, r15d, 22
        add	r14d, ebx
        xor	edx, ecx
        mov	ebx, r8d
        add	r10d, r14d
        xor	ebx, r15d
        and	eax, ebx
        add	r14d, edx
        xor	eax, r8d
        rorx	edx, r10d, 6
        rorx	ecx, r10d, 11
        add	r14d, eax
        add	r13d, DWORD PTR [rsp+8]
        mov	eax, r11d
        xor	ecx, edx
        xor	eax, r12d
        rorx	edx, r10d, 25
        xor	edx, ecx
        and	eax, r10d
        add	r13d, edx
        rorx	edx, r14d, 2
        rorx	ecx, r14d, 13
        xor	eax, r12d
        xor	ecx, edx
        rorx	edx, r14d, 22
        add	r13d, eax
        xor	edx, ecx
        mov	eax, r15d
        add	r9d, r13d
        xor	eax, r14d
        and	ebx, eax
        add	r13d, edx
        xor	ebx, r15d
        rorx	edx, r9d, 6
        rorx	ecx, r9d, 11
        add	r13d, ebx
        add	r12d, DWORD PTR [rsp+12]
        mov	ebx, r10d
        xor	ecx, edx
        xor	ebx, r11d
        rorx	edx, r9d, 25
        xor	edx, ecx
        and	ebx, r9d
        add	r12d, edx
        rorx	edx, r13d, 2
        rorx	ecx, r13d, 13
        xor	ebx, r11d
        xor	ecx, edx
        rorx	edx, r13d, 22
        add	r12d, ebx
        xor	edx, ecx
        mov	ebx, r14d
        add	r8d, r12d
        xor	ebx, r13d
        and	eax, ebx
        add	r12d, edx
        xor	eax, r14d
        ; rnd_all_4: 1-4
        rorx	edx, r8d, 6
        rorx	ecx, r8d, 11
        add	r12d, eax
        add	r11d, DWORD PTR [rsp+16]
        mov	eax, r9d
        xor	ecx, edx
        xor	eax, r10d
        rorx	edx, r8d, 25
        xor	edx, ecx
        and	eax, r8d
        add	r11d, edx
        rorx	edx, r12d, 2
        rorx	ecx, r12d, 13
        xor	eax, r10d
        xor	ecx, edx
        rorx	edx, r12d, 22
        add	r11d, eax
        xor	edx, ecx
        mov	eax, r13d
        add	r15d, r11d
        xor	eax, r12d
        and	ebx, eax
        add	r11d, edx
        xor	ebx, r13d
        rorx	edx, r15d, 6
        rorx	ecx, r15d, 11
        add	r11d, ebx
        add	r10d, DWORD PTR [rsp+20]
        mov	ebx, r8d
        xor	ecx, edx
        xor	ebx, r9d
        rorx	edx, r15d, 25
        xor	edx, ecx
        and	ebx, r15d
        add	r10d, edx
        rorx	edx, r11d, 2
        rorx	ecx, r11d, 13
        xor	ebx, r9d
        xor	ecx, edx
        rorx	edx, r11d, 22
        add	r10d, ebx
        xor	edx, ecx
        mov	ebx, r12d
        add	r14d, r10d
        xor	ebx, r11d
        and	eax, ebx
        add	r10d, edx
        xor	eax, r12d
        rorx	edx, r14d, 6
        rorx	ecx, r14d, 11
        add	r10d, eax
        add	r9d, DWORD PTR [rsp+24]
        mov	eax, r15d
        xor	ecx, edx
        xor	eax, r8d
        rorx	edx, r14d, 25
        xor	edx, ecx
        and	eax, r14d
        add	r9d, edx
        rorx	edx, r10d, 2
        rorx	ecx, r10d, 13
        xor	eax, r8d
        xor	ecx, edx
        rorx	edx, r10d, 22
        add	r9d, eax
        xor	edx, ecx
        mov	eax, r11d
        add	r13d, r9d
        xor	eax, r10d
        and	ebx, eax
        add	r9d, edx
        xor	ebx, r11d
        rorx	edx, r13d, 6
        rorx	ecx, r13d, 11
        add	r9d, ebx
        add	r8d, DWORD PTR [rsp+28]
        mov	ebx, r14d
        xor	ecx, edx
        xor	ebx, r15d
        rorx	edx, r13d, 25
        xor	edx, ecx
        and	ebx, r13d
        add	r8d, edx
        rorx	edx, r9d, 2
        rorx	ecx, r9d, 13
        xor	ebx, r15d
        xor	ecx, edx
        rorx	edx, r9d, 22
        add	r8d, ebx
        xor	edx, ecx
        mov	ebx, r10d
        add	r12d, r8d
        xor	ebx, r9d
        and	eax, ebx
        add	r8d, edx
        xor	eax, r10d
        ; rnd_all_4: 2-5
        rorx	edx, r12d, 6
        rorx	ecx, r12d, 11
        add	r8d, eax
        add	r15d, DWORD PTR [rsp+32]
        mov	eax, r13d
        xor	ecx, edx
        xor	eax, r14d
        rorx	edx, r12d, 25
        xor	edx, ecx
        and	eax, r12d
        add	r15d, edx
        rorx	edx, r8d, 2
        rorx	ecx, r8d, 13
        xor	eax, r14d
        xor	ecx, edx
        rorx	edx, r8d, 22
        add	r15d, eax
        xor	edx, ecx
        mov	eax, r9d
        add	r11d, r15d
        xor	eax, r8d
        and	ebx, eax
        add	r15d, edx
        xor	ebx, r9d
        rorx	edx, r11d, 6
        rorx	ecx, r11d, 11
        add	r15d, ebx
        add	r14d, DWORD PTR [rsp+36]
        mov	ebx, r12d
        xor	ecx, edx
        xor	ebx, r13d
        rorx	edx, r11d, 25
        xor	edx, ecx
        and	ebx, r11d
        add	r14d, edx
        rorx	edx, r15d, 2
        rorx	ecx, r15d, 13
        xor	ebx, r13d
        xor	ecx, edx
        rorx	edx, r15d, 22
        add	r14d, ebx
        xor	edx, ecx
        mov	ebx, r8d
        add	r10d, r14d
        xor	ebx, r15d
        and	eax, ebx
        add	r14d, edx
        xor	eax, r8d
        rorx	edx, r10d, 6
        rorx	ecx, r10d, 11
        add	r14d, eax
        add	r13d, DWORD PTR [rsp+40]
        mov	eax, r11d
        xor	ecx, edx
        xor	eax, r12d
        rorx	edx, r10d, 25
        xor	edx, ecx
        and	eax, r10d
        add	r13d, edx
        rorx	edx, r14d, 2
        rorx	ecx, r14d, 13
        xor	eax, r12d
        xor	ecx, edx
        rorx	edx, r14d, 22
        add	r13d, eax
        xor	edx, ecx
        mov	eax, r15d
        add	r9d, r13d
        xor	eax, r14d
        and	ebx, eax
        add	r13d, edx
        xor	ebx, r15d
        rorx	edx, r9d, 6
        rorx	ecx, r9d, 11
        add	r13d, ebx
        add	r12d, DWORD PTR [rsp+44]
        mov	ebx, r10d
        xor	ecx, edx
        xor	ebx, r11d
        rorx	edx, r9d, 25
        xor	edx, ecx
        and	ebx, r9d
        add	r12d, edx
        rorx	edx, r13d, 2
        rorx	ecx, r13d, 13
        xor	ebx, r11d
        xor	ecx, edx
        rorx	edx, r13d, 22
        add	r12d, ebx
        xor	edx, ecx
        mov	ebx, r14d
        add	r8d, r12d
        xor	ebx, r13d
        and	eax, ebx
        add	r12d, edx
        xor	eax, r14d
        ; rnd_all_4: 3-6
        rorx	edx, r8d, 6
        rorx	ecx, r8d, 11
        add	r12d, eax
        add	r11d, DWORD PTR [rsp+48]
        mov	eax, r9d
        xor	ecx, edx
        xor	eax, r10d
        rorx	edx, r8d, 25
        xor	edx, ecx
        and	eax, r8d
        add	r11d, edx
        rorx	edx, r12d, 2
        rorx	ecx, r12d, 13
        xor	eax, r10d
        xor	ecx, edx
        rorx	edx, r12d, 22
        add	r11d, eax
        xor	edx, ecx
        mov	eax, r13d
        add	r15d, r11d
        xor	eax, r12d
        and	ebx, eax
        add	r11d, edx
        xor	ebx, r13d
        rorx	edx, r15d, 6
        rorx	ecx, r15d, 11
        add	r11d, ebx
        add	r10d, DWORD PTR [rsp+52]
        mov	ebx, r8d
        xor	ecx, edx
        xor	ebx, r9d
        rorx	edx, r15d, 25
        xor	edx, ecx
        and	ebx, r15d
        add	r10d, edx
        rorx	edx, r11d, 2
        rorx	ecx, r11d, 13
        xor	ebx, r9d
        xor	ecx, edx
        rorx	edx, r11d, 22
        add	r10d, ebx
        xor	edx, ecx
        mov	ebx, r12d
        add	r14d, r10d
        xor	ebx, r11d
        and	eax, ebx
        add	r10d, edx
        xor	eax, r12d
        rorx	edx, r14d, 6
        rorx	ecx, r14d, 11
        add	r10d, eax
        add	r9d, DWORD PTR [rsp+56]
        mov	eax, r15d
        xor	ecx, edx
        xor	eax, r8d
        rorx	edx, r14d, 25
        xor	edx, ecx
        and	eax, r14d
        add	r9d, edx
        rorx	edx, r10d, 2
        rorx	ecx, r10d, 13
        xor	eax, r8d
        xor	ecx, edx
        rorx	edx, r10d, 22
        add	r9d, eax
        xor	edx, ecx
        mov	eax, r11d
        add	r13d, r9d
        xor	eax, r10d
        and	ebx, eax
        add	r9d, edx
        xor	ebx, r11d
        rorx	edx, r13d, 6
        rorx	ecx, r13d, 11
        add	r9d, ebx
        add	r8d, DWORD PTR [rsp+60]
        mov	ebx, r14d
        xor	ecx, edx
        xor	ebx, r15d
        rorx	edx, r13d, 25
        xor	edx, ecx
        and	ebx, r13d
        add	r8d, edx
        rorx	edx, r9d, 2
        rorx	ecx, r9d, 13
        xor	ebx, r15d
        xor	ecx, edx
        rorx	edx, r9d, 22
        add	r8d, ebx
        xor	edx, ecx
        mov	ebx, r10d
        add	r12d, r8d
        xor	ebx, r9d
        and	eax, ebx
        add	r8d, edx
        xor	eax, r10d
        add	r8d, eax
        add	r8d, DWORD PTR [rdi]
        add	r9d, DWORD PTR [rdi+4]
        add	r10d, DWORD PTR [rdi+8]
        add	r11d, DWORD PTR [rdi+12]
        add	r12d, DWORD PTR [rdi+16]
        add	r13d, DWORD PTR [rdi+20]
        add	r14d, DWORD PTR [rdi+24]
        add	r15d, DWORD PTR [rdi+28]
        add	rsi, 64
        sub	DWORD PTR [rsp+64], 64
        mov	DWORD PTR [rdi], r8d
        mov	DWORD PTR [rdi+4], r9d
        mov	DWORD PTR [rdi+8], r10d
        mov	DWORD PTR [rdi+12], r11d
        mov	DWORD PTR [rdi+16], r12d
        mov	DWORD PTR [rdi+20], r13d
        mov	DWORD PTR [rdi+24], r14d
        mov	DWORD PTR [rdi+28], r15d
        jnz	L_sha256_len_avx1_len_rorx_start
        xor	rax, rax
        vmovdqu	xmm6, OWORD PTR [rsp+64]
        vmovdqu	xmm7, OWORD PTR [rsp+80]
        vmovdqu	xmm8, OWORD PTR [rsp+96]
        vmovdqu	xmm9, OWORD PTR [rsp+112]
        vmovdqu	xmm10, OWORD PTR [rsp+128]
        vmovdqu	xmm11, OWORD PTR [rsp+144]
        vmovdqu	xmm12, OWORD PTR [rsp+160]
        vmovdqu	xmm13, OWORD PTR [rsp+176]
        add	rsp, 196
        pop	rbp
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        pop	rbx
        ret
Transform_Sha256_AVX1_RORX_Len ENDP
_TEXT ENDS
_DATA SEGMENT
ALIGN 16
L_avx1_sha256_sha_k DWORD 428a2f98h, 71374491h, 0b5c0fbcfh, 0e9b5dba5h
        DWORD 3956c25bh, 59f111f1h, 923f82a4h, 0ab1c5ed5h
        DWORD 0d807aa98h, 12835b01h, 243185beh, 550c7dc3h
        DWORD 72be5d74h, 80deb1feh, 9bdc06a7h, 0c19bf174h
        DWORD 0e49b69c1h, 0efbe4786h, 0fc19dc6h, 240ca1cch
        DWORD 2de92c6fh, 4a7484aah, 5cb0a9dch, 76f988dah
        DWORD 983e5152h, 0a831c66dh, 0b00327c8h, 0bf597fc7h
        DWORD 0c6e00bf3h, 0d5a79147h, 06ca6351h, 14292967h
        DWORD 27b70a85h, 2e1b2138h, 4d2c6dfch, 53380d13h
        DWORD 650a7354h, 766a0abbh, 81c2c92eh, 92722c85h
        DWORD 0a2bfe8a1h, 0a81a664bh, 0c24b8b70h, 0c76c51a3h
        DWORD 0d192e819h, 0d6990624h, 0f40e3585h, 106aa070h
        DWORD 19a4c116h, 1e376c08h, 2748774ch, 34b0bcb5h
        DWORD 391c0cb3h, 4ed8aa4ah, 5b9cca4fh, 682e6ff3h
        DWORD 748f82eeh, 78a5636fh, 84c87814h, 8cc70208h
        DWORD 90befffah, 0a4506cebh, 0bef9a3f7h, 0c67178f2h
ptr_L_avx1_sha256_sha_k QWORD L_avx1_sha256_sha_k
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_avx1_sha256_shuf_mask QWORD 0405060700010203h, 0c0d0e0f08090a0bh
ptr_L_avx1_sha256_shuf_mask QWORD L_avx1_sha256_shuf_mask
_DATA ENDS
_TEXT SEGMENT READONLY PARA
Transform_Sha256_AVX1_Sha PROC
        sub	rsp, 80
        vmovdqu	OWORD PTR [rsp], xmm6
        vmovdqu	OWORD PTR [rsp+16], xmm7
        vmovdqu	OWORD PTR [rsp+32], xmm8
        vmovdqu	OWORD PTR [rsp+48], xmm9
        vmovdqu	OWORD PTR [rsp+64], xmm10
        mov	rax, QWORD PTR [ptr_L_avx1_sha256_sha_k]
        vmovdqa	xmm10, OWORD PTR L_avx1_sha256_shuf_mask
        vmovq	xmm1, QWORD PTR [rcx]
        vmovq	xmm2, QWORD PTR [rcx+8]
        vmovhpd	xmm1, xmm1, QWORD PTR [rcx+16]
        vmovhpd	xmm2, xmm2, QWORD PTR [rcx+24]
        vpshufd	xmm1, xmm1, 27
        vpshufd	xmm2, xmm2, 27
        vmovdqu	xmm3, OWORD PTR [rdx]
        vmovdqu	xmm4, OWORD PTR [rdx+16]
        vmovdqu	xmm5, OWORD PTR [rdx+32]
        vmovdqu	xmm6, OWORD PTR [rdx+48]
        vpshufb	xmm3, xmm3, xmm10
        vmovdqa	xmm8, xmm1
        vmovdqa	xmm9, xmm2
        ; Rounds: 0-3
        vpaddd	xmm0, xmm3, OWORD PTR [rax]
        sha256rnds2	xmm2, xmm1, xmm0
        vpshufd	xmm0, xmm0, 14
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 4-7
        vpshufb	xmm4, xmm4, xmm10
        vpaddd	xmm0, xmm4, OWORD PTR [rax+16]
        sha256rnds2	xmm2, xmm1, xmm0
        vpshufd	xmm0, xmm0, 14
        sha256msg1	xmm3, xmm4
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 8-11
        vpshufb	xmm5, xmm5, xmm10
        vpaddd	xmm0, xmm5, OWORD PTR [rax+32]
        sha256rnds2	xmm2, xmm1, xmm0
        vpshufd	xmm0, xmm0, 14
        sha256msg1	xmm4, xmm5
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 12-15
        vpshufb	xmm6, xmm6, xmm10
        vpaddd	xmm0, xmm6, OWORD PTR [rax+48]
        sha256rnds2	xmm2, xmm1, xmm0
        vpalignr	xmm7, xmm6, xmm5, 4
        vpaddd	xmm3, xmm3, xmm7
        sha256msg2	xmm3, xmm6
        vpshufd	xmm0, xmm0, 14
        sha256msg1	xmm5, xmm6
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 16-19
        vpaddd	xmm0, xmm3, OWORD PTR [rax+64]
        sha256rnds2	xmm2, xmm1, xmm0
        vpalignr	xmm7, xmm3, xmm6, 4
        vpaddd	xmm4, xmm4, xmm7
        sha256msg2	xmm4, xmm3
        vpshufd	xmm0, xmm0, 14
        sha256msg1	xmm6, xmm3
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 20-23
        vpaddd	xmm0, xmm4, OWORD PTR [rax+80]
        sha256rnds2	xmm2, xmm1, xmm0
        vpalignr	xmm7, xmm4, xmm3, 4
        vpaddd	xmm5, xmm5, xmm7
        sha256msg2	xmm5, xmm4
        vpshufd	xmm0, xmm0, 14
        sha256msg1	xmm3, xmm4
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 24-27
        vpaddd	xmm0, xmm5, OWORD PTR [rax+96]
        sha256rnds2	xmm2, xmm1, xmm0
        vpalignr	xmm7, xmm5, xmm4, 4
        vpaddd	xmm6, xmm6, xmm7
        sha256msg2	xmm6, xmm5
        vpshufd	xmm0, xmm0, 14
        sha256msg1	xmm4, xmm5
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 28-31
        vpaddd	xmm0, xmm6, OWORD PTR [rax+112]
        sha256rnds2	xmm2, xmm1, xmm0
        vpalignr	xmm7, xmm6, xmm5, 4
        vpaddd	xmm3, xmm3, xmm7
        sha256msg2	xmm3, xmm6
        vpshufd	xmm0, xmm0, 14
        sha256msg1	xmm5, xmm6
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 32-35
        vpaddd	xmm0, xmm3, OWORD PTR [rax+128]
        sha256rnds2	xmm2, xmm1, xmm0
        vpalignr	xmm7, xmm3, xmm6, 4
        vpaddd	xmm4, xmm4, xmm7
        sha256msg2	xmm4, xmm3
        vpshufd	xmm0, xmm0, 14
        sha256msg1	xmm6, xmm3
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 36-39
        vpaddd	xmm0, xmm4, OWORD PTR [rax+144]
        sha256rnds2	xmm2, xmm1, xmm0
        vpalignr	xmm7, xmm4, xmm3, 4
        vpaddd	xmm5, xmm5, xmm7
        sha256msg2	xmm5, xmm4
        vpshufd	xmm0, xmm0, 14
        sha256msg1	xmm3, xmm4
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 40-43
        vpaddd	xmm0, xmm5, OWORD PTR [rax+160]
        sha256rnds2	xmm2, xmm1, xmm0
        vpalignr	xmm7, xmm5, xmm4, 4
        vpaddd	xmm6, xmm6, xmm7
        sha256msg2	xmm6, xmm5
        vpshufd	xmm0, xmm0, 14
        sha256msg1	xmm4, xmm5
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 44-47
        vpaddd	xmm0, xmm6, OWORD PTR [rax+176]
        sha256rnds2	xmm2, xmm1, xmm0
        vpalignr	xmm7, xmm6, xmm5, 4
        vpaddd	xmm3, xmm3, xmm7
        sha256msg2	xmm3, xmm6
        vpshufd	xmm0, xmm0, 14
        sha256msg1	xmm5, xmm6
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 48-51
        vpaddd	xmm0, xmm3, OWORD PTR [rax+192]
        sha256rnds2	xmm2, xmm1, xmm0
        vpalignr	xmm7, xmm3, xmm6, 4
        vpaddd	xmm4, xmm4, xmm7
        sha256msg2	xmm4, xmm3
        vpshufd	xmm0, xmm0, 14
        sha256msg1	xmm6, xmm3
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 52-63
        vpaddd	xmm0, xmm4, OWORD PTR [rax+208]
        sha256rnds2	xmm2, xmm1, xmm0
        vpalignr	xmm7, xmm4, xmm3, 4
        vpaddd	xmm5, xmm5, xmm7
        sha256msg2	xmm5, xmm4
        vpshufd	xmm0, xmm0, 14
        sha256rnds2	xmm1, xmm2, xmm0
        vpaddd	xmm0, xmm5, OWORD PTR [rax+224]
        sha256rnds2	xmm2, xmm1, xmm0
        vpalignr	xmm7, xmm5, xmm4, 4
        vpaddd	xmm6, xmm6, xmm7
        sha256msg2	xmm6, xmm5
        vpshufd	xmm0, xmm0, 14
        sha256rnds2	xmm1, xmm2, xmm0
        vpaddd	xmm0, xmm6, OWORD PTR [rax+240]
        sha256rnds2	xmm2, xmm1, xmm0
        vpshufd	xmm0, xmm0, 14
        sha256rnds2	xmm1, xmm2, xmm0
        vpaddd	xmm1, xmm1, xmm8
        vpaddd	xmm2, xmm2, xmm9
        vpshufd	xmm1, xmm1, 27
        vpshufd	xmm2, xmm2, 27
        vmovq	QWORD PTR [rcx], xmm1
        vmovq	QWORD PTR [rcx+8], xmm2
        vmovhpd	QWORD PTR [rcx+16], xmm1
        vmovhpd	QWORD PTR [rcx+24], xmm2
        xor	rax, rax
        vmovdqu	xmm6, OWORD PTR [rsp]
        vmovdqu	xmm7, OWORD PTR [rsp+16]
        vmovdqu	xmm8, OWORD PTR [rsp+32]
        vmovdqu	xmm9, OWORD PTR [rsp+48]
        vmovdqu	xmm10, OWORD PTR [rsp+64]
        add	rsp, 80
        ret
Transform_Sha256_AVX1_Sha ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
Transform_Sha256_AVX1_Sha_Len PROC
        sub	rsp, 80
        vmovdqu	OWORD PTR [rsp], xmm6
        vmovdqu	OWORD PTR [rsp+16], xmm7
        vmovdqu	OWORD PTR [rsp+32], xmm8
        vmovdqu	OWORD PTR [rsp+48], xmm9
        vmovdqu	OWORD PTR [rsp+64], xmm10
        mov	rax, QWORD PTR [ptr_L_avx1_sha256_sha_k]
        vmovdqa	xmm10, OWORD PTR L_avx1_sha256_shuf_mask
        vmovq	xmm1, QWORD PTR [rcx]
        vmovq	xmm2, QWORD PTR [rcx+8]
        vmovhpd	xmm1, xmm1, QWORD PTR [rcx+16]
        vmovhpd	xmm2, xmm2, QWORD PTR [rcx+24]
        vpshufd	xmm1, xmm1, 27
        vpshufd	xmm2, xmm2, 27
        ; Start of loop processing a block
L_sha256_sha_len_avx1_start:
        vmovdqu	xmm3, OWORD PTR [rdx]
        vmovdqu	xmm4, OWORD PTR [rdx+16]
        vmovdqu	xmm5, OWORD PTR [rdx+32]
        vmovdqu	xmm6, OWORD PTR [rdx+48]
        vpshufb	xmm3, xmm3, xmm10
        vmovdqa	xmm8, xmm1
        vmovdqa	xmm9, xmm2
        ; Rounds: 0-3
        vpaddd	xmm0, xmm3, OWORD PTR [rax]
        sha256rnds2	xmm2, xmm1, xmm0
        vpshufd	xmm0, xmm0, 14
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 4-7
        vpshufb	xmm4, xmm4, xmm10
        vpaddd	xmm0, xmm4, OWORD PTR [rax+16]
        sha256rnds2	xmm2, xmm1, xmm0
        vpshufd	xmm0, xmm0, 14
        sha256msg1	xmm3, xmm4
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 8-11
        vpshufb	xmm5, xmm5, xmm10
        vpaddd	xmm0, xmm5, OWORD PTR [rax+32]
        sha256rnds2	xmm2, xmm1, xmm0
        vpshufd	xmm0, xmm0, 14
        sha256msg1	xmm4, xmm5
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 12-15
        vpshufb	xmm6, xmm6, xmm10
        vpaddd	xmm0, xmm6, OWORD PTR [rax+48]
        sha256rnds2	xmm2, xmm1, xmm0
        vpalignr	xmm7, xmm6, xmm5, 4
        vpaddd	xmm3, xmm3, xmm7
        sha256msg2	xmm3, xmm6
        vpshufd	xmm0, xmm0, 14
        sha256msg1	xmm5, xmm6
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 16-19
        vpaddd	xmm0, xmm3, OWORD PTR [rax+64]
        sha256rnds2	xmm2, xmm1, xmm0
        vpalignr	xmm7, xmm3, xmm6, 4
        vpaddd	xmm4, xmm4, xmm7
        sha256msg2	xmm4, xmm3
        vpshufd	xmm0, xmm0, 14
        sha256msg1	xmm6, xmm3
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 20-23
        vpaddd	xmm0, xmm4, OWORD PTR [rax+80]
        sha256rnds2	xmm2, xmm1, xmm0
        vpalignr	xmm7, xmm4, xmm3, 4
        vpaddd	xmm5, xmm5, xmm7
        sha256msg2	xmm5, xmm4
        vpshufd	xmm0, xmm0, 14
        sha256msg1	xmm3, xmm4
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 24-27
        vpaddd	xmm0, xmm5, OWORD PTR [rax+96]
        sha256rnds2	xmm2, xmm1, xmm0
        vpalignr	xmm7, xmm5, xmm4, 4
        vpaddd	xmm6, xmm6, xmm7
        sha256msg2	xmm6, xmm5
        vpshufd	xmm0, xmm0, 14
        sha256msg1	xmm4, xmm5
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 28-31
        vpaddd	xmm0, xmm6, OWORD PTR [rax+112]
        sha256rnds2	xmm2, xmm1, xmm0
        vpalignr	xmm7, xmm6, xmm5, 4
        vpaddd	xmm3, xmm3, xmm7
        sha256msg2	xmm3, xmm6
        vpshufd	xmm0, xmm0, 14
        sha256msg1	xmm5, xmm6
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 32-35
        vpaddd	xmm0, xmm3, OWORD PTR [rax+128]
        sha256rnds2	xmm2, xmm1, xmm0
        vpalignr	xmm7, xmm3, xmm6, 4
        vpaddd	xmm4, xmm4, xmm7
        sha256msg2	xmm4, xmm3
        vpshufd	xmm0, xmm0, 14
        sha256msg1	xmm6, xmm3
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 36-39
        vpaddd	xmm0, xmm4, OWORD PTR [rax+144]
        sha256rnds2	xmm2, xmm1, xmm0
        vpalignr	xmm7, xmm4, xmm3, 4
        vpaddd	xmm5, xmm5, xmm7
        sha256msg2	xmm5, xmm4
        vpshufd	xmm0, xmm0, 14
        sha256msg1	xmm3, xmm4
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 40-43
        vpaddd	xmm0, xmm5, OWORD PTR [rax+160]
        sha256rnds2	xmm2, xmm1, xmm0
        vpalignr	xmm7, xmm5, xmm4, 4
        vpaddd	xmm6, xmm6, xmm7
        sha256msg2	xmm6, xmm5
        vpshufd	xmm0, xmm0, 14
        sha256msg1	xmm4, xmm5
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 44-47
        vpaddd	xmm0, xmm6, OWORD PTR [rax+176]
        sha256rnds2	xmm2, xmm1, xmm0
        vpalignr	xmm7, xmm6, xmm5, 4
        vpaddd	xmm3, xmm3, xmm7
        sha256msg2	xmm3, xmm6
        vpshufd	xmm0, xmm0, 14
        sha256msg1	xmm5, xmm6
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 48-51
        vpaddd	xmm0, xmm3, OWORD PTR [rax+192]
        sha256rnds2	xmm2, xmm1, xmm0
        vpalignr	xmm7, xmm3, xmm6, 4
        vpaddd	xmm4, xmm4, xmm7
        sha256msg2	xmm4, xmm3
        vpshufd	xmm0, xmm0, 14
        sha256msg1	xmm6, xmm3
        sha256rnds2	xmm1, xmm2, xmm0
        ; Rounds: 52-63
        vpaddd	xmm0, xmm4, OWORD PTR [rax+208]
        sha256rnds2	xmm2, xmm1, xmm0
        vpalignr	xmm7, xmm4, xmm3, 4
        vpaddd	xmm5, xmm5, xmm7
        sha256msg2	xmm5, xmm4
        vpshufd	xmm0, xmm0, 14
        sha256rnds2	xmm1, xmm2, xmm0
        vpaddd	xmm0, xmm5, OWORD PTR [rax+224]
        sha256rnds2	xmm2, xmm1, xmm0
        vpalignr	xmm7, xmm5, xmm4, 4
        vpaddd	xmm6, xmm6, xmm7
        sha256msg2	xmm6, xmm5
        vpshufd	xmm0, xmm0, 14
        sha256rnds2	xmm1, xmm2, xmm0
        vpaddd	xmm0, xmm6, OWORD PTR [rax+240]
        sha256rnds2	xmm2, xmm1, xmm0
        vpshufd	xmm0, xmm0, 14
        sha256rnds2	xmm1, xmm2, xmm0
        add	rdx, 64
        sub	r8d, 64
        vpaddd	xmm1, xmm1, xmm8
        vpaddd	xmm2, xmm2, xmm9
        jnz	L_sha256_sha_len_avx1_start
        vpshufd	xmm1, xmm1, 27
        vpshufd	xmm2, xmm2, 27
        vmovq	QWORD PTR [rcx], xmm1
        vmovq	QWORD PTR [rcx+8], xmm2
        vmovhpd	QWORD PTR [rcx+16], xmm1
        vmovhpd	QWORD PTR [rcx+24], xmm2
        xor	rax, rax
        vmovdqu	xmm6, OWORD PTR [rsp]
        vmovdqu	xmm7, OWORD PTR [rsp+16]
        vmovdqu	xmm8, OWORD PTR [rsp+32]
        vmovdqu	xmm9, OWORD PTR [rsp+48]
        vmovdqu	xmm10, OWORD PTR [rsp+64]
        add	rsp, 80
        ret
Transform_Sha256_AVX1_Sha_Len ENDP
_TEXT ENDS
ENDIF
IFDEF HAVE_INTEL_AVX2
_DATA SEGMENT
ALIGN 16
L_avx2_sha256_k DWORD 428a2f98h, 71374491h, 0b5c0fbcfh, 0e9b5dba5h
        DWORD 428a2f98h, 71374491h, 0b5c0fbcfh, 0e9b5dba5h
        DWORD 3956c25bh, 59f111f1h, 923f82a4h, 0ab1c5ed5h
        DWORD 3956c25bh, 59f111f1h, 923f82a4h, 0ab1c5ed5h
        DWORD 0d807aa98h, 12835b01h, 243185beh, 550c7dc3h
        DWORD 0d807aa98h, 12835b01h, 243185beh, 550c7dc3h
        DWORD 72be5d74h, 80deb1feh, 9bdc06a7h, 0c19bf174h
        DWORD 72be5d74h, 80deb1feh, 9bdc06a7h, 0c19bf174h
        DWORD 0e49b69c1h, 0efbe4786h, 0fc19dc6h, 240ca1cch
        DWORD 0e49b69c1h, 0efbe4786h, 0fc19dc6h, 240ca1cch
        DWORD 2de92c6fh, 4a7484aah, 5cb0a9dch, 76f988dah
        DWORD 2de92c6fh, 4a7484aah, 5cb0a9dch, 76f988dah
        DWORD 983e5152h, 0a831c66dh, 0b00327c8h, 0bf597fc7h
        DWORD 983e5152h, 0a831c66dh, 0b00327c8h, 0bf597fc7h
        DWORD 0c6e00bf3h, 0d5a79147h, 06ca6351h, 14292967h
        DWORD 0c6e00bf3h, 0d5a79147h, 06ca6351h, 14292967h
        DWORD 27b70a85h, 2e1b2138h, 4d2c6dfch, 53380d13h
        DWORD 27b70a85h, 2e1b2138h, 4d2c6dfch, 53380d13h
        DWORD 650a7354h, 766a0abbh, 81c2c92eh, 92722c85h
        DWORD 650a7354h, 766a0abbh, 81c2c92eh, 92722c85h
        DWORD 0a2bfe8a1h, 0a81a664bh, 0c24b8b70h, 0c76c51a3h
        DWORD 0a2bfe8a1h, 0a81a664bh, 0c24b8b70h, 0c76c51a3h
        DWORD 0d192e819h, 0d6990624h, 0f40e3585h, 106aa070h
        DWORD 0d192e819h, 0d6990624h, 0f40e3585h, 106aa070h
        DWORD 19a4c116h, 1e376c08h, 2748774ch, 34b0bcb5h
        DWORD 19a4c116h, 1e376c08h, 2748774ch, 34b0bcb5h
        DWORD 391c0cb3h, 4ed8aa4ah, 5b9cca4fh, 682e6ff3h
        DWORD 391c0cb3h, 4ed8aa4ah, 5b9cca4fh, 682e6ff3h
        DWORD 748f82eeh, 78a5636fh, 84c87814h, 8cc70208h
        DWORD 748f82eeh, 78a5636fh, 84c87814h, 8cc70208h
        DWORD 90befffah, 0a4506cebh, 0bef9a3f7h, 0c67178f2h
        DWORD 90befffah, 0a4506cebh, 0bef9a3f7h, 0c67178f2h
ptr_L_avx2_sha256_k QWORD L_avx2_sha256_k
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_avx2_sha256_shuf_00BA QWORD 0b0a090803020100h, 0ffffffffffffffffh
        QWORD 0b0a090803020100h, 0ffffffffffffffffh
ptr_L_avx2_sha256_shuf_00BA QWORD L_avx2_sha256_shuf_00BA
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_avx2_sha256_shuf_DC00 QWORD 0ffffffffffffffffh, 0b0a090803020100h
        QWORD 0ffffffffffffffffh, 0b0a090803020100h
ptr_L_avx2_sha256_shuf_DC00 QWORD L_avx2_sha256_shuf_DC00
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_avx2_sha256_flip_mask QWORD 0405060700010203h, 0c0d0e0f08090a0bh
        QWORD 0405060700010203h, 0c0d0e0f08090a0bh
ptr_L_avx2_sha256_flip_mask QWORD L_avx2_sha256_flip_mask
_DATA ENDS
_TEXT SEGMENT READONLY PARA
Transform_Sha256_AVX2 PROC
        push	rbx
        push	r12
        push	r13
        push	r14
        push	r15
        push	rbp
        push	rdi
        push	rsi
        mov	rdi, rcx
        mov	rsi, rdx
        sub	rsp, 640
        vmovdqu	OWORD PTR [rsp+512], xmm6
        vmovdqu	OWORD PTR [rsp+528], xmm7
        vmovdqu	OWORD PTR [rsp+544], xmm8
        vmovdqu	OWORD PTR [rsp+560], xmm9
        vmovdqu	OWORD PTR [rsp+576], xmm10
        vmovdqu	OWORD PTR [rsp+592], xmm11
        vmovdqu	OWORD PTR [rsp+608], xmm12
        vmovdqu	OWORD PTR [rsp+624], xmm13
        mov	rbp, QWORD PTR [ptr_L_avx2_sha256_k]
        vmovdqa	xmm13, OWORD PTR L_avx2_sha256_flip_mask
        vmovdqu	ymm11, YMMWORD PTR L_avx2_sha256_shuf_00BA
        vmovdqu	ymm12, YMMWORD PTR L_avx2_sha256_shuf_DC00
        mov	r8d, DWORD PTR [rdi]
        mov	r9d, DWORD PTR [rdi+4]
        mov	r10d, DWORD PTR [rdi+8]
        mov	r11d, DWORD PTR [rdi+12]
        mov	r12d, DWORD PTR [rdi+16]
        mov	r13d, DWORD PTR [rdi+20]
        mov	r14d, DWORD PTR [rdi+24]
        mov	r15d, DWORD PTR [rdi+28]
        ; X0, X1, X2, X3 = W[0..15]
        vmovdqu	xmm0, OWORD PTR [rsi]
        vmovdqu	xmm1, OWORD PTR [rsi+16]
        vpshufb	xmm0, xmm0, xmm13
        vpshufb	xmm1, xmm1, xmm13
        vmovdqu	xmm2, OWORD PTR [rsi+32]
        vmovdqu	xmm3, OWORD PTR [rsi+48]
        vpshufb	xmm2, xmm2, xmm13
        vpshufb	xmm3, xmm3, xmm13
        mov	ebx, r9d
        mov	edx, r12d
        xor	ebx, r10d
        ; set_w_k_xfer_4: 0
        vpaddd	ymm4, ymm0, YMMWORD PTR [rbp]
        vpaddd	ymm5, ymm1, YMMWORD PTR [rbp+32]
        vmovdqu	YMMWORD PTR [rsp], ymm4
        vmovdqu	YMMWORD PTR [rsp+32], ymm5
        vpaddd	ymm4, ymm2, YMMWORD PTR [rbp+64]
        vpaddd	ymm5, ymm3, YMMWORD PTR [rbp+96]
        vmovdqu	YMMWORD PTR [rsp+64], ymm4
        vmovdqu	YMMWORD PTR [rsp+96], ymm5
        ; msg_sched: 0-3
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	ymm5, ymm1, ymm0, 4
        vpalignr	ymm4, ymm3, ymm2, 4
        ; rnd_0: 1 - 2
        mov	eax, r9d
        mov	ecx, r13d
        add	r15d, DWORD PTR [rsp]
        xor	ecx, r14d
        xor	edx, r12d
        and	ecx, r12d
        vpsrld	ymm6, ymm5, 7
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r14d
        xor	edx, r12d
        add	r15d, ecx
        ror	edx, 6
        xor	eax, r8d
        add	r15d, edx
        mov	ecx, r8d
        vpsrld	ymm8, ymm5, 18
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r8d
        xor	ebx, r9d
        ror	ecx, 11
        add	r11d, r15d
        xor	ecx, r8d
        add	r15d, ebx
        vpor	ymm6, ymm7, ymm6
        vpor	ymm8, ymm9, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r11d
        add	r15d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r8d
        mov	ecx, r12d
        add	r14d, DWORD PTR [rsp+4]
        xor	ecx, r13d
        vpsrld	ymm9, ymm5, 3
        vpxor	ymm6, ymm8, ymm6
        ; rnd_1: 2 - 3
        xor	edx, r11d
        and	ecx, r11d
        ror	edx, 5
        xor	ecx, r13d
        xor	edx, r11d
        add	r14d, ecx
        vpxor	ymm5, ymm9, ymm6
        vpshufd	ymm6, ymm3, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r15d
        add	r14d, edx
        mov	ecx, r15d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r15d
        xor	eax, r8d
        vpsrld	ymm8, ymm6, 10
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r10d, r14d
        xor	ecx, r15d
        add	r14d, eax
        ror	ecx, 2
        mov	edx, r10d
        add	r14d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	ymm6, ymm6, 17
        vpaddd	ymm4, ymm4, ymm0
        ; rnd_0: 1 - 3
        mov	eax, r15d
        mov	ecx, r11d
        add	r13d, DWORD PTR [rsp+8]
        xor	ecx, r12d
        xor	edx, r10d
        and	ecx, r10d
        ror	edx, 5
        xor	ecx, r12d
        xor	edx, r10d
        add	r13d, ecx
        vpxor	ymm6, ymm7, ymm6
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r14d
        add	r13d, edx
        mov	ecx, r14d
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r14d
        xor	ebx, r15d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r9d, r13d
        xor	ecx, r14d
        add	r13d, ebx
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r9d
        add	r13d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	ymm6, ymm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r14d
        mov	ecx, r10d
        add	r12d, DWORD PTR [rsp+12]
        xor	ecx, r11d
        vpsrlq	ymm8, ymm6, 17
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r9d
        and	ecx, r9d
        ror	edx, 5
        xor	ecx, r11d
        xor	edx, r9d
        add	r12d, ecx
        vpsrld	ymm9, ymm6, 10
        vpxor	ymm8, ymm7, ymm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r13d
        add	r12d, edx
        mov	ecx, r13d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r13d
        xor	eax, r14d
        vpxor	ymm9, ymm8, ymm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r8d, r12d
        xor	ecx, r13d
        add	r12d, eax
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r8d
        add	r12d, ecx
        vpaddd	ymm0, ymm9, ymm4
        ; msg_sched done: 0-3
        ; msg_sched: 8-11
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	ymm5, ymm2, ymm1, 4
        vpalignr	ymm4, ymm0, ymm3, 4
        ; rnd_0: 1 - 2
        mov	eax, r13d
        mov	ecx, r9d
        add	r11d, DWORD PTR [rsp+32]
        xor	ecx, r10d
        xor	edx, r8d
        and	ecx, r8d
        vpsrld	ymm6, ymm5, 7
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r10d
        xor	edx, r8d
        add	r11d, ecx
        ror	edx, 6
        xor	eax, r12d
        add	r11d, edx
        mov	ecx, r12d
        vpsrld	ymm8, ymm5, 18
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r12d
        xor	ebx, r13d
        ror	ecx, 11
        add	r15d, r11d
        xor	ecx, r12d
        add	r11d, ebx
        vpor	ymm6, ymm7, ymm6
        vpor	ymm8, ymm9, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r15d
        add	r11d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r12d
        mov	ecx, r8d
        add	r10d, DWORD PTR [rsp+36]
        xor	ecx, r9d
        vpsrld	ymm9, ymm5, 3
        vpxor	ymm6, ymm8, ymm6
        ; rnd_1: 2 - 3
        xor	edx, r15d
        and	ecx, r15d
        ror	edx, 5
        xor	ecx, r9d
        xor	edx, r15d
        add	r10d, ecx
        vpxor	ymm5, ymm9, ymm6
        vpshufd	ymm6, ymm0, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r11d
        add	r10d, edx
        mov	ecx, r11d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r11d
        xor	eax, r12d
        vpsrld	ymm8, ymm6, 10
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r14d, r10d
        xor	ecx, r11d
        add	r10d, eax
        ror	ecx, 2
        mov	edx, r14d
        add	r10d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	ymm6, ymm6, 17
        vpaddd	ymm4, ymm4, ymm1
        ; rnd_0: 1 - 3
        mov	eax, r11d
        mov	ecx, r15d
        add	r9d, DWORD PTR [rsp+40]
        xor	ecx, r8d
        xor	edx, r14d
        and	ecx, r14d
        ror	edx, 5
        xor	ecx, r8d
        xor	edx, r14d
        add	r9d, ecx
        vpxor	ymm6, ymm7, ymm6
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r10d
        add	r9d, edx
        mov	ecx, r10d
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r10d
        xor	ebx, r11d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r13d, r9d
        xor	ecx, r10d
        add	r9d, ebx
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r13d
        add	r9d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	ymm6, ymm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r10d
        mov	ecx, r14d
        add	r8d, DWORD PTR [rsp+44]
        xor	ecx, r15d
        vpsrlq	ymm8, ymm6, 17
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r13d
        and	ecx, r13d
        ror	edx, 5
        xor	ecx, r15d
        xor	edx, r13d
        add	r8d, ecx
        vpsrld	ymm9, ymm6, 10
        vpxor	ymm8, ymm7, ymm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r9d
        add	r8d, edx
        mov	ecx, r9d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r9d
        xor	eax, r10d
        vpxor	ymm9, ymm8, ymm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r12d, r8d
        xor	ecx, r9d
        add	r8d, eax
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r12d
        add	r8d, ecx
        vpaddd	ymm1, ymm9, ymm4
        ; msg_sched done: 8-11
        ; msg_sched: 16-19
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	ymm5, ymm3, ymm2, 4
        vpalignr	ymm4, ymm1, ymm0, 4
        ; rnd_0: 1 - 2
        mov	eax, r9d
        mov	ecx, r13d
        add	r15d, DWORD PTR [rsp+64]
        xor	ecx, r14d
        xor	edx, r12d
        and	ecx, r12d
        vpsrld	ymm6, ymm5, 7
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r14d
        xor	edx, r12d
        add	r15d, ecx
        ror	edx, 6
        xor	eax, r8d
        add	r15d, edx
        mov	ecx, r8d
        vpsrld	ymm8, ymm5, 18
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r8d
        xor	ebx, r9d
        ror	ecx, 11
        add	r11d, r15d
        xor	ecx, r8d
        add	r15d, ebx
        vpor	ymm6, ymm7, ymm6
        vpor	ymm8, ymm9, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r11d
        add	r15d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r8d
        mov	ecx, r12d
        add	r14d, DWORD PTR [rsp+68]
        xor	ecx, r13d
        vpsrld	ymm9, ymm5, 3
        vpxor	ymm6, ymm8, ymm6
        ; rnd_1: 2 - 3
        xor	edx, r11d
        and	ecx, r11d
        ror	edx, 5
        xor	ecx, r13d
        xor	edx, r11d
        add	r14d, ecx
        vpxor	ymm5, ymm9, ymm6
        vpshufd	ymm6, ymm1, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r15d
        add	r14d, edx
        mov	ecx, r15d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r15d
        xor	eax, r8d
        vpsrld	ymm8, ymm6, 10
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r10d, r14d
        xor	ecx, r15d
        add	r14d, eax
        ror	ecx, 2
        mov	edx, r10d
        add	r14d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	ymm6, ymm6, 17
        vpaddd	ymm4, ymm4, ymm2
        ; rnd_0: 1 - 3
        mov	eax, r15d
        mov	ecx, r11d
        add	r13d, DWORD PTR [rsp+72]
        xor	ecx, r12d
        xor	edx, r10d
        and	ecx, r10d
        ror	edx, 5
        xor	ecx, r12d
        xor	edx, r10d
        add	r13d, ecx
        vpxor	ymm6, ymm7, ymm6
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r14d
        add	r13d, edx
        mov	ecx, r14d
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r14d
        xor	ebx, r15d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r9d, r13d
        xor	ecx, r14d
        add	r13d, ebx
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r9d
        add	r13d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	ymm6, ymm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r14d
        mov	ecx, r10d
        add	r12d, DWORD PTR [rsp+76]
        xor	ecx, r11d
        vpsrlq	ymm8, ymm6, 17
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r9d
        and	ecx, r9d
        ror	edx, 5
        xor	ecx, r11d
        xor	edx, r9d
        add	r12d, ecx
        vpsrld	ymm9, ymm6, 10
        vpxor	ymm8, ymm7, ymm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r13d
        add	r12d, edx
        mov	ecx, r13d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r13d
        xor	eax, r14d
        vpxor	ymm9, ymm8, ymm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r8d, r12d
        xor	ecx, r13d
        add	r12d, eax
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r8d
        add	r12d, ecx
        vpaddd	ymm2, ymm9, ymm4
        ; msg_sched done: 16-19
        ; msg_sched: 24-27
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	ymm5, ymm0, ymm3, 4
        vpalignr	ymm4, ymm2, ymm1, 4
        ; rnd_0: 1 - 2
        mov	eax, r13d
        mov	ecx, r9d
        add	r11d, DWORD PTR [rsp+96]
        xor	ecx, r10d
        xor	edx, r8d
        and	ecx, r8d
        vpsrld	ymm6, ymm5, 7
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r10d
        xor	edx, r8d
        add	r11d, ecx
        ror	edx, 6
        xor	eax, r12d
        add	r11d, edx
        mov	ecx, r12d
        vpsrld	ymm8, ymm5, 18
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r12d
        xor	ebx, r13d
        ror	ecx, 11
        add	r15d, r11d
        xor	ecx, r12d
        add	r11d, ebx
        vpor	ymm6, ymm7, ymm6
        vpor	ymm8, ymm9, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r15d
        add	r11d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r12d
        mov	ecx, r8d
        add	r10d, DWORD PTR [rsp+100]
        xor	ecx, r9d
        vpsrld	ymm9, ymm5, 3
        vpxor	ymm6, ymm8, ymm6
        ; rnd_1: 2 - 3
        xor	edx, r15d
        and	ecx, r15d
        ror	edx, 5
        xor	ecx, r9d
        xor	edx, r15d
        add	r10d, ecx
        vpxor	ymm5, ymm9, ymm6
        vpshufd	ymm6, ymm2, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r11d
        add	r10d, edx
        mov	ecx, r11d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r11d
        xor	eax, r12d
        vpsrld	ymm8, ymm6, 10
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r14d, r10d
        xor	ecx, r11d
        add	r10d, eax
        ror	ecx, 2
        mov	edx, r14d
        add	r10d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	ymm6, ymm6, 17
        vpaddd	ymm4, ymm4, ymm3
        ; rnd_0: 1 - 3
        mov	eax, r11d
        mov	ecx, r15d
        add	r9d, DWORD PTR [rsp+104]
        xor	ecx, r8d
        xor	edx, r14d
        and	ecx, r14d
        ror	edx, 5
        xor	ecx, r8d
        xor	edx, r14d
        add	r9d, ecx
        vpxor	ymm6, ymm7, ymm6
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r10d
        add	r9d, edx
        mov	ecx, r10d
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r10d
        xor	ebx, r11d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r13d, r9d
        xor	ecx, r10d
        add	r9d, ebx
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r13d
        add	r9d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	ymm6, ymm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r10d
        mov	ecx, r14d
        add	r8d, DWORD PTR [rsp+108]
        xor	ecx, r15d
        vpsrlq	ymm8, ymm6, 17
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r13d
        and	ecx, r13d
        ror	edx, 5
        xor	ecx, r15d
        xor	edx, r13d
        add	r8d, ecx
        vpsrld	ymm9, ymm6, 10
        vpxor	ymm8, ymm7, ymm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r9d
        add	r8d, edx
        mov	ecx, r9d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r9d
        xor	eax, r10d
        vpxor	ymm9, ymm8, ymm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r12d, r8d
        xor	ecx, r9d
        add	r8d, eax
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r12d
        add	r8d, ecx
        vpaddd	ymm3, ymm9, ymm4
        ; msg_sched done: 24-27
        ; set_w_k_xfer_4: 4
        vpaddd	ymm4, ymm0, YMMWORD PTR [rbp+128]
        vpaddd	ymm5, ymm1, YMMWORD PTR [rbp+160]
        vmovdqu	YMMWORD PTR [rsp+128], ymm4
        vmovdqu	YMMWORD PTR [rsp+160], ymm5
        vpaddd	ymm4, ymm2, YMMWORD PTR [rbp+192]
        vpaddd	ymm5, ymm3, YMMWORD PTR [rbp+224]
        vmovdqu	YMMWORD PTR [rsp+192], ymm4
        vmovdqu	YMMWORD PTR [rsp+224], ymm5
        ; msg_sched: 32-35
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	ymm5, ymm1, ymm0, 4
        vpalignr	ymm4, ymm3, ymm2, 4
        ; rnd_0: 1 - 2
        mov	eax, r9d
        mov	ecx, r13d
        add	r15d, DWORD PTR [rsp+128]
        xor	ecx, r14d
        xor	edx, r12d
        and	ecx, r12d
        vpsrld	ymm6, ymm5, 7
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r14d
        xor	edx, r12d
        add	r15d, ecx
        ror	edx, 6
        xor	eax, r8d
        add	r15d, edx
        mov	ecx, r8d
        vpsrld	ymm8, ymm5, 18
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r8d
        xor	ebx, r9d
        ror	ecx, 11
        add	r11d, r15d
        xor	ecx, r8d
        add	r15d, ebx
        vpor	ymm6, ymm7, ymm6
        vpor	ymm8, ymm9, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r11d
        add	r15d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r8d
        mov	ecx, r12d
        add	r14d, DWORD PTR [rsp+132]
        xor	ecx, r13d
        vpsrld	ymm9, ymm5, 3
        vpxor	ymm6, ymm8, ymm6
        ; rnd_1: 2 - 3
        xor	edx, r11d
        and	ecx, r11d
        ror	edx, 5
        xor	ecx, r13d
        xor	edx, r11d
        add	r14d, ecx
        vpxor	ymm5, ymm9, ymm6
        vpshufd	ymm6, ymm3, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r15d
        add	r14d, edx
        mov	ecx, r15d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r15d
        xor	eax, r8d
        vpsrld	ymm8, ymm6, 10
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r10d, r14d
        xor	ecx, r15d
        add	r14d, eax
        ror	ecx, 2
        mov	edx, r10d
        add	r14d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	ymm6, ymm6, 17
        vpaddd	ymm4, ymm4, ymm0
        ; rnd_0: 1 - 3
        mov	eax, r15d
        mov	ecx, r11d
        add	r13d, DWORD PTR [rsp+136]
        xor	ecx, r12d
        xor	edx, r10d
        and	ecx, r10d
        ror	edx, 5
        xor	ecx, r12d
        xor	edx, r10d
        add	r13d, ecx
        vpxor	ymm6, ymm7, ymm6
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r14d
        add	r13d, edx
        mov	ecx, r14d
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r14d
        xor	ebx, r15d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r9d, r13d
        xor	ecx, r14d
        add	r13d, ebx
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r9d
        add	r13d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	ymm6, ymm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r14d
        mov	ecx, r10d
        add	r12d, DWORD PTR [rsp+140]
        xor	ecx, r11d
        vpsrlq	ymm8, ymm6, 17
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r9d
        and	ecx, r9d
        ror	edx, 5
        xor	ecx, r11d
        xor	edx, r9d
        add	r12d, ecx
        vpsrld	ymm9, ymm6, 10
        vpxor	ymm8, ymm7, ymm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r13d
        add	r12d, edx
        mov	ecx, r13d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r13d
        xor	eax, r14d
        vpxor	ymm9, ymm8, ymm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r8d, r12d
        xor	ecx, r13d
        add	r12d, eax
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r8d
        add	r12d, ecx
        vpaddd	ymm0, ymm9, ymm4
        ; msg_sched done: 32-35
        ; msg_sched: 40-43
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	ymm5, ymm2, ymm1, 4
        vpalignr	ymm4, ymm0, ymm3, 4
        ; rnd_0: 1 - 2
        mov	eax, r13d
        mov	ecx, r9d
        add	r11d, DWORD PTR [rsp+160]
        xor	ecx, r10d
        xor	edx, r8d
        and	ecx, r8d
        vpsrld	ymm6, ymm5, 7
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r10d
        xor	edx, r8d
        add	r11d, ecx
        ror	edx, 6
        xor	eax, r12d
        add	r11d, edx
        mov	ecx, r12d
        vpsrld	ymm8, ymm5, 18
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r12d
        xor	ebx, r13d
        ror	ecx, 11
        add	r15d, r11d
        xor	ecx, r12d
        add	r11d, ebx
        vpor	ymm6, ymm7, ymm6
        vpor	ymm8, ymm9, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r15d
        add	r11d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r12d
        mov	ecx, r8d
        add	r10d, DWORD PTR [rsp+164]
        xor	ecx, r9d
        vpsrld	ymm9, ymm5, 3
        vpxor	ymm6, ymm8, ymm6
        ; rnd_1: 2 - 3
        xor	edx, r15d
        and	ecx, r15d
        ror	edx, 5
        xor	ecx, r9d
        xor	edx, r15d
        add	r10d, ecx
        vpxor	ymm5, ymm9, ymm6
        vpshufd	ymm6, ymm0, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r11d
        add	r10d, edx
        mov	ecx, r11d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r11d
        xor	eax, r12d
        vpsrld	ymm8, ymm6, 10
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r14d, r10d
        xor	ecx, r11d
        add	r10d, eax
        ror	ecx, 2
        mov	edx, r14d
        add	r10d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	ymm6, ymm6, 17
        vpaddd	ymm4, ymm4, ymm1
        ; rnd_0: 1 - 3
        mov	eax, r11d
        mov	ecx, r15d
        add	r9d, DWORD PTR [rsp+168]
        xor	ecx, r8d
        xor	edx, r14d
        and	ecx, r14d
        ror	edx, 5
        xor	ecx, r8d
        xor	edx, r14d
        add	r9d, ecx
        vpxor	ymm6, ymm7, ymm6
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r10d
        add	r9d, edx
        mov	ecx, r10d
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r10d
        xor	ebx, r11d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r13d, r9d
        xor	ecx, r10d
        add	r9d, ebx
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r13d
        add	r9d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	ymm6, ymm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r10d
        mov	ecx, r14d
        add	r8d, DWORD PTR [rsp+172]
        xor	ecx, r15d
        vpsrlq	ymm8, ymm6, 17
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r13d
        and	ecx, r13d
        ror	edx, 5
        xor	ecx, r15d
        xor	edx, r13d
        add	r8d, ecx
        vpsrld	ymm9, ymm6, 10
        vpxor	ymm8, ymm7, ymm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r9d
        add	r8d, edx
        mov	ecx, r9d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r9d
        xor	eax, r10d
        vpxor	ymm9, ymm8, ymm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r12d, r8d
        xor	ecx, r9d
        add	r8d, eax
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r12d
        add	r8d, ecx
        vpaddd	ymm1, ymm9, ymm4
        ; msg_sched done: 40-43
        ; msg_sched: 48-51
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	ymm5, ymm3, ymm2, 4
        vpalignr	ymm4, ymm1, ymm0, 4
        ; rnd_0: 1 - 2
        mov	eax, r9d
        mov	ecx, r13d
        add	r15d, DWORD PTR [rsp+192]
        xor	ecx, r14d
        xor	edx, r12d
        and	ecx, r12d
        vpsrld	ymm6, ymm5, 7
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r14d
        xor	edx, r12d
        add	r15d, ecx
        ror	edx, 6
        xor	eax, r8d
        add	r15d, edx
        mov	ecx, r8d
        vpsrld	ymm8, ymm5, 18
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r8d
        xor	ebx, r9d
        ror	ecx, 11
        add	r11d, r15d
        xor	ecx, r8d
        add	r15d, ebx
        vpor	ymm6, ymm7, ymm6
        vpor	ymm8, ymm9, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r11d
        add	r15d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r8d
        mov	ecx, r12d
        add	r14d, DWORD PTR [rsp+196]
        xor	ecx, r13d
        vpsrld	ymm9, ymm5, 3
        vpxor	ymm6, ymm8, ymm6
        ; rnd_1: 2 - 3
        xor	edx, r11d
        and	ecx, r11d
        ror	edx, 5
        xor	ecx, r13d
        xor	edx, r11d
        add	r14d, ecx
        vpxor	ymm5, ymm9, ymm6
        vpshufd	ymm6, ymm1, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r15d
        add	r14d, edx
        mov	ecx, r15d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r15d
        xor	eax, r8d
        vpsrld	ymm8, ymm6, 10
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r10d, r14d
        xor	ecx, r15d
        add	r14d, eax
        ror	ecx, 2
        mov	edx, r10d
        add	r14d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	ymm6, ymm6, 17
        vpaddd	ymm4, ymm4, ymm2
        ; rnd_0: 1 - 3
        mov	eax, r15d
        mov	ecx, r11d
        add	r13d, DWORD PTR [rsp+200]
        xor	ecx, r12d
        xor	edx, r10d
        and	ecx, r10d
        ror	edx, 5
        xor	ecx, r12d
        xor	edx, r10d
        add	r13d, ecx
        vpxor	ymm6, ymm7, ymm6
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r14d
        add	r13d, edx
        mov	ecx, r14d
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r14d
        xor	ebx, r15d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r9d, r13d
        xor	ecx, r14d
        add	r13d, ebx
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r9d
        add	r13d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	ymm6, ymm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r14d
        mov	ecx, r10d
        add	r12d, DWORD PTR [rsp+204]
        xor	ecx, r11d
        vpsrlq	ymm8, ymm6, 17
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r9d
        and	ecx, r9d
        ror	edx, 5
        xor	ecx, r11d
        xor	edx, r9d
        add	r12d, ecx
        vpsrld	ymm9, ymm6, 10
        vpxor	ymm8, ymm7, ymm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r13d
        add	r12d, edx
        mov	ecx, r13d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r13d
        xor	eax, r14d
        vpxor	ymm9, ymm8, ymm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r8d, r12d
        xor	ecx, r13d
        add	r12d, eax
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r8d
        add	r12d, ecx
        vpaddd	ymm2, ymm9, ymm4
        ; msg_sched done: 48-51
        ; msg_sched: 56-59
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	ymm5, ymm0, ymm3, 4
        vpalignr	ymm4, ymm2, ymm1, 4
        ; rnd_0: 1 - 2
        mov	eax, r13d
        mov	ecx, r9d
        add	r11d, DWORD PTR [rsp+224]
        xor	ecx, r10d
        xor	edx, r8d
        and	ecx, r8d
        vpsrld	ymm6, ymm5, 7
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r10d
        xor	edx, r8d
        add	r11d, ecx
        ror	edx, 6
        xor	eax, r12d
        add	r11d, edx
        mov	ecx, r12d
        vpsrld	ymm8, ymm5, 18
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r12d
        xor	ebx, r13d
        ror	ecx, 11
        add	r15d, r11d
        xor	ecx, r12d
        add	r11d, ebx
        vpor	ymm6, ymm7, ymm6
        vpor	ymm8, ymm9, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r15d
        add	r11d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r12d
        mov	ecx, r8d
        add	r10d, DWORD PTR [rsp+228]
        xor	ecx, r9d
        vpsrld	ymm9, ymm5, 3
        vpxor	ymm6, ymm8, ymm6
        ; rnd_1: 2 - 3
        xor	edx, r15d
        and	ecx, r15d
        ror	edx, 5
        xor	ecx, r9d
        xor	edx, r15d
        add	r10d, ecx
        vpxor	ymm5, ymm9, ymm6
        vpshufd	ymm6, ymm2, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r11d
        add	r10d, edx
        mov	ecx, r11d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r11d
        xor	eax, r12d
        vpsrld	ymm8, ymm6, 10
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r14d, r10d
        xor	ecx, r11d
        add	r10d, eax
        ror	ecx, 2
        mov	edx, r14d
        add	r10d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	ymm6, ymm6, 17
        vpaddd	ymm4, ymm4, ymm3
        ; rnd_0: 1 - 3
        mov	eax, r11d
        mov	ecx, r15d
        add	r9d, DWORD PTR [rsp+232]
        xor	ecx, r8d
        xor	edx, r14d
        and	ecx, r14d
        ror	edx, 5
        xor	ecx, r8d
        xor	edx, r14d
        add	r9d, ecx
        vpxor	ymm6, ymm7, ymm6
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r10d
        add	r9d, edx
        mov	ecx, r10d
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r10d
        xor	ebx, r11d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r13d, r9d
        xor	ecx, r10d
        add	r9d, ebx
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r13d
        add	r9d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	ymm6, ymm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r10d
        mov	ecx, r14d
        add	r8d, DWORD PTR [rsp+236]
        xor	ecx, r15d
        vpsrlq	ymm8, ymm6, 17
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r13d
        and	ecx, r13d
        ror	edx, 5
        xor	ecx, r15d
        xor	edx, r13d
        add	r8d, ecx
        vpsrld	ymm9, ymm6, 10
        vpxor	ymm8, ymm7, ymm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r9d
        add	r8d, edx
        mov	ecx, r9d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r9d
        xor	eax, r10d
        vpxor	ymm9, ymm8, ymm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r12d, r8d
        xor	ecx, r9d
        add	r8d, eax
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r12d
        add	r8d, ecx
        vpaddd	ymm3, ymm9, ymm4
        ; msg_sched done: 56-59
        ; set_w_k_xfer_4: 8
        vpaddd	ymm4, ymm0, YMMWORD PTR [rbp+256]
        vpaddd	ymm5, ymm1, YMMWORD PTR [rbp+288]
        vmovdqu	YMMWORD PTR [rsp+256], ymm4
        vmovdqu	YMMWORD PTR [rsp+288], ymm5
        vpaddd	ymm4, ymm2, YMMWORD PTR [rbp+320]
        vpaddd	ymm5, ymm3, YMMWORD PTR [rbp+352]
        vmovdqu	YMMWORD PTR [rsp+320], ymm4
        vmovdqu	YMMWORD PTR [rsp+352], ymm5
        ; msg_sched: 64-67
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	ymm5, ymm1, ymm0, 4
        vpalignr	ymm4, ymm3, ymm2, 4
        ; rnd_0: 1 - 2
        mov	eax, r9d
        mov	ecx, r13d
        add	r15d, DWORD PTR [rsp+256]
        xor	ecx, r14d
        xor	edx, r12d
        and	ecx, r12d
        vpsrld	ymm6, ymm5, 7
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r14d
        xor	edx, r12d
        add	r15d, ecx
        ror	edx, 6
        xor	eax, r8d
        add	r15d, edx
        mov	ecx, r8d
        vpsrld	ymm8, ymm5, 18
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r8d
        xor	ebx, r9d
        ror	ecx, 11
        add	r11d, r15d
        xor	ecx, r8d
        add	r15d, ebx
        vpor	ymm6, ymm7, ymm6
        vpor	ymm8, ymm9, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r11d
        add	r15d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r8d
        mov	ecx, r12d
        add	r14d, DWORD PTR [rsp+260]
        xor	ecx, r13d
        vpsrld	ymm9, ymm5, 3
        vpxor	ymm6, ymm8, ymm6
        ; rnd_1: 2 - 3
        xor	edx, r11d
        and	ecx, r11d
        ror	edx, 5
        xor	ecx, r13d
        xor	edx, r11d
        add	r14d, ecx
        vpxor	ymm5, ymm9, ymm6
        vpshufd	ymm6, ymm3, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r15d
        add	r14d, edx
        mov	ecx, r15d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r15d
        xor	eax, r8d
        vpsrld	ymm8, ymm6, 10
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r10d, r14d
        xor	ecx, r15d
        add	r14d, eax
        ror	ecx, 2
        mov	edx, r10d
        add	r14d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	ymm6, ymm6, 17
        vpaddd	ymm4, ymm4, ymm0
        ; rnd_0: 1 - 3
        mov	eax, r15d
        mov	ecx, r11d
        add	r13d, DWORD PTR [rsp+264]
        xor	ecx, r12d
        xor	edx, r10d
        and	ecx, r10d
        ror	edx, 5
        xor	ecx, r12d
        xor	edx, r10d
        add	r13d, ecx
        vpxor	ymm6, ymm7, ymm6
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r14d
        add	r13d, edx
        mov	ecx, r14d
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r14d
        xor	ebx, r15d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r9d, r13d
        xor	ecx, r14d
        add	r13d, ebx
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r9d
        add	r13d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	ymm6, ymm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r14d
        mov	ecx, r10d
        add	r12d, DWORD PTR [rsp+268]
        xor	ecx, r11d
        vpsrlq	ymm8, ymm6, 17
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r9d
        and	ecx, r9d
        ror	edx, 5
        xor	ecx, r11d
        xor	edx, r9d
        add	r12d, ecx
        vpsrld	ymm9, ymm6, 10
        vpxor	ymm8, ymm7, ymm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r13d
        add	r12d, edx
        mov	ecx, r13d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r13d
        xor	eax, r14d
        vpxor	ymm9, ymm8, ymm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r8d, r12d
        xor	ecx, r13d
        add	r12d, eax
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r8d
        add	r12d, ecx
        vpaddd	ymm0, ymm9, ymm4
        ; msg_sched done: 64-67
        ; msg_sched: 72-75
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	ymm5, ymm2, ymm1, 4
        vpalignr	ymm4, ymm0, ymm3, 4
        ; rnd_0: 1 - 2
        mov	eax, r13d
        mov	ecx, r9d
        add	r11d, DWORD PTR [rsp+288]
        xor	ecx, r10d
        xor	edx, r8d
        and	ecx, r8d
        vpsrld	ymm6, ymm5, 7
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r10d
        xor	edx, r8d
        add	r11d, ecx
        ror	edx, 6
        xor	eax, r12d
        add	r11d, edx
        mov	ecx, r12d
        vpsrld	ymm8, ymm5, 18
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r12d
        xor	ebx, r13d
        ror	ecx, 11
        add	r15d, r11d
        xor	ecx, r12d
        add	r11d, ebx
        vpor	ymm6, ymm7, ymm6
        vpor	ymm8, ymm9, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r15d
        add	r11d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r12d
        mov	ecx, r8d
        add	r10d, DWORD PTR [rsp+292]
        xor	ecx, r9d
        vpsrld	ymm9, ymm5, 3
        vpxor	ymm6, ymm8, ymm6
        ; rnd_1: 2 - 3
        xor	edx, r15d
        and	ecx, r15d
        ror	edx, 5
        xor	ecx, r9d
        xor	edx, r15d
        add	r10d, ecx
        vpxor	ymm5, ymm9, ymm6
        vpshufd	ymm6, ymm0, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r11d
        add	r10d, edx
        mov	ecx, r11d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r11d
        xor	eax, r12d
        vpsrld	ymm8, ymm6, 10
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r14d, r10d
        xor	ecx, r11d
        add	r10d, eax
        ror	ecx, 2
        mov	edx, r14d
        add	r10d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	ymm6, ymm6, 17
        vpaddd	ymm4, ymm4, ymm1
        ; rnd_0: 1 - 3
        mov	eax, r11d
        mov	ecx, r15d
        add	r9d, DWORD PTR [rsp+296]
        xor	ecx, r8d
        xor	edx, r14d
        and	ecx, r14d
        ror	edx, 5
        xor	ecx, r8d
        xor	edx, r14d
        add	r9d, ecx
        vpxor	ymm6, ymm7, ymm6
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r10d
        add	r9d, edx
        mov	ecx, r10d
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r10d
        xor	ebx, r11d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r13d, r9d
        xor	ecx, r10d
        add	r9d, ebx
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r13d
        add	r9d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	ymm6, ymm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r10d
        mov	ecx, r14d
        add	r8d, DWORD PTR [rsp+300]
        xor	ecx, r15d
        vpsrlq	ymm8, ymm6, 17
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r13d
        and	ecx, r13d
        ror	edx, 5
        xor	ecx, r15d
        xor	edx, r13d
        add	r8d, ecx
        vpsrld	ymm9, ymm6, 10
        vpxor	ymm8, ymm7, ymm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r9d
        add	r8d, edx
        mov	ecx, r9d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r9d
        xor	eax, r10d
        vpxor	ymm9, ymm8, ymm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r12d, r8d
        xor	ecx, r9d
        add	r8d, eax
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r12d
        add	r8d, ecx
        vpaddd	ymm1, ymm9, ymm4
        ; msg_sched done: 72-75
        ; msg_sched: 80-83
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	ymm5, ymm3, ymm2, 4
        vpalignr	ymm4, ymm1, ymm0, 4
        ; rnd_0: 1 - 2
        mov	eax, r9d
        mov	ecx, r13d
        add	r15d, DWORD PTR [rsp+320]
        xor	ecx, r14d
        xor	edx, r12d
        and	ecx, r12d
        vpsrld	ymm6, ymm5, 7
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r14d
        xor	edx, r12d
        add	r15d, ecx
        ror	edx, 6
        xor	eax, r8d
        add	r15d, edx
        mov	ecx, r8d
        vpsrld	ymm8, ymm5, 18
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r8d
        xor	ebx, r9d
        ror	ecx, 11
        add	r11d, r15d
        xor	ecx, r8d
        add	r15d, ebx
        vpor	ymm6, ymm7, ymm6
        vpor	ymm8, ymm9, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r11d
        add	r15d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r8d
        mov	ecx, r12d
        add	r14d, DWORD PTR [rsp+324]
        xor	ecx, r13d
        vpsrld	ymm9, ymm5, 3
        vpxor	ymm6, ymm8, ymm6
        ; rnd_1: 2 - 3
        xor	edx, r11d
        and	ecx, r11d
        ror	edx, 5
        xor	ecx, r13d
        xor	edx, r11d
        add	r14d, ecx
        vpxor	ymm5, ymm9, ymm6
        vpshufd	ymm6, ymm1, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r15d
        add	r14d, edx
        mov	ecx, r15d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r15d
        xor	eax, r8d
        vpsrld	ymm8, ymm6, 10
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r10d, r14d
        xor	ecx, r15d
        add	r14d, eax
        ror	ecx, 2
        mov	edx, r10d
        add	r14d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	ymm6, ymm6, 17
        vpaddd	ymm4, ymm4, ymm2
        ; rnd_0: 1 - 3
        mov	eax, r15d
        mov	ecx, r11d
        add	r13d, DWORD PTR [rsp+328]
        xor	ecx, r12d
        xor	edx, r10d
        and	ecx, r10d
        ror	edx, 5
        xor	ecx, r12d
        xor	edx, r10d
        add	r13d, ecx
        vpxor	ymm6, ymm7, ymm6
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r14d
        add	r13d, edx
        mov	ecx, r14d
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r14d
        xor	ebx, r15d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r9d, r13d
        xor	ecx, r14d
        add	r13d, ebx
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r9d
        add	r13d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	ymm6, ymm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r14d
        mov	ecx, r10d
        add	r12d, DWORD PTR [rsp+332]
        xor	ecx, r11d
        vpsrlq	ymm8, ymm6, 17
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r9d
        and	ecx, r9d
        ror	edx, 5
        xor	ecx, r11d
        xor	edx, r9d
        add	r12d, ecx
        vpsrld	ymm9, ymm6, 10
        vpxor	ymm8, ymm7, ymm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r13d
        add	r12d, edx
        mov	ecx, r13d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r13d
        xor	eax, r14d
        vpxor	ymm9, ymm8, ymm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r8d, r12d
        xor	ecx, r13d
        add	r12d, eax
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r8d
        add	r12d, ecx
        vpaddd	ymm2, ymm9, ymm4
        ; msg_sched done: 80-83
        ; msg_sched: 88-91
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	ymm5, ymm0, ymm3, 4
        vpalignr	ymm4, ymm2, ymm1, 4
        ; rnd_0: 1 - 2
        mov	eax, r13d
        mov	ecx, r9d
        add	r11d, DWORD PTR [rsp+352]
        xor	ecx, r10d
        xor	edx, r8d
        and	ecx, r8d
        vpsrld	ymm6, ymm5, 7
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r10d
        xor	edx, r8d
        add	r11d, ecx
        ror	edx, 6
        xor	eax, r12d
        add	r11d, edx
        mov	ecx, r12d
        vpsrld	ymm8, ymm5, 18
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r12d
        xor	ebx, r13d
        ror	ecx, 11
        add	r15d, r11d
        xor	ecx, r12d
        add	r11d, ebx
        vpor	ymm6, ymm7, ymm6
        vpor	ymm8, ymm9, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r15d
        add	r11d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r12d
        mov	ecx, r8d
        add	r10d, DWORD PTR [rsp+356]
        xor	ecx, r9d
        vpsrld	ymm9, ymm5, 3
        vpxor	ymm6, ymm8, ymm6
        ; rnd_1: 2 - 3
        xor	edx, r15d
        and	ecx, r15d
        ror	edx, 5
        xor	ecx, r9d
        xor	edx, r15d
        add	r10d, ecx
        vpxor	ymm5, ymm9, ymm6
        vpshufd	ymm6, ymm2, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r11d
        add	r10d, edx
        mov	ecx, r11d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r11d
        xor	eax, r12d
        vpsrld	ymm8, ymm6, 10
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r14d, r10d
        xor	ecx, r11d
        add	r10d, eax
        ror	ecx, 2
        mov	edx, r14d
        add	r10d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	ymm6, ymm6, 17
        vpaddd	ymm4, ymm4, ymm3
        ; rnd_0: 1 - 3
        mov	eax, r11d
        mov	ecx, r15d
        add	r9d, DWORD PTR [rsp+360]
        xor	ecx, r8d
        xor	edx, r14d
        and	ecx, r14d
        ror	edx, 5
        xor	ecx, r8d
        xor	edx, r14d
        add	r9d, ecx
        vpxor	ymm6, ymm7, ymm6
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r10d
        add	r9d, edx
        mov	ecx, r10d
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r10d
        xor	ebx, r11d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r13d, r9d
        xor	ecx, r10d
        add	r9d, ebx
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r13d
        add	r9d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	ymm6, ymm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r10d
        mov	ecx, r14d
        add	r8d, DWORD PTR [rsp+364]
        xor	ecx, r15d
        vpsrlq	ymm8, ymm6, 17
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r13d
        and	ecx, r13d
        ror	edx, 5
        xor	ecx, r15d
        xor	edx, r13d
        add	r8d, ecx
        vpsrld	ymm9, ymm6, 10
        vpxor	ymm8, ymm7, ymm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r9d
        add	r8d, edx
        mov	ecx, r9d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r9d
        xor	eax, r10d
        vpxor	ymm9, ymm8, ymm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r12d, r8d
        xor	ecx, r9d
        add	r8d, eax
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r12d
        add	r8d, ecx
        vpaddd	ymm3, ymm9, ymm4
        ; msg_sched done: 88-91
        ; set_w_k_xfer_4: 12
        vpaddd	ymm4, ymm0, YMMWORD PTR [rbp+384]
        vpaddd	ymm5, ymm1, YMMWORD PTR [rbp+416]
        vmovdqu	YMMWORD PTR [rsp+384], ymm4
        vmovdqu	YMMWORD PTR [rsp+416], ymm5
        vpaddd	ymm4, ymm2, YMMWORD PTR [rbp+448]
        vpaddd	ymm5, ymm3, YMMWORD PTR [rbp+480]
        vmovdqu	YMMWORD PTR [rsp+448], ymm4
        vmovdqu	YMMWORD PTR [rsp+480], ymm5
        ; rnd_all_4: 24-27
        add	r15d, DWORD PTR [rsp+384]
        mov	ecx, r13d
        mov	eax, r9d
        xor	ecx, r14d
        ror	edx, 14
        and	ecx, r12d
        xor	edx, r12d
        xor	ecx, r14d
        ror	edx, 5
        add	r15d, ecx
        xor	edx, r12d
        xor	eax, r8d
        ror	edx, 6
        mov	ecx, r8d
        add	r15d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r8d
        xor	ebx, r9d
        ror	ecx, 11
        add	r11d, r15d
        xor	ecx, r8d
        add	r15d, ebx
        ror	ecx, 2
        mov	edx, r11d
        add	r15d, ecx
        add	r14d, DWORD PTR [rsp+388]
        mov	ecx, r12d
        mov	ebx, r8d
        xor	ecx, r13d
        ror	edx, 14
        and	ecx, r11d
        xor	edx, r11d
        xor	ecx, r13d
        ror	edx, 5
        add	r14d, ecx
        xor	edx, r11d
        xor	ebx, r15d
        ror	edx, 6
        mov	ecx, r15d
        add	r14d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r15d
        xor	eax, r8d
        ror	ecx, 11
        add	r10d, r14d
        xor	ecx, r15d
        add	r14d, eax
        ror	ecx, 2
        mov	edx, r10d
        add	r14d, ecx
        add	r13d, DWORD PTR [rsp+392]
        mov	ecx, r11d
        mov	eax, r15d
        xor	ecx, r12d
        ror	edx, 14
        and	ecx, r10d
        xor	edx, r10d
        xor	ecx, r12d
        ror	edx, 5
        add	r13d, ecx
        xor	edx, r10d
        xor	eax, r14d
        ror	edx, 6
        mov	ecx, r14d
        add	r13d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r14d
        xor	ebx, r15d
        ror	ecx, 11
        add	r9d, r13d
        xor	ecx, r14d
        add	r13d, ebx
        ror	ecx, 2
        mov	edx, r9d
        add	r13d, ecx
        add	r12d, DWORD PTR [rsp+396]
        mov	ecx, r10d
        mov	ebx, r14d
        xor	ecx, r11d
        ror	edx, 14
        and	ecx, r9d
        xor	edx, r9d
        xor	ecx, r11d
        ror	edx, 5
        add	r12d, ecx
        xor	edx, r9d
        xor	ebx, r13d
        ror	edx, 6
        mov	ecx, r13d
        add	r12d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r13d
        xor	eax, r14d
        ror	ecx, 11
        add	r8d, r12d
        xor	ecx, r13d
        add	r12d, eax
        ror	ecx, 2
        mov	edx, r8d
        add	r12d, ecx
        ; rnd_all_4: 26-29
        add	r11d, DWORD PTR [rsp+416]
        mov	ecx, r9d
        mov	eax, r13d
        xor	ecx, r10d
        ror	edx, 14
        and	ecx, r8d
        xor	edx, r8d
        xor	ecx, r10d
        ror	edx, 5
        add	r11d, ecx
        xor	edx, r8d
        xor	eax, r12d
        ror	edx, 6
        mov	ecx, r12d
        add	r11d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r12d
        xor	ebx, r13d
        ror	ecx, 11
        add	r15d, r11d
        xor	ecx, r12d
        add	r11d, ebx
        ror	ecx, 2
        mov	edx, r15d
        add	r11d, ecx
        add	r10d, DWORD PTR [rsp+420]
        mov	ecx, r8d
        mov	ebx, r12d
        xor	ecx, r9d
        ror	edx, 14
        and	ecx, r15d
        xor	edx, r15d
        xor	ecx, r9d
        ror	edx, 5
        add	r10d, ecx
        xor	edx, r15d
        xor	ebx, r11d
        ror	edx, 6
        mov	ecx, r11d
        add	r10d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r11d
        xor	eax, r12d
        ror	ecx, 11
        add	r14d, r10d
        xor	ecx, r11d
        add	r10d, eax
        ror	ecx, 2
        mov	edx, r14d
        add	r10d, ecx
        add	r9d, DWORD PTR [rsp+424]
        mov	ecx, r15d
        mov	eax, r11d
        xor	ecx, r8d
        ror	edx, 14
        and	ecx, r14d
        xor	edx, r14d
        xor	ecx, r8d
        ror	edx, 5
        add	r9d, ecx
        xor	edx, r14d
        xor	eax, r10d
        ror	edx, 6
        mov	ecx, r10d
        add	r9d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r10d
        xor	ebx, r11d
        ror	ecx, 11
        add	r13d, r9d
        xor	ecx, r10d
        add	r9d, ebx
        ror	ecx, 2
        mov	edx, r13d
        add	r9d, ecx
        add	r8d, DWORD PTR [rsp+428]
        mov	ecx, r14d
        mov	ebx, r10d
        xor	ecx, r15d
        ror	edx, 14
        and	ecx, r13d
        xor	edx, r13d
        xor	ecx, r15d
        ror	edx, 5
        add	r8d, ecx
        xor	edx, r13d
        xor	ebx, r9d
        ror	edx, 6
        mov	ecx, r9d
        add	r8d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r9d
        xor	eax, r10d
        ror	ecx, 11
        add	r12d, r8d
        xor	ecx, r9d
        add	r8d, eax
        ror	ecx, 2
        mov	edx, r12d
        add	r8d, ecx
        ; rnd_all_4: 28-31
        add	r15d, DWORD PTR [rsp+448]
        mov	ecx, r13d
        mov	eax, r9d
        xor	ecx, r14d
        ror	edx, 14
        and	ecx, r12d
        xor	edx, r12d
        xor	ecx, r14d
        ror	edx, 5
        add	r15d, ecx
        xor	edx, r12d
        xor	eax, r8d
        ror	edx, 6
        mov	ecx, r8d
        add	r15d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r8d
        xor	ebx, r9d
        ror	ecx, 11
        add	r11d, r15d
        xor	ecx, r8d
        add	r15d, ebx
        ror	ecx, 2
        mov	edx, r11d
        add	r15d, ecx
        add	r14d, DWORD PTR [rsp+452]
        mov	ecx, r12d
        mov	ebx, r8d
        xor	ecx, r13d
        ror	edx, 14
        and	ecx, r11d
        xor	edx, r11d
        xor	ecx, r13d
        ror	edx, 5
        add	r14d, ecx
        xor	edx, r11d
        xor	ebx, r15d
        ror	edx, 6
        mov	ecx, r15d
        add	r14d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r15d
        xor	eax, r8d
        ror	ecx, 11
        add	r10d, r14d
        xor	ecx, r15d
        add	r14d, eax
        ror	ecx, 2
        mov	edx, r10d
        add	r14d, ecx
        add	r13d, DWORD PTR [rsp+456]
        mov	ecx, r11d
        mov	eax, r15d
        xor	ecx, r12d
        ror	edx, 14
        and	ecx, r10d
        xor	edx, r10d
        xor	ecx, r12d
        ror	edx, 5
        add	r13d, ecx
        xor	edx, r10d
        xor	eax, r14d
        ror	edx, 6
        mov	ecx, r14d
        add	r13d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r14d
        xor	ebx, r15d
        ror	ecx, 11
        add	r9d, r13d
        xor	ecx, r14d
        add	r13d, ebx
        ror	ecx, 2
        mov	edx, r9d
        add	r13d, ecx
        add	r12d, DWORD PTR [rsp+460]
        mov	ecx, r10d
        mov	ebx, r14d
        xor	ecx, r11d
        ror	edx, 14
        and	ecx, r9d
        xor	edx, r9d
        xor	ecx, r11d
        ror	edx, 5
        add	r12d, ecx
        xor	edx, r9d
        xor	ebx, r13d
        ror	edx, 6
        mov	ecx, r13d
        add	r12d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r13d
        xor	eax, r14d
        ror	ecx, 11
        add	r8d, r12d
        xor	ecx, r13d
        add	r12d, eax
        ror	ecx, 2
        mov	edx, r8d
        add	r12d, ecx
        ; rnd_all_4: 30-33
        add	r11d, DWORD PTR [rsp+480]
        mov	ecx, r9d
        mov	eax, r13d
        xor	ecx, r10d
        ror	edx, 14
        and	ecx, r8d
        xor	edx, r8d
        xor	ecx, r10d
        ror	edx, 5
        add	r11d, ecx
        xor	edx, r8d
        xor	eax, r12d
        ror	edx, 6
        mov	ecx, r12d
        add	r11d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r12d
        xor	ebx, r13d
        ror	ecx, 11
        add	r15d, r11d
        xor	ecx, r12d
        add	r11d, ebx
        ror	ecx, 2
        mov	edx, r15d
        add	r11d, ecx
        add	r10d, DWORD PTR [rsp+484]
        mov	ecx, r8d
        mov	ebx, r12d
        xor	ecx, r9d
        ror	edx, 14
        and	ecx, r15d
        xor	edx, r15d
        xor	ecx, r9d
        ror	edx, 5
        add	r10d, ecx
        xor	edx, r15d
        xor	ebx, r11d
        ror	edx, 6
        mov	ecx, r11d
        add	r10d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r11d
        xor	eax, r12d
        ror	ecx, 11
        add	r14d, r10d
        xor	ecx, r11d
        add	r10d, eax
        ror	ecx, 2
        mov	edx, r14d
        add	r10d, ecx
        add	r9d, DWORD PTR [rsp+488]
        mov	ecx, r15d
        mov	eax, r11d
        xor	ecx, r8d
        ror	edx, 14
        and	ecx, r14d
        xor	edx, r14d
        xor	ecx, r8d
        ror	edx, 5
        add	r9d, ecx
        xor	edx, r14d
        xor	eax, r10d
        ror	edx, 6
        mov	ecx, r10d
        add	r9d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r10d
        xor	ebx, r11d
        ror	ecx, 11
        add	r13d, r9d
        xor	ecx, r10d
        add	r9d, ebx
        ror	ecx, 2
        mov	edx, r13d
        add	r9d, ecx
        add	r8d, DWORD PTR [rsp+492]
        mov	ecx, r14d
        mov	ebx, r10d
        xor	ecx, r15d
        ror	edx, 14
        and	ecx, r13d
        xor	edx, r13d
        xor	ecx, r15d
        ror	edx, 5
        add	r8d, ecx
        xor	edx, r13d
        xor	ebx, r9d
        ror	edx, 6
        mov	ecx, r9d
        add	r8d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r9d
        xor	eax, r10d
        ror	ecx, 11
        add	r12d, r8d
        xor	ecx, r9d
        add	r8d, eax
        ror	ecx, 2
        mov	edx, r12d
        add	r8d, ecx
        add	DWORD PTR [rdi], r8d
        add	DWORD PTR [rdi+4], r9d
        add	DWORD PTR [rdi+8], r10d
        add	DWORD PTR [rdi+12], r11d
        add	DWORD PTR [rdi+16], r12d
        add	DWORD PTR [rdi+20], r13d
        add	DWORD PTR [rdi+24], r14d
        add	DWORD PTR [rdi+28], r15d
        xor	rax, rax
        vzeroupper
        vmovdqu	xmm6, OWORD PTR [rsp+512]
        vmovdqu	xmm7, OWORD PTR [rsp+528]
        vmovdqu	xmm8, OWORD PTR [rsp+544]
        vmovdqu	xmm9, OWORD PTR [rsp+560]
        vmovdqu	xmm10, OWORD PTR [rsp+576]
        vmovdqu	xmm11, OWORD PTR [rsp+592]
        vmovdqu	xmm12, OWORD PTR [rsp+608]
        vmovdqu	xmm13, OWORD PTR [rsp+624]
        add	rsp, 640
        pop	rsi
        pop	rdi
        pop	rbp
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        pop	rbx
        ret
Transform_Sha256_AVX2 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
Transform_Sha256_AVX2_Len PROC
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
        mov	rbp, r8
        sub	rsp, 644
        vmovdqu	OWORD PTR [rsp+512], xmm6
        vmovdqu	OWORD PTR [rsp+528], xmm7
        vmovdqu	OWORD PTR [rsp+544], xmm8
        vmovdqu	OWORD PTR [rsp+560], xmm9
        vmovdqu	OWORD PTR [rsp+576], xmm10
        vmovdqu	OWORD PTR [rsp+592], xmm11
        vmovdqu	OWORD PTR [rsp+608], xmm12
        vmovdqu	OWORD PTR [rsp+624], xmm13
        test	bpl, 64
        mov	DWORD PTR [rsp+512], ebp
        je	L_sha256_len_avx2_block
        vmovdqu	ymm0, YMMWORD PTR [rsi]
        vmovdqu	ymm1, YMMWORD PTR [rsi+32]
        vmovups	YMMWORD PTR [rdi+32], ymm0
        vmovups	YMMWORD PTR [rdi+64], ymm1
        call	Transform_Sha256_AVX2
        add	rsi, 64
        sub	DWORD PTR [rsp+512], 64
        jz	L_sha256_len_avx2_done
L_sha256_len_avx2_block:
        mov	rbp, QWORD PTR [ptr_L_avx2_sha256_k]
        vmovdqu	ymm13, YMMWORD PTR L_avx2_sha256_flip_mask
        vmovdqu	ymm11, YMMWORD PTR L_avx2_sha256_shuf_00BA
        vmovdqu	ymm12, YMMWORD PTR L_avx2_sha256_shuf_DC00
        mov	r8d, DWORD PTR [rdi]
        mov	r9d, DWORD PTR [rdi+4]
        mov	r10d, DWORD PTR [rdi+8]
        mov	r11d, DWORD PTR [rdi+12]
        mov	r12d, DWORD PTR [rdi+16]
        mov	r13d, DWORD PTR [rdi+20]
        mov	r14d, DWORD PTR [rdi+24]
        mov	r15d, DWORD PTR [rdi+28]
        ; Start of loop processing two blocks
L_sha256_len_avx2_start:
        ; X0, X1, X2, X3 = W[0..15]
        vmovdqu	xmm0, OWORD PTR [rsi]
        vmovdqu	xmm1, OWORD PTR [rsi+16]
        vmovdqu	xmm4, OWORD PTR [rsi+64]
        vmovdqu	xmm5, OWORD PTR [rsi+80]
        vinserti128	ymm0, ymm0, xmm4, 1
        vinserti128	ymm1, ymm1, xmm5, 1
        vpshufb	ymm0, ymm0, ymm13
        vpshufb	ymm1, ymm1, ymm13
        vmovdqu	xmm2, OWORD PTR [rsi+32]
        vmovdqu	xmm3, OWORD PTR [rsi+48]
        vmovdqu	xmm6, OWORD PTR [rsi+96]
        vmovdqu	xmm7, OWORD PTR [rsi+112]
        vinserti128	ymm2, ymm2, xmm6, 1
        vinserti128	ymm3, ymm3, xmm7, 1
        vpshufb	ymm2, ymm2, ymm13
        vpshufb	ymm3, ymm3, ymm13
        mov	ebx, r9d
        mov	edx, r12d
        xor	ebx, r10d
        ; set_w_k_xfer_4: 0
        vpaddd	ymm4, ymm0, YMMWORD PTR [rbp]
        vpaddd	ymm5, ymm1, YMMWORD PTR [rbp+32]
        vmovdqu	YMMWORD PTR [rsp], ymm4
        vmovdqu	YMMWORD PTR [rsp+32], ymm5
        vpaddd	ymm4, ymm2, YMMWORD PTR [rbp+64]
        vpaddd	ymm5, ymm3, YMMWORD PTR [rbp+96]
        vmovdqu	YMMWORD PTR [rsp+64], ymm4
        vmovdqu	YMMWORD PTR [rsp+96], ymm5
        ; msg_sched: 0-3
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	ymm5, ymm1, ymm0, 4
        vpalignr	ymm4, ymm3, ymm2, 4
        ; rnd_0: 1 - 2
        mov	eax, r9d
        mov	ecx, r13d
        add	r15d, DWORD PTR [rsp]
        xor	ecx, r14d
        xor	edx, r12d
        and	ecx, r12d
        vpsrld	ymm6, ymm5, 7
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r14d
        xor	edx, r12d
        add	r15d, ecx
        ror	edx, 6
        xor	eax, r8d
        add	r15d, edx
        mov	ecx, r8d
        vpsrld	ymm8, ymm5, 18
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r8d
        xor	ebx, r9d
        ror	ecx, 11
        add	r11d, r15d
        xor	ecx, r8d
        add	r15d, ebx
        vpor	ymm6, ymm7, ymm6
        vpor	ymm8, ymm9, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r11d
        add	r15d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r8d
        mov	ecx, r12d
        add	r14d, DWORD PTR [rsp+4]
        xor	ecx, r13d
        vpsrld	ymm9, ymm5, 3
        vpxor	ymm6, ymm8, ymm6
        ; rnd_1: 2 - 3
        xor	edx, r11d
        and	ecx, r11d
        ror	edx, 5
        xor	ecx, r13d
        xor	edx, r11d
        add	r14d, ecx
        vpxor	ymm5, ymm9, ymm6
        vpshufd	ymm6, ymm3, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r15d
        add	r14d, edx
        mov	ecx, r15d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r15d
        xor	eax, r8d
        vpsrld	ymm8, ymm6, 10
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r10d, r14d
        xor	ecx, r15d
        add	r14d, eax
        ror	ecx, 2
        mov	edx, r10d
        add	r14d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	ymm6, ymm6, 17
        vpaddd	ymm4, ymm4, ymm0
        ; rnd_0: 1 - 3
        mov	eax, r15d
        mov	ecx, r11d
        add	r13d, DWORD PTR [rsp+8]
        xor	ecx, r12d
        xor	edx, r10d
        and	ecx, r10d
        ror	edx, 5
        xor	ecx, r12d
        xor	edx, r10d
        add	r13d, ecx
        vpxor	ymm6, ymm7, ymm6
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r14d
        add	r13d, edx
        mov	ecx, r14d
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r14d
        xor	ebx, r15d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r9d, r13d
        xor	ecx, r14d
        add	r13d, ebx
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r9d
        add	r13d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	ymm6, ymm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r14d
        mov	ecx, r10d
        add	r12d, DWORD PTR [rsp+12]
        xor	ecx, r11d
        vpsrlq	ymm8, ymm6, 17
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r9d
        and	ecx, r9d
        ror	edx, 5
        xor	ecx, r11d
        xor	edx, r9d
        add	r12d, ecx
        vpsrld	ymm9, ymm6, 10
        vpxor	ymm8, ymm7, ymm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r13d
        add	r12d, edx
        mov	ecx, r13d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r13d
        xor	eax, r14d
        vpxor	ymm9, ymm8, ymm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r8d, r12d
        xor	ecx, r13d
        add	r12d, eax
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r8d
        add	r12d, ecx
        vpaddd	ymm0, ymm9, ymm4
        ; msg_sched done: 0-3
        ; msg_sched: 8-11
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	ymm5, ymm2, ymm1, 4
        vpalignr	ymm4, ymm0, ymm3, 4
        ; rnd_0: 1 - 2
        mov	eax, r13d
        mov	ecx, r9d
        add	r11d, DWORD PTR [rsp+32]
        xor	ecx, r10d
        xor	edx, r8d
        and	ecx, r8d
        vpsrld	ymm6, ymm5, 7
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r10d
        xor	edx, r8d
        add	r11d, ecx
        ror	edx, 6
        xor	eax, r12d
        add	r11d, edx
        mov	ecx, r12d
        vpsrld	ymm8, ymm5, 18
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r12d
        xor	ebx, r13d
        ror	ecx, 11
        add	r15d, r11d
        xor	ecx, r12d
        add	r11d, ebx
        vpor	ymm6, ymm7, ymm6
        vpor	ymm8, ymm9, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r15d
        add	r11d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r12d
        mov	ecx, r8d
        add	r10d, DWORD PTR [rsp+36]
        xor	ecx, r9d
        vpsrld	ymm9, ymm5, 3
        vpxor	ymm6, ymm8, ymm6
        ; rnd_1: 2 - 3
        xor	edx, r15d
        and	ecx, r15d
        ror	edx, 5
        xor	ecx, r9d
        xor	edx, r15d
        add	r10d, ecx
        vpxor	ymm5, ymm9, ymm6
        vpshufd	ymm6, ymm0, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r11d
        add	r10d, edx
        mov	ecx, r11d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r11d
        xor	eax, r12d
        vpsrld	ymm8, ymm6, 10
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r14d, r10d
        xor	ecx, r11d
        add	r10d, eax
        ror	ecx, 2
        mov	edx, r14d
        add	r10d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	ymm6, ymm6, 17
        vpaddd	ymm4, ymm4, ymm1
        ; rnd_0: 1 - 3
        mov	eax, r11d
        mov	ecx, r15d
        add	r9d, DWORD PTR [rsp+40]
        xor	ecx, r8d
        xor	edx, r14d
        and	ecx, r14d
        ror	edx, 5
        xor	ecx, r8d
        xor	edx, r14d
        add	r9d, ecx
        vpxor	ymm6, ymm7, ymm6
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r10d
        add	r9d, edx
        mov	ecx, r10d
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r10d
        xor	ebx, r11d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r13d, r9d
        xor	ecx, r10d
        add	r9d, ebx
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r13d
        add	r9d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	ymm6, ymm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r10d
        mov	ecx, r14d
        add	r8d, DWORD PTR [rsp+44]
        xor	ecx, r15d
        vpsrlq	ymm8, ymm6, 17
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r13d
        and	ecx, r13d
        ror	edx, 5
        xor	ecx, r15d
        xor	edx, r13d
        add	r8d, ecx
        vpsrld	ymm9, ymm6, 10
        vpxor	ymm8, ymm7, ymm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r9d
        add	r8d, edx
        mov	ecx, r9d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r9d
        xor	eax, r10d
        vpxor	ymm9, ymm8, ymm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r12d, r8d
        xor	ecx, r9d
        add	r8d, eax
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r12d
        add	r8d, ecx
        vpaddd	ymm1, ymm9, ymm4
        ; msg_sched done: 8-11
        ; msg_sched: 16-19
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	ymm5, ymm3, ymm2, 4
        vpalignr	ymm4, ymm1, ymm0, 4
        ; rnd_0: 1 - 2
        mov	eax, r9d
        mov	ecx, r13d
        add	r15d, DWORD PTR [rsp+64]
        xor	ecx, r14d
        xor	edx, r12d
        and	ecx, r12d
        vpsrld	ymm6, ymm5, 7
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r14d
        xor	edx, r12d
        add	r15d, ecx
        ror	edx, 6
        xor	eax, r8d
        add	r15d, edx
        mov	ecx, r8d
        vpsrld	ymm8, ymm5, 18
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r8d
        xor	ebx, r9d
        ror	ecx, 11
        add	r11d, r15d
        xor	ecx, r8d
        add	r15d, ebx
        vpor	ymm6, ymm7, ymm6
        vpor	ymm8, ymm9, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r11d
        add	r15d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r8d
        mov	ecx, r12d
        add	r14d, DWORD PTR [rsp+68]
        xor	ecx, r13d
        vpsrld	ymm9, ymm5, 3
        vpxor	ymm6, ymm8, ymm6
        ; rnd_1: 2 - 3
        xor	edx, r11d
        and	ecx, r11d
        ror	edx, 5
        xor	ecx, r13d
        xor	edx, r11d
        add	r14d, ecx
        vpxor	ymm5, ymm9, ymm6
        vpshufd	ymm6, ymm1, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r15d
        add	r14d, edx
        mov	ecx, r15d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r15d
        xor	eax, r8d
        vpsrld	ymm8, ymm6, 10
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r10d, r14d
        xor	ecx, r15d
        add	r14d, eax
        ror	ecx, 2
        mov	edx, r10d
        add	r14d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	ymm6, ymm6, 17
        vpaddd	ymm4, ymm4, ymm2
        ; rnd_0: 1 - 3
        mov	eax, r15d
        mov	ecx, r11d
        add	r13d, DWORD PTR [rsp+72]
        xor	ecx, r12d
        xor	edx, r10d
        and	ecx, r10d
        ror	edx, 5
        xor	ecx, r12d
        xor	edx, r10d
        add	r13d, ecx
        vpxor	ymm6, ymm7, ymm6
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r14d
        add	r13d, edx
        mov	ecx, r14d
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r14d
        xor	ebx, r15d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r9d, r13d
        xor	ecx, r14d
        add	r13d, ebx
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r9d
        add	r13d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	ymm6, ymm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r14d
        mov	ecx, r10d
        add	r12d, DWORD PTR [rsp+76]
        xor	ecx, r11d
        vpsrlq	ymm8, ymm6, 17
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r9d
        and	ecx, r9d
        ror	edx, 5
        xor	ecx, r11d
        xor	edx, r9d
        add	r12d, ecx
        vpsrld	ymm9, ymm6, 10
        vpxor	ymm8, ymm7, ymm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r13d
        add	r12d, edx
        mov	ecx, r13d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r13d
        xor	eax, r14d
        vpxor	ymm9, ymm8, ymm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r8d, r12d
        xor	ecx, r13d
        add	r12d, eax
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r8d
        add	r12d, ecx
        vpaddd	ymm2, ymm9, ymm4
        ; msg_sched done: 16-19
        ; msg_sched: 24-27
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	ymm5, ymm0, ymm3, 4
        vpalignr	ymm4, ymm2, ymm1, 4
        ; rnd_0: 1 - 2
        mov	eax, r13d
        mov	ecx, r9d
        add	r11d, DWORD PTR [rsp+96]
        xor	ecx, r10d
        xor	edx, r8d
        and	ecx, r8d
        vpsrld	ymm6, ymm5, 7
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r10d
        xor	edx, r8d
        add	r11d, ecx
        ror	edx, 6
        xor	eax, r12d
        add	r11d, edx
        mov	ecx, r12d
        vpsrld	ymm8, ymm5, 18
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r12d
        xor	ebx, r13d
        ror	ecx, 11
        add	r15d, r11d
        xor	ecx, r12d
        add	r11d, ebx
        vpor	ymm6, ymm7, ymm6
        vpor	ymm8, ymm9, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r15d
        add	r11d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r12d
        mov	ecx, r8d
        add	r10d, DWORD PTR [rsp+100]
        xor	ecx, r9d
        vpsrld	ymm9, ymm5, 3
        vpxor	ymm6, ymm8, ymm6
        ; rnd_1: 2 - 3
        xor	edx, r15d
        and	ecx, r15d
        ror	edx, 5
        xor	ecx, r9d
        xor	edx, r15d
        add	r10d, ecx
        vpxor	ymm5, ymm9, ymm6
        vpshufd	ymm6, ymm2, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r11d
        add	r10d, edx
        mov	ecx, r11d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r11d
        xor	eax, r12d
        vpsrld	ymm8, ymm6, 10
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r14d, r10d
        xor	ecx, r11d
        add	r10d, eax
        ror	ecx, 2
        mov	edx, r14d
        add	r10d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	ymm6, ymm6, 17
        vpaddd	ymm4, ymm4, ymm3
        ; rnd_0: 1 - 3
        mov	eax, r11d
        mov	ecx, r15d
        add	r9d, DWORD PTR [rsp+104]
        xor	ecx, r8d
        xor	edx, r14d
        and	ecx, r14d
        ror	edx, 5
        xor	ecx, r8d
        xor	edx, r14d
        add	r9d, ecx
        vpxor	ymm6, ymm7, ymm6
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r10d
        add	r9d, edx
        mov	ecx, r10d
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r10d
        xor	ebx, r11d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r13d, r9d
        xor	ecx, r10d
        add	r9d, ebx
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r13d
        add	r9d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	ymm6, ymm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r10d
        mov	ecx, r14d
        add	r8d, DWORD PTR [rsp+108]
        xor	ecx, r15d
        vpsrlq	ymm8, ymm6, 17
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r13d
        and	ecx, r13d
        ror	edx, 5
        xor	ecx, r15d
        xor	edx, r13d
        add	r8d, ecx
        vpsrld	ymm9, ymm6, 10
        vpxor	ymm8, ymm7, ymm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r9d
        add	r8d, edx
        mov	ecx, r9d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r9d
        xor	eax, r10d
        vpxor	ymm9, ymm8, ymm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r12d, r8d
        xor	ecx, r9d
        add	r8d, eax
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r12d
        add	r8d, ecx
        vpaddd	ymm3, ymm9, ymm4
        ; msg_sched done: 24-27
        ; set_w_k_xfer_4: 4
        vpaddd	ymm4, ymm0, YMMWORD PTR [rbp+128]
        vpaddd	ymm5, ymm1, YMMWORD PTR [rbp+160]
        vmovdqu	YMMWORD PTR [rsp+128], ymm4
        vmovdqu	YMMWORD PTR [rsp+160], ymm5
        vpaddd	ymm4, ymm2, YMMWORD PTR [rbp+192]
        vpaddd	ymm5, ymm3, YMMWORD PTR [rbp+224]
        vmovdqu	YMMWORD PTR [rsp+192], ymm4
        vmovdqu	YMMWORD PTR [rsp+224], ymm5
        ; msg_sched: 32-35
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	ymm5, ymm1, ymm0, 4
        vpalignr	ymm4, ymm3, ymm2, 4
        ; rnd_0: 1 - 2
        mov	eax, r9d
        mov	ecx, r13d
        add	r15d, DWORD PTR [rsp+128]
        xor	ecx, r14d
        xor	edx, r12d
        and	ecx, r12d
        vpsrld	ymm6, ymm5, 7
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r14d
        xor	edx, r12d
        add	r15d, ecx
        ror	edx, 6
        xor	eax, r8d
        add	r15d, edx
        mov	ecx, r8d
        vpsrld	ymm8, ymm5, 18
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r8d
        xor	ebx, r9d
        ror	ecx, 11
        add	r11d, r15d
        xor	ecx, r8d
        add	r15d, ebx
        vpor	ymm6, ymm7, ymm6
        vpor	ymm8, ymm9, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r11d
        add	r15d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r8d
        mov	ecx, r12d
        add	r14d, DWORD PTR [rsp+132]
        xor	ecx, r13d
        vpsrld	ymm9, ymm5, 3
        vpxor	ymm6, ymm8, ymm6
        ; rnd_1: 2 - 3
        xor	edx, r11d
        and	ecx, r11d
        ror	edx, 5
        xor	ecx, r13d
        xor	edx, r11d
        add	r14d, ecx
        vpxor	ymm5, ymm9, ymm6
        vpshufd	ymm6, ymm3, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r15d
        add	r14d, edx
        mov	ecx, r15d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r15d
        xor	eax, r8d
        vpsrld	ymm8, ymm6, 10
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r10d, r14d
        xor	ecx, r15d
        add	r14d, eax
        ror	ecx, 2
        mov	edx, r10d
        add	r14d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	ymm6, ymm6, 17
        vpaddd	ymm4, ymm4, ymm0
        ; rnd_0: 1 - 3
        mov	eax, r15d
        mov	ecx, r11d
        add	r13d, DWORD PTR [rsp+136]
        xor	ecx, r12d
        xor	edx, r10d
        and	ecx, r10d
        ror	edx, 5
        xor	ecx, r12d
        xor	edx, r10d
        add	r13d, ecx
        vpxor	ymm6, ymm7, ymm6
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r14d
        add	r13d, edx
        mov	ecx, r14d
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r14d
        xor	ebx, r15d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r9d, r13d
        xor	ecx, r14d
        add	r13d, ebx
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r9d
        add	r13d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	ymm6, ymm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r14d
        mov	ecx, r10d
        add	r12d, DWORD PTR [rsp+140]
        xor	ecx, r11d
        vpsrlq	ymm8, ymm6, 17
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r9d
        and	ecx, r9d
        ror	edx, 5
        xor	ecx, r11d
        xor	edx, r9d
        add	r12d, ecx
        vpsrld	ymm9, ymm6, 10
        vpxor	ymm8, ymm7, ymm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r13d
        add	r12d, edx
        mov	ecx, r13d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r13d
        xor	eax, r14d
        vpxor	ymm9, ymm8, ymm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r8d, r12d
        xor	ecx, r13d
        add	r12d, eax
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r8d
        add	r12d, ecx
        vpaddd	ymm0, ymm9, ymm4
        ; msg_sched done: 32-35
        ; msg_sched: 40-43
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	ymm5, ymm2, ymm1, 4
        vpalignr	ymm4, ymm0, ymm3, 4
        ; rnd_0: 1 - 2
        mov	eax, r13d
        mov	ecx, r9d
        add	r11d, DWORD PTR [rsp+160]
        xor	ecx, r10d
        xor	edx, r8d
        and	ecx, r8d
        vpsrld	ymm6, ymm5, 7
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r10d
        xor	edx, r8d
        add	r11d, ecx
        ror	edx, 6
        xor	eax, r12d
        add	r11d, edx
        mov	ecx, r12d
        vpsrld	ymm8, ymm5, 18
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r12d
        xor	ebx, r13d
        ror	ecx, 11
        add	r15d, r11d
        xor	ecx, r12d
        add	r11d, ebx
        vpor	ymm6, ymm7, ymm6
        vpor	ymm8, ymm9, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r15d
        add	r11d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r12d
        mov	ecx, r8d
        add	r10d, DWORD PTR [rsp+164]
        xor	ecx, r9d
        vpsrld	ymm9, ymm5, 3
        vpxor	ymm6, ymm8, ymm6
        ; rnd_1: 2 - 3
        xor	edx, r15d
        and	ecx, r15d
        ror	edx, 5
        xor	ecx, r9d
        xor	edx, r15d
        add	r10d, ecx
        vpxor	ymm5, ymm9, ymm6
        vpshufd	ymm6, ymm0, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r11d
        add	r10d, edx
        mov	ecx, r11d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r11d
        xor	eax, r12d
        vpsrld	ymm8, ymm6, 10
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r14d, r10d
        xor	ecx, r11d
        add	r10d, eax
        ror	ecx, 2
        mov	edx, r14d
        add	r10d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	ymm6, ymm6, 17
        vpaddd	ymm4, ymm4, ymm1
        ; rnd_0: 1 - 3
        mov	eax, r11d
        mov	ecx, r15d
        add	r9d, DWORD PTR [rsp+168]
        xor	ecx, r8d
        xor	edx, r14d
        and	ecx, r14d
        ror	edx, 5
        xor	ecx, r8d
        xor	edx, r14d
        add	r9d, ecx
        vpxor	ymm6, ymm7, ymm6
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r10d
        add	r9d, edx
        mov	ecx, r10d
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r10d
        xor	ebx, r11d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r13d, r9d
        xor	ecx, r10d
        add	r9d, ebx
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r13d
        add	r9d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	ymm6, ymm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r10d
        mov	ecx, r14d
        add	r8d, DWORD PTR [rsp+172]
        xor	ecx, r15d
        vpsrlq	ymm8, ymm6, 17
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r13d
        and	ecx, r13d
        ror	edx, 5
        xor	ecx, r15d
        xor	edx, r13d
        add	r8d, ecx
        vpsrld	ymm9, ymm6, 10
        vpxor	ymm8, ymm7, ymm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r9d
        add	r8d, edx
        mov	ecx, r9d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r9d
        xor	eax, r10d
        vpxor	ymm9, ymm8, ymm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r12d, r8d
        xor	ecx, r9d
        add	r8d, eax
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r12d
        add	r8d, ecx
        vpaddd	ymm1, ymm9, ymm4
        ; msg_sched done: 40-43
        ; msg_sched: 48-51
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	ymm5, ymm3, ymm2, 4
        vpalignr	ymm4, ymm1, ymm0, 4
        ; rnd_0: 1 - 2
        mov	eax, r9d
        mov	ecx, r13d
        add	r15d, DWORD PTR [rsp+192]
        xor	ecx, r14d
        xor	edx, r12d
        and	ecx, r12d
        vpsrld	ymm6, ymm5, 7
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r14d
        xor	edx, r12d
        add	r15d, ecx
        ror	edx, 6
        xor	eax, r8d
        add	r15d, edx
        mov	ecx, r8d
        vpsrld	ymm8, ymm5, 18
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r8d
        xor	ebx, r9d
        ror	ecx, 11
        add	r11d, r15d
        xor	ecx, r8d
        add	r15d, ebx
        vpor	ymm6, ymm7, ymm6
        vpor	ymm8, ymm9, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r11d
        add	r15d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r8d
        mov	ecx, r12d
        add	r14d, DWORD PTR [rsp+196]
        xor	ecx, r13d
        vpsrld	ymm9, ymm5, 3
        vpxor	ymm6, ymm8, ymm6
        ; rnd_1: 2 - 3
        xor	edx, r11d
        and	ecx, r11d
        ror	edx, 5
        xor	ecx, r13d
        xor	edx, r11d
        add	r14d, ecx
        vpxor	ymm5, ymm9, ymm6
        vpshufd	ymm6, ymm1, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r15d
        add	r14d, edx
        mov	ecx, r15d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r15d
        xor	eax, r8d
        vpsrld	ymm8, ymm6, 10
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r10d, r14d
        xor	ecx, r15d
        add	r14d, eax
        ror	ecx, 2
        mov	edx, r10d
        add	r14d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	ymm6, ymm6, 17
        vpaddd	ymm4, ymm4, ymm2
        ; rnd_0: 1 - 3
        mov	eax, r15d
        mov	ecx, r11d
        add	r13d, DWORD PTR [rsp+200]
        xor	ecx, r12d
        xor	edx, r10d
        and	ecx, r10d
        ror	edx, 5
        xor	ecx, r12d
        xor	edx, r10d
        add	r13d, ecx
        vpxor	ymm6, ymm7, ymm6
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r14d
        add	r13d, edx
        mov	ecx, r14d
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r14d
        xor	ebx, r15d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r9d, r13d
        xor	ecx, r14d
        add	r13d, ebx
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r9d
        add	r13d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	ymm6, ymm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r14d
        mov	ecx, r10d
        add	r12d, DWORD PTR [rsp+204]
        xor	ecx, r11d
        vpsrlq	ymm8, ymm6, 17
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r9d
        and	ecx, r9d
        ror	edx, 5
        xor	ecx, r11d
        xor	edx, r9d
        add	r12d, ecx
        vpsrld	ymm9, ymm6, 10
        vpxor	ymm8, ymm7, ymm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r13d
        add	r12d, edx
        mov	ecx, r13d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r13d
        xor	eax, r14d
        vpxor	ymm9, ymm8, ymm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r8d, r12d
        xor	ecx, r13d
        add	r12d, eax
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r8d
        add	r12d, ecx
        vpaddd	ymm2, ymm9, ymm4
        ; msg_sched done: 48-51
        ; msg_sched: 56-59
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	ymm5, ymm0, ymm3, 4
        vpalignr	ymm4, ymm2, ymm1, 4
        ; rnd_0: 1 - 2
        mov	eax, r13d
        mov	ecx, r9d
        add	r11d, DWORD PTR [rsp+224]
        xor	ecx, r10d
        xor	edx, r8d
        and	ecx, r8d
        vpsrld	ymm6, ymm5, 7
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r10d
        xor	edx, r8d
        add	r11d, ecx
        ror	edx, 6
        xor	eax, r12d
        add	r11d, edx
        mov	ecx, r12d
        vpsrld	ymm8, ymm5, 18
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r12d
        xor	ebx, r13d
        ror	ecx, 11
        add	r15d, r11d
        xor	ecx, r12d
        add	r11d, ebx
        vpor	ymm6, ymm7, ymm6
        vpor	ymm8, ymm9, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r15d
        add	r11d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r12d
        mov	ecx, r8d
        add	r10d, DWORD PTR [rsp+228]
        xor	ecx, r9d
        vpsrld	ymm9, ymm5, 3
        vpxor	ymm6, ymm8, ymm6
        ; rnd_1: 2 - 3
        xor	edx, r15d
        and	ecx, r15d
        ror	edx, 5
        xor	ecx, r9d
        xor	edx, r15d
        add	r10d, ecx
        vpxor	ymm5, ymm9, ymm6
        vpshufd	ymm6, ymm2, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r11d
        add	r10d, edx
        mov	ecx, r11d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r11d
        xor	eax, r12d
        vpsrld	ymm8, ymm6, 10
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r14d, r10d
        xor	ecx, r11d
        add	r10d, eax
        ror	ecx, 2
        mov	edx, r14d
        add	r10d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	ymm6, ymm6, 17
        vpaddd	ymm4, ymm4, ymm3
        ; rnd_0: 1 - 3
        mov	eax, r11d
        mov	ecx, r15d
        add	r9d, DWORD PTR [rsp+232]
        xor	ecx, r8d
        xor	edx, r14d
        and	ecx, r14d
        ror	edx, 5
        xor	ecx, r8d
        xor	edx, r14d
        add	r9d, ecx
        vpxor	ymm6, ymm7, ymm6
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r10d
        add	r9d, edx
        mov	ecx, r10d
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r10d
        xor	ebx, r11d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r13d, r9d
        xor	ecx, r10d
        add	r9d, ebx
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r13d
        add	r9d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	ymm6, ymm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r10d
        mov	ecx, r14d
        add	r8d, DWORD PTR [rsp+236]
        xor	ecx, r15d
        vpsrlq	ymm8, ymm6, 17
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r13d
        and	ecx, r13d
        ror	edx, 5
        xor	ecx, r15d
        xor	edx, r13d
        add	r8d, ecx
        vpsrld	ymm9, ymm6, 10
        vpxor	ymm8, ymm7, ymm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r9d
        add	r8d, edx
        mov	ecx, r9d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r9d
        xor	eax, r10d
        vpxor	ymm9, ymm8, ymm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r12d, r8d
        xor	ecx, r9d
        add	r8d, eax
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r12d
        add	r8d, ecx
        vpaddd	ymm3, ymm9, ymm4
        ; msg_sched done: 56-59
        ; set_w_k_xfer_4: 8
        vpaddd	ymm4, ymm0, YMMWORD PTR [rbp+256]
        vpaddd	ymm5, ymm1, YMMWORD PTR [rbp+288]
        vmovdqu	YMMWORD PTR [rsp+256], ymm4
        vmovdqu	YMMWORD PTR [rsp+288], ymm5
        vpaddd	ymm4, ymm2, YMMWORD PTR [rbp+320]
        vpaddd	ymm5, ymm3, YMMWORD PTR [rbp+352]
        vmovdqu	YMMWORD PTR [rsp+320], ymm4
        vmovdqu	YMMWORD PTR [rsp+352], ymm5
        ; msg_sched: 64-67
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	ymm5, ymm1, ymm0, 4
        vpalignr	ymm4, ymm3, ymm2, 4
        ; rnd_0: 1 - 2
        mov	eax, r9d
        mov	ecx, r13d
        add	r15d, DWORD PTR [rsp+256]
        xor	ecx, r14d
        xor	edx, r12d
        and	ecx, r12d
        vpsrld	ymm6, ymm5, 7
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r14d
        xor	edx, r12d
        add	r15d, ecx
        ror	edx, 6
        xor	eax, r8d
        add	r15d, edx
        mov	ecx, r8d
        vpsrld	ymm8, ymm5, 18
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r8d
        xor	ebx, r9d
        ror	ecx, 11
        add	r11d, r15d
        xor	ecx, r8d
        add	r15d, ebx
        vpor	ymm6, ymm7, ymm6
        vpor	ymm8, ymm9, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r11d
        add	r15d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r8d
        mov	ecx, r12d
        add	r14d, DWORD PTR [rsp+260]
        xor	ecx, r13d
        vpsrld	ymm9, ymm5, 3
        vpxor	ymm6, ymm8, ymm6
        ; rnd_1: 2 - 3
        xor	edx, r11d
        and	ecx, r11d
        ror	edx, 5
        xor	ecx, r13d
        xor	edx, r11d
        add	r14d, ecx
        vpxor	ymm5, ymm9, ymm6
        vpshufd	ymm6, ymm3, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r15d
        add	r14d, edx
        mov	ecx, r15d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r15d
        xor	eax, r8d
        vpsrld	ymm8, ymm6, 10
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r10d, r14d
        xor	ecx, r15d
        add	r14d, eax
        ror	ecx, 2
        mov	edx, r10d
        add	r14d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	ymm6, ymm6, 17
        vpaddd	ymm4, ymm4, ymm0
        ; rnd_0: 1 - 3
        mov	eax, r15d
        mov	ecx, r11d
        add	r13d, DWORD PTR [rsp+264]
        xor	ecx, r12d
        xor	edx, r10d
        and	ecx, r10d
        ror	edx, 5
        xor	ecx, r12d
        xor	edx, r10d
        add	r13d, ecx
        vpxor	ymm6, ymm7, ymm6
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r14d
        add	r13d, edx
        mov	ecx, r14d
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r14d
        xor	ebx, r15d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r9d, r13d
        xor	ecx, r14d
        add	r13d, ebx
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r9d
        add	r13d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	ymm6, ymm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r14d
        mov	ecx, r10d
        add	r12d, DWORD PTR [rsp+268]
        xor	ecx, r11d
        vpsrlq	ymm8, ymm6, 17
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r9d
        and	ecx, r9d
        ror	edx, 5
        xor	ecx, r11d
        xor	edx, r9d
        add	r12d, ecx
        vpsrld	ymm9, ymm6, 10
        vpxor	ymm8, ymm7, ymm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r13d
        add	r12d, edx
        mov	ecx, r13d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r13d
        xor	eax, r14d
        vpxor	ymm9, ymm8, ymm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r8d, r12d
        xor	ecx, r13d
        add	r12d, eax
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r8d
        add	r12d, ecx
        vpaddd	ymm0, ymm9, ymm4
        ; msg_sched done: 64-67
        ; msg_sched: 72-75
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	ymm5, ymm2, ymm1, 4
        vpalignr	ymm4, ymm0, ymm3, 4
        ; rnd_0: 1 - 2
        mov	eax, r13d
        mov	ecx, r9d
        add	r11d, DWORD PTR [rsp+288]
        xor	ecx, r10d
        xor	edx, r8d
        and	ecx, r8d
        vpsrld	ymm6, ymm5, 7
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r10d
        xor	edx, r8d
        add	r11d, ecx
        ror	edx, 6
        xor	eax, r12d
        add	r11d, edx
        mov	ecx, r12d
        vpsrld	ymm8, ymm5, 18
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r12d
        xor	ebx, r13d
        ror	ecx, 11
        add	r15d, r11d
        xor	ecx, r12d
        add	r11d, ebx
        vpor	ymm6, ymm7, ymm6
        vpor	ymm8, ymm9, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r15d
        add	r11d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r12d
        mov	ecx, r8d
        add	r10d, DWORD PTR [rsp+292]
        xor	ecx, r9d
        vpsrld	ymm9, ymm5, 3
        vpxor	ymm6, ymm8, ymm6
        ; rnd_1: 2 - 3
        xor	edx, r15d
        and	ecx, r15d
        ror	edx, 5
        xor	ecx, r9d
        xor	edx, r15d
        add	r10d, ecx
        vpxor	ymm5, ymm9, ymm6
        vpshufd	ymm6, ymm0, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r11d
        add	r10d, edx
        mov	ecx, r11d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r11d
        xor	eax, r12d
        vpsrld	ymm8, ymm6, 10
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r14d, r10d
        xor	ecx, r11d
        add	r10d, eax
        ror	ecx, 2
        mov	edx, r14d
        add	r10d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	ymm6, ymm6, 17
        vpaddd	ymm4, ymm4, ymm1
        ; rnd_0: 1 - 3
        mov	eax, r11d
        mov	ecx, r15d
        add	r9d, DWORD PTR [rsp+296]
        xor	ecx, r8d
        xor	edx, r14d
        and	ecx, r14d
        ror	edx, 5
        xor	ecx, r8d
        xor	edx, r14d
        add	r9d, ecx
        vpxor	ymm6, ymm7, ymm6
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r10d
        add	r9d, edx
        mov	ecx, r10d
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r10d
        xor	ebx, r11d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r13d, r9d
        xor	ecx, r10d
        add	r9d, ebx
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r13d
        add	r9d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	ymm6, ymm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r10d
        mov	ecx, r14d
        add	r8d, DWORD PTR [rsp+300]
        xor	ecx, r15d
        vpsrlq	ymm8, ymm6, 17
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r13d
        and	ecx, r13d
        ror	edx, 5
        xor	ecx, r15d
        xor	edx, r13d
        add	r8d, ecx
        vpsrld	ymm9, ymm6, 10
        vpxor	ymm8, ymm7, ymm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r9d
        add	r8d, edx
        mov	ecx, r9d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r9d
        xor	eax, r10d
        vpxor	ymm9, ymm8, ymm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r12d, r8d
        xor	ecx, r9d
        add	r8d, eax
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r12d
        add	r8d, ecx
        vpaddd	ymm1, ymm9, ymm4
        ; msg_sched done: 72-75
        ; msg_sched: 80-83
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	ymm5, ymm3, ymm2, 4
        vpalignr	ymm4, ymm1, ymm0, 4
        ; rnd_0: 1 - 2
        mov	eax, r9d
        mov	ecx, r13d
        add	r15d, DWORD PTR [rsp+320]
        xor	ecx, r14d
        xor	edx, r12d
        and	ecx, r12d
        vpsrld	ymm6, ymm5, 7
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r14d
        xor	edx, r12d
        add	r15d, ecx
        ror	edx, 6
        xor	eax, r8d
        add	r15d, edx
        mov	ecx, r8d
        vpsrld	ymm8, ymm5, 18
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r8d
        xor	ebx, r9d
        ror	ecx, 11
        add	r11d, r15d
        xor	ecx, r8d
        add	r15d, ebx
        vpor	ymm6, ymm7, ymm6
        vpor	ymm8, ymm9, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r11d
        add	r15d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r8d
        mov	ecx, r12d
        add	r14d, DWORD PTR [rsp+324]
        xor	ecx, r13d
        vpsrld	ymm9, ymm5, 3
        vpxor	ymm6, ymm8, ymm6
        ; rnd_1: 2 - 3
        xor	edx, r11d
        and	ecx, r11d
        ror	edx, 5
        xor	ecx, r13d
        xor	edx, r11d
        add	r14d, ecx
        vpxor	ymm5, ymm9, ymm6
        vpshufd	ymm6, ymm1, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r15d
        add	r14d, edx
        mov	ecx, r15d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r15d
        xor	eax, r8d
        vpsrld	ymm8, ymm6, 10
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r10d, r14d
        xor	ecx, r15d
        add	r14d, eax
        ror	ecx, 2
        mov	edx, r10d
        add	r14d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	ymm6, ymm6, 17
        vpaddd	ymm4, ymm4, ymm2
        ; rnd_0: 1 - 3
        mov	eax, r15d
        mov	ecx, r11d
        add	r13d, DWORD PTR [rsp+328]
        xor	ecx, r12d
        xor	edx, r10d
        and	ecx, r10d
        ror	edx, 5
        xor	ecx, r12d
        xor	edx, r10d
        add	r13d, ecx
        vpxor	ymm6, ymm7, ymm6
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r14d
        add	r13d, edx
        mov	ecx, r14d
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r14d
        xor	ebx, r15d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r9d, r13d
        xor	ecx, r14d
        add	r13d, ebx
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r9d
        add	r13d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	ymm6, ymm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r14d
        mov	ecx, r10d
        add	r12d, DWORD PTR [rsp+332]
        xor	ecx, r11d
        vpsrlq	ymm8, ymm6, 17
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r9d
        and	ecx, r9d
        ror	edx, 5
        xor	ecx, r11d
        xor	edx, r9d
        add	r12d, ecx
        vpsrld	ymm9, ymm6, 10
        vpxor	ymm8, ymm7, ymm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r13d
        add	r12d, edx
        mov	ecx, r13d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r13d
        xor	eax, r14d
        vpxor	ymm9, ymm8, ymm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r8d, r12d
        xor	ecx, r13d
        add	r12d, eax
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r8d
        add	r12d, ecx
        vpaddd	ymm2, ymm9, ymm4
        ; msg_sched done: 80-83
        ; msg_sched: 88-91
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpalignr	ymm5, ymm0, ymm3, 4
        vpalignr	ymm4, ymm2, ymm1, 4
        ; rnd_0: 1 - 2
        mov	eax, r13d
        mov	ecx, r9d
        add	r11d, DWORD PTR [rsp+352]
        xor	ecx, r10d
        xor	edx, r8d
        and	ecx, r8d
        vpsrld	ymm6, ymm5, 7
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 3 - 4
        ror	edx, 5
        xor	ecx, r10d
        xor	edx, r8d
        add	r11d, ecx
        ror	edx, 6
        xor	eax, r12d
        add	r11d, edx
        mov	ecx, r12d
        vpsrld	ymm8, ymm5, 18
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 5 - 6
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r12d
        xor	ebx, r13d
        ror	ecx, 11
        add	r15d, r11d
        xor	ecx, r12d
        add	r11d, ebx
        vpor	ymm6, ymm7, ymm6
        vpor	ymm8, ymm9, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r15d
        add	r11d, ecx
        ; rnd_1: 0 - 1
        ror	edx, 14
        mov	ebx, r12d
        mov	ecx, r8d
        add	r10d, DWORD PTR [rsp+356]
        xor	ecx, r9d
        vpsrld	ymm9, ymm5, 3
        vpxor	ymm6, ymm8, ymm6
        ; rnd_1: 2 - 3
        xor	edx, r15d
        and	ecx, r15d
        ror	edx, 5
        xor	ecx, r9d
        xor	edx, r15d
        add	r10d, ecx
        vpxor	ymm5, ymm9, ymm6
        vpshufd	ymm6, ymm2, 250
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r11d
        add	r10d, edx
        mov	ecx, r11d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r11d
        xor	eax, r12d
        vpsrld	ymm8, ymm6, 10
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 6 - 7
        ror	ecx, 11
        add	r14d, r10d
        xor	ecx, r11d
        add	r10d, eax
        ror	ecx, 2
        mov	edx, r14d
        add	r10d, ecx
        ; rnd_0: 0 - 0
        ror	edx, 14
        vpsrlq	ymm6, ymm6, 17
        vpaddd	ymm4, ymm4, ymm3
        ; rnd_0: 1 - 3
        mov	eax, r11d
        mov	ecx, r15d
        add	r9d, DWORD PTR [rsp+360]
        xor	ecx, r8d
        xor	edx, r14d
        and	ecx, r14d
        ror	edx, 5
        xor	ecx, r8d
        xor	edx, r14d
        add	r9d, ecx
        vpxor	ymm6, ymm7, ymm6
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 4 - 4
        ror	edx, 6
        xor	eax, r10d
        add	r9d, edx
        mov	ecx, r10d
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 5 - 5
        and	ebx, eax
        ror	ecx, 9
        xor	ecx, r10d
        xor	ebx, r11d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 6 - 6
        ror	ecx, 11
        add	r13d, r9d
        xor	ecx, r10d
        add	r9d, ebx
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 7 - 7
        ror	ecx, 2
        mov	edx, r13d
        add	r9d, ecx
        ; rnd_1: 0 - 0
        ror	edx, 14
        vpshufd	ymm6, ymm4, 80
        ; rnd_1: 1 - 1
        mov	ebx, r10d
        mov	ecx, r14d
        add	r8d, DWORD PTR [rsp+364]
        xor	ecx, r15d
        vpsrlq	ymm8, ymm6, 17
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 2 - 3
        xor	edx, r13d
        and	ecx, r13d
        ror	edx, 5
        xor	ecx, r15d
        xor	edx, r13d
        add	r8d, ecx
        vpsrld	ymm9, ymm6, 10
        vpxor	ymm8, ymm7, ymm8
        ; rnd_1: 4 - 5
        ror	edx, 6
        xor	ebx, r9d
        add	r8d, edx
        mov	ecx, r9d
        and	eax, ebx
        ror	ecx, 9
        xor	ecx, r9d
        xor	eax, r10d
        vpxor	ymm9, ymm8, ymm9
        ; rnd_1: 6 - 6
        ror	ecx, 11
        add	r12d, r8d
        xor	ecx, r9d
        add	r8d, eax
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 7 - 7
        ror	ecx, 2
        mov	edx, r12d
        add	r8d, ecx
        vpaddd	ymm3, ymm9, ymm4
        ; msg_sched done: 88-91
        ; set_w_k_xfer_4: 12
        vpaddd	ymm4, ymm0, YMMWORD PTR [rbp+384]
        vpaddd	ymm5, ymm1, YMMWORD PTR [rbp+416]
        vmovdqu	YMMWORD PTR [rsp+384], ymm4
        vmovdqu	YMMWORD PTR [rsp+416], ymm5
        vpaddd	ymm4, ymm2, YMMWORD PTR [rbp+448]
        vpaddd	ymm5, ymm3, YMMWORD PTR [rbp+480]
        vmovdqu	YMMWORD PTR [rsp+448], ymm4
        vmovdqu	YMMWORD PTR [rsp+480], ymm5
        ; rnd_all_4: 24-27
        add	r15d, DWORD PTR [rsp+384]
        mov	ecx, r13d
        mov	eax, r9d
        xor	ecx, r14d
        ror	edx, 14
        and	ecx, r12d
        xor	edx, r12d
        xor	ecx, r14d
        ror	edx, 5
        add	r15d, ecx
        xor	edx, r12d
        xor	eax, r8d
        ror	edx, 6
        mov	ecx, r8d
        add	r15d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r8d
        xor	ebx, r9d
        ror	ecx, 11
        add	r11d, r15d
        xor	ecx, r8d
        add	r15d, ebx
        ror	ecx, 2
        mov	edx, r11d
        add	r15d, ecx
        add	r14d, DWORD PTR [rsp+388]
        mov	ecx, r12d
        mov	ebx, r8d
        xor	ecx, r13d
        ror	edx, 14
        and	ecx, r11d
        xor	edx, r11d
        xor	ecx, r13d
        ror	edx, 5
        add	r14d, ecx
        xor	edx, r11d
        xor	ebx, r15d
        ror	edx, 6
        mov	ecx, r15d
        add	r14d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r15d
        xor	eax, r8d
        ror	ecx, 11
        add	r10d, r14d
        xor	ecx, r15d
        add	r14d, eax
        ror	ecx, 2
        mov	edx, r10d
        add	r14d, ecx
        add	r13d, DWORD PTR [rsp+392]
        mov	ecx, r11d
        mov	eax, r15d
        xor	ecx, r12d
        ror	edx, 14
        and	ecx, r10d
        xor	edx, r10d
        xor	ecx, r12d
        ror	edx, 5
        add	r13d, ecx
        xor	edx, r10d
        xor	eax, r14d
        ror	edx, 6
        mov	ecx, r14d
        add	r13d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r14d
        xor	ebx, r15d
        ror	ecx, 11
        add	r9d, r13d
        xor	ecx, r14d
        add	r13d, ebx
        ror	ecx, 2
        mov	edx, r9d
        add	r13d, ecx
        add	r12d, DWORD PTR [rsp+396]
        mov	ecx, r10d
        mov	ebx, r14d
        xor	ecx, r11d
        ror	edx, 14
        and	ecx, r9d
        xor	edx, r9d
        xor	ecx, r11d
        ror	edx, 5
        add	r12d, ecx
        xor	edx, r9d
        xor	ebx, r13d
        ror	edx, 6
        mov	ecx, r13d
        add	r12d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r13d
        xor	eax, r14d
        ror	ecx, 11
        add	r8d, r12d
        xor	ecx, r13d
        add	r12d, eax
        ror	ecx, 2
        mov	edx, r8d
        add	r12d, ecx
        ; rnd_all_4: 26-29
        add	r11d, DWORD PTR [rsp+416]
        mov	ecx, r9d
        mov	eax, r13d
        xor	ecx, r10d
        ror	edx, 14
        and	ecx, r8d
        xor	edx, r8d
        xor	ecx, r10d
        ror	edx, 5
        add	r11d, ecx
        xor	edx, r8d
        xor	eax, r12d
        ror	edx, 6
        mov	ecx, r12d
        add	r11d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r12d
        xor	ebx, r13d
        ror	ecx, 11
        add	r15d, r11d
        xor	ecx, r12d
        add	r11d, ebx
        ror	ecx, 2
        mov	edx, r15d
        add	r11d, ecx
        add	r10d, DWORD PTR [rsp+420]
        mov	ecx, r8d
        mov	ebx, r12d
        xor	ecx, r9d
        ror	edx, 14
        and	ecx, r15d
        xor	edx, r15d
        xor	ecx, r9d
        ror	edx, 5
        add	r10d, ecx
        xor	edx, r15d
        xor	ebx, r11d
        ror	edx, 6
        mov	ecx, r11d
        add	r10d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r11d
        xor	eax, r12d
        ror	ecx, 11
        add	r14d, r10d
        xor	ecx, r11d
        add	r10d, eax
        ror	ecx, 2
        mov	edx, r14d
        add	r10d, ecx
        add	r9d, DWORD PTR [rsp+424]
        mov	ecx, r15d
        mov	eax, r11d
        xor	ecx, r8d
        ror	edx, 14
        and	ecx, r14d
        xor	edx, r14d
        xor	ecx, r8d
        ror	edx, 5
        add	r9d, ecx
        xor	edx, r14d
        xor	eax, r10d
        ror	edx, 6
        mov	ecx, r10d
        add	r9d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r10d
        xor	ebx, r11d
        ror	ecx, 11
        add	r13d, r9d
        xor	ecx, r10d
        add	r9d, ebx
        ror	ecx, 2
        mov	edx, r13d
        add	r9d, ecx
        add	r8d, DWORD PTR [rsp+428]
        mov	ecx, r14d
        mov	ebx, r10d
        xor	ecx, r15d
        ror	edx, 14
        and	ecx, r13d
        xor	edx, r13d
        xor	ecx, r15d
        ror	edx, 5
        add	r8d, ecx
        xor	edx, r13d
        xor	ebx, r9d
        ror	edx, 6
        mov	ecx, r9d
        add	r8d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r9d
        xor	eax, r10d
        ror	ecx, 11
        add	r12d, r8d
        xor	ecx, r9d
        add	r8d, eax
        ror	ecx, 2
        mov	edx, r12d
        add	r8d, ecx
        ; rnd_all_4: 28-31
        add	r15d, DWORD PTR [rsp+448]
        mov	ecx, r13d
        mov	eax, r9d
        xor	ecx, r14d
        ror	edx, 14
        and	ecx, r12d
        xor	edx, r12d
        xor	ecx, r14d
        ror	edx, 5
        add	r15d, ecx
        xor	edx, r12d
        xor	eax, r8d
        ror	edx, 6
        mov	ecx, r8d
        add	r15d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r8d
        xor	ebx, r9d
        ror	ecx, 11
        add	r11d, r15d
        xor	ecx, r8d
        add	r15d, ebx
        ror	ecx, 2
        mov	edx, r11d
        add	r15d, ecx
        add	r14d, DWORD PTR [rsp+452]
        mov	ecx, r12d
        mov	ebx, r8d
        xor	ecx, r13d
        ror	edx, 14
        and	ecx, r11d
        xor	edx, r11d
        xor	ecx, r13d
        ror	edx, 5
        add	r14d, ecx
        xor	edx, r11d
        xor	ebx, r15d
        ror	edx, 6
        mov	ecx, r15d
        add	r14d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r15d
        xor	eax, r8d
        ror	ecx, 11
        add	r10d, r14d
        xor	ecx, r15d
        add	r14d, eax
        ror	ecx, 2
        mov	edx, r10d
        add	r14d, ecx
        add	r13d, DWORD PTR [rsp+456]
        mov	ecx, r11d
        mov	eax, r15d
        xor	ecx, r12d
        ror	edx, 14
        and	ecx, r10d
        xor	edx, r10d
        xor	ecx, r12d
        ror	edx, 5
        add	r13d, ecx
        xor	edx, r10d
        xor	eax, r14d
        ror	edx, 6
        mov	ecx, r14d
        add	r13d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r14d
        xor	ebx, r15d
        ror	ecx, 11
        add	r9d, r13d
        xor	ecx, r14d
        add	r13d, ebx
        ror	ecx, 2
        mov	edx, r9d
        add	r13d, ecx
        add	r12d, DWORD PTR [rsp+460]
        mov	ecx, r10d
        mov	ebx, r14d
        xor	ecx, r11d
        ror	edx, 14
        and	ecx, r9d
        xor	edx, r9d
        xor	ecx, r11d
        ror	edx, 5
        add	r12d, ecx
        xor	edx, r9d
        xor	ebx, r13d
        ror	edx, 6
        mov	ecx, r13d
        add	r12d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r13d
        xor	eax, r14d
        ror	ecx, 11
        add	r8d, r12d
        xor	ecx, r13d
        add	r12d, eax
        ror	ecx, 2
        mov	edx, r8d
        add	r12d, ecx
        ; rnd_all_4: 30-33
        add	r11d, DWORD PTR [rsp+480]
        mov	ecx, r9d
        mov	eax, r13d
        xor	ecx, r10d
        ror	edx, 14
        and	ecx, r8d
        xor	edx, r8d
        xor	ecx, r10d
        ror	edx, 5
        add	r11d, ecx
        xor	edx, r8d
        xor	eax, r12d
        ror	edx, 6
        mov	ecx, r12d
        add	r11d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r12d
        xor	ebx, r13d
        ror	ecx, 11
        add	r15d, r11d
        xor	ecx, r12d
        add	r11d, ebx
        ror	ecx, 2
        mov	edx, r15d
        add	r11d, ecx
        add	r10d, DWORD PTR [rsp+484]
        mov	ecx, r8d
        mov	ebx, r12d
        xor	ecx, r9d
        ror	edx, 14
        and	ecx, r15d
        xor	edx, r15d
        xor	ecx, r9d
        ror	edx, 5
        add	r10d, ecx
        xor	edx, r15d
        xor	ebx, r11d
        ror	edx, 6
        mov	ecx, r11d
        add	r10d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r11d
        xor	eax, r12d
        ror	ecx, 11
        add	r14d, r10d
        xor	ecx, r11d
        add	r10d, eax
        ror	ecx, 2
        mov	edx, r14d
        add	r10d, ecx
        add	r9d, DWORD PTR [rsp+488]
        mov	ecx, r15d
        mov	eax, r11d
        xor	ecx, r8d
        ror	edx, 14
        and	ecx, r14d
        xor	edx, r14d
        xor	ecx, r8d
        ror	edx, 5
        add	r9d, ecx
        xor	edx, r14d
        xor	eax, r10d
        ror	edx, 6
        mov	ecx, r10d
        add	r9d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r10d
        xor	ebx, r11d
        ror	ecx, 11
        add	r13d, r9d
        xor	ecx, r10d
        add	r9d, ebx
        ror	ecx, 2
        mov	edx, r13d
        add	r9d, ecx
        add	r8d, DWORD PTR [rsp+492]
        mov	ecx, r14d
        mov	ebx, r10d
        xor	ecx, r15d
        ror	edx, 14
        and	ecx, r13d
        xor	edx, r13d
        xor	ecx, r15d
        ror	edx, 5
        add	r8d, ecx
        xor	edx, r13d
        xor	ebx, r9d
        ror	edx, 6
        mov	ecx, r9d
        add	r8d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r9d
        xor	eax, r10d
        ror	ecx, 11
        add	r12d, r8d
        xor	ecx, r9d
        add	r8d, eax
        ror	ecx, 2
        mov	edx, r12d
        add	r8d, ecx
        add	r8d, DWORD PTR [rdi]
        add	r9d, DWORD PTR [rdi+4]
        add	r10d, DWORD PTR [rdi+8]
        add	r11d, DWORD PTR [rdi+12]
        add	r12d, DWORD PTR [rdi+16]
        add	r13d, DWORD PTR [rdi+20]
        add	r14d, DWORD PTR [rdi+24]
        add	r15d, DWORD PTR [rdi+28]
        mov	DWORD PTR [rdi], r8d
        mov	DWORD PTR [rdi+4], r9d
        mov	DWORD PTR [rdi+8], r10d
        mov	DWORD PTR [rdi+12], r11d
        mov	DWORD PTR [rdi+16], r12d
        mov	DWORD PTR [rdi+20], r13d
        mov	DWORD PTR [rdi+24], r14d
        mov	DWORD PTR [rdi+28], r15d
        mov	ebx, r9d
        mov	edx, r12d
        xor	ebx, r10d
        ; rnd_all_4: 1-4
        add	r15d, DWORD PTR [rsp+16]
        mov	ecx, r13d
        mov	eax, r9d
        xor	ecx, r14d
        ror	edx, 14
        and	ecx, r12d
        xor	edx, r12d
        xor	ecx, r14d
        ror	edx, 5
        add	r15d, ecx
        xor	edx, r12d
        xor	eax, r8d
        ror	edx, 6
        mov	ecx, r8d
        add	r15d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r8d
        xor	ebx, r9d
        ror	ecx, 11
        add	r11d, r15d
        xor	ecx, r8d
        add	r15d, ebx
        ror	ecx, 2
        mov	edx, r11d
        add	r15d, ecx
        add	r14d, DWORD PTR [rsp+20]
        mov	ecx, r12d
        mov	ebx, r8d
        xor	ecx, r13d
        ror	edx, 14
        and	ecx, r11d
        xor	edx, r11d
        xor	ecx, r13d
        ror	edx, 5
        add	r14d, ecx
        xor	edx, r11d
        xor	ebx, r15d
        ror	edx, 6
        mov	ecx, r15d
        add	r14d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r15d
        xor	eax, r8d
        ror	ecx, 11
        add	r10d, r14d
        xor	ecx, r15d
        add	r14d, eax
        ror	ecx, 2
        mov	edx, r10d
        add	r14d, ecx
        add	r13d, DWORD PTR [rsp+24]
        mov	ecx, r11d
        mov	eax, r15d
        xor	ecx, r12d
        ror	edx, 14
        and	ecx, r10d
        xor	edx, r10d
        xor	ecx, r12d
        ror	edx, 5
        add	r13d, ecx
        xor	edx, r10d
        xor	eax, r14d
        ror	edx, 6
        mov	ecx, r14d
        add	r13d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r14d
        xor	ebx, r15d
        ror	ecx, 11
        add	r9d, r13d
        xor	ecx, r14d
        add	r13d, ebx
        ror	ecx, 2
        mov	edx, r9d
        add	r13d, ecx
        add	r12d, DWORD PTR [rsp+28]
        mov	ecx, r10d
        mov	ebx, r14d
        xor	ecx, r11d
        ror	edx, 14
        and	ecx, r9d
        xor	edx, r9d
        xor	ecx, r11d
        ror	edx, 5
        add	r12d, ecx
        xor	edx, r9d
        xor	ebx, r13d
        ror	edx, 6
        mov	ecx, r13d
        add	r12d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r13d
        xor	eax, r14d
        ror	ecx, 11
        add	r8d, r12d
        xor	ecx, r13d
        add	r12d, eax
        ror	ecx, 2
        mov	edx, r8d
        add	r12d, ecx
        ; rnd_all_4: 3-6
        add	r11d, DWORD PTR [rsp+48]
        mov	ecx, r9d
        mov	eax, r13d
        xor	ecx, r10d
        ror	edx, 14
        and	ecx, r8d
        xor	edx, r8d
        xor	ecx, r10d
        ror	edx, 5
        add	r11d, ecx
        xor	edx, r8d
        xor	eax, r12d
        ror	edx, 6
        mov	ecx, r12d
        add	r11d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r12d
        xor	ebx, r13d
        ror	ecx, 11
        add	r15d, r11d
        xor	ecx, r12d
        add	r11d, ebx
        ror	ecx, 2
        mov	edx, r15d
        add	r11d, ecx
        add	r10d, DWORD PTR [rsp+52]
        mov	ecx, r8d
        mov	ebx, r12d
        xor	ecx, r9d
        ror	edx, 14
        and	ecx, r15d
        xor	edx, r15d
        xor	ecx, r9d
        ror	edx, 5
        add	r10d, ecx
        xor	edx, r15d
        xor	ebx, r11d
        ror	edx, 6
        mov	ecx, r11d
        add	r10d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r11d
        xor	eax, r12d
        ror	ecx, 11
        add	r14d, r10d
        xor	ecx, r11d
        add	r10d, eax
        ror	ecx, 2
        mov	edx, r14d
        add	r10d, ecx
        add	r9d, DWORD PTR [rsp+56]
        mov	ecx, r15d
        mov	eax, r11d
        xor	ecx, r8d
        ror	edx, 14
        and	ecx, r14d
        xor	edx, r14d
        xor	ecx, r8d
        ror	edx, 5
        add	r9d, ecx
        xor	edx, r14d
        xor	eax, r10d
        ror	edx, 6
        mov	ecx, r10d
        add	r9d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r10d
        xor	ebx, r11d
        ror	ecx, 11
        add	r13d, r9d
        xor	ecx, r10d
        add	r9d, ebx
        ror	ecx, 2
        mov	edx, r13d
        add	r9d, ecx
        add	r8d, DWORD PTR [rsp+60]
        mov	ecx, r14d
        mov	ebx, r10d
        xor	ecx, r15d
        ror	edx, 14
        and	ecx, r13d
        xor	edx, r13d
        xor	ecx, r15d
        ror	edx, 5
        add	r8d, ecx
        xor	edx, r13d
        xor	ebx, r9d
        ror	edx, 6
        mov	ecx, r9d
        add	r8d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r9d
        xor	eax, r10d
        ror	ecx, 11
        add	r12d, r8d
        xor	ecx, r9d
        add	r8d, eax
        ror	ecx, 2
        mov	edx, r12d
        add	r8d, ecx
        ; rnd_all_4: 5-8
        add	r15d, DWORD PTR [rsp+80]
        mov	ecx, r13d
        mov	eax, r9d
        xor	ecx, r14d
        ror	edx, 14
        and	ecx, r12d
        xor	edx, r12d
        xor	ecx, r14d
        ror	edx, 5
        add	r15d, ecx
        xor	edx, r12d
        xor	eax, r8d
        ror	edx, 6
        mov	ecx, r8d
        add	r15d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r8d
        xor	ebx, r9d
        ror	ecx, 11
        add	r11d, r15d
        xor	ecx, r8d
        add	r15d, ebx
        ror	ecx, 2
        mov	edx, r11d
        add	r15d, ecx
        add	r14d, DWORD PTR [rsp+84]
        mov	ecx, r12d
        mov	ebx, r8d
        xor	ecx, r13d
        ror	edx, 14
        and	ecx, r11d
        xor	edx, r11d
        xor	ecx, r13d
        ror	edx, 5
        add	r14d, ecx
        xor	edx, r11d
        xor	ebx, r15d
        ror	edx, 6
        mov	ecx, r15d
        add	r14d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r15d
        xor	eax, r8d
        ror	ecx, 11
        add	r10d, r14d
        xor	ecx, r15d
        add	r14d, eax
        ror	ecx, 2
        mov	edx, r10d
        add	r14d, ecx
        add	r13d, DWORD PTR [rsp+88]
        mov	ecx, r11d
        mov	eax, r15d
        xor	ecx, r12d
        ror	edx, 14
        and	ecx, r10d
        xor	edx, r10d
        xor	ecx, r12d
        ror	edx, 5
        add	r13d, ecx
        xor	edx, r10d
        xor	eax, r14d
        ror	edx, 6
        mov	ecx, r14d
        add	r13d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r14d
        xor	ebx, r15d
        ror	ecx, 11
        add	r9d, r13d
        xor	ecx, r14d
        add	r13d, ebx
        ror	ecx, 2
        mov	edx, r9d
        add	r13d, ecx
        add	r12d, DWORD PTR [rsp+92]
        mov	ecx, r10d
        mov	ebx, r14d
        xor	ecx, r11d
        ror	edx, 14
        and	ecx, r9d
        xor	edx, r9d
        xor	ecx, r11d
        ror	edx, 5
        add	r12d, ecx
        xor	edx, r9d
        xor	ebx, r13d
        ror	edx, 6
        mov	ecx, r13d
        add	r12d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r13d
        xor	eax, r14d
        ror	ecx, 11
        add	r8d, r12d
        xor	ecx, r13d
        add	r12d, eax
        ror	ecx, 2
        mov	edx, r8d
        add	r12d, ecx
        ; rnd_all_4: 7-10
        add	r11d, DWORD PTR [rsp+112]
        mov	ecx, r9d
        mov	eax, r13d
        xor	ecx, r10d
        ror	edx, 14
        and	ecx, r8d
        xor	edx, r8d
        xor	ecx, r10d
        ror	edx, 5
        add	r11d, ecx
        xor	edx, r8d
        xor	eax, r12d
        ror	edx, 6
        mov	ecx, r12d
        add	r11d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r12d
        xor	ebx, r13d
        ror	ecx, 11
        add	r15d, r11d
        xor	ecx, r12d
        add	r11d, ebx
        ror	ecx, 2
        mov	edx, r15d
        add	r11d, ecx
        add	r10d, DWORD PTR [rsp+116]
        mov	ecx, r8d
        mov	ebx, r12d
        xor	ecx, r9d
        ror	edx, 14
        and	ecx, r15d
        xor	edx, r15d
        xor	ecx, r9d
        ror	edx, 5
        add	r10d, ecx
        xor	edx, r15d
        xor	ebx, r11d
        ror	edx, 6
        mov	ecx, r11d
        add	r10d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r11d
        xor	eax, r12d
        ror	ecx, 11
        add	r14d, r10d
        xor	ecx, r11d
        add	r10d, eax
        ror	ecx, 2
        mov	edx, r14d
        add	r10d, ecx
        add	r9d, DWORD PTR [rsp+120]
        mov	ecx, r15d
        mov	eax, r11d
        xor	ecx, r8d
        ror	edx, 14
        and	ecx, r14d
        xor	edx, r14d
        xor	ecx, r8d
        ror	edx, 5
        add	r9d, ecx
        xor	edx, r14d
        xor	eax, r10d
        ror	edx, 6
        mov	ecx, r10d
        add	r9d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r10d
        xor	ebx, r11d
        ror	ecx, 11
        add	r13d, r9d
        xor	ecx, r10d
        add	r9d, ebx
        ror	ecx, 2
        mov	edx, r13d
        add	r9d, ecx
        add	r8d, DWORD PTR [rsp+124]
        mov	ecx, r14d
        mov	ebx, r10d
        xor	ecx, r15d
        ror	edx, 14
        and	ecx, r13d
        xor	edx, r13d
        xor	ecx, r15d
        ror	edx, 5
        add	r8d, ecx
        xor	edx, r13d
        xor	ebx, r9d
        ror	edx, 6
        mov	ecx, r9d
        add	r8d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r9d
        xor	eax, r10d
        ror	ecx, 11
        add	r12d, r8d
        xor	ecx, r9d
        add	r8d, eax
        ror	ecx, 2
        mov	edx, r12d
        add	r8d, ecx
        ; rnd_all_4: 9-12
        add	r15d, DWORD PTR [rsp+144]
        mov	ecx, r13d
        mov	eax, r9d
        xor	ecx, r14d
        ror	edx, 14
        and	ecx, r12d
        xor	edx, r12d
        xor	ecx, r14d
        ror	edx, 5
        add	r15d, ecx
        xor	edx, r12d
        xor	eax, r8d
        ror	edx, 6
        mov	ecx, r8d
        add	r15d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r8d
        xor	ebx, r9d
        ror	ecx, 11
        add	r11d, r15d
        xor	ecx, r8d
        add	r15d, ebx
        ror	ecx, 2
        mov	edx, r11d
        add	r15d, ecx
        add	r14d, DWORD PTR [rsp+148]
        mov	ecx, r12d
        mov	ebx, r8d
        xor	ecx, r13d
        ror	edx, 14
        and	ecx, r11d
        xor	edx, r11d
        xor	ecx, r13d
        ror	edx, 5
        add	r14d, ecx
        xor	edx, r11d
        xor	ebx, r15d
        ror	edx, 6
        mov	ecx, r15d
        add	r14d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r15d
        xor	eax, r8d
        ror	ecx, 11
        add	r10d, r14d
        xor	ecx, r15d
        add	r14d, eax
        ror	ecx, 2
        mov	edx, r10d
        add	r14d, ecx
        add	r13d, DWORD PTR [rsp+152]
        mov	ecx, r11d
        mov	eax, r15d
        xor	ecx, r12d
        ror	edx, 14
        and	ecx, r10d
        xor	edx, r10d
        xor	ecx, r12d
        ror	edx, 5
        add	r13d, ecx
        xor	edx, r10d
        xor	eax, r14d
        ror	edx, 6
        mov	ecx, r14d
        add	r13d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r14d
        xor	ebx, r15d
        ror	ecx, 11
        add	r9d, r13d
        xor	ecx, r14d
        add	r13d, ebx
        ror	ecx, 2
        mov	edx, r9d
        add	r13d, ecx
        add	r12d, DWORD PTR [rsp+156]
        mov	ecx, r10d
        mov	ebx, r14d
        xor	ecx, r11d
        ror	edx, 14
        and	ecx, r9d
        xor	edx, r9d
        xor	ecx, r11d
        ror	edx, 5
        add	r12d, ecx
        xor	edx, r9d
        xor	ebx, r13d
        ror	edx, 6
        mov	ecx, r13d
        add	r12d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r13d
        xor	eax, r14d
        ror	ecx, 11
        add	r8d, r12d
        xor	ecx, r13d
        add	r12d, eax
        ror	ecx, 2
        mov	edx, r8d
        add	r12d, ecx
        ; rnd_all_4: 11-14
        add	r11d, DWORD PTR [rsp+176]
        mov	ecx, r9d
        mov	eax, r13d
        xor	ecx, r10d
        ror	edx, 14
        and	ecx, r8d
        xor	edx, r8d
        xor	ecx, r10d
        ror	edx, 5
        add	r11d, ecx
        xor	edx, r8d
        xor	eax, r12d
        ror	edx, 6
        mov	ecx, r12d
        add	r11d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r12d
        xor	ebx, r13d
        ror	ecx, 11
        add	r15d, r11d
        xor	ecx, r12d
        add	r11d, ebx
        ror	ecx, 2
        mov	edx, r15d
        add	r11d, ecx
        add	r10d, DWORD PTR [rsp+180]
        mov	ecx, r8d
        mov	ebx, r12d
        xor	ecx, r9d
        ror	edx, 14
        and	ecx, r15d
        xor	edx, r15d
        xor	ecx, r9d
        ror	edx, 5
        add	r10d, ecx
        xor	edx, r15d
        xor	ebx, r11d
        ror	edx, 6
        mov	ecx, r11d
        add	r10d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r11d
        xor	eax, r12d
        ror	ecx, 11
        add	r14d, r10d
        xor	ecx, r11d
        add	r10d, eax
        ror	ecx, 2
        mov	edx, r14d
        add	r10d, ecx
        add	r9d, DWORD PTR [rsp+184]
        mov	ecx, r15d
        mov	eax, r11d
        xor	ecx, r8d
        ror	edx, 14
        and	ecx, r14d
        xor	edx, r14d
        xor	ecx, r8d
        ror	edx, 5
        add	r9d, ecx
        xor	edx, r14d
        xor	eax, r10d
        ror	edx, 6
        mov	ecx, r10d
        add	r9d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r10d
        xor	ebx, r11d
        ror	ecx, 11
        add	r13d, r9d
        xor	ecx, r10d
        add	r9d, ebx
        ror	ecx, 2
        mov	edx, r13d
        add	r9d, ecx
        add	r8d, DWORD PTR [rsp+188]
        mov	ecx, r14d
        mov	ebx, r10d
        xor	ecx, r15d
        ror	edx, 14
        and	ecx, r13d
        xor	edx, r13d
        xor	ecx, r15d
        ror	edx, 5
        add	r8d, ecx
        xor	edx, r13d
        xor	ebx, r9d
        ror	edx, 6
        mov	ecx, r9d
        add	r8d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r9d
        xor	eax, r10d
        ror	ecx, 11
        add	r12d, r8d
        xor	ecx, r9d
        add	r8d, eax
        ror	ecx, 2
        mov	edx, r12d
        add	r8d, ecx
        ; rnd_all_4: 13-16
        add	r15d, DWORD PTR [rsp+208]
        mov	ecx, r13d
        mov	eax, r9d
        xor	ecx, r14d
        ror	edx, 14
        and	ecx, r12d
        xor	edx, r12d
        xor	ecx, r14d
        ror	edx, 5
        add	r15d, ecx
        xor	edx, r12d
        xor	eax, r8d
        ror	edx, 6
        mov	ecx, r8d
        add	r15d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r8d
        xor	ebx, r9d
        ror	ecx, 11
        add	r11d, r15d
        xor	ecx, r8d
        add	r15d, ebx
        ror	ecx, 2
        mov	edx, r11d
        add	r15d, ecx
        add	r14d, DWORD PTR [rsp+212]
        mov	ecx, r12d
        mov	ebx, r8d
        xor	ecx, r13d
        ror	edx, 14
        and	ecx, r11d
        xor	edx, r11d
        xor	ecx, r13d
        ror	edx, 5
        add	r14d, ecx
        xor	edx, r11d
        xor	ebx, r15d
        ror	edx, 6
        mov	ecx, r15d
        add	r14d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r15d
        xor	eax, r8d
        ror	ecx, 11
        add	r10d, r14d
        xor	ecx, r15d
        add	r14d, eax
        ror	ecx, 2
        mov	edx, r10d
        add	r14d, ecx
        add	r13d, DWORD PTR [rsp+216]
        mov	ecx, r11d
        mov	eax, r15d
        xor	ecx, r12d
        ror	edx, 14
        and	ecx, r10d
        xor	edx, r10d
        xor	ecx, r12d
        ror	edx, 5
        add	r13d, ecx
        xor	edx, r10d
        xor	eax, r14d
        ror	edx, 6
        mov	ecx, r14d
        add	r13d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r14d
        xor	ebx, r15d
        ror	ecx, 11
        add	r9d, r13d
        xor	ecx, r14d
        add	r13d, ebx
        ror	ecx, 2
        mov	edx, r9d
        add	r13d, ecx
        add	r12d, DWORD PTR [rsp+220]
        mov	ecx, r10d
        mov	ebx, r14d
        xor	ecx, r11d
        ror	edx, 14
        and	ecx, r9d
        xor	edx, r9d
        xor	ecx, r11d
        ror	edx, 5
        add	r12d, ecx
        xor	edx, r9d
        xor	ebx, r13d
        ror	edx, 6
        mov	ecx, r13d
        add	r12d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r13d
        xor	eax, r14d
        ror	ecx, 11
        add	r8d, r12d
        xor	ecx, r13d
        add	r12d, eax
        ror	ecx, 2
        mov	edx, r8d
        add	r12d, ecx
        ; rnd_all_4: 15-18
        add	r11d, DWORD PTR [rsp+240]
        mov	ecx, r9d
        mov	eax, r13d
        xor	ecx, r10d
        ror	edx, 14
        and	ecx, r8d
        xor	edx, r8d
        xor	ecx, r10d
        ror	edx, 5
        add	r11d, ecx
        xor	edx, r8d
        xor	eax, r12d
        ror	edx, 6
        mov	ecx, r12d
        add	r11d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r12d
        xor	ebx, r13d
        ror	ecx, 11
        add	r15d, r11d
        xor	ecx, r12d
        add	r11d, ebx
        ror	ecx, 2
        mov	edx, r15d
        add	r11d, ecx
        add	r10d, DWORD PTR [rsp+244]
        mov	ecx, r8d
        mov	ebx, r12d
        xor	ecx, r9d
        ror	edx, 14
        and	ecx, r15d
        xor	edx, r15d
        xor	ecx, r9d
        ror	edx, 5
        add	r10d, ecx
        xor	edx, r15d
        xor	ebx, r11d
        ror	edx, 6
        mov	ecx, r11d
        add	r10d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r11d
        xor	eax, r12d
        ror	ecx, 11
        add	r14d, r10d
        xor	ecx, r11d
        add	r10d, eax
        ror	ecx, 2
        mov	edx, r14d
        add	r10d, ecx
        add	r9d, DWORD PTR [rsp+248]
        mov	ecx, r15d
        mov	eax, r11d
        xor	ecx, r8d
        ror	edx, 14
        and	ecx, r14d
        xor	edx, r14d
        xor	ecx, r8d
        ror	edx, 5
        add	r9d, ecx
        xor	edx, r14d
        xor	eax, r10d
        ror	edx, 6
        mov	ecx, r10d
        add	r9d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r10d
        xor	ebx, r11d
        ror	ecx, 11
        add	r13d, r9d
        xor	ecx, r10d
        add	r9d, ebx
        ror	ecx, 2
        mov	edx, r13d
        add	r9d, ecx
        add	r8d, DWORD PTR [rsp+252]
        mov	ecx, r14d
        mov	ebx, r10d
        xor	ecx, r15d
        ror	edx, 14
        and	ecx, r13d
        xor	edx, r13d
        xor	ecx, r15d
        ror	edx, 5
        add	r8d, ecx
        xor	edx, r13d
        xor	ebx, r9d
        ror	edx, 6
        mov	ecx, r9d
        add	r8d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r9d
        xor	eax, r10d
        ror	ecx, 11
        add	r12d, r8d
        xor	ecx, r9d
        add	r8d, eax
        ror	ecx, 2
        mov	edx, r12d
        add	r8d, ecx
        ; rnd_all_4: 17-20
        add	r15d, DWORD PTR [rsp+272]
        mov	ecx, r13d
        mov	eax, r9d
        xor	ecx, r14d
        ror	edx, 14
        and	ecx, r12d
        xor	edx, r12d
        xor	ecx, r14d
        ror	edx, 5
        add	r15d, ecx
        xor	edx, r12d
        xor	eax, r8d
        ror	edx, 6
        mov	ecx, r8d
        add	r15d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r8d
        xor	ebx, r9d
        ror	ecx, 11
        add	r11d, r15d
        xor	ecx, r8d
        add	r15d, ebx
        ror	ecx, 2
        mov	edx, r11d
        add	r15d, ecx
        add	r14d, DWORD PTR [rsp+276]
        mov	ecx, r12d
        mov	ebx, r8d
        xor	ecx, r13d
        ror	edx, 14
        and	ecx, r11d
        xor	edx, r11d
        xor	ecx, r13d
        ror	edx, 5
        add	r14d, ecx
        xor	edx, r11d
        xor	ebx, r15d
        ror	edx, 6
        mov	ecx, r15d
        add	r14d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r15d
        xor	eax, r8d
        ror	ecx, 11
        add	r10d, r14d
        xor	ecx, r15d
        add	r14d, eax
        ror	ecx, 2
        mov	edx, r10d
        add	r14d, ecx
        add	r13d, DWORD PTR [rsp+280]
        mov	ecx, r11d
        mov	eax, r15d
        xor	ecx, r12d
        ror	edx, 14
        and	ecx, r10d
        xor	edx, r10d
        xor	ecx, r12d
        ror	edx, 5
        add	r13d, ecx
        xor	edx, r10d
        xor	eax, r14d
        ror	edx, 6
        mov	ecx, r14d
        add	r13d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r14d
        xor	ebx, r15d
        ror	ecx, 11
        add	r9d, r13d
        xor	ecx, r14d
        add	r13d, ebx
        ror	ecx, 2
        mov	edx, r9d
        add	r13d, ecx
        add	r12d, DWORD PTR [rsp+284]
        mov	ecx, r10d
        mov	ebx, r14d
        xor	ecx, r11d
        ror	edx, 14
        and	ecx, r9d
        xor	edx, r9d
        xor	ecx, r11d
        ror	edx, 5
        add	r12d, ecx
        xor	edx, r9d
        xor	ebx, r13d
        ror	edx, 6
        mov	ecx, r13d
        add	r12d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r13d
        xor	eax, r14d
        ror	ecx, 11
        add	r8d, r12d
        xor	ecx, r13d
        add	r12d, eax
        ror	ecx, 2
        mov	edx, r8d
        add	r12d, ecx
        ; rnd_all_4: 19-22
        add	r11d, DWORD PTR [rsp+304]
        mov	ecx, r9d
        mov	eax, r13d
        xor	ecx, r10d
        ror	edx, 14
        and	ecx, r8d
        xor	edx, r8d
        xor	ecx, r10d
        ror	edx, 5
        add	r11d, ecx
        xor	edx, r8d
        xor	eax, r12d
        ror	edx, 6
        mov	ecx, r12d
        add	r11d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r12d
        xor	ebx, r13d
        ror	ecx, 11
        add	r15d, r11d
        xor	ecx, r12d
        add	r11d, ebx
        ror	ecx, 2
        mov	edx, r15d
        add	r11d, ecx
        add	r10d, DWORD PTR [rsp+308]
        mov	ecx, r8d
        mov	ebx, r12d
        xor	ecx, r9d
        ror	edx, 14
        and	ecx, r15d
        xor	edx, r15d
        xor	ecx, r9d
        ror	edx, 5
        add	r10d, ecx
        xor	edx, r15d
        xor	ebx, r11d
        ror	edx, 6
        mov	ecx, r11d
        add	r10d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r11d
        xor	eax, r12d
        ror	ecx, 11
        add	r14d, r10d
        xor	ecx, r11d
        add	r10d, eax
        ror	ecx, 2
        mov	edx, r14d
        add	r10d, ecx
        add	r9d, DWORD PTR [rsp+312]
        mov	ecx, r15d
        mov	eax, r11d
        xor	ecx, r8d
        ror	edx, 14
        and	ecx, r14d
        xor	edx, r14d
        xor	ecx, r8d
        ror	edx, 5
        add	r9d, ecx
        xor	edx, r14d
        xor	eax, r10d
        ror	edx, 6
        mov	ecx, r10d
        add	r9d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r10d
        xor	ebx, r11d
        ror	ecx, 11
        add	r13d, r9d
        xor	ecx, r10d
        add	r9d, ebx
        ror	ecx, 2
        mov	edx, r13d
        add	r9d, ecx
        add	r8d, DWORD PTR [rsp+316]
        mov	ecx, r14d
        mov	ebx, r10d
        xor	ecx, r15d
        ror	edx, 14
        and	ecx, r13d
        xor	edx, r13d
        xor	ecx, r15d
        ror	edx, 5
        add	r8d, ecx
        xor	edx, r13d
        xor	ebx, r9d
        ror	edx, 6
        mov	ecx, r9d
        add	r8d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r9d
        xor	eax, r10d
        ror	ecx, 11
        add	r12d, r8d
        xor	ecx, r9d
        add	r8d, eax
        ror	ecx, 2
        mov	edx, r12d
        add	r8d, ecx
        ; rnd_all_4: 21-24
        add	r15d, DWORD PTR [rsp+336]
        mov	ecx, r13d
        mov	eax, r9d
        xor	ecx, r14d
        ror	edx, 14
        and	ecx, r12d
        xor	edx, r12d
        xor	ecx, r14d
        ror	edx, 5
        add	r15d, ecx
        xor	edx, r12d
        xor	eax, r8d
        ror	edx, 6
        mov	ecx, r8d
        add	r15d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r8d
        xor	ebx, r9d
        ror	ecx, 11
        add	r11d, r15d
        xor	ecx, r8d
        add	r15d, ebx
        ror	ecx, 2
        mov	edx, r11d
        add	r15d, ecx
        add	r14d, DWORD PTR [rsp+340]
        mov	ecx, r12d
        mov	ebx, r8d
        xor	ecx, r13d
        ror	edx, 14
        and	ecx, r11d
        xor	edx, r11d
        xor	ecx, r13d
        ror	edx, 5
        add	r14d, ecx
        xor	edx, r11d
        xor	ebx, r15d
        ror	edx, 6
        mov	ecx, r15d
        add	r14d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r15d
        xor	eax, r8d
        ror	ecx, 11
        add	r10d, r14d
        xor	ecx, r15d
        add	r14d, eax
        ror	ecx, 2
        mov	edx, r10d
        add	r14d, ecx
        add	r13d, DWORD PTR [rsp+344]
        mov	ecx, r11d
        mov	eax, r15d
        xor	ecx, r12d
        ror	edx, 14
        and	ecx, r10d
        xor	edx, r10d
        xor	ecx, r12d
        ror	edx, 5
        add	r13d, ecx
        xor	edx, r10d
        xor	eax, r14d
        ror	edx, 6
        mov	ecx, r14d
        add	r13d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r14d
        xor	ebx, r15d
        ror	ecx, 11
        add	r9d, r13d
        xor	ecx, r14d
        add	r13d, ebx
        ror	ecx, 2
        mov	edx, r9d
        add	r13d, ecx
        add	r12d, DWORD PTR [rsp+348]
        mov	ecx, r10d
        mov	ebx, r14d
        xor	ecx, r11d
        ror	edx, 14
        and	ecx, r9d
        xor	edx, r9d
        xor	ecx, r11d
        ror	edx, 5
        add	r12d, ecx
        xor	edx, r9d
        xor	ebx, r13d
        ror	edx, 6
        mov	ecx, r13d
        add	r12d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r13d
        xor	eax, r14d
        ror	ecx, 11
        add	r8d, r12d
        xor	ecx, r13d
        add	r12d, eax
        ror	ecx, 2
        mov	edx, r8d
        add	r12d, ecx
        ; rnd_all_4: 23-26
        add	r11d, DWORD PTR [rsp+368]
        mov	ecx, r9d
        mov	eax, r13d
        xor	ecx, r10d
        ror	edx, 14
        and	ecx, r8d
        xor	edx, r8d
        xor	ecx, r10d
        ror	edx, 5
        add	r11d, ecx
        xor	edx, r8d
        xor	eax, r12d
        ror	edx, 6
        mov	ecx, r12d
        add	r11d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r12d
        xor	ebx, r13d
        ror	ecx, 11
        add	r15d, r11d
        xor	ecx, r12d
        add	r11d, ebx
        ror	ecx, 2
        mov	edx, r15d
        add	r11d, ecx
        add	r10d, DWORD PTR [rsp+372]
        mov	ecx, r8d
        mov	ebx, r12d
        xor	ecx, r9d
        ror	edx, 14
        and	ecx, r15d
        xor	edx, r15d
        xor	ecx, r9d
        ror	edx, 5
        add	r10d, ecx
        xor	edx, r15d
        xor	ebx, r11d
        ror	edx, 6
        mov	ecx, r11d
        add	r10d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r11d
        xor	eax, r12d
        ror	ecx, 11
        add	r14d, r10d
        xor	ecx, r11d
        add	r10d, eax
        ror	ecx, 2
        mov	edx, r14d
        add	r10d, ecx
        add	r9d, DWORD PTR [rsp+376]
        mov	ecx, r15d
        mov	eax, r11d
        xor	ecx, r8d
        ror	edx, 14
        and	ecx, r14d
        xor	edx, r14d
        xor	ecx, r8d
        ror	edx, 5
        add	r9d, ecx
        xor	edx, r14d
        xor	eax, r10d
        ror	edx, 6
        mov	ecx, r10d
        add	r9d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r10d
        xor	ebx, r11d
        ror	ecx, 11
        add	r13d, r9d
        xor	ecx, r10d
        add	r9d, ebx
        ror	ecx, 2
        mov	edx, r13d
        add	r9d, ecx
        add	r8d, DWORD PTR [rsp+380]
        mov	ecx, r14d
        mov	ebx, r10d
        xor	ecx, r15d
        ror	edx, 14
        and	ecx, r13d
        xor	edx, r13d
        xor	ecx, r15d
        ror	edx, 5
        add	r8d, ecx
        xor	edx, r13d
        xor	ebx, r9d
        ror	edx, 6
        mov	ecx, r9d
        add	r8d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r9d
        xor	eax, r10d
        ror	ecx, 11
        add	r12d, r8d
        xor	ecx, r9d
        add	r8d, eax
        ror	ecx, 2
        mov	edx, r12d
        add	r8d, ecx
        ; rnd_all_4: 25-28
        add	r15d, DWORD PTR [rsp+400]
        mov	ecx, r13d
        mov	eax, r9d
        xor	ecx, r14d
        ror	edx, 14
        and	ecx, r12d
        xor	edx, r12d
        xor	ecx, r14d
        ror	edx, 5
        add	r15d, ecx
        xor	edx, r12d
        xor	eax, r8d
        ror	edx, 6
        mov	ecx, r8d
        add	r15d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r8d
        xor	ebx, r9d
        ror	ecx, 11
        add	r11d, r15d
        xor	ecx, r8d
        add	r15d, ebx
        ror	ecx, 2
        mov	edx, r11d
        add	r15d, ecx
        add	r14d, DWORD PTR [rsp+404]
        mov	ecx, r12d
        mov	ebx, r8d
        xor	ecx, r13d
        ror	edx, 14
        and	ecx, r11d
        xor	edx, r11d
        xor	ecx, r13d
        ror	edx, 5
        add	r14d, ecx
        xor	edx, r11d
        xor	ebx, r15d
        ror	edx, 6
        mov	ecx, r15d
        add	r14d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r15d
        xor	eax, r8d
        ror	ecx, 11
        add	r10d, r14d
        xor	ecx, r15d
        add	r14d, eax
        ror	ecx, 2
        mov	edx, r10d
        add	r14d, ecx
        add	r13d, DWORD PTR [rsp+408]
        mov	ecx, r11d
        mov	eax, r15d
        xor	ecx, r12d
        ror	edx, 14
        and	ecx, r10d
        xor	edx, r10d
        xor	ecx, r12d
        ror	edx, 5
        add	r13d, ecx
        xor	edx, r10d
        xor	eax, r14d
        ror	edx, 6
        mov	ecx, r14d
        add	r13d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r14d
        xor	ebx, r15d
        ror	ecx, 11
        add	r9d, r13d
        xor	ecx, r14d
        add	r13d, ebx
        ror	ecx, 2
        mov	edx, r9d
        add	r13d, ecx
        add	r12d, DWORD PTR [rsp+412]
        mov	ecx, r10d
        mov	ebx, r14d
        xor	ecx, r11d
        ror	edx, 14
        and	ecx, r9d
        xor	edx, r9d
        xor	ecx, r11d
        ror	edx, 5
        add	r12d, ecx
        xor	edx, r9d
        xor	ebx, r13d
        ror	edx, 6
        mov	ecx, r13d
        add	r12d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r13d
        xor	eax, r14d
        ror	ecx, 11
        add	r8d, r12d
        xor	ecx, r13d
        add	r12d, eax
        ror	ecx, 2
        mov	edx, r8d
        add	r12d, ecx
        ; rnd_all_4: 27-30
        add	r11d, DWORD PTR [rsp+432]
        mov	ecx, r9d
        mov	eax, r13d
        xor	ecx, r10d
        ror	edx, 14
        and	ecx, r8d
        xor	edx, r8d
        xor	ecx, r10d
        ror	edx, 5
        add	r11d, ecx
        xor	edx, r8d
        xor	eax, r12d
        ror	edx, 6
        mov	ecx, r12d
        add	r11d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r12d
        xor	ebx, r13d
        ror	ecx, 11
        add	r15d, r11d
        xor	ecx, r12d
        add	r11d, ebx
        ror	ecx, 2
        mov	edx, r15d
        add	r11d, ecx
        add	r10d, DWORD PTR [rsp+436]
        mov	ecx, r8d
        mov	ebx, r12d
        xor	ecx, r9d
        ror	edx, 14
        and	ecx, r15d
        xor	edx, r15d
        xor	ecx, r9d
        ror	edx, 5
        add	r10d, ecx
        xor	edx, r15d
        xor	ebx, r11d
        ror	edx, 6
        mov	ecx, r11d
        add	r10d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r11d
        xor	eax, r12d
        ror	ecx, 11
        add	r14d, r10d
        xor	ecx, r11d
        add	r10d, eax
        ror	ecx, 2
        mov	edx, r14d
        add	r10d, ecx
        add	r9d, DWORD PTR [rsp+440]
        mov	ecx, r15d
        mov	eax, r11d
        xor	ecx, r8d
        ror	edx, 14
        and	ecx, r14d
        xor	edx, r14d
        xor	ecx, r8d
        ror	edx, 5
        add	r9d, ecx
        xor	edx, r14d
        xor	eax, r10d
        ror	edx, 6
        mov	ecx, r10d
        add	r9d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r10d
        xor	ebx, r11d
        ror	ecx, 11
        add	r13d, r9d
        xor	ecx, r10d
        add	r9d, ebx
        ror	ecx, 2
        mov	edx, r13d
        add	r9d, ecx
        add	r8d, DWORD PTR [rsp+444]
        mov	ecx, r14d
        mov	ebx, r10d
        xor	ecx, r15d
        ror	edx, 14
        and	ecx, r13d
        xor	edx, r13d
        xor	ecx, r15d
        ror	edx, 5
        add	r8d, ecx
        xor	edx, r13d
        xor	ebx, r9d
        ror	edx, 6
        mov	ecx, r9d
        add	r8d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r9d
        xor	eax, r10d
        ror	ecx, 11
        add	r12d, r8d
        xor	ecx, r9d
        add	r8d, eax
        ror	ecx, 2
        mov	edx, r12d
        add	r8d, ecx
        ; rnd_all_4: 29-32
        add	r15d, DWORD PTR [rsp+464]
        mov	ecx, r13d
        mov	eax, r9d
        xor	ecx, r14d
        ror	edx, 14
        and	ecx, r12d
        xor	edx, r12d
        xor	ecx, r14d
        ror	edx, 5
        add	r15d, ecx
        xor	edx, r12d
        xor	eax, r8d
        ror	edx, 6
        mov	ecx, r8d
        add	r15d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r8d
        xor	ebx, r9d
        ror	ecx, 11
        add	r11d, r15d
        xor	ecx, r8d
        add	r15d, ebx
        ror	ecx, 2
        mov	edx, r11d
        add	r15d, ecx
        add	r14d, DWORD PTR [rsp+468]
        mov	ecx, r12d
        mov	ebx, r8d
        xor	ecx, r13d
        ror	edx, 14
        and	ecx, r11d
        xor	edx, r11d
        xor	ecx, r13d
        ror	edx, 5
        add	r14d, ecx
        xor	edx, r11d
        xor	ebx, r15d
        ror	edx, 6
        mov	ecx, r15d
        add	r14d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r15d
        xor	eax, r8d
        ror	ecx, 11
        add	r10d, r14d
        xor	ecx, r15d
        add	r14d, eax
        ror	ecx, 2
        mov	edx, r10d
        add	r14d, ecx
        add	r13d, DWORD PTR [rsp+472]
        mov	ecx, r11d
        mov	eax, r15d
        xor	ecx, r12d
        ror	edx, 14
        and	ecx, r10d
        xor	edx, r10d
        xor	ecx, r12d
        ror	edx, 5
        add	r13d, ecx
        xor	edx, r10d
        xor	eax, r14d
        ror	edx, 6
        mov	ecx, r14d
        add	r13d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r14d
        xor	ebx, r15d
        ror	ecx, 11
        add	r9d, r13d
        xor	ecx, r14d
        add	r13d, ebx
        ror	ecx, 2
        mov	edx, r9d
        add	r13d, ecx
        add	r12d, DWORD PTR [rsp+476]
        mov	ecx, r10d
        mov	ebx, r14d
        xor	ecx, r11d
        ror	edx, 14
        and	ecx, r9d
        xor	edx, r9d
        xor	ecx, r11d
        ror	edx, 5
        add	r12d, ecx
        xor	edx, r9d
        xor	ebx, r13d
        ror	edx, 6
        mov	ecx, r13d
        add	r12d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r13d
        xor	eax, r14d
        ror	ecx, 11
        add	r8d, r12d
        xor	ecx, r13d
        add	r12d, eax
        ror	ecx, 2
        mov	edx, r8d
        add	r12d, ecx
        ; rnd_all_4: 31-34
        add	r11d, DWORD PTR [rsp+496]
        mov	ecx, r9d
        mov	eax, r13d
        xor	ecx, r10d
        ror	edx, 14
        and	ecx, r8d
        xor	edx, r8d
        xor	ecx, r10d
        ror	edx, 5
        add	r11d, ecx
        xor	edx, r8d
        xor	eax, r12d
        ror	edx, 6
        mov	ecx, r12d
        add	r11d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r12d
        xor	ebx, r13d
        ror	ecx, 11
        add	r15d, r11d
        xor	ecx, r12d
        add	r11d, ebx
        ror	ecx, 2
        mov	edx, r15d
        add	r11d, ecx
        add	r10d, DWORD PTR [rsp+500]
        mov	ecx, r8d
        mov	ebx, r12d
        xor	ecx, r9d
        ror	edx, 14
        and	ecx, r15d
        xor	edx, r15d
        xor	ecx, r9d
        ror	edx, 5
        add	r10d, ecx
        xor	edx, r15d
        xor	ebx, r11d
        ror	edx, 6
        mov	ecx, r11d
        add	r10d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r11d
        xor	eax, r12d
        ror	ecx, 11
        add	r14d, r10d
        xor	ecx, r11d
        add	r10d, eax
        ror	ecx, 2
        mov	edx, r14d
        add	r10d, ecx
        add	r9d, DWORD PTR [rsp+504]
        mov	ecx, r15d
        mov	eax, r11d
        xor	ecx, r8d
        ror	edx, 14
        and	ecx, r14d
        xor	edx, r14d
        xor	ecx, r8d
        ror	edx, 5
        add	r9d, ecx
        xor	edx, r14d
        xor	eax, r10d
        ror	edx, 6
        mov	ecx, r10d
        add	r9d, edx
        ror	ecx, 9
        and	ebx, eax
        xor	ecx, r10d
        xor	ebx, r11d
        ror	ecx, 11
        add	r13d, r9d
        xor	ecx, r10d
        add	r9d, ebx
        ror	ecx, 2
        mov	edx, r13d
        add	r9d, ecx
        add	r8d, DWORD PTR [rsp+508]
        mov	ecx, r14d
        mov	ebx, r10d
        xor	ecx, r15d
        ror	edx, 14
        and	ecx, r13d
        xor	edx, r13d
        xor	ecx, r15d
        ror	edx, 5
        add	r8d, ecx
        xor	edx, r13d
        xor	ebx, r9d
        ror	edx, 6
        mov	ecx, r9d
        add	r8d, edx
        ror	ecx, 9
        and	eax, ebx
        xor	ecx, r9d
        xor	eax, r10d
        ror	ecx, 11
        add	r12d, r8d
        xor	ecx, r9d
        add	r8d, eax
        ror	ecx, 2
        mov	edx, r12d
        add	r8d, ecx
        add	r8d, DWORD PTR [rdi]
        add	r9d, DWORD PTR [rdi+4]
        add	r10d, DWORD PTR [rdi+8]
        add	r11d, DWORD PTR [rdi+12]
        add	r12d, DWORD PTR [rdi+16]
        add	r13d, DWORD PTR [rdi+20]
        add	r14d, DWORD PTR [rdi+24]
        add	r15d, DWORD PTR [rdi+28]
        add	rsi, 128
        sub	DWORD PTR [rsp+512], 128
        mov	DWORD PTR [rdi], r8d
        mov	DWORD PTR [rdi+4], r9d
        mov	DWORD PTR [rdi+8], r10d
        mov	DWORD PTR [rdi+12], r11d
        mov	DWORD PTR [rdi+16], r12d
        mov	DWORD PTR [rdi+20], r13d
        mov	DWORD PTR [rdi+24], r14d
        mov	DWORD PTR [rdi+28], r15d
        jnz	L_sha256_len_avx2_start
L_sha256_len_avx2_done:
        xor	rax, rax
        vzeroupper
        vmovdqu	xmm6, OWORD PTR [rsp+512]
        vmovdqu	xmm7, OWORD PTR [rsp+528]
        vmovdqu	xmm8, OWORD PTR [rsp+544]
        vmovdqu	xmm9, OWORD PTR [rsp+560]
        vmovdqu	xmm10, OWORD PTR [rsp+576]
        vmovdqu	xmm11, OWORD PTR [rsp+592]
        vmovdqu	xmm12, OWORD PTR [rsp+608]
        vmovdqu	xmm13, OWORD PTR [rsp+624]
        add	rsp, 644
        pop	rbp
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        pop	rbx
        ret
Transform_Sha256_AVX2_Len ENDP
_TEXT ENDS
_DATA SEGMENT
ALIGN 16
L_avx2_rorx_sha256_k DWORD 428a2f98h, 71374491h, 0b5c0fbcfh, 0e9b5dba5h
        DWORD 428a2f98h, 71374491h, 0b5c0fbcfh, 0e9b5dba5h
        DWORD 3956c25bh, 59f111f1h, 923f82a4h, 0ab1c5ed5h
        DWORD 3956c25bh, 59f111f1h, 923f82a4h, 0ab1c5ed5h
        DWORD 0d807aa98h, 12835b01h, 243185beh, 550c7dc3h
        DWORD 0d807aa98h, 12835b01h, 243185beh, 550c7dc3h
        DWORD 72be5d74h, 80deb1feh, 9bdc06a7h, 0c19bf174h
        DWORD 72be5d74h, 80deb1feh, 9bdc06a7h, 0c19bf174h
        DWORD 0e49b69c1h, 0efbe4786h, 0fc19dc6h, 240ca1cch
        DWORD 0e49b69c1h, 0efbe4786h, 0fc19dc6h, 240ca1cch
        DWORD 2de92c6fh, 4a7484aah, 5cb0a9dch, 76f988dah
        DWORD 2de92c6fh, 4a7484aah, 5cb0a9dch, 76f988dah
        DWORD 983e5152h, 0a831c66dh, 0b00327c8h, 0bf597fc7h
        DWORD 983e5152h, 0a831c66dh, 0b00327c8h, 0bf597fc7h
        DWORD 0c6e00bf3h, 0d5a79147h, 06ca6351h, 14292967h
        DWORD 0c6e00bf3h, 0d5a79147h, 06ca6351h, 14292967h
        DWORD 27b70a85h, 2e1b2138h, 4d2c6dfch, 53380d13h
        DWORD 27b70a85h, 2e1b2138h, 4d2c6dfch, 53380d13h
        DWORD 650a7354h, 766a0abbh, 81c2c92eh, 92722c85h
        DWORD 650a7354h, 766a0abbh, 81c2c92eh, 92722c85h
        DWORD 0a2bfe8a1h, 0a81a664bh, 0c24b8b70h, 0c76c51a3h
        DWORD 0a2bfe8a1h, 0a81a664bh, 0c24b8b70h, 0c76c51a3h
        DWORD 0d192e819h, 0d6990624h, 0f40e3585h, 106aa070h
        DWORD 0d192e819h, 0d6990624h, 0f40e3585h, 106aa070h
        DWORD 19a4c116h, 1e376c08h, 2748774ch, 34b0bcb5h
        DWORD 19a4c116h, 1e376c08h, 2748774ch, 34b0bcb5h
        DWORD 391c0cb3h, 4ed8aa4ah, 5b9cca4fh, 682e6ff3h
        DWORD 391c0cb3h, 4ed8aa4ah, 5b9cca4fh, 682e6ff3h
        DWORD 748f82eeh, 78a5636fh, 84c87814h, 8cc70208h
        DWORD 748f82eeh, 78a5636fh, 84c87814h, 8cc70208h
        DWORD 90befffah, 0a4506cebh, 0bef9a3f7h, 0c67178f2h
        DWORD 90befffah, 0a4506cebh, 0bef9a3f7h, 0c67178f2h
ptr_L_avx2_rorx_sha256_k QWORD L_avx2_rorx_sha256_k
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_avx2_rorx_sha256_flip_mask QWORD 0405060700010203h, 0c0d0e0f08090a0bh
        QWORD 0405060700010203h, 0c0d0e0f08090a0bh
ptr_L_avx2_rorx_sha256_flip_mask QWORD L_avx2_rorx_sha256_flip_mask
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_avx2_rorx_sha256_shuf_00BA QWORD 0b0a090803020100h, 0ffffffffffffffffh
        QWORD 0b0a090803020100h, 0ffffffffffffffffh
ptr_L_avx2_rorx_sha256_shuf_00BA QWORD L_avx2_rorx_sha256_shuf_00BA
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_avx2_rorx_sha256_shuf_DC00 QWORD 0ffffffffffffffffh, 0b0a090803020100h
        QWORD 0ffffffffffffffffh, 0b0a090803020100h
ptr_L_avx2_rorx_sha256_shuf_DC00 QWORD L_avx2_rorx_sha256_shuf_DC00
_DATA ENDS
_TEXT SEGMENT READONLY PARA
Transform_Sha256_AVX2_RORX PROC
        push	rbx
        push	r12
        push	r13
        push	r14
        push	r15
        push	rbp
        push	rdi
        push	rsi
        mov	rdi, rcx
        mov	rsi, rdx
        sub	rsp, 640
        vmovdqu	OWORD PTR [rsp+512], xmm6
        vmovdqu	OWORD PTR [rsp+528], xmm7
        vmovdqu	OWORD PTR [rsp+544], xmm8
        vmovdqu	OWORD PTR [rsp+560], xmm9
        vmovdqu	OWORD PTR [rsp+576], xmm10
        vmovdqu	OWORD PTR [rsp+592], xmm11
        vmovdqu	OWORD PTR [rsp+608], xmm12
        vmovdqu	OWORD PTR [rsp+624], xmm13
        mov	rbp, QWORD PTR [ptr_L_avx2_rorx_sha256_k]
        vmovdqa	xmm13, OWORD PTR L_avx2_rorx_sha256_flip_mask
        vmovdqu	ymm11, YMMWORD PTR L_avx2_rorx_sha256_shuf_00BA
        vmovdqu	ymm12, YMMWORD PTR L_avx2_rorx_sha256_shuf_DC00
        ; X0, X1, X2, X3 = W[0..15]
        vmovdqu	xmm0, OWORD PTR [rsi]
        vmovdqu	xmm1, OWORD PTR [rsi+16]
        vpshufb	xmm0, xmm0, xmm13
        vpshufb	xmm1, xmm1, xmm13
        vpaddd	ymm4, ymm0, YMMWORD PTR [rbp]
        vpaddd	ymm5, ymm1, YMMWORD PTR [rbp+32]
        vmovdqu	YMMWORD PTR [rsp], ymm4
        vmovdqu	YMMWORD PTR [rsp+32], ymm5
        vmovdqu	xmm2, OWORD PTR [rsi+32]
        vmovdqu	xmm3, OWORD PTR [rsi+48]
        vpshufb	xmm2, xmm2, xmm13
        vpshufb	xmm3, xmm3, xmm13
        vpaddd	ymm4, ymm2, YMMWORD PTR [rbp+64]
        vpaddd	ymm5, ymm3, YMMWORD PTR [rbp+96]
        vmovdqu	YMMWORD PTR [rsp+64], ymm4
        vmovdqu	YMMWORD PTR [rsp+96], ymm5
        mov	r8d, DWORD PTR [rdi]
        mov	r9d, DWORD PTR [rdi+4]
        mov	r10d, DWORD PTR [rdi+8]
        mov	r11d, DWORD PTR [rdi+12]
        mov	r12d, DWORD PTR [rdi+16]
        mov	r13d, DWORD PTR [rdi+20]
        mov	r14d, DWORD PTR [rdi+24]
        mov	r15d, DWORD PTR [rdi+28]
        mov	ebx, r9d
        rorx	edx, r12d, 6
        xor	ebx, r10d
        ; rnd_0: 0 - 0
        mov	eax, r13d
        rorx	ecx, r12d, 11
        add	r15d, DWORD PTR [rsp]
        vpalignr	ymm5, ymm1, ymm0, 4
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r14d
        rorx	edx, r12d, 25
        vpalignr	ymm4, ymm3, ymm2, 4
        ; rnd_0: 2 - 2
        and	eax, r12d
        xor	edx, ecx
        rorx	ecx, r8d, 13
        vpsrld	ymm6, ymm5, 7
        ; rnd_0: 3 - 3
        add	r15d, edx
        rorx	edx, r8d, 2
        xor	eax, r14d
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r8d, 22
        add	r15d, eax
        vpsrld	ymm8, ymm5, 18
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r9d
        add	r11d, r15d
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 6 - 6
        xor	eax, r8d
        add	r15d, edx
        and	ebx, eax
        vpor	ymm6, ymm6, ymm7
        ; rnd_0: 7 - 7
        xor	ebx, r9d
        rorx	edx, r11d, 6
        add	r15d, ebx
        vpor	ymm8, ymm8, ymm9
        ; rnd_1: 0 - 0
        mov	ebx, r12d
        rorx	ecx, r11d, 11
        add	r14d, DWORD PTR [rsp+4]
        vpsrld	ymm9, ymm5, 3
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r13d
        rorx	edx, r11d, 25
        vpxor	ymm6, ymm6, ymm8
        ; rnd_1: 2 - 2
        and	ebx, r11d
        xor	edx, ecx
        rorx	ecx, r15d, 13
        vpshufd	ymm7, ymm3, 250
        ; rnd_1: 3 - 3
        add	r14d, edx
        rorx	edx, r15d, 2
        xor	ebx, r13d
        vpxor	ymm5, ymm9, ymm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r15d, 22
        add	r14d, ebx
        vpsrld	ymm8, ymm7, 10
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r10d, r14d
        mov	ebx, r8d
        vpsrlq	ymm6, ymm7, 19
        ; rnd_1: 6 - 6
        xor	ebx, r15d
        add	r14d, edx
        and	eax, ebx
        vpsrlq	ymm7, ymm7, 17
        ; rnd_1: 7 - 7
        xor	eax, r8d
        rorx	edx, r10d, 6
        add	r14d, eax
        vpaddd	ymm4, ymm4, ymm0
        ; rnd_0: 0 - 0
        mov	eax, r11d
        rorx	ecx, r10d, 11
        add	r13d, DWORD PTR [rsp+8]
        vpxor	ymm6, ymm6, ymm7
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r12d
        rorx	edx, r10d, 25
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 2 - 2
        and	eax, r10d
        xor	edx, ecx
        rorx	ecx, r14d, 13
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 3 - 3
        add	r13d, edx
        rorx	edx, r14d, 2
        xor	eax, r12d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r14d, 22
        add	r13d, eax
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r15d
        add	r9d, r13d
        vpshufd	ymm6, ymm4, 80
        ; rnd_0: 6 - 6
        xor	eax, r14d
        add	r13d, edx
        and	ebx, eax
        vpsrlq	ymm8, ymm6, 17
        ; rnd_0: 7 - 7
        xor	ebx, r15d
        rorx	edx, r9d, 6
        add	r13d, ebx
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 0 - 0
        mov	ebx, r10d
        rorx	ecx, r9d, 11
        add	r12d, DWORD PTR [rsp+12]
        vpsrld	ymm9, ymm6, 10
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r11d
        rorx	edx, r9d, 25
        vpxor	ymm8, ymm8, ymm7
        ; rnd_1: 2 - 2
        and	ebx, r9d
        xor	edx, ecx
        rorx	ecx, r13d, 13
        vpxor	ymm9, ymm9, ymm8
        ; rnd_1: 3 - 3
        add	r12d, edx
        rorx	edx, r13d, 2
        xor	ebx, r11d
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r13d, 22
        add	r12d, ebx
        vpaddd	ymm0, ymm9, ymm4
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r8d, r12d
        mov	ebx, r14d
        vpaddd	ymm4, ymm0, YMMWORD PTR [rbp+128]
        ; rnd_1: 6 - 6
        xor	ebx, r13d
        add	r12d, edx
        and	eax, ebx
        ; rnd_1: 7 - 7
        xor	eax, r14d
        rorx	edx, r8d, 6
        add	r12d, eax
        vmovdqu	YMMWORD PTR [rsp+128], ymm4
        ; rnd_0: 0 - 0
        mov	eax, r9d
        rorx	ecx, r8d, 11
        add	r11d, DWORD PTR [rsp+32]
        vpalignr	ymm5, ymm2, ymm1, 4
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r10d
        rorx	edx, r8d, 25
        vpalignr	ymm4, ymm0, ymm3, 4
        ; rnd_0: 2 - 2
        and	eax, r8d
        xor	edx, ecx
        rorx	ecx, r12d, 13
        vpsrld	ymm6, ymm5, 7
        ; rnd_0: 3 - 3
        add	r11d, edx
        rorx	edx, r12d, 2
        xor	eax, r10d
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r12d, 22
        add	r11d, eax
        vpsrld	ymm8, ymm5, 18
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r13d
        add	r15d, r11d
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 6 - 6
        xor	eax, r12d
        add	r11d, edx
        and	ebx, eax
        vpor	ymm6, ymm6, ymm7
        ; rnd_0: 7 - 7
        xor	ebx, r13d
        rorx	edx, r15d, 6
        add	r11d, ebx
        vpor	ymm8, ymm8, ymm9
        ; rnd_1: 0 - 0
        mov	ebx, r8d
        rorx	ecx, r15d, 11
        add	r10d, DWORD PTR [rsp+36]
        vpsrld	ymm9, ymm5, 3
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r9d
        rorx	edx, r15d, 25
        vpxor	ymm6, ymm6, ymm8
        ; rnd_1: 2 - 2
        and	ebx, r15d
        xor	edx, ecx
        rorx	ecx, r11d, 13
        vpshufd	ymm7, ymm0, 250
        ; rnd_1: 3 - 3
        add	r10d, edx
        rorx	edx, r11d, 2
        xor	ebx, r9d
        vpxor	ymm5, ymm9, ymm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r11d, 22
        add	r10d, ebx
        vpsrld	ymm8, ymm7, 10
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r14d, r10d
        mov	ebx, r12d
        vpsrlq	ymm6, ymm7, 19
        ; rnd_1: 6 - 6
        xor	ebx, r11d
        add	r10d, edx
        and	eax, ebx
        vpsrlq	ymm7, ymm7, 17
        ; rnd_1: 7 - 7
        xor	eax, r12d
        rorx	edx, r14d, 6
        add	r10d, eax
        vpaddd	ymm4, ymm4, ymm1
        ; rnd_0: 0 - 0
        mov	eax, r15d
        rorx	ecx, r14d, 11
        add	r9d, DWORD PTR [rsp+40]
        vpxor	ymm6, ymm6, ymm7
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r8d
        rorx	edx, r14d, 25
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 2 - 2
        and	eax, r14d
        xor	edx, ecx
        rorx	ecx, r10d, 13
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 3 - 3
        add	r9d, edx
        rorx	edx, r10d, 2
        xor	eax, r8d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r10d, 22
        add	r9d, eax
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r11d
        add	r13d, r9d
        vpshufd	ymm6, ymm4, 80
        ; rnd_0: 6 - 6
        xor	eax, r10d
        add	r9d, edx
        and	ebx, eax
        vpsrlq	ymm8, ymm6, 17
        ; rnd_0: 7 - 7
        xor	ebx, r11d
        rorx	edx, r13d, 6
        add	r9d, ebx
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 0 - 0
        mov	ebx, r14d
        rorx	ecx, r13d, 11
        add	r8d, DWORD PTR [rsp+44]
        vpsrld	ymm9, ymm6, 10
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r15d
        rorx	edx, r13d, 25
        vpxor	ymm8, ymm8, ymm7
        ; rnd_1: 2 - 2
        and	ebx, r13d
        xor	edx, ecx
        rorx	ecx, r9d, 13
        vpxor	ymm9, ymm9, ymm8
        ; rnd_1: 3 - 3
        add	r8d, edx
        rorx	edx, r9d, 2
        xor	ebx, r15d
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r9d, 22
        add	r8d, ebx
        vpaddd	ymm1, ymm9, ymm4
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r12d, r8d
        mov	ebx, r10d
        vpaddd	ymm4, ymm1, YMMWORD PTR [rbp+160]
        ; rnd_1: 6 - 6
        xor	ebx, r9d
        add	r8d, edx
        and	eax, ebx
        ; rnd_1: 7 - 7
        xor	eax, r10d
        rorx	edx, r12d, 6
        add	r8d, eax
        vmovdqu	YMMWORD PTR [rsp+160], ymm4
        ; rnd_0: 0 - 0
        mov	eax, r13d
        rorx	ecx, r12d, 11
        add	r15d, DWORD PTR [rsp+64]
        vpalignr	ymm5, ymm3, ymm2, 4
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r14d
        rorx	edx, r12d, 25
        vpalignr	ymm4, ymm1, ymm0, 4
        ; rnd_0: 2 - 2
        and	eax, r12d
        xor	edx, ecx
        rorx	ecx, r8d, 13
        vpsrld	ymm6, ymm5, 7
        ; rnd_0: 3 - 3
        add	r15d, edx
        rorx	edx, r8d, 2
        xor	eax, r14d
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r8d, 22
        add	r15d, eax
        vpsrld	ymm8, ymm5, 18
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r9d
        add	r11d, r15d
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 6 - 6
        xor	eax, r8d
        add	r15d, edx
        and	ebx, eax
        vpor	ymm6, ymm6, ymm7
        ; rnd_0: 7 - 7
        xor	ebx, r9d
        rorx	edx, r11d, 6
        add	r15d, ebx
        vpor	ymm8, ymm8, ymm9
        ; rnd_1: 0 - 0
        mov	ebx, r12d
        rorx	ecx, r11d, 11
        add	r14d, DWORD PTR [rsp+68]
        vpsrld	ymm9, ymm5, 3
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r13d
        rorx	edx, r11d, 25
        vpxor	ymm6, ymm6, ymm8
        ; rnd_1: 2 - 2
        and	ebx, r11d
        xor	edx, ecx
        rorx	ecx, r15d, 13
        vpshufd	ymm7, ymm1, 250
        ; rnd_1: 3 - 3
        add	r14d, edx
        rorx	edx, r15d, 2
        xor	ebx, r13d
        vpxor	ymm5, ymm9, ymm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r15d, 22
        add	r14d, ebx
        vpsrld	ymm8, ymm7, 10
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r10d, r14d
        mov	ebx, r8d
        vpsrlq	ymm6, ymm7, 19
        ; rnd_1: 6 - 6
        xor	ebx, r15d
        add	r14d, edx
        and	eax, ebx
        vpsrlq	ymm7, ymm7, 17
        ; rnd_1: 7 - 7
        xor	eax, r8d
        rorx	edx, r10d, 6
        add	r14d, eax
        vpaddd	ymm4, ymm4, ymm2
        ; rnd_0: 0 - 0
        mov	eax, r11d
        rorx	ecx, r10d, 11
        add	r13d, DWORD PTR [rsp+72]
        vpxor	ymm6, ymm6, ymm7
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r12d
        rorx	edx, r10d, 25
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 2 - 2
        and	eax, r10d
        xor	edx, ecx
        rorx	ecx, r14d, 13
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 3 - 3
        add	r13d, edx
        rorx	edx, r14d, 2
        xor	eax, r12d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r14d, 22
        add	r13d, eax
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r15d
        add	r9d, r13d
        vpshufd	ymm6, ymm4, 80
        ; rnd_0: 6 - 6
        xor	eax, r14d
        add	r13d, edx
        and	ebx, eax
        vpsrlq	ymm8, ymm6, 17
        ; rnd_0: 7 - 7
        xor	ebx, r15d
        rorx	edx, r9d, 6
        add	r13d, ebx
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 0 - 0
        mov	ebx, r10d
        rorx	ecx, r9d, 11
        add	r12d, DWORD PTR [rsp+76]
        vpsrld	ymm9, ymm6, 10
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r11d
        rorx	edx, r9d, 25
        vpxor	ymm8, ymm8, ymm7
        ; rnd_1: 2 - 2
        and	ebx, r9d
        xor	edx, ecx
        rorx	ecx, r13d, 13
        vpxor	ymm9, ymm9, ymm8
        ; rnd_1: 3 - 3
        add	r12d, edx
        rorx	edx, r13d, 2
        xor	ebx, r11d
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r13d, 22
        add	r12d, ebx
        vpaddd	ymm2, ymm9, ymm4
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r8d, r12d
        mov	ebx, r14d
        vpaddd	ymm4, ymm2, YMMWORD PTR [rbp+192]
        ; rnd_1: 6 - 6
        xor	ebx, r13d
        add	r12d, edx
        and	eax, ebx
        ; rnd_1: 7 - 7
        xor	eax, r14d
        rorx	edx, r8d, 6
        add	r12d, eax
        vmovdqu	YMMWORD PTR [rsp+192], ymm4
        ; rnd_0: 0 - 0
        mov	eax, r9d
        rorx	ecx, r8d, 11
        add	r11d, DWORD PTR [rsp+96]
        vpalignr	ymm5, ymm0, ymm3, 4
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r10d
        rorx	edx, r8d, 25
        vpalignr	ymm4, ymm2, ymm1, 4
        ; rnd_0: 2 - 2
        and	eax, r8d
        xor	edx, ecx
        rorx	ecx, r12d, 13
        vpsrld	ymm6, ymm5, 7
        ; rnd_0: 3 - 3
        add	r11d, edx
        rorx	edx, r12d, 2
        xor	eax, r10d
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r12d, 22
        add	r11d, eax
        vpsrld	ymm8, ymm5, 18
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r13d
        add	r15d, r11d
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 6 - 6
        xor	eax, r12d
        add	r11d, edx
        and	ebx, eax
        vpor	ymm6, ymm6, ymm7
        ; rnd_0: 7 - 7
        xor	ebx, r13d
        rorx	edx, r15d, 6
        add	r11d, ebx
        vpor	ymm8, ymm8, ymm9
        ; rnd_1: 0 - 0
        mov	ebx, r8d
        rorx	ecx, r15d, 11
        add	r10d, DWORD PTR [rsp+100]
        vpsrld	ymm9, ymm5, 3
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r9d
        rorx	edx, r15d, 25
        vpxor	ymm6, ymm6, ymm8
        ; rnd_1: 2 - 2
        and	ebx, r15d
        xor	edx, ecx
        rorx	ecx, r11d, 13
        vpshufd	ymm7, ymm2, 250
        ; rnd_1: 3 - 3
        add	r10d, edx
        rorx	edx, r11d, 2
        xor	ebx, r9d
        vpxor	ymm5, ymm9, ymm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r11d, 22
        add	r10d, ebx
        vpsrld	ymm8, ymm7, 10
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r14d, r10d
        mov	ebx, r12d
        vpsrlq	ymm6, ymm7, 19
        ; rnd_1: 6 - 6
        xor	ebx, r11d
        add	r10d, edx
        and	eax, ebx
        vpsrlq	ymm7, ymm7, 17
        ; rnd_1: 7 - 7
        xor	eax, r12d
        rorx	edx, r14d, 6
        add	r10d, eax
        vpaddd	ymm4, ymm4, ymm3
        ; rnd_0: 0 - 0
        mov	eax, r15d
        rorx	ecx, r14d, 11
        add	r9d, DWORD PTR [rsp+104]
        vpxor	ymm6, ymm6, ymm7
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r8d
        rorx	edx, r14d, 25
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 2 - 2
        and	eax, r14d
        xor	edx, ecx
        rorx	ecx, r10d, 13
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 3 - 3
        add	r9d, edx
        rorx	edx, r10d, 2
        xor	eax, r8d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r10d, 22
        add	r9d, eax
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r11d
        add	r13d, r9d
        vpshufd	ymm6, ymm4, 80
        ; rnd_0: 6 - 6
        xor	eax, r10d
        add	r9d, edx
        and	ebx, eax
        vpsrlq	ymm8, ymm6, 17
        ; rnd_0: 7 - 7
        xor	ebx, r11d
        rorx	edx, r13d, 6
        add	r9d, ebx
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 0 - 0
        mov	ebx, r14d
        rorx	ecx, r13d, 11
        add	r8d, DWORD PTR [rsp+108]
        vpsrld	ymm9, ymm6, 10
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r15d
        rorx	edx, r13d, 25
        vpxor	ymm8, ymm8, ymm7
        ; rnd_1: 2 - 2
        and	ebx, r13d
        xor	edx, ecx
        rorx	ecx, r9d, 13
        vpxor	ymm9, ymm9, ymm8
        ; rnd_1: 3 - 3
        add	r8d, edx
        rorx	edx, r9d, 2
        xor	ebx, r15d
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r9d, 22
        add	r8d, ebx
        vpaddd	ymm3, ymm9, ymm4
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r12d, r8d
        mov	ebx, r10d
        vpaddd	ymm4, ymm3, YMMWORD PTR [rbp+224]
        ; rnd_1: 6 - 6
        xor	ebx, r9d
        add	r8d, edx
        and	eax, ebx
        ; rnd_1: 7 - 7
        xor	eax, r10d
        rorx	edx, r12d, 6
        add	r8d, eax
        vmovdqu	YMMWORD PTR [rsp+224], ymm4
        ; rnd_0: 0 - 0
        mov	eax, r13d
        rorx	ecx, r12d, 11
        add	r15d, DWORD PTR [rsp+128]
        vpalignr	ymm5, ymm1, ymm0, 4
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r14d
        rorx	edx, r12d, 25
        vpalignr	ymm4, ymm3, ymm2, 4
        ; rnd_0: 2 - 2
        and	eax, r12d
        xor	edx, ecx
        rorx	ecx, r8d, 13
        vpsrld	ymm6, ymm5, 7
        ; rnd_0: 3 - 3
        add	r15d, edx
        rorx	edx, r8d, 2
        xor	eax, r14d
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r8d, 22
        add	r15d, eax
        vpsrld	ymm8, ymm5, 18
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r9d
        add	r11d, r15d
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 6 - 6
        xor	eax, r8d
        add	r15d, edx
        and	ebx, eax
        vpor	ymm6, ymm6, ymm7
        ; rnd_0: 7 - 7
        xor	ebx, r9d
        rorx	edx, r11d, 6
        add	r15d, ebx
        vpor	ymm8, ymm8, ymm9
        ; rnd_1: 0 - 0
        mov	ebx, r12d
        rorx	ecx, r11d, 11
        add	r14d, DWORD PTR [rsp+132]
        vpsrld	ymm9, ymm5, 3
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r13d
        rorx	edx, r11d, 25
        vpxor	ymm6, ymm6, ymm8
        ; rnd_1: 2 - 2
        and	ebx, r11d
        xor	edx, ecx
        rorx	ecx, r15d, 13
        vpshufd	ymm7, ymm3, 250
        ; rnd_1: 3 - 3
        add	r14d, edx
        rorx	edx, r15d, 2
        xor	ebx, r13d
        vpxor	ymm5, ymm9, ymm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r15d, 22
        add	r14d, ebx
        vpsrld	ymm8, ymm7, 10
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r10d, r14d
        mov	ebx, r8d
        vpsrlq	ymm6, ymm7, 19
        ; rnd_1: 6 - 6
        xor	ebx, r15d
        add	r14d, edx
        and	eax, ebx
        vpsrlq	ymm7, ymm7, 17
        ; rnd_1: 7 - 7
        xor	eax, r8d
        rorx	edx, r10d, 6
        add	r14d, eax
        vpaddd	ymm4, ymm4, ymm0
        ; rnd_0: 0 - 0
        mov	eax, r11d
        rorx	ecx, r10d, 11
        add	r13d, DWORD PTR [rsp+136]
        vpxor	ymm6, ymm6, ymm7
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r12d
        rorx	edx, r10d, 25
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 2 - 2
        and	eax, r10d
        xor	edx, ecx
        rorx	ecx, r14d, 13
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 3 - 3
        add	r13d, edx
        rorx	edx, r14d, 2
        xor	eax, r12d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r14d, 22
        add	r13d, eax
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r15d
        add	r9d, r13d
        vpshufd	ymm6, ymm4, 80
        ; rnd_0: 6 - 6
        xor	eax, r14d
        add	r13d, edx
        and	ebx, eax
        vpsrlq	ymm8, ymm6, 17
        ; rnd_0: 7 - 7
        xor	ebx, r15d
        rorx	edx, r9d, 6
        add	r13d, ebx
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 0 - 0
        mov	ebx, r10d
        rorx	ecx, r9d, 11
        add	r12d, DWORD PTR [rsp+140]
        vpsrld	ymm9, ymm6, 10
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r11d
        rorx	edx, r9d, 25
        vpxor	ymm8, ymm8, ymm7
        ; rnd_1: 2 - 2
        and	ebx, r9d
        xor	edx, ecx
        rorx	ecx, r13d, 13
        vpxor	ymm9, ymm9, ymm8
        ; rnd_1: 3 - 3
        add	r12d, edx
        rorx	edx, r13d, 2
        xor	ebx, r11d
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r13d, 22
        add	r12d, ebx
        vpaddd	ymm0, ymm9, ymm4
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r8d, r12d
        mov	ebx, r14d
        vpaddd	ymm4, ymm0, YMMWORD PTR [rbp+256]
        ; rnd_1: 6 - 6
        xor	ebx, r13d
        add	r12d, edx
        and	eax, ebx
        ; rnd_1: 7 - 7
        xor	eax, r14d
        rorx	edx, r8d, 6
        add	r12d, eax
        vmovdqu	YMMWORD PTR [rsp+256], ymm4
        ; rnd_0: 0 - 0
        mov	eax, r9d
        rorx	ecx, r8d, 11
        add	r11d, DWORD PTR [rsp+160]
        vpalignr	ymm5, ymm2, ymm1, 4
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r10d
        rorx	edx, r8d, 25
        vpalignr	ymm4, ymm0, ymm3, 4
        ; rnd_0: 2 - 2
        and	eax, r8d
        xor	edx, ecx
        rorx	ecx, r12d, 13
        vpsrld	ymm6, ymm5, 7
        ; rnd_0: 3 - 3
        add	r11d, edx
        rorx	edx, r12d, 2
        xor	eax, r10d
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r12d, 22
        add	r11d, eax
        vpsrld	ymm8, ymm5, 18
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r13d
        add	r15d, r11d
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 6 - 6
        xor	eax, r12d
        add	r11d, edx
        and	ebx, eax
        vpor	ymm6, ymm6, ymm7
        ; rnd_0: 7 - 7
        xor	ebx, r13d
        rorx	edx, r15d, 6
        add	r11d, ebx
        vpor	ymm8, ymm8, ymm9
        ; rnd_1: 0 - 0
        mov	ebx, r8d
        rorx	ecx, r15d, 11
        add	r10d, DWORD PTR [rsp+164]
        vpsrld	ymm9, ymm5, 3
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r9d
        rorx	edx, r15d, 25
        vpxor	ymm6, ymm6, ymm8
        ; rnd_1: 2 - 2
        and	ebx, r15d
        xor	edx, ecx
        rorx	ecx, r11d, 13
        vpshufd	ymm7, ymm0, 250
        ; rnd_1: 3 - 3
        add	r10d, edx
        rorx	edx, r11d, 2
        xor	ebx, r9d
        vpxor	ymm5, ymm9, ymm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r11d, 22
        add	r10d, ebx
        vpsrld	ymm8, ymm7, 10
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r14d, r10d
        mov	ebx, r12d
        vpsrlq	ymm6, ymm7, 19
        ; rnd_1: 6 - 6
        xor	ebx, r11d
        add	r10d, edx
        and	eax, ebx
        vpsrlq	ymm7, ymm7, 17
        ; rnd_1: 7 - 7
        xor	eax, r12d
        rorx	edx, r14d, 6
        add	r10d, eax
        vpaddd	ymm4, ymm4, ymm1
        ; rnd_0: 0 - 0
        mov	eax, r15d
        rorx	ecx, r14d, 11
        add	r9d, DWORD PTR [rsp+168]
        vpxor	ymm6, ymm6, ymm7
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r8d
        rorx	edx, r14d, 25
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 2 - 2
        and	eax, r14d
        xor	edx, ecx
        rorx	ecx, r10d, 13
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 3 - 3
        add	r9d, edx
        rorx	edx, r10d, 2
        xor	eax, r8d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r10d, 22
        add	r9d, eax
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r11d
        add	r13d, r9d
        vpshufd	ymm6, ymm4, 80
        ; rnd_0: 6 - 6
        xor	eax, r10d
        add	r9d, edx
        and	ebx, eax
        vpsrlq	ymm8, ymm6, 17
        ; rnd_0: 7 - 7
        xor	ebx, r11d
        rorx	edx, r13d, 6
        add	r9d, ebx
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 0 - 0
        mov	ebx, r14d
        rorx	ecx, r13d, 11
        add	r8d, DWORD PTR [rsp+172]
        vpsrld	ymm9, ymm6, 10
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r15d
        rorx	edx, r13d, 25
        vpxor	ymm8, ymm8, ymm7
        ; rnd_1: 2 - 2
        and	ebx, r13d
        xor	edx, ecx
        rorx	ecx, r9d, 13
        vpxor	ymm9, ymm9, ymm8
        ; rnd_1: 3 - 3
        add	r8d, edx
        rorx	edx, r9d, 2
        xor	ebx, r15d
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r9d, 22
        add	r8d, ebx
        vpaddd	ymm1, ymm9, ymm4
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r12d, r8d
        mov	ebx, r10d
        vpaddd	ymm4, ymm1, YMMWORD PTR [rbp+288]
        ; rnd_1: 6 - 6
        xor	ebx, r9d
        add	r8d, edx
        and	eax, ebx
        ; rnd_1: 7 - 7
        xor	eax, r10d
        rorx	edx, r12d, 6
        add	r8d, eax
        vmovdqu	YMMWORD PTR [rsp+288], ymm4
        ; rnd_0: 0 - 0
        mov	eax, r13d
        rorx	ecx, r12d, 11
        add	r15d, DWORD PTR [rsp+192]
        vpalignr	ymm5, ymm3, ymm2, 4
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r14d
        rorx	edx, r12d, 25
        vpalignr	ymm4, ymm1, ymm0, 4
        ; rnd_0: 2 - 2
        and	eax, r12d
        xor	edx, ecx
        rorx	ecx, r8d, 13
        vpsrld	ymm6, ymm5, 7
        ; rnd_0: 3 - 3
        add	r15d, edx
        rorx	edx, r8d, 2
        xor	eax, r14d
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r8d, 22
        add	r15d, eax
        vpsrld	ymm8, ymm5, 18
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r9d
        add	r11d, r15d
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 6 - 6
        xor	eax, r8d
        add	r15d, edx
        and	ebx, eax
        vpor	ymm6, ymm6, ymm7
        ; rnd_0: 7 - 7
        xor	ebx, r9d
        rorx	edx, r11d, 6
        add	r15d, ebx
        vpor	ymm8, ymm8, ymm9
        ; rnd_1: 0 - 0
        mov	ebx, r12d
        rorx	ecx, r11d, 11
        add	r14d, DWORD PTR [rsp+196]
        vpsrld	ymm9, ymm5, 3
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r13d
        rorx	edx, r11d, 25
        vpxor	ymm6, ymm6, ymm8
        ; rnd_1: 2 - 2
        and	ebx, r11d
        xor	edx, ecx
        rorx	ecx, r15d, 13
        vpshufd	ymm7, ymm1, 250
        ; rnd_1: 3 - 3
        add	r14d, edx
        rorx	edx, r15d, 2
        xor	ebx, r13d
        vpxor	ymm5, ymm9, ymm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r15d, 22
        add	r14d, ebx
        vpsrld	ymm8, ymm7, 10
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r10d, r14d
        mov	ebx, r8d
        vpsrlq	ymm6, ymm7, 19
        ; rnd_1: 6 - 6
        xor	ebx, r15d
        add	r14d, edx
        and	eax, ebx
        vpsrlq	ymm7, ymm7, 17
        ; rnd_1: 7 - 7
        xor	eax, r8d
        rorx	edx, r10d, 6
        add	r14d, eax
        vpaddd	ymm4, ymm4, ymm2
        ; rnd_0: 0 - 0
        mov	eax, r11d
        rorx	ecx, r10d, 11
        add	r13d, DWORD PTR [rsp+200]
        vpxor	ymm6, ymm6, ymm7
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r12d
        rorx	edx, r10d, 25
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 2 - 2
        and	eax, r10d
        xor	edx, ecx
        rorx	ecx, r14d, 13
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 3 - 3
        add	r13d, edx
        rorx	edx, r14d, 2
        xor	eax, r12d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r14d, 22
        add	r13d, eax
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r15d
        add	r9d, r13d
        vpshufd	ymm6, ymm4, 80
        ; rnd_0: 6 - 6
        xor	eax, r14d
        add	r13d, edx
        and	ebx, eax
        vpsrlq	ymm8, ymm6, 17
        ; rnd_0: 7 - 7
        xor	ebx, r15d
        rorx	edx, r9d, 6
        add	r13d, ebx
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 0 - 0
        mov	ebx, r10d
        rorx	ecx, r9d, 11
        add	r12d, DWORD PTR [rsp+204]
        vpsrld	ymm9, ymm6, 10
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r11d
        rorx	edx, r9d, 25
        vpxor	ymm8, ymm8, ymm7
        ; rnd_1: 2 - 2
        and	ebx, r9d
        xor	edx, ecx
        rorx	ecx, r13d, 13
        vpxor	ymm9, ymm9, ymm8
        ; rnd_1: 3 - 3
        add	r12d, edx
        rorx	edx, r13d, 2
        xor	ebx, r11d
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r13d, 22
        add	r12d, ebx
        vpaddd	ymm2, ymm9, ymm4
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r8d, r12d
        mov	ebx, r14d
        vpaddd	ymm4, ymm2, YMMWORD PTR [rbp+320]
        ; rnd_1: 6 - 6
        xor	ebx, r13d
        add	r12d, edx
        and	eax, ebx
        ; rnd_1: 7 - 7
        xor	eax, r14d
        rorx	edx, r8d, 6
        add	r12d, eax
        vmovdqu	YMMWORD PTR [rsp+320], ymm4
        ; rnd_0: 0 - 0
        mov	eax, r9d
        rorx	ecx, r8d, 11
        add	r11d, DWORD PTR [rsp+224]
        vpalignr	ymm5, ymm0, ymm3, 4
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r10d
        rorx	edx, r8d, 25
        vpalignr	ymm4, ymm2, ymm1, 4
        ; rnd_0: 2 - 2
        and	eax, r8d
        xor	edx, ecx
        rorx	ecx, r12d, 13
        vpsrld	ymm6, ymm5, 7
        ; rnd_0: 3 - 3
        add	r11d, edx
        rorx	edx, r12d, 2
        xor	eax, r10d
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r12d, 22
        add	r11d, eax
        vpsrld	ymm8, ymm5, 18
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r13d
        add	r15d, r11d
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 6 - 6
        xor	eax, r12d
        add	r11d, edx
        and	ebx, eax
        vpor	ymm6, ymm6, ymm7
        ; rnd_0: 7 - 7
        xor	ebx, r13d
        rorx	edx, r15d, 6
        add	r11d, ebx
        vpor	ymm8, ymm8, ymm9
        ; rnd_1: 0 - 0
        mov	ebx, r8d
        rorx	ecx, r15d, 11
        add	r10d, DWORD PTR [rsp+228]
        vpsrld	ymm9, ymm5, 3
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r9d
        rorx	edx, r15d, 25
        vpxor	ymm6, ymm6, ymm8
        ; rnd_1: 2 - 2
        and	ebx, r15d
        xor	edx, ecx
        rorx	ecx, r11d, 13
        vpshufd	ymm7, ymm2, 250
        ; rnd_1: 3 - 3
        add	r10d, edx
        rorx	edx, r11d, 2
        xor	ebx, r9d
        vpxor	ymm5, ymm9, ymm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r11d, 22
        add	r10d, ebx
        vpsrld	ymm8, ymm7, 10
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r14d, r10d
        mov	ebx, r12d
        vpsrlq	ymm6, ymm7, 19
        ; rnd_1: 6 - 6
        xor	ebx, r11d
        add	r10d, edx
        and	eax, ebx
        vpsrlq	ymm7, ymm7, 17
        ; rnd_1: 7 - 7
        xor	eax, r12d
        rorx	edx, r14d, 6
        add	r10d, eax
        vpaddd	ymm4, ymm4, ymm3
        ; rnd_0: 0 - 0
        mov	eax, r15d
        rorx	ecx, r14d, 11
        add	r9d, DWORD PTR [rsp+232]
        vpxor	ymm6, ymm6, ymm7
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r8d
        rorx	edx, r14d, 25
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 2 - 2
        and	eax, r14d
        xor	edx, ecx
        rorx	ecx, r10d, 13
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 3 - 3
        add	r9d, edx
        rorx	edx, r10d, 2
        xor	eax, r8d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r10d, 22
        add	r9d, eax
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r11d
        add	r13d, r9d
        vpshufd	ymm6, ymm4, 80
        ; rnd_0: 6 - 6
        xor	eax, r10d
        add	r9d, edx
        and	ebx, eax
        vpsrlq	ymm8, ymm6, 17
        ; rnd_0: 7 - 7
        xor	ebx, r11d
        rorx	edx, r13d, 6
        add	r9d, ebx
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 0 - 0
        mov	ebx, r14d
        rorx	ecx, r13d, 11
        add	r8d, DWORD PTR [rsp+236]
        vpsrld	ymm9, ymm6, 10
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r15d
        rorx	edx, r13d, 25
        vpxor	ymm8, ymm8, ymm7
        ; rnd_1: 2 - 2
        and	ebx, r13d
        xor	edx, ecx
        rorx	ecx, r9d, 13
        vpxor	ymm9, ymm9, ymm8
        ; rnd_1: 3 - 3
        add	r8d, edx
        rorx	edx, r9d, 2
        xor	ebx, r15d
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r9d, 22
        add	r8d, ebx
        vpaddd	ymm3, ymm9, ymm4
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r12d, r8d
        mov	ebx, r10d
        vpaddd	ymm4, ymm3, YMMWORD PTR [rbp+352]
        ; rnd_1: 6 - 6
        xor	ebx, r9d
        add	r8d, edx
        and	eax, ebx
        ; rnd_1: 7 - 7
        xor	eax, r10d
        rorx	edx, r12d, 6
        add	r8d, eax
        vmovdqu	YMMWORD PTR [rsp+352], ymm4
        ; rnd_0: 0 - 0
        mov	eax, r13d
        rorx	ecx, r12d, 11
        add	r15d, DWORD PTR [rsp+256]
        vpalignr	ymm5, ymm1, ymm0, 4
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r14d
        rorx	edx, r12d, 25
        vpalignr	ymm4, ymm3, ymm2, 4
        ; rnd_0: 2 - 2
        and	eax, r12d
        xor	edx, ecx
        rorx	ecx, r8d, 13
        vpsrld	ymm6, ymm5, 7
        ; rnd_0: 3 - 3
        add	r15d, edx
        rorx	edx, r8d, 2
        xor	eax, r14d
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r8d, 22
        add	r15d, eax
        vpsrld	ymm8, ymm5, 18
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r9d
        add	r11d, r15d
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 6 - 6
        xor	eax, r8d
        add	r15d, edx
        and	ebx, eax
        vpor	ymm6, ymm6, ymm7
        ; rnd_0: 7 - 7
        xor	ebx, r9d
        rorx	edx, r11d, 6
        add	r15d, ebx
        vpor	ymm8, ymm8, ymm9
        ; rnd_1: 0 - 0
        mov	ebx, r12d
        rorx	ecx, r11d, 11
        add	r14d, DWORD PTR [rsp+260]
        vpsrld	ymm9, ymm5, 3
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r13d
        rorx	edx, r11d, 25
        vpxor	ymm6, ymm6, ymm8
        ; rnd_1: 2 - 2
        and	ebx, r11d
        xor	edx, ecx
        rorx	ecx, r15d, 13
        vpshufd	ymm7, ymm3, 250
        ; rnd_1: 3 - 3
        add	r14d, edx
        rorx	edx, r15d, 2
        xor	ebx, r13d
        vpxor	ymm5, ymm9, ymm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r15d, 22
        add	r14d, ebx
        vpsrld	ymm8, ymm7, 10
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r10d, r14d
        mov	ebx, r8d
        vpsrlq	ymm6, ymm7, 19
        ; rnd_1: 6 - 6
        xor	ebx, r15d
        add	r14d, edx
        and	eax, ebx
        vpsrlq	ymm7, ymm7, 17
        ; rnd_1: 7 - 7
        xor	eax, r8d
        rorx	edx, r10d, 6
        add	r14d, eax
        vpaddd	ymm4, ymm4, ymm0
        ; rnd_0: 0 - 0
        mov	eax, r11d
        rorx	ecx, r10d, 11
        add	r13d, DWORD PTR [rsp+264]
        vpxor	ymm6, ymm6, ymm7
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r12d
        rorx	edx, r10d, 25
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 2 - 2
        and	eax, r10d
        xor	edx, ecx
        rorx	ecx, r14d, 13
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 3 - 3
        add	r13d, edx
        rorx	edx, r14d, 2
        xor	eax, r12d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r14d, 22
        add	r13d, eax
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r15d
        add	r9d, r13d
        vpshufd	ymm6, ymm4, 80
        ; rnd_0: 6 - 6
        xor	eax, r14d
        add	r13d, edx
        and	ebx, eax
        vpsrlq	ymm8, ymm6, 17
        ; rnd_0: 7 - 7
        xor	ebx, r15d
        rorx	edx, r9d, 6
        add	r13d, ebx
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 0 - 0
        mov	ebx, r10d
        rorx	ecx, r9d, 11
        add	r12d, DWORD PTR [rsp+268]
        vpsrld	ymm9, ymm6, 10
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r11d
        rorx	edx, r9d, 25
        vpxor	ymm8, ymm8, ymm7
        ; rnd_1: 2 - 2
        and	ebx, r9d
        xor	edx, ecx
        rorx	ecx, r13d, 13
        vpxor	ymm9, ymm9, ymm8
        ; rnd_1: 3 - 3
        add	r12d, edx
        rorx	edx, r13d, 2
        xor	ebx, r11d
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r13d, 22
        add	r12d, ebx
        vpaddd	ymm0, ymm9, ymm4
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r8d, r12d
        mov	ebx, r14d
        vpaddd	ymm4, ymm0, YMMWORD PTR [rbp+384]
        ; rnd_1: 6 - 6
        xor	ebx, r13d
        add	r12d, edx
        and	eax, ebx
        ; rnd_1: 7 - 7
        xor	eax, r14d
        rorx	edx, r8d, 6
        add	r12d, eax
        vmovdqu	YMMWORD PTR [rsp+384], ymm4
        ; rnd_0: 0 - 0
        mov	eax, r9d
        rorx	ecx, r8d, 11
        add	r11d, DWORD PTR [rsp+288]
        vpalignr	ymm5, ymm2, ymm1, 4
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r10d
        rorx	edx, r8d, 25
        vpalignr	ymm4, ymm0, ymm3, 4
        ; rnd_0: 2 - 2
        and	eax, r8d
        xor	edx, ecx
        rorx	ecx, r12d, 13
        vpsrld	ymm6, ymm5, 7
        ; rnd_0: 3 - 3
        add	r11d, edx
        rorx	edx, r12d, 2
        xor	eax, r10d
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r12d, 22
        add	r11d, eax
        vpsrld	ymm8, ymm5, 18
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r13d
        add	r15d, r11d
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 6 - 6
        xor	eax, r12d
        add	r11d, edx
        and	ebx, eax
        vpor	ymm6, ymm6, ymm7
        ; rnd_0: 7 - 7
        xor	ebx, r13d
        rorx	edx, r15d, 6
        add	r11d, ebx
        vpor	ymm8, ymm8, ymm9
        ; rnd_1: 0 - 0
        mov	ebx, r8d
        rorx	ecx, r15d, 11
        add	r10d, DWORD PTR [rsp+292]
        vpsrld	ymm9, ymm5, 3
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r9d
        rorx	edx, r15d, 25
        vpxor	ymm6, ymm6, ymm8
        ; rnd_1: 2 - 2
        and	ebx, r15d
        xor	edx, ecx
        rorx	ecx, r11d, 13
        vpshufd	ymm7, ymm0, 250
        ; rnd_1: 3 - 3
        add	r10d, edx
        rorx	edx, r11d, 2
        xor	ebx, r9d
        vpxor	ymm5, ymm9, ymm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r11d, 22
        add	r10d, ebx
        vpsrld	ymm8, ymm7, 10
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r14d, r10d
        mov	ebx, r12d
        vpsrlq	ymm6, ymm7, 19
        ; rnd_1: 6 - 6
        xor	ebx, r11d
        add	r10d, edx
        and	eax, ebx
        vpsrlq	ymm7, ymm7, 17
        ; rnd_1: 7 - 7
        xor	eax, r12d
        rorx	edx, r14d, 6
        add	r10d, eax
        vpaddd	ymm4, ymm4, ymm1
        ; rnd_0: 0 - 0
        mov	eax, r15d
        rorx	ecx, r14d, 11
        add	r9d, DWORD PTR [rsp+296]
        vpxor	ymm6, ymm6, ymm7
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r8d
        rorx	edx, r14d, 25
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 2 - 2
        and	eax, r14d
        xor	edx, ecx
        rorx	ecx, r10d, 13
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 3 - 3
        add	r9d, edx
        rorx	edx, r10d, 2
        xor	eax, r8d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r10d, 22
        add	r9d, eax
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r11d
        add	r13d, r9d
        vpshufd	ymm6, ymm4, 80
        ; rnd_0: 6 - 6
        xor	eax, r10d
        add	r9d, edx
        and	ebx, eax
        vpsrlq	ymm8, ymm6, 17
        ; rnd_0: 7 - 7
        xor	ebx, r11d
        rorx	edx, r13d, 6
        add	r9d, ebx
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 0 - 0
        mov	ebx, r14d
        rorx	ecx, r13d, 11
        add	r8d, DWORD PTR [rsp+300]
        vpsrld	ymm9, ymm6, 10
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r15d
        rorx	edx, r13d, 25
        vpxor	ymm8, ymm8, ymm7
        ; rnd_1: 2 - 2
        and	ebx, r13d
        xor	edx, ecx
        rorx	ecx, r9d, 13
        vpxor	ymm9, ymm9, ymm8
        ; rnd_1: 3 - 3
        add	r8d, edx
        rorx	edx, r9d, 2
        xor	ebx, r15d
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r9d, 22
        add	r8d, ebx
        vpaddd	ymm1, ymm9, ymm4
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r12d, r8d
        mov	ebx, r10d
        vpaddd	ymm4, ymm1, YMMWORD PTR [rbp+416]
        ; rnd_1: 6 - 6
        xor	ebx, r9d
        add	r8d, edx
        and	eax, ebx
        ; rnd_1: 7 - 7
        xor	eax, r10d
        rorx	edx, r12d, 6
        add	r8d, eax
        vmovdqu	YMMWORD PTR [rsp+416], ymm4
        ; rnd_0: 0 - 0
        mov	eax, r13d
        rorx	ecx, r12d, 11
        add	r15d, DWORD PTR [rsp+320]
        vpalignr	ymm5, ymm3, ymm2, 4
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r14d
        rorx	edx, r12d, 25
        vpalignr	ymm4, ymm1, ymm0, 4
        ; rnd_0: 2 - 2
        and	eax, r12d
        xor	edx, ecx
        rorx	ecx, r8d, 13
        vpsrld	ymm6, ymm5, 7
        ; rnd_0: 3 - 3
        add	r15d, edx
        rorx	edx, r8d, 2
        xor	eax, r14d
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r8d, 22
        add	r15d, eax
        vpsrld	ymm8, ymm5, 18
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r9d
        add	r11d, r15d
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 6 - 6
        xor	eax, r8d
        add	r15d, edx
        and	ebx, eax
        vpor	ymm6, ymm6, ymm7
        ; rnd_0: 7 - 7
        xor	ebx, r9d
        rorx	edx, r11d, 6
        add	r15d, ebx
        vpor	ymm8, ymm8, ymm9
        ; rnd_1: 0 - 0
        mov	ebx, r12d
        rorx	ecx, r11d, 11
        add	r14d, DWORD PTR [rsp+324]
        vpsrld	ymm9, ymm5, 3
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r13d
        rorx	edx, r11d, 25
        vpxor	ymm6, ymm6, ymm8
        ; rnd_1: 2 - 2
        and	ebx, r11d
        xor	edx, ecx
        rorx	ecx, r15d, 13
        vpshufd	ymm7, ymm1, 250
        ; rnd_1: 3 - 3
        add	r14d, edx
        rorx	edx, r15d, 2
        xor	ebx, r13d
        vpxor	ymm5, ymm9, ymm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r15d, 22
        add	r14d, ebx
        vpsrld	ymm8, ymm7, 10
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r10d, r14d
        mov	ebx, r8d
        vpsrlq	ymm6, ymm7, 19
        ; rnd_1: 6 - 6
        xor	ebx, r15d
        add	r14d, edx
        and	eax, ebx
        vpsrlq	ymm7, ymm7, 17
        ; rnd_1: 7 - 7
        xor	eax, r8d
        rorx	edx, r10d, 6
        add	r14d, eax
        vpaddd	ymm4, ymm4, ymm2
        ; rnd_0: 0 - 0
        mov	eax, r11d
        rorx	ecx, r10d, 11
        add	r13d, DWORD PTR [rsp+328]
        vpxor	ymm6, ymm6, ymm7
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r12d
        rorx	edx, r10d, 25
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 2 - 2
        and	eax, r10d
        xor	edx, ecx
        rorx	ecx, r14d, 13
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 3 - 3
        add	r13d, edx
        rorx	edx, r14d, 2
        xor	eax, r12d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r14d, 22
        add	r13d, eax
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r15d
        add	r9d, r13d
        vpshufd	ymm6, ymm4, 80
        ; rnd_0: 6 - 6
        xor	eax, r14d
        add	r13d, edx
        and	ebx, eax
        vpsrlq	ymm8, ymm6, 17
        ; rnd_0: 7 - 7
        xor	ebx, r15d
        rorx	edx, r9d, 6
        add	r13d, ebx
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 0 - 0
        mov	ebx, r10d
        rorx	ecx, r9d, 11
        add	r12d, DWORD PTR [rsp+332]
        vpsrld	ymm9, ymm6, 10
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r11d
        rorx	edx, r9d, 25
        vpxor	ymm8, ymm8, ymm7
        ; rnd_1: 2 - 2
        and	ebx, r9d
        xor	edx, ecx
        rorx	ecx, r13d, 13
        vpxor	ymm9, ymm9, ymm8
        ; rnd_1: 3 - 3
        add	r12d, edx
        rorx	edx, r13d, 2
        xor	ebx, r11d
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r13d, 22
        add	r12d, ebx
        vpaddd	ymm2, ymm9, ymm4
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r8d, r12d
        mov	ebx, r14d
        vpaddd	ymm4, ymm2, YMMWORD PTR [rbp+448]
        ; rnd_1: 6 - 6
        xor	ebx, r13d
        add	r12d, edx
        and	eax, ebx
        ; rnd_1: 7 - 7
        xor	eax, r14d
        rorx	edx, r8d, 6
        add	r12d, eax
        vmovdqu	YMMWORD PTR [rsp+448], ymm4
        ; rnd_0: 0 - 0
        mov	eax, r9d
        rorx	ecx, r8d, 11
        add	r11d, DWORD PTR [rsp+352]
        vpalignr	ymm5, ymm0, ymm3, 4
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r10d
        rorx	edx, r8d, 25
        vpalignr	ymm4, ymm2, ymm1, 4
        ; rnd_0: 2 - 2
        and	eax, r8d
        xor	edx, ecx
        rorx	ecx, r12d, 13
        vpsrld	ymm6, ymm5, 7
        ; rnd_0: 3 - 3
        add	r11d, edx
        rorx	edx, r12d, 2
        xor	eax, r10d
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r12d, 22
        add	r11d, eax
        vpsrld	ymm8, ymm5, 18
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r13d
        add	r15d, r11d
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 6 - 6
        xor	eax, r12d
        add	r11d, edx
        and	ebx, eax
        vpor	ymm6, ymm6, ymm7
        ; rnd_0: 7 - 7
        xor	ebx, r13d
        rorx	edx, r15d, 6
        add	r11d, ebx
        vpor	ymm8, ymm8, ymm9
        ; rnd_1: 0 - 0
        mov	ebx, r8d
        rorx	ecx, r15d, 11
        add	r10d, DWORD PTR [rsp+356]
        vpsrld	ymm9, ymm5, 3
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r9d
        rorx	edx, r15d, 25
        vpxor	ymm6, ymm6, ymm8
        ; rnd_1: 2 - 2
        and	ebx, r15d
        xor	edx, ecx
        rorx	ecx, r11d, 13
        vpshufd	ymm7, ymm2, 250
        ; rnd_1: 3 - 3
        add	r10d, edx
        rorx	edx, r11d, 2
        xor	ebx, r9d
        vpxor	ymm5, ymm9, ymm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r11d, 22
        add	r10d, ebx
        vpsrld	ymm8, ymm7, 10
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r14d, r10d
        mov	ebx, r12d
        vpsrlq	ymm6, ymm7, 19
        ; rnd_1: 6 - 6
        xor	ebx, r11d
        add	r10d, edx
        and	eax, ebx
        vpsrlq	ymm7, ymm7, 17
        ; rnd_1: 7 - 7
        xor	eax, r12d
        rorx	edx, r14d, 6
        add	r10d, eax
        vpaddd	ymm4, ymm4, ymm3
        ; rnd_0: 0 - 0
        mov	eax, r15d
        rorx	ecx, r14d, 11
        add	r9d, DWORD PTR [rsp+360]
        vpxor	ymm6, ymm6, ymm7
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r8d
        rorx	edx, r14d, 25
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 2 - 2
        and	eax, r14d
        xor	edx, ecx
        rorx	ecx, r10d, 13
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 3 - 3
        add	r9d, edx
        rorx	edx, r10d, 2
        xor	eax, r8d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r10d, 22
        add	r9d, eax
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r11d
        add	r13d, r9d
        vpshufd	ymm6, ymm4, 80
        ; rnd_0: 6 - 6
        xor	eax, r10d
        add	r9d, edx
        and	ebx, eax
        vpsrlq	ymm8, ymm6, 17
        ; rnd_0: 7 - 7
        xor	ebx, r11d
        rorx	edx, r13d, 6
        add	r9d, ebx
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 0 - 0
        mov	ebx, r14d
        rorx	ecx, r13d, 11
        add	r8d, DWORD PTR [rsp+364]
        vpsrld	ymm9, ymm6, 10
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r15d
        rorx	edx, r13d, 25
        vpxor	ymm8, ymm8, ymm7
        ; rnd_1: 2 - 2
        and	ebx, r13d
        xor	edx, ecx
        rorx	ecx, r9d, 13
        vpxor	ymm9, ymm9, ymm8
        ; rnd_1: 3 - 3
        add	r8d, edx
        rorx	edx, r9d, 2
        xor	ebx, r15d
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r9d, 22
        add	r8d, ebx
        vpaddd	ymm3, ymm9, ymm4
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r12d, r8d
        mov	ebx, r10d
        vpaddd	ymm4, ymm3, YMMWORD PTR [rbp+480]
        ; rnd_1: 6 - 6
        xor	ebx, r9d
        add	r8d, edx
        and	eax, ebx
        ; rnd_1: 7 - 7
        xor	eax, r10d
        rorx	edx, r12d, 6
        add	r8d, eax
        vmovdqu	YMMWORD PTR [rsp+480], ymm4
        xor	eax, eax
        xor	ecx, ecx
        rorx	edx, r12d, 6
        rorx	ecx, r12d, 11
        lea	r8d, DWORD PTR [r8+rax]
        add	r15d, DWORD PTR [rsp+384]
        mov	eax, r13d
        xor	ecx, edx
        xor	eax, r14d
        rorx	edx, r12d, 25
        xor	edx, ecx
        and	eax, r12d
        add	r15d, edx
        rorx	edx, r8d, 2
        rorx	ecx, r8d, 13
        xor	eax, r14d
        xor	ecx, edx
        rorx	edx, r8d, 22
        add	r15d, eax
        xor	edx, ecx
        mov	eax, r9d
        add	r11d, r15d
        xor	eax, r8d
        and	ebx, eax
        add	r15d, edx
        xor	ebx, r9d
        rorx	edx, r11d, 6
        rorx	ecx, r11d, 11
        add	r15d, ebx
        add	r14d, DWORD PTR [rsp+388]
        mov	ebx, r12d
        xor	ecx, edx
        xor	ebx, r13d
        rorx	edx, r11d, 25
        xor	edx, ecx
        and	ebx, r11d
        add	r14d, edx
        rorx	edx, r15d, 2
        rorx	ecx, r15d, 13
        xor	ebx, r13d
        xor	ecx, edx
        rorx	edx, r15d, 22
        add	r14d, ebx
        xor	edx, ecx
        mov	ebx, r8d
        lea	r10d, DWORD PTR [r10+r14]
        xor	ebx, r15d
        and	eax, ebx
        add	r14d, edx
        xor	eax, r8d
        rorx	edx, r10d, 6
        rorx	ecx, r10d, 11
        lea	r14d, DWORD PTR [r14+rax]
        add	r13d, DWORD PTR [rsp+392]
        mov	eax, r11d
        xor	ecx, edx
        xor	eax, r12d
        rorx	edx, r10d, 25
        xor	edx, ecx
        and	eax, r10d
        add	r13d, edx
        rorx	edx, r14d, 2
        rorx	ecx, r14d, 13
        xor	eax, r12d
        xor	ecx, edx
        rorx	edx, r14d, 22
        add	r13d, eax
        xor	edx, ecx
        mov	eax, r15d
        add	r9d, r13d
        xor	eax, r14d
        and	ebx, eax
        add	r13d, edx
        xor	ebx, r15d
        rorx	edx, r9d, 6
        rorx	ecx, r9d, 11
        add	r13d, ebx
        add	r12d, DWORD PTR [rsp+396]
        mov	ebx, r10d
        xor	ecx, edx
        xor	ebx, r11d
        rorx	edx, r9d, 25
        xor	edx, ecx
        and	ebx, r9d
        add	r12d, edx
        rorx	edx, r13d, 2
        rorx	ecx, r13d, 13
        xor	ebx, r11d
        xor	ecx, edx
        rorx	edx, r13d, 22
        add	r12d, ebx
        xor	edx, ecx
        mov	ebx, r14d
        lea	r8d, DWORD PTR [r8+r12]
        xor	ebx, r13d
        and	eax, ebx
        add	r12d, edx
        xor	eax, r14d
        rorx	edx, r8d, 6
        rorx	ecx, r8d, 11
        lea	r12d, DWORD PTR [r12+rax]
        add	r11d, DWORD PTR [rsp+416]
        mov	eax, r9d
        xor	ecx, edx
        xor	eax, r10d
        rorx	edx, r8d, 25
        xor	edx, ecx
        and	eax, r8d
        add	r11d, edx
        rorx	edx, r12d, 2
        rorx	ecx, r12d, 13
        xor	eax, r10d
        xor	ecx, edx
        rorx	edx, r12d, 22
        add	r11d, eax
        xor	edx, ecx
        mov	eax, r13d
        add	r15d, r11d
        xor	eax, r12d
        and	ebx, eax
        add	r11d, edx
        xor	ebx, r13d
        rorx	edx, r15d, 6
        rorx	ecx, r15d, 11
        add	r11d, ebx
        add	r10d, DWORD PTR [rsp+420]
        mov	ebx, r8d
        xor	ecx, edx
        xor	ebx, r9d
        rorx	edx, r15d, 25
        xor	edx, ecx
        and	ebx, r15d
        add	r10d, edx
        rorx	edx, r11d, 2
        rorx	ecx, r11d, 13
        xor	ebx, r9d
        xor	ecx, edx
        rorx	edx, r11d, 22
        add	r10d, ebx
        xor	edx, ecx
        mov	ebx, r12d
        lea	r14d, DWORD PTR [r14+r10]
        xor	ebx, r11d
        and	eax, ebx
        add	r10d, edx
        xor	eax, r12d
        rorx	edx, r14d, 6
        rorx	ecx, r14d, 11
        lea	r10d, DWORD PTR [r10+rax]
        add	r9d, DWORD PTR [rsp+424]
        mov	eax, r15d
        xor	ecx, edx
        xor	eax, r8d
        rorx	edx, r14d, 25
        xor	edx, ecx
        and	eax, r14d
        add	r9d, edx
        rorx	edx, r10d, 2
        rorx	ecx, r10d, 13
        xor	eax, r8d
        xor	ecx, edx
        rorx	edx, r10d, 22
        add	r9d, eax
        xor	edx, ecx
        mov	eax, r11d
        add	r13d, r9d
        xor	eax, r10d
        and	ebx, eax
        add	r9d, edx
        xor	ebx, r11d
        rorx	edx, r13d, 6
        rorx	ecx, r13d, 11
        add	r9d, ebx
        add	r8d, DWORD PTR [rsp+428]
        mov	ebx, r14d
        xor	ecx, edx
        xor	ebx, r15d
        rorx	edx, r13d, 25
        xor	edx, ecx
        and	ebx, r13d
        add	r8d, edx
        rorx	edx, r9d, 2
        rorx	ecx, r9d, 13
        xor	ebx, r15d
        xor	ecx, edx
        rorx	edx, r9d, 22
        add	r8d, ebx
        xor	edx, ecx
        mov	ebx, r10d
        lea	r12d, DWORD PTR [r12+r8]
        xor	ebx, r9d
        and	eax, ebx
        add	r8d, edx
        xor	eax, r10d
        rorx	edx, r12d, 6
        rorx	ecx, r12d, 11
        lea	r8d, DWORD PTR [r8+rax]
        add	r15d, DWORD PTR [rsp+448]
        mov	eax, r13d
        xor	ecx, edx
        xor	eax, r14d
        rorx	edx, r12d, 25
        xor	edx, ecx
        and	eax, r12d
        add	r15d, edx
        rorx	edx, r8d, 2
        rorx	ecx, r8d, 13
        xor	eax, r14d
        xor	ecx, edx
        rorx	edx, r8d, 22
        add	r15d, eax
        xor	edx, ecx
        mov	eax, r9d
        add	r11d, r15d
        xor	eax, r8d
        and	ebx, eax
        add	r15d, edx
        xor	ebx, r9d
        rorx	edx, r11d, 6
        rorx	ecx, r11d, 11
        add	r15d, ebx
        add	r14d, DWORD PTR [rsp+452]
        mov	ebx, r12d
        xor	ecx, edx
        xor	ebx, r13d
        rorx	edx, r11d, 25
        xor	edx, ecx
        and	ebx, r11d
        add	r14d, edx
        rorx	edx, r15d, 2
        rorx	ecx, r15d, 13
        xor	ebx, r13d
        xor	ecx, edx
        rorx	edx, r15d, 22
        add	r14d, ebx
        xor	edx, ecx
        mov	ebx, r8d
        lea	r10d, DWORD PTR [r10+r14]
        xor	ebx, r15d
        and	eax, ebx
        add	r14d, edx
        xor	eax, r8d
        rorx	edx, r10d, 6
        rorx	ecx, r10d, 11
        lea	r14d, DWORD PTR [r14+rax]
        add	r13d, DWORD PTR [rsp+456]
        mov	eax, r11d
        xor	ecx, edx
        xor	eax, r12d
        rorx	edx, r10d, 25
        xor	edx, ecx
        and	eax, r10d
        add	r13d, edx
        rorx	edx, r14d, 2
        rorx	ecx, r14d, 13
        xor	eax, r12d
        xor	ecx, edx
        rorx	edx, r14d, 22
        add	r13d, eax
        xor	edx, ecx
        mov	eax, r15d
        add	r9d, r13d
        xor	eax, r14d
        and	ebx, eax
        add	r13d, edx
        xor	ebx, r15d
        rorx	edx, r9d, 6
        rorx	ecx, r9d, 11
        add	r13d, ebx
        add	r12d, DWORD PTR [rsp+460]
        mov	ebx, r10d
        xor	ecx, edx
        xor	ebx, r11d
        rorx	edx, r9d, 25
        xor	edx, ecx
        and	ebx, r9d
        add	r12d, edx
        rorx	edx, r13d, 2
        rorx	ecx, r13d, 13
        xor	ebx, r11d
        xor	ecx, edx
        rorx	edx, r13d, 22
        add	r12d, ebx
        xor	edx, ecx
        mov	ebx, r14d
        lea	r8d, DWORD PTR [r8+r12]
        xor	ebx, r13d
        and	eax, ebx
        add	r12d, edx
        xor	eax, r14d
        rorx	edx, r8d, 6
        rorx	ecx, r8d, 11
        lea	r12d, DWORD PTR [r12+rax]
        add	r11d, DWORD PTR [rsp+480]
        mov	eax, r9d
        xor	ecx, edx
        xor	eax, r10d
        rorx	edx, r8d, 25
        xor	edx, ecx
        and	eax, r8d
        add	r11d, edx
        rorx	edx, r12d, 2
        rorx	ecx, r12d, 13
        xor	eax, r10d
        xor	ecx, edx
        rorx	edx, r12d, 22
        add	r11d, eax
        xor	edx, ecx
        mov	eax, r13d
        add	r15d, r11d
        xor	eax, r12d
        and	ebx, eax
        add	r11d, edx
        xor	ebx, r13d
        rorx	edx, r15d, 6
        rorx	ecx, r15d, 11
        add	r11d, ebx
        add	r10d, DWORD PTR [rsp+484]
        mov	ebx, r8d
        xor	ecx, edx
        xor	ebx, r9d
        rorx	edx, r15d, 25
        xor	edx, ecx
        and	ebx, r15d
        add	r10d, edx
        rorx	edx, r11d, 2
        rorx	ecx, r11d, 13
        xor	ebx, r9d
        xor	ecx, edx
        rorx	edx, r11d, 22
        add	r10d, ebx
        xor	edx, ecx
        mov	ebx, r12d
        lea	r14d, DWORD PTR [r14+r10]
        xor	ebx, r11d
        and	eax, ebx
        add	r10d, edx
        xor	eax, r12d
        rorx	edx, r14d, 6
        rorx	ecx, r14d, 11
        lea	r10d, DWORD PTR [r10+rax]
        add	r9d, DWORD PTR [rsp+488]
        mov	eax, r15d
        xor	ecx, edx
        xor	eax, r8d
        rorx	edx, r14d, 25
        xor	edx, ecx
        and	eax, r14d
        add	r9d, edx
        rorx	edx, r10d, 2
        rorx	ecx, r10d, 13
        xor	eax, r8d
        xor	ecx, edx
        rorx	edx, r10d, 22
        add	r9d, eax
        xor	edx, ecx
        mov	eax, r11d
        add	r13d, r9d
        xor	eax, r10d
        and	ebx, eax
        add	r9d, edx
        xor	ebx, r11d
        rorx	edx, r13d, 6
        rorx	ecx, r13d, 11
        add	r9d, ebx
        add	r8d, DWORD PTR [rsp+492]
        mov	ebx, r14d
        xor	ecx, edx
        xor	ebx, r15d
        rorx	edx, r13d, 25
        xor	edx, ecx
        and	ebx, r13d
        add	r8d, edx
        rorx	edx, r9d, 2
        rorx	ecx, r9d, 13
        xor	ebx, r15d
        xor	ecx, edx
        rorx	edx, r9d, 22
        add	r8d, ebx
        xor	edx, ecx
        mov	ebx, r10d
        lea	r12d, DWORD PTR [r12+r8]
        xor	ebx, r9d
        and	eax, ebx
        add	r8d, edx
        xor	eax, r10d
        add	r8d, eax
        add	DWORD PTR [rdi], r8d
        add	DWORD PTR [rdi+4], r9d
        add	DWORD PTR [rdi+8], r10d
        add	DWORD PTR [rdi+12], r11d
        add	DWORD PTR [rdi+16], r12d
        add	DWORD PTR [rdi+20], r13d
        add	DWORD PTR [rdi+24], r14d
        add	DWORD PTR [rdi+28], r15d
        xor	rax, rax
        vzeroupper
        vmovdqu	xmm6, OWORD PTR [rsp+512]
        vmovdqu	xmm7, OWORD PTR [rsp+528]
        vmovdqu	xmm8, OWORD PTR [rsp+544]
        vmovdqu	xmm9, OWORD PTR [rsp+560]
        vmovdqu	xmm10, OWORD PTR [rsp+576]
        vmovdqu	xmm11, OWORD PTR [rsp+592]
        vmovdqu	xmm12, OWORD PTR [rsp+608]
        vmovdqu	xmm13, OWORD PTR [rsp+624]
        add	rsp, 640
        pop	rsi
        pop	rdi
        pop	rbp
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        pop	rbx
        ret
Transform_Sha256_AVX2_RORX ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
Transform_Sha256_AVX2_RORX_Len PROC
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
        mov	rbp, r8
        sub	rsp, 644
        vmovdqu	OWORD PTR [rsp+512], xmm6
        vmovdqu	OWORD PTR [rsp+528], xmm7
        vmovdqu	OWORD PTR [rsp+544], xmm8
        vmovdqu	OWORD PTR [rsp+560], xmm9
        vmovdqu	OWORD PTR [rsp+576], xmm10
        vmovdqu	OWORD PTR [rsp+592], xmm11
        vmovdqu	OWORD PTR [rsp+608], xmm12
        vmovdqu	OWORD PTR [rsp+624], xmm13
        test	bpl, 64
        mov	DWORD PTR [rsp+512], ebp
        je	L_sha256_len_avx2_rorx_block
        vmovdqu	ymm0, YMMWORD PTR [rsi]
        vmovdqu	ymm1, YMMWORD PTR [rsi+32]
        vmovups	YMMWORD PTR [rdi+32], ymm0
        vmovups	YMMWORD PTR [rdi+64], ymm1
        call	Transform_Sha256_AVX2_RORX
        add	rsi, 64
        sub	DWORD PTR [rsp+512], 64
        jz	L_sha256_len_avx2_rorx_done
L_sha256_len_avx2_rorx_block:
        mov	rbp, QWORD PTR [ptr_L_avx2_rorx_sha256_k]
        vmovdqu	ymm13, YMMWORD PTR L_avx2_rorx_sha256_flip_mask
        vmovdqu	ymm11, YMMWORD PTR L_avx2_rorx_sha256_shuf_00BA
        vmovdqu	ymm12, YMMWORD PTR L_avx2_rorx_sha256_shuf_DC00
        mov	r8d, DWORD PTR [rdi]
        mov	r9d, DWORD PTR [rdi+4]
        mov	r10d, DWORD PTR [rdi+8]
        mov	r11d, DWORD PTR [rdi+12]
        mov	r12d, DWORD PTR [rdi+16]
        mov	r13d, DWORD PTR [rdi+20]
        mov	r14d, DWORD PTR [rdi+24]
        mov	r15d, DWORD PTR [rdi+28]
        ; Start of loop processing two blocks
L_sha256_len_avx2_rorx_start:
        ; X0, X1, X2, X3 = W[0..15]
        vmovdqu	xmm0, OWORD PTR [rsi]
        vmovdqu	xmm1, OWORD PTR [rsi+16]
        vinserti128	ymm0, ymm0, OWORD PTR [rsi+64], 1
        vinserti128	ymm1, ymm1, OWORD PTR [rsi+80], 1
        vpshufb	ymm0, ymm0, ymm13
        vpshufb	ymm1, ymm1, ymm13
        vpaddd	ymm4, ymm0, YMMWORD PTR [rbp]
        vpaddd	ymm5, ymm1, YMMWORD PTR [rbp+32]
        vmovdqu	YMMWORD PTR [rsp], ymm4
        vmovdqu	YMMWORD PTR [rsp+32], ymm5
        vmovdqu	xmm2, OWORD PTR [rsi+32]
        vmovdqu	xmm3, OWORD PTR [rsi+48]
        vinserti128	ymm2, ymm2, OWORD PTR [rsi+96], 1
        vinserti128	ymm3, ymm3, OWORD PTR [rsi+112], 1
        vpshufb	ymm2, ymm2, ymm13
        vpshufb	ymm3, ymm3, ymm13
        vpaddd	ymm4, ymm2, YMMWORD PTR [rbp+64]
        vpaddd	ymm5, ymm3, YMMWORD PTR [rbp+96]
        vmovdqu	YMMWORD PTR [rsp+64], ymm4
        vmovdqu	YMMWORD PTR [rsp+96], ymm5
        mov	ebx, r9d
        rorx	edx, r12d, 6
        xor	ebx, r10d
        ; rnd_0: 0 - 0
        mov	eax, r13d
        rorx	ecx, r12d, 11
        add	r15d, DWORD PTR [rsp]
        vpalignr	ymm5, ymm1, ymm0, 4
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r14d
        rorx	edx, r12d, 25
        vpalignr	ymm4, ymm3, ymm2, 4
        ; rnd_0: 2 - 2
        and	eax, r12d
        xor	edx, ecx
        rorx	ecx, r8d, 13
        vpsrld	ymm6, ymm5, 7
        ; rnd_0: 3 - 3
        add	r15d, edx
        rorx	edx, r8d, 2
        xor	eax, r14d
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r8d, 22
        add	r15d, eax
        vpsrld	ymm8, ymm5, 18
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r9d
        add	r11d, r15d
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 6 - 6
        xor	eax, r8d
        add	r15d, edx
        and	ebx, eax
        vpor	ymm6, ymm6, ymm7
        ; rnd_0: 7 - 7
        xor	ebx, r9d
        rorx	edx, r11d, 6
        add	r15d, ebx
        vpor	ymm8, ymm8, ymm9
        ; rnd_1: 0 - 0
        mov	ebx, r12d
        rorx	ecx, r11d, 11
        add	r14d, DWORD PTR [rsp+4]
        vpsrld	ymm9, ymm5, 3
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r13d
        rorx	edx, r11d, 25
        vpxor	ymm6, ymm6, ymm8
        ; rnd_1: 2 - 2
        and	ebx, r11d
        xor	edx, ecx
        rorx	ecx, r15d, 13
        vpshufd	ymm7, ymm3, 250
        ; rnd_1: 3 - 3
        add	r14d, edx
        rorx	edx, r15d, 2
        xor	ebx, r13d
        vpxor	ymm5, ymm9, ymm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r15d, 22
        add	r14d, ebx
        vpsrld	ymm8, ymm7, 10
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r10d, r14d
        mov	ebx, r8d
        vpsrlq	ymm6, ymm7, 19
        ; rnd_1: 6 - 6
        xor	ebx, r15d
        add	r14d, edx
        and	eax, ebx
        vpsrlq	ymm7, ymm7, 17
        ; rnd_1: 7 - 7
        xor	eax, r8d
        rorx	edx, r10d, 6
        add	r14d, eax
        vpaddd	ymm4, ymm4, ymm0
        ; rnd_0: 0 - 0
        mov	eax, r11d
        rorx	ecx, r10d, 11
        add	r13d, DWORD PTR [rsp+8]
        vpxor	ymm6, ymm6, ymm7
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r12d
        rorx	edx, r10d, 25
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 2 - 2
        and	eax, r10d
        xor	edx, ecx
        rorx	ecx, r14d, 13
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 3 - 3
        add	r13d, edx
        rorx	edx, r14d, 2
        xor	eax, r12d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r14d, 22
        add	r13d, eax
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r15d
        add	r9d, r13d
        vpshufd	ymm6, ymm4, 80
        ; rnd_0: 6 - 6
        xor	eax, r14d
        add	r13d, edx
        and	ebx, eax
        vpsrlq	ymm8, ymm6, 17
        ; rnd_0: 7 - 7
        xor	ebx, r15d
        rorx	edx, r9d, 6
        add	r13d, ebx
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 0 - 0
        mov	ebx, r10d
        rorx	ecx, r9d, 11
        add	r12d, DWORD PTR [rsp+12]
        vpsrld	ymm9, ymm6, 10
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r11d
        rorx	edx, r9d, 25
        vpxor	ymm8, ymm8, ymm7
        ; rnd_1: 2 - 2
        and	ebx, r9d
        xor	edx, ecx
        rorx	ecx, r13d, 13
        vpxor	ymm9, ymm9, ymm8
        ; rnd_1: 3 - 3
        add	r12d, edx
        rorx	edx, r13d, 2
        xor	ebx, r11d
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r13d, 22
        add	r12d, ebx
        vpaddd	ymm0, ymm9, ymm4
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r8d, r12d
        mov	ebx, r14d
        vpaddd	ymm4, ymm0, YMMWORD PTR [rbp+128]
        ; rnd_1: 6 - 6
        xor	ebx, r13d
        add	r12d, edx
        and	eax, ebx
        ; rnd_1: 7 - 7
        xor	eax, r14d
        rorx	edx, r8d, 6
        add	r12d, eax
        vmovdqu	YMMWORD PTR [rsp+128], ymm4
        ; rnd_0: 0 - 0
        mov	eax, r9d
        rorx	ecx, r8d, 11
        add	r11d, DWORD PTR [rsp+32]
        vpalignr	ymm5, ymm2, ymm1, 4
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r10d
        rorx	edx, r8d, 25
        vpalignr	ymm4, ymm0, ymm3, 4
        ; rnd_0: 2 - 2
        and	eax, r8d
        xor	edx, ecx
        rorx	ecx, r12d, 13
        vpsrld	ymm6, ymm5, 7
        ; rnd_0: 3 - 3
        add	r11d, edx
        rorx	edx, r12d, 2
        xor	eax, r10d
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r12d, 22
        add	r11d, eax
        vpsrld	ymm8, ymm5, 18
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r13d
        add	r15d, r11d
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 6 - 6
        xor	eax, r12d
        add	r11d, edx
        and	ebx, eax
        vpor	ymm6, ymm6, ymm7
        ; rnd_0: 7 - 7
        xor	ebx, r13d
        rorx	edx, r15d, 6
        add	r11d, ebx
        vpor	ymm8, ymm8, ymm9
        ; rnd_1: 0 - 0
        mov	ebx, r8d
        rorx	ecx, r15d, 11
        add	r10d, DWORD PTR [rsp+36]
        vpsrld	ymm9, ymm5, 3
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r9d
        rorx	edx, r15d, 25
        vpxor	ymm6, ymm6, ymm8
        ; rnd_1: 2 - 2
        and	ebx, r15d
        xor	edx, ecx
        rorx	ecx, r11d, 13
        vpshufd	ymm7, ymm0, 250
        ; rnd_1: 3 - 3
        add	r10d, edx
        rorx	edx, r11d, 2
        xor	ebx, r9d
        vpxor	ymm5, ymm9, ymm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r11d, 22
        add	r10d, ebx
        vpsrld	ymm8, ymm7, 10
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r14d, r10d
        mov	ebx, r12d
        vpsrlq	ymm6, ymm7, 19
        ; rnd_1: 6 - 6
        xor	ebx, r11d
        add	r10d, edx
        and	eax, ebx
        vpsrlq	ymm7, ymm7, 17
        ; rnd_1: 7 - 7
        xor	eax, r12d
        rorx	edx, r14d, 6
        add	r10d, eax
        vpaddd	ymm4, ymm4, ymm1
        ; rnd_0: 0 - 0
        mov	eax, r15d
        rorx	ecx, r14d, 11
        add	r9d, DWORD PTR [rsp+40]
        vpxor	ymm6, ymm6, ymm7
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r8d
        rorx	edx, r14d, 25
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 2 - 2
        and	eax, r14d
        xor	edx, ecx
        rorx	ecx, r10d, 13
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 3 - 3
        add	r9d, edx
        rorx	edx, r10d, 2
        xor	eax, r8d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r10d, 22
        add	r9d, eax
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r11d
        add	r13d, r9d
        vpshufd	ymm6, ymm4, 80
        ; rnd_0: 6 - 6
        xor	eax, r10d
        add	r9d, edx
        and	ebx, eax
        vpsrlq	ymm8, ymm6, 17
        ; rnd_0: 7 - 7
        xor	ebx, r11d
        rorx	edx, r13d, 6
        add	r9d, ebx
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 0 - 0
        mov	ebx, r14d
        rorx	ecx, r13d, 11
        add	r8d, DWORD PTR [rsp+44]
        vpsrld	ymm9, ymm6, 10
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r15d
        rorx	edx, r13d, 25
        vpxor	ymm8, ymm8, ymm7
        ; rnd_1: 2 - 2
        and	ebx, r13d
        xor	edx, ecx
        rorx	ecx, r9d, 13
        vpxor	ymm9, ymm9, ymm8
        ; rnd_1: 3 - 3
        add	r8d, edx
        rorx	edx, r9d, 2
        xor	ebx, r15d
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r9d, 22
        add	r8d, ebx
        vpaddd	ymm1, ymm9, ymm4
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r12d, r8d
        mov	ebx, r10d
        vpaddd	ymm4, ymm1, YMMWORD PTR [rbp+160]
        ; rnd_1: 6 - 6
        xor	ebx, r9d
        add	r8d, edx
        and	eax, ebx
        ; rnd_1: 7 - 7
        xor	eax, r10d
        rorx	edx, r12d, 6
        add	r8d, eax
        vmovdqu	YMMWORD PTR [rsp+160], ymm4
        ; rnd_0: 0 - 0
        mov	eax, r13d
        rorx	ecx, r12d, 11
        add	r15d, DWORD PTR [rsp+64]
        vpalignr	ymm5, ymm3, ymm2, 4
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r14d
        rorx	edx, r12d, 25
        vpalignr	ymm4, ymm1, ymm0, 4
        ; rnd_0: 2 - 2
        and	eax, r12d
        xor	edx, ecx
        rorx	ecx, r8d, 13
        vpsrld	ymm6, ymm5, 7
        ; rnd_0: 3 - 3
        add	r15d, edx
        rorx	edx, r8d, 2
        xor	eax, r14d
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r8d, 22
        add	r15d, eax
        vpsrld	ymm8, ymm5, 18
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r9d
        add	r11d, r15d
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 6 - 6
        xor	eax, r8d
        add	r15d, edx
        and	ebx, eax
        vpor	ymm6, ymm6, ymm7
        ; rnd_0: 7 - 7
        xor	ebx, r9d
        rorx	edx, r11d, 6
        add	r15d, ebx
        vpor	ymm8, ymm8, ymm9
        ; rnd_1: 0 - 0
        mov	ebx, r12d
        rorx	ecx, r11d, 11
        add	r14d, DWORD PTR [rsp+68]
        vpsrld	ymm9, ymm5, 3
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r13d
        rorx	edx, r11d, 25
        vpxor	ymm6, ymm6, ymm8
        ; rnd_1: 2 - 2
        and	ebx, r11d
        xor	edx, ecx
        rorx	ecx, r15d, 13
        vpshufd	ymm7, ymm1, 250
        ; rnd_1: 3 - 3
        add	r14d, edx
        rorx	edx, r15d, 2
        xor	ebx, r13d
        vpxor	ymm5, ymm9, ymm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r15d, 22
        add	r14d, ebx
        vpsrld	ymm8, ymm7, 10
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r10d, r14d
        mov	ebx, r8d
        vpsrlq	ymm6, ymm7, 19
        ; rnd_1: 6 - 6
        xor	ebx, r15d
        add	r14d, edx
        and	eax, ebx
        vpsrlq	ymm7, ymm7, 17
        ; rnd_1: 7 - 7
        xor	eax, r8d
        rorx	edx, r10d, 6
        add	r14d, eax
        vpaddd	ymm4, ymm4, ymm2
        ; rnd_0: 0 - 0
        mov	eax, r11d
        rorx	ecx, r10d, 11
        add	r13d, DWORD PTR [rsp+72]
        vpxor	ymm6, ymm6, ymm7
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r12d
        rorx	edx, r10d, 25
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 2 - 2
        and	eax, r10d
        xor	edx, ecx
        rorx	ecx, r14d, 13
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 3 - 3
        add	r13d, edx
        rorx	edx, r14d, 2
        xor	eax, r12d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r14d, 22
        add	r13d, eax
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r15d
        add	r9d, r13d
        vpshufd	ymm6, ymm4, 80
        ; rnd_0: 6 - 6
        xor	eax, r14d
        add	r13d, edx
        and	ebx, eax
        vpsrlq	ymm8, ymm6, 17
        ; rnd_0: 7 - 7
        xor	ebx, r15d
        rorx	edx, r9d, 6
        add	r13d, ebx
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 0 - 0
        mov	ebx, r10d
        rorx	ecx, r9d, 11
        add	r12d, DWORD PTR [rsp+76]
        vpsrld	ymm9, ymm6, 10
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r11d
        rorx	edx, r9d, 25
        vpxor	ymm8, ymm8, ymm7
        ; rnd_1: 2 - 2
        and	ebx, r9d
        xor	edx, ecx
        rorx	ecx, r13d, 13
        vpxor	ymm9, ymm9, ymm8
        ; rnd_1: 3 - 3
        add	r12d, edx
        rorx	edx, r13d, 2
        xor	ebx, r11d
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r13d, 22
        add	r12d, ebx
        vpaddd	ymm2, ymm9, ymm4
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r8d, r12d
        mov	ebx, r14d
        vpaddd	ymm4, ymm2, YMMWORD PTR [rbp+192]
        ; rnd_1: 6 - 6
        xor	ebx, r13d
        add	r12d, edx
        and	eax, ebx
        ; rnd_1: 7 - 7
        xor	eax, r14d
        rorx	edx, r8d, 6
        add	r12d, eax
        vmovdqu	YMMWORD PTR [rsp+192], ymm4
        ; rnd_0: 0 - 0
        mov	eax, r9d
        rorx	ecx, r8d, 11
        add	r11d, DWORD PTR [rsp+96]
        vpalignr	ymm5, ymm0, ymm3, 4
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r10d
        rorx	edx, r8d, 25
        vpalignr	ymm4, ymm2, ymm1, 4
        ; rnd_0: 2 - 2
        and	eax, r8d
        xor	edx, ecx
        rorx	ecx, r12d, 13
        vpsrld	ymm6, ymm5, 7
        ; rnd_0: 3 - 3
        add	r11d, edx
        rorx	edx, r12d, 2
        xor	eax, r10d
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r12d, 22
        add	r11d, eax
        vpsrld	ymm8, ymm5, 18
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r13d
        add	r15d, r11d
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 6 - 6
        xor	eax, r12d
        add	r11d, edx
        and	ebx, eax
        vpor	ymm6, ymm6, ymm7
        ; rnd_0: 7 - 7
        xor	ebx, r13d
        rorx	edx, r15d, 6
        add	r11d, ebx
        vpor	ymm8, ymm8, ymm9
        ; rnd_1: 0 - 0
        mov	ebx, r8d
        rorx	ecx, r15d, 11
        add	r10d, DWORD PTR [rsp+100]
        vpsrld	ymm9, ymm5, 3
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r9d
        rorx	edx, r15d, 25
        vpxor	ymm6, ymm6, ymm8
        ; rnd_1: 2 - 2
        and	ebx, r15d
        xor	edx, ecx
        rorx	ecx, r11d, 13
        vpshufd	ymm7, ymm2, 250
        ; rnd_1: 3 - 3
        add	r10d, edx
        rorx	edx, r11d, 2
        xor	ebx, r9d
        vpxor	ymm5, ymm9, ymm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r11d, 22
        add	r10d, ebx
        vpsrld	ymm8, ymm7, 10
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r14d, r10d
        mov	ebx, r12d
        vpsrlq	ymm6, ymm7, 19
        ; rnd_1: 6 - 6
        xor	ebx, r11d
        add	r10d, edx
        and	eax, ebx
        vpsrlq	ymm7, ymm7, 17
        ; rnd_1: 7 - 7
        xor	eax, r12d
        rorx	edx, r14d, 6
        add	r10d, eax
        vpaddd	ymm4, ymm4, ymm3
        ; rnd_0: 0 - 0
        mov	eax, r15d
        rorx	ecx, r14d, 11
        add	r9d, DWORD PTR [rsp+104]
        vpxor	ymm6, ymm6, ymm7
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r8d
        rorx	edx, r14d, 25
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 2 - 2
        and	eax, r14d
        xor	edx, ecx
        rorx	ecx, r10d, 13
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 3 - 3
        add	r9d, edx
        rorx	edx, r10d, 2
        xor	eax, r8d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r10d, 22
        add	r9d, eax
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r11d
        add	r13d, r9d
        vpshufd	ymm6, ymm4, 80
        ; rnd_0: 6 - 6
        xor	eax, r10d
        add	r9d, edx
        and	ebx, eax
        vpsrlq	ymm8, ymm6, 17
        ; rnd_0: 7 - 7
        xor	ebx, r11d
        rorx	edx, r13d, 6
        add	r9d, ebx
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 0 - 0
        mov	ebx, r14d
        rorx	ecx, r13d, 11
        add	r8d, DWORD PTR [rsp+108]
        vpsrld	ymm9, ymm6, 10
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r15d
        rorx	edx, r13d, 25
        vpxor	ymm8, ymm8, ymm7
        ; rnd_1: 2 - 2
        and	ebx, r13d
        xor	edx, ecx
        rorx	ecx, r9d, 13
        vpxor	ymm9, ymm9, ymm8
        ; rnd_1: 3 - 3
        add	r8d, edx
        rorx	edx, r9d, 2
        xor	ebx, r15d
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r9d, 22
        add	r8d, ebx
        vpaddd	ymm3, ymm9, ymm4
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r12d, r8d
        mov	ebx, r10d
        vpaddd	ymm4, ymm3, YMMWORD PTR [rbp+224]
        ; rnd_1: 6 - 6
        xor	ebx, r9d
        add	r8d, edx
        and	eax, ebx
        ; rnd_1: 7 - 7
        xor	eax, r10d
        rorx	edx, r12d, 6
        add	r8d, eax
        vmovdqu	YMMWORD PTR [rsp+224], ymm4
        ; rnd_0: 0 - 0
        mov	eax, r13d
        rorx	ecx, r12d, 11
        add	r15d, DWORD PTR [rsp+128]
        vpalignr	ymm5, ymm1, ymm0, 4
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r14d
        rorx	edx, r12d, 25
        vpalignr	ymm4, ymm3, ymm2, 4
        ; rnd_0: 2 - 2
        and	eax, r12d
        xor	edx, ecx
        rorx	ecx, r8d, 13
        vpsrld	ymm6, ymm5, 7
        ; rnd_0: 3 - 3
        add	r15d, edx
        rorx	edx, r8d, 2
        xor	eax, r14d
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r8d, 22
        add	r15d, eax
        vpsrld	ymm8, ymm5, 18
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r9d
        add	r11d, r15d
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 6 - 6
        xor	eax, r8d
        add	r15d, edx
        and	ebx, eax
        vpor	ymm6, ymm6, ymm7
        ; rnd_0: 7 - 7
        xor	ebx, r9d
        rorx	edx, r11d, 6
        add	r15d, ebx
        vpor	ymm8, ymm8, ymm9
        ; rnd_1: 0 - 0
        mov	ebx, r12d
        rorx	ecx, r11d, 11
        add	r14d, DWORD PTR [rsp+132]
        vpsrld	ymm9, ymm5, 3
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r13d
        rorx	edx, r11d, 25
        vpxor	ymm6, ymm6, ymm8
        ; rnd_1: 2 - 2
        and	ebx, r11d
        xor	edx, ecx
        rorx	ecx, r15d, 13
        vpshufd	ymm7, ymm3, 250
        ; rnd_1: 3 - 3
        add	r14d, edx
        rorx	edx, r15d, 2
        xor	ebx, r13d
        vpxor	ymm5, ymm9, ymm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r15d, 22
        add	r14d, ebx
        vpsrld	ymm8, ymm7, 10
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r10d, r14d
        mov	ebx, r8d
        vpsrlq	ymm6, ymm7, 19
        ; rnd_1: 6 - 6
        xor	ebx, r15d
        add	r14d, edx
        and	eax, ebx
        vpsrlq	ymm7, ymm7, 17
        ; rnd_1: 7 - 7
        xor	eax, r8d
        rorx	edx, r10d, 6
        add	r14d, eax
        vpaddd	ymm4, ymm4, ymm0
        ; rnd_0: 0 - 0
        mov	eax, r11d
        rorx	ecx, r10d, 11
        add	r13d, DWORD PTR [rsp+136]
        vpxor	ymm6, ymm6, ymm7
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r12d
        rorx	edx, r10d, 25
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 2 - 2
        and	eax, r10d
        xor	edx, ecx
        rorx	ecx, r14d, 13
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 3 - 3
        add	r13d, edx
        rorx	edx, r14d, 2
        xor	eax, r12d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r14d, 22
        add	r13d, eax
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r15d
        add	r9d, r13d
        vpshufd	ymm6, ymm4, 80
        ; rnd_0: 6 - 6
        xor	eax, r14d
        add	r13d, edx
        and	ebx, eax
        vpsrlq	ymm8, ymm6, 17
        ; rnd_0: 7 - 7
        xor	ebx, r15d
        rorx	edx, r9d, 6
        add	r13d, ebx
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 0 - 0
        mov	ebx, r10d
        rorx	ecx, r9d, 11
        add	r12d, DWORD PTR [rsp+140]
        vpsrld	ymm9, ymm6, 10
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r11d
        rorx	edx, r9d, 25
        vpxor	ymm8, ymm8, ymm7
        ; rnd_1: 2 - 2
        and	ebx, r9d
        xor	edx, ecx
        rorx	ecx, r13d, 13
        vpxor	ymm9, ymm9, ymm8
        ; rnd_1: 3 - 3
        add	r12d, edx
        rorx	edx, r13d, 2
        xor	ebx, r11d
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r13d, 22
        add	r12d, ebx
        vpaddd	ymm0, ymm9, ymm4
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r8d, r12d
        mov	ebx, r14d
        vpaddd	ymm4, ymm0, YMMWORD PTR [rbp+256]
        ; rnd_1: 6 - 6
        xor	ebx, r13d
        add	r12d, edx
        and	eax, ebx
        ; rnd_1: 7 - 7
        xor	eax, r14d
        rorx	edx, r8d, 6
        add	r12d, eax
        vmovdqu	YMMWORD PTR [rsp+256], ymm4
        ; rnd_0: 0 - 0
        mov	eax, r9d
        rorx	ecx, r8d, 11
        add	r11d, DWORD PTR [rsp+160]
        vpalignr	ymm5, ymm2, ymm1, 4
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r10d
        rorx	edx, r8d, 25
        vpalignr	ymm4, ymm0, ymm3, 4
        ; rnd_0: 2 - 2
        and	eax, r8d
        xor	edx, ecx
        rorx	ecx, r12d, 13
        vpsrld	ymm6, ymm5, 7
        ; rnd_0: 3 - 3
        add	r11d, edx
        rorx	edx, r12d, 2
        xor	eax, r10d
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r12d, 22
        add	r11d, eax
        vpsrld	ymm8, ymm5, 18
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r13d
        add	r15d, r11d
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 6 - 6
        xor	eax, r12d
        add	r11d, edx
        and	ebx, eax
        vpor	ymm6, ymm6, ymm7
        ; rnd_0: 7 - 7
        xor	ebx, r13d
        rorx	edx, r15d, 6
        add	r11d, ebx
        vpor	ymm8, ymm8, ymm9
        ; rnd_1: 0 - 0
        mov	ebx, r8d
        rorx	ecx, r15d, 11
        add	r10d, DWORD PTR [rsp+164]
        vpsrld	ymm9, ymm5, 3
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r9d
        rorx	edx, r15d, 25
        vpxor	ymm6, ymm6, ymm8
        ; rnd_1: 2 - 2
        and	ebx, r15d
        xor	edx, ecx
        rorx	ecx, r11d, 13
        vpshufd	ymm7, ymm0, 250
        ; rnd_1: 3 - 3
        add	r10d, edx
        rorx	edx, r11d, 2
        xor	ebx, r9d
        vpxor	ymm5, ymm9, ymm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r11d, 22
        add	r10d, ebx
        vpsrld	ymm8, ymm7, 10
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r14d, r10d
        mov	ebx, r12d
        vpsrlq	ymm6, ymm7, 19
        ; rnd_1: 6 - 6
        xor	ebx, r11d
        add	r10d, edx
        and	eax, ebx
        vpsrlq	ymm7, ymm7, 17
        ; rnd_1: 7 - 7
        xor	eax, r12d
        rorx	edx, r14d, 6
        add	r10d, eax
        vpaddd	ymm4, ymm4, ymm1
        ; rnd_0: 0 - 0
        mov	eax, r15d
        rorx	ecx, r14d, 11
        add	r9d, DWORD PTR [rsp+168]
        vpxor	ymm6, ymm6, ymm7
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r8d
        rorx	edx, r14d, 25
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 2 - 2
        and	eax, r14d
        xor	edx, ecx
        rorx	ecx, r10d, 13
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 3 - 3
        add	r9d, edx
        rorx	edx, r10d, 2
        xor	eax, r8d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r10d, 22
        add	r9d, eax
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r11d
        add	r13d, r9d
        vpshufd	ymm6, ymm4, 80
        ; rnd_0: 6 - 6
        xor	eax, r10d
        add	r9d, edx
        and	ebx, eax
        vpsrlq	ymm8, ymm6, 17
        ; rnd_0: 7 - 7
        xor	ebx, r11d
        rorx	edx, r13d, 6
        add	r9d, ebx
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 0 - 0
        mov	ebx, r14d
        rorx	ecx, r13d, 11
        add	r8d, DWORD PTR [rsp+172]
        vpsrld	ymm9, ymm6, 10
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r15d
        rorx	edx, r13d, 25
        vpxor	ymm8, ymm8, ymm7
        ; rnd_1: 2 - 2
        and	ebx, r13d
        xor	edx, ecx
        rorx	ecx, r9d, 13
        vpxor	ymm9, ymm9, ymm8
        ; rnd_1: 3 - 3
        add	r8d, edx
        rorx	edx, r9d, 2
        xor	ebx, r15d
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r9d, 22
        add	r8d, ebx
        vpaddd	ymm1, ymm9, ymm4
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r12d, r8d
        mov	ebx, r10d
        vpaddd	ymm4, ymm1, YMMWORD PTR [rbp+288]
        ; rnd_1: 6 - 6
        xor	ebx, r9d
        add	r8d, edx
        and	eax, ebx
        ; rnd_1: 7 - 7
        xor	eax, r10d
        rorx	edx, r12d, 6
        add	r8d, eax
        vmovdqu	YMMWORD PTR [rsp+288], ymm4
        ; rnd_0: 0 - 0
        mov	eax, r13d
        rorx	ecx, r12d, 11
        add	r15d, DWORD PTR [rsp+192]
        vpalignr	ymm5, ymm3, ymm2, 4
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r14d
        rorx	edx, r12d, 25
        vpalignr	ymm4, ymm1, ymm0, 4
        ; rnd_0: 2 - 2
        and	eax, r12d
        xor	edx, ecx
        rorx	ecx, r8d, 13
        vpsrld	ymm6, ymm5, 7
        ; rnd_0: 3 - 3
        add	r15d, edx
        rorx	edx, r8d, 2
        xor	eax, r14d
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r8d, 22
        add	r15d, eax
        vpsrld	ymm8, ymm5, 18
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r9d
        add	r11d, r15d
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 6 - 6
        xor	eax, r8d
        add	r15d, edx
        and	ebx, eax
        vpor	ymm6, ymm6, ymm7
        ; rnd_0: 7 - 7
        xor	ebx, r9d
        rorx	edx, r11d, 6
        add	r15d, ebx
        vpor	ymm8, ymm8, ymm9
        ; rnd_1: 0 - 0
        mov	ebx, r12d
        rorx	ecx, r11d, 11
        add	r14d, DWORD PTR [rsp+196]
        vpsrld	ymm9, ymm5, 3
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r13d
        rorx	edx, r11d, 25
        vpxor	ymm6, ymm6, ymm8
        ; rnd_1: 2 - 2
        and	ebx, r11d
        xor	edx, ecx
        rorx	ecx, r15d, 13
        vpshufd	ymm7, ymm1, 250
        ; rnd_1: 3 - 3
        add	r14d, edx
        rorx	edx, r15d, 2
        xor	ebx, r13d
        vpxor	ymm5, ymm9, ymm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r15d, 22
        add	r14d, ebx
        vpsrld	ymm8, ymm7, 10
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r10d, r14d
        mov	ebx, r8d
        vpsrlq	ymm6, ymm7, 19
        ; rnd_1: 6 - 6
        xor	ebx, r15d
        add	r14d, edx
        and	eax, ebx
        vpsrlq	ymm7, ymm7, 17
        ; rnd_1: 7 - 7
        xor	eax, r8d
        rorx	edx, r10d, 6
        add	r14d, eax
        vpaddd	ymm4, ymm4, ymm2
        ; rnd_0: 0 - 0
        mov	eax, r11d
        rorx	ecx, r10d, 11
        add	r13d, DWORD PTR [rsp+200]
        vpxor	ymm6, ymm6, ymm7
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r12d
        rorx	edx, r10d, 25
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 2 - 2
        and	eax, r10d
        xor	edx, ecx
        rorx	ecx, r14d, 13
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 3 - 3
        add	r13d, edx
        rorx	edx, r14d, 2
        xor	eax, r12d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r14d, 22
        add	r13d, eax
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r15d
        add	r9d, r13d
        vpshufd	ymm6, ymm4, 80
        ; rnd_0: 6 - 6
        xor	eax, r14d
        add	r13d, edx
        and	ebx, eax
        vpsrlq	ymm8, ymm6, 17
        ; rnd_0: 7 - 7
        xor	ebx, r15d
        rorx	edx, r9d, 6
        add	r13d, ebx
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 0 - 0
        mov	ebx, r10d
        rorx	ecx, r9d, 11
        add	r12d, DWORD PTR [rsp+204]
        vpsrld	ymm9, ymm6, 10
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r11d
        rorx	edx, r9d, 25
        vpxor	ymm8, ymm8, ymm7
        ; rnd_1: 2 - 2
        and	ebx, r9d
        xor	edx, ecx
        rorx	ecx, r13d, 13
        vpxor	ymm9, ymm9, ymm8
        ; rnd_1: 3 - 3
        add	r12d, edx
        rorx	edx, r13d, 2
        xor	ebx, r11d
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r13d, 22
        add	r12d, ebx
        vpaddd	ymm2, ymm9, ymm4
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r8d, r12d
        mov	ebx, r14d
        vpaddd	ymm4, ymm2, YMMWORD PTR [rbp+320]
        ; rnd_1: 6 - 6
        xor	ebx, r13d
        add	r12d, edx
        and	eax, ebx
        ; rnd_1: 7 - 7
        xor	eax, r14d
        rorx	edx, r8d, 6
        add	r12d, eax
        vmovdqu	YMMWORD PTR [rsp+320], ymm4
        ; rnd_0: 0 - 0
        mov	eax, r9d
        rorx	ecx, r8d, 11
        add	r11d, DWORD PTR [rsp+224]
        vpalignr	ymm5, ymm0, ymm3, 4
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r10d
        rorx	edx, r8d, 25
        vpalignr	ymm4, ymm2, ymm1, 4
        ; rnd_0: 2 - 2
        and	eax, r8d
        xor	edx, ecx
        rorx	ecx, r12d, 13
        vpsrld	ymm6, ymm5, 7
        ; rnd_0: 3 - 3
        add	r11d, edx
        rorx	edx, r12d, 2
        xor	eax, r10d
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r12d, 22
        add	r11d, eax
        vpsrld	ymm8, ymm5, 18
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r13d
        add	r15d, r11d
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 6 - 6
        xor	eax, r12d
        add	r11d, edx
        and	ebx, eax
        vpor	ymm6, ymm6, ymm7
        ; rnd_0: 7 - 7
        xor	ebx, r13d
        rorx	edx, r15d, 6
        add	r11d, ebx
        vpor	ymm8, ymm8, ymm9
        ; rnd_1: 0 - 0
        mov	ebx, r8d
        rorx	ecx, r15d, 11
        add	r10d, DWORD PTR [rsp+228]
        vpsrld	ymm9, ymm5, 3
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r9d
        rorx	edx, r15d, 25
        vpxor	ymm6, ymm6, ymm8
        ; rnd_1: 2 - 2
        and	ebx, r15d
        xor	edx, ecx
        rorx	ecx, r11d, 13
        vpshufd	ymm7, ymm2, 250
        ; rnd_1: 3 - 3
        add	r10d, edx
        rorx	edx, r11d, 2
        xor	ebx, r9d
        vpxor	ymm5, ymm9, ymm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r11d, 22
        add	r10d, ebx
        vpsrld	ymm8, ymm7, 10
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r14d, r10d
        mov	ebx, r12d
        vpsrlq	ymm6, ymm7, 19
        ; rnd_1: 6 - 6
        xor	ebx, r11d
        add	r10d, edx
        and	eax, ebx
        vpsrlq	ymm7, ymm7, 17
        ; rnd_1: 7 - 7
        xor	eax, r12d
        rorx	edx, r14d, 6
        add	r10d, eax
        vpaddd	ymm4, ymm4, ymm3
        ; rnd_0: 0 - 0
        mov	eax, r15d
        rorx	ecx, r14d, 11
        add	r9d, DWORD PTR [rsp+232]
        vpxor	ymm6, ymm6, ymm7
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r8d
        rorx	edx, r14d, 25
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 2 - 2
        and	eax, r14d
        xor	edx, ecx
        rorx	ecx, r10d, 13
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 3 - 3
        add	r9d, edx
        rorx	edx, r10d, 2
        xor	eax, r8d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r10d, 22
        add	r9d, eax
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r11d
        add	r13d, r9d
        vpshufd	ymm6, ymm4, 80
        ; rnd_0: 6 - 6
        xor	eax, r10d
        add	r9d, edx
        and	ebx, eax
        vpsrlq	ymm8, ymm6, 17
        ; rnd_0: 7 - 7
        xor	ebx, r11d
        rorx	edx, r13d, 6
        add	r9d, ebx
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 0 - 0
        mov	ebx, r14d
        rorx	ecx, r13d, 11
        add	r8d, DWORD PTR [rsp+236]
        vpsrld	ymm9, ymm6, 10
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r15d
        rorx	edx, r13d, 25
        vpxor	ymm8, ymm8, ymm7
        ; rnd_1: 2 - 2
        and	ebx, r13d
        xor	edx, ecx
        rorx	ecx, r9d, 13
        vpxor	ymm9, ymm9, ymm8
        ; rnd_1: 3 - 3
        add	r8d, edx
        rorx	edx, r9d, 2
        xor	ebx, r15d
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r9d, 22
        add	r8d, ebx
        vpaddd	ymm3, ymm9, ymm4
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r12d, r8d
        mov	ebx, r10d
        vpaddd	ymm4, ymm3, YMMWORD PTR [rbp+352]
        ; rnd_1: 6 - 6
        xor	ebx, r9d
        add	r8d, edx
        and	eax, ebx
        ; rnd_1: 7 - 7
        xor	eax, r10d
        rorx	edx, r12d, 6
        add	r8d, eax
        vmovdqu	YMMWORD PTR [rsp+352], ymm4
        ; rnd_0: 0 - 0
        mov	eax, r13d
        rorx	ecx, r12d, 11
        add	r15d, DWORD PTR [rsp+256]
        vpalignr	ymm5, ymm1, ymm0, 4
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r14d
        rorx	edx, r12d, 25
        vpalignr	ymm4, ymm3, ymm2, 4
        ; rnd_0: 2 - 2
        and	eax, r12d
        xor	edx, ecx
        rorx	ecx, r8d, 13
        vpsrld	ymm6, ymm5, 7
        ; rnd_0: 3 - 3
        add	r15d, edx
        rorx	edx, r8d, 2
        xor	eax, r14d
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r8d, 22
        add	r15d, eax
        vpsrld	ymm8, ymm5, 18
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r9d
        add	r11d, r15d
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 6 - 6
        xor	eax, r8d
        add	r15d, edx
        and	ebx, eax
        vpor	ymm6, ymm6, ymm7
        ; rnd_0: 7 - 7
        xor	ebx, r9d
        rorx	edx, r11d, 6
        add	r15d, ebx
        vpor	ymm8, ymm8, ymm9
        ; rnd_1: 0 - 0
        mov	ebx, r12d
        rorx	ecx, r11d, 11
        add	r14d, DWORD PTR [rsp+260]
        vpsrld	ymm9, ymm5, 3
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r13d
        rorx	edx, r11d, 25
        vpxor	ymm6, ymm6, ymm8
        ; rnd_1: 2 - 2
        and	ebx, r11d
        xor	edx, ecx
        rorx	ecx, r15d, 13
        vpshufd	ymm7, ymm3, 250
        ; rnd_1: 3 - 3
        add	r14d, edx
        rorx	edx, r15d, 2
        xor	ebx, r13d
        vpxor	ymm5, ymm9, ymm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r15d, 22
        add	r14d, ebx
        vpsrld	ymm8, ymm7, 10
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r10d, r14d
        mov	ebx, r8d
        vpsrlq	ymm6, ymm7, 19
        ; rnd_1: 6 - 6
        xor	ebx, r15d
        add	r14d, edx
        and	eax, ebx
        vpsrlq	ymm7, ymm7, 17
        ; rnd_1: 7 - 7
        xor	eax, r8d
        rorx	edx, r10d, 6
        add	r14d, eax
        vpaddd	ymm4, ymm4, ymm0
        ; rnd_0: 0 - 0
        mov	eax, r11d
        rorx	ecx, r10d, 11
        add	r13d, DWORD PTR [rsp+264]
        vpxor	ymm6, ymm6, ymm7
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r12d
        rorx	edx, r10d, 25
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 2 - 2
        and	eax, r10d
        xor	edx, ecx
        rorx	ecx, r14d, 13
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 3 - 3
        add	r13d, edx
        rorx	edx, r14d, 2
        xor	eax, r12d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r14d, 22
        add	r13d, eax
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r15d
        add	r9d, r13d
        vpshufd	ymm6, ymm4, 80
        ; rnd_0: 6 - 6
        xor	eax, r14d
        add	r13d, edx
        and	ebx, eax
        vpsrlq	ymm8, ymm6, 17
        ; rnd_0: 7 - 7
        xor	ebx, r15d
        rorx	edx, r9d, 6
        add	r13d, ebx
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 0 - 0
        mov	ebx, r10d
        rorx	ecx, r9d, 11
        add	r12d, DWORD PTR [rsp+268]
        vpsrld	ymm9, ymm6, 10
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r11d
        rorx	edx, r9d, 25
        vpxor	ymm8, ymm8, ymm7
        ; rnd_1: 2 - 2
        and	ebx, r9d
        xor	edx, ecx
        rorx	ecx, r13d, 13
        vpxor	ymm9, ymm9, ymm8
        ; rnd_1: 3 - 3
        add	r12d, edx
        rorx	edx, r13d, 2
        xor	ebx, r11d
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r13d, 22
        add	r12d, ebx
        vpaddd	ymm0, ymm9, ymm4
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r8d, r12d
        mov	ebx, r14d
        vpaddd	ymm4, ymm0, YMMWORD PTR [rbp+384]
        ; rnd_1: 6 - 6
        xor	ebx, r13d
        add	r12d, edx
        and	eax, ebx
        ; rnd_1: 7 - 7
        xor	eax, r14d
        rorx	edx, r8d, 6
        add	r12d, eax
        vmovdqu	YMMWORD PTR [rsp+384], ymm4
        ; rnd_0: 0 - 0
        mov	eax, r9d
        rorx	ecx, r8d, 11
        add	r11d, DWORD PTR [rsp+288]
        vpalignr	ymm5, ymm2, ymm1, 4
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r10d
        rorx	edx, r8d, 25
        vpalignr	ymm4, ymm0, ymm3, 4
        ; rnd_0: 2 - 2
        and	eax, r8d
        xor	edx, ecx
        rorx	ecx, r12d, 13
        vpsrld	ymm6, ymm5, 7
        ; rnd_0: 3 - 3
        add	r11d, edx
        rorx	edx, r12d, 2
        xor	eax, r10d
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r12d, 22
        add	r11d, eax
        vpsrld	ymm8, ymm5, 18
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r13d
        add	r15d, r11d
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 6 - 6
        xor	eax, r12d
        add	r11d, edx
        and	ebx, eax
        vpor	ymm6, ymm6, ymm7
        ; rnd_0: 7 - 7
        xor	ebx, r13d
        rorx	edx, r15d, 6
        add	r11d, ebx
        vpor	ymm8, ymm8, ymm9
        ; rnd_1: 0 - 0
        mov	ebx, r8d
        rorx	ecx, r15d, 11
        add	r10d, DWORD PTR [rsp+292]
        vpsrld	ymm9, ymm5, 3
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r9d
        rorx	edx, r15d, 25
        vpxor	ymm6, ymm6, ymm8
        ; rnd_1: 2 - 2
        and	ebx, r15d
        xor	edx, ecx
        rorx	ecx, r11d, 13
        vpshufd	ymm7, ymm0, 250
        ; rnd_1: 3 - 3
        add	r10d, edx
        rorx	edx, r11d, 2
        xor	ebx, r9d
        vpxor	ymm5, ymm9, ymm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r11d, 22
        add	r10d, ebx
        vpsrld	ymm8, ymm7, 10
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r14d, r10d
        mov	ebx, r12d
        vpsrlq	ymm6, ymm7, 19
        ; rnd_1: 6 - 6
        xor	ebx, r11d
        add	r10d, edx
        and	eax, ebx
        vpsrlq	ymm7, ymm7, 17
        ; rnd_1: 7 - 7
        xor	eax, r12d
        rorx	edx, r14d, 6
        add	r10d, eax
        vpaddd	ymm4, ymm4, ymm1
        ; rnd_0: 0 - 0
        mov	eax, r15d
        rorx	ecx, r14d, 11
        add	r9d, DWORD PTR [rsp+296]
        vpxor	ymm6, ymm6, ymm7
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r8d
        rorx	edx, r14d, 25
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 2 - 2
        and	eax, r14d
        xor	edx, ecx
        rorx	ecx, r10d, 13
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 3 - 3
        add	r9d, edx
        rorx	edx, r10d, 2
        xor	eax, r8d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r10d, 22
        add	r9d, eax
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r11d
        add	r13d, r9d
        vpshufd	ymm6, ymm4, 80
        ; rnd_0: 6 - 6
        xor	eax, r10d
        add	r9d, edx
        and	ebx, eax
        vpsrlq	ymm8, ymm6, 17
        ; rnd_0: 7 - 7
        xor	ebx, r11d
        rorx	edx, r13d, 6
        add	r9d, ebx
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 0 - 0
        mov	ebx, r14d
        rorx	ecx, r13d, 11
        add	r8d, DWORD PTR [rsp+300]
        vpsrld	ymm9, ymm6, 10
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r15d
        rorx	edx, r13d, 25
        vpxor	ymm8, ymm8, ymm7
        ; rnd_1: 2 - 2
        and	ebx, r13d
        xor	edx, ecx
        rorx	ecx, r9d, 13
        vpxor	ymm9, ymm9, ymm8
        ; rnd_1: 3 - 3
        add	r8d, edx
        rorx	edx, r9d, 2
        xor	ebx, r15d
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r9d, 22
        add	r8d, ebx
        vpaddd	ymm1, ymm9, ymm4
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r12d, r8d
        mov	ebx, r10d
        vpaddd	ymm4, ymm1, YMMWORD PTR [rbp+416]
        ; rnd_1: 6 - 6
        xor	ebx, r9d
        add	r8d, edx
        and	eax, ebx
        ; rnd_1: 7 - 7
        xor	eax, r10d
        rorx	edx, r12d, 6
        add	r8d, eax
        vmovdqu	YMMWORD PTR [rsp+416], ymm4
        ; rnd_0: 0 - 0
        mov	eax, r13d
        rorx	ecx, r12d, 11
        add	r15d, DWORD PTR [rsp+320]
        vpalignr	ymm5, ymm3, ymm2, 4
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r14d
        rorx	edx, r12d, 25
        vpalignr	ymm4, ymm1, ymm0, 4
        ; rnd_0: 2 - 2
        and	eax, r12d
        xor	edx, ecx
        rorx	ecx, r8d, 13
        vpsrld	ymm6, ymm5, 7
        ; rnd_0: 3 - 3
        add	r15d, edx
        rorx	edx, r8d, 2
        xor	eax, r14d
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r8d, 22
        add	r15d, eax
        vpsrld	ymm8, ymm5, 18
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r9d
        add	r11d, r15d
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 6 - 6
        xor	eax, r8d
        add	r15d, edx
        and	ebx, eax
        vpor	ymm6, ymm6, ymm7
        ; rnd_0: 7 - 7
        xor	ebx, r9d
        rorx	edx, r11d, 6
        add	r15d, ebx
        vpor	ymm8, ymm8, ymm9
        ; rnd_1: 0 - 0
        mov	ebx, r12d
        rorx	ecx, r11d, 11
        add	r14d, DWORD PTR [rsp+324]
        vpsrld	ymm9, ymm5, 3
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r13d
        rorx	edx, r11d, 25
        vpxor	ymm6, ymm6, ymm8
        ; rnd_1: 2 - 2
        and	ebx, r11d
        xor	edx, ecx
        rorx	ecx, r15d, 13
        vpshufd	ymm7, ymm1, 250
        ; rnd_1: 3 - 3
        add	r14d, edx
        rorx	edx, r15d, 2
        xor	ebx, r13d
        vpxor	ymm5, ymm9, ymm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r15d, 22
        add	r14d, ebx
        vpsrld	ymm8, ymm7, 10
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r10d, r14d
        mov	ebx, r8d
        vpsrlq	ymm6, ymm7, 19
        ; rnd_1: 6 - 6
        xor	ebx, r15d
        add	r14d, edx
        and	eax, ebx
        vpsrlq	ymm7, ymm7, 17
        ; rnd_1: 7 - 7
        xor	eax, r8d
        rorx	edx, r10d, 6
        add	r14d, eax
        vpaddd	ymm4, ymm4, ymm2
        ; rnd_0: 0 - 0
        mov	eax, r11d
        rorx	ecx, r10d, 11
        add	r13d, DWORD PTR [rsp+328]
        vpxor	ymm6, ymm6, ymm7
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r12d
        rorx	edx, r10d, 25
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 2 - 2
        and	eax, r10d
        xor	edx, ecx
        rorx	ecx, r14d, 13
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 3 - 3
        add	r13d, edx
        rorx	edx, r14d, 2
        xor	eax, r12d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r14d, 22
        add	r13d, eax
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r15d
        add	r9d, r13d
        vpshufd	ymm6, ymm4, 80
        ; rnd_0: 6 - 6
        xor	eax, r14d
        add	r13d, edx
        and	ebx, eax
        vpsrlq	ymm8, ymm6, 17
        ; rnd_0: 7 - 7
        xor	ebx, r15d
        rorx	edx, r9d, 6
        add	r13d, ebx
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 0 - 0
        mov	ebx, r10d
        rorx	ecx, r9d, 11
        add	r12d, DWORD PTR [rsp+332]
        vpsrld	ymm9, ymm6, 10
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r11d
        rorx	edx, r9d, 25
        vpxor	ymm8, ymm8, ymm7
        ; rnd_1: 2 - 2
        and	ebx, r9d
        xor	edx, ecx
        rorx	ecx, r13d, 13
        vpxor	ymm9, ymm9, ymm8
        ; rnd_1: 3 - 3
        add	r12d, edx
        rorx	edx, r13d, 2
        xor	ebx, r11d
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r13d, 22
        add	r12d, ebx
        vpaddd	ymm2, ymm9, ymm4
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r8d, r12d
        mov	ebx, r14d
        vpaddd	ymm4, ymm2, YMMWORD PTR [rbp+448]
        ; rnd_1: 6 - 6
        xor	ebx, r13d
        add	r12d, edx
        and	eax, ebx
        ; rnd_1: 7 - 7
        xor	eax, r14d
        rorx	edx, r8d, 6
        add	r12d, eax
        vmovdqu	YMMWORD PTR [rsp+448], ymm4
        ; rnd_0: 0 - 0
        mov	eax, r9d
        rorx	ecx, r8d, 11
        add	r11d, DWORD PTR [rsp+352]
        vpalignr	ymm5, ymm0, ymm3, 4
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r10d
        rorx	edx, r8d, 25
        vpalignr	ymm4, ymm2, ymm1, 4
        ; rnd_0: 2 - 2
        and	eax, r8d
        xor	edx, ecx
        rorx	ecx, r12d, 13
        vpsrld	ymm6, ymm5, 7
        ; rnd_0: 3 - 3
        add	r11d, edx
        rorx	edx, r12d, 2
        xor	eax, r10d
        vpslld	ymm7, ymm5, 25
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r12d, 22
        add	r11d, eax
        vpsrld	ymm8, ymm5, 18
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r13d
        add	r15d, r11d
        vpslld	ymm9, ymm5, 14
        ; rnd_0: 6 - 6
        xor	eax, r12d
        add	r11d, edx
        and	ebx, eax
        vpor	ymm6, ymm6, ymm7
        ; rnd_0: 7 - 7
        xor	ebx, r13d
        rorx	edx, r15d, 6
        add	r11d, ebx
        vpor	ymm8, ymm8, ymm9
        ; rnd_1: 0 - 0
        mov	ebx, r8d
        rorx	ecx, r15d, 11
        add	r10d, DWORD PTR [rsp+356]
        vpsrld	ymm9, ymm5, 3
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r9d
        rorx	edx, r15d, 25
        vpxor	ymm6, ymm6, ymm8
        ; rnd_1: 2 - 2
        and	ebx, r15d
        xor	edx, ecx
        rorx	ecx, r11d, 13
        vpshufd	ymm7, ymm2, 250
        ; rnd_1: 3 - 3
        add	r10d, edx
        rorx	edx, r11d, 2
        xor	ebx, r9d
        vpxor	ymm5, ymm9, ymm6
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r11d, 22
        add	r10d, ebx
        vpsrld	ymm8, ymm7, 10
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r14d, r10d
        mov	ebx, r12d
        vpsrlq	ymm6, ymm7, 19
        ; rnd_1: 6 - 6
        xor	ebx, r11d
        add	r10d, edx
        and	eax, ebx
        vpsrlq	ymm7, ymm7, 17
        ; rnd_1: 7 - 7
        xor	eax, r12d
        rorx	edx, r14d, 6
        add	r10d, eax
        vpaddd	ymm4, ymm4, ymm3
        ; rnd_0: 0 - 0
        mov	eax, r15d
        rorx	ecx, r14d, 11
        add	r9d, DWORD PTR [rsp+360]
        vpxor	ymm6, ymm6, ymm7
        ; rnd_0: 1 - 1
        xor	ecx, edx
        xor	eax, r8d
        rorx	edx, r14d, 25
        vpxor	ymm8, ymm8, ymm6
        ; rnd_0: 2 - 2
        and	eax, r14d
        xor	edx, ecx
        rorx	ecx, r10d, 13
        vpaddd	ymm4, ymm4, ymm5
        ; rnd_0: 3 - 3
        add	r9d, edx
        rorx	edx, r10d, 2
        xor	eax, r8d
        vpshufb	ymm8, ymm8, ymm11
        ; rnd_0: 4 - 4
        xor	ecx, edx
        rorx	edx, r10d, 22
        add	r9d, eax
        vpaddd	ymm4, ymm4, ymm8
        ; rnd_0: 5 - 5
        xor	edx, ecx
        mov	eax, r11d
        add	r13d, r9d
        vpshufd	ymm6, ymm4, 80
        ; rnd_0: 6 - 6
        xor	eax, r10d
        add	r9d, edx
        and	ebx, eax
        vpsrlq	ymm8, ymm6, 17
        ; rnd_0: 7 - 7
        xor	ebx, r11d
        rorx	edx, r13d, 6
        add	r9d, ebx
        vpsrlq	ymm7, ymm6, 19
        ; rnd_1: 0 - 0
        mov	ebx, r14d
        rorx	ecx, r13d, 11
        add	r8d, DWORD PTR [rsp+364]
        vpsrld	ymm9, ymm6, 10
        ; rnd_1: 1 - 1
        xor	ecx, edx
        xor	ebx, r15d
        rorx	edx, r13d, 25
        vpxor	ymm8, ymm8, ymm7
        ; rnd_1: 2 - 2
        and	ebx, r13d
        xor	edx, ecx
        rorx	ecx, r9d, 13
        vpxor	ymm9, ymm9, ymm8
        ; rnd_1: 3 - 3
        add	r8d, edx
        rorx	edx, r9d, 2
        xor	ebx, r15d
        vpshufb	ymm9, ymm9, ymm12
        ; rnd_1: 4 - 4
        xor	ecx, edx
        rorx	edx, r9d, 22
        add	r8d, ebx
        vpaddd	ymm3, ymm9, ymm4
        ; rnd_1: 5 - 5
        xor	edx, ecx
        add	r12d, r8d
        mov	ebx, r10d
        vpaddd	ymm4, ymm3, YMMWORD PTR [rbp+480]
        ; rnd_1: 6 - 6
        xor	ebx, r9d
        add	r8d, edx
        and	eax, ebx
        ; rnd_1: 7 - 7
        xor	eax, r10d
        rorx	edx, r12d, 6
        add	r8d, eax
        vmovdqu	YMMWORD PTR [rsp+480], ymm4
        xor	eax, eax
        xor	ecx, ecx
        rorx	edx, r12d, 6
        rorx	ecx, r12d, 11
        lea	r8d, DWORD PTR [r8+rax]
        add	r15d, DWORD PTR [rsp+384]
        mov	eax, r13d
        xor	ecx, edx
        xor	eax, r14d
        rorx	edx, r12d, 25
        xor	edx, ecx
        and	eax, r12d
        add	r15d, edx
        rorx	edx, r8d, 2
        rorx	ecx, r8d, 13
        xor	eax, r14d
        xor	ecx, edx
        rorx	edx, r8d, 22
        add	r15d, eax
        xor	edx, ecx
        mov	eax, r9d
        add	r11d, r15d
        xor	eax, r8d
        and	ebx, eax
        add	r15d, edx
        xor	ebx, r9d
        rorx	edx, r11d, 6
        rorx	ecx, r11d, 11
        add	r15d, ebx
        add	r14d, DWORD PTR [rsp+388]
        mov	ebx, r12d
        xor	ecx, edx
        xor	ebx, r13d
        rorx	edx, r11d, 25
        xor	edx, ecx
        and	ebx, r11d
        add	r14d, edx
        rorx	edx, r15d, 2
        rorx	ecx, r15d, 13
        xor	ebx, r13d
        xor	ecx, edx
        rorx	edx, r15d, 22
        add	r14d, ebx
        xor	edx, ecx
        mov	ebx, r8d
        lea	r10d, DWORD PTR [r10+r14]
        xor	ebx, r15d
        and	eax, ebx
        add	r14d, edx
        xor	eax, r8d
        rorx	edx, r10d, 6
        rorx	ecx, r10d, 11
        lea	r14d, DWORD PTR [r14+rax]
        add	r13d, DWORD PTR [rsp+392]
        mov	eax, r11d
        xor	ecx, edx
        xor	eax, r12d
        rorx	edx, r10d, 25
        xor	edx, ecx
        and	eax, r10d
        add	r13d, edx
        rorx	edx, r14d, 2
        rorx	ecx, r14d, 13
        xor	eax, r12d
        xor	ecx, edx
        rorx	edx, r14d, 22
        add	r13d, eax
        xor	edx, ecx
        mov	eax, r15d
        add	r9d, r13d
        xor	eax, r14d
        and	ebx, eax
        add	r13d, edx
        xor	ebx, r15d
        rorx	edx, r9d, 6
        rorx	ecx, r9d, 11
        add	r13d, ebx
        add	r12d, DWORD PTR [rsp+396]
        mov	ebx, r10d
        xor	ecx, edx
        xor	ebx, r11d
        rorx	edx, r9d, 25
        xor	edx, ecx
        and	ebx, r9d
        add	r12d, edx
        rorx	edx, r13d, 2
        rorx	ecx, r13d, 13
        xor	ebx, r11d
        xor	ecx, edx
        rorx	edx, r13d, 22
        add	r12d, ebx
        xor	edx, ecx
        mov	ebx, r14d
        lea	r8d, DWORD PTR [r8+r12]
        xor	ebx, r13d
        and	eax, ebx
        add	r12d, edx
        xor	eax, r14d
        rorx	edx, r8d, 6
        rorx	ecx, r8d, 11
        lea	r12d, DWORD PTR [r12+rax]
        add	r11d, DWORD PTR [rsp+416]
        mov	eax, r9d
        xor	ecx, edx
        xor	eax, r10d
        rorx	edx, r8d, 25
        xor	edx, ecx
        and	eax, r8d
        add	r11d, edx
        rorx	edx, r12d, 2
        rorx	ecx, r12d, 13
        xor	eax, r10d
        xor	ecx, edx
        rorx	edx, r12d, 22
        add	r11d, eax
        xor	edx, ecx
        mov	eax, r13d
        add	r15d, r11d
        xor	eax, r12d
        and	ebx, eax
        add	r11d, edx
        xor	ebx, r13d
        rorx	edx, r15d, 6
        rorx	ecx, r15d, 11
        add	r11d, ebx
        add	r10d, DWORD PTR [rsp+420]
        mov	ebx, r8d
        xor	ecx, edx
        xor	ebx, r9d
        rorx	edx, r15d, 25
        xor	edx, ecx
        and	ebx, r15d
        add	r10d, edx
        rorx	edx, r11d, 2
        rorx	ecx, r11d, 13
        xor	ebx, r9d
        xor	ecx, edx
        rorx	edx, r11d, 22
        add	r10d, ebx
        xor	edx, ecx
        mov	ebx, r12d
        lea	r14d, DWORD PTR [r14+r10]
        xor	ebx, r11d
        and	eax, ebx
        add	r10d, edx
        xor	eax, r12d
        rorx	edx, r14d, 6
        rorx	ecx, r14d, 11
        lea	r10d, DWORD PTR [r10+rax]
        add	r9d, DWORD PTR [rsp+424]
        mov	eax, r15d
        xor	ecx, edx
        xor	eax, r8d
        rorx	edx, r14d, 25
        xor	edx, ecx
        and	eax, r14d
        add	r9d, edx
        rorx	edx, r10d, 2
        rorx	ecx, r10d, 13
        xor	eax, r8d
        xor	ecx, edx
        rorx	edx, r10d, 22
        add	r9d, eax
        xor	edx, ecx
        mov	eax, r11d
        add	r13d, r9d
        xor	eax, r10d
        and	ebx, eax
        add	r9d, edx
        xor	ebx, r11d
        rorx	edx, r13d, 6
        rorx	ecx, r13d, 11
        add	r9d, ebx
        add	r8d, DWORD PTR [rsp+428]
        mov	ebx, r14d
        xor	ecx, edx
        xor	ebx, r15d
        rorx	edx, r13d, 25
        xor	edx, ecx
        and	ebx, r13d
        add	r8d, edx
        rorx	edx, r9d, 2
        rorx	ecx, r9d, 13
        xor	ebx, r15d
        xor	ecx, edx
        rorx	edx, r9d, 22
        add	r8d, ebx
        xor	edx, ecx
        mov	ebx, r10d
        lea	r12d, DWORD PTR [r12+r8]
        xor	ebx, r9d
        and	eax, ebx
        add	r8d, edx
        xor	eax, r10d
        rorx	edx, r12d, 6
        rorx	ecx, r12d, 11
        lea	r8d, DWORD PTR [r8+rax]
        add	r15d, DWORD PTR [rsp+448]
        mov	eax, r13d
        xor	ecx, edx
        xor	eax, r14d
        rorx	edx, r12d, 25
        xor	edx, ecx
        and	eax, r12d
        add	r15d, edx
        rorx	edx, r8d, 2
        rorx	ecx, r8d, 13
        xor	eax, r14d
        xor	ecx, edx
        rorx	edx, r8d, 22
        add	r15d, eax
        xor	edx, ecx
        mov	eax, r9d
        add	r11d, r15d
        xor	eax, r8d
        and	ebx, eax
        add	r15d, edx
        xor	ebx, r9d
        rorx	edx, r11d, 6
        rorx	ecx, r11d, 11
        add	r15d, ebx
        add	r14d, DWORD PTR [rsp+452]
        mov	ebx, r12d
        xor	ecx, edx
        xor	ebx, r13d
        rorx	edx, r11d, 25
        xor	edx, ecx
        and	ebx, r11d
        add	r14d, edx
        rorx	edx, r15d, 2
        rorx	ecx, r15d, 13
        xor	ebx, r13d
        xor	ecx, edx
        rorx	edx, r15d, 22
        add	r14d, ebx
        xor	edx, ecx
        mov	ebx, r8d
        lea	r10d, DWORD PTR [r10+r14]
        xor	ebx, r15d
        and	eax, ebx
        add	r14d, edx
        xor	eax, r8d
        rorx	edx, r10d, 6
        rorx	ecx, r10d, 11
        lea	r14d, DWORD PTR [r14+rax]
        add	r13d, DWORD PTR [rsp+456]
        mov	eax, r11d
        xor	ecx, edx
        xor	eax, r12d
        rorx	edx, r10d, 25
        xor	edx, ecx
        and	eax, r10d
        add	r13d, edx
        rorx	edx, r14d, 2
        rorx	ecx, r14d, 13
        xor	eax, r12d
        xor	ecx, edx
        rorx	edx, r14d, 22
        add	r13d, eax
        xor	edx, ecx
        mov	eax, r15d
        add	r9d, r13d
        xor	eax, r14d
        and	ebx, eax
        add	r13d, edx
        xor	ebx, r15d
        rorx	edx, r9d, 6
        rorx	ecx, r9d, 11
        add	r13d, ebx
        add	r12d, DWORD PTR [rsp+460]
        mov	ebx, r10d
        xor	ecx, edx
        xor	ebx, r11d
        rorx	edx, r9d, 25
        xor	edx, ecx
        and	ebx, r9d
        add	r12d, edx
        rorx	edx, r13d, 2
        rorx	ecx, r13d, 13
        xor	ebx, r11d
        xor	ecx, edx
        rorx	edx, r13d, 22
        add	r12d, ebx
        xor	edx, ecx
        mov	ebx, r14d
        lea	r8d, DWORD PTR [r8+r12]
        xor	ebx, r13d
        and	eax, ebx
        add	r12d, edx
        xor	eax, r14d
        rorx	edx, r8d, 6
        rorx	ecx, r8d, 11
        lea	r12d, DWORD PTR [r12+rax]
        add	r11d, DWORD PTR [rsp+480]
        mov	eax, r9d
        xor	ecx, edx
        xor	eax, r10d
        rorx	edx, r8d, 25
        xor	edx, ecx
        and	eax, r8d
        add	r11d, edx
        rorx	edx, r12d, 2
        rorx	ecx, r12d, 13
        xor	eax, r10d
        xor	ecx, edx
        rorx	edx, r12d, 22
        add	r11d, eax
        xor	edx, ecx
        mov	eax, r13d
        add	r15d, r11d
        xor	eax, r12d
        and	ebx, eax
        add	r11d, edx
        xor	ebx, r13d
        rorx	edx, r15d, 6
        rorx	ecx, r15d, 11
        add	r11d, ebx
        add	r10d, DWORD PTR [rsp+484]
        mov	ebx, r8d
        xor	ecx, edx
        xor	ebx, r9d
        rorx	edx, r15d, 25
        xor	edx, ecx
        and	ebx, r15d
        add	r10d, edx
        rorx	edx, r11d, 2
        rorx	ecx, r11d, 13
        xor	ebx, r9d
        xor	ecx, edx
        rorx	edx, r11d, 22
        add	r10d, ebx
        xor	edx, ecx
        mov	ebx, r12d
        lea	r14d, DWORD PTR [r14+r10]
        xor	ebx, r11d
        and	eax, ebx
        add	r10d, edx
        xor	eax, r12d
        rorx	edx, r14d, 6
        rorx	ecx, r14d, 11
        lea	r10d, DWORD PTR [r10+rax]
        add	r9d, DWORD PTR [rsp+488]
        mov	eax, r15d
        xor	ecx, edx
        xor	eax, r8d
        rorx	edx, r14d, 25
        xor	edx, ecx
        and	eax, r14d
        add	r9d, edx
        rorx	edx, r10d, 2
        rorx	ecx, r10d, 13
        xor	eax, r8d
        xor	ecx, edx
        rorx	edx, r10d, 22
        add	r9d, eax
        xor	edx, ecx
        mov	eax, r11d
        add	r13d, r9d
        xor	eax, r10d
        and	ebx, eax
        add	r9d, edx
        xor	ebx, r11d
        rorx	edx, r13d, 6
        rorx	ecx, r13d, 11
        add	r9d, ebx
        add	r8d, DWORD PTR [rsp+492]
        mov	ebx, r14d
        xor	ecx, edx
        xor	ebx, r15d
        rorx	edx, r13d, 25
        xor	edx, ecx
        and	ebx, r13d
        add	r8d, edx
        rorx	edx, r9d, 2
        rorx	ecx, r9d, 13
        xor	ebx, r15d
        xor	ecx, edx
        rorx	edx, r9d, 22
        add	r8d, ebx
        xor	edx, ecx
        mov	ebx, r10d
        lea	r12d, DWORD PTR [r12+r8]
        xor	ebx, r9d
        and	eax, ebx
        add	r8d, edx
        xor	eax, r10d
        add	r8d, eax
        xor	ecx, ecx
        add	r8d, DWORD PTR [rdi]
        add	r9d, DWORD PTR [rdi+4]
        add	r10d, DWORD PTR [rdi+8]
        add	r11d, DWORD PTR [rdi+12]
        add	r12d, DWORD PTR [rdi+16]
        add	r13d, DWORD PTR [rdi+20]
        add	r14d, DWORD PTR [rdi+24]
        add	r15d, DWORD PTR [rdi+28]
        mov	DWORD PTR [rdi], r8d
        mov	DWORD PTR [rdi+4], r9d
        mov	DWORD PTR [rdi+8], r10d
        mov	DWORD PTR [rdi+12], r11d
        mov	DWORD PTR [rdi+16], r12d
        mov	DWORD PTR [rdi+20], r13d
        mov	DWORD PTR [rdi+24], r14d
        mov	DWORD PTR [rdi+28], r15d
        mov	ebx, r9d
        xor	eax, eax
        xor	ebx, r10d
        rorx	edx, r12d, 6
        rorx	ecx, r12d, 11
        lea	r8d, DWORD PTR [r8+rax]
        add	r15d, DWORD PTR [rsp+16]
        mov	eax, r13d
        xor	ecx, edx
        xor	eax, r14d
        rorx	edx, r12d, 25
        xor	edx, ecx
        and	eax, r12d
        add	r15d, edx
        rorx	edx, r8d, 2
        rorx	ecx, r8d, 13
        xor	eax, r14d
        xor	ecx, edx
        rorx	edx, r8d, 22
        add	r15d, eax
        xor	edx, ecx
        mov	eax, r9d
        add	r11d, r15d
        xor	eax, r8d
        and	ebx, eax
        add	r15d, edx
        xor	ebx, r9d
        rorx	edx, r11d, 6
        rorx	ecx, r11d, 11
        add	r15d, ebx
        add	r14d, DWORD PTR [rsp+20]
        mov	ebx, r12d
        xor	ecx, edx
        xor	ebx, r13d
        rorx	edx, r11d, 25
        xor	edx, ecx
        and	ebx, r11d
        add	r14d, edx
        rorx	edx, r15d, 2
        rorx	ecx, r15d, 13
        xor	ebx, r13d
        xor	ecx, edx
        rorx	edx, r15d, 22
        add	r14d, ebx
        xor	edx, ecx
        mov	ebx, r8d
        lea	r10d, DWORD PTR [r10+r14]
        xor	ebx, r15d
        and	eax, ebx
        add	r14d, edx
        xor	eax, r8d
        rorx	edx, r10d, 6
        rorx	ecx, r10d, 11
        lea	r14d, DWORD PTR [r14+rax]
        add	r13d, DWORD PTR [rsp+24]
        mov	eax, r11d
        xor	ecx, edx
        xor	eax, r12d
        rorx	edx, r10d, 25
        xor	edx, ecx
        and	eax, r10d
        add	r13d, edx
        rorx	edx, r14d, 2
        rorx	ecx, r14d, 13
        xor	eax, r12d
        xor	ecx, edx
        rorx	edx, r14d, 22
        add	r13d, eax
        xor	edx, ecx
        mov	eax, r15d
        add	r9d, r13d
        xor	eax, r14d
        and	ebx, eax
        add	r13d, edx
        xor	ebx, r15d
        rorx	edx, r9d, 6
        rorx	ecx, r9d, 11
        add	r13d, ebx
        add	r12d, DWORD PTR [rsp+28]
        mov	ebx, r10d
        xor	ecx, edx
        xor	ebx, r11d
        rorx	edx, r9d, 25
        xor	edx, ecx
        and	ebx, r9d
        add	r12d, edx
        rorx	edx, r13d, 2
        rorx	ecx, r13d, 13
        xor	ebx, r11d
        xor	ecx, edx
        rorx	edx, r13d, 22
        add	r12d, ebx
        xor	edx, ecx
        mov	ebx, r14d
        lea	r8d, DWORD PTR [r8+r12]
        xor	ebx, r13d
        and	eax, ebx
        add	r12d, edx
        xor	eax, r14d
        rorx	edx, r8d, 6
        rorx	ecx, r8d, 11
        lea	r12d, DWORD PTR [r12+rax]
        add	r11d, DWORD PTR [rsp+48]
        mov	eax, r9d
        xor	ecx, edx
        xor	eax, r10d
        rorx	edx, r8d, 25
        xor	edx, ecx
        and	eax, r8d
        add	r11d, edx
        rorx	edx, r12d, 2
        rorx	ecx, r12d, 13
        xor	eax, r10d
        xor	ecx, edx
        rorx	edx, r12d, 22
        add	r11d, eax
        xor	edx, ecx
        mov	eax, r13d
        add	r15d, r11d
        xor	eax, r12d
        and	ebx, eax
        add	r11d, edx
        xor	ebx, r13d
        rorx	edx, r15d, 6
        rorx	ecx, r15d, 11
        add	r11d, ebx
        add	r10d, DWORD PTR [rsp+52]
        mov	ebx, r8d
        xor	ecx, edx
        xor	ebx, r9d
        rorx	edx, r15d, 25
        xor	edx, ecx
        and	ebx, r15d
        add	r10d, edx
        rorx	edx, r11d, 2
        rorx	ecx, r11d, 13
        xor	ebx, r9d
        xor	ecx, edx
        rorx	edx, r11d, 22
        add	r10d, ebx
        xor	edx, ecx
        mov	ebx, r12d
        lea	r14d, DWORD PTR [r14+r10]
        xor	ebx, r11d
        and	eax, ebx
        add	r10d, edx
        xor	eax, r12d
        rorx	edx, r14d, 6
        rorx	ecx, r14d, 11
        lea	r10d, DWORD PTR [r10+rax]
        add	r9d, DWORD PTR [rsp+56]
        mov	eax, r15d
        xor	ecx, edx
        xor	eax, r8d
        rorx	edx, r14d, 25
        xor	edx, ecx
        and	eax, r14d
        add	r9d, edx
        rorx	edx, r10d, 2
        rorx	ecx, r10d, 13
        xor	eax, r8d
        xor	ecx, edx
        rorx	edx, r10d, 22
        add	r9d, eax
        xor	edx, ecx
        mov	eax, r11d
        add	r13d, r9d
        xor	eax, r10d
        and	ebx, eax
        add	r9d, edx
        xor	ebx, r11d
        rorx	edx, r13d, 6
        rorx	ecx, r13d, 11
        add	r9d, ebx
        add	r8d, DWORD PTR [rsp+60]
        mov	ebx, r14d
        xor	ecx, edx
        xor	ebx, r15d
        rorx	edx, r13d, 25
        xor	edx, ecx
        and	ebx, r13d
        add	r8d, edx
        rorx	edx, r9d, 2
        rorx	ecx, r9d, 13
        xor	ebx, r15d
        xor	ecx, edx
        rorx	edx, r9d, 22
        add	r8d, ebx
        xor	edx, ecx
        mov	ebx, r10d
        lea	r12d, DWORD PTR [r12+r8]
        xor	ebx, r9d
        and	eax, ebx
        add	r8d, edx
        xor	eax, r10d
        rorx	edx, r12d, 6
        rorx	ecx, r12d, 11
        lea	r8d, DWORD PTR [r8+rax]
        add	r15d, DWORD PTR [rsp+80]
        mov	eax, r13d
        xor	ecx, edx
        xor	eax, r14d
        rorx	edx, r12d, 25
        xor	edx, ecx
        and	eax, r12d
        add	r15d, edx
        rorx	edx, r8d, 2
        rorx	ecx, r8d, 13
        xor	eax, r14d
        xor	ecx, edx
        rorx	edx, r8d, 22
        add	r15d, eax
        xor	edx, ecx
        mov	eax, r9d
        add	r11d, r15d
        xor	eax, r8d
        and	ebx, eax
        add	r15d, edx
        xor	ebx, r9d
        rorx	edx, r11d, 6
        rorx	ecx, r11d, 11
        add	r15d, ebx
        add	r14d, DWORD PTR [rsp+84]
        mov	ebx, r12d
        xor	ecx, edx
        xor	ebx, r13d
        rorx	edx, r11d, 25
        xor	edx, ecx
        and	ebx, r11d
        add	r14d, edx
        rorx	edx, r15d, 2
        rorx	ecx, r15d, 13
        xor	ebx, r13d
        xor	ecx, edx
        rorx	edx, r15d, 22
        add	r14d, ebx
        xor	edx, ecx
        mov	ebx, r8d
        lea	r10d, DWORD PTR [r10+r14]
        xor	ebx, r15d
        and	eax, ebx
        add	r14d, edx
        xor	eax, r8d
        rorx	edx, r10d, 6
        rorx	ecx, r10d, 11
        lea	r14d, DWORD PTR [r14+rax]
        add	r13d, DWORD PTR [rsp+88]
        mov	eax, r11d
        xor	ecx, edx
        xor	eax, r12d
        rorx	edx, r10d, 25
        xor	edx, ecx
        and	eax, r10d
        add	r13d, edx
        rorx	edx, r14d, 2
        rorx	ecx, r14d, 13
        xor	eax, r12d
        xor	ecx, edx
        rorx	edx, r14d, 22
        add	r13d, eax
        xor	edx, ecx
        mov	eax, r15d
        add	r9d, r13d
        xor	eax, r14d
        and	ebx, eax
        add	r13d, edx
        xor	ebx, r15d
        rorx	edx, r9d, 6
        rorx	ecx, r9d, 11
        add	r13d, ebx
        add	r12d, DWORD PTR [rsp+92]
        mov	ebx, r10d
        xor	ecx, edx
        xor	ebx, r11d
        rorx	edx, r9d, 25
        xor	edx, ecx
        and	ebx, r9d
        add	r12d, edx
        rorx	edx, r13d, 2
        rorx	ecx, r13d, 13
        xor	ebx, r11d
        xor	ecx, edx
        rorx	edx, r13d, 22
        add	r12d, ebx
        xor	edx, ecx
        mov	ebx, r14d
        lea	r8d, DWORD PTR [r8+r12]
        xor	ebx, r13d
        and	eax, ebx
        add	r12d, edx
        xor	eax, r14d
        rorx	edx, r8d, 6
        rorx	ecx, r8d, 11
        lea	r12d, DWORD PTR [r12+rax]
        add	r11d, DWORD PTR [rsp+112]
        mov	eax, r9d
        xor	ecx, edx
        xor	eax, r10d
        rorx	edx, r8d, 25
        xor	edx, ecx
        and	eax, r8d
        add	r11d, edx
        rorx	edx, r12d, 2
        rorx	ecx, r12d, 13
        xor	eax, r10d
        xor	ecx, edx
        rorx	edx, r12d, 22
        add	r11d, eax
        xor	edx, ecx
        mov	eax, r13d
        add	r15d, r11d
        xor	eax, r12d
        and	ebx, eax
        add	r11d, edx
        xor	ebx, r13d
        rorx	edx, r15d, 6
        rorx	ecx, r15d, 11
        add	r11d, ebx
        add	r10d, DWORD PTR [rsp+116]
        mov	ebx, r8d
        xor	ecx, edx
        xor	ebx, r9d
        rorx	edx, r15d, 25
        xor	edx, ecx
        and	ebx, r15d
        add	r10d, edx
        rorx	edx, r11d, 2
        rorx	ecx, r11d, 13
        xor	ebx, r9d
        xor	ecx, edx
        rorx	edx, r11d, 22
        add	r10d, ebx
        xor	edx, ecx
        mov	ebx, r12d
        lea	r14d, DWORD PTR [r14+r10]
        xor	ebx, r11d
        and	eax, ebx
        add	r10d, edx
        xor	eax, r12d
        rorx	edx, r14d, 6
        rorx	ecx, r14d, 11
        lea	r10d, DWORD PTR [r10+rax]
        add	r9d, DWORD PTR [rsp+120]
        mov	eax, r15d
        xor	ecx, edx
        xor	eax, r8d
        rorx	edx, r14d, 25
        xor	edx, ecx
        and	eax, r14d
        add	r9d, edx
        rorx	edx, r10d, 2
        rorx	ecx, r10d, 13
        xor	eax, r8d
        xor	ecx, edx
        rorx	edx, r10d, 22
        add	r9d, eax
        xor	edx, ecx
        mov	eax, r11d
        add	r13d, r9d
        xor	eax, r10d
        and	ebx, eax
        add	r9d, edx
        xor	ebx, r11d
        rorx	edx, r13d, 6
        rorx	ecx, r13d, 11
        add	r9d, ebx
        add	r8d, DWORD PTR [rsp+124]
        mov	ebx, r14d
        xor	ecx, edx
        xor	ebx, r15d
        rorx	edx, r13d, 25
        xor	edx, ecx
        and	ebx, r13d
        add	r8d, edx
        rorx	edx, r9d, 2
        rorx	ecx, r9d, 13
        xor	ebx, r15d
        xor	ecx, edx
        rorx	edx, r9d, 22
        add	r8d, ebx
        xor	edx, ecx
        mov	ebx, r10d
        lea	r12d, DWORD PTR [r12+r8]
        xor	ebx, r9d
        and	eax, ebx
        add	r8d, edx
        xor	eax, r10d
        rorx	edx, r12d, 6
        rorx	ecx, r12d, 11
        lea	r8d, DWORD PTR [r8+rax]
        add	r15d, DWORD PTR [rsp+144]
        mov	eax, r13d
        xor	ecx, edx
        xor	eax, r14d
        rorx	edx, r12d, 25
        xor	edx, ecx
        and	eax, r12d
        add	r15d, edx
        rorx	edx, r8d, 2
        rorx	ecx, r8d, 13
        xor	eax, r14d
        xor	ecx, edx
        rorx	edx, r8d, 22
        add	r15d, eax
        xor	edx, ecx
        mov	eax, r9d
        add	r11d, r15d
        xor	eax, r8d
        and	ebx, eax
        add	r15d, edx
        xor	ebx, r9d
        rorx	edx, r11d, 6
        rorx	ecx, r11d, 11
        add	r15d, ebx
        add	r14d, DWORD PTR [rsp+148]
        mov	ebx, r12d
        xor	ecx, edx
        xor	ebx, r13d
        rorx	edx, r11d, 25
        xor	edx, ecx
        and	ebx, r11d
        add	r14d, edx
        rorx	edx, r15d, 2
        rorx	ecx, r15d, 13
        xor	ebx, r13d
        xor	ecx, edx
        rorx	edx, r15d, 22
        add	r14d, ebx
        xor	edx, ecx
        mov	ebx, r8d
        lea	r10d, DWORD PTR [r10+r14]
        xor	ebx, r15d
        and	eax, ebx
        add	r14d, edx
        xor	eax, r8d
        rorx	edx, r10d, 6
        rorx	ecx, r10d, 11
        lea	r14d, DWORD PTR [r14+rax]
        add	r13d, DWORD PTR [rsp+152]
        mov	eax, r11d
        xor	ecx, edx
        xor	eax, r12d
        rorx	edx, r10d, 25
        xor	edx, ecx
        and	eax, r10d
        add	r13d, edx
        rorx	edx, r14d, 2
        rorx	ecx, r14d, 13
        xor	eax, r12d
        xor	ecx, edx
        rorx	edx, r14d, 22
        add	r13d, eax
        xor	edx, ecx
        mov	eax, r15d
        add	r9d, r13d
        xor	eax, r14d
        and	ebx, eax
        add	r13d, edx
        xor	ebx, r15d
        rorx	edx, r9d, 6
        rorx	ecx, r9d, 11
        add	r13d, ebx
        add	r12d, DWORD PTR [rsp+156]
        mov	ebx, r10d
        xor	ecx, edx
        xor	ebx, r11d
        rorx	edx, r9d, 25
        xor	edx, ecx
        and	ebx, r9d
        add	r12d, edx
        rorx	edx, r13d, 2
        rorx	ecx, r13d, 13
        xor	ebx, r11d
        xor	ecx, edx
        rorx	edx, r13d, 22
        add	r12d, ebx
        xor	edx, ecx
        mov	ebx, r14d
        lea	r8d, DWORD PTR [r8+r12]
        xor	ebx, r13d
        and	eax, ebx
        add	r12d, edx
        xor	eax, r14d
        rorx	edx, r8d, 6
        rorx	ecx, r8d, 11
        lea	r12d, DWORD PTR [r12+rax]
        add	r11d, DWORD PTR [rsp+176]
        mov	eax, r9d
        xor	ecx, edx
        xor	eax, r10d
        rorx	edx, r8d, 25
        xor	edx, ecx
        and	eax, r8d
        add	r11d, edx
        rorx	edx, r12d, 2
        rorx	ecx, r12d, 13
        xor	eax, r10d
        xor	ecx, edx
        rorx	edx, r12d, 22
        add	r11d, eax
        xor	edx, ecx
        mov	eax, r13d
        add	r15d, r11d
        xor	eax, r12d
        and	ebx, eax
        add	r11d, edx
        xor	ebx, r13d
        rorx	edx, r15d, 6
        rorx	ecx, r15d, 11
        add	r11d, ebx
        add	r10d, DWORD PTR [rsp+180]
        mov	ebx, r8d
        xor	ecx, edx
        xor	ebx, r9d
        rorx	edx, r15d, 25
        xor	edx, ecx
        and	ebx, r15d
        add	r10d, edx
        rorx	edx, r11d, 2
        rorx	ecx, r11d, 13
        xor	ebx, r9d
        xor	ecx, edx
        rorx	edx, r11d, 22
        add	r10d, ebx
        xor	edx, ecx
        mov	ebx, r12d
        lea	r14d, DWORD PTR [r14+r10]
        xor	ebx, r11d
        and	eax, ebx
        add	r10d, edx
        xor	eax, r12d
        rorx	edx, r14d, 6
        rorx	ecx, r14d, 11
        lea	r10d, DWORD PTR [r10+rax]
        add	r9d, DWORD PTR [rsp+184]
        mov	eax, r15d
        xor	ecx, edx
        xor	eax, r8d
        rorx	edx, r14d, 25
        xor	edx, ecx
        and	eax, r14d
        add	r9d, edx
        rorx	edx, r10d, 2
        rorx	ecx, r10d, 13
        xor	eax, r8d
        xor	ecx, edx
        rorx	edx, r10d, 22
        add	r9d, eax
        xor	edx, ecx
        mov	eax, r11d
        add	r13d, r9d
        xor	eax, r10d
        and	ebx, eax
        add	r9d, edx
        xor	ebx, r11d
        rorx	edx, r13d, 6
        rorx	ecx, r13d, 11
        add	r9d, ebx
        add	r8d, DWORD PTR [rsp+188]
        mov	ebx, r14d
        xor	ecx, edx
        xor	ebx, r15d
        rorx	edx, r13d, 25
        xor	edx, ecx
        and	ebx, r13d
        add	r8d, edx
        rorx	edx, r9d, 2
        rorx	ecx, r9d, 13
        xor	ebx, r15d
        xor	ecx, edx
        rorx	edx, r9d, 22
        add	r8d, ebx
        xor	edx, ecx
        mov	ebx, r10d
        lea	r12d, DWORD PTR [r12+r8]
        xor	ebx, r9d
        and	eax, ebx
        add	r8d, edx
        xor	eax, r10d
        rorx	edx, r12d, 6
        rorx	ecx, r12d, 11
        lea	r8d, DWORD PTR [r8+rax]
        add	r15d, DWORD PTR [rsp+208]
        mov	eax, r13d
        xor	ecx, edx
        xor	eax, r14d
        rorx	edx, r12d, 25
        xor	edx, ecx
        and	eax, r12d
        add	r15d, edx
        rorx	edx, r8d, 2
        rorx	ecx, r8d, 13
        xor	eax, r14d
        xor	ecx, edx
        rorx	edx, r8d, 22
        add	r15d, eax
        xor	edx, ecx
        mov	eax, r9d
        add	r11d, r15d
        xor	eax, r8d
        and	ebx, eax
        add	r15d, edx
        xor	ebx, r9d
        rorx	edx, r11d, 6
        rorx	ecx, r11d, 11
        add	r15d, ebx
        add	r14d, DWORD PTR [rsp+212]
        mov	ebx, r12d
        xor	ecx, edx
        xor	ebx, r13d
        rorx	edx, r11d, 25
        xor	edx, ecx
        and	ebx, r11d
        add	r14d, edx
        rorx	edx, r15d, 2
        rorx	ecx, r15d, 13
        xor	ebx, r13d
        xor	ecx, edx
        rorx	edx, r15d, 22
        add	r14d, ebx
        xor	edx, ecx
        mov	ebx, r8d
        lea	r10d, DWORD PTR [r10+r14]
        xor	ebx, r15d
        and	eax, ebx
        add	r14d, edx
        xor	eax, r8d
        rorx	edx, r10d, 6
        rorx	ecx, r10d, 11
        lea	r14d, DWORD PTR [r14+rax]
        add	r13d, DWORD PTR [rsp+216]
        mov	eax, r11d
        xor	ecx, edx
        xor	eax, r12d
        rorx	edx, r10d, 25
        xor	edx, ecx
        and	eax, r10d
        add	r13d, edx
        rorx	edx, r14d, 2
        rorx	ecx, r14d, 13
        xor	eax, r12d
        xor	ecx, edx
        rorx	edx, r14d, 22
        add	r13d, eax
        xor	edx, ecx
        mov	eax, r15d
        add	r9d, r13d
        xor	eax, r14d
        and	ebx, eax
        add	r13d, edx
        xor	ebx, r15d
        rorx	edx, r9d, 6
        rorx	ecx, r9d, 11
        add	r13d, ebx
        add	r12d, DWORD PTR [rsp+220]
        mov	ebx, r10d
        xor	ecx, edx
        xor	ebx, r11d
        rorx	edx, r9d, 25
        xor	edx, ecx
        and	ebx, r9d
        add	r12d, edx
        rorx	edx, r13d, 2
        rorx	ecx, r13d, 13
        xor	ebx, r11d
        xor	ecx, edx
        rorx	edx, r13d, 22
        add	r12d, ebx
        xor	edx, ecx
        mov	ebx, r14d
        lea	r8d, DWORD PTR [r8+r12]
        xor	ebx, r13d
        and	eax, ebx
        add	r12d, edx
        xor	eax, r14d
        rorx	edx, r8d, 6
        rorx	ecx, r8d, 11
        lea	r12d, DWORD PTR [r12+rax]
        add	r11d, DWORD PTR [rsp+240]
        mov	eax, r9d
        xor	ecx, edx
        xor	eax, r10d
        rorx	edx, r8d, 25
        xor	edx, ecx
        and	eax, r8d
        add	r11d, edx
        rorx	edx, r12d, 2
        rorx	ecx, r12d, 13
        xor	eax, r10d
        xor	ecx, edx
        rorx	edx, r12d, 22
        add	r11d, eax
        xor	edx, ecx
        mov	eax, r13d
        add	r15d, r11d
        xor	eax, r12d
        and	ebx, eax
        add	r11d, edx
        xor	ebx, r13d
        rorx	edx, r15d, 6
        rorx	ecx, r15d, 11
        add	r11d, ebx
        add	r10d, DWORD PTR [rsp+244]
        mov	ebx, r8d
        xor	ecx, edx
        xor	ebx, r9d
        rorx	edx, r15d, 25
        xor	edx, ecx
        and	ebx, r15d
        add	r10d, edx
        rorx	edx, r11d, 2
        rorx	ecx, r11d, 13
        xor	ebx, r9d
        xor	ecx, edx
        rorx	edx, r11d, 22
        add	r10d, ebx
        xor	edx, ecx
        mov	ebx, r12d
        lea	r14d, DWORD PTR [r14+r10]
        xor	ebx, r11d
        and	eax, ebx
        add	r10d, edx
        xor	eax, r12d
        rorx	edx, r14d, 6
        rorx	ecx, r14d, 11
        lea	r10d, DWORD PTR [r10+rax]
        add	r9d, DWORD PTR [rsp+248]
        mov	eax, r15d
        xor	ecx, edx
        xor	eax, r8d
        rorx	edx, r14d, 25
        xor	edx, ecx
        and	eax, r14d
        add	r9d, edx
        rorx	edx, r10d, 2
        rorx	ecx, r10d, 13
        xor	eax, r8d
        xor	ecx, edx
        rorx	edx, r10d, 22
        add	r9d, eax
        xor	edx, ecx
        mov	eax, r11d
        add	r13d, r9d
        xor	eax, r10d
        and	ebx, eax
        add	r9d, edx
        xor	ebx, r11d
        rorx	edx, r13d, 6
        rorx	ecx, r13d, 11
        add	r9d, ebx
        add	r8d, DWORD PTR [rsp+252]
        mov	ebx, r14d
        xor	ecx, edx
        xor	ebx, r15d
        rorx	edx, r13d, 25
        xor	edx, ecx
        and	ebx, r13d
        add	r8d, edx
        rorx	edx, r9d, 2
        rorx	ecx, r9d, 13
        xor	ebx, r15d
        xor	ecx, edx
        rorx	edx, r9d, 22
        add	r8d, ebx
        xor	edx, ecx
        mov	ebx, r10d
        lea	r12d, DWORD PTR [r12+r8]
        xor	ebx, r9d
        and	eax, ebx
        add	r8d, edx
        xor	eax, r10d
        rorx	edx, r12d, 6
        rorx	ecx, r12d, 11
        lea	r8d, DWORD PTR [r8+rax]
        add	r15d, DWORD PTR [rsp+272]
        mov	eax, r13d
        xor	ecx, edx
        xor	eax, r14d
        rorx	edx, r12d, 25
        xor	edx, ecx
        and	eax, r12d
        add	r15d, edx
        rorx	edx, r8d, 2
        rorx	ecx, r8d, 13
        xor	eax, r14d
        xor	ecx, edx
        rorx	edx, r8d, 22
        add	r15d, eax
        xor	edx, ecx
        mov	eax, r9d
        add	r11d, r15d
        xor	eax, r8d
        and	ebx, eax
        add	r15d, edx
        xor	ebx, r9d
        rorx	edx, r11d, 6
        rorx	ecx, r11d, 11
        add	r15d, ebx
        add	r14d, DWORD PTR [rsp+276]
        mov	ebx, r12d
        xor	ecx, edx
        xor	ebx, r13d
        rorx	edx, r11d, 25
        xor	edx, ecx
        and	ebx, r11d
        add	r14d, edx
        rorx	edx, r15d, 2
        rorx	ecx, r15d, 13
        xor	ebx, r13d
        xor	ecx, edx
        rorx	edx, r15d, 22
        add	r14d, ebx
        xor	edx, ecx
        mov	ebx, r8d
        lea	r10d, DWORD PTR [r10+r14]
        xor	ebx, r15d
        and	eax, ebx
        add	r14d, edx
        xor	eax, r8d
        rorx	edx, r10d, 6
        rorx	ecx, r10d, 11
        lea	r14d, DWORD PTR [r14+rax]
        add	r13d, DWORD PTR [rsp+280]
        mov	eax, r11d
        xor	ecx, edx
        xor	eax, r12d
        rorx	edx, r10d, 25
        xor	edx, ecx
        and	eax, r10d
        add	r13d, edx
        rorx	edx, r14d, 2
        rorx	ecx, r14d, 13
        xor	eax, r12d
        xor	ecx, edx
        rorx	edx, r14d, 22
        add	r13d, eax
        xor	edx, ecx
        mov	eax, r15d
        add	r9d, r13d
        xor	eax, r14d
        and	ebx, eax
        add	r13d, edx
        xor	ebx, r15d
        rorx	edx, r9d, 6
        rorx	ecx, r9d, 11
        add	r13d, ebx
        add	r12d, DWORD PTR [rsp+284]
        mov	ebx, r10d
        xor	ecx, edx
        xor	ebx, r11d
        rorx	edx, r9d, 25
        xor	edx, ecx
        and	ebx, r9d
        add	r12d, edx
        rorx	edx, r13d, 2
        rorx	ecx, r13d, 13
        xor	ebx, r11d
        xor	ecx, edx
        rorx	edx, r13d, 22
        add	r12d, ebx
        xor	edx, ecx
        mov	ebx, r14d
        lea	r8d, DWORD PTR [r8+r12]
        xor	ebx, r13d
        and	eax, ebx
        add	r12d, edx
        xor	eax, r14d
        rorx	edx, r8d, 6
        rorx	ecx, r8d, 11
        lea	r12d, DWORD PTR [r12+rax]
        add	r11d, DWORD PTR [rsp+304]
        mov	eax, r9d
        xor	ecx, edx
        xor	eax, r10d
        rorx	edx, r8d, 25
        xor	edx, ecx
        and	eax, r8d
        add	r11d, edx
        rorx	edx, r12d, 2
        rorx	ecx, r12d, 13
        xor	eax, r10d
        xor	ecx, edx
        rorx	edx, r12d, 22
        add	r11d, eax
        xor	edx, ecx
        mov	eax, r13d
        add	r15d, r11d
        xor	eax, r12d
        and	ebx, eax
        add	r11d, edx
        xor	ebx, r13d
        rorx	edx, r15d, 6
        rorx	ecx, r15d, 11
        add	r11d, ebx
        add	r10d, DWORD PTR [rsp+308]
        mov	ebx, r8d
        xor	ecx, edx
        xor	ebx, r9d
        rorx	edx, r15d, 25
        xor	edx, ecx
        and	ebx, r15d
        add	r10d, edx
        rorx	edx, r11d, 2
        rorx	ecx, r11d, 13
        xor	ebx, r9d
        xor	ecx, edx
        rorx	edx, r11d, 22
        add	r10d, ebx
        xor	edx, ecx
        mov	ebx, r12d
        lea	r14d, DWORD PTR [r14+r10]
        xor	ebx, r11d
        and	eax, ebx
        add	r10d, edx
        xor	eax, r12d
        rorx	edx, r14d, 6
        rorx	ecx, r14d, 11
        lea	r10d, DWORD PTR [r10+rax]
        add	r9d, DWORD PTR [rsp+312]
        mov	eax, r15d
        xor	ecx, edx
        xor	eax, r8d
        rorx	edx, r14d, 25
        xor	edx, ecx
        and	eax, r14d
        add	r9d, edx
        rorx	edx, r10d, 2
        rorx	ecx, r10d, 13
        xor	eax, r8d
        xor	ecx, edx
        rorx	edx, r10d, 22
        add	r9d, eax
        xor	edx, ecx
        mov	eax, r11d
        add	r13d, r9d
        xor	eax, r10d
        and	ebx, eax
        add	r9d, edx
        xor	ebx, r11d
        rorx	edx, r13d, 6
        rorx	ecx, r13d, 11
        add	r9d, ebx
        add	r8d, DWORD PTR [rsp+316]
        mov	ebx, r14d
        xor	ecx, edx
        xor	ebx, r15d
        rorx	edx, r13d, 25
        xor	edx, ecx
        and	ebx, r13d
        add	r8d, edx
        rorx	edx, r9d, 2
        rorx	ecx, r9d, 13
        xor	ebx, r15d
        xor	ecx, edx
        rorx	edx, r9d, 22
        add	r8d, ebx
        xor	edx, ecx
        mov	ebx, r10d
        lea	r12d, DWORD PTR [r12+r8]
        xor	ebx, r9d
        and	eax, ebx
        add	r8d, edx
        xor	eax, r10d
        rorx	edx, r12d, 6
        rorx	ecx, r12d, 11
        lea	r8d, DWORD PTR [r8+rax]
        add	r15d, DWORD PTR [rsp+336]
        mov	eax, r13d
        xor	ecx, edx
        xor	eax, r14d
        rorx	edx, r12d, 25
        xor	edx, ecx
        and	eax, r12d
        add	r15d, edx
        rorx	edx, r8d, 2
        rorx	ecx, r8d, 13
        xor	eax, r14d
        xor	ecx, edx
        rorx	edx, r8d, 22
        add	r15d, eax
        xor	edx, ecx
        mov	eax, r9d
        add	r11d, r15d
        xor	eax, r8d
        and	ebx, eax
        add	r15d, edx
        xor	ebx, r9d
        rorx	edx, r11d, 6
        rorx	ecx, r11d, 11
        add	r15d, ebx
        add	r14d, DWORD PTR [rsp+340]
        mov	ebx, r12d
        xor	ecx, edx
        xor	ebx, r13d
        rorx	edx, r11d, 25
        xor	edx, ecx
        and	ebx, r11d
        add	r14d, edx
        rorx	edx, r15d, 2
        rorx	ecx, r15d, 13
        xor	ebx, r13d
        xor	ecx, edx
        rorx	edx, r15d, 22
        add	r14d, ebx
        xor	edx, ecx
        mov	ebx, r8d
        lea	r10d, DWORD PTR [r10+r14]
        xor	ebx, r15d
        and	eax, ebx
        add	r14d, edx
        xor	eax, r8d
        rorx	edx, r10d, 6
        rorx	ecx, r10d, 11
        lea	r14d, DWORD PTR [r14+rax]
        add	r13d, DWORD PTR [rsp+344]
        mov	eax, r11d
        xor	ecx, edx
        xor	eax, r12d
        rorx	edx, r10d, 25
        xor	edx, ecx
        and	eax, r10d
        add	r13d, edx
        rorx	edx, r14d, 2
        rorx	ecx, r14d, 13
        xor	eax, r12d
        xor	ecx, edx
        rorx	edx, r14d, 22
        add	r13d, eax
        xor	edx, ecx
        mov	eax, r15d
        add	r9d, r13d
        xor	eax, r14d
        and	ebx, eax
        add	r13d, edx
        xor	ebx, r15d
        rorx	edx, r9d, 6
        rorx	ecx, r9d, 11
        add	r13d, ebx
        add	r12d, DWORD PTR [rsp+348]
        mov	ebx, r10d
        xor	ecx, edx
        xor	ebx, r11d
        rorx	edx, r9d, 25
        xor	edx, ecx
        and	ebx, r9d
        add	r12d, edx
        rorx	edx, r13d, 2
        rorx	ecx, r13d, 13
        xor	ebx, r11d
        xor	ecx, edx
        rorx	edx, r13d, 22
        add	r12d, ebx
        xor	edx, ecx
        mov	ebx, r14d
        lea	r8d, DWORD PTR [r8+r12]
        xor	ebx, r13d
        and	eax, ebx
        add	r12d, edx
        xor	eax, r14d
        rorx	edx, r8d, 6
        rorx	ecx, r8d, 11
        lea	r12d, DWORD PTR [r12+rax]
        add	r11d, DWORD PTR [rsp+368]
        mov	eax, r9d
        xor	ecx, edx
        xor	eax, r10d
        rorx	edx, r8d, 25
        xor	edx, ecx
        and	eax, r8d
        add	r11d, edx
        rorx	edx, r12d, 2
        rorx	ecx, r12d, 13
        xor	eax, r10d
        xor	ecx, edx
        rorx	edx, r12d, 22
        add	r11d, eax
        xor	edx, ecx
        mov	eax, r13d
        add	r15d, r11d
        xor	eax, r12d
        and	ebx, eax
        add	r11d, edx
        xor	ebx, r13d
        rorx	edx, r15d, 6
        rorx	ecx, r15d, 11
        add	r11d, ebx
        add	r10d, DWORD PTR [rsp+372]
        mov	ebx, r8d
        xor	ecx, edx
        xor	ebx, r9d
        rorx	edx, r15d, 25
        xor	edx, ecx
        and	ebx, r15d
        add	r10d, edx
        rorx	edx, r11d, 2
        rorx	ecx, r11d, 13
        xor	ebx, r9d
        xor	ecx, edx
        rorx	edx, r11d, 22
        add	r10d, ebx
        xor	edx, ecx
        mov	ebx, r12d
        lea	r14d, DWORD PTR [r14+r10]
        xor	ebx, r11d
        and	eax, ebx
        add	r10d, edx
        xor	eax, r12d
        rorx	edx, r14d, 6
        rorx	ecx, r14d, 11
        lea	r10d, DWORD PTR [r10+rax]
        add	r9d, DWORD PTR [rsp+376]
        mov	eax, r15d
        xor	ecx, edx
        xor	eax, r8d
        rorx	edx, r14d, 25
        xor	edx, ecx
        and	eax, r14d
        add	r9d, edx
        rorx	edx, r10d, 2
        rorx	ecx, r10d, 13
        xor	eax, r8d
        xor	ecx, edx
        rorx	edx, r10d, 22
        add	r9d, eax
        xor	edx, ecx
        mov	eax, r11d
        add	r13d, r9d
        xor	eax, r10d
        and	ebx, eax
        add	r9d, edx
        xor	ebx, r11d
        rorx	edx, r13d, 6
        rorx	ecx, r13d, 11
        add	r9d, ebx
        add	r8d, DWORD PTR [rsp+380]
        mov	ebx, r14d
        xor	ecx, edx
        xor	ebx, r15d
        rorx	edx, r13d, 25
        xor	edx, ecx
        and	ebx, r13d
        add	r8d, edx
        rorx	edx, r9d, 2
        rorx	ecx, r9d, 13
        xor	ebx, r15d
        xor	ecx, edx
        rorx	edx, r9d, 22
        add	r8d, ebx
        xor	edx, ecx
        mov	ebx, r10d
        lea	r12d, DWORD PTR [r12+r8]
        xor	ebx, r9d
        and	eax, ebx
        add	r8d, edx
        xor	eax, r10d
        rorx	edx, r12d, 6
        rorx	ecx, r12d, 11
        lea	r8d, DWORD PTR [r8+rax]
        add	r15d, DWORD PTR [rsp+400]
        mov	eax, r13d
        xor	ecx, edx
        xor	eax, r14d
        rorx	edx, r12d, 25
        xor	edx, ecx
        and	eax, r12d
        add	r15d, edx
        rorx	edx, r8d, 2
        rorx	ecx, r8d, 13
        xor	eax, r14d
        xor	ecx, edx
        rorx	edx, r8d, 22
        add	r15d, eax
        xor	edx, ecx
        mov	eax, r9d
        add	r11d, r15d
        xor	eax, r8d
        and	ebx, eax
        add	r15d, edx
        xor	ebx, r9d
        rorx	edx, r11d, 6
        rorx	ecx, r11d, 11
        add	r15d, ebx
        add	r14d, DWORD PTR [rsp+404]
        mov	ebx, r12d
        xor	ecx, edx
        xor	ebx, r13d
        rorx	edx, r11d, 25
        xor	edx, ecx
        and	ebx, r11d
        add	r14d, edx
        rorx	edx, r15d, 2
        rorx	ecx, r15d, 13
        xor	ebx, r13d
        xor	ecx, edx
        rorx	edx, r15d, 22
        add	r14d, ebx
        xor	edx, ecx
        mov	ebx, r8d
        lea	r10d, DWORD PTR [r10+r14]
        xor	ebx, r15d
        and	eax, ebx
        add	r14d, edx
        xor	eax, r8d
        rorx	edx, r10d, 6
        rorx	ecx, r10d, 11
        lea	r14d, DWORD PTR [r14+rax]
        add	r13d, DWORD PTR [rsp+408]
        mov	eax, r11d
        xor	ecx, edx
        xor	eax, r12d
        rorx	edx, r10d, 25
        xor	edx, ecx
        and	eax, r10d
        add	r13d, edx
        rorx	edx, r14d, 2
        rorx	ecx, r14d, 13
        xor	eax, r12d
        xor	ecx, edx
        rorx	edx, r14d, 22
        add	r13d, eax
        xor	edx, ecx
        mov	eax, r15d
        add	r9d, r13d
        xor	eax, r14d
        and	ebx, eax
        add	r13d, edx
        xor	ebx, r15d
        rorx	edx, r9d, 6
        rorx	ecx, r9d, 11
        add	r13d, ebx
        add	r12d, DWORD PTR [rsp+412]
        mov	ebx, r10d
        xor	ecx, edx
        xor	ebx, r11d
        rorx	edx, r9d, 25
        xor	edx, ecx
        and	ebx, r9d
        add	r12d, edx
        rorx	edx, r13d, 2
        rorx	ecx, r13d, 13
        xor	ebx, r11d
        xor	ecx, edx
        rorx	edx, r13d, 22
        add	r12d, ebx
        xor	edx, ecx
        mov	ebx, r14d
        lea	r8d, DWORD PTR [r8+r12]
        xor	ebx, r13d
        and	eax, ebx
        add	r12d, edx
        xor	eax, r14d
        rorx	edx, r8d, 6
        rorx	ecx, r8d, 11
        lea	r12d, DWORD PTR [r12+rax]
        add	r11d, DWORD PTR [rsp+432]
        mov	eax, r9d
        xor	ecx, edx
        xor	eax, r10d
        rorx	edx, r8d, 25
        xor	edx, ecx
        and	eax, r8d
        add	r11d, edx
        rorx	edx, r12d, 2
        rorx	ecx, r12d, 13
        xor	eax, r10d
        xor	ecx, edx
        rorx	edx, r12d, 22
        add	r11d, eax
        xor	edx, ecx
        mov	eax, r13d
        add	r15d, r11d
        xor	eax, r12d
        and	ebx, eax
        add	r11d, edx
        xor	ebx, r13d
        rorx	edx, r15d, 6
        rorx	ecx, r15d, 11
        add	r11d, ebx
        add	r10d, DWORD PTR [rsp+436]
        mov	ebx, r8d
        xor	ecx, edx
        xor	ebx, r9d
        rorx	edx, r15d, 25
        xor	edx, ecx
        and	ebx, r15d
        add	r10d, edx
        rorx	edx, r11d, 2
        rorx	ecx, r11d, 13
        xor	ebx, r9d
        xor	ecx, edx
        rorx	edx, r11d, 22
        add	r10d, ebx
        xor	edx, ecx
        mov	ebx, r12d
        lea	r14d, DWORD PTR [r14+r10]
        xor	ebx, r11d
        and	eax, ebx
        add	r10d, edx
        xor	eax, r12d
        rorx	edx, r14d, 6
        rorx	ecx, r14d, 11
        lea	r10d, DWORD PTR [r10+rax]
        add	r9d, DWORD PTR [rsp+440]
        mov	eax, r15d
        xor	ecx, edx
        xor	eax, r8d
        rorx	edx, r14d, 25
        xor	edx, ecx
        and	eax, r14d
        add	r9d, edx
        rorx	edx, r10d, 2
        rorx	ecx, r10d, 13
        xor	eax, r8d
        xor	ecx, edx
        rorx	edx, r10d, 22
        add	r9d, eax
        xor	edx, ecx
        mov	eax, r11d
        add	r13d, r9d
        xor	eax, r10d
        and	ebx, eax
        add	r9d, edx
        xor	ebx, r11d
        rorx	edx, r13d, 6
        rorx	ecx, r13d, 11
        add	r9d, ebx
        add	r8d, DWORD PTR [rsp+444]
        mov	ebx, r14d
        xor	ecx, edx
        xor	ebx, r15d
        rorx	edx, r13d, 25
        xor	edx, ecx
        and	ebx, r13d
        add	r8d, edx
        rorx	edx, r9d, 2
        rorx	ecx, r9d, 13
        xor	ebx, r15d
        xor	ecx, edx
        rorx	edx, r9d, 22
        add	r8d, ebx
        xor	edx, ecx
        mov	ebx, r10d
        lea	r12d, DWORD PTR [r12+r8]
        xor	ebx, r9d
        and	eax, ebx
        add	r8d, edx
        xor	eax, r10d
        rorx	edx, r12d, 6
        rorx	ecx, r12d, 11
        lea	r8d, DWORD PTR [r8+rax]
        add	r15d, DWORD PTR [rsp+464]
        mov	eax, r13d
        xor	ecx, edx
        xor	eax, r14d
        rorx	edx, r12d, 25
        xor	edx, ecx
        and	eax, r12d
        add	r15d, edx
        rorx	edx, r8d, 2
        rorx	ecx, r8d, 13
        xor	eax, r14d
        xor	ecx, edx
        rorx	edx, r8d, 22
        add	r15d, eax
        xor	edx, ecx
        mov	eax, r9d
        add	r11d, r15d
        xor	eax, r8d
        and	ebx, eax
        add	r15d, edx
        xor	ebx, r9d
        rorx	edx, r11d, 6
        rorx	ecx, r11d, 11
        add	r15d, ebx
        add	r14d, DWORD PTR [rsp+468]
        mov	ebx, r12d
        xor	ecx, edx
        xor	ebx, r13d
        rorx	edx, r11d, 25
        xor	edx, ecx
        and	ebx, r11d
        add	r14d, edx
        rorx	edx, r15d, 2
        rorx	ecx, r15d, 13
        xor	ebx, r13d
        xor	ecx, edx
        rorx	edx, r15d, 22
        add	r14d, ebx
        xor	edx, ecx
        mov	ebx, r8d
        lea	r10d, DWORD PTR [r10+r14]
        xor	ebx, r15d
        and	eax, ebx
        add	r14d, edx
        xor	eax, r8d
        rorx	edx, r10d, 6
        rorx	ecx, r10d, 11
        lea	r14d, DWORD PTR [r14+rax]
        add	r13d, DWORD PTR [rsp+472]
        mov	eax, r11d
        xor	ecx, edx
        xor	eax, r12d
        rorx	edx, r10d, 25
        xor	edx, ecx
        and	eax, r10d
        add	r13d, edx
        rorx	edx, r14d, 2
        rorx	ecx, r14d, 13
        xor	eax, r12d
        xor	ecx, edx
        rorx	edx, r14d, 22
        add	r13d, eax
        xor	edx, ecx
        mov	eax, r15d
        add	r9d, r13d
        xor	eax, r14d
        and	ebx, eax
        add	r13d, edx
        xor	ebx, r15d
        rorx	edx, r9d, 6
        rorx	ecx, r9d, 11
        add	r13d, ebx
        add	r12d, DWORD PTR [rsp+476]
        mov	ebx, r10d
        xor	ecx, edx
        xor	ebx, r11d
        rorx	edx, r9d, 25
        xor	edx, ecx
        and	ebx, r9d
        add	r12d, edx
        rorx	edx, r13d, 2
        rorx	ecx, r13d, 13
        xor	ebx, r11d
        xor	ecx, edx
        rorx	edx, r13d, 22
        add	r12d, ebx
        xor	edx, ecx
        mov	ebx, r14d
        lea	r8d, DWORD PTR [r8+r12]
        xor	ebx, r13d
        and	eax, ebx
        add	r12d, edx
        xor	eax, r14d
        rorx	edx, r8d, 6
        rorx	ecx, r8d, 11
        lea	r12d, DWORD PTR [r12+rax]
        add	r11d, DWORD PTR [rsp+496]
        mov	eax, r9d
        xor	ecx, edx
        xor	eax, r10d
        rorx	edx, r8d, 25
        xor	edx, ecx
        and	eax, r8d
        add	r11d, edx
        rorx	edx, r12d, 2
        rorx	ecx, r12d, 13
        xor	eax, r10d
        xor	ecx, edx
        rorx	edx, r12d, 22
        add	r11d, eax
        xor	edx, ecx
        mov	eax, r13d
        add	r15d, r11d
        xor	eax, r12d
        and	ebx, eax
        add	r11d, edx
        xor	ebx, r13d
        rorx	edx, r15d, 6
        rorx	ecx, r15d, 11
        add	r11d, ebx
        add	r10d, DWORD PTR [rsp+500]
        mov	ebx, r8d
        xor	ecx, edx
        xor	ebx, r9d
        rorx	edx, r15d, 25
        xor	edx, ecx
        and	ebx, r15d
        add	r10d, edx
        rorx	edx, r11d, 2
        rorx	ecx, r11d, 13
        xor	ebx, r9d
        xor	ecx, edx
        rorx	edx, r11d, 22
        add	r10d, ebx
        xor	edx, ecx
        mov	ebx, r12d
        lea	r14d, DWORD PTR [r14+r10]
        xor	ebx, r11d
        and	eax, ebx
        add	r10d, edx
        xor	eax, r12d
        rorx	edx, r14d, 6
        rorx	ecx, r14d, 11
        lea	r10d, DWORD PTR [r10+rax]
        add	r9d, DWORD PTR [rsp+504]
        mov	eax, r15d
        xor	ecx, edx
        xor	eax, r8d
        rorx	edx, r14d, 25
        xor	edx, ecx
        and	eax, r14d
        add	r9d, edx
        rorx	edx, r10d, 2
        rorx	ecx, r10d, 13
        xor	eax, r8d
        xor	ecx, edx
        rorx	edx, r10d, 22
        add	r9d, eax
        xor	edx, ecx
        mov	eax, r11d
        add	r13d, r9d
        xor	eax, r10d
        and	ebx, eax
        add	r9d, edx
        xor	ebx, r11d
        rorx	edx, r13d, 6
        rorx	ecx, r13d, 11
        add	r9d, ebx
        add	r8d, DWORD PTR [rsp+508]
        mov	ebx, r14d
        xor	ecx, edx
        xor	ebx, r15d
        rorx	edx, r13d, 25
        xor	edx, ecx
        and	ebx, r13d
        add	r8d, edx
        rorx	edx, r9d, 2
        rorx	ecx, r9d, 13
        xor	ebx, r15d
        xor	ecx, edx
        rorx	edx, r9d, 22
        add	r8d, ebx
        xor	edx, ecx
        mov	ebx, r10d
        lea	r12d, DWORD PTR [r12+r8]
        xor	ebx, r9d
        and	eax, ebx
        add	r8d, edx
        xor	eax, r10d
        add	r8d, eax
        add	rsi, 128
        add	r8d, DWORD PTR [rdi]
        add	r9d, DWORD PTR [rdi+4]
        add	r10d, DWORD PTR [rdi+8]
        add	r11d, DWORD PTR [rdi+12]
        add	r12d, DWORD PTR [rdi+16]
        add	r13d, DWORD PTR [rdi+20]
        add	r14d, DWORD PTR [rdi+24]
        add	r15d, DWORD PTR [rdi+28]
        sub	DWORD PTR [rsp+512], 128
        mov	DWORD PTR [rdi], r8d
        mov	DWORD PTR [rdi+4], r9d
        mov	DWORD PTR [rdi+8], r10d
        mov	DWORD PTR [rdi+12], r11d
        mov	DWORD PTR [rdi+16], r12d
        mov	DWORD PTR [rdi+20], r13d
        mov	DWORD PTR [rdi+24], r14d
        mov	DWORD PTR [rdi+28], r15d
        jnz	L_sha256_len_avx2_rorx_start
L_sha256_len_avx2_rorx_done:
        xor	rax, rax
        vzeroupper
        vmovdqu	xmm6, OWORD PTR [rsp+512]
        vmovdqu	xmm7, OWORD PTR [rsp+528]
        vmovdqu	xmm8, OWORD PTR [rsp+544]
        vmovdqu	xmm9, OWORD PTR [rsp+560]
        vmovdqu	xmm10, OWORD PTR [rsp+576]
        vmovdqu	xmm11, OWORD PTR [rsp+592]
        vmovdqu	xmm12, OWORD PTR [rsp+608]
        vmovdqu	xmm13, OWORD PTR [rsp+624]
        add	rsp, 644
        pop	rbp
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        pop	rbx
        ret
Transform_Sha256_AVX2_RORX_Len ENDP
_TEXT ENDS
ENDIF
ENDIF
END
