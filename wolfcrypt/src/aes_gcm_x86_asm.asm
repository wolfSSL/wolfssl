; /* aes_gcm_x86_asm
;  *
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

IFNDEF _WIN32
_WIN32 = 1
ENDIF

.686P
.XMM
.MODEL FLAT, C

_DATA SEGMENT
ALIGN 16
L_aes_gcm_one DWORD 00000000h, 00000000h, 00000001h, 00000000h
ptr_L_aes_gcm_one QWORD L_aes_gcm_one
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_aes_gcm_two DWORD 00000000h, 00000000h, 00000002h, 00000000h
ptr_L_aes_gcm_two QWORD L_aes_gcm_two
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_aes_gcm_three DWORD 00000000h, 00000000h, 00000003h, 00000000h
ptr_L_aes_gcm_three QWORD L_aes_gcm_three
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_aes_gcm_four DWORD 00000000h, 00000000h, 00000004h, 00000000h
ptr_L_aes_gcm_four QWORD L_aes_gcm_four
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_aes_gcm_bswap_epi64 DWORD 04050607h, 00010203h, 0c0d0e0fh, 08090a0bh
ptr_L_aes_gcm_bswap_epi64 QWORD L_aes_gcm_bswap_epi64
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_aes_gcm_bswap_mask DWORD 0c0d0e0fh, 08090a0bh, 04050607h, 00010203h
ptr_L_aes_gcm_bswap_mask QWORD L_aes_gcm_bswap_mask
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_aes_gcm_mod2_128 DWORD 00000001h, 00000000h, 00000000h, 0c2000000h
ptr_L_aes_gcm_mod2_128 QWORD L_aes_gcm_mod2_128
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_aes_gcm_avx1_one DWORD 00000000h, 00000000h, 00000001h, 00000000h
ptr_L_aes_gcm_avx1_one QWORD L_aes_gcm_avx1_one
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_aes_gcm_avx1_two DWORD 00000000h, 00000000h, 00000002h, 00000000h
ptr_L_aes_gcm_avx1_two QWORD L_aes_gcm_avx1_two
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_aes_gcm_avx1_three DWORD 00000000h, 00000000h, 00000003h, 00000000h
ptr_L_aes_gcm_avx1_three QWORD L_aes_gcm_avx1_three
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_aes_gcm_avx1_four DWORD 00000000h, 00000000h, 00000004h, 00000000h
ptr_L_aes_gcm_avx1_four QWORD L_aes_gcm_avx1_four
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_aes_gcm_avx1_bswap_epi64 DWORD 04050607h, 00010203h, 0c0d0e0fh, 08090a0bh
ptr_L_aes_gcm_avx1_bswap_epi64 QWORD L_aes_gcm_avx1_bswap_epi64
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_aes_gcm_avx1_bswap_mask DWORD 0c0d0e0fh, 08090a0bh, 04050607h, 00010203h
ptr_L_aes_gcm_avx1_bswap_mask QWORD L_aes_gcm_avx1_bswap_mask
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_aes_gcm_avx1_mod2_128 DWORD 00000001h, 00000000h, 00000000h, 0c2000000h
ptr_L_aes_gcm_avx1_mod2_128 QWORD L_aes_gcm_avx1_mod2_128
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_aes_gcm_avx2_one DWORD 00000000h, 00000000h, 00000001h, 00000000h
ptr_L_aes_gcm_avx2_one QWORD L_aes_gcm_avx2_one
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_aes_gcm_avx2_two DWORD 00000000h, 00000000h, 00000002h, 00000000h
ptr_L_aes_gcm_avx2_two QWORD L_aes_gcm_avx2_two
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_aes_gcm_avx2_three DWORD 00000000h, 00000000h, 00000003h, 00000000h
ptr_L_aes_gcm_avx2_three QWORD L_aes_gcm_avx2_three
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_aes_gcm_avx2_four DWORD 00000000h, 00000000h, 00000004h, 00000000h
ptr_L_aes_gcm_avx2_four QWORD L_aes_gcm_avx2_four
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_avx2_aes_gcm_bswap_one DWORD 00000000h, 00000000h, 00000000h, 01000000h
ptr_L_avx2_aes_gcm_bswap_one QWORD L_avx2_aes_gcm_bswap_one
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_aes_gcm_avx2_bswap_epi64 DWORD 04050607h, 00010203h, 0c0d0e0fh, 08090a0bh
ptr_L_aes_gcm_avx2_bswap_epi64 QWORD L_aes_gcm_avx2_bswap_epi64
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_aes_gcm_avx2_bswap_mask DWORD 0c0d0e0fh, 08090a0bh, 04050607h, 00010203h
ptr_L_aes_gcm_avx2_bswap_mask QWORD L_aes_gcm_avx2_bswap_mask
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_aes_gcm_avx2_mod2_128 DWORD 00000001h, 00000000h, 00000000h, 0c2000000h
ptr_L_aes_gcm_avx2_mod2_128 QWORD L_aes_gcm_avx2_mod2_128
_DATA ENDS
_TEXT SEGMENT READONLY PARA
AES_GCM_encrypt_aesni PROC
        push	ebx
        push	esi
        push	edi
        push	ebp
        sub	esp, 112
        mov	esi, DWORD PTR [esp+144]
        mov	ebp, DWORD PTR [esp+168]
        mov	edx, DWORD PTR [esp+160]
        pxor	xmm0, xmm0
        pxor	xmm2, xmm2
        cmp	edx, 12
        jne	L_AES_GCM_encrypt_aesni_iv_not_12
        ; # Calculate values when IV is 12 bytes
        ; Set counter based on IV
        mov	ecx, 16777216
        pinsrd	xmm0, DWORD PTR [esi], 0
        pinsrd	xmm0, DWORD PTR [esi+4], 1
        pinsrd	xmm0, DWORD PTR [esi+8], 2
        pinsrd	xmm0, ecx, 3
        ; H = Encrypt X(=0) and T = Encrypt counter
        movdqa	xmm5, xmm0
        movdqa	xmm1, OWORD PTR [ebp]
        pxor	xmm5, xmm1
        movdqa	xmm3, OWORD PTR [ebp+16]
        aesenc	xmm1, xmm3
        aesenc	xmm5, xmm3
        movdqa	xmm3, OWORD PTR [ebp+32]
        aesenc	xmm1, xmm3
        aesenc	xmm5, xmm3
        movdqa	xmm3, OWORD PTR [ebp+48]
        aesenc	xmm1, xmm3
        aesenc	xmm5, xmm3
        movdqa	xmm3, OWORD PTR [ebp+64]
        aesenc	xmm1, xmm3
        aesenc	xmm5, xmm3
        movdqa	xmm3, OWORD PTR [ebp+80]
        aesenc	xmm1, xmm3
        aesenc	xmm5, xmm3
        movdqa	xmm3, OWORD PTR [ebp+96]
        aesenc	xmm1, xmm3
        aesenc	xmm5, xmm3
        movdqa	xmm3, OWORD PTR [ebp+112]
        aesenc	xmm1, xmm3
        aesenc	xmm5, xmm3
        movdqa	xmm3, OWORD PTR [ebp+128]
        aesenc	xmm1, xmm3
        aesenc	xmm5, xmm3
        movdqa	xmm3, OWORD PTR [ebp+144]
        aesenc	xmm1, xmm3
        aesenc	xmm5, xmm3
        cmp	DWORD PTR [esp+172], 11
        movdqa	xmm3, OWORD PTR [ebp+160]
        jl	L_AES_GCM_encrypt_aesni_calc_iv_12_last
        aesenc	xmm1, xmm3
        aesenc	xmm5, xmm3
        movdqa	xmm3, OWORD PTR [ebp+176]
        aesenc	xmm1, xmm3
        aesenc	xmm5, xmm3
        cmp	DWORD PTR [esp+172], 13
        movdqa	xmm3, OWORD PTR [ebp+192]
        jl	L_AES_GCM_encrypt_aesni_calc_iv_12_last
        aesenc	xmm1, xmm3
        aesenc	xmm5, xmm3
        movdqa	xmm3, OWORD PTR [ebp+208]
        aesenc	xmm1, xmm3
        aesenc	xmm5, xmm3
        movdqa	xmm3, OWORD PTR [ebp+224]
L_AES_GCM_encrypt_aesni_calc_iv_12_last:
        aesenclast	xmm1, xmm3
        aesenclast	xmm5, xmm3
        pshufb	xmm1, OWORD PTR L_aes_gcm_bswap_mask
        movdqu	OWORD PTR [esp+80], xmm5
        jmp	L_AES_GCM_encrypt_aesni_iv_done
L_AES_GCM_encrypt_aesni_iv_not_12:
        ; Calculate values when IV is not 12 bytes
        ; H = Encrypt X(=0)
        movdqa	xmm1, OWORD PTR [ebp]
        aesenc	xmm1, [ebp+16]
        aesenc	xmm1, [ebp+32]
        aesenc	xmm1, [ebp+48]
        aesenc	xmm1, [ebp+64]
        aesenc	xmm1, [ebp+80]
        aesenc	xmm1, [ebp+96]
        aesenc	xmm1, [ebp+112]
        aesenc	xmm1, [ebp+128]
        aesenc	xmm1, [ebp+144]
        cmp	DWORD PTR [esp+172], 11
        movdqa	xmm5, OWORD PTR [ebp+160]
        jl	L_AES_GCM_encrypt_aesni_calc_iv_1_aesenc_avx_last
        aesenc	xmm1, xmm5
        aesenc	xmm1, [ebp+176]
        cmp	DWORD PTR [esp+172], 13
        movdqa	xmm5, OWORD PTR [ebp+192]
        jl	L_AES_GCM_encrypt_aesni_calc_iv_1_aesenc_avx_last
        aesenc	xmm1, xmm5
        aesenc	xmm1, [ebp+208]
        movdqa	xmm5, OWORD PTR [ebp+224]
L_AES_GCM_encrypt_aesni_calc_iv_1_aesenc_avx_last:
        aesenclast	xmm1, xmm5
        pshufb	xmm1, OWORD PTR L_aes_gcm_bswap_mask
        ; Calc counter
        ; Initialization vector
        cmp	edx, 0
        mov	ecx, 0
        je	L_AES_GCM_encrypt_aesni_calc_iv_done
        cmp	edx, 16
        jl	L_AES_GCM_encrypt_aesni_calc_iv_lt16
        and	edx, 4294967280
L_AES_GCM_encrypt_aesni_calc_iv_16_loop:
        movdqu	xmm4, OWORD PTR [esi+ecx]
        pshufb	xmm4, OWORD PTR L_aes_gcm_bswap_mask
        pxor	xmm0, xmm4
        pshufd	xmm5, xmm0, 78
        pshufd	xmm6, xmm1, 78
        movdqa	xmm7, xmm1
        movdqa	xmm4, xmm1
        pclmulqdq	xmm7, xmm0, 17
        pclmulqdq	xmm4, xmm0, 0
        pxor	xmm5, xmm0
        pxor	xmm6, xmm1
        pclmulqdq	xmm5, xmm6, 0
        pxor	xmm5, xmm4
        pxor	xmm5, xmm7
        movdqa	xmm6, xmm5
        movdqa	xmm3, xmm4
        movdqa	xmm0, xmm7
        pslldq	xmm6, 8
        psrldq	xmm5, 8
        pxor	xmm3, xmm6
        pxor	xmm0, xmm5
        movdqa	xmm4, xmm3
        movdqa	xmm5, xmm0
        psrld	xmm4, 31
        psrld	xmm5, 31
        pslld	xmm3, 1
        pslld	xmm0, 1
        movdqa	xmm6, xmm4
        pslldq	xmm4, 4
        psrldq	xmm6, 12
        pslldq	xmm5, 4
        por	xmm0, xmm6
        por	xmm3, xmm4
        por	xmm0, xmm5
        movdqa	xmm4, xmm3
        movdqa	xmm5, xmm3
        movdqa	xmm6, xmm3
        pslld	xmm4, 31
        pslld	xmm5, 30
        pslld	xmm6, 25
        pxor	xmm4, xmm5
        pxor	xmm4, xmm6
        movdqa	xmm5, xmm4
        psrldq	xmm5, 4
        pslldq	xmm4, 12
        pxor	xmm3, xmm4
        movdqa	xmm6, xmm3
        movdqa	xmm7, xmm3
        movdqa	xmm4, xmm3
        psrld	xmm6, 1
        psrld	xmm7, 2
        psrld	xmm4, 7
        pxor	xmm6, xmm7
        pxor	xmm6, xmm4
        pxor	xmm6, xmm5
        pxor	xmm6, xmm3
        pxor	xmm0, xmm6
        add	ecx, 16
        cmp	ecx, edx
        jl	L_AES_GCM_encrypt_aesni_calc_iv_16_loop
        mov	edx, DWORD PTR [esp+160]
        cmp	ecx, edx
        je	L_AES_GCM_encrypt_aesni_calc_iv_done
L_AES_GCM_encrypt_aesni_calc_iv_lt16:
        sub	esp, 16
        pxor	xmm4, xmm4
        xor	ebx, ebx
        movdqu	OWORD PTR [esp], xmm4
L_AES_GCM_encrypt_aesni_calc_iv_loop:
        movzx	eax, BYTE PTR [esi+ecx]
        mov	BYTE PTR [esp+ebx], al
        inc	ecx
        inc	ebx
        cmp	ecx, edx
        jl	L_AES_GCM_encrypt_aesni_calc_iv_loop
        movdqu	xmm4, OWORD PTR [esp]
        add	esp, 16
        pshufb	xmm4, OWORD PTR L_aes_gcm_bswap_mask
        pxor	xmm0, xmm4
        pshufd	xmm5, xmm0, 78
        pshufd	xmm6, xmm1, 78
        movdqa	xmm7, xmm1
        movdqa	xmm4, xmm1
        pclmulqdq	xmm7, xmm0, 17
        pclmulqdq	xmm4, xmm0, 0
        pxor	xmm5, xmm0
        pxor	xmm6, xmm1
        pclmulqdq	xmm5, xmm6, 0
        pxor	xmm5, xmm4
        pxor	xmm5, xmm7
        movdqa	xmm6, xmm5
        movdqa	xmm3, xmm4
        movdqa	xmm0, xmm7
        pslldq	xmm6, 8
        psrldq	xmm5, 8
        pxor	xmm3, xmm6
        pxor	xmm0, xmm5
        movdqa	xmm4, xmm3
        movdqa	xmm5, xmm0
        psrld	xmm4, 31
        psrld	xmm5, 31
        pslld	xmm3, 1
        pslld	xmm0, 1
        movdqa	xmm6, xmm4
        pslldq	xmm4, 4
        psrldq	xmm6, 12
        pslldq	xmm5, 4
        por	xmm0, xmm6
        por	xmm3, xmm4
        por	xmm0, xmm5
        movdqa	xmm4, xmm3
        movdqa	xmm5, xmm3
        movdqa	xmm6, xmm3
        pslld	xmm4, 31
        pslld	xmm5, 30
        pslld	xmm6, 25
        pxor	xmm4, xmm5
        pxor	xmm4, xmm6
        movdqa	xmm5, xmm4
        psrldq	xmm5, 4
        pslldq	xmm4, 12
        pxor	xmm3, xmm4
        movdqa	xmm6, xmm3
        movdqa	xmm7, xmm3
        movdqa	xmm4, xmm3
        psrld	xmm6, 1
        psrld	xmm7, 2
        psrld	xmm4, 7
        pxor	xmm6, xmm7
        pxor	xmm6, xmm4
        pxor	xmm6, xmm5
        pxor	xmm6, xmm3
        pxor	xmm0, xmm6
L_AES_GCM_encrypt_aesni_calc_iv_done:
        ; T = Encrypt counter
        pxor	xmm4, xmm4
        shl	edx, 3
        pinsrd	xmm4, edx, 0
        pxor	xmm0, xmm4
        pshufd	xmm5, xmm0, 78
        pshufd	xmm6, xmm1, 78
        movdqa	xmm7, xmm1
        movdqa	xmm4, xmm1
        pclmulqdq	xmm7, xmm0, 17
        pclmulqdq	xmm4, xmm0, 0
        pxor	xmm5, xmm0
        pxor	xmm6, xmm1
        pclmulqdq	xmm5, xmm6, 0
        pxor	xmm5, xmm4
        pxor	xmm5, xmm7
        movdqa	xmm6, xmm5
        movdqa	xmm3, xmm4
        movdqa	xmm0, xmm7
        pslldq	xmm6, 8
        psrldq	xmm5, 8
        pxor	xmm3, xmm6
        pxor	xmm0, xmm5
        movdqa	xmm4, xmm3
        movdqa	xmm5, xmm0
        psrld	xmm4, 31
        psrld	xmm5, 31
        pslld	xmm3, 1
        pslld	xmm0, 1
        movdqa	xmm6, xmm4
        pslldq	xmm4, 4
        psrldq	xmm6, 12
        pslldq	xmm5, 4
        por	xmm0, xmm6
        por	xmm3, xmm4
        por	xmm0, xmm5
        movdqa	xmm4, xmm3
        movdqa	xmm5, xmm3
        movdqa	xmm6, xmm3
        pslld	xmm4, 31
        pslld	xmm5, 30
        pslld	xmm6, 25
        pxor	xmm4, xmm5
        pxor	xmm4, xmm6
        movdqa	xmm5, xmm4
        psrldq	xmm5, 4
        pslldq	xmm4, 12
        pxor	xmm3, xmm4
        movdqa	xmm6, xmm3
        movdqa	xmm7, xmm3
        movdqa	xmm4, xmm3
        psrld	xmm6, 1
        psrld	xmm7, 2
        psrld	xmm4, 7
        pxor	xmm6, xmm7
        pxor	xmm6, xmm4
        pxor	xmm6, xmm5
        pxor	xmm6, xmm3
        pxor	xmm0, xmm6
        pshufb	xmm0, OWORD PTR L_aes_gcm_bswap_mask
        ;   Encrypt counter
        movdqa	xmm4, OWORD PTR [ebp]
        pxor	xmm4, xmm0
        aesenc	xmm4, [ebp+16]
        aesenc	xmm4, [ebp+32]
        aesenc	xmm4, [ebp+48]
        aesenc	xmm4, [ebp+64]
        aesenc	xmm4, [ebp+80]
        aesenc	xmm4, [ebp+96]
        aesenc	xmm4, [ebp+112]
        aesenc	xmm4, [ebp+128]
        aesenc	xmm4, [ebp+144]
        cmp	DWORD PTR [esp+172], 11
        movdqa	xmm5, OWORD PTR [ebp+160]
        jl	L_AES_GCM_encrypt_aesni_calc_iv_2_aesenc_avx_last
        aesenc	xmm4, xmm5
        aesenc	xmm4, [ebp+176]
        cmp	DWORD PTR [esp+172], 13
        movdqa	xmm5, OWORD PTR [ebp+192]
        jl	L_AES_GCM_encrypt_aesni_calc_iv_2_aesenc_avx_last
        aesenc	xmm4, xmm5
        aesenc	xmm4, [ebp+208]
        movdqa	xmm5, OWORD PTR [ebp+224]
L_AES_GCM_encrypt_aesni_calc_iv_2_aesenc_avx_last:
        aesenclast	xmm4, xmm5
        movdqu	OWORD PTR [esp+80], xmm4
L_AES_GCM_encrypt_aesni_iv_done:
        mov	esi, DWORD PTR [esp+140]
        ; Additional authentication data
        mov	edx, DWORD PTR [esp+156]
        cmp	edx, 0
        je	L_AES_GCM_encrypt_aesni_calc_aad_done
        xor	ecx, ecx
        cmp	edx, 16
        jl	L_AES_GCM_encrypt_aesni_calc_aad_lt16
        and	edx, 4294967280
L_AES_GCM_encrypt_aesni_calc_aad_16_loop:
        movdqu	xmm4, OWORD PTR [esi+ecx]
        pshufb	xmm4, OWORD PTR L_aes_gcm_bswap_mask
        pxor	xmm2, xmm4
        pshufd	xmm5, xmm2, 78
        pshufd	xmm6, xmm1, 78
        movdqa	xmm7, xmm1
        movdqa	xmm4, xmm1
        pclmulqdq	xmm7, xmm2, 17
        pclmulqdq	xmm4, xmm2, 0
        pxor	xmm5, xmm2
        pxor	xmm6, xmm1
        pclmulqdq	xmm5, xmm6, 0
        pxor	xmm5, xmm4
        pxor	xmm5, xmm7
        movdqa	xmm6, xmm5
        movdqa	xmm3, xmm4
        movdqa	xmm2, xmm7
        pslldq	xmm6, 8
        psrldq	xmm5, 8
        pxor	xmm3, xmm6
        pxor	xmm2, xmm5
        movdqa	xmm4, xmm3
        movdqa	xmm5, xmm2
        psrld	xmm4, 31
        psrld	xmm5, 31
        pslld	xmm3, 1
        pslld	xmm2, 1
        movdqa	xmm6, xmm4
        pslldq	xmm4, 4
        psrldq	xmm6, 12
        pslldq	xmm5, 4
        por	xmm2, xmm6
        por	xmm3, xmm4
        por	xmm2, xmm5
        movdqa	xmm4, xmm3
        movdqa	xmm5, xmm3
        movdqa	xmm6, xmm3
        pslld	xmm4, 31
        pslld	xmm5, 30
        pslld	xmm6, 25
        pxor	xmm4, xmm5
        pxor	xmm4, xmm6
        movdqa	xmm5, xmm4
        psrldq	xmm5, 4
        pslldq	xmm4, 12
        pxor	xmm3, xmm4
        movdqa	xmm6, xmm3
        movdqa	xmm7, xmm3
        movdqa	xmm4, xmm3
        psrld	xmm6, 1
        psrld	xmm7, 2
        psrld	xmm4, 7
        pxor	xmm6, xmm7
        pxor	xmm6, xmm4
        pxor	xmm6, xmm5
        pxor	xmm6, xmm3
        pxor	xmm2, xmm6
        add	ecx, 16
        cmp	ecx, edx
        jl	L_AES_GCM_encrypt_aesni_calc_aad_16_loop
        mov	edx, DWORD PTR [esp+156]
        cmp	ecx, edx
        je	L_AES_GCM_encrypt_aesni_calc_aad_done
L_AES_GCM_encrypt_aesni_calc_aad_lt16:
        sub	esp, 16
        pxor	xmm4, xmm4
        xor	ebx, ebx
        movdqu	OWORD PTR [esp], xmm4
L_AES_GCM_encrypt_aesni_calc_aad_loop:
        movzx	eax, BYTE PTR [esi+ecx]
        mov	BYTE PTR [esp+ebx], al
        inc	ecx
        inc	ebx
        cmp	ecx, edx
        jl	L_AES_GCM_encrypt_aesni_calc_aad_loop
        movdqu	xmm4, OWORD PTR [esp]
        add	esp, 16
        pshufb	xmm4, OWORD PTR L_aes_gcm_bswap_mask
        pxor	xmm2, xmm4
        pshufd	xmm5, xmm2, 78
        pshufd	xmm6, xmm1, 78
        movdqa	xmm7, xmm1
        movdqa	xmm4, xmm1
        pclmulqdq	xmm7, xmm2, 17
        pclmulqdq	xmm4, xmm2, 0
        pxor	xmm5, xmm2
        pxor	xmm6, xmm1
        pclmulqdq	xmm5, xmm6, 0
        pxor	xmm5, xmm4
        pxor	xmm5, xmm7
        movdqa	xmm6, xmm5
        movdqa	xmm3, xmm4
        movdqa	xmm2, xmm7
        pslldq	xmm6, 8
        psrldq	xmm5, 8
        pxor	xmm3, xmm6
        pxor	xmm2, xmm5
        movdqa	xmm4, xmm3
        movdqa	xmm5, xmm2
        psrld	xmm4, 31
        psrld	xmm5, 31
        pslld	xmm3, 1
        pslld	xmm2, 1
        movdqa	xmm6, xmm4
        pslldq	xmm4, 4
        psrldq	xmm6, 12
        pslldq	xmm5, 4
        por	xmm2, xmm6
        por	xmm3, xmm4
        por	xmm2, xmm5
        movdqa	xmm4, xmm3
        movdqa	xmm5, xmm3
        movdqa	xmm6, xmm3
        pslld	xmm4, 31
        pslld	xmm5, 30
        pslld	xmm6, 25
        pxor	xmm4, xmm5
        pxor	xmm4, xmm6
        movdqa	xmm5, xmm4
        psrldq	xmm5, 4
        pslldq	xmm4, 12
        pxor	xmm3, xmm4
        movdqa	xmm6, xmm3
        movdqa	xmm7, xmm3
        movdqa	xmm4, xmm3
        psrld	xmm6, 1
        psrld	xmm7, 2
        psrld	xmm4, 7
        pxor	xmm6, xmm7
        pxor	xmm6, xmm4
        pxor	xmm6, xmm5
        pxor	xmm6, xmm3
        pxor	xmm2, xmm6
L_AES_GCM_encrypt_aesni_calc_aad_done:
        movdqu	OWORD PTR [esp+96], xmm2
        mov	esi, DWORD PTR [esp+132]
        mov	edi, DWORD PTR [esp+136]
        ; Calculate counter and H
        pshufb	xmm0, OWORD PTR L_aes_gcm_bswap_epi64
        movdqa	xmm5, xmm1
        paddd	xmm0, OWORD PTR L_aes_gcm_one
        movdqa	xmm4, xmm1
        movdqu	OWORD PTR [esp+64], xmm0
        psrlq	xmm5, 63
        psllq	xmm4, 1
        pslldq	xmm5, 8
        por	xmm4, xmm5
        pshufd	xmm1, xmm1, 255
        psrad	xmm1, 31
        pand	xmm1, OWORD PTR L_aes_gcm_mod2_128
        pxor	xmm1, xmm4
        xor	ebx, ebx
        mov	eax, DWORD PTR [esp+152]
        cmp	eax, 64
        jl	L_AES_GCM_encrypt_aesni_done_64
        and	eax, 4294967232
        movdqa	xmm6, xmm2
        ; H ^ 1
        movdqu	OWORD PTR [esp], xmm1
        ; H ^ 2
        pshufd	xmm5, xmm1, 78
        pshufd	xmm6, xmm1, 78
        movdqa	xmm7, xmm1
        movdqa	xmm4, xmm1
        pclmulqdq	xmm7, xmm1, 17
        pclmulqdq	xmm4, xmm1, 0
        pxor	xmm5, xmm1
        pxor	xmm6, xmm1
        pclmulqdq	xmm5, xmm6, 0
        pxor	xmm5, xmm4
        pxor	xmm5, xmm7
        movdqa	xmm6, xmm5
        movdqa	xmm0, xmm7
        pslldq	xmm6, 8
        psrldq	xmm5, 8
        pxor	xmm4, xmm6
        pxor	xmm0, xmm5
        movdqa	xmm5, xmm4
        movdqa	xmm6, xmm4
        movdqa	xmm7, xmm4
        pslld	xmm5, 31
        pslld	xmm6, 30
        pslld	xmm7, 25
        pxor	xmm5, xmm6
        pxor	xmm5, xmm7
        movdqa	xmm7, xmm5
        psrldq	xmm7, 4
        pslldq	xmm5, 12
        pxor	xmm4, xmm5
        movdqa	xmm5, xmm4
        movdqa	xmm6, xmm4
        psrld	xmm5, 1
        psrld	xmm6, 2
        pxor	xmm5, xmm6
        pxor	xmm5, xmm4
        psrld	xmm4, 7
        pxor	xmm5, xmm7
        pxor	xmm5, xmm4
        pxor	xmm0, xmm5
        movdqu	OWORD PTR [esp+16], xmm0
        ; H ^ 3
        pshufd	xmm5, xmm1, 78
        pshufd	xmm6, xmm0, 78
        movdqa	xmm7, xmm0
        movdqa	xmm4, xmm0
        pclmulqdq	xmm7, xmm1, 17
        pclmulqdq	xmm4, xmm1, 0
        pxor	xmm5, xmm1
        pxor	xmm6, xmm0
        pclmulqdq	xmm5, xmm6, 0
        pxor	xmm5, xmm4
        pxor	xmm5, xmm7
        movdqa	xmm6, xmm5
        movdqa	xmm3, xmm7
        pslldq	xmm6, 8
        psrldq	xmm5, 8
        pxor	xmm4, xmm6
        pxor	xmm3, xmm5
        movdqa	xmm5, xmm4
        movdqa	xmm6, xmm4
        movdqa	xmm7, xmm4
        pslld	xmm5, 31
        pslld	xmm6, 30
        pslld	xmm7, 25
        pxor	xmm5, xmm6
        pxor	xmm5, xmm7
        movdqa	xmm7, xmm5
        psrldq	xmm7, 4
        pslldq	xmm5, 12
        pxor	xmm4, xmm5
        movdqa	xmm5, xmm4
        movdqa	xmm6, xmm4
        psrld	xmm5, 1
        psrld	xmm6, 2
        pxor	xmm5, xmm6
        pxor	xmm5, xmm4
        psrld	xmm4, 7
        pxor	xmm5, xmm7
        pxor	xmm5, xmm4
        pxor	xmm3, xmm5
        movdqu	OWORD PTR [esp+32], xmm3
        ; H ^ 4
        pshufd	xmm5, xmm0, 78
        pshufd	xmm6, xmm0, 78
        movdqa	xmm7, xmm0
        movdqa	xmm4, xmm0
        pclmulqdq	xmm7, xmm0, 17
        pclmulqdq	xmm4, xmm0, 0
        pxor	xmm5, xmm0
        pxor	xmm6, xmm0
        pclmulqdq	xmm5, xmm6, 0
        pxor	xmm5, xmm4
        pxor	xmm5, xmm7
        movdqa	xmm6, xmm5
        movdqa	xmm3, xmm7
        pslldq	xmm6, 8
        psrldq	xmm5, 8
        pxor	xmm4, xmm6
        pxor	xmm3, xmm5
        movdqa	xmm5, xmm4
        movdqa	xmm6, xmm4
        movdqa	xmm7, xmm4
        pslld	xmm5, 31
        pslld	xmm6, 30
        pslld	xmm7, 25
        pxor	xmm5, xmm6
        pxor	xmm5, xmm7
        movdqa	xmm7, xmm5
        psrldq	xmm7, 4
        pslldq	xmm5, 12
        pxor	xmm4, xmm5
        movdqa	xmm5, xmm4
        movdqa	xmm6, xmm4
        psrld	xmm5, 1
        psrld	xmm6, 2
        pxor	xmm5, xmm6
        pxor	xmm5, xmm4
        psrld	xmm4, 7
        pxor	xmm5, xmm7
        pxor	xmm5, xmm4
        pxor	xmm3, xmm5
        movdqu	OWORD PTR [esp+48], xmm3
        ; First 64 bytes of input
        ; Encrypt 64 bytes of counter
        movdqu	xmm4, OWORD PTR [esp+64]
        movdqu	xmm3, xmm4
        paddd	xmm3, OWORD PTR L_aes_gcm_four
        movdqu	OWORD PTR [esp+64], xmm3
        movdqa	xmm3, OWORD PTR L_aes_gcm_bswap_epi64
        movdqa	xmm5, xmm4
        movdqa	xmm6, xmm4
        movdqa	xmm7, xmm4
        pshufb	xmm4, xmm3
        paddd	xmm5, OWORD PTR L_aes_gcm_one
        pshufb	xmm5, xmm3
        paddd	xmm6, OWORD PTR L_aes_gcm_two
        pshufb	xmm6, xmm3
        paddd	xmm7, OWORD PTR L_aes_gcm_three
        pshufb	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp]
        pxor	xmm4, xmm3
        pxor	xmm5, xmm3
        pxor	xmm6, xmm3
        pxor	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+16]
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+32]
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+48]
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+64]
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+80]
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+96]
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+112]
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+128]
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+144]
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        cmp	DWORD PTR [esp+172], 11
        movdqa	xmm3, OWORD PTR [ebp+160]
        jl	L_AES_GCM_encrypt_aesni_enc_done
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+176]
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        cmp	DWORD PTR [esp+172], 13
        movdqa	xmm3, OWORD PTR [ebp+192]
        jl	L_AES_GCM_encrypt_aesni_enc_done
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+208]
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+224]
L_AES_GCM_encrypt_aesni_enc_done:
        aesenclast	xmm4, xmm3
        aesenclast	xmm5, xmm3
        movdqu	xmm0, OWORD PTR [esi]
        movdqu	xmm1, OWORD PTR [esi+16]
        pxor	xmm4, xmm0
        pxor	xmm5, xmm1
        movdqu	OWORD PTR [edi], xmm4
        movdqu	OWORD PTR [edi+16], xmm5
        aesenclast	xmm6, xmm3
        aesenclast	xmm7, xmm3
        movdqu	xmm0, OWORD PTR [esi+32]
        movdqu	xmm1, OWORD PTR [esi+48]
        pxor	xmm6, xmm0
        pxor	xmm7, xmm1
        movdqu	OWORD PTR [edi+32], xmm6
        movdqu	OWORD PTR [edi+48], xmm7
        cmp	eax, 64
        mov	ebx, 64
        mov	ecx, esi
        mov	edx, edi
        jle	L_AES_GCM_encrypt_aesni_end_64
        ; More 64 bytes of input
L_AES_GCM_encrypt_aesni_ghash_64:
        lea	ecx, DWORD PTR [esi+ebx]
        lea	edx, DWORD PTR [edi+ebx]
        ; Encrypt 64 bytes of counter
        movdqu	xmm4, OWORD PTR [esp+64]
        movdqu	xmm3, xmm4
        paddd	xmm3, OWORD PTR L_aes_gcm_four
        movdqu	OWORD PTR [esp+64], xmm3
        movdqa	xmm3, OWORD PTR L_aes_gcm_bswap_epi64
        movdqa	xmm5, xmm4
        movdqa	xmm6, xmm4
        movdqa	xmm7, xmm4
        pshufb	xmm4, xmm3
        paddd	xmm5, OWORD PTR L_aes_gcm_one
        pshufb	xmm5, xmm3
        paddd	xmm6, OWORD PTR L_aes_gcm_two
        pshufb	xmm6, xmm3
        paddd	xmm7, OWORD PTR L_aes_gcm_three
        pshufb	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp]
        pxor	xmm4, xmm3
        pxor	xmm5, xmm3
        pxor	xmm6, xmm3
        pxor	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+16]
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+32]
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+48]
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+64]
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+80]
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+96]
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+112]
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+128]
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+144]
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        cmp	DWORD PTR [esp+172], 11
        movdqa	xmm3, OWORD PTR [ebp+160]
        jl	L_AES_GCM_encrypt_aesni_aesenc_64_ghash_avx_done
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+176]
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        cmp	DWORD PTR [esp+172], 13
        movdqa	xmm3, OWORD PTR [ebp+192]
        jl	L_AES_GCM_encrypt_aesni_aesenc_64_ghash_avx_done
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+208]
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+224]
L_AES_GCM_encrypt_aesni_aesenc_64_ghash_avx_done:
        aesenclast	xmm4, xmm3
        aesenclast	xmm5, xmm3
        movdqu	xmm0, OWORD PTR [ecx]
        movdqu	xmm1, OWORD PTR [ecx+16]
        pxor	xmm4, xmm0
        pxor	xmm5, xmm1
        movdqu	OWORD PTR [edx], xmm4
        movdqu	OWORD PTR [edx+16], xmm5
        aesenclast	xmm6, xmm3
        aesenclast	xmm7, xmm3
        movdqu	xmm0, OWORD PTR [ecx+32]
        movdqu	xmm1, OWORD PTR [ecx+48]
        pxor	xmm6, xmm0
        pxor	xmm7, xmm1
        movdqu	OWORD PTR [edx+32], xmm6
        movdqu	OWORD PTR [edx+48], xmm7
        ; ghash encrypted counter
        movdqu	xmm6, OWORD PTR [esp+96]
        movdqu	xmm3, OWORD PTR [esp+48]
        movdqu	xmm4, OWORD PTR [edx+-64]
        pshufb	xmm4, OWORD PTR L_aes_gcm_bswap_mask
        pxor	xmm4, xmm6
        pshufd	xmm5, xmm3, 78
        pshufd	xmm1, xmm4, 78
        pxor	xmm5, xmm3
        pxor	xmm1, xmm4
        movdqa	xmm7, xmm4
        pclmulqdq	xmm7, xmm3, 17
        movdqa	xmm6, xmm4
        pclmulqdq	xmm6, xmm3, 0
        pclmulqdq	xmm5, xmm1, 0
        pxor	xmm5, xmm6
        pxor	xmm5, xmm7
        movdqu	xmm3, OWORD PTR [esp+32]
        movdqu	xmm4, OWORD PTR [edx+-48]
        pshufd	xmm0, xmm3, 78
        pshufb	xmm4, OWORD PTR L_aes_gcm_bswap_mask
        pxor	xmm0, xmm3
        pshufd	xmm1, xmm4, 78
        pxor	xmm1, xmm4
        movdqa	xmm2, xmm4
        pclmulqdq	xmm2, xmm3, 17
        pclmulqdq	xmm3, xmm4, 0
        pclmulqdq	xmm0, xmm1, 0
        pxor	xmm5, xmm3
        pxor	xmm6, xmm3
        pxor	xmm5, xmm2
        pxor	xmm7, xmm2
        pxor	xmm5, xmm0
        movdqu	xmm3, OWORD PTR [esp+16]
        movdqu	xmm4, OWORD PTR [edx+-32]
        pshufd	xmm0, xmm3, 78
        pshufb	xmm4, OWORD PTR L_aes_gcm_bswap_mask
        pxor	xmm0, xmm3
        pshufd	xmm1, xmm4, 78
        pxor	xmm1, xmm4
        movdqa	xmm2, xmm4
        pclmulqdq	xmm2, xmm3, 17
        pclmulqdq	xmm3, xmm4, 0
        pclmulqdq	xmm0, xmm1, 0
        pxor	xmm5, xmm3
        pxor	xmm6, xmm3
        pxor	xmm5, xmm2
        pxor	xmm7, xmm2
        pxor	xmm5, xmm0
        movdqu	xmm3, OWORD PTR [esp]
        movdqu	xmm4, OWORD PTR [edx+-16]
        pshufd	xmm0, xmm3, 78
        pshufb	xmm4, OWORD PTR L_aes_gcm_bswap_mask
        pxor	xmm0, xmm3
        pshufd	xmm1, xmm4, 78
        pxor	xmm1, xmm4
        movdqa	xmm2, xmm4
        pclmulqdq	xmm2, xmm3, 17
        pclmulqdq	xmm3, xmm4, 0
        pclmulqdq	xmm0, xmm1, 0
        pxor	xmm5, xmm3
        pxor	xmm6, xmm3
        pxor	xmm5, xmm2
        pxor	xmm7, xmm2
        pxor	xmm5, xmm0
        movdqa	xmm1, xmm5
        psrldq	xmm5, 8
        pslldq	xmm1, 8
        pxor	xmm6, xmm1
        pxor	xmm7, xmm5
        movdqa	xmm3, xmm6
        movdqa	xmm0, xmm6
        movdqa	xmm1, xmm6
        pslld	xmm3, 31
        pslld	xmm0, 30
        pslld	xmm1, 25
        pxor	xmm3, xmm0
        pxor	xmm3, xmm1
        movdqa	xmm0, xmm3
        pslldq	xmm3, 12
        psrldq	xmm0, 4
        pxor	xmm6, xmm3
        movdqa	xmm1, xmm6
        movdqa	xmm5, xmm6
        movdqa	xmm4, xmm6
        psrld	xmm1, 1
        psrld	xmm5, 2
        psrld	xmm4, 7
        pxor	xmm1, xmm5
        pxor	xmm1, xmm4
        pxor	xmm1, xmm0
        pxor	xmm6, xmm1
        pxor	xmm6, xmm7
        movdqu	OWORD PTR [esp+96], xmm6
        add	ebx, 64
        cmp	ebx, eax
        jl	L_AES_GCM_encrypt_aesni_ghash_64
L_AES_GCM_encrypt_aesni_end_64:
        movdqu	xmm2, OWORD PTR [esp+96]
        ; Block 1
        movdqa	xmm4, OWORD PTR L_aes_gcm_bswap_mask
        movdqu	xmm1, OWORD PTR [edx]
        pshufb	xmm1, xmm4
        movdqu	xmm3, OWORD PTR [esp+48]
        pxor	xmm1, xmm2
        pshufd	xmm5, xmm1, 78
        pshufd	xmm6, xmm3, 78
        movdqa	xmm7, xmm3
        movdqa	xmm4, xmm3
        pclmulqdq	xmm7, xmm1, 17
        pclmulqdq	xmm4, xmm1, 0
        pxor	xmm5, xmm1
        pxor	xmm6, xmm3
        pclmulqdq	xmm5, xmm6, 0
        pxor	xmm5, xmm4
        pxor	xmm5, xmm7
        movdqa	xmm6, xmm5
        movdqa	xmm0, xmm4
        movdqa	xmm2, xmm7
        pslldq	xmm6, 8
        psrldq	xmm5, 8
        pxor	xmm0, xmm6
        pxor	xmm2, xmm5
        ; Block 2
        movdqa	xmm4, OWORD PTR L_aes_gcm_bswap_mask
        movdqu	xmm1, OWORD PTR [edx+16]
        pshufb	xmm1, xmm4
        movdqu	xmm3, OWORD PTR [esp+32]
        pshufd	xmm5, xmm1, 78
        pshufd	xmm6, xmm3, 78
        movdqa	xmm7, xmm3
        movdqa	xmm4, xmm3
        pclmulqdq	xmm7, xmm1, 17
        pclmulqdq	xmm4, xmm1, 0
        pxor	xmm5, xmm1
        pxor	xmm6, xmm3
        pclmulqdq	xmm5, xmm6, 0
        pxor	xmm5, xmm4
        pxor	xmm5, xmm7
        movdqa	xmm6, xmm5
        pxor	xmm0, xmm4
        pxor	xmm2, xmm7
        pslldq	xmm6, 8
        psrldq	xmm5, 8
        pxor	xmm0, xmm6
        pxor	xmm2, xmm5
        ; Block 3
        movdqa	xmm4, OWORD PTR L_aes_gcm_bswap_mask
        movdqu	xmm1, OWORD PTR [edx+32]
        pshufb	xmm1, xmm4
        movdqu	xmm3, OWORD PTR [esp+16]
        pshufd	xmm5, xmm1, 78
        pshufd	xmm6, xmm3, 78
        movdqa	xmm7, xmm3
        movdqa	xmm4, xmm3
        pclmulqdq	xmm7, xmm1, 17
        pclmulqdq	xmm4, xmm1, 0
        pxor	xmm5, xmm1
        pxor	xmm6, xmm3
        pclmulqdq	xmm5, xmm6, 0
        pxor	xmm5, xmm4
        pxor	xmm5, xmm7
        movdqa	xmm6, xmm5
        pxor	xmm0, xmm4
        pxor	xmm2, xmm7
        pslldq	xmm6, 8
        psrldq	xmm5, 8
        pxor	xmm0, xmm6
        pxor	xmm2, xmm5
        ; Block 4
        movdqa	xmm4, OWORD PTR L_aes_gcm_bswap_mask
        movdqu	xmm1, OWORD PTR [edx+48]
        pshufb	xmm1, xmm4
        movdqu	xmm3, OWORD PTR [esp]
        pshufd	xmm5, xmm1, 78
        pshufd	xmm6, xmm3, 78
        movdqa	xmm7, xmm3
        movdqa	xmm4, xmm3
        pclmulqdq	xmm7, xmm1, 17
        pclmulqdq	xmm4, xmm1, 0
        pxor	xmm5, xmm1
        pxor	xmm6, xmm3
        pclmulqdq	xmm5, xmm6, 0
        pxor	xmm5, xmm4
        pxor	xmm5, xmm7
        movdqa	xmm6, xmm5
        pxor	xmm0, xmm4
        pxor	xmm2, xmm7
        pslldq	xmm6, 8
        psrldq	xmm5, 8
        pxor	xmm0, xmm6
        pxor	xmm2, xmm5
        movdqa	xmm4, xmm0
        movdqa	xmm5, xmm0
        movdqa	xmm6, xmm0
        pslld	xmm4, 31
        pslld	xmm5, 30
        pslld	xmm6, 25
        pxor	xmm4, xmm5
        pxor	xmm4, xmm6
        movdqa	xmm5, xmm4
        psrldq	xmm5, 4
        pslldq	xmm4, 12
        pxor	xmm0, xmm4
        movdqa	xmm6, xmm0
        movdqa	xmm7, xmm0
        movdqa	xmm4, xmm0
        psrld	xmm6, 1
        psrld	xmm7, 2
        psrld	xmm4, 7
        pxor	xmm6, xmm7
        pxor	xmm6, xmm4
        pxor	xmm6, xmm5
        pxor	xmm6, xmm0
        pxor	xmm2, xmm6
        movdqu	xmm1, OWORD PTR [esp]
L_AES_GCM_encrypt_aesni_done_64:
        mov	edx, DWORD PTR [esp+152]
        cmp	ebx, edx
        jge	L_AES_GCM_encrypt_aesni_done_enc
        mov	eax, DWORD PTR [esp+152]
        and	eax, 4294967280
        cmp	ebx, eax
        jge	L_AES_GCM_encrypt_aesni_last_block_done
        lea	ecx, DWORD PTR [esi+ebx]
        lea	edx, DWORD PTR [edi+ebx]
        movdqu	xmm4, OWORD PTR [esp+64]
        movdqa	xmm5, xmm4
        pshufb	xmm4, OWORD PTR L_aes_gcm_bswap_epi64
        paddd	xmm5, OWORD PTR L_aes_gcm_one
        pxor	xmm4, [ebp]
        movdqu	OWORD PTR [esp+64], xmm5
        aesenc	xmm4, [ebp+16]
        aesenc	xmm4, [ebp+32]
        aesenc	xmm4, [ebp+48]
        aesenc	xmm4, [ebp+64]
        aesenc	xmm4, [ebp+80]
        aesenc	xmm4, [ebp+96]
        aesenc	xmm4, [ebp+112]
        aesenc	xmm4, [ebp+128]
        aesenc	xmm4, [ebp+144]
        cmp	DWORD PTR [esp+172], 11
        movdqa	xmm5, OWORD PTR [ebp+160]
        jl	L_AES_GCM_encrypt_aesni_aesenc_block_aesenc_avx_last
        aesenc	xmm4, xmm5
        aesenc	xmm4, [ebp+176]
        cmp	DWORD PTR [esp+172], 13
        movdqa	xmm5, OWORD PTR [ebp+192]
        jl	L_AES_GCM_encrypt_aesni_aesenc_block_aesenc_avx_last
        aesenc	xmm4, xmm5
        aesenc	xmm4, [ebp+208]
        movdqa	xmm5, OWORD PTR [ebp+224]
L_AES_GCM_encrypt_aesni_aesenc_block_aesenc_avx_last:
        aesenclast	xmm4, xmm5
        movdqu	xmm5, OWORD PTR [ecx]
        pxor	xmm4, xmm5
        movdqu	OWORD PTR [edx], xmm4
        pshufb	xmm4, OWORD PTR L_aes_gcm_bswap_mask
        pxor	xmm2, xmm4
        add	ebx, 16
        cmp	ebx, eax
        jge	L_AES_GCM_encrypt_aesni_last_block_ghash
L_AES_GCM_encrypt_aesni_last_block_start:
        lea	ecx, DWORD PTR [esi+ebx]
        lea	edx, DWORD PTR [edi+ebx]
        movdqu	xmm4, OWORD PTR [esp+64]
        movdqa	xmm5, xmm4
        pshufb	xmm4, OWORD PTR L_aes_gcm_bswap_epi64
        paddd	xmm5, OWORD PTR L_aes_gcm_one
        pxor	xmm4, [ebp]
        movdqu	OWORD PTR [esp+64], xmm5
        movdqu	xmm0, xmm2
        pclmulqdq	xmm0, xmm1, 16
        aesenc	xmm4, [ebp+16]
        aesenc	xmm4, [ebp+32]
        movdqu	xmm3, xmm2
        pclmulqdq	xmm3, xmm1, 1
        aesenc	xmm4, [ebp+48]
        aesenc	xmm4, [ebp+64]
        aesenc	xmm4, [ebp+80]
        movdqu	xmm5, xmm2
        pclmulqdq	xmm5, xmm1, 17
        aesenc	xmm4, [ebp+96]
        pxor	xmm0, xmm3
        movdqa	xmm6, xmm0
        psrldq	xmm0, 8
        pslldq	xmm6, 8
        aesenc	xmm4, [ebp+112]
        movdqu	xmm3, xmm2
        pclmulqdq	xmm3, xmm1, 0
        pxor	xmm6, xmm3
        pxor	xmm5, xmm0
        movdqa	xmm7, OWORD PTR L_aes_gcm_mod2_128
        movdqa	xmm3, xmm6
        pclmulqdq	xmm3, xmm7, 16
        aesenc	xmm4, [ebp+128]
        pshufd	xmm0, xmm6, 78
        pxor	xmm0, xmm3
        movdqa	xmm3, xmm0
        pclmulqdq	xmm3, xmm7, 16
        aesenc	xmm4, [ebp+144]
        pshufd	xmm2, xmm0, 78
        pxor	xmm2, xmm3
        pxor	xmm2, xmm5
        cmp	DWORD PTR [esp+172], 11
        movdqa	xmm5, OWORD PTR [ebp+160]
        jl	L_AES_GCM_encrypt_aesni_aesenc_gfmul_last
        aesenc	xmm4, xmm5
        aesenc	xmm4, [ebp+176]
        cmp	DWORD PTR [esp+172], 13
        movdqa	xmm5, OWORD PTR [ebp+192]
        jl	L_AES_GCM_encrypt_aesni_aesenc_gfmul_last
        aesenc	xmm4, xmm5
        aesenc	xmm4, [ebp+208]
        movdqa	xmm5, OWORD PTR [ebp+224]
L_AES_GCM_encrypt_aesni_aesenc_gfmul_last:
        aesenclast	xmm4, xmm5
        movdqu	xmm5, OWORD PTR [ecx]
        pxor	xmm4, xmm5
        movdqu	OWORD PTR [edx], xmm4
        pshufb	xmm4, OWORD PTR L_aes_gcm_bswap_mask
        pxor	xmm2, xmm4
        add	ebx, 16
        cmp	ebx, eax
        jl	L_AES_GCM_encrypt_aesni_last_block_start
L_AES_GCM_encrypt_aesni_last_block_ghash:
        pshufd	xmm5, xmm1, 78
        pshufd	xmm6, xmm2, 78
        movdqa	xmm7, xmm2
        movdqa	xmm4, xmm2
        pclmulqdq	xmm7, xmm1, 17
        pclmulqdq	xmm4, xmm1, 0
        pxor	xmm5, xmm1
        pxor	xmm6, xmm2
        pclmulqdq	xmm5, xmm6, 0
        pxor	xmm5, xmm4
        pxor	xmm5, xmm7
        movdqa	xmm6, xmm5
        movdqa	xmm2, xmm7
        pslldq	xmm6, 8
        psrldq	xmm5, 8
        pxor	xmm4, xmm6
        pxor	xmm2, xmm5
        movdqa	xmm5, xmm4
        movdqa	xmm6, xmm4
        movdqa	xmm7, xmm4
        pslld	xmm5, 31
        pslld	xmm6, 30
        pslld	xmm7, 25
        pxor	xmm5, xmm6
        pxor	xmm5, xmm7
        movdqa	xmm7, xmm5
        psrldq	xmm7, 4
        pslldq	xmm5, 12
        pxor	xmm4, xmm5
        movdqa	xmm5, xmm4
        movdqa	xmm6, xmm4
        psrld	xmm5, 1
        psrld	xmm6, 2
        pxor	xmm5, xmm6
        pxor	xmm5, xmm4
        psrld	xmm4, 7
        pxor	xmm5, xmm7
        pxor	xmm5, xmm4
        pxor	xmm2, xmm5
L_AES_GCM_encrypt_aesni_last_block_done:
        mov	ecx, DWORD PTR [esp+152]
        mov	edx, ecx
        and	ecx, 15
        jz	L_AES_GCM_encrypt_aesni_aesenc_last15_enc_avx_done
        movdqu	xmm0, OWORD PTR [esp+64]
        pshufb	xmm0, OWORD PTR L_aes_gcm_bswap_epi64
        pxor	xmm0, [ebp]
        aesenc	xmm0, [ebp+16]
        aesenc	xmm0, [ebp+32]
        aesenc	xmm0, [ebp+48]
        aesenc	xmm0, [ebp+64]
        aesenc	xmm0, [ebp+80]
        aesenc	xmm0, [ebp+96]
        aesenc	xmm0, [ebp+112]
        aesenc	xmm0, [ebp+128]
        aesenc	xmm0, [ebp+144]
        cmp	DWORD PTR [esp+172], 11
        movdqa	xmm5, OWORD PTR [ebp+160]
        jl	L_AES_GCM_encrypt_aesni_aesenc_last15_enc_avx_aesenc_avx_last
        aesenc	xmm0, xmm5
        aesenc	xmm0, [ebp+176]
        cmp	DWORD PTR [esp+172], 13
        movdqa	xmm5, OWORD PTR [ebp+192]
        jl	L_AES_GCM_encrypt_aesni_aesenc_last15_enc_avx_aesenc_avx_last
        aesenc	xmm0, xmm5
        aesenc	xmm0, [ebp+208]
        movdqa	xmm5, OWORD PTR [ebp+224]
L_AES_GCM_encrypt_aesni_aesenc_last15_enc_avx_aesenc_avx_last:
        aesenclast	xmm0, xmm5
        sub	esp, 16
        xor	ecx, ecx
        movdqu	OWORD PTR [esp], xmm0
L_AES_GCM_encrypt_aesni_aesenc_last15_enc_avx_loop:
        movzx	eax, BYTE PTR [esi+ebx]
        xor	al, BYTE PTR [esp+ecx]
        mov	BYTE PTR [edi+ebx], al
        mov	BYTE PTR [esp+ecx], al
        inc	ebx
        inc	ecx
        cmp	ebx, edx
        jl	L_AES_GCM_encrypt_aesni_aesenc_last15_enc_avx_loop
        xor	eax, eax
        cmp	ecx, 16
        je	L_AES_GCM_encrypt_aesni_aesenc_last15_enc_avx_finish_enc
L_AES_GCM_encrypt_aesni_aesenc_last15_enc_avx_byte_loop:
        mov	BYTE PTR [esp+ecx], al
        inc	ecx
        cmp	ecx, 16
        jl	L_AES_GCM_encrypt_aesni_aesenc_last15_enc_avx_byte_loop
L_AES_GCM_encrypt_aesni_aesenc_last15_enc_avx_finish_enc:
        movdqu	xmm0, OWORD PTR [esp]
        add	esp, 16
        pshufb	xmm0, OWORD PTR L_aes_gcm_bswap_mask
        pxor	xmm2, xmm0
        pshufd	xmm5, xmm1, 78
        pshufd	xmm6, xmm2, 78
        movdqa	xmm7, xmm2
        movdqa	xmm4, xmm2
        pclmulqdq	xmm7, xmm1, 17
        pclmulqdq	xmm4, xmm1, 0
        pxor	xmm5, xmm1
        pxor	xmm6, xmm2
        pclmulqdq	xmm5, xmm6, 0
        pxor	xmm5, xmm4
        pxor	xmm5, xmm7
        movdqa	xmm6, xmm5
        movdqa	xmm2, xmm7
        pslldq	xmm6, 8
        psrldq	xmm5, 8
        pxor	xmm4, xmm6
        pxor	xmm2, xmm5
        movdqa	xmm5, xmm4
        movdqa	xmm6, xmm4
        movdqa	xmm7, xmm4
        pslld	xmm5, 31
        pslld	xmm6, 30
        pslld	xmm7, 25
        pxor	xmm5, xmm6
        pxor	xmm5, xmm7
        movdqa	xmm7, xmm5
        psrldq	xmm7, 4
        pslldq	xmm5, 12
        pxor	xmm4, xmm5
        movdqa	xmm5, xmm4
        movdqa	xmm6, xmm4
        psrld	xmm5, 1
        psrld	xmm6, 2
        pxor	xmm5, xmm6
        pxor	xmm5, xmm4
        psrld	xmm4, 7
        pxor	xmm5, xmm7
        pxor	xmm5, xmm4
        pxor	xmm2, xmm5
L_AES_GCM_encrypt_aesni_aesenc_last15_enc_avx_done:
L_AES_GCM_encrypt_aesni_done_enc:
        mov	edi, DWORD PTR [esp+148]
        mov	ebx, DWORD PTR [esp+164]
        mov	edx, DWORD PTR [esp+152]
        mov	ecx, DWORD PTR [esp+156]
        shl	edx, 3
        shl	ecx, 3
        pinsrd	xmm4, edx, 0
        pinsrd	xmm4, ecx, 2
        mov	edx, DWORD PTR [esp+152]
        mov	ecx, DWORD PTR [esp+156]
        shr	edx, 29
        shr	ecx, 29
        pinsrd	xmm4, edx, 1
        pinsrd	xmm4, ecx, 3
        pxor	xmm2, xmm4
        pshufd	xmm5, xmm1, 78
        pshufd	xmm6, xmm2, 78
        movdqa	xmm7, xmm2
        movdqa	xmm4, xmm2
        pclmulqdq	xmm7, xmm1, 17
        pclmulqdq	xmm4, xmm1, 0
        pxor	xmm5, xmm1
        pxor	xmm6, xmm2
        pclmulqdq	xmm5, xmm6, 0
        pxor	xmm5, xmm4
        pxor	xmm5, xmm7
        movdqa	xmm6, xmm5
        movdqa	xmm2, xmm7
        pslldq	xmm6, 8
        psrldq	xmm5, 8
        pxor	xmm4, xmm6
        pxor	xmm2, xmm5
        movdqa	xmm5, xmm4
        movdqa	xmm6, xmm4
        movdqa	xmm7, xmm4
        pslld	xmm5, 31
        pslld	xmm6, 30
        pslld	xmm7, 25
        pxor	xmm5, xmm6
        pxor	xmm5, xmm7
        movdqa	xmm7, xmm5
        psrldq	xmm7, 4
        pslldq	xmm5, 12
        pxor	xmm4, xmm5
        movdqa	xmm5, xmm4
        movdqa	xmm6, xmm4
        psrld	xmm5, 1
        psrld	xmm6, 2
        pxor	xmm5, xmm6
        pxor	xmm5, xmm4
        psrld	xmm4, 7
        pxor	xmm5, xmm7
        pxor	xmm5, xmm4
        pxor	xmm2, xmm5
        pshufb	xmm2, OWORD PTR L_aes_gcm_bswap_mask
        movdqu	xmm4, OWORD PTR [esp+80]
        pxor	xmm4, xmm2
        cmp	ebx, 16
        je	L_AES_GCM_encrypt_aesni_store_tag_16
        xor	ecx, ecx
        movdqu	OWORD PTR [esp], xmm4
L_AES_GCM_encrypt_aesni_store_tag_loop:
        movzx	eax, BYTE PTR [esp+ecx]
        mov	BYTE PTR [edi+ecx], al
        inc	ecx
        cmp	ecx, ebx
        jne	L_AES_GCM_encrypt_aesni_store_tag_loop
        jmp	L_AES_GCM_encrypt_aesni_store_tag_done
L_AES_GCM_encrypt_aesni_store_tag_16:
        movdqu	OWORD PTR [edi], xmm4
L_AES_GCM_encrypt_aesni_store_tag_done:
        add	esp, 112
        pop	ebp
        pop	edi
        pop	esi
        pop	ebx
        ret
AES_GCM_encrypt_aesni ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_GCM_decrypt_aesni PROC
        push	ebx
        push	esi
        push	edi
        push	ebp
        sub	esp, 176
        mov	esi, DWORD PTR [esp+208]
        mov	ebp, DWORD PTR [esp+232]
        mov	edx, DWORD PTR [esp+224]
        pxor	xmm0, xmm0
        pxor	xmm2, xmm2
        cmp	edx, 12
        jne	L_AES_GCM_decrypt_aesni_iv_not_12
        ; # Calculate values when IV is 12 bytes
        ; Set counter based on IV
        mov	ecx, 16777216
        pinsrd	xmm0, DWORD PTR [esi], 0
        pinsrd	xmm0, DWORD PTR [esi+4], 1
        pinsrd	xmm0, DWORD PTR [esi+8], 2
        pinsrd	xmm0, ecx, 3
        ; H = Encrypt X(=0) and T = Encrypt counter
        movdqa	xmm5, xmm0
        movdqa	xmm1, OWORD PTR [ebp]
        pxor	xmm5, xmm1
        movdqa	xmm3, OWORD PTR [ebp+16]
        aesenc	xmm1, xmm3
        aesenc	xmm5, xmm3
        movdqa	xmm3, OWORD PTR [ebp+32]
        aesenc	xmm1, xmm3
        aesenc	xmm5, xmm3
        movdqa	xmm3, OWORD PTR [ebp+48]
        aesenc	xmm1, xmm3
        aesenc	xmm5, xmm3
        movdqa	xmm3, OWORD PTR [ebp+64]
        aesenc	xmm1, xmm3
        aesenc	xmm5, xmm3
        movdqa	xmm3, OWORD PTR [ebp+80]
        aesenc	xmm1, xmm3
        aesenc	xmm5, xmm3
        movdqa	xmm3, OWORD PTR [ebp+96]
        aesenc	xmm1, xmm3
        aesenc	xmm5, xmm3
        movdqa	xmm3, OWORD PTR [ebp+112]
        aesenc	xmm1, xmm3
        aesenc	xmm5, xmm3
        movdqa	xmm3, OWORD PTR [ebp+128]
        aesenc	xmm1, xmm3
        aesenc	xmm5, xmm3
        movdqa	xmm3, OWORD PTR [ebp+144]
        aesenc	xmm1, xmm3
        aesenc	xmm5, xmm3
        cmp	DWORD PTR [esp+236], 11
        movdqa	xmm3, OWORD PTR [ebp+160]
        jl	L_AES_GCM_decrypt_aesni_calc_iv_12_last
        aesenc	xmm1, xmm3
        aesenc	xmm5, xmm3
        movdqa	xmm3, OWORD PTR [ebp+176]
        aesenc	xmm1, xmm3
        aesenc	xmm5, xmm3
        cmp	DWORD PTR [esp+236], 13
        movdqa	xmm3, OWORD PTR [ebp+192]
        jl	L_AES_GCM_decrypt_aesni_calc_iv_12_last
        aesenc	xmm1, xmm3
        aesenc	xmm5, xmm3
        movdqa	xmm3, OWORD PTR [ebp+208]
        aesenc	xmm1, xmm3
        aesenc	xmm5, xmm3
        movdqa	xmm3, OWORD PTR [ebp+224]
L_AES_GCM_decrypt_aesni_calc_iv_12_last:
        aesenclast	xmm1, xmm3
        aesenclast	xmm5, xmm3
        pshufb	xmm1, OWORD PTR L_aes_gcm_bswap_mask
        movdqu	OWORD PTR [esp+80], xmm5
        jmp	L_AES_GCM_decrypt_aesni_iv_done
L_AES_GCM_decrypt_aesni_iv_not_12:
        ; Calculate values when IV is not 12 bytes
        ; H = Encrypt X(=0)
        movdqa	xmm1, OWORD PTR [ebp]
        aesenc	xmm1, [ebp+16]
        aesenc	xmm1, [ebp+32]
        aesenc	xmm1, [ebp+48]
        aesenc	xmm1, [ebp+64]
        aesenc	xmm1, [ebp+80]
        aesenc	xmm1, [ebp+96]
        aesenc	xmm1, [ebp+112]
        aesenc	xmm1, [ebp+128]
        aesenc	xmm1, [ebp+144]
        cmp	DWORD PTR [esp+236], 11
        movdqa	xmm5, OWORD PTR [ebp+160]
        jl	L_AES_GCM_decrypt_aesni_calc_iv_1_aesenc_avx_last
        aesenc	xmm1, xmm5
        aesenc	xmm1, [ebp+176]
        cmp	DWORD PTR [esp+236], 13
        movdqa	xmm5, OWORD PTR [ebp+192]
        jl	L_AES_GCM_decrypt_aesni_calc_iv_1_aesenc_avx_last
        aesenc	xmm1, xmm5
        aesenc	xmm1, [ebp+208]
        movdqa	xmm5, OWORD PTR [ebp+224]
L_AES_GCM_decrypt_aesni_calc_iv_1_aesenc_avx_last:
        aesenclast	xmm1, xmm5
        pshufb	xmm1, OWORD PTR L_aes_gcm_bswap_mask
        ; Calc counter
        ; Initialization vector
        cmp	edx, 0
        mov	ecx, 0
        je	L_AES_GCM_decrypt_aesni_calc_iv_done
        cmp	edx, 16
        jl	L_AES_GCM_decrypt_aesni_calc_iv_lt16
        and	edx, 4294967280
L_AES_GCM_decrypt_aesni_calc_iv_16_loop:
        movdqu	xmm4, OWORD PTR [esi+ecx]
        pshufb	xmm4, OWORD PTR L_aes_gcm_bswap_mask
        pxor	xmm0, xmm4
        pshufd	xmm5, xmm0, 78
        pshufd	xmm6, xmm1, 78
        movdqa	xmm7, xmm1
        movdqa	xmm4, xmm1
        pclmulqdq	xmm7, xmm0, 17
        pclmulqdq	xmm4, xmm0, 0
        pxor	xmm5, xmm0
        pxor	xmm6, xmm1
        pclmulqdq	xmm5, xmm6, 0
        pxor	xmm5, xmm4
        pxor	xmm5, xmm7
        movdqa	xmm6, xmm5
        movdqa	xmm3, xmm4
        movdqa	xmm0, xmm7
        pslldq	xmm6, 8
        psrldq	xmm5, 8
        pxor	xmm3, xmm6
        pxor	xmm0, xmm5
        movdqa	xmm4, xmm3
        movdqa	xmm5, xmm0
        psrld	xmm4, 31
        psrld	xmm5, 31
        pslld	xmm3, 1
        pslld	xmm0, 1
        movdqa	xmm6, xmm4
        pslldq	xmm4, 4
        psrldq	xmm6, 12
        pslldq	xmm5, 4
        por	xmm0, xmm6
        por	xmm3, xmm4
        por	xmm0, xmm5
        movdqa	xmm4, xmm3
        movdqa	xmm5, xmm3
        movdqa	xmm6, xmm3
        pslld	xmm4, 31
        pslld	xmm5, 30
        pslld	xmm6, 25
        pxor	xmm4, xmm5
        pxor	xmm4, xmm6
        movdqa	xmm5, xmm4
        psrldq	xmm5, 4
        pslldq	xmm4, 12
        pxor	xmm3, xmm4
        movdqa	xmm6, xmm3
        movdqa	xmm7, xmm3
        movdqa	xmm4, xmm3
        psrld	xmm6, 1
        psrld	xmm7, 2
        psrld	xmm4, 7
        pxor	xmm6, xmm7
        pxor	xmm6, xmm4
        pxor	xmm6, xmm5
        pxor	xmm6, xmm3
        pxor	xmm0, xmm6
        add	ecx, 16
        cmp	ecx, edx
        jl	L_AES_GCM_decrypt_aesni_calc_iv_16_loop
        mov	edx, DWORD PTR [esp+224]
        cmp	ecx, edx
        je	L_AES_GCM_decrypt_aesni_calc_iv_done
L_AES_GCM_decrypt_aesni_calc_iv_lt16:
        sub	esp, 16
        pxor	xmm4, xmm4
        xor	ebx, ebx
        movdqu	OWORD PTR [esp], xmm4
L_AES_GCM_decrypt_aesni_calc_iv_loop:
        movzx	eax, BYTE PTR [esi+ecx]
        mov	BYTE PTR [esp+ebx], al
        inc	ecx
        inc	ebx
        cmp	ecx, edx
        jl	L_AES_GCM_decrypt_aesni_calc_iv_loop
        movdqu	xmm4, OWORD PTR [esp]
        add	esp, 16
        pshufb	xmm4, OWORD PTR L_aes_gcm_bswap_mask
        pxor	xmm0, xmm4
        pshufd	xmm5, xmm0, 78
        pshufd	xmm6, xmm1, 78
        movdqa	xmm7, xmm1
        movdqa	xmm4, xmm1
        pclmulqdq	xmm7, xmm0, 17
        pclmulqdq	xmm4, xmm0, 0
        pxor	xmm5, xmm0
        pxor	xmm6, xmm1
        pclmulqdq	xmm5, xmm6, 0
        pxor	xmm5, xmm4
        pxor	xmm5, xmm7
        movdqa	xmm6, xmm5
        movdqa	xmm3, xmm4
        movdqa	xmm0, xmm7
        pslldq	xmm6, 8
        psrldq	xmm5, 8
        pxor	xmm3, xmm6
        pxor	xmm0, xmm5
        movdqa	xmm4, xmm3
        movdqa	xmm5, xmm0
        psrld	xmm4, 31
        psrld	xmm5, 31
        pslld	xmm3, 1
        pslld	xmm0, 1
        movdqa	xmm6, xmm4
        pslldq	xmm4, 4
        psrldq	xmm6, 12
        pslldq	xmm5, 4
        por	xmm0, xmm6
        por	xmm3, xmm4
        por	xmm0, xmm5
        movdqa	xmm4, xmm3
        movdqa	xmm5, xmm3
        movdqa	xmm6, xmm3
        pslld	xmm4, 31
        pslld	xmm5, 30
        pslld	xmm6, 25
        pxor	xmm4, xmm5
        pxor	xmm4, xmm6
        movdqa	xmm5, xmm4
        psrldq	xmm5, 4
        pslldq	xmm4, 12
        pxor	xmm3, xmm4
        movdqa	xmm6, xmm3
        movdqa	xmm7, xmm3
        movdqa	xmm4, xmm3
        psrld	xmm6, 1
        psrld	xmm7, 2
        psrld	xmm4, 7
        pxor	xmm6, xmm7
        pxor	xmm6, xmm4
        pxor	xmm6, xmm5
        pxor	xmm6, xmm3
        pxor	xmm0, xmm6
L_AES_GCM_decrypt_aesni_calc_iv_done:
        ; T = Encrypt counter
        pxor	xmm4, xmm4
        shl	edx, 3
        pinsrd	xmm4, edx, 0
        pxor	xmm0, xmm4
        pshufd	xmm5, xmm0, 78
        pshufd	xmm6, xmm1, 78
        movdqa	xmm7, xmm1
        movdqa	xmm4, xmm1
        pclmulqdq	xmm7, xmm0, 17
        pclmulqdq	xmm4, xmm0, 0
        pxor	xmm5, xmm0
        pxor	xmm6, xmm1
        pclmulqdq	xmm5, xmm6, 0
        pxor	xmm5, xmm4
        pxor	xmm5, xmm7
        movdqa	xmm6, xmm5
        movdqa	xmm3, xmm4
        movdqa	xmm0, xmm7
        pslldq	xmm6, 8
        psrldq	xmm5, 8
        pxor	xmm3, xmm6
        pxor	xmm0, xmm5
        movdqa	xmm4, xmm3
        movdqa	xmm5, xmm0
        psrld	xmm4, 31
        psrld	xmm5, 31
        pslld	xmm3, 1
        pslld	xmm0, 1
        movdqa	xmm6, xmm4
        pslldq	xmm4, 4
        psrldq	xmm6, 12
        pslldq	xmm5, 4
        por	xmm0, xmm6
        por	xmm3, xmm4
        por	xmm0, xmm5
        movdqa	xmm4, xmm3
        movdqa	xmm5, xmm3
        movdqa	xmm6, xmm3
        pslld	xmm4, 31
        pslld	xmm5, 30
        pslld	xmm6, 25
        pxor	xmm4, xmm5
        pxor	xmm4, xmm6
        movdqa	xmm5, xmm4
        psrldq	xmm5, 4
        pslldq	xmm4, 12
        pxor	xmm3, xmm4
        movdqa	xmm6, xmm3
        movdqa	xmm7, xmm3
        movdqa	xmm4, xmm3
        psrld	xmm6, 1
        psrld	xmm7, 2
        psrld	xmm4, 7
        pxor	xmm6, xmm7
        pxor	xmm6, xmm4
        pxor	xmm6, xmm5
        pxor	xmm6, xmm3
        pxor	xmm0, xmm6
        pshufb	xmm0, OWORD PTR L_aes_gcm_bswap_mask
        ;   Encrypt counter
        movdqa	xmm4, OWORD PTR [ebp]
        pxor	xmm4, xmm0
        aesenc	xmm4, [ebp+16]
        aesenc	xmm4, [ebp+32]
        aesenc	xmm4, [ebp+48]
        aesenc	xmm4, [ebp+64]
        aesenc	xmm4, [ebp+80]
        aesenc	xmm4, [ebp+96]
        aesenc	xmm4, [ebp+112]
        aesenc	xmm4, [ebp+128]
        aesenc	xmm4, [ebp+144]
        cmp	DWORD PTR [esp+236], 11
        movdqa	xmm5, OWORD PTR [ebp+160]
        jl	L_AES_GCM_decrypt_aesni_calc_iv_2_aesenc_avx_last
        aesenc	xmm4, xmm5
        aesenc	xmm4, [ebp+176]
        cmp	DWORD PTR [esp+236], 13
        movdqa	xmm5, OWORD PTR [ebp+192]
        jl	L_AES_GCM_decrypt_aesni_calc_iv_2_aesenc_avx_last
        aesenc	xmm4, xmm5
        aesenc	xmm4, [ebp+208]
        movdqa	xmm5, OWORD PTR [ebp+224]
L_AES_GCM_decrypt_aesni_calc_iv_2_aesenc_avx_last:
        aesenclast	xmm4, xmm5
        movdqu	OWORD PTR [esp+80], xmm4
L_AES_GCM_decrypt_aesni_iv_done:
        mov	esi, DWORD PTR [esp+204]
        ; Additional authentication data
        mov	edx, DWORD PTR [esp+220]
        cmp	edx, 0
        je	L_AES_GCM_decrypt_aesni_calc_aad_done
        xor	ecx, ecx
        cmp	edx, 16
        jl	L_AES_GCM_decrypt_aesni_calc_aad_lt16
        and	edx, 4294967280
L_AES_GCM_decrypt_aesni_calc_aad_16_loop:
        movdqu	xmm4, OWORD PTR [esi+ecx]
        pshufb	xmm4, OWORD PTR L_aes_gcm_bswap_mask
        pxor	xmm2, xmm4
        pshufd	xmm5, xmm2, 78
        pshufd	xmm6, xmm1, 78
        movdqa	xmm7, xmm1
        movdqa	xmm4, xmm1
        pclmulqdq	xmm7, xmm2, 17
        pclmulqdq	xmm4, xmm2, 0
        pxor	xmm5, xmm2
        pxor	xmm6, xmm1
        pclmulqdq	xmm5, xmm6, 0
        pxor	xmm5, xmm4
        pxor	xmm5, xmm7
        movdqa	xmm6, xmm5
        movdqa	xmm3, xmm4
        movdqa	xmm2, xmm7
        pslldq	xmm6, 8
        psrldq	xmm5, 8
        pxor	xmm3, xmm6
        pxor	xmm2, xmm5
        movdqa	xmm4, xmm3
        movdqa	xmm5, xmm2
        psrld	xmm4, 31
        psrld	xmm5, 31
        pslld	xmm3, 1
        pslld	xmm2, 1
        movdqa	xmm6, xmm4
        pslldq	xmm4, 4
        psrldq	xmm6, 12
        pslldq	xmm5, 4
        por	xmm2, xmm6
        por	xmm3, xmm4
        por	xmm2, xmm5
        movdqa	xmm4, xmm3
        movdqa	xmm5, xmm3
        movdqa	xmm6, xmm3
        pslld	xmm4, 31
        pslld	xmm5, 30
        pslld	xmm6, 25
        pxor	xmm4, xmm5
        pxor	xmm4, xmm6
        movdqa	xmm5, xmm4
        psrldq	xmm5, 4
        pslldq	xmm4, 12
        pxor	xmm3, xmm4
        movdqa	xmm6, xmm3
        movdqa	xmm7, xmm3
        movdqa	xmm4, xmm3
        psrld	xmm6, 1
        psrld	xmm7, 2
        psrld	xmm4, 7
        pxor	xmm6, xmm7
        pxor	xmm6, xmm4
        pxor	xmm6, xmm5
        pxor	xmm6, xmm3
        pxor	xmm2, xmm6
        add	ecx, 16
        cmp	ecx, edx
        jl	L_AES_GCM_decrypt_aesni_calc_aad_16_loop
        mov	edx, DWORD PTR [esp+220]
        cmp	ecx, edx
        je	L_AES_GCM_decrypt_aesni_calc_aad_done
L_AES_GCM_decrypt_aesni_calc_aad_lt16:
        sub	esp, 16
        pxor	xmm4, xmm4
        xor	ebx, ebx
        movdqu	OWORD PTR [esp], xmm4
L_AES_GCM_decrypt_aesni_calc_aad_loop:
        movzx	eax, BYTE PTR [esi+ecx]
        mov	BYTE PTR [esp+ebx], al
        inc	ecx
        inc	ebx
        cmp	ecx, edx
        jl	L_AES_GCM_decrypt_aesni_calc_aad_loop
        movdqu	xmm4, OWORD PTR [esp]
        add	esp, 16
        pshufb	xmm4, OWORD PTR L_aes_gcm_bswap_mask
        pxor	xmm2, xmm4
        pshufd	xmm5, xmm2, 78
        pshufd	xmm6, xmm1, 78
        movdqa	xmm7, xmm1
        movdqa	xmm4, xmm1
        pclmulqdq	xmm7, xmm2, 17
        pclmulqdq	xmm4, xmm2, 0
        pxor	xmm5, xmm2
        pxor	xmm6, xmm1
        pclmulqdq	xmm5, xmm6, 0
        pxor	xmm5, xmm4
        pxor	xmm5, xmm7
        movdqa	xmm6, xmm5
        movdqa	xmm3, xmm4
        movdqa	xmm2, xmm7
        pslldq	xmm6, 8
        psrldq	xmm5, 8
        pxor	xmm3, xmm6
        pxor	xmm2, xmm5
        movdqa	xmm4, xmm3
        movdqa	xmm5, xmm2
        psrld	xmm4, 31
        psrld	xmm5, 31
        pslld	xmm3, 1
        pslld	xmm2, 1
        movdqa	xmm6, xmm4
        pslldq	xmm4, 4
        psrldq	xmm6, 12
        pslldq	xmm5, 4
        por	xmm2, xmm6
        por	xmm3, xmm4
        por	xmm2, xmm5
        movdqa	xmm4, xmm3
        movdqa	xmm5, xmm3
        movdqa	xmm6, xmm3
        pslld	xmm4, 31
        pslld	xmm5, 30
        pslld	xmm6, 25
        pxor	xmm4, xmm5
        pxor	xmm4, xmm6
        movdqa	xmm5, xmm4
        psrldq	xmm5, 4
        pslldq	xmm4, 12
        pxor	xmm3, xmm4
        movdqa	xmm6, xmm3
        movdqa	xmm7, xmm3
        movdqa	xmm4, xmm3
        psrld	xmm6, 1
        psrld	xmm7, 2
        psrld	xmm4, 7
        pxor	xmm6, xmm7
        pxor	xmm6, xmm4
        pxor	xmm6, xmm5
        pxor	xmm6, xmm3
        pxor	xmm2, xmm6
L_AES_GCM_decrypt_aesni_calc_aad_done:
        movdqu	OWORD PTR [esp+96], xmm2
        mov	esi, DWORD PTR [esp+196]
        mov	edi, DWORD PTR [esp+200]
        ; Calculate counter and H
        pshufb	xmm0, OWORD PTR L_aes_gcm_bswap_epi64
        movdqa	xmm5, xmm1
        paddd	xmm0, OWORD PTR L_aes_gcm_one
        movdqa	xmm4, xmm1
        movdqu	OWORD PTR [esp+64], xmm0
        psrlq	xmm5, 63
        psllq	xmm4, 1
        pslldq	xmm5, 8
        por	xmm4, xmm5
        pshufd	xmm1, xmm1, 255
        psrad	xmm1, 31
        pand	xmm1, OWORD PTR L_aes_gcm_mod2_128
        pxor	xmm1, xmm4
        xor	ebx, ebx
        cmp	DWORD PTR [esp+216], 64
        mov	eax, DWORD PTR [esp+216]
        jl	L_AES_GCM_decrypt_aesni_done_64
        and	eax, 4294967232
        movdqa	xmm6, xmm2
        ; H ^ 1
        movdqu	OWORD PTR [esp], xmm1
        ; H ^ 2
        pshufd	xmm5, xmm1, 78
        pshufd	xmm6, xmm1, 78
        movdqa	xmm7, xmm1
        movdqa	xmm4, xmm1
        pclmulqdq	xmm7, xmm1, 17
        pclmulqdq	xmm4, xmm1, 0
        pxor	xmm5, xmm1
        pxor	xmm6, xmm1
        pclmulqdq	xmm5, xmm6, 0
        pxor	xmm5, xmm4
        pxor	xmm5, xmm7
        movdqa	xmm6, xmm5
        movdqa	xmm0, xmm7
        pslldq	xmm6, 8
        psrldq	xmm5, 8
        pxor	xmm4, xmm6
        pxor	xmm0, xmm5
        movdqa	xmm5, xmm4
        movdqa	xmm6, xmm4
        movdqa	xmm7, xmm4
        pslld	xmm5, 31
        pslld	xmm6, 30
        pslld	xmm7, 25
        pxor	xmm5, xmm6
        pxor	xmm5, xmm7
        movdqa	xmm7, xmm5
        psrldq	xmm7, 4
        pslldq	xmm5, 12
        pxor	xmm4, xmm5
        movdqa	xmm5, xmm4
        movdqa	xmm6, xmm4
        psrld	xmm5, 1
        psrld	xmm6, 2
        pxor	xmm5, xmm6
        pxor	xmm5, xmm4
        psrld	xmm4, 7
        pxor	xmm5, xmm7
        pxor	xmm5, xmm4
        pxor	xmm0, xmm5
        movdqu	OWORD PTR [esp+16], xmm0
        ; H ^ 3
        pshufd	xmm5, xmm1, 78
        pshufd	xmm6, xmm0, 78
        movdqa	xmm7, xmm0
        movdqa	xmm4, xmm0
        pclmulqdq	xmm7, xmm1, 17
        pclmulqdq	xmm4, xmm1, 0
        pxor	xmm5, xmm1
        pxor	xmm6, xmm0
        pclmulqdq	xmm5, xmm6, 0
        pxor	xmm5, xmm4
        pxor	xmm5, xmm7
        movdqa	xmm6, xmm5
        movdqa	xmm3, xmm7
        pslldq	xmm6, 8
        psrldq	xmm5, 8
        pxor	xmm4, xmm6
        pxor	xmm3, xmm5
        movdqa	xmm5, xmm4
        movdqa	xmm6, xmm4
        movdqa	xmm7, xmm4
        pslld	xmm5, 31
        pslld	xmm6, 30
        pslld	xmm7, 25
        pxor	xmm5, xmm6
        pxor	xmm5, xmm7
        movdqa	xmm7, xmm5
        psrldq	xmm7, 4
        pslldq	xmm5, 12
        pxor	xmm4, xmm5
        movdqa	xmm5, xmm4
        movdqa	xmm6, xmm4
        psrld	xmm5, 1
        psrld	xmm6, 2
        pxor	xmm5, xmm6
        pxor	xmm5, xmm4
        psrld	xmm4, 7
        pxor	xmm5, xmm7
        pxor	xmm5, xmm4
        pxor	xmm3, xmm5
        movdqu	OWORD PTR [esp+32], xmm3
        ; H ^ 4
        pshufd	xmm5, xmm0, 78
        pshufd	xmm6, xmm0, 78
        movdqa	xmm7, xmm0
        movdqa	xmm4, xmm0
        pclmulqdq	xmm7, xmm0, 17
        pclmulqdq	xmm4, xmm0, 0
        pxor	xmm5, xmm0
        pxor	xmm6, xmm0
        pclmulqdq	xmm5, xmm6, 0
        pxor	xmm5, xmm4
        pxor	xmm5, xmm7
        movdqa	xmm6, xmm5
        movdqa	xmm3, xmm7
        pslldq	xmm6, 8
        psrldq	xmm5, 8
        pxor	xmm4, xmm6
        pxor	xmm3, xmm5
        movdqa	xmm5, xmm4
        movdqa	xmm6, xmm4
        movdqa	xmm7, xmm4
        pslld	xmm5, 31
        pslld	xmm6, 30
        pslld	xmm7, 25
        pxor	xmm5, xmm6
        pxor	xmm5, xmm7
        movdqa	xmm7, xmm5
        psrldq	xmm7, 4
        pslldq	xmm5, 12
        pxor	xmm4, xmm5
        movdqa	xmm5, xmm4
        movdqa	xmm6, xmm4
        psrld	xmm5, 1
        psrld	xmm6, 2
        pxor	xmm5, xmm6
        pxor	xmm5, xmm4
        psrld	xmm4, 7
        pxor	xmm5, xmm7
        pxor	xmm5, xmm4
        pxor	xmm3, xmm5
        movdqu	OWORD PTR [esp+48], xmm3
        cmp	edi, esi
        jne	L_AES_GCM_decrypt_aesni_ghash_64
L_AES_GCM_decrypt_aesni_ghash_64_inplace:
        lea	ecx, DWORD PTR [esi+ebx]
        lea	edx, DWORD PTR [edi+ebx]
        ; Encrypt 64 bytes of counter
        movdqu	xmm4, OWORD PTR [esp+64]
        movdqu	xmm3, xmm4
        paddd	xmm3, OWORD PTR L_aes_gcm_four
        movdqu	OWORD PTR [esp+64], xmm3
        movdqa	xmm3, OWORD PTR L_aes_gcm_bswap_epi64
        movdqa	xmm5, xmm4
        movdqa	xmm6, xmm4
        movdqa	xmm7, xmm4
        pshufb	xmm4, xmm3
        paddd	xmm5, OWORD PTR L_aes_gcm_one
        pshufb	xmm5, xmm3
        paddd	xmm6, OWORD PTR L_aes_gcm_two
        pshufb	xmm6, xmm3
        paddd	xmm7, OWORD PTR L_aes_gcm_three
        pshufb	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp]
        pxor	xmm4, xmm3
        pxor	xmm5, xmm3
        pxor	xmm6, xmm3
        pxor	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+16]
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+32]
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+48]
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+64]
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+80]
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+96]
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+112]
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+128]
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+144]
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        cmp	DWORD PTR [esp+236], 11
        movdqa	xmm3, OWORD PTR [ebp+160]
        jl	L_AES_GCM_decrypt_aesniinplace_aesenc_64_ghash_avx_done
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+176]
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        cmp	DWORD PTR [esp+236], 13
        movdqa	xmm3, OWORD PTR [ebp+192]
        jl	L_AES_GCM_decrypt_aesniinplace_aesenc_64_ghash_avx_done
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+208]
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+224]
L_AES_GCM_decrypt_aesniinplace_aesenc_64_ghash_avx_done:
        aesenclast	xmm4, xmm3
        aesenclast	xmm5, xmm3
        movdqu	xmm0, OWORD PTR [ecx]
        movdqu	xmm1, OWORD PTR [ecx+16]
        pxor	xmm4, xmm0
        pxor	xmm5, xmm1
        movdqu	OWORD PTR [esp+112], xmm0
        movdqu	OWORD PTR [esp+128], xmm1
        movdqu	OWORD PTR [edx], xmm4
        movdqu	OWORD PTR [edx+16], xmm5
        aesenclast	xmm6, xmm3
        aesenclast	xmm7, xmm3
        movdqu	xmm0, OWORD PTR [ecx+32]
        movdqu	xmm1, OWORD PTR [ecx+48]
        pxor	xmm6, xmm0
        pxor	xmm7, xmm1
        movdqu	OWORD PTR [esp+144], xmm0
        movdqu	OWORD PTR [esp+160], xmm1
        movdqu	OWORD PTR [edx+32], xmm6
        movdqu	OWORD PTR [edx+48], xmm7
        ; ghash encrypted counter
        movdqu	xmm6, OWORD PTR [esp+96]
        movdqu	xmm3, OWORD PTR [esp+48]
        movdqu	xmm4, OWORD PTR [esp+112]
        pshufb	xmm4, OWORD PTR L_aes_gcm_bswap_mask
        pxor	xmm4, xmm6
        pshufd	xmm5, xmm3, 78
        pshufd	xmm1, xmm4, 78
        pxor	xmm5, xmm3
        pxor	xmm1, xmm4
        movdqa	xmm7, xmm4
        pclmulqdq	xmm7, xmm3, 17
        movdqa	xmm6, xmm4
        pclmulqdq	xmm6, xmm3, 0
        pclmulqdq	xmm5, xmm1, 0
        pxor	xmm5, xmm6
        pxor	xmm5, xmm7
        movdqu	xmm3, OWORD PTR [esp+32]
        movdqu	xmm4, OWORD PTR [esp+128]
        pshufd	xmm0, xmm3, 78
        pshufb	xmm4, OWORD PTR L_aes_gcm_bswap_mask
        pxor	xmm0, xmm3
        pshufd	xmm1, xmm4, 78
        pxor	xmm1, xmm4
        movdqa	xmm2, xmm4
        pclmulqdq	xmm2, xmm3, 17
        pclmulqdq	xmm3, xmm4, 0
        pclmulqdq	xmm0, xmm1, 0
        pxor	xmm5, xmm3
        pxor	xmm6, xmm3
        pxor	xmm5, xmm2
        pxor	xmm7, xmm2
        pxor	xmm5, xmm0
        movdqu	xmm3, OWORD PTR [esp+16]
        movdqu	xmm4, OWORD PTR [esp+144]
        pshufd	xmm0, xmm3, 78
        pshufb	xmm4, OWORD PTR L_aes_gcm_bswap_mask
        pxor	xmm0, xmm3
        pshufd	xmm1, xmm4, 78
        pxor	xmm1, xmm4
        movdqa	xmm2, xmm4
        pclmulqdq	xmm2, xmm3, 17
        pclmulqdq	xmm3, xmm4, 0
        pclmulqdq	xmm0, xmm1, 0
        pxor	xmm5, xmm3
        pxor	xmm6, xmm3
        pxor	xmm5, xmm2
        pxor	xmm7, xmm2
        pxor	xmm5, xmm0
        movdqu	xmm3, OWORD PTR [esp]
        movdqu	xmm4, OWORD PTR [esp+160]
        pshufd	xmm0, xmm3, 78
        pshufb	xmm4, OWORD PTR L_aes_gcm_bswap_mask
        pxor	xmm0, xmm3
        pshufd	xmm1, xmm4, 78
        pxor	xmm1, xmm4
        movdqa	xmm2, xmm4
        pclmulqdq	xmm2, xmm3, 17
        pclmulqdq	xmm3, xmm4, 0
        pclmulqdq	xmm0, xmm1, 0
        pxor	xmm5, xmm3
        pxor	xmm6, xmm3
        pxor	xmm5, xmm2
        pxor	xmm7, xmm2
        pxor	xmm5, xmm0
        movdqa	xmm1, xmm5
        psrldq	xmm5, 8
        pslldq	xmm1, 8
        pxor	xmm6, xmm1
        pxor	xmm7, xmm5
        movdqa	xmm3, xmm6
        movdqa	xmm0, xmm6
        movdqa	xmm1, xmm6
        pslld	xmm3, 31
        pslld	xmm0, 30
        pslld	xmm1, 25
        pxor	xmm3, xmm0
        pxor	xmm3, xmm1
        movdqa	xmm0, xmm3
        pslldq	xmm3, 12
        psrldq	xmm0, 4
        pxor	xmm6, xmm3
        movdqa	xmm1, xmm6
        movdqa	xmm5, xmm6
        movdqa	xmm4, xmm6
        psrld	xmm1, 1
        psrld	xmm5, 2
        psrld	xmm4, 7
        pxor	xmm1, xmm5
        pxor	xmm1, xmm4
        pxor	xmm1, xmm0
        pxor	xmm6, xmm1
        pxor	xmm6, xmm7
        movdqu	OWORD PTR [esp+96], xmm6
        add	ebx, 64
        cmp	ebx, eax
        jl	L_AES_GCM_decrypt_aesni_ghash_64_inplace
        jmp	L_AES_GCM_decrypt_aesni_ghash_64_done
L_AES_GCM_decrypt_aesni_ghash_64:
        lea	ecx, DWORD PTR [esi+ebx]
        lea	edx, DWORD PTR [edi+ebx]
        ; Encrypt 64 bytes of counter
        movdqu	xmm4, OWORD PTR [esp+64]
        movdqu	xmm3, xmm4
        paddd	xmm3, OWORD PTR L_aes_gcm_four
        movdqu	OWORD PTR [esp+64], xmm3
        movdqa	xmm3, OWORD PTR L_aes_gcm_bswap_epi64
        movdqa	xmm5, xmm4
        movdqa	xmm6, xmm4
        movdqa	xmm7, xmm4
        pshufb	xmm4, xmm3
        paddd	xmm5, OWORD PTR L_aes_gcm_one
        pshufb	xmm5, xmm3
        paddd	xmm6, OWORD PTR L_aes_gcm_two
        pshufb	xmm6, xmm3
        paddd	xmm7, OWORD PTR L_aes_gcm_three
        pshufb	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp]
        pxor	xmm4, xmm3
        pxor	xmm5, xmm3
        pxor	xmm6, xmm3
        pxor	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+16]
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+32]
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+48]
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+64]
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+80]
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+96]
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+112]
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+128]
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+144]
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        cmp	DWORD PTR [esp+236], 11
        movdqa	xmm3, OWORD PTR [ebp+160]
        jl	L_AES_GCM_decrypt_aesni_aesenc_64_ghash_avx_done
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+176]
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        cmp	DWORD PTR [esp+236], 13
        movdqa	xmm3, OWORD PTR [ebp+192]
        jl	L_AES_GCM_decrypt_aesni_aesenc_64_ghash_avx_done
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+208]
        aesenc	xmm4, xmm3
        aesenc	xmm5, xmm3
        aesenc	xmm6, xmm3
        aesenc	xmm7, xmm3
        movdqa	xmm3, OWORD PTR [ebp+224]
L_AES_GCM_decrypt_aesni_aesenc_64_ghash_avx_done:
        aesenclast	xmm4, xmm3
        aesenclast	xmm5, xmm3
        movdqu	xmm0, OWORD PTR [ecx]
        movdqu	xmm1, OWORD PTR [ecx+16]
        pxor	xmm4, xmm0
        pxor	xmm5, xmm1
        movdqu	OWORD PTR [edx], xmm4
        movdqu	OWORD PTR [edx+16], xmm5
        aesenclast	xmm6, xmm3
        aesenclast	xmm7, xmm3
        movdqu	xmm0, OWORD PTR [ecx+32]
        movdqu	xmm1, OWORD PTR [ecx+48]
        pxor	xmm6, xmm0
        pxor	xmm7, xmm1
        movdqu	OWORD PTR [edx+32], xmm6
        movdqu	OWORD PTR [edx+48], xmm7
        ; ghash encrypted counter
        movdqu	xmm6, OWORD PTR [esp+96]
        movdqu	xmm3, OWORD PTR [esp+48]
        movdqu	xmm4, OWORD PTR [ecx]
        pshufb	xmm4, OWORD PTR L_aes_gcm_bswap_mask
        pxor	xmm4, xmm6
        pshufd	xmm5, xmm3, 78
        pshufd	xmm1, xmm4, 78
        pxor	xmm5, xmm3
        pxor	xmm1, xmm4
        movdqa	xmm7, xmm4
        pclmulqdq	xmm7, xmm3, 17
        movdqa	xmm6, xmm4
        pclmulqdq	xmm6, xmm3, 0
        pclmulqdq	xmm5, xmm1, 0
        pxor	xmm5, xmm6
        pxor	xmm5, xmm7
        movdqu	xmm3, OWORD PTR [esp+32]
        movdqu	xmm4, OWORD PTR [ecx+16]
        pshufd	xmm0, xmm3, 78
        pshufb	xmm4, OWORD PTR L_aes_gcm_bswap_mask
        pxor	xmm0, xmm3
        pshufd	xmm1, xmm4, 78
        pxor	xmm1, xmm4
        movdqa	xmm2, xmm4
        pclmulqdq	xmm2, xmm3, 17
        pclmulqdq	xmm3, xmm4, 0
        pclmulqdq	xmm0, xmm1, 0
        pxor	xmm5, xmm3
        pxor	xmm6, xmm3
        pxor	xmm5, xmm2
        pxor	xmm7, xmm2
        pxor	xmm5, xmm0
        movdqu	xmm3, OWORD PTR [esp+16]
        movdqu	xmm4, OWORD PTR [ecx+32]
        pshufd	xmm0, xmm3, 78
        pshufb	xmm4, OWORD PTR L_aes_gcm_bswap_mask
        pxor	xmm0, xmm3
        pshufd	xmm1, xmm4, 78
        pxor	xmm1, xmm4
        movdqa	xmm2, xmm4
        pclmulqdq	xmm2, xmm3, 17
        pclmulqdq	xmm3, xmm4, 0
        pclmulqdq	xmm0, xmm1, 0
        pxor	xmm5, xmm3
        pxor	xmm6, xmm3
        pxor	xmm5, xmm2
        pxor	xmm7, xmm2
        pxor	xmm5, xmm0
        movdqu	xmm3, OWORD PTR [esp]
        movdqu	xmm4, OWORD PTR [ecx+48]
        pshufd	xmm0, xmm3, 78
        pshufb	xmm4, OWORD PTR L_aes_gcm_bswap_mask
        pxor	xmm0, xmm3
        pshufd	xmm1, xmm4, 78
        pxor	xmm1, xmm4
        movdqa	xmm2, xmm4
        pclmulqdq	xmm2, xmm3, 17
        pclmulqdq	xmm3, xmm4, 0
        pclmulqdq	xmm0, xmm1, 0
        pxor	xmm5, xmm3
        pxor	xmm6, xmm3
        pxor	xmm5, xmm2
        pxor	xmm7, xmm2
        pxor	xmm5, xmm0
        movdqa	xmm1, xmm5
        psrldq	xmm5, 8
        pslldq	xmm1, 8
        pxor	xmm6, xmm1
        pxor	xmm7, xmm5
        movdqa	xmm3, xmm6
        movdqa	xmm0, xmm6
        movdqa	xmm1, xmm6
        pslld	xmm3, 31
        pslld	xmm0, 30
        pslld	xmm1, 25
        pxor	xmm3, xmm0
        pxor	xmm3, xmm1
        movdqa	xmm0, xmm3
        pslldq	xmm3, 12
        psrldq	xmm0, 4
        pxor	xmm6, xmm3
        movdqa	xmm1, xmm6
        movdqa	xmm5, xmm6
        movdqa	xmm4, xmm6
        psrld	xmm1, 1
        psrld	xmm5, 2
        psrld	xmm4, 7
        pxor	xmm1, xmm5
        pxor	xmm1, xmm4
        pxor	xmm1, xmm0
        pxor	xmm6, xmm1
        pxor	xmm6, xmm7
        movdqu	OWORD PTR [esp+96], xmm6
        add	ebx, 64
        cmp	ebx, eax
        jl	L_AES_GCM_decrypt_aesni_ghash_64
L_AES_GCM_decrypt_aesni_ghash_64_done:
        movdqa	xmm2, xmm6
        movdqu	xmm1, OWORD PTR [esp]
L_AES_GCM_decrypt_aesni_done_64:
        mov	edx, DWORD PTR [esp+216]
        cmp	ebx, edx
        jge	L_AES_GCM_decrypt_aesni_done_dec
        mov	eax, DWORD PTR [esp+216]
        and	eax, 4294967280
        cmp	ebx, eax
        jge	L_AES_GCM_decrypt_aesni_last_block_done
L_AES_GCM_decrypt_aesni_last_block_start:
        lea	ecx, DWORD PTR [esi+ebx]
        lea	edx, DWORD PTR [edi+ebx]
        movdqu	xmm5, OWORD PTR [ecx]
        pshufb	xmm5, OWORD PTR L_aes_gcm_bswap_mask
        pxor	xmm5, xmm2
        movdqu	OWORD PTR [esp], xmm5
        movdqu	xmm4, OWORD PTR [esp+64]
        movdqa	xmm5, xmm4
        pshufb	xmm4, OWORD PTR L_aes_gcm_bswap_epi64
        paddd	xmm5, OWORD PTR L_aes_gcm_one
        pxor	xmm4, [ebp]
        movdqu	OWORD PTR [esp+64], xmm5
        movdqu	xmm0, OWORD PTR [esp]
        pclmulqdq	xmm0, xmm1, 16
        aesenc	xmm4, [ebp+16]
        aesenc	xmm4, [ebp+32]
        movdqu	xmm3, OWORD PTR [esp]
        pclmulqdq	xmm3, xmm1, 1
        aesenc	xmm4, [ebp+48]
        aesenc	xmm4, [ebp+64]
        aesenc	xmm4, [ebp+80]
        movdqu	xmm5, OWORD PTR [esp]
        pclmulqdq	xmm5, xmm1, 17
        aesenc	xmm4, [ebp+96]
        pxor	xmm0, xmm3
        movdqa	xmm6, xmm0
        psrldq	xmm0, 8
        pslldq	xmm6, 8
        aesenc	xmm4, [ebp+112]
        movdqu	xmm3, OWORD PTR [esp]
        pclmulqdq	xmm3, xmm1, 0
        pxor	xmm6, xmm3
        pxor	xmm5, xmm0
        movdqa	xmm7, OWORD PTR L_aes_gcm_mod2_128
        movdqa	xmm3, xmm6
        pclmulqdq	xmm3, xmm7, 16
        aesenc	xmm4, [ebp+128]
        pshufd	xmm0, xmm6, 78
        pxor	xmm0, xmm3
        movdqa	xmm3, xmm0
        pclmulqdq	xmm3, xmm7, 16
        aesenc	xmm4, [ebp+144]
        pshufd	xmm2, xmm0, 78
        pxor	xmm2, xmm3
        pxor	xmm2, xmm5
        cmp	DWORD PTR [esp+236], 11
        movdqa	xmm5, OWORD PTR [ebp+160]
        jl	L_AES_GCM_decrypt_aesni_aesenc_gfmul_last
        aesenc	xmm4, xmm5
        aesenc	xmm4, [ebp+176]
        cmp	DWORD PTR [esp+236], 13
        movdqa	xmm5, OWORD PTR [ebp+192]
        jl	L_AES_GCM_decrypt_aesni_aesenc_gfmul_last
        aesenc	xmm4, xmm5
        aesenc	xmm4, [ebp+208]
        movdqa	xmm5, OWORD PTR [ebp+224]
L_AES_GCM_decrypt_aesni_aesenc_gfmul_last:
        aesenclast	xmm4, xmm5
        movdqu	xmm5, OWORD PTR [ecx]
        pxor	xmm4, xmm5
        movdqu	OWORD PTR [edx], xmm4
        add	ebx, 16
        cmp	ebx, eax
        jl	L_AES_GCM_decrypt_aesni_last_block_start
L_AES_GCM_decrypt_aesni_last_block_done:
        mov	ecx, DWORD PTR [esp+216]
        mov	edx, ecx
        and	ecx, 15
        jz	L_AES_GCM_decrypt_aesni_aesenc_last15_dec_avx_done
        movdqu	xmm0, OWORD PTR [esp+64]
        pshufb	xmm0, OWORD PTR L_aes_gcm_bswap_epi64
        pxor	xmm0, [ebp]
        aesenc	xmm0, [ebp+16]
        aesenc	xmm0, [ebp+32]
        aesenc	xmm0, [ebp+48]
        aesenc	xmm0, [ebp+64]
        aesenc	xmm0, [ebp+80]
        aesenc	xmm0, [ebp+96]
        aesenc	xmm0, [ebp+112]
        aesenc	xmm0, [ebp+128]
        aesenc	xmm0, [ebp+144]
        cmp	DWORD PTR [esp+236], 11
        movdqa	xmm5, OWORD PTR [ebp+160]
        jl	L_AES_GCM_decrypt_aesni_aesenc_last15_dec_avx_aesenc_avx_last
        aesenc	xmm0, xmm5
        aesenc	xmm0, [ebp+176]
        cmp	DWORD PTR [esp+236], 13
        movdqa	xmm5, OWORD PTR [ebp+192]
        jl	L_AES_GCM_decrypt_aesni_aesenc_last15_dec_avx_aesenc_avx_last
        aesenc	xmm0, xmm5
        aesenc	xmm0, [ebp+208]
        movdqa	xmm5, OWORD PTR [ebp+224]
L_AES_GCM_decrypt_aesni_aesenc_last15_dec_avx_aesenc_avx_last:
        aesenclast	xmm0, xmm5
        sub	esp, 32
        xor	ecx, ecx
        movdqu	OWORD PTR [esp], xmm0
        pxor	xmm4, xmm4
        movdqu	OWORD PTR [esp+16], xmm4
L_AES_GCM_decrypt_aesni_aesenc_last15_dec_avx_loop:
        movzx	eax, BYTE PTR [esi+ebx]
        mov	BYTE PTR [esp+ecx+16], al
        xor	al, BYTE PTR [esp+ecx]
        mov	BYTE PTR [edi+ebx], al
        inc	ebx
        inc	ecx
        cmp	ebx, edx
        jl	L_AES_GCM_decrypt_aesni_aesenc_last15_dec_avx_loop
        movdqu	xmm0, OWORD PTR [esp+16]
        add	esp, 32
        pshufb	xmm0, OWORD PTR L_aes_gcm_bswap_mask
        pxor	xmm2, xmm0
        pshufd	xmm5, xmm1, 78
        pshufd	xmm6, xmm2, 78
        movdqa	xmm7, xmm2
        movdqa	xmm4, xmm2
        pclmulqdq	xmm7, xmm1, 17
        pclmulqdq	xmm4, xmm1, 0
        pxor	xmm5, xmm1
        pxor	xmm6, xmm2
        pclmulqdq	xmm5, xmm6, 0
        pxor	xmm5, xmm4
        pxor	xmm5, xmm7
        movdqa	xmm6, xmm5
        movdqa	xmm2, xmm7
        pslldq	xmm6, 8
        psrldq	xmm5, 8
        pxor	xmm4, xmm6
        pxor	xmm2, xmm5
        movdqa	xmm5, xmm4
        movdqa	xmm6, xmm4
        movdqa	xmm7, xmm4
        pslld	xmm5, 31
        pslld	xmm6, 30
        pslld	xmm7, 25
        pxor	xmm5, xmm6
        pxor	xmm5, xmm7
        movdqa	xmm7, xmm5
        psrldq	xmm7, 4
        pslldq	xmm5, 12
        pxor	xmm4, xmm5
        movdqa	xmm5, xmm4
        movdqa	xmm6, xmm4
        psrld	xmm5, 1
        psrld	xmm6, 2
        pxor	xmm5, xmm6
        pxor	xmm5, xmm4
        psrld	xmm4, 7
        pxor	xmm5, xmm7
        pxor	xmm5, xmm4
        pxor	xmm2, xmm5
L_AES_GCM_decrypt_aesni_aesenc_last15_dec_avx_done:
L_AES_GCM_decrypt_aesni_done_dec:
        mov	esi, DWORD PTR [esp+212]
        mov	ebp, DWORD PTR [esp+228]
        mov	edx, DWORD PTR [esp+216]
        mov	ecx, DWORD PTR [esp+220]
        shl	edx, 3
        shl	ecx, 3
        pinsrd	xmm4, edx, 0
        pinsrd	xmm4, ecx, 2
        mov	edx, DWORD PTR [esp+216]
        mov	ecx, DWORD PTR [esp+220]
        shr	edx, 29
        shr	ecx, 29
        pinsrd	xmm4, edx, 1
        pinsrd	xmm4, ecx, 3
        pxor	xmm2, xmm4
        pshufd	xmm5, xmm1, 78
        pshufd	xmm6, xmm2, 78
        movdqa	xmm7, xmm2
        movdqa	xmm4, xmm2
        pclmulqdq	xmm7, xmm1, 17
        pclmulqdq	xmm4, xmm1, 0
        pxor	xmm5, xmm1
        pxor	xmm6, xmm2
        pclmulqdq	xmm5, xmm6, 0
        pxor	xmm5, xmm4
        pxor	xmm5, xmm7
        movdqa	xmm6, xmm5
        movdqa	xmm2, xmm7
        pslldq	xmm6, 8
        psrldq	xmm5, 8
        pxor	xmm4, xmm6
        pxor	xmm2, xmm5
        movdqa	xmm5, xmm4
        movdqa	xmm6, xmm4
        movdqa	xmm7, xmm4
        pslld	xmm5, 31
        pslld	xmm6, 30
        pslld	xmm7, 25
        pxor	xmm5, xmm6
        pxor	xmm5, xmm7
        movdqa	xmm7, xmm5
        psrldq	xmm7, 4
        pslldq	xmm5, 12
        pxor	xmm4, xmm5
        movdqa	xmm5, xmm4
        movdqa	xmm6, xmm4
        psrld	xmm5, 1
        psrld	xmm6, 2
        pxor	xmm5, xmm6
        pxor	xmm5, xmm4
        psrld	xmm4, 7
        pxor	xmm5, xmm7
        pxor	xmm5, xmm4
        pxor	xmm2, xmm5
        pshufb	xmm2, OWORD PTR L_aes_gcm_bswap_mask
        movdqu	xmm4, OWORD PTR [esp+80]
        pxor	xmm4, xmm2
        mov	edi, DWORD PTR [esp+240]
        cmp	ebp, 16
        je	L_AES_GCM_decrypt_aesni_cmp_tag_16
        sub	esp, 16
        xor	ecx, ecx
        xor	ebx, ebx
        movdqu	OWORD PTR [esp], xmm4
L_AES_GCM_decrypt_aesni_cmp_tag_loop:
        movzx	eax, BYTE PTR [esp+ecx]
        xor	al, BYTE PTR [esi+ecx]
        or	bl, al
        inc	ecx
        cmp	ecx, ebp
        jne	L_AES_GCM_decrypt_aesni_cmp_tag_loop
        cmp	bl, 0
        sete	bl
        add	esp, 16
        xor	ecx, ecx
        jmp	L_AES_GCM_decrypt_aesni_cmp_tag_done
L_AES_GCM_decrypt_aesni_cmp_tag_16:
        movdqu	xmm5, OWORD PTR [esi]
        pcmpeqb	xmm4, xmm5
        pmovmskb	edx, xmm4
        ; %%edx == 0xFFFF then return 1 else => return 0
        xor	ebx, ebx
        cmp	edx, 65535
        sete	bl
L_AES_GCM_decrypt_aesni_cmp_tag_done:
        mov	DWORD PTR [edi], ebx
        add	esp, 176
        pop	ebp
        pop	edi
        pop	esi
        pop	ebx
        ret
AES_GCM_decrypt_aesni ENDP
_TEXT ENDS
IFDEF WOLFSSL_AESGCM_STREAM
_TEXT SEGMENT READONLY PARA
AES_GCM_init_aesni PROC
        push	ebx
        push	esi
        push	edi
        push	ebp
        sub	esp, 16
        mov	ebp, DWORD PTR [esp+36]
        mov	esi, DWORD PTR [esp+44]
        mov	edi, DWORD PTR [esp+60]
        pxor	xmm4, xmm4
        mov	edx, DWORD PTR [esp+48]
        cmp	edx, 12
        jne	L_AES_GCM_init_aesni_iv_not_12
        ; # Calculate values when IV is 12 bytes
        ; Set counter based on IV
        mov	ecx, 16777216
        pinsrd	xmm4, DWORD PTR [esi], 0
        pinsrd	xmm4, DWORD PTR [esi+4], 1
        pinsrd	xmm4, DWORD PTR [esi+8], 2
        pinsrd	xmm4, ecx, 3
        ; H = Encrypt X(=0) and T = Encrypt counter
        movdqa	xmm1, xmm4
        movdqa	xmm5, OWORD PTR [ebp]
        pxor	xmm1, xmm5
        movdqa	xmm7, OWORD PTR [ebp+16]
        aesenc	xmm5, xmm7
        aesenc	xmm1, xmm7
        movdqa	xmm7, OWORD PTR [ebp+32]
        aesenc	xmm5, xmm7
        aesenc	xmm1, xmm7
        movdqa	xmm7, OWORD PTR [ebp+48]
        aesenc	xmm5, xmm7
        aesenc	xmm1, xmm7
        movdqa	xmm7, OWORD PTR [ebp+64]
        aesenc	xmm5, xmm7
        aesenc	xmm1, xmm7
        movdqa	xmm7, OWORD PTR [ebp+80]
        aesenc	xmm5, xmm7
        aesenc	xmm1, xmm7
        movdqa	xmm7, OWORD PTR [ebp+96]
        aesenc	xmm5, xmm7
        aesenc	xmm1, xmm7
        movdqa	xmm7, OWORD PTR [ebp+112]
        aesenc	xmm5, xmm7
        aesenc	xmm1, xmm7
        movdqa	xmm7, OWORD PTR [ebp+128]
        aesenc	xmm5, xmm7
        aesenc	xmm1, xmm7
        movdqa	xmm7, OWORD PTR [ebp+144]
        aesenc	xmm5, xmm7
        aesenc	xmm1, xmm7
        cmp	DWORD PTR [esp+40], 11
        movdqa	xmm7, OWORD PTR [ebp+160]
        jl	L_AES_GCM_init_aesni_calc_iv_12_last
        aesenc	xmm5, xmm7
        aesenc	xmm1, xmm7
        movdqa	xmm7, OWORD PTR [ebp+176]
        aesenc	xmm5, xmm7
        aesenc	xmm1, xmm7
        cmp	DWORD PTR [esp+40], 13
        movdqa	xmm7, OWORD PTR [ebp+192]
        jl	L_AES_GCM_init_aesni_calc_iv_12_last
        aesenc	xmm5, xmm7
        aesenc	xmm1, xmm7
        movdqa	xmm7, OWORD PTR [ebp+208]
        aesenc	xmm5, xmm7
        aesenc	xmm1, xmm7
        movdqa	xmm7, OWORD PTR [ebp+224]
L_AES_GCM_init_aesni_calc_iv_12_last:
        aesenclast	xmm5, xmm7
        aesenclast	xmm1, xmm7
        pshufb	xmm5, OWORD PTR L_aes_gcm_bswap_mask
        movdqu	OWORD PTR [edi], xmm1
        jmp	L_AES_GCM_init_aesni_iv_done
L_AES_GCM_init_aesni_iv_not_12:
        ; Calculate values when IV is not 12 bytes
        ; H = Encrypt X(=0)
        movdqa	xmm5, OWORD PTR [ebp]
        aesenc	xmm5, [ebp+16]
        aesenc	xmm5, [ebp+32]
        aesenc	xmm5, [ebp+48]
        aesenc	xmm5, [ebp+64]
        aesenc	xmm5, [ebp+80]
        aesenc	xmm5, [ebp+96]
        aesenc	xmm5, [ebp+112]
        aesenc	xmm5, [ebp+128]
        aesenc	xmm5, [ebp+144]
        cmp	DWORD PTR [esp+40], 11
        movdqa	xmm1, OWORD PTR [ebp+160]
        jl	L_AES_GCM_init_aesni_calc_iv_1_aesenc_avx_last
        aesenc	xmm5, xmm1
        aesenc	xmm5, [ebp+176]
        cmp	DWORD PTR [esp+40], 13
        movdqa	xmm1, OWORD PTR [ebp+192]
        jl	L_AES_GCM_init_aesni_calc_iv_1_aesenc_avx_last
        aesenc	xmm5, xmm1
        aesenc	xmm5, [ebp+208]
        movdqa	xmm1, OWORD PTR [ebp+224]
L_AES_GCM_init_aesni_calc_iv_1_aesenc_avx_last:
        aesenclast	xmm5, xmm1
        pshufb	xmm5, OWORD PTR L_aes_gcm_bswap_mask
        ; Calc counter
        ; Initialization vector
        cmp	edx, 0
        mov	ecx, 0
        je	L_AES_GCM_init_aesni_calc_iv_done
        cmp	edx, 16
        jl	L_AES_GCM_init_aesni_calc_iv_lt16
        and	edx, 4294967280
L_AES_GCM_init_aesni_calc_iv_16_loop:
        movdqu	xmm0, OWORD PTR [esi+ecx]
        pshufb	xmm0, OWORD PTR L_aes_gcm_bswap_mask
        pxor	xmm4, xmm0
        pshufd	xmm1, xmm4, 78
        pshufd	xmm2, xmm5, 78
        movdqa	xmm3, xmm5
        movdqa	xmm0, xmm5
        pclmulqdq	xmm3, xmm4, 17
        pclmulqdq	xmm0, xmm4, 0
        pxor	xmm1, xmm4
        pxor	xmm2, xmm5
        pclmulqdq	xmm1, xmm2, 0
        pxor	xmm1, xmm0
        pxor	xmm1, xmm3
        movdqa	xmm2, xmm1
        movdqa	xmm7, xmm0
        movdqa	xmm4, xmm3
        pslldq	xmm2, 8
        psrldq	xmm1, 8
        pxor	xmm7, xmm2
        pxor	xmm4, xmm1
        movdqa	xmm0, xmm7
        movdqa	xmm1, xmm4
        psrld	xmm0, 31
        psrld	xmm1, 31
        pslld	xmm7, 1
        pslld	xmm4, 1
        movdqa	xmm2, xmm0
        pslldq	xmm0, 4
        psrldq	xmm2, 12
        pslldq	xmm1, 4
        por	xmm4, xmm2
        por	xmm7, xmm0
        por	xmm4, xmm1
        movdqa	xmm0, xmm7
        movdqa	xmm1, xmm7
        movdqa	xmm2, xmm7
        pslld	xmm0, 31
        pslld	xmm1, 30
        pslld	xmm2, 25
        pxor	xmm0, xmm1
        pxor	xmm0, xmm2
        movdqa	xmm1, xmm0
        psrldq	xmm1, 4
        pslldq	xmm0, 12
        pxor	xmm7, xmm0
        movdqa	xmm2, xmm7
        movdqa	xmm3, xmm7
        movdqa	xmm0, xmm7
        psrld	xmm2, 1
        psrld	xmm3, 2
        psrld	xmm0, 7
        pxor	xmm2, xmm3
        pxor	xmm2, xmm0
        pxor	xmm2, xmm1
        pxor	xmm2, xmm7
        pxor	xmm4, xmm2
        add	ecx, 16
        cmp	ecx, edx
        jl	L_AES_GCM_init_aesni_calc_iv_16_loop
        mov	edx, DWORD PTR [esp+48]
        cmp	ecx, edx
        je	L_AES_GCM_init_aesni_calc_iv_done
L_AES_GCM_init_aesni_calc_iv_lt16:
        sub	esp, 16
        pxor	xmm0, xmm0
        xor	ebx, ebx
        movdqu	OWORD PTR [esp], xmm0
L_AES_GCM_init_aesni_calc_iv_loop:
        movzx	eax, BYTE PTR [esi+ecx]
        mov	BYTE PTR [esp+ebx], al
        inc	ecx
        inc	ebx
        cmp	ecx, edx
        jl	L_AES_GCM_init_aesni_calc_iv_loop
        movdqu	xmm0, OWORD PTR [esp]
        add	esp, 16
        pshufb	xmm0, OWORD PTR L_aes_gcm_bswap_mask
        pxor	xmm4, xmm0
        pshufd	xmm1, xmm4, 78
        pshufd	xmm2, xmm5, 78
        movdqa	xmm3, xmm5
        movdqa	xmm0, xmm5
        pclmulqdq	xmm3, xmm4, 17
        pclmulqdq	xmm0, xmm4, 0
        pxor	xmm1, xmm4
        pxor	xmm2, xmm5
        pclmulqdq	xmm1, xmm2, 0
        pxor	xmm1, xmm0
        pxor	xmm1, xmm3
        movdqa	xmm2, xmm1
        movdqa	xmm7, xmm0
        movdqa	xmm4, xmm3
        pslldq	xmm2, 8
        psrldq	xmm1, 8
        pxor	xmm7, xmm2
        pxor	xmm4, xmm1
        movdqa	xmm0, xmm7
        movdqa	xmm1, xmm4
        psrld	xmm0, 31
        psrld	xmm1, 31
        pslld	xmm7, 1
        pslld	xmm4, 1
        movdqa	xmm2, xmm0
        pslldq	xmm0, 4
        psrldq	xmm2, 12
        pslldq	xmm1, 4
        por	xmm4, xmm2
        por	xmm7, xmm0
        por	xmm4, xmm1
        movdqa	xmm0, xmm7
        movdqa	xmm1, xmm7
        movdqa	xmm2, xmm7
        pslld	xmm0, 31
        pslld	xmm1, 30
        pslld	xmm2, 25
        pxor	xmm0, xmm1
        pxor	xmm0, xmm2
        movdqa	xmm1, xmm0
        psrldq	xmm1, 4
        pslldq	xmm0, 12
        pxor	xmm7, xmm0
        movdqa	xmm2, xmm7
        movdqa	xmm3, xmm7
        movdqa	xmm0, xmm7
        psrld	xmm2, 1
        psrld	xmm3, 2
        psrld	xmm0, 7
        pxor	xmm2, xmm3
        pxor	xmm2, xmm0
        pxor	xmm2, xmm1
        pxor	xmm2, xmm7
        pxor	xmm4, xmm2
L_AES_GCM_init_aesni_calc_iv_done:
        ; T = Encrypt counter
        pxor	xmm0, xmm0
        shl	edx, 3
        pinsrd	xmm0, edx, 0
        pxor	xmm4, xmm0
        pshufd	xmm1, xmm4, 78
        pshufd	xmm2, xmm5, 78
        movdqa	xmm3, xmm5
        movdqa	xmm0, xmm5
        pclmulqdq	xmm3, xmm4, 17
        pclmulqdq	xmm0, xmm4, 0
        pxor	xmm1, xmm4
        pxor	xmm2, xmm5
        pclmulqdq	xmm1, xmm2, 0
        pxor	xmm1, xmm0
        pxor	xmm1, xmm3
        movdqa	xmm2, xmm1
        movdqa	xmm7, xmm0
        movdqa	xmm4, xmm3
        pslldq	xmm2, 8
        psrldq	xmm1, 8
        pxor	xmm7, xmm2
        pxor	xmm4, xmm1
        movdqa	xmm0, xmm7
        movdqa	xmm1, xmm4
        psrld	xmm0, 31
        psrld	xmm1, 31
        pslld	xmm7, 1
        pslld	xmm4, 1
        movdqa	xmm2, xmm0
        pslldq	xmm0, 4
        psrldq	xmm2, 12
        pslldq	xmm1, 4
        por	xmm4, xmm2
        por	xmm7, xmm0
        por	xmm4, xmm1
        movdqa	xmm0, xmm7
        movdqa	xmm1, xmm7
        movdqa	xmm2, xmm7
        pslld	xmm0, 31
        pslld	xmm1, 30
        pslld	xmm2, 25
        pxor	xmm0, xmm1
        pxor	xmm0, xmm2
        movdqa	xmm1, xmm0
        psrldq	xmm1, 4
        pslldq	xmm0, 12
        pxor	xmm7, xmm0
        movdqa	xmm2, xmm7
        movdqa	xmm3, xmm7
        movdqa	xmm0, xmm7
        psrld	xmm2, 1
        psrld	xmm3, 2
        psrld	xmm0, 7
        pxor	xmm2, xmm3
        pxor	xmm2, xmm0
        pxor	xmm2, xmm1
        pxor	xmm2, xmm7
        pxor	xmm4, xmm2
        pshufb	xmm4, OWORD PTR L_aes_gcm_bswap_mask
        ;   Encrypt counter
        movdqa	xmm0, OWORD PTR [ebp]
        pxor	xmm0, xmm4
        aesenc	xmm0, [ebp+16]
        aesenc	xmm0, [ebp+32]
        aesenc	xmm0, [ebp+48]
        aesenc	xmm0, [ebp+64]
        aesenc	xmm0, [ebp+80]
        aesenc	xmm0, [ebp+96]
        aesenc	xmm0, [ebp+112]
        aesenc	xmm0, [ebp+128]
        aesenc	xmm0, [ebp+144]
        cmp	DWORD PTR [esp+40], 11
        movdqa	xmm1, OWORD PTR [ebp+160]
        jl	L_AES_GCM_init_aesni_calc_iv_2_aesenc_avx_last
        aesenc	xmm0, xmm1
        aesenc	xmm0, [ebp+176]
        cmp	DWORD PTR [esp+40], 13
        movdqa	xmm1, OWORD PTR [ebp+192]
        jl	L_AES_GCM_init_aesni_calc_iv_2_aesenc_avx_last
        aesenc	xmm0, xmm1
        aesenc	xmm0, [ebp+208]
        movdqa	xmm1, OWORD PTR [ebp+224]
L_AES_GCM_init_aesni_calc_iv_2_aesenc_avx_last:
        aesenclast	xmm0, xmm1
        movdqu	OWORD PTR [edi], xmm0
L_AES_GCM_init_aesni_iv_done:
        mov	ebp, DWORD PTR [esp+52]
        mov	edi, DWORD PTR [esp+56]
        pshufb	xmm4, OWORD PTR L_aes_gcm_bswap_epi64
        paddd	xmm4, OWORD PTR L_aes_gcm_one
        movdqa	OWORD PTR [ebp], xmm5
        movdqa	OWORD PTR [edi], xmm4
        add	esp, 16
        pop	ebp
        pop	edi
        pop	esi
        pop	ebx
        ret
AES_GCM_init_aesni ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_GCM_aad_update_aesni PROC
        push	esi
        push	edi
        mov	esi, DWORD PTR [esp+12]
        mov	edx, DWORD PTR [esp+16]
        mov	edi, DWORD PTR [esp+20]
        mov	eax, DWORD PTR [esp+24]
        movdqa	xmm5, OWORD PTR [edi]
        movdqa	xmm6, OWORD PTR [eax]
        xor	ecx, ecx
L_AES_GCM_aad_update_aesni_16_loop:
        movdqu	xmm0, OWORD PTR [esi+ecx]
        pshufb	xmm0, OWORD PTR L_aes_gcm_bswap_mask
        pxor	xmm5, xmm0
        pshufd	xmm1, xmm5, 78
        pshufd	xmm2, xmm6, 78
        movdqa	xmm3, xmm6
        movdqa	xmm0, xmm6
        pclmulqdq	xmm3, xmm5, 17
        pclmulqdq	xmm0, xmm5, 0
        pxor	xmm1, xmm5
        pxor	xmm2, xmm6
        pclmulqdq	xmm1, xmm2, 0
        pxor	xmm1, xmm0
        pxor	xmm1, xmm3
        movdqa	xmm2, xmm1
        movdqa	xmm4, xmm0
        movdqa	xmm5, xmm3
        pslldq	xmm2, 8
        psrldq	xmm1, 8
        pxor	xmm4, xmm2
        pxor	xmm5, xmm1
        movdqa	xmm0, xmm4
        movdqa	xmm1, xmm5
        psrld	xmm0, 31
        psrld	xmm1, 31
        pslld	xmm4, 1
        pslld	xmm5, 1
        movdqa	xmm2, xmm0
        pslldq	xmm0, 4
        psrldq	xmm2, 12
        pslldq	xmm1, 4
        por	xmm5, xmm2
        por	xmm4, xmm0
        por	xmm5, xmm1
        movdqa	xmm0, xmm4
        movdqa	xmm1, xmm4
        movdqa	xmm2, xmm4
        pslld	xmm0, 31
        pslld	xmm1, 30
        pslld	xmm2, 25
        pxor	xmm0, xmm1
        pxor	xmm0, xmm2
        movdqa	xmm1, xmm0
        psrldq	xmm1, 4
        pslldq	xmm0, 12
        pxor	xmm4, xmm0
        movdqa	xmm2, xmm4
        movdqa	xmm3, xmm4
        movdqa	xmm0, xmm4
        psrld	xmm2, 1
        psrld	xmm3, 2
        psrld	xmm0, 7
        pxor	xmm2, xmm3
        pxor	xmm2, xmm0
        pxor	xmm2, xmm1
        pxor	xmm2, xmm4
        pxor	xmm5, xmm2
        add	ecx, 16
        cmp	ecx, edx
        jl	L_AES_GCM_aad_update_aesni_16_loop
        movdqa	OWORD PTR [edi], xmm5
        pop	edi
        pop	esi
        ret
AES_GCM_aad_update_aesni ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_GCM_encrypt_block_aesni PROC
        push	esi
        push	edi
        mov	ecx, DWORD PTR [esp+12]
        mov	eax, DWORD PTR [esp+16]
        mov	edi, DWORD PTR [esp+20]
        mov	esi, DWORD PTR [esp+24]
        mov	edx, DWORD PTR [esp+28]
        movdqu	xmm0, OWORD PTR [edx]
        movdqa	xmm1, xmm0
        pshufb	xmm0, OWORD PTR L_aes_gcm_bswap_epi64
        paddd	xmm1, OWORD PTR L_aes_gcm_one
        pxor	xmm0, [ecx]
        movdqu	OWORD PTR [edx], xmm1
        aesenc	xmm0, [ecx+16]
        aesenc	xmm0, [ecx+32]
        aesenc	xmm0, [ecx+48]
        aesenc	xmm0, [ecx+64]
        aesenc	xmm0, [ecx+80]
        aesenc	xmm0, [ecx+96]
        aesenc	xmm0, [ecx+112]
        aesenc	xmm0, [ecx+128]
        aesenc	xmm0, [ecx+144]
        cmp	eax, 11
        movdqa	xmm1, OWORD PTR [ecx+160]
        jl	L_AES_GCM_encrypt_block_aesni_aesenc_block_aesenc_avx_last
        aesenc	xmm0, xmm1
        aesenc	xmm0, [ecx+176]
        cmp	eax, 13
        movdqa	xmm1, OWORD PTR [ecx+192]
        jl	L_AES_GCM_encrypt_block_aesni_aesenc_block_aesenc_avx_last
        aesenc	xmm0, xmm1
        aesenc	xmm0, [ecx+208]
        movdqa	xmm1, OWORD PTR [ecx+224]
L_AES_GCM_encrypt_block_aesni_aesenc_block_aesenc_avx_last:
        aesenclast	xmm0, xmm1
        movdqu	xmm1, OWORD PTR [esi]
        pxor	xmm0, xmm1
        movdqu	OWORD PTR [edi], xmm0
        pshufb	xmm0, OWORD PTR L_aes_gcm_bswap_mask
        pop	edi
        pop	esi
        ret
AES_GCM_encrypt_block_aesni ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_GCM_ghash_block_aesni PROC
        mov	edx, DWORD PTR [esp+4]
        mov	eax, DWORD PTR [esp+8]
        mov	ecx, DWORD PTR [esp+12]
        movdqa	xmm4, OWORD PTR [eax]
        movdqa	xmm5, OWORD PTR [ecx]
        movdqu	xmm0, OWORD PTR [edx]
        pshufb	xmm0, OWORD PTR L_aes_gcm_bswap_mask
        pxor	xmm4, xmm0
        pshufd	xmm1, xmm4, 78
        pshufd	xmm2, xmm5, 78
        movdqa	xmm3, xmm5
        movdqa	xmm0, xmm5
        pclmulqdq	xmm3, xmm4, 17
        pclmulqdq	xmm0, xmm4, 0
        pxor	xmm1, xmm4
        pxor	xmm2, xmm5
        pclmulqdq	xmm1, xmm2, 0
        pxor	xmm1, xmm0
        pxor	xmm1, xmm3
        movdqa	xmm2, xmm1
        movdqa	xmm6, xmm0
        movdqa	xmm4, xmm3
        pslldq	xmm2, 8
        psrldq	xmm1, 8
        pxor	xmm6, xmm2
        pxor	xmm4, xmm1
        movdqa	xmm0, xmm6
        movdqa	xmm1, xmm4
        psrld	xmm0, 31
        psrld	xmm1, 31
        pslld	xmm6, 1
        pslld	xmm4, 1
        movdqa	xmm2, xmm0
        pslldq	xmm0, 4
        psrldq	xmm2, 12
        pslldq	xmm1, 4
        por	xmm4, xmm2
        por	xmm6, xmm0
        por	xmm4, xmm1
        movdqa	xmm0, xmm6
        movdqa	xmm1, xmm6
        movdqa	xmm2, xmm6
        pslld	xmm0, 31
        pslld	xmm1, 30
        pslld	xmm2, 25
        pxor	xmm0, xmm1
        pxor	xmm0, xmm2
        movdqa	xmm1, xmm0
        psrldq	xmm1, 4
        pslldq	xmm0, 12
        pxor	xmm6, xmm0
        movdqa	xmm2, xmm6
        movdqa	xmm3, xmm6
        movdqa	xmm0, xmm6
        psrld	xmm2, 1
        psrld	xmm3, 2
        psrld	xmm0, 7
        pxor	xmm2, xmm3
        pxor	xmm2, xmm0
        pxor	xmm2, xmm1
        pxor	xmm2, xmm6
        pxor	xmm4, xmm2
        movdqa	OWORD PTR [eax], xmm4
        ret
AES_GCM_ghash_block_aesni ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_GCM_encrypt_update_aesni PROC
        push	ebx
        push	esi
        push	edi
        push	ebp
        sub	esp, 96
        mov	esi, DWORD PTR [esp+144]
        movdqa	xmm4, OWORD PTR [esi]
        movdqu	OWORD PTR [esp+64], xmm4
        mov	esi, DWORD PTR [esp+136]
        mov	ebp, DWORD PTR [esp+140]
        movdqa	xmm6, OWORD PTR [esi]
        movdqa	xmm5, OWORD PTR [ebp]
        movdqu	OWORD PTR [esp+80], xmm6
        mov	ebp, DWORD PTR [esp+116]
        mov	edi, DWORD PTR [esp+124]
        mov	esi, DWORD PTR [esp+128]
        movdqa	xmm1, xmm5
        movdqa	xmm0, xmm5
        psrlq	xmm1, 63
        psllq	xmm0, 1
        pslldq	xmm1, 8
        por	xmm0, xmm1
        pshufd	xmm5, xmm5, 255
        psrad	xmm5, 31
        pand	xmm5, OWORD PTR L_aes_gcm_mod2_128
        pxor	xmm5, xmm0
        xor	ebx, ebx
        cmp	DWORD PTR [esp+132], 64
        mov	eax, DWORD PTR [esp+132]
        jl	L_AES_GCM_encrypt_update_aesni_done_64
        and	eax, 4294967232
        movdqa	xmm2, xmm6
        ; H ^ 1
        movdqu	OWORD PTR [esp], xmm5
        ; H ^ 2
        pshufd	xmm1, xmm5, 78
        pshufd	xmm2, xmm5, 78
        movdqa	xmm3, xmm5
        movdqa	xmm0, xmm5
        pclmulqdq	xmm3, xmm5, 17
        pclmulqdq	xmm0, xmm5, 0
        pxor	xmm1, xmm5
        pxor	xmm2, xmm5
        pclmulqdq	xmm1, xmm2, 0
        pxor	xmm1, xmm0
        pxor	xmm1, xmm3
        movdqa	xmm2, xmm1
        movdqa	xmm4, xmm3
        pslldq	xmm2, 8
        psrldq	xmm1, 8
        pxor	xmm0, xmm2
        pxor	xmm4, xmm1
        movdqa	xmm1, xmm0
        movdqa	xmm2, xmm0
        movdqa	xmm3, xmm0
        pslld	xmm1, 31
        pslld	xmm2, 30
        pslld	xmm3, 25
        pxor	xmm1, xmm2
        pxor	xmm1, xmm3
        movdqa	xmm3, xmm1
        psrldq	xmm3, 4
        pslldq	xmm1, 12
        pxor	xmm0, xmm1
        movdqa	xmm1, xmm0
        movdqa	xmm2, xmm0
        psrld	xmm1, 1
        psrld	xmm2, 2
        pxor	xmm1, xmm2
        pxor	xmm1, xmm0
        psrld	xmm0, 7
        pxor	xmm1, xmm3
        pxor	xmm1, xmm0
        pxor	xmm4, xmm1
        movdqu	OWORD PTR [esp+16], xmm4
        ; H ^ 3
        pshufd	xmm1, xmm5, 78
        pshufd	xmm2, xmm4, 78
        movdqa	xmm3, xmm4
        movdqa	xmm0, xmm4
        pclmulqdq	xmm3, xmm5, 17
        pclmulqdq	xmm0, xmm5, 0
        pxor	xmm1, xmm5
        pxor	xmm2, xmm4
        pclmulqdq	xmm1, xmm2, 0
        pxor	xmm1, xmm0
        pxor	xmm1, xmm3
        movdqa	xmm2, xmm1
        movdqa	xmm7, xmm3
        pslldq	xmm2, 8
        psrldq	xmm1, 8
        pxor	xmm0, xmm2
        pxor	xmm7, xmm1
        movdqa	xmm1, xmm0
        movdqa	xmm2, xmm0
        movdqa	xmm3, xmm0
        pslld	xmm1, 31
        pslld	xmm2, 30
        pslld	xmm3, 25
        pxor	xmm1, xmm2
        pxor	xmm1, xmm3
        movdqa	xmm3, xmm1
        psrldq	xmm3, 4
        pslldq	xmm1, 12
        pxor	xmm0, xmm1
        movdqa	xmm1, xmm0
        movdqa	xmm2, xmm0
        psrld	xmm1, 1
        psrld	xmm2, 2
        pxor	xmm1, xmm2
        pxor	xmm1, xmm0
        psrld	xmm0, 7
        pxor	xmm1, xmm3
        pxor	xmm1, xmm0
        pxor	xmm7, xmm1
        movdqu	OWORD PTR [esp+32], xmm7
        ; H ^ 4
        pshufd	xmm1, xmm4, 78
        pshufd	xmm2, xmm4, 78
        movdqa	xmm3, xmm4
        movdqa	xmm0, xmm4
        pclmulqdq	xmm3, xmm4, 17
        pclmulqdq	xmm0, xmm4, 0
        pxor	xmm1, xmm4
        pxor	xmm2, xmm4
        pclmulqdq	xmm1, xmm2, 0
        pxor	xmm1, xmm0
        pxor	xmm1, xmm3
        movdqa	xmm2, xmm1
        movdqa	xmm7, xmm3
        pslldq	xmm2, 8
        psrldq	xmm1, 8
        pxor	xmm0, xmm2
        pxor	xmm7, xmm1
        movdqa	xmm1, xmm0
        movdqa	xmm2, xmm0
        movdqa	xmm3, xmm0
        pslld	xmm1, 31
        pslld	xmm2, 30
        pslld	xmm3, 25
        pxor	xmm1, xmm2
        pxor	xmm1, xmm3
        movdqa	xmm3, xmm1
        psrldq	xmm3, 4
        pslldq	xmm1, 12
        pxor	xmm0, xmm1
        movdqa	xmm1, xmm0
        movdqa	xmm2, xmm0
        psrld	xmm1, 1
        psrld	xmm2, 2
        pxor	xmm1, xmm2
        pxor	xmm1, xmm0
        psrld	xmm0, 7
        pxor	xmm1, xmm3
        pxor	xmm1, xmm0
        pxor	xmm7, xmm1
        movdqu	OWORD PTR [esp+48], xmm7
        ; First 64 bytes of input
        ; Encrypt 64 bytes of counter
        movdqu	xmm0, OWORD PTR [esp+64]
        movdqu	xmm7, xmm0
        paddd	xmm7, OWORD PTR L_aes_gcm_four
        movdqu	OWORD PTR [esp+64], xmm7
        movdqa	xmm7, OWORD PTR L_aes_gcm_bswap_epi64
        movdqa	xmm1, xmm0
        movdqa	xmm2, xmm0
        movdqa	xmm3, xmm0
        pshufb	xmm0, xmm7
        paddd	xmm1, OWORD PTR L_aes_gcm_one
        pshufb	xmm1, xmm7
        paddd	xmm2, OWORD PTR L_aes_gcm_two
        pshufb	xmm2, xmm7
        paddd	xmm3, OWORD PTR L_aes_gcm_three
        pshufb	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp]
        pxor	xmm0, xmm7
        pxor	xmm1, xmm7
        pxor	xmm2, xmm7
        pxor	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+16]
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+32]
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+48]
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+64]
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+80]
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+96]
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+112]
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+128]
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+144]
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        cmp	DWORD PTR [esp+120], 11
        movdqa	xmm7, OWORD PTR [ebp+160]
        jl	L_AES_GCM_encrypt_update_aesni_enc_done
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+176]
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        cmp	DWORD PTR [esp+120], 13
        movdqa	xmm7, OWORD PTR [ebp+192]
        jl	L_AES_GCM_encrypt_update_aesni_enc_done
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+208]
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+224]
L_AES_GCM_encrypt_update_aesni_enc_done:
        aesenclast	xmm0, xmm7
        aesenclast	xmm1, xmm7
        movdqu	xmm4, OWORD PTR [esi]
        movdqu	xmm5, OWORD PTR [esi+16]
        pxor	xmm0, xmm4
        pxor	xmm1, xmm5
        movdqu	OWORD PTR [edi], xmm0
        movdqu	OWORD PTR [edi+16], xmm1
        aesenclast	xmm2, xmm7
        aesenclast	xmm3, xmm7
        movdqu	xmm4, OWORD PTR [esi+32]
        movdqu	xmm5, OWORD PTR [esi+48]
        pxor	xmm2, xmm4
        pxor	xmm3, xmm5
        movdqu	OWORD PTR [edi+32], xmm2
        movdqu	OWORD PTR [edi+48], xmm3
        cmp	eax, 64
        mov	ebx, 64
        mov	ecx, esi
        mov	edx, edi
        jle	L_AES_GCM_encrypt_update_aesni_end_64
        ; More 64 bytes of input
L_AES_GCM_encrypt_update_aesni_ghash_64:
        lea	ecx, DWORD PTR [esi+ebx]
        lea	edx, DWORD PTR [edi+ebx]
        ; Encrypt 64 bytes of counter
        movdqu	xmm0, OWORD PTR [esp+64]
        movdqu	xmm7, xmm0
        paddd	xmm7, OWORD PTR L_aes_gcm_four
        movdqu	OWORD PTR [esp+64], xmm7
        movdqa	xmm7, OWORD PTR L_aes_gcm_bswap_epi64
        movdqa	xmm1, xmm0
        movdqa	xmm2, xmm0
        movdqa	xmm3, xmm0
        pshufb	xmm0, xmm7
        paddd	xmm1, OWORD PTR L_aes_gcm_one
        pshufb	xmm1, xmm7
        paddd	xmm2, OWORD PTR L_aes_gcm_two
        pshufb	xmm2, xmm7
        paddd	xmm3, OWORD PTR L_aes_gcm_three
        pshufb	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp]
        pxor	xmm0, xmm7
        pxor	xmm1, xmm7
        pxor	xmm2, xmm7
        pxor	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+16]
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+32]
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+48]
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+64]
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+80]
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+96]
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+112]
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+128]
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+144]
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        cmp	DWORD PTR [esp+120], 11
        movdqa	xmm7, OWORD PTR [ebp+160]
        jl	L_AES_GCM_encrypt_update_aesni_aesenc_64_ghash_avx_done
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+176]
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        cmp	DWORD PTR [esp+120], 13
        movdqa	xmm7, OWORD PTR [ebp+192]
        jl	L_AES_GCM_encrypt_update_aesni_aesenc_64_ghash_avx_done
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+208]
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+224]
L_AES_GCM_encrypt_update_aesni_aesenc_64_ghash_avx_done:
        aesenclast	xmm0, xmm7
        aesenclast	xmm1, xmm7
        movdqu	xmm4, OWORD PTR [ecx]
        movdqu	xmm5, OWORD PTR [ecx+16]
        pxor	xmm0, xmm4
        pxor	xmm1, xmm5
        movdqu	OWORD PTR [edx], xmm0
        movdqu	OWORD PTR [edx+16], xmm1
        aesenclast	xmm2, xmm7
        aesenclast	xmm3, xmm7
        movdqu	xmm4, OWORD PTR [ecx+32]
        movdqu	xmm5, OWORD PTR [ecx+48]
        pxor	xmm2, xmm4
        pxor	xmm3, xmm5
        movdqu	OWORD PTR [edx+32], xmm2
        movdqu	OWORD PTR [edx+48], xmm3
        ; ghash encrypted counter
        movdqu	xmm2, OWORD PTR [esp+80]
        movdqu	xmm7, OWORD PTR [esp+48]
        movdqu	xmm0, OWORD PTR [edx+-64]
        pshufb	xmm0, OWORD PTR L_aes_gcm_bswap_mask
        pxor	xmm0, xmm2
        pshufd	xmm1, xmm7, 78
        pshufd	xmm5, xmm0, 78
        pxor	xmm1, xmm7
        pxor	xmm5, xmm0
        movdqa	xmm3, xmm0
        pclmulqdq	xmm3, xmm7, 17
        movdqa	xmm2, xmm0
        pclmulqdq	xmm2, xmm7, 0
        pclmulqdq	xmm1, xmm5, 0
        pxor	xmm1, xmm2
        pxor	xmm1, xmm3
        movdqu	xmm7, OWORD PTR [esp+32]
        movdqu	xmm0, OWORD PTR [edx+-48]
        pshufd	xmm4, xmm7, 78
        pshufb	xmm0, OWORD PTR L_aes_gcm_bswap_mask
        pxor	xmm4, xmm7
        pshufd	xmm5, xmm0, 78
        pxor	xmm5, xmm0
        movdqa	xmm6, xmm0
        pclmulqdq	xmm6, xmm7, 17
        pclmulqdq	xmm7, xmm0, 0
        pclmulqdq	xmm4, xmm5, 0
        pxor	xmm1, xmm7
        pxor	xmm2, xmm7
        pxor	xmm1, xmm6
        pxor	xmm3, xmm6
        pxor	xmm1, xmm4
        movdqu	xmm7, OWORD PTR [esp+16]
        movdqu	xmm0, OWORD PTR [edx+-32]
        pshufd	xmm4, xmm7, 78
        pshufb	xmm0, OWORD PTR L_aes_gcm_bswap_mask
        pxor	xmm4, xmm7
        pshufd	xmm5, xmm0, 78
        pxor	xmm5, xmm0
        movdqa	xmm6, xmm0
        pclmulqdq	xmm6, xmm7, 17
        pclmulqdq	xmm7, xmm0, 0
        pclmulqdq	xmm4, xmm5, 0
        pxor	xmm1, xmm7
        pxor	xmm2, xmm7
        pxor	xmm1, xmm6
        pxor	xmm3, xmm6
        pxor	xmm1, xmm4
        movdqu	xmm7, OWORD PTR [esp]
        movdqu	xmm0, OWORD PTR [edx+-16]
        pshufd	xmm4, xmm7, 78
        pshufb	xmm0, OWORD PTR L_aes_gcm_bswap_mask
        pxor	xmm4, xmm7
        pshufd	xmm5, xmm0, 78
        pxor	xmm5, xmm0
        movdqa	xmm6, xmm0
        pclmulqdq	xmm6, xmm7, 17
        pclmulqdq	xmm7, xmm0, 0
        pclmulqdq	xmm4, xmm5, 0
        pxor	xmm1, xmm7
        pxor	xmm2, xmm7
        pxor	xmm1, xmm6
        pxor	xmm3, xmm6
        pxor	xmm1, xmm4
        movdqa	xmm5, xmm1
        psrldq	xmm1, 8
        pslldq	xmm5, 8
        pxor	xmm2, xmm5
        pxor	xmm3, xmm1
        movdqa	xmm7, xmm2
        movdqa	xmm4, xmm2
        movdqa	xmm5, xmm2
        pslld	xmm7, 31
        pslld	xmm4, 30
        pslld	xmm5, 25
        pxor	xmm7, xmm4
        pxor	xmm7, xmm5
        movdqa	xmm4, xmm7
        pslldq	xmm7, 12
        psrldq	xmm4, 4
        pxor	xmm2, xmm7
        movdqa	xmm5, xmm2
        movdqa	xmm1, xmm2
        movdqa	xmm0, xmm2
        psrld	xmm5, 1
        psrld	xmm1, 2
        psrld	xmm0, 7
        pxor	xmm5, xmm1
        pxor	xmm5, xmm0
        pxor	xmm5, xmm4
        pxor	xmm2, xmm5
        pxor	xmm2, xmm3
        movdqu	OWORD PTR [esp+80], xmm2
        add	ebx, 64
        cmp	ebx, eax
        jl	L_AES_GCM_encrypt_update_aesni_ghash_64
L_AES_GCM_encrypt_update_aesni_end_64:
        movdqu	xmm6, OWORD PTR [esp+80]
        ; Block 1
        movdqa	xmm0, OWORD PTR L_aes_gcm_bswap_mask
        movdqu	xmm5, OWORD PTR [edx]
        pshufb	xmm5, xmm0
        movdqu	xmm7, OWORD PTR [esp+48]
        pxor	xmm5, xmm6
        pshufd	xmm1, xmm5, 78
        pshufd	xmm2, xmm7, 78
        movdqa	xmm3, xmm7
        movdqa	xmm0, xmm7
        pclmulqdq	xmm3, xmm5, 17
        pclmulqdq	xmm0, xmm5, 0
        pxor	xmm1, xmm5
        pxor	xmm2, xmm7
        pclmulqdq	xmm1, xmm2, 0
        pxor	xmm1, xmm0
        pxor	xmm1, xmm3
        movdqa	xmm2, xmm1
        movdqa	xmm4, xmm0
        movdqa	xmm6, xmm3
        pslldq	xmm2, 8
        psrldq	xmm1, 8
        pxor	xmm4, xmm2
        pxor	xmm6, xmm1
        ; Block 2
        movdqa	xmm0, OWORD PTR L_aes_gcm_bswap_mask
        movdqu	xmm5, OWORD PTR [edx+16]
        pshufb	xmm5, xmm0
        movdqu	xmm7, OWORD PTR [esp+32]
        pshufd	xmm1, xmm5, 78
        pshufd	xmm2, xmm7, 78
        movdqa	xmm3, xmm7
        movdqa	xmm0, xmm7
        pclmulqdq	xmm3, xmm5, 17
        pclmulqdq	xmm0, xmm5, 0
        pxor	xmm1, xmm5
        pxor	xmm2, xmm7
        pclmulqdq	xmm1, xmm2, 0
        pxor	xmm1, xmm0
        pxor	xmm1, xmm3
        movdqa	xmm2, xmm1
        pxor	xmm4, xmm0
        pxor	xmm6, xmm3
        pslldq	xmm2, 8
        psrldq	xmm1, 8
        pxor	xmm4, xmm2
        pxor	xmm6, xmm1
        ; Block 3
        movdqa	xmm0, OWORD PTR L_aes_gcm_bswap_mask
        movdqu	xmm5, OWORD PTR [edx+32]
        pshufb	xmm5, xmm0
        movdqu	xmm7, OWORD PTR [esp+16]
        pshufd	xmm1, xmm5, 78
        pshufd	xmm2, xmm7, 78
        movdqa	xmm3, xmm7
        movdqa	xmm0, xmm7
        pclmulqdq	xmm3, xmm5, 17
        pclmulqdq	xmm0, xmm5, 0
        pxor	xmm1, xmm5
        pxor	xmm2, xmm7
        pclmulqdq	xmm1, xmm2, 0
        pxor	xmm1, xmm0
        pxor	xmm1, xmm3
        movdqa	xmm2, xmm1
        pxor	xmm4, xmm0
        pxor	xmm6, xmm3
        pslldq	xmm2, 8
        psrldq	xmm1, 8
        pxor	xmm4, xmm2
        pxor	xmm6, xmm1
        ; Block 4
        movdqa	xmm0, OWORD PTR L_aes_gcm_bswap_mask
        movdqu	xmm5, OWORD PTR [edx+48]
        pshufb	xmm5, xmm0
        movdqu	xmm7, OWORD PTR [esp]
        pshufd	xmm1, xmm5, 78
        pshufd	xmm2, xmm7, 78
        movdqa	xmm3, xmm7
        movdqa	xmm0, xmm7
        pclmulqdq	xmm3, xmm5, 17
        pclmulqdq	xmm0, xmm5, 0
        pxor	xmm1, xmm5
        pxor	xmm2, xmm7
        pclmulqdq	xmm1, xmm2, 0
        pxor	xmm1, xmm0
        pxor	xmm1, xmm3
        movdqa	xmm2, xmm1
        pxor	xmm4, xmm0
        pxor	xmm6, xmm3
        pslldq	xmm2, 8
        psrldq	xmm1, 8
        pxor	xmm4, xmm2
        pxor	xmm6, xmm1
        movdqa	xmm0, xmm4
        movdqa	xmm1, xmm4
        movdqa	xmm2, xmm4
        pslld	xmm0, 31
        pslld	xmm1, 30
        pslld	xmm2, 25
        pxor	xmm0, xmm1
        pxor	xmm0, xmm2
        movdqa	xmm1, xmm0
        psrldq	xmm1, 4
        pslldq	xmm0, 12
        pxor	xmm4, xmm0
        movdqa	xmm2, xmm4
        movdqa	xmm3, xmm4
        movdqa	xmm0, xmm4
        psrld	xmm2, 1
        psrld	xmm3, 2
        psrld	xmm0, 7
        pxor	xmm2, xmm3
        pxor	xmm2, xmm0
        pxor	xmm2, xmm1
        pxor	xmm2, xmm4
        pxor	xmm6, xmm2
        movdqu	xmm5, OWORD PTR [esp]
L_AES_GCM_encrypt_update_aesni_done_64:
        mov	edx, DWORD PTR [esp+132]
        cmp	ebx, edx
        jge	L_AES_GCM_encrypt_update_aesni_done_enc
        mov	eax, DWORD PTR [esp+132]
        and	eax, 4294967280
        cmp	ebx, eax
        jge	L_AES_GCM_encrypt_update_aesni_last_block_done
        lea	ecx, DWORD PTR [esi+ebx]
        lea	edx, DWORD PTR [edi+ebx]
        movdqu	xmm0, OWORD PTR [esp+64]
        movdqa	xmm1, xmm0
        pshufb	xmm0, OWORD PTR L_aes_gcm_bswap_epi64
        paddd	xmm1, OWORD PTR L_aes_gcm_one
        pxor	xmm0, [ebp]
        movdqu	OWORD PTR [esp+64], xmm1
        aesenc	xmm0, [ebp+16]
        aesenc	xmm0, [ebp+32]
        aesenc	xmm0, [ebp+48]
        aesenc	xmm0, [ebp+64]
        aesenc	xmm0, [ebp+80]
        aesenc	xmm0, [ebp+96]
        aesenc	xmm0, [ebp+112]
        aesenc	xmm0, [ebp+128]
        aesenc	xmm0, [ebp+144]
        cmp	DWORD PTR [esp+120], 11
        movdqa	xmm1, OWORD PTR [ebp+160]
        jl	L_AES_GCM_encrypt_update_aesni_aesenc_block_aesenc_avx_last
        aesenc	xmm0, xmm1
        aesenc	xmm0, [ebp+176]
        cmp	DWORD PTR [esp+120], 13
        movdqa	xmm1, OWORD PTR [ebp+192]
        jl	L_AES_GCM_encrypt_update_aesni_aesenc_block_aesenc_avx_last
        aesenc	xmm0, xmm1
        aesenc	xmm0, [ebp+208]
        movdqa	xmm1, OWORD PTR [ebp+224]
L_AES_GCM_encrypt_update_aesni_aesenc_block_aesenc_avx_last:
        aesenclast	xmm0, xmm1
        movdqu	xmm1, OWORD PTR [ecx]
        pxor	xmm0, xmm1
        movdqu	OWORD PTR [edx], xmm0
        pshufb	xmm0, OWORD PTR L_aes_gcm_bswap_mask
        pxor	xmm6, xmm0
        add	ebx, 16
        cmp	ebx, eax
        jge	L_AES_GCM_encrypt_update_aesni_last_block_ghash
L_AES_GCM_encrypt_update_aesni_last_block_start:
        lea	ecx, DWORD PTR [esi+ebx]
        lea	edx, DWORD PTR [edi+ebx]
        movdqu	xmm0, OWORD PTR [esp+64]
        movdqa	xmm1, xmm0
        pshufb	xmm0, OWORD PTR L_aes_gcm_bswap_epi64
        paddd	xmm1, OWORD PTR L_aes_gcm_one
        pxor	xmm0, [ebp]
        movdqu	OWORD PTR [esp+64], xmm1
        movdqu	xmm4, xmm6
        pclmulqdq	xmm4, xmm5, 16
        aesenc	xmm0, [ebp+16]
        aesenc	xmm0, [ebp+32]
        movdqu	xmm7, xmm6
        pclmulqdq	xmm7, xmm5, 1
        aesenc	xmm0, [ebp+48]
        aesenc	xmm0, [ebp+64]
        aesenc	xmm0, [ebp+80]
        movdqu	xmm1, xmm6
        pclmulqdq	xmm1, xmm5, 17
        aesenc	xmm0, [ebp+96]
        pxor	xmm4, xmm7
        movdqa	xmm2, xmm4
        psrldq	xmm4, 8
        pslldq	xmm2, 8
        aesenc	xmm0, [ebp+112]
        movdqu	xmm7, xmm6
        pclmulqdq	xmm7, xmm5, 0
        pxor	xmm2, xmm7
        pxor	xmm1, xmm4
        movdqa	xmm3, OWORD PTR L_aes_gcm_mod2_128
        movdqa	xmm7, xmm2
        pclmulqdq	xmm7, xmm3, 16
        aesenc	xmm0, [ebp+128]
        pshufd	xmm4, xmm2, 78
        pxor	xmm4, xmm7
        movdqa	xmm7, xmm4
        pclmulqdq	xmm7, xmm3, 16
        aesenc	xmm0, [ebp+144]
        pshufd	xmm6, xmm4, 78
        pxor	xmm6, xmm7
        pxor	xmm6, xmm1
        cmp	DWORD PTR [esp+120], 11
        movdqa	xmm1, OWORD PTR [ebp+160]
        jl	L_AES_GCM_encrypt_update_aesni_aesenc_gfmul_last
        aesenc	xmm0, xmm1
        aesenc	xmm0, [ebp+176]
        cmp	DWORD PTR [esp+120], 13
        movdqa	xmm1, OWORD PTR [ebp+192]
        jl	L_AES_GCM_encrypt_update_aesni_aesenc_gfmul_last
        aesenc	xmm0, xmm1
        aesenc	xmm0, [ebp+208]
        movdqa	xmm1, OWORD PTR [ebp+224]
L_AES_GCM_encrypt_update_aesni_aesenc_gfmul_last:
        aesenclast	xmm0, xmm1
        movdqu	xmm1, OWORD PTR [ecx]
        pxor	xmm0, xmm1
        movdqu	OWORD PTR [edx], xmm0
        pshufb	xmm0, OWORD PTR L_aes_gcm_bswap_mask
        pxor	xmm6, xmm0
        add	ebx, 16
        cmp	ebx, eax
        jl	L_AES_GCM_encrypt_update_aesni_last_block_start
L_AES_GCM_encrypt_update_aesni_last_block_ghash:
        pshufd	xmm1, xmm5, 78
        pshufd	xmm2, xmm6, 78
        movdqa	xmm3, xmm6
        movdqa	xmm0, xmm6
        pclmulqdq	xmm3, xmm5, 17
        pclmulqdq	xmm0, xmm5, 0
        pxor	xmm1, xmm5
        pxor	xmm2, xmm6
        pclmulqdq	xmm1, xmm2, 0
        pxor	xmm1, xmm0
        pxor	xmm1, xmm3
        movdqa	xmm2, xmm1
        movdqa	xmm6, xmm3
        pslldq	xmm2, 8
        psrldq	xmm1, 8
        pxor	xmm0, xmm2
        pxor	xmm6, xmm1
        movdqa	xmm1, xmm0
        movdqa	xmm2, xmm0
        movdqa	xmm3, xmm0
        pslld	xmm1, 31
        pslld	xmm2, 30
        pslld	xmm3, 25
        pxor	xmm1, xmm2
        pxor	xmm1, xmm3
        movdqa	xmm3, xmm1
        psrldq	xmm3, 4
        pslldq	xmm1, 12
        pxor	xmm0, xmm1
        movdqa	xmm1, xmm0
        movdqa	xmm2, xmm0
        psrld	xmm1, 1
        psrld	xmm2, 2
        pxor	xmm1, xmm2
        pxor	xmm1, xmm0
        psrld	xmm0, 7
        pxor	xmm1, xmm3
        pxor	xmm1, xmm0
        pxor	xmm6, xmm1
L_AES_GCM_encrypt_update_aesni_last_block_done:
L_AES_GCM_encrypt_update_aesni_done_enc:
        mov	esi, DWORD PTR [esp+136]
        mov	edi, DWORD PTR [esp+144]
        movdqu	xmm4, OWORD PTR [esp+64]
        movdqa	OWORD PTR [esi], xmm6
        movdqu	OWORD PTR [edi], xmm4
        add	esp, 96
        pop	ebp
        pop	edi
        pop	esi
        pop	ebx
        ret
AES_GCM_encrypt_update_aesni ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_GCM_encrypt_final_aesni PROC
        push	esi
        push	edi
        push	ebp
        sub	esp, 16
        mov	ebp, DWORD PTR [esp+32]
        mov	esi, DWORD PTR [esp+52]
        mov	edi, DWORD PTR [esp+56]
        movdqa	xmm4, OWORD PTR [ebp]
        movdqa	xmm5, OWORD PTR [esi]
        movdqa	xmm6, OWORD PTR [edi]
        movdqa	xmm1, xmm5
        movdqa	xmm0, xmm5
        psrlq	xmm1, 63
        psllq	xmm0, 1
        pslldq	xmm1, 8
        por	xmm0, xmm1
        pshufd	xmm5, xmm5, 255
        psrad	xmm5, 31
        pand	xmm5, OWORD PTR L_aes_gcm_mod2_128
        pxor	xmm5, xmm0
        mov	edx, DWORD PTR [esp+44]
        mov	ecx, DWORD PTR [esp+48]
        shl	edx, 3
        shl	ecx, 3
        pinsrd	xmm0, edx, 0
        pinsrd	xmm0, ecx, 2
        mov	edx, DWORD PTR [esp+44]
        mov	ecx, DWORD PTR [esp+48]
        shr	edx, 29
        shr	ecx, 29
        pinsrd	xmm0, edx, 1
        pinsrd	xmm0, ecx, 3
        pxor	xmm4, xmm0
        pshufd	xmm1, xmm5, 78
        pshufd	xmm2, xmm4, 78
        movdqa	xmm3, xmm4
        movdqa	xmm0, xmm4
        pclmulqdq	xmm3, xmm5, 17
        pclmulqdq	xmm0, xmm5, 0
        pxor	xmm1, xmm5
        pxor	xmm2, xmm4
        pclmulqdq	xmm1, xmm2, 0
        pxor	xmm1, xmm0
        pxor	xmm1, xmm3
        movdqa	xmm2, xmm1
        movdqa	xmm4, xmm3
        pslldq	xmm2, 8
        psrldq	xmm1, 8
        pxor	xmm0, xmm2
        pxor	xmm4, xmm1
        movdqa	xmm1, xmm0
        movdqa	xmm2, xmm0
        movdqa	xmm3, xmm0
        pslld	xmm1, 31
        pslld	xmm2, 30
        pslld	xmm3, 25
        pxor	xmm1, xmm2
        pxor	xmm1, xmm3
        movdqa	xmm3, xmm1
        psrldq	xmm3, 4
        pslldq	xmm1, 12
        pxor	xmm0, xmm1
        movdqa	xmm1, xmm0
        movdqa	xmm2, xmm0
        psrld	xmm1, 1
        psrld	xmm2, 2
        pxor	xmm1, xmm2
        pxor	xmm1, xmm0
        psrld	xmm0, 7
        pxor	xmm1, xmm3
        pxor	xmm1, xmm0
        pxor	xmm4, xmm1
        pshufb	xmm4, OWORD PTR L_aes_gcm_bswap_mask
        movdqu	xmm0, xmm6
        pxor	xmm0, xmm4
        mov	edi, DWORD PTR [esp+36]
        cmp	DWORD PTR [esp+40], 16
        je	L_AES_GCM_encrypt_final_aesni_store_tag_16
        xor	ecx, ecx
        movdqu	OWORD PTR [esp], xmm0
L_AES_GCM_encrypt_final_aesni_store_tag_loop:
        movzx	eax, BYTE PTR [esp+ecx]
        mov	BYTE PTR [edi+ecx], al
        inc	ecx
        cmp	ecx, DWORD PTR [esp+40]
        jne	L_AES_GCM_encrypt_final_aesni_store_tag_loop
        jmp	L_AES_GCM_encrypt_final_aesni_store_tag_done
L_AES_GCM_encrypt_final_aesni_store_tag_16:
        movdqu	OWORD PTR [edi], xmm0
L_AES_GCM_encrypt_final_aesni_store_tag_done:
        add	esp, 16
        pop	ebp
        pop	edi
        pop	esi
        ret
AES_GCM_encrypt_final_aesni ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_GCM_decrypt_update_aesni PROC
        push	ebx
        push	esi
        push	edi
        push	ebp
        sub	esp, 160
        mov	esi, DWORD PTR [esp+208]
        movdqa	xmm4, OWORD PTR [esi]
        movdqu	OWORD PTR [esp+64], xmm4
        mov	esi, DWORD PTR [esp+200]
        mov	ebp, DWORD PTR [esp+204]
        movdqa	xmm6, OWORD PTR [esi]
        movdqa	xmm5, OWORD PTR [ebp]
        movdqu	OWORD PTR [esp+80], xmm6
        mov	ebp, DWORD PTR [esp+180]
        mov	edi, DWORD PTR [esp+188]
        mov	esi, DWORD PTR [esp+192]
        movdqa	xmm1, xmm5
        movdqa	xmm0, xmm5
        psrlq	xmm1, 63
        psllq	xmm0, 1
        pslldq	xmm1, 8
        por	xmm0, xmm1
        pshufd	xmm5, xmm5, 255
        psrad	xmm5, 31
        pand	xmm5, OWORD PTR L_aes_gcm_mod2_128
        pxor	xmm5, xmm0
        xor	ebx, ebx
        cmp	DWORD PTR [esp+196], 64
        mov	eax, DWORD PTR [esp+196]
        jl	L_AES_GCM_decrypt_update_aesni_done_64
        and	eax, 4294967232
        movdqa	xmm2, xmm6
        ; H ^ 1
        movdqu	OWORD PTR [esp], xmm5
        ; H ^ 2
        pshufd	xmm1, xmm5, 78
        pshufd	xmm2, xmm5, 78
        movdqa	xmm3, xmm5
        movdqa	xmm0, xmm5
        pclmulqdq	xmm3, xmm5, 17
        pclmulqdq	xmm0, xmm5, 0
        pxor	xmm1, xmm5
        pxor	xmm2, xmm5
        pclmulqdq	xmm1, xmm2, 0
        pxor	xmm1, xmm0
        pxor	xmm1, xmm3
        movdqa	xmm2, xmm1
        movdqa	xmm4, xmm3
        pslldq	xmm2, 8
        psrldq	xmm1, 8
        pxor	xmm0, xmm2
        pxor	xmm4, xmm1
        movdqa	xmm1, xmm0
        movdqa	xmm2, xmm0
        movdqa	xmm3, xmm0
        pslld	xmm1, 31
        pslld	xmm2, 30
        pslld	xmm3, 25
        pxor	xmm1, xmm2
        pxor	xmm1, xmm3
        movdqa	xmm3, xmm1
        psrldq	xmm3, 4
        pslldq	xmm1, 12
        pxor	xmm0, xmm1
        movdqa	xmm1, xmm0
        movdqa	xmm2, xmm0
        psrld	xmm1, 1
        psrld	xmm2, 2
        pxor	xmm1, xmm2
        pxor	xmm1, xmm0
        psrld	xmm0, 7
        pxor	xmm1, xmm3
        pxor	xmm1, xmm0
        pxor	xmm4, xmm1
        movdqu	OWORD PTR [esp+16], xmm4
        ; H ^ 3
        pshufd	xmm1, xmm5, 78
        pshufd	xmm2, xmm4, 78
        movdqa	xmm3, xmm4
        movdqa	xmm0, xmm4
        pclmulqdq	xmm3, xmm5, 17
        pclmulqdq	xmm0, xmm5, 0
        pxor	xmm1, xmm5
        pxor	xmm2, xmm4
        pclmulqdq	xmm1, xmm2, 0
        pxor	xmm1, xmm0
        pxor	xmm1, xmm3
        movdqa	xmm2, xmm1
        movdqa	xmm7, xmm3
        pslldq	xmm2, 8
        psrldq	xmm1, 8
        pxor	xmm0, xmm2
        pxor	xmm7, xmm1
        movdqa	xmm1, xmm0
        movdqa	xmm2, xmm0
        movdqa	xmm3, xmm0
        pslld	xmm1, 31
        pslld	xmm2, 30
        pslld	xmm3, 25
        pxor	xmm1, xmm2
        pxor	xmm1, xmm3
        movdqa	xmm3, xmm1
        psrldq	xmm3, 4
        pslldq	xmm1, 12
        pxor	xmm0, xmm1
        movdqa	xmm1, xmm0
        movdqa	xmm2, xmm0
        psrld	xmm1, 1
        psrld	xmm2, 2
        pxor	xmm1, xmm2
        pxor	xmm1, xmm0
        psrld	xmm0, 7
        pxor	xmm1, xmm3
        pxor	xmm1, xmm0
        pxor	xmm7, xmm1
        movdqu	OWORD PTR [esp+32], xmm7
        ; H ^ 4
        pshufd	xmm1, xmm4, 78
        pshufd	xmm2, xmm4, 78
        movdqa	xmm3, xmm4
        movdqa	xmm0, xmm4
        pclmulqdq	xmm3, xmm4, 17
        pclmulqdq	xmm0, xmm4, 0
        pxor	xmm1, xmm4
        pxor	xmm2, xmm4
        pclmulqdq	xmm1, xmm2, 0
        pxor	xmm1, xmm0
        pxor	xmm1, xmm3
        movdqa	xmm2, xmm1
        movdqa	xmm7, xmm3
        pslldq	xmm2, 8
        psrldq	xmm1, 8
        pxor	xmm0, xmm2
        pxor	xmm7, xmm1
        movdqa	xmm1, xmm0
        movdqa	xmm2, xmm0
        movdqa	xmm3, xmm0
        pslld	xmm1, 31
        pslld	xmm2, 30
        pslld	xmm3, 25
        pxor	xmm1, xmm2
        pxor	xmm1, xmm3
        movdqa	xmm3, xmm1
        psrldq	xmm3, 4
        pslldq	xmm1, 12
        pxor	xmm0, xmm1
        movdqa	xmm1, xmm0
        movdqa	xmm2, xmm0
        psrld	xmm1, 1
        psrld	xmm2, 2
        pxor	xmm1, xmm2
        pxor	xmm1, xmm0
        psrld	xmm0, 7
        pxor	xmm1, xmm3
        pxor	xmm1, xmm0
        pxor	xmm7, xmm1
        movdqu	OWORD PTR [esp+48], xmm7
        cmp	edi, esi
        jne	L_AES_GCM_decrypt_update_aesni_ghash_64
L_AES_GCM_decrypt_update_aesni_ghash_64_inplace:
        lea	ecx, DWORD PTR [esi+ebx]
        lea	edx, DWORD PTR [edi+ebx]
        ; Encrypt 64 bytes of counter
        movdqu	xmm0, OWORD PTR [esp+64]
        movdqu	xmm7, xmm0
        paddd	xmm7, OWORD PTR L_aes_gcm_four
        movdqu	OWORD PTR [esp+64], xmm7
        movdqa	xmm7, OWORD PTR L_aes_gcm_bswap_epi64
        movdqa	xmm1, xmm0
        movdqa	xmm2, xmm0
        movdqa	xmm3, xmm0
        pshufb	xmm0, xmm7
        paddd	xmm1, OWORD PTR L_aes_gcm_one
        pshufb	xmm1, xmm7
        paddd	xmm2, OWORD PTR L_aes_gcm_two
        pshufb	xmm2, xmm7
        paddd	xmm3, OWORD PTR L_aes_gcm_three
        pshufb	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp]
        pxor	xmm0, xmm7
        pxor	xmm1, xmm7
        pxor	xmm2, xmm7
        pxor	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+16]
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+32]
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+48]
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+64]
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+80]
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+96]
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+112]
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+128]
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+144]
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        cmp	DWORD PTR [esp+184], 11
        movdqa	xmm7, OWORD PTR [ebp+160]
        jl	L_AES_GCM_decrypt_update_aesniinplace_aesenc_64_ghash_avx_done
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+176]
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        cmp	DWORD PTR [esp+184], 13
        movdqa	xmm7, OWORD PTR [ebp+192]
        jl	L_AES_GCM_decrypt_update_aesniinplace_aesenc_64_ghash_avx_done
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+208]
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+224]
L_AES_GCM_decrypt_update_aesniinplace_aesenc_64_ghash_avx_done:
        aesenclast	xmm0, xmm7
        aesenclast	xmm1, xmm7
        movdqu	xmm4, OWORD PTR [ecx]
        movdqu	xmm5, OWORD PTR [ecx+16]
        pxor	xmm0, xmm4
        pxor	xmm1, xmm5
        movdqu	OWORD PTR [esp+96], xmm4
        movdqu	OWORD PTR [esp+112], xmm5
        movdqu	OWORD PTR [edx], xmm0
        movdqu	OWORD PTR [edx+16], xmm1
        aesenclast	xmm2, xmm7
        aesenclast	xmm3, xmm7
        movdqu	xmm4, OWORD PTR [ecx+32]
        movdqu	xmm5, OWORD PTR [ecx+48]
        pxor	xmm2, xmm4
        pxor	xmm3, xmm5
        movdqu	OWORD PTR [esp+128], xmm4
        movdqu	OWORD PTR [esp+144], xmm5
        movdqu	OWORD PTR [edx+32], xmm2
        movdqu	OWORD PTR [edx+48], xmm3
        ; ghash encrypted counter
        movdqu	xmm2, OWORD PTR [esp+80]
        movdqu	xmm7, OWORD PTR [esp+48]
        movdqu	xmm0, OWORD PTR [esp+96]
        pshufb	xmm0, OWORD PTR L_aes_gcm_bswap_mask
        pxor	xmm0, xmm2
        pshufd	xmm1, xmm7, 78
        pshufd	xmm5, xmm0, 78
        pxor	xmm1, xmm7
        pxor	xmm5, xmm0
        movdqa	xmm3, xmm0
        pclmulqdq	xmm3, xmm7, 17
        movdqa	xmm2, xmm0
        pclmulqdq	xmm2, xmm7, 0
        pclmulqdq	xmm1, xmm5, 0
        pxor	xmm1, xmm2
        pxor	xmm1, xmm3
        movdqu	xmm7, OWORD PTR [esp+32]
        movdqu	xmm0, OWORD PTR [esp+112]
        pshufd	xmm4, xmm7, 78
        pshufb	xmm0, OWORD PTR L_aes_gcm_bswap_mask
        pxor	xmm4, xmm7
        pshufd	xmm5, xmm0, 78
        pxor	xmm5, xmm0
        movdqa	xmm6, xmm0
        pclmulqdq	xmm6, xmm7, 17
        pclmulqdq	xmm7, xmm0, 0
        pclmulqdq	xmm4, xmm5, 0
        pxor	xmm1, xmm7
        pxor	xmm2, xmm7
        pxor	xmm1, xmm6
        pxor	xmm3, xmm6
        pxor	xmm1, xmm4
        movdqu	xmm7, OWORD PTR [esp+16]
        movdqu	xmm0, OWORD PTR [esp+128]
        pshufd	xmm4, xmm7, 78
        pshufb	xmm0, OWORD PTR L_aes_gcm_bswap_mask
        pxor	xmm4, xmm7
        pshufd	xmm5, xmm0, 78
        pxor	xmm5, xmm0
        movdqa	xmm6, xmm0
        pclmulqdq	xmm6, xmm7, 17
        pclmulqdq	xmm7, xmm0, 0
        pclmulqdq	xmm4, xmm5, 0
        pxor	xmm1, xmm7
        pxor	xmm2, xmm7
        pxor	xmm1, xmm6
        pxor	xmm3, xmm6
        pxor	xmm1, xmm4
        movdqu	xmm7, OWORD PTR [esp]
        movdqu	xmm0, OWORD PTR [esp+144]
        pshufd	xmm4, xmm7, 78
        pshufb	xmm0, OWORD PTR L_aes_gcm_bswap_mask
        pxor	xmm4, xmm7
        pshufd	xmm5, xmm0, 78
        pxor	xmm5, xmm0
        movdqa	xmm6, xmm0
        pclmulqdq	xmm6, xmm7, 17
        pclmulqdq	xmm7, xmm0, 0
        pclmulqdq	xmm4, xmm5, 0
        pxor	xmm1, xmm7
        pxor	xmm2, xmm7
        pxor	xmm1, xmm6
        pxor	xmm3, xmm6
        pxor	xmm1, xmm4
        movdqa	xmm5, xmm1
        psrldq	xmm1, 8
        pslldq	xmm5, 8
        pxor	xmm2, xmm5
        pxor	xmm3, xmm1
        movdqa	xmm7, xmm2
        movdqa	xmm4, xmm2
        movdqa	xmm5, xmm2
        pslld	xmm7, 31
        pslld	xmm4, 30
        pslld	xmm5, 25
        pxor	xmm7, xmm4
        pxor	xmm7, xmm5
        movdqa	xmm4, xmm7
        pslldq	xmm7, 12
        psrldq	xmm4, 4
        pxor	xmm2, xmm7
        movdqa	xmm5, xmm2
        movdqa	xmm1, xmm2
        movdqa	xmm0, xmm2
        psrld	xmm5, 1
        psrld	xmm1, 2
        psrld	xmm0, 7
        pxor	xmm5, xmm1
        pxor	xmm5, xmm0
        pxor	xmm5, xmm4
        pxor	xmm2, xmm5
        pxor	xmm2, xmm3
        movdqu	OWORD PTR [esp+80], xmm2
        add	ebx, 64
        cmp	ebx, eax
        jl	L_AES_GCM_decrypt_update_aesni_ghash_64_inplace
        jmp	L_AES_GCM_decrypt_update_aesni_ghash_64_done
L_AES_GCM_decrypt_update_aesni_ghash_64:
        lea	ecx, DWORD PTR [esi+ebx]
        lea	edx, DWORD PTR [edi+ebx]
        ; Encrypt 64 bytes of counter
        movdqu	xmm0, OWORD PTR [esp+64]
        movdqu	xmm7, xmm0
        paddd	xmm7, OWORD PTR L_aes_gcm_four
        movdqu	OWORD PTR [esp+64], xmm7
        movdqa	xmm7, OWORD PTR L_aes_gcm_bswap_epi64
        movdqa	xmm1, xmm0
        movdqa	xmm2, xmm0
        movdqa	xmm3, xmm0
        pshufb	xmm0, xmm7
        paddd	xmm1, OWORD PTR L_aes_gcm_one
        pshufb	xmm1, xmm7
        paddd	xmm2, OWORD PTR L_aes_gcm_two
        pshufb	xmm2, xmm7
        paddd	xmm3, OWORD PTR L_aes_gcm_three
        pshufb	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp]
        pxor	xmm0, xmm7
        pxor	xmm1, xmm7
        pxor	xmm2, xmm7
        pxor	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+16]
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+32]
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+48]
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+64]
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+80]
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+96]
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+112]
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+128]
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+144]
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        cmp	DWORD PTR [esp+184], 11
        movdqa	xmm7, OWORD PTR [ebp+160]
        jl	L_AES_GCM_decrypt_update_aesni_aesenc_64_ghash_avx_done
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+176]
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        cmp	DWORD PTR [esp+184], 13
        movdqa	xmm7, OWORD PTR [ebp+192]
        jl	L_AES_GCM_decrypt_update_aesni_aesenc_64_ghash_avx_done
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+208]
        aesenc	xmm0, xmm7
        aesenc	xmm1, xmm7
        aesenc	xmm2, xmm7
        aesenc	xmm3, xmm7
        movdqa	xmm7, OWORD PTR [ebp+224]
L_AES_GCM_decrypt_update_aesni_aesenc_64_ghash_avx_done:
        aesenclast	xmm0, xmm7
        aesenclast	xmm1, xmm7
        movdqu	xmm4, OWORD PTR [ecx]
        movdqu	xmm5, OWORD PTR [ecx+16]
        pxor	xmm0, xmm4
        pxor	xmm1, xmm5
        movdqu	OWORD PTR [edx], xmm0
        movdqu	OWORD PTR [edx+16], xmm1
        aesenclast	xmm2, xmm7
        aesenclast	xmm3, xmm7
        movdqu	xmm4, OWORD PTR [ecx+32]
        movdqu	xmm5, OWORD PTR [ecx+48]
        pxor	xmm2, xmm4
        pxor	xmm3, xmm5
        movdqu	OWORD PTR [edx+32], xmm2
        movdqu	OWORD PTR [edx+48], xmm3
        ; ghash encrypted counter
        movdqu	xmm2, OWORD PTR [esp+80]
        movdqu	xmm7, OWORD PTR [esp+48]
        movdqu	xmm0, OWORD PTR [ecx]
        pshufb	xmm0, OWORD PTR L_aes_gcm_bswap_mask
        pxor	xmm0, xmm2
        pshufd	xmm1, xmm7, 78
        pshufd	xmm5, xmm0, 78
        pxor	xmm1, xmm7
        pxor	xmm5, xmm0
        movdqa	xmm3, xmm0
        pclmulqdq	xmm3, xmm7, 17
        movdqa	xmm2, xmm0
        pclmulqdq	xmm2, xmm7, 0
        pclmulqdq	xmm1, xmm5, 0
        pxor	xmm1, xmm2
        pxor	xmm1, xmm3
        movdqu	xmm7, OWORD PTR [esp+32]
        movdqu	xmm0, OWORD PTR [ecx+16]
        pshufd	xmm4, xmm7, 78
        pshufb	xmm0, OWORD PTR L_aes_gcm_bswap_mask
        pxor	xmm4, xmm7
        pshufd	xmm5, xmm0, 78
        pxor	xmm5, xmm0
        movdqa	xmm6, xmm0
        pclmulqdq	xmm6, xmm7, 17
        pclmulqdq	xmm7, xmm0, 0
        pclmulqdq	xmm4, xmm5, 0
        pxor	xmm1, xmm7
        pxor	xmm2, xmm7
        pxor	xmm1, xmm6
        pxor	xmm3, xmm6
        pxor	xmm1, xmm4
        movdqu	xmm7, OWORD PTR [esp+16]
        movdqu	xmm0, OWORD PTR [ecx+32]
        pshufd	xmm4, xmm7, 78
        pshufb	xmm0, OWORD PTR L_aes_gcm_bswap_mask
        pxor	xmm4, xmm7
        pshufd	xmm5, xmm0, 78
        pxor	xmm5, xmm0
        movdqa	xmm6, xmm0
        pclmulqdq	xmm6, xmm7, 17
        pclmulqdq	xmm7, xmm0, 0
        pclmulqdq	xmm4, xmm5, 0
        pxor	xmm1, xmm7
        pxor	xmm2, xmm7
        pxor	xmm1, xmm6
        pxor	xmm3, xmm6
        pxor	xmm1, xmm4
        movdqu	xmm7, OWORD PTR [esp]
        movdqu	xmm0, OWORD PTR [ecx+48]
        pshufd	xmm4, xmm7, 78
        pshufb	xmm0, OWORD PTR L_aes_gcm_bswap_mask
        pxor	xmm4, xmm7
        pshufd	xmm5, xmm0, 78
        pxor	xmm5, xmm0
        movdqa	xmm6, xmm0
        pclmulqdq	xmm6, xmm7, 17
        pclmulqdq	xmm7, xmm0, 0
        pclmulqdq	xmm4, xmm5, 0
        pxor	xmm1, xmm7
        pxor	xmm2, xmm7
        pxor	xmm1, xmm6
        pxor	xmm3, xmm6
        pxor	xmm1, xmm4
        movdqa	xmm5, xmm1
        psrldq	xmm1, 8
        pslldq	xmm5, 8
        pxor	xmm2, xmm5
        pxor	xmm3, xmm1
        movdqa	xmm7, xmm2
        movdqa	xmm4, xmm2
        movdqa	xmm5, xmm2
        pslld	xmm7, 31
        pslld	xmm4, 30
        pslld	xmm5, 25
        pxor	xmm7, xmm4
        pxor	xmm7, xmm5
        movdqa	xmm4, xmm7
        pslldq	xmm7, 12
        psrldq	xmm4, 4
        pxor	xmm2, xmm7
        movdqa	xmm5, xmm2
        movdqa	xmm1, xmm2
        movdqa	xmm0, xmm2
        psrld	xmm5, 1
        psrld	xmm1, 2
        psrld	xmm0, 7
        pxor	xmm5, xmm1
        pxor	xmm5, xmm0
        pxor	xmm5, xmm4
        pxor	xmm2, xmm5
        pxor	xmm2, xmm3
        movdqu	OWORD PTR [esp+80], xmm2
        add	ebx, 64
        cmp	ebx, eax
        jl	L_AES_GCM_decrypt_update_aesni_ghash_64
L_AES_GCM_decrypt_update_aesni_ghash_64_done:
        movdqa	xmm6, xmm2
        movdqu	xmm5, OWORD PTR [esp]
L_AES_GCM_decrypt_update_aesni_done_64:
        mov	edx, DWORD PTR [esp+196]
        cmp	ebx, edx
        jge	L_AES_GCM_decrypt_update_aesni_done_dec
        mov	eax, DWORD PTR [esp+196]
        and	eax, 4294967280
        cmp	ebx, eax
        jge	L_AES_GCM_decrypt_update_aesni_last_block_done
L_AES_GCM_decrypt_update_aesni_last_block_start:
        lea	ecx, DWORD PTR [esi+ebx]
        lea	edx, DWORD PTR [edi+ebx]
        movdqu	xmm1, OWORD PTR [ecx]
        pshufb	xmm1, OWORD PTR L_aes_gcm_bswap_mask
        pxor	xmm1, xmm6
        movdqu	OWORD PTR [esp], xmm1
        movdqu	xmm0, OWORD PTR [esp+64]
        movdqa	xmm1, xmm0
        pshufb	xmm0, OWORD PTR L_aes_gcm_bswap_epi64
        paddd	xmm1, OWORD PTR L_aes_gcm_one
        pxor	xmm0, [ebp]
        movdqu	OWORD PTR [esp+64], xmm1
        movdqu	xmm4, OWORD PTR [esp]
        pclmulqdq	xmm4, xmm5, 16
        aesenc	xmm0, [ebp+16]
        aesenc	xmm0, [ebp+32]
        movdqu	xmm7, OWORD PTR [esp]
        pclmulqdq	xmm7, xmm5, 1
        aesenc	xmm0, [ebp+48]
        aesenc	xmm0, [ebp+64]
        aesenc	xmm0, [ebp+80]
        movdqu	xmm1, OWORD PTR [esp]
        pclmulqdq	xmm1, xmm5, 17
        aesenc	xmm0, [ebp+96]
        pxor	xmm4, xmm7
        movdqa	xmm2, xmm4
        psrldq	xmm4, 8
        pslldq	xmm2, 8
        aesenc	xmm0, [ebp+112]
        movdqu	xmm7, OWORD PTR [esp]
        pclmulqdq	xmm7, xmm5, 0
        pxor	xmm2, xmm7
        pxor	xmm1, xmm4
        movdqa	xmm3, OWORD PTR L_aes_gcm_mod2_128
        movdqa	xmm7, xmm2
        pclmulqdq	xmm7, xmm3, 16
        aesenc	xmm0, [ebp+128]
        pshufd	xmm4, xmm2, 78
        pxor	xmm4, xmm7
        movdqa	xmm7, xmm4
        pclmulqdq	xmm7, xmm3, 16
        aesenc	xmm0, [ebp+144]
        pshufd	xmm6, xmm4, 78
        pxor	xmm6, xmm7
        pxor	xmm6, xmm1
        cmp	DWORD PTR [esp+184], 11
        movdqa	xmm1, OWORD PTR [ebp+160]
        jl	L_AES_GCM_decrypt_update_aesni_aesenc_gfmul_last
        aesenc	xmm0, xmm1
        aesenc	xmm0, [ebp+176]
        cmp	DWORD PTR [esp+184], 13
        movdqa	xmm1, OWORD PTR [ebp+192]
        jl	L_AES_GCM_decrypt_update_aesni_aesenc_gfmul_last
        aesenc	xmm0, xmm1
        aesenc	xmm0, [ebp+208]
        movdqa	xmm1, OWORD PTR [ebp+224]
L_AES_GCM_decrypt_update_aesni_aesenc_gfmul_last:
        aesenclast	xmm0, xmm1
        movdqu	xmm1, OWORD PTR [ecx]
        pxor	xmm0, xmm1
        movdqu	OWORD PTR [edx], xmm0
        add	ebx, 16
        cmp	ebx, eax
        jl	L_AES_GCM_decrypt_update_aesni_last_block_start
L_AES_GCM_decrypt_update_aesni_last_block_done:
L_AES_GCM_decrypt_update_aesni_done_dec:
        mov	esi, DWORD PTR [esp+200]
        mov	edi, DWORD PTR [esp+208]
        movdqu	xmm4, OWORD PTR [esp+64]
        movdqa	OWORD PTR [esi], xmm6
        movdqu	OWORD PTR [edi], xmm4
        add	esp, 160
        pop	ebp
        pop	edi
        pop	esi
        pop	ebx
        ret
AES_GCM_decrypt_update_aesni ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_GCM_decrypt_final_aesni PROC
        push	ebx
        push	esi
        push	edi
        push	ebp
        sub	esp, 16
        mov	ebp, DWORD PTR [esp+36]
        mov	esi, DWORD PTR [esp+56]
        mov	edi, DWORD PTR [esp+60]
        movdqa	xmm6, OWORD PTR [ebp]
        movdqa	xmm5, OWORD PTR [esi]
        movdqa	xmm7, OWORD PTR [edi]
        movdqa	xmm1, xmm5
        movdqa	xmm0, xmm5
        psrlq	xmm1, 63
        psllq	xmm0, 1
        pslldq	xmm1, 8
        por	xmm0, xmm1
        pshufd	xmm5, xmm5, 255
        psrad	xmm5, 31
        pand	xmm5, OWORD PTR L_aes_gcm_mod2_128
        pxor	xmm5, xmm0
        mov	edx, DWORD PTR [esp+48]
        mov	ecx, DWORD PTR [esp+52]
        shl	edx, 3
        shl	ecx, 3
        pinsrd	xmm0, edx, 0
        pinsrd	xmm0, ecx, 2
        mov	edx, DWORD PTR [esp+48]
        mov	ecx, DWORD PTR [esp+52]
        shr	edx, 29
        shr	ecx, 29
        pinsrd	xmm0, edx, 1
        pinsrd	xmm0, ecx, 3
        pxor	xmm6, xmm0
        pshufd	xmm1, xmm5, 78
        pshufd	xmm2, xmm6, 78
        movdqa	xmm3, xmm6
        movdqa	xmm0, xmm6
        pclmulqdq	xmm3, xmm5, 17
        pclmulqdq	xmm0, xmm5, 0
        pxor	xmm1, xmm5
        pxor	xmm2, xmm6
        pclmulqdq	xmm1, xmm2, 0
        pxor	xmm1, xmm0
        pxor	xmm1, xmm3
        movdqa	xmm2, xmm1
        movdqa	xmm6, xmm3
        pslldq	xmm2, 8
        psrldq	xmm1, 8
        pxor	xmm0, xmm2
        pxor	xmm6, xmm1
        movdqa	xmm1, xmm0
        movdqa	xmm2, xmm0
        movdqa	xmm3, xmm0
        pslld	xmm1, 31
        pslld	xmm2, 30
        pslld	xmm3, 25
        pxor	xmm1, xmm2
        pxor	xmm1, xmm3
        movdqa	xmm3, xmm1
        psrldq	xmm3, 4
        pslldq	xmm1, 12
        pxor	xmm0, xmm1
        movdqa	xmm1, xmm0
        movdqa	xmm2, xmm0
        psrld	xmm1, 1
        psrld	xmm2, 2
        pxor	xmm1, xmm2
        pxor	xmm1, xmm0
        psrld	xmm0, 7
        pxor	xmm1, xmm3
        pxor	xmm1, xmm0
        pxor	xmm6, xmm1
        pshufb	xmm6, OWORD PTR L_aes_gcm_bswap_mask
        movdqu	xmm0, xmm7
        pxor	xmm0, xmm6
        mov	esi, DWORD PTR [esp+40]
        mov	edi, DWORD PTR [esp+64]
        cmp	DWORD PTR [esp+44], 16
        je	L_AES_GCM_decrypt_final_aesni_cmp_tag_16
        sub	esp, 16
        xor	ecx, ecx
        xor	ebx, ebx
        movdqu	OWORD PTR [esp], xmm0
L_AES_GCM_decrypt_final_aesni_cmp_tag_loop:
        movzx	eax, BYTE PTR [esp+ecx]
        xor	al, BYTE PTR [esi+ecx]
        or	bl, al
        inc	ecx
        cmp	ecx, DWORD PTR [esp+44]
        jne	L_AES_GCM_decrypt_final_aesni_cmp_tag_loop
        cmp	bl, 0
        sete	bl
        add	esp, 16
        xor	ecx, ecx
        jmp	L_AES_GCM_decrypt_final_aesni_cmp_tag_done
L_AES_GCM_decrypt_final_aesni_cmp_tag_16:
        movdqu	xmm1, OWORD PTR [esi]
        pcmpeqb	xmm0, xmm1
        pmovmskb	edx, xmm0
        ; %%edx == 0xFFFF then return 1 else => return 0
        xor	ebx, ebx
        cmp	edx, 65535
        sete	bl
L_AES_GCM_decrypt_final_aesni_cmp_tag_done:
        mov	DWORD PTR [edi], ebx
        add	esp, 16
        pop	ebp
        pop	edi
        pop	esi
        pop	ebx
        ret
AES_GCM_decrypt_final_aesni ENDP
_TEXT ENDS
ENDIF
IFDEF HAVE_INTEL_AVX1
_TEXT SEGMENT READONLY PARA
AES_GCM_encrypt_avx1 PROC
        push	ebx
        push	esi
        push	edi
        push	ebp
        sub	esp, 112
        mov	esi, DWORD PTR [esp+144]
        mov	ebp, DWORD PTR [esp+168]
        mov	edx, DWORD PTR [esp+160]
        vpxor	xmm0, xmm0, xmm0
        vpxor	xmm2, xmm2, xmm2
        cmp	edx, 12
        jne	L_AES_GCM_encrypt_avx1_iv_not_12
        ; # Calculate values when IV is 12 bytes
        ; Set counter based on IV
        mov	ecx, 16777216
        vpinsrd	xmm0, xmm0, DWORD PTR [esi], 0
        vpinsrd	xmm0, xmm0, DWORD PTR [esi+4], 1
        vpinsrd	xmm0, xmm0, DWORD PTR [esi+8], 2
        vpinsrd	xmm0, xmm0, ecx, 3
        ; H = Encrypt X(=0) and T = Encrypt counter
        vmovdqa	xmm1, OWORD PTR [ebp]
        vpxor	xmm5, xmm0, xmm1
        vmovdqa	xmm3, OWORD PTR [ebp+16]
        vaesenc	xmm1, xmm1, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+32]
        vaesenc	xmm1, xmm1, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+48]
        vaesenc	xmm1, xmm1, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+64]
        vaesenc	xmm1, xmm1, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+80]
        vaesenc	xmm1, xmm1, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+96]
        vaesenc	xmm1, xmm1, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+112]
        vaesenc	xmm1, xmm1, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+128]
        vaesenc	xmm1, xmm1, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+144]
        vaesenc	xmm1, xmm1, xmm3
        vaesenc	xmm5, xmm5, xmm3
        cmp	DWORD PTR [esp+172], 11
        vmovdqa	xmm3, OWORD PTR [ebp+160]
        jl	L_AES_GCM_encrypt_avx1_calc_iv_12_last
        vaesenc	xmm1, xmm1, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+176]
        vaesenc	xmm1, xmm1, xmm3
        vaesenc	xmm5, xmm5, xmm3
        cmp	DWORD PTR [esp+172], 13
        vmovdqa	xmm3, OWORD PTR [ebp+192]
        jl	L_AES_GCM_encrypt_avx1_calc_iv_12_last
        vaesenc	xmm1, xmm1, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+208]
        vaesenc	xmm1, xmm1, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+224]
L_AES_GCM_encrypt_avx1_calc_iv_12_last:
        vaesenclast	xmm1, xmm1, xmm3
        vaesenclast	xmm5, xmm5, xmm3
        vpshufb	xmm1, xmm1, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vmovdqu	OWORD PTR [esp+80], xmm5
        jmp	L_AES_GCM_encrypt_avx1_iv_done
L_AES_GCM_encrypt_avx1_iv_not_12:
        ; Calculate values when IV is not 12 bytes
        ; H = Encrypt X(=0)
        vmovdqa	xmm1, OWORD PTR [ebp]
        vaesenc	xmm1, xmm1, [ebp+16]
        vaesenc	xmm1, xmm1, [ebp+32]
        vaesenc	xmm1, xmm1, [ebp+48]
        vaesenc	xmm1, xmm1, [ebp+64]
        vaesenc	xmm1, xmm1, [ebp+80]
        vaesenc	xmm1, xmm1, [ebp+96]
        vaesenc	xmm1, xmm1, [ebp+112]
        vaesenc	xmm1, xmm1, [ebp+128]
        vaesenc	xmm1, xmm1, [ebp+144]
        cmp	DWORD PTR [esp+172], 11
        vmovdqa	xmm5, OWORD PTR [ebp+160]
        jl	L_AES_GCM_encrypt_avx1_calc_iv_1_aesenc_avx_last
        vaesenc	xmm1, xmm1, xmm5
        vaesenc	xmm1, xmm1, [ebp+176]
        cmp	DWORD PTR [esp+172], 13
        vmovdqa	xmm5, OWORD PTR [ebp+192]
        jl	L_AES_GCM_encrypt_avx1_calc_iv_1_aesenc_avx_last
        vaesenc	xmm1, xmm1, xmm5
        vaesenc	xmm1, xmm1, [ebp+208]
        vmovdqa	xmm5, OWORD PTR [ebp+224]
L_AES_GCM_encrypt_avx1_calc_iv_1_aesenc_avx_last:
        vaesenclast	xmm1, xmm1, xmm5
        vpshufb	xmm1, xmm1, OWORD PTR L_aes_gcm_avx1_bswap_mask
        ; Calc counter
        ; Initialization vector
        cmp	edx, 0
        mov	ecx, 0
        je	L_AES_GCM_encrypt_avx1_calc_iv_done
        cmp	edx, 16
        jl	L_AES_GCM_encrypt_avx1_calc_iv_lt16
        and	edx, 4294967280
L_AES_GCM_encrypt_avx1_calc_iv_16_loop:
        vmovdqu	xmm4, OWORD PTR [esi+ecx]
        vpshufb	xmm4, xmm4, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm0, xmm0, xmm4
        ; ghash_gfmul_avx
        vpshufd	xmm5, xmm0, 78
        vpshufd	xmm6, xmm1, 78
        vpclmulqdq	xmm7, xmm1, xmm0, 17
        vpclmulqdq	xmm4, xmm1, xmm0, 0
        vpxor	xmm5, xmm5, xmm0
        vpxor	xmm6, xmm6, xmm1
        vpclmulqdq	xmm5, xmm5, xmm6, 0
        vpxor	xmm5, xmm5, xmm4
        vpxor	xmm5, xmm5, xmm7
        vmovdqa	xmm3, xmm4
        vmovdqa	xmm0, xmm7
        vpslldq	xmm6, xmm5, 8
        vpsrldq	xmm5, xmm5, 8
        vpxor	xmm3, xmm3, xmm6
        vpxor	xmm0, xmm0, xmm5
        vpsrld	xmm4, xmm3, 31
        vpsrld	xmm5, xmm0, 31
        vpslld	xmm3, xmm3, 1
        vpslld	xmm0, xmm0, 1
        vpsrldq	xmm6, xmm4, 12
        vpslldq	xmm4, xmm4, 4
        vpslldq	xmm5, xmm5, 4
        vpor	xmm0, xmm0, xmm6
        vpor	xmm3, xmm3, xmm4
        vpor	xmm0, xmm0, xmm5
        vpslld	xmm4, xmm3, 31
        vpslld	xmm5, xmm3, 30
        vpslld	xmm6, xmm3, 25
        vpxor	xmm4, xmm4, xmm5
        vpxor	xmm4, xmm4, xmm6
        vmovdqa	xmm5, xmm4
        vpsrldq	xmm5, xmm5, 4
        vpslldq	xmm4, xmm4, 12
        vpxor	xmm3, xmm3, xmm4
        vpsrld	xmm6, xmm3, 1
        vpsrld	xmm7, xmm3, 2
        vpsrld	xmm4, xmm3, 7
        vpxor	xmm6, xmm6, xmm7
        vpxor	xmm6, xmm6, xmm4
        vpxor	xmm6, xmm6, xmm5
        vpxor	xmm6, xmm6, xmm3
        vpxor	xmm0, xmm0, xmm6
        add	ecx, 16
        cmp	ecx, edx
        jl	L_AES_GCM_encrypt_avx1_calc_iv_16_loop
        mov	edx, DWORD PTR [esp+160]
        cmp	ecx, edx
        je	L_AES_GCM_encrypt_avx1_calc_iv_done
L_AES_GCM_encrypt_avx1_calc_iv_lt16:
        sub	esp, 16
        vpxor	xmm4, xmm4, xmm4
        xor	ebx, ebx
        vmovdqu	OWORD PTR [esp], xmm4
L_AES_GCM_encrypt_avx1_calc_iv_loop:
        movzx	eax, BYTE PTR [esi+ecx]
        mov	BYTE PTR [esp+ebx], al
        inc	ecx
        inc	ebx
        cmp	ecx, edx
        jl	L_AES_GCM_encrypt_avx1_calc_iv_loop
        vmovdqu	xmm4, OWORD PTR [esp]
        add	esp, 16
        vpshufb	xmm4, xmm4, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm0, xmm0, xmm4
        ; ghash_gfmul_avx
        vpshufd	xmm5, xmm0, 78
        vpshufd	xmm6, xmm1, 78
        vpclmulqdq	xmm7, xmm1, xmm0, 17
        vpclmulqdq	xmm4, xmm1, xmm0, 0
        vpxor	xmm5, xmm5, xmm0
        vpxor	xmm6, xmm6, xmm1
        vpclmulqdq	xmm5, xmm5, xmm6, 0
        vpxor	xmm5, xmm5, xmm4
        vpxor	xmm5, xmm5, xmm7
        vmovdqa	xmm3, xmm4
        vmovdqa	xmm0, xmm7
        vpslldq	xmm6, xmm5, 8
        vpsrldq	xmm5, xmm5, 8
        vpxor	xmm3, xmm3, xmm6
        vpxor	xmm0, xmm0, xmm5
        vpsrld	xmm4, xmm3, 31
        vpsrld	xmm5, xmm0, 31
        vpslld	xmm3, xmm3, 1
        vpslld	xmm0, xmm0, 1
        vpsrldq	xmm6, xmm4, 12
        vpslldq	xmm4, xmm4, 4
        vpslldq	xmm5, xmm5, 4
        vpor	xmm0, xmm0, xmm6
        vpor	xmm3, xmm3, xmm4
        vpor	xmm0, xmm0, xmm5
        vpslld	xmm4, xmm3, 31
        vpslld	xmm5, xmm3, 30
        vpslld	xmm6, xmm3, 25
        vpxor	xmm4, xmm4, xmm5
        vpxor	xmm4, xmm4, xmm6
        vmovdqa	xmm5, xmm4
        vpsrldq	xmm5, xmm5, 4
        vpslldq	xmm4, xmm4, 12
        vpxor	xmm3, xmm3, xmm4
        vpsrld	xmm6, xmm3, 1
        vpsrld	xmm7, xmm3, 2
        vpsrld	xmm4, xmm3, 7
        vpxor	xmm6, xmm6, xmm7
        vpxor	xmm6, xmm6, xmm4
        vpxor	xmm6, xmm6, xmm5
        vpxor	xmm6, xmm6, xmm3
        vpxor	xmm0, xmm0, xmm6
L_AES_GCM_encrypt_avx1_calc_iv_done:
        ; T = Encrypt counter
        vpxor	xmm4, xmm4, xmm4
        shl	edx, 3
        vpinsrd	xmm4, xmm4, edx, 0
        vpxor	xmm0, xmm0, xmm4
        ; ghash_gfmul_avx
        vpshufd	xmm5, xmm0, 78
        vpshufd	xmm6, xmm1, 78
        vpclmulqdq	xmm7, xmm1, xmm0, 17
        vpclmulqdq	xmm4, xmm1, xmm0, 0
        vpxor	xmm5, xmm5, xmm0
        vpxor	xmm6, xmm6, xmm1
        vpclmulqdq	xmm5, xmm5, xmm6, 0
        vpxor	xmm5, xmm5, xmm4
        vpxor	xmm5, xmm5, xmm7
        vmovdqa	xmm3, xmm4
        vmovdqa	xmm0, xmm7
        vpslldq	xmm6, xmm5, 8
        vpsrldq	xmm5, xmm5, 8
        vpxor	xmm3, xmm3, xmm6
        vpxor	xmm0, xmm0, xmm5
        vpsrld	xmm4, xmm3, 31
        vpsrld	xmm5, xmm0, 31
        vpslld	xmm3, xmm3, 1
        vpslld	xmm0, xmm0, 1
        vpsrldq	xmm6, xmm4, 12
        vpslldq	xmm4, xmm4, 4
        vpslldq	xmm5, xmm5, 4
        vpor	xmm0, xmm0, xmm6
        vpor	xmm3, xmm3, xmm4
        vpor	xmm0, xmm0, xmm5
        vpslld	xmm4, xmm3, 31
        vpslld	xmm5, xmm3, 30
        vpslld	xmm6, xmm3, 25
        vpxor	xmm4, xmm4, xmm5
        vpxor	xmm4, xmm4, xmm6
        vmovdqa	xmm5, xmm4
        vpsrldq	xmm5, xmm5, 4
        vpslldq	xmm4, xmm4, 12
        vpxor	xmm3, xmm3, xmm4
        vpsrld	xmm6, xmm3, 1
        vpsrld	xmm7, xmm3, 2
        vpsrld	xmm4, xmm3, 7
        vpxor	xmm6, xmm6, xmm7
        vpxor	xmm6, xmm6, xmm4
        vpxor	xmm6, xmm6, xmm5
        vpxor	xmm6, xmm6, xmm3
        vpxor	xmm0, xmm0, xmm6
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx1_bswap_mask
        ;   Encrypt counter
        vmovdqa	xmm4, OWORD PTR [ebp]
        vpxor	xmm4, xmm4, xmm0
        vaesenc	xmm4, xmm4, [ebp+16]
        vaesenc	xmm4, xmm4, [ebp+32]
        vaesenc	xmm4, xmm4, [ebp+48]
        vaesenc	xmm4, xmm4, [ebp+64]
        vaesenc	xmm4, xmm4, [ebp+80]
        vaesenc	xmm4, xmm4, [ebp+96]
        vaesenc	xmm4, xmm4, [ebp+112]
        vaesenc	xmm4, xmm4, [ebp+128]
        vaesenc	xmm4, xmm4, [ebp+144]
        cmp	DWORD PTR [esp+172], 11
        vmovdqa	xmm5, OWORD PTR [ebp+160]
        jl	L_AES_GCM_encrypt_avx1_calc_iv_2_aesenc_avx_last
        vaesenc	xmm4, xmm4, xmm5
        vaesenc	xmm4, xmm4, [ebp+176]
        cmp	DWORD PTR [esp+172], 13
        vmovdqa	xmm5, OWORD PTR [ebp+192]
        jl	L_AES_GCM_encrypt_avx1_calc_iv_2_aesenc_avx_last
        vaesenc	xmm4, xmm4, xmm5
        vaesenc	xmm4, xmm4, [ebp+208]
        vmovdqa	xmm5, OWORD PTR [ebp+224]
L_AES_GCM_encrypt_avx1_calc_iv_2_aesenc_avx_last:
        vaesenclast	xmm4, xmm4, xmm5
        vmovdqu	OWORD PTR [esp+80], xmm4
L_AES_GCM_encrypt_avx1_iv_done:
        mov	esi, DWORD PTR [esp+140]
        ; Additional authentication data
        mov	edx, DWORD PTR [esp+156]
        cmp	edx, 0
        je	L_AES_GCM_encrypt_avx1_calc_aad_done
        xor	ecx, ecx
        cmp	edx, 16
        jl	L_AES_GCM_encrypt_avx1_calc_aad_lt16
        and	edx, 4294967280
L_AES_GCM_encrypt_avx1_calc_aad_16_loop:
        vmovdqu	xmm4, OWORD PTR [esi+ecx]
        vpshufb	xmm4, xmm4, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm2, xmm2, xmm4
        ; ghash_gfmul_avx
        vpshufd	xmm5, xmm2, 78
        vpshufd	xmm6, xmm1, 78
        vpclmulqdq	xmm7, xmm1, xmm2, 17
        vpclmulqdq	xmm4, xmm1, xmm2, 0
        vpxor	xmm5, xmm5, xmm2
        vpxor	xmm6, xmm6, xmm1
        vpclmulqdq	xmm5, xmm5, xmm6, 0
        vpxor	xmm5, xmm5, xmm4
        vpxor	xmm5, xmm5, xmm7
        vmovdqa	xmm3, xmm4
        vmovdqa	xmm2, xmm7
        vpslldq	xmm6, xmm5, 8
        vpsrldq	xmm5, xmm5, 8
        vpxor	xmm3, xmm3, xmm6
        vpxor	xmm2, xmm2, xmm5
        vpsrld	xmm4, xmm3, 31
        vpsrld	xmm5, xmm2, 31
        vpslld	xmm3, xmm3, 1
        vpslld	xmm2, xmm2, 1
        vpsrldq	xmm6, xmm4, 12
        vpslldq	xmm4, xmm4, 4
        vpslldq	xmm5, xmm5, 4
        vpor	xmm2, xmm2, xmm6
        vpor	xmm3, xmm3, xmm4
        vpor	xmm2, xmm2, xmm5
        vpslld	xmm4, xmm3, 31
        vpslld	xmm5, xmm3, 30
        vpslld	xmm6, xmm3, 25
        vpxor	xmm4, xmm4, xmm5
        vpxor	xmm4, xmm4, xmm6
        vmovdqa	xmm5, xmm4
        vpsrldq	xmm5, xmm5, 4
        vpslldq	xmm4, xmm4, 12
        vpxor	xmm3, xmm3, xmm4
        vpsrld	xmm6, xmm3, 1
        vpsrld	xmm7, xmm3, 2
        vpsrld	xmm4, xmm3, 7
        vpxor	xmm6, xmm6, xmm7
        vpxor	xmm6, xmm6, xmm4
        vpxor	xmm6, xmm6, xmm5
        vpxor	xmm6, xmm6, xmm3
        vpxor	xmm2, xmm2, xmm6
        add	ecx, 16
        cmp	ecx, edx
        jl	L_AES_GCM_encrypt_avx1_calc_aad_16_loop
        mov	edx, DWORD PTR [esp+156]
        cmp	ecx, edx
        je	L_AES_GCM_encrypt_avx1_calc_aad_done
L_AES_GCM_encrypt_avx1_calc_aad_lt16:
        sub	esp, 16
        vpxor	xmm4, xmm4, xmm4
        xor	ebx, ebx
        vmovdqu	OWORD PTR [esp], xmm4
L_AES_GCM_encrypt_avx1_calc_aad_loop:
        movzx	eax, BYTE PTR [esi+ecx]
        mov	BYTE PTR [esp+ebx], al
        inc	ecx
        inc	ebx
        cmp	ecx, edx
        jl	L_AES_GCM_encrypt_avx1_calc_aad_loop
        vmovdqu	xmm4, OWORD PTR [esp]
        add	esp, 16
        vpshufb	xmm4, xmm4, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm2, xmm2, xmm4
        ; ghash_gfmul_avx
        vpshufd	xmm5, xmm2, 78
        vpshufd	xmm6, xmm1, 78
        vpclmulqdq	xmm7, xmm1, xmm2, 17
        vpclmulqdq	xmm4, xmm1, xmm2, 0
        vpxor	xmm5, xmm5, xmm2
        vpxor	xmm6, xmm6, xmm1
        vpclmulqdq	xmm5, xmm5, xmm6, 0
        vpxor	xmm5, xmm5, xmm4
        vpxor	xmm5, xmm5, xmm7
        vmovdqa	xmm3, xmm4
        vmovdqa	xmm2, xmm7
        vpslldq	xmm6, xmm5, 8
        vpsrldq	xmm5, xmm5, 8
        vpxor	xmm3, xmm3, xmm6
        vpxor	xmm2, xmm2, xmm5
        vpsrld	xmm4, xmm3, 31
        vpsrld	xmm5, xmm2, 31
        vpslld	xmm3, xmm3, 1
        vpslld	xmm2, xmm2, 1
        vpsrldq	xmm6, xmm4, 12
        vpslldq	xmm4, xmm4, 4
        vpslldq	xmm5, xmm5, 4
        vpor	xmm2, xmm2, xmm6
        vpor	xmm3, xmm3, xmm4
        vpor	xmm2, xmm2, xmm5
        vpslld	xmm4, xmm3, 31
        vpslld	xmm5, xmm3, 30
        vpslld	xmm6, xmm3, 25
        vpxor	xmm4, xmm4, xmm5
        vpxor	xmm4, xmm4, xmm6
        vmovdqa	xmm5, xmm4
        vpsrldq	xmm5, xmm5, 4
        vpslldq	xmm4, xmm4, 12
        vpxor	xmm3, xmm3, xmm4
        vpsrld	xmm6, xmm3, 1
        vpsrld	xmm7, xmm3, 2
        vpsrld	xmm4, xmm3, 7
        vpxor	xmm6, xmm6, xmm7
        vpxor	xmm6, xmm6, xmm4
        vpxor	xmm6, xmm6, xmm5
        vpxor	xmm6, xmm6, xmm3
        vpxor	xmm2, xmm2, xmm6
L_AES_GCM_encrypt_avx1_calc_aad_done:
        vmovdqu	OWORD PTR [esp+96], xmm2
        mov	esi, DWORD PTR [esp+132]
        mov	edi, DWORD PTR [esp+136]
        ; Calculate counter and H
        vpsrlq	xmm5, xmm1, 63
        vpsllq	xmm4, xmm1, 1
        vpslldq	xmm5, xmm5, 8
        vpor	xmm4, xmm4, xmm5
        vpshufd	xmm1, xmm1, 255
        vpsrad	xmm1, xmm1, 31
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx1_bswap_epi64
        vpand	xmm1, xmm1, OWORD PTR L_aes_gcm_avx1_mod2_128
        vpaddd	xmm0, xmm0, OWORD PTR L_aes_gcm_avx1_one
        vpxor	xmm1, xmm1, xmm4
        vmovdqu	OWORD PTR [esp+64], xmm0
        xor	ebx, ebx
        cmp	DWORD PTR [esp+152], 64
        mov	eax, DWORD PTR [esp+152]
        jl	L_AES_GCM_encrypt_avx1_done_64
        and	eax, 4294967232
        vmovdqa	xmm6, xmm2
        ; H ^ 1
        vmovdqu	OWORD PTR [esp], xmm1
        ; H ^ 2
        vpclmulqdq	xmm4, xmm1, xmm1, 0
        vpclmulqdq	xmm0, xmm1, xmm1, 17
        vpslld	xmm5, xmm4, 31
        vpslld	xmm6, xmm4, 30
        vpslld	xmm7, xmm4, 25
        vpxor	xmm5, xmm5, xmm6
        vpxor	xmm5, xmm5, xmm7
        vpsrldq	xmm7, xmm5, 4
        vpslldq	xmm5, xmm5, 12
        vpxor	xmm4, xmm4, xmm5
        vpsrld	xmm5, xmm4, 1
        vpsrld	xmm6, xmm4, 2
        vpxor	xmm5, xmm5, xmm6
        vpxor	xmm5, xmm5, xmm4
        vpsrld	xmm4, xmm4, 7
        vpxor	xmm5, xmm5, xmm7
        vpxor	xmm5, xmm5, xmm4
        vpxor	xmm0, xmm0, xmm5
        vmovdqu	OWORD PTR [esp+16], xmm0
        ; H ^ 3
        ; ghash_gfmul_red_avx
        vpshufd	xmm5, xmm1, 78
        vpshufd	xmm6, xmm0, 78
        vpclmulqdq	xmm7, xmm0, xmm1, 17
        vpclmulqdq	xmm4, xmm0, xmm1, 0
        vpxor	xmm5, xmm5, xmm1
        vpxor	xmm6, xmm6, xmm0
        vpclmulqdq	xmm5, xmm5, xmm6, 0
        vpxor	xmm5, xmm5, xmm4
        vpxor	xmm5, xmm5, xmm7
        vpslldq	xmm6, xmm5, 8
        vpsrldq	xmm5, xmm5, 8
        vpxor	xmm4, xmm4, xmm6
        vpxor	xmm3, xmm7, xmm5
        vpslld	xmm5, xmm4, 31
        vpslld	xmm6, xmm4, 30
        vpslld	xmm7, xmm4, 25
        vpxor	xmm5, xmm5, xmm6
        vpxor	xmm5, xmm5, xmm7
        vpsrldq	xmm7, xmm5, 4
        vpslldq	xmm5, xmm5, 12
        vpxor	xmm4, xmm4, xmm5
        vpsrld	xmm5, xmm4, 1
        vpsrld	xmm6, xmm4, 2
        vpxor	xmm5, xmm5, xmm6
        vpxor	xmm5, xmm5, xmm4
        vpsrld	xmm4, xmm4, 7
        vpxor	xmm5, xmm5, xmm7
        vpxor	xmm5, xmm5, xmm4
        vpxor	xmm3, xmm3, xmm5
        vmovdqu	OWORD PTR [esp+32], xmm3
        ; H ^ 4
        vpclmulqdq	xmm4, xmm0, xmm0, 0
        vpclmulqdq	xmm3, xmm0, xmm0, 17
        vpslld	xmm5, xmm4, 31
        vpslld	xmm6, xmm4, 30
        vpslld	xmm7, xmm4, 25
        vpxor	xmm5, xmm5, xmm6
        vpxor	xmm5, xmm5, xmm7
        vpsrldq	xmm7, xmm5, 4
        vpslldq	xmm5, xmm5, 12
        vpxor	xmm4, xmm4, xmm5
        vpsrld	xmm5, xmm4, 1
        vpsrld	xmm6, xmm4, 2
        vpxor	xmm5, xmm5, xmm6
        vpxor	xmm5, xmm5, xmm4
        vpsrld	xmm4, xmm4, 7
        vpxor	xmm5, xmm5, xmm7
        vpxor	xmm5, xmm5, xmm4
        vpxor	xmm3, xmm3, xmm5
        vmovdqu	OWORD PTR [esp+48], xmm3
        ; First 64 bytes of input
        vmovdqu	xmm4, OWORD PTR [esp+64]
        vpaddd	xmm3, xmm4, OWORD PTR L_aes_gcm_avx1_four
        vmovdqu	OWORD PTR [esp+64], xmm3
        vmovdqa	xmm3, OWORD PTR L_aes_gcm_avx1_bswap_epi64
        vpaddd	xmm5, xmm4, OWORD PTR L_aes_gcm_avx1_one
        vpshufb	xmm5, xmm5, xmm3
        vpaddd	xmm6, xmm4, OWORD PTR L_aes_gcm_avx1_two
        vpshufb	xmm6, xmm6, xmm3
        vpaddd	xmm7, xmm4, OWORD PTR L_aes_gcm_avx1_three
        vpshufb	xmm7, xmm7, xmm3
        vpshufb	xmm4, xmm4, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp]
        vpxor	xmm4, xmm4, xmm3
        vpxor	xmm5, xmm5, xmm3
        vpxor	xmm6, xmm6, xmm3
        vpxor	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+16]
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+32]
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+48]
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+64]
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+80]
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+96]
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+112]
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+128]
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+144]
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        cmp	DWORD PTR [esp+172], 11
        vmovdqa	xmm3, OWORD PTR [ebp+160]
        jl	L_AES_GCM_encrypt_avx1_aesenc_64_enc_done
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+176]
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        cmp	DWORD PTR [esp+172], 13
        vmovdqa	xmm3, OWORD PTR [ebp+192]
        jl	L_AES_GCM_encrypt_avx1_aesenc_64_enc_done
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+208]
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+224]
L_AES_GCM_encrypt_avx1_aesenc_64_enc_done:
        vaesenclast	xmm4, xmm4, xmm3
        vaesenclast	xmm5, xmm5, xmm3
        vmovdqu	xmm0, OWORD PTR [esi]
        vmovdqu	xmm1, OWORD PTR [esi+16]
        vpxor	xmm4, xmm4, xmm0
        vpxor	xmm5, xmm5, xmm1
        vmovdqu	OWORD PTR [edi], xmm4
        vmovdqu	OWORD PTR [edi+16], xmm5
        vaesenclast	xmm6, xmm6, xmm3
        vaesenclast	xmm7, xmm7, xmm3
        vmovdqu	xmm0, OWORD PTR [esi+32]
        vmovdqu	xmm1, OWORD PTR [esi+48]
        vpxor	xmm6, xmm6, xmm0
        vpxor	xmm7, xmm7, xmm1
        vmovdqu	OWORD PTR [edi+32], xmm6
        vmovdqu	OWORD PTR [edi+48], xmm7
        cmp	eax, 64
        mov	ebx, 64
        mov	ecx, esi
        mov	edx, edi
        jle	L_AES_GCM_encrypt_avx1_end_64
        ; More 64 bytes of input
L_AES_GCM_encrypt_avx1_ghash_64:
        lea	ecx, DWORD PTR [esi+ebx]
        lea	edx, DWORD PTR [edi+ebx]
        vmovdqu	xmm4, OWORD PTR [esp+64]
        vpaddd	xmm3, xmm4, OWORD PTR L_aes_gcm_avx1_four
        vmovdqu	OWORD PTR [esp+64], xmm3
        vmovdqa	xmm3, OWORD PTR L_aes_gcm_avx1_bswap_epi64
        vpaddd	xmm5, xmm4, OWORD PTR L_aes_gcm_avx1_one
        vpshufb	xmm5, xmm5, xmm3
        vpaddd	xmm6, xmm4, OWORD PTR L_aes_gcm_avx1_two
        vpshufb	xmm6, xmm6, xmm3
        vpaddd	xmm7, xmm4, OWORD PTR L_aes_gcm_avx1_three
        vpshufb	xmm7, xmm7, xmm3
        vpshufb	xmm4, xmm4, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp]
        vpxor	xmm4, xmm4, xmm3
        vpxor	xmm5, xmm5, xmm3
        vpxor	xmm6, xmm6, xmm3
        vpxor	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+16]
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+32]
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+48]
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+64]
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+80]
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+96]
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+112]
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+128]
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+144]
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        cmp	DWORD PTR [esp+172], 11
        vmovdqa	xmm3, OWORD PTR [ebp+160]
        jl	L_AES_GCM_encrypt_avx1_aesenc_64_ghash_avx_aesenc_64_enc_done
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+176]
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        cmp	DWORD PTR [esp+172], 13
        vmovdqa	xmm3, OWORD PTR [ebp+192]
        jl	L_AES_GCM_encrypt_avx1_aesenc_64_ghash_avx_aesenc_64_enc_done
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+208]
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+224]
L_AES_GCM_encrypt_avx1_aesenc_64_ghash_avx_aesenc_64_enc_done:
        vaesenclast	xmm4, xmm4, xmm3
        vaesenclast	xmm5, xmm5, xmm3
        vmovdqu	xmm0, OWORD PTR [ecx]
        vmovdqu	xmm1, OWORD PTR [ecx+16]
        vpxor	xmm4, xmm4, xmm0
        vpxor	xmm5, xmm5, xmm1
        vmovdqu	OWORD PTR [edx], xmm4
        vmovdqu	OWORD PTR [edx+16], xmm5
        vaesenclast	xmm6, xmm6, xmm3
        vaesenclast	xmm7, xmm7, xmm3
        vmovdqu	xmm0, OWORD PTR [ecx+32]
        vmovdqu	xmm1, OWORD PTR [ecx+48]
        vpxor	xmm6, xmm6, xmm0
        vpxor	xmm7, xmm7, xmm1
        vmovdqu	OWORD PTR [edx+32], xmm6
        vmovdqu	OWORD PTR [edx+48], xmm7
        ; ghash encrypted counter
        vmovdqu	xmm6, OWORD PTR [esp+96]
        vmovdqu	xmm3, OWORD PTR [esp+48]
        vmovdqu	xmm4, OWORD PTR [edx+-64]
        vpshufb	xmm4, xmm4, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm4, xmm4, xmm6
        vpshufd	xmm5, xmm3, 78
        vpshufd	xmm1, xmm4, 78
        vpxor	xmm5, xmm5, xmm3
        vpxor	xmm1, xmm1, xmm4
        vpclmulqdq	xmm7, xmm4, xmm3, 17
        vpclmulqdq	xmm6, xmm4, xmm3, 0
        vpclmulqdq	xmm5, xmm5, xmm1, 0
        vpxor	xmm5, xmm5, xmm6
        vpxor	xmm5, xmm5, xmm7
        vmovdqu	xmm3, OWORD PTR [esp+32]
        vmovdqu	xmm4, OWORD PTR [edx+-48]
        vpshufd	xmm0, xmm3, 78
        vpshufb	xmm4, xmm4, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm0, xmm0, xmm3
        vpshufd	xmm1, xmm4, 78
        vpxor	xmm1, xmm1, xmm4
        vpclmulqdq	xmm2, xmm4, xmm3, 17
        vpclmulqdq	xmm3, xmm4, xmm3, 0
        vpclmulqdq	xmm0, xmm0, xmm1, 0
        vpxor	xmm5, xmm5, xmm3
        vpxor	xmm6, xmm6, xmm3
        vpxor	xmm5, xmm5, xmm2
        vpxor	xmm7, xmm7, xmm2
        vpxor	xmm5, xmm5, xmm0
        vmovdqu	xmm3, OWORD PTR [esp+16]
        vmovdqu	xmm4, OWORD PTR [edx+-32]
        vpshufd	xmm0, xmm3, 78
        vpshufb	xmm4, xmm4, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm0, xmm0, xmm3
        vpshufd	xmm1, xmm4, 78
        vpxor	xmm1, xmm1, xmm4
        vpclmulqdq	xmm2, xmm4, xmm3, 17
        vpclmulqdq	xmm3, xmm4, xmm3, 0
        vpclmulqdq	xmm0, xmm0, xmm1, 0
        vpxor	xmm5, xmm5, xmm3
        vpxor	xmm6, xmm6, xmm3
        vpxor	xmm5, xmm5, xmm2
        vpxor	xmm7, xmm7, xmm2
        vpxor	xmm5, xmm5, xmm0
        vmovdqu	xmm3, OWORD PTR [esp]
        vmovdqu	xmm4, OWORD PTR [edx+-16]
        vpshufd	xmm0, xmm3, 78
        vpshufb	xmm4, xmm4, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm0, xmm0, xmm3
        vpshufd	xmm1, xmm4, 78
        vpxor	xmm1, xmm1, xmm4
        vpclmulqdq	xmm2, xmm4, xmm3, 17
        vpclmulqdq	xmm3, xmm4, xmm3, 0
        vpclmulqdq	xmm0, xmm0, xmm1, 0
        vpxor	xmm5, xmm5, xmm3
        vpxor	xmm6, xmm6, xmm3
        vpxor	xmm5, xmm5, xmm2
        vpxor	xmm7, xmm7, xmm2
        vpxor	xmm5, xmm5, xmm0
        vpslldq	xmm1, xmm5, 8
        vpsrldq	xmm5, xmm5, 8
        vpxor	xmm6, xmm6, xmm1
        vpxor	xmm7, xmm7, xmm5
        vpslld	xmm3, xmm6, 31
        vpslld	xmm0, xmm6, 30
        vpslld	xmm1, xmm6, 25
        vpxor	xmm3, xmm3, xmm0
        vpxor	xmm3, xmm3, xmm1
        vpsrldq	xmm0, xmm3, 4
        vpslldq	xmm3, xmm3, 12
        vpxor	xmm6, xmm6, xmm3
        vpsrld	xmm1, xmm6, 1
        vpsrld	xmm5, xmm6, 2
        vpsrld	xmm4, xmm6, 7
        vpxor	xmm1, xmm1, xmm5
        vpxor	xmm1, xmm1, xmm4
        vpxor	xmm1, xmm1, xmm0
        vpxor	xmm6, xmm6, xmm1
        vpxor	xmm6, xmm6, xmm7
        vmovdqu	OWORD PTR [esp+96], xmm6
        add	ebx, 64
        cmp	ebx, eax
        jl	L_AES_GCM_encrypt_avx1_ghash_64
L_AES_GCM_encrypt_avx1_end_64:
        vmovdqu	xmm2, OWORD PTR [esp+96]
        ; Block 1
        vmovdqa	xmm4, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vmovdqu	xmm1, OWORD PTR [edx]
        vpshufb	xmm1, xmm1, xmm4
        vmovdqu	xmm3, OWORD PTR [esp+48]
        vpxor	xmm1, xmm1, xmm2
        ; ghash_gfmul_avx
        vpshufd	xmm5, xmm1, 78
        vpshufd	xmm6, xmm3, 78
        vpclmulqdq	xmm7, xmm3, xmm1, 17
        vpclmulqdq	xmm4, xmm3, xmm1, 0
        vpxor	xmm5, xmm5, xmm1
        vpxor	xmm6, xmm6, xmm3
        vpclmulqdq	xmm5, xmm5, xmm6, 0
        vpxor	xmm5, xmm5, xmm4
        vpxor	xmm5, xmm5, xmm7
        vmovdqa	xmm0, xmm4
        vmovdqa	xmm2, xmm7
        vpslldq	xmm6, xmm5, 8
        vpsrldq	xmm5, xmm5, 8
        vpxor	xmm0, xmm0, xmm6
        vpxor	xmm2, xmm2, xmm5
        ; Block 2
        vmovdqa	xmm4, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vmovdqu	xmm1, OWORD PTR [edx+16]
        vpshufb	xmm1, xmm1, xmm4
        vmovdqu	xmm3, OWORD PTR [esp+32]
        ; ghash_gfmul_xor_avx
        vpshufd	xmm5, xmm1, 78
        vpshufd	xmm6, xmm3, 78
        vpclmulqdq	xmm7, xmm3, xmm1, 17
        vpclmulqdq	xmm4, xmm3, xmm1, 0
        vpxor	xmm5, xmm5, xmm1
        vpxor	xmm6, xmm6, xmm3
        vpclmulqdq	xmm5, xmm5, xmm6, 0
        vpxor	xmm5, xmm5, xmm4
        vpxor	xmm5, xmm5, xmm7
        vpxor	xmm0, xmm0, xmm4
        vpxor	xmm2, xmm2, xmm7
        vpslldq	xmm6, xmm5, 8
        vpsrldq	xmm5, xmm5, 8
        vpxor	xmm0, xmm0, xmm6
        vpxor	xmm2, xmm2, xmm5
        ; Block 3
        vmovdqa	xmm4, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vmovdqu	xmm1, OWORD PTR [edx+32]
        vpshufb	xmm1, xmm1, xmm4
        vmovdqu	xmm3, OWORD PTR [esp+16]
        ; ghash_gfmul_xor_avx
        vpshufd	xmm5, xmm1, 78
        vpshufd	xmm6, xmm3, 78
        vpclmulqdq	xmm7, xmm3, xmm1, 17
        vpclmulqdq	xmm4, xmm3, xmm1, 0
        vpxor	xmm5, xmm5, xmm1
        vpxor	xmm6, xmm6, xmm3
        vpclmulqdq	xmm5, xmm5, xmm6, 0
        vpxor	xmm5, xmm5, xmm4
        vpxor	xmm5, xmm5, xmm7
        vpxor	xmm0, xmm0, xmm4
        vpxor	xmm2, xmm2, xmm7
        vpslldq	xmm6, xmm5, 8
        vpsrldq	xmm5, xmm5, 8
        vpxor	xmm0, xmm0, xmm6
        vpxor	xmm2, xmm2, xmm5
        ; Block 4
        vmovdqa	xmm4, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vmovdqu	xmm1, OWORD PTR [edx+48]
        vpshufb	xmm1, xmm1, xmm4
        vmovdqu	xmm3, OWORD PTR [esp]
        ; ghash_gfmul_xor_avx
        vpshufd	xmm5, xmm1, 78
        vpshufd	xmm6, xmm3, 78
        vpclmulqdq	xmm7, xmm3, xmm1, 17
        vpclmulqdq	xmm4, xmm3, xmm1, 0
        vpxor	xmm5, xmm5, xmm1
        vpxor	xmm6, xmm6, xmm3
        vpclmulqdq	xmm5, xmm5, xmm6, 0
        vpxor	xmm5, xmm5, xmm4
        vpxor	xmm5, xmm5, xmm7
        vpxor	xmm0, xmm0, xmm4
        vpxor	xmm2, xmm2, xmm7
        vpslldq	xmm6, xmm5, 8
        vpsrldq	xmm5, xmm5, 8
        vpxor	xmm0, xmm0, xmm6
        vpxor	xmm2, xmm2, xmm5
        vpslld	xmm4, xmm0, 31
        vpslld	xmm5, xmm0, 30
        vpslld	xmm6, xmm0, 25
        vpxor	xmm4, xmm4, xmm5
        vpxor	xmm4, xmm4, xmm6
        vmovdqa	xmm5, xmm4
        vpsrldq	xmm5, xmm5, 4
        vpslldq	xmm4, xmm4, 12
        vpxor	xmm0, xmm0, xmm4
        vpsrld	xmm6, xmm0, 1
        vpsrld	xmm7, xmm0, 2
        vpsrld	xmm4, xmm0, 7
        vpxor	xmm6, xmm6, xmm7
        vpxor	xmm6, xmm6, xmm4
        vpxor	xmm6, xmm6, xmm5
        vpxor	xmm6, xmm6, xmm0
        vpxor	xmm2, xmm2, xmm6
        vmovdqu	xmm1, OWORD PTR [esp]
L_AES_GCM_encrypt_avx1_done_64:
        mov	edx, DWORD PTR [esp+152]
        cmp	ebx, edx
        jge	L_AES_GCM_encrypt_avx1_done_enc
        mov	eax, DWORD PTR [esp+152]
        and	eax, 4294967280
        cmp	ebx, eax
        jge	L_AES_GCM_encrypt_avx1_last_block_done
        lea	ecx, DWORD PTR [esi+ebx]
        lea	edx, DWORD PTR [edi+ebx]
        vmovdqu	xmm5, OWORD PTR [esp+64]
        vpshufb	xmm4, xmm5, OWORD PTR L_aes_gcm_avx1_bswap_epi64
        vpaddd	xmm5, xmm5, OWORD PTR L_aes_gcm_avx1_one
        vmovdqu	OWORD PTR [esp+64], xmm5
        vpxor	xmm4, xmm4, [ebp]
        vaesenc	xmm4, xmm4, [ebp+16]
        vaesenc	xmm4, xmm4, [ebp+32]
        vaesenc	xmm4, xmm4, [ebp+48]
        vaesenc	xmm4, xmm4, [ebp+64]
        vaesenc	xmm4, xmm4, [ebp+80]
        vaesenc	xmm4, xmm4, [ebp+96]
        vaesenc	xmm4, xmm4, [ebp+112]
        vaesenc	xmm4, xmm4, [ebp+128]
        vaesenc	xmm4, xmm4, [ebp+144]
        cmp	DWORD PTR [esp+172], 11
        vmovdqa	xmm5, OWORD PTR [ebp+160]
        jl	L_AES_GCM_encrypt_avx1_aesenc_block_aesenc_avx_last
        vaesenc	xmm4, xmm4, xmm5
        vaesenc	xmm4, xmm4, [ebp+176]
        cmp	DWORD PTR [esp+172], 13
        vmovdqa	xmm5, OWORD PTR [ebp+192]
        jl	L_AES_GCM_encrypt_avx1_aesenc_block_aesenc_avx_last
        vaesenc	xmm4, xmm4, xmm5
        vaesenc	xmm4, xmm4, [ebp+208]
        vmovdqa	xmm5, OWORD PTR [ebp+224]
L_AES_GCM_encrypt_avx1_aesenc_block_aesenc_avx_last:
        vaesenclast	xmm4, xmm4, xmm5
        vmovdqu	xmm5, OWORD PTR [ecx]
        vpxor	xmm4, xmm4, xmm5
        vmovdqu	OWORD PTR [edx], xmm4
        vpshufb	xmm4, xmm4, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm2, xmm2, xmm4
        add	ebx, 16
        cmp	ebx, eax
        jge	L_AES_GCM_encrypt_avx1_last_block_ghash
L_AES_GCM_encrypt_avx1_last_block_start:
        lea	ecx, DWORD PTR [esi+ebx]
        lea	edx, DWORD PTR [edi+ebx]
        vmovdqu	xmm5, OWORD PTR [esp+64]
        vmovdqu	xmm7, xmm2
        vpshufb	xmm4, xmm5, OWORD PTR L_aes_gcm_avx1_bswap_epi64
        vpaddd	xmm5, xmm5, OWORD PTR L_aes_gcm_avx1_one
        vmovdqu	OWORD PTR [esp+64], xmm5
        vpxor	xmm4, xmm4, [ebp]
        vpclmulqdq	xmm0, xmm7, xmm1, 16
        vaesenc	xmm4, xmm4, [ebp+16]
        vaesenc	xmm4, xmm4, [ebp+32]
        vpclmulqdq	xmm3, xmm7, xmm1, 1
        vaesenc	xmm4, xmm4, [ebp+48]
        vaesenc	xmm4, xmm4, [ebp+64]
        vaesenc	xmm4, xmm4, [ebp+80]
        vpclmulqdq	xmm5, xmm7, xmm1, 17
        vaesenc	xmm4, xmm4, [ebp+96]
        vpxor	xmm0, xmm0, xmm3
        vpslldq	xmm6, xmm0, 8
        vpsrldq	xmm0, xmm0, 8
        vaesenc	xmm4, xmm4, [ebp+112]
        vpclmulqdq	xmm3, xmm7, xmm1, 0
        vpxor	xmm6, xmm6, xmm3
        vpxor	xmm5, xmm5, xmm0
        vmovdqa	xmm7, OWORD PTR L_aes_gcm_avx1_mod2_128
        vpclmulqdq	xmm3, xmm6, xmm7, 16
        vaesenc	xmm4, xmm4, [ebp+128]
        vpshufd	xmm0, xmm6, 78
        vpxor	xmm0, xmm0, xmm3
        vpclmulqdq	xmm3, xmm0, xmm7, 16
        vaesenc	xmm4, xmm4, [ebp+144]
        vpshufd	xmm2, xmm0, 78
        vpxor	xmm2, xmm2, xmm3
        vpxor	xmm2, xmm2, xmm5
        cmp	DWORD PTR [esp+172], 11
        vmovdqa	xmm5, OWORD PTR [ebp+160]
        jl	L_AES_GCM_encrypt_avx1_aesenc_gfmul_last
        vaesenc	xmm4, xmm4, xmm5
        vaesenc	xmm4, xmm4, [ebp+176]
        cmp	DWORD PTR [esp+172], 13
        vmovdqa	xmm5, OWORD PTR [ebp+192]
        jl	L_AES_GCM_encrypt_avx1_aesenc_gfmul_last
        vaesenc	xmm4, xmm4, xmm5
        vaesenc	xmm4, xmm4, [ebp+208]
        vmovdqa	xmm5, OWORD PTR [ebp+224]
L_AES_GCM_encrypt_avx1_aesenc_gfmul_last:
        vaesenclast	xmm4, xmm4, xmm5
        vmovdqu	xmm5, OWORD PTR [ecx]
        vpxor	xmm4, xmm4, xmm5
        vmovdqu	OWORD PTR [edx], xmm4
        vpshufb	xmm4, xmm4, OWORD PTR L_aes_gcm_avx1_bswap_mask
        add	ebx, 16
        vpxor	xmm2, xmm2, xmm4
        cmp	ebx, eax
        jl	L_AES_GCM_encrypt_avx1_last_block_start
L_AES_GCM_encrypt_avx1_last_block_ghash:
        ; ghash_gfmul_red_avx
        vpshufd	xmm5, xmm1, 78
        vpshufd	xmm6, xmm2, 78
        vpclmulqdq	xmm7, xmm2, xmm1, 17
        vpclmulqdq	xmm4, xmm2, xmm1, 0
        vpxor	xmm5, xmm5, xmm1
        vpxor	xmm6, xmm6, xmm2
        vpclmulqdq	xmm5, xmm5, xmm6, 0
        vpxor	xmm5, xmm5, xmm4
        vpxor	xmm5, xmm5, xmm7
        vpslldq	xmm6, xmm5, 8
        vpsrldq	xmm5, xmm5, 8
        vpxor	xmm4, xmm4, xmm6
        vpxor	xmm2, xmm7, xmm5
        vpslld	xmm5, xmm4, 31
        vpslld	xmm6, xmm4, 30
        vpslld	xmm7, xmm4, 25
        vpxor	xmm5, xmm5, xmm6
        vpxor	xmm5, xmm5, xmm7
        vpsrldq	xmm7, xmm5, 4
        vpslldq	xmm5, xmm5, 12
        vpxor	xmm4, xmm4, xmm5
        vpsrld	xmm5, xmm4, 1
        vpsrld	xmm6, xmm4, 2
        vpxor	xmm5, xmm5, xmm6
        vpxor	xmm5, xmm5, xmm4
        vpsrld	xmm4, xmm4, 7
        vpxor	xmm5, xmm5, xmm7
        vpxor	xmm5, xmm5, xmm4
        vpxor	xmm2, xmm2, xmm5
L_AES_GCM_encrypt_avx1_last_block_done:
        mov	ecx, DWORD PTR [esp+152]
        mov	edx, ecx
        and	ecx, 15
        jz	L_AES_GCM_encrypt_avx1_aesenc_last15_enc_avx_done
        vmovdqu	xmm0, OWORD PTR [esp+64]
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx1_bswap_epi64
        vpxor	xmm0, xmm0, [ebp]
        vaesenc	xmm0, xmm0, [ebp+16]
        vaesenc	xmm0, xmm0, [ebp+32]
        vaesenc	xmm0, xmm0, [ebp+48]
        vaesenc	xmm0, xmm0, [ebp+64]
        vaesenc	xmm0, xmm0, [ebp+80]
        vaesenc	xmm0, xmm0, [ebp+96]
        vaesenc	xmm0, xmm0, [ebp+112]
        vaesenc	xmm0, xmm0, [ebp+128]
        vaesenc	xmm0, xmm0, [ebp+144]
        cmp	DWORD PTR [esp+172], 11
        vmovdqa	xmm5, OWORD PTR [ebp+160]
        jl	L_AES_GCM_encrypt_avx1_aesenc_last15_enc_avx_aesenc_avx_last
        vaesenc	xmm0, xmm0, xmm5
        vaesenc	xmm0, xmm0, [ebp+176]
        cmp	DWORD PTR [esp+172], 13
        vmovdqa	xmm5, OWORD PTR [ebp+192]
        jl	L_AES_GCM_encrypt_avx1_aesenc_last15_enc_avx_aesenc_avx_last
        vaesenc	xmm0, xmm0, xmm5
        vaesenc	xmm0, xmm0, [ebp+208]
        vmovdqa	xmm5, OWORD PTR [ebp+224]
L_AES_GCM_encrypt_avx1_aesenc_last15_enc_avx_aesenc_avx_last:
        vaesenclast	xmm0, xmm0, xmm5
        sub	esp, 16
        xor	ecx, ecx
        vmovdqu	OWORD PTR [esp], xmm0
L_AES_GCM_encrypt_avx1_aesenc_last15_enc_avx_loop:
        movzx	eax, BYTE PTR [esi+ebx]
        xor	al, BYTE PTR [esp+ecx]
        mov	BYTE PTR [edi+ebx], al
        mov	BYTE PTR [esp+ecx], al
        inc	ebx
        inc	ecx
        cmp	ebx, edx
        jl	L_AES_GCM_encrypt_avx1_aesenc_last15_enc_avx_loop
        xor	eax, eax
        cmp	ecx, 16
        je	L_AES_GCM_encrypt_avx1_aesenc_last15_enc_avx_finish_enc
L_AES_GCM_encrypt_avx1_aesenc_last15_enc_avx_byte_loop:
        mov	BYTE PTR [esp+ecx], al
        inc	ecx
        cmp	ecx, 16
        jl	L_AES_GCM_encrypt_avx1_aesenc_last15_enc_avx_byte_loop
L_AES_GCM_encrypt_avx1_aesenc_last15_enc_avx_finish_enc:
        vmovdqu	xmm0, OWORD PTR [esp]
        add	esp, 16
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm2, xmm2, xmm0
        ; ghash_gfmul_red_avx
        vpshufd	xmm5, xmm1, 78
        vpshufd	xmm6, xmm2, 78
        vpclmulqdq	xmm7, xmm2, xmm1, 17
        vpclmulqdq	xmm4, xmm2, xmm1, 0
        vpxor	xmm5, xmm5, xmm1
        vpxor	xmm6, xmm6, xmm2
        vpclmulqdq	xmm5, xmm5, xmm6, 0
        vpxor	xmm5, xmm5, xmm4
        vpxor	xmm5, xmm5, xmm7
        vpslldq	xmm6, xmm5, 8
        vpsrldq	xmm5, xmm5, 8
        vpxor	xmm4, xmm4, xmm6
        vpxor	xmm2, xmm7, xmm5
        vpslld	xmm5, xmm4, 31
        vpslld	xmm6, xmm4, 30
        vpslld	xmm7, xmm4, 25
        vpxor	xmm5, xmm5, xmm6
        vpxor	xmm5, xmm5, xmm7
        vpsrldq	xmm7, xmm5, 4
        vpslldq	xmm5, xmm5, 12
        vpxor	xmm4, xmm4, xmm5
        vpsrld	xmm5, xmm4, 1
        vpsrld	xmm6, xmm4, 2
        vpxor	xmm5, xmm5, xmm6
        vpxor	xmm5, xmm5, xmm4
        vpsrld	xmm4, xmm4, 7
        vpxor	xmm5, xmm5, xmm7
        vpxor	xmm5, xmm5, xmm4
        vpxor	xmm2, xmm2, xmm5
L_AES_GCM_encrypt_avx1_aesenc_last15_enc_avx_done:
L_AES_GCM_encrypt_avx1_done_enc:
        mov	edi, DWORD PTR [esp+148]
        mov	ebx, DWORD PTR [esp+164]
        mov	edx, DWORD PTR [esp+152]
        mov	ecx, DWORD PTR [esp+156]
        shl	edx, 3
        shl	ecx, 3
        vpinsrd	xmm4, xmm4, edx, 0
        vpinsrd	xmm4, xmm4, ecx, 2
        mov	edx, DWORD PTR [esp+152]
        mov	ecx, DWORD PTR [esp+156]
        shr	edx, 29
        shr	ecx, 29
        vpinsrd	xmm4, xmm4, edx, 1
        vpinsrd	xmm4, xmm4, ecx, 3
        vpxor	xmm2, xmm2, xmm4
        ; ghash_gfmul_red_avx
        vpshufd	xmm5, xmm1, 78
        vpshufd	xmm6, xmm2, 78
        vpclmulqdq	xmm7, xmm2, xmm1, 17
        vpclmulqdq	xmm4, xmm2, xmm1, 0
        vpxor	xmm5, xmm5, xmm1
        vpxor	xmm6, xmm6, xmm2
        vpclmulqdq	xmm5, xmm5, xmm6, 0
        vpxor	xmm5, xmm5, xmm4
        vpxor	xmm5, xmm5, xmm7
        vpslldq	xmm6, xmm5, 8
        vpsrldq	xmm5, xmm5, 8
        vpxor	xmm4, xmm4, xmm6
        vpxor	xmm2, xmm7, xmm5
        vpslld	xmm5, xmm4, 31
        vpslld	xmm6, xmm4, 30
        vpslld	xmm7, xmm4, 25
        vpxor	xmm5, xmm5, xmm6
        vpxor	xmm5, xmm5, xmm7
        vpsrldq	xmm7, xmm5, 4
        vpslldq	xmm5, xmm5, 12
        vpxor	xmm4, xmm4, xmm5
        vpsrld	xmm5, xmm4, 1
        vpsrld	xmm6, xmm4, 2
        vpxor	xmm5, xmm5, xmm6
        vpxor	xmm5, xmm5, xmm4
        vpsrld	xmm4, xmm4, 7
        vpxor	xmm5, xmm5, xmm7
        vpxor	xmm5, xmm5, xmm4
        vpxor	xmm2, xmm2, xmm5
        vpshufb	xmm2, xmm2, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm4, xmm2, [esp+80]
        cmp	ebx, 16
        je	L_AES_GCM_encrypt_avx1_store_tag_16
        xor	ecx, ecx
        vmovdqu	OWORD PTR [esp], xmm4
L_AES_GCM_encrypt_avx1_store_tag_loop:
        movzx	eax, BYTE PTR [esp+ecx]
        mov	BYTE PTR [edi+ecx], al
        inc	ecx
        cmp	ecx, ebx
        jne	L_AES_GCM_encrypt_avx1_store_tag_loop
        jmp	L_AES_GCM_encrypt_avx1_store_tag_done
L_AES_GCM_encrypt_avx1_store_tag_16:
        vmovdqu	OWORD PTR [edi], xmm4
L_AES_GCM_encrypt_avx1_store_tag_done:
        add	esp, 112
        pop	ebp
        pop	edi
        pop	esi
        pop	ebx
        ret
AES_GCM_encrypt_avx1 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_GCM_decrypt_avx1 PROC
        push	ebx
        push	esi
        push	edi
        push	ebp
        sub	esp, 176
        mov	esi, DWORD PTR [esp+208]
        mov	ebp, DWORD PTR [esp+232]
        mov	edx, DWORD PTR [esp+224]
        vpxor	xmm0, xmm0, xmm0
        vpxor	xmm2, xmm2, xmm2
        cmp	edx, 12
        jne	L_AES_GCM_decrypt_avx1_iv_not_12
        ; # Calculate values when IV is 12 bytes
        ; Set counter based on IV
        mov	ecx, 16777216
        vpinsrd	xmm0, xmm0, DWORD PTR [esi], 0
        vpinsrd	xmm0, xmm0, DWORD PTR [esi+4], 1
        vpinsrd	xmm0, xmm0, DWORD PTR [esi+8], 2
        vpinsrd	xmm0, xmm0, ecx, 3
        ; H = Encrypt X(=0) and T = Encrypt counter
        vmovdqa	xmm1, OWORD PTR [ebp]
        vpxor	xmm5, xmm0, xmm1
        vmovdqa	xmm3, OWORD PTR [ebp+16]
        vaesenc	xmm1, xmm1, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+32]
        vaesenc	xmm1, xmm1, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+48]
        vaesenc	xmm1, xmm1, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+64]
        vaesenc	xmm1, xmm1, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+80]
        vaesenc	xmm1, xmm1, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+96]
        vaesenc	xmm1, xmm1, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+112]
        vaesenc	xmm1, xmm1, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+128]
        vaesenc	xmm1, xmm1, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+144]
        vaesenc	xmm1, xmm1, xmm3
        vaesenc	xmm5, xmm5, xmm3
        cmp	DWORD PTR [esp+236], 11
        vmovdqa	xmm3, OWORD PTR [ebp+160]
        jl	L_AES_GCM_decrypt_avx1_calc_iv_12_last
        vaesenc	xmm1, xmm1, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+176]
        vaesenc	xmm1, xmm1, xmm3
        vaesenc	xmm5, xmm5, xmm3
        cmp	DWORD PTR [esp+236], 13
        vmovdqa	xmm3, OWORD PTR [ebp+192]
        jl	L_AES_GCM_decrypt_avx1_calc_iv_12_last
        vaesenc	xmm1, xmm1, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+208]
        vaesenc	xmm1, xmm1, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+224]
L_AES_GCM_decrypt_avx1_calc_iv_12_last:
        vaesenclast	xmm1, xmm1, xmm3
        vaesenclast	xmm5, xmm5, xmm3
        vpshufb	xmm1, xmm1, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vmovdqu	OWORD PTR [esp+80], xmm5
        jmp	L_AES_GCM_decrypt_avx1_iv_done
L_AES_GCM_decrypt_avx1_iv_not_12:
        ; Calculate values when IV is not 12 bytes
        ; H = Encrypt X(=0)
        vmovdqa	xmm1, OWORD PTR [ebp]
        vaesenc	xmm1, xmm1, [ebp+16]
        vaesenc	xmm1, xmm1, [ebp+32]
        vaesenc	xmm1, xmm1, [ebp+48]
        vaesenc	xmm1, xmm1, [ebp+64]
        vaesenc	xmm1, xmm1, [ebp+80]
        vaesenc	xmm1, xmm1, [ebp+96]
        vaesenc	xmm1, xmm1, [ebp+112]
        vaesenc	xmm1, xmm1, [ebp+128]
        vaesenc	xmm1, xmm1, [ebp+144]
        cmp	DWORD PTR [esp+236], 11
        vmovdqa	xmm5, OWORD PTR [ebp+160]
        jl	L_AES_GCM_decrypt_avx1_calc_iv_1_aesenc_avx_last
        vaesenc	xmm1, xmm1, xmm5
        vaesenc	xmm1, xmm1, [ebp+176]
        cmp	DWORD PTR [esp+236], 13
        vmovdqa	xmm5, OWORD PTR [ebp+192]
        jl	L_AES_GCM_decrypt_avx1_calc_iv_1_aesenc_avx_last
        vaesenc	xmm1, xmm1, xmm5
        vaesenc	xmm1, xmm1, [ebp+208]
        vmovdqa	xmm5, OWORD PTR [ebp+224]
L_AES_GCM_decrypt_avx1_calc_iv_1_aesenc_avx_last:
        vaesenclast	xmm1, xmm1, xmm5
        vpshufb	xmm1, xmm1, OWORD PTR L_aes_gcm_avx1_bswap_mask
        ; Calc counter
        ; Initialization vector
        cmp	edx, 0
        mov	ecx, 0
        je	L_AES_GCM_decrypt_avx1_calc_iv_done
        cmp	edx, 16
        jl	L_AES_GCM_decrypt_avx1_calc_iv_lt16
        and	edx, 4294967280
L_AES_GCM_decrypt_avx1_calc_iv_16_loop:
        vmovdqu	xmm4, OWORD PTR [esi+ecx]
        vpshufb	xmm4, xmm4, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm0, xmm0, xmm4
        ; ghash_gfmul_avx
        vpshufd	xmm5, xmm0, 78
        vpshufd	xmm6, xmm1, 78
        vpclmulqdq	xmm7, xmm1, xmm0, 17
        vpclmulqdq	xmm4, xmm1, xmm0, 0
        vpxor	xmm5, xmm5, xmm0
        vpxor	xmm6, xmm6, xmm1
        vpclmulqdq	xmm5, xmm5, xmm6, 0
        vpxor	xmm5, xmm5, xmm4
        vpxor	xmm5, xmm5, xmm7
        vmovdqa	xmm3, xmm4
        vmovdqa	xmm0, xmm7
        vpslldq	xmm6, xmm5, 8
        vpsrldq	xmm5, xmm5, 8
        vpxor	xmm3, xmm3, xmm6
        vpxor	xmm0, xmm0, xmm5
        vpsrld	xmm4, xmm3, 31
        vpsrld	xmm5, xmm0, 31
        vpslld	xmm3, xmm3, 1
        vpslld	xmm0, xmm0, 1
        vpsrldq	xmm6, xmm4, 12
        vpslldq	xmm4, xmm4, 4
        vpslldq	xmm5, xmm5, 4
        vpor	xmm0, xmm0, xmm6
        vpor	xmm3, xmm3, xmm4
        vpor	xmm0, xmm0, xmm5
        vpslld	xmm4, xmm3, 31
        vpslld	xmm5, xmm3, 30
        vpslld	xmm6, xmm3, 25
        vpxor	xmm4, xmm4, xmm5
        vpxor	xmm4, xmm4, xmm6
        vmovdqa	xmm5, xmm4
        vpsrldq	xmm5, xmm5, 4
        vpslldq	xmm4, xmm4, 12
        vpxor	xmm3, xmm3, xmm4
        vpsrld	xmm6, xmm3, 1
        vpsrld	xmm7, xmm3, 2
        vpsrld	xmm4, xmm3, 7
        vpxor	xmm6, xmm6, xmm7
        vpxor	xmm6, xmm6, xmm4
        vpxor	xmm6, xmm6, xmm5
        vpxor	xmm6, xmm6, xmm3
        vpxor	xmm0, xmm0, xmm6
        add	ecx, 16
        cmp	ecx, edx
        jl	L_AES_GCM_decrypt_avx1_calc_iv_16_loop
        mov	edx, DWORD PTR [esp+224]
        cmp	ecx, edx
        je	L_AES_GCM_decrypt_avx1_calc_iv_done
L_AES_GCM_decrypt_avx1_calc_iv_lt16:
        sub	esp, 16
        vpxor	xmm4, xmm4, xmm4
        xor	ebx, ebx
        vmovdqu	OWORD PTR [esp], xmm4
L_AES_GCM_decrypt_avx1_calc_iv_loop:
        movzx	eax, BYTE PTR [esi+ecx]
        mov	BYTE PTR [esp+ebx], al
        inc	ecx
        inc	ebx
        cmp	ecx, edx
        jl	L_AES_GCM_decrypt_avx1_calc_iv_loop
        vmovdqu	xmm4, OWORD PTR [esp]
        add	esp, 16
        vpshufb	xmm4, xmm4, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm0, xmm0, xmm4
        ; ghash_gfmul_avx
        vpshufd	xmm5, xmm0, 78
        vpshufd	xmm6, xmm1, 78
        vpclmulqdq	xmm7, xmm1, xmm0, 17
        vpclmulqdq	xmm4, xmm1, xmm0, 0
        vpxor	xmm5, xmm5, xmm0
        vpxor	xmm6, xmm6, xmm1
        vpclmulqdq	xmm5, xmm5, xmm6, 0
        vpxor	xmm5, xmm5, xmm4
        vpxor	xmm5, xmm5, xmm7
        vmovdqa	xmm3, xmm4
        vmovdqa	xmm0, xmm7
        vpslldq	xmm6, xmm5, 8
        vpsrldq	xmm5, xmm5, 8
        vpxor	xmm3, xmm3, xmm6
        vpxor	xmm0, xmm0, xmm5
        vpsrld	xmm4, xmm3, 31
        vpsrld	xmm5, xmm0, 31
        vpslld	xmm3, xmm3, 1
        vpslld	xmm0, xmm0, 1
        vpsrldq	xmm6, xmm4, 12
        vpslldq	xmm4, xmm4, 4
        vpslldq	xmm5, xmm5, 4
        vpor	xmm0, xmm0, xmm6
        vpor	xmm3, xmm3, xmm4
        vpor	xmm0, xmm0, xmm5
        vpslld	xmm4, xmm3, 31
        vpslld	xmm5, xmm3, 30
        vpslld	xmm6, xmm3, 25
        vpxor	xmm4, xmm4, xmm5
        vpxor	xmm4, xmm4, xmm6
        vmovdqa	xmm5, xmm4
        vpsrldq	xmm5, xmm5, 4
        vpslldq	xmm4, xmm4, 12
        vpxor	xmm3, xmm3, xmm4
        vpsrld	xmm6, xmm3, 1
        vpsrld	xmm7, xmm3, 2
        vpsrld	xmm4, xmm3, 7
        vpxor	xmm6, xmm6, xmm7
        vpxor	xmm6, xmm6, xmm4
        vpxor	xmm6, xmm6, xmm5
        vpxor	xmm6, xmm6, xmm3
        vpxor	xmm0, xmm0, xmm6
L_AES_GCM_decrypt_avx1_calc_iv_done:
        ; T = Encrypt counter
        vpxor	xmm4, xmm4, xmm4
        shl	edx, 3
        vpinsrd	xmm4, xmm4, edx, 0
        vpxor	xmm0, xmm0, xmm4
        ; ghash_gfmul_avx
        vpshufd	xmm5, xmm0, 78
        vpshufd	xmm6, xmm1, 78
        vpclmulqdq	xmm7, xmm1, xmm0, 17
        vpclmulqdq	xmm4, xmm1, xmm0, 0
        vpxor	xmm5, xmm5, xmm0
        vpxor	xmm6, xmm6, xmm1
        vpclmulqdq	xmm5, xmm5, xmm6, 0
        vpxor	xmm5, xmm5, xmm4
        vpxor	xmm5, xmm5, xmm7
        vmovdqa	xmm3, xmm4
        vmovdqa	xmm0, xmm7
        vpslldq	xmm6, xmm5, 8
        vpsrldq	xmm5, xmm5, 8
        vpxor	xmm3, xmm3, xmm6
        vpxor	xmm0, xmm0, xmm5
        vpsrld	xmm4, xmm3, 31
        vpsrld	xmm5, xmm0, 31
        vpslld	xmm3, xmm3, 1
        vpslld	xmm0, xmm0, 1
        vpsrldq	xmm6, xmm4, 12
        vpslldq	xmm4, xmm4, 4
        vpslldq	xmm5, xmm5, 4
        vpor	xmm0, xmm0, xmm6
        vpor	xmm3, xmm3, xmm4
        vpor	xmm0, xmm0, xmm5
        vpslld	xmm4, xmm3, 31
        vpslld	xmm5, xmm3, 30
        vpslld	xmm6, xmm3, 25
        vpxor	xmm4, xmm4, xmm5
        vpxor	xmm4, xmm4, xmm6
        vmovdqa	xmm5, xmm4
        vpsrldq	xmm5, xmm5, 4
        vpslldq	xmm4, xmm4, 12
        vpxor	xmm3, xmm3, xmm4
        vpsrld	xmm6, xmm3, 1
        vpsrld	xmm7, xmm3, 2
        vpsrld	xmm4, xmm3, 7
        vpxor	xmm6, xmm6, xmm7
        vpxor	xmm6, xmm6, xmm4
        vpxor	xmm6, xmm6, xmm5
        vpxor	xmm6, xmm6, xmm3
        vpxor	xmm0, xmm0, xmm6
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx1_bswap_mask
        ;   Encrypt counter
        vmovdqa	xmm4, OWORD PTR [ebp]
        vpxor	xmm4, xmm4, xmm0
        vaesenc	xmm4, xmm4, [ebp+16]
        vaesenc	xmm4, xmm4, [ebp+32]
        vaesenc	xmm4, xmm4, [ebp+48]
        vaesenc	xmm4, xmm4, [ebp+64]
        vaesenc	xmm4, xmm4, [ebp+80]
        vaesenc	xmm4, xmm4, [ebp+96]
        vaesenc	xmm4, xmm4, [ebp+112]
        vaesenc	xmm4, xmm4, [ebp+128]
        vaesenc	xmm4, xmm4, [ebp+144]
        cmp	DWORD PTR [esp+236], 11
        vmovdqa	xmm5, OWORD PTR [ebp+160]
        jl	L_AES_GCM_decrypt_avx1_calc_iv_2_aesenc_avx_last
        vaesenc	xmm4, xmm4, xmm5
        vaesenc	xmm4, xmm4, [ebp+176]
        cmp	DWORD PTR [esp+236], 13
        vmovdqa	xmm5, OWORD PTR [ebp+192]
        jl	L_AES_GCM_decrypt_avx1_calc_iv_2_aesenc_avx_last
        vaesenc	xmm4, xmm4, xmm5
        vaesenc	xmm4, xmm4, [ebp+208]
        vmovdqa	xmm5, OWORD PTR [ebp+224]
L_AES_GCM_decrypt_avx1_calc_iv_2_aesenc_avx_last:
        vaesenclast	xmm4, xmm4, xmm5
        vmovdqu	OWORD PTR [esp+80], xmm4
L_AES_GCM_decrypt_avx1_iv_done:
        mov	esi, DWORD PTR [esp+204]
        ; Additional authentication data
        mov	edx, DWORD PTR [esp+220]
        cmp	edx, 0
        je	L_AES_GCM_decrypt_avx1_calc_aad_done
        xor	ecx, ecx
        cmp	edx, 16
        jl	L_AES_GCM_decrypt_avx1_calc_aad_lt16
        and	edx, 4294967280
L_AES_GCM_decrypt_avx1_calc_aad_16_loop:
        vmovdqu	xmm4, OWORD PTR [esi+ecx]
        vpshufb	xmm4, xmm4, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm2, xmm2, xmm4
        ; ghash_gfmul_avx
        vpshufd	xmm5, xmm2, 78
        vpshufd	xmm6, xmm1, 78
        vpclmulqdq	xmm7, xmm1, xmm2, 17
        vpclmulqdq	xmm4, xmm1, xmm2, 0
        vpxor	xmm5, xmm5, xmm2
        vpxor	xmm6, xmm6, xmm1
        vpclmulqdq	xmm5, xmm5, xmm6, 0
        vpxor	xmm5, xmm5, xmm4
        vpxor	xmm5, xmm5, xmm7
        vmovdqa	xmm3, xmm4
        vmovdqa	xmm2, xmm7
        vpslldq	xmm6, xmm5, 8
        vpsrldq	xmm5, xmm5, 8
        vpxor	xmm3, xmm3, xmm6
        vpxor	xmm2, xmm2, xmm5
        vpsrld	xmm4, xmm3, 31
        vpsrld	xmm5, xmm2, 31
        vpslld	xmm3, xmm3, 1
        vpslld	xmm2, xmm2, 1
        vpsrldq	xmm6, xmm4, 12
        vpslldq	xmm4, xmm4, 4
        vpslldq	xmm5, xmm5, 4
        vpor	xmm2, xmm2, xmm6
        vpor	xmm3, xmm3, xmm4
        vpor	xmm2, xmm2, xmm5
        vpslld	xmm4, xmm3, 31
        vpslld	xmm5, xmm3, 30
        vpslld	xmm6, xmm3, 25
        vpxor	xmm4, xmm4, xmm5
        vpxor	xmm4, xmm4, xmm6
        vmovdqa	xmm5, xmm4
        vpsrldq	xmm5, xmm5, 4
        vpslldq	xmm4, xmm4, 12
        vpxor	xmm3, xmm3, xmm4
        vpsrld	xmm6, xmm3, 1
        vpsrld	xmm7, xmm3, 2
        vpsrld	xmm4, xmm3, 7
        vpxor	xmm6, xmm6, xmm7
        vpxor	xmm6, xmm6, xmm4
        vpxor	xmm6, xmm6, xmm5
        vpxor	xmm6, xmm6, xmm3
        vpxor	xmm2, xmm2, xmm6
        add	ecx, 16
        cmp	ecx, edx
        jl	L_AES_GCM_decrypt_avx1_calc_aad_16_loop
        mov	edx, DWORD PTR [esp+220]
        cmp	ecx, edx
        je	L_AES_GCM_decrypt_avx1_calc_aad_done
L_AES_GCM_decrypt_avx1_calc_aad_lt16:
        sub	esp, 16
        vpxor	xmm4, xmm4, xmm4
        xor	ebx, ebx
        vmovdqu	OWORD PTR [esp], xmm4
L_AES_GCM_decrypt_avx1_calc_aad_loop:
        movzx	eax, BYTE PTR [esi+ecx]
        mov	BYTE PTR [esp+ebx], al
        inc	ecx
        inc	ebx
        cmp	ecx, edx
        jl	L_AES_GCM_decrypt_avx1_calc_aad_loop
        vmovdqu	xmm4, OWORD PTR [esp]
        add	esp, 16
        vpshufb	xmm4, xmm4, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm2, xmm2, xmm4
        ; ghash_gfmul_avx
        vpshufd	xmm5, xmm2, 78
        vpshufd	xmm6, xmm1, 78
        vpclmulqdq	xmm7, xmm1, xmm2, 17
        vpclmulqdq	xmm4, xmm1, xmm2, 0
        vpxor	xmm5, xmm5, xmm2
        vpxor	xmm6, xmm6, xmm1
        vpclmulqdq	xmm5, xmm5, xmm6, 0
        vpxor	xmm5, xmm5, xmm4
        vpxor	xmm5, xmm5, xmm7
        vmovdqa	xmm3, xmm4
        vmovdqa	xmm2, xmm7
        vpslldq	xmm6, xmm5, 8
        vpsrldq	xmm5, xmm5, 8
        vpxor	xmm3, xmm3, xmm6
        vpxor	xmm2, xmm2, xmm5
        vpsrld	xmm4, xmm3, 31
        vpsrld	xmm5, xmm2, 31
        vpslld	xmm3, xmm3, 1
        vpslld	xmm2, xmm2, 1
        vpsrldq	xmm6, xmm4, 12
        vpslldq	xmm4, xmm4, 4
        vpslldq	xmm5, xmm5, 4
        vpor	xmm2, xmm2, xmm6
        vpor	xmm3, xmm3, xmm4
        vpor	xmm2, xmm2, xmm5
        vpslld	xmm4, xmm3, 31
        vpslld	xmm5, xmm3, 30
        vpslld	xmm6, xmm3, 25
        vpxor	xmm4, xmm4, xmm5
        vpxor	xmm4, xmm4, xmm6
        vmovdqa	xmm5, xmm4
        vpsrldq	xmm5, xmm5, 4
        vpslldq	xmm4, xmm4, 12
        vpxor	xmm3, xmm3, xmm4
        vpsrld	xmm6, xmm3, 1
        vpsrld	xmm7, xmm3, 2
        vpsrld	xmm4, xmm3, 7
        vpxor	xmm6, xmm6, xmm7
        vpxor	xmm6, xmm6, xmm4
        vpxor	xmm6, xmm6, xmm5
        vpxor	xmm6, xmm6, xmm3
        vpxor	xmm2, xmm2, xmm6
L_AES_GCM_decrypt_avx1_calc_aad_done:
        vmovdqu	OWORD PTR [esp+96], xmm2
        mov	esi, DWORD PTR [esp+196]
        mov	edi, DWORD PTR [esp+200]
        ; Calculate counter and H
        vpsrlq	xmm5, xmm1, 63
        vpsllq	xmm4, xmm1, 1
        vpslldq	xmm5, xmm5, 8
        vpor	xmm4, xmm4, xmm5
        vpshufd	xmm1, xmm1, 255
        vpsrad	xmm1, xmm1, 31
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx1_bswap_epi64
        vpand	xmm1, xmm1, OWORD PTR L_aes_gcm_avx1_mod2_128
        vpaddd	xmm0, xmm0, OWORD PTR L_aes_gcm_avx1_one
        vpxor	xmm1, xmm1, xmm4
        vmovdqu	OWORD PTR [esp+64], xmm0
        xor	ebx, ebx
        cmp	DWORD PTR [esp+216], 64
        mov	eax, DWORD PTR [esp+216]
        jl	L_AES_GCM_decrypt_avx1_done_64
        and	eax, 4294967232
        vmovdqa	xmm6, xmm2
        ; H ^ 1
        vmovdqu	OWORD PTR [esp], xmm1
        ; H ^ 2
        vpclmulqdq	xmm4, xmm1, xmm1, 0
        vpclmulqdq	xmm0, xmm1, xmm1, 17
        vpslld	xmm5, xmm4, 31
        vpslld	xmm6, xmm4, 30
        vpslld	xmm7, xmm4, 25
        vpxor	xmm5, xmm5, xmm6
        vpxor	xmm5, xmm5, xmm7
        vpsrldq	xmm7, xmm5, 4
        vpslldq	xmm5, xmm5, 12
        vpxor	xmm4, xmm4, xmm5
        vpsrld	xmm5, xmm4, 1
        vpsrld	xmm6, xmm4, 2
        vpxor	xmm5, xmm5, xmm6
        vpxor	xmm5, xmm5, xmm4
        vpsrld	xmm4, xmm4, 7
        vpxor	xmm5, xmm5, xmm7
        vpxor	xmm5, xmm5, xmm4
        vpxor	xmm0, xmm0, xmm5
        vmovdqu	OWORD PTR [esp+16], xmm0
        ; H ^ 3
        ; ghash_gfmul_red_avx
        vpshufd	xmm5, xmm1, 78
        vpshufd	xmm6, xmm0, 78
        vpclmulqdq	xmm7, xmm0, xmm1, 17
        vpclmulqdq	xmm4, xmm0, xmm1, 0
        vpxor	xmm5, xmm5, xmm1
        vpxor	xmm6, xmm6, xmm0
        vpclmulqdq	xmm5, xmm5, xmm6, 0
        vpxor	xmm5, xmm5, xmm4
        vpxor	xmm5, xmm5, xmm7
        vpslldq	xmm6, xmm5, 8
        vpsrldq	xmm5, xmm5, 8
        vpxor	xmm4, xmm4, xmm6
        vpxor	xmm3, xmm7, xmm5
        vpslld	xmm5, xmm4, 31
        vpslld	xmm6, xmm4, 30
        vpslld	xmm7, xmm4, 25
        vpxor	xmm5, xmm5, xmm6
        vpxor	xmm5, xmm5, xmm7
        vpsrldq	xmm7, xmm5, 4
        vpslldq	xmm5, xmm5, 12
        vpxor	xmm4, xmm4, xmm5
        vpsrld	xmm5, xmm4, 1
        vpsrld	xmm6, xmm4, 2
        vpxor	xmm5, xmm5, xmm6
        vpxor	xmm5, xmm5, xmm4
        vpsrld	xmm4, xmm4, 7
        vpxor	xmm5, xmm5, xmm7
        vpxor	xmm5, xmm5, xmm4
        vpxor	xmm3, xmm3, xmm5
        vmovdqu	OWORD PTR [esp+32], xmm3
        ; H ^ 4
        vpclmulqdq	xmm4, xmm0, xmm0, 0
        vpclmulqdq	xmm3, xmm0, xmm0, 17
        vpslld	xmm5, xmm4, 31
        vpslld	xmm6, xmm4, 30
        vpslld	xmm7, xmm4, 25
        vpxor	xmm5, xmm5, xmm6
        vpxor	xmm5, xmm5, xmm7
        vpsrldq	xmm7, xmm5, 4
        vpslldq	xmm5, xmm5, 12
        vpxor	xmm4, xmm4, xmm5
        vpsrld	xmm5, xmm4, 1
        vpsrld	xmm6, xmm4, 2
        vpxor	xmm5, xmm5, xmm6
        vpxor	xmm5, xmm5, xmm4
        vpsrld	xmm4, xmm4, 7
        vpxor	xmm5, xmm5, xmm7
        vpxor	xmm5, xmm5, xmm4
        vpxor	xmm3, xmm3, xmm5
        vmovdqu	OWORD PTR [esp+48], xmm3
        cmp	edi, esi
        jne	L_AES_GCM_decrypt_avx1_ghash_64
L_AES_GCM_decrypt_avx1_ghash_64_inplace:
        lea	ecx, DWORD PTR [esi+ebx]
        lea	edx, DWORD PTR [edi+ebx]
        vmovdqu	xmm4, OWORD PTR [esp+64]
        vpaddd	xmm3, xmm4, OWORD PTR L_aes_gcm_avx1_four
        vmovdqu	OWORD PTR [esp+64], xmm3
        vmovdqa	xmm3, OWORD PTR L_aes_gcm_avx1_bswap_epi64
        vpaddd	xmm5, xmm4, OWORD PTR L_aes_gcm_avx1_one
        vpshufb	xmm5, xmm5, xmm3
        vpaddd	xmm6, xmm4, OWORD PTR L_aes_gcm_avx1_two
        vpshufb	xmm6, xmm6, xmm3
        vpaddd	xmm7, xmm4, OWORD PTR L_aes_gcm_avx1_three
        vpshufb	xmm7, xmm7, xmm3
        vpshufb	xmm4, xmm4, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp]
        vpxor	xmm4, xmm4, xmm3
        vpxor	xmm5, xmm5, xmm3
        vpxor	xmm6, xmm6, xmm3
        vpxor	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+16]
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+32]
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+48]
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+64]
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+80]
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+96]
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+112]
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+128]
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+144]
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        cmp	DWORD PTR [esp+236], 11
        vmovdqa	xmm3, OWORD PTR [ebp+160]
        jl	L_AES_GCM_decrypt_avx1inplace_aesenc_64_ghash_avx_aesenc_64_enc_done
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+176]
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        cmp	DWORD PTR [esp+236], 13
        vmovdqa	xmm3, OWORD PTR [ebp+192]
        jl	L_AES_GCM_decrypt_avx1inplace_aesenc_64_ghash_avx_aesenc_64_enc_done
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+208]
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+224]
L_AES_GCM_decrypt_avx1inplace_aesenc_64_ghash_avx_aesenc_64_enc_done:
        vaesenclast	xmm4, xmm4, xmm3
        vaesenclast	xmm5, xmm5, xmm3
        vmovdqu	xmm0, OWORD PTR [ecx]
        vmovdqu	xmm1, OWORD PTR [ecx+16]
        vpxor	xmm4, xmm4, xmm0
        vpxor	xmm5, xmm5, xmm1
        vmovdqu	OWORD PTR [esp+112], xmm0
        vmovdqu	OWORD PTR [esp+128], xmm1
        vmovdqu	OWORD PTR [edx], xmm4
        vmovdqu	OWORD PTR [edx+16], xmm5
        vaesenclast	xmm6, xmm6, xmm3
        vaesenclast	xmm7, xmm7, xmm3
        vmovdqu	xmm0, OWORD PTR [ecx+32]
        vmovdqu	xmm1, OWORD PTR [ecx+48]
        vpxor	xmm6, xmm6, xmm0
        vpxor	xmm7, xmm7, xmm1
        vmovdqu	OWORD PTR [esp+144], xmm0
        vmovdqu	OWORD PTR [esp+160], xmm1
        vmovdqu	OWORD PTR [edx+32], xmm6
        vmovdqu	OWORD PTR [edx+48], xmm7
        ; ghash encrypted counter
        vmovdqu	xmm6, OWORD PTR [esp+96]
        vmovdqu	xmm3, OWORD PTR [esp+48]
        vmovdqu	xmm4, OWORD PTR [esp+112]
        vpshufb	xmm4, xmm4, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm4, xmm4, xmm6
        vpshufd	xmm5, xmm3, 78
        vpshufd	xmm1, xmm4, 78
        vpxor	xmm5, xmm5, xmm3
        vpxor	xmm1, xmm1, xmm4
        vpclmulqdq	xmm7, xmm4, xmm3, 17
        vpclmulqdq	xmm6, xmm4, xmm3, 0
        vpclmulqdq	xmm5, xmm5, xmm1, 0
        vpxor	xmm5, xmm5, xmm6
        vpxor	xmm5, xmm5, xmm7
        vmovdqu	xmm3, OWORD PTR [esp+32]
        vmovdqu	xmm4, OWORD PTR [esp+128]
        vpshufd	xmm0, xmm3, 78
        vpshufb	xmm4, xmm4, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm0, xmm0, xmm3
        vpshufd	xmm1, xmm4, 78
        vpxor	xmm1, xmm1, xmm4
        vpclmulqdq	xmm2, xmm4, xmm3, 17
        vpclmulqdq	xmm3, xmm4, xmm3, 0
        vpclmulqdq	xmm0, xmm0, xmm1, 0
        vpxor	xmm5, xmm5, xmm3
        vpxor	xmm6, xmm6, xmm3
        vpxor	xmm5, xmm5, xmm2
        vpxor	xmm7, xmm7, xmm2
        vpxor	xmm5, xmm5, xmm0
        vmovdqu	xmm3, OWORD PTR [esp+16]
        vmovdqu	xmm4, OWORD PTR [esp+144]
        vpshufd	xmm0, xmm3, 78
        vpshufb	xmm4, xmm4, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm0, xmm0, xmm3
        vpshufd	xmm1, xmm4, 78
        vpxor	xmm1, xmm1, xmm4
        vpclmulqdq	xmm2, xmm4, xmm3, 17
        vpclmulqdq	xmm3, xmm4, xmm3, 0
        vpclmulqdq	xmm0, xmm0, xmm1, 0
        vpxor	xmm5, xmm5, xmm3
        vpxor	xmm6, xmm6, xmm3
        vpxor	xmm5, xmm5, xmm2
        vpxor	xmm7, xmm7, xmm2
        vpxor	xmm5, xmm5, xmm0
        vmovdqu	xmm3, OWORD PTR [esp]
        vmovdqu	xmm4, OWORD PTR [esp+160]
        vpshufd	xmm0, xmm3, 78
        vpshufb	xmm4, xmm4, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm0, xmm0, xmm3
        vpshufd	xmm1, xmm4, 78
        vpxor	xmm1, xmm1, xmm4
        vpclmulqdq	xmm2, xmm4, xmm3, 17
        vpclmulqdq	xmm3, xmm4, xmm3, 0
        vpclmulqdq	xmm0, xmm0, xmm1, 0
        vpxor	xmm5, xmm5, xmm3
        vpxor	xmm6, xmm6, xmm3
        vpxor	xmm5, xmm5, xmm2
        vpxor	xmm7, xmm7, xmm2
        vpxor	xmm5, xmm5, xmm0
        vpslldq	xmm1, xmm5, 8
        vpsrldq	xmm5, xmm5, 8
        vpxor	xmm6, xmm6, xmm1
        vpxor	xmm7, xmm7, xmm5
        vpslld	xmm3, xmm6, 31
        vpslld	xmm0, xmm6, 30
        vpslld	xmm1, xmm6, 25
        vpxor	xmm3, xmm3, xmm0
        vpxor	xmm3, xmm3, xmm1
        vpsrldq	xmm0, xmm3, 4
        vpslldq	xmm3, xmm3, 12
        vpxor	xmm6, xmm6, xmm3
        vpsrld	xmm1, xmm6, 1
        vpsrld	xmm5, xmm6, 2
        vpsrld	xmm4, xmm6, 7
        vpxor	xmm1, xmm1, xmm5
        vpxor	xmm1, xmm1, xmm4
        vpxor	xmm1, xmm1, xmm0
        vpxor	xmm6, xmm6, xmm1
        vpxor	xmm6, xmm6, xmm7
        vmovdqu	OWORD PTR [esp+96], xmm6
        add	ebx, 64
        cmp	ebx, eax
        jl	L_AES_GCM_decrypt_avx1_ghash_64_inplace
        jmp	L_AES_GCM_decrypt_avx1_ghash_64_done
L_AES_GCM_decrypt_avx1_ghash_64:
        lea	ecx, DWORD PTR [esi+ebx]
        lea	edx, DWORD PTR [edi+ebx]
        vmovdqu	xmm4, OWORD PTR [esp+64]
        vpaddd	xmm3, xmm4, OWORD PTR L_aes_gcm_avx1_four
        vmovdqu	OWORD PTR [esp+64], xmm3
        vmovdqa	xmm3, OWORD PTR L_aes_gcm_avx1_bswap_epi64
        vpaddd	xmm5, xmm4, OWORD PTR L_aes_gcm_avx1_one
        vpshufb	xmm5, xmm5, xmm3
        vpaddd	xmm6, xmm4, OWORD PTR L_aes_gcm_avx1_two
        vpshufb	xmm6, xmm6, xmm3
        vpaddd	xmm7, xmm4, OWORD PTR L_aes_gcm_avx1_three
        vpshufb	xmm7, xmm7, xmm3
        vpshufb	xmm4, xmm4, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp]
        vpxor	xmm4, xmm4, xmm3
        vpxor	xmm5, xmm5, xmm3
        vpxor	xmm6, xmm6, xmm3
        vpxor	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+16]
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+32]
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+48]
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+64]
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+80]
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+96]
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+112]
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+128]
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+144]
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        cmp	DWORD PTR [esp+236], 11
        vmovdqa	xmm3, OWORD PTR [ebp+160]
        jl	L_AES_GCM_decrypt_avx1_aesenc_64_ghash_avx_aesenc_64_enc_done
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+176]
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        cmp	DWORD PTR [esp+236], 13
        vmovdqa	xmm3, OWORD PTR [ebp+192]
        jl	L_AES_GCM_decrypt_avx1_aesenc_64_ghash_avx_aesenc_64_enc_done
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+208]
        vaesenc	xmm4, xmm4, xmm3
        vaesenc	xmm5, xmm5, xmm3
        vaesenc	xmm6, xmm6, xmm3
        vaesenc	xmm7, xmm7, xmm3
        vmovdqa	xmm3, OWORD PTR [ebp+224]
L_AES_GCM_decrypt_avx1_aesenc_64_ghash_avx_aesenc_64_enc_done:
        vaesenclast	xmm4, xmm4, xmm3
        vaesenclast	xmm5, xmm5, xmm3
        vmovdqu	xmm0, OWORD PTR [ecx]
        vmovdqu	xmm1, OWORD PTR [ecx+16]
        vpxor	xmm4, xmm4, xmm0
        vpxor	xmm5, xmm5, xmm1
        vmovdqu	OWORD PTR [edx], xmm4
        vmovdqu	OWORD PTR [edx+16], xmm5
        vaesenclast	xmm6, xmm6, xmm3
        vaesenclast	xmm7, xmm7, xmm3
        vmovdqu	xmm0, OWORD PTR [ecx+32]
        vmovdqu	xmm1, OWORD PTR [ecx+48]
        vpxor	xmm6, xmm6, xmm0
        vpxor	xmm7, xmm7, xmm1
        vmovdqu	OWORD PTR [edx+32], xmm6
        vmovdqu	OWORD PTR [edx+48], xmm7
        ; ghash encrypted counter
        vmovdqu	xmm6, OWORD PTR [esp+96]
        vmovdqu	xmm3, OWORD PTR [esp+48]
        vmovdqu	xmm4, OWORD PTR [ecx]
        vpshufb	xmm4, xmm4, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm4, xmm4, xmm6
        vpshufd	xmm5, xmm3, 78
        vpshufd	xmm1, xmm4, 78
        vpxor	xmm5, xmm5, xmm3
        vpxor	xmm1, xmm1, xmm4
        vpclmulqdq	xmm7, xmm4, xmm3, 17
        vpclmulqdq	xmm6, xmm4, xmm3, 0
        vpclmulqdq	xmm5, xmm5, xmm1, 0
        vpxor	xmm5, xmm5, xmm6
        vpxor	xmm5, xmm5, xmm7
        vmovdqu	xmm3, OWORD PTR [esp+32]
        vmovdqu	xmm4, OWORD PTR [ecx+16]
        vpshufd	xmm0, xmm3, 78
        vpshufb	xmm4, xmm4, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm0, xmm0, xmm3
        vpshufd	xmm1, xmm4, 78
        vpxor	xmm1, xmm1, xmm4
        vpclmulqdq	xmm2, xmm4, xmm3, 17
        vpclmulqdq	xmm3, xmm4, xmm3, 0
        vpclmulqdq	xmm0, xmm0, xmm1, 0
        vpxor	xmm5, xmm5, xmm3
        vpxor	xmm6, xmm6, xmm3
        vpxor	xmm5, xmm5, xmm2
        vpxor	xmm7, xmm7, xmm2
        vpxor	xmm5, xmm5, xmm0
        vmovdqu	xmm3, OWORD PTR [esp+16]
        vmovdqu	xmm4, OWORD PTR [ecx+32]
        vpshufd	xmm0, xmm3, 78
        vpshufb	xmm4, xmm4, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm0, xmm0, xmm3
        vpshufd	xmm1, xmm4, 78
        vpxor	xmm1, xmm1, xmm4
        vpclmulqdq	xmm2, xmm4, xmm3, 17
        vpclmulqdq	xmm3, xmm4, xmm3, 0
        vpclmulqdq	xmm0, xmm0, xmm1, 0
        vpxor	xmm5, xmm5, xmm3
        vpxor	xmm6, xmm6, xmm3
        vpxor	xmm5, xmm5, xmm2
        vpxor	xmm7, xmm7, xmm2
        vpxor	xmm5, xmm5, xmm0
        vmovdqu	xmm3, OWORD PTR [esp]
        vmovdqu	xmm4, OWORD PTR [ecx+48]
        vpshufd	xmm0, xmm3, 78
        vpshufb	xmm4, xmm4, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm0, xmm0, xmm3
        vpshufd	xmm1, xmm4, 78
        vpxor	xmm1, xmm1, xmm4
        vpclmulqdq	xmm2, xmm4, xmm3, 17
        vpclmulqdq	xmm3, xmm4, xmm3, 0
        vpclmulqdq	xmm0, xmm0, xmm1, 0
        vpxor	xmm5, xmm5, xmm3
        vpxor	xmm6, xmm6, xmm3
        vpxor	xmm5, xmm5, xmm2
        vpxor	xmm7, xmm7, xmm2
        vpxor	xmm5, xmm5, xmm0
        vpslldq	xmm1, xmm5, 8
        vpsrldq	xmm5, xmm5, 8
        vpxor	xmm6, xmm6, xmm1
        vpxor	xmm7, xmm7, xmm5
        vpslld	xmm3, xmm6, 31
        vpslld	xmm0, xmm6, 30
        vpslld	xmm1, xmm6, 25
        vpxor	xmm3, xmm3, xmm0
        vpxor	xmm3, xmm3, xmm1
        vpsrldq	xmm0, xmm3, 4
        vpslldq	xmm3, xmm3, 12
        vpxor	xmm6, xmm6, xmm3
        vpsrld	xmm1, xmm6, 1
        vpsrld	xmm5, xmm6, 2
        vpsrld	xmm4, xmm6, 7
        vpxor	xmm1, xmm1, xmm5
        vpxor	xmm1, xmm1, xmm4
        vpxor	xmm1, xmm1, xmm0
        vpxor	xmm6, xmm6, xmm1
        vpxor	xmm6, xmm6, xmm7
        vmovdqu	OWORD PTR [esp+96], xmm6
        add	ebx, 64
        cmp	ebx, eax
        jl	L_AES_GCM_decrypt_avx1_ghash_64
L_AES_GCM_decrypt_avx1_ghash_64_done:
        vmovdqa	xmm2, xmm6
        vmovdqu	xmm1, OWORD PTR [esp]
L_AES_GCM_decrypt_avx1_done_64:
        mov	edx, DWORD PTR [esp+216]
        cmp	ebx, edx
        jge	L_AES_GCM_decrypt_avx1_done_dec
        mov	eax, DWORD PTR [esp+216]
        and	eax, 4294967280
        cmp	ebx, eax
        jge	L_AES_GCM_decrypt_avx1_last_block_done
L_AES_GCM_decrypt_avx1_last_block_start:
        lea	ecx, DWORD PTR [esi+ebx]
        lea	edx, DWORD PTR [edi+ebx]
        vmovdqu	xmm7, OWORD PTR [ecx]
        pshufb	xmm7, OWORD PTR L_aes_gcm_avx1_bswap_mask
        pxor	xmm7, xmm2
        vmovdqu	xmm5, OWORD PTR [esp+64]
        vpshufb	xmm4, xmm5, OWORD PTR L_aes_gcm_avx1_bswap_epi64
        vpaddd	xmm5, xmm5, OWORD PTR L_aes_gcm_avx1_one
        vmovdqu	OWORD PTR [esp+64], xmm5
        vpxor	xmm4, xmm4, [ebp]
        vpclmulqdq	xmm0, xmm7, xmm1, 16
        vaesenc	xmm4, xmm4, [ebp+16]
        vaesenc	xmm4, xmm4, [ebp+32]
        vpclmulqdq	xmm3, xmm7, xmm1, 1
        vaesenc	xmm4, xmm4, [ebp+48]
        vaesenc	xmm4, xmm4, [ebp+64]
        vaesenc	xmm4, xmm4, [ebp+80]
        vpclmulqdq	xmm5, xmm7, xmm1, 17
        vaesenc	xmm4, xmm4, [ebp+96]
        vpxor	xmm0, xmm0, xmm3
        vpslldq	xmm6, xmm0, 8
        vpsrldq	xmm0, xmm0, 8
        vaesenc	xmm4, xmm4, [ebp+112]
        vpclmulqdq	xmm3, xmm7, xmm1, 0
        vpxor	xmm6, xmm6, xmm3
        vpxor	xmm5, xmm5, xmm0
        vmovdqa	xmm7, OWORD PTR L_aes_gcm_avx1_mod2_128
        vpclmulqdq	xmm3, xmm6, xmm7, 16
        vaesenc	xmm4, xmm4, [ebp+128]
        vpshufd	xmm0, xmm6, 78
        vpxor	xmm0, xmm0, xmm3
        vpclmulqdq	xmm3, xmm0, xmm7, 16
        vaesenc	xmm4, xmm4, [ebp+144]
        vpshufd	xmm2, xmm0, 78
        vpxor	xmm2, xmm2, xmm3
        vpxor	xmm2, xmm2, xmm5
        cmp	DWORD PTR [esp+236], 11
        vmovdqa	xmm5, OWORD PTR [ebp+160]
        jl	L_AES_GCM_decrypt_avx1_aesenc_gfmul_last
        vaesenc	xmm4, xmm4, xmm5
        vaesenc	xmm4, xmm4, [ebp+176]
        cmp	DWORD PTR [esp+236], 13
        vmovdqa	xmm5, OWORD PTR [ebp+192]
        jl	L_AES_GCM_decrypt_avx1_aesenc_gfmul_last
        vaesenc	xmm4, xmm4, xmm5
        vaesenc	xmm4, xmm4, [ebp+208]
        vmovdqa	xmm5, OWORD PTR [ebp+224]
L_AES_GCM_decrypt_avx1_aesenc_gfmul_last:
        vaesenclast	xmm4, xmm4, xmm5
        vmovdqu	xmm5, OWORD PTR [ecx]
        vpxor	xmm4, xmm4, xmm5
        vmovdqu	OWORD PTR [edx], xmm4
        add	ebx, 16
        cmp	ebx, eax
        jl	L_AES_GCM_decrypt_avx1_last_block_start
L_AES_GCM_decrypt_avx1_last_block_done:
        mov	ecx, DWORD PTR [esp+216]
        mov	edx, ecx
        and	ecx, 15
        jz	L_AES_GCM_decrypt_avx1_aesenc_last15_dec_avx_done
        vmovdqu	xmm0, OWORD PTR [esp+64]
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx1_bswap_epi64
        vpxor	xmm0, xmm0, [ebp]
        vaesenc	xmm0, xmm0, [ebp+16]
        vaesenc	xmm0, xmm0, [ebp+32]
        vaesenc	xmm0, xmm0, [ebp+48]
        vaesenc	xmm0, xmm0, [ebp+64]
        vaesenc	xmm0, xmm0, [ebp+80]
        vaesenc	xmm0, xmm0, [ebp+96]
        vaesenc	xmm0, xmm0, [ebp+112]
        vaesenc	xmm0, xmm0, [ebp+128]
        vaesenc	xmm0, xmm0, [ebp+144]
        cmp	DWORD PTR [esp+236], 11
        vmovdqa	xmm5, OWORD PTR [ebp+160]
        jl	L_AES_GCM_decrypt_avx1_aesenc_last15_dec_avx_aesenc_avx_last
        vaesenc	xmm0, xmm0, xmm5
        vaesenc	xmm0, xmm0, [ebp+176]
        cmp	DWORD PTR [esp+236], 13
        vmovdqa	xmm5, OWORD PTR [ebp+192]
        jl	L_AES_GCM_decrypt_avx1_aesenc_last15_dec_avx_aesenc_avx_last
        vaesenc	xmm0, xmm0, xmm5
        vaesenc	xmm0, xmm0, [ebp+208]
        vmovdqa	xmm5, OWORD PTR [ebp+224]
L_AES_GCM_decrypt_avx1_aesenc_last15_dec_avx_aesenc_avx_last:
        vaesenclast	xmm0, xmm0, xmm5
        sub	esp, 32
        xor	ecx, ecx
        vmovdqu	OWORD PTR [esp], xmm0
        vpxor	xmm4, xmm4, xmm4
        vmovdqu	OWORD PTR [esp+16], xmm4
L_AES_GCM_decrypt_avx1_aesenc_last15_dec_avx_loop:
        movzx	eax, BYTE PTR [esi+ebx]
        mov	BYTE PTR [esp+ecx+16], al
        xor	al, BYTE PTR [esp+ecx]
        mov	BYTE PTR [edi+ebx], al
        inc	ebx
        inc	ecx
        cmp	ebx, edx
        jl	L_AES_GCM_decrypt_avx1_aesenc_last15_dec_avx_loop
        vmovdqu	xmm0, OWORD PTR [esp+16]
        add	esp, 32
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm2, xmm2, xmm0
        ; ghash_gfmul_red_avx
        vpshufd	xmm5, xmm1, 78
        vpshufd	xmm6, xmm2, 78
        vpclmulqdq	xmm7, xmm2, xmm1, 17
        vpclmulqdq	xmm4, xmm2, xmm1, 0
        vpxor	xmm5, xmm5, xmm1
        vpxor	xmm6, xmm6, xmm2
        vpclmulqdq	xmm5, xmm5, xmm6, 0
        vpxor	xmm5, xmm5, xmm4
        vpxor	xmm5, xmm5, xmm7
        vpslldq	xmm6, xmm5, 8
        vpsrldq	xmm5, xmm5, 8
        vpxor	xmm4, xmm4, xmm6
        vpxor	xmm2, xmm7, xmm5
        vpslld	xmm5, xmm4, 31
        vpslld	xmm6, xmm4, 30
        vpslld	xmm7, xmm4, 25
        vpxor	xmm5, xmm5, xmm6
        vpxor	xmm5, xmm5, xmm7
        vpsrldq	xmm7, xmm5, 4
        vpslldq	xmm5, xmm5, 12
        vpxor	xmm4, xmm4, xmm5
        vpsrld	xmm5, xmm4, 1
        vpsrld	xmm6, xmm4, 2
        vpxor	xmm5, xmm5, xmm6
        vpxor	xmm5, xmm5, xmm4
        vpsrld	xmm4, xmm4, 7
        vpxor	xmm5, xmm5, xmm7
        vpxor	xmm5, xmm5, xmm4
        vpxor	xmm2, xmm2, xmm5
L_AES_GCM_decrypt_avx1_aesenc_last15_dec_avx_done:
L_AES_GCM_decrypt_avx1_done_dec:
        mov	esi, DWORD PTR [esp+212]
        mov	ebp, DWORD PTR [esp+228]
        mov	edx, DWORD PTR [esp+216]
        mov	ecx, DWORD PTR [esp+220]
        shl	edx, 3
        shl	ecx, 3
        vpinsrd	xmm4, xmm4, edx, 0
        vpinsrd	xmm4, xmm4, ecx, 2
        mov	edx, DWORD PTR [esp+216]
        mov	ecx, DWORD PTR [esp+220]
        shr	edx, 29
        shr	ecx, 29
        vpinsrd	xmm4, xmm4, edx, 1
        vpinsrd	xmm4, xmm4, ecx, 3
        vpxor	xmm2, xmm2, xmm4
        ; ghash_gfmul_red_avx
        vpshufd	xmm5, xmm1, 78
        vpshufd	xmm6, xmm2, 78
        vpclmulqdq	xmm7, xmm2, xmm1, 17
        vpclmulqdq	xmm4, xmm2, xmm1, 0
        vpxor	xmm5, xmm5, xmm1
        vpxor	xmm6, xmm6, xmm2
        vpclmulqdq	xmm5, xmm5, xmm6, 0
        vpxor	xmm5, xmm5, xmm4
        vpxor	xmm5, xmm5, xmm7
        vpslldq	xmm6, xmm5, 8
        vpsrldq	xmm5, xmm5, 8
        vpxor	xmm4, xmm4, xmm6
        vpxor	xmm2, xmm7, xmm5
        vpslld	xmm5, xmm4, 31
        vpslld	xmm6, xmm4, 30
        vpslld	xmm7, xmm4, 25
        vpxor	xmm5, xmm5, xmm6
        vpxor	xmm5, xmm5, xmm7
        vpsrldq	xmm7, xmm5, 4
        vpslldq	xmm5, xmm5, 12
        vpxor	xmm4, xmm4, xmm5
        vpsrld	xmm5, xmm4, 1
        vpsrld	xmm6, xmm4, 2
        vpxor	xmm5, xmm5, xmm6
        vpxor	xmm5, xmm5, xmm4
        vpsrld	xmm4, xmm4, 7
        vpxor	xmm5, xmm5, xmm7
        vpxor	xmm5, xmm5, xmm4
        vpxor	xmm2, xmm2, xmm5
        vpshufb	xmm2, xmm2, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm4, xmm2, [esp+80]
        mov	edi, DWORD PTR [esp+240]
        cmp	ebp, 16
        je	L_AES_GCM_decrypt_avx1_cmp_tag_16
        sub	esp, 16
        xor	ecx, ecx
        xor	ebx, ebx
        vmovdqu	OWORD PTR [esp], xmm4
L_AES_GCM_decrypt_avx1_cmp_tag_loop:
        movzx	eax, BYTE PTR [esp+ecx]
        xor	al, BYTE PTR [esi+ecx]
        or	bl, al
        inc	ecx
        cmp	ecx, ebp
        jne	L_AES_GCM_decrypt_avx1_cmp_tag_loop
        cmp	bl, 0
        sete	bl
        add	esp, 16
        xor	ecx, ecx
        jmp	L_AES_GCM_decrypt_avx1_cmp_tag_done
L_AES_GCM_decrypt_avx1_cmp_tag_16:
        vmovdqu	xmm5, OWORD PTR [esi]
        vpcmpeqb	xmm4, xmm4, xmm5
        vpmovmskb	edx, xmm4
        ; %%edx == 0xFFFF then return 1 else => return 0
        xor	ebx, ebx
        cmp	edx, 65535
        sete	bl
L_AES_GCM_decrypt_avx1_cmp_tag_done:
        mov	DWORD PTR [edi], ebx
        add	esp, 176
        pop	ebp
        pop	edi
        pop	esi
        pop	ebx
        ret
AES_GCM_decrypt_avx1 ENDP
_TEXT ENDS
IFDEF WOLFSSL_AESGCM_STREAM
_TEXT SEGMENT READONLY PARA
AES_GCM_init_avx1 PROC
        push	ebx
        push	esi
        push	edi
        push	ebp
        sub	esp, 16
        mov	ebp, DWORD PTR [esp+36]
        mov	esi, DWORD PTR [esp+44]
        mov	edi, DWORD PTR [esp+60]
        vpxor	xmm4, xmm4, xmm4
        mov	edx, DWORD PTR [esp+48]
        cmp	edx, 12
        jne	L_AES_GCM_init_avx1_iv_not_12
        ; # Calculate values when IV is 12 bytes
        ; Set counter based on IV
        mov	ecx, 16777216
        vpinsrd	xmm4, xmm4, DWORD PTR [esi], 0
        vpinsrd	xmm4, xmm4, DWORD PTR [esi+4], 1
        vpinsrd	xmm4, xmm4, DWORD PTR [esi+8], 2
        vpinsrd	xmm4, xmm4, ecx, 3
        ; H = Encrypt X(=0) and T = Encrypt counter
        vmovdqa	xmm5, OWORD PTR [ebp]
        vpxor	xmm1, xmm4, xmm5
        vmovdqa	xmm7, OWORD PTR [ebp+16]
        vaesenc	xmm5, xmm5, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+32]
        vaesenc	xmm5, xmm5, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+48]
        vaesenc	xmm5, xmm5, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+64]
        vaesenc	xmm5, xmm5, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+80]
        vaesenc	xmm5, xmm5, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+96]
        vaesenc	xmm5, xmm5, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+112]
        vaesenc	xmm5, xmm5, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+128]
        vaesenc	xmm5, xmm5, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+144]
        vaesenc	xmm5, xmm5, xmm7
        vaesenc	xmm1, xmm1, xmm7
        cmp	DWORD PTR [esp+40], 11
        vmovdqa	xmm7, OWORD PTR [ebp+160]
        jl	L_AES_GCM_init_avx1_calc_iv_12_last
        vaesenc	xmm5, xmm5, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+176]
        vaesenc	xmm5, xmm5, xmm7
        vaesenc	xmm1, xmm1, xmm7
        cmp	DWORD PTR [esp+40], 13
        vmovdqa	xmm7, OWORD PTR [ebp+192]
        jl	L_AES_GCM_init_avx1_calc_iv_12_last
        vaesenc	xmm5, xmm5, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+208]
        vaesenc	xmm5, xmm5, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+224]
L_AES_GCM_init_avx1_calc_iv_12_last:
        vaesenclast	xmm5, xmm5, xmm7
        vaesenclast	xmm1, xmm1, xmm7
        vpshufb	xmm5, xmm5, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vmovdqu	OWORD PTR [edi], xmm1
        jmp	L_AES_GCM_init_avx1_iv_done
L_AES_GCM_init_avx1_iv_not_12:
        ; Calculate values when IV is not 12 bytes
        ; H = Encrypt X(=0)
        vmovdqa	xmm5, OWORD PTR [ebp]
        vaesenc	xmm5, xmm5, [ebp+16]
        vaesenc	xmm5, xmm5, [ebp+32]
        vaesenc	xmm5, xmm5, [ebp+48]
        vaesenc	xmm5, xmm5, [ebp+64]
        vaesenc	xmm5, xmm5, [ebp+80]
        vaesenc	xmm5, xmm5, [ebp+96]
        vaesenc	xmm5, xmm5, [ebp+112]
        vaesenc	xmm5, xmm5, [ebp+128]
        vaesenc	xmm5, xmm5, [ebp+144]
        cmp	DWORD PTR [esp+40], 11
        vmovdqa	xmm1, OWORD PTR [ebp+160]
        jl	L_AES_GCM_init_avx1_calc_iv_1_aesenc_avx_last
        vaesenc	xmm5, xmm5, xmm1
        vaesenc	xmm5, xmm5, [ebp+176]
        cmp	DWORD PTR [esp+40], 13
        vmovdqa	xmm1, OWORD PTR [ebp+192]
        jl	L_AES_GCM_init_avx1_calc_iv_1_aesenc_avx_last
        vaesenc	xmm5, xmm5, xmm1
        vaesenc	xmm5, xmm5, [ebp+208]
        vmovdqa	xmm1, OWORD PTR [ebp+224]
L_AES_GCM_init_avx1_calc_iv_1_aesenc_avx_last:
        vaesenclast	xmm5, xmm5, xmm1
        vpshufb	xmm5, xmm5, OWORD PTR L_aes_gcm_avx1_bswap_mask
        ; Calc counter
        ; Initialization vector
        cmp	edx, 0
        mov	ecx, 0
        je	L_AES_GCM_init_avx1_calc_iv_done
        cmp	edx, 16
        jl	L_AES_GCM_init_avx1_calc_iv_lt16
        and	edx, 4294967280
L_AES_GCM_init_avx1_calc_iv_16_loop:
        vmovdqu	xmm0, OWORD PTR [esi+ecx]
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm4, xmm4, xmm0
        ; ghash_gfmul_avx
        vpshufd	xmm1, xmm4, 78
        vpshufd	xmm2, xmm5, 78
        vpclmulqdq	xmm3, xmm5, xmm4, 17
        vpclmulqdq	xmm0, xmm5, xmm4, 0
        vpxor	xmm1, xmm1, xmm4
        vpxor	xmm2, xmm2, xmm5
        vpclmulqdq	xmm1, xmm1, xmm2, 0
        vpxor	xmm1, xmm1, xmm0
        vpxor	xmm1, xmm1, xmm3
        vmovdqa	xmm7, xmm0
        vmovdqa	xmm4, xmm3
        vpslldq	xmm2, xmm1, 8
        vpsrldq	xmm1, xmm1, 8
        vpxor	xmm7, xmm7, xmm2
        vpxor	xmm4, xmm4, xmm1
        vpsrld	xmm0, xmm7, 31
        vpsrld	xmm1, xmm4, 31
        vpslld	xmm7, xmm7, 1
        vpslld	xmm4, xmm4, 1
        vpsrldq	xmm2, xmm0, 12
        vpslldq	xmm0, xmm0, 4
        vpslldq	xmm1, xmm1, 4
        vpor	xmm4, xmm4, xmm2
        vpor	xmm7, xmm7, xmm0
        vpor	xmm4, xmm4, xmm1
        vpslld	xmm0, xmm7, 31
        vpslld	xmm1, xmm7, 30
        vpslld	xmm2, xmm7, 25
        vpxor	xmm0, xmm0, xmm1
        vpxor	xmm0, xmm0, xmm2
        vmovdqa	xmm1, xmm0
        vpsrldq	xmm1, xmm1, 4
        vpslldq	xmm0, xmm0, 12
        vpxor	xmm7, xmm7, xmm0
        vpsrld	xmm2, xmm7, 1
        vpsrld	xmm3, xmm7, 2
        vpsrld	xmm0, xmm7, 7
        vpxor	xmm2, xmm2, xmm3
        vpxor	xmm2, xmm2, xmm0
        vpxor	xmm2, xmm2, xmm1
        vpxor	xmm2, xmm2, xmm7
        vpxor	xmm4, xmm4, xmm2
        add	ecx, 16
        cmp	ecx, edx
        jl	L_AES_GCM_init_avx1_calc_iv_16_loop
        mov	edx, DWORD PTR [esp+48]
        cmp	ecx, edx
        je	L_AES_GCM_init_avx1_calc_iv_done
L_AES_GCM_init_avx1_calc_iv_lt16:
        sub	esp, 16
        vpxor	xmm0, xmm0, xmm0
        xor	ebx, ebx
        vmovdqu	OWORD PTR [esp], xmm0
L_AES_GCM_init_avx1_calc_iv_loop:
        movzx	eax, BYTE PTR [esi+ecx]
        mov	BYTE PTR [esp+ebx], al
        inc	ecx
        inc	ebx
        cmp	ecx, edx
        jl	L_AES_GCM_init_avx1_calc_iv_loop
        vmovdqu	xmm0, OWORD PTR [esp]
        add	esp, 16
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm4, xmm4, xmm0
        ; ghash_gfmul_avx
        vpshufd	xmm1, xmm4, 78
        vpshufd	xmm2, xmm5, 78
        vpclmulqdq	xmm3, xmm5, xmm4, 17
        vpclmulqdq	xmm0, xmm5, xmm4, 0
        vpxor	xmm1, xmm1, xmm4
        vpxor	xmm2, xmm2, xmm5
        vpclmulqdq	xmm1, xmm1, xmm2, 0
        vpxor	xmm1, xmm1, xmm0
        vpxor	xmm1, xmm1, xmm3
        vmovdqa	xmm7, xmm0
        vmovdqa	xmm4, xmm3
        vpslldq	xmm2, xmm1, 8
        vpsrldq	xmm1, xmm1, 8
        vpxor	xmm7, xmm7, xmm2
        vpxor	xmm4, xmm4, xmm1
        vpsrld	xmm0, xmm7, 31
        vpsrld	xmm1, xmm4, 31
        vpslld	xmm7, xmm7, 1
        vpslld	xmm4, xmm4, 1
        vpsrldq	xmm2, xmm0, 12
        vpslldq	xmm0, xmm0, 4
        vpslldq	xmm1, xmm1, 4
        vpor	xmm4, xmm4, xmm2
        vpor	xmm7, xmm7, xmm0
        vpor	xmm4, xmm4, xmm1
        vpslld	xmm0, xmm7, 31
        vpslld	xmm1, xmm7, 30
        vpslld	xmm2, xmm7, 25
        vpxor	xmm0, xmm0, xmm1
        vpxor	xmm0, xmm0, xmm2
        vmovdqa	xmm1, xmm0
        vpsrldq	xmm1, xmm1, 4
        vpslldq	xmm0, xmm0, 12
        vpxor	xmm7, xmm7, xmm0
        vpsrld	xmm2, xmm7, 1
        vpsrld	xmm3, xmm7, 2
        vpsrld	xmm0, xmm7, 7
        vpxor	xmm2, xmm2, xmm3
        vpxor	xmm2, xmm2, xmm0
        vpxor	xmm2, xmm2, xmm1
        vpxor	xmm2, xmm2, xmm7
        vpxor	xmm4, xmm4, xmm2
L_AES_GCM_init_avx1_calc_iv_done:
        ; T = Encrypt counter
        vpxor	xmm0, xmm0, xmm0
        shl	edx, 3
        vpinsrd	xmm0, xmm0, edx, 0
        vpxor	xmm4, xmm4, xmm0
        ; ghash_gfmul_avx
        vpshufd	xmm1, xmm4, 78
        vpshufd	xmm2, xmm5, 78
        vpclmulqdq	xmm3, xmm5, xmm4, 17
        vpclmulqdq	xmm0, xmm5, xmm4, 0
        vpxor	xmm1, xmm1, xmm4
        vpxor	xmm2, xmm2, xmm5
        vpclmulqdq	xmm1, xmm1, xmm2, 0
        vpxor	xmm1, xmm1, xmm0
        vpxor	xmm1, xmm1, xmm3
        vmovdqa	xmm7, xmm0
        vmovdqa	xmm4, xmm3
        vpslldq	xmm2, xmm1, 8
        vpsrldq	xmm1, xmm1, 8
        vpxor	xmm7, xmm7, xmm2
        vpxor	xmm4, xmm4, xmm1
        vpsrld	xmm0, xmm7, 31
        vpsrld	xmm1, xmm4, 31
        vpslld	xmm7, xmm7, 1
        vpslld	xmm4, xmm4, 1
        vpsrldq	xmm2, xmm0, 12
        vpslldq	xmm0, xmm0, 4
        vpslldq	xmm1, xmm1, 4
        vpor	xmm4, xmm4, xmm2
        vpor	xmm7, xmm7, xmm0
        vpor	xmm4, xmm4, xmm1
        vpslld	xmm0, xmm7, 31
        vpslld	xmm1, xmm7, 30
        vpslld	xmm2, xmm7, 25
        vpxor	xmm0, xmm0, xmm1
        vpxor	xmm0, xmm0, xmm2
        vmovdqa	xmm1, xmm0
        vpsrldq	xmm1, xmm1, 4
        vpslldq	xmm0, xmm0, 12
        vpxor	xmm7, xmm7, xmm0
        vpsrld	xmm2, xmm7, 1
        vpsrld	xmm3, xmm7, 2
        vpsrld	xmm0, xmm7, 7
        vpxor	xmm2, xmm2, xmm3
        vpxor	xmm2, xmm2, xmm0
        vpxor	xmm2, xmm2, xmm1
        vpxor	xmm2, xmm2, xmm7
        vpxor	xmm4, xmm4, xmm2
        vpshufb	xmm4, xmm4, OWORD PTR L_aes_gcm_avx1_bswap_mask
        ;   Encrypt counter
        vmovdqa	xmm0, OWORD PTR [ebp]
        vpxor	xmm0, xmm0, xmm4
        vaesenc	xmm0, xmm0, [ebp+16]
        vaesenc	xmm0, xmm0, [ebp+32]
        vaesenc	xmm0, xmm0, [ebp+48]
        vaesenc	xmm0, xmm0, [ebp+64]
        vaesenc	xmm0, xmm0, [ebp+80]
        vaesenc	xmm0, xmm0, [ebp+96]
        vaesenc	xmm0, xmm0, [ebp+112]
        vaesenc	xmm0, xmm0, [ebp+128]
        vaesenc	xmm0, xmm0, [ebp+144]
        cmp	DWORD PTR [esp+40], 11
        vmovdqa	xmm1, OWORD PTR [ebp+160]
        jl	L_AES_GCM_init_avx1_calc_iv_2_aesenc_avx_last
        vaesenc	xmm0, xmm0, xmm1
        vaesenc	xmm0, xmm0, [ebp+176]
        cmp	DWORD PTR [esp+40], 13
        vmovdqa	xmm1, OWORD PTR [ebp+192]
        jl	L_AES_GCM_init_avx1_calc_iv_2_aesenc_avx_last
        vaesenc	xmm0, xmm0, xmm1
        vaesenc	xmm0, xmm0, [ebp+208]
        vmovdqa	xmm1, OWORD PTR [ebp+224]
L_AES_GCM_init_avx1_calc_iv_2_aesenc_avx_last:
        vaesenclast	xmm0, xmm0, xmm1
        vmovdqu	OWORD PTR [edi], xmm0
L_AES_GCM_init_avx1_iv_done:
        mov	ebp, DWORD PTR [esp+52]
        mov	edi, DWORD PTR [esp+56]
        vpshufb	xmm4, xmm4, OWORD PTR L_aes_gcm_avx1_bswap_epi64
        vpaddd	xmm4, xmm4, OWORD PTR L_aes_gcm_avx1_one
        vmovdqa	OWORD PTR [ebp], xmm5
        vmovdqa	OWORD PTR [edi], xmm4
        add	esp, 16
        pop	ebp
        pop	edi
        pop	esi
        pop	ebx
        ret
AES_GCM_init_avx1 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_GCM_aad_update_avx1 PROC
        push	esi
        push	edi
        mov	esi, DWORD PTR [esp+12]
        mov	edx, DWORD PTR [esp+16]
        mov	edi, DWORD PTR [esp+20]
        mov	eax, DWORD PTR [esp+24]
        vmovdqa	xmm5, OWORD PTR [edi]
        vmovdqa	xmm6, OWORD PTR [eax]
        xor	ecx, ecx
L_AES_GCM_aad_update_avx1_16_loop:
        vmovdqu	xmm0, OWORD PTR [esi+ecx]
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm5, xmm5, xmm0
        ; ghash_gfmul_avx
        vpshufd	xmm1, xmm5, 78
        vpshufd	xmm2, xmm6, 78
        vpclmulqdq	xmm3, xmm6, xmm5, 17
        vpclmulqdq	xmm0, xmm6, xmm5, 0
        vpxor	xmm1, xmm1, xmm5
        vpxor	xmm2, xmm2, xmm6
        vpclmulqdq	xmm1, xmm1, xmm2, 0
        vpxor	xmm1, xmm1, xmm0
        vpxor	xmm1, xmm1, xmm3
        vmovdqa	xmm4, xmm0
        vmovdqa	xmm5, xmm3
        vpslldq	xmm2, xmm1, 8
        vpsrldq	xmm1, xmm1, 8
        vpxor	xmm4, xmm4, xmm2
        vpxor	xmm5, xmm5, xmm1
        vpsrld	xmm0, xmm4, 31
        vpsrld	xmm1, xmm5, 31
        vpslld	xmm4, xmm4, 1
        vpslld	xmm5, xmm5, 1
        vpsrldq	xmm2, xmm0, 12
        vpslldq	xmm0, xmm0, 4
        vpslldq	xmm1, xmm1, 4
        vpor	xmm5, xmm5, xmm2
        vpor	xmm4, xmm4, xmm0
        vpor	xmm5, xmm5, xmm1
        vpslld	xmm0, xmm4, 31
        vpslld	xmm1, xmm4, 30
        vpslld	xmm2, xmm4, 25
        vpxor	xmm0, xmm0, xmm1
        vpxor	xmm0, xmm0, xmm2
        vmovdqa	xmm1, xmm0
        vpsrldq	xmm1, xmm1, 4
        vpslldq	xmm0, xmm0, 12
        vpxor	xmm4, xmm4, xmm0
        vpsrld	xmm2, xmm4, 1
        vpsrld	xmm3, xmm4, 2
        vpsrld	xmm0, xmm4, 7
        vpxor	xmm2, xmm2, xmm3
        vpxor	xmm2, xmm2, xmm0
        vpxor	xmm2, xmm2, xmm1
        vpxor	xmm2, xmm2, xmm4
        vpxor	xmm5, xmm5, xmm2
        add	ecx, 16
        cmp	ecx, edx
        jl	L_AES_GCM_aad_update_avx1_16_loop
        vmovdqa	OWORD PTR [edi], xmm5
        pop	edi
        pop	esi
        ret
AES_GCM_aad_update_avx1 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_GCM_encrypt_block_avx1 PROC
        push	esi
        push	edi
        mov	ecx, DWORD PTR [esp+12]
        mov	eax, DWORD PTR [esp+16]
        mov	edi, DWORD PTR [esp+20]
        mov	esi, DWORD PTR [esp+24]
        mov	edx, DWORD PTR [esp+28]
        vmovdqu	xmm1, OWORD PTR [edx]
        vpshufb	xmm0, xmm1, OWORD PTR L_aes_gcm_avx1_bswap_epi64
        vpaddd	xmm1, xmm1, OWORD PTR L_aes_gcm_avx1_one
        vmovdqu	OWORD PTR [edx], xmm1
        vpxor	xmm0, xmm0, [ecx]
        vaesenc	xmm0, xmm0, [ecx+16]
        vaesenc	xmm0, xmm0, [ecx+32]
        vaesenc	xmm0, xmm0, [ecx+48]
        vaesenc	xmm0, xmm0, [ecx+64]
        vaesenc	xmm0, xmm0, [ecx+80]
        vaesenc	xmm0, xmm0, [ecx+96]
        vaesenc	xmm0, xmm0, [ecx+112]
        vaesenc	xmm0, xmm0, [ecx+128]
        vaesenc	xmm0, xmm0, [ecx+144]
        cmp	eax, 11
        vmovdqa	xmm1, OWORD PTR [ecx+160]
        jl	L_AES_GCM_encrypt_block_avx1_aesenc_block_aesenc_avx_last
        vaesenc	xmm0, xmm0, xmm1
        vaesenc	xmm0, xmm0, [ecx+176]
        cmp	eax, 13
        vmovdqa	xmm1, OWORD PTR [ecx+192]
        jl	L_AES_GCM_encrypt_block_avx1_aesenc_block_aesenc_avx_last
        vaesenc	xmm0, xmm0, xmm1
        vaesenc	xmm0, xmm0, [ecx+208]
        vmovdqa	xmm1, OWORD PTR [ecx+224]
L_AES_GCM_encrypt_block_avx1_aesenc_block_aesenc_avx_last:
        vaesenclast	xmm0, xmm0, xmm1
        vmovdqu	xmm1, OWORD PTR [esi]
        vpxor	xmm0, xmm0, xmm1
        vmovdqu	OWORD PTR [edi], xmm0
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx1_bswap_mask
        pop	edi
        pop	esi
        ret
AES_GCM_encrypt_block_avx1 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_GCM_ghash_block_avx1 PROC
        mov	edx, DWORD PTR [esp+4]
        mov	eax, DWORD PTR [esp+8]
        mov	ecx, DWORD PTR [esp+12]
        vmovdqa	xmm4, OWORD PTR [eax]
        vmovdqa	xmm5, OWORD PTR [ecx]
        vmovdqu	xmm0, OWORD PTR [edx]
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm4, xmm4, xmm0
        ; ghash_gfmul_avx
        vpshufd	xmm1, xmm4, 78
        vpshufd	xmm2, xmm5, 78
        vpclmulqdq	xmm3, xmm5, xmm4, 17
        vpclmulqdq	xmm0, xmm5, xmm4, 0
        vpxor	xmm1, xmm1, xmm4
        vpxor	xmm2, xmm2, xmm5
        vpclmulqdq	xmm1, xmm1, xmm2, 0
        vpxor	xmm1, xmm1, xmm0
        vpxor	xmm1, xmm1, xmm3
        vmovdqa	xmm6, xmm0
        vmovdqa	xmm4, xmm3
        vpslldq	xmm2, xmm1, 8
        vpsrldq	xmm1, xmm1, 8
        vpxor	xmm6, xmm6, xmm2
        vpxor	xmm4, xmm4, xmm1
        vpsrld	xmm0, xmm6, 31
        vpsrld	xmm1, xmm4, 31
        vpslld	xmm6, xmm6, 1
        vpslld	xmm4, xmm4, 1
        vpsrldq	xmm2, xmm0, 12
        vpslldq	xmm0, xmm0, 4
        vpslldq	xmm1, xmm1, 4
        vpor	xmm4, xmm4, xmm2
        vpor	xmm6, xmm6, xmm0
        vpor	xmm4, xmm4, xmm1
        vpslld	xmm0, xmm6, 31
        vpslld	xmm1, xmm6, 30
        vpslld	xmm2, xmm6, 25
        vpxor	xmm0, xmm0, xmm1
        vpxor	xmm0, xmm0, xmm2
        vmovdqa	xmm1, xmm0
        vpsrldq	xmm1, xmm1, 4
        vpslldq	xmm0, xmm0, 12
        vpxor	xmm6, xmm6, xmm0
        vpsrld	xmm2, xmm6, 1
        vpsrld	xmm3, xmm6, 2
        vpsrld	xmm0, xmm6, 7
        vpxor	xmm2, xmm2, xmm3
        vpxor	xmm2, xmm2, xmm0
        vpxor	xmm2, xmm2, xmm1
        vpxor	xmm2, xmm2, xmm6
        vpxor	xmm4, xmm4, xmm2
        vmovdqa	OWORD PTR [eax], xmm4
        ret
AES_GCM_ghash_block_avx1 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_GCM_encrypt_update_avx1 PROC
        push	ebx
        push	esi
        push	edi
        push	ebp
        sub	esp, 96
        mov	esi, DWORD PTR [esp+144]
        vmovdqa	xmm4, OWORD PTR [esi]
        vmovdqu	OWORD PTR [esp+64], xmm4
        mov	esi, DWORD PTR [esp+136]
        mov	ebp, DWORD PTR [esp+140]
        vmovdqa	xmm6, OWORD PTR [esi]
        vmovdqa	xmm5, OWORD PTR [ebp]
        vmovdqu	OWORD PTR [esp+80], xmm6
        mov	ebp, DWORD PTR [esp+116]
        mov	edi, DWORD PTR [esp+124]
        mov	esi, DWORD PTR [esp+128]
        vpsrlq	xmm1, xmm5, 63
        vpsllq	xmm0, xmm5, 1
        vpslldq	xmm1, xmm1, 8
        vpor	xmm0, xmm0, xmm1
        vpshufd	xmm5, xmm5, 255
        vpsrad	xmm5, xmm5, 31
        vpand	xmm5, xmm5, OWORD PTR L_aes_gcm_avx1_mod2_128
        vpxor	xmm5, xmm5, xmm0
        xor	ebx, ebx
        cmp	DWORD PTR [esp+132], 64
        mov	eax, DWORD PTR [esp+132]
        jl	L_AES_GCM_encrypt_update_avx1_done_64
        and	eax, 4294967232
        vmovdqa	xmm2, xmm6
        ; H ^ 1
        vmovdqu	OWORD PTR [esp], xmm5
        ; H ^ 2
        vpclmulqdq	xmm0, xmm5, xmm5, 0
        vpclmulqdq	xmm4, xmm5, xmm5, 17
        vpslld	xmm1, xmm0, 31
        vpslld	xmm2, xmm0, 30
        vpslld	xmm3, xmm0, 25
        vpxor	xmm1, xmm1, xmm2
        vpxor	xmm1, xmm1, xmm3
        vpsrldq	xmm3, xmm1, 4
        vpslldq	xmm1, xmm1, 12
        vpxor	xmm0, xmm0, xmm1
        vpsrld	xmm1, xmm0, 1
        vpsrld	xmm2, xmm0, 2
        vpxor	xmm1, xmm1, xmm2
        vpxor	xmm1, xmm1, xmm0
        vpsrld	xmm0, xmm0, 7
        vpxor	xmm1, xmm1, xmm3
        vpxor	xmm1, xmm1, xmm0
        vpxor	xmm4, xmm4, xmm1
        vmovdqu	OWORD PTR [esp+16], xmm4
        ; H ^ 3
        ; ghash_gfmul_red_avx
        vpshufd	xmm1, xmm5, 78
        vpshufd	xmm2, xmm4, 78
        vpclmulqdq	xmm3, xmm4, xmm5, 17
        vpclmulqdq	xmm0, xmm4, xmm5, 0
        vpxor	xmm1, xmm1, xmm5
        vpxor	xmm2, xmm2, xmm4
        vpclmulqdq	xmm1, xmm1, xmm2, 0
        vpxor	xmm1, xmm1, xmm0
        vpxor	xmm1, xmm1, xmm3
        vpslldq	xmm2, xmm1, 8
        vpsrldq	xmm1, xmm1, 8
        vpxor	xmm0, xmm0, xmm2
        vpxor	xmm7, xmm3, xmm1
        vpslld	xmm1, xmm0, 31
        vpslld	xmm2, xmm0, 30
        vpslld	xmm3, xmm0, 25
        vpxor	xmm1, xmm1, xmm2
        vpxor	xmm1, xmm1, xmm3
        vpsrldq	xmm3, xmm1, 4
        vpslldq	xmm1, xmm1, 12
        vpxor	xmm0, xmm0, xmm1
        vpsrld	xmm1, xmm0, 1
        vpsrld	xmm2, xmm0, 2
        vpxor	xmm1, xmm1, xmm2
        vpxor	xmm1, xmm1, xmm0
        vpsrld	xmm0, xmm0, 7
        vpxor	xmm1, xmm1, xmm3
        vpxor	xmm1, xmm1, xmm0
        vpxor	xmm7, xmm7, xmm1
        vmovdqu	OWORD PTR [esp+32], xmm7
        ; H ^ 4
        vpclmulqdq	xmm0, xmm4, xmm4, 0
        vpclmulqdq	xmm7, xmm4, xmm4, 17
        vpslld	xmm1, xmm0, 31
        vpslld	xmm2, xmm0, 30
        vpslld	xmm3, xmm0, 25
        vpxor	xmm1, xmm1, xmm2
        vpxor	xmm1, xmm1, xmm3
        vpsrldq	xmm3, xmm1, 4
        vpslldq	xmm1, xmm1, 12
        vpxor	xmm0, xmm0, xmm1
        vpsrld	xmm1, xmm0, 1
        vpsrld	xmm2, xmm0, 2
        vpxor	xmm1, xmm1, xmm2
        vpxor	xmm1, xmm1, xmm0
        vpsrld	xmm0, xmm0, 7
        vpxor	xmm1, xmm1, xmm3
        vpxor	xmm1, xmm1, xmm0
        vpxor	xmm7, xmm7, xmm1
        vmovdqu	OWORD PTR [esp+48], xmm7
        ; First 64 bytes of input
        vmovdqu	xmm0, OWORD PTR [esp+64]
        vpaddd	xmm7, xmm0, OWORD PTR L_aes_gcm_avx1_four
        vmovdqu	OWORD PTR [esp+64], xmm7
        vmovdqa	xmm7, OWORD PTR L_aes_gcm_avx1_bswap_epi64
        vpaddd	xmm1, xmm0, OWORD PTR L_aes_gcm_avx1_one
        vpshufb	xmm1, xmm1, xmm7
        vpaddd	xmm2, xmm0, OWORD PTR L_aes_gcm_avx1_two
        vpshufb	xmm2, xmm2, xmm7
        vpaddd	xmm3, xmm0, OWORD PTR L_aes_gcm_avx1_three
        vpshufb	xmm3, xmm3, xmm7
        vpshufb	xmm0, xmm0, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp]
        vpxor	xmm0, xmm0, xmm7
        vpxor	xmm1, xmm1, xmm7
        vpxor	xmm2, xmm2, xmm7
        vpxor	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+16]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+32]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+48]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+64]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+80]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+96]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+112]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+128]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+144]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        cmp	DWORD PTR [esp+120], 11
        vmovdqa	xmm7, OWORD PTR [ebp+160]
        jl	L_AES_GCM_encrypt_update_avx1_aesenc_64_enc_done
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+176]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        cmp	DWORD PTR [esp+120], 13
        vmovdqa	xmm7, OWORD PTR [ebp+192]
        jl	L_AES_GCM_encrypt_update_avx1_aesenc_64_enc_done
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+208]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+224]
L_AES_GCM_encrypt_update_avx1_aesenc_64_enc_done:
        vaesenclast	xmm0, xmm0, xmm7
        vaesenclast	xmm1, xmm1, xmm7
        vmovdqu	xmm4, OWORD PTR [esi]
        vmovdqu	xmm5, OWORD PTR [esi+16]
        vpxor	xmm0, xmm0, xmm4
        vpxor	xmm1, xmm1, xmm5
        vmovdqu	OWORD PTR [edi], xmm0
        vmovdqu	OWORD PTR [edi+16], xmm1
        vaesenclast	xmm2, xmm2, xmm7
        vaesenclast	xmm3, xmm3, xmm7
        vmovdqu	xmm4, OWORD PTR [esi+32]
        vmovdqu	xmm5, OWORD PTR [esi+48]
        vpxor	xmm2, xmm2, xmm4
        vpxor	xmm3, xmm3, xmm5
        vmovdqu	OWORD PTR [edi+32], xmm2
        vmovdqu	OWORD PTR [edi+48], xmm3
        cmp	eax, 64
        mov	ebx, 64
        mov	ecx, esi
        mov	edx, edi
        jle	L_AES_GCM_encrypt_update_avx1_end_64
        ; More 64 bytes of input
L_AES_GCM_encrypt_update_avx1_ghash_64:
        lea	ecx, DWORD PTR [esi+ebx]
        lea	edx, DWORD PTR [edi+ebx]
        vmovdqu	xmm0, OWORD PTR [esp+64]
        vpaddd	xmm7, xmm0, OWORD PTR L_aes_gcm_avx1_four
        vmovdqu	OWORD PTR [esp+64], xmm7
        vmovdqa	xmm7, OWORD PTR L_aes_gcm_avx1_bswap_epi64
        vpaddd	xmm1, xmm0, OWORD PTR L_aes_gcm_avx1_one
        vpshufb	xmm1, xmm1, xmm7
        vpaddd	xmm2, xmm0, OWORD PTR L_aes_gcm_avx1_two
        vpshufb	xmm2, xmm2, xmm7
        vpaddd	xmm3, xmm0, OWORD PTR L_aes_gcm_avx1_three
        vpshufb	xmm3, xmm3, xmm7
        vpshufb	xmm0, xmm0, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp]
        vpxor	xmm0, xmm0, xmm7
        vpxor	xmm1, xmm1, xmm7
        vpxor	xmm2, xmm2, xmm7
        vpxor	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+16]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+32]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+48]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+64]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+80]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+96]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+112]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+128]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+144]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        cmp	DWORD PTR [esp+120], 11
        vmovdqa	xmm7, OWORD PTR [ebp+160]
        jl	L_AES_GCM_encrypt_update_avx1_aesenc_64_ghash_avx_aesenc_64_enc_done
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+176]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        cmp	DWORD PTR [esp+120], 13
        vmovdqa	xmm7, OWORD PTR [ebp+192]
        jl	L_AES_GCM_encrypt_update_avx1_aesenc_64_ghash_avx_aesenc_64_enc_done
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+208]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+224]
L_AES_GCM_encrypt_update_avx1_aesenc_64_ghash_avx_aesenc_64_enc_done:
        vaesenclast	xmm0, xmm0, xmm7
        vaesenclast	xmm1, xmm1, xmm7
        vmovdqu	xmm4, OWORD PTR [ecx]
        vmovdqu	xmm5, OWORD PTR [ecx+16]
        vpxor	xmm0, xmm0, xmm4
        vpxor	xmm1, xmm1, xmm5
        vmovdqu	OWORD PTR [edx], xmm0
        vmovdqu	OWORD PTR [edx+16], xmm1
        vaesenclast	xmm2, xmm2, xmm7
        vaesenclast	xmm3, xmm3, xmm7
        vmovdqu	xmm4, OWORD PTR [ecx+32]
        vmovdqu	xmm5, OWORD PTR [ecx+48]
        vpxor	xmm2, xmm2, xmm4
        vpxor	xmm3, xmm3, xmm5
        vmovdqu	OWORD PTR [edx+32], xmm2
        vmovdqu	OWORD PTR [edx+48], xmm3
        ; ghash encrypted counter
        vmovdqu	xmm2, OWORD PTR [esp+80]
        vmovdqu	xmm7, OWORD PTR [esp+48]
        vmovdqu	xmm0, OWORD PTR [edx+-64]
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm0, xmm0, xmm2
        vpshufd	xmm1, xmm7, 78
        vpshufd	xmm5, xmm0, 78
        vpxor	xmm1, xmm1, xmm7
        vpxor	xmm5, xmm5, xmm0
        vpclmulqdq	xmm3, xmm0, xmm7, 17
        vpclmulqdq	xmm2, xmm0, xmm7, 0
        vpclmulqdq	xmm1, xmm1, xmm5, 0
        vpxor	xmm1, xmm1, xmm2
        vpxor	xmm1, xmm1, xmm3
        vmovdqu	xmm7, OWORD PTR [esp+32]
        vmovdqu	xmm0, OWORD PTR [edx+-48]
        vpshufd	xmm4, xmm7, 78
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm4, xmm4, xmm7
        vpshufd	xmm5, xmm0, 78
        vpxor	xmm5, xmm5, xmm0
        vpclmulqdq	xmm6, xmm0, xmm7, 17
        vpclmulqdq	xmm7, xmm0, xmm7, 0
        vpclmulqdq	xmm4, xmm4, xmm5, 0
        vpxor	xmm1, xmm1, xmm7
        vpxor	xmm2, xmm2, xmm7
        vpxor	xmm1, xmm1, xmm6
        vpxor	xmm3, xmm3, xmm6
        vpxor	xmm1, xmm1, xmm4
        vmovdqu	xmm7, OWORD PTR [esp+16]
        vmovdqu	xmm0, OWORD PTR [edx+-32]
        vpshufd	xmm4, xmm7, 78
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm4, xmm4, xmm7
        vpshufd	xmm5, xmm0, 78
        vpxor	xmm5, xmm5, xmm0
        vpclmulqdq	xmm6, xmm0, xmm7, 17
        vpclmulqdq	xmm7, xmm0, xmm7, 0
        vpclmulqdq	xmm4, xmm4, xmm5, 0
        vpxor	xmm1, xmm1, xmm7
        vpxor	xmm2, xmm2, xmm7
        vpxor	xmm1, xmm1, xmm6
        vpxor	xmm3, xmm3, xmm6
        vpxor	xmm1, xmm1, xmm4
        vmovdqu	xmm7, OWORD PTR [esp]
        vmovdqu	xmm0, OWORD PTR [edx+-16]
        vpshufd	xmm4, xmm7, 78
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm4, xmm4, xmm7
        vpshufd	xmm5, xmm0, 78
        vpxor	xmm5, xmm5, xmm0
        vpclmulqdq	xmm6, xmm0, xmm7, 17
        vpclmulqdq	xmm7, xmm0, xmm7, 0
        vpclmulqdq	xmm4, xmm4, xmm5, 0
        vpxor	xmm1, xmm1, xmm7
        vpxor	xmm2, xmm2, xmm7
        vpxor	xmm1, xmm1, xmm6
        vpxor	xmm3, xmm3, xmm6
        vpxor	xmm1, xmm1, xmm4
        vpslldq	xmm5, xmm1, 8
        vpsrldq	xmm1, xmm1, 8
        vpxor	xmm2, xmm2, xmm5
        vpxor	xmm3, xmm3, xmm1
        vpslld	xmm7, xmm2, 31
        vpslld	xmm4, xmm2, 30
        vpslld	xmm5, xmm2, 25
        vpxor	xmm7, xmm7, xmm4
        vpxor	xmm7, xmm7, xmm5
        vpsrldq	xmm4, xmm7, 4
        vpslldq	xmm7, xmm7, 12
        vpxor	xmm2, xmm2, xmm7
        vpsrld	xmm5, xmm2, 1
        vpsrld	xmm1, xmm2, 2
        vpsrld	xmm0, xmm2, 7
        vpxor	xmm5, xmm5, xmm1
        vpxor	xmm5, xmm5, xmm0
        vpxor	xmm5, xmm5, xmm4
        vpxor	xmm2, xmm2, xmm5
        vpxor	xmm2, xmm2, xmm3
        vmovdqu	OWORD PTR [esp+80], xmm2
        add	ebx, 64
        cmp	ebx, eax
        jl	L_AES_GCM_encrypt_update_avx1_ghash_64
L_AES_GCM_encrypt_update_avx1_end_64:
        movdqu	xmm6, OWORD PTR [esp+80]
        ; Block 1
        vmovdqa	xmm0, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vmovdqu	xmm5, OWORD PTR [edx]
        pshufb	xmm5, xmm0
        vmovdqu	xmm7, OWORD PTR [esp+48]
        pxor	xmm5, xmm6
        ; ghash_gfmul_avx
        vpshufd	xmm1, xmm5, 78
        vpshufd	xmm2, xmm7, 78
        vpclmulqdq	xmm3, xmm7, xmm5, 17
        vpclmulqdq	xmm0, xmm7, xmm5, 0
        vpxor	xmm1, xmm1, xmm5
        vpxor	xmm2, xmm2, xmm7
        vpclmulqdq	xmm1, xmm1, xmm2, 0
        vpxor	xmm1, xmm1, xmm0
        vpxor	xmm1, xmm1, xmm3
        vmovdqa	xmm4, xmm0
        vmovdqa	xmm6, xmm3
        vpslldq	xmm2, xmm1, 8
        vpsrldq	xmm1, xmm1, 8
        vpxor	xmm4, xmm4, xmm2
        vpxor	xmm6, xmm6, xmm1
        ; Block 2
        vmovdqa	xmm0, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vmovdqu	xmm5, OWORD PTR [edx+16]
        pshufb	xmm5, xmm0
        vmovdqu	xmm7, OWORD PTR [esp+32]
        ; ghash_gfmul_xor_avx
        vpshufd	xmm1, xmm5, 78
        vpshufd	xmm2, xmm7, 78
        vpclmulqdq	xmm3, xmm7, xmm5, 17
        vpclmulqdq	xmm0, xmm7, xmm5, 0
        vpxor	xmm1, xmm1, xmm5
        vpxor	xmm2, xmm2, xmm7
        vpclmulqdq	xmm1, xmm1, xmm2, 0
        vpxor	xmm1, xmm1, xmm0
        vpxor	xmm1, xmm1, xmm3
        vpxor	xmm4, xmm4, xmm0
        vpxor	xmm6, xmm6, xmm3
        vpslldq	xmm2, xmm1, 8
        vpsrldq	xmm1, xmm1, 8
        vpxor	xmm4, xmm4, xmm2
        vpxor	xmm6, xmm6, xmm1
        ; Block 3
        vmovdqa	xmm0, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vmovdqu	xmm5, OWORD PTR [edx+32]
        pshufb	xmm5, xmm0
        vmovdqu	xmm7, OWORD PTR [esp+16]
        ; ghash_gfmul_xor_avx
        vpshufd	xmm1, xmm5, 78
        vpshufd	xmm2, xmm7, 78
        vpclmulqdq	xmm3, xmm7, xmm5, 17
        vpclmulqdq	xmm0, xmm7, xmm5, 0
        vpxor	xmm1, xmm1, xmm5
        vpxor	xmm2, xmm2, xmm7
        vpclmulqdq	xmm1, xmm1, xmm2, 0
        vpxor	xmm1, xmm1, xmm0
        vpxor	xmm1, xmm1, xmm3
        vpxor	xmm4, xmm4, xmm0
        vpxor	xmm6, xmm6, xmm3
        vpslldq	xmm2, xmm1, 8
        vpsrldq	xmm1, xmm1, 8
        vpxor	xmm4, xmm4, xmm2
        vpxor	xmm6, xmm6, xmm1
        ; Block 4
        vmovdqa	xmm0, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vmovdqu	xmm5, OWORD PTR [edx+48]
        pshufb	xmm5, xmm0
        vmovdqu	xmm7, OWORD PTR [esp]
        ; ghash_gfmul_xor_avx
        vpshufd	xmm1, xmm5, 78
        vpshufd	xmm2, xmm7, 78
        vpclmulqdq	xmm3, xmm7, xmm5, 17
        vpclmulqdq	xmm0, xmm7, xmm5, 0
        vpxor	xmm1, xmm1, xmm5
        vpxor	xmm2, xmm2, xmm7
        vpclmulqdq	xmm1, xmm1, xmm2, 0
        vpxor	xmm1, xmm1, xmm0
        vpxor	xmm1, xmm1, xmm3
        vpxor	xmm4, xmm4, xmm0
        vpxor	xmm6, xmm6, xmm3
        vpslldq	xmm2, xmm1, 8
        vpsrldq	xmm1, xmm1, 8
        vpxor	xmm4, xmm4, xmm2
        vpxor	xmm6, xmm6, xmm1
        vpslld	xmm0, xmm4, 31
        vpslld	xmm1, xmm4, 30
        vpslld	xmm2, xmm4, 25
        vpxor	xmm0, xmm0, xmm1
        vpxor	xmm0, xmm0, xmm2
        vmovdqa	xmm1, xmm0
        vpsrldq	xmm1, xmm1, 4
        vpslldq	xmm0, xmm0, 12
        vpxor	xmm4, xmm4, xmm0
        vpsrld	xmm2, xmm4, 1
        vpsrld	xmm3, xmm4, 2
        vpsrld	xmm0, xmm4, 7
        vpxor	xmm2, xmm2, xmm3
        vpxor	xmm2, xmm2, xmm0
        vpxor	xmm2, xmm2, xmm1
        vpxor	xmm2, xmm2, xmm4
        vpxor	xmm6, xmm6, xmm2
        vmovdqu	xmm5, OWORD PTR [esp]
L_AES_GCM_encrypt_update_avx1_done_64:
        mov	edx, DWORD PTR [esp+132]
        cmp	ebx, edx
        jge	L_AES_GCM_encrypt_update_avx1_done_enc
        mov	eax, DWORD PTR [esp+132]
        and	eax, 4294967280
        cmp	ebx, eax
        jge	L_AES_GCM_encrypt_update_avx1_last_block_done
        lea	ecx, DWORD PTR [esi+ebx]
        lea	edx, DWORD PTR [edi+ebx]
        vmovdqu	xmm1, OWORD PTR [esp+64]
        vpshufb	xmm0, xmm1, OWORD PTR L_aes_gcm_avx1_bswap_epi64
        vpaddd	xmm1, xmm1, OWORD PTR L_aes_gcm_avx1_one
        vmovdqu	OWORD PTR [esp+64], xmm1
        vpxor	xmm0, xmm0, [ebp]
        vaesenc	xmm0, xmm0, [ebp+16]
        vaesenc	xmm0, xmm0, [ebp+32]
        vaesenc	xmm0, xmm0, [ebp+48]
        vaesenc	xmm0, xmm0, [ebp+64]
        vaesenc	xmm0, xmm0, [ebp+80]
        vaesenc	xmm0, xmm0, [ebp+96]
        vaesenc	xmm0, xmm0, [ebp+112]
        vaesenc	xmm0, xmm0, [ebp+128]
        vaesenc	xmm0, xmm0, [ebp+144]
        cmp	DWORD PTR [esp+120], 11
        vmovdqa	xmm1, OWORD PTR [ebp+160]
        jl	L_AES_GCM_encrypt_update_avx1_aesenc_block_aesenc_avx_last
        vaesenc	xmm0, xmm0, xmm1
        vaesenc	xmm0, xmm0, [ebp+176]
        cmp	DWORD PTR [esp+120], 13
        vmovdqa	xmm1, OWORD PTR [ebp+192]
        jl	L_AES_GCM_encrypt_update_avx1_aesenc_block_aesenc_avx_last
        vaesenc	xmm0, xmm0, xmm1
        vaesenc	xmm0, xmm0, [ebp+208]
        vmovdqa	xmm1, OWORD PTR [ebp+224]
L_AES_GCM_encrypt_update_avx1_aesenc_block_aesenc_avx_last:
        vaesenclast	xmm0, xmm0, xmm1
        vmovdqu	xmm1, OWORD PTR [ecx]
        vpxor	xmm0, xmm0, xmm1
        vmovdqu	OWORD PTR [edx], xmm0
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm6, xmm6, xmm0
        add	ebx, 16
        cmp	ebx, eax
        jge	L_AES_GCM_encrypt_update_avx1_last_block_ghash
L_AES_GCM_encrypt_update_avx1_last_block_start:
        lea	ecx, DWORD PTR [esi+ebx]
        lea	edx, DWORD PTR [edi+ebx]
        vmovdqu	xmm1, OWORD PTR [esp+64]
        vmovdqu	xmm3, xmm6
        vpshufb	xmm0, xmm1, OWORD PTR L_aes_gcm_avx1_bswap_epi64
        vpaddd	xmm1, xmm1, OWORD PTR L_aes_gcm_avx1_one
        vmovdqu	OWORD PTR [esp+64], xmm1
        vpxor	xmm0, xmm0, [ebp]
        vpclmulqdq	xmm4, xmm3, xmm5, 16
        vaesenc	xmm0, xmm0, [ebp+16]
        vaesenc	xmm0, xmm0, [ebp+32]
        vpclmulqdq	xmm7, xmm3, xmm5, 1
        vaesenc	xmm0, xmm0, [ebp+48]
        vaesenc	xmm0, xmm0, [ebp+64]
        vaesenc	xmm0, xmm0, [ebp+80]
        vpclmulqdq	xmm1, xmm3, xmm5, 17
        vaesenc	xmm0, xmm0, [ebp+96]
        vpxor	xmm4, xmm4, xmm7
        vpslldq	xmm2, xmm4, 8
        vpsrldq	xmm4, xmm4, 8
        vaesenc	xmm0, xmm0, [ebp+112]
        vpclmulqdq	xmm7, xmm3, xmm5, 0
        vpxor	xmm2, xmm2, xmm7
        vpxor	xmm1, xmm1, xmm4
        vmovdqa	xmm3, OWORD PTR L_aes_gcm_avx1_mod2_128
        vpclmulqdq	xmm7, xmm2, xmm3, 16
        vaesenc	xmm0, xmm0, [ebp+128]
        vpshufd	xmm4, xmm2, 78
        vpxor	xmm4, xmm4, xmm7
        vpclmulqdq	xmm7, xmm4, xmm3, 16
        vaesenc	xmm0, xmm0, [ebp+144]
        vpshufd	xmm6, xmm4, 78
        vpxor	xmm6, xmm6, xmm7
        vpxor	xmm6, xmm6, xmm1
        cmp	DWORD PTR [esp+120], 11
        vmovdqa	xmm1, OWORD PTR [ebp+160]
        jl	L_AES_GCM_encrypt_update_avx1_aesenc_gfmul_last
        vaesenc	xmm0, xmm0, xmm1
        vaesenc	xmm0, xmm0, [ebp+176]
        cmp	DWORD PTR [esp+120], 13
        vmovdqa	xmm1, OWORD PTR [ebp+192]
        jl	L_AES_GCM_encrypt_update_avx1_aesenc_gfmul_last
        vaesenc	xmm0, xmm0, xmm1
        vaesenc	xmm0, xmm0, [ebp+208]
        vmovdqa	xmm1, OWORD PTR [ebp+224]
L_AES_GCM_encrypt_update_avx1_aesenc_gfmul_last:
        vaesenclast	xmm0, xmm0, xmm1
        vmovdqu	xmm1, OWORD PTR [ecx]
        vpxor	xmm0, xmm0, xmm1
        vmovdqu	OWORD PTR [edx], xmm0
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx1_bswap_mask
        add	ebx, 16
        vpxor	xmm6, xmm6, xmm0
        cmp	ebx, eax
        jl	L_AES_GCM_encrypt_update_avx1_last_block_start
L_AES_GCM_encrypt_update_avx1_last_block_ghash:
        ; ghash_gfmul_red_avx
        vpshufd	xmm1, xmm5, 78
        vpshufd	xmm2, xmm6, 78
        vpclmulqdq	xmm3, xmm6, xmm5, 17
        vpclmulqdq	xmm0, xmm6, xmm5, 0
        vpxor	xmm1, xmm1, xmm5
        vpxor	xmm2, xmm2, xmm6
        vpclmulqdq	xmm1, xmm1, xmm2, 0
        vpxor	xmm1, xmm1, xmm0
        vpxor	xmm1, xmm1, xmm3
        vpslldq	xmm2, xmm1, 8
        vpsrldq	xmm1, xmm1, 8
        vpxor	xmm0, xmm0, xmm2
        vpxor	xmm6, xmm3, xmm1
        vpslld	xmm1, xmm0, 31
        vpslld	xmm2, xmm0, 30
        vpslld	xmm3, xmm0, 25
        vpxor	xmm1, xmm1, xmm2
        vpxor	xmm1, xmm1, xmm3
        vpsrldq	xmm3, xmm1, 4
        vpslldq	xmm1, xmm1, 12
        vpxor	xmm0, xmm0, xmm1
        vpsrld	xmm1, xmm0, 1
        vpsrld	xmm2, xmm0, 2
        vpxor	xmm1, xmm1, xmm2
        vpxor	xmm1, xmm1, xmm0
        vpsrld	xmm0, xmm0, 7
        vpxor	xmm1, xmm1, xmm3
        vpxor	xmm1, xmm1, xmm0
        vpxor	xmm6, xmm6, xmm1
L_AES_GCM_encrypt_update_avx1_last_block_done:
L_AES_GCM_encrypt_update_avx1_done_enc:
        mov	esi, DWORD PTR [esp+136]
        mov	edi, DWORD PTR [esp+144]
        vmovdqu	xmm4, OWORD PTR [esp+64]
        vmovdqa	OWORD PTR [esi], xmm6
        vmovdqu	OWORD PTR [edi], xmm4
        add	esp, 96
        pop	ebp
        pop	edi
        pop	esi
        pop	ebx
        ret
AES_GCM_encrypt_update_avx1 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_GCM_encrypt_final_avx1 PROC
        push	esi
        push	edi
        push	ebp
        sub	esp, 16
        mov	ebp, DWORD PTR [esp+32]
        mov	esi, DWORD PTR [esp+52]
        mov	edi, DWORD PTR [esp+56]
        vmovdqa	xmm4, OWORD PTR [ebp]
        vmovdqa	xmm5, OWORD PTR [esi]
        vmovdqa	xmm6, OWORD PTR [edi]
        vpsrlq	xmm1, xmm5, 63
        vpsllq	xmm0, xmm5, 1
        vpslldq	xmm1, xmm1, 8
        vpor	xmm0, xmm0, xmm1
        vpshufd	xmm5, xmm5, 255
        vpsrad	xmm5, xmm5, 31
        vpand	xmm5, xmm5, OWORD PTR L_aes_gcm_avx1_mod2_128
        vpxor	xmm5, xmm5, xmm0
        mov	edx, DWORD PTR [esp+44]
        mov	ecx, DWORD PTR [esp+48]
        shl	edx, 3
        shl	ecx, 3
        vpinsrd	xmm0, xmm0, edx, 0
        vpinsrd	xmm0, xmm0, ecx, 2
        mov	edx, DWORD PTR [esp+44]
        mov	ecx, DWORD PTR [esp+48]
        shr	edx, 29
        shr	ecx, 29
        vpinsrd	xmm0, xmm0, edx, 1
        vpinsrd	xmm0, xmm0, ecx, 3
        vpxor	xmm4, xmm4, xmm0
        ; ghash_gfmul_red_avx
        vpshufd	xmm1, xmm5, 78
        vpshufd	xmm2, xmm4, 78
        vpclmulqdq	xmm3, xmm4, xmm5, 17
        vpclmulqdq	xmm0, xmm4, xmm5, 0
        vpxor	xmm1, xmm1, xmm5
        vpxor	xmm2, xmm2, xmm4
        vpclmulqdq	xmm1, xmm1, xmm2, 0
        vpxor	xmm1, xmm1, xmm0
        vpxor	xmm1, xmm1, xmm3
        vpslldq	xmm2, xmm1, 8
        vpsrldq	xmm1, xmm1, 8
        vpxor	xmm0, xmm0, xmm2
        vpxor	xmm4, xmm3, xmm1
        vpslld	xmm1, xmm0, 31
        vpslld	xmm2, xmm0, 30
        vpslld	xmm3, xmm0, 25
        vpxor	xmm1, xmm1, xmm2
        vpxor	xmm1, xmm1, xmm3
        vpsrldq	xmm3, xmm1, 4
        vpslldq	xmm1, xmm1, 12
        vpxor	xmm0, xmm0, xmm1
        vpsrld	xmm1, xmm0, 1
        vpsrld	xmm2, xmm0, 2
        vpxor	xmm1, xmm1, xmm2
        vpxor	xmm1, xmm1, xmm0
        vpsrld	xmm0, xmm0, 7
        vpxor	xmm1, xmm1, xmm3
        vpxor	xmm1, xmm1, xmm0
        vpxor	xmm4, xmm4, xmm1
        vpshufb	xmm4, xmm4, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm0, xmm4, xmm6
        mov	edi, DWORD PTR [esp+36]
        cmp	DWORD PTR [esp+40], 16
        je	L_AES_GCM_encrypt_final_avx1_store_tag_16
        xor	ecx, ecx
        vmovdqu	OWORD PTR [esp], xmm0
L_AES_GCM_encrypt_final_avx1_store_tag_loop:
        movzx	eax, BYTE PTR [esp+ecx]
        mov	BYTE PTR [edi+ecx], al
        inc	ecx
        cmp	ecx, DWORD PTR [esp+40]
        jne	L_AES_GCM_encrypt_final_avx1_store_tag_loop
        jmp	L_AES_GCM_encrypt_final_avx1_store_tag_done
L_AES_GCM_encrypt_final_avx1_store_tag_16:
        vmovdqu	OWORD PTR [edi], xmm0
L_AES_GCM_encrypt_final_avx1_store_tag_done:
        add	esp, 16
        pop	ebp
        pop	edi
        pop	esi
        ret
AES_GCM_encrypt_final_avx1 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_GCM_decrypt_update_avx1 PROC
        push	ebx
        push	esi
        push	edi
        push	ebp
        sub	esp, 160
        mov	esi, DWORD PTR [esp+208]
        vmovdqa	xmm4, OWORD PTR [esi]
        vmovdqu	OWORD PTR [esp+64], xmm4
        mov	esi, DWORD PTR [esp+200]
        mov	ebp, DWORD PTR [esp+204]
        vmovdqa	xmm6, OWORD PTR [esi]
        vmovdqa	xmm5, OWORD PTR [ebp]
        vmovdqu	OWORD PTR [esp+80], xmm6
        mov	ebp, DWORD PTR [esp+180]
        mov	edi, DWORD PTR [esp+188]
        mov	esi, DWORD PTR [esp+192]
        vpsrlq	xmm1, xmm5, 63
        vpsllq	xmm0, xmm5, 1
        vpslldq	xmm1, xmm1, 8
        vpor	xmm0, xmm0, xmm1
        vpshufd	xmm5, xmm5, 255
        vpsrad	xmm5, xmm5, 31
        vpand	xmm5, xmm5, OWORD PTR L_aes_gcm_avx1_mod2_128
        vpxor	xmm5, xmm5, xmm0
        xor	ebx, ebx
        cmp	DWORD PTR [esp+196], 64
        mov	eax, DWORD PTR [esp+196]
        jl	L_AES_GCM_decrypt_update_avx1_done_64
        and	eax, 4294967232
        vmovdqa	xmm2, xmm6
        ; H ^ 1
        vmovdqu	OWORD PTR [esp], xmm5
        ; H ^ 2
        vpclmulqdq	xmm0, xmm5, xmm5, 0
        vpclmulqdq	xmm4, xmm5, xmm5, 17
        vpslld	xmm1, xmm0, 31
        vpslld	xmm2, xmm0, 30
        vpslld	xmm3, xmm0, 25
        vpxor	xmm1, xmm1, xmm2
        vpxor	xmm1, xmm1, xmm3
        vpsrldq	xmm3, xmm1, 4
        vpslldq	xmm1, xmm1, 12
        vpxor	xmm0, xmm0, xmm1
        vpsrld	xmm1, xmm0, 1
        vpsrld	xmm2, xmm0, 2
        vpxor	xmm1, xmm1, xmm2
        vpxor	xmm1, xmm1, xmm0
        vpsrld	xmm0, xmm0, 7
        vpxor	xmm1, xmm1, xmm3
        vpxor	xmm1, xmm1, xmm0
        vpxor	xmm4, xmm4, xmm1
        vmovdqu	OWORD PTR [esp+16], xmm4
        ; H ^ 3
        ; ghash_gfmul_red_avx
        vpshufd	xmm1, xmm5, 78
        vpshufd	xmm2, xmm4, 78
        vpclmulqdq	xmm3, xmm4, xmm5, 17
        vpclmulqdq	xmm0, xmm4, xmm5, 0
        vpxor	xmm1, xmm1, xmm5
        vpxor	xmm2, xmm2, xmm4
        vpclmulqdq	xmm1, xmm1, xmm2, 0
        vpxor	xmm1, xmm1, xmm0
        vpxor	xmm1, xmm1, xmm3
        vpslldq	xmm2, xmm1, 8
        vpsrldq	xmm1, xmm1, 8
        vpxor	xmm0, xmm0, xmm2
        vpxor	xmm7, xmm3, xmm1
        vpslld	xmm1, xmm0, 31
        vpslld	xmm2, xmm0, 30
        vpslld	xmm3, xmm0, 25
        vpxor	xmm1, xmm1, xmm2
        vpxor	xmm1, xmm1, xmm3
        vpsrldq	xmm3, xmm1, 4
        vpslldq	xmm1, xmm1, 12
        vpxor	xmm0, xmm0, xmm1
        vpsrld	xmm1, xmm0, 1
        vpsrld	xmm2, xmm0, 2
        vpxor	xmm1, xmm1, xmm2
        vpxor	xmm1, xmm1, xmm0
        vpsrld	xmm0, xmm0, 7
        vpxor	xmm1, xmm1, xmm3
        vpxor	xmm1, xmm1, xmm0
        vpxor	xmm7, xmm7, xmm1
        vmovdqu	OWORD PTR [esp+32], xmm7
        ; H ^ 4
        vpclmulqdq	xmm0, xmm4, xmm4, 0
        vpclmulqdq	xmm7, xmm4, xmm4, 17
        vpslld	xmm1, xmm0, 31
        vpslld	xmm2, xmm0, 30
        vpslld	xmm3, xmm0, 25
        vpxor	xmm1, xmm1, xmm2
        vpxor	xmm1, xmm1, xmm3
        vpsrldq	xmm3, xmm1, 4
        vpslldq	xmm1, xmm1, 12
        vpxor	xmm0, xmm0, xmm1
        vpsrld	xmm1, xmm0, 1
        vpsrld	xmm2, xmm0, 2
        vpxor	xmm1, xmm1, xmm2
        vpxor	xmm1, xmm1, xmm0
        vpsrld	xmm0, xmm0, 7
        vpxor	xmm1, xmm1, xmm3
        vpxor	xmm1, xmm1, xmm0
        vpxor	xmm7, xmm7, xmm1
        vmovdqu	OWORD PTR [esp+48], xmm7
        cmp	edi, esi
        jne	L_AES_GCM_decrypt_update_avx1_ghash_64
L_AES_GCM_decrypt_update_avx1_ghash_64_inplace:
        lea	ecx, DWORD PTR [esi+ebx]
        lea	edx, DWORD PTR [edi+ebx]
        vmovdqu	xmm0, OWORD PTR [esp+64]
        vpaddd	xmm7, xmm0, OWORD PTR L_aes_gcm_avx1_four
        vmovdqu	OWORD PTR [esp+64], xmm7
        vmovdqa	xmm7, OWORD PTR L_aes_gcm_avx1_bswap_epi64
        vpaddd	xmm1, xmm0, OWORD PTR L_aes_gcm_avx1_one
        vpshufb	xmm1, xmm1, xmm7
        vpaddd	xmm2, xmm0, OWORD PTR L_aes_gcm_avx1_two
        vpshufb	xmm2, xmm2, xmm7
        vpaddd	xmm3, xmm0, OWORD PTR L_aes_gcm_avx1_three
        vpshufb	xmm3, xmm3, xmm7
        vpshufb	xmm0, xmm0, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp]
        vpxor	xmm0, xmm0, xmm7
        vpxor	xmm1, xmm1, xmm7
        vpxor	xmm2, xmm2, xmm7
        vpxor	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+16]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+32]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+48]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+64]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+80]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+96]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+112]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+128]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+144]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        cmp	DWORD PTR [esp+184], 11
        vmovdqa	xmm7, OWORD PTR [ebp+160]
        jl	L_AES_GCM_decrypt_update_avx1inplace_aesenc_64_ghash_avx_aesenc_64_enc_done
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+176]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        cmp	DWORD PTR [esp+184], 13
        vmovdqa	xmm7, OWORD PTR [ebp+192]
        jl	L_AES_GCM_decrypt_update_avx1inplace_aesenc_64_ghash_avx_aesenc_64_enc_done
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+208]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+224]
L_AES_GCM_decrypt_update_avx1inplace_aesenc_64_ghash_avx_aesenc_64_enc_done:
        vaesenclast	xmm0, xmm0, xmm7
        vaesenclast	xmm1, xmm1, xmm7
        vmovdqu	xmm4, OWORD PTR [ecx]
        vmovdqu	xmm5, OWORD PTR [ecx+16]
        vpxor	xmm0, xmm0, xmm4
        vpxor	xmm1, xmm1, xmm5
        vmovdqu	OWORD PTR [esp+96], xmm4
        vmovdqu	OWORD PTR [esp+112], xmm5
        vmovdqu	OWORD PTR [edx], xmm0
        vmovdqu	OWORD PTR [edx+16], xmm1
        vaesenclast	xmm2, xmm2, xmm7
        vaesenclast	xmm3, xmm3, xmm7
        vmovdqu	xmm4, OWORD PTR [ecx+32]
        vmovdqu	xmm5, OWORD PTR [ecx+48]
        vpxor	xmm2, xmm2, xmm4
        vpxor	xmm3, xmm3, xmm5
        vmovdqu	OWORD PTR [esp+128], xmm4
        vmovdqu	OWORD PTR [esp+144], xmm5
        vmovdqu	OWORD PTR [edx+32], xmm2
        vmovdqu	OWORD PTR [edx+48], xmm3
        ; ghash encrypted counter
        vmovdqu	xmm2, OWORD PTR [esp+80]
        vmovdqu	xmm7, OWORD PTR [esp+48]
        vmovdqu	xmm0, OWORD PTR [esp+96]
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm0, xmm0, xmm2
        vpshufd	xmm1, xmm7, 78
        vpshufd	xmm5, xmm0, 78
        vpxor	xmm1, xmm1, xmm7
        vpxor	xmm5, xmm5, xmm0
        vpclmulqdq	xmm3, xmm0, xmm7, 17
        vpclmulqdq	xmm2, xmm0, xmm7, 0
        vpclmulqdq	xmm1, xmm1, xmm5, 0
        vpxor	xmm1, xmm1, xmm2
        vpxor	xmm1, xmm1, xmm3
        vmovdqu	xmm7, OWORD PTR [esp+32]
        vmovdqu	xmm0, OWORD PTR [esp+112]
        vpshufd	xmm4, xmm7, 78
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm4, xmm4, xmm7
        vpshufd	xmm5, xmm0, 78
        vpxor	xmm5, xmm5, xmm0
        vpclmulqdq	xmm6, xmm0, xmm7, 17
        vpclmulqdq	xmm7, xmm0, xmm7, 0
        vpclmulqdq	xmm4, xmm4, xmm5, 0
        vpxor	xmm1, xmm1, xmm7
        vpxor	xmm2, xmm2, xmm7
        vpxor	xmm1, xmm1, xmm6
        vpxor	xmm3, xmm3, xmm6
        vpxor	xmm1, xmm1, xmm4
        vmovdqu	xmm7, OWORD PTR [esp+16]
        vmovdqu	xmm0, OWORD PTR [esp+128]
        vpshufd	xmm4, xmm7, 78
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm4, xmm4, xmm7
        vpshufd	xmm5, xmm0, 78
        vpxor	xmm5, xmm5, xmm0
        vpclmulqdq	xmm6, xmm0, xmm7, 17
        vpclmulqdq	xmm7, xmm0, xmm7, 0
        vpclmulqdq	xmm4, xmm4, xmm5, 0
        vpxor	xmm1, xmm1, xmm7
        vpxor	xmm2, xmm2, xmm7
        vpxor	xmm1, xmm1, xmm6
        vpxor	xmm3, xmm3, xmm6
        vpxor	xmm1, xmm1, xmm4
        vmovdqu	xmm7, OWORD PTR [esp]
        vmovdqu	xmm0, OWORD PTR [esp+144]
        vpshufd	xmm4, xmm7, 78
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm4, xmm4, xmm7
        vpshufd	xmm5, xmm0, 78
        vpxor	xmm5, xmm5, xmm0
        vpclmulqdq	xmm6, xmm0, xmm7, 17
        vpclmulqdq	xmm7, xmm0, xmm7, 0
        vpclmulqdq	xmm4, xmm4, xmm5, 0
        vpxor	xmm1, xmm1, xmm7
        vpxor	xmm2, xmm2, xmm7
        vpxor	xmm1, xmm1, xmm6
        vpxor	xmm3, xmm3, xmm6
        vpxor	xmm1, xmm1, xmm4
        vpslldq	xmm5, xmm1, 8
        vpsrldq	xmm1, xmm1, 8
        vpxor	xmm2, xmm2, xmm5
        vpxor	xmm3, xmm3, xmm1
        vpslld	xmm7, xmm2, 31
        vpslld	xmm4, xmm2, 30
        vpslld	xmm5, xmm2, 25
        vpxor	xmm7, xmm7, xmm4
        vpxor	xmm7, xmm7, xmm5
        vpsrldq	xmm4, xmm7, 4
        vpslldq	xmm7, xmm7, 12
        vpxor	xmm2, xmm2, xmm7
        vpsrld	xmm5, xmm2, 1
        vpsrld	xmm1, xmm2, 2
        vpsrld	xmm0, xmm2, 7
        vpxor	xmm5, xmm5, xmm1
        vpxor	xmm5, xmm5, xmm0
        vpxor	xmm5, xmm5, xmm4
        vpxor	xmm2, xmm2, xmm5
        vpxor	xmm2, xmm2, xmm3
        vmovdqu	OWORD PTR [esp+80], xmm2
        add	ebx, 64
        cmp	ebx, eax
        jl	L_AES_GCM_decrypt_update_avx1_ghash_64_inplace
        jmp	L_AES_GCM_decrypt_update_avx1_ghash_64_done
L_AES_GCM_decrypt_update_avx1_ghash_64:
        lea	ecx, DWORD PTR [esi+ebx]
        lea	edx, DWORD PTR [edi+ebx]
        vmovdqu	xmm0, OWORD PTR [esp+64]
        vpaddd	xmm7, xmm0, OWORD PTR L_aes_gcm_avx1_four
        vmovdqu	OWORD PTR [esp+64], xmm7
        vmovdqa	xmm7, OWORD PTR L_aes_gcm_avx1_bswap_epi64
        vpaddd	xmm1, xmm0, OWORD PTR L_aes_gcm_avx1_one
        vpshufb	xmm1, xmm1, xmm7
        vpaddd	xmm2, xmm0, OWORD PTR L_aes_gcm_avx1_two
        vpshufb	xmm2, xmm2, xmm7
        vpaddd	xmm3, xmm0, OWORD PTR L_aes_gcm_avx1_three
        vpshufb	xmm3, xmm3, xmm7
        vpshufb	xmm0, xmm0, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp]
        vpxor	xmm0, xmm0, xmm7
        vpxor	xmm1, xmm1, xmm7
        vpxor	xmm2, xmm2, xmm7
        vpxor	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+16]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+32]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+48]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+64]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+80]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+96]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+112]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+128]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+144]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        cmp	DWORD PTR [esp+184], 11
        vmovdqa	xmm7, OWORD PTR [ebp+160]
        jl	L_AES_GCM_decrypt_update_avx1_aesenc_64_ghash_avx_aesenc_64_enc_done
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+176]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        cmp	DWORD PTR [esp+184], 13
        vmovdqa	xmm7, OWORD PTR [ebp+192]
        jl	L_AES_GCM_decrypt_update_avx1_aesenc_64_ghash_avx_aesenc_64_enc_done
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+208]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqa	xmm7, OWORD PTR [ebp+224]
L_AES_GCM_decrypt_update_avx1_aesenc_64_ghash_avx_aesenc_64_enc_done:
        vaesenclast	xmm0, xmm0, xmm7
        vaesenclast	xmm1, xmm1, xmm7
        vmovdqu	xmm4, OWORD PTR [ecx]
        vmovdqu	xmm5, OWORD PTR [ecx+16]
        vpxor	xmm0, xmm0, xmm4
        vpxor	xmm1, xmm1, xmm5
        vmovdqu	OWORD PTR [edx], xmm0
        vmovdqu	OWORD PTR [edx+16], xmm1
        vaesenclast	xmm2, xmm2, xmm7
        vaesenclast	xmm3, xmm3, xmm7
        vmovdqu	xmm4, OWORD PTR [ecx+32]
        vmovdqu	xmm5, OWORD PTR [ecx+48]
        vpxor	xmm2, xmm2, xmm4
        vpxor	xmm3, xmm3, xmm5
        vmovdqu	OWORD PTR [edx+32], xmm2
        vmovdqu	OWORD PTR [edx+48], xmm3
        ; ghash encrypted counter
        vmovdqu	xmm2, OWORD PTR [esp+80]
        vmovdqu	xmm7, OWORD PTR [esp+48]
        vmovdqu	xmm0, OWORD PTR [ecx]
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm0, xmm0, xmm2
        vpshufd	xmm1, xmm7, 78
        vpshufd	xmm5, xmm0, 78
        vpxor	xmm1, xmm1, xmm7
        vpxor	xmm5, xmm5, xmm0
        vpclmulqdq	xmm3, xmm0, xmm7, 17
        vpclmulqdq	xmm2, xmm0, xmm7, 0
        vpclmulqdq	xmm1, xmm1, xmm5, 0
        vpxor	xmm1, xmm1, xmm2
        vpxor	xmm1, xmm1, xmm3
        vmovdqu	xmm7, OWORD PTR [esp+32]
        vmovdqu	xmm0, OWORD PTR [ecx+16]
        vpshufd	xmm4, xmm7, 78
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm4, xmm4, xmm7
        vpshufd	xmm5, xmm0, 78
        vpxor	xmm5, xmm5, xmm0
        vpclmulqdq	xmm6, xmm0, xmm7, 17
        vpclmulqdq	xmm7, xmm0, xmm7, 0
        vpclmulqdq	xmm4, xmm4, xmm5, 0
        vpxor	xmm1, xmm1, xmm7
        vpxor	xmm2, xmm2, xmm7
        vpxor	xmm1, xmm1, xmm6
        vpxor	xmm3, xmm3, xmm6
        vpxor	xmm1, xmm1, xmm4
        vmovdqu	xmm7, OWORD PTR [esp+16]
        vmovdqu	xmm0, OWORD PTR [ecx+32]
        vpshufd	xmm4, xmm7, 78
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm4, xmm4, xmm7
        vpshufd	xmm5, xmm0, 78
        vpxor	xmm5, xmm5, xmm0
        vpclmulqdq	xmm6, xmm0, xmm7, 17
        vpclmulqdq	xmm7, xmm0, xmm7, 0
        vpclmulqdq	xmm4, xmm4, xmm5, 0
        vpxor	xmm1, xmm1, xmm7
        vpxor	xmm2, xmm2, xmm7
        vpxor	xmm1, xmm1, xmm6
        vpxor	xmm3, xmm3, xmm6
        vpxor	xmm1, xmm1, xmm4
        vmovdqu	xmm7, OWORD PTR [esp]
        vmovdqu	xmm0, OWORD PTR [ecx+48]
        vpshufd	xmm4, xmm7, 78
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm4, xmm4, xmm7
        vpshufd	xmm5, xmm0, 78
        vpxor	xmm5, xmm5, xmm0
        vpclmulqdq	xmm6, xmm0, xmm7, 17
        vpclmulqdq	xmm7, xmm0, xmm7, 0
        vpclmulqdq	xmm4, xmm4, xmm5, 0
        vpxor	xmm1, xmm1, xmm7
        vpxor	xmm2, xmm2, xmm7
        vpxor	xmm1, xmm1, xmm6
        vpxor	xmm3, xmm3, xmm6
        vpxor	xmm1, xmm1, xmm4
        vpslldq	xmm5, xmm1, 8
        vpsrldq	xmm1, xmm1, 8
        vpxor	xmm2, xmm2, xmm5
        vpxor	xmm3, xmm3, xmm1
        vpslld	xmm7, xmm2, 31
        vpslld	xmm4, xmm2, 30
        vpslld	xmm5, xmm2, 25
        vpxor	xmm7, xmm7, xmm4
        vpxor	xmm7, xmm7, xmm5
        vpsrldq	xmm4, xmm7, 4
        vpslldq	xmm7, xmm7, 12
        vpxor	xmm2, xmm2, xmm7
        vpsrld	xmm5, xmm2, 1
        vpsrld	xmm1, xmm2, 2
        vpsrld	xmm0, xmm2, 7
        vpxor	xmm5, xmm5, xmm1
        vpxor	xmm5, xmm5, xmm0
        vpxor	xmm5, xmm5, xmm4
        vpxor	xmm2, xmm2, xmm5
        vpxor	xmm2, xmm2, xmm3
        vmovdqu	OWORD PTR [esp+80], xmm2
        add	ebx, 64
        cmp	ebx, eax
        jl	L_AES_GCM_decrypt_update_avx1_ghash_64
L_AES_GCM_decrypt_update_avx1_ghash_64_done:
        vmovdqa	xmm6, xmm2
        vmovdqu	xmm5, OWORD PTR [esp]
L_AES_GCM_decrypt_update_avx1_done_64:
        mov	edx, DWORD PTR [esp+196]
        cmp	ebx, edx
        jge	L_AES_GCM_decrypt_update_avx1_done_dec
        mov	eax, DWORD PTR [esp+196]
        and	eax, 4294967280
        cmp	ebx, eax
        jge	L_AES_GCM_decrypt_update_avx1_last_block_done
L_AES_GCM_decrypt_update_avx1_last_block_start:
        lea	ecx, DWORD PTR [esi+ebx]
        lea	edx, DWORD PTR [edi+ebx]
        vmovdqu	xmm3, OWORD PTR [ecx]
        vpshufb	xmm3, xmm3, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm3, xmm3, xmm6
        vmovdqu	xmm1, OWORD PTR [esp+64]
        vpshufb	xmm0, xmm1, OWORD PTR L_aes_gcm_avx1_bswap_epi64
        vpaddd	xmm1, xmm1, OWORD PTR L_aes_gcm_avx1_one
        vmovdqu	OWORD PTR [esp+64], xmm1
        vpxor	xmm0, xmm0, [ebp]
        vpclmulqdq	xmm4, xmm3, xmm5, 16
        vaesenc	xmm0, xmm0, [ebp+16]
        vaesenc	xmm0, xmm0, [ebp+32]
        vpclmulqdq	xmm7, xmm3, xmm5, 1
        vaesenc	xmm0, xmm0, [ebp+48]
        vaesenc	xmm0, xmm0, [ebp+64]
        vaesenc	xmm0, xmm0, [ebp+80]
        vpclmulqdq	xmm1, xmm3, xmm5, 17
        vaesenc	xmm0, xmm0, [ebp+96]
        vpxor	xmm4, xmm4, xmm7
        vpslldq	xmm2, xmm4, 8
        vpsrldq	xmm4, xmm4, 8
        vaesenc	xmm0, xmm0, [ebp+112]
        vpclmulqdq	xmm7, xmm3, xmm5, 0
        vpxor	xmm2, xmm2, xmm7
        vpxor	xmm1, xmm1, xmm4
        vmovdqa	xmm3, OWORD PTR L_aes_gcm_avx1_mod2_128
        vpclmulqdq	xmm7, xmm2, xmm3, 16
        vaesenc	xmm0, xmm0, [ebp+128]
        vpshufd	xmm4, xmm2, 78
        vpxor	xmm4, xmm4, xmm7
        vpclmulqdq	xmm7, xmm4, xmm3, 16
        vaesenc	xmm0, xmm0, [ebp+144]
        vpshufd	xmm6, xmm4, 78
        vpxor	xmm6, xmm6, xmm7
        vpxor	xmm6, xmm6, xmm1
        cmp	DWORD PTR [esp+184], 11
        vmovdqa	xmm1, OWORD PTR [ebp+160]
        jl	L_AES_GCM_decrypt_update_avx1_aesenc_gfmul_last
        vaesenc	xmm0, xmm0, xmm1
        vaesenc	xmm0, xmm0, [ebp+176]
        cmp	DWORD PTR [esp+184], 13
        vmovdqa	xmm1, OWORD PTR [ebp+192]
        jl	L_AES_GCM_decrypt_update_avx1_aesenc_gfmul_last
        vaesenc	xmm0, xmm0, xmm1
        vaesenc	xmm0, xmm0, [ebp+208]
        vmovdqa	xmm1, OWORD PTR [ebp+224]
L_AES_GCM_decrypt_update_avx1_aesenc_gfmul_last:
        vaesenclast	xmm0, xmm0, xmm1
        vmovdqu	xmm1, OWORD PTR [ecx]
        vpxor	xmm0, xmm0, xmm1
        vmovdqu	OWORD PTR [edx], xmm0
        add	ebx, 16
        cmp	ebx, eax
        jl	L_AES_GCM_decrypt_update_avx1_last_block_start
L_AES_GCM_decrypt_update_avx1_last_block_done:
L_AES_GCM_decrypt_update_avx1_done_dec:
        mov	esi, DWORD PTR [esp+200]
        mov	edi, DWORD PTR [esp+208]
        vmovdqu	xmm4, OWORD PTR [esp+64]
        vmovdqa	OWORD PTR [esi], xmm6
        vmovdqu	OWORD PTR [edi], xmm4
        add	esp, 160
        pop	ebp
        pop	edi
        pop	esi
        pop	ebx
        ret
AES_GCM_decrypt_update_avx1 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_GCM_decrypt_final_avx1 PROC
        push	ebx
        push	esi
        push	edi
        push	ebp
        sub	esp, 16
        mov	ebp, DWORD PTR [esp+36]
        mov	esi, DWORD PTR [esp+56]
        mov	edi, DWORD PTR [esp+60]
        vmovdqa	xmm6, OWORD PTR [ebp]
        vmovdqa	xmm5, OWORD PTR [esi]
        vmovdqa	xmm7, OWORD PTR [edi]
        vpsrlq	xmm1, xmm5, 63
        vpsllq	xmm0, xmm5, 1
        vpslldq	xmm1, xmm1, 8
        vpor	xmm0, xmm0, xmm1
        vpshufd	xmm5, xmm5, 255
        vpsrad	xmm5, xmm5, 31
        vpand	xmm5, xmm5, OWORD PTR L_aes_gcm_avx1_mod2_128
        vpxor	xmm5, xmm5, xmm0
        mov	edx, DWORD PTR [esp+48]
        mov	ecx, DWORD PTR [esp+52]
        shl	edx, 3
        shl	ecx, 3
        vpinsrd	xmm0, xmm0, edx, 0
        vpinsrd	xmm0, xmm0, ecx, 2
        mov	edx, DWORD PTR [esp+48]
        mov	ecx, DWORD PTR [esp+52]
        shr	edx, 29
        shr	ecx, 29
        vpinsrd	xmm0, xmm0, edx, 1
        vpinsrd	xmm0, xmm0, ecx, 3
        vpxor	xmm6, xmm6, xmm0
        ; ghash_gfmul_red_avx
        vpshufd	xmm1, xmm5, 78
        vpshufd	xmm2, xmm6, 78
        vpclmulqdq	xmm3, xmm6, xmm5, 17
        vpclmulqdq	xmm0, xmm6, xmm5, 0
        vpxor	xmm1, xmm1, xmm5
        vpxor	xmm2, xmm2, xmm6
        vpclmulqdq	xmm1, xmm1, xmm2, 0
        vpxor	xmm1, xmm1, xmm0
        vpxor	xmm1, xmm1, xmm3
        vpslldq	xmm2, xmm1, 8
        vpsrldq	xmm1, xmm1, 8
        vpxor	xmm0, xmm0, xmm2
        vpxor	xmm6, xmm3, xmm1
        vpslld	xmm1, xmm0, 31
        vpslld	xmm2, xmm0, 30
        vpslld	xmm3, xmm0, 25
        vpxor	xmm1, xmm1, xmm2
        vpxor	xmm1, xmm1, xmm3
        vpsrldq	xmm3, xmm1, 4
        vpslldq	xmm1, xmm1, 12
        vpxor	xmm0, xmm0, xmm1
        vpsrld	xmm1, xmm0, 1
        vpsrld	xmm2, xmm0, 2
        vpxor	xmm1, xmm1, xmm2
        vpxor	xmm1, xmm1, xmm0
        vpsrld	xmm0, xmm0, 7
        vpxor	xmm1, xmm1, xmm3
        vpxor	xmm1, xmm1, xmm0
        vpxor	xmm6, xmm6, xmm1
        vpshufb	xmm6, xmm6, OWORD PTR L_aes_gcm_avx1_bswap_mask
        vpxor	xmm0, xmm6, xmm7
        mov	esi, DWORD PTR [esp+40]
        mov	edi, DWORD PTR [esp+64]
        cmp	DWORD PTR [esp+44], 16
        je	L_AES_GCM_decrypt_final_avx1_cmp_tag_16
        sub	esp, 16
        xor	ecx, ecx
        xor	ebx, ebx
        vmovdqu	OWORD PTR [esp], xmm0
L_AES_GCM_decrypt_final_avx1_cmp_tag_loop:
        movzx	eax, BYTE PTR [esp+ecx]
        xor	al, BYTE PTR [esi+ecx]
        or	bl, al
        inc	ecx
        cmp	ecx, DWORD PTR [esp+44]
        jne	L_AES_GCM_decrypt_final_avx1_cmp_tag_loop
        cmp	bl, 0
        sete	bl
        add	esp, 16
        xor	ecx, ecx
        jmp	L_AES_GCM_decrypt_final_avx1_cmp_tag_done
L_AES_GCM_decrypt_final_avx1_cmp_tag_16:
        vmovdqu	xmm1, OWORD PTR [esi]
        vpcmpeqb	xmm0, xmm0, xmm1
        vpmovmskb	edx, xmm0
        ; %%edx == 0xFFFF then return 1 else => return 0
        xor	ebx, ebx
        cmp	edx, 65535
        sete	bl
L_AES_GCM_decrypt_final_avx1_cmp_tag_done:
        mov	DWORD PTR [edi], ebx
        add	esp, 16
        pop	ebp
        pop	edi
        pop	esi
        pop	ebx
        ret
AES_GCM_decrypt_final_avx1 ENDP
_TEXT ENDS
ENDIF
ENDIF
IFDEF HAVE_INTEL_AVX2
_TEXT SEGMENT READONLY PARA
AES_GCM_encrypt_avx2 PROC
        push	ebx
        push	esi
        push	edi
        push	ebp
        sub	esp, 112
        mov	esi, DWORD PTR [esp+144]
        mov	ebp, DWORD PTR [esp+168]
        mov	edx, DWORD PTR [esp+160]
        vpxor	xmm4, xmm4, xmm4
        cmp	edx, 12
        je	L_AES_GCM_encrypt_avx2_iv_12
        ; Calculate values when IV is not 12 bytes
        ; H = Encrypt X(=0)
        vmovdqu	xmm5, OWORD PTR [ebp]
        vaesenc	xmm5, xmm5, [ebp+16]
        vaesenc	xmm5, xmm5, [ebp+32]
        vaesenc	xmm5, xmm5, [ebp+48]
        vaesenc	xmm5, xmm5, [ebp+64]
        vaesenc	xmm5, xmm5, [ebp+80]
        vaesenc	xmm5, xmm5, [ebp+96]
        vaesenc	xmm5, xmm5, [ebp+112]
        vaesenc	xmm5, xmm5, [ebp+128]
        vaesenc	xmm5, xmm5, [ebp+144]
        cmp	DWORD PTR [esp+172], 11
        vmovdqu	xmm0, OWORD PTR [ebp+160]
        jl	L_AES_GCM_encrypt_avx2_calc_iv_1_aesenc_avx_last
        vaesenc	xmm5, xmm5, xmm0
        vaesenc	xmm5, xmm5, [ebp+176]
        cmp	DWORD PTR [esp+172], 13
        vmovdqu	xmm0, OWORD PTR [ebp+192]
        jl	L_AES_GCM_encrypt_avx2_calc_iv_1_aesenc_avx_last
        vaesenc	xmm5, xmm5, xmm0
        vaesenc	xmm5, xmm5, [ebp+208]
        vmovdqu	xmm0, OWORD PTR [ebp+224]
L_AES_GCM_encrypt_avx2_calc_iv_1_aesenc_avx_last:
        vaesenclast	xmm5, xmm5, xmm0
        vpshufb	xmm5, xmm5, OWORD PTR L_aes_gcm_avx2_bswap_mask
        ; Calc counter
        ; Initialization vector
        cmp	edx, 0
        mov	ecx, 0
        je	L_AES_GCM_encrypt_avx2_calc_iv_done
        cmp	edx, 16
        jl	L_AES_GCM_encrypt_avx2_calc_iv_lt16
        and	edx, 4294967280
L_AES_GCM_encrypt_avx2_calc_iv_16_loop:
        vmovdqu	xmm0, OWORD PTR [esi+ecx]
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpxor	xmm4, xmm4, xmm0
        ; ghash_gfmul_avx
        vpclmulqdq	xmm2, xmm5, xmm4, 16
        vpclmulqdq	xmm1, xmm5, xmm4, 1
        vpclmulqdq	xmm0, xmm5, xmm4, 0
        vpclmulqdq	xmm3, xmm5, xmm4, 17
        vpxor	xmm2, xmm2, xmm1
        vpslldq	xmm1, xmm2, 8
        vpsrldq	xmm2, xmm2, 8
        vpxor	xmm7, xmm0, xmm1
        vpxor	xmm4, xmm3, xmm2
        ; ghash_mid
        vpsrld	xmm0, xmm7, 31
        vpsrld	xmm1, xmm4, 31
        vpslld	xmm7, xmm7, 1
        vpslld	xmm4, xmm4, 1
        vpsrldq	xmm2, xmm0, 12
        vpslldq	xmm0, xmm0, 4
        vpslldq	xmm1, xmm1, 4
        vpor	xmm4, xmm4, xmm2
        vpor	xmm7, xmm7, xmm0
        vpor	xmm4, xmm4, xmm1
        ; ghash_red
        vmovdqu	xmm2, OWORD PTR L_aes_gcm_avx2_mod2_128
        vpclmulqdq	xmm0, xmm7, xmm2, 16
        vpshufd	xmm1, xmm7, 78
        vpxor	xmm1, xmm1, xmm0
        vpclmulqdq	xmm0, xmm1, xmm2, 16
        vpshufd	xmm1, xmm1, 78
        vpxor	xmm1, xmm1, xmm0
        vpxor	xmm4, xmm4, xmm1
        add	ecx, 16
        cmp	ecx, edx
        jl	L_AES_GCM_encrypt_avx2_calc_iv_16_loop
        mov	edx, DWORD PTR [esp+160]
        cmp	ecx, edx
        je	L_AES_GCM_encrypt_avx2_calc_iv_done
L_AES_GCM_encrypt_avx2_calc_iv_lt16:
        vpxor	xmm0, xmm0, xmm0
        xor	ebx, ebx
        vmovdqu	OWORD PTR [esp], xmm0
L_AES_GCM_encrypt_avx2_calc_iv_loop:
        movzx	eax, BYTE PTR [esi+ecx]
        mov	BYTE PTR [esp+ebx], al
        inc	ecx
        inc	ebx
        cmp	ecx, edx
        jl	L_AES_GCM_encrypt_avx2_calc_iv_loop
        vmovdqu	xmm0, OWORD PTR [esp]
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpxor	xmm4, xmm4, xmm0
        ; ghash_gfmul_avx
        vpclmulqdq	xmm2, xmm5, xmm4, 16
        vpclmulqdq	xmm1, xmm5, xmm4, 1
        vpclmulqdq	xmm0, xmm5, xmm4, 0
        vpclmulqdq	xmm3, xmm5, xmm4, 17
        vpxor	xmm2, xmm2, xmm1
        vpslldq	xmm1, xmm2, 8
        vpsrldq	xmm2, xmm2, 8
        vpxor	xmm7, xmm0, xmm1
        vpxor	xmm4, xmm3, xmm2
        ; ghash_mid
        vpsrld	xmm0, xmm7, 31
        vpsrld	xmm1, xmm4, 31
        vpslld	xmm7, xmm7, 1
        vpslld	xmm4, xmm4, 1
        vpsrldq	xmm2, xmm0, 12
        vpslldq	xmm0, xmm0, 4
        vpslldq	xmm1, xmm1, 4
        vpor	xmm4, xmm4, xmm2
        vpor	xmm7, xmm7, xmm0
        vpor	xmm4, xmm4, xmm1
        ; ghash_red
        vmovdqu	xmm2, OWORD PTR L_aes_gcm_avx2_mod2_128
        vpclmulqdq	xmm0, xmm7, xmm2, 16
        vpshufd	xmm1, xmm7, 78
        vpxor	xmm1, xmm1, xmm0
        vpclmulqdq	xmm0, xmm1, xmm2, 16
        vpshufd	xmm1, xmm1, 78
        vpxor	xmm1, xmm1, xmm0
        vpxor	xmm4, xmm4, xmm1
L_AES_GCM_encrypt_avx2_calc_iv_done:
        ; T = Encrypt counter
        vpxor	xmm0, xmm0, xmm0
        shl	edx, 3
        vpinsrd	xmm0, xmm0, edx, 0
        vpxor	xmm4, xmm4, xmm0
        ; ghash_gfmul_avx
        vpclmulqdq	xmm2, xmm5, xmm4, 16
        vpclmulqdq	xmm1, xmm5, xmm4, 1
        vpclmulqdq	xmm0, xmm5, xmm4, 0
        vpclmulqdq	xmm3, xmm5, xmm4, 17
        vpxor	xmm2, xmm2, xmm1
        vpslldq	xmm1, xmm2, 8
        vpsrldq	xmm2, xmm2, 8
        vpxor	xmm7, xmm0, xmm1
        vpxor	xmm4, xmm3, xmm2
        ; ghash_mid
        vpsrld	xmm0, xmm7, 31
        vpsrld	xmm1, xmm4, 31
        vpslld	xmm7, xmm7, 1
        vpslld	xmm4, xmm4, 1
        vpsrldq	xmm2, xmm0, 12
        vpslldq	xmm0, xmm0, 4
        vpslldq	xmm1, xmm1, 4
        vpor	xmm4, xmm4, xmm2
        vpor	xmm7, xmm7, xmm0
        vpor	xmm4, xmm4, xmm1
        ; ghash_red
        vmovdqu	xmm2, OWORD PTR L_aes_gcm_avx2_mod2_128
        vpclmulqdq	xmm0, xmm7, xmm2, 16
        vpshufd	xmm1, xmm7, 78
        vpxor	xmm1, xmm1, xmm0
        vpclmulqdq	xmm0, xmm1, xmm2, 16
        vpshufd	xmm1, xmm1, 78
        vpxor	xmm1, xmm1, xmm0
        vpxor	xmm4, xmm4, xmm1
        vpshufb	xmm4, xmm4, OWORD PTR L_aes_gcm_avx2_bswap_mask
        ;   Encrypt counter
        vmovdqu	xmm6, OWORD PTR [ebp]
        vpxor	xmm6, xmm6, xmm4
        vaesenc	xmm6, xmm6, [ebp+16]
        vaesenc	xmm6, xmm6, [ebp+32]
        vaesenc	xmm6, xmm6, [ebp+48]
        vaesenc	xmm6, xmm6, [ebp+64]
        vaesenc	xmm6, xmm6, [ebp+80]
        vaesenc	xmm6, xmm6, [ebp+96]
        vaesenc	xmm6, xmm6, [ebp+112]
        vaesenc	xmm6, xmm6, [ebp+128]
        vaesenc	xmm6, xmm6, [ebp+144]
        cmp	DWORD PTR [esp+172], 11
        vmovdqu	xmm0, OWORD PTR [ebp+160]
        jl	L_AES_GCM_encrypt_avx2_calc_iv_2_aesenc_avx_last
        vaesenc	xmm6, xmm6, xmm0
        vaesenc	xmm6, xmm6, [ebp+176]
        cmp	DWORD PTR [esp+172], 13
        vmovdqu	xmm0, OWORD PTR [ebp+192]
        jl	L_AES_GCM_encrypt_avx2_calc_iv_2_aesenc_avx_last
        vaesenc	xmm6, xmm6, xmm0
        vaesenc	xmm6, xmm6, [ebp+208]
        vmovdqu	xmm0, OWORD PTR [ebp+224]
L_AES_GCM_encrypt_avx2_calc_iv_2_aesenc_avx_last:
        vaesenclast	xmm6, xmm6, xmm0
        jmp	L_AES_GCM_encrypt_avx2_iv_done
L_AES_GCM_encrypt_avx2_iv_12:
        ; # Calculate values when IV is 12 bytes
        ; Set counter based on IV
        vmovdqu	xmm4, OWORD PTR L_avx2_aes_gcm_bswap_one
        vmovdqu	xmm5, OWORD PTR [ebp]
        vpblendd	xmm4, xmm4, [esi], 7
        ; H = Encrypt X(=0) and T = Encrypt counter
        vmovdqu	xmm7, OWORD PTR [ebp+16]
        vpxor	xmm6, xmm4, xmm5
        vaesenc	xmm5, xmm5, xmm7
        vaesenc	xmm6, xmm6, xmm7
        vmovdqu	xmm0, OWORD PTR [ebp+32]
        vaesenc	xmm5, xmm5, xmm0
        vaesenc	xmm6, xmm6, xmm0
        vmovdqu	xmm0, OWORD PTR [ebp+48]
        vaesenc	xmm5, xmm5, xmm0
        vaesenc	xmm6, xmm6, xmm0
        vmovdqu	xmm0, OWORD PTR [ebp+64]
        vaesenc	xmm5, xmm5, xmm0
        vaesenc	xmm6, xmm6, xmm0
        vmovdqu	xmm0, OWORD PTR [ebp+80]
        vaesenc	xmm5, xmm5, xmm0
        vaesenc	xmm6, xmm6, xmm0
        vmovdqu	xmm0, OWORD PTR [ebp+96]
        vaesenc	xmm5, xmm5, xmm0
        vaesenc	xmm6, xmm6, xmm0
        vmovdqu	xmm0, OWORD PTR [ebp+112]
        vaesenc	xmm5, xmm5, xmm0
        vaesenc	xmm6, xmm6, xmm0
        vmovdqu	xmm0, OWORD PTR [ebp+128]
        vaesenc	xmm5, xmm5, xmm0
        vaesenc	xmm6, xmm6, xmm0
        vmovdqu	xmm0, OWORD PTR [ebp+144]
        vaesenc	xmm5, xmm5, xmm0
        vaesenc	xmm6, xmm6, xmm0
        cmp	DWORD PTR [esp+172], 11
        vmovdqu	xmm0, OWORD PTR [ebp+160]
        jl	L_AES_GCM_encrypt_avx2_calc_iv_12_last
        vaesenc	xmm5, xmm5, xmm0
        vaesenc	xmm6, xmm6, xmm0
        vmovdqu	xmm0, OWORD PTR [ebp+176]
        vaesenc	xmm5, xmm5, xmm0
        vaesenc	xmm6, xmm6, xmm0
        cmp	DWORD PTR [esp+172], 13
        vmovdqu	xmm0, OWORD PTR [ebp+192]
        jl	L_AES_GCM_encrypt_avx2_calc_iv_12_last
        vaesenc	xmm5, xmm5, xmm0
        vaesenc	xmm6, xmm6, xmm0
        vmovdqu	xmm0, OWORD PTR [ebp+208]
        vaesenc	xmm5, xmm5, xmm0
        vaesenc	xmm6, xmm6, xmm0
        vmovdqu	xmm0, OWORD PTR [ebp+224]
L_AES_GCM_encrypt_avx2_calc_iv_12_last:
        vaesenclast	xmm5, xmm5, xmm0
        vaesenclast	xmm6, xmm6, xmm0
        vpshufb	xmm5, xmm5, OWORD PTR L_aes_gcm_avx2_bswap_mask
L_AES_GCM_encrypt_avx2_iv_done:
        vmovdqu	OWORD PTR [esp+80], xmm6
        vpxor	xmm6, xmm6, xmm6
        mov	esi, DWORD PTR [esp+140]
        ; Additional authentication data
        mov	edx, DWORD PTR [esp+156]
        cmp	edx, 0
        je	L_AES_GCM_encrypt_avx2_calc_aad_done
        xor	ecx, ecx
        cmp	edx, 16
        jl	L_AES_GCM_encrypt_avx2_calc_aad_lt16
        and	edx, 4294967280
L_AES_GCM_encrypt_avx2_calc_aad_16_loop:
        vmovdqu	xmm0, OWORD PTR [esi+ecx]
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpxor	xmm6, xmm6, xmm0
        ; ghash_gfmul_avx
        vpclmulqdq	xmm2, xmm5, xmm6, 16
        vpclmulqdq	xmm1, xmm5, xmm6, 1
        vpclmulqdq	xmm0, xmm5, xmm6, 0
        vpclmulqdq	xmm3, xmm5, xmm6, 17
        vpxor	xmm2, xmm2, xmm1
        vpslldq	xmm1, xmm2, 8
        vpsrldq	xmm2, xmm2, 8
        vpxor	xmm7, xmm0, xmm1
        vpxor	xmm6, xmm3, xmm2
        ; ghash_mid
        vpsrld	xmm0, xmm7, 31
        vpsrld	xmm1, xmm6, 31
        vpslld	xmm7, xmm7, 1
        vpslld	xmm6, xmm6, 1
        vpsrldq	xmm2, xmm0, 12
        vpslldq	xmm0, xmm0, 4
        vpslldq	xmm1, xmm1, 4
        vpor	xmm6, xmm6, xmm2
        vpor	xmm7, xmm7, xmm0
        vpor	xmm6, xmm6, xmm1
        ; ghash_red
        vmovdqu	xmm2, OWORD PTR L_aes_gcm_avx2_mod2_128
        vpclmulqdq	xmm0, xmm7, xmm2, 16
        vpshufd	xmm1, xmm7, 78
        vpxor	xmm1, xmm1, xmm0
        vpclmulqdq	xmm0, xmm1, xmm2, 16
        vpshufd	xmm1, xmm1, 78
        vpxor	xmm1, xmm1, xmm0
        vpxor	xmm6, xmm6, xmm1
        add	ecx, 16
        cmp	ecx, edx
        jl	L_AES_GCM_encrypt_avx2_calc_aad_16_loop
        mov	edx, DWORD PTR [esp+156]
        cmp	ecx, edx
        je	L_AES_GCM_encrypt_avx2_calc_aad_done
L_AES_GCM_encrypt_avx2_calc_aad_lt16:
        vpxor	xmm0, xmm0, xmm0
        xor	ebx, ebx
        vmovdqu	OWORD PTR [esp], xmm0
L_AES_GCM_encrypt_avx2_calc_aad_loop:
        movzx	eax, BYTE PTR [esi+ecx]
        mov	BYTE PTR [esp+ebx], al
        inc	ecx
        inc	ebx
        cmp	ecx, edx
        jl	L_AES_GCM_encrypt_avx2_calc_aad_loop
        vmovdqu	xmm0, OWORD PTR [esp]
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpxor	xmm6, xmm6, xmm0
        ; ghash_gfmul_avx
        vpclmulqdq	xmm2, xmm5, xmm6, 16
        vpclmulqdq	xmm1, xmm5, xmm6, 1
        vpclmulqdq	xmm0, xmm5, xmm6, 0
        vpclmulqdq	xmm3, xmm5, xmm6, 17
        vpxor	xmm2, xmm2, xmm1
        vpslldq	xmm1, xmm2, 8
        vpsrldq	xmm2, xmm2, 8
        vpxor	xmm7, xmm0, xmm1
        vpxor	xmm6, xmm3, xmm2
        ; ghash_mid
        vpsrld	xmm0, xmm7, 31
        vpsrld	xmm1, xmm6, 31
        vpslld	xmm7, xmm7, 1
        vpslld	xmm6, xmm6, 1
        vpsrldq	xmm2, xmm0, 12
        vpslldq	xmm0, xmm0, 4
        vpslldq	xmm1, xmm1, 4
        vpor	xmm6, xmm6, xmm2
        vpor	xmm7, xmm7, xmm0
        vpor	xmm6, xmm6, xmm1
        ; ghash_red
        vmovdqu	xmm2, OWORD PTR L_aes_gcm_avx2_mod2_128
        vpclmulqdq	xmm0, xmm7, xmm2, 16
        vpshufd	xmm1, xmm7, 78
        vpxor	xmm1, xmm1, xmm0
        vpclmulqdq	xmm0, xmm1, xmm2, 16
        vpshufd	xmm1, xmm1, 78
        vpxor	xmm1, xmm1, xmm0
        vpxor	xmm6, xmm6, xmm1
L_AES_GCM_encrypt_avx2_calc_aad_done:
        mov	esi, DWORD PTR [esp+132]
        mov	edi, DWORD PTR [esp+136]
        ; Calculate counter and H
        vpsrlq	xmm1, xmm5, 63
        vpsllq	xmm0, xmm5, 1
        vpslldq	xmm1, xmm1, 8
        vpor	xmm0, xmm0, xmm1
        vpshufd	xmm5, xmm5, 255
        vpsrad	xmm5, xmm5, 31
        vpshufb	xmm4, xmm4, OWORD PTR L_aes_gcm_avx2_bswap_epi64
        vpand	xmm5, xmm5, OWORD PTR L_aes_gcm_avx2_mod2_128
        vpaddd	xmm4, xmm4, OWORD PTR L_aes_gcm_avx2_one
        vpxor	xmm5, xmm5, xmm0
        xor	ebx, ebx
        cmp	DWORD PTR [esp+152], 64
        mov	eax, DWORD PTR [esp+152]
        jl	L_AES_GCM_encrypt_avx2_done_64
        and	eax, 4294967232
        vmovdqu	OWORD PTR [esp+64], xmm4
        vmovdqu	OWORD PTR [esp+96], xmm6
        vmovdqu	xmm3, OWORD PTR L_aes_gcm_avx2_mod2_128
        ; H ^ 1
        vmovdqu	OWORD PTR [esp], xmm5
        vmovdqu	xmm2, xmm5
        ; H ^ 2
        vpclmulqdq	xmm5, xmm2, xmm2, 0
        vpclmulqdq	xmm6, xmm2, xmm2, 17
        vpclmulqdq	xmm4, xmm5, xmm3, 16
        vpshufd	xmm5, xmm5, 78
        vpxor	xmm5, xmm5, xmm4
        vpclmulqdq	xmm4, xmm5, xmm3, 16
        vpshufd	xmm5, xmm5, 78
        vpxor	xmm5, xmm5, xmm4
        vpxor	xmm0, xmm6, xmm5
        vmovdqu	OWORD PTR [esp+16], xmm0
        ; H ^ 3
        ; ghash_gfmul_red
        vpclmulqdq	xmm6, xmm2, xmm0, 16
        vpclmulqdq	xmm5, xmm2, xmm0, 1
        vpclmulqdq	xmm4, xmm2, xmm0, 0
        vpxor	xmm6, xmm6, xmm5
        vpslldq	xmm5, xmm6, 8
        vpsrldq	xmm6, xmm6, 8
        vpxor	xmm5, xmm5, xmm4
        vpclmulqdq	xmm1, xmm2, xmm0, 17
        vpclmulqdq	xmm4, xmm5, xmm3, 16
        vpshufd	xmm5, xmm5, 78
        vpxor	xmm5, xmm5, xmm4
        vpclmulqdq	xmm4, xmm5, xmm3, 16
        vpshufd	xmm5, xmm5, 78
        vpxor	xmm1, xmm1, xmm6
        vpxor	xmm1, xmm1, xmm5
        vpxor	xmm1, xmm1, xmm4
        vmovdqu	OWORD PTR [esp+32], xmm1
        ; H ^ 4
        vpclmulqdq	xmm5, xmm0, xmm0, 0
        vpclmulqdq	xmm6, xmm0, xmm0, 17
        vpclmulqdq	xmm4, xmm5, xmm3, 16
        vpshufd	xmm5, xmm5, 78
        vpxor	xmm5, xmm5, xmm4
        vpclmulqdq	xmm4, xmm5, xmm3, 16
        vpshufd	xmm5, xmm5, 78
        vpxor	xmm5, xmm5, xmm4
        vpxor	xmm2, xmm6, xmm5
        vmovdqu	OWORD PTR [esp+48], xmm2
        vmovdqu	xmm6, OWORD PTR [esp+96]
        ; First 64 bytes of input
        ; aesenc_64
        ; aesenc_ctr
        vmovdqu	xmm4, OWORD PTR [esp+64]
        vmovdqu	xmm7, OWORD PTR L_aes_gcm_avx2_bswap_epi64
        vpaddd	xmm1, xmm4, OWORD PTR L_aes_gcm_avx2_one
        vpshufb	xmm0, xmm4, xmm7
        vpaddd	xmm2, xmm4, OWORD PTR L_aes_gcm_avx2_two
        vpshufb	xmm1, xmm1, xmm7
        vpaddd	xmm3, xmm4, OWORD PTR L_aes_gcm_avx2_three
        vpshufb	xmm2, xmm2, xmm7
        vpaddd	xmm4, xmm4, OWORD PTR L_aes_gcm_avx2_four
        vpshufb	xmm3, xmm3, xmm7
        ; aesenc_xor
        vmovdqu	xmm7, OWORD PTR [ebp]
        vmovdqu	OWORD PTR [esp+64], xmm4
        vpxor	xmm0, xmm0, xmm7
        vpxor	xmm1, xmm1, xmm7
        vpxor	xmm2, xmm2, xmm7
        vpxor	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+16]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+32]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+48]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+64]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+80]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+96]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+112]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+128]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+144]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        cmp	DWORD PTR [esp+172], 11
        vmovdqu	xmm7, OWORD PTR [ebp+160]
        jl	L_AES_GCM_encrypt_avx2_aesenc_64_enc_done
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+176]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        cmp	DWORD PTR [esp+172], 13
        vmovdqu	xmm7, OWORD PTR [ebp+192]
        jl	L_AES_GCM_encrypt_avx2_aesenc_64_enc_done
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+208]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+224]
L_AES_GCM_encrypt_avx2_aesenc_64_enc_done:
        ; aesenc_last
        vaesenclast	xmm0, xmm0, xmm7
        vaesenclast	xmm1, xmm1, xmm7
        vaesenclast	xmm2, xmm2, xmm7
        vaesenclast	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [esi]
        vmovdqu	xmm4, OWORD PTR [esi+16]
        vpxor	xmm0, xmm0, xmm7
        vpxor	xmm1, xmm1, xmm4
        vmovdqu	OWORD PTR [edi], xmm0
        vmovdqu	OWORD PTR [edi+16], xmm1
        vmovdqu	xmm7, OWORD PTR [esi+32]
        vmovdqu	xmm4, OWORD PTR [esi+48]
        vpxor	xmm2, xmm2, xmm7
        vpxor	xmm3, xmm3, xmm4
        vmovdqu	OWORD PTR [edi+32], xmm2
        vmovdqu	OWORD PTR [edi+48], xmm3
        cmp	eax, 64
        mov	ebx, 64
        mov	ecx, esi
        mov	edx, edi
        jle	L_AES_GCM_encrypt_avx2_end_64
        ; More 64 bytes of input
L_AES_GCM_encrypt_avx2_ghash_64:
        ; aesenc_64_ghash
        lea	ecx, DWORD PTR [esi+ebx]
        lea	edx, DWORD PTR [edi+ebx]
        ; aesenc_64
        ; aesenc_ctr
        vmovdqu	xmm4, OWORD PTR [esp+64]
        vmovdqu	xmm7, OWORD PTR L_aes_gcm_avx2_bswap_epi64
        vpaddd	xmm1, xmm4, OWORD PTR L_aes_gcm_avx2_one
        vpshufb	xmm0, xmm4, xmm7
        vpaddd	xmm2, xmm4, OWORD PTR L_aes_gcm_avx2_two
        vpshufb	xmm1, xmm1, xmm7
        vpaddd	xmm3, xmm4, OWORD PTR L_aes_gcm_avx2_three
        vpshufb	xmm2, xmm2, xmm7
        vpaddd	xmm4, xmm4, OWORD PTR L_aes_gcm_avx2_four
        vpshufb	xmm3, xmm3, xmm7
        ; aesenc_xor
        vmovdqu	xmm7, OWORD PTR [ebp]
        vmovdqu	OWORD PTR [esp+64], xmm4
        vpxor	xmm0, xmm0, xmm7
        vpxor	xmm1, xmm1, xmm7
        vpxor	xmm2, xmm2, xmm7
        vpxor	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+16]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+32]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+48]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+64]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+80]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+96]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+112]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+128]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+144]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        cmp	DWORD PTR [esp+172], 11
        vmovdqu	xmm7, OWORD PTR [ebp+160]
        jl	L_AES_GCM_encrypt_avx2_aesenc_64_ghash_aesenc_64_enc_done
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+176]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        cmp	DWORD PTR [esp+172], 13
        vmovdqu	xmm7, OWORD PTR [ebp+192]
        jl	L_AES_GCM_encrypt_avx2_aesenc_64_ghash_aesenc_64_enc_done
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+208]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+224]
L_AES_GCM_encrypt_avx2_aesenc_64_ghash_aesenc_64_enc_done:
        ; aesenc_last
        vaesenclast	xmm0, xmm0, xmm7
        vaesenclast	xmm1, xmm1, xmm7
        vaesenclast	xmm2, xmm2, xmm7
        vaesenclast	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ecx]
        vmovdqu	xmm4, OWORD PTR [ecx+16]
        vpxor	xmm0, xmm0, xmm7
        vpxor	xmm1, xmm1, xmm4
        vmovdqu	OWORD PTR [edx], xmm0
        vmovdqu	OWORD PTR [edx+16], xmm1
        vmovdqu	xmm7, OWORD PTR [ecx+32]
        vmovdqu	xmm4, OWORD PTR [ecx+48]
        vpxor	xmm2, xmm2, xmm7
        vpxor	xmm3, xmm3, xmm4
        vmovdqu	OWORD PTR [edx+32], xmm2
        vmovdqu	OWORD PTR [edx+48], xmm3
        ; pclmul_1
        vmovdqu	xmm1, OWORD PTR [edx+-64]
        vpshufb	xmm1, xmm1, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vmovdqu	xmm2, OWORD PTR [esp+48]
        vpxor	xmm1, xmm1, xmm6
        vpclmulqdq	xmm5, xmm1, xmm2, 16
        vpclmulqdq	xmm3, xmm1, xmm2, 1
        vpclmulqdq	xmm6, xmm1, xmm2, 0
        vpclmulqdq	xmm7, xmm1, xmm2, 17
        ; pclmul_2
        vmovdqu	xmm1, OWORD PTR [edx+-48]
        vmovdqu	xmm0, OWORD PTR [esp+32]
        vpshufb	xmm1, xmm1, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpxor	xmm5, xmm5, xmm3
        vpclmulqdq	xmm2, xmm1, xmm0, 16
        vpclmulqdq	xmm3, xmm1, xmm0, 1
        vpclmulqdq	xmm4, xmm1, xmm0, 0
        vpclmulqdq	xmm1, xmm1, xmm0, 17
        vpxor	xmm7, xmm7, xmm1
        ; pclmul_n
        vmovdqu	xmm1, OWORD PTR [edx+-32]
        vmovdqu	xmm0, OWORD PTR [esp+16]
        vpshufb	xmm1, xmm1, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpxor	xmm5, xmm5, xmm2
        vpclmulqdq	xmm2, xmm1, xmm0, 16
        vpxor	xmm5, xmm5, xmm3
        vpclmulqdq	xmm3, xmm1, xmm0, 1
        vpxor	xmm6, xmm6, xmm4
        vpclmulqdq	xmm4, xmm1, xmm0, 0
        vpclmulqdq	xmm1, xmm1, xmm0, 17
        vpxor	xmm7, xmm7, xmm1
        ; pclmul_n
        vmovdqu	xmm1, OWORD PTR [edx+-16]
        vmovdqu	xmm0, OWORD PTR [esp]
        vpshufb	xmm1, xmm1, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpxor	xmm5, xmm5, xmm2
        vpclmulqdq	xmm2, xmm1, xmm0, 16
        vpxor	xmm5, xmm5, xmm3
        vpclmulqdq	xmm3, xmm1, xmm0, 1
        vpxor	xmm6, xmm6, xmm4
        vpclmulqdq	xmm4, xmm1, xmm0, 0
        vpclmulqdq	xmm1, xmm1, xmm0, 17
        vpxor	xmm7, xmm7, xmm1
        ; aesenc_pclmul_l
        vpxor	xmm5, xmm5, xmm2
        vpxor	xmm6, xmm6, xmm4
        vpxor	xmm5, xmm5, xmm3
        vpslldq	xmm1, xmm5, 8
        vpsrldq	xmm5, xmm5, 8
        vmovdqu	xmm0, OWORD PTR L_aes_gcm_avx2_mod2_128
        vpxor	xmm6, xmm6, xmm1
        vpxor	xmm7, xmm7, xmm5
        vpclmulqdq	xmm3, xmm6, xmm0, 16
        vpshufd	xmm6, xmm6, 78
        vpxor	xmm6, xmm6, xmm3
        vpclmulqdq	xmm3, xmm6, xmm0, 16
        vpshufd	xmm6, xmm6, 78
        vpxor	xmm6, xmm6, xmm3
        vpxor	xmm6, xmm6, xmm7
        ; aesenc_64_ghash - end
        add	ebx, 64
        cmp	ebx, eax
        jl	L_AES_GCM_encrypt_avx2_ghash_64
L_AES_GCM_encrypt_avx2_end_64:
        vmovdqu	OWORD PTR [esp+96], xmm6
        vmovdqu	xmm3, OWORD PTR [edx+48]
        vmovdqu	xmm7, OWORD PTR [esp]
        vpshufb	xmm3, xmm3, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpclmulqdq	xmm5, xmm7, xmm3, 16
        vpclmulqdq	xmm1, xmm7, xmm3, 1
        vpclmulqdq	xmm4, xmm7, xmm3, 0
        vpclmulqdq	xmm6, xmm7, xmm3, 17
        vpxor	xmm5, xmm5, xmm1
        vmovdqu	xmm3, OWORD PTR [edx+32]
        vmovdqu	xmm7, OWORD PTR [esp+16]
        vpshufb	xmm3, xmm3, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpclmulqdq	xmm2, xmm7, xmm3, 16
        vpclmulqdq	xmm1, xmm7, xmm3, 1
        vpclmulqdq	xmm0, xmm7, xmm3, 0
        vpclmulqdq	xmm3, xmm7, xmm3, 17
        vpxor	xmm2, xmm2, xmm1
        vpxor	xmm6, xmm6, xmm3
        vpxor	xmm5, xmm5, xmm2
        vpxor	xmm4, xmm4, xmm0
        vmovdqu	xmm3, OWORD PTR [edx+16]
        vmovdqu	xmm7, OWORD PTR [esp+32]
        vpshufb	xmm3, xmm3, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpclmulqdq	xmm2, xmm7, xmm3, 16
        vpclmulqdq	xmm1, xmm7, xmm3, 1
        vpclmulqdq	xmm0, xmm7, xmm3, 0
        vpclmulqdq	xmm3, xmm7, xmm3, 17
        vpxor	xmm2, xmm2, xmm1
        vpxor	xmm6, xmm6, xmm3
        vpxor	xmm5, xmm5, xmm2
        vpxor	xmm4, xmm4, xmm0
        vmovdqu	xmm0, OWORD PTR [esp+96]
        vmovdqu	xmm3, OWORD PTR [edx]
        vmovdqu	xmm7, OWORD PTR [esp+48]
        vpshufb	xmm3, xmm3, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpxor	xmm3, xmm3, xmm0
        vpclmulqdq	xmm2, xmm7, xmm3, 16
        vpclmulqdq	xmm1, xmm7, xmm3, 1
        vpclmulqdq	xmm0, xmm7, xmm3, 0
        vpclmulqdq	xmm3, xmm7, xmm3, 17
        vpxor	xmm2, xmm2, xmm1
        vpxor	xmm6, xmm6, xmm3
        vpxor	xmm5, xmm5, xmm2
        vpxor	xmm4, xmm4, xmm0
        vpslldq	xmm7, xmm5, 8
        vpsrldq	xmm5, xmm5, 8
        vpxor	xmm4, xmm4, xmm7
        vpxor	xmm6, xmm6, xmm5
        ; ghash_red
        vmovdqu	xmm2, OWORD PTR L_aes_gcm_avx2_mod2_128
        vpclmulqdq	xmm0, xmm4, xmm2, 16
        vpshufd	xmm1, xmm4, 78
        vpxor	xmm1, xmm1, xmm0
        vpclmulqdq	xmm0, xmm1, xmm2, 16
        vpshufd	xmm1, xmm1, 78
        vpxor	xmm1, xmm1, xmm0
        vpxor	xmm6, xmm6, xmm1
        vmovdqu	xmm5, OWORD PTR [esp]
        vmovdqu	xmm4, OWORD PTR [esp+64]
L_AES_GCM_encrypt_avx2_done_64:
        cmp	ebx, DWORD PTR [esp+152]
        je	L_AES_GCM_encrypt_avx2_done_enc
        mov	eax, DWORD PTR [esp+152]
        and	eax, 4294967280
        cmp	ebx, eax
        jge	L_AES_GCM_encrypt_avx2_last_block_done
        lea	ecx, DWORD PTR [esi+ebx]
        lea	edx, DWORD PTR [edi+ebx]
        ; aesenc_block
        vmovdqu	xmm1, xmm4
        vpshufb	xmm0, xmm1, OWORD PTR L_aes_gcm_avx2_bswap_epi64
        vpaddd	xmm1, xmm1, OWORD PTR L_aes_gcm_avx2_one
        vpxor	xmm0, xmm0, [ebp]
        vaesenc	xmm0, xmm0, [ebp+16]
        vaesenc	xmm0, xmm0, [ebp+32]
        vaesenc	xmm0, xmm0, [ebp+48]
        vaesenc	xmm0, xmm0, [ebp+64]
        vaesenc	xmm0, xmm0, [ebp+80]
        vaesenc	xmm0, xmm0, [ebp+96]
        vaesenc	xmm0, xmm0, [ebp+112]
        vaesenc	xmm0, xmm0, [ebp+128]
        vaesenc	xmm0, xmm0, [ebp+144]
        cmp	DWORD PTR [esp+172], 11
        vmovdqu	xmm2, OWORD PTR [ebp+160]
        jl	L_AES_GCM_encrypt_avx2_aesenc_block_aesenc_avx_last
        vaesenc	xmm0, xmm0, xmm2
        vaesenc	xmm0, xmm0, [ebp+176]
        cmp	DWORD PTR [esp+172], 13
        vmovdqu	xmm2, OWORD PTR [ebp+192]
        jl	L_AES_GCM_encrypt_avx2_aesenc_block_aesenc_avx_last
        vaesenc	xmm0, xmm0, xmm2
        vaesenc	xmm0, xmm0, [ebp+208]
        vmovdqu	xmm2, OWORD PTR [ebp+224]
L_AES_GCM_encrypt_avx2_aesenc_block_aesenc_avx_last:
        vaesenclast	xmm0, xmm0, xmm2
        vmovdqu	xmm4, xmm1
        vmovdqu	xmm1, OWORD PTR [ecx]
        vpxor	xmm0, xmm0, xmm1
        vmovdqu	OWORD PTR [edx], xmm0
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpxor	xmm6, xmm6, xmm0
        add	ebx, 16
        cmp	ebx, eax
        jge	L_AES_GCM_encrypt_avx2_last_block_ghash
L_AES_GCM_encrypt_avx2_last_block_start:
        vpshufb	xmm7, xmm4, OWORD PTR L_aes_gcm_avx2_bswap_epi64
        vpaddd	xmm4, xmm4, OWORD PTR L_aes_gcm_avx2_one
        vmovdqu	OWORD PTR [esp+64], xmm4
        ; aesenc_gfmul_sb
        vpclmulqdq	xmm2, xmm6, xmm5, 1
        vpclmulqdq	xmm3, xmm6, xmm5, 16
        vpclmulqdq	xmm1, xmm6, xmm5, 0
        vpclmulqdq	xmm4, xmm6, xmm5, 17
        vpxor	xmm7, xmm7, [ebp]
        vaesenc	xmm7, xmm7, [ebp+16]
        vpxor	xmm3, xmm3, xmm2
        vpslldq	xmm2, xmm3, 8
        vpsrldq	xmm3, xmm3, 8
        vaesenc	xmm7, xmm7, [ebp+32]
        vpxor	xmm2, xmm2, xmm1
        vpclmulqdq	xmm1, xmm2, OWORD PTR L_aes_gcm_avx2_mod2_128, 16
        vaesenc	xmm7, xmm7, [ebp+48]
        vaesenc	xmm7, xmm7, [ebp+64]
        vaesenc	xmm7, xmm7, [ebp+80]
        vpshufd	xmm2, xmm2, 78
        vpxor	xmm2, xmm2, xmm1
        vpclmulqdq	xmm1, xmm2, OWORD PTR L_aes_gcm_avx2_mod2_128, 16
        vaesenc	xmm7, xmm7, [ebp+96]
        vaesenc	xmm7, xmm7, [ebp+112]
        vaesenc	xmm7, xmm7, [ebp+128]
        vpshufd	xmm2, xmm2, 78
        vaesenc	xmm7, xmm7, [ebp+144]
        vpxor	xmm4, xmm4, xmm3
        vpxor	xmm2, xmm2, xmm4
        vmovdqu	xmm0, OWORD PTR [ebp+160]
        cmp	DWORD PTR [esp+172], 11
        jl	L_AES_GCM_encrypt_avx2_aesenc_gfmul_sb_last
        vaesenc	xmm7, xmm7, xmm0
        vaesenc	xmm7, xmm7, [ebp+176]
        vmovdqu	xmm0, OWORD PTR [ebp+192]
        cmp	DWORD PTR [esp+172], 13
        jl	L_AES_GCM_encrypt_avx2_aesenc_gfmul_sb_last
        vaesenc	xmm7, xmm7, xmm0
        vaesenc	xmm7, xmm7, [ebp+208]
        vmovdqu	xmm0, OWORD PTR [ebp+224]
L_AES_GCM_encrypt_avx2_aesenc_gfmul_sb_last:
        vaesenclast	xmm7, xmm7, xmm0
        vmovdqu	xmm3, OWORD PTR [esi+ebx]
        vpxor	xmm6, xmm2, xmm1
        vpxor	xmm7, xmm7, xmm3
        vmovdqu	OWORD PTR [edi+ebx], xmm7
        vpshufb	xmm7, xmm7, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpxor	xmm6, xmm6, xmm7
        vmovdqu	xmm4, OWORD PTR [esp+64]
        add	ebx, 16
        cmp	ebx, eax
        jl	L_AES_GCM_encrypt_avx2_last_block_start
L_AES_GCM_encrypt_avx2_last_block_ghash:
        ; ghash_gfmul_red
        vpclmulqdq	xmm2, xmm6, xmm5, 16
        vpclmulqdq	xmm1, xmm6, xmm5, 1
        vpclmulqdq	xmm0, xmm6, xmm5, 0
        vpxor	xmm2, xmm2, xmm1
        vpslldq	xmm1, xmm2, 8
        vpsrldq	xmm2, xmm2, 8
        vpxor	xmm1, xmm1, xmm0
        vpclmulqdq	xmm6, xmm6, xmm5, 17
        vpclmulqdq	xmm0, xmm1, OWORD PTR L_aes_gcm_avx2_mod2_128, 16
        vpshufd	xmm1, xmm1, 78
        vpxor	xmm1, xmm1, xmm0
        vpclmulqdq	xmm0, xmm1, OWORD PTR L_aes_gcm_avx2_mod2_128, 16
        vpshufd	xmm1, xmm1, 78
        vpxor	xmm6, xmm6, xmm2
        vpxor	xmm6, xmm6, xmm1
        vpxor	xmm6, xmm6, xmm0
L_AES_GCM_encrypt_avx2_last_block_done:
        mov	ecx, DWORD PTR [esp+152]
        mov	edx, DWORD PTR [esp+152]
        and	ecx, 15
        jz	L_AES_GCM_encrypt_avx2_done_enc
        ; aesenc_last15_enc
        vpshufb	xmm4, xmm4, OWORD PTR L_aes_gcm_avx2_bswap_epi64
        vpxor	xmm4, xmm4, [ebp]
        vaesenc	xmm4, xmm4, [ebp+16]
        vaesenc	xmm4, xmm4, [ebp+32]
        vaesenc	xmm4, xmm4, [ebp+48]
        vaesenc	xmm4, xmm4, [ebp+64]
        vaesenc	xmm4, xmm4, [ebp+80]
        vaesenc	xmm4, xmm4, [ebp+96]
        vaesenc	xmm4, xmm4, [ebp+112]
        vaesenc	xmm4, xmm4, [ebp+128]
        vaesenc	xmm4, xmm4, [ebp+144]
        cmp	DWORD PTR [esp+172], 11
        vmovdqu	xmm0, OWORD PTR [ebp+160]
        jl	L_AES_GCM_encrypt_avx2_aesenc_last15_enc_avx_aesenc_avx_last
        vaesenc	xmm4, xmm4, xmm0
        vaesenc	xmm4, xmm4, [ebp+176]
        cmp	DWORD PTR [esp+172], 13
        vmovdqu	xmm0, OWORD PTR [ebp+192]
        jl	L_AES_GCM_encrypt_avx2_aesenc_last15_enc_avx_aesenc_avx_last
        vaesenc	xmm4, xmm4, xmm0
        vaesenc	xmm4, xmm4, [ebp+208]
        vmovdqu	xmm0, OWORD PTR [ebp+224]
L_AES_GCM_encrypt_avx2_aesenc_last15_enc_avx_aesenc_avx_last:
        vaesenclast	xmm4, xmm4, xmm0
        xor	ecx, ecx
        vpxor	xmm0, xmm0, xmm0
        vmovdqu	OWORD PTR [esp], xmm4
        vmovdqu	OWORD PTR [esp+16], xmm0
L_AES_GCM_encrypt_avx2_aesenc_last15_enc_avx_loop:
        movzx	eax, BYTE PTR [esi+ebx]
        xor	al, BYTE PTR [esp+ecx]
        mov	BYTE PTR [esp+ecx+16], al
        mov	BYTE PTR [edi+ebx], al
        inc	ebx
        inc	ecx
        cmp	ebx, edx
        jl	L_AES_GCM_encrypt_avx2_aesenc_last15_enc_avx_loop
L_AES_GCM_encrypt_avx2_aesenc_last15_enc_avx_finish_enc:
        vmovdqu	xmm4, OWORD PTR [esp+16]
        vpshufb	xmm4, xmm4, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpxor	xmm6, xmm6, xmm4
        ; ghash_gfmul_red
        vpclmulqdq	xmm2, xmm6, xmm5, 16
        vpclmulqdq	xmm1, xmm6, xmm5, 1
        vpclmulqdq	xmm0, xmm6, xmm5, 0
        vpxor	xmm2, xmm2, xmm1
        vpslldq	xmm1, xmm2, 8
        vpsrldq	xmm2, xmm2, 8
        vpxor	xmm1, xmm1, xmm0
        vpclmulqdq	xmm6, xmm6, xmm5, 17
        vpclmulqdq	xmm0, xmm1, OWORD PTR L_aes_gcm_avx2_mod2_128, 16
        vpshufd	xmm1, xmm1, 78
        vpxor	xmm1, xmm1, xmm0
        vpclmulqdq	xmm0, xmm1, OWORD PTR L_aes_gcm_avx2_mod2_128, 16
        vpshufd	xmm1, xmm1, 78
        vpxor	xmm6, xmm6, xmm2
        vpxor	xmm6, xmm6, xmm1
        vpxor	xmm6, xmm6, xmm0
L_AES_GCM_encrypt_avx2_done_enc:
        vmovdqu	xmm7, OWORD PTR [esp+80]
        ; calc_tag
        mov	ecx, DWORD PTR [esp+152]
        shl	ecx, 3
        vpinsrd	xmm0, xmm0, ecx, 0
        mov	ecx, DWORD PTR [esp+156]
        shl	ecx, 3
        vpinsrd	xmm0, xmm0, ecx, 2
        mov	ecx, DWORD PTR [esp+152]
        shr	ecx, 29
        vpinsrd	xmm0, xmm0, ecx, 1
        mov	ecx, DWORD PTR [esp+156]
        shr	ecx, 29
        vpinsrd	xmm0, xmm0, ecx, 3
        vpxor	xmm0, xmm0, xmm6
        ; ghash_gfmul_red
        vpclmulqdq	xmm4, xmm0, xmm5, 16
        vpclmulqdq	xmm3, xmm0, xmm5, 1
        vpclmulqdq	xmm2, xmm0, xmm5, 0
        vpxor	xmm4, xmm4, xmm3
        vpslldq	xmm3, xmm4, 8
        vpsrldq	xmm4, xmm4, 8
        vpxor	xmm3, xmm3, xmm2
        vpclmulqdq	xmm0, xmm0, xmm5, 17
        vpclmulqdq	xmm2, xmm3, OWORD PTR L_aes_gcm_avx2_mod2_128, 16
        vpshufd	xmm3, xmm3, 78
        vpxor	xmm3, xmm3, xmm2
        vpclmulqdq	xmm2, xmm3, OWORD PTR L_aes_gcm_avx2_mod2_128, 16
        vpshufd	xmm3, xmm3, 78
        vpxor	xmm0, xmm0, xmm4
        vpxor	xmm0, xmm0, xmm3
        vpxor	xmm0, xmm0, xmm2
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpxor	xmm0, xmm0, xmm7
        mov	edi, DWORD PTR [esp+148]
        mov	ebx, DWORD PTR [esp+164]
        ; store_tag
        cmp	ebx, 16
        je	L_AES_GCM_encrypt_avx2_store_tag_16
        xor	ecx, ecx
        vmovdqu	OWORD PTR [esp], xmm0
L_AES_GCM_encrypt_avx2_store_tag_loop:
        movzx	eax, BYTE PTR [esp+ecx]
        mov	BYTE PTR [edi+ecx], al
        inc	ecx
        cmp	ecx, ebx
        jne	L_AES_GCM_encrypt_avx2_store_tag_loop
        jmp	L_AES_GCM_encrypt_avx2_store_tag_done
L_AES_GCM_encrypt_avx2_store_tag_16:
        vmovdqu	OWORD PTR [edi], xmm0
L_AES_GCM_encrypt_avx2_store_tag_done:
        add	esp, 112
        pop	ebp
        pop	edi
        pop	esi
        pop	ebx
        ret
AES_GCM_encrypt_avx2 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_GCM_decrypt_avx2 PROC
        push	ebx
        push	esi
        push	edi
        push	ebp
        sub	esp, 176
        mov	esi, DWORD PTR [esp+208]
        mov	ebp, DWORD PTR [esp+232]
        vpxor	xmm4, xmm4, xmm4
        mov	edx, DWORD PTR [esp+224]
        cmp	edx, 12
        je	L_AES_GCM_decrypt_avx2_iv_12
        ; Calculate values when IV is not 12 bytes
        ; H = Encrypt X(=0)
        vmovdqu	xmm5, OWORD PTR [ebp]
        vaesenc	xmm5, xmm5, [ebp+16]
        vaesenc	xmm5, xmm5, [ebp+32]
        vaesenc	xmm5, xmm5, [ebp+48]
        vaesenc	xmm5, xmm5, [ebp+64]
        vaesenc	xmm5, xmm5, [ebp+80]
        vaesenc	xmm5, xmm5, [ebp+96]
        vaesenc	xmm5, xmm5, [ebp+112]
        vaesenc	xmm5, xmm5, [ebp+128]
        vaesenc	xmm5, xmm5, [ebp+144]
        cmp	DWORD PTR [esp+236], 11
        vmovdqu	xmm0, OWORD PTR [ebp+160]
        jl	L_AES_GCM_decrypt_avx2_calc_iv_1_aesenc_avx_last
        vaesenc	xmm5, xmm5, xmm0
        vaesenc	xmm5, xmm5, [ebp+176]
        cmp	DWORD PTR [esp+236], 13
        vmovdqu	xmm0, OWORD PTR [ebp+192]
        jl	L_AES_GCM_decrypt_avx2_calc_iv_1_aesenc_avx_last
        vaesenc	xmm5, xmm5, xmm0
        vaesenc	xmm5, xmm5, [ebp+208]
        vmovdqu	xmm0, OWORD PTR [ebp+224]
L_AES_GCM_decrypt_avx2_calc_iv_1_aesenc_avx_last:
        vaesenclast	xmm5, xmm5, xmm0
        vpshufb	xmm5, xmm5, OWORD PTR L_aes_gcm_avx2_bswap_mask
        ; Calc counter
        ; Initialization vector
        cmp	edx, 0
        mov	ecx, 0
        je	L_AES_GCM_decrypt_avx2_calc_iv_done
        cmp	edx, 16
        jl	L_AES_GCM_decrypt_avx2_calc_iv_lt16
        and	edx, 4294967280
L_AES_GCM_decrypt_avx2_calc_iv_16_loop:
        vmovdqu	xmm0, OWORD PTR [esi+ecx]
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpxor	xmm4, xmm4, xmm0
        ; ghash_gfmul_avx
        vpclmulqdq	xmm2, xmm5, xmm4, 16
        vpclmulqdq	xmm1, xmm5, xmm4, 1
        vpclmulqdq	xmm0, xmm5, xmm4, 0
        vpclmulqdq	xmm3, xmm5, xmm4, 17
        vpxor	xmm2, xmm2, xmm1
        vpslldq	xmm1, xmm2, 8
        vpsrldq	xmm2, xmm2, 8
        vpxor	xmm7, xmm0, xmm1
        vpxor	xmm4, xmm3, xmm2
        ; ghash_mid
        vpsrld	xmm0, xmm7, 31
        vpsrld	xmm1, xmm4, 31
        vpslld	xmm7, xmm7, 1
        vpslld	xmm4, xmm4, 1
        vpsrldq	xmm2, xmm0, 12
        vpslldq	xmm0, xmm0, 4
        vpslldq	xmm1, xmm1, 4
        vpor	xmm4, xmm4, xmm2
        vpor	xmm7, xmm7, xmm0
        vpor	xmm4, xmm4, xmm1
        ; ghash_red
        vmovdqu	xmm2, OWORD PTR L_aes_gcm_avx2_mod2_128
        vpclmulqdq	xmm0, xmm7, xmm2, 16
        vpshufd	xmm1, xmm7, 78
        vpxor	xmm1, xmm1, xmm0
        vpclmulqdq	xmm0, xmm1, xmm2, 16
        vpshufd	xmm1, xmm1, 78
        vpxor	xmm1, xmm1, xmm0
        vpxor	xmm4, xmm4, xmm1
        add	ecx, 16
        cmp	ecx, edx
        jl	L_AES_GCM_decrypt_avx2_calc_iv_16_loop
        mov	edx, DWORD PTR [esp+224]
        cmp	ecx, edx
        je	L_AES_GCM_decrypt_avx2_calc_iv_done
L_AES_GCM_decrypt_avx2_calc_iv_lt16:
        vpxor	xmm0, xmm0, xmm0
        xor	ebx, ebx
        vmovdqu	OWORD PTR [esp], xmm0
L_AES_GCM_decrypt_avx2_calc_iv_loop:
        movzx	eax, BYTE PTR [esi+ecx]
        mov	BYTE PTR [esp+ebx], al
        inc	ecx
        inc	ebx
        cmp	ecx, edx
        jl	L_AES_GCM_decrypt_avx2_calc_iv_loop
        vmovdqu	xmm0, OWORD PTR [esp]
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpxor	xmm4, xmm4, xmm0
        ; ghash_gfmul_avx
        vpclmulqdq	xmm2, xmm5, xmm4, 16
        vpclmulqdq	xmm1, xmm5, xmm4, 1
        vpclmulqdq	xmm0, xmm5, xmm4, 0
        vpclmulqdq	xmm3, xmm5, xmm4, 17
        vpxor	xmm2, xmm2, xmm1
        vpslldq	xmm1, xmm2, 8
        vpsrldq	xmm2, xmm2, 8
        vpxor	xmm7, xmm0, xmm1
        vpxor	xmm4, xmm3, xmm2
        ; ghash_mid
        vpsrld	xmm0, xmm7, 31
        vpsrld	xmm1, xmm4, 31
        vpslld	xmm7, xmm7, 1
        vpslld	xmm4, xmm4, 1
        vpsrldq	xmm2, xmm0, 12
        vpslldq	xmm0, xmm0, 4
        vpslldq	xmm1, xmm1, 4
        vpor	xmm4, xmm4, xmm2
        vpor	xmm7, xmm7, xmm0
        vpor	xmm4, xmm4, xmm1
        ; ghash_red
        vmovdqu	xmm2, OWORD PTR L_aes_gcm_avx2_mod2_128
        vpclmulqdq	xmm0, xmm7, xmm2, 16
        vpshufd	xmm1, xmm7, 78
        vpxor	xmm1, xmm1, xmm0
        vpclmulqdq	xmm0, xmm1, xmm2, 16
        vpshufd	xmm1, xmm1, 78
        vpxor	xmm1, xmm1, xmm0
        vpxor	xmm4, xmm4, xmm1
L_AES_GCM_decrypt_avx2_calc_iv_done:
        ; T = Encrypt counter
        vpxor	xmm0, xmm0, xmm0
        shl	edx, 3
        vpinsrd	xmm0, xmm0, edx, 0
        vpxor	xmm4, xmm4, xmm0
        ; ghash_gfmul_avx
        vpclmulqdq	xmm2, xmm5, xmm4, 16
        vpclmulqdq	xmm1, xmm5, xmm4, 1
        vpclmulqdq	xmm0, xmm5, xmm4, 0
        vpclmulqdq	xmm3, xmm5, xmm4, 17
        vpxor	xmm2, xmm2, xmm1
        vpslldq	xmm1, xmm2, 8
        vpsrldq	xmm2, xmm2, 8
        vpxor	xmm7, xmm0, xmm1
        vpxor	xmm4, xmm3, xmm2
        ; ghash_mid
        vpsrld	xmm0, xmm7, 31
        vpsrld	xmm1, xmm4, 31
        vpslld	xmm7, xmm7, 1
        vpslld	xmm4, xmm4, 1
        vpsrldq	xmm2, xmm0, 12
        vpslldq	xmm0, xmm0, 4
        vpslldq	xmm1, xmm1, 4
        vpor	xmm4, xmm4, xmm2
        vpor	xmm7, xmm7, xmm0
        vpor	xmm4, xmm4, xmm1
        ; ghash_red
        vmovdqu	xmm2, OWORD PTR L_aes_gcm_avx2_mod2_128
        vpclmulqdq	xmm0, xmm7, xmm2, 16
        vpshufd	xmm1, xmm7, 78
        vpxor	xmm1, xmm1, xmm0
        vpclmulqdq	xmm0, xmm1, xmm2, 16
        vpshufd	xmm1, xmm1, 78
        vpxor	xmm1, xmm1, xmm0
        vpxor	xmm4, xmm4, xmm1
        vpshufb	xmm4, xmm4, OWORD PTR L_aes_gcm_avx2_bswap_mask
        ;   Encrypt counter
        vmovdqu	xmm6, OWORD PTR [ebp]
        vpxor	xmm6, xmm6, xmm4
        vaesenc	xmm6, xmm6, [ebp+16]
        vaesenc	xmm6, xmm6, [ebp+32]
        vaesenc	xmm6, xmm6, [ebp+48]
        vaesenc	xmm6, xmm6, [ebp+64]
        vaesenc	xmm6, xmm6, [ebp+80]
        vaesenc	xmm6, xmm6, [ebp+96]
        vaesenc	xmm6, xmm6, [ebp+112]
        vaesenc	xmm6, xmm6, [ebp+128]
        vaesenc	xmm6, xmm6, [ebp+144]
        cmp	DWORD PTR [esp+236], 11
        vmovdqu	xmm0, OWORD PTR [ebp+160]
        jl	L_AES_GCM_decrypt_avx2_calc_iv_2_aesenc_avx_last
        vaesenc	xmm6, xmm6, xmm0
        vaesenc	xmm6, xmm6, [ebp+176]
        cmp	DWORD PTR [esp+236], 13
        vmovdqu	xmm0, OWORD PTR [ebp+192]
        jl	L_AES_GCM_decrypt_avx2_calc_iv_2_aesenc_avx_last
        vaesenc	xmm6, xmm6, xmm0
        vaesenc	xmm6, xmm6, [ebp+208]
        vmovdqu	xmm0, OWORD PTR [ebp+224]
L_AES_GCM_decrypt_avx2_calc_iv_2_aesenc_avx_last:
        vaesenclast	xmm6, xmm6, xmm0
        jmp	L_AES_GCM_decrypt_avx2_iv_done
L_AES_GCM_decrypt_avx2_iv_12:
        ; # Calculate values when IV is 12 bytes
        ; Set counter based on IV
        vmovdqu	xmm4, OWORD PTR L_avx2_aes_gcm_bswap_one
        vmovdqu	xmm5, OWORD PTR [ebp]
        vpblendd	xmm4, xmm4, [esi], 7
        ; H = Encrypt X(=0) and T = Encrypt counter
        vmovdqu	xmm7, OWORD PTR [ebp+16]
        vpxor	xmm6, xmm4, xmm5
        vaesenc	xmm5, xmm5, xmm7
        vaesenc	xmm6, xmm6, xmm7
        vmovdqu	xmm0, OWORD PTR [ebp+32]
        vaesenc	xmm5, xmm5, xmm0
        vaesenc	xmm6, xmm6, xmm0
        vmovdqu	xmm0, OWORD PTR [ebp+48]
        vaesenc	xmm5, xmm5, xmm0
        vaesenc	xmm6, xmm6, xmm0
        vmovdqu	xmm0, OWORD PTR [ebp+64]
        vaesenc	xmm5, xmm5, xmm0
        vaesenc	xmm6, xmm6, xmm0
        vmovdqu	xmm0, OWORD PTR [ebp+80]
        vaesenc	xmm5, xmm5, xmm0
        vaesenc	xmm6, xmm6, xmm0
        vmovdqu	xmm0, OWORD PTR [ebp+96]
        vaesenc	xmm5, xmm5, xmm0
        vaesenc	xmm6, xmm6, xmm0
        vmovdqu	xmm0, OWORD PTR [ebp+112]
        vaesenc	xmm5, xmm5, xmm0
        vaesenc	xmm6, xmm6, xmm0
        vmovdqu	xmm0, OWORD PTR [ebp+128]
        vaesenc	xmm5, xmm5, xmm0
        vaesenc	xmm6, xmm6, xmm0
        vmovdqu	xmm0, OWORD PTR [ebp+144]
        vaesenc	xmm5, xmm5, xmm0
        vaesenc	xmm6, xmm6, xmm0
        cmp	DWORD PTR [esp+236], 11
        vmovdqu	xmm0, OWORD PTR [ebp+160]
        jl	L_AES_GCM_decrypt_avx2_calc_iv_12_last
        vaesenc	xmm5, xmm5, xmm0
        vaesenc	xmm6, xmm6, xmm0
        vmovdqu	xmm0, OWORD PTR [ebp+176]
        vaesenc	xmm5, xmm5, xmm0
        vaesenc	xmm6, xmm6, xmm0
        cmp	DWORD PTR [esp+236], 13
        vmovdqu	xmm0, OWORD PTR [ebp+192]
        jl	L_AES_GCM_decrypt_avx2_calc_iv_12_last
        vaesenc	xmm5, xmm5, xmm0
        vaesenc	xmm6, xmm6, xmm0
        vmovdqu	xmm0, OWORD PTR [ebp+208]
        vaesenc	xmm5, xmm5, xmm0
        vaesenc	xmm6, xmm6, xmm0
        vmovdqu	xmm0, OWORD PTR [ebp+224]
L_AES_GCM_decrypt_avx2_calc_iv_12_last:
        vaesenclast	xmm5, xmm5, xmm0
        vaesenclast	xmm6, xmm6, xmm0
        vpshufb	xmm5, xmm5, OWORD PTR L_aes_gcm_avx2_bswap_mask
L_AES_GCM_decrypt_avx2_iv_done:
        vmovdqu	OWORD PTR [esp+80], xmm6
        vpxor	xmm6, xmm6, xmm6
        mov	esi, DWORD PTR [esp+204]
        ; Additional authentication data
        mov	edx, DWORD PTR [esp+220]
        cmp	edx, 0
        je	L_AES_GCM_decrypt_avx2_calc_aad_done
        xor	ecx, ecx
        cmp	edx, 16
        jl	L_AES_GCM_decrypt_avx2_calc_aad_lt16
        and	edx, 4294967280
L_AES_GCM_decrypt_avx2_calc_aad_16_loop:
        vmovdqu	xmm0, OWORD PTR [esi+ecx]
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpxor	xmm6, xmm6, xmm0
        ; ghash_gfmul_avx
        vpclmulqdq	xmm2, xmm5, xmm6, 16
        vpclmulqdq	xmm1, xmm5, xmm6, 1
        vpclmulqdq	xmm0, xmm5, xmm6, 0
        vpclmulqdq	xmm3, xmm5, xmm6, 17
        vpxor	xmm2, xmm2, xmm1
        vpslldq	xmm1, xmm2, 8
        vpsrldq	xmm2, xmm2, 8
        vpxor	xmm7, xmm0, xmm1
        vpxor	xmm6, xmm3, xmm2
        ; ghash_mid
        vpsrld	xmm0, xmm7, 31
        vpsrld	xmm1, xmm6, 31
        vpslld	xmm7, xmm7, 1
        vpslld	xmm6, xmm6, 1
        vpsrldq	xmm2, xmm0, 12
        vpslldq	xmm0, xmm0, 4
        vpslldq	xmm1, xmm1, 4
        vpor	xmm6, xmm6, xmm2
        vpor	xmm7, xmm7, xmm0
        vpor	xmm6, xmm6, xmm1
        ; ghash_red
        vmovdqu	xmm2, OWORD PTR L_aes_gcm_avx2_mod2_128
        vpclmulqdq	xmm0, xmm7, xmm2, 16
        vpshufd	xmm1, xmm7, 78
        vpxor	xmm1, xmm1, xmm0
        vpclmulqdq	xmm0, xmm1, xmm2, 16
        vpshufd	xmm1, xmm1, 78
        vpxor	xmm1, xmm1, xmm0
        vpxor	xmm6, xmm6, xmm1
        add	ecx, 16
        cmp	ecx, edx
        jl	L_AES_GCM_decrypt_avx2_calc_aad_16_loop
        mov	edx, DWORD PTR [esp+220]
        cmp	ecx, edx
        je	L_AES_GCM_decrypt_avx2_calc_aad_done
L_AES_GCM_decrypt_avx2_calc_aad_lt16:
        vpxor	xmm0, xmm0, xmm0
        xor	ebx, ebx
        vmovdqu	OWORD PTR [esp], xmm0
L_AES_GCM_decrypt_avx2_calc_aad_loop:
        movzx	eax, BYTE PTR [esi+ecx]
        mov	BYTE PTR [esp+ebx], al
        inc	ecx
        inc	ebx
        cmp	ecx, edx
        jl	L_AES_GCM_decrypt_avx2_calc_aad_loop
        vmovdqu	xmm0, OWORD PTR [esp]
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpxor	xmm6, xmm6, xmm0
        ; ghash_gfmul_avx
        vpclmulqdq	xmm2, xmm5, xmm6, 16
        vpclmulqdq	xmm1, xmm5, xmm6, 1
        vpclmulqdq	xmm0, xmm5, xmm6, 0
        vpclmulqdq	xmm3, xmm5, xmm6, 17
        vpxor	xmm2, xmm2, xmm1
        vpslldq	xmm1, xmm2, 8
        vpsrldq	xmm2, xmm2, 8
        vpxor	xmm7, xmm0, xmm1
        vpxor	xmm6, xmm3, xmm2
        ; ghash_mid
        vpsrld	xmm0, xmm7, 31
        vpsrld	xmm1, xmm6, 31
        vpslld	xmm7, xmm7, 1
        vpslld	xmm6, xmm6, 1
        vpsrldq	xmm2, xmm0, 12
        vpslldq	xmm0, xmm0, 4
        vpslldq	xmm1, xmm1, 4
        vpor	xmm6, xmm6, xmm2
        vpor	xmm7, xmm7, xmm0
        vpor	xmm6, xmm6, xmm1
        ; ghash_red
        vmovdqu	xmm2, OWORD PTR L_aes_gcm_avx2_mod2_128
        vpclmulqdq	xmm0, xmm7, xmm2, 16
        vpshufd	xmm1, xmm7, 78
        vpxor	xmm1, xmm1, xmm0
        vpclmulqdq	xmm0, xmm1, xmm2, 16
        vpshufd	xmm1, xmm1, 78
        vpxor	xmm1, xmm1, xmm0
        vpxor	xmm6, xmm6, xmm1
L_AES_GCM_decrypt_avx2_calc_aad_done:
        mov	esi, DWORD PTR [esp+196]
        mov	edi, DWORD PTR [esp+200]
        ; Calculate counter and H
        vpsrlq	xmm1, xmm5, 63
        vpsllq	xmm0, xmm5, 1
        vpslldq	xmm1, xmm1, 8
        vpor	xmm0, xmm0, xmm1
        vpshufd	xmm5, xmm5, 255
        vpsrad	xmm5, xmm5, 31
        vpshufb	xmm4, xmm4, OWORD PTR L_aes_gcm_avx2_bswap_epi64
        vpand	xmm5, xmm5, OWORD PTR L_aes_gcm_avx2_mod2_128
        vpaddd	xmm4, xmm4, OWORD PTR L_aes_gcm_avx2_one
        vpxor	xmm5, xmm5, xmm0
        xor	ebx, ebx
        cmp	DWORD PTR [esp+216], 64
        mov	eax, DWORD PTR [esp+216]
        jl	L_AES_GCM_decrypt_avx2_done_64
        and	eax, 4294967232
        vmovdqu	OWORD PTR [esp+64], xmm4
        vmovdqu	OWORD PTR [esp+96], xmm6
        vmovdqu	xmm3, OWORD PTR L_aes_gcm_avx2_mod2_128
        ; H ^ 1
        vmovdqu	OWORD PTR [esp], xmm5
        vmovdqu	xmm2, xmm5
        ; H ^ 2
        vpclmulqdq	xmm5, xmm2, xmm2, 0
        vpclmulqdq	xmm6, xmm2, xmm2, 17
        vpclmulqdq	xmm4, xmm5, xmm3, 16
        vpshufd	xmm5, xmm5, 78
        vpxor	xmm5, xmm5, xmm4
        vpclmulqdq	xmm4, xmm5, xmm3, 16
        vpshufd	xmm5, xmm5, 78
        vpxor	xmm5, xmm5, xmm4
        vpxor	xmm0, xmm6, xmm5
        vmovdqu	OWORD PTR [esp+16], xmm0
        ; H ^ 3
        ; ghash_gfmul_red
        vpclmulqdq	xmm6, xmm2, xmm0, 16
        vpclmulqdq	xmm5, xmm2, xmm0, 1
        vpclmulqdq	xmm4, xmm2, xmm0, 0
        vpxor	xmm6, xmm6, xmm5
        vpslldq	xmm5, xmm6, 8
        vpsrldq	xmm6, xmm6, 8
        vpxor	xmm5, xmm5, xmm4
        vpclmulqdq	xmm1, xmm2, xmm0, 17
        vpclmulqdq	xmm4, xmm5, xmm3, 16
        vpshufd	xmm5, xmm5, 78
        vpxor	xmm5, xmm5, xmm4
        vpclmulqdq	xmm4, xmm5, xmm3, 16
        vpshufd	xmm5, xmm5, 78
        vpxor	xmm1, xmm1, xmm6
        vpxor	xmm1, xmm1, xmm5
        vpxor	xmm1, xmm1, xmm4
        vmovdqu	OWORD PTR [esp+32], xmm1
        ; H ^ 4
        vpclmulqdq	xmm5, xmm0, xmm0, 0
        vpclmulqdq	xmm6, xmm0, xmm0, 17
        vpclmulqdq	xmm4, xmm5, xmm3, 16
        vpshufd	xmm5, xmm5, 78
        vpxor	xmm5, xmm5, xmm4
        vpclmulqdq	xmm4, xmm5, xmm3, 16
        vpshufd	xmm5, xmm5, 78
        vpxor	xmm5, xmm5, xmm4
        vpxor	xmm2, xmm6, xmm5
        vmovdqu	OWORD PTR [esp+48], xmm2
        vmovdqu	xmm6, OWORD PTR [esp+96]
        cmp	edi, esi
        jne	L_AES_GCM_decrypt_avx2_ghash_64
L_AES_GCM_decrypt_avx2_ghash_64_inplace:
        ; aesenc_64_ghash
        lea	ecx, DWORD PTR [esi+ebx]
        lea	edx, DWORD PTR [edi+ebx]
        ; aesenc_64
        ; aesenc_ctr
        vmovdqu	xmm4, OWORD PTR [esp+64]
        vmovdqu	xmm7, OWORD PTR L_aes_gcm_avx2_bswap_epi64
        vpaddd	xmm1, xmm4, OWORD PTR L_aes_gcm_avx2_one
        vpshufb	xmm0, xmm4, xmm7
        vpaddd	xmm2, xmm4, OWORD PTR L_aes_gcm_avx2_two
        vpshufb	xmm1, xmm1, xmm7
        vpaddd	xmm3, xmm4, OWORD PTR L_aes_gcm_avx2_three
        vpshufb	xmm2, xmm2, xmm7
        vpaddd	xmm4, xmm4, OWORD PTR L_aes_gcm_avx2_four
        vpshufb	xmm3, xmm3, xmm7
        ; aesenc_xor
        vmovdqu	xmm7, OWORD PTR [ebp]
        vmovdqu	OWORD PTR [esp+64], xmm4
        vpxor	xmm0, xmm0, xmm7
        vpxor	xmm1, xmm1, xmm7
        vpxor	xmm2, xmm2, xmm7
        vpxor	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+16]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+32]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+48]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+64]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+80]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+96]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+112]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+128]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+144]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        cmp	DWORD PTR [esp+236], 11
        vmovdqu	xmm7, OWORD PTR [ebp+160]
        jl	L_AES_GCM_decrypt_avx2_inplace_aesenc_64_ghash_aesenc_64_enc_done
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+176]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        cmp	DWORD PTR [esp+236], 13
        vmovdqu	xmm7, OWORD PTR [ebp+192]
        jl	L_AES_GCM_decrypt_avx2_inplace_aesenc_64_ghash_aesenc_64_enc_done
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+208]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+224]
L_AES_GCM_decrypt_avx2_inplace_aesenc_64_ghash_aesenc_64_enc_done:
        ; aesenc_last
        vaesenclast	xmm0, xmm0, xmm7
        vaesenclast	xmm1, xmm1, xmm7
        vaesenclast	xmm2, xmm2, xmm7
        vaesenclast	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ecx]
        vmovdqu	xmm4, OWORD PTR [ecx+16]
        vpxor	xmm0, xmm0, xmm7
        vpxor	xmm1, xmm1, xmm4
        vmovdqu	OWORD PTR [esp+112], xmm7
        vmovdqu	OWORD PTR [esp+128], xmm4
        vmovdqu	OWORD PTR [edx], xmm0
        vmovdqu	OWORD PTR [edx+16], xmm1
        vmovdqu	xmm7, OWORD PTR [ecx+32]
        vmovdqu	xmm4, OWORD PTR [ecx+48]
        vpxor	xmm2, xmm2, xmm7
        vpxor	xmm3, xmm3, xmm4
        vmovdqu	OWORD PTR [esp+144], xmm7
        vmovdqu	OWORD PTR [esp+160], xmm4
        vmovdqu	OWORD PTR [edx+32], xmm2
        vmovdqu	OWORD PTR [edx+48], xmm3
        ; pclmul_1
        vmovdqu	xmm1, OWORD PTR [esp+112]
        vpshufb	xmm1, xmm1, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vmovdqu	xmm2, OWORD PTR [esp+48]
        vpxor	xmm1, xmm1, xmm6
        vpclmulqdq	xmm5, xmm1, xmm2, 16
        vpclmulqdq	xmm3, xmm1, xmm2, 1
        vpclmulqdq	xmm6, xmm1, xmm2, 0
        vpclmulqdq	xmm7, xmm1, xmm2, 17
        ; pclmul_2
        vmovdqu	xmm1, OWORD PTR [esp+128]
        vmovdqu	xmm0, OWORD PTR [esp+32]
        vpshufb	xmm1, xmm1, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpxor	xmm5, xmm5, xmm3
        vpclmulqdq	xmm2, xmm1, xmm0, 16
        vpclmulqdq	xmm3, xmm1, xmm0, 1
        vpclmulqdq	xmm4, xmm1, xmm0, 0
        vpclmulqdq	xmm1, xmm1, xmm0, 17
        vpxor	xmm7, xmm7, xmm1
        ; pclmul_n
        vmovdqu	xmm1, OWORD PTR [esp+144]
        vmovdqu	xmm0, OWORD PTR [esp+16]
        vpshufb	xmm1, xmm1, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpxor	xmm5, xmm5, xmm2
        vpclmulqdq	xmm2, xmm1, xmm0, 16
        vpxor	xmm5, xmm5, xmm3
        vpclmulqdq	xmm3, xmm1, xmm0, 1
        vpxor	xmm6, xmm6, xmm4
        vpclmulqdq	xmm4, xmm1, xmm0, 0
        vpclmulqdq	xmm1, xmm1, xmm0, 17
        vpxor	xmm7, xmm7, xmm1
        ; pclmul_n
        vmovdqu	xmm1, OWORD PTR [esp+160]
        vmovdqu	xmm0, OWORD PTR [esp]
        vpshufb	xmm1, xmm1, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpxor	xmm5, xmm5, xmm2
        vpclmulqdq	xmm2, xmm1, xmm0, 16
        vpxor	xmm5, xmm5, xmm3
        vpclmulqdq	xmm3, xmm1, xmm0, 1
        vpxor	xmm6, xmm6, xmm4
        vpclmulqdq	xmm4, xmm1, xmm0, 0
        vpclmulqdq	xmm1, xmm1, xmm0, 17
        vpxor	xmm7, xmm7, xmm1
        ; aesenc_pclmul_l
        vpxor	xmm5, xmm5, xmm2
        vpxor	xmm6, xmm6, xmm4
        vpxor	xmm5, xmm5, xmm3
        vpslldq	xmm1, xmm5, 8
        vpsrldq	xmm5, xmm5, 8
        vmovdqu	xmm0, OWORD PTR L_aes_gcm_avx2_mod2_128
        vpxor	xmm6, xmm6, xmm1
        vpxor	xmm7, xmm7, xmm5
        vpclmulqdq	xmm3, xmm6, xmm0, 16
        vpshufd	xmm6, xmm6, 78
        vpxor	xmm6, xmm6, xmm3
        vpclmulqdq	xmm3, xmm6, xmm0, 16
        vpshufd	xmm6, xmm6, 78
        vpxor	xmm6, xmm6, xmm3
        vpxor	xmm6, xmm6, xmm7
        ; aesenc_64_ghash - end
        add	ebx, 64
        cmp	ebx, eax
        jl	L_AES_GCM_decrypt_avx2_ghash_64_inplace
        jmp	L_AES_GCM_decrypt_avx2_ghash_64_done
L_AES_GCM_decrypt_avx2_ghash_64:
        ; aesenc_64_ghash
        lea	ecx, DWORD PTR [esi+ebx]
        lea	edx, DWORD PTR [edi+ebx]
        ; aesenc_64
        ; aesenc_ctr
        vmovdqu	xmm4, OWORD PTR [esp+64]
        vmovdqu	xmm7, OWORD PTR L_aes_gcm_avx2_bswap_epi64
        vpaddd	xmm1, xmm4, OWORD PTR L_aes_gcm_avx2_one
        vpshufb	xmm0, xmm4, xmm7
        vpaddd	xmm2, xmm4, OWORD PTR L_aes_gcm_avx2_two
        vpshufb	xmm1, xmm1, xmm7
        vpaddd	xmm3, xmm4, OWORD PTR L_aes_gcm_avx2_three
        vpshufb	xmm2, xmm2, xmm7
        vpaddd	xmm4, xmm4, OWORD PTR L_aes_gcm_avx2_four
        vpshufb	xmm3, xmm3, xmm7
        ; aesenc_xor
        vmovdqu	xmm7, OWORD PTR [ebp]
        vmovdqu	OWORD PTR [esp+64], xmm4
        vpxor	xmm0, xmm0, xmm7
        vpxor	xmm1, xmm1, xmm7
        vpxor	xmm2, xmm2, xmm7
        vpxor	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+16]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+32]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+48]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+64]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+80]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+96]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+112]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+128]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+144]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        cmp	DWORD PTR [esp+236], 11
        vmovdqu	xmm7, OWORD PTR [ebp+160]
        jl	L_AES_GCM_decrypt_avx2_aesenc_64_ghash_aesenc_64_enc_done
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+176]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        cmp	DWORD PTR [esp+236], 13
        vmovdqu	xmm7, OWORD PTR [ebp+192]
        jl	L_AES_GCM_decrypt_avx2_aesenc_64_ghash_aesenc_64_enc_done
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+208]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+224]
L_AES_GCM_decrypt_avx2_aesenc_64_ghash_aesenc_64_enc_done:
        ; aesenc_last
        vaesenclast	xmm0, xmm0, xmm7
        vaesenclast	xmm1, xmm1, xmm7
        vaesenclast	xmm2, xmm2, xmm7
        vaesenclast	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ecx]
        vmovdqu	xmm4, OWORD PTR [ecx+16]
        vpxor	xmm0, xmm0, xmm7
        vpxor	xmm1, xmm1, xmm4
        vmovdqu	OWORD PTR [edx], xmm0
        vmovdqu	OWORD PTR [edx+16], xmm1
        vmovdqu	xmm7, OWORD PTR [ecx+32]
        vmovdqu	xmm4, OWORD PTR [ecx+48]
        vpxor	xmm2, xmm2, xmm7
        vpxor	xmm3, xmm3, xmm4
        vmovdqu	OWORD PTR [ecx+32], xmm7
        vmovdqu	OWORD PTR [ecx+48], xmm4
        vmovdqu	OWORD PTR [edx+32], xmm2
        vmovdqu	OWORD PTR [edx+48], xmm3
        ; pclmul_1
        vmovdqu	xmm1, OWORD PTR [ecx]
        vpshufb	xmm1, xmm1, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vmovdqu	xmm2, OWORD PTR [esp+48]
        vpxor	xmm1, xmm1, xmm6
        vpclmulqdq	xmm5, xmm1, xmm2, 16
        vpclmulqdq	xmm3, xmm1, xmm2, 1
        vpclmulqdq	xmm6, xmm1, xmm2, 0
        vpclmulqdq	xmm7, xmm1, xmm2, 17
        ; pclmul_2
        vmovdqu	xmm1, OWORD PTR [ecx+16]
        vmovdqu	xmm0, OWORD PTR [esp+32]
        vpshufb	xmm1, xmm1, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpxor	xmm5, xmm5, xmm3
        vpclmulqdq	xmm2, xmm1, xmm0, 16
        vpclmulqdq	xmm3, xmm1, xmm0, 1
        vpclmulqdq	xmm4, xmm1, xmm0, 0
        vpclmulqdq	xmm1, xmm1, xmm0, 17
        vpxor	xmm7, xmm7, xmm1
        ; pclmul_n
        vmovdqu	xmm1, OWORD PTR [ecx+32]
        vmovdqu	xmm0, OWORD PTR [esp+16]
        vpshufb	xmm1, xmm1, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpxor	xmm5, xmm5, xmm2
        vpclmulqdq	xmm2, xmm1, xmm0, 16
        vpxor	xmm5, xmm5, xmm3
        vpclmulqdq	xmm3, xmm1, xmm0, 1
        vpxor	xmm6, xmm6, xmm4
        vpclmulqdq	xmm4, xmm1, xmm0, 0
        vpclmulqdq	xmm1, xmm1, xmm0, 17
        vpxor	xmm7, xmm7, xmm1
        ; pclmul_n
        vmovdqu	xmm1, OWORD PTR [ecx+48]
        vmovdqu	xmm0, OWORD PTR [esp]
        vpshufb	xmm1, xmm1, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpxor	xmm5, xmm5, xmm2
        vpclmulqdq	xmm2, xmm1, xmm0, 16
        vpxor	xmm5, xmm5, xmm3
        vpclmulqdq	xmm3, xmm1, xmm0, 1
        vpxor	xmm6, xmm6, xmm4
        vpclmulqdq	xmm4, xmm1, xmm0, 0
        vpclmulqdq	xmm1, xmm1, xmm0, 17
        vpxor	xmm7, xmm7, xmm1
        ; aesenc_pclmul_l
        vpxor	xmm5, xmm5, xmm2
        vpxor	xmm6, xmm6, xmm4
        vpxor	xmm5, xmm5, xmm3
        vpslldq	xmm1, xmm5, 8
        vpsrldq	xmm5, xmm5, 8
        vmovdqu	xmm0, OWORD PTR L_aes_gcm_avx2_mod2_128
        vpxor	xmm6, xmm6, xmm1
        vpxor	xmm7, xmm7, xmm5
        vpclmulqdq	xmm3, xmm6, xmm0, 16
        vpshufd	xmm6, xmm6, 78
        vpxor	xmm6, xmm6, xmm3
        vpclmulqdq	xmm3, xmm6, xmm0, 16
        vpshufd	xmm6, xmm6, 78
        vpxor	xmm6, xmm6, xmm3
        vpxor	xmm6, xmm6, xmm7
        ; aesenc_64_ghash - end
        add	ebx, 64
        cmp	ebx, eax
        jl	L_AES_GCM_decrypt_avx2_ghash_64
L_AES_GCM_decrypt_avx2_ghash_64_done:
        vmovdqu	xmm5, OWORD PTR [esp]
        vmovdqu	xmm4, OWORD PTR [esp+64]
L_AES_GCM_decrypt_avx2_done_64:
        cmp	ebx, DWORD PTR [esp+216]
        jge	L_AES_GCM_decrypt_avx2_done_dec
        mov	eax, DWORD PTR [esp+216]
        and	eax, 4294967280
        cmp	ebx, eax
        jge	L_AES_GCM_decrypt_avx2_last_block_done
L_AES_GCM_decrypt_avx2_last_block_start:
        vmovdqu	xmm0, OWORD PTR [esi+ebx]
        vpshufb	xmm7, xmm4, OWORD PTR L_aes_gcm_avx2_bswap_epi64
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpaddd	xmm4, xmm4, OWORD PTR L_aes_gcm_avx2_one
        vmovdqu	OWORD PTR [esp+64], xmm4
        vpxor	xmm4, xmm0, xmm6
        ; aesenc_gfmul_sb
        vpclmulqdq	xmm2, xmm4, xmm5, 1
        vpclmulqdq	xmm3, xmm4, xmm5, 16
        vpclmulqdq	xmm1, xmm4, xmm5, 0
        vpclmulqdq	xmm4, xmm4, xmm5, 17
        vpxor	xmm7, xmm7, [ebp]
        vaesenc	xmm7, xmm7, [ebp+16]
        vpxor	xmm3, xmm3, xmm2
        vpslldq	xmm2, xmm3, 8
        vpsrldq	xmm3, xmm3, 8
        vaesenc	xmm7, xmm7, [ebp+32]
        vpxor	xmm2, xmm2, xmm1
        vpclmulqdq	xmm1, xmm2, OWORD PTR L_aes_gcm_avx2_mod2_128, 16
        vaesenc	xmm7, xmm7, [ebp+48]
        vaesenc	xmm7, xmm7, [ebp+64]
        vaesenc	xmm7, xmm7, [ebp+80]
        vpshufd	xmm2, xmm2, 78
        vpxor	xmm2, xmm2, xmm1
        vpclmulqdq	xmm1, xmm2, OWORD PTR L_aes_gcm_avx2_mod2_128, 16
        vaesenc	xmm7, xmm7, [ebp+96]
        vaesenc	xmm7, xmm7, [ebp+112]
        vaesenc	xmm7, xmm7, [ebp+128]
        vpshufd	xmm2, xmm2, 78
        vaesenc	xmm7, xmm7, [ebp+144]
        vpxor	xmm4, xmm4, xmm3
        vpxor	xmm2, xmm2, xmm4
        vmovdqu	xmm0, OWORD PTR [ebp+160]
        cmp	DWORD PTR [esp+236], 11
        jl	L_AES_GCM_decrypt_avx2_aesenc_gfmul_sb_last
        vaesenc	xmm7, xmm7, xmm0
        vaesenc	xmm7, xmm7, [ebp+176]
        vmovdqu	xmm0, OWORD PTR [ebp+192]
        cmp	DWORD PTR [esp+236], 13
        jl	L_AES_GCM_decrypt_avx2_aesenc_gfmul_sb_last
        vaesenc	xmm7, xmm7, xmm0
        vaesenc	xmm7, xmm7, [ebp+208]
        vmovdqu	xmm0, OWORD PTR [ebp+224]
L_AES_GCM_decrypt_avx2_aesenc_gfmul_sb_last:
        vaesenclast	xmm7, xmm7, xmm0
        vmovdqu	xmm3, OWORD PTR [esi+ebx]
        vpxor	xmm6, xmm2, xmm1
        vpxor	xmm7, xmm7, xmm3
        vmovdqu	OWORD PTR [edi+ebx], xmm7
        vmovdqu	xmm4, OWORD PTR [esp+64]
        add	ebx, 16
        cmp	ebx, eax
        jl	L_AES_GCM_decrypt_avx2_last_block_start
L_AES_GCM_decrypt_avx2_last_block_done:
        mov	ecx, DWORD PTR [esp+216]
        mov	edx, DWORD PTR [esp+216]
        and	ecx, 15
        jz	L_AES_GCM_decrypt_avx2_done_dec
        ; aesenc_last15_dec
        vpshufb	xmm4, xmm4, OWORD PTR L_aes_gcm_avx2_bswap_epi64
        vpxor	xmm4, xmm4, [ebp]
        vaesenc	xmm4, xmm4, [ebp+16]
        vaesenc	xmm4, xmm4, [ebp+32]
        vaesenc	xmm4, xmm4, [ebp+48]
        vaesenc	xmm4, xmm4, [ebp+64]
        vaesenc	xmm4, xmm4, [ebp+80]
        vaesenc	xmm4, xmm4, [ebp+96]
        vaesenc	xmm4, xmm4, [ebp+112]
        vaesenc	xmm4, xmm4, [ebp+128]
        vaesenc	xmm4, xmm4, [ebp+144]
        cmp	DWORD PTR [esp+236], 11
        vmovdqu	xmm1, OWORD PTR [ebp+160]
        jl	L_AES_GCM_decrypt_avx2_aesenc_last15_dec_avx_aesenc_avx_last
        vaesenc	xmm4, xmm4, xmm1
        vaesenc	xmm4, xmm4, [ebp+176]
        cmp	DWORD PTR [esp+236], 13
        vmovdqu	xmm1, OWORD PTR [ebp+192]
        jl	L_AES_GCM_decrypt_avx2_aesenc_last15_dec_avx_aesenc_avx_last
        vaesenc	xmm4, xmm4, xmm1
        vaesenc	xmm4, xmm4, [ebp+208]
        vmovdqu	xmm1, OWORD PTR [ebp+224]
L_AES_GCM_decrypt_avx2_aesenc_last15_dec_avx_aesenc_avx_last:
        vaesenclast	xmm4, xmm4, xmm1
        xor	ecx, ecx
        vpxor	xmm0, xmm0, xmm0
        vmovdqu	OWORD PTR [esp], xmm4
        vmovdqu	OWORD PTR [esp+16], xmm0
L_AES_GCM_decrypt_avx2_aesenc_last15_dec_avx_loop:
        movzx	eax, BYTE PTR [esi+ebx]
        mov	BYTE PTR [esp+ecx+16], al
        xor	al, BYTE PTR [esp+ecx]
        mov	BYTE PTR [edi+ebx], al
        inc	ebx
        inc	ecx
        cmp	ebx, edx
        jl	L_AES_GCM_decrypt_avx2_aesenc_last15_dec_avx_loop
        vmovdqu	xmm4, OWORD PTR [esp+16]
        vpshufb	xmm4, xmm4, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpxor	xmm6, xmm6, xmm4
        ; ghash_gfmul_red
        vpclmulqdq	xmm2, xmm6, xmm5, 16
        vpclmulqdq	xmm1, xmm6, xmm5, 1
        vpclmulqdq	xmm0, xmm6, xmm5, 0
        vpxor	xmm2, xmm2, xmm1
        vpslldq	xmm1, xmm2, 8
        vpsrldq	xmm2, xmm2, 8
        vpxor	xmm1, xmm1, xmm0
        vpclmulqdq	xmm6, xmm6, xmm5, 17
        vpclmulqdq	xmm0, xmm1, OWORD PTR L_aes_gcm_avx2_mod2_128, 16
        vpshufd	xmm1, xmm1, 78
        vpxor	xmm1, xmm1, xmm0
        vpclmulqdq	xmm0, xmm1, OWORD PTR L_aes_gcm_avx2_mod2_128, 16
        vpshufd	xmm1, xmm1, 78
        vpxor	xmm6, xmm6, xmm2
        vpxor	xmm6, xmm6, xmm1
        vpxor	xmm6, xmm6, xmm0
L_AES_GCM_decrypt_avx2_done_dec:
        vmovdqu	xmm7, OWORD PTR [esp+80]
        ; calc_tag
        mov	ecx, DWORD PTR [esp+216]
        shl	ecx, 3
        vpinsrd	xmm0, xmm0, ecx, 0
        mov	ecx, DWORD PTR [esp+220]
        shl	ecx, 3
        vpinsrd	xmm0, xmm0, ecx, 2
        mov	ecx, DWORD PTR [esp+216]
        shr	ecx, 29
        vpinsrd	xmm0, xmm0, ecx, 1
        mov	ecx, DWORD PTR [esp+220]
        shr	ecx, 29
        vpinsrd	xmm0, xmm0, ecx, 3
        vpxor	xmm0, xmm0, xmm6
        ; ghash_gfmul_red
        vpclmulqdq	xmm4, xmm0, xmm5, 16
        vpclmulqdq	xmm3, xmm0, xmm5, 1
        vpclmulqdq	xmm2, xmm0, xmm5, 0
        vpxor	xmm4, xmm4, xmm3
        vpslldq	xmm3, xmm4, 8
        vpsrldq	xmm4, xmm4, 8
        vpxor	xmm3, xmm3, xmm2
        vpclmulqdq	xmm0, xmm0, xmm5, 17
        vpclmulqdq	xmm2, xmm3, OWORD PTR L_aes_gcm_avx2_mod2_128, 16
        vpshufd	xmm3, xmm3, 78
        vpxor	xmm3, xmm3, xmm2
        vpclmulqdq	xmm2, xmm3, OWORD PTR L_aes_gcm_avx2_mod2_128, 16
        vpshufd	xmm3, xmm3, 78
        vpxor	xmm0, xmm0, xmm4
        vpxor	xmm0, xmm0, xmm3
        vpxor	xmm0, xmm0, xmm2
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpxor	xmm0, xmm0, xmm7
        mov	edi, DWORD PTR [esp+212]
        mov	ebx, DWORD PTR [esp+228]
        mov	ebp, DWORD PTR [esp+240]
        ; cmp_tag
        cmp	ebx, 16
        je	L_AES_GCM_decrypt_avx2_cmp_tag_16
        xor	edx, edx
        xor	ecx, ecx
        vmovdqu	OWORD PTR [esp], xmm0
L_AES_GCM_decrypt_avx2_cmp_tag_loop:
        movzx	eax, BYTE PTR [esp+edx]
        xor	al, BYTE PTR [edi+edx]
        or	cl, al
        inc	edx
        cmp	edx, ebx
        jne	L_AES_GCM_decrypt_avx2_cmp_tag_loop
        cmp	cl, 0
        sete	cl
        jmp	L_AES_GCM_decrypt_avx2_cmp_tag_done
L_AES_GCM_decrypt_avx2_cmp_tag_16:
        vmovdqu	xmm1, OWORD PTR [edi]
        vpcmpeqb	xmm0, xmm0, xmm1
        vpmovmskb	edx, xmm0
        ; %%edx == 0xFFFF then return 1 else => return 0
        xor	ecx, ecx
        cmp	edx, 65535
        sete	cl
L_AES_GCM_decrypt_avx2_cmp_tag_done:
        mov	DWORD PTR [ebp], ecx
        add	esp, 176
        pop	ebp
        pop	edi
        pop	esi
        pop	ebx
        ret
AES_GCM_decrypt_avx2 ENDP
_TEXT ENDS
IFDEF WOLFSSL_AESGCM_STREAM
_TEXT SEGMENT READONLY PARA
AES_GCM_init_avx2 PROC
        push	ebx
        push	esi
        push	edi
        push	ebp
        sub	esp, 32
        mov	ebp, DWORD PTR [esp+52]
        mov	esi, DWORD PTR [esp+60]
        mov	edi, DWORD PTR [esp+76]
        vpxor	xmm4, xmm4, xmm4
        mov	edx, DWORD PTR [esp+64]
        cmp	edx, 12
        je	L_AES_GCM_init_avx2_iv_12
        ; Calculate values when IV is not 12 bytes
        ; H = Encrypt X(=0)
        vmovdqu	xmm5, OWORD PTR [ebp]
        vaesenc	xmm5, xmm5, [ebp+16]
        vaesenc	xmm5, xmm5, [ebp+32]
        vaesenc	xmm5, xmm5, [ebp+48]
        vaesenc	xmm5, xmm5, [ebp+64]
        vaesenc	xmm5, xmm5, [ebp+80]
        vaesenc	xmm5, xmm5, [ebp+96]
        vaesenc	xmm5, xmm5, [ebp+112]
        vaesenc	xmm5, xmm5, [ebp+128]
        vaesenc	xmm5, xmm5, [ebp+144]
        cmp	DWORD PTR [esp+56], 11
        vmovdqu	xmm0, OWORD PTR [ebp+160]
        jl	L_AES_GCM_init_avx2_calc_iv_1_aesenc_avx_last
        vaesenc	xmm5, xmm5, xmm0
        vaesenc	xmm5, xmm5, [ebp+176]
        cmp	DWORD PTR [esp+56], 13
        vmovdqu	xmm0, OWORD PTR [ebp+192]
        jl	L_AES_GCM_init_avx2_calc_iv_1_aesenc_avx_last
        vaesenc	xmm5, xmm5, xmm0
        vaesenc	xmm5, xmm5, [ebp+208]
        vmovdqu	xmm0, OWORD PTR [ebp+224]
L_AES_GCM_init_avx2_calc_iv_1_aesenc_avx_last:
        vaesenclast	xmm5, xmm5, xmm0
        vpshufb	xmm5, xmm5, OWORD PTR L_aes_gcm_avx2_bswap_mask
        ; Calc counter
        ; Initialization vector
        cmp	edx, 0
        mov	ecx, 0
        je	L_AES_GCM_init_avx2_calc_iv_done
        cmp	edx, 16
        jl	L_AES_GCM_init_avx2_calc_iv_lt16
        and	edx, 4294967280
L_AES_GCM_init_avx2_calc_iv_16_loop:
        vmovdqu	xmm0, OWORD PTR [esi+ecx]
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpxor	xmm4, xmm4, xmm0
        ; ghash_gfmul_avx
        vpclmulqdq	xmm2, xmm5, xmm4, 16
        vpclmulqdq	xmm1, xmm5, xmm4, 1
        vpclmulqdq	xmm0, xmm5, xmm4, 0
        vpclmulqdq	xmm3, xmm5, xmm4, 17
        vpxor	xmm2, xmm2, xmm1
        vpslldq	xmm1, xmm2, 8
        vpsrldq	xmm2, xmm2, 8
        vpxor	xmm6, xmm0, xmm1
        vpxor	xmm4, xmm3, xmm2
        ; ghash_mid
        vpsrld	xmm0, xmm6, 31
        vpsrld	xmm1, xmm4, 31
        vpslld	xmm6, xmm6, 1
        vpslld	xmm4, xmm4, 1
        vpsrldq	xmm2, xmm0, 12
        vpslldq	xmm0, xmm0, 4
        vpslldq	xmm1, xmm1, 4
        vpor	xmm4, xmm4, xmm2
        vpor	xmm6, xmm6, xmm0
        vpor	xmm4, xmm4, xmm1
        ; ghash_red
        vmovdqu	xmm2, OWORD PTR L_aes_gcm_avx2_mod2_128
        vpclmulqdq	xmm0, xmm6, xmm2, 16
        vpshufd	xmm1, xmm6, 78
        vpxor	xmm1, xmm1, xmm0
        vpclmulqdq	xmm0, xmm1, xmm2, 16
        vpshufd	xmm1, xmm1, 78
        vpxor	xmm1, xmm1, xmm0
        vpxor	xmm4, xmm4, xmm1
        add	ecx, 16
        cmp	ecx, edx
        jl	L_AES_GCM_init_avx2_calc_iv_16_loop
        mov	edx, DWORD PTR [esp+64]
        cmp	ecx, edx
        je	L_AES_GCM_init_avx2_calc_iv_done
L_AES_GCM_init_avx2_calc_iv_lt16:
        vpxor	xmm0, xmm0, xmm0
        xor	ebx, ebx
        vmovdqu	OWORD PTR [esp], xmm0
L_AES_GCM_init_avx2_calc_iv_loop:
        movzx	eax, BYTE PTR [esi+ecx]
        mov	BYTE PTR [esp+ebx], al
        inc	ecx
        inc	ebx
        cmp	ecx, edx
        jl	L_AES_GCM_init_avx2_calc_iv_loop
        vmovdqu	xmm0, OWORD PTR [esp]
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpxor	xmm4, xmm4, xmm0
        ; ghash_gfmul_avx
        vpclmulqdq	xmm2, xmm5, xmm4, 16
        vpclmulqdq	xmm1, xmm5, xmm4, 1
        vpclmulqdq	xmm0, xmm5, xmm4, 0
        vpclmulqdq	xmm3, xmm5, xmm4, 17
        vpxor	xmm2, xmm2, xmm1
        vpslldq	xmm1, xmm2, 8
        vpsrldq	xmm2, xmm2, 8
        vpxor	xmm6, xmm0, xmm1
        vpxor	xmm4, xmm3, xmm2
        ; ghash_mid
        vpsrld	xmm0, xmm6, 31
        vpsrld	xmm1, xmm4, 31
        vpslld	xmm6, xmm6, 1
        vpslld	xmm4, xmm4, 1
        vpsrldq	xmm2, xmm0, 12
        vpslldq	xmm0, xmm0, 4
        vpslldq	xmm1, xmm1, 4
        vpor	xmm4, xmm4, xmm2
        vpor	xmm6, xmm6, xmm0
        vpor	xmm4, xmm4, xmm1
        ; ghash_red
        vmovdqu	xmm2, OWORD PTR L_aes_gcm_avx2_mod2_128
        vpclmulqdq	xmm0, xmm6, xmm2, 16
        vpshufd	xmm1, xmm6, 78
        vpxor	xmm1, xmm1, xmm0
        vpclmulqdq	xmm0, xmm1, xmm2, 16
        vpshufd	xmm1, xmm1, 78
        vpxor	xmm1, xmm1, xmm0
        vpxor	xmm4, xmm4, xmm1
L_AES_GCM_init_avx2_calc_iv_done:
        ; T = Encrypt counter
        vpxor	xmm0, xmm0, xmm0
        shl	edx, 3
        vpinsrd	xmm0, xmm0, edx, 0
        vpxor	xmm4, xmm4, xmm0
        ; ghash_gfmul_avx
        vpclmulqdq	xmm2, xmm5, xmm4, 16
        vpclmulqdq	xmm1, xmm5, xmm4, 1
        vpclmulqdq	xmm0, xmm5, xmm4, 0
        vpclmulqdq	xmm3, xmm5, xmm4, 17
        vpxor	xmm2, xmm2, xmm1
        vpslldq	xmm1, xmm2, 8
        vpsrldq	xmm2, xmm2, 8
        vpxor	xmm6, xmm0, xmm1
        vpxor	xmm4, xmm3, xmm2
        ; ghash_mid
        vpsrld	xmm0, xmm6, 31
        vpsrld	xmm1, xmm4, 31
        vpslld	xmm6, xmm6, 1
        vpslld	xmm4, xmm4, 1
        vpsrldq	xmm2, xmm0, 12
        vpslldq	xmm0, xmm0, 4
        vpslldq	xmm1, xmm1, 4
        vpor	xmm4, xmm4, xmm2
        vpor	xmm6, xmm6, xmm0
        vpor	xmm4, xmm4, xmm1
        ; ghash_red
        vmovdqu	xmm2, OWORD PTR L_aes_gcm_avx2_mod2_128
        vpclmulqdq	xmm0, xmm6, xmm2, 16
        vpshufd	xmm1, xmm6, 78
        vpxor	xmm1, xmm1, xmm0
        vpclmulqdq	xmm0, xmm1, xmm2, 16
        vpshufd	xmm1, xmm1, 78
        vpxor	xmm1, xmm1, xmm0
        vpxor	xmm4, xmm4, xmm1
        vpshufb	xmm4, xmm4, OWORD PTR L_aes_gcm_avx2_bswap_mask
        ;   Encrypt counter
        vmovdqu	xmm7, OWORD PTR [ebp]
        vpxor	xmm7, xmm7, xmm4
        vaesenc	xmm7, xmm7, [ebp+16]
        vaesenc	xmm7, xmm7, [ebp+32]
        vaesenc	xmm7, xmm7, [ebp+48]
        vaesenc	xmm7, xmm7, [ebp+64]
        vaesenc	xmm7, xmm7, [ebp+80]
        vaesenc	xmm7, xmm7, [ebp+96]
        vaesenc	xmm7, xmm7, [ebp+112]
        vaesenc	xmm7, xmm7, [ebp+128]
        vaesenc	xmm7, xmm7, [ebp+144]
        cmp	DWORD PTR [esp+56], 11
        vmovdqu	xmm0, OWORD PTR [ebp+160]
        jl	L_AES_GCM_init_avx2_calc_iv_2_aesenc_avx_last
        vaesenc	xmm7, xmm7, xmm0
        vaesenc	xmm7, xmm7, [ebp+176]
        cmp	DWORD PTR [esp+56], 13
        vmovdqu	xmm0, OWORD PTR [ebp+192]
        jl	L_AES_GCM_init_avx2_calc_iv_2_aesenc_avx_last
        vaesenc	xmm7, xmm7, xmm0
        vaesenc	xmm7, xmm7, [ebp+208]
        vmovdqu	xmm0, OWORD PTR [ebp+224]
L_AES_GCM_init_avx2_calc_iv_2_aesenc_avx_last:
        vaesenclast	xmm7, xmm7, xmm0
        jmp	L_AES_GCM_init_avx2_iv_done
L_AES_GCM_init_avx2_iv_12:
        ; # Calculate values when IV is 12 bytes
        ; Set counter based on IV
        vmovdqu	xmm4, OWORD PTR L_avx2_aes_gcm_bswap_one
        vmovdqu	xmm5, OWORD PTR [ebp]
        vpblendd	xmm4, xmm4, [esi], 7
        ; H = Encrypt X(=0) and T = Encrypt counter
        vmovdqu	xmm6, OWORD PTR [ebp+16]
        vpxor	xmm7, xmm4, xmm5
        vaesenc	xmm5, xmm5, xmm6
        vaesenc	xmm7, xmm7, xmm6
        vmovdqu	xmm0, OWORD PTR [ebp+32]
        vaesenc	xmm5, xmm5, xmm0
        vaesenc	xmm7, xmm7, xmm0
        vmovdqu	xmm0, OWORD PTR [ebp+48]
        vaesenc	xmm5, xmm5, xmm0
        vaesenc	xmm7, xmm7, xmm0
        vmovdqu	xmm0, OWORD PTR [ebp+64]
        vaesenc	xmm5, xmm5, xmm0
        vaesenc	xmm7, xmm7, xmm0
        vmovdqu	xmm0, OWORD PTR [ebp+80]
        vaesenc	xmm5, xmm5, xmm0
        vaesenc	xmm7, xmm7, xmm0
        vmovdqu	xmm0, OWORD PTR [ebp+96]
        vaesenc	xmm5, xmm5, xmm0
        vaesenc	xmm7, xmm7, xmm0
        vmovdqu	xmm0, OWORD PTR [ebp+112]
        vaesenc	xmm5, xmm5, xmm0
        vaesenc	xmm7, xmm7, xmm0
        vmovdqu	xmm0, OWORD PTR [ebp+128]
        vaesenc	xmm5, xmm5, xmm0
        vaesenc	xmm7, xmm7, xmm0
        vmovdqu	xmm0, OWORD PTR [ebp+144]
        vaesenc	xmm5, xmm5, xmm0
        vaesenc	xmm7, xmm7, xmm0
        cmp	DWORD PTR [esp+56], 11
        vmovdqu	xmm0, OWORD PTR [ebp+160]
        jl	L_AES_GCM_init_avx2_calc_iv_12_last
        vaesenc	xmm5, xmm5, xmm0
        vaesenc	xmm7, xmm7, xmm0
        vmovdqu	xmm0, OWORD PTR [ebp+176]
        vaesenc	xmm5, xmm5, xmm0
        vaesenc	xmm7, xmm7, xmm0
        cmp	DWORD PTR [esp+56], 13
        vmovdqu	xmm0, OWORD PTR [ebp+192]
        jl	L_AES_GCM_init_avx2_calc_iv_12_last
        vaesenc	xmm5, xmm5, xmm0
        vaesenc	xmm7, xmm7, xmm0
        vmovdqu	xmm0, OWORD PTR [ebp+208]
        vaesenc	xmm5, xmm5, xmm0
        vaesenc	xmm7, xmm7, xmm0
        vmovdqu	xmm0, OWORD PTR [ebp+224]
L_AES_GCM_init_avx2_calc_iv_12_last:
        vaesenclast	xmm5, xmm5, xmm0
        vaesenclast	xmm7, xmm7, xmm0
        vpshufb	xmm5, xmm5, OWORD PTR L_aes_gcm_avx2_bswap_mask
L_AES_GCM_init_avx2_iv_done:
        vmovdqu	OWORD PTR [edi], xmm7
        mov	ebp, DWORD PTR [esp+68]
        mov	edi, DWORD PTR [esp+72]
        vpshufb	xmm4, xmm4, OWORD PTR L_aes_gcm_avx2_bswap_epi64
        vpaddd	xmm4, xmm4, OWORD PTR L_aes_gcm_avx2_one
        vmovdqu	OWORD PTR [ebp], xmm5
        vmovdqu	OWORD PTR [edi], xmm4
        add	esp, 32
        pop	ebp
        pop	edi
        pop	esi
        pop	ebx
        ret
AES_GCM_init_avx2 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_GCM_aad_update_avx2 PROC
        push	esi
        push	edi
        mov	esi, DWORD PTR [esp+12]
        mov	edx, DWORD PTR [esp+16]
        mov	edi, DWORD PTR [esp+20]
        mov	eax, DWORD PTR [esp+24]
        vmovdqu	xmm4, OWORD PTR [edi]
        vmovdqu	xmm5, OWORD PTR [eax]
        xor	ecx, ecx
L_AES_GCM_aad_update_avx2_16_loop:
        vmovdqu	xmm0, OWORD PTR [esi+ecx]
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpxor	xmm4, xmm4, xmm0
        ; ghash_gfmul_avx
        vpclmulqdq	xmm2, xmm5, xmm4, 16
        vpclmulqdq	xmm1, xmm5, xmm4, 1
        vpclmulqdq	xmm0, xmm5, xmm4, 0
        vpclmulqdq	xmm3, xmm5, xmm4, 17
        vpxor	xmm2, xmm2, xmm1
        vpslldq	xmm1, xmm2, 8
        vpsrldq	xmm2, xmm2, 8
        vpxor	xmm6, xmm0, xmm1
        vpxor	xmm4, xmm3, xmm2
        ; ghash_mid
        vpsrld	xmm0, xmm6, 31
        vpsrld	xmm1, xmm4, 31
        vpslld	xmm6, xmm6, 1
        vpslld	xmm4, xmm4, 1
        vpsrldq	xmm2, xmm0, 12
        vpslldq	xmm0, xmm0, 4
        vpslldq	xmm1, xmm1, 4
        vpor	xmm4, xmm4, xmm2
        vpor	xmm6, xmm6, xmm0
        vpor	xmm4, xmm4, xmm1
        ; ghash_red
        vmovdqu	xmm2, OWORD PTR L_aes_gcm_avx2_mod2_128
        vpclmulqdq	xmm0, xmm6, xmm2, 16
        vpshufd	xmm1, xmm6, 78
        vpxor	xmm1, xmm1, xmm0
        vpclmulqdq	xmm0, xmm1, xmm2, 16
        vpshufd	xmm1, xmm1, 78
        vpxor	xmm1, xmm1, xmm0
        vpxor	xmm4, xmm4, xmm1
        add	ecx, 16
        cmp	ecx, edx
        jl	L_AES_GCM_aad_update_avx2_16_loop
        vmovdqu	OWORD PTR [edi], xmm4
        pop	edi
        pop	esi
        ret
AES_GCM_aad_update_avx2 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_GCM_encrypt_block_avx2 PROC
        push	esi
        push	edi
        mov	ecx, DWORD PTR [esp+12]
        mov	eax, DWORD PTR [esp+16]
        mov	edi, DWORD PTR [esp+20]
        mov	esi, DWORD PTR [esp+24]
        mov	edx, DWORD PTR [esp+28]
        vmovdqu	xmm3, OWORD PTR [edx]
        ; aesenc_block
        vmovdqu	xmm1, xmm3
        vpshufb	xmm0, xmm1, OWORD PTR L_aes_gcm_avx2_bswap_epi64
        vpaddd	xmm1, xmm1, OWORD PTR L_aes_gcm_avx2_one
        vpxor	xmm0, xmm0, [ecx]
        vaesenc	xmm0, xmm0, [ecx+16]
        vaesenc	xmm0, xmm0, [ecx+32]
        vaesenc	xmm0, xmm0, [ecx+48]
        vaesenc	xmm0, xmm0, [ecx+64]
        vaesenc	xmm0, xmm0, [ecx+80]
        vaesenc	xmm0, xmm0, [ecx+96]
        vaesenc	xmm0, xmm0, [ecx+112]
        vaesenc	xmm0, xmm0, [ecx+128]
        vaesenc	xmm0, xmm0, [ecx+144]
        cmp	eax, 11
        vmovdqu	xmm2, OWORD PTR [ecx+160]
        jl	L_AES_GCM_encrypt_block_avx2_aesenc_block_aesenc_avx_last
        vaesenc	xmm0, xmm0, xmm2
        vaesenc	xmm0, xmm0, [ecx+176]
        cmp	eax, 13
        vmovdqu	xmm2, OWORD PTR [ecx+192]
        jl	L_AES_GCM_encrypt_block_avx2_aesenc_block_aesenc_avx_last
        vaesenc	xmm0, xmm0, xmm2
        vaesenc	xmm0, xmm0, [ecx+208]
        vmovdqu	xmm2, OWORD PTR [ecx+224]
L_AES_GCM_encrypt_block_avx2_aesenc_block_aesenc_avx_last:
        vaesenclast	xmm0, xmm0, xmm2
        vmovdqu	xmm3, xmm1
        vmovdqu	xmm1, OWORD PTR [esi]
        vpxor	xmm0, xmm0, xmm1
        vmovdqu	OWORD PTR [edi], xmm0
        vmovdqu	OWORD PTR [edx], xmm3
        pop	edi
        pop	esi
        ret
AES_GCM_encrypt_block_avx2 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_GCM_ghash_block_avx2 PROC
        mov	edx, DWORD PTR [esp+4]
        mov	eax, DWORD PTR [esp+8]
        mov	ecx, DWORD PTR [esp+12]
        vmovdqu	xmm4, OWORD PTR [eax]
        vmovdqu	xmm5, OWORD PTR [ecx]
        vmovdqu	xmm0, OWORD PTR [edx]
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpxor	xmm4, xmm4, xmm0
        ; ghash_gfmul_avx
        vpclmulqdq	xmm2, xmm5, xmm4, 16
        vpclmulqdq	xmm1, xmm5, xmm4, 1
        vpclmulqdq	xmm0, xmm5, xmm4, 0
        vpclmulqdq	xmm3, xmm5, xmm4, 17
        vpxor	xmm2, xmm2, xmm1
        vpslldq	xmm1, xmm2, 8
        vpsrldq	xmm2, xmm2, 8
        vpxor	xmm6, xmm0, xmm1
        vpxor	xmm4, xmm3, xmm2
        ; ghash_mid
        vpsrld	xmm0, xmm6, 31
        vpsrld	xmm1, xmm4, 31
        vpslld	xmm6, xmm6, 1
        vpslld	xmm4, xmm4, 1
        vpsrldq	xmm2, xmm0, 12
        vpslldq	xmm0, xmm0, 4
        vpslldq	xmm1, xmm1, 4
        vpor	xmm4, xmm4, xmm2
        vpor	xmm6, xmm6, xmm0
        vpor	xmm4, xmm4, xmm1
        ; ghash_red
        vmovdqu	xmm2, OWORD PTR L_aes_gcm_avx2_mod2_128
        vpclmulqdq	xmm0, xmm6, xmm2, 16
        vpshufd	xmm1, xmm6, 78
        vpxor	xmm1, xmm1, xmm0
        vpclmulqdq	xmm0, xmm1, xmm2, 16
        vpshufd	xmm1, xmm1, 78
        vpxor	xmm1, xmm1, xmm0
        vpxor	xmm4, xmm4, xmm1
        vmovdqu	OWORD PTR [eax], xmm4
        ret
AES_GCM_ghash_block_avx2 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_GCM_encrypt_update_avx2 PROC
        push	ebx
        push	esi
        push	edi
        push	ebp
        sub	esp, 96
        mov	esi, DWORD PTR [esp+144]
        vmovdqu	xmm4, OWORD PTR [esi]
        vmovdqu	OWORD PTR [esp+64], xmm4
        mov	esi, DWORD PTR [esp+136]
        mov	ebp, DWORD PTR [esp+140]
        vmovdqu	xmm6, OWORD PTR [esi]
        vmovdqu	xmm5, OWORD PTR [ebp]
        vmovdqu	OWORD PTR [esp+80], xmm6
        mov	ebp, DWORD PTR [esp+116]
        mov	edi, DWORD PTR [esp+124]
        mov	esi, DWORD PTR [esp+128]
        ; Calculate H
        vpsrlq	xmm1, xmm5, 63
        vpsllq	xmm0, xmm5, 1
        vpslldq	xmm1, xmm1, 8
        vpor	xmm0, xmm0, xmm1
        vpshufd	xmm5, xmm5, 255
        vpsrad	xmm5, xmm5, 31
        vpand	xmm5, xmm5, OWORD PTR L_aes_gcm_avx2_mod2_128
        vpxor	xmm5, xmm5, xmm0
        xor	ebx, ebx
        cmp	DWORD PTR [esp+132], 64
        mov	eax, DWORD PTR [esp+132]
        jl	L_AES_GCM_encrypt_update_avx2_done_64
        and	eax, 4294967232
        vmovdqu	OWORD PTR [esp+64], xmm4
        vmovdqu	OWORD PTR [esp+80], xmm6
        vmovdqu	xmm3, OWORD PTR L_aes_gcm_avx2_mod2_128
        ; H ^ 1
        vmovdqu	OWORD PTR [esp], xmm5
        vmovdqu	xmm2, xmm5
        ; H ^ 2
        vpclmulqdq	xmm5, xmm2, xmm2, 0
        vpclmulqdq	xmm6, xmm2, xmm2, 17
        vpclmulqdq	xmm4, xmm5, xmm3, 16
        vpshufd	xmm5, xmm5, 78
        vpxor	xmm5, xmm5, xmm4
        vpclmulqdq	xmm4, xmm5, xmm3, 16
        vpshufd	xmm5, xmm5, 78
        vpxor	xmm5, xmm5, xmm4
        vpxor	xmm0, xmm6, xmm5
        vmovdqu	OWORD PTR [esp+16], xmm0
        ; H ^ 3
        ; ghash_gfmul_red
        vpclmulqdq	xmm6, xmm2, xmm0, 16
        vpclmulqdq	xmm5, xmm2, xmm0, 1
        vpclmulqdq	xmm4, xmm2, xmm0, 0
        vpxor	xmm6, xmm6, xmm5
        vpslldq	xmm5, xmm6, 8
        vpsrldq	xmm6, xmm6, 8
        vpxor	xmm5, xmm5, xmm4
        vpclmulqdq	xmm1, xmm2, xmm0, 17
        vpclmulqdq	xmm4, xmm5, xmm3, 16
        vpshufd	xmm5, xmm5, 78
        vpxor	xmm5, xmm5, xmm4
        vpclmulqdq	xmm4, xmm5, xmm3, 16
        vpshufd	xmm5, xmm5, 78
        vpxor	xmm1, xmm1, xmm6
        vpxor	xmm1, xmm1, xmm5
        vpxor	xmm1, xmm1, xmm4
        vmovdqu	OWORD PTR [esp+32], xmm1
        ; H ^ 4
        vpclmulqdq	xmm5, xmm0, xmm0, 0
        vpclmulqdq	xmm6, xmm0, xmm0, 17
        vpclmulqdq	xmm4, xmm5, xmm3, 16
        vpshufd	xmm5, xmm5, 78
        vpxor	xmm5, xmm5, xmm4
        vpclmulqdq	xmm4, xmm5, xmm3, 16
        vpshufd	xmm5, xmm5, 78
        vpxor	xmm5, xmm5, xmm4
        vpxor	xmm2, xmm6, xmm5
        vmovdqu	OWORD PTR [esp+48], xmm2
        vmovdqu	xmm6, OWORD PTR [esp+80]
        ; First 64 bytes of input
        ; aesenc_64
        ; aesenc_ctr
        vmovdqu	xmm4, OWORD PTR [esp+64]
        vmovdqu	xmm7, OWORD PTR L_aes_gcm_avx2_bswap_epi64
        vpaddd	xmm1, xmm4, OWORD PTR L_aes_gcm_avx2_one
        vpshufb	xmm0, xmm4, xmm7
        vpaddd	xmm2, xmm4, OWORD PTR L_aes_gcm_avx2_two
        vpshufb	xmm1, xmm1, xmm7
        vpaddd	xmm3, xmm4, OWORD PTR L_aes_gcm_avx2_three
        vpshufb	xmm2, xmm2, xmm7
        vpaddd	xmm4, xmm4, OWORD PTR L_aes_gcm_avx2_four
        vpshufb	xmm3, xmm3, xmm7
        ; aesenc_xor
        vmovdqu	xmm7, OWORD PTR [ebp]
        vmovdqu	OWORD PTR [esp+64], xmm4
        vpxor	xmm0, xmm0, xmm7
        vpxor	xmm1, xmm1, xmm7
        vpxor	xmm2, xmm2, xmm7
        vpxor	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+16]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+32]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+48]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+64]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+80]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+96]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+112]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+128]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+144]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        cmp	DWORD PTR [esp+120], 11
        vmovdqu	xmm7, OWORD PTR [ebp+160]
        jl	L_AES_GCM_encrypt_update_avx2_aesenc_64_enc_done
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+176]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        cmp	DWORD PTR [esp+120], 13
        vmovdqu	xmm7, OWORD PTR [ebp+192]
        jl	L_AES_GCM_encrypt_update_avx2_aesenc_64_enc_done
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+208]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+224]
L_AES_GCM_encrypt_update_avx2_aesenc_64_enc_done:
        ; aesenc_last
        vaesenclast	xmm0, xmm0, xmm7
        vaesenclast	xmm1, xmm1, xmm7
        vaesenclast	xmm2, xmm2, xmm7
        vaesenclast	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [esi]
        vmovdqu	xmm4, OWORD PTR [esi+16]
        vpxor	xmm0, xmm0, xmm7
        vpxor	xmm1, xmm1, xmm4
        vmovdqu	OWORD PTR [edi], xmm0
        vmovdqu	OWORD PTR [edi+16], xmm1
        vmovdqu	xmm7, OWORD PTR [esi+32]
        vmovdqu	xmm4, OWORD PTR [esi+48]
        vpxor	xmm2, xmm2, xmm7
        vpxor	xmm3, xmm3, xmm4
        vmovdqu	OWORD PTR [edi+32], xmm2
        vmovdqu	OWORD PTR [edi+48], xmm3
        cmp	eax, 64
        mov	ebx, 64
        mov	ecx, esi
        mov	edx, edi
        jle	L_AES_GCM_encrypt_update_avx2_end_64
        ; More 64 bytes of input
L_AES_GCM_encrypt_update_avx2_ghash_64:
        ; aesenc_64_ghash
        lea	ecx, DWORD PTR [esi+ebx]
        lea	edx, DWORD PTR [edi+ebx]
        ; aesenc_64
        ; aesenc_ctr
        vmovdqu	xmm4, OWORD PTR [esp+64]
        vmovdqu	xmm7, OWORD PTR L_aes_gcm_avx2_bswap_epi64
        vpaddd	xmm1, xmm4, OWORD PTR L_aes_gcm_avx2_one
        vpshufb	xmm0, xmm4, xmm7
        vpaddd	xmm2, xmm4, OWORD PTR L_aes_gcm_avx2_two
        vpshufb	xmm1, xmm1, xmm7
        vpaddd	xmm3, xmm4, OWORD PTR L_aes_gcm_avx2_three
        vpshufb	xmm2, xmm2, xmm7
        vpaddd	xmm4, xmm4, OWORD PTR L_aes_gcm_avx2_four
        vpshufb	xmm3, xmm3, xmm7
        ; aesenc_xor
        vmovdqu	xmm7, OWORD PTR [ebp]
        vmovdqu	OWORD PTR [esp+64], xmm4
        vpxor	xmm0, xmm0, xmm7
        vpxor	xmm1, xmm1, xmm7
        vpxor	xmm2, xmm2, xmm7
        vpxor	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+16]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+32]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+48]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+64]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+80]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+96]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+112]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+128]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+144]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        cmp	DWORD PTR [esp+120], 11
        vmovdqu	xmm7, OWORD PTR [ebp+160]
        jl	L_AES_GCM_encrypt_update_avx2_aesenc_64_ghash_aesenc_64_enc_done
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+176]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        cmp	DWORD PTR [esp+120], 13
        vmovdqu	xmm7, OWORD PTR [ebp+192]
        jl	L_AES_GCM_encrypt_update_avx2_aesenc_64_ghash_aesenc_64_enc_done
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+208]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+224]
L_AES_GCM_encrypt_update_avx2_aesenc_64_ghash_aesenc_64_enc_done:
        ; aesenc_last
        vaesenclast	xmm0, xmm0, xmm7
        vaesenclast	xmm1, xmm1, xmm7
        vaesenclast	xmm2, xmm2, xmm7
        vaesenclast	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ecx]
        vmovdqu	xmm4, OWORD PTR [ecx+16]
        vpxor	xmm0, xmm0, xmm7
        vpxor	xmm1, xmm1, xmm4
        vmovdqu	OWORD PTR [edx], xmm0
        vmovdqu	OWORD PTR [edx+16], xmm1
        vmovdqu	xmm7, OWORD PTR [ecx+32]
        vmovdqu	xmm4, OWORD PTR [ecx+48]
        vpxor	xmm2, xmm2, xmm7
        vpxor	xmm3, xmm3, xmm4
        vmovdqu	OWORD PTR [edx+32], xmm2
        vmovdqu	OWORD PTR [edx+48], xmm3
        ; pclmul_1
        vmovdqu	xmm1, OWORD PTR [edx+-64]
        vpshufb	xmm1, xmm1, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vmovdqu	xmm2, OWORD PTR [esp+48]
        vpxor	xmm1, xmm1, xmm6
        vpclmulqdq	xmm5, xmm1, xmm2, 16
        vpclmulqdq	xmm3, xmm1, xmm2, 1
        vpclmulqdq	xmm6, xmm1, xmm2, 0
        vpclmulqdq	xmm7, xmm1, xmm2, 17
        ; pclmul_2
        vmovdqu	xmm1, OWORD PTR [edx+-48]
        vmovdqu	xmm0, OWORD PTR [esp+32]
        vpshufb	xmm1, xmm1, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpxor	xmm5, xmm5, xmm3
        vpclmulqdq	xmm2, xmm1, xmm0, 16
        vpclmulqdq	xmm3, xmm1, xmm0, 1
        vpclmulqdq	xmm4, xmm1, xmm0, 0
        vpclmulqdq	xmm1, xmm1, xmm0, 17
        vpxor	xmm7, xmm7, xmm1
        ; pclmul_n
        vmovdqu	xmm1, OWORD PTR [edx+-32]
        vmovdqu	xmm0, OWORD PTR [esp+16]
        vpshufb	xmm1, xmm1, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpxor	xmm5, xmm5, xmm2
        vpclmulqdq	xmm2, xmm1, xmm0, 16
        vpxor	xmm5, xmm5, xmm3
        vpclmulqdq	xmm3, xmm1, xmm0, 1
        vpxor	xmm6, xmm6, xmm4
        vpclmulqdq	xmm4, xmm1, xmm0, 0
        vpclmulqdq	xmm1, xmm1, xmm0, 17
        vpxor	xmm7, xmm7, xmm1
        ; pclmul_n
        vmovdqu	xmm1, OWORD PTR [edx+-16]
        vmovdqu	xmm0, OWORD PTR [esp]
        vpshufb	xmm1, xmm1, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpxor	xmm5, xmm5, xmm2
        vpclmulqdq	xmm2, xmm1, xmm0, 16
        vpxor	xmm5, xmm5, xmm3
        vpclmulqdq	xmm3, xmm1, xmm0, 1
        vpxor	xmm6, xmm6, xmm4
        vpclmulqdq	xmm4, xmm1, xmm0, 0
        vpclmulqdq	xmm1, xmm1, xmm0, 17
        vpxor	xmm7, xmm7, xmm1
        ; aesenc_pclmul_l
        vpxor	xmm5, xmm5, xmm2
        vpxor	xmm6, xmm6, xmm4
        vpxor	xmm5, xmm5, xmm3
        vpslldq	xmm1, xmm5, 8
        vpsrldq	xmm5, xmm5, 8
        vmovdqu	xmm0, OWORD PTR L_aes_gcm_avx2_mod2_128
        vpxor	xmm6, xmm6, xmm1
        vpxor	xmm7, xmm7, xmm5
        vpclmulqdq	xmm3, xmm6, xmm0, 16
        vpshufd	xmm6, xmm6, 78
        vpxor	xmm6, xmm6, xmm3
        vpclmulqdq	xmm3, xmm6, xmm0, 16
        vpshufd	xmm6, xmm6, 78
        vpxor	xmm6, xmm6, xmm3
        vpxor	xmm6, xmm6, xmm7
        ; aesenc_64_ghash - end
        add	ebx, 64
        cmp	ebx, eax
        jl	L_AES_GCM_encrypt_update_avx2_ghash_64
L_AES_GCM_encrypt_update_avx2_end_64:
        vmovdqu	OWORD PTR [esp+80], xmm6
        vmovdqu	xmm3, OWORD PTR [edx+48]
        vmovdqu	xmm7, OWORD PTR [esp]
        vpshufb	xmm3, xmm3, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpclmulqdq	xmm5, xmm7, xmm3, 16
        vpclmulqdq	xmm1, xmm7, xmm3, 1
        vpclmulqdq	xmm4, xmm7, xmm3, 0
        vpclmulqdq	xmm6, xmm7, xmm3, 17
        vpxor	xmm5, xmm5, xmm1
        vmovdqu	xmm3, OWORD PTR [edx+32]
        vmovdqu	xmm7, OWORD PTR [esp+16]
        vpshufb	xmm3, xmm3, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpclmulqdq	xmm2, xmm7, xmm3, 16
        vpclmulqdq	xmm1, xmm7, xmm3, 1
        vpclmulqdq	xmm0, xmm7, xmm3, 0
        vpclmulqdq	xmm3, xmm7, xmm3, 17
        vpxor	xmm2, xmm2, xmm1
        vpxor	xmm6, xmm6, xmm3
        vpxor	xmm5, xmm5, xmm2
        vpxor	xmm4, xmm4, xmm0
        vmovdqu	xmm3, OWORD PTR [edx+16]
        vmovdqu	xmm7, OWORD PTR [esp+32]
        vpshufb	xmm3, xmm3, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpclmulqdq	xmm2, xmm7, xmm3, 16
        vpclmulqdq	xmm1, xmm7, xmm3, 1
        vpclmulqdq	xmm0, xmm7, xmm3, 0
        vpclmulqdq	xmm3, xmm7, xmm3, 17
        vpxor	xmm2, xmm2, xmm1
        vpxor	xmm6, xmm6, xmm3
        vpxor	xmm5, xmm5, xmm2
        vpxor	xmm4, xmm4, xmm0
        vmovdqu	xmm0, OWORD PTR [esp+80]
        vmovdqu	xmm3, OWORD PTR [edx]
        vmovdqu	xmm7, OWORD PTR [esp+48]
        vpshufb	xmm3, xmm3, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpxor	xmm3, xmm3, xmm0
        vpclmulqdq	xmm2, xmm7, xmm3, 16
        vpclmulqdq	xmm1, xmm7, xmm3, 1
        vpclmulqdq	xmm0, xmm7, xmm3, 0
        vpclmulqdq	xmm3, xmm7, xmm3, 17
        vpxor	xmm2, xmm2, xmm1
        vpxor	xmm6, xmm6, xmm3
        vpxor	xmm5, xmm5, xmm2
        vpxor	xmm4, xmm4, xmm0
        vpslldq	xmm7, xmm5, 8
        vpsrldq	xmm5, xmm5, 8
        vpxor	xmm4, xmm4, xmm7
        vpxor	xmm6, xmm6, xmm5
        ; ghash_red
        vmovdqu	xmm2, OWORD PTR L_aes_gcm_avx2_mod2_128
        vpclmulqdq	xmm0, xmm4, xmm2, 16
        vpshufd	xmm1, xmm4, 78
        vpxor	xmm1, xmm1, xmm0
        vpclmulqdq	xmm0, xmm1, xmm2, 16
        vpshufd	xmm1, xmm1, 78
        vpxor	xmm1, xmm1, xmm0
        vpxor	xmm6, xmm6, xmm1
        vmovdqu	xmm5, OWORD PTR [esp]
        vmovdqu	xmm4, OWORD PTR [esp+64]
L_AES_GCM_encrypt_update_avx2_done_64:
        cmp	ebx, DWORD PTR [esp+132]
        je	L_AES_GCM_encrypt_update_avx2_done_enc
        mov	eax, DWORD PTR [esp+132]
        and	eax, 4294967280
        cmp	ebx, eax
        jge	L_AES_GCM_encrypt_update_avx2_last_block_done
        lea	ecx, DWORD PTR [esi+ebx]
        lea	edx, DWORD PTR [edi+ebx]
        ; aesenc_block
        vmovdqu	xmm1, xmm4
        vpshufb	xmm0, xmm1, OWORD PTR L_aes_gcm_avx2_bswap_epi64
        vpaddd	xmm1, xmm1, OWORD PTR L_aes_gcm_avx2_one
        vpxor	xmm0, xmm0, [ebp]
        vaesenc	xmm0, xmm0, [ebp+16]
        vaesenc	xmm0, xmm0, [ebp+32]
        vaesenc	xmm0, xmm0, [ebp+48]
        vaesenc	xmm0, xmm0, [ebp+64]
        vaesenc	xmm0, xmm0, [ebp+80]
        vaesenc	xmm0, xmm0, [ebp+96]
        vaesenc	xmm0, xmm0, [ebp+112]
        vaesenc	xmm0, xmm0, [ebp+128]
        vaesenc	xmm0, xmm0, [ebp+144]
        cmp	DWORD PTR [esp+120], 11
        vmovdqu	xmm2, OWORD PTR [ebp+160]
        jl	L_AES_GCM_encrypt_update_avx2_aesenc_block_aesenc_avx_last
        vaesenc	xmm0, xmm0, xmm2
        vaesenc	xmm0, xmm0, [ebp+176]
        cmp	DWORD PTR [esp+120], 13
        vmovdqu	xmm2, OWORD PTR [ebp+192]
        jl	L_AES_GCM_encrypt_update_avx2_aesenc_block_aesenc_avx_last
        vaesenc	xmm0, xmm0, xmm2
        vaesenc	xmm0, xmm0, [ebp+208]
        vmovdqu	xmm2, OWORD PTR [ebp+224]
L_AES_GCM_encrypt_update_avx2_aesenc_block_aesenc_avx_last:
        vaesenclast	xmm0, xmm0, xmm2
        vmovdqu	xmm4, xmm1
        vmovdqu	xmm1, OWORD PTR [ecx]
        vpxor	xmm0, xmm0, xmm1
        vmovdqu	OWORD PTR [edx], xmm0
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpxor	xmm6, xmm6, xmm0
        add	ebx, 16
        cmp	ebx, eax
        jge	L_AES_GCM_encrypt_update_avx2_last_block_ghash
L_AES_GCM_encrypt_update_avx2_last_block_start:
        vpshufb	xmm7, xmm4, OWORD PTR L_aes_gcm_avx2_bswap_epi64
        vpaddd	xmm4, xmm4, OWORD PTR L_aes_gcm_avx2_one
        vmovdqu	OWORD PTR [esp+64], xmm4
        ; aesenc_gfmul_sb
        vpclmulqdq	xmm2, xmm6, xmm5, 1
        vpclmulqdq	xmm3, xmm6, xmm5, 16
        vpclmulqdq	xmm1, xmm6, xmm5, 0
        vpclmulqdq	xmm4, xmm6, xmm5, 17
        vpxor	xmm7, xmm7, [ebp]
        vaesenc	xmm7, xmm7, [ebp+16]
        vpxor	xmm3, xmm3, xmm2
        vpslldq	xmm2, xmm3, 8
        vpsrldq	xmm3, xmm3, 8
        vaesenc	xmm7, xmm7, [ebp+32]
        vpxor	xmm2, xmm2, xmm1
        vpclmulqdq	xmm1, xmm2, OWORD PTR L_aes_gcm_avx2_mod2_128, 16
        vaesenc	xmm7, xmm7, [ebp+48]
        vaesenc	xmm7, xmm7, [ebp+64]
        vaesenc	xmm7, xmm7, [ebp+80]
        vpshufd	xmm2, xmm2, 78
        vpxor	xmm2, xmm2, xmm1
        vpclmulqdq	xmm1, xmm2, OWORD PTR L_aes_gcm_avx2_mod2_128, 16
        vaesenc	xmm7, xmm7, [ebp+96]
        vaesenc	xmm7, xmm7, [ebp+112]
        vaesenc	xmm7, xmm7, [ebp+128]
        vpshufd	xmm2, xmm2, 78
        vaesenc	xmm7, xmm7, [ebp+144]
        vpxor	xmm4, xmm4, xmm3
        vpxor	xmm2, xmm2, xmm4
        vmovdqu	xmm0, OWORD PTR [ebp+160]
        cmp	DWORD PTR [esp+120], 11
        jl	L_AES_GCM_encrypt_update_avx2_aesenc_gfmul_sb_last
        vaesenc	xmm7, xmm7, xmm0
        vaesenc	xmm7, xmm7, [ebp+176]
        vmovdqu	xmm0, OWORD PTR [ebp+192]
        cmp	DWORD PTR [esp+120], 13
        jl	L_AES_GCM_encrypt_update_avx2_aesenc_gfmul_sb_last
        vaesenc	xmm7, xmm7, xmm0
        vaesenc	xmm7, xmm7, [ebp+208]
        vmovdqu	xmm0, OWORD PTR [ebp+224]
L_AES_GCM_encrypt_update_avx2_aesenc_gfmul_sb_last:
        vaesenclast	xmm7, xmm7, xmm0
        vmovdqu	xmm3, OWORD PTR [esi+ebx]
        vpxor	xmm6, xmm2, xmm1
        vpxor	xmm7, xmm7, xmm3
        vmovdqu	OWORD PTR [edi+ebx], xmm7
        vpshufb	xmm7, xmm7, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpxor	xmm6, xmm6, xmm7
        vmovdqu	xmm4, OWORD PTR [esp+64]
        add	ebx, 16
        cmp	ebx, eax
        jl	L_AES_GCM_encrypt_update_avx2_last_block_start
L_AES_GCM_encrypt_update_avx2_last_block_ghash:
        ; ghash_gfmul_red
        vpclmulqdq	xmm2, xmm6, xmm5, 16
        vpclmulqdq	xmm1, xmm6, xmm5, 1
        vpclmulqdq	xmm0, xmm6, xmm5, 0
        vpxor	xmm2, xmm2, xmm1
        vpslldq	xmm1, xmm2, 8
        vpsrldq	xmm2, xmm2, 8
        vpxor	xmm1, xmm1, xmm0
        vpclmulqdq	xmm6, xmm6, xmm5, 17
        vpclmulqdq	xmm0, xmm1, OWORD PTR L_aes_gcm_avx2_mod2_128, 16
        vpshufd	xmm1, xmm1, 78
        vpxor	xmm1, xmm1, xmm0
        vpclmulqdq	xmm0, xmm1, OWORD PTR L_aes_gcm_avx2_mod2_128, 16
        vpshufd	xmm1, xmm1, 78
        vpxor	xmm6, xmm6, xmm2
        vpxor	xmm6, xmm6, xmm1
        vpxor	xmm6, xmm6, xmm0
L_AES_GCM_encrypt_update_avx2_last_block_done:
L_AES_GCM_encrypt_update_avx2_done_enc:
        mov	esi, DWORD PTR [esp+136]
        mov	edi, DWORD PTR [esp+144]
        vmovdqu	OWORD PTR [esi], xmm6
        vmovdqu	OWORD PTR [edi], xmm4
        add	esp, 96
        pop	ebp
        pop	edi
        pop	esi
        pop	ebx
        ret
AES_GCM_encrypt_update_avx2 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_GCM_encrypt_final_avx2 PROC
        push	esi
        push	edi
        push	ebp
        sub	esp, 16
        mov	ebp, DWORD PTR [esp+32]
        mov	esi, DWORD PTR [esp+52]
        mov	edi, DWORD PTR [esp+56]
        vmovdqu	xmm4, OWORD PTR [ebp]
        vmovdqu	xmm5, OWORD PTR [esi]
        vmovdqu	xmm6, OWORD PTR [edi]
        vpsrlq	xmm1, xmm5, 63
        vpsllq	xmm0, xmm5, 1
        vpslldq	xmm1, xmm1, 8
        vpor	xmm0, xmm0, xmm1
        vpshufd	xmm5, xmm5, 255
        vpsrad	xmm5, xmm5, 31
        vpand	xmm5, xmm5, OWORD PTR L_aes_gcm_avx2_mod2_128
        vpxor	xmm5, xmm5, xmm0
        ; calc_tag
        mov	ecx, DWORD PTR [esp+44]
        shl	ecx, 3
        vpinsrd	xmm0, xmm0, ecx, 0
        mov	ecx, DWORD PTR [esp+48]
        shl	ecx, 3
        vpinsrd	xmm0, xmm0, ecx, 2
        mov	ecx, DWORD PTR [esp+44]
        shr	ecx, 29
        vpinsrd	xmm0, xmm0, ecx, 1
        mov	ecx, DWORD PTR [esp+48]
        shr	ecx, 29
        vpinsrd	xmm0, xmm0, ecx, 3
        vpxor	xmm0, xmm0, xmm4
        ; ghash_gfmul_red
        vpclmulqdq	xmm7, xmm0, xmm5, 16
        vpclmulqdq	xmm3, xmm0, xmm5, 1
        vpclmulqdq	xmm2, xmm0, xmm5, 0
        vpxor	xmm7, xmm7, xmm3
        vpslldq	xmm3, xmm7, 8
        vpsrldq	xmm7, xmm7, 8
        vpxor	xmm3, xmm3, xmm2
        vpclmulqdq	xmm0, xmm0, xmm5, 17
        vpclmulqdq	xmm2, xmm3, OWORD PTR L_aes_gcm_avx2_mod2_128, 16
        vpshufd	xmm3, xmm3, 78
        vpxor	xmm3, xmm3, xmm2
        vpclmulqdq	xmm2, xmm3, OWORD PTR L_aes_gcm_avx2_mod2_128, 16
        vpshufd	xmm3, xmm3, 78
        vpxor	xmm0, xmm0, xmm7
        vpxor	xmm0, xmm0, xmm3
        vpxor	xmm0, xmm0, xmm2
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpxor	xmm0, xmm0, xmm6
        mov	edi, DWORD PTR [esp+36]
        ; store_tag
        cmp	DWORD PTR [esp+40], 16
        je	L_AES_GCM_encrypt_final_avx2_store_tag_16
        xor	ecx, ecx
        vmovdqu	OWORD PTR [esp], xmm0
L_AES_GCM_encrypt_final_avx2_store_tag_loop:
        movzx	eax, BYTE PTR [esp+ecx]
        mov	BYTE PTR [edi+ecx], al
        inc	ecx
        cmp	ecx, DWORD PTR [esp+40]
        jne	L_AES_GCM_encrypt_final_avx2_store_tag_loop
        jmp	L_AES_GCM_encrypt_final_avx2_store_tag_done
L_AES_GCM_encrypt_final_avx2_store_tag_16:
        vmovdqu	OWORD PTR [edi], xmm0
L_AES_GCM_encrypt_final_avx2_store_tag_done:
        add	esp, 16
        pop	ebp
        pop	edi
        pop	esi
        ret
AES_GCM_encrypt_final_avx2 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_GCM_decrypt_update_avx2 PROC
        push	ebx
        push	esi
        push	edi
        push	ebp
        sub	esp, 160
        mov	esi, DWORD PTR [esp+208]
        vmovdqu	xmm4, OWORD PTR [esi]
        mov	esi, DWORD PTR [esp+200]
        mov	ebp, DWORD PTR [esp+204]
        vmovdqu	xmm6, OWORD PTR [esi]
        vmovdqu	xmm5, OWORD PTR [ebp]
        mov	ebp, DWORD PTR [esp+180]
        mov	edi, DWORD PTR [esp+188]
        mov	esi, DWORD PTR [esp+192]
        ; Calculate H
        vpsrlq	xmm1, xmm5, 63
        vpsllq	xmm0, xmm5, 1
        vpslldq	xmm1, xmm1, 8
        vpor	xmm0, xmm0, xmm1
        vpshufd	xmm5, xmm5, 255
        vpsrad	xmm5, xmm5, 31
        vpand	xmm5, xmm5, OWORD PTR L_aes_gcm_avx2_mod2_128
        vpxor	xmm5, xmm5, xmm0
        xor	ebx, ebx
        cmp	DWORD PTR [esp+196], 64
        mov	eax, DWORD PTR [esp+196]
        jl	L_AES_GCM_decrypt_update_avx2_done_64
        and	eax, 4294967232
        vmovdqu	OWORD PTR [esp+64], xmm4
        vmovdqu	OWORD PTR [esp+80], xmm6
        vmovdqu	xmm3, OWORD PTR L_aes_gcm_avx2_mod2_128
        ; H ^ 1
        vmovdqu	OWORD PTR [esp], xmm5
        vmovdqu	xmm2, xmm5
        ; H ^ 2
        vpclmulqdq	xmm5, xmm2, xmm2, 0
        vpclmulqdq	xmm6, xmm2, xmm2, 17
        vpclmulqdq	xmm4, xmm5, xmm3, 16
        vpshufd	xmm5, xmm5, 78
        vpxor	xmm5, xmm5, xmm4
        vpclmulqdq	xmm4, xmm5, xmm3, 16
        vpshufd	xmm5, xmm5, 78
        vpxor	xmm5, xmm5, xmm4
        vpxor	xmm0, xmm6, xmm5
        vmovdqu	OWORD PTR [esp+16], xmm0
        ; H ^ 3
        ; ghash_gfmul_red
        vpclmulqdq	xmm6, xmm2, xmm0, 16
        vpclmulqdq	xmm5, xmm2, xmm0, 1
        vpclmulqdq	xmm4, xmm2, xmm0, 0
        vpxor	xmm6, xmm6, xmm5
        vpslldq	xmm5, xmm6, 8
        vpsrldq	xmm6, xmm6, 8
        vpxor	xmm5, xmm5, xmm4
        vpclmulqdq	xmm1, xmm2, xmm0, 17
        vpclmulqdq	xmm4, xmm5, xmm3, 16
        vpshufd	xmm5, xmm5, 78
        vpxor	xmm5, xmm5, xmm4
        vpclmulqdq	xmm4, xmm5, xmm3, 16
        vpshufd	xmm5, xmm5, 78
        vpxor	xmm1, xmm1, xmm6
        vpxor	xmm1, xmm1, xmm5
        vpxor	xmm1, xmm1, xmm4
        vmovdqu	OWORD PTR [esp+32], xmm1
        ; H ^ 4
        vpclmulqdq	xmm5, xmm0, xmm0, 0
        vpclmulqdq	xmm6, xmm0, xmm0, 17
        vpclmulqdq	xmm4, xmm5, xmm3, 16
        vpshufd	xmm5, xmm5, 78
        vpxor	xmm5, xmm5, xmm4
        vpclmulqdq	xmm4, xmm5, xmm3, 16
        vpshufd	xmm5, xmm5, 78
        vpxor	xmm5, xmm5, xmm4
        vpxor	xmm2, xmm6, xmm5
        vmovdqu	OWORD PTR [esp+48], xmm2
        vmovdqu	xmm6, OWORD PTR [esp+80]
        cmp	edi, esi
        jne	L_AES_GCM_decrypt_update_avx2_ghash_64
L_AES_GCM_decrypt_update_avx2_ghash_64_inplace:
        ; aesenc_64_ghash
        lea	ecx, DWORD PTR [esi+ebx]
        lea	edx, DWORD PTR [edi+ebx]
        ; aesenc_64
        ; aesenc_ctr
        vmovdqu	xmm4, OWORD PTR [esp+64]
        vmovdqu	xmm7, OWORD PTR L_aes_gcm_avx2_bswap_epi64
        vpaddd	xmm1, xmm4, OWORD PTR L_aes_gcm_avx2_one
        vpshufb	xmm0, xmm4, xmm7
        vpaddd	xmm2, xmm4, OWORD PTR L_aes_gcm_avx2_two
        vpshufb	xmm1, xmm1, xmm7
        vpaddd	xmm3, xmm4, OWORD PTR L_aes_gcm_avx2_three
        vpshufb	xmm2, xmm2, xmm7
        vpaddd	xmm4, xmm4, OWORD PTR L_aes_gcm_avx2_four
        vpshufb	xmm3, xmm3, xmm7
        ; aesenc_xor
        vmovdqu	xmm7, OWORD PTR [ebp]
        vmovdqu	OWORD PTR [esp+64], xmm4
        vpxor	xmm0, xmm0, xmm7
        vpxor	xmm1, xmm1, xmm7
        vpxor	xmm2, xmm2, xmm7
        vpxor	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+16]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+32]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+48]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+64]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+80]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+96]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+112]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+128]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+144]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        cmp	DWORD PTR [esp+184], 11
        vmovdqu	xmm7, OWORD PTR [ebp+160]
        jl	L_AES_GCM_decrypt_update_avx2_inplace_aesenc_64_ghash_aesenc_64_enc_done
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+176]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        cmp	DWORD PTR [esp+184], 13
        vmovdqu	xmm7, OWORD PTR [ebp+192]
        jl	L_AES_GCM_decrypt_update_avx2_inplace_aesenc_64_ghash_aesenc_64_enc_done
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+208]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+224]
L_AES_GCM_decrypt_update_avx2_inplace_aesenc_64_ghash_aesenc_64_enc_done:
        ; aesenc_last
        vaesenclast	xmm0, xmm0, xmm7
        vaesenclast	xmm1, xmm1, xmm7
        vaesenclast	xmm2, xmm2, xmm7
        vaesenclast	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ecx]
        vmovdqu	xmm4, OWORD PTR [ecx+16]
        vpxor	xmm0, xmm0, xmm7
        vpxor	xmm1, xmm1, xmm4
        vmovdqu	OWORD PTR [esp+96], xmm7
        vmovdqu	OWORD PTR [esp+112], xmm4
        vmovdqu	OWORD PTR [edx], xmm0
        vmovdqu	OWORD PTR [edx+16], xmm1
        vmovdqu	xmm7, OWORD PTR [ecx+32]
        vmovdqu	xmm4, OWORD PTR [ecx+48]
        vpxor	xmm2, xmm2, xmm7
        vpxor	xmm3, xmm3, xmm4
        vmovdqu	OWORD PTR [esp+128], xmm7
        vmovdqu	OWORD PTR [esp+144], xmm4
        vmovdqu	OWORD PTR [edx+32], xmm2
        vmovdqu	OWORD PTR [edx+48], xmm3
        ; pclmul_1
        vmovdqu	xmm1, OWORD PTR [esp+96]
        vpshufb	xmm1, xmm1, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vmovdqu	xmm2, OWORD PTR [esp+48]
        vpxor	xmm1, xmm1, xmm6
        vpclmulqdq	xmm5, xmm1, xmm2, 16
        vpclmulqdq	xmm3, xmm1, xmm2, 1
        vpclmulqdq	xmm6, xmm1, xmm2, 0
        vpclmulqdq	xmm7, xmm1, xmm2, 17
        ; pclmul_2
        vmovdqu	xmm1, OWORD PTR [esp+112]
        vmovdqu	xmm0, OWORD PTR [esp+32]
        vpshufb	xmm1, xmm1, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpxor	xmm5, xmm5, xmm3
        vpclmulqdq	xmm2, xmm1, xmm0, 16
        vpclmulqdq	xmm3, xmm1, xmm0, 1
        vpclmulqdq	xmm4, xmm1, xmm0, 0
        vpclmulqdq	xmm1, xmm1, xmm0, 17
        vpxor	xmm7, xmm7, xmm1
        ; pclmul_n
        vmovdqu	xmm1, OWORD PTR [esp+128]
        vmovdqu	xmm0, OWORD PTR [esp+16]
        vpshufb	xmm1, xmm1, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpxor	xmm5, xmm5, xmm2
        vpclmulqdq	xmm2, xmm1, xmm0, 16
        vpxor	xmm5, xmm5, xmm3
        vpclmulqdq	xmm3, xmm1, xmm0, 1
        vpxor	xmm6, xmm6, xmm4
        vpclmulqdq	xmm4, xmm1, xmm0, 0
        vpclmulqdq	xmm1, xmm1, xmm0, 17
        vpxor	xmm7, xmm7, xmm1
        ; pclmul_n
        vmovdqu	xmm1, OWORD PTR [esp+144]
        vmovdqu	xmm0, OWORD PTR [esp]
        vpshufb	xmm1, xmm1, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpxor	xmm5, xmm5, xmm2
        vpclmulqdq	xmm2, xmm1, xmm0, 16
        vpxor	xmm5, xmm5, xmm3
        vpclmulqdq	xmm3, xmm1, xmm0, 1
        vpxor	xmm6, xmm6, xmm4
        vpclmulqdq	xmm4, xmm1, xmm0, 0
        vpclmulqdq	xmm1, xmm1, xmm0, 17
        vpxor	xmm7, xmm7, xmm1
        ; aesenc_pclmul_l
        vpxor	xmm5, xmm5, xmm2
        vpxor	xmm6, xmm6, xmm4
        vpxor	xmm5, xmm5, xmm3
        vpslldq	xmm1, xmm5, 8
        vpsrldq	xmm5, xmm5, 8
        vmovdqu	xmm0, OWORD PTR L_aes_gcm_avx2_mod2_128
        vpxor	xmm6, xmm6, xmm1
        vpxor	xmm7, xmm7, xmm5
        vpclmulqdq	xmm3, xmm6, xmm0, 16
        vpshufd	xmm6, xmm6, 78
        vpxor	xmm6, xmm6, xmm3
        vpclmulqdq	xmm3, xmm6, xmm0, 16
        vpshufd	xmm6, xmm6, 78
        vpxor	xmm6, xmm6, xmm3
        vpxor	xmm6, xmm6, xmm7
        ; aesenc_64_ghash - end
        add	ebx, 64
        cmp	ebx, eax
        jl	L_AES_GCM_decrypt_update_avx2_ghash_64_inplace
        jmp	L_AES_GCM_decrypt_update_avx2_ghash_64_done
L_AES_GCM_decrypt_update_avx2_ghash_64:
        ; aesenc_64_ghash
        lea	ecx, DWORD PTR [esi+ebx]
        lea	edx, DWORD PTR [edi+ebx]
        ; aesenc_64
        ; aesenc_ctr
        vmovdqu	xmm4, OWORD PTR [esp+64]
        vmovdqu	xmm7, OWORD PTR L_aes_gcm_avx2_bswap_epi64
        vpaddd	xmm1, xmm4, OWORD PTR L_aes_gcm_avx2_one
        vpshufb	xmm0, xmm4, xmm7
        vpaddd	xmm2, xmm4, OWORD PTR L_aes_gcm_avx2_two
        vpshufb	xmm1, xmm1, xmm7
        vpaddd	xmm3, xmm4, OWORD PTR L_aes_gcm_avx2_three
        vpshufb	xmm2, xmm2, xmm7
        vpaddd	xmm4, xmm4, OWORD PTR L_aes_gcm_avx2_four
        vpshufb	xmm3, xmm3, xmm7
        ; aesenc_xor
        vmovdqu	xmm7, OWORD PTR [ebp]
        vmovdqu	OWORD PTR [esp+64], xmm4
        vpxor	xmm0, xmm0, xmm7
        vpxor	xmm1, xmm1, xmm7
        vpxor	xmm2, xmm2, xmm7
        vpxor	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+16]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+32]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+48]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+64]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+80]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+96]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+112]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+128]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+144]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        cmp	DWORD PTR [esp+184], 11
        vmovdqu	xmm7, OWORD PTR [ebp+160]
        jl	L_AES_GCM_decrypt_update_avx2_aesenc_64_ghash_aesenc_64_enc_done
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+176]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        cmp	DWORD PTR [esp+184], 13
        vmovdqu	xmm7, OWORD PTR [ebp+192]
        jl	L_AES_GCM_decrypt_update_avx2_aesenc_64_ghash_aesenc_64_enc_done
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+208]
        vaesenc	xmm0, xmm0, xmm7
        vaesenc	xmm1, xmm1, xmm7
        vaesenc	xmm2, xmm2, xmm7
        vaesenc	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ebp+224]
L_AES_GCM_decrypt_update_avx2_aesenc_64_ghash_aesenc_64_enc_done:
        ; aesenc_last
        vaesenclast	xmm0, xmm0, xmm7
        vaesenclast	xmm1, xmm1, xmm7
        vaesenclast	xmm2, xmm2, xmm7
        vaesenclast	xmm3, xmm3, xmm7
        vmovdqu	xmm7, OWORD PTR [ecx]
        vmovdqu	xmm4, OWORD PTR [ecx+16]
        vpxor	xmm0, xmm0, xmm7
        vpxor	xmm1, xmm1, xmm4
        vmovdqu	OWORD PTR [edx], xmm0
        vmovdqu	OWORD PTR [edx+16], xmm1
        vmovdqu	xmm7, OWORD PTR [ecx+32]
        vmovdqu	xmm4, OWORD PTR [ecx+48]
        vpxor	xmm2, xmm2, xmm7
        vpxor	xmm3, xmm3, xmm4
        vmovdqu	OWORD PTR [ecx+32], xmm7
        vmovdqu	OWORD PTR [ecx+48], xmm4
        vmovdqu	OWORD PTR [edx+32], xmm2
        vmovdqu	OWORD PTR [edx+48], xmm3
        ; pclmul_1
        vmovdqu	xmm1, OWORD PTR [ecx]
        vpshufb	xmm1, xmm1, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vmovdqu	xmm2, OWORD PTR [esp+48]
        vpxor	xmm1, xmm1, xmm6
        vpclmulqdq	xmm5, xmm1, xmm2, 16
        vpclmulqdq	xmm3, xmm1, xmm2, 1
        vpclmulqdq	xmm6, xmm1, xmm2, 0
        vpclmulqdq	xmm7, xmm1, xmm2, 17
        ; pclmul_2
        vmovdqu	xmm1, OWORD PTR [ecx+16]
        vmovdqu	xmm0, OWORD PTR [esp+32]
        vpshufb	xmm1, xmm1, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpxor	xmm5, xmm5, xmm3
        vpclmulqdq	xmm2, xmm1, xmm0, 16
        vpclmulqdq	xmm3, xmm1, xmm0, 1
        vpclmulqdq	xmm4, xmm1, xmm0, 0
        vpclmulqdq	xmm1, xmm1, xmm0, 17
        vpxor	xmm7, xmm7, xmm1
        ; pclmul_n
        vmovdqu	xmm1, OWORD PTR [ecx+32]
        vmovdqu	xmm0, OWORD PTR [esp+16]
        vpshufb	xmm1, xmm1, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpxor	xmm5, xmm5, xmm2
        vpclmulqdq	xmm2, xmm1, xmm0, 16
        vpxor	xmm5, xmm5, xmm3
        vpclmulqdq	xmm3, xmm1, xmm0, 1
        vpxor	xmm6, xmm6, xmm4
        vpclmulqdq	xmm4, xmm1, xmm0, 0
        vpclmulqdq	xmm1, xmm1, xmm0, 17
        vpxor	xmm7, xmm7, xmm1
        ; pclmul_n
        vmovdqu	xmm1, OWORD PTR [ecx+48]
        vmovdqu	xmm0, OWORD PTR [esp]
        vpshufb	xmm1, xmm1, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpxor	xmm5, xmm5, xmm2
        vpclmulqdq	xmm2, xmm1, xmm0, 16
        vpxor	xmm5, xmm5, xmm3
        vpclmulqdq	xmm3, xmm1, xmm0, 1
        vpxor	xmm6, xmm6, xmm4
        vpclmulqdq	xmm4, xmm1, xmm0, 0
        vpclmulqdq	xmm1, xmm1, xmm0, 17
        vpxor	xmm7, xmm7, xmm1
        ; aesenc_pclmul_l
        vpxor	xmm5, xmm5, xmm2
        vpxor	xmm6, xmm6, xmm4
        vpxor	xmm5, xmm5, xmm3
        vpslldq	xmm1, xmm5, 8
        vpsrldq	xmm5, xmm5, 8
        vmovdqu	xmm0, OWORD PTR L_aes_gcm_avx2_mod2_128
        vpxor	xmm6, xmm6, xmm1
        vpxor	xmm7, xmm7, xmm5
        vpclmulqdq	xmm3, xmm6, xmm0, 16
        vpshufd	xmm6, xmm6, 78
        vpxor	xmm6, xmm6, xmm3
        vpclmulqdq	xmm3, xmm6, xmm0, 16
        vpshufd	xmm6, xmm6, 78
        vpxor	xmm6, xmm6, xmm3
        vpxor	xmm6, xmm6, xmm7
        ; aesenc_64_ghash - end
        add	ebx, 64
        cmp	ebx, eax
        jl	L_AES_GCM_decrypt_update_avx2_ghash_64
L_AES_GCM_decrypt_update_avx2_ghash_64_done:
        vmovdqu	xmm5, OWORD PTR [esp]
        vmovdqu	xmm4, OWORD PTR [esp+64]
L_AES_GCM_decrypt_update_avx2_done_64:
        cmp	ebx, DWORD PTR [esp+196]
        jge	L_AES_GCM_decrypt_update_avx2_done_dec
        mov	eax, DWORD PTR [esp+196]
        and	eax, 4294967280
        cmp	ebx, eax
        jge	L_AES_GCM_decrypt_update_avx2_last_block_done
L_AES_GCM_decrypt_update_avx2_last_block_start:
        vmovdqu	xmm0, OWORD PTR [esi+ebx]
        vpshufb	xmm7, xmm4, OWORD PTR L_aes_gcm_avx2_bswap_epi64
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpaddd	xmm4, xmm4, OWORD PTR L_aes_gcm_avx2_one
        vmovdqu	OWORD PTR [esp+64], xmm4
        vpxor	xmm4, xmm0, xmm6
        ; aesenc_gfmul_sb
        vpclmulqdq	xmm2, xmm4, xmm5, 1
        vpclmulqdq	xmm3, xmm4, xmm5, 16
        vpclmulqdq	xmm1, xmm4, xmm5, 0
        vpclmulqdq	xmm4, xmm4, xmm5, 17
        vpxor	xmm7, xmm7, [ebp]
        vaesenc	xmm7, xmm7, [ebp+16]
        vpxor	xmm3, xmm3, xmm2
        vpslldq	xmm2, xmm3, 8
        vpsrldq	xmm3, xmm3, 8
        vaesenc	xmm7, xmm7, [ebp+32]
        vpxor	xmm2, xmm2, xmm1
        vpclmulqdq	xmm1, xmm2, OWORD PTR L_aes_gcm_avx2_mod2_128, 16
        vaesenc	xmm7, xmm7, [ebp+48]
        vaesenc	xmm7, xmm7, [ebp+64]
        vaesenc	xmm7, xmm7, [ebp+80]
        vpshufd	xmm2, xmm2, 78
        vpxor	xmm2, xmm2, xmm1
        vpclmulqdq	xmm1, xmm2, OWORD PTR L_aes_gcm_avx2_mod2_128, 16
        vaesenc	xmm7, xmm7, [ebp+96]
        vaesenc	xmm7, xmm7, [ebp+112]
        vaesenc	xmm7, xmm7, [ebp+128]
        vpshufd	xmm2, xmm2, 78
        vaesenc	xmm7, xmm7, [ebp+144]
        vpxor	xmm4, xmm4, xmm3
        vpxor	xmm2, xmm2, xmm4
        vmovdqu	xmm0, OWORD PTR [ebp+160]
        cmp	DWORD PTR [esp+184], 11
        jl	L_AES_GCM_decrypt_update_avx2_aesenc_gfmul_sb_last
        vaesenc	xmm7, xmm7, xmm0
        vaesenc	xmm7, xmm7, [ebp+176]
        vmovdqu	xmm0, OWORD PTR [ebp+192]
        cmp	DWORD PTR [esp+184], 13
        jl	L_AES_GCM_decrypt_update_avx2_aesenc_gfmul_sb_last
        vaesenc	xmm7, xmm7, xmm0
        vaesenc	xmm7, xmm7, [ebp+208]
        vmovdqu	xmm0, OWORD PTR [ebp+224]
L_AES_GCM_decrypt_update_avx2_aesenc_gfmul_sb_last:
        vaesenclast	xmm7, xmm7, xmm0
        vmovdqu	xmm3, OWORD PTR [esi+ebx]
        vpxor	xmm6, xmm2, xmm1
        vpxor	xmm7, xmm7, xmm3
        vmovdqu	OWORD PTR [edi+ebx], xmm7
        vmovdqu	xmm4, OWORD PTR [esp+64]
        add	ebx, 16
        cmp	ebx, eax
        jl	L_AES_GCM_decrypt_update_avx2_last_block_start
L_AES_GCM_decrypt_update_avx2_last_block_done:
L_AES_GCM_decrypt_update_avx2_done_dec:
        mov	esi, DWORD PTR [esp+200]
        mov	edi, DWORD PTR [esp+208]
        vmovdqu	xmm4, OWORD PTR [esp+64]
        vmovdqu	OWORD PTR [esi], xmm6
        vmovdqu	OWORD PTR [edi], xmm4
        add	esp, 160
        pop	ebp
        pop	edi
        pop	esi
        pop	ebx
        ret
AES_GCM_decrypt_update_avx2 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_GCM_decrypt_final_avx2 PROC
        push	ebx
        push	esi
        push	edi
        push	ebp
        sub	esp, 16
        mov	ebp, DWORD PTR [esp+36]
        mov	esi, DWORD PTR [esp+56]
        mov	edi, DWORD PTR [esp+60]
        vmovdqu	xmm4, OWORD PTR [ebp]
        vmovdqu	xmm5, OWORD PTR [esi]
        vmovdqu	xmm6, OWORD PTR [edi]
        vpsrlq	xmm1, xmm5, 63
        vpsllq	xmm0, xmm5, 1
        vpslldq	xmm1, xmm1, 8
        vpor	xmm0, xmm0, xmm1
        vpshufd	xmm5, xmm5, 255
        vpsrad	xmm5, xmm5, 31
        vpand	xmm5, xmm5, OWORD PTR L_aes_gcm_avx2_mod2_128
        vpxor	xmm5, xmm5, xmm0
        ; calc_tag
        mov	ecx, DWORD PTR [esp+48]
        shl	ecx, 3
        vpinsrd	xmm0, xmm0, ecx, 0
        mov	ecx, DWORD PTR [esp+52]
        shl	ecx, 3
        vpinsrd	xmm0, xmm0, ecx, 2
        mov	ecx, DWORD PTR [esp+48]
        shr	ecx, 29
        vpinsrd	xmm0, xmm0, ecx, 1
        mov	ecx, DWORD PTR [esp+52]
        shr	ecx, 29
        vpinsrd	xmm0, xmm0, ecx, 3
        vpxor	xmm0, xmm0, xmm4
        ; ghash_gfmul_red
        vpclmulqdq	xmm7, xmm0, xmm5, 16
        vpclmulqdq	xmm3, xmm0, xmm5, 1
        vpclmulqdq	xmm2, xmm0, xmm5, 0
        vpxor	xmm7, xmm7, xmm3
        vpslldq	xmm3, xmm7, 8
        vpsrldq	xmm7, xmm7, 8
        vpxor	xmm3, xmm3, xmm2
        vpclmulqdq	xmm0, xmm0, xmm5, 17
        vpclmulqdq	xmm2, xmm3, OWORD PTR L_aes_gcm_avx2_mod2_128, 16
        vpshufd	xmm3, xmm3, 78
        vpxor	xmm3, xmm3, xmm2
        vpclmulqdq	xmm2, xmm3, OWORD PTR L_aes_gcm_avx2_mod2_128, 16
        vpshufd	xmm3, xmm3, 78
        vpxor	xmm0, xmm0, xmm7
        vpxor	xmm0, xmm0, xmm3
        vpxor	xmm0, xmm0, xmm2
        vpshufb	xmm0, xmm0, OWORD PTR L_aes_gcm_avx2_bswap_mask
        vpxor	xmm0, xmm0, xmm6
        mov	esi, DWORD PTR [esp+40]
        mov	edi, DWORD PTR [esp+64]
        ; cmp_tag
        cmp	DWORD PTR [esp+44], 16
        je	L_AES_GCM_decrypt_final_avx2_cmp_tag_16
        xor	ecx, ecx
        xor	edx, edx
        vmovdqu	OWORD PTR [esp], xmm0
L_AES_GCM_decrypt_final_avx2_cmp_tag_loop:
        movzx	eax, BYTE PTR [esp+ecx]
        xor	al, BYTE PTR [esi+ecx]
        or	dl, al
        inc	ecx
        cmp	ecx, DWORD PTR [esp+44]
        jne	L_AES_GCM_decrypt_final_avx2_cmp_tag_loop
        cmp	dl, 0
        sete	dl
        jmp	L_AES_GCM_decrypt_final_avx2_cmp_tag_done
L_AES_GCM_decrypt_final_avx2_cmp_tag_16:
        vmovdqu	xmm1, OWORD PTR [esi]
        vpcmpeqb	xmm0, xmm0, xmm1
        vpmovmskb	ecx, xmm0
        ; %%edx == 0xFFFF then return 1 else => return 0
        xor	edx, edx
        cmp	ecx, 65535
        sete	dl
L_AES_GCM_decrypt_final_avx2_cmp_tag_done:
        mov	DWORD PTR [edi], edx
        add	esp, 16
        pop	ebp
        pop	edi
        pop	esi
        pop	ebx
        ret
AES_GCM_decrypt_final_avx2 ENDP
_TEXT ENDS
ENDIF
ENDIF
END
