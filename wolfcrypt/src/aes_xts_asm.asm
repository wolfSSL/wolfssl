; /* aes_xts_asm.asm */
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

_TEXT SEGMENT READONLY PARA
AES_XTS_init_aesni PROC
        movdqu	xmm0, OWORD PTR [rcx]
        ; aes_enc_block
        pxor	xmm0, [rdx]
        movdqu	xmm2, OWORD PTR [rdx+16]
        aesenc	xmm0, xmm2
        movdqu	xmm2, OWORD PTR [rdx+32]
        aesenc	xmm0, xmm2
        movdqu	xmm2, OWORD PTR [rdx+48]
        aesenc	xmm0, xmm2
        movdqu	xmm2, OWORD PTR [rdx+64]
        aesenc	xmm0, xmm2
        movdqu	xmm2, OWORD PTR [rdx+80]
        aesenc	xmm0, xmm2
        movdqu	xmm2, OWORD PTR [rdx+96]
        aesenc	xmm0, xmm2
        movdqu	xmm2, OWORD PTR [rdx+112]
        aesenc	xmm0, xmm2
        movdqu	xmm2, OWORD PTR [rdx+128]
        aesenc	xmm0, xmm2
        movdqu	xmm2, OWORD PTR [rdx+144]
        aesenc	xmm0, xmm2
        cmp	r8d, 11
        movdqu	xmm2, OWORD PTR [rdx+160]
        jl	L_AES_XTS_init_aesni_tweak_aes_enc_block_last
        aesenc	xmm0, xmm2
        movdqu	xmm3, OWORD PTR [rdx+176]
        aesenc	xmm0, xmm3
        cmp	r8d, 13
        movdqu	xmm2, OWORD PTR [rdx+192]
        jl	L_AES_XTS_init_aesni_tweak_aes_enc_block_last
        aesenc	xmm0, xmm2
        movdqu	xmm3, OWORD PTR [rdx+208]
        aesenc	xmm0, xmm3
        movdqu	xmm2, OWORD PTR [rdx+224]
L_AES_XTS_init_aesni_tweak_aes_enc_block_last:
        aesenclast	xmm0, xmm2
        movdqu	OWORD PTR [rcx], xmm0
        ret
AES_XTS_init_aesni ENDP
_TEXT ENDS
_DATA SEGMENT
ALIGN 16
L_aes_xts_gc_xts DWORD \
     00000087h,  00000001h,  00000001h,  00000001h
ptr_L_aes_xts_gc_xts QWORD L_aes_xts_gc_xts
_DATA ENDS
_TEXT SEGMENT READONLY PARA
AES_XTS_encrypt_aesni PROC
        push	rdi
        push	rsi
        push	r12
        push	r13
        mov	rdi, rcx
        mov	rsi, rdx
        mov	rax, r8
        mov	r12, r9
        mov	r8, QWORD PTR [rsp+72]
        mov	r9, QWORD PTR [rsp+80]
        mov	r10d, DWORD PTR [rsp+88]
        sub	rsp, 176
        movdqu	OWORD PTR [rsp+64], xmm6
        movdqu	OWORD PTR [rsp+80], xmm7
        movdqu	OWORD PTR [rsp+96], xmm8
        movdqu	OWORD PTR [rsp+112], xmm9
        movdqu	OWORD PTR [rsp+128], xmm10
        movdqu	OWORD PTR [rsp+144], xmm11
        movdqu	OWORD PTR [rsp+160], xmm12
        movdqu	xmm12, OWORD PTR L_aes_xts_gc_xts
        movdqu	xmm0, OWORD PTR [r12]
        ; aes_enc_block
        pxor	xmm0, [r9]
        movdqu	xmm5, OWORD PTR [r9+16]
        aesenc	xmm0, xmm5
        movdqu	xmm5, OWORD PTR [r9+32]
        aesenc	xmm0, xmm5
        movdqu	xmm5, OWORD PTR [r9+48]
        aesenc	xmm0, xmm5
        movdqu	xmm5, OWORD PTR [r9+64]
        aesenc	xmm0, xmm5
        movdqu	xmm5, OWORD PTR [r9+80]
        aesenc	xmm0, xmm5
        movdqu	xmm5, OWORD PTR [r9+96]
        aesenc	xmm0, xmm5
        movdqu	xmm5, OWORD PTR [r9+112]
        aesenc	xmm0, xmm5
        movdqu	xmm5, OWORD PTR [r9+128]
        aesenc	xmm0, xmm5
        movdqu	xmm5, OWORD PTR [r9+144]
        aesenc	xmm0, xmm5
        cmp	r10d, 11
        movdqu	xmm5, OWORD PTR [r9+160]
        jl	L_AES_XTS_encrypt_aesni_tweak_aes_enc_block_last
        aesenc	xmm0, xmm5
        movdqu	xmm6, OWORD PTR [r9+176]
        aesenc	xmm0, xmm6
        cmp	r10d, 13
        movdqu	xmm5, OWORD PTR [r9+192]
        jl	L_AES_XTS_encrypt_aesni_tweak_aes_enc_block_last
        aesenc	xmm0, xmm5
        movdqu	xmm6, OWORD PTR [r9+208]
        aesenc	xmm0, xmm6
        movdqu	xmm5, OWORD PTR [r9+224]
L_AES_XTS_encrypt_aesni_tweak_aes_enc_block_last:
        aesenclast	xmm0, xmm5
        xor	r13d, r13d
        cmp	eax, 64
        mov	r11d, eax
        jl	L_AES_XTS_encrypt_aesni_done_64
        and	r11d, 4294967232
L_AES_XTS_encrypt_aesni_enc_64:
        ; 64 bytes of input
        ; aes_enc_64
        lea	rcx, QWORD PTR [rdi+r13]
        lea	rdx, QWORD PTR [rsi+r13]
        movdqu	xmm8, OWORD PTR [rcx]
        movdqu	xmm9, OWORD PTR [rcx+16]
        movdqu	xmm10, OWORD PTR [rcx+32]
        movdqu	xmm11, OWORD PTR [rcx+48]
        movdqa	xmm4, xmm0
        movdqa	xmm1, xmm0
        psrad	xmm4, 31
        pslld	xmm1, 1
        pshufd	xmm4, xmm4, 147
        pand	xmm4, xmm12
        pxor	xmm1, xmm4
        movdqa	xmm4, xmm1
        movdqa	xmm2, xmm1
        psrad	xmm4, 31
        pslld	xmm2, 1
        pshufd	xmm4, xmm4, 147
        pand	xmm4, xmm12
        pxor	xmm2, xmm4
        movdqa	xmm4, xmm2
        movdqa	xmm3, xmm2
        psrad	xmm4, 31
        pslld	xmm3, 1
        pshufd	xmm4, xmm4, 147
        pand	xmm4, xmm12
        pxor	xmm3, xmm4
        pxor	xmm8, xmm0
        pxor	xmm9, xmm1
        pxor	xmm10, xmm2
        pxor	xmm11, xmm3
        ; aes_enc_block
        movdqu	xmm4, OWORD PTR [r8]
        pxor	xmm8, xmm4
        pxor	xmm9, xmm4
        pxor	xmm10, xmm4
        pxor	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r8+16]
        aesenc	xmm8, xmm4
        aesenc	xmm9, xmm4
        aesenc	xmm10, xmm4
        aesenc	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r8+32]
        aesenc	xmm8, xmm4
        aesenc	xmm9, xmm4
        aesenc	xmm10, xmm4
        aesenc	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r8+48]
        aesenc	xmm8, xmm4
        aesenc	xmm9, xmm4
        aesenc	xmm10, xmm4
        aesenc	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r8+64]
        aesenc	xmm8, xmm4
        aesenc	xmm9, xmm4
        aesenc	xmm10, xmm4
        aesenc	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r8+80]
        aesenc	xmm8, xmm4
        aesenc	xmm9, xmm4
        aesenc	xmm10, xmm4
        aesenc	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r8+96]
        aesenc	xmm8, xmm4
        aesenc	xmm9, xmm4
        aesenc	xmm10, xmm4
        aesenc	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r8+112]
        aesenc	xmm8, xmm4
        aesenc	xmm9, xmm4
        aesenc	xmm10, xmm4
        aesenc	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r8+128]
        aesenc	xmm8, xmm4
        aesenc	xmm9, xmm4
        aesenc	xmm10, xmm4
        aesenc	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r8+144]
        aesenc	xmm8, xmm4
        aesenc	xmm9, xmm4
        aesenc	xmm10, xmm4
        aesenc	xmm11, xmm4
        cmp	r10d, 11
        movdqu	xmm4, OWORD PTR [r8+160]
        jl	L_AES_XTS_encrypt_aesni_aes_enc_64_aes_enc_block_last
        aesenc	xmm8, xmm4
        aesenc	xmm9, xmm4
        aesenc	xmm10, xmm4
        aesenc	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r8+176]
        aesenc	xmm8, xmm4
        aesenc	xmm9, xmm4
        aesenc	xmm10, xmm4
        aesenc	xmm11, xmm4
        cmp	r10d, 13
        movdqu	xmm4, OWORD PTR [r8+192]
        jl	L_AES_XTS_encrypt_aesni_aes_enc_64_aes_enc_block_last
        aesenc	xmm8, xmm4
        aesenc	xmm9, xmm4
        aesenc	xmm10, xmm4
        aesenc	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r8+208]
        aesenc	xmm8, xmm4
        aesenc	xmm9, xmm4
        aesenc	xmm10, xmm4
        aesenc	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r8+224]
L_AES_XTS_encrypt_aesni_aes_enc_64_aes_enc_block_last:
        aesenclast	xmm8, xmm4
        aesenclast	xmm9, xmm4
        aesenclast	xmm10, xmm4
        aesenclast	xmm11, xmm4
        pxor	xmm8, xmm0
        pxor	xmm9, xmm1
        pxor	xmm10, xmm2
        pxor	xmm11, xmm3
        movdqu	OWORD PTR [rdx], xmm8
        movdqu	OWORD PTR [rdx+16], xmm9
        movdqu	OWORD PTR [rdx+32], xmm10
        movdqu	OWORD PTR [rdx+48], xmm11
        movdqa	xmm4, xmm3
        movdqa	xmm0, xmm3
        psrad	xmm4, 31
        pslld	xmm0, 1
        pshufd	xmm4, xmm4, 147
        pand	xmm4, xmm12
        pxor	xmm0, xmm4
        add	r13d, 64
        cmp	r13d, r11d
        jl	L_AES_XTS_encrypt_aesni_enc_64
L_AES_XTS_encrypt_aesni_done_64:
        cmp	r13d, eax
        mov	r11d, eax
        je	L_AES_XTS_encrypt_aesni_done_enc
        sub	r11d, r13d
        cmp	r11d, 16
        mov	r11d, eax
        jl	L_AES_XTS_encrypt_aesni_last_15
        and	r11d, 4294967280
        ; 16 bytes of input
L_AES_XTS_encrypt_aesni_enc_16:
        lea	rcx, QWORD PTR [rdi+r13]
        movdqu	xmm8, OWORD PTR [rcx]
        pxor	xmm8, xmm0
        ; aes_enc_block
        pxor	xmm8, [r8]
        movdqu	xmm5, OWORD PTR [r8+16]
        aesenc	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r8+32]
        aesenc	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r8+48]
        aesenc	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r8+64]
        aesenc	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r8+80]
        aesenc	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r8+96]
        aesenc	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r8+112]
        aesenc	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r8+128]
        aesenc	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r8+144]
        aesenc	xmm8, xmm5
        cmp	r10d, 11
        movdqu	xmm5, OWORD PTR [r8+160]
        jl	L_AES_XTS_encrypt_aesni_aes_enc_block_last
        aesenc	xmm8, xmm5
        movdqu	xmm6, OWORD PTR [r8+176]
        aesenc	xmm8, xmm6
        cmp	r10d, 13
        movdqu	xmm5, OWORD PTR [r8+192]
        jl	L_AES_XTS_encrypt_aesni_aes_enc_block_last
        aesenc	xmm8, xmm5
        movdqu	xmm6, OWORD PTR [r8+208]
        aesenc	xmm8, xmm6
        movdqu	xmm5, OWORD PTR [r8+224]
L_AES_XTS_encrypt_aesni_aes_enc_block_last:
        aesenclast	xmm8, xmm5
        pxor	xmm8, xmm0
        lea	rcx, QWORD PTR [rsi+r13]
        movdqu	OWORD PTR [rcx], xmm8
        movdqa	xmm4, xmm0
        psrad	xmm4, 31
        pslld	xmm0, 1
        pshufd	xmm4, xmm4, 147
        pand	xmm4, xmm12
        pxor	xmm0, xmm4
        add	r13d, 16
        cmp	r13d, r11d
        jl	L_AES_XTS_encrypt_aesni_enc_16
        cmp	r13d, eax
        je	L_AES_XTS_encrypt_aesni_done_enc
L_AES_XTS_encrypt_aesni_last_15:
        sub	r13, 16
        lea	rcx, QWORD PTR [rsi+r13]
        movdqu	xmm8, OWORD PTR [rcx]
        add	r13, 16
        movdqu	OWORD PTR [rsp], xmm8
        xor	rdx, rdx
L_AES_XTS_encrypt_aesni_last_15_byte_loop:
        mov	r11b, BYTE PTR [rsp+rdx]
        mov	cl, BYTE PTR [rdi+r13]
        mov	BYTE PTR [rsi+r13], r11b
        mov	BYTE PTR [rsp+rdx], cl
        inc	r13d
        inc	edx
        cmp	r13d, eax
        jl	L_AES_XTS_encrypt_aesni_last_15_byte_loop
        sub	r13, rdx
        movdqu	xmm8, OWORD PTR [rsp]
        sub	r13, 16
        pxor	xmm8, xmm0
        ; aes_enc_block
        pxor	xmm8, [r8]
        movdqu	xmm5, OWORD PTR [r8+16]
        aesenc	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r8+32]
        aesenc	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r8+48]
        aesenc	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r8+64]
        aesenc	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r8+80]
        aesenc	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r8+96]
        aesenc	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r8+112]
        aesenc	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r8+128]
        aesenc	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r8+144]
        aesenc	xmm8, xmm5
        cmp	r10d, 11
        movdqu	xmm5, OWORD PTR [r8+160]
        jl	L_AES_XTS_encrypt_aesni_last_15_aes_enc_block_last
        aesenc	xmm8, xmm5
        movdqu	xmm6, OWORD PTR [r8+176]
        aesenc	xmm8, xmm6
        cmp	r10d, 13
        movdqu	xmm5, OWORD PTR [r8+192]
        jl	L_AES_XTS_encrypt_aesni_last_15_aes_enc_block_last
        aesenc	xmm8, xmm5
        movdqu	xmm6, OWORD PTR [r8+208]
        aesenc	xmm8, xmm6
        movdqu	xmm5, OWORD PTR [r8+224]
L_AES_XTS_encrypt_aesni_last_15_aes_enc_block_last:
        aesenclast	xmm8, xmm5
        pxor	xmm8, xmm0
        lea	rcx, QWORD PTR [rsi+r13]
        movdqu	OWORD PTR [rcx], xmm8
L_AES_XTS_encrypt_aesni_done_enc:
        movdqu	xmm6, OWORD PTR [rsp+64]
        movdqu	xmm7, OWORD PTR [rsp+80]
        movdqu	xmm8, OWORD PTR [rsp+96]
        movdqu	xmm9, OWORD PTR [rsp+112]
        movdqu	xmm10, OWORD PTR [rsp+128]
        movdqu	xmm11, OWORD PTR [rsp+144]
        movdqu	xmm12, OWORD PTR [rsp+160]
        add	rsp, 176
        pop	r13
        pop	r12
        pop	rsi
        pop	rdi
        ret
AES_XTS_encrypt_aesni ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_XTS_encrypt_update_aesni PROC
        push	rdi
        push	rsi
        push	r12
        mov	rdi, rcx
        mov	rsi, rdx
        mov	rax, r8
        mov	r10, r9
        mov	r8, QWORD PTR [rsp+64]
        mov	r9d, DWORD PTR [rsp+72]
        sub	rsp, 176
        movdqu	OWORD PTR [rsp+64], xmm6
        movdqu	OWORD PTR [rsp+80], xmm7
        movdqu	OWORD PTR [rsp+96], xmm8
        movdqu	OWORD PTR [rsp+112], xmm9
        movdqu	OWORD PTR [rsp+128], xmm10
        movdqu	OWORD PTR [rsp+144], xmm11
        movdqu	OWORD PTR [rsp+160], xmm12
        movdqu	xmm12, OWORD PTR L_aes_xts_gc_xts
        movdqu	xmm0, OWORD PTR [r8]
        xor	r12d, r12d
        cmp	eax, 64
        mov	r11d, eax
        jl	L_AES_XTS_encrypt_update_aesni_done_64
        and	r11d, 4294967232
L_AES_XTS_encrypt_update_aesni_enc_64:
        ; 64 bytes of input
        ; aes_enc_64
        lea	rcx, QWORD PTR [rdi+r12]
        lea	rdx, QWORD PTR [rsi+r12]
        movdqu	xmm8, OWORD PTR [rcx]
        movdqu	xmm9, OWORD PTR [rcx+16]
        movdqu	xmm10, OWORD PTR [rcx+32]
        movdqu	xmm11, OWORD PTR [rcx+48]
        movdqa	xmm4, xmm0
        movdqa	xmm1, xmm0
        psrad	xmm4, 31
        pslld	xmm1, 1
        pshufd	xmm4, xmm4, 147
        pand	xmm4, xmm12
        pxor	xmm1, xmm4
        movdqa	xmm4, xmm1
        movdqa	xmm2, xmm1
        psrad	xmm4, 31
        pslld	xmm2, 1
        pshufd	xmm4, xmm4, 147
        pand	xmm4, xmm12
        pxor	xmm2, xmm4
        movdqa	xmm4, xmm2
        movdqa	xmm3, xmm2
        psrad	xmm4, 31
        pslld	xmm3, 1
        pshufd	xmm4, xmm4, 147
        pand	xmm4, xmm12
        pxor	xmm3, xmm4
        pxor	xmm8, xmm0
        pxor	xmm9, xmm1
        pxor	xmm10, xmm2
        pxor	xmm11, xmm3
        ; aes_enc_block
        movdqu	xmm4, OWORD PTR [r10]
        pxor	xmm8, xmm4
        pxor	xmm9, xmm4
        pxor	xmm10, xmm4
        pxor	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r10+16]
        aesenc	xmm8, xmm4
        aesenc	xmm9, xmm4
        aesenc	xmm10, xmm4
        aesenc	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r10+32]
        aesenc	xmm8, xmm4
        aesenc	xmm9, xmm4
        aesenc	xmm10, xmm4
        aesenc	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r10+48]
        aesenc	xmm8, xmm4
        aesenc	xmm9, xmm4
        aesenc	xmm10, xmm4
        aesenc	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r10+64]
        aesenc	xmm8, xmm4
        aesenc	xmm9, xmm4
        aesenc	xmm10, xmm4
        aesenc	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r10+80]
        aesenc	xmm8, xmm4
        aesenc	xmm9, xmm4
        aesenc	xmm10, xmm4
        aesenc	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r10+96]
        aesenc	xmm8, xmm4
        aesenc	xmm9, xmm4
        aesenc	xmm10, xmm4
        aesenc	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r10+112]
        aesenc	xmm8, xmm4
        aesenc	xmm9, xmm4
        aesenc	xmm10, xmm4
        aesenc	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r10+128]
        aesenc	xmm8, xmm4
        aesenc	xmm9, xmm4
        aesenc	xmm10, xmm4
        aesenc	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r10+144]
        aesenc	xmm8, xmm4
        aesenc	xmm9, xmm4
        aesenc	xmm10, xmm4
        aesenc	xmm11, xmm4
        cmp	r9d, 11
        movdqu	xmm4, OWORD PTR [r10+160]
        jl	L_AES_XTS_encrypt_update_aesni_aes_enc_64_aes_enc_block_last
        aesenc	xmm8, xmm4
        aesenc	xmm9, xmm4
        aesenc	xmm10, xmm4
        aesenc	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r10+176]
        aesenc	xmm8, xmm4
        aesenc	xmm9, xmm4
        aesenc	xmm10, xmm4
        aesenc	xmm11, xmm4
        cmp	r9d, 13
        movdqu	xmm4, OWORD PTR [r10+192]
        jl	L_AES_XTS_encrypt_update_aesni_aes_enc_64_aes_enc_block_last
        aesenc	xmm8, xmm4
        aesenc	xmm9, xmm4
        aesenc	xmm10, xmm4
        aesenc	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r10+208]
        aesenc	xmm8, xmm4
        aesenc	xmm9, xmm4
        aesenc	xmm10, xmm4
        aesenc	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r10+224]
L_AES_XTS_encrypt_update_aesni_aes_enc_64_aes_enc_block_last:
        aesenclast	xmm8, xmm4
        aesenclast	xmm9, xmm4
        aesenclast	xmm10, xmm4
        aesenclast	xmm11, xmm4
        pxor	xmm8, xmm0
        pxor	xmm9, xmm1
        pxor	xmm10, xmm2
        pxor	xmm11, xmm3
        movdqu	OWORD PTR [rdx], xmm8
        movdqu	OWORD PTR [rdx+16], xmm9
        movdqu	OWORD PTR [rdx+32], xmm10
        movdqu	OWORD PTR [rdx+48], xmm11
        movdqa	xmm4, xmm3
        movdqa	xmm0, xmm3
        psrad	xmm4, 31
        pslld	xmm0, 1
        pshufd	xmm4, xmm4, 147
        pand	xmm4, xmm12
        pxor	xmm0, xmm4
        add	r12d, 64
        cmp	r12d, r11d
        jl	L_AES_XTS_encrypt_update_aesni_enc_64
L_AES_XTS_encrypt_update_aesni_done_64:
        cmp	r12d, eax
        mov	r11d, eax
        je	L_AES_XTS_encrypt_update_aesni_done_enc
        sub	r11d, r12d
        cmp	r11d, 16
        mov	r11d, eax
        jl	L_AES_XTS_encrypt_update_aesni_last_15
        and	r11d, 4294967280
        ; 16 bytes of input
L_AES_XTS_encrypt_update_aesni_enc_16:
        lea	rcx, QWORD PTR [rdi+r12]
        movdqu	xmm8, OWORD PTR [rcx]
        pxor	xmm8, xmm0
        ; aes_enc_block
        pxor	xmm8, [r10]
        movdqu	xmm5, OWORD PTR [r10+16]
        aesenc	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r10+32]
        aesenc	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r10+48]
        aesenc	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r10+64]
        aesenc	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r10+80]
        aesenc	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r10+96]
        aesenc	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r10+112]
        aesenc	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r10+128]
        aesenc	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r10+144]
        aesenc	xmm8, xmm5
        cmp	r9d, 11
        movdqu	xmm5, OWORD PTR [r10+160]
        jl	L_AES_XTS_encrypt_update_aesni_aes_enc_block_last
        aesenc	xmm8, xmm5
        movdqu	xmm6, OWORD PTR [r10+176]
        aesenc	xmm8, xmm6
        cmp	r9d, 13
        movdqu	xmm5, OWORD PTR [r10+192]
        jl	L_AES_XTS_encrypt_update_aesni_aes_enc_block_last
        aesenc	xmm8, xmm5
        movdqu	xmm6, OWORD PTR [r10+208]
        aesenc	xmm8, xmm6
        movdqu	xmm5, OWORD PTR [r10+224]
L_AES_XTS_encrypt_update_aesni_aes_enc_block_last:
        aesenclast	xmm8, xmm5
        pxor	xmm8, xmm0
        lea	rcx, QWORD PTR [rsi+r12]
        movdqu	OWORD PTR [rcx], xmm8
        movdqa	xmm4, xmm0
        psrad	xmm4, 31
        pslld	xmm0, 1
        pshufd	xmm4, xmm4, 147
        pand	xmm4, xmm12
        pxor	xmm0, xmm4
        add	r12d, 16
        cmp	r12d, r11d
        jl	L_AES_XTS_encrypt_update_aesni_enc_16
        cmp	r12d, eax
        je	L_AES_XTS_encrypt_update_aesni_done_enc
L_AES_XTS_encrypt_update_aesni_last_15:
        sub	r12, 16
        lea	rcx, QWORD PTR [rsi+r12]
        movdqu	xmm8, OWORD PTR [rcx]
        add	r12, 16
        movdqu	OWORD PTR [rsp], xmm8
        xor	rdx, rdx
L_AES_XTS_encrypt_update_aesni_last_15_byte_loop:
        mov	r11b, BYTE PTR [rsp+rdx]
        mov	cl, BYTE PTR [rdi+r12]
        mov	BYTE PTR [rsi+r12], r11b
        mov	BYTE PTR [rsp+rdx], cl
        inc	r12d
        inc	edx
        cmp	r12d, eax
        jl	L_AES_XTS_encrypt_update_aesni_last_15_byte_loop
        sub	r12, rdx
        movdqu	xmm8, OWORD PTR [rsp]
        sub	r12, 16
        pxor	xmm8, xmm0
        ; aes_enc_block
        pxor	xmm8, [r10]
        movdqu	xmm5, OWORD PTR [r10+16]
        aesenc	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r10+32]
        aesenc	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r10+48]
        aesenc	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r10+64]
        aesenc	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r10+80]
        aesenc	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r10+96]
        aesenc	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r10+112]
        aesenc	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r10+128]
        aesenc	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r10+144]
        aesenc	xmm8, xmm5
        cmp	r9d, 11
        movdqu	xmm5, OWORD PTR [r10+160]
        jl	L_AES_XTS_encrypt_update_aesni_last_15_aes_enc_block_last
        aesenc	xmm8, xmm5
        movdqu	xmm6, OWORD PTR [r10+176]
        aesenc	xmm8, xmm6
        cmp	r9d, 13
        movdqu	xmm5, OWORD PTR [r10+192]
        jl	L_AES_XTS_encrypt_update_aesni_last_15_aes_enc_block_last
        aesenc	xmm8, xmm5
        movdqu	xmm6, OWORD PTR [r10+208]
        aesenc	xmm8, xmm6
        movdqu	xmm5, OWORD PTR [r10+224]
L_AES_XTS_encrypt_update_aesni_last_15_aes_enc_block_last:
        aesenclast	xmm8, xmm5
        pxor	xmm8, xmm0
        lea	rcx, QWORD PTR [rsi+r12]
        movdqu	OWORD PTR [rcx], xmm8
L_AES_XTS_encrypt_update_aesni_done_enc:
        movdqu	OWORD PTR [r8], xmm0
        movdqu	xmm6, OWORD PTR [rsp+64]
        movdqu	xmm7, OWORD PTR [rsp+80]
        movdqu	xmm8, OWORD PTR [rsp+96]
        movdqu	xmm9, OWORD PTR [rsp+112]
        movdqu	xmm10, OWORD PTR [rsp+128]
        movdqu	xmm11, OWORD PTR [rsp+144]
        movdqu	xmm12, OWORD PTR [rsp+160]
        add	rsp, 176
        pop	r12
        pop	rsi
        pop	rdi
        ret
AES_XTS_encrypt_update_aesni ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_XTS_decrypt_aesni PROC
        push	rdi
        push	rsi
        push	r12
        push	r13
        mov	rdi, rcx
        mov	rsi, rdx
        mov	rax, r8
        mov	r12, r9
        mov	r8, QWORD PTR [rsp+72]
        mov	r9, QWORD PTR [rsp+80]
        mov	r10d, DWORD PTR [rsp+88]
        sub	rsp, 128
        movdqu	OWORD PTR [rsp+16], xmm6
        movdqu	OWORD PTR [rsp+32], xmm7
        movdqu	OWORD PTR [rsp+48], xmm8
        movdqu	OWORD PTR [rsp+64], xmm9
        movdqu	OWORD PTR [rsp+80], xmm10
        movdqu	OWORD PTR [rsp+96], xmm11
        movdqu	OWORD PTR [rsp+112], xmm12
        movdqu	xmm12, OWORD PTR L_aes_xts_gc_xts
        movdqu	xmm0, OWORD PTR [r12]
        ; aes_enc_block
        pxor	xmm0, [r9]
        movdqu	xmm5, OWORD PTR [r9+16]
        aesenc	xmm0, xmm5
        movdqu	xmm5, OWORD PTR [r9+32]
        aesenc	xmm0, xmm5
        movdqu	xmm5, OWORD PTR [r9+48]
        aesenc	xmm0, xmm5
        movdqu	xmm5, OWORD PTR [r9+64]
        aesenc	xmm0, xmm5
        movdqu	xmm5, OWORD PTR [r9+80]
        aesenc	xmm0, xmm5
        movdqu	xmm5, OWORD PTR [r9+96]
        aesenc	xmm0, xmm5
        movdqu	xmm5, OWORD PTR [r9+112]
        aesenc	xmm0, xmm5
        movdqu	xmm5, OWORD PTR [r9+128]
        aesenc	xmm0, xmm5
        movdqu	xmm5, OWORD PTR [r9+144]
        aesenc	xmm0, xmm5
        cmp	r10d, 11
        movdqu	xmm5, OWORD PTR [r9+160]
        jl	L_AES_XTS_decrypt_aesni_tweak_aes_enc_block_last
        aesenc	xmm0, xmm5
        movdqu	xmm6, OWORD PTR [r9+176]
        aesenc	xmm0, xmm6
        cmp	r10d, 13
        movdqu	xmm5, OWORD PTR [r9+192]
        jl	L_AES_XTS_decrypt_aesni_tweak_aes_enc_block_last
        aesenc	xmm0, xmm5
        movdqu	xmm6, OWORD PTR [r9+208]
        aesenc	xmm0, xmm6
        movdqu	xmm5, OWORD PTR [r9+224]
L_AES_XTS_decrypt_aesni_tweak_aes_enc_block_last:
        aesenclast	xmm0, xmm5
        xor	r13d, r13d
        mov	r11d, eax
        and	r11d, 4294967280
        cmp	r11d, eax
        je	L_AES_XTS_decrypt_aesni_mul16_64
        sub	r11d, 16
        cmp	r11d, 16
        jl	L_AES_XTS_decrypt_aesni_last_31_start
L_AES_XTS_decrypt_aesni_mul16_64:
        cmp	r11d, 64
        jl	L_AES_XTS_decrypt_aesni_done_64
        and	r11d, 4294967232
L_AES_XTS_decrypt_aesni_dec_64:
        ; 64 bytes of input
        ; aes_dec_64
        lea	rcx, QWORD PTR [rdi+r13]
        lea	rdx, QWORD PTR [rsi+r13]
        movdqu	xmm8, OWORD PTR [rcx]
        movdqu	xmm9, OWORD PTR [rcx+16]
        movdqu	xmm10, OWORD PTR [rcx+32]
        movdqu	xmm11, OWORD PTR [rcx+48]
        movdqa	xmm4, xmm0
        movdqa	xmm1, xmm0
        psrad	xmm4, 31
        pslld	xmm1, 1
        pshufd	xmm4, xmm4, 147
        pand	xmm4, xmm12
        pxor	xmm1, xmm4
        movdqa	xmm4, xmm1
        movdqa	xmm2, xmm1
        psrad	xmm4, 31
        pslld	xmm2, 1
        pshufd	xmm4, xmm4, 147
        pand	xmm4, xmm12
        pxor	xmm2, xmm4
        movdqa	xmm4, xmm2
        movdqa	xmm3, xmm2
        psrad	xmm4, 31
        pslld	xmm3, 1
        pshufd	xmm4, xmm4, 147
        pand	xmm4, xmm12
        pxor	xmm3, xmm4
        pxor	xmm8, xmm0
        pxor	xmm9, xmm1
        pxor	xmm10, xmm2
        pxor	xmm11, xmm3
        ; aes_dec_block
        movdqu	xmm4, OWORD PTR [r8]
        pxor	xmm8, xmm4
        pxor	xmm9, xmm4
        pxor	xmm10, xmm4
        pxor	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r8+16]
        aesdec	xmm8, xmm4
        aesdec	xmm9, xmm4
        aesdec	xmm10, xmm4
        aesdec	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r8+32]
        aesdec	xmm8, xmm4
        aesdec	xmm9, xmm4
        aesdec	xmm10, xmm4
        aesdec	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r8+48]
        aesdec	xmm8, xmm4
        aesdec	xmm9, xmm4
        aesdec	xmm10, xmm4
        aesdec	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r8+64]
        aesdec	xmm8, xmm4
        aesdec	xmm9, xmm4
        aesdec	xmm10, xmm4
        aesdec	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r8+80]
        aesdec	xmm8, xmm4
        aesdec	xmm9, xmm4
        aesdec	xmm10, xmm4
        aesdec	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r8+96]
        aesdec	xmm8, xmm4
        aesdec	xmm9, xmm4
        aesdec	xmm10, xmm4
        aesdec	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r8+112]
        aesdec	xmm8, xmm4
        aesdec	xmm9, xmm4
        aesdec	xmm10, xmm4
        aesdec	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r8+128]
        aesdec	xmm8, xmm4
        aesdec	xmm9, xmm4
        aesdec	xmm10, xmm4
        aesdec	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r8+144]
        aesdec	xmm8, xmm4
        aesdec	xmm9, xmm4
        aesdec	xmm10, xmm4
        aesdec	xmm11, xmm4
        cmp	r10d, 11
        movdqu	xmm4, OWORD PTR [r8+160]
        jl	L_AES_XTS_decrypt_aesni_aes_dec_64_aes_dec_block_last
        aesdec	xmm8, xmm4
        aesdec	xmm9, xmm4
        aesdec	xmm10, xmm4
        aesdec	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r8+176]
        aesdec	xmm8, xmm4
        aesdec	xmm9, xmm4
        aesdec	xmm10, xmm4
        aesdec	xmm11, xmm4
        cmp	r10d, 13
        movdqu	xmm4, OWORD PTR [r8+192]
        jl	L_AES_XTS_decrypt_aesni_aes_dec_64_aes_dec_block_last
        aesdec	xmm8, xmm4
        aesdec	xmm9, xmm4
        aesdec	xmm10, xmm4
        aesdec	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r8+208]
        aesdec	xmm8, xmm4
        aesdec	xmm9, xmm4
        aesdec	xmm10, xmm4
        aesdec	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r8+224]
L_AES_XTS_decrypt_aesni_aes_dec_64_aes_dec_block_last:
        aesdeclast	xmm8, xmm4
        aesdeclast	xmm9, xmm4
        aesdeclast	xmm10, xmm4
        aesdeclast	xmm11, xmm4
        pxor	xmm8, xmm0
        pxor	xmm9, xmm1
        pxor	xmm10, xmm2
        pxor	xmm11, xmm3
        movdqu	OWORD PTR [rdx], xmm8
        movdqu	OWORD PTR [rdx+16], xmm9
        movdqu	OWORD PTR [rdx+32], xmm10
        movdqu	OWORD PTR [rdx+48], xmm11
        movdqa	xmm4, xmm3
        movdqa	xmm0, xmm3
        psrad	xmm4, 31
        pslld	xmm0, 1
        pshufd	xmm4, xmm4, 147
        pand	xmm4, xmm12
        pxor	xmm0, xmm4
        add	r13d, 64
        cmp	r13d, r11d
        jl	L_AES_XTS_decrypt_aesni_dec_64
L_AES_XTS_decrypt_aesni_done_64:
        cmp	r13d, eax
        mov	r11d, eax
        je	L_AES_XTS_decrypt_aesni_done_dec
        and	r11d, 4294967280
        cmp	r11d, eax
        je	L_AES_XTS_decrypt_aesni_mul16
        sub	r11d, 16
        sub	r11d, r13d
        cmp	r11d, 16
        jl	L_AES_XTS_decrypt_aesni_last_31_start
        add	r11d, r13d
L_AES_XTS_decrypt_aesni_mul16:
L_AES_XTS_decrypt_aesni_dec_16:
        ; 16 bytes of input
        lea	rcx, QWORD PTR [rdi+r13]
        movdqu	xmm8, OWORD PTR [rcx]
        pxor	xmm8, xmm0
        ; aes_dec_block
        pxor	xmm8, [r8]
        movdqu	xmm5, OWORD PTR [r8+16]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r8+32]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r8+48]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r8+64]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r8+80]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r8+96]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r8+112]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r8+128]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r8+144]
        aesdec	xmm8, xmm5
        cmp	r10d, 11
        movdqu	xmm5, OWORD PTR [r8+160]
        jl	L_AES_XTS_decrypt_aesni_aes_dec_block_last
        aesdec	xmm8, xmm5
        movdqu	xmm6, OWORD PTR [r8+176]
        aesdec	xmm8, xmm6
        cmp	r10d, 13
        movdqu	xmm5, OWORD PTR [r8+192]
        jl	L_AES_XTS_decrypt_aesni_aes_dec_block_last
        aesdec	xmm8, xmm5
        movdqu	xmm6, OWORD PTR [r8+208]
        aesdec	xmm8, xmm6
        movdqu	xmm5, OWORD PTR [r8+224]
L_AES_XTS_decrypt_aesni_aes_dec_block_last:
        aesdeclast	xmm8, xmm5
        pxor	xmm8, xmm0
        lea	rcx, QWORD PTR [rsi+r13]
        movdqu	OWORD PTR [rcx], xmm8
        movdqa	xmm4, xmm0
        psrad	xmm4, 31
        pslld	xmm0, 1
        pshufd	xmm4, xmm4, 147
        pand	xmm4, xmm12
        pxor	xmm0, xmm4
        add	r13d, 16
        cmp	r13d, r11d
        jl	L_AES_XTS_decrypt_aesni_dec_16
        cmp	r13d, eax
        je	L_AES_XTS_decrypt_aesni_done_dec
L_AES_XTS_decrypt_aesni_last_31_start:
        movdqa	xmm4, xmm0
        movdqa	xmm7, xmm0
        psrad	xmm4, 31
        pslld	xmm7, 1
        pshufd	xmm4, xmm4, 147
        pand	xmm4, xmm12
        pxor	xmm7, xmm4
        lea	rcx, QWORD PTR [rdi+r13]
        movdqu	xmm8, OWORD PTR [rcx]
        pxor	xmm8, xmm7
        ; aes_dec_block
        pxor	xmm8, [r8]
        movdqu	xmm5, OWORD PTR [r8+16]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r8+32]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r8+48]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r8+64]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r8+80]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r8+96]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r8+112]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r8+128]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r8+144]
        aesdec	xmm8, xmm5
        cmp	r10d, 11
        movdqu	xmm5, OWORD PTR [r8+160]
        jl	L_AES_XTS_decrypt_aesni_last_31_aes_dec_block_last
        aesdec	xmm8, xmm5
        movdqu	xmm6, OWORD PTR [r8+176]
        aesdec	xmm8, xmm6
        cmp	r10d, 13
        movdqu	xmm5, OWORD PTR [r8+192]
        jl	L_AES_XTS_decrypt_aesni_last_31_aes_dec_block_last
        aesdec	xmm8, xmm5
        movdqu	xmm6, OWORD PTR [r8+208]
        aesdec	xmm8, xmm6
        movdqu	xmm5, OWORD PTR [r8+224]
L_AES_XTS_decrypt_aesni_last_31_aes_dec_block_last:
        aesdeclast	xmm8, xmm5
        pxor	xmm8, xmm7
        movdqu	OWORD PTR [rsp], xmm8
        add	r13, 16
        xor	rdx, rdx
L_AES_XTS_decrypt_aesni_last_31_byte_loop:
        mov	r11b, BYTE PTR [rsp+rdx]
        mov	cl, BYTE PTR [rdi+r13]
        mov	BYTE PTR [rsi+r13], r11b
        mov	BYTE PTR [rsp+rdx], cl
        inc	r13d
        inc	edx
        cmp	r13d, eax
        jl	L_AES_XTS_decrypt_aesni_last_31_byte_loop
        sub	r13, rdx
        movdqu	xmm8, OWORD PTR [rsp]
        pxor	xmm8, xmm0
        ; aes_dec_block
        pxor	xmm8, [r8]
        movdqu	xmm5, OWORD PTR [r8+16]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r8+32]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r8+48]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r8+64]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r8+80]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r8+96]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r8+112]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r8+128]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r8+144]
        aesdec	xmm8, xmm5
        cmp	r10d, 11
        movdqu	xmm5, OWORD PTR [r8+160]
        jl	L_AES_XTS_decrypt_aesni_last_31_2_aes_dec_block_last
        aesdec	xmm8, xmm5
        movdqu	xmm6, OWORD PTR [r8+176]
        aesdec	xmm8, xmm6
        cmp	r10d, 13
        movdqu	xmm5, OWORD PTR [r8+192]
        jl	L_AES_XTS_decrypt_aesni_last_31_2_aes_dec_block_last
        aesdec	xmm8, xmm5
        movdqu	xmm6, OWORD PTR [r8+208]
        aesdec	xmm8, xmm6
        movdqu	xmm5, OWORD PTR [r8+224]
L_AES_XTS_decrypt_aesni_last_31_2_aes_dec_block_last:
        aesdeclast	xmm8, xmm5
        pxor	xmm8, xmm0
        sub	r13, 16
        lea	rcx, QWORD PTR [rsi+r13]
        movdqu	OWORD PTR [rcx], xmm8
L_AES_XTS_decrypt_aesni_done_dec:
        movdqu	xmm6, OWORD PTR [rsp+16]
        movdqu	xmm7, OWORD PTR [rsp+32]
        movdqu	xmm8, OWORD PTR [rsp+48]
        movdqu	xmm9, OWORD PTR [rsp+64]
        movdqu	xmm10, OWORD PTR [rsp+80]
        movdqu	xmm11, OWORD PTR [rsp+96]
        movdqu	xmm12, OWORD PTR [rsp+112]
        add	rsp, 128
        pop	r13
        pop	r12
        pop	rsi
        pop	rdi
        ret
AES_XTS_decrypt_aesni ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_XTS_decrypt_update_aesni PROC
        push	rdi
        push	rsi
        push	r12
        mov	rdi, rcx
        mov	rsi, rdx
        mov	rax, r8
        mov	r10, r9
        mov	r8, QWORD PTR [rsp+64]
        mov	r9d, DWORD PTR [rsp+72]
        sub	rsp, 128
        movdqu	OWORD PTR [rsp+16], xmm6
        movdqu	OWORD PTR [rsp+32], xmm7
        movdqu	OWORD PTR [rsp+48], xmm8
        movdqu	OWORD PTR [rsp+64], xmm9
        movdqu	OWORD PTR [rsp+80], xmm10
        movdqu	OWORD PTR [rsp+96], xmm11
        movdqu	OWORD PTR [rsp+112], xmm12
        movdqu	xmm12, OWORD PTR L_aes_xts_gc_xts
        movdqu	xmm0, OWORD PTR [r8]
        xor	r12d, r12d
        mov	r11d, eax
        and	r11d, 4294967280
        cmp	r11d, eax
        je	L_AES_XTS_decrypt_update_aesni_mul16_64
        sub	r11d, 16
        cmp	r11d, 16
        jl	L_AES_XTS_decrypt_update_aesni_last_31_start
L_AES_XTS_decrypt_update_aesni_mul16_64:
        cmp	r11d, 64
        jl	L_AES_XTS_decrypt_update_aesni_done_64
        and	r11d, 4294967232
L_AES_XTS_decrypt_update_aesni_dec_64:
        ; 64 bytes of input
        ; aes_dec_64
        lea	rcx, QWORD PTR [rdi+r12]
        lea	rdx, QWORD PTR [rsi+r12]
        movdqu	xmm8, OWORD PTR [rcx]
        movdqu	xmm9, OWORD PTR [rcx+16]
        movdqu	xmm10, OWORD PTR [rcx+32]
        movdqu	xmm11, OWORD PTR [rcx+48]
        movdqa	xmm4, xmm0
        movdqa	xmm1, xmm0
        psrad	xmm4, 31
        pslld	xmm1, 1
        pshufd	xmm4, xmm4, 147
        pand	xmm4, xmm12
        pxor	xmm1, xmm4
        movdqa	xmm4, xmm1
        movdqa	xmm2, xmm1
        psrad	xmm4, 31
        pslld	xmm2, 1
        pshufd	xmm4, xmm4, 147
        pand	xmm4, xmm12
        pxor	xmm2, xmm4
        movdqa	xmm4, xmm2
        movdqa	xmm3, xmm2
        psrad	xmm4, 31
        pslld	xmm3, 1
        pshufd	xmm4, xmm4, 147
        pand	xmm4, xmm12
        pxor	xmm3, xmm4
        pxor	xmm8, xmm0
        pxor	xmm9, xmm1
        pxor	xmm10, xmm2
        pxor	xmm11, xmm3
        ; aes_dec_block
        movdqu	xmm4, OWORD PTR [r10]
        pxor	xmm8, xmm4
        pxor	xmm9, xmm4
        pxor	xmm10, xmm4
        pxor	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r10+16]
        aesdec	xmm8, xmm4
        aesdec	xmm9, xmm4
        aesdec	xmm10, xmm4
        aesdec	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r10+32]
        aesdec	xmm8, xmm4
        aesdec	xmm9, xmm4
        aesdec	xmm10, xmm4
        aesdec	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r10+48]
        aesdec	xmm8, xmm4
        aesdec	xmm9, xmm4
        aesdec	xmm10, xmm4
        aesdec	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r10+64]
        aesdec	xmm8, xmm4
        aesdec	xmm9, xmm4
        aesdec	xmm10, xmm4
        aesdec	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r10+80]
        aesdec	xmm8, xmm4
        aesdec	xmm9, xmm4
        aesdec	xmm10, xmm4
        aesdec	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r10+96]
        aesdec	xmm8, xmm4
        aesdec	xmm9, xmm4
        aesdec	xmm10, xmm4
        aesdec	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r10+112]
        aesdec	xmm8, xmm4
        aesdec	xmm9, xmm4
        aesdec	xmm10, xmm4
        aesdec	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r10+128]
        aesdec	xmm8, xmm4
        aesdec	xmm9, xmm4
        aesdec	xmm10, xmm4
        aesdec	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r10+144]
        aesdec	xmm8, xmm4
        aesdec	xmm9, xmm4
        aesdec	xmm10, xmm4
        aesdec	xmm11, xmm4
        cmp	r9d, 11
        movdqu	xmm4, OWORD PTR [r10+160]
        jl	L_AES_XTS_decrypt_update_aesni_aes_dec_64_aes_dec_block_last
        aesdec	xmm8, xmm4
        aesdec	xmm9, xmm4
        aesdec	xmm10, xmm4
        aesdec	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r10+176]
        aesdec	xmm8, xmm4
        aesdec	xmm9, xmm4
        aesdec	xmm10, xmm4
        aesdec	xmm11, xmm4
        cmp	r9d, 13
        movdqu	xmm4, OWORD PTR [r10+192]
        jl	L_AES_XTS_decrypt_update_aesni_aes_dec_64_aes_dec_block_last
        aesdec	xmm8, xmm4
        aesdec	xmm9, xmm4
        aesdec	xmm10, xmm4
        aesdec	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r10+208]
        aesdec	xmm8, xmm4
        aesdec	xmm9, xmm4
        aesdec	xmm10, xmm4
        aesdec	xmm11, xmm4
        movdqu	xmm4, OWORD PTR [r10+224]
L_AES_XTS_decrypt_update_aesni_aes_dec_64_aes_dec_block_last:
        aesdeclast	xmm8, xmm4
        aesdeclast	xmm9, xmm4
        aesdeclast	xmm10, xmm4
        aesdeclast	xmm11, xmm4
        pxor	xmm8, xmm0
        pxor	xmm9, xmm1
        pxor	xmm10, xmm2
        pxor	xmm11, xmm3
        movdqu	OWORD PTR [rdx], xmm8
        movdqu	OWORD PTR [rdx+16], xmm9
        movdqu	OWORD PTR [rdx+32], xmm10
        movdqu	OWORD PTR [rdx+48], xmm11
        movdqa	xmm4, xmm3
        movdqa	xmm0, xmm3
        psrad	xmm4, 31
        pslld	xmm0, 1
        pshufd	xmm4, xmm4, 147
        pand	xmm4, xmm12
        pxor	xmm0, xmm4
        add	r12d, 64
        cmp	r12d, r11d
        jl	L_AES_XTS_decrypt_update_aesni_dec_64
L_AES_XTS_decrypt_update_aesni_done_64:
        cmp	r12d, eax
        mov	r11d, eax
        je	L_AES_XTS_decrypt_update_aesni_done_dec
        and	r11d, 4294967280
        cmp	r11d, eax
        je	L_AES_XTS_decrypt_update_aesni_mul16
        sub	r11d, 16
        sub	r11d, r12d
        cmp	r11d, 16
        jl	L_AES_XTS_decrypt_update_aesni_last_31_start
        add	r11d, r12d
L_AES_XTS_decrypt_update_aesni_mul16:
L_AES_XTS_decrypt_update_aesni_dec_16:
        ; 16 bytes of input
        lea	rcx, QWORD PTR [rdi+r12]
        movdqu	xmm8, OWORD PTR [rcx]
        pxor	xmm8, xmm0
        ; aes_dec_block
        pxor	xmm8, [r10]
        movdqu	xmm5, OWORD PTR [r10+16]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r10+32]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r10+48]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r10+64]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r10+80]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r10+96]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r10+112]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r10+128]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r10+144]
        aesdec	xmm8, xmm5
        cmp	r9d, 11
        movdqu	xmm5, OWORD PTR [r10+160]
        jl	L_AES_XTS_decrypt_update_aesni_aes_dec_block_last
        aesdec	xmm8, xmm5
        movdqu	xmm6, OWORD PTR [r10+176]
        aesdec	xmm8, xmm6
        cmp	r9d, 13
        movdqu	xmm5, OWORD PTR [r10+192]
        jl	L_AES_XTS_decrypt_update_aesni_aes_dec_block_last
        aesdec	xmm8, xmm5
        movdqu	xmm6, OWORD PTR [r10+208]
        aesdec	xmm8, xmm6
        movdqu	xmm5, OWORD PTR [r10+224]
L_AES_XTS_decrypt_update_aesni_aes_dec_block_last:
        aesdeclast	xmm8, xmm5
        pxor	xmm8, xmm0
        lea	rcx, QWORD PTR [rsi+r12]
        movdqu	OWORD PTR [rcx], xmm8
        movdqa	xmm4, xmm0
        psrad	xmm4, 31
        pslld	xmm0, 1
        pshufd	xmm4, xmm4, 147
        pand	xmm4, xmm12
        pxor	xmm0, xmm4
        add	r12d, 16
        cmp	r12d, r11d
        jl	L_AES_XTS_decrypt_update_aesni_dec_16
        cmp	r12d, eax
        je	L_AES_XTS_decrypt_update_aesni_done_dec
L_AES_XTS_decrypt_update_aesni_last_31_start:
        movdqa	xmm4, xmm0
        movdqa	xmm7, xmm0
        psrad	xmm4, 31
        pslld	xmm7, 1
        pshufd	xmm4, xmm4, 147
        pand	xmm4, xmm12
        pxor	xmm7, xmm4
        lea	rcx, QWORD PTR [rdi+r12]
        movdqu	xmm8, OWORD PTR [rcx]
        pxor	xmm8, xmm7
        ; aes_dec_block
        pxor	xmm8, [r10]
        movdqu	xmm5, OWORD PTR [r10+16]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r10+32]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r10+48]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r10+64]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r10+80]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r10+96]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r10+112]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r10+128]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r10+144]
        aesdec	xmm8, xmm5
        cmp	r9d, 11
        movdqu	xmm5, OWORD PTR [r10+160]
        jl	L_AES_XTS_decrypt_update_aesni_last_31_aes_dec_block_last
        aesdec	xmm8, xmm5
        movdqu	xmm6, OWORD PTR [r10+176]
        aesdec	xmm8, xmm6
        cmp	r9d, 13
        movdqu	xmm5, OWORD PTR [r10+192]
        jl	L_AES_XTS_decrypt_update_aesni_last_31_aes_dec_block_last
        aesdec	xmm8, xmm5
        movdqu	xmm6, OWORD PTR [r10+208]
        aesdec	xmm8, xmm6
        movdqu	xmm5, OWORD PTR [r10+224]
L_AES_XTS_decrypt_update_aesni_last_31_aes_dec_block_last:
        aesdeclast	xmm8, xmm5
        pxor	xmm8, xmm7
        movdqu	OWORD PTR [rsp], xmm8
        add	r12, 16
        xor	rdx, rdx
L_AES_XTS_decrypt_update_aesni_last_31_byte_loop:
        mov	r11b, BYTE PTR [rsp+rdx]
        mov	cl, BYTE PTR [rdi+r12]
        mov	BYTE PTR [rsi+r12], r11b
        mov	BYTE PTR [rsp+rdx], cl
        inc	r12d
        inc	edx
        cmp	r12d, eax
        jl	L_AES_XTS_decrypt_update_aesni_last_31_byte_loop
        sub	r12, rdx
        movdqu	xmm8, OWORD PTR [rsp]
        pxor	xmm8, xmm0
        ; aes_dec_block
        pxor	xmm8, [r10]
        movdqu	xmm5, OWORD PTR [r10+16]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r10+32]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r10+48]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r10+64]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r10+80]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r10+96]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r10+112]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r10+128]
        aesdec	xmm8, xmm5
        movdqu	xmm5, OWORD PTR [r10+144]
        aesdec	xmm8, xmm5
        cmp	r9d, 11
        movdqu	xmm5, OWORD PTR [r10+160]
        jl	L_AES_XTS_decrypt_update_aesni_last_31_2_aes_dec_block_last
        aesdec	xmm8, xmm5
        movdqu	xmm6, OWORD PTR [r10+176]
        aesdec	xmm8, xmm6
        cmp	r9d, 13
        movdqu	xmm5, OWORD PTR [r10+192]
        jl	L_AES_XTS_decrypt_update_aesni_last_31_2_aes_dec_block_last
        aesdec	xmm8, xmm5
        movdqu	xmm6, OWORD PTR [r10+208]
        aesdec	xmm8, xmm6
        movdqu	xmm5, OWORD PTR [r10+224]
L_AES_XTS_decrypt_update_aesni_last_31_2_aes_dec_block_last:
        aesdeclast	xmm8, xmm5
        pxor	xmm8, xmm0
        sub	r12, 16
        lea	rcx, QWORD PTR [rsi+r12]
        movdqu	OWORD PTR [rcx], xmm8
L_AES_XTS_decrypt_update_aesni_done_dec:
        movdqu	OWORD PTR [r8], xmm0
        movdqu	xmm6, OWORD PTR [rsp+16]
        movdqu	xmm7, OWORD PTR [rsp+32]
        movdqu	xmm8, OWORD PTR [rsp+48]
        movdqu	xmm9, OWORD PTR [rsp+64]
        movdqu	xmm10, OWORD PTR [rsp+80]
        movdqu	xmm11, OWORD PTR [rsp+96]
        movdqu	xmm12, OWORD PTR [rsp+112]
        add	rsp, 128
        pop	r12
        pop	rsi
        pop	rdi
        ret
AES_XTS_decrypt_update_aesni ENDP
_TEXT ENDS
IFDEF HAVE_INTEL_AVX1
_TEXT SEGMENT READONLY PARA
AES_XTS_init_avx1 PROC
        vmovdqu	xmm0, OWORD PTR [rcx]
        ; aes_enc_block
        vpxor	xmm0, xmm0, [rdx]
        vmovdqu	xmm2, OWORD PTR [rdx+16]
        vaesenc	xmm0, xmm0, xmm2
        vmovdqu	xmm2, OWORD PTR [rdx+32]
        vaesenc	xmm0, xmm0, xmm2
        vmovdqu	xmm2, OWORD PTR [rdx+48]
        vaesenc	xmm0, xmm0, xmm2
        vmovdqu	xmm2, OWORD PTR [rdx+64]
        vaesenc	xmm0, xmm0, xmm2
        vmovdqu	xmm2, OWORD PTR [rdx+80]
        vaesenc	xmm0, xmm0, xmm2
        vmovdqu	xmm2, OWORD PTR [rdx+96]
        vaesenc	xmm0, xmm0, xmm2
        vmovdqu	xmm2, OWORD PTR [rdx+112]
        vaesenc	xmm0, xmm0, xmm2
        vmovdqu	xmm2, OWORD PTR [rdx+128]
        vaesenc	xmm0, xmm0, xmm2
        vmovdqu	xmm2, OWORD PTR [rdx+144]
        vaesenc	xmm0, xmm0, xmm2
        cmp	r8d, 11
        vmovdqu	xmm2, OWORD PTR [rdx+160]
        jl	L_AES_XTS_init_avx1_tweak_aes_enc_block_last
        vaesenc	xmm0, xmm0, xmm2
        vmovdqu	xmm3, OWORD PTR [rdx+176]
        vaesenc	xmm0, xmm0, xmm3
        cmp	r8d, 13
        vmovdqu	xmm2, OWORD PTR [rdx+192]
        jl	L_AES_XTS_init_avx1_tweak_aes_enc_block_last
        vaesenc	xmm0, xmm0, xmm2
        vmovdqu	xmm3, OWORD PTR [rdx+208]
        vaesenc	xmm0, xmm0, xmm3
        vmovdqu	xmm2, OWORD PTR [rdx+224]
L_AES_XTS_init_avx1_tweak_aes_enc_block_last:
        vaesenclast	xmm0, xmm0, xmm2
        vmovdqu	OWORD PTR [rcx], xmm0
        ret
AES_XTS_init_avx1 ENDP
_TEXT ENDS
_DATA SEGMENT
ALIGN 16
L_avx1_aes_xts_gc_xts DWORD \
     00000087h,  00000001h,  00000001h,  00000001h
ptr_L_avx1_aes_xts_gc_xts QWORD L_avx1_aes_xts_gc_xts
_DATA ENDS
_TEXT SEGMENT READONLY PARA
AES_XTS_encrypt_avx1 PROC
        push	rdi
        push	rsi
        push	r12
        push	r13
        mov	rdi, rcx
        mov	rsi, rdx
        mov	rax, r8
        mov	r12, r9
        mov	r8, QWORD PTR [rsp+72]
        mov	r9, QWORD PTR [rsp+80]
        mov	r10d, DWORD PTR [rsp+88]
        sub	rsp, 176
        vmovdqu	OWORD PTR [rsp+64], xmm6
        vmovdqu	OWORD PTR [rsp+80], xmm7
        vmovdqu	OWORD PTR [rsp+96], xmm8
        vmovdqu	OWORD PTR [rsp+112], xmm9
        vmovdqu	OWORD PTR [rsp+128], xmm10
        vmovdqu	OWORD PTR [rsp+144], xmm11
        vmovdqu	OWORD PTR [rsp+160], xmm12
        vmovdqu	xmm12, OWORD PTR L_avx1_aes_xts_gc_xts
        vmovdqu	xmm0, OWORD PTR [r12]
        ; aes_enc_block
        vpxor	xmm0, xmm0, [r9]
        vmovdqu	xmm5, OWORD PTR [r9+16]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+32]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+48]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+64]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+80]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+96]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+112]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+128]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+144]
        vaesenc	xmm0, xmm0, xmm5
        cmp	r10d, 11
        vmovdqu	xmm5, OWORD PTR [r9+160]
        jl	L_AES_XTS_encrypt_avx1_tweak_aes_enc_block_last
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r9+176]
        vaesenc	xmm0, xmm0, xmm6
        cmp	r10d, 13
        vmovdqu	xmm5, OWORD PTR [r9+192]
        jl	L_AES_XTS_encrypt_avx1_tweak_aes_enc_block_last
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r9+208]
        vaesenc	xmm0, xmm0, xmm6
        vmovdqu	xmm5, OWORD PTR [r9+224]
L_AES_XTS_encrypt_avx1_tweak_aes_enc_block_last:
        vaesenclast	xmm0, xmm0, xmm5
        xor	r13d, r13d
        cmp	eax, 64
        mov	r11d, eax
        jl	L_AES_XTS_encrypt_avx1_done_64
        and	r11d, 4294967232
L_AES_XTS_encrypt_avx1_enc_64:
        ; 64 bytes of input
        ; aes_enc_64
        lea	rcx, QWORD PTR [rdi+r13]
        lea	rdx, QWORD PTR [rsi+r13]
        vmovdqu	xmm8, OWORD PTR [rcx]
        vmovdqu	xmm9, OWORD PTR [rcx+16]
        vmovdqu	xmm10, OWORD PTR [rcx+32]
        vmovdqu	xmm11, OWORD PTR [rcx+48]
        vpsrad	xmm4, xmm0, 31
        vpslld	xmm1, xmm0, 1
        vpshufd	xmm4, xmm4, 147
        vpand	xmm4, xmm4, xmm12
        vpxor	xmm1, xmm1, xmm4
        vpsrad	xmm4, xmm1, 31
        vpslld	xmm2, xmm1, 1
        vpshufd	xmm4, xmm4, 147
        vpand	xmm4, xmm4, xmm12
        vpxor	xmm2, xmm2, xmm4
        vpsrad	xmm4, xmm2, 31
        vpslld	xmm3, xmm2, 1
        vpshufd	xmm4, xmm4, 147
        vpand	xmm4, xmm4, xmm12
        vpxor	xmm3, xmm3, xmm4
        vpxor	xmm8, xmm8, xmm0
        vpxor	xmm9, xmm9, xmm1
        vpxor	xmm10, xmm10, xmm2
        vpxor	xmm11, xmm11, xmm3
        ; aes_enc_block
        vmovdqu	xmm4, OWORD PTR [r8]
        vpxor	xmm8, xmm8, xmm4
        vpxor	xmm9, xmm9, xmm4
        vpxor	xmm10, xmm10, xmm4
        vpxor	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r8+16]
        vaesenc	xmm8, xmm8, xmm4
        vaesenc	xmm9, xmm9, xmm4
        vaesenc	xmm10, xmm10, xmm4
        vaesenc	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r8+32]
        vaesenc	xmm8, xmm8, xmm4
        vaesenc	xmm9, xmm9, xmm4
        vaesenc	xmm10, xmm10, xmm4
        vaesenc	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r8+48]
        vaesenc	xmm8, xmm8, xmm4
        vaesenc	xmm9, xmm9, xmm4
        vaesenc	xmm10, xmm10, xmm4
        vaesenc	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r8+64]
        vaesenc	xmm8, xmm8, xmm4
        vaesenc	xmm9, xmm9, xmm4
        vaesenc	xmm10, xmm10, xmm4
        vaesenc	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r8+80]
        vaesenc	xmm8, xmm8, xmm4
        vaesenc	xmm9, xmm9, xmm4
        vaesenc	xmm10, xmm10, xmm4
        vaesenc	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r8+96]
        vaesenc	xmm8, xmm8, xmm4
        vaesenc	xmm9, xmm9, xmm4
        vaesenc	xmm10, xmm10, xmm4
        vaesenc	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r8+112]
        vaesenc	xmm8, xmm8, xmm4
        vaesenc	xmm9, xmm9, xmm4
        vaesenc	xmm10, xmm10, xmm4
        vaesenc	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r8+128]
        vaesenc	xmm8, xmm8, xmm4
        vaesenc	xmm9, xmm9, xmm4
        vaesenc	xmm10, xmm10, xmm4
        vaesenc	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r8+144]
        vaesenc	xmm8, xmm8, xmm4
        vaesenc	xmm9, xmm9, xmm4
        vaesenc	xmm10, xmm10, xmm4
        vaesenc	xmm11, xmm11, xmm4
        cmp	r10d, 11
        vmovdqu	xmm4, OWORD PTR [r8+160]
        jl	L_AES_XTS_encrypt_avx1_aes_enc_64_aes_enc_block_last
        vaesenc	xmm8, xmm8, xmm4
        vaesenc	xmm9, xmm9, xmm4
        vaesenc	xmm10, xmm10, xmm4
        vaesenc	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r8+176]
        vaesenc	xmm8, xmm8, xmm4
        vaesenc	xmm9, xmm9, xmm4
        vaesenc	xmm10, xmm10, xmm4
        vaesenc	xmm11, xmm11, xmm4
        cmp	r10d, 13
        vmovdqu	xmm4, OWORD PTR [r8+192]
        jl	L_AES_XTS_encrypt_avx1_aes_enc_64_aes_enc_block_last
        vaesenc	xmm8, xmm8, xmm4
        vaesenc	xmm9, xmm9, xmm4
        vaesenc	xmm10, xmm10, xmm4
        vaesenc	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r8+208]
        vaesenc	xmm8, xmm8, xmm4
        vaesenc	xmm9, xmm9, xmm4
        vaesenc	xmm10, xmm10, xmm4
        vaesenc	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r8+224]
L_AES_XTS_encrypt_avx1_aes_enc_64_aes_enc_block_last:
        vaesenclast	xmm8, xmm8, xmm4
        vaesenclast	xmm9, xmm9, xmm4
        vaesenclast	xmm10, xmm10, xmm4
        vaesenclast	xmm11, xmm11, xmm4
        vpxor	xmm8, xmm8, xmm0
        vpxor	xmm9, xmm9, xmm1
        vpxor	xmm10, xmm10, xmm2
        vpxor	xmm11, xmm11, xmm3
        vmovdqu	OWORD PTR [rdx], xmm8
        vmovdqu	OWORD PTR [rdx+16], xmm9
        vmovdqu	OWORD PTR [rdx+32], xmm10
        vmovdqu	OWORD PTR [rdx+48], xmm11
        vpsrad	xmm4, xmm3, 31
        vpslld	xmm0, xmm3, 1
        vpshufd	xmm4, xmm4, 147
        vpand	xmm4, xmm4, xmm12
        vpxor	xmm0, xmm0, xmm4
        add	r13d, 64
        cmp	r13d, r11d
        jl	L_AES_XTS_encrypt_avx1_enc_64
L_AES_XTS_encrypt_avx1_done_64:
        cmp	r13d, eax
        mov	r11d, eax
        je	L_AES_XTS_encrypt_avx1_done_enc
        sub	r11d, r13d
        cmp	r11d, 16
        mov	r11d, eax
        jl	L_AES_XTS_encrypt_avx1_last_15
        and	r11d, 4294967280
        ; 16 bytes of input
L_AES_XTS_encrypt_avx1_enc_16:
        lea	rcx, QWORD PTR [rdi+r13]
        vmovdqu	xmm8, OWORD PTR [rcx]
        vpxor	xmm8, xmm8, xmm0
        ; aes_enc_block
        vpxor	xmm8, xmm8, [r8]
        vmovdqu	xmm5, OWORD PTR [r8+16]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+32]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+48]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+64]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+80]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+96]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+112]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+128]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+144]
        vaesenc	xmm8, xmm8, xmm5
        cmp	r10d, 11
        vmovdqu	xmm5, OWORD PTR [r8+160]
        jl	L_AES_XTS_encrypt_avx1_aes_enc_block_last
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm6, OWORD PTR [r8+176]
        vaesenc	xmm8, xmm8, xmm6
        cmp	r10d, 13
        vmovdqu	xmm5, OWORD PTR [r8+192]
        jl	L_AES_XTS_encrypt_avx1_aes_enc_block_last
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm6, OWORD PTR [r8+208]
        vaesenc	xmm8, xmm8, xmm6
        vmovdqu	xmm5, OWORD PTR [r8+224]
L_AES_XTS_encrypt_avx1_aes_enc_block_last:
        vaesenclast	xmm8, xmm8, xmm5
        vpxor	xmm8, xmm8, xmm0
        lea	rcx, QWORD PTR [rsi+r13]
        vmovdqu	OWORD PTR [rcx], xmm8
        vpsrad	xmm4, xmm0, 31
        vpslld	xmm0, xmm0, 1
        vpshufd	xmm4, xmm4, 147
        vpand	xmm4, xmm4, xmm12
        vpxor	xmm0, xmm0, xmm4
        add	r13d, 16
        cmp	r13d, r11d
        jl	L_AES_XTS_encrypt_avx1_enc_16
        cmp	r13d, eax
        je	L_AES_XTS_encrypt_avx1_done_enc
L_AES_XTS_encrypt_avx1_last_15:
        sub	r13, 16
        lea	rcx, QWORD PTR [rsi+r13]
        vmovdqu	xmm8, OWORD PTR [rcx]
        add	r13, 16
        vmovdqu	OWORD PTR [rsp], xmm8
        xor	rdx, rdx
L_AES_XTS_encrypt_avx1_last_15_byte_loop:
        mov	r11b, BYTE PTR [rsp+rdx]
        mov	cl, BYTE PTR [rdi+r13]
        mov	BYTE PTR [rsi+r13], r11b
        mov	BYTE PTR [rsp+rdx], cl
        inc	r13d
        inc	edx
        cmp	r13d, eax
        jl	L_AES_XTS_encrypt_avx1_last_15_byte_loop
        sub	r13, rdx
        vmovdqu	xmm8, OWORD PTR [rsp]
        sub	r13, 16
        vpxor	xmm8, xmm8, xmm0
        ; aes_enc_block
        vpxor	xmm8, xmm8, [r8]
        vmovdqu	xmm5, OWORD PTR [r8+16]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+32]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+48]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+64]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+80]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+96]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+112]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+128]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+144]
        vaesenc	xmm8, xmm8, xmm5
        cmp	r10d, 11
        vmovdqu	xmm5, OWORD PTR [r8+160]
        jl	L_AES_XTS_encrypt_avx1_last_15_aes_enc_block_last
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm6, OWORD PTR [r8+176]
        vaesenc	xmm8, xmm8, xmm6
        cmp	r10d, 13
        vmovdqu	xmm5, OWORD PTR [r8+192]
        jl	L_AES_XTS_encrypt_avx1_last_15_aes_enc_block_last
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm6, OWORD PTR [r8+208]
        vaesenc	xmm8, xmm8, xmm6
        vmovdqu	xmm5, OWORD PTR [r8+224]
L_AES_XTS_encrypt_avx1_last_15_aes_enc_block_last:
        vaesenclast	xmm8, xmm8, xmm5
        vpxor	xmm8, xmm8, xmm0
        lea	rcx, QWORD PTR [rsi+r13]
        vmovdqu	OWORD PTR [rcx], xmm8
L_AES_XTS_encrypt_avx1_done_enc:
        vmovdqu	xmm6, OWORD PTR [rsp+64]
        vmovdqu	xmm7, OWORD PTR [rsp+80]
        vmovdqu	xmm8, OWORD PTR [rsp+96]
        vmovdqu	xmm9, OWORD PTR [rsp+112]
        vmovdqu	xmm10, OWORD PTR [rsp+128]
        vmovdqu	xmm11, OWORD PTR [rsp+144]
        vmovdqu	xmm12, OWORD PTR [rsp+160]
        add	rsp, 176
        pop	r13
        pop	r12
        pop	rsi
        pop	rdi
        ret
AES_XTS_encrypt_avx1 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_XTS_encrypt_update_avx1 PROC
        push	rdi
        push	rsi
        push	r12
        mov	rdi, rcx
        mov	rsi, rdx
        mov	rax, r8
        mov	r10, r9
        mov	r8, QWORD PTR [rsp+64]
        mov	r9d, DWORD PTR [rsp+72]
        sub	rsp, 176
        vmovdqu	OWORD PTR [rsp+64], xmm6
        vmovdqu	OWORD PTR [rsp+80], xmm7
        vmovdqu	OWORD PTR [rsp+96], xmm8
        vmovdqu	OWORD PTR [rsp+112], xmm9
        vmovdqu	OWORD PTR [rsp+128], xmm10
        vmovdqu	OWORD PTR [rsp+144], xmm11
        vmovdqu	OWORD PTR [rsp+160], xmm12
        vmovdqu	xmm12, OWORD PTR L_avx1_aes_xts_gc_xts
        vmovdqu	xmm0, OWORD PTR [r8]
        xor	r12d, r12d
        cmp	eax, 64
        mov	r11d, eax
        jl	L_AES_XTS_encrypt_update_avx1_done_64
        and	r11d, 4294967232
L_AES_XTS_encrypt_update_avx1_enc_64:
        ; 64 bytes of input
        ; aes_enc_64
        lea	rcx, QWORD PTR [rdi+r12]
        lea	rdx, QWORD PTR [rsi+r12]
        vmovdqu	xmm8, OWORD PTR [rcx]
        vmovdqu	xmm9, OWORD PTR [rcx+16]
        vmovdqu	xmm10, OWORD PTR [rcx+32]
        vmovdqu	xmm11, OWORD PTR [rcx+48]
        vpsrad	xmm4, xmm0, 31
        vpslld	xmm1, xmm0, 1
        vpshufd	xmm4, xmm4, 147
        vpand	xmm4, xmm4, xmm12
        vpxor	xmm1, xmm1, xmm4
        vpsrad	xmm4, xmm1, 31
        vpslld	xmm2, xmm1, 1
        vpshufd	xmm4, xmm4, 147
        vpand	xmm4, xmm4, xmm12
        vpxor	xmm2, xmm2, xmm4
        vpsrad	xmm4, xmm2, 31
        vpslld	xmm3, xmm2, 1
        vpshufd	xmm4, xmm4, 147
        vpand	xmm4, xmm4, xmm12
        vpxor	xmm3, xmm3, xmm4
        vpxor	xmm8, xmm8, xmm0
        vpxor	xmm9, xmm9, xmm1
        vpxor	xmm10, xmm10, xmm2
        vpxor	xmm11, xmm11, xmm3
        ; aes_enc_block
        vmovdqu	xmm4, OWORD PTR [r10]
        vpxor	xmm8, xmm8, xmm4
        vpxor	xmm9, xmm9, xmm4
        vpxor	xmm10, xmm10, xmm4
        vpxor	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r10+16]
        vaesenc	xmm8, xmm8, xmm4
        vaesenc	xmm9, xmm9, xmm4
        vaesenc	xmm10, xmm10, xmm4
        vaesenc	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r10+32]
        vaesenc	xmm8, xmm8, xmm4
        vaesenc	xmm9, xmm9, xmm4
        vaesenc	xmm10, xmm10, xmm4
        vaesenc	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r10+48]
        vaesenc	xmm8, xmm8, xmm4
        vaesenc	xmm9, xmm9, xmm4
        vaesenc	xmm10, xmm10, xmm4
        vaesenc	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r10+64]
        vaesenc	xmm8, xmm8, xmm4
        vaesenc	xmm9, xmm9, xmm4
        vaesenc	xmm10, xmm10, xmm4
        vaesenc	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r10+80]
        vaesenc	xmm8, xmm8, xmm4
        vaesenc	xmm9, xmm9, xmm4
        vaesenc	xmm10, xmm10, xmm4
        vaesenc	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r10+96]
        vaesenc	xmm8, xmm8, xmm4
        vaesenc	xmm9, xmm9, xmm4
        vaesenc	xmm10, xmm10, xmm4
        vaesenc	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r10+112]
        vaesenc	xmm8, xmm8, xmm4
        vaesenc	xmm9, xmm9, xmm4
        vaesenc	xmm10, xmm10, xmm4
        vaesenc	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r10+128]
        vaesenc	xmm8, xmm8, xmm4
        vaesenc	xmm9, xmm9, xmm4
        vaesenc	xmm10, xmm10, xmm4
        vaesenc	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r10+144]
        vaesenc	xmm8, xmm8, xmm4
        vaesenc	xmm9, xmm9, xmm4
        vaesenc	xmm10, xmm10, xmm4
        vaesenc	xmm11, xmm11, xmm4
        cmp	r9d, 11
        vmovdqu	xmm4, OWORD PTR [r10+160]
        jl	L_AES_XTS_encrypt_update_avx1_aes_enc_64_aes_enc_block_last
        vaesenc	xmm8, xmm8, xmm4
        vaesenc	xmm9, xmm9, xmm4
        vaesenc	xmm10, xmm10, xmm4
        vaesenc	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r10+176]
        vaesenc	xmm8, xmm8, xmm4
        vaesenc	xmm9, xmm9, xmm4
        vaesenc	xmm10, xmm10, xmm4
        vaesenc	xmm11, xmm11, xmm4
        cmp	r9d, 13
        vmovdqu	xmm4, OWORD PTR [r10+192]
        jl	L_AES_XTS_encrypt_update_avx1_aes_enc_64_aes_enc_block_last
        vaesenc	xmm8, xmm8, xmm4
        vaesenc	xmm9, xmm9, xmm4
        vaesenc	xmm10, xmm10, xmm4
        vaesenc	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r10+208]
        vaesenc	xmm8, xmm8, xmm4
        vaesenc	xmm9, xmm9, xmm4
        vaesenc	xmm10, xmm10, xmm4
        vaesenc	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r10+224]
L_AES_XTS_encrypt_update_avx1_aes_enc_64_aes_enc_block_last:
        vaesenclast	xmm8, xmm8, xmm4
        vaesenclast	xmm9, xmm9, xmm4
        vaesenclast	xmm10, xmm10, xmm4
        vaesenclast	xmm11, xmm11, xmm4
        vpxor	xmm8, xmm8, xmm0
        vpxor	xmm9, xmm9, xmm1
        vpxor	xmm10, xmm10, xmm2
        vpxor	xmm11, xmm11, xmm3
        vmovdqu	OWORD PTR [rdx], xmm8
        vmovdqu	OWORD PTR [rdx+16], xmm9
        vmovdqu	OWORD PTR [rdx+32], xmm10
        vmovdqu	OWORD PTR [rdx+48], xmm11
        vpsrad	xmm4, xmm3, 31
        vpslld	xmm0, xmm3, 1
        vpshufd	xmm4, xmm4, 147
        vpand	xmm4, xmm4, xmm12
        vpxor	xmm0, xmm0, xmm4
        add	r12d, 64
        cmp	r12d, r11d
        jl	L_AES_XTS_encrypt_update_avx1_enc_64
L_AES_XTS_encrypt_update_avx1_done_64:
        cmp	r12d, eax
        mov	r11d, eax
        je	L_AES_XTS_encrypt_update_avx1_done_enc
        sub	r11d, r12d
        cmp	r11d, 16
        mov	r11d, eax
        jl	L_AES_XTS_encrypt_update_avx1_last_15
        and	r11d, 4294967280
        ; 16 bytes of input
L_AES_XTS_encrypt_update_avx1_enc_16:
        lea	rcx, QWORD PTR [rdi+r12]
        vmovdqu	xmm8, OWORD PTR [rcx]
        vpxor	xmm8, xmm8, xmm0
        ; aes_enc_block
        vpxor	xmm8, xmm8, [r10]
        vmovdqu	xmm5, OWORD PTR [r10+16]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+32]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+48]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+64]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+80]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+96]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+112]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+128]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+144]
        vaesenc	xmm8, xmm8, xmm5
        cmp	r9d, 11
        vmovdqu	xmm5, OWORD PTR [r10+160]
        jl	L_AES_XTS_encrypt_update_avx1_aes_enc_block_last
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm6, OWORD PTR [r10+176]
        vaesenc	xmm8, xmm8, xmm6
        cmp	r9d, 13
        vmovdqu	xmm5, OWORD PTR [r10+192]
        jl	L_AES_XTS_encrypt_update_avx1_aes_enc_block_last
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm6, OWORD PTR [r10+208]
        vaesenc	xmm8, xmm8, xmm6
        vmovdqu	xmm5, OWORD PTR [r10+224]
L_AES_XTS_encrypt_update_avx1_aes_enc_block_last:
        vaesenclast	xmm8, xmm8, xmm5
        vpxor	xmm8, xmm8, xmm0
        lea	rcx, QWORD PTR [rsi+r12]
        vmovdqu	OWORD PTR [rcx], xmm8
        vpsrad	xmm4, xmm0, 31
        vpslld	xmm0, xmm0, 1
        vpshufd	xmm4, xmm4, 147
        vpand	xmm4, xmm4, xmm12
        vpxor	xmm0, xmm0, xmm4
        add	r12d, 16
        cmp	r12d, r11d
        jl	L_AES_XTS_encrypt_update_avx1_enc_16
        cmp	r12d, eax
        je	L_AES_XTS_encrypt_update_avx1_done_enc
L_AES_XTS_encrypt_update_avx1_last_15:
        sub	r12, 16
        lea	rcx, QWORD PTR [rsi+r12]
        vmovdqu	xmm8, OWORD PTR [rcx]
        add	r12, 16
        vmovdqu	OWORD PTR [rsp], xmm8
        xor	rdx, rdx
L_AES_XTS_encrypt_update_avx1_last_15_byte_loop:
        mov	r11b, BYTE PTR [rsp+rdx]
        mov	cl, BYTE PTR [rdi+r12]
        mov	BYTE PTR [rsi+r12], r11b
        mov	BYTE PTR [rsp+rdx], cl
        inc	r12d
        inc	edx
        cmp	r12d, eax
        jl	L_AES_XTS_encrypt_update_avx1_last_15_byte_loop
        sub	r12, rdx
        vmovdqu	xmm8, OWORD PTR [rsp]
        sub	r12, 16
        vpxor	xmm8, xmm8, xmm0
        ; aes_enc_block
        vpxor	xmm8, xmm8, [r10]
        vmovdqu	xmm5, OWORD PTR [r10+16]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+32]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+48]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+64]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+80]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+96]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+112]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+128]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+144]
        vaesenc	xmm8, xmm8, xmm5
        cmp	r9d, 11
        vmovdqu	xmm5, OWORD PTR [r10+160]
        jl	L_AES_XTS_encrypt_update_avx1_last_15_aes_enc_block_last
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm6, OWORD PTR [r10+176]
        vaesenc	xmm8, xmm8, xmm6
        cmp	r9d, 13
        vmovdqu	xmm5, OWORD PTR [r10+192]
        jl	L_AES_XTS_encrypt_update_avx1_last_15_aes_enc_block_last
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm6, OWORD PTR [r10+208]
        vaesenc	xmm8, xmm8, xmm6
        vmovdqu	xmm5, OWORD PTR [r10+224]
L_AES_XTS_encrypt_update_avx1_last_15_aes_enc_block_last:
        vaesenclast	xmm8, xmm8, xmm5
        vpxor	xmm8, xmm8, xmm0
        lea	rcx, QWORD PTR [rsi+r12]
        vmovdqu	OWORD PTR [rcx], xmm8
L_AES_XTS_encrypt_update_avx1_done_enc:
        vmovdqu	OWORD PTR [r8], xmm0
        vmovdqu	xmm6, OWORD PTR [rsp+64]
        vmovdqu	xmm7, OWORD PTR [rsp+80]
        vmovdqu	xmm8, OWORD PTR [rsp+96]
        vmovdqu	xmm9, OWORD PTR [rsp+112]
        vmovdqu	xmm10, OWORD PTR [rsp+128]
        vmovdqu	xmm11, OWORD PTR [rsp+144]
        vmovdqu	xmm12, OWORD PTR [rsp+160]
        add	rsp, 176
        pop	r12
        pop	rsi
        pop	rdi
        ret
AES_XTS_encrypt_update_avx1 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_XTS_decrypt_avx1 PROC
        push	rdi
        push	rsi
        push	r12
        push	r13
        mov	rdi, rcx
        mov	rsi, rdx
        mov	rax, r8
        mov	r12, r9
        mov	r8, QWORD PTR [rsp+72]
        mov	r9, QWORD PTR [rsp+80]
        mov	r10d, DWORD PTR [rsp+88]
        sub	rsp, 128
        vmovdqu	OWORD PTR [rsp+16], xmm6
        vmovdqu	OWORD PTR [rsp+32], xmm7
        vmovdqu	OWORD PTR [rsp+48], xmm8
        vmovdqu	OWORD PTR [rsp+64], xmm9
        vmovdqu	OWORD PTR [rsp+80], xmm10
        vmovdqu	OWORD PTR [rsp+96], xmm11
        vmovdqu	OWORD PTR [rsp+112], xmm12
        vmovdqu	xmm12, OWORD PTR L_avx1_aes_xts_gc_xts
        vmovdqu	xmm0, OWORD PTR [r12]
        ; aes_enc_block
        vpxor	xmm0, xmm0, [r9]
        vmovdqu	xmm5, OWORD PTR [r9+16]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+32]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+48]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+64]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+80]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+96]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+112]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+128]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+144]
        vaesenc	xmm0, xmm0, xmm5
        cmp	r10d, 11
        vmovdqu	xmm5, OWORD PTR [r9+160]
        jl	L_AES_XTS_decrypt_avx1_tweak_aes_enc_block_last
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r9+176]
        vaesenc	xmm0, xmm0, xmm6
        cmp	r10d, 13
        vmovdqu	xmm5, OWORD PTR [r9+192]
        jl	L_AES_XTS_decrypt_avx1_tweak_aes_enc_block_last
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r9+208]
        vaesenc	xmm0, xmm0, xmm6
        vmovdqu	xmm5, OWORD PTR [r9+224]
L_AES_XTS_decrypt_avx1_tweak_aes_enc_block_last:
        vaesenclast	xmm0, xmm0, xmm5
        xor	r13d, r13d
        mov	r11d, eax
        and	r11d, 4294967280
        cmp	r11d, eax
        je	L_AES_XTS_decrypt_avx1_mul16_64
        sub	r11d, 16
        cmp	r11d, 16
        jl	L_AES_XTS_decrypt_avx1_last_31_start
L_AES_XTS_decrypt_avx1_mul16_64:
        cmp	r11d, 64
        jl	L_AES_XTS_decrypt_avx1_done_64
        and	r11d, 4294967232
L_AES_XTS_decrypt_avx1_dec_64:
        ; 64 bytes of input
        ; aes_dec_64
        lea	rcx, QWORD PTR [rdi+r13]
        lea	rdx, QWORD PTR [rsi+r13]
        vmovdqu	xmm8, OWORD PTR [rcx]
        vmovdqu	xmm9, OWORD PTR [rcx+16]
        vmovdqu	xmm10, OWORD PTR [rcx+32]
        vmovdqu	xmm11, OWORD PTR [rcx+48]
        vpsrad	xmm4, xmm0, 31
        vpslld	xmm1, xmm0, 1
        vpshufd	xmm4, xmm4, 147
        vpand	xmm4, xmm4, xmm12
        vpxor	xmm1, xmm1, xmm4
        vpsrad	xmm4, xmm1, 31
        vpslld	xmm2, xmm1, 1
        vpshufd	xmm4, xmm4, 147
        vpand	xmm4, xmm4, xmm12
        vpxor	xmm2, xmm2, xmm4
        vpsrad	xmm4, xmm2, 31
        vpslld	xmm3, xmm2, 1
        vpshufd	xmm4, xmm4, 147
        vpand	xmm4, xmm4, xmm12
        vpxor	xmm3, xmm3, xmm4
        vpxor	xmm8, xmm8, xmm0
        vpxor	xmm9, xmm9, xmm1
        vpxor	xmm10, xmm10, xmm2
        vpxor	xmm11, xmm11, xmm3
        ; aes_dec_block
        vmovdqu	xmm4, OWORD PTR [r8]
        vpxor	xmm8, xmm8, xmm4
        vpxor	xmm9, xmm9, xmm4
        vpxor	xmm10, xmm10, xmm4
        vpxor	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r8+16]
        vaesdec	xmm8, xmm8, xmm4
        vaesdec	xmm9, xmm9, xmm4
        vaesdec	xmm10, xmm10, xmm4
        vaesdec	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r8+32]
        vaesdec	xmm8, xmm8, xmm4
        vaesdec	xmm9, xmm9, xmm4
        vaesdec	xmm10, xmm10, xmm4
        vaesdec	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r8+48]
        vaesdec	xmm8, xmm8, xmm4
        vaesdec	xmm9, xmm9, xmm4
        vaesdec	xmm10, xmm10, xmm4
        vaesdec	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r8+64]
        vaesdec	xmm8, xmm8, xmm4
        vaesdec	xmm9, xmm9, xmm4
        vaesdec	xmm10, xmm10, xmm4
        vaesdec	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r8+80]
        vaesdec	xmm8, xmm8, xmm4
        vaesdec	xmm9, xmm9, xmm4
        vaesdec	xmm10, xmm10, xmm4
        vaesdec	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r8+96]
        vaesdec	xmm8, xmm8, xmm4
        vaesdec	xmm9, xmm9, xmm4
        vaesdec	xmm10, xmm10, xmm4
        vaesdec	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r8+112]
        vaesdec	xmm8, xmm8, xmm4
        vaesdec	xmm9, xmm9, xmm4
        vaesdec	xmm10, xmm10, xmm4
        vaesdec	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r8+128]
        vaesdec	xmm8, xmm8, xmm4
        vaesdec	xmm9, xmm9, xmm4
        vaesdec	xmm10, xmm10, xmm4
        vaesdec	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r8+144]
        vaesdec	xmm8, xmm8, xmm4
        vaesdec	xmm9, xmm9, xmm4
        vaesdec	xmm10, xmm10, xmm4
        vaesdec	xmm11, xmm11, xmm4
        cmp	r10d, 11
        vmovdqu	xmm4, OWORD PTR [r8+160]
        jl	L_AES_XTS_decrypt_avx1_aes_dec_64_aes_dec_block_last
        vaesdec	xmm8, xmm8, xmm4
        vaesdec	xmm9, xmm9, xmm4
        vaesdec	xmm10, xmm10, xmm4
        vaesdec	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r8+176]
        vaesdec	xmm8, xmm8, xmm4
        vaesdec	xmm9, xmm9, xmm4
        vaesdec	xmm10, xmm10, xmm4
        vaesdec	xmm11, xmm11, xmm4
        cmp	r10d, 13
        vmovdqu	xmm4, OWORD PTR [r8+192]
        jl	L_AES_XTS_decrypt_avx1_aes_dec_64_aes_dec_block_last
        vaesdec	xmm8, xmm8, xmm4
        vaesdec	xmm9, xmm9, xmm4
        vaesdec	xmm10, xmm10, xmm4
        vaesdec	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r8+208]
        vaesdec	xmm8, xmm8, xmm4
        vaesdec	xmm9, xmm9, xmm4
        vaesdec	xmm10, xmm10, xmm4
        vaesdec	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r8+224]
L_AES_XTS_decrypt_avx1_aes_dec_64_aes_dec_block_last:
        vaesdeclast	xmm8, xmm8, xmm4
        vaesdeclast	xmm9, xmm9, xmm4
        vaesdeclast	xmm10, xmm10, xmm4
        vaesdeclast	xmm11, xmm11, xmm4
        vpxor	xmm8, xmm8, xmm0
        vpxor	xmm9, xmm9, xmm1
        vpxor	xmm10, xmm10, xmm2
        vpxor	xmm11, xmm11, xmm3
        vmovdqu	OWORD PTR [rdx], xmm8
        vmovdqu	OWORD PTR [rdx+16], xmm9
        vmovdqu	OWORD PTR [rdx+32], xmm10
        vmovdqu	OWORD PTR [rdx+48], xmm11
        vpsrad	xmm4, xmm3, 31
        vpslld	xmm0, xmm3, 1
        vpshufd	xmm4, xmm4, 147
        vpand	xmm4, xmm4, xmm12
        vpxor	xmm0, xmm0, xmm4
        add	r13d, 64
        cmp	r13d, r11d
        jl	L_AES_XTS_decrypt_avx1_dec_64
L_AES_XTS_decrypt_avx1_done_64:
        cmp	r13d, eax
        mov	r11d, eax
        je	L_AES_XTS_decrypt_avx1_done_dec
        and	r11d, 4294967280
        cmp	r11d, eax
        je	L_AES_XTS_decrypt_avx1_mul16
        sub	r11d, 16
        sub	r11d, r13d
        cmp	r11d, 16
        jl	L_AES_XTS_decrypt_avx1_last_31_start
        add	r11d, r13d
L_AES_XTS_decrypt_avx1_mul16:
L_AES_XTS_decrypt_avx1_dec_16:
        ; 16 bytes of input
        lea	rcx, QWORD PTR [rdi+r13]
        vmovdqu	xmm8, OWORD PTR [rcx]
        vpxor	xmm8, xmm8, xmm0
        ; aes_dec_block
        vpxor	xmm8, xmm8, [r8]
        vmovdqu	xmm5, OWORD PTR [r8+16]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+32]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+48]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+64]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+80]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+96]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+112]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+128]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+144]
        vaesdec	xmm8, xmm8, xmm5
        cmp	r10d, 11
        vmovdqu	xmm5, OWORD PTR [r8+160]
        jl	L_AES_XTS_decrypt_avx1_aes_dec_block_last
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm6, OWORD PTR [r8+176]
        vaesdec	xmm8, xmm8, xmm6
        cmp	r10d, 13
        vmovdqu	xmm5, OWORD PTR [r8+192]
        jl	L_AES_XTS_decrypt_avx1_aes_dec_block_last
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm6, OWORD PTR [r8+208]
        vaesdec	xmm8, xmm8, xmm6
        vmovdqu	xmm5, OWORD PTR [r8+224]
L_AES_XTS_decrypt_avx1_aes_dec_block_last:
        vaesdeclast	xmm8, xmm8, xmm5
        vpxor	xmm8, xmm8, xmm0
        lea	rcx, QWORD PTR [rsi+r13]
        vmovdqu	OWORD PTR [rcx], xmm8
        vpsrad	xmm4, xmm0, 31
        vpslld	xmm0, xmm0, 1
        vpshufd	xmm4, xmm4, 147
        vpand	xmm4, xmm4, xmm12
        vpxor	xmm0, xmm0, xmm4
        add	r13d, 16
        cmp	r13d, r11d
        jl	L_AES_XTS_decrypt_avx1_dec_16
        cmp	r13d, eax
        je	L_AES_XTS_decrypt_avx1_done_dec
L_AES_XTS_decrypt_avx1_last_31_start:
        vpsrad	xmm4, xmm0, 31
        vpslld	xmm7, xmm0, 1
        vpshufd	xmm4, xmm4, 147
        vpand	xmm4, xmm4, xmm12
        vpxor	xmm7, xmm7, xmm4
        lea	rcx, QWORD PTR [rdi+r13]
        vmovdqu	xmm8, OWORD PTR [rcx]
        vpxor	xmm8, xmm8, xmm7
        ; aes_dec_block
        vpxor	xmm8, xmm8, [r8]
        vmovdqu	xmm5, OWORD PTR [r8+16]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+32]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+48]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+64]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+80]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+96]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+112]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+128]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+144]
        vaesdec	xmm8, xmm8, xmm5
        cmp	r10d, 11
        vmovdqu	xmm5, OWORD PTR [r8+160]
        jl	L_AES_XTS_decrypt_avx1_last_31_aes_dec_block_last
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm6, OWORD PTR [r8+176]
        vaesdec	xmm8, xmm8, xmm6
        cmp	r10d, 13
        vmovdqu	xmm5, OWORD PTR [r8+192]
        jl	L_AES_XTS_decrypt_avx1_last_31_aes_dec_block_last
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm6, OWORD PTR [r8+208]
        vaesdec	xmm8, xmm8, xmm6
        vmovdqu	xmm5, OWORD PTR [r8+224]
L_AES_XTS_decrypt_avx1_last_31_aes_dec_block_last:
        vaesdeclast	xmm8, xmm8, xmm5
        vpxor	xmm8, xmm8, xmm7
        vmovdqu	OWORD PTR [rsp], xmm8
        add	r13, 16
        xor	rdx, rdx
L_AES_XTS_decrypt_avx1_last_31_byte_loop:
        mov	r11b, BYTE PTR [rsp+rdx]
        mov	cl, BYTE PTR [rdi+r13]
        mov	BYTE PTR [rsi+r13], r11b
        mov	BYTE PTR [rsp+rdx], cl
        inc	r13d
        inc	edx
        cmp	r13d, eax
        jl	L_AES_XTS_decrypt_avx1_last_31_byte_loop
        sub	r13, rdx
        vmovdqu	xmm8, OWORD PTR [rsp]
        vpxor	xmm8, xmm8, xmm0
        ; aes_dec_block
        vpxor	xmm8, xmm8, [r8]
        vmovdqu	xmm5, OWORD PTR [r8+16]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+32]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+48]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+64]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+80]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+96]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+112]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+128]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+144]
        vaesdec	xmm8, xmm8, xmm5
        cmp	r10d, 11
        vmovdqu	xmm5, OWORD PTR [r8+160]
        jl	L_AES_XTS_decrypt_avx1_last_31_2_aes_dec_block_last
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm6, OWORD PTR [r8+176]
        vaesdec	xmm8, xmm8, xmm6
        cmp	r10d, 13
        vmovdqu	xmm5, OWORD PTR [r8+192]
        jl	L_AES_XTS_decrypt_avx1_last_31_2_aes_dec_block_last
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm6, OWORD PTR [r8+208]
        vaesdec	xmm8, xmm8, xmm6
        vmovdqu	xmm5, OWORD PTR [r8+224]
L_AES_XTS_decrypt_avx1_last_31_2_aes_dec_block_last:
        vaesdeclast	xmm8, xmm8, xmm5
        vpxor	xmm8, xmm8, xmm0
        sub	r13, 16
        lea	rcx, QWORD PTR [rsi+r13]
        vmovdqu	OWORD PTR [rcx], xmm8
L_AES_XTS_decrypt_avx1_done_dec:
        vmovdqu	xmm6, OWORD PTR [rsp+16]
        vmovdqu	xmm7, OWORD PTR [rsp+32]
        vmovdqu	xmm8, OWORD PTR [rsp+48]
        vmovdqu	xmm9, OWORD PTR [rsp+64]
        vmovdqu	xmm10, OWORD PTR [rsp+80]
        vmovdqu	xmm11, OWORD PTR [rsp+96]
        vmovdqu	xmm12, OWORD PTR [rsp+112]
        add	rsp, 128
        pop	r13
        pop	r12
        pop	rsi
        pop	rdi
        ret
AES_XTS_decrypt_avx1 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_XTS_decrypt_update_avx1 PROC
        push	rdi
        push	rsi
        push	r12
        mov	rdi, rcx
        mov	rsi, rdx
        mov	rax, r8
        mov	r10, r9
        mov	r8, QWORD PTR [rsp+64]
        mov	r9d, DWORD PTR [rsp+72]
        sub	rsp, 128
        vmovdqu	OWORD PTR [rsp+16], xmm6
        vmovdqu	OWORD PTR [rsp+32], xmm7
        vmovdqu	OWORD PTR [rsp+48], xmm8
        vmovdqu	OWORD PTR [rsp+64], xmm9
        vmovdqu	OWORD PTR [rsp+80], xmm10
        vmovdqu	OWORD PTR [rsp+96], xmm11
        vmovdqu	OWORD PTR [rsp+112], xmm12
        vmovdqu	xmm12, OWORD PTR L_avx1_aes_xts_gc_xts
        vmovdqu	xmm0, OWORD PTR [r8]
        xor	r12d, r12d
        mov	r11d, eax
        and	r11d, 4294967280
        cmp	r11d, eax
        je	L_AES_XTS_decrypt_update_avx1_mul16_64
        sub	r11d, 16
        cmp	r11d, 16
        jl	L_AES_XTS_decrypt_update_avx1_last_31_start
L_AES_XTS_decrypt_update_avx1_mul16_64:
        cmp	r11d, 64
        jl	L_AES_XTS_decrypt_update_avx1_done_64
        and	r11d, 4294967232
L_AES_XTS_decrypt_update_avx1_dec_64:
        ; 64 bytes of input
        ; aes_dec_64
        lea	rcx, QWORD PTR [rdi+r12]
        lea	rdx, QWORD PTR [rsi+r12]
        vmovdqu	xmm8, OWORD PTR [rcx]
        vmovdqu	xmm9, OWORD PTR [rcx+16]
        vmovdqu	xmm10, OWORD PTR [rcx+32]
        vmovdqu	xmm11, OWORD PTR [rcx+48]
        vpsrad	xmm4, xmm0, 31
        vpslld	xmm1, xmm0, 1
        vpshufd	xmm4, xmm4, 147
        vpand	xmm4, xmm4, xmm12
        vpxor	xmm1, xmm1, xmm4
        vpsrad	xmm4, xmm1, 31
        vpslld	xmm2, xmm1, 1
        vpshufd	xmm4, xmm4, 147
        vpand	xmm4, xmm4, xmm12
        vpxor	xmm2, xmm2, xmm4
        vpsrad	xmm4, xmm2, 31
        vpslld	xmm3, xmm2, 1
        vpshufd	xmm4, xmm4, 147
        vpand	xmm4, xmm4, xmm12
        vpxor	xmm3, xmm3, xmm4
        vpxor	xmm8, xmm8, xmm0
        vpxor	xmm9, xmm9, xmm1
        vpxor	xmm10, xmm10, xmm2
        vpxor	xmm11, xmm11, xmm3
        ; aes_dec_block
        vmovdqu	xmm4, OWORD PTR [r10]
        vpxor	xmm8, xmm8, xmm4
        vpxor	xmm9, xmm9, xmm4
        vpxor	xmm10, xmm10, xmm4
        vpxor	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r10+16]
        vaesdec	xmm8, xmm8, xmm4
        vaesdec	xmm9, xmm9, xmm4
        vaesdec	xmm10, xmm10, xmm4
        vaesdec	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r10+32]
        vaesdec	xmm8, xmm8, xmm4
        vaesdec	xmm9, xmm9, xmm4
        vaesdec	xmm10, xmm10, xmm4
        vaesdec	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r10+48]
        vaesdec	xmm8, xmm8, xmm4
        vaesdec	xmm9, xmm9, xmm4
        vaesdec	xmm10, xmm10, xmm4
        vaesdec	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r10+64]
        vaesdec	xmm8, xmm8, xmm4
        vaesdec	xmm9, xmm9, xmm4
        vaesdec	xmm10, xmm10, xmm4
        vaesdec	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r10+80]
        vaesdec	xmm8, xmm8, xmm4
        vaesdec	xmm9, xmm9, xmm4
        vaesdec	xmm10, xmm10, xmm4
        vaesdec	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r10+96]
        vaesdec	xmm8, xmm8, xmm4
        vaesdec	xmm9, xmm9, xmm4
        vaesdec	xmm10, xmm10, xmm4
        vaesdec	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r10+112]
        vaesdec	xmm8, xmm8, xmm4
        vaesdec	xmm9, xmm9, xmm4
        vaesdec	xmm10, xmm10, xmm4
        vaesdec	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r10+128]
        vaesdec	xmm8, xmm8, xmm4
        vaesdec	xmm9, xmm9, xmm4
        vaesdec	xmm10, xmm10, xmm4
        vaesdec	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r10+144]
        vaesdec	xmm8, xmm8, xmm4
        vaesdec	xmm9, xmm9, xmm4
        vaesdec	xmm10, xmm10, xmm4
        vaesdec	xmm11, xmm11, xmm4
        cmp	r9d, 11
        vmovdqu	xmm4, OWORD PTR [r10+160]
        jl	L_AES_XTS_decrypt_update_avx1_aes_dec_64_aes_dec_block_last
        vaesdec	xmm8, xmm8, xmm4
        vaesdec	xmm9, xmm9, xmm4
        vaesdec	xmm10, xmm10, xmm4
        vaesdec	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r10+176]
        vaesdec	xmm8, xmm8, xmm4
        vaesdec	xmm9, xmm9, xmm4
        vaesdec	xmm10, xmm10, xmm4
        vaesdec	xmm11, xmm11, xmm4
        cmp	r9d, 13
        vmovdqu	xmm4, OWORD PTR [r10+192]
        jl	L_AES_XTS_decrypt_update_avx1_aes_dec_64_aes_dec_block_last
        vaesdec	xmm8, xmm8, xmm4
        vaesdec	xmm9, xmm9, xmm4
        vaesdec	xmm10, xmm10, xmm4
        vaesdec	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r10+208]
        vaesdec	xmm8, xmm8, xmm4
        vaesdec	xmm9, xmm9, xmm4
        vaesdec	xmm10, xmm10, xmm4
        vaesdec	xmm11, xmm11, xmm4
        vmovdqu	xmm4, OWORD PTR [r10+224]
L_AES_XTS_decrypt_update_avx1_aes_dec_64_aes_dec_block_last:
        vaesdeclast	xmm8, xmm8, xmm4
        vaesdeclast	xmm9, xmm9, xmm4
        vaesdeclast	xmm10, xmm10, xmm4
        vaesdeclast	xmm11, xmm11, xmm4
        vpxor	xmm8, xmm8, xmm0
        vpxor	xmm9, xmm9, xmm1
        vpxor	xmm10, xmm10, xmm2
        vpxor	xmm11, xmm11, xmm3
        vmovdqu	OWORD PTR [rdx], xmm8
        vmovdqu	OWORD PTR [rdx+16], xmm9
        vmovdqu	OWORD PTR [rdx+32], xmm10
        vmovdqu	OWORD PTR [rdx+48], xmm11
        vpsrad	xmm4, xmm3, 31
        vpslld	xmm0, xmm3, 1
        vpshufd	xmm4, xmm4, 147
        vpand	xmm4, xmm4, xmm12
        vpxor	xmm0, xmm0, xmm4
        add	r12d, 64
        cmp	r12d, r11d
        jl	L_AES_XTS_decrypt_update_avx1_dec_64
L_AES_XTS_decrypt_update_avx1_done_64:
        cmp	r12d, eax
        mov	r11d, eax
        je	L_AES_XTS_decrypt_update_avx1_done_dec
        and	r11d, 4294967280
        cmp	r11d, eax
        je	L_AES_XTS_decrypt_update_avx1_mul16
        sub	r11d, 16
        sub	r11d, r12d
        cmp	r11d, 16
        jl	L_AES_XTS_decrypt_update_avx1_last_31_start
        add	r11d, r12d
L_AES_XTS_decrypt_update_avx1_mul16:
L_AES_XTS_decrypt_update_avx1_dec_16:
        ; 16 bytes of input
        lea	rcx, QWORD PTR [rdi+r12]
        vmovdqu	xmm8, OWORD PTR [rcx]
        vpxor	xmm8, xmm8, xmm0
        ; aes_dec_block
        vpxor	xmm8, xmm8, [r10]
        vmovdqu	xmm5, OWORD PTR [r10+16]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+32]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+48]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+64]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+80]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+96]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+112]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+128]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+144]
        vaesdec	xmm8, xmm8, xmm5
        cmp	r9d, 11
        vmovdqu	xmm5, OWORD PTR [r10+160]
        jl	L_AES_XTS_decrypt_update_avx1_aes_dec_block_last
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm6, OWORD PTR [r10+176]
        vaesdec	xmm8, xmm8, xmm6
        cmp	r9d, 13
        vmovdqu	xmm5, OWORD PTR [r10+192]
        jl	L_AES_XTS_decrypt_update_avx1_aes_dec_block_last
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm6, OWORD PTR [r10+208]
        vaesdec	xmm8, xmm8, xmm6
        vmovdqu	xmm5, OWORD PTR [r10+224]
L_AES_XTS_decrypt_update_avx1_aes_dec_block_last:
        vaesdeclast	xmm8, xmm8, xmm5
        vpxor	xmm8, xmm8, xmm0
        lea	rcx, QWORD PTR [rsi+r12]
        vmovdqu	OWORD PTR [rcx], xmm8
        vpsrad	xmm4, xmm0, 31
        vpslld	xmm0, xmm0, 1
        vpshufd	xmm4, xmm4, 147
        vpand	xmm4, xmm4, xmm12
        vpxor	xmm0, xmm0, xmm4
        add	r12d, 16
        cmp	r12d, r11d
        jl	L_AES_XTS_decrypt_update_avx1_dec_16
        cmp	r12d, eax
        je	L_AES_XTS_decrypt_update_avx1_done_dec
L_AES_XTS_decrypt_update_avx1_last_31_start:
        vpsrad	xmm4, xmm0, 31
        vpslld	xmm7, xmm0, 1
        vpshufd	xmm4, xmm4, 147
        vpand	xmm4, xmm4, xmm12
        vpxor	xmm7, xmm7, xmm4
        lea	rcx, QWORD PTR [rdi+r12]
        vmovdqu	xmm8, OWORD PTR [rcx]
        vpxor	xmm8, xmm8, xmm7
        ; aes_dec_block
        vpxor	xmm8, xmm8, [r10]
        vmovdqu	xmm5, OWORD PTR [r10+16]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+32]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+48]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+64]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+80]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+96]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+112]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+128]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+144]
        vaesdec	xmm8, xmm8, xmm5
        cmp	r9d, 11
        vmovdqu	xmm5, OWORD PTR [r10+160]
        jl	L_AES_XTS_decrypt_update_avx1_last_31_aes_dec_block_last
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm6, OWORD PTR [r10+176]
        vaesdec	xmm8, xmm8, xmm6
        cmp	r9d, 13
        vmovdqu	xmm5, OWORD PTR [r10+192]
        jl	L_AES_XTS_decrypt_update_avx1_last_31_aes_dec_block_last
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm6, OWORD PTR [r10+208]
        vaesdec	xmm8, xmm8, xmm6
        vmovdqu	xmm5, OWORD PTR [r10+224]
L_AES_XTS_decrypt_update_avx1_last_31_aes_dec_block_last:
        vaesdeclast	xmm8, xmm8, xmm5
        vpxor	xmm8, xmm8, xmm7
        vmovdqu	OWORD PTR [rsp], xmm8
        add	r12, 16
        xor	rdx, rdx
L_AES_XTS_decrypt_update_avx1_last_31_byte_loop:
        mov	r11b, BYTE PTR [rsp+rdx]
        mov	cl, BYTE PTR [rdi+r12]
        mov	BYTE PTR [rsi+r12], r11b
        mov	BYTE PTR [rsp+rdx], cl
        inc	r12d
        inc	edx
        cmp	r12d, eax
        jl	L_AES_XTS_decrypt_update_avx1_last_31_byte_loop
        sub	r12, rdx
        vmovdqu	xmm8, OWORD PTR [rsp]
        vpxor	xmm8, xmm8, xmm0
        ; aes_dec_block
        vpxor	xmm8, xmm8, [r10]
        vmovdqu	xmm5, OWORD PTR [r10+16]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+32]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+48]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+64]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+80]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+96]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+112]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+128]
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+144]
        vaesdec	xmm8, xmm8, xmm5
        cmp	r9d, 11
        vmovdqu	xmm5, OWORD PTR [r10+160]
        jl	L_AES_XTS_decrypt_update_avx1_last_31_2_aes_dec_block_last
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm6, OWORD PTR [r10+176]
        vaesdec	xmm8, xmm8, xmm6
        cmp	r9d, 13
        vmovdqu	xmm5, OWORD PTR [r10+192]
        jl	L_AES_XTS_decrypt_update_avx1_last_31_2_aes_dec_block_last
        vaesdec	xmm8, xmm8, xmm5
        vmovdqu	xmm6, OWORD PTR [r10+208]
        vaesdec	xmm8, xmm8, xmm6
        vmovdqu	xmm5, OWORD PTR [r10+224]
L_AES_XTS_decrypt_update_avx1_last_31_2_aes_dec_block_last:
        vaesdeclast	xmm8, xmm8, xmm5
        vpxor	xmm8, xmm8, xmm0
        sub	r12, 16
        lea	rcx, QWORD PTR [rsi+r12]
        vmovdqu	OWORD PTR [rcx], xmm8
L_AES_XTS_decrypt_update_avx1_done_dec:
        vmovdqu	OWORD PTR [r8], xmm0
        vmovdqu	xmm6, OWORD PTR [rsp+16]
        vmovdqu	xmm7, OWORD PTR [rsp+32]
        vmovdqu	xmm8, OWORD PTR [rsp+48]
        vmovdqu	xmm9, OWORD PTR [rsp+64]
        vmovdqu	xmm10, OWORD PTR [rsp+80]
        vmovdqu	xmm11, OWORD PTR [rsp+96]
        vmovdqu	xmm12, OWORD PTR [rsp+112]
        add	rsp, 128
        pop	r12
        pop	rsi
        pop	rdi
        ret
AES_XTS_decrypt_update_avx1 ENDP
_TEXT ENDS
ENDIF
IFDEF HAVE_INTEL_VAES
_TEXT SEGMENT READONLY PARA
AES_XTS_init_vaes PROC
        vmovdqu	xmm0, OWORD PTR [rcx]
        ; aes_enc_block
        vpxor	xmm0, xmm0, [rdx]
        vmovdqu	xmm2, OWORD PTR [rdx+16]
        vaesenc	xmm0, xmm0, xmm2
        vmovdqu	xmm2, OWORD PTR [rdx+32]
        vaesenc	xmm0, xmm0, xmm2
        vmovdqu	xmm2, OWORD PTR [rdx+48]
        vaesenc	xmm0, xmm0, xmm2
        vmovdqu	xmm2, OWORD PTR [rdx+64]
        vaesenc	xmm0, xmm0, xmm2
        vmovdqu	xmm2, OWORD PTR [rdx+80]
        vaesenc	xmm0, xmm0, xmm2
        vmovdqu	xmm2, OWORD PTR [rdx+96]
        vaesenc	xmm0, xmm0, xmm2
        vmovdqu	xmm2, OWORD PTR [rdx+112]
        vaesenc	xmm0, xmm0, xmm2
        vmovdqu	xmm2, OWORD PTR [rdx+128]
        vaesenc	xmm0, xmm0, xmm2
        vmovdqu	xmm2, OWORD PTR [rdx+144]
        vaesenc	xmm0, xmm0, xmm2
        cmp	r8d, 11
        vmovdqu	xmm2, OWORD PTR [rdx+160]
        jl	L_AES_XTS_init_vaes_tweak_aes_enc_block_last
        vaesenc	xmm0, xmm0, xmm2
        vmovdqu	xmm3, OWORD PTR [rdx+176]
        vaesenc	xmm0, xmm0, xmm3
        cmp	r8d, 13
        vmovdqu	xmm2, OWORD PTR [rdx+192]
        jl	L_AES_XTS_init_vaes_tweak_aes_enc_block_last
        vaesenc	xmm0, xmm0, xmm2
        vmovdqu	xmm3, OWORD PTR [rdx+208]
        vaesenc	xmm0, xmm0, xmm3
        vmovdqu	xmm2, OWORD PTR [rdx+224]
L_AES_XTS_init_vaes_tweak_aes_enc_block_last:
        vaesenclast	xmm0, xmm0, xmm2
        vmovdqu	OWORD PTR [rcx], xmm0
        ret
AES_XTS_init_vaes ENDP
_TEXT ENDS
_DATA SEGMENT
ALIGN 16
L_vaes_aes_xts_gc_xts DWORD \
     00000087h,  00000000h,  00000001h,  00000000h
ptr_L_vaes_aes_xts_gc_xts QWORD L_vaes_aes_xts_gc_xts
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_vaes_aes_xts_poly DWORD \
     00000087h,  00000000h,  00000000h,  00000000h
ptr_L_vaes_aes_xts_poly QWORD L_vaes_aes_xts_poly
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_vaes_aes_xts_shl DWORD \
     00000000h,  00000000h,  00000000h,  00000000h,
     00000001h,  00000000h,  00000001h,  00000000h
ptr_L_vaes_aes_xts_shl QWORD L_vaes_aes_xts_shl
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_vaes_aes_xts_shr DWORD \
     00000040h,  00000000h,  00000040h,  00000000h,
     0000003fh,  00000000h,  0000003fh,  00000000h
ptr_L_vaes_aes_xts_shr QWORD L_vaes_aes_xts_shr
_DATA ENDS
_TEXT SEGMENT READONLY PARA
AES_XTS_encrypt_vaes PROC
        push	rdi
        push	rsi
        push	r12
        push	r13
        mov	rdi, rcx
        mov	rsi, rdx
        mov	rax, r8
        mov	r12, r9
        mov	r8, QWORD PTR [rsp+72]
        mov	r9, QWORD PTR [rsp+80]
        mov	r10d, DWORD PTR [rsp+88]
        sub	rsp, 224
        vmovdqu	OWORD PTR [rsp+64], xmm6
        vmovdqu	OWORD PTR [rsp+80], xmm7
        vmovdqu	OWORD PTR [rsp+96], xmm8
        vmovdqu	OWORD PTR [rsp+112], xmm9
        vmovdqu	OWORD PTR [rsp+128], xmm10
        vmovdqu	OWORD PTR [rsp+144], xmm11
        vmovdqu	OWORD PTR [rsp+160], xmm12
        vmovdqu	OWORD PTR [rsp+176], xmm13
        vmovdqu	OWORD PTR [rsp+192], xmm14
        vmovdqu	OWORD PTR [rsp+208], xmm15
        vmovdqu	xmm12, OWORD PTR L_vaes_aes_xts_gc_xts
        vbroadcasti128	ymm13, ptr_L_vaes_aes_xts_poly
        vmovdqu	ymm14, YMMWORD PTR L_vaes_aes_xts_shl
        vmovdqu	ymm15, YMMWORD PTR L_vaes_aes_xts_shr
        vmovdqu	xmm8, OWORD PTR [r12]
        ; aes_enc_block
        vpxor	xmm8, xmm8, [r9]
        vmovdqu	xmm5, OWORD PTR [r9+16]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+32]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+48]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+64]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+80]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+96]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+112]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+128]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+144]
        vaesenc	xmm8, xmm8, xmm5
        cmp	r10d, 11
        vmovdqu	xmm5, OWORD PTR [r9+160]
        jl	L_AES_XTS_encrypt_vaes_tweak_aes_enc_block_last
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm6, OWORD PTR [r9+176]
        vaesenc	xmm8, xmm8, xmm6
        cmp	r10d, 13
        vmovdqu	xmm5, OWORD PTR [r9+192]
        jl	L_AES_XTS_encrypt_vaes_tweak_aes_enc_block_last
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm6, OWORD PTR [r9+208]
        vaesenc	xmm8, xmm8, xmm6
        vmovdqu	xmm5, OWORD PTR [r9+224]
L_AES_XTS_encrypt_vaes_tweak_aes_enc_block_last:
        vaesenclast	xmm8, xmm8, xmm5
        xor	r13d, r13d
        cmp	eax, 32
        jl	L_AES_XTS_encrypt_vaes_done_128
        cmp	eax, 128
        mov	r11d, eax
        jl	L_AES_XTS_encrypt_vaes_done_128
        and	r11d, 4294967168
        vperm2i128	ymm5, ymm8, ymm8, 0
        vpsrlvq	ymm6, ymm5, ymm15
        vpclmulqdq	ymm7, ymm6, ymm13, 1
        vpslldq	ymm6, ymm6, 8
        vpsllvq	ymm4, ymm5, ymm14
        vpxor	ymm4, ymm4, ymm7
        vpxor	ymm4, ymm4, ymm6
        vpsrlq	ymm9, ymm4, 62
        vpclmulqdq	ymm10, ymm9, ymm13, 1
        vpslldq	ymm9, ymm9, 8
        vpsllq	ymm5, ymm4, 2
        vpxor	ymm5, ymm5, ymm10
        vpxor	ymm5, ymm5, ymm9
        vpsrlq	ymm9, ymm5, 62
        vpclmulqdq	ymm10, ymm9, ymm13, 1
        vpslldq	ymm9, ymm9, 8
        vpsllq	ymm6, ymm5, 2
        vpxor	ymm6, ymm6, ymm10
        vpxor	ymm6, ymm6, ymm9
        vpsrlq	ymm9, ymm6, 62
        vpclmulqdq	ymm10, ymm9, ymm13, 1
        vpslldq	ymm9, ymm9, 8
        vpsllq	ymm7, ymm6, 2
        vpxor	ymm7, ymm7, ymm10
        vpxor	ymm7, ymm7, ymm9
L_AES_XTS_encrypt_vaes_enc_128:
        ; 128 bytes of input
        ; aes_enc_128
        lea	rcx, QWORD PTR [rdi+r13]
        lea	rdx, QWORD PTR [rsi+r13]
        vmovdqu	ymm0, YMMWORD PTR [rcx]
        vmovdqu	ymm1, YMMWORD PTR [rcx+32]
        vmovdqu	ymm2, YMMWORD PTR [rcx+64]
        vmovdqu	ymm3, YMMWORD PTR [rcx+96]
        ; aes_enc_block
        vbroadcasti128	ymm9, [r8]
        vpxor	ymm0, ymm0, ymm4
        vpxor	ymm0, ymm0, ymm9
        vpxor	ymm1, ymm1, ymm5
        vpxor	ymm1, ymm1, ymm9
        vpxor	ymm2, ymm2, ymm6
        vpxor	ymm2, ymm2, ymm9
        vpxor	ymm3, ymm3, ymm7
        vpxor	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r8+16]
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vaesenc	ymm2, ymm2, ymm9
        vaesenc	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r8+32]
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vaesenc	ymm2, ymm2, ymm9
        vaesenc	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r8+48]
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vaesenc	ymm2, ymm2, ymm9
        vaesenc	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r8+64]
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vaesenc	ymm2, ymm2, ymm9
        vaesenc	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r8+80]
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vaesenc	ymm2, ymm2, ymm9
        vaesenc	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r8+96]
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vaesenc	ymm2, ymm2, ymm9
        vaesenc	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r8+112]
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vaesenc	ymm2, ymm2, ymm9
        vaesenc	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r8+128]
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vaesenc	ymm2, ymm2, ymm9
        vaesenc	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r8+144]
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vaesenc	ymm2, ymm2, ymm9
        vaesenc	ymm3, ymm3, ymm9
        cmp	r10d, 11
        vbroadcasti128	ymm9, [r8+160]
        jl	L_AES_XTS_encrypt_vaes_aes_enc_128_aes_enc_block_last
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vaesenc	ymm2, ymm2, ymm9
        vaesenc	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r8+176]
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vaesenc	ymm2, ymm2, ymm9
        vaesenc	ymm3, ymm3, ymm9
        cmp	r10d, 13
        vbroadcasti128	ymm9, [r8+192]
        jl	L_AES_XTS_encrypt_vaes_aes_enc_128_aes_enc_block_last
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vaesenc	ymm2, ymm2, ymm9
        vaesenc	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r8+208]
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vaesenc	ymm2, ymm2, ymm9
        vaesenc	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r8+224]
L_AES_XTS_encrypt_vaes_aes_enc_128_aes_enc_block_last:
        vaesenclast	ymm0, ymm0, ymm9
        vaesenclast	ymm1, ymm1, ymm9
        vaesenclast	ymm2, ymm2, ymm9
        vaesenclast	ymm3, ymm3, ymm9
        vpxor	ymm0, ymm0, ymm4
        vmovdqu	YMMWORD PTR [rdx], ymm0
        vpsrlq	ymm9, ymm4, 56
        vpclmulqdq	ymm10, ymm9, ymm13, 1
        vpslldq	ymm9, ymm9, 8
        vpsllq	ymm4, ymm4, 8
        vpxor	ymm4, ymm4, ymm10
        vpxor	ymm4, ymm4, ymm9
        vpxor	ymm1, ymm1, ymm5
        vmovdqu	YMMWORD PTR [rdx+32], ymm1
        vpsrlq	ymm9, ymm5, 56
        vpclmulqdq	ymm10, ymm9, ymm13, 1
        vpslldq	ymm9, ymm9, 8
        vpsllq	ymm5, ymm5, 8
        vpxor	ymm5, ymm5, ymm10
        vpxor	ymm5, ymm5, ymm9
        vpxor	ymm2, ymm2, ymm6
        vmovdqu	YMMWORD PTR [rdx+64], ymm2
        vpsrlq	ymm9, ymm6, 56
        vpclmulqdq	ymm10, ymm9, ymm13, 1
        vpslldq	ymm9, ymm9, 8
        vpsllq	ymm6, ymm6, 8
        vpxor	ymm6, ymm6, ymm10
        vpxor	ymm6, ymm6, ymm9
        vpxor	ymm3, ymm3, ymm7
        vmovdqu	YMMWORD PTR [rdx+96], ymm3
        vpsrlq	ymm9, ymm7, 56
        vpclmulqdq	ymm10, ymm9, ymm13, 1
        vpslldq	ymm9, ymm9, 8
        vpsllq	ymm7, ymm7, 8
        vpxor	ymm7, ymm7, ymm10
        vpxor	ymm7, ymm7, ymm9
        add	r13d, 128
        cmp	r13d, r11d
        jl	L_AES_XTS_encrypt_vaes_enc_128
        vextracti128	xmm8, ymm4, 0
L_AES_XTS_encrypt_vaes_done_128:
        mov	r11d, eax
        and	r11d, 4294967232
        cmp	r13d, r11d
        je	L_AES_XTS_encrypt_vaes_done_64
        ; 64 bytes of input
        ; aes_enc_64
        lea	rcx, QWORD PTR [rdi+r13]
        lea	rdx, QWORD PTR [rsi+r13]
        vmovdqu	ymm0, YMMWORD PTR [rcx]
        vmovdqu	ymm1, YMMWORD PTR [rcx+32]
        vperm2i128	ymm5, ymm8, ymm8, 0
        vpsrlvq	ymm6, ymm5, ymm15
        vpclmulqdq	ymm7, ymm6, ymm13, 1
        vpslldq	ymm6, ymm6, 8
        vpsllvq	ymm4, ymm5, ymm14
        vpxor	ymm4, ymm4, ymm7
        vpxor	ymm4, ymm4, ymm6
        vpsrlq	ymm9, ymm4, 62
        vpclmulqdq	ymm10, ymm9, ymm13, 1
        vpslldq	ymm9, ymm9, 8
        vpsllq	ymm5, ymm4, 2
        vpxor	ymm5, ymm5, ymm10
        vpxor	ymm5, ymm5, ymm9
        ; aes_enc_block
        vbroadcasti128	ymm9, [r8]
        vpxor	ymm0, ymm0, ymm4
        vpxor	ymm0, ymm0, ymm9
        vpxor	ymm1, ymm1, ymm5
        vpxor	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r8+16]
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r8+32]
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r8+48]
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r8+64]
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r8+80]
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r8+96]
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r8+112]
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r8+128]
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r8+144]
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        cmp	r10d, 11
        vbroadcasti128	ymm9, [r8+160]
        jl	L_AES_XTS_encrypt_vaes_aes_enc_64_aes_enc_block_last
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r8+176]
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        cmp	r10d, 13
        vbroadcasti128	ymm9, [r8+192]
        jl	L_AES_XTS_encrypt_vaes_aes_enc_64_aes_enc_block_last
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r8+208]
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r8+224]
L_AES_XTS_encrypt_vaes_aes_enc_64_aes_enc_block_last:
        vaesenclast	ymm0, ymm0, ymm9
        vaesenclast	ymm1, ymm1, ymm9
        vpxor	ymm0, ymm0, ymm4
        vmovdqu	YMMWORD PTR [rdx], ymm0
        vpxor	ymm1, ymm1, ymm5
        vmovdqu	YMMWORD PTR [rdx+32], ymm1
        vextracti128	xmm8, ymm5, 1
        vpshufd	xmm9, xmm8, 19
        vpaddq	xmm8, xmm8, xmm8
        vpsrad	xmm9, xmm9, 31
        vpand	xmm9, xmm9, xmm12
        vpxor	xmm8, xmm8, xmm9
        add	r13d, 64
L_AES_XTS_encrypt_vaes_done_64:
        mov	r11d, eax
        and	r11d, 4294967264
        cmp	r13d, r11d
        je	L_AES_XTS_encrypt_vaes_done_32
        ; 32 bytes of input
        ; aes_enc_32
        lea	rcx, QWORD PTR [rdi+r13]
        lea	rdx, QWORD PTR [rsi+r13]
        vmovdqu	ymm0, YMMWORD PTR [rcx]
        vperm2i128	ymm5, ymm8, ymm8, 0
        vpsrlvq	ymm6, ymm5, ymm15
        vpclmulqdq	ymm7, ymm6, ymm13, 1
        vpslldq	ymm6, ymm6, 8
        vpsllvq	ymm4, ymm5, ymm14
        vpxor	ymm4, ymm4, ymm7
        vpxor	ymm4, ymm4, ymm6
        ; aes_enc_block
        vbroadcasti128	ymm9, [r8]
        vpxor	ymm0, ymm0, ymm4
        vpxor	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r8+16]
        vaesenc	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r8+32]
        vaesenc	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r8+48]
        vaesenc	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r8+64]
        vaesenc	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r8+80]
        vaesenc	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r8+96]
        vaesenc	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r8+112]
        vaesenc	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r8+128]
        vaesenc	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r8+144]
        vaesenc	ymm0, ymm0, ymm9
        cmp	r10d, 11
        vbroadcasti128	ymm9, [r8+160]
        jl	L_AES_XTS_encrypt_vaes_aes_enc_32_aes_enc_block_last
        vaesenc	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r8+176]
        vaesenc	ymm0, ymm0, ymm9
        cmp	r10d, 13
        vbroadcasti128	ymm9, [r8+192]
        jl	L_AES_XTS_encrypt_vaes_aes_enc_32_aes_enc_block_last
        vaesenc	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r8+208]
        vaesenc	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r8+224]
L_AES_XTS_encrypt_vaes_aes_enc_32_aes_enc_block_last:
        vaesenclast	ymm0, ymm0, ymm9
        vpxor	ymm0, ymm0, ymm4
        vmovdqu	YMMWORD PTR [rdx], ymm0
        vextracti128	xmm8, ymm4, 1
        vpshufd	xmm9, xmm8, 19
        vpaddq	xmm8, xmm8, xmm8
        vpsrad	xmm9, xmm9, 31
        vpand	xmm9, xmm9, xmm12
        vpxor	xmm8, xmm8, xmm9
        add	r13d, 32
L_AES_XTS_encrypt_vaes_done_32:
        cmp	r13d, eax
        mov	r11d, eax
        je	L_AES_XTS_encrypt_vaes_done_enc
        sub	r11d, r13d
        cmp	r11d, 16
        mov	r11d, eax
        jl	L_AES_XTS_encrypt_vaes_last_15
        and	r11d, 4294967280
        ; 16 bytes of input
L_AES_XTS_encrypt_vaes_enc_16:
        lea	rcx, QWORD PTR [rdi+r13]
        vmovdqu	xmm0, OWORD PTR [rcx]
        vpxor	xmm0, xmm0, xmm8
        ; aes_enc_block
        vpxor	xmm0, xmm0, [r8]
        vmovdqu	xmm5, OWORD PTR [r8+16]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+32]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+48]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+64]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+80]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+96]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+112]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+128]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+144]
        vaesenc	xmm0, xmm0, xmm5
        cmp	r10d, 11
        vmovdqu	xmm5, OWORD PTR [r8+160]
        jl	L_AES_XTS_encrypt_vaes_aes_enc_block_last
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r8+176]
        vaesenc	xmm0, xmm0, xmm6
        cmp	r10d, 13
        vmovdqu	xmm5, OWORD PTR [r8+192]
        jl	L_AES_XTS_encrypt_vaes_aes_enc_block_last
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r8+208]
        vaesenc	xmm0, xmm0, xmm6
        vmovdqu	xmm5, OWORD PTR [r8+224]
L_AES_XTS_encrypt_vaes_aes_enc_block_last:
        vaesenclast	xmm0, xmm0, xmm5
        vpxor	xmm0, xmm0, xmm8
        lea	rcx, QWORD PTR [rsi+r13]
        vmovdqu	OWORD PTR [rcx], xmm0
        vpshufd	xmm4, xmm8, 19
        vpaddq	xmm8, xmm8, xmm8
        vpsrad	xmm4, xmm4, 31
        vpand	xmm4, xmm4, xmm12
        vpxor	xmm8, xmm8, xmm4
        add	r13d, 16
        cmp	r13d, r11d
        jl	L_AES_XTS_encrypt_vaes_enc_16
        cmp	r13d, eax
        je	L_AES_XTS_encrypt_vaes_done_enc
L_AES_XTS_encrypt_vaes_last_15:
        sub	r13, 16
        lea	rcx, QWORD PTR [rsi+r13]
        vmovdqu	xmm0, OWORD PTR [rcx]
        add	r13, 16
        vmovdqu	OWORD PTR [rsp], xmm0
        xor	rdx, rdx
L_AES_XTS_encrypt_vaes_last_15_byte_loop:
        mov	r11b, BYTE PTR [rsp+rdx]
        mov	cl, BYTE PTR [rdi+r13]
        mov	BYTE PTR [rsi+r13], r11b
        mov	BYTE PTR [rsp+rdx], cl
        inc	r13d
        inc	edx
        cmp	r13d, eax
        jl	L_AES_XTS_encrypt_vaes_last_15_byte_loop
        sub	r13, rdx
        vmovdqu	xmm0, OWORD PTR [rsp]
        sub	r13, 16
        vpxor	xmm0, xmm0, xmm8
        ; aes_enc_block
        vpxor	xmm0, xmm0, [r8]
        vmovdqu	xmm5, OWORD PTR [r8+16]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+32]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+48]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+64]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+80]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+96]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+112]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+128]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+144]
        vaesenc	xmm0, xmm0, xmm5
        cmp	r10d, 11
        vmovdqu	xmm5, OWORD PTR [r8+160]
        jl	L_AES_XTS_encrypt_vaes_last_15_aes_enc_block_last
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r8+176]
        vaesenc	xmm0, xmm0, xmm6
        cmp	r10d, 13
        vmovdqu	xmm5, OWORD PTR [r8+192]
        jl	L_AES_XTS_encrypt_vaes_last_15_aes_enc_block_last
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r8+208]
        vaesenc	xmm0, xmm0, xmm6
        vmovdqu	xmm5, OWORD PTR [r8+224]
L_AES_XTS_encrypt_vaes_last_15_aes_enc_block_last:
        vaesenclast	xmm0, xmm0, xmm5
        vpxor	xmm0, xmm0, xmm8
        lea	rcx, QWORD PTR [rsi+r13]
        vmovdqu	OWORD PTR [rcx], xmm0
L_AES_XTS_encrypt_vaes_done_enc:
        vmovdqu	xmm6, OWORD PTR [rsp+64]
        vmovdqu	xmm7, OWORD PTR [rsp+80]
        vmovdqu	xmm8, OWORD PTR [rsp+96]
        vmovdqu	xmm9, OWORD PTR [rsp+112]
        vmovdqu	xmm10, OWORD PTR [rsp+128]
        vmovdqu	xmm11, OWORD PTR [rsp+144]
        vmovdqu	xmm12, OWORD PTR [rsp+160]
        vmovdqu	xmm13, OWORD PTR [rsp+176]
        vmovdqu	xmm14, OWORD PTR [rsp+192]
        vmovdqu	xmm15, OWORD PTR [rsp+208]
        add	rsp, 224
        pop	r13
        pop	r12
        pop	rsi
        pop	rdi
        ret
AES_XTS_encrypt_vaes ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_XTS_encrypt_update_vaes PROC
        push	rdi
        push	rsi
        push	r12
        mov	rdi, rcx
        mov	rsi, rdx
        mov	rax, r8
        mov	r10, r9
        mov	r8, QWORD PTR [rsp+64]
        mov	r9d, DWORD PTR [rsp+72]
        sub	rsp, 224
        vmovdqu	OWORD PTR [rsp+64], xmm6
        vmovdqu	OWORD PTR [rsp+80], xmm7
        vmovdqu	OWORD PTR [rsp+96], xmm8
        vmovdqu	OWORD PTR [rsp+112], xmm9
        vmovdqu	OWORD PTR [rsp+128], xmm10
        vmovdqu	OWORD PTR [rsp+144], xmm11
        vmovdqu	OWORD PTR [rsp+160], xmm12
        vmovdqu	OWORD PTR [rsp+176], xmm13
        vmovdqu	OWORD PTR [rsp+192], xmm14
        vmovdqu	OWORD PTR [rsp+208], xmm15
        vmovdqu	xmm12, OWORD PTR L_vaes_aes_xts_gc_xts
        vbroadcasti128	ymm13, ptr_L_vaes_aes_xts_poly
        vmovdqu	ymm14, YMMWORD PTR L_vaes_aes_xts_shl
        vmovdqu	ymm15, YMMWORD PTR L_vaes_aes_xts_shr
        vmovdqu	xmm8, OWORD PTR [r8]
        xor	r12d, r12d
        cmp	eax, 32
        jl	L_AES_XTS_encrypt_update_vaes_done_128
        cmp	eax, 128
        mov	r11d, eax
        jl	L_AES_XTS_encrypt_update_vaes_done_128
        and	r11d, 4294967168
        vperm2i128	ymm5, ymm8, ymm8, 0
        vpsrlvq	ymm6, ymm5, ymm15
        vpclmulqdq	ymm7, ymm6, ymm13, 1
        vpslldq	ymm6, ymm6, 8
        vpsllvq	ymm4, ymm5, ymm14
        vpxor	ymm4, ymm4, ymm7
        vpxor	ymm4, ymm4, ymm6
        vpsrlq	ymm9, ymm4, 62
        vpclmulqdq	ymm10, ymm9, ymm13, 1
        vpslldq	ymm9, ymm9, 8
        vpsllq	ymm5, ymm4, 2
        vpxor	ymm5, ymm5, ymm10
        vpxor	ymm5, ymm5, ymm9
        vpsrlq	ymm9, ymm5, 62
        vpclmulqdq	ymm10, ymm9, ymm13, 1
        vpslldq	ymm9, ymm9, 8
        vpsllq	ymm6, ymm5, 2
        vpxor	ymm6, ymm6, ymm10
        vpxor	ymm6, ymm6, ymm9
        vpsrlq	ymm9, ymm6, 62
        vpclmulqdq	ymm10, ymm9, ymm13, 1
        vpslldq	ymm9, ymm9, 8
        vpsllq	ymm7, ymm6, 2
        vpxor	ymm7, ymm7, ymm10
        vpxor	ymm7, ymm7, ymm9
L_AES_XTS_encrypt_update_vaes_enc_128:
        ; 128 bytes of input
        ; aes_enc_128
        lea	rcx, QWORD PTR [rdi+r12]
        lea	rdx, QWORD PTR [rsi+r12]
        vmovdqu	ymm0, YMMWORD PTR [rcx]
        vmovdqu	ymm1, YMMWORD PTR [rcx+32]
        vmovdqu	ymm2, YMMWORD PTR [rcx+64]
        vmovdqu	ymm3, YMMWORD PTR [rcx+96]
        ; aes_enc_block
        vbroadcasti128	ymm9, [r10]
        vpxor	ymm0, ymm0, ymm4
        vpxor	ymm0, ymm0, ymm9
        vpxor	ymm1, ymm1, ymm5
        vpxor	ymm1, ymm1, ymm9
        vpxor	ymm2, ymm2, ymm6
        vpxor	ymm2, ymm2, ymm9
        vpxor	ymm3, ymm3, ymm7
        vpxor	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r10+16]
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vaesenc	ymm2, ymm2, ymm9
        vaesenc	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r10+32]
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vaesenc	ymm2, ymm2, ymm9
        vaesenc	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r10+48]
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vaesenc	ymm2, ymm2, ymm9
        vaesenc	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r10+64]
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vaesenc	ymm2, ymm2, ymm9
        vaesenc	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r10+80]
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vaesenc	ymm2, ymm2, ymm9
        vaesenc	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r10+96]
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vaesenc	ymm2, ymm2, ymm9
        vaesenc	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r10+112]
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vaesenc	ymm2, ymm2, ymm9
        vaesenc	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r10+128]
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vaesenc	ymm2, ymm2, ymm9
        vaesenc	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r10+144]
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vaesenc	ymm2, ymm2, ymm9
        vaesenc	ymm3, ymm3, ymm9
        cmp	r9d, 11
        vbroadcasti128	ymm9, [r10+160]
        jl	L_AES_XTS_encrypt_update_vaes_aes_enc_128_aes_enc_block_last
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vaesenc	ymm2, ymm2, ymm9
        vaesenc	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r10+176]
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vaesenc	ymm2, ymm2, ymm9
        vaesenc	ymm3, ymm3, ymm9
        cmp	r9d, 13
        vbroadcasti128	ymm9, [r10+192]
        jl	L_AES_XTS_encrypt_update_vaes_aes_enc_128_aes_enc_block_last
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vaesenc	ymm2, ymm2, ymm9
        vaesenc	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r10+208]
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vaesenc	ymm2, ymm2, ymm9
        vaesenc	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r10+224]
L_AES_XTS_encrypt_update_vaes_aes_enc_128_aes_enc_block_last:
        vaesenclast	ymm0, ymm0, ymm9
        vaesenclast	ymm1, ymm1, ymm9
        vaesenclast	ymm2, ymm2, ymm9
        vaesenclast	ymm3, ymm3, ymm9
        vpxor	ymm0, ymm0, ymm4
        vmovdqu	YMMWORD PTR [rdx], ymm0
        vpsrlq	ymm9, ymm4, 56
        vpclmulqdq	ymm10, ymm9, ymm13, 1
        vpslldq	ymm9, ymm9, 8
        vpsllq	ymm4, ymm4, 8
        vpxor	ymm4, ymm4, ymm10
        vpxor	ymm4, ymm4, ymm9
        vpxor	ymm1, ymm1, ymm5
        vmovdqu	YMMWORD PTR [rdx+32], ymm1
        vpsrlq	ymm9, ymm5, 56
        vpclmulqdq	ymm10, ymm9, ymm13, 1
        vpslldq	ymm9, ymm9, 8
        vpsllq	ymm5, ymm5, 8
        vpxor	ymm5, ymm5, ymm10
        vpxor	ymm5, ymm5, ymm9
        vpxor	ymm2, ymm2, ymm6
        vmovdqu	YMMWORD PTR [rdx+64], ymm2
        vpsrlq	ymm9, ymm6, 56
        vpclmulqdq	ymm10, ymm9, ymm13, 1
        vpslldq	ymm9, ymm9, 8
        vpsllq	ymm6, ymm6, 8
        vpxor	ymm6, ymm6, ymm10
        vpxor	ymm6, ymm6, ymm9
        vpxor	ymm3, ymm3, ymm7
        vmovdqu	YMMWORD PTR [rdx+96], ymm3
        vpsrlq	ymm9, ymm7, 56
        vpclmulqdq	ymm10, ymm9, ymm13, 1
        vpslldq	ymm9, ymm9, 8
        vpsllq	ymm7, ymm7, 8
        vpxor	ymm7, ymm7, ymm10
        vpxor	ymm7, ymm7, ymm9
        add	r12d, 128
        cmp	r12d, r11d
        jl	L_AES_XTS_encrypt_update_vaes_enc_128
        vextracti128	xmm8, ymm4, 0
L_AES_XTS_encrypt_update_vaes_done_128:
        mov	r11d, eax
        and	r11d, 4294967232
        cmp	r12d, r11d
        je	L_AES_XTS_encrypt_update_vaes_done_64
        ; 64 bytes of input
        ; aes_enc_64
        lea	rcx, QWORD PTR [rdi+r12]
        lea	rdx, QWORD PTR [rsi+r12]
        vmovdqu	ymm0, YMMWORD PTR [rcx]
        vmovdqu	ymm1, YMMWORD PTR [rcx+32]
        vperm2i128	ymm5, ymm8, ymm8, 0
        vpsrlvq	ymm6, ymm5, ymm15
        vpclmulqdq	ymm7, ymm6, ymm13, 1
        vpslldq	ymm6, ymm6, 8
        vpsllvq	ymm4, ymm5, ymm14
        vpxor	ymm4, ymm4, ymm7
        vpxor	ymm4, ymm4, ymm6
        vpsrlq	ymm9, ymm4, 62
        vpclmulqdq	ymm10, ymm9, ymm13, 1
        vpslldq	ymm9, ymm9, 8
        vpsllq	ymm5, ymm4, 2
        vpxor	ymm5, ymm5, ymm10
        vpxor	ymm5, ymm5, ymm9
        ; aes_enc_block
        vbroadcasti128	ymm9, [r10]
        vpxor	ymm0, ymm0, ymm4
        vpxor	ymm0, ymm0, ymm9
        vpxor	ymm1, ymm1, ymm5
        vpxor	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r10+16]
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r10+32]
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r10+48]
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r10+64]
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r10+80]
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r10+96]
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r10+112]
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r10+128]
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r10+144]
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        cmp	r9d, 11
        vbroadcasti128	ymm9, [r10+160]
        jl	L_AES_XTS_encrypt_update_vaes_aes_enc_64_aes_enc_block_last
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r10+176]
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        cmp	r9d, 13
        vbroadcasti128	ymm9, [r10+192]
        jl	L_AES_XTS_encrypt_update_vaes_aes_enc_64_aes_enc_block_last
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r10+208]
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r10+224]
L_AES_XTS_encrypt_update_vaes_aes_enc_64_aes_enc_block_last:
        vaesenclast	ymm0, ymm0, ymm9
        vaesenclast	ymm1, ymm1, ymm9
        vpxor	ymm0, ymm0, ymm4
        vmovdqu	YMMWORD PTR [rdx], ymm0
        vpxor	ymm1, ymm1, ymm5
        vmovdqu	YMMWORD PTR [rdx+32], ymm1
        vextracti128	xmm8, ymm5, 1
        vpshufd	xmm9, xmm8, 19
        vpaddq	xmm8, xmm8, xmm8
        vpsrad	xmm9, xmm9, 31
        vpand	xmm9, xmm9, xmm12
        vpxor	xmm8, xmm8, xmm9
        add	r12d, 64
L_AES_XTS_encrypt_update_vaes_done_64:
        mov	r11d, eax
        and	r11d, 4294967264
        cmp	r12d, r11d
        je	L_AES_XTS_encrypt_update_vaes_done_32
        ; 32 bytes of input
        ; aes_enc_32
        lea	rcx, QWORD PTR [rdi+r12]
        lea	rdx, QWORD PTR [rsi+r12]
        vmovdqu	ymm0, YMMWORD PTR [rcx]
        vperm2i128	ymm5, ymm8, ymm8, 0
        vpsrlvq	ymm6, ymm5, ymm15
        vpclmulqdq	ymm7, ymm6, ymm13, 1
        vpslldq	ymm6, ymm6, 8
        vpsllvq	ymm4, ymm5, ymm14
        vpxor	ymm4, ymm4, ymm7
        vpxor	ymm4, ymm4, ymm6
        ; aes_enc_block
        vbroadcasti128	ymm9, [r10]
        vpxor	ymm0, ymm0, ymm4
        vpxor	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r10+16]
        vaesenc	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r10+32]
        vaesenc	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r10+48]
        vaesenc	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r10+64]
        vaesenc	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r10+80]
        vaesenc	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r10+96]
        vaesenc	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r10+112]
        vaesenc	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r10+128]
        vaesenc	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r10+144]
        vaesenc	ymm0, ymm0, ymm9
        cmp	r9d, 11
        vbroadcasti128	ymm9, [r10+160]
        jl	L_AES_XTS_encrypt_update_vaes_aes_enc_32_aes_enc_block_last
        vaesenc	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r10+176]
        vaesenc	ymm0, ymm0, ymm9
        cmp	r9d, 13
        vbroadcasti128	ymm9, [r10+192]
        jl	L_AES_XTS_encrypt_update_vaes_aes_enc_32_aes_enc_block_last
        vaesenc	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r10+208]
        vaesenc	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r10+224]
L_AES_XTS_encrypt_update_vaes_aes_enc_32_aes_enc_block_last:
        vaesenclast	ymm0, ymm0, ymm9
        vpxor	ymm0, ymm0, ymm4
        vmovdqu	YMMWORD PTR [rdx], ymm0
        vextracti128	xmm8, ymm4, 1
        vpshufd	xmm9, xmm8, 19
        vpaddq	xmm8, xmm8, xmm8
        vpsrad	xmm9, xmm9, 31
        vpand	xmm9, xmm9, xmm12
        vpxor	xmm8, xmm8, xmm9
        add	r12d, 32
L_AES_XTS_encrypt_update_vaes_done_32:
        cmp	r12d, eax
        mov	r11d, eax
        je	L_AES_XTS_encrypt_update_vaes_done_enc
        sub	r11d, r12d
        cmp	r11d, 16
        mov	r11d, eax
        jl	L_AES_XTS_encrypt_update_vaes_last_15
        and	r11d, 4294967280
        ; 16 bytes of input
L_AES_XTS_encrypt_update_vaes_enc_16:
        lea	rcx, QWORD PTR [rdi+r12]
        vmovdqu	xmm0, OWORD PTR [rcx]
        vpxor	xmm0, xmm0, xmm8
        ; aes_enc_block
        vpxor	xmm0, xmm0, [r10]
        vmovdqu	xmm5, OWORD PTR [r10+16]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+32]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+48]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+64]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+80]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+96]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+112]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+128]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+144]
        vaesenc	xmm0, xmm0, xmm5
        cmp	r9d, 11
        vmovdqu	xmm5, OWORD PTR [r10+160]
        jl	L_AES_XTS_encrypt_update_vaes_aes_enc_block_last
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r10+176]
        vaesenc	xmm0, xmm0, xmm6
        cmp	r9d, 13
        vmovdqu	xmm5, OWORD PTR [r10+192]
        jl	L_AES_XTS_encrypt_update_vaes_aes_enc_block_last
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r10+208]
        vaesenc	xmm0, xmm0, xmm6
        vmovdqu	xmm5, OWORD PTR [r10+224]
L_AES_XTS_encrypt_update_vaes_aes_enc_block_last:
        vaesenclast	xmm0, xmm0, xmm5
        vpxor	xmm0, xmm0, xmm8
        lea	rcx, QWORD PTR [rsi+r12]
        vmovdqu	OWORD PTR [rcx], xmm0
        vpshufd	xmm4, xmm8, 19
        vpaddq	xmm8, xmm8, xmm8
        vpsrad	xmm4, xmm4, 31
        vpand	xmm4, xmm4, xmm12
        vpxor	xmm8, xmm8, xmm4
        add	r12d, 16
        cmp	r12d, r11d
        jl	L_AES_XTS_encrypt_update_vaes_enc_16
        cmp	r12d, eax
        je	L_AES_XTS_encrypt_update_vaes_done_enc
L_AES_XTS_encrypt_update_vaes_last_15:
        sub	r12, 16
        lea	rcx, QWORD PTR [rsi+r12]
        vmovdqu	xmm0, OWORD PTR [rcx]
        add	r12, 16
        vmovdqu	OWORD PTR [rsp], xmm0
        xor	rdx, rdx
L_AES_XTS_encrypt_update_vaes_last_15_byte_loop:
        mov	r11b, BYTE PTR [rsp+rdx]
        mov	cl, BYTE PTR [rdi+r12]
        mov	BYTE PTR [rsi+r12], r11b
        mov	BYTE PTR [rsp+rdx], cl
        inc	r12d
        inc	edx
        cmp	r12d, eax
        jl	L_AES_XTS_encrypt_update_vaes_last_15_byte_loop
        sub	r12, rdx
        vmovdqu	xmm0, OWORD PTR [rsp]
        sub	r12, 16
        vpxor	xmm0, xmm0, xmm8
        ; aes_enc_block
        vpxor	xmm0, xmm0, [r10]
        vmovdqu	xmm5, OWORD PTR [r10+16]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+32]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+48]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+64]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+80]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+96]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+112]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+128]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+144]
        vaesenc	xmm0, xmm0, xmm5
        cmp	r9d, 11
        vmovdqu	xmm5, OWORD PTR [r10+160]
        jl	L_AES_XTS_encrypt_update_vaes_last_15_aes_enc_block_last
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r10+176]
        vaesenc	xmm0, xmm0, xmm6
        cmp	r9d, 13
        vmovdqu	xmm5, OWORD PTR [r10+192]
        jl	L_AES_XTS_encrypt_update_vaes_last_15_aes_enc_block_last
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r10+208]
        vaesenc	xmm0, xmm0, xmm6
        vmovdqu	xmm5, OWORD PTR [r10+224]
L_AES_XTS_encrypt_update_vaes_last_15_aes_enc_block_last:
        vaesenclast	xmm0, xmm0, xmm5
        vpxor	xmm0, xmm0, xmm8
        lea	rcx, QWORD PTR [rsi+r12]
        vmovdqu	OWORD PTR [rcx], xmm0
L_AES_XTS_encrypt_update_vaes_done_enc:
        vmovdqu	OWORD PTR [r8], xmm8
        vmovdqu	xmm6, OWORD PTR [rsp+64]
        vmovdqu	xmm7, OWORD PTR [rsp+80]
        vmovdqu	xmm8, OWORD PTR [rsp+96]
        vmovdqu	xmm9, OWORD PTR [rsp+112]
        vmovdqu	xmm10, OWORD PTR [rsp+128]
        vmovdqu	xmm11, OWORD PTR [rsp+144]
        vmovdqu	xmm12, OWORD PTR [rsp+160]
        vmovdqu	xmm13, OWORD PTR [rsp+176]
        vmovdqu	xmm14, OWORD PTR [rsp+192]
        vmovdqu	xmm15, OWORD PTR [rsp+208]
        add	rsp, 224
        pop	r12
        pop	rsi
        pop	rdi
        ret
AES_XTS_encrypt_update_vaes ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_XTS_decrypt_vaes PROC
        push	rdi
        push	rsi
        push	r12
        push	r13
        mov	rdi, rcx
        mov	rsi, rdx
        mov	rax, r8
        mov	r12, r9
        mov	r8, QWORD PTR [rsp+72]
        mov	r9, QWORD PTR [rsp+80]
        mov	r10d, DWORD PTR [rsp+88]
        sub	rsp, 224
        vmovdqu	OWORD PTR [rsp+64], xmm6
        vmovdqu	OWORD PTR [rsp+80], xmm7
        vmovdqu	OWORD PTR [rsp+96], xmm8
        vmovdqu	OWORD PTR [rsp+112], xmm9
        vmovdqu	OWORD PTR [rsp+128], xmm10
        vmovdqu	OWORD PTR [rsp+144], xmm11
        vmovdqu	OWORD PTR [rsp+160], xmm12
        vmovdqu	OWORD PTR [rsp+176], xmm13
        vmovdqu	OWORD PTR [rsp+192], xmm14
        vmovdqu	OWORD PTR [rsp+208], xmm15
        vmovdqu	xmm12, OWORD PTR L_vaes_aes_xts_gc_xts
        vbroadcasti128	ymm13, ptr_L_vaes_aes_xts_poly
        vmovdqu	ymm14, YMMWORD PTR L_vaes_aes_xts_shl
        vmovdqu	ymm15, YMMWORD PTR L_vaes_aes_xts_shr
        vmovdqu	xmm8, OWORD PTR [r12]
        ; aes_enc_block
        vpxor	xmm8, xmm8, [r9]
        vmovdqu	xmm5, OWORD PTR [r9+16]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+32]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+48]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+64]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+80]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+96]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+112]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+128]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+144]
        vaesenc	xmm8, xmm8, xmm5
        cmp	r10d, 11
        vmovdqu	xmm5, OWORD PTR [r9+160]
        jl	L_AES_XTS_decrypt_vaes_tweak_aes_enc_block_last
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm6, OWORD PTR [r9+176]
        vaesenc	xmm8, xmm8, xmm6
        cmp	r10d, 13
        vmovdqu	xmm5, OWORD PTR [r9+192]
        jl	L_AES_XTS_decrypt_vaes_tweak_aes_enc_block_last
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm6, OWORD PTR [r9+208]
        vaesenc	xmm8, xmm8, xmm6
        vmovdqu	xmm5, OWORD PTR [r9+224]
L_AES_XTS_decrypt_vaes_tweak_aes_enc_block_last:
        vaesenclast	xmm8, xmm8, xmm5
        xor	r13d, r13d
        mov	r11d, eax
        and	r11d, 4294967280
        cmp	r11d, eax
        je	L_AES_XTS_decrypt_vaes_mul16_128
        sub	r11d, 16
        cmp	r11d, 16
        jl	L_AES_XTS_decrypt_vaes_last_31_start
L_AES_XTS_decrypt_vaes_mul16_128:
        cmp	r11d, 32
        jl	L_AES_XTS_decrypt_vaes_done_128
        cmp	r11d, 128
        jl	L_AES_XTS_decrypt_vaes_done_128
        and	r11d, 4294967168
        vperm2i128	ymm5, ymm8, ymm8, 0
        vpsrlvq	ymm6, ymm5, ymm15
        vpclmulqdq	ymm7, ymm6, ymm13, 1
        vpslldq	ymm6, ymm6, 8
        vpsllvq	ymm4, ymm5, ymm14
        vpxor	ymm4, ymm4, ymm7
        vpxor	ymm4, ymm4, ymm6
        vpsrlq	ymm9, ymm4, 62
        vpclmulqdq	ymm10, ymm9, ymm13, 1
        vpslldq	ymm9, ymm9, 8
        vpsllq	ymm5, ymm4, 2
        vpxor	ymm5, ymm5, ymm10
        vpxor	ymm5, ymm5, ymm9
        vpsrlq	ymm9, ymm5, 62
        vpclmulqdq	ymm10, ymm9, ymm13, 1
        vpslldq	ymm9, ymm9, 8
        vpsllq	ymm6, ymm5, 2
        vpxor	ymm6, ymm6, ymm10
        vpxor	ymm6, ymm6, ymm9
        vpsrlq	ymm9, ymm6, 62
        vpclmulqdq	ymm10, ymm9, ymm13, 1
        vpslldq	ymm9, ymm9, 8
        vpsllq	ymm7, ymm6, 2
        vpxor	ymm7, ymm7, ymm10
        vpxor	ymm7, ymm7, ymm9
L_AES_XTS_decrypt_vaes_dec_128:
        ; 128 bytes of input
        ; aes_dec_128
        lea	rcx, QWORD PTR [rdi+r13]
        lea	rdx, QWORD PTR [rsi+r13]
        vmovdqu	ymm0, YMMWORD PTR [rcx]
        vmovdqu	ymm1, YMMWORD PTR [rcx+32]
        vmovdqu	ymm2, YMMWORD PTR [rcx+64]
        vmovdqu	ymm3, YMMWORD PTR [rcx+96]
        ; aes_dec_block
        vbroadcasti128	ymm9, [r8]
        vpxor	ymm0, ymm0, ymm4
        vpxor	ymm0, ymm0, ymm9
        vpxor	ymm1, ymm1, ymm5
        vpxor	ymm1, ymm1, ymm9
        vpxor	ymm2, ymm2, ymm6
        vpxor	ymm2, ymm2, ymm9
        vpxor	ymm3, ymm3, ymm7
        vpxor	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r8+16]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vaesdec	ymm2, ymm2, ymm9
        vaesdec	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r8+32]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vaesdec	ymm2, ymm2, ymm9
        vaesdec	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r8+48]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vaesdec	ymm2, ymm2, ymm9
        vaesdec	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r8+64]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vaesdec	ymm2, ymm2, ymm9
        vaesdec	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r8+80]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vaesdec	ymm2, ymm2, ymm9
        vaesdec	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r8+96]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vaesdec	ymm2, ymm2, ymm9
        vaesdec	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r8+112]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vaesdec	ymm2, ymm2, ymm9
        vaesdec	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r8+128]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vaesdec	ymm2, ymm2, ymm9
        vaesdec	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r8+144]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vaesdec	ymm2, ymm2, ymm9
        vaesdec	ymm3, ymm3, ymm9
        cmp	r10d, 11
        vbroadcasti128	ymm9, [r8+160]
        jl	L_AES_XTS_decrypt_vaes_aes_dec_128_aes_dec_block_last
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vaesdec	ymm2, ymm2, ymm9
        vaesdec	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r8+176]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vaesdec	ymm2, ymm2, ymm9
        vaesdec	ymm3, ymm3, ymm9
        cmp	r10d, 13
        vbroadcasti128	ymm9, [r8+192]
        jl	L_AES_XTS_decrypt_vaes_aes_dec_128_aes_dec_block_last
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vaesdec	ymm2, ymm2, ymm9
        vaesdec	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r8+208]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vaesdec	ymm2, ymm2, ymm9
        vaesdec	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r8+224]
L_AES_XTS_decrypt_vaes_aes_dec_128_aes_dec_block_last:
        vaesdeclast	ymm0, ymm0, ymm9
        vaesdeclast	ymm1, ymm1, ymm9
        vaesdeclast	ymm2, ymm2, ymm9
        vaesdeclast	ymm3, ymm3, ymm9
        vpxor	ymm0, ymm0, ymm4
        vmovdqu	YMMWORD PTR [rdx], ymm0
        vpsrlq	ymm9, ymm4, 56
        vpclmulqdq	ymm10, ymm9, ymm13, 1
        vpslldq	ymm9, ymm9, 8
        vpsllq	ymm4, ymm4, 8
        vpxor	ymm4, ymm4, ymm10
        vpxor	ymm4, ymm4, ymm9
        vpxor	ymm1, ymm1, ymm5
        vmovdqu	YMMWORD PTR [rdx+32], ymm1
        vpsrlq	ymm9, ymm5, 56
        vpclmulqdq	ymm10, ymm9, ymm13, 1
        vpslldq	ymm9, ymm9, 8
        vpsllq	ymm5, ymm5, 8
        vpxor	ymm5, ymm5, ymm10
        vpxor	ymm5, ymm5, ymm9
        vpxor	ymm2, ymm2, ymm6
        vmovdqu	YMMWORD PTR [rdx+64], ymm2
        vpsrlq	ymm9, ymm6, 56
        vpclmulqdq	ymm10, ymm9, ymm13, 1
        vpslldq	ymm9, ymm9, 8
        vpsllq	ymm6, ymm6, 8
        vpxor	ymm6, ymm6, ymm10
        vpxor	ymm6, ymm6, ymm9
        vpxor	ymm3, ymm3, ymm7
        vmovdqu	YMMWORD PTR [rdx+96], ymm3
        vpsrlq	ymm9, ymm7, 56
        vpclmulqdq	ymm10, ymm9, ymm13, 1
        vpslldq	ymm9, ymm9, 8
        vpsllq	ymm7, ymm7, 8
        vpxor	ymm7, ymm7, ymm10
        vpxor	ymm7, ymm7, ymm9
        add	r13d, 128
        cmp	r13d, r11d
        jl	L_AES_XTS_decrypt_vaes_dec_128
        vextracti128	xmm8, ymm4, 0
L_AES_XTS_decrypt_vaes_done_128:
        cmp	r13d, eax
        mov	r11d, eax
        je	L_AES_XTS_decrypt_vaes_done_dec
        and	r11d, 4294967280
        cmp	r11d, eax
        je	L_AES_XTS_decrypt_vaes_mul16_64
        sub	r11d, 16
        sub	r11d, r13d
        cmp	r11d, 16
        jl	L_AES_XTS_decrypt_vaes_last_31_start
        add	r11d, r13d
L_AES_XTS_decrypt_vaes_mul16_64:
        and	r11d, 4294967232
        cmp	r13d, r11d
        je	L_AES_XTS_decrypt_vaes_done_64
        ; 64 bytes of input
        ; aes_dec_64
        lea	rcx, QWORD PTR [rdi+r13]
        lea	rdx, QWORD PTR [rsi+r13]
        vmovdqu	ymm0, YMMWORD PTR [rcx]
        vmovdqu	ymm1, YMMWORD PTR [rcx+32]
        vperm2i128	ymm5, ymm8, ymm8, 0
        vpsrlvq	ymm6, ymm5, ymm15
        vpclmulqdq	ymm7, ymm6, ymm13, 1
        vpslldq	ymm6, ymm6, 8
        vpsllvq	ymm4, ymm5, ymm14
        vpxor	ymm4, ymm4, ymm7
        vpxor	ymm4, ymm4, ymm6
        vpsrlq	ymm9, ymm4, 62
        vpclmulqdq	ymm10, ymm9, ymm13, 1
        vpslldq	ymm9, ymm9, 8
        vpsllq	ymm5, ymm4, 2
        vpxor	ymm5, ymm5, ymm10
        vpxor	ymm5, ymm5, ymm9
        ; aes_dec_block
        vbroadcasti128	ymm9, [r8]
        vpxor	ymm0, ymm0, ymm4
        vpxor	ymm0, ymm0, ymm9
        vpxor	ymm1, ymm1, ymm5
        vpxor	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r8+16]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r8+32]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r8+48]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r8+64]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r8+80]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r8+96]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r8+112]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r8+128]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r8+144]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        cmp	r10d, 11
        vbroadcasti128	ymm9, [r8+160]
        jl	L_AES_XTS_decrypt_vaes_aes_dec_64_aes_dec_block_last
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r8+176]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        cmp	r10d, 13
        vbroadcasti128	ymm9, [r8+192]
        jl	L_AES_XTS_decrypt_vaes_aes_dec_64_aes_dec_block_last
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r8+208]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r8+224]
L_AES_XTS_decrypt_vaes_aes_dec_64_aes_dec_block_last:
        vaesdeclast	ymm0, ymm0, ymm9
        vaesdeclast	ymm1, ymm1, ymm9
        vpxor	ymm0, ymm0, ymm4
        vmovdqu	YMMWORD PTR [rdx], ymm0
        vpxor	ymm1, ymm1, ymm5
        vmovdqu	YMMWORD PTR [rdx+32], ymm1
        vextracti128	xmm8, ymm5, 1
        vpshufd	xmm9, xmm8, 19
        vpaddq	xmm8, xmm8, xmm8
        vpsrad	xmm9, xmm9, 31
        vpand	xmm9, xmm9, xmm12
        vpxor	xmm8, xmm8, xmm9
        add	r13d, 64
L_AES_XTS_decrypt_vaes_done_64:
        cmp	r13d, eax
        mov	r11d, eax
        je	L_AES_XTS_decrypt_vaes_done_dec
        and	r11d, 4294967280
        cmp	r11d, eax
        je	L_AES_XTS_decrypt_vaes_mul16_32
        sub	r11d, 16
        sub	r11d, r13d
        cmp	r11d, 16
        jl	L_AES_XTS_decrypt_vaes_last_31_start
        add	r11d, r13d
L_AES_XTS_decrypt_vaes_mul16_32:
        and	r11d, 4294967264
        cmp	r13d, r11d
        je	L_AES_XTS_decrypt_vaes_done_32
        ; 32 bytes of input
        ; aes_dec_32
        lea	rcx, QWORD PTR [rdi+r13]
        lea	rdx, QWORD PTR [rsi+r13]
        vmovdqu	ymm0, YMMWORD PTR [rcx]
        vperm2i128	ymm5, ymm8, ymm8, 0
        vpsrlvq	ymm6, ymm5, ymm15
        vpclmulqdq	ymm7, ymm6, ymm13, 1
        vpslldq	ymm6, ymm6, 8
        vpsllvq	ymm4, ymm5, ymm14
        vpxor	ymm4, ymm4, ymm7
        vpxor	ymm4, ymm4, ymm6
        ; aes_dec_block
        vbroadcasti128	ymm9, [r8]
        vpxor	ymm0, ymm0, ymm4
        vpxor	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r8+16]
        vaesdec	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r8+32]
        vaesdec	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r8+48]
        vaesdec	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r8+64]
        vaesdec	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r8+80]
        vaesdec	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r8+96]
        vaesdec	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r8+112]
        vaesdec	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r8+128]
        vaesdec	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r8+144]
        vaesdec	ymm0, ymm0, ymm9
        cmp	r10d, 11
        vbroadcasti128	ymm9, [r8+160]
        jl	L_AES_XTS_decrypt_vaes_aes_dec_32_aes_dec_block_last
        vaesdec	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r8+176]
        vaesdec	ymm0, ymm0, ymm9
        cmp	r10d, 13
        vbroadcasti128	ymm9, [r8+192]
        jl	L_AES_XTS_decrypt_vaes_aes_dec_32_aes_dec_block_last
        vaesdec	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r8+208]
        vaesdec	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r8+224]
L_AES_XTS_decrypt_vaes_aes_dec_32_aes_dec_block_last:
        vaesdeclast	ymm0, ymm0, ymm9
        vpxor	ymm0, ymm0, ymm4
        vmovdqu	YMMWORD PTR [rdx], ymm0
        vextracti128	xmm8, ymm4, 1
        vpshufd	xmm9, xmm8, 19
        vpaddq	xmm8, xmm8, xmm8
        vpsrad	xmm9, xmm9, 31
        vpand	xmm9, xmm9, xmm12
        vpxor	xmm8, xmm8, xmm9
        add	r13d, 32
L_AES_XTS_decrypt_vaes_done_32:
        cmp	r13d, eax
        mov	r11d, eax
        je	L_AES_XTS_decrypt_vaes_done_dec
        and	r11d, 4294967280
        cmp	r11d, eax
        je	L_AES_XTS_decrypt_vaes_mul16
        sub	r11d, 16
        sub	r11d, r13d
        cmp	r11d, 16
        jl	L_AES_XTS_decrypt_vaes_last_31_start
        add	r11d, r13d
L_AES_XTS_decrypt_vaes_mul16:
L_AES_XTS_decrypt_vaes_dec_16:
        ; 16 bytes of input
        lea	rcx, QWORD PTR [rdi+r13]
        vmovdqu	xmm0, OWORD PTR [rcx]
        vpxor	xmm0, xmm0, xmm8
        ; aes_dec_block
        vpxor	xmm0, xmm0, [r8]
        vmovdqu	xmm5, OWORD PTR [r8+16]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+32]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+48]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+64]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+80]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+96]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+112]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+128]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+144]
        vaesdec	xmm0, xmm0, xmm5
        cmp	r10d, 11
        vmovdqu	xmm5, OWORD PTR [r8+160]
        jl	L_AES_XTS_decrypt_vaes_aes_dec_block_last
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r8+176]
        vaesdec	xmm0, xmm0, xmm6
        cmp	r10d, 13
        vmovdqu	xmm5, OWORD PTR [r8+192]
        jl	L_AES_XTS_decrypt_vaes_aes_dec_block_last
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r8+208]
        vaesdec	xmm0, xmm0, xmm6
        vmovdqu	xmm5, OWORD PTR [r8+224]
L_AES_XTS_decrypt_vaes_aes_dec_block_last:
        vaesdeclast	xmm0, xmm0, xmm5
        vpxor	xmm0, xmm0, xmm8
        lea	rcx, QWORD PTR [rsi+r13]
        vmovdqu	OWORD PTR [rcx], xmm0
        vpshufd	xmm4, xmm8, 19
        vpaddq	xmm8, xmm8, xmm8
        vpsrad	xmm4, xmm4, 31
        vpand	xmm4, xmm4, xmm12
        vpxor	xmm8, xmm8, xmm4
        add	r13d, 16
        cmp	r13d, r11d
        jl	L_AES_XTS_decrypt_vaes_dec_16
        cmp	r13d, eax
        je	L_AES_XTS_decrypt_vaes_done_dec
L_AES_XTS_decrypt_vaes_last_31_start:
        vpshufd	xmm4, xmm8, 19
        vpaddq	xmm7, xmm8, xmm8
        vpsrad	xmm4, xmm4, 31
        vpand	xmm4, xmm4, xmm12
        vpxor	xmm7, xmm7, xmm4
        lea	rcx, QWORD PTR [rdi+r13]
        vmovdqu	xmm0, OWORD PTR [rcx]
        vpxor	xmm0, xmm0, xmm7
        ; aes_dec_block
        vpxor	xmm0, xmm0, [r8]
        vmovdqu	xmm5, OWORD PTR [r8+16]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+32]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+48]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+64]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+80]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+96]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+112]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+128]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+144]
        vaesdec	xmm0, xmm0, xmm5
        cmp	r10d, 11
        vmovdqu	xmm5, OWORD PTR [r8+160]
        jl	L_AES_XTS_decrypt_vaes_last_31_aes_dec_block_last
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r8+176]
        vaesdec	xmm0, xmm0, xmm6
        cmp	r10d, 13
        vmovdqu	xmm5, OWORD PTR [r8+192]
        jl	L_AES_XTS_decrypt_vaes_last_31_aes_dec_block_last
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r8+208]
        vaesdec	xmm0, xmm0, xmm6
        vmovdqu	xmm5, OWORD PTR [r8+224]
L_AES_XTS_decrypt_vaes_last_31_aes_dec_block_last:
        vaesdeclast	xmm0, xmm0, xmm5
        vpxor	xmm0, xmm0, xmm7
        vmovdqu	OWORD PTR [rsp], xmm0
        add	r13, 16
        xor	rdx, rdx
L_AES_XTS_decrypt_vaes_last_31_byte_loop:
        mov	r11b, BYTE PTR [rsp+rdx]
        mov	cl, BYTE PTR [rdi+r13]
        mov	BYTE PTR [rsi+r13], r11b
        mov	BYTE PTR [rsp+rdx], cl
        inc	r13d
        inc	edx
        cmp	r13d, eax
        jl	L_AES_XTS_decrypt_vaes_last_31_byte_loop
        sub	r13, rdx
        vmovdqu	xmm0, OWORD PTR [rsp]
        vpxor	xmm0, xmm0, xmm8
        ; aes_dec_block
        vpxor	xmm0, xmm0, [r8]
        vmovdqu	xmm5, OWORD PTR [r8+16]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+32]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+48]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+64]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+80]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+96]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+112]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+128]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+144]
        vaesdec	xmm0, xmm0, xmm5
        cmp	r10d, 11
        vmovdqu	xmm5, OWORD PTR [r8+160]
        jl	L_AES_XTS_decrypt_vaes_last_31_2_aes_dec_block_last
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r8+176]
        vaesdec	xmm0, xmm0, xmm6
        cmp	r10d, 13
        vmovdqu	xmm5, OWORD PTR [r8+192]
        jl	L_AES_XTS_decrypt_vaes_last_31_2_aes_dec_block_last
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r8+208]
        vaesdec	xmm0, xmm0, xmm6
        vmovdqu	xmm5, OWORD PTR [r8+224]
L_AES_XTS_decrypt_vaes_last_31_2_aes_dec_block_last:
        vaesdeclast	xmm0, xmm0, xmm5
        vpxor	xmm0, xmm0, xmm8
        sub	r13, 16
        lea	rcx, QWORD PTR [rsi+r13]
        vmovdqu	OWORD PTR [rcx], xmm0
L_AES_XTS_decrypt_vaes_done_dec:
        vmovdqu	xmm6, OWORD PTR [rsp+64]
        vmovdqu	xmm7, OWORD PTR [rsp+80]
        vmovdqu	xmm8, OWORD PTR [rsp+96]
        vmovdqu	xmm9, OWORD PTR [rsp+112]
        vmovdqu	xmm10, OWORD PTR [rsp+128]
        vmovdqu	xmm11, OWORD PTR [rsp+144]
        vmovdqu	xmm12, OWORD PTR [rsp+160]
        vmovdqu	xmm13, OWORD PTR [rsp+176]
        vmovdqu	xmm14, OWORD PTR [rsp+192]
        vmovdqu	xmm15, OWORD PTR [rsp+208]
        add	rsp, 224
        pop	r13
        pop	r12
        pop	rsi
        pop	rdi
        ret
AES_XTS_decrypt_vaes ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_XTS_decrypt_update_vaes PROC
        push	rdi
        push	rsi
        push	r12
        mov	rdi, rcx
        mov	rsi, rdx
        mov	rax, r8
        mov	r10, r9
        mov	r8, QWORD PTR [rsp+64]
        mov	r9d, DWORD PTR [rsp+72]
        sub	rsp, 224
        vmovdqu	OWORD PTR [rsp+64], xmm6
        vmovdqu	OWORD PTR [rsp+80], xmm7
        vmovdqu	OWORD PTR [rsp+96], xmm8
        vmovdqu	OWORD PTR [rsp+112], xmm9
        vmovdqu	OWORD PTR [rsp+128], xmm10
        vmovdqu	OWORD PTR [rsp+144], xmm11
        vmovdqu	OWORD PTR [rsp+160], xmm12
        vmovdqu	OWORD PTR [rsp+176], xmm13
        vmovdqu	OWORD PTR [rsp+192], xmm14
        vmovdqu	OWORD PTR [rsp+208], xmm15
        vmovdqu	xmm12, OWORD PTR L_vaes_aes_xts_gc_xts
        vbroadcasti128	ymm13, ptr_L_vaes_aes_xts_poly
        vmovdqu	ymm14, YMMWORD PTR L_vaes_aes_xts_shl
        vmovdqu	ymm15, YMMWORD PTR L_vaes_aes_xts_shr
        vmovdqu	xmm8, OWORD PTR [r8]
        xor	r12d, r12d
        mov	r11d, eax
        and	r11d, 4294967280
        cmp	r11d, eax
        je	L_AES_XTS_decrypt_update_vaes_mul16_128
        sub	r11d, 16
        cmp	r11d, 16
        jl	L_AES_XTS_decrypt_update_vaes_last_31_start
L_AES_XTS_decrypt_update_vaes_mul16_128:
        cmp	r11d, 32
        jl	L_AES_XTS_decrypt_update_vaes_done_128
        cmp	r11d, 128
        jl	L_AES_XTS_decrypt_update_vaes_done_128
        and	r11d, 4294967168
        vperm2i128	ymm5, ymm8, ymm8, 0
        vpsrlvq	ymm6, ymm5, ymm15
        vpclmulqdq	ymm7, ymm6, ymm13, 1
        vpslldq	ymm6, ymm6, 8
        vpsllvq	ymm4, ymm5, ymm14
        vpxor	ymm4, ymm4, ymm7
        vpxor	ymm4, ymm4, ymm6
        vpsrlq	ymm9, ymm4, 62
        vpclmulqdq	ymm10, ymm9, ymm13, 1
        vpslldq	ymm9, ymm9, 8
        vpsllq	ymm5, ymm4, 2
        vpxor	ymm5, ymm5, ymm10
        vpxor	ymm5, ymm5, ymm9
        vpsrlq	ymm9, ymm5, 62
        vpclmulqdq	ymm10, ymm9, ymm13, 1
        vpslldq	ymm9, ymm9, 8
        vpsllq	ymm6, ymm5, 2
        vpxor	ymm6, ymm6, ymm10
        vpxor	ymm6, ymm6, ymm9
        vpsrlq	ymm9, ymm6, 62
        vpclmulqdq	ymm10, ymm9, ymm13, 1
        vpslldq	ymm9, ymm9, 8
        vpsllq	ymm7, ymm6, 2
        vpxor	ymm7, ymm7, ymm10
        vpxor	ymm7, ymm7, ymm9
L_AES_XTS_decrypt_update_vaes_dec_128:
        ; 128 bytes of input
        ; aes_dec_128
        lea	rcx, QWORD PTR [rdi+r12]
        lea	rdx, QWORD PTR [rsi+r12]
        vmovdqu	ymm0, YMMWORD PTR [rcx]
        vmovdqu	ymm1, YMMWORD PTR [rcx+32]
        vmovdqu	ymm2, YMMWORD PTR [rcx+64]
        vmovdqu	ymm3, YMMWORD PTR [rcx+96]
        ; aes_dec_block
        vbroadcasti128	ymm9, [r10]
        vpxor	ymm0, ymm0, ymm4
        vpxor	ymm0, ymm0, ymm9
        vpxor	ymm1, ymm1, ymm5
        vpxor	ymm1, ymm1, ymm9
        vpxor	ymm2, ymm2, ymm6
        vpxor	ymm2, ymm2, ymm9
        vpxor	ymm3, ymm3, ymm7
        vpxor	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r10+16]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vaesdec	ymm2, ymm2, ymm9
        vaesdec	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r10+32]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vaesdec	ymm2, ymm2, ymm9
        vaesdec	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r10+48]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vaesdec	ymm2, ymm2, ymm9
        vaesdec	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r10+64]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vaesdec	ymm2, ymm2, ymm9
        vaesdec	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r10+80]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vaesdec	ymm2, ymm2, ymm9
        vaesdec	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r10+96]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vaesdec	ymm2, ymm2, ymm9
        vaesdec	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r10+112]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vaesdec	ymm2, ymm2, ymm9
        vaesdec	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r10+128]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vaesdec	ymm2, ymm2, ymm9
        vaesdec	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r10+144]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vaesdec	ymm2, ymm2, ymm9
        vaesdec	ymm3, ymm3, ymm9
        cmp	r9d, 11
        vbroadcasti128	ymm9, [r10+160]
        jl	L_AES_XTS_decrypt_update_vaes_aes_dec_128_aes_dec_block_last
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vaesdec	ymm2, ymm2, ymm9
        vaesdec	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r10+176]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vaesdec	ymm2, ymm2, ymm9
        vaesdec	ymm3, ymm3, ymm9
        cmp	r9d, 13
        vbroadcasti128	ymm9, [r10+192]
        jl	L_AES_XTS_decrypt_update_vaes_aes_dec_128_aes_dec_block_last
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vaesdec	ymm2, ymm2, ymm9
        vaesdec	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r10+208]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vaesdec	ymm2, ymm2, ymm9
        vaesdec	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [r10+224]
L_AES_XTS_decrypt_update_vaes_aes_dec_128_aes_dec_block_last:
        vaesdeclast	ymm0, ymm0, ymm9
        vaesdeclast	ymm1, ymm1, ymm9
        vaesdeclast	ymm2, ymm2, ymm9
        vaesdeclast	ymm3, ymm3, ymm9
        vpxor	ymm0, ymm0, ymm4
        vmovdqu	YMMWORD PTR [rdx], ymm0
        vpsrlq	ymm9, ymm4, 56
        vpclmulqdq	ymm10, ymm9, ymm13, 1
        vpslldq	ymm9, ymm9, 8
        vpsllq	ymm4, ymm4, 8
        vpxor	ymm4, ymm4, ymm10
        vpxor	ymm4, ymm4, ymm9
        vpxor	ymm1, ymm1, ymm5
        vmovdqu	YMMWORD PTR [rdx+32], ymm1
        vpsrlq	ymm9, ymm5, 56
        vpclmulqdq	ymm10, ymm9, ymm13, 1
        vpslldq	ymm9, ymm9, 8
        vpsllq	ymm5, ymm5, 8
        vpxor	ymm5, ymm5, ymm10
        vpxor	ymm5, ymm5, ymm9
        vpxor	ymm2, ymm2, ymm6
        vmovdqu	YMMWORD PTR [rdx+64], ymm2
        vpsrlq	ymm9, ymm6, 56
        vpclmulqdq	ymm10, ymm9, ymm13, 1
        vpslldq	ymm9, ymm9, 8
        vpsllq	ymm6, ymm6, 8
        vpxor	ymm6, ymm6, ymm10
        vpxor	ymm6, ymm6, ymm9
        vpxor	ymm3, ymm3, ymm7
        vmovdqu	YMMWORD PTR [rdx+96], ymm3
        vpsrlq	ymm9, ymm7, 56
        vpclmulqdq	ymm10, ymm9, ymm13, 1
        vpslldq	ymm9, ymm9, 8
        vpsllq	ymm7, ymm7, 8
        vpxor	ymm7, ymm7, ymm10
        vpxor	ymm7, ymm7, ymm9
        add	r12d, 128
        cmp	r12d, r11d
        jl	L_AES_XTS_decrypt_update_vaes_dec_128
        vextracti128	xmm8, ymm4, 0
L_AES_XTS_decrypt_update_vaes_done_128:
        cmp	r12d, eax
        mov	r11d, eax
        je	L_AES_XTS_decrypt_update_vaes_done_dec
        and	r11d, 4294967280
        cmp	r11d, eax
        je	L_AES_XTS_decrypt_update_vaes_mul16_64
        sub	r11d, 16
        sub	r11d, r12d
        cmp	r11d, 16
        jl	L_AES_XTS_decrypt_update_vaes_last_31_start
        add	r11d, r12d
L_AES_XTS_decrypt_update_vaes_mul16_64:
        and	r11d, 4294967232
        cmp	r12d, r11d
        je	L_AES_XTS_decrypt_update_vaes_done_64
        ; 64 bytes of input
        ; aes_dec_64
        lea	rcx, QWORD PTR [rdi+r12]
        lea	rdx, QWORD PTR [rsi+r12]
        vmovdqu	ymm0, YMMWORD PTR [rcx]
        vmovdqu	ymm1, YMMWORD PTR [rcx+32]
        vperm2i128	ymm5, ymm8, ymm8, 0
        vpsrlvq	ymm6, ymm5, ymm15
        vpclmulqdq	ymm7, ymm6, ymm13, 1
        vpslldq	ymm6, ymm6, 8
        vpsllvq	ymm4, ymm5, ymm14
        vpxor	ymm4, ymm4, ymm7
        vpxor	ymm4, ymm4, ymm6
        vpsrlq	ymm9, ymm4, 62
        vpclmulqdq	ymm10, ymm9, ymm13, 1
        vpslldq	ymm9, ymm9, 8
        vpsllq	ymm5, ymm4, 2
        vpxor	ymm5, ymm5, ymm10
        vpxor	ymm5, ymm5, ymm9
        ; aes_dec_block
        vbroadcasti128	ymm9, [r10]
        vpxor	ymm0, ymm0, ymm4
        vpxor	ymm0, ymm0, ymm9
        vpxor	ymm1, ymm1, ymm5
        vpxor	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r10+16]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r10+32]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r10+48]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r10+64]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r10+80]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r10+96]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r10+112]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r10+128]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r10+144]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        cmp	r9d, 11
        vbroadcasti128	ymm9, [r10+160]
        jl	L_AES_XTS_decrypt_update_vaes_aes_dec_64_aes_dec_block_last
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r10+176]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        cmp	r9d, 13
        vbroadcasti128	ymm9, [r10+192]
        jl	L_AES_XTS_decrypt_update_vaes_aes_dec_64_aes_dec_block_last
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r10+208]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [r10+224]
L_AES_XTS_decrypt_update_vaes_aes_dec_64_aes_dec_block_last:
        vaesdeclast	ymm0, ymm0, ymm9
        vaesdeclast	ymm1, ymm1, ymm9
        vpxor	ymm0, ymm0, ymm4
        vmovdqu	YMMWORD PTR [rdx], ymm0
        vpxor	ymm1, ymm1, ymm5
        vmovdqu	YMMWORD PTR [rdx+32], ymm1
        vextracti128	xmm8, ymm5, 1
        vpshufd	xmm9, xmm8, 19
        vpaddq	xmm8, xmm8, xmm8
        vpsrad	xmm9, xmm9, 31
        vpand	xmm9, xmm9, xmm12
        vpxor	xmm8, xmm8, xmm9
        add	r12d, 64
L_AES_XTS_decrypt_update_vaes_done_64:
        cmp	r12d, eax
        mov	r11d, eax
        je	L_AES_XTS_decrypt_update_vaes_done_dec
        and	r11d, 4294967280
        cmp	r11d, eax
        je	L_AES_XTS_decrypt_update_vaes_mul16_32
        sub	r11d, 16
        sub	r11d, r12d
        cmp	r11d, 16
        jl	L_AES_XTS_decrypt_update_vaes_last_31_start
        add	r11d, r12d
L_AES_XTS_decrypt_update_vaes_mul16_32:
        and	r11d, 4294967264
        cmp	r12d, r11d
        je	L_AES_XTS_decrypt_update_vaes_done_32
        ; 32 bytes of input
        ; aes_dec_32
        lea	rcx, QWORD PTR [rdi+r12]
        lea	rdx, QWORD PTR [rsi+r12]
        vmovdqu	ymm0, YMMWORD PTR [rcx]
        vperm2i128	ymm5, ymm8, ymm8, 0
        vpsrlvq	ymm6, ymm5, ymm15
        vpclmulqdq	ymm7, ymm6, ymm13, 1
        vpslldq	ymm6, ymm6, 8
        vpsllvq	ymm4, ymm5, ymm14
        vpxor	ymm4, ymm4, ymm7
        vpxor	ymm4, ymm4, ymm6
        ; aes_dec_block
        vbroadcasti128	ymm9, [r10]
        vpxor	ymm0, ymm0, ymm4
        vpxor	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r10+16]
        vaesdec	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r10+32]
        vaesdec	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r10+48]
        vaesdec	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r10+64]
        vaesdec	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r10+80]
        vaesdec	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r10+96]
        vaesdec	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r10+112]
        vaesdec	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r10+128]
        vaesdec	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r10+144]
        vaesdec	ymm0, ymm0, ymm9
        cmp	r9d, 11
        vbroadcasti128	ymm9, [r10+160]
        jl	L_AES_XTS_decrypt_update_vaes_aes_dec_32_aes_dec_block_last
        vaesdec	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r10+176]
        vaesdec	ymm0, ymm0, ymm9
        cmp	r9d, 13
        vbroadcasti128	ymm9, [r10+192]
        jl	L_AES_XTS_decrypt_update_vaes_aes_dec_32_aes_dec_block_last
        vaesdec	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r10+208]
        vaesdec	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [r10+224]
L_AES_XTS_decrypt_update_vaes_aes_dec_32_aes_dec_block_last:
        vaesdeclast	ymm0, ymm0, ymm9
        vpxor	ymm0, ymm0, ymm4
        vmovdqu	YMMWORD PTR [rdx], ymm0
        vextracti128	xmm8, ymm4, 1
        vpshufd	xmm9, xmm8, 19
        vpaddq	xmm8, xmm8, xmm8
        vpsrad	xmm9, xmm9, 31
        vpand	xmm9, xmm9, xmm12
        vpxor	xmm8, xmm8, xmm9
        add	r12d, 32
L_AES_XTS_decrypt_update_vaes_done_32:
        cmp	r12d, eax
        mov	r11d, eax
        je	L_AES_XTS_decrypt_update_vaes_done_dec
        and	r11d, 4294967280
        cmp	r11d, eax
        je	L_AES_XTS_decrypt_update_vaes_mul16
        sub	r11d, 16
        sub	r11d, r12d
        cmp	r11d, 16
        jl	L_AES_XTS_decrypt_update_vaes_last_31_start
        add	r11d, r12d
L_AES_XTS_decrypt_update_vaes_mul16:
L_AES_XTS_decrypt_update_vaes_dec_16:
        ; 16 bytes of input
        lea	rcx, QWORD PTR [rdi+r12]
        vmovdqu	xmm0, OWORD PTR [rcx]
        vpxor	xmm0, xmm0, xmm8
        ; aes_dec_block
        vpxor	xmm0, xmm0, [r10]
        vmovdqu	xmm5, OWORD PTR [r10+16]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+32]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+48]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+64]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+80]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+96]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+112]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+128]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+144]
        vaesdec	xmm0, xmm0, xmm5
        cmp	r9d, 11
        vmovdqu	xmm5, OWORD PTR [r10+160]
        jl	L_AES_XTS_decrypt_update_vaes_aes_dec_block_last
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r10+176]
        vaesdec	xmm0, xmm0, xmm6
        cmp	r9d, 13
        vmovdqu	xmm5, OWORD PTR [r10+192]
        jl	L_AES_XTS_decrypt_update_vaes_aes_dec_block_last
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r10+208]
        vaesdec	xmm0, xmm0, xmm6
        vmovdqu	xmm5, OWORD PTR [r10+224]
L_AES_XTS_decrypt_update_vaes_aes_dec_block_last:
        vaesdeclast	xmm0, xmm0, xmm5
        vpxor	xmm0, xmm0, xmm8
        lea	rcx, QWORD PTR [rsi+r12]
        vmovdqu	OWORD PTR [rcx], xmm0
        vpshufd	xmm4, xmm8, 19
        vpaddq	xmm8, xmm8, xmm8
        vpsrad	xmm4, xmm4, 31
        vpand	xmm4, xmm4, xmm12
        vpxor	xmm8, xmm8, xmm4
        add	r12d, 16
        cmp	r12d, r11d
        jl	L_AES_XTS_decrypt_update_vaes_dec_16
        cmp	r12d, eax
        je	L_AES_XTS_decrypt_update_vaes_done_dec
L_AES_XTS_decrypt_update_vaes_last_31_start:
        vpshufd	xmm4, xmm8, 19
        vpaddq	xmm7, xmm8, xmm8
        vpsrad	xmm4, xmm4, 31
        vpand	xmm4, xmm4, xmm12
        vpxor	xmm7, xmm7, xmm4
        lea	rcx, QWORD PTR [rdi+r12]
        vmovdqu	xmm0, OWORD PTR [rcx]
        vpxor	xmm0, xmm0, xmm7
        ; aes_dec_block
        vpxor	xmm0, xmm0, [r10]
        vmovdqu	xmm5, OWORD PTR [r10+16]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+32]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+48]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+64]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+80]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+96]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+112]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+128]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+144]
        vaesdec	xmm0, xmm0, xmm5
        cmp	r9d, 11
        vmovdqu	xmm5, OWORD PTR [r10+160]
        jl	L_AES_XTS_decrypt_update_vaes_last_31_aes_dec_block_last
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r10+176]
        vaesdec	xmm0, xmm0, xmm6
        cmp	r9d, 13
        vmovdqu	xmm5, OWORD PTR [r10+192]
        jl	L_AES_XTS_decrypt_update_vaes_last_31_aes_dec_block_last
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r10+208]
        vaesdec	xmm0, xmm0, xmm6
        vmovdqu	xmm5, OWORD PTR [r10+224]
L_AES_XTS_decrypt_update_vaes_last_31_aes_dec_block_last:
        vaesdeclast	xmm0, xmm0, xmm5
        vpxor	xmm0, xmm0, xmm7
        vmovdqu	OWORD PTR [rsp], xmm0
        add	r12, 16
        xor	rdx, rdx
L_AES_XTS_decrypt_update_vaes_last_31_byte_loop:
        mov	r11b, BYTE PTR [rsp+rdx]
        mov	cl, BYTE PTR [rdi+r12]
        mov	BYTE PTR [rsi+r12], r11b
        mov	BYTE PTR [rsp+rdx], cl
        inc	r12d
        inc	edx
        cmp	r12d, eax
        jl	L_AES_XTS_decrypt_update_vaes_last_31_byte_loop
        sub	r12, rdx
        vmovdqu	xmm0, OWORD PTR [rsp]
        vpxor	xmm0, xmm0, xmm8
        ; aes_dec_block
        vpxor	xmm0, xmm0, [r10]
        vmovdqu	xmm5, OWORD PTR [r10+16]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+32]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+48]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+64]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+80]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+96]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+112]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+128]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+144]
        vaesdec	xmm0, xmm0, xmm5
        cmp	r9d, 11
        vmovdqu	xmm5, OWORD PTR [r10+160]
        jl	L_AES_XTS_decrypt_update_vaes_last_31_2_aes_dec_block_last
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r10+176]
        vaesdec	xmm0, xmm0, xmm6
        cmp	r9d, 13
        vmovdqu	xmm5, OWORD PTR [r10+192]
        jl	L_AES_XTS_decrypt_update_vaes_last_31_2_aes_dec_block_last
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r10+208]
        vaesdec	xmm0, xmm0, xmm6
        vmovdqu	xmm5, OWORD PTR [r10+224]
L_AES_XTS_decrypt_update_vaes_last_31_2_aes_dec_block_last:
        vaesdeclast	xmm0, xmm0, xmm5
        vpxor	xmm0, xmm0, xmm8
        sub	r12, 16
        lea	rcx, QWORD PTR [rsi+r12]
        vmovdqu	OWORD PTR [rcx], xmm0
L_AES_XTS_decrypt_update_vaes_done_dec:
        vmovdqu	OWORD PTR [r8], xmm8
        vmovdqu	xmm6, OWORD PTR [rsp+64]
        vmovdqu	xmm7, OWORD PTR [rsp+80]
        vmovdqu	xmm8, OWORD PTR [rsp+96]
        vmovdqu	xmm9, OWORD PTR [rsp+112]
        vmovdqu	xmm10, OWORD PTR [rsp+128]
        vmovdqu	xmm11, OWORD PTR [rsp+144]
        vmovdqu	xmm12, OWORD PTR [rsp+160]
        vmovdqu	xmm13, OWORD PTR [rsp+176]
        vmovdqu	xmm14, OWORD PTR [rsp+192]
        vmovdqu	xmm15, OWORD PTR [rsp+208]
        add	rsp, 224
        pop	r12
        pop	rsi
        pop	rdi
        ret
AES_XTS_decrypt_update_vaes ENDP
_TEXT ENDS
ENDIF
IFDEF HAVE_INTEL_AVX512
_TEXT SEGMENT READONLY PARA
AES_XTS_init_avx512 PROC
        vmovdqu	xmm0, OWORD PTR [rcx]
        ; aes_enc_block
        vpxor	xmm0, xmm0, [rdx]
        vmovdqu	xmm2, OWORD PTR [rdx+16]
        vaesenc	xmm0, xmm0, xmm2
        vmovdqu	xmm2, OWORD PTR [rdx+32]
        vaesenc	xmm0, xmm0, xmm2
        vmovdqu	xmm2, OWORD PTR [rdx+48]
        vaesenc	xmm0, xmm0, xmm2
        vmovdqu	xmm2, OWORD PTR [rdx+64]
        vaesenc	xmm0, xmm0, xmm2
        vmovdqu	xmm2, OWORD PTR [rdx+80]
        vaesenc	xmm0, xmm0, xmm2
        vmovdqu	xmm2, OWORD PTR [rdx+96]
        vaesenc	xmm0, xmm0, xmm2
        vmovdqu	xmm2, OWORD PTR [rdx+112]
        vaesenc	xmm0, xmm0, xmm2
        vmovdqu	xmm2, OWORD PTR [rdx+128]
        vaesenc	xmm0, xmm0, xmm2
        vmovdqu	xmm2, OWORD PTR [rdx+144]
        vaesenc	xmm0, xmm0, xmm2
        cmp	r8d, 11
        vmovdqu	xmm2, OWORD PTR [rdx+160]
        jl	L_AES_XTS_init_avx512_tweak_aes_enc_block_last
        vaesenc	xmm0, xmm0, xmm2
        vmovdqu	xmm3, OWORD PTR [rdx+176]
        vaesenc	xmm0, xmm0, xmm3
        cmp	r8d, 13
        vmovdqu	xmm2, OWORD PTR [rdx+192]
        jl	L_AES_XTS_init_avx512_tweak_aes_enc_block_last
        vaesenc	xmm0, xmm0, xmm2
        vmovdqu	xmm3, OWORD PTR [rdx+208]
        vaesenc	xmm0, xmm0, xmm3
        vmovdqu	xmm2, OWORD PTR [rdx+224]
L_AES_XTS_init_avx512_tweak_aes_enc_block_last:
        vaesenclast	xmm0, xmm0, xmm2
        vmovdqu	OWORD PTR [rcx], xmm0
        ret
AES_XTS_init_avx512 ENDP
_TEXT ENDS
_DATA SEGMENT
ALIGN 16
L_avx512_aes_xts_gc_xts DWORD \
     00000087h,  00000000h,  00000001h,  00000000h
ptr_L_avx512_aes_xts_gc_xts QWORD L_avx512_aes_xts_gc_xts
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_avx512_aes_xts_poly DWORD \
     00000087h,  00000000h,  00000000h,  00000000h
ptr_L_avx512_aes_xts_poly QWORD L_avx512_aes_xts_poly
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_avx512_aes_xts_shl DWORD \
     00000000h,  00000000h,  00000000h,  00000000h,
     00000001h,  00000000h,  00000001h,  00000000h,
     00000002h,  00000000h,  00000002h,  00000000h,
     00000003h,  00000000h,  00000003h,  00000000h
ptr_L_avx512_aes_xts_shl QWORD L_avx512_aes_xts_shl
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_avx512_aes_xts_shr DWORD \
     00000040h,  00000000h,  00000040h,  00000000h,
     0000003fh,  00000000h,  0000003fh,  00000000h,
     0000003eh,  00000000h,  0000003eh,  00000000h,
     0000003dh,  00000000h,  0000003dh,  00000000h
ptr_L_avx512_aes_xts_shr QWORD L_avx512_aes_xts_shr
_DATA ENDS
_TEXT SEGMENT READONLY PARA
AES_XTS_encrypt_avx512 PROC
        push	rdi
        push	rsi
        push	r12
        push	r13
        mov	rdi, rcx
        mov	rsi, rdx
        mov	rax, r8
        mov	r12, r9
        mov	r8, QWORD PTR [rsp+72]
        mov	r9, QWORD PTR [rsp+80]
        mov	r10d, DWORD PTR [rsp+88]
        sub	rsp, 224
        vmovdqu	OWORD PTR [rsp+64], xmm6
        vmovdqu	OWORD PTR [rsp+80], xmm7
        vmovdqu	OWORD PTR [rsp+96], xmm8
        vmovdqu	OWORD PTR [rsp+112], xmm9
        vmovdqu	OWORD PTR [rsp+128], xmm10
        vmovdqu	OWORD PTR [rsp+144], xmm11
        vmovdqu	OWORD PTR [rsp+160], xmm12
        vmovdqu	OWORD PTR [rsp+176], xmm13
        vmovdqu	OWORD PTR [rsp+192], xmm14
        vmovdqu	OWORD PTR [rsp+208], xmm15
        vmovdqu	xmm12, OWORD PTR L_avx512_aes_xts_gc_xts
        vbroadcasti32x4	zmm13, ptr_L_avx512_aes_xts_poly
        vmovdqu64	zmm14, ptr_L_avx512_aes_xts_shl
        vmovdqu64	zmm15, ptr_L_avx512_aes_xts_shr
        vmovdqu	xmm8, OWORD PTR [r12]
        ; aes_enc_block
        vpxor	xmm8, xmm8, [r9]
        vmovdqu	xmm5, OWORD PTR [r9+16]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+32]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+48]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+64]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+80]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+96]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+112]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+128]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+144]
        vaesenc	xmm8, xmm8, xmm5
        cmp	r10d, 11
        vmovdqu	xmm5, OWORD PTR [r9+160]
        jl	L_AES_XTS_encrypt_avx512_tweak_aes_enc_block_last
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm6, OWORD PTR [r9+176]
        vaesenc	xmm8, xmm8, xmm6
        cmp	r10d, 13
        vmovdqu	xmm5, OWORD PTR [r9+192]
        jl	L_AES_XTS_encrypt_avx512_tweak_aes_enc_block_last
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm6, OWORD PTR [r9+208]
        vaesenc	xmm8, xmm8, xmm6
        vmovdqu	xmm5, OWORD PTR [r9+224]
L_AES_XTS_encrypt_avx512_tweak_aes_enc_block_last:
        vaesenclast	xmm8, xmm8, xmm5
        xor	r13d, r13d
        cmp	eax, 32
        jl	L_AES_XTS_encrypt_avx512_done_128
        vbroadcasti32x4	zmm16, [r8]
        vbroadcasti32x4	zmm17, [r8+16]
        vbroadcasti32x4	zmm18, [r8+32]
        vbroadcasti32x4	zmm19, [r8+48]
        vbroadcasti32x4	zmm20, [r8+64]
        vbroadcasti32x4	zmm21, [r8+80]
        vbroadcasti32x4	zmm22, [r8+96]
        vbroadcasti32x4	zmm23, [r8+112]
        vbroadcasti32x4	zmm24, [r8+128]
        vbroadcasti32x4	zmm25, [r8+144]
        vbroadcasti32x4	zmm26, [r8+160]
        cmp	r10d, 11
        jl	L_AES_XTS_encrypt_avx512_key_cached
        vbroadcasti32x4	zmm27, [r8+176]
        vbroadcasti32x4	zmm28, [r8+192]
        cmp	r10d, 13
        jl	L_AES_XTS_encrypt_avx512_key_cached
        vbroadcasti32x4	zmm29, [r8+208]
        vbroadcasti32x4	zmm30, [r8+224]
L_AES_XTS_encrypt_avx512_key_cached:
        cmp	eax, 256
        mov	r11d, eax
        jl	L_AES_XTS_encrypt_avx512_done_256
        and	r11d, 4294967040
        vshufi64x2	zmm5, zmm8, zmm8, 0
        vpsrlvq	zmm6, zmm5, zmm15
        vpclmulqdq	zmm7, zmm6, zmm13, 1
        vpslldq	zmm6, zmm6, 8
        vpsllvq	zmm4, zmm5, zmm14
        vpternlogq	zmm4, zmm7, zmm6, 150
        vpsrlq	zmm9, zmm4, 60
        vpclmulqdq	zmm10, zmm9, zmm13, 1
        vpslldq	zmm9, zmm9, 8
        vpsllq	zmm5, zmm4, 4
        vpternlogq	zmm5, zmm10, zmm9, 150
        vpsrlq	zmm9, zmm5, 60
        vpclmulqdq	zmm10, zmm9, zmm13, 1
        vpslldq	zmm9, zmm9, 8
        vpsllq	zmm6, zmm5, 4
        vpternlogq	zmm6, zmm10, zmm9, 150
        vpsrlq	zmm9, zmm6, 60
        vpclmulqdq	zmm10, zmm9, zmm13, 1
        vpslldq	zmm9, zmm9, 8
        vpsllq	zmm7, zmm6, 4
        vpternlogq	zmm7, zmm10, zmm9, 150
L_AES_XTS_encrypt_avx512_enc_256:
        ; 256 bytes of input
        ; aes_enc_256
        lea	rcx, QWORD PTR [rdi+r13]
        lea	rdx, QWORD PTR [rsi+r13]
        vmovdqu64	zmm0, [rcx]
        vmovdqu64	zmm1, [rcx+64]
        vmovdqu64	zmm2, [rcx+128]
        vmovdqu64	zmm3, [rcx+192]
        ; aes_enc_block
        vpternlogq	zmm0, zmm16, zmm4, 150
        vpternlogq	zmm1, zmm16, zmm5, 150
        vpternlogq	zmm2, zmm16, zmm6, 150
        vpternlogq	zmm3, zmm16, zmm7, 150
        vaesenc	zmm0, zmm0, zmm17
        vaesenc	zmm1, zmm1, zmm17
        vaesenc	zmm2, zmm2, zmm17
        vaesenc	zmm3, zmm3, zmm17
        vaesenc	zmm0, zmm0, zmm18
        vaesenc	zmm1, zmm1, zmm18
        vaesenc	zmm2, zmm2, zmm18
        vaesenc	zmm3, zmm3, zmm18
        vaesenc	zmm0, zmm0, zmm19
        vaesenc	zmm1, zmm1, zmm19
        vaesenc	zmm2, zmm2, zmm19
        vaesenc	zmm3, zmm3, zmm19
        vaesenc	zmm0, zmm0, zmm20
        vaesenc	zmm1, zmm1, zmm20
        vaesenc	zmm2, zmm2, zmm20
        vaesenc	zmm3, zmm3, zmm20
        vaesenc	zmm0, zmm0, zmm21
        vaesenc	zmm1, zmm1, zmm21
        vaesenc	zmm2, zmm2, zmm21
        vaesenc	zmm3, zmm3, zmm21
        vaesenc	zmm0, zmm0, zmm22
        vaesenc	zmm1, zmm1, zmm22
        vaesenc	zmm2, zmm2, zmm22
        vaesenc	zmm3, zmm3, zmm22
        vaesenc	zmm0, zmm0, zmm23
        vaesenc	zmm1, zmm1, zmm23
        vaesenc	zmm2, zmm2, zmm23
        vaesenc	zmm3, zmm3, zmm23
        vaesenc	zmm0, zmm0, zmm24
        vaesenc	zmm1, zmm1, zmm24
        vaesenc	zmm2, zmm2, zmm24
        vaesenc	zmm3, zmm3, zmm24
        vaesenc	zmm0, zmm0, zmm25
        vaesenc	zmm1, zmm1, zmm25
        vaesenc	zmm2, zmm2, zmm25
        vaesenc	zmm3, zmm3, zmm25
        cmp	r10d, 11
        vmovdqa64	zmm9, zmm26
        jl	L_AES_XTS_encrypt_avx512_aes_enc_256_aes_enc_block_last
        vaesenc	zmm0, zmm0, zmm26
        vaesenc	zmm1, zmm1, zmm26
        vaesenc	zmm2, zmm2, zmm26
        vaesenc	zmm3, zmm3, zmm26
        vaesenc	zmm0, zmm0, zmm27
        vaesenc	zmm1, zmm1, zmm27
        vaesenc	zmm2, zmm2, zmm27
        vaesenc	zmm3, zmm3, zmm27
        cmp	r10d, 13
        vmovdqa64	zmm9, zmm28
        jl	L_AES_XTS_encrypt_avx512_aes_enc_256_aes_enc_block_last
        vaesenc	zmm0, zmm0, zmm28
        vaesenc	zmm1, zmm1, zmm28
        vaesenc	zmm2, zmm2, zmm28
        vaesenc	zmm3, zmm3, zmm28
        vaesenc	zmm0, zmm0, zmm29
        vaesenc	zmm1, zmm1, zmm29
        vaesenc	zmm2, zmm2, zmm29
        vaesenc	zmm3, zmm3, zmm29
        vmovdqa64	zmm9, zmm30
L_AES_XTS_encrypt_avx512_aes_enc_256_aes_enc_block_last:
        vaesenclast	zmm0, zmm0, zmm9
        vaesenclast	zmm1, zmm1, zmm9
        vaesenclast	zmm2, zmm2, zmm9
        vaesenclast	zmm3, zmm3, zmm9
        vpxorq	zmm0, zmm0, zmm4
        vmovdqu64	[rdx], zmm0
        vpsrlq	zmm9, zmm4, 48
        vpclmulqdq	zmm10, zmm9, zmm13, 1
        vpslldq	zmm9, zmm9, 8
        vpsllq	zmm4, zmm4, 16
        vpternlogq	zmm4, zmm10, zmm9, 150
        vpxorq	zmm1, zmm1, zmm5
        vmovdqu64	[rdx+64], zmm1
        vpsrlq	zmm9, zmm5, 48
        vpclmulqdq	zmm10, zmm9, zmm13, 1
        vpslldq	zmm9, zmm9, 8
        vpsllq	zmm5, zmm5, 16
        vpternlogq	zmm5, zmm10, zmm9, 150
        vpxorq	zmm2, zmm2, zmm6
        vmovdqu64	[rdx+128], zmm2
        vpsrlq	zmm9, zmm6, 48
        vpclmulqdq	zmm10, zmm9, zmm13, 1
        vpslldq	zmm9, zmm9, 8
        vpsllq	zmm6, zmm6, 16
        vpternlogq	zmm6, zmm10, zmm9, 150
        vpxorq	zmm3, zmm3, zmm7
        vmovdqu64	[rdx+192], zmm3
        vpsrlq	zmm9, zmm7, 48
        vpclmulqdq	zmm10, zmm9, zmm13, 1
        vpslldq	zmm9, zmm9, 8
        vpsllq	zmm7, zmm7, 16
        vpternlogq	zmm7, zmm10, zmm9, 150
        add	r13d, 256
        cmp	r13d, r11d
        jl	L_AES_XTS_encrypt_avx512_enc_256
        vextracti32x4	xmm8, zmm4, 0
L_AES_XTS_encrypt_avx512_done_256:
        mov	r11d, eax
        and	r11d, 4294967168
        cmp	r13d, r11d
        je	L_AES_XTS_encrypt_avx512_done_128
        ; 128 bytes of input
        ; aes_enc_128
        lea	rcx, QWORD PTR [rdi+r13]
        lea	rdx, QWORD PTR [rsi+r13]
        vmovdqu64	zmm0, [rcx]
        vmovdqu64	zmm1, [rcx+64]
        vshufi64x2	zmm5, zmm8, zmm8, 0
        vpsrlvq	zmm6, zmm5, zmm15
        vpclmulqdq	zmm7, zmm6, zmm13, 1
        vpslldq	zmm6, zmm6, 8
        vpsllvq	zmm4, zmm5, zmm14
        vpternlogq	zmm4, zmm7, zmm6, 150
        vpsrlq	zmm9, zmm4, 60
        vpclmulqdq	zmm10, zmm9, zmm13, 1
        vpslldq	zmm9, zmm9, 8
        vpsllq	zmm5, zmm4, 4
        vpternlogq	zmm5, zmm10, zmm9, 150
        ; aes_enc_block
        vpternlogq	zmm0, zmm16, zmm4, 150
        vpternlogq	zmm1, zmm16, zmm5, 150
        vaesenc	zmm0, zmm0, zmm17
        vaesenc	zmm1, zmm1, zmm17
        vaesenc	zmm0, zmm0, zmm18
        vaesenc	zmm1, zmm1, zmm18
        vaesenc	zmm0, zmm0, zmm19
        vaesenc	zmm1, zmm1, zmm19
        vaesenc	zmm0, zmm0, zmm20
        vaesenc	zmm1, zmm1, zmm20
        vaesenc	zmm0, zmm0, zmm21
        vaesenc	zmm1, zmm1, zmm21
        vaesenc	zmm0, zmm0, zmm22
        vaesenc	zmm1, zmm1, zmm22
        vaesenc	zmm0, zmm0, zmm23
        vaesenc	zmm1, zmm1, zmm23
        vaesenc	zmm0, zmm0, zmm24
        vaesenc	zmm1, zmm1, zmm24
        vaesenc	zmm0, zmm0, zmm25
        vaesenc	zmm1, zmm1, zmm25
        cmp	r10d, 11
        vmovdqa64	zmm9, zmm26
        jl	L_AES_XTS_encrypt_avx512_aes_enc_128_aes_enc_block_last
        vaesenc	zmm0, zmm0, zmm26
        vaesenc	zmm1, zmm1, zmm26
        vaesenc	zmm0, zmm0, zmm27
        vaesenc	zmm1, zmm1, zmm27
        cmp	r10d, 13
        vmovdqa64	zmm9, zmm28
        jl	L_AES_XTS_encrypt_avx512_aes_enc_128_aes_enc_block_last
        vaesenc	zmm0, zmm0, zmm28
        vaesenc	zmm1, zmm1, zmm28
        vaesenc	zmm0, zmm0, zmm29
        vaesenc	zmm1, zmm1, zmm29
        vmovdqa64	zmm9, zmm30
L_AES_XTS_encrypt_avx512_aes_enc_128_aes_enc_block_last:
        vaesenclast	zmm0, zmm0, zmm9
        vaesenclast	zmm1, zmm1, zmm9
        vpxorq	zmm0, zmm0, zmm4
        vmovdqu64	[rdx], zmm0
        vpxorq	zmm1, zmm1, zmm5
        vmovdqu64	[rdx+64], zmm1
        vextracti32x4	xmm8, zmm5, 3
        vpshufd	xmm9, xmm8, 19
        vpaddq	xmm8, xmm8, xmm8
        vpsrad	xmm9, xmm9, 31
        vpternlogd	xmm8, xmm9, xmm12, 120
        add	r13d, 128
L_AES_XTS_encrypt_avx512_done_128:
        mov	r11d, eax
        and	r11d, 4294967232
        cmp	r13d, r11d
        je	L_AES_XTS_encrypt_avx512_done_64
        ; 64 bytes of input
        ; aes_enc_64
        lea	rcx, QWORD PTR [rdi+r13]
        lea	rdx, QWORD PTR [rsi+r13]
        vmovdqu64	zmm0, [rcx]
        vshufi64x2	zmm5, zmm8, zmm8, 0
        vpsrlvq	zmm6, zmm5, zmm15
        vpclmulqdq	zmm7, zmm6, zmm13, 1
        vpslldq	zmm6, zmm6, 8
        vpsllvq	zmm4, zmm5, zmm14
        vpternlogq	zmm4, zmm7, zmm6, 150
        ; aes_enc_block
        vpternlogq	zmm0, zmm16, zmm4, 150
        vaesenc	zmm0, zmm0, zmm17
        vaesenc	zmm0, zmm0, zmm18
        vaesenc	zmm0, zmm0, zmm19
        vaesenc	zmm0, zmm0, zmm20
        vaesenc	zmm0, zmm0, zmm21
        vaesenc	zmm0, zmm0, zmm22
        vaesenc	zmm0, zmm0, zmm23
        vaesenc	zmm0, zmm0, zmm24
        vaesenc	zmm0, zmm0, zmm25
        cmp	r10d, 11
        vmovdqa64	zmm9, zmm26
        jl	L_AES_XTS_encrypt_avx512_aes_enc_64_aes_enc_block_last
        vaesenc	zmm0, zmm0, zmm26
        vaesenc	zmm0, zmm0, zmm27
        cmp	r10d, 13
        vmovdqa64	zmm9, zmm28
        jl	L_AES_XTS_encrypt_avx512_aes_enc_64_aes_enc_block_last
        vaesenc	zmm0, zmm0, zmm28
        vaesenc	zmm0, zmm0, zmm29
        vmovdqa64	zmm9, zmm30
L_AES_XTS_encrypt_avx512_aes_enc_64_aes_enc_block_last:
        vaesenclast	zmm0, zmm0, zmm9
        vpxorq	zmm0, zmm0, zmm4
        vmovdqu64	[rdx], zmm0
        vextracti32x4	xmm8, zmm4, 3
        vpshufd	xmm9, xmm8, 19
        vpaddq	xmm8, xmm8, xmm8
        vpsrad	xmm9, xmm9, 31
        vpternlogd	xmm8, xmm9, xmm12, 120
        add	r13d, 64
L_AES_XTS_encrypt_avx512_done_64:
        mov	r11d, eax
        and	r11d, 4294967264
        cmp	r13d, r11d
        je	L_AES_XTS_encrypt_avx512_done_32
        ; 32 bytes of input
        ; aes_enc_32
        lea	rcx, QWORD PTR [rdi+r13]
        lea	rdx, QWORD PTR [rsi+r13]
        vmovdqu64	ymm0, [rcx]
        vshufi64x2	zmm5, zmm8, zmm8, 0
        vpsrlvq	zmm6, zmm5, zmm15
        vpclmulqdq	zmm7, zmm6, zmm13, 1
        vpslldq	zmm6, zmm6, 8
        vpsllvq	zmm4, zmm5, zmm14
        vpternlogq	zmm4, zmm7, zmm6, 150
        ; aes_enc_block
        vpternlogq	ymm0, ymm16, ymm4, 150
        vaesenc	ymm0, ymm0, ymm17
        vaesenc	ymm0, ymm0, ymm18
        vaesenc	ymm0, ymm0, ymm19
        vaesenc	ymm0, ymm0, ymm20
        vaesenc	ymm0, ymm0, ymm21
        vaesenc	ymm0, ymm0, ymm22
        vaesenc	ymm0, ymm0, ymm23
        vaesenc	ymm0, ymm0, ymm24
        vaesenc	ymm0, ymm0, ymm25
        cmp	r10d, 11
        vmovdqa64	ymm9, ymm26
        jl	L_AES_XTS_encrypt_avx512_aes_enc_32_aes_enc_block_last
        vaesenc	ymm0, ymm0, ymm26
        vaesenc	ymm0, ymm0, ymm27
        cmp	r10d, 13
        vmovdqa64	ymm9, ymm28
        jl	L_AES_XTS_encrypt_avx512_aes_enc_32_aes_enc_block_last
        vaesenc	ymm0, ymm0, ymm28
        vaesenc	ymm0, ymm0, ymm29
        vmovdqa64	ymm9, ymm30
L_AES_XTS_encrypt_avx512_aes_enc_32_aes_enc_block_last:
        vaesenclast	ymm0, ymm0, ymm9
        vpxorq	ymm0, ymm0, ymm4
        vmovdqu64	[rdx], ymm0
        vextracti32x4	xmm8, zmm4, 2
        add	r13d, 32
L_AES_XTS_encrypt_avx512_done_32:
        cmp	r13d, eax
        mov	r11d, eax
        je	L_AES_XTS_encrypt_avx512_done_enc
        sub	r11d, r13d
        cmp	r11d, 16
        mov	r11d, eax
        jl	L_AES_XTS_encrypt_avx512_last_15
        and	r11d, 4294967280
        ; 16 bytes of input
L_AES_XTS_encrypt_avx512_enc_16:
        lea	rcx, QWORD PTR [rdi+r13]
        vmovdqu	xmm0, OWORD PTR [rcx]
        vpxor	xmm0, xmm0, xmm8
        ; aes_enc_block
        vpxor	xmm0, xmm0, [r8]
        vmovdqu	xmm5, OWORD PTR [r8+16]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+32]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+48]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+64]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+80]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+96]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+112]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+128]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+144]
        vaesenc	xmm0, xmm0, xmm5
        cmp	r10d, 11
        vmovdqu	xmm5, OWORD PTR [r8+160]
        jl	L_AES_XTS_encrypt_avx512_aes_enc_block_last
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r8+176]
        vaesenc	xmm0, xmm0, xmm6
        cmp	r10d, 13
        vmovdqu	xmm5, OWORD PTR [r8+192]
        jl	L_AES_XTS_encrypt_avx512_aes_enc_block_last
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r8+208]
        vaesenc	xmm0, xmm0, xmm6
        vmovdqu	xmm5, OWORD PTR [r8+224]
L_AES_XTS_encrypt_avx512_aes_enc_block_last:
        vaesenclast	xmm0, xmm0, xmm5
        vpxor	xmm0, xmm0, xmm8
        lea	rcx, QWORD PTR [rsi+r13]
        vmovdqu	OWORD PTR [rcx], xmm0
        vpshufd	xmm4, xmm8, 19
        vpaddq	xmm8, xmm8, xmm8
        vpsrad	xmm4, xmm4, 31
        vpternlogd	xmm8, xmm4, xmm12, 120
        add	r13d, 16
        cmp	r13d, r11d
        jl	L_AES_XTS_encrypt_avx512_enc_16
        cmp	r13d, eax
        je	L_AES_XTS_encrypt_avx512_done_enc
L_AES_XTS_encrypt_avx512_last_15:
        sub	r13, 16
        lea	rcx, QWORD PTR [rsi+r13]
        vmovdqu	xmm0, OWORD PTR [rcx]
        add	r13, 16
        vmovdqu	OWORD PTR [rsp], xmm0
        xor	rdx, rdx
L_AES_XTS_encrypt_avx512_last_15_byte_loop:
        mov	r11b, BYTE PTR [rsp+rdx]
        mov	cl, BYTE PTR [rdi+r13]
        mov	BYTE PTR [rsi+r13], r11b
        mov	BYTE PTR [rsp+rdx], cl
        inc	r13d
        inc	edx
        cmp	r13d, eax
        jl	L_AES_XTS_encrypt_avx512_last_15_byte_loop
        sub	r13, rdx
        vmovdqu	xmm0, OWORD PTR [rsp]
        sub	r13, 16
        vpxor	xmm0, xmm0, xmm8
        ; aes_enc_block
        vpxor	xmm0, xmm0, [r8]
        vmovdqu	xmm5, OWORD PTR [r8+16]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+32]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+48]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+64]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+80]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+96]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+112]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+128]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+144]
        vaesenc	xmm0, xmm0, xmm5
        cmp	r10d, 11
        vmovdqu	xmm5, OWORD PTR [r8+160]
        jl	L_AES_XTS_encrypt_avx512_last_15_aes_enc_block_last
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r8+176]
        vaesenc	xmm0, xmm0, xmm6
        cmp	r10d, 13
        vmovdqu	xmm5, OWORD PTR [r8+192]
        jl	L_AES_XTS_encrypt_avx512_last_15_aes_enc_block_last
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r8+208]
        vaesenc	xmm0, xmm0, xmm6
        vmovdqu	xmm5, OWORD PTR [r8+224]
L_AES_XTS_encrypt_avx512_last_15_aes_enc_block_last:
        vaesenclast	xmm0, xmm0, xmm5
        vpxor	xmm0, xmm0, xmm8
        lea	rcx, QWORD PTR [rsi+r13]
        vmovdqu	OWORD PTR [rcx], xmm0
L_AES_XTS_encrypt_avx512_done_enc:
        vmovdqu	xmm6, OWORD PTR [rsp+64]
        vmovdqu	xmm7, OWORD PTR [rsp+80]
        vmovdqu	xmm8, OWORD PTR [rsp+96]
        vmovdqu	xmm9, OWORD PTR [rsp+112]
        vmovdqu	xmm10, OWORD PTR [rsp+128]
        vmovdqu	xmm11, OWORD PTR [rsp+144]
        vmovdqu	xmm12, OWORD PTR [rsp+160]
        vmovdqu	xmm13, OWORD PTR [rsp+176]
        vmovdqu	xmm14, OWORD PTR [rsp+192]
        vmovdqu	xmm15, OWORD PTR [rsp+208]
        add	rsp, 224
        pop	r13
        pop	r12
        pop	rsi
        pop	rdi
        ret
AES_XTS_encrypt_avx512 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_XTS_encrypt_update_avx512 PROC
        push	rdi
        push	rsi
        push	r12
        mov	rdi, rcx
        mov	rsi, rdx
        mov	rax, r8
        mov	r10, r9
        mov	r8, QWORD PTR [rsp+64]
        mov	r9d, DWORD PTR [rsp+72]
        sub	rsp, 224
        vmovdqu	OWORD PTR [rsp+64], xmm6
        vmovdqu	OWORD PTR [rsp+80], xmm7
        vmovdqu	OWORD PTR [rsp+96], xmm8
        vmovdqu	OWORD PTR [rsp+112], xmm9
        vmovdqu	OWORD PTR [rsp+128], xmm10
        vmovdqu	OWORD PTR [rsp+144], xmm11
        vmovdqu	OWORD PTR [rsp+160], xmm12
        vmovdqu	OWORD PTR [rsp+176], xmm13
        vmovdqu	OWORD PTR [rsp+192], xmm14
        vmovdqu	OWORD PTR [rsp+208], xmm15
        vmovdqu	xmm12, OWORD PTR L_avx512_aes_xts_gc_xts
        vbroadcasti32x4	zmm13, ptr_L_avx512_aes_xts_poly
        vmovdqu64	zmm14, ptr_L_avx512_aes_xts_shl
        vmovdqu64	zmm15, ptr_L_avx512_aes_xts_shr
        vmovdqu	xmm8, OWORD PTR [r8]
        xor	r12d, r12d
        cmp	eax, 32
        jl	L_AES_XTS_encrypt_update_avx512_done_128
        vbroadcasti32x4	zmm16, [r10]
        vbroadcasti32x4	zmm17, [r10+16]
        vbroadcasti32x4	zmm18, [r10+32]
        vbroadcasti32x4	zmm19, [r10+48]
        vbroadcasti32x4	zmm20, [r10+64]
        vbroadcasti32x4	zmm21, [r10+80]
        vbroadcasti32x4	zmm22, [r10+96]
        vbroadcasti32x4	zmm23, [r10+112]
        vbroadcasti32x4	zmm24, [r10+128]
        vbroadcasti32x4	zmm25, [r10+144]
        vbroadcasti32x4	zmm26, [r10+160]
        cmp	r9d, 11
        jl	L_AES_XTS_encrypt_update_avx512_key_cached
        vbroadcasti32x4	zmm27, [r10+176]
        vbroadcasti32x4	zmm28, [r10+192]
        cmp	r9d, 13
        jl	L_AES_XTS_encrypt_update_avx512_key_cached
        vbroadcasti32x4	zmm29, [r10+208]
        vbroadcasti32x4	zmm30, [r10+224]
L_AES_XTS_encrypt_update_avx512_key_cached:
        cmp	eax, 256
        mov	r11d, eax
        jl	L_AES_XTS_encrypt_update_avx512_done_256
        and	r11d, 4294967040
        vshufi64x2	zmm5, zmm8, zmm8, 0
        vpsrlvq	zmm6, zmm5, zmm15
        vpclmulqdq	zmm7, zmm6, zmm13, 1
        vpslldq	zmm6, zmm6, 8
        vpsllvq	zmm4, zmm5, zmm14
        vpternlogq	zmm4, zmm7, zmm6, 150
        vpsrlq	zmm9, zmm4, 60
        vpclmulqdq	zmm10, zmm9, zmm13, 1
        vpslldq	zmm9, zmm9, 8
        vpsllq	zmm5, zmm4, 4
        vpternlogq	zmm5, zmm10, zmm9, 150
        vpsrlq	zmm9, zmm5, 60
        vpclmulqdq	zmm10, zmm9, zmm13, 1
        vpslldq	zmm9, zmm9, 8
        vpsllq	zmm6, zmm5, 4
        vpternlogq	zmm6, zmm10, zmm9, 150
        vpsrlq	zmm9, zmm6, 60
        vpclmulqdq	zmm10, zmm9, zmm13, 1
        vpslldq	zmm9, zmm9, 8
        vpsllq	zmm7, zmm6, 4
        vpternlogq	zmm7, zmm10, zmm9, 150
L_AES_XTS_encrypt_update_avx512_enc_256:
        ; 256 bytes of input
        ; aes_enc_256
        lea	rcx, QWORD PTR [rdi+r12]
        lea	rdx, QWORD PTR [rsi+r12]
        vmovdqu64	zmm0, [rcx]
        vmovdqu64	zmm1, [rcx+64]
        vmovdqu64	zmm2, [rcx+128]
        vmovdqu64	zmm3, [rcx+192]
        ; aes_enc_block
        vpternlogq	zmm0, zmm16, zmm4, 150
        vpternlogq	zmm1, zmm16, zmm5, 150
        vpternlogq	zmm2, zmm16, zmm6, 150
        vpternlogq	zmm3, zmm16, zmm7, 150
        vaesenc	zmm0, zmm0, zmm17
        vaesenc	zmm1, zmm1, zmm17
        vaesenc	zmm2, zmm2, zmm17
        vaesenc	zmm3, zmm3, zmm17
        vaesenc	zmm0, zmm0, zmm18
        vaesenc	zmm1, zmm1, zmm18
        vaesenc	zmm2, zmm2, zmm18
        vaesenc	zmm3, zmm3, zmm18
        vaesenc	zmm0, zmm0, zmm19
        vaesenc	zmm1, zmm1, zmm19
        vaesenc	zmm2, zmm2, zmm19
        vaesenc	zmm3, zmm3, zmm19
        vaesenc	zmm0, zmm0, zmm20
        vaesenc	zmm1, zmm1, zmm20
        vaesenc	zmm2, zmm2, zmm20
        vaesenc	zmm3, zmm3, zmm20
        vaesenc	zmm0, zmm0, zmm21
        vaesenc	zmm1, zmm1, zmm21
        vaesenc	zmm2, zmm2, zmm21
        vaesenc	zmm3, zmm3, zmm21
        vaesenc	zmm0, zmm0, zmm22
        vaesenc	zmm1, zmm1, zmm22
        vaesenc	zmm2, zmm2, zmm22
        vaesenc	zmm3, zmm3, zmm22
        vaesenc	zmm0, zmm0, zmm23
        vaesenc	zmm1, zmm1, zmm23
        vaesenc	zmm2, zmm2, zmm23
        vaesenc	zmm3, zmm3, zmm23
        vaesenc	zmm0, zmm0, zmm24
        vaesenc	zmm1, zmm1, zmm24
        vaesenc	zmm2, zmm2, zmm24
        vaesenc	zmm3, zmm3, zmm24
        vaesenc	zmm0, zmm0, zmm25
        vaesenc	zmm1, zmm1, zmm25
        vaesenc	zmm2, zmm2, zmm25
        vaesenc	zmm3, zmm3, zmm25
        cmp	r9d, 11
        vmovdqa64	zmm9, zmm26
        jl	L_AES_XTS_encrypt_update_avx512_aes_enc_256_aes_enc_block_last
        vaesenc	zmm0, zmm0, zmm26
        vaesenc	zmm1, zmm1, zmm26
        vaesenc	zmm2, zmm2, zmm26
        vaesenc	zmm3, zmm3, zmm26
        vaesenc	zmm0, zmm0, zmm27
        vaesenc	zmm1, zmm1, zmm27
        vaesenc	zmm2, zmm2, zmm27
        vaesenc	zmm3, zmm3, zmm27
        cmp	r9d, 13
        vmovdqa64	zmm9, zmm28
        jl	L_AES_XTS_encrypt_update_avx512_aes_enc_256_aes_enc_block_last
        vaesenc	zmm0, zmm0, zmm28
        vaesenc	zmm1, zmm1, zmm28
        vaesenc	zmm2, zmm2, zmm28
        vaesenc	zmm3, zmm3, zmm28
        vaesenc	zmm0, zmm0, zmm29
        vaesenc	zmm1, zmm1, zmm29
        vaesenc	zmm2, zmm2, zmm29
        vaesenc	zmm3, zmm3, zmm29
        vmovdqa64	zmm9, zmm30
L_AES_XTS_encrypt_update_avx512_aes_enc_256_aes_enc_block_last:
        vaesenclast	zmm0, zmm0, zmm9
        vaesenclast	zmm1, zmm1, zmm9
        vaesenclast	zmm2, zmm2, zmm9
        vaesenclast	zmm3, zmm3, zmm9
        vpxorq	zmm0, zmm0, zmm4
        vmovdqu64	[rdx], zmm0
        vpsrlq	zmm9, zmm4, 48
        vpclmulqdq	zmm10, zmm9, zmm13, 1
        vpslldq	zmm9, zmm9, 8
        vpsllq	zmm4, zmm4, 16
        vpternlogq	zmm4, zmm10, zmm9, 150
        vpxorq	zmm1, zmm1, zmm5
        vmovdqu64	[rdx+64], zmm1
        vpsrlq	zmm9, zmm5, 48
        vpclmulqdq	zmm10, zmm9, zmm13, 1
        vpslldq	zmm9, zmm9, 8
        vpsllq	zmm5, zmm5, 16
        vpternlogq	zmm5, zmm10, zmm9, 150
        vpxorq	zmm2, zmm2, zmm6
        vmovdqu64	[rdx+128], zmm2
        vpsrlq	zmm9, zmm6, 48
        vpclmulqdq	zmm10, zmm9, zmm13, 1
        vpslldq	zmm9, zmm9, 8
        vpsllq	zmm6, zmm6, 16
        vpternlogq	zmm6, zmm10, zmm9, 150
        vpxorq	zmm3, zmm3, zmm7
        vmovdqu64	[rdx+192], zmm3
        vpsrlq	zmm9, zmm7, 48
        vpclmulqdq	zmm10, zmm9, zmm13, 1
        vpslldq	zmm9, zmm9, 8
        vpsllq	zmm7, zmm7, 16
        vpternlogq	zmm7, zmm10, zmm9, 150
        add	r12d, 256
        cmp	r12d, r11d
        jl	L_AES_XTS_encrypt_update_avx512_enc_256
        vextracti32x4	xmm8, zmm4, 0
L_AES_XTS_encrypt_update_avx512_done_256:
        mov	r11d, eax
        and	r11d, 4294967168
        cmp	r12d, r11d
        je	L_AES_XTS_encrypt_update_avx512_done_128
        ; 128 bytes of input
        ; aes_enc_128
        lea	rcx, QWORD PTR [rdi+r12]
        lea	rdx, QWORD PTR [rsi+r12]
        vmovdqu64	zmm0, [rcx]
        vmovdqu64	zmm1, [rcx+64]
        vshufi64x2	zmm5, zmm8, zmm8, 0
        vpsrlvq	zmm6, zmm5, zmm15
        vpclmulqdq	zmm7, zmm6, zmm13, 1
        vpslldq	zmm6, zmm6, 8
        vpsllvq	zmm4, zmm5, zmm14
        vpternlogq	zmm4, zmm7, zmm6, 150
        vpsrlq	zmm9, zmm4, 60
        vpclmulqdq	zmm10, zmm9, zmm13, 1
        vpslldq	zmm9, zmm9, 8
        vpsllq	zmm5, zmm4, 4
        vpternlogq	zmm5, zmm10, zmm9, 150
        ; aes_enc_block
        vpternlogq	zmm0, zmm16, zmm4, 150
        vpternlogq	zmm1, zmm16, zmm5, 150
        vaesenc	zmm0, zmm0, zmm17
        vaesenc	zmm1, zmm1, zmm17
        vaesenc	zmm0, zmm0, zmm18
        vaesenc	zmm1, zmm1, zmm18
        vaesenc	zmm0, zmm0, zmm19
        vaesenc	zmm1, zmm1, zmm19
        vaesenc	zmm0, zmm0, zmm20
        vaesenc	zmm1, zmm1, zmm20
        vaesenc	zmm0, zmm0, zmm21
        vaesenc	zmm1, zmm1, zmm21
        vaesenc	zmm0, zmm0, zmm22
        vaesenc	zmm1, zmm1, zmm22
        vaesenc	zmm0, zmm0, zmm23
        vaesenc	zmm1, zmm1, zmm23
        vaesenc	zmm0, zmm0, zmm24
        vaesenc	zmm1, zmm1, zmm24
        vaesenc	zmm0, zmm0, zmm25
        vaesenc	zmm1, zmm1, zmm25
        cmp	r9d, 11
        vmovdqa64	zmm9, zmm26
        jl	L_AES_XTS_encrypt_update_avx512_aes_enc_128_aes_enc_block_last
        vaesenc	zmm0, zmm0, zmm26
        vaesenc	zmm1, zmm1, zmm26
        vaesenc	zmm0, zmm0, zmm27
        vaesenc	zmm1, zmm1, zmm27
        cmp	r9d, 13
        vmovdqa64	zmm9, zmm28
        jl	L_AES_XTS_encrypt_update_avx512_aes_enc_128_aes_enc_block_last
        vaesenc	zmm0, zmm0, zmm28
        vaesenc	zmm1, zmm1, zmm28
        vaesenc	zmm0, zmm0, zmm29
        vaesenc	zmm1, zmm1, zmm29
        vmovdqa64	zmm9, zmm30
L_AES_XTS_encrypt_update_avx512_aes_enc_128_aes_enc_block_last:
        vaesenclast	zmm0, zmm0, zmm9
        vaesenclast	zmm1, zmm1, zmm9
        vpxorq	zmm0, zmm0, zmm4
        vmovdqu64	[rdx], zmm0
        vpxorq	zmm1, zmm1, zmm5
        vmovdqu64	[rdx+64], zmm1
        vextracti32x4	xmm8, zmm5, 3
        vpshufd	xmm9, xmm8, 19
        vpaddq	xmm8, xmm8, xmm8
        vpsrad	xmm9, xmm9, 31
        vpternlogd	xmm8, xmm9, xmm12, 120
        add	r12d, 128
L_AES_XTS_encrypt_update_avx512_done_128:
        mov	r11d, eax
        and	r11d, 4294967232
        cmp	r12d, r11d
        je	L_AES_XTS_encrypt_update_avx512_done_64
        ; 64 bytes of input
        ; aes_enc_64
        lea	rcx, QWORD PTR [rdi+r12]
        lea	rdx, QWORD PTR [rsi+r12]
        vmovdqu64	zmm0, [rcx]
        vshufi64x2	zmm5, zmm8, zmm8, 0
        vpsrlvq	zmm6, zmm5, zmm15
        vpclmulqdq	zmm7, zmm6, zmm13, 1
        vpslldq	zmm6, zmm6, 8
        vpsllvq	zmm4, zmm5, zmm14
        vpternlogq	zmm4, zmm7, zmm6, 150
        ; aes_enc_block
        vpternlogq	zmm0, zmm16, zmm4, 150
        vaesenc	zmm0, zmm0, zmm17
        vaesenc	zmm0, zmm0, zmm18
        vaesenc	zmm0, zmm0, zmm19
        vaesenc	zmm0, zmm0, zmm20
        vaesenc	zmm0, zmm0, zmm21
        vaesenc	zmm0, zmm0, zmm22
        vaesenc	zmm0, zmm0, zmm23
        vaesenc	zmm0, zmm0, zmm24
        vaesenc	zmm0, zmm0, zmm25
        cmp	r9d, 11
        vmovdqa64	zmm9, zmm26
        jl	L_AES_XTS_encrypt_update_avx512_aes_enc_64_aes_enc_block_last
        vaesenc	zmm0, zmm0, zmm26
        vaesenc	zmm0, zmm0, zmm27
        cmp	r9d, 13
        vmovdqa64	zmm9, zmm28
        jl	L_AES_XTS_encrypt_update_avx512_aes_enc_64_aes_enc_block_last
        vaesenc	zmm0, zmm0, zmm28
        vaesenc	zmm0, zmm0, zmm29
        vmovdqa64	zmm9, zmm30
L_AES_XTS_encrypt_update_avx512_aes_enc_64_aes_enc_block_last:
        vaesenclast	zmm0, zmm0, zmm9
        vpxorq	zmm0, zmm0, zmm4
        vmovdqu64	[rdx], zmm0
        vextracti32x4	xmm8, zmm4, 3
        vpshufd	xmm9, xmm8, 19
        vpaddq	xmm8, xmm8, xmm8
        vpsrad	xmm9, xmm9, 31
        vpternlogd	xmm8, xmm9, xmm12, 120
        add	r12d, 64
L_AES_XTS_encrypt_update_avx512_done_64:
        mov	r11d, eax
        and	r11d, 4294967264
        cmp	r12d, r11d
        je	L_AES_XTS_encrypt_update_avx512_done_32
        ; 32 bytes of input
        ; aes_enc_32
        lea	rcx, QWORD PTR [rdi+r12]
        lea	rdx, QWORD PTR [rsi+r12]
        vmovdqu64	ymm0, [rcx]
        vshufi64x2	zmm5, zmm8, zmm8, 0
        vpsrlvq	zmm6, zmm5, zmm15
        vpclmulqdq	zmm7, zmm6, zmm13, 1
        vpslldq	zmm6, zmm6, 8
        vpsllvq	zmm4, zmm5, zmm14
        vpternlogq	zmm4, zmm7, zmm6, 150
        ; aes_enc_block
        vpternlogq	ymm0, ymm16, ymm4, 150
        vaesenc	ymm0, ymm0, ymm17
        vaesenc	ymm0, ymm0, ymm18
        vaesenc	ymm0, ymm0, ymm19
        vaesenc	ymm0, ymm0, ymm20
        vaesenc	ymm0, ymm0, ymm21
        vaesenc	ymm0, ymm0, ymm22
        vaesenc	ymm0, ymm0, ymm23
        vaesenc	ymm0, ymm0, ymm24
        vaesenc	ymm0, ymm0, ymm25
        cmp	r9d, 11
        vmovdqa64	ymm9, ymm26
        jl	L_AES_XTS_encrypt_update_avx512_aes_enc_32_aes_enc_block_last
        vaesenc	ymm0, ymm0, ymm26
        vaesenc	ymm0, ymm0, ymm27
        cmp	r9d, 13
        vmovdqa64	ymm9, ymm28
        jl	L_AES_XTS_encrypt_update_avx512_aes_enc_32_aes_enc_block_last
        vaesenc	ymm0, ymm0, ymm28
        vaesenc	ymm0, ymm0, ymm29
        vmovdqa64	ymm9, ymm30
L_AES_XTS_encrypt_update_avx512_aes_enc_32_aes_enc_block_last:
        vaesenclast	ymm0, ymm0, ymm9
        vpxorq	ymm0, ymm0, ymm4
        vmovdqu64	[rdx], ymm0
        vextracti32x4	xmm8, zmm4, 2
        add	r12d, 32
L_AES_XTS_encrypt_update_avx512_done_32:
        cmp	r12d, eax
        mov	r11d, eax
        je	L_AES_XTS_encrypt_update_avx512_done_enc
        sub	r11d, r12d
        cmp	r11d, 16
        mov	r11d, eax
        jl	L_AES_XTS_encrypt_update_avx512_last_15
        and	r11d, 4294967280
        ; 16 bytes of input
L_AES_XTS_encrypt_update_avx512_enc_16:
        lea	rcx, QWORD PTR [rdi+r12]
        vmovdqu	xmm0, OWORD PTR [rcx]
        vpxor	xmm0, xmm0, xmm8
        ; aes_enc_block
        vpxor	xmm0, xmm0, [r10]
        vmovdqu	xmm5, OWORD PTR [r10+16]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+32]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+48]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+64]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+80]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+96]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+112]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+128]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+144]
        vaesenc	xmm0, xmm0, xmm5
        cmp	r9d, 11
        vmovdqu	xmm5, OWORD PTR [r10+160]
        jl	L_AES_XTS_encrypt_update_avx512_aes_enc_block_last
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r10+176]
        vaesenc	xmm0, xmm0, xmm6
        cmp	r9d, 13
        vmovdqu	xmm5, OWORD PTR [r10+192]
        jl	L_AES_XTS_encrypt_update_avx512_aes_enc_block_last
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r10+208]
        vaesenc	xmm0, xmm0, xmm6
        vmovdqu	xmm5, OWORD PTR [r10+224]
L_AES_XTS_encrypt_update_avx512_aes_enc_block_last:
        vaesenclast	xmm0, xmm0, xmm5
        vpxor	xmm0, xmm0, xmm8
        lea	rcx, QWORD PTR [rsi+r12]
        vmovdqu	OWORD PTR [rcx], xmm0
        vpshufd	xmm4, xmm8, 19
        vpaddq	xmm8, xmm8, xmm8
        vpsrad	xmm4, xmm4, 31
        vpternlogd	xmm8, xmm4, xmm12, 120
        add	r12d, 16
        cmp	r12d, r11d
        jl	L_AES_XTS_encrypt_update_avx512_enc_16
        cmp	r12d, eax
        je	L_AES_XTS_encrypt_update_avx512_done_enc
L_AES_XTS_encrypt_update_avx512_last_15:
        sub	r12, 16
        lea	rcx, QWORD PTR [rsi+r12]
        vmovdqu	xmm0, OWORD PTR [rcx]
        add	r12, 16
        vmovdqu	OWORD PTR [rsp], xmm0
        xor	rdx, rdx
L_AES_XTS_encrypt_update_avx512_last_15_byte_loop:
        mov	r11b, BYTE PTR [rsp+rdx]
        mov	cl, BYTE PTR [rdi+r12]
        mov	BYTE PTR [rsi+r12], r11b
        mov	BYTE PTR [rsp+rdx], cl
        inc	r12d
        inc	edx
        cmp	r12d, eax
        jl	L_AES_XTS_encrypt_update_avx512_last_15_byte_loop
        sub	r12, rdx
        vmovdqu	xmm0, OWORD PTR [rsp]
        sub	r12, 16
        vpxor	xmm0, xmm0, xmm8
        ; aes_enc_block
        vpxor	xmm0, xmm0, [r10]
        vmovdqu	xmm5, OWORD PTR [r10+16]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+32]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+48]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+64]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+80]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+96]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+112]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+128]
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+144]
        vaesenc	xmm0, xmm0, xmm5
        cmp	r9d, 11
        vmovdqu	xmm5, OWORD PTR [r10+160]
        jl	L_AES_XTS_encrypt_update_avx512_last_15_aes_enc_block_last
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r10+176]
        vaesenc	xmm0, xmm0, xmm6
        cmp	r9d, 13
        vmovdqu	xmm5, OWORD PTR [r10+192]
        jl	L_AES_XTS_encrypt_update_avx512_last_15_aes_enc_block_last
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r10+208]
        vaesenc	xmm0, xmm0, xmm6
        vmovdqu	xmm5, OWORD PTR [r10+224]
L_AES_XTS_encrypt_update_avx512_last_15_aes_enc_block_last:
        vaesenclast	xmm0, xmm0, xmm5
        vpxor	xmm0, xmm0, xmm8
        lea	rcx, QWORD PTR [rsi+r12]
        vmovdqu	OWORD PTR [rcx], xmm0
L_AES_XTS_encrypt_update_avx512_done_enc:
        vmovdqu	OWORD PTR [r8], xmm8
        vmovdqu	xmm6, OWORD PTR [rsp+64]
        vmovdqu	xmm7, OWORD PTR [rsp+80]
        vmovdqu	xmm8, OWORD PTR [rsp+96]
        vmovdqu	xmm9, OWORD PTR [rsp+112]
        vmovdqu	xmm10, OWORD PTR [rsp+128]
        vmovdqu	xmm11, OWORD PTR [rsp+144]
        vmovdqu	xmm12, OWORD PTR [rsp+160]
        vmovdqu	xmm13, OWORD PTR [rsp+176]
        vmovdqu	xmm14, OWORD PTR [rsp+192]
        vmovdqu	xmm15, OWORD PTR [rsp+208]
        add	rsp, 224
        pop	r12
        pop	rsi
        pop	rdi
        ret
AES_XTS_encrypt_update_avx512 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_XTS_decrypt_avx512 PROC
        push	rdi
        push	rsi
        push	r12
        push	r13
        mov	rdi, rcx
        mov	rsi, rdx
        mov	rax, r8
        mov	r12, r9
        mov	r8, QWORD PTR [rsp+72]
        mov	r9, QWORD PTR [rsp+80]
        mov	r10d, DWORD PTR [rsp+88]
        sub	rsp, 224
        vmovdqu	OWORD PTR [rsp+64], xmm6
        vmovdqu	OWORD PTR [rsp+80], xmm7
        vmovdqu	OWORD PTR [rsp+96], xmm8
        vmovdqu	OWORD PTR [rsp+112], xmm9
        vmovdqu	OWORD PTR [rsp+128], xmm10
        vmovdqu	OWORD PTR [rsp+144], xmm11
        vmovdqu	OWORD PTR [rsp+160], xmm12
        vmovdqu	OWORD PTR [rsp+176], xmm13
        vmovdqu	OWORD PTR [rsp+192], xmm14
        vmovdqu	OWORD PTR [rsp+208], xmm15
        vmovdqu	xmm12, OWORD PTR L_avx512_aes_xts_gc_xts
        vbroadcasti32x4	zmm13, ptr_L_avx512_aes_xts_poly
        vmovdqu64	zmm14, ptr_L_avx512_aes_xts_shl
        vmovdqu64	zmm15, ptr_L_avx512_aes_xts_shr
        vmovdqu	xmm8, OWORD PTR [r12]
        ; aes_enc_block
        vpxor	xmm8, xmm8, [r9]
        vmovdqu	xmm5, OWORD PTR [r9+16]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+32]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+48]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+64]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+80]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+96]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+112]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+128]
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+144]
        vaesenc	xmm8, xmm8, xmm5
        cmp	r10d, 11
        vmovdqu	xmm5, OWORD PTR [r9+160]
        jl	L_AES_XTS_decrypt_avx512_tweak_aes_enc_block_last
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm6, OWORD PTR [r9+176]
        vaesenc	xmm8, xmm8, xmm6
        cmp	r10d, 13
        vmovdqu	xmm5, OWORD PTR [r9+192]
        jl	L_AES_XTS_decrypt_avx512_tweak_aes_enc_block_last
        vaesenc	xmm8, xmm8, xmm5
        vmovdqu	xmm6, OWORD PTR [r9+208]
        vaesenc	xmm8, xmm8, xmm6
        vmovdqu	xmm5, OWORD PTR [r9+224]
L_AES_XTS_decrypt_avx512_tweak_aes_enc_block_last:
        vaesenclast	xmm8, xmm8, xmm5
        xor	r13d, r13d
        mov	r11d, eax
        and	r11d, 4294967280
        cmp	r11d, eax
        je	L_AES_XTS_decrypt_avx512_mul16_256
        sub	r11d, 16
        cmp	r11d, 16
        jl	L_AES_XTS_decrypt_avx512_last_31_start
L_AES_XTS_decrypt_avx512_mul16_256:
        cmp	r11d, 32
        jl	L_AES_XTS_decrypt_avx512_done_128
        vbroadcasti32x4	zmm16, [r8]
        vbroadcasti32x4	zmm17, [r8+16]
        vbroadcasti32x4	zmm18, [r8+32]
        vbroadcasti32x4	zmm19, [r8+48]
        vbroadcasti32x4	zmm20, [r8+64]
        vbroadcasti32x4	zmm21, [r8+80]
        vbroadcasti32x4	zmm22, [r8+96]
        vbroadcasti32x4	zmm23, [r8+112]
        vbroadcasti32x4	zmm24, [r8+128]
        vbroadcasti32x4	zmm25, [r8+144]
        vbroadcasti32x4	zmm26, [r8+160]
        cmp	r10d, 11
        jl	L_AES_XTS_decrypt_avx512_key_cached
        vbroadcasti32x4	zmm27, [r8+176]
        vbroadcasti32x4	zmm28, [r8+192]
        cmp	r10d, 13
        jl	L_AES_XTS_decrypt_avx512_key_cached
        vbroadcasti32x4	zmm29, [r8+208]
        vbroadcasti32x4	zmm30, [r8+224]
L_AES_XTS_decrypt_avx512_key_cached:
        cmp	r11d, 256
        jl	L_AES_XTS_decrypt_avx512_done_256
        and	r11d, 4294967040
        vshufi64x2	zmm5, zmm8, zmm8, 0
        vpsrlvq	zmm6, zmm5, zmm15
        vpclmulqdq	zmm7, zmm6, zmm13, 1
        vpslldq	zmm6, zmm6, 8
        vpsllvq	zmm4, zmm5, zmm14
        vpternlogq	zmm4, zmm7, zmm6, 150
        vpsrlq	zmm9, zmm4, 60
        vpclmulqdq	zmm10, zmm9, zmm13, 1
        vpslldq	zmm9, zmm9, 8
        vpsllq	zmm5, zmm4, 4
        vpternlogq	zmm5, zmm10, zmm9, 150
        vpsrlq	zmm9, zmm5, 60
        vpclmulqdq	zmm10, zmm9, zmm13, 1
        vpslldq	zmm9, zmm9, 8
        vpsllq	zmm6, zmm5, 4
        vpternlogq	zmm6, zmm10, zmm9, 150
        vpsrlq	zmm9, zmm6, 60
        vpclmulqdq	zmm10, zmm9, zmm13, 1
        vpslldq	zmm9, zmm9, 8
        vpsllq	zmm7, zmm6, 4
        vpternlogq	zmm7, zmm10, zmm9, 150
L_AES_XTS_decrypt_avx512_dec_256:
        ; 256 bytes of input
        ; aes_dec_256
        lea	rcx, QWORD PTR [rdi+r13]
        lea	rdx, QWORD PTR [rsi+r13]
        vmovdqu64	zmm0, [rcx]
        vmovdqu64	zmm1, [rcx+64]
        vmovdqu64	zmm2, [rcx+128]
        vmovdqu64	zmm3, [rcx+192]
        ; aes_dec_block
        vpternlogq	zmm0, zmm16, zmm4, 150
        vpternlogq	zmm1, zmm16, zmm5, 150
        vpternlogq	zmm2, zmm16, zmm6, 150
        vpternlogq	zmm3, zmm16, zmm7, 150
        vaesdec	zmm0, zmm0, zmm17
        vaesdec	zmm1, zmm1, zmm17
        vaesdec	zmm2, zmm2, zmm17
        vaesdec	zmm3, zmm3, zmm17
        vaesdec	zmm0, zmm0, zmm18
        vaesdec	zmm1, zmm1, zmm18
        vaesdec	zmm2, zmm2, zmm18
        vaesdec	zmm3, zmm3, zmm18
        vaesdec	zmm0, zmm0, zmm19
        vaesdec	zmm1, zmm1, zmm19
        vaesdec	zmm2, zmm2, zmm19
        vaesdec	zmm3, zmm3, zmm19
        vaesdec	zmm0, zmm0, zmm20
        vaesdec	zmm1, zmm1, zmm20
        vaesdec	zmm2, zmm2, zmm20
        vaesdec	zmm3, zmm3, zmm20
        vaesdec	zmm0, zmm0, zmm21
        vaesdec	zmm1, zmm1, zmm21
        vaesdec	zmm2, zmm2, zmm21
        vaesdec	zmm3, zmm3, zmm21
        vaesdec	zmm0, zmm0, zmm22
        vaesdec	zmm1, zmm1, zmm22
        vaesdec	zmm2, zmm2, zmm22
        vaesdec	zmm3, zmm3, zmm22
        vaesdec	zmm0, zmm0, zmm23
        vaesdec	zmm1, zmm1, zmm23
        vaesdec	zmm2, zmm2, zmm23
        vaesdec	zmm3, zmm3, zmm23
        vaesdec	zmm0, zmm0, zmm24
        vaesdec	zmm1, zmm1, zmm24
        vaesdec	zmm2, zmm2, zmm24
        vaesdec	zmm3, zmm3, zmm24
        vaesdec	zmm0, zmm0, zmm25
        vaesdec	zmm1, zmm1, zmm25
        vaesdec	zmm2, zmm2, zmm25
        vaesdec	zmm3, zmm3, zmm25
        cmp	r10d, 11
        vmovdqa64	zmm9, zmm26
        jl	L_AES_XTS_decrypt_avx512_aes_dec_256_aes_dec_block_last
        vaesdec	zmm0, zmm0, zmm26
        vaesdec	zmm1, zmm1, zmm26
        vaesdec	zmm2, zmm2, zmm26
        vaesdec	zmm3, zmm3, zmm26
        vaesdec	zmm0, zmm0, zmm27
        vaesdec	zmm1, zmm1, zmm27
        vaesdec	zmm2, zmm2, zmm27
        vaesdec	zmm3, zmm3, zmm27
        cmp	r10d, 13
        vmovdqa64	zmm9, zmm28
        jl	L_AES_XTS_decrypt_avx512_aes_dec_256_aes_dec_block_last
        vaesdec	zmm0, zmm0, zmm28
        vaesdec	zmm1, zmm1, zmm28
        vaesdec	zmm2, zmm2, zmm28
        vaesdec	zmm3, zmm3, zmm28
        vaesdec	zmm0, zmm0, zmm29
        vaesdec	zmm1, zmm1, zmm29
        vaesdec	zmm2, zmm2, zmm29
        vaesdec	zmm3, zmm3, zmm29
        vmovdqa64	zmm9, zmm30
L_AES_XTS_decrypt_avx512_aes_dec_256_aes_dec_block_last:
        vaesdeclast	zmm0, zmm0, zmm9
        vaesdeclast	zmm1, zmm1, zmm9
        vaesdeclast	zmm2, zmm2, zmm9
        vaesdeclast	zmm3, zmm3, zmm9
        vpxorq	zmm0, zmm0, zmm4
        vmovdqu64	[rdx], zmm0
        vpsrlq	zmm9, zmm4, 48
        vpclmulqdq	zmm10, zmm9, zmm13, 1
        vpslldq	zmm9, zmm9, 8
        vpsllq	zmm4, zmm4, 16
        vpternlogq	zmm4, zmm10, zmm9, 150
        vpxorq	zmm1, zmm1, zmm5
        vmovdqu64	[rdx+64], zmm1
        vpsrlq	zmm9, zmm5, 48
        vpclmulqdq	zmm10, zmm9, zmm13, 1
        vpslldq	zmm9, zmm9, 8
        vpsllq	zmm5, zmm5, 16
        vpternlogq	zmm5, zmm10, zmm9, 150
        vpxorq	zmm2, zmm2, zmm6
        vmovdqu64	[rdx+128], zmm2
        vpsrlq	zmm9, zmm6, 48
        vpclmulqdq	zmm10, zmm9, zmm13, 1
        vpslldq	zmm9, zmm9, 8
        vpsllq	zmm6, zmm6, 16
        vpternlogq	zmm6, zmm10, zmm9, 150
        vpxorq	zmm3, zmm3, zmm7
        vmovdqu64	[rdx+192], zmm3
        vpsrlq	zmm9, zmm7, 48
        vpclmulqdq	zmm10, zmm9, zmm13, 1
        vpslldq	zmm9, zmm9, 8
        vpsllq	zmm7, zmm7, 16
        vpternlogq	zmm7, zmm10, zmm9, 150
        add	r13d, 256
        cmp	r13d, r11d
        jl	L_AES_XTS_decrypt_avx512_dec_256
        vextracti32x4	xmm8, zmm4, 0
L_AES_XTS_decrypt_avx512_done_256:
        cmp	r13d, eax
        mov	r11d, eax
        je	L_AES_XTS_decrypt_avx512_done_dec
        and	r11d, 4294967280
        cmp	r11d, eax
        je	L_AES_XTS_decrypt_avx512_mul16_128
        sub	r11d, 16
        sub	r11d, r13d
        cmp	r11d, 16
        jl	L_AES_XTS_decrypt_avx512_last_31_start
        add	r11d, r13d
L_AES_XTS_decrypt_avx512_mul16_128:
        and	r11d, 4294967168
        cmp	r13d, r11d
        je	L_AES_XTS_decrypt_avx512_done_128
        ; 128 bytes of input
        ; aes_dec_128
        lea	rcx, QWORD PTR [rdi+r13]
        lea	rdx, QWORD PTR [rsi+r13]
        vmovdqu64	zmm0, [rcx]
        vmovdqu64	zmm1, [rcx+64]
        vshufi64x2	zmm5, zmm8, zmm8, 0
        vpsrlvq	zmm6, zmm5, zmm15
        vpclmulqdq	zmm7, zmm6, zmm13, 1
        vpslldq	zmm6, zmm6, 8
        vpsllvq	zmm4, zmm5, zmm14
        vpternlogq	zmm4, zmm7, zmm6, 150
        vpsrlq	zmm9, zmm4, 60
        vpclmulqdq	zmm10, zmm9, zmm13, 1
        vpslldq	zmm9, zmm9, 8
        vpsllq	zmm5, zmm4, 4
        vpternlogq	zmm5, zmm10, zmm9, 150
        ; aes_dec_block
        vpternlogq	zmm0, zmm16, zmm4, 150
        vpternlogq	zmm1, zmm16, zmm5, 150
        vaesdec	zmm0, zmm0, zmm17
        vaesdec	zmm1, zmm1, zmm17
        vaesdec	zmm0, zmm0, zmm18
        vaesdec	zmm1, zmm1, zmm18
        vaesdec	zmm0, zmm0, zmm19
        vaesdec	zmm1, zmm1, zmm19
        vaesdec	zmm0, zmm0, zmm20
        vaesdec	zmm1, zmm1, zmm20
        vaesdec	zmm0, zmm0, zmm21
        vaesdec	zmm1, zmm1, zmm21
        vaesdec	zmm0, zmm0, zmm22
        vaesdec	zmm1, zmm1, zmm22
        vaesdec	zmm0, zmm0, zmm23
        vaesdec	zmm1, zmm1, zmm23
        vaesdec	zmm0, zmm0, zmm24
        vaesdec	zmm1, zmm1, zmm24
        vaesdec	zmm0, zmm0, zmm25
        vaesdec	zmm1, zmm1, zmm25
        cmp	r10d, 11
        vmovdqa64	zmm9, zmm26
        jl	L_AES_XTS_decrypt_avx512_aes_dec_128_aes_dec_block_last
        vaesdec	zmm0, zmm0, zmm26
        vaesdec	zmm1, zmm1, zmm26
        vaesdec	zmm0, zmm0, zmm27
        vaesdec	zmm1, zmm1, zmm27
        cmp	r10d, 13
        vmovdqa64	zmm9, zmm28
        jl	L_AES_XTS_decrypt_avx512_aes_dec_128_aes_dec_block_last
        vaesdec	zmm0, zmm0, zmm28
        vaesdec	zmm1, zmm1, zmm28
        vaesdec	zmm0, zmm0, zmm29
        vaesdec	zmm1, zmm1, zmm29
        vmovdqa64	zmm9, zmm30
L_AES_XTS_decrypt_avx512_aes_dec_128_aes_dec_block_last:
        vaesdeclast	zmm0, zmm0, zmm9
        vaesdeclast	zmm1, zmm1, zmm9
        vpxorq	zmm0, zmm0, zmm4
        vmovdqu64	[rdx], zmm0
        vpxorq	zmm1, zmm1, zmm5
        vmovdqu64	[rdx+64], zmm1
        vextracti32x4	xmm8, zmm5, 3
        vpshufd	xmm9, xmm8, 19
        vpaddq	xmm8, xmm8, xmm8
        vpsrad	xmm9, xmm9, 31
        vpternlogd	xmm8, xmm9, xmm12, 120
        add	r13d, 128
L_AES_XTS_decrypt_avx512_done_128:
        cmp	r13d, eax
        mov	r11d, eax
        je	L_AES_XTS_decrypt_avx512_done_dec
        and	r11d, 4294967280
        cmp	r11d, eax
        je	L_AES_XTS_decrypt_avx512_mul16_64
        sub	r11d, 16
        sub	r11d, r13d
        cmp	r11d, 16
        jl	L_AES_XTS_decrypt_avx512_last_31_start
        add	r11d, r13d
L_AES_XTS_decrypt_avx512_mul16_64:
        and	r11d, 4294967232
        cmp	r13d, r11d
        je	L_AES_XTS_decrypt_avx512_done_64
        ; 64 bytes of input
        ; aes_dec_64
        lea	rcx, QWORD PTR [rdi+r13]
        lea	rdx, QWORD PTR [rsi+r13]
        vmovdqu64	zmm0, [rcx]
        vshufi64x2	zmm5, zmm8, zmm8, 0
        vpsrlvq	zmm6, zmm5, zmm15
        vpclmulqdq	zmm7, zmm6, zmm13, 1
        vpslldq	zmm6, zmm6, 8
        vpsllvq	zmm4, zmm5, zmm14
        vpternlogq	zmm4, zmm7, zmm6, 150
        ; aes_dec_block
        vpternlogq	zmm0, zmm16, zmm4, 150
        vaesdec	zmm0, zmm0, zmm17
        vaesdec	zmm0, zmm0, zmm18
        vaesdec	zmm0, zmm0, zmm19
        vaesdec	zmm0, zmm0, zmm20
        vaesdec	zmm0, zmm0, zmm21
        vaesdec	zmm0, zmm0, zmm22
        vaesdec	zmm0, zmm0, zmm23
        vaesdec	zmm0, zmm0, zmm24
        vaesdec	zmm0, zmm0, zmm25
        cmp	r10d, 11
        vmovdqa64	zmm9, zmm26
        jl	L_AES_XTS_decrypt_avx512_aes_dec_64_aes_dec_block_last
        vaesdec	zmm0, zmm0, zmm26
        vaesdec	zmm0, zmm0, zmm27
        cmp	r10d, 13
        vmovdqa64	zmm9, zmm28
        jl	L_AES_XTS_decrypt_avx512_aes_dec_64_aes_dec_block_last
        vaesdec	zmm0, zmm0, zmm28
        vaesdec	zmm0, zmm0, zmm29
        vmovdqa64	zmm9, zmm30
L_AES_XTS_decrypt_avx512_aes_dec_64_aes_dec_block_last:
        vaesdeclast	zmm0, zmm0, zmm9
        vpxorq	zmm0, zmm0, zmm4
        vmovdqu64	[rdx], zmm0
        vextracti32x4	xmm8, zmm4, 3
        vpshufd	xmm9, xmm8, 19
        vpaddq	xmm8, xmm8, xmm8
        vpsrad	xmm9, xmm9, 31
        vpternlogd	xmm8, xmm9, xmm12, 120
        add	r13d, 64
L_AES_XTS_decrypt_avx512_done_64:
        cmp	r13d, eax
        mov	r11d, eax
        je	L_AES_XTS_decrypt_avx512_done_dec
        and	r11d, 4294967280
        cmp	r11d, eax
        je	L_AES_XTS_decrypt_avx512_mul16_32
        sub	r11d, 16
        sub	r11d, r13d
        cmp	r11d, 16
        jl	L_AES_XTS_decrypt_avx512_last_31_start
        add	r11d, r13d
L_AES_XTS_decrypt_avx512_mul16_32:
        and	r11d, 4294967264
        cmp	r13d, r11d
        je	L_AES_XTS_decrypt_avx512_done_32
        ; 32 bytes of input
        ; aes_dec_32
        lea	rcx, QWORD PTR [rdi+r13]
        lea	rdx, QWORD PTR [rsi+r13]
        vmovdqu64	ymm0, [rcx]
        vshufi64x2	zmm5, zmm8, zmm8, 0
        vpsrlvq	zmm6, zmm5, zmm15
        vpclmulqdq	zmm7, zmm6, zmm13, 1
        vpslldq	zmm6, zmm6, 8
        vpsllvq	zmm4, zmm5, zmm14
        vpternlogq	zmm4, zmm7, zmm6, 150
        ; aes_dec_block
        vpternlogq	ymm0, ymm16, ymm4, 150
        vaesdec	ymm0, ymm0, ymm17
        vaesdec	ymm0, ymm0, ymm18
        vaesdec	ymm0, ymm0, ymm19
        vaesdec	ymm0, ymm0, ymm20
        vaesdec	ymm0, ymm0, ymm21
        vaesdec	ymm0, ymm0, ymm22
        vaesdec	ymm0, ymm0, ymm23
        vaesdec	ymm0, ymm0, ymm24
        vaesdec	ymm0, ymm0, ymm25
        cmp	r10d, 11
        vmovdqa64	ymm9, ymm26
        jl	L_AES_XTS_decrypt_avx512_aes_dec_32_aes_dec_block_last
        vaesdec	ymm0, ymm0, ymm26
        vaesdec	ymm0, ymm0, ymm27
        cmp	r10d, 13
        vmovdqa64	ymm9, ymm28
        jl	L_AES_XTS_decrypt_avx512_aes_dec_32_aes_dec_block_last
        vaesdec	ymm0, ymm0, ymm28
        vaesdec	ymm0, ymm0, ymm29
        vmovdqa64	ymm9, ymm30
L_AES_XTS_decrypt_avx512_aes_dec_32_aes_dec_block_last:
        vaesdeclast	ymm0, ymm0, ymm9
        vpxorq	ymm0, ymm0, ymm4
        vmovdqu64	[rdx], ymm0
        vextracti32x4	xmm8, zmm4, 2
        add	r13d, 32
L_AES_XTS_decrypt_avx512_done_32:
        cmp	r13d, eax
        mov	r11d, eax
        je	L_AES_XTS_decrypt_avx512_done_dec
        and	r11d, 4294967280
        cmp	r11d, eax
        je	L_AES_XTS_decrypt_avx512_mul16
        sub	r11d, 16
        sub	r11d, r13d
        cmp	r11d, 16
        jl	L_AES_XTS_decrypt_avx512_last_31_start
        add	r11d, r13d
L_AES_XTS_decrypt_avx512_mul16:
L_AES_XTS_decrypt_avx512_dec_16:
        ; 16 bytes of input
        lea	rcx, QWORD PTR [rdi+r13]
        vmovdqu	xmm0, OWORD PTR [rcx]
        vpxor	xmm0, xmm0, xmm8
        ; aes_dec_block
        vpxor	xmm0, xmm0, [r8]
        vmovdqu	xmm5, OWORD PTR [r8+16]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+32]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+48]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+64]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+80]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+96]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+112]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+128]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+144]
        vaesdec	xmm0, xmm0, xmm5
        cmp	r10d, 11
        vmovdqu	xmm5, OWORD PTR [r8+160]
        jl	L_AES_XTS_decrypt_avx512_aes_dec_block_last
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r8+176]
        vaesdec	xmm0, xmm0, xmm6
        cmp	r10d, 13
        vmovdqu	xmm5, OWORD PTR [r8+192]
        jl	L_AES_XTS_decrypt_avx512_aes_dec_block_last
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r8+208]
        vaesdec	xmm0, xmm0, xmm6
        vmovdqu	xmm5, OWORD PTR [r8+224]
L_AES_XTS_decrypt_avx512_aes_dec_block_last:
        vaesdeclast	xmm0, xmm0, xmm5
        vpxor	xmm0, xmm0, xmm8
        lea	rcx, QWORD PTR [rsi+r13]
        vmovdqu	OWORD PTR [rcx], xmm0
        vpshufd	xmm4, xmm8, 19
        vpaddq	xmm8, xmm8, xmm8
        vpsrad	xmm4, xmm4, 31
        vpternlogd	xmm8, xmm4, xmm12, 120
        add	r13d, 16
        cmp	r13d, r11d
        jl	L_AES_XTS_decrypt_avx512_dec_16
        cmp	r13d, eax
        je	L_AES_XTS_decrypt_avx512_done_dec
L_AES_XTS_decrypt_avx512_last_31_start:
        vpshufd	xmm4, xmm8, 19
        vpaddq	xmm7, xmm8, xmm8
        vpsrad	xmm4, xmm4, 31
        vpternlogd	xmm7, xmm4, xmm12, 120
        lea	rcx, QWORD PTR [rdi+r13]
        vmovdqu	xmm0, OWORD PTR [rcx]
        vpxor	xmm0, xmm0, xmm7
        ; aes_dec_block
        vpxor	xmm0, xmm0, [r8]
        vmovdqu	xmm5, OWORD PTR [r8+16]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+32]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+48]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+64]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+80]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+96]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+112]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+128]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+144]
        vaesdec	xmm0, xmm0, xmm5
        cmp	r10d, 11
        vmovdqu	xmm5, OWORD PTR [r8+160]
        jl	L_AES_XTS_decrypt_avx512_last_31_aes_dec_block_last
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r8+176]
        vaesdec	xmm0, xmm0, xmm6
        cmp	r10d, 13
        vmovdqu	xmm5, OWORD PTR [r8+192]
        jl	L_AES_XTS_decrypt_avx512_last_31_aes_dec_block_last
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r8+208]
        vaesdec	xmm0, xmm0, xmm6
        vmovdqu	xmm5, OWORD PTR [r8+224]
L_AES_XTS_decrypt_avx512_last_31_aes_dec_block_last:
        vaesdeclast	xmm0, xmm0, xmm5
        vpxor	xmm0, xmm0, xmm7
        vmovdqu	OWORD PTR [rsp], xmm0
        add	r13, 16
        xor	rdx, rdx
L_AES_XTS_decrypt_avx512_last_31_byte_loop:
        mov	r11b, BYTE PTR [rsp+rdx]
        mov	cl, BYTE PTR [rdi+r13]
        mov	BYTE PTR [rsi+r13], r11b
        mov	BYTE PTR [rsp+rdx], cl
        inc	r13d
        inc	edx
        cmp	r13d, eax
        jl	L_AES_XTS_decrypt_avx512_last_31_byte_loop
        sub	r13, rdx
        vmovdqu	xmm0, OWORD PTR [rsp]
        vpxor	xmm0, xmm0, xmm8
        ; aes_dec_block
        vpxor	xmm0, xmm0, [r8]
        vmovdqu	xmm5, OWORD PTR [r8+16]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+32]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+48]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+64]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+80]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+96]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+112]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+128]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r8+144]
        vaesdec	xmm0, xmm0, xmm5
        cmp	r10d, 11
        vmovdqu	xmm5, OWORD PTR [r8+160]
        jl	L_AES_XTS_decrypt_avx512_last_31_2_aes_dec_block_last
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r8+176]
        vaesdec	xmm0, xmm0, xmm6
        cmp	r10d, 13
        vmovdqu	xmm5, OWORD PTR [r8+192]
        jl	L_AES_XTS_decrypt_avx512_last_31_2_aes_dec_block_last
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r8+208]
        vaesdec	xmm0, xmm0, xmm6
        vmovdqu	xmm5, OWORD PTR [r8+224]
L_AES_XTS_decrypt_avx512_last_31_2_aes_dec_block_last:
        vaesdeclast	xmm0, xmm0, xmm5
        vpxor	xmm0, xmm0, xmm8
        sub	r13, 16
        lea	rcx, QWORD PTR [rsi+r13]
        vmovdqu	OWORD PTR [rcx], xmm0
L_AES_XTS_decrypt_avx512_done_dec:
        vmovdqu	xmm6, OWORD PTR [rsp+64]
        vmovdqu	xmm7, OWORD PTR [rsp+80]
        vmovdqu	xmm8, OWORD PTR [rsp+96]
        vmovdqu	xmm9, OWORD PTR [rsp+112]
        vmovdqu	xmm10, OWORD PTR [rsp+128]
        vmovdqu	xmm11, OWORD PTR [rsp+144]
        vmovdqu	xmm12, OWORD PTR [rsp+160]
        vmovdqu	xmm13, OWORD PTR [rsp+176]
        vmovdqu	xmm14, OWORD PTR [rsp+192]
        vmovdqu	xmm15, OWORD PTR [rsp+208]
        add	rsp, 224
        pop	r13
        pop	r12
        pop	rsi
        pop	rdi
        ret
AES_XTS_decrypt_avx512 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_XTS_decrypt_update_avx512 PROC
        push	rdi
        push	rsi
        push	r12
        mov	rdi, rcx
        mov	rsi, rdx
        mov	rax, r8
        mov	r10, r9
        mov	r8, QWORD PTR [rsp+64]
        mov	r9d, DWORD PTR [rsp+72]
        sub	rsp, 224
        vmovdqu	OWORD PTR [rsp+64], xmm6
        vmovdqu	OWORD PTR [rsp+80], xmm7
        vmovdqu	OWORD PTR [rsp+96], xmm8
        vmovdqu	OWORD PTR [rsp+112], xmm9
        vmovdqu	OWORD PTR [rsp+128], xmm10
        vmovdqu	OWORD PTR [rsp+144], xmm11
        vmovdqu	OWORD PTR [rsp+160], xmm12
        vmovdqu	OWORD PTR [rsp+176], xmm13
        vmovdqu	OWORD PTR [rsp+192], xmm14
        vmovdqu	OWORD PTR [rsp+208], xmm15
        vmovdqu	xmm12, OWORD PTR L_avx512_aes_xts_gc_xts
        vbroadcasti32x4	zmm13, ptr_L_avx512_aes_xts_poly
        vmovdqu64	zmm14, ptr_L_avx512_aes_xts_shl
        vmovdqu64	zmm15, ptr_L_avx512_aes_xts_shr
        vmovdqu	xmm8, OWORD PTR [r8]
        xor	r12d, r12d
        mov	r11d, eax
        and	r11d, 4294967280
        cmp	r11d, eax
        je	L_AES_XTS_decrypt_update_avx512_mul16_256
        sub	r11d, 16
        cmp	r11d, 16
        jl	L_AES_XTS_decrypt_update_avx512_last_31_start
L_AES_XTS_decrypt_update_avx512_mul16_256:
        cmp	r11d, 32
        jl	L_AES_XTS_decrypt_update_avx512_done_128
        vbroadcasti32x4	zmm16, [r10]
        vbroadcasti32x4	zmm17, [r10+16]
        vbroadcasti32x4	zmm18, [r10+32]
        vbroadcasti32x4	zmm19, [r10+48]
        vbroadcasti32x4	zmm20, [r10+64]
        vbroadcasti32x4	zmm21, [r10+80]
        vbroadcasti32x4	zmm22, [r10+96]
        vbroadcasti32x4	zmm23, [r10+112]
        vbroadcasti32x4	zmm24, [r10+128]
        vbroadcasti32x4	zmm25, [r10+144]
        vbroadcasti32x4	zmm26, [r10+160]
        cmp	r9d, 11
        jl	L_AES_XTS_decrypt_update_avx512_key_cached
        vbroadcasti32x4	zmm27, [r10+176]
        vbroadcasti32x4	zmm28, [r10+192]
        cmp	r9d, 13
        jl	L_AES_XTS_decrypt_update_avx512_key_cached
        vbroadcasti32x4	zmm29, [r10+208]
        vbroadcasti32x4	zmm30, [r10+224]
L_AES_XTS_decrypt_update_avx512_key_cached:
        cmp	r11d, 256
        jl	L_AES_XTS_decrypt_update_avx512_done_256
        and	r11d, 4294967040
        vshufi64x2	zmm5, zmm8, zmm8, 0
        vpsrlvq	zmm6, zmm5, zmm15
        vpclmulqdq	zmm7, zmm6, zmm13, 1
        vpslldq	zmm6, zmm6, 8
        vpsllvq	zmm4, zmm5, zmm14
        vpternlogq	zmm4, zmm7, zmm6, 150
        vpsrlq	zmm9, zmm4, 60
        vpclmulqdq	zmm10, zmm9, zmm13, 1
        vpslldq	zmm9, zmm9, 8
        vpsllq	zmm5, zmm4, 4
        vpternlogq	zmm5, zmm10, zmm9, 150
        vpsrlq	zmm9, zmm5, 60
        vpclmulqdq	zmm10, zmm9, zmm13, 1
        vpslldq	zmm9, zmm9, 8
        vpsllq	zmm6, zmm5, 4
        vpternlogq	zmm6, zmm10, zmm9, 150
        vpsrlq	zmm9, zmm6, 60
        vpclmulqdq	zmm10, zmm9, zmm13, 1
        vpslldq	zmm9, zmm9, 8
        vpsllq	zmm7, zmm6, 4
        vpternlogq	zmm7, zmm10, zmm9, 150
L_AES_XTS_decrypt_update_avx512_dec_256:
        ; 256 bytes of input
        ; aes_dec_256
        lea	rcx, QWORD PTR [rdi+r12]
        lea	rdx, QWORD PTR [rsi+r12]
        vmovdqu64	zmm0, [rcx]
        vmovdqu64	zmm1, [rcx+64]
        vmovdqu64	zmm2, [rcx+128]
        vmovdqu64	zmm3, [rcx+192]
        ; aes_dec_block
        vpternlogq	zmm0, zmm16, zmm4, 150
        vpternlogq	zmm1, zmm16, zmm5, 150
        vpternlogq	zmm2, zmm16, zmm6, 150
        vpternlogq	zmm3, zmm16, zmm7, 150
        vaesdec	zmm0, zmm0, zmm17
        vaesdec	zmm1, zmm1, zmm17
        vaesdec	zmm2, zmm2, zmm17
        vaesdec	zmm3, zmm3, zmm17
        vaesdec	zmm0, zmm0, zmm18
        vaesdec	zmm1, zmm1, zmm18
        vaesdec	zmm2, zmm2, zmm18
        vaesdec	zmm3, zmm3, zmm18
        vaesdec	zmm0, zmm0, zmm19
        vaesdec	zmm1, zmm1, zmm19
        vaesdec	zmm2, zmm2, zmm19
        vaesdec	zmm3, zmm3, zmm19
        vaesdec	zmm0, zmm0, zmm20
        vaesdec	zmm1, zmm1, zmm20
        vaesdec	zmm2, zmm2, zmm20
        vaesdec	zmm3, zmm3, zmm20
        vaesdec	zmm0, zmm0, zmm21
        vaesdec	zmm1, zmm1, zmm21
        vaesdec	zmm2, zmm2, zmm21
        vaesdec	zmm3, zmm3, zmm21
        vaesdec	zmm0, zmm0, zmm22
        vaesdec	zmm1, zmm1, zmm22
        vaesdec	zmm2, zmm2, zmm22
        vaesdec	zmm3, zmm3, zmm22
        vaesdec	zmm0, zmm0, zmm23
        vaesdec	zmm1, zmm1, zmm23
        vaesdec	zmm2, zmm2, zmm23
        vaesdec	zmm3, zmm3, zmm23
        vaesdec	zmm0, zmm0, zmm24
        vaesdec	zmm1, zmm1, zmm24
        vaesdec	zmm2, zmm2, zmm24
        vaesdec	zmm3, zmm3, zmm24
        vaesdec	zmm0, zmm0, zmm25
        vaesdec	zmm1, zmm1, zmm25
        vaesdec	zmm2, zmm2, zmm25
        vaesdec	zmm3, zmm3, zmm25
        cmp	r9d, 11
        vmovdqa64	zmm9, zmm26
        jl	L_AES_XTS_decrypt_update_avx512_aes_dec_256_aes_dec_block_last
        vaesdec	zmm0, zmm0, zmm26
        vaesdec	zmm1, zmm1, zmm26
        vaesdec	zmm2, zmm2, zmm26
        vaesdec	zmm3, zmm3, zmm26
        vaesdec	zmm0, zmm0, zmm27
        vaesdec	zmm1, zmm1, zmm27
        vaesdec	zmm2, zmm2, zmm27
        vaesdec	zmm3, zmm3, zmm27
        cmp	r9d, 13
        vmovdqa64	zmm9, zmm28
        jl	L_AES_XTS_decrypt_update_avx512_aes_dec_256_aes_dec_block_last
        vaesdec	zmm0, zmm0, zmm28
        vaesdec	zmm1, zmm1, zmm28
        vaesdec	zmm2, zmm2, zmm28
        vaesdec	zmm3, zmm3, zmm28
        vaesdec	zmm0, zmm0, zmm29
        vaesdec	zmm1, zmm1, zmm29
        vaesdec	zmm2, zmm2, zmm29
        vaesdec	zmm3, zmm3, zmm29
        vmovdqa64	zmm9, zmm30
L_AES_XTS_decrypt_update_avx512_aes_dec_256_aes_dec_block_last:
        vaesdeclast	zmm0, zmm0, zmm9
        vaesdeclast	zmm1, zmm1, zmm9
        vaesdeclast	zmm2, zmm2, zmm9
        vaesdeclast	zmm3, zmm3, zmm9
        vpxorq	zmm0, zmm0, zmm4
        vmovdqu64	[rdx], zmm0
        vpsrlq	zmm9, zmm4, 48
        vpclmulqdq	zmm10, zmm9, zmm13, 1
        vpslldq	zmm9, zmm9, 8
        vpsllq	zmm4, zmm4, 16
        vpternlogq	zmm4, zmm10, zmm9, 150
        vpxorq	zmm1, zmm1, zmm5
        vmovdqu64	[rdx+64], zmm1
        vpsrlq	zmm9, zmm5, 48
        vpclmulqdq	zmm10, zmm9, zmm13, 1
        vpslldq	zmm9, zmm9, 8
        vpsllq	zmm5, zmm5, 16
        vpternlogq	zmm5, zmm10, zmm9, 150
        vpxorq	zmm2, zmm2, zmm6
        vmovdqu64	[rdx+128], zmm2
        vpsrlq	zmm9, zmm6, 48
        vpclmulqdq	zmm10, zmm9, zmm13, 1
        vpslldq	zmm9, zmm9, 8
        vpsllq	zmm6, zmm6, 16
        vpternlogq	zmm6, zmm10, zmm9, 150
        vpxorq	zmm3, zmm3, zmm7
        vmovdqu64	[rdx+192], zmm3
        vpsrlq	zmm9, zmm7, 48
        vpclmulqdq	zmm10, zmm9, zmm13, 1
        vpslldq	zmm9, zmm9, 8
        vpsllq	zmm7, zmm7, 16
        vpternlogq	zmm7, zmm10, zmm9, 150
        add	r12d, 256
        cmp	r12d, r11d
        jl	L_AES_XTS_decrypt_update_avx512_dec_256
        vextracti32x4	xmm8, zmm4, 0
L_AES_XTS_decrypt_update_avx512_done_256:
        cmp	r12d, eax
        mov	r11d, eax
        je	L_AES_XTS_decrypt_update_avx512_done_dec
        and	r11d, 4294967280
        cmp	r11d, eax
        je	L_AES_XTS_decrypt_update_avx512_mul16_128
        sub	r11d, 16
        sub	r11d, r12d
        cmp	r11d, 16
        jl	L_AES_XTS_decrypt_update_avx512_last_31_start
        add	r11d, r12d
L_AES_XTS_decrypt_update_avx512_mul16_128:
        and	r11d, 4294967168
        cmp	r12d, r11d
        je	L_AES_XTS_decrypt_update_avx512_done_128
        ; 128 bytes of input
        ; aes_dec_128
        lea	rcx, QWORD PTR [rdi+r12]
        lea	rdx, QWORD PTR [rsi+r12]
        vmovdqu64	zmm0, [rcx]
        vmovdqu64	zmm1, [rcx+64]
        vshufi64x2	zmm5, zmm8, zmm8, 0
        vpsrlvq	zmm6, zmm5, zmm15
        vpclmulqdq	zmm7, zmm6, zmm13, 1
        vpslldq	zmm6, zmm6, 8
        vpsllvq	zmm4, zmm5, zmm14
        vpternlogq	zmm4, zmm7, zmm6, 150
        vpsrlq	zmm9, zmm4, 60
        vpclmulqdq	zmm10, zmm9, zmm13, 1
        vpslldq	zmm9, zmm9, 8
        vpsllq	zmm5, zmm4, 4
        vpternlogq	zmm5, zmm10, zmm9, 150
        ; aes_dec_block
        vpternlogq	zmm0, zmm16, zmm4, 150
        vpternlogq	zmm1, zmm16, zmm5, 150
        vaesdec	zmm0, zmm0, zmm17
        vaesdec	zmm1, zmm1, zmm17
        vaesdec	zmm0, zmm0, zmm18
        vaesdec	zmm1, zmm1, zmm18
        vaesdec	zmm0, zmm0, zmm19
        vaesdec	zmm1, zmm1, zmm19
        vaesdec	zmm0, zmm0, zmm20
        vaesdec	zmm1, zmm1, zmm20
        vaesdec	zmm0, zmm0, zmm21
        vaesdec	zmm1, zmm1, zmm21
        vaesdec	zmm0, zmm0, zmm22
        vaesdec	zmm1, zmm1, zmm22
        vaesdec	zmm0, zmm0, zmm23
        vaesdec	zmm1, zmm1, zmm23
        vaesdec	zmm0, zmm0, zmm24
        vaesdec	zmm1, zmm1, zmm24
        vaesdec	zmm0, zmm0, zmm25
        vaesdec	zmm1, zmm1, zmm25
        cmp	r9d, 11
        vmovdqa64	zmm9, zmm26
        jl	L_AES_XTS_decrypt_update_avx512_aes_dec_128_aes_dec_block_last
        vaesdec	zmm0, zmm0, zmm26
        vaesdec	zmm1, zmm1, zmm26
        vaesdec	zmm0, zmm0, zmm27
        vaesdec	zmm1, zmm1, zmm27
        cmp	r9d, 13
        vmovdqa64	zmm9, zmm28
        jl	L_AES_XTS_decrypt_update_avx512_aes_dec_128_aes_dec_block_last
        vaesdec	zmm0, zmm0, zmm28
        vaesdec	zmm1, zmm1, zmm28
        vaesdec	zmm0, zmm0, zmm29
        vaesdec	zmm1, zmm1, zmm29
        vmovdqa64	zmm9, zmm30
L_AES_XTS_decrypt_update_avx512_aes_dec_128_aes_dec_block_last:
        vaesdeclast	zmm0, zmm0, zmm9
        vaesdeclast	zmm1, zmm1, zmm9
        vpxorq	zmm0, zmm0, zmm4
        vmovdqu64	[rdx], zmm0
        vpxorq	zmm1, zmm1, zmm5
        vmovdqu64	[rdx+64], zmm1
        vextracti32x4	xmm8, zmm5, 3
        vpshufd	xmm9, xmm8, 19
        vpaddq	xmm8, xmm8, xmm8
        vpsrad	xmm9, xmm9, 31
        vpternlogd	xmm8, xmm9, xmm12, 120
        add	r12d, 128
L_AES_XTS_decrypt_update_avx512_done_128:
        cmp	r12d, eax
        mov	r11d, eax
        je	L_AES_XTS_decrypt_update_avx512_done_dec
        and	r11d, 4294967280
        cmp	r11d, eax
        je	L_AES_XTS_decrypt_update_avx512_mul16_64
        sub	r11d, 16
        sub	r11d, r12d
        cmp	r11d, 16
        jl	L_AES_XTS_decrypt_update_avx512_last_31_start
        add	r11d, r12d
L_AES_XTS_decrypt_update_avx512_mul16_64:
        and	r11d, 4294967232
        cmp	r12d, r11d
        je	L_AES_XTS_decrypt_update_avx512_done_64
        ; 64 bytes of input
        ; aes_dec_64
        lea	rcx, QWORD PTR [rdi+r12]
        lea	rdx, QWORD PTR [rsi+r12]
        vmovdqu64	zmm0, [rcx]
        vshufi64x2	zmm5, zmm8, zmm8, 0
        vpsrlvq	zmm6, zmm5, zmm15
        vpclmulqdq	zmm7, zmm6, zmm13, 1
        vpslldq	zmm6, zmm6, 8
        vpsllvq	zmm4, zmm5, zmm14
        vpternlogq	zmm4, zmm7, zmm6, 150
        ; aes_dec_block
        vpternlogq	zmm0, zmm16, zmm4, 150
        vaesdec	zmm0, zmm0, zmm17
        vaesdec	zmm0, zmm0, zmm18
        vaesdec	zmm0, zmm0, zmm19
        vaesdec	zmm0, zmm0, zmm20
        vaesdec	zmm0, zmm0, zmm21
        vaesdec	zmm0, zmm0, zmm22
        vaesdec	zmm0, zmm0, zmm23
        vaesdec	zmm0, zmm0, zmm24
        vaesdec	zmm0, zmm0, zmm25
        cmp	r9d, 11
        vmovdqa64	zmm9, zmm26
        jl	L_AES_XTS_decrypt_update_avx512_aes_dec_64_aes_dec_block_last
        vaesdec	zmm0, zmm0, zmm26
        vaesdec	zmm0, zmm0, zmm27
        cmp	r9d, 13
        vmovdqa64	zmm9, zmm28
        jl	L_AES_XTS_decrypt_update_avx512_aes_dec_64_aes_dec_block_last
        vaesdec	zmm0, zmm0, zmm28
        vaesdec	zmm0, zmm0, zmm29
        vmovdqa64	zmm9, zmm30
L_AES_XTS_decrypt_update_avx512_aes_dec_64_aes_dec_block_last:
        vaesdeclast	zmm0, zmm0, zmm9
        vpxorq	zmm0, zmm0, zmm4
        vmovdqu64	[rdx], zmm0
        vextracti32x4	xmm8, zmm4, 3
        vpshufd	xmm9, xmm8, 19
        vpaddq	xmm8, xmm8, xmm8
        vpsrad	xmm9, xmm9, 31
        vpternlogd	xmm8, xmm9, xmm12, 120
        add	r12d, 64
L_AES_XTS_decrypt_update_avx512_done_64:
        cmp	r12d, eax
        mov	r11d, eax
        je	L_AES_XTS_decrypt_update_avx512_done_dec
        and	r11d, 4294967280
        cmp	r11d, eax
        je	L_AES_XTS_decrypt_update_avx512_mul16_32
        sub	r11d, 16
        sub	r11d, r12d
        cmp	r11d, 16
        jl	L_AES_XTS_decrypt_update_avx512_last_31_start
        add	r11d, r12d
L_AES_XTS_decrypt_update_avx512_mul16_32:
        and	r11d, 4294967264
        cmp	r12d, r11d
        je	L_AES_XTS_decrypt_update_avx512_done_32
        ; 32 bytes of input
        ; aes_dec_32
        lea	rcx, QWORD PTR [rdi+r12]
        lea	rdx, QWORD PTR [rsi+r12]
        vmovdqu64	ymm0, [rcx]
        vshufi64x2	zmm5, zmm8, zmm8, 0
        vpsrlvq	zmm6, zmm5, zmm15
        vpclmulqdq	zmm7, zmm6, zmm13, 1
        vpslldq	zmm6, zmm6, 8
        vpsllvq	zmm4, zmm5, zmm14
        vpternlogq	zmm4, zmm7, zmm6, 150
        ; aes_dec_block
        vpternlogq	ymm0, ymm16, ymm4, 150
        vaesdec	ymm0, ymm0, ymm17
        vaesdec	ymm0, ymm0, ymm18
        vaesdec	ymm0, ymm0, ymm19
        vaesdec	ymm0, ymm0, ymm20
        vaesdec	ymm0, ymm0, ymm21
        vaesdec	ymm0, ymm0, ymm22
        vaesdec	ymm0, ymm0, ymm23
        vaesdec	ymm0, ymm0, ymm24
        vaesdec	ymm0, ymm0, ymm25
        cmp	r9d, 11
        vmovdqa64	ymm9, ymm26
        jl	L_AES_XTS_decrypt_update_avx512_aes_dec_32_aes_dec_block_last
        vaesdec	ymm0, ymm0, ymm26
        vaesdec	ymm0, ymm0, ymm27
        cmp	r9d, 13
        vmovdqa64	ymm9, ymm28
        jl	L_AES_XTS_decrypt_update_avx512_aes_dec_32_aes_dec_block_last
        vaesdec	ymm0, ymm0, ymm28
        vaesdec	ymm0, ymm0, ymm29
        vmovdqa64	ymm9, ymm30
L_AES_XTS_decrypt_update_avx512_aes_dec_32_aes_dec_block_last:
        vaesdeclast	ymm0, ymm0, ymm9
        vpxorq	ymm0, ymm0, ymm4
        vmovdqu64	[rdx], ymm0
        vextracti32x4	xmm8, zmm4, 2
        add	r12d, 32
L_AES_XTS_decrypt_update_avx512_done_32:
        cmp	r12d, eax
        mov	r11d, eax
        je	L_AES_XTS_decrypt_update_avx512_done_dec
        and	r11d, 4294967280
        cmp	r11d, eax
        je	L_AES_XTS_decrypt_update_avx512_mul16
        sub	r11d, 16
        sub	r11d, r12d
        cmp	r11d, 16
        jl	L_AES_XTS_decrypt_update_avx512_last_31_start
        add	r11d, r12d
L_AES_XTS_decrypt_update_avx512_mul16:
L_AES_XTS_decrypt_update_avx512_dec_16:
        ; 16 bytes of input
        lea	rcx, QWORD PTR [rdi+r12]
        vmovdqu	xmm0, OWORD PTR [rcx]
        vpxor	xmm0, xmm0, xmm8
        ; aes_dec_block
        vpxor	xmm0, xmm0, [r10]
        vmovdqu	xmm5, OWORD PTR [r10+16]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+32]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+48]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+64]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+80]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+96]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+112]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+128]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+144]
        vaesdec	xmm0, xmm0, xmm5
        cmp	r9d, 11
        vmovdqu	xmm5, OWORD PTR [r10+160]
        jl	L_AES_XTS_decrypt_update_avx512_aes_dec_block_last
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r10+176]
        vaesdec	xmm0, xmm0, xmm6
        cmp	r9d, 13
        vmovdqu	xmm5, OWORD PTR [r10+192]
        jl	L_AES_XTS_decrypt_update_avx512_aes_dec_block_last
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r10+208]
        vaesdec	xmm0, xmm0, xmm6
        vmovdqu	xmm5, OWORD PTR [r10+224]
L_AES_XTS_decrypt_update_avx512_aes_dec_block_last:
        vaesdeclast	xmm0, xmm0, xmm5
        vpxor	xmm0, xmm0, xmm8
        lea	rcx, QWORD PTR [rsi+r12]
        vmovdqu	OWORD PTR [rcx], xmm0
        vpshufd	xmm4, xmm8, 19
        vpaddq	xmm8, xmm8, xmm8
        vpsrad	xmm4, xmm4, 31
        vpternlogd	xmm8, xmm4, xmm12, 120
        add	r12d, 16
        cmp	r12d, r11d
        jl	L_AES_XTS_decrypt_update_avx512_dec_16
        cmp	r12d, eax
        je	L_AES_XTS_decrypt_update_avx512_done_dec
L_AES_XTS_decrypt_update_avx512_last_31_start:
        vpshufd	xmm4, xmm8, 19
        vpaddq	xmm7, xmm8, xmm8
        vpsrad	xmm4, xmm4, 31
        vpternlogd	xmm7, xmm4, xmm12, 120
        lea	rcx, QWORD PTR [rdi+r12]
        vmovdqu	xmm0, OWORD PTR [rcx]
        vpxor	xmm0, xmm0, xmm7
        ; aes_dec_block
        vpxor	xmm0, xmm0, [r10]
        vmovdqu	xmm5, OWORD PTR [r10+16]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+32]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+48]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+64]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+80]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+96]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+112]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+128]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+144]
        vaesdec	xmm0, xmm0, xmm5
        cmp	r9d, 11
        vmovdqu	xmm5, OWORD PTR [r10+160]
        jl	L_AES_XTS_decrypt_update_avx512_last_31_aes_dec_block_last
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r10+176]
        vaesdec	xmm0, xmm0, xmm6
        cmp	r9d, 13
        vmovdqu	xmm5, OWORD PTR [r10+192]
        jl	L_AES_XTS_decrypt_update_avx512_last_31_aes_dec_block_last
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r10+208]
        vaesdec	xmm0, xmm0, xmm6
        vmovdqu	xmm5, OWORD PTR [r10+224]
L_AES_XTS_decrypt_update_avx512_last_31_aes_dec_block_last:
        vaesdeclast	xmm0, xmm0, xmm5
        vpxor	xmm0, xmm0, xmm7
        vmovdqu	OWORD PTR [rsp], xmm0
        add	r12, 16
        xor	rdx, rdx
L_AES_XTS_decrypt_update_avx512_last_31_byte_loop:
        mov	r11b, BYTE PTR [rsp+rdx]
        mov	cl, BYTE PTR [rdi+r12]
        mov	BYTE PTR [rsi+r12], r11b
        mov	BYTE PTR [rsp+rdx], cl
        inc	r12d
        inc	edx
        cmp	r12d, eax
        jl	L_AES_XTS_decrypt_update_avx512_last_31_byte_loop
        sub	r12, rdx
        vmovdqu	xmm0, OWORD PTR [rsp]
        vpxor	xmm0, xmm0, xmm8
        ; aes_dec_block
        vpxor	xmm0, xmm0, [r10]
        vmovdqu	xmm5, OWORD PTR [r10+16]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+32]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+48]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+64]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+80]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+96]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+112]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+128]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r10+144]
        vaesdec	xmm0, xmm0, xmm5
        cmp	r9d, 11
        vmovdqu	xmm5, OWORD PTR [r10+160]
        jl	L_AES_XTS_decrypt_update_avx512_last_31_2_aes_dec_block_last
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r10+176]
        vaesdec	xmm0, xmm0, xmm6
        cmp	r9d, 13
        vmovdqu	xmm5, OWORD PTR [r10+192]
        jl	L_AES_XTS_decrypt_update_avx512_last_31_2_aes_dec_block_last
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r10+208]
        vaesdec	xmm0, xmm0, xmm6
        vmovdqu	xmm5, OWORD PTR [r10+224]
L_AES_XTS_decrypt_update_avx512_last_31_2_aes_dec_block_last:
        vaesdeclast	xmm0, xmm0, xmm5
        vpxor	xmm0, xmm0, xmm8
        sub	r12, 16
        lea	rcx, QWORD PTR [rsi+r12]
        vmovdqu	OWORD PTR [rcx], xmm0
L_AES_XTS_decrypt_update_avx512_done_dec:
        vmovdqu	OWORD PTR [r8], xmm8
        vmovdqu	xmm6, OWORD PTR [rsp+64]
        vmovdqu	xmm7, OWORD PTR [rsp+80]
        vmovdqu	xmm8, OWORD PTR [rsp+96]
        vmovdqu	xmm9, OWORD PTR [rsp+112]
        vmovdqu	xmm10, OWORD PTR [rsp+128]
        vmovdqu	xmm11, OWORD PTR [rsp+144]
        vmovdqu	xmm12, OWORD PTR [rsp+160]
        vmovdqu	xmm13, OWORD PTR [rsp+176]
        vmovdqu	xmm14, OWORD PTR [rsp+192]
        vmovdqu	xmm15, OWORD PTR [rsp+208]
        add	rsp, 224
        pop	r12
        pop	rsi
        pop	rdi
        ret
AES_XTS_decrypt_update_avx512 ENDP
_TEXT ENDS
ENDIF
END
