; /* aes_xts_asm.asm */
; /*
;  * Copyright (C) 2006-2024 wolfSSL Inc.
;  *
;  * This file is part of wolfSSL.
;  *
;  * wolfSSL is free software; you can redistribute it and/or modify
;  * it under the terms of the GNU General Public License as published by
;  * the Free Software Foundation; either version 2 of the License, or
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

_text SEGMENT READONLY PARA
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
_text ENDS
_DATA SEGMENT
ALIGN 16
L_aes_xts_gc_xts DWORD 135,1,1,1
ptr_L_aes_xts_gc_xts QWORD L_aes_xts_gc_xts
_DATA ENDS
_text SEGMENT READONLY PARA
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
_text ENDS
_text SEGMENT READONLY PARA
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
_text ENDS
_text SEGMENT READONLY PARA
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
_text ENDS
_text SEGMENT READONLY PARA
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
_text ENDS
IFDEF HAVE_INTEL_AVX1
_text SEGMENT READONLY PARA
AES_XTS_init_avx1 PROC
        mov	eax, r8d
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
        cmp	eax, 11
        vmovdqu	xmm2, OWORD PTR [rdx+160]
        jl	L_AES_XTS_init_avx1_tweak_aes_enc_block_last
        vaesenc	xmm0, xmm0, xmm2
        vmovdqu	xmm3, OWORD PTR [rdx+176]
        vaesenc	xmm0, xmm0, xmm3
        cmp	eax, 13
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
_text ENDS
_DATA SEGMENT
ALIGN 16
L_avx1_aes_xts_gc_xts DWORD 135,1,1,1
ptr_L_avx1_aes_xts_gc_xts QWORD L_avx1_aes_xts_gc_xts
_DATA ENDS
_text SEGMENT READONLY PARA
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
_text ENDS
_text SEGMENT READONLY PARA
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
_text ENDS
_text SEGMENT READONLY PARA
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
_text ENDS
_text SEGMENT READONLY PARA
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
_text ENDS
ENDIF
END
