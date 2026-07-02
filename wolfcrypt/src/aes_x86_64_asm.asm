; /* aes_x86_64_asm.asm */
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
AES_128_Key_Expansion_AESNI PROC
        movdqu	xmm0, OWORD PTR [rcx]
        movdqu	OWORD PTR [rdx], xmm0
        aeskeygenassist	xmm1, xmm0, 1
        pshufd	xmm1, xmm1, 255
        movdqa	xmm2, xmm0
        pslldq	xmm2, 4
        pxor	xmm0, xmm2
        pslldq	xmm2, 4
        pxor	xmm0, xmm2
        pslldq	xmm2, 4
        pxor	xmm0, xmm2
        pxor	xmm0, xmm1
        movdqu	OWORD PTR [rdx+16], xmm0
        aeskeygenassist	xmm1, xmm0, 2
        pshufd	xmm1, xmm1, 255
        movdqa	xmm2, xmm0
        pslldq	xmm2, 4
        pxor	xmm0, xmm2
        pslldq	xmm2, 4
        pxor	xmm0, xmm2
        pslldq	xmm2, 4
        pxor	xmm0, xmm2
        pxor	xmm0, xmm1
        movdqu	OWORD PTR [rdx+32], xmm0
        aeskeygenassist	xmm1, xmm0, 4
        pshufd	xmm1, xmm1, 255
        movdqa	xmm2, xmm0
        pslldq	xmm2, 4
        pxor	xmm0, xmm2
        pslldq	xmm2, 4
        pxor	xmm0, xmm2
        pslldq	xmm2, 4
        pxor	xmm0, xmm2
        pxor	xmm0, xmm1
        movdqu	OWORD PTR [rdx+48], xmm0
        aeskeygenassist	xmm1, xmm0, 8
        pshufd	xmm1, xmm1, 255
        movdqa	xmm2, xmm0
        pslldq	xmm2, 4
        pxor	xmm0, xmm2
        pslldq	xmm2, 4
        pxor	xmm0, xmm2
        pslldq	xmm2, 4
        pxor	xmm0, xmm2
        pxor	xmm0, xmm1
        movdqu	OWORD PTR [rdx+64], xmm0
        aeskeygenassist	xmm1, xmm0, 16
        pshufd	xmm1, xmm1, 255
        movdqa	xmm2, xmm0
        pslldq	xmm2, 4
        pxor	xmm0, xmm2
        pslldq	xmm2, 4
        pxor	xmm0, xmm2
        pslldq	xmm2, 4
        pxor	xmm0, xmm2
        pxor	xmm0, xmm1
        movdqu	OWORD PTR [rdx+80], xmm0
        aeskeygenassist	xmm1, xmm0, 32
        pshufd	xmm1, xmm1, 255
        movdqa	xmm2, xmm0
        pslldq	xmm2, 4
        pxor	xmm0, xmm2
        pslldq	xmm2, 4
        pxor	xmm0, xmm2
        pslldq	xmm2, 4
        pxor	xmm0, xmm2
        pxor	xmm0, xmm1
        movdqu	OWORD PTR [rdx+96], xmm0
        aeskeygenassist	xmm1, xmm0, 64
        pshufd	xmm1, xmm1, 255
        movdqa	xmm2, xmm0
        pslldq	xmm2, 4
        pxor	xmm0, xmm2
        pslldq	xmm2, 4
        pxor	xmm0, xmm2
        pslldq	xmm2, 4
        pxor	xmm0, xmm2
        pxor	xmm0, xmm1
        movdqu	OWORD PTR [rdx+112], xmm0
        aeskeygenassist	xmm1, xmm0, 128
        pshufd	xmm1, xmm1, 255
        movdqa	xmm2, xmm0
        pslldq	xmm2, 4
        pxor	xmm0, xmm2
        pslldq	xmm2, 4
        pxor	xmm0, xmm2
        pslldq	xmm2, 4
        pxor	xmm0, xmm2
        pxor	xmm0, xmm1
        movdqu	OWORD PTR [rdx+128], xmm0
        aeskeygenassist	xmm1, xmm0, 27
        pshufd	xmm1, xmm1, 255
        movdqa	xmm2, xmm0
        pslldq	xmm2, 4
        pxor	xmm0, xmm2
        pslldq	xmm2, 4
        pxor	xmm0, xmm2
        pslldq	xmm2, 4
        pxor	xmm0, xmm2
        pxor	xmm0, xmm1
        movdqu	OWORD PTR [rdx+144], xmm0
        aeskeygenassist	xmm1, xmm0, 54
        pshufd	xmm1, xmm1, 255
        movdqa	xmm2, xmm0
        pslldq	xmm2, 4
        pxor	xmm0, xmm2
        pslldq	xmm2, 4
        pxor	xmm0, xmm2
        pslldq	xmm2, 4
        pxor	xmm0, xmm2
        pxor	xmm0, xmm1
        movdqu	OWORD PTR [rdx+160], xmm0
        ret
AES_128_Key_Expansion_AESNI ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_192_Key_Expansion_AESNI PROC
        movdqu	xmm0, OWORD PTR [rcx]
        pxor	xmm1, xmm1
        pinsrq	xmm1, QWORD PTR [rcx+16], 0
        movdqu	OWORD PTR [rdx], xmm0
        movdqa	xmm4, xmm1
        aeskeygenassist	xmm2, xmm1, 1
        pshufd	xmm2, xmm2, 85
        movdqa	xmm3, xmm0
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pxor	xmm0, xmm2
        pshufd	xmm2, xmm0, 255
        movdqa	xmm3, xmm1
        pslldq	xmm3, 4
        pxor	xmm1, xmm3
        pxor	xmm1, xmm2
        shufpd	xmm4, xmm0, 0
        movdqu	OWORD PTR [rdx+16], xmm4
        movdqa	xmm5, xmm0
        shufpd	xmm5, xmm1, 1
        movdqu	OWORD PTR [rdx+32], xmm5
        aeskeygenassist	xmm2, xmm1, 2
        pshufd	xmm2, xmm2, 85
        movdqa	xmm3, xmm0
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pxor	xmm0, xmm2
        pshufd	xmm2, xmm0, 255
        movdqa	xmm3, xmm1
        pslldq	xmm3, 4
        pxor	xmm1, xmm3
        pxor	xmm1, xmm2
        movdqu	OWORD PTR [rdx+48], xmm0
        movdqa	xmm4, xmm1
        aeskeygenassist	xmm2, xmm1, 4
        pshufd	xmm2, xmm2, 85
        movdqa	xmm3, xmm0
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pxor	xmm0, xmm2
        pshufd	xmm2, xmm0, 255
        movdqa	xmm3, xmm1
        pslldq	xmm3, 4
        pxor	xmm1, xmm3
        pxor	xmm1, xmm2
        shufpd	xmm4, xmm0, 0
        movdqu	OWORD PTR [rdx+64], xmm4
        movdqa	xmm5, xmm0
        shufpd	xmm5, xmm1, 1
        movdqu	OWORD PTR [rdx+80], xmm5
        aeskeygenassist	xmm2, xmm1, 8
        pshufd	xmm2, xmm2, 85
        movdqa	xmm3, xmm0
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pxor	xmm0, xmm2
        pshufd	xmm2, xmm0, 255
        movdqa	xmm3, xmm1
        pslldq	xmm3, 4
        pxor	xmm1, xmm3
        pxor	xmm1, xmm2
        movdqu	OWORD PTR [rdx+96], xmm0
        movdqa	xmm4, xmm1
        aeskeygenassist	xmm2, xmm1, 16
        pshufd	xmm2, xmm2, 85
        movdqa	xmm3, xmm0
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pxor	xmm0, xmm2
        pshufd	xmm2, xmm0, 255
        movdqa	xmm3, xmm1
        pslldq	xmm3, 4
        pxor	xmm1, xmm3
        pxor	xmm1, xmm2
        shufpd	xmm4, xmm0, 0
        movdqu	OWORD PTR [rdx+112], xmm4
        movdqa	xmm5, xmm0
        shufpd	xmm5, xmm1, 1
        movdqu	OWORD PTR [rdx+128], xmm5
        aeskeygenassist	xmm2, xmm1, 32
        pshufd	xmm2, xmm2, 85
        movdqa	xmm3, xmm0
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pxor	xmm0, xmm2
        pshufd	xmm2, xmm0, 255
        movdqa	xmm3, xmm1
        pslldq	xmm3, 4
        pxor	xmm1, xmm3
        pxor	xmm1, xmm2
        movdqu	OWORD PTR [rdx+144], xmm0
        movdqa	xmm4, xmm1
        aeskeygenassist	xmm2, xmm1, 64
        pshufd	xmm2, xmm2, 85
        movdqa	xmm3, xmm0
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pxor	xmm0, xmm2
        pshufd	xmm2, xmm0, 255
        movdqa	xmm3, xmm1
        pslldq	xmm3, 4
        pxor	xmm1, xmm3
        pxor	xmm1, xmm2
        shufpd	xmm4, xmm0, 0
        movdqu	OWORD PTR [rdx+160], xmm4
        movdqa	xmm5, xmm0
        shufpd	xmm5, xmm1, 1
        movdqu	OWORD PTR [rdx+176], xmm5
        aeskeygenassist	xmm2, xmm1, 128
        pshufd	xmm2, xmm2, 85
        movdqa	xmm3, xmm0
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pxor	xmm0, xmm2
        pshufd	xmm2, xmm0, 255
        movdqa	xmm3, xmm1
        pslldq	xmm3, 4
        pxor	xmm1, xmm3
        pxor	xmm1, xmm2
        movdqu	OWORD PTR [rdx+192], xmm0
        movdqu	OWORD PTR [rdx+208], xmm1
        ret
AES_192_Key_Expansion_AESNI ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_256_Key_Expansion_AESNI PROC
        movdqu	xmm0, OWORD PTR [rcx]
        movdqu	xmm1, OWORD PTR [rcx+16]
        movdqu	OWORD PTR [rdx], xmm0
        movdqu	OWORD PTR [rdx+16], xmm1
        aeskeygenassist	xmm2, xmm1, 1
        pshufd	xmm2, xmm2, 255
        movdqa	xmm3, xmm0
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pxor	xmm0, xmm2
        movdqu	OWORD PTR [rdx+32], xmm0
        aeskeygenassist	xmm2, xmm0, 0
        pshufd	xmm2, xmm2, 170
        movdqa	xmm3, xmm1
        pslldq	xmm3, 4
        pxor	xmm1, xmm3
        pslldq	xmm3, 4
        pxor	xmm1, xmm3
        pslldq	xmm3, 4
        pxor	xmm1, xmm3
        pxor	xmm1, xmm2
        movdqu	OWORD PTR [rdx+48], xmm1
        aeskeygenassist	xmm2, xmm1, 2
        pshufd	xmm2, xmm2, 255
        movdqa	xmm3, xmm0
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pxor	xmm0, xmm2
        movdqu	OWORD PTR [rdx+64], xmm0
        aeskeygenassist	xmm2, xmm0, 0
        pshufd	xmm2, xmm2, 170
        movdqa	xmm3, xmm1
        pslldq	xmm3, 4
        pxor	xmm1, xmm3
        pslldq	xmm3, 4
        pxor	xmm1, xmm3
        pslldq	xmm3, 4
        pxor	xmm1, xmm3
        pxor	xmm1, xmm2
        movdqu	OWORD PTR [rdx+80], xmm1
        aeskeygenassist	xmm2, xmm1, 4
        pshufd	xmm2, xmm2, 255
        movdqa	xmm3, xmm0
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pxor	xmm0, xmm2
        movdqu	OWORD PTR [rdx+96], xmm0
        aeskeygenassist	xmm2, xmm0, 0
        pshufd	xmm2, xmm2, 170
        movdqa	xmm3, xmm1
        pslldq	xmm3, 4
        pxor	xmm1, xmm3
        pslldq	xmm3, 4
        pxor	xmm1, xmm3
        pslldq	xmm3, 4
        pxor	xmm1, xmm3
        pxor	xmm1, xmm2
        movdqu	OWORD PTR [rdx+112], xmm1
        aeskeygenassist	xmm2, xmm1, 8
        pshufd	xmm2, xmm2, 255
        movdqa	xmm3, xmm0
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pxor	xmm0, xmm2
        movdqu	OWORD PTR [rdx+128], xmm0
        aeskeygenassist	xmm2, xmm0, 0
        pshufd	xmm2, xmm2, 170
        movdqa	xmm3, xmm1
        pslldq	xmm3, 4
        pxor	xmm1, xmm3
        pslldq	xmm3, 4
        pxor	xmm1, xmm3
        pslldq	xmm3, 4
        pxor	xmm1, xmm3
        pxor	xmm1, xmm2
        movdqu	OWORD PTR [rdx+144], xmm1
        aeskeygenassist	xmm2, xmm1, 16
        pshufd	xmm2, xmm2, 255
        movdqa	xmm3, xmm0
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pxor	xmm0, xmm2
        movdqu	OWORD PTR [rdx+160], xmm0
        aeskeygenassist	xmm2, xmm0, 0
        pshufd	xmm2, xmm2, 170
        movdqa	xmm3, xmm1
        pslldq	xmm3, 4
        pxor	xmm1, xmm3
        pslldq	xmm3, 4
        pxor	xmm1, xmm3
        pslldq	xmm3, 4
        pxor	xmm1, xmm3
        pxor	xmm1, xmm2
        movdqu	OWORD PTR [rdx+176], xmm1
        aeskeygenassist	xmm2, xmm1, 32
        pshufd	xmm2, xmm2, 255
        movdqa	xmm3, xmm0
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pxor	xmm0, xmm2
        movdqu	OWORD PTR [rdx+192], xmm0
        aeskeygenassist	xmm2, xmm0, 0
        pshufd	xmm2, xmm2, 170
        movdqa	xmm3, xmm1
        pslldq	xmm3, 4
        pxor	xmm1, xmm3
        pslldq	xmm3, 4
        pxor	xmm1, xmm3
        pslldq	xmm3, 4
        pxor	xmm1, xmm3
        pxor	xmm1, xmm2
        movdqu	OWORD PTR [rdx+208], xmm1
        aeskeygenassist	xmm2, xmm1, 64
        pshufd	xmm2, xmm2, 255
        movdqa	xmm3, xmm0
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pslldq	xmm3, 4
        pxor	xmm0, xmm3
        pxor	xmm0, xmm2
        movdqu	OWORD PTR [rdx+224], xmm0
        ret
AES_256_Key_Expansion_AESNI ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_ECB_encrypt_AESNI PROC
        mov	eax, DWORD PTR [rsp+40]
        sub	rsp, 16
        movdqu	OWORD PTR [rsp], xmm6
        xor	eax, eax
        cmp	r8d, 64
        mov	r9d, r8d
        jl	L_AES_ECB_encrypt_AESNI_done_64
        and	r9d, 4294967232
L_AES_ECB_encrypt_AESNI_enc_64:
        ; 64 bytes of input
        ; aes_ecb_enc_64
        lea	r10, QWORD PTR [rcx+rax]
        lea	r11, QWORD PTR [rdx+rax]
        movdqu	xmm0, OWORD PTR [r10]
        movdqu	xmm1, OWORD PTR [r10+16]
        movdqu	xmm2, OWORD PTR [r10+32]
        movdqu	xmm3, OWORD PTR [r10+48]
        ; aes_enc_block
        movdqu	xmm4, OWORD PTR [r9]
        pxor	xmm0, xmm4
        pxor	xmm1, xmm4
        pxor	xmm2, xmm4
        pxor	xmm3, xmm4
        movdqu	xmm4, OWORD PTR [r9+16]
        aesenc	xmm0, xmm4
        aesenc	xmm1, xmm4
        aesenc	xmm2, xmm4
        aesenc	xmm3, xmm4
        movdqu	xmm4, OWORD PTR [r9+32]
        aesenc	xmm0, xmm4
        aesenc	xmm1, xmm4
        aesenc	xmm2, xmm4
        aesenc	xmm3, xmm4
        movdqu	xmm4, OWORD PTR [r9+48]
        aesenc	xmm0, xmm4
        aesenc	xmm1, xmm4
        aesenc	xmm2, xmm4
        aesenc	xmm3, xmm4
        movdqu	xmm4, OWORD PTR [r9+64]
        aesenc	xmm0, xmm4
        aesenc	xmm1, xmm4
        aesenc	xmm2, xmm4
        aesenc	xmm3, xmm4
        movdqu	xmm4, OWORD PTR [r9+80]
        aesenc	xmm0, xmm4
        aesenc	xmm1, xmm4
        aesenc	xmm2, xmm4
        aesenc	xmm3, xmm4
        movdqu	xmm4, OWORD PTR [r9+96]
        aesenc	xmm0, xmm4
        aesenc	xmm1, xmm4
        aesenc	xmm2, xmm4
        aesenc	xmm3, xmm4
        movdqu	xmm4, OWORD PTR [r9+112]
        aesenc	xmm0, xmm4
        aesenc	xmm1, xmm4
        aesenc	xmm2, xmm4
        aesenc	xmm3, xmm4
        movdqu	xmm4, OWORD PTR [r9+128]
        aesenc	xmm0, xmm4
        aesenc	xmm1, xmm4
        aesenc	xmm2, xmm4
        aesenc	xmm3, xmm4
        movdqu	xmm4, OWORD PTR [r9+144]
        aesenc	xmm0, xmm4
        aesenc	xmm1, xmm4
        aesenc	xmm2, xmm4
        aesenc	xmm3, xmm4
        cmp	eax, 11
        movdqu	xmm4, OWORD PTR [r9+160]
        jl	L_AES_ECB_encrypt_AESNI_64_aes_enc_block_last
        aesenc	xmm0, xmm4
        aesenc	xmm1, xmm4
        aesenc	xmm2, xmm4
        aesenc	xmm3, xmm4
        movdqu	xmm4, OWORD PTR [r9+176]
        aesenc	xmm0, xmm4
        aesenc	xmm1, xmm4
        aesenc	xmm2, xmm4
        aesenc	xmm3, xmm4
        cmp	eax, 13
        movdqu	xmm4, OWORD PTR [r9+192]
        jl	L_AES_ECB_encrypt_AESNI_64_aes_enc_block_last
        aesenc	xmm0, xmm4
        aesenc	xmm1, xmm4
        aesenc	xmm2, xmm4
        aesenc	xmm3, xmm4
        movdqu	xmm4, OWORD PTR [r9+208]
        aesenc	xmm0, xmm4
        aesenc	xmm1, xmm4
        aesenc	xmm2, xmm4
        aesenc	xmm3, xmm4
        movdqu	xmm4, OWORD PTR [r9+224]
L_AES_ECB_encrypt_AESNI_64_aes_enc_block_last:
        aesenclast	xmm0, xmm4
        aesenclast	xmm1, xmm4
        aesenclast	xmm2, xmm4
        aesenclast	xmm3, xmm4
        movdqu	OWORD PTR [r11], xmm0
        movdqu	OWORD PTR [r11+16], xmm1
        movdqu	OWORD PTR [r11+32], xmm2
        movdqu	OWORD PTR [r11+48], xmm3
        add	eax, 64
        cmp	eax, r9d
        jl	L_AES_ECB_encrypt_AESNI_enc_64
L_AES_ECB_encrypt_AESNI_done_64:
        cmp	eax, r8d
        mov	r9d, r8d
        je	L_AES_ECB_encrypt_AESNI_done_enc
        and	r9d, 4294967280
L_AES_ECB_encrypt_AESNI_enc_16:
        ; 16 bytes of input
        lea	r10, QWORD PTR [rcx+rax]
        movdqu	xmm0, OWORD PTR [r10]
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
        cmp	eax, 11
        movdqu	xmm5, OWORD PTR [r9+160]
        jl	L_AES_ECB_encrypt_AESNI_16_aes_enc_block_last
        aesenc	xmm0, xmm5
        movdqu	xmm6, OWORD PTR [r9+176]
        aesenc	xmm0, xmm6
        cmp	eax, 13
        movdqu	xmm5, OWORD PTR [r9+192]
        jl	L_AES_ECB_encrypt_AESNI_16_aes_enc_block_last
        aesenc	xmm0, xmm5
        movdqu	xmm6, OWORD PTR [r9+208]
        aesenc	xmm0, xmm6
        movdqu	xmm5, OWORD PTR [r9+224]
L_AES_ECB_encrypt_AESNI_16_aes_enc_block_last:
        aesenclast	xmm0, xmm5
        lea	r10, QWORD PTR [rdx+rax]
        movdqu	OWORD PTR [r10], xmm0
        add	eax, 16
        cmp	eax, r9d
        jl	L_AES_ECB_encrypt_AESNI_enc_16
L_AES_ECB_encrypt_AESNI_done_enc:
        movdqu	xmm6, OWORD PTR [rsp]
        add	rsp, 16
        ret
AES_ECB_encrypt_AESNI ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_ECB_decrypt_AESNI PROC
        mov	eax, DWORD PTR [rsp+40]
        sub	rsp, 16
        movdqu	OWORD PTR [rsp], xmm6
        xor	eax, eax
        cmp	r8d, 64
        mov	r9d, r8d
        jl	L_AES_ECB_decrypt_AESNI_done_64
        and	r9d, 4294967232
L_AES_ECB_decrypt_AESNI_dec_64:
        ; 64 bytes of input
        ; aes_ecb_dec_64
        lea	r10, QWORD PTR [rcx+rax]
        lea	r11, QWORD PTR [rdx+rax]
        movdqu	xmm0, OWORD PTR [r10]
        movdqu	xmm1, OWORD PTR [r10+16]
        movdqu	xmm2, OWORD PTR [r10+32]
        movdqu	xmm3, OWORD PTR [r10+48]
        ; aes_dec_block
        movdqu	xmm4, OWORD PTR [r9]
        pxor	xmm0, xmm4
        pxor	xmm1, xmm4
        pxor	xmm2, xmm4
        pxor	xmm3, xmm4
        movdqu	xmm4, OWORD PTR [r9+16]
        aesdec	xmm0, xmm4
        aesdec	xmm1, xmm4
        aesdec	xmm2, xmm4
        aesdec	xmm3, xmm4
        movdqu	xmm4, OWORD PTR [r9+32]
        aesdec	xmm0, xmm4
        aesdec	xmm1, xmm4
        aesdec	xmm2, xmm4
        aesdec	xmm3, xmm4
        movdqu	xmm4, OWORD PTR [r9+48]
        aesdec	xmm0, xmm4
        aesdec	xmm1, xmm4
        aesdec	xmm2, xmm4
        aesdec	xmm3, xmm4
        movdqu	xmm4, OWORD PTR [r9+64]
        aesdec	xmm0, xmm4
        aesdec	xmm1, xmm4
        aesdec	xmm2, xmm4
        aesdec	xmm3, xmm4
        movdqu	xmm4, OWORD PTR [r9+80]
        aesdec	xmm0, xmm4
        aesdec	xmm1, xmm4
        aesdec	xmm2, xmm4
        aesdec	xmm3, xmm4
        movdqu	xmm4, OWORD PTR [r9+96]
        aesdec	xmm0, xmm4
        aesdec	xmm1, xmm4
        aesdec	xmm2, xmm4
        aesdec	xmm3, xmm4
        movdqu	xmm4, OWORD PTR [r9+112]
        aesdec	xmm0, xmm4
        aesdec	xmm1, xmm4
        aesdec	xmm2, xmm4
        aesdec	xmm3, xmm4
        movdqu	xmm4, OWORD PTR [r9+128]
        aesdec	xmm0, xmm4
        aesdec	xmm1, xmm4
        aesdec	xmm2, xmm4
        aesdec	xmm3, xmm4
        movdqu	xmm4, OWORD PTR [r9+144]
        aesdec	xmm0, xmm4
        aesdec	xmm1, xmm4
        aesdec	xmm2, xmm4
        aesdec	xmm3, xmm4
        cmp	eax, 11
        movdqu	xmm4, OWORD PTR [r9+160]
        jl	L_AES_ECB_decrypt_AESNI_64_aes_dec_block_last
        aesdec	xmm0, xmm4
        aesdec	xmm1, xmm4
        aesdec	xmm2, xmm4
        aesdec	xmm3, xmm4
        movdqu	xmm4, OWORD PTR [r9+176]
        aesdec	xmm0, xmm4
        aesdec	xmm1, xmm4
        aesdec	xmm2, xmm4
        aesdec	xmm3, xmm4
        cmp	eax, 13
        movdqu	xmm4, OWORD PTR [r9+192]
        jl	L_AES_ECB_decrypt_AESNI_64_aes_dec_block_last
        aesdec	xmm0, xmm4
        aesdec	xmm1, xmm4
        aesdec	xmm2, xmm4
        aesdec	xmm3, xmm4
        movdqu	xmm4, OWORD PTR [r9+208]
        aesdec	xmm0, xmm4
        aesdec	xmm1, xmm4
        aesdec	xmm2, xmm4
        aesdec	xmm3, xmm4
        movdqu	xmm4, OWORD PTR [r9+224]
L_AES_ECB_decrypt_AESNI_64_aes_dec_block_last:
        aesdeclast	xmm0, xmm4
        aesdeclast	xmm1, xmm4
        aesdeclast	xmm2, xmm4
        aesdeclast	xmm3, xmm4
        movdqu	OWORD PTR [r11], xmm0
        movdqu	OWORD PTR [r11+16], xmm1
        movdqu	OWORD PTR [r11+32], xmm2
        movdqu	OWORD PTR [r11+48], xmm3
        add	eax, 64
        cmp	eax, r9d
        jl	L_AES_ECB_decrypt_AESNI_dec_64
L_AES_ECB_decrypt_AESNI_done_64:
        cmp	eax, r8d
        mov	r9d, r8d
        je	L_AES_ECB_decrypt_AESNI_done_dec
        and	r9d, 4294967280
L_AES_ECB_decrypt_AESNI_dec_16:
        ; 16 bytes of input
        lea	r10, QWORD PTR [rcx+rax]
        movdqu	xmm0, OWORD PTR [r10]
        ; aes_dec_block
        pxor	xmm0, [r9]
        movdqu	xmm5, OWORD PTR [r9+16]
        aesdec	xmm0, xmm5
        movdqu	xmm5, OWORD PTR [r9+32]
        aesdec	xmm0, xmm5
        movdqu	xmm5, OWORD PTR [r9+48]
        aesdec	xmm0, xmm5
        movdqu	xmm5, OWORD PTR [r9+64]
        aesdec	xmm0, xmm5
        movdqu	xmm5, OWORD PTR [r9+80]
        aesdec	xmm0, xmm5
        movdqu	xmm5, OWORD PTR [r9+96]
        aesdec	xmm0, xmm5
        movdqu	xmm5, OWORD PTR [r9+112]
        aesdec	xmm0, xmm5
        movdqu	xmm5, OWORD PTR [r9+128]
        aesdec	xmm0, xmm5
        movdqu	xmm5, OWORD PTR [r9+144]
        aesdec	xmm0, xmm5
        cmp	eax, 11
        movdqu	xmm5, OWORD PTR [r9+160]
        jl	L_AES_ECB_decrypt_AESNI_16_aes_dec_block_last
        aesdec	xmm0, xmm5
        movdqu	xmm6, OWORD PTR [r9+176]
        aesdec	xmm0, xmm6
        cmp	eax, 13
        movdqu	xmm5, OWORD PTR [r9+192]
        jl	L_AES_ECB_decrypt_AESNI_16_aes_dec_block_last
        aesdec	xmm0, xmm5
        movdqu	xmm6, OWORD PTR [r9+208]
        aesdec	xmm0, xmm6
        movdqu	xmm5, OWORD PTR [r9+224]
L_AES_ECB_decrypt_AESNI_16_aes_dec_block_last:
        aesdeclast	xmm0, xmm5
        lea	r10, QWORD PTR [rdx+rax]
        movdqu	OWORD PTR [r10], xmm0
        add	eax, 16
        cmp	eax, r9d
        jl	L_AES_ECB_decrypt_AESNI_dec_16
L_AES_ECB_decrypt_AESNI_done_dec:
        movdqu	xmm6, OWORD PTR [rsp]
        add	rsp, 16
        ret
AES_ECB_decrypt_AESNI ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_CBC_encrypt_AESNI PROC
        mov	rax, QWORD PTR [rsp+40]
        mov	r10d, DWORD PTR [rsp+48]
        movdqu	xmm0, OWORD PTR [r8]
        xor	eax, eax
        cmp	eax, r9d
        je	L_AES_CBC_encrypt_AESNI_done
L_AES_CBC_encrypt_AESNI_loop:
        ; 16 bytes of input
        lea	r10, QWORD PTR [rcx+rax]
        movdqu	xmm1, OWORD PTR [r10]
        pxor	xmm1, xmm0
        ; aes_enc_block
        pxor	xmm1, [rax]
        movdqu	xmm3, OWORD PTR [rax+16]
        aesenc	xmm1, xmm3
        movdqu	xmm3, OWORD PTR [rax+32]
        aesenc	xmm1, xmm3
        movdqu	xmm3, OWORD PTR [rax+48]
        aesenc	xmm1, xmm3
        movdqu	xmm3, OWORD PTR [rax+64]
        aesenc	xmm1, xmm3
        movdqu	xmm3, OWORD PTR [rax+80]
        aesenc	xmm1, xmm3
        movdqu	xmm3, OWORD PTR [rax+96]
        aesenc	xmm1, xmm3
        movdqu	xmm3, OWORD PTR [rax+112]
        aesenc	xmm1, xmm3
        movdqu	xmm3, OWORD PTR [rax+128]
        aesenc	xmm1, xmm3
        movdqu	xmm3, OWORD PTR [rax+144]
        aesenc	xmm1, xmm3
        cmp	r10d, 11
        movdqu	xmm3, OWORD PTR [rax+160]
        jl	L_AES_CBC_encrypt_AESNI_aes_enc_block_last
        aesenc	xmm1, xmm3
        movdqu	xmm4, OWORD PTR [rax+176]
        aesenc	xmm1, xmm4
        cmp	r10d, 13
        movdqu	xmm3, OWORD PTR [rax+192]
        jl	L_AES_CBC_encrypt_AESNI_aes_enc_block_last
        aesenc	xmm1, xmm3
        movdqu	xmm4, OWORD PTR [rax+208]
        aesenc	xmm1, xmm4
        movdqu	xmm3, OWORD PTR [rax+224]
L_AES_CBC_encrypt_AESNI_aes_enc_block_last:
        aesenclast	xmm1, xmm3
        lea	r11, QWORD PTR [rdx+rax]
        movdqu	OWORD PTR [r11], xmm1
        movdqa	xmm0, xmm1
        add	eax, 16
        cmp	eax, r9d
        jl	L_AES_CBC_encrypt_AESNI_loop
L_AES_CBC_encrypt_AESNI_done:
        movdqu	OWORD PTR [r8], xmm0
        ret
AES_CBC_encrypt_AESNI ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_CBC_decrypt_AESNI PROC
        push	r12
        mov	rax, QWORD PTR [rsp+48]
        mov	r10d, DWORD PTR [rsp+56]
        sub	rsp, 48
        movdqu	OWORD PTR [rsp], xmm6
        movdqu	OWORD PTR [rsp+16], xmm7
        movdqu	OWORD PTR [rsp+32], xmm8
        movdqu	xmm4, OWORD PTR [r8]
        xor	eax, eax
        cmp	r9d, 64
        mov	r10d, r9d
        jl	L_AES_CBC_decrypt_AESNI_done_64
        and	r10d, 4294967232
L_AES_CBC_decrypt_AESNI_dec_64:
        ; 64 bytes of input
        ; aes_cbc_dec_64
        lea	r11, QWORD PTR [rcx+rax]
        lea	r12, QWORD PTR [rdx+rax]
        movdqu	xmm0, OWORD PTR [r11]
        movdqu	xmm1, OWORD PTR [r11+16]
        movdqu	xmm2, OWORD PTR [r11+32]
        movdqu	xmm3, OWORD PTR [r11+48]
        ; aes_dec_block
        movdqu	xmm5, OWORD PTR [rax]
        pxor	xmm0, xmm5
        pxor	xmm1, xmm5
        pxor	xmm2, xmm5
        pxor	xmm3, xmm5
        movdqu	xmm5, OWORD PTR [rax+16]
        aesdec	xmm0, xmm5
        aesdec	xmm1, xmm5
        aesdec	xmm2, xmm5
        aesdec	xmm3, xmm5
        movdqu	xmm5, OWORD PTR [rax+32]
        aesdec	xmm0, xmm5
        aesdec	xmm1, xmm5
        aesdec	xmm2, xmm5
        aesdec	xmm3, xmm5
        movdqu	xmm5, OWORD PTR [rax+48]
        aesdec	xmm0, xmm5
        aesdec	xmm1, xmm5
        aesdec	xmm2, xmm5
        aesdec	xmm3, xmm5
        movdqu	xmm5, OWORD PTR [rax+64]
        aesdec	xmm0, xmm5
        aesdec	xmm1, xmm5
        aesdec	xmm2, xmm5
        aesdec	xmm3, xmm5
        movdqu	xmm5, OWORD PTR [rax+80]
        aesdec	xmm0, xmm5
        aesdec	xmm1, xmm5
        aesdec	xmm2, xmm5
        aesdec	xmm3, xmm5
        movdqu	xmm5, OWORD PTR [rax+96]
        aesdec	xmm0, xmm5
        aesdec	xmm1, xmm5
        aesdec	xmm2, xmm5
        aesdec	xmm3, xmm5
        movdqu	xmm5, OWORD PTR [rax+112]
        aesdec	xmm0, xmm5
        aesdec	xmm1, xmm5
        aesdec	xmm2, xmm5
        aesdec	xmm3, xmm5
        movdqu	xmm5, OWORD PTR [rax+128]
        aesdec	xmm0, xmm5
        aesdec	xmm1, xmm5
        aesdec	xmm2, xmm5
        aesdec	xmm3, xmm5
        movdqu	xmm5, OWORD PTR [rax+144]
        aesdec	xmm0, xmm5
        aesdec	xmm1, xmm5
        aesdec	xmm2, xmm5
        aesdec	xmm3, xmm5
        cmp	r10d, 11
        movdqu	xmm5, OWORD PTR [rax+160]
        jl	L_AES_CBC_decrypt_AESNI_64_aes_dec_block_last
        aesdec	xmm0, xmm5
        aesdec	xmm1, xmm5
        aesdec	xmm2, xmm5
        aesdec	xmm3, xmm5
        movdqu	xmm5, OWORD PTR [rax+176]
        aesdec	xmm0, xmm5
        aesdec	xmm1, xmm5
        aesdec	xmm2, xmm5
        aesdec	xmm3, xmm5
        cmp	r10d, 13
        movdqu	xmm5, OWORD PTR [rax+192]
        jl	L_AES_CBC_decrypt_AESNI_64_aes_dec_block_last
        aesdec	xmm0, xmm5
        aesdec	xmm1, xmm5
        aesdec	xmm2, xmm5
        aesdec	xmm3, xmm5
        movdqu	xmm5, OWORD PTR [rax+208]
        aesdec	xmm0, xmm5
        aesdec	xmm1, xmm5
        aesdec	xmm2, xmm5
        aesdec	xmm3, xmm5
        movdqu	xmm5, OWORD PTR [rax+224]
L_AES_CBC_decrypt_AESNI_64_aes_dec_block_last:
        aesdeclast	xmm0, xmm5
        aesdeclast	xmm1, xmm5
        aesdeclast	xmm2, xmm5
        aesdeclast	xmm3, xmm5
        pxor	xmm0, xmm4
        movdqu	xmm5, OWORD PTR [r11]
        pxor	xmm1, xmm5
        movdqu	xmm5, OWORD PTR [r11+16]
        pxor	xmm2, xmm5
        movdqu	xmm5, OWORD PTR [r11+32]
        pxor	xmm3, xmm5
        movdqu	xmm4, OWORD PTR [r11+48]
        movdqu	OWORD PTR [r12], xmm0
        movdqu	OWORD PTR [r12+16], xmm1
        movdqu	OWORD PTR [r12+32], xmm2
        movdqu	OWORD PTR [r12+48], xmm3
        add	eax, 64
        cmp	eax, r10d
        jl	L_AES_CBC_decrypt_AESNI_dec_64
L_AES_CBC_decrypt_AESNI_done_64:
        cmp	eax, r9d
        mov	r10d, r9d
        je	L_AES_CBC_decrypt_AESNI_done_dec
        and	r10d, 4294967280
L_AES_CBC_decrypt_AESNI_dec_16:
        ; 16 bytes of input
        lea	r11, QWORD PTR [rcx+rax]
        movdqu	xmm0, OWORD PTR [r11]
        movdqa	xmm8, xmm0
        ; aes_dec_block
        pxor	xmm0, [rax]
        movdqu	xmm6, OWORD PTR [rax+16]
        aesdec	xmm0, xmm6
        movdqu	xmm6, OWORD PTR [rax+32]
        aesdec	xmm0, xmm6
        movdqu	xmm6, OWORD PTR [rax+48]
        aesdec	xmm0, xmm6
        movdqu	xmm6, OWORD PTR [rax+64]
        aesdec	xmm0, xmm6
        movdqu	xmm6, OWORD PTR [rax+80]
        aesdec	xmm0, xmm6
        movdqu	xmm6, OWORD PTR [rax+96]
        aesdec	xmm0, xmm6
        movdqu	xmm6, OWORD PTR [rax+112]
        aesdec	xmm0, xmm6
        movdqu	xmm6, OWORD PTR [rax+128]
        aesdec	xmm0, xmm6
        movdqu	xmm6, OWORD PTR [rax+144]
        aesdec	xmm0, xmm6
        cmp	r10d, 11
        movdqu	xmm6, OWORD PTR [rax+160]
        jl	L_AES_CBC_decrypt_AESNI_16_aes_dec_block_last
        aesdec	xmm0, xmm6
        movdqu	xmm7, OWORD PTR [rax+176]
        aesdec	xmm0, xmm7
        cmp	r10d, 13
        movdqu	xmm6, OWORD PTR [rax+192]
        jl	L_AES_CBC_decrypt_AESNI_16_aes_dec_block_last
        aesdec	xmm0, xmm6
        movdqu	xmm7, OWORD PTR [rax+208]
        aesdec	xmm0, xmm7
        movdqu	xmm6, OWORD PTR [rax+224]
L_AES_CBC_decrypt_AESNI_16_aes_dec_block_last:
        aesdeclast	xmm0, xmm6
        pxor	xmm0, xmm4
        movdqa	xmm4, xmm8
        lea	r11, QWORD PTR [rdx+rax]
        movdqu	OWORD PTR [r11], xmm0
        add	eax, 16
        cmp	eax, r10d
        jl	L_AES_CBC_decrypt_AESNI_dec_16
L_AES_CBC_decrypt_AESNI_done_dec:
        movdqu	OWORD PTR [r8], xmm4
        movdqu	xmm6, OWORD PTR [rsp]
        movdqu	xmm7, OWORD PTR [rsp+16]
        movdqu	xmm8, OWORD PTR [rsp+32]
        add	rsp, 48
        pop	r12
        ret
AES_CBC_decrypt_AESNI ENDP
_TEXT ENDS
_DATA SEGMENT
ALIGN 16
L_aes_ctr_aesni_bswap QWORD \
     08090a0b0c0d0e0fh,  0001020304050607h
ptr_L_aes_ctr_aesni_bswap QWORD L_aes_ctr_aesni_bswap
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_aes_ctr_aesni_one QWORD \
     0000000000000001h,  0000000000000000h
ptr_L_aes_ctr_aesni_one QWORD L_aes_ctr_aesni_one
_DATA ENDS
_TEXT SEGMENT READONLY PARA
AES_CTR_encrypt_AESNI PROC
        push	rbx
        mov	eax, DWORD PTR [rsp+48]
        mov	r10, QWORD PTR [rsp+56]
        sub	rsp, 96
        movdqu	OWORD PTR [rsp], xmm6
        movdqu	OWORD PTR [rsp+16], xmm7
        movdqu	OWORD PTR [rsp+32], xmm8
        movdqu	OWORD PTR [rsp+48], xmm9
        movdqu	OWORD PTR [rsp+64], xmm10
        movdqu	OWORD PTR [rsp+80], xmm11
        movdqu	xmm8, OWORD PTR L_aes_ctr_aesni_bswap
        movdqu	xmm9, OWORD PTR L_aes_ctr_aesni_one
        pxor	xmm10, xmm10
        movdqu	xmm7, OWORD PTR [r10]
        pshufb	xmm7, xmm8
        xor	eax, eax
        cmp	r8d, 64
        mov	r10d, r8d
        jl	L_AES_CTR_encrypt_AESNI_done_64
        and	r10d, 4294967232
L_AES_CTR_encrypt_AESNI_enc_64:
        ; 64 bytes of input
        ; aes_ctr_enc_64
        lea	r11, QWORD PTR [rcx+rax]
        lea	rbx, QWORD PTR [rdx+rax]
        movdqa	xmm0, xmm7
        pshufb	xmm0, xmm8
        paddq	xmm7, xmm9
        movdqa	xmm11, xmm7
        pcmpeqq	xmm11, xmm10
        pslldq	xmm11, 8
        psrlq	xmm11, 63
        paddq	xmm7, xmm11
        movdqa	xmm1, xmm7
        pshufb	xmm1, xmm8
        paddq	xmm7, xmm9
        movdqa	xmm11, xmm7
        pcmpeqq	xmm11, xmm10
        pslldq	xmm11, 8
        psrlq	xmm11, 63
        paddq	xmm7, xmm11
        movdqa	xmm2, xmm7
        pshufb	xmm2, xmm8
        paddq	xmm7, xmm9
        movdqa	xmm11, xmm7
        pcmpeqq	xmm11, xmm10
        pslldq	xmm11, 8
        psrlq	xmm11, 63
        paddq	xmm7, xmm11
        movdqa	xmm3, xmm7
        pshufb	xmm3, xmm8
        paddq	xmm7, xmm9
        movdqa	xmm11, xmm7
        pcmpeqq	xmm11, xmm10
        pslldq	xmm11, 8
        psrlq	xmm11, 63
        paddq	xmm7, xmm11
        ; aes_enc_block
        movdqu	xmm4, OWORD PTR [r9]
        pxor	xmm0, xmm4
        pxor	xmm1, xmm4
        pxor	xmm2, xmm4
        pxor	xmm3, xmm4
        movdqu	xmm4, OWORD PTR [r9+16]
        aesenc	xmm0, xmm4
        aesenc	xmm1, xmm4
        aesenc	xmm2, xmm4
        aesenc	xmm3, xmm4
        movdqu	xmm4, OWORD PTR [r9+32]
        aesenc	xmm0, xmm4
        aesenc	xmm1, xmm4
        aesenc	xmm2, xmm4
        aesenc	xmm3, xmm4
        movdqu	xmm4, OWORD PTR [r9+48]
        aesenc	xmm0, xmm4
        aesenc	xmm1, xmm4
        aesenc	xmm2, xmm4
        aesenc	xmm3, xmm4
        movdqu	xmm4, OWORD PTR [r9+64]
        aesenc	xmm0, xmm4
        aesenc	xmm1, xmm4
        aesenc	xmm2, xmm4
        aesenc	xmm3, xmm4
        movdqu	xmm4, OWORD PTR [r9+80]
        aesenc	xmm0, xmm4
        aesenc	xmm1, xmm4
        aesenc	xmm2, xmm4
        aesenc	xmm3, xmm4
        movdqu	xmm4, OWORD PTR [r9+96]
        aesenc	xmm0, xmm4
        aesenc	xmm1, xmm4
        aesenc	xmm2, xmm4
        aesenc	xmm3, xmm4
        movdqu	xmm4, OWORD PTR [r9+112]
        aesenc	xmm0, xmm4
        aesenc	xmm1, xmm4
        aesenc	xmm2, xmm4
        aesenc	xmm3, xmm4
        movdqu	xmm4, OWORD PTR [r9+128]
        aesenc	xmm0, xmm4
        aesenc	xmm1, xmm4
        aesenc	xmm2, xmm4
        aesenc	xmm3, xmm4
        movdqu	xmm4, OWORD PTR [r9+144]
        aesenc	xmm0, xmm4
        aesenc	xmm1, xmm4
        aesenc	xmm2, xmm4
        aesenc	xmm3, xmm4
        cmp	eax, 11
        movdqu	xmm4, OWORD PTR [r9+160]
        jl	L_AES_CTR_encrypt_AESNI_64_aes_enc_block_last
        aesenc	xmm0, xmm4
        aesenc	xmm1, xmm4
        aesenc	xmm2, xmm4
        aesenc	xmm3, xmm4
        movdqu	xmm4, OWORD PTR [r9+176]
        aesenc	xmm0, xmm4
        aesenc	xmm1, xmm4
        aesenc	xmm2, xmm4
        aesenc	xmm3, xmm4
        cmp	eax, 13
        movdqu	xmm4, OWORD PTR [r9+192]
        jl	L_AES_CTR_encrypt_AESNI_64_aes_enc_block_last
        aesenc	xmm0, xmm4
        aesenc	xmm1, xmm4
        aesenc	xmm2, xmm4
        aesenc	xmm3, xmm4
        movdqu	xmm4, OWORD PTR [r9+208]
        aesenc	xmm0, xmm4
        aesenc	xmm1, xmm4
        aesenc	xmm2, xmm4
        aesenc	xmm3, xmm4
        movdqu	xmm4, OWORD PTR [r9+224]
L_AES_CTR_encrypt_AESNI_64_aes_enc_block_last:
        aesenclast	xmm0, xmm4
        aesenclast	xmm1, xmm4
        aesenclast	xmm2, xmm4
        aesenclast	xmm3, xmm4
        movdqu	xmm4, OWORD PTR [r11]
        pxor	xmm0, xmm4
        movdqu	xmm4, OWORD PTR [r11+16]
        pxor	xmm1, xmm4
        movdqu	xmm4, OWORD PTR [r11+32]
        pxor	xmm2, xmm4
        movdqu	xmm4, OWORD PTR [r11+48]
        pxor	xmm3, xmm4
        movdqu	OWORD PTR [rbx], xmm0
        movdqu	OWORD PTR [rbx+16], xmm1
        movdqu	OWORD PTR [rbx+32], xmm2
        movdqu	OWORD PTR [rbx+48], xmm3
        add	eax, 64
        cmp	eax, r10d
        jl	L_AES_CTR_encrypt_AESNI_enc_64
L_AES_CTR_encrypt_AESNI_done_64:
        cmp	eax, r8d
        mov	r10d, r8d
        je	L_AES_CTR_encrypt_AESNI_done_enc
        and	r10d, 4294967280
L_AES_CTR_encrypt_AESNI_enc_16:
        ; 16 bytes of input
        movdqa	xmm0, xmm7
        pshufb	xmm0, xmm8
        paddq	xmm7, xmm9
        movdqa	xmm11, xmm7
        pcmpeqq	xmm11, xmm10
        pslldq	xmm11, 8
        psrlq	xmm11, 63
        paddq	xmm7, xmm11
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
        cmp	eax, 11
        movdqu	xmm5, OWORD PTR [r9+160]
        jl	L_AES_CTR_encrypt_AESNI_16_aes_enc_block_last
        aesenc	xmm0, xmm5
        movdqu	xmm6, OWORD PTR [r9+176]
        aesenc	xmm0, xmm6
        cmp	eax, 13
        movdqu	xmm5, OWORD PTR [r9+192]
        jl	L_AES_CTR_encrypt_AESNI_16_aes_enc_block_last
        aesenc	xmm0, xmm5
        movdqu	xmm6, OWORD PTR [r9+208]
        aesenc	xmm0, xmm6
        movdqu	xmm5, OWORD PTR [r9+224]
L_AES_CTR_encrypt_AESNI_16_aes_enc_block_last:
        aesenclast	xmm0, xmm5
        lea	r11, QWORD PTR [rcx+rax]
        movdqu	xmm4, OWORD PTR [r11]
        pxor	xmm0, xmm4
        lea	r11, QWORD PTR [rdx+rax]
        movdqu	OWORD PTR [r11], xmm0
        add	eax, 16
        cmp	eax, r10d
        jl	L_AES_CTR_encrypt_AESNI_enc_16
L_AES_CTR_encrypt_AESNI_done_enc:
        pshufb	xmm7, xmm8
        movdqu	OWORD PTR [r10], xmm7
        movdqu	xmm6, OWORD PTR [rsp]
        movdqu	xmm7, OWORD PTR [rsp+16]
        movdqu	xmm8, OWORD PTR [rsp+32]
        movdqu	xmm9, OWORD PTR [rsp+48]
        movdqu	xmm10, OWORD PTR [rsp+64]
        movdqu	xmm11, OWORD PTR [rsp+80]
        add	rsp, 96
        pop	rbx
        ret
AES_CTR_encrypt_AESNI ENDP
_TEXT ENDS
IFDEF HAVE_INTEL_AVX1
_TEXT SEGMENT READONLY PARA
AES_ECB_encrypt_avx1 PROC
        mov	eax, DWORD PTR [rsp+40]
        sub	rsp, 16
        vmovdqu	OWORD PTR [rsp], xmm6
        xor	eax, eax
        cmp	r8d, 64
        mov	r9d, r8d
        jl	L_AES_ECB_encrypt_avx1_done_64
        and	r9d, 4294967232
L_AES_ECB_encrypt_avx1_enc_64:
        ; 64 bytes of input
        ; aes_ecb_enc_64
        lea	r10, QWORD PTR [rcx+rax]
        lea	r11, QWORD PTR [rdx+rax]
        vmovdqu	xmm0, OWORD PTR [r10]
        vmovdqu	xmm1, OWORD PTR [r10+16]
        vmovdqu	xmm2, OWORD PTR [r10+32]
        vmovdqu	xmm3, OWORD PTR [r10+48]
        ; aes_enc_block
        vmovdqu	xmm4, OWORD PTR [r9]
        vpxor	xmm0, xmm0, xmm4
        vpxor	xmm1, xmm1, xmm4
        vpxor	xmm2, xmm2, xmm4
        vpxor	xmm3, xmm3, xmm4
        vmovdqu	xmm4, OWORD PTR [r9+16]
        vaesenc	xmm0, xmm0, xmm4
        vaesenc	xmm1, xmm1, xmm4
        vaesenc	xmm2, xmm2, xmm4
        vaesenc	xmm3, xmm3, xmm4
        vmovdqu	xmm4, OWORD PTR [r9+32]
        vaesenc	xmm0, xmm0, xmm4
        vaesenc	xmm1, xmm1, xmm4
        vaesenc	xmm2, xmm2, xmm4
        vaesenc	xmm3, xmm3, xmm4
        vmovdqu	xmm4, OWORD PTR [r9+48]
        vaesenc	xmm0, xmm0, xmm4
        vaesenc	xmm1, xmm1, xmm4
        vaesenc	xmm2, xmm2, xmm4
        vaesenc	xmm3, xmm3, xmm4
        vmovdqu	xmm4, OWORD PTR [r9+64]
        vaesenc	xmm0, xmm0, xmm4
        vaesenc	xmm1, xmm1, xmm4
        vaesenc	xmm2, xmm2, xmm4
        vaesenc	xmm3, xmm3, xmm4
        vmovdqu	xmm4, OWORD PTR [r9+80]
        vaesenc	xmm0, xmm0, xmm4
        vaesenc	xmm1, xmm1, xmm4
        vaesenc	xmm2, xmm2, xmm4
        vaesenc	xmm3, xmm3, xmm4
        vmovdqu	xmm4, OWORD PTR [r9+96]
        vaesenc	xmm0, xmm0, xmm4
        vaesenc	xmm1, xmm1, xmm4
        vaesenc	xmm2, xmm2, xmm4
        vaesenc	xmm3, xmm3, xmm4
        vmovdqu	xmm4, OWORD PTR [r9+112]
        vaesenc	xmm0, xmm0, xmm4
        vaesenc	xmm1, xmm1, xmm4
        vaesenc	xmm2, xmm2, xmm4
        vaesenc	xmm3, xmm3, xmm4
        vmovdqu	xmm4, OWORD PTR [r9+128]
        vaesenc	xmm0, xmm0, xmm4
        vaesenc	xmm1, xmm1, xmm4
        vaesenc	xmm2, xmm2, xmm4
        vaesenc	xmm3, xmm3, xmm4
        vmovdqu	xmm4, OWORD PTR [r9+144]
        vaesenc	xmm0, xmm0, xmm4
        vaesenc	xmm1, xmm1, xmm4
        vaesenc	xmm2, xmm2, xmm4
        vaesenc	xmm3, xmm3, xmm4
        cmp	eax, 11
        vmovdqu	xmm4, OWORD PTR [r9+160]
        jl	L_AES_ECB_encrypt_avx1_64_aes_enc_block_last
        vaesenc	xmm0, xmm0, xmm4
        vaesenc	xmm1, xmm1, xmm4
        vaesenc	xmm2, xmm2, xmm4
        vaesenc	xmm3, xmm3, xmm4
        vmovdqu	xmm4, OWORD PTR [r9+176]
        vaesenc	xmm0, xmm0, xmm4
        vaesenc	xmm1, xmm1, xmm4
        vaesenc	xmm2, xmm2, xmm4
        vaesenc	xmm3, xmm3, xmm4
        cmp	eax, 13
        vmovdqu	xmm4, OWORD PTR [r9+192]
        jl	L_AES_ECB_encrypt_avx1_64_aes_enc_block_last
        vaesenc	xmm0, xmm0, xmm4
        vaesenc	xmm1, xmm1, xmm4
        vaesenc	xmm2, xmm2, xmm4
        vaesenc	xmm3, xmm3, xmm4
        vmovdqu	xmm4, OWORD PTR [r9+208]
        vaesenc	xmm0, xmm0, xmm4
        vaesenc	xmm1, xmm1, xmm4
        vaesenc	xmm2, xmm2, xmm4
        vaesenc	xmm3, xmm3, xmm4
        vmovdqu	xmm4, OWORD PTR [r9+224]
L_AES_ECB_encrypt_avx1_64_aes_enc_block_last:
        vaesenclast	xmm0, xmm0, xmm4
        vaesenclast	xmm1, xmm1, xmm4
        vaesenclast	xmm2, xmm2, xmm4
        vaesenclast	xmm3, xmm3, xmm4
        vmovdqu	OWORD PTR [r11], xmm0
        vmovdqu	OWORD PTR [r11+16], xmm1
        vmovdqu	OWORD PTR [r11+32], xmm2
        vmovdqu	OWORD PTR [r11+48], xmm3
        add	eax, 64
        cmp	eax, r9d
        jl	L_AES_ECB_encrypt_avx1_enc_64
L_AES_ECB_encrypt_avx1_done_64:
        cmp	eax, r8d
        mov	r9d, r8d
        je	L_AES_ECB_encrypt_avx1_done_enc
        and	r9d, 4294967280
L_AES_ECB_encrypt_avx1_enc_16:
        ; 16 bytes of input
        lea	r10, QWORD PTR [rcx+rax]
        vmovdqu	xmm0, OWORD PTR [r10]
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
        cmp	eax, 11
        vmovdqu	xmm5, OWORD PTR [r9+160]
        jl	L_AES_ECB_encrypt_avx1_16_aes_enc_block_last
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r9+176]
        vaesenc	xmm0, xmm0, xmm6
        cmp	eax, 13
        vmovdqu	xmm5, OWORD PTR [r9+192]
        jl	L_AES_ECB_encrypt_avx1_16_aes_enc_block_last
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r9+208]
        vaesenc	xmm0, xmm0, xmm6
        vmovdqu	xmm5, OWORD PTR [r9+224]
L_AES_ECB_encrypt_avx1_16_aes_enc_block_last:
        vaesenclast	xmm0, xmm0, xmm5
        lea	r10, QWORD PTR [rdx+rax]
        vmovdqu	OWORD PTR [r10], xmm0
        add	eax, 16
        cmp	eax, r9d
        jl	L_AES_ECB_encrypt_avx1_enc_16
L_AES_ECB_encrypt_avx1_done_enc:
        vmovdqu	xmm6, OWORD PTR [rsp]
        add	rsp, 16
        ret
AES_ECB_encrypt_avx1 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_ECB_decrypt_avx1 PROC
        mov	eax, DWORD PTR [rsp+40]
        sub	rsp, 16
        vmovdqu	OWORD PTR [rsp], xmm6
        xor	eax, eax
        cmp	r8d, 64
        mov	r9d, r8d
        jl	L_AES_ECB_decrypt_avx1_done_64
        and	r9d, 4294967232
L_AES_ECB_decrypt_avx1_dec_64:
        ; 64 bytes of input
        ; aes_ecb_dec_64
        lea	r10, QWORD PTR [rcx+rax]
        lea	r11, QWORD PTR [rdx+rax]
        vmovdqu	xmm0, OWORD PTR [r10]
        vmovdqu	xmm1, OWORD PTR [r10+16]
        vmovdqu	xmm2, OWORD PTR [r10+32]
        vmovdqu	xmm3, OWORD PTR [r10+48]
        ; aes_dec_block
        vmovdqu	xmm4, OWORD PTR [r9]
        vpxor	xmm0, xmm0, xmm4
        vpxor	xmm1, xmm1, xmm4
        vpxor	xmm2, xmm2, xmm4
        vpxor	xmm3, xmm3, xmm4
        vmovdqu	xmm4, OWORD PTR [r9+16]
        vaesdec	xmm0, xmm0, xmm4
        vaesdec	xmm1, xmm1, xmm4
        vaesdec	xmm2, xmm2, xmm4
        vaesdec	xmm3, xmm3, xmm4
        vmovdqu	xmm4, OWORD PTR [r9+32]
        vaesdec	xmm0, xmm0, xmm4
        vaesdec	xmm1, xmm1, xmm4
        vaesdec	xmm2, xmm2, xmm4
        vaesdec	xmm3, xmm3, xmm4
        vmovdqu	xmm4, OWORD PTR [r9+48]
        vaesdec	xmm0, xmm0, xmm4
        vaesdec	xmm1, xmm1, xmm4
        vaesdec	xmm2, xmm2, xmm4
        vaesdec	xmm3, xmm3, xmm4
        vmovdqu	xmm4, OWORD PTR [r9+64]
        vaesdec	xmm0, xmm0, xmm4
        vaesdec	xmm1, xmm1, xmm4
        vaesdec	xmm2, xmm2, xmm4
        vaesdec	xmm3, xmm3, xmm4
        vmovdqu	xmm4, OWORD PTR [r9+80]
        vaesdec	xmm0, xmm0, xmm4
        vaesdec	xmm1, xmm1, xmm4
        vaesdec	xmm2, xmm2, xmm4
        vaesdec	xmm3, xmm3, xmm4
        vmovdqu	xmm4, OWORD PTR [r9+96]
        vaesdec	xmm0, xmm0, xmm4
        vaesdec	xmm1, xmm1, xmm4
        vaesdec	xmm2, xmm2, xmm4
        vaesdec	xmm3, xmm3, xmm4
        vmovdqu	xmm4, OWORD PTR [r9+112]
        vaesdec	xmm0, xmm0, xmm4
        vaesdec	xmm1, xmm1, xmm4
        vaesdec	xmm2, xmm2, xmm4
        vaesdec	xmm3, xmm3, xmm4
        vmovdqu	xmm4, OWORD PTR [r9+128]
        vaesdec	xmm0, xmm0, xmm4
        vaesdec	xmm1, xmm1, xmm4
        vaesdec	xmm2, xmm2, xmm4
        vaesdec	xmm3, xmm3, xmm4
        vmovdqu	xmm4, OWORD PTR [r9+144]
        vaesdec	xmm0, xmm0, xmm4
        vaesdec	xmm1, xmm1, xmm4
        vaesdec	xmm2, xmm2, xmm4
        vaesdec	xmm3, xmm3, xmm4
        cmp	eax, 11
        vmovdqu	xmm4, OWORD PTR [r9+160]
        jl	L_AES_ECB_decrypt_avx1_64_aes_dec_block_last
        vaesdec	xmm0, xmm0, xmm4
        vaesdec	xmm1, xmm1, xmm4
        vaesdec	xmm2, xmm2, xmm4
        vaesdec	xmm3, xmm3, xmm4
        vmovdqu	xmm4, OWORD PTR [r9+176]
        vaesdec	xmm0, xmm0, xmm4
        vaesdec	xmm1, xmm1, xmm4
        vaesdec	xmm2, xmm2, xmm4
        vaesdec	xmm3, xmm3, xmm4
        cmp	eax, 13
        vmovdqu	xmm4, OWORD PTR [r9+192]
        jl	L_AES_ECB_decrypt_avx1_64_aes_dec_block_last
        vaesdec	xmm0, xmm0, xmm4
        vaesdec	xmm1, xmm1, xmm4
        vaesdec	xmm2, xmm2, xmm4
        vaesdec	xmm3, xmm3, xmm4
        vmovdqu	xmm4, OWORD PTR [r9+208]
        vaesdec	xmm0, xmm0, xmm4
        vaesdec	xmm1, xmm1, xmm4
        vaesdec	xmm2, xmm2, xmm4
        vaesdec	xmm3, xmm3, xmm4
        vmovdqu	xmm4, OWORD PTR [r9+224]
L_AES_ECB_decrypt_avx1_64_aes_dec_block_last:
        vaesdeclast	xmm0, xmm0, xmm4
        vaesdeclast	xmm1, xmm1, xmm4
        vaesdeclast	xmm2, xmm2, xmm4
        vaesdeclast	xmm3, xmm3, xmm4
        vmovdqu	OWORD PTR [r11], xmm0
        vmovdqu	OWORD PTR [r11+16], xmm1
        vmovdqu	OWORD PTR [r11+32], xmm2
        vmovdqu	OWORD PTR [r11+48], xmm3
        add	eax, 64
        cmp	eax, r9d
        jl	L_AES_ECB_decrypt_avx1_dec_64
L_AES_ECB_decrypt_avx1_done_64:
        cmp	eax, r8d
        mov	r9d, r8d
        je	L_AES_ECB_decrypt_avx1_done_dec
        and	r9d, 4294967280
L_AES_ECB_decrypt_avx1_dec_16:
        ; 16 bytes of input
        lea	r10, QWORD PTR [rcx+rax]
        vmovdqu	xmm0, OWORD PTR [r10]
        ; aes_dec_block
        vpxor	xmm0, xmm0, [r9]
        vmovdqu	xmm5, OWORD PTR [r9+16]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+32]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+48]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+64]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+80]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+96]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+112]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+128]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+144]
        vaesdec	xmm0, xmm0, xmm5
        cmp	eax, 11
        vmovdqu	xmm5, OWORD PTR [r9+160]
        jl	L_AES_ECB_decrypt_avx1_16_aes_dec_block_last
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r9+176]
        vaesdec	xmm0, xmm0, xmm6
        cmp	eax, 13
        vmovdqu	xmm5, OWORD PTR [r9+192]
        jl	L_AES_ECB_decrypt_avx1_16_aes_dec_block_last
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r9+208]
        vaesdec	xmm0, xmm0, xmm6
        vmovdqu	xmm5, OWORD PTR [r9+224]
L_AES_ECB_decrypt_avx1_16_aes_dec_block_last:
        vaesdeclast	xmm0, xmm0, xmm5
        lea	r10, QWORD PTR [rdx+rax]
        vmovdqu	OWORD PTR [r10], xmm0
        add	eax, 16
        cmp	eax, r9d
        jl	L_AES_ECB_decrypt_avx1_dec_16
L_AES_ECB_decrypt_avx1_done_dec:
        vmovdqu	xmm6, OWORD PTR [rsp]
        add	rsp, 16
        ret
AES_ECB_decrypt_avx1 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_CBC_encrypt_avx1 PROC
        mov	rax, QWORD PTR [rsp+40]
        mov	r10d, DWORD PTR [rsp+48]
        vmovdqu	xmm0, OWORD PTR [r8]
        xor	eax, eax
        cmp	eax, r9d
        je	L_AES_CBC_encrypt_avx1_done
L_AES_CBC_encrypt_avx1_loop:
        ; 16 bytes of input
        lea	r10, QWORD PTR [rcx+rax]
        vmovdqu	xmm1, OWORD PTR [r10]
        vpxor	xmm1, xmm1, xmm0
        ; aes_enc_block
        vpxor	xmm1, xmm1, [rax]
        vmovdqu	xmm3, OWORD PTR [rax+16]
        vaesenc	xmm1, xmm1, xmm3
        vmovdqu	xmm3, OWORD PTR [rax+32]
        vaesenc	xmm1, xmm1, xmm3
        vmovdqu	xmm3, OWORD PTR [rax+48]
        vaesenc	xmm1, xmm1, xmm3
        vmovdqu	xmm3, OWORD PTR [rax+64]
        vaesenc	xmm1, xmm1, xmm3
        vmovdqu	xmm3, OWORD PTR [rax+80]
        vaesenc	xmm1, xmm1, xmm3
        vmovdqu	xmm3, OWORD PTR [rax+96]
        vaesenc	xmm1, xmm1, xmm3
        vmovdqu	xmm3, OWORD PTR [rax+112]
        vaesenc	xmm1, xmm1, xmm3
        vmovdqu	xmm3, OWORD PTR [rax+128]
        vaesenc	xmm1, xmm1, xmm3
        vmovdqu	xmm3, OWORD PTR [rax+144]
        vaesenc	xmm1, xmm1, xmm3
        cmp	r10d, 11
        vmovdqu	xmm3, OWORD PTR [rax+160]
        jl	L_AES_CBC_encrypt_avx1_aes_enc_block_last
        vaesenc	xmm1, xmm1, xmm3
        vmovdqu	xmm4, OWORD PTR [rax+176]
        vaesenc	xmm1, xmm1, xmm4
        cmp	r10d, 13
        vmovdqu	xmm3, OWORD PTR [rax+192]
        jl	L_AES_CBC_encrypt_avx1_aes_enc_block_last
        vaesenc	xmm1, xmm1, xmm3
        vmovdqu	xmm4, OWORD PTR [rax+208]
        vaesenc	xmm1, xmm1, xmm4
        vmovdqu	xmm3, OWORD PTR [rax+224]
L_AES_CBC_encrypt_avx1_aes_enc_block_last:
        vaesenclast	xmm1, xmm1, xmm3
        lea	r11, QWORD PTR [rdx+rax]
        vmovdqu	OWORD PTR [r11], xmm1
        vmovdqa	xmm0, xmm1
        add	eax, 16
        cmp	eax, r9d
        jl	L_AES_CBC_encrypt_avx1_loop
L_AES_CBC_encrypt_avx1_done:
        vmovdqu	OWORD PTR [r8], xmm0
        ret
AES_CBC_encrypt_avx1 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_CBC_decrypt_avx1 PROC
        push	r12
        mov	rax, QWORD PTR [rsp+48]
        mov	r10d, DWORD PTR [rsp+56]
        sub	rsp, 48
        vmovdqu	OWORD PTR [rsp], xmm6
        vmovdqu	OWORD PTR [rsp+16], xmm7
        vmovdqu	OWORD PTR [rsp+32], xmm8
        vmovdqu	xmm4, OWORD PTR [r8]
        xor	eax, eax
        cmp	r9d, 64
        mov	r10d, r9d
        jl	L_AES_CBC_decrypt_avx1_done_64
        and	r10d, 4294967232
L_AES_CBC_decrypt_avx1_dec_64:
        ; 64 bytes of input
        ; aes_cbc_dec_64
        lea	r11, QWORD PTR [rcx+rax]
        lea	r12, QWORD PTR [rdx+rax]
        vmovdqu	xmm0, OWORD PTR [r11]
        vmovdqu	xmm1, OWORD PTR [r11+16]
        vmovdqu	xmm2, OWORD PTR [r11+32]
        vmovdqu	xmm3, OWORD PTR [r11+48]
        ; aes_dec_block
        vmovdqu	xmm5, OWORD PTR [rax]
        vpxor	xmm0, xmm0, xmm5
        vpxor	xmm1, xmm1, xmm5
        vpxor	xmm2, xmm2, xmm5
        vpxor	xmm3, xmm3, xmm5
        vmovdqu	xmm5, OWORD PTR [rax+16]
        vaesdec	xmm0, xmm0, xmm5
        vaesdec	xmm1, xmm1, xmm5
        vaesdec	xmm2, xmm2, xmm5
        vaesdec	xmm3, xmm3, xmm5
        vmovdqu	xmm5, OWORD PTR [rax+32]
        vaesdec	xmm0, xmm0, xmm5
        vaesdec	xmm1, xmm1, xmm5
        vaesdec	xmm2, xmm2, xmm5
        vaesdec	xmm3, xmm3, xmm5
        vmovdqu	xmm5, OWORD PTR [rax+48]
        vaesdec	xmm0, xmm0, xmm5
        vaesdec	xmm1, xmm1, xmm5
        vaesdec	xmm2, xmm2, xmm5
        vaesdec	xmm3, xmm3, xmm5
        vmovdqu	xmm5, OWORD PTR [rax+64]
        vaesdec	xmm0, xmm0, xmm5
        vaesdec	xmm1, xmm1, xmm5
        vaesdec	xmm2, xmm2, xmm5
        vaesdec	xmm3, xmm3, xmm5
        vmovdqu	xmm5, OWORD PTR [rax+80]
        vaesdec	xmm0, xmm0, xmm5
        vaesdec	xmm1, xmm1, xmm5
        vaesdec	xmm2, xmm2, xmm5
        vaesdec	xmm3, xmm3, xmm5
        vmovdqu	xmm5, OWORD PTR [rax+96]
        vaesdec	xmm0, xmm0, xmm5
        vaesdec	xmm1, xmm1, xmm5
        vaesdec	xmm2, xmm2, xmm5
        vaesdec	xmm3, xmm3, xmm5
        vmovdqu	xmm5, OWORD PTR [rax+112]
        vaesdec	xmm0, xmm0, xmm5
        vaesdec	xmm1, xmm1, xmm5
        vaesdec	xmm2, xmm2, xmm5
        vaesdec	xmm3, xmm3, xmm5
        vmovdqu	xmm5, OWORD PTR [rax+128]
        vaesdec	xmm0, xmm0, xmm5
        vaesdec	xmm1, xmm1, xmm5
        vaesdec	xmm2, xmm2, xmm5
        vaesdec	xmm3, xmm3, xmm5
        vmovdqu	xmm5, OWORD PTR [rax+144]
        vaesdec	xmm0, xmm0, xmm5
        vaesdec	xmm1, xmm1, xmm5
        vaesdec	xmm2, xmm2, xmm5
        vaesdec	xmm3, xmm3, xmm5
        cmp	r10d, 11
        vmovdqu	xmm5, OWORD PTR [rax+160]
        jl	L_AES_CBC_decrypt_avx1_64_aes_dec_block_last
        vaesdec	xmm0, xmm0, xmm5
        vaesdec	xmm1, xmm1, xmm5
        vaesdec	xmm2, xmm2, xmm5
        vaesdec	xmm3, xmm3, xmm5
        vmovdqu	xmm5, OWORD PTR [rax+176]
        vaesdec	xmm0, xmm0, xmm5
        vaesdec	xmm1, xmm1, xmm5
        vaesdec	xmm2, xmm2, xmm5
        vaesdec	xmm3, xmm3, xmm5
        cmp	r10d, 13
        vmovdqu	xmm5, OWORD PTR [rax+192]
        jl	L_AES_CBC_decrypt_avx1_64_aes_dec_block_last
        vaesdec	xmm0, xmm0, xmm5
        vaesdec	xmm1, xmm1, xmm5
        vaesdec	xmm2, xmm2, xmm5
        vaesdec	xmm3, xmm3, xmm5
        vmovdqu	xmm5, OWORD PTR [rax+208]
        vaesdec	xmm0, xmm0, xmm5
        vaesdec	xmm1, xmm1, xmm5
        vaesdec	xmm2, xmm2, xmm5
        vaesdec	xmm3, xmm3, xmm5
        vmovdqu	xmm5, OWORD PTR [rax+224]
L_AES_CBC_decrypt_avx1_64_aes_dec_block_last:
        vaesdeclast	xmm0, xmm0, xmm5
        vaesdeclast	xmm1, xmm1, xmm5
        vaesdeclast	xmm2, xmm2, xmm5
        vaesdeclast	xmm3, xmm3, xmm5
        vpxor	xmm0, xmm0, xmm4
        vpxor	xmm1, xmm1, [r11]
        vpxor	xmm2, xmm2, [r11+16]
        vpxor	xmm3, xmm3, [r11+32]
        vmovdqu	xmm4, OWORD PTR [r11+48]
        vmovdqu	OWORD PTR [r12], xmm0
        vmovdqu	OWORD PTR [r12+16], xmm1
        vmovdqu	OWORD PTR [r12+32], xmm2
        vmovdqu	OWORD PTR [r12+48], xmm3
        add	eax, 64
        cmp	eax, r10d
        jl	L_AES_CBC_decrypt_avx1_dec_64
L_AES_CBC_decrypt_avx1_done_64:
        cmp	eax, r9d
        mov	r10d, r9d
        je	L_AES_CBC_decrypt_avx1_done_dec
        and	r10d, 4294967280
L_AES_CBC_decrypt_avx1_dec_16:
        ; 16 bytes of input
        lea	r11, QWORD PTR [rcx+rax]
        vmovdqu	xmm0, OWORD PTR [r11]
        vmovdqa	xmm8, xmm0
        ; aes_dec_block
        vpxor	xmm0, xmm0, [rax]
        vmovdqu	xmm6, OWORD PTR [rax+16]
        vaesdec	xmm0, xmm0, xmm6
        vmovdqu	xmm6, OWORD PTR [rax+32]
        vaesdec	xmm0, xmm0, xmm6
        vmovdqu	xmm6, OWORD PTR [rax+48]
        vaesdec	xmm0, xmm0, xmm6
        vmovdqu	xmm6, OWORD PTR [rax+64]
        vaesdec	xmm0, xmm0, xmm6
        vmovdqu	xmm6, OWORD PTR [rax+80]
        vaesdec	xmm0, xmm0, xmm6
        vmovdqu	xmm6, OWORD PTR [rax+96]
        vaesdec	xmm0, xmm0, xmm6
        vmovdqu	xmm6, OWORD PTR [rax+112]
        vaesdec	xmm0, xmm0, xmm6
        vmovdqu	xmm6, OWORD PTR [rax+128]
        vaesdec	xmm0, xmm0, xmm6
        vmovdqu	xmm6, OWORD PTR [rax+144]
        vaesdec	xmm0, xmm0, xmm6
        cmp	r10d, 11
        vmovdqu	xmm6, OWORD PTR [rax+160]
        jl	L_AES_CBC_decrypt_avx1_16_aes_dec_block_last
        vaesdec	xmm0, xmm0, xmm6
        vmovdqu	xmm7, OWORD PTR [rax+176]
        vaesdec	xmm0, xmm0, xmm7
        cmp	r10d, 13
        vmovdqu	xmm6, OWORD PTR [rax+192]
        jl	L_AES_CBC_decrypt_avx1_16_aes_dec_block_last
        vaesdec	xmm0, xmm0, xmm6
        vmovdqu	xmm7, OWORD PTR [rax+208]
        vaesdec	xmm0, xmm0, xmm7
        vmovdqu	xmm6, OWORD PTR [rax+224]
L_AES_CBC_decrypt_avx1_16_aes_dec_block_last:
        vaesdeclast	xmm0, xmm0, xmm6
        vpxor	xmm0, xmm0, xmm4
        vmovdqa	xmm4, xmm8
        lea	r11, QWORD PTR [rdx+rax]
        vmovdqu	OWORD PTR [r11], xmm0
        add	eax, 16
        cmp	eax, r10d
        jl	L_AES_CBC_decrypt_avx1_dec_16
L_AES_CBC_decrypt_avx1_done_dec:
        vmovdqu	OWORD PTR [r8], xmm4
        vmovdqu	xmm6, OWORD PTR [rsp]
        vmovdqu	xmm7, OWORD PTR [rsp+16]
        vmovdqu	xmm8, OWORD PTR [rsp+32]
        add	rsp, 48
        pop	r12
        ret
AES_CBC_decrypt_avx1 ENDP
_TEXT ENDS
_DATA SEGMENT
ALIGN 16
L_aes_ctr_avx1_bswap QWORD \
     08090a0b0c0d0e0fh,  0001020304050607h
ptr_L_aes_ctr_avx1_bswap QWORD L_aes_ctr_avx1_bswap
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_aes_ctr_avx1_one QWORD \
     0000000000000001h,  0000000000000000h
ptr_L_aes_ctr_avx1_one QWORD L_aes_ctr_avx1_one
_DATA ENDS
_TEXT SEGMENT READONLY PARA
AES_CTR_encrypt_avx1 PROC
        push	rbx
        mov	eax, DWORD PTR [rsp+48]
        mov	r10, QWORD PTR [rsp+56]
        sub	rsp, 96
        vmovdqu	OWORD PTR [rsp], xmm6
        vmovdqu	OWORD PTR [rsp+16], xmm7
        vmovdqu	OWORD PTR [rsp+32], xmm8
        vmovdqu	OWORD PTR [rsp+48], xmm9
        vmovdqu	OWORD PTR [rsp+64], xmm10
        vmovdqu	OWORD PTR [rsp+80], xmm11
        vmovdqu	xmm8, OWORD PTR L_aes_ctr_avx1_bswap
        vmovdqu	xmm9, OWORD PTR L_aes_ctr_avx1_one
        vpxor	xmm10, xmm10, xmm10
        vmovdqu	xmm7, OWORD PTR [r10]
        vpshufb	xmm7, xmm7, xmm8
        xor	eax, eax
        cmp	r8d, 64
        mov	r10d, r8d
        jl	L_AES_CTR_encrypt_avx1_done_64
        and	r10d, 4294967232
L_AES_CTR_encrypt_avx1_enc_64:
        ; 64 bytes of input
        ; aes_ctr_enc_64
        lea	r11, QWORD PTR [rcx+rax]
        lea	rbx, QWORD PTR [rdx+rax]
        vpshufb	xmm0, xmm7, xmm8
        vpaddq	xmm7, xmm7, xmm9
        vpcmpeqq	xmm11, xmm7, xmm10
        vpslldq	xmm11, xmm11, 8
        vpsrlq	xmm11, xmm11, 63
        vpaddq	xmm7, xmm7, xmm11
        vpshufb	xmm1, xmm7, xmm8
        vpaddq	xmm7, xmm7, xmm9
        vpcmpeqq	xmm11, xmm7, xmm10
        vpslldq	xmm11, xmm11, 8
        vpsrlq	xmm11, xmm11, 63
        vpaddq	xmm7, xmm7, xmm11
        vpshufb	xmm2, xmm7, xmm8
        vpaddq	xmm7, xmm7, xmm9
        vpcmpeqq	xmm11, xmm7, xmm10
        vpslldq	xmm11, xmm11, 8
        vpsrlq	xmm11, xmm11, 63
        vpaddq	xmm7, xmm7, xmm11
        vpshufb	xmm3, xmm7, xmm8
        vpaddq	xmm7, xmm7, xmm9
        vpcmpeqq	xmm11, xmm7, xmm10
        vpslldq	xmm11, xmm11, 8
        vpsrlq	xmm11, xmm11, 63
        vpaddq	xmm7, xmm7, xmm11
        ; aes_enc_block
        vmovdqu	xmm4, OWORD PTR [r9]
        vpxor	xmm0, xmm0, xmm4
        vpxor	xmm1, xmm1, xmm4
        vpxor	xmm2, xmm2, xmm4
        vpxor	xmm3, xmm3, xmm4
        vmovdqu	xmm4, OWORD PTR [r9+16]
        vaesenc	xmm0, xmm0, xmm4
        vaesenc	xmm1, xmm1, xmm4
        vaesenc	xmm2, xmm2, xmm4
        vaesenc	xmm3, xmm3, xmm4
        vmovdqu	xmm4, OWORD PTR [r9+32]
        vaesenc	xmm0, xmm0, xmm4
        vaesenc	xmm1, xmm1, xmm4
        vaesenc	xmm2, xmm2, xmm4
        vaesenc	xmm3, xmm3, xmm4
        vmovdqu	xmm4, OWORD PTR [r9+48]
        vaesenc	xmm0, xmm0, xmm4
        vaesenc	xmm1, xmm1, xmm4
        vaesenc	xmm2, xmm2, xmm4
        vaesenc	xmm3, xmm3, xmm4
        vmovdqu	xmm4, OWORD PTR [r9+64]
        vaesenc	xmm0, xmm0, xmm4
        vaesenc	xmm1, xmm1, xmm4
        vaesenc	xmm2, xmm2, xmm4
        vaesenc	xmm3, xmm3, xmm4
        vmovdqu	xmm4, OWORD PTR [r9+80]
        vaesenc	xmm0, xmm0, xmm4
        vaesenc	xmm1, xmm1, xmm4
        vaesenc	xmm2, xmm2, xmm4
        vaesenc	xmm3, xmm3, xmm4
        vmovdqu	xmm4, OWORD PTR [r9+96]
        vaesenc	xmm0, xmm0, xmm4
        vaesenc	xmm1, xmm1, xmm4
        vaesenc	xmm2, xmm2, xmm4
        vaesenc	xmm3, xmm3, xmm4
        vmovdqu	xmm4, OWORD PTR [r9+112]
        vaesenc	xmm0, xmm0, xmm4
        vaesenc	xmm1, xmm1, xmm4
        vaesenc	xmm2, xmm2, xmm4
        vaesenc	xmm3, xmm3, xmm4
        vmovdqu	xmm4, OWORD PTR [r9+128]
        vaesenc	xmm0, xmm0, xmm4
        vaesenc	xmm1, xmm1, xmm4
        vaesenc	xmm2, xmm2, xmm4
        vaesenc	xmm3, xmm3, xmm4
        vmovdqu	xmm4, OWORD PTR [r9+144]
        vaesenc	xmm0, xmm0, xmm4
        vaesenc	xmm1, xmm1, xmm4
        vaesenc	xmm2, xmm2, xmm4
        vaesenc	xmm3, xmm3, xmm4
        cmp	eax, 11
        vmovdqu	xmm4, OWORD PTR [r9+160]
        jl	L_AES_CTR_encrypt_avx1_64_aes_enc_block_last
        vaesenc	xmm0, xmm0, xmm4
        vaesenc	xmm1, xmm1, xmm4
        vaesenc	xmm2, xmm2, xmm4
        vaesenc	xmm3, xmm3, xmm4
        vmovdqu	xmm4, OWORD PTR [r9+176]
        vaesenc	xmm0, xmm0, xmm4
        vaesenc	xmm1, xmm1, xmm4
        vaesenc	xmm2, xmm2, xmm4
        vaesenc	xmm3, xmm3, xmm4
        cmp	eax, 13
        vmovdqu	xmm4, OWORD PTR [r9+192]
        jl	L_AES_CTR_encrypt_avx1_64_aes_enc_block_last
        vaesenc	xmm0, xmm0, xmm4
        vaesenc	xmm1, xmm1, xmm4
        vaesenc	xmm2, xmm2, xmm4
        vaesenc	xmm3, xmm3, xmm4
        vmovdqu	xmm4, OWORD PTR [r9+208]
        vaesenc	xmm0, xmm0, xmm4
        vaesenc	xmm1, xmm1, xmm4
        vaesenc	xmm2, xmm2, xmm4
        vaesenc	xmm3, xmm3, xmm4
        vmovdqu	xmm4, OWORD PTR [r9+224]
L_AES_CTR_encrypt_avx1_64_aes_enc_block_last:
        vaesenclast	xmm0, xmm0, xmm4
        vaesenclast	xmm1, xmm1, xmm4
        vaesenclast	xmm2, xmm2, xmm4
        vaesenclast	xmm3, xmm3, xmm4
        vpxor	xmm0, xmm0, [r11]
        vpxor	xmm1, xmm1, [r11+16]
        vpxor	xmm2, xmm2, [r11+32]
        vpxor	xmm3, xmm3, [r11+48]
        vmovdqu	OWORD PTR [rbx], xmm0
        vmovdqu	OWORD PTR [rbx+16], xmm1
        vmovdqu	OWORD PTR [rbx+32], xmm2
        vmovdqu	OWORD PTR [rbx+48], xmm3
        add	eax, 64
        cmp	eax, r10d
        jl	L_AES_CTR_encrypt_avx1_enc_64
L_AES_CTR_encrypt_avx1_done_64:
        cmp	eax, r8d
        mov	r10d, r8d
        je	L_AES_CTR_encrypt_avx1_done_enc
        and	r10d, 4294967280
L_AES_CTR_encrypt_avx1_enc_16:
        ; 16 bytes of input
        vpshufb	xmm0, xmm7, xmm8
        vpaddq	xmm7, xmm7, xmm9
        vpcmpeqq	xmm11, xmm7, xmm10
        vpslldq	xmm11, xmm11, 8
        vpsrlq	xmm11, xmm11, 63
        vpaddq	xmm7, xmm7, xmm11
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
        cmp	eax, 11
        vmovdqu	xmm5, OWORD PTR [r9+160]
        jl	L_AES_CTR_encrypt_avx1_16_aes_enc_block_last
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r9+176]
        vaesenc	xmm0, xmm0, xmm6
        cmp	eax, 13
        vmovdqu	xmm5, OWORD PTR [r9+192]
        jl	L_AES_CTR_encrypt_avx1_16_aes_enc_block_last
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r9+208]
        vaesenc	xmm0, xmm0, xmm6
        vmovdqu	xmm5, OWORD PTR [r9+224]
L_AES_CTR_encrypt_avx1_16_aes_enc_block_last:
        vaesenclast	xmm0, xmm0, xmm5
        lea	r11, QWORD PTR [rcx+rax]
        vpxor	xmm0, xmm0, [r11]
        lea	r11, QWORD PTR [rdx+rax]
        vmovdqu	OWORD PTR [r11], xmm0
        add	eax, 16
        cmp	eax, r10d
        jl	L_AES_CTR_encrypt_avx1_enc_16
L_AES_CTR_encrypt_avx1_done_enc:
        vpshufb	xmm7, xmm7, xmm8
        vmovdqu	OWORD PTR [r10], xmm7
        vmovdqu	xmm6, OWORD PTR [rsp]
        vmovdqu	xmm7, OWORD PTR [rsp+16]
        vmovdqu	xmm8, OWORD PTR [rsp+32]
        vmovdqu	xmm9, OWORD PTR [rsp+48]
        vmovdqu	xmm10, OWORD PTR [rsp+64]
        vmovdqu	xmm11, OWORD PTR [rsp+80]
        add	rsp, 96
        pop	rbx
        ret
AES_CTR_encrypt_avx1 ENDP
_TEXT ENDS
ENDIF
IFDEF HAVE_INTEL_VAES
_TEXT SEGMENT READONLY PARA
AES_ECB_encrypt_vaes PROC
        mov	eax, DWORD PTR [rsp+40]
        sub	rsp, 32
        vmovdqu	OWORD PTR [rsp], xmm6
        vmovdqu	OWORD PTR [rsp+16], xmm7
        xor	eax, eax
        cmp	r8d, 128
        mov	r9d, r8d
        jl	L_AES_ECB_encrypt_vaes_done_128
        and	r9d, 4294967168
L_AES_ECB_encrypt_vaes_enc_128:
        ; 128 bytes of input
        ; aes_ecb_enc_128
        lea	r10, QWORD PTR [rcx+rax]
        lea	r11, QWORD PTR [rdx+rax]
        vmovdqu	ymm0, YMMWORD PTR [r10]
        vmovdqu	ymm1, YMMWORD PTR [r10+32]
        vmovdqu	ymm2, YMMWORD PTR [r10+64]
        vmovdqu	ymm3, YMMWORD PTR [r10+96]
        ; aes_enc_block
        vbroadcasti128	ymm7, [r9]
        vpxor	ymm0, ymm0, ymm7
        vpxor	ymm1, ymm1, ymm7
        vpxor	ymm2, ymm2, ymm7
        vpxor	ymm3, ymm3, ymm7
        vbroadcasti128	ymm7, [r9+16]
        vaesenc	ymm0, ymm0, ymm7
        vaesenc	ymm1, ymm1, ymm7
        vaesenc	ymm2, ymm2, ymm7
        vaesenc	ymm3, ymm3, ymm7
        vbroadcasti128	ymm7, [r9+32]
        vaesenc	ymm0, ymm0, ymm7
        vaesenc	ymm1, ymm1, ymm7
        vaesenc	ymm2, ymm2, ymm7
        vaesenc	ymm3, ymm3, ymm7
        vbroadcasti128	ymm7, [r9+48]
        vaesenc	ymm0, ymm0, ymm7
        vaesenc	ymm1, ymm1, ymm7
        vaesenc	ymm2, ymm2, ymm7
        vaesenc	ymm3, ymm3, ymm7
        vbroadcasti128	ymm7, [r9+64]
        vaesenc	ymm0, ymm0, ymm7
        vaesenc	ymm1, ymm1, ymm7
        vaesenc	ymm2, ymm2, ymm7
        vaesenc	ymm3, ymm3, ymm7
        vbroadcasti128	ymm7, [r9+80]
        vaesenc	ymm0, ymm0, ymm7
        vaesenc	ymm1, ymm1, ymm7
        vaesenc	ymm2, ymm2, ymm7
        vaesenc	ymm3, ymm3, ymm7
        vbroadcasti128	ymm7, [r9+96]
        vaesenc	ymm0, ymm0, ymm7
        vaesenc	ymm1, ymm1, ymm7
        vaesenc	ymm2, ymm2, ymm7
        vaesenc	ymm3, ymm3, ymm7
        vbroadcasti128	ymm7, [r9+112]
        vaesenc	ymm0, ymm0, ymm7
        vaesenc	ymm1, ymm1, ymm7
        vaesenc	ymm2, ymm2, ymm7
        vaesenc	ymm3, ymm3, ymm7
        vbroadcasti128	ymm7, [r9+128]
        vaesenc	ymm0, ymm0, ymm7
        vaesenc	ymm1, ymm1, ymm7
        vaesenc	ymm2, ymm2, ymm7
        vaesenc	ymm3, ymm3, ymm7
        vbroadcasti128	ymm7, [r9+144]
        vaesenc	ymm0, ymm0, ymm7
        vaesenc	ymm1, ymm1, ymm7
        vaesenc	ymm2, ymm2, ymm7
        vaesenc	ymm3, ymm3, ymm7
        cmp	eax, 11
        vbroadcasti128	ymm7, [r9+160]
        jl	L_AES_ECB_encrypt_vaes_128_aes_enc_block_last
        vaesenc	ymm0, ymm0, ymm7
        vaesenc	ymm1, ymm1, ymm7
        vaesenc	ymm2, ymm2, ymm7
        vaesenc	ymm3, ymm3, ymm7
        vbroadcasti128	ymm7, [r9+176]
        vaesenc	ymm0, ymm0, ymm7
        vaesenc	ymm1, ymm1, ymm7
        vaesenc	ymm2, ymm2, ymm7
        vaesenc	ymm3, ymm3, ymm7
        cmp	eax, 13
        vbroadcasti128	ymm7, [r9+192]
        jl	L_AES_ECB_encrypt_vaes_128_aes_enc_block_last
        vaesenc	ymm0, ymm0, ymm7
        vaesenc	ymm1, ymm1, ymm7
        vaesenc	ymm2, ymm2, ymm7
        vaesenc	ymm3, ymm3, ymm7
        vbroadcasti128	ymm7, [r9+208]
        vaesenc	ymm0, ymm0, ymm7
        vaesenc	ymm1, ymm1, ymm7
        vaesenc	ymm2, ymm2, ymm7
        vaesenc	ymm3, ymm3, ymm7
        vbroadcasti128	ymm7, [r9+224]
L_AES_ECB_encrypt_vaes_128_aes_enc_block_last:
        vaesenclast	ymm0, ymm0, ymm7
        vaesenclast	ymm1, ymm1, ymm7
        vaesenclast	ymm2, ymm2, ymm7
        vaesenclast	ymm3, ymm3, ymm7
        vmovdqu	YMMWORD PTR [r11], ymm0
        vmovdqu	YMMWORD PTR [r11+32], ymm1
        vmovdqu	YMMWORD PTR [r11+64], ymm2
        vmovdqu	YMMWORD PTR [r11+96], ymm3
        add	eax, 128
        cmp	eax, r9d
        jl	L_AES_ECB_encrypt_vaes_enc_128
L_AES_ECB_encrypt_vaes_done_128:
        mov	r9d, r8d
        sub	r9d, eax
        cmp	r9d, 64
        jl	L_AES_ECB_encrypt_vaes_done_64
        ; 64 bytes of input
        ; aes_ecb_enc_64
        lea	r10, QWORD PTR [rcx+rax]
        lea	r11, QWORD PTR [rdx+rax]
        vmovdqu	ymm0, YMMWORD PTR [r10]
        vmovdqu	ymm1, YMMWORD PTR [r10+32]
        ; aes_enc_block
        vbroadcasti128	ymm7, [r9]
        vpxor	ymm0, ymm0, ymm7
        vpxor	ymm1, ymm1, ymm7
        vbroadcasti128	ymm7, [r9+16]
        vaesenc	ymm0, ymm0, ymm7
        vaesenc	ymm1, ymm1, ymm7
        vbroadcasti128	ymm7, [r9+32]
        vaesenc	ymm0, ymm0, ymm7
        vaesenc	ymm1, ymm1, ymm7
        vbroadcasti128	ymm7, [r9+48]
        vaesenc	ymm0, ymm0, ymm7
        vaesenc	ymm1, ymm1, ymm7
        vbroadcasti128	ymm7, [r9+64]
        vaesenc	ymm0, ymm0, ymm7
        vaesenc	ymm1, ymm1, ymm7
        vbroadcasti128	ymm7, [r9+80]
        vaesenc	ymm0, ymm0, ymm7
        vaesenc	ymm1, ymm1, ymm7
        vbroadcasti128	ymm7, [r9+96]
        vaesenc	ymm0, ymm0, ymm7
        vaesenc	ymm1, ymm1, ymm7
        vbroadcasti128	ymm7, [r9+112]
        vaesenc	ymm0, ymm0, ymm7
        vaesenc	ymm1, ymm1, ymm7
        vbroadcasti128	ymm7, [r9+128]
        vaesenc	ymm0, ymm0, ymm7
        vaesenc	ymm1, ymm1, ymm7
        vbroadcasti128	ymm7, [r9+144]
        vaesenc	ymm0, ymm0, ymm7
        vaesenc	ymm1, ymm1, ymm7
        cmp	eax, 11
        vbroadcasti128	ymm7, [r9+160]
        jl	L_AES_ECB_encrypt_vaes_64_aes_enc_block_last
        vaesenc	ymm0, ymm0, ymm7
        vaesenc	ymm1, ymm1, ymm7
        vbroadcasti128	ymm7, [r9+176]
        vaesenc	ymm0, ymm0, ymm7
        vaesenc	ymm1, ymm1, ymm7
        cmp	eax, 13
        vbroadcasti128	ymm7, [r9+192]
        jl	L_AES_ECB_encrypt_vaes_64_aes_enc_block_last
        vaesenc	ymm0, ymm0, ymm7
        vaesenc	ymm1, ymm1, ymm7
        vbroadcasti128	ymm7, [r9+208]
        vaesenc	ymm0, ymm0, ymm7
        vaesenc	ymm1, ymm1, ymm7
        vbroadcasti128	ymm7, [r9+224]
L_AES_ECB_encrypt_vaes_64_aes_enc_block_last:
        vaesenclast	ymm0, ymm0, ymm7
        vaesenclast	ymm1, ymm1, ymm7
        vmovdqu	YMMWORD PTR [r11], ymm0
        vmovdqu	YMMWORD PTR [r11+32], ymm1
        add	eax, 64
L_AES_ECB_encrypt_vaes_done_64:
        mov	r9d, r8d
        and	r9d, 4294967264
        cmp	eax, r9d
        je	L_AES_ECB_encrypt_vaes_done_32
L_AES_ECB_encrypt_vaes_enc_32:
        ; 32 bytes of input
        ; aes_ecb_enc_32
        lea	r10, QWORD PTR [rcx+rax]
        lea	r11, QWORD PTR [rdx+rax]
        vmovdqu	ymm0, YMMWORD PTR [r10]
        ; aes_enc_block
        vbroadcasti128	ymm7, [r9]
        vpxor	ymm0, ymm0, ymm7
        vbroadcasti128	ymm7, [r9+16]
        vaesenc	ymm0, ymm0, ymm7
        vbroadcasti128	ymm7, [r9+32]
        vaesenc	ymm0, ymm0, ymm7
        vbroadcasti128	ymm7, [r9+48]
        vaesenc	ymm0, ymm0, ymm7
        vbroadcasti128	ymm7, [r9+64]
        vaesenc	ymm0, ymm0, ymm7
        vbroadcasti128	ymm7, [r9+80]
        vaesenc	ymm0, ymm0, ymm7
        vbroadcasti128	ymm7, [r9+96]
        vaesenc	ymm0, ymm0, ymm7
        vbroadcasti128	ymm7, [r9+112]
        vaesenc	ymm0, ymm0, ymm7
        vbroadcasti128	ymm7, [r9+128]
        vaesenc	ymm0, ymm0, ymm7
        vbroadcasti128	ymm7, [r9+144]
        vaesenc	ymm0, ymm0, ymm7
        cmp	eax, 11
        vbroadcasti128	ymm7, [r9+160]
        jl	L_AES_ECB_encrypt_vaes_32_aes_enc_block_last
        vaesenc	ymm0, ymm0, ymm7
        vbroadcasti128	ymm7, [r9+176]
        vaesenc	ymm0, ymm0, ymm7
        cmp	eax, 13
        vbroadcasti128	ymm7, [r9+192]
        jl	L_AES_ECB_encrypt_vaes_32_aes_enc_block_last
        vaesenc	ymm0, ymm0, ymm7
        vbroadcasti128	ymm7, [r9+208]
        vaesenc	ymm0, ymm0, ymm7
        vbroadcasti128	ymm7, [r9+224]
L_AES_ECB_encrypt_vaes_32_aes_enc_block_last:
        vaesenclast	ymm0, ymm0, ymm7
        vmovdqu	YMMWORD PTR [r11], ymm0
        add	eax, 32
        cmp	eax, r9d
        jl	L_AES_ECB_encrypt_vaes_enc_32
L_AES_ECB_encrypt_vaes_done_32:
        cmp	eax, r8d
        mov	r9d, r8d
        je	L_AES_ECB_encrypt_vaes_done_enc
        and	r9d, 4294967280
L_AES_ECB_encrypt_vaes_enc_16:
        ; 16 bytes of input
        lea	r10, QWORD PTR [rcx+rax]
        vmovdqu	xmm0, OWORD PTR [r10]
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
        cmp	eax, 11
        vmovdqu	xmm5, OWORD PTR [r9+160]
        jl	L_AES_ECB_encrypt_vaes_16_aes_enc_block_last
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r9+176]
        vaesenc	xmm0, xmm0, xmm6
        cmp	eax, 13
        vmovdqu	xmm5, OWORD PTR [r9+192]
        jl	L_AES_ECB_encrypt_vaes_16_aes_enc_block_last
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r9+208]
        vaesenc	xmm0, xmm0, xmm6
        vmovdqu	xmm5, OWORD PTR [r9+224]
L_AES_ECB_encrypt_vaes_16_aes_enc_block_last:
        vaesenclast	xmm0, xmm0, xmm5
        lea	r10, QWORD PTR [rdx+rax]
        vmovdqu	OWORD PTR [r10], xmm0
        add	eax, 16
        cmp	eax, r9d
        jl	L_AES_ECB_encrypt_vaes_enc_16
L_AES_ECB_encrypt_vaes_done_enc:
        vmovdqu	xmm6, OWORD PTR [rsp]
        vmovdqu	xmm7, OWORD PTR [rsp+16]
        add	rsp, 32
        ret
AES_ECB_encrypt_vaes ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_ECB_decrypt_vaes PROC
        mov	eax, DWORD PTR [rsp+40]
        sub	rsp, 32
        vmovdqu	OWORD PTR [rsp], xmm6
        vmovdqu	OWORD PTR [rsp+16], xmm7
        xor	eax, eax
        cmp	r8d, 128
        mov	r9d, r8d
        jl	L_AES_ECB_decrypt_vaes_done_128
        and	r9d, 4294967168
L_AES_ECB_decrypt_vaes_dec_128:
        ; 128 bytes of input
        ; aes_ecb_dec_128
        lea	r10, QWORD PTR [rcx+rax]
        lea	r11, QWORD PTR [rdx+rax]
        vmovdqu	ymm0, YMMWORD PTR [r10]
        vmovdqu	ymm1, YMMWORD PTR [r10+32]
        vmovdqu	ymm2, YMMWORD PTR [r10+64]
        vmovdqu	ymm3, YMMWORD PTR [r10+96]
        ; aes_dec_block
        vbroadcasti128	ymm7, [r9]
        vpxor	ymm0, ymm0, ymm7
        vpxor	ymm1, ymm1, ymm7
        vpxor	ymm2, ymm2, ymm7
        vpxor	ymm3, ymm3, ymm7
        vbroadcasti128	ymm7, [r9+16]
        vaesdec	ymm0, ymm0, ymm7
        vaesdec	ymm1, ymm1, ymm7
        vaesdec	ymm2, ymm2, ymm7
        vaesdec	ymm3, ymm3, ymm7
        vbroadcasti128	ymm7, [r9+32]
        vaesdec	ymm0, ymm0, ymm7
        vaesdec	ymm1, ymm1, ymm7
        vaesdec	ymm2, ymm2, ymm7
        vaesdec	ymm3, ymm3, ymm7
        vbroadcasti128	ymm7, [r9+48]
        vaesdec	ymm0, ymm0, ymm7
        vaesdec	ymm1, ymm1, ymm7
        vaesdec	ymm2, ymm2, ymm7
        vaesdec	ymm3, ymm3, ymm7
        vbroadcasti128	ymm7, [r9+64]
        vaesdec	ymm0, ymm0, ymm7
        vaesdec	ymm1, ymm1, ymm7
        vaesdec	ymm2, ymm2, ymm7
        vaesdec	ymm3, ymm3, ymm7
        vbroadcasti128	ymm7, [r9+80]
        vaesdec	ymm0, ymm0, ymm7
        vaesdec	ymm1, ymm1, ymm7
        vaesdec	ymm2, ymm2, ymm7
        vaesdec	ymm3, ymm3, ymm7
        vbroadcasti128	ymm7, [r9+96]
        vaesdec	ymm0, ymm0, ymm7
        vaesdec	ymm1, ymm1, ymm7
        vaesdec	ymm2, ymm2, ymm7
        vaesdec	ymm3, ymm3, ymm7
        vbroadcasti128	ymm7, [r9+112]
        vaesdec	ymm0, ymm0, ymm7
        vaesdec	ymm1, ymm1, ymm7
        vaesdec	ymm2, ymm2, ymm7
        vaesdec	ymm3, ymm3, ymm7
        vbroadcasti128	ymm7, [r9+128]
        vaesdec	ymm0, ymm0, ymm7
        vaesdec	ymm1, ymm1, ymm7
        vaesdec	ymm2, ymm2, ymm7
        vaesdec	ymm3, ymm3, ymm7
        vbroadcasti128	ymm7, [r9+144]
        vaesdec	ymm0, ymm0, ymm7
        vaesdec	ymm1, ymm1, ymm7
        vaesdec	ymm2, ymm2, ymm7
        vaesdec	ymm3, ymm3, ymm7
        cmp	eax, 11
        vbroadcasti128	ymm7, [r9+160]
        jl	L_AES_ECB_decrypt_vaes_128_aes_dec_block_last
        vaesdec	ymm0, ymm0, ymm7
        vaesdec	ymm1, ymm1, ymm7
        vaesdec	ymm2, ymm2, ymm7
        vaesdec	ymm3, ymm3, ymm7
        vbroadcasti128	ymm7, [r9+176]
        vaesdec	ymm0, ymm0, ymm7
        vaesdec	ymm1, ymm1, ymm7
        vaesdec	ymm2, ymm2, ymm7
        vaesdec	ymm3, ymm3, ymm7
        cmp	eax, 13
        vbroadcasti128	ymm7, [r9+192]
        jl	L_AES_ECB_decrypt_vaes_128_aes_dec_block_last
        vaesdec	ymm0, ymm0, ymm7
        vaesdec	ymm1, ymm1, ymm7
        vaesdec	ymm2, ymm2, ymm7
        vaesdec	ymm3, ymm3, ymm7
        vbroadcasti128	ymm7, [r9+208]
        vaesdec	ymm0, ymm0, ymm7
        vaesdec	ymm1, ymm1, ymm7
        vaesdec	ymm2, ymm2, ymm7
        vaesdec	ymm3, ymm3, ymm7
        vbroadcasti128	ymm7, [r9+224]
L_AES_ECB_decrypt_vaes_128_aes_dec_block_last:
        vaesdeclast	ymm0, ymm0, ymm7
        vaesdeclast	ymm1, ymm1, ymm7
        vaesdeclast	ymm2, ymm2, ymm7
        vaesdeclast	ymm3, ymm3, ymm7
        vmovdqu	YMMWORD PTR [r11], ymm0
        vmovdqu	YMMWORD PTR [r11+32], ymm1
        vmovdqu	YMMWORD PTR [r11+64], ymm2
        vmovdqu	YMMWORD PTR [r11+96], ymm3
        add	eax, 128
        cmp	eax, r9d
        jl	L_AES_ECB_decrypt_vaes_dec_128
L_AES_ECB_decrypt_vaes_done_128:
        mov	r9d, r8d
        sub	r9d, eax
        cmp	r9d, 64
        jl	L_AES_ECB_decrypt_vaes_done_64
        ; 64 bytes of input
        ; aes_ecb_dec_64
        lea	r10, QWORD PTR [rcx+rax]
        lea	r11, QWORD PTR [rdx+rax]
        vmovdqu	ymm0, YMMWORD PTR [r10]
        vmovdqu	ymm1, YMMWORD PTR [r10+32]
        ; aes_dec_block
        vbroadcasti128	ymm7, [r9]
        vpxor	ymm0, ymm0, ymm7
        vpxor	ymm1, ymm1, ymm7
        vbroadcasti128	ymm7, [r9+16]
        vaesdec	ymm0, ymm0, ymm7
        vaesdec	ymm1, ymm1, ymm7
        vbroadcasti128	ymm7, [r9+32]
        vaesdec	ymm0, ymm0, ymm7
        vaesdec	ymm1, ymm1, ymm7
        vbroadcasti128	ymm7, [r9+48]
        vaesdec	ymm0, ymm0, ymm7
        vaesdec	ymm1, ymm1, ymm7
        vbroadcasti128	ymm7, [r9+64]
        vaesdec	ymm0, ymm0, ymm7
        vaesdec	ymm1, ymm1, ymm7
        vbroadcasti128	ymm7, [r9+80]
        vaesdec	ymm0, ymm0, ymm7
        vaesdec	ymm1, ymm1, ymm7
        vbroadcasti128	ymm7, [r9+96]
        vaesdec	ymm0, ymm0, ymm7
        vaesdec	ymm1, ymm1, ymm7
        vbroadcasti128	ymm7, [r9+112]
        vaesdec	ymm0, ymm0, ymm7
        vaesdec	ymm1, ymm1, ymm7
        vbroadcasti128	ymm7, [r9+128]
        vaesdec	ymm0, ymm0, ymm7
        vaesdec	ymm1, ymm1, ymm7
        vbroadcasti128	ymm7, [r9+144]
        vaesdec	ymm0, ymm0, ymm7
        vaesdec	ymm1, ymm1, ymm7
        cmp	eax, 11
        vbroadcasti128	ymm7, [r9+160]
        jl	L_AES_ECB_decrypt_vaes_64_aes_dec_block_last
        vaesdec	ymm0, ymm0, ymm7
        vaesdec	ymm1, ymm1, ymm7
        vbroadcasti128	ymm7, [r9+176]
        vaesdec	ymm0, ymm0, ymm7
        vaesdec	ymm1, ymm1, ymm7
        cmp	eax, 13
        vbroadcasti128	ymm7, [r9+192]
        jl	L_AES_ECB_decrypt_vaes_64_aes_dec_block_last
        vaesdec	ymm0, ymm0, ymm7
        vaesdec	ymm1, ymm1, ymm7
        vbroadcasti128	ymm7, [r9+208]
        vaesdec	ymm0, ymm0, ymm7
        vaesdec	ymm1, ymm1, ymm7
        vbroadcasti128	ymm7, [r9+224]
L_AES_ECB_decrypt_vaes_64_aes_dec_block_last:
        vaesdeclast	ymm0, ymm0, ymm7
        vaesdeclast	ymm1, ymm1, ymm7
        vmovdqu	YMMWORD PTR [r11], ymm0
        vmovdqu	YMMWORD PTR [r11+32], ymm1
        add	eax, 64
L_AES_ECB_decrypt_vaes_done_64:
        mov	r9d, r8d
        and	r9d, 4294967264
        cmp	eax, r9d
        je	L_AES_ECB_decrypt_vaes_done_32
L_AES_ECB_decrypt_vaes_dec_32:
        ; 32 bytes of input
        ; aes_ecb_dec_32
        lea	r10, QWORD PTR [rcx+rax]
        lea	r11, QWORD PTR [rdx+rax]
        vmovdqu	ymm0, YMMWORD PTR [r10]
        ; aes_dec_block
        vbroadcasti128	ymm7, [r9]
        vpxor	ymm0, ymm0, ymm7
        vbroadcasti128	ymm7, [r9+16]
        vaesdec	ymm0, ymm0, ymm7
        vbroadcasti128	ymm7, [r9+32]
        vaesdec	ymm0, ymm0, ymm7
        vbroadcasti128	ymm7, [r9+48]
        vaesdec	ymm0, ymm0, ymm7
        vbroadcasti128	ymm7, [r9+64]
        vaesdec	ymm0, ymm0, ymm7
        vbroadcasti128	ymm7, [r9+80]
        vaesdec	ymm0, ymm0, ymm7
        vbroadcasti128	ymm7, [r9+96]
        vaesdec	ymm0, ymm0, ymm7
        vbroadcasti128	ymm7, [r9+112]
        vaesdec	ymm0, ymm0, ymm7
        vbroadcasti128	ymm7, [r9+128]
        vaesdec	ymm0, ymm0, ymm7
        vbroadcasti128	ymm7, [r9+144]
        vaesdec	ymm0, ymm0, ymm7
        cmp	eax, 11
        vbroadcasti128	ymm7, [r9+160]
        jl	L_AES_ECB_decrypt_vaes_32_aes_dec_block_last
        vaesdec	ymm0, ymm0, ymm7
        vbroadcasti128	ymm7, [r9+176]
        vaesdec	ymm0, ymm0, ymm7
        cmp	eax, 13
        vbroadcasti128	ymm7, [r9+192]
        jl	L_AES_ECB_decrypt_vaes_32_aes_dec_block_last
        vaesdec	ymm0, ymm0, ymm7
        vbroadcasti128	ymm7, [r9+208]
        vaesdec	ymm0, ymm0, ymm7
        vbroadcasti128	ymm7, [r9+224]
L_AES_ECB_decrypt_vaes_32_aes_dec_block_last:
        vaesdeclast	ymm0, ymm0, ymm7
        vmovdqu	YMMWORD PTR [r11], ymm0
        add	eax, 32
        cmp	eax, r9d
        jl	L_AES_ECB_decrypt_vaes_dec_32
L_AES_ECB_decrypt_vaes_done_32:
        cmp	eax, r8d
        mov	r9d, r8d
        je	L_AES_ECB_decrypt_vaes_done_dec
        and	r9d, 4294967280
L_AES_ECB_decrypt_vaes_dec_16:
        ; 16 bytes of input
        lea	r10, QWORD PTR [rcx+rax]
        vmovdqu	xmm0, OWORD PTR [r10]
        ; aes_dec_block
        vpxor	xmm0, xmm0, [r9]
        vmovdqu	xmm5, OWORD PTR [r9+16]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+32]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+48]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+64]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+80]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+96]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+112]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+128]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+144]
        vaesdec	xmm0, xmm0, xmm5
        cmp	eax, 11
        vmovdqu	xmm5, OWORD PTR [r9+160]
        jl	L_AES_ECB_decrypt_vaes_16_aes_dec_block_last
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r9+176]
        vaesdec	xmm0, xmm0, xmm6
        cmp	eax, 13
        vmovdqu	xmm5, OWORD PTR [r9+192]
        jl	L_AES_ECB_decrypt_vaes_16_aes_dec_block_last
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r9+208]
        vaesdec	xmm0, xmm0, xmm6
        vmovdqu	xmm5, OWORD PTR [r9+224]
L_AES_ECB_decrypt_vaes_16_aes_dec_block_last:
        vaesdeclast	xmm0, xmm0, xmm5
        lea	r10, QWORD PTR [rdx+rax]
        vmovdqu	OWORD PTR [r10], xmm0
        add	eax, 16
        cmp	eax, r9d
        jl	L_AES_ECB_decrypt_vaes_dec_16
L_AES_ECB_decrypt_vaes_done_dec:
        vmovdqu	xmm6, OWORD PTR [rsp]
        vmovdqu	xmm7, OWORD PTR [rsp+16]
        add	rsp, 32
        ret
AES_ECB_decrypt_vaes ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_CBC_encrypt_vaes PROC
        mov	rax, QWORD PTR [rsp+40]
        mov	r10d, DWORD PTR [rsp+48]
        vmovdqu	xmm0, OWORD PTR [r8]
        xor	eax, eax
        cmp	eax, r9d
        je	L_AES_CBC_encrypt_vaes_done
L_AES_CBC_encrypt_vaes_loop:
        ; 16 bytes of input
        lea	r10, QWORD PTR [rcx+rax]
        vmovdqu	xmm1, OWORD PTR [r10]
        vpxor	xmm1, xmm1, xmm0
        ; aes_enc_block
        vpxor	xmm1, xmm1, [rax]
        vmovdqu	xmm3, OWORD PTR [rax+16]
        vaesenc	xmm1, xmm1, xmm3
        vmovdqu	xmm3, OWORD PTR [rax+32]
        vaesenc	xmm1, xmm1, xmm3
        vmovdqu	xmm3, OWORD PTR [rax+48]
        vaesenc	xmm1, xmm1, xmm3
        vmovdqu	xmm3, OWORD PTR [rax+64]
        vaesenc	xmm1, xmm1, xmm3
        vmovdqu	xmm3, OWORD PTR [rax+80]
        vaesenc	xmm1, xmm1, xmm3
        vmovdqu	xmm3, OWORD PTR [rax+96]
        vaesenc	xmm1, xmm1, xmm3
        vmovdqu	xmm3, OWORD PTR [rax+112]
        vaesenc	xmm1, xmm1, xmm3
        vmovdqu	xmm3, OWORD PTR [rax+128]
        vaesenc	xmm1, xmm1, xmm3
        vmovdqu	xmm3, OWORD PTR [rax+144]
        vaesenc	xmm1, xmm1, xmm3
        cmp	r10d, 11
        vmovdqu	xmm3, OWORD PTR [rax+160]
        jl	L_AES_CBC_encrypt_vaes_aes_enc_block_last
        vaesenc	xmm1, xmm1, xmm3
        vmovdqu	xmm4, OWORD PTR [rax+176]
        vaesenc	xmm1, xmm1, xmm4
        cmp	r10d, 13
        vmovdqu	xmm3, OWORD PTR [rax+192]
        jl	L_AES_CBC_encrypt_vaes_aes_enc_block_last
        vaesenc	xmm1, xmm1, xmm3
        vmovdqu	xmm4, OWORD PTR [rax+208]
        vaesenc	xmm1, xmm1, xmm4
        vmovdqu	xmm3, OWORD PTR [rax+224]
L_AES_CBC_encrypt_vaes_aes_enc_block_last:
        vaesenclast	xmm1, xmm1, xmm3
        lea	r11, QWORD PTR [rdx+rax]
        vmovdqu	OWORD PTR [r11], xmm1
        vmovdqa	xmm0, xmm1
        add	eax, 16
        cmp	eax, r9d
        jl	L_AES_CBC_encrypt_vaes_loop
L_AES_CBC_encrypt_vaes_done:
        vmovdqu	OWORD PTR [r8], xmm0
        ret
AES_CBC_encrypt_vaes ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_CBC_decrypt_vaes PROC
        push	r12
        mov	rax, QWORD PTR [rsp+48]
        mov	r10d, DWORD PTR [rsp+56]
        sub	rsp, 128
        vmovdqu	OWORD PTR [rsp], xmm6
        vmovdqu	OWORD PTR [rsp+16], xmm7
        vmovdqu	OWORD PTR [rsp+32], xmm8
        vmovdqu	OWORD PTR [rsp+48], xmm9
        vmovdqu	OWORD PTR [rsp+64], xmm10
        vmovdqu	OWORD PTR [rsp+80], xmm11
        vmovdqu	OWORD PTR [rsp+96], xmm12
        vmovdqu	OWORD PTR [rsp+112], xmm13
        vmovdqu	xmm8, OWORD PTR [r8]
        xor	eax, eax
        cmp	r9d, 128
        mov	r10d, r9d
        jl	L_AES_CBC_decrypt_vaes_done_128
        and	r10d, 4294967168
L_AES_CBC_decrypt_vaes_dec_128:
        ; 128 bytes of input
        ; aes_cbc_dec_128
        lea	r11, QWORD PTR [rcx+rax]
        lea	r12, QWORD PTR [rdx+rax]
        vmovdqu	ymm0, YMMWORD PTR [r11]
        vmovdqu	ymm1, YMMWORD PTR [r11+32]
        vmovdqu	ymm2, YMMWORD PTR [r11+64]
        vmovdqu	ymm3, YMMWORD PTR [r11+96]
        vinserti128	ymm10, ymm8, xmm0, 1
        vmovdqu	ymm11, YMMWORD PTR [r11+16]
        vmovdqu	ymm12, YMMWORD PTR [r11+48]
        vmovdqu	ymm13, YMMWORD PTR [r11+80]
        vextracti128	xmm8, ymm3, 1
        ; aes_dec_block
        vbroadcasti128	ymm9, [rax]
        vpxor	ymm0, ymm0, ymm9
        vpxor	ymm1, ymm1, ymm9
        vpxor	ymm2, ymm2, ymm9
        vpxor	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [rax+16]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vaesdec	ymm2, ymm2, ymm9
        vaesdec	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [rax+32]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vaesdec	ymm2, ymm2, ymm9
        vaesdec	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [rax+48]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vaesdec	ymm2, ymm2, ymm9
        vaesdec	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [rax+64]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vaesdec	ymm2, ymm2, ymm9
        vaesdec	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [rax+80]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vaesdec	ymm2, ymm2, ymm9
        vaesdec	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [rax+96]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vaesdec	ymm2, ymm2, ymm9
        vaesdec	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [rax+112]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vaesdec	ymm2, ymm2, ymm9
        vaesdec	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [rax+128]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vaesdec	ymm2, ymm2, ymm9
        vaesdec	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [rax+144]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vaesdec	ymm2, ymm2, ymm9
        vaesdec	ymm3, ymm3, ymm9
        cmp	r10d, 11
        vbroadcasti128	ymm9, [rax+160]
        jl	L_AES_CBC_decrypt_vaes_128_aes_dec_block_last
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vaesdec	ymm2, ymm2, ymm9
        vaesdec	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [rax+176]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vaesdec	ymm2, ymm2, ymm9
        vaesdec	ymm3, ymm3, ymm9
        cmp	r10d, 13
        vbroadcasti128	ymm9, [rax+192]
        jl	L_AES_CBC_decrypt_vaes_128_aes_dec_block_last
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vaesdec	ymm2, ymm2, ymm9
        vaesdec	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [rax+208]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vaesdec	ymm2, ymm2, ymm9
        vaesdec	ymm3, ymm3, ymm9
        vbroadcasti128	ymm9, [rax+224]
L_AES_CBC_decrypt_vaes_128_aes_dec_block_last:
        vaesdeclast	ymm0, ymm0, ymm9
        vaesdeclast	ymm1, ymm1, ymm9
        vaesdeclast	ymm2, ymm2, ymm9
        vaesdeclast	ymm3, ymm3, ymm9
        vpxor	ymm0, ymm0, ymm10
        vpxor	ymm1, ymm1, ymm11
        vpxor	ymm2, ymm2, ymm12
        vpxor	ymm3, ymm3, ymm13
        vmovdqu	YMMWORD PTR [r12], ymm0
        vmovdqu	YMMWORD PTR [r12+32], ymm1
        vmovdqu	YMMWORD PTR [r12+64], ymm2
        vmovdqu	YMMWORD PTR [r12+96], ymm3
        add	eax, 128
        cmp	eax, r10d
        jl	L_AES_CBC_decrypt_vaes_dec_128
L_AES_CBC_decrypt_vaes_done_128:
        mov	r10d, r9d
        sub	r10d, eax
        cmp	r10d, 64
        jl	L_AES_CBC_decrypt_vaes_done_64
        ; 64 bytes of input
        ; aes_cbc_dec_64
        lea	r11, QWORD PTR [rcx+rax]
        lea	r12, QWORD PTR [rdx+rax]
        vmovdqu	ymm0, YMMWORD PTR [r11]
        vmovdqu	ymm1, YMMWORD PTR [r11+32]
        vinserti128	ymm10, ymm8, xmm0, 1
        vmovdqu	ymm11, YMMWORD PTR [r11+16]
        vextracti128	xmm8, ymm1, 1
        ; aes_dec_block
        vbroadcasti128	ymm9, [rax]
        vpxor	ymm0, ymm0, ymm9
        vpxor	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [rax+16]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [rax+32]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [rax+48]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [rax+64]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [rax+80]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [rax+96]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [rax+112]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [rax+128]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [rax+144]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        cmp	r10d, 11
        vbroadcasti128	ymm9, [rax+160]
        jl	L_AES_CBC_decrypt_vaes_64_aes_dec_block_last
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [rax+176]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        cmp	r10d, 13
        vbroadcasti128	ymm9, [rax+192]
        jl	L_AES_CBC_decrypt_vaes_64_aes_dec_block_last
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [rax+208]
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm1, ymm1, ymm9
        vbroadcasti128	ymm9, [rax+224]
L_AES_CBC_decrypt_vaes_64_aes_dec_block_last:
        vaesdeclast	ymm0, ymm0, ymm9
        vaesdeclast	ymm1, ymm1, ymm9
        vpxor	ymm0, ymm0, ymm10
        vpxor	ymm1, ymm1, ymm11
        vmovdqu	YMMWORD PTR [r12], ymm0
        vmovdqu	YMMWORD PTR [r12+32], ymm1
        add	eax, 64
L_AES_CBC_decrypt_vaes_done_64:
        mov	r10d, r9d
        and	r10d, 4294967264
        cmp	eax, r10d
        je	L_AES_CBC_decrypt_vaes_done_32
L_AES_CBC_decrypt_vaes_dec_32:
        ; 32 bytes of input
        ; aes_cbc_dec_32
        lea	r11, QWORD PTR [rcx+rax]
        lea	r12, QWORD PTR [rdx+rax]
        vmovdqu	ymm0, YMMWORD PTR [r11]
        vinserti128	ymm10, ymm8, xmm0, 1
        vextracti128	xmm8, ymm0, 1
        ; aes_dec_block
        vbroadcasti128	ymm9, [rax]
        vpxor	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [rax+16]
        vaesdec	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [rax+32]
        vaesdec	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [rax+48]
        vaesdec	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [rax+64]
        vaesdec	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [rax+80]
        vaesdec	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [rax+96]
        vaesdec	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [rax+112]
        vaesdec	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [rax+128]
        vaesdec	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [rax+144]
        vaesdec	ymm0, ymm0, ymm9
        cmp	r10d, 11
        vbroadcasti128	ymm9, [rax+160]
        jl	L_AES_CBC_decrypt_vaes_32_aes_dec_block_last
        vaesdec	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [rax+176]
        vaesdec	ymm0, ymm0, ymm9
        cmp	r10d, 13
        vbroadcasti128	ymm9, [rax+192]
        jl	L_AES_CBC_decrypt_vaes_32_aes_dec_block_last
        vaesdec	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [rax+208]
        vaesdec	ymm0, ymm0, ymm9
        vbroadcasti128	ymm9, [rax+224]
L_AES_CBC_decrypt_vaes_32_aes_dec_block_last:
        vaesdeclast	ymm0, ymm0, ymm9
        vpxor	ymm0, ymm0, ymm10
        vmovdqu	YMMWORD PTR [r12], ymm0
        add	eax, 32
        cmp	eax, r10d
        jl	L_AES_CBC_decrypt_vaes_dec_32
L_AES_CBC_decrypt_vaes_done_32:
        cmp	eax, r9d
        mov	r10d, r9d
        je	L_AES_CBC_decrypt_vaes_done_dec
        and	r10d, 4294967280
L_AES_CBC_decrypt_vaes_dec_16:
        ; 16 bytes of input
        lea	r11, QWORD PTR [rcx+rax]
        vmovdqu	xmm0, OWORD PTR [r11]
        vmovdqa	xmm7, xmm0
        ; aes_dec_block
        vpxor	xmm0, xmm0, [rax]
        vmovdqu	xmm5, OWORD PTR [rax+16]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [rax+32]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [rax+48]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [rax+64]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [rax+80]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [rax+96]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [rax+112]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [rax+128]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [rax+144]
        vaesdec	xmm0, xmm0, xmm5
        cmp	r10d, 11
        vmovdqu	xmm5, OWORD PTR [rax+160]
        jl	L_AES_CBC_decrypt_vaes_16_aes_dec_block_last
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [rax+176]
        vaesdec	xmm0, xmm0, xmm6
        cmp	r10d, 13
        vmovdqu	xmm5, OWORD PTR [rax+192]
        jl	L_AES_CBC_decrypt_vaes_16_aes_dec_block_last
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [rax+208]
        vaesdec	xmm0, xmm0, xmm6
        vmovdqu	xmm5, OWORD PTR [rax+224]
L_AES_CBC_decrypt_vaes_16_aes_dec_block_last:
        vaesdeclast	xmm0, xmm0, xmm5
        vpxor	xmm0, xmm0, xmm8
        vmovdqa	xmm8, xmm7
        lea	r11, QWORD PTR [rdx+rax]
        vmovdqu	OWORD PTR [r11], xmm0
        add	eax, 16
        cmp	eax, r10d
        jl	L_AES_CBC_decrypt_vaes_dec_16
L_AES_CBC_decrypt_vaes_done_dec:
        vmovdqu	OWORD PTR [r8], xmm8
        vmovdqu	xmm6, OWORD PTR [rsp]
        vmovdqu	xmm7, OWORD PTR [rsp+16]
        vmovdqu	xmm8, OWORD PTR [rsp+32]
        vmovdqu	xmm9, OWORD PTR [rsp+48]
        vmovdqu	xmm10, OWORD PTR [rsp+64]
        vmovdqu	xmm11, OWORD PTR [rsp+80]
        vmovdqu	xmm12, OWORD PTR [rsp+96]
        vmovdqu	xmm13, OWORD PTR [rsp+112]
        add	rsp, 128
        pop	r12
        ret
AES_CBC_decrypt_vaes ENDP
_TEXT ENDS
_DATA SEGMENT
ALIGN 16
L_aes_ctr_bswap_vaes QWORD \
     08090a0b0c0d0e0fh,  0001020304050607h
ptr_L_aes_ctr_bswap_vaes QWORD L_aes_ctr_bswap_vaes
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_aes_ctr_inc_vaes QWORD \
     0000000000000000h,  0000000000000000h,
     0000000000000001h,  0000000000000000h,
     0000000000000002h,  0000000000000000h,
     0000000000000003h,  0000000000000000h,
     0000000000000004h,  0000000000000000h,
     0000000000000005h,  0000000000000000h,
     0000000000000006h,  0000000000000000h,
     0000000000000007h,  0000000000000000h,
     0000000000000008h,  0000000000000000h,
     0000000000000009h,  0000000000000000h,
     000000000000000ah,  0000000000000000h,
     000000000000000bh,  0000000000000000h,
     000000000000000ch,  0000000000000000h,
     000000000000000dh,  0000000000000000h,
     000000000000000eh,  0000000000000000h,
     000000000000000fh,  0000000000000000h,
     0000000000000010h,  0000000000000000h
ptr_L_aes_ctr_inc_vaes QWORD L_aes_ctr_inc_vaes
_DATA ENDS
_TEXT SEGMENT READONLY PARA
AES_CTR_encrypt_vaes PROC
        push	rbx
        mov	eax, DWORD PTR [rsp+48]
        mov	r10, QWORD PTR [rsp+56]
        sub	rsp, 160
        vmovdqu	OWORD PTR [rsp], xmm6
        vmovdqu	OWORD PTR [rsp+16], xmm7
        vmovdqu	OWORD PTR [rsp+32], xmm8
        vmovdqu	OWORD PTR [rsp+48], xmm9
        vmovdqu	OWORD PTR [rsp+64], xmm10
        vmovdqu	OWORD PTR [rsp+80], xmm11
        vmovdqu	OWORD PTR [rsp+96], xmm12
        vmovdqu	OWORD PTR [rsp+112], xmm13
        vmovdqu	OWORD PTR [rsp+128], xmm14
        vmovdqu	OWORD PTR [rsp+144], xmm15
        vbroadcasti128	ymm8, ptr_L_aes_ctr_bswap_vaes
        vbroadcasti128	ymm7, [r10]
        vpshufb	ymm7, ymm7, ymm8
        vbroadcasti128	ymm12, [ptr_L_aes_ctr_inc_vaes+32]
        vbroadcasti128	ymm13, [ptr_L_aes_ctr_inc_vaes+16]
        xor	eax, eax
        cmp	r8d, 128
        mov	r10d, r8d
        jl	L_AES_CTR_encrypt_vaes_done_128
        and	r10d, 4294967168
        vbroadcasti128	ymm10, [ptr_L_aes_ctr_inc_vaes+128]
        vmovdqa	ymm9, ymm7
        vpaddq	ymm4, ymm7, [ptr_L_aes_ctr_inc_vaes]
        vpand	ymm15, ymm9, [ptr_L_aes_ctr_inc_vaes]
        vpor	ymm9, ymm9, [ptr_L_aes_ctr_inc_vaes]
        vpandn	ymm9, ymm4, ymm9
        vpor	ymm9, ymm9, ymm15
        vpsrlq	ymm9, ymm9, 63
        vpslldq	ymm9, ymm9, 8
        vpaddq	ymm4, ymm4, ymm9
        vmovdqa	ymm9, ymm7
        vpaddq	ymm5, ymm7, [ptr_L_aes_ctr_inc_vaes+32]
        vpand	ymm15, ymm9, [ptr_L_aes_ctr_inc_vaes+32]
        vpor	ymm9, ymm9, [ptr_L_aes_ctr_inc_vaes+32]
        vpandn	ymm9, ymm5, ymm9
        vpor	ymm9, ymm9, ymm15
        vpsrlq	ymm9, ymm9, 63
        vpslldq	ymm9, ymm9, 8
        vpaddq	ymm5, ymm5, ymm9
        vmovdqa	ymm9, ymm7
        vpaddq	ymm6, ymm7, [ptr_L_aes_ctr_inc_vaes+64]
        vpand	ymm15, ymm9, [ptr_L_aes_ctr_inc_vaes+64]
        vpor	ymm9, ymm9, [ptr_L_aes_ctr_inc_vaes+64]
        vpandn	ymm9, ymm6, ymm9
        vpor	ymm9, ymm9, ymm15
        vpsrlq	ymm9, ymm9, 63
        vpslldq	ymm9, ymm9, 8
        vpaddq	ymm6, ymm6, ymm9
        vmovdqa	ymm9, ymm7
        vpaddq	ymm7, ymm7, [ptr_L_aes_ctr_inc_vaes+96]
        vpand	ymm15, ymm9, [ptr_L_aes_ctr_inc_vaes+96]
        vpor	ymm9, ymm9, [ptr_L_aes_ctr_inc_vaes+96]
        vpandn	ymm9, ymm7, ymm9
        vpor	ymm9, ymm9, ymm15
        vpsrlq	ymm9, ymm9, 63
        vpslldq	ymm9, ymm9, 8
        vpaddq	ymm7, ymm7, ymm9
L_AES_CTR_encrypt_vaes_enc_128:
        ; 128 bytes of input
        lea	r11, QWORD PTR [rcx+rax]
        lea	rbx, QWORD PTR [rdx+rax]
        vpshufb	ymm0, ymm4, ymm8
        vpshufb	ymm1, ymm5, ymm8
        vpshufb	ymm2, ymm6, ymm8
        vpshufb	ymm3, ymm7, ymm8
        vmovdqa	ymm9, ymm4
        vpaddq	ymm4, ymm4, ymm10
        vpand	ymm15, ymm9, ymm10
        vpor	ymm9, ymm9, ymm10
        vpandn	ymm9, ymm4, ymm9
        vpor	ymm9, ymm9, ymm15
        vpsrlq	ymm9, ymm9, 63
        vpslldq	ymm9, ymm9, 8
        vpaddq	ymm4, ymm4, ymm9
        vmovdqa	ymm9, ymm5
        vpaddq	ymm5, ymm5, ymm10
        vpand	ymm15, ymm9, ymm10
        vpor	ymm9, ymm9, ymm10
        vpandn	ymm9, ymm5, ymm9
        vpor	ymm9, ymm9, ymm15
        vpsrlq	ymm9, ymm9, 63
        vpslldq	ymm9, ymm9, 8
        vpaddq	ymm5, ymm5, ymm9
        vmovdqa	ymm9, ymm6
        vpaddq	ymm6, ymm6, ymm10
        vpand	ymm15, ymm9, ymm10
        vpor	ymm9, ymm9, ymm10
        vpandn	ymm9, ymm6, ymm9
        vpor	ymm9, ymm9, ymm15
        vpsrlq	ymm9, ymm9, 63
        vpslldq	ymm9, ymm9, 8
        vpaddq	ymm6, ymm6, ymm9
        vmovdqa	ymm9, ymm7
        vpaddq	ymm7, ymm7, ymm10
        vpand	ymm15, ymm9, ymm10
        vpor	ymm9, ymm9, ymm10
        vpandn	ymm9, ymm7, ymm9
        vpor	ymm9, ymm9, ymm15
        vpsrlq	ymm9, ymm9, 63
        vpslldq	ymm9, ymm9, 8
        vpaddq	ymm7, ymm7, ymm9
        ; aes_enc_block
        vbroadcasti128	ymm14, [r9]
        vpxor	ymm0, ymm0, ymm14
        vpxor	ymm1, ymm1, ymm14
        vpxor	ymm2, ymm2, ymm14
        vpxor	ymm3, ymm3, ymm14
        vbroadcasti128	ymm14, [r9+16]
        vaesenc	ymm0, ymm0, ymm14
        vaesenc	ymm1, ymm1, ymm14
        vaesenc	ymm2, ymm2, ymm14
        vaesenc	ymm3, ymm3, ymm14
        vbroadcasti128	ymm14, [r9+32]
        vaesenc	ymm0, ymm0, ymm14
        vaesenc	ymm1, ymm1, ymm14
        vaesenc	ymm2, ymm2, ymm14
        vaesenc	ymm3, ymm3, ymm14
        vbroadcasti128	ymm14, [r9+48]
        vaesenc	ymm0, ymm0, ymm14
        vaesenc	ymm1, ymm1, ymm14
        vaesenc	ymm2, ymm2, ymm14
        vaesenc	ymm3, ymm3, ymm14
        vbroadcasti128	ymm14, [r9+64]
        vaesenc	ymm0, ymm0, ymm14
        vaesenc	ymm1, ymm1, ymm14
        vaesenc	ymm2, ymm2, ymm14
        vaesenc	ymm3, ymm3, ymm14
        vbroadcasti128	ymm14, [r9+80]
        vaesenc	ymm0, ymm0, ymm14
        vaesenc	ymm1, ymm1, ymm14
        vaesenc	ymm2, ymm2, ymm14
        vaesenc	ymm3, ymm3, ymm14
        vbroadcasti128	ymm14, [r9+96]
        vaesenc	ymm0, ymm0, ymm14
        vaesenc	ymm1, ymm1, ymm14
        vaesenc	ymm2, ymm2, ymm14
        vaesenc	ymm3, ymm3, ymm14
        vbroadcasti128	ymm14, [r9+112]
        vaesenc	ymm0, ymm0, ymm14
        vaesenc	ymm1, ymm1, ymm14
        vaesenc	ymm2, ymm2, ymm14
        vaesenc	ymm3, ymm3, ymm14
        vbroadcasti128	ymm14, [r9+128]
        vaesenc	ymm0, ymm0, ymm14
        vaesenc	ymm1, ymm1, ymm14
        vaesenc	ymm2, ymm2, ymm14
        vaesenc	ymm3, ymm3, ymm14
        vbroadcasti128	ymm14, [r9+144]
        vaesenc	ymm0, ymm0, ymm14
        vaesenc	ymm1, ymm1, ymm14
        vaesenc	ymm2, ymm2, ymm14
        vaesenc	ymm3, ymm3, ymm14
        cmp	eax, 11
        vbroadcasti128	ymm14, [r9+160]
        jl	L_AES_CTR_encrypt_vaes_128_aes_enc_block_last
        vaesenc	ymm0, ymm0, ymm14
        vaesenc	ymm1, ymm1, ymm14
        vaesenc	ymm2, ymm2, ymm14
        vaesenc	ymm3, ymm3, ymm14
        vbroadcasti128	ymm14, [r9+176]
        vaesenc	ymm0, ymm0, ymm14
        vaesenc	ymm1, ymm1, ymm14
        vaesenc	ymm2, ymm2, ymm14
        vaesenc	ymm3, ymm3, ymm14
        cmp	eax, 13
        vbroadcasti128	ymm14, [r9+192]
        jl	L_AES_CTR_encrypt_vaes_128_aes_enc_block_last
        vaesenc	ymm0, ymm0, ymm14
        vaesenc	ymm1, ymm1, ymm14
        vaesenc	ymm2, ymm2, ymm14
        vaesenc	ymm3, ymm3, ymm14
        vbroadcasti128	ymm14, [r9+208]
        vaesenc	ymm0, ymm0, ymm14
        vaesenc	ymm1, ymm1, ymm14
        vaesenc	ymm2, ymm2, ymm14
        vaesenc	ymm3, ymm3, ymm14
        vbroadcasti128	ymm14, [r9+224]
L_AES_CTR_encrypt_vaes_128_aes_enc_block_last:
        vaesenclast	ymm0, ymm0, ymm14
        vaesenclast	ymm1, ymm1, ymm14
        vaesenclast	ymm2, ymm2, ymm14
        vaesenclast	ymm3, ymm3, ymm14
        vpxor	ymm0, ymm0, [r11]
        vpxor	ymm1, ymm1, [r11+32]
        vpxor	ymm2, ymm2, [r11+64]
        vpxor	ymm3, ymm3, [r11+96]
        vmovdqu	YMMWORD PTR [rbx], ymm0
        vmovdqu	YMMWORD PTR [rbx+32], ymm1
        vmovdqu	YMMWORD PTR [rbx+64], ymm2
        vmovdqu	YMMWORD PTR [rbx+96], ymm3
        add	eax, 128
        cmp	eax, r10d
        jl	L_AES_CTR_encrypt_vaes_enc_128
        vperm2i128	ymm7, ymm4, ymm4, 0
L_AES_CTR_encrypt_vaes_done_128:
        mov	r10d, r8d
        sub	r10d, eax
        cmp	r10d, 64
        jl	L_AES_CTR_encrypt_vaes_done_64
        ; 64 bytes of input
        vbroadcasti128	ymm11, [ptr_L_aes_ctr_inc_vaes+64]
        ; aes_ctr_enc_64
        lea	r11, QWORD PTR [rcx+rax]
        lea	rbx, QWORD PTR [rdx+rax]
        vpaddq	ymm0, ymm7, [ptr_L_aes_ctr_inc_vaes]
        vmovdqa	ymm9, ymm7
        vpand	ymm15, ymm9, [ptr_L_aes_ctr_inc_vaes]
        vpor	ymm9, ymm9, [ptr_L_aes_ctr_inc_vaes]
        vpandn	ymm9, ymm0, ymm9
        vpor	ymm9, ymm9, ymm15
        vpsrlq	ymm9, ymm9, 63
        vpslldq	ymm9, ymm9, 8
        vpaddq	ymm0, ymm0, ymm9
        vpshufb	ymm0, ymm0, ymm8
        vpaddq	ymm1, ymm7, [ptr_L_aes_ctr_inc_vaes+32]
        vmovdqa	ymm9, ymm7
        vpand	ymm15, ymm9, [ptr_L_aes_ctr_inc_vaes+32]
        vpor	ymm9, ymm9, [ptr_L_aes_ctr_inc_vaes+32]
        vpandn	ymm9, ymm1, ymm9
        vpor	ymm9, ymm9, ymm15
        vpsrlq	ymm9, ymm9, 63
        vpslldq	ymm9, ymm9, 8
        vpaddq	ymm1, ymm1, ymm9
        vpshufb	ymm1, ymm1, ymm8
        vmovdqa	ymm9, ymm7
        vpaddq	ymm7, ymm7, ymm11
        vpand	ymm15, ymm9, ymm11
        vpor	ymm9, ymm9, ymm11
        vpandn	ymm9, ymm7, ymm9
        vpor	ymm9, ymm9, ymm15
        vpsrlq	ymm9, ymm9, 63
        vpslldq	ymm9, ymm9, 8
        vpaddq	ymm7, ymm7, ymm9
        ; aes_enc_block
        vbroadcasti128	ymm14, [r9]
        vpxor	ymm0, ymm0, ymm14
        vpxor	ymm1, ymm1, ymm14
        vbroadcasti128	ymm14, [r9+16]
        vaesenc	ymm0, ymm0, ymm14
        vaesenc	ymm1, ymm1, ymm14
        vbroadcasti128	ymm14, [r9+32]
        vaesenc	ymm0, ymm0, ymm14
        vaesenc	ymm1, ymm1, ymm14
        vbroadcasti128	ymm14, [r9+48]
        vaesenc	ymm0, ymm0, ymm14
        vaesenc	ymm1, ymm1, ymm14
        vbroadcasti128	ymm14, [r9+64]
        vaesenc	ymm0, ymm0, ymm14
        vaesenc	ymm1, ymm1, ymm14
        vbroadcasti128	ymm14, [r9+80]
        vaesenc	ymm0, ymm0, ymm14
        vaesenc	ymm1, ymm1, ymm14
        vbroadcasti128	ymm14, [r9+96]
        vaesenc	ymm0, ymm0, ymm14
        vaesenc	ymm1, ymm1, ymm14
        vbroadcasti128	ymm14, [r9+112]
        vaesenc	ymm0, ymm0, ymm14
        vaesenc	ymm1, ymm1, ymm14
        vbroadcasti128	ymm14, [r9+128]
        vaesenc	ymm0, ymm0, ymm14
        vaesenc	ymm1, ymm1, ymm14
        vbroadcasti128	ymm14, [r9+144]
        vaesenc	ymm0, ymm0, ymm14
        vaesenc	ymm1, ymm1, ymm14
        cmp	eax, 11
        vbroadcasti128	ymm14, [r9+160]
        jl	L_AES_CTR_encrypt_vaes_64_aes_enc_block_last
        vaesenc	ymm0, ymm0, ymm14
        vaesenc	ymm1, ymm1, ymm14
        vbroadcasti128	ymm14, [r9+176]
        vaesenc	ymm0, ymm0, ymm14
        vaesenc	ymm1, ymm1, ymm14
        cmp	eax, 13
        vbroadcasti128	ymm14, [r9+192]
        jl	L_AES_CTR_encrypt_vaes_64_aes_enc_block_last
        vaesenc	ymm0, ymm0, ymm14
        vaesenc	ymm1, ymm1, ymm14
        vbroadcasti128	ymm14, [r9+208]
        vaesenc	ymm0, ymm0, ymm14
        vaesenc	ymm1, ymm1, ymm14
        vbroadcasti128	ymm14, [r9+224]
L_AES_CTR_encrypt_vaes_64_aes_enc_block_last:
        vaesenclast	ymm0, ymm0, ymm14
        vaesenclast	ymm1, ymm1, ymm14
        vpxor	ymm0, ymm0, [r11]
        vpxor	ymm1, ymm1, [r11+32]
        vmovdqu	YMMWORD PTR [rbx], ymm0
        vmovdqu	YMMWORD PTR [rbx+32], ymm1
        add	eax, 64
L_AES_CTR_encrypt_vaes_done_64:
        mov	r10d, r8d
        and	r10d, 4294967264
        cmp	eax, r10d
        je	L_AES_CTR_encrypt_vaes_done_32
L_AES_CTR_encrypt_vaes_enc_32:
        ; 32 bytes of input
        ; aes_ctr_enc_32
        lea	r11, QWORD PTR [rcx+rax]
        lea	rbx, QWORD PTR [rdx+rax]
        vpaddq	ymm0, ymm7, [ptr_L_aes_ctr_inc_vaes]
        vmovdqa	ymm9, ymm7
        vpand	ymm15, ymm9, [ptr_L_aes_ctr_inc_vaes]
        vpor	ymm9, ymm9, [ptr_L_aes_ctr_inc_vaes]
        vpandn	ymm9, ymm0, ymm9
        vpor	ymm9, ymm9, ymm15
        vpsrlq	ymm9, ymm9, 63
        vpslldq	ymm9, ymm9, 8
        vpaddq	ymm0, ymm0, ymm9
        vpshufb	ymm0, ymm0, ymm8
        vmovdqa	ymm9, ymm7
        vpaddq	ymm7, ymm7, ymm12
        vpand	ymm15, ymm9, ymm12
        vpor	ymm9, ymm9, ymm12
        vpandn	ymm9, ymm7, ymm9
        vpor	ymm9, ymm9, ymm15
        vpsrlq	ymm9, ymm9, 63
        vpslldq	ymm9, ymm9, 8
        vpaddq	ymm7, ymm7, ymm9
        ; aes_enc_block
        vbroadcasti128	ymm14, [r9]
        vpxor	ymm0, ymm0, ymm14
        vbroadcasti128	ymm14, [r9+16]
        vaesenc	ymm0, ymm0, ymm14
        vbroadcasti128	ymm14, [r9+32]
        vaesenc	ymm0, ymm0, ymm14
        vbroadcasti128	ymm14, [r9+48]
        vaesenc	ymm0, ymm0, ymm14
        vbroadcasti128	ymm14, [r9+64]
        vaesenc	ymm0, ymm0, ymm14
        vbroadcasti128	ymm14, [r9+80]
        vaesenc	ymm0, ymm0, ymm14
        vbroadcasti128	ymm14, [r9+96]
        vaesenc	ymm0, ymm0, ymm14
        vbroadcasti128	ymm14, [r9+112]
        vaesenc	ymm0, ymm0, ymm14
        vbroadcasti128	ymm14, [r9+128]
        vaesenc	ymm0, ymm0, ymm14
        vbroadcasti128	ymm14, [r9+144]
        vaesenc	ymm0, ymm0, ymm14
        cmp	eax, 11
        vbroadcasti128	ymm14, [r9+160]
        jl	L_AES_CTR_encrypt_vaes_32_aes_enc_block_last
        vaesenc	ymm0, ymm0, ymm14
        vbroadcasti128	ymm14, [r9+176]
        vaesenc	ymm0, ymm0, ymm14
        cmp	eax, 13
        vbroadcasti128	ymm14, [r9+192]
        jl	L_AES_CTR_encrypt_vaes_32_aes_enc_block_last
        vaesenc	ymm0, ymm0, ymm14
        vbroadcasti128	ymm14, [r9+208]
        vaesenc	ymm0, ymm0, ymm14
        vbroadcasti128	ymm14, [r9+224]
L_AES_CTR_encrypt_vaes_32_aes_enc_block_last:
        vaesenclast	ymm0, ymm0, ymm14
        vpxor	ymm0, ymm0, [r11]
        vmovdqu	YMMWORD PTR [rbx], ymm0
        add	eax, 32
        cmp	eax, r10d
        jl	L_AES_CTR_encrypt_vaes_enc_32
L_AES_CTR_encrypt_vaes_done_32:
        cmp	eax, r8d
        mov	r10d, r8d
        je	L_AES_CTR_encrypt_vaes_done_enc
        and	r10d, 4294967280
L_AES_CTR_encrypt_vaes_enc_16:
        ; 16 bytes of input
        vpshufb	xmm0, xmm7, xmm8
        vmovdqa	ymm9, ymm7
        vpaddq	ymm7, ymm7, ymm13
        vpand	ymm15, ymm9, ymm13
        vpor	ymm9, ymm9, ymm13
        vpandn	ymm9, ymm7, ymm9
        vpor	ymm9, ymm9, ymm15
        vpsrlq	ymm9, ymm9, 63
        vpslldq	ymm9, ymm9, 8
        vpaddq	ymm7, ymm7, ymm9
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
        cmp	eax, 11
        vmovdqu	xmm5, OWORD PTR [r9+160]
        jl	L_AES_CTR_encrypt_vaes_16_aes_enc_block_last
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r9+176]
        vaesenc	xmm0, xmm0, xmm6
        cmp	eax, 13
        vmovdqu	xmm5, OWORD PTR [r9+192]
        jl	L_AES_CTR_encrypt_vaes_16_aes_enc_block_last
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r9+208]
        vaesenc	xmm0, xmm0, xmm6
        vmovdqu	xmm5, OWORD PTR [r9+224]
L_AES_CTR_encrypt_vaes_16_aes_enc_block_last:
        vaesenclast	xmm0, xmm0, xmm5
        lea	r11, QWORD PTR [rcx+rax]
        vpxor	xmm0, xmm0, [r11]
        lea	r11, QWORD PTR [rdx+rax]
        vmovdqu	OWORD PTR [r11], xmm0
        add	eax, 16
        cmp	eax, r10d
        jl	L_AES_CTR_encrypt_vaes_enc_16
L_AES_CTR_encrypt_vaes_done_enc:
        vpshufb	xmm0, xmm7, xmm8
        vmovdqu	OWORD PTR [r10], xmm0
        vmovdqu	xmm6, OWORD PTR [rsp]
        vmovdqu	xmm7, OWORD PTR [rsp+16]
        vmovdqu	xmm8, OWORD PTR [rsp+32]
        vmovdqu	xmm9, OWORD PTR [rsp+48]
        vmovdqu	xmm10, OWORD PTR [rsp+64]
        vmovdqu	xmm11, OWORD PTR [rsp+80]
        vmovdqu	xmm12, OWORD PTR [rsp+96]
        vmovdqu	xmm13, OWORD PTR [rsp+112]
        vmovdqu	xmm14, OWORD PTR [rsp+128]
        vmovdqu	xmm15, OWORD PTR [rsp+144]
        add	rsp, 160
        pop	rbx
        ret
AES_CTR_encrypt_vaes ENDP
_TEXT ENDS
ENDIF
IFDEF HAVE_INTEL_AVX512
_TEXT SEGMENT READONLY PARA
AES_ECB_encrypt_avx512 PROC
        mov	eax, DWORD PTR [rsp+40]
        sub	rsp, 160
        vmovdqu	OWORD PTR [rsp], xmm6
        vmovdqu	OWORD PTR [rsp+16], xmm7
        vmovdqu	OWORD PTR [rsp+32], xmm8
        vmovdqu	OWORD PTR [rsp+48], xmm9
        vmovdqu	OWORD PTR [rsp+64], xmm10
        vmovdqu	OWORD PTR [rsp+80], xmm11
        vmovdqu	OWORD PTR [rsp+96], xmm12
        vmovdqu	OWORD PTR [rsp+112], xmm13
        vmovdqu	OWORD PTR [rsp+128], xmm14
        vmovdqu	OWORD PTR [rsp+144], xmm15
        xor	eax, eax
        cmp	r8d, 32
        jl	L_AES_ECB_encrypt_avx512_done_32
        vbroadcasti32x4	zmm8, [r9]
        vbroadcasti32x4	zmm9, [r9+16]
        vbroadcasti32x4	zmm10, [r9+32]
        vbroadcasti32x4	zmm11, [r9+48]
        vbroadcasti32x4	zmm12, [r9+64]
        vbroadcasti32x4	zmm13, [r9+80]
        vbroadcasti32x4	zmm14, [r9+96]
        vbroadcasti32x4	zmm15, [r9+112]
        vbroadcasti32x4	zmm16, [r9+128]
        vbroadcasti32x4	zmm17, [r9+144]
        vbroadcasti32x4	zmm18, [r9+160]
        cmp	eax, 11
        jl	L_AES_ECB_encrypt_avx512_key_cached
        vbroadcasti32x4	zmm19, [r9+176]
        vbroadcasti32x4	zmm20, [r9+192]
        cmp	eax, 13
        jl	L_AES_ECB_encrypt_avx512_key_cached
        vbroadcasti32x4	zmm21, [r9+208]
        vbroadcasti32x4	zmm22, [r9+224]
L_AES_ECB_encrypt_avx512_key_cached:
        cmp	r8d, 256
        mov	r9d, r8d
        jl	L_AES_ECB_encrypt_avx512_done_256
        and	r9d, 4294967040
L_AES_ECB_encrypt_avx512_enc_256:
        ; 256 bytes of input
        ; aes_ecb_enc_256
        lea	r10, QWORD PTR [rcx+rax]
        lea	r11, QWORD PTR [rdx+rax]
        vmovdqu64	zmm0, [r10]
        vmovdqu64	zmm1, [r10+64]
        vmovdqu64	zmm2, [r10+128]
        vmovdqu64	zmm3, [r10+192]
        ; aes_enc_block
        vpxorq	zmm0, zmm0, zmm8
        vpxorq	zmm1, zmm1, zmm8
        vpxorq	zmm2, zmm2, zmm8
        vpxorq	zmm3, zmm3, zmm8
        vaesenc	zmm0, zmm0, zmm9
        vaesenc	zmm1, zmm1, zmm9
        vaesenc	zmm2, zmm2, zmm9
        vaesenc	zmm3, zmm3, zmm9
        vaesenc	zmm0, zmm0, zmm10
        vaesenc	zmm1, zmm1, zmm10
        vaesenc	zmm2, zmm2, zmm10
        vaesenc	zmm3, zmm3, zmm10
        vaesenc	zmm0, zmm0, zmm11
        vaesenc	zmm1, zmm1, zmm11
        vaesenc	zmm2, zmm2, zmm11
        vaesenc	zmm3, zmm3, zmm11
        vaesenc	zmm0, zmm0, zmm12
        vaesenc	zmm1, zmm1, zmm12
        vaesenc	zmm2, zmm2, zmm12
        vaesenc	zmm3, zmm3, zmm12
        vaesenc	zmm0, zmm0, zmm13
        vaesenc	zmm1, zmm1, zmm13
        vaesenc	zmm2, zmm2, zmm13
        vaesenc	zmm3, zmm3, zmm13
        vaesenc	zmm0, zmm0, zmm14
        vaesenc	zmm1, zmm1, zmm14
        vaesenc	zmm2, zmm2, zmm14
        vaesenc	zmm3, zmm3, zmm14
        vaesenc	zmm0, zmm0, zmm15
        vaesenc	zmm1, zmm1, zmm15
        vaesenc	zmm2, zmm2, zmm15
        vaesenc	zmm3, zmm3, zmm15
        vaesenc	zmm0, zmm0, zmm16
        vaesenc	zmm1, zmm1, zmm16
        vaesenc	zmm2, zmm2, zmm16
        vaesenc	zmm3, zmm3, zmm16
        vaesenc	zmm0, zmm0, zmm17
        vaesenc	zmm1, zmm1, zmm17
        vaesenc	zmm2, zmm2, zmm17
        vaesenc	zmm3, zmm3, zmm17
        cmp	eax, 11
        vmovdqa64	zmm7, zmm18
        jl	L_AES_ECB_encrypt_avx512_256_aes_enc_block_last
        vaesenc	zmm0, zmm0, zmm18
        vaesenc	zmm1, zmm1, zmm18
        vaesenc	zmm2, zmm2, zmm18
        vaesenc	zmm3, zmm3, zmm18
        vaesenc	zmm0, zmm0, zmm19
        vaesenc	zmm1, zmm1, zmm19
        vaesenc	zmm2, zmm2, zmm19
        vaesenc	zmm3, zmm3, zmm19
        cmp	eax, 13
        vmovdqa64	zmm7, zmm20
        jl	L_AES_ECB_encrypt_avx512_256_aes_enc_block_last
        vaesenc	zmm0, zmm0, zmm20
        vaesenc	zmm1, zmm1, zmm20
        vaesenc	zmm2, zmm2, zmm20
        vaesenc	zmm3, zmm3, zmm20
        vaesenc	zmm0, zmm0, zmm21
        vaesenc	zmm1, zmm1, zmm21
        vaesenc	zmm2, zmm2, zmm21
        vaesenc	zmm3, zmm3, zmm21
        vmovdqa64	zmm7, zmm22
L_AES_ECB_encrypt_avx512_256_aes_enc_block_last:
        vaesenclast	zmm0, zmm0, zmm7
        vaesenclast	zmm1, zmm1, zmm7
        vaesenclast	zmm2, zmm2, zmm7
        vaesenclast	zmm3, zmm3, zmm7
        vmovdqu64	[r11], zmm0
        vmovdqu64	[r11+64], zmm1
        vmovdqu64	[r11+128], zmm2
        vmovdqu64	[r11+192], zmm3
        add	eax, 256
        cmp	eax, r9d
        jl	L_AES_ECB_encrypt_avx512_enc_256
L_AES_ECB_encrypt_avx512_done_256:
        mov	r9d, r8d
        sub	r9d, eax
        cmp	r9d, 128
        jl	L_AES_ECB_encrypt_avx512_done_128
        ; 128 bytes of input
        ; aes_ecb_enc_128
        lea	r10, QWORD PTR [rcx+rax]
        lea	r11, QWORD PTR [rdx+rax]
        vmovdqu64	zmm0, [r10]
        vmovdqu64	zmm1, [r10+64]
        ; aes_enc_block
        vpxorq	zmm0, zmm0, zmm8
        vpxorq	zmm1, zmm1, zmm8
        vaesenc	zmm0, zmm0, zmm9
        vaesenc	zmm1, zmm1, zmm9
        vaesenc	zmm0, zmm0, zmm10
        vaesenc	zmm1, zmm1, zmm10
        vaesenc	zmm0, zmm0, zmm11
        vaesenc	zmm1, zmm1, zmm11
        vaesenc	zmm0, zmm0, zmm12
        vaesenc	zmm1, zmm1, zmm12
        vaesenc	zmm0, zmm0, zmm13
        vaesenc	zmm1, zmm1, zmm13
        vaesenc	zmm0, zmm0, zmm14
        vaesenc	zmm1, zmm1, zmm14
        vaesenc	zmm0, zmm0, zmm15
        vaesenc	zmm1, zmm1, zmm15
        vaesenc	zmm0, zmm0, zmm16
        vaesenc	zmm1, zmm1, zmm16
        vaesenc	zmm0, zmm0, zmm17
        vaesenc	zmm1, zmm1, zmm17
        cmp	eax, 11
        vmovdqa64	zmm7, zmm18
        jl	L_AES_ECB_encrypt_avx512_128_aes_enc_block_last
        vaesenc	zmm0, zmm0, zmm18
        vaesenc	zmm1, zmm1, zmm18
        vaesenc	zmm0, zmm0, zmm19
        vaesenc	zmm1, zmm1, zmm19
        cmp	eax, 13
        vmovdqa64	zmm7, zmm20
        jl	L_AES_ECB_encrypt_avx512_128_aes_enc_block_last
        vaesenc	zmm0, zmm0, zmm20
        vaesenc	zmm1, zmm1, zmm20
        vaesenc	zmm0, zmm0, zmm21
        vaesenc	zmm1, zmm1, zmm21
        vmovdqa64	zmm7, zmm22
L_AES_ECB_encrypt_avx512_128_aes_enc_block_last:
        vaesenclast	zmm0, zmm0, zmm7
        vaesenclast	zmm1, zmm1, zmm7
        vmovdqu64	[r11], zmm0
        vmovdqu64	[r11+64], zmm1
        add	eax, 128
L_AES_ECB_encrypt_avx512_done_128:
        mov	r9d, r8d
        and	r9d, 4294967232
        cmp	eax, r9d
        je	L_AES_ECB_encrypt_avx512_done_64
L_AES_ECB_encrypt_avx512_enc_64:
        ; 64 bytes of input
        ; aes_ecb_enc_64
        lea	r10, QWORD PTR [rcx+rax]
        lea	r11, QWORD PTR [rdx+rax]
        vmovdqu64	zmm0, [r10]
        ; aes_enc_block
        vpxorq	zmm0, zmm0, zmm8
        vaesenc	zmm0, zmm0, zmm9
        vaesenc	zmm0, zmm0, zmm10
        vaesenc	zmm0, zmm0, zmm11
        vaesenc	zmm0, zmm0, zmm12
        vaesenc	zmm0, zmm0, zmm13
        vaesenc	zmm0, zmm0, zmm14
        vaesenc	zmm0, zmm0, zmm15
        vaesenc	zmm0, zmm0, zmm16
        vaesenc	zmm0, zmm0, zmm17
        cmp	eax, 11
        vmovdqa64	zmm7, zmm18
        jl	L_AES_ECB_encrypt_avx512_64_aes_enc_block_last
        vaesenc	zmm0, zmm0, zmm18
        vaesenc	zmm0, zmm0, zmm19
        cmp	eax, 13
        vmovdqa64	zmm7, zmm20
        jl	L_AES_ECB_encrypt_avx512_64_aes_enc_block_last
        vaesenc	zmm0, zmm0, zmm20
        vaesenc	zmm0, zmm0, zmm21
        vmovdqa64	zmm7, zmm22
L_AES_ECB_encrypt_avx512_64_aes_enc_block_last:
        vaesenclast	zmm0, zmm0, zmm7
        vmovdqu64	[r11], zmm0
        add	eax, 64
        cmp	eax, r9d
        jl	L_AES_ECB_encrypt_avx512_enc_64
L_AES_ECB_encrypt_avx512_done_64:
        mov	r9d, r8d
        sub	r9d, eax
        cmp	r9d, 32
        jl	L_AES_ECB_encrypt_avx512_done_32
        ; 32 bytes of input
        lea	r10, QWORD PTR [rcx+rax]
        vmovdqu	ymm0, YMMWORD PTR [r10]
        ; aes_enc_block
        vpxorq	ymm0, ymm0, ymm8
        vaesenc	ymm0, ymm0, ymm9
        vaesenc	ymm0, ymm0, ymm10
        vaesenc	ymm0, ymm0, ymm11
        vaesenc	ymm0, ymm0, ymm12
        vaesenc	ymm0, ymm0, ymm13
        vaesenc	ymm0, ymm0, ymm14
        vaesenc	ymm0, ymm0, ymm15
        vaesenc	ymm0, ymm0, ymm16
        vaesenc	ymm0, ymm0, ymm17
        cmp	eax, 11
        vmovdqa64	ymm7, ymm18
        jl	L_AES_ECB_encrypt_avx512_32_aes_enc_block_last
        vaesenc	ymm0, ymm0, ymm18
        vaesenc	ymm0, ymm0, ymm19
        cmp	eax, 13
        vmovdqa64	ymm7, ymm20
        jl	L_AES_ECB_encrypt_avx512_32_aes_enc_block_last
        vaesenc	ymm0, ymm0, ymm20
        vaesenc	ymm0, ymm0, ymm21
        vmovdqa64	ymm7, ymm22
L_AES_ECB_encrypt_avx512_32_aes_enc_block_last:
        vaesenclast	ymm0, ymm0, ymm7
        lea	r10, QWORD PTR [rdx+rax]
        vmovdqu	YMMWORD PTR [r10], ymm0
        add	eax, 32
L_AES_ECB_encrypt_avx512_done_32:
        cmp	eax, r8d
        mov	r9d, r8d
        je	L_AES_ECB_encrypt_avx512_done_enc
        and	r9d, 4294967280
L_AES_ECB_encrypt_avx512_enc_16:
        ; 16 bytes of input
        lea	r10, QWORD PTR [rcx+rax]
        vmovdqu	xmm0, OWORD PTR [r10]
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
        cmp	eax, 11
        vmovdqu	xmm5, OWORD PTR [r9+160]
        jl	L_AES_ECB_encrypt_avx512_16_aes_enc_block_last
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r9+176]
        vaesenc	xmm0, xmm0, xmm6
        cmp	eax, 13
        vmovdqu	xmm5, OWORD PTR [r9+192]
        jl	L_AES_ECB_encrypt_avx512_16_aes_enc_block_last
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r9+208]
        vaesenc	xmm0, xmm0, xmm6
        vmovdqu	xmm5, OWORD PTR [r9+224]
L_AES_ECB_encrypt_avx512_16_aes_enc_block_last:
        vaesenclast	xmm0, xmm0, xmm5
        lea	r10, QWORD PTR [rdx+rax]
        vmovdqu	OWORD PTR [r10], xmm0
        add	eax, 16
        cmp	eax, r9d
        jl	L_AES_ECB_encrypt_avx512_enc_16
L_AES_ECB_encrypt_avx512_done_enc:
        vmovdqu	xmm6, OWORD PTR [rsp]
        vmovdqu	xmm7, OWORD PTR [rsp+16]
        vmovdqu	xmm8, OWORD PTR [rsp+32]
        vmovdqu	xmm9, OWORD PTR [rsp+48]
        vmovdqu	xmm10, OWORD PTR [rsp+64]
        vmovdqu	xmm11, OWORD PTR [rsp+80]
        vmovdqu	xmm12, OWORD PTR [rsp+96]
        vmovdqu	xmm13, OWORD PTR [rsp+112]
        vmovdqu	xmm14, OWORD PTR [rsp+128]
        vmovdqu	xmm15, OWORD PTR [rsp+144]
        add	rsp, 160
        ret
AES_ECB_encrypt_avx512 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_ECB_decrypt_avx512 PROC
        mov	eax, DWORD PTR [rsp+40]
        sub	rsp, 160
        vmovdqu	OWORD PTR [rsp], xmm6
        vmovdqu	OWORD PTR [rsp+16], xmm7
        vmovdqu	OWORD PTR [rsp+32], xmm8
        vmovdqu	OWORD PTR [rsp+48], xmm9
        vmovdqu	OWORD PTR [rsp+64], xmm10
        vmovdqu	OWORD PTR [rsp+80], xmm11
        vmovdqu	OWORD PTR [rsp+96], xmm12
        vmovdqu	OWORD PTR [rsp+112], xmm13
        vmovdqu	OWORD PTR [rsp+128], xmm14
        vmovdqu	OWORD PTR [rsp+144], xmm15
        xor	eax, eax
        cmp	r8d, 32
        jl	L_AES_ECB_decrypt_avx512_done_32
        vbroadcasti32x4	zmm8, [r9]
        vbroadcasti32x4	zmm9, [r9+16]
        vbroadcasti32x4	zmm10, [r9+32]
        vbroadcasti32x4	zmm11, [r9+48]
        vbroadcasti32x4	zmm12, [r9+64]
        vbroadcasti32x4	zmm13, [r9+80]
        vbroadcasti32x4	zmm14, [r9+96]
        vbroadcasti32x4	zmm15, [r9+112]
        vbroadcasti32x4	zmm16, [r9+128]
        vbroadcasti32x4	zmm17, [r9+144]
        vbroadcasti32x4	zmm18, [r9+160]
        cmp	eax, 11
        jl	L_AES_ECB_decrypt_avx512_key_cached
        vbroadcasti32x4	zmm19, [r9+176]
        vbroadcasti32x4	zmm20, [r9+192]
        cmp	eax, 13
        jl	L_AES_ECB_decrypt_avx512_key_cached
        vbroadcasti32x4	zmm21, [r9+208]
        vbroadcasti32x4	zmm22, [r9+224]
L_AES_ECB_decrypt_avx512_key_cached:
        cmp	r8d, 256
        mov	r9d, r8d
        jl	L_AES_ECB_decrypt_avx512_done_256
        and	r9d, 4294967040
L_AES_ECB_decrypt_avx512_dec_256:
        ; 256 bytes of input
        ; aes_ecb_dec_256
        lea	r10, QWORD PTR [rcx+rax]
        lea	r11, QWORD PTR [rdx+rax]
        vmovdqu64	zmm0, [r10]
        vmovdqu64	zmm1, [r10+64]
        vmovdqu64	zmm2, [r10+128]
        vmovdqu64	zmm3, [r10+192]
        ; aes_dec_block
        vpxorq	zmm0, zmm0, zmm8
        vpxorq	zmm1, zmm1, zmm8
        vpxorq	zmm2, zmm2, zmm8
        vpxorq	zmm3, zmm3, zmm8
        vaesdec	zmm0, zmm0, zmm9
        vaesdec	zmm1, zmm1, zmm9
        vaesdec	zmm2, zmm2, zmm9
        vaesdec	zmm3, zmm3, zmm9
        vaesdec	zmm0, zmm0, zmm10
        vaesdec	zmm1, zmm1, zmm10
        vaesdec	zmm2, zmm2, zmm10
        vaesdec	zmm3, zmm3, zmm10
        vaesdec	zmm0, zmm0, zmm11
        vaesdec	zmm1, zmm1, zmm11
        vaesdec	zmm2, zmm2, zmm11
        vaesdec	zmm3, zmm3, zmm11
        vaesdec	zmm0, zmm0, zmm12
        vaesdec	zmm1, zmm1, zmm12
        vaesdec	zmm2, zmm2, zmm12
        vaesdec	zmm3, zmm3, zmm12
        vaesdec	zmm0, zmm0, zmm13
        vaesdec	zmm1, zmm1, zmm13
        vaesdec	zmm2, zmm2, zmm13
        vaesdec	zmm3, zmm3, zmm13
        vaesdec	zmm0, zmm0, zmm14
        vaesdec	zmm1, zmm1, zmm14
        vaesdec	zmm2, zmm2, zmm14
        vaesdec	zmm3, zmm3, zmm14
        vaesdec	zmm0, zmm0, zmm15
        vaesdec	zmm1, zmm1, zmm15
        vaesdec	zmm2, zmm2, zmm15
        vaesdec	zmm3, zmm3, zmm15
        vaesdec	zmm0, zmm0, zmm16
        vaesdec	zmm1, zmm1, zmm16
        vaesdec	zmm2, zmm2, zmm16
        vaesdec	zmm3, zmm3, zmm16
        vaesdec	zmm0, zmm0, zmm17
        vaesdec	zmm1, zmm1, zmm17
        vaesdec	zmm2, zmm2, zmm17
        vaesdec	zmm3, zmm3, zmm17
        cmp	eax, 11
        vmovdqa64	zmm7, zmm18
        jl	L_AES_ECB_decrypt_avx512_256_aes_dec_block_last
        vaesdec	zmm0, zmm0, zmm18
        vaesdec	zmm1, zmm1, zmm18
        vaesdec	zmm2, zmm2, zmm18
        vaesdec	zmm3, zmm3, zmm18
        vaesdec	zmm0, zmm0, zmm19
        vaesdec	zmm1, zmm1, zmm19
        vaesdec	zmm2, zmm2, zmm19
        vaesdec	zmm3, zmm3, zmm19
        cmp	eax, 13
        vmovdqa64	zmm7, zmm20
        jl	L_AES_ECB_decrypt_avx512_256_aes_dec_block_last
        vaesdec	zmm0, zmm0, zmm20
        vaesdec	zmm1, zmm1, zmm20
        vaesdec	zmm2, zmm2, zmm20
        vaesdec	zmm3, zmm3, zmm20
        vaesdec	zmm0, zmm0, zmm21
        vaesdec	zmm1, zmm1, zmm21
        vaesdec	zmm2, zmm2, zmm21
        vaesdec	zmm3, zmm3, zmm21
        vmovdqa64	zmm7, zmm22
L_AES_ECB_decrypt_avx512_256_aes_dec_block_last:
        vaesdeclast	zmm0, zmm0, zmm7
        vaesdeclast	zmm1, zmm1, zmm7
        vaesdeclast	zmm2, zmm2, zmm7
        vaesdeclast	zmm3, zmm3, zmm7
        vmovdqu64	[r11], zmm0
        vmovdqu64	[r11+64], zmm1
        vmovdqu64	[r11+128], zmm2
        vmovdqu64	[r11+192], zmm3
        add	eax, 256
        cmp	eax, r9d
        jl	L_AES_ECB_decrypt_avx512_dec_256
L_AES_ECB_decrypt_avx512_done_256:
        mov	r9d, r8d
        sub	r9d, eax
        cmp	r9d, 128
        jl	L_AES_ECB_decrypt_avx512_done_128
        ; 128 bytes of input
        ; aes_ecb_dec_128
        lea	r10, QWORD PTR [rcx+rax]
        lea	r11, QWORD PTR [rdx+rax]
        vmovdqu64	zmm0, [r10]
        vmovdqu64	zmm1, [r10+64]
        ; aes_dec_block
        vpxorq	zmm0, zmm0, zmm8
        vpxorq	zmm1, zmm1, zmm8
        vaesdec	zmm0, zmm0, zmm9
        vaesdec	zmm1, zmm1, zmm9
        vaesdec	zmm0, zmm0, zmm10
        vaesdec	zmm1, zmm1, zmm10
        vaesdec	zmm0, zmm0, zmm11
        vaesdec	zmm1, zmm1, zmm11
        vaesdec	zmm0, zmm0, zmm12
        vaesdec	zmm1, zmm1, zmm12
        vaesdec	zmm0, zmm0, zmm13
        vaesdec	zmm1, zmm1, zmm13
        vaesdec	zmm0, zmm0, zmm14
        vaesdec	zmm1, zmm1, zmm14
        vaesdec	zmm0, zmm0, zmm15
        vaesdec	zmm1, zmm1, zmm15
        vaesdec	zmm0, zmm0, zmm16
        vaesdec	zmm1, zmm1, zmm16
        vaesdec	zmm0, zmm0, zmm17
        vaesdec	zmm1, zmm1, zmm17
        cmp	eax, 11
        vmovdqa64	zmm7, zmm18
        jl	L_AES_ECB_decrypt_avx512_128_aes_dec_block_last
        vaesdec	zmm0, zmm0, zmm18
        vaesdec	zmm1, zmm1, zmm18
        vaesdec	zmm0, zmm0, zmm19
        vaesdec	zmm1, zmm1, zmm19
        cmp	eax, 13
        vmovdqa64	zmm7, zmm20
        jl	L_AES_ECB_decrypt_avx512_128_aes_dec_block_last
        vaesdec	zmm0, zmm0, zmm20
        vaesdec	zmm1, zmm1, zmm20
        vaesdec	zmm0, zmm0, zmm21
        vaesdec	zmm1, zmm1, zmm21
        vmovdqa64	zmm7, zmm22
L_AES_ECB_decrypt_avx512_128_aes_dec_block_last:
        vaesdeclast	zmm0, zmm0, zmm7
        vaesdeclast	zmm1, zmm1, zmm7
        vmovdqu64	[r11], zmm0
        vmovdqu64	[r11+64], zmm1
        add	eax, 128
L_AES_ECB_decrypt_avx512_done_128:
        mov	r9d, r8d
        and	r9d, 4294967232
        cmp	eax, r9d
        je	L_AES_ECB_decrypt_avx512_done_64
L_AES_ECB_decrypt_avx512_dec_64:
        ; 64 bytes of input
        ; aes_ecb_dec_64
        lea	r10, QWORD PTR [rcx+rax]
        lea	r11, QWORD PTR [rdx+rax]
        vmovdqu64	zmm0, [r10]
        ; aes_dec_block
        vpxorq	zmm0, zmm0, zmm8
        vaesdec	zmm0, zmm0, zmm9
        vaesdec	zmm0, zmm0, zmm10
        vaesdec	zmm0, zmm0, zmm11
        vaesdec	zmm0, zmm0, zmm12
        vaesdec	zmm0, zmm0, zmm13
        vaesdec	zmm0, zmm0, zmm14
        vaesdec	zmm0, zmm0, zmm15
        vaesdec	zmm0, zmm0, zmm16
        vaesdec	zmm0, zmm0, zmm17
        cmp	eax, 11
        vmovdqa64	zmm7, zmm18
        jl	L_AES_ECB_decrypt_avx512_64_aes_dec_block_last
        vaesdec	zmm0, zmm0, zmm18
        vaesdec	zmm0, zmm0, zmm19
        cmp	eax, 13
        vmovdqa64	zmm7, zmm20
        jl	L_AES_ECB_decrypt_avx512_64_aes_dec_block_last
        vaesdec	zmm0, zmm0, zmm20
        vaesdec	zmm0, zmm0, zmm21
        vmovdqa64	zmm7, zmm22
L_AES_ECB_decrypt_avx512_64_aes_dec_block_last:
        vaesdeclast	zmm0, zmm0, zmm7
        vmovdqu64	[r11], zmm0
        add	eax, 64
        cmp	eax, r9d
        jl	L_AES_ECB_decrypt_avx512_dec_64
L_AES_ECB_decrypt_avx512_done_64:
        mov	r9d, r8d
        sub	r9d, eax
        cmp	r9d, 32
        jl	L_AES_ECB_decrypt_avx512_done_32
        ; 32 bytes of input
        lea	r10, QWORD PTR [rcx+rax]
        vmovdqu	ymm0, YMMWORD PTR [r10]
        ; aes_dec_block
        vpxorq	ymm0, ymm0, ymm8
        vaesdec	ymm0, ymm0, ymm9
        vaesdec	ymm0, ymm0, ymm10
        vaesdec	ymm0, ymm0, ymm11
        vaesdec	ymm0, ymm0, ymm12
        vaesdec	ymm0, ymm0, ymm13
        vaesdec	ymm0, ymm0, ymm14
        vaesdec	ymm0, ymm0, ymm15
        vaesdec	ymm0, ymm0, ymm16
        vaesdec	ymm0, ymm0, ymm17
        cmp	eax, 11
        vmovdqa64	ymm7, ymm18
        jl	L_AES_ECB_decrypt_avx512_32_aes_dec_block_last
        vaesdec	ymm0, ymm0, ymm18
        vaesdec	ymm0, ymm0, ymm19
        cmp	eax, 13
        vmovdqa64	ymm7, ymm20
        jl	L_AES_ECB_decrypt_avx512_32_aes_dec_block_last
        vaesdec	ymm0, ymm0, ymm20
        vaesdec	ymm0, ymm0, ymm21
        vmovdqa64	ymm7, ymm22
L_AES_ECB_decrypt_avx512_32_aes_dec_block_last:
        vaesdeclast	ymm0, ymm0, ymm7
        lea	r10, QWORD PTR [rdx+rax]
        vmovdqu	YMMWORD PTR [r10], ymm0
        add	eax, 32
L_AES_ECB_decrypt_avx512_done_32:
        cmp	eax, r8d
        mov	r9d, r8d
        je	L_AES_ECB_decrypt_avx512_done_dec
        and	r9d, 4294967280
L_AES_ECB_decrypt_avx512_dec_16:
        ; 16 bytes of input
        lea	r10, QWORD PTR [rcx+rax]
        vmovdqu	xmm0, OWORD PTR [r10]
        ; aes_dec_block
        vpxor	xmm0, xmm0, [r9]
        vmovdqu	xmm5, OWORD PTR [r9+16]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+32]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+48]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+64]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+80]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+96]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+112]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+128]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [r9+144]
        vaesdec	xmm0, xmm0, xmm5
        cmp	eax, 11
        vmovdqu	xmm5, OWORD PTR [r9+160]
        jl	L_AES_ECB_decrypt_avx512_16_aes_dec_block_last
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r9+176]
        vaesdec	xmm0, xmm0, xmm6
        cmp	eax, 13
        vmovdqu	xmm5, OWORD PTR [r9+192]
        jl	L_AES_ECB_decrypt_avx512_16_aes_dec_block_last
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r9+208]
        vaesdec	xmm0, xmm0, xmm6
        vmovdqu	xmm5, OWORD PTR [r9+224]
L_AES_ECB_decrypt_avx512_16_aes_dec_block_last:
        vaesdeclast	xmm0, xmm0, xmm5
        lea	r10, QWORD PTR [rdx+rax]
        vmovdqu	OWORD PTR [r10], xmm0
        add	eax, 16
        cmp	eax, r9d
        jl	L_AES_ECB_decrypt_avx512_dec_16
L_AES_ECB_decrypt_avx512_done_dec:
        vmovdqu	xmm6, OWORD PTR [rsp]
        vmovdqu	xmm7, OWORD PTR [rsp+16]
        vmovdqu	xmm8, OWORD PTR [rsp+32]
        vmovdqu	xmm9, OWORD PTR [rsp+48]
        vmovdqu	xmm10, OWORD PTR [rsp+64]
        vmovdqu	xmm11, OWORD PTR [rsp+80]
        vmovdqu	xmm12, OWORD PTR [rsp+96]
        vmovdqu	xmm13, OWORD PTR [rsp+112]
        vmovdqu	xmm14, OWORD PTR [rsp+128]
        vmovdqu	xmm15, OWORD PTR [rsp+144]
        add	rsp, 160
        ret
AES_ECB_decrypt_avx512 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_CBC_encrypt_avx512 PROC
        mov	rax, QWORD PTR [rsp+40]
        mov	r10d, DWORD PTR [rsp+48]
        vmovdqu	xmm0, OWORD PTR [r8]
        xor	eax, eax
        cmp	eax, r9d
        je	L_AES_CBC_encrypt_avx512_done
L_AES_CBC_encrypt_avx512_loop:
        ; 16 bytes of input
        lea	r10, QWORD PTR [rcx+rax]
        vmovdqu	xmm1, OWORD PTR [r10]
        vpternlogq	xmm1, xmm0, [rax], 150
        ; aes_enc_block
        vmovdqu	xmm3, OWORD PTR [rax+16]
        vaesenc	xmm1, xmm1, xmm3
        vmovdqu	xmm3, OWORD PTR [rax+32]
        vaesenc	xmm1, xmm1, xmm3
        vmovdqu	xmm3, OWORD PTR [rax+48]
        vaesenc	xmm1, xmm1, xmm3
        vmovdqu	xmm3, OWORD PTR [rax+64]
        vaesenc	xmm1, xmm1, xmm3
        vmovdqu	xmm3, OWORD PTR [rax+80]
        vaesenc	xmm1, xmm1, xmm3
        vmovdqu	xmm3, OWORD PTR [rax+96]
        vaesenc	xmm1, xmm1, xmm3
        vmovdqu	xmm3, OWORD PTR [rax+112]
        vaesenc	xmm1, xmm1, xmm3
        vmovdqu	xmm3, OWORD PTR [rax+128]
        vaesenc	xmm1, xmm1, xmm3
        vmovdqu	xmm3, OWORD PTR [rax+144]
        vaesenc	xmm1, xmm1, xmm3
        cmp	r10d, 11
        vmovdqu	xmm3, OWORD PTR [rax+160]
        jl	L_AES_CBC_encrypt_avx512_aes_enc_block_last
        vaesenc	xmm1, xmm1, xmm3
        vmovdqu	xmm4, OWORD PTR [rax+176]
        vaesenc	xmm1, xmm1, xmm4
        cmp	r10d, 13
        vmovdqu	xmm3, OWORD PTR [rax+192]
        jl	L_AES_CBC_encrypt_avx512_aes_enc_block_last
        vaesenc	xmm1, xmm1, xmm3
        vmovdqu	xmm4, OWORD PTR [rax+208]
        vaesenc	xmm1, xmm1, xmm4
        vmovdqu	xmm3, OWORD PTR [rax+224]
L_AES_CBC_encrypt_avx512_aes_enc_block_last:
        vaesenclast	xmm1, xmm1, xmm3
        lea	r11, QWORD PTR [rdx+rax]
        vmovdqu	OWORD PTR [r11], xmm1
        vmovdqa	xmm0, xmm1
        add	eax, 16
        cmp	eax, r9d
        jl	L_AES_CBC_encrypt_avx512_loop
L_AES_CBC_encrypt_avx512_done:
        vmovdqu	OWORD PTR [r8], xmm0
        ret
AES_CBC_encrypt_avx512 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
AES_CBC_decrypt_avx512 PROC
        push	r12
        mov	rax, QWORD PTR [rsp+48]
        mov	r10d, DWORD PTR [rsp+56]
        sub	rsp, 160
        vmovdqu	OWORD PTR [rsp], xmm6
        vmovdqu	OWORD PTR [rsp+16], xmm7
        vmovdqu	OWORD PTR [rsp+32], xmm8
        vmovdqu	OWORD PTR [rsp+48], xmm9
        vmovdqu	OWORD PTR [rsp+64], xmm10
        vmovdqu	OWORD PTR [rsp+80], xmm11
        vmovdqu	OWORD PTR [rsp+96], xmm12
        vmovdqu	OWORD PTR [rsp+112], xmm13
        vmovdqu	OWORD PTR [rsp+128], xmm14
        vmovdqu	OWORD PTR [rsp+144], xmm15
        vmovdqu	xmm8, OWORD PTR [r8]
        xor	eax, eax
        cmp	r9d, 32
        jl	L_AES_CBC_decrypt_avx512_done_32
        vbroadcasti32x4	zmm14, [rax]
        vbroadcasti32x4	zmm15, [rax+16]
        vbroadcasti32x4	zmm16, [rax+32]
        vbroadcasti32x4	zmm17, [rax+48]
        vbroadcasti32x4	zmm18, [rax+64]
        vbroadcasti32x4	zmm19, [rax+80]
        vbroadcasti32x4	zmm20, [rax+96]
        vbroadcasti32x4	zmm21, [rax+112]
        vbroadcasti32x4	zmm22, [rax+128]
        vbroadcasti32x4	zmm23, [rax+144]
        vbroadcasti32x4	zmm24, [rax+160]
        cmp	r10d, 11
        jl	L_AES_CBC_decrypt_avx512_key_cached
        vbroadcasti32x4	zmm25, [rax+176]
        vbroadcasti32x4	zmm26, [rax+192]
        cmp	r10d, 13
        jl	L_AES_CBC_decrypt_avx512_key_cached
        vbroadcasti32x4	zmm27, [rax+208]
        vbroadcasti32x4	zmm28, [rax+224]
L_AES_CBC_decrypt_avx512_key_cached:
        cmp	r9d, 256
        mov	r10d, r9d
        jl	L_AES_CBC_decrypt_avx512_done_256
        and	r10d, 4294967040
L_AES_CBC_decrypt_avx512_dec_256:
        ; 256 bytes of input
        ; aes_cbc_dec_256
        lea	r11, QWORD PTR [rcx+rax]
        lea	r12, QWORD PTR [rdx+rax]
        vmovdqu64	zmm0, [r11]
        vmovdqu64	zmm1, [r11+64]
        vmovdqu64	zmm2, [r11+128]
        vmovdqu64	zmm3, [r11+192]
        vshufi64x2	zmm10, zmm0, zmm0, 144
        vinserti32x4	zmm10, zmm10, xmm8, 0
        vmovdqu64	zmm11, [r11+48]
        vmovdqu64	zmm12, [r11+112]
        vmovdqu64	zmm13, [r11+176]
        vextracti32x4	xmm8, zmm3, 3
        ; aes_dec_block
        vpxorq	zmm0, zmm0, zmm14
        vpxorq	zmm1, zmm1, zmm14
        vpxorq	zmm2, zmm2, zmm14
        vpxorq	zmm3, zmm3, zmm14
        vaesdec	zmm0, zmm0, zmm15
        vaesdec	zmm1, zmm1, zmm15
        vaesdec	zmm2, zmm2, zmm15
        vaesdec	zmm3, zmm3, zmm15
        vaesdec	zmm0, zmm0, zmm16
        vaesdec	zmm1, zmm1, zmm16
        vaesdec	zmm2, zmm2, zmm16
        vaesdec	zmm3, zmm3, zmm16
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
        cmp	r10d, 11
        vmovdqa64	zmm9, zmm24
        jl	L_AES_CBC_decrypt_avx512_256_aes_dec_block_last
        vaesdec	zmm0, zmm0, zmm24
        vaesdec	zmm1, zmm1, zmm24
        vaesdec	zmm2, zmm2, zmm24
        vaesdec	zmm3, zmm3, zmm24
        vaesdec	zmm0, zmm0, zmm25
        vaesdec	zmm1, zmm1, zmm25
        vaesdec	zmm2, zmm2, zmm25
        vaesdec	zmm3, zmm3, zmm25
        cmp	r10d, 13
        vmovdqa64	zmm9, zmm26
        jl	L_AES_CBC_decrypt_avx512_256_aes_dec_block_last
        vaesdec	zmm0, zmm0, zmm26
        vaesdec	zmm1, zmm1, zmm26
        vaesdec	zmm2, zmm2, zmm26
        vaesdec	zmm3, zmm3, zmm26
        vaesdec	zmm0, zmm0, zmm27
        vaesdec	zmm1, zmm1, zmm27
        vaesdec	zmm2, zmm2, zmm27
        vaesdec	zmm3, zmm3, zmm27
        vmovdqa64	zmm9, zmm28
L_AES_CBC_decrypt_avx512_256_aes_dec_block_last:
        vaesdeclast	zmm0, zmm0, zmm9
        vaesdeclast	zmm1, zmm1, zmm9
        vaesdeclast	zmm2, zmm2, zmm9
        vaesdeclast	zmm3, zmm3, zmm9
        vpxorq	zmm0, zmm0, zmm10
        vpxorq	zmm1, zmm1, zmm11
        vpxorq	zmm2, zmm2, zmm12
        vpxorq	zmm3, zmm3, zmm13
        vmovdqu64	[r12], zmm0
        vmovdqu64	[r12+64], zmm1
        vmovdqu64	[r12+128], zmm2
        vmovdqu64	[r12+192], zmm3
        add	eax, 256
        cmp	eax, r10d
        jl	L_AES_CBC_decrypt_avx512_dec_256
L_AES_CBC_decrypt_avx512_done_256:
        mov	r10d, r9d
        sub	r10d, eax
        cmp	r10d, 128
        jl	L_AES_CBC_decrypt_avx512_done_128
        ; 128 bytes of input
        ; aes_cbc_dec_128
        lea	r11, QWORD PTR [rcx+rax]
        lea	r12, QWORD PTR [rdx+rax]
        vmovdqu64	zmm0, [r11]
        vmovdqu64	zmm1, [r11+64]
        vshufi64x2	zmm10, zmm0, zmm0, 144
        vinserti32x4	zmm10, zmm10, xmm8, 0
        vmovdqu64	zmm11, [r11+48]
        vextracti32x4	xmm8, zmm1, 3
        ; aes_dec_block
        vpxorq	zmm0, zmm0, zmm14
        vpxorq	zmm1, zmm1, zmm14
        vaesdec	zmm0, zmm0, zmm15
        vaesdec	zmm1, zmm1, zmm15
        vaesdec	zmm0, zmm0, zmm16
        vaesdec	zmm1, zmm1, zmm16
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
        cmp	r10d, 11
        vmovdqa64	zmm9, zmm24
        jl	L_AES_CBC_decrypt_avx512_128_aes_dec_block_last
        vaesdec	zmm0, zmm0, zmm24
        vaesdec	zmm1, zmm1, zmm24
        vaesdec	zmm0, zmm0, zmm25
        vaesdec	zmm1, zmm1, zmm25
        cmp	r10d, 13
        vmovdqa64	zmm9, zmm26
        jl	L_AES_CBC_decrypt_avx512_128_aes_dec_block_last
        vaesdec	zmm0, zmm0, zmm26
        vaesdec	zmm1, zmm1, zmm26
        vaesdec	zmm0, zmm0, zmm27
        vaesdec	zmm1, zmm1, zmm27
        vmovdqa64	zmm9, zmm28
L_AES_CBC_decrypt_avx512_128_aes_dec_block_last:
        vaesdeclast	zmm0, zmm0, zmm9
        vaesdeclast	zmm1, zmm1, zmm9
        vpxorq	zmm0, zmm0, zmm10
        vpxorq	zmm1, zmm1, zmm11
        vmovdqu64	[r12], zmm0
        vmovdqu64	[r12+64], zmm1
        add	eax, 128
L_AES_CBC_decrypt_avx512_done_128:
        mov	r10d, r9d
        and	r10d, 4294967232
        cmp	eax, r10d
        je	L_AES_CBC_decrypt_avx512_done_64
L_AES_CBC_decrypt_avx512_dec_64:
        ; 64 bytes of input
        ; aes_cbc_dec_64
        lea	r11, QWORD PTR [rcx+rax]
        lea	r12, QWORD PTR [rdx+rax]
        vmovdqu64	zmm0, [r11]
        vshufi64x2	zmm10, zmm0, zmm0, 144
        vinserti32x4	zmm10, zmm10, xmm8, 0
        vextracti32x4	xmm8, zmm0, 3
        ; aes_dec_block
        vpxorq	zmm0, zmm0, zmm14
        vaesdec	zmm0, zmm0, zmm15
        vaesdec	zmm0, zmm0, zmm16
        vaesdec	zmm0, zmm0, zmm17
        vaesdec	zmm0, zmm0, zmm18
        vaesdec	zmm0, zmm0, zmm19
        vaesdec	zmm0, zmm0, zmm20
        vaesdec	zmm0, zmm0, zmm21
        vaesdec	zmm0, zmm0, zmm22
        vaesdec	zmm0, zmm0, zmm23
        cmp	r10d, 11
        vmovdqa64	zmm9, zmm24
        jl	L_AES_CBC_decrypt_avx512_64_aes_dec_block_last
        vaesdec	zmm0, zmm0, zmm24
        vaesdec	zmm0, zmm0, zmm25
        cmp	r10d, 13
        vmovdqa64	zmm9, zmm26
        jl	L_AES_CBC_decrypt_avx512_64_aes_dec_block_last
        vaesdec	zmm0, zmm0, zmm26
        vaesdec	zmm0, zmm0, zmm27
        vmovdqa64	zmm9, zmm28
L_AES_CBC_decrypt_avx512_64_aes_dec_block_last:
        vaesdeclast	zmm0, zmm0, zmm9
        vpxorq	zmm0, zmm0, zmm10
        vmovdqu64	[r12], zmm0
        add	eax, 64
        cmp	eax, r10d
        jl	L_AES_CBC_decrypt_avx512_dec_64
L_AES_CBC_decrypt_avx512_done_64:
        mov	r10d, r9d
        sub	r10d, eax
        cmp	r10d, 32
        jl	L_AES_CBC_decrypt_avx512_done_32
        ; 32 bytes of input
        lea	r11, QWORD PTR [rcx+rax]
        vmovdqu	ymm0, YMMWORD PTR [r11]
        vinserti128	ymm10, ymm8, xmm0, 1
        vextracti128	xmm8, ymm0, 1
        ; aes_dec_block
        vpxorq	ymm0, ymm0, ymm14
        vaesdec	ymm0, ymm0, ymm15
        vaesdec	ymm0, ymm0, ymm16
        vaesdec	ymm0, ymm0, ymm17
        vaesdec	ymm0, ymm0, ymm18
        vaesdec	ymm0, ymm0, ymm19
        vaesdec	ymm0, ymm0, ymm20
        vaesdec	ymm0, ymm0, ymm21
        vaesdec	ymm0, ymm0, ymm22
        vaesdec	ymm0, ymm0, ymm23
        cmp	r10d, 11
        vmovdqa64	ymm9, ymm24
        jl	L_AES_CBC_decrypt_avx512_32_aes_dec_block_last
        vaesdec	ymm0, ymm0, ymm24
        vaesdec	ymm0, ymm0, ymm25
        cmp	r10d, 13
        vmovdqa64	ymm9, ymm26
        jl	L_AES_CBC_decrypt_avx512_32_aes_dec_block_last
        vaesdec	ymm0, ymm0, ymm26
        vaesdec	ymm0, ymm0, ymm27
        vmovdqa64	ymm9, ymm28
L_AES_CBC_decrypt_avx512_32_aes_dec_block_last:
        vaesdeclast	ymm0, ymm0, ymm9
        vpxorq	ymm0, ymm0, ymm10
        lea	r11, QWORD PTR [rdx+rax]
        vmovdqu	YMMWORD PTR [r11], ymm0
        add	eax, 32
L_AES_CBC_decrypt_avx512_done_32:
        cmp	eax, r9d
        mov	r10d, r9d
        je	L_AES_CBC_decrypt_avx512_done_dec
        and	r10d, 4294967280
L_AES_CBC_decrypt_avx512_dec_16:
        ; 16 bytes of input
        lea	r11, QWORD PTR [rcx+rax]
        vmovdqu	xmm0, OWORD PTR [r11]
        vmovdqa	xmm7, xmm0
        ; aes_dec_block
        vpxor	xmm0, xmm0, [rax]
        vmovdqu	xmm5, OWORD PTR [rax+16]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [rax+32]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [rax+48]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [rax+64]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [rax+80]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [rax+96]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [rax+112]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [rax+128]
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm5, OWORD PTR [rax+144]
        vaesdec	xmm0, xmm0, xmm5
        cmp	r10d, 11
        vmovdqu	xmm5, OWORD PTR [rax+160]
        jl	L_AES_CBC_decrypt_avx512_16_aes_dec_block_last
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [rax+176]
        vaesdec	xmm0, xmm0, xmm6
        cmp	r10d, 13
        vmovdqu	xmm5, OWORD PTR [rax+192]
        jl	L_AES_CBC_decrypt_avx512_16_aes_dec_block_last
        vaesdec	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [rax+208]
        vaesdec	xmm0, xmm0, xmm6
        vmovdqu	xmm5, OWORD PTR [rax+224]
L_AES_CBC_decrypt_avx512_16_aes_dec_block_last:
        vaesdeclast	xmm0, xmm0, xmm5
        vpxor	xmm0, xmm0, xmm8
        vmovdqa	xmm8, xmm7
        lea	r11, QWORD PTR [rdx+rax]
        vmovdqu	OWORD PTR [r11], xmm0
        add	eax, 16
        cmp	eax, r10d
        jl	L_AES_CBC_decrypt_avx512_dec_16
L_AES_CBC_decrypt_avx512_done_dec:
        vmovdqu	OWORD PTR [r8], xmm8
        vmovdqu	xmm6, OWORD PTR [rsp]
        vmovdqu	xmm7, OWORD PTR [rsp+16]
        vmovdqu	xmm8, OWORD PTR [rsp+32]
        vmovdqu	xmm9, OWORD PTR [rsp+48]
        vmovdqu	xmm10, OWORD PTR [rsp+64]
        vmovdqu	xmm11, OWORD PTR [rsp+80]
        vmovdqu	xmm12, OWORD PTR [rsp+96]
        vmovdqu	xmm13, OWORD PTR [rsp+112]
        vmovdqu	xmm14, OWORD PTR [rsp+128]
        vmovdqu	xmm15, OWORD PTR [rsp+144]
        add	rsp, 160
        pop	r12
        ret
AES_CBC_decrypt_avx512 ENDP
_TEXT ENDS
_DATA SEGMENT
ALIGN 16
L_aes_ctr_bswap_avx512 QWORD \
     08090a0b0c0d0e0fh,  0001020304050607h
ptr_L_aes_ctr_bswap_avx512 QWORD L_aes_ctr_bswap_avx512
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_aes_ctr_inc_avx512 QWORD \
     0000000000000000h,  0000000000000000h,
     0000000000000001h,  0000000000000000h,
     0000000000000002h,  0000000000000000h,
     0000000000000003h,  0000000000000000h,
     0000000000000004h,  0000000000000000h,
     0000000000000005h,  0000000000000000h,
     0000000000000006h,  0000000000000000h,
     0000000000000007h,  0000000000000000h,
     0000000000000008h,  0000000000000000h,
     0000000000000009h,  0000000000000000h,
     000000000000000ah,  0000000000000000h,
     000000000000000bh,  0000000000000000h,
     000000000000000ch,  0000000000000000h,
     000000000000000dh,  0000000000000000h,
     000000000000000eh,  0000000000000000h,
     000000000000000fh,  0000000000000000h,
     0000000000000010h,  0000000000000000h
ptr_L_aes_ctr_inc_avx512 QWORD L_aes_ctr_inc_avx512
_DATA ENDS
_TEXT SEGMENT READONLY PARA
AES_CTR_encrypt_avx512 PROC
        push	rbx
        mov	eax, DWORD PTR [rsp+48]
        mov	r10, QWORD PTR [rsp+56]
        sub	rsp, 160
        vmovdqu	OWORD PTR [rsp], xmm6
        vmovdqu	OWORD PTR [rsp+16], xmm7
        vmovdqu	OWORD PTR [rsp+32], xmm8
        vmovdqu	OWORD PTR [rsp+48], xmm9
        vmovdqu	OWORD PTR [rsp+64], xmm10
        vmovdqu	OWORD PTR [rsp+80], xmm11
        vmovdqu	OWORD PTR [rsp+96], xmm12
        vmovdqu	OWORD PTR [rsp+112], xmm13
        vmovdqu	OWORD PTR [rsp+128], xmm14
        vmovdqu	OWORD PTR [rsp+144], xmm15
        vbroadcasti32x4	zmm8, ptr_L_aes_ctr_bswap_avx512
        vbroadcasti32x4	zmm7, [r10]
        vpshufb	zmm7, zmm7, zmm8
        vbroadcasti32x4	zmm12, [ptr_L_aes_ctr_inc_avx512+64]
        vbroadcasti32x4	zmm13, [ptr_L_aes_ctr_inc_avx512+16]
        xor	eax, eax
        cmp	r8d, 32
        jl	L_AES_CTR_encrypt_avx512_done_32
        vbroadcasti32x4	zmm15, [r9]
        vbroadcasti32x4	zmm16, [r9+16]
        vbroadcasti32x4	zmm17, [r9+32]
        vbroadcasti32x4	zmm18, [r9+48]
        vbroadcasti32x4	zmm19, [r9+64]
        vbroadcasti32x4	zmm20, [r9+80]
        vbroadcasti32x4	zmm21, [r9+96]
        vbroadcasti32x4	zmm22, [r9+112]
        vbroadcasti32x4	zmm23, [r9+128]
        vbroadcasti32x4	zmm24, [r9+144]
        vbroadcasti32x4	zmm25, [r9+160]
        cmp	eax, 11
        jl	L_AES_CTR_encrypt_avx512_key_cached
        vbroadcasti32x4	zmm26, [r9+176]
        vbroadcasti32x4	zmm27, [r9+192]
        cmp	eax, 13
        jl	L_AES_CTR_encrypt_avx512_key_cached
        vbroadcasti32x4	zmm28, [r9+208]
        vbroadcasti32x4	zmm29, [r9+224]
L_AES_CTR_encrypt_avx512_key_cached:
        cmp	r8d, 256
        mov	r10d, r8d
        jl	L_AES_CTR_encrypt_avx512_done_256
        and	r10d, 4294967040
        vbroadcasti32x4	zmm10, [ptr_L_aes_ctr_inc_avx512+256]
        vmovdqa64	zmm9, zmm7
        vpaddq	zmm4, zmm7, [ptr_L_aes_ctr_inc_avx512]
        vpternlogq	zmm9, zmm4, [ptr_L_aes_ctr_inc_avx512], 178
        vpsrlq	zmm9, zmm9, 63
        vpslldq	zmm9, zmm9, 8
        vpaddq	zmm4, zmm4, zmm9
        vmovdqa64	zmm9, zmm7
        vpaddq	zmm5, zmm7, [ptr_L_aes_ctr_inc_avx512+64]
        vpternlogq	zmm9, zmm5, [ptr_L_aes_ctr_inc_avx512+64], 178
        vpsrlq	zmm9, zmm9, 63
        vpslldq	zmm9, zmm9, 8
        vpaddq	zmm5, zmm5, zmm9
        vmovdqa64	zmm9, zmm7
        vpaddq	zmm6, zmm7, [ptr_L_aes_ctr_inc_avx512+128]
        vpternlogq	zmm9, zmm6, [ptr_L_aes_ctr_inc_avx512+128], 178
        vpsrlq	zmm9, zmm9, 63
        vpslldq	zmm9, zmm9, 8
        vpaddq	zmm6, zmm6, zmm9
        vmovdqa64	zmm9, zmm7
        vpaddq	zmm7, zmm7, [ptr_L_aes_ctr_inc_avx512+192]
        vpternlogq	zmm9, zmm7, [ptr_L_aes_ctr_inc_avx512+192], 178
        vpsrlq	zmm9, zmm9, 63
        vpslldq	zmm9, zmm9, 8
        vpaddq	zmm7, zmm7, zmm9
L_AES_CTR_encrypt_avx512_enc_256:
        ; 256 bytes of input
        lea	r11, QWORD PTR [rcx+rax]
        lea	rbx, QWORD PTR [rdx+rax]
        vpshufb	zmm0, zmm4, zmm8
        vpshufb	zmm1, zmm5, zmm8
        vpshufb	zmm2, zmm6, zmm8
        vpshufb	zmm3, zmm7, zmm8
        vmovdqa64	zmm9, zmm4
        vpaddq	zmm4, zmm4, zmm10
        vpternlogq	zmm9, zmm4, zmm10, 178
        vpsrlq	zmm9, zmm9, 63
        vpslldq	zmm9, zmm9, 8
        vpaddq	zmm4, zmm4, zmm9
        vmovdqa64	zmm9, zmm5
        vpaddq	zmm5, zmm5, zmm10
        vpternlogq	zmm9, zmm5, zmm10, 178
        vpsrlq	zmm9, zmm9, 63
        vpslldq	zmm9, zmm9, 8
        vpaddq	zmm5, zmm5, zmm9
        vmovdqa64	zmm9, zmm6
        vpaddq	zmm6, zmm6, zmm10
        vpternlogq	zmm9, zmm6, zmm10, 178
        vpsrlq	zmm9, zmm9, 63
        vpslldq	zmm9, zmm9, 8
        vpaddq	zmm6, zmm6, zmm9
        vmovdqa64	zmm9, zmm7
        vpaddq	zmm7, zmm7, zmm10
        vpternlogq	zmm9, zmm7, zmm10, 178
        vpsrlq	zmm9, zmm9, 63
        vpslldq	zmm9, zmm9, 8
        vpaddq	zmm7, zmm7, zmm9
        ; aes_enc_block
        vpxorq	zmm0, zmm0, zmm15
        vpxorq	zmm1, zmm1, zmm15
        vpxorq	zmm2, zmm2, zmm15
        vpxorq	zmm3, zmm3, zmm15
        vaesenc	zmm0, zmm0, zmm16
        vaesenc	zmm1, zmm1, zmm16
        vaesenc	zmm2, zmm2, zmm16
        vaesenc	zmm3, zmm3, zmm16
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
        cmp	eax, 11
        vmovdqa64	zmm14, zmm25
        jl	L_AES_CTR_encrypt_avx512_256_aes_enc_block_last
        vaesenc	zmm0, zmm0, zmm25
        vaesenc	zmm1, zmm1, zmm25
        vaesenc	zmm2, zmm2, zmm25
        vaesenc	zmm3, zmm3, zmm25
        vaesenc	zmm0, zmm0, zmm26
        vaesenc	zmm1, zmm1, zmm26
        vaesenc	zmm2, zmm2, zmm26
        vaesenc	zmm3, zmm3, zmm26
        cmp	eax, 13
        vmovdqa64	zmm14, zmm27
        jl	L_AES_CTR_encrypt_avx512_256_aes_enc_block_last
        vaesenc	zmm0, zmm0, zmm27
        vaesenc	zmm1, zmm1, zmm27
        vaesenc	zmm2, zmm2, zmm27
        vaesenc	zmm3, zmm3, zmm27
        vaesenc	zmm0, zmm0, zmm28
        vaesenc	zmm1, zmm1, zmm28
        vaesenc	zmm2, zmm2, zmm28
        vaesenc	zmm3, zmm3, zmm28
        vmovdqa64	zmm14, zmm29
L_AES_CTR_encrypt_avx512_256_aes_enc_block_last:
        vaesenclast	zmm0, zmm0, zmm14
        vaesenclast	zmm1, zmm1, zmm14
        vaesenclast	zmm2, zmm2, zmm14
        vaesenclast	zmm3, zmm3, zmm14
        vpxorq	zmm0, zmm0, [r11]
        vpxorq	zmm1, zmm1, [r11+64]
        vpxorq	zmm2, zmm2, [r11+128]
        vpxorq	zmm3, zmm3, [r11+192]
        vmovdqu64	[rbx], zmm0
        vmovdqu64	[rbx+64], zmm1
        vmovdqu64	[rbx+128], zmm2
        vmovdqu64	[rbx+192], zmm3
        add	eax, 256
        cmp	eax, r10d
        jl	L_AES_CTR_encrypt_avx512_enc_256
        vshufi64x2	zmm7, zmm4, zmm4, 0
L_AES_CTR_encrypt_avx512_done_256:
        mov	r10d, r8d
        sub	r10d, eax
        cmp	r10d, 128
        jl	L_AES_CTR_encrypt_avx512_done_128
        ; 128 bytes of input
        vbroadcasti32x4	zmm11, [ptr_L_aes_ctr_inc_avx512+128]
        ; aes_ctr_enc_128
        lea	r11, QWORD PTR [rcx+rax]
        lea	rbx, QWORD PTR [rdx+rax]
        vpaddq	zmm0, zmm7, [ptr_L_aes_ctr_inc_avx512]
        vmovdqa64	zmm9, zmm7
        vpternlogq	zmm9, zmm0, [ptr_L_aes_ctr_inc_avx512], 178
        vpsrlq	zmm9, zmm9, 63
        vpslldq	zmm9, zmm9, 8
        vpaddq	zmm0, zmm0, zmm9
        vpshufb	zmm0, zmm0, zmm8
        vpaddq	zmm1, zmm7, [ptr_L_aes_ctr_inc_avx512+64]
        vmovdqa64	zmm9, zmm7
        vpternlogq	zmm9, zmm1, [ptr_L_aes_ctr_inc_avx512+64], 178
        vpsrlq	zmm9, zmm9, 63
        vpslldq	zmm9, zmm9, 8
        vpaddq	zmm1, zmm1, zmm9
        vpshufb	zmm1, zmm1, zmm8
        vmovdqa64	zmm9, zmm7
        vpaddq	zmm7, zmm7, zmm11
        vpternlogq	zmm9, zmm7, zmm11, 178
        vpsrlq	zmm9, zmm9, 63
        vpslldq	zmm9, zmm9, 8
        vpaddq	zmm7, zmm7, zmm9
        ; aes_enc_block
        vpxorq	zmm0, zmm0, zmm15
        vpxorq	zmm1, zmm1, zmm15
        vaesenc	zmm0, zmm0, zmm16
        vaesenc	zmm1, zmm1, zmm16
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
        cmp	eax, 11
        vmovdqa64	zmm14, zmm25
        jl	L_AES_CTR_encrypt_avx512_128_aes_enc_block_last
        vaesenc	zmm0, zmm0, zmm25
        vaesenc	zmm1, zmm1, zmm25
        vaesenc	zmm0, zmm0, zmm26
        vaesenc	zmm1, zmm1, zmm26
        cmp	eax, 13
        vmovdqa64	zmm14, zmm27
        jl	L_AES_CTR_encrypt_avx512_128_aes_enc_block_last
        vaesenc	zmm0, zmm0, zmm27
        vaesenc	zmm1, zmm1, zmm27
        vaesenc	zmm0, zmm0, zmm28
        vaesenc	zmm1, zmm1, zmm28
        vmovdqa64	zmm14, zmm29
L_AES_CTR_encrypt_avx512_128_aes_enc_block_last:
        vaesenclast	zmm0, zmm0, zmm14
        vaesenclast	zmm1, zmm1, zmm14
        vpxorq	zmm0, zmm0, [r11]
        vpxorq	zmm1, zmm1, [r11+64]
        vmovdqu64	[rbx], zmm0
        vmovdqu64	[rbx+64], zmm1
        add	eax, 128
L_AES_CTR_encrypt_avx512_done_128:
        mov	r10d, r8d
        and	r10d, 4294967232
        cmp	eax, r10d
        je	L_AES_CTR_encrypt_avx512_done_64
L_AES_CTR_encrypt_avx512_enc_64:
        ; 64 bytes of input
        ; aes_ctr_enc_64
        lea	r11, QWORD PTR [rcx+rax]
        lea	rbx, QWORD PTR [rdx+rax]
        vpaddq	zmm0, zmm7, [ptr_L_aes_ctr_inc_avx512]
        vmovdqa64	zmm9, zmm7
        vpternlogq	zmm9, zmm0, [ptr_L_aes_ctr_inc_avx512], 178
        vpsrlq	zmm9, zmm9, 63
        vpslldq	zmm9, zmm9, 8
        vpaddq	zmm0, zmm0, zmm9
        vpshufb	zmm0, zmm0, zmm8
        vmovdqa64	zmm9, zmm7
        vpaddq	zmm7, zmm7, zmm12
        vpternlogq	zmm9, zmm7, zmm12, 178
        vpsrlq	zmm9, zmm9, 63
        vpslldq	zmm9, zmm9, 8
        vpaddq	zmm7, zmm7, zmm9
        ; aes_enc_block
        vpxorq	zmm0, zmm0, zmm15
        vaesenc	zmm0, zmm0, zmm16
        vaesenc	zmm0, zmm0, zmm17
        vaesenc	zmm0, zmm0, zmm18
        vaesenc	zmm0, zmm0, zmm19
        vaesenc	zmm0, zmm0, zmm20
        vaesenc	zmm0, zmm0, zmm21
        vaesenc	zmm0, zmm0, zmm22
        vaesenc	zmm0, zmm0, zmm23
        vaesenc	zmm0, zmm0, zmm24
        cmp	eax, 11
        vmovdqa64	zmm14, zmm25
        jl	L_AES_CTR_encrypt_avx512_64_aes_enc_block_last
        vaesenc	zmm0, zmm0, zmm25
        vaesenc	zmm0, zmm0, zmm26
        cmp	eax, 13
        vmovdqa64	zmm14, zmm27
        jl	L_AES_CTR_encrypt_avx512_64_aes_enc_block_last
        vaesenc	zmm0, zmm0, zmm27
        vaesenc	zmm0, zmm0, zmm28
        vmovdqa64	zmm14, zmm29
L_AES_CTR_encrypt_avx512_64_aes_enc_block_last:
        vaesenclast	zmm0, zmm0, zmm14
        vpxorq	zmm0, zmm0, [r11]
        vmovdqu64	[rbx], zmm0
        add	eax, 64
        cmp	eax, r10d
        jl	L_AES_CTR_encrypt_avx512_enc_64
L_AES_CTR_encrypt_avx512_done_64:
        mov	r10d, r8d
        sub	r10d, eax
        cmp	r10d, 32
        jl	L_AES_CTR_encrypt_avx512_done_32
        ; 32 bytes of input
        vbroadcasti32x4	zmm4, [ptr_L_aes_ctr_inc_avx512+32]
        vpaddq	ymm0, ymm7, [ptr_L_aes_ctr_inc_avx512]
        vmovdqa64	ymm9, ymm7
        vpternlogq	ymm9, ymm0, [ptr_L_aes_ctr_inc_avx512], 178
        vpsrlq	ymm9, ymm9, 63
        vpslldq	ymm9, ymm9, 8
        vpaddq	ymm0, ymm0, ymm9
        vpshufb	ymm0, ymm0, ymm8
        vmovdqa64	zmm9, zmm7
        vpaddq	zmm7, zmm7, zmm4
        vpternlogq	zmm9, zmm7, zmm4, 178
        vpsrlq	zmm9, zmm9, 63
        vpslldq	zmm9, zmm9, 8
        vpaddq	zmm7, zmm7, zmm9
        ; aes_enc_block
        vpxorq	ymm0, ymm0, ymm15
        vaesenc	ymm0, ymm0, ymm16
        vaesenc	ymm0, ymm0, ymm17
        vaesenc	ymm0, ymm0, ymm18
        vaesenc	ymm0, ymm0, ymm19
        vaesenc	ymm0, ymm0, ymm20
        vaesenc	ymm0, ymm0, ymm21
        vaesenc	ymm0, ymm0, ymm22
        vaesenc	ymm0, ymm0, ymm23
        vaesenc	ymm0, ymm0, ymm24
        cmp	eax, 11
        vmovdqa64	ymm14, ymm25
        jl	L_AES_CTR_encrypt_avx512_32_aes_enc_block_last
        vaesenc	ymm0, ymm0, ymm25
        vaesenc	ymm0, ymm0, ymm26
        cmp	eax, 13
        vmovdqa64	ymm14, ymm27
        jl	L_AES_CTR_encrypt_avx512_32_aes_enc_block_last
        vaesenc	ymm0, ymm0, ymm27
        vaesenc	ymm0, ymm0, ymm28
        vmovdqa64	ymm14, ymm29
L_AES_CTR_encrypt_avx512_32_aes_enc_block_last:
        vaesenclast	ymm0, ymm0, ymm14
        lea	r11, QWORD PTR [rcx+rax]
        vpxorq	ymm0, ymm0, [r11]
        lea	r11, QWORD PTR [rdx+rax]
        vmovdqu	YMMWORD PTR [r11], ymm0
        add	eax, 32
L_AES_CTR_encrypt_avx512_done_32:
        cmp	eax, r8d
        mov	r10d, r8d
        je	L_AES_CTR_encrypt_avx512_done_enc
        and	r10d, 4294967280
L_AES_CTR_encrypt_avx512_enc_16:
        ; 16 bytes of input
        vpshufb	xmm0, xmm7, xmm8
        vmovdqa64	zmm9, zmm7
        vpaddq	zmm7, zmm7, zmm13
        vpternlogq	zmm9, zmm7, zmm13, 178
        vpsrlq	zmm9, zmm9, 63
        vpslldq	zmm9, zmm9, 8
        vpaddq	zmm7, zmm7, zmm9
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
        cmp	eax, 11
        vmovdqu	xmm5, OWORD PTR [r9+160]
        jl	L_AES_CTR_encrypt_avx512_16_aes_enc_block_last
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r9+176]
        vaesenc	xmm0, xmm0, xmm6
        cmp	eax, 13
        vmovdqu	xmm5, OWORD PTR [r9+192]
        jl	L_AES_CTR_encrypt_avx512_16_aes_enc_block_last
        vaesenc	xmm0, xmm0, xmm5
        vmovdqu	xmm6, OWORD PTR [r9+208]
        vaesenc	xmm0, xmm0, xmm6
        vmovdqu	xmm5, OWORD PTR [r9+224]
L_AES_CTR_encrypt_avx512_16_aes_enc_block_last:
        vaesenclast	xmm0, xmm0, xmm5
        lea	r11, QWORD PTR [rcx+rax]
        vpxor	xmm0, xmm0, [r11]
        lea	r11, QWORD PTR [rdx+rax]
        vmovdqu	OWORD PTR [r11], xmm0
        add	eax, 16
        cmp	eax, r10d
        jl	L_AES_CTR_encrypt_avx512_enc_16
L_AES_CTR_encrypt_avx512_done_enc:
        vpshufb	xmm0, xmm7, xmm8
        vmovdqu	OWORD PTR [r10], xmm0
        vmovdqu	xmm6, OWORD PTR [rsp]
        vmovdqu	xmm7, OWORD PTR [rsp+16]
        vmovdqu	xmm8, OWORD PTR [rsp+32]
        vmovdqu	xmm9, OWORD PTR [rsp+48]
        vmovdqu	xmm10, OWORD PTR [rsp+64]
        vmovdqu	xmm11, OWORD PTR [rsp+80]
        vmovdqu	xmm12, OWORD PTR [rsp+96]
        vmovdqu	xmm13, OWORD PTR [rsp+112]
        vmovdqu	xmm14, OWORD PTR [rsp+128]
        vmovdqu	xmm15, OWORD PTR [rsp+144]
        add	rsp, 160
        pop	rbx
        ret
AES_CTR_encrypt_avx512 ENDP
_TEXT ENDS
ENDIF
END
