; /* chacha_asm.asm */
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
chacha_encrypt_x64 PROC
        push	rbx
        push	rbp
        push	r12
        push	r13
        push	r14
        push	r15
        sub	rsp, 64
        cmp	r9d, 64
        jl	L_chacha_x64_small
L_chacha_x64_start:
        sub	rsp, 48
        mov	QWORD PTR [rsp+24], r8
        mov	QWORD PTR [rsp+32], rdx
        mov	QWORD PTR [rsp+40], r9
        mov	rax, QWORD PTR [rcx+32]
        mov	rbx, QWORD PTR [rcx+40]
        mov	QWORD PTR [rsp+8], rax
        mov	QWORD PTR [rsp+16], rbx
        mov	eax, DWORD PTR [rcx]
        mov	ebx, DWORD PTR [rcx+4]
        mov	r9d, DWORD PTR [rcx+8]
        mov	r8d, DWORD PTR [rcx+12]
        mov	r8d, DWORD PTR [rcx+16]
        mov	r9d, DWORD PTR [rcx+20]
        mov	r10d, DWORD PTR [rcx+24]
        mov	r11d, DWORD PTR [rcx+28]
        mov	r12d, DWORD PTR [rcx+48]
        mov	r13d, DWORD PTR [rcx+52]
        mov	r14d, DWORD PTR [rcx+56]
        mov	r15d, DWORD PTR [rcx+60]
        mov	BYTE PTR [rsp], 10
L_chacha_x64_block_crypt_start:
        add	eax, r8d
        add	ebx, r9d
        add	r9d, r10d
        add	r8d, r11d
        xor	r12d, eax
        xor	r13d, ebx
        xor	r14d, r9d
        xor	r15d, r8d
        rol	r12d, 16
        rol	r13d, 16
        rol	r14d, 16
        rol	r15d, 16
        add	DWORD PTR [rsp+8], r12d
        add	DWORD PTR [rsp+12], r13d
        add	DWORD PTR [rsp+16], r14d
        add	DWORD PTR [rsp+20], r15d
        xor	r8d, DWORD PTR [rsp+8]
        xor	r9d, DWORD PTR [rsp+12]
        xor	r10d, DWORD PTR [rsp+16]
        xor	r11d, DWORD PTR [rsp+20]
        rol	r8d, 12
        rol	r9d, 12
        rol	r10d, 12
        rol	r11d, 12
        add	eax, r8d
        add	ebx, r9d
        add	r9d, r10d
        add	r8d, r11d
        xor	r12d, eax
        xor	r13d, ebx
        xor	r14d, r9d
        xor	r15d, r8d
        rol	r12d, 8
        rol	r13d, 8
        rol	r14d, 8
        rol	r15d, 8
        add	DWORD PTR [rsp+8], r12d
        add	DWORD PTR [rsp+12], r13d
        add	DWORD PTR [rsp+16], r14d
        add	DWORD PTR [rsp+20], r15d
        xor	r8d, DWORD PTR [rsp+8]
        xor	r9d, DWORD PTR [rsp+12]
        xor	r10d, DWORD PTR [rsp+16]
        xor	r11d, DWORD PTR [rsp+20]
        rol	r8d, 7
        rol	r9d, 7
        rol	r10d, 7
        rol	r11d, 7
        add	eax, r9d
        add	ebx, r10d
        add	r9d, r11d
        add	r8d, r8d
        xor	r15d, eax
        xor	r12d, ebx
        xor	r13d, r9d
        xor	r14d, r8d
        rol	r15d, 16
        rol	r12d, 16
        rol	r13d, 16
        rol	r14d, 16
        add	DWORD PTR [rsp+16], r15d
        add	DWORD PTR [rsp+20], r12d
        add	DWORD PTR [rsp+8], r13d
        add	DWORD PTR [rsp+12], r14d
        xor	r9d, DWORD PTR [rsp+16]
        xor	r10d, DWORD PTR [rsp+20]
        xor	r11d, DWORD PTR [rsp+8]
        xor	r8d, DWORD PTR [rsp+12]
        rol	r9d, 12
        rol	r10d, 12
        rol	r11d, 12
        rol	r8d, 12
        add	eax, r9d
        add	ebx, r10d
        add	r9d, r11d
        add	r8d, r8d
        xor	r15d, eax
        xor	r12d, ebx
        xor	r13d, r9d
        xor	r14d, r8d
        rol	r15d, 8
        rol	r12d, 8
        rol	r13d, 8
        rol	r14d, 8
        add	DWORD PTR [rsp+16], r15d
        add	DWORD PTR [rsp+20], r12d
        add	DWORD PTR [rsp+8], r13d
        add	DWORD PTR [rsp+12], r14d
        xor	r9d, DWORD PTR [rsp+16]
        xor	r10d, DWORD PTR [rsp+20]
        xor	r11d, DWORD PTR [rsp+8]
        xor	r8d, DWORD PTR [rsp+12]
        rol	r9d, 7
        rol	r10d, 7
        rol	r11d, 7
        rol	r8d, 7
        dec	BYTE PTR [rsp]
        jnz	L_chacha_x64_block_crypt_start
        mov	rdx, QWORD PTR [rsp+32]
        mov	rbp, QWORD PTR [rsp+24]
        add	eax, DWORD PTR [rcx]
        add	ebx, DWORD PTR [rcx+4]
        add	r9d, DWORD PTR [rcx+8]
        add	r8d, DWORD PTR [rcx+12]
        add	r8d, DWORD PTR [rcx+16]
        add	r9d, DWORD PTR [rcx+20]
        add	r10d, DWORD PTR [rcx+24]
        add	r11d, DWORD PTR [rcx+28]
        add	r12d, DWORD PTR [rcx+48]
        add	r13d, DWORD PTR [rcx+52]
        add	r14d, DWORD PTR [rcx+56]
        add	r15d, DWORD PTR [rcx+60]
        xor	eax, DWORD PTR [rdx]
        xor	ebx, DWORD PTR [rdx+4]
        xor	r9d, DWORD PTR [rdx+8]
        xor	r8d, DWORD PTR [rdx+12]
        xor	r8d, DWORD PTR [rdx+16]
        xor	r9d, DWORD PTR [rdx+20]
        xor	r10d, DWORD PTR [rdx+24]
        xor	r11d, DWORD PTR [rdx+28]
        xor	r12d, DWORD PTR [rdx+48]
        xor	r13d, DWORD PTR [rdx+52]
        xor	r14d, DWORD PTR [rdx+56]
        xor	r15d, DWORD PTR [rdx+60]
        mov	DWORD PTR [rbp], eax
        mov	DWORD PTR [rbp+4], ebx
        mov	DWORD PTR [rbp+8], r9d
        mov	DWORD PTR [rbp+12], r8d
        mov	DWORD PTR [rbp+16], r8d
        mov	DWORD PTR [rbp+20], r9d
        mov	DWORD PTR [rbp+24], r10d
        mov	DWORD PTR [rbp+28], r11d
        mov	DWORD PTR [rbp+48], r12d
        mov	DWORD PTR [rbp+52], r13d
        mov	DWORD PTR [rbp+56], r14d
        mov	DWORD PTR [rbp+60], r15d
        mov	eax, DWORD PTR [rsp+8]
        mov	ebx, DWORD PTR [rsp+12]
        mov	r9d, DWORD PTR [rsp+16]
        mov	r8d, DWORD PTR [rsp+20]
        add	eax, DWORD PTR [rcx+32]
        add	ebx, DWORD PTR [rcx+36]
        add	r9d, DWORD PTR [rcx+40]
        add	r8d, DWORD PTR [rcx+44]
        xor	eax, DWORD PTR [rdx+32]
        xor	ebx, DWORD PTR [rdx+36]
        xor	r9d, DWORD PTR [rdx+40]
        xor	r8d, DWORD PTR [rdx+44]
        mov	DWORD PTR [rbp+32], eax
        mov	DWORD PTR [rbp+36], ebx
        mov	DWORD PTR [rbp+40], r9d
        mov	DWORD PTR [rbp+44], r8d
        mov	r8, QWORD PTR [rsp+24]
        mov	r9, QWORD PTR [rsp+40]
        add	DWORD PTR [rcx+48], 1
        add	rsp, 48
        sub	r9d, 64
        add	rdx, 64
        add	r8, 64
        cmp	r9d, 64
        jge	L_chacha_x64_start
L_chacha_x64_small:
        cmp	r9d, 0
        je	L_chacha_x64_done
        sub	rsp, 48
        mov	QWORD PTR [rsp+24], r8
        mov	QWORD PTR [rsp+32], rdx
        mov	QWORD PTR [rsp+40], r9
        mov	rax, QWORD PTR [rcx+32]
        mov	rbx, QWORD PTR [rcx+40]
        mov	QWORD PTR [rsp+8], rax
        mov	QWORD PTR [rsp+16], rbx
        mov	eax, DWORD PTR [rcx]
        mov	ebx, DWORD PTR [rcx+4]
        mov	r9d, DWORD PTR [rcx+8]
        mov	r8d, DWORD PTR [rcx+12]
        mov	r8d, DWORD PTR [rcx+16]
        mov	r9d, DWORD PTR [rcx+20]
        mov	r10d, DWORD PTR [rcx+24]
        mov	r11d, DWORD PTR [rcx+28]
        mov	r12d, DWORD PTR [rcx+48]
        mov	r13d, DWORD PTR [rcx+52]
        mov	r14d, DWORD PTR [rcx+56]
        mov	r15d, DWORD PTR [rcx+60]
        mov	BYTE PTR [rsp], 10
L_chacha_x64_partial_crypt_start:
        add	eax, r8d
        add	ebx, r9d
        add	r9d, r10d
        add	r8d, r11d
        xor	r12d, eax
        xor	r13d, ebx
        xor	r14d, r9d
        xor	r15d, r8d
        rol	r12d, 16
        rol	r13d, 16
        rol	r14d, 16
        rol	r15d, 16
        add	DWORD PTR [rsp+8], r12d
        add	DWORD PTR [rsp+12], r13d
        add	DWORD PTR [rsp+16], r14d
        add	DWORD PTR [rsp+20], r15d
        xor	r8d, DWORD PTR [rsp+8]
        xor	r9d, DWORD PTR [rsp+12]
        xor	r10d, DWORD PTR [rsp+16]
        xor	r11d, DWORD PTR [rsp+20]
        rol	r8d, 12
        rol	r9d, 12
        rol	r10d, 12
        rol	r11d, 12
        add	eax, r8d
        add	ebx, r9d
        add	r9d, r10d
        add	r8d, r11d
        xor	r12d, eax
        xor	r13d, ebx
        xor	r14d, r9d
        xor	r15d, r8d
        rol	r12d, 8
        rol	r13d, 8
        rol	r14d, 8
        rol	r15d, 8
        add	DWORD PTR [rsp+8], r12d
        add	DWORD PTR [rsp+12], r13d
        add	DWORD PTR [rsp+16], r14d
        add	DWORD PTR [rsp+20], r15d
        xor	r8d, DWORD PTR [rsp+8]
        xor	r9d, DWORD PTR [rsp+12]
        xor	r10d, DWORD PTR [rsp+16]
        xor	r11d, DWORD PTR [rsp+20]
        rol	r8d, 7
        rol	r9d, 7
        rol	r10d, 7
        rol	r11d, 7
        add	eax, r9d
        add	ebx, r10d
        add	r9d, r11d
        add	r8d, r8d
        xor	r15d, eax
        xor	r12d, ebx
        xor	r13d, r9d
        xor	r14d, r8d
        rol	r15d, 16
        rol	r12d, 16
        rol	r13d, 16
        rol	r14d, 16
        add	DWORD PTR [rsp+16], r15d
        add	DWORD PTR [rsp+20], r12d
        add	DWORD PTR [rsp+8], r13d
        add	DWORD PTR [rsp+12], r14d
        xor	r9d, DWORD PTR [rsp+16]
        xor	r10d, DWORD PTR [rsp+20]
        xor	r11d, DWORD PTR [rsp+8]
        xor	r8d, DWORD PTR [rsp+12]
        rol	r9d, 12
        rol	r10d, 12
        rol	r11d, 12
        rol	r8d, 12
        add	eax, r9d
        add	ebx, r10d
        add	r9d, r11d
        add	r8d, r8d
        xor	r15d, eax
        xor	r12d, ebx
        xor	r13d, r9d
        xor	r14d, r8d
        rol	r15d, 8
        rol	r12d, 8
        rol	r13d, 8
        rol	r14d, 8
        add	DWORD PTR [rsp+16], r15d
        add	DWORD PTR [rsp+20], r12d
        add	DWORD PTR [rsp+8], r13d
        add	DWORD PTR [rsp+12], r14d
        xor	r9d, DWORD PTR [rsp+16]
        xor	r10d, DWORD PTR [rsp+20]
        xor	r11d, DWORD PTR [rsp+8]
        xor	r8d, DWORD PTR [rsp+12]
        rol	r9d, 7
        rol	r10d, 7
        rol	r11d, 7
        rol	r8d, 7
        dec	BYTE PTR [rsp]
        jnz	L_chacha_x64_partial_crypt_start
        mov	rdx, QWORD PTR [rsp+32]
        add	eax, DWORD PTR [rcx]
        add	ebx, DWORD PTR [rcx+4]
        add	r9d, DWORD PTR [rcx+8]
        add	r8d, DWORD PTR [rcx+12]
        add	r8d, DWORD PTR [rcx+16]
        add	r9d, DWORD PTR [rcx+20]
        add	r10d, DWORD PTR [rcx+24]
        add	r11d, DWORD PTR [rcx+28]
        add	r12d, DWORD PTR [rcx+48]
        add	r13d, DWORD PTR [rcx+52]
        add	r14d, DWORD PTR [rcx+56]
        add	r15d, DWORD PTR [rcx+60]
        lea	rbp, QWORD PTR [rcx+80]
        mov	DWORD PTR [rbp], eax
        mov	DWORD PTR [rbp+4], ebx
        mov	DWORD PTR [rbp+8], r9d
        mov	DWORD PTR [rbp+12], r8d
        mov	DWORD PTR [rbp+16], r8d
        mov	DWORD PTR [rbp+20], r9d
        mov	DWORD PTR [rbp+24], r10d
        mov	DWORD PTR [rbp+28], r11d
        mov	DWORD PTR [rbp+48], r12d
        mov	DWORD PTR [rbp+52], r13d
        mov	DWORD PTR [rbp+56], r14d
        mov	DWORD PTR [rbp+60], r15d
        mov	eax, DWORD PTR [rsp+8]
        mov	ebx, DWORD PTR [rsp+12]
        mov	r9d, DWORD PTR [rsp+16]
        mov	r8d, DWORD PTR [rsp+20]
        add	eax, DWORD PTR [rcx+32]
        add	ebx, DWORD PTR [rcx+36]
        add	r9d, DWORD PTR [rcx+40]
        add	r8d, DWORD PTR [rcx+44]
        mov	DWORD PTR [rbp+32], eax
        mov	DWORD PTR [rbp+36], ebx
        mov	DWORD PTR [rbp+40], r9d
        mov	DWORD PTR [rbp+44], r8d
        mov	r8, QWORD PTR [rsp+24]
        mov	r9, QWORD PTR [rsp+40]
        add	DWORD PTR [rcx+48], 1
        add	rsp, 48
        mov	r8d, r9d
        xor	rbx, rbx
        and	r8d, 7
        jz	L_chacha_x64_partial_start64
L_chacha_x64_partial_start8:
        movzx	eax, BYTE PTR [rbp+rbx]
        xor	al, BYTE PTR [rdx+rbx]
        mov	BYTE PTR [r8+rbx], al
        inc	ebx
        cmp	ebx, r8d
        jne	L_chacha_x64_partial_start8
        je	L_chacha_x64_partial_end64
L_chacha_x64_partial_start64:
        mov	rax, QWORD PTR [rbp+rbx]
        xor	rax, QWORD PTR [rdx+rbx]
        mov	QWORD PTR [r8+rbx], rax
        add	ebx, 8
L_chacha_x64_partial_end64:
        cmp	ebx, r9d
        jne	L_chacha_x64_partial_start64
        mov	r9d, 64
        sub	r9d, ebx
        mov	DWORD PTR [rcx+76], r9d
L_chacha_x64_done:
        add	rsp, 64
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        pop	rbp
        pop	rbx
        ret
chacha_encrypt_x64 ENDP
_TEXT ENDS
IFNDEF HAVE_INTEL_SSSE3
HAVE_INTEL_SSSE3 = 1
ENDIF
IFDEF HAVE_INTEL_SSSE3
_DATA SEGMENT
ALIGN 16
L_chacha20_sse3_rotl8 QWORD 0605040702010003h, 0e0d0c0f0a09080bh
ptr_L_chacha20_sse3_rotl8 QWORD L_chacha20_sse3_rotl8
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_chacha20_sse3_rotl16 QWORD 0504070601000302h, 0d0c0f0e09080b0ah
ptr_L_chacha20_sse3_rotl16 QWORD L_chacha20_sse3_rotl16
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_chacha20_sse3_one QWORD 0000000000000001h, 0000000000000000h
ptr_L_chacha20_sse3_one QWORD L_chacha20_sse3_one
_DATA ENDS
_TEXT SEGMENT READONLY PARA
chacha_encrypt_sse3 PROC
        push	r12
        push	r13
        push	r14
        push	r15
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
        mov	r13, QWORD PTR [ptr_L_chacha20_sse3_rotl8]
        mov	r14, QWORD PTR [ptr_L_chacha20_sse3_rotl16]
        mov	r15, QWORD PTR [ptr_L_chacha20_sse3_one]
        cmp	r9d, 128
        jl	L_chacha20_sse3_128_done
L_chacha20_sse3_128_start:
        movdqu	xmm0, OWORD PTR [rcx]
        movdqu	xmm1, OWORD PTR [rcx+16]
        movdqu	xmm2, OWORD PTR [rcx+32]
        movdqu	xmm3, OWORD PTR [rcx+48]
        movdqa	xmm10, xmm0
        movdqa	xmm11, xmm1
        movdqa	xmm12, xmm2
        movdqa	xmm13, xmm3
        movdqa	xmm4, xmm0
        movdqa	xmm5, xmm1
        movdqa	xmm6, xmm2
        movdqa	xmm7, xmm3
        paddd	xmm7, OWORD PTR [r15]
        mov	al, 10
L_chacha20_sse3_128_crypt2_start:
        paddd	xmm0, xmm1
        paddd	xmm4, xmm5
        pxor	xmm3, xmm0
        pxor	xmm7, xmm4
        pshufb	xmm3, OWORD PTR [r14]
        pshufb	xmm7, OWORD PTR [r14]
        paddd	xmm2, xmm3
        paddd	xmm6, xmm7
        pxor	xmm1, xmm2
        pxor	xmm5, xmm6
        movdqa	xmm8, xmm1
        movdqa	xmm9, xmm5
        psrld	xmm8, 20
        psrld	xmm9, 20
        pslld	xmm1, 12
        pslld	xmm5, 12
        pxor	xmm1, xmm8
        pxor	xmm5, xmm9
        paddd	xmm0, xmm1
        paddd	xmm4, xmm5
        pxor	xmm3, xmm0
        pxor	xmm7, xmm4
        pshufb	xmm3, OWORD PTR [r13]
        pshufb	xmm7, OWORD PTR [r13]
        paddd	xmm2, xmm3
        paddd	xmm6, xmm7
        pxor	xmm1, xmm2
        pxor	xmm5, xmm6
        movdqa	xmm8, xmm1
        movdqa	xmm9, xmm5
        psrld	xmm8, 25
        psrld	xmm9, 25
        pslld	xmm1, 7
        pslld	xmm5, 7
        pxor	xmm1, xmm8
        pxor	xmm5, xmm9
        pshufd	xmm1, xmm1, 57
        pshufd	xmm2, xmm2, 78
        pshufd	xmm3, xmm3, 147
        pshufd	xmm5, xmm5, 57
        pshufd	xmm6, xmm6, 78
        pshufd	xmm7, xmm7, 147
        paddd	xmm0, xmm1
        paddd	xmm4, xmm5
        pxor	xmm3, xmm0
        pxor	xmm7, xmm4
        pshufb	xmm3, OWORD PTR [r14]
        pshufb	xmm7, OWORD PTR [r14]
        paddd	xmm2, xmm3
        paddd	xmm6, xmm7
        pxor	xmm1, xmm2
        pxor	xmm5, xmm6
        movdqa	xmm8, xmm1
        movdqa	xmm9, xmm5
        psrld	xmm8, 20
        psrld	xmm9, 20
        pslld	xmm1, 12
        pslld	xmm5, 12
        pxor	xmm1, xmm8
        pxor	xmm5, xmm9
        paddd	xmm0, xmm1
        paddd	xmm4, xmm5
        pxor	xmm3, xmm0
        pxor	xmm7, xmm4
        pshufb	xmm3, OWORD PTR [r13]
        pshufb	xmm7, OWORD PTR [r13]
        paddd	xmm2, xmm3
        paddd	xmm6, xmm7
        pxor	xmm1, xmm2
        pxor	xmm5, xmm6
        movdqa	xmm8, xmm1
        movdqa	xmm9, xmm5
        psrld	xmm8, 25
        psrld	xmm9, 25
        pslld	xmm1, 7
        pslld	xmm5, 7
        pxor	xmm1, xmm8
        pxor	xmm5, xmm9
        pshufd	xmm1, xmm1, 147
        pshufd	xmm2, xmm2, 78
        pshufd	xmm3, xmm3, 57
        pshufd	xmm5, xmm5, 147
        pshufd	xmm6, xmm6, 78
        pshufd	xmm7, xmm7, 57
        dec	al
        jnz	L_chacha20_sse3_128_crypt2_start
        paddd	xmm0, xmm10
        paddd	xmm1, xmm11
        paddd	xmm2, xmm12
        paddd	xmm3, xmm13
        paddd	xmm4, xmm10
        paddd	xmm5, xmm11
        paddd	xmm6, xmm12
        paddd	xmm7, xmm13
        paddd	xmm7, OWORD PTR [r15]
        movdqu	xmm8, OWORD PTR [rdx]
        pxor	xmm0, xmm8
        movdqu	OWORD PTR [r8], xmm0
        movdqu	xmm8, OWORD PTR [rdx+16]
        pxor	xmm1, xmm8
        movdqu	OWORD PTR [r8+16], xmm1
        movdqu	xmm8, OWORD PTR [rdx+32]
        pxor	xmm2, xmm8
        movdqu	OWORD PTR [r8+32], xmm2
        movdqu	xmm8, OWORD PTR [rdx+48]
        pxor	xmm3, xmm8
        movdqu	OWORD PTR [r8+48], xmm3
        movdqu	xmm8, OWORD PTR [rdx+64]
        pxor	xmm4, xmm8
        movdqu	OWORD PTR [r8+64], xmm4
        movdqu	xmm8, OWORD PTR [rdx+80]
        pxor	xmm5, xmm8
        movdqu	OWORD PTR [r8+80], xmm5
        movdqu	xmm8, OWORD PTR [rdx+96]
        pxor	xmm6, xmm8
        movdqu	OWORD PTR [r8+96], xmm6
        movdqu	xmm8, OWORD PTR [rdx+112]
        pxor	xmm7, xmm8
        movdqu	OWORD PTR [r8+112], xmm7
        add	DWORD PTR [rcx+48], 2
        sub	r9d, 128
        add	rdx, 128
        add	r8, 128
        cmp	r9d, 128
        jge	L_chacha20_sse3_128_start
L_chacha20_sse3_128_done:
        cmp	r9d, 0
        je	L_chacha20_sse3_last_done
        movdqu	xmm0, OWORD PTR [rcx]
        movdqu	xmm1, OWORD PTR [rcx+16]
        movdqu	xmm2, OWORD PTR [rcx+32]
        movdqu	xmm3, OWORD PTR [rcx+48]
        movdqa	xmm10, xmm0
        movdqa	xmm11, xmm1
        movdqa	xmm12, xmm2
        movdqa	xmm13, xmm3
        movdqa	xmm4, xmm0
        movdqa	xmm5, xmm1
        movdqa	xmm6, xmm2
        movdqa	xmm7, xmm3
        paddd	xmm7, OWORD PTR [r15]
        mov	al, 10
L_chacha20_sse3_last_crypt2_start:
        paddd	xmm0, xmm1
        paddd	xmm4, xmm5
        pxor	xmm3, xmm0
        pxor	xmm7, xmm4
        pshufb	xmm3, OWORD PTR [r14]
        pshufb	xmm7, OWORD PTR [r14]
        paddd	xmm2, xmm3
        paddd	xmm6, xmm7
        pxor	xmm1, xmm2
        pxor	xmm5, xmm6
        movdqa	xmm8, xmm1
        movdqa	xmm9, xmm5
        psrld	xmm8, 20
        psrld	xmm9, 20
        pslld	xmm1, 12
        pslld	xmm5, 12
        pxor	xmm1, xmm8
        pxor	xmm5, xmm9
        paddd	xmm0, xmm1
        paddd	xmm4, xmm5
        pxor	xmm3, xmm0
        pxor	xmm7, xmm4
        pshufb	xmm3, OWORD PTR [r13]
        pshufb	xmm7, OWORD PTR [r13]
        paddd	xmm2, xmm3
        paddd	xmm6, xmm7
        pxor	xmm1, xmm2
        pxor	xmm5, xmm6
        movdqa	xmm8, xmm1
        movdqa	xmm9, xmm5
        psrld	xmm8, 25
        psrld	xmm9, 25
        pslld	xmm1, 7
        pslld	xmm5, 7
        pxor	xmm1, xmm8
        pxor	xmm5, xmm9
        pshufd	xmm1, xmm1, 57
        pshufd	xmm2, xmm2, 78
        pshufd	xmm3, xmm3, 147
        pshufd	xmm5, xmm5, 57
        pshufd	xmm6, xmm6, 78
        pshufd	xmm7, xmm7, 147
        paddd	xmm0, xmm1
        paddd	xmm4, xmm5
        pxor	xmm3, xmm0
        pxor	xmm7, xmm4
        pshufb	xmm3, OWORD PTR [r14]
        pshufb	xmm7, OWORD PTR [r14]
        paddd	xmm2, xmm3
        paddd	xmm6, xmm7
        pxor	xmm1, xmm2
        pxor	xmm5, xmm6
        movdqa	xmm8, xmm1
        movdqa	xmm9, xmm5
        psrld	xmm8, 20
        psrld	xmm9, 20
        pslld	xmm1, 12
        pslld	xmm5, 12
        pxor	xmm1, xmm8
        pxor	xmm5, xmm9
        paddd	xmm0, xmm1
        paddd	xmm4, xmm5
        pxor	xmm3, xmm0
        pxor	xmm7, xmm4
        pshufb	xmm3, OWORD PTR [r13]
        pshufb	xmm7, OWORD PTR [r13]
        paddd	xmm2, xmm3
        paddd	xmm6, xmm7
        pxor	xmm1, xmm2
        pxor	xmm5, xmm6
        movdqa	xmm8, xmm1
        movdqa	xmm9, xmm5
        psrld	xmm8, 25
        psrld	xmm9, 25
        pslld	xmm1, 7
        pslld	xmm5, 7
        pxor	xmm1, xmm8
        pxor	xmm5, xmm9
        pshufd	xmm1, xmm1, 147
        pshufd	xmm2, xmm2, 78
        pshufd	xmm3, xmm3, 57
        pshufd	xmm5, xmm5, 147
        pshufd	xmm6, xmm6, 78
        pshufd	xmm7, xmm7, 57
        dec	al
        jnz	L_chacha20_sse3_last_crypt2_start
        paddd	xmm0, xmm10
        paddd	xmm1, xmm11
        paddd	xmm2, xmm12
        paddd	xmm3, xmm13
        paddd	xmm4, xmm10
        paddd	xmm5, xmm11
        paddd	xmm6, xmm12
        paddd	xmm7, xmm13
        paddd	xmm7, OWORD PTR [r15]
        cmp	r9d, 64
        jle	L_chacha20_sse3_last_lt64
        movdqu	xmm8, OWORD PTR [rdx]
        pxor	xmm0, xmm8
        movdqu	OWORD PTR [r8], xmm0
        movdqu	xmm8, OWORD PTR [rdx+16]
        pxor	xmm1, xmm8
        movdqu	OWORD PTR [r8+16], xmm1
        movdqu	xmm8, OWORD PTR [rdx+32]
        pxor	xmm2, xmm8
        movdqu	OWORD PTR [r8+32], xmm2
        movdqu	xmm8, OWORD PTR [rdx+48]
        pxor	xmm3, xmm8
        movdqu	OWORD PTR [r8+48], xmm3
        movdqa	xmm0, xmm4
        movdqa	xmm1, xmm5
        movdqa	xmm2, xmm6
        movdqa	xmm3, xmm7
        add	DWORD PTR [rcx+48], 1
        sub	r9d, 64
        add	rdx, 64
        add	r8, 64
L_chacha20_sse3_last_lt64:
        lea	r10, QWORD PTR [rcx+80]
        movdqu	OWORD PTR [r10], xmm0
        movdqu	OWORD PTR [r10+16], xmm1
        movdqu	OWORD PTR [r10+32], xmm2
        movdqu	OWORD PTR [r10+48], xmm3
        add	DWORD PTR [rcx+48], 1
        mov	eax, r9d
        xor	r11, r11
        and	eax, 7
        jz	L_chacha20_sse3_last_start64
L_chacha20_sse3_last_start8:
        movzx	r12d, BYTE PTR [r10+r11]
        xor	r12b, BYTE PTR [rdx+r11]
        mov	BYTE PTR [r8+r11], r12b
        inc	r11d
        cmp	r11d, eax
        jne	L_chacha20_sse3_last_start8
        je	L_chacha20_sse3_last_end64
L_chacha20_sse3_last_start64:
        mov	r12, QWORD PTR [r10+r11]
        xor	r12, QWORD PTR [rdx+r11]
        mov	QWORD PTR [r8+r11], r12
        add	r11d, 8
L_chacha20_sse3_last_end64:
        cmp	r11d, r9d
        jne	L_chacha20_sse3_last_start64
        mov	eax, 64
        sub	eax, r11d
        mov	DWORD PTR [rcx+76], eax
L_chacha20_sse3_last_done:
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
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
chacha_encrypt_sse3 ENDP
_TEXT ENDS
ENDIF
IFDEF HAVE_INTEL_AVX1
_DATA SEGMENT
ALIGN 16
L_chacha20_avx1_rotl8 QWORD 0605040702010003h, 0e0d0c0f0a09080bh
ptr_L_chacha20_avx1_rotl8 QWORD L_chacha20_avx1_rotl8
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_chacha20_avx1_rotl16 QWORD 0504070601000302h, 0d0c0f0e09080b0ah
ptr_L_chacha20_avx1_rotl16 QWORD L_chacha20_avx1_rotl16
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_chacha20_avx1_add QWORD 0000000100000000h, 0000000300000002h
ptr_L_chacha20_avx1_add QWORD L_chacha20_avx1_add
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_chacha20_avx1_four QWORD 0000000400000004h, 0000000400000004h
ptr_L_chacha20_avx1_four QWORD L_chacha20_avx1_four
_DATA ENDS
_TEXT SEGMENT READONLY PARA
chacha_encrypt_avx1 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        sub	rsp, 560
        vmovdqu	OWORD PTR [rsp+400], xmm6
        vmovdqu	OWORD PTR [rsp+416], xmm7
        vmovdqu	OWORD PTR [rsp+432], xmm8
        vmovdqu	OWORD PTR [rsp+448], xmm9
        vmovdqu	OWORD PTR [rsp+464], xmm10
        vmovdqu	OWORD PTR [rsp+480], xmm11
        vmovdqu	OWORD PTR [rsp+496], xmm12
        vmovdqu	OWORD PTR [rsp+512], xmm13
        vmovdqu	OWORD PTR [rsp+528], xmm14
        vmovdqu	OWORD PTR [rsp+544], xmm15
        mov	r11, rsp
        lea	r12, QWORD PTR [rsp+256]
        mov	r14, QWORD PTR [ptr_L_chacha20_avx1_rotl8]
        mov	r15, QWORD PTR [ptr_L_chacha20_avx1_rotl16]
        mov	rdi, QWORD PTR [ptr_L_chacha20_avx1_add]
        mov	rsi, QWORD PTR [ptr_L_chacha20_avx1_four]
        add	r11, 15
        add	r12, 15
        and	r11, -16
        and	r12, -16
        mov	eax, r9d
        shr	eax, 8
        jz	L_chacha20_avx1_end128
        vpshufd	xmm0, [rcx], 0
        vpshufd	xmm1, [rcx+4], 0
        vpshufd	xmm2, [rcx+8], 0
        vpshufd	xmm3, [rcx+12], 0
        vpshufd	xmm4, [rcx+16], 0
        vpshufd	xmm5, [rcx+20], 0
        vpshufd	xmm6, [rcx+24], 0
        vpshufd	xmm7, [rcx+28], 0
        vpshufd	xmm8, [rcx+32], 0
        vpshufd	xmm9, [rcx+36], 0
        vpshufd	xmm10, [rcx+40], 0
        vpshufd	xmm11, [rcx+44], 0
        vpshufd	xmm12, [rcx+48], 0
        vpshufd	xmm13, [rcx+52], 0
        vpshufd	xmm14, [rcx+56], 0
        vpshufd	xmm15, [rcx+60], 0
        vpaddd	xmm12, xmm12, OWORD PTR [rdi]
        vmovdqa	OWORD PTR [r11], xmm0
        vmovdqa	OWORD PTR [r11+16], xmm1
        vmovdqa	OWORD PTR [r11+32], xmm2
        vmovdqa	OWORD PTR [r11+48], xmm3
        vmovdqa	OWORD PTR [r11+64], xmm4
        vmovdqa	OWORD PTR [r11+80], xmm5
        vmovdqa	OWORD PTR [r11+96], xmm6
        vmovdqa	OWORD PTR [r11+112], xmm7
        vmovdqa	OWORD PTR [r11+128], xmm8
        vmovdqa	OWORD PTR [r11+144], xmm9
        vmovdqa	OWORD PTR [r11+160], xmm10
        vmovdqa	OWORD PTR [r11+176], xmm11
        vmovdqa	OWORD PTR [r11+192], xmm12
        vmovdqa	OWORD PTR [r11+208], xmm13
        vmovdqa	OWORD PTR [r11+224], xmm14
        vmovdqa	OWORD PTR [r11+240], xmm15
L_chacha20_avx1_start128:
        vmovdqa	OWORD PTR [r12+48], xmm11
        mov	r10b, 10
L_chacha20_avx1_loop128:
        vpaddd	xmm0, xmm0, xmm4
        vpxor	xmm12, xmm12, xmm0
        vmovdqa	xmm11, OWORD PTR [r12+48]
        vpshufb	xmm12, xmm12, OWORD PTR [r15]
        vpaddd	xmm8, xmm8, xmm12
        vpxor	xmm4, xmm4, xmm8
        vpaddd	xmm1, xmm1, xmm5
        vpxor	xmm13, xmm13, xmm1
        vpshufb	xmm13, xmm13, OWORD PTR [r15]
        vpaddd	xmm9, xmm9, xmm13
        vpxor	xmm5, xmm5, xmm9
        vpaddd	xmm2, xmm2, xmm6
        vpxor	xmm14, xmm14, xmm2
        vpshufb	xmm14, xmm14, OWORD PTR [r15]
        vpaddd	xmm10, xmm10, xmm14
        vpxor	xmm6, xmm6, xmm10
        vpaddd	xmm3, xmm3, xmm7
        vpxor	xmm15, xmm15, xmm3
        vpshufb	xmm15, xmm15, OWORD PTR [r15]
        vpaddd	xmm11, xmm11, xmm15
        vpxor	xmm7, xmm7, xmm11
        vmovdqa	OWORD PTR [r12+48], xmm11
        vpsrld	xmm11, xmm4, 20
        vpslld	xmm4, xmm4, 12
        vpxor	xmm4, xmm4, xmm11
        vpsrld	xmm11, xmm5, 20
        vpslld	xmm5, xmm5, 12
        vpxor	xmm5, xmm5, xmm11
        vpsrld	xmm11, xmm6, 20
        vpslld	xmm6, xmm6, 12
        vpxor	xmm6, xmm6, xmm11
        vpsrld	xmm11, xmm7, 20
        vpslld	xmm7, xmm7, 12
        vpxor	xmm7, xmm7, xmm11
        vpaddd	xmm0, xmm0, xmm4
        vpxor	xmm12, xmm12, xmm0
        vmovdqa	xmm11, OWORD PTR [r12+48]
        vpshufb	xmm12, xmm12, OWORD PTR [r14]
        vpaddd	xmm8, xmm8, xmm12
        vpxor	xmm4, xmm4, xmm8
        vpaddd	xmm1, xmm1, xmm5
        vpxor	xmm13, xmm13, xmm1
        vpshufb	xmm13, xmm13, OWORD PTR [r14]
        vpaddd	xmm9, xmm9, xmm13
        vpxor	xmm5, xmm5, xmm9
        vpaddd	xmm2, xmm2, xmm6
        vpxor	xmm14, xmm14, xmm2
        vpshufb	xmm14, xmm14, OWORD PTR [r14]
        vpaddd	xmm10, xmm10, xmm14
        vpxor	xmm6, xmm6, xmm10
        vpaddd	xmm3, xmm3, xmm7
        vpxor	xmm15, xmm15, xmm3
        vpshufb	xmm15, xmm15, OWORD PTR [r14]
        vpaddd	xmm11, xmm11, xmm15
        vpxor	xmm7, xmm7, xmm11
        vmovdqa	OWORD PTR [r12+48], xmm11
        vpsrld	xmm11, xmm4, 25
        vpslld	xmm4, xmm4, 7
        vpxor	xmm4, xmm4, xmm11
        vpsrld	xmm11, xmm5, 25
        vpslld	xmm5, xmm5, 7
        vpxor	xmm5, xmm5, xmm11
        vpsrld	xmm11, xmm6, 25
        vpslld	xmm6, xmm6, 7
        vpxor	xmm6, xmm6, xmm11
        vpsrld	xmm11, xmm7, 25
        vpslld	xmm7, xmm7, 7
        vpxor	xmm7, xmm7, xmm11
        vpaddd	xmm0, xmm0, xmm5
        vpxor	xmm15, xmm15, xmm0
        vmovdqa	xmm11, OWORD PTR [r12+48]
        vpshufb	xmm15, xmm15, OWORD PTR [r15]
        vpaddd	xmm10, xmm10, xmm15
        vpxor	xmm5, xmm5, xmm10
        vpaddd	xmm1, xmm1, xmm6
        vpxor	xmm12, xmm12, xmm1
        vpshufb	xmm12, xmm12, OWORD PTR [r15]
        vpaddd	xmm11, xmm11, xmm12
        vpxor	xmm6, xmm6, xmm11
        vpaddd	xmm2, xmm2, xmm7
        vpxor	xmm13, xmm13, xmm2
        vpshufb	xmm13, xmm13, OWORD PTR [r15]
        vpaddd	xmm8, xmm8, xmm13
        vpxor	xmm7, xmm7, xmm8
        vpaddd	xmm3, xmm3, xmm4
        vpxor	xmm14, xmm14, xmm3
        vpshufb	xmm14, xmm14, OWORD PTR [r15]
        vpaddd	xmm9, xmm9, xmm14
        vpxor	xmm4, xmm4, xmm9
        vmovdqa	OWORD PTR [r12+48], xmm11
        vpsrld	xmm11, xmm5, 20
        vpslld	xmm5, xmm5, 12
        vpxor	xmm5, xmm5, xmm11
        vpsrld	xmm11, xmm6, 20
        vpslld	xmm6, xmm6, 12
        vpxor	xmm6, xmm6, xmm11
        vpsrld	xmm11, xmm7, 20
        vpslld	xmm7, xmm7, 12
        vpxor	xmm7, xmm7, xmm11
        vpsrld	xmm11, xmm4, 20
        vpslld	xmm4, xmm4, 12
        vpxor	xmm4, xmm4, xmm11
        vpaddd	xmm0, xmm0, xmm5
        vpxor	xmm15, xmm15, xmm0
        vmovdqa	xmm11, OWORD PTR [r12+48]
        vpshufb	xmm15, xmm15, OWORD PTR [r14]
        vpaddd	xmm10, xmm10, xmm15
        vpxor	xmm5, xmm5, xmm10
        vpaddd	xmm1, xmm1, xmm6
        vpxor	xmm12, xmm12, xmm1
        vpshufb	xmm12, xmm12, OWORD PTR [r14]
        vpaddd	xmm11, xmm11, xmm12
        vpxor	xmm6, xmm6, xmm11
        vpaddd	xmm2, xmm2, xmm7
        vpxor	xmm13, xmm13, xmm2
        vpshufb	xmm13, xmm13, OWORD PTR [r14]
        vpaddd	xmm8, xmm8, xmm13
        vpxor	xmm7, xmm7, xmm8
        vpaddd	xmm3, xmm3, xmm4
        vpxor	xmm14, xmm14, xmm3
        vpshufb	xmm14, xmm14, OWORD PTR [r14]
        vpaddd	xmm9, xmm9, xmm14
        vpxor	xmm4, xmm4, xmm9
        vmovdqa	OWORD PTR [r12+48], xmm11
        vpsrld	xmm11, xmm5, 25
        vpslld	xmm5, xmm5, 7
        vpxor	xmm5, xmm5, xmm11
        vpsrld	xmm11, xmm6, 25
        vpslld	xmm6, xmm6, 7
        vpxor	xmm6, xmm6, xmm11
        vpsrld	xmm11, xmm7, 25
        vpslld	xmm7, xmm7, 7
        vpxor	xmm7, xmm7, xmm11
        vpsrld	xmm11, xmm4, 25
        vpslld	xmm4, xmm4, 7
        vpxor	xmm4, xmm4, xmm11
        dec	r10b
        jnz	L_chacha20_avx1_loop128
        vmovdqa	xmm11, OWORD PTR [r12+48]
        vpaddd	xmm0, xmm0, OWORD PTR [r11]
        vpaddd	xmm1, xmm1, OWORD PTR [r11+16]
        vpaddd	xmm2, xmm2, OWORD PTR [r11+32]
        vpaddd	xmm3, xmm3, OWORD PTR [r11+48]
        vpaddd	xmm4, xmm4, OWORD PTR [r11+64]
        vpaddd	xmm5, xmm5, OWORD PTR [r11+80]
        vpaddd	xmm6, xmm6, OWORD PTR [r11+96]
        vpaddd	xmm7, xmm7, OWORD PTR [r11+112]
        vpaddd	xmm8, xmm8, OWORD PTR [r11+128]
        vpaddd	xmm9, xmm9, OWORD PTR [r11+144]
        vpaddd	xmm10, xmm10, OWORD PTR [r11+160]
        vpaddd	xmm11, xmm11, OWORD PTR [r11+176]
        vpaddd	xmm12, xmm12, OWORD PTR [r11+192]
        vpaddd	xmm13, xmm13, OWORD PTR [r11+208]
        vpaddd	xmm14, xmm14, OWORD PTR [r11+224]
        vpaddd	xmm15, xmm15, OWORD PTR [r11+240]
        vmovdqa	OWORD PTR [r12], xmm8
        vmovdqa	OWORD PTR [r12+16], xmm9
        vmovdqa	OWORD PTR [r12+32], xmm10
        vmovdqa	OWORD PTR [r12+48], xmm11
        vmovdqa	OWORD PTR [r12+64], xmm12
        vmovdqa	OWORD PTR [r12+80], xmm13
        vmovdqa	OWORD PTR [r12+96], xmm14
        vmovdqa	OWORD PTR [r12+112], xmm15
        vpunpckldq	xmm8, xmm0, xmm1
        vpunpckldq	xmm9, xmm2, xmm3
        vpunpckhdq	xmm12, xmm0, xmm1
        vpunpckhdq	xmm13, xmm2, xmm3
        vpunpckldq	xmm10, xmm4, xmm5
        vpunpckldq	xmm11, xmm6, xmm7
        vpunpckhdq	xmm14, xmm4, xmm5
        vpunpckhdq	xmm15, xmm6, xmm7
        vpunpcklqdq	xmm0, xmm8, xmm9
        vpunpcklqdq	xmm1, xmm10, xmm11
        vpunpckhqdq	xmm2, xmm8, xmm9
        vpunpckhqdq	xmm3, xmm10, xmm11
        vpunpcklqdq	xmm4, xmm12, xmm13
        vpunpcklqdq	xmm5, xmm14, xmm15
        vpunpckhqdq	xmm6, xmm12, xmm13
        vpunpckhqdq	xmm7, xmm14, xmm15
        vmovdqu	xmm8, OWORD PTR [rdx]
        vmovdqu	xmm9, OWORD PTR [rdx+16]
        vmovdqu	xmm10, OWORD PTR [rdx+64]
        vmovdqu	xmm11, OWORD PTR [rdx+80]
        vmovdqu	xmm12, OWORD PTR [rdx+128]
        vmovdqu	xmm13, OWORD PTR [rdx+144]
        vmovdqu	xmm14, OWORD PTR [rdx+192]
        vmovdqu	xmm15, OWORD PTR [rdx+208]
        vpxor	xmm0, xmm0, xmm8
        vpxor	xmm1, xmm1, xmm9
        vpxor	xmm2, xmm2, xmm10
        vpxor	xmm3, xmm3, xmm11
        vpxor	xmm4, xmm4, xmm12
        vpxor	xmm5, xmm5, xmm13
        vpxor	xmm6, xmm6, xmm14
        vpxor	xmm7, xmm7, xmm15
        vmovdqu	OWORD PTR [r8], xmm0
        vmovdqu	OWORD PTR [r8+16], xmm1
        vmovdqu	OWORD PTR [r8+64], xmm2
        vmovdqu	OWORD PTR [r8+80], xmm3
        vmovdqu	OWORD PTR [r8+128], xmm4
        vmovdqu	OWORD PTR [r8+144], xmm5
        vmovdqu	OWORD PTR [r8+192], xmm6
        vmovdqu	OWORD PTR [r8+208], xmm7
        vmovdqa	xmm0, OWORD PTR [r12]
        vmovdqa	xmm1, OWORD PTR [r12+16]
        vmovdqa	xmm2, OWORD PTR [r12+32]
        vmovdqa	xmm3, OWORD PTR [r12+48]
        vmovdqa	xmm4, OWORD PTR [r12+64]
        vmovdqa	xmm5, OWORD PTR [r12+80]
        vmovdqa	xmm6, OWORD PTR [r12+96]
        vmovdqa	xmm7, OWORD PTR [r12+112]
        vpunpckldq	xmm8, xmm0, xmm1
        vpunpckldq	xmm9, xmm2, xmm3
        vpunpckhdq	xmm12, xmm0, xmm1
        vpunpckhdq	xmm13, xmm2, xmm3
        vpunpckldq	xmm10, xmm4, xmm5
        vpunpckldq	xmm11, xmm6, xmm7
        vpunpckhdq	xmm14, xmm4, xmm5
        vpunpckhdq	xmm15, xmm6, xmm7
        vpunpcklqdq	xmm0, xmm8, xmm9
        vpunpcklqdq	xmm1, xmm10, xmm11
        vpunpckhqdq	xmm2, xmm8, xmm9
        vpunpckhqdq	xmm3, xmm10, xmm11
        vpunpcklqdq	xmm4, xmm12, xmm13
        vpunpcklqdq	xmm5, xmm14, xmm15
        vpunpckhqdq	xmm6, xmm12, xmm13
        vpunpckhqdq	xmm7, xmm14, xmm15
        vmovdqu	xmm8, OWORD PTR [rdx+32]
        vmovdqu	xmm9, OWORD PTR [rdx+48]
        vmovdqu	xmm10, OWORD PTR [rdx+96]
        vmovdqu	xmm11, OWORD PTR [rdx+112]
        vmovdqu	xmm12, OWORD PTR [rdx+160]
        vmovdqu	xmm13, OWORD PTR [rdx+176]
        vmovdqu	xmm14, OWORD PTR [rdx+224]
        vmovdqu	xmm15, OWORD PTR [rdx+240]
        vpxor	xmm0, xmm0, xmm8
        vpxor	xmm1, xmm1, xmm9
        vpxor	xmm2, xmm2, xmm10
        vpxor	xmm3, xmm3, xmm11
        vpxor	xmm4, xmm4, xmm12
        vpxor	xmm5, xmm5, xmm13
        vpxor	xmm6, xmm6, xmm14
        vpxor	xmm7, xmm7, xmm15
        vmovdqu	OWORD PTR [r8+32], xmm0
        vmovdqu	OWORD PTR [r8+48], xmm1
        vmovdqu	OWORD PTR [r8+96], xmm2
        vmovdqu	OWORD PTR [r8+112], xmm3
        vmovdqu	OWORD PTR [r8+160], xmm4
        vmovdqu	OWORD PTR [r8+176], xmm5
        vmovdqu	OWORD PTR [r8+224], xmm6
        vmovdqu	OWORD PTR [r8+240], xmm7
        vmovdqa	xmm12, OWORD PTR [r11+192]
        add	rdx, 256
        add	r8, 256
        vpaddd	xmm12, xmm12, OWORD PTR [rsi]
        sub	r9d, 256
        vmovdqa	OWORD PTR [r11+192], xmm12
        cmp	r9d, 256
        jl	L_chacha20_avx1_done128
        vmovdqa	xmm0, OWORD PTR [r11]
        vmovdqa	xmm1, OWORD PTR [r11+16]
        vmovdqa	xmm2, OWORD PTR [r11+32]
        vmovdqa	xmm3, OWORD PTR [r11+48]
        vmovdqa	xmm4, OWORD PTR [r11+64]
        vmovdqa	xmm5, OWORD PTR [r11+80]
        vmovdqa	xmm6, OWORD PTR [r11+96]
        vmovdqa	xmm7, OWORD PTR [r11+112]
        vmovdqa	xmm8, OWORD PTR [r11+128]
        vmovdqa	xmm9, OWORD PTR [r11+144]
        vmovdqa	xmm10, OWORD PTR [r11+160]
        vmovdqa	xmm11, OWORD PTR [r11+176]
        vmovdqa	xmm12, OWORD PTR [r11+192]
        vmovdqa	xmm13, OWORD PTR [r11+208]
        vmovdqa	xmm14, OWORD PTR [r11+224]
        vmovdqa	xmm15, OWORD PTR [r11+240]
        jmp	L_chacha20_avx1_start128
L_chacha20_avx1_done128:
        shl	eax, 2
        add	DWORD PTR [rcx+48], eax
L_chacha20_avx1_end128:
        cmp	r9d, 64
        jl	L_chacha20_avx1_block_done
L_chacha20_avx1_block_start:
        vmovdqu	xmm0, OWORD PTR [rcx]
        vmovdqu	xmm1, OWORD PTR [rcx+16]
        vmovdqu	xmm2, OWORD PTR [rcx+32]
        vmovdqu	xmm3, OWORD PTR [rcx+48]
        vmovdqa	xmm5, xmm0
        vmovdqa	xmm6, xmm1
        vmovdqa	xmm7, xmm2
        vmovdqa	xmm8, xmm3
        mov	al, 10
L_chacha20_avx1_block_crypt_start:
        vpaddd	xmm0, xmm0, xmm1
        vpxor	xmm3, xmm3, xmm0
        vpshufb	xmm3, xmm3, OWORD PTR [r15]
        vpaddd	xmm2, xmm2, xmm3
        vpxor	xmm1, xmm1, xmm2
        vpsrld	xmm4, xmm1, 20
        vpslld	xmm1, xmm1, 12
        vpxor	xmm1, xmm1, xmm4
        vpaddd	xmm0, xmm0, xmm1
        vpxor	xmm3, xmm3, xmm0
        vpshufb	xmm3, xmm3, OWORD PTR [r14]
        vpaddd	xmm2, xmm2, xmm3
        vpxor	xmm1, xmm1, xmm2
        vpsrld	xmm4, xmm1, 25
        vpslld	xmm1, xmm1, 7
        vpxor	xmm1, xmm1, xmm4
        vpshufd	xmm1, xmm1, 57
        vpshufd	xmm2, xmm2, 78
        vpshufd	xmm3, xmm3, 147
        vpaddd	xmm0, xmm0, xmm1
        vpxor	xmm3, xmm3, xmm0
        vpshufb	xmm3, xmm3, OWORD PTR [r15]
        vpaddd	xmm2, xmm2, xmm3
        vpxor	xmm1, xmm1, xmm2
        vpsrld	xmm4, xmm1, 20
        vpslld	xmm1, xmm1, 12
        vpxor	xmm1, xmm1, xmm4
        vpaddd	xmm0, xmm0, xmm1
        vpxor	xmm3, xmm3, xmm0
        vpshufb	xmm3, xmm3, OWORD PTR [r14]
        vpaddd	xmm2, xmm2, xmm3
        vpxor	xmm1, xmm1, xmm2
        vpsrld	xmm4, xmm1, 25
        vpslld	xmm1, xmm1, 7
        vpxor	xmm1, xmm1, xmm4
        vpshufd	xmm1, xmm1, 147
        vpshufd	xmm2, xmm2, 78
        vpshufd	xmm3, xmm3, 57
        dec	al
        jnz	L_chacha20_avx1_block_crypt_start
        vpaddd	xmm0, xmm0, xmm5
        vpaddd	xmm1, xmm1, xmm6
        vpaddd	xmm2, xmm2, xmm7
        vpaddd	xmm3, xmm3, xmm8
        vmovdqu	xmm5, OWORD PTR [rdx]
        vmovdqu	xmm6, OWORD PTR [rdx+16]
        vmovdqu	xmm7, OWORD PTR [rdx+32]
        vmovdqu	xmm8, OWORD PTR [rdx+48]
        vpxor	xmm0, xmm0, xmm5
        vpxor	xmm1, xmm1, xmm6
        vpxor	xmm2, xmm2, xmm7
        vpxor	xmm3, xmm3, xmm8
        vmovdqu	OWORD PTR [r8], xmm0
        vmovdqu	OWORD PTR [r8+16], xmm1
        vmovdqu	OWORD PTR [r8+32], xmm2
        vmovdqu	OWORD PTR [r8+48], xmm3
        add	DWORD PTR [rcx+48], 1
        sub	r9d, 64
        add	rdx, 64
        add	r8, 64
        cmp	r9d, 64
        jge	L_chacha20_avx1_block_start
L_chacha20_avx1_block_done:
        cmp	r9d, 0
        je	L_chacha20_avx1_partial_done
        lea	r12, QWORD PTR [rcx+80]
        vmovdqu	xmm0, OWORD PTR [rcx]
        vmovdqu	xmm1, OWORD PTR [rcx+16]
        vmovdqu	xmm2, OWORD PTR [rcx+32]
        vmovdqu	xmm3, OWORD PTR [rcx+48]
        vmovdqa	xmm5, xmm0
        vmovdqa	xmm6, xmm1
        vmovdqa	xmm7, xmm2
        vmovdqa	xmm8, xmm3
        mov	al, 10
L_chacha20_avx1_partial_crypt_start:
        vpaddd	xmm0, xmm0, xmm1
        vpxor	xmm3, xmm3, xmm0
        vpshufb	xmm3, xmm3, OWORD PTR [r15]
        vpaddd	xmm2, xmm2, xmm3
        vpxor	xmm1, xmm1, xmm2
        vpsrld	xmm4, xmm1, 20
        vpslld	xmm1, xmm1, 12
        vpxor	xmm1, xmm1, xmm4
        vpaddd	xmm0, xmm0, xmm1
        vpxor	xmm3, xmm3, xmm0
        vpshufb	xmm3, xmm3, OWORD PTR [r14]
        vpaddd	xmm2, xmm2, xmm3
        vpxor	xmm1, xmm1, xmm2
        vpsrld	xmm4, xmm1, 25
        vpslld	xmm1, xmm1, 7
        vpxor	xmm1, xmm1, xmm4
        vpshufd	xmm1, xmm1, 57
        vpshufd	xmm2, xmm2, 78
        vpshufd	xmm3, xmm3, 147
        vpaddd	xmm0, xmm0, xmm1
        vpxor	xmm3, xmm3, xmm0
        vpshufb	xmm3, xmm3, OWORD PTR [r15]
        vpaddd	xmm2, xmm2, xmm3
        vpxor	xmm1, xmm1, xmm2
        vpsrld	xmm4, xmm1, 20
        vpslld	xmm1, xmm1, 12
        vpxor	xmm1, xmm1, xmm4
        vpaddd	xmm0, xmm0, xmm1
        vpxor	xmm3, xmm3, xmm0
        vpshufb	xmm3, xmm3, OWORD PTR [r14]
        vpaddd	xmm2, xmm2, xmm3
        vpxor	xmm1, xmm1, xmm2
        vpsrld	xmm4, xmm1, 25
        vpslld	xmm1, xmm1, 7
        vpxor	xmm1, xmm1, xmm4
        vpshufd	xmm1, xmm1, 147
        vpshufd	xmm2, xmm2, 78
        vpshufd	xmm3, xmm3, 57
        dec	al
        jnz	L_chacha20_avx1_partial_crypt_start
        vpaddd	xmm0, xmm0, xmm5
        vpaddd	xmm1, xmm1, xmm6
        vpaddd	xmm2, xmm2, xmm7
        vpaddd	xmm3, xmm3, xmm8
        vmovdqu	OWORD PTR [r12], xmm0
        vmovdqu	OWORD PTR [r12+16], xmm1
        vmovdqu	OWORD PTR [r12+32], xmm2
        vmovdqu	OWORD PTR [r12+48], xmm3
        add	DWORD PTR [rcx+48], 1
        mov	r10d, r9d
        xor	r13, r13
        and	r10d, 7
        jz	L_chacha20_avx1_partial_start64
L_chacha20_avx1_partial_start8:
        movzx	eax, BYTE PTR [r12+r13]
        xor	al, BYTE PTR [rdx+r13]
        mov	BYTE PTR [r8+r13], al
        inc	r13d
        cmp	r13d, r10d
        jne	L_chacha20_avx1_partial_start8
        je	L_chacha20_avx1_partial_end64
L_chacha20_avx1_partial_start64:
        mov	rax, QWORD PTR [r12+r13]
        xor	rax, QWORD PTR [rdx+r13]
        mov	QWORD PTR [r8+r13], rax
        add	r13d, 8
L_chacha20_avx1_partial_end64:
        cmp	r13d, r9d
        jne	L_chacha20_avx1_partial_start64
        mov	r10d, 64
        sub	r10d, r13d
        mov	DWORD PTR [rcx+76], r10d
L_chacha20_avx1_partial_done:
        vmovdqu	xmm6, OWORD PTR [rsp+400]
        vmovdqu	xmm7, OWORD PTR [rsp+416]
        vmovdqu	xmm8, OWORD PTR [rsp+432]
        vmovdqu	xmm9, OWORD PTR [rsp+448]
        vmovdqu	xmm10, OWORD PTR [rsp+464]
        vmovdqu	xmm11, OWORD PTR [rsp+480]
        vmovdqu	xmm12, OWORD PTR [rsp+496]
        vmovdqu	xmm13, OWORD PTR [rsp+512]
        vmovdqu	xmm14, OWORD PTR [rsp+528]
        vmovdqu	xmm15, OWORD PTR [rsp+544]
        add	rsp, 560
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
chacha_encrypt_avx1 ENDP
_TEXT ENDS
ENDIF
IFDEF HAVE_INTEL_AVX2
_DATA SEGMENT
ALIGN 16
L_chacha20_avx2_rotl8 QWORD 0605040702010003h, 0e0d0c0f0a09080bh
        QWORD 0605040702010003h, 0e0d0c0f0a09080bh
ptr_L_chacha20_avx2_rotl8 QWORD L_chacha20_avx2_rotl8
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_chacha20_avx2_rotl16 QWORD 0504070601000302h, 0d0c0f0e09080b0ah
        QWORD 0504070601000302h, 0d0c0f0e09080b0ah
ptr_L_chacha20_avx2_rotl16 QWORD L_chacha20_avx2_rotl16
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_chacha20_avx2_add QWORD 0000000100000000h, 0000000300000002h
        QWORD 0000000500000004h, 0000000700000006h
ptr_L_chacha20_avx2_add QWORD L_chacha20_avx2_add
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_chacha20_avx2_eight QWORD 0000000800000008h, 0000000800000008h
        QWORD 0000000800000008h, 0000000800000008h
ptr_L_chacha20_avx2_eight QWORD L_chacha20_avx2_eight
_DATA ENDS
_TEXT SEGMENT READONLY PARA
chacha_encrypt_avx2 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        sub	rsp, 960
        vmovdqu	OWORD PTR [rsp+800], xmm6
        vmovdqu	OWORD PTR [rsp+816], xmm7
        vmovdqu	OWORD PTR [rsp+832], xmm8
        vmovdqu	OWORD PTR [rsp+848], xmm9
        vmovdqu	OWORD PTR [rsp+864], xmm10
        vmovdqu	OWORD PTR [rsp+880], xmm11
        vmovdqu	OWORD PTR [rsp+896], xmm12
        vmovdqu	OWORD PTR [rsp+912], xmm13
        vmovdqu	OWORD PTR [rsp+928], xmm14
        vmovdqu	OWORD PTR [rsp+944], xmm15
        mov	r11, rsp
        mov	r13, QWORD PTR [ptr_L_chacha20_avx2_rotl8]
        mov	r14, QWORD PTR [ptr_L_chacha20_avx2_rotl16]
        mov	r15, QWORD PTR [ptr_L_chacha20_avx2_add]
        mov	rdi, QWORD PTR [ptr_L_chacha20_avx2_eight]
        lea	r12, QWORD PTR [rsp+512]
        add	r11, 31
        add	r12, 31
        and	r11, -32
        and	r12, -32
        mov	eax, r9d
        shr	eax, 9
        jz	L_chacha20_avx2_end256
        vpbroadcastd	ymm0, DWORD PTR [rcx]
        vpbroadcastd	ymm1, DWORD PTR [rcx+4]
        vpbroadcastd	ymm2, DWORD PTR [rcx+8]
        vpbroadcastd	ymm3, DWORD PTR [rcx+12]
        vpbroadcastd	ymm4, DWORD PTR [rcx+16]
        vpbroadcastd	ymm5, DWORD PTR [rcx+20]
        vpbroadcastd	ymm6, DWORD PTR [rcx+24]
        vpbroadcastd	ymm7, DWORD PTR [rcx+28]
        vpbroadcastd	ymm8, DWORD PTR [rcx+32]
        vpbroadcastd	ymm9, DWORD PTR [rcx+36]
        vpbroadcastd	ymm10, DWORD PTR [rcx+40]
        vpbroadcastd	ymm11, DWORD PTR [rcx+44]
        vpbroadcastd	ymm12, DWORD PTR [rcx+48]
        vpbroadcastd	ymm13, DWORD PTR [rcx+52]
        vpbroadcastd	ymm14, DWORD PTR [rcx+56]
        vpbroadcastd	ymm15, DWORD PTR [rcx+60]
        vpaddd	ymm12, ymm12, YMMWORD PTR [r15]
        vmovdqu	YMMWORD PTR [r11], ymm0
        vmovdqu	YMMWORD PTR [r11+32], ymm1
        vmovdqu	YMMWORD PTR [r11+64], ymm2
        vmovdqu	YMMWORD PTR [r11+96], ymm3
        vmovdqu	YMMWORD PTR [r11+128], ymm4
        vmovdqu	YMMWORD PTR [r11+160], ymm5
        vmovdqu	YMMWORD PTR [r11+192], ymm6
        vmovdqu	YMMWORD PTR [r11+224], ymm7
        vmovdqu	YMMWORD PTR [r11+256], ymm8
        vmovdqu	YMMWORD PTR [r11+288], ymm9
        vmovdqu	YMMWORD PTR [r11+320], ymm10
        vmovdqu	YMMWORD PTR [r11+352], ymm11
        vmovdqu	YMMWORD PTR [r11+384], ymm12
        vmovdqu	YMMWORD PTR [r11+416], ymm13
        vmovdqu	YMMWORD PTR [r11+448], ymm14
        vmovdqu	YMMWORD PTR [r11+480], ymm15
L_chacha20_avx2_start256:
        mov	r10b, 10
        vmovdqu	YMMWORD PTR [r12+96], ymm11
L_chacha20_avx2_loop256:
        vpaddd	ymm0, ymm0, ymm4
        vpxor	ymm12, ymm12, ymm0
        vmovdqu	ymm11, YMMWORD PTR [r12+96]
        vpshufb	ymm12, ymm12, YMMWORD PTR [r14]
        vpaddd	ymm8, ymm8, ymm12
        vpxor	ymm4, ymm4, ymm8
        vpaddd	ymm1, ymm1, ymm5
        vpxor	ymm13, ymm13, ymm1
        vpshufb	ymm13, ymm13, YMMWORD PTR [r14]
        vpaddd	ymm9, ymm9, ymm13
        vpxor	ymm5, ymm5, ymm9
        vpaddd	ymm2, ymm2, ymm6
        vpxor	ymm14, ymm14, ymm2
        vpshufb	ymm14, ymm14, YMMWORD PTR [r14]
        vpaddd	ymm10, ymm10, ymm14
        vpxor	ymm6, ymm6, ymm10
        vpaddd	ymm3, ymm3, ymm7
        vpxor	ymm15, ymm15, ymm3
        vpshufb	ymm15, ymm15, YMMWORD PTR [r14]
        vpaddd	ymm11, ymm11, ymm15
        vpxor	ymm7, ymm7, ymm11
        vmovdqu	YMMWORD PTR [r12+96], ymm11
        vpsrld	ymm11, ymm4, 20
        vpslld	ymm4, ymm4, 12
        vpxor	ymm4, ymm4, ymm11
        vpsrld	ymm11, ymm5, 20
        vpslld	ymm5, ymm5, 12
        vpxor	ymm5, ymm5, ymm11
        vpsrld	ymm11, ymm6, 20
        vpslld	ymm6, ymm6, 12
        vpxor	ymm6, ymm6, ymm11
        vpsrld	ymm11, ymm7, 20
        vpslld	ymm7, ymm7, 12
        vpxor	ymm7, ymm7, ymm11
        vpaddd	ymm0, ymm0, ymm4
        vpxor	ymm12, ymm12, ymm0
        vmovdqu	ymm11, YMMWORD PTR [r12+96]
        vpshufb	ymm12, ymm12, YMMWORD PTR [r13]
        vpaddd	ymm8, ymm8, ymm12
        vpxor	ymm4, ymm4, ymm8
        vpaddd	ymm1, ymm1, ymm5
        vpxor	ymm13, ymm13, ymm1
        vpshufb	ymm13, ymm13, YMMWORD PTR [r13]
        vpaddd	ymm9, ymm9, ymm13
        vpxor	ymm5, ymm5, ymm9
        vpaddd	ymm2, ymm2, ymm6
        vpxor	ymm14, ymm14, ymm2
        vpshufb	ymm14, ymm14, YMMWORD PTR [r13]
        vpaddd	ymm10, ymm10, ymm14
        vpxor	ymm6, ymm6, ymm10
        vpaddd	ymm3, ymm3, ymm7
        vpxor	ymm15, ymm15, ymm3
        vpshufb	ymm15, ymm15, YMMWORD PTR [r13]
        vpaddd	ymm11, ymm11, ymm15
        vpxor	ymm7, ymm7, ymm11
        vmovdqu	YMMWORD PTR [r12+96], ymm11
        vpsrld	ymm11, ymm4, 25
        vpslld	ymm4, ymm4, 7
        vpxor	ymm4, ymm4, ymm11
        vpsrld	ymm11, ymm5, 25
        vpslld	ymm5, ymm5, 7
        vpxor	ymm5, ymm5, ymm11
        vpsrld	ymm11, ymm6, 25
        vpslld	ymm6, ymm6, 7
        vpxor	ymm6, ymm6, ymm11
        vpsrld	ymm11, ymm7, 25
        vpslld	ymm7, ymm7, 7
        vpxor	ymm7, ymm7, ymm11
        vpaddd	ymm0, ymm0, ymm5
        vpxor	ymm15, ymm15, ymm0
        vmovdqu	ymm11, YMMWORD PTR [r12+96]
        vpshufb	ymm15, ymm15, YMMWORD PTR [r14]
        vpaddd	ymm10, ymm10, ymm15
        vpxor	ymm5, ymm5, ymm10
        vpaddd	ymm1, ymm1, ymm6
        vpxor	ymm12, ymm12, ymm1
        vpshufb	ymm12, ymm12, YMMWORD PTR [r14]
        vpaddd	ymm11, ymm11, ymm12
        vpxor	ymm6, ymm6, ymm11
        vpaddd	ymm2, ymm2, ymm7
        vpxor	ymm13, ymm13, ymm2
        vpshufb	ymm13, ymm13, YMMWORD PTR [r14]
        vpaddd	ymm8, ymm8, ymm13
        vpxor	ymm7, ymm7, ymm8
        vpaddd	ymm3, ymm3, ymm4
        vpxor	ymm14, ymm14, ymm3
        vpshufb	ymm14, ymm14, YMMWORD PTR [r14]
        vpaddd	ymm9, ymm9, ymm14
        vpxor	ymm4, ymm4, ymm9
        vmovdqu	YMMWORD PTR [r12+96], ymm11
        vpsrld	ymm11, ymm5, 20
        vpslld	ymm5, ymm5, 12
        vpxor	ymm5, ymm5, ymm11
        vpsrld	ymm11, ymm6, 20
        vpslld	ymm6, ymm6, 12
        vpxor	ymm6, ymm6, ymm11
        vpsrld	ymm11, ymm7, 20
        vpslld	ymm7, ymm7, 12
        vpxor	ymm7, ymm7, ymm11
        vpsrld	ymm11, ymm4, 20
        vpslld	ymm4, ymm4, 12
        vpxor	ymm4, ymm4, ymm11
        vpaddd	ymm0, ymm0, ymm5
        vpxor	ymm15, ymm15, ymm0
        vmovdqu	ymm11, YMMWORD PTR [r12+96]
        vpshufb	ymm15, ymm15, YMMWORD PTR [r13]
        vpaddd	ymm10, ymm10, ymm15
        vpxor	ymm5, ymm5, ymm10
        vpaddd	ymm1, ymm1, ymm6
        vpxor	ymm12, ymm12, ymm1
        vpshufb	ymm12, ymm12, YMMWORD PTR [r13]
        vpaddd	ymm11, ymm11, ymm12
        vpxor	ymm6, ymm6, ymm11
        vpaddd	ymm2, ymm2, ymm7
        vpxor	ymm13, ymm13, ymm2
        vpshufb	ymm13, ymm13, YMMWORD PTR [r13]
        vpaddd	ymm8, ymm8, ymm13
        vpxor	ymm7, ymm7, ymm8
        vpaddd	ymm3, ymm3, ymm4
        vpxor	ymm14, ymm14, ymm3
        vpshufb	ymm14, ymm14, YMMWORD PTR [r13]
        vpaddd	ymm9, ymm9, ymm14
        vpxor	ymm4, ymm4, ymm9
        vmovdqu	YMMWORD PTR [r12+96], ymm11
        vpsrld	ymm11, ymm5, 25
        vpslld	ymm5, ymm5, 7
        vpxor	ymm5, ymm5, ymm11
        vpsrld	ymm11, ymm6, 25
        vpslld	ymm6, ymm6, 7
        vpxor	ymm6, ymm6, ymm11
        vpsrld	ymm11, ymm7, 25
        vpslld	ymm7, ymm7, 7
        vpxor	ymm7, ymm7, ymm11
        vpsrld	ymm11, ymm4, 25
        vpslld	ymm4, ymm4, 7
        vpxor	ymm4, ymm4, ymm11
        dec	r10b
        jnz	L_chacha20_avx2_loop256
        vmovdqu	ymm11, YMMWORD PTR [r12+96]
        vpaddd	ymm0, ymm0, YMMWORD PTR [r11]
        vpaddd	ymm1, ymm1, YMMWORD PTR [r11+32]
        vpaddd	ymm2, ymm2, YMMWORD PTR [r11+64]
        vpaddd	ymm3, ymm3, YMMWORD PTR [r11+96]
        vpaddd	ymm4, ymm4, YMMWORD PTR [r11+128]
        vpaddd	ymm5, ymm5, YMMWORD PTR [r11+160]
        vpaddd	ymm6, ymm6, YMMWORD PTR [r11+192]
        vpaddd	ymm7, ymm7, YMMWORD PTR [r11+224]
        vpaddd	ymm8, ymm8, YMMWORD PTR [r11+256]
        vpaddd	ymm9, ymm9, YMMWORD PTR [r11+288]
        vpaddd	ymm10, ymm10, YMMWORD PTR [r11+320]
        vpaddd	ymm11, ymm11, YMMWORD PTR [r11+352]
        vpaddd	ymm12, ymm12, YMMWORD PTR [r11+384]
        vpaddd	ymm13, ymm13, YMMWORD PTR [r11+416]
        vpaddd	ymm14, ymm14, YMMWORD PTR [r11+448]
        vpaddd	ymm15, ymm15, YMMWORD PTR [r11+480]
        vmovdqu	YMMWORD PTR [r12], ymm8
        vmovdqu	YMMWORD PTR [r12+32], ymm9
        vmovdqu	YMMWORD PTR [r12+64], ymm10
        vmovdqu	YMMWORD PTR [r12+96], ymm11
        vmovdqu	YMMWORD PTR [r12+128], ymm12
        vmovdqu	YMMWORD PTR [r12+160], ymm13
        vmovdqu	YMMWORD PTR [r12+192], ymm14
        vmovdqu	YMMWORD PTR [r12+224], ymm15
        vpunpckldq	ymm8, ymm0, ymm1
        vpunpckldq	ymm9, ymm2, ymm3
        vpunpckhdq	ymm12, ymm0, ymm1
        vpunpckhdq	ymm13, ymm2, ymm3
        vpunpckldq	ymm10, ymm4, ymm5
        vpunpckldq	ymm11, ymm6, ymm7
        vpunpckhdq	ymm14, ymm4, ymm5
        vpunpckhdq	ymm15, ymm6, ymm7
        vpunpcklqdq	ymm0, ymm8, ymm9
        vpunpcklqdq	ymm1, ymm10, ymm11
        vpunpckhqdq	ymm2, ymm8, ymm9
        vpunpckhqdq	ymm3, ymm10, ymm11
        vpunpcklqdq	ymm4, ymm12, ymm13
        vpunpcklqdq	ymm5, ymm14, ymm15
        vpunpckhqdq	ymm6, ymm12, ymm13
        vpunpckhqdq	ymm7, ymm14, ymm15
        vperm2i128	ymm8, ymm0, ymm1, 32
        vperm2i128	ymm9, ymm2, ymm3, 32
        vperm2i128	ymm12, ymm0, ymm1, 49
        vperm2i128	ymm13, ymm2, ymm3, 49
        vperm2i128	ymm10, ymm4, ymm5, 32
        vperm2i128	ymm11, ymm6, ymm7, 32
        vperm2i128	ymm14, ymm4, ymm5, 49
        vperm2i128	ymm15, ymm6, ymm7, 49
        vmovdqu	ymm0, YMMWORD PTR [rdx]
        vmovdqu	ymm1, YMMWORD PTR [rdx+64]
        vmovdqu	ymm2, YMMWORD PTR [rdx+128]
        vmovdqu	ymm3, YMMWORD PTR [rdx+192]
        vmovdqu	ymm4, YMMWORD PTR [rdx+256]
        vmovdqu	ymm5, YMMWORD PTR [rdx+320]
        vmovdqu	ymm6, YMMWORD PTR [rdx+384]
        vmovdqu	ymm7, YMMWORD PTR [rdx+448]
        vpxor	ymm8, ymm8, ymm0
        vpxor	ymm9, ymm9, ymm1
        vpxor	ymm10, ymm10, ymm2
        vpxor	ymm11, ymm11, ymm3
        vpxor	ymm12, ymm12, ymm4
        vpxor	ymm13, ymm13, ymm5
        vpxor	ymm14, ymm14, ymm6
        vpxor	ymm15, ymm15, ymm7
        vmovdqu	YMMWORD PTR [r8], ymm8
        vmovdqu	YMMWORD PTR [r8+64], ymm9
        vmovdqu	YMMWORD PTR [r8+128], ymm10
        vmovdqu	YMMWORD PTR [r8+192], ymm11
        vmovdqu	YMMWORD PTR [r8+256], ymm12
        vmovdqu	YMMWORD PTR [r8+320], ymm13
        vmovdqu	YMMWORD PTR [r8+384], ymm14
        vmovdqu	YMMWORD PTR [r8+448], ymm15
        vmovdqu	ymm0, YMMWORD PTR [r12]
        vmovdqu	ymm1, YMMWORD PTR [r12+32]
        vmovdqu	ymm2, YMMWORD PTR [r12+64]
        vmovdqu	ymm3, YMMWORD PTR [r12+96]
        vmovdqu	ymm4, YMMWORD PTR [r12+128]
        vmovdqu	ymm5, YMMWORD PTR [r12+160]
        vmovdqu	ymm6, YMMWORD PTR [r12+192]
        vmovdqu	ymm7, YMMWORD PTR [r12+224]
        vpunpckldq	ymm8, ymm0, ymm1
        vpunpckldq	ymm9, ymm2, ymm3
        vpunpckhdq	ymm12, ymm0, ymm1
        vpunpckhdq	ymm13, ymm2, ymm3
        vpunpckldq	ymm10, ymm4, ymm5
        vpunpckldq	ymm11, ymm6, ymm7
        vpunpckhdq	ymm14, ymm4, ymm5
        vpunpckhdq	ymm15, ymm6, ymm7
        vpunpcklqdq	ymm0, ymm8, ymm9
        vpunpcklqdq	ymm1, ymm10, ymm11
        vpunpckhqdq	ymm2, ymm8, ymm9
        vpunpckhqdq	ymm3, ymm10, ymm11
        vpunpcklqdq	ymm4, ymm12, ymm13
        vpunpcklqdq	ymm5, ymm14, ymm15
        vpunpckhqdq	ymm6, ymm12, ymm13
        vpunpckhqdq	ymm7, ymm14, ymm15
        vperm2i128	ymm8, ymm0, ymm1, 32
        vperm2i128	ymm9, ymm2, ymm3, 32
        vperm2i128	ymm12, ymm0, ymm1, 49
        vperm2i128	ymm13, ymm2, ymm3, 49
        vperm2i128	ymm10, ymm4, ymm5, 32
        vperm2i128	ymm11, ymm6, ymm7, 32
        vperm2i128	ymm14, ymm4, ymm5, 49
        vperm2i128	ymm15, ymm6, ymm7, 49
        vmovdqu	ymm0, YMMWORD PTR [rdx+32]
        vmovdqu	ymm1, YMMWORD PTR [rdx+96]
        vmovdqu	ymm2, YMMWORD PTR [rdx+160]
        vmovdqu	ymm3, YMMWORD PTR [rdx+224]
        vmovdqu	ymm4, YMMWORD PTR [rdx+288]
        vmovdqu	ymm5, YMMWORD PTR [rdx+352]
        vmovdqu	ymm6, YMMWORD PTR [rdx+416]
        vmovdqu	ymm7, YMMWORD PTR [rdx+480]
        vpxor	ymm8, ymm8, ymm0
        vpxor	ymm9, ymm9, ymm1
        vpxor	ymm10, ymm10, ymm2
        vpxor	ymm11, ymm11, ymm3
        vpxor	ymm12, ymm12, ymm4
        vpxor	ymm13, ymm13, ymm5
        vpxor	ymm14, ymm14, ymm6
        vpxor	ymm15, ymm15, ymm7
        vmovdqu	YMMWORD PTR [r8+32], ymm8
        vmovdqu	YMMWORD PTR [r8+96], ymm9
        vmovdqu	YMMWORD PTR [r8+160], ymm10
        vmovdqu	YMMWORD PTR [r8+224], ymm11
        vmovdqu	YMMWORD PTR [r8+288], ymm12
        vmovdqu	YMMWORD PTR [r8+352], ymm13
        vmovdqu	YMMWORD PTR [r8+416], ymm14
        vmovdqu	YMMWORD PTR [r8+480], ymm15
        vmovdqu	ymm12, YMMWORD PTR [r11+384]
        add	rdx, 512
        add	r8, 512
        vpaddd	ymm12, ymm12, YMMWORD PTR [rdi]
        sub	r9d, 512
        vmovdqu	YMMWORD PTR [r11+384], ymm12
        cmp	r9d, 512
        jl	L_chacha20_avx2_done256
        vmovdqu	ymm0, YMMWORD PTR [r11]
        vmovdqu	ymm1, YMMWORD PTR [r11+32]
        vmovdqu	ymm2, YMMWORD PTR [r11+64]
        vmovdqu	ymm3, YMMWORD PTR [r11+96]
        vmovdqu	ymm4, YMMWORD PTR [r11+128]
        vmovdqu	ymm5, YMMWORD PTR [r11+160]
        vmovdqu	ymm6, YMMWORD PTR [r11+192]
        vmovdqu	ymm7, YMMWORD PTR [r11+224]
        vmovdqu	ymm8, YMMWORD PTR [r11+256]
        vmovdqu	ymm9, YMMWORD PTR [r11+288]
        vmovdqu	ymm10, YMMWORD PTR [r11+320]
        vmovdqu	ymm11, YMMWORD PTR [r11+352]
        vmovdqu	ymm12, YMMWORD PTR [r11+384]
        vmovdqu	ymm13, YMMWORD PTR [r11+416]
        vmovdqu	ymm14, YMMWORD PTR [r11+448]
        vmovdqu	ymm15, YMMWORD PTR [r11+480]
        jmp	L_chacha20_avx2_start256
L_chacha20_avx2_done256:
        shl	eax, 3
        add	DWORD PTR [rcx+48], eax
L_chacha20_avx2_end256:
        call	chacha_encrypt_avx1
        vzeroupper
        vmovdqu	xmm6, OWORD PTR [rsp+800]
        vmovdqu	xmm7, OWORD PTR [rsp+816]
        vmovdqu	xmm8, OWORD PTR [rsp+832]
        vmovdqu	xmm9, OWORD PTR [rsp+848]
        vmovdqu	xmm10, OWORD PTR [rsp+864]
        vmovdqu	xmm11, OWORD PTR [rsp+880]
        vmovdqu	xmm12, OWORD PTR [rsp+896]
        vmovdqu	xmm13, OWORD PTR [rsp+912]
        vmovdqu	xmm14, OWORD PTR [rsp+928]
        vmovdqu	xmm15, OWORD PTR [rsp+944]
        add	rsp, 960
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
chacha_encrypt_avx2 ENDP
_TEXT ENDS
ENDIF
IFDEF HAVE_INTEL_AVX512
_DATA SEGMENT
ALIGN 16
L_chacha20_avx512vl_add QWORD 0000000100000000h, 0000000300000002h
ptr_L_chacha20_avx512vl_add QWORD L_chacha20_avx512vl_add
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_chacha20_avx512vl_four QWORD 0000000400000004h, 0000000400000004h
ptr_L_chacha20_avx512vl_four QWORD L_chacha20_avx512vl_four
_DATA ENDS
_TEXT SEGMENT READONLY PARA
chacha_encrypt_avx512vl PROC
        push	r12
        push	r13
        push	r14
        push	r15
        sub	rsp, 560
        vmovdqu	OWORD PTR [rsp+400], xmm6
        vmovdqu	OWORD PTR [rsp+416], xmm7
        vmovdqu	OWORD PTR [rsp+432], xmm8
        vmovdqu	OWORD PTR [rsp+448], xmm9
        vmovdqu	OWORD PTR [rsp+464], xmm10
        vmovdqu	OWORD PTR [rsp+480], xmm11
        vmovdqu	OWORD PTR [rsp+496], xmm12
        vmovdqu	OWORD PTR [rsp+512], xmm13
        vmovdqu	OWORD PTR [rsp+528], xmm14
        vmovdqu	OWORD PTR [rsp+544], xmm15
        mov	r11, rsp
        lea	r12, QWORD PTR [rsp+256]
        mov	r14, QWORD PTR [ptr_L_chacha20_avx512vl_add]
        mov	r15, QWORD PTR [ptr_L_chacha20_avx512vl_four]
        add	r11, 15
        add	r12, 15
        and	r11, -16
        and	r12, -16
        mov	eax, r9d
        shr	eax, 8
        jz	L_chacha20_avx512vl_end128
        vpbroadcastd	xmm0, DWORD PTR [rcx]
        vpbroadcastd	xmm1, DWORD PTR [rcx+4]
        vpbroadcastd	xmm2, DWORD PTR [rcx+8]
        vpbroadcastd	xmm3, DWORD PTR [rcx+12]
        vpbroadcastd	xmm4, DWORD PTR [rcx+16]
        vpbroadcastd	xmm5, DWORD PTR [rcx+20]
        vpbroadcastd	xmm6, DWORD PTR [rcx+24]
        vpbroadcastd	xmm7, DWORD PTR [rcx+28]
        vpbroadcastd	xmm8, DWORD PTR [rcx+32]
        vpbroadcastd	xmm9, DWORD PTR [rcx+36]
        vpbroadcastd	xmm10, DWORD PTR [rcx+40]
        vpbroadcastd	xmm11, DWORD PTR [rcx+44]
        vpbroadcastd	xmm12, DWORD PTR [rcx+48]
        vpbroadcastd	xmm13, DWORD PTR [rcx+52]
        vpbroadcastd	xmm14, DWORD PTR [rcx+56]
        vpbroadcastd	xmm15, DWORD PTR [rcx+60]
        vpaddd	xmm12, xmm12, OWORD PTR [r14]
        vmovdqa	OWORD PTR [r11], xmm0
        vmovdqa	OWORD PTR [r11+16], xmm1
        vmovdqa	OWORD PTR [r11+32], xmm2
        vmovdqa	OWORD PTR [r11+48], xmm3
        vmovdqa	OWORD PTR [r11+64], xmm4
        vmovdqa	OWORD PTR [r11+80], xmm5
        vmovdqa	OWORD PTR [r11+96], xmm6
        vmovdqa	OWORD PTR [r11+112], xmm7
        vmovdqa	OWORD PTR [r11+128], xmm8
        vmovdqa	OWORD PTR [r11+144], xmm9
        vmovdqa	OWORD PTR [r11+160], xmm10
        vmovdqa	OWORD PTR [r11+176], xmm11
        vmovdqa	OWORD PTR [r11+192], xmm12
        vmovdqa	OWORD PTR [r11+208], xmm13
        vmovdqa	OWORD PTR [r11+224], xmm14
        vmovdqa	OWORD PTR [r11+240], xmm15
L_chacha20_avx512vl_start128:
        mov	r10b, 10
L_chacha20_avx512vl_loop128:
        vpaddd	xmm0, xmm0, xmm4
        vpaddd	xmm1, xmm1, xmm5
        vpaddd	xmm2, xmm2, xmm6
        vpaddd	xmm3, xmm3, xmm7
        vpxord	xmm12, xmm12, xmm0
        vpxord	xmm13, xmm13, xmm1
        vpxord	xmm14, xmm14, xmm2
        vpxord	xmm15, xmm15, xmm3
        vprold	xmm12, xmm12, 16
        vprold	xmm13, xmm13, 16
        vprold	xmm14, xmm14, 16
        vprold	xmm15, xmm15, 16
        vpaddd	xmm8, xmm8, xmm12
        vpaddd	xmm9, xmm9, xmm13
        vpaddd	xmm10, xmm10, xmm14
        vpaddd	xmm11, xmm11, xmm15
        vpxord	xmm4, xmm4, xmm8
        vpxord	xmm5, xmm5, xmm9
        vpxord	xmm6, xmm6, xmm10
        vpxord	xmm7, xmm7, xmm11
        vprold	xmm4, xmm4, 12
        vprold	xmm5, xmm5, 12
        vprold	xmm6, xmm6, 12
        vprold	xmm7, xmm7, 12
        vpaddd	xmm0, xmm0, xmm4
        vpaddd	xmm1, xmm1, xmm5
        vpaddd	xmm2, xmm2, xmm6
        vpaddd	xmm3, xmm3, xmm7
        vpxord	xmm12, xmm12, xmm0
        vpxord	xmm13, xmm13, xmm1
        vpxord	xmm14, xmm14, xmm2
        vpxord	xmm15, xmm15, xmm3
        vprold	xmm12, xmm12, 8
        vprold	xmm13, xmm13, 8
        vprold	xmm14, xmm14, 8
        vprold	xmm15, xmm15, 8
        vpaddd	xmm8, xmm8, xmm12
        vpaddd	xmm9, xmm9, xmm13
        vpaddd	xmm10, xmm10, xmm14
        vpaddd	xmm11, xmm11, xmm15
        vpxord	xmm4, xmm4, xmm8
        vpxord	xmm5, xmm5, xmm9
        vpxord	xmm6, xmm6, xmm10
        vpxord	xmm7, xmm7, xmm11
        vprold	xmm4, xmm4, 7
        vprold	xmm5, xmm5, 7
        vprold	xmm6, xmm6, 7
        vprold	xmm7, xmm7, 7
        vpaddd	xmm0, xmm0, xmm5
        vpaddd	xmm1, xmm1, xmm6
        vpaddd	xmm2, xmm2, xmm7
        vpaddd	xmm3, xmm3, xmm4
        vpxord	xmm15, xmm15, xmm0
        vpxord	xmm12, xmm12, xmm1
        vpxord	xmm13, xmm13, xmm2
        vpxord	xmm14, xmm14, xmm3
        vprold	xmm15, xmm15, 16
        vprold	xmm12, xmm12, 16
        vprold	xmm13, xmm13, 16
        vprold	xmm14, xmm14, 16
        vpaddd	xmm10, xmm10, xmm15
        vpaddd	xmm11, xmm11, xmm12
        vpaddd	xmm8, xmm8, xmm13
        vpaddd	xmm9, xmm9, xmm14
        vpxord	xmm5, xmm5, xmm10
        vpxord	xmm6, xmm6, xmm11
        vpxord	xmm7, xmm7, xmm8
        vpxord	xmm4, xmm4, xmm9
        vprold	xmm5, xmm5, 12
        vprold	xmm6, xmm6, 12
        vprold	xmm7, xmm7, 12
        vprold	xmm4, xmm4, 12
        vpaddd	xmm0, xmm0, xmm5
        vpaddd	xmm1, xmm1, xmm6
        vpaddd	xmm2, xmm2, xmm7
        vpaddd	xmm3, xmm3, xmm4
        vpxord	xmm15, xmm15, xmm0
        vpxord	xmm12, xmm12, xmm1
        vpxord	xmm13, xmm13, xmm2
        vpxord	xmm14, xmm14, xmm3
        vprold	xmm15, xmm15, 8
        vprold	xmm12, xmm12, 8
        vprold	xmm13, xmm13, 8
        vprold	xmm14, xmm14, 8
        vpaddd	xmm10, xmm10, xmm15
        vpaddd	xmm11, xmm11, xmm12
        vpaddd	xmm8, xmm8, xmm13
        vpaddd	xmm9, xmm9, xmm14
        vpxord	xmm5, xmm5, xmm10
        vpxord	xmm6, xmm6, xmm11
        vpxord	xmm7, xmm7, xmm8
        vpxord	xmm4, xmm4, xmm9
        vprold	xmm5, xmm5, 7
        vprold	xmm6, xmm6, 7
        vprold	xmm7, xmm7, 7
        vprold	xmm4, xmm4, 7
        dec	r10b
        jnz	L_chacha20_avx512vl_loop128
        vpaddd	xmm0, xmm0, OWORD PTR [r11]
        vpaddd	xmm1, xmm1, OWORD PTR [r11+16]
        vpaddd	xmm2, xmm2, OWORD PTR [r11+32]
        vpaddd	xmm3, xmm3, OWORD PTR [r11+48]
        vpaddd	xmm4, xmm4, OWORD PTR [r11+64]
        vpaddd	xmm5, xmm5, OWORD PTR [r11+80]
        vpaddd	xmm6, xmm6, OWORD PTR [r11+96]
        vpaddd	xmm7, xmm7, OWORD PTR [r11+112]
        vpaddd	xmm8, xmm8, OWORD PTR [r11+128]
        vpaddd	xmm9, xmm9, OWORD PTR [r11+144]
        vpaddd	xmm10, xmm10, OWORD PTR [r11+160]
        vpaddd	xmm11, xmm11, OWORD PTR [r11+176]
        vpaddd	xmm12, xmm12, OWORD PTR [r11+192]
        vpaddd	xmm13, xmm13, OWORD PTR [r11+208]
        vpaddd	xmm14, xmm14, OWORD PTR [r11+224]
        vpaddd	xmm15, xmm15, OWORD PTR [r11+240]
        vmovdqa	OWORD PTR [r12], xmm8
        vmovdqa	OWORD PTR [r12+16], xmm9
        vmovdqa	OWORD PTR [r12+32], xmm10
        vmovdqa	OWORD PTR [r12+48], xmm11
        vmovdqa	OWORD PTR [r12+64], xmm12
        vmovdqa	OWORD PTR [r12+80], xmm13
        vmovdqa	OWORD PTR [r12+96], xmm14
        vmovdqa	OWORD PTR [r12+112], xmm15
        vpunpckldq	xmm8, xmm0, xmm1
        vpunpckldq	xmm9, xmm2, xmm3
        vpunpckhdq	xmm12, xmm0, xmm1
        vpunpckhdq	xmm13, xmm2, xmm3
        vpunpckldq	xmm10, xmm4, xmm5
        vpunpckldq	xmm11, xmm6, xmm7
        vpunpckhdq	xmm14, xmm4, xmm5
        vpunpckhdq	xmm15, xmm6, xmm7
        vpunpcklqdq	xmm0, xmm8, xmm9
        vpunpcklqdq	xmm1, xmm10, xmm11
        vpunpckhqdq	xmm2, xmm8, xmm9
        vpunpckhqdq	xmm3, xmm10, xmm11
        vpunpcklqdq	xmm4, xmm12, xmm13
        vpunpcklqdq	xmm5, xmm14, xmm15
        vpunpckhqdq	xmm6, xmm12, xmm13
        vpunpckhqdq	xmm7, xmm14, xmm15
        vmovdqu	xmm8, OWORD PTR [rdx]
        vmovdqu	xmm9, OWORD PTR [rdx+16]
        vmovdqu	xmm10, OWORD PTR [rdx+64]
        vmovdqu	xmm11, OWORD PTR [rdx+80]
        vmovdqu	xmm12, OWORD PTR [rdx+128]
        vmovdqu	xmm13, OWORD PTR [rdx+144]
        vmovdqu	xmm14, OWORD PTR [rdx+192]
        vmovdqu	xmm15, OWORD PTR [rdx+208]
        vpxor	xmm0, xmm0, xmm8
        vpxor	xmm1, xmm1, xmm9
        vpxor	xmm2, xmm2, xmm10
        vpxor	xmm3, xmm3, xmm11
        vpxor	xmm4, xmm4, xmm12
        vpxor	xmm5, xmm5, xmm13
        vpxor	xmm6, xmm6, xmm14
        vpxor	xmm7, xmm7, xmm15
        vmovdqu	OWORD PTR [r8], xmm0
        vmovdqu	OWORD PTR [r8+16], xmm1
        vmovdqu	OWORD PTR [r8+64], xmm2
        vmovdqu	OWORD PTR [r8+80], xmm3
        vmovdqu	OWORD PTR [r8+128], xmm4
        vmovdqu	OWORD PTR [r8+144], xmm5
        vmovdqu	OWORD PTR [r8+192], xmm6
        vmovdqu	OWORD PTR [r8+208], xmm7
        vmovdqa	xmm0, OWORD PTR [r12]
        vmovdqa	xmm1, OWORD PTR [r12+16]
        vmovdqa	xmm2, OWORD PTR [r12+32]
        vmovdqa	xmm3, OWORD PTR [r12+48]
        vmovdqa	xmm4, OWORD PTR [r12+64]
        vmovdqa	xmm5, OWORD PTR [r12+80]
        vmovdqa	xmm6, OWORD PTR [r12+96]
        vmovdqa	xmm7, OWORD PTR [r12+112]
        vpunpckldq	xmm8, xmm0, xmm1
        vpunpckldq	xmm9, xmm2, xmm3
        vpunpckhdq	xmm12, xmm0, xmm1
        vpunpckhdq	xmm13, xmm2, xmm3
        vpunpckldq	xmm10, xmm4, xmm5
        vpunpckldq	xmm11, xmm6, xmm7
        vpunpckhdq	xmm14, xmm4, xmm5
        vpunpckhdq	xmm15, xmm6, xmm7
        vpunpcklqdq	xmm0, xmm8, xmm9
        vpunpcklqdq	xmm1, xmm10, xmm11
        vpunpckhqdq	xmm2, xmm8, xmm9
        vpunpckhqdq	xmm3, xmm10, xmm11
        vpunpcklqdq	xmm4, xmm12, xmm13
        vpunpcklqdq	xmm5, xmm14, xmm15
        vpunpckhqdq	xmm6, xmm12, xmm13
        vpunpckhqdq	xmm7, xmm14, xmm15
        vmovdqu	xmm8, OWORD PTR [rdx+32]
        vmovdqu	xmm9, OWORD PTR [rdx+48]
        vmovdqu	xmm10, OWORD PTR [rdx+96]
        vmovdqu	xmm11, OWORD PTR [rdx+112]
        vmovdqu	xmm12, OWORD PTR [rdx+160]
        vmovdqu	xmm13, OWORD PTR [rdx+176]
        vmovdqu	xmm14, OWORD PTR [rdx+224]
        vmovdqu	xmm15, OWORD PTR [rdx+240]
        vpxor	xmm0, xmm0, xmm8
        vpxor	xmm1, xmm1, xmm9
        vpxor	xmm2, xmm2, xmm10
        vpxor	xmm3, xmm3, xmm11
        vpxor	xmm4, xmm4, xmm12
        vpxor	xmm5, xmm5, xmm13
        vpxor	xmm6, xmm6, xmm14
        vpxor	xmm7, xmm7, xmm15
        vmovdqu	OWORD PTR [r8+32], xmm0
        vmovdqu	OWORD PTR [r8+48], xmm1
        vmovdqu	OWORD PTR [r8+96], xmm2
        vmovdqu	OWORD PTR [r8+112], xmm3
        vmovdqu	OWORD PTR [r8+160], xmm4
        vmovdqu	OWORD PTR [r8+176], xmm5
        vmovdqu	OWORD PTR [r8+224], xmm6
        vmovdqu	OWORD PTR [r8+240], xmm7
        vmovdqa	xmm12, OWORD PTR [r11+192]
        add	rdx, 256
        add	r8, 256
        vpaddd	xmm12, xmm12, OWORD PTR [r15]
        sub	r9d, 256
        vmovdqa	OWORD PTR [r11+192], xmm12
        cmp	r9d, 256
        jl	L_chacha20_avx512vl_done128
        vmovdqa	xmm0, OWORD PTR [r11]
        vmovdqa	xmm1, OWORD PTR [r11+16]
        vmovdqa	xmm2, OWORD PTR [r11+32]
        vmovdqa	xmm3, OWORD PTR [r11+48]
        vmovdqa	xmm4, OWORD PTR [r11+64]
        vmovdqa	xmm5, OWORD PTR [r11+80]
        vmovdqa	xmm6, OWORD PTR [r11+96]
        vmovdqa	xmm7, OWORD PTR [r11+112]
        vmovdqa	xmm8, OWORD PTR [r11+128]
        vmovdqa	xmm9, OWORD PTR [r11+144]
        vmovdqa	xmm10, OWORD PTR [r11+160]
        vmovdqa	xmm11, OWORD PTR [r11+176]
        vmovdqa	xmm12, OWORD PTR [r11+192]
        vmovdqa	xmm13, OWORD PTR [r11+208]
        vmovdqa	xmm14, OWORD PTR [r11+224]
        vmovdqa	xmm15, OWORD PTR [r11+240]
        jmp	L_chacha20_avx512vl_start128
L_chacha20_avx512vl_done128:
        shl	eax, 2
        add	DWORD PTR [rcx+48], eax
L_chacha20_avx512vl_end128:
        cmp	r9d, 0
        je	L_chacha20_avx512vl_last_done
        vpbroadcastd	xmm0, DWORD PTR [rcx]
        vpbroadcastd	xmm1, DWORD PTR [rcx+4]
        vpbroadcastd	xmm2, DWORD PTR [rcx+8]
        vpbroadcastd	xmm3, DWORD PTR [rcx+12]
        vpbroadcastd	xmm4, DWORD PTR [rcx+16]
        vpbroadcastd	xmm5, DWORD PTR [rcx+20]
        vpbroadcastd	xmm6, DWORD PTR [rcx+24]
        vpbroadcastd	xmm7, DWORD PTR [rcx+28]
        vpbroadcastd	xmm8, DWORD PTR [rcx+32]
        vpbroadcastd	xmm9, DWORD PTR [rcx+36]
        vpbroadcastd	xmm10, DWORD PTR [rcx+40]
        vpbroadcastd	xmm11, DWORD PTR [rcx+44]
        vpbroadcastd	xmm12, DWORD PTR [rcx+48]
        vpbroadcastd	xmm13, DWORD PTR [rcx+52]
        vpbroadcastd	xmm14, DWORD PTR [rcx+56]
        vpbroadcastd	xmm15, DWORD PTR [rcx+60]
        vpaddd	xmm12, xmm12, OWORD PTR [r14]
        vmovdqa	OWORD PTR [r11], xmm0
        vmovdqa	OWORD PTR [r11+16], xmm1
        vmovdqa	OWORD PTR [r11+32], xmm2
        vmovdqa	OWORD PTR [r11+48], xmm3
        vmovdqa	OWORD PTR [r11+64], xmm4
        vmovdqa	OWORD PTR [r11+80], xmm5
        vmovdqa	OWORD PTR [r11+96], xmm6
        vmovdqa	OWORD PTR [r11+112], xmm7
        vmovdqa	OWORD PTR [r11+128], xmm8
        vmovdqa	OWORD PTR [r11+144], xmm9
        vmovdqa	OWORD PTR [r11+160], xmm10
        vmovdqa	OWORD PTR [r11+176], xmm11
        vmovdqa	OWORD PTR [r11+192], xmm12
        vmovdqa	OWORD PTR [r11+208], xmm13
        vmovdqa	OWORD PTR [r11+224], xmm14
        vmovdqa	OWORD PTR [r11+240], xmm15
        mov	r10b, 10
L_chacha20_avx512vl_last_round:
        vpaddd	xmm0, xmm0, xmm4
        vpaddd	xmm1, xmm1, xmm5
        vpaddd	xmm2, xmm2, xmm6
        vpaddd	xmm3, xmm3, xmm7
        vpxord	xmm12, xmm12, xmm0
        vpxord	xmm13, xmm13, xmm1
        vpxord	xmm14, xmm14, xmm2
        vpxord	xmm15, xmm15, xmm3
        vprold	xmm12, xmm12, 16
        vprold	xmm13, xmm13, 16
        vprold	xmm14, xmm14, 16
        vprold	xmm15, xmm15, 16
        vpaddd	xmm8, xmm8, xmm12
        vpaddd	xmm9, xmm9, xmm13
        vpaddd	xmm10, xmm10, xmm14
        vpaddd	xmm11, xmm11, xmm15
        vpxord	xmm4, xmm4, xmm8
        vpxord	xmm5, xmm5, xmm9
        vpxord	xmm6, xmm6, xmm10
        vpxord	xmm7, xmm7, xmm11
        vprold	xmm4, xmm4, 12
        vprold	xmm5, xmm5, 12
        vprold	xmm6, xmm6, 12
        vprold	xmm7, xmm7, 12
        vpaddd	xmm0, xmm0, xmm4
        vpaddd	xmm1, xmm1, xmm5
        vpaddd	xmm2, xmm2, xmm6
        vpaddd	xmm3, xmm3, xmm7
        vpxord	xmm12, xmm12, xmm0
        vpxord	xmm13, xmm13, xmm1
        vpxord	xmm14, xmm14, xmm2
        vpxord	xmm15, xmm15, xmm3
        vprold	xmm12, xmm12, 8
        vprold	xmm13, xmm13, 8
        vprold	xmm14, xmm14, 8
        vprold	xmm15, xmm15, 8
        vpaddd	xmm8, xmm8, xmm12
        vpaddd	xmm9, xmm9, xmm13
        vpaddd	xmm10, xmm10, xmm14
        vpaddd	xmm11, xmm11, xmm15
        vpxord	xmm4, xmm4, xmm8
        vpxord	xmm5, xmm5, xmm9
        vpxord	xmm6, xmm6, xmm10
        vpxord	xmm7, xmm7, xmm11
        vprold	xmm4, xmm4, 7
        vprold	xmm5, xmm5, 7
        vprold	xmm6, xmm6, 7
        vprold	xmm7, xmm7, 7
        vpaddd	xmm0, xmm0, xmm5
        vpaddd	xmm1, xmm1, xmm6
        vpaddd	xmm2, xmm2, xmm7
        vpaddd	xmm3, xmm3, xmm4
        vpxord	xmm15, xmm15, xmm0
        vpxord	xmm12, xmm12, xmm1
        vpxord	xmm13, xmm13, xmm2
        vpxord	xmm14, xmm14, xmm3
        vprold	xmm15, xmm15, 16
        vprold	xmm12, xmm12, 16
        vprold	xmm13, xmm13, 16
        vprold	xmm14, xmm14, 16
        vpaddd	xmm10, xmm10, xmm15
        vpaddd	xmm11, xmm11, xmm12
        vpaddd	xmm8, xmm8, xmm13
        vpaddd	xmm9, xmm9, xmm14
        vpxord	xmm5, xmm5, xmm10
        vpxord	xmm6, xmm6, xmm11
        vpxord	xmm7, xmm7, xmm8
        vpxord	xmm4, xmm4, xmm9
        vprold	xmm5, xmm5, 12
        vprold	xmm6, xmm6, 12
        vprold	xmm7, xmm7, 12
        vprold	xmm4, xmm4, 12
        vpaddd	xmm0, xmm0, xmm5
        vpaddd	xmm1, xmm1, xmm6
        vpaddd	xmm2, xmm2, xmm7
        vpaddd	xmm3, xmm3, xmm4
        vpxord	xmm15, xmm15, xmm0
        vpxord	xmm12, xmm12, xmm1
        vpxord	xmm13, xmm13, xmm2
        vpxord	xmm14, xmm14, xmm3
        vprold	xmm15, xmm15, 8
        vprold	xmm12, xmm12, 8
        vprold	xmm13, xmm13, 8
        vprold	xmm14, xmm14, 8
        vpaddd	xmm10, xmm10, xmm15
        vpaddd	xmm11, xmm11, xmm12
        vpaddd	xmm8, xmm8, xmm13
        vpaddd	xmm9, xmm9, xmm14
        vpxord	xmm5, xmm5, xmm10
        vpxord	xmm6, xmm6, xmm11
        vpxord	xmm7, xmm7, xmm8
        vpxord	xmm4, xmm4, xmm9
        vprold	xmm5, xmm5, 7
        vprold	xmm6, xmm6, 7
        vprold	xmm7, xmm7, 7
        vprold	xmm4, xmm4, 7
        dec	r10b
        jnz	L_chacha20_avx512vl_last_round
        vpaddd	xmm0, xmm0, OWORD PTR [r11]
        vpaddd	xmm1, xmm1, OWORD PTR [r11+16]
        vpaddd	xmm2, xmm2, OWORD PTR [r11+32]
        vpaddd	xmm3, xmm3, OWORD PTR [r11+48]
        vpaddd	xmm4, xmm4, OWORD PTR [r11+64]
        vpaddd	xmm5, xmm5, OWORD PTR [r11+80]
        vpaddd	xmm6, xmm6, OWORD PTR [r11+96]
        vpaddd	xmm7, xmm7, OWORD PTR [r11+112]
        vpaddd	xmm8, xmm8, OWORD PTR [r11+128]
        vpaddd	xmm9, xmm9, OWORD PTR [r11+144]
        vpaddd	xmm10, xmm10, OWORD PTR [r11+160]
        vpaddd	xmm11, xmm11, OWORD PTR [r11+176]
        vpaddd	xmm12, xmm12, OWORD PTR [r11+192]
        vpaddd	xmm13, xmm13, OWORD PTR [r11+208]
        vpaddd	xmm14, xmm14, OWORD PTR [r11+224]
        vpaddd	xmm15, xmm15, OWORD PTR [r11+240]
        vmovdqa	OWORD PTR [r12], xmm8
        vmovdqa	OWORD PTR [r12+16], xmm9
        vmovdqa	OWORD PTR [r12+32], xmm10
        vmovdqa	OWORD PTR [r12+48], xmm11
        vmovdqa	OWORD PTR [r12+64], xmm12
        vmovdqa	OWORD PTR [r12+80], xmm13
        vmovdqa	OWORD PTR [r12+96], xmm14
        vmovdqa	OWORD PTR [r12+112], xmm15
        vpunpckldq	xmm8, xmm0, xmm1
        vpunpckldq	xmm9, xmm2, xmm3
        vpunpckhdq	xmm12, xmm0, xmm1
        vpunpckhdq	xmm13, xmm2, xmm3
        vpunpckldq	xmm10, xmm4, xmm5
        vpunpckldq	xmm11, xmm6, xmm7
        vpunpckhdq	xmm14, xmm4, xmm5
        vpunpckhdq	xmm15, xmm6, xmm7
        vpunpcklqdq	xmm0, xmm8, xmm9
        vpunpcklqdq	xmm1, xmm10, xmm11
        vpunpckhqdq	xmm2, xmm8, xmm9
        vpunpckhqdq	xmm3, xmm10, xmm11
        vpunpcklqdq	xmm4, xmm12, xmm13
        vpunpcklqdq	xmm5, xmm14, xmm15
        vpunpckhqdq	xmm6, xmm12, xmm13
        vpunpckhqdq	xmm7, xmm14, xmm15
        vmovdqu	OWORD PTR [r11], xmm0
        vmovdqu	OWORD PTR [r11+16], xmm1
        vmovdqu	OWORD PTR [r11+64], xmm2
        vmovdqu	OWORD PTR [r11+80], xmm3
        vmovdqu	OWORD PTR [r11+128], xmm4
        vmovdqu	OWORD PTR [r11+144], xmm5
        vmovdqu	OWORD PTR [r11+192], xmm6
        vmovdqu	OWORD PTR [r11+208], xmm7
        vmovdqa	xmm0, OWORD PTR [r12]
        vmovdqa	xmm1, OWORD PTR [r12+16]
        vmovdqa	xmm2, OWORD PTR [r12+32]
        vmovdqa	xmm3, OWORD PTR [r12+48]
        vmovdqa	xmm4, OWORD PTR [r12+64]
        vmovdqa	xmm5, OWORD PTR [r12+80]
        vmovdqa	xmm6, OWORD PTR [r12+96]
        vmovdqa	xmm7, OWORD PTR [r12+112]
        vpunpckldq	xmm8, xmm0, xmm1
        vpunpckldq	xmm9, xmm2, xmm3
        vpunpckhdq	xmm12, xmm0, xmm1
        vpunpckhdq	xmm13, xmm2, xmm3
        vpunpckldq	xmm10, xmm4, xmm5
        vpunpckldq	xmm11, xmm6, xmm7
        vpunpckhdq	xmm14, xmm4, xmm5
        vpunpckhdq	xmm15, xmm6, xmm7
        vpunpcklqdq	xmm0, xmm8, xmm9
        vpunpcklqdq	xmm1, xmm10, xmm11
        vpunpckhqdq	xmm2, xmm8, xmm9
        vpunpckhqdq	xmm3, xmm10, xmm11
        vpunpcklqdq	xmm4, xmm12, xmm13
        vpunpcklqdq	xmm5, xmm14, xmm15
        vpunpckhqdq	xmm6, xmm12, xmm13
        vpunpckhqdq	xmm7, xmm14, xmm15
        vmovdqu	OWORD PTR [r11+32], xmm0
        vmovdqu	OWORD PTR [r11+48], xmm1
        vmovdqu	OWORD PTR [r11+96], xmm2
        vmovdqu	OWORD PTR [r11+112], xmm3
        vmovdqu	OWORD PTR [r11+160], xmm4
        vmovdqu	OWORD PTR [r11+176], xmm5
        vmovdqu	OWORD PTR [r11+224], xmm6
        vmovdqu	OWORD PTR [r11+240], xmm7
        cmp	r9d, 64
        jl	L_chacha20_avx512vl_last_fdone
L_chacha20_avx512vl_last_fstart:
        vmovdqu	xmm0, OWORD PTR [rdx]
        vpxor	xmm0, xmm0, [r11]
        vmovdqu	OWORD PTR [r8], xmm0
        vmovdqu	xmm0, OWORD PTR [rdx+16]
        vpxor	xmm0, xmm0, [r11+16]
        vmovdqu	OWORD PTR [r8+16], xmm0
        vmovdqu	xmm0, OWORD PTR [rdx+32]
        vpxor	xmm0, xmm0, [r11+32]
        vmovdqu	OWORD PTR [r8+32], xmm0
        vmovdqu	xmm0, OWORD PTR [rdx+48]
        vpxor	xmm0, xmm0, [r11+48]
        vmovdqu	OWORD PTR [r8+48], xmm0
        add	DWORD PTR [rcx+48], 1
        sub	r9d, 64
        add	rdx, 64
        add	r8, 64
        add	r11, 64
        cmp	r9d, 64
        jge	L_chacha20_avx512vl_last_fstart
L_chacha20_avx512vl_last_fdone:
        cmp	r9d, 0
        je	L_chacha20_avx512vl_last_done
        lea	r12, QWORD PTR [rcx+80]
        vmovdqu	xmm0, OWORD PTR [r11]
        vmovdqu	OWORD PTR [r12], xmm0
        vmovdqu	xmm0, OWORD PTR [r11+16]
        vmovdqu	OWORD PTR [r12+16], xmm0
        vmovdqu	xmm0, OWORD PTR [r11+32]
        vmovdqu	OWORD PTR [r12+32], xmm0
        vmovdqu	xmm0, OWORD PTR [r11+48]
        vmovdqu	OWORD PTR [r12+48], xmm0
        add	DWORD PTR [rcx+48], 1
        mov	r10d, r9d
        xor	r13, r13
        and	r10d, 7
        jz	L_chacha20_avx512vl_last_start64
L_chacha20_avx512vl_last_start8:
        movzx	eax, BYTE PTR [r12+r13]
        xor	al, BYTE PTR [rdx+r13]
        mov	BYTE PTR [r8+r13], al
        inc	r13d
        cmp	r13d, r10d
        jne	L_chacha20_avx512vl_last_start8
        je	L_chacha20_avx512vl_last_end64
L_chacha20_avx512vl_last_start64:
        mov	rax, QWORD PTR [r12+r13]
        xor	rax, QWORD PTR [rdx+r13]
        mov	QWORD PTR [r8+r13], rax
        add	r13d, 8
L_chacha20_avx512vl_last_end64:
        cmp	r13d, r9d
        jne	L_chacha20_avx512vl_last_start64
        mov	r10d, 64
        sub	r10d, r13d
        mov	DWORD PTR [rcx+76], r10d
L_chacha20_avx512vl_last_done:
        vmovdqu	xmm6, OWORD PTR [rsp+400]
        vmovdqu	xmm7, OWORD PTR [rsp+416]
        vmovdqu	xmm8, OWORD PTR [rsp+432]
        vmovdqu	xmm9, OWORD PTR [rsp+448]
        vmovdqu	xmm10, OWORD PTR [rsp+464]
        vmovdqu	xmm11, OWORD PTR [rsp+480]
        vmovdqu	xmm12, OWORD PTR [rsp+496]
        vmovdqu	xmm13, OWORD PTR [rsp+512]
        vmovdqu	xmm14, OWORD PTR [rsp+528]
        vmovdqu	xmm15, OWORD PTR [rsp+544]
        add	rsp, 560
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
chacha_encrypt_avx512vl ENDP
_TEXT ENDS
ENDIF
IFDEF HAVE_INTEL_AVX512
_DATA SEGMENT
ALIGN 16
L_chacha20_avx512_add QWORD 0000000100000000h, 0000000300000002h
        QWORD 0000000500000004h, 0000000700000006h
        QWORD 0000000900000008h, 0000000b0000000ah
        QWORD 0000000d0000000ch, 0000000f0000000eh
ptr_L_chacha20_avx512_add QWORD L_chacha20_avx512_add
_DATA ENDS
_TEXT SEGMENT READONLY PARA
chacha_encrypt_avx512 PROC
        sub	rsp, 168
        vmovdqu	OWORD PTR [rsp+8], xmm6
        vmovdqu	OWORD PTR [rsp+24], xmm7
        vmovdqu	OWORD PTR [rsp+40], xmm8
        vmovdqu	OWORD PTR [rsp+56], xmm9
        vmovdqu	OWORD PTR [rsp+72], xmm10
        vmovdqu	OWORD PTR [rsp+88], xmm11
        vmovdqu	OWORD PTR [rsp+104], xmm12
        vmovdqu	OWORD PTR [rsp+120], xmm13
        vmovdqu	OWORD PTR [rsp+136], xmm14
        vmovdqu	OWORD PTR [rsp+152], xmm15
        mov	r10, QWORD PTR [ptr_L_chacha20_avx512_add]
        cmp	r9d, 1024
        jl	L_chacha20_avx512_end512
L_chacha20_avx512_start512:
        vpbroadcastd	zmm0, DWORD PTR [rcx]
        vpbroadcastd	zmm1, DWORD PTR [rcx+4]
        vpbroadcastd	zmm2, DWORD PTR [rcx+8]
        vpbroadcastd	zmm3, DWORD PTR [rcx+12]
        vpbroadcastd	zmm4, DWORD PTR [rcx+16]
        vpbroadcastd	zmm5, DWORD PTR [rcx+20]
        vpbroadcastd	zmm6, DWORD PTR [rcx+24]
        vpbroadcastd	zmm7, DWORD PTR [rcx+28]
        vpbroadcastd	zmm8, DWORD PTR [rcx+32]
        vpbroadcastd	zmm9, DWORD PTR [rcx+36]
        vpbroadcastd	zmm10, DWORD PTR [rcx+40]
        vpbroadcastd	zmm11, DWORD PTR [rcx+44]
        vpbroadcastd	zmm13, DWORD PTR [rcx+52]
        vpbroadcastd	zmm14, DWORD PTR [rcx+56]
        vpbroadcastd	zmm15, DWORD PTR [rcx+60]
        vpbroadcastd	zmm12, DWORD PTR [rcx+48]
        vpaddd	zmm12, zmm12, [r10]
        mov	al, 10
L_chacha20_avx512_loop512:
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vprold	zmm15, zmm15, 16
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 12
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vprold	zmm15, zmm15, 8
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 7
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 16
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vprold	zmm4, zmm4, 12
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 8
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vprold	zmm4, zmm4, 7
        dec	al
        jnz	L_chacha20_avx512_loop512
        vpaddd	zmm0, zmm0, DWORD BCST [rcx]
        vpaddd	zmm1, zmm1, DWORD BCST [rcx+4]
        vpaddd	zmm2, zmm2, DWORD BCST [rcx+8]
        vpaddd	zmm3, zmm3, DWORD BCST [rcx+12]
        vpaddd	zmm4, zmm4, DWORD BCST [rcx+16]
        vpaddd	zmm5, zmm5, DWORD BCST [rcx+20]
        vpaddd	zmm6, zmm6, DWORD BCST [rcx+24]
        vpaddd	zmm7, zmm7, DWORD BCST [rcx+28]
        vpaddd	zmm8, zmm8, DWORD BCST [rcx+32]
        vpaddd	zmm9, zmm9, DWORD BCST [rcx+36]
        vpaddd	zmm10, zmm10, DWORD BCST [rcx+40]
        vpaddd	zmm11, zmm11, DWORD BCST [rcx+44]
        vpaddd	zmm13, zmm13, DWORD BCST [rcx+52]
        vpaddd	zmm14, zmm14, DWORD BCST [rcx+56]
        vpaddd	zmm15, zmm15, DWORD BCST [rcx+60]
        vpbroadcastd	zmm16, DWORD PTR [rcx+48]
        vpaddd	zmm16, zmm16, [r10]
        vpaddd	zmm12, zmm12, zmm16
        vpunpckldq	zmm16, zmm0, zmm1
        vpunpckhdq	zmm17, zmm0, zmm1
        vpunpckldq	zmm18, zmm2, zmm3
        vpunpckhdq	zmm19, zmm2, zmm3
        vpunpckldq	zmm20, zmm4, zmm5
        vpunpckhdq	zmm21, zmm4, zmm5
        vpunpckldq	zmm22, zmm6, zmm7
        vpunpckhdq	zmm23, zmm6, zmm7
        vpunpckldq	zmm24, zmm8, zmm9
        vpunpckhdq	zmm25, zmm8, zmm9
        vpunpckldq	zmm26, zmm10, zmm11
        vpunpckhdq	zmm27, zmm10, zmm11
        vpunpckldq	zmm28, zmm12, zmm13
        vpunpckhdq	zmm29, zmm12, zmm13
        vpunpckldq	zmm30, zmm14, zmm15
        vpunpckhdq	zmm31, zmm14, zmm15
        vpunpcklqdq	zmm0, zmm16, zmm18
        vpunpckhqdq	zmm1, zmm16, zmm18
        vpunpcklqdq	zmm2, zmm17, zmm19
        vpunpckhqdq	zmm3, zmm17, zmm19
        vpunpcklqdq	zmm4, zmm20, zmm22
        vpunpckhqdq	zmm5, zmm20, zmm22
        vpunpcklqdq	zmm6, zmm21, zmm23
        vpunpckhqdq	zmm7, zmm21, zmm23
        vpunpcklqdq	zmm8, zmm24, zmm26
        vpunpckhqdq	zmm9, zmm24, zmm26
        vpunpcklqdq	zmm10, zmm25, zmm27
        vpunpckhqdq	zmm11, zmm25, zmm27
        vpunpcklqdq	zmm12, zmm28, zmm30
        vpunpckhqdq	zmm13, zmm28, zmm30
        vpunpcklqdq	zmm14, zmm29, zmm31
        vpunpckhqdq	zmm15, zmm29, zmm31
        vshufi32x4	zmm16, zmm0, zmm4, 68
        vshufi32x4	zmm17, zmm0, zmm4, 238
        vshufi32x4	zmm18, zmm8, zmm12, 68
        vshufi32x4	zmm19, zmm8, zmm12, 238
        vshufi32x4	zmm20, zmm16, zmm18, 136
        vshufi32x4	zmm21, zmm16, zmm18, 221
        vshufi32x4	zmm22, zmm17, zmm19, 136
        vshufi32x4	zmm23, zmm17, zmm19, 221
        vpxord	zmm20, zmm20, [rdx]
        vmovdqu64	[r8], zmm20
        vpxord	zmm21, zmm21, [rdx+256]
        vmovdqu64	[r8+256], zmm21
        vpxord	zmm22, zmm22, [rdx+512]
        vmovdqu64	[r8+512], zmm22
        vpxord	zmm23, zmm23, [rdx+768]
        vmovdqu64	[r8+768], zmm23
        vshufi32x4	zmm16, zmm1, zmm5, 68
        vshufi32x4	zmm17, zmm1, zmm5, 238
        vshufi32x4	zmm18, zmm9, zmm13, 68
        vshufi32x4	zmm19, zmm9, zmm13, 238
        vshufi32x4	zmm20, zmm16, zmm18, 136
        vshufi32x4	zmm21, zmm16, zmm18, 221
        vshufi32x4	zmm22, zmm17, zmm19, 136
        vshufi32x4	zmm23, zmm17, zmm19, 221
        vpxord	zmm20, zmm20, [rdx+64]
        vmovdqu64	[r8+64], zmm20
        vpxord	zmm21, zmm21, [rdx+320]
        vmovdqu64	[r8+320], zmm21
        vpxord	zmm22, zmm22, [rdx+576]
        vmovdqu64	[r8+576], zmm22
        vpxord	zmm23, zmm23, [rdx+832]
        vmovdqu64	[r8+832], zmm23
        vshufi32x4	zmm16, zmm2, zmm6, 68
        vshufi32x4	zmm17, zmm2, zmm6, 238
        vshufi32x4	zmm18, zmm10, zmm14, 68
        vshufi32x4	zmm19, zmm10, zmm14, 238
        vshufi32x4	zmm20, zmm16, zmm18, 136
        vshufi32x4	zmm21, zmm16, zmm18, 221
        vshufi32x4	zmm22, zmm17, zmm19, 136
        vshufi32x4	zmm23, zmm17, zmm19, 221
        vpxord	zmm20, zmm20, [rdx+128]
        vmovdqu64	[r8+128], zmm20
        vpxord	zmm21, zmm21, [rdx+384]
        vmovdqu64	[r8+384], zmm21
        vpxord	zmm22, zmm22, [rdx+640]
        vmovdqu64	[r8+640], zmm22
        vpxord	zmm23, zmm23, [rdx+896]
        vmovdqu64	[r8+896], zmm23
        vshufi32x4	zmm16, zmm3, zmm7, 68
        vshufi32x4	zmm17, zmm3, zmm7, 238
        vshufi32x4	zmm18, zmm11, zmm15, 68
        vshufi32x4	zmm19, zmm11, zmm15, 238
        vshufi32x4	zmm20, zmm16, zmm18, 136
        vshufi32x4	zmm21, zmm16, zmm18, 221
        vshufi32x4	zmm22, zmm17, zmm19, 136
        vshufi32x4	zmm23, zmm17, zmm19, 221
        vpxord	zmm20, zmm20, [rdx+192]
        vmovdqu64	[r8+192], zmm20
        vpxord	zmm21, zmm21, [rdx+448]
        vmovdqu64	[r8+448], zmm21
        vpxord	zmm22, zmm22, [rdx+704]
        vmovdqu64	[r8+704], zmm22
        vpxord	zmm23, zmm23, [rdx+960]
        vmovdqu64	[r8+960], zmm23
        add	rdx, 1024
        add	r8, 1024
        add	DWORD PTR [rcx+48], 16
        sub	r9d, 1024
        cmp	r9d, 1024
        jge	L_chacha20_avx512_start512
L_chacha20_avx512_end512:
        call	chacha_encrypt_avx2
        vzeroupper
        vmovdqu	xmm6, OWORD PTR [rsp+8]
        vmovdqu	xmm7, OWORD PTR [rsp+24]
        vmovdqu	xmm8, OWORD PTR [rsp+40]
        vmovdqu	xmm9, OWORD PTR [rsp+56]
        vmovdqu	xmm10, OWORD PTR [rsp+72]
        vmovdqu	xmm11, OWORD PTR [rsp+88]
        vmovdqu	xmm12, OWORD PTR [rsp+104]
        vmovdqu	xmm13, OWORD PTR [rsp+120]
        vmovdqu	xmm14, OWORD PTR [rsp+136]
        vmovdqu	xmm15, OWORD PTR [rsp+152]
        add	rsp, 168
        ret
chacha_encrypt_avx512 ENDP
_TEXT ENDS
ENDIF
IFDEF HAVE_INTEL_AVX512
_DATA SEGMENT
ALIGN 16
L_chacha20_poly1305_add QWORD 0000000100000000h, 0000000300000002h
ptr_L_chacha20_poly1305_add QWORD L_chacha20_poly1305_add
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_chacha20_poly1305_four QWORD 0000000400000004h, 0000000400000004h
ptr_L_chacha20_poly1305_four QWORD L_chacha20_poly1305_four
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_chacha20_poly1305_mask QWORD 0000000003ffffffh, 0000000003ffffffh
        QWORD 0000000003ffffffh, 0000000003ffffffh
ptr_L_chacha20_poly1305_mask QWORD L_chacha20_poly1305_mask
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_chacha20_poly1305_hibit QWORD 0000000001000000h, 0000000001000000h
        QWORD 0000000001000000h, 0000000001000000h
ptr_L_chacha20_poly1305_hibit QWORD L_chacha20_poly1305_hibit
_DATA ENDS
_TEXT SEGMENT READONLY PARA
chacha20_poly1305_avx512 PROC
        push	rdi
        push	rsi
        push	r12
        push	r13
        push	r14
        push	r15
        push	rbx
        push	rbp
        mov	rdi, rcx
        mov	rsi, rdx
        mov	rdx, r8
        mov	rcx, r9
        mov	rax, QWORD PTR [rsp+104]
        sub	rsp, 880
        vmovdqu	OWORD PTR [rsp+720], xmm6
        vmovdqu	OWORD PTR [rsp+736], xmm7
        vmovdqu	OWORD PTR [rsp+752], xmm8
        vmovdqu	OWORD PTR [rsp+768], xmm9
        vmovdqu	OWORD PTR [rsp+784], xmm10
        vmovdqu	OWORD PTR [rsp+800], xmm11
        vmovdqu	OWORD PTR [rsp+816], xmm12
        vmovdqu	OWORD PTR [rsp+832], xmm13
        vmovdqu	OWORD PTR [rsp+848], xmm14
        vmovdqu	OWORD PTR [rsp+864], xmm15
        mov	r10, QWORD PTR [ptr_L_chacha20_poly1305_add]
        mov	r11, QWORD PTR [ptr_L_chacha20_poly1305_four]
        mov	r12, QWORD PTR [ptr_L_chacha20_poly1305_mask]
        mov	r13, QWORD PTR [ptr_L_chacha20_poly1305_hibit]
        mov	r14, rsp
        add	r14, 15
        and	r14, -16
        lea	r15, QWORD PTR [rsp+272]
        add	r15, 15
        and	r15, -16
        lea	rbx, QWORD PTR [rsp+416]
        lea	rbp, QWORD PTR [rsp+576]
        vpxor	xmm15, xmm15, xmm15
        lea	r9, QWORD PTR [rsi+64]
        vmovdqu	ymm0, YMMWORD PTR [r9]
        vmovdqu	ymm1, YMMWORD PTR [r9+32]
        vmovdqu	ymm2, YMMWORD PTR [r9+64]
        vmovdqu	ymm3, YMMWORD PTR [r9+96]
        vmovdqu	ymm4, YMMWORD PTR [r9+128]
        vmovdqu	ymm13, YMMWORD PTR [rsi+320]
        vpermq	ymm5, ymm13, 0
        vpsrlq	ymm14, ymm13, 32
        vpermq	ymm7, ymm13, 85
        vpermq	ymm9, ymm13, 170
        vpermq	ymm6, ymm14, 0
        vpermq	ymm8, ymm14, 85
        vpslld	ymm10, ymm6, 2
        vpslld	ymm11, ymm7, 2
        vpslld	ymm12, ymm8, 2
        vpslld	ymm13, ymm9, 2
        vpaddq	ymm10, ymm6, ymm10
        vpaddq	ymm11, ymm7, ymm11
        vpaddq	ymm12, ymm8, ymm12
        vpaddq	ymm13, ymm9, ymm13
        vmovdqu	YMMWORD PTR [rbp], ymm10
        vmovdqu	YMMWORD PTR [rbp+32], ymm11
        vmovdqu	YMMWORD PTR [rbp+64], ymm12
        vmovdqu	YMMWORD PTR [rbp+96], ymm13
        vmovdqu	YMMWORD PTR [rbx], ymm5
        vmovdqu	YMMWORD PTR [rbx+32], ymm6
        vmovdqu	YMMWORD PTR [rbx+64], ymm7
        vmovdqu	YMMWORD PTR [rbx+96], ymm8
        vmovdqu	YMMWORD PTR [rbx+128], ymm9
        vmovdqu	ymm14, YMMWORD PTR [r12]
        vpbroadcastd	xmm16, DWORD PTR [rdi]
        vpbroadcastd	xmm17, DWORD PTR [rdi+4]
        vpbroadcastd	xmm18, DWORD PTR [rdi+8]
        vpbroadcastd	xmm19, DWORD PTR [rdi+12]
        vpbroadcastd	xmm20, DWORD PTR [rdi+16]
        vpbroadcastd	xmm21, DWORD PTR [rdi+20]
        vpbroadcastd	xmm22, DWORD PTR [rdi+24]
        vpbroadcastd	xmm23, DWORD PTR [rdi+28]
        vpbroadcastd	xmm24, DWORD PTR [rdi+32]
        vpbroadcastd	xmm25, DWORD PTR [rdi+36]
        vpbroadcastd	xmm26, DWORD PTR [rdi+40]
        vpbroadcastd	xmm27, DWORD PTR [rdi+44]
        vpbroadcastd	xmm28, DWORD PTR [rdi+48]
        vpbroadcastd	xmm29, DWORD PTR [rdi+52]
        vpbroadcastd	xmm30, DWORD PTR [rdi+56]
        vpbroadcastd	xmm31, DWORD PTR [rdi+60]
        vpaddd	xmm28, xmm28, OWORD PTR [r10]
        vmovdqa64	[r14], xmm16
        vmovdqa64	[r14+16], xmm17
        vmovdqa64	[r14+32], xmm18
        vmovdqa64	[r14+48], xmm19
        vmovdqa64	[r14+64], xmm20
        vmovdqa64	[r14+80], xmm21
        vmovdqa64	[r14+96], xmm22
        vmovdqa64	[r14+112], xmm23
        vmovdqa64	[r14+128], xmm24
        vmovdqa64	[r14+144], xmm25
        vmovdqa64	[r14+160], xmm26
        vmovdqa64	[r14+176], xmm27
        vmovdqa64	[r14+192], xmm28
        vmovdqa64	[r14+208], xmm29
        vmovdqa64	[r14+224], xmm30
        vmovdqa64	[r14+240], xmm31
        mov	r8b, 10
L_chacha20_poly1305_rounds:
        vpaddd	xmm16, xmm16, xmm20
        vpaddd	xmm17, xmm17, xmm21
        vpaddd	xmm18, xmm18, xmm22
        vpaddd	xmm19, xmm19, xmm23
        vpxord	xmm28, xmm28, xmm16
        vpxord	xmm29, xmm29, xmm17
        vpxord	xmm30, xmm30, xmm18
        vpxord	xmm31, xmm31, xmm19
        vprold	xmm28, xmm28, 16
        vprold	xmm29, xmm29, 16
        vprold	xmm30, xmm30, 16
        vprold	xmm31, xmm31, 16
        vpaddd	xmm24, xmm24, xmm28
        vpaddd	xmm25, xmm25, xmm29
        vpaddd	xmm26, xmm26, xmm30
        vpaddd	xmm27, xmm27, xmm31
        vpxord	xmm20, xmm20, xmm24
        vpxord	xmm21, xmm21, xmm25
        vpxord	xmm22, xmm22, xmm26
        vpxord	xmm23, xmm23, xmm27
        vprold	xmm20, xmm20, 12
        vprold	xmm21, xmm21, 12
        vprold	xmm22, xmm22, 12
        vprold	xmm23, xmm23, 12
        vpaddd	xmm16, xmm16, xmm20
        vpaddd	xmm17, xmm17, xmm21
        vpaddd	xmm18, xmm18, xmm22
        vpaddd	xmm19, xmm19, xmm23
        vpxord	xmm28, xmm28, xmm16
        vpxord	xmm29, xmm29, xmm17
        vpxord	xmm30, xmm30, xmm18
        vpxord	xmm31, xmm31, xmm19
        vprold	xmm28, xmm28, 8
        vprold	xmm29, xmm29, 8
        vprold	xmm30, xmm30, 8
        vprold	xmm31, xmm31, 8
        vpaddd	xmm24, xmm24, xmm28
        vpaddd	xmm25, xmm25, xmm29
        vpaddd	xmm26, xmm26, xmm30
        vpaddd	xmm27, xmm27, xmm31
        vpxord	xmm20, xmm20, xmm24
        vpxord	xmm21, xmm21, xmm25
        vpxord	xmm22, xmm22, xmm26
        vpxord	xmm23, xmm23, xmm27
        vprold	xmm20, xmm20, 7
        vprold	xmm21, xmm21, 7
        vprold	xmm22, xmm22, 7
        vprold	xmm23, xmm23, 7
        vpaddd	xmm16, xmm16, xmm21
        vpaddd	xmm17, xmm17, xmm22
        vpaddd	xmm18, xmm18, xmm23
        vpaddd	xmm19, xmm19, xmm20
        vpxord	xmm31, xmm31, xmm16
        vpxord	xmm28, xmm28, xmm17
        vpxord	xmm29, xmm29, xmm18
        vpxord	xmm30, xmm30, xmm19
        vprold	xmm31, xmm31, 16
        vprold	xmm28, xmm28, 16
        vprold	xmm29, xmm29, 16
        vprold	xmm30, xmm30, 16
        vpaddd	xmm26, xmm26, xmm31
        vpaddd	xmm27, xmm27, xmm28
        vpaddd	xmm24, xmm24, xmm29
        vpaddd	xmm25, xmm25, xmm30
        vpxord	xmm21, xmm21, xmm26
        vpxord	xmm22, xmm22, xmm27
        vpxord	xmm23, xmm23, xmm24
        vpxord	xmm20, xmm20, xmm25
        vprold	xmm21, xmm21, 12
        vprold	xmm22, xmm22, 12
        vprold	xmm23, xmm23, 12
        vprold	xmm20, xmm20, 12
        vpaddd	xmm16, xmm16, xmm21
        vpaddd	xmm17, xmm17, xmm22
        vpaddd	xmm18, xmm18, xmm23
        vpaddd	xmm19, xmm19, xmm20
        vpxord	xmm31, xmm31, xmm16
        vpxord	xmm28, xmm28, xmm17
        vpxord	xmm29, xmm29, xmm18
        vpxord	xmm30, xmm30, xmm19
        vprold	xmm31, xmm31, 8
        vprold	xmm28, xmm28, 8
        vprold	xmm29, xmm29, 8
        vprold	xmm30, xmm30, 8
        vpaddd	xmm26, xmm26, xmm31
        vpaddd	xmm27, xmm27, xmm28
        vpaddd	xmm24, xmm24, xmm29
        vpaddd	xmm25, xmm25, xmm30
        vpxord	xmm21, xmm21, xmm26
        vpxord	xmm22, xmm22, xmm27
        vpxord	xmm23, xmm23, xmm24
        vpxord	xmm20, xmm20, xmm25
        vprold	xmm21, xmm21, 7
        vprold	xmm22, xmm22, 7
        vprold	xmm23, xmm23, 7
        vprold	xmm20, xmm20, 7
        dec	r8b
        jnz	L_chacha20_poly1305_rounds
        vpaddd	xmm16, xmm16, OWORD PTR [r14]
        vpaddd	xmm17, xmm17, OWORD PTR [r14+16]
        vpaddd	xmm18, xmm18, OWORD PTR [r14+32]
        vpaddd	xmm19, xmm19, OWORD PTR [r14+48]
        vpaddd	xmm20, xmm20, OWORD PTR [r14+64]
        vpaddd	xmm21, xmm21, OWORD PTR [r14+80]
        vpaddd	xmm22, xmm22, OWORD PTR [r14+96]
        vpaddd	xmm23, xmm23, OWORD PTR [r14+112]
        vpaddd	xmm24, xmm24, OWORD PTR [r14+128]
        vpaddd	xmm25, xmm25, OWORD PTR [r14+144]
        vpaddd	xmm26, xmm26, OWORD PTR [r14+160]
        vpaddd	xmm27, xmm27, OWORD PTR [r14+176]
        vpaddd	xmm28, xmm28, OWORD PTR [r14+192]
        vpaddd	xmm29, xmm29, OWORD PTR [r14+208]
        vpaddd	xmm30, xmm30, OWORD PTR [r14+224]
        vpaddd	xmm31, xmm31, OWORD PTR [r14+240]
        vmovdqa64	[r15], xmm24
        vmovdqa64	[r15+16], xmm25
        vmovdqa64	[r15+32], xmm26
        vmovdqa64	[r15+48], xmm27
        vmovdqa64	[r15+64], xmm28
        vmovdqa64	[r15+80], xmm29
        vmovdqa64	[r15+96], xmm30
        vmovdqa64	[r15+112], xmm31
        vpunpckldq	xmm24, xmm16, xmm17
        vpunpckldq	xmm25, xmm18, xmm19
        vpunpckhdq	xmm28, xmm16, xmm17
        vpunpckhdq	xmm29, xmm18, xmm19
        vpunpckldq	xmm26, xmm20, xmm21
        vpunpckldq	xmm27, xmm22, xmm23
        vpunpckhdq	xmm30, xmm20, xmm21
        vpunpckhdq	xmm31, xmm22, xmm23
        vpunpcklqdq	xmm16, xmm24, xmm25
        vpunpcklqdq	xmm17, xmm26, xmm27
        vpunpckhqdq	xmm18, xmm24, xmm25
        vpunpckhqdq	xmm19, xmm26, xmm27
        vpunpcklqdq	xmm20, xmm28, xmm29
        vpunpcklqdq	xmm21, xmm30, xmm31
        vpunpckhqdq	xmm22, xmm28, xmm29
        vpunpckhqdq	xmm23, xmm30, xmm31
        vmovdqu64	xmm24, [rdx]
        vmovdqu64	xmm25, [rdx+16]
        vmovdqu64	xmm26, [rdx+64]
        vmovdqu64	xmm27, [rdx+80]
        vmovdqu64	xmm28, [rdx+128]
        vmovdqu64	xmm29, [rdx+144]
        vmovdqu64	xmm30, [rdx+192]
        vmovdqu64	xmm31, [rdx+208]
        vpxord	xmm16, xmm16, xmm24
        vpxord	xmm17, xmm17, xmm25
        vpxord	xmm18, xmm18, xmm26
        vpxord	xmm19, xmm19, xmm27
        vpxord	xmm20, xmm20, xmm28
        vpxord	xmm21, xmm21, xmm29
        vpxord	xmm22, xmm22, xmm30
        vpxord	xmm23, xmm23, xmm31
        vmovdqu64	[rcx], xmm16
        vmovdqu64	[rcx+16], xmm17
        vmovdqu64	[rcx+64], xmm18
        vmovdqu64	[rcx+80], xmm19
        vmovdqu64	[rcx+128], xmm20
        vmovdqu64	[rcx+144], xmm21
        vmovdqu64	[rcx+192], xmm22
        vmovdqu64	[rcx+208], xmm23
        vmovdqa64	xmm16, [r15]
        vmovdqa64	xmm17, [r15+16]
        vmovdqa64	xmm18, [r15+32]
        vmovdqa64	xmm19, [r15+48]
        vmovdqa64	xmm20, [r15+64]
        vmovdqa64	xmm21, [r15+80]
        vmovdqa64	xmm22, [r15+96]
        vmovdqa64	xmm23, [r15+112]
        vpunpckldq	xmm24, xmm16, xmm17
        vpunpckldq	xmm25, xmm18, xmm19
        vpunpckhdq	xmm28, xmm16, xmm17
        vpunpckhdq	xmm29, xmm18, xmm19
        vpunpckldq	xmm26, xmm20, xmm21
        vpunpckldq	xmm27, xmm22, xmm23
        vpunpckhdq	xmm30, xmm20, xmm21
        vpunpckhdq	xmm31, xmm22, xmm23
        vpunpcklqdq	xmm16, xmm24, xmm25
        vpunpcklqdq	xmm17, xmm26, xmm27
        vpunpckhqdq	xmm18, xmm24, xmm25
        vpunpckhqdq	xmm19, xmm26, xmm27
        vpunpcklqdq	xmm20, xmm28, xmm29
        vpunpcklqdq	xmm21, xmm30, xmm31
        vpunpckhqdq	xmm22, xmm28, xmm29
        vpunpckhqdq	xmm23, xmm30, xmm31
        vmovdqu64	xmm24, [rdx+32]
        vmovdqu64	xmm25, [rdx+48]
        vmovdqu64	xmm26, [rdx+96]
        vmovdqu64	xmm27, [rdx+112]
        vmovdqu64	xmm28, [rdx+160]
        vmovdqu64	xmm29, [rdx+176]
        vmovdqu64	xmm30, [rdx+224]
        vmovdqu64	xmm31, [rdx+240]
        vpxord	xmm16, xmm16, xmm24
        vpxord	xmm17, xmm17, xmm25
        vpxord	xmm18, xmm18, xmm26
        vpxord	xmm19, xmm19, xmm27
        vpxord	xmm20, xmm20, xmm28
        vpxord	xmm21, xmm21, xmm29
        vpxord	xmm22, xmm22, xmm30
        vpxord	xmm23, xmm23, xmm31
        vmovdqu64	[rcx+32], xmm16
        vmovdqu64	[rcx+48], xmm17
        vmovdqu64	[rcx+96], xmm18
        vmovdqu64	[rcx+112], xmm19
        vmovdqu64	[rcx+160], xmm20
        vmovdqu64	[rcx+176], xmm21
        vmovdqu64	[rcx+224], xmm22
        vmovdqu64	[rcx+240], xmm23
        vmovdqa64	xmm28, [r14+192]
        vpaddd	xmm28, xmm28, OWORD PTR [r11]
        vmovdqa64	[r14+192], xmm28
        vmovdqa64	xmm16, [r14]
        vmovdqa64	xmm17, [r14+16]
        vmovdqa64	xmm18, [r14+32]
        vmovdqa64	xmm19, [r14+48]
        vmovdqa64	xmm20, [r14+64]
        vmovdqa64	xmm21, [r14+80]
        vmovdqa64	xmm22, [r14+96]
        vmovdqa64	xmm23, [r14+112]
        vmovdqa64	xmm24, [r14+128]
        vmovdqa64	xmm25, [r14+144]
        vmovdqa64	xmm26, [r14+160]
        vmovdqa64	xmm27, [r14+176]
        vmovdqa64	xmm28, [r14+192]
        vmovdqa64	xmm29, [r14+208]
        vmovdqa64	xmm30, [r14+224]
        vmovdqa64	xmm31, [r14+240]
        add	rdx, 256
        add	rcx, 256
        sub	eax, 256
        jz	L_chacha20_poly1305_epilogue
L_chacha20_poly1305_start:
        vpaddd	xmm16, xmm16, xmm20
        vpaddd	xmm17, xmm17, xmm21
        vpaddd	xmm18, xmm18, xmm22
        vpaddd	xmm19, xmm19, xmm23
        vpxord	xmm28, xmm28, xmm16
        vpxord	xmm29, xmm29, xmm17
        vpxord	xmm30, xmm30, xmm18
        vpxord	xmm31, xmm31, xmm19
        vprold	xmm28, xmm28, 16
        vprold	xmm29, xmm29, 16
        vprold	xmm30, xmm30, 16
        vprold	xmm31, xmm31, 16
        vpaddd	xmm24, xmm24, xmm28
        vpaddd	xmm25, xmm25, xmm29
        vpaddd	xmm26, xmm26, xmm30
        vpaddd	xmm27, xmm27, xmm31
        vpxord	xmm20, xmm20, xmm24
        vpxord	xmm21, xmm21, xmm25
        vpxord	xmm22, xmm22, xmm26
        vpxord	xmm23, xmm23, xmm27
        vprold	xmm20, xmm20, 12
        vprold	xmm21, xmm21, 12
        vprold	xmm22, xmm22, 12
        vprold	xmm23, xmm23, 12
        vpaddd	xmm16, xmm16, xmm20
        vpaddd	xmm17, xmm17, xmm21
        vpaddd	xmm18, xmm18, xmm22
        vpaddd	xmm19, xmm19, xmm23
        vpxord	xmm28, xmm28, xmm16
        vpxord	xmm29, xmm29, xmm17
        vpxord	xmm30, xmm30, xmm18
        vpxord	xmm31, xmm31, xmm19
        vprold	xmm28, xmm28, 8
        vprold	xmm29, xmm29, 8
        vprold	xmm30, xmm30, 8
        vprold	xmm31, xmm31, 8
        vpaddd	xmm24, xmm24, xmm28
        vpaddd	xmm25, xmm25, xmm29
        vpaddd	xmm26, xmm26, xmm30
        vpaddd	xmm27, xmm27, xmm31
        vpxord	xmm20, xmm20, xmm24
        vpxord	xmm21, xmm21, xmm25
        vpxord	xmm22, xmm22, xmm26
        vpxord	xmm23, xmm23, xmm27
        vprold	xmm20, xmm20, 7
        vprold	xmm21, xmm21, 7
        vprold	xmm22, xmm22, 7
        vprold	xmm23, xmm23, 7
        vpaddd	xmm16, xmm16, xmm21
        vpaddd	xmm17, xmm17, xmm22
        vpaddd	xmm18, xmm18, xmm23
        vpaddd	xmm19, xmm19, xmm20
        vpxord	xmm31, xmm31, xmm16
        vpxord	xmm28, xmm28, xmm17
        vpxord	xmm29, xmm29, xmm18
        vpxord	xmm30, xmm30, xmm19
        vprold	xmm31, xmm31, 16
        vprold	xmm28, xmm28, 16
        vprold	xmm29, xmm29, 16
        vprold	xmm30, xmm30, 16
        vpaddd	xmm26, xmm26, xmm31
        vpaddd	xmm27, xmm27, xmm28
        vpaddd	xmm24, xmm24, xmm29
        vpaddd	xmm25, xmm25, xmm30
        vpxord	xmm21, xmm21, xmm26
        vpxord	xmm22, xmm22, xmm27
        vpxord	xmm23, xmm23, xmm24
        vpxord	xmm20, xmm20, xmm25
        vprold	xmm21, xmm21, 12
        vprold	xmm22, xmm22, 12
        vprold	xmm23, xmm23, 12
        vprold	xmm20, xmm20, 12
        vpaddd	xmm16, xmm16, xmm21
        vpaddd	xmm17, xmm17, xmm22
        vpaddd	xmm18, xmm18, xmm23
        vpaddd	xmm19, xmm19, xmm20
        vpxord	xmm31, xmm31, xmm16
        vpxord	xmm28, xmm28, xmm17
        vpxord	xmm29, xmm29, xmm18
        vpxord	xmm30, xmm30, xmm19
        vprold	xmm31, xmm31, 8
        vprold	xmm28, xmm28, 8
        vprold	xmm29, xmm29, 8
        vprold	xmm30, xmm30, 8
        vpaddd	xmm26, xmm26, xmm31
        vpaddd	xmm27, xmm27, xmm28
        vpaddd	xmm24, xmm24, xmm29
        vpaddd	xmm25, xmm25, xmm30
        vpxord	xmm21, xmm21, xmm26
        vpxord	xmm22, xmm22, xmm27
        vpxord	xmm23, xmm23, xmm24
        vpxord	xmm20, xmm20, xmm25
        vprold	xmm21, xmm21, 7
        vprold	xmm22, xmm22, 7
        vprold	xmm23, xmm23, 7
        vprold	xmm20, xmm20, 7
        vpaddd	xmm16, xmm16, xmm20
        vpaddd	xmm17, xmm17, xmm21
        vpaddd	xmm18, xmm18, xmm22
        vpaddd	xmm19, xmm19, xmm23
        vpxord	xmm28, xmm28, xmm16
        vpxord	xmm29, xmm29, xmm17
        vpxord	xmm30, xmm30, xmm18
        vpxord	xmm31, xmm31, xmm19
        vprold	xmm28, xmm28, 16
        vprold	xmm29, xmm29, 16
        vprold	xmm30, xmm30, 16
        vprold	xmm31, xmm31, 16
        vpaddd	xmm24, xmm24, xmm28
        vpaddd	xmm25, xmm25, xmm29
        vpaddd	xmm26, xmm26, xmm30
        vpaddd	xmm27, xmm27, xmm31
        vpxord	xmm20, xmm20, xmm24
        vpxord	xmm21, xmm21, xmm25
        vpxord	xmm22, xmm22, xmm26
        vpxord	xmm23, xmm23, xmm27
        vprold	xmm20, xmm20, 12
        vprold	xmm21, xmm21, 12
        vprold	xmm22, xmm22, 12
        vprold	xmm23, xmm23, 12
        vpaddd	xmm16, xmm16, xmm20
        vpaddd	xmm17, xmm17, xmm21
        vpaddd	xmm18, xmm18, xmm22
        vpaddd	xmm19, xmm19, xmm23
        vpxord	xmm28, xmm28, xmm16
        vpxord	xmm29, xmm29, xmm17
        vpxord	xmm30, xmm30, xmm18
        vpxord	xmm31, xmm31, xmm19
        vprold	xmm28, xmm28, 8
        vprold	xmm29, xmm29, 8
        vprold	xmm30, xmm30, 8
        vprold	xmm31, xmm31, 8
        vpaddd	xmm24, xmm24, xmm28
        vpaddd	xmm25, xmm25, xmm29
        vpaddd	xmm26, xmm26, xmm30
        vpaddd	xmm27, xmm27, xmm31
        vpxord	xmm20, xmm20, xmm24
        vpxord	xmm21, xmm21, xmm25
        vpxord	xmm22, xmm22, xmm26
        vpxord	xmm23, xmm23, xmm27
        vprold	xmm20, xmm20, 7
        vprold	xmm21, xmm21, 7
        vprold	xmm22, xmm22, 7
        vprold	xmm23, xmm23, 7
        vpaddd	xmm16, xmm16, xmm21
        vpaddd	xmm17, xmm17, xmm22
        vpaddd	xmm18, xmm18, xmm23
        vpaddd	xmm19, xmm19, xmm20
        vpxord	xmm31, xmm31, xmm16
        vpxord	xmm28, xmm28, xmm17
        vpxord	xmm29, xmm29, xmm18
        vpxord	xmm30, xmm30, xmm19
        vprold	xmm31, xmm31, 16
        vprold	xmm28, xmm28, 16
        vprold	xmm29, xmm29, 16
        vprold	xmm30, xmm30, 16
        vpaddd	xmm26, xmm26, xmm31
        vpaddd	xmm27, xmm27, xmm28
        vpaddd	xmm24, xmm24, xmm29
        vpaddd	xmm25, xmm25, xmm30
        vpxord	xmm21, xmm21, xmm26
        vpxord	xmm22, xmm22, xmm27
        vpxord	xmm23, xmm23, xmm24
        vpxord	xmm20, xmm20, xmm25
        vprold	xmm21, xmm21, 12
        vprold	xmm22, xmm22, 12
        vprold	xmm23, xmm23, 12
        vprold	xmm20, xmm20, 12
        vpaddd	xmm16, xmm16, xmm21
        vpaddd	xmm17, xmm17, xmm22
        vpaddd	xmm18, xmm18, xmm23
        vpaddd	xmm19, xmm19, xmm20
        vpxord	xmm31, xmm31, xmm16
        vpxord	xmm28, xmm28, xmm17
        vpxord	xmm29, xmm29, xmm18
        vpxord	xmm30, xmm30, xmm19
        vprold	xmm31, xmm31, 8
        vprold	xmm28, xmm28, 8
        vprold	xmm29, xmm29, 8
        vprold	xmm30, xmm30, 8
        vpaddd	xmm26, xmm26, xmm31
        vpaddd	xmm27, xmm27, xmm28
        vpaddd	xmm24, xmm24, xmm29
        vpaddd	xmm25, xmm25, xmm30
        vpxord	xmm21, xmm21, xmm26
        vpxord	xmm22, xmm22, xmm27
        vpxord	xmm23, xmm23, xmm24
        vpxord	xmm20, xmm20, xmm25
        vprold	xmm21, xmm21, 7
        vprold	xmm22, xmm22, 7
        vprold	xmm23, xmm23, 7
        vprold	xmm20, xmm20, 7
        vmovdqu	ymm5, YMMWORD PTR [rcx+-256]
        vmovdqu	ymm6, YMMWORD PTR [rcx+-224]
        vperm2i128	ymm7, ymm5, ymm6, 32
        vperm2i128	ymm5, ymm5, ymm6, 49
        vpunpckldq	ymm6, ymm7, ymm5
        vpunpckhdq	ymm8, ymm7, ymm5
        vpunpckldq	ymm5, ymm6, ymm15
        vpunpckhdq	ymm6, ymm6, ymm15
        vpunpckldq	ymm7, ymm8, ymm15
        vpunpckhdq	ymm8, ymm8, ymm15
        vmovdqu	ymm9, YMMWORD PTR [r13]
        vpsllq	ymm6, ymm6, 6
        vpsllq	ymm7, ymm7, 12
        vpsllq	ymm8, ymm8, 18
        vpmuludq	ymm10, ymm4, [rbp]
        vpaddq	ymm5, ymm10, ymm5
        vpmuludq	ymm10, ymm3, [rbp+32]
        vpmuludq	ymm11, ymm4, [rbp+32]
        vpaddq	ymm6, ymm11, ymm6
        vpmuludq	ymm11, ymm3, [rbp+64]
        vpmuludq	ymm12, ymm4, [rbp+64]
        vpaddq	ymm7, ymm12, ymm7
        vpaddq	ymm5, ymm10, ymm5
        vpmuludq	ymm12, ymm2, [rbp+64]
        vpmuludq	ymm13, ymm4, [rbp+96]
        vpaddq	ymm8, ymm13, ymm8
        vpaddq	ymm6, ymm11, ymm6
        vpmuludq	ymm13, ymm1, [rbp+96]
        vpmuludq	ymm10, ymm2, [rbp+96]
        vpaddq	ymm5, ymm12, ymm5
        vpmuludq	ymm11, ymm3, [rbp+96]
        vpmuludq	ymm12, ymm3, [rbx]
        vpaddq	ymm5, ymm13, ymm5
        vpmuludq	ymm13, ymm4, [rbx]
        vpaddq	ymm9, ymm13, ymm9
        vpaddq	ymm6, ymm10, ymm6
        vpmuludq	ymm13, ymm0, [rbx]
        vpaddq	ymm7, ymm11, ymm7
        vpmuludq	ymm10, ymm1, [rbx]
        vpaddq	ymm8, ymm12, ymm8
        vpmuludq	ymm11, ymm2, [rbx]
        vpmuludq	ymm12, ymm2, [rbx+32]
        vpaddq	ymm5, ymm13, ymm5
        vpmuludq	ymm13, ymm3, [rbx+32]
        vpaddq	ymm6, ymm10, ymm6
        vpmuludq	ymm10, ymm0, [rbx+32]
        vpaddq	ymm7, ymm11, ymm7
        vpmuludq	ymm11, ymm1, [rbx+32]
        vpaddq	ymm8, ymm12, ymm8
        vpmuludq	ymm12, ymm1, [rbx+64]
        vpaddq	ymm9, ymm13, ymm9
        vpmuludq	ymm13, ymm2, [rbx+64]
        vpaddq	ymm6, ymm10, ymm6
        vpmuludq	ymm10, ymm0, [rbx+64]
        vpaddq	ymm7, ymm11, ymm7
        vpmuludq	ymm11, ymm0, [rbx+96]
        vpaddq	ymm8, ymm12, ymm8
        vpmuludq	ymm12, ymm1, [rbx+96]
        vpaddq	ymm9, ymm13, ymm9
        vpaddq	ymm7, ymm10, ymm7
        vpmuludq	ymm13, ymm0, [rbx+128]
        vpaddq	ymm8, ymm11, ymm8
        vpaddq	ymm9, ymm12, ymm9
        vpaddq	ymm9, ymm13, ymm9
        vpsrlq	ymm10, ymm5, 26
        vpsrlq	ymm11, ymm8, 26
        vpand	ymm5, ymm5, ymm14
        vpand	ymm8, ymm8, ymm14
        vpaddq	ymm6, ymm10, ymm6
        vpaddq	ymm9, ymm11, ymm9
        vpsrlq	ymm10, ymm6, 26
        vpsrlq	ymm11, ymm9, 26
        vpand	ymm1, ymm6, ymm14
        vpand	ymm4, ymm9, ymm14
        vpaddq	ymm7, ymm10, ymm7
        vpslld	ymm12, ymm11, 2
        vpaddd	ymm12, ymm11, ymm12
        vpsrlq	ymm10, ymm7, 26
        vpaddq	ymm5, ymm12, ymm5
        vpsrlq	ymm11, ymm5, 26
        vpand	ymm2, ymm7, ymm14
        vpand	ymm0, ymm5, ymm14
        vpaddq	ymm8, ymm10, ymm8
        vpaddq	ymm1, ymm11, ymm1
        vpsrlq	ymm10, ymm8, 26
        vpand	ymm3, ymm8, ymm14
        vpaddq	ymm4, ymm10, ymm4
        vpaddd	xmm16, xmm16, xmm20
        vpaddd	xmm17, xmm17, xmm21
        vpaddd	xmm18, xmm18, xmm22
        vpaddd	xmm19, xmm19, xmm23
        vpxord	xmm28, xmm28, xmm16
        vpxord	xmm29, xmm29, xmm17
        vpxord	xmm30, xmm30, xmm18
        vpxord	xmm31, xmm31, xmm19
        vprold	xmm28, xmm28, 16
        vprold	xmm29, xmm29, 16
        vprold	xmm30, xmm30, 16
        vprold	xmm31, xmm31, 16
        vpaddd	xmm24, xmm24, xmm28
        vpaddd	xmm25, xmm25, xmm29
        vpaddd	xmm26, xmm26, xmm30
        vpaddd	xmm27, xmm27, xmm31
        vpxord	xmm20, xmm20, xmm24
        vpxord	xmm21, xmm21, xmm25
        vpxord	xmm22, xmm22, xmm26
        vpxord	xmm23, xmm23, xmm27
        vprold	xmm20, xmm20, 12
        vprold	xmm21, xmm21, 12
        vprold	xmm22, xmm22, 12
        vprold	xmm23, xmm23, 12
        vpaddd	xmm16, xmm16, xmm20
        vpaddd	xmm17, xmm17, xmm21
        vpaddd	xmm18, xmm18, xmm22
        vpaddd	xmm19, xmm19, xmm23
        vpxord	xmm28, xmm28, xmm16
        vpxord	xmm29, xmm29, xmm17
        vpxord	xmm30, xmm30, xmm18
        vpxord	xmm31, xmm31, xmm19
        vprold	xmm28, xmm28, 8
        vprold	xmm29, xmm29, 8
        vprold	xmm30, xmm30, 8
        vprold	xmm31, xmm31, 8
        vpaddd	xmm24, xmm24, xmm28
        vpaddd	xmm25, xmm25, xmm29
        vpaddd	xmm26, xmm26, xmm30
        vpaddd	xmm27, xmm27, xmm31
        vpxord	xmm20, xmm20, xmm24
        vpxord	xmm21, xmm21, xmm25
        vpxord	xmm22, xmm22, xmm26
        vpxord	xmm23, xmm23, xmm27
        vprold	xmm20, xmm20, 7
        vprold	xmm21, xmm21, 7
        vprold	xmm22, xmm22, 7
        vprold	xmm23, xmm23, 7
        vpaddd	xmm16, xmm16, xmm21
        vpaddd	xmm17, xmm17, xmm22
        vpaddd	xmm18, xmm18, xmm23
        vpaddd	xmm19, xmm19, xmm20
        vpxord	xmm31, xmm31, xmm16
        vpxord	xmm28, xmm28, xmm17
        vpxord	xmm29, xmm29, xmm18
        vpxord	xmm30, xmm30, xmm19
        vprold	xmm31, xmm31, 16
        vprold	xmm28, xmm28, 16
        vprold	xmm29, xmm29, 16
        vprold	xmm30, xmm30, 16
        vpaddd	xmm26, xmm26, xmm31
        vpaddd	xmm27, xmm27, xmm28
        vpaddd	xmm24, xmm24, xmm29
        vpaddd	xmm25, xmm25, xmm30
        vpxord	xmm21, xmm21, xmm26
        vpxord	xmm22, xmm22, xmm27
        vpxord	xmm23, xmm23, xmm24
        vpxord	xmm20, xmm20, xmm25
        vprold	xmm21, xmm21, 12
        vprold	xmm22, xmm22, 12
        vprold	xmm23, xmm23, 12
        vprold	xmm20, xmm20, 12
        vpaddd	xmm16, xmm16, xmm21
        vpaddd	xmm17, xmm17, xmm22
        vpaddd	xmm18, xmm18, xmm23
        vpaddd	xmm19, xmm19, xmm20
        vpxord	xmm31, xmm31, xmm16
        vpxord	xmm28, xmm28, xmm17
        vpxord	xmm29, xmm29, xmm18
        vpxord	xmm30, xmm30, xmm19
        vprold	xmm31, xmm31, 8
        vprold	xmm28, xmm28, 8
        vprold	xmm29, xmm29, 8
        vprold	xmm30, xmm30, 8
        vpaddd	xmm26, xmm26, xmm31
        vpaddd	xmm27, xmm27, xmm28
        vpaddd	xmm24, xmm24, xmm29
        vpaddd	xmm25, xmm25, xmm30
        vpxord	xmm21, xmm21, xmm26
        vpxord	xmm22, xmm22, xmm27
        vpxord	xmm23, xmm23, xmm24
        vpxord	xmm20, xmm20, xmm25
        vprold	xmm21, xmm21, 7
        vprold	xmm22, xmm22, 7
        vprold	xmm23, xmm23, 7
        vprold	xmm20, xmm20, 7
        vpaddd	xmm16, xmm16, xmm20
        vpaddd	xmm17, xmm17, xmm21
        vpaddd	xmm18, xmm18, xmm22
        vpaddd	xmm19, xmm19, xmm23
        vpxord	xmm28, xmm28, xmm16
        vpxord	xmm29, xmm29, xmm17
        vpxord	xmm30, xmm30, xmm18
        vpxord	xmm31, xmm31, xmm19
        vprold	xmm28, xmm28, 16
        vprold	xmm29, xmm29, 16
        vprold	xmm30, xmm30, 16
        vprold	xmm31, xmm31, 16
        vpaddd	xmm24, xmm24, xmm28
        vpaddd	xmm25, xmm25, xmm29
        vpaddd	xmm26, xmm26, xmm30
        vpaddd	xmm27, xmm27, xmm31
        vpxord	xmm20, xmm20, xmm24
        vpxord	xmm21, xmm21, xmm25
        vpxord	xmm22, xmm22, xmm26
        vpxord	xmm23, xmm23, xmm27
        vprold	xmm20, xmm20, 12
        vprold	xmm21, xmm21, 12
        vprold	xmm22, xmm22, 12
        vprold	xmm23, xmm23, 12
        vpaddd	xmm16, xmm16, xmm20
        vpaddd	xmm17, xmm17, xmm21
        vpaddd	xmm18, xmm18, xmm22
        vpaddd	xmm19, xmm19, xmm23
        vpxord	xmm28, xmm28, xmm16
        vpxord	xmm29, xmm29, xmm17
        vpxord	xmm30, xmm30, xmm18
        vpxord	xmm31, xmm31, xmm19
        vprold	xmm28, xmm28, 8
        vprold	xmm29, xmm29, 8
        vprold	xmm30, xmm30, 8
        vprold	xmm31, xmm31, 8
        vpaddd	xmm24, xmm24, xmm28
        vpaddd	xmm25, xmm25, xmm29
        vpaddd	xmm26, xmm26, xmm30
        vpaddd	xmm27, xmm27, xmm31
        vpxord	xmm20, xmm20, xmm24
        vpxord	xmm21, xmm21, xmm25
        vpxord	xmm22, xmm22, xmm26
        vpxord	xmm23, xmm23, xmm27
        vprold	xmm20, xmm20, 7
        vprold	xmm21, xmm21, 7
        vprold	xmm22, xmm22, 7
        vprold	xmm23, xmm23, 7
        vpaddd	xmm16, xmm16, xmm21
        vpaddd	xmm17, xmm17, xmm22
        vpaddd	xmm18, xmm18, xmm23
        vpaddd	xmm19, xmm19, xmm20
        vpxord	xmm31, xmm31, xmm16
        vpxord	xmm28, xmm28, xmm17
        vpxord	xmm29, xmm29, xmm18
        vpxord	xmm30, xmm30, xmm19
        vprold	xmm31, xmm31, 16
        vprold	xmm28, xmm28, 16
        vprold	xmm29, xmm29, 16
        vprold	xmm30, xmm30, 16
        vpaddd	xmm26, xmm26, xmm31
        vpaddd	xmm27, xmm27, xmm28
        vpaddd	xmm24, xmm24, xmm29
        vpaddd	xmm25, xmm25, xmm30
        vpxord	xmm21, xmm21, xmm26
        vpxord	xmm22, xmm22, xmm27
        vpxord	xmm23, xmm23, xmm24
        vpxord	xmm20, xmm20, xmm25
        vprold	xmm21, xmm21, 12
        vprold	xmm22, xmm22, 12
        vprold	xmm23, xmm23, 12
        vprold	xmm20, xmm20, 12
        vpaddd	xmm16, xmm16, xmm21
        vpaddd	xmm17, xmm17, xmm22
        vpaddd	xmm18, xmm18, xmm23
        vpaddd	xmm19, xmm19, xmm20
        vpxord	xmm31, xmm31, xmm16
        vpxord	xmm28, xmm28, xmm17
        vpxord	xmm29, xmm29, xmm18
        vpxord	xmm30, xmm30, xmm19
        vprold	xmm31, xmm31, 8
        vprold	xmm28, xmm28, 8
        vprold	xmm29, xmm29, 8
        vprold	xmm30, xmm30, 8
        vpaddd	xmm26, xmm26, xmm31
        vpaddd	xmm27, xmm27, xmm28
        vpaddd	xmm24, xmm24, xmm29
        vpaddd	xmm25, xmm25, xmm30
        vpxord	xmm21, xmm21, xmm26
        vpxord	xmm22, xmm22, xmm27
        vpxord	xmm23, xmm23, xmm24
        vpxord	xmm20, xmm20, xmm25
        vprold	xmm21, xmm21, 7
        vprold	xmm22, xmm22, 7
        vprold	xmm23, xmm23, 7
        vprold	xmm20, xmm20, 7
        vmovdqu	ymm5, YMMWORD PTR [rcx+-192]
        vmovdqu	ymm6, YMMWORD PTR [rcx+-160]
        vperm2i128	ymm7, ymm5, ymm6, 32
        vperm2i128	ymm5, ymm5, ymm6, 49
        vpunpckldq	ymm6, ymm7, ymm5
        vpunpckhdq	ymm8, ymm7, ymm5
        vpunpckldq	ymm5, ymm6, ymm15
        vpunpckhdq	ymm6, ymm6, ymm15
        vpunpckldq	ymm7, ymm8, ymm15
        vpunpckhdq	ymm8, ymm8, ymm15
        vmovdqu	ymm9, YMMWORD PTR [r13]
        vpsllq	ymm6, ymm6, 6
        vpsllq	ymm7, ymm7, 12
        vpsllq	ymm8, ymm8, 18
        vpmuludq	ymm10, ymm4, [rbp]
        vpaddq	ymm5, ymm10, ymm5
        vpmuludq	ymm10, ymm3, [rbp+32]
        vpmuludq	ymm11, ymm4, [rbp+32]
        vpaddq	ymm6, ymm11, ymm6
        vpmuludq	ymm11, ymm3, [rbp+64]
        vpmuludq	ymm12, ymm4, [rbp+64]
        vpaddq	ymm7, ymm12, ymm7
        vpaddq	ymm5, ymm10, ymm5
        vpmuludq	ymm12, ymm2, [rbp+64]
        vpmuludq	ymm13, ymm4, [rbp+96]
        vpaddq	ymm8, ymm13, ymm8
        vpaddq	ymm6, ymm11, ymm6
        vpmuludq	ymm13, ymm1, [rbp+96]
        vpmuludq	ymm10, ymm2, [rbp+96]
        vpaddq	ymm5, ymm12, ymm5
        vpmuludq	ymm11, ymm3, [rbp+96]
        vpmuludq	ymm12, ymm3, [rbx]
        vpaddq	ymm5, ymm13, ymm5
        vpmuludq	ymm13, ymm4, [rbx]
        vpaddq	ymm9, ymm13, ymm9
        vpaddq	ymm6, ymm10, ymm6
        vpmuludq	ymm13, ymm0, [rbx]
        vpaddq	ymm7, ymm11, ymm7
        vpmuludq	ymm10, ymm1, [rbx]
        vpaddq	ymm8, ymm12, ymm8
        vpmuludq	ymm11, ymm2, [rbx]
        vpmuludq	ymm12, ymm2, [rbx+32]
        vpaddq	ymm5, ymm13, ymm5
        vpmuludq	ymm13, ymm3, [rbx+32]
        vpaddq	ymm6, ymm10, ymm6
        vpmuludq	ymm10, ymm0, [rbx+32]
        vpaddq	ymm7, ymm11, ymm7
        vpmuludq	ymm11, ymm1, [rbx+32]
        vpaddq	ymm8, ymm12, ymm8
        vpmuludq	ymm12, ymm1, [rbx+64]
        vpaddq	ymm9, ymm13, ymm9
        vpmuludq	ymm13, ymm2, [rbx+64]
        vpaddq	ymm6, ymm10, ymm6
        vpmuludq	ymm10, ymm0, [rbx+64]
        vpaddq	ymm7, ymm11, ymm7
        vpmuludq	ymm11, ymm0, [rbx+96]
        vpaddq	ymm8, ymm12, ymm8
        vpmuludq	ymm12, ymm1, [rbx+96]
        vpaddq	ymm9, ymm13, ymm9
        vpaddq	ymm7, ymm10, ymm7
        vpmuludq	ymm13, ymm0, [rbx+128]
        vpaddq	ymm8, ymm11, ymm8
        vpaddq	ymm9, ymm12, ymm9
        vpaddq	ymm9, ymm13, ymm9
        vpsrlq	ymm10, ymm5, 26
        vpsrlq	ymm11, ymm8, 26
        vpand	ymm5, ymm5, ymm14
        vpand	ymm8, ymm8, ymm14
        vpaddq	ymm6, ymm10, ymm6
        vpaddq	ymm9, ymm11, ymm9
        vpsrlq	ymm10, ymm6, 26
        vpsrlq	ymm11, ymm9, 26
        vpand	ymm1, ymm6, ymm14
        vpand	ymm4, ymm9, ymm14
        vpaddq	ymm7, ymm10, ymm7
        vpslld	ymm12, ymm11, 2
        vpaddd	ymm12, ymm11, ymm12
        vpsrlq	ymm10, ymm7, 26
        vpaddq	ymm5, ymm12, ymm5
        vpsrlq	ymm11, ymm5, 26
        vpand	ymm2, ymm7, ymm14
        vpand	ymm0, ymm5, ymm14
        vpaddq	ymm8, ymm10, ymm8
        vpaddq	ymm1, ymm11, ymm1
        vpsrlq	ymm10, ymm8, 26
        vpand	ymm3, ymm8, ymm14
        vpaddq	ymm4, ymm10, ymm4
        vpaddd	xmm16, xmm16, xmm20
        vpaddd	xmm17, xmm17, xmm21
        vpaddd	xmm18, xmm18, xmm22
        vpaddd	xmm19, xmm19, xmm23
        vpxord	xmm28, xmm28, xmm16
        vpxord	xmm29, xmm29, xmm17
        vpxord	xmm30, xmm30, xmm18
        vpxord	xmm31, xmm31, xmm19
        vprold	xmm28, xmm28, 16
        vprold	xmm29, xmm29, 16
        vprold	xmm30, xmm30, 16
        vprold	xmm31, xmm31, 16
        vpaddd	xmm24, xmm24, xmm28
        vpaddd	xmm25, xmm25, xmm29
        vpaddd	xmm26, xmm26, xmm30
        vpaddd	xmm27, xmm27, xmm31
        vpxord	xmm20, xmm20, xmm24
        vpxord	xmm21, xmm21, xmm25
        vpxord	xmm22, xmm22, xmm26
        vpxord	xmm23, xmm23, xmm27
        vprold	xmm20, xmm20, 12
        vprold	xmm21, xmm21, 12
        vprold	xmm22, xmm22, 12
        vprold	xmm23, xmm23, 12
        vpaddd	xmm16, xmm16, xmm20
        vpaddd	xmm17, xmm17, xmm21
        vpaddd	xmm18, xmm18, xmm22
        vpaddd	xmm19, xmm19, xmm23
        vpxord	xmm28, xmm28, xmm16
        vpxord	xmm29, xmm29, xmm17
        vpxord	xmm30, xmm30, xmm18
        vpxord	xmm31, xmm31, xmm19
        vprold	xmm28, xmm28, 8
        vprold	xmm29, xmm29, 8
        vprold	xmm30, xmm30, 8
        vprold	xmm31, xmm31, 8
        vpaddd	xmm24, xmm24, xmm28
        vpaddd	xmm25, xmm25, xmm29
        vpaddd	xmm26, xmm26, xmm30
        vpaddd	xmm27, xmm27, xmm31
        vpxord	xmm20, xmm20, xmm24
        vpxord	xmm21, xmm21, xmm25
        vpxord	xmm22, xmm22, xmm26
        vpxord	xmm23, xmm23, xmm27
        vprold	xmm20, xmm20, 7
        vprold	xmm21, xmm21, 7
        vprold	xmm22, xmm22, 7
        vprold	xmm23, xmm23, 7
        vpaddd	xmm16, xmm16, xmm21
        vpaddd	xmm17, xmm17, xmm22
        vpaddd	xmm18, xmm18, xmm23
        vpaddd	xmm19, xmm19, xmm20
        vpxord	xmm31, xmm31, xmm16
        vpxord	xmm28, xmm28, xmm17
        vpxord	xmm29, xmm29, xmm18
        vpxord	xmm30, xmm30, xmm19
        vprold	xmm31, xmm31, 16
        vprold	xmm28, xmm28, 16
        vprold	xmm29, xmm29, 16
        vprold	xmm30, xmm30, 16
        vpaddd	xmm26, xmm26, xmm31
        vpaddd	xmm27, xmm27, xmm28
        vpaddd	xmm24, xmm24, xmm29
        vpaddd	xmm25, xmm25, xmm30
        vpxord	xmm21, xmm21, xmm26
        vpxord	xmm22, xmm22, xmm27
        vpxord	xmm23, xmm23, xmm24
        vpxord	xmm20, xmm20, xmm25
        vprold	xmm21, xmm21, 12
        vprold	xmm22, xmm22, 12
        vprold	xmm23, xmm23, 12
        vprold	xmm20, xmm20, 12
        vpaddd	xmm16, xmm16, xmm21
        vpaddd	xmm17, xmm17, xmm22
        vpaddd	xmm18, xmm18, xmm23
        vpaddd	xmm19, xmm19, xmm20
        vpxord	xmm31, xmm31, xmm16
        vpxord	xmm28, xmm28, xmm17
        vpxord	xmm29, xmm29, xmm18
        vpxord	xmm30, xmm30, xmm19
        vprold	xmm31, xmm31, 8
        vprold	xmm28, xmm28, 8
        vprold	xmm29, xmm29, 8
        vprold	xmm30, xmm30, 8
        vpaddd	xmm26, xmm26, xmm31
        vpaddd	xmm27, xmm27, xmm28
        vpaddd	xmm24, xmm24, xmm29
        vpaddd	xmm25, xmm25, xmm30
        vpxord	xmm21, xmm21, xmm26
        vpxord	xmm22, xmm22, xmm27
        vpxord	xmm23, xmm23, xmm24
        vpxord	xmm20, xmm20, xmm25
        vprold	xmm21, xmm21, 7
        vprold	xmm22, xmm22, 7
        vprold	xmm23, xmm23, 7
        vprold	xmm20, xmm20, 7
        vpaddd	xmm16, xmm16, xmm20
        vpaddd	xmm17, xmm17, xmm21
        vpaddd	xmm18, xmm18, xmm22
        vpaddd	xmm19, xmm19, xmm23
        vpxord	xmm28, xmm28, xmm16
        vpxord	xmm29, xmm29, xmm17
        vpxord	xmm30, xmm30, xmm18
        vpxord	xmm31, xmm31, xmm19
        vprold	xmm28, xmm28, 16
        vprold	xmm29, xmm29, 16
        vprold	xmm30, xmm30, 16
        vprold	xmm31, xmm31, 16
        vpaddd	xmm24, xmm24, xmm28
        vpaddd	xmm25, xmm25, xmm29
        vpaddd	xmm26, xmm26, xmm30
        vpaddd	xmm27, xmm27, xmm31
        vpxord	xmm20, xmm20, xmm24
        vpxord	xmm21, xmm21, xmm25
        vpxord	xmm22, xmm22, xmm26
        vpxord	xmm23, xmm23, xmm27
        vprold	xmm20, xmm20, 12
        vprold	xmm21, xmm21, 12
        vprold	xmm22, xmm22, 12
        vprold	xmm23, xmm23, 12
        vpaddd	xmm16, xmm16, xmm20
        vpaddd	xmm17, xmm17, xmm21
        vpaddd	xmm18, xmm18, xmm22
        vpaddd	xmm19, xmm19, xmm23
        vpxord	xmm28, xmm28, xmm16
        vpxord	xmm29, xmm29, xmm17
        vpxord	xmm30, xmm30, xmm18
        vpxord	xmm31, xmm31, xmm19
        vprold	xmm28, xmm28, 8
        vprold	xmm29, xmm29, 8
        vprold	xmm30, xmm30, 8
        vprold	xmm31, xmm31, 8
        vpaddd	xmm24, xmm24, xmm28
        vpaddd	xmm25, xmm25, xmm29
        vpaddd	xmm26, xmm26, xmm30
        vpaddd	xmm27, xmm27, xmm31
        vpxord	xmm20, xmm20, xmm24
        vpxord	xmm21, xmm21, xmm25
        vpxord	xmm22, xmm22, xmm26
        vpxord	xmm23, xmm23, xmm27
        vprold	xmm20, xmm20, 7
        vprold	xmm21, xmm21, 7
        vprold	xmm22, xmm22, 7
        vprold	xmm23, xmm23, 7
        vpaddd	xmm16, xmm16, xmm21
        vpaddd	xmm17, xmm17, xmm22
        vpaddd	xmm18, xmm18, xmm23
        vpaddd	xmm19, xmm19, xmm20
        vpxord	xmm31, xmm31, xmm16
        vpxord	xmm28, xmm28, xmm17
        vpxord	xmm29, xmm29, xmm18
        vpxord	xmm30, xmm30, xmm19
        vprold	xmm31, xmm31, 16
        vprold	xmm28, xmm28, 16
        vprold	xmm29, xmm29, 16
        vprold	xmm30, xmm30, 16
        vpaddd	xmm26, xmm26, xmm31
        vpaddd	xmm27, xmm27, xmm28
        vpaddd	xmm24, xmm24, xmm29
        vpaddd	xmm25, xmm25, xmm30
        vpxord	xmm21, xmm21, xmm26
        vpxord	xmm22, xmm22, xmm27
        vpxord	xmm23, xmm23, xmm24
        vpxord	xmm20, xmm20, xmm25
        vprold	xmm21, xmm21, 12
        vprold	xmm22, xmm22, 12
        vprold	xmm23, xmm23, 12
        vprold	xmm20, xmm20, 12
        vpaddd	xmm16, xmm16, xmm21
        vpaddd	xmm17, xmm17, xmm22
        vpaddd	xmm18, xmm18, xmm23
        vpaddd	xmm19, xmm19, xmm20
        vpxord	xmm31, xmm31, xmm16
        vpxord	xmm28, xmm28, xmm17
        vpxord	xmm29, xmm29, xmm18
        vpxord	xmm30, xmm30, xmm19
        vprold	xmm31, xmm31, 8
        vprold	xmm28, xmm28, 8
        vprold	xmm29, xmm29, 8
        vprold	xmm30, xmm30, 8
        vpaddd	xmm26, xmm26, xmm31
        vpaddd	xmm27, xmm27, xmm28
        vpaddd	xmm24, xmm24, xmm29
        vpaddd	xmm25, xmm25, xmm30
        vpxord	xmm21, xmm21, xmm26
        vpxord	xmm22, xmm22, xmm27
        vpxord	xmm23, xmm23, xmm24
        vpxord	xmm20, xmm20, xmm25
        vprold	xmm21, xmm21, 7
        vprold	xmm22, xmm22, 7
        vprold	xmm23, xmm23, 7
        vprold	xmm20, xmm20, 7
        vmovdqu	ymm5, YMMWORD PTR [rcx+-128]
        vmovdqu	ymm6, YMMWORD PTR [rcx+-96]
        vperm2i128	ymm7, ymm5, ymm6, 32
        vperm2i128	ymm5, ymm5, ymm6, 49
        vpunpckldq	ymm6, ymm7, ymm5
        vpunpckhdq	ymm8, ymm7, ymm5
        vpunpckldq	ymm5, ymm6, ymm15
        vpunpckhdq	ymm6, ymm6, ymm15
        vpunpckldq	ymm7, ymm8, ymm15
        vpunpckhdq	ymm8, ymm8, ymm15
        vmovdqu	ymm9, YMMWORD PTR [r13]
        vpsllq	ymm6, ymm6, 6
        vpsllq	ymm7, ymm7, 12
        vpsllq	ymm8, ymm8, 18
        vpmuludq	ymm10, ymm4, [rbp]
        vpaddq	ymm5, ymm10, ymm5
        vpmuludq	ymm10, ymm3, [rbp+32]
        vpmuludq	ymm11, ymm4, [rbp+32]
        vpaddq	ymm6, ymm11, ymm6
        vpmuludq	ymm11, ymm3, [rbp+64]
        vpmuludq	ymm12, ymm4, [rbp+64]
        vpaddq	ymm7, ymm12, ymm7
        vpaddq	ymm5, ymm10, ymm5
        vpmuludq	ymm12, ymm2, [rbp+64]
        vpmuludq	ymm13, ymm4, [rbp+96]
        vpaddq	ymm8, ymm13, ymm8
        vpaddq	ymm6, ymm11, ymm6
        vpmuludq	ymm13, ymm1, [rbp+96]
        vpmuludq	ymm10, ymm2, [rbp+96]
        vpaddq	ymm5, ymm12, ymm5
        vpmuludq	ymm11, ymm3, [rbp+96]
        vpmuludq	ymm12, ymm3, [rbx]
        vpaddq	ymm5, ymm13, ymm5
        vpmuludq	ymm13, ymm4, [rbx]
        vpaddq	ymm9, ymm13, ymm9
        vpaddq	ymm6, ymm10, ymm6
        vpmuludq	ymm13, ymm0, [rbx]
        vpaddq	ymm7, ymm11, ymm7
        vpmuludq	ymm10, ymm1, [rbx]
        vpaddq	ymm8, ymm12, ymm8
        vpmuludq	ymm11, ymm2, [rbx]
        vpmuludq	ymm12, ymm2, [rbx+32]
        vpaddq	ymm5, ymm13, ymm5
        vpmuludq	ymm13, ymm3, [rbx+32]
        vpaddq	ymm6, ymm10, ymm6
        vpmuludq	ymm10, ymm0, [rbx+32]
        vpaddq	ymm7, ymm11, ymm7
        vpmuludq	ymm11, ymm1, [rbx+32]
        vpaddq	ymm8, ymm12, ymm8
        vpmuludq	ymm12, ymm1, [rbx+64]
        vpaddq	ymm9, ymm13, ymm9
        vpmuludq	ymm13, ymm2, [rbx+64]
        vpaddq	ymm6, ymm10, ymm6
        vpmuludq	ymm10, ymm0, [rbx+64]
        vpaddq	ymm7, ymm11, ymm7
        vpmuludq	ymm11, ymm0, [rbx+96]
        vpaddq	ymm8, ymm12, ymm8
        vpmuludq	ymm12, ymm1, [rbx+96]
        vpaddq	ymm9, ymm13, ymm9
        vpaddq	ymm7, ymm10, ymm7
        vpmuludq	ymm13, ymm0, [rbx+128]
        vpaddq	ymm8, ymm11, ymm8
        vpaddq	ymm9, ymm12, ymm9
        vpaddq	ymm9, ymm13, ymm9
        vpsrlq	ymm10, ymm5, 26
        vpsrlq	ymm11, ymm8, 26
        vpand	ymm5, ymm5, ymm14
        vpand	ymm8, ymm8, ymm14
        vpaddq	ymm6, ymm10, ymm6
        vpaddq	ymm9, ymm11, ymm9
        vpsrlq	ymm10, ymm6, 26
        vpsrlq	ymm11, ymm9, 26
        vpand	ymm1, ymm6, ymm14
        vpand	ymm4, ymm9, ymm14
        vpaddq	ymm7, ymm10, ymm7
        vpslld	ymm12, ymm11, 2
        vpaddd	ymm12, ymm11, ymm12
        vpsrlq	ymm10, ymm7, 26
        vpaddq	ymm5, ymm12, ymm5
        vpsrlq	ymm11, ymm5, 26
        vpand	ymm2, ymm7, ymm14
        vpand	ymm0, ymm5, ymm14
        vpaddq	ymm8, ymm10, ymm8
        vpaddq	ymm1, ymm11, ymm1
        vpsrlq	ymm10, ymm8, 26
        vpand	ymm3, ymm8, ymm14
        vpaddq	ymm4, ymm10, ymm4
        vpaddd	xmm16, xmm16, xmm20
        vpaddd	xmm17, xmm17, xmm21
        vpaddd	xmm18, xmm18, xmm22
        vpaddd	xmm19, xmm19, xmm23
        vpxord	xmm28, xmm28, xmm16
        vpxord	xmm29, xmm29, xmm17
        vpxord	xmm30, xmm30, xmm18
        vpxord	xmm31, xmm31, xmm19
        vprold	xmm28, xmm28, 16
        vprold	xmm29, xmm29, 16
        vprold	xmm30, xmm30, 16
        vprold	xmm31, xmm31, 16
        vpaddd	xmm24, xmm24, xmm28
        vpaddd	xmm25, xmm25, xmm29
        vpaddd	xmm26, xmm26, xmm30
        vpaddd	xmm27, xmm27, xmm31
        vpxord	xmm20, xmm20, xmm24
        vpxord	xmm21, xmm21, xmm25
        vpxord	xmm22, xmm22, xmm26
        vpxord	xmm23, xmm23, xmm27
        vprold	xmm20, xmm20, 12
        vprold	xmm21, xmm21, 12
        vprold	xmm22, xmm22, 12
        vprold	xmm23, xmm23, 12
        vpaddd	xmm16, xmm16, xmm20
        vpaddd	xmm17, xmm17, xmm21
        vpaddd	xmm18, xmm18, xmm22
        vpaddd	xmm19, xmm19, xmm23
        vpxord	xmm28, xmm28, xmm16
        vpxord	xmm29, xmm29, xmm17
        vpxord	xmm30, xmm30, xmm18
        vpxord	xmm31, xmm31, xmm19
        vprold	xmm28, xmm28, 8
        vprold	xmm29, xmm29, 8
        vprold	xmm30, xmm30, 8
        vprold	xmm31, xmm31, 8
        vpaddd	xmm24, xmm24, xmm28
        vpaddd	xmm25, xmm25, xmm29
        vpaddd	xmm26, xmm26, xmm30
        vpaddd	xmm27, xmm27, xmm31
        vpxord	xmm20, xmm20, xmm24
        vpxord	xmm21, xmm21, xmm25
        vpxord	xmm22, xmm22, xmm26
        vpxord	xmm23, xmm23, xmm27
        vprold	xmm20, xmm20, 7
        vprold	xmm21, xmm21, 7
        vprold	xmm22, xmm22, 7
        vprold	xmm23, xmm23, 7
        vpaddd	xmm16, xmm16, xmm21
        vpaddd	xmm17, xmm17, xmm22
        vpaddd	xmm18, xmm18, xmm23
        vpaddd	xmm19, xmm19, xmm20
        vpxord	xmm31, xmm31, xmm16
        vpxord	xmm28, xmm28, xmm17
        vpxord	xmm29, xmm29, xmm18
        vpxord	xmm30, xmm30, xmm19
        vprold	xmm31, xmm31, 16
        vprold	xmm28, xmm28, 16
        vprold	xmm29, xmm29, 16
        vprold	xmm30, xmm30, 16
        vpaddd	xmm26, xmm26, xmm31
        vpaddd	xmm27, xmm27, xmm28
        vpaddd	xmm24, xmm24, xmm29
        vpaddd	xmm25, xmm25, xmm30
        vpxord	xmm21, xmm21, xmm26
        vpxord	xmm22, xmm22, xmm27
        vpxord	xmm23, xmm23, xmm24
        vpxord	xmm20, xmm20, xmm25
        vprold	xmm21, xmm21, 12
        vprold	xmm22, xmm22, 12
        vprold	xmm23, xmm23, 12
        vprold	xmm20, xmm20, 12
        vpaddd	xmm16, xmm16, xmm21
        vpaddd	xmm17, xmm17, xmm22
        vpaddd	xmm18, xmm18, xmm23
        vpaddd	xmm19, xmm19, xmm20
        vpxord	xmm31, xmm31, xmm16
        vpxord	xmm28, xmm28, xmm17
        vpxord	xmm29, xmm29, xmm18
        vpxord	xmm30, xmm30, xmm19
        vprold	xmm31, xmm31, 8
        vprold	xmm28, xmm28, 8
        vprold	xmm29, xmm29, 8
        vprold	xmm30, xmm30, 8
        vpaddd	xmm26, xmm26, xmm31
        vpaddd	xmm27, xmm27, xmm28
        vpaddd	xmm24, xmm24, xmm29
        vpaddd	xmm25, xmm25, xmm30
        vpxord	xmm21, xmm21, xmm26
        vpxord	xmm22, xmm22, xmm27
        vpxord	xmm23, xmm23, xmm24
        vpxord	xmm20, xmm20, xmm25
        vprold	xmm21, xmm21, 7
        vprold	xmm22, xmm22, 7
        vprold	xmm23, xmm23, 7
        vprold	xmm20, xmm20, 7
        vpaddd	xmm16, xmm16, xmm20
        vpaddd	xmm17, xmm17, xmm21
        vpaddd	xmm18, xmm18, xmm22
        vpaddd	xmm19, xmm19, xmm23
        vpxord	xmm28, xmm28, xmm16
        vpxord	xmm29, xmm29, xmm17
        vpxord	xmm30, xmm30, xmm18
        vpxord	xmm31, xmm31, xmm19
        vprold	xmm28, xmm28, 16
        vprold	xmm29, xmm29, 16
        vprold	xmm30, xmm30, 16
        vprold	xmm31, xmm31, 16
        vpaddd	xmm24, xmm24, xmm28
        vpaddd	xmm25, xmm25, xmm29
        vpaddd	xmm26, xmm26, xmm30
        vpaddd	xmm27, xmm27, xmm31
        vpxord	xmm20, xmm20, xmm24
        vpxord	xmm21, xmm21, xmm25
        vpxord	xmm22, xmm22, xmm26
        vpxord	xmm23, xmm23, xmm27
        vprold	xmm20, xmm20, 12
        vprold	xmm21, xmm21, 12
        vprold	xmm22, xmm22, 12
        vprold	xmm23, xmm23, 12
        vpaddd	xmm16, xmm16, xmm20
        vpaddd	xmm17, xmm17, xmm21
        vpaddd	xmm18, xmm18, xmm22
        vpaddd	xmm19, xmm19, xmm23
        vpxord	xmm28, xmm28, xmm16
        vpxord	xmm29, xmm29, xmm17
        vpxord	xmm30, xmm30, xmm18
        vpxord	xmm31, xmm31, xmm19
        vprold	xmm28, xmm28, 8
        vprold	xmm29, xmm29, 8
        vprold	xmm30, xmm30, 8
        vprold	xmm31, xmm31, 8
        vpaddd	xmm24, xmm24, xmm28
        vpaddd	xmm25, xmm25, xmm29
        vpaddd	xmm26, xmm26, xmm30
        vpaddd	xmm27, xmm27, xmm31
        vpxord	xmm20, xmm20, xmm24
        vpxord	xmm21, xmm21, xmm25
        vpxord	xmm22, xmm22, xmm26
        vpxord	xmm23, xmm23, xmm27
        vprold	xmm20, xmm20, 7
        vprold	xmm21, xmm21, 7
        vprold	xmm22, xmm22, 7
        vprold	xmm23, xmm23, 7
        vpaddd	xmm16, xmm16, xmm21
        vpaddd	xmm17, xmm17, xmm22
        vpaddd	xmm18, xmm18, xmm23
        vpaddd	xmm19, xmm19, xmm20
        vpxord	xmm31, xmm31, xmm16
        vpxord	xmm28, xmm28, xmm17
        vpxord	xmm29, xmm29, xmm18
        vpxord	xmm30, xmm30, xmm19
        vprold	xmm31, xmm31, 16
        vprold	xmm28, xmm28, 16
        vprold	xmm29, xmm29, 16
        vprold	xmm30, xmm30, 16
        vpaddd	xmm26, xmm26, xmm31
        vpaddd	xmm27, xmm27, xmm28
        vpaddd	xmm24, xmm24, xmm29
        vpaddd	xmm25, xmm25, xmm30
        vpxord	xmm21, xmm21, xmm26
        vpxord	xmm22, xmm22, xmm27
        vpxord	xmm23, xmm23, xmm24
        vpxord	xmm20, xmm20, xmm25
        vprold	xmm21, xmm21, 12
        vprold	xmm22, xmm22, 12
        vprold	xmm23, xmm23, 12
        vprold	xmm20, xmm20, 12
        vpaddd	xmm16, xmm16, xmm21
        vpaddd	xmm17, xmm17, xmm22
        vpaddd	xmm18, xmm18, xmm23
        vpaddd	xmm19, xmm19, xmm20
        vpxord	xmm31, xmm31, xmm16
        vpxord	xmm28, xmm28, xmm17
        vpxord	xmm29, xmm29, xmm18
        vpxord	xmm30, xmm30, xmm19
        vprold	xmm31, xmm31, 8
        vprold	xmm28, xmm28, 8
        vprold	xmm29, xmm29, 8
        vprold	xmm30, xmm30, 8
        vpaddd	xmm26, xmm26, xmm31
        vpaddd	xmm27, xmm27, xmm28
        vpaddd	xmm24, xmm24, xmm29
        vpaddd	xmm25, xmm25, xmm30
        vpxord	xmm21, xmm21, xmm26
        vpxord	xmm22, xmm22, xmm27
        vpxord	xmm23, xmm23, xmm24
        vpxord	xmm20, xmm20, xmm25
        vprold	xmm21, xmm21, 7
        vprold	xmm22, xmm22, 7
        vprold	xmm23, xmm23, 7
        vprold	xmm20, xmm20, 7
        vmovdqu	ymm5, YMMWORD PTR [rcx+-64]
        vmovdqu	ymm6, YMMWORD PTR [rcx+-32]
        vperm2i128	ymm7, ymm5, ymm6, 32
        vperm2i128	ymm5, ymm5, ymm6, 49
        vpunpckldq	ymm6, ymm7, ymm5
        vpunpckhdq	ymm8, ymm7, ymm5
        vpunpckldq	ymm5, ymm6, ymm15
        vpunpckhdq	ymm6, ymm6, ymm15
        vpunpckldq	ymm7, ymm8, ymm15
        vpunpckhdq	ymm8, ymm8, ymm15
        vmovdqu	ymm9, YMMWORD PTR [r13]
        vpsllq	ymm6, ymm6, 6
        vpsllq	ymm7, ymm7, 12
        vpsllq	ymm8, ymm8, 18
        vpmuludq	ymm10, ymm4, [rbp]
        vpaddq	ymm5, ymm10, ymm5
        vpmuludq	ymm10, ymm3, [rbp+32]
        vpmuludq	ymm11, ymm4, [rbp+32]
        vpaddq	ymm6, ymm11, ymm6
        vpmuludq	ymm11, ymm3, [rbp+64]
        vpmuludq	ymm12, ymm4, [rbp+64]
        vpaddq	ymm7, ymm12, ymm7
        vpaddq	ymm5, ymm10, ymm5
        vpmuludq	ymm12, ymm2, [rbp+64]
        vpmuludq	ymm13, ymm4, [rbp+96]
        vpaddq	ymm8, ymm13, ymm8
        vpaddq	ymm6, ymm11, ymm6
        vpmuludq	ymm13, ymm1, [rbp+96]
        vpmuludq	ymm10, ymm2, [rbp+96]
        vpaddq	ymm5, ymm12, ymm5
        vpmuludq	ymm11, ymm3, [rbp+96]
        vpmuludq	ymm12, ymm3, [rbx]
        vpaddq	ymm5, ymm13, ymm5
        vpmuludq	ymm13, ymm4, [rbx]
        vpaddq	ymm9, ymm13, ymm9
        vpaddq	ymm6, ymm10, ymm6
        vpmuludq	ymm13, ymm0, [rbx]
        vpaddq	ymm7, ymm11, ymm7
        vpmuludq	ymm10, ymm1, [rbx]
        vpaddq	ymm8, ymm12, ymm8
        vpmuludq	ymm11, ymm2, [rbx]
        vpmuludq	ymm12, ymm2, [rbx+32]
        vpaddq	ymm5, ymm13, ymm5
        vpmuludq	ymm13, ymm3, [rbx+32]
        vpaddq	ymm6, ymm10, ymm6
        vpmuludq	ymm10, ymm0, [rbx+32]
        vpaddq	ymm7, ymm11, ymm7
        vpmuludq	ymm11, ymm1, [rbx+32]
        vpaddq	ymm8, ymm12, ymm8
        vpmuludq	ymm12, ymm1, [rbx+64]
        vpaddq	ymm9, ymm13, ymm9
        vpmuludq	ymm13, ymm2, [rbx+64]
        vpaddq	ymm6, ymm10, ymm6
        vpmuludq	ymm10, ymm0, [rbx+64]
        vpaddq	ymm7, ymm11, ymm7
        vpmuludq	ymm11, ymm0, [rbx+96]
        vpaddq	ymm8, ymm12, ymm8
        vpmuludq	ymm12, ymm1, [rbx+96]
        vpaddq	ymm9, ymm13, ymm9
        vpaddq	ymm7, ymm10, ymm7
        vpmuludq	ymm13, ymm0, [rbx+128]
        vpaddq	ymm8, ymm11, ymm8
        vpaddq	ymm9, ymm12, ymm9
        vpaddq	ymm9, ymm13, ymm9
        vpsrlq	ymm10, ymm5, 26
        vpsrlq	ymm11, ymm8, 26
        vpand	ymm5, ymm5, ymm14
        vpand	ymm8, ymm8, ymm14
        vpaddq	ymm6, ymm10, ymm6
        vpaddq	ymm9, ymm11, ymm9
        vpsrlq	ymm10, ymm6, 26
        vpsrlq	ymm11, ymm9, 26
        vpand	ymm1, ymm6, ymm14
        vpand	ymm4, ymm9, ymm14
        vpaddq	ymm7, ymm10, ymm7
        vpslld	ymm12, ymm11, 2
        vpaddd	ymm12, ymm11, ymm12
        vpsrlq	ymm10, ymm7, 26
        vpaddq	ymm5, ymm12, ymm5
        vpsrlq	ymm11, ymm5, 26
        vpand	ymm2, ymm7, ymm14
        vpand	ymm0, ymm5, ymm14
        vpaddq	ymm8, ymm10, ymm8
        vpaddq	ymm1, ymm11, ymm1
        vpsrlq	ymm10, ymm8, 26
        vpand	ymm3, ymm8, ymm14
        vpaddq	ymm4, ymm10, ymm4
        vpaddd	xmm16, xmm16, xmm20
        vpaddd	xmm17, xmm17, xmm21
        vpaddd	xmm18, xmm18, xmm22
        vpaddd	xmm19, xmm19, xmm23
        vpxord	xmm28, xmm28, xmm16
        vpxord	xmm29, xmm29, xmm17
        vpxord	xmm30, xmm30, xmm18
        vpxord	xmm31, xmm31, xmm19
        vprold	xmm28, xmm28, 16
        vprold	xmm29, xmm29, 16
        vprold	xmm30, xmm30, 16
        vprold	xmm31, xmm31, 16
        vpaddd	xmm24, xmm24, xmm28
        vpaddd	xmm25, xmm25, xmm29
        vpaddd	xmm26, xmm26, xmm30
        vpaddd	xmm27, xmm27, xmm31
        vpxord	xmm20, xmm20, xmm24
        vpxord	xmm21, xmm21, xmm25
        vpxord	xmm22, xmm22, xmm26
        vpxord	xmm23, xmm23, xmm27
        vprold	xmm20, xmm20, 12
        vprold	xmm21, xmm21, 12
        vprold	xmm22, xmm22, 12
        vprold	xmm23, xmm23, 12
        vpaddd	xmm16, xmm16, xmm20
        vpaddd	xmm17, xmm17, xmm21
        vpaddd	xmm18, xmm18, xmm22
        vpaddd	xmm19, xmm19, xmm23
        vpxord	xmm28, xmm28, xmm16
        vpxord	xmm29, xmm29, xmm17
        vpxord	xmm30, xmm30, xmm18
        vpxord	xmm31, xmm31, xmm19
        vprold	xmm28, xmm28, 8
        vprold	xmm29, xmm29, 8
        vprold	xmm30, xmm30, 8
        vprold	xmm31, xmm31, 8
        vpaddd	xmm24, xmm24, xmm28
        vpaddd	xmm25, xmm25, xmm29
        vpaddd	xmm26, xmm26, xmm30
        vpaddd	xmm27, xmm27, xmm31
        vpxord	xmm20, xmm20, xmm24
        vpxord	xmm21, xmm21, xmm25
        vpxord	xmm22, xmm22, xmm26
        vpxord	xmm23, xmm23, xmm27
        vprold	xmm20, xmm20, 7
        vprold	xmm21, xmm21, 7
        vprold	xmm22, xmm22, 7
        vprold	xmm23, xmm23, 7
        vpaddd	xmm16, xmm16, xmm21
        vpaddd	xmm17, xmm17, xmm22
        vpaddd	xmm18, xmm18, xmm23
        vpaddd	xmm19, xmm19, xmm20
        vpxord	xmm31, xmm31, xmm16
        vpxord	xmm28, xmm28, xmm17
        vpxord	xmm29, xmm29, xmm18
        vpxord	xmm30, xmm30, xmm19
        vprold	xmm31, xmm31, 16
        vprold	xmm28, xmm28, 16
        vprold	xmm29, xmm29, 16
        vprold	xmm30, xmm30, 16
        vpaddd	xmm26, xmm26, xmm31
        vpaddd	xmm27, xmm27, xmm28
        vpaddd	xmm24, xmm24, xmm29
        vpaddd	xmm25, xmm25, xmm30
        vpxord	xmm21, xmm21, xmm26
        vpxord	xmm22, xmm22, xmm27
        vpxord	xmm23, xmm23, xmm24
        vpxord	xmm20, xmm20, xmm25
        vprold	xmm21, xmm21, 12
        vprold	xmm22, xmm22, 12
        vprold	xmm23, xmm23, 12
        vprold	xmm20, xmm20, 12
        vpaddd	xmm16, xmm16, xmm21
        vpaddd	xmm17, xmm17, xmm22
        vpaddd	xmm18, xmm18, xmm23
        vpaddd	xmm19, xmm19, xmm20
        vpxord	xmm31, xmm31, xmm16
        vpxord	xmm28, xmm28, xmm17
        vpxord	xmm29, xmm29, xmm18
        vpxord	xmm30, xmm30, xmm19
        vprold	xmm31, xmm31, 8
        vprold	xmm28, xmm28, 8
        vprold	xmm29, xmm29, 8
        vprold	xmm30, xmm30, 8
        vpaddd	xmm26, xmm26, xmm31
        vpaddd	xmm27, xmm27, xmm28
        vpaddd	xmm24, xmm24, xmm29
        vpaddd	xmm25, xmm25, xmm30
        vpxord	xmm21, xmm21, xmm26
        vpxord	xmm22, xmm22, xmm27
        vpxord	xmm23, xmm23, xmm24
        vpxord	xmm20, xmm20, xmm25
        vprold	xmm21, xmm21, 7
        vprold	xmm22, xmm22, 7
        vprold	xmm23, xmm23, 7
        vprold	xmm20, xmm20, 7
        vpaddd	xmm16, xmm16, xmm20
        vpaddd	xmm17, xmm17, xmm21
        vpaddd	xmm18, xmm18, xmm22
        vpaddd	xmm19, xmm19, xmm23
        vpxord	xmm28, xmm28, xmm16
        vpxord	xmm29, xmm29, xmm17
        vpxord	xmm30, xmm30, xmm18
        vpxord	xmm31, xmm31, xmm19
        vprold	xmm28, xmm28, 16
        vprold	xmm29, xmm29, 16
        vprold	xmm30, xmm30, 16
        vprold	xmm31, xmm31, 16
        vpaddd	xmm24, xmm24, xmm28
        vpaddd	xmm25, xmm25, xmm29
        vpaddd	xmm26, xmm26, xmm30
        vpaddd	xmm27, xmm27, xmm31
        vpxord	xmm20, xmm20, xmm24
        vpxord	xmm21, xmm21, xmm25
        vpxord	xmm22, xmm22, xmm26
        vpxord	xmm23, xmm23, xmm27
        vprold	xmm20, xmm20, 12
        vprold	xmm21, xmm21, 12
        vprold	xmm22, xmm22, 12
        vprold	xmm23, xmm23, 12
        vpaddd	xmm16, xmm16, xmm20
        vpaddd	xmm17, xmm17, xmm21
        vpaddd	xmm18, xmm18, xmm22
        vpaddd	xmm19, xmm19, xmm23
        vpxord	xmm28, xmm28, xmm16
        vpxord	xmm29, xmm29, xmm17
        vpxord	xmm30, xmm30, xmm18
        vpxord	xmm31, xmm31, xmm19
        vprold	xmm28, xmm28, 8
        vprold	xmm29, xmm29, 8
        vprold	xmm30, xmm30, 8
        vprold	xmm31, xmm31, 8
        vpaddd	xmm24, xmm24, xmm28
        vpaddd	xmm25, xmm25, xmm29
        vpaddd	xmm26, xmm26, xmm30
        vpaddd	xmm27, xmm27, xmm31
        vpxord	xmm20, xmm20, xmm24
        vpxord	xmm21, xmm21, xmm25
        vpxord	xmm22, xmm22, xmm26
        vpxord	xmm23, xmm23, xmm27
        vprold	xmm20, xmm20, 7
        vprold	xmm21, xmm21, 7
        vprold	xmm22, xmm22, 7
        vprold	xmm23, xmm23, 7
        vpaddd	xmm16, xmm16, xmm21
        vpaddd	xmm17, xmm17, xmm22
        vpaddd	xmm18, xmm18, xmm23
        vpaddd	xmm19, xmm19, xmm20
        vpxord	xmm31, xmm31, xmm16
        vpxord	xmm28, xmm28, xmm17
        vpxord	xmm29, xmm29, xmm18
        vpxord	xmm30, xmm30, xmm19
        vprold	xmm31, xmm31, 16
        vprold	xmm28, xmm28, 16
        vprold	xmm29, xmm29, 16
        vprold	xmm30, xmm30, 16
        vpaddd	xmm26, xmm26, xmm31
        vpaddd	xmm27, xmm27, xmm28
        vpaddd	xmm24, xmm24, xmm29
        vpaddd	xmm25, xmm25, xmm30
        vpxord	xmm21, xmm21, xmm26
        vpxord	xmm22, xmm22, xmm27
        vpxord	xmm23, xmm23, xmm24
        vpxord	xmm20, xmm20, xmm25
        vprold	xmm21, xmm21, 12
        vprold	xmm22, xmm22, 12
        vprold	xmm23, xmm23, 12
        vprold	xmm20, xmm20, 12
        vpaddd	xmm16, xmm16, xmm21
        vpaddd	xmm17, xmm17, xmm22
        vpaddd	xmm18, xmm18, xmm23
        vpaddd	xmm19, xmm19, xmm20
        vpxord	xmm31, xmm31, xmm16
        vpxord	xmm28, xmm28, xmm17
        vpxord	xmm29, xmm29, xmm18
        vpxord	xmm30, xmm30, xmm19
        vprold	xmm31, xmm31, 8
        vprold	xmm28, xmm28, 8
        vprold	xmm29, xmm29, 8
        vprold	xmm30, xmm30, 8
        vpaddd	xmm26, xmm26, xmm31
        vpaddd	xmm27, xmm27, xmm28
        vpaddd	xmm24, xmm24, xmm29
        vpaddd	xmm25, xmm25, xmm30
        vpxord	xmm21, xmm21, xmm26
        vpxord	xmm22, xmm22, xmm27
        vpxord	xmm23, xmm23, xmm24
        vpxord	xmm20, xmm20, xmm25
        vprold	xmm21, xmm21, 7
        vprold	xmm22, xmm22, 7
        vprold	xmm23, xmm23, 7
        vprold	xmm20, xmm20, 7
        vpaddd	xmm16, xmm16, OWORD PTR [r14]
        vpaddd	xmm17, xmm17, OWORD PTR [r14+16]
        vpaddd	xmm18, xmm18, OWORD PTR [r14+32]
        vpaddd	xmm19, xmm19, OWORD PTR [r14+48]
        vpaddd	xmm20, xmm20, OWORD PTR [r14+64]
        vpaddd	xmm21, xmm21, OWORD PTR [r14+80]
        vpaddd	xmm22, xmm22, OWORD PTR [r14+96]
        vpaddd	xmm23, xmm23, OWORD PTR [r14+112]
        vpaddd	xmm24, xmm24, OWORD PTR [r14+128]
        vpaddd	xmm25, xmm25, OWORD PTR [r14+144]
        vpaddd	xmm26, xmm26, OWORD PTR [r14+160]
        vpaddd	xmm27, xmm27, OWORD PTR [r14+176]
        vpaddd	xmm28, xmm28, OWORD PTR [r14+192]
        vpaddd	xmm29, xmm29, OWORD PTR [r14+208]
        vpaddd	xmm30, xmm30, OWORD PTR [r14+224]
        vpaddd	xmm31, xmm31, OWORD PTR [r14+240]
        vmovdqa64	[r15], xmm24
        vmovdqa64	[r15+16], xmm25
        vmovdqa64	[r15+32], xmm26
        vmovdqa64	[r15+48], xmm27
        vmovdqa64	[r15+64], xmm28
        vmovdqa64	[r15+80], xmm29
        vmovdqa64	[r15+96], xmm30
        vmovdqa64	[r15+112], xmm31
        vpunpckldq	xmm24, xmm16, xmm17
        vpunpckldq	xmm25, xmm18, xmm19
        vpunpckhdq	xmm28, xmm16, xmm17
        vpunpckhdq	xmm29, xmm18, xmm19
        vpunpckldq	xmm26, xmm20, xmm21
        vpunpckldq	xmm27, xmm22, xmm23
        vpunpckhdq	xmm30, xmm20, xmm21
        vpunpckhdq	xmm31, xmm22, xmm23
        vpunpcklqdq	xmm16, xmm24, xmm25
        vpunpcklqdq	xmm17, xmm26, xmm27
        vpunpckhqdq	xmm18, xmm24, xmm25
        vpunpckhqdq	xmm19, xmm26, xmm27
        vpunpcklqdq	xmm20, xmm28, xmm29
        vpunpcklqdq	xmm21, xmm30, xmm31
        vpunpckhqdq	xmm22, xmm28, xmm29
        vpunpckhqdq	xmm23, xmm30, xmm31
        vmovdqu64	xmm24, [rdx]
        vmovdqu64	xmm25, [rdx+16]
        vmovdqu64	xmm26, [rdx+64]
        vmovdqu64	xmm27, [rdx+80]
        vmovdqu64	xmm28, [rdx+128]
        vmovdqu64	xmm29, [rdx+144]
        vmovdqu64	xmm30, [rdx+192]
        vmovdqu64	xmm31, [rdx+208]
        vpxord	xmm16, xmm16, xmm24
        vpxord	xmm17, xmm17, xmm25
        vpxord	xmm18, xmm18, xmm26
        vpxord	xmm19, xmm19, xmm27
        vpxord	xmm20, xmm20, xmm28
        vpxord	xmm21, xmm21, xmm29
        vpxord	xmm22, xmm22, xmm30
        vpxord	xmm23, xmm23, xmm31
        vmovdqu64	[rcx], xmm16
        vmovdqu64	[rcx+16], xmm17
        vmovdqu64	[rcx+64], xmm18
        vmovdqu64	[rcx+80], xmm19
        vmovdqu64	[rcx+128], xmm20
        vmovdqu64	[rcx+144], xmm21
        vmovdqu64	[rcx+192], xmm22
        vmovdqu64	[rcx+208], xmm23
        vmovdqa64	xmm16, [r15]
        vmovdqa64	xmm17, [r15+16]
        vmovdqa64	xmm18, [r15+32]
        vmovdqa64	xmm19, [r15+48]
        vmovdqa64	xmm20, [r15+64]
        vmovdqa64	xmm21, [r15+80]
        vmovdqa64	xmm22, [r15+96]
        vmovdqa64	xmm23, [r15+112]
        vpunpckldq	xmm24, xmm16, xmm17
        vpunpckldq	xmm25, xmm18, xmm19
        vpunpckhdq	xmm28, xmm16, xmm17
        vpunpckhdq	xmm29, xmm18, xmm19
        vpunpckldq	xmm26, xmm20, xmm21
        vpunpckldq	xmm27, xmm22, xmm23
        vpunpckhdq	xmm30, xmm20, xmm21
        vpunpckhdq	xmm31, xmm22, xmm23
        vpunpcklqdq	xmm16, xmm24, xmm25
        vpunpcklqdq	xmm17, xmm26, xmm27
        vpunpckhqdq	xmm18, xmm24, xmm25
        vpunpckhqdq	xmm19, xmm26, xmm27
        vpunpcklqdq	xmm20, xmm28, xmm29
        vpunpcklqdq	xmm21, xmm30, xmm31
        vpunpckhqdq	xmm22, xmm28, xmm29
        vpunpckhqdq	xmm23, xmm30, xmm31
        vmovdqu64	xmm24, [rdx+32]
        vmovdqu64	xmm25, [rdx+48]
        vmovdqu64	xmm26, [rdx+96]
        vmovdqu64	xmm27, [rdx+112]
        vmovdqu64	xmm28, [rdx+160]
        vmovdqu64	xmm29, [rdx+176]
        vmovdqu64	xmm30, [rdx+224]
        vmovdqu64	xmm31, [rdx+240]
        vpxord	xmm16, xmm16, xmm24
        vpxord	xmm17, xmm17, xmm25
        vpxord	xmm18, xmm18, xmm26
        vpxord	xmm19, xmm19, xmm27
        vpxord	xmm20, xmm20, xmm28
        vpxord	xmm21, xmm21, xmm29
        vpxord	xmm22, xmm22, xmm30
        vpxord	xmm23, xmm23, xmm31
        vmovdqu64	[rcx+32], xmm16
        vmovdqu64	[rcx+48], xmm17
        vmovdqu64	[rcx+96], xmm18
        vmovdqu64	[rcx+112], xmm19
        vmovdqu64	[rcx+160], xmm20
        vmovdqu64	[rcx+176], xmm21
        vmovdqu64	[rcx+224], xmm22
        vmovdqu64	[rcx+240], xmm23
        vmovdqa64	xmm28, [r14+192]
        vpaddd	xmm28, xmm28, OWORD PTR [r11]
        vmovdqa64	[r14+192], xmm28
        vmovdqa64	xmm16, [r14]
        vmovdqa64	xmm17, [r14+16]
        vmovdqa64	xmm18, [r14+32]
        vmovdqa64	xmm19, [r14+48]
        vmovdqa64	xmm20, [r14+64]
        vmovdqa64	xmm21, [r14+80]
        vmovdqa64	xmm22, [r14+96]
        vmovdqa64	xmm23, [r14+112]
        vmovdqa64	xmm24, [r14+128]
        vmovdqa64	xmm25, [r14+144]
        vmovdqa64	xmm26, [r14+160]
        vmovdqa64	xmm27, [r14+176]
        vmovdqa64	xmm28, [r14+192]
        vmovdqa64	xmm29, [r14+208]
        vmovdqa64	xmm30, [r14+224]
        vmovdqa64	xmm31, [r14+240]
        add	rdx, 256
        add	rcx, 256
        sub	eax, 256
        jnz	L_chacha20_poly1305_start
L_chacha20_poly1305_epilogue:
        vmovdqu	ymm5, YMMWORD PTR [rcx+-256]
        vmovdqu	ymm6, YMMWORD PTR [rcx+-224]
        vperm2i128	ymm7, ymm5, ymm6, 32
        vperm2i128	ymm5, ymm5, ymm6, 49
        vpunpckldq	ymm6, ymm7, ymm5
        vpunpckhdq	ymm8, ymm7, ymm5
        vpunpckldq	ymm5, ymm6, ymm15
        vpunpckhdq	ymm6, ymm6, ymm15
        vpunpckldq	ymm7, ymm8, ymm15
        vpunpckhdq	ymm8, ymm8, ymm15
        vmovdqu	ymm9, YMMWORD PTR [r13]
        vpsllq	ymm6, ymm6, 6
        vpsllq	ymm7, ymm7, 12
        vpsllq	ymm8, ymm8, 18
        vpmuludq	ymm10, ymm4, [rbp]
        vpaddq	ymm5, ymm10, ymm5
        vpmuludq	ymm10, ymm3, [rbp+32]
        vpmuludq	ymm11, ymm4, [rbp+32]
        vpaddq	ymm6, ymm11, ymm6
        vpmuludq	ymm11, ymm3, [rbp+64]
        vpmuludq	ymm12, ymm4, [rbp+64]
        vpaddq	ymm7, ymm12, ymm7
        vpaddq	ymm5, ymm10, ymm5
        vpmuludq	ymm12, ymm2, [rbp+64]
        vpmuludq	ymm13, ymm4, [rbp+96]
        vpaddq	ymm8, ymm13, ymm8
        vpaddq	ymm6, ymm11, ymm6
        vpmuludq	ymm13, ymm1, [rbp+96]
        vpmuludq	ymm10, ymm2, [rbp+96]
        vpaddq	ymm5, ymm12, ymm5
        vpmuludq	ymm11, ymm3, [rbp+96]
        vpmuludq	ymm12, ymm3, [rbx]
        vpaddq	ymm5, ymm13, ymm5
        vpmuludq	ymm13, ymm4, [rbx]
        vpaddq	ymm9, ymm13, ymm9
        vpaddq	ymm6, ymm10, ymm6
        vpmuludq	ymm13, ymm0, [rbx]
        vpaddq	ymm7, ymm11, ymm7
        vpmuludq	ymm10, ymm1, [rbx]
        vpaddq	ymm8, ymm12, ymm8
        vpmuludq	ymm11, ymm2, [rbx]
        vpmuludq	ymm12, ymm2, [rbx+32]
        vpaddq	ymm5, ymm13, ymm5
        vpmuludq	ymm13, ymm3, [rbx+32]
        vpaddq	ymm6, ymm10, ymm6
        vpmuludq	ymm10, ymm0, [rbx+32]
        vpaddq	ymm7, ymm11, ymm7
        vpmuludq	ymm11, ymm1, [rbx+32]
        vpaddq	ymm8, ymm12, ymm8
        vpmuludq	ymm12, ymm1, [rbx+64]
        vpaddq	ymm9, ymm13, ymm9
        vpmuludq	ymm13, ymm2, [rbx+64]
        vpaddq	ymm6, ymm10, ymm6
        vpmuludq	ymm10, ymm0, [rbx+64]
        vpaddq	ymm7, ymm11, ymm7
        vpmuludq	ymm11, ymm0, [rbx+96]
        vpaddq	ymm8, ymm12, ymm8
        vpmuludq	ymm12, ymm1, [rbx+96]
        vpaddq	ymm9, ymm13, ymm9
        vpaddq	ymm7, ymm10, ymm7
        vpmuludq	ymm13, ymm0, [rbx+128]
        vpaddq	ymm8, ymm11, ymm8
        vpaddq	ymm9, ymm12, ymm9
        vpaddq	ymm9, ymm13, ymm9
        vpsrlq	ymm10, ymm5, 26
        vpsrlq	ymm11, ymm8, 26
        vpand	ymm5, ymm5, ymm14
        vpand	ymm8, ymm8, ymm14
        vpaddq	ymm6, ymm10, ymm6
        vpaddq	ymm9, ymm11, ymm9
        vpsrlq	ymm10, ymm6, 26
        vpsrlq	ymm11, ymm9, 26
        vpand	ymm1, ymm6, ymm14
        vpand	ymm4, ymm9, ymm14
        vpaddq	ymm7, ymm10, ymm7
        vpslld	ymm12, ymm11, 2
        vpaddd	ymm12, ymm11, ymm12
        vpsrlq	ymm10, ymm7, 26
        vpaddq	ymm5, ymm12, ymm5
        vpsrlq	ymm11, ymm5, 26
        vpand	ymm2, ymm7, ymm14
        vpand	ymm0, ymm5, ymm14
        vpaddq	ymm8, ymm10, ymm8
        vpaddq	ymm1, ymm11, ymm1
        vpsrlq	ymm10, ymm8, 26
        vpand	ymm3, ymm8, ymm14
        vpaddq	ymm4, ymm10, ymm4
        vmovdqu	ymm5, YMMWORD PTR [rcx+-192]
        vmovdqu	ymm6, YMMWORD PTR [rcx+-160]
        vperm2i128	ymm7, ymm5, ymm6, 32
        vperm2i128	ymm5, ymm5, ymm6, 49
        vpunpckldq	ymm6, ymm7, ymm5
        vpunpckhdq	ymm8, ymm7, ymm5
        vpunpckldq	ymm5, ymm6, ymm15
        vpunpckhdq	ymm6, ymm6, ymm15
        vpunpckldq	ymm7, ymm8, ymm15
        vpunpckhdq	ymm8, ymm8, ymm15
        vmovdqu	ymm9, YMMWORD PTR [r13]
        vpsllq	ymm6, ymm6, 6
        vpsllq	ymm7, ymm7, 12
        vpsllq	ymm8, ymm8, 18
        vpmuludq	ymm10, ymm4, [rbp]
        vpaddq	ymm5, ymm10, ymm5
        vpmuludq	ymm10, ymm3, [rbp+32]
        vpmuludq	ymm11, ymm4, [rbp+32]
        vpaddq	ymm6, ymm11, ymm6
        vpmuludq	ymm11, ymm3, [rbp+64]
        vpmuludq	ymm12, ymm4, [rbp+64]
        vpaddq	ymm7, ymm12, ymm7
        vpaddq	ymm5, ymm10, ymm5
        vpmuludq	ymm12, ymm2, [rbp+64]
        vpmuludq	ymm13, ymm4, [rbp+96]
        vpaddq	ymm8, ymm13, ymm8
        vpaddq	ymm6, ymm11, ymm6
        vpmuludq	ymm13, ymm1, [rbp+96]
        vpmuludq	ymm10, ymm2, [rbp+96]
        vpaddq	ymm5, ymm12, ymm5
        vpmuludq	ymm11, ymm3, [rbp+96]
        vpmuludq	ymm12, ymm3, [rbx]
        vpaddq	ymm5, ymm13, ymm5
        vpmuludq	ymm13, ymm4, [rbx]
        vpaddq	ymm9, ymm13, ymm9
        vpaddq	ymm6, ymm10, ymm6
        vpmuludq	ymm13, ymm0, [rbx]
        vpaddq	ymm7, ymm11, ymm7
        vpmuludq	ymm10, ymm1, [rbx]
        vpaddq	ymm8, ymm12, ymm8
        vpmuludq	ymm11, ymm2, [rbx]
        vpmuludq	ymm12, ymm2, [rbx+32]
        vpaddq	ymm5, ymm13, ymm5
        vpmuludq	ymm13, ymm3, [rbx+32]
        vpaddq	ymm6, ymm10, ymm6
        vpmuludq	ymm10, ymm0, [rbx+32]
        vpaddq	ymm7, ymm11, ymm7
        vpmuludq	ymm11, ymm1, [rbx+32]
        vpaddq	ymm8, ymm12, ymm8
        vpmuludq	ymm12, ymm1, [rbx+64]
        vpaddq	ymm9, ymm13, ymm9
        vpmuludq	ymm13, ymm2, [rbx+64]
        vpaddq	ymm6, ymm10, ymm6
        vpmuludq	ymm10, ymm0, [rbx+64]
        vpaddq	ymm7, ymm11, ymm7
        vpmuludq	ymm11, ymm0, [rbx+96]
        vpaddq	ymm8, ymm12, ymm8
        vpmuludq	ymm12, ymm1, [rbx+96]
        vpaddq	ymm9, ymm13, ymm9
        vpaddq	ymm7, ymm10, ymm7
        vpmuludq	ymm13, ymm0, [rbx+128]
        vpaddq	ymm8, ymm11, ymm8
        vpaddq	ymm9, ymm12, ymm9
        vpaddq	ymm9, ymm13, ymm9
        vpsrlq	ymm10, ymm5, 26
        vpsrlq	ymm11, ymm8, 26
        vpand	ymm5, ymm5, ymm14
        vpand	ymm8, ymm8, ymm14
        vpaddq	ymm6, ymm10, ymm6
        vpaddq	ymm9, ymm11, ymm9
        vpsrlq	ymm10, ymm6, 26
        vpsrlq	ymm11, ymm9, 26
        vpand	ymm1, ymm6, ymm14
        vpand	ymm4, ymm9, ymm14
        vpaddq	ymm7, ymm10, ymm7
        vpslld	ymm12, ymm11, 2
        vpaddd	ymm12, ymm11, ymm12
        vpsrlq	ymm10, ymm7, 26
        vpaddq	ymm5, ymm12, ymm5
        vpsrlq	ymm11, ymm5, 26
        vpand	ymm2, ymm7, ymm14
        vpand	ymm0, ymm5, ymm14
        vpaddq	ymm8, ymm10, ymm8
        vpaddq	ymm1, ymm11, ymm1
        vpsrlq	ymm10, ymm8, 26
        vpand	ymm3, ymm8, ymm14
        vpaddq	ymm4, ymm10, ymm4
        vmovdqu	ymm5, YMMWORD PTR [rcx+-128]
        vmovdqu	ymm6, YMMWORD PTR [rcx+-96]
        vperm2i128	ymm7, ymm5, ymm6, 32
        vperm2i128	ymm5, ymm5, ymm6, 49
        vpunpckldq	ymm6, ymm7, ymm5
        vpunpckhdq	ymm8, ymm7, ymm5
        vpunpckldq	ymm5, ymm6, ymm15
        vpunpckhdq	ymm6, ymm6, ymm15
        vpunpckldq	ymm7, ymm8, ymm15
        vpunpckhdq	ymm8, ymm8, ymm15
        vmovdqu	ymm9, YMMWORD PTR [r13]
        vpsllq	ymm6, ymm6, 6
        vpsllq	ymm7, ymm7, 12
        vpsllq	ymm8, ymm8, 18
        vpmuludq	ymm10, ymm4, [rbp]
        vpaddq	ymm5, ymm10, ymm5
        vpmuludq	ymm10, ymm3, [rbp+32]
        vpmuludq	ymm11, ymm4, [rbp+32]
        vpaddq	ymm6, ymm11, ymm6
        vpmuludq	ymm11, ymm3, [rbp+64]
        vpmuludq	ymm12, ymm4, [rbp+64]
        vpaddq	ymm7, ymm12, ymm7
        vpaddq	ymm5, ymm10, ymm5
        vpmuludq	ymm12, ymm2, [rbp+64]
        vpmuludq	ymm13, ymm4, [rbp+96]
        vpaddq	ymm8, ymm13, ymm8
        vpaddq	ymm6, ymm11, ymm6
        vpmuludq	ymm13, ymm1, [rbp+96]
        vpmuludq	ymm10, ymm2, [rbp+96]
        vpaddq	ymm5, ymm12, ymm5
        vpmuludq	ymm11, ymm3, [rbp+96]
        vpmuludq	ymm12, ymm3, [rbx]
        vpaddq	ymm5, ymm13, ymm5
        vpmuludq	ymm13, ymm4, [rbx]
        vpaddq	ymm9, ymm13, ymm9
        vpaddq	ymm6, ymm10, ymm6
        vpmuludq	ymm13, ymm0, [rbx]
        vpaddq	ymm7, ymm11, ymm7
        vpmuludq	ymm10, ymm1, [rbx]
        vpaddq	ymm8, ymm12, ymm8
        vpmuludq	ymm11, ymm2, [rbx]
        vpmuludq	ymm12, ymm2, [rbx+32]
        vpaddq	ymm5, ymm13, ymm5
        vpmuludq	ymm13, ymm3, [rbx+32]
        vpaddq	ymm6, ymm10, ymm6
        vpmuludq	ymm10, ymm0, [rbx+32]
        vpaddq	ymm7, ymm11, ymm7
        vpmuludq	ymm11, ymm1, [rbx+32]
        vpaddq	ymm8, ymm12, ymm8
        vpmuludq	ymm12, ymm1, [rbx+64]
        vpaddq	ymm9, ymm13, ymm9
        vpmuludq	ymm13, ymm2, [rbx+64]
        vpaddq	ymm6, ymm10, ymm6
        vpmuludq	ymm10, ymm0, [rbx+64]
        vpaddq	ymm7, ymm11, ymm7
        vpmuludq	ymm11, ymm0, [rbx+96]
        vpaddq	ymm8, ymm12, ymm8
        vpmuludq	ymm12, ymm1, [rbx+96]
        vpaddq	ymm9, ymm13, ymm9
        vpaddq	ymm7, ymm10, ymm7
        vpmuludq	ymm13, ymm0, [rbx+128]
        vpaddq	ymm8, ymm11, ymm8
        vpaddq	ymm9, ymm12, ymm9
        vpaddq	ymm9, ymm13, ymm9
        vpsrlq	ymm10, ymm5, 26
        vpsrlq	ymm11, ymm8, 26
        vpand	ymm5, ymm5, ymm14
        vpand	ymm8, ymm8, ymm14
        vpaddq	ymm6, ymm10, ymm6
        vpaddq	ymm9, ymm11, ymm9
        vpsrlq	ymm10, ymm6, 26
        vpsrlq	ymm11, ymm9, 26
        vpand	ymm1, ymm6, ymm14
        vpand	ymm4, ymm9, ymm14
        vpaddq	ymm7, ymm10, ymm7
        vpslld	ymm12, ymm11, 2
        vpaddd	ymm12, ymm11, ymm12
        vpsrlq	ymm10, ymm7, 26
        vpaddq	ymm5, ymm12, ymm5
        vpsrlq	ymm11, ymm5, 26
        vpand	ymm2, ymm7, ymm14
        vpand	ymm0, ymm5, ymm14
        vpaddq	ymm8, ymm10, ymm8
        vpaddq	ymm1, ymm11, ymm1
        vpsrlq	ymm10, ymm8, 26
        vpand	ymm3, ymm8, ymm14
        vpaddq	ymm4, ymm10, ymm4
        vmovdqu	ymm5, YMMWORD PTR [rcx+-64]
        vmovdqu	ymm6, YMMWORD PTR [rcx+-32]
        vperm2i128	ymm7, ymm5, ymm6, 32
        vperm2i128	ymm5, ymm5, ymm6, 49
        vpunpckldq	ymm6, ymm7, ymm5
        vpunpckhdq	ymm8, ymm7, ymm5
        vpunpckldq	ymm5, ymm6, ymm15
        vpunpckhdq	ymm6, ymm6, ymm15
        vpunpckldq	ymm7, ymm8, ymm15
        vpunpckhdq	ymm8, ymm8, ymm15
        vmovdqu	ymm9, YMMWORD PTR [r13]
        vpsllq	ymm6, ymm6, 6
        vpsllq	ymm7, ymm7, 12
        vpsllq	ymm8, ymm8, 18
        vpmuludq	ymm10, ymm4, [rbp]
        vpaddq	ymm5, ymm10, ymm5
        vpmuludq	ymm10, ymm3, [rbp+32]
        vpmuludq	ymm11, ymm4, [rbp+32]
        vpaddq	ymm6, ymm11, ymm6
        vpmuludq	ymm11, ymm3, [rbp+64]
        vpmuludq	ymm12, ymm4, [rbp+64]
        vpaddq	ymm7, ymm12, ymm7
        vpaddq	ymm5, ymm10, ymm5
        vpmuludq	ymm12, ymm2, [rbp+64]
        vpmuludq	ymm13, ymm4, [rbp+96]
        vpaddq	ymm8, ymm13, ymm8
        vpaddq	ymm6, ymm11, ymm6
        vpmuludq	ymm13, ymm1, [rbp+96]
        vpmuludq	ymm10, ymm2, [rbp+96]
        vpaddq	ymm5, ymm12, ymm5
        vpmuludq	ymm11, ymm3, [rbp+96]
        vpmuludq	ymm12, ymm3, [rbx]
        vpaddq	ymm5, ymm13, ymm5
        vpmuludq	ymm13, ymm4, [rbx]
        vpaddq	ymm9, ymm13, ymm9
        vpaddq	ymm6, ymm10, ymm6
        vpmuludq	ymm13, ymm0, [rbx]
        vpaddq	ymm7, ymm11, ymm7
        vpmuludq	ymm10, ymm1, [rbx]
        vpaddq	ymm8, ymm12, ymm8
        vpmuludq	ymm11, ymm2, [rbx]
        vpmuludq	ymm12, ymm2, [rbx+32]
        vpaddq	ymm5, ymm13, ymm5
        vpmuludq	ymm13, ymm3, [rbx+32]
        vpaddq	ymm6, ymm10, ymm6
        vpmuludq	ymm10, ymm0, [rbx+32]
        vpaddq	ymm7, ymm11, ymm7
        vpmuludq	ymm11, ymm1, [rbx+32]
        vpaddq	ymm8, ymm12, ymm8
        vpmuludq	ymm12, ymm1, [rbx+64]
        vpaddq	ymm9, ymm13, ymm9
        vpmuludq	ymm13, ymm2, [rbx+64]
        vpaddq	ymm6, ymm10, ymm6
        vpmuludq	ymm10, ymm0, [rbx+64]
        vpaddq	ymm7, ymm11, ymm7
        vpmuludq	ymm11, ymm0, [rbx+96]
        vpaddq	ymm8, ymm12, ymm8
        vpmuludq	ymm12, ymm1, [rbx+96]
        vpaddq	ymm9, ymm13, ymm9
        vpaddq	ymm7, ymm10, ymm7
        vpmuludq	ymm13, ymm0, [rbx+128]
        vpaddq	ymm8, ymm11, ymm8
        vpaddq	ymm9, ymm12, ymm9
        vpaddq	ymm9, ymm13, ymm9
        vpsrlq	ymm10, ymm5, 26
        vpsrlq	ymm11, ymm8, 26
        vpand	ymm5, ymm5, ymm14
        vpand	ymm8, ymm8, ymm14
        vpaddq	ymm6, ymm10, ymm6
        vpaddq	ymm9, ymm11, ymm9
        vpsrlq	ymm10, ymm6, 26
        vpsrlq	ymm11, ymm9, 26
        vpand	ymm1, ymm6, ymm14
        vpand	ymm4, ymm9, ymm14
        vpaddq	ymm7, ymm10, ymm7
        vpslld	ymm12, ymm11, 2
        vpaddd	ymm12, ymm11, ymm12
        vpsrlq	ymm10, ymm7, 26
        vpaddq	ymm5, ymm12, ymm5
        vpsrlq	ymm11, ymm5, 26
        vpand	ymm2, ymm7, ymm14
        vpand	ymm0, ymm5, ymm14
        vpaddq	ymm8, ymm10, ymm8
        vpaddq	ymm1, ymm11, ymm1
        vpsrlq	ymm10, ymm8, 26
        vpand	ymm3, ymm8, ymm14
        vpaddq	ymm4, ymm10, ymm4
        vmovdqu	YMMWORD PTR [r9], ymm0
        vmovdqu	YMMWORD PTR [r9+32], ymm1
        vmovdqu	YMMWORD PTR [r9+64], ymm2
        vmovdqu	YMMWORD PTR [r9+96], ymm3
        vmovdqu	YMMWORD PTR [r9+128], ymm4
        vmovd	[rdi+48], xmm28
        vzeroupper
        vmovdqu	xmm6, OWORD PTR [rsp+720]
        vmovdqu	xmm7, OWORD PTR [rsp+736]
        vmovdqu	xmm8, OWORD PTR [rsp+752]
        vmovdqu	xmm9, OWORD PTR [rsp+768]
        vmovdqu	xmm10, OWORD PTR [rsp+784]
        vmovdqu	xmm11, OWORD PTR [rsp+800]
        vmovdqu	xmm12, OWORD PTR [rsp+816]
        vmovdqu	xmm13, OWORD PTR [rsp+832]
        vmovdqu	xmm14, OWORD PTR [rsp+848]
        vmovdqu	xmm15, OWORD PTR [rsp+864]
        add	rsp, 880
        pop	rbp
        pop	rbx
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        pop	rsi
        pop	rdi
        ret
chacha20_poly1305_avx512 ENDP
_TEXT ENDS
ENDIF
IFDEF HAVE_INTEL_AVX512
_DATA SEGMENT
ALIGN 16
L_cp512_add QWORD 0000000100000000h, 0000000300000002h
        QWORD 0000000500000004h, 0000000700000006h
        QWORD 0000000900000008h, 0000000b0000000ah
        QWORD 0000000d0000000ch, 0000000f0000000eh
ptr_L_cp512_add QWORD L_cp512_add
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_cp512_pc QWORD 00000fffffffffffh, 00000fffffffffffh
        QWORD 00000fffffffffffh, 00000fffffffffffh
        QWORD 00000fffffffffffh, 00000fffffffffffh
        QWORD 00000fffffffffffh, 00000fffffffffffh
        QWORD 0000000000ffffffh, 0000000000ffffffh
        QWORD 0000000000ffffffh, 0000000000ffffffh
        QWORD 0000000000ffffffh, 0000000000ffffffh
        QWORD 0000000000ffffffh, 0000000000ffffffh
        QWORD 0000010000000000h, 0000010000000000h
        QWORD 0000010000000000h, 0000010000000000h
        QWORD 0000010000000000h, 0000010000000000h
        QWORD 0000010000000000h, 0000010000000000h
        QWORD 0000000000000000h, 0000000000000002h
        QWORD 0000000000000004h, 0000000000000006h
        QWORD 0000000000000008h, 000000000000000ah
        QWORD 000000000000000ch, 000000000000000eh
        QWORD 0000000000000001h, 0000000000000003h
        QWORD 0000000000000005h, 0000000000000007h
        QWORD 0000000000000009h, 000000000000000bh
        QWORD 000000000000000dh, 000000000000000fh
        QWORD 0000001000000010h, 0000001000000010h
        QWORD 0000001000000010h, 0000001000000010h
        QWORD 0000001000000010h, 0000001000000010h
        QWORD 0000001000000010h, 0000001000000010h
ptr_L_cp512_pc QWORD L_cp512_pc
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_cp512_rx QWORD 000000000000000ch, 0000000000000008h
        QWORD 0000000000000004h, 0000000000000000h
        QWORD 0000000000000000h, 0000000000000000h
        QWORD 0000000000000000h, 0000000000000000h
        QWORD 000000000000000dh, 0000000000000009h
        QWORD 0000000000000005h, 0000000000000001h
        QWORD 0000000000000000h, 0000000000000000h
        QWORD 0000000000000000h, 0000000000000000h
        QWORD 000000000000000eh, 000000000000000ah
        QWORD 0000000000000006h, 0000000000000002h
        QWORD 0000000000000000h, 0000000000000000h
        QWORD 0000000000000000h, 0000000000000000h
ptr_L_cp512_rx QWORD L_cp512_rx
_DATA ENDS
_TEXT SEGMENT READONLY PARA
chacha20_poly1305_ifma PROC
        push	rdi
        push	rsi
        push	r12
        push	r13
        push	r14
        mov	rdi, rcx
        mov	rsi, rdx
        mov	rdx, r8
        mov	rcx, r9
        mov	rax, QWORD PTR [rsp+80]
        sub	rsp, 1360
        vmovdqu	OWORD PTR [rsp+1200], xmm6
        vmovdqu	OWORD PTR [rsp+1216], xmm7
        vmovdqu	OWORD PTR [rsp+1232], xmm8
        vmovdqu	OWORD PTR [rsp+1248], xmm9
        vmovdqu	OWORD PTR [rsp+1264], xmm10
        vmovdqu	OWORD PTR [rsp+1280], xmm11
        vmovdqu	OWORD PTR [rsp+1296], xmm12
        vmovdqu	OWORD PTR [rsp+1312], xmm13
        vmovdqu	OWORD PTR [rsp+1328], xmm14
        vmovdqu	OWORD PTR [rsp+1344], xmm15
        mov	r8, QWORD PTR [ptr_L_cp512_pc]
        mov	r10, QWORD PTR [ptr_L_cp512_rx]
        mov	r9, QWORD PTR [ptr_L_cp512_add]
        lea	r11, QWORD PTR [rsp+32]
        add	r11, 63
        and	r11, -64
        vpxorq	zmm16, zmm16, zmm16
        vpxorq	zmm17, zmm17, zmm17
        vpxorq	zmm18, zmm18, zmm18
        vmovdqu64	[rsi+752], zmm16
        vmovdqu64	[rsi+816], zmm17
        vmovdqu64	[rsi+880], zmm18
        vpbroadcastq	zmm19, QWORD PTR [rsi+720]
        vpbroadcastq	zmm20, QWORD PTR [rsi+728]
        vpbroadcastq	zmm21, QWORD PTR [rsi+736]
        vpsllq	zmm30, zmm20, 2
        vpsllq	zmm22, zmm20, 4
        vpaddq	zmm22, zmm22, zmm30
        vpsllq	zmm30, zmm21, 2
        vpsllq	zmm23, zmm21, 4
        vpaddq	zmm23, zmm23, zmm30
        vpbroadcastd	zmm0, DWORD PTR [rdi]
        vpbroadcastd	zmm1, DWORD PTR [rdi+4]
        vpbroadcastd	zmm2, DWORD PTR [rdi+8]
        vpbroadcastd	zmm3, DWORD PTR [rdi+12]
        vpbroadcastd	zmm4, DWORD PTR [rdi+16]
        vpbroadcastd	zmm5, DWORD PTR [rdi+20]
        vpbroadcastd	zmm6, DWORD PTR [rdi+24]
        vpbroadcastd	zmm7, DWORD PTR [rdi+28]
        vpbroadcastd	zmm8, DWORD PTR [rdi+32]
        vpbroadcastd	zmm9, DWORD PTR [rdi+36]
        vpbroadcastd	zmm10, DWORD PTR [rdi+40]
        vpbroadcastd	zmm11, DWORD PTR [rdi+44]
        vpbroadcastd	zmm12, DWORD PTR [rdi+48]
        vpbroadcastd	zmm13, DWORD PTR [rdi+52]
        vpbroadcastd	zmm14, DWORD PTR [rdi+56]
        vpbroadcastd	zmm15, DWORD PTR [rdi+60]
        vpaddd	zmm12, zmm12, [r9]
        vmovdqa64	[r11], zmm0
        vmovdqa64	[r11+64], zmm1
        vmovdqa64	[r11+128], zmm2
        vmovdqa64	[r11+192], zmm3
        vmovdqa64	[r11+256], zmm4
        vmovdqa64	[r11+320], zmm5
        vmovdqa64	[r11+384], zmm6
        vmovdqa64	[r11+448], zmm7
        vmovdqa64	[r11+512], zmm8
        vmovdqa64	[r11+576], zmm9
        vmovdqa64	[r11+640], zmm10
        vmovdqa64	[r11+704], zmm11
        vmovdqa64	[r11+768], zmm12
        vmovdqa64	[r11+832], zmm13
        vmovdqa64	[r11+896], zmm14
        vmovdqa64	[r11+960], zmm15
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vprold	zmm15, zmm15, 16
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 12
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vprold	zmm15, zmm15, 8
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 7
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 16
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vprold	zmm4, zmm4, 12
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 8
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vprold	zmm4, zmm4, 7
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vprold	zmm15, zmm15, 16
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 12
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vprold	zmm15, zmm15, 8
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 7
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 16
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vprold	zmm4, zmm4, 12
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 8
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vprold	zmm4, zmm4, 7
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vprold	zmm15, zmm15, 16
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 12
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vprold	zmm15, zmm15, 8
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 7
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 16
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vprold	zmm4, zmm4, 12
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 8
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vprold	zmm4, zmm4, 7
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vprold	zmm15, zmm15, 16
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 12
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vprold	zmm15, zmm15, 8
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 7
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 16
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vprold	zmm4, zmm4, 12
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 8
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vprold	zmm4, zmm4, 7
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vprold	zmm15, zmm15, 16
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 12
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vprold	zmm15, zmm15, 8
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 7
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 16
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vprold	zmm4, zmm4, 12
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 8
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vprold	zmm4, zmm4, 7
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vprold	zmm15, zmm15, 16
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 12
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vprold	zmm15, zmm15, 8
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 7
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 16
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vprold	zmm4, zmm4, 12
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 8
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vprold	zmm4, zmm4, 7
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vprold	zmm15, zmm15, 16
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 12
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vprold	zmm15, zmm15, 8
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 7
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 16
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vprold	zmm4, zmm4, 12
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 8
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vprold	zmm4, zmm4, 7
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vprold	zmm15, zmm15, 16
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 12
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vprold	zmm15, zmm15, 8
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 7
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 16
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vprold	zmm4, zmm4, 12
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 8
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vprold	zmm4, zmm4, 7
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vprold	zmm15, zmm15, 16
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 12
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vprold	zmm15, zmm15, 8
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 7
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 16
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vprold	zmm4, zmm4, 12
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 8
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vprold	zmm4, zmm4, 7
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vprold	zmm15, zmm15, 16
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 12
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vprold	zmm15, zmm15, 8
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 7
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 16
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vprold	zmm4, zmm4, 12
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 8
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vprold	zmm4, zmm4, 7
        vpaddd	zmm0, zmm0, [r11]
        vpaddd	zmm1, zmm1, [r11+64]
        vpaddd	zmm2, zmm2, [r11+128]
        vpaddd	zmm3, zmm3, [r11+192]
        vpaddd	zmm4, zmm4, [r11+256]
        vpaddd	zmm5, zmm5, [r11+320]
        vpaddd	zmm6, zmm6, [r11+384]
        vpaddd	zmm7, zmm7, [r11+448]
        vpaddd	zmm8, zmm8, [r11+512]
        vpaddd	zmm9, zmm9, [r11+576]
        vpaddd	zmm10, zmm10, [r11+640]
        vpaddd	zmm11, zmm11, [r11+704]
        vpaddd	zmm12, zmm12, [r11+768]
        vpaddd	zmm13, zmm13, [r11+832]
        vpaddd	zmm14, zmm14, [r11+896]
        vpaddd	zmm15, zmm15, [r11+960]
        vpunpckldq	zmm16, zmm0, zmm1
        vpunpckhdq	zmm17, zmm0, zmm1
        vpunpckldq	zmm18, zmm2, zmm3
        vpunpckhdq	zmm19, zmm2, zmm3
        vpunpckldq	zmm20, zmm4, zmm5
        vpunpckhdq	zmm21, zmm4, zmm5
        vpunpckldq	zmm22, zmm6, zmm7
        vpunpckhdq	zmm23, zmm6, zmm7
        vpunpckldq	zmm24, zmm8, zmm9
        vpunpckhdq	zmm25, zmm8, zmm9
        vpunpckldq	zmm26, zmm10, zmm11
        vpunpckhdq	zmm27, zmm10, zmm11
        vpunpckldq	zmm28, zmm12, zmm13
        vpunpckhdq	zmm29, zmm12, zmm13
        vpunpckldq	zmm30, zmm14, zmm15
        vpunpckhdq	zmm31, zmm14, zmm15
        vpunpcklqdq	zmm0, zmm16, zmm18
        vpunpckhqdq	zmm1, zmm16, zmm18
        vpunpcklqdq	zmm2, zmm17, zmm19
        vpunpckhqdq	zmm3, zmm17, zmm19
        vpunpcklqdq	zmm4, zmm20, zmm22
        vpunpckhqdq	zmm5, zmm20, zmm22
        vpunpcklqdq	zmm6, zmm21, zmm23
        vpunpckhqdq	zmm7, zmm21, zmm23
        vpunpcklqdq	zmm8, zmm24, zmm26
        vpunpckhqdq	zmm9, zmm24, zmm26
        vpunpcklqdq	zmm10, zmm25, zmm27
        vpunpckhqdq	zmm11, zmm25, zmm27
        vpunpcklqdq	zmm12, zmm28, zmm30
        vpunpckhqdq	zmm13, zmm28, zmm30
        vpunpcklqdq	zmm14, zmm29, zmm31
        vpunpckhqdq	zmm15, zmm29, zmm31
        vshufi32x4	zmm16, zmm0, zmm4, 68
        vshufi32x4	zmm17, zmm0, zmm4, 238
        vshufi32x4	zmm18, zmm8, zmm12, 68
        vshufi32x4	zmm19, zmm8, zmm12, 238
        vshufi32x4	zmm20, zmm16, zmm18, 136
        vshufi32x4	zmm21, zmm16, zmm18, 221
        vshufi32x4	zmm22, zmm17, zmm19, 136
        vshufi32x4	zmm23, zmm17, zmm19, 221
        vpxord	zmm20, zmm20, [rdx]
        vmovdqu64	[rcx], zmm20
        vpxord	zmm21, zmm21, [rdx+256]
        vmovdqu64	[rcx+256], zmm21
        vpxord	zmm22, zmm22, [rdx+512]
        vmovdqu64	[rcx+512], zmm22
        vpxord	zmm23, zmm23, [rdx+768]
        vmovdqu64	[rcx+768], zmm23
        vshufi32x4	zmm16, zmm1, zmm5, 68
        vshufi32x4	zmm17, zmm1, zmm5, 238
        vshufi32x4	zmm18, zmm9, zmm13, 68
        vshufi32x4	zmm19, zmm9, zmm13, 238
        vshufi32x4	zmm20, zmm16, zmm18, 136
        vshufi32x4	zmm21, zmm16, zmm18, 221
        vshufi32x4	zmm22, zmm17, zmm19, 136
        vshufi32x4	zmm23, zmm17, zmm19, 221
        vpxord	zmm20, zmm20, [rdx+64]
        vmovdqu64	[rcx+64], zmm20
        vpxord	zmm21, zmm21, [rdx+320]
        vmovdqu64	[rcx+320], zmm21
        vpxord	zmm22, zmm22, [rdx+576]
        vmovdqu64	[rcx+576], zmm22
        vpxord	zmm23, zmm23, [rdx+832]
        vmovdqu64	[rcx+832], zmm23
        vshufi32x4	zmm16, zmm2, zmm6, 68
        vshufi32x4	zmm17, zmm2, zmm6, 238
        vshufi32x4	zmm18, zmm10, zmm14, 68
        vshufi32x4	zmm19, zmm10, zmm14, 238
        vshufi32x4	zmm20, zmm16, zmm18, 136
        vshufi32x4	zmm21, zmm16, zmm18, 221
        vshufi32x4	zmm22, zmm17, zmm19, 136
        vshufi32x4	zmm23, zmm17, zmm19, 221
        vpxord	zmm20, zmm20, [rdx+128]
        vmovdqu64	[rcx+128], zmm20
        vpxord	zmm21, zmm21, [rdx+384]
        vmovdqu64	[rcx+384], zmm21
        vpxord	zmm22, zmm22, [rdx+640]
        vmovdqu64	[rcx+640], zmm22
        vpxord	zmm23, zmm23, [rdx+896]
        vmovdqu64	[rcx+896], zmm23
        vshufi32x4	zmm16, zmm3, zmm7, 68
        vshufi32x4	zmm17, zmm3, zmm7, 238
        vshufi32x4	zmm18, zmm11, zmm15, 68
        vshufi32x4	zmm19, zmm11, zmm15, 238
        vshufi32x4	zmm20, zmm16, zmm18, 136
        vshufi32x4	zmm21, zmm16, zmm18, 221
        vshufi32x4	zmm22, zmm17, zmm19, 136
        vshufi32x4	zmm23, zmm17, zmm19, 221
        vpxord	zmm20, zmm20, [rdx+192]
        vmovdqu64	[rcx+192], zmm20
        vpxord	zmm21, zmm21, [rdx+448]
        vmovdqu64	[rcx+448], zmm21
        vpxord	zmm22, zmm22, [rdx+704]
        vmovdqu64	[rcx+704], zmm22
        vpxord	zmm23, zmm23, [rdx+960]
        vmovdqu64	[rcx+960], zmm23
        vmovdqa64	zmm12, [r11+768]
        vpaddd	zmm12, zmm12, [r8+320]
        vmovdqa64	[r11+768], zmm12
        vmovdqa64	zmm0, [r11]
        vmovdqa64	zmm1, [r11+64]
        vmovdqa64	zmm2, [r11+128]
        vmovdqa64	zmm3, [r11+192]
        vmovdqa64	zmm4, [r11+256]
        vmovdqa64	zmm5, [r11+320]
        vmovdqa64	zmm6, [r11+384]
        vmovdqa64	zmm7, [r11+448]
        vmovdqa64	zmm8, [r11+512]
        vmovdqa64	zmm9, [r11+576]
        vmovdqa64	zmm10, [r11+640]
        vmovdqa64	zmm11, [r11+704]
        vmovdqa64	zmm12, [r11+768]
        vmovdqa64	zmm13, [r11+832]
        vmovdqa64	zmm14, [r11+896]
        vmovdqa64	zmm15, [r11+960]
        add	rdx, 1024
        add	rcx, 1024
        sub	eax, 1024
        jz	L_cp512_epi
L_cp512_start:
        vmovdqu64	zmm16, [rsi+752]
        vmovdqu64	zmm17, [rsi+816]
        vmovdqu64	zmm18, [rsi+880]
        vpbroadcastq	zmm19, QWORD PTR [rsi+720]
        vpbroadcastq	zmm20, QWORD PTR [rsi+728]
        vpbroadcastq	zmm21, QWORD PTR [rsi+736]
        vpsllq	zmm30, zmm20, 2
        vpsllq	zmm22, zmm20, 4
        vpaddq	zmm22, zmm22, zmm30
        vpsllq	zmm30, zmm21, 2
        vpsllq	zmm23, zmm21, 4
        vpaddq	zmm23, zmm23, zmm30
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vprold	zmm15, zmm15, 16
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 12
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vprold	zmm15, zmm15, 8
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 7
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 16
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vprold	zmm4, zmm4, 12
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 8
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vprold	zmm4, zmm4, 7
        vmovdqu64	zmm27, [rcx+-1024]
        vmovdqu64	zmm28, [rcx+-960]
        vmovdqu64	zmm29, [r8+192]
        vpermi2q	zmm29, zmm27, zmm28
        vmovdqu64	zmm30, [r8+256]
        vpermi2q	zmm30, zmm27, zmm28
        vpandq	zmm24, zmm29, [r8]
        vpsrlq	zmm27, zmm29, 44
        vpandq	zmm28, zmm30, [r8+64]
        vpsllq	zmm28, zmm28, 20
        vporq	zmm25, zmm28, zmm27
        vpsrlq	zmm26, zmm30, 24
        vporq	zmm26, zmm26, [r8+128]
        vpxorq	zmm27, zmm27, zmm27
        vpxorq	zmm28, zmm28, zmm28
        vpxorq	zmm29, zmm29, zmm29
        vpmadd52luq	zmm24, zmm16, zmm19
        vpmadd52luq	zmm24, zmm17, zmm23
        vpmadd52luq	zmm24, zmm18, zmm22
        vpmadd52huq	zmm27, zmm16, zmm19
        vpmadd52huq	zmm27, zmm17, zmm23
        vpmadd52huq	zmm27, zmm18, zmm22
        vpmadd52luq	zmm25, zmm16, zmm20
        vpmadd52luq	zmm25, zmm17, zmm19
        vpmadd52luq	zmm25, zmm18, zmm23
        vpmadd52huq	zmm28, zmm16, zmm20
        vpmadd52huq	zmm28, zmm17, zmm19
        vpmadd52huq	zmm28, zmm18, zmm23
        vpmadd52luq	zmm26, zmm16, zmm21
        vpmadd52luq	zmm26, zmm17, zmm20
        vpmadd52luq	zmm26, zmm18, zmm19
        vpmadd52huq	zmm29, zmm16, zmm21
        vpmadd52huq	zmm29, zmm17, zmm20
        vpmadd52huq	zmm29, zmm18, zmm19
        vpsllq	zmm30, zmm27, 8
        vpaddq	zmm25, zmm30, zmm25
        vpsllq	zmm30, zmm28, 8
        vpaddq	zmm26, zmm30, zmm26
        vpsllq	zmm31, zmm29, 8
        vpsllq	zmm30, zmm31, 2
        vpsllq	zmm31, zmm31, 4
        vpaddq	zmm31, zmm31, zmm30
        vpaddq	zmm24, zmm31, zmm24
        vpsrlq	zmm30, zmm24, 44
        vpandq	zmm16, zmm24, [r8]
        vpaddq	zmm25, zmm30, zmm25
        vpsrlq	zmm30, zmm25, 44
        vpandq	zmm17, zmm25, [r8]
        vpaddq	zmm26, zmm30, zmm26
        vpsrlq	zmm30, zmm26, 44
        vpandq	zmm18, zmm26, [r8]
        vpsllq	zmm31, zmm30, 2
        vpsllq	zmm30, zmm30, 4
        vpaddq	zmm30, zmm30, zmm31
        vpaddq	zmm16, zmm30, zmm16
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vprold	zmm15, zmm15, 16
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 12
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vprold	zmm15, zmm15, 8
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 7
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 16
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vprold	zmm4, zmm4, 12
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 8
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vprold	zmm4, zmm4, 7
        vmovdqu64	zmm27, [rcx+-896]
        vmovdqu64	zmm28, [rcx+-832]
        vmovdqu64	zmm29, [r8+192]
        vpermi2q	zmm29, zmm27, zmm28
        vmovdqu64	zmm30, [r8+256]
        vpermi2q	zmm30, zmm27, zmm28
        vpandq	zmm24, zmm29, [r8]
        vpsrlq	zmm27, zmm29, 44
        vpandq	zmm28, zmm30, [r8+64]
        vpsllq	zmm28, zmm28, 20
        vporq	zmm25, zmm28, zmm27
        vpsrlq	zmm26, zmm30, 24
        vporq	zmm26, zmm26, [r8+128]
        vpxorq	zmm27, zmm27, zmm27
        vpxorq	zmm28, zmm28, zmm28
        vpxorq	zmm29, zmm29, zmm29
        vpmadd52luq	zmm24, zmm16, zmm19
        vpmadd52luq	zmm24, zmm17, zmm23
        vpmadd52luq	zmm24, zmm18, zmm22
        vpmadd52huq	zmm27, zmm16, zmm19
        vpmadd52huq	zmm27, zmm17, zmm23
        vpmadd52huq	zmm27, zmm18, zmm22
        vpmadd52luq	zmm25, zmm16, zmm20
        vpmadd52luq	zmm25, zmm17, zmm19
        vpmadd52luq	zmm25, zmm18, zmm23
        vpmadd52huq	zmm28, zmm16, zmm20
        vpmadd52huq	zmm28, zmm17, zmm19
        vpmadd52huq	zmm28, zmm18, zmm23
        vpmadd52luq	zmm26, zmm16, zmm21
        vpmadd52luq	zmm26, zmm17, zmm20
        vpmadd52luq	zmm26, zmm18, zmm19
        vpmadd52huq	zmm29, zmm16, zmm21
        vpmadd52huq	zmm29, zmm17, zmm20
        vpmadd52huq	zmm29, zmm18, zmm19
        vpsllq	zmm30, zmm27, 8
        vpaddq	zmm25, zmm30, zmm25
        vpsllq	zmm30, zmm28, 8
        vpaddq	zmm26, zmm30, zmm26
        vpsllq	zmm31, zmm29, 8
        vpsllq	zmm30, zmm31, 2
        vpsllq	zmm31, zmm31, 4
        vpaddq	zmm31, zmm31, zmm30
        vpaddq	zmm24, zmm31, zmm24
        vpsrlq	zmm30, zmm24, 44
        vpandq	zmm16, zmm24, [r8]
        vpaddq	zmm25, zmm30, zmm25
        vpsrlq	zmm30, zmm25, 44
        vpandq	zmm17, zmm25, [r8]
        vpaddq	zmm26, zmm30, zmm26
        vpsrlq	zmm30, zmm26, 44
        vpandq	zmm18, zmm26, [r8]
        vpsllq	zmm31, zmm30, 2
        vpsllq	zmm30, zmm30, 4
        vpaddq	zmm30, zmm30, zmm31
        vpaddq	zmm16, zmm30, zmm16
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vprold	zmm15, zmm15, 16
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 12
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vprold	zmm15, zmm15, 8
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 7
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 16
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vprold	zmm4, zmm4, 12
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 8
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vprold	zmm4, zmm4, 7
        vmovdqu64	zmm27, [rcx+-768]
        vmovdqu64	zmm28, [rcx+-704]
        vmovdqu64	zmm29, [r8+192]
        vpermi2q	zmm29, zmm27, zmm28
        vmovdqu64	zmm30, [r8+256]
        vpermi2q	zmm30, zmm27, zmm28
        vpandq	zmm24, zmm29, [r8]
        vpsrlq	zmm27, zmm29, 44
        vpandq	zmm28, zmm30, [r8+64]
        vpsllq	zmm28, zmm28, 20
        vporq	zmm25, zmm28, zmm27
        vpsrlq	zmm26, zmm30, 24
        vporq	zmm26, zmm26, [r8+128]
        vpxorq	zmm27, zmm27, zmm27
        vpxorq	zmm28, zmm28, zmm28
        vpxorq	zmm29, zmm29, zmm29
        vpmadd52luq	zmm24, zmm16, zmm19
        vpmadd52luq	zmm24, zmm17, zmm23
        vpmadd52luq	zmm24, zmm18, zmm22
        vpmadd52huq	zmm27, zmm16, zmm19
        vpmadd52huq	zmm27, zmm17, zmm23
        vpmadd52huq	zmm27, zmm18, zmm22
        vpmadd52luq	zmm25, zmm16, zmm20
        vpmadd52luq	zmm25, zmm17, zmm19
        vpmadd52luq	zmm25, zmm18, zmm23
        vpmadd52huq	zmm28, zmm16, zmm20
        vpmadd52huq	zmm28, zmm17, zmm19
        vpmadd52huq	zmm28, zmm18, zmm23
        vpmadd52luq	zmm26, zmm16, zmm21
        vpmadd52luq	zmm26, zmm17, zmm20
        vpmadd52luq	zmm26, zmm18, zmm19
        vpmadd52huq	zmm29, zmm16, zmm21
        vpmadd52huq	zmm29, zmm17, zmm20
        vpmadd52huq	zmm29, zmm18, zmm19
        vpsllq	zmm30, zmm27, 8
        vpaddq	zmm25, zmm30, zmm25
        vpsllq	zmm30, zmm28, 8
        vpaddq	zmm26, zmm30, zmm26
        vpsllq	zmm31, zmm29, 8
        vpsllq	zmm30, zmm31, 2
        vpsllq	zmm31, zmm31, 4
        vpaddq	zmm31, zmm31, zmm30
        vpaddq	zmm24, zmm31, zmm24
        vpsrlq	zmm30, zmm24, 44
        vpandq	zmm16, zmm24, [r8]
        vpaddq	zmm25, zmm30, zmm25
        vpsrlq	zmm30, zmm25, 44
        vpandq	zmm17, zmm25, [r8]
        vpaddq	zmm26, zmm30, zmm26
        vpsrlq	zmm30, zmm26, 44
        vpandq	zmm18, zmm26, [r8]
        vpsllq	zmm31, zmm30, 2
        vpsllq	zmm30, zmm30, 4
        vpaddq	zmm30, zmm30, zmm31
        vpaddq	zmm16, zmm30, zmm16
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vprold	zmm15, zmm15, 16
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 12
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vprold	zmm15, zmm15, 8
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 7
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 16
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vprold	zmm4, zmm4, 12
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 8
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vprold	zmm4, zmm4, 7
        vmovdqu64	zmm27, [rcx+-640]
        vmovdqu64	zmm28, [rcx+-576]
        vmovdqu64	zmm29, [r8+192]
        vpermi2q	zmm29, zmm27, zmm28
        vmovdqu64	zmm30, [r8+256]
        vpermi2q	zmm30, zmm27, zmm28
        vpandq	zmm24, zmm29, [r8]
        vpsrlq	zmm27, zmm29, 44
        vpandq	zmm28, zmm30, [r8+64]
        vpsllq	zmm28, zmm28, 20
        vporq	zmm25, zmm28, zmm27
        vpsrlq	zmm26, zmm30, 24
        vporq	zmm26, zmm26, [r8+128]
        vpxorq	zmm27, zmm27, zmm27
        vpxorq	zmm28, zmm28, zmm28
        vpxorq	zmm29, zmm29, zmm29
        vpmadd52luq	zmm24, zmm16, zmm19
        vpmadd52luq	zmm24, zmm17, zmm23
        vpmadd52luq	zmm24, zmm18, zmm22
        vpmadd52huq	zmm27, zmm16, zmm19
        vpmadd52huq	zmm27, zmm17, zmm23
        vpmadd52huq	zmm27, zmm18, zmm22
        vpmadd52luq	zmm25, zmm16, zmm20
        vpmadd52luq	zmm25, zmm17, zmm19
        vpmadd52luq	zmm25, zmm18, zmm23
        vpmadd52huq	zmm28, zmm16, zmm20
        vpmadd52huq	zmm28, zmm17, zmm19
        vpmadd52huq	zmm28, zmm18, zmm23
        vpmadd52luq	zmm26, zmm16, zmm21
        vpmadd52luq	zmm26, zmm17, zmm20
        vpmadd52luq	zmm26, zmm18, zmm19
        vpmadd52huq	zmm29, zmm16, zmm21
        vpmadd52huq	zmm29, zmm17, zmm20
        vpmadd52huq	zmm29, zmm18, zmm19
        vpsllq	zmm30, zmm27, 8
        vpaddq	zmm25, zmm30, zmm25
        vpsllq	zmm30, zmm28, 8
        vpaddq	zmm26, zmm30, zmm26
        vpsllq	zmm31, zmm29, 8
        vpsllq	zmm30, zmm31, 2
        vpsllq	zmm31, zmm31, 4
        vpaddq	zmm31, zmm31, zmm30
        vpaddq	zmm24, zmm31, zmm24
        vpsrlq	zmm30, zmm24, 44
        vpandq	zmm16, zmm24, [r8]
        vpaddq	zmm25, zmm30, zmm25
        vpsrlq	zmm30, zmm25, 44
        vpandq	zmm17, zmm25, [r8]
        vpaddq	zmm26, zmm30, zmm26
        vpsrlq	zmm30, zmm26, 44
        vpandq	zmm18, zmm26, [r8]
        vpsllq	zmm31, zmm30, 2
        vpsllq	zmm30, zmm30, 4
        vpaddq	zmm30, zmm30, zmm31
        vpaddq	zmm16, zmm30, zmm16
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vprold	zmm15, zmm15, 16
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 12
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vprold	zmm15, zmm15, 8
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 7
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 16
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vprold	zmm4, zmm4, 12
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 8
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vprold	zmm4, zmm4, 7
        vmovdqu64	zmm27, [rcx+-512]
        vmovdqu64	zmm28, [rcx+-448]
        vmovdqu64	zmm29, [r8+192]
        vpermi2q	zmm29, zmm27, zmm28
        vmovdqu64	zmm30, [r8+256]
        vpermi2q	zmm30, zmm27, zmm28
        vpandq	zmm24, zmm29, [r8]
        vpsrlq	zmm27, zmm29, 44
        vpandq	zmm28, zmm30, [r8+64]
        vpsllq	zmm28, zmm28, 20
        vporq	zmm25, zmm28, zmm27
        vpsrlq	zmm26, zmm30, 24
        vporq	zmm26, zmm26, [r8+128]
        vpxorq	zmm27, zmm27, zmm27
        vpxorq	zmm28, zmm28, zmm28
        vpxorq	zmm29, zmm29, zmm29
        vpmadd52luq	zmm24, zmm16, zmm19
        vpmadd52luq	zmm24, zmm17, zmm23
        vpmadd52luq	zmm24, zmm18, zmm22
        vpmadd52huq	zmm27, zmm16, zmm19
        vpmadd52huq	zmm27, zmm17, zmm23
        vpmadd52huq	zmm27, zmm18, zmm22
        vpmadd52luq	zmm25, zmm16, zmm20
        vpmadd52luq	zmm25, zmm17, zmm19
        vpmadd52luq	zmm25, zmm18, zmm23
        vpmadd52huq	zmm28, zmm16, zmm20
        vpmadd52huq	zmm28, zmm17, zmm19
        vpmadd52huq	zmm28, zmm18, zmm23
        vpmadd52luq	zmm26, zmm16, zmm21
        vpmadd52luq	zmm26, zmm17, zmm20
        vpmadd52luq	zmm26, zmm18, zmm19
        vpmadd52huq	zmm29, zmm16, zmm21
        vpmadd52huq	zmm29, zmm17, zmm20
        vpmadd52huq	zmm29, zmm18, zmm19
        vpsllq	zmm30, zmm27, 8
        vpaddq	zmm25, zmm30, zmm25
        vpsllq	zmm30, zmm28, 8
        vpaddq	zmm26, zmm30, zmm26
        vpsllq	zmm31, zmm29, 8
        vpsllq	zmm30, zmm31, 2
        vpsllq	zmm31, zmm31, 4
        vpaddq	zmm31, zmm31, zmm30
        vpaddq	zmm24, zmm31, zmm24
        vpsrlq	zmm30, zmm24, 44
        vpandq	zmm16, zmm24, [r8]
        vpaddq	zmm25, zmm30, zmm25
        vpsrlq	zmm30, zmm25, 44
        vpandq	zmm17, zmm25, [r8]
        vpaddq	zmm26, zmm30, zmm26
        vpsrlq	zmm30, zmm26, 44
        vpandq	zmm18, zmm26, [r8]
        vpsllq	zmm31, zmm30, 2
        vpsllq	zmm30, zmm30, 4
        vpaddq	zmm30, zmm30, zmm31
        vpaddq	zmm16, zmm30, zmm16
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vprold	zmm15, zmm15, 16
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 12
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vprold	zmm15, zmm15, 8
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 7
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 16
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vprold	zmm4, zmm4, 12
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 8
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vprold	zmm4, zmm4, 7
        vmovdqu64	zmm27, [rcx+-384]
        vmovdqu64	zmm28, [rcx+-320]
        vmovdqu64	zmm29, [r8+192]
        vpermi2q	zmm29, zmm27, zmm28
        vmovdqu64	zmm30, [r8+256]
        vpermi2q	zmm30, zmm27, zmm28
        vpandq	zmm24, zmm29, [r8]
        vpsrlq	zmm27, zmm29, 44
        vpandq	zmm28, zmm30, [r8+64]
        vpsllq	zmm28, zmm28, 20
        vporq	zmm25, zmm28, zmm27
        vpsrlq	zmm26, zmm30, 24
        vporq	zmm26, zmm26, [r8+128]
        vpxorq	zmm27, zmm27, zmm27
        vpxorq	zmm28, zmm28, zmm28
        vpxorq	zmm29, zmm29, zmm29
        vpmadd52luq	zmm24, zmm16, zmm19
        vpmadd52luq	zmm24, zmm17, zmm23
        vpmadd52luq	zmm24, zmm18, zmm22
        vpmadd52huq	zmm27, zmm16, zmm19
        vpmadd52huq	zmm27, zmm17, zmm23
        vpmadd52huq	zmm27, zmm18, zmm22
        vpmadd52luq	zmm25, zmm16, zmm20
        vpmadd52luq	zmm25, zmm17, zmm19
        vpmadd52luq	zmm25, zmm18, zmm23
        vpmadd52huq	zmm28, zmm16, zmm20
        vpmadd52huq	zmm28, zmm17, zmm19
        vpmadd52huq	zmm28, zmm18, zmm23
        vpmadd52luq	zmm26, zmm16, zmm21
        vpmadd52luq	zmm26, zmm17, zmm20
        vpmadd52luq	zmm26, zmm18, zmm19
        vpmadd52huq	zmm29, zmm16, zmm21
        vpmadd52huq	zmm29, zmm17, zmm20
        vpmadd52huq	zmm29, zmm18, zmm19
        vpsllq	zmm30, zmm27, 8
        vpaddq	zmm25, zmm30, zmm25
        vpsllq	zmm30, zmm28, 8
        vpaddq	zmm26, zmm30, zmm26
        vpsllq	zmm31, zmm29, 8
        vpsllq	zmm30, zmm31, 2
        vpsllq	zmm31, zmm31, 4
        vpaddq	zmm31, zmm31, zmm30
        vpaddq	zmm24, zmm31, zmm24
        vpsrlq	zmm30, zmm24, 44
        vpandq	zmm16, zmm24, [r8]
        vpaddq	zmm25, zmm30, zmm25
        vpsrlq	zmm30, zmm25, 44
        vpandq	zmm17, zmm25, [r8]
        vpaddq	zmm26, zmm30, zmm26
        vpsrlq	zmm30, zmm26, 44
        vpandq	zmm18, zmm26, [r8]
        vpsllq	zmm31, zmm30, 2
        vpsllq	zmm30, zmm30, 4
        vpaddq	zmm30, zmm30, zmm31
        vpaddq	zmm16, zmm30, zmm16
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vprold	zmm15, zmm15, 16
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 12
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vprold	zmm15, zmm15, 8
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 7
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 16
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vprold	zmm4, zmm4, 12
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 8
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vprold	zmm4, zmm4, 7
        vmovdqu64	zmm27, [rcx+-256]
        vmovdqu64	zmm28, [rcx+-192]
        vmovdqu64	zmm29, [r8+192]
        vpermi2q	zmm29, zmm27, zmm28
        vmovdqu64	zmm30, [r8+256]
        vpermi2q	zmm30, zmm27, zmm28
        vpandq	zmm24, zmm29, [r8]
        vpsrlq	zmm27, zmm29, 44
        vpandq	zmm28, zmm30, [r8+64]
        vpsllq	zmm28, zmm28, 20
        vporq	zmm25, zmm28, zmm27
        vpsrlq	zmm26, zmm30, 24
        vporq	zmm26, zmm26, [r8+128]
        vpxorq	zmm27, zmm27, zmm27
        vpxorq	zmm28, zmm28, zmm28
        vpxorq	zmm29, zmm29, zmm29
        vpmadd52luq	zmm24, zmm16, zmm19
        vpmadd52luq	zmm24, zmm17, zmm23
        vpmadd52luq	zmm24, zmm18, zmm22
        vpmadd52huq	zmm27, zmm16, zmm19
        vpmadd52huq	zmm27, zmm17, zmm23
        vpmadd52huq	zmm27, zmm18, zmm22
        vpmadd52luq	zmm25, zmm16, zmm20
        vpmadd52luq	zmm25, zmm17, zmm19
        vpmadd52luq	zmm25, zmm18, zmm23
        vpmadd52huq	zmm28, zmm16, zmm20
        vpmadd52huq	zmm28, zmm17, zmm19
        vpmadd52huq	zmm28, zmm18, zmm23
        vpmadd52luq	zmm26, zmm16, zmm21
        vpmadd52luq	zmm26, zmm17, zmm20
        vpmadd52luq	zmm26, zmm18, zmm19
        vpmadd52huq	zmm29, zmm16, zmm21
        vpmadd52huq	zmm29, zmm17, zmm20
        vpmadd52huq	zmm29, zmm18, zmm19
        vpsllq	zmm30, zmm27, 8
        vpaddq	zmm25, zmm30, zmm25
        vpsllq	zmm30, zmm28, 8
        vpaddq	zmm26, zmm30, zmm26
        vpsllq	zmm31, zmm29, 8
        vpsllq	zmm30, zmm31, 2
        vpsllq	zmm31, zmm31, 4
        vpaddq	zmm31, zmm31, zmm30
        vpaddq	zmm24, zmm31, zmm24
        vpsrlq	zmm30, zmm24, 44
        vpandq	zmm16, zmm24, [r8]
        vpaddq	zmm25, zmm30, zmm25
        vpsrlq	zmm30, zmm25, 44
        vpandq	zmm17, zmm25, [r8]
        vpaddq	zmm26, zmm30, zmm26
        vpsrlq	zmm30, zmm26, 44
        vpandq	zmm18, zmm26, [r8]
        vpsllq	zmm31, zmm30, 2
        vpsllq	zmm30, zmm30, 4
        vpaddq	zmm30, zmm30, zmm31
        vpaddq	zmm16, zmm30, zmm16
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vprold	zmm15, zmm15, 16
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 12
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vprold	zmm15, zmm15, 8
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 7
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 16
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vprold	zmm4, zmm4, 12
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 8
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vprold	zmm4, zmm4, 7
        vmovdqu64	zmm27, [rcx+-128]
        vmovdqu64	zmm28, [rcx+-64]
        vmovdqu64	zmm29, [r8+192]
        vpermi2q	zmm29, zmm27, zmm28
        vmovdqu64	zmm30, [r8+256]
        vpermi2q	zmm30, zmm27, zmm28
        vpandq	zmm24, zmm29, [r8]
        vpsrlq	zmm27, zmm29, 44
        vpandq	zmm28, zmm30, [r8+64]
        vpsllq	zmm28, zmm28, 20
        vporq	zmm25, zmm28, zmm27
        vpsrlq	zmm26, zmm30, 24
        vporq	zmm26, zmm26, [r8+128]
        vpxorq	zmm27, zmm27, zmm27
        vpxorq	zmm28, zmm28, zmm28
        vpxorq	zmm29, zmm29, zmm29
        vpmadd52luq	zmm24, zmm16, zmm19
        vpmadd52luq	zmm24, zmm17, zmm23
        vpmadd52luq	zmm24, zmm18, zmm22
        vpmadd52huq	zmm27, zmm16, zmm19
        vpmadd52huq	zmm27, zmm17, zmm23
        vpmadd52huq	zmm27, zmm18, zmm22
        vpmadd52luq	zmm25, zmm16, zmm20
        vpmadd52luq	zmm25, zmm17, zmm19
        vpmadd52luq	zmm25, zmm18, zmm23
        vpmadd52huq	zmm28, zmm16, zmm20
        vpmadd52huq	zmm28, zmm17, zmm19
        vpmadd52huq	zmm28, zmm18, zmm23
        vpmadd52luq	zmm26, zmm16, zmm21
        vpmadd52luq	zmm26, zmm17, zmm20
        vpmadd52luq	zmm26, zmm18, zmm19
        vpmadd52huq	zmm29, zmm16, zmm21
        vpmadd52huq	zmm29, zmm17, zmm20
        vpmadd52huq	zmm29, zmm18, zmm19
        vpsllq	zmm30, zmm27, 8
        vpaddq	zmm25, zmm30, zmm25
        vpsllq	zmm30, zmm28, 8
        vpaddq	zmm26, zmm30, zmm26
        vpsllq	zmm31, zmm29, 8
        vpsllq	zmm30, zmm31, 2
        vpsllq	zmm31, zmm31, 4
        vpaddq	zmm31, zmm31, zmm30
        vpaddq	zmm24, zmm31, zmm24
        vpsrlq	zmm30, zmm24, 44
        vpandq	zmm16, zmm24, [r8]
        vpaddq	zmm25, zmm30, zmm25
        vpsrlq	zmm30, zmm25, 44
        vpandq	zmm17, zmm25, [r8]
        vpaddq	zmm26, zmm30, zmm26
        vpsrlq	zmm30, zmm26, 44
        vpandq	zmm18, zmm26, [r8]
        vpsllq	zmm31, zmm30, 2
        vpsllq	zmm30, zmm30, 4
        vpaddq	zmm30, zmm30, zmm31
        vpaddq	zmm16, zmm30, zmm16
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vprold	zmm15, zmm15, 16
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 12
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vprold	zmm15, zmm15, 8
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 7
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 16
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vprold	zmm4, zmm4, 12
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 8
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vprold	zmm4, zmm4, 7
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vprold	zmm15, zmm15, 16
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 12
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vprold	zmm15, zmm15, 8
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 7
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 16
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vprold	zmm4, zmm4, 12
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 8
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vprold	zmm4, zmm4, 7
        vpaddd	zmm0, zmm0, [r11]
        vpaddd	zmm1, zmm1, [r11+64]
        vpaddd	zmm2, zmm2, [r11+128]
        vpaddd	zmm3, zmm3, [r11+192]
        vpaddd	zmm4, zmm4, [r11+256]
        vpaddd	zmm5, zmm5, [r11+320]
        vpaddd	zmm6, zmm6, [r11+384]
        vpaddd	zmm7, zmm7, [r11+448]
        vpaddd	zmm8, zmm8, [r11+512]
        vpaddd	zmm9, zmm9, [r11+576]
        vpaddd	zmm10, zmm10, [r11+640]
        vpaddd	zmm11, zmm11, [r11+704]
        vpaddd	zmm12, zmm12, [r11+768]
        vpaddd	zmm13, zmm13, [r11+832]
        vpaddd	zmm14, zmm14, [r11+896]
        vpaddd	zmm15, zmm15, [r11+960]
        vmovdqu64	[rsi+752], zmm16
        vmovdqu64	[rsi+816], zmm17
        vmovdqu64	[rsi+880], zmm18
        vpunpckldq	zmm16, zmm0, zmm1
        vpunpckhdq	zmm17, zmm0, zmm1
        vpunpckldq	zmm18, zmm2, zmm3
        vpunpckhdq	zmm19, zmm2, zmm3
        vpunpckldq	zmm20, zmm4, zmm5
        vpunpckhdq	zmm21, zmm4, zmm5
        vpunpckldq	zmm22, zmm6, zmm7
        vpunpckhdq	zmm23, zmm6, zmm7
        vpunpckldq	zmm24, zmm8, zmm9
        vpunpckhdq	zmm25, zmm8, zmm9
        vpunpckldq	zmm26, zmm10, zmm11
        vpunpckhdq	zmm27, zmm10, zmm11
        vpunpckldq	zmm28, zmm12, zmm13
        vpunpckhdq	zmm29, zmm12, zmm13
        vpunpckldq	zmm30, zmm14, zmm15
        vpunpckhdq	zmm31, zmm14, zmm15
        vpunpcklqdq	zmm0, zmm16, zmm18
        vpunpckhqdq	zmm1, zmm16, zmm18
        vpunpcklqdq	zmm2, zmm17, zmm19
        vpunpckhqdq	zmm3, zmm17, zmm19
        vpunpcklqdq	zmm4, zmm20, zmm22
        vpunpckhqdq	zmm5, zmm20, zmm22
        vpunpcklqdq	zmm6, zmm21, zmm23
        vpunpckhqdq	zmm7, zmm21, zmm23
        vpunpcklqdq	zmm8, zmm24, zmm26
        vpunpckhqdq	zmm9, zmm24, zmm26
        vpunpcklqdq	zmm10, zmm25, zmm27
        vpunpckhqdq	zmm11, zmm25, zmm27
        vpunpcklqdq	zmm12, zmm28, zmm30
        vpunpckhqdq	zmm13, zmm28, zmm30
        vpunpcklqdq	zmm14, zmm29, zmm31
        vpunpckhqdq	zmm15, zmm29, zmm31
        vshufi32x4	zmm16, zmm0, zmm4, 68
        vshufi32x4	zmm17, zmm0, zmm4, 238
        vshufi32x4	zmm18, zmm8, zmm12, 68
        vshufi32x4	zmm19, zmm8, zmm12, 238
        vshufi32x4	zmm20, zmm16, zmm18, 136
        vshufi32x4	zmm21, zmm16, zmm18, 221
        vshufi32x4	zmm22, zmm17, zmm19, 136
        vshufi32x4	zmm23, zmm17, zmm19, 221
        vpxord	zmm20, zmm20, [rdx]
        vmovdqu64	[rcx], zmm20
        vpxord	zmm21, zmm21, [rdx+256]
        vmovdqu64	[rcx+256], zmm21
        vpxord	zmm22, zmm22, [rdx+512]
        vmovdqu64	[rcx+512], zmm22
        vpxord	zmm23, zmm23, [rdx+768]
        vmovdqu64	[rcx+768], zmm23
        vshufi32x4	zmm16, zmm1, zmm5, 68
        vshufi32x4	zmm17, zmm1, zmm5, 238
        vshufi32x4	zmm18, zmm9, zmm13, 68
        vshufi32x4	zmm19, zmm9, zmm13, 238
        vshufi32x4	zmm20, zmm16, zmm18, 136
        vshufi32x4	zmm21, zmm16, zmm18, 221
        vshufi32x4	zmm22, zmm17, zmm19, 136
        vshufi32x4	zmm23, zmm17, zmm19, 221
        vpxord	zmm20, zmm20, [rdx+64]
        vmovdqu64	[rcx+64], zmm20
        vpxord	zmm21, zmm21, [rdx+320]
        vmovdqu64	[rcx+320], zmm21
        vpxord	zmm22, zmm22, [rdx+576]
        vmovdqu64	[rcx+576], zmm22
        vpxord	zmm23, zmm23, [rdx+832]
        vmovdqu64	[rcx+832], zmm23
        vshufi32x4	zmm16, zmm2, zmm6, 68
        vshufi32x4	zmm17, zmm2, zmm6, 238
        vshufi32x4	zmm18, zmm10, zmm14, 68
        vshufi32x4	zmm19, zmm10, zmm14, 238
        vshufi32x4	zmm20, zmm16, zmm18, 136
        vshufi32x4	zmm21, zmm16, zmm18, 221
        vshufi32x4	zmm22, zmm17, zmm19, 136
        vshufi32x4	zmm23, zmm17, zmm19, 221
        vpxord	zmm20, zmm20, [rdx+128]
        vmovdqu64	[rcx+128], zmm20
        vpxord	zmm21, zmm21, [rdx+384]
        vmovdqu64	[rcx+384], zmm21
        vpxord	zmm22, zmm22, [rdx+640]
        vmovdqu64	[rcx+640], zmm22
        vpxord	zmm23, zmm23, [rdx+896]
        vmovdqu64	[rcx+896], zmm23
        vshufi32x4	zmm16, zmm3, zmm7, 68
        vshufi32x4	zmm17, zmm3, zmm7, 238
        vshufi32x4	zmm18, zmm11, zmm15, 68
        vshufi32x4	zmm19, zmm11, zmm15, 238
        vshufi32x4	zmm20, zmm16, zmm18, 136
        vshufi32x4	zmm21, zmm16, zmm18, 221
        vshufi32x4	zmm22, zmm17, zmm19, 136
        vshufi32x4	zmm23, zmm17, zmm19, 221
        vpxord	zmm20, zmm20, [rdx+192]
        vmovdqu64	[rcx+192], zmm20
        vpxord	zmm21, zmm21, [rdx+448]
        vmovdqu64	[rcx+448], zmm21
        vpxord	zmm22, zmm22, [rdx+704]
        vmovdqu64	[rcx+704], zmm22
        vpxord	zmm23, zmm23, [rdx+960]
        vmovdqu64	[rcx+960], zmm23
        vmovdqa64	zmm12, [r11+768]
        vpaddd	zmm12, zmm12, [r8+320]
        vmovdqa64	[r11+768], zmm12
        vmovdqa64	zmm0, [r11]
        vmovdqa64	zmm1, [r11+64]
        vmovdqa64	zmm2, [r11+128]
        vmovdqa64	zmm3, [r11+192]
        vmovdqa64	zmm4, [r11+256]
        vmovdqa64	zmm5, [r11+320]
        vmovdqa64	zmm6, [r11+384]
        vmovdqa64	zmm7, [r11+448]
        vmovdqa64	zmm8, [r11+512]
        vmovdqa64	zmm9, [r11+576]
        vmovdqa64	zmm10, [r11+640]
        vmovdqa64	zmm11, [r11+704]
        vmovdqa64	zmm12, [r11+768]
        vmovdqa64	zmm13, [r11+832]
        vmovdqa64	zmm14, [r11+896]
        vmovdqa64	zmm15, [r11+960]
        add	rdx, 1024
        add	rcx, 1024
        sub	eax, 1024
        jnz	L_cp512_start
L_cp512_epi:
        vmovdqu64	zmm16, [rsi+752]
        vmovdqu64	zmm17, [rsi+816]
        vmovdqu64	zmm18, [rsi+880]
        vpbroadcastq	zmm19, QWORD PTR [rsi+720]
        vpbroadcastq	zmm20, QWORD PTR [rsi+728]
        vpbroadcastq	zmm21, QWORD PTR [rsi+736]
        vpsllq	zmm30, zmm20, 2
        vpsllq	zmm22, zmm20, 4
        vpaddq	zmm22, zmm22, zmm30
        vpsllq	zmm30, zmm21, 2
        vpsllq	zmm23, zmm21, 4
        vpaddq	zmm23, zmm23, zmm30
        vmovdqu64	zmm27, [rcx+-1024]
        vmovdqu64	zmm28, [rcx+-960]
        vmovdqu64	zmm29, [r8+192]
        vpermi2q	zmm29, zmm27, zmm28
        vmovdqu64	zmm30, [r8+256]
        vpermi2q	zmm30, zmm27, zmm28
        vpandq	zmm24, zmm29, [r8]
        vpsrlq	zmm27, zmm29, 44
        vpandq	zmm28, zmm30, [r8+64]
        vpsllq	zmm28, zmm28, 20
        vporq	zmm25, zmm28, zmm27
        vpsrlq	zmm26, zmm30, 24
        vporq	zmm26, zmm26, [r8+128]
        vpxorq	zmm27, zmm27, zmm27
        vpxorq	zmm28, zmm28, zmm28
        vpxorq	zmm29, zmm29, zmm29
        vpmadd52luq	zmm24, zmm16, zmm19
        vpmadd52luq	zmm24, zmm17, zmm23
        vpmadd52luq	zmm24, zmm18, zmm22
        vpmadd52huq	zmm27, zmm16, zmm19
        vpmadd52huq	zmm27, zmm17, zmm23
        vpmadd52huq	zmm27, zmm18, zmm22
        vpmadd52luq	zmm25, zmm16, zmm20
        vpmadd52luq	zmm25, zmm17, zmm19
        vpmadd52luq	zmm25, zmm18, zmm23
        vpmadd52huq	zmm28, zmm16, zmm20
        vpmadd52huq	zmm28, zmm17, zmm19
        vpmadd52huq	zmm28, zmm18, zmm23
        vpmadd52luq	zmm26, zmm16, zmm21
        vpmadd52luq	zmm26, zmm17, zmm20
        vpmadd52luq	zmm26, zmm18, zmm19
        vpmadd52huq	zmm29, zmm16, zmm21
        vpmadd52huq	zmm29, zmm17, zmm20
        vpmadd52huq	zmm29, zmm18, zmm19
        vpsllq	zmm30, zmm27, 8
        vpaddq	zmm25, zmm30, zmm25
        vpsllq	zmm30, zmm28, 8
        vpaddq	zmm26, zmm30, zmm26
        vpsllq	zmm31, zmm29, 8
        vpsllq	zmm30, zmm31, 2
        vpsllq	zmm31, zmm31, 4
        vpaddq	zmm31, zmm31, zmm30
        vpaddq	zmm24, zmm31, zmm24
        vpsrlq	zmm30, zmm24, 44
        vpandq	zmm16, zmm24, [r8]
        vpaddq	zmm25, zmm30, zmm25
        vpsrlq	zmm30, zmm25, 44
        vpandq	zmm17, zmm25, [r8]
        vpaddq	zmm26, zmm30, zmm26
        vpsrlq	zmm30, zmm26, 44
        vpandq	zmm18, zmm26, [r8]
        vpsllq	zmm31, zmm30, 2
        vpsllq	zmm30, zmm30, 4
        vpaddq	zmm30, zmm30, zmm31
        vpaddq	zmm16, zmm30, zmm16
        vmovdqu64	zmm27, [rcx+-896]
        vmovdqu64	zmm28, [rcx+-832]
        vmovdqu64	zmm29, [r8+192]
        vpermi2q	zmm29, zmm27, zmm28
        vmovdqu64	zmm30, [r8+256]
        vpermi2q	zmm30, zmm27, zmm28
        vpandq	zmm24, zmm29, [r8]
        vpsrlq	zmm27, zmm29, 44
        vpandq	zmm28, zmm30, [r8+64]
        vpsllq	zmm28, zmm28, 20
        vporq	zmm25, zmm28, zmm27
        vpsrlq	zmm26, zmm30, 24
        vporq	zmm26, zmm26, [r8+128]
        vpxorq	zmm27, zmm27, zmm27
        vpxorq	zmm28, zmm28, zmm28
        vpxorq	zmm29, zmm29, zmm29
        vpmadd52luq	zmm24, zmm16, zmm19
        vpmadd52luq	zmm24, zmm17, zmm23
        vpmadd52luq	zmm24, zmm18, zmm22
        vpmadd52huq	zmm27, zmm16, zmm19
        vpmadd52huq	zmm27, zmm17, zmm23
        vpmadd52huq	zmm27, zmm18, zmm22
        vpmadd52luq	zmm25, zmm16, zmm20
        vpmadd52luq	zmm25, zmm17, zmm19
        vpmadd52luq	zmm25, zmm18, zmm23
        vpmadd52huq	zmm28, zmm16, zmm20
        vpmadd52huq	zmm28, zmm17, zmm19
        vpmadd52huq	zmm28, zmm18, zmm23
        vpmadd52luq	zmm26, zmm16, zmm21
        vpmadd52luq	zmm26, zmm17, zmm20
        vpmadd52luq	zmm26, zmm18, zmm19
        vpmadd52huq	zmm29, zmm16, zmm21
        vpmadd52huq	zmm29, zmm17, zmm20
        vpmadd52huq	zmm29, zmm18, zmm19
        vpsllq	zmm30, zmm27, 8
        vpaddq	zmm25, zmm30, zmm25
        vpsllq	zmm30, zmm28, 8
        vpaddq	zmm26, zmm30, zmm26
        vpsllq	zmm31, zmm29, 8
        vpsllq	zmm30, zmm31, 2
        vpsllq	zmm31, zmm31, 4
        vpaddq	zmm31, zmm31, zmm30
        vpaddq	zmm24, zmm31, zmm24
        vpsrlq	zmm30, zmm24, 44
        vpandq	zmm16, zmm24, [r8]
        vpaddq	zmm25, zmm30, zmm25
        vpsrlq	zmm30, zmm25, 44
        vpandq	zmm17, zmm25, [r8]
        vpaddq	zmm26, zmm30, zmm26
        vpsrlq	zmm30, zmm26, 44
        vpandq	zmm18, zmm26, [r8]
        vpsllq	zmm31, zmm30, 2
        vpsllq	zmm30, zmm30, 4
        vpaddq	zmm30, zmm30, zmm31
        vpaddq	zmm16, zmm30, zmm16
        vmovdqu64	zmm27, [rcx+-768]
        vmovdqu64	zmm28, [rcx+-704]
        vmovdqu64	zmm29, [r8+192]
        vpermi2q	zmm29, zmm27, zmm28
        vmovdqu64	zmm30, [r8+256]
        vpermi2q	zmm30, zmm27, zmm28
        vpandq	zmm24, zmm29, [r8]
        vpsrlq	zmm27, zmm29, 44
        vpandq	zmm28, zmm30, [r8+64]
        vpsllq	zmm28, zmm28, 20
        vporq	zmm25, zmm28, zmm27
        vpsrlq	zmm26, zmm30, 24
        vporq	zmm26, zmm26, [r8+128]
        vpxorq	zmm27, zmm27, zmm27
        vpxorq	zmm28, zmm28, zmm28
        vpxorq	zmm29, zmm29, zmm29
        vpmadd52luq	zmm24, zmm16, zmm19
        vpmadd52luq	zmm24, zmm17, zmm23
        vpmadd52luq	zmm24, zmm18, zmm22
        vpmadd52huq	zmm27, zmm16, zmm19
        vpmadd52huq	zmm27, zmm17, zmm23
        vpmadd52huq	zmm27, zmm18, zmm22
        vpmadd52luq	zmm25, zmm16, zmm20
        vpmadd52luq	zmm25, zmm17, zmm19
        vpmadd52luq	zmm25, zmm18, zmm23
        vpmadd52huq	zmm28, zmm16, zmm20
        vpmadd52huq	zmm28, zmm17, zmm19
        vpmadd52huq	zmm28, zmm18, zmm23
        vpmadd52luq	zmm26, zmm16, zmm21
        vpmadd52luq	zmm26, zmm17, zmm20
        vpmadd52luq	zmm26, zmm18, zmm19
        vpmadd52huq	zmm29, zmm16, zmm21
        vpmadd52huq	zmm29, zmm17, zmm20
        vpmadd52huq	zmm29, zmm18, zmm19
        vpsllq	zmm30, zmm27, 8
        vpaddq	zmm25, zmm30, zmm25
        vpsllq	zmm30, zmm28, 8
        vpaddq	zmm26, zmm30, zmm26
        vpsllq	zmm31, zmm29, 8
        vpsllq	zmm30, zmm31, 2
        vpsllq	zmm31, zmm31, 4
        vpaddq	zmm31, zmm31, zmm30
        vpaddq	zmm24, zmm31, zmm24
        vpsrlq	zmm30, zmm24, 44
        vpandq	zmm16, zmm24, [r8]
        vpaddq	zmm25, zmm30, zmm25
        vpsrlq	zmm30, zmm25, 44
        vpandq	zmm17, zmm25, [r8]
        vpaddq	zmm26, zmm30, zmm26
        vpsrlq	zmm30, zmm26, 44
        vpandq	zmm18, zmm26, [r8]
        vpsllq	zmm31, zmm30, 2
        vpsllq	zmm30, zmm30, 4
        vpaddq	zmm30, zmm30, zmm31
        vpaddq	zmm16, zmm30, zmm16
        vmovdqu64	zmm27, [rcx+-640]
        vmovdqu64	zmm28, [rcx+-576]
        vmovdqu64	zmm29, [r8+192]
        vpermi2q	zmm29, zmm27, zmm28
        vmovdqu64	zmm30, [r8+256]
        vpermi2q	zmm30, zmm27, zmm28
        vpandq	zmm24, zmm29, [r8]
        vpsrlq	zmm27, zmm29, 44
        vpandq	zmm28, zmm30, [r8+64]
        vpsllq	zmm28, zmm28, 20
        vporq	zmm25, zmm28, zmm27
        vpsrlq	zmm26, zmm30, 24
        vporq	zmm26, zmm26, [r8+128]
        vpxorq	zmm27, zmm27, zmm27
        vpxorq	zmm28, zmm28, zmm28
        vpxorq	zmm29, zmm29, zmm29
        vpmadd52luq	zmm24, zmm16, zmm19
        vpmadd52luq	zmm24, zmm17, zmm23
        vpmadd52luq	zmm24, zmm18, zmm22
        vpmadd52huq	zmm27, zmm16, zmm19
        vpmadd52huq	zmm27, zmm17, zmm23
        vpmadd52huq	zmm27, zmm18, zmm22
        vpmadd52luq	zmm25, zmm16, zmm20
        vpmadd52luq	zmm25, zmm17, zmm19
        vpmadd52luq	zmm25, zmm18, zmm23
        vpmadd52huq	zmm28, zmm16, zmm20
        vpmadd52huq	zmm28, zmm17, zmm19
        vpmadd52huq	zmm28, zmm18, zmm23
        vpmadd52luq	zmm26, zmm16, zmm21
        vpmadd52luq	zmm26, zmm17, zmm20
        vpmadd52luq	zmm26, zmm18, zmm19
        vpmadd52huq	zmm29, zmm16, zmm21
        vpmadd52huq	zmm29, zmm17, zmm20
        vpmadd52huq	zmm29, zmm18, zmm19
        vpsllq	zmm30, zmm27, 8
        vpaddq	zmm25, zmm30, zmm25
        vpsllq	zmm30, zmm28, 8
        vpaddq	zmm26, zmm30, zmm26
        vpsllq	zmm31, zmm29, 8
        vpsllq	zmm30, zmm31, 2
        vpsllq	zmm31, zmm31, 4
        vpaddq	zmm31, zmm31, zmm30
        vpaddq	zmm24, zmm31, zmm24
        vpsrlq	zmm30, zmm24, 44
        vpandq	zmm16, zmm24, [r8]
        vpaddq	zmm25, zmm30, zmm25
        vpsrlq	zmm30, zmm25, 44
        vpandq	zmm17, zmm25, [r8]
        vpaddq	zmm26, zmm30, zmm26
        vpsrlq	zmm30, zmm26, 44
        vpandq	zmm18, zmm26, [r8]
        vpsllq	zmm31, zmm30, 2
        vpsllq	zmm30, zmm30, 4
        vpaddq	zmm30, zmm30, zmm31
        vpaddq	zmm16, zmm30, zmm16
        vmovdqu64	zmm27, [rcx+-512]
        vmovdqu64	zmm28, [rcx+-448]
        vmovdqu64	zmm29, [r8+192]
        vpermi2q	zmm29, zmm27, zmm28
        vmovdqu64	zmm30, [r8+256]
        vpermi2q	zmm30, zmm27, zmm28
        vpandq	zmm24, zmm29, [r8]
        vpsrlq	zmm27, zmm29, 44
        vpandq	zmm28, zmm30, [r8+64]
        vpsllq	zmm28, zmm28, 20
        vporq	zmm25, zmm28, zmm27
        vpsrlq	zmm26, zmm30, 24
        vporq	zmm26, zmm26, [r8+128]
        vpxorq	zmm27, zmm27, zmm27
        vpxorq	zmm28, zmm28, zmm28
        vpxorq	zmm29, zmm29, zmm29
        vpmadd52luq	zmm24, zmm16, zmm19
        vpmadd52luq	zmm24, zmm17, zmm23
        vpmadd52luq	zmm24, zmm18, zmm22
        vpmadd52huq	zmm27, zmm16, zmm19
        vpmadd52huq	zmm27, zmm17, zmm23
        vpmadd52huq	zmm27, zmm18, zmm22
        vpmadd52luq	zmm25, zmm16, zmm20
        vpmadd52luq	zmm25, zmm17, zmm19
        vpmadd52luq	zmm25, zmm18, zmm23
        vpmadd52huq	zmm28, zmm16, zmm20
        vpmadd52huq	zmm28, zmm17, zmm19
        vpmadd52huq	zmm28, zmm18, zmm23
        vpmadd52luq	zmm26, zmm16, zmm21
        vpmadd52luq	zmm26, zmm17, zmm20
        vpmadd52luq	zmm26, zmm18, zmm19
        vpmadd52huq	zmm29, zmm16, zmm21
        vpmadd52huq	zmm29, zmm17, zmm20
        vpmadd52huq	zmm29, zmm18, zmm19
        vpsllq	zmm30, zmm27, 8
        vpaddq	zmm25, zmm30, zmm25
        vpsllq	zmm30, zmm28, 8
        vpaddq	zmm26, zmm30, zmm26
        vpsllq	zmm31, zmm29, 8
        vpsllq	zmm30, zmm31, 2
        vpsllq	zmm31, zmm31, 4
        vpaddq	zmm31, zmm31, zmm30
        vpaddq	zmm24, zmm31, zmm24
        vpsrlq	zmm30, zmm24, 44
        vpandq	zmm16, zmm24, [r8]
        vpaddq	zmm25, zmm30, zmm25
        vpsrlq	zmm30, zmm25, 44
        vpandq	zmm17, zmm25, [r8]
        vpaddq	zmm26, zmm30, zmm26
        vpsrlq	zmm30, zmm26, 44
        vpandq	zmm18, zmm26, [r8]
        vpsllq	zmm31, zmm30, 2
        vpsllq	zmm30, zmm30, 4
        vpaddq	zmm30, zmm30, zmm31
        vpaddq	zmm16, zmm30, zmm16
        vmovdqu64	zmm27, [rcx+-384]
        vmovdqu64	zmm28, [rcx+-320]
        vmovdqu64	zmm29, [r8+192]
        vpermi2q	zmm29, zmm27, zmm28
        vmovdqu64	zmm30, [r8+256]
        vpermi2q	zmm30, zmm27, zmm28
        vpandq	zmm24, zmm29, [r8]
        vpsrlq	zmm27, zmm29, 44
        vpandq	zmm28, zmm30, [r8+64]
        vpsllq	zmm28, zmm28, 20
        vporq	zmm25, zmm28, zmm27
        vpsrlq	zmm26, zmm30, 24
        vporq	zmm26, zmm26, [r8+128]
        vpxorq	zmm27, zmm27, zmm27
        vpxorq	zmm28, zmm28, zmm28
        vpxorq	zmm29, zmm29, zmm29
        vpmadd52luq	zmm24, zmm16, zmm19
        vpmadd52luq	zmm24, zmm17, zmm23
        vpmadd52luq	zmm24, zmm18, zmm22
        vpmadd52huq	zmm27, zmm16, zmm19
        vpmadd52huq	zmm27, zmm17, zmm23
        vpmadd52huq	zmm27, zmm18, zmm22
        vpmadd52luq	zmm25, zmm16, zmm20
        vpmadd52luq	zmm25, zmm17, zmm19
        vpmadd52luq	zmm25, zmm18, zmm23
        vpmadd52huq	zmm28, zmm16, zmm20
        vpmadd52huq	zmm28, zmm17, zmm19
        vpmadd52huq	zmm28, zmm18, zmm23
        vpmadd52luq	zmm26, zmm16, zmm21
        vpmadd52luq	zmm26, zmm17, zmm20
        vpmadd52luq	zmm26, zmm18, zmm19
        vpmadd52huq	zmm29, zmm16, zmm21
        vpmadd52huq	zmm29, zmm17, zmm20
        vpmadd52huq	zmm29, zmm18, zmm19
        vpsllq	zmm30, zmm27, 8
        vpaddq	zmm25, zmm30, zmm25
        vpsllq	zmm30, zmm28, 8
        vpaddq	zmm26, zmm30, zmm26
        vpsllq	zmm31, zmm29, 8
        vpsllq	zmm30, zmm31, 2
        vpsllq	zmm31, zmm31, 4
        vpaddq	zmm31, zmm31, zmm30
        vpaddq	zmm24, zmm31, zmm24
        vpsrlq	zmm30, zmm24, 44
        vpandq	zmm16, zmm24, [r8]
        vpaddq	zmm25, zmm30, zmm25
        vpsrlq	zmm30, zmm25, 44
        vpandq	zmm17, zmm25, [r8]
        vpaddq	zmm26, zmm30, zmm26
        vpsrlq	zmm30, zmm26, 44
        vpandq	zmm18, zmm26, [r8]
        vpsllq	zmm31, zmm30, 2
        vpsllq	zmm30, zmm30, 4
        vpaddq	zmm30, zmm30, zmm31
        vpaddq	zmm16, zmm30, zmm16
        vmovdqu64	zmm27, [rcx+-256]
        vmovdqu64	zmm28, [rcx+-192]
        vmovdqu64	zmm29, [r8+192]
        vpermi2q	zmm29, zmm27, zmm28
        vmovdqu64	zmm30, [r8+256]
        vpermi2q	zmm30, zmm27, zmm28
        vpandq	zmm24, zmm29, [r8]
        vpsrlq	zmm27, zmm29, 44
        vpandq	zmm28, zmm30, [r8+64]
        vpsllq	zmm28, zmm28, 20
        vporq	zmm25, zmm28, zmm27
        vpsrlq	zmm26, zmm30, 24
        vporq	zmm26, zmm26, [r8+128]
        vpxorq	zmm27, zmm27, zmm27
        vpxorq	zmm28, zmm28, zmm28
        vpxorq	zmm29, zmm29, zmm29
        vpmadd52luq	zmm24, zmm16, zmm19
        vpmadd52luq	zmm24, zmm17, zmm23
        vpmadd52luq	zmm24, zmm18, zmm22
        vpmadd52huq	zmm27, zmm16, zmm19
        vpmadd52huq	zmm27, zmm17, zmm23
        vpmadd52huq	zmm27, zmm18, zmm22
        vpmadd52luq	zmm25, zmm16, zmm20
        vpmadd52luq	zmm25, zmm17, zmm19
        vpmadd52luq	zmm25, zmm18, zmm23
        vpmadd52huq	zmm28, zmm16, zmm20
        vpmadd52huq	zmm28, zmm17, zmm19
        vpmadd52huq	zmm28, zmm18, zmm23
        vpmadd52luq	zmm26, zmm16, zmm21
        vpmadd52luq	zmm26, zmm17, zmm20
        vpmadd52luq	zmm26, zmm18, zmm19
        vpmadd52huq	zmm29, zmm16, zmm21
        vpmadd52huq	zmm29, zmm17, zmm20
        vpmadd52huq	zmm29, zmm18, zmm19
        vpsllq	zmm30, zmm27, 8
        vpaddq	zmm25, zmm30, zmm25
        vpsllq	zmm30, zmm28, 8
        vpaddq	zmm26, zmm30, zmm26
        vpsllq	zmm31, zmm29, 8
        vpsllq	zmm30, zmm31, 2
        vpsllq	zmm31, zmm31, 4
        vpaddq	zmm31, zmm31, zmm30
        vpaddq	zmm24, zmm31, zmm24
        vpsrlq	zmm30, zmm24, 44
        vpandq	zmm16, zmm24, [r8]
        vpaddq	zmm25, zmm30, zmm25
        vpsrlq	zmm30, zmm25, 44
        vpandq	zmm17, zmm25, [r8]
        vpaddq	zmm26, zmm30, zmm26
        vpsrlq	zmm30, zmm26, 44
        vpandq	zmm18, zmm26, [r8]
        vpsllq	zmm31, zmm30, 2
        vpsllq	zmm30, zmm30, 4
        vpaddq	zmm30, zmm30, zmm31
        vpaddq	zmm16, zmm30, zmm16
        vmovdqu64	zmm27, [rcx+-128]
        vmovdqu64	zmm28, [rcx+-64]
        vmovdqu64	zmm29, [r8+192]
        vpermi2q	zmm29, zmm27, zmm28
        vmovdqu64	zmm30, [r8+256]
        vpermi2q	zmm30, zmm27, zmm28
        vpandq	zmm24, zmm29, [r8]
        vpsrlq	zmm27, zmm29, 44
        vpandq	zmm28, zmm30, [r8+64]
        vpsllq	zmm28, zmm28, 20
        vporq	zmm25, zmm28, zmm27
        vpsrlq	zmm26, zmm30, 24
        vporq	zmm26, zmm26, [r8+128]
        vpxorq	zmm27, zmm27, zmm27
        vpxorq	zmm28, zmm28, zmm28
        vpxorq	zmm29, zmm29, zmm29
        vpmadd52luq	zmm24, zmm16, zmm19
        vpmadd52luq	zmm24, zmm17, zmm23
        vpmadd52luq	zmm24, zmm18, zmm22
        vpmadd52huq	zmm27, zmm16, zmm19
        vpmadd52huq	zmm27, zmm17, zmm23
        vpmadd52huq	zmm27, zmm18, zmm22
        vpmadd52luq	zmm25, zmm16, zmm20
        vpmadd52luq	zmm25, zmm17, zmm19
        vpmadd52luq	zmm25, zmm18, zmm23
        vpmadd52huq	zmm28, zmm16, zmm20
        vpmadd52huq	zmm28, zmm17, zmm19
        vpmadd52huq	zmm28, zmm18, zmm23
        vpmadd52luq	zmm26, zmm16, zmm21
        vpmadd52luq	zmm26, zmm17, zmm20
        vpmadd52luq	zmm26, zmm18, zmm19
        vpmadd52huq	zmm29, zmm16, zmm21
        vpmadd52huq	zmm29, zmm17, zmm20
        vpmadd52huq	zmm29, zmm18, zmm19
        vpsllq	zmm30, zmm27, 8
        vpaddq	zmm25, zmm30, zmm25
        vpsllq	zmm30, zmm28, 8
        vpaddq	zmm26, zmm30, zmm26
        vpsllq	zmm31, zmm29, 8
        vpsllq	zmm30, zmm31, 2
        vpsllq	zmm31, zmm31, 4
        vpaddq	zmm31, zmm31, zmm30
        vpaddq	zmm24, zmm31, zmm24
        vpsrlq	zmm30, zmm24, 44
        vpandq	zmm16, zmm24, [r8]
        vpaddq	zmm25, zmm30, zmm25
        vpsrlq	zmm30, zmm25, 44
        vpandq	zmm17, zmm25, [r8]
        vpaddq	zmm26, zmm30, zmm26
        vpsrlq	zmm30, zmm26, 44
        vpandq	zmm18, zmm26, [r8]
        vpsllq	zmm31, zmm30, 2
        vpsllq	zmm30, zmm30, 4
        vpaddq	zmm30, zmm30, zmm31
        vpaddq	zmm16, zmm30, zmm16
        vmovdqu64	zmm24, [rsi+224]
        vmovdqu64	zmm25, [rsi+288]
        vmovdqu64	zmm26, [rsi+624]
        vmovdqu64	zmm27, [rsi+688]
        vmovdqu64	zmm28, [r10]
        vpermi2q	zmm28, zmm26, zmm27
        vmovdqu64	zmm29, [r10]
        vpermi2q	zmm29, zmm24, zmm25
        vinserti64x4	zmm19, zmm28, ymm29, 1
        vmovdqu64	zmm28, [r10+64]
        vpermi2q	zmm28, zmm26, zmm27
        vmovdqu64	zmm29, [r10+64]
        vpermi2q	zmm29, zmm24, zmm25
        vinserti64x4	zmm20, zmm28, ymm29, 1
        vmovdqu64	zmm28, [r10+128]
        vpermi2q	zmm28, zmm26, zmm27
        vmovdqu64	zmm29, [r10+128]
        vpermi2q	zmm29, zmm24, zmm25
        vinserti64x4	zmm21, zmm28, ymm29, 1
        vpsllq	zmm30, zmm20, 2
        vpsllq	zmm22, zmm20, 4
        vpaddq	zmm22, zmm22, zmm30
        vpsllq	zmm30, zmm21, 2
        vpsllq	zmm23, zmm21, 4
        vpaddq	zmm23, zmm23, zmm30
        vpxorq	zmm24, zmm24, zmm24
        vpxorq	zmm25, zmm25, zmm25
        vpxorq	zmm26, zmm26, zmm26
        vpxorq	zmm27, zmm27, zmm27
        vpxorq	zmm28, zmm28, zmm28
        vpxorq	zmm29, zmm29, zmm29
        vpmadd52luq	zmm24, zmm16, zmm19
        vpmadd52luq	zmm24, zmm17, zmm23
        vpmadd52luq	zmm24, zmm18, zmm22
        vpmadd52huq	zmm27, zmm16, zmm19
        vpmadd52huq	zmm27, zmm17, zmm23
        vpmadd52huq	zmm27, zmm18, zmm22
        vpmadd52luq	zmm25, zmm16, zmm20
        vpmadd52luq	zmm25, zmm17, zmm19
        vpmadd52luq	zmm25, zmm18, zmm23
        vpmadd52huq	zmm28, zmm16, zmm20
        vpmadd52huq	zmm28, zmm17, zmm19
        vpmadd52huq	zmm28, zmm18, zmm23
        vpmadd52luq	zmm26, zmm16, zmm21
        vpmadd52luq	zmm26, zmm17, zmm20
        vpmadd52luq	zmm26, zmm18, zmm19
        vpmadd52huq	zmm29, zmm16, zmm21
        vpmadd52huq	zmm29, zmm17, zmm20
        vpmadd52huq	zmm29, zmm18, zmm19
        vpsllq	zmm30, zmm27, 8
        vpaddq	zmm25, zmm30, zmm25
        vpsllq	zmm30, zmm28, 8
        vpaddq	zmm26, zmm30, zmm26
        vpsllq	zmm31, zmm29, 8
        vpsllq	zmm30, zmm31, 2
        vpsllq	zmm31, zmm31, 4
        vpaddq	zmm31, zmm31, zmm30
        vpaddq	zmm24, zmm31, zmm24
        vpsrlq	zmm30, zmm24, 44
        vpandq	zmm16, zmm24, [r8]
        vpaddq	zmm25, zmm30, zmm25
        vpsrlq	zmm30, zmm25, 44
        vpandq	zmm17, zmm25, [r8]
        vpaddq	zmm26, zmm30, zmm26
        vpsrlq	zmm30, zmm26, 44
        vpandq	zmm18, zmm26, [r8]
        vpsllq	zmm31, zmm30, 2
        vpsllq	zmm30, zmm30, 4
        vpaddq	zmm30, zmm30, zmm31
        vpaddq	zmm16, zmm30, zmm16
        vshufi64x2	zmm24, zmm16, zmm16, 78
        vshufi64x2	zmm25, zmm17, zmm17, 78
        vshufi64x2	zmm26, zmm18, zmm18, 78
        vpaddq	zmm16, zmm24, zmm16
        vpaddq	zmm17, zmm25, zmm17
        vpaddq	zmm18, zmm26, zmm18
        vpsrldq	zmm24, zmm16, 8
        vpsrldq	zmm25, zmm17, 8
        vpsrldq	zmm26, zmm18, 8
        vpaddq	zmm16, zmm24, zmm16
        vpaddq	zmm17, zmm25, zmm17
        vpaddq	zmm18, zmm26, zmm18
        vpermq	zmm24, zmm16, 2
        vpermq	zmm25, zmm17, 2
        vpermq	zmm26, zmm18, 2
        vpaddq	zmm16, zmm24, zmm16
        vpaddq	zmm17, zmm25, zmm17
        vpaddq	zmm18, zmm26, zmm18
        vmovq	r12, xmm16
        vmovq	r13, xmm17
        vmovq	r14, xmm18
        mov	r10, r13
        shr	r10, 20
        mov	r11, r14
        shr	r11, 40
        mov	r8, r12
        mov	r12, r13
        shl	r12, 44
        add	r8, r12
        adc	r10, 0
        mov	r12, r14
        shl	r12, 24
        add	r10, r12
        adc	r11, 0
        mov	r9, r11
        and	r11, 3
        shr	r9, 2
        lea	r9, QWORD PTR [r9+4*r9+0]
        add	r8, r9
        adc	r10, 0
        adc	r11, 0
        mov	r12, QWORD PTR [rsi+24]
        mov	QWORD PTR [rsi+64], r12
        mov	r12, QWORD PTR [rsi+32]
        mov	QWORD PTR [rsi+72], r12
        mov	r12, QWORD PTR [rsi+40]
        mov	QWORD PTR [rsi+80], r12
        mov	QWORD PTR [rsi+24], r8
        mov	QWORD PTR [rsi+32], r10
        mov	QWORD PTR [rsi+40], r11
        vmovd	[rdi+48], xmm12
        vzeroupper
        vmovdqu	xmm6, OWORD PTR [rsp+1200]
        vmovdqu	xmm7, OWORD PTR [rsp+1216]
        vmovdqu	xmm8, OWORD PTR [rsp+1232]
        vmovdqu	xmm9, OWORD PTR [rsp+1248]
        vmovdqu	xmm10, OWORD PTR [rsp+1264]
        vmovdqu	xmm11, OWORD PTR [rsp+1280]
        vmovdqu	xmm12, OWORD PTR [rsp+1296]
        vmovdqu	xmm13, OWORD PTR [rsp+1312]
        vmovdqu	xmm14, OWORD PTR [rsp+1328]
        vmovdqu	xmm15, OWORD PTR [rsp+1344]
        add	rsp, 1360
        pop	r14
        pop	r13
        pop	r12
        pop	rsi
        pop	rdi
        ret
chacha20_poly1305_ifma ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
chacha20_poly1305_ifma_decrypt PROC
        push	rdi
        push	rsi
        push	r12
        push	r13
        push	r14
        mov	rdi, rcx
        mov	rsi, rdx
        mov	rdx, r8
        mov	rcx, r9
        mov	rax, QWORD PTR [rsp+80]
        sub	rsp, 1360
        vmovdqu	OWORD PTR [rsp+1200], xmm6
        vmovdqu	OWORD PTR [rsp+1216], xmm7
        vmovdqu	OWORD PTR [rsp+1232], xmm8
        vmovdqu	OWORD PTR [rsp+1248], xmm9
        vmovdqu	OWORD PTR [rsp+1264], xmm10
        vmovdqu	OWORD PTR [rsp+1280], xmm11
        vmovdqu	OWORD PTR [rsp+1296], xmm12
        vmovdqu	OWORD PTR [rsp+1312], xmm13
        vmovdqu	OWORD PTR [rsp+1328], xmm14
        vmovdqu	OWORD PTR [rsp+1344], xmm15
        mov	r8, QWORD PTR [ptr_L_cp512_pc]
        mov	r10, QWORD PTR [ptr_L_cp512_rx]
        mov	r9, QWORD PTR [ptr_L_cp512_add]
        lea	r11, QWORD PTR [rsp+32]
        add	r11, 63
        and	r11, -64
        vpxorq	zmm16, zmm16, zmm16
        vpxorq	zmm17, zmm17, zmm17
        vpxorq	zmm18, zmm18, zmm18
        vmovdqu64	[rsi+752], zmm16
        vmovdqu64	[rsi+816], zmm17
        vmovdqu64	[rsi+880], zmm18
        vpbroadcastd	zmm0, DWORD PTR [rdi]
        vpbroadcastd	zmm1, DWORD PTR [rdi+4]
        vpbroadcastd	zmm2, DWORD PTR [rdi+8]
        vpbroadcastd	zmm3, DWORD PTR [rdi+12]
        vpbroadcastd	zmm4, DWORD PTR [rdi+16]
        vpbroadcastd	zmm5, DWORD PTR [rdi+20]
        vpbroadcastd	zmm6, DWORD PTR [rdi+24]
        vpbroadcastd	zmm7, DWORD PTR [rdi+28]
        vpbroadcastd	zmm8, DWORD PTR [rdi+32]
        vpbroadcastd	zmm9, DWORD PTR [rdi+36]
        vpbroadcastd	zmm10, DWORD PTR [rdi+40]
        vpbroadcastd	zmm11, DWORD PTR [rdi+44]
        vpbroadcastd	zmm12, DWORD PTR [rdi+48]
        vpbroadcastd	zmm13, DWORD PTR [rdi+52]
        vpbroadcastd	zmm14, DWORD PTR [rdi+56]
        vpbroadcastd	zmm15, DWORD PTR [rdi+60]
        vpaddd	zmm12, zmm12, [r9]
        vmovdqa64	[r11], zmm0
        vmovdqa64	[r11+64], zmm1
        vmovdqa64	[r11+128], zmm2
        vmovdqa64	[r11+192], zmm3
        vmovdqa64	[r11+256], zmm4
        vmovdqa64	[r11+320], zmm5
        vmovdqa64	[r11+384], zmm6
        vmovdqa64	[r11+448], zmm7
        vmovdqa64	[r11+512], zmm8
        vmovdqa64	[r11+576], zmm9
        vmovdqa64	[r11+640], zmm10
        vmovdqa64	[r11+704], zmm11
        vmovdqa64	[r11+768], zmm12
        vmovdqa64	[r11+832], zmm13
        vmovdqa64	[r11+896], zmm14
        vmovdqa64	[r11+960], zmm15
L_cp512_dstart:
        vmovdqu64	zmm16, [rsi+752]
        vmovdqu64	zmm17, [rsi+816]
        vmovdqu64	zmm18, [rsi+880]
        vpbroadcastq	zmm19, QWORD PTR [rsi+720]
        vpbroadcastq	zmm20, QWORD PTR [rsi+728]
        vpbroadcastq	zmm21, QWORD PTR [rsi+736]
        vpsllq	zmm30, zmm20, 2
        vpsllq	zmm22, zmm20, 4
        vpaddq	zmm22, zmm22, zmm30
        vpsllq	zmm30, zmm21, 2
        vpsllq	zmm23, zmm21, 4
        vpaddq	zmm23, zmm23, zmm30
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vprold	zmm15, zmm15, 16
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 12
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vprold	zmm15, zmm15, 8
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 7
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 16
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vprold	zmm4, zmm4, 12
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 8
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vprold	zmm4, zmm4, 7
        vmovdqu64	zmm27, [rdx]
        vmovdqu64	zmm28, [rdx+64]
        vmovdqu64	zmm29, [r8+192]
        vpermi2q	zmm29, zmm27, zmm28
        vmovdqu64	zmm30, [r8+256]
        vpermi2q	zmm30, zmm27, zmm28
        vpandq	zmm24, zmm29, [r8]
        vpsrlq	zmm27, zmm29, 44
        vpandq	zmm28, zmm30, [r8+64]
        vpsllq	zmm28, zmm28, 20
        vporq	zmm25, zmm28, zmm27
        vpsrlq	zmm26, zmm30, 24
        vporq	zmm26, zmm26, [r8+128]
        vpxorq	zmm27, zmm27, zmm27
        vpxorq	zmm28, zmm28, zmm28
        vpxorq	zmm29, zmm29, zmm29
        vpmadd52luq	zmm24, zmm16, zmm19
        vpmadd52luq	zmm24, zmm17, zmm23
        vpmadd52luq	zmm24, zmm18, zmm22
        vpmadd52huq	zmm27, zmm16, zmm19
        vpmadd52huq	zmm27, zmm17, zmm23
        vpmadd52huq	zmm27, zmm18, zmm22
        vpmadd52luq	zmm25, zmm16, zmm20
        vpmadd52luq	zmm25, zmm17, zmm19
        vpmadd52luq	zmm25, zmm18, zmm23
        vpmadd52huq	zmm28, zmm16, zmm20
        vpmadd52huq	zmm28, zmm17, zmm19
        vpmadd52huq	zmm28, zmm18, zmm23
        vpmadd52luq	zmm26, zmm16, zmm21
        vpmadd52luq	zmm26, zmm17, zmm20
        vpmadd52luq	zmm26, zmm18, zmm19
        vpmadd52huq	zmm29, zmm16, zmm21
        vpmadd52huq	zmm29, zmm17, zmm20
        vpmadd52huq	zmm29, zmm18, zmm19
        vpsllq	zmm30, zmm27, 8
        vpaddq	zmm25, zmm30, zmm25
        vpsllq	zmm30, zmm28, 8
        vpaddq	zmm26, zmm30, zmm26
        vpsllq	zmm31, zmm29, 8
        vpsllq	zmm30, zmm31, 2
        vpsllq	zmm31, zmm31, 4
        vpaddq	zmm31, zmm31, zmm30
        vpaddq	zmm24, zmm31, zmm24
        vpsrlq	zmm30, zmm24, 44
        vpandq	zmm16, zmm24, [r8]
        vpaddq	zmm25, zmm30, zmm25
        vpsrlq	zmm30, zmm25, 44
        vpandq	zmm17, zmm25, [r8]
        vpaddq	zmm26, zmm30, zmm26
        vpsrlq	zmm30, zmm26, 44
        vpandq	zmm18, zmm26, [r8]
        vpsllq	zmm31, zmm30, 2
        vpsllq	zmm30, zmm30, 4
        vpaddq	zmm30, zmm30, zmm31
        vpaddq	zmm16, zmm30, zmm16
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vprold	zmm15, zmm15, 16
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 12
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vprold	zmm15, zmm15, 8
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 7
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 16
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vprold	zmm4, zmm4, 12
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 8
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vprold	zmm4, zmm4, 7
        vmovdqu64	zmm27, [rdx+128]
        vmovdqu64	zmm28, [rdx+192]
        vmovdqu64	zmm29, [r8+192]
        vpermi2q	zmm29, zmm27, zmm28
        vmovdqu64	zmm30, [r8+256]
        vpermi2q	zmm30, zmm27, zmm28
        vpandq	zmm24, zmm29, [r8]
        vpsrlq	zmm27, zmm29, 44
        vpandq	zmm28, zmm30, [r8+64]
        vpsllq	zmm28, zmm28, 20
        vporq	zmm25, zmm28, zmm27
        vpsrlq	zmm26, zmm30, 24
        vporq	zmm26, zmm26, [r8+128]
        vpxorq	zmm27, zmm27, zmm27
        vpxorq	zmm28, zmm28, zmm28
        vpxorq	zmm29, zmm29, zmm29
        vpmadd52luq	zmm24, zmm16, zmm19
        vpmadd52luq	zmm24, zmm17, zmm23
        vpmadd52luq	zmm24, zmm18, zmm22
        vpmadd52huq	zmm27, zmm16, zmm19
        vpmadd52huq	zmm27, zmm17, zmm23
        vpmadd52huq	zmm27, zmm18, zmm22
        vpmadd52luq	zmm25, zmm16, zmm20
        vpmadd52luq	zmm25, zmm17, zmm19
        vpmadd52luq	zmm25, zmm18, zmm23
        vpmadd52huq	zmm28, zmm16, zmm20
        vpmadd52huq	zmm28, zmm17, zmm19
        vpmadd52huq	zmm28, zmm18, zmm23
        vpmadd52luq	zmm26, zmm16, zmm21
        vpmadd52luq	zmm26, zmm17, zmm20
        vpmadd52luq	zmm26, zmm18, zmm19
        vpmadd52huq	zmm29, zmm16, zmm21
        vpmadd52huq	zmm29, zmm17, zmm20
        vpmadd52huq	zmm29, zmm18, zmm19
        vpsllq	zmm30, zmm27, 8
        vpaddq	zmm25, zmm30, zmm25
        vpsllq	zmm30, zmm28, 8
        vpaddq	zmm26, zmm30, zmm26
        vpsllq	zmm31, zmm29, 8
        vpsllq	zmm30, zmm31, 2
        vpsllq	zmm31, zmm31, 4
        vpaddq	zmm31, zmm31, zmm30
        vpaddq	zmm24, zmm31, zmm24
        vpsrlq	zmm30, zmm24, 44
        vpandq	zmm16, zmm24, [r8]
        vpaddq	zmm25, zmm30, zmm25
        vpsrlq	zmm30, zmm25, 44
        vpandq	zmm17, zmm25, [r8]
        vpaddq	zmm26, zmm30, zmm26
        vpsrlq	zmm30, zmm26, 44
        vpandq	zmm18, zmm26, [r8]
        vpsllq	zmm31, zmm30, 2
        vpsllq	zmm30, zmm30, 4
        vpaddq	zmm30, zmm30, zmm31
        vpaddq	zmm16, zmm30, zmm16
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vprold	zmm15, zmm15, 16
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 12
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vprold	zmm15, zmm15, 8
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 7
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 16
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vprold	zmm4, zmm4, 12
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 8
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vprold	zmm4, zmm4, 7
        vmovdqu64	zmm27, [rdx+256]
        vmovdqu64	zmm28, [rdx+320]
        vmovdqu64	zmm29, [r8+192]
        vpermi2q	zmm29, zmm27, zmm28
        vmovdqu64	zmm30, [r8+256]
        vpermi2q	zmm30, zmm27, zmm28
        vpandq	zmm24, zmm29, [r8]
        vpsrlq	zmm27, zmm29, 44
        vpandq	zmm28, zmm30, [r8+64]
        vpsllq	zmm28, zmm28, 20
        vporq	zmm25, zmm28, zmm27
        vpsrlq	zmm26, zmm30, 24
        vporq	zmm26, zmm26, [r8+128]
        vpxorq	zmm27, zmm27, zmm27
        vpxorq	zmm28, zmm28, zmm28
        vpxorq	zmm29, zmm29, zmm29
        vpmadd52luq	zmm24, zmm16, zmm19
        vpmadd52luq	zmm24, zmm17, zmm23
        vpmadd52luq	zmm24, zmm18, zmm22
        vpmadd52huq	zmm27, zmm16, zmm19
        vpmadd52huq	zmm27, zmm17, zmm23
        vpmadd52huq	zmm27, zmm18, zmm22
        vpmadd52luq	zmm25, zmm16, zmm20
        vpmadd52luq	zmm25, zmm17, zmm19
        vpmadd52luq	zmm25, zmm18, zmm23
        vpmadd52huq	zmm28, zmm16, zmm20
        vpmadd52huq	zmm28, zmm17, zmm19
        vpmadd52huq	zmm28, zmm18, zmm23
        vpmadd52luq	zmm26, zmm16, zmm21
        vpmadd52luq	zmm26, zmm17, zmm20
        vpmadd52luq	zmm26, zmm18, zmm19
        vpmadd52huq	zmm29, zmm16, zmm21
        vpmadd52huq	zmm29, zmm17, zmm20
        vpmadd52huq	zmm29, zmm18, zmm19
        vpsllq	zmm30, zmm27, 8
        vpaddq	zmm25, zmm30, zmm25
        vpsllq	zmm30, zmm28, 8
        vpaddq	zmm26, zmm30, zmm26
        vpsllq	zmm31, zmm29, 8
        vpsllq	zmm30, zmm31, 2
        vpsllq	zmm31, zmm31, 4
        vpaddq	zmm31, zmm31, zmm30
        vpaddq	zmm24, zmm31, zmm24
        vpsrlq	zmm30, zmm24, 44
        vpandq	zmm16, zmm24, [r8]
        vpaddq	zmm25, zmm30, zmm25
        vpsrlq	zmm30, zmm25, 44
        vpandq	zmm17, zmm25, [r8]
        vpaddq	zmm26, zmm30, zmm26
        vpsrlq	zmm30, zmm26, 44
        vpandq	zmm18, zmm26, [r8]
        vpsllq	zmm31, zmm30, 2
        vpsllq	zmm30, zmm30, 4
        vpaddq	zmm30, zmm30, zmm31
        vpaddq	zmm16, zmm30, zmm16
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vprold	zmm15, zmm15, 16
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 12
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vprold	zmm15, zmm15, 8
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 7
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 16
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vprold	zmm4, zmm4, 12
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 8
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vprold	zmm4, zmm4, 7
        vmovdqu64	zmm27, [rdx+384]
        vmovdqu64	zmm28, [rdx+448]
        vmovdqu64	zmm29, [r8+192]
        vpermi2q	zmm29, zmm27, zmm28
        vmovdqu64	zmm30, [r8+256]
        vpermi2q	zmm30, zmm27, zmm28
        vpandq	zmm24, zmm29, [r8]
        vpsrlq	zmm27, zmm29, 44
        vpandq	zmm28, zmm30, [r8+64]
        vpsllq	zmm28, zmm28, 20
        vporq	zmm25, zmm28, zmm27
        vpsrlq	zmm26, zmm30, 24
        vporq	zmm26, zmm26, [r8+128]
        vpxorq	zmm27, zmm27, zmm27
        vpxorq	zmm28, zmm28, zmm28
        vpxorq	zmm29, zmm29, zmm29
        vpmadd52luq	zmm24, zmm16, zmm19
        vpmadd52luq	zmm24, zmm17, zmm23
        vpmadd52luq	zmm24, zmm18, zmm22
        vpmadd52huq	zmm27, zmm16, zmm19
        vpmadd52huq	zmm27, zmm17, zmm23
        vpmadd52huq	zmm27, zmm18, zmm22
        vpmadd52luq	zmm25, zmm16, zmm20
        vpmadd52luq	zmm25, zmm17, zmm19
        vpmadd52luq	zmm25, zmm18, zmm23
        vpmadd52huq	zmm28, zmm16, zmm20
        vpmadd52huq	zmm28, zmm17, zmm19
        vpmadd52huq	zmm28, zmm18, zmm23
        vpmadd52luq	zmm26, zmm16, zmm21
        vpmadd52luq	zmm26, zmm17, zmm20
        vpmadd52luq	zmm26, zmm18, zmm19
        vpmadd52huq	zmm29, zmm16, zmm21
        vpmadd52huq	zmm29, zmm17, zmm20
        vpmadd52huq	zmm29, zmm18, zmm19
        vpsllq	zmm30, zmm27, 8
        vpaddq	zmm25, zmm30, zmm25
        vpsllq	zmm30, zmm28, 8
        vpaddq	zmm26, zmm30, zmm26
        vpsllq	zmm31, zmm29, 8
        vpsllq	zmm30, zmm31, 2
        vpsllq	zmm31, zmm31, 4
        vpaddq	zmm31, zmm31, zmm30
        vpaddq	zmm24, zmm31, zmm24
        vpsrlq	zmm30, zmm24, 44
        vpandq	zmm16, zmm24, [r8]
        vpaddq	zmm25, zmm30, zmm25
        vpsrlq	zmm30, zmm25, 44
        vpandq	zmm17, zmm25, [r8]
        vpaddq	zmm26, zmm30, zmm26
        vpsrlq	zmm30, zmm26, 44
        vpandq	zmm18, zmm26, [r8]
        vpsllq	zmm31, zmm30, 2
        vpsllq	zmm30, zmm30, 4
        vpaddq	zmm30, zmm30, zmm31
        vpaddq	zmm16, zmm30, zmm16
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vprold	zmm15, zmm15, 16
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 12
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vprold	zmm15, zmm15, 8
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 7
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 16
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vprold	zmm4, zmm4, 12
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 8
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vprold	zmm4, zmm4, 7
        vmovdqu64	zmm27, [rdx+512]
        vmovdqu64	zmm28, [rdx+576]
        vmovdqu64	zmm29, [r8+192]
        vpermi2q	zmm29, zmm27, zmm28
        vmovdqu64	zmm30, [r8+256]
        vpermi2q	zmm30, zmm27, zmm28
        vpandq	zmm24, zmm29, [r8]
        vpsrlq	zmm27, zmm29, 44
        vpandq	zmm28, zmm30, [r8+64]
        vpsllq	zmm28, zmm28, 20
        vporq	zmm25, zmm28, zmm27
        vpsrlq	zmm26, zmm30, 24
        vporq	zmm26, zmm26, [r8+128]
        vpxorq	zmm27, zmm27, zmm27
        vpxorq	zmm28, zmm28, zmm28
        vpxorq	zmm29, zmm29, zmm29
        vpmadd52luq	zmm24, zmm16, zmm19
        vpmadd52luq	zmm24, zmm17, zmm23
        vpmadd52luq	zmm24, zmm18, zmm22
        vpmadd52huq	zmm27, zmm16, zmm19
        vpmadd52huq	zmm27, zmm17, zmm23
        vpmadd52huq	zmm27, zmm18, zmm22
        vpmadd52luq	zmm25, zmm16, zmm20
        vpmadd52luq	zmm25, zmm17, zmm19
        vpmadd52luq	zmm25, zmm18, zmm23
        vpmadd52huq	zmm28, zmm16, zmm20
        vpmadd52huq	zmm28, zmm17, zmm19
        vpmadd52huq	zmm28, zmm18, zmm23
        vpmadd52luq	zmm26, zmm16, zmm21
        vpmadd52luq	zmm26, zmm17, zmm20
        vpmadd52luq	zmm26, zmm18, zmm19
        vpmadd52huq	zmm29, zmm16, zmm21
        vpmadd52huq	zmm29, zmm17, zmm20
        vpmadd52huq	zmm29, zmm18, zmm19
        vpsllq	zmm30, zmm27, 8
        vpaddq	zmm25, zmm30, zmm25
        vpsllq	zmm30, zmm28, 8
        vpaddq	zmm26, zmm30, zmm26
        vpsllq	zmm31, zmm29, 8
        vpsllq	zmm30, zmm31, 2
        vpsllq	zmm31, zmm31, 4
        vpaddq	zmm31, zmm31, zmm30
        vpaddq	zmm24, zmm31, zmm24
        vpsrlq	zmm30, zmm24, 44
        vpandq	zmm16, zmm24, [r8]
        vpaddq	zmm25, zmm30, zmm25
        vpsrlq	zmm30, zmm25, 44
        vpandq	zmm17, zmm25, [r8]
        vpaddq	zmm26, zmm30, zmm26
        vpsrlq	zmm30, zmm26, 44
        vpandq	zmm18, zmm26, [r8]
        vpsllq	zmm31, zmm30, 2
        vpsllq	zmm30, zmm30, 4
        vpaddq	zmm30, zmm30, zmm31
        vpaddq	zmm16, zmm30, zmm16
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vprold	zmm15, zmm15, 16
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 12
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vprold	zmm15, zmm15, 8
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 7
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 16
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vprold	zmm4, zmm4, 12
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 8
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vprold	zmm4, zmm4, 7
        vmovdqu64	zmm27, [rdx+640]
        vmovdqu64	zmm28, [rdx+704]
        vmovdqu64	zmm29, [r8+192]
        vpermi2q	zmm29, zmm27, zmm28
        vmovdqu64	zmm30, [r8+256]
        vpermi2q	zmm30, zmm27, zmm28
        vpandq	zmm24, zmm29, [r8]
        vpsrlq	zmm27, zmm29, 44
        vpandq	zmm28, zmm30, [r8+64]
        vpsllq	zmm28, zmm28, 20
        vporq	zmm25, zmm28, zmm27
        vpsrlq	zmm26, zmm30, 24
        vporq	zmm26, zmm26, [r8+128]
        vpxorq	zmm27, zmm27, zmm27
        vpxorq	zmm28, zmm28, zmm28
        vpxorq	zmm29, zmm29, zmm29
        vpmadd52luq	zmm24, zmm16, zmm19
        vpmadd52luq	zmm24, zmm17, zmm23
        vpmadd52luq	zmm24, zmm18, zmm22
        vpmadd52huq	zmm27, zmm16, zmm19
        vpmadd52huq	zmm27, zmm17, zmm23
        vpmadd52huq	zmm27, zmm18, zmm22
        vpmadd52luq	zmm25, zmm16, zmm20
        vpmadd52luq	zmm25, zmm17, zmm19
        vpmadd52luq	zmm25, zmm18, zmm23
        vpmadd52huq	zmm28, zmm16, zmm20
        vpmadd52huq	zmm28, zmm17, zmm19
        vpmadd52huq	zmm28, zmm18, zmm23
        vpmadd52luq	zmm26, zmm16, zmm21
        vpmadd52luq	zmm26, zmm17, zmm20
        vpmadd52luq	zmm26, zmm18, zmm19
        vpmadd52huq	zmm29, zmm16, zmm21
        vpmadd52huq	zmm29, zmm17, zmm20
        vpmadd52huq	zmm29, zmm18, zmm19
        vpsllq	zmm30, zmm27, 8
        vpaddq	zmm25, zmm30, zmm25
        vpsllq	zmm30, zmm28, 8
        vpaddq	zmm26, zmm30, zmm26
        vpsllq	zmm31, zmm29, 8
        vpsllq	zmm30, zmm31, 2
        vpsllq	zmm31, zmm31, 4
        vpaddq	zmm31, zmm31, zmm30
        vpaddq	zmm24, zmm31, zmm24
        vpsrlq	zmm30, zmm24, 44
        vpandq	zmm16, zmm24, [r8]
        vpaddq	zmm25, zmm30, zmm25
        vpsrlq	zmm30, zmm25, 44
        vpandq	zmm17, zmm25, [r8]
        vpaddq	zmm26, zmm30, zmm26
        vpsrlq	zmm30, zmm26, 44
        vpandq	zmm18, zmm26, [r8]
        vpsllq	zmm31, zmm30, 2
        vpsllq	zmm30, zmm30, 4
        vpaddq	zmm30, zmm30, zmm31
        vpaddq	zmm16, zmm30, zmm16
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vprold	zmm15, zmm15, 16
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 12
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vprold	zmm15, zmm15, 8
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 7
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 16
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vprold	zmm4, zmm4, 12
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 8
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vprold	zmm4, zmm4, 7
        vmovdqu64	zmm27, [rdx+768]
        vmovdqu64	zmm28, [rdx+832]
        vmovdqu64	zmm29, [r8+192]
        vpermi2q	zmm29, zmm27, zmm28
        vmovdqu64	zmm30, [r8+256]
        vpermi2q	zmm30, zmm27, zmm28
        vpandq	zmm24, zmm29, [r8]
        vpsrlq	zmm27, zmm29, 44
        vpandq	zmm28, zmm30, [r8+64]
        vpsllq	zmm28, zmm28, 20
        vporq	zmm25, zmm28, zmm27
        vpsrlq	zmm26, zmm30, 24
        vporq	zmm26, zmm26, [r8+128]
        vpxorq	zmm27, zmm27, zmm27
        vpxorq	zmm28, zmm28, zmm28
        vpxorq	zmm29, zmm29, zmm29
        vpmadd52luq	zmm24, zmm16, zmm19
        vpmadd52luq	zmm24, zmm17, zmm23
        vpmadd52luq	zmm24, zmm18, zmm22
        vpmadd52huq	zmm27, zmm16, zmm19
        vpmadd52huq	zmm27, zmm17, zmm23
        vpmadd52huq	zmm27, zmm18, zmm22
        vpmadd52luq	zmm25, zmm16, zmm20
        vpmadd52luq	zmm25, zmm17, zmm19
        vpmadd52luq	zmm25, zmm18, zmm23
        vpmadd52huq	zmm28, zmm16, zmm20
        vpmadd52huq	zmm28, zmm17, zmm19
        vpmadd52huq	zmm28, zmm18, zmm23
        vpmadd52luq	zmm26, zmm16, zmm21
        vpmadd52luq	zmm26, zmm17, zmm20
        vpmadd52luq	zmm26, zmm18, zmm19
        vpmadd52huq	zmm29, zmm16, zmm21
        vpmadd52huq	zmm29, zmm17, zmm20
        vpmadd52huq	zmm29, zmm18, zmm19
        vpsllq	zmm30, zmm27, 8
        vpaddq	zmm25, zmm30, zmm25
        vpsllq	zmm30, zmm28, 8
        vpaddq	zmm26, zmm30, zmm26
        vpsllq	zmm31, zmm29, 8
        vpsllq	zmm30, zmm31, 2
        vpsllq	zmm31, zmm31, 4
        vpaddq	zmm31, zmm31, zmm30
        vpaddq	zmm24, zmm31, zmm24
        vpsrlq	zmm30, zmm24, 44
        vpandq	zmm16, zmm24, [r8]
        vpaddq	zmm25, zmm30, zmm25
        vpsrlq	zmm30, zmm25, 44
        vpandq	zmm17, zmm25, [r8]
        vpaddq	zmm26, zmm30, zmm26
        vpsrlq	zmm30, zmm26, 44
        vpandq	zmm18, zmm26, [r8]
        vpsllq	zmm31, zmm30, 2
        vpsllq	zmm30, zmm30, 4
        vpaddq	zmm30, zmm30, zmm31
        vpaddq	zmm16, zmm30, zmm16
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vprold	zmm15, zmm15, 16
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 12
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vprold	zmm15, zmm15, 8
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 7
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 16
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vprold	zmm4, zmm4, 12
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 8
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vprold	zmm4, zmm4, 7
        vmovdqu64	zmm27, [rdx+896]
        vmovdqu64	zmm28, [rdx+960]
        vmovdqu64	zmm29, [r8+192]
        vpermi2q	zmm29, zmm27, zmm28
        vmovdqu64	zmm30, [r8+256]
        vpermi2q	zmm30, zmm27, zmm28
        vpandq	zmm24, zmm29, [r8]
        vpsrlq	zmm27, zmm29, 44
        vpandq	zmm28, zmm30, [r8+64]
        vpsllq	zmm28, zmm28, 20
        vporq	zmm25, zmm28, zmm27
        vpsrlq	zmm26, zmm30, 24
        vporq	zmm26, zmm26, [r8+128]
        vpxorq	zmm27, zmm27, zmm27
        vpxorq	zmm28, zmm28, zmm28
        vpxorq	zmm29, zmm29, zmm29
        vpmadd52luq	zmm24, zmm16, zmm19
        vpmadd52luq	zmm24, zmm17, zmm23
        vpmadd52luq	zmm24, zmm18, zmm22
        vpmadd52huq	zmm27, zmm16, zmm19
        vpmadd52huq	zmm27, zmm17, zmm23
        vpmadd52huq	zmm27, zmm18, zmm22
        vpmadd52luq	zmm25, zmm16, zmm20
        vpmadd52luq	zmm25, zmm17, zmm19
        vpmadd52luq	zmm25, zmm18, zmm23
        vpmadd52huq	zmm28, zmm16, zmm20
        vpmadd52huq	zmm28, zmm17, zmm19
        vpmadd52huq	zmm28, zmm18, zmm23
        vpmadd52luq	zmm26, zmm16, zmm21
        vpmadd52luq	zmm26, zmm17, zmm20
        vpmadd52luq	zmm26, zmm18, zmm19
        vpmadd52huq	zmm29, zmm16, zmm21
        vpmadd52huq	zmm29, zmm17, zmm20
        vpmadd52huq	zmm29, zmm18, zmm19
        vpsllq	zmm30, zmm27, 8
        vpaddq	zmm25, zmm30, zmm25
        vpsllq	zmm30, zmm28, 8
        vpaddq	zmm26, zmm30, zmm26
        vpsllq	zmm31, zmm29, 8
        vpsllq	zmm30, zmm31, 2
        vpsllq	zmm31, zmm31, 4
        vpaddq	zmm31, zmm31, zmm30
        vpaddq	zmm24, zmm31, zmm24
        vpsrlq	zmm30, zmm24, 44
        vpandq	zmm16, zmm24, [r8]
        vpaddq	zmm25, zmm30, zmm25
        vpsrlq	zmm30, zmm25, 44
        vpandq	zmm17, zmm25, [r8]
        vpaddq	zmm26, zmm30, zmm26
        vpsrlq	zmm30, zmm26, 44
        vpandq	zmm18, zmm26, [r8]
        vpsllq	zmm31, zmm30, 2
        vpsllq	zmm30, zmm30, 4
        vpaddq	zmm30, zmm30, zmm31
        vpaddq	zmm16, zmm30, zmm16
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vprold	zmm15, zmm15, 16
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 12
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vprold	zmm15, zmm15, 8
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 7
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 16
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vprold	zmm4, zmm4, 12
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 8
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vprold	zmm4, zmm4, 7
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vprold	zmm15, zmm15, 16
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 12
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vpaddd	zmm0, zmm0, zmm4
        vpaddd	zmm1, zmm1, zmm5
        vpaddd	zmm2, zmm2, zmm6
        vpaddd	zmm3, zmm3, zmm7
        vpxord	zmm12, zmm12, zmm0
        vpxord	zmm13, zmm13, zmm1
        vpxord	zmm14, zmm14, zmm2
        vpxord	zmm15, zmm15, zmm3
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vprold	zmm15, zmm15, 8
        vpaddd	zmm8, zmm8, zmm12
        vpaddd	zmm9, zmm9, zmm13
        vpaddd	zmm10, zmm10, zmm14
        vpaddd	zmm11, zmm11, zmm15
        vpxord	zmm4, zmm4, zmm8
        vpxord	zmm5, zmm5, zmm9
        vpxord	zmm6, zmm6, zmm10
        vpxord	zmm7, zmm7, zmm11
        vprold	zmm4, zmm4, 7
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 16
        vprold	zmm12, zmm12, 16
        vprold	zmm13, zmm13, 16
        vprold	zmm14, zmm14, 16
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 12
        vprold	zmm6, zmm6, 12
        vprold	zmm7, zmm7, 12
        vprold	zmm4, zmm4, 12
        vpaddd	zmm0, zmm0, zmm5
        vpaddd	zmm1, zmm1, zmm6
        vpaddd	zmm2, zmm2, zmm7
        vpaddd	zmm3, zmm3, zmm4
        vpxord	zmm15, zmm15, zmm0
        vpxord	zmm12, zmm12, zmm1
        vpxord	zmm13, zmm13, zmm2
        vpxord	zmm14, zmm14, zmm3
        vprold	zmm15, zmm15, 8
        vprold	zmm12, zmm12, 8
        vprold	zmm13, zmm13, 8
        vprold	zmm14, zmm14, 8
        vpaddd	zmm10, zmm10, zmm15
        vpaddd	zmm11, zmm11, zmm12
        vpaddd	zmm8, zmm8, zmm13
        vpaddd	zmm9, zmm9, zmm14
        vpxord	zmm5, zmm5, zmm10
        vpxord	zmm6, zmm6, zmm11
        vpxord	zmm7, zmm7, zmm8
        vpxord	zmm4, zmm4, zmm9
        vprold	zmm5, zmm5, 7
        vprold	zmm6, zmm6, 7
        vprold	zmm7, zmm7, 7
        vprold	zmm4, zmm4, 7
        vpaddd	zmm0, zmm0, [r11]
        vpaddd	zmm1, zmm1, [r11+64]
        vpaddd	zmm2, zmm2, [r11+128]
        vpaddd	zmm3, zmm3, [r11+192]
        vpaddd	zmm4, zmm4, [r11+256]
        vpaddd	zmm5, zmm5, [r11+320]
        vpaddd	zmm6, zmm6, [r11+384]
        vpaddd	zmm7, zmm7, [r11+448]
        vpaddd	zmm8, zmm8, [r11+512]
        vpaddd	zmm9, zmm9, [r11+576]
        vpaddd	zmm10, zmm10, [r11+640]
        vpaddd	zmm11, zmm11, [r11+704]
        vpaddd	zmm12, zmm12, [r11+768]
        vpaddd	zmm13, zmm13, [r11+832]
        vpaddd	zmm14, zmm14, [r11+896]
        vpaddd	zmm15, zmm15, [r11+960]
        vmovdqu64	[rsi+752], zmm16
        vmovdqu64	[rsi+816], zmm17
        vmovdqu64	[rsi+880], zmm18
        vpunpckldq	zmm16, zmm0, zmm1
        vpunpckhdq	zmm17, zmm0, zmm1
        vpunpckldq	zmm18, zmm2, zmm3
        vpunpckhdq	zmm19, zmm2, zmm3
        vpunpckldq	zmm20, zmm4, zmm5
        vpunpckhdq	zmm21, zmm4, zmm5
        vpunpckldq	zmm22, zmm6, zmm7
        vpunpckhdq	zmm23, zmm6, zmm7
        vpunpckldq	zmm24, zmm8, zmm9
        vpunpckhdq	zmm25, zmm8, zmm9
        vpunpckldq	zmm26, zmm10, zmm11
        vpunpckhdq	zmm27, zmm10, zmm11
        vpunpckldq	zmm28, zmm12, zmm13
        vpunpckhdq	zmm29, zmm12, zmm13
        vpunpckldq	zmm30, zmm14, zmm15
        vpunpckhdq	zmm31, zmm14, zmm15
        vpunpcklqdq	zmm0, zmm16, zmm18
        vpunpckhqdq	zmm1, zmm16, zmm18
        vpunpcklqdq	zmm2, zmm17, zmm19
        vpunpckhqdq	zmm3, zmm17, zmm19
        vpunpcklqdq	zmm4, zmm20, zmm22
        vpunpckhqdq	zmm5, zmm20, zmm22
        vpunpcklqdq	zmm6, zmm21, zmm23
        vpunpckhqdq	zmm7, zmm21, zmm23
        vpunpcklqdq	zmm8, zmm24, zmm26
        vpunpckhqdq	zmm9, zmm24, zmm26
        vpunpcklqdq	zmm10, zmm25, zmm27
        vpunpckhqdq	zmm11, zmm25, zmm27
        vpunpcklqdq	zmm12, zmm28, zmm30
        vpunpckhqdq	zmm13, zmm28, zmm30
        vpunpcklqdq	zmm14, zmm29, zmm31
        vpunpckhqdq	zmm15, zmm29, zmm31
        vshufi32x4	zmm16, zmm0, zmm4, 68
        vshufi32x4	zmm17, zmm0, zmm4, 238
        vshufi32x4	zmm18, zmm8, zmm12, 68
        vshufi32x4	zmm19, zmm8, zmm12, 238
        vshufi32x4	zmm20, zmm16, zmm18, 136
        vshufi32x4	zmm21, zmm16, zmm18, 221
        vshufi32x4	zmm22, zmm17, zmm19, 136
        vshufi32x4	zmm23, zmm17, zmm19, 221
        vpxord	zmm20, zmm20, [rdx]
        vmovdqu64	[rcx], zmm20
        vpxord	zmm21, zmm21, [rdx+256]
        vmovdqu64	[rcx+256], zmm21
        vpxord	zmm22, zmm22, [rdx+512]
        vmovdqu64	[rcx+512], zmm22
        vpxord	zmm23, zmm23, [rdx+768]
        vmovdqu64	[rcx+768], zmm23
        vshufi32x4	zmm16, zmm1, zmm5, 68
        vshufi32x4	zmm17, zmm1, zmm5, 238
        vshufi32x4	zmm18, zmm9, zmm13, 68
        vshufi32x4	zmm19, zmm9, zmm13, 238
        vshufi32x4	zmm20, zmm16, zmm18, 136
        vshufi32x4	zmm21, zmm16, zmm18, 221
        vshufi32x4	zmm22, zmm17, zmm19, 136
        vshufi32x4	zmm23, zmm17, zmm19, 221
        vpxord	zmm20, zmm20, [rdx+64]
        vmovdqu64	[rcx+64], zmm20
        vpxord	zmm21, zmm21, [rdx+320]
        vmovdqu64	[rcx+320], zmm21
        vpxord	zmm22, zmm22, [rdx+576]
        vmovdqu64	[rcx+576], zmm22
        vpxord	zmm23, zmm23, [rdx+832]
        vmovdqu64	[rcx+832], zmm23
        vshufi32x4	zmm16, zmm2, zmm6, 68
        vshufi32x4	zmm17, zmm2, zmm6, 238
        vshufi32x4	zmm18, zmm10, zmm14, 68
        vshufi32x4	zmm19, zmm10, zmm14, 238
        vshufi32x4	zmm20, zmm16, zmm18, 136
        vshufi32x4	zmm21, zmm16, zmm18, 221
        vshufi32x4	zmm22, zmm17, zmm19, 136
        vshufi32x4	zmm23, zmm17, zmm19, 221
        vpxord	zmm20, zmm20, [rdx+128]
        vmovdqu64	[rcx+128], zmm20
        vpxord	zmm21, zmm21, [rdx+384]
        vmovdqu64	[rcx+384], zmm21
        vpxord	zmm22, zmm22, [rdx+640]
        vmovdqu64	[rcx+640], zmm22
        vpxord	zmm23, zmm23, [rdx+896]
        vmovdqu64	[rcx+896], zmm23
        vshufi32x4	zmm16, zmm3, zmm7, 68
        vshufi32x4	zmm17, zmm3, zmm7, 238
        vshufi32x4	zmm18, zmm11, zmm15, 68
        vshufi32x4	zmm19, zmm11, zmm15, 238
        vshufi32x4	zmm20, zmm16, zmm18, 136
        vshufi32x4	zmm21, zmm16, zmm18, 221
        vshufi32x4	zmm22, zmm17, zmm19, 136
        vshufi32x4	zmm23, zmm17, zmm19, 221
        vpxord	zmm20, zmm20, [rdx+192]
        vmovdqu64	[rcx+192], zmm20
        vpxord	zmm21, zmm21, [rdx+448]
        vmovdqu64	[rcx+448], zmm21
        vpxord	zmm22, zmm22, [rdx+704]
        vmovdqu64	[rcx+704], zmm22
        vpxord	zmm23, zmm23, [rdx+960]
        vmovdqu64	[rcx+960], zmm23
        vmovdqa64	zmm12, [r11+768]
        vpaddd	zmm12, zmm12, [r8+320]
        vmovdqa64	[r11+768], zmm12
        vmovdqa64	zmm0, [r11]
        vmovdqa64	zmm1, [r11+64]
        vmovdqa64	zmm2, [r11+128]
        vmovdqa64	zmm3, [r11+192]
        vmovdqa64	zmm4, [r11+256]
        vmovdqa64	zmm5, [r11+320]
        vmovdqa64	zmm6, [r11+384]
        vmovdqa64	zmm7, [r11+448]
        vmovdqa64	zmm8, [r11+512]
        vmovdqa64	zmm9, [r11+576]
        vmovdqa64	zmm10, [r11+640]
        vmovdqa64	zmm11, [r11+704]
        vmovdqa64	zmm12, [r11+768]
        vmovdqa64	zmm13, [r11+832]
        vmovdqa64	zmm14, [r11+896]
        vmovdqa64	zmm15, [r11+960]
        add	rdx, 1024
        add	rcx, 1024
        sub	eax, 1024
        jnz	L_cp512_dstart
        vmovdqu64	zmm16, [rsi+752]
        vmovdqu64	zmm17, [rsi+816]
        vmovdqu64	zmm18, [rsi+880]
        vmovdqu64	zmm24, [rsi+224]
        vmovdqu64	zmm25, [rsi+288]
        vmovdqu64	zmm26, [rsi+624]
        vmovdqu64	zmm27, [rsi+688]
        vmovdqu64	zmm28, [r10]
        vpermi2q	zmm28, zmm26, zmm27
        vmovdqu64	zmm29, [r10]
        vpermi2q	zmm29, zmm24, zmm25
        vinserti64x4	zmm19, zmm28, ymm29, 1
        vmovdqu64	zmm28, [r10+64]
        vpermi2q	zmm28, zmm26, zmm27
        vmovdqu64	zmm29, [r10+64]
        vpermi2q	zmm29, zmm24, zmm25
        vinserti64x4	zmm20, zmm28, ymm29, 1
        vmovdqu64	zmm28, [r10+128]
        vpermi2q	zmm28, zmm26, zmm27
        vmovdqu64	zmm29, [r10+128]
        vpermi2q	zmm29, zmm24, zmm25
        vinserti64x4	zmm21, zmm28, ymm29, 1
        vpsllq	zmm30, zmm20, 2
        vpsllq	zmm22, zmm20, 4
        vpaddq	zmm22, zmm22, zmm30
        vpsllq	zmm30, zmm21, 2
        vpsllq	zmm23, zmm21, 4
        vpaddq	zmm23, zmm23, zmm30
        vpxorq	zmm24, zmm24, zmm24
        vpxorq	zmm25, zmm25, zmm25
        vpxorq	zmm26, zmm26, zmm26
        vpxorq	zmm27, zmm27, zmm27
        vpxorq	zmm28, zmm28, zmm28
        vpxorq	zmm29, zmm29, zmm29
        vpmadd52luq	zmm24, zmm16, zmm19
        vpmadd52luq	zmm24, zmm17, zmm23
        vpmadd52luq	zmm24, zmm18, zmm22
        vpmadd52huq	zmm27, zmm16, zmm19
        vpmadd52huq	zmm27, zmm17, zmm23
        vpmadd52huq	zmm27, zmm18, zmm22
        vpmadd52luq	zmm25, zmm16, zmm20
        vpmadd52luq	zmm25, zmm17, zmm19
        vpmadd52luq	zmm25, zmm18, zmm23
        vpmadd52huq	zmm28, zmm16, zmm20
        vpmadd52huq	zmm28, zmm17, zmm19
        vpmadd52huq	zmm28, zmm18, zmm23
        vpmadd52luq	zmm26, zmm16, zmm21
        vpmadd52luq	zmm26, zmm17, zmm20
        vpmadd52luq	zmm26, zmm18, zmm19
        vpmadd52huq	zmm29, zmm16, zmm21
        vpmadd52huq	zmm29, zmm17, zmm20
        vpmadd52huq	zmm29, zmm18, zmm19
        vpsllq	zmm30, zmm27, 8
        vpaddq	zmm25, zmm30, zmm25
        vpsllq	zmm30, zmm28, 8
        vpaddq	zmm26, zmm30, zmm26
        vpsllq	zmm31, zmm29, 8
        vpsllq	zmm30, zmm31, 2
        vpsllq	zmm31, zmm31, 4
        vpaddq	zmm31, zmm31, zmm30
        vpaddq	zmm24, zmm31, zmm24
        vpsrlq	zmm30, zmm24, 44
        vpandq	zmm16, zmm24, [r8]
        vpaddq	zmm25, zmm30, zmm25
        vpsrlq	zmm30, zmm25, 44
        vpandq	zmm17, zmm25, [r8]
        vpaddq	zmm26, zmm30, zmm26
        vpsrlq	zmm30, zmm26, 44
        vpandq	zmm18, zmm26, [r8]
        vpsllq	zmm31, zmm30, 2
        vpsllq	zmm30, zmm30, 4
        vpaddq	zmm30, zmm30, zmm31
        vpaddq	zmm16, zmm30, zmm16
        vshufi64x2	zmm24, zmm16, zmm16, 78
        vshufi64x2	zmm25, zmm17, zmm17, 78
        vshufi64x2	zmm26, zmm18, zmm18, 78
        vpaddq	zmm16, zmm24, zmm16
        vpaddq	zmm17, zmm25, zmm17
        vpaddq	zmm18, zmm26, zmm18
        vpsrldq	zmm24, zmm16, 8
        vpsrldq	zmm25, zmm17, 8
        vpsrldq	zmm26, zmm18, 8
        vpaddq	zmm16, zmm24, zmm16
        vpaddq	zmm17, zmm25, zmm17
        vpaddq	zmm18, zmm26, zmm18
        vpermq	zmm24, zmm16, 2
        vpermq	zmm25, zmm17, 2
        vpermq	zmm26, zmm18, 2
        vpaddq	zmm16, zmm24, zmm16
        vpaddq	zmm17, zmm25, zmm17
        vpaddq	zmm18, zmm26, zmm18
        vmovq	r12, xmm16
        vmovq	r13, xmm17
        vmovq	r14, xmm18
        mov	r10, r13
        shr	r10, 20
        mov	r11, r14
        shr	r11, 40
        mov	r8, r12
        mov	r12, r13
        shl	r12, 44
        add	r8, r12
        adc	r10, 0
        mov	r12, r14
        shl	r12, 24
        add	r10, r12
        adc	r11, 0
        mov	r9, r11
        and	r11, 3
        shr	r9, 2
        lea	r9, QWORD PTR [r9+4*r9+0]
        add	r8, r9
        adc	r10, 0
        adc	r11, 0
        mov	r12, QWORD PTR [rsi+24]
        mov	QWORD PTR [rsi+64], r12
        mov	r12, QWORD PTR [rsi+32]
        mov	QWORD PTR [rsi+72], r12
        mov	r12, QWORD PTR [rsi+40]
        mov	QWORD PTR [rsi+80], r12
        mov	QWORD PTR [rsi+24], r8
        mov	QWORD PTR [rsi+32], r10
        mov	QWORD PTR [rsi+40], r11
        vmovd	[rdi+48], xmm12
        vzeroupper
        vmovdqu	xmm6, OWORD PTR [rsp+1200]
        vmovdqu	xmm7, OWORD PTR [rsp+1216]
        vmovdqu	xmm8, OWORD PTR [rsp+1232]
        vmovdqu	xmm9, OWORD PTR [rsp+1248]
        vmovdqu	xmm10, OWORD PTR [rsp+1264]
        vmovdqu	xmm11, OWORD PTR [rsp+1280]
        vmovdqu	xmm12, OWORD PTR [rsp+1296]
        vmovdqu	xmm13, OWORD PTR [rsp+1312]
        vmovdqu	xmm14, OWORD PTR [rsp+1328]
        vmovdqu	xmm15, OWORD PTR [rsp+1344]
        add	rsp, 1360
        pop	r14
        pop	r13
        pop	r12
        pop	rsi
        pop	rdi
        ret
chacha20_poly1305_ifma_decrypt ENDP
_TEXT ENDS
ENDIF
IFDEF HAVE_INTEL_AVX2
_DATA SEGMENT
ALIGN 16
L_chacha20_poly1305_small_enc_rotl8 QWORD 0605040702010003h, 0e0d0c0f0a09080bh
        QWORD 0605040702010003h, 0e0d0c0f0a09080bh
ptr_L_chacha20_poly1305_small_enc_rotl8 QWORD L_chacha20_poly1305_small_enc_rotl8
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_chacha20_poly1305_small_enc_rotl16 QWORD 0504070601000302h, 0d0c0f0e09080b0ah
        QWORD 0504070601000302h, 0d0c0f0e09080b0ah
ptr_L_chacha20_poly1305_small_enc_rotl16 QWORD L_chacha20_poly1305_small_enc_rotl16
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_chacha20_poly1305_small_enc_ymm_inc QWORD 0000000000000000h, 0000000000000000h
        QWORD 0000000000000001h, 0000000000000000h
ptr_L_chacha20_poly1305_small_enc_ymm_inc QWORD L_chacha20_poly1305_small_enc_ymm_inc
_DATA ENDS
_TEXT SEGMENT READONLY PARA
chacha20_poly1305_small_enc PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        push	rbp
        mov	r10, QWORD PTR [rsp+104]
        mov	r11, QWORD PTR [rsp+112]
        sub	rsp, 352
        vmovdqu	OWORD PTR [rsp+192], xmm6
        vmovdqu	OWORD PTR [rsp+208], xmm7
        vmovdqu	OWORD PTR [rsp+224], xmm8
        vmovdqu	OWORD PTR [rsp+240], xmm9
        vmovdqu	OWORD PTR [rsp+256], xmm10
        vmovdqu	OWORD PTR [rsp+272], xmm11
        vmovdqu	OWORD PTR [rsp+288], xmm12
        vmovdqu	OWORD PTR [rsp+304], xmm13
        vmovdqu	OWORD PTR [rsp+320], xmm14
        vmovdqu	OWORD PTR [rsp+336], xmm15
        mov	eax, DWORD PTR [rsp+280]
        mov	QWORD PTR [rsp+128], rax
        mov	rax, QWORD PTR [rsp+288]
        mov	QWORD PTR [rsp+152], rax
        mov	QWORD PTR [rsp+136], r9
        mov	rax, r10
        mov	QWORD PTR [rsp+144], rax
        mov	r13, QWORD PTR [ptr_L_chacha20_poly1305_small_enc_rotl8]
        mov	r14, QWORD PTR [ptr_L_chacha20_poly1305_small_enc_rotl16]
        mov	r15, QWORD PTR [ptr_L_chacha20_poly1305_small_enc_ymm_inc]
        vbroadcasti128	ymm0, OWORD PTR [rcx]
        vbroadcasti128	ymm1, OWORD PTR [rcx+16]
        vbroadcasti128	ymm2, OWORD PTR [rcx+32]
        vbroadcasti128	ymm3, OWORD PTR [rcx+48]
        vpaddd	ymm3, ymm3, YMMWORD PTR [r15]
        vmovdqa	ymm10, ymm0
        vmovdqa	ymm11, ymm1
        vmovdqa	ymm12, ymm2
        vmovdqa	ymm13, ymm3
        mov	r9b, 10
L_c20p1305_small_enc_crypt2_start:
        vpaddd	ymm0, ymm0, ymm1
        vpxor	ymm3, ymm3, ymm0
        vpshufb	ymm3, ymm3, YMMWORD PTR [r14]
        vpaddd	ymm2, ymm2, ymm3
        vpxor	ymm1, ymm1, ymm2
        vpsrld	ymm8, ymm1, 20
        vpslld	ymm1, ymm1, 12
        vpxor	ymm1, ymm1, ymm8
        vpaddd	ymm0, ymm0, ymm1
        vpxor	ymm3, ymm3, ymm0
        vpshufb	ymm3, ymm3, YMMWORD PTR [r13]
        vpaddd	ymm2, ymm2, ymm3
        vpxor	ymm1, ymm1, ymm2
        vpsrld	ymm8, ymm1, 25
        vpslld	ymm1, ymm1, 7
        vpxor	ymm1, ymm1, ymm8
        vpshufd	ymm1, ymm1, 57
        vpshufd	ymm2, ymm2, 78
        vpshufd	ymm3, ymm3, 147
        vpaddd	ymm0, ymm0, ymm1
        vpxor	ymm3, ymm3, ymm0
        vpshufb	ymm3, ymm3, YMMWORD PTR [r14]
        vpaddd	ymm2, ymm2, ymm3
        vpxor	ymm1, ymm1, ymm2
        vpsrld	ymm8, ymm1, 20
        vpslld	ymm1, ymm1, 12
        vpxor	ymm1, ymm1, ymm8
        vpaddd	ymm0, ymm0, ymm1
        vpxor	ymm3, ymm3, ymm0
        vpshufb	ymm3, ymm3, YMMWORD PTR [r13]
        vpaddd	ymm2, ymm2, ymm3
        vpxor	ymm1, ymm1, ymm2
        vpsrld	ymm8, ymm1, 25
        vpslld	ymm1, ymm1, 7
        vpxor	ymm1, ymm1, ymm8
        vpshufd	ymm1, ymm1, 147
        vpshufd	ymm2, ymm2, 78
        vpshufd	ymm3, ymm3, 57
        dec	r9b
        jnz	L_c20p1305_small_enc_crypt2_start
        vpaddd	ymm0, ymm0, ymm10
        vpaddd	ymm1, ymm1, ymm11
        vpaddd	ymm2, ymm2, ymm12
        vpaddd	ymm3, ymm3, ymm13
        vextracti128	xmm4, ymm0, 1
        vextracti128	xmm5, ymm1, 1
        vextracti128	xmm6, ymm2, 1
        vextracti128	xmm7, ymm3, 1
        vmovdqu	OWORD PTR [rsp], xmm0
        vmovdqu	OWORD PTR [rsp+16], xmm1
        vmovdqu	OWORD PTR [rsp+32], xmm4
        vmovdqu	OWORD PTR [rsp+48], xmm5
        vmovdqu	OWORD PTR [rsp+64], xmm6
        vmovdqu	OWORD PTR [rsp+80], xmm7
        mov	r9, QWORD PTR [rsp+136]
        mov	rbp, QWORD PTR [rsp+144]
        lea	rbx, QWORD PTR [rsp+32]
L_chacha20_poly1305_small_enc_x16:
        cmp	rbp, 16
        jl	L_chacha20_poly1305_small_enc_xtail
        vmovdqu	xmm8, OWORD PTR [r8]
        vpxor	xmm8, xmm8, [rbx]
        vmovdqu	OWORD PTR [r9], xmm8
        add	r8, 16
        add	r9, 16
        add	rbx, 16
        sub	rbp, 16
        jmp	L_chacha20_poly1305_small_enc_x16
L_chacha20_poly1305_small_enc_xtail:
        vzeroupper
        test	rbp, rbp
        jz	L_chacha20_poly1305_small_enc_xdone
        xor	rcx, rcx
L_chacha20_poly1305_small_enc_xbyte:
        cmp	rcx, rbp
        jge	L_chacha20_poly1305_small_enc_xdone
        movzx	eax, BYTE PTR [r8+rcx]
        xor	al, BYTE PTR [rbx+rcx]
        mov	BYTE PTR [r9+rcx], al
        inc	rcx
        jmp	L_chacha20_poly1305_small_enc_xbyte
L_chacha20_poly1305_small_enc_xdone:
        mov	r12, rdx
        mov	rax, 1152921487695413247
        mov	r8, 1152921487695413244
        mov	r13, QWORD PTR [rsp]
        and	r13, rax
        mov	r14, QWORD PTR [rsp+8]
        and	r14, r8
        mov	rax, QWORD PTR [rsp+16]
        mov	QWORD PTR [r12+48], rax
        mov	rax, QWORD PTR [rsp+24]
        mov	QWORD PTR [r12+56], rax
        xor	rax, rax
        mov	QWORD PTR [r12+352], rax
        mov	QWORD PTR [r12+408], rax
        mov	QWORD PTR [r12+360], r13
        mov	QWORD PTR [r12+416], r14
        mov	r9, r13
        mov	rdx, r14
        add	r9, r13
        add	rdx, r14
        mov	QWORD PTR [r12+368], r9
        mov	QWORD PTR [r12+424], rdx
        add	r9, r13
        add	rdx, r14
        mov	QWORD PTR [r12+376], r9
        mov	QWORD PTR [r12+432], rdx
        add	r9, r13
        add	rdx, r14
        mov	QWORD PTR [r12+384], r9
        mov	QWORD PTR [r12+440], rdx
        add	r9, r13
        add	rdx, r14
        mov	QWORD PTR [r12+392], r9
        mov	QWORD PTR [r12+448], rdx
        add	r9, r13
        add	rdx, r14
        mov	QWORD PTR [r12+400], r9
        mov	QWORD PTR [r12+456], rdx
        xor	r15, r15
        xor	rdi, rdi
        xor	rsi, rsi
        mov	rbx, r11
        mov	rbp, QWORD PTR [rsp+128]
L_c20p1305_small_aad_full:
        cmp	rbp, 16
        jl	L_c20p1305_small_aad_part
        mov	r9, QWORD PTR [rbx]
        mov	rdx, QWORD PTR [rbx+8]
        add	r15, r9
        adc	rdi, rdx
        mov	rax, r14
        adc	rsi, 1
        mul	r15
        mov	rdx, rax
        mov	rcx, r8
        mov	rax, r13
        mul	rdi
        add	rdx, rax
        mov	rax, r13
        adc	rcx, r8
        mul	r15
        mov	r9, rax
        mov	r11, r8
        mov	rax, r14
        mul	rdi
        add	rcx, QWORD PTR [r12+8*rsi+352]
        mov	r10, r8
        add	rdx, r11
        adc	rcx, rax
        adc	r10, QWORD PTR [r12+8*rsi+408]
        mov	rsi, rcx
        and	rcx, -4
        and	rsi, 3
        add	r9, rcx
        mov	r15, rcx
        adc	rdx, r10
        adc	rsi, 0
        shrd	r15, r10, 2
        shr	r10, 2
        add	r15, r9
        adc	rdx, r10
        mov	rdi, rdx
        adc	rsi, 0
        add	rbx, 16
        sub	rbp, 16
        jmp	L_c20p1305_small_aad_full
L_c20p1305_small_aad_part:
        test	rbp, rbp
        jz	L_c20p1305_small_aad_done
        xor	rax, rax
        mov	QWORD PTR [rsp+96], rax
        mov	QWORD PTR [rsp+104], rax
        lea	r11, QWORD PTR [rsp+96]
        cmp	rbp, 8
        jl	L_c20p1305_small_aad_c4
        mov	rax, QWORD PTR [rbx]
        mov	QWORD PTR [r11], rax
        add	rbx, 8
        add	r11, 8
        sub	rbp, 8
L_c20p1305_small_aad_c4:
        cmp	rbp, 4
        jl	L_c20p1305_small_aad_cby
        mov	eax, DWORD PTR [rbx]
        mov	DWORD PTR [r11], eax
        add	rbx, 4
        add	r11, 4
        sub	rbp, 4
L_c20p1305_small_aad_cby:
        test	rbp, rbp
        jz	L_c20p1305_small_aad_cpyd
L_c20p1305_small_aad_cbyl:
        movzx	eax, BYTE PTR [rbx]
        mov	BYTE PTR [r11], al
        add	rbx, 1
        add	r11, 1
        sub	rbp, 1
        jnz	L_c20p1305_small_aad_cbyl
L_c20p1305_small_aad_cpyd:
        lea	rbx, QWORD PTR [rsp+96]
        mov	r9, QWORD PTR [rbx]
        mov	rdx, QWORD PTR [rbx+8]
        add	r15, r9
        adc	rdi, rdx
        mov	rax, r14
        adc	rsi, 1
        mul	r15
        mov	rdx, rax
        mov	rcx, r8
        mov	rax, r13
        mul	rdi
        add	rdx, rax
        mov	rax, r13
        adc	rcx, r8
        mul	r15
        mov	r9, rax
        mov	r11, r8
        mov	rax, r14
        mul	rdi
        add	rcx, QWORD PTR [r12+8*rsi+352]
        mov	r10, r8
        add	rdx, r11
        adc	rcx, rax
        adc	r10, QWORD PTR [r12+8*rsi+408]
        mov	rsi, rcx
        and	rcx, -4
        and	rsi, 3
        add	r9, rcx
        mov	r15, rcx
        adc	rdx, r10
        adc	rsi, 0
        shrd	r15, r10, 2
        shr	r10, 2
        add	r15, r9
        adc	rdx, r10
        mov	rdi, rdx
        adc	rsi, 0
L_c20p1305_small_aad_done:
        mov	rbx, QWORD PTR [rsp+136]
        mov	rbp, QWORD PTR [rsp+144]
L_c20p1305_small_ct_full:
        cmp	rbp, 16
        jl	L_c20p1305_small_ct_part
        mov	r9, QWORD PTR [rbx]
        mov	rdx, QWORD PTR [rbx+8]
        add	r15, r9
        adc	rdi, rdx
        mov	rax, r14
        adc	rsi, 1
        mul	r15
        mov	rdx, rax
        mov	rcx, r8
        mov	rax, r13
        mul	rdi
        add	rdx, rax
        mov	rax, r13
        adc	rcx, r8
        mul	r15
        mov	r9, rax
        mov	r11, r8
        mov	rax, r14
        mul	rdi
        add	rcx, QWORD PTR [r12+8*rsi+352]
        mov	r10, r8
        add	rdx, r11
        adc	rcx, rax
        adc	r10, QWORD PTR [r12+8*rsi+408]
        mov	rsi, rcx
        and	rcx, -4
        and	rsi, 3
        add	r9, rcx
        mov	r15, rcx
        adc	rdx, r10
        adc	rsi, 0
        shrd	r15, r10, 2
        shr	r10, 2
        add	r15, r9
        adc	rdx, r10
        mov	rdi, rdx
        adc	rsi, 0
        add	rbx, 16
        sub	rbp, 16
        jmp	L_c20p1305_small_ct_full
L_c20p1305_small_ct_part:
        test	rbp, rbp
        jz	L_c20p1305_small_ct_done
        xor	rax, rax
        mov	QWORD PTR [rsp+96], rax
        mov	QWORD PTR [rsp+104], rax
        lea	r11, QWORD PTR [rsp+96]
        cmp	rbp, 8
        jl	L_c20p1305_small_ct_c4
        mov	rax, QWORD PTR [rbx]
        mov	QWORD PTR [r11], rax
        add	rbx, 8
        add	r11, 8
        sub	rbp, 8
L_c20p1305_small_ct_c4:
        cmp	rbp, 4
        jl	L_c20p1305_small_ct_cby
        mov	eax, DWORD PTR [rbx]
        mov	DWORD PTR [r11], eax
        add	rbx, 4
        add	r11, 4
        sub	rbp, 4
L_c20p1305_small_ct_cby:
        test	rbp, rbp
        jz	L_c20p1305_small_ct_cpyd
L_c20p1305_small_ct_cbyl:
        movzx	eax, BYTE PTR [rbx]
        mov	BYTE PTR [r11], al
        add	rbx, 1
        add	r11, 1
        sub	rbp, 1
        jnz	L_c20p1305_small_ct_cbyl
L_c20p1305_small_ct_cpyd:
        lea	rbx, QWORD PTR [rsp+96]
        mov	r9, QWORD PTR [rbx]
        mov	rdx, QWORD PTR [rbx+8]
        add	r15, r9
        adc	rdi, rdx
        mov	rax, r14
        adc	rsi, 1
        mul	r15
        mov	rdx, rax
        mov	rcx, r8
        mov	rax, r13
        mul	rdi
        add	rdx, rax
        mov	rax, r13
        adc	rcx, r8
        mul	r15
        mov	r9, rax
        mov	r11, r8
        mov	rax, r14
        mul	rdi
        add	rcx, QWORD PTR [r12+8*rsi+352]
        mov	r10, r8
        add	rdx, r11
        adc	rcx, rax
        adc	r10, QWORD PTR [r12+8*rsi+408]
        mov	rsi, rcx
        and	rcx, -4
        and	rsi, 3
        add	r9, rcx
        mov	r15, rcx
        adc	rdx, r10
        adc	rsi, 0
        shrd	r15, r10, 2
        shr	r10, 2
        add	r15, r9
        adc	rdx, r10
        mov	rdi, rdx
        adc	rsi, 0
L_c20p1305_small_ct_done:
        mov	rax, QWORD PTR [rsp+128]
        mov	QWORD PTR [rsp+112], rax
        mov	rax, QWORD PTR [rsp+144]
        mov	QWORD PTR [rsp+120], rax
        lea	rbx, QWORD PTR [rsp+112]
        mov	r9, QWORD PTR [rbx]
        mov	rdx, QWORD PTR [rbx+8]
        add	r15, r9
        adc	rdi, rdx
        mov	rax, r14
        adc	rsi, 1
        mul	r15
        mov	rdx, rax
        mov	rcx, r8
        mov	rax, r13
        mul	rdi
        add	rdx, rax
        mov	rax, r13
        adc	rcx, r8
        mul	r15
        mov	r9, rax
        mov	r11, r8
        mov	rax, r14
        mul	rdi
        add	rcx, QWORD PTR [r12+8*rsi+352]
        mov	r10, r8
        add	rdx, r11
        adc	rcx, rax
        adc	r10, QWORD PTR [r12+8*rsi+408]
        mov	rsi, rcx
        and	rcx, -4
        and	rsi, 3
        add	r9, rcx
        mov	r15, rcx
        adc	rdx, r10
        adc	rsi, 0
        shrd	r15, r10, 2
        shr	r10, 2
        add	r15, r9
        adc	rdx, r10
        mov	rdi, rdx
        adc	rsi, 0
        mov	rbx, QWORD PTR [rsp+152]
        mov	r9, rsi
        and	rsi, 3
        shr	r9, 2
        lea	r9, QWORD PTR [r9+4*r9+0]
        add	r15, r9
        adc	rdi, 0
        adc	rsi, 0
        mov	r9, r15
        mov	rdx, rdi
        mov	rcx, rsi
        add	r9, 5
        adc	rdx, 0
        adc	rcx, 0
        cmp	rcx, 4
        cmove	r15, r9
        cmove	rdi, rdx
        add	r15, QWORD PTR [r12+48]
        adc	rdi, QWORD PTR [r12+56]
        mov	QWORD PTR [rbx], r15
        mov	QWORD PTR [rbx+8], rdi
        vpxor	xmm0, xmm0, xmm0
        vmovdqu	OWORD PTR [rsp], xmm0
        vmovdqu	OWORD PTR [rsp+16], xmm0
        vmovdqu	OWORD PTR [rsp+32], xmm0
        vmovdqu	OWORD PTR [rsp+48], xmm0
        vmovdqu	OWORD PTR [rsp+64], xmm0
        vmovdqu	OWORD PTR [rsp+80], xmm0
        vmovdqu	xmm6, OWORD PTR [rsp+192]
        vmovdqu	xmm7, OWORD PTR [rsp+208]
        vmovdqu	xmm8, OWORD PTR [rsp+224]
        vmovdqu	xmm9, OWORD PTR [rsp+240]
        vmovdqu	xmm10, OWORD PTR [rsp+256]
        vmovdqu	xmm11, OWORD PTR [rsp+272]
        vmovdqu	xmm12, OWORD PTR [rsp+288]
        vmovdqu	xmm13, OWORD PTR [rsp+304]
        vmovdqu	xmm14, OWORD PTR [rsp+320]
        vmovdqu	xmm15, OWORD PTR [rsp+336]
        add	rsp, 352
        pop	rbp
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
chacha20_poly1305_small_enc ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
chacha20_poly1305_small_dec PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        push	rbp
        mov	r10, QWORD PTR [rsp+104]
        mov	r11, QWORD PTR [rsp+112]
        sub	rsp, 328
        vmovdqu	OWORD PTR [rsp+168], xmm6
        vmovdqu	OWORD PTR [rsp+184], xmm7
        vmovdqu	OWORD PTR [rsp+200], xmm8
        vmovdqu	OWORD PTR [rsp+216], xmm9
        vmovdqu	OWORD PTR [rsp+232], xmm10
        vmovdqu	OWORD PTR [rsp+248], xmm11
        vmovdqu	OWORD PTR [rsp+264], xmm12
        vmovdqu	OWORD PTR [rsp+280], xmm13
        vmovdqu	OWORD PTR [rsp+296], xmm14
        vmovdqu	OWORD PTR [rsp+312], xmm15
        mov	eax, DWORD PTR [rsp+256]
        mov	QWORD PTR [rsp+128], rax
        mov	rax, QWORD PTR [rsp+264]
        mov	QWORD PTR [rsp+144], rax
        mov	rax, r10
        mov	QWORD PTR [rsp+136], rax
        mov	rax, r8
        mov	QWORD PTR [rsp+152], rax
        mov	rax, r9
        mov	QWORD PTR [rsp+160], rax
        mov	r13, QWORD PTR [ptr_L_chacha20_poly1305_small_enc_rotl8]
        mov	r14, QWORD PTR [ptr_L_chacha20_poly1305_small_enc_rotl16]
        mov	r15, QWORD PTR [ptr_L_chacha20_poly1305_small_enc_ymm_inc]
        vbroadcasti128	ymm0, OWORD PTR [rcx]
        vbroadcasti128	ymm1, OWORD PTR [rcx+16]
        vbroadcasti128	ymm2, OWORD PTR [rcx+32]
        vbroadcasti128	ymm3, OWORD PTR [rcx+48]
        vpaddd	ymm3, ymm3, YMMWORD PTR [r15]
        vmovdqa	ymm10, ymm0
        vmovdqa	ymm11, ymm1
        vmovdqa	ymm12, ymm2
        vmovdqa	ymm13, ymm3
        mov	r9b, 10
L_c20p1305_small_dec_crypt2_start:
        vpaddd	ymm0, ymm0, ymm1
        vpxor	ymm3, ymm3, ymm0
        vpshufb	ymm3, ymm3, YMMWORD PTR [r14]
        vpaddd	ymm2, ymm2, ymm3
        vpxor	ymm1, ymm1, ymm2
        vpsrld	ymm8, ymm1, 20
        vpslld	ymm1, ymm1, 12
        vpxor	ymm1, ymm1, ymm8
        vpaddd	ymm0, ymm0, ymm1
        vpxor	ymm3, ymm3, ymm0
        vpshufb	ymm3, ymm3, YMMWORD PTR [r13]
        vpaddd	ymm2, ymm2, ymm3
        vpxor	ymm1, ymm1, ymm2
        vpsrld	ymm8, ymm1, 25
        vpslld	ymm1, ymm1, 7
        vpxor	ymm1, ymm1, ymm8
        vpshufd	ymm1, ymm1, 57
        vpshufd	ymm2, ymm2, 78
        vpshufd	ymm3, ymm3, 147
        vpaddd	ymm0, ymm0, ymm1
        vpxor	ymm3, ymm3, ymm0
        vpshufb	ymm3, ymm3, YMMWORD PTR [r14]
        vpaddd	ymm2, ymm2, ymm3
        vpxor	ymm1, ymm1, ymm2
        vpsrld	ymm8, ymm1, 20
        vpslld	ymm1, ymm1, 12
        vpxor	ymm1, ymm1, ymm8
        vpaddd	ymm0, ymm0, ymm1
        vpxor	ymm3, ymm3, ymm0
        vpshufb	ymm3, ymm3, YMMWORD PTR [r13]
        vpaddd	ymm2, ymm2, ymm3
        vpxor	ymm1, ymm1, ymm2
        vpsrld	ymm8, ymm1, 25
        vpslld	ymm1, ymm1, 7
        vpxor	ymm1, ymm1, ymm8
        vpshufd	ymm1, ymm1, 147
        vpshufd	ymm2, ymm2, 78
        vpshufd	ymm3, ymm3, 57
        dec	r9b
        jnz	L_c20p1305_small_dec_crypt2_start
        vpaddd	ymm0, ymm0, ymm10
        vpaddd	ymm1, ymm1, ymm11
        vpaddd	ymm2, ymm2, ymm12
        vpaddd	ymm3, ymm3, ymm13
        vextracti128	xmm4, ymm0, 1
        vextracti128	xmm5, ymm1, 1
        vextracti128	xmm6, ymm2, 1
        vextracti128	xmm7, ymm3, 1
        mov	r12, rdx
        vmovdqu	OWORD PTR [rsp], xmm0
        vmovdqu	OWORD PTR [rsp+16], xmm1
        vmovdqu	OWORD PTR [rsp+32], xmm4
        vmovdqu	OWORD PTR [rsp+48], xmm5
        vmovdqu	OWORD PTR [rsp+64], xmm6
        vmovdqu	OWORD PTR [rsp+80], xmm7
        mov	rax, 1152921487695413247
        mov	r8, 1152921487695413244
        mov	r13, QWORD PTR [rsp]
        and	r13, rax
        mov	r14, QWORD PTR [rsp+8]
        and	r14, r8
        mov	rax, QWORD PTR [rsp+16]
        mov	QWORD PTR [r12+48], rax
        mov	rax, QWORD PTR [rsp+24]
        mov	QWORD PTR [r12+56], rax
        xor	rax, rax
        mov	QWORD PTR [r12+352], rax
        mov	QWORD PTR [r12+408], rax
        mov	QWORD PTR [r12+360], r13
        mov	QWORD PTR [r12+416], r14
        mov	r9, r13
        mov	rdx, r14
        add	r9, r13
        add	rdx, r14
        mov	QWORD PTR [r12+368], r9
        mov	QWORD PTR [r12+424], rdx
        add	r9, r13
        add	rdx, r14
        mov	QWORD PTR [r12+376], r9
        mov	QWORD PTR [r12+432], rdx
        add	r9, r13
        add	rdx, r14
        mov	QWORD PTR [r12+384], r9
        mov	QWORD PTR [r12+440], rdx
        add	r9, r13
        add	rdx, r14
        mov	QWORD PTR [r12+392], r9
        mov	QWORD PTR [r12+448], rdx
        add	r9, r13
        add	rdx, r14
        mov	QWORD PTR [r12+400], r9
        mov	QWORD PTR [r12+456], rdx
        xor	r15, r15
        xor	rdi, rdi
        xor	rsi, rsi
        mov	rbx, r11
        mov	rbp, QWORD PTR [rsp+128]
L_c20p1305_small_dec_aad_full:
        cmp	rbp, 16
        jl	L_c20p1305_small_dec_aad_part
        mov	r9, QWORD PTR [rbx]
        mov	rdx, QWORD PTR [rbx+8]
        add	r15, r9
        adc	rdi, rdx
        mov	rax, r14
        adc	rsi, 1
        mul	r15
        mov	rdx, rax
        mov	rcx, r8
        mov	rax, r13
        mul	rdi
        add	rdx, rax
        mov	rax, r13
        adc	rcx, r8
        mul	r15
        mov	r9, rax
        mov	r11, r8
        mov	rax, r14
        mul	rdi
        add	rcx, QWORD PTR [r12+8*rsi+352]
        mov	r10, r8
        add	rdx, r11
        adc	rcx, rax
        adc	r10, QWORD PTR [r12+8*rsi+408]
        mov	rsi, rcx
        and	rcx, -4
        and	rsi, 3
        add	r9, rcx
        mov	r15, rcx
        adc	rdx, r10
        adc	rsi, 0
        shrd	r15, r10, 2
        shr	r10, 2
        add	r15, r9
        adc	rdx, r10
        mov	rdi, rdx
        adc	rsi, 0
        add	rbx, 16
        sub	rbp, 16
        jmp	L_c20p1305_small_dec_aad_full
L_c20p1305_small_dec_aad_part:
        test	rbp, rbp
        jz	L_c20p1305_small_dec_aad_done
        xor	rax, rax
        mov	QWORD PTR [rsp+96], rax
        mov	QWORD PTR [rsp+104], rax
        lea	r11, QWORD PTR [rsp+96]
        cmp	rbp, 8
        jl	L_c20p1305_small_dec_aad_c4
        mov	rax, QWORD PTR [rbx]
        mov	QWORD PTR [r11], rax
        add	rbx, 8
        add	r11, 8
        sub	rbp, 8
L_c20p1305_small_dec_aad_c4:
        cmp	rbp, 4
        jl	L_c20p1305_small_dec_aad_cby
        mov	eax, DWORD PTR [rbx]
        mov	DWORD PTR [r11], eax
        add	rbx, 4
        add	r11, 4
        sub	rbp, 4
L_c20p1305_small_dec_aad_cby:
        test	rbp, rbp
        jz	L_c20p1305_small_dec_aad_cpyd
L_c20p1305_small_dec_aad_cbyl:
        movzx	eax, BYTE PTR [rbx]
        mov	BYTE PTR [r11], al
        add	rbx, 1
        add	r11, 1
        sub	rbp, 1
        jnz	L_c20p1305_small_dec_aad_cbyl
L_c20p1305_small_dec_aad_cpyd:
        lea	rbx, QWORD PTR [rsp+96]
        mov	r9, QWORD PTR [rbx]
        mov	rdx, QWORD PTR [rbx+8]
        add	r15, r9
        adc	rdi, rdx
        mov	rax, r14
        adc	rsi, 1
        mul	r15
        mov	rdx, rax
        mov	rcx, r8
        mov	rax, r13
        mul	rdi
        add	rdx, rax
        mov	rax, r13
        adc	rcx, r8
        mul	r15
        mov	r9, rax
        mov	r11, r8
        mov	rax, r14
        mul	rdi
        add	rcx, QWORD PTR [r12+8*rsi+352]
        mov	r10, r8
        add	rdx, r11
        adc	rcx, rax
        adc	r10, QWORD PTR [r12+8*rsi+408]
        mov	rsi, rcx
        and	rcx, -4
        and	rsi, 3
        add	r9, rcx
        mov	r15, rcx
        adc	rdx, r10
        adc	rsi, 0
        shrd	r15, r10, 2
        shr	r10, 2
        add	r15, r9
        adc	rdx, r10
        mov	rdi, rdx
        adc	rsi, 0
L_c20p1305_small_dec_aad_done:
        mov	rbx, QWORD PTR [rsp+152]
        mov	rbp, QWORD PTR [rsp+136]
L_c20p1305_small_dec_ct_full:
        cmp	rbp, 16
        jl	L_c20p1305_small_dec_ct_part
        mov	r9, QWORD PTR [rbx]
        mov	rdx, QWORD PTR [rbx+8]
        add	r15, r9
        adc	rdi, rdx
        mov	rax, r14
        adc	rsi, 1
        mul	r15
        mov	rdx, rax
        mov	rcx, r8
        mov	rax, r13
        mul	rdi
        add	rdx, rax
        mov	rax, r13
        adc	rcx, r8
        mul	r15
        mov	r9, rax
        mov	r11, r8
        mov	rax, r14
        mul	rdi
        add	rcx, QWORD PTR [r12+8*rsi+352]
        mov	r10, r8
        add	rdx, r11
        adc	rcx, rax
        adc	r10, QWORD PTR [r12+8*rsi+408]
        mov	rsi, rcx
        and	rcx, -4
        and	rsi, 3
        add	r9, rcx
        mov	r15, rcx
        adc	rdx, r10
        adc	rsi, 0
        shrd	r15, r10, 2
        shr	r10, 2
        add	r15, r9
        adc	rdx, r10
        mov	rdi, rdx
        adc	rsi, 0
        add	rbx, 16
        sub	rbp, 16
        jmp	L_c20p1305_small_dec_ct_full
L_c20p1305_small_dec_ct_part:
        test	rbp, rbp
        jz	L_c20p1305_small_dec_ct_done
        xor	rax, rax
        mov	QWORD PTR [rsp+96], rax
        mov	QWORD PTR [rsp+104], rax
        lea	r11, QWORD PTR [rsp+96]
        cmp	rbp, 8
        jl	L_c20p1305_small_dec_ct_c4
        mov	rax, QWORD PTR [rbx]
        mov	QWORD PTR [r11], rax
        add	rbx, 8
        add	r11, 8
        sub	rbp, 8
L_c20p1305_small_dec_ct_c4:
        cmp	rbp, 4
        jl	L_c20p1305_small_dec_ct_cby
        mov	eax, DWORD PTR [rbx]
        mov	DWORD PTR [r11], eax
        add	rbx, 4
        add	r11, 4
        sub	rbp, 4
L_c20p1305_small_dec_ct_cby:
        test	rbp, rbp
        jz	L_c20p1305_small_dec_ct_cpyd
L_c20p1305_small_dec_ct_cbyl:
        movzx	eax, BYTE PTR [rbx]
        mov	BYTE PTR [r11], al
        add	rbx, 1
        add	r11, 1
        sub	rbp, 1
        jnz	L_c20p1305_small_dec_ct_cbyl
L_c20p1305_small_dec_ct_cpyd:
        lea	rbx, QWORD PTR [rsp+96]
        mov	r9, QWORD PTR [rbx]
        mov	rdx, QWORD PTR [rbx+8]
        add	r15, r9
        adc	rdi, rdx
        mov	rax, r14
        adc	rsi, 1
        mul	r15
        mov	rdx, rax
        mov	rcx, r8
        mov	rax, r13
        mul	rdi
        add	rdx, rax
        mov	rax, r13
        adc	rcx, r8
        mul	r15
        mov	r9, rax
        mov	r11, r8
        mov	rax, r14
        mul	rdi
        add	rcx, QWORD PTR [r12+8*rsi+352]
        mov	r10, r8
        add	rdx, r11
        adc	rcx, rax
        adc	r10, QWORD PTR [r12+8*rsi+408]
        mov	rsi, rcx
        and	rcx, -4
        and	rsi, 3
        add	r9, rcx
        mov	r15, rcx
        adc	rdx, r10
        adc	rsi, 0
        shrd	r15, r10, 2
        shr	r10, 2
        add	r15, r9
        adc	rdx, r10
        mov	rdi, rdx
        adc	rsi, 0
L_c20p1305_small_dec_ct_done:
        mov	rax, QWORD PTR [rsp+128]
        mov	QWORD PTR [rsp+112], rax
        mov	rax, QWORD PTR [rsp+136]
        mov	QWORD PTR [rsp+120], rax
        lea	rbx, QWORD PTR [rsp+112]
        mov	r9, QWORD PTR [rbx]
        mov	rdx, QWORD PTR [rbx+8]
        add	r15, r9
        adc	rdi, rdx
        mov	rax, r14
        adc	rsi, 1
        mul	r15
        mov	rdx, rax
        mov	rcx, r8
        mov	rax, r13
        mul	rdi
        add	rdx, rax
        mov	rax, r13
        adc	rcx, r8
        mul	r15
        mov	r9, rax
        mov	r11, r8
        mov	rax, r14
        mul	rdi
        add	rcx, QWORD PTR [r12+8*rsi+352]
        mov	r10, r8
        add	rdx, r11
        adc	rcx, rax
        adc	r10, QWORD PTR [r12+8*rsi+408]
        mov	rsi, rcx
        and	rcx, -4
        and	rsi, 3
        add	r9, rcx
        mov	r15, rcx
        adc	rdx, r10
        adc	rsi, 0
        shrd	r15, r10, 2
        shr	r10, 2
        add	r15, r9
        adc	rdx, r10
        mov	rdi, rdx
        adc	rsi, 0
        mov	r8, QWORD PTR [rsp+152]
        mov	r9, QWORD PTR [rsp+160]
        mov	rbp, QWORD PTR [rsp+136]
        lea	rbx, QWORD PTR [rsp+32]
L_chacha20_poly1305_small_dec_x16:
        cmp	rbp, 16
        jl	L_chacha20_poly1305_small_dec_xtail
        vmovdqu	xmm8, OWORD PTR [r8]
        vpxor	xmm8, xmm8, [rbx]
        vmovdqu	OWORD PTR [r9], xmm8
        add	r8, 16
        add	r9, 16
        add	rbx, 16
        sub	rbp, 16
        jmp	L_chacha20_poly1305_small_dec_x16
L_chacha20_poly1305_small_dec_xtail:
        test	rbp, rbp
        jz	L_chacha20_poly1305_small_dec_xdone
        xor	rcx, rcx
L_chacha20_poly1305_small_dec_xbyte:
        cmp	rcx, rbp
        jge	L_chacha20_poly1305_small_dec_xdone
        movzx	eax, BYTE PTR [r8+rcx]
        xor	al, BYTE PTR [rbx+rcx]
        mov	BYTE PTR [r9+rcx], al
        inc	rcx
        jmp	L_chacha20_poly1305_small_dec_xbyte
L_chacha20_poly1305_small_dec_xdone:
        vpxor	xmm0, xmm0, xmm0
        vmovdqu	OWORD PTR [rsp], xmm0
        vmovdqu	OWORD PTR [rsp+16], xmm0
        vmovdqu	OWORD PTR [rsp+32], xmm0
        vmovdqu	OWORD PTR [rsp+48], xmm0
        vmovdqu	OWORD PTR [rsp+64], xmm0
        vmovdqu	OWORD PTR [rsp+80], xmm0
        vzeroupper
        mov	rbx, QWORD PTR [rsp+144]
        mov	r9, rsi
        and	rsi, 3
        shr	r9, 2
        lea	r9, QWORD PTR [r9+4*r9+0]
        add	r15, r9
        adc	rdi, 0
        adc	rsi, 0
        mov	r9, r15
        mov	rdx, rdi
        mov	rcx, rsi
        add	r9, 5
        adc	rdx, 0
        adc	rcx, 0
        cmp	rcx, 4
        cmove	r15, r9
        cmove	rdi, rdx
        add	r15, QWORD PTR [r12+48]
        adc	rdi, QWORD PTR [r12+56]
        xor	r15, QWORD PTR [rbx]
        xor	rdi, QWORD PTR [rbx+8]
        or	r15, rdi
        mov	rax, r15
        neg	rax
        or	rax, r15
        shr	rax, 63
        vmovdqu	xmm6, OWORD PTR [rsp+168]
        vmovdqu	xmm7, OWORD PTR [rsp+184]
        vmovdqu	xmm8, OWORD PTR [rsp+200]
        vmovdqu	xmm9, OWORD PTR [rsp+216]
        vmovdqu	xmm10, OWORD PTR [rsp+232]
        vmovdqu	xmm11, OWORD PTR [rsp+248]
        vmovdqu	xmm12, OWORD PTR [rsp+264]
        vmovdqu	xmm13, OWORD PTR [rsp+280]
        vmovdqu	xmm14, OWORD PTR [rsp+296]
        vmovdqu	xmm15, OWORD PTR [rsp+312]
        add	rsp, 328
        pop	rbp
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
chacha20_poly1305_small_dec ENDP
_TEXT ENDS
ENDIF
END
