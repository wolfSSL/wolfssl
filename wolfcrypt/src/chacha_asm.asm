; /* chacha_asm.asm */
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
        mov	edx, DWORD PTR [rsp+8]
        mov	ebp, DWORD PTR [rsp+12]
L_chacha_x64_block_crypt_start:
        add	eax, r8d
        add	ebx, r9d
        xor	r12d, eax
        xor	r13d, ebx
        rol	r12d, 16
        rol	r13d, 16
        add	edx, r12d
        add	ebp, r13d
        xor	r8d, edx
        xor	r9d, ebp
        rol	r8d, 12
        rol	r9d, 12
        add	eax, r8d
        add	ebx, r9d
        xor	r12d, eax
        xor	r13d, ebx
        rol	r12d, 8
        rol	r13d, 8
        add	edx, r12d
        add	ebp, r13d
        xor	r8d, edx
        xor	r9d, ebp
        rol	r8d, 7
        rol	r9d, 7
        mov	DWORD PTR [rsp+8], edx
        mov	DWORD PTR [rsp+12], ebp
        mov	edx, DWORD PTR [rsp+16]
        mov	ebp, DWORD PTR [rsp+20]
        add	r9d, r10d
        add	r8d, r11d
        xor	r14d, r9d
        xor	r15d, r8d
        rol	r14d, 16
        rol	r15d, 16
        add	edx, r14d
        add	ebp, r15d
        xor	r10d, edx
        xor	r11d, ebp
        rol	r10d, 12
        rol	r11d, 12
        add	r9d, r10d
        add	r8d, r11d
        xor	r14d, r9d
        xor	r15d, r8d
        rol	r14d, 8
        rol	r15d, 8
        add	edx, r14d
        add	ebp, r15d
        xor	r10d, edx
        xor	r11d, ebp
        rol	r10d, 7
        rol	r11d, 7
        add	eax, r9d
        add	ebx, r10d
        xor	r15d, eax
        xor	r12d, ebx
        rol	r15d, 16
        rol	r12d, 16
        add	edx, r15d
        add	ebp, r12d
        xor	r9d, edx
        xor	r10d, ebp
        rol	r9d, 12
        rol	r10d, 12
        add	eax, r9d
        add	ebx, r10d
        xor	r15d, eax
        xor	r12d, ebx
        rol	r15d, 8
        rol	r12d, 8
        add	edx, r15d
        add	ebp, r12d
        xor	r9d, edx
        xor	r10d, ebp
        rol	r9d, 7
        rol	r10d, 7
        mov	DWORD PTR [rsp+16], edx
        mov	DWORD PTR [rsp+20], ebp
        mov	edx, DWORD PTR [rsp+8]
        mov	ebp, DWORD PTR [rsp+12]
        add	r9d, r11d
        add	r8d, r8d
        xor	r13d, r9d
        xor	r14d, r8d
        rol	r13d, 16
        rol	r14d, 16
        add	edx, r13d
        add	ebp, r14d
        xor	r11d, edx
        xor	r8d, ebp
        rol	r11d, 12
        rol	r8d, 12
        add	r9d, r11d
        add	r8d, r8d
        xor	r13d, r9d
        xor	r14d, r8d
        rol	r13d, 8
        rol	r14d, 8
        add	edx, r13d
        add	ebp, r14d
        xor	r11d, edx
        xor	r8d, ebp
        rol	r11d, 7
        rol	r8d, 7
        dec	BYTE PTR [rsp]
        jnz	L_chacha_x64_block_crypt_start
        mov	DWORD PTR [rsp+8], edx
        mov	DWORD PTR [rsp+12], ebp
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
        mov	edx, DWORD PTR [rsp+8]
        mov	ebp, DWORD PTR [rsp+12]
L_chacha_x64_partial_crypt_start:
        add	eax, r8d
        add	ebx, r9d
        xor	r12d, eax
        xor	r13d, ebx
        rol	r12d, 16
        rol	r13d, 16
        add	edx, r12d
        add	ebp, r13d
        xor	r8d, edx
        xor	r9d, ebp
        rol	r8d, 12
        rol	r9d, 12
        add	eax, r8d
        add	ebx, r9d
        xor	r12d, eax
        xor	r13d, ebx
        rol	r12d, 8
        rol	r13d, 8
        add	edx, r12d
        add	ebp, r13d
        xor	r8d, edx
        xor	r9d, ebp
        rol	r8d, 7
        rol	r9d, 7
        mov	DWORD PTR [rsp+8], edx
        mov	DWORD PTR [rsp+12], ebp
        mov	edx, DWORD PTR [rsp+16]
        mov	ebp, DWORD PTR [rsp+20]
        add	r9d, r10d
        add	r8d, r11d
        xor	r14d, r9d
        xor	r15d, r8d
        rol	r14d, 16
        rol	r15d, 16
        add	edx, r14d
        add	ebp, r15d
        xor	r10d, edx
        xor	r11d, ebp
        rol	r10d, 12
        rol	r11d, 12
        add	r9d, r10d
        add	r8d, r11d
        xor	r14d, r9d
        xor	r15d, r8d
        rol	r14d, 8
        rol	r15d, 8
        add	edx, r14d
        add	ebp, r15d
        xor	r10d, edx
        xor	r11d, ebp
        rol	r10d, 7
        rol	r11d, 7
        add	eax, r9d
        add	ebx, r10d
        xor	r15d, eax
        xor	r12d, ebx
        rol	r15d, 16
        rol	r12d, 16
        add	edx, r15d
        add	ebp, r12d
        xor	r9d, edx
        xor	r10d, ebp
        rol	r9d, 12
        rol	r10d, 12
        add	eax, r9d
        add	ebx, r10d
        xor	r15d, eax
        xor	r12d, ebx
        rol	r15d, 8
        rol	r12d, 8
        add	edx, r15d
        add	ebp, r12d
        xor	r9d, edx
        xor	r10d, ebp
        rol	r9d, 7
        rol	r10d, 7
        mov	DWORD PTR [rsp+16], edx
        mov	DWORD PTR [rsp+20], ebp
        mov	edx, DWORD PTR [rsp+8]
        mov	ebp, DWORD PTR [rsp+12]
        add	r9d, r11d
        add	r8d, r8d
        xor	r13d, r9d
        xor	r14d, r8d
        rol	r13d, 16
        rol	r14d, 16
        add	edx, r13d
        add	ebp, r14d
        xor	r11d, edx
        xor	r8d, ebp
        rol	r11d, 12
        rol	r8d, 12
        add	r9d, r11d
        add	r8d, r8d
        xor	r13d, r9d
        xor	r14d, r8d
        rol	r13d, 8
        rol	r14d, 8
        add	edx, r13d
        add	ebp, r14d
        xor	r11d, edx
        xor	r8d, ebp
        rol	r11d, 7
        rol	r8d, 7
        dec	BYTE PTR [rsp]
        jnz	L_chacha_x64_partial_crypt_start
        mov	DWORD PTR [rsp+8], edx
        mov	DWORD PTR [rsp+12], ebp
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
_text ENDS
IFDEF HAVE_INTEL_AVX1
_DATA SEGMENT
ALIGN 16
L_chacha20_avx1_rotl8 QWORD 433757367256023043, 1012478749960636427
ptr_L_chacha20_avx1_rotl8 QWORD L_chacha20_avx1_rotl8
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_chacha20_avx1_rotl16 QWORD 361421592464458498, 940142975169071882
ptr_L_chacha20_avx1_rotl16 QWORD L_chacha20_avx1_rotl16
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_chacha20_avx1_add QWORD 4294967296, 12884901890
ptr_L_chacha20_avx1_add QWORD L_chacha20_avx1_add
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_chacha20_avx1_four QWORD 17179869188, 17179869188
ptr_L_chacha20_avx1_four QWORD L_chacha20_avx1_four
_DATA ENDS
_text SEGMENT READONLY PARA
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
        vzeroupper
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
_text ENDS
ENDIF
IFDEF HAVE_INTEL_AVX2
_DATA SEGMENT
ALIGN 16
L_chacha20_avx2_rotl8 QWORD 433757367256023043, 1012478749960636427,
    433757367256023043, 1012478749960636427
ptr_L_chacha20_avx2_rotl8 QWORD L_chacha20_avx2_rotl8
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_chacha20_avx2_rotl16 QWORD 361421592464458498, 940142975169071882,
    361421592464458498, 940142975169071882
ptr_L_chacha20_avx2_rotl16 QWORD L_chacha20_avx2_rotl16
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_chacha20_avx2_add QWORD 4294967296, 12884901890,
    21474836484, 30064771078
ptr_L_chacha20_avx2_add QWORD L_chacha20_avx2_add
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_chacha20_avx2_eight QWORD 34359738376, 34359738376,
    34359738376, 34359738376
ptr_L_chacha20_avx2_eight QWORD L_chacha20_avx2_eight
_DATA ENDS
_text SEGMENT READONLY PARA
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
        vmovdqa	YMMWORD PTR [r11], ymm0
        vmovdqa	YMMWORD PTR [r11+32], ymm1
        vmovdqa	YMMWORD PTR [r11+64], ymm2
        vmovdqa	YMMWORD PTR [r11+96], ymm3
        vmovdqa	YMMWORD PTR [r11+128], ymm4
        vmovdqa	YMMWORD PTR [r11+160], ymm5
        vmovdqa	YMMWORD PTR [r11+192], ymm6
        vmovdqa	YMMWORD PTR [r11+224], ymm7
        vmovdqa	YMMWORD PTR [r11+256], ymm8
        vmovdqa	YMMWORD PTR [r11+288], ymm9
        vmovdqa	YMMWORD PTR [r11+320], ymm10
        vmovdqa	YMMWORD PTR [r11+352], ymm11
        vmovdqa	YMMWORD PTR [r11+384], ymm12
        vmovdqa	YMMWORD PTR [r11+416], ymm13
        vmovdqa	YMMWORD PTR [r11+448], ymm14
        vmovdqa	YMMWORD PTR [r11+480], ymm15
L_chacha20_avx2_start256:
        mov	r10b, 10
        vmovdqa	YMMWORD PTR [r12+96], ymm11
L_chacha20_avx2_loop256:
        vpaddd	ymm0, ymm0, ymm4
        vpxor	ymm12, ymm12, ymm0
        vmovdqa	ymm11, YMMWORD PTR [r12+96]
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
        vmovdqa	YMMWORD PTR [r12+96], ymm11
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
        vmovdqa	ymm11, YMMWORD PTR [r12+96]
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
        vmovdqa	YMMWORD PTR [r12+96], ymm11
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
        vmovdqa	ymm11, YMMWORD PTR [r12+96]
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
        vmovdqa	YMMWORD PTR [r12+96], ymm11
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
        vmovdqa	ymm11, YMMWORD PTR [r12+96]
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
        vmovdqa	YMMWORD PTR [r12+96], ymm11
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
        vmovdqa	ymm11, YMMWORD PTR [r12+96]
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
        vmovdqa	YMMWORD PTR [r12], ymm8
        vmovdqa	YMMWORD PTR [r12+32], ymm9
        vmovdqa	YMMWORD PTR [r12+64], ymm10
        vmovdqa	YMMWORD PTR [r12+96], ymm11
        vmovdqa	YMMWORD PTR [r12+128], ymm12
        vmovdqa	YMMWORD PTR [r12+160], ymm13
        vmovdqa	YMMWORD PTR [r12+192], ymm14
        vmovdqa	YMMWORD PTR [r12+224], ymm15
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
        vmovdqa	ymm0, YMMWORD PTR [r12]
        vmovdqa	ymm1, YMMWORD PTR [r12+32]
        vmovdqa	ymm2, YMMWORD PTR [r12+64]
        vmovdqa	ymm3, YMMWORD PTR [r12+96]
        vmovdqa	ymm4, YMMWORD PTR [r12+128]
        vmovdqa	ymm5, YMMWORD PTR [r12+160]
        vmovdqa	ymm6, YMMWORD PTR [r12+192]
        vmovdqa	ymm7, YMMWORD PTR [r12+224]
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
        vmovdqa	ymm12, YMMWORD PTR [r11+384]
        add	rdx, 512
        add	r8, 512
        vpaddd	ymm12, ymm12, YMMWORD PTR [rdi]
        sub	r9d, 512
        vmovdqa	YMMWORD PTR [r11+384], ymm12
        cmp	r9d, 512
        jl	L_chacha20_avx2_done256
        vmovdqa	ymm0, YMMWORD PTR [r11]
        vmovdqa	ymm1, YMMWORD PTR [r11+32]
        vmovdqa	ymm2, YMMWORD PTR [r11+64]
        vmovdqa	ymm3, YMMWORD PTR [r11+96]
        vmovdqa	ymm4, YMMWORD PTR [r11+128]
        vmovdqa	ymm5, YMMWORD PTR [r11+160]
        vmovdqa	ymm6, YMMWORD PTR [r11+192]
        vmovdqa	ymm7, YMMWORD PTR [r11+224]
        vmovdqa	ymm8, YMMWORD PTR [r11+256]
        vmovdqa	ymm9, YMMWORD PTR [r11+288]
        vmovdqa	ymm10, YMMWORD PTR [r11+320]
        vmovdqa	ymm11, YMMWORD PTR [r11+352]
        vmovdqa	ymm12, YMMWORD PTR [r11+384]
        vmovdqa	ymm13, YMMWORD PTR [r11+416]
        vmovdqa	ymm14, YMMWORD PTR [r11+448]
        vmovdqa	ymm15, YMMWORD PTR [r11+480]
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
_text ENDS
ENDIF
END
