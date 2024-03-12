; /* poly1305_asm.asm */
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

IFDEF HAVE_INTEL_AVX1
_text SEGMENT READONLY PARA
poly1305_setkey_avx PROC
        push	r12
        push	r13
        mov	r12, 1152921487695413247
        mov	r13, 1152921487695413244
        mov	rax, QWORD PTR [rdx]
        mov	r8, QWORD PTR [rdx+8]
        mov	r9, QWORD PTR [rdx+16]
        mov	r10, QWORD PTR [rdx+24]
        and	rax, r12
        and	r8, r13
        mov	r12, rax
        mov	r13, r8
        xor	r11, r11
        mov	QWORD PTR [rcx], rax
        mov	QWORD PTR [rcx+8], r8
        mov	QWORD PTR [rcx+24], r11
        mov	QWORD PTR [rcx+32], r11
        mov	QWORD PTR [rcx+40], r11
        mov	QWORD PTR [rcx+48], r9
        mov	QWORD PTR [rcx+56], r10
        mov	QWORD PTR [rcx+352], r11
        mov	QWORD PTR [rcx+408], r11
        mov	QWORD PTR [rcx+360], rax
        mov	QWORD PTR [rcx+416], r8
        add	r12, rax
        add	r13, r8
        mov	QWORD PTR [rcx+368], r12
        mov	QWORD PTR [rcx+424], r13
        add	r12, rax
        add	r13, r8
        mov	QWORD PTR [rcx+376], r12
        mov	QWORD PTR [rcx+432], r13
        add	r12, rax
        add	r13, r8
        mov	QWORD PTR [rcx+384], r12
        mov	QWORD PTR [rcx+440], r13
        add	r12, rax
        add	r13, r8
        mov	QWORD PTR [rcx+392], r12
        mov	QWORD PTR [rcx+448], r13
        add	r12, rax
        add	r13, r8
        mov	QWORD PTR [rcx+400], r12
        mov	QWORD PTR [rcx+456], r13
        mov	QWORD PTR [rcx+608], r11
        mov	BYTE PTR [rcx+616], 1
        pop	r13
        pop	r12
        ret
poly1305_setkey_avx ENDP
_text ENDS
_text SEGMENT READONLY PARA
poly1305_block_avx PROC
        push	r15
        push	rbx
        push	r12
        push	r13
        push	r14
        mov	r15, QWORD PTR [rcx]
        mov	rbx, QWORD PTR [rcx+8]
        mov	r8, QWORD PTR [rcx+24]
        mov	r9, QWORD PTR [rcx+32]
        mov	r10, QWORD PTR [rcx+40]
        xor	r14, r14
        mov	r14b, BYTE PTR [rcx+616]
        ; h += m
        mov	r11, QWORD PTR [rdx]
        mov	r12, QWORD PTR [rdx+8]
        add	r8, r11
        adc	r9, r12
        mov	rax, rbx
        adc	r10, r14
        ; r[1] * h[0] => rdx, rax ==> t2, t1
        mul	r8
        mov	r12, rax
        mov	r13, rdx
        ; r[0] * h[1] => rdx, rax ++> t2, t1
        mov	rax, r15
        mul	r9
        add	r12, rax
        mov	rax, r15
        adc	r13, rdx
        ; r[0] * h[0] => rdx, rax ==> t4, t0
        mul	r8
        mov	r11, rax
        mov	r8, rdx
        ; r[1] * h[1] => rdx, rax =+> t3, t2
        mov	rax, rbx
        mul	r9
        ;   r[0] * h[2] +> t2
        add	r13, QWORD PTR [rcx+8*r10+352]
        mov	r14, rdx
        add	r12, r8
        adc	r13, rax
        ;   r[1] * h[2] +> t3
        adc	r14, QWORD PTR [rcx+8*r10+408]
        ; r * h in r14, r13, r12, r11
        ; h = (r * h) mod 2^130 - 5
        mov	r10, r13
        and	r13, -4
        and	r10, 3
        add	r11, r13
        mov	r8, r13
        adc	r12, r14
        adc	r10, 0
        shrd	r8, r14, 2
        shr	r14, 2
        add	r8, r11
        adc	r12, r14
        mov	r9, r12
        adc	r10, 0
        ; h in r10, r9, r8
        ; Store h to ctx
        mov	QWORD PTR [rcx+24], r8
        mov	QWORD PTR [rcx+32], r9
        mov	QWORD PTR [rcx+40], r10
        pop	r14
        pop	r13
        pop	r12
        pop	rbx
        pop	r15
        ret
poly1305_block_avx ENDP
_text ENDS
_text SEGMENT READONLY PARA
poly1305_blocks_avx PROC
        push	rdi
        push	rsi
        push	r15
        push	rbx
        push	r12
        push	r13
        push	r14
        mov	rdi, rcx
        mov	rsi, rdx
        mov	rcx, r8
        mov	r15, QWORD PTR [rdi]
        mov	rbx, QWORD PTR [rdi+8]
        mov	r8, QWORD PTR [rdi+24]
        mov	r9, QWORD PTR [rdi+32]
        mov	r10, QWORD PTR [rdi+40]
L_poly1305_avx_blocks_start:
        ; h += m
        mov	r11, QWORD PTR [rsi]
        mov	r12, QWORD PTR [rsi+8]
        add	r8, r11
        adc	r9, r12
        mov	rax, rbx
        adc	r10, 0
        ; r[1] * h[0] => rdx, rax ==> t2, t1
        mul	r8
        mov	r12, rax
        mov	r13, rdx
        ; r[0] * h[1] => rdx, rax ++> t2, t1
        mov	rax, r15
        mul	r9
        add	r12, rax
        mov	rax, r15
        adc	r13, rdx
        ; r[0] * h[0] => rdx, rax ==> t4, t0
        mul	r8
        mov	r11, rax
        mov	r8, rdx
        ; r[1] * h[1] => rdx, rax =+> t3, t2
        mov	rax, rbx
        mul	r9
        ;   r[0] * h[2] +> t2
        add	r13, QWORD PTR [rdi+8*r10+360]
        mov	r14, rdx
        add	r12, r8
        adc	r13, rax
        ;   r[1] * h[2] +> t3
        adc	r14, QWORD PTR [rdi+8*r10+416]
        ; r * h in r14, r13, r12, r11
        ; h = (r * h) mod 2^130 - 5
        mov	r10, r13
        and	r13, -4
        and	r10, 3
        add	r11, r13
        mov	r8, r13
        adc	r12, r14
        adc	r10, 0
        shrd	r8, r14, 2
        shr	r14, 2
        add	r8, r11
        adc	r12, r14
        mov	r9, r12
        adc	r10, 0
        ; h in r10, r9, r8
        ; Next block from message
        add	rsi, 16
        sub	rcx, 16
        jg	L_poly1305_avx_blocks_start
        ; Store h to ctx
        mov	QWORD PTR [rdi+24], r8
        mov	QWORD PTR [rdi+32], r9
        mov	QWORD PTR [rdi+40], r10
        pop	r14
        pop	r13
        pop	r12
        pop	rbx
        pop	r15
        pop	rsi
        pop	rdi
        ret
poly1305_blocks_avx ENDP
_text ENDS
_text SEGMENT READONLY PARA
poly1305_final_avx PROC
        push	rdi
        push	rbx
        push	r12
        mov	rdi, rcx
        mov	rbx, rdx
        mov	rax, QWORD PTR [rdi+608]
        test	rax, rax
        je	L_poly1305_avx_final_no_more
        mov	BYTE PTR [rdi+rax+480], 1
        jmp	L_poly1305_avx_final_cmp_rem
L_poly1305_avx_final_zero_rem:
        mov	BYTE PTR [rdi+rax+480], 0
L_poly1305_avx_final_cmp_rem:
        inc	al
        cmp	rax, 16
        jl	L_poly1305_avx_final_zero_rem
        mov	BYTE PTR [rdi+616], 0
        lea	rdx, QWORD PTR [rdi+480]
        call	poly1305_block_avx
L_poly1305_avx_final_no_more:
        mov	rax, QWORD PTR [rdi+24]
        mov	rdx, QWORD PTR [rdi+32]
        mov	rcx, QWORD PTR [rdi+40]
        mov	r11, QWORD PTR [rdi+48]
        mov	r12, QWORD PTR [rdi+56]
        ; h %= p
        ; h = (h + pad)
        ; mod 2^130 - 5
        mov	r8, rcx
        and	rcx, 3
        shr	r8, 2
        ;   Multiply by 5
        lea	r8, QWORD PTR [r8+4*r8+0]
        add	rax, r8
        adc	rdx, 0
        adc	rcx, 0
        ; Fixup when between (1 << 130) - 1 and (1 << 130) - 5
        mov	r8, rax
        mov	r9, rdx
        mov	r10, rcx
        add	r8, 5
        adc	r9, 0
        adc	r10, 0
        cmp	r10, 4
        cmove	rax, r8
        cmove	rdx, r9
        ; h += pad
        add	rax, r11
        adc	rdx, r12
        mov	QWORD PTR [rbx], rax
        mov	QWORD PTR [rbx+8], rdx
        ; Zero out r
        mov	QWORD PTR [rdi], 0
        mov	QWORD PTR [rdi+8], 0
        ; Zero out h
        mov	QWORD PTR [rdi+24], 0
        mov	QWORD PTR [rdi+32], 0
        mov	QWORD PTR [rdi+40], 0
        ; Zero out pad
        mov	QWORD PTR [rdi+48], 0
        mov	QWORD PTR [rdi+56], 0
        pop	r12
        pop	rbx
        pop	rdi
        ret
poly1305_final_avx ENDP
_text ENDS
ENDIF
IFDEF HAVE_INTEL_AVX2
_text SEGMENT READONLY PARA
poly1305_calc_powers_avx2 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        push	rbp
        mov	r8, QWORD PTR [rcx]
        mov	r9, QWORD PTR [rcx+8]
        xor	r10, r10
        ; Convert to 26 bits in 32
        mov	rax, r8
        mov	rdx, r8
        mov	rsi, r8
        mov	rbx, r9
        mov	rbp, r9
        shr	rdx, 26
        shrd	rsi, r9, 52
        shr	rbx, 14
        shrd	rbp, r10, 40
        and	rax, 67108863
        and	rdx, 67108863
        and	rsi, 67108863
        and	rbx, 67108863
        and	rbp, 67108863
        mov	DWORD PTR [rcx+224], eax
        mov	DWORD PTR [rcx+228], edx
        mov	DWORD PTR [rcx+232], esi
        mov	DWORD PTR [rcx+236], ebx
        mov	DWORD PTR [rcx+240], ebp
        mov	DWORD PTR [rcx+244], 0
        ; Square 128-bit
        mov	rax, r9
        mul	r8
        xor	r14, r14
        mov	r12, rax
        mov	r13, rdx
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        mov	rax, r8
        mul	rax
        mov	r11, rax
        mov	rdi, rdx
        mov	rax, r9
        mul	rax
        add	r12, rdi
        adc	r13, rax
        adc	r14, rdx
        ; Reduce 256-bit to 130-bit
        mov	rax, r13
        mov	rdx, r14
        and	rax, -4
        and	r13, 3
        add	r11, rax
        adc	r12, rdx
        adc	r13, 0
        shrd	rax, rdx, 2
        shr	rdx, 2
        add	r11, rax
        adc	r12, rdx
        adc	r13, 0
        mov	rax, r13
        shr	rax, 2
        lea	rax, QWORD PTR [rax+4*rax+0]
        and	r13, 3
        add	r11, rax
        adc	r12, 0
        adc	r13, 0
        ; Convert to 26 bits in 32
        mov	rax, r11
        mov	rdx, r11
        mov	rsi, r11
        mov	rbx, r12
        mov	rbp, r12
        shr	rdx, 26
        shrd	rsi, r12, 52
        shr	rbx, 14
        shrd	rbp, r13, 40
        and	rax, 67108863
        and	rdx, 67108863
        and	rsi, 67108863
        and	rbx, 67108863
        and	rbp, 67108863
        mov	DWORD PTR [rcx+256], eax
        mov	DWORD PTR [rcx+260], edx
        mov	DWORD PTR [rcx+264], esi
        mov	DWORD PTR [rcx+268], ebx
        mov	DWORD PTR [rcx+272], ebp
        mov	DWORD PTR [rcx+276], 0
        ; Multiply 128-bit by 130-bit
        ;   r1[0] * r2[0]
        mov	rax, r8
        mul	r11
        mov	r14, rax
        mov	r15, rdx
        ;   r1[0] * r2[1]
        mov	rax, r8
        mul	r12
        mov	rdi, 0
        add	r15, rax
        adc	rdi, rdx
        ;   r1[1] * r2[0]
        mov	rax, r9
        mul	r11
        mov	rsi, 0
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;   r1[0] * r2[2]
        mov	rax, r8
        mul	r13
        add	rdi, rax
        adc	rsi, rdx
        ;   r1[1] * r2[1]
        mov	rax, r9
        mul	r12
        mov	rbx, 0
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;   r1[1] * r2[2]
        mov	rax, r9
        mul	r13
        add	rsi, rax
        adc	rbx, rdx
        ; Reduce 260-bit to 130-bit
        mov	rax, rdi
        mov	rdx, rsi
        mov	rbx, rbx
        and	rax, -4
        and	rdi, 3
        add	r14, rax
        adc	r15, rdx
        adc	rdi, rbx
        shrd	rax, rdx, 2
        shrd	rdx, rbx, 2
        shr	rbx, 2
        add	r14, rax
        adc	r15, rdx
        adc	rdi, rbx
        mov	rax, rdi
        and	rdi, 3
        shr	rax, 2
        lea	rax, QWORD PTR [rax+4*rax+0]
        add	r14, rax
        adc	r15, 0
        adc	rdi, 0
        ; Convert to 26 bits in 32
        mov	rax, r14
        mov	rdx, r14
        mov	rsi, r14
        mov	rbx, r15
        mov	rbp, r15
        shr	rdx, 26
        shrd	rsi, r15, 52
        shr	rbx, 14
        shrd	rbp, rdi, 40
        and	rax, 67108863
        and	rdx, 67108863
        and	rsi, 67108863
        and	rbx, 67108863
        and	rbp, 67108863
        mov	DWORD PTR [rcx+288], eax
        mov	DWORD PTR [rcx+292], edx
        mov	DWORD PTR [rcx+296], esi
        mov	DWORD PTR [rcx+300], ebx
        mov	DWORD PTR [rcx+304], ebp
        mov	DWORD PTR [rcx+308], 0
        ; Square 130-bit
        mov	rax, r12
        mul	r11
        xor	r14, r14
        mov	r9, rax
        mov	r10, rdx
        add	r9, rax
        adc	r10, rdx
        adc	r14, 0
        mov	rax, r11
        mul	rax
        mov	r8, rax
        mov	rdi, rdx
        mov	rax, r12
        mul	rax
        add	r9, rdi
        adc	r10, rax
        adc	r14, rdx
        mov	rax, r13
        mul	rax
        mov	r15, rax
        mov	rax, r13
        mul	r11
        add	r10, rax
        adc	r14, rdx
        adc	r15, 0
        add	r10, rax
        adc	r14, rdx
        adc	r15, 0
        mov	rax, r13
        mul	r12
        add	r14, rax
        adc	r15, rdx
        add	r14, rax
        adc	r15, rdx
        ; Reduce 260-bit to 130-bit
        mov	rax, r10
        mov	rdx, r14
        mov	rdi, r15
        and	rax, -4
        and	r10, 3
        add	r8, rax
        adc	r9, rdx
        adc	r10, rdi
        shrd	rax, rdx, 2
        shrd	rdx, rdi, 2
        shr	rdi, 2
        add	r8, rax
        adc	r9, rdx
        adc	r10, rdi
        mov	rax, r10
        and	r10, 3
        shr	rax, 2
        lea	rax, QWORD PTR [rax+4*rax+0]
        add	r8, rax
        adc	r9, 0
        adc	r10, 0
        ; Convert to 26 bits in 32
        mov	rax, r8
        mov	rdx, r8
        mov	rsi, r8
        mov	rbx, r9
        mov	rbp, r9
        shr	rdx, 26
        shrd	rsi, r9, 52
        shr	rbx, 14
        shrd	rbp, r10, 40
        and	rax, 67108863
        and	rdx, 67108863
        and	rsi, 67108863
        and	rbx, 67108863
        and	rbp, 67108863
        mov	DWORD PTR [rcx+320], eax
        mov	DWORD PTR [rcx+324], edx
        mov	DWORD PTR [rcx+328], esi
        mov	DWORD PTR [rcx+332], ebx
        mov	DWORD PTR [rcx+336], ebp
        mov	DWORD PTR [rcx+340], 0
        pop	rbp
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
poly1305_calc_powers_avx2 ENDP
_text ENDS
_text SEGMENT READONLY PARA
poly1305_setkey_avx2 PROC
        call	poly1305_setkey_avx
        vpxor	ymm0, ymm0, ymm0
        vmovdqu	YMMWORD PTR [rcx+64], ymm0
        vmovdqu	YMMWORD PTR [rcx+96], ymm0
        vmovdqu	YMMWORD PTR [rcx+128], ymm0
        vmovdqu	YMMWORD PTR [rcx+160], ymm0
        vmovdqu	YMMWORD PTR [rcx+192], ymm0
        mov	QWORD PTR [rcx+608], 0
        mov	WORD PTR [rcx+616], 0
        ret
poly1305_setkey_avx2 ENDP
_text ENDS
_DATA SEGMENT
ALIGN 16
L_poly1305_avx2_blocks_mask QWORD 67108863, 67108863,
    67108863, 67108863
ptr_L_poly1305_avx2_blocks_mask QWORD L_poly1305_avx2_blocks_mask
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_poly1305_avx2_blocks_hibit QWORD 16777216, 16777216,
    16777216, 16777216
ptr_L_poly1305_avx2_blocks_hibit QWORD L_poly1305_avx2_blocks_hibit
_DATA ENDS
_text SEGMENT READONLY PARA
poly1305_blocks_avx2 PROC
        push	r12
        push	rdi
        push	rsi
        push	rbx
        push	r13
        push	r14
        mov	rdi, rcx
        mov	rsi, rdx
        mov	rdx, r8
        sub	rsp, 480
        vmovdqu	OWORD PTR [rsp+320], xmm6
        vmovdqu	OWORD PTR [rsp+336], xmm7
        vmovdqu	OWORD PTR [rsp+352], xmm8
        vmovdqu	OWORD PTR [rsp+368], xmm9
        vmovdqu	OWORD PTR [rsp+384], xmm10
        vmovdqu	OWORD PTR [rsp+400], xmm11
        vmovdqu	OWORD PTR [rsp+416], xmm12
        vmovdqu	OWORD PTR [rsp+432], xmm13
        vmovdqu	OWORD PTR [rsp+448], xmm14
        vmovdqu	OWORD PTR [rsp+464], xmm15
        mov	r13, QWORD PTR [ptr_L_poly1305_avx2_blocks_mask]
        mov	r14, QWORD PTR [ptr_L_poly1305_avx2_blocks_hibit]
        mov	rcx, rsp
        and	rcx, -32
        add	rcx, 32
        vpxor	ymm15, ymm15, ymm15
        mov	rbx, rcx
        lea	rax, QWORD PTR [rdi+64]
        add	rbx, 160
        cmp	WORD PTR [rdi+616], 0
        jne	L_poly1305_avx2_blocks_begin_h
        ; Load the message data
        vmovdqu	ymm0, YMMWORD PTR [rsi]
        vmovdqu	ymm1, YMMWORD PTR [rsi+32]
        vperm2i128	ymm2, ymm0, ymm1, 32
        vperm2i128	ymm0, ymm0, ymm1, 49
        vpunpckldq	ymm1, ymm2, ymm0
        vpunpckhdq	ymm3, ymm2, ymm0
        vpunpckldq	ymm0, ymm1, ymm15
        vpunpckhdq	ymm1, ymm1, ymm15
        vpunpckldq	ymm2, ymm3, ymm15
        vpunpckhdq	ymm3, ymm3, ymm15
        vmovdqu	ymm4, YMMWORD PTR [r14]
        vpsllq	ymm1, ymm1, 6
        vpsllq	ymm2, ymm2, 12
        vpsllq	ymm3, ymm3, 18
        vmovdqu	ymm14, YMMWORD PTR [r13]
        ; Reduce, in place, the message data
        vpsrlq	ymm10, ymm0, 26
        vpsrlq	ymm11, ymm3, 26
        vpand	ymm0, ymm0, ymm14
        vpand	ymm3, ymm3, ymm14
        vpaddq	ymm1, ymm10, ymm1
        vpaddq	ymm4, ymm11, ymm4
        vpsrlq	ymm10, ymm1, 26
        vpsrlq	ymm11, ymm4, 26
        vpand	ymm1, ymm1, ymm14
        vpand	ymm4, ymm4, ymm14
        vpaddq	ymm2, ymm10, ymm2
        vpslld	ymm12, ymm11, 2
        vpaddd	ymm12, ymm11, ymm12
        vpsrlq	ymm10, ymm2, 26
        vpaddq	ymm0, ymm12, ymm0
        vpsrlq	ymm11, ymm0, 26
        vpand	ymm2, ymm2, ymm14
        vpand	ymm0, ymm0, ymm14
        vpaddq	ymm3, ymm10, ymm3
        vpaddq	ymm1, ymm11, ymm1
        vpsrlq	ymm10, ymm3, 26
        vpand	ymm3, ymm3, ymm14
        vpaddq	ymm4, ymm10, ymm4
        add	rsi, 64
        sub	rdx, 64
        jz	L_poly1305_avx2_blocks_store
        jmp	L_poly1305_avx2_blocks_load_r4
L_poly1305_avx2_blocks_begin_h:
        ; Load the H values.
        vmovdqu	ymm0, YMMWORD PTR [rax]
        vmovdqu	ymm1, YMMWORD PTR [rax+32]
        vmovdqu	ymm2, YMMWORD PTR [rax+64]
        vmovdqu	ymm3, YMMWORD PTR [rax+96]
        vmovdqu	ymm4, YMMWORD PTR [rax+128]
        ; Check if there is a power of r to load - otherwise use r^4.
        cmp	BYTE PTR [rdi+616], 0
        je	L_poly1305_avx2_blocks_load_r4
        ; Load the 4 powers of r - r^4, r^3, r^2, r^1.
        vmovdqu	ymm8, YMMWORD PTR [rdi+224]
        vmovdqu	ymm7, YMMWORD PTR [rdi+256]
        vmovdqu	ymm6, YMMWORD PTR [rdi+288]
        vmovdqu	ymm5, YMMWORD PTR [rdi+320]
        vpermq	ymm5, ymm5, 216
        vpermq	ymm6, ymm6, 216
        vpermq	ymm7, ymm7, 216
        vpermq	ymm8, ymm8, 216
        vpunpcklqdq	ymm10, ymm5, ymm6
        vpunpckhqdq	ymm11, ymm5, ymm6
        vpunpcklqdq	ymm12, ymm7, ymm8
        vpunpckhqdq	ymm13, ymm7, ymm8
        vperm2i128	ymm5, ymm10, ymm12, 32
        vperm2i128	ymm7, ymm10, ymm12, 49
        vperm2i128	ymm9, ymm11, ymm13, 32
        vpsrlq	ymm6, ymm5, 32
        vpsrlq	ymm8, ymm7, 32
        jmp	L_poly1305_avx2_blocks_mul_5
L_poly1305_avx2_blocks_load_r4:
        ; Load r^4 into all four positions.
        vmovdqu	ymm13, YMMWORD PTR [rdi+320]
        vpermq	ymm5, ymm13, 0
        vpsrlq	ymm14, ymm13, 32
        vpermq	ymm7, ymm13, 85
        vpermq	ymm9, ymm13, 170
        vpermq	ymm6, ymm14, 0
        vpermq	ymm8, ymm14, 85
L_poly1305_avx2_blocks_mul_5:
        ; Multiply top 4 26-bit values of all four H by 5
        vpslld	ymm10, ymm6, 2
        vpslld	ymm11, ymm7, 2
        vpslld	ymm12, ymm8, 2
        vpslld	ymm13, ymm9, 2
        vpaddq	ymm10, ymm6, ymm10
        vpaddq	ymm11, ymm7, ymm11
        vpaddq	ymm12, ymm8, ymm12
        vpaddq	ymm13, ymm9, ymm13
        ; Store powers of r and multiple of 5 for use in multiply.
        vmovdqa	YMMWORD PTR [rbx], ymm10
        vmovdqa	YMMWORD PTR [rbx+32], ymm11
        vmovdqa	YMMWORD PTR [rbx+64], ymm12
        vmovdqa	YMMWORD PTR [rbx+96], ymm13
        vmovdqa	YMMWORD PTR [rcx], ymm5
        vmovdqa	YMMWORD PTR [rcx+32], ymm6
        vmovdqa	YMMWORD PTR [rcx+64], ymm7
        vmovdqa	YMMWORD PTR [rcx+96], ymm8
        vmovdqa	YMMWORD PTR [rcx+128], ymm9
        vmovdqu	ymm14, YMMWORD PTR [r13]
        ; If not finished then loop over data
        cmp	BYTE PTR [rdi+616], 1
        jne	L_poly1305_avx2_blocks_start
        ; Do last multiply, reduce, add the four H together and move to
        ; 32-bit registers
        vpmuludq	ymm5, ymm4, [rbx]
        vpmuludq	ymm10, ymm3, [rbx+32]
        vpmuludq	ymm6, ymm4, [rbx+32]
        vpmuludq	ymm11, ymm3, [rbx+64]
        vpmuludq	ymm7, ymm4, [rbx+64]
        vpaddq	ymm5, ymm10, ymm5
        vpmuludq	ymm12, ymm2, [rbx+64]
        vpmuludq	ymm8, ymm4, [rbx+96]
        vpaddq	ymm6, ymm11, ymm6
        vpmuludq	ymm13, ymm1, [rbx+96]
        vpmuludq	ymm10, ymm2, [rbx+96]
        vpaddq	ymm5, ymm12, ymm5
        vpmuludq	ymm11, ymm3, [rbx+96]
        vpmuludq	ymm12, ymm3, [rcx]
        vpaddq	ymm5, ymm13, ymm5
        vpmuludq	ymm9, ymm4, [rcx]
        vpaddq	ymm6, ymm10, ymm6
        vpmuludq	ymm13, ymm0, [rcx]
        vpaddq	ymm7, ymm11, ymm7
        vpmuludq	ymm10, ymm1, [rcx]
        vpaddq	ymm8, ymm12, ymm8
        vpmuludq	ymm11, ymm2, [rcx]
        vpmuludq	ymm12, ymm2, [rcx+32]
        vpaddq	ymm5, ymm13, ymm5
        vpmuludq	ymm13, ymm3, [rcx+32]
        vpaddq	ymm6, ymm10, ymm6
        vpmuludq	ymm10, ymm0, [rcx+32]
        vpaddq	ymm7, ymm11, ymm7
        vpmuludq	ymm11, ymm1, [rcx+32]
        vpaddq	ymm8, ymm12, ymm8
        vpmuludq	ymm12, ymm1, [rcx+64]
        vpaddq	ymm9, ymm13, ymm9
        vpmuludq	ymm13, ymm2, [rcx+64]
        vpaddq	ymm6, ymm10, ymm6
        vpmuludq	ymm10, ymm0, [rcx+64]
        vpaddq	ymm7, ymm11, ymm7
        vpmuludq	ymm11, ymm0, [rcx+96]
        vpaddq	ymm8, ymm12, ymm8
        vpmuludq	ymm12, ymm1, [rcx+96]
        vpaddq	ymm9, ymm13, ymm9
        vpaddq	ymm7, ymm10, ymm7
        vpmuludq	ymm13, ymm0, [rcx+128]
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
        vpsrldq	ymm5, ymm0, 8
        vpsrldq	ymm6, ymm1, 8
        vpsrldq	ymm7, ymm2, 8
        vpsrldq	ymm8, ymm3, 8
        vpsrldq	ymm9, ymm4, 8
        vpaddq	ymm0, ymm5, ymm0
        vpaddq	ymm1, ymm6, ymm1
        vpaddq	ymm2, ymm7, ymm2
        vpaddq	ymm3, ymm8, ymm3
        vpaddq	ymm4, ymm9, ymm4
        vpermq	ymm5, ymm0, 2
        vpermq	ymm6, ymm1, 2
        vpermq	ymm7, ymm2, 2
        vpermq	ymm8, ymm3, 2
        vpermq	ymm9, ymm4, 2
        vpaddq	ymm0, ymm5, ymm0
        vpaddq	ymm1, ymm6, ymm1
        vpaddq	ymm2, ymm7, ymm2
        vpaddq	ymm3, ymm8, ymm3
        vpaddq	ymm4, ymm9, ymm4
        vmovd	r8d, xmm0
        vmovd	r9d, xmm1
        vmovd	r10d, xmm2
        vmovd	r11d, xmm3
        vmovd	r12d, xmm4
        jmp	L_poly1305_avx2_blocks_end_calc
L_poly1305_avx2_blocks_start:
        vmovdqu	ymm5, YMMWORD PTR [rsi]
        vmovdqu	ymm6, YMMWORD PTR [rsi+32]
        vperm2i128	ymm7, ymm5, ymm6, 32
        vperm2i128	ymm5, ymm5, ymm6, 49
        vpunpckldq	ymm6, ymm7, ymm5
        vpunpckhdq	ymm8, ymm7, ymm5
        vpunpckldq	ymm5, ymm6, ymm15
        vpunpckhdq	ymm6, ymm6, ymm15
        vpunpckldq	ymm7, ymm8, ymm15
        vpunpckhdq	ymm8, ymm8, ymm15
        vmovdqu	ymm9, YMMWORD PTR [r14]
        vpsllq	ymm6, ymm6, 6
        vpsllq	ymm7, ymm7, 12
        vpsllq	ymm8, ymm8, 18
        vpmuludq	ymm10, ymm4, [rbx]
        vpaddq	ymm5, ymm10, ymm5
        vpmuludq	ymm10, ymm3, [rbx+32]
        vpmuludq	ymm11, ymm4, [rbx+32]
        vpaddq	ymm6, ymm11, ymm6
        vpmuludq	ymm11, ymm3, [rbx+64]
        vpmuludq	ymm12, ymm4, [rbx+64]
        vpaddq	ymm7, ymm12, ymm7
        vpaddq	ymm5, ymm10, ymm5
        vpmuludq	ymm12, ymm2, [rbx+64]
        vpmuludq	ymm13, ymm4, [rbx+96]
        vpaddq	ymm8, ymm13, ymm8
        vpaddq	ymm6, ymm11, ymm6
        vpmuludq	ymm13, ymm1, [rbx+96]
        vpmuludq	ymm10, ymm2, [rbx+96]
        vpaddq	ymm5, ymm12, ymm5
        vpmuludq	ymm11, ymm3, [rbx+96]
        vpmuludq	ymm12, ymm3, [rcx]
        vpaddq	ymm5, ymm13, ymm5
        vpmuludq	ymm13, ymm4, [rcx]
        vpaddq	ymm9, ymm13, ymm9
        vpaddq	ymm6, ymm10, ymm6
        vpmuludq	ymm13, ymm0, [rcx]
        vpaddq	ymm7, ymm11, ymm7
        vpmuludq	ymm10, ymm1, [rcx]
        vpaddq	ymm8, ymm12, ymm8
        vpmuludq	ymm11, ymm2, [rcx]
        vpmuludq	ymm12, ymm2, [rcx+32]
        vpaddq	ymm5, ymm13, ymm5
        vpmuludq	ymm13, ymm3, [rcx+32]
        vpaddq	ymm6, ymm10, ymm6
        vpmuludq	ymm10, ymm0, [rcx+32]
        vpaddq	ymm7, ymm11, ymm7
        vpmuludq	ymm11, ymm1, [rcx+32]
        vpaddq	ymm8, ymm12, ymm8
        vpmuludq	ymm12, ymm1, [rcx+64]
        vpaddq	ymm9, ymm13, ymm9
        vpmuludq	ymm13, ymm2, [rcx+64]
        vpaddq	ymm6, ymm10, ymm6
        vpmuludq	ymm10, ymm0, [rcx+64]
        vpaddq	ymm7, ymm11, ymm7
        vpmuludq	ymm11, ymm0, [rcx+96]
        vpaddq	ymm8, ymm12, ymm8
        vpmuludq	ymm12, ymm1, [rcx+96]
        vpaddq	ymm9, ymm13, ymm9
        vpaddq	ymm7, ymm10, ymm7
        vpmuludq	ymm13, ymm0, [rcx+128]
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
        add	rsi, 64
        sub	rdx, 64
        jnz	L_poly1305_avx2_blocks_start
L_poly1305_avx2_blocks_store:
        ; Store four H values - state
        vmovdqu	YMMWORD PTR [rax], ymm0
        vmovdqu	YMMWORD PTR [rax+32], ymm1
        vmovdqu	YMMWORD PTR [rax+64], ymm2
        vmovdqu	YMMWORD PTR [rax+96], ymm3
        vmovdqu	YMMWORD PTR [rax+128], ymm4
L_poly1305_avx2_blocks_end_calc:
        cmp	BYTE PTR [rdi+616], 0
        je	L_poly1305_avx2_blocks_complete
        mov	rax, r8
        mov	rdx, r10
        mov	rcx, r12
        shr	rdx, 12
        shr	rcx, 24
        shl	r9, 26
        shl	r10, 52
        shl	r11, 14
        shl	r12, 40
        add	rax, r9
        adc	rax, r10
        adc	rdx, r11
        adc	rdx, r12
        adc	rcx, 0
        mov	r8, rcx
        and	rcx, 3
        shr	r8, 2
        lea	r8, QWORD PTR [r8+4*r8+0]
        add	rax, r8
        adc	rdx, 0
        adc	rcx, 0
        mov	QWORD PTR [rdi+24], rax
        mov	QWORD PTR [rdi+32], rdx
        mov	QWORD PTR [rdi+40], rcx
L_poly1305_avx2_blocks_complete:
        mov	BYTE PTR [rdi+617], 1
        vzeroupper
        vmovdqu	xmm6, OWORD PTR [rsp+320]
        vmovdqu	xmm7, OWORD PTR [rsp+336]
        vmovdqu	xmm8, OWORD PTR [rsp+352]
        vmovdqu	xmm9, OWORD PTR [rsp+368]
        vmovdqu	xmm10, OWORD PTR [rsp+384]
        vmovdqu	xmm11, OWORD PTR [rsp+400]
        vmovdqu	xmm12, OWORD PTR [rsp+416]
        vmovdqu	xmm13, OWORD PTR [rsp+432]
        vmovdqu	xmm14, OWORD PTR [rsp+448]
        vmovdqu	xmm15, OWORD PTR [rsp+464]
        add	rsp, 480
        pop	r14
        pop	r13
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r12
        ret
poly1305_blocks_avx2 ENDP
_text ENDS
_text SEGMENT READONLY PARA
poly1305_final_avx2 PROC
        push	rdi
        push	rsi
        mov	rdi, rcx
        mov	rsi, rdx
        mov	BYTE PTR [rdi+616], 1
        mov	cl, BYTE PTR [rdi+617]
        cmp	cl, 0
        je	L_poly1305_avx2_final_done_blocks_X4
        push	rsi
        mov	r8, 64
        xor	rdx, rdx
        mov	rcx, rdi
        call	poly1305_blocks_avx2
        pop	rsi
L_poly1305_avx2_final_done_blocks_X4:
        mov	rax, QWORD PTR [rdi+608]
        mov	rcx, rax
        and	rcx, -16
        cmp	cl, 0
        je	L_poly1305_avx2_final_done_blocks
        push	rcx
        push	rax
        push	rsi
        mov	r8, rcx
        lea	rdx, QWORD PTR [rdi+480]
        mov	rcx, rdi
        call	poly1305_blocks_avx
        pop	rsi
        pop	rax
        pop	rcx
L_poly1305_avx2_final_done_blocks:
        sub	QWORD PTR [rdi+608], rcx
        xor	rdx, rdx
        jmp	L_poly1305_avx2_final_cmp_copy
L_poly1305_avx2_final_start_copy:
        mov	r8b, BYTE PTR [rdi+rcx+480]
        mov	BYTE PTR [rdi+rdx+480], r8b
        inc	cl
        inc	dl
L_poly1305_avx2_final_cmp_copy:
        cmp	al, cl
        jne	L_poly1305_avx2_final_start_copy
        mov	rcx, rdi
        mov	rdx, rsi
        call	poly1305_final_avx
        vpxor	ymm0, ymm0, ymm0
        vmovdqu	YMMWORD PTR [rdi+64], ymm0
        vmovdqu	YMMWORD PTR [rdi+96], ymm0
        vmovdqu	YMMWORD PTR [rdi+128], ymm0
        vmovdqu	YMMWORD PTR [rdi+160], ymm0
        vmovdqu	YMMWORD PTR [rdi+192], ymm0
        vmovdqu	YMMWORD PTR [rdi+224], ymm0
        vmovdqu	YMMWORD PTR [rdi+256], ymm0
        vmovdqu	YMMWORD PTR [rdi+288], ymm0
        vmovdqu	YMMWORD PTR [rdi+320], ymm0
        mov	QWORD PTR [rdi+608], 0
        mov	WORD PTR [rdi+616], 0
        vzeroupper
        pop	rsi
        pop	rdi
        ret
poly1305_final_avx2 ENDP
_text ENDS
ENDIF
END
