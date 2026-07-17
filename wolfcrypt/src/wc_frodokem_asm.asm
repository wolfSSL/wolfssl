; /* wc_frodokem_asm.asm */
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

IFDEF WOLFSSL_HAVE_FRODOKEM
IFDEF HAVE_INTEL_AVX2
_TEXT SEGMENT READONLY PARA
frodokem_sa_accum_avx2 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        mov	rax, QWORD PTR [rsp+72]
        movsxd	r9, r9d
        shl	r9, 1
        add	rdx, r9
        movsxd	r10, eax
        shl	r10, 1
        mov	r11, r8
        add	r11, r10
        mov	r12, r11
        add	r12, r10
        mov	r13, r12
        add	r13, r10
        mov	r15, 8
L_frodokem_sa_accum_avx2_i:
        vpbroadcastw	ymm0, WORD PTR [rdx]
        vpbroadcastw	ymm1, WORD PTR [rdx+2]
        vpbroadcastw	ymm2, WORD PTR [rdx+4]
        vpbroadcastw	ymm3, WORD PTR [rdx+6]
        xor	r14, r14
L_frodokem_sa_accum_avx2_k:
        vmovdqu	ymm4, YMMWORD PTR [rcx+r14]
        vpmullw	ymm5, ymm0, [r8+r14]
        vpaddw	ymm4, ymm4, ymm5
        vpmullw	ymm5, ymm1, [r11+r14]
        vpaddw	ymm4, ymm4, ymm5
        vpmullw	ymm5, ymm2, [r12+r14]
        vpaddw	ymm4, ymm4, ymm5
        vpmullw	ymm5, ymm3, [r13+r14]
        vpaddw	ymm4, ymm4, ymm5
        vmovdqu	YMMWORD PTR [rcx+r14], ymm4
        add	r14, 32
        cmp	r14, r10
        jl	L_frodokem_sa_accum_avx2_k
        add	rcx, r10
        add	rdx, r10
        sub	r15, 1
        jnz	L_frodokem_sa_accum_avx2_i
        vzeroupper
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
frodokem_sa_accum_avx2 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
frodokem_as_accum_avx2 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        push	rbp
        mov	rax, QWORD PTR [rsp+104]
        sub	rsp, 112
        vmovdqu	OWORD PTR [rsp], xmm6
        vmovdqu	OWORD PTR [rsp+16], xmm7
        vmovdqu	OWORD PTR [rsp+32], xmm8
        vmovdqu	OWORD PTR [rsp+48], xmm9
        vmovdqu	OWORD PTR [rsp+64], xmm10
        vmovdqu	OWORD PTR [rsp+80], xmm11
        vmovdqu	OWORD PTR [rsp+96], xmm12
        movsxd	r9, r9d
        shl	r9, 4
        add	rcx, r9
        movsxd	r10, eax
        shl	r10, 1
        mov	r11, rdx
        add	r11, r10
        mov	r12, r11
        add	r12, r10
        mov	r13, r12
        add	r13, r10
        mov	r14, r13
        add	r14, r10
        mov	r15, r14
        add	r15, r10
        mov	rdi, r15
        add	rdi, r10
        mov	rsi, rdi
        add	rsi, r10
        mov	rbp, 4
        vpcmpeqd	xmm12, xmm12, xmm12
        vpsrld	xmm12, xmm12, 16
L_frodokem_as_accum_avx2_r:
        vpxor	ymm0, ymm0, ymm0
        vpxor	ymm1, ymm1, ymm1
        vpxor	ymm2, ymm2, ymm2
        vpxor	ymm3, ymm3, ymm3
        vpxor	ymm4, ymm4, ymm4
        vpxor	ymm5, ymm5, ymm5
        vpxor	ymm6, ymm6, ymm6
        vpxor	ymm7, ymm7, ymm7
        xor	rbx, rbx
L_frodokem_as_accum_avx2_j:
        vmovdqu	ymm8, YMMWORD PTR [r8+rbx]
        vpmaddwd	ymm10, ymm8, [rdx+rbx]
        vpaddd	ymm0, ymm0, ymm10
        vpmaddwd	ymm10, ymm8, [r11+rbx]
        vpaddd	ymm1, ymm1, ymm10
        vpmaddwd	ymm10, ymm8, [r12+rbx]
        vpaddd	ymm2, ymm2, ymm10
        vpmaddwd	ymm10, ymm8, [r13+rbx]
        vpaddd	ymm3, ymm3, ymm10
        vpmaddwd	ymm10, ymm8, [r14+rbx]
        vpaddd	ymm4, ymm4, ymm10
        vpmaddwd	ymm10, ymm8, [r15+rbx]
        vpaddd	ymm5, ymm5, ymm10
        vpmaddwd	ymm10, ymm8, [rdi+rbx]
        vpaddd	ymm6, ymm6, ymm10
        vpmaddwd	ymm10, ymm8, [rsi+rbx]
        vpaddd	ymm7, ymm7, ymm10
        add	rbx, 32
        cmp	rbx, r10
        jl	L_frodokem_as_accum_avx2_j
        vextracti128	xmm8, ymm0, 1
        vpaddd	xmm0, xmm0, xmm8
        vextracti128	xmm8, ymm1, 1
        vpaddd	xmm1, xmm1, xmm8
        vextracti128	xmm8, ymm2, 1
        vpaddd	xmm2, xmm2, xmm8
        vextracti128	xmm8, ymm3, 1
        vpaddd	xmm3, xmm3, xmm8
        vextracti128	xmm8, ymm4, 1
        vpaddd	xmm4, xmm4, xmm8
        vextracti128	xmm8, ymm5, 1
        vpaddd	xmm5, xmm5, xmm8
        vextracti128	xmm8, ymm6, 1
        vpaddd	xmm6, xmm6, xmm8
        vextracti128	xmm8, ymm7, 1
        vpaddd	xmm7, xmm7, xmm8
        vphaddd	xmm10, xmm0, xmm1
        vphaddd	xmm11, xmm2, xmm3
        vphaddd	xmm9, xmm10, xmm11
        vphaddd	xmm10, xmm4, xmm5
        vphaddd	xmm11, xmm6, xmm7
        vphaddd	xmm10, xmm10, xmm11
        vpand	xmm9, xmm9, xmm12
        vpand	xmm10, xmm10, xmm12
        vpackusdw	xmm9, xmm9, xmm10
        vpaddw	xmm9, xmm9, [rcx]
        vmovdqu	OWORD PTR [rcx], xmm9
        add	r8, r10
        add	rcx, 16
        sub	rbp, 1
        jnz	L_frodokem_as_accum_avx2_r
        vzeroupper
        vmovdqu	xmm6, OWORD PTR [rsp]
        vmovdqu	xmm7, OWORD PTR [rsp+16]
        vmovdqu	xmm8, OWORD PTR [rsp+32]
        vmovdqu	xmm9, OWORD PTR [rsp+48]
        vmovdqu	xmm10, OWORD PTR [rsp+64]
        vmovdqu	xmm11, OWORD PTR [rsp+80]
        vmovdqu	xmm12, OWORD PTR [rsp+96]
        add	rsp, 112
        pop	rbp
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
frodokem_as_accum_avx2 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
frodokem_mul_bs_avx2 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        push	rbp
        mov	rax, QWORD PTR [rsp+104]
        sub	rsp, 112
        vmovdqu	OWORD PTR [rsp], xmm6
        vmovdqu	OWORD PTR [rsp+16], xmm7
        vmovdqu	OWORD PTR [rsp+32], xmm8
        vmovdqu	OWORD PTR [rsp+48], xmm9
        vmovdqu	OWORD PTR [rsp+64], xmm10
        vmovdqu	OWORD PTR [rsp+80], xmm11
        vmovdqu	OWORD PTR [rsp+96], xmm12
        movsxd	r10, r9d
        shl	r10, 1
        mov	r11, r8
        add	r11, r10
        mov	r12, r11
        add	r12, r10
        mov	r13, r12
        add	r13, r10
        mov	r14, r13
        add	r14, r10
        mov	r15, r14
        add	r15, r10
        mov	rdi, r15
        add	rdi, r10
        mov	rsi, rdi
        add	rsi, r10
        mov	rbp, 8
        vmovd	xmm12, rax
        vpbroadcastd	xmm12, xmm12
L_frodokem_mul_bs_avx2_r:
        vpxor	ymm0, ymm0, ymm0
        vpxor	ymm1, ymm1, ymm1
        vpxor	ymm2, ymm2, ymm2
        vpxor	ymm3, ymm3, ymm3
        vpxor	ymm4, ymm4, ymm4
        vpxor	ymm5, ymm5, ymm5
        vpxor	ymm6, ymm6, ymm6
        vpxor	ymm7, ymm7, ymm7
        xor	rbx, rbx
L_frodokem_mul_bs_avx2_j:
        vmovdqu	ymm8, YMMWORD PTR [rdx+rbx]
        vpmaddwd	ymm10, ymm8, [r8+rbx]
        vpaddd	ymm0, ymm0, ymm10
        vpmaddwd	ymm10, ymm8, [r11+rbx]
        vpaddd	ymm1, ymm1, ymm10
        vpmaddwd	ymm10, ymm8, [r12+rbx]
        vpaddd	ymm2, ymm2, ymm10
        vpmaddwd	ymm10, ymm8, [r13+rbx]
        vpaddd	ymm3, ymm3, ymm10
        vpmaddwd	ymm10, ymm8, [r14+rbx]
        vpaddd	ymm4, ymm4, ymm10
        vpmaddwd	ymm10, ymm8, [r15+rbx]
        vpaddd	ymm5, ymm5, ymm10
        vpmaddwd	ymm10, ymm8, [rdi+rbx]
        vpaddd	ymm6, ymm6, ymm10
        vpmaddwd	ymm10, ymm8, [rsi+rbx]
        vpaddd	ymm7, ymm7, ymm10
        add	rbx, 32
        cmp	rbx, r10
        jl	L_frodokem_mul_bs_avx2_j
        vextracti128	xmm8, ymm0, 1
        vpaddd	xmm0, xmm0, xmm8
        vextracti128	xmm8, ymm1, 1
        vpaddd	xmm1, xmm1, xmm8
        vextracti128	xmm8, ymm2, 1
        vpaddd	xmm2, xmm2, xmm8
        vextracti128	xmm8, ymm3, 1
        vpaddd	xmm3, xmm3, xmm8
        vextracti128	xmm8, ymm4, 1
        vpaddd	xmm4, xmm4, xmm8
        vextracti128	xmm8, ymm5, 1
        vpaddd	xmm5, xmm5, xmm8
        vextracti128	xmm8, ymm6, 1
        vpaddd	xmm6, xmm6, xmm8
        vextracti128	xmm8, ymm7, 1
        vpaddd	xmm7, xmm7, xmm8
        vphaddd	xmm10, xmm0, xmm1
        vphaddd	xmm11, xmm2, xmm3
        vphaddd	xmm9, xmm10, xmm11
        vphaddd	xmm10, xmm4, xmm5
        vphaddd	xmm11, xmm6, xmm7
        vphaddd	xmm10, xmm10, xmm11
        vpand	xmm9, xmm9, xmm12
        vpand	xmm10, xmm10, xmm12
        vpackusdw	xmm9, xmm9, xmm10
        vmovdqu	OWORD PTR [rcx], xmm9
        add	rdx, r10
        add	rcx, 16
        sub	rbp, 1
        jnz	L_frodokem_mul_bs_avx2_r
        vzeroupper
        vmovdqu	xmm6, OWORD PTR [rsp]
        vmovdqu	xmm7, OWORD PTR [rsp+16]
        vmovdqu	xmm8, OWORD PTR [rsp+32]
        vmovdqu	xmm9, OWORD PTR [rsp+48]
        vmovdqu	xmm10, OWORD PTR [rsp+64]
        vmovdqu	xmm11, OWORD PTR [rsp+80]
        vmovdqu	xmm12, OWORD PTR [rsp+96]
        add	rsp, 112
        pop	rbp
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
frodokem_mul_bs_avx2 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
frodokem_mul_add_sb_plus_e_avx2 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        mov	rax, QWORD PTR [rsp+96]
        sub	rsp, 32
        vmovdqu	OWORD PTR [rsp], xmm6
        vmovdqu	OWORD PTR [rsp+16], xmm7
        movsxd	r10, r9d
        shl	r10, 1
        mov	r11, r8
        add	r11, r10
        mov	r12, r11
        add	r12, r10
        mov	r13, r12
        add	r13, r10
        mov	r14, r13
        add	r14, r10
        mov	r15, r14
        add	r15, r10
        mov	rdi, r15
        add	rdi, r10
        mov	rsi, rdi
        add	rsi, r10
        vmovd	xmm7, rax
        vpbroadcastw	ymm7, xmm7
        vmovdqu	ymm0, YMMWORD PTR [rcx]
        vmovdqu	ymm1, YMMWORD PTR [rcx+32]
        vmovdqu	ymm2, YMMWORD PTR [rcx+64]
        vmovdqu	ymm3, YMMWORD PTR [rcx+96]
        xor	rbx, rbx
L_frodokem_mul_add_sb_plus_e_avx2_j:
        vbroadcasti128	ymm4, OWORD PTR [rdx]
        vpbroadcastw	ymm5, WORD PTR [r8+rbx]
        vpbroadcastw	ymm6, WORD PTR [r11+rbx]
        vinserti128	ymm5, ymm5, xmm6, 1
        vpmullw	ymm6, ymm5, ymm4
        vpaddw	ymm0, ymm0, ymm6
        vpbroadcastw	ymm5, WORD PTR [r12+rbx]
        vpbroadcastw	ymm6, WORD PTR [r13+rbx]
        vinserti128	ymm5, ymm5, xmm6, 1
        vpmullw	ymm6, ymm5, ymm4
        vpaddw	ymm1, ymm1, ymm6
        vpbroadcastw	ymm5, WORD PTR [r14+rbx]
        vpbroadcastw	ymm6, WORD PTR [r15+rbx]
        vinserti128	ymm5, ymm5, xmm6, 1
        vpmullw	ymm6, ymm5, ymm4
        vpaddw	ymm2, ymm2, ymm6
        vpbroadcastw	ymm5, WORD PTR [rdi+rbx]
        vpbroadcastw	ymm6, WORD PTR [rsi+rbx]
        vinserti128	ymm5, ymm5, xmm6, 1
        vpmullw	ymm6, ymm5, ymm4
        vpaddw	ymm3, ymm3, ymm6
        add	rdx, 16
        add	rbx, 2
        cmp	rbx, r10
        jl	L_frodokem_mul_add_sb_plus_e_avx2_j
        vpand	ymm0, ymm0, ymm7
        vmovdqu	YMMWORD PTR [rcx], ymm0
        vpand	ymm1, ymm1, ymm7
        vmovdqu	YMMWORD PTR [rcx+32], ymm1
        vpand	ymm2, ymm2, ymm7
        vmovdqu	YMMWORD PTR [rcx+64], ymm2
        vpand	ymm3, ymm3, ymm7
        vmovdqu	YMMWORD PTR [rcx+96], ymm3
        vzeroupper
        vmovdqu	xmm6, OWORD PTR [rsp]
        vmovdqu	xmm7, OWORD PTR [rsp+16]
        add	rsp, 32
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
frodokem_mul_add_sb_plus_e_avx2 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
frodokem_add_avx2 PROC
        vmovd	xmm0, r8
        vpbroadcastw	ymm0, xmm0
        vmovdqu	ymm1, YMMWORD PTR [rcx]
        vpaddw	ymm1, ymm1, [rdx]
        vpand	ymm1, ymm1, ymm0
        vmovdqu	YMMWORD PTR [rcx], ymm1
        vmovdqu	ymm2, YMMWORD PTR [rcx+32]
        vpaddw	ymm2, ymm2, [rdx+32]
        vpand	ymm2, ymm2, ymm0
        vmovdqu	YMMWORD PTR [rcx+32], ymm2
        vmovdqu	ymm3, YMMWORD PTR [rcx+64]
        vpaddw	ymm3, ymm3, [rdx+64]
        vpand	ymm3, ymm3, ymm0
        vmovdqu	YMMWORD PTR [rcx+64], ymm3
        vmovdqu	ymm4, YMMWORD PTR [rcx+96]
        vpaddw	ymm4, ymm4, [rdx+96]
        vpand	ymm4, ymm4, ymm0
        vmovdqu	YMMWORD PTR [rcx+96], ymm4
        vzeroupper
        ret
frodokem_add_avx2 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
frodokem_a_rows_reduce_avx2 PROC
        vmovd	xmm0, r8
        vpbroadcastw	ymm0, xmm0
        mov	eax, edx
L_frodokem_a_rows_reduce_avx2_blk:
        cmp	rax, 16
        jl	L_frodokem_a_rows_reduce_avx2_tail
        vpand	ymm1, ymm0, YMMWORD PTR [rcx]
        vmovdqu	YMMWORD PTR [rcx], ymm1
        add	rcx, 32
        sub	rax, 16
        jmp	L_frodokem_a_rows_reduce_avx2_blk
L_frodokem_a_rows_reduce_avx2_tail:
        cmp	rax, 0
        jle	L_frodokem_a_rows_reduce_avx2_done
L_frodokem_a_rows_reduce_avx2_word:
        movzx	r9d, WORD PTR [rcx]
        and	r9d, r8d
        mov	WORD PTR [rcx], r9w
        add	rcx, 2
        sub	rax, 1
        jg	L_frodokem_a_rows_reduce_avx2_word
L_frodokem_a_rows_reduce_avx2_done:
        vzeroupper
        ret
frodokem_a_rows_reduce_avx2 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
frodokem_sample_avx2 PROC
        push	r12
        sub	rsp, 32
        vmovdqu	OWORD PTR [rsp], xmm6
        vmovdqu	OWORD PTR [rsp+16], xmm7
        movsxd	rax, edx
        shl	rax, 1
        vpcmpeqw	ymm0, ymm0, ymm0
        vpsrlw	ymm0, ymm0, 15
        vpxor	ymm1, ymm1, ymm1
        xor	r10, r10
L_frodokem_sample_avx2_blk:
        vmovdqu	ymm2, YMMWORD PTR [rcx+r10]
        vpsrlw	ymm3, ymm2, 1
        vpand	ymm4, ymm2, ymm0
        vpxor	ymm5, ymm5, ymm5
        mov	r11, r8
        mov	r12d, r9d
L_frodokem_sample_avx2_cdf:
        vpbroadcastw	ymm6, WORD PTR [r11]
        vpsubw	ymm6, ymm6, ymm3
        vpsrlw	ymm6, ymm6, 15
        vpaddw	ymm5, ymm5, ymm6
        add	r11, 2
        sub	r12, 1
        jnz	L_frodokem_sample_avx2_cdf
        vpsubw	ymm7, ymm1, ymm4
        vpxor	ymm5, ymm5, ymm7
        vpaddw	ymm5, ymm5, ymm4
        vmovdqu	YMMWORD PTR [rcx+r10], ymm5
        add	r10, 32
        cmp	r10, rax
        jl	L_frodokem_sample_avx2_blk
        vzeroupper
        vmovdqu	xmm6, OWORD PTR [rsp]
        vmovdqu	xmm7, OWORD PTR [rsp+16]
        add	rsp, 32
        pop	r12
        ret
frodokem_sample_avx2 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
frodokem_gen_a_rows_aes_avx2 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        mov	rax, QWORD PTR [rsp+88]
        mov	r10, QWORD PTR [rsp+96]
        mov	r11, QWORD PTR [rsp+104]
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
        vbroadcasti128	ymm0, OWORD PTR [r8]
        vbroadcasti128	ymm1, OWORD PTR [r8+16]
        vbroadcasti128	ymm2, OWORD PTR [r8+32]
        vbroadcasti128	ymm3, OWORD PTR [r8+48]
        vbroadcasti128	ymm4, OWORD PTR [r8+64]
        vbroadcasti128	ymm5, OWORD PTR [r8+80]
        vbroadcasti128	ymm6, OWORD PTR [r8+96]
        vbroadcasti128	ymm7, OWORD PTR [r8+112]
        vbroadcasti128	ymm8, OWORD PTR [r8+128]
        vbroadcasti128	ymm9, OWORD PTR [r8+144]
        vbroadcasti128	ymm10, OWORD PTR [r8+160]
        vmovd	xmm15, r11
        vpbroadcastw	ymm15, xmm15
        movsxd	r12, r10d
        shr	r12, 3
        movsxd	r13, eax
        movsxd	r9, r9d
        xor	r14, r14
L_frodokem_gen_a_rows_aes_avx2_row:
        mov	rdi, r9
        add	rdi, r14
        xor	r15, r15
L_frodokem_gen_a_rows_aes_avx2_blk:
        lea	rsi, QWORD PTR [r15+8]
        cmp	rsi, r12
        jg	L_frodokem_gen_a_rows_aes_avx2_tail
        vmovd	xmm11, edi
        add	rdi, 524288
        vmovd	xmm0, edi
        add	rdi, 524288
        vinserti128	ymm11, ymm11, xmm0, 1
        vmovd	xmm12, edi
        add	rdi, 524288
        vmovd	xmm0, edi
        add	rdi, 524288
        vinserti128	ymm12, ymm12, xmm0, 1
        vmovd	xmm13, edi
        add	rdi, 524288
        vmovd	xmm0, edi
        add	rdi, 524288
        vinserti128	ymm13, ymm13, xmm0, 1
        vmovd	xmm14, edi
        add	rdi, 524288
        vmovd	xmm0, edi
        add	rdi, 524288
        vinserti128	ymm14, ymm14, xmm0, 1
        vbroadcasti128	ymm0, OWORD PTR [r8]
        vpxor	ymm11, ymm11, ymm0
        vpxor	ymm12, ymm12, ymm0
        vpxor	ymm13, ymm13, ymm0
        vpxor	ymm14, ymm14, ymm0
        vaesenc	ymm11, ymm11, ymm1
        vaesenc	ymm12, ymm12, ymm1
        vaesenc	ymm13, ymm13, ymm1
        vaesenc	ymm14, ymm14, ymm1
        vaesenc	ymm11, ymm11, ymm2
        vaesenc	ymm12, ymm12, ymm2
        vaesenc	ymm13, ymm13, ymm2
        vaesenc	ymm14, ymm14, ymm2
        vaesenc	ymm11, ymm11, ymm3
        vaesenc	ymm12, ymm12, ymm3
        vaesenc	ymm13, ymm13, ymm3
        vaesenc	ymm14, ymm14, ymm3
        vaesenc	ymm11, ymm11, ymm4
        vaesenc	ymm12, ymm12, ymm4
        vaesenc	ymm13, ymm13, ymm4
        vaesenc	ymm14, ymm14, ymm4
        vaesenc	ymm11, ymm11, ymm5
        vaesenc	ymm12, ymm12, ymm5
        vaesenc	ymm13, ymm13, ymm5
        vaesenc	ymm14, ymm14, ymm5
        vaesenc	ymm11, ymm11, ymm6
        vaesenc	ymm12, ymm12, ymm6
        vaesenc	ymm13, ymm13, ymm6
        vaesenc	ymm14, ymm14, ymm6
        vaesenc	ymm11, ymm11, ymm7
        vaesenc	ymm12, ymm12, ymm7
        vaesenc	ymm13, ymm13, ymm7
        vaesenc	ymm14, ymm14, ymm7
        vaesenc	ymm11, ymm11, ymm8
        vaesenc	ymm12, ymm12, ymm8
        vaesenc	ymm13, ymm13, ymm8
        vaesenc	ymm14, ymm14, ymm8
        vaesenc	ymm11, ymm11, ymm9
        vaesenc	ymm12, ymm12, ymm9
        vaesenc	ymm13, ymm13, ymm9
        vaesenc	ymm14, ymm14, ymm9
        vaesenclast	ymm11, ymm11, ymm10
        vaesenclast	ymm12, ymm12, ymm10
        vaesenclast	ymm13, ymm13, ymm10
        vaesenclast	ymm14, ymm14, ymm10
        vpand	ymm11, ymm11, ymm15
        vmovdqu	YMMWORD PTR [rdx], ymm11
        vpand	ymm12, ymm12, ymm15
        vmovdqu	YMMWORD PTR [rdx+32], ymm12
        vpand	ymm13, ymm13, ymm15
        vmovdqu	YMMWORD PTR [rdx+64], ymm13
        vpand	ymm14, ymm14, ymm15
        vmovdqu	YMMWORD PTR [rdx+96], ymm14
        add	rdx, 128
        add	r15, 8
        jmp	L_frodokem_gen_a_rows_aes_avx2_blk
L_frodokem_gen_a_rows_aes_avx2_tail:
        cmp	r15, r12
        jge	L_frodokem_gen_a_rows_aes_avx2_next
        vmovd	xmm11, edi
        add	rdi, 524288
        vpxor	xmm11, xmm11, xmm0
        vaesenc	xmm11, xmm11, xmm1
        vaesenc	xmm11, xmm11, xmm2
        vaesenc	xmm11, xmm11, xmm3
        vaesenc	xmm11, xmm11, xmm4
        vaesenc	xmm11, xmm11, xmm5
        vaesenc	xmm11, xmm11, xmm6
        vaesenc	xmm11, xmm11, xmm7
        vaesenc	xmm11, xmm11, xmm8
        vaesenc	xmm11, xmm11, xmm9
        vaesenclast	xmm11, xmm11, xmm10
        vpand	xmm11, xmm11, xmm15
        vmovdqu	OWORD PTR [rdx], xmm11
        add	rdx, 16
        add	r15, 1
        jmp	L_frodokem_gen_a_rows_aes_avx2_tail
L_frodokem_gen_a_rows_aes_avx2_next:
        add	r14, 1
        cmp	r14, r13
        jl	L_frodokem_gen_a_rows_aes_avx2_row
        vzeroupper
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
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
frodokem_gen_a_rows_aes_avx2 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
frodokem_gen_a_rows_aes_aesni PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        mov	rax, QWORD PTR [rsp+88]
        mov	r10, QWORD PTR [rsp+96]
        mov	r11, QWORD PTR [rsp+104]
        sub	rsp, 48
        vmovdqu	OWORD PTR [rsp], xmm6
        vmovdqu	OWORD PTR [rsp+16], xmm7
        vmovdqu	OWORD PTR [rsp+32], xmm8
        vmovd	xmm8, r11
        vpbroadcastw	xmm8, xmm8
        movsxd	r12, r10d
        shr	r12, 3
        movsxd	r13, eax
        movsxd	r9, r9d
        xor	r14, r14
L_frodokem_gen_a_rows_aes_aesni_row:
        mov	rdi, r9
        add	rdi, r14
        xor	r15, r15
L_frodokem_gen_a_rows_aes_aesni_blk:
        lea	rsi, QWORD PTR [r15+8]
        cmp	rsi, r12
        jg	L_frodokem_gen_a_rows_aes_aesni_tail
        vmovd	xmm0, edi
        add	rdi, 524288
        vmovd	xmm1, edi
        add	rdi, 524288
        vmovd	xmm2, edi
        add	rdi, 524288
        vmovd	xmm3, edi
        add	rdi, 524288
        vmovd	xmm4, edi
        add	rdi, 524288
        vmovd	xmm5, edi
        add	rdi, 524288
        vmovd	xmm6, edi
        add	rdi, 524288
        vmovd	xmm7, edi
        add	rdi, 524288
        vpxor	xmm0, xmm0, [r8]
        vpxor	xmm1, xmm1, [r8]
        vpxor	xmm2, xmm2, [r8]
        vpxor	xmm3, xmm3, [r8]
        vpxor	xmm4, xmm4, [r8]
        vpxor	xmm5, xmm5, [r8]
        vpxor	xmm6, xmm6, [r8]
        vpxor	xmm7, xmm7, [r8]
        vaesenc	xmm0, xmm0, [r8+16]
        vaesenc	xmm1, xmm1, [r8+16]
        vaesenc	xmm2, xmm2, [r8+16]
        vaesenc	xmm3, xmm3, [r8+16]
        vaesenc	xmm4, xmm4, [r8+16]
        vaesenc	xmm5, xmm5, [r8+16]
        vaesenc	xmm6, xmm6, [r8+16]
        vaesenc	xmm7, xmm7, [r8+16]
        vaesenc	xmm0, xmm0, [r8+32]
        vaesenc	xmm1, xmm1, [r8+32]
        vaesenc	xmm2, xmm2, [r8+32]
        vaesenc	xmm3, xmm3, [r8+32]
        vaesenc	xmm4, xmm4, [r8+32]
        vaesenc	xmm5, xmm5, [r8+32]
        vaesenc	xmm6, xmm6, [r8+32]
        vaesenc	xmm7, xmm7, [r8+32]
        vaesenc	xmm0, xmm0, [r8+48]
        vaesenc	xmm1, xmm1, [r8+48]
        vaesenc	xmm2, xmm2, [r8+48]
        vaesenc	xmm3, xmm3, [r8+48]
        vaesenc	xmm4, xmm4, [r8+48]
        vaesenc	xmm5, xmm5, [r8+48]
        vaesenc	xmm6, xmm6, [r8+48]
        vaesenc	xmm7, xmm7, [r8+48]
        vaesenc	xmm0, xmm0, [r8+64]
        vaesenc	xmm1, xmm1, [r8+64]
        vaesenc	xmm2, xmm2, [r8+64]
        vaesenc	xmm3, xmm3, [r8+64]
        vaesenc	xmm4, xmm4, [r8+64]
        vaesenc	xmm5, xmm5, [r8+64]
        vaesenc	xmm6, xmm6, [r8+64]
        vaesenc	xmm7, xmm7, [r8+64]
        vaesenc	xmm0, xmm0, [r8+80]
        vaesenc	xmm1, xmm1, [r8+80]
        vaesenc	xmm2, xmm2, [r8+80]
        vaesenc	xmm3, xmm3, [r8+80]
        vaesenc	xmm4, xmm4, [r8+80]
        vaesenc	xmm5, xmm5, [r8+80]
        vaesenc	xmm6, xmm6, [r8+80]
        vaesenc	xmm7, xmm7, [r8+80]
        vaesenc	xmm0, xmm0, [r8+96]
        vaesenc	xmm1, xmm1, [r8+96]
        vaesenc	xmm2, xmm2, [r8+96]
        vaesenc	xmm3, xmm3, [r8+96]
        vaesenc	xmm4, xmm4, [r8+96]
        vaesenc	xmm5, xmm5, [r8+96]
        vaesenc	xmm6, xmm6, [r8+96]
        vaesenc	xmm7, xmm7, [r8+96]
        vaesenc	xmm0, xmm0, [r8+112]
        vaesenc	xmm1, xmm1, [r8+112]
        vaesenc	xmm2, xmm2, [r8+112]
        vaesenc	xmm3, xmm3, [r8+112]
        vaesenc	xmm4, xmm4, [r8+112]
        vaesenc	xmm5, xmm5, [r8+112]
        vaesenc	xmm6, xmm6, [r8+112]
        vaesenc	xmm7, xmm7, [r8+112]
        vaesenc	xmm0, xmm0, [r8+128]
        vaesenc	xmm1, xmm1, [r8+128]
        vaesenc	xmm2, xmm2, [r8+128]
        vaesenc	xmm3, xmm3, [r8+128]
        vaesenc	xmm4, xmm4, [r8+128]
        vaesenc	xmm5, xmm5, [r8+128]
        vaesenc	xmm6, xmm6, [r8+128]
        vaesenc	xmm7, xmm7, [r8+128]
        vaesenc	xmm0, xmm0, [r8+144]
        vaesenc	xmm1, xmm1, [r8+144]
        vaesenc	xmm2, xmm2, [r8+144]
        vaesenc	xmm3, xmm3, [r8+144]
        vaesenc	xmm4, xmm4, [r8+144]
        vaesenc	xmm5, xmm5, [r8+144]
        vaesenc	xmm6, xmm6, [r8+144]
        vaesenc	xmm7, xmm7, [r8+144]
        vaesenclast	xmm0, xmm0, [r8+160]
        vaesenclast	xmm1, xmm1, [r8+160]
        vaesenclast	xmm2, xmm2, [r8+160]
        vaesenclast	xmm3, xmm3, [r8+160]
        vaesenclast	xmm4, xmm4, [r8+160]
        vaesenclast	xmm5, xmm5, [r8+160]
        vaesenclast	xmm6, xmm6, [r8+160]
        vaesenclast	xmm7, xmm7, [r8+160]
        vpand	xmm0, xmm0, xmm8
        vmovdqu	OWORD PTR [rdx], xmm0
        vpand	xmm1, xmm1, xmm8
        vmovdqu	OWORD PTR [rdx+16], xmm1
        vpand	xmm2, xmm2, xmm8
        vmovdqu	OWORD PTR [rdx+32], xmm2
        vpand	xmm3, xmm3, xmm8
        vmovdqu	OWORD PTR [rdx+48], xmm3
        vpand	xmm4, xmm4, xmm8
        vmovdqu	OWORD PTR [rdx+64], xmm4
        vpand	xmm5, xmm5, xmm8
        vmovdqu	OWORD PTR [rdx+80], xmm5
        vpand	xmm6, xmm6, xmm8
        vmovdqu	OWORD PTR [rdx+96], xmm6
        vpand	xmm7, xmm7, xmm8
        vmovdqu	OWORD PTR [rdx+112], xmm7
        add	rdx, 128
        add	r15, 8
        jmp	L_frodokem_gen_a_rows_aes_aesni_blk
L_frodokem_gen_a_rows_aes_aesni_tail:
        cmp	r15, r12
        jge	L_frodokem_gen_a_rows_aes_aesni_next
        vmovd	xmm0, edi
        add	rdi, 524288
        vpxor	xmm0, xmm0, [r8]
        vaesenc	xmm0, xmm0, [r8+16]
        vaesenc	xmm0, xmm0, [r8+32]
        vaesenc	xmm0, xmm0, [r8+48]
        vaesenc	xmm0, xmm0, [r8+64]
        vaesenc	xmm0, xmm0, [r8+80]
        vaesenc	xmm0, xmm0, [r8+96]
        vaesenc	xmm0, xmm0, [r8+112]
        vaesenc	xmm0, xmm0, [r8+128]
        vaesenc	xmm0, xmm0, [r8+144]
        vaesenclast	xmm0, xmm0, [r8+160]
        vpand	xmm0, xmm0, xmm8
        vmovdqu	OWORD PTR [rdx], xmm0
        add	rdx, 16
        add	r15, 1
        jmp	L_frodokem_gen_a_rows_aes_aesni_tail
L_frodokem_gen_a_rows_aes_aesni_next:
        add	r14, 1
        cmp	r14, r13
        jl	L_frodokem_gen_a_rows_aes_aesni_row
        vzeroupper
        vmovdqu	xmm6, OWORD PTR [rsp]
        vmovdqu	xmm7, OWORD PTR [rsp+16]
        vmovdqu	xmm8, OWORD PTR [rsp+32]
        add	rsp, 48
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
frodokem_gen_a_rows_aes_aesni ENDP
_TEXT ENDS
ENDIF
ENDIF
IFDEF WOLFSSL_HAVE_FRODOKEM
IFDEF HAVE_INTEL_AVX512
_TEXT SEGMENT READONLY PARA
frodokem_sa_accum_avx512 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        push	rbp
        mov	rax, QWORD PTR [rsp+104]
        sub	rsp, 64
        vmovdqu	OWORD PTR [rsp], xmm6
        vmovdqu	OWORD PTR [rsp+16], xmm7
        vmovdqu	OWORD PTR [rsp+32], xmm8
        vmovdqu	OWORD PTR [rsp+48], xmm9
        movsxd	r9, r9d
        shl	r9, 1
        add	rdx, r9
        movsxd	r10, eax
        shl	r10, 1
        mov	r9, r10
        and	r9, -64
        mov	r11, r8
        add	r11, r10
        mov	r12, r11
        add	r12, r10
        mov	r13, r12
        add	r13, r10
        mov	r14, r13
        add	r14, r10
        mov	r15, r14
        add	r15, r10
        mov	rdi, r15
        add	rdi, r10
        mov	rsi, rdi
        add	rsi, r10
        mov	rbp, 8
L_frodokem_sa_accum_avx512_i:
        vpbroadcastw	zmm0, WORD PTR [rdx]
        vpbroadcastw	zmm1, WORD PTR [rdx+2]
        vpbroadcastw	zmm2, WORD PTR [rdx+4]
        vpbroadcastw	zmm3, WORD PTR [rdx+6]
        vpbroadcastw	zmm4, WORD PTR [rdx+8]
        vpbroadcastw	zmm5, WORD PTR [rdx+10]
        vpbroadcastw	zmm6, WORD PTR [rdx+12]
        vpbroadcastw	zmm7, WORD PTR [rdx+14]
        xor	rbx, rbx
L_frodokem_sa_accum_avx512_k:
        vmovdqu64	zmm8, [rcx+rbx]
        vpmullw	zmm9, zmm0, [r8+rbx]
        vpaddw	zmm8, zmm8, zmm9
        vpmullw	zmm9, zmm1, [r11+rbx]
        vpaddw	zmm8, zmm8, zmm9
        vpmullw	zmm9, zmm2, [r12+rbx]
        vpaddw	zmm8, zmm8, zmm9
        vpmullw	zmm9, zmm3, [r13+rbx]
        vpaddw	zmm8, zmm8, zmm9
        vpmullw	zmm9, zmm4, [r14+rbx]
        vpaddw	zmm8, zmm8, zmm9
        vpmullw	zmm9, zmm5, [r15+rbx]
        vpaddw	zmm8, zmm8, zmm9
        vpmullw	zmm9, zmm6, [rdi+rbx]
        vpaddw	zmm8, zmm8, zmm9
        vpmullw	zmm9, zmm7, [rsi+rbx]
        vpaddw	zmm8, zmm8, zmm9
        vmovdqu64	[rcx+rbx], zmm8
        add	rbx, 64
        cmp	rbx, r9
        jl	L_frodokem_sa_accum_avx512_k
        cmp	rbx, r10
        jge	L_frodokem_sa_accum_avx512_tail
        vmovdqu	ymm8, YMMWORD PTR [rcx+rbx]
        vpmullw	ymm9, ymm0, [r8+rbx]
        vpaddw	ymm8, ymm8, ymm9
        vpmullw	ymm9, ymm1, [r11+rbx]
        vpaddw	ymm8, ymm8, ymm9
        vpmullw	ymm9, ymm2, [r12+rbx]
        vpaddw	ymm8, ymm8, ymm9
        vpmullw	ymm9, ymm3, [r13+rbx]
        vpaddw	ymm8, ymm8, ymm9
        vpmullw	ymm9, ymm4, [r14+rbx]
        vpaddw	ymm8, ymm8, ymm9
        vpmullw	ymm9, ymm5, [r15+rbx]
        vpaddw	ymm8, ymm8, ymm9
        vpmullw	ymm9, ymm6, [rdi+rbx]
        vpaddw	ymm8, ymm8, ymm9
        vpmullw	ymm9, ymm7, [rsi+rbx]
        vpaddw	ymm8, ymm8, ymm9
        vmovdqu	YMMWORD PTR [rcx+rbx], ymm8
L_frodokem_sa_accum_avx512_tail:
        add	rcx, r10
        add	rdx, r10
        sub	rbp, 1
        jnz	L_frodokem_sa_accum_avx512_i
        vzeroupper
        vmovdqu	xmm6, OWORD PTR [rsp]
        vmovdqu	xmm7, OWORD PTR [rsp+16]
        vmovdqu	xmm8, OWORD PTR [rsp+32]
        vmovdqu	xmm9, OWORD PTR [rsp+48]
        add	rsp, 64
        pop	rbp
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
frodokem_sa_accum_avx512 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
frodokem_as_accum_avx512 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        push	rbp
        mov	rax, QWORD PTR [rsp+104]
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
        movsxd	r9, r9d
        shl	r9, 4
        add	rcx, r9
        movsxd	r10, eax
        shl	r10, 1
        mov	r9, r10
        and	r9, -64
        mov	r11, rdx
        add	r11, r10
        mov	r12, r11
        add	r12, r10
        mov	r13, r12
        add	r13, r10
        mov	r14, r13
        add	r14, r10
        mov	r15, r14
        add	r15, r10
        mov	rdi, r15
        add	rdi, r10
        mov	rsi, rdi
        add	rsi, r10
        mov	rbp, 8
        vpcmpeqd	xmm13, xmm13, xmm13
        vpsrld	xmm13, xmm13, 16
L_frodokem_as_accum_avx512_r:
        vpxorq	zmm14, zmm14, zmm14
        vpxorq	ymm22, ymm22, ymm22
        vpxorq	zmm15, zmm15, zmm15
        vpxorq	ymm23, ymm23, ymm23
        vpxorq	zmm16, zmm16, zmm16
        vpxorq	ymm24, ymm24, ymm24
        vpxorq	zmm17, zmm17, zmm17
        vpxorq	ymm25, ymm25, ymm25
        vpxorq	zmm18, zmm18, zmm18
        vpxorq	ymm26, ymm26, ymm26
        vpxorq	zmm19, zmm19, zmm19
        vpxorq	ymm27, ymm27, ymm27
        vpxorq	zmm20, zmm20, zmm20
        vpxorq	ymm28, ymm28, ymm28
        vpxorq	zmm21, zmm21, zmm21
        vpxorq	ymm29, ymm29, ymm29
        xor	rbx, rbx
L_frodokem_as_accum_avx512_j:
        vmovdqu64	zmm0, [r8+rbx]
        vpmaddwd	zmm1, zmm0, [rdx+rbx]
        vpaddd	zmm14, zmm14, zmm1
        vpmaddwd	zmm1, zmm0, [r11+rbx]
        vpaddd	zmm15, zmm15, zmm1
        vpmaddwd	zmm1, zmm0, [r12+rbx]
        vpaddd	zmm16, zmm16, zmm1
        vpmaddwd	zmm1, zmm0, [r13+rbx]
        vpaddd	zmm17, zmm17, zmm1
        vpmaddwd	zmm1, zmm0, [r14+rbx]
        vpaddd	zmm18, zmm18, zmm1
        vpmaddwd	zmm1, zmm0, [r15+rbx]
        vpaddd	zmm19, zmm19, zmm1
        vpmaddwd	zmm1, zmm0, [rdi+rbx]
        vpaddd	zmm20, zmm20, zmm1
        vpmaddwd	zmm1, zmm0, [rsi+rbx]
        vpaddd	zmm21, zmm21, zmm1
        add	rbx, 64
        cmp	rbx, r9
        jl	L_frodokem_as_accum_avx512_j
        cmp	rbx, r10
        jge	L_frodokem_as_accum_avx512_tail
        vmovdqu	ymm0, YMMWORD PTR [r8+rbx]
        vpmaddwd	ymm22, ymm0, [rdx+rbx]
        vpmaddwd	ymm23, ymm0, [r11+rbx]
        vpmaddwd	ymm24, ymm0, [r12+rbx]
        vpmaddwd	ymm25, ymm0, [r13+rbx]
        vpmaddwd	ymm26, ymm0, [r14+rbx]
        vpmaddwd	ymm27, ymm0, [r15+rbx]
        vpmaddwd	ymm28, ymm0, [rdi+rbx]
        vpmaddwd	ymm29, ymm0, [rsi+rbx]
L_frodokem_as_accum_avx512_tail:
        vextracti64x4	ymm1, zmm14, 1
        vpaddd	ymm1, ymm14, ymm1
        vpaddd	ymm1, ymm1, ymm22
        vextracti128	xmm0, ymm1, 1
        vpaddd	xmm2, xmm1, xmm0
        vextracti64x4	ymm1, zmm15, 1
        vpaddd	ymm1, ymm15, ymm1
        vpaddd	ymm1, ymm1, ymm23
        vextracti128	xmm0, ymm1, 1
        vpaddd	xmm3, xmm1, xmm0
        vextracti64x4	ymm1, zmm16, 1
        vpaddd	ymm1, ymm16, ymm1
        vpaddd	ymm1, ymm1, ymm24
        vextracti128	xmm0, ymm1, 1
        vpaddd	xmm4, xmm1, xmm0
        vextracti64x4	ymm1, zmm17, 1
        vpaddd	ymm1, ymm17, ymm1
        vpaddd	ymm1, ymm1, ymm25
        vextracti128	xmm0, ymm1, 1
        vpaddd	xmm5, xmm1, xmm0
        vextracti64x4	ymm1, zmm18, 1
        vpaddd	ymm1, ymm18, ymm1
        vpaddd	ymm1, ymm1, ymm26
        vextracti128	xmm0, ymm1, 1
        vpaddd	xmm6, xmm1, xmm0
        vextracti64x4	ymm1, zmm19, 1
        vpaddd	ymm1, ymm19, ymm1
        vpaddd	ymm1, ymm1, ymm27
        vextracti128	xmm0, ymm1, 1
        vpaddd	xmm7, xmm1, xmm0
        vextracti64x4	ymm1, zmm20, 1
        vpaddd	ymm1, ymm20, ymm1
        vpaddd	ymm1, ymm1, ymm28
        vextracti128	xmm0, ymm1, 1
        vpaddd	xmm8, xmm1, xmm0
        vextracti64x4	ymm1, zmm21, 1
        vpaddd	ymm1, ymm21, ymm1
        vpaddd	ymm1, ymm1, ymm29
        vextracti128	xmm0, ymm1, 1
        vpaddd	xmm9, xmm1, xmm0
        vphaddd	xmm11, xmm2, xmm3
        vphaddd	xmm12, xmm4, xmm5
        vphaddd	xmm10, xmm11, xmm12
        vphaddd	xmm11, xmm6, xmm7
        vphaddd	xmm12, xmm8, xmm9
        vphaddd	xmm11, xmm11, xmm12
        vpand	xmm10, xmm10, xmm13
        vpand	xmm11, xmm11, xmm13
        vpackusdw	xmm10, xmm10, xmm11
        vpaddw	xmm10, xmm10, [rcx]
        vmovdqu	OWORD PTR [rcx], xmm10
        add	r8, r10
        add	rcx, 16
        sub	rbp, 1
        jnz	L_frodokem_as_accum_avx512_r
        vzeroupper
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
        pop	rbp
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
frodokem_as_accum_avx512 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
frodokem_mul_bs_avx512 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        push	rbp
        mov	rax, QWORD PTR [rsp+104]
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
        movsxd	r10, r9d
        shl	r10, 1
        mov	r9, r10
        and	r9, -64
        mov	r11, r8
        add	r11, r10
        mov	r12, r11
        add	r12, r10
        mov	r13, r12
        add	r13, r10
        mov	r14, r13
        add	r14, r10
        mov	r15, r14
        add	r15, r10
        mov	rdi, r15
        add	rdi, r10
        mov	rsi, rdi
        add	rsi, r10
        mov	rbp, 8
        vmovd	xmm13, rax
        vpbroadcastd	xmm13, xmm13
L_frodokem_mul_bs_avx512_r:
        vpxorq	zmm14, zmm14, zmm14
        vpxorq	ymm22, ymm22, ymm22
        vpxorq	zmm15, zmm15, zmm15
        vpxorq	ymm23, ymm23, ymm23
        vpxorq	zmm16, zmm16, zmm16
        vpxorq	ymm24, ymm24, ymm24
        vpxorq	zmm17, zmm17, zmm17
        vpxorq	ymm25, ymm25, ymm25
        vpxorq	zmm18, zmm18, zmm18
        vpxorq	ymm26, ymm26, ymm26
        vpxorq	zmm19, zmm19, zmm19
        vpxorq	ymm27, ymm27, ymm27
        vpxorq	zmm20, zmm20, zmm20
        vpxorq	ymm28, ymm28, ymm28
        vpxorq	zmm21, zmm21, zmm21
        vpxorq	ymm29, ymm29, ymm29
        xor	rbx, rbx
L_frodokem_mul_bs_avx512_j:
        vmovdqu64	zmm0, [rdx+rbx]
        vpmaddwd	zmm1, zmm0, [r8+rbx]
        vpaddd	zmm14, zmm14, zmm1
        vpmaddwd	zmm1, zmm0, [r11+rbx]
        vpaddd	zmm15, zmm15, zmm1
        vpmaddwd	zmm1, zmm0, [r12+rbx]
        vpaddd	zmm16, zmm16, zmm1
        vpmaddwd	zmm1, zmm0, [r13+rbx]
        vpaddd	zmm17, zmm17, zmm1
        vpmaddwd	zmm1, zmm0, [r14+rbx]
        vpaddd	zmm18, zmm18, zmm1
        vpmaddwd	zmm1, zmm0, [r15+rbx]
        vpaddd	zmm19, zmm19, zmm1
        vpmaddwd	zmm1, zmm0, [rdi+rbx]
        vpaddd	zmm20, zmm20, zmm1
        vpmaddwd	zmm1, zmm0, [rsi+rbx]
        vpaddd	zmm21, zmm21, zmm1
        add	rbx, 64
        cmp	rbx, r9
        jl	L_frodokem_mul_bs_avx512_j
        cmp	rbx, r10
        jge	L_frodokem_mul_bs_avx512_tail
        vmovdqu	ymm0, YMMWORD PTR [rdx+rbx]
        vpmaddwd	ymm22, ymm0, [r8+rbx]
        vpmaddwd	ymm23, ymm0, [r11+rbx]
        vpmaddwd	ymm24, ymm0, [r12+rbx]
        vpmaddwd	ymm25, ymm0, [r13+rbx]
        vpmaddwd	ymm26, ymm0, [r14+rbx]
        vpmaddwd	ymm27, ymm0, [r15+rbx]
        vpmaddwd	ymm28, ymm0, [rdi+rbx]
        vpmaddwd	ymm29, ymm0, [rsi+rbx]
L_frodokem_mul_bs_avx512_tail:
        vextracti64x4	ymm1, zmm14, 1
        vpaddd	ymm1, ymm14, ymm1
        vpaddd	ymm1, ymm1, ymm22
        vextracti128	xmm0, ymm1, 1
        vpaddd	xmm2, xmm1, xmm0
        vextracti64x4	ymm1, zmm15, 1
        vpaddd	ymm1, ymm15, ymm1
        vpaddd	ymm1, ymm1, ymm23
        vextracti128	xmm0, ymm1, 1
        vpaddd	xmm3, xmm1, xmm0
        vextracti64x4	ymm1, zmm16, 1
        vpaddd	ymm1, ymm16, ymm1
        vpaddd	ymm1, ymm1, ymm24
        vextracti128	xmm0, ymm1, 1
        vpaddd	xmm4, xmm1, xmm0
        vextracti64x4	ymm1, zmm17, 1
        vpaddd	ymm1, ymm17, ymm1
        vpaddd	ymm1, ymm1, ymm25
        vextracti128	xmm0, ymm1, 1
        vpaddd	xmm5, xmm1, xmm0
        vextracti64x4	ymm1, zmm18, 1
        vpaddd	ymm1, ymm18, ymm1
        vpaddd	ymm1, ymm1, ymm26
        vextracti128	xmm0, ymm1, 1
        vpaddd	xmm6, xmm1, xmm0
        vextracti64x4	ymm1, zmm19, 1
        vpaddd	ymm1, ymm19, ymm1
        vpaddd	ymm1, ymm1, ymm27
        vextracti128	xmm0, ymm1, 1
        vpaddd	xmm7, xmm1, xmm0
        vextracti64x4	ymm1, zmm20, 1
        vpaddd	ymm1, ymm20, ymm1
        vpaddd	ymm1, ymm1, ymm28
        vextracti128	xmm0, ymm1, 1
        vpaddd	xmm8, xmm1, xmm0
        vextracti64x4	ymm1, zmm21, 1
        vpaddd	ymm1, ymm21, ymm1
        vpaddd	ymm1, ymm1, ymm29
        vextracti128	xmm0, ymm1, 1
        vpaddd	xmm9, xmm1, xmm0
        vphaddd	xmm11, xmm2, xmm3
        vphaddd	xmm12, xmm4, xmm5
        vphaddd	xmm10, xmm11, xmm12
        vphaddd	xmm11, xmm6, xmm7
        vphaddd	xmm12, xmm8, xmm9
        vphaddd	xmm11, xmm11, xmm12
        vpand	xmm10, xmm10, xmm13
        vpand	xmm11, xmm11, xmm13
        vpackusdw	xmm10, xmm10, xmm11
        vmovdqu	OWORD PTR [rcx], xmm10
        add	rdx, r10
        add	rcx, 16
        sub	rbp, 1
        jnz	L_frodokem_mul_bs_avx512_r
        vzeroupper
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
        pop	rbp
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
frodokem_mul_bs_avx512 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
frodokem_mul_add_sb_plus_e_avx512 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        mov	rax, QWORD PTR [rsp+96]
        movsxd	r10, r9d
        shl	r10, 1
        mov	r11, r8
        add	r11, r10
        mov	r12, r11
        add	r12, r10
        mov	r13, r12
        add	r13, r10
        mov	r14, r13
        add	r14, r10
        mov	r15, r14
        add	r15, r10
        mov	rdi, r15
        add	rdi, r10
        mov	rsi, rdi
        add	rsi, r10
        vmovd	xmm5, rax
        vpbroadcastw	zmm5, xmm5
        vmovdqu64	zmm0, [rcx]
        vmovdqu64	zmm1, [rcx+64]
        xor	rbx, rbx
L_frodokem_mul_add_sb_plus_e_avx512_j:
        vbroadcasti32x4	zmm2, OWORD PTR [rdx]
        vpbroadcastw	zmm3, WORD PTR [r8+rbx]
        vpbroadcastw	zmm4, WORD PTR [r11+rbx]
        vinserti32x4	zmm3, zmm3, xmm4, 1
        vpbroadcastw	zmm4, WORD PTR [r12+rbx]
        vinserti32x4	zmm3, zmm3, xmm4, 2
        vpbroadcastw	zmm4, WORD PTR [r13+rbx]
        vinserti32x4	zmm3, zmm3, xmm4, 3
        vpmullw	zmm4, zmm3, zmm2
        vpaddw	zmm0, zmm0, zmm4
        vpbroadcastw	zmm3, WORD PTR [r14+rbx]
        vpbroadcastw	zmm4, WORD PTR [r15+rbx]
        vinserti32x4	zmm3, zmm3, xmm4, 1
        vpbroadcastw	zmm4, WORD PTR [rdi+rbx]
        vinserti32x4	zmm3, zmm3, xmm4, 2
        vpbroadcastw	zmm4, WORD PTR [rsi+rbx]
        vinserti32x4	zmm3, zmm3, xmm4, 3
        vpmullw	zmm4, zmm3, zmm2
        vpaddw	zmm1, zmm1, zmm4
        add	rdx, 16
        add	rbx, 2
        cmp	rbx, r10
        jl	L_frodokem_mul_add_sb_plus_e_avx512_j
        vpandq	zmm0, zmm0, zmm5
        vmovdqu64	[rcx], zmm0
        vpandq	zmm1, zmm1, zmm5
        vmovdqu64	[rcx+64], zmm1
        vzeroupper
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
frodokem_mul_add_sb_plus_e_avx512 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
frodokem_add_avx512 PROC
        vmovd	xmm0, r8
        vpbroadcastw	zmm0, xmm0
        vmovdqu64	zmm1, [rcx]
        vpaddw	zmm1, zmm1, [rdx]
        vpandq	zmm1, zmm1, zmm0
        vmovdqu64	[rcx], zmm1
        vmovdqu64	zmm2, [rcx+64]
        vpaddw	zmm2, zmm2, [rdx+64]
        vpandq	zmm2, zmm2, zmm0
        vmovdqu64	[rcx+64], zmm2
        vzeroupper
        ret
frodokem_add_avx512 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
frodokem_sample_avx512 PROC
        push	r12
        sub	rsp, 32
        vmovdqu	OWORD PTR [rsp], xmm6
        vmovdqu	OWORD PTR [rsp+16], xmm7
        movsxd	rax, edx
        shl	rax, 1
        vpternlogd	zmm0, zmm0, zmm0, 255
        vpsrlw	zmm0, zmm0, 15
        vpxorq	zmm1, zmm1, zmm1
        xor	r10, r10
L_frodokem_sample_avx512_blk:
        vmovdqu64	zmm2, [rcx+r10]
        vpsrlw	zmm3, zmm2, 1
        vpandq	zmm4, zmm2, zmm0
        vpxorq	zmm5, zmm5, zmm5
        mov	r11, r8
        mov	r12d, r9d
L_frodokem_sample_avx512_cdf:
        vpbroadcastw	zmm6, WORD PTR [r11]
        vpsubw	zmm6, zmm6, zmm3
        vpsrlw	zmm6, zmm6, 15
        vpaddw	zmm5, zmm5, zmm6
        add	r11, 2
        sub	r12, 1
        jnz	L_frodokem_sample_avx512_cdf
        vpsubw	zmm7, zmm1, zmm4
        vpxorq	zmm5, zmm5, zmm7
        vpaddw	zmm5, zmm5, zmm4
        vmovdqu64	[rcx+r10], zmm5
        add	r10, 64
        cmp	r10, rax
        jl	L_frodokem_sample_avx512_blk
        vzeroupper
        vmovdqu	xmm6, OWORD PTR [rsp]
        vmovdqu	xmm7, OWORD PTR [rsp+16]
        add	rsp, 32
        pop	r12
        ret
frodokem_sample_avx512 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
frodokem_gen_a_rows_aes_avx512 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        mov	rax, QWORD PTR [rsp+88]
        mov	r10, QWORD PTR [rsp+96]
        mov	r11, QWORD PTR [rsp+104]
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
        vbroadcasti32x4	zmm0, OWORD PTR [r8]
        vbroadcasti32x4	zmm1, OWORD PTR [r8+16]
        vbroadcasti32x4	zmm2, OWORD PTR [r8+32]
        vbroadcasti32x4	zmm3, OWORD PTR [r8+48]
        vbroadcasti32x4	zmm4, OWORD PTR [r8+64]
        vbroadcasti32x4	zmm5, OWORD PTR [r8+80]
        vbroadcasti32x4	zmm6, OWORD PTR [r8+96]
        vbroadcasti32x4	zmm7, OWORD PTR [r8+112]
        vbroadcasti32x4	zmm8, OWORD PTR [r8+128]
        vbroadcasti32x4	zmm9, OWORD PTR [r8+144]
        vbroadcasti32x4	zmm10, OWORD PTR [r8+160]
        vmovd	xmm15, r11
        vpbroadcastw	zmm15, xmm15
        movsxd	r12, r10d
        shl	r12, 1
        movsxd	r13, eax
        imul	r13, r12
        movsxd	r9, r9d
        xor	rsi, rsi
        mov	r14, rcx
L_frodokem_gen_a_rows_aes_avx512_row:
        mov	edi, r9d
        mov	r15, r14
        add	r15, r12
L_frodokem_gen_a_rows_aes_avx512_blk:
        mov	QWORD PTR [r14], rdi
        mov	QWORD PTR [r14+8], rsi
        add	rdi, 524288
        add	r14, 16
        cmp	r14, r15
        jl	L_frodokem_gen_a_rows_aes_avx512_blk
        add	r9, 1
        mov	r15, rcx
        add	r15, r13
        cmp	r14, r15
        jl	L_frodokem_gen_a_rows_aes_avx512_row
        xor	rdi, rdi
L_frodokem_gen_a_rows_aes_avx512_aes:
        vmovdqu64	zmm11, [rcx]
        vmovdqu64	zmm12, [rcx+64]
        vmovdqu64	zmm13, [rcx+128]
        vmovdqu64	zmm14, [rcx+192]
        vpxorq	zmm11, zmm11, zmm0
        vpxorq	zmm12, zmm12, zmm0
        vpxorq	zmm13, zmm13, zmm0
        vpxorq	zmm14, zmm14, zmm0
        vaesenc	zmm11, zmm11, zmm1
        vaesenc	zmm12, zmm12, zmm1
        vaesenc	zmm13, zmm13, zmm1
        vaesenc	zmm14, zmm14, zmm1
        vaesenc	zmm11, zmm11, zmm2
        vaesenc	zmm12, zmm12, zmm2
        vaesenc	zmm13, zmm13, zmm2
        vaesenc	zmm14, zmm14, zmm2
        vaesenc	zmm11, zmm11, zmm3
        vaesenc	zmm12, zmm12, zmm3
        vaesenc	zmm13, zmm13, zmm3
        vaesenc	zmm14, zmm14, zmm3
        vaesenc	zmm11, zmm11, zmm4
        vaesenc	zmm12, zmm12, zmm4
        vaesenc	zmm13, zmm13, zmm4
        vaesenc	zmm14, zmm14, zmm4
        vaesenc	zmm11, zmm11, zmm5
        vaesenc	zmm12, zmm12, zmm5
        vaesenc	zmm13, zmm13, zmm5
        vaesenc	zmm14, zmm14, zmm5
        vaesenc	zmm11, zmm11, zmm6
        vaesenc	zmm12, zmm12, zmm6
        vaesenc	zmm13, zmm13, zmm6
        vaesenc	zmm14, zmm14, zmm6
        vaesenc	zmm11, zmm11, zmm7
        vaesenc	zmm12, zmm12, zmm7
        vaesenc	zmm13, zmm13, zmm7
        vaesenc	zmm14, zmm14, zmm7
        vaesenc	zmm11, zmm11, zmm8
        vaesenc	zmm12, zmm12, zmm8
        vaesenc	zmm13, zmm13, zmm8
        vaesenc	zmm14, zmm14, zmm8
        vaesenc	zmm11, zmm11, zmm9
        vaesenc	zmm12, zmm12, zmm9
        vaesenc	zmm13, zmm13, zmm9
        vaesenc	zmm14, zmm14, zmm9
        vaesenclast	zmm11, zmm11, zmm10
        vaesenclast	zmm12, zmm12, zmm10
        vaesenclast	zmm13, zmm13, zmm10
        vaesenclast	zmm14, zmm14, zmm10
        vpandq	zmm11, zmm11, zmm15
        vpandq	zmm12, zmm12, zmm15
        vpandq	zmm13, zmm13, zmm15
        vpandq	zmm14, zmm14, zmm15
        vmovdqu64	[rdx], zmm11
        vmovdqu64	[rdx+64], zmm12
        vmovdqu64	[rdx+128], zmm13
        vmovdqu64	[rdx+192], zmm14
        add	rcx, 256
        add	rdx, 256
        add	rdi, 256
        cmp	rdi, r13
        jl	L_frodokem_gen_a_rows_aes_avx512_aes
        vzeroupper
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
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
frodokem_gen_a_rows_aes_avx512 ENDP
_TEXT ENDS
ENDIF
ENDIF
END
