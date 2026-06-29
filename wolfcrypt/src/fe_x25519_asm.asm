; /* fe_x25519_asm.asm */
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

EXTERN cpuid_get_flags:PROC
_TEXT SEGMENT READONLY PARA
fe_init PROC
IFDEF HAVE_INTEL_AVX2
        mov	eax, DWORD PTR [cpuFlagsSet]
        test	eax, eax
        je	L_fe_init_get_flags
        ret
L_fe_init_get_flags:
        sub	rsp, 40
        call	cpuid_get_flags
        add	rsp, 40
        mov	DWORD PTR [intelFlags], eax
        and	eax, 80
        cmp	eax, 80
        jne	L_fe_init_flags_done
        lea	rax, [fe_cmov_table_avx2]
        mov	QWORD PTR [fe_cmov_table_p], rax
        lea	rax, [fe_mul_avx2]
        mov	QWORD PTR [fe_mul_p], rax
        lea	rax, [fe_sq_avx2]
        mov	QWORD PTR [fe_sq_p], rax
        lea	rax, [fe_mul121666_avx2]
        mov	QWORD PTR [fe_mul121666_p], rax
        lea	rax, [fe_invert_avx2]
        mov	QWORD PTR [fe_invert_p], rax
        lea	rax, [curve25519_avx2]
        mov	QWORD PTR [curve25519_p], rax
        lea	rax, [fe_pow22523_avx2]
        mov	QWORD PTR [fe_pow22523_p], rax
        lea	rax, [ge_p1p1_to_p2_avx2]
        mov	QWORD PTR [ge_p1p1_to_p2_p], rax
        lea	rax, [ge_p1p1_to_p3_avx2]
        mov	QWORD PTR [ge_p1p1_to_p3_p], rax
        lea	rax, [ge_p2_dbl_avx2]
        mov	QWORD PTR [ge_p2_dbl_p], rax
        lea	rax, [ge_madd_avx2]
        mov	QWORD PTR [ge_madd_p], rax
        lea	rax, [ge_msub_avx2]
        mov	QWORD PTR [ge_msub_p], rax
        lea	rax, [ge_add_avx2]
        mov	QWORD PTR [ge_add_p], rax
        lea	rax, [ge_sub_avx2]
        mov	QWORD PTR [ge_sub_p], rax
IFDEF WOLFSSL_CURVE25519_NOT_USE_ED25519
        lea	rax, [curve25519_base_avx2]
        mov	QWORD PTR [curve25519_base_p], rax
ENDIF
IFDEF HAVE_ED25519
        lea	rax, [fe_sq2_avx2]
        mov	QWORD PTR [fe_sq2_p], rax
        lea	rax, [fe_invert_nct_avx2]
        mov	QWORD PTR [fe_invert_nct_p], rax
        lea	rax, [sc_reduce_avx2]
        mov	QWORD PTR [sc_reduce_p], rax
        lea	rax, [sc_muladd_avx2]
        mov	QWORD PTR [sc_muladd_p], rax
ENDIF
L_fe_init_flags_done:
        mov	DWORD PTR [cpuFlagsSet], 1
ENDIF
        ret
fe_init ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
fe_frombytes PROC
        mov	r11, 9223372036854775807
        mov	rax, QWORD PTR [rdx]
        mov	r8, QWORD PTR [rdx+8]
        mov	r9, QWORD PTR [rdx+16]
        mov	r10, QWORD PTR [rdx+24]
        and	r10, r11
        mov	QWORD PTR [rcx], rax
        mov	QWORD PTR [rcx+8], r8
        mov	QWORD PTR [rcx+16], r9
        mov	QWORD PTR [rcx+24], r10
        ret
fe_frombytes ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
fe_tobytes PROC
        push	r12
        mov	r12, 9223372036854775807
        mov	rax, QWORD PTR [rdx]
        mov	r8, QWORD PTR [rdx+8]
        mov	r9, QWORD PTR [rdx+16]
        mov	r10, QWORD PTR [rdx+24]
        add	rax, 19
        adc	r8, 0
        adc	r9, 0
        adc	r10, 0
        shr	r10, 63
        imul	r11, r10, 19
        mov	rax, QWORD PTR [rdx]
        mov	r8, QWORD PTR [rdx+8]
        mov	r9, QWORD PTR [rdx+16]
        mov	r10, QWORD PTR [rdx+24]
        add	rax, r11
        adc	r8, 0
        adc	r9, 0
        adc	r10, 0
        and	r10, r12
        mov	QWORD PTR [rcx], rax
        mov	QWORD PTR [rcx+8], r8
        mov	QWORD PTR [rcx+16], r9
        mov	QWORD PTR [rcx+24], r10
        pop	r12
        ret
fe_tobytes ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
fe_1 PROC
        ; Set one
        mov	QWORD PTR [rcx], 1
        mov	QWORD PTR [rcx+8], 0
        mov	QWORD PTR [rcx+16], 0
        mov	QWORD PTR [rcx+24], 0
        ret
fe_1 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
fe_0 PROC
        ; Set zero
        mov	QWORD PTR [rcx], 0
        mov	QWORD PTR [rcx+8], 0
        mov	QWORD PTR [rcx+16], 0
        mov	QWORD PTR [rcx+24], 0
        ret
fe_0 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
fe_copy PROC
        ; Copy
        mov	rax, QWORD PTR [rdx]
        mov	r8, QWORD PTR [rdx+8]
        mov	r9, QWORD PTR [rdx+16]
        mov	r10, QWORD PTR [rdx+24]
        mov	QWORD PTR [rcx], rax
        mov	QWORD PTR [rcx+8], r8
        mov	QWORD PTR [rcx+16], r9
        mov	QWORD PTR [rcx+24], r10
        ret
fe_copy ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
fe_sub PROC
        push	r12
        ; Sub
        mov	rax, QWORD PTR [rdx]
        mov	r9, QWORD PTR [rdx+8]
        mov	r10, QWORD PTR [rdx+16]
        mov	r11, QWORD PTR [rdx+24]
        sub	rax, QWORD PTR [r8]
        sbb	r9, QWORD PTR [r8+8]
        sbb	r10, QWORD PTR [r8+16]
        sbb	r11, QWORD PTR [r8+24]
        sbb	r12, r12
        shld	r12, r11, 1
        imul	r12, -19
        btr	r11, 63
        ;   Add modulus (if underflow)
        sub	rax, r12
        sbb	r9, 0
        sbb	r10, 0
        sbb	r11, 0
        mov	QWORD PTR [rcx], rax
        mov	QWORD PTR [rcx+8], r9
        mov	QWORD PTR [rcx+16], r10
        mov	QWORD PTR [rcx+24], r11
        pop	r12
        ret
fe_sub ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
fe_add PROC
        push	r12
        ; Add
        mov	rax, QWORD PTR [rdx]
        mov	r9, QWORD PTR [rdx+8]
        add	rax, QWORD PTR [r8]
        mov	r10, QWORD PTR [rdx+16]
        adc	r9, QWORD PTR [r8+8]
        mov	r11, QWORD PTR [rdx+24]
        adc	r10, QWORD PTR [r8+16]
        adc	r11, QWORD PTR [r8+24]
        mov	r12, 0
        adc	r12, 0
        shld	r12, r11, 1
        imul	r12, 19
        btr	r11, 63
        ;   Sub modulus (if overflow)
        add	rax, r12
        adc	r9, 0
        adc	r10, 0
        adc	r11, 0
        mov	QWORD PTR [rcx], rax
        mov	QWORD PTR [rcx+8], r9
        mov	QWORD PTR [rcx+16], r10
        mov	QWORD PTR [rcx+24], r11
        pop	r12
        ret
fe_add ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
fe_neg PROC
        mov	rax, -19
        mov	r8, -1
        mov	r9, -1
        mov	r10, 9223372036854775807
        sub	rax, QWORD PTR [rdx]
        sbb	r8, QWORD PTR [rdx+8]
        sbb	r9, QWORD PTR [rdx+16]
        sbb	r10, QWORD PTR [rdx+24]
        mov	QWORD PTR [rcx], rax
        mov	QWORD PTR [rcx+8], r8
        mov	QWORD PTR [rcx+16], r9
        mov	QWORD PTR [rcx+24], r10
        ret
fe_neg ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
fe_cmov PROC
        push	r12
        cmp	r8d, 1
        mov	r9, QWORD PTR [rcx]
        mov	r10, QWORD PTR [rcx+8]
        mov	r11, QWORD PTR [rcx+16]
        mov	r12, QWORD PTR [rcx+24]
        cmove	r9, QWORD PTR [rdx]
        cmove	r10, QWORD PTR [rdx+8]
        cmove	r11, QWORD PTR [rdx+16]
        cmove	r12, QWORD PTR [rdx+24]
        mov	QWORD PTR [rcx], r9
        mov	QWORD PTR [rcx+8], r10
        mov	QWORD PTR [rcx+16], r11
        mov	QWORD PTR [rcx+24], r12
        pop	r12
        ret
fe_cmov ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
fe_isnonzero PROC
        mov	r11, 9223372036854775807
        mov	rax, QWORD PTR [rcx]
        mov	rdx, QWORD PTR [rcx+8]
        mov	r8, QWORD PTR [rcx+16]
        mov	r9, QWORD PTR [rcx+24]
        add	rax, 19
        adc	rdx, 0
        adc	r8, 0
        adc	r9, 0
        shr	r9, 63
        imul	r10, r9, 19
        mov	rax, QWORD PTR [rcx]
        mov	rdx, QWORD PTR [rcx+8]
        mov	r8, QWORD PTR [rcx+16]
        mov	r9, QWORD PTR [rcx+24]
        add	rax, r10
        adc	rdx, 0
        adc	r8, 0
        adc	r9, 0
        and	r9, r11
        or	rax, rdx
        or	rax, r8
        or	rax, r9
        ret
fe_isnonzero ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
fe_isnegative PROC
        push	r12
        mov	r12, 9223372036854775807
        mov	rdx, QWORD PTR [rcx]
        mov	r8, QWORD PTR [rcx+8]
        mov	r9, QWORD PTR [rcx+16]
        mov	r10, QWORD PTR [rcx+24]
        mov	rax, rdx
        add	rdx, 19
        adc	r8, 0
        adc	r9, 0
        adc	r10, 0
        shr	r10, 63
        imul	r11, r10, 19
        add	rax, r11
        and	rax, 1
        pop	r12
        ret
fe_isnegative ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
fe_cmov_table PROC
        jmp	QWORD PTR [fe_cmov_table_p]
fe_cmov_table ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
fe_mul PROC
        jmp	QWORD PTR [fe_mul_p]
fe_mul ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
fe_sq PROC
        jmp	QWORD PTR [fe_sq_p]
fe_sq ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
fe_mul121666 PROC
        jmp	QWORD PTR [fe_mul121666_p]
fe_mul121666 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
fe_invert PROC
        jmp	QWORD PTR [fe_invert_p]
fe_invert ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
curve25519 PROC
        jmp	QWORD PTR [curve25519_p]
curve25519 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
fe_pow22523 PROC
        jmp	QWORD PTR [fe_pow22523_p]
fe_pow22523 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
ge_p1p1_to_p2 PROC
        jmp	QWORD PTR [ge_p1p1_to_p2_p]
ge_p1p1_to_p2 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
ge_p1p1_to_p3 PROC
        jmp	QWORD PTR [ge_p1p1_to_p3_p]
ge_p1p1_to_p3 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
ge_p2_dbl PROC
        jmp	QWORD PTR [ge_p2_dbl_p]
ge_p2_dbl ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
ge_madd PROC
        jmp	QWORD PTR [ge_madd_p]
ge_madd ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
ge_msub PROC
        jmp	QWORD PTR [ge_msub_p]
ge_msub ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
ge_add PROC
        jmp	QWORD PTR [ge_add_p]
ge_add ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
ge_sub PROC
        jmp	QWORD PTR [ge_sub_p]
ge_sub ENDP
_TEXT ENDS
IFDEF WOLFSSL_CURVE25519_NOT_USE_ED25519
IFDEF WOLFSSL_CURVE25519_NOT_USE_ED25519
_TEXT SEGMENT READONLY PARA
curve25519_base PROC
        jmp	QWORD PTR [curve25519_base_p]
curve25519_base ENDP
_TEXT ENDS
ENDIF
ENDIF
IFDEF HAVE_ED25519
IFDEF HAVE_ED25519
_TEXT SEGMENT READONLY PARA
fe_sq2 PROC
        jmp	QWORD PTR [fe_sq2_p]
fe_sq2 ENDP
_TEXT ENDS
ENDIF
IFDEF HAVE_ED25519
_TEXT SEGMENT READONLY PARA
fe_invert_nct PROC
        jmp	QWORD PTR [fe_invert_nct_p]
fe_invert_nct ENDP
_TEXT ENDS
ENDIF
IFDEF HAVE_ED25519
_TEXT SEGMENT READONLY PARA
sc_reduce PROC
        jmp	QWORD PTR [sc_reduce_p]
sc_reduce ENDP
_TEXT ENDS
ENDIF
IFDEF HAVE_ED25519
_TEXT SEGMENT READONLY PARA
sc_muladd PROC
        jmp	QWORD PTR [sc_muladd_p]
sc_muladd ENDP
_TEXT ENDS
ENDIF
ENDIF
_DATA SEGMENT
cpuFlagsSet	dd	0
_DATA ENDS
_DATA SEGMENT
intelFlags	dd	0
_DATA ENDS
_DATA SEGMENT
fe_cmov_table_p	dq	fe_cmov_table_x64
_DATA ENDS
_DATA SEGMENT
fe_mul_p	dq	fe_mul_x64
_DATA ENDS
_DATA SEGMENT
fe_sq_p	dq	fe_sq_x64
_DATA ENDS
_DATA SEGMENT
fe_mul121666_p	dq	fe_mul121666_x64
_DATA ENDS
_DATA SEGMENT
fe_invert_p	dq	fe_invert_x64
_DATA ENDS
_DATA SEGMENT
curve25519_p	dq	curve25519_x64
_DATA ENDS
_DATA SEGMENT
fe_pow22523_p	dq	fe_pow22523_x64
_DATA ENDS
_DATA SEGMENT
ge_p1p1_to_p2_p	dq	ge_p1p1_to_p2_x64
_DATA ENDS
_DATA SEGMENT
ge_p1p1_to_p3_p	dq	ge_p1p1_to_p3_x64
_DATA ENDS
_DATA SEGMENT
ge_p2_dbl_p	dq	ge_p2_dbl_x64
_DATA ENDS
_DATA SEGMENT
ge_madd_p	dq	ge_madd_x64
_DATA ENDS
_DATA SEGMENT
ge_msub_p	dq	ge_msub_x64
_DATA ENDS
_DATA SEGMENT
ge_add_p	dq	ge_add_x64
_DATA ENDS
_DATA SEGMENT
ge_sub_p	dq	ge_sub_x64
_DATA ENDS
IFDEF WOLFSSL_CURVE25519_NOT_USE_ED25519
_DATA SEGMENT
curve25519_base_p	dq	curve25519_base_x64
_DATA ENDS
ENDIF
IFDEF HAVE_ED25519
_DATA SEGMENT
fe_sq2_p	dq	fe_sq2_x64
_DATA ENDS
_DATA SEGMENT
fe_invert_nct_p	dq	fe_invert_nct_x64
_DATA ENDS
_DATA SEGMENT
sc_reduce_p	dq	sc_reduce_x64
_DATA ENDS
_DATA SEGMENT
sc_muladd_p	dq	sc_muladd_x64
_DATA ENDS
ENDIF
_TEXT SEGMENT READONLY PARA
fe_cmov_table_x64 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        mov	r9, rdx
        movsx	rax, r8b
        cdq
        xor	al, dl
        sub	al, dl
        mov	sil, al
        mov	rax, 1
        xor	rdx, rdx
        xor	r10, r10
        xor	r11, r11
        mov	r12, 1
        xor	r13, r13
        xor	r14, r14
        xor	r15, r15
        cmp	sil, 1
        mov	rdi, QWORD PTR [r9]
        cmove	rax, rdi
        mov	rdi, QWORD PTR [r9+8]
        cmove	rdx, rdi
        mov	rdi, QWORD PTR [r9+16]
        cmove	r10, rdi
        mov	rdi, QWORD PTR [r9+24]
        cmove	r11, rdi
        mov	rdi, QWORD PTR [r9+32]
        cmove	r12, rdi
        mov	rdi, QWORD PTR [r9+40]
        cmove	r13, rdi
        mov	rdi, QWORD PTR [r9+48]
        cmove	r14, rdi
        mov	rdi, QWORD PTR [r9+56]
        cmove	r15, rdi
        cmp	sil, 2
        mov	rdi, QWORD PTR [r9+96]
        cmove	rax, rdi
        mov	rdi, QWORD PTR [r9+104]
        cmove	rdx, rdi
        mov	rdi, QWORD PTR [r9+112]
        cmove	r10, rdi
        mov	rdi, QWORD PTR [r9+120]
        cmove	r11, rdi
        mov	rdi, QWORD PTR [r9+128]
        cmove	r12, rdi
        mov	rdi, QWORD PTR [r9+136]
        cmove	r13, rdi
        mov	rdi, QWORD PTR [r9+144]
        cmove	r14, rdi
        mov	rdi, QWORD PTR [r9+152]
        cmove	r15, rdi
        cmp	sil, 3
        mov	rdi, QWORD PTR [r9+192]
        cmove	rax, rdi
        mov	rdi, QWORD PTR [r9+200]
        cmove	rdx, rdi
        mov	rdi, QWORD PTR [r9+208]
        cmove	r10, rdi
        mov	rdi, QWORD PTR [r9+216]
        cmove	r11, rdi
        mov	rdi, QWORD PTR [r9+224]
        cmove	r12, rdi
        mov	rdi, QWORD PTR [r9+232]
        cmove	r13, rdi
        mov	rdi, QWORD PTR [r9+240]
        cmove	r14, rdi
        mov	rdi, QWORD PTR [r9+248]
        cmove	r15, rdi
        cmp	sil, 4
        mov	rdi, QWORD PTR [r9+288]
        cmove	rax, rdi
        mov	rdi, QWORD PTR [r9+296]
        cmove	rdx, rdi
        mov	rdi, QWORD PTR [r9+304]
        cmove	r10, rdi
        mov	rdi, QWORD PTR [r9+312]
        cmove	r11, rdi
        mov	rdi, QWORD PTR [r9+320]
        cmove	r12, rdi
        mov	rdi, QWORD PTR [r9+328]
        cmove	r13, rdi
        mov	rdi, QWORD PTR [r9+336]
        cmove	r14, rdi
        mov	rdi, QWORD PTR [r9+344]
        cmove	r15, rdi
        cmp	sil, 5
        mov	rdi, QWORD PTR [r9+384]
        cmove	rax, rdi
        mov	rdi, QWORD PTR [r9+392]
        cmove	rdx, rdi
        mov	rdi, QWORD PTR [r9+400]
        cmove	r10, rdi
        mov	rdi, QWORD PTR [r9+408]
        cmove	r11, rdi
        mov	rdi, QWORD PTR [r9+416]
        cmove	r12, rdi
        mov	rdi, QWORD PTR [r9+424]
        cmove	r13, rdi
        mov	rdi, QWORD PTR [r9+432]
        cmove	r14, rdi
        mov	rdi, QWORD PTR [r9+440]
        cmove	r15, rdi
        cmp	sil, 6
        mov	rdi, QWORD PTR [r9+480]
        cmove	rax, rdi
        mov	rdi, QWORD PTR [r9+488]
        cmove	rdx, rdi
        mov	rdi, QWORD PTR [r9+496]
        cmove	r10, rdi
        mov	rdi, QWORD PTR [r9+504]
        cmove	r11, rdi
        mov	rdi, QWORD PTR [r9+512]
        cmove	r12, rdi
        mov	rdi, QWORD PTR [r9+520]
        cmove	r13, rdi
        mov	rdi, QWORD PTR [r9+528]
        cmove	r14, rdi
        mov	rdi, QWORD PTR [r9+536]
        cmove	r15, rdi
        cmp	sil, 7
        mov	rdi, QWORD PTR [r9+576]
        cmove	rax, rdi
        mov	rdi, QWORD PTR [r9+584]
        cmove	rdx, rdi
        mov	rdi, QWORD PTR [r9+592]
        cmove	r10, rdi
        mov	rdi, QWORD PTR [r9+600]
        cmove	r11, rdi
        mov	rdi, QWORD PTR [r9+608]
        cmove	r12, rdi
        mov	rdi, QWORD PTR [r9+616]
        cmove	r13, rdi
        mov	rdi, QWORD PTR [r9+624]
        cmove	r14, rdi
        mov	rdi, QWORD PTR [r9+632]
        cmove	r15, rdi
        cmp	sil, 8
        mov	rdi, QWORD PTR [r9+672]
        cmove	rax, rdi
        mov	rdi, QWORD PTR [r9+680]
        cmove	rdx, rdi
        mov	rdi, QWORD PTR [r9+688]
        cmove	r10, rdi
        mov	rdi, QWORD PTR [r9+696]
        cmove	r11, rdi
        mov	rdi, QWORD PTR [r9+704]
        cmove	r12, rdi
        mov	rdi, QWORD PTR [r9+712]
        cmove	r13, rdi
        mov	rdi, QWORD PTR [r9+720]
        cmove	r14, rdi
        mov	rdi, QWORD PTR [r9+728]
        cmove	r15, rdi
        cmp	r8b, 0
        mov	rdi, rax
        cmovl	rax, r12
        cmovl	r12, rdi
        mov	rdi, rdx
        cmovl	rdx, r13
        cmovl	r13, rdi
        mov	rdi, r10
        cmovl	r10, r14
        cmovl	r14, rdi
        mov	rdi, r11
        cmovl	r11, r15
        cmovl	r15, rdi
        mov	QWORD PTR [rcx], rax
        mov	QWORD PTR [rcx+8], rdx
        mov	QWORD PTR [rcx+16], r10
        mov	QWORD PTR [rcx+24], r11
        mov	QWORD PTR [rcx+32], r12
        mov	QWORD PTR [rcx+40], r13
        mov	QWORD PTR [rcx+48], r14
        mov	QWORD PTR [rcx+56], r15
        xor	rax, rax
        xor	rdx, rdx
        xor	r10, r10
        xor	r11, r11
        cmp	sil, 1
        mov	rdi, QWORD PTR [r9+64]
        cmove	rax, rdi
        mov	rdi, QWORD PTR [r9+72]
        cmove	rdx, rdi
        mov	rdi, QWORD PTR [r9+80]
        cmove	r10, rdi
        mov	rdi, QWORD PTR [r9+88]
        cmove	r11, rdi
        cmp	sil, 2
        mov	rdi, QWORD PTR [r9+160]
        cmove	rax, rdi
        mov	rdi, QWORD PTR [r9+168]
        cmove	rdx, rdi
        mov	rdi, QWORD PTR [r9+176]
        cmove	r10, rdi
        mov	rdi, QWORD PTR [r9+184]
        cmove	r11, rdi
        cmp	sil, 3
        mov	rdi, QWORD PTR [r9+256]
        cmove	rax, rdi
        mov	rdi, QWORD PTR [r9+264]
        cmove	rdx, rdi
        mov	rdi, QWORD PTR [r9+272]
        cmove	r10, rdi
        mov	rdi, QWORD PTR [r9+280]
        cmove	r11, rdi
        cmp	sil, 4
        mov	rdi, QWORD PTR [r9+352]
        cmove	rax, rdi
        mov	rdi, QWORD PTR [r9+360]
        cmove	rdx, rdi
        mov	rdi, QWORD PTR [r9+368]
        cmove	r10, rdi
        mov	rdi, QWORD PTR [r9+376]
        cmove	r11, rdi
        cmp	sil, 5
        mov	rdi, QWORD PTR [r9+448]
        cmove	rax, rdi
        mov	rdi, QWORD PTR [r9+456]
        cmove	rdx, rdi
        mov	rdi, QWORD PTR [r9+464]
        cmove	r10, rdi
        mov	rdi, QWORD PTR [r9+472]
        cmove	r11, rdi
        cmp	sil, 6
        mov	rdi, QWORD PTR [r9+544]
        cmove	rax, rdi
        mov	rdi, QWORD PTR [r9+552]
        cmove	rdx, rdi
        mov	rdi, QWORD PTR [r9+560]
        cmove	r10, rdi
        mov	rdi, QWORD PTR [r9+568]
        cmove	r11, rdi
        cmp	sil, 7
        mov	rdi, QWORD PTR [r9+640]
        cmove	rax, rdi
        mov	rdi, QWORD PTR [r9+648]
        cmove	rdx, rdi
        mov	rdi, QWORD PTR [r9+656]
        cmove	r10, rdi
        mov	rdi, QWORD PTR [r9+664]
        cmove	r11, rdi
        cmp	sil, 8
        mov	rdi, QWORD PTR [r9+736]
        cmove	rax, rdi
        mov	rdi, QWORD PTR [r9+744]
        cmove	rdx, rdi
        mov	rdi, QWORD PTR [r9+752]
        cmove	r10, rdi
        mov	rdi, QWORD PTR [r9+760]
        cmove	r11, rdi
        mov	r12, -19
        mov	r13, -1
        mov	r14, -1
        mov	r15, 9223372036854775807
        sub	r12, rax
        sbb	r13, rdx
        sbb	r14, r10
        sbb	r15, r11
        cmp	r8b, 0
        cmovl	rax, r12
        cmovl	rdx, r13
        cmovl	r10, r14
        cmovl	r11, r15
        mov	QWORD PTR [rcx+64], rax
        mov	QWORD PTR [rcx+72], rdx
        mov	QWORD PTR [rcx+80], r10
        mov	QWORD PTR [rcx+88], r11
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
fe_cmov_table_x64 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
fe_mul_x64 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        mov	r9, rdx
        ; Multiply
        ;  A[0] * B[0]
        mov	rax, QWORD PTR [r8]
        mul	QWORD PTR [r9]
        mov	r10, rax
        mov	r11, rdx
        ;  A[0] * B[1]
        mov	rax, QWORD PTR [r8+8]
        mul	QWORD PTR [r9]
        xor	r12, r12
        add	r11, rax
        adc	r12, rdx
        ;  A[1] * B[0]
        mov	rax, QWORD PTR [r8]
        mul	QWORD PTR [r9+8]
        xor	r13, r13
        add	r11, rax
        adc	r12, rdx
        adc	r13, 0
        ;  A[0] * B[2]
        mov	rax, QWORD PTR [r8+16]
        mul	QWORD PTR [r9]
        add	r12, rax
        adc	r13, rdx
        ;  A[1] * B[1]
        mov	rax, QWORD PTR [r8+8]
        mul	QWORD PTR [r9+8]
        xor	r14, r14
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[2] * B[0]
        mov	rax, QWORD PTR [r8]
        mul	QWORD PTR [r9+16]
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[0] * B[3]
        mov	rax, QWORD PTR [r8+24]
        mul	QWORD PTR [r9]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[1] * B[2]
        mov	rax, QWORD PTR [r8+16]
        mul	QWORD PTR [r9+8]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[2] * B[1]
        mov	rax, QWORD PTR [r8+8]
        mul	QWORD PTR [r9+16]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[3] * B[0]
        mov	rax, QWORD PTR [r8]
        mul	QWORD PTR [r9+24]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[1] * B[3]
        mov	rax, QWORD PTR [r8+24]
        mul	QWORD PTR [r9+8]
        xor	rdi, rdi
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[2] * B[2]
        mov	rax, QWORD PTR [r8+16]
        mul	QWORD PTR [r9+16]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[3] * B[1]
        mov	rax, QWORD PTR [r8+8]
        mul	QWORD PTR [r9+24]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[2] * B[3]
        mov	rax, QWORD PTR [r8+24]
        mul	QWORD PTR [r9+16]
        xor	rsi, rsi
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[3] * B[2]
        mov	rax, QWORD PTR [r8+16]
        mul	QWORD PTR [r9+24]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[3] * B[3]
        mov	rax, QWORD PTR [r8+24]
        mul	QWORD PTR [r9+24]
        add	rdi, rax
        adc	rsi, rdx
        mov	rax, 38
        mul	rsi
        add	r13, rax
        adc	rdx, 0
        mov	rbx, 9223372036854775807
        shld	rdx, r13, 1
        imul	rdx, rdx, 19
        and	r13, rbx
        mov	rbx, rdx
        mov	rax, 38
        mul	r14
        xor	r14, r14
        add	r10, rax
        mov	rax, 38
        adc	r14, rdx
        mul	r15
        xor	r15, r15
        add	r11, rax
        mov	rax, 38
        adc	r15, rdx
        mul	rdi
        xor	rdi, rdi
        add	r12, rax
        adc	rdi, rdx
        add	r10, rbx
        adc	r11, r14
        adc	r12, r15
        adc	r13, rdi
        mov	rbx, 9223372036854775807
        mov	rax, r13
        sar	rax, 63
        and	rax, 19
        and	r13, rbx
        add	r10, rax
        adc	r11, 0
        adc	r12, 0
        adc	r13, 0
        ; Store
        mov	QWORD PTR [rcx], r10
        mov	QWORD PTR [rcx+8], r11
        mov	QWORD PTR [rcx+16], r12
        mov	QWORD PTR [rcx+24], r13
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
fe_mul_x64 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
fe_sq_x64 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        mov	r8, rdx
        ; Square
        ;  A[0] * A[1]
        mov	rax, QWORD PTR [r8]
        mul	QWORD PTR [r8+8]
        mov	r10, rax
        mov	r11, rdx
        ;  A[0] * A[2]
        mov	rax, QWORD PTR [r8]
        mul	QWORD PTR [r8+16]
        xor	r12, r12
        add	r11, rax
        adc	r12, rdx
        ;  A[0] * A[3]
        mov	rax, QWORD PTR [r8]
        mul	QWORD PTR [r8+24]
        xor	r13, r13
        add	r12, rax
        adc	r13, rdx
        ;  A[1] * A[2]
        mov	rax, QWORD PTR [r8+8]
        mul	QWORD PTR [r8+16]
        xor	r14, r14
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[1] * A[3]
        mov	rax, QWORD PTR [r8+8]
        mul	QWORD PTR [r8+24]
        add	r13, rax
        adc	r14, rdx
        ;  A[2] * A[3]
        mov	rax, QWORD PTR [r8+16]
        mul	QWORD PTR [r8+24]
        xor	r15, r15
        add	r14, rax
        adc	r15, rdx
        ; Double
        xor	rdi, rdi
        add	r10, r10
        adc	r11, r11
        adc	r12, r12
        adc	r13, r13
        adc	r14, r14
        adc	r15, r15
        adc	rdi, 0
        ;  A[0] * A[0]
        mov	rax, QWORD PTR [r8]
        mul	rax
        mov	r9, rax
        mov	rsi, rdx
        ;  A[1] * A[1]
        mov	rax, QWORD PTR [r8+8]
        mul	rax
        add	r10, rsi
        adc	r11, rax
        adc	rdx, 0
        mov	rsi, rdx
        ;  A[2] * A[2]
        mov	rax, QWORD PTR [r8+16]
        mul	rax
        add	r12, rsi
        adc	r13, rax
        adc	rdx, 0
        mov	rsi, rdx
        ;  A[3] * A[3]
        mov	rax, QWORD PTR [r8+24]
        mul	rax
        add	r15, rax
        adc	rdi, rdx
        add	r14, rsi
        adc	r15, 0
        adc	rdi, 0
        mov	rax, 38
        mul	rdi
        add	r12, rax
        adc	rdx, 0
        mov	rsi, 9223372036854775807
        shld	rdx, r12, 1
        imul	rdx, rdx, 19
        and	r12, rsi
        mov	rsi, rdx
        mov	rax, 38
        mul	r13
        xor	r13, r13
        add	r9, rax
        mov	rax, 38
        adc	r13, rdx
        mul	r14
        xor	r14, r14
        add	r10, rax
        mov	rax, 38
        adc	r14, rdx
        mul	r15
        xor	r15, r15
        add	r11, rax
        adc	r15, rdx
        add	r9, rsi
        adc	r10, r13
        adc	r11, r14
        adc	r12, r15
        mov	rsi, 9223372036854775807
        mov	rax, r12
        sar	rax, 63
        and	rax, 19
        and	r12, rsi
        add	r9, rax
        adc	r10, 0
        adc	r11, 0
        adc	r12, 0
        ; Store
        mov	QWORD PTR [rcx], r9
        mov	QWORD PTR [rcx+8], r10
        mov	QWORD PTR [rcx+16], r11
        mov	QWORD PTR [rcx+24], r12
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
fe_sq_x64 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
fe_sq_n_x64 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        mov	r9, rdx
L_fe_sq_n_x64:
        ; Square
        ;  A[0] * A[1]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r9+8]
        mov	r11, rax
        mov	r12, rdx
        ;  A[0] * A[2]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r9+16]
        xor	r13, r13
        add	r12, rax
        adc	r13, rdx
        ;  A[0] * A[3]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r9+24]
        xor	r14, r14
        add	r13, rax
        adc	r14, rdx
        ;  A[1] * A[2]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r9+16]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[1] * A[3]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r9+24]
        add	r14, rax
        adc	r15, rdx
        ;  A[2] * A[3]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r9+24]
        xor	rdi, rdi
        add	r15, rax
        adc	rdi, rdx
        ; Double
        xor	rsi, rsi
        add	r11, r11
        adc	r12, r12
        adc	r13, r13
        adc	r14, r14
        adc	r15, r15
        adc	rdi, rdi
        adc	rsi, 0
        ;  A[0] * A[0]
        mov	rax, QWORD PTR [r9]
        mul	rax
        mov	r10, rax
        mov	rbx, rdx
        ;  A[1] * A[1]
        mov	rax, QWORD PTR [r9+8]
        mul	rax
        add	r11, rbx
        adc	r12, rax
        adc	rdx, 0
        mov	rbx, rdx
        ;  A[2] * A[2]
        mov	rax, QWORD PTR [r9+16]
        mul	rax
        add	r13, rbx
        adc	r14, rax
        adc	rdx, 0
        mov	rbx, rdx
        ;  A[3] * A[3]
        mov	rax, QWORD PTR [r9+24]
        mul	rax
        add	rdi, rax
        adc	rsi, rdx
        add	r15, rbx
        adc	rdi, 0
        adc	rsi, 0
        mov	rax, 38
        mul	rsi
        add	r13, rax
        adc	rdx, 0
        mov	rbx, 9223372036854775807
        shld	rdx, r13, 1
        imul	rdx, rdx, 19
        and	r13, rbx
        mov	rbx, rdx
        mov	rax, 38
        mul	r14
        xor	r14, r14
        add	r10, rax
        mov	rax, 38
        adc	r14, rdx
        mul	r15
        xor	r15, r15
        add	r11, rax
        mov	rax, 38
        adc	r15, rdx
        mul	rdi
        xor	rdi, rdi
        add	r12, rax
        adc	rdi, rdx
        add	r10, rbx
        adc	r11, r14
        adc	r12, r15
        adc	r13, rdi
        ; Store
        mov	QWORD PTR [rcx], r10
        mov	QWORD PTR [rcx+8], r11
        mov	QWORD PTR [rcx+16], r12
        mov	QWORD PTR [rcx+24], r13
        dec	r8b
        jnz	L_fe_sq_n_x64
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
fe_sq_n_x64 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
fe_mul121666_x64 PROC
        push	r12
        push	r13
        push	r14
        mov	r8, rdx
        ; Multiply by 121666
        mov	rax, 121666
        mul	QWORD PTR [r8]
        xor	r12, r12
        mov	r10, rax
        mov	r11, rdx
        mov	rax, 121666
        mul	QWORD PTR [r8+8]
        xor	r13, r13
        add	r11, rax
        adc	r12, rdx
        mov	rax, 121666
        mul	QWORD PTR [r8+16]
        xor	r14, r14
        add	r12, rax
        adc	r13, rdx
        mov	rax, 121666
        mul	QWORD PTR [r8+24]
        mov	r9, 9223372036854775807
        add	r13, rax
        adc	r14, rdx
        shld	r14, r13, 1
        and	r13, r9
        mov	rax, 19
        mul	r14
        add	r10, rax
        adc	r11, 0
        adc	r12, 0
        adc	r13, 0
        mov	QWORD PTR [rcx], r10
        mov	QWORD PTR [rcx+8], r11
        mov	QWORD PTR [rcx+16], r12
        mov	QWORD PTR [rcx+24], r13
        pop	r14
        pop	r13
        pop	r12
        ret
fe_mul121666_x64 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
fe_invert_x64 PROC
        sub	rsp, 144
        ; Invert
        mov	QWORD PTR [rsp+128], rcx
        mov	QWORD PTR [rsp+136], rdx
        mov	rcx, rsp
        mov	rdx, QWORD PTR [rsp+136]
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+32]
        mov	rdx, rsp
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+32]
        mov	rdx, QWORD PTR [rsp+136]
        lea	r8, QWORD PTR [rsp+32]
        call	fe_mul_x64
        mov	rcx, rsp
        mov	rdx, rsp
        lea	r8, QWORD PTR [rsp+32]
        call	fe_mul_x64
        lea	rcx, QWORD PTR [rsp+64]
        mov	rdx, rsp
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        lea	r8, QWORD PTR [rsp+64]
        call	fe_mul_x64
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+32]
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        mov	r8, 4
        call	fe_sq_n_x64
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+64]
        lea	r8, QWORD PTR [rsp+32]
        call	fe_mul_x64
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+32]
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        mov	r8, 9
        call	fe_sq_n_x64
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        lea	r8, QWORD PTR [rsp+32]
        call	fe_mul_x64
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+64]
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 19
        call	fe_sq_n_x64
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        call	fe_mul_x64
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        mov	r8, 9
        call	fe_sq_n_x64
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+64]
        lea	r8, QWORD PTR [rsp+32]
        call	fe_mul_x64
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+32]
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        mov	r8, 49
        call	fe_sq_n_x64
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        lea	r8, QWORD PTR [rsp+32]
        call	fe_mul_x64
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+64]
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 99
        call	fe_sq_n_x64
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        call	fe_mul_x64
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        mov	r8, 49
        call	fe_sq_n_x64
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+64]
        lea	r8, QWORD PTR [rsp+32]
        call	fe_mul_x64
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, 4
        call	fe_sq_n_x64
        mov	rcx, QWORD PTR [rsp+128]
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, rsp
        call	fe_mul_x64
        mov	rdx, QWORD PTR [rsp+136]
        mov	rcx, QWORD PTR [rsp+128]
        add	rsp, 144
        ret
fe_invert_x64 ENDP
_TEXT ENDS
IFDEF WOLFSSL_CURVE25519_NOT_USE_ED25519
_DATA SEGMENT
ALIGN 16
L_curve25519_base_x64_x2 QWORD 5cae469cdd684efbh, 8f3f5ced1e350b5ch
        QWORD 0d9750c687d157114h, 20d342d51873f1b7h
ptr_L_curve25519_base_x64_x2 QWORD L_curve25519_base_x64_x2
_DATA ENDS
_TEXT SEGMENT READONLY PARA
curve25519_base_x64 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        push	rbp
        mov	r8, rcx
        mov	r9, rdx
        sub	rsp, 168
        xor	rsi, rsi
        mov	QWORD PTR [rsp+160], r8
        ; Set base point x
        mov	QWORD PTR [r8], 9
        mov	QWORD PTR [r8+8], 0
        mov	QWORD PTR [r8+16], 0
        mov	QWORD PTR [r8+24], 0
        ; Set one
        mov	QWORD PTR [rsp], 1
        mov	QWORD PTR [rsp+8], 0
        mov	QWORD PTR [rsp+16], 0
        mov	QWORD PTR [rsp+24], 0
        mov	rcx, QWORD PTR [ptr_L_curve25519_base_x64_x2]
        mov	r10, QWORD PTR [ptr_L_curve25519_base_x64_x2+8]
        mov	r11, QWORD PTR [ptr_L_curve25519_base_x64_x2+16]
        mov	r12, QWORD PTR [ptr_L_curve25519_base_x64_x2+24]
        ; Set one
        mov	QWORD PTR [rsp+32], 1
        mov	QWORD PTR [rsp+40], 0
        mov	QWORD PTR [rsp+48], 0
        mov	QWORD PTR [rsp+56], 0
        mov	QWORD PTR [rsp+64], rcx
        mov	QWORD PTR [rsp+72], r10
        mov	QWORD PTR [rsp+80], r11
        mov	QWORD PTR [rsp+88], r12
        mov	rbp, 253
L_curve25519_base_x64_bits:
        mov	r10, rbp
        mov	rcx, rbp
        and	rcx, 63
        shr	r10, 6
        mov	rbx, QWORD PTR [r9+8*r10]
        shr	rbx, cl
        and	rbx, 1
        xor	rsi, rbx
        neg	rsi
        ; Conditional Swap
        mov	rcx, QWORD PTR [r8]
        mov	r10, QWORD PTR [r8+8]
        mov	r11, QWORD PTR [r8+16]
        mov	r12, QWORD PTR [r8+24]
        mov	r13, QWORD PTR [rsp]
        mov	r14, QWORD PTR [rsp+8]
        mov	r15, QWORD PTR [rsp+16]
        mov	rdi, QWORD PTR [rsp+24]
        xor	rcx, QWORD PTR [rsp+64]
        xor	r10, QWORD PTR [rsp+72]
        xor	r11, QWORD PTR [rsp+80]
        xor	r12, QWORD PTR [rsp+88]
        xor	r13, QWORD PTR [rsp+32]
        xor	r14, QWORD PTR [rsp+40]
        xor	r15, QWORD PTR [rsp+48]
        xor	rdi, QWORD PTR [rsp+56]
        and	rcx, rsi
        and	r10, rsi
        and	r11, rsi
        and	r12, rsi
        and	r13, rsi
        and	r14, rsi
        and	r15, rsi
        and	rdi, rsi
        xor	QWORD PTR [r8], rcx
        xor	QWORD PTR [r8+8], r10
        xor	QWORD PTR [r8+16], r11
        xor	QWORD PTR [r8+24], r12
        xor	QWORD PTR [rsp], r13
        xor	QWORD PTR [rsp+8], r14
        xor	QWORD PTR [rsp+16], r15
        xor	QWORD PTR [rsp+24], rdi
        xor	QWORD PTR [rsp+64], rcx
        xor	QWORD PTR [rsp+72], r10
        xor	QWORD PTR [rsp+80], r11
        xor	QWORD PTR [rsp+88], r12
        xor	QWORD PTR [rsp+32], r13
        xor	QWORD PTR [rsp+40], r14
        xor	QWORD PTR [rsp+48], r15
        xor	QWORD PTR [rsp+56], rdi
        mov	rsi, rbx
        ; Add-Sub
        ; Add
        mov	rcx, QWORD PTR [r8]
        mov	r10, QWORD PTR [r8+8]
        mov	r11, QWORD PTR [r8+16]
        mov	r12, QWORD PTR [r8+24]
        mov	r13, rcx
        add	rcx, QWORD PTR [rsp]
        mov	r14, r10
        adc	r10, QWORD PTR [rsp+8]
        mov	r15, r11
        adc	r11, QWORD PTR [rsp+16]
        mov	rdi, r12
        adc	r12, QWORD PTR [rsp+24]
        mov	rbx, 0
        adc	rbx, 0
        shld	rbx, r12, 1
        imul	rbx, 19
        btr	r12, 63
        ;   Sub modulus (if overflow)
        add	rcx, rbx
        adc	r10, 0
        adc	r11, 0
        adc	r12, 0
        ; Sub
        sub	r13, QWORD PTR [rsp]
        sbb	r14, QWORD PTR [rsp+8]
        sbb	r15, QWORD PTR [rsp+16]
        sbb	rdi, QWORD PTR [rsp+24]
        sbb	rbx, rbx
        shld	rbx, rdi, 1
        imul	rbx, -19
        btr	rdi, 63
        ;   Add modulus (if underflow)
        sub	r13, rbx
        sbb	r14, 0
        sbb	r15, 0
        sbb	rdi, 0
        mov	QWORD PTR [r8], rcx
        mov	QWORD PTR [r8+8], r10
        mov	QWORD PTR [r8+16], r11
        mov	QWORD PTR [r8+24], r12
        mov	QWORD PTR [rsp+128], r13
        mov	QWORD PTR [rsp+136], r14
        mov	QWORD PTR [rsp+144], r15
        mov	QWORD PTR [rsp+152], rdi
        ; Add-Sub
        ; Add
        mov	rcx, QWORD PTR [rsp+64]
        mov	r10, QWORD PTR [rsp+72]
        mov	r11, QWORD PTR [rsp+80]
        mov	r12, QWORD PTR [rsp+88]
        mov	r13, rcx
        add	rcx, QWORD PTR [rsp+32]
        mov	r14, r10
        adc	r10, QWORD PTR [rsp+40]
        mov	r15, r11
        adc	r11, QWORD PTR [rsp+48]
        mov	rdi, r12
        adc	r12, QWORD PTR [rsp+56]
        mov	rbx, 0
        adc	rbx, 0
        shld	rbx, r12, 1
        imul	rbx, 19
        btr	r12, 63
        ;   Sub modulus (if overflow)
        add	rcx, rbx
        adc	r10, 0
        adc	r11, 0
        adc	r12, 0
        ; Sub
        sub	r13, QWORD PTR [rsp+32]
        sbb	r14, QWORD PTR [rsp+40]
        sbb	r15, QWORD PTR [rsp+48]
        sbb	rdi, QWORD PTR [rsp+56]
        sbb	rbx, rbx
        shld	rbx, rdi, 1
        imul	rbx, -19
        btr	rdi, 63
        ;   Add modulus (if underflow)
        sub	r13, rbx
        sbb	r14, 0
        sbb	r15, 0
        sbb	rdi, 0
        mov	QWORD PTR [rsp+32], rcx
        mov	QWORD PTR [rsp+40], r10
        mov	QWORD PTR [rsp+48], r11
        mov	QWORD PTR [rsp+56], r12
        mov	QWORD PTR [rsp+96], r13
        mov	QWORD PTR [rsp+104], r14
        mov	QWORD PTR [rsp+112], r15
        mov	QWORD PTR [rsp+120], rdi
        ; Multiply
        ;  A[0] * B[0]
        mov	rax, QWORD PTR [rsp+128]
        mul	QWORD PTR [rsp+32]
        mov	rcx, rax
        mov	r10, rdx
        ;  A[0] * B[1]
        mov	rax, QWORD PTR [rsp+136]
        mul	QWORD PTR [rsp+32]
        xor	r11, r11
        add	r10, rax
        adc	r11, rdx
        ;  A[1] * B[0]
        mov	rax, QWORD PTR [rsp+128]
        mul	QWORD PTR [rsp+40]
        xor	r12, r12
        add	r10, rax
        adc	r11, rdx
        adc	r12, 0
        ;  A[0] * B[2]
        mov	rax, QWORD PTR [rsp+144]
        mul	QWORD PTR [rsp+32]
        add	r11, rax
        adc	r12, rdx
        ;  A[1] * B[1]
        mov	rax, QWORD PTR [rsp+136]
        mul	QWORD PTR [rsp+40]
        xor	r13, r13
        add	r11, rax
        adc	r12, rdx
        adc	r13, 0
        ;  A[2] * B[0]
        mov	rax, QWORD PTR [rsp+128]
        mul	QWORD PTR [rsp+48]
        add	r11, rax
        adc	r12, rdx
        adc	r13, 0
        ;  A[0] * B[3]
        mov	rax, QWORD PTR [rsp+152]
        mul	QWORD PTR [rsp+32]
        xor	r14, r14
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[1] * B[2]
        mov	rax, QWORD PTR [rsp+144]
        mul	QWORD PTR [rsp+40]
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[2] * B[1]
        mov	rax, QWORD PTR [rsp+136]
        mul	QWORD PTR [rsp+48]
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[3] * B[0]
        mov	rax, QWORD PTR [rsp+128]
        mul	QWORD PTR [rsp+56]
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[1] * B[3]
        mov	rax, QWORD PTR [rsp+152]
        mul	QWORD PTR [rsp+40]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[2] * B[2]
        mov	rax, QWORD PTR [rsp+144]
        mul	QWORD PTR [rsp+48]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[3] * B[1]
        mov	rax, QWORD PTR [rsp+136]
        mul	QWORD PTR [rsp+56]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[2] * B[3]
        mov	rax, QWORD PTR [rsp+152]
        mul	QWORD PTR [rsp+48]
        xor	rdi, rdi
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[3] * B[2]
        mov	rax, QWORD PTR [rsp+144]
        mul	QWORD PTR [rsp+56]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[3] * B[3]
        mov	rax, QWORD PTR [rsp+152]
        mul	QWORD PTR [rsp+56]
        add	r15, rax
        adc	rdi, rdx
        mov	rax, 38
        mul	rdi
        add	r12, rax
        adc	rdx, 0
        mov	rbx, 9223372036854775807
        shld	rdx, r12, 1
        imul	rdx, rdx, 19
        and	r12, rbx
        mov	rbx, rdx
        mov	rax, 38
        mul	r13
        xor	r13, r13
        add	rcx, rax
        mov	rax, 38
        adc	r13, rdx
        mul	r14
        xor	r14, r14
        add	r10, rax
        mov	rax, 38
        adc	r14, rdx
        mul	r15
        xor	r15, r15
        add	r11, rax
        adc	r15, rdx
        add	rcx, rbx
        adc	r10, r13
        adc	r11, r14
        adc	r12, r15
        ; Store
        mov	QWORD PTR [rsp+32], rcx
        mov	QWORD PTR [rsp+40], r10
        mov	QWORD PTR [rsp+48], r11
        mov	QWORD PTR [rsp+56], r12
        ; Multiply
        ;  A[0] * B[0]
        mov	rax, QWORD PTR [r8]
        mul	QWORD PTR [rsp+96]
        mov	rcx, rax
        mov	r10, rdx
        ;  A[0] * B[1]
        mov	rax, QWORD PTR [r8+8]
        mul	QWORD PTR [rsp+96]
        xor	r11, r11
        add	r10, rax
        adc	r11, rdx
        ;  A[1] * B[0]
        mov	rax, QWORD PTR [r8]
        mul	QWORD PTR [rsp+104]
        xor	r12, r12
        add	r10, rax
        adc	r11, rdx
        adc	r12, 0
        ;  A[0] * B[2]
        mov	rax, QWORD PTR [r8+16]
        mul	QWORD PTR [rsp+96]
        add	r11, rax
        adc	r12, rdx
        ;  A[1] * B[1]
        mov	rax, QWORD PTR [r8+8]
        mul	QWORD PTR [rsp+104]
        xor	r13, r13
        add	r11, rax
        adc	r12, rdx
        adc	r13, 0
        ;  A[2] * B[0]
        mov	rax, QWORD PTR [r8]
        mul	QWORD PTR [rsp+112]
        add	r11, rax
        adc	r12, rdx
        adc	r13, 0
        ;  A[0] * B[3]
        mov	rax, QWORD PTR [r8+24]
        mul	QWORD PTR [rsp+96]
        xor	r14, r14
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[1] * B[2]
        mov	rax, QWORD PTR [r8+16]
        mul	QWORD PTR [rsp+104]
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[2] * B[1]
        mov	rax, QWORD PTR [r8+8]
        mul	QWORD PTR [rsp+112]
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[3] * B[0]
        mov	rax, QWORD PTR [r8]
        mul	QWORD PTR [rsp+120]
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[1] * B[3]
        mov	rax, QWORD PTR [r8+24]
        mul	QWORD PTR [rsp+104]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[2] * B[2]
        mov	rax, QWORD PTR [r8+16]
        mul	QWORD PTR [rsp+112]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[3] * B[1]
        mov	rax, QWORD PTR [r8+8]
        mul	QWORD PTR [rsp+120]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[2] * B[3]
        mov	rax, QWORD PTR [r8+24]
        mul	QWORD PTR [rsp+112]
        xor	rdi, rdi
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[3] * B[2]
        mov	rax, QWORD PTR [r8+16]
        mul	QWORD PTR [rsp+120]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[3] * B[3]
        mov	rax, QWORD PTR [r8+24]
        mul	QWORD PTR [rsp+120]
        add	r15, rax
        adc	rdi, rdx
        mov	rax, 38
        mul	rdi
        add	r12, rax
        adc	rdx, 0
        mov	rbx, 9223372036854775807
        shld	rdx, r12, 1
        imul	rdx, rdx, 19
        and	r12, rbx
        mov	rbx, rdx
        mov	rax, 38
        mul	r13
        xor	r13, r13
        add	rcx, rax
        mov	rax, 38
        adc	r13, rdx
        mul	r14
        xor	r14, r14
        add	r10, rax
        mov	rax, 38
        adc	r14, rdx
        mul	r15
        xor	r15, r15
        add	r11, rax
        adc	r15, rdx
        add	rcx, rbx
        adc	r10, r13
        adc	r11, r14
        adc	r12, r15
        ; Store
        mov	QWORD PTR [rsp], rcx
        mov	QWORD PTR [rsp+8], r10
        mov	QWORD PTR [rsp+16], r11
        mov	QWORD PTR [rsp+24], r12
        ; Square
        ;  A[0] * A[1]
        mov	rax, QWORD PTR [rsp+128]
        mul	QWORD PTR [rsp+136]
        mov	r10, rax
        mov	r11, rdx
        ;  A[0] * A[2]
        mov	rax, QWORD PTR [rsp+128]
        mul	QWORD PTR [rsp+144]
        xor	r12, r12
        add	r11, rax
        adc	r12, rdx
        ;  A[0] * A[3]
        mov	rax, QWORD PTR [rsp+128]
        mul	QWORD PTR [rsp+152]
        xor	r13, r13
        add	r12, rax
        adc	r13, rdx
        ;  A[1] * A[2]
        mov	rax, QWORD PTR [rsp+136]
        mul	QWORD PTR [rsp+144]
        xor	r14, r14
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[1] * A[3]
        mov	rax, QWORD PTR [rsp+136]
        mul	QWORD PTR [rsp+152]
        add	r13, rax
        adc	r14, rdx
        ;  A[2] * A[3]
        mov	rax, QWORD PTR [rsp+144]
        mul	QWORD PTR [rsp+152]
        xor	r15, r15
        add	r14, rax
        adc	r15, rdx
        ; Double
        xor	rdi, rdi
        add	r10, r10
        adc	r11, r11
        adc	r12, r12
        adc	r13, r13
        adc	r14, r14
        adc	r15, r15
        adc	rdi, 0
        ;  A[0] * A[0]
        mov	rax, QWORD PTR [rsp+128]
        mul	rax
        mov	rcx, rax
        mov	rbx, rdx
        ;  A[1] * A[1]
        mov	rax, QWORD PTR [rsp+136]
        mul	rax
        add	r10, rbx
        adc	r11, rax
        adc	rdx, 0
        mov	rbx, rdx
        ;  A[2] * A[2]
        mov	rax, QWORD PTR [rsp+144]
        mul	rax
        add	r12, rbx
        adc	r13, rax
        adc	rdx, 0
        mov	rbx, rdx
        ;  A[3] * A[3]
        mov	rax, QWORD PTR [rsp+152]
        mul	rax
        add	r15, rax
        adc	rdi, rdx
        add	r14, rbx
        adc	r15, 0
        adc	rdi, 0
        mov	rax, 38
        mul	rdi
        add	r12, rax
        adc	rdx, 0
        mov	rbx, 9223372036854775807
        shld	rdx, r12, 1
        imul	rdx, rdx, 19
        and	r12, rbx
        mov	rbx, rdx
        mov	rax, 38
        mul	r13
        xor	r13, r13
        add	rcx, rax
        mov	rax, 38
        adc	r13, rdx
        mul	r14
        xor	r14, r14
        add	r10, rax
        mov	rax, 38
        adc	r14, rdx
        mul	r15
        xor	r15, r15
        add	r11, rax
        adc	r15, rdx
        add	rcx, rbx
        adc	r10, r13
        adc	r11, r14
        adc	r12, r15
        ; Store
        mov	QWORD PTR [rsp+96], rcx
        mov	QWORD PTR [rsp+104], r10
        mov	QWORD PTR [rsp+112], r11
        mov	QWORD PTR [rsp+120], r12
        ; Square
        ;  A[0] * A[1]
        mov	rax, QWORD PTR [r8]
        mul	QWORD PTR [r8+8]
        mov	r10, rax
        mov	r11, rdx
        ;  A[0] * A[2]
        mov	rax, QWORD PTR [r8]
        mul	QWORD PTR [r8+16]
        xor	r12, r12
        add	r11, rax
        adc	r12, rdx
        ;  A[0] * A[3]
        mov	rax, QWORD PTR [r8]
        mul	QWORD PTR [r8+24]
        xor	r13, r13
        add	r12, rax
        adc	r13, rdx
        ;  A[1] * A[2]
        mov	rax, QWORD PTR [r8+8]
        mul	QWORD PTR [r8+16]
        xor	r14, r14
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[1] * A[3]
        mov	rax, QWORD PTR [r8+8]
        mul	QWORD PTR [r8+24]
        add	r13, rax
        adc	r14, rdx
        ;  A[2] * A[3]
        mov	rax, QWORD PTR [r8+16]
        mul	QWORD PTR [r8+24]
        xor	r15, r15
        add	r14, rax
        adc	r15, rdx
        ; Double
        xor	rdi, rdi
        add	r10, r10
        adc	r11, r11
        adc	r12, r12
        adc	r13, r13
        adc	r14, r14
        adc	r15, r15
        adc	rdi, 0
        ;  A[0] * A[0]
        mov	rax, QWORD PTR [r8]
        mul	rax
        mov	rcx, rax
        mov	rbx, rdx
        ;  A[1] * A[1]
        mov	rax, QWORD PTR [r8+8]
        mul	rax
        add	r10, rbx
        adc	r11, rax
        adc	rdx, 0
        mov	rbx, rdx
        ;  A[2] * A[2]
        mov	rax, QWORD PTR [r8+16]
        mul	rax
        add	r12, rbx
        adc	r13, rax
        adc	rdx, 0
        mov	rbx, rdx
        ;  A[3] * A[3]
        mov	rax, QWORD PTR [r8+24]
        mul	rax
        add	r15, rax
        adc	rdi, rdx
        add	r14, rbx
        adc	r15, 0
        adc	rdi, 0
        mov	rax, 38
        mul	rdi
        add	r12, rax
        adc	rdx, 0
        mov	rbx, 9223372036854775807
        shld	rdx, r12, 1
        imul	rdx, rdx, 19
        and	r12, rbx
        mov	rbx, rdx
        mov	rax, 38
        mul	r13
        xor	r13, r13
        add	rcx, rax
        mov	rax, 38
        adc	r13, rdx
        mul	r14
        xor	r14, r14
        add	r10, rax
        mov	rax, 38
        adc	r14, rdx
        mul	r15
        xor	r15, r15
        add	r11, rax
        adc	r15, rdx
        add	rcx, rbx
        adc	r10, r13
        adc	r11, r14
        adc	r12, r15
        ; Store
        mov	QWORD PTR [rsp+128], rcx
        mov	QWORD PTR [rsp+136], r10
        mov	QWORD PTR [rsp+144], r11
        mov	QWORD PTR [rsp+152], r12
        ; Add-Sub
        ; Add
        mov	rcx, QWORD PTR [rsp]
        mov	r10, QWORD PTR [rsp+8]
        mov	r11, QWORD PTR [rsp+16]
        mov	r12, QWORD PTR [rsp+24]
        mov	r13, rcx
        add	rcx, QWORD PTR [rsp+32]
        mov	r14, r10
        adc	r10, QWORD PTR [rsp+40]
        mov	r15, r11
        adc	r11, QWORD PTR [rsp+48]
        mov	rdi, r12
        adc	r12, QWORD PTR [rsp+56]
        mov	rbx, 0
        adc	rbx, 0
        shld	rbx, r12, 1
        imul	rbx, 19
        btr	r12, 63
        ;   Sub modulus (if overflow)
        add	rcx, rbx
        adc	r10, 0
        adc	r11, 0
        adc	r12, 0
        ; Sub
        sub	r13, QWORD PTR [rsp+32]
        sbb	r14, QWORD PTR [rsp+40]
        sbb	r15, QWORD PTR [rsp+48]
        sbb	rdi, QWORD PTR [rsp+56]
        sbb	rbx, rbx
        shld	rbx, rdi, 1
        imul	rbx, -19
        btr	rdi, 63
        ;   Add modulus (if underflow)
        sub	r13, rbx
        sbb	r14, 0
        sbb	r15, 0
        sbb	rdi, 0
        mov	QWORD PTR [rsp+64], rcx
        mov	QWORD PTR [rsp+72], r10
        mov	QWORD PTR [rsp+80], r11
        mov	QWORD PTR [rsp+88], r12
        mov	QWORD PTR [rsp+32], r13
        mov	QWORD PTR [rsp+40], r14
        mov	QWORD PTR [rsp+48], r15
        mov	QWORD PTR [rsp+56], rdi
        ; Multiply
        ;  A[0] * B[0]
        mov	rax, QWORD PTR [rsp+96]
        mul	QWORD PTR [rsp+128]
        mov	rcx, rax
        mov	r10, rdx
        ;  A[0] * B[1]
        mov	rax, QWORD PTR [rsp+104]
        mul	QWORD PTR [rsp+128]
        xor	r11, r11
        add	r10, rax
        adc	r11, rdx
        ;  A[1] * B[0]
        mov	rax, QWORD PTR [rsp+96]
        mul	QWORD PTR [rsp+136]
        xor	r12, r12
        add	r10, rax
        adc	r11, rdx
        adc	r12, 0
        ;  A[0] * B[2]
        mov	rax, QWORD PTR [rsp+112]
        mul	QWORD PTR [rsp+128]
        add	r11, rax
        adc	r12, rdx
        ;  A[1] * B[1]
        mov	rax, QWORD PTR [rsp+104]
        mul	QWORD PTR [rsp+136]
        xor	r13, r13
        add	r11, rax
        adc	r12, rdx
        adc	r13, 0
        ;  A[2] * B[0]
        mov	rax, QWORD PTR [rsp+96]
        mul	QWORD PTR [rsp+144]
        add	r11, rax
        adc	r12, rdx
        adc	r13, 0
        ;  A[0] * B[3]
        mov	rax, QWORD PTR [rsp+120]
        mul	QWORD PTR [rsp+128]
        xor	r14, r14
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[1] * B[2]
        mov	rax, QWORD PTR [rsp+112]
        mul	QWORD PTR [rsp+136]
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[2] * B[1]
        mov	rax, QWORD PTR [rsp+104]
        mul	QWORD PTR [rsp+144]
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[3] * B[0]
        mov	rax, QWORD PTR [rsp+96]
        mul	QWORD PTR [rsp+152]
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[1] * B[3]
        mov	rax, QWORD PTR [rsp+120]
        mul	QWORD PTR [rsp+136]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[2] * B[2]
        mov	rax, QWORD PTR [rsp+112]
        mul	QWORD PTR [rsp+144]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[3] * B[1]
        mov	rax, QWORD PTR [rsp+104]
        mul	QWORD PTR [rsp+152]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[2] * B[3]
        mov	rax, QWORD PTR [rsp+120]
        mul	QWORD PTR [rsp+144]
        xor	rdi, rdi
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[3] * B[2]
        mov	rax, QWORD PTR [rsp+112]
        mul	QWORD PTR [rsp+152]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[3] * B[3]
        mov	rax, QWORD PTR [rsp+120]
        mul	QWORD PTR [rsp+152]
        add	r15, rax
        adc	rdi, rdx
        mov	rax, 38
        mul	rdi
        add	r12, rax
        adc	rdx, 0
        mov	rbx, 9223372036854775807
        shld	rdx, r12, 1
        imul	rdx, rdx, 19
        and	r12, rbx
        mov	rbx, rdx
        mov	rax, 38
        mul	r13
        xor	r13, r13
        add	rcx, rax
        mov	rax, 38
        adc	r13, rdx
        mul	r14
        xor	r14, r14
        add	r10, rax
        mov	rax, 38
        adc	r14, rdx
        mul	r15
        xor	r15, r15
        add	r11, rax
        adc	r15, rdx
        add	rcx, rbx
        adc	r10, r13
        adc	r11, r14
        adc	r12, r15
        ; Store
        mov	QWORD PTR [r8], rcx
        mov	QWORD PTR [r8+8], r10
        mov	QWORD PTR [r8+16], r11
        mov	QWORD PTR [r8+24], r12
        ; Sub
        mov	rcx, QWORD PTR [rsp+128]
        mov	r10, QWORD PTR [rsp+136]
        mov	r11, QWORD PTR [rsp+144]
        mov	r12, QWORD PTR [rsp+152]
        sub	rcx, QWORD PTR [rsp+96]
        sbb	r10, QWORD PTR [rsp+104]
        sbb	r11, QWORD PTR [rsp+112]
        sbb	r12, QWORD PTR [rsp+120]
        sbb	rbx, rbx
        shld	rbx, r12, 1
        imul	rbx, -19
        btr	r12, 63
        ;   Add modulus (if underflow)
        sub	rcx, rbx
        sbb	r10, 0
        sbb	r11, 0
        sbb	r12, 0
        mov	QWORD PTR [rsp+128], rcx
        mov	QWORD PTR [rsp+136], r10
        mov	QWORD PTR [rsp+144], r11
        mov	QWORD PTR [rsp+152], r12
        ; Square
        ;  A[0] * A[1]
        mov	rax, QWORD PTR [rsp+32]
        mul	QWORD PTR [rsp+40]
        mov	r10, rax
        mov	r11, rdx
        ;  A[0] * A[2]
        mov	rax, QWORD PTR [rsp+32]
        mul	QWORD PTR [rsp+48]
        xor	r12, r12
        add	r11, rax
        adc	r12, rdx
        ;  A[0] * A[3]
        mov	rax, QWORD PTR [rsp+32]
        mul	QWORD PTR [rsp+56]
        xor	r13, r13
        add	r12, rax
        adc	r13, rdx
        ;  A[1] * A[2]
        mov	rax, QWORD PTR [rsp+40]
        mul	QWORD PTR [rsp+48]
        xor	r14, r14
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[1] * A[3]
        mov	rax, QWORD PTR [rsp+40]
        mul	QWORD PTR [rsp+56]
        add	r13, rax
        adc	r14, rdx
        ;  A[2] * A[3]
        mov	rax, QWORD PTR [rsp+48]
        mul	QWORD PTR [rsp+56]
        xor	r15, r15
        add	r14, rax
        adc	r15, rdx
        ; Double
        xor	rdi, rdi
        add	r10, r10
        adc	r11, r11
        adc	r12, r12
        adc	r13, r13
        adc	r14, r14
        adc	r15, r15
        adc	rdi, 0
        ;  A[0] * A[0]
        mov	rax, QWORD PTR [rsp+32]
        mul	rax
        mov	rcx, rax
        mov	rbx, rdx
        ;  A[1] * A[1]
        mov	rax, QWORD PTR [rsp+40]
        mul	rax
        add	r10, rbx
        adc	r11, rax
        adc	rdx, 0
        mov	rbx, rdx
        ;  A[2] * A[2]
        mov	rax, QWORD PTR [rsp+48]
        mul	rax
        add	r12, rbx
        adc	r13, rax
        adc	rdx, 0
        mov	rbx, rdx
        ;  A[3] * A[3]
        mov	rax, QWORD PTR [rsp+56]
        mul	rax
        add	r15, rax
        adc	rdi, rdx
        add	r14, rbx
        adc	r15, 0
        adc	rdi, 0
        mov	rax, 38
        mul	rdi
        add	r12, rax
        adc	rdx, 0
        mov	rbx, 9223372036854775807
        shld	rdx, r12, 1
        imul	rdx, rdx, 19
        and	r12, rbx
        mov	rbx, rdx
        mov	rax, 38
        mul	r13
        xor	r13, r13
        add	rcx, rax
        mov	rax, 38
        adc	r13, rdx
        mul	r14
        xor	r14, r14
        add	r10, rax
        mov	rax, 38
        adc	r14, rdx
        mul	r15
        xor	r15, r15
        add	r11, rax
        adc	r15, rdx
        add	rcx, rbx
        adc	r10, r13
        adc	r11, r14
        adc	r12, r15
        ; Store
        mov	QWORD PTR [rsp+32], rcx
        mov	QWORD PTR [rsp+40], r10
        mov	QWORD PTR [rsp+48], r11
        mov	QWORD PTR [rsp+56], r12
        ; Square
        ;  A[0] * A[1]
        mov	rax, QWORD PTR [rsp+64]
        mul	QWORD PTR [rsp+72]
        mov	r10, rax
        mov	r11, rdx
        ;  A[0] * A[2]
        mov	rax, QWORD PTR [rsp+64]
        mul	QWORD PTR [rsp+80]
        xor	r12, r12
        add	r11, rax
        adc	r12, rdx
        ;  A[0] * A[3]
        mov	rax, QWORD PTR [rsp+64]
        mul	QWORD PTR [rsp+88]
        xor	r13, r13
        add	r12, rax
        adc	r13, rdx
        ;  A[1] * A[2]
        mov	rax, QWORD PTR [rsp+72]
        mul	QWORD PTR [rsp+80]
        xor	r14, r14
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[1] * A[3]
        mov	rax, QWORD PTR [rsp+72]
        mul	QWORD PTR [rsp+88]
        add	r13, rax
        adc	r14, rdx
        ;  A[2] * A[3]
        mov	rax, QWORD PTR [rsp+80]
        mul	QWORD PTR [rsp+88]
        xor	r15, r15
        add	r14, rax
        adc	r15, rdx
        ; Double
        xor	rdi, rdi
        add	r10, r10
        adc	r11, r11
        adc	r12, r12
        adc	r13, r13
        adc	r14, r14
        adc	r15, r15
        adc	rdi, 0
        ;  A[0] * A[0]
        mov	rax, QWORD PTR [rsp+64]
        mul	rax
        mov	rcx, rax
        mov	rbx, rdx
        ;  A[1] * A[1]
        mov	rax, QWORD PTR [rsp+72]
        mul	rax
        add	r10, rbx
        adc	r11, rax
        adc	rdx, 0
        mov	rbx, rdx
        ;  A[2] * A[2]
        mov	rax, QWORD PTR [rsp+80]
        mul	rax
        add	r12, rbx
        adc	r13, rax
        adc	rdx, 0
        mov	rbx, rdx
        ;  A[3] * A[3]
        mov	rax, QWORD PTR [rsp+88]
        mul	rax
        add	r15, rax
        adc	rdi, rdx
        add	r14, rbx
        adc	r15, 0
        adc	rdi, 0
        mov	rax, 38
        mul	rdi
        add	r12, rax
        adc	rdx, 0
        mov	rbx, 9223372036854775807
        shld	rdx, r12, 1
        imul	rdx, rdx, 19
        and	r12, rbx
        mov	rbx, rdx
        mov	rax, 38
        mul	r13
        xor	r13, r13
        add	rcx, rax
        mov	rax, 38
        adc	r13, rdx
        mul	r14
        xor	r14, r14
        add	r10, rax
        mov	rax, 38
        adc	r14, rdx
        mul	r15
        xor	r15, r15
        add	r11, rax
        adc	r15, rdx
        add	rcx, rbx
        adc	r10, r13
        adc	r11, r14
        adc	r12, r15
        ; Store
        mov	QWORD PTR [rsp+64], rcx
        mov	QWORD PTR [rsp+72], r10
        mov	QWORD PTR [rsp+80], r11
        mov	QWORD PTR [rsp+88], r12
        ; Multiply by 121666
        mov	rax, 121666
        mul	QWORD PTR [rsp+128]
        xor	r11, r11
        mov	rcx, rax
        mov	r10, rdx
        mov	rax, 121666
        mul	QWORD PTR [rsp+136]
        xor	r12, r12
        add	r10, rax
        adc	r11, rdx
        mov	rax, 121666
        mul	QWORD PTR [rsp+144]
        xor	r14, r14
        add	r11, rax
        adc	r12, rdx
        mov	rax, 121666
        mul	QWORD PTR [rsp+152]
        mov	r13, 9223372036854775807
        add	r12, rax
        adc	r14, rdx
        add	rcx, QWORD PTR [rsp+96]
        adc	r10, QWORD PTR [rsp+104]
        adc	r11, QWORD PTR [rsp+112]
        adc	r12, QWORD PTR [rsp+120]
        adc	r14, 0
        shld	r14, r12, 1
        and	r12, r13
        mov	rax, 19
        mul	r14
        add	rcx, rax
        adc	r10, 0
        adc	r11, 0
        adc	r12, 0
        mov	QWORD PTR [rsp+96], rcx
        mov	QWORD PTR [rsp+104], r10
        mov	QWORD PTR [rsp+112], r11
        mov	QWORD PTR [rsp+120], r12
        ; Multiply by 9
        mov	rax, 9
        mul	QWORD PTR [rsp+32]
        xor	r11, r11
        mov	rcx, rax
        mov	r10, rdx
        mov	rax, 9
        mul	QWORD PTR [rsp+40]
        xor	r12, r12
        add	r10, rax
        adc	r11, rdx
        mov	rax, 9
        mul	QWORD PTR [rsp+48]
        xor	r14, r14
        add	r11, rax
        adc	r12, rdx
        mov	rax, 9
        mul	QWORD PTR [rsp+56]
        mov	r13, 9223372036854775807
        add	r12, rax
        adc	r14, rdx
        shld	r14, r12, 1
        and	r12, r13
        mov	rax, 19
        mul	r14
        add	rcx, rax
        adc	r10, 0
        adc	r11, 0
        adc	r12, 0
        mov	QWORD PTR [rsp+32], rcx
        mov	QWORD PTR [rsp+40], r10
        mov	QWORD PTR [rsp+48], r11
        mov	QWORD PTR [rsp+56], r12
        ; Multiply
        ;  A[0] * B[0]
        mov	rax, QWORD PTR [rsp+96]
        mul	QWORD PTR [rsp+128]
        mov	rcx, rax
        mov	r10, rdx
        ;  A[0] * B[1]
        mov	rax, QWORD PTR [rsp+104]
        mul	QWORD PTR [rsp+128]
        xor	r11, r11
        add	r10, rax
        adc	r11, rdx
        ;  A[1] * B[0]
        mov	rax, QWORD PTR [rsp+96]
        mul	QWORD PTR [rsp+136]
        xor	r12, r12
        add	r10, rax
        adc	r11, rdx
        adc	r12, 0
        ;  A[0] * B[2]
        mov	rax, QWORD PTR [rsp+112]
        mul	QWORD PTR [rsp+128]
        add	r11, rax
        adc	r12, rdx
        ;  A[1] * B[1]
        mov	rax, QWORD PTR [rsp+104]
        mul	QWORD PTR [rsp+136]
        xor	r13, r13
        add	r11, rax
        adc	r12, rdx
        adc	r13, 0
        ;  A[2] * B[0]
        mov	rax, QWORD PTR [rsp+96]
        mul	QWORD PTR [rsp+144]
        add	r11, rax
        adc	r12, rdx
        adc	r13, 0
        ;  A[0] * B[3]
        mov	rax, QWORD PTR [rsp+120]
        mul	QWORD PTR [rsp+128]
        xor	r14, r14
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[1] * B[2]
        mov	rax, QWORD PTR [rsp+112]
        mul	QWORD PTR [rsp+136]
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[2] * B[1]
        mov	rax, QWORD PTR [rsp+104]
        mul	QWORD PTR [rsp+144]
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[3] * B[0]
        mov	rax, QWORD PTR [rsp+96]
        mul	QWORD PTR [rsp+152]
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[1] * B[3]
        mov	rax, QWORD PTR [rsp+120]
        mul	QWORD PTR [rsp+136]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[2] * B[2]
        mov	rax, QWORD PTR [rsp+112]
        mul	QWORD PTR [rsp+144]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[3] * B[1]
        mov	rax, QWORD PTR [rsp+104]
        mul	QWORD PTR [rsp+152]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[2] * B[3]
        mov	rax, QWORD PTR [rsp+120]
        mul	QWORD PTR [rsp+144]
        xor	rdi, rdi
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[3] * B[2]
        mov	rax, QWORD PTR [rsp+112]
        mul	QWORD PTR [rsp+152]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[3] * B[3]
        mov	rax, QWORD PTR [rsp+120]
        mul	QWORD PTR [rsp+152]
        add	r15, rax
        adc	rdi, rdx
        mov	rax, 38
        mul	rdi
        add	r12, rax
        adc	rdx, 0
        mov	rbx, 9223372036854775807
        shld	rdx, r12, 1
        imul	rdx, rdx, 19
        and	r12, rbx
        mov	rbx, rdx
        mov	rax, 38
        mul	r13
        xor	r13, r13
        add	rcx, rax
        mov	rax, 38
        adc	r13, rdx
        mul	r14
        xor	r14, r14
        add	r10, rax
        mov	rax, 38
        adc	r14, rdx
        mul	r15
        xor	r15, r15
        add	r11, rax
        adc	r15, rdx
        add	rcx, rbx
        adc	r10, r13
        adc	r11, r14
        adc	r12, r15
        ; Store
        mov	QWORD PTR [rsp], rcx
        mov	QWORD PTR [rsp+8], r10
        mov	QWORD PTR [rsp+16], r11
        mov	QWORD PTR [rsp+24], r12
        dec	rbp
        cmp	rbp, 3
        jge	L_curve25519_base_x64_bits
        neg	rsi
        ; Conditional Swap
        mov	rcx, QWORD PTR [r8]
        mov	r10, QWORD PTR [r8+8]
        mov	r11, QWORD PTR [r8+16]
        mov	r12, QWORD PTR [r8+24]
        mov	r13, QWORD PTR [rsp]
        mov	r14, QWORD PTR [rsp+8]
        mov	r15, QWORD PTR [rsp+16]
        mov	rdi, QWORD PTR [rsp+24]
        xor	rcx, QWORD PTR [rsp+64]
        xor	r10, QWORD PTR [rsp+72]
        xor	r11, QWORD PTR [rsp+80]
        xor	r12, QWORD PTR [rsp+88]
        xor	r13, QWORD PTR [rsp+32]
        xor	r14, QWORD PTR [rsp+40]
        xor	r15, QWORD PTR [rsp+48]
        xor	rdi, QWORD PTR [rsp+56]
        and	rcx, rsi
        and	r10, rsi
        and	r11, rsi
        and	r12, rsi
        and	r13, rsi
        and	r14, rsi
        and	r15, rsi
        and	rdi, rsi
        xor	QWORD PTR [r8], rcx
        xor	QWORD PTR [r8+8], r10
        xor	QWORD PTR [r8+16], r11
        xor	QWORD PTR [r8+24], r12
        xor	QWORD PTR [rsp], r13
        xor	QWORD PTR [rsp+8], r14
        xor	QWORD PTR [rsp+16], r15
        xor	QWORD PTR [rsp+24], rdi
        xor	QWORD PTR [rsp+64], rcx
        xor	QWORD PTR [rsp+72], r10
        xor	QWORD PTR [rsp+80], r11
        xor	QWORD PTR [rsp+88], r12
        xor	QWORD PTR [rsp+32], r13
        xor	QWORD PTR [rsp+40], r14
        xor	QWORD PTR [rsp+48], r15
        xor	QWORD PTR [rsp+56], rdi
L_curve25519_base_x64_3:
        ; Add-Sub
        ; Add
        mov	rcx, QWORD PTR [r8]
        mov	r10, QWORD PTR [r8+8]
        mov	r11, QWORD PTR [r8+16]
        mov	r12, QWORD PTR [r8+24]
        mov	r13, rcx
        add	rcx, QWORD PTR [rsp]
        mov	r14, r10
        adc	r10, QWORD PTR [rsp+8]
        mov	r15, r11
        adc	r11, QWORD PTR [rsp+16]
        mov	rdi, r12
        adc	r12, QWORD PTR [rsp+24]
        mov	rbx, 0
        adc	rbx, 0
        shld	rbx, r12, 1
        imul	rbx, 19
        btr	r12, 63
        ;   Sub modulus (if overflow)
        add	rcx, rbx
        adc	r10, 0
        adc	r11, 0
        adc	r12, 0
        ; Sub
        sub	r13, QWORD PTR [rsp]
        sbb	r14, QWORD PTR [rsp+8]
        sbb	r15, QWORD PTR [rsp+16]
        sbb	rdi, QWORD PTR [rsp+24]
        sbb	rbx, rbx
        shld	rbx, rdi, 1
        imul	rbx, -19
        btr	rdi, 63
        ;   Add modulus (if underflow)
        sub	r13, rbx
        sbb	r14, 0
        sbb	r15, 0
        sbb	rdi, 0
        mov	QWORD PTR [r8], rcx
        mov	QWORD PTR [r8+8], r10
        mov	QWORD PTR [r8+16], r11
        mov	QWORD PTR [r8+24], r12
        mov	QWORD PTR [rsp+128], r13
        mov	QWORD PTR [rsp+136], r14
        mov	QWORD PTR [rsp+144], r15
        mov	QWORD PTR [rsp+152], rdi
        ; Square
        ;  A[0] * A[1]
        mov	rax, QWORD PTR [rsp+128]
        mul	QWORD PTR [rsp+136]
        mov	r10, rax
        mov	r11, rdx
        ;  A[0] * A[2]
        mov	rax, QWORD PTR [rsp+128]
        mul	QWORD PTR [rsp+144]
        xor	r12, r12
        add	r11, rax
        adc	r12, rdx
        ;  A[0] * A[3]
        mov	rax, QWORD PTR [rsp+128]
        mul	QWORD PTR [rsp+152]
        xor	r13, r13
        add	r12, rax
        adc	r13, rdx
        ;  A[1] * A[2]
        mov	rax, QWORD PTR [rsp+136]
        mul	QWORD PTR [rsp+144]
        xor	r14, r14
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[1] * A[3]
        mov	rax, QWORD PTR [rsp+136]
        mul	QWORD PTR [rsp+152]
        add	r13, rax
        adc	r14, rdx
        ;  A[2] * A[3]
        mov	rax, QWORD PTR [rsp+144]
        mul	QWORD PTR [rsp+152]
        xor	r15, r15
        add	r14, rax
        adc	r15, rdx
        ; Double
        xor	rdi, rdi
        add	r10, r10
        adc	r11, r11
        adc	r12, r12
        adc	r13, r13
        adc	r14, r14
        adc	r15, r15
        adc	rdi, 0
        ;  A[0] * A[0]
        mov	rax, QWORD PTR [rsp+128]
        mul	rax
        mov	rcx, rax
        mov	rbx, rdx
        ;  A[1] * A[1]
        mov	rax, QWORD PTR [rsp+136]
        mul	rax
        add	r10, rbx
        adc	r11, rax
        adc	rdx, 0
        mov	rbx, rdx
        ;  A[2] * A[2]
        mov	rax, QWORD PTR [rsp+144]
        mul	rax
        add	r12, rbx
        adc	r13, rax
        adc	rdx, 0
        mov	rbx, rdx
        ;  A[3] * A[3]
        mov	rax, QWORD PTR [rsp+152]
        mul	rax
        add	r15, rax
        adc	rdi, rdx
        add	r14, rbx
        adc	r15, 0
        adc	rdi, 0
        mov	rax, 38
        mul	rdi
        add	r12, rax
        adc	rdx, 0
        mov	rbx, 9223372036854775807
        shld	rdx, r12, 1
        imul	rdx, rdx, 19
        and	r12, rbx
        mov	rbx, rdx
        mov	rax, 38
        mul	r13
        xor	r13, r13
        add	rcx, rax
        mov	rax, 38
        adc	r13, rdx
        mul	r14
        xor	r14, r14
        add	r10, rax
        mov	rax, 38
        adc	r14, rdx
        mul	r15
        xor	r15, r15
        add	r11, rax
        adc	r15, rdx
        add	rcx, rbx
        adc	r10, r13
        adc	r11, r14
        adc	r12, r15
        ; Store
        mov	QWORD PTR [rsp+96], rcx
        mov	QWORD PTR [rsp+104], r10
        mov	QWORD PTR [rsp+112], r11
        mov	QWORD PTR [rsp+120], r12
        ; Square
        ;  A[0] * A[1]
        mov	rax, QWORD PTR [r8]
        mul	QWORD PTR [r8+8]
        mov	r10, rax
        mov	r11, rdx
        ;  A[0] * A[2]
        mov	rax, QWORD PTR [r8]
        mul	QWORD PTR [r8+16]
        xor	r12, r12
        add	r11, rax
        adc	r12, rdx
        ;  A[0] * A[3]
        mov	rax, QWORD PTR [r8]
        mul	QWORD PTR [r8+24]
        xor	r13, r13
        add	r12, rax
        adc	r13, rdx
        ;  A[1] * A[2]
        mov	rax, QWORD PTR [r8+8]
        mul	QWORD PTR [r8+16]
        xor	r14, r14
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[1] * A[3]
        mov	rax, QWORD PTR [r8+8]
        mul	QWORD PTR [r8+24]
        add	r13, rax
        adc	r14, rdx
        ;  A[2] * A[3]
        mov	rax, QWORD PTR [r8+16]
        mul	QWORD PTR [r8+24]
        xor	r15, r15
        add	r14, rax
        adc	r15, rdx
        ; Double
        xor	rdi, rdi
        add	r10, r10
        adc	r11, r11
        adc	r12, r12
        adc	r13, r13
        adc	r14, r14
        adc	r15, r15
        adc	rdi, 0
        ;  A[0] * A[0]
        mov	rax, QWORD PTR [r8]
        mul	rax
        mov	rcx, rax
        mov	rbx, rdx
        ;  A[1] * A[1]
        mov	rax, QWORD PTR [r8+8]
        mul	rax
        add	r10, rbx
        adc	r11, rax
        adc	rdx, 0
        mov	rbx, rdx
        ;  A[2] * A[2]
        mov	rax, QWORD PTR [r8+16]
        mul	rax
        add	r12, rbx
        adc	r13, rax
        adc	rdx, 0
        mov	rbx, rdx
        ;  A[3] * A[3]
        mov	rax, QWORD PTR [r8+24]
        mul	rax
        add	r15, rax
        adc	rdi, rdx
        add	r14, rbx
        adc	r15, 0
        adc	rdi, 0
        mov	rax, 38
        mul	rdi
        add	r12, rax
        adc	rdx, 0
        mov	rbx, 9223372036854775807
        shld	rdx, r12, 1
        imul	rdx, rdx, 19
        and	r12, rbx
        mov	rbx, rdx
        mov	rax, 38
        mul	r13
        xor	r13, r13
        add	rcx, rax
        mov	rax, 38
        adc	r13, rdx
        mul	r14
        xor	r14, r14
        add	r10, rax
        mov	rax, 38
        adc	r14, rdx
        mul	r15
        xor	r15, r15
        add	r11, rax
        adc	r15, rdx
        add	rcx, rbx
        adc	r10, r13
        adc	r11, r14
        adc	r12, r15
        ; Store
        mov	QWORD PTR [rsp+128], rcx
        mov	QWORD PTR [rsp+136], r10
        mov	QWORD PTR [rsp+144], r11
        mov	QWORD PTR [rsp+152], r12
        ; Multiply
        ;  A[0] * B[0]
        mov	rax, QWORD PTR [rsp+96]
        mul	QWORD PTR [rsp+128]
        mov	rcx, rax
        mov	r10, rdx
        ;  A[0] * B[1]
        mov	rax, QWORD PTR [rsp+104]
        mul	QWORD PTR [rsp+128]
        xor	r11, r11
        add	r10, rax
        adc	r11, rdx
        ;  A[1] * B[0]
        mov	rax, QWORD PTR [rsp+96]
        mul	QWORD PTR [rsp+136]
        xor	r12, r12
        add	r10, rax
        adc	r11, rdx
        adc	r12, 0
        ;  A[0] * B[2]
        mov	rax, QWORD PTR [rsp+112]
        mul	QWORD PTR [rsp+128]
        add	r11, rax
        adc	r12, rdx
        ;  A[1] * B[1]
        mov	rax, QWORD PTR [rsp+104]
        mul	QWORD PTR [rsp+136]
        xor	r13, r13
        add	r11, rax
        adc	r12, rdx
        adc	r13, 0
        ;  A[2] * B[0]
        mov	rax, QWORD PTR [rsp+96]
        mul	QWORD PTR [rsp+144]
        add	r11, rax
        adc	r12, rdx
        adc	r13, 0
        ;  A[0] * B[3]
        mov	rax, QWORD PTR [rsp+120]
        mul	QWORD PTR [rsp+128]
        xor	r14, r14
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[1] * B[2]
        mov	rax, QWORD PTR [rsp+112]
        mul	QWORD PTR [rsp+136]
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[2] * B[1]
        mov	rax, QWORD PTR [rsp+104]
        mul	QWORD PTR [rsp+144]
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[3] * B[0]
        mov	rax, QWORD PTR [rsp+96]
        mul	QWORD PTR [rsp+152]
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[1] * B[3]
        mov	rax, QWORD PTR [rsp+120]
        mul	QWORD PTR [rsp+136]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[2] * B[2]
        mov	rax, QWORD PTR [rsp+112]
        mul	QWORD PTR [rsp+144]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[3] * B[1]
        mov	rax, QWORD PTR [rsp+104]
        mul	QWORD PTR [rsp+152]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[2] * B[3]
        mov	rax, QWORD PTR [rsp+120]
        mul	QWORD PTR [rsp+144]
        xor	rdi, rdi
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[3] * B[2]
        mov	rax, QWORD PTR [rsp+112]
        mul	QWORD PTR [rsp+152]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[3] * B[3]
        mov	rax, QWORD PTR [rsp+120]
        mul	QWORD PTR [rsp+152]
        add	r15, rax
        adc	rdi, rdx
        mov	rax, 38
        mul	rdi
        add	r12, rax
        adc	rdx, 0
        mov	rbx, 9223372036854775807
        shld	rdx, r12, 1
        imul	rdx, rdx, 19
        and	r12, rbx
        mov	rbx, rdx
        mov	rax, 38
        mul	r13
        xor	r13, r13
        add	rcx, rax
        mov	rax, 38
        adc	r13, rdx
        mul	r14
        xor	r14, r14
        add	r10, rax
        mov	rax, 38
        adc	r14, rdx
        mul	r15
        xor	r15, r15
        add	r11, rax
        adc	r15, rdx
        add	rcx, rbx
        adc	r10, r13
        adc	r11, r14
        adc	r12, r15
        ; Store
        mov	QWORD PTR [r8], rcx
        mov	QWORD PTR [r8+8], r10
        mov	QWORD PTR [r8+16], r11
        mov	QWORD PTR [r8+24], r12
        ; Sub
        mov	rcx, QWORD PTR [rsp+128]
        mov	r10, QWORD PTR [rsp+136]
        mov	r11, QWORD PTR [rsp+144]
        mov	r12, QWORD PTR [rsp+152]
        sub	rcx, QWORD PTR [rsp+96]
        sbb	r10, QWORD PTR [rsp+104]
        sbb	r11, QWORD PTR [rsp+112]
        sbb	r12, QWORD PTR [rsp+120]
        sbb	rbx, rbx
        shld	rbx, r12, 1
        imul	rbx, -19
        btr	r12, 63
        ;   Add modulus (if underflow)
        sub	rcx, rbx
        sbb	r10, 0
        sbb	r11, 0
        sbb	r12, 0
        mov	QWORD PTR [rsp+128], rcx
        mov	QWORD PTR [rsp+136], r10
        mov	QWORD PTR [rsp+144], r11
        mov	QWORD PTR [rsp+152], r12
        ; Multiply by 121666
        mov	rax, 121666
        mul	QWORD PTR [rsp+128]
        xor	r11, r11
        mov	rcx, rax
        mov	r10, rdx
        mov	rax, 121666
        mul	QWORD PTR [rsp+136]
        xor	r12, r12
        add	r10, rax
        adc	r11, rdx
        mov	rax, 121666
        mul	QWORD PTR [rsp+144]
        xor	r14, r14
        add	r11, rax
        adc	r12, rdx
        mov	rax, 121666
        mul	QWORD PTR [rsp+152]
        mov	r13, 9223372036854775807
        add	r12, rax
        adc	r14, rdx
        add	rcx, QWORD PTR [rsp+96]
        adc	r10, QWORD PTR [rsp+104]
        adc	r11, QWORD PTR [rsp+112]
        adc	r12, QWORD PTR [rsp+120]
        adc	r14, 0
        shld	r14, r12, 1
        and	r12, r13
        mov	rax, 19
        mul	r14
        add	rcx, rax
        adc	r10, 0
        adc	r11, 0
        adc	r12, 0
        mov	QWORD PTR [rsp+96], rcx
        mov	QWORD PTR [rsp+104], r10
        mov	QWORD PTR [rsp+112], r11
        mov	QWORD PTR [rsp+120], r12
        ; Multiply
        ;  A[0] * B[0]
        mov	rax, QWORD PTR [rsp+96]
        mul	QWORD PTR [rsp+128]
        mov	rcx, rax
        mov	r10, rdx
        ;  A[0] * B[1]
        mov	rax, QWORD PTR [rsp+104]
        mul	QWORD PTR [rsp+128]
        xor	r11, r11
        add	r10, rax
        adc	r11, rdx
        ;  A[1] * B[0]
        mov	rax, QWORD PTR [rsp+96]
        mul	QWORD PTR [rsp+136]
        xor	r12, r12
        add	r10, rax
        adc	r11, rdx
        adc	r12, 0
        ;  A[0] * B[2]
        mov	rax, QWORD PTR [rsp+112]
        mul	QWORD PTR [rsp+128]
        add	r11, rax
        adc	r12, rdx
        ;  A[1] * B[1]
        mov	rax, QWORD PTR [rsp+104]
        mul	QWORD PTR [rsp+136]
        xor	r13, r13
        add	r11, rax
        adc	r12, rdx
        adc	r13, 0
        ;  A[2] * B[0]
        mov	rax, QWORD PTR [rsp+96]
        mul	QWORD PTR [rsp+144]
        add	r11, rax
        adc	r12, rdx
        adc	r13, 0
        ;  A[0] * B[3]
        mov	rax, QWORD PTR [rsp+120]
        mul	QWORD PTR [rsp+128]
        xor	r14, r14
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[1] * B[2]
        mov	rax, QWORD PTR [rsp+112]
        mul	QWORD PTR [rsp+136]
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[2] * B[1]
        mov	rax, QWORD PTR [rsp+104]
        mul	QWORD PTR [rsp+144]
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[3] * B[0]
        mov	rax, QWORD PTR [rsp+96]
        mul	QWORD PTR [rsp+152]
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[1] * B[3]
        mov	rax, QWORD PTR [rsp+120]
        mul	QWORD PTR [rsp+136]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[2] * B[2]
        mov	rax, QWORD PTR [rsp+112]
        mul	QWORD PTR [rsp+144]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[3] * B[1]
        mov	rax, QWORD PTR [rsp+104]
        mul	QWORD PTR [rsp+152]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[2] * B[3]
        mov	rax, QWORD PTR [rsp+120]
        mul	QWORD PTR [rsp+144]
        xor	rdi, rdi
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[3] * B[2]
        mov	rax, QWORD PTR [rsp+112]
        mul	QWORD PTR [rsp+152]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[3] * B[3]
        mov	rax, QWORD PTR [rsp+120]
        mul	QWORD PTR [rsp+152]
        add	r15, rax
        adc	rdi, rdx
        mov	rax, 38
        mul	rdi
        add	r12, rax
        adc	rdx, 0
        mov	rbx, 9223372036854775807
        shld	rdx, r12, 1
        imul	rdx, rdx, 19
        and	r12, rbx
        mov	rbx, rdx
        mov	rax, 38
        mul	r13
        xor	r13, r13
        add	rcx, rax
        mov	rax, 38
        adc	r13, rdx
        mul	r14
        xor	r14, r14
        add	r10, rax
        mov	rax, 38
        adc	r14, rdx
        mul	r15
        xor	r15, r15
        add	r11, rax
        adc	r15, rdx
        add	rcx, rbx
        adc	r10, r13
        adc	r11, r14
        adc	r12, r15
        ; Store
        mov	QWORD PTR [rsp], rcx
        mov	QWORD PTR [rsp+8], r10
        mov	QWORD PTR [rsp+16], r11
        mov	QWORD PTR [rsp+24], r12
        dec	rbp
        jge	L_curve25519_base_x64_3
        ; Invert
        lea	rcx, QWORD PTR [rsp+32]
        mov	rdx, rsp
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+32]
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+64]
        mov	rdx, rsp
        lea	r8, QWORD PTR [rsp+64]
        call	fe_mul_x64
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        lea	r8, QWORD PTR [rsp+64]
        call	fe_mul_x64
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+32]
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        lea	r8, QWORD PTR [rsp+96]
        call	fe_mul_x64
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+64]
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 4
        call	fe_sq_n_x64
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        call	fe_mul_x64
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+64]
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 9
        call	fe_sq_n_x64
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        call	fe_mul_x64
        lea	rcx, QWORD PTR [rsp+128]
        lea	rdx, QWORD PTR [rsp+96]
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+128]
        lea	rdx, QWORD PTR [rsp+128]
        mov	r8, 19
        call	fe_sq_n_x64
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+128]
        lea	r8, QWORD PTR [rsp+96]
        call	fe_mul_x64
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 9
        call	fe_sq_n_x64
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        call	fe_mul_x64
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+64]
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 49
        call	fe_sq_n_x64
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        call	fe_mul_x64
        lea	rcx, QWORD PTR [rsp+128]
        lea	rdx, QWORD PTR [rsp+96]
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+128]
        lea	rdx, QWORD PTR [rsp+128]
        mov	r8, 99
        call	fe_sq_n_x64
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+128]
        lea	r8, QWORD PTR [rsp+96]
        call	fe_mul_x64
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 49
        call	fe_sq_n_x64
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        call	fe_mul_x64
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        mov	r8, 4
        call	fe_sq_n_x64
        mov	rcx, rsp
        lea	rdx, QWORD PTR [rsp+64]
        lea	r8, QWORD PTR [rsp+32]
        call	fe_mul_x64
        mov	r8, QWORD PTR [rsp+160]
        ; Multiply
        ;  A[0] * B[0]
        mov	rax, QWORD PTR [rsp]
        mul	QWORD PTR [r8]
        mov	rcx, rax
        mov	r10, rdx
        ;  A[0] * B[1]
        mov	rax, QWORD PTR [rsp+8]
        mul	QWORD PTR [r8]
        xor	r11, r11
        add	r10, rax
        adc	r11, rdx
        ;  A[1] * B[0]
        mov	rax, QWORD PTR [rsp]
        mul	QWORD PTR [r8+8]
        xor	r12, r12
        add	r10, rax
        adc	r11, rdx
        adc	r12, 0
        ;  A[0] * B[2]
        mov	rax, QWORD PTR [rsp+16]
        mul	QWORD PTR [r8]
        add	r11, rax
        adc	r12, rdx
        ;  A[1] * B[1]
        mov	rax, QWORD PTR [rsp+8]
        mul	QWORD PTR [r8+8]
        xor	r13, r13
        add	r11, rax
        adc	r12, rdx
        adc	r13, 0
        ;  A[2] * B[0]
        mov	rax, QWORD PTR [rsp]
        mul	QWORD PTR [r8+16]
        add	r11, rax
        adc	r12, rdx
        adc	r13, 0
        ;  A[0] * B[3]
        mov	rax, QWORD PTR [rsp+24]
        mul	QWORD PTR [r8]
        xor	r14, r14
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[1] * B[2]
        mov	rax, QWORD PTR [rsp+16]
        mul	QWORD PTR [r8+8]
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[2] * B[1]
        mov	rax, QWORD PTR [rsp+8]
        mul	QWORD PTR [r8+16]
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[3] * B[0]
        mov	rax, QWORD PTR [rsp]
        mul	QWORD PTR [r8+24]
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[1] * B[3]
        mov	rax, QWORD PTR [rsp+24]
        mul	QWORD PTR [r8+8]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[2] * B[2]
        mov	rax, QWORD PTR [rsp+16]
        mul	QWORD PTR [r8+16]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[3] * B[1]
        mov	rax, QWORD PTR [rsp+8]
        mul	QWORD PTR [r8+24]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[2] * B[3]
        mov	rax, QWORD PTR [rsp+24]
        mul	QWORD PTR [r8+16]
        xor	rdi, rdi
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[3] * B[2]
        mov	rax, QWORD PTR [rsp+16]
        mul	QWORD PTR [r8+24]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[3] * B[3]
        mov	rax, QWORD PTR [rsp+24]
        mul	QWORD PTR [r8+24]
        add	r15, rax
        adc	rdi, rdx
        mov	rax, 38
        mul	rdi
        add	r12, rax
        adc	rdx, 0
        mov	rbx, 9223372036854775807
        shld	rdx, r12, 1
        imul	rdx, rdx, 19
        and	r12, rbx
        mov	rbx, rdx
        mov	rax, 38
        mul	r13
        xor	r13, r13
        add	rcx, rax
        mov	rax, 38
        adc	r13, rdx
        mul	r14
        xor	r14, r14
        add	r10, rax
        mov	rax, 38
        adc	r14, rdx
        mul	r15
        xor	r15, r15
        add	r11, rax
        adc	r15, rdx
        add	rcx, rbx
        adc	r10, r13
        adc	r11, r14
        adc	r12, r15
        mov	rbx, 9223372036854775807
        mov	rax, r12
        sar	rax, 63
        and	rax, 19
        and	r12, rbx
        add	rcx, rax
        adc	r10, 0
        adc	r11, 0
        adc	r12, 0
        mov	rax, 9223372036854775807
        mov	rdx, rcx
        add	rdx, 19
        mov	rdx, r10
        adc	rdx, 0
        mov	rdx, r11
        adc	rdx, 0
        mov	rdx, r12
        adc	rdx, 0
        sar	rdx, 63
        and	rdx, 19
        and	r12, rax
        add	rcx, rdx
        adc	r10, 0
        adc	r11, 0
        adc	r12, 0
        and	r12, rax
        ; Store
        mov	QWORD PTR [r8], rcx
        mov	QWORD PTR [r8+8], r10
        mov	QWORD PTR [r8+16], r11
        mov	QWORD PTR [r8+24], r12
        xor	rax, rax
        add	rsp, 168
        pop	rbp
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
curve25519_base_x64 ENDP
_TEXT ENDS
ENDIF
_TEXT SEGMENT READONLY PARA
curve25519_x64 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        push	rbp
        mov	r9, rcx
        mov	r10, rdx
        sub	rsp, 176
        xor	rbx, rbx
        mov	QWORD PTR [rsp+168], r9
        ; Set one
        mov	QWORD PTR [r9], 1
        mov	QWORD PTR [r9+8], 0
        mov	QWORD PTR [r9+16], 0
        mov	QWORD PTR [r9+24], 0
        ; Set zero
        mov	QWORD PTR [rsp], 0
        mov	QWORD PTR [rsp+8], 0
        mov	QWORD PTR [rsp+16], 0
        mov	QWORD PTR [rsp+24], 0
        ; Set one
        mov	QWORD PTR [rsp+32], 1
        mov	QWORD PTR [rsp+40], 0
        mov	QWORD PTR [rsp+48], 0
        mov	QWORD PTR [rsp+56], 0
        ; Copy
        mov	rcx, QWORD PTR [r8]
        mov	r11, QWORD PTR [r8+8]
        mov	r12, QWORD PTR [r8+16]
        mov	r13, QWORD PTR [r8+24]
        mov	QWORD PTR [rsp+64], rcx
        mov	QWORD PTR [rsp+72], r11
        mov	QWORD PTR [rsp+80], r12
        mov	QWORD PTR [rsp+88], r13
        mov	r11, 254
L_curve25519_x64_bits:
        mov	QWORD PTR [rsp+160], r11
        mov	rcx, r11
        and	rcx, 63
        shr	r11, 6
        mov	rbp, QWORD PTR [r10+8*r11]
        shr	rbp, cl
        and	rbp, 1
        xor	rbx, rbp
        neg	rbx
        ; Conditional Swap
        mov	rcx, QWORD PTR [r9]
        mov	r11, QWORD PTR [r9+8]
        mov	r12, QWORD PTR [r9+16]
        mov	r13, QWORD PTR [r9+24]
        mov	r14, QWORD PTR [rsp]
        mov	r15, QWORD PTR [rsp+8]
        mov	rdi, QWORD PTR [rsp+16]
        mov	rsi, QWORD PTR [rsp+24]
        xor	rcx, QWORD PTR [rsp+64]
        xor	r11, QWORD PTR [rsp+72]
        xor	r12, QWORD PTR [rsp+80]
        xor	r13, QWORD PTR [rsp+88]
        xor	r14, QWORD PTR [rsp+32]
        xor	r15, QWORD PTR [rsp+40]
        xor	rdi, QWORD PTR [rsp+48]
        xor	rsi, QWORD PTR [rsp+56]
        and	rcx, rbx
        and	r11, rbx
        and	r12, rbx
        and	r13, rbx
        and	r14, rbx
        and	r15, rbx
        and	rdi, rbx
        and	rsi, rbx
        xor	QWORD PTR [r9], rcx
        xor	QWORD PTR [r9+8], r11
        xor	QWORD PTR [r9+16], r12
        xor	QWORD PTR [r9+24], r13
        xor	QWORD PTR [rsp], r14
        xor	QWORD PTR [rsp+8], r15
        xor	QWORD PTR [rsp+16], rdi
        xor	QWORD PTR [rsp+24], rsi
        xor	QWORD PTR [rsp+64], rcx
        xor	QWORD PTR [rsp+72], r11
        xor	QWORD PTR [rsp+80], r12
        xor	QWORD PTR [rsp+88], r13
        xor	QWORD PTR [rsp+32], r14
        xor	QWORD PTR [rsp+40], r15
        xor	QWORD PTR [rsp+48], rdi
        xor	QWORD PTR [rsp+56], rsi
        mov	rbx, rbp
        ; Add-Sub
        ; Add
        mov	rcx, QWORD PTR [r9]
        mov	r11, QWORD PTR [r9+8]
        mov	r12, QWORD PTR [r9+16]
        mov	r13, QWORD PTR [r9+24]
        mov	r14, rcx
        add	rcx, QWORD PTR [rsp]
        mov	r15, r11
        adc	r11, QWORD PTR [rsp+8]
        mov	rdi, r12
        adc	r12, QWORD PTR [rsp+16]
        mov	rsi, r13
        adc	r13, QWORD PTR [rsp+24]
        mov	rbp, 0
        adc	rbp, 0
        shld	rbp, r13, 1
        imul	rbp, 19
        btr	r13, 63
        ;   Sub modulus (if overflow)
        add	rcx, rbp
        adc	r11, 0
        adc	r12, 0
        adc	r13, 0
        ; Sub
        sub	r14, QWORD PTR [rsp]
        sbb	r15, QWORD PTR [rsp+8]
        sbb	rdi, QWORD PTR [rsp+16]
        sbb	rsi, QWORD PTR [rsp+24]
        sbb	rbp, rbp
        shld	rbp, rsi, 1
        imul	rbp, -19
        btr	rsi, 63
        ;   Add modulus (if underflow)
        sub	r14, rbp
        sbb	r15, 0
        sbb	rdi, 0
        sbb	rsi, 0
        mov	QWORD PTR [r9], rcx
        mov	QWORD PTR [r9+8], r11
        mov	QWORD PTR [r9+16], r12
        mov	QWORD PTR [r9+24], r13
        mov	QWORD PTR [rsp+128], r14
        mov	QWORD PTR [rsp+136], r15
        mov	QWORD PTR [rsp+144], rdi
        mov	QWORD PTR [rsp+152], rsi
        ; Add-Sub
        ; Add
        mov	rcx, QWORD PTR [rsp+64]
        mov	r11, QWORD PTR [rsp+72]
        mov	r12, QWORD PTR [rsp+80]
        mov	r13, QWORD PTR [rsp+88]
        mov	r14, rcx
        add	rcx, QWORD PTR [rsp+32]
        mov	r15, r11
        adc	r11, QWORD PTR [rsp+40]
        mov	rdi, r12
        adc	r12, QWORD PTR [rsp+48]
        mov	rsi, r13
        adc	r13, QWORD PTR [rsp+56]
        mov	rbp, 0
        adc	rbp, 0
        shld	rbp, r13, 1
        imul	rbp, 19
        btr	r13, 63
        ;   Sub modulus (if overflow)
        add	rcx, rbp
        adc	r11, 0
        adc	r12, 0
        adc	r13, 0
        ; Sub
        sub	r14, QWORD PTR [rsp+32]
        sbb	r15, QWORD PTR [rsp+40]
        sbb	rdi, QWORD PTR [rsp+48]
        sbb	rsi, QWORD PTR [rsp+56]
        sbb	rbp, rbp
        shld	rbp, rsi, 1
        imul	rbp, -19
        btr	rsi, 63
        ;   Add modulus (if underflow)
        sub	r14, rbp
        sbb	r15, 0
        sbb	rdi, 0
        sbb	rsi, 0
        mov	QWORD PTR [rsp+32], rcx
        mov	QWORD PTR [rsp+40], r11
        mov	QWORD PTR [rsp+48], r12
        mov	QWORD PTR [rsp+56], r13
        mov	QWORD PTR [rsp+96], r14
        mov	QWORD PTR [rsp+104], r15
        mov	QWORD PTR [rsp+112], rdi
        mov	QWORD PTR [rsp+120], rsi
        ; Multiply
        ;  A[0] * B[0]
        mov	rax, QWORD PTR [rsp+128]
        mul	QWORD PTR [rsp+32]
        mov	rcx, rax
        mov	r11, rdx
        ;  A[0] * B[1]
        mov	rax, QWORD PTR [rsp+136]
        mul	QWORD PTR [rsp+32]
        xor	r12, r12
        add	r11, rax
        adc	r12, rdx
        ;  A[1] * B[0]
        mov	rax, QWORD PTR [rsp+128]
        mul	QWORD PTR [rsp+40]
        xor	r13, r13
        add	r11, rax
        adc	r12, rdx
        adc	r13, 0
        ;  A[0] * B[2]
        mov	rax, QWORD PTR [rsp+144]
        mul	QWORD PTR [rsp+32]
        add	r12, rax
        adc	r13, rdx
        ;  A[1] * B[1]
        mov	rax, QWORD PTR [rsp+136]
        mul	QWORD PTR [rsp+40]
        xor	r14, r14
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[2] * B[0]
        mov	rax, QWORD PTR [rsp+128]
        mul	QWORD PTR [rsp+48]
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[0] * B[3]
        mov	rax, QWORD PTR [rsp+152]
        mul	QWORD PTR [rsp+32]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[1] * B[2]
        mov	rax, QWORD PTR [rsp+144]
        mul	QWORD PTR [rsp+40]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[2] * B[1]
        mov	rax, QWORD PTR [rsp+136]
        mul	QWORD PTR [rsp+48]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[3] * B[0]
        mov	rax, QWORD PTR [rsp+128]
        mul	QWORD PTR [rsp+56]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[1] * B[3]
        mov	rax, QWORD PTR [rsp+152]
        mul	QWORD PTR [rsp+40]
        xor	rdi, rdi
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[2] * B[2]
        mov	rax, QWORD PTR [rsp+144]
        mul	QWORD PTR [rsp+48]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[3] * B[1]
        mov	rax, QWORD PTR [rsp+136]
        mul	QWORD PTR [rsp+56]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[2] * B[3]
        mov	rax, QWORD PTR [rsp+152]
        mul	QWORD PTR [rsp+48]
        xor	rsi, rsi
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[3] * B[2]
        mov	rax, QWORD PTR [rsp+144]
        mul	QWORD PTR [rsp+56]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[3] * B[3]
        mov	rax, QWORD PTR [rsp+152]
        mul	QWORD PTR [rsp+56]
        add	rdi, rax
        adc	rsi, rdx
        mov	rax, 38
        mul	rsi
        add	r13, rax
        adc	rdx, 0
        mov	rbp, 9223372036854775807
        shld	rdx, r13, 1
        imul	rdx, rdx, 19
        and	r13, rbp
        mov	rbp, rdx
        mov	rax, 38
        mul	r14
        xor	r14, r14
        add	rcx, rax
        mov	rax, 38
        adc	r14, rdx
        mul	r15
        xor	r15, r15
        add	r11, rax
        mov	rax, 38
        adc	r15, rdx
        mul	rdi
        xor	rdi, rdi
        add	r12, rax
        adc	rdi, rdx
        add	rcx, rbp
        adc	r11, r14
        adc	r12, r15
        adc	r13, rdi
        ; Store
        mov	QWORD PTR [rsp+32], rcx
        mov	QWORD PTR [rsp+40], r11
        mov	QWORD PTR [rsp+48], r12
        mov	QWORD PTR [rsp+56], r13
        ; Multiply
        ;  A[0] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [rsp+96]
        mov	rcx, rax
        mov	r11, rdx
        ;  A[0] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [rsp+96]
        xor	r12, r12
        add	r11, rax
        adc	r12, rdx
        ;  A[1] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [rsp+104]
        xor	r13, r13
        add	r11, rax
        adc	r12, rdx
        adc	r13, 0
        ;  A[0] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [rsp+96]
        add	r12, rax
        adc	r13, rdx
        ;  A[1] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [rsp+104]
        xor	r14, r14
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[2] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [rsp+112]
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[0] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [rsp+96]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[1] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [rsp+104]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[2] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [rsp+112]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[3] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [rsp+120]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[1] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [rsp+104]
        xor	rdi, rdi
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[2] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [rsp+112]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[3] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [rsp+120]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[2] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [rsp+112]
        xor	rsi, rsi
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[3] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [rsp+120]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[3] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [rsp+120]
        add	rdi, rax
        adc	rsi, rdx
        mov	rax, 38
        mul	rsi
        add	r13, rax
        adc	rdx, 0
        mov	rbp, 9223372036854775807
        shld	rdx, r13, 1
        imul	rdx, rdx, 19
        and	r13, rbp
        mov	rbp, rdx
        mov	rax, 38
        mul	r14
        xor	r14, r14
        add	rcx, rax
        mov	rax, 38
        adc	r14, rdx
        mul	r15
        xor	r15, r15
        add	r11, rax
        mov	rax, 38
        adc	r15, rdx
        mul	rdi
        xor	rdi, rdi
        add	r12, rax
        adc	rdi, rdx
        add	rcx, rbp
        adc	r11, r14
        adc	r12, r15
        adc	r13, rdi
        ; Store
        mov	QWORD PTR [rsp], rcx
        mov	QWORD PTR [rsp+8], r11
        mov	QWORD PTR [rsp+16], r12
        mov	QWORD PTR [rsp+24], r13
        ; Square
        ;  A[0] * A[1]
        mov	rax, QWORD PTR [rsp+128]
        mul	QWORD PTR [rsp+136]
        mov	r11, rax
        mov	r12, rdx
        ;  A[0] * A[2]
        mov	rax, QWORD PTR [rsp+128]
        mul	QWORD PTR [rsp+144]
        xor	r13, r13
        add	r12, rax
        adc	r13, rdx
        ;  A[0] * A[3]
        mov	rax, QWORD PTR [rsp+128]
        mul	QWORD PTR [rsp+152]
        xor	r14, r14
        add	r13, rax
        adc	r14, rdx
        ;  A[1] * A[2]
        mov	rax, QWORD PTR [rsp+136]
        mul	QWORD PTR [rsp+144]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[1] * A[3]
        mov	rax, QWORD PTR [rsp+136]
        mul	QWORD PTR [rsp+152]
        add	r14, rax
        adc	r15, rdx
        ;  A[2] * A[3]
        mov	rax, QWORD PTR [rsp+144]
        mul	QWORD PTR [rsp+152]
        xor	rdi, rdi
        add	r15, rax
        adc	rdi, rdx
        ; Double
        xor	rsi, rsi
        add	r11, r11
        adc	r12, r12
        adc	r13, r13
        adc	r14, r14
        adc	r15, r15
        adc	rdi, rdi
        adc	rsi, 0
        ;  A[0] * A[0]
        mov	rax, QWORD PTR [rsp+128]
        mul	rax
        mov	rcx, rax
        mov	rbp, rdx
        ;  A[1] * A[1]
        mov	rax, QWORD PTR [rsp+136]
        mul	rax
        add	r11, rbp
        adc	r12, rax
        adc	rdx, 0
        mov	rbp, rdx
        ;  A[2] * A[2]
        mov	rax, QWORD PTR [rsp+144]
        mul	rax
        add	r13, rbp
        adc	r14, rax
        adc	rdx, 0
        mov	rbp, rdx
        ;  A[3] * A[3]
        mov	rax, QWORD PTR [rsp+152]
        mul	rax
        add	rdi, rax
        adc	rsi, rdx
        add	r15, rbp
        adc	rdi, 0
        adc	rsi, 0
        mov	rax, 38
        mul	rsi
        add	r13, rax
        adc	rdx, 0
        mov	rbp, 9223372036854775807
        shld	rdx, r13, 1
        imul	rdx, rdx, 19
        and	r13, rbp
        mov	rbp, rdx
        mov	rax, 38
        mul	r14
        xor	r14, r14
        add	rcx, rax
        mov	rax, 38
        adc	r14, rdx
        mul	r15
        xor	r15, r15
        add	r11, rax
        mov	rax, 38
        adc	r15, rdx
        mul	rdi
        xor	rdi, rdi
        add	r12, rax
        adc	rdi, rdx
        add	rcx, rbp
        adc	r11, r14
        adc	r12, r15
        adc	r13, rdi
        ; Store
        mov	QWORD PTR [rsp+96], rcx
        mov	QWORD PTR [rsp+104], r11
        mov	QWORD PTR [rsp+112], r12
        mov	QWORD PTR [rsp+120], r13
        ; Square
        ;  A[0] * A[1]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r9+8]
        mov	r11, rax
        mov	r12, rdx
        ;  A[0] * A[2]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r9+16]
        xor	r13, r13
        add	r12, rax
        adc	r13, rdx
        ;  A[0] * A[3]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r9+24]
        xor	r14, r14
        add	r13, rax
        adc	r14, rdx
        ;  A[1] * A[2]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r9+16]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[1] * A[3]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r9+24]
        add	r14, rax
        adc	r15, rdx
        ;  A[2] * A[3]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r9+24]
        xor	rdi, rdi
        add	r15, rax
        adc	rdi, rdx
        ; Double
        xor	rsi, rsi
        add	r11, r11
        adc	r12, r12
        adc	r13, r13
        adc	r14, r14
        adc	r15, r15
        adc	rdi, rdi
        adc	rsi, 0
        ;  A[0] * A[0]
        mov	rax, QWORD PTR [r9]
        mul	rax
        mov	rcx, rax
        mov	rbp, rdx
        ;  A[1] * A[1]
        mov	rax, QWORD PTR [r9+8]
        mul	rax
        add	r11, rbp
        adc	r12, rax
        adc	rdx, 0
        mov	rbp, rdx
        ;  A[2] * A[2]
        mov	rax, QWORD PTR [r9+16]
        mul	rax
        add	r13, rbp
        adc	r14, rax
        adc	rdx, 0
        mov	rbp, rdx
        ;  A[3] * A[3]
        mov	rax, QWORD PTR [r9+24]
        mul	rax
        add	rdi, rax
        adc	rsi, rdx
        add	r15, rbp
        adc	rdi, 0
        adc	rsi, 0
        mov	rax, 38
        mul	rsi
        add	r13, rax
        adc	rdx, 0
        mov	rbp, 9223372036854775807
        shld	rdx, r13, 1
        imul	rdx, rdx, 19
        and	r13, rbp
        mov	rbp, rdx
        mov	rax, 38
        mul	r14
        xor	r14, r14
        add	rcx, rax
        mov	rax, 38
        adc	r14, rdx
        mul	r15
        xor	r15, r15
        add	r11, rax
        mov	rax, 38
        adc	r15, rdx
        mul	rdi
        xor	rdi, rdi
        add	r12, rax
        adc	rdi, rdx
        add	rcx, rbp
        adc	r11, r14
        adc	r12, r15
        adc	r13, rdi
        ; Store
        mov	QWORD PTR [rsp+128], rcx
        mov	QWORD PTR [rsp+136], r11
        mov	QWORD PTR [rsp+144], r12
        mov	QWORD PTR [rsp+152], r13
        ; Add-Sub
        ; Add
        mov	rcx, QWORD PTR [rsp]
        mov	r11, QWORD PTR [rsp+8]
        mov	r12, QWORD PTR [rsp+16]
        mov	r13, QWORD PTR [rsp+24]
        mov	r14, rcx
        add	rcx, QWORD PTR [rsp+32]
        mov	r15, r11
        adc	r11, QWORD PTR [rsp+40]
        mov	rdi, r12
        adc	r12, QWORD PTR [rsp+48]
        mov	rsi, r13
        adc	r13, QWORD PTR [rsp+56]
        mov	rbp, 0
        adc	rbp, 0
        shld	rbp, r13, 1
        imul	rbp, 19
        btr	r13, 63
        ;   Sub modulus (if overflow)
        add	rcx, rbp
        adc	r11, 0
        adc	r12, 0
        adc	r13, 0
        ; Sub
        sub	r14, QWORD PTR [rsp+32]
        sbb	r15, QWORD PTR [rsp+40]
        sbb	rdi, QWORD PTR [rsp+48]
        sbb	rsi, QWORD PTR [rsp+56]
        sbb	rbp, rbp
        shld	rbp, rsi, 1
        imul	rbp, -19
        btr	rsi, 63
        ;   Add modulus (if underflow)
        sub	r14, rbp
        sbb	r15, 0
        sbb	rdi, 0
        sbb	rsi, 0
        mov	QWORD PTR [rsp+64], rcx
        mov	QWORD PTR [rsp+72], r11
        mov	QWORD PTR [rsp+80], r12
        mov	QWORD PTR [rsp+88], r13
        mov	QWORD PTR [rsp+32], r14
        mov	QWORD PTR [rsp+40], r15
        mov	QWORD PTR [rsp+48], rdi
        mov	QWORD PTR [rsp+56], rsi
        ; Multiply
        ;  A[0] * B[0]
        mov	rax, QWORD PTR [rsp+96]
        mul	QWORD PTR [rsp+128]
        mov	rcx, rax
        mov	r11, rdx
        ;  A[0] * B[1]
        mov	rax, QWORD PTR [rsp+104]
        mul	QWORD PTR [rsp+128]
        xor	r12, r12
        add	r11, rax
        adc	r12, rdx
        ;  A[1] * B[0]
        mov	rax, QWORD PTR [rsp+96]
        mul	QWORD PTR [rsp+136]
        xor	r13, r13
        add	r11, rax
        adc	r12, rdx
        adc	r13, 0
        ;  A[0] * B[2]
        mov	rax, QWORD PTR [rsp+112]
        mul	QWORD PTR [rsp+128]
        add	r12, rax
        adc	r13, rdx
        ;  A[1] * B[1]
        mov	rax, QWORD PTR [rsp+104]
        mul	QWORD PTR [rsp+136]
        xor	r14, r14
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[2] * B[0]
        mov	rax, QWORD PTR [rsp+96]
        mul	QWORD PTR [rsp+144]
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[0] * B[3]
        mov	rax, QWORD PTR [rsp+120]
        mul	QWORD PTR [rsp+128]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[1] * B[2]
        mov	rax, QWORD PTR [rsp+112]
        mul	QWORD PTR [rsp+136]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[2] * B[1]
        mov	rax, QWORD PTR [rsp+104]
        mul	QWORD PTR [rsp+144]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[3] * B[0]
        mov	rax, QWORD PTR [rsp+96]
        mul	QWORD PTR [rsp+152]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[1] * B[3]
        mov	rax, QWORD PTR [rsp+120]
        mul	QWORD PTR [rsp+136]
        xor	rdi, rdi
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[2] * B[2]
        mov	rax, QWORD PTR [rsp+112]
        mul	QWORD PTR [rsp+144]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[3] * B[1]
        mov	rax, QWORD PTR [rsp+104]
        mul	QWORD PTR [rsp+152]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[2] * B[3]
        mov	rax, QWORD PTR [rsp+120]
        mul	QWORD PTR [rsp+144]
        xor	rsi, rsi
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[3] * B[2]
        mov	rax, QWORD PTR [rsp+112]
        mul	QWORD PTR [rsp+152]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[3] * B[3]
        mov	rax, QWORD PTR [rsp+120]
        mul	QWORD PTR [rsp+152]
        add	rdi, rax
        adc	rsi, rdx
        mov	rax, 38
        mul	rsi
        add	r13, rax
        adc	rdx, 0
        mov	rbp, 9223372036854775807
        shld	rdx, r13, 1
        imul	rdx, rdx, 19
        and	r13, rbp
        mov	rbp, rdx
        mov	rax, 38
        mul	r14
        xor	r14, r14
        add	rcx, rax
        mov	rax, 38
        adc	r14, rdx
        mul	r15
        xor	r15, r15
        add	r11, rax
        mov	rax, 38
        adc	r15, rdx
        mul	rdi
        xor	rdi, rdi
        add	r12, rax
        adc	rdi, rdx
        add	rcx, rbp
        adc	r11, r14
        adc	r12, r15
        adc	r13, rdi
        ; Store
        mov	QWORD PTR [r9], rcx
        mov	QWORD PTR [r9+8], r11
        mov	QWORD PTR [r9+16], r12
        mov	QWORD PTR [r9+24], r13
        ; Sub
        mov	rcx, QWORD PTR [rsp+128]
        mov	r11, QWORD PTR [rsp+136]
        mov	r12, QWORD PTR [rsp+144]
        mov	r13, QWORD PTR [rsp+152]
        sub	rcx, QWORD PTR [rsp+96]
        sbb	r11, QWORD PTR [rsp+104]
        sbb	r12, QWORD PTR [rsp+112]
        sbb	r13, QWORD PTR [rsp+120]
        sbb	rbp, rbp
        shld	rbp, r13, 1
        imul	rbp, -19
        btr	r13, 63
        ;   Add modulus (if underflow)
        sub	rcx, rbp
        sbb	r11, 0
        sbb	r12, 0
        sbb	r13, 0
        mov	QWORD PTR [rsp+128], rcx
        mov	QWORD PTR [rsp+136], r11
        mov	QWORD PTR [rsp+144], r12
        mov	QWORD PTR [rsp+152], r13
        ; Square
        ;  A[0] * A[1]
        mov	rax, QWORD PTR [rsp+32]
        mul	QWORD PTR [rsp+40]
        mov	r11, rax
        mov	r12, rdx
        ;  A[0] * A[2]
        mov	rax, QWORD PTR [rsp+32]
        mul	QWORD PTR [rsp+48]
        xor	r13, r13
        add	r12, rax
        adc	r13, rdx
        ;  A[0] * A[3]
        mov	rax, QWORD PTR [rsp+32]
        mul	QWORD PTR [rsp+56]
        xor	r14, r14
        add	r13, rax
        adc	r14, rdx
        ;  A[1] * A[2]
        mov	rax, QWORD PTR [rsp+40]
        mul	QWORD PTR [rsp+48]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[1] * A[3]
        mov	rax, QWORD PTR [rsp+40]
        mul	QWORD PTR [rsp+56]
        add	r14, rax
        adc	r15, rdx
        ;  A[2] * A[3]
        mov	rax, QWORD PTR [rsp+48]
        mul	QWORD PTR [rsp+56]
        xor	rdi, rdi
        add	r15, rax
        adc	rdi, rdx
        ; Double
        xor	rsi, rsi
        add	r11, r11
        adc	r12, r12
        adc	r13, r13
        adc	r14, r14
        adc	r15, r15
        adc	rdi, rdi
        adc	rsi, 0
        ;  A[0] * A[0]
        mov	rax, QWORD PTR [rsp+32]
        mul	rax
        mov	rcx, rax
        mov	rbp, rdx
        ;  A[1] * A[1]
        mov	rax, QWORD PTR [rsp+40]
        mul	rax
        add	r11, rbp
        adc	r12, rax
        adc	rdx, 0
        mov	rbp, rdx
        ;  A[2] * A[2]
        mov	rax, QWORD PTR [rsp+48]
        mul	rax
        add	r13, rbp
        adc	r14, rax
        adc	rdx, 0
        mov	rbp, rdx
        ;  A[3] * A[3]
        mov	rax, QWORD PTR [rsp+56]
        mul	rax
        add	rdi, rax
        adc	rsi, rdx
        add	r15, rbp
        adc	rdi, 0
        adc	rsi, 0
        mov	rax, 38
        mul	rsi
        add	r13, rax
        adc	rdx, 0
        mov	rbp, 9223372036854775807
        shld	rdx, r13, 1
        imul	rdx, rdx, 19
        and	r13, rbp
        mov	rbp, rdx
        mov	rax, 38
        mul	r14
        xor	r14, r14
        add	rcx, rax
        mov	rax, 38
        adc	r14, rdx
        mul	r15
        xor	r15, r15
        add	r11, rax
        mov	rax, 38
        adc	r15, rdx
        mul	rdi
        xor	rdi, rdi
        add	r12, rax
        adc	rdi, rdx
        add	rcx, rbp
        adc	r11, r14
        adc	r12, r15
        adc	r13, rdi
        ; Store
        mov	QWORD PTR [rsp+32], rcx
        mov	QWORD PTR [rsp+40], r11
        mov	QWORD PTR [rsp+48], r12
        mov	QWORD PTR [rsp+56], r13
        ; Square
        ;  A[0] * A[1]
        mov	rax, QWORD PTR [rsp+64]
        mul	QWORD PTR [rsp+72]
        mov	r11, rax
        mov	r12, rdx
        ;  A[0] * A[2]
        mov	rax, QWORD PTR [rsp+64]
        mul	QWORD PTR [rsp+80]
        xor	r13, r13
        add	r12, rax
        adc	r13, rdx
        ;  A[0] * A[3]
        mov	rax, QWORD PTR [rsp+64]
        mul	QWORD PTR [rsp+88]
        xor	r14, r14
        add	r13, rax
        adc	r14, rdx
        ;  A[1] * A[2]
        mov	rax, QWORD PTR [rsp+72]
        mul	QWORD PTR [rsp+80]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[1] * A[3]
        mov	rax, QWORD PTR [rsp+72]
        mul	QWORD PTR [rsp+88]
        add	r14, rax
        adc	r15, rdx
        ;  A[2] * A[3]
        mov	rax, QWORD PTR [rsp+80]
        mul	QWORD PTR [rsp+88]
        xor	rdi, rdi
        add	r15, rax
        adc	rdi, rdx
        ; Double
        xor	rsi, rsi
        add	r11, r11
        adc	r12, r12
        adc	r13, r13
        adc	r14, r14
        adc	r15, r15
        adc	rdi, rdi
        adc	rsi, 0
        ;  A[0] * A[0]
        mov	rax, QWORD PTR [rsp+64]
        mul	rax
        mov	rcx, rax
        mov	rbp, rdx
        ;  A[1] * A[1]
        mov	rax, QWORD PTR [rsp+72]
        mul	rax
        add	r11, rbp
        adc	r12, rax
        adc	rdx, 0
        mov	rbp, rdx
        ;  A[2] * A[2]
        mov	rax, QWORD PTR [rsp+80]
        mul	rax
        add	r13, rbp
        adc	r14, rax
        adc	rdx, 0
        mov	rbp, rdx
        ;  A[3] * A[3]
        mov	rax, QWORD PTR [rsp+88]
        mul	rax
        add	rdi, rax
        adc	rsi, rdx
        add	r15, rbp
        adc	rdi, 0
        adc	rsi, 0
        mov	rax, 38
        mul	rsi
        add	r13, rax
        adc	rdx, 0
        mov	rbp, 9223372036854775807
        shld	rdx, r13, 1
        imul	rdx, rdx, 19
        and	r13, rbp
        mov	rbp, rdx
        mov	rax, 38
        mul	r14
        xor	r14, r14
        add	rcx, rax
        mov	rax, 38
        adc	r14, rdx
        mul	r15
        xor	r15, r15
        add	r11, rax
        mov	rax, 38
        adc	r15, rdx
        mul	rdi
        xor	rdi, rdi
        add	r12, rax
        adc	rdi, rdx
        add	rcx, rbp
        adc	r11, r14
        adc	r12, r15
        adc	r13, rdi
        ; Store
        mov	QWORD PTR [rsp+64], rcx
        mov	QWORD PTR [rsp+72], r11
        mov	QWORD PTR [rsp+80], r12
        mov	QWORD PTR [rsp+88], r13
        ; Multiply by 121666
        mov	rax, 121666
        mul	QWORD PTR [rsp+128]
        xor	r12, r12
        mov	rcx, rax
        mov	r11, rdx
        mov	rax, 121666
        mul	QWORD PTR [rsp+136]
        xor	r13, r13
        add	r11, rax
        adc	r12, rdx
        mov	rax, 121666
        mul	QWORD PTR [rsp+144]
        xor	r15, r15
        add	r12, rax
        adc	r13, rdx
        mov	rax, 121666
        mul	QWORD PTR [rsp+152]
        mov	r14, 9223372036854775807
        add	r13, rax
        adc	r15, rdx
        add	rcx, QWORD PTR [rsp+96]
        adc	r11, QWORD PTR [rsp+104]
        adc	r12, QWORD PTR [rsp+112]
        adc	r13, QWORD PTR [rsp+120]
        adc	r15, 0
        shld	r15, r13, 1
        and	r13, r14
        mov	rax, 19
        mul	r15
        add	rcx, rax
        adc	r11, 0
        adc	r12, 0
        adc	r13, 0
        mov	QWORD PTR [rsp+96], rcx
        mov	QWORD PTR [rsp+104], r11
        mov	QWORD PTR [rsp+112], r12
        mov	QWORD PTR [rsp+120], r13
        ; Multiply
        ;  A[0] * B[0]
        mov	rax, QWORD PTR [rsp+32]
        mul	QWORD PTR [r8]
        mov	rcx, rax
        mov	r11, rdx
        ;  A[0] * B[1]
        mov	rax, QWORD PTR [rsp+40]
        mul	QWORD PTR [r8]
        xor	r12, r12
        add	r11, rax
        adc	r12, rdx
        ;  A[1] * B[0]
        mov	rax, QWORD PTR [rsp+32]
        mul	QWORD PTR [r8+8]
        xor	r13, r13
        add	r11, rax
        adc	r12, rdx
        adc	r13, 0
        ;  A[0] * B[2]
        mov	rax, QWORD PTR [rsp+48]
        mul	QWORD PTR [r8]
        add	r12, rax
        adc	r13, rdx
        ;  A[1] * B[1]
        mov	rax, QWORD PTR [rsp+40]
        mul	QWORD PTR [r8+8]
        xor	r14, r14
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[2] * B[0]
        mov	rax, QWORD PTR [rsp+32]
        mul	QWORD PTR [r8+16]
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[0] * B[3]
        mov	rax, QWORD PTR [rsp+56]
        mul	QWORD PTR [r8]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[1] * B[2]
        mov	rax, QWORD PTR [rsp+48]
        mul	QWORD PTR [r8+8]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[2] * B[1]
        mov	rax, QWORD PTR [rsp+40]
        mul	QWORD PTR [r8+16]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[3] * B[0]
        mov	rax, QWORD PTR [rsp+32]
        mul	QWORD PTR [r8+24]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[1] * B[3]
        mov	rax, QWORD PTR [rsp+56]
        mul	QWORD PTR [r8+8]
        xor	rdi, rdi
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[2] * B[2]
        mov	rax, QWORD PTR [rsp+48]
        mul	QWORD PTR [r8+16]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[3] * B[1]
        mov	rax, QWORD PTR [rsp+40]
        mul	QWORD PTR [r8+24]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[2] * B[3]
        mov	rax, QWORD PTR [rsp+56]
        mul	QWORD PTR [r8+16]
        xor	rsi, rsi
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[3] * B[2]
        mov	rax, QWORD PTR [rsp+48]
        mul	QWORD PTR [r8+24]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[3] * B[3]
        mov	rax, QWORD PTR [rsp+56]
        mul	QWORD PTR [r8+24]
        add	rdi, rax
        adc	rsi, rdx
        mov	rax, 38
        mul	rsi
        add	r13, rax
        adc	rdx, 0
        mov	rbp, 9223372036854775807
        shld	rdx, r13, 1
        imul	rdx, rdx, 19
        and	r13, rbp
        mov	rbp, rdx
        mov	rax, 38
        mul	r14
        xor	r14, r14
        add	rcx, rax
        mov	rax, 38
        adc	r14, rdx
        mul	r15
        xor	r15, r15
        add	r11, rax
        mov	rax, 38
        adc	r15, rdx
        mul	rdi
        xor	rdi, rdi
        add	r12, rax
        adc	rdi, rdx
        add	rcx, rbp
        adc	r11, r14
        adc	r12, r15
        adc	r13, rdi
        ; Store
        mov	QWORD PTR [rsp+32], rcx
        mov	QWORD PTR [rsp+40], r11
        mov	QWORD PTR [rsp+48], r12
        mov	QWORD PTR [rsp+56], r13
        ; Multiply
        ;  A[0] * B[0]
        mov	rax, QWORD PTR [rsp+96]
        mul	QWORD PTR [rsp+128]
        mov	rcx, rax
        mov	r11, rdx
        ;  A[0] * B[1]
        mov	rax, QWORD PTR [rsp+104]
        mul	QWORD PTR [rsp+128]
        xor	r12, r12
        add	r11, rax
        adc	r12, rdx
        ;  A[1] * B[0]
        mov	rax, QWORD PTR [rsp+96]
        mul	QWORD PTR [rsp+136]
        xor	r13, r13
        add	r11, rax
        adc	r12, rdx
        adc	r13, 0
        ;  A[0] * B[2]
        mov	rax, QWORD PTR [rsp+112]
        mul	QWORD PTR [rsp+128]
        add	r12, rax
        adc	r13, rdx
        ;  A[1] * B[1]
        mov	rax, QWORD PTR [rsp+104]
        mul	QWORD PTR [rsp+136]
        xor	r14, r14
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[2] * B[0]
        mov	rax, QWORD PTR [rsp+96]
        mul	QWORD PTR [rsp+144]
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[0] * B[3]
        mov	rax, QWORD PTR [rsp+120]
        mul	QWORD PTR [rsp+128]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[1] * B[2]
        mov	rax, QWORD PTR [rsp+112]
        mul	QWORD PTR [rsp+136]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[2] * B[1]
        mov	rax, QWORD PTR [rsp+104]
        mul	QWORD PTR [rsp+144]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[3] * B[0]
        mov	rax, QWORD PTR [rsp+96]
        mul	QWORD PTR [rsp+152]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[1] * B[3]
        mov	rax, QWORD PTR [rsp+120]
        mul	QWORD PTR [rsp+136]
        xor	rdi, rdi
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[2] * B[2]
        mov	rax, QWORD PTR [rsp+112]
        mul	QWORD PTR [rsp+144]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[3] * B[1]
        mov	rax, QWORD PTR [rsp+104]
        mul	QWORD PTR [rsp+152]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[2] * B[3]
        mov	rax, QWORD PTR [rsp+120]
        mul	QWORD PTR [rsp+144]
        xor	rsi, rsi
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[3] * B[2]
        mov	rax, QWORD PTR [rsp+112]
        mul	QWORD PTR [rsp+152]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[3] * B[3]
        mov	rax, QWORD PTR [rsp+120]
        mul	QWORD PTR [rsp+152]
        add	rdi, rax
        adc	rsi, rdx
        mov	rax, 38
        mul	rsi
        add	r13, rax
        adc	rdx, 0
        mov	rbp, 9223372036854775807
        shld	rdx, r13, 1
        imul	rdx, rdx, 19
        and	r13, rbp
        mov	rbp, rdx
        mov	rax, 38
        mul	r14
        xor	r14, r14
        add	rcx, rax
        mov	rax, 38
        adc	r14, rdx
        mul	r15
        xor	r15, r15
        add	r11, rax
        mov	rax, 38
        adc	r15, rdx
        mul	rdi
        xor	rdi, rdi
        add	r12, rax
        adc	rdi, rdx
        add	rcx, rbp
        adc	r11, r14
        adc	r12, r15
        adc	r13, rdi
        ; Store
        mov	QWORD PTR [rsp], rcx
        mov	QWORD PTR [rsp+8], r11
        mov	QWORD PTR [rsp+16], r12
        mov	QWORD PTR [rsp+24], r13
        mov	r11, QWORD PTR [rsp+160]
        dec	r11
        cmp	r11, 3
        jge	L_curve25519_x64_bits
        mov	QWORD PTR [rsp+160], 2
        neg	rbx
        ; Conditional Swap
        mov	rcx, QWORD PTR [r9]
        mov	r11, QWORD PTR [r9+8]
        mov	r12, QWORD PTR [r9+16]
        mov	r13, QWORD PTR [r9+24]
        mov	r14, QWORD PTR [rsp]
        mov	r15, QWORD PTR [rsp+8]
        mov	rdi, QWORD PTR [rsp+16]
        mov	rsi, QWORD PTR [rsp+24]
        xor	rcx, QWORD PTR [rsp+64]
        xor	r11, QWORD PTR [rsp+72]
        xor	r12, QWORD PTR [rsp+80]
        xor	r13, QWORD PTR [rsp+88]
        xor	r14, QWORD PTR [rsp+32]
        xor	r15, QWORD PTR [rsp+40]
        xor	rdi, QWORD PTR [rsp+48]
        xor	rsi, QWORD PTR [rsp+56]
        and	rcx, rbx
        and	r11, rbx
        and	r12, rbx
        and	r13, rbx
        and	r14, rbx
        and	r15, rbx
        and	rdi, rbx
        and	rsi, rbx
        xor	QWORD PTR [r9], rcx
        xor	QWORD PTR [r9+8], r11
        xor	QWORD PTR [r9+16], r12
        xor	QWORD PTR [r9+24], r13
        xor	QWORD PTR [rsp], r14
        xor	QWORD PTR [rsp+8], r15
        xor	QWORD PTR [rsp+16], rdi
        xor	QWORD PTR [rsp+24], rsi
        xor	QWORD PTR [rsp+64], rcx
        xor	QWORD PTR [rsp+72], r11
        xor	QWORD PTR [rsp+80], r12
        xor	QWORD PTR [rsp+88], r13
        xor	QWORD PTR [rsp+32], r14
        xor	QWORD PTR [rsp+40], r15
        xor	QWORD PTR [rsp+48], rdi
        xor	QWORD PTR [rsp+56], rsi
L_curve25519_x64_3:
        ; Add-Sub
        ; Add
        mov	rcx, QWORD PTR [r9]
        mov	r11, QWORD PTR [r9+8]
        mov	r12, QWORD PTR [r9+16]
        mov	r13, QWORD PTR [r9+24]
        mov	r14, rcx
        add	rcx, QWORD PTR [rsp]
        mov	r15, r11
        adc	r11, QWORD PTR [rsp+8]
        mov	rdi, r12
        adc	r12, QWORD PTR [rsp+16]
        mov	rsi, r13
        adc	r13, QWORD PTR [rsp+24]
        mov	rbp, 0
        adc	rbp, 0
        shld	rbp, r13, 1
        imul	rbp, 19
        btr	r13, 63
        ;   Sub modulus (if overflow)
        add	rcx, rbp
        adc	r11, 0
        adc	r12, 0
        adc	r13, 0
        ; Sub
        sub	r14, QWORD PTR [rsp]
        sbb	r15, QWORD PTR [rsp+8]
        sbb	rdi, QWORD PTR [rsp+16]
        sbb	rsi, QWORD PTR [rsp+24]
        sbb	rbp, rbp
        shld	rbp, rsi, 1
        imul	rbp, -19
        btr	rsi, 63
        ;   Add modulus (if underflow)
        sub	r14, rbp
        sbb	r15, 0
        sbb	rdi, 0
        sbb	rsi, 0
        mov	QWORD PTR [r9], rcx
        mov	QWORD PTR [r9+8], r11
        mov	QWORD PTR [r9+16], r12
        mov	QWORD PTR [r9+24], r13
        mov	QWORD PTR [rsp+128], r14
        mov	QWORD PTR [rsp+136], r15
        mov	QWORD PTR [rsp+144], rdi
        mov	QWORD PTR [rsp+152], rsi
        ; Square
        ;  A[0] * A[1]
        mov	rax, QWORD PTR [rsp+128]
        mul	QWORD PTR [rsp+136]
        mov	r11, rax
        mov	r12, rdx
        ;  A[0] * A[2]
        mov	rax, QWORD PTR [rsp+128]
        mul	QWORD PTR [rsp+144]
        xor	r13, r13
        add	r12, rax
        adc	r13, rdx
        ;  A[0] * A[3]
        mov	rax, QWORD PTR [rsp+128]
        mul	QWORD PTR [rsp+152]
        xor	r14, r14
        add	r13, rax
        adc	r14, rdx
        ;  A[1] * A[2]
        mov	rax, QWORD PTR [rsp+136]
        mul	QWORD PTR [rsp+144]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[1] * A[3]
        mov	rax, QWORD PTR [rsp+136]
        mul	QWORD PTR [rsp+152]
        add	r14, rax
        adc	r15, rdx
        ;  A[2] * A[3]
        mov	rax, QWORD PTR [rsp+144]
        mul	QWORD PTR [rsp+152]
        xor	rdi, rdi
        add	r15, rax
        adc	rdi, rdx
        ; Double
        xor	rsi, rsi
        add	r11, r11
        adc	r12, r12
        adc	r13, r13
        adc	r14, r14
        adc	r15, r15
        adc	rdi, rdi
        adc	rsi, 0
        ;  A[0] * A[0]
        mov	rax, QWORD PTR [rsp+128]
        mul	rax
        mov	rcx, rax
        mov	rbp, rdx
        ;  A[1] * A[1]
        mov	rax, QWORD PTR [rsp+136]
        mul	rax
        add	r11, rbp
        adc	r12, rax
        adc	rdx, 0
        mov	rbp, rdx
        ;  A[2] * A[2]
        mov	rax, QWORD PTR [rsp+144]
        mul	rax
        add	r13, rbp
        adc	r14, rax
        adc	rdx, 0
        mov	rbp, rdx
        ;  A[3] * A[3]
        mov	rax, QWORD PTR [rsp+152]
        mul	rax
        add	rdi, rax
        adc	rsi, rdx
        add	r15, rbp
        adc	rdi, 0
        adc	rsi, 0
        mov	rax, 38
        mul	rsi
        add	r13, rax
        adc	rdx, 0
        mov	rbp, 9223372036854775807
        shld	rdx, r13, 1
        imul	rdx, rdx, 19
        and	r13, rbp
        mov	rbp, rdx
        mov	rax, 38
        mul	r14
        xor	r14, r14
        add	rcx, rax
        mov	rax, 38
        adc	r14, rdx
        mul	r15
        xor	r15, r15
        add	r11, rax
        mov	rax, 38
        adc	r15, rdx
        mul	rdi
        xor	rdi, rdi
        add	r12, rax
        adc	rdi, rdx
        add	rcx, rbp
        adc	r11, r14
        adc	r12, r15
        adc	r13, rdi
        ; Store
        mov	QWORD PTR [rsp+96], rcx
        mov	QWORD PTR [rsp+104], r11
        mov	QWORD PTR [rsp+112], r12
        mov	QWORD PTR [rsp+120], r13
        ; Square
        ;  A[0] * A[1]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r9+8]
        mov	r11, rax
        mov	r12, rdx
        ;  A[0] * A[2]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r9+16]
        xor	r13, r13
        add	r12, rax
        adc	r13, rdx
        ;  A[0] * A[3]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r9+24]
        xor	r14, r14
        add	r13, rax
        adc	r14, rdx
        ;  A[1] * A[2]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r9+16]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[1] * A[3]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r9+24]
        add	r14, rax
        adc	r15, rdx
        ;  A[2] * A[3]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r9+24]
        xor	rdi, rdi
        add	r15, rax
        adc	rdi, rdx
        ; Double
        xor	rsi, rsi
        add	r11, r11
        adc	r12, r12
        adc	r13, r13
        adc	r14, r14
        adc	r15, r15
        adc	rdi, rdi
        adc	rsi, 0
        ;  A[0] * A[0]
        mov	rax, QWORD PTR [r9]
        mul	rax
        mov	rcx, rax
        mov	rbp, rdx
        ;  A[1] * A[1]
        mov	rax, QWORD PTR [r9+8]
        mul	rax
        add	r11, rbp
        adc	r12, rax
        adc	rdx, 0
        mov	rbp, rdx
        ;  A[2] * A[2]
        mov	rax, QWORD PTR [r9+16]
        mul	rax
        add	r13, rbp
        adc	r14, rax
        adc	rdx, 0
        mov	rbp, rdx
        ;  A[3] * A[3]
        mov	rax, QWORD PTR [r9+24]
        mul	rax
        add	rdi, rax
        adc	rsi, rdx
        add	r15, rbp
        adc	rdi, 0
        adc	rsi, 0
        mov	rax, 38
        mul	rsi
        add	r13, rax
        adc	rdx, 0
        mov	rbp, 9223372036854775807
        shld	rdx, r13, 1
        imul	rdx, rdx, 19
        and	r13, rbp
        mov	rbp, rdx
        mov	rax, 38
        mul	r14
        xor	r14, r14
        add	rcx, rax
        mov	rax, 38
        adc	r14, rdx
        mul	r15
        xor	r15, r15
        add	r11, rax
        mov	rax, 38
        adc	r15, rdx
        mul	rdi
        xor	rdi, rdi
        add	r12, rax
        adc	rdi, rdx
        add	rcx, rbp
        adc	r11, r14
        adc	r12, r15
        adc	r13, rdi
        ; Store
        mov	QWORD PTR [rsp+128], rcx
        mov	QWORD PTR [rsp+136], r11
        mov	QWORD PTR [rsp+144], r12
        mov	QWORD PTR [rsp+152], r13
        ; Multiply
        ;  A[0] * B[0]
        mov	rax, QWORD PTR [rsp+96]
        mul	QWORD PTR [rsp+128]
        mov	rcx, rax
        mov	r11, rdx
        ;  A[0] * B[1]
        mov	rax, QWORD PTR [rsp+104]
        mul	QWORD PTR [rsp+128]
        xor	r12, r12
        add	r11, rax
        adc	r12, rdx
        ;  A[1] * B[0]
        mov	rax, QWORD PTR [rsp+96]
        mul	QWORD PTR [rsp+136]
        xor	r13, r13
        add	r11, rax
        adc	r12, rdx
        adc	r13, 0
        ;  A[0] * B[2]
        mov	rax, QWORD PTR [rsp+112]
        mul	QWORD PTR [rsp+128]
        add	r12, rax
        adc	r13, rdx
        ;  A[1] * B[1]
        mov	rax, QWORD PTR [rsp+104]
        mul	QWORD PTR [rsp+136]
        xor	r14, r14
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[2] * B[0]
        mov	rax, QWORD PTR [rsp+96]
        mul	QWORD PTR [rsp+144]
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[0] * B[3]
        mov	rax, QWORD PTR [rsp+120]
        mul	QWORD PTR [rsp+128]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[1] * B[2]
        mov	rax, QWORD PTR [rsp+112]
        mul	QWORD PTR [rsp+136]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[2] * B[1]
        mov	rax, QWORD PTR [rsp+104]
        mul	QWORD PTR [rsp+144]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[3] * B[0]
        mov	rax, QWORD PTR [rsp+96]
        mul	QWORD PTR [rsp+152]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[1] * B[3]
        mov	rax, QWORD PTR [rsp+120]
        mul	QWORD PTR [rsp+136]
        xor	rdi, rdi
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[2] * B[2]
        mov	rax, QWORD PTR [rsp+112]
        mul	QWORD PTR [rsp+144]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[3] * B[1]
        mov	rax, QWORD PTR [rsp+104]
        mul	QWORD PTR [rsp+152]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[2] * B[3]
        mov	rax, QWORD PTR [rsp+120]
        mul	QWORD PTR [rsp+144]
        xor	rsi, rsi
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[3] * B[2]
        mov	rax, QWORD PTR [rsp+112]
        mul	QWORD PTR [rsp+152]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[3] * B[3]
        mov	rax, QWORD PTR [rsp+120]
        mul	QWORD PTR [rsp+152]
        add	rdi, rax
        adc	rsi, rdx
        mov	rax, 38
        mul	rsi
        add	r13, rax
        adc	rdx, 0
        mov	rbp, 9223372036854775807
        shld	rdx, r13, 1
        imul	rdx, rdx, 19
        and	r13, rbp
        mov	rbp, rdx
        mov	rax, 38
        mul	r14
        xor	r14, r14
        add	rcx, rax
        mov	rax, 38
        adc	r14, rdx
        mul	r15
        xor	r15, r15
        add	r11, rax
        mov	rax, 38
        adc	r15, rdx
        mul	rdi
        xor	rdi, rdi
        add	r12, rax
        adc	rdi, rdx
        add	rcx, rbp
        adc	r11, r14
        adc	r12, r15
        adc	r13, rdi
        ; Store
        mov	QWORD PTR [r9], rcx
        mov	QWORD PTR [r9+8], r11
        mov	QWORD PTR [r9+16], r12
        mov	QWORD PTR [r9+24], r13
        ; Sub
        mov	rcx, QWORD PTR [rsp+128]
        mov	r11, QWORD PTR [rsp+136]
        mov	r12, QWORD PTR [rsp+144]
        mov	r13, QWORD PTR [rsp+152]
        sub	rcx, QWORD PTR [rsp+96]
        sbb	r11, QWORD PTR [rsp+104]
        sbb	r12, QWORD PTR [rsp+112]
        sbb	r13, QWORD PTR [rsp+120]
        sbb	rbp, rbp
        shld	rbp, r13, 1
        imul	rbp, -19
        btr	r13, 63
        ;   Add modulus (if underflow)
        sub	rcx, rbp
        sbb	r11, 0
        sbb	r12, 0
        sbb	r13, 0
        mov	QWORD PTR [rsp+128], rcx
        mov	QWORD PTR [rsp+136], r11
        mov	QWORD PTR [rsp+144], r12
        mov	QWORD PTR [rsp+152], r13
        ; Multiply by 121666
        mov	rax, 121666
        mul	QWORD PTR [rsp+128]
        xor	r12, r12
        mov	rcx, rax
        mov	r11, rdx
        mov	rax, 121666
        mul	QWORD PTR [rsp+136]
        xor	r13, r13
        add	r11, rax
        adc	r12, rdx
        mov	rax, 121666
        mul	QWORD PTR [rsp+144]
        xor	r15, r15
        add	r12, rax
        adc	r13, rdx
        mov	rax, 121666
        mul	QWORD PTR [rsp+152]
        mov	r14, 9223372036854775807
        add	r13, rax
        adc	r15, rdx
        add	rcx, QWORD PTR [rsp+96]
        adc	r11, QWORD PTR [rsp+104]
        adc	r12, QWORD PTR [rsp+112]
        adc	r13, QWORD PTR [rsp+120]
        adc	r15, 0
        shld	r15, r13, 1
        and	r13, r14
        mov	rax, 19
        mul	r15
        add	rcx, rax
        adc	r11, 0
        adc	r12, 0
        adc	r13, 0
        mov	QWORD PTR [rsp+96], rcx
        mov	QWORD PTR [rsp+104], r11
        mov	QWORD PTR [rsp+112], r12
        mov	QWORD PTR [rsp+120], r13
        ; Multiply
        ;  A[0] * B[0]
        mov	rax, QWORD PTR [rsp+96]
        mul	QWORD PTR [rsp+128]
        mov	rcx, rax
        mov	r11, rdx
        ;  A[0] * B[1]
        mov	rax, QWORD PTR [rsp+104]
        mul	QWORD PTR [rsp+128]
        xor	r12, r12
        add	r11, rax
        adc	r12, rdx
        ;  A[1] * B[0]
        mov	rax, QWORD PTR [rsp+96]
        mul	QWORD PTR [rsp+136]
        xor	r13, r13
        add	r11, rax
        adc	r12, rdx
        adc	r13, 0
        ;  A[0] * B[2]
        mov	rax, QWORD PTR [rsp+112]
        mul	QWORD PTR [rsp+128]
        add	r12, rax
        adc	r13, rdx
        ;  A[1] * B[1]
        mov	rax, QWORD PTR [rsp+104]
        mul	QWORD PTR [rsp+136]
        xor	r14, r14
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[2] * B[0]
        mov	rax, QWORD PTR [rsp+96]
        mul	QWORD PTR [rsp+144]
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[0] * B[3]
        mov	rax, QWORD PTR [rsp+120]
        mul	QWORD PTR [rsp+128]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[1] * B[2]
        mov	rax, QWORD PTR [rsp+112]
        mul	QWORD PTR [rsp+136]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[2] * B[1]
        mov	rax, QWORD PTR [rsp+104]
        mul	QWORD PTR [rsp+144]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[3] * B[0]
        mov	rax, QWORD PTR [rsp+96]
        mul	QWORD PTR [rsp+152]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[1] * B[3]
        mov	rax, QWORD PTR [rsp+120]
        mul	QWORD PTR [rsp+136]
        xor	rdi, rdi
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[2] * B[2]
        mov	rax, QWORD PTR [rsp+112]
        mul	QWORD PTR [rsp+144]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[3] * B[1]
        mov	rax, QWORD PTR [rsp+104]
        mul	QWORD PTR [rsp+152]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[2] * B[3]
        mov	rax, QWORD PTR [rsp+120]
        mul	QWORD PTR [rsp+144]
        xor	rsi, rsi
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[3] * B[2]
        mov	rax, QWORD PTR [rsp+112]
        mul	QWORD PTR [rsp+152]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[3] * B[3]
        mov	rax, QWORD PTR [rsp+120]
        mul	QWORD PTR [rsp+152]
        add	rdi, rax
        adc	rsi, rdx
        mov	rax, 38
        mul	rsi
        add	r13, rax
        adc	rdx, 0
        mov	rbp, 9223372036854775807
        shld	rdx, r13, 1
        imul	rdx, rdx, 19
        and	r13, rbp
        mov	rbp, rdx
        mov	rax, 38
        mul	r14
        xor	r14, r14
        add	rcx, rax
        mov	rax, 38
        adc	r14, rdx
        mul	r15
        xor	r15, r15
        add	r11, rax
        mov	rax, 38
        adc	r15, rdx
        mul	rdi
        xor	rdi, rdi
        add	r12, rax
        adc	rdi, rdx
        add	rcx, rbp
        adc	r11, r14
        adc	r12, r15
        adc	r13, rdi
        ; Store
        mov	QWORD PTR [rsp], rcx
        mov	QWORD PTR [rsp+8], r11
        mov	QWORD PTR [rsp+16], r12
        mov	QWORD PTR [rsp+24], r13
        dec	QWORD PTR [rsp+160]
        jge	L_curve25519_x64_3
        ; Invert
        lea	rcx, QWORD PTR [rsp+32]
        mov	rdx, rsp
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+32]
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+64]
        mov	rdx, rsp
        lea	r8, QWORD PTR [rsp+64]
        call	fe_mul_x64
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        lea	r8, QWORD PTR [rsp+64]
        call	fe_mul_x64
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+32]
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        lea	r8, QWORD PTR [rsp+96]
        call	fe_mul_x64
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+64]
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 4
        call	fe_sq_n_x64
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        call	fe_mul_x64
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+64]
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 9
        call	fe_sq_n_x64
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        call	fe_mul_x64
        lea	rcx, QWORD PTR [rsp+128]
        lea	rdx, QWORD PTR [rsp+96]
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+128]
        lea	rdx, QWORD PTR [rsp+128]
        mov	r8, 19
        call	fe_sq_n_x64
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+128]
        lea	r8, QWORD PTR [rsp+96]
        call	fe_mul_x64
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 9
        call	fe_sq_n_x64
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        call	fe_mul_x64
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+64]
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 49
        call	fe_sq_n_x64
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        call	fe_mul_x64
        lea	rcx, QWORD PTR [rsp+128]
        lea	rdx, QWORD PTR [rsp+96]
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+128]
        lea	rdx, QWORD PTR [rsp+128]
        mov	r8, 99
        call	fe_sq_n_x64
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+128]
        lea	r8, QWORD PTR [rsp+96]
        call	fe_mul_x64
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 49
        call	fe_sq_n_x64
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        call	fe_mul_x64
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        mov	r8, 4
        call	fe_sq_n_x64
        mov	rcx, rsp
        lea	rdx, QWORD PTR [rsp+64]
        lea	r8, QWORD PTR [rsp+32]
        call	fe_mul_x64
        mov	r9, QWORD PTR [rsp+168]
        ; Multiply
        ;  A[0] * B[0]
        mov	rax, QWORD PTR [rsp]
        mul	QWORD PTR [r9]
        mov	rcx, rax
        mov	r11, rdx
        ;  A[0] * B[1]
        mov	rax, QWORD PTR [rsp+8]
        mul	QWORD PTR [r9]
        xor	r12, r12
        add	r11, rax
        adc	r12, rdx
        ;  A[1] * B[0]
        mov	rax, QWORD PTR [rsp]
        mul	QWORD PTR [r9+8]
        xor	r13, r13
        add	r11, rax
        adc	r12, rdx
        adc	r13, 0
        ;  A[0] * B[2]
        mov	rax, QWORD PTR [rsp+16]
        mul	QWORD PTR [r9]
        add	r12, rax
        adc	r13, rdx
        ;  A[1] * B[1]
        mov	rax, QWORD PTR [rsp+8]
        mul	QWORD PTR [r9+8]
        xor	r14, r14
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[2] * B[0]
        mov	rax, QWORD PTR [rsp]
        mul	QWORD PTR [r9+16]
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[0] * B[3]
        mov	rax, QWORD PTR [rsp+24]
        mul	QWORD PTR [r9]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[1] * B[2]
        mov	rax, QWORD PTR [rsp+16]
        mul	QWORD PTR [r9+8]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[2] * B[1]
        mov	rax, QWORD PTR [rsp+8]
        mul	QWORD PTR [r9+16]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[3] * B[0]
        mov	rax, QWORD PTR [rsp]
        mul	QWORD PTR [r9+24]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[1] * B[3]
        mov	rax, QWORD PTR [rsp+24]
        mul	QWORD PTR [r9+8]
        xor	rdi, rdi
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[2] * B[2]
        mov	rax, QWORD PTR [rsp+16]
        mul	QWORD PTR [r9+16]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[3] * B[1]
        mov	rax, QWORD PTR [rsp+8]
        mul	QWORD PTR [r9+24]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[2] * B[3]
        mov	rax, QWORD PTR [rsp+24]
        mul	QWORD PTR [r9+16]
        xor	rsi, rsi
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[3] * B[2]
        mov	rax, QWORD PTR [rsp+16]
        mul	QWORD PTR [r9+24]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[3] * B[3]
        mov	rax, QWORD PTR [rsp+24]
        mul	QWORD PTR [r9+24]
        add	rdi, rax
        adc	rsi, rdx
        mov	rax, 38
        mul	rsi
        add	r13, rax
        adc	rdx, 0
        mov	rbp, 9223372036854775807
        shld	rdx, r13, 1
        imul	rdx, rdx, 19
        and	r13, rbp
        mov	rbp, rdx
        mov	rax, 38
        mul	r14
        xor	r14, r14
        add	rcx, rax
        mov	rax, 38
        adc	r14, rdx
        mul	r15
        xor	r15, r15
        add	r11, rax
        mov	rax, 38
        adc	r15, rdx
        mul	rdi
        xor	rdi, rdi
        add	r12, rax
        adc	rdi, rdx
        add	rcx, rbp
        adc	r11, r14
        adc	r12, r15
        adc	r13, rdi
        mov	rbp, 9223372036854775807
        mov	rax, r13
        sar	rax, 63
        and	rax, 19
        and	r13, rbp
        add	rcx, rax
        adc	r11, 0
        adc	r12, 0
        adc	r13, 0
        mov	rax, 9223372036854775807
        mov	rdx, rcx
        add	rdx, 19
        mov	rdx, r11
        adc	rdx, 0
        mov	rdx, r12
        adc	rdx, 0
        mov	rdx, r13
        adc	rdx, 0
        sar	rdx, 63
        and	rdx, 19
        and	r13, rax
        add	rcx, rdx
        adc	r11, 0
        adc	r12, 0
        adc	r13, 0
        and	r13, rax
        ; Store
        mov	QWORD PTR [r9], rcx
        mov	QWORD PTR [r9+8], r11
        mov	QWORD PTR [r9+16], r12
        mov	QWORD PTR [r9+24], r13
        xor	rax, rax
        add	rsp, 176
        pop	rbp
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
curve25519_x64 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
fe_pow22523_x64 PROC
        sub	rsp, 112
        ; pow22523
        mov	QWORD PTR [rsp+96], rcx
        mov	QWORD PTR [rsp+104], rdx
        mov	rcx, rsp
        mov	rdx, QWORD PTR [rsp+104]
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+32]
        mov	rdx, rsp
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+32]
        mov	rdx, QWORD PTR [rsp+104]
        lea	r8, QWORD PTR [rsp+32]
        call	fe_mul_x64
        mov	rcx, rsp
        mov	rdx, rsp
        lea	r8, QWORD PTR [rsp+32]
        call	fe_mul_x64
        mov	rcx, rsp
        mov	rdx, rsp
        call	fe_sq_x64
        mov	rcx, rsp
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, rsp
        call	fe_mul_x64
        lea	rcx, QWORD PTR [rsp+32]
        mov	rdx, rsp
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, 4
        call	fe_sq_n_x64
        mov	rcx, rsp
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, rsp
        call	fe_mul_x64
        lea	rcx, QWORD PTR [rsp+32]
        mov	rdx, rsp
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, 9
        call	fe_sq_n_x64
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, rsp
        call	fe_mul_x64
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+32]
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        mov	r8, 19
        call	fe_sq_n_x64
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+64]
        lea	r8, QWORD PTR [rsp+32]
        call	fe_mul_x64
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, 9
        call	fe_sq_n_x64
        mov	rcx, rsp
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, rsp
        call	fe_mul_x64
        lea	rcx, QWORD PTR [rsp+32]
        mov	rdx, rsp
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, 49
        call	fe_sq_n_x64
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, rsp
        call	fe_mul_x64
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+32]
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        mov	r8, 99
        call	fe_sq_n_x64
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+64]
        lea	r8, QWORD PTR [rsp+32]
        call	fe_mul_x64
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        call	fe_sq_x64
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, 49
        call	fe_sq_n_x64
        mov	rcx, rsp
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, rsp
        call	fe_mul_x64
        mov	rcx, rsp
        mov	rdx, rsp
        call	fe_sq_x64
        mov	rcx, rsp
        mov	rdx, rsp
        call	fe_sq_x64
        mov	rcx, QWORD PTR [rsp+96]
        mov	rdx, rsp
        mov	r8, QWORD PTR [rsp+104]
        call	fe_mul_x64
        mov	rdx, QWORD PTR [rsp+104]
        mov	rcx, QWORD PTR [rsp+96]
        add	rsp, 112
        ret
fe_pow22523_x64 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
ge_p1p1_to_p2_x64 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        mov	r8, rdx
        sub	rsp, 16
        mov	QWORD PTR [rsp], rcx
        mov	QWORD PTR [rsp+8], r8
        mov	r9, r8
        add	r9, 96
        ; Multiply
        ;  A[0] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r8]
        mov	r11, rax
        mov	r12, rdx
        ;  A[0] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r8]
        xor	r13, r13
        add	r12, rax
        adc	r13, rdx
        ;  A[1] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r8+8]
        xor	r14, r14
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[0] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r8]
        add	r13, rax
        adc	r14, rdx
        ;  A[1] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r8+8]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[2] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r8+16]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[0] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r8]
        xor	rdi, rdi
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[1] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r8+8]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[2] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r8+16]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[3] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r8+24]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[1] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r8+8]
        xor	rsi, rsi
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[2] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r8+16]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[3] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r8+24]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[2] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r8+16]
        xor	rbx, rbx
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[3] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r8+24]
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[3] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r8+24]
        add	rsi, rax
        adc	rbx, rdx
        mov	rax, 38
        mul	rbx
        add	r14, rax
        adc	rdx, 0
        mov	r10, 9223372036854775807
        shld	rdx, r14, 1
        imul	rdx, rdx, 19
        and	r14, r10
        mov	r10, rdx
        mov	rax, 38
        mul	r15
        xor	r15, r15
        add	r11, rax
        mov	rax, 38
        adc	r15, rdx
        mul	rdi
        xor	rdi, rdi
        add	r12, rax
        mov	rax, 38
        adc	rdi, rdx
        mul	rsi
        xor	rsi, rsi
        add	r13, rax
        adc	rsi, rdx
        add	r11, r10
        adc	r12, r15
        adc	r13, rdi
        adc	r14, rsi
        ; Store
        mov	QWORD PTR [rcx], r11
        mov	QWORD PTR [rcx+8], r12
        mov	QWORD PTR [rcx+16], r13
        mov	QWORD PTR [rcx+24], r14
        add	r8, 64
        add	rcx, 64
        ; Multiply
        ;  A[0] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r8]
        mov	r11, rax
        mov	r12, rdx
        ;  A[0] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r8]
        xor	r13, r13
        add	r12, rax
        adc	r13, rdx
        ;  A[1] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r8+8]
        xor	r14, r14
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[0] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r8]
        add	r13, rax
        adc	r14, rdx
        ;  A[1] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r8+8]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[2] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r8+16]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[0] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r8]
        xor	rdi, rdi
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[1] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r8+8]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[2] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r8+16]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[3] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r8+24]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[1] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r8+8]
        xor	rsi, rsi
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[2] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r8+16]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[3] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r8+24]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[2] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r8+16]
        xor	rbx, rbx
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[3] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r8+24]
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[3] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r8+24]
        add	rsi, rax
        adc	rbx, rdx
        mov	rax, 38
        mul	rbx
        add	r14, rax
        adc	rdx, 0
        mov	r10, 9223372036854775807
        shld	rdx, r14, 1
        imul	rdx, rdx, 19
        and	r14, r10
        mov	r10, rdx
        mov	rax, 38
        mul	r15
        xor	r15, r15
        add	r11, rax
        mov	rax, 38
        adc	r15, rdx
        mul	rdi
        xor	rdi, rdi
        add	r12, rax
        mov	rax, 38
        adc	rdi, rdx
        mul	rsi
        xor	rsi, rsi
        add	r13, rax
        adc	rsi, rdx
        add	r11, r10
        adc	r12, r15
        adc	r13, rdi
        adc	r14, rsi
        ; Store
        mov	QWORD PTR [rcx], r11
        mov	QWORD PTR [rcx+8], r12
        mov	QWORD PTR [rcx+16], r13
        mov	QWORD PTR [rcx+24], r14
        mov	r9, r8
        sub	r9, 32
        sub	rcx, 32
        ; Multiply
        ;  A[0] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r8]
        mov	r11, rax
        mov	r12, rdx
        ;  A[0] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r8]
        xor	r13, r13
        add	r12, rax
        adc	r13, rdx
        ;  A[1] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r8+8]
        xor	r14, r14
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[0] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r8]
        add	r13, rax
        adc	r14, rdx
        ;  A[1] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r8+8]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[2] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r8+16]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[0] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r8]
        xor	rdi, rdi
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[1] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r8+8]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[2] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r8+16]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[3] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r8+24]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[1] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r8+8]
        xor	rsi, rsi
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[2] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r8+16]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[3] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r8+24]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[2] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r8+16]
        xor	rbx, rbx
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[3] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r8+24]
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[3] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r8+24]
        add	rsi, rax
        adc	rbx, rdx
        mov	rax, 38
        mul	rbx
        add	r14, rax
        adc	rdx, 0
        mov	r10, 9223372036854775807
        shld	rdx, r14, 1
        imul	rdx, rdx, 19
        and	r14, r10
        mov	r10, rdx
        mov	rax, 38
        mul	r15
        xor	r15, r15
        add	r11, rax
        mov	rax, 38
        adc	r15, rdx
        mul	rdi
        xor	rdi, rdi
        add	r12, rax
        mov	rax, 38
        adc	rdi, rdx
        mul	rsi
        xor	rsi, rsi
        add	r13, rax
        adc	rsi, rdx
        add	r11, r10
        adc	r12, r15
        adc	r13, rdi
        adc	r14, rsi
        ; Store
        mov	QWORD PTR [rcx], r11
        mov	QWORD PTR [rcx+8], r12
        mov	QWORD PTR [rcx+16], r13
        mov	QWORD PTR [rcx+24], r14
        add	rsp, 16
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
ge_p1p1_to_p2_x64 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
ge_p1p1_to_p3_x64 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        mov	r8, rdx
        sub	rsp, 16
        mov	QWORD PTR [rsp], rcx
        mov	QWORD PTR [rsp+8], r8
        mov	r9, r8
        add	r9, 96
        ; Multiply
        ;  A[0] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r8]
        mov	r11, rax
        mov	r12, rdx
        ;  A[0] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r8]
        xor	r13, r13
        add	r12, rax
        adc	r13, rdx
        ;  A[1] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r8+8]
        xor	r14, r14
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[0] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r8]
        add	r13, rax
        adc	r14, rdx
        ;  A[1] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r8+8]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[2] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r8+16]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[0] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r8]
        xor	rdi, rdi
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[1] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r8+8]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[2] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r8+16]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[3] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r8+24]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[1] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r8+8]
        xor	rsi, rsi
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[2] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r8+16]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[3] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r8+24]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[2] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r8+16]
        xor	rbx, rbx
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[3] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r8+24]
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[3] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r8+24]
        add	rsi, rax
        adc	rbx, rdx
        mov	rax, 38
        mul	rbx
        add	r14, rax
        adc	rdx, 0
        mov	r10, 9223372036854775807
        shld	rdx, r14, 1
        imul	rdx, rdx, 19
        and	r14, r10
        mov	r10, rdx
        mov	rax, 38
        mul	r15
        xor	r15, r15
        add	r11, rax
        mov	rax, 38
        adc	r15, rdx
        mul	rdi
        xor	rdi, rdi
        add	r12, rax
        mov	rax, 38
        adc	rdi, rdx
        mul	rsi
        xor	rsi, rsi
        add	r13, rax
        adc	rsi, rdx
        add	r11, r10
        adc	r12, r15
        adc	r13, rdi
        adc	r14, rsi
        ; Store
        mov	QWORD PTR [rcx], r11
        mov	QWORD PTR [rcx+8], r12
        mov	QWORD PTR [rcx+16], r13
        mov	QWORD PTR [rcx+24], r14
        mov	r9, r8
        add	r9, 32
        add	rcx, 96
        ; Multiply
        ;  A[0] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r8]
        mov	r11, rax
        mov	r12, rdx
        ;  A[0] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r8]
        xor	r13, r13
        add	r12, rax
        adc	r13, rdx
        ;  A[1] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r8+8]
        xor	r14, r14
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[0] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r8]
        add	r13, rax
        adc	r14, rdx
        ;  A[1] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r8+8]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[2] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r8+16]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[0] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r8]
        xor	rdi, rdi
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[1] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r8+8]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[2] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r8+16]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[3] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r8+24]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[1] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r8+8]
        xor	rsi, rsi
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[2] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r8+16]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[3] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r8+24]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[2] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r8+16]
        xor	rbx, rbx
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[3] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r8+24]
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[3] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r8+24]
        add	rsi, rax
        adc	rbx, rdx
        mov	rax, 38
        mul	rbx
        add	r14, rax
        adc	rdx, 0
        mov	r10, 9223372036854775807
        shld	rdx, r14, 1
        imul	rdx, rdx, 19
        and	r14, r10
        mov	r10, rdx
        mov	rax, 38
        mul	r15
        xor	r15, r15
        add	r11, rax
        mov	rax, 38
        adc	r15, rdx
        mul	rdi
        xor	rdi, rdi
        add	r12, rax
        mov	rax, 38
        adc	rdi, rdx
        mul	rsi
        xor	rsi, rsi
        add	r13, rax
        adc	rsi, rdx
        add	r11, r10
        adc	r12, r15
        adc	r13, rdi
        adc	r14, rsi
        ; Store
        mov	QWORD PTR [rcx], r11
        mov	QWORD PTR [rcx+8], r12
        mov	QWORD PTR [rcx+16], r13
        mov	QWORD PTR [rcx+24], r14
        add	r8, 64
        sub	rcx, 64
        ; Multiply
        ;  A[0] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r8]
        mov	r11, rax
        mov	r12, rdx
        ;  A[0] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r8]
        xor	r13, r13
        add	r12, rax
        adc	r13, rdx
        ;  A[1] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r8+8]
        xor	r14, r14
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[0] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r8]
        add	r13, rax
        adc	r14, rdx
        ;  A[1] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r8+8]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[2] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r8+16]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[0] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r8]
        xor	rdi, rdi
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[1] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r8+8]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[2] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r8+16]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[3] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r8+24]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[1] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r8+8]
        xor	rsi, rsi
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[2] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r8+16]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[3] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r8+24]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[2] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r8+16]
        xor	rbx, rbx
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[3] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r8+24]
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[3] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r8+24]
        add	rsi, rax
        adc	rbx, rdx
        mov	rax, 38
        mul	rbx
        add	r14, rax
        adc	rdx, 0
        mov	r10, 9223372036854775807
        shld	rdx, r14, 1
        imul	rdx, rdx, 19
        and	r14, r10
        mov	r10, rdx
        mov	rax, 38
        mul	r15
        xor	r15, r15
        add	r11, rax
        mov	rax, 38
        adc	r15, rdx
        mul	rdi
        xor	rdi, rdi
        add	r12, rax
        mov	rax, 38
        adc	rdi, rdx
        mul	rsi
        xor	rsi, rsi
        add	r13, rax
        adc	rsi, rdx
        add	r11, r10
        adc	r12, r15
        adc	r13, rdi
        adc	r14, rsi
        ; Store
        mov	QWORD PTR [rcx], r11
        mov	QWORD PTR [rcx+8], r12
        mov	QWORD PTR [rcx+16], r13
        mov	QWORD PTR [rcx+24], r14
        mov	r9, r8
        add	r9, 32
        add	rcx, 32
        ; Multiply
        ;  A[0] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r8]
        mov	r11, rax
        mov	r12, rdx
        ;  A[0] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r8]
        xor	r13, r13
        add	r12, rax
        adc	r13, rdx
        ;  A[1] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r8+8]
        xor	r14, r14
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[0] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r8]
        add	r13, rax
        adc	r14, rdx
        ;  A[1] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r8+8]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[2] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r8+16]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[0] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r8]
        xor	rdi, rdi
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[1] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r8+8]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[2] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r8+16]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[3] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r8+24]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[1] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r8+8]
        xor	rsi, rsi
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[2] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r8+16]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[3] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r8+24]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[2] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r8+16]
        xor	rbx, rbx
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[3] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r8+24]
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[3] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r8+24]
        add	rsi, rax
        adc	rbx, rdx
        mov	rax, 38
        mul	rbx
        add	r14, rax
        adc	rdx, 0
        mov	r10, 9223372036854775807
        shld	rdx, r14, 1
        imul	rdx, rdx, 19
        and	r14, r10
        mov	r10, rdx
        mov	rax, 38
        mul	r15
        xor	r15, r15
        add	r11, rax
        mov	rax, 38
        adc	r15, rdx
        mul	rdi
        xor	rdi, rdi
        add	r12, rax
        mov	rax, 38
        adc	rdi, rdx
        mul	rsi
        xor	rsi, rsi
        add	r13, rax
        adc	rsi, rdx
        add	r11, r10
        adc	r12, r15
        adc	r13, rdi
        adc	r14, rsi
        ; Store
        mov	QWORD PTR [rcx], r11
        mov	QWORD PTR [rcx+8], r12
        mov	QWORD PTR [rcx+16], r13
        mov	QWORD PTR [rcx+24], r14
        add	rsp, 16
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
ge_p1p1_to_p3_x64 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
ge_p2_dbl_x64 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        mov	r8, rdx
        sub	rsp, 16
        mov	QWORD PTR [rsp], rcx
        mov	QWORD PTR [rsp+8], r8
        add	rcx, 64
        ; Square
        ;  A[0] * A[1]
        mov	rax, QWORD PTR [r8]
        mul	QWORD PTR [r8+8]
        mov	r12, rax
        mov	r13, rdx
        ;  A[0] * A[2]
        mov	rax, QWORD PTR [r8]
        mul	QWORD PTR [r8+16]
        xor	r14, r14
        add	r13, rax
        adc	r14, rdx
        ;  A[0] * A[3]
        mov	rax, QWORD PTR [r8]
        mul	QWORD PTR [r8+24]
        xor	r15, r15
        add	r14, rax
        adc	r15, rdx
        ;  A[1] * A[2]
        mov	rax, QWORD PTR [r8+8]
        mul	QWORD PTR [r8+16]
        xor	rdi, rdi
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[1] * A[3]
        mov	rax, QWORD PTR [r8+8]
        mul	QWORD PTR [r8+24]
        add	r15, rax
        adc	rdi, rdx
        ;  A[2] * A[3]
        mov	rax, QWORD PTR [r8+16]
        mul	QWORD PTR [r8+24]
        xor	rsi, rsi
        add	rdi, rax
        adc	rsi, rdx
        ; Double
        xor	rbx, rbx
        add	r12, r12
        adc	r13, r13
        adc	r14, r14
        adc	r15, r15
        adc	rdi, rdi
        adc	rsi, rsi
        adc	rbx, 0
        ;  A[0] * A[0]
        mov	rax, QWORD PTR [r8]
        mul	rax
        mov	r11, rax
        mov	r10, rdx
        ;  A[1] * A[1]
        mov	rax, QWORD PTR [r8+8]
        mul	rax
        add	r12, r10
        adc	r13, rax
        adc	rdx, 0
        mov	r10, rdx
        ;  A[2] * A[2]
        mov	rax, QWORD PTR [r8+16]
        mul	rax
        add	r14, r10
        adc	r15, rax
        adc	rdx, 0
        mov	r10, rdx
        ;  A[3] * A[3]
        mov	rax, QWORD PTR [r8+24]
        mul	rax
        add	rsi, rax
        adc	rbx, rdx
        add	rdi, r10
        adc	rsi, 0
        adc	rbx, 0
        mov	rax, 38
        mul	rbx
        add	r14, rax
        adc	rdx, 0
        mov	r10, 9223372036854775807
        shld	rdx, r14, 1
        imul	rdx, rdx, 19
        and	r14, r10
        mov	r10, rdx
        mov	rax, 38
        mul	r15
        xor	r15, r15
        add	r11, rax
        mov	rax, 38
        adc	r15, rdx
        mul	rdi
        xor	rdi, rdi
        add	r12, rax
        mov	rax, 38
        adc	rdi, rdx
        mul	rsi
        xor	rsi, rsi
        add	r13, rax
        adc	rsi, rdx
        add	r11, r10
        adc	r12, r15
        adc	r13, rdi
        adc	r14, rsi
        ; Store
        mov	QWORD PTR [rcx], r11
        mov	QWORD PTR [rcx+8], r12
        mov	QWORD PTR [rcx+16], r13
        mov	QWORD PTR [rcx+24], r14
        add	r8, 32
        ; Square
        ;  A[0] * A[1]
        mov	rax, QWORD PTR [r8]
        mul	QWORD PTR [r8+8]
        mov	r12, rax
        mov	r13, rdx
        ;  A[0] * A[2]
        mov	rax, QWORD PTR [r8]
        mul	QWORD PTR [r8+16]
        xor	r14, r14
        add	r13, rax
        adc	r14, rdx
        ;  A[0] * A[3]
        mov	rax, QWORD PTR [r8]
        mul	QWORD PTR [r8+24]
        xor	r15, r15
        add	r14, rax
        adc	r15, rdx
        ;  A[1] * A[2]
        mov	rax, QWORD PTR [r8+8]
        mul	QWORD PTR [r8+16]
        xor	rdi, rdi
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[1] * A[3]
        mov	rax, QWORD PTR [r8+8]
        mul	QWORD PTR [r8+24]
        add	r15, rax
        adc	rdi, rdx
        ;  A[2] * A[3]
        mov	rax, QWORD PTR [r8+16]
        mul	QWORD PTR [r8+24]
        xor	rsi, rsi
        add	rdi, rax
        adc	rsi, rdx
        ; Double
        xor	rbx, rbx
        add	r12, r12
        adc	r13, r13
        adc	r14, r14
        adc	r15, r15
        adc	rdi, rdi
        adc	rsi, rsi
        adc	rbx, 0
        ;  A[0] * A[0]
        mov	rax, QWORD PTR [r8]
        mul	rax
        mov	r11, rax
        mov	r10, rdx
        ;  A[1] * A[1]
        mov	rax, QWORD PTR [r8+8]
        mul	rax
        add	r12, r10
        adc	r13, rax
        adc	rdx, 0
        mov	r10, rdx
        ;  A[2] * A[2]
        mov	rax, QWORD PTR [r8+16]
        mul	rax
        add	r14, r10
        adc	r15, rax
        adc	rdx, 0
        mov	r10, rdx
        ;  A[3] * A[3]
        mov	rax, QWORD PTR [r8+24]
        mul	rax
        add	rsi, rax
        adc	rbx, rdx
        add	rdi, r10
        adc	rsi, 0
        adc	rbx, 0
        mov	rax, 38
        mul	rbx
        add	r14, rax
        adc	rdx, 0
        mov	r10, 9223372036854775807
        shld	rdx, r14, 1
        imul	rdx, rdx, 19
        and	r14, r10
        mov	r10, rdx
        mov	rax, 38
        mul	r15
        xor	r15, r15
        add	r11, rax
        mov	rax, 38
        adc	r15, rdx
        mul	rdi
        xor	rdi, rdi
        add	r12, rax
        mov	rax, 38
        adc	rdi, rdx
        mul	rsi
        xor	rsi, rsi
        add	r13, rax
        adc	rsi, rdx
        add	r11, r10
        adc	r12, r15
        adc	r13, rdi
        adc	r14, rsi
        ; Store
        mov	r8, rcx
        sub	rcx, 32
        ; Add-Sub
        ; Add
        mov	r15, r11
        add	r11, QWORD PTR [r8]
        mov	rdi, r12
        adc	r12, QWORD PTR [r8+8]
        mov	rsi, r13
        adc	r13, QWORD PTR [r8+16]
        mov	rbx, r14
        adc	r14, QWORD PTR [r8+24]
        mov	r10, 0
        adc	r10, 0
        shld	r10, r14, 1
        imul	r10, 19
        btr	r14, 63
        ;   Sub modulus (if overflow)
        add	r11, r10
        adc	r12, 0
        adc	r13, 0
        adc	r14, 0
        ; Sub
        sub	r15, QWORD PTR [r8]
        sbb	rdi, QWORD PTR [r8+8]
        sbb	rsi, QWORD PTR [r8+16]
        sbb	rbx, QWORD PTR [r8+24]
        sbb	r10, r10
        shld	r10, rbx, 1
        imul	r10, -19
        btr	rbx, 63
        ;   Add modulus (if underflow)
        sub	r15, r10
        sbb	rdi, 0
        sbb	rsi, 0
        sbb	rbx, 0
        mov	QWORD PTR [rcx], r11
        mov	QWORD PTR [rcx+8], r12
        mov	QWORD PTR [rcx+16], r13
        mov	QWORD PTR [rcx+24], r14
        mov	QWORD PTR [r8], r15
        mov	QWORD PTR [r8+8], rdi
        mov	QWORD PTR [r8+16], rsi
        mov	QWORD PTR [r8+24], rbx
        mov	r9, QWORD PTR [rsp+8]
        mov	r8, r9
        add	r8, 32
        sub	rcx, 32
        ; Add
        mov	r11, QWORD PTR [r8]
        mov	r12, QWORD PTR [r8+8]
        add	r11, QWORD PTR [r9]
        mov	r13, QWORD PTR [r8+16]
        adc	r12, QWORD PTR [r9+8]
        mov	r14, QWORD PTR [r8+24]
        adc	r13, QWORD PTR [r9+16]
        adc	r14, QWORD PTR [r9+24]
        mov	r10, 0
        adc	r10, 0
        shld	r10, r14, 1
        imul	r10, 19
        btr	r14, 63
        ;   Sub modulus (if overflow)
        add	r11, r10
        adc	r12, 0
        adc	r13, 0
        adc	r14, 0
        mov	QWORD PTR [rcx], r11
        mov	QWORD PTR [rcx+8], r12
        mov	QWORD PTR [rcx+16], r13
        mov	QWORD PTR [rcx+24], r14
        ; Square
        ;  A[0] * A[1]
        mov	rax, QWORD PTR [rcx]
        mul	QWORD PTR [rcx+8]
        mov	r12, rax
        mov	r13, rdx
        ;  A[0] * A[2]
        mov	rax, QWORD PTR [rcx]
        mul	QWORD PTR [rcx+16]
        xor	r14, r14
        add	r13, rax
        adc	r14, rdx
        ;  A[0] * A[3]
        mov	rax, QWORD PTR [rcx]
        mul	QWORD PTR [rcx+24]
        xor	r15, r15
        add	r14, rax
        adc	r15, rdx
        ;  A[1] * A[2]
        mov	rax, QWORD PTR [rcx+8]
        mul	QWORD PTR [rcx+16]
        xor	rdi, rdi
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[1] * A[3]
        mov	rax, QWORD PTR [rcx+8]
        mul	QWORD PTR [rcx+24]
        add	r15, rax
        adc	rdi, rdx
        ;  A[2] * A[3]
        mov	rax, QWORD PTR [rcx+16]
        mul	QWORD PTR [rcx+24]
        xor	rsi, rsi
        add	rdi, rax
        adc	rsi, rdx
        ; Double
        xor	rbx, rbx
        add	r12, r12
        adc	r13, r13
        adc	r14, r14
        adc	r15, r15
        adc	rdi, rdi
        adc	rsi, rsi
        adc	rbx, 0
        ;  A[0] * A[0]
        mov	rax, QWORD PTR [rcx]
        mul	rax
        mov	r11, rax
        mov	r10, rdx
        ;  A[1] * A[1]
        mov	rax, QWORD PTR [rcx+8]
        mul	rax
        add	r12, r10
        adc	r13, rax
        adc	rdx, 0
        mov	r10, rdx
        ;  A[2] * A[2]
        mov	rax, QWORD PTR [rcx+16]
        mul	rax
        add	r14, r10
        adc	r15, rax
        adc	rdx, 0
        mov	r10, rdx
        ;  A[3] * A[3]
        mov	rax, QWORD PTR [rcx+24]
        mul	rax
        add	rsi, rax
        adc	rbx, rdx
        add	rdi, r10
        adc	rsi, 0
        adc	rbx, 0
        mov	rax, 38
        mul	rbx
        add	r14, rax
        adc	rdx, 0
        mov	r10, 9223372036854775807
        shld	rdx, r14, 1
        imul	rdx, rdx, 19
        and	r14, r10
        mov	r10, rdx
        mov	rax, 38
        mul	r15
        xor	r15, r15
        add	r11, rax
        mov	rax, 38
        adc	r15, rdx
        mul	rdi
        xor	rdi, rdi
        add	r12, rax
        mov	rax, 38
        adc	rdi, rdx
        mul	rsi
        xor	rsi, rsi
        add	r13, rax
        adc	rsi, rdx
        add	r11, r10
        adc	r12, r15
        adc	r13, rdi
        adc	r14, rsi
        ; Store
        mov	r8, rcx
        add	r8, 32
        ; Sub
        sub	r11, QWORD PTR [r8]
        sbb	r12, QWORD PTR [r8+8]
        sbb	r13, QWORD PTR [r8+16]
        sbb	r14, QWORD PTR [r8+24]
        sbb	r10, r10
        shld	r10, r14, 1
        imul	r10, -19
        btr	r14, 63
        ;   Add modulus (if underflow)
        sub	r11, r10
        sbb	r12, 0
        sbb	r13, 0
        sbb	r14, 0
        mov	QWORD PTR [rcx], r11
        mov	QWORD PTR [rcx+8], r12
        mov	QWORD PTR [rcx+16], r13
        mov	QWORD PTR [rcx+24], r14
        add	r9, 64
        ; Square * 2
        ;  A[0] * A[1]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r9+8]
        mov	r12, rax
        mov	r13, rdx
        ;  A[0] * A[2]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r9+16]
        xor	r14, r14
        add	r13, rax
        adc	r14, rdx
        ;  A[0] * A[3]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r9+24]
        xor	r15, r15
        add	r14, rax
        adc	r15, rdx
        ;  A[1] * A[2]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r9+16]
        xor	rdi, rdi
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[1] * A[3]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r9+24]
        add	r15, rax
        adc	rdi, rdx
        ;  A[2] * A[3]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r9+24]
        xor	rsi, rsi
        add	rdi, rax
        adc	rsi, rdx
        ; Double
        xor	rbx, rbx
        add	r12, r12
        adc	r13, r13
        adc	r14, r14
        adc	r15, r15
        adc	rdi, rdi
        adc	rsi, rsi
        adc	rbx, 0
        ;  A[0] * A[0]
        mov	rax, QWORD PTR [r9]
        mul	rax
        mov	r11, rax
        mov	r10, rdx
        ;  A[1] * A[1]
        mov	rax, QWORD PTR [r9+8]
        mul	rax
        add	r12, r10
        adc	r13, rax
        adc	rdx, 0
        mov	r10, rdx
        ;  A[2] * A[2]
        mov	rax, QWORD PTR [r9+16]
        mul	rax
        add	r14, r10
        adc	r15, rax
        adc	rdx, 0
        mov	r10, rdx
        ;  A[3] * A[3]
        mov	rax, QWORD PTR [r9+24]
        mul	rax
        add	rsi, rax
        adc	rbx, rdx
        add	rdi, r10
        adc	rsi, 0
        adc	rbx, 0
        mov	rax, 38
        mul	rbx
        add	r14, rax
        adc	rdx, 0
        mov	r10, 9223372036854775807
        shld	rdx, r14, 1
        imul	rdx, rdx, 19
        and	r14, r10
        mov	r10, rdx
        mov	rax, 38
        mul	r15
        xor	r15, r15
        add	r11, rax
        mov	rax, 38
        adc	r15, rdx
        mul	rdi
        xor	rdi, rdi
        add	r12, rax
        mov	rax, 38
        adc	rdi, rdx
        mul	rsi
        xor	rsi, rsi
        add	r13, rax
        adc	rsi, rdx
        add	r11, r10
        adc	r12, r15
        adc	r13, rdi
        adc	r14, rsi
        mov	rax, r14
        shld	r14, r13, 1
        shld	r13, r12, 1
        shld	r12, r11, 1
        shl	r11, 1
        mov	r10, 9223372036854775807
        shr	rax, 62
        and	r14, r10
        imul	rax, rax, 19
        add	r11, rax
        adc	r12, 0
        adc	r13, 0
        adc	r14, 0
        ; Store
        mov	r8, rcx
        add	r8, 64
        add	rcx, 96
        ; Sub
        sub	r11, QWORD PTR [r8]
        sbb	r12, QWORD PTR [r8+8]
        sbb	r13, QWORD PTR [r8+16]
        sbb	r14, QWORD PTR [r8+24]
        sbb	r10, r10
        shld	r10, r14, 1
        imul	r10, -19
        btr	r14, 63
        ;   Add modulus (if underflow)
        sub	r11, r10
        sbb	r12, 0
        sbb	r13, 0
        sbb	r14, 0
        mov	QWORD PTR [rcx], r11
        mov	QWORD PTR [rcx+8], r12
        mov	QWORD PTR [rcx+16], r13
        mov	QWORD PTR [rcx+24], r14
        add	rsp, 16
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
ge_p2_dbl_x64 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
ge_madd_x64 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        push	rbp
        mov	r9, r8
        mov	r8, rdx
        sub	rsp, 24
        mov	QWORD PTR [rsp], rcx
        mov	QWORD PTR [rsp+8], r8
        mov	QWORD PTR [rsp+16], r9
        mov	r10, r8
        mov	r9, r8
        add	r9, 32
        mov	r8, rcx
        add	r8, 32
        ; Add-Sub
        ; Add
        mov	r12, QWORD PTR [r9]
        mov	r13, QWORD PTR [r9+8]
        mov	r14, QWORD PTR [r9+16]
        mov	r15, QWORD PTR [r9+24]
        mov	rdi, r12
        add	r12, QWORD PTR [r10]
        mov	rsi, r13
        adc	r13, QWORD PTR [r10+8]
        mov	rbx, r14
        adc	r14, QWORD PTR [r10+16]
        mov	rbp, r15
        adc	r15, QWORD PTR [r10+24]
        mov	r11, 0
        adc	r11, 0
        shld	r11, r15, 1
        imul	r11, 19
        btr	r15, 63
        ;   Sub modulus (if overflow)
        add	r12, r11
        adc	r13, 0
        adc	r14, 0
        adc	r15, 0
        ; Sub
        sub	rdi, QWORD PTR [r10]
        sbb	rsi, QWORD PTR [r10+8]
        sbb	rbx, QWORD PTR [r10+16]
        sbb	rbp, QWORD PTR [r10+24]
        sbb	r11, r11
        shld	r11, rbp, 1
        imul	r11, -19
        btr	rbp, 63
        ;   Add modulus (if underflow)
        sub	rdi, r11
        sbb	rsi, 0
        sbb	rbx, 0
        sbb	rbp, 0
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        mov	QWORD PTR [r8], rdi
        mov	QWORD PTR [r8+8], rsi
        mov	QWORD PTR [r8+16], rbx
        mov	QWORD PTR [r8+24], rbp
        mov	r9, QWORD PTR [rsp+16]
        add	r9, 32
        ; Multiply
        ;  A[0] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r8]
        mov	r12, rax
        mov	r13, rdx
        ;  A[0] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r8]
        xor	r14, r14
        add	r13, rax
        adc	r14, rdx
        ;  A[1] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r8+8]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[0] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r8]
        add	r14, rax
        adc	r15, rdx
        ;  A[1] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r8+8]
        xor	rdi, rdi
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[2] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r8+16]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[0] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r8]
        xor	rsi, rsi
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[1] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r8+8]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[2] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r8+16]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[3] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r8+24]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[1] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r8+8]
        xor	rbx, rbx
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[2] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r8+16]
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[3] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r8+24]
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[2] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r8+16]
        xor	rbp, rbp
        add	rsi, rax
        adc	rbx, rdx
        adc	rbp, 0
        ;  A[3] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r8+24]
        add	rsi, rax
        adc	rbx, rdx
        adc	rbp, 0
        ;  A[3] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r8+24]
        add	rbx, rax
        adc	rbp, rdx
        mov	rax, 38
        mul	rbp
        add	r15, rax
        adc	rdx, 0
        mov	r11, 9223372036854775807
        shld	rdx, r15, 1
        imul	rdx, rdx, 19
        and	r15, r11
        mov	r11, rdx
        mov	rax, 38
        mul	rdi
        xor	rdi, rdi
        add	r12, rax
        mov	rax, 38
        adc	rdi, rdx
        mul	rsi
        xor	rsi, rsi
        add	r13, rax
        mov	rax, 38
        adc	rsi, rdx
        mul	rbx
        xor	rbx, rbx
        add	r14, rax
        adc	rbx, rdx
        add	r12, r11
        adc	r13, rdi
        adc	r14, rsi
        adc	r15, rbx
        ; Store
        mov	QWORD PTR [r8], r12
        mov	QWORD PTR [r8+8], r13
        mov	QWORD PTR [r8+16], r14
        mov	QWORD PTR [r8+24], r15
        add	r10, 96
        add	r9, 32
        add	rcx, 96
        ; Multiply
        ;  A[0] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r10]
        mov	r12, rax
        mov	r13, rdx
        ;  A[0] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r10]
        xor	r14, r14
        add	r13, rax
        adc	r14, rdx
        ;  A[1] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r10+8]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[0] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r10]
        add	r14, rax
        adc	r15, rdx
        ;  A[1] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r10+8]
        xor	rdi, rdi
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[2] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r10+16]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[0] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r10]
        xor	rsi, rsi
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[1] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r10+8]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[2] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r10+16]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[3] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r10+24]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[1] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r10+8]
        xor	rbx, rbx
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[2] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r10+16]
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[3] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r10+24]
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[2] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r10+16]
        xor	rbp, rbp
        add	rsi, rax
        adc	rbx, rdx
        adc	rbp, 0
        ;  A[3] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r10+24]
        add	rsi, rax
        adc	rbx, rdx
        adc	rbp, 0
        ;  A[3] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r10+24]
        add	rbx, rax
        adc	rbp, rdx
        mov	rax, 38
        mul	rbp
        add	r15, rax
        adc	rdx, 0
        mov	r11, 9223372036854775807
        shld	rdx, r15, 1
        imul	rdx, rdx, 19
        and	r15, r11
        mov	r11, rdx
        mov	rax, 38
        mul	rdi
        xor	rdi, rdi
        add	r12, rax
        mov	rax, 38
        adc	rdi, rdx
        mul	rsi
        xor	rsi, rsi
        add	r13, rax
        mov	rax, 38
        adc	rsi, rdx
        mul	rbx
        xor	rbx, rbx
        add	r14, rax
        adc	rbx, rdx
        add	r12, r11
        adc	r13, rdi
        adc	r14, rsi
        adc	r15, rbx
        ; Store
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        sub	r9, 64
        sub	rcx, 96
        ; Multiply
        ;  A[0] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [rcx]
        mov	r12, rax
        mov	r13, rdx
        ;  A[0] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [rcx]
        xor	r14, r14
        add	r13, rax
        adc	r14, rdx
        ;  A[1] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [rcx+8]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[0] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [rcx]
        add	r14, rax
        adc	r15, rdx
        ;  A[1] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [rcx+8]
        xor	rdi, rdi
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[2] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [rcx+16]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[0] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [rcx]
        xor	rsi, rsi
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[1] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [rcx+8]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[2] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [rcx+16]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[3] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [rcx+24]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[1] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [rcx+8]
        xor	rbx, rbx
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[2] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [rcx+16]
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[3] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [rcx+24]
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[2] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [rcx+16]
        xor	rbp, rbp
        add	rsi, rax
        adc	rbx, rdx
        adc	rbp, 0
        ;  A[3] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [rcx+24]
        add	rsi, rax
        adc	rbx, rdx
        adc	rbp, 0
        ;  A[3] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [rcx+24]
        add	rbx, rax
        adc	rbp, rdx
        mov	rax, 38
        mul	rbp
        add	r15, rax
        adc	rdx, 0
        mov	r11, 9223372036854775807
        shld	rdx, r15, 1
        imul	rdx, rdx, 19
        and	r15, r11
        mov	r11, rdx
        mov	rax, 38
        mul	rdi
        xor	rdi, rdi
        add	r12, rax
        mov	rax, 38
        adc	rdi, rdx
        mul	rsi
        xor	rsi, rsi
        add	r13, rax
        mov	rax, 38
        adc	rsi, rdx
        mul	rbx
        xor	rbx, rbx
        add	r14, rax
        adc	rbx, rdx
        add	r12, r11
        adc	r13, rdi
        adc	r14, rsi
        adc	r15, rbx
        ; Store
        ; Add-Sub
        ; Add
        mov	rdi, r12
        add	r12, QWORD PTR [r8]
        mov	rsi, r13
        adc	r13, QWORD PTR [r8+8]
        mov	rbx, r14
        adc	r14, QWORD PTR [r8+16]
        mov	rbp, r15
        adc	r15, QWORD PTR [r8+24]
        mov	r11, 0
        adc	r11, 0
        shld	r11, r15, 1
        imul	r11, 19
        btr	r15, 63
        ;   Sub modulus (if overflow)
        add	r12, r11
        adc	r13, 0
        adc	r14, 0
        adc	r15, 0
        ; Sub
        sub	rdi, QWORD PTR [r8]
        sbb	rsi, QWORD PTR [r8+8]
        sbb	rbx, QWORD PTR [r8+16]
        sbb	rbp, QWORD PTR [r8+24]
        sbb	r11, r11
        shld	r11, rbp, 1
        imul	r11, -19
        btr	rbp, 63
        ;   Add modulus (if underflow)
        sub	rdi, r11
        sbb	rsi, 0
        sbb	rbx, 0
        sbb	rbp, 0
        mov	QWORD PTR [r8], r12
        mov	QWORD PTR [r8+8], r13
        mov	QWORD PTR [r8+16], r14
        mov	QWORD PTR [r8+24], r15
        mov	QWORD PTR [rcx], rdi
        mov	QWORD PTR [rcx+8], rsi
        mov	QWORD PTR [rcx+16], rbx
        mov	QWORD PTR [rcx+24], rbp
        sub	r10, 32
        ; Double
        mov	r12, QWORD PTR [r10]
        mov	r13, QWORD PTR [r10+8]
        add	r12, r12
        mov	r14, QWORD PTR [r10+16]
        adc	r13, r13
        mov	r15, QWORD PTR [r10+24]
        adc	r14, r14
        adc	r15, r15
        mov	r11, 0
        adc	r11, 0
        shld	r11, r15, 1
        imul	r11, 19
        btr	r15, 63
        ;   Sub modulus (if overflow)
        add	r12, r11
        adc	r13, 0
        adc	r14, 0
        adc	r15, 0
        mov	r8, rcx
        add	r8, 96
        add	rcx, 64
        ; Add-Sub
        ; Add
        mov	rdi, r12
        add	r12, QWORD PTR [r8]
        mov	rsi, r13
        adc	r13, QWORD PTR [r8+8]
        mov	rbx, r14
        adc	r14, QWORD PTR [r8+16]
        mov	rbp, r15
        adc	r15, QWORD PTR [r8+24]
        mov	r11, 0
        adc	r11, 0
        shld	r11, r15, 1
        imul	r11, 19
        btr	r15, 63
        ;   Sub modulus (if overflow)
        add	r12, r11
        adc	r13, 0
        adc	r14, 0
        adc	r15, 0
        ; Sub
        sub	rdi, QWORD PTR [r8]
        sbb	rsi, QWORD PTR [r8+8]
        sbb	rbx, QWORD PTR [r8+16]
        sbb	rbp, QWORD PTR [r8+24]
        sbb	r11, r11
        shld	r11, rbp, 1
        imul	r11, -19
        btr	rbp, 63
        ;   Add modulus (if underflow)
        sub	rdi, r11
        sbb	rsi, 0
        sbb	rbx, 0
        sbb	rbp, 0
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        mov	QWORD PTR [r8], rdi
        mov	QWORD PTR [r8+8], rsi
        mov	QWORD PTR [r8+16], rbx
        mov	QWORD PTR [r8+24], rbp
        add	rsp, 24
        pop	rbp
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
ge_madd_x64 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
ge_msub_x64 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        push	rbp
        mov	r9, r8
        mov	r8, rdx
        sub	rsp, 24
        mov	QWORD PTR [rsp], rcx
        mov	QWORD PTR [rsp+8], r8
        mov	QWORD PTR [rsp+16], r9
        mov	r10, r8
        mov	r9, r8
        add	r9, 32
        mov	r8, rcx
        add	r8, 32
        ; Add-Sub
        ; Add
        mov	r12, QWORD PTR [r9]
        mov	r13, QWORD PTR [r9+8]
        mov	r14, QWORD PTR [r9+16]
        mov	r15, QWORD PTR [r9+24]
        mov	rdi, r12
        add	r12, QWORD PTR [r10]
        mov	rsi, r13
        adc	r13, QWORD PTR [r10+8]
        mov	rbx, r14
        adc	r14, QWORD PTR [r10+16]
        mov	rbp, r15
        adc	r15, QWORD PTR [r10+24]
        mov	r11, 0
        adc	r11, 0
        shld	r11, r15, 1
        imul	r11, 19
        btr	r15, 63
        ;   Sub modulus (if overflow)
        add	r12, r11
        adc	r13, 0
        adc	r14, 0
        adc	r15, 0
        ; Sub
        sub	rdi, QWORD PTR [r10]
        sbb	rsi, QWORD PTR [r10+8]
        sbb	rbx, QWORD PTR [r10+16]
        sbb	rbp, QWORD PTR [r10+24]
        sbb	r11, r11
        shld	r11, rbp, 1
        imul	r11, -19
        btr	rbp, 63
        ;   Add modulus (if underflow)
        sub	rdi, r11
        sbb	rsi, 0
        sbb	rbx, 0
        sbb	rbp, 0
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        mov	QWORD PTR [r8], rdi
        mov	QWORD PTR [r8+8], rsi
        mov	QWORD PTR [r8+16], rbx
        mov	QWORD PTR [r8+24], rbp
        mov	r9, QWORD PTR [rsp+16]
        add	rcx, 32
        ; Multiply
        ;  A[0] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [rcx]
        mov	r12, rax
        mov	r13, rdx
        ;  A[0] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [rcx]
        xor	r14, r14
        add	r13, rax
        adc	r14, rdx
        ;  A[1] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [rcx+8]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[0] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [rcx]
        add	r14, rax
        adc	r15, rdx
        ;  A[1] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [rcx+8]
        xor	rdi, rdi
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[2] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [rcx+16]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[0] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [rcx]
        xor	rsi, rsi
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[1] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [rcx+8]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[2] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [rcx+16]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[3] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [rcx+24]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[1] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [rcx+8]
        xor	rbx, rbx
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[2] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [rcx+16]
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[3] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [rcx+24]
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[2] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [rcx+16]
        xor	rbp, rbp
        add	rsi, rax
        adc	rbx, rdx
        adc	rbp, 0
        ;  A[3] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [rcx+24]
        add	rsi, rax
        adc	rbx, rdx
        adc	rbp, 0
        ;  A[3] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [rcx+24]
        add	rbx, rax
        adc	rbp, rdx
        mov	rax, 38
        mul	rbp
        add	r15, rax
        adc	rdx, 0
        mov	r11, 9223372036854775807
        shld	rdx, r15, 1
        imul	rdx, rdx, 19
        and	r15, r11
        mov	r11, rdx
        mov	rax, 38
        mul	rdi
        xor	rdi, rdi
        add	r12, rax
        mov	rax, 38
        adc	rdi, rdx
        mul	rsi
        xor	rsi, rsi
        add	r13, rax
        mov	rax, 38
        adc	rsi, rdx
        mul	rbx
        xor	rbx, rbx
        add	r14, rax
        adc	rbx, rdx
        add	r12, r11
        adc	r13, rdi
        adc	r14, rsi
        adc	r15, rbx
        ; Store
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        add	r10, 96
        add	r9, 64
        add	rcx, 64
        ; Multiply
        ;  A[0] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r10]
        mov	r12, rax
        mov	r13, rdx
        ;  A[0] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r10]
        xor	r14, r14
        add	r13, rax
        adc	r14, rdx
        ;  A[1] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r10+8]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[0] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r10]
        add	r14, rax
        adc	r15, rdx
        ;  A[1] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r10+8]
        xor	rdi, rdi
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[2] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r10+16]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[0] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r10]
        xor	rsi, rsi
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[1] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r10+8]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[2] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r10+16]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[3] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r10+24]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[1] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r10+8]
        xor	rbx, rbx
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[2] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r10+16]
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[3] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r10+24]
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[2] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r10+16]
        xor	rbp, rbp
        add	rsi, rax
        adc	rbx, rdx
        adc	rbp, 0
        ;  A[3] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r10+24]
        add	rsi, rax
        adc	rbx, rdx
        adc	rbp, 0
        ;  A[3] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r10+24]
        add	rbx, rax
        adc	rbp, rdx
        mov	rax, 38
        mul	rbp
        add	r15, rax
        adc	rdx, 0
        mov	r11, 9223372036854775807
        shld	rdx, r15, 1
        imul	rdx, rdx, 19
        and	r15, r11
        mov	r11, rdx
        mov	rax, 38
        mul	rdi
        xor	rdi, rdi
        add	r12, rax
        mov	rax, 38
        adc	rdi, rdx
        mul	rsi
        xor	rsi, rsi
        add	r13, rax
        mov	rax, 38
        adc	rsi, rdx
        mul	rbx
        xor	rbx, rbx
        add	r14, rax
        adc	rbx, rdx
        add	r12, r11
        adc	r13, rdi
        adc	r14, rsi
        adc	r15, rbx
        ; Store
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        sub	r9, 32
        sub	rcx, 96
        ; Multiply
        ;  A[0] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [rcx]
        mov	r12, rax
        mov	r13, rdx
        ;  A[0] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [rcx]
        xor	r14, r14
        add	r13, rax
        adc	r14, rdx
        ;  A[1] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [rcx+8]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[0] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [rcx]
        add	r14, rax
        adc	r15, rdx
        ;  A[1] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [rcx+8]
        xor	rdi, rdi
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[2] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [rcx+16]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[0] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [rcx]
        xor	rsi, rsi
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[1] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [rcx+8]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[2] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [rcx+16]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[3] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [rcx+24]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[1] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [rcx+8]
        xor	rbx, rbx
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[2] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [rcx+16]
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[3] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [rcx+24]
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[2] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [rcx+16]
        xor	rbp, rbp
        add	rsi, rax
        adc	rbx, rdx
        adc	rbp, 0
        ;  A[3] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [rcx+24]
        add	rsi, rax
        adc	rbx, rdx
        adc	rbp, 0
        ;  A[3] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [rcx+24]
        add	rbx, rax
        adc	rbp, rdx
        mov	rax, 38
        mul	rbp
        add	r15, rax
        adc	rdx, 0
        mov	r11, 9223372036854775807
        shld	rdx, r15, 1
        imul	rdx, rdx, 19
        and	r15, r11
        mov	r11, rdx
        mov	rax, 38
        mul	rdi
        xor	rdi, rdi
        add	r12, rax
        mov	rax, 38
        adc	rdi, rdx
        mul	rsi
        xor	rsi, rsi
        add	r13, rax
        mov	rax, 38
        adc	rsi, rdx
        mul	rbx
        xor	rbx, rbx
        add	r14, rax
        adc	rbx, rdx
        add	r12, r11
        adc	r13, rdi
        adc	r14, rsi
        adc	r15, rbx
        ; Store
        ; Add-Sub
        ; Add
        mov	rdi, r12
        add	r12, QWORD PTR [r8]
        mov	rsi, r13
        adc	r13, QWORD PTR [r8+8]
        mov	rbx, r14
        adc	r14, QWORD PTR [r8+16]
        mov	rbp, r15
        adc	r15, QWORD PTR [r8+24]
        mov	r11, 0
        adc	r11, 0
        shld	r11, r15, 1
        imul	r11, 19
        btr	r15, 63
        ;   Sub modulus (if overflow)
        add	r12, r11
        adc	r13, 0
        adc	r14, 0
        adc	r15, 0
        ; Sub
        sub	rdi, QWORD PTR [r8]
        sbb	rsi, QWORD PTR [r8+8]
        sbb	rbx, QWORD PTR [r8+16]
        sbb	rbp, QWORD PTR [r8+24]
        sbb	r11, r11
        shld	r11, rbp, 1
        imul	r11, -19
        btr	rbp, 63
        ;   Add modulus (if underflow)
        sub	rdi, r11
        sbb	rsi, 0
        sbb	rbx, 0
        sbb	rbp, 0
        mov	QWORD PTR [r8], r12
        mov	QWORD PTR [r8+8], r13
        mov	QWORD PTR [r8+16], r14
        mov	QWORD PTR [r8+24], r15
        mov	QWORD PTR [rcx], rdi
        mov	QWORD PTR [rcx+8], rsi
        mov	QWORD PTR [rcx+16], rbx
        mov	QWORD PTR [rcx+24], rbp
        sub	r10, 32
        add	rcx, 64
        ; Double
        mov	r12, QWORD PTR [r10]
        mov	r13, QWORD PTR [r10+8]
        add	r12, r12
        mov	r14, QWORD PTR [r10+16]
        adc	r13, r13
        mov	r15, QWORD PTR [r10+24]
        adc	r14, r14
        adc	r15, r15
        mov	r11, 0
        adc	r11, 0
        shld	r11, r15, 1
        imul	r11, 19
        btr	r15, 63
        ;   Sub modulus (if overflow)
        add	r12, r11
        adc	r13, 0
        adc	r14, 0
        adc	r15, 0
        mov	r8, rcx
        add	r8, 32
        ; Add-Sub
        ; Add
        mov	rdi, r12
        add	r12, QWORD PTR [r8]
        mov	rsi, r13
        adc	r13, QWORD PTR [r8+8]
        mov	rbx, r14
        adc	r14, QWORD PTR [r8+16]
        mov	rbp, r15
        adc	r15, QWORD PTR [r8+24]
        mov	r11, 0
        adc	r11, 0
        shld	r11, r15, 1
        imul	r11, 19
        btr	r15, 63
        ;   Sub modulus (if overflow)
        add	r12, r11
        adc	r13, 0
        adc	r14, 0
        adc	r15, 0
        ; Sub
        sub	rdi, QWORD PTR [r8]
        sbb	rsi, QWORD PTR [r8+8]
        sbb	rbx, QWORD PTR [r8+16]
        sbb	rbp, QWORD PTR [r8+24]
        sbb	r11, r11
        shld	r11, rbp, 1
        imul	r11, -19
        btr	rbp, 63
        ;   Add modulus (if underflow)
        sub	rdi, r11
        sbb	rsi, 0
        sbb	rbx, 0
        sbb	rbp, 0
        mov	QWORD PTR [r8], r12
        mov	QWORD PTR [r8+8], r13
        mov	QWORD PTR [r8+16], r14
        mov	QWORD PTR [r8+24], r15
        mov	QWORD PTR [rcx], rdi
        mov	QWORD PTR [rcx+8], rsi
        mov	QWORD PTR [rcx+16], rbx
        mov	QWORD PTR [rcx+24], rbp
        add	rsp, 24
        pop	rbp
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
ge_msub_x64 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
ge_add_x64 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        push	rbp
        mov	r9, r8
        mov	r8, rdx
        sub	rsp, 24
        mov	QWORD PTR [rsp], rcx
        mov	QWORD PTR [rsp+8], r8
        mov	QWORD PTR [rsp+16], r9
        mov	r10, r8
        mov	r9, r8
        add	r9, 32
        mov	r8, rcx
        add	r8, 32
        ; Add-Sub
        ; Add
        mov	r12, QWORD PTR [r9]
        mov	r13, QWORD PTR [r9+8]
        mov	r14, QWORD PTR [r9+16]
        mov	r15, QWORD PTR [r9+24]
        mov	rdi, r12
        add	r12, QWORD PTR [r10]
        mov	rsi, r13
        adc	r13, QWORD PTR [r10+8]
        mov	rbx, r14
        adc	r14, QWORD PTR [r10+16]
        mov	rbp, r15
        adc	r15, QWORD PTR [r10+24]
        mov	r11, 0
        adc	r11, 0
        shld	r11, r15, 1
        imul	r11, 19
        btr	r15, 63
        ;   Sub modulus (if overflow)
        add	r12, r11
        adc	r13, 0
        adc	r14, 0
        adc	r15, 0
        ; Sub
        sub	rdi, QWORD PTR [r10]
        sbb	rsi, QWORD PTR [r10+8]
        sbb	rbx, QWORD PTR [r10+16]
        sbb	rbp, QWORD PTR [r10+24]
        sbb	r11, r11
        shld	r11, rbp, 1
        imul	r11, -19
        btr	rbp, 63
        ;   Add modulus (if underflow)
        sub	rdi, r11
        sbb	rsi, 0
        sbb	rbx, 0
        sbb	rbp, 0
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        mov	QWORD PTR [r8], rdi
        mov	QWORD PTR [r8+8], rsi
        mov	QWORD PTR [r8+16], rbx
        mov	QWORD PTR [r8+24], rbp
        mov	r9, QWORD PTR [rsp+16]
        add	r9, 32
        add	rcx, 32
        ; Multiply
        ;  A[0] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [rcx]
        mov	r12, rax
        mov	r13, rdx
        ;  A[0] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [rcx]
        xor	r14, r14
        add	r13, rax
        adc	r14, rdx
        ;  A[1] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [rcx+8]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[0] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [rcx]
        add	r14, rax
        adc	r15, rdx
        ;  A[1] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [rcx+8]
        xor	rdi, rdi
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[2] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [rcx+16]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[0] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [rcx]
        xor	rsi, rsi
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[1] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [rcx+8]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[2] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [rcx+16]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[3] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [rcx+24]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[1] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [rcx+8]
        xor	rbx, rbx
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[2] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [rcx+16]
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[3] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [rcx+24]
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[2] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [rcx+16]
        xor	rbp, rbp
        add	rsi, rax
        adc	rbx, rdx
        adc	rbp, 0
        ;  A[3] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [rcx+24]
        add	rsi, rax
        adc	rbx, rdx
        adc	rbp, 0
        ;  A[3] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [rcx+24]
        add	rbx, rax
        adc	rbp, rdx
        mov	rax, 38
        mul	rbp
        add	r15, rax
        adc	rdx, 0
        mov	r11, 9223372036854775807
        shld	rdx, r15, 1
        imul	rdx, rdx, 19
        and	r15, r11
        mov	r11, rdx
        mov	rax, 38
        mul	rdi
        xor	rdi, rdi
        add	r12, rax
        mov	rax, 38
        adc	rdi, rdx
        mul	rsi
        xor	rsi, rsi
        add	r13, rax
        mov	rax, 38
        adc	rsi, rdx
        mul	rbx
        xor	rbx, rbx
        add	r14, rax
        adc	rbx, rdx
        add	r12, r11
        adc	r13, rdi
        adc	r14, rsi
        adc	r15, rbx
        ; Store
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        add	r10, 96
        add	r9, 64
        add	rcx, 64
        ; Multiply
        ;  A[0] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r10]
        mov	r12, rax
        mov	r13, rdx
        ;  A[0] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r10]
        xor	r14, r14
        add	r13, rax
        adc	r14, rdx
        ;  A[1] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r10+8]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[0] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r10]
        add	r14, rax
        adc	r15, rdx
        ;  A[1] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r10+8]
        xor	rdi, rdi
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[2] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r10+16]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[0] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r10]
        xor	rsi, rsi
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[1] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r10+8]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[2] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r10+16]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[3] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r10+24]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[1] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r10+8]
        xor	rbx, rbx
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[2] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r10+16]
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[3] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r10+24]
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[2] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r10+16]
        xor	rbp, rbp
        add	rsi, rax
        adc	rbx, rdx
        adc	rbp, 0
        ;  A[3] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r10+24]
        add	rsi, rax
        adc	rbx, rdx
        adc	rbp, 0
        ;  A[3] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r10+24]
        add	rbx, rax
        adc	rbp, rdx
        mov	rax, 38
        mul	rbp
        add	r15, rax
        adc	rdx, 0
        mov	r11, 9223372036854775807
        shld	rdx, r15, 1
        imul	rdx, rdx, 19
        and	r15, r11
        mov	r11, rdx
        mov	rax, 38
        mul	rdi
        xor	rdi, rdi
        add	r12, rax
        mov	rax, 38
        adc	rdi, rdx
        mul	rsi
        xor	rsi, rsi
        add	r13, rax
        mov	rax, 38
        adc	rsi, rdx
        mul	rbx
        xor	rbx, rbx
        add	r14, rax
        adc	rbx, rdx
        add	r12, r11
        adc	r13, rdi
        adc	r14, rsi
        adc	r15, rbx
        ; Store
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        sub	r9, 96
        sub	rcx, 96
        ; Multiply
        ;  A[0] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [rcx]
        mov	r12, rax
        mov	r13, rdx
        ;  A[0] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [rcx]
        xor	r14, r14
        add	r13, rax
        adc	r14, rdx
        ;  A[1] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [rcx+8]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[0] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [rcx]
        add	r14, rax
        adc	r15, rdx
        ;  A[1] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [rcx+8]
        xor	rdi, rdi
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[2] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [rcx+16]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[0] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [rcx]
        xor	rsi, rsi
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[1] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [rcx+8]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[2] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [rcx+16]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[3] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [rcx+24]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[1] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [rcx+8]
        xor	rbx, rbx
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[2] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [rcx+16]
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[3] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [rcx+24]
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[2] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [rcx+16]
        xor	rbp, rbp
        add	rsi, rax
        adc	rbx, rdx
        adc	rbp, 0
        ;  A[3] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [rcx+24]
        add	rsi, rax
        adc	rbx, rdx
        adc	rbp, 0
        ;  A[3] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [rcx+24]
        add	rbx, rax
        adc	rbp, rdx
        mov	rax, 38
        mul	rbp
        add	r15, rax
        adc	rdx, 0
        mov	r11, 9223372036854775807
        shld	rdx, r15, 1
        imul	rdx, rdx, 19
        and	r15, r11
        mov	r11, rdx
        mov	rax, 38
        mul	rdi
        xor	rdi, rdi
        add	r12, rax
        mov	rax, 38
        adc	rdi, rdx
        mul	rsi
        xor	rsi, rsi
        add	r13, rax
        mov	rax, 38
        adc	rsi, rdx
        mul	rbx
        xor	rbx, rbx
        add	r14, rax
        adc	rbx, rdx
        add	r12, r11
        adc	r13, rdi
        adc	r14, rsi
        adc	r15, rbx
        ; Store
        ; Add-Sub
        ; Add
        mov	rdi, r12
        add	r12, QWORD PTR [r8]
        mov	rsi, r13
        adc	r13, QWORD PTR [r8+8]
        mov	rbx, r14
        adc	r14, QWORD PTR [r8+16]
        mov	rbp, r15
        adc	r15, QWORD PTR [r8+24]
        mov	r11, 0
        adc	r11, 0
        shld	r11, r15, 1
        imul	r11, 19
        btr	r15, 63
        ;   Sub modulus (if overflow)
        add	r12, r11
        adc	r13, 0
        adc	r14, 0
        adc	r15, 0
        ; Sub
        sub	rdi, QWORD PTR [r8]
        sbb	rsi, QWORD PTR [r8+8]
        sbb	rbx, QWORD PTR [r8+16]
        sbb	rbp, QWORD PTR [r8+24]
        sbb	r11, r11
        shld	r11, rbp, 1
        imul	r11, -19
        btr	rbp, 63
        ;   Add modulus (if underflow)
        sub	rdi, r11
        sbb	rsi, 0
        sbb	rbx, 0
        sbb	rbp, 0
        mov	QWORD PTR [r8], r12
        mov	QWORD PTR [r8+8], r13
        mov	QWORD PTR [r8+16], r14
        mov	QWORD PTR [r8+24], r15
        mov	QWORD PTR [rcx], rdi
        mov	QWORD PTR [rcx+8], rsi
        mov	QWORD PTR [rcx+16], rbx
        mov	QWORD PTR [rcx+24], rbp
        sub	r10, 32
        add	r9, 64
        ; Multiply
        ;  A[0] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r10]
        mov	r12, rax
        mov	r13, rdx
        ;  A[0] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r10]
        xor	r14, r14
        add	r13, rax
        adc	r14, rdx
        ;  A[1] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r10+8]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[0] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r10]
        add	r14, rax
        adc	r15, rdx
        ;  A[1] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r10+8]
        xor	rdi, rdi
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[2] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r10+16]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[0] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r10]
        xor	rsi, rsi
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[1] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r10+8]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[2] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r10+16]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[3] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r10+24]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[1] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r10+8]
        xor	rbx, rbx
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[2] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r10+16]
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[3] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r10+24]
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[2] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r10+16]
        xor	rbp, rbp
        add	rsi, rax
        adc	rbx, rdx
        adc	rbp, 0
        ;  A[3] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r10+24]
        add	rsi, rax
        adc	rbx, rdx
        adc	rbp, 0
        ;  A[3] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r10+24]
        add	rbx, rax
        adc	rbp, rdx
        mov	rax, 38
        mul	rbp
        add	r15, rax
        adc	rdx, 0
        mov	r11, 9223372036854775807
        shld	rdx, r15, 1
        imul	rdx, rdx, 19
        and	r15, r11
        mov	r11, rdx
        mov	rax, 38
        mul	rdi
        xor	rdi, rdi
        add	r12, rax
        mov	rax, 38
        adc	rdi, rdx
        mul	rsi
        xor	rsi, rsi
        add	r13, rax
        mov	rax, 38
        adc	rsi, rdx
        mul	rbx
        xor	rbx, rbx
        add	r14, rax
        adc	rbx, rdx
        add	r12, r11
        adc	r13, rdi
        adc	r14, rsi
        adc	r15, rbx
        ; Store
        add	rcx, 64
        ; Double
        add	r12, r12
        adc	r13, r13
        adc	r14, r14
        adc	r15, r15
        mov	r11, 0
        adc	r11, 0
        shld	r11, r15, 1
        imul	r11, 19
        btr	r15, 63
        ;   Sub modulus (if overflow)
        add	r12, r11
        adc	r13, 0
        adc	r14, 0
        adc	r15, 0
        mov	r8, rcx
        add	r8, 32
        ; Add-Sub
        ; Add
        mov	rdi, r12
        add	r12, QWORD PTR [r8]
        mov	rsi, r13
        adc	r13, QWORD PTR [r8+8]
        mov	rbx, r14
        adc	r14, QWORD PTR [r8+16]
        mov	rbp, r15
        adc	r15, QWORD PTR [r8+24]
        mov	r11, 0
        adc	r11, 0
        shld	r11, r15, 1
        imul	r11, 19
        btr	r15, 63
        ;   Sub modulus (if overflow)
        add	r12, r11
        adc	r13, 0
        adc	r14, 0
        adc	r15, 0
        ; Sub
        sub	rdi, QWORD PTR [r8]
        sbb	rsi, QWORD PTR [r8+8]
        sbb	rbx, QWORD PTR [r8+16]
        sbb	rbp, QWORD PTR [r8+24]
        sbb	r11, r11
        shld	r11, rbp, 1
        imul	r11, -19
        btr	rbp, 63
        ;   Add modulus (if underflow)
        sub	rdi, r11
        sbb	rsi, 0
        sbb	rbx, 0
        sbb	rbp, 0
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        mov	QWORD PTR [r8], rdi
        mov	QWORD PTR [r8+8], rsi
        mov	QWORD PTR [r8+16], rbx
        mov	QWORD PTR [r8+24], rbp
        add	rsp, 24
        pop	rbp
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
ge_add_x64 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
ge_sub_x64 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        push	rbp
        mov	r9, r8
        mov	r8, rdx
        sub	rsp, 24
        mov	QWORD PTR [rsp], rcx
        mov	QWORD PTR [rsp+8], r8
        mov	QWORD PTR [rsp+16], r9
        mov	r10, r8
        mov	r9, r8
        add	r9, 32
        mov	r8, rcx
        add	r8, 32
        ; Add-Sub
        ; Add
        mov	r12, QWORD PTR [r9]
        mov	r13, QWORD PTR [r9+8]
        mov	r14, QWORD PTR [r9+16]
        mov	r15, QWORD PTR [r9+24]
        mov	rdi, r12
        add	r12, QWORD PTR [r10]
        mov	rsi, r13
        adc	r13, QWORD PTR [r10+8]
        mov	rbx, r14
        adc	r14, QWORD PTR [r10+16]
        mov	rbp, r15
        adc	r15, QWORD PTR [r10+24]
        mov	r11, 0
        adc	r11, 0
        shld	r11, r15, 1
        imul	r11, 19
        btr	r15, 63
        ;   Sub modulus (if overflow)
        add	r12, r11
        adc	r13, 0
        adc	r14, 0
        adc	r15, 0
        ; Sub
        sub	rdi, QWORD PTR [r10]
        sbb	rsi, QWORD PTR [r10+8]
        sbb	rbx, QWORD PTR [r10+16]
        sbb	rbp, QWORD PTR [r10+24]
        sbb	r11, r11
        shld	r11, rbp, 1
        imul	r11, -19
        btr	rbp, 63
        ;   Add modulus (if underflow)
        sub	rdi, r11
        sbb	rsi, 0
        sbb	rbx, 0
        sbb	rbp, 0
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        mov	QWORD PTR [r8], rdi
        mov	QWORD PTR [r8+8], rsi
        mov	QWORD PTR [r8+16], rbx
        mov	QWORD PTR [r8+24], rbp
        mov	r9, QWORD PTR [rsp+16]
        add	rcx, 32
        ; Multiply
        ;  A[0] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [rcx]
        mov	r12, rax
        mov	r13, rdx
        ;  A[0] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [rcx]
        xor	r14, r14
        add	r13, rax
        adc	r14, rdx
        ;  A[1] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [rcx+8]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[0] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [rcx]
        add	r14, rax
        adc	r15, rdx
        ;  A[1] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [rcx+8]
        xor	rdi, rdi
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[2] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [rcx+16]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[0] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [rcx]
        xor	rsi, rsi
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[1] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [rcx+8]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[2] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [rcx+16]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[3] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [rcx+24]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[1] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [rcx+8]
        xor	rbx, rbx
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[2] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [rcx+16]
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[3] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [rcx+24]
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[2] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [rcx+16]
        xor	rbp, rbp
        add	rsi, rax
        adc	rbx, rdx
        adc	rbp, 0
        ;  A[3] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [rcx+24]
        add	rsi, rax
        adc	rbx, rdx
        adc	rbp, 0
        ;  A[3] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [rcx+24]
        add	rbx, rax
        adc	rbp, rdx
        mov	rax, 38
        mul	rbp
        add	r15, rax
        adc	rdx, 0
        mov	r11, 9223372036854775807
        shld	rdx, r15, 1
        imul	rdx, rdx, 19
        and	r15, r11
        mov	r11, rdx
        mov	rax, 38
        mul	rdi
        xor	rdi, rdi
        add	r12, rax
        mov	rax, 38
        adc	rdi, rdx
        mul	rsi
        xor	rsi, rsi
        add	r13, rax
        mov	rax, 38
        adc	rsi, rdx
        mul	rbx
        xor	rbx, rbx
        add	r14, rax
        adc	rbx, rdx
        add	r12, r11
        adc	r13, rdi
        adc	r14, rsi
        adc	r15, rbx
        ; Store
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        add	r10, 96
        add	r9, 96
        add	rcx, 64
        ; Multiply
        ;  A[0] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r10]
        mov	r12, rax
        mov	r13, rdx
        ;  A[0] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r10]
        xor	r14, r14
        add	r13, rax
        adc	r14, rdx
        ;  A[1] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r10+8]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[0] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r10]
        add	r14, rax
        adc	r15, rdx
        ;  A[1] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r10+8]
        xor	rdi, rdi
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[2] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r10+16]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[0] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r10]
        xor	rsi, rsi
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[1] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r10+8]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[2] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r10+16]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[3] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r10+24]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[1] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r10+8]
        xor	rbx, rbx
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[2] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r10+16]
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[3] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r10+24]
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[2] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r10+16]
        xor	rbp, rbp
        add	rsi, rax
        adc	rbx, rdx
        adc	rbp, 0
        ;  A[3] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r10+24]
        add	rsi, rax
        adc	rbx, rdx
        adc	rbp, 0
        ;  A[3] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r10+24]
        add	rbx, rax
        adc	rbp, rdx
        mov	rax, 38
        mul	rbp
        add	r15, rax
        adc	rdx, 0
        mov	r11, 9223372036854775807
        shld	rdx, r15, 1
        imul	rdx, rdx, 19
        and	r15, r11
        mov	r11, rdx
        mov	rax, 38
        mul	rdi
        xor	rdi, rdi
        add	r12, rax
        mov	rax, 38
        adc	rdi, rdx
        mul	rsi
        xor	rsi, rsi
        add	r13, rax
        mov	rax, 38
        adc	rsi, rdx
        mul	rbx
        xor	rbx, rbx
        add	r14, rax
        adc	rbx, rdx
        add	r12, r11
        adc	r13, rdi
        adc	r14, rsi
        adc	r15, rbx
        ; Store
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        sub	r9, 64
        sub	rcx, 96
        ; Multiply
        ;  A[0] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [rcx]
        mov	r12, rax
        mov	r13, rdx
        ;  A[0] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [rcx]
        xor	r14, r14
        add	r13, rax
        adc	r14, rdx
        ;  A[1] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [rcx+8]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[0] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [rcx]
        add	r14, rax
        adc	r15, rdx
        ;  A[1] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [rcx+8]
        xor	rdi, rdi
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[2] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [rcx+16]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[0] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [rcx]
        xor	rsi, rsi
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[1] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [rcx+8]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[2] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [rcx+16]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[3] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [rcx+24]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[1] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [rcx+8]
        xor	rbx, rbx
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[2] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [rcx+16]
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[3] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [rcx+24]
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[2] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [rcx+16]
        xor	rbp, rbp
        add	rsi, rax
        adc	rbx, rdx
        adc	rbp, 0
        ;  A[3] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [rcx+24]
        add	rsi, rax
        adc	rbx, rdx
        adc	rbp, 0
        ;  A[3] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [rcx+24]
        add	rbx, rax
        adc	rbp, rdx
        mov	rax, 38
        mul	rbp
        add	r15, rax
        adc	rdx, 0
        mov	r11, 9223372036854775807
        shld	rdx, r15, 1
        imul	rdx, rdx, 19
        and	r15, r11
        mov	r11, rdx
        mov	rax, 38
        mul	rdi
        xor	rdi, rdi
        add	r12, rax
        mov	rax, 38
        adc	rdi, rdx
        mul	rsi
        xor	rsi, rsi
        add	r13, rax
        mov	rax, 38
        adc	rsi, rdx
        mul	rbx
        xor	rbx, rbx
        add	r14, rax
        adc	rbx, rdx
        add	r12, r11
        adc	r13, rdi
        adc	r14, rsi
        adc	r15, rbx
        ; Store
        ; Add-Sub
        ; Add
        mov	rdi, r12
        add	r12, QWORD PTR [r8]
        mov	rsi, r13
        adc	r13, QWORD PTR [r8+8]
        mov	rbx, r14
        adc	r14, QWORD PTR [r8+16]
        mov	rbp, r15
        adc	r15, QWORD PTR [r8+24]
        mov	r11, 0
        adc	r11, 0
        shld	r11, r15, 1
        imul	r11, 19
        btr	r15, 63
        ;   Sub modulus (if overflow)
        add	r12, r11
        adc	r13, 0
        adc	r14, 0
        adc	r15, 0
        ; Sub
        sub	rdi, QWORD PTR [r8]
        sbb	rsi, QWORD PTR [r8+8]
        sbb	rbx, QWORD PTR [r8+16]
        sbb	rbp, QWORD PTR [r8+24]
        sbb	r11, r11
        shld	r11, rbp, 1
        imul	r11, -19
        btr	rbp, 63
        ;   Add modulus (if underflow)
        sub	rdi, r11
        sbb	rsi, 0
        sbb	rbx, 0
        sbb	rbp, 0
        mov	QWORD PTR [r8], r12
        mov	QWORD PTR [r8+8], r13
        mov	QWORD PTR [r8+16], r14
        mov	QWORD PTR [r8+24], r15
        mov	QWORD PTR [rcx], rdi
        mov	QWORD PTR [rcx+8], rsi
        mov	QWORD PTR [rcx+16], rbx
        mov	QWORD PTR [rcx+24], rbp
        sub	r10, 32
        add	r9, 32
        ; Multiply
        ;  A[0] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r10]
        mov	r12, rax
        mov	r13, rdx
        ;  A[0] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r10]
        xor	r14, r14
        add	r13, rax
        adc	r14, rdx
        ;  A[1] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r10+8]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[0] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r10]
        add	r14, rax
        adc	r15, rdx
        ;  A[1] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r10+8]
        xor	rdi, rdi
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[2] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r10+16]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[0] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r10]
        xor	rsi, rsi
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[1] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r10+8]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[2] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r10+16]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[3] * B[0]
        mov	rax, QWORD PTR [r9]
        mul	QWORD PTR [r10+24]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[1] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r10+8]
        xor	rbx, rbx
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[2] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r10+16]
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[3] * B[1]
        mov	rax, QWORD PTR [r9+8]
        mul	QWORD PTR [r10+24]
        add	rdi, rax
        adc	rsi, rdx
        adc	rbx, 0
        ;  A[2] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r10+16]
        xor	rbp, rbp
        add	rsi, rax
        adc	rbx, rdx
        adc	rbp, 0
        ;  A[3] * B[2]
        mov	rax, QWORD PTR [r9+16]
        mul	QWORD PTR [r10+24]
        add	rsi, rax
        adc	rbx, rdx
        adc	rbp, 0
        ;  A[3] * B[3]
        mov	rax, QWORD PTR [r9+24]
        mul	QWORD PTR [r10+24]
        add	rbx, rax
        adc	rbp, rdx
        mov	rax, 38
        mul	rbp
        add	r15, rax
        adc	rdx, 0
        mov	r11, 9223372036854775807
        shld	rdx, r15, 1
        imul	rdx, rdx, 19
        and	r15, r11
        mov	r11, rdx
        mov	rax, 38
        mul	rdi
        xor	rdi, rdi
        add	r12, rax
        mov	rax, 38
        adc	rdi, rdx
        mul	rsi
        xor	rsi, rsi
        add	r13, rax
        mov	rax, 38
        adc	rsi, rdx
        mul	rbx
        xor	rbx, rbx
        add	r14, rax
        adc	rbx, rdx
        add	r12, r11
        adc	r13, rdi
        adc	r14, rsi
        adc	r15, rbx
        ; Store
        ; Double
        add	r12, r12
        adc	r13, r13
        adc	r14, r14
        adc	r15, r15
        mov	r11, 0
        adc	r11, 0
        shld	r11, r15, 1
        imul	r11, 19
        btr	r15, 63
        ;   Sub modulus (if overflow)
        add	r12, r11
        adc	r13, 0
        adc	r14, 0
        adc	r15, 0
        mov	r8, rcx
        add	r8, 64
        add	rcx, 96
        ; Add-Sub
        ; Add
        mov	rdi, r12
        add	r12, QWORD PTR [rcx]
        mov	rsi, r13
        adc	r13, QWORD PTR [rcx+8]
        mov	rbx, r14
        adc	r14, QWORD PTR [rcx+16]
        mov	rbp, r15
        adc	r15, QWORD PTR [rcx+24]
        mov	r11, 0
        adc	r11, 0
        shld	r11, r15, 1
        imul	r11, 19
        btr	r15, 63
        ;   Sub modulus (if overflow)
        add	r12, r11
        adc	r13, 0
        adc	r14, 0
        adc	r15, 0
        ; Sub
        sub	rdi, QWORD PTR [rcx]
        sbb	rsi, QWORD PTR [rcx+8]
        sbb	rbx, QWORD PTR [rcx+16]
        sbb	rbp, QWORD PTR [rcx+24]
        sbb	r11, r11
        shld	r11, rbp, 1
        imul	r11, -19
        btr	rbp, 63
        ;   Add modulus (if underflow)
        sub	rdi, r11
        sbb	rsi, 0
        sbb	rbx, 0
        sbb	rbp, 0
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        mov	QWORD PTR [r8], rdi
        mov	QWORD PTR [r8+8], rsi
        mov	QWORD PTR [r8+16], rbx
        mov	QWORD PTR [r8+24], rbp
        add	rsp, 24
        pop	rbp
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
ge_sub_x64 ENDP
_TEXT ENDS
IFDEF HAVE_ED25519
_TEXT SEGMENT READONLY PARA
fe_sq2_x64 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        mov	r8, rdx
        ; Square * 2
        ;  A[0] * A[1]
        mov	rax, QWORD PTR [r8]
        mul	QWORD PTR [r8+8]
        mov	r10, rax
        mov	r11, rdx
        ;  A[0] * A[2]
        mov	rax, QWORD PTR [r8]
        mul	QWORD PTR [r8+16]
        xor	r12, r12
        add	r11, rax
        adc	r12, rdx
        ;  A[0] * A[3]
        mov	rax, QWORD PTR [r8]
        mul	QWORD PTR [r8+24]
        xor	r13, r13
        add	r12, rax
        adc	r13, rdx
        ;  A[1] * A[2]
        mov	rax, QWORD PTR [r8+8]
        mul	QWORD PTR [r8+16]
        xor	r14, r14
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[1] * A[3]
        mov	rax, QWORD PTR [r8+8]
        mul	QWORD PTR [r8+24]
        add	r13, rax
        adc	r14, rdx
        ;  A[2] * A[3]
        mov	rax, QWORD PTR [r8+16]
        mul	QWORD PTR [r8+24]
        xor	r15, r15
        add	r14, rax
        adc	r15, rdx
        ; Double
        xor	rdi, rdi
        add	r10, r10
        adc	r11, r11
        adc	r12, r12
        adc	r13, r13
        adc	r14, r14
        adc	r15, r15
        adc	rdi, 0
        ;  A[0] * A[0]
        mov	rax, QWORD PTR [r8]
        mul	rax
        mov	r9, rax
        mov	rsi, rdx
        ;  A[1] * A[1]
        mov	rax, QWORD PTR [r8+8]
        mul	rax
        add	r10, rsi
        adc	r11, rax
        adc	rdx, 0
        mov	rsi, rdx
        ;  A[2] * A[2]
        mov	rax, QWORD PTR [r8+16]
        mul	rax
        add	r12, rsi
        adc	r13, rax
        adc	rdx, 0
        mov	rsi, rdx
        ;  A[3] * A[3]
        mov	rax, QWORD PTR [r8+24]
        mul	rax
        add	r15, rax
        adc	rdi, rdx
        add	r14, rsi
        adc	r15, 0
        adc	rdi, 0
        mov	rax, 38
        mul	rdi
        add	r12, rax
        adc	rdx, 0
        mov	rsi, 9223372036854775807
        shld	rdx, r12, 1
        imul	rdx, rdx, 19
        and	r12, rsi
        mov	rsi, rdx
        mov	rax, 38
        mul	r13
        xor	r13, r13
        add	r9, rax
        mov	rax, 38
        adc	r13, rdx
        mul	r14
        xor	r14, r14
        add	r10, rax
        mov	rax, 38
        adc	r14, rdx
        mul	r15
        xor	r15, r15
        add	r11, rax
        adc	r15, rdx
        add	r9, rsi
        adc	r10, r13
        adc	r11, r14
        adc	r12, r15
        mov	rax, r12
        shld	r12, r11, 1
        shld	r11, r10, 1
        shld	r10, r9, 1
        shl	r9, 1
        mov	rsi, 9223372036854775807
        shr	rax, 62
        and	r12, rsi
        imul	rax, rax, 19
        add	r9, rax
        adc	r10, 0
        adc	r11, 0
        adc	r12, 0
        ; Store
        mov	QWORD PTR [rcx], r9
        mov	QWORD PTR [rcx+8], r10
        mov	QWORD PTR [rcx+16], r11
        mov	QWORD PTR [rcx+24], r12
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
fe_sq2_x64 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
sc_reduce_x64 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        push	rbp
        mov	r9, QWORD PTR [rcx]
        mov	r10, QWORD PTR [rcx+8]
        mov	r11, QWORD PTR [rcx+16]
        mov	r12, QWORD PTR [rcx+24]
        mov	r13, QWORD PTR [rcx+32]
        mov	r14, QWORD PTR [rcx+40]
        mov	r15, QWORD PTR [rcx+48]
        mov	rdi, QWORD PTR [rcx+56]
        mov	r8, rdi
        mov	rsi, 1152921504606846975
        shr	r8, 56
        shld	rdi, r15, 4
        shld	r15, r14, 4
        shld	r14, r13, 4
        shld	r13, r12, 4
        and	r12, rsi
        and	rdi, rsi
        ; Add order times bits 504..511
        sub	r15, r8
        sbb	rdi, 0
        mov	rax, 16942830013509034793
        mul	r8
        mov	rsi, 0
        add	r14, rax
        mov	rax, 12100500283911187475
        adc	rsi, rdx
        mul	r8
        add	r13, rax
        adc	r14, rdx
        adc	r15, rsi
        adc	rdi, 0
        ; Sub product of top 4 words and order
        mov	r8, 12100500283911187475
        mov	rax, r13
        mul	r8
        mov	rbp, 0
        add	r9, rax
        adc	rbp, rdx
        mov	rax, r14
        mul	r8
        mov	rsi, 0
        add	r10, rax
        adc	rsi, rdx
        mov	rax, r15
        mul	r8
        add	r10, rbp
        adc	r11, rax
        adc	r12, rdx
        mov	rbx, 0
        adc	rbx, 0
        mov	rax, rdi
        mul	r8
        add	r11, rsi
        adc	r12, rax
        adc	rbx, rdx
        mov	r8, 16942830013509034793
        mov	rax, r13
        mul	r8
        mov	rbp, 0
        add	r10, rax
        adc	rbp, rdx
        mov	rax, r14
        mul	r8
        mov	rsi, 0
        add	r11, rax
        adc	rsi, rdx
        mov	rax, r15
        mul	r8
        add	r11, rbp
        adc	r12, rax
        adc	rbx, rdx
        mov	rbp, 0
        adc	rbp, 0
        mov	rax, rdi
        mul	r8
        add	r12, rsi
        adc	rbx, rax
        adc	rbp, rdx
        sub	r11, r13
        mov	r13, rbx
        sbb	r12, r14
        mov	r14, rbp
        sbb	r13, r15
        sbb	r14, rdi
        mov	r8, r14
        sar	r8, 57
        ;   Conditionally subtract order starting at bit 125
        mov	rax, 11529215046068469760
        mov	rdx, 14628338529006959229
        mov	rbx, 187989257525064602
        mov	rbp, 144115188075855872
        and	rax, r8
        and	rdx, r8
        and	rbx, r8
        and	rbp, r8
        add	r10, rax
        adc	r11, rdx
        adc	r12, rbx
        adc	r13, 0
        adc	r14, rbp
        ;   Move bits 252-376 to own registers
        mov	r8, 1152921504606846975
        shld	r14, r13, 4
        shld	r13, r12, 4
        and	r12, r8
        ; Sub product of top 2 words and order
        ;   * -5812631a5cf5d3ed
        mov	r8, 12100500283911187475
        mov	rax, r13
        mul	r8
        mov	rbx, 0
        add	r9, rax
        adc	r10, rdx
        adc	rbx, 0
        mov	rax, r14
        mul	r8
        add	r10, rax
        adc	rbx, rdx
        ;   * -14def9dea2f79cd7
        mov	r8, 16942830013509034793
        mov	rax, r13
        mul	r8
        mov	rbp, 0
        add	r10, rax
        adc	r11, rdx
        adc	rbp, 0
        mov	rax, r14
        mul	r8
        add	r11, rax
        adc	rbp, rdx
        ;   Add overflows at 2 * 64
        mov	rsi, 1152921504606846975
        and	r12, rsi
        add	r11, rbx
        adc	r12, rbp
        ;   Subtract top at 2 * 64
        sub	r11, r13
        sbb	r12, r14
        sbb	rsi, rsi
        ;   Conditional sub order
        mov	rax, 6346243789798364141
        mov	rdx, 1503914060200516822
        mov	rbx, 1152921504606846976
        and	rax, rsi
        and	rdx, rsi
        and	rbx, rsi
        add	r9, rax
        mov	rax, 1152921504606846975
        adc	r10, rdx
        adc	r11, 0
        adc	r12, rbx
        and	r12, rax
        ; Store result
        mov	QWORD PTR [rcx], r9
        mov	QWORD PTR [rcx+8], r10
        mov	QWORD PTR [rcx+16], r11
        mov	QWORD PTR [rcx+24], r12
        pop	rbp
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
sc_reduce_x64 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
sc_muladd_x64 PROC
        push	rbp
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        mov	rbp, r8
        mov	r8, rdx
        ; Multiply
        ;  A[0] * B[0]
        mov	rax, QWORD PTR [rbp]
        mul	QWORD PTR [r8]
        mov	r10, rax
        mov	r11, rdx
        ;  A[0] * B[1]
        mov	rax, QWORD PTR [rbp+8]
        mul	QWORD PTR [r8]
        xor	r12, r12
        add	r11, rax
        adc	r12, rdx
        ;  A[1] * B[0]
        mov	rax, QWORD PTR [rbp]
        mul	QWORD PTR [r8+8]
        xor	r13, r13
        add	r11, rax
        adc	r12, rdx
        adc	r13, 0
        ;  A[0] * B[2]
        mov	rax, QWORD PTR [rbp+16]
        mul	QWORD PTR [r8]
        add	r12, rax
        adc	r13, rdx
        ;  A[1] * B[1]
        mov	rax, QWORD PTR [rbp+8]
        mul	QWORD PTR [r8+8]
        xor	r14, r14
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[2] * B[0]
        mov	rax, QWORD PTR [rbp]
        mul	QWORD PTR [r8+16]
        add	r12, rax
        adc	r13, rdx
        adc	r14, 0
        ;  A[0] * B[3]
        mov	rax, QWORD PTR [rbp+24]
        mul	QWORD PTR [r8]
        xor	r15, r15
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[1] * B[2]
        mov	rax, QWORD PTR [rbp+16]
        mul	QWORD PTR [r8+8]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[2] * B[1]
        mov	rax, QWORD PTR [rbp+8]
        mul	QWORD PTR [r8+16]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[3] * B[0]
        mov	rax, QWORD PTR [rbp]
        mul	QWORD PTR [r8+24]
        add	r13, rax
        adc	r14, rdx
        adc	r15, 0
        ;  A[1] * B[3]
        mov	rax, QWORD PTR [rbp+24]
        mul	QWORD PTR [r8+8]
        xor	rdi, rdi
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[2] * B[2]
        mov	rax, QWORD PTR [rbp+16]
        mul	QWORD PTR [r8+16]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[3] * B[1]
        mov	rax, QWORD PTR [rbp+8]
        mul	QWORD PTR [r8+24]
        add	r14, rax
        adc	r15, rdx
        adc	rdi, 0
        ;  A[2] * B[3]
        mov	rax, QWORD PTR [rbp+24]
        mul	QWORD PTR [r8+16]
        xor	rsi, rsi
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[3] * B[2]
        mov	rax, QWORD PTR [rbp+16]
        mul	QWORD PTR [r8+24]
        add	r15, rax
        adc	rdi, rdx
        adc	rsi, 0
        ;  A[3] * B[3]
        mov	rax, QWORD PTR [rbp+24]
        mul	QWORD PTR [r8+24]
        add	rdi, rax
        adc	rsi, rdx
        ; Add c to a * b
        add	r10, QWORD PTR [r9]
        adc	r11, QWORD PTR [r9+8]
        adc	r12, QWORD PTR [r9+16]
        adc	r13, QWORD PTR [r9+24]
        adc	r14, 0
        adc	r15, 0
        adc	rdi, 0
        adc	rsi, 0
        mov	rbx, rsi
        mov	r9, 1152921504606846975
        shr	rbx, 56
        shld	rsi, rdi, 4
        shld	rdi, r15, 4
        shld	r15, r14, 4
        shld	r14, r13, 4
        and	r13, r9
        and	rsi, r9
        ; Add order times bits 504..507
        sub	rdi, rbx
        sbb	rsi, 0
        mov	rax, 16942830013509034793
        mul	rbx
        mov	r9, 0
        add	r15, rax
        mov	rax, 12100500283911187475
        adc	r9, rdx
        mul	rbx
        add	r14, rax
        adc	r15, rdx
        adc	rdi, r9
        adc	rsi, 0
        ; Sub product of top 4 words and order
        mov	rbx, 12100500283911187475
        mov	rax, r14
        mul	rbx
        mov	rbp, 0
        add	r10, rax
        adc	rbp, rdx
        mov	rax, r15
        mul	rbx
        mov	r9, 0
        add	r11, rax
        adc	r9, rdx
        mov	rax, rdi
        mul	rbx
        add	r11, rbp
        adc	r12, rax
        adc	r13, rdx
        mov	r8, 0
        adc	r8, 0
        mov	rax, rsi
        mul	rbx
        add	r12, r9
        adc	r13, rax
        adc	r8, rdx
        mov	rbx, 16942830013509034793
        mov	rax, r14
        mul	rbx
        mov	rbp, 0
        add	r11, rax
        adc	rbp, rdx
        mov	rax, r15
        mul	rbx
        mov	r9, 0
        add	r12, rax
        adc	r9, rdx
        mov	rax, rdi
        mul	rbx
        add	r12, rbp
        adc	r13, rax
        adc	r8, rdx
        mov	rbp, 0
        adc	rbp, 0
        mov	rax, rsi
        mul	rbx
        add	r13, r9
        adc	r8, rax
        adc	rbp, rdx
        sub	r12, r14
        mov	r14, r8
        sbb	r13, r15
        mov	r15, rbp
        sbb	r14, rdi
        sbb	r15, rsi
        mov	rbx, r15
        sar	rbx, 57
        ;   Conditionally subtract order starting at bit 125
        mov	rax, 11529215046068469760
        mov	rdx, 14628338529006959229
        mov	r8, 187989257525064602
        mov	rbp, 144115188075855872
        and	rax, rbx
        and	rdx, rbx
        and	r8, rbx
        and	rbp, rbx
        add	r11, rax
        adc	r12, rdx
        adc	r13, r8
        adc	r14, 0
        adc	r15, rbp
        ;   Move bits 252-376 to own registers
        mov	rbx, 1152921504606846975
        shld	r15, r14, 4
        shld	r14, r13, 4
        and	r13, rbx
        ; Sub product of top 2 words and order
        ;   * -5812631a5cf5d3ed
        mov	rbx, 12100500283911187475
        mov	rax, r14
        mul	rbx
        mov	r8, 0
        add	r10, rax
        adc	r11, rdx
        adc	r8, 0
        mov	rax, r15
        mul	rbx
        add	r11, rax
        adc	r8, rdx
        ;   * -14def9dea2f79cd7
        mov	rbx, 16942830013509034793
        mov	rax, r14
        mul	rbx
        mov	rbp, 0
        add	r11, rax
        adc	r12, rdx
        adc	rbp, 0
        mov	rax, r15
        mul	rbx
        add	r12, rax
        adc	rbp, rdx
        ;   Add overflows at 2 * 64
        mov	r9, 1152921504606846975
        and	r13, r9
        add	r12, r8
        adc	r13, rbp
        ;   Subtract top at 2 * 64
        sub	r12, r14
        sbb	r13, r15
        sbb	r9, r9
        ;   Conditional sub order
        mov	rax, 6346243789798364141
        mov	rdx, 1503914060200516822
        mov	r8, 1152921504606846976
        and	rax, r9
        and	rdx, r9
        and	r8, r9
        add	r10, rax
        mov	rax, 1152921504606846975
        adc	r11, rdx
        adc	r12, 0
        adc	r13, r8
        and	r13, rax
        ; Store result
        mov	QWORD PTR [rcx], r10
        mov	QWORD PTR [rcx+8], r11
        mov	QWORD PTR [rcx+16], r12
        mov	QWORD PTR [rcx+24], r13
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        pop	rbp
        ret
sc_muladd_x64 ENDP
_TEXT ENDS
; /* Non-constant time modular inversion.
;  *
;  * @param  [out]  r   Resulting number.
;  * @param  [in]   a   Number to invert.
;  * @return  MP_OKAY on success.
;  */
_TEXT SEGMENT READONLY PARA
fe_invert_nct_x64 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        sub	rsp, 513
        mov	r9, -19
        mov	r10, -1
        mov	r11, -1
        mov	r12, 9223372036854775807
        mov	r13, QWORD PTR [rdx]
        mov	r14, QWORD PTR [rdx+8]
        mov	r15, QWORD PTR [rdx+16]
        mov	rdi, QWORD PTR [rdx+24]
        mov	rsi, 0
        test	r13b, 1
        jnz	fe_invert_nct_v_even_end
fe_invert_nct_v_even_start:
        shrd	r13, r14, 1
        shrd	r14, r15, 1
        shrd	r15, rdi, 1
        shr	rdi, 1
        mov	BYTE PTR [rsp+rsi], 1
        inc	rsi
        test	r13b, 1
        jz	fe_invert_nct_v_even_start
fe_invert_nct_v_even_end:
L_fe_invert_nct_uv_start:
        cmp	r12, rdi
        jb	L_fe_invert_nct_uv_v
        ja	L_fe_invert_nct_uv_u
        cmp	r11, r15
        jb	L_fe_invert_nct_uv_v
        ja	L_fe_invert_nct_uv_u
        cmp	r10, r14
        jb	L_fe_invert_nct_uv_v
        ja	L_fe_invert_nct_uv_u
        cmp	r9, r13
        jb	L_fe_invert_nct_uv_v
L_fe_invert_nct_uv_u:
        mov	BYTE PTR [rsp+rsi], 2
        inc	rsi
        sub	r9, r13
        sbb	r10, r14
        sbb	r11, r15
        sbb	r12, rdi
        shrd	r9, r10, 1
        shrd	r10, r11, 1
        shrd	r11, r12, 1
        shr	r12, 1
        test	r9b, 1
        jnz	fe_invert_nct_usubv_even_end
fe_invert_nct_usubv_even_start:
        shrd	r9, r10, 1
        shrd	r10, r11, 1
        shrd	r11, r12, 1
        shr	r12, 1
        mov	BYTE PTR [rsp+rsi], 0
        inc	rsi
        test	r9b, 1
        jz	fe_invert_nct_usubv_even_start
fe_invert_nct_usubv_even_end:
        cmp	r9, 1
        jne	L_fe_invert_nct_uv_start
        mov	rax, r10
        or	rax, r11
        jne	L_fe_invert_nct_uv_start
        or	rax, r12
        jne	L_fe_invert_nct_uv_start
        mov	r8b, 1
        jmp	L_fe_invert_nct_uv_end
L_fe_invert_nct_uv_v:
        mov	BYTE PTR [rsp+rsi], 3
        inc	rsi
        sub	r13, r9
        sbb	r14, r10
        sbb	r15, r11
        sbb	rdi, r12
        shrd	r13, r14, 1
        shrd	r14, r15, 1
        shrd	r15, rdi, 1
        shr	rdi, 1
        test	r13b, 1
        jnz	fe_invert_nct_vsubu_even_end
fe_invert_nct_vsubu_even_start:
        shrd	r13, r14, 1
        shrd	r14, r15, 1
        shrd	r15, rdi, 1
        shr	rdi, 1
        mov	BYTE PTR [rsp+rsi], 1
        inc	rsi
        test	r13b, 1
        jz	fe_invert_nct_vsubu_even_start
fe_invert_nct_vsubu_even_end:
        cmp	r13, 1
        jne	L_fe_invert_nct_uv_start
        mov	rax, r14
        or	rax, r15
        jne	L_fe_invert_nct_uv_start
        or	rax, rdi
        jne	L_fe_invert_nct_uv_start
        mov	r8b, 0
L_fe_invert_nct_uv_end:
        mov	r9, -19
        mov	r10, -1
        mov	r11, -1
        mov	r12, 9223372036854775807
        mov	r13, 1
        xor	r14, r14
        xor	r15, r15
        xor	rdi, rdi
        mov	BYTE PTR [rsp+rsi], 7
        mov	al, BYTE PTR [rsp]
        mov	rsi, 1
        cmp	al, 1
        je	L_fe_invert_nct_op_div2_d
        jl	L_fe_invert_nct_op_div2_b
        cmp	al, 3
        je	L_fe_invert_nct_op_d_sub_b
        jl	L_fe_invert_nct_op_b_sub_d
        jmp	L_fe_invert_nct_op_end
L_fe_invert_nct_op_b_sub_d:
        sub	r9, r13
        sbb	r10, r14
        sbb	r11, r15
        sbb	r12, rdi
        jnc	L_fe_invert_nct_op_div2_b
        mov	rax, -1
        add	r9, -19
        adc	r10, rax
        adc	r11, rax
        mov	rax, 9223372036854775807
        adc	r12, rax
L_fe_invert_nct_op_div2_b:
        test	r9b, 1
        jz	L_fe_invert_nct_op_div2_b_mod
        add	r9, -19
        mov	rax, -1
        adc	r10, rax
        adc	r11, rax
        mov	rax, 9223372036854775807
        adc	r12, rax
L_fe_invert_nct_op_div2_b_mod:
        shrd	r9, r10, 1
        shrd	r10, r11, 1
        shrd	r11, r12, 1
        shr	r12, 1
        mov	al, BYTE PTR [rsp+rsi]
        inc	rsi
        cmp	al, 1
        je	L_fe_invert_nct_op_div2_d
        jl	L_fe_invert_nct_op_div2_b
        cmp	al, 3
        je	L_fe_invert_nct_op_d_sub_b
        jl	L_fe_invert_nct_op_b_sub_d
        jmp	L_fe_invert_nct_op_end
L_fe_invert_nct_op_d_sub_b:
        sub	r13, r9
        sbb	r14, r10
        sbb	r15, r11
        sbb	rdi, r12
        jnc	L_fe_invert_nct_op_div2_d
        mov	rax, -1
        add	r13, -19
        adc	r14, rax
        adc	r15, rax
        mov	rax, 9223372036854775807
        adc	rdi, rax
L_fe_invert_nct_op_div2_d:
        test	r13b, 1
        jz	L_fe_invert_nct_op_div2_d_mod
        add	r13, -19
        mov	rax, -1
        adc	r14, rax
        adc	r15, rax
        mov	rax, 9223372036854775807
        adc	rdi, rax
L_fe_invert_nct_op_div2_d_mod:
        shrd	r13, r14, 1
        shrd	r14, r15, 1
        shrd	r15, rdi, 1
        shr	rdi, 1
        mov	al, BYTE PTR [rsp+rsi]
        inc	rsi
        cmp	al, 1
        je	L_fe_invert_nct_op_div2_d
        jl	L_fe_invert_nct_op_div2_b
        cmp	al, 3
        je	L_fe_invert_nct_op_d_sub_b
        jl	L_fe_invert_nct_op_b_sub_d
L_fe_invert_nct_op_end:
        cmp	r8b, 1
        jne	L_fe_invert_nct_store_d
        mov	QWORD PTR [rcx], r9
        mov	QWORD PTR [rcx+8], r10
        mov	QWORD PTR [rcx+16], r11
        mov	QWORD PTR [rcx+24], r12
        jmp	L_fe_invert_nct_store_end
L_fe_invert_nct_store_d:
        mov	QWORD PTR [rcx], r13
        mov	QWORD PTR [rcx+8], r14
        mov	QWORD PTR [rcx+16], r15
        mov	QWORD PTR [rcx+24], rdi
L_fe_invert_nct_store_end:
        add	rsp, 513
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
fe_invert_nct_x64 ENDP
_TEXT ENDS
ENDIF
IFDEF HAVE_INTEL_AVX2
_TEXT SEGMENT READONLY PARA
fe_cmov_table_avx2 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        mov	r9, rdx
        sub	rsp, 64
        vmovdqu	OWORD PTR [rsp], xmm6
        vmovdqu	OWORD PTR [rsp+16], xmm7
        vmovdqu	OWORD PTR [rsp+32], xmm8
        vmovdqu	OWORD PTR [rsp+48], xmm9
        xor	rbx, rbx
        movsx	rax, r8b
        cdq
        xor	al, dl
        sub	al, dl
        mov	bl, al
        movd	xmm7, ebx
        mov	rbx, 1
        movd	xmm9, rbx
        vmovdqa	ymm3, ymm9
        vmovdqa	ymm4, ymm9
        vpxor	ymm8, ymm8, ymm8
        vpermd	ymm7, ymm8, ymm7
        vpermd	ymm9, ymm8, ymm9
        vpxor	ymm0, ymm0, ymm0
        vpxor	ymm1, ymm1, ymm1
        vpxor	ymm2, ymm2, ymm2
        vpcmpeqd	ymm6, ymm8, ymm7
        vpxor	ymm5, ymm5, ymm5
        vpand	ymm3, ymm3, ymm6
        vpand	ymm4, ymm4, ymm6
        vmovdqa	ymm8, ymm9
        vpcmpeqd	ymm6, ymm8, ymm7
        vpaddd	ymm8, ymm8, ymm9
        vmovupd	ymm0, YMMWORD PTR [r9]
        vmovupd	ymm1, YMMWORD PTR [r9+32]
        vmovupd	ymm2, YMMWORD PTR [r9+64]
        vpand	ymm0, ymm0, ymm6
        vpand	ymm1, ymm1, ymm6
        vpand	ymm2, ymm2, ymm6
        vpor	ymm3, ymm3, ymm0
        vpor	ymm4, ymm4, ymm1
        vpor	ymm5, ymm5, ymm2
        vpcmpeqd	ymm6, ymm8, ymm7
        vpaddd	ymm8, ymm8, ymm9
        vmovupd	ymm0, YMMWORD PTR [r9+96]
        vmovupd	ymm1, YMMWORD PTR [r9+128]
        vmovupd	ymm2, YMMWORD PTR [r9+160]
        vpand	ymm0, ymm0, ymm6
        vpand	ymm1, ymm1, ymm6
        vpand	ymm2, ymm2, ymm6
        vpor	ymm3, ymm3, ymm0
        vpor	ymm4, ymm4, ymm1
        vpor	ymm5, ymm5, ymm2
        vpcmpeqd	ymm6, ymm8, ymm7
        vpaddd	ymm8, ymm8, ymm9
        vmovupd	ymm0, YMMWORD PTR [r9+192]
        vmovupd	ymm1, YMMWORD PTR [r9+224]
        vmovupd	ymm2, YMMWORD PTR [r9+256]
        vpand	ymm0, ymm0, ymm6
        vpand	ymm1, ymm1, ymm6
        vpand	ymm2, ymm2, ymm6
        vpor	ymm3, ymm3, ymm0
        vpor	ymm4, ymm4, ymm1
        vpor	ymm5, ymm5, ymm2
        vpcmpeqd	ymm6, ymm8, ymm7
        vpaddd	ymm8, ymm8, ymm9
        vmovupd	ymm0, YMMWORD PTR [r9+288]
        vmovupd	ymm1, YMMWORD PTR [r9+320]
        vmovupd	ymm2, YMMWORD PTR [r9+352]
        vpand	ymm0, ymm0, ymm6
        vpand	ymm1, ymm1, ymm6
        vpand	ymm2, ymm2, ymm6
        vpor	ymm3, ymm3, ymm0
        vpor	ymm4, ymm4, ymm1
        vpor	ymm5, ymm5, ymm2
        vpcmpeqd	ymm6, ymm8, ymm7
        vpaddd	ymm8, ymm8, ymm9
        vmovupd	ymm0, YMMWORD PTR [r9+384]
        vmovupd	ymm1, YMMWORD PTR [r9+416]
        vmovupd	ymm2, YMMWORD PTR [r9+448]
        vpand	ymm0, ymm0, ymm6
        vpand	ymm1, ymm1, ymm6
        vpand	ymm2, ymm2, ymm6
        vpor	ymm3, ymm3, ymm0
        vpor	ymm4, ymm4, ymm1
        vpor	ymm5, ymm5, ymm2
        vpcmpeqd	ymm6, ymm8, ymm7
        vpaddd	ymm8, ymm8, ymm9
        vmovupd	ymm0, YMMWORD PTR [r9+480]
        vmovupd	ymm1, YMMWORD PTR [r9+512]
        vmovupd	ymm2, YMMWORD PTR [r9+544]
        vpand	ymm0, ymm0, ymm6
        vpand	ymm1, ymm1, ymm6
        vpand	ymm2, ymm2, ymm6
        vpor	ymm3, ymm3, ymm0
        vpor	ymm4, ymm4, ymm1
        vpor	ymm5, ymm5, ymm2
        vpcmpeqd	ymm6, ymm8, ymm7
        vpaddd	ymm8, ymm8, ymm9
        vmovupd	ymm0, YMMWORD PTR [r9+576]
        vmovupd	ymm1, YMMWORD PTR [r9+608]
        vmovupd	ymm2, YMMWORD PTR [r9+640]
        vpand	ymm0, ymm0, ymm6
        vpand	ymm1, ymm1, ymm6
        vpand	ymm2, ymm2, ymm6
        vpor	ymm3, ymm3, ymm0
        vpor	ymm4, ymm4, ymm1
        vpor	ymm5, ymm5, ymm2
        vpcmpeqd	ymm6, ymm8, ymm7
        vpaddd	ymm8, ymm8, ymm9
        vmovupd	ymm0, YMMWORD PTR [r9+672]
        vmovupd	ymm1, YMMWORD PTR [r9+704]
        vmovupd	ymm2, YMMWORD PTR [r9+736]
        vpand	ymm0, ymm0, ymm6
        vpand	ymm1, ymm1, ymm6
        vpand	ymm2, ymm2, ymm6
        vpor	ymm3, ymm3, ymm0
        vpor	ymm4, ymm4, ymm1
        vpor	ymm5, ymm5, ymm2
        movsx	rax, r8b
        sar	rax, 63
        vmovd	xmm6, eax
        vpxor	ymm8, ymm8, ymm8
        vpermd	ymm6, ymm8, ymm6
        vpxor	ymm8, ymm3, ymm4
        vpand	ymm8, ymm8, ymm6
        vpxor	ymm3, ymm3, ymm8
        vpxor	ymm4, ymm4, ymm8
        vmovupd	YMMWORD PTR [rcx], ymm3
        vmovupd	YMMWORD PTR [rcx+32], ymm4
        vmovupd	YMMWORD PTR [rcx+64], ymm5
        mov	r10, QWORD PTR [rcx+64]
        mov	r11, QWORD PTR [rcx+72]
        mov	r12, QWORD PTR [rcx+80]
        mov	r13, QWORD PTR [rcx+88]
        mov	r14, -19
        mov	r15, -1
        mov	rdi, -1
        mov	rsi, 9223372036854775807
        sub	r14, r10
        sbb	r15, r11
        sbb	rdi, r12
        sbb	rsi, r13
        cmp	r8b, 0
        cmovl	r10, r14
        cmovl	r11, r15
        cmovl	r12, rdi
        cmovl	r13, rsi
        mov	QWORD PTR [rcx+64], r10
        mov	QWORD PTR [rcx+72], r11
        mov	QWORD PTR [rcx+80], r12
        mov	QWORD PTR [rcx+88], r13
        vzeroupper
        vmovdqu	xmm6, OWORD PTR [rsp]
        vmovdqu	xmm7, OWORD PTR [rsp+16]
        vmovdqu	xmm8, OWORD PTR [rsp+32]
        vmovdqu	xmm9, OWORD PTR [rsp+48]
        add	rsp, 64
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
fe_cmov_table_avx2 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
fe_mul_avx2 PROC
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
        mov	rbx, QWORD PTR [rsi]
        ; Multiply
        ; A[0] * B[0]
        mov	rdx, QWORD PTR [rbp]
        mulx	r9, r8, rbx
        ; A[2] * B[0]
        mulx	r11, r10, QWORD PTR [rsi+16]
        ; A[1] * B[0]
        mulx	rcx, rax, QWORD PTR [rsi+8]
        xor	r15, r15
        adcx	r9, rax
        ; A[3] * B[1]
        mov	rdx, QWORD PTR [rbp+8]
        mulx	r13, r12, QWORD PTR [rsi+24]
        adcx	r10, rcx
        ; A[0] * B[1]
        mulx	rcx, rax, rbx
        adox	r9, rax
        ; A[2] * B[1]
        mulx	r14, rax, QWORD PTR [rsi+16]
        adox	r10, rcx
        adcx	r11, rax
        ; A[1] * B[2]
        mov	rdx, QWORD PTR [rbp+16]
        mulx	rcx, rax, QWORD PTR [rsi+8]
        adcx	r12, r14
        adox	r11, rax
        adcx	r13, r15
        adox	r12, rcx
        ; A[0] * B[2]
        mulx	rcx, rax, rbx
        adox	r13, r15
        xor	r14, r14
        adcx	r10, rax
        ; A[1] * B[1]
        mov	rdx, QWORD PTR [rbp+8]
        mulx	rax, rdx, QWORD PTR [rsi+8]
        adcx	r11, rcx
        adox	r10, rdx
        ; A[1] * B[3]
        mov	rdx, QWORD PTR [rbp+24]
        adox	r11, rax
        mulx	rcx, rax, QWORD PTR [rsi+8]
        adcx	r12, rax
        ; A[2] * B[2]
        mov	rdx, QWORD PTR [rbp+16]
        mulx	rax, rdx, QWORD PTR [rsi+16]
        adcx	r13, rcx
        adox	r12, rdx
        ; A[3] * B[3]
        mov	rdx, QWORD PTR [rbp+24]
        adox	r13, rax
        mulx	rcx, rax, QWORD PTR [rsi+24]
        adox	r14, r15
        adcx	r14, rax
        ; A[0] * B[3]
        mulx	rax, rdx, rbx
        adcx	r15, rcx
        xor	rcx, rcx
        adcx	r11, rdx
        ; A[3] * B[0]
        mov	rdx, QWORD PTR [rsi+24]
        adcx	r12, rax
        mulx	rax, rdx, QWORD PTR [rbp]
        adox	r11, rdx
        adox	r12, rax
        ; A[3] * B[2]
        mov	rdx, QWORD PTR [rsi+24]
        mulx	rax, rdx, QWORD PTR [rbp+16]
        adcx	r13, rdx
        ; A[2] * B[3]
        mov	rdx, QWORD PTR [rbp+24]
        adcx	r14, rax
        mulx	rdx, rax, QWORD PTR [rsi+16]
        adcx	r15, rcx
        adox	r13, rax
        adox	r14, rdx
        adox	r15, rcx
        mov	rdx, 38
        mulx	rax, r15, r15
        add	r11, r15
        adc	rax, 0
        mov	rcx, 9223372036854775807
        shld	rax, r11, 1
        imul	rax, rax, 19
        and	r11, rcx
        xor	rcx, rcx
        adox	r8, rax
        mulx	r12, rax, r12
        adcx	r8, rax
        adox	r9, r12
        mulx	r13, rax, r13
        adcx	r9, rax
        adox	r10, r13
        mulx	r14, rax, r14
        adcx	r10, rax
        adox	r11, r14
        adcx	r11, rcx
        mov	rcx, 9223372036854775807
        mov	rdx, r11
        sar	rdx, 63
        and	rdx, 19
        and	r11, rcx
        add	r8, rdx
        adc	r9, 0
        adc	r10, 0
        adc	r11, 0
        ; Store
        mov	QWORD PTR [rdi], r8
        mov	QWORD PTR [rdi+8], r9
        mov	QWORD PTR [rdi+16], r10
        mov	QWORD PTR [rdi+24], r11
        pop	rbp
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        pop	rbx
        ret
fe_mul_avx2 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
fe_sq_avx2 PROC
        push	rbx
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        mov	rdi, rcx
        mov	rsi, rdx
        ; Square
        mov	rdx, QWORD PTR [rsi]
        mov	rax, QWORD PTR [rsi+8]
        ; A[0] * A[1]
        mov	r15, rdx
        mulx	r10, r9, rax
        ; A[0] * A[3]
        mulx	r12, r11, QWORD PTR [rsi+24]
        ; A[2] * A[1]
        mov	rdx, QWORD PTR [rsi+16]
        mulx	rbx, rcx, rax
        xor	r8, r8
        adox	r11, rcx
        ; A[2] * A[3]
        mulx	r14, r13, QWORD PTR [rsi+24]
        adox	r12, rbx
        ; A[2] * A[0]
        mulx	rbx, rcx, r15
        adox	r13, r8
        adcx	r10, rcx
        adox	r14, r8
        ; A[1] * A[3]
        mov	rdx, rax
        mulx	rdx, rcx, QWORD PTR [rsi+24]
        adcx	r11, rbx
        adcx	r12, rcx
        adcx	r13, rdx
        adcx	r14, r8
        ; A[0] * A[0]
        mov	rdx, r15
        mulx	rcx, r8, rdx
        xor	r15, r15
        adcx	r9, r9
        ; A[1] * A[1]
        mov	rdx, rax
        adox	r9, rcx
        mulx	rbx, rcx, rdx
        adcx	r10, r10
        adox	r10, rcx
        adcx	r11, r11
        ; A[2] * A[2]
        mov	rdx, QWORD PTR [rsi+16]
        adox	r11, rbx
        mulx	rcx, rbx, rdx
        adcx	r12, r12
        adox	r12, rbx
        adcx	r13, r13
        ; A[3] * A[3]
        mov	rdx, QWORD PTR [rsi+24]
        adox	r13, rcx
        mulx	rbx, rcx, rdx
        adcx	r14, r14
        adox	r14, rcx
        adcx	r15, r15
        adox	r15, rbx
        mov	rdx, 38
        mulx	rbx, r15, r15
        add	r11, r15
        adc	rbx, 0
        mov	rcx, 9223372036854775807
        shld	rbx, r11, 1
        imul	rbx, rbx, 19
        and	r11, rcx
        xor	rcx, rcx
        adox	r8, rbx
        mulx	r12, rbx, r12
        adcx	r8, rbx
        adox	r9, r12
        mulx	r13, rbx, r13
        adcx	r9, rbx
        adox	r10, r13
        mulx	r14, rbx, r14
        adcx	r10, rbx
        adox	r11, r14
        adcx	r11, rcx
        mov	rcx, 9223372036854775807
        mov	rdx, r11
        sar	rdx, 63
        and	rdx, 19
        and	r11, rcx
        add	r8, rdx
        adc	r9, 0
        adc	r10, 0
        adc	r11, 0
        ; Store
        mov	QWORD PTR [rdi], r8
        mov	QWORD PTR [rdi+8], r9
        mov	QWORD PTR [rdi+16], r10
        mov	QWORD PTR [rdi+24], r11
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        pop	rbx
        ret
fe_sq_avx2 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
fe_sq_n_avx2 PROC
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
L_fe_sq_n_avx2:
        ; Square
        mov	rdx, QWORD PTR [rsi]
        mov	rax, QWORD PTR [rsi+8]
        ; A[0] * A[1]
        mov	r15, rdx
        mulx	r10, r9, rax
        ; A[0] * A[3]
        mulx	r12, r11, QWORD PTR [rsi+24]
        ; A[2] * A[1]
        mov	rdx, QWORD PTR [rsi+16]
        mulx	rbx, rcx, rax
        xor	r8, r8
        adox	r11, rcx
        ; A[2] * A[3]
        mulx	r14, r13, QWORD PTR [rsi+24]
        adox	r12, rbx
        ; A[2] * A[0]
        mulx	rbx, rcx, r15
        adox	r13, r8
        adcx	r10, rcx
        adox	r14, r8
        ; A[1] * A[3]
        mov	rdx, rax
        mulx	rdx, rcx, QWORD PTR [rsi+24]
        adcx	r11, rbx
        adcx	r12, rcx
        adcx	r13, rdx
        adcx	r14, r8
        ; A[0] * A[0]
        mov	rdx, r15
        mulx	rcx, r8, rdx
        xor	r15, r15
        adcx	r9, r9
        ; A[1] * A[1]
        mov	rdx, rax
        adox	r9, rcx
        mulx	rbx, rcx, rdx
        adcx	r10, r10
        adox	r10, rcx
        adcx	r11, r11
        ; A[2] * A[2]
        mov	rdx, QWORD PTR [rsi+16]
        adox	r11, rbx
        mulx	rcx, rbx, rdx
        adcx	r12, r12
        adox	r12, rbx
        adcx	r13, r13
        ; A[3] * A[3]
        mov	rdx, QWORD PTR [rsi+24]
        adox	r13, rcx
        mulx	rbx, rcx, rdx
        adcx	r14, r14
        adox	r14, rcx
        adcx	r15, r15
        adox	r15, rbx
        mov	rdx, 38
        mulx	rbx, r15, r15
        add	r11, r15
        adc	rbx, 0
        mov	rcx, 9223372036854775807
        shld	rbx, r11, 1
        imul	rbx, rbx, 19
        and	r11, rcx
        xor	rcx, rcx
        adox	r8, rbx
        mulx	r12, rbx, r12
        adcx	r8, rbx
        adox	r9, r12
        mulx	r13, rbx, r13
        adcx	r9, rbx
        adox	r10, r13
        mulx	r14, rbx, r14
        adcx	r10, rbx
        adox	r11, r14
        adcx	r11, rcx
        ; Store
        mov	QWORD PTR [rdi], r8
        mov	QWORD PTR [rdi+8], r9
        mov	QWORD PTR [rdi+16], r10
        mov	QWORD PTR [rdi+24], r11
        dec	bpl
        jnz	L_fe_sq_n_avx2
        pop	rbp
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        pop	rbx
        ret
fe_sq_n_avx2 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
fe_mul121666_avx2 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        mov	rax, rdx
        mov	rdx, 121666
        mulx	r15, r8, QWORD PTR [rax]
        mulx	r14, r9, QWORD PTR [rax+8]
        mulx	r13, r10, QWORD PTR [rax+16]
        add	r9, r15
        mulx	r12, r11, QWORD PTR [rax+24]
        adc	r10, r14
        adc	r11, r13
        adc	r12, 0
        shld	r12, r11, 1
        btr	r11, 63
        imul	r12, r12, 19
        add	r8, r12
        adc	r9, 0
        adc	r10, 0
        adc	r11, 0
        mov	QWORD PTR [rcx], r8
        mov	QWORD PTR [rcx+8], r9
        mov	QWORD PTR [rcx+16], r10
        mov	QWORD PTR [rcx+24], r11
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
fe_mul121666_avx2 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
fe_invert_avx2 PROC
        sub	rsp, 144
        ; Invert
        mov	QWORD PTR [rsp+128], rcx
        mov	QWORD PTR [rsp+136], rdx
        mov	rcx, rsp
        mov	rdx, QWORD PTR [rsp+136]
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+32]
        mov	rdx, rsp
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+32]
        mov	rdx, QWORD PTR [rsp+136]
        lea	r8, QWORD PTR [rsp+32]
        call	fe_mul_avx2
        mov	rcx, rsp
        mov	rdx, rsp
        lea	r8, QWORD PTR [rsp+32]
        call	fe_mul_avx2
        lea	rcx, QWORD PTR [rsp+64]
        mov	rdx, rsp
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        lea	r8, QWORD PTR [rsp+64]
        call	fe_mul_avx2
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+32]
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        mov	r8, 4
        call	fe_sq_n_avx2
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+64]
        lea	r8, QWORD PTR [rsp+32]
        call	fe_mul_avx2
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+32]
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        mov	r8, 9
        call	fe_sq_n_avx2
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        lea	r8, QWORD PTR [rsp+32]
        call	fe_mul_avx2
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+64]
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 19
        call	fe_sq_n_avx2
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        call	fe_mul_avx2
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        mov	r8, 9
        call	fe_sq_n_avx2
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+64]
        lea	r8, QWORD PTR [rsp+32]
        call	fe_mul_avx2
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+32]
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        mov	r8, 49
        call	fe_sq_n_avx2
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        lea	r8, QWORD PTR [rsp+32]
        call	fe_mul_avx2
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+64]
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 99
        call	fe_sq_n_avx2
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        call	fe_mul_avx2
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        mov	r8, 49
        call	fe_sq_n_avx2
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+64]
        lea	r8, QWORD PTR [rsp+32]
        call	fe_mul_avx2
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, 4
        call	fe_sq_n_avx2
        mov	rcx, QWORD PTR [rsp+128]
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, rsp
        call	fe_mul_avx2
        mov	rdx, QWORD PTR [rsp+136]
        mov	rcx, QWORD PTR [rsp+128]
        add	rsp, 144
        ret
fe_invert_avx2 ENDP
_TEXT ENDS
IFDEF WOLFSSL_CURVE25519_NOT_USE_ED25519
_DATA SEGMENT
ALIGN 16
L_curve25519_base_avx2_x2 QWORD 5cae469cdd684efbh, 8f3f5ced1e350b5ch
        QWORD 0d9750c687d157114h, 20d342d51873f1b7h
ptr_L_curve25519_base_avx2_x2 QWORD L_curve25519_base_avx2_x2
_DATA ENDS
_TEXT SEGMENT READONLY PARA
curve25519_base_avx2 PROC
        push	rbx
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbp
        mov	r8, rcx
        mov	r9, rdx
        sub	rsp, 176
        mov	QWORD PTR [rsp+168], 0
        mov	QWORD PTR [rsp+160], r8
        ; Set base point x
        mov	QWORD PTR [r8], 9
        mov	QWORD PTR [r8+8], 0
        mov	QWORD PTR [r8+16], 0
        mov	QWORD PTR [r8+24], 0
        ; Set one
        mov	QWORD PTR [rsp], 1
        mov	QWORD PTR [rsp+8], 0
        mov	QWORD PTR [rsp+16], 0
        mov	QWORD PTR [rsp+24], 0
        mov	r10, QWORD PTR [ptr_L_curve25519_base_avx2_x2]
        mov	r11, QWORD PTR [ptr_L_curve25519_base_avx2_x2+8]
        mov	r12, QWORD PTR [ptr_L_curve25519_base_avx2_x2+16]
        mov	r13, QWORD PTR [ptr_L_curve25519_base_avx2_x2+24]
        ; Set one
        mov	QWORD PTR [rsp+32], 1
        mov	QWORD PTR [rsp+40], 0
        mov	QWORD PTR [rsp+48], 0
        mov	QWORD PTR [rsp+56], 0
        mov	QWORD PTR [rsp+64], r10
        mov	QWORD PTR [rsp+72], r11
        mov	QWORD PTR [rsp+80], r12
        mov	QWORD PTR [rsp+88], r13
        mov	rbp, 253
L_curve25519_base_avx2_bits:
        mov	rax, QWORD PTR [rsp+168]
        mov	rbx, rbp
        mov	rcx, rbp
        shr	rbx, 6
        and	rcx, 63
        mov	rbx, QWORD PTR [r9+8*rbx]
        shr	rbx, cl
        and	rbx, 1
        xor	rax, rbx
        neg	rax
        ; Conditional Swap
        mov	r10, QWORD PTR [r8]
        mov	r11, QWORD PTR [r8+8]
        mov	r12, QWORD PTR [r8+16]
        mov	r13, QWORD PTR [r8+24]
        mov	r14, QWORD PTR [rsp]
        mov	r15, QWORD PTR [rsp+8]
        mov	rdi, QWORD PTR [rsp+16]
        mov	rsi, QWORD PTR [rsp+24]
        xor	r10, QWORD PTR [rsp+64]
        xor	r11, QWORD PTR [rsp+72]
        xor	r12, QWORD PTR [rsp+80]
        xor	r13, QWORD PTR [rsp+88]
        xor	r14, QWORD PTR [rsp+32]
        xor	r15, QWORD PTR [rsp+40]
        xor	rdi, QWORD PTR [rsp+48]
        xor	rsi, QWORD PTR [rsp+56]
        and	r10, rax
        and	r11, rax
        and	r12, rax
        and	r13, rax
        and	r14, rax
        and	r15, rax
        and	rdi, rax
        and	rsi, rax
        xor	QWORD PTR [r8], r10
        xor	QWORD PTR [r8+8], r11
        xor	QWORD PTR [r8+16], r12
        xor	QWORD PTR [r8+24], r13
        xor	QWORD PTR [rsp], r14
        xor	QWORD PTR [rsp+8], r15
        xor	QWORD PTR [rsp+16], rdi
        xor	QWORD PTR [rsp+24], rsi
        xor	QWORD PTR [rsp+64], r10
        xor	QWORD PTR [rsp+72], r11
        xor	QWORD PTR [rsp+80], r12
        xor	QWORD PTR [rsp+88], r13
        xor	QWORD PTR [rsp+32], r14
        xor	QWORD PTR [rsp+40], r15
        xor	QWORD PTR [rsp+48], rdi
        xor	QWORD PTR [rsp+56], rsi
        mov	QWORD PTR [rsp+168], rbx
        ; Add-Sub
        ; Add
        mov	r10, QWORD PTR [r8]
        mov	r11, QWORD PTR [r8+8]
        mov	r12, QWORD PTR [r8+16]
        mov	r13, QWORD PTR [r8+24]
        mov	r14, r10
        add	r10, QWORD PTR [rsp]
        mov	r15, r11
        adc	r11, QWORD PTR [rsp+8]
        mov	rdi, r12
        adc	r12, QWORD PTR [rsp+16]
        mov	rsi, r13
        adc	r13, QWORD PTR [rsp+24]
        mov	rbx, 0
        adc	rbx, 0
        shld	rbx, r13, 1
        imul	rbx, 19
        btr	r13, 63
        ;   Sub modulus (if overflow)
        add	r10, rbx
        adc	r11, 0
        adc	r12, 0
        adc	r13, 0
        ; Sub
        sub	r14, QWORD PTR [rsp]
        sbb	r15, QWORD PTR [rsp+8]
        sbb	rdi, QWORD PTR [rsp+16]
        sbb	rsi, QWORD PTR [rsp+24]
        sbb	rbx, rbx
        shld	rbx, rsi, 1
        imul	rbx, -19
        btr	rsi, 63
        ;   Add modulus (if underflow)
        sub	r14, rbx
        sbb	r15, 0
        sbb	rdi, 0
        sbb	rsi, 0
        mov	QWORD PTR [r8], r10
        mov	QWORD PTR [r8+8], r11
        mov	QWORD PTR [r8+16], r12
        mov	QWORD PTR [r8+24], r13
        mov	QWORD PTR [rsp+128], r14
        mov	QWORD PTR [rsp+136], r15
        mov	QWORD PTR [rsp+144], rdi
        mov	QWORD PTR [rsp+152], rsi
        ; Add-Sub
        ; Add
        mov	r10, QWORD PTR [rsp+64]
        mov	r11, QWORD PTR [rsp+72]
        mov	r12, QWORD PTR [rsp+80]
        mov	r13, QWORD PTR [rsp+88]
        mov	r14, r10
        add	r10, QWORD PTR [rsp+32]
        mov	r15, r11
        adc	r11, QWORD PTR [rsp+40]
        mov	rdi, r12
        adc	r12, QWORD PTR [rsp+48]
        mov	rsi, r13
        adc	r13, QWORD PTR [rsp+56]
        mov	rbx, 0
        adc	rbx, 0
        shld	rbx, r13, 1
        imul	rbx, 19
        btr	r13, 63
        ;   Sub modulus (if overflow)
        add	r10, rbx
        adc	r11, 0
        adc	r12, 0
        adc	r13, 0
        ; Sub
        sub	r14, QWORD PTR [rsp+32]
        sbb	r15, QWORD PTR [rsp+40]
        sbb	rdi, QWORD PTR [rsp+48]
        sbb	rsi, QWORD PTR [rsp+56]
        sbb	rbx, rbx
        shld	rbx, rsi, 1
        imul	rbx, -19
        btr	rsi, 63
        ;   Add modulus (if underflow)
        sub	r14, rbx
        sbb	r15, 0
        sbb	rdi, 0
        sbb	rsi, 0
        mov	QWORD PTR [rsp+32], r10
        mov	QWORD PTR [rsp+40], r11
        mov	QWORD PTR [rsp+48], r12
        mov	QWORD PTR [rsp+56], r13
        mov	QWORD PTR [rsp+96], r14
        mov	QWORD PTR [rsp+104], r15
        mov	QWORD PTR [rsp+112], rdi
        mov	QWORD PTR [rsp+120], rsi
        mov	rax, QWORD PTR [rsp+32]
        ; Multiply
        ; A[0] * B[0]
        mov	rdx, QWORD PTR [rsp+128]
        mulx	r11, r10, rax
        ; A[2] * B[0]
        mulx	r13, r12, QWORD PTR [rsp+48]
        ; A[1] * B[0]
        mulx	rbx, rcx, QWORD PTR [rsp+40]
        xor	rsi, rsi
        adcx	r11, rcx
        ; A[3] * B[1]
        mov	rdx, QWORD PTR [rsp+136]
        mulx	r15, r14, QWORD PTR [rsp+56]
        adcx	r12, rbx
        ; A[0] * B[1]
        mulx	rbx, rcx, rax
        adox	r11, rcx
        ; A[2] * B[1]
        mulx	rdi, rcx, QWORD PTR [rsp+48]
        adox	r12, rbx
        adcx	r13, rcx
        ; A[1] * B[2]
        mov	rdx, QWORD PTR [rsp+144]
        mulx	rbx, rcx, QWORD PTR [rsp+40]
        adcx	r14, rdi
        adox	r13, rcx
        adcx	r15, rsi
        adox	r14, rbx
        ; A[0] * B[2]
        mulx	rbx, rcx, rax
        adox	r15, rsi
        xor	rdi, rdi
        adcx	r12, rcx
        ; A[1] * B[1]
        mov	rdx, QWORD PTR [rsp+136]
        mulx	rcx, rdx, QWORD PTR [rsp+40]
        adcx	r13, rbx
        adox	r12, rdx
        ; A[1] * B[3]
        mov	rdx, QWORD PTR [rsp+152]
        adox	r13, rcx
        mulx	rbx, rcx, QWORD PTR [rsp+40]
        adcx	r14, rcx
        ; A[2] * B[2]
        mov	rdx, QWORD PTR [rsp+144]
        mulx	rcx, rdx, QWORD PTR [rsp+48]
        adcx	r15, rbx
        adox	r14, rdx
        ; A[3] * B[3]
        mov	rdx, QWORD PTR [rsp+152]
        adox	r15, rcx
        mulx	rbx, rcx, QWORD PTR [rsp+56]
        adox	rdi, rsi
        adcx	rdi, rcx
        ; A[0] * B[3]
        mulx	rcx, rdx, rax
        adcx	rsi, rbx
        xor	rbx, rbx
        adcx	r13, rdx
        ; A[3] * B[0]
        mov	rdx, QWORD PTR [rsp+56]
        adcx	r14, rcx
        mulx	rcx, rdx, QWORD PTR [rsp+128]
        adox	r13, rdx
        adox	r14, rcx
        ; A[3] * B[2]
        mov	rdx, QWORD PTR [rsp+56]
        mulx	rcx, rdx, QWORD PTR [rsp+144]
        adcx	r15, rdx
        ; A[2] * B[3]
        mov	rdx, QWORD PTR [rsp+152]
        adcx	rdi, rcx
        mulx	rdx, rcx, QWORD PTR [rsp+48]
        adcx	rsi, rbx
        adox	r15, rcx
        adox	rdi, rdx
        adox	rsi, rbx
        mov	rdx, 38
        mulx	rcx, rsi, rsi
        add	r13, rsi
        adc	rcx, 0
        mov	rbx, 9223372036854775807
        shld	rcx, r13, 1
        imul	rcx, rcx, 19
        and	r13, rbx
        xor	rbx, rbx
        adox	r10, rcx
        mulx	r14, rcx, r14
        adcx	r10, rcx
        adox	r11, r14
        mulx	r15, rcx, r15
        adcx	r11, rcx
        adox	r12, r15
        mulx	rdi, rcx, rdi
        adcx	r12, rcx
        adox	r13, rdi
        adcx	r13, rbx
        ; Store
        mov	QWORD PTR [rsp+32], r10
        mov	QWORD PTR [rsp+40], r11
        mov	QWORD PTR [rsp+48], r12
        mov	QWORD PTR [rsp+56], r13
        mov	rax, QWORD PTR [rsp+96]
        ; Multiply
        ; A[0] * B[0]
        mov	rdx, QWORD PTR [r8]
        mulx	r11, r10, rax
        ; A[2] * B[0]
        mulx	r13, r12, QWORD PTR [rsp+112]
        ; A[1] * B[0]
        mulx	rbx, rcx, QWORD PTR [rsp+104]
        xor	rsi, rsi
        adcx	r11, rcx
        ; A[3] * B[1]
        mov	rdx, QWORD PTR [r8+8]
        mulx	r15, r14, QWORD PTR [rsp+120]
        adcx	r12, rbx
        ; A[0] * B[1]
        mulx	rbx, rcx, rax
        adox	r11, rcx
        ; A[2] * B[1]
        mulx	rdi, rcx, QWORD PTR [rsp+112]
        adox	r12, rbx
        adcx	r13, rcx
        ; A[1] * B[2]
        mov	rdx, QWORD PTR [r8+16]
        mulx	rbx, rcx, QWORD PTR [rsp+104]
        adcx	r14, rdi
        adox	r13, rcx
        adcx	r15, rsi
        adox	r14, rbx
        ; A[0] * B[2]
        mulx	rbx, rcx, rax
        adox	r15, rsi
        xor	rdi, rdi
        adcx	r12, rcx
        ; A[1] * B[1]
        mov	rdx, QWORD PTR [r8+8]
        mulx	rcx, rdx, QWORD PTR [rsp+104]
        adcx	r13, rbx
        adox	r12, rdx
        ; A[1] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	r13, rcx
        mulx	rbx, rcx, QWORD PTR [rsp+104]
        adcx	r14, rcx
        ; A[2] * B[2]
        mov	rdx, QWORD PTR [r8+16]
        mulx	rcx, rdx, QWORD PTR [rsp+112]
        adcx	r15, rbx
        adox	r14, rdx
        ; A[3] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	r15, rcx
        mulx	rbx, rcx, QWORD PTR [rsp+120]
        adox	rdi, rsi
        adcx	rdi, rcx
        ; A[0] * B[3]
        mulx	rcx, rdx, rax
        adcx	rsi, rbx
        xor	rbx, rbx
        adcx	r13, rdx
        ; A[3] * B[0]
        mov	rdx, QWORD PTR [rsp+120]
        adcx	r14, rcx
        mulx	rcx, rdx, QWORD PTR [r8]
        adox	r13, rdx
        adox	r14, rcx
        ; A[3] * B[2]
        mov	rdx, QWORD PTR [rsp+120]
        mulx	rcx, rdx, QWORD PTR [r8+16]
        adcx	r15, rdx
        ; A[2] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adcx	rdi, rcx
        mulx	rdx, rcx, QWORD PTR [rsp+112]
        adcx	rsi, rbx
        adox	r15, rcx
        adox	rdi, rdx
        adox	rsi, rbx
        mov	rdx, 38
        mulx	rcx, rsi, rsi
        add	r13, rsi
        adc	rcx, 0
        mov	rbx, 9223372036854775807
        shld	rcx, r13, 1
        imul	rcx, rcx, 19
        and	r13, rbx
        xor	rbx, rbx
        adox	r10, rcx
        mulx	r14, rcx, r14
        adcx	r10, rcx
        adox	r11, r14
        mulx	r15, rcx, r15
        adcx	r11, rcx
        adox	r12, r15
        mulx	rdi, rcx, rdi
        adcx	r12, rcx
        adox	r13, rdi
        adcx	r13, rbx
        ; Store
        mov	QWORD PTR [rsp], r10
        mov	QWORD PTR [rsp+8], r11
        mov	QWORD PTR [rsp+16], r12
        mov	QWORD PTR [rsp+24], r13
        ; Square
        mov	rdx, QWORD PTR [rsp+128]
        mov	rax, QWORD PTR [rsp+136]
        ; A[0] * A[1]
        mov	rsi, rdx
        mulx	r12, r11, rax
        ; A[0] * A[3]
        mulx	r14, r13, QWORD PTR [rsp+152]
        ; A[2] * A[1]
        mov	rdx, QWORD PTR [rsp+144]
        mulx	rbx, rcx, rax
        xor	r10, r10
        adox	r13, rcx
        ; A[2] * A[3]
        mulx	rdi, r15, QWORD PTR [rsp+152]
        adox	r14, rbx
        ; A[2] * A[0]
        mulx	rbx, rcx, rsi
        adox	r15, r10
        adcx	r12, rcx
        adox	rdi, r10
        ; A[1] * A[3]
        mov	rdx, rax
        mulx	rdx, rcx, QWORD PTR [rsp+152]
        adcx	r13, rbx
        adcx	r14, rcx
        adcx	r15, rdx
        adcx	rdi, r10
        ; A[0] * A[0]
        mov	rdx, rsi
        mulx	rcx, r10, rdx
        xor	rsi, rsi
        adcx	r11, r11
        ; A[1] * A[1]
        mov	rdx, rax
        adox	r11, rcx
        mulx	rbx, rcx, rdx
        adcx	r12, r12
        adox	r12, rcx
        adcx	r13, r13
        ; A[2] * A[2]
        mov	rdx, QWORD PTR [rsp+144]
        adox	r13, rbx
        mulx	rcx, rbx, rdx
        adcx	r14, r14
        adox	r14, rbx
        adcx	r15, r15
        ; A[3] * A[3]
        mov	rdx, QWORD PTR [rsp+152]
        adox	r15, rcx
        mulx	rbx, rcx, rdx
        adcx	rdi, rdi
        adox	rdi, rcx
        adcx	rsi, rsi
        adox	rsi, rbx
        mov	rdx, 38
        mulx	rbx, rsi, rsi
        add	r13, rsi
        adc	rbx, 0
        mov	rcx, 9223372036854775807
        shld	rbx, r13, 1
        imul	rbx, rbx, 19
        and	r13, rcx
        xor	rcx, rcx
        adox	r10, rbx
        mulx	r14, rbx, r14
        adcx	r10, rbx
        adox	r11, r14
        mulx	r15, rbx, r15
        adcx	r11, rbx
        adox	r12, r15
        mulx	rdi, rbx, rdi
        adcx	r12, rbx
        adox	r13, rdi
        adcx	r13, rcx
        ; Store
        mov	QWORD PTR [rsp+96], r10
        mov	QWORD PTR [rsp+104], r11
        mov	QWORD PTR [rsp+112], r12
        mov	QWORD PTR [rsp+120], r13
        ; Square
        mov	rdx, QWORD PTR [r8]
        mov	rax, QWORD PTR [r8+8]
        ; A[0] * A[1]
        mov	rsi, rdx
        mulx	r12, r11, rax
        ; A[0] * A[3]
        mulx	r14, r13, QWORD PTR [r8+24]
        ; A[2] * A[1]
        mov	rdx, QWORD PTR [r8+16]
        mulx	rbx, rcx, rax
        xor	r10, r10
        adox	r13, rcx
        ; A[2] * A[3]
        mulx	rdi, r15, QWORD PTR [r8+24]
        adox	r14, rbx
        ; A[2] * A[0]
        mulx	rbx, rcx, rsi
        adox	r15, r10
        adcx	r12, rcx
        adox	rdi, r10
        ; A[1] * A[3]
        mov	rdx, rax
        mulx	rdx, rcx, QWORD PTR [r8+24]
        adcx	r13, rbx
        adcx	r14, rcx
        adcx	r15, rdx
        adcx	rdi, r10
        ; A[0] * A[0]
        mov	rdx, rsi
        mulx	rcx, r10, rdx
        xor	rsi, rsi
        adcx	r11, r11
        ; A[1] * A[1]
        mov	rdx, rax
        adox	r11, rcx
        mulx	rbx, rcx, rdx
        adcx	r12, r12
        adox	r12, rcx
        adcx	r13, r13
        ; A[2] * A[2]
        mov	rdx, QWORD PTR [r8+16]
        adox	r13, rbx
        mulx	rcx, rbx, rdx
        adcx	r14, r14
        adox	r14, rbx
        adcx	r15, r15
        ; A[3] * A[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	r15, rcx
        mulx	rbx, rcx, rdx
        adcx	rdi, rdi
        adox	rdi, rcx
        adcx	rsi, rsi
        adox	rsi, rbx
        mov	rdx, 38
        mulx	rbx, rsi, rsi
        add	r13, rsi
        adc	rbx, 0
        mov	rcx, 9223372036854775807
        shld	rbx, r13, 1
        imul	rbx, rbx, 19
        and	r13, rcx
        xor	rcx, rcx
        adox	r10, rbx
        mulx	r14, rbx, r14
        adcx	r10, rbx
        adox	r11, r14
        mulx	r15, rbx, r15
        adcx	r11, rbx
        adox	r12, r15
        mulx	rdi, rbx, rdi
        adcx	r12, rbx
        adox	r13, rdi
        adcx	r13, rcx
        ; Store
        mov	QWORD PTR [rsp+128], r10
        mov	QWORD PTR [rsp+136], r11
        mov	QWORD PTR [rsp+144], r12
        mov	QWORD PTR [rsp+152], r13
        ; Add-Sub
        ; Add
        mov	r10, QWORD PTR [rsp]
        mov	r11, QWORD PTR [rsp+8]
        mov	r12, QWORD PTR [rsp+16]
        mov	r13, QWORD PTR [rsp+24]
        mov	r14, r10
        add	r10, QWORD PTR [rsp+32]
        mov	r15, r11
        adc	r11, QWORD PTR [rsp+40]
        mov	rdi, r12
        adc	r12, QWORD PTR [rsp+48]
        mov	rsi, r13
        adc	r13, QWORD PTR [rsp+56]
        mov	rbx, 0
        adc	rbx, 0
        shld	rbx, r13, 1
        imul	rbx, 19
        btr	r13, 63
        ;   Sub modulus (if overflow)
        add	r10, rbx
        adc	r11, 0
        adc	r12, 0
        adc	r13, 0
        ; Sub
        sub	r14, QWORD PTR [rsp+32]
        sbb	r15, QWORD PTR [rsp+40]
        sbb	rdi, QWORD PTR [rsp+48]
        sbb	rsi, QWORD PTR [rsp+56]
        sbb	rbx, rbx
        shld	rbx, rsi, 1
        imul	rbx, -19
        btr	rsi, 63
        ;   Add modulus (if underflow)
        sub	r14, rbx
        sbb	r15, 0
        sbb	rdi, 0
        sbb	rsi, 0
        mov	QWORD PTR [rsp+64], r10
        mov	QWORD PTR [rsp+72], r11
        mov	QWORD PTR [rsp+80], r12
        mov	QWORD PTR [rsp+88], r13
        mov	QWORD PTR [rsp+32], r14
        mov	QWORD PTR [rsp+40], r15
        mov	QWORD PTR [rsp+48], rdi
        mov	QWORD PTR [rsp+56], rsi
        mov	rax, QWORD PTR [rsp+128]
        ; Multiply
        ; A[0] * B[0]
        mov	rdx, QWORD PTR [rsp+96]
        mulx	r11, r10, rax
        ; A[2] * B[0]
        mulx	r13, r12, QWORD PTR [rsp+144]
        ; A[1] * B[0]
        mulx	rbx, rcx, QWORD PTR [rsp+136]
        xor	rsi, rsi
        adcx	r11, rcx
        ; A[3] * B[1]
        mov	rdx, QWORD PTR [rsp+104]
        mulx	r15, r14, QWORD PTR [rsp+152]
        adcx	r12, rbx
        ; A[0] * B[1]
        mulx	rbx, rcx, rax
        adox	r11, rcx
        ; A[2] * B[1]
        mulx	rdi, rcx, QWORD PTR [rsp+144]
        adox	r12, rbx
        adcx	r13, rcx
        ; A[1] * B[2]
        mov	rdx, QWORD PTR [rsp+112]
        mulx	rbx, rcx, QWORD PTR [rsp+136]
        adcx	r14, rdi
        adox	r13, rcx
        adcx	r15, rsi
        adox	r14, rbx
        ; A[0] * B[2]
        mulx	rbx, rcx, rax
        adox	r15, rsi
        xor	rdi, rdi
        adcx	r12, rcx
        ; A[1] * B[1]
        mov	rdx, QWORD PTR [rsp+104]
        mulx	rcx, rdx, QWORD PTR [rsp+136]
        adcx	r13, rbx
        adox	r12, rdx
        ; A[1] * B[3]
        mov	rdx, QWORD PTR [rsp+120]
        adox	r13, rcx
        mulx	rbx, rcx, QWORD PTR [rsp+136]
        adcx	r14, rcx
        ; A[2] * B[2]
        mov	rdx, QWORD PTR [rsp+112]
        mulx	rcx, rdx, QWORD PTR [rsp+144]
        adcx	r15, rbx
        adox	r14, rdx
        ; A[3] * B[3]
        mov	rdx, QWORD PTR [rsp+120]
        adox	r15, rcx
        mulx	rbx, rcx, QWORD PTR [rsp+152]
        adox	rdi, rsi
        adcx	rdi, rcx
        ; A[0] * B[3]
        mulx	rcx, rdx, rax
        adcx	rsi, rbx
        xor	rbx, rbx
        adcx	r13, rdx
        ; A[3] * B[0]
        mov	rdx, QWORD PTR [rsp+152]
        adcx	r14, rcx
        mulx	rcx, rdx, QWORD PTR [rsp+96]
        adox	r13, rdx
        adox	r14, rcx
        ; A[3] * B[2]
        mov	rdx, QWORD PTR [rsp+152]
        mulx	rcx, rdx, QWORD PTR [rsp+112]
        adcx	r15, rdx
        ; A[2] * B[3]
        mov	rdx, QWORD PTR [rsp+120]
        adcx	rdi, rcx
        mulx	rdx, rcx, QWORD PTR [rsp+144]
        adcx	rsi, rbx
        adox	r15, rcx
        adox	rdi, rdx
        adox	rsi, rbx
        mov	rdx, 38
        mulx	rcx, rsi, rsi
        add	r13, rsi
        adc	rcx, 0
        mov	rbx, 9223372036854775807
        shld	rcx, r13, 1
        imul	rcx, rcx, 19
        and	r13, rbx
        xor	rbx, rbx
        adox	r10, rcx
        mulx	r14, rcx, r14
        adcx	r10, rcx
        adox	r11, r14
        mulx	r15, rcx, r15
        adcx	r11, rcx
        adox	r12, r15
        mulx	rdi, rcx, rdi
        adcx	r12, rcx
        adox	r13, rdi
        adcx	r13, rbx
        ; Store
        mov	QWORD PTR [r8], r10
        mov	QWORD PTR [r8+8], r11
        mov	QWORD PTR [r8+16], r12
        mov	QWORD PTR [r8+24], r13
        ; Sub
        mov	r10, QWORD PTR [rsp+128]
        mov	r11, QWORD PTR [rsp+136]
        mov	r12, QWORD PTR [rsp+144]
        mov	r13, QWORD PTR [rsp+152]
        sub	r10, QWORD PTR [rsp+96]
        sbb	r11, QWORD PTR [rsp+104]
        sbb	r12, QWORD PTR [rsp+112]
        sbb	r13, QWORD PTR [rsp+120]
        sbb	rbx, rbx
        shld	rbx, r13, 1
        imul	rbx, -19
        btr	r13, 63
        ;   Add modulus (if underflow)
        sub	r10, rbx
        sbb	r11, 0
        sbb	r12, 0
        sbb	r13, 0
        mov	QWORD PTR [rsp+128], r10
        mov	QWORD PTR [rsp+136], r11
        mov	QWORD PTR [rsp+144], r12
        mov	QWORD PTR [rsp+152], r13
        ; Square
        mov	rdx, QWORD PTR [rsp+32]
        mov	rax, QWORD PTR [rsp+40]
        ; A[0] * A[1]
        mov	rsi, rdx
        mulx	r12, r11, rax
        ; A[0] * A[3]
        mulx	r14, r13, QWORD PTR [rsp+56]
        ; A[2] * A[1]
        mov	rdx, QWORD PTR [rsp+48]
        mulx	rbx, rcx, rax
        xor	r10, r10
        adox	r13, rcx
        ; A[2] * A[3]
        mulx	rdi, r15, QWORD PTR [rsp+56]
        adox	r14, rbx
        ; A[2] * A[0]
        mulx	rbx, rcx, rsi
        adox	r15, r10
        adcx	r12, rcx
        adox	rdi, r10
        ; A[1] * A[3]
        mov	rdx, rax
        mulx	rdx, rcx, QWORD PTR [rsp+56]
        adcx	r13, rbx
        adcx	r14, rcx
        adcx	r15, rdx
        adcx	rdi, r10
        ; A[0] * A[0]
        mov	rdx, rsi
        mulx	rcx, r10, rdx
        xor	rsi, rsi
        adcx	r11, r11
        ; A[1] * A[1]
        mov	rdx, rax
        adox	r11, rcx
        mulx	rbx, rcx, rdx
        adcx	r12, r12
        adox	r12, rcx
        adcx	r13, r13
        ; A[2] * A[2]
        mov	rdx, QWORD PTR [rsp+48]
        adox	r13, rbx
        mulx	rcx, rbx, rdx
        adcx	r14, r14
        adox	r14, rbx
        adcx	r15, r15
        ; A[3] * A[3]
        mov	rdx, QWORD PTR [rsp+56]
        adox	r15, rcx
        mulx	rbx, rcx, rdx
        adcx	rdi, rdi
        adox	rdi, rcx
        adcx	rsi, rsi
        adox	rsi, rbx
        mov	rdx, 38
        mulx	rbx, rsi, rsi
        add	r13, rsi
        adc	rbx, 0
        mov	rcx, 9223372036854775807
        shld	rbx, r13, 1
        imul	rbx, rbx, 19
        and	r13, rcx
        xor	rcx, rcx
        adox	r10, rbx
        mulx	r14, rbx, r14
        adcx	r10, rbx
        adox	r11, r14
        mulx	r15, rbx, r15
        adcx	r11, rbx
        adox	r12, r15
        mulx	rdi, rbx, rdi
        adcx	r12, rbx
        adox	r13, rdi
        adcx	r13, rcx
        ; Store
        mov	QWORD PTR [rsp+32], r10
        mov	QWORD PTR [rsp+40], r11
        mov	QWORD PTR [rsp+48], r12
        mov	QWORD PTR [rsp+56], r13
        ; Square
        mov	rdx, QWORD PTR [rsp+64]
        mov	rax, QWORD PTR [rsp+72]
        ; A[0] * A[1]
        mov	rsi, rdx
        mulx	r12, r11, rax
        ; A[0] * A[3]
        mulx	r14, r13, QWORD PTR [rsp+88]
        ; A[2] * A[1]
        mov	rdx, QWORD PTR [rsp+80]
        mulx	rbx, rcx, rax
        xor	r10, r10
        adox	r13, rcx
        ; A[2] * A[3]
        mulx	rdi, r15, QWORD PTR [rsp+88]
        adox	r14, rbx
        ; A[2] * A[0]
        mulx	rbx, rcx, rsi
        adox	r15, r10
        adcx	r12, rcx
        adox	rdi, r10
        ; A[1] * A[3]
        mov	rdx, rax
        mulx	rdx, rcx, QWORD PTR [rsp+88]
        adcx	r13, rbx
        adcx	r14, rcx
        adcx	r15, rdx
        adcx	rdi, r10
        ; A[0] * A[0]
        mov	rdx, rsi
        mulx	rcx, r10, rdx
        xor	rsi, rsi
        adcx	r11, r11
        ; A[1] * A[1]
        mov	rdx, rax
        adox	r11, rcx
        mulx	rbx, rcx, rdx
        adcx	r12, r12
        adox	r12, rcx
        adcx	r13, r13
        ; A[2] * A[2]
        mov	rdx, QWORD PTR [rsp+80]
        adox	r13, rbx
        mulx	rcx, rbx, rdx
        adcx	r14, r14
        adox	r14, rbx
        adcx	r15, r15
        ; A[3] * A[3]
        mov	rdx, QWORD PTR [rsp+88]
        adox	r15, rcx
        mulx	rbx, rcx, rdx
        adcx	rdi, rdi
        adox	rdi, rcx
        adcx	rsi, rsi
        adox	rsi, rbx
        mov	rdx, 38
        mulx	rbx, rsi, rsi
        add	r13, rsi
        adc	rbx, 0
        mov	rcx, 9223372036854775807
        shld	rbx, r13, 1
        imul	rbx, rbx, 19
        and	r13, rcx
        xor	rcx, rcx
        adox	r10, rbx
        mulx	r14, rbx, r14
        adcx	r10, rbx
        adox	r11, r14
        mulx	r15, rbx, r15
        adcx	r11, rbx
        adox	r12, r15
        mulx	rdi, rbx, rdi
        adcx	r12, rbx
        adox	r13, rdi
        adcx	r13, rcx
        ; Store
        mov	QWORD PTR [rsp+64], r10
        mov	QWORD PTR [rsp+72], r11
        mov	QWORD PTR [rsp+80], r12
        mov	QWORD PTR [rsp+88], r13
        mov	rdx, 121666
        mulx	rsi, r10, QWORD PTR [rsp+128]
        mulx	rdi, r11, QWORD PTR [rsp+136]
        mulx	r15, r12, QWORD PTR [rsp+144]
        add	r11, rsi
        mulx	r14, r13, QWORD PTR [rsp+152]
        adc	r12, rdi
        adc	r13, r15
        adc	r14, 0
        add	r10, QWORD PTR [rsp+96]
        adc	r11, QWORD PTR [rsp+104]
        adc	r12, QWORD PTR [rsp+112]
        adc	r13, QWORD PTR [rsp+120]
        adc	r14, 0
        shld	r14, r13, 1
        btr	r13, 63
        imul	r14, r14, 19
        add	r10, r14
        adc	r11, 0
        adc	r12, 0
        adc	r13, 0
        mov	QWORD PTR [rsp+96], r10
        mov	QWORD PTR [rsp+104], r11
        mov	QWORD PTR [rsp+112], r12
        mov	QWORD PTR [rsp+120], r13
        mov	rdx, 9
        mulx	rsi, r10, QWORD PTR [rsp+32]
        mulx	rdi, r11, QWORD PTR [rsp+40]
        mulx	r15, r12, QWORD PTR [rsp+48]
        add	r11, rsi
        mulx	r14, r13, QWORD PTR [rsp+56]
        adc	r12, rdi
        adc	r13, r15
        adc	r14, 0
        shld	r14, r13, 1
        btr	r13, 63
        imul	r14, r14, 19
        add	r10, r14
        adc	r11, 0
        adc	r12, 0
        adc	r13, 0
        mov	QWORD PTR [rsp+32], r10
        mov	QWORD PTR [rsp+40], r11
        mov	QWORD PTR [rsp+48], r12
        mov	QWORD PTR [rsp+56], r13
        mov	rax, QWORD PTR [rsp+128]
        ; Multiply
        ; A[0] * B[0]
        mov	rdx, QWORD PTR [rsp+96]
        mulx	r11, r10, rax
        ; A[2] * B[0]
        mulx	r13, r12, QWORD PTR [rsp+144]
        ; A[1] * B[0]
        mulx	rbx, rcx, QWORD PTR [rsp+136]
        xor	rsi, rsi
        adcx	r11, rcx
        ; A[3] * B[1]
        mov	rdx, QWORD PTR [rsp+104]
        mulx	r15, r14, QWORD PTR [rsp+152]
        adcx	r12, rbx
        ; A[0] * B[1]
        mulx	rbx, rcx, rax
        adox	r11, rcx
        ; A[2] * B[1]
        mulx	rdi, rcx, QWORD PTR [rsp+144]
        adox	r12, rbx
        adcx	r13, rcx
        ; A[1] * B[2]
        mov	rdx, QWORD PTR [rsp+112]
        mulx	rbx, rcx, QWORD PTR [rsp+136]
        adcx	r14, rdi
        adox	r13, rcx
        adcx	r15, rsi
        adox	r14, rbx
        ; A[0] * B[2]
        mulx	rbx, rcx, rax
        adox	r15, rsi
        xor	rdi, rdi
        adcx	r12, rcx
        ; A[1] * B[1]
        mov	rdx, QWORD PTR [rsp+104]
        mulx	rcx, rdx, QWORD PTR [rsp+136]
        adcx	r13, rbx
        adox	r12, rdx
        ; A[1] * B[3]
        mov	rdx, QWORD PTR [rsp+120]
        adox	r13, rcx
        mulx	rbx, rcx, QWORD PTR [rsp+136]
        adcx	r14, rcx
        ; A[2] * B[2]
        mov	rdx, QWORD PTR [rsp+112]
        mulx	rcx, rdx, QWORD PTR [rsp+144]
        adcx	r15, rbx
        adox	r14, rdx
        ; A[3] * B[3]
        mov	rdx, QWORD PTR [rsp+120]
        adox	r15, rcx
        mulx	rbx, rcx, QWORD PTR [rsp+152]
        adox	rdi, rsi
        adcx	rdi, rcx
        ; A[0] * B[3]
        mulx	rcx, rdx, rax
        adcx	rsi, rbx
        xor	rbx, rbx
        adcx	r13, rdx
        ; A[3] * B[0]
        mov	rdx, QWORD PTR [rsp+152]
        adcx	r14, rcx
        mulx	rcx, rdx, QWORD PTR [rsp+96]
        adox	r13, rdx
        adox	r14, rcx
        ; A[3] * B[2]
        mov	rdx, QWORD PTR [rsp+152]
        mulx	rcx, rdx, QWORD PTR [rsp+112]
        adcx	r15, rdx
        ; A[2] * B[3]
        mov	rdx, QWORD PTR [rsp+120]
        adcx	rdi, rcx
        mulx	rdx, rcx, QWORD PTR [rsp+144]
        adcx	rsi, rbx
        adox	r15, rcx
        adox	rdi, rdx
        adox	rsi, rbx
        mov	rdx, 38
        mulx	rcx, rsi, rsi
        add	r13, rsi
        adc	rcx, 0
        mov	rbx, 9223372036854775807
        shld	rcx, r13, 1
        imul	rcx, rcx, 19
        and	r13, rbx
        xor	rbx, rbx
        adox	r10, rcx
        mulx	r14, rcx, r14
        adcx	r10, rcx
        adox	r11, r14
        mulx	r15, rcx, r15
        adcx	r11, rcx
        adox	r12, r15
        mulx	rdi, rcx, rdi
        adcx	r12, rcx
        adox	r13, rdi
        adcx	r13, rbx
        ; Store
        mov	QWORD PTR [rsp], r10
        mov	QWORD PTR [rsp+8], r11
        mov	QWORD PTR [rsp+16], r12
        mov	QWORD PTR [rsp+24], r13
        dec	rbp
        cmp	rbp, 3
        jge	L_curve25519_base_avx2_bits
        mov	rax, QWORD PTR [rsp+168]
        neg	rax
        ; Conditional Swap
        mov	r10, QWORD PTR [r8]
        mov	r11, QWORD PTR [r8+8]
        mov	r12, QWORD PTR [r8+16]
        mov	r13, QWORD PTR [r8+24]
        mov	r14, QWORD PTR [rsp]
        mov	r15, QWORD PTR [rsp+8]
        mov	rdi, QWORD PTR [rsp+16]
        mov	rsi, QWORD PTR [rsp+24]
        xor	r10, QWORD PTR [rsp+64]
        xor	r11, QWORD PTR [rsp+72]
        xor	r12, QWORD PTR [rsp+80]
        xor	r13, QWORD PTR [rsp+88]
        xor	r14, QWORD PTR [rsp+32]
        xor	r15, QWORD PTR [rsp+40]
        xor	rdi, QWORD PTR [rsp+48]
        xor	rsi, QWORD PTR [rsp+56]
        and	r10, rax
        and	r11, rax
        and	r12, rax
        and	r13, rax
        and	r14, rax
        and	r15, rax
        and	rdi, rax
        and	rsi, rax
        xor	QWORD PTR [r8], r10
        xor	QWORD PTR [r8+8], r11
        xor	QWORD PTR [r8+16], r12
        xor	QWORD PTR [r8+24], r13
        xor	QWORD PTR [rsp], r14
        xor	QWORD PTR [rsp+8], r15
        xor	QWORD PTR [rsp+16], rdi
        xor	QWORD PTR [rsp+24], rsi
        xor	QWORD PTR [rsp+64], r10
        xor	QWORD PTR [rsp+72], r11
        xor	QWORD PTR [rsp+80], r12
        xor	QWORD PTR [rsp+88], r13
        xor	QWORD PTR [rsp+32], r14
        xor	QWORD PTR [rsp+40], r15
        xor	QWORD PTR [rsp+48], rdi
        xor	QWORD PTR [rsp+56], rsi
L_curve25519_base_avx2_last_3:
        ; Add-Sub
        ; Add
        mov	r10, QWORD PTR [r8]
        mov	r11, QWORD PTR [r8+8]
        mov	r12, QWORD PTR [r8+16]
        mov	r13, QWORD PTR [r8+24]
        mov	r14, r10
        add	r10, QWORD PTR [rsp]
        mov	r15, r11
        adc	r11, QWORD PTR [rsp+8]
        mov	rdi, r12
        adc	r12, QWORD PTR [rsp+16]
        mov	rsi, r13
        adc	r13, QWORD PTR [rsp+24]
        mov	rbx, 0
        adc	rbx, 0
        shld	rbx, r13, 1
        imul	rbx, 19
        btr	r13, 63
        ;   Sub modulus (if overflow)
        add	r10, rbx
        adc	r11, 0
        adc	r12, 0
        adc	r13, 0
        ; Sub
        sub	r14, QWORD PTR [rsp]
        sbb	r15, QWORD PTR [rsp+8]
        sbb	rdi, QWORD PTR [rsp+16]
        sbb	rsi, QWORD PTR [rsp+24]
        sbb	rbx, rbx
        shld	rbx, rsi, 1
        imul	rbx, -19
        btr	rsi, 63
        ;   Add modulus (if underflow)
        sub	r14, rbx
        sbb	r15, 0
        sbb	rdi, 0
        sbb	rsi, 0
        mov	QWORD PTR [r8], r10
        mov	QWORD PTR [r8+8], r11
        mov	QWORD PTR [r8+16], r12
        mov	QWORD PTR [r8+24], r13
        mov	QWORD PTR [rsp+128], r14
        mov	QWORD PTR [rsp+136], r15
        mov	QWORD PTR [rsp+144], rdi
        mov	QWORD PTR [rsp+152], rsi
        ; Square
        mov	rdx, QWORD PTR [rsp+128]
        mov	rax, QWORD PTR [rsp+136]
        ; A[0] * A[1]
        mov	rsi, rdx
        mulx	r12, r11, rax
        ; A[0] * A[3]
        mulx	r14, r13, QWORD PTR [rsp+152]
        ; A[2] * A[1]
        mov	rdx, QWORD PTR [rsp+144]
        mulx	rbx, rcx, rax
        xor	r10, r10
        adox	r13, rcx
        ; A[2] * A[3]
        mulx	rdi, r15, QWORD PTR [rsp+152]
        adox	r14, rbx
        ; A[2] * A[0]
        mulx	rbx, rcx, rsi
        adox	r15, r10
        adcx	r12, rcx
        adox	rdi, r10
        ; A[1] * A[3]
        mov	rdx, rax
        mulx	rdx, rcx, QWORD PTR [rsp+152]
        adcx	r13, rbx
        adcx	r14, rcx
        adcx	r15, rdx
        adcx	rdi, r10
        ; A[0] * A[0]
        mov	rdx, rsi
        mulx	rcx, r10, rdx
        xor	rsi, rsi
        adcx	r11, r11
        ; A[1] * A[1]
        mov	rdx, rax
        adox	r11, rcx
        mulx	rbx, rcx, rdx
        adcx	r12, r12
        adox	r12, rcx
        adcx	r13, r13
        ; A[2] * A[2]
        mov	rdx, QWORD PTR [rsp+144]
        adox	r13, rbx
        mulx	rcx, rbx, rdx
        adcx	r14, r14
        adox	r14, rbx
        adcx	r15, r15
        ; A[3] * A[3]
        mov	rdx, QWORD PTR [rsp+152]
        adox	r15, rcx
        mulx	rbx, rcx, rdx
        adcx	rdi, rdi
        adox	rdi, rcx
        adcx	rsi, rsi
        adox	rsi, rbx
        mov	rdx, 38
        mulx	rbx, rsi, rsi
        add	r13, rsi
        adc	rbx, 0
        mov	rcx, 9223372036854775807
        shld	rbx, r13, 1
        imul	rbx, rbx, 19
        and	r13, rcx
        xor	rcx, rcx
        adox	r10, rbx
        mulx	r14, rbx, r14
        adcx	r10, rbx
        adox	r11, r14
        mulx	r15, rbx, r15
        adcx	r11, rbx
        adox	r12, r15
        mulx	rdi, rbx, rdi
        adcx	r12, rbx
        adox	r13, rdi
        adcx	r13, rcx
        ; Store
        mov	QWORD PTR [rsp+96], r10
        mov	QWORD PTR [rsp+104], r11
        mov	QWORD PTR [rsp+112], r12
        mov	QWORD PTR [rsp+120], r13
        ; Square
        mov	rdx, QWORD PTR [r8]
        mov	rax, QWORD PTR [r8+8]
        ; A[0] * A[1]
        mov	rsi, rdx
        mulx	r12, r11, rax
        ; A[0] * A[3]
        mulx	r14, r13, QWORD PTR [r8+24]
        ; A[2] * A[1]
        mov	rdx, QWORD PTR [r8+16]
        mulx	rbx, rcx, rax
        xor	r10, r10
        adox	r13, rcx
        ; A[2] * A[3]
        mulx	rdi, r15, QWORD PTR [r8+24]
        adox	r14, rbx
        ; A[2] * A[0]
        mulx	rbx, rcx, rsi
        adox	r15, r10
        adcx	r12, rcx
        adox	rdi, r10
        ; A[1] * A[3]
        mov	rdx, rax
        mulx	rdx, rcx, QWORD PTR [r8+24]
        adcx	r13, rbx
        adcx	r14, rcx
        adcx	r15, rdx
        adcx	rdi, r10
        ; A[0] * A[0]
        mov	rdx, rsi
        mulx	rcx, r10, rdx
        xor	rsi, rsi
        adcx	r11, r11
        ; A[1] * A[1]
        mov	rdx, rax
        adox	r11, rcx
        mulx	rbx, rcx, rdx
        adcx	r12, r12
        adox	r12, rcx
        adcx	r13, r13
        ; A[2] * A[2]
        mov	rdx, QWORD PTR [r8+16]
        adox	r13, rbx
        mulx	rcx, rbx, rdx
        adcx	r14, r14
        adox	r14, rbx
        adcx	r15, r15
        ; A[3] * A[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	r15, rcx
        mulx	rbx, rcx, rdx
        adcx	rdi, rdi
        adox	rdi, rcx
        adcx	rsi, rsi
        adox	rsi, rbx
        mov	rdx, 38
        mulx	rbx, rsi, rsi
        add	r13, rsi
        adc	rbx, 0
        mov	rcx, 9223372036854775807
        shld	rbx, r13, 1
        imul	rbx, rbx, 19
        and	r13, rcx
        xor	rcx, rcx
        adox	r10, rbx
        mulx	r14, rbx, r14
        adcx	r10, rbx
        adox	r11, r14
        mulx	r15, rbx, r15
        adcx	r11, rbx
        adox	r12, r15
        mulx	rdi, rbx, rdi
        adcx	r12, rbx
        adox	r13, rdi
        adcx	r13, rcx
        ; Store
        mov	QWORD PTR [rsp+128], r10
        mov	QWORD PTR [rsp+136], r11
        mov	QWORD PTR [rsp+144], r12
        mov	QWORD PTR [rsp+152], r13
        mov	rax, QWORD PTR [rsp+128]
        ; Multiply
        ; A[0] * B[0]
        mov	rdx, QWORD PTR [rsp+96]
        mulx	r11, r10, rax
        ; A[2] * B[0]
        mulx	r13, r12, QWORD PTR [rsp+144]
        ; A[1] * B[0]
        mulx	rbx, rcx, QWORD PTR [rsp+136]
        xor	rsi, rsi
        adcx	r11, rcx
        ; A[3] * B[1]
        mov	rdx, QWORD PTR [rsp+104]
        mulx	r15, r14, QWORD PTR [rsp+152]
        adcx	r12, rbx
        ; A[0] * B[1]
        mulx	rbx, rcx, rax
        adox	r11, rcx
        ; A[2] * B[1]
        mulx	rdi, rcx, QWORD PTR [rsp+144]
        adox	r12, rbx
        adcx	r13, rcx
        ; A[1] * B[2]
        mov	rdx, QWORD PTR [rsp+112]
        mulx	rbx, rcx, QWORD PTR [rsp+136]
        adcx	r14, rdi
        adox	r13, rcx
        adcx	r15, rsi
        adox	r14, rbx
        ; A[0] * B[2]
        mulx	rbx, rcx, rax
        adox	r15, rsi
        xor	rdi, rdi
        adcx	r12, rcx
        ; A[1] * B[1]
        mov	rdx, QWORD PTR [rsp+104]
        mulx	rcx, rdx, QWORD PTR [rsp+136]
        adcx	r13, rbx
        adox	r12, rdx
        ; A[1] * B[3]
        mov	rdx, QWORD PTR [rsp+120]
        adox	r13, rcx
        mulx	rbx, rcx, QWORD PTR [rsp+136]
        adcx	r14, rcx
        ; A[2] * B[2]
        mov	rdx, QWORD PTR [rsp+112]
        mulx	rcx, rdx, QWORD PTR [rsp+144]
        adcx	r15, rbx
        adox	r14, rdx
        ; A[3] * B[3]
        mov	rdx, QWORD PTR [rsp+120]
        adox	r15, rcx
        mulx	rbx, rcx, QWORD PTR [rsp+152]
        adox	rdi, rsi
        adcx	rdi, rcx
        ; A[0] * B[3]
        mulx	rcx, rdx, rax
        adcx	rsi, rbx
        xor	rbx, rbx
        adcx	r13, rdx
        ; A[3] * B[0]
        mov	rdx, QWORD PTR [rsp+152]
        adcx	r14, rcx
        mulx	rcx, rdx, QWORD PTR [rsp+96]
        adox	r13, rdx
        adox	r14, rcx
        ; A[3] * B[2]
        mov	rdx, QWORD PTR [rsp+152]
        mulx	rcx, rdx, QWORD PTR [rsp+112]
        adcx	r15, rdx
        ; A[2] * B[3]
        mov	rdx, QWORD PTR [rsp+120]
        adcx	rdi, rcx
        mulx	rdx, rcx, QWORD PTR [rsp+144]
        adcx	rsi, rbx
        adox	r15, rcx
        adox	rdi, rdx
        adox	rsi, rbx
        mov	rdx, 38
        mulx	rcx, rsi, rsi
        add	r13, rsi
        adc	rcx, 0
        mov	rbx, 9223372036854775807
        shld	rcx, r13, 1
        imul	rcx, rcx, 19
        and	r13, rbx
        xor	rbx, rbx
        adox	r10, rcx
        mulx	r14, rcx, r14
        adcx	r10, rcx
        adox	r11, r14
        mulx	r15, rcx, r15
        adcx	r11, rcx
        adox	r12, r15
        mulx	rdi, rcx, rdi
        adcx	r12, rcx
        adox	r13, rdi
        adcx	r13, rbx
        ; Store
        mov	QWORD PTR [r8], r10
        mov	QWORD PTR [r8+8], r11
        mov	QWORD PTR [r8+16], r12
        mov	QWORD PTR [r8+24], r13
        ; Sub
        mov	r10, QWORD PTR [rsp+128]
        mov	r11, QWORD PTR [rsp+136]
        mov	r12, QWORD PTR [rsp+144]
        mov	r13, QWORD PTR [rsp+152]
        sub	r10, QWORD PTR [rsp+96]
        sbb	r11, QWORD PTR [rsp+104]
        sbb	r12, QWORD PTR [rsp+112]
        sbb	r13, QWORD PTR [rsp+120]
        sbb	rbx, rbx
        shld	rbx, r13, 1
        imul	rbx, -19
        btr	r13, 63
        ;   Add modulus (if underflow)
        sub	r10, rbx
        sbb	r11, 0
        sbb	r12, 0
        sbb	r13, 0
        mov	QWORD PTR [rsp+128], r10
        mov	QWORD PTR [rsp+136], r11
        mov	QWORD PTR [rsp+144], r12
        mov	QWORD PTR [rsp+152], r13
        mov	rdx, 121666
        mulx	rsi, r10, QWORD PTR [rsp+128]
        mulx	rdi, r11, QWORD PTR [rsp+136]
        mulx	r15, r12, QWORD PTR [rsp+144]
        add	r11, rsi
        mulx	r14, r13, QWORD PTR [rsp+152]
        adc	r12, rdi
        adc	r13, r15
        adc	r14, 0
        add	r10, QWORD PTR [rsp+96]
        adc	r11, QWORD PTR [rsp+104]
        adc	r12, QWORD PTR [rsp+112]
        adc	r13, QWORD PTR [rsp+120]
        adc	r14, 0
        shld	r14, r13, 1
        btr	r13, 63
        imul	r14, r14, 19
        add	r10, r14
        adc	r11, 0
        adc	r12, 0
        adc	r13, 0
        mov	QWORD PTR [rsp+96], r10
        mov	QWORD PTR [rsp+104], r11
        mov	QWORD PTR [rsp+112], r12
        mov	QWORD PTR [rsp+120], r13
        mov	rax, QWORD PTR [rsp+128]
        ; Multiply
        ; A[0] * B[0]
        mov	rdx, QWORD PTR [rsp+96]
        mulx	r11, r10, rax
        ; A[2] * B[0]
        mulx	r13, r12, QWORD PTR [rsp+144]
        ; A[1] * B[0]
        mulx	rbx, rcx, QWORD PTR [rsp+136]
        xor	rsi, rsi
        adcx	r11, rcx
        ; A[3] * B[1]
        mov	rdx, QWORD PTR [rsp+104]
        mulx	r15, r14, QWORD PTR [rsp+152]
        adcx	r12, rbx
        ; A[0] * B[1]
        mulx	rbx, rcx, rax
        adox	r11, rcx
        ; A[2] * B[1]
        mulx	rdi, rcx, QWORD PTR [rsp+144]
        adox	r12, rbx
        adcx	r13, rcx
        ; A[1] * B[2]
        mov	rdx, QWORD PTR [rsp+112]
        mulx	rbx, rcx, QWORD PTR [rsp+136]
        adcx	r14, rdi
        adox	r13, rcx
        adcx	r15, rsi
        adox	r14, rbx
        ; A[0] * B[2]
        mulx	rbx, rcx, rax
        adox	r15, rsi
        xor	rdi, rdi
        adcx	r12, rcx
        ; A[1] * B[1]
        mov	rdx, QWORD PTR [rsp+104]
        mulx	rcx, rdx, QWORD PTR [rsp+136]
        adcx	r13, rbx
        adox	r12, rdx
        ; A[1] * B[3]
        mov	rdx, QWORD PTR [rsp+120]
        adox	r13, rcx
        mulx	rbx, rcx, QWORD PTR [rsp+136]
        adcx	r14, rcx
        ; A[2] * B[2]
        mov	rdx, QWORD PTR [rsp+112]
        mulx	rcx, rdx, QWORD PTR [rsp+144]
        adcx	r15, rbx
        adox	r14, rdx
        ; A[3] * B[3]
        mov	rdx, QWORD PTR [rsp+120]
        adox	r15, rcx
        mulx	rbx, rcx, QWORD PTR [rsp+152]
        adox	rdi, rsi
        adcx	rdi, rcx
        ; A[0] * B[3]
        mulx	rcx, rdx, rax
        adcx	rsi, rbx
        xor	rbx, rbx
        adcx	r13, rdx
        ; A[3] * B[0]
        mov	rdx, QWORD PTR [rsp+152]
        adcx	r14, rcx
        mulx	rcx, rdx, QWORD PTR [rsp+96]
        adox	r13, rdx
        adox	r14, rcx
        ; A[3] * B[2]
        mov	rdx, QWORD PTR [rsp+152]
        mulx	rcx, rdx, QWORD PTR [rsp+112]
        adcx	r15, rdx
        ; A[2] * B[3]
        mov	rdx, QWORD PTR [rsp+120]
        adcx	rdi, rcx
        mulx	rdx, rcx, QWORD PTR [rsp+144]
        adcx	rsi, rbx
        adox	r15, rcx
        adox	rdi, rdx
        adox	rsi, rbx
        mov	rdx, 38
        mulx	rcx, rsi, rsi
        add	r13, rsi
        adc	rcx, 0
        mov	rbx, 9223372036854775807
        shld	rcx, r13, 1
        imul	rcx, rcx, 19
        and	r13, rbx
        xor	rbx, rbx
        adox	r10, rcx
        mulx	r14, rcx, r14
        adcx	r10, rcx
        adox	r11, r14
        mulx	r15, rcx, r15
        adcx	r11, rcx
        adox	r12, r15
        mulx	rdi, rcx, rdi
        adcx	r12, rcx
        adox	r13, rdi
        adcx	r13, rbx
        ; Store
        mov	QWORD PTR [rsp], r10
        mov	QWORD PTR [rsp+8], r11
        mov	QWORD PTR [rsp+16], r12
        mov	QWORD PTR [rsp+24], r13
        dec	rbp
        jge	L_curve25519_base_avx2_last_3
        ; Invert
        lea	rcx, QWORD PTR [rsp+32]
        mov	rdx, rsp
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+32]
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+64]
        mov	rdx, rsp
        lea	r8, QWORD PTR [rsp+64]
        call	fe_mul_avx2
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        lea	r8, QWORD PTR [rsp+64]
        call	fe_mul_avx2
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+32]
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        lea	r8, QWORD PTR [rsp+96]
        call	fe_mul_avx2
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+64]
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 4
        call	fe_sq_n_avx2
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        call	fe_mul_avx2
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+64]
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 9
        call	fe_sq_n_avx2
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        call	fe_mul_avx2
        lea	rcx, QWORD PTR [rsp+128]
        lea	rdx, QWORD PTR [rsp+96]
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+128]
        lea	rdx, QWORD PTR [rsp+128]
        mov	r8, 19
        call	fe_sq_n_avx2
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+128]
        lea	r8, QWORD PTR [rsp+96]
        call	fe_mul_avx2
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 9
        call	fe_sq_n_avx2
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        call	fe_mul_avx2
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+64]
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 49
        call	fe_sq_n_avx2
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        call	fe_mul_avx2
        lea	rcx, QWORD PTR [rsp+128]
        lea	rdx, QWORD PTR [rsp+96]
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+128]
        lea	rdx, QWORD PTR [rsp+128]
        mov	r8, 99
        call	fe_sq_n_avx2
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+128]
        lea	r8, QWORD PTR [rsp+96]
        call	fe_mul_avx2
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 49
        call	fe_sq_n_avx2
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        call	fe_mul_avx2
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        mov	r8, 4
        call	fe_sq_n_avx2
        mov	rcx, rsp
        lea	rdx, QWORD PTR [rsp+64]
        lea	r8, QWORD PTR [rsp+32]
        call	fe_mul_avx2
        mov	r8, QWORD PTR [rsp+160]
        mov	rax, QWORD PTR [r8]
        ; Multiply
        ; A[0] * B[0]
        mov	rdx, QWORD PTR [rsp]
        mulx	r11, r10, rax
        ; A[2] * B[0]
        mulx	r13, r12, QWORD PTR [r8+16]
        ; A[1] * B[0]
        mulx	rbx, rcx, QWORD PTR [r8+8]
        xor	rsi, rsi
        adcx	r11, rcx
        ; A[3] * B[1]
        mov	rdx, QWORD PTR [rsp+8]
        mulx	r15, r14, QWORD PTR [r8+24]
        adcx	r12, rbx
        ; A[0] * B[1]
        mulx	rbx, rcx, rax
        adox	r11, rcx
        ; A[2] * B[1]
        mulx	rdi, rcx, QWORD PTR [r8+16]
        adox	r12, rbx
        adcx	r13, rcx
        ; A[1] * B[2]
        mov	rdx, QWORD PTR [rsp+16]
        mulx	rbx, rcx, QWORD PTR [r8+8]
        adcx	r14, rdi
        adox	r13, rcx
        adcx	r15, rsi
        adox	r14, rbx
        ; A[0] * B[2]
        mulx	rbx, rcx, rax
        adox	r15, rsi
        xor	rdi, rdi
        adcx	r12, rcx
        ; A[1] * B[1]
        mov	rdx, QWORD PTR [rsp+8]
        mulx	rcx, rdx, QWORD PTR [r8+8]
        adcx	r13, rbx
        adox	r12, rdx
        ; A[1] * B[3]
        mov	rdx, QWORD PTR [rsp+24]
        adox	r13, rcx
        mulx	rbx, rcx, QWORD PTR [r8+8]
        adcx	r14, rcx
        ; A[2] * B[2]
        mov	rdx, QWORD PTR [rsp+16]
        mulx	rcx, rdx, QWORD PTR [r8+16]
        adcx	r15, rbx
        adox	r14, rdx
        ; A[3] * B[3]
        mov	rdx, QWORD PTR [rsp+24]
        adox	r15, rcx
        mulx	rbx, rcx, QWORD PTR [r8+24]
        adox	rdi, rsi
        adcx	rdi, rcx
        ; A[0] * B[3]
        mulx	rcx, rdx, rax
        adcx	rsi, rbx
        xor	rbx, rbx
        adcx	r13, rdx
        ; A[3] * B[0]
        mov	rdx, QWORD PTR [r8+24]
        adcx	r14, rcx
        mulx	rcx, rdx, QWORD PTR [rsp]
        adox	r13, rdx
        adox	r14, rcx
        ; A[3] * B[2]
        mov	rdx, QWORD PTR [r8+24]
        mulx	rcx, rdx, QWORD PTR [rsp+16]
        adcx	r15, rdx
        ; A[2] * B[3]
        mov	rdx, QWORD PTR [rsp+24]
        adcx	rdi, rcx
        mulx	rdx, rcx, QWORD PTR [r8+16]
        adcx	rsi, rbx
        adox	r15, rcx
        adox	rdi, rdx
        adox	rsi, rbx
        mov	rdx, 38
        mulx	rcx, rsi, rsi
        add	r13, rsi
        adc	rcx, 0
        mov	rbx, 9223372036854775807
        shld	rcx, r13, 1
        imul	rcx, rcx, 19
        and	r13, rbx
        xor	rbx, rbx
        adox	r10, rcx
        mulx	r14, rcx, r14
        adcx	r10, rcx
        adox	r11, r14
        mulx	r15, rcx, r15
        adcx	r11, rcx
        adox	r12, r15
        mulx	rdi, rcx, rdi
        adcx	r12, rcx
        adox	r13, rdi
        adcx	r13, rbx
        mov	rbx, 9223372036854775807
        mov	rdx, r13
        sar	rdx, 63
        and	rdx, 19
        and	r13, rbx
        add	r10, rdx
        adc	r11, 0
        adc	r12, 0
        adc	r13, 0
        mov	rcx, 9223372036854775807
        mov	rdx, r10
        add	rdx, 19
        mov	rdx, r11
        adc	rdx, 0
        mov	rdx, r12
        adc	rdx, 0
        mov	rdx, r13
        adc	rdx, 0
        sar	rdx, 63
        and	rdx, 19
        and	r13, rcx
        add	r10, rdx
        adc	r11, 0
        adc	r12, 0
        adc	r13, 0
        and	r13, rcx
        ; Store
        mov	QWORD PTR [r8], r10
        mov	QWORD PTR [r8+8], r11
        mov	QWORD PTR [r8+16], r12
        mov	QWORD PTR [r8+24], r13
        xor	rax, rax
        add	rsp, 176
        pop	rbp
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        pop	rbx
        ret
curve25519_base_avx2 ENDP
_TEXT ENDS
ENDIF
_TEXT SEGMENT READONLY PARA
curve25519_avx2 PROC
        push	rbx
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbp
        mov	r9, rcx
        mov	r10, rdx
        sub	rsp, 184
        mov	QWORD PTR [rsp+176], 0
        mov	QWORD PTR [rsp+168], r9
        ; Set one
        mov	QWORD PTR [r9], 1
        mov	QWORD PTR [r9+8], 0
        mov	QWORD PTR [r9+16], 0
        mov	QWORD PTR [r9+24], 0
        ; Set zero
        mov	QWORD PTR [rsp], 0
        mov	QWORD PTR [rsp+8], 0
        mov	QWORD PTR [rsp+16], 0
        mov	QWORD PTR [rsp+24], 0
        ; Set one
        mov	QWORD PTR [rsp+32], 1
        mov	QWORD PTR [rsp+40], 0
        mov	QWORD PTR [rsp+48], 0
        mov	QWORD PTR [rsp+56], 0
        ; Copy
        mov	r11, QWORD PTR [r8]
        mov	r12, QWORD PTR [r8+8]
        mov	r13, QWORD PTR [r8+16]
        mov	r14, QWORD PTR [r8+24]
        mov	QWORD PTR [rsp+64], r11
        mov	QWORD PTR [rsp+72], r12
        mov	QWORD PTR [rsp+80], r13
        mov	QWORD PTR [rsp+88], r14
        mov	rbx, 254
L_curve25519_avx2_bits:
        mov	QWORD PTR [rsp+160], rbx
        mov	rcx, rbx
        mov	rax, QWORD PTR [rsp+176]
        and	rcx, 63
        shr	rbx, 6
        mov	rbx, QWORD PTR [r10+8*rbx]
        shr	rbx, cl
        and	rbx, 1
        xor	rax, rbx
        mov	QWORD PTR [rsp+176], rbx
        neg	rax
        ; Conditional Swap
        mov	r11, QWORD PTR [r9]
        mov	r12, QWORD PTR [r9+8]
        mov	r13, QWORD PTR [r9+16]
        mov	r14, QWORD PTR [r9+24]
        mov	r15, QWORD PTR [rsp]
        mov	rdi, QWORD PTR [rsp+8]
        mov	rsi, QWORD PTR [rsp+16]
        mov	rbp, QWORD PTR [rsp+24]
        xor	r11, QWORD PTR [rsp+64]
        xor	r12, QWORD PTR [rsp+72]
        xor	r13, QWORD PTR [rsp+80]
        xor	r14, QWORD PTR [rsp+88]
        xor	r15, QWORD PTR [rsp+32]
        xor	rdi, QWORD PTR [rsp+40]
        xor	rsi, QWORD PTR [rsp+48]
        xor	rbp, QWORD PTR [rsp+56]
        and	r11, rax
        and	r12, rax
        and	r13, rax
        and	r14, rax
        and	r15, rax
        and	rdi, rax
        and	rsi, rax
        and	rbp, rax
        xor	QWORD PTR [r9], r11
        xor	QWORD PTR [r9+8], r12
        xor	QWORD PTR [r9+16], r13
        xor	QWORD PTR [r9+24], r14
        xor	QWORD PTR [rsp], r15
        xor	QWORD PTR [rsp+8], rdi
        xor	QWORD PTR [rsp+16], rsi
        xor	QWORD PTR [rsp+24], rbp
        xor	QWORD PTR [rsp+64], r11
        xor	QWORD PTR [rsp+72], r12
        xor	QWORD PTR [rsp+80], r13
        xor	QWORD PTR [rsp+88], r14
        xor	QWORD PTR [rsp+32], r15
        xor	QWORD PTR [rsp+40], rdi
        xor	QWORD PTR [rsp+48], rsi
        xor	QWORD PTR [rsp+56], rbp
        ; Add-Sub
        ; Add
        mov	r11, QWORD PTR [r9]
        mov	r12, QWORD PTR [r9+8]
        mov	r13, QWORD PTR [r9+16]
        mov	r14, QWORD PTR [r9+24]
        mov	r15, r11
        add	r11, QWORD PTR [rsp]
        mov	rdi, r12
        adc	r12, QWORD PTR [rsp+8]
        mov	rsi, r13
        adc	r13, QWORD PTR [rsp+16]
        mov	rbp, r14
        adc	r14, QWORD PTR [rsp+24]
        mov	rbx, 0
        adc	rbx, 0
        shld	rbx, r14, 1
        imul	rbx, 19
        btr	r14, 63
        ;   Sub modulus (if overflow)
        add	r11, rbx
        adc	r12, 0
        adc	r13, 0
        adc	r14, 0
        ; Sub
        sub	r15, QWORD PTR [rsp]
        sbb	rdi, QWORD PTR [rsp+8]
        sbb	rsi, QWORD PTR [rsp+16]
        sbb	rbp, QWORD PTR [rsp+24]
        sbb	rbx, rbx
        shld	rbx, rbp, 1
        imul	rbx, -19
        btr	rbp, 63
        ;   Add modulus (if underflow)
        sub	r15, rbx
        sbb	rdi, 0
        sbb	rsi, 0
        sbb	rbp, 0
        mov	QWORD PTR [r9], r11
        mov	QWORD PTR [r9+8], r12
        mov	QWORD PTR [r9+16], r13
        mov	QWORD PTR [r9+24], r14
        mov	QWORD PTR [rsp+128], r15
        mov	QWORD PTR [rsp+136], rdi
        mov	QWORD PTR [rsp+144], rsi
        mov	QWORD PTR [rsp+152], rbp
        ; Add-Sub
        ; Add
        mov	r11, QWORD PTR [rsp+64]
        mov	r12, QWORD PTR [rsp+72]
        mov	r13, QWORD PTR [rsp+80]
        mov	r14, QWORD PTR [rsp+88]
        mov	r15, r11
        add	r11, QWORD PTR [rsp+32]
        mov	rdi, r12
        adc	r12, QWORD PTR [rsp+40]
        mov	rsi, r13
        adc	r13, QWORD PTR [rsp+48]
        mov	rbp, r14
        adc	r14, QWORD PTR [rsp+56]
        mov	rbx, 0
        adc	rbx, 0
        shld	rbx, r14, 1
        imul	rbx, 19
        btr	r14, 63
        ;   Sub modulus (if overflow)
        add	r11, rbx
        adc	r12, 0
        adc	r13, 0
        adc	r14, 0
        ; Sub
        sub	r15, QWORD PTR [rsp+32]
        sbb	rdi, QWORD PTR [rsp+40]
        sbb	rsi, QWORD PTR [rsp+48]
        sbb	rbp, QWORD PTR [rsp+56]
        sbb	rbx, rbx
        shld	rbx, rbp, 1
        imul	rbx, -19
        btr	rbp, 63
        ;   Add modulus (if underflow)
        sub	r15, rbx
        sbb	rdi, 0
        sbb	rsi, 0
        sbb	rbp, 0
        mov	QWORD PTR [rsp+32], r11
        mov	QWORD PTR [rsp+40], r12
        mov	QWORD PTR [rsp+48], r13
        mov	QWORD PTR [rsp+56], r14
        mov	QWORD PTR [rsp+96], r15
        mov	QWORD PTR [rsp+104], rdi
        mov	QWORD PTR [rsp+112], rsi
        mov	QWORD PTR [rsp+120], rbp
        mov	rax, QWORD PTR [rsp+32]
        ; Multiply
        ; A[0] * B[0]
        mov	rdx, QWORD PTR [rsp+128]
        mulx	r12, r11, rax
        ; A[2] * B[0]
        mulx	r14, r13, QWORD PTR [rsp+48]
        ; A[1] * B[0]
        mulx	rbx, rcx, QWORD PTR [rsp+40]
        xor	rbp, rbp
        adcx	r12, rcx
        ; A[3] * B[1]
        mov	rdx, QWORD PTR [rsp+136]
        mulx	rdi, r15, QWORD PTR [rsp+56]
        adcx	r13, rbx
        ; A[0] * B[1]
        mulx	rbx, rcx, rax
        adox	r12, rcx
        ; A[2] * B[1]
        mulx	rsi, rcx, QWORD PTR [rsp+48]
        adox	r13, rbx
        adcx	r14, rcx
        ; A[1] * B[2]
        mov	rdx, QWORD PTR [rsp+144]
        mulx	rbx, rcx, QWORD PTR [rsp+40]
        adcx	r15, rsi
        adox	r14, rcx
        adcx	rdi, rbp
        adox	r15, rbx
        ; A[0] * B[2]
        mulx	rbx, rcx, rax
        adox	rdi, rbp
        xor	rsi, rsi
        adcx	r13, rcx
        ; A[1] * B[1]
        mov	rdx, QWORD PTR [rsp+136]
        mulx	rcx, rdx, QWORD PTR [rsp+40]
        adcx	r14, rbx
        adox	r13, rdx
        ; A[1] * B[3]
        mov	rdx, QWORD PTR [rsp+152]
        adox	r14, rcx
        mulx	rbx, rcx, QWORD PTR [rsp+40]
        adcx	r15, rcx
        ; A[2] * B[2]
        mov	rdx, QWORD PTR [rsp+144]
        mulx	rcx, rdx, QWORD PTR [rsp+48]
        adcx	rdi, rbx
        adox	r15, rdx
        ; A[3] * B[3]
        mov	rdx, QWORD PTR [rsp+152]
        adox	rdi, rcx
        mulx	rbx, rcx, QWORD PTR [rsp+56]
        adox	rsi, rbp
        adcx	rsi, rcx
        ; A[0] * B[3]
        mulx	rcx, rdx, rax
        adcx	rbp, rbx
        xor	rbx, rbx
        adcx	r14, rdx
        ; A[3] * B[0]
        mov	rdx, QWORD PTR [rsp+56]
        adcx	r15, rcx
        mulx	rcx, rdx, QWORD PTR [rsp+128]
        adox	r14, rdx
        adox	r15, rcx
        ; A[3] * B[2]
        mov	rdx, QWORD PTR [rsp+56]
        mulx	rcx, rdx, QWORD PTR [rsp+144]
        adcx	rdi, rdx
        ; A[2] * B[3]
        mov	rdx, QWORD PTR [rsp+152]
        adcx	rsi, rcx
        mulx	rdx, rcx, QWORD PTR [rsp+48]
        adcx	rbp, rbx
        adox	rdi, rcx
        adox	rsi, rdx
        adox	rbp, rbx
        mov	rdx, 38
        mulx	rcx, rbp, rbp
        add	r14, rbp
        adc	rcx, 0
        mov	rbx, 9223372036854775807
        shld	rcx, r14, 1
        imul	rcx, rcx, 19
        and	r14, rbx
        xor	rbx, rbx
        adox	r11, rcx
        mulx	r15, rcx, r15
        adcx	r11, rcx
        adox	r12, r15
        mulx	rdi, rcx, rdi
        adcx	r12, rcx
        adox	r13, rdi
        mulx	rsi, rcx, rsi
        adcx	r13, rcx
        adox	r14, rsi
        adcx	r14, rbx
        ; Store
        mov	QWORD PTR [rsp+32], r11
        mov	QWORD PTR [rsp+40], r12
        mov	QWORD PTR [rsp+48], r13
        mov	QWORD PTR [rsp+56], r14
        mov	rax, QWORD PTR [rsp+96]
        ; Multiply
        ; A[0] * B[0]
        mov	rdx, QWORD PTR [r9]
        mulx	r12, r11, rax
        ; A[2] * B[0]
        mulx	r14, r13, QWORD PTR [rsp+112]
        ; A[1] * B[0]
        mulx	rbx, rcx, QWORD PTR [rsp+104]
        xor	rbp, rbp
        adcx	r12, rcx
        ; A[3] * B[1]
        mov	rdx, QWORD PTR [r9+8]
        mulx	rdi, r15, QWORD PTR [rsp+120]
        adcx	r13, rbx
        ; A[0] * B[1]
        mulx	rbx, rcx, rax
        adox	r12, rcx
        ; A[2] * B[1]
        mulx	rsi, rcx, QWORD PTR [rsp+112]
        adox	r13, rbx
        adcx	r14, rcx
        ; A[1] * B[2]
        mov	rdx, QWORD PTR [r9+16]
        mulx	rbx, rcx, QWORD PTR [rsp+104]
        adcx	r15, rsi
        adox	r14, rcx
        adcx	rdi, rbp
        adox	r15, rbx
        ; A[0] * B[2]
        mulx	rbx, rcx, rax
        adox	rdi, rbp
        xor	rsi, rsi
        adcx	r13, rcx
        ; A[1] * B[1]
        mov	rdx, QWORD PTR [r9+8]
        mulx	rcx, rdx, QWORD PTR [rsp+104]
        adcx	r14, rbx
        adox	r13, rdx
        ; A[1] * B[3]
        mov	rdx, QWORD PTR [r9+24]
        adox	r14, rcx
        mulx	rbx, rcx, QWORD PTR [rsp+104]
        adcx	r15, rcx
        ; A[2] * B[2]
        mov	rdx, QWORD PTR [r9+16]
        mulx	rcx, rdx, QWORD PTR [rsp+112]
        adcx	rdi, rbx
        adox	r15, rdx
        ; A[3] * B[3]
        mov	rdx, QWORD PTR [r9+24]
        adox	rdi, rcx
        mulx	rbx, rcx, QWORD PTR [rsp+120]
        adox	rsi, rbp
        adcx	rsi, rcx
        ; A[0] * B[3]
        mulx	rcx, rdx, rax
        adcx	rbp, rbx
        xor	rbx, rbx
        adcx	r14, rdx
        ; A[3] * B[0]
        mov	rdx, QWORD PTR [rsp+120]
        adcx	r15, rcx
        mulx	rcx, rdx, QWORD PTR [r9]
        adox	r14, rdx
        adox	r15, rcx
        ; A[3] * B[2]
        mov	rdx, QWORD PTR [rsp+120]
        mulx	rcx, rdx, QWORD PTR [r9+16]
        adcx	rdi, rdx
        ; A[2] * B[3]
        mov	rdx, QWORD PTR [r9+24]
        adcx	rsi, rcx
        mulx	rdx, rcx, QWORD PTR [rsp+112]
        adcx	rbp, rbx
        adox	rdi, rcx
        adox	rsi, rdx
        adox	rbp, rbx
        mov	rdx, 38
        mulx	rcx, rbp, rbp
        add	r14, rbp
        adc	rcx, 0
        mov	rbx, 9223372036854775807
        shld	rcx, r14, 1
        imul	rcx, rcx, 19
        and	r14, rbx
        xor	rbx, rbx
        adox	r11, rcx
        mulx	r15, rcx, r15
        adcx	r11, rcx
        adox	r12, r15
        mulx	rdi, rcx, rdi
        adcx	r12, rcx
        adox	r13, rdi
        mulx	rsi, rcx, rsi
        adcx	r13, rcx
        adox	r14, rsi
        adcx	r14, rbx
        ; Store
        mov	QWORD PTR [rsp], r11
        mov	QWORD PTR [rsp+8], r12
        mov	QWORD PTR [rsp+16], r13
        mov	QWORD PTR [rsp+24], r14
        ; Square
        mov	rdx, QWORD PTR [rsp+128]
        mov	rax, QWORD PTR [rsp+136]
        ; A[0] * A[1]
        mov	rbp, rdx
        mulx	r13, r12, rax
        ; A[0] * A[3]
        mulx	r15, r14, QWORD PTR [rsp+152]
        ; A[2] * A[1]
        mov	rdx, QWORD PTR [rsp+144]
        mulx	rbx, rcx, rax
        xor	r11, r11
        adox	r14, rcx
        ; A[2] * A[3]
        mulx	rsi, rdi, QWORD PTR [rsp+152]
        adox	r15, rbx
        ; A[2] * A[0]
        mulx	rbx, rcx, rbp
        adox	rdi, r11
        adcx	r13, rcx
        adox	rsi, r11
        ; A[1] * A[3]
        mov	rdx, rax
        mulx	rdx, rcx, QWORD PTR [rsp+152]
        adcx	r14, rbx
        adcx	r15, rcx
        adcx	rdi, rdx
        adcx	rsi, r11
        ; A[0] * A[0]
        mov	rdx, rbp
        mulx	rcx, r11, rdx
        xor	rbp, rbp
        adcx	r12, r12
        ; A[1] * A[1]
        mov	rdx, rax
        adox	r12, rcx
        mulx	rbx, rcx, rdx
        adcx	r13, r13
        adox	r13, rcx
        adcx	r14, r14
        ; A[2] * A[2]
        mov	rdx, QWORD PTR [rsp+144]
        adox	r14, rbx
        mulx	rcx, rbx, rdx
        adcx	r15, r15
        adox	r15, rbx
        adcx	rdi, rdi
        ; A[3] * A[3]
        mov	rdx, QWORD PTR [rsp+152]
        adox	rdi, rcx
        mulx	rbx, rcx, rdx
        adcx	rsi, rsi
        adox	rsi, rcx
        adcx	rbp, rbp
        adox	rbp, rbx
        mov	rdx, 38
        mulx	rbx, rbp, rbp
        add	r14, rbp
        adc	rbx, 0
        mov	rcx, 9223372036854775807
        shld	rbx, r14, 1
        imul	rbx, rbx, 19
        and	r14, rcx
        xor	rcx, rcx
        adox	r11, rbx
        mulx	r15, rbx, r15
        adcx	r11, rbx
        adox	r12, r15
        mulx	rdi, rbx, rdi
        adcx	r12, rbx
        adox	r13, rdi
        mulx	rsi, rbx, rsi
        adcx	r13, rbx
        adox	r14, rsi
        adcx	r14, rcx
        ; Store
        mov	QWORD PTR [rsp+96], r11
        mov	QWORD PTR [rsp+104], r12
        mov	QWORD PTR [rsp+112], r13
        mov	QWORD PTR [rsp+120], r14
        ; Square
        mov	rdx, QWORD PTR [r9]
        mov	rax, QWORD PTR [r9+8]
        ; A[0] * A[1]
        mov	rbp, rdx
        mulx	r13, r12, rax
        ; A[0] * A[3]
        mulx	r15, r14, QWORD PTR [r9+24]
        ; A[2] * A[1]
        mov	rdx, QWORD PTR [r9+16]
        mulx	rbx, rcx, rax
        xor	r11, r11
        adox	r14, rcx
        ; A[2] * A[3]
        mulx	rsi, rdi, QWORD PTR [r9+24]
        adox	r15, rbx
        ; A[2] * A[0]
        mulx	rbx, rcx, rbp
        adox	rdi, r11
        adcx	r13, rcx
        adox	rsi, r11
        ; A[1] * A[3]
        mov	rdx, rax
        mulx	rdx, rcx, QWORD PTR [r9+24]
        adcx	r14, rbx
        adcx	r15, rcx
        adcx	rdi, rdx
        adcx	rsi, r11
        ; A[0] * A[0]
        mov	rdx, rbp
        mulx	rcx, r11, rdx
        xor	rbp, rbp
        adcx	r12, r12
        ; A[1] * A[1]
        mov	rdx, rax
        adox	r12, rcx
        mulx	rbx, rcx, rdx
        adcx	r13, r13
        adox	r13, rcx
        adcx	r14, r14
        ; A[2] * A[2]
        mov	rdx, QWORD PTR [r9+16]
        adox	r14, rbx
        mulx	rcx, rbx, rdx
        adcx	r15, r15
        adox	r15, rbx
        adcx	rdi, rdi
        ; A[3] * A[3]
        mov	rdx, QWORD PTR [r9+24]
        adox	rdi, rcx
        mulx	rbx, rcx, rdx
        adcx	rsi, rsi
        adox	rsi, rcx
        adcx	rbp, rbp
        adox	rbp, rbx
        mov	rdx, 38
        mulx	rbx, rbp, rbp
        add	r14, rbp
        adc	rbx, 0
        mov	rcx, 9223372036854775807
        shld	rbx, r14, 1
        imul	rbx, rbx, 19
        and	r14, rcx
        xor	rcx, rcx
        adox	r11, rbx
        mulx	r15, rbx, r15
        adcx	r11, rbx
        adox	r12, r15
        mulx	rdi, rbx, rdi
        adcx	r12, rbx
        adox	r13, rdi
        mulx	rsi, rbx, rsi
        adcx	r13, rbx
        adox	r14, rsi
        adcx	r14, rcx
        ; Store
        mov	QWORD PTR [rsp+128], r11
        mov	QWORD PTR [rsp+136], r12
        mov	QWORD PTR [rsp+144], r13
        mov	QWORD PTR [rsp+152], r14
        ; Add-Sub
        ; Add
        mov	r11, QWORD PTR [rsp]
        mov	r12, QWORD PTR [rsp+8]
        mov	r13, QWORD PTR [rsp+16]
        mov	r14, QWORD PTR [rsp+24]
        mov	r15, r11
        add	r11, QWORD PTR [rsp+32]
        mov	rdi, r12
        adc	r12, QWORD PTR [rsp+40]
        mov	rsi, r13
        adc	r13, QWORD PTR [rsp+48]
        mov	rbp, r14
        adc	r14, QWORD PTR [rsp+56]
        mov	rbx, 0
        adc	rbx, 0
        shld	rbx, r14, 1
        imul	rbx, 19
        btr	r14, 63
        ;   Sub modulus (if overflow)
        add	r11, rbx
        adc	r12, 0
        adc	r13, 0
        adc	r14, 0
        ; Sub
        sub	r15, QWORD PTR [rsp+32]
        sbb	rdi, QWORD PTR [rsp+40]
        sbb	rsi, QWORD PTR [rsp+48]
        sbb	rbp, QWORD PTR [rsp+56]
        sbb	rbx, rbx
        shld	rbx, rbp, 1
        imul	rbx, -19
        btr	rbp, 63
        ;   Add modulus (if underflow)
        sub	r15, rbx
        sbb	rdi, 0
        sbb	rsi, 0
        sbb	rbp, 0
        mov	QWORD PTR [rsp+64], r11
        mov	QWORD PTR [rsp+72], r12
        mov	QWORD PTR [rsp+80], r13
        mov	QWORD PTR [rsp+88], r14
        mov	QWORD PTR [rsp+32], r15
        mov	QWORD PTR [rsp+40], rdi
        mov	QWORD PTR [rsp+48], rsi
        mov	QWORD PTR [rsp+56], rbp
        mov	rax, QWORD PTR [rsp+128]
        ; Multiply
        ; A[0] * B[0]
        mov	rdx, QWORD PTR [rsp+96]
        mulx	r12, r11, rax
        ; A[2] * B[0]
        mulx	r14, r13, QWORD PTR [rsp+144]
        ; A[1] * B[0]
        mulx	rbx, rcx, QWORD PTR [rsp+136]
        xor	rbp, rbp
        adcx	r12, rcx
        ; A[3] * B[1]
        mov	rdx, QWORD PTR [rsp+104]
        mulx	rdi, r15, QWORD PTR [rsp+152]
        adcx	r13, rbx
        ; A[0] * B[1]
        mulx	rbx, rcx, rax
        adox	r12, rcx
        ; A[2] * B[1]
        mulx	rsi, rcx, QWORD PTR [rsp+144]
        adox	r13, rbx
        adcx	r14, rcx
        ; A[1] * B[2]
        mov	rdx, QWORD PTR [rsp+112]
        mulx	rbx, rcx, QWORD PTR [rsp+136]
        adcx	r15, rsi
        adox	r14, rcx
        adcx	rdi, rbp
        adox	r15, rbx
        ; A[0] * B[2]
        mulx	rbx, rcx, rax
        adox	rdi, rbp
        xor	rsi, rsi
        adcx	r13, rcx
        ; A[1] * B[1]
        mov	rdx, QWORD PTR [rsp+104]
        mulx	rcx, rdx, QWORD PTR [rsp+136]
        adcx	r14, rbx
        adox	r13, rdx
        ; A[1] * B[3]
        mov	rdx, QWORD PTR [rsp+120]
        adox	r14, rcx
        mulx	rbx, rcx, QWORD PTR [rsp+136]
        adcx	r15, rcx
        ; A[2] * B[2]
        mov	rdx, QWORD PTR [rsp+112]
        mulx	rcx, rdx, QWORD PTR [rsp+144]
        adcx	rdi, rbx
        adox	r15, rdx
        ; A[3] * B[3]
        mov	rdx, QWORD PTR [rsp+120]
        adox	rdi, rcx
        mulx	rbx, rcx, QWORD PTR [rsp+152]
        adox	rsi, rbp
        adcx	rsi, rcx
        ; A[0] * B[3]
        mulx	rcx, rdx, rax
        adcx	rbp, rbx
        xor	rbx, rbx
        adcx	r14, rdx
        ; A[3] * B[0]
        mov	rdx, QWORD PTR [rsp+152]
        adcx	r15, rcx
        mulx	rcx, rdx, QWORD PTR [rsp+96]
        adox	r14, rdx
        adox	r15, rcx
        ; A[3] * B[2]
        mov	rdx, QWORD PTR [rsp+152]
        mulx	rcx, rdx, QWORD PTR [rsp+112]
        adcx	rdi, rdx
        ; A[2] * B[3]
        mov	rdx, QWORD PTR [rsp+120]
        adcx	rsi, rcx
        mulx	rdx, rcx, QWORD PTR [rsp+144]
        adcx	rbp, rbx
        adox	rdi, rcx
        adox	rsi, rdx
        adox	rbp, rbx
        mov	rdx, 38
        mulx	rcx, rbp, rbp
        add	r14, rbp
        adc	rcx, 0
        mov	rbx, 9223372036854775807
        shld	rcx, r14, 1
        imul	rcx, rcx, 19
        and	r14, rbx
        xor	rbx, rbx
        adox	r11, rcx
        mulx	r15, rcx, r15
        adcx	r11, rcx
        adox	r12, r15
        mulx	rdi, rcx, rdi
        adcx	r12, rcx
        adox	r13, rdi
        mulx	rsi, rcx, rsi
        adcx	r13, rcx
        adox	r14, rsi
        adcx	r14, rbx
        ; Store
        mov	QWORD PTR [r9], r11
        mov	QWORD PTR [r9+8], r12
        mov	QWORD PTR [r9+16], r13
        mov	QWORD PTR [r9+24], r14
        ; Sub
        mov	r11, QWORD PTR [rsp+128]
        mov	r12, QWORD PTR [rsp+136]
        mov	r13, QWORD PTR [rsp+144]
        mov	r14, QWORD PTR [rsp+152]
        sub	r11, QWORD PTR [rsp+96]
        sbb	r12, QWORD PTR [rsp+104]
        sbb	r13, QWORD PTR [rsp+112]
        sbb	r14, QWORD PTR [rsp+120]
        sbb	rbx, rbx
        shld	rbx, r14, 1
        imul	rbx, -19
        btr	r14, 63
        ;   Add modulus (if underflow)
        sub	r11, rbx
        sbb	r12, 0
        sbb	r13, 0
        sbb	r14, 0
        mov	QWORD PTR [rsp+128], r11
        mov	QWORD PTR [rsp+136], r12
        mov	QWORD PTR [rsp+144], r13
        mov	QWORD PTR [rsp+152], r14
        ; Square
        mov	rdx, QWORD PTR [rsp+32]
        mov	rax, QWORD PTR [rsp+40]
        ; A[0] * A[1]
        mov	rbp, rdx
        mulx	r13, r12, rax
        ; A[0] * A[3]
        mulx	r15, r14, QWORD PTR [rsp+56]
        ; A[2] * A[1]
        mov	rdx, QWORD PTR [rsp+48]
        mulx	rbx, rcx, rax
        xor	r11, r11
        adox	r14, rcx
        ; A[2] * A[3]
        mulx	rsi, rdi, QWORD PTR [rsp+56]
        adox	r15, rbx
        ; A[2] * A[0]
        mulx	rbx, rcx, rbp
        adox	rdi, r11
        adcx	r13, rcx
        adox	rsi, r11
        ; A[1] * A[3]
        mov	rdx, rax
        mulx	rdx, rcx, QWORD PTR [rsp+56]
        adcx	r14, rbx
        adcx	r15, rcx
        adcx	rdi, rdx
        adcx	rsi, r11
        ; A[0] * A[0]
        mov	rdx, rbp
        mulx	rcx, r11, rdx
        xor	rbp, rbp
        adcx	r12, r12
        ; A[1] * A[1]
        mov	rdx, rax
        adox	r12, rcx
        mulx	rbx, rcx, rdx
        adcx	r13, r13
        adox	r13, rcx
        adcx	r14, r14
        ; A[2] * A[2]
        mov	rdx, QWORD PTR [rsp+48]
        adox	r14, rbx
        mulx	rcx, rbx, rdx
        adcx	r15, r15
        adox	r15, rbx
        adcx	rdi, rdi
        ; A[3] * A[3]
        mov	rdx, QWORD PTR [rsp+56]
        adox	rdi, rcx
        mulx	rbx, rcx, rdx
        adcx	rsi, rsi
        adox	rsi, rcx
        adcx	rbp, rbp
        adox	rbp, rbx
        mov	rdx, 38
        mulx	rbx, rbp, rbp
        add	r14, rbp
        adc	rbx, 0
        mov	rcx, 9223372036854775807
        shld	rbx, r14, 1
        imul	rbx, rbx, 19
        and	r14, rcx
        xor	rcx, rcx
        adox	r11, rbx
        mulx	r15, rbx, r15
        adcx	r11, rbx
        adox	r12, r15
        mulx	rdi, rbx, rdi
        adcx	r12, rbx
        adox	r13, rdi
        mulx	rsi, rbx, rsi
        adcx	r13, rbx
        adox	r14, rsi
        adcx	r14, rcx
        ; Store
        mov	QWORD PTR [rsp+32], r11
        mov	QWORD PTR [rsp+40], r12
        mov	QWORD PTR [rsp+48], r13
        mov	QWORD PTR [rsp+56], r14
        ; Square
        mov	rdx, QWORD PTR [rsp+64]
        mov	rax, QWORD PTR [rsp+72]
        ; A[0] * A[1]
        mov	rbp, rdx
        mulx	r13, r12, rax
        ; A[0] * A[3]
        mulx	r15, r14, QWORD PTR [rsp+88]
        ; A[2] * A[1]
        mov	rdx, QWORD PTR [rsp+80]
        mulx	rbx, rcx, rax
        xor	r11, r11
        adox	r14, rcx
        ; A[2] * A[3]
        mulx	rsi, rdi, QWORD PTR [rsp+88]
        adox	r15, rbx
        ; A[2] * A[0]
        mulx	rbx, rcx, rbp
        adox	rdi, r11
        adcx	r13, rcx
        adox	rsi, r11
        ; A[1] * A[3]
        mov	rdx, rax
        mulx	rdx, rcx, QWORD PTR [rsp+88]
        adcx	r14, rbx
        adcx	r15, rcx
        adcx	rdi, rdx
        adcx	rsi, r11
        ; A[0] * A[0]
        mov	rdx, rbp
        mulx	rcx, r11, rdx
        xor	rbp, rbp
        adcx	r12, r12
        ; A[1] * A[1]
        mov	rdx, rax
        adox	r12, rcx
        mulx	rbx, rcx, rdx
        adcx	r13, r13
        adox	r13, rcx
        adcx	r14, r14
        ; A[2] * A[2]
        mov	rdx, QWORD PTR [rsp+80]
        adox	r14, rbx
        mulx	rcx, rbx, rdx
        adcx	r15, r15
        adox	r15, rbx
        adcx	rdi, rdi
        ; A[3] * A[3]
        mov	rdx, QWORD PTR [rsp+88]
        adox	rdi, rcx
        mulx	rbx, rcx, rdx
        adcx	rsi, rsi
        adox	rsi, rcx
        adcx	rbp, rbp
        adox	rbp, rbx
        mov	rdx, 38
        mulx	rbx, rbp, rbp
        add	r14, rbp
        adc	rbx, 0
        mov	rcx, 9223372036854775807
        shld	rbx, r14, 1
        imul	rbx, rbx, 19
        and	r14, rcx
        xor	rcx, rcx
        adox	r11, rbx
        mulx	r15, rbx, r15
        adcx	r11, rbx
        adox	r12, r15
        mulx	rdi, rbx, rdi
        adcx	r12, rbx
        adox	r13, rdi
        mulx	rsi, rbx, rsi
        adcx	r13, rbx
        adox	r14, rsi
        adcx	r14, rcx
        ; Store
        mov	QWORD PTR [rsp+64], r11
        mov	QWORD PTR [rsp+72], r12
        mov	QWORD PTR [rsp+80], r13
        mov	QWORD PTR [rsp+88], r14
        mov	rdx, 121666
        mulx	rbp, r11, QWORD PTR [rsp+128]
        mulx	rsi, r12, QWORD PTR [rsp+136]
        mulx	rdi, r13, QWORD PTR [rsp+144]
        add	r12, rbp
        mulx	r15, r14, QWORD PTR [rsp+152]
        adc	r13, rsi
        adc	r14, rdi
        adc	r15, 0
        add	r11, QWORD PTR [rsp+96]
        adc	r12, QWORD PTR [rsp+104]
        adc	r13, QWORD PTR [rsp+112]
        adc	r14, QWORD PTR [rsp+120]
        adc	r15, 0
        shld	r15, r14, 1
        btr	r14, 63
        imul	r15, r15, 19
        add	r11, r15
        adc	r12, 0
        adc	r13, 0
        adc	r14, 0
        mov	QWORD PTR [rsp+96], r11
        mov	QWORD PTR [rsp+104], r12
        mov	QWORD PTR [rsp+112], r13
        mov	QWORD PTR [rsp+120], r14
        mov	rax, QWORD PTR [r8]
        ; Multiply
        ; A[0] * B[0]
        mov	rdx, QWORD PTR [rsp+32]
        mulx	r12, r11, rax
        ; A[2] * B[0]
        mulx	r14, r13, QWORD PTR [r8+16]
        ; A[1] * B[0]
        mulx	rbx, rcx, QWORD PTR [r8+8]
        xor	rbp, rbp
        adcx	r12, rcx
        ; A[3] * B[1]
        mov	rdx, QWORD PTR [rsp+40]
        mulx	rdi, r15, QWORD PTR [r8+24]
        adcx	r13, rbx
        ; A[0] * B[1]
        mulx	rbx, rcx, rax
        adox	r12, rcx
        ; A[2] * B[1]
        mulx	rsi, rcx, QWORD PTR [r8+16]
        adox	r13, rbx
        adcx	r14, rcx
        ; A[1] * B[2]
        mov	rdx, QWORD PTR [rsp+48]
        mulx	rbx, rcx, QWORD PTR [r8+8]
        adcx	r15, rsi
        adox	r14, rcx
        adcx	rdi, rbp
        adox	r15, rbx
        ; A[0] * B[2]
        mulx	rbx, rcx, rax
        adox	rdi, rbp
        xor	rsi, rsi
        adcx	r13, rcx
        ; A[1] * B[1]
        mov	rdx, QWORD PTR [rsp+40]
        mulx	rcx, rdx, QWORD PTR [r8+8]
        adcx	r14, rbx
        adox	r13, rdx
        ; A[1] * B[3]
        mov	rdx, QWORD PTR [rsp+56]
        adox	r14, rcx
        mulx	rbx, rcx, QWORD PTR [r8+8]
        adcx	r15, rcx
        ; A[2] * B[2]
        mov	rdx, QWORD PTR [rsp+48]
        mulx	rcx, rdx, QWORD PTR [r8+16]
        adcx	rdi, rbx
        adox	r15, rdx
        ; A[3] * B[3]
        mov	rdx, QWORD PTR [rsp+56]
        adox	rdi, rcx
        mulx	rbx, rcx, QWORD PTR [r8+24]
        adox	rsi, rbp
        adcx	rsi, rcx
        ; A[0] * B[3]
        mulx	rcx, rdx, rax
        adcx	rbp, rbx
        xor	rbx, rbx
        adcx	r14, rdx
        ; A[3] * B[0]
        mov	rdx, QWORD PTR [r8+24]
        adcx	r15, rcx
        mulx	rcx, rdx, QWORD PTR [rsp+32]
        adox	r14, rdx
        adox	r15, rcx
        ; A[3] * B[2]
        mov	rdx, QWORD PTR [r8+24]
        mulx	rcx, rdx, QWORD PTR [rsp+48]
        adcx	rdi, rdx
        ; A[2] * B[3]
        mov	rdx, QWORD PTR [rsp+56]
        adcx	rsi, rcx
        mulx	rdx, rcx, QWORD PTR [r8+16]
        adcx	rbp, rbx
        adox	rdi, rcx
        adox	rsi, rdx
        adox	rbp, rbx
        mov	rdx, 38
        mulx	rcx, rbp, rbp
        add	r14, rbp
        adc	rcx, 0
        mov	rbx, 9223372036854775807
        shld	rcx, r14, 1
        imul	rcx, rcx, 19
        and	r14, rbx
        xor	rbx, rbx
        adox	r11, rcx
        mulx	r15, rcx, r15
        adcx	r11, rcx
        adox	r12, r15
        mulx	rdi, rcx, rdi
        adcx	r12, rcx
        adox	r13, rdi
        mulx	rsi, rcx, rsi
        adcx	r13, rcx
        adox	r14, rsi
        adcx	r14, rbx
        ; Store
        mov	QWORD PTR [rsp+32], r11
        mov	QWORD PTR [rsp+40], r12
        mov	QWORD PTR [rsp+48], r13
        mov	QWORD PTR [rsp+56], r14
        mov	rax, QWORD PTR [rsp+96]
        ; Multiply
        ; A[0] * B[0]
        mov	rdx, QWORD PTR [rsp+128]
        mulx	r12, r11, rax
        ; A[2] * B[0]
        mulx	r14, r13, QWORD PTR [rsp+112]
        ; A[1] * B[0]
        mulx	rbx, rcx, QWORD PTR [rsp+104]
        xor	rbp, rbp
        adcx	r12, rcx
        ; A[3] * B[1]
        mov	rdx, QWORD PTR [rsp+136]
        mulx	rdi, r15, QWORD PTR [rsp+120]
        adcx	r13, rbx
        ; A[0] * B[1]
        mulx	rbx, rcx, rax
        adox	r12, rcx
        ; A[2] * B[1]
        mulx	rsi, rcx, QWORD PTR [rsp+112]
        adox	r13, rbx
        adcx	r14, rcx
        ; A[1] * B[2]
        mov	rdx, QWORD PTR [rsp+144]
        mulx	rbx, rcx, QWORD PTR [rsp+104]
        adcx	r15, rsi
        adox	r14, rcx
        adcx	rdi, rbp
        adox	r15, rbx
        ; A[0] * B[2]
        mulx	rbx, rcx, rax
        adox	rdi, rbp
        xor	rsi, rsi
        adcx	r13, rcx
        ; A[1] * B[1]
        mov	rdx, QWORD PTR [rsp+136]
        mulx	rcx, rdx, QWORD PTR [rsp+104]
        adcx	r14, rbx
        adox	r13, rdx
        ; A[1] * B[3]
        mov	rdx, QWORD PTR [rsp+152]
        adox	r14, rcx
        mulx	rbx, rcx, QWORD PTR [rsp+104]
        adcx	r15, rcx
        ; A[2] * B[2]
        mov	rdx, QWORD PTR [rsp+144]
        mulx	rcx, rdx, QWORD PTR [rsp+112]
        adcx	rdi, rbx
        adox	r15, rdx
        ; A[3] * B[3]
        mov	rdx, QWORD PTR [rsp+152]
        adox	rdi, rcx
        mulx	rbx, rcx, QWORD PTR [rsp+120]
        adox	rsi, rbp
        adcx	rsi, rcx
        ; A[0] * B[3]
        mulx	rcx, rdx, rax
        adcx	rbp, rbx
        xor	rbx, rbx
        adcx	r14, rdx
        ; A[3] * B[0]
        mov	rdx, QWORD PTR [rsp+120]
        adcx	r15, rcx
        mulx	rcx, rdx, QWORD PTR [rsp+128]
        adox	r14, rdx
        adox	r15, rcx
        ; A[3] * B[2]
        mov	rdx, QWORD PTR [rsp+120]
        mulx	rcx, rdx, QWORD PTR [rsp+144]
        adcx	rdi, rdx
        ; A[2] * B[3]
        mov	rdx, QWORD PTR [rsp+152]
        adcx	rsi, rcx
        mulx	rdx, rcx, QWORD PTR [rsp+112]
        adcx	rbp, rbx
        adox	rdi, rcx
        adox	rsi, rdx
        adox	rbp, rbx
        mov	rdx, 38
        mulx	rcx, rbp, rbp
        add	r14, rbp
        adc	rcx, 0
        mov	rbx, 9223372036854775807
        shld	rcx, r14, 1
        imul	rcx, rcx, 19
        and	r14, rbx
        xor	rbx, rbx
        adox	r11, rcx
        mulx	r15, rcx, r15
        adcx	r11, rcx
        adox	r12, r15
        mulx	rdi, rcx, rdi
        adcx	r12, rcx
        adox	r13, rdi
        mulx	rsi, rcx, rsi
        adcx	r13, rcx
        adox	r14, rsi
        adcx	r14, rbx
        ; Store
        mov	QWORD PTR [rsp], r11
        mov	QWORD PTR [rsp+8], r12
        mov	QWORD PTR [rsp+16], r13
        mov	QWORD PTR [rsp+24], r14
        mov	rbx, QWORD PTR [rsp+160]
        dec	rbx
        cmp	rbx, 3
        jge	L_curve25519_avx2_bits
        mov	QWORD PTR [rsp+160], 2
        mov	rax, QWORD PTR [rsp+176]
        neg	rax
        ; Conditional Swap
        mov	r11, QWORD PTR [r9]
        mov	r12, QWORD PTR [r9+8]
        mov	r13, QWORD PTR [r9+16]
        mov	r14, QWORD PTR [r9+24]
        mov	r15, QWORD PTR [rsp]
        mov	rdi, QWORD PTR [rsp+8]
        mov	rsi, QWORD PTR [rsp+16]
        mov	rbp, QWORD PTR [rsp+24]
        xor	r11, QWORD PTR [rsp+64]
        xor	r12, QWORD PTR [rsp+72]
        xor	r13, QWORD PTR [rsp+80]
        xor	r14, QWORD PTR [rsp+88]
        xor	r15, QWORD PTR [rsp+32]
        xor	rdi, QWORD PTR [rsp+40]
        xor	rsi, QWORD PTR [rsp+48]
        xor	rbp, QWORD PTR [rsp+56]
        and	r11, rax
        and	r12, rax
        and	r13, rax
        and	r14, rax
        and	r15, rax
        and	rdi, rax
        and	rsi, rax
        and	rbp, rax
        xor	QWORD PTR [r9], r11
        xor	QWORD PTR [r9+8], r12
        xor	QWORD PTR [r9+16], r13
        xor	QWORD PTR [r9+24], r14
        xor	QWORD PTR [rsp], r15
        xor	QWORD PTR [rsp+8], rdi
        xor	QWORD PTR [rsp+16], rsi
        xor	QWORD PTR [rsp+24], rbp
        xor	QWORD PTR [rsp+64], r11
        xor	QWORD PTR [rsp+72], r12
        xor	QWORD PTR [rsp+80], r13
        xor	QWORD PTR [rsp+88], r14
        xor	QWORD PTR [rsp+32], r15
        xor	QWORD PTR [rsp+40], rdi
        xor	QWORD PTR [rsp+48], rsi
        xor	QWORD PTR [rsp+56], rbp
L_curve25519_avx2_last_3:
        ; Add-Sub
        ; Add
        mov	r11, QWORD PTR [r9]
        mov	r12, QWORD PTR [r9+8]
        mov	r13, QWORD PTR [r9+16]
        mov	r14, QWORD PTR [r9+24]
        mov	r15, r11
        add	r11, QWORD PTR [rsp]
        mov	rdi, r12
        adc	r12, QWORD PTR [rsp+8]
        mov	rsi, r13
        adc	r13, QWORD PTR [rsp+16]
        mov	rbp, r14
        adc	r14, QWORD PTR [rsp+24]
        mov	rbx, 0
        adc	rbx, 0
        shld	rbx, r14, 1
        imul	rbx, 19
        btr	r14, 63
        ;   Sub modulus (if overflow)
        add	r11, rbx
        adc	r12, 0
        adc	r13, 0
        adc	r14, 0
        ; Sub
        sub	r15, QWORD PTR [rsp]
        sbb	rdi, QWORD PTR [rsp+8]
        sbb	rsi, QWORD PTR [rsp+16]
        sbb	rbp, QWORD PTR [rsp+24]
        sbb	rbx, rbx
        shld	rbx, rbp, 1
        imul	rbx, -19
        btr	rbp, 63
        ;   Add modulus (if underflow)
        sub	r15, rbx
        sbb	rdi, 0
        sbb	rsi, 0
        sbb	rbp, 0
        mov	QWORD PTR [r9], r11
        mov	QWORD PTR [r9+8], r12
        mov	QWORD PTR [r9+16], r13
        mov	QWORD PTR [r9+24], r14
        mov	QWORD PTR [rsp+128], r15
        mov	QWORD PTR [rsp+136], rdi
        mov	QWORD PTR [rsp+144], rsi
        mov	QWORD PTR [rsp+152], rbp
        ; Square
        mov	rdx, QWORD PTR [rsp+128]
        mov	rax, QWORD PTR [rsp+136]
        ; A[0] * A[1]
        mov	rbp, rdx
        mulx	r13, r12, rax
        ; A[0] * A[3]
        mulx	r15, r14, QWORD PTR [rsp+152]
        ; A[2] * A[1]
        mov	rdx, QWORD PTR [rsp+144]
        mulx	rbx, rcx, rax
        xor	r11, r11
        adox	r14, rcx
        ; A[2] * A[3]
        mulx	rsi, rdi, QWORD PTR [rsp+152]
        adox	r15, rbx
        ; A[2] * A[0]
        mulx	rbx, rcx, rbp
        adox	rdi, r11
        adcx	r13, rcx
        adox	rsi, r11
        ; A[1] * A[3]
        mov	rdx, rax
        mulx	rdx, rcx, QWORD PTR [rsp+152]
        adcx	r14, rbx
        adcx	r15, rcx
        adcx	rdi, rdx
        adcx	rsi, r11
        ; A[0] * A[0]
        mov	rdx, rbp
        mulx	rcx, r11, rdx
        xor	rbp, rbp
        adcx	r12, r12
        ; A[1] * A[1]
        mov	rdx, rax
        adox	r12, rcx
        mulx	rbx, rcx, rdx
        adcx	r13, r13
        adox	r13, rcx
        adcx	r14, r14
        ; A[2] * A[2]
        mov	rdx, QWORD PTR [rsp+144]
        adox	r14, rbx
        mulx	rcx, rbx, rdx
        adcx	r15, r15
        adox	r15, rbx
        adcx	rdi, rdi
        ; A[3] * A[3]
        mov	rdx, QWORD PTR [rsp+152]
        adox	rdi, rcx
        mulx	rbx, rcx, rdx
        adcx	rsi, rsi
        adox	rsi, rcx
        adcx	rbp, rbp
        adox	rbp, rbx
        mov	rdx, 38
        mulx	rbx, rbp, rbp
        add	r14, rbp
        adc	rbx, 0
        mov	rcx, 9223372036854775807
        shld	rbx, r14, 1
        imul	rbx, rbx, 19
        and	r14, rcx
        xor	rcx, rcx
        adox	r11, rbx
        mulx	r15, rbx, r15
        adcx	r11, rbx
        adox	r12, r15
        mulx	rdi, rbx, rdi
        adcx	r12, rbx
        adox	r13, rdi
        mulx	rsi, rbx, rsi
        adcx	r13, rbx
        adox	r14, rsi
        adcx	r14, rcx
        ; Store
        mov	QWORD PTR [rsp+96], r11
        mov	QWORD PTR [rsp+104], r12
        mov	QWORD PTR [rsp+112], r13
        mov	QWORD PTR [rsp+120], r14
        ; Square
        mov	rdx, QWORD PTR [r9]
        mov	rax, QWORD PTR [r9+8]
        ; A[0] * A[1]
        mov	rbp, rdx
        mulx	r13, r12, rax
        ; A[0] * A[3]
        mulx	r15, r14, QWORD PTR [r9+24]
        ; A[2] * A[1]
        mov	rdx, QWORD PTR [r9+16]
        mulx	rbx, rcx, rax
        xor	r11, r11
        adox	r14, rcx
        ; A[2] * A[3]
        mulx	rsi, rdi, QWORD PTR [r9+24]
        adox	r15, rbx
        ; A[2] * A[0]
        mulx	rbx, rcx, rbp
        adox	rdi, r11
        adcx	r13, rcx
        adox	rsi, r11
        ; A[1] * A[3]
        mov	rdx, rax
        mulx	rdx, rcx, QWORD PTR [r9+24]
        adcx	r14, rbx
        adcx	r15, rcx
        adcx	rdi, rdx
        adcx	rsi, r11
        ; A[0] * A[0]
        mov	rdx, rbp
        mulx	rcx, r11, rdx
        xor	rbp, rbp
        adcx	r12, r12
        ; A[1] * A[1]
        mov	rdx, rax
        adox	r12, rcx
        mulx	rbx, rcx, rdx
        adcx	r13, r13
        adox	r13, rcx
        adcx	r14, r14
        ; A[2] * A[2]
        mov	rdx, QWORD PTR [r9+16]
        adox	r14, rbx
        mulx	rcx, rbx, rdx
        adcx	r15, r15
        adox	r15, rbx
        adcx	rdi, rdi
        ; A[3] * A[3]
        mov	rdx, QWORD PTR [r9+24]
        adox	rdi, rcx
        mulx	rbx, rcx, rdx
        adcx	rsi, rsi
        adox	rsi, rcx
        adcx	rbp, rbp
        adox	rbp, rbx
        mov	rdx, 38
        mulx	rbx, rbp, rbp
        add	r14, rbp
        adc	rbx, 0
        mov	rcx, 9223372036854775807
        shld	rbx, r14, 1
        imul	rbx, rbx, 19
        and	r14, rcx
        xor	rcx, rcx
        adox	r11, rbx
        mulx	r15, rbx, r15
        adcx	r11, rbx
        adox	r12, r15
        mulx	rdi, rbx, rdi
        adcx	r12, rbx
        adox	r13, rdi
        mulx	rsi, rbx, rsi
        adcx	r13, rbx
        adox	r14, rsi
        adcx	r14, rcx
        ; Store
        mov	QWORD PTR [rsp+128], r11
        mov	QWORD PTR [rsp+136], r12
        mov	QWORD PTR [rsp+144], r13
        mov	QWORD PTR [rsp+152], r14
        mov	rax, QWORD PTR [rsp+128]
        ; Multiply
        ; A[0] * B[0]
        mov	rdx, QWORD PTR [rsp+96]
        mulx	r12, r11, rax
        ; A[2] * B[0]
        mulx	r14, r13, QWORD PTR [rsp+144]
        ; A[1] * B[0]
        mulx	rbx, rcx, QWORD PTR [rsp+136]
        xor	rbp, rbp
        adcx	r12, rcx
        ; A[3] * B[1]
        mov	rdx, QWORD PTR [rsp+104]
        mulx	rdi, r15, QWORD PTR [rsp+152]
        adcx	r13, rbx
        ; A[0] * B[1]
        mulx	rbx, rcx, rax
        adox	r12, rcx
        ; A[2] * B[1]
        mulx	rsi, rcx, QWORD PTR [rsp+144]
        adox	r13, rbx
        adcx	r14, rcx
        ; A[1] * B[2]
        mov	rdx, QWORD PTR [rsp+112]
        mulx	rbx, rcx, QWORD PTR [rsp+136]
        adcx	r15, rsi
        adox	r14, rcx
        adcx	rdi, rbp
        adox	r15, rbx
        ; A[0] * B[2]
        mulx	rbx, rcx, rax
        adox	rdi, rbp
        xor	rsi, rsi
        adcx	r13, rcx
        ; A[1] * B[1]
        mov	rdx, QWORD PTR [rsp+104]
        mulx	rcx, rdx, QWORD PTR [rsp+136]
        adcx	r14, rbx
        adox	r13, rdx
        ; A[1] * B[3]
        mov	rdx, QWORD PTR [rsp+120]
        adox	r14, rcx
        mulx	rbx, rcx, QWORD PTR [rsp+136]
        adcx	r15, rcx
        ; A[2] * B[2]
        mov	rdx, QWORD PTR [rsp+112]
        mulx	rcx, rdx, QWORD PTR [rsp+144]
        adcx	rdi, rbx
        adox	r15, rdx
        ; A[3] * B[3]
        mov	rdx, QWORD PTR [rsp+120]
        adox	rdi, rcx
        mulx	rbx, rcx, QWORD PTR [rsp+152]
        adox	rsi, rbp
        adcx	rsi, rcx
        ; A[0] * B[3]
        mulx	rcx, rdx, rax
        adcx	rbp, rbx
        xor	rbx, rbx
        adcx	r14, rdx
        ; A[3] * B[0]
        mov	rdx, QWORD PTR [rsp+152]
        adcx	r15, rcx
        mulx	rcx, rdx, QWORD PTR [rsp+96]
        adox	r14, rdx
        adox	r15, rcx
        ; A[3] * B[2]
        mov	rdx, QWORD PTR [rsp+152]
        mulx	rcx, rdx, QWORD PTR [rsp+112]
        adcx	rdi, rdx
        ; A[2] * B[3]
        mov	rdx, QWORD PTR [rsp+120]
        adcx	rsi, rcx
        mulx	rdx, rcx, QWORD PTR [rsp+144]
        adcx	rbp, rbx
        adox	rdi, rcx
        adox	rsi, rdx
        adox	rbp, rbx
        mov	rdx, 38
        mulx	rcx, rbp, rbp
        add	r14, rbp
        adc	rcx, 0
        mov	rbx, 9223372036854775807
        shld	rcx, r14, 1
        imul	rcx, rcx, 19
        and	r14, rbx
        xor	rbx, rbx
        adox	r11, rcx
        mulx	r15, rcx, r15
        adcx	r11, rcx
        adox	r12, r15
        mulx	rdi, rcx, rdi
        adcx	r12, rcx
        adox	r13, rdi
        mulx	rsi, rcx, rsi
        adcx	r13, rcx
        adox	r14, rsi
        adcx	r14, rbx
        ; Store
        mov	QWORD PTR [r9], r11
        mov	QWORD PTR [r9+8], r12
        mov	QWORD PTR [r9+16], r13
        mov	QWORD PTR [r9+24], r14
        ; Sub
        mov	r11, QWORD PTR [rsp+128]
        mov	r12, QWORD PTR [rsp+136]
        mov	r13, QWORD PTR [rsp+144]
        mov	r14, QWORD PTR [rsp+152]
        sub	r11, QWORD PTR [rsp+96]
        sbb	r12, QWORD PTR [rsp+104]
        sbb	r13, QWORD PTR [rsp+112]
        sbb	r14, QWORD PTR [rsp+120]
        sbb	rbx, rbx
        shld	rbx, r14, 1
        imul	rbx, -19
        btr	r14, 63
        ;   Add modulus (if underflow)
        sub	r11, rbx
        sbb	r12, 0
        sbb	r13, 0
        sbb	r14, 0
        mov	QWORD PTR [rsp+128], r11
        mov	QWORD PTR [rsp+136], r12
        mov	QWORD PTR [rsp+144], r13
        mov	QWORD PTR [rsp+152], r14
        mov	rdx, 121666
        mulx	rbp, r11, QWORD PTR [rsp+128]
        mulx	rsi, r12, QWORD PTR [rsp+136]
        mulx	rdi, r13, QWORD PTR [rsp+144]
        add	r12, rbp
        mulx	r15, r14, QWORD PTR [rsp+152]
        adc	r13, rsi
        adc	r14, rdi
        adc	r15, 0
        add	r11, QWORD PTR [rsp+96]
        adc	r12, QWORD PTR [rsp+104]
        adc	r13, QWORD PTR [rsp+112]
        adc	r14, QWORD PTR [rsp+120]
        adc	r15, 0
        shld	r15, r14, 1
        btr	r14, 63
        imul	r15, r15, 19
        add	r11, r15
        adc	r12, 0
        adc	r13, 0
        adc	r14, 0
        mov	QWORD PTR [rsp+96], r11
        mov	QWORD PTR [rsp+104], r12
        mov	QWORD PTR [rsp+112], r13
        mov	QWORD PTR [rsp+120], r14
        mov	rax, QWORD PTR [rsp+96]
        ; Multiply
        ; A[0] * B[0]
        mov	rdx, QWORD PTR [rsp+128]
        mulx	r12, r11, rax
        ; A[2] * B[0]
        mulx	r14, r13, QWORD PTR [rsp+112]
        ; A[1] * B[0]
        mulx	rbx, rcx, QWORD PTR [rsp+104]
        xor	rbp, rbp
        adcx	r12, rcx
        ; A[3] * B[1]
        mov	rdx, QWORD PTR [rsp+136]
        mulx	rdi, r15, QWORD PTR [rsp+120]
        adcx	r13, rbx
        ; A[0] * B[1]
        mulx	rbx, rcx, rax
        adox	r12, rcx
        ; A[2] * B[1]
        mulx	rsi, rcx, QWORD PTR [rsp+112]
        adox	r13, rbx
        adcx	r14, rcx
        ; A[1] * B[2]
        mov	rdx, QWORD PTR [rsp+144]
        mulx	rbx, rcx, QWORD PTR [rsp+104]
        adcx	r15, rsi
        adox	r14, rcx
        adcx	rdi, rbp
        adox	r15, rbx
        ; A[0] * B[2]
        mulx	rbx, rcx, rax
        adox	rdi, rbp
        xor	rsi, rsi
        adcx	r13, rcx
        ; A[1] * B[1]
        mov	rdx, QWORD PTR [rsp+136]
        mulx	rcx, rdx, QWORD PTR [rsp+104]
        adcx	r14, rbx
        adox	r13, rdx
        ; A[1] * B[3]
        mov	rdx, QWORD PTR [rsp+152]
        adox	r14, rcx
        mulx	rbx, rcx, QWORD PTR [rsp+104]
        adcx	r15, rcx
        ; A[2] * B[2]
        mov	rdx, QWORD PTR [rsp+144]
        mulx	rcx, rdx, QWORD PTR [rsp+112]
        adcx	rdi, rbx
        adox	r15, rdx
        ; A[3] * B[3]
        mov	rdx, QWORD PTR [rsp+152]
        adox	rdi, rcx
        mulx	rbx, rcx, QWORD PTR [rsp+120]
        adox	rsi, rbp
        adcx	rsi, rcx
        ; A[0] * B[3]
        mulx	rcx, rdx, rax
        adcx	rbp, rbx
        xor	rbx, rbx
        adcx	r14, rdx
        ; A[3] * B[0]
        mov	rdx, QWORD PTR [rsp+120]
        adcx	r15, rcx
        mulx	rcx, rdx, QWORD PTR [rsp+128]
        adox	r14, rdx
        adox	r15, rcx
        ; A[3] * B[2]
        mov	rdx, QWORD PTR [rsp+120]
        mulx	rcx, rdx, QWORD PTR [rsp+144]
        adcx	rdi, rdx
        ; A[2] * B[3]
        mov	rdx, QWORD PTR [rsp+152]
        adcx	rsi, rcx
        mulx	rdx, rcx, QWORD PTR [rsp+112]
        adcx	rbp, rbx
        adox	rdi, rcx
        adox	rsi, rdx
        adox	rbp, rbx
        mov	rdx, 38
        mulx	rcx, rbp, rbp
        add	r14, rbp
        adc	rcx, 0
        mov	rbx, 9223372036854775807
        shld	rcx, r14, 1
        imul	rcx, rcx, 19
        and	r14, rbx
        xor	rbx, rbx
        adox	r11, rcx
        mulx	r15, rcx, r15
        adcx	r11, rcx
        adox	r12, r15
        mulx	rdi, rcx, rdi
        adcx	r12, rcx
        adox	r13, rdi
        mulx	rsi, rcx, rsi
        adcx	r13, rcx
        adox	r14, rsi
        adcx	r14, rbx
        ; Store
        mov	QWORD PTR [rsp], r11
        mov	QWORD PTR [rsp+8], r12
        mov	QWORD PTR [rsp+16], r13
        mov	QWORD PTR [rsp+24], r14
        dec	QWORD PTR [rsp+160]
        jge	L_curve25519_avx2_last_3
        ; Invert
        lea	rcx, QWORD PTR [rsp+32]
        mov	rdx, rsp
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+32]
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+64]
        mov	rdx, rsp
        lea	r8, QWORD PTR [rsp+64]
        call	fe_mul_avx2
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        lea	r8, QWORD PTR [rsp+64]
        call	fe_mul_avx2
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+32]
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        lea	r8, QWORD PTR [rsp+96]
        call	fe_mul_avx2
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+64]
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 4
        call	fe_sq_n_avx2
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        call	fe_mul_avx2
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+64]
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 9
        call	fe_sq_n_avx2
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        call	fe_mul_avx2
        lea	rcx, QWORD PTR [rsp+128]
        lea	rdx, QWORD PTR [rsp+96]
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+128]
        lea	rdx, QWORD PTR [rsp+128]
        mov	r8, 19
        call	fe_sq_n_avx2
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+128]
        lea	r8, QWORD PTR [rsp+96]
        call	fe_mul_avx2
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 9
        call	fe_sq_n_avx2
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        call	fe_mul_avx2
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+64]
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 49
        call	fe_sq_n_avx2
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        call	fe_mul_avx2
        lea	rcx, QWORD PTR [rsp+128]
        lea	rdx, QWORD PTR [rsp+96]
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+128]
        lea	rdx, QWORD PTR [rsp+128]
        mov	r8, 99
        call	fe_sq_n_avx2
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+128]
        lea	r8, QWORD PTR [rsp+96]
        call	fe_mul_avx2
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 49
        call	fe_sq_n_avx2
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        call	fe_mul_avx2
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        mov	r8, 4
        call	fe_sq_n_avx2
        mov	rcx, rsp
        lea	rdx, QWORD PTR [rsp+64]
        lea	r8, QWORD PTR [rsp+32]
        call	fe_mul_avx2
        mov	r9, QWORD PTR [rsp+168]
        mov	rax, QWORD PTR [r9]
        ; Multiply
        ; A[0] * B[0]
        mov	rdx, QWORD PTR [rsp]
        mulx	r12, r11, rax
        ; A[2] * B[0]
        mulx	r14, r13, QWORD PTR [r9+16]
        ; A[1] * B[0]
        mulx	rbx, rcx, QWORD PTR [r9+8]
        xor	rbp, rbp
        adcx	r12, rcx
        ; A[3] * B[1]
        mov	rdx, QWORD PTR [rsp+8]
        mulx	rdi, r15, QWORD PTR [r9+24]
        adcx	r13, rbx
        ; A[0] * B[1]
        mulx	rbx, rcx, rax
        adox	r12, rcx
        ; A[2] * B[1]
        mulx	rsi, rcx, QWORD PTR [r9+16]
        adox	r13, rbx
        adcx	r14, rcx
        ; A[1] * B[2]
        mov	rdx, QWORD PTR [rsp+16]
        mulx	rbx, rcx, QWORD PTR [r9+8]
        adcx	r15, rsi
        adox	r14, rcx
        adcx	rdi, rbp
        adox	r15, rbx
        ; A[0] * B[2]
        mulx	rbx, rcx, rax
        adox	rdi, rbp
        xor	rsi, rsi
        adcx	r13, rcx
        ; A[1] * B[1]
        mov	rdx, QWORD PTR [rsp+8]
        mulx	rcx, rdx, QWORD PTR [r9+8]
        adcx	r14, rbx
        adox	r13, rdx
        ; A[1] * B[3]
        mov	rdx, QWORD PTR [rsp+24]
        adox	r14, rcx
        mulx	rbx, rcx, QWORD PTR [r9+8]
        adcx	r15, rcx
        ; A[2] * B[2]
        mov	rdx, QWORD PTR [rsp+16]
        mulx	rcx, rdx, QWORD PTR [r9+16]
        adcx	rdi, rbx
        adox	r15, rdx
        ; A[3] * B[3]
        mov	rdx, QWORD PTR [rsp+24]
        adox	rdi, rcx
        mulx	rbx, rcx, QWORD PTR [r9+24]
        adox	rsi, rbp
        adcx	rsi, rcx
        ; A[0] * B[3]
        mulx	rcx, rdx, rax
        adcx	rbp, rbx
        xor	rbx, rbx
        adcx	r14, rdx
        ; A[3] * B[0]
        mov	rdx, QWORD PTR [r9+24]
        adcx	r15, rcx
        mulx	rcx, rdx, QWORD PTR [rsp]
        adox	r14, rdx
        adox	r15, rcx
        ; A[3] * B[2]
        mov	rdx, QWORD PTR [r9+24]
        mulx	rcx, rdx, QWORD PTR [rsp+16]
        adcx	rdi, rdx
        ; A[2] * B[3]
        mov	rdx, QWORD PTR [rsp+24]
        adcx	rsi, rcx
        mulx	rdx, rcx, QWORD PTR [r9+16]
        adcx	rbp, rbx
        adox	rdi, rcx
        adox	rsi, rdx
        adox	rbp, rbx
        mov	rdx, 38
        mulx	rcx, rbp, rbp
        add	r14, rbp
        adc	rcx, 0
        mov	rbx, 9223372036854775807
        shld	rcx, r14, 1
        imul	rcx, rcx, 19
        and	r14, rbx
        xor	rbx, rbx
        adox	r11, rcx
        mulx	r15, rcx, r15
        adcx	r11, rcx
        adox	r12, r15
        mulx	rdi, rcx, rdi
        adcx	r12, rcx
        adox	r13, rdi
        mulx	rsi, rcx, rsi
        adcx	r13, rcx
        adox	r14, rsi
        adcx	r14, rbx
        mov	rbx, 9223372036854775807
        mov	rdx, r14
        sar	rdx, 63
        and	rdx, 19
        and	r14, rbx
        add	r11, rdx
        adc	r12, 0
        adc	r13, 0
        adc	r14, 0
        mov	rcx, 9223372036854775807
        mov	rdx, r11
        add	rdx, 19
        mov	rdx, r12
        adc	rdx, 0
        mov	rdx, r13
        adc	rdx, 0
        mov	rdx, r14
        adc	rdx, 0
        sar	rdx, 63
        and	rdx, 19
        and	r14, rcx
        add	r11, rdx
        adc	r12, 0
        adc	r13, 0
        adc	r14, 0
        and	r14, rcx
        ; Store
        mov	QWORD PTR [r9], r11
        mov	QWORD PTR [r9+8], r12
        mov	QWORD PTR [r9+16], r13
        mov	QWORD PTR [r9+24], r14
        xor	rax, rax
        add	rsp, 184
        pop	rbp
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        pop	rbx
        ret
curve25519_avx2 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
fe_pow22523_avx2 PROC
        sub	rsp, 112
        ; pow22523
        mov	QWORD PTR [rsp+96], rcx
        mov	QWORD PTR [rsp+104], rdx
        mov	rcx, rsp
        mov	rdx, QWORD PTR [rsp+104]
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+32]
        mov	rdx, rsp
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+32]
        mov	rdx, QWORD PTR [rsp+104]
        lea	r8, QWORD PTR [rsp+32]
        call	fe_mul_avx2
        mov	rcx, rsp
        mov	rdx, rsp
        lea	r8, QWORD PTR [rsp+32]
        call	fe_mul_avx2
        mov	rcx, rsp
        mov	rdx, rsp
        call	fe_sq_avx2
        mov	rcx, rsp
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, rsp
        call	fe_mul_avx2
        lea	rcx, QWORD PTR [rsp+32]
        mov	rdx, rsp
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, 4
        call	fe_sq_n_avx2
        mov	rcx, rsp
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, rsp
        call	fe_mul_avx2
        lea	rcx, QWORD PTR [rsp+32]
        mov	rdx, rsp
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, 9
        call	fe_sq_n_avx2
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, rsp
        call	fe_mul_avx2
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+32]
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        mov	r8, 19
        call	fe_sq_n_avx2
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+64]
        lea	r8, QWORD PTR [rsp+32]
        call	fe_mul_avx2
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, 9
        call	fe_sq_n_avx2
        mov	rcx, rsp
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, rsp
        call	fe_mul_avx2
        lea	rcx, QWORD PTR [rsp+32]
        mov	rdx, rsp
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, 49
        call	fe_sq_n_avx2
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, rsp
        call	fe_mul_avx2
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+32]
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        mov	r8, 99
        call	fe_sq_n_avx2
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+64]
        lea	r8, QWORD PTR [rsp+32]
        call	fe_mul_avx2
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        call	fe_sq_avx2
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, 49
        call	fe_sq_n_avx2
        mov	rcx, rsp
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, rsp
        call	fe_mul_avx2
        mov	rcx, rsp
        mov	rdx, rsp
        call	fe_sq_avx2
        mov	rcx, rsp
        mov	rdx, rsp
        call	fe_sq_avx2
        mov	rcx, QWORD PTR [rsp+96]
        mov	rdx, rsp
        mov	r8, QWORD PTR [rsp+104]
        call	fe_mul_avx2
        mov	rdx, QWORD PTR [rsp+104]
        mov	rcx, QWORD PTR [rsp+96]
        add	rsp, 112
        ret
fe_pow22523_avx2 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
ge_p1p1_to_p2_avx2 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        push	rbp
        mov	rax, rdx
        sub	rsp, 16
        mov	QWORD PTR [rsp], rcx
        mov	QWORD PTR [rsp+8], rax
        lea	r8, QWORD PTR [rax+96]
        mov	r11, QWORD PTR [rax]
        ; Multiply
        ; A[0] * B[0]
        mov	rdx, QWORD PTR [r8]
        mulx	r13, r12, r11
        ; A[2] * B[0]
        mulx	r15, r14, QWORD PTR [rax+16]
        ; A[1] * B[0]
        mulx	r10, r9, QWORD PTR [rax+8]
        xor	rbp, rbp
        adcx	r13, r9
        ; A[3] * B[1]
        mov	rdx, QWORD PTR [r8+8]
        mulx	rsi, rdi, QWORD PTR [rax+24]
        adcx	r14, r10
        ; A[0] * B[1]
        mulx	r10, r9, r11
        adox	r13, r9
        ; A[2] * B[1]
        mulx	rbx, r9, QWORD PTR [rax+16]
        adox	r14, r10
        adcx	r15, r9
        ; A[1] * B[2]
        mov	rdx, QWORD PTR [r8+16]
        mulx	r10, r9, QWORD PTR [rax+8]
        adcx	rdi, rbx
        adox	r15, r9
        adcx	rsi, rbp
        adox	rdi, r10
        ; A[0] * B[2]
        mulx	r10, r9, r11
        adox	rsi, rbp
        xor	rbx, rbx
        adcx	r14, r9
        ; A[1] * B[1]
        mov	rdx, QWORD PTR [r8+8]
        mulx	r9, rdx, QWORD PTR [rax+8]
        adcx	r15, r10
        adox	r14, rdx
        ; A[1] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	r15, r9
        mulx	r10, r9, QWORD PTR [rax+8]
        adcx	rdi, r9
        ; A[2] * B[2]
        mov	rdx, QWORD PTR [r8+16]
        mulx	r9, rdx, QWORD PTR [rax+16]
        adcx	rsi, r10
        adox	rdi, rdx
        ; A[3] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	rsi, r9
        mulx	r10, r9, QWORD PTR [rax+24]
        adox	rbx, rbp
        adcx	rbx, r9
        ; A[0] * B[3]
        mulx	r9, rdx, r11
        adcx	rbp, r10
        xor	r10, r10
        adcx	r15, rdx
        ; A[3] * B[0]
        mov	rdx, QWORD PTR [rax+24]
        adcx	rdi, r9
        mulx	r9, rdx, QWORD PTR [r8]
        adox	r15, rdx
        adox	rdi, r9
        ; A[3] * B[2]
        mov	rdx, QWORD PTR [rax+24]
        mulx	r9, rdx, QWORD PTR [r8+16]
        adcx	rsi, rdx
        ; A[2] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adcx	rbx, r9
        mulx	rdx, r9, QWORD PTR [rax+16]
        adcx	rbp, r10
        adox	rsi, r9
        adox	rbx, rdx
        adox	rbp, r10
        mov	rdx, 38
        mulx	r9, rbp, rbp
        add	r15, rbp
        adc	r9, 0
        mov	r10, 9223372036854775807
        shld	r9, r15, 1
        imul	r9, r9, 19
        and	r15, r10
        xor	r10, r10
        adox	r12, r9
        mulx	rdi, r9, rdi
        adcx	r12, r9
        adox	r13, rdi
        mulx	rsi, r9, rsi
        adcx	r13, r9
        adox	r14, rsi
        mulx	rbx, r9, rbx
        adcx	r14, r9
        adox	r15, rbx
        adcx	r15, r10
        ; Store
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        lea	rax, QWORD PTR [rax+64]
        lea	rcx, QWORD PTR [rcx+64]
        mov	r11, QWORD PTR [rax]
        ; Multiply
        ; A[0] * B[0]
        mov	rdx, QWORD PTR [r8]
        mulx	r13, r12, r11
        ; A[2] * B[0]
        mulx	r15, r14, QWORD PTR [rax+16]
        ; A[1] * B[0]
        mulx	r10, r9, QWORD PTR [rax+8]
        xor	rbp, rbp
        adcx	r13, r9
        ; A[3] * B[1]
        mov	rdx, QWORD PTR [r8+8]
        mulx	rsi, rdi, QWORD PTR [rax+24]
        adcx	r14, r10
        ; A[0] * B[1]
        mulx	r10, r9, r11
        adox	r13, r9
        ; A[2] * B[1]
        mulx	rbx, r9, QWORD PTR [rax+16]
        adox	r14, r10
        adcx	r15, r9
        ; A[1] * B[2]
        mov	rdx, QWORD PTR [r8+16]
        mulx	r10, r9, QWORD PTR [rax+8]
        adcx	rdi, rbx
        adox	r15, r9
        adcx	rsi, rbp
        adox	rdi, r10
        ; A[0] * B[2]
        mulx	r10, r9, r11
        adox	rsi, rbp
        xor	rbx, rbx
        adcx	r14, r9
        ; A[1] * B[1]
        mov	rdx, QWORD PTR [r8+8]
        mulx	r9, rdx, QWORD PTR [rax+8]
        adcx	r15, r10
        adox	r14, rdx
        ; A[1] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	r15, r9
        mulx	r10, r9, QWORD PTR [rax+8]
        adcx	rdi, r9
        ; A[2] * B[2]
        mov	rdx, QWORD PTR [r8+16]
        mulx	r9, rdx, QWORD PTR [rax+16]
        adcx	rsi, r10
        adox	rdi, rdx
        ; A[3] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	rsi, r9
        mulx	r10, r9, QWORD PTR [rax+24]
        adox	rbx, rbp
        adcx	rbx, r9
        ; A[0] * B[3]
        mulx	r9, rdx, r11
        adcx	rbp, r10
        xor	r10, r10
        adcx	r15, rdx
        ; A[3] * B[0]
        mov	rdx, QWORD PTR [rax+24]
        adcx	rdi, r9
        mulx	r9, rdx, QWORD PTR [r8]
        adox	r15, rdx
        adox	rdi, r9
        ; A[3] * B[2]
        mov	rdx, QWORD PTR [rax+24]
        mulx	r9, rdx, QWORD PTR [r8+16]
        adcx	rsi, rdx
        ; A[2] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adcx	rbx, r9
        mulx	rdx, r9, QWORD PTR [rax+16]
        adcx	rbp, r10
        adox	rsi, r9
        adox	rbx, rdx
        adox	rbp, r10
        mov	rdx, 38
        mulx	r9, rbp, rbp
        add	r15, rbp
        adc	r9, 0
        mov	r10, 9223372036854775807
        shld	r9, r15, 1
        imul	r9, r9, 19
        and	r15, r10
        xor	r10, r10
        adox	r12, r9
        mulx	rdi, r9, rdi
        adcx	r12, r9
        adox	r13, rdi
        mulx	rsi, r9, rsi
        adcx	r13, r9
        adox	r14, rsi
        mulx	rbx, r9, rbx
        adcx	r14, r9
        adox	r15, rbx
        adcx	r15, r10
        ; Store
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        lea	r8, QWORD PTR [rax+-32]
        lea	rcx, QWORD PTR [rcx+-32]
        mov	r11, QWORD PTR [rax]
        ; Multiply
        ; A[0] * B[0]
        mov	rdx, QWORD PTR [r8]
        mulx	r13, r12, r11
        ; A[2] * B[0]
        mulx	r15, r14, QWORD PTR [rax+16]
        ; A[1] * B[0]
        mulx	r10, r9, QWORD PTR [rax+8]
        xor	rbp, rbp
        adcx	r13, r9
        ; A[3] * B[1]
        mov	rdx, QWORD PTR [r8+8]
        mulx	rsi, rdi, QWORD PTR [rax+24]
        adcx	r14, r10
        ; A[0] * B[1]
        mulx	r10, r9, r11
        adox	r13, r9
        ; A[2] * B[1]
        mulx	rbx, r9, QWORD PTR [rax+16]
        adox	r14, r10
        adcx	r15, r9
        ; A[1] * B[2]
        mov	rdx, QWORD PTR [r8+16]
        mulx	r10, r9, QWORD PTR [rax+8]
        adcx	rdi, rbx
        adox	r15, r9
        adcx	rsi, rbp
        adox	rdi, r10
        ; A[0] * B[2]
        mulx	r10, r9, r11
        adox	rsi, rbp
        xor	rbx, rbx
        adcx	r14, r9
        ; A[1] * B[1]
        mov	rdx, QWORD PTR [r8+8]
        mulx	r9, rdx, QWORD PTR [rax+8]
        adcx	r15, r10
        adox	r14, rdx
        ; A[1] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	r15, r9
        mulx	r10, r9, QWORD PTR [rax+8]
        adcx	rdi, r9
        ; A[2] * B[2]
        mov	rdx, QWORD PTR [r8+16]
        mulx	r9, rdx, QWORD PTR [rax+16]
        adcx	rsi, r10
        adox	rdi, rdx
        ; A[3] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	rsi, r9
        mulx	r10, r9, QWORD PTR [rax+24]
        adox	rbx, rbp
        adcx	rbx, r9
        ; A[0] * B[3]
        mulx	r9, rdx, r11
        adcx	rbp, r10
        xor	r10, r10
        adcx	r15, rdx
        ; A[3] * B[0]
        mov	rdx, QWORD PTR [rax+24]
        adcx	rdi, r9
        mulx	r9, rdx, QWORD PTR [r8]
        adox	r15, rdx
        adox	rdi, r9
        ; A[3] * B[2]
        mov	rdx, QWORD PTR [rax+24]
        mulx	r9, rdx, QWORD PTR [r8+16]
        adcx	rsi, rdx
        ; A[2] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adcx	rbx, r9
        mulx	rdx, r9, QWORD PTR [rax+16]
        adcx	rbp, r10
        adox	rsi, r9
        adox	rbx, rdx
        adox	rbp, r10
        mov	rdx, 38
        mulx	r9, rbp, rbp
        add	r15, rbp
        adc	r9, 0
        mov	r10, 9223372036854775807
        shld	r9, r15, 1
        imul	r9, r9, 19
        and	r15, r10
        xor	r10, r10
        adox	r12, r9
        mulx	rdi, r9, rdi
        adcx	r12, r9
        adox	r13, rdi
        mulx	rsi, r9, rsi
        adcx	r13, r9
        adox	r14, rsi
        mulx	rbx, r9, rbx
        adcx	r14, r9
        adox	r15, rbx
        adcx	r15, r10
        ; Store
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        add	rsp, 16
        pop	rbp
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
ge_p1p1_to_p2_avx2 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
ge_p1p1_to_p3_avx2 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        push	rbp
        mov	rax, rdx
        sub	rsp, 16
        mov	QWORD PTR [rsp], rcx
        mov	QWORD PTR [rsp+8], rax
        lea	r8, QWORD PTR [rax+96]
        mov	r11, QWORD PTR [rax]
        ; Multiply
        ; A[0] * B[0]
        mov	rdx, QWORD PTR [r8]
        mulx	r13, r12, r11
        ; A[2] * B[0]
        mulx	r15, r14, QWORD PTR [rax+16]
        ; A[1] * B[0]
        mulx	r10, r9, QWORD PTR [rax+8]
        xor	rbp, rbp
        adcx	r13, r9
        ; A[3] * B[1]
        mov	rdx, QWORD PTR [r8+8]
        mulx	rsi, rdi, QWORD PTR [rax+24]
        adcx	r14, r10
        ; A[0] * B[1]
        mulx	r10, r9, r11
        adox	r13, r9
        ; A[2] * B[1]
        mulx	rbx, r9, QWORD PTR [rax+16]
        adox	r14, r10
        adcx	r15, r9
        ; A[1] * B[2]
        mov	rdx, QWORD PTR [r8+16]
        mulx	r10, r9, QWORD PTR [rax+8]
        adcx	rdi, rbx
        adox	r15, r9
        adcx	rsi, rbp
        adox	rdi, r10
        ; A[0] * B[2]
        mulx	r10, r9, r11
        adox	rsi, rbp
        xor	rbx, rbx
        adcx	r14, r9
        ; A[1] * B[1]
        mov	rdx, QWORD PTR [r8+8]
        mulx	r9, rdx, QWORD PTR [rax+8]
        adcx	r15, r10
        adox	r14, rdx
        ; A[1] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	r15, r9
        mulx	r10, r9, QWORD PTR [rax+8]
        adcx	rdi, r9
        ; A[2] * B[2]
        mov	rdx, QWORD PTR [r8+16]
        mulx	r9, rdx, QWORD PTR [rax+16]
        adcx	rsi, r10
        adox	rdi, rdx
        ; A[3] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	rsi, r9
        mulx	r10, r9, QWORD PTR [rax+24]
        adox	rbx, rbp
        adcx	rbx, r9
        ; A[0] * B[3]
        mulx	r9, rdx, r11
        adcx	rbp, r10
        xor	r10, r10
        adcx	r15, rdx
        ; A[3] * B[0]
        mov	rdx, QWORD PTR [rax+24]
        adcx	rdi, r9
        mulx	r9, rdx, QWORD PTR [r8]
        adox	r15, rdx
        adox	rdi, r9
        ; A[3] * B[2]
        mov	rdx, QWORD PTR [rax+24]
        mulx	r9, rdx, QWORD PTR [r8+16]
        adcx	rsi, rdx
        ; A[2] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adcx	rbx, r9
        mulx	rdx, r9, QWORD PTR [rax+16]
        adcx	rbp, r10
        adox	rsi, r9
        adox	rbx, rdx
        adox	rbp, r10
        mov	rdx, 38
        mulx	r9, rbp, rbp
        add	r15, rbp
        adc	r9, 0
        mov	r10, 9223372036854775807
        shld	r9, r15, 1
        imul	r9, r9, 19
        and	r15, r10
        xor	r10, r10
        adox	r12, r9
        mulx	rdi, r9, rdi
        adcx	r12, r9
        adox	r13, rdi
        mulx	rsi, r9, rsi
        adcx	r13, r9
        adox	r14, rsi
        mulx	rbx, r9, rbx
        adcx	r14, r9
        adox	r15, rbx
        adcx	r15, r10
        ; Store
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        lea	r8, QWORD PTR [rax+32]
        lea	rcx, QWORD PTR [rcx+96]
        mov	r11, QWORD PTR [rax]
        ; Multiply
        ; A[0] * B[0]
        mov	rdx, QWORD PTR [r8]
        mulx	r13, r12, r11
        ; A[2] * B[0]
        mulx	r15, r14, QWORD PTR [rax+16]
        ; A[1] * B[0]
        mulx	r10, r9, QWORD PTR [rax+8]
        xor	rbp, rbp
        adcx	r13, r9
        ; A[3] * B[1]
        mov	rdx, QWORD PTR [r8+8]
        mulx	rsi, rdi, QWORD PTR [rax+24]
        adcx	r14, r10
        ; A[0] * B[1]
        mulx	r10, r9, r11
        adox	r13, r9
        ; A[2] * B[1]
        mulx	rbx, r9, QWORD PTR [rax+16]
        adox	r14, r10
        adcx	r15, r9
        ; A[1] * B[2]
        mov	rdx, QWORD PTR [r8+16]
        mulx	r10, r9, QWORD PTR [rax+8]
        adcx	rdi, rbx
        adox	r15, r9
        adcx	rsi, rbp
        adox	rdi, r10
        ; A[0] * B[2]
        mulx	r10, r9, r11
        adox	rsi, rbp
        xor	rbx, rbx
        adcx	r14, r9
        ; A[1] * B[1]
        mov	rdx, QWORD PTR [r8+8]
        mulx	r9, rdx, QWORD PTR [rax+8]
        adcx	r15, r10
        adox	r14, rdx
        ; A[1] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	r15, r9
        mulx	r10, r9, QWORD PTR [rax+8]
        adcx	rdi, r9
        ; A[2] * B[2]
        mov	rdx, QWORD PTR [r8+16]
        mulx	r9, rdx, QWORD PTR [rax+16]
        adcx	rsi, r10
        adox	rdi, rdx
        ; A[3] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	rsi, r9
        mulx	r10, r9, QWORD PTR [rax+24]
        adox	rbx, rbp
        adcx	rbx, r9
        ; A[0] * B[3]
        mulx	r9, rdx, r11
        adcx	rbp, r10
        xor	r10, r10
        adcx	r15, rdx
        ; A[3] * B[0]
        mov	rdx, QWORD PTR [rax+24]
        adcx	rdi, r9
        mulx	r9, rdx, QWORD PTR [r8]
        adox	r15, rdx
        adox	rdi, r9
        ; A[3] * B[2]
        mov	rdx, QWORD PTR [rax+24]
        mulx	r9, rdx, QWORD PTR [r8+16]
        adcx	rsi, rdx
        ; A[2] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adcx	rbx, r9
        mulx	rdx, r9, QWORD PTR [rax+16]
        adcx	rbp, r10
        adox	rsi, r9
        adox	rbx, rdx
        adox	rbp, r10
        mov	rdx, 38
        mulx	r9, rbp, rbp
        add	r15, rbp
        adc	r9, 0
        mov	r10, 9223372036854775807
        shld	r9, r15, 1
        imul	r9, r9, 19
        and	r15, r10
        xor	r10, r10
        adox	r12, r9
        mulx	rdi, r9, rdi
        adcx	r12, r9
        adox	r13, rdi
        mulx	rsi, r9, rsi
        adcx	r13, r9
        adox	r14, rsi
        mulx	rbx, r9, rbx
        adcx	r14, r9
        adox	r15, rbx
        adcx	r15, r10
        ; Store
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        lea	rax, QWORD PTR [rax+64]
        lea	rcx, QWORD PTR [rcx+-64]
        mov	r11, QWORD PTR [rax]
        ; Multiply
        ; A[0] * B[0]
        mov	rdx, QWORD PTR [r8]
        mulx	r13, r12, r11
        ; A[2] * B[0]
        mulx	r15, r14, QWORD PTR [rax+16]
        ; A[1] * B[0]
        mulx	r10, r9, QWORD PTR [rax+8]
        xor	rbp, rbp
        adcx	r13, r9
        ; A[3] * B[1]
        mov	rdx, QWORD PTR [r8+8]
        mulx	rsi, rdi, QWORD PTR [rax+24]
        adcx	r14, r10
        ; A[0] * B[1]
        mulx	r10, r9, r11
        adox	r13, r9
        ; A[2] * B[1]
        mulx	rbx, r9, QWORD PTR [rax+16]
        adox	r14, r10
        adcx	r15, r9
        ; A[1] * B[2]
        mov	rdx, QWORD PTR [r8+16]
        mulx	r10, r9, QWORD PTR [rax+8]
        adcx	rdi, rbx
        adox	r15, r9
        adcx	rsi, rbp
        adox	rdi, r10
        ; A[0] * B[2]
        mulx	r10, r9, r11
        adox	rsi, rbp
        xor	rbx, rbx
        adcx	r14, r9
        ; A[1] * B[1]
        mov	rdx, QWORD PTR [r8+8]
        mulx	r9, rdx, QWORD PTR [rax+8]
        adcx	r15, r10
        adox	r14, rdx
        ; A[1] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	r15, r9
        mulx	r10, r9, QWORD PTR [rax+8]
        adcx	rdi, r9
        ; A[2] * B[2]
        mov	rdx, QWORD PTR [r8+16]
        mulx	r9, rdx, QWORD PTR [rax+16]
        adcx	rsi, r10
        adox	rdi, rdx
        ; A[3] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	rsi, r9
        mulx	r10, r9, QWORD PTR [rax+24]
        adox	rbx, rbp
        adcx	rbx, r9
        ; A[0] * B[3]
        mulx	r9, rdx, r11
        adcx	rbp, r10
        xor	r10, r10
        adcx	r15, rdx
        ; A[3] * B[0]
        mov	rdx, QWORD PTR [rax+24]
        adcx	rdi, r9
        mulx	r9, rdx, QWORD PTR [r8]
        adox	r15, rdx
        adox	rdi, r9
        ; A[3] * B[2]
        mov	rdx, QWORD PTR [rax+24]
        mulx	r9, rdx, QWORD PTR [r8+16]
        adcx	rsi, rdx
        ; A[2] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adcx	rbx, r9
        mulx	rdx, r9, QWORD PTR [rax+16]
        adcx	rbp, r10
        adox	rsi, r9
        adox	rbx, rdx
        adox	rbp, r10
        mov	rdx, 38
        mulx	r9, rbp, rbp
        add	r15, rbp
        adc	r9, 0
        mov	r10, 9223372036854775807
        shld	r9, r15, 1
        imul	r9, r9, 19
        and	r15, r10
        xor	r10, r10
        adox	r12, r9
        mulx	rdi, r9, rdi
        adcx	r12, r9
        adox	r13, rdi
        mulx	rsi, r9, rsi
        adcx	r13, r9
        adox	r14, rsi
        mulx	rbx, r9, rbx
        adcx	r14, r9
        adox	r15, rbx
        adcx	r15, r10
        ; Store
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        lea	r8, QWORD PTR [rax+32]
        lea	rcx, QWORD PTR [rcx+32]
        mov	r11, QWORD PTR [rax]
        ; Multiply
        ; A[0] * B[0]
        mov	rdx, QWORD PTR [r8]
        mulx	r13, r12, r11
        ; A[2] * B[0]
        mulx	r15, r14, QWORD PTR [rax+16]
        ; A[1] * B[0]
        mulx	r10, r9, QWORD PTR [rax+8]
        xor	rbp, rbp
        adcx	r13, r9
        ; A[3] * B[1]
        mov	rdx, QWORD PTR [r8+8]
        mulx	rsi, rdi, QWORD PTR [rax+24]
        adcx	r14, r10
        ; A[0] * B[1]
        mulx	r10, r9, r11
        adox	r13, r9
        ; A[2] * B[1]
        mulx	rbx, r9, QWORD PTR [rax+16]
        adox	r14, r10
        adcx	r15, r9
        ; A[1] * B[2]
        mov	rdx, QWORD PTR [r8+16]
        mulx	r10, r9, QWORD PTR [rax+8]
        adcx	rdi, rbx
        adox	r15, r9
        adcx	rsi, rbp
        adox	rdi, r10
        ; A[0] * B[2]
        mulx	r10, r9, r11
        adox	rsi, rbp
        xor	rbx, rbx
        adcx	r14, r9
        ; A[1] * B[1]
        mov	rdx, QWORD PTR [r8+8]
        mulx	r9, rdx, QWORD PTR [rax+8]
        adcx	r15, r10
        adox	r14, rdx
        ; A[1] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	r15, r9
        mulx	r10, r9, QWORD PTR [rax+8]
        adcx	rdi, r9
        ; A[2] * B[2]
        mov	rdx, QWORD PTR [r8+16]
        mulx	r9, rdx, QWORD PTR [rax+16]
        adcx	rsi, r10
        adox	rdi, rdx
        ; A[3] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	rsi, r9
        mulx	r10, r9, QWORD PTR [rax+24]
        adox	rbx, rbp
        adcx	rbx, r9
        ; A[0] * B[3]
        mulx	r9, rdx, r11
        adcx	rbp, r10
        xor	r10, r10
        adcx	r15, rdx
        ; A[3] * B[0]
        mov	rdx, QWORD PTR [rax+24]
        adcx	rdi, r9
        mulx	r9, rdx, QWORD PTR [r8]
        adox	r15, rdx
        adox	rdi, r9
        ; A[3] * B[2]
        mov	rdx, QWORD PTR [rax+24]
        mulx	r9, rdx, QWORD PTR [r8+16]
        adcx	rsi, rdx
        ; A[2] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adcx	rbx, r9
        mulx	rdx, r9, QWORD PTR [rax+16]
        adcx	rbp, r10
        adox	rsi, r9
        adox	rbx, rdx
        adox	rbp, r10
        mov	rdx, 38
        mulx	r9, rbp, rbp
        add	r15, rbp
        adc	r9, 0
        mov	r10, 9223372036854775807
        shld	r9, r15, 1
        imul	r9, r9, 19
        and	r15, r10
        xor	r10, r10
        adox	r12, r9
        mulx	rdi, r9, rdi
        adcx	r12, r9
        adox	r13, rdi
        mulx	rsi, r9, rsi
        adcx	r13, r9
        adox	r14, rsi
        mulx	rbx, r9, rbx
        adcx	r14, r9
        adox	r15, rbx
        adcx	r15, r10
        ; Store
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        add	rsp, 16
        pop	rbp
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
ge_p1p1_to_p3_avx2 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
ge_p2_dbl_avx2 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        push	rbp
        mov	rax, rdx
        sub	rsp, 16
        mov	QWORD PTR [rsp], rcx
        mov	QWORD PTR [rsp+8], rax
        lea	rcx, QWORD PTR [rcx+64]
        ; Square
        mov	rdx, QWORD PTR [rax]
        mov	r11, QWORD PTR [rax+8]
        ; A[0] * A[1]
        mov	rbp, rdx
        mulx	r14, r13, r11
        ; A[0] * A[3]
        mulx	rdi, r15, QWORD PTR [rax+24]
        ; A[2] * A[1]
        mov	rdx, QWORD PTR [rax+16]
        mulx	r10, r9, r11
        xor	r12, r12
        adox	r15, r9
        ; A[2] * A[3]
        mulx	rbx, rsi, QWORD PTR [rax+24]
        adox	rdi, r10
        ; A[2] * A[0]
        mulx	r10, r9, rbp
        adox	rsi, r12
        adcx	r14, r9
        adox	rbx, r12
        ; A[1] * A[3]
        mov	rdx, r11
        mulx	rdx, r9, QWORD PTR [rax+24]
        adcx	r15, r10
        adcx	rdi, r9
        adcx	rsi, rdx
        adcx	rbx, r12
        ; A[0] * A[0]
        mov	rdx, rbp
        mulx	r9, r12, rdx
        xor	rbp, rbp
        adcx	r13, r13
        ; A[1] * A[1]
        mov	rdx, r11
        adox	r13, r9
        mulx	r10, r9, rdx
        adcx	r14, r14
        adox	r14, r9
        adcx	r15, r15
        ; A[2] * A[2]
        mov	rdx, QWORD PTR [rax+16]
        adox	r15, r10
        mulx	r9, r10, rdx
        adcx	rdi, rdi
        adox	rdi, r10
        adcx	rsi, rsi
        ; A[3] * A[3]
        mov	rdx, QWORD PTR [rax+24]
        adox	rsi, r9
        mulx	r10, r9, rdx
        adcx	rbx, rbx
        adox	rbx, r9
        adcx	rbp, rbp
        adox	rbp, r10
        mov	rdx, 38
        mulx	r10, rbp, rbp
        add	r15, rbp
        adc	r10, 0
        mov	r9, 9223372036854775807
        shld	r10, r15, 1
        imul	r10, r10, 19
        and	r15, r9
        xor	r9, r9
        adox	r12, r10
        mulx	rdi, r10, rdi
        adcx	r12, r10
        adox	r13, rdi
        mulx	rsi, r10, rsi
        adcx	r13, r10
        adox	r14, rsi
        mulx	rbx, r10, rbx
        adcx	r14, r10
        adox	r15, rbx
        adcx	r15, r9
        ; Store
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        lea	rax, QWORD PTR [rax+32]
        ; Square
        mov	rdx, QWORD PTR [rax]
        mov	r11, QWORD PTR [rax+8]
        ; A[0] * A[1]
        mov	rbp, rdx
        mulx	r14, r13, r11
        ; A[0] * A[3]
        mulx	rdi, r15, QWORD PTR [rax+24]
        ; A[2] * A[1]
        mov	rdx, QWORD PTR [rax+16]
        mulx	r10, r9, r11
        xor	r12, r12
        adox	r15, r9
        ; A[2] * A[3]
        mulx	rbx, rsi, QWORD PTR [rax+24]
        adox	rdi, r10
        ; A[2] * A[0]
        mulx	r10, r9, rbp
        adox	rsi, r12
        adcx	r14, r9
        adox	rbx, r12
        ; A[1] * A[3]
        mov	rdx, r11
        mulx	rdx, r9, QWORD PTR [rax+24]
        adcx	r15, r10
        adcx	rdi, r9
        adcx	rsi, rdx
        adcx	rbx, r12
        ; A[0] * A[0]
        mov	rdx, rbp
        mulx	r9, r12, rdx
        xor	rbp, rbp
        adcx	r13, r13
        ; A[1] * A[1]
        mov	rdx, r11
        adox	r13, r9
        mulx	r10, r9, rdx
        adcx	r14, r14
        adox	r14, r9
        adcx	r15, r15
        ; A[2] * A[2]
        mov	rdx, QWORD PTR [rax+16]
        adox	r15, r10
        mulx	r9, r10, rdx
        adcx	rdi, rdi
        adox	rdi, r10
        adcx	rsi, rsi
        ; A[3] * A[3]
        mov	rdx, QWORD PTR [rax+24]
        adox	rsi, r9
        mulx	r10, r9, rdx
        adcx	rbx, rbx
        adox	rbx, r9
        adcx	rbp, rbp
        adox	rbp, r10
        mov	rdx, 38
        mulx	r10, rbp, rbp
        add	r15, rbp
        adc	r10, 0
        mov	r9, 9223372036854775807
        shld	r10, r15, 1
        imul	r10, r10, 19
        and	r15, r9
        xor	r9, r9
        adox	r12, r10
        mulx	rdi, r10, rdi
        adcx	r12, r10
        adox	r13, rdi
        mulx	rsi, r10, rsi
        adcx	r13, r10
        adox	r14, rsi
        mulx	rbx, r10, rbx
        adcx	r14, r10
        adox	r15, rbx
        adcx	r15, r9
        ; Store
        mov	rax, rcx
        lea	rcx, QWORD PTR [rcx+-32]
        ; Add-Sub
        ; Add
        mov	rdi, r12
        add	r12, QWORD PTR [rax]
        mov	rsi, r13
        adc	r13, QWORD PTR [rax+8]
        mov	rbx, r14
        adc	r14, QWORD PTR [rax+16]
        mov	rbp, r15
        adc	r15, QWORD PTR [rax+24]
        mov	rdx, 0
        adc	rdx, 0
        shld	rdx, r15, 1
        imul	rdx, 19
        btr	r15, 63
        ;   Sub modulus (if overflow)
        add	r12, rdx
        adc	r13, 0
        adc	r14, 0
        adc	r15, 0
        ; Sub
        sub	rdi, QWORD PTR [rax]
        sbb	rsi, QWORD PTR [rax+8]
        sbb	rbx, QWORD PTR [rax+16]
        sbb	rbp, QWORD PTR [rax+24]
        sbb	rdx, rdx
        shld	rdx, rbp, 1
        imul	rdx, -19
        btr	rbp, 63
        ;   Add modulus (if underflow)
        sub	rdi, rdx
        sbb	rsi, 0
        sbb	rbx, 0
        sbb	rbp, 0
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        mov	QWORD PTR [rax], rdi
        mov	QWORD PTR [rax+8], rsi
        mov	QWORD PTR [rax+16], rbx
        mov	QWORD PTR [rax+24], rbp
        mov	r8, QWORD PTR [rsp+8]
        lea	rax, QWORD PTR [r8+32]
        lea	rcx, QWORD PTR [rcx+-32]
        ; Add
        mov	r12, QWORD PTR [rax]
        mov	r13, QWORD PTR [rax+8]
        add	r12, QWORD PTR [r8]
        mov	r14, QWORD PTR [rax+16]
        adc	r13, QWORD PTR [r8+8]
        mov	r15, QWORD PTR [rax+24]
        adc	r14, QWORD PTR [r8+16]
        adc	r15, QWORD PTR [r8+24]
        mov	rdx, 0
        adc	rdx, 0
        shld	rdx, r15, 1
        imul	rdx, 19
        btr	r15, 63
        ;   Sub modulus (if overflow)
        add	r12, rdx
        adc	r13, 0
        adc	r14, 0
        adc	r15, 0
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        ; Square
        mov	rdx, QWORD PTR [rcx]
        mov	r11, QWORD PTR [rcx+8]
        ; A[0] * A[1]
        mov	rbp, rdx
        mulx	r14, r13, r11
        ; A[0] * A[3]
        mulx	rdi, r15, QWORD PTR [rcx+24]
        ; A[2] * A[1]
        mov	rdx, QWORD PTR [rcx+16]
        mulx	r10, r9, r11
        xor	r12, r12
        adox	r15, r9
        ; A[2] * A[3]
        mulx	rbx, rsi, QWORD PTR [rcx+24]
        adox	rdi, r10
        ; A[2] * A[0]
        mulx	r10, r9, rbp
        adox	rsi, r12
        adcx	r14, r9
        adox	rbx, r12
        ; A[1] * A[3]
        mov	rdx, r11
        mulx	rdx, r9, QWORD PTR [rcx+24]
        adcx	r15, r10
        adcx	rdi, r9
        adcx	rsi, rdx
        adcx	rbx, r12
        ; A[0] * A[0]
        mov	rdx, rbp
        mulx	r9, r12, rdx
        xor	rbp, rbp
        adcx	r13, r13
        ; A[1] * A[1]
        mov	rdx, r11
        adox	r13, r9
        mulx	r10, r9, rdx
        adcx	r14, r14
        adox	r14, r9
        adcx	r15, r15
        ; A[2] * A[2]
        mov	rdx, QWORD PTR [rcx+16]
        adox	r15, r10
        mulx	r9, r10, rdx
        adcx	rdi, rdi
        adox	rdi, r10
        adcx	rsi, rsi
        ; A[3] * A[3]
        mov	rdx, QWORD PTR [rcx+24]
        adox	rsi, r9
        mulx	r10, r9, rdx
        adcx	rbx, rbx
        adox	rbx, r9
        adcx	rbp, rbp
        adox	rbp, r10
        mov	rdx, 38
        mulx	r10, rbp, rbp
        add	r15, rbp
        adc	r10, 0
        mov	r9, 9223372036854775807
        shld	r10, r15, 1
        imul	r10, r10, 19
        and	r15, r9
        xor	r9, r9
        adox	r12, r10
        mulx	rdi, r10, rdi
        adcx	r12, r10
        adox	r13, rdi
        mulx	rsi, r10, rsi
        adcx	r13, r10
        adox	r14, rsi
        mulx	rbx, r10, rbx
        adcx	r14, r10
        adox	r15, rbx
        adcx	r15, r9
        ; Store
        lea	rax, QWORD PTR [rcx+32]
        ; Sub
        sub	r12, QWORD PTR [rax]
        sbb	r13, QWORD PTR [rax+8]
        sbb	r14, QWORD PTR [rax+16]
        sbb	r15, QWORD PTR [rax+24]
        sbb	rdx, rdx
        shld	rdx, r15, 1
        imul	rdx, -19
        btr	r15, 63
        ;   Add modulus (if underflow)
        sub	r12, rdx
        sbb	r13, 0
        sbb	r14, 0
        sbb	r15, 0
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        lea	r8, QWORD PTR [r8+64]
        ; Square * 2
        mov	rdx, QWORD PTR [r8]
        mov	r11, QWORD PTR [r8+8]
        ; A[0] * A[1]
        mov	rbp, rdx
        mulx	r14, r13, r11
        ; A[0] * A[3]
        mulx	rdi, r15, QWORD PTR [r8+24]
        ; A[2] * A[1]
        mov	rdx, QWORD PTR [r8+16]
        mulx	r10, r9, r11
        xor	r12, r12
        adox	r15, r9
        ; A[2] * A[3]
        mulx	rbx, rsi, QWORD PTR [r8+24]
        adox	rdi, r10
        ; A[2] * A[0]
        mulx	r10, r9, rbp
        adox	rsi, r12
        adcx	r14, r9
        adox	rbx, r12
        ; A[1] * A[3]
        mov	rdx, r11
        mulx	rdx, r9, QWORD PTR [r8+24]
        adcx	r15, r10
        adcx	rdi, r9
        adcx	rsi, rdx
        adcx	rbx, r12
        ; A[0] * A[0]
        mov	rdx, rbp
        mulx	r9, r12, rdx
        xor	rbp, rbp
        adcx	r13, r13
        ; A[1] * A[1]
        mov	rdx, r11
        adox	r13, r9
        mulx	r10, r9, rdx
        adcx	r14, r14
        adox	r14, r9
        adcx	r15, r15
        ; A[2] * A[2]
        mov	rdx, QWORD PTR [r8+16]
        adox	r15, r10
        mulx	r9, r10, rdx
        adcx	rdi, rdi
        adox	rdi, r10
        adcx	rsi, rsi
        ; A[3] * A[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	rsi, r9
        mulx	r10, r9, rdx
        adcx	rbx, rbx
        adox	rbx, r9
        adcx	rbp, rbp
        adox	rbp, r10
        mov	rdx, 38
        mulx	r11, rbp, rbp
        add	r15, rbp
        adc	r11, 0
        mov	r9, 9223372036854775807
        shld	r11, r15, 1
        imul	r11, r11, 19
        and	r15, r9
        xor	r9, r9
        adox	r12, r11
        mulx	rdi, r11, rdi
        adcx	r12, r11
        adox	r13, rdi
        mulx	rsi, r11, rsi
        adcx	r13, r11
        adox	r14, rsi
        mulx	rbx, r11, rbx
        adcx	r14, r11
        adox	r15, rbx
        adcx	r15, r9
        mov	r11, r15
        shld	r15, r14, 1
        shld	r14, r13, 1
        shld	r13, r12, 1
        shl	r12, 1
        mov	r9, 9223372036854775807
        shr	r11, 62
        and	r15, r9
        imul	r11, r11, 19
        add	r12, r11
        adc	r13, 0
        adc	r14, 0
        adc	r15, 0
        ; Store
        lea	rax, QWORD PTR [rcx+64]
        lea	rcx, QWORD PTR [rcx+96]
        ; Sub
        sub	r12, QWORD PTR [rax]
        sbb	r13, QWORD PTR [rax+8]
        sbb	r14, QWORD PTR [rax+16]
        sbb	r15, QWORD PTR [rax+24]
        sbb	rdx, rdx
        shld	rdx, r15, 1
        imul	rdx, -19
        btr	r15, 63
        ;   Add modulus (if underflow)
        sub	r12, rdx
        sbb	r13, 0
        sbb	r14, 0
        sbb	r15, 0
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        add	rsp, 16
        pop	rbp
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
ge_p2_dbl_avx2 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
ge_madd_avx2 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        push	rbp
        mov	rax, rdx
        sub	rsp, 24
        mov	QWORD PTR [rsp], rcx
        mov	QWORD PTR [rsp+8], rax
        mov	QWORD PTR [rsp+16], r8
        lea	r9, QWORD PTR [rax+96]
        lea	r8, QWORD PTR [r8+64]
        lea	rcx, QWORD PTR [rcx+96]
        ; Multiply
        ; A[0] * B[0]
        mov	rdx, QWORD PTR [r8]
        mulx	r13, r12, QWORD PTR [r9]
        ; A[2] * B[0]
        mulx	r15, r14, QWORD PTR [r9+16]
        ; A[1] * B[0]
        mulx	r11, r10, QWORD PTR [r9+8]
        xor	rbp, rbp
        adcx	r13, r10
        ; A[3] * B[1]
        mov	rdx, QWORD PTR [r8+8]
        mulx	rsi, rdi, QWORD PTR [r9+24]
        adcx	r14, r11
        ; A[0] * B[1]
        mulx	r11, r10, QWORD PTR [r9]
        adox	r13, r10
        ; A[2] * B[1]
        mulx	rbx, r10, QWORD PTR [r9+16]
        adox	r14, r11
        adcx	r15, r10
        ; A[1] * B[2]
        mov	rdx, QWORD PTR [r8+16]
        mulx	r11, r10, QWORD PTR [r9+8]
        adcx	rdi, rbx
        adox	r15, r10
        adcx	rsi, rbp
        adox	rdi, r11
        ; A[0] * B[2]
        mulx	r11, r10, QWORD PTR [r9]
        adox	rsi, rbp
        xor	rbx, rbx
        adcx	r14, r10
        ; A[1] * B[1]
        mov	rdx, QWORD PTR [r8+8]
        mulx	r10, rdx, QWORD PTR [r9+8]
        adcx	r15, r11
        adox	r14, rdx
        ; A[1] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	r15, r10
        mulx	r11, r10, QWORD PTR [r9+8]
        adcx	rdi, r10
        ; A[2] * B[2]
        mov	rdx, QWORD PTR [r8+16]
        mulx	r10, rdx, QWORD PTR [r9+16]
        adcx	rsi, r11
        adox	rdi, rdx
        ; A[3] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	rsi, r10
        mulx	r11, r10, QWORD PTR [r9+24]
        adox	rbx, rbp
        adcx	rbx, r10
        ; A[0] * B[3]
        mulx	r10, rdx, QWORD PTR [r9]
        adcx	rbp, r11
        xor	r11, r11
        adcx	r15, rdx
        ; A[3] * B[0]
        mov	rdx, QWORD PTR [r9+24]
        adcx	rdi, r10
        mulx	r10, rdx, QWORD PTR [r8]
        adox	r15, rdx
        adox	rdi, r10
        ; A[3] * B[2]
        mov	rdx, QWORD PTR [r9+24]
        mulx	r10, rdx, QWORD PTR [r8+16]
        adcx	rsi, rdx
        ; A[2] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adcx	rbx, r10
        mulx	rdx, r10, QWORD PTR [r9+16]
        adcx	rbp, r11
        adox	rsi, r10
        adox	rbx, rdx
        adox	rbp, r11
        mov	rdx, 38
        mulx	r10, rbp, rbp
        add	r15, rbp
        adc	r10, 0
        mov	r11, 9223372036854775807
        shld	r10, r15, 1
        imul	r10, r10, 19
        and	r15, r11
        xor	r11, r11
        adox	r12, r10
        mulx	rdi, r10, rdi
        adcx	r12, r10
        adox	r13, rdi
        mulx	rsi, r10, rsi
        adcx	r13, r10
        adox	r14, rsi
        mulx	rbx, r10, rbx
        adcx	r14, r10
        adox	r15, rbx
        adcx	r15, r11
        ; Store
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        mov	r9, rax
        lea	r8, QWORD PTR [rax+32]
        lea	rax, QWORD PTR [rcx+-64]
        lea	rcx, QWORD PTR [rcx+-96]
        ; Add-Sub
        ; Add
        mov	r12, QWORD PTR [r8]
        mov	r13, QWORD PTR [r8+8]
        mov	r14, QWORD PTR [r8+16]
        mov	r15, QWORD PTR [r8+24]
        mov	rdi, r12
        add	r12, QWORD PTR [r9]
        mov	rsi, r13
        adc	r13, QWORD PTR [r9+8]
        mov	rbx, r14
        adc	r14, QWORD PTR [r9+16]
        mov	rbp, r15
        adc	r15, QWORD PTR [r9+24]
        mov	rdx, 0
        adc	rdx, 0
        shld	rdx, r15, 1
        imul	rdx, 19
        btr	r15, 63
        ;   Sub modulus (if overflow)
        add	r12, rdx
        adc	r13, 0
        adc	r14, 0
        adc	r15, 0
        ; Sub
        sub	rdi, QWORD PTR [r9]
        sbb	rsi, QWORD PTR [r9+8]
        sbb	rbx, QWORD PTR [r9+16]
        sbb	rbp, QWORD PTR [r9+24]
        sbb	rdx, rdx
        shld	rdx, rbp, 1
        imul	rdx, -19
        btr	rbp, 63
        ;   Add modulus (if underflow)
        sub	rdi, rdx
        sbb	rsi, 0
        sbb	rbx, 0
        sbb	rbp, 0
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        mov	QWORD PTR [rax], rdi
        mov	QWORD PTR [rax+8], rsi
        mov	QWORD PTR [rax+16], rbx
        mov	QWORD PTR [rax+24], rbp
        mov	r8, QWORD PTR [rsp+16]
        ; Multiply
        ; A[0] * B[0]
        mov	rdx, QWORD PTR [r8]
        mulx	r13, r12, QWORD PTR [rcx]
        ; A[2] * B[0]
        mulx	r15, r14, QWORD PTR [rcx+16]
        ; A[1] * B[0]
        mulx	r11, r10, QWORD PTR [rcx+8]
        xor	rbp, rbp
        adcx	r13, r10
        ; A[3] * B[1]
        mov	rdx, QWORD PTR [r8+8]
        mulx	rsi, rdi, QWORD PTR [rcx+24]
        adcx	r14, r11
        ; A[0] * B[1]
        mulx	r11, r10, QWORD PTR [rcx]
        adox	r13, r10
        ; A[2] * B[1]
        mulx	rbx, r10, QWORD PTR [rcx+16]
        adox	r14, r11
        adcx	r15, r10
        ; A[1] * B[2]
        mov	rdx, QWORD PTR [r8+16]
        mulx	r11, r10, QWORD PTR [rcx+8]
        adcx	rdi, rbx
        adox	r15, r10
        adcx	rsi, rbp
        adox	rdi, r11
        ; A[0] * B[2]
        mulx	r11, r10, QWORD PTR [rcx]
        adox	rsi, rbp
        xor	rbx, rbx
        adcx	r14, r10
        ; A[1] * B[1]
        mov	rdx, QWORD PTR [r8+8]
        mulx	r10, rdx, QWORD PTR [rcx+8]
        adcx	r15, r11
        adox	r14, rdx
        ; A[1] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	r15, r10
        mulx	r11, r10, QWORD PTR [rcx+8]
        adcx	rdi, r10
        ; A[2] * B[2]
        mov	rdx, QWORD PTR [r8+16]
        mulx	r10, rdx, QWORD PTR [rcx+16]
        adcx	rsi, r11
        adox	rdi, rdx
        ; A[3] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	rsi, r10
        mulx	r11, r10, QWORD PTR [rcx+24]
        adox	rbx, rbp
        adcx	rbx, r10
        ; A[0] * B[3]
        mulx	r10, rdx, QWORD PTR [rcx]
        adcx	rbp, r11
        xor	r11, r11
        adcx	r15, rdx
        ; A[3] * B[0]
        mov	rdx, QWORD PTR [rcx+24]
        adcx	rdi, r10
        mulx	r10, rdx, QWORD PTR [r8]
        adox	r15, rdx
        adox	rdi, r10
        ; A[3] * B[2]
        mov	rdx, QWORD PTR [rcx+24]
        mulx	r10, rdx, QWORD PTR [r8+16]
        adcx	rsi, rdx
        ; A[2] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adcx	rbx, r10
        mulx	rdx, r10, QWORD PTR [rcx+16]
        adcx	rbp, r11
        adox	rsi, r10
        adox	rbx, rdx
        adox	rbp, r11
        mov	rdx, 38
        mulx	r10, rbp, rbp
        add	r15, rbp
        adc	r10, 0
        mov	r11, 9223372036854775807
        shld	r10, r15, 1
        imul	r10, r10, 19
        and	r15, r11
        xor	r11, r11
        adox	r12, r10
        mulx	rdi, r10, rdi
        adcx	r12, r10
        adox	r13, rdi
        mulx	rsi, r10, rsi
        adcx	r13, r10
        adox	r14, rsi
        mulx	rbx, r10, rbx
        adcx	r14, r10
        adox	r15, rbx
        adcx	r15, r11
        ; Store
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        lea	r8, QWORD PTR [r8+32]
        ; Multiply
        ; A[0] * B[0]
        mov	rdx, QWORD PTR [r8]
        mulx	r13, r12, QWORD PTR [rax]
        ; A[2] * B[0]
        mulx	r15, r14, QWORD PTR [rax+16]
        ; A[1] * B[0]
        mulx	r11, r10, QWORD PTR [rax+8]
        xor	rbp, rbp
        adcx	r13, r10
        ; A[3] * B[1]
        mov	rdx, QWORD PTR [r8+8]
        mulx	rsi, rdi, QWORD PTR [rax+24]
        adcx	r14, r11
        ; A[0] * B[1]
        mulx	r11, r10, QWORD PTR [rax]
        adox	r13, r10
        ; A[2] * B[1]
        mulx	rbx, r10, QWORD PTR [rax+16]
        adox	r14, r11
        adcx	r15, r10
        ; A[1] * B[2]
        mov	rdx, QWORD PTR [r8+16]
        mulx	r11, r10, QWORD PTR [rax+8]
        adcx	rdi, rbx
        adox	r15, r10
        adcx	rsi, rbp
        adox	rdi, r11
        ; A[0] * B[2]
        mulx	r11, r10, QWORD PTR [rax]
        adox	rsi, rbp
        xor	rbx, rbx
        adcx	r14, r10
        ; A[1] * B[1]
        mov	rdx, QWORD PTR [r8+8]
        mulx	r10, rdx, QWORD PTR [rax+8]
        adcx	r15, r11
        adox	r14, rdx
        ; A[1] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	r15, r10
        mulx	r11, r10, QWORD PTR [rax+8]
        adcx	rdi, r10
        ; A[2] * B[2]
        mov	rdx, QWORD PTR [r8+16]
        mulx	r10, rdx, QWORD PTR [rax+16]
        adcx	rsi, r11
        adox	rdi, rdx
        ; A[3] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	rsi, r10
        mulx	r11, r10, QWORD PTR [rax+24]
        adox	rbx, rbp
        adcx	rbx, r10
        ; A[0] * B[3]
        mulx	r10, rdx, QWORD PTR [rax]
        adcx	rbp, r11
        xor	r11, r11
        adcx	r15, rdx
        ; A[3] * B[0]
        mov	rdx, QWORD PTR [rax+24]
        adcx	rdi, r10
        mulx	r10, rdx, QWORD PTR [r8]
        adox	r15, rdx
        adox	rdi, r10
        ; A[3] * B[2]
        mov	rdx, QWORD PTR [rax+24]
        mulx	r10, rdx, QWORD PTR [r8+16]
        adcx	rsi, rdx
        ; A[2] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adcx	rbx, r10
        mulx	rdx, r10, QWORD PTR [rax+16]
        adcx	rbp, r11
        adox	rsi, r10
        adox	rbx, rdx
        adox	rbp, r11
        mov	rdx, 38
        mulx	r10, rbp, rbp
        add	r15, rbp
        adc	r10, 0
        mov	r11, 9223372036854775807
        shld	r10, r15, 1
        imul	r10, r10, 19
        and	r15, r11
        xor	r11, r11
        adox	r12, r10
        mulx	rdi, r10, rdi
        adcx	r12, r10
        adox	r13, rdi
        mulx	rsi, r10, rsi
        adcx	r13, r10
        adox	r14, rsi
        mulx	rbx, r10, rbx
        adcx	r14, r10
        adox	r15, rbx
        adcx	r15, r11
        ; Store
        mov	QWORD PTR [rax], r12
        mov	QWORD PTR [rax+8], r13
        mov	QWORD PTR [rax+16], r14
        mov	QWORD PTR [rax+24], r15
        ; Add-Sub
        ; Add
        mov	r12, QWORD PTR [rcx]
        mov	r13, QWORD PTR [rcx+8]
        mov	r14, QWORD PTR [rcx+16]
        mov	r15, QWORD PTR [rcx+24]
        mov	rdi, r12
        add	r12, QWORD PTR [rax]
        mov	rsi, r13
        adc	r13, QWORD PTR [rax+8]
        mov	rbx, r14
        adc	r14, QWORD PTR [rax+16]
        mov	rbp, r15
        adc	r15, QWORD PTR [rax+24]
        mov	rdx, 0
        adc	rdx, 0
        shld	rdx, r15, 1
        imul	rdx, 19
        btr	r15, 63
        ;   Sub modulus (if overflow)
        add	r12, rdx
        adc	r13, 0
        adc	r14, 0
        adc	r15, 0
        ; Sub
        sub	rdi, QWORD PTR [rax]
        sbb	rsi, QWORD PTR [rax+8]
        sbb	rbx, QWORD PTR [rax+16]
        sbb	rbp, QWORD PTR [rax+24]
        sbb	rdx, rdx
        shld	rdx, rbp, 1
        imul	rdx, -19
        btr	rbp, 63
        ;   Add modulus (if underflow)
        sub	rdi, rdx
        sbb	rsi, 0
        sbb	rbx, 0
        sbb	rbp, 0
        mov	QWORD PTR [rax], r12
        mov	QWORD PTR [rax+8], r13
        mov	QWORD PTR [rax+16], r14
        mov	QWORD PTR [rax+24], r15
        mov	QWORD PTR [rcx], rdi
        mov	QWORD PTR [rcx+8], rsi
        mov	QWORD PTR [rcx+16], rbx
        mov	QWORD PTR [rcx+24], rbp
        lea	r9, QWORD PTR [r9+64]
        ; Double
        mov	r12, QWORD PTR [r9]
        mov	r13, QWORD PTR [r9+8]
        add	r12, r12
        mov	r14, QWORD PTR [r9+16]
        adc	r13, r13
        mov	r15, QWORD PTR [r9+24]
        adc	r14, r14
        adc	r15, r15
        mov	rdx, 0
        adc	rdx, 0
        shld	rdx, r15, 1
        imul	rdx, 19
        btr	r15, 63
        ;   Sub modulus (if overflow)
        add	r12, rdx
        adc	r13, 0
        adc	r14, 0
        adc	r15, 0
        lea	rax, QWORD PTR [rcx+96]
        lea	rcx, QWORD PTR [rcx+64]
        ; Add-Sub
        ; Add
        mov	rdi, r12
        add	r12, QWORD PTR [rax]
        mov	rsi, r13
        adc	r13, QWORD PTR [rax+8]
        mov	rbx, r14
        adc	r14, QWORD PTR [rax+16]
        mov	rbp, r15
        adc	r15, QWORD PTR [rax+24]
        mov	rdx, 0
        adc	rdx, 0
        shld	rdx, r15, 1
        imul	rdx, 19
        btr	r15, 63
        ;   Sub modulus (if overflow)
        add	r12, rdx
        adc	r13, 0
        adc	r14, 0
        adc	r15, 0
        ; Sub
        sub	rdi, QWORD PTR [rax]
        sbb	rsi, QWORD PTR [rax+8]
        sbb	rbx, QWORD PTR [rax+16]
        sbb	rbp, QWORD PTR [rax+24]
        sbb	rdx, rdx
        shld	rdx, rbp, 1
        imul	rdx, -19
        btr	rbp, 63
        ;   Add modulus (if underflow)
        sub	rdi, rdx
        sbb	rsi, 0
        sbb	rbx, 0
        sbb	rbp, 0
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        mov	QWORD PTR [rax], rdi
        mov	QWORD PTR [rax+8], rsi
        mov	QWORD PTR [rax+16], rbx
        mov	QWORD PTR [rax+24], rbp
        add	rsp, 24
        pop	rbp
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
ge_madd_avx2 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
ge_msub_avx2 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        push	rbp
        mov	rax, rdx
        sub	rsp, 24
        mov	QWORD PTR [rsp], rcx
        mov	QWORD PTR [rsp+8], rax
        mov	QWORD PTR [rsp+16], r8
        lea	r9, QWORD PTR [rax+96]
        lea	r8, QWORD PTR [r8+64]
        lea	rcx, QWORD PTR [rcx+96]
        ; Multiply
        ; A[0] * B[0]
        mov	rdx, QWORD PTR [r8]
        mulx	r13, r12, QWORD PTR [r9]
        ; A[2] * B[0]
        mulx	r15, r14, QWORD PTR [r9+16]
        ; A[1] * B[0]
        mulx	r11, r10, QWORD PTR [r9+8]
        xor	rbp, rbp
        adcx	r13, r10
        ; A[3] * B[1]
        mov	rdx, QWORD PTR [r8+8]
        mulx	rsi, rdi, QWORD PTR [r9+24]
        adcx	r14, r11
        ; A[0] * B[1]
        mulx	r11, r10, QWORD PTR [r9]
        adox	r13, r10
        ; A[2] * B[1]
        mulx	rbx, r10, QWORD PTR [r9+16]
        adox	r14, r11
        adcx	r15, r10
        ; A[1] * B[2]
        mov	rdx, QWORD PTR [r8+16]
        mulx	r11, r10, QWORD PTR [r9+8]
        adcx	rdi, rbx
        adox	r15, r10
        adcx	rsi, rbp
        adox	rdi, r11
        ; A[0] * B[2]
        mulx	r11, r10, QWORD PTR [r9]
        adox	rsi, rbp
        xor	rbx, rbx
        adcx	r14, r10
        ; A[1] * B[1]
        mov	rdx, QWORD PTR [r8+8]
        mulx	r10, rdx, QWORD PTR [r9+8]
        adcx	r15, r11
        adox	r14, rdx
        ; A[1] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	r15, r10
        mulx	r11, r10, QWORD PTR [r9+8]
        adcx	rdi, r10
        ; A[2] * B[2]
        mov	rdx, QWORD PTR [r8+16]
        mulx	r10, rdx, QWORD PTR [r9+16]
        adcx	rsi, r11
        adox	rdi, rdx
        ; A[3] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	rsi, r10
        mulx	r11, r10, QWORD PTR [r9+24]
        adox	rbx, rbp
        adcx	rbx, r10
        ; A[0] * B[3]
        mulx	r10, rdx, QWORD PTR [r9]
        adcx	rbp, r11
        xor	r11, r11
        adcx	r15, rdx
        ; A[3] * B[0]
        mov	rdx, QWORD PTR [r9+24]
        adcx	rdi, r10
        mulx	r10, rdx, QWORD PTR [r8]
        adox	r15, rdx
        adox	rdi, r10
        ; A[3] * B[2]
        mov	rdx, QWORD PTR [r9+24]
        mulx	r10, rdx, QWORD PTR [r8+16]
        adcx	rsi, rdx
        ; A[2] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adcx	rbx, r10
        mulx	rdx, r10, QWORD PTR [r9+16]
        adcx	rbp, r11
        adox	rsi, r10
        adox	rbx, rdx
        adox	rbp, r11
        mov	rdx, 38
        mulx	r10, rbp, rbp
        add	r15, rbp
        adc	r10, 0
        mov	r11, 9223372036854775807
        shld	r10, r15, 1
        imul	r10, r10, 19
        and	r15, r11
        xor	r11, r11
        adox	r12, r10
        mulx	rdi, r10, rdi
        adcx	r12, r10
        adox	r13, rdi
        mulx	rsi, r10, rsi
        adcx	r13, r10
        adox	r14, rsi
        mulx	rbx, r10, rbx
        adcx	r14, r10
        adox	r15, rbx
        adcx	r15, r11
        ; Store
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        mov	r9, rax
        lea	r8, QWORD PTR [rax+32]
        lea	rax, QWORD PTR [rcx+-64]
        lea	rcx, QWORD PTR [rcx+-96]
        ; Add-Sub
        ; Add
        mov	r12, QWORD PTR [r8]
        mov	r13, QWORD PTR [r8+8]
        mov	r14, QWORD PTR [r8+16]
        mov	r15, QWORD PTR [r8+24]
        mov	rdi, r12
        add	r12, QWORD PTR [r9]
        mov	rsi, r13
        adc	r13, QWORD PTR [r9+8]
        mov	rbx, r14
        adc	r14, QWORD PTR [r9+16]
        mov	rbp, r15
        adc	r15, QWORD PTR [r9+24]
        mov	rdx, 0
        adc	rdx, 0
        shld	rdx, r15, 1
        imul	rdx, 19
        btr	r15, 63
        ;   Sub modulus (if overflow)
        add	r12, rdx
        adc	r13, 0
        adc	r14, 0
        adc	r15, 0
        ; Sub
        sub	rdi, QWORD PTR [r9]
        sbb	rsi, QWORD PTR [r9+8]
        sbb	rbx, QWORD PTR [r9+16]
        sbb	rbp, QWORD PTR [r9+24]
        sbb	rdx, rdx
        shld	rdx, rbp, 1
        imul	rdx, -19
        btr	rbp, 63
        ;   Add modulus (if underflow)
        sub	rdi, rdx
        sbb	rsi, 0
        sbb	rbx, 0
        sbb	rbp, 0
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        mov	QWORD PTR [rax], rdi
        mov	QWORD PTR [rax+8], rsi
        mov	QWORD PTR [rax+16], rbx
        mov	QWORD PTR [rax+24], rbp
        mov	r8, QWORD PTR [rsp+16]
        lea	r8, QWORD PTR [r8+32]
        ; Multiply
        ; A[0] * B[0]
        mov	rdx, QWORD PTR [r8]
        mulx	r13, r12, QWORD PTR [rcx]
        ; A[2] * B[0]
        mulx	r15, r14, QWORD PTR [rcx+16]
        ; A[1] * B[0]
        mulx	r11, r10, QWORD PTR [rcx+8]
        xor	rbp, rbp
        adcx	r13, r10
        ; A[3] * B[1]
        mov	rdx, QWORD PTR [r8+8]
        mulx	rsi, rdi, QWORD PTR [rcx+24]
        adcx	r14, r11
        ; A[0] * B[1]
        mulx	r11, r10, QWORD PTR [rcx]
        adox	r13, r10
        ; A[2] * B[1]
        mulx	rbx, r10, QWORD PTR [rcx+16]
        adox	r14, r11
        adcx	r15, r10
        ; A[1] * B[2]
        mov	rdx, QWORD PTR [r8+16]
        mulx	r11, r10, QWORD PTR [rcx+8]
        adcx	rdi, rbx
        adox	r15, r10
        adcx	rsi, rbp
        adox	rdi, r11
        ; A[0] * B[2]
        mulx	r11, r10, QWORD PTR [rcx]
        adox	rsi, rbp
        xor	rbx, rbx
        adcx	r14, r10
        ; A[1] * B[1]
        mov	rdx, QWORD PTR [r8+8]
        mulx	r10, rdx, QWORD PTR [rcx+8]
        adcx	r15, r11
        adox	r14, rdx
        ; A[1] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	r15, r10
        mulx	r11, r10, QWORD PTR [rcx+8]
        adcx	rdi, r10
        ; A[2] * B[2]
        mov	rdx, QWORD PTR [r8+16]
        mulx	r10, rdx, QWORD PTR [rcx+16]
        adcx	rsi, r11
        adox	rdi, rdx
        ; A[3] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	rsi, r10
        mulx	r11, r10, QWORD PTR [rcx+24]
        adox	rbx, rbp
        adcx	rbx, r10
        ; A[0] * B[3]
        mulx	r10, rdx, QWORD PTR [rcx]
        adcx	rbp, r11
        xor	r11, r11
        adcx	r15, rdx
        ; A[3] * B[0]
        mov	rdx, QWORD PTR [rcx+24]
        adcx	rdi, r10
        mulx	r10, rdx, QWORD PTR [r8]
        adox	r15, rdx
        adox	rdi, r10
        ; A[3] * B[2]
        mov	rdx, QWORD PTR [rcx+24]
        mulx	r10, rdx, QWORD PTR [r8+16]
        adcx	rsi, rdx
        ; A[2] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adcx	rbx, r10
        mulx	rdx, r10, QWORD PTR [rcx+16]
        adcx	rbp, r11
        adox	rsi, r10
        adox	rbx, rdx
        adox	rbp, r11
        mov	rdx, 38
        mulx	r10, rbp, rbp
        add	r15, rbp
        adc	r10, 0
        mov	r11, 9223372036854775807
        shld	r10, r15, 1
        imul	r10, r10, 19
        and	r15, r11
        xor	r11, r11
        adox	r12, r10
        mulx	rdi, r10, rdi
        adcx	r12, r10
        adox	r13, rdi
        mulx	rsi, r10, rsi
        adcx	r13, r10
        adox	r14, rsi
        mulx	rbx, r10, rbx
        adcx	r14, r10
        adox	r15, rbx
        adcx	r15, r11
        ; Store
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        lea	r8, QWORD PTR [r8+-32]
        ; Multiply
        ; A[0] * B[0]
        mov	rdx, QWORD PTR [r8]
        mulx	r13, r12, QWORD PTR [rax]
        ; A[2] * B[0]
        mulx	r15, r14, QWORD PTR [rax+16]
        ; A[1] * B[0]
        mulx	r11, r10, QWORD PTR [rax+8]
        xor	rbp, rbp
        adcx	r13, r10
        ; A[3] * B[1]
        mov	rdx, QWORD PTR [r8+8]
        mulx	rsi, rdi, QWORD PTR [rax+24]
        adcx	r14, r11
        ; A[0] * B[1]
        mulx	r11, r10, QWORD PTR [rax]
        adox	r13, r10
        ; A[2] * B[1]
        mulx	rbx, r10, QWORD PTR [rax+16]
        adox	r14, r11
        adcx	r15, r10
        ; A[1] * B[2]
        mov	rdx, QWORD PTR [r8+16]
        mulx	r11, r10, QWORD PTR [rax+8]
        adcx	rdi, rbx
        adox	r15, r10
        adcx	rsi, rbp
        adox	rdi, r11
        ; A[0] * B[2]
        mulx	r11, r10, QWORD PTR [rax]
        adox	rsi, rbp
        xor	rbx, rbx
        adcx	r14, r10
        ; A[1] * B[1]
        mov	rdx, QWORD PTR [r8+8]
        mulx	r10, rdx, QWORD PTR [rax+8]
        adcx	r15, r11
        adox	r14, rdx
        ; A[1] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	r15, r10
        mulx	r11, r10, QWORD PTR [rax+8]
        adcx	rdi, r10
        ; A[2] * B[2]
        mov	rdx, QWORD PTR [r8+16]
        mulx	r10, rdx, QWORD PTR [rax+16]
        adcx	rsi, r11
        adox	rdi, rdx
        ; A[3] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	rsi, r10
        mulx	r11, r10, QWORD PTR [rax+24]
        adox	rbx, rbp
        adcx	rbx, r10
        ; A[0] * B[3]
        mulx	r10, rdx, QWORD PTR [rax]
        adcx	rbp, r11
        xor	r11, r11
        adcx	r15, rdx
        ; A[3] * B[0]
        mov	rdx, QWORD PTR [rax+24]
        adcx	rdi, r10
        mulx	r10, rdx, QWORD PTR [r8]
        adox	r15, rdx
        adox	rdi, r10
        ; A[3] * B[2]
        mov	rdx, QWORD PTR [rax+24]
        mulx	r10, rdx, QWORD PTR [r8+16]
        adcx	rsi, rdx
        ; A[2] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adcx	rbx, r10
        mulx	rdx, r10, QWORD PTR [rax+16]
        adcx	rbp, r11
        adox	rsi, r10
        adox	rbx, rdx
        adox	rbp, r11
        mov	rdx, 38
        mulx	r10, rbp, rbp
        add	r15, rbp
        adc	r10, 0
        mov	r11, 9223372036854775807
        shld	r10, r15, 1
        imul	r10, r10, 19
        and	r15, r11
        xor	r11, r11
        adox	r12, r10
        mulx	rdi, r10, rdi
        adcx	r12, r10
        adox	r13, rdi
        mulx	rsi, r10, rsi
        adcx	r13, r10
        adox	r14, rsi
        mulx	rbx, r10, rbx
        adcx	r14, r10
        adox	r15, rbx
        adcx	r15, r11
        ; Store
        mov	QWORD PTR [rax], r12
        mov	QWORD PTR [rax+8], r13
        mov	QWORD PTR [rax+16], r14
        mov	QWORD PTR [rax+24], r15
        ; Add-Sub
        ; Add
        mov	r12, QWORD PTR [rcx]
        mov	r13, QWORD PTR [rcx+8]
        mov	r14, QWORD PTR [rcx+16]
        mov	r15, QWORD PTR [rcx+24]
        mov	rdi, r12
        add	r12, QWORD PTR [rax]
        mov	rsi, r13
        adc	r13, QWORD PTR [rax+8]
        mov	rbx, r14
        adc	r14, QWORD PTR [rax+16]
        mov	rbp, r15
        adc	r15, QWORD PTR [rax+24]
        mov	rdx, 0
        adc	rdx, 0
        shld	rdx, r15, 1
        imul	rdx, 19
        btr	r15, 63
        ;   Sub modulus (if overflow)
        add	r12, rdx
        adc	r13, 0
        adc	r14, 0
        adc	r15, 0
        ; Sub
        sub	rdi, QWORD PTR [rax]
        sbb	rsi, QWORD PTR [rax+8]
        sbb	rbx, QWORD PTR [rax+16]
        sbb	rbp, QWORD PTR [rax+24]
        sbb	rdx, rdx
        shld	rdx, rbp, 1
        imul	rdx, -19
        btr	rbp, 63
        ;   Add modulus (if underflow)
        sub	rdi, rdx
        sbb	rsi, 0
        sbb	rbx, 0
        sbb	rbp, 0
        mov	QWORD PTR [rax], r12
        mov	QWORD PTR [rax+8], r13
        mov	QWORD PTR [rax+16], r14
        mov	QWORD PTR [rax+24], r15
        mov	QWORD PTR [rcx], rdi
        mov	QWORD PTR [rcx+8], rsi
        mov	QWORD PTR [rcx+16], rbx
        mov	QWORD PTR [rcx+24], rbp
        lea	r9, QWORD PTR [r9+64]
        ; Double
        mov	r12, QWORD PTR [r9]
        mov	r13, QWORD PTR [r9+8]
        add	r12, r12
        mov	r14, QWORD PTR [r9+16]
        adc	r13, r13
        mov	r15, QWORD PTR [r9+24]
        adc	r14, r14
        adc	r15, r15
        mov	rdx, 0
        adc	rdx, 0
        shld	rdx, r15, 1
        imul	rdx, 19
        btr	r15, 63
        ;   Sub modulus (if overflow)
        add	r12, rdx
        adc	r13, 0
        adc	r14, 0
        adc	r15, 0
        lea	rax, QWORD PTR [rcx+96]
        lea	rcx, QWORD PTR [rcx+64]
        ; Add-Sub
        ; Add
        mov	rdi, r12
        add	r12, QWORD PTR [rax]
        mov	rsi, r13
        adc	r13, QWORD PTR [rax+8]
        mov	rbx, r14
        adc	r14, QWORD PTR [rax+16]
        mov	rbp, r15
        adc	r15, QWORD PTR [rax+24]
        mov	rdx, 0
        adc	rdx, 0
        shld	rdx, r15, 1
        imul	rdx, 19
        btr	r15, 63
        ;   Sub modulus (if overflow)
        add	r12, rdx
        adc	r13, 0
        adc	r14, 0
        adc	r15, 0
        ; Sub
        sub	rdi, QWORD PTR [rax]
        sbb	rsi, QWORD PTR [rax+8]
        sbb	rbx, QWORD PTR [rax+16]
        sbb	rbp, QWORD PTR [rax+24]
        sbb	rdx, rdx
        shld	rdx, rbp, 1
        imul	rdx, -19
        btr	rbp, 63
        ;   Add modulus (if underflow)
        sub	rdi, rdx
        sbb	rsi, 0
        sbb	rbx, 0
        sbb	rbp, 0
        mov	QWORD PTR [rax], r12
        mov	QWORD PTR [rax+8], r13
        mov	QWORD PTR [rax+16], r14
        mov	QWORD PTR [rax+24], r15
        mov	QWORD PTR [rcx], rdi
        mov	QWORD PTR [rcx+8], rsi
        mov	QWORD PTR [rcx+16], rbx
        mov	QWORD PTR [rcx+24], rbp
        add	rsp, 24
        pop	rbp
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
ge_msub_avx2 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
ge_add_avx2 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        push	rbp
        mov	rax, rdx
        sub	rsp, 24
        mov	QWORD PTR [rsp], rcx
        mov	QWORD PTR [rsp+8], rax
        mov	QWORD PTR [rsp+16], r8
        lea	r9, QWORD PTR [rax+96]
        lea	r8, QWORD PTR [r8+96]
        lea	rcx, QWORD PTR [rcx+96]
        ; Multiply
        ; A[0] * B[0]
        mov	rdx, QWORD PTR [r8]
        mulx	r13, r12, QWORD PTR [r9]
        ; A[2] * B[0]
        mulx	r15, r14, QWORD PTR [r9+16]
        ; A[1] * B[0]
        mulx	r11, r10, QWORD PTR [r9+8]
        xor	rbp, rbp
        adcx	r13, r10
        ; A[3] * B[1]
        mov	rdx, QWORD PTR [r8+8]
        mulx	rsi, rdi, QWORD PTR [r9+24]
        adcx	r14, r11
        ; A[0] * B[1]
        mulx	r11, r10, QWORD PTR [r9]
        adox	r13, r10
        ; A[2] * B[1]
        mulx	rbx, r10, QWORD PTR [r9+16]
        adox	r14, r11
        adcx	r15, r10
        ; A[1] * B[2]
        mov	rdx, QWORD PTR [r8+16]
        mulx	r11, r10, QWORD PTR [r9+8]
        adcx	rdi, rbx
        adox	r15, r10
        adcx	rsi, rbp
        adox	rdi, r11
        ; A[0] * B[2]
        mulx	r11, r10, QWORD PTR [r9]
        adox	rsi, rbp
        xor	rbx, rbx
        adcx	r14, r10
        ; A[1] * B[1]
        mov	rdx, QWORD PTR [r8+8]
        mulx	r10, rdx, QWORD PTR [r9+8]
        adcx	r15, r11
        adox	r14, rdx
        ; A[1] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	r15, r10
        mulx	r11, r10, QWORD PTR [r9+8]
        adcx	rdi, r10
        ; A[2] * B[2]
        mov	rdx, QWORD PTR [r8+16]
        mulx	r10, rdx, QWORD PTR [r9+16]
        adcx	rsi, r11
        adox	rdi, rdx
        ; A[3] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	rsi, r10
        mulx	r11, r10, QWORD PTR [r9+24]
        adox	rbx, rbp
        adcx	rbx, r10
        ; A[0] * B[3]
        mulx	r10, rdx, QWORD PTR [r9]
        adcx	rbp, r11
        xor	r11, r11
        adcx	r15, rdx
        ; A[3] * B[0]
        mov	rdx, QWORD PTR [r9+24]
        adcx	rdi, r10
        mulx	r10, rdx, QWORD PTR [r8]
        adox	r15, rdx
        adox	rdi, r10
        ; A[3] * B[2]
        mov	rdx, QWORD PTR [r9+24]
        mulx	r10, rdx, QWORD PTR [r8+16]
        adcx	rsi, rdx
        ; A[2] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adcx	rbx, r10
        mulx	rdx, r10, QWORD PTR [r9+16]
        adcx	rbp, r11
        adox	rsi, r10
        adox	rbx, rdx
        adox	rbp, r11
        mov	rdx, 38
        mulx	r10, rbp, rbp
        add	r15, rbp
        adc	r10, 0
        mov	r11, 9223372036854775807
        shld	r10, r15, 1
        imul	r10, r10, 19
        and	r15, r11
        xor	r11, r11
        adox	r12, r10
        mulx	rdi, r10, rdi
        adcx	r12, r10
        adox	r13, rdi
        mulx	rsi, r10, rsi
        adcx	r13, r10
        adox	r14, rsi
        mulx	rbx, r10, rbx
        adcx	r14, r10
        adox	r15, rbx
        adcx	r15, r11
        ; Store
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        mov	r9, rax
        lea	r8, QWORD PTR [rax+32]
        lea	rax, QWORD PTR [rcx+-64]
        lea	rcx, QWORD PTR [rcx+-96]
        ; Add-Sub
        ; Add
        mov	r12, QWORD PTR [r8]
        mov	r13, QWORD PTR [r8+8]
        mov	r14, QWORD PTR [r8+16]
        mov	r15, QWORD PTR [r8+24]
        mov	rdi, r12
        add	r12, QWORD PTR [r9]
        mov	rsi, r13
        adc	r13, QWORD PTR [r9+8]
        mov	rbx, r14
        adc	r14, QWORD PTR [r9+16]
        mov	rbp, r15
        adc	r15, QWORD PTR [r9+24]
        mov	rdx, 0
        adc	rdx, 0
        shld	rdx, r15, 1
        imul	rdx, 19
        btr	r15, 63
        ;   Sub modulus (if overflow)
        add	r12, rdx
        adc	r13, 0
        adc	r14, 0
        adc	r15, 0
        ; Sub
        sub	rdi, QWORD PTR [r9]
        sbb	rsi, QWORD PTR [r9+8]
        sbb	rbx, QWORD PTR [r9+16]
        sbb	rbp, QWORD PTR [r9+24]
        sbb	rdx, rdx
        shld	rdx, rbp, 1
        imul	rdx, -19
        btr	rbp, 63
        ;   Add modulus (if underflow)
        sub	rdi, rdx
        sbb	rsi, 0
        sbb	rbx, 0
        sbb	rbp, 0
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        mov	QWORD PTR [rax], rdi
        mov	QWORD PTR [rax+8], rsi
        mov	QWORD PTR [rax+16], rbx
        mov	QWORD PTR [rax+24], rbp
        mov	r8, QWORD PTR [rsp+16]
        ; Multiply
        ; A[0] * B[0]
        mov	rdx, QWORD PTR [r8]
        mulx	r13, r12, QWORD PTR [rcx]
        ; A[2] * B[0]
        mulx	r15, r14, QWORD PTR [rcx+16]
        ; A[1] * B[0]
        mulx	r11, r10, QWORD PTR [rcx+8]
        xor	rbp, rbp
        adcx	r13, r10
        ; A[3] * B[1]
        mov	rdx, QWORD PTR [r8+8]
        mulx	rsi, rdi, QWORD PTR [rcx+24]
        adcx	r14, r11
        ; A[0] * B[1]
        mulx	r11, r10, QWORD PTR [rcx]
        adox	r13, r10
        ; A[2] * B[1]
        mulx	rbx, r10, QWORD PTR [rcx+16]
        adox	r14, r11
        adcx	r15, r10
        ; A[1] * B[2]
        mov	rdx, QWORD PTR [r8+16]
        mulx	r11, r10, QWORD PTR [rcx+8]
        adcx	rdi, rbx
        adox	r15, r10
        adcx	rsi, rbp
        adox	rdi, r11
        ; A[0] * B[2]
        mulx	r11, r10, QWORD PTR [rcx]
        adox	rsi, rbp
        xor	rbx, rbx
        adcx	r14, r10
        ; A[1] * B[1]
        mov	rdx, QWORD PTR [r8+8]
        mulx	r10, rdx, QWORD PTR [rcx+8]
        adcx	r15, r11
        adox	r14, rdx
        ; A[1] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	r15, r10
        mulx	r11, r10, QWORD PTR [rcx+8]
        adcx	rdi, r10
        ; A[2] * B[2]
        mov	rdx, QWORD PTR [r8+16]
        mulx	r10, rdx, QWORD PTR [rcx+16]
        adcx	rsi, r11
        adox	rdi, rdx
        ; A[3] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	rsi, r10
        mulx	r11, r10, QWORD PTR [rcx+24]
        adox	rbx, rbp
        adcx	rbx, r10
        ; A[0] * B[3]
        mulx	r10, rdx, QWORD PTR [rcx]
        adcx	rbp, r11
        xor	r11, r11
        adcx	r15, rdx
        ; A[3] * B[0]
        mov	rdx, QWORD PTR [rcx+24]
        adcx	rdi, r10
        mulx	r10, rdx, QWORD PTR [r8]
        adox	r15, rdx
        adox	rdi, r10
        ; A[3] * B[2]
        mov	rdx, QWORD PTR [rcx+24]
        mulx	r10, rdx, QWORD PTR [r8+16]
        adcx	rsi, rdx
        ; A[2] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adcx	rbx, r10
        mulx	rdx, r10, QWORD PTR [rcx+16]
        adcx	rbp, r11
        adox	rsi, r10
        adox	rbx, rdx
        adox	rbp, r11
        mov	rdx, 38
        mulx	r10, rbp, rbp
        add	r15, rbp
        adc	r10, 0
        mov	r11, 9223372036854775807
        shld	r10, r15, 1
        imul	r10, r10, 19
        and	r15, r11
        xor	r11, r11
        adox	r12, r10
        mulx	rdi, r10, rdi
        adcx	r12, r10
        adox	r13, rdi
        mulx	rsi, r10, rsi
        adcx	r13, r10
        adox	r14, rsi
        mulx	rbx, r10, rbx
        adcx	r14, r10
        adox	r15, rbx
        adcx	r15, r11
        ; Store
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        lea	r8, QWORD PTR [r8+32]
        ; Multiply
        ; A[0] * B[0]
        mov	rdx, QWORD PTR [r8]
        mulx	r13, r12, QWORD PTR [rax]
        ; A[2] * B[0]
        mulx	r15, r14, QWORD PTR [rax+16]
        ; A[1] * B[0]
        mulx	r11, r10, QWORD PTR [rax+8]
        xor	rbp, rbp
        adcx	r13, r10
        ; A[3] * B[1]
        mov	rdx, QWORD PTR [r8+8]
        mulx	rsi, rdi, QWORD PTR [rax+24]
        adcx	r14, r11
        ; A[0] * B[1]
        mulx	r11, r10, QWORD PTR [rax]
        adox	r13, r10
        ; A[2] * B[1]
        mulx	rbx, r10, QWORD PTR [rax+16]
        adox	r14, r11
        adcx	r15, r10
        ; A[1] * B[2]
        mov	rdx, QWORD PTR [r8+16]
        mulx	r11, r10, QWORD PTR [rax+8]
        adcx	rdi, rbx
        adox	r15, r10
        adcx	rsi, rbp
        adox	rdi, r11
        ; A[0] * B[2]
        mulx	r11, r10, QWORD PTR [rax]
        adox	rsi, rbp
        xor	rbx, rbx
        adcx	r14, r10
        ; A[1] * B[1]
        mov	rdx, QWORD PTR [r8+8]
        mulx	r10, rdx, QWORD PTR [rax+8]
        adcx	r15, r11
        adox	r14, rdx
        ; A[1] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	r15, r10
        mulx	r11, r10, QWORD PTR [rax+8]
        adcx	rdi, r10
        ; A[2] * B[2]
        mov	rdx, QWORD PTR [r8+16]
        mulx	r10, rdx, QWORD PTR [rax+16]
        adcx	rsi, r11
        adox	rdi, rdx
        ; A[3] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	rsi, r10
        mulx	r11, r10, QWORD PTR [rax+24]
        adox	rbx, rbp
        adcx	rbx, r10
        ; A[0] * B[3]
        mulx	r10, rdx, QWORD PTR [rax]
        adcx	rbp, r11
        xor	r11, r11
        adcx	r15, rdx
        ; A[3] * B[0]
        mov	rdx, QWORD PTR [rax+24]
        adcx	rdi, r10
        mulx	r10, rdx, QWORD PTR [r8]
        adox	r15, rdx
        adox	rdi, r10
        ; A[3] * B[2]
        mov	rdx, QWORD PTR [rax+24]
        mulx	r10, rdx, QWORD PTR [r8+16]
        adcx	rsi, rdx
        ; A[2] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adcx	rbx, r10
        mulx	rdx, r10, QWORD PTR [rax+16]
        adcx	rbp, r11
        adox	rsi, r10
        adox	rbx, rdx
        adox	rbp, r11
        mov	rdx, 38
        mulx	r10, rbp, rbp
        add	r15, rbp
        adc	r10, 0
        mov	r11, 9223372036854775807
        shld	r10, r15, 1
        imul	r10, r10, 19
        and	r15, r11
        xor	r11, r11
        adox	r12, r10
        mulx	rdi, r10, rdi
        adcx	r12, r10
        adox	r13, rdi
        mulx	rsi, r10, rsi
        adcx	r13, r10
        adox	r14, rsi
        mulx	rbx, r10, rbx
        adcx	r14, r10
        adox	r15, rbx
        adcx	r15, r11
        ; Store
        mov	QWORD PTR [rax], r12
        mov	QWORD PTR [rax+8], r13
        mov	QWORD PTR [rax+16], r14
        mov	QWORD PTR [rax+24], r15
        lea	r9, QWORD PTR [r9+64]
        lea	r8, QWORD PTR [r8+32]
        ; Multiply
        ; A[0] * B[0]
        mov	rdx, QWORD PTR [r8]
        mulx	r13, r12, QWORD PTR [r9]
        ; A[2] * B[0]
        mulx	r15, r14, QWORD PTR [r9+16]
        ; A[1] * B[0]
        mulx	r11, r10, QWORD PTR [r9+8]
        xor	rbp, rbp
        adcx	r13, r10
        ; A[3] * B[1]
        mov	rdx, QWORD PTR [r8+8]
        mulx	rsi, rdi, QWORD PTR [r9+24]
        adcx	r14, r11
        ; A[0] * B[1]
        mulx	r11, r10, QWORD PTR [r9]
        adox	r13, r10
        ; A[2] * B[1]
        mulx	rbx, r10, QWORD PTR [r9+16]
        adox	r14, r11
        adcx	r15, r10
        ; A[1] * B[2]
        mov	rdx, QWORD PTR [r8+16]
        mulx	r11, r10, QWORD PTR [r9+8]
        adcx	rdi, rbx
        adox	r15, r10
        adcx	rsi, rbp
        adox	rdi, r11
        ; A[0] * B[2]
        mulx	r11, r10, QWORD PTR [r9]
        adox	rsi, rbp
        xor	rbx, rbx
        adcx	r14, r10
        ; A[1] * B[1]
        mov	rdx, QWORD PTR [r8+8]
        mulx	r10, rdx, QWORD PTR [r9+8]
        adcx	r15, r11
        adox	r14, rdx
        ; A[1] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	r15, r10
        mulx	r11, r10, QWORD PTR [r9+8]
        adcx	rdi, r10
        ; A[2] * B[2]
        mov	rdx, QWORD PTR [r8+16]
        mulx	r10, rdx, QWORD PTR [r9+16]
        adcx	rsi, r11
        adox	rdi, rdx
        ; A[3] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	rsi, r10
        mulx	r11, r10, QWORD PTR [r9+24]
        adox	rbx, rbp
        adcx	rbx, r10
        ; A[0] * B[3]
        mulx	r10, rdx, QWORD PTR [r9]
        adcx	rbp, r11
        xor	r11, r11
        adcx	r15, rdx
        ; A[3] * B[0]
        mov	rdx, QWORD PTR [r9+24]
        adcx	rdi, r10
        mulx	r10, rdx, QWORD PTR [r8]
        adox	r15, rdx
        adox	rdi, r10
        ; A[3] * B[2]
        mov	rdx, QWORD PTR [r9+24]
        mulx	r10, rdx, QWORD PTR [r8+16]
        adcx	rsi, rdx
        ; A[2] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adcx	rbx, r10
        mulx	rdx, r10, QWORD PTR [r9+16]
        adcx	rbp, r11
        adox	rsi, r10
        adox	rbx, rdx
        adox	rbp, r11
        mov	rdx, 38
        mulx	r10, rbp, rbp
        add	r15, rbp
        adc	r10, 0
        mov	r11, 9223372036854775807
        shld	r10, r15, 1
        imul	r10, r10, 19
        and	r15, r11
        xor	r11, r11
        adox	r12, r10
        mulx	rdi, r10, rdi
        adcx	r12, r10
        adox	r13, rdi
        mulx	rsi, r10, rsi
        adcx	r13, r10
        adox	r14, rsi
        mulx	rbx, r10, rbx
        adcx	r14, r10
        adox	r15, rbx
        adcx	r15, r11
        ; Store
        lea	rcx, QWORD PTR [rcx+64]
        ; Double
        add	r12, r12
        adc	r13, r13
        adc	r14, r14
        adc	r15, r15
        mov	rdx, 0
        adc	rdx, 0
        shld	rdx, r15, 1
        imul	rdx, 19
        btr	r15, 63
        ;   Sub modulus (if overflow)
        add	r12, rdx
        adc	r13, 0
        adc	r14, 0
        adc	r15, 0
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        lea	rcx, QWORD PTR [rcx+-64]
        ; Add-Sub
        ; Add
        mov	r12, QWORD PTR [rcx]
        mov	r13, QWORD PTR [rcx+8]
        mov	r14, QWORD PTR [rcx+16]
        mov	r15, QWORD PTR [rcx+24]
        mov	rdi, r12
        add	r12, QWORD PTR [rax]
        mov	rsi, r13
        adc	r13, QWORD PTR [rax+8]
        mov	rbx, r14
        adc	r14, QWORD PTR [rax+16]
        mov	rbp, r15
        adc	r15, QWORD PTR [rax+24]
        mov	rdx, 0
        adc	rdx, 0
        shld	rdx, r15, 1
        imul	rdx, 19
        btr	r15, 63
        ;   Sub modulus (if overflow)
        add	r12, rdx
        adc	r13, 0
        adc	r14, 0
        adc	r15, 0
        ; Sub
        sub	rdi, QWORD PTR [rax]
        sbb	rsi, QWORD PTR [rax+8]
        sbb	rbx, QWORD PTR [rax+16]
        sbb	rbp, QWORD PTR [rax+24]
        sbb	rdx, rdx
        shld	rdx, rbp, 1
        imul	rdx, -19
        btr	rbp, 63
        ;   Add modulus (if underflow)
        sub	rdi, rdx
        sbb	rsi, 0
        sbb	rbx, 0
        sbb	rbp, 0
        mov	QWORD PTR [rax], r12
        mov	QWORD PTR [rax+8], r13
        mov	QWORD PTR [rax+16], r14
        mov	QWORD PTR [rax+24], r15
        mov	QWORD PTR [rcx], rdi
        mov	QWORD PTR [rcx+8], rsi
        mov	QWORD PTR [rcx+16], rbx
        mov	QWORD PTR [rcx+24], rbp
        lea	rax, QWORD PTR [rcx+96]
        lea	rcx, QWORD PTR [rcx+64]
        ; Add-Sub
        ; Add
        mov	r12, QWORD PTR [rcx]
        mov	r13, QWORD PTR [rcx+8]
        mov	r14, QWORD PTR [rcx+16]
        mov	r15, QWORD PTR [rcx+24]
        mov	rdi, r12
        add	r12, QWORD PTR [rax]
        mov	rsi, r13
        adc	r13, QWORD PTR [rax+8]
        mov	rbx, r14
        adc	r14, QWORD PTR [rax+16]
        mov	rbp, r15
        adc	r15, QWORD PTR [rax+24]
        mov	rdx, 0
        adc	rdx, 0
        shld	rdx, r15, 1
        imul	rdx, 19
        btr	r15, 63
        ;   Sub modulus (if overflow)
        add	r12, rdx
        adc	r13, 0
        adc	r14, 0
        adc	r15, 0
        ; Sub
        sub	rdi, QWORD PTR [rax]
        sbb	rsi, QWORD PTR [rax+8]
        sbb	rbx, QWORD PTR [rax+16]
        sbb	rbp, QWORD PTR [rax+24]
        sbb	rdx, rdx
        shld	rdx, rbp, 1
        imul	rdx, -19
        btr	rbp, 63
        ;   Add modulus (if underflow)
        sub	rdi, rdx
        sbb	rsi, 0
        sbb	rbx, 0
        sbb	rbp, 0
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        mov	QWORD PTR [rax], rdi
        mov	QWORD PTR [rax+8], rsi
        mov	QWORD PTR [rax+16], rbx
        mov	QWORD PTR [rax+24], rbp
        add	rsp, 24
        pop	rbp
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
ge_add_avx2 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
ge_sub_avx2 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        push	rbp
        mov	rax, rdx
        sub	rsp, 24
        mov	QWORD PTR [rsp], rcx
        mov	QWORD PTR [rsp+8], rax
        mov	QWORD PTR [rsp+16], r8
        lea	r9, QWORD PTR [rax+96]
        lea	r8, QWORD PTR [r8+96]
        lea	rcx, QWORD PTR [rcx+96]
        ; Multiply
        ; A[0] * B[0]
        mov	rdx, QWORD PTR [r8]
        mulx	r13, r12, QWORD PTR [r9]
        ; A[2] * B[0]
        mulx	r15, r14, QWORD PTR [r9+16]
        ; A[1] * B[0]
        mulx	r11, r10, QWORD PTR [r9+8]
        xor	rbp, rbp
        adcx	r13, r10
        ; A[3] * B[1]
        mov	rdx, QWORD PTR [r8+8]
        mulx	rsi, rdi, QWORD PTR [r9+24]
        adcx	r14, r11
        ; A[0] * B[1]
        mulx	r11, r10, QWORD PTR [r9]
        adox	r13, r10
        ; A[2] * B[1]
        mulx	rbx, r10, QWORD PTR [r9+16]
        adox	r14, r11
        adcx	r15, r10
        ; A[1] * B[2]
        mov	rdx, QWORD PTR [r8+16]
        mulx	r11, r10, QWORD PTR [r9+8]
        adcx	rdi, rbx
        adox	r15, r10
        adcx	rsi, rbp
        adox	rdi, r11
        ; A[0] * B[2]
        mulx	r11, r10, QWORD PTR [r9]
        adox	rsi, rbp
        xor	rbx, rbx
        adcx	r14, r10
        ; A[1] * B[1]
        mov	rdx, QWORD PTR [r8+8]
        mulx	r10, rdx, QWORD PTR [r9+8]
        adcx	r15, r11
        adox	r14, rdx
        ; A[1] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	r15, r10
        mulx	r11, r10, QWORD PTR [r9+8]
        adcx	rdi, r10
        ; A[2] * B[2]
        mov	rdx, QWORD PTR [r8+16]
        mulx	r10, rdx, QWORD PTR [r9+16]
        adcx	rsi, r11
        adox	rdi, rdx
        ; A[3] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	rsi, r10
        mulx	r11, r10, QWORD PTR [r9+24]
        adox	rbx, rbp
        adcx	rbx, r10
        ; A[0] * B[3]
        mulx	r10, rdx, QWORD PTR [r9]
        adcx	rbp, r11
        xor	r11, r11
        adcx	r15, rdx
        ; A[3] * B[0]
        mov	rdx, QWORD PTR [r9+24]
        adcx	rdi, r10
        mulx	r10, rdx, QWORD PTR [r8]
        adox	r15, rdx
        adox	rdi, r10
        ; A[3] * B[2]
        mov	rdx, QWORD PTR [r9+24]
        mulx	r10, rdx, QWORD PTR [r8+16]
        adcx	rsi, rdx
        ; A[2] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adcx	rbx, r10
        mulx	rdx, r10, QWORD PTR [r9+16]
        adcx	rbp, r11
        adox	rsi, r10
        adox	rbx, rdx
        adox	rbp, r11
        mov	rdx, 38
        mulx	r10, rbp, rbp
        add	r15, rbp
        adc	r10, 0
        mov	r11, 9223372036854775807
        shld	r10, r15, 1
        imul	r10, r10, 19
        and	r15, r11
        xor	r11, r11
        adox	r12, r10
        mulx	rdi, r10, rdi
        adcx	r12, r10
        adox	r13, rdi
        mulx	rsi, r10, rsi
        adcx	r13, r10
        adox	r14, rsi
        mulx	rbx, r10, rbx
        adcx	r14, r10
        adox	r15, rbx
        adcx	r15, r11
        ; Store
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        mov	r9, rax
        lea	r8, QWORD PTR [rax+32]
        lea	rax, QWORD PTR [rcx+-64]
        lea	rcx, QWORD PTR [rcx+-96]
        ; Add-Sub
        ; Add
        mov	r12, QWORD PTR [r8]
        mov	r13, QWORD PTR [r8+8]
        mov	r14, QWORD PTR [r8+16]
        mov	r15, QWORD PTR [r8+24]
        mov	rdi, r12
        add	r12, QWORD PTR [r9]
        mov	rsi, r13
        adc	r13, QWORD PTR [r9+8]
        mov	rbx, r14
        adc	r14, QWORD PTR [r9+16]
        mov	rbp, r15
        adc	r15, QWORD PTR [r9+24]
        mov	rdx, 0
        adc	rdx, 0
        shld	rdx, r15, 1
        imul	rdx, 19
        btr	r15, 63
        ;   Sub modulus (if overflow)
        add	r12, rdx
        adc	r13, 0
        adc	r14, 0
        adc	r15, 0
        ; Sub
        sub	rdi, QWORD PTR [r9]
        sbb	rsi, QWORD PTR [r9+8]
        sbb	rbx, QWORD PTR [r9+16]
        sbb	rbp, QWORD PTR [r9+24]
        sbb	rdx, rdx
        shld	rdx, rbp, 1
        imul	rdx, -19
        btr	rbp, 63
        ;   Add modulus (if underflow)
        sub	rdi, rdx
        sbb	rsi, 0
        sbb	rbx, 0
        sbb	rbp, 0
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        mov	QWORD PTR [rax], rdi
        mov	QWORD PTR [rax+8], rsi
        mov	QWORD PTR [rax+16], rbx
        mov	QWORD PTR [rax+24], rbp
        mov	r8, QWORD PTR [rsp+16]
        lea	r8, QWORD PTR [r8+32]
        ; Multiply
        ; A[0] * B[0]
        mov	rdx, QWORD PTR [r8]
        mulx	r13, r12, QWORD PTR [rcx]
        ; A[2] * B[0]
        mulx	r15, r14, QWORD PTR [rcx+16]
        ; A[1] * B[0]
        mulx	r11, r10, QWORD PTR [rcx+8]
        xor	rbp, rbp
        adcx	r13, r10
        ; A[3] * B[1]
        mov	rdx, QWORD PTR [r8+8]
        mulx	rsi, rdi, QWORD PTR [rcx+24]
        adcx	r14, r11
        ; A[0] * B[1]
        mulx	r11, r10, QWORD PTR [rcx]
        adox	r13, r10
        ; A[2] * B[1]
        mulx	rbx, r10, QWORD PTR [rcx+16]
        adox	r14, r11
        adcx	r15, r10
        ; A[1] * B[2]
        mov	rdx, QWORD PTR [r8+16]
        mulx	r11, r10, QWORD PTR [rcx+8]
        adcx	rdi, rbx
        adox	r15, r10
        adcx	rsi, rbp
        adox	rdi, r11
        ; A[0] * B[2]
        mulx	r11, r10, QWORD PTR [rcx]
        adox	rsi, rbp
        xor	rbx, rbx
        adcx	r14, r10
        ; A[1] * B[1]
        mov	rdx, QWORD PTR [r8+8]
        mulx	r10, rdx, QWORD PTR [rcx+8]
        adcx	r15, r11
        adox	r14, rdx
        ; A[1] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	r15, r10
        mulx	r11, r10, QWORD PTR [rcx+8]
        adcx	rdi, r10
        ; A[2] * B[2]
        mov	rdx, QWORD PTR [r8+16]
        mulx	r10, rdx, QWORD PTR [rcx+16]
        adcx	rsi, r11
        adox	rdi, rdx
        ; A[3] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	rsi, r10
        mulx	r11, r10, QWORD PTR [rcx+24]
        adox	rbx, rbp
        adcx	rbx, r10
        ; A[0] * B[3]
        mulx	r10, rdx, QWORD PTR [rcx]
        adcx	rbp, r11
        xor	r11, r11
        adcx	r15, rdx
        ; A[3] * B[0]
        mov	rdx, QWORD PTR [rcx+24]
        adcx	rdi, r10
        mulx	r10, rdx, QWORD PTR [r8]
        adox	r15, rdx
        adox	rdi, r10
        ; A[3] * B[2]
        mov	rdx, QWORD PTR [rcx+24]
        mulx	r10, rdx, QWORD PTR [r8+16]
        adcx	rsi, rdx
        ; A[2] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adcx	rbx, r10
        mulx	rdx, r10, QWORD PTR [rcx+16]
        adcx	rbp, r11
        adox	rsi, r10
        adox	rbx, rdx
        adox	rbp, r11
        mov	rdx, 38
        mulx	r10, rbp, rbp
        add	r15, rbp
        adc	r10, 0
        mov	r11, 9223372036854775807
        shld	r10, r15, 1
        imul	r10, r10, 19
        and	r15, r11
        xor	r11, r11
        adox	r12, r10
        mulx	rdi, r10, rdi
        adcx	r12, r10
        adox	r13, rdi
        mulx	rsi, r10, rsi
        adcx	r13, r10
        adox	r14, rsi
        mulx	rbx, r10, rbx
        adcx	r14, r10
        adox	r15, rbx
        adcx	r15, r11
        ; Store
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        lea	r8, QWORD PTR [r8+-32]
        ; Multiply
        ; A[0] * B[0]
        mov	rdx, QWORD PTR [r8]
        mulx	r13, r12, QWORD PTR [rax]
        ; A[2] * B[0]
        mulx	r15, r14, QWORD PTR [rax+16]
        ; A[1] * B[0]
        mulx	r11, r10, QWORD PTR [rax+8]
        xor	rbp, rbp
        adcx	r13, r10
        ; A[3] * B[1]
        mov	rdx, QWORD PTR [r8+8]
        mulx	rsi, rdi, QWORD PTR [rax+24]
        adcx	r14, r11
        ; A[0] * B[1]
        mulx	r11, r10, QWORD PTR [rax]
        adox	r13, r10
        ; A[2] * B[1]
        mulx	rbx, r10, QWORD PTR [rax+16]
        adox	r14, r11
        adcx	r15, r10
        ; A[1] * B[2]
        mov	rdx, QWORD PTR [r8+16]
        mulx	r11, r10, QWORD PTR [rax+8]
        adcx	rdi, rbx
        adox	r15, r10
        adcx	rsi, rbp
        adox	rdi, r11
        ; A[0] * B[2]
        mulx	r11, r10, QWORD PTR [rax]
        adox	rsi, rbp
        xor	rbx, rbx
        adcx	r14, r10
        ; A[1] * B[1]
        mov	rdx, QWORD PTR [r8+8]
        mulx	r10, rdx, QWORD PTR [rax+8]
        adcx	r15, r11
        adox	r14, rdx
        ; A[1] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	r15, r10
        mulx	r11, r10, QWORD PTR [rax+8]
        adcx	rdi, r10
        ; A[2] * B[2]
        mov	rdx, QWORD PTR [r8+16]
        mulx	r10, rdx, QWORD PTR [rax+16]
        adcx	rsi, r11
        adox	rdi, rdx
        ; A[3] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	rsi, r10
        mulx	r11, r10, QWORD PTR [rax+24]
        adox	rbx, rbp
        adcx	rbx, r10
        ; A[0] * B[3]
        mulx	r10, rdx, QWORD PTR [rax]
        adcx	rbp, r11
        xor	r11, r11
        adcx	r15, rdx
        ; A[3] * B[0]
        mov	rdx, QWORD PTR [rax+24]
        adcx	rdi, r10
        mulx	r10, rdx, QWORD PTR [r8]
        adox	r15, rdx
        adox	rdi, r10
        ; A[3] * B[2]
        mov	rdx, QWORD PTR [rax+24]
        mulx	r10, rdx, QWORD PTR [r8+16]
        adcx	rsi, rdx
        ; A[2] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adcx	rbx, r10
        mulx	rdx, r10, QWORD PTR [rax+16]
        adcx	rbp, r11
        adox	rsi, r10
        adox	rbx, rdx
        adox	rbp, r11
        mov	rdx, 38
        mulx	r10, rbp, rbp
        add	r15, rbp
        adc	r10, 0
        mov	r11, 9223372036854775807
        shld	r10, r15, 1
        imul	r10, r10, 19
        and	r15, r11
        xor	r11, r11
        adox	r12, r10
        mulx	rdi, r10, rdi
        adcx	r12, r10
        adox	r13, rdi
        mulx	rsi, r10, rsi
        adcx	r13, r10
        adox	r14, rsi
        mulx	rbx, r10, rbx
        adcx	r14, r10
        adox	r15, rbx
        adcx	r15, r11
        ; Store
        mov	QWORD PTR [rax], r12
        mov	QWORD PTR [rax+8], r13
        mov	QWORD PTR [rax+16], r14
        mov	QWORD PTR [rax+24], r15
        lea	r9, QWORD PTR [r9+64]
        lea	r8, QWORD PTR [r8+64]
        ; Multiply
        ; A[0] * B[0]
        mov	rdx, QWORD PTR [r8]
        mulx	r13, r12, QWORD PTR [r9]
        ; A[2] * B[0]
        mulx	r15, r14, QWORD PTR [r9+16]
        ; A[1] * B[0]
        mulx	r11, r10, QWORD PTR [r9+8]
        xor	rbp, rbp
        adcx	r13, r10
        ; A[3] * B[1]
        mov	rdx, QWORD PTR [r8+8]
        mulx	rsi, rdi, QWORD PTR [r9+24]
        adcx	r14, r11
        ; A[0] * B[1]
        mulx	r11, r10, QWORD PTR [r9]
        adox	r13, r10
        ; A[2] * B[1]
        mulx	rbx, r10, QWORD PTR [r9+16]
        adox	r14, r11
        adcx	r15, r10
        ; A[1] * B[2]
        mov	rdx, QWORD PTR [r8+16]
        mulx	r11, r10, QWORD PTR [r9+8]
        adcx	rdi, rbx
        adox	r15, r10
        adcx	rsi, rbp
        adox	rdi, r11
        ; A[0] * B[2]
        mulx	r11, r10, QWORD PTR [r9]
        adox	rsi, rbp
        xor	rbx, rbx
        adcx	r14, r10
        ; A[1] * B[1]
        mov	rdx, QWORD PTR [r8+8]
        mulx	r10, rdx, QWORD PTR [r9+8]
        adcx	r15, r11
        adox	r14, rdx
        ; A[1] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	r15, r10
        mulx	r11, r10, QWORD PTR [r9+8]
        adcx	rdi, r10
        ; A[2] * B[2]
        mov	rdx, QWORD PTR [r8+16]
        mulx	r10, rdx, QWORD PTR [r9+16]
        adcx	rsi, r11
        adox	rdi, rdx
        ; A[3] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adox	rsi, r10
        mulx	r11, r10, QWORD PTR [r9+24]
        adox	rbx, rbp
        adcx	rbx, r10
        ; A[0] * B[3]
        mulx	r10, rdx, QWORD PTR [r9]
        adcx	rbp, r11
        xor	r11, r11
        adcx	r15, rdx
        ; A[3] * B[0]
        mov	rdx, QWORD PTR [r9+24]
        adcx	rdi, r10
        mulx	r10, rdx, QWORD PTR [r8]
        adox	r15, rdx
        adox	rdi, r10
        ; A[3] * B[2]
        mov	rdx, QWORD PTR [r9+24]
        mulx	r10, rdx, QWORD PTR [r8+16]
        adcx	rsi, rdx
        ; A[2] * B[3]
        mov	rdx, QWORD PTR [r8+24]
        adcx	rbx, r10
        mulx	rdx, r10, QWORD PTR [r9+16]
        adcx	rbp, r11
        adox	rsi, r10
        adox	rbx, rdx
        adox	rbp, r11
        mov	rdx, 38
        mulx	r10, rbp, rbp
        add	r15, rbp
        adc	r10, 0
        mov	r11, 9223372036854775807
        shld	r10, r15, 1
        imul	r10, r10, 19
        and	r15, r11
        xor	r11, r11
        adox	r12, r10
        mulx	rdi, r10, rdi
        adcx	r12, r10
        adox	r13, rdi
        mulx	rsi, r10, rsi
        adcx	r13, r10
        adox	r14, rsi
        mulx	rbx, r10, rbx
        adcx	r14, r10
        adox	r15, rbx
        adcx	r15, r11
        ; Store
        lea	rcx, QWORD PTR [rcx+64]
        ; Double
        add	r12, r12
        adc	r13, r13
        adc	r14, r14
        adc	r15, r15
        mov	rdx, 0
        adc	rdx, 0
        shld	rdx, r15, 1
        imul	rdx, 19
        btr	r15, 63
        ;   Sub modulus (if overflow)
        add	r12, rdx
        adc	r13, 0
        adc	r14, 0
        adc	r15, 0
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        lea	rcx, QWORD PTR [rcx+-64]
        ; Add-Sub
        ; Add
        mov	r12, QWORD PTR [rcx]
        mov	r13, QWORD PTR [rcx+8]
        mov	r14, QWORD PTR [rcx+16]
        mov	r15, QWORD PTR [rcx+24]
        mov	rdi, r12
        add	r12, QWORD PTR [rax]
        mov	rsi, r13
        adc	r13, QWORD PTR [rax+8]
        mov	rbx, r14
        adc	r14, QWORD PTR [rax+16]
        mov	rbp, r15
        adc	r15, QWORD PTR [rax+24]
        mov	rdx, 0
        adc	rdx, 0
        shld	rdx, r15, 1
        imul	rdx, 19
        btr	r15, 63
        ;   Sub modulus (if overflow)
        add	r12, rdx
        adc	r13, 0
        adc	r14, 0
        adc	r15, 0
        ; Sub
        sub	rdi, QWORD PTR [rax]
        sbb	rsi, QWORD PTR [rax+8]
        sbb	rbx, QWORD PTR [rax+16]
        sbb	rbp, QWORD PTR [rax+24]
        sbb	rdx, rdx
        shld	rdx, rbp, 1
        imul	rdx, -19
        btr	rbp, 63
        ;   Add modulus (if underflow)
        sub	rdi, rdx
        sbb	rsi, 0
        sbb	rbx, 0
        sbb	rbp, 0
        mov	QWORD PTR [rax], r12
        mov	QWORD PTR [rax+8], r13
        mov	QWORD PTR [rax+16], r14
        mov	QWORD PTR [rax+24], r15
        mov	QWORD PTR [rcx], rdi
        mov	QWORD PTR [rcx+8], rsi
        mov	QWORD PTR [rcx+16], rbx
        mov	QWORD PTR [rcx+24], rbp
        lea	rax, QWORD PTR [rcx+64]
        lea	rcx, QWORD PTR [rcx+96]
        ; Add-Sub
        ; Add
        mov	r12, QWORD PTR [rax]
        mov	r13, QWORD PTR [rax+8]
        mov	r14, QWORD PTR [rax+16]
        mov	r15, QWORD PTR [rax+24]
        mov	rdi, r12
        add	r12, QWORD PTR [rcx]
        mov	rsi, r13
        adc	r13, QWORD PTR [rcx+8]
        mov	rbx, r14
        adc	r14, QWORD PTR [rcx+16]
        mov	rbp, r15
        adc	r15, QWORD PTR [rcx+24]
        mov	rdx, 0
        adc	rdx, 0
        shld	rdx, r15, 1
        imul	rdx, 19
        btr	r15, 63
        ;   Sub modulus (if overflow)
        add	r12, rdx
        adc	r13, 0
        adc	r14, 0
        adc	r15, 0
        ; Sub
        sub	rdi, QWORD PTR [rcx]
        sbb	rsi, QWORD PTR [rcx+8]
        sbb	rbx, QWORD PTR [rcx+16]
        sbb	rbp, QWORD PTR [rcx+24]
        sbb	rdx, rdx
        shld	rdx, rbp, 1
        imul	rdx, -19
        btr	rbp, 63
        ;   Add modulus (if underflow)
        sub	rdi, rdx
        sbb	rsi, 0
        sbb	rbx, 0
        sbb	rbp, 0
        mov	QWORD PTR [rcx], r12
        mov	QWORD PTR [rcx+8], r13
        mov	QWORD PTR [rcx+16], r14
        mov	QWORD PTR [rcx+24], r15
        mov	QWORD PTR [rax], rdi
        mov	QWORD PTR [rax+8], rsi
        mov	QWORD PTR [rax+16], rbx
        mov	QWORD PTR [rax+24], rbp
        add	rsp, 24
        pop	rbp
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
ge_sub_avx2 ENDP
_TEXT ENDS
IFDEF HAVE_ED25519
_TEXT SEGMENT READONLY PARA
fe_sq2_avx2 PROC
        push	rbx
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        mov	rdi, rcx
        mov	rsi, rdx
        ; Square * 2
        mov	rdx, QWORD PTR [rsi]
        mov	rax, QWORD PTR [rsi+8]
        ; A[0] * A[1]
        mov	r15, rdx
        mulx	r10, r9, rax
        ; A[0] * A[3]
        mulx	r12, r11, QWORD PTR [rsi+24]
        ; A[2] * A[1]
        mov	rdx, QWORD PTR [rsi+16]
        mulx	rbx, rcx, rax
        xor	r8, r8
        adox	r11, rcx
        ; A[2] * A[3]
        mulx	r14, r13, QWORD PTR [rsi+24]
        adox	r12, rbx
        ; A[2] * A[0]
        mulx	rbx, rcx, r15
        adox	r13, r8
        adcx	r10, rcx
        adox	r14, r8
        ; A[1] * A[3]
        mov	rdx, rax
        mulx	rdx, rcx, QWORD PTR [rsi+24]
        adcx	r11, rbx
        adcx	r12, rcx
        adcx	r13, rdx
        adcx	r14, r8
        ; A[0] * A[0]
        mov	rdx, r15
        mulx	rcx, r8, rdx
        xor	r15, r15
        adcx	r9, r9
        ; A[1] * A[1]
        mov	rdx, rax
        adox	r9, rcx
        mulx	rbx, rcx, rdx
        adcx	r10, r10
        adox	r10, rcx
        adcx	r11, r11
        ; A[2] * A[2]
        mov	rdx, QWORD PTR [rsi+16]
        adox	r11, rbx
        mulx	rcx, rbx, rdx
        adcx	r12, r12
        adox	r12, rbx
        adcx	r13, r13
        ; A[3] * A[3]
        mov	rdx, QWORD PTR [rsi+24]
        adox	r13, rcx
        mulx	rbx, rcx, rdx
        adcx	r14, r14
        adox	r14, rcx
        adcx	r15, r15
        adox	r15, rbx
        mov	rdx, 38
        mulx	rax, r15, r15
        add	r11, r15
        adc	rax, 0
        mov	rcx, 9223372036854775807
        shld	rax, r11, 1
        imul	rax, rax, 19
        and	r11, rcx
        xor	rcx, rcx
        adox	r8, rax
        mulx	r12, rax, r12
        adcx	r8, rax
        adox	r9, r12
        mulx	r13, rax, r13
        adcx	r9, rax
        adox	r10, r13
        mulx	r14, rax, r14
        adcx	r10, rax
        adox	r11, r14
        adcx	r11, rcx
        mov	rax, r11
        shld	r11, r10, 1
        shld	r10, r9, 1
        shld	r9, r8, 1
        shl	r8, 1
        mov	rcx, 9223372036854775807
        shr	rax, 62
        and	r11, rcx
        imul	rax, rax, 19
        add	r8, rax
        adc	r9, 0
        adc	r10, 0
        adc	r11, 0
        ; Store
        mov	QWORD PTR [rdi], r8
        mov	QWORD PTR [rdi+8], r9
        mov	QWORD PTR [rdi+16], r10
        mov	QWORD PTR [rdi+24], r11
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        pop	rbx
        ret
fe_sq2_avx2 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
sc_reduce_avx2 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        push	rbp
        mov	r8, rcx
        mov	r9, QWORD PTR [r8]
        mov	r10, QWORD PTR [r8+8]
        mov	r11, QWORD PTR [r8+16]
        mov	r12, QWORD PTR [r8+24]
        mov	r13, QWORD PTR [r8+32]
        mov	r14, QWORD PTR [r8+40]
        mov	r15, QWORD PTR [r8+48]
        mov	rdi, QWORD PTR [r8+56]
        mov	rax, rdi
        mov	rcx, 1152921504606846975
        shr	rax, 56
        shld	rdi, r15, 4
        shld	r15, r14, 4
        shld	r14, r13, 4
        shld	r13, r12, 4
        and	r12, rcx
        and	rdi, rcx
        ; Add order times bits 504..511
        sub	r15, rax
        sbb	rdi, 0
        mov	rdx, 16942830013509034793
        mulx	rcx, rsi, rax
        mov	rdx, 12100500283911187475
        add	r14, rsi
        mulx	rbx, rsi, rax
        adc	rcx, 0
        add	r13, rsi
        adc	r14, rbx
        adc	r15, rcx
        adc	rdi, 0
        ; Sub product of top 4 words and order
        mov	rdx, 12100500283911187475
        mulx	rax, rcx, r13
        add	r9, rcx
        adc	r10, rax
        mulx	rax, rcx, r15
        adc	r11, rcx
        adc	r12, rax
        mov	rsi, 0
        adc	rsi, 0
        mulx	rax, rcx, r14
        add	r10, rcx
        adc	r11, rax
        mulx	rax, rcx, rdi
        adc	r12, rcx
        adc	rsi, rax
        mov	rdx, 16942830013509034793
        mulx	rax, rcx, r13
        add	r10, rcx
        adc	r11, rax
        mulx	rax, rcx, r15
        adc	r12, rcx
        adc	rsi, rax
        mov	rbx, 0
        adc	rbx, 0
        mulx	rax, rcx, r14
        add	r11, rcx
        adc	r12, rax
        mulx	rax, rcx, rdi
        adc	rsi, rcx
        adc	rbx, rax
        sub	r11, r13
        mov	r13, rsi
        sbb	r12, r14
        mov	r14, rbx
        sbb	r13, r15
        sbb	r14, rdi
        mov	rax, r14
        sar	rax, 57
        ;   Conditionally subtract order starting at bit 125
        mov	rsi, 11529215046068469760
        mov	rbx, 14628338529006959229
        mov	rbp, 187989257525064602
        mov	rcx, 144115188075855872
        and	rsi, rax
        and	rbx, rax
        and	rbp, rax
        and	rcx, rax
        add	r10, rsi
        adc	r11, rbx
        adc	r12, rbp
        adc	r13, 0
        adc	r14, rcx
        ;   Move bits 252-376 to own registers
        mov	rax, 1152921504606846975
        shld	r14, r13, 4
        shld	r13, r12, 4
        and	r12, rax
        ; Sub product of top 2 words and order
        ;   * -5812631a5cf5d3ed
        mov	rdx, 12100500283911187475
        mulx	rax, rbp, r13
        mov	rsi, 0
        add	r9, rbp
        adc	r10, rax
        mulx	rax, rbp, r14
        adc	rsi, 0
        add	r10, rbp
        adc	rsi, rax
        ;   * -14def9dea2f79cd7
        mov	rdx, 16942830013509034793
        mulx	rax, rbp, r13
        mov	rbx, 0
        add	r10, rbp
        adc	r11, rax
        mulx	rax, rbp, r14
        adc	rbx, 0
        add	r11, rbp
        adc	rbx, rax
        ;   Add overflows at 2 * 64
        mov	rcx, 1152921504606846975
        and	r12, rcx
        add	r11, rsi
        adc	r12, rbx
        ;   Subtract top at 2 * 64
        sub	r11, r13
        sbb	r12, r14
        sbb	rcx, rcx
        ;   Conditional sub order
        mov	rsi, 6346243789798364141
        mov	rbx, 1503914060200516822
        mov	rbp, 1152921504606846976
        and	rsi, rcx
        and	rbx, rcx
        and	rbp, rcx
        add	r9, rsi
        mov	rsi, 1152921504606846975
        adc	r10, rbx
        adc	r11, 0
        adc	r12, rbp
        and	r12, rsi
        ; Store result
        mov	QWORD PTR [r8], r9
        mov	QWORD PTR [r8+8], r10
        mov	QWORD PTR [r8+16], r11
        mov	QWORD PTR [r8+24], r12
        pop	rbp
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
sc_reduce_avx2 ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
sc_muladd_avx2 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        push	rbp
        mov	r10, r8
        mov	r8, rcx
        mov	r11, r9
        mov	r9, rdx
        ; Multiply
        ; A[0] * B[0]
        mov	rdx, QWORD PTR [r10]
        mulx	r13, r12, QWORD PTR [r9]
        ; A[2] * B[0]
        mulx	r15, r14, QWORD PTR [r9+16]
        ; A[1] * B[0]
        mulx	rcx, rax, QWORD PTR [r9+8]
        xor	rbp, rbp
        adcx	r13, rax
        ; A[3] * B[1]
        mov	rdx, QWORD PTR [r10+8]
        mulx	rsi, rdi, QWORD PTR [r9+24]
        adcx	r14, rcx
        ; A[0] * B[1]
        mulx	rcx, rax, QWORD PTR [r9]
        adox	r13, rax
        ; A[2] * B[1]
        mulx	rbx, rax, QWORD PTR [r9+16]
        adox	r14, rcx
        adcx	r15, rax
        ; A[1] * B[2]
        mov	rdx, QWORD PTR [r10+16]
        mulx	rcx, rax, QWORD PTR [r9+8]
        adcx	rdi, rbx
        adox	r15, rax
        adcx	rsi, rbp
        adox	rdi, rcx
        ; A[0] * B[2]
        mulx	rcx, rax, QWORD PTR [r9]
        adox	rsi, rbp
        xor	rbx, rbx
        adcx	r14, rax
        ; A[1] * B[1]
        mov	rdx, QWORD PTR [r10+8]
        mulx	rax, rdx, QWORD PTR [r9+8]
        adcx	r15, rcx
        adox	r14, rdx
        ; A[1] * B[3]
        mov	rdx, QWORD PTR [r10+24]
        adox	r15, rax
        mulx	rcx, rax, QWORD PTR [r9+8]
        adcx	rdi, rax
        ; A[2] * B[2]
        mov	rdx, QWORD PTR [r10+16]
        mulx	rax, rdx, QWORD PTR [r9+16]
        adcx	rsi, rcx
        adox	rdi, rdx
        ; A[3] * B[3]
        mov	rdx, QWORD PTR [r10+24]
        adox	rsi, rax
        mulx	rcx, rax, QWORD PTR [r9+24]
        adox	rbx, rbp
        adcx	rbx, rax
        ; A[0] * B[3]
        mulx	rax, rdx, QWORD PTR [r9]
        adcx	rbp, rcx
        xor	rcx, rcx
        adcx	r15, rdx
        ; A[3] * B[0]
        mov	rdx, QWORD PTR [r9+24]
        adcx	rdi, rax
        mulx	rax, rdx, QWORD PTR [r10]
        adox	r15, rdx
        adox	rdi, rax
        ; A[3] * B[2]
        mov	rdx, QWORD PTR [r9+24]
        mulx	rax, rdx, QWORD PTR [r10+16]
        adcx	rsi, rdx
        ; A[2] * B[3]
        mov	rdx, QWORD PTR [r10+24]
        adcx	rbx, rax
        mulx	rdx, rax, QWORD PTR [r9+16]
        adcx	rbp, rcx
        adox	rsi, rax
        adox	rbx, rdx
        adox	rbp, rcx
        ; Add c to a * b
        add	r12, QWORD PTR [r11]
        adc	r13, QWORD PTR [r11+8]
        adc	r14, QWORD PTR [r11+16]
        adc	r15, QWORD PTR [r11+24]
        adc	rdi, 0
        adc	rsi, 0
        adc	rbx, 0
        adc	rbp, 0
        mov	rax, rbp
        mov	rcx, 1152921504606846975
        shr	rax, 56
        shld	rbp, rbx, 4
        shld	rbx, rsi, 4
        shld	rsi, rdi, 4
        shld	rdi, r15, 4
        and	r15, rcx
        and	rbp, rcx
        ; Add order times bits 504..507
        sub	rbx, rax
        sbb	rbp, 0
        mov	rdx, 16942830013509034793
        mulx	rcx, r9, rax
        mov	rdx, 12100500283911187475
        add	rsi, r9
        mulx	r10, r9, rax
        adc	rcx, 0
        add	rdi, r9
        adc	rsi, r10
        adc	rbx, rcx
        adc	rbp, 0
        ; Sub product of top 4 words and order
        mov	rdx, 12100500283911187475
        mulx	rax, rcx, rdi
        add	r12, rcx
        adc	r13, rax
        mulx	rax, rcx, rbx
        adc	r14, rcx
        adc	r15, rax
        mov	r9, 0
        adc	r9, 0
        mulx	rax, rcx, rsi
        add	r13, rcx
        adc	r14, rax
        mulx	rax, rcx, rbp
        adc	r15, rcx
        adc	r9, rax
        mov	rdx, 16942830013509034793
        mulx	rax, rcx, rdi
        add	r13, rcx
        adc	r14, rax
        mulx	rax, rcx, rbx
        adc	r15, rcx
        adc	r9, rax
        mov	r10, 0
        adc	r10, 0
        mulx	rax, rcx, rsi
        add	r14, rcx
        adc	r15, rax
        mulx	rax, rcx, rbp
        adc	r9, rcx
        adc	r10, rax
        sub	r14, rdi
        mov	rdi, r9
        sbb	r15, rsi
        mov	rsi, r10
        sbb	rdi, rbx
        sbb	rsi, rbp
        mov	rax, rsi
        sar	rax, 57
        ;   Conditionally subtract order starting at bit 125
        mov	r9, 11529215046068469760
        mov	r10, 14628338529006959229
        mov	r11, 187989257525064602
        mov	rcx, 144115188075855872
        and	r9, rax
        and	r10, rax
        and	r11, rax
        and	rcx, rax
        add	r13, r9
        adc	r14, r10
        adc	r15, r11
        adc	rdi, 0
        adc	rsi, rcx
        ;   Move bits 252-376 to own registers
        mov	rax, 1152921504606846975
        shld	rsi, rdi, 4
        shld	rdi, r15, 4
        and	r15, rax
        ; Sub product of top 2 words and order
        ;   * -5812631a5cf5d3ed
        mov	rdx, 12100500283911187475
        mulx	rax, r11, rdi
        mov	r9, 0
        add	r12, r11
        adc	r13, rax
        mulx	rax, r11, rsi
        adc	r9, 0
        add	r13, r11
        adc	r9, rax
        ;   * -14def9dea2f79cd7
        mov	rdx, 16942830013509034793
        mulx	rax, r11, rdi
        mov	r10, 0
        add	r13, r11
        adc	r14, rax
        mulx	rax, r11, rsi
        adc	r10, 0
        add	r14, r11
        adc	r10, rax
        ;   Add overflows at 2 * 64
        mov	rcx, 1152921504606846975
        and	r15, rcx
        add	r14, r9
        adc	r15, r10
        ;   Subtract top at 2 * 64
        sub	r14, rdi
        sbb	r15, rsi
        sbb	rcx, rcx
        ;   Conditional sub order
        mov	r9, 6346243789798364141
        mov	r10, 1503914060200516822
        mov	r11, 1152921504606846976
        and	r9, rcx
        and	r10, rcx
        and	r11, rcx
        add	r12, r9
        mov	r9, 1152921504606846975
        adc	r13, r10
        adc	r14, 0
        adc	r15, r11
        and	r15, r9
        ; Store result
        mov	QWORD PTR [r8], r12
        mov	QWORD PTR [r8+8], r13
        mov	QWORD PTR [r8+16], r14
        mov	QWORD PTR [r8+24], r15
        pop	rbp
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
sc_muladd_avx2 ENDP
_TEXT ENDS
_DATA SEGMENT
ALIGN 16
L_fe_invert_nct_avx2_prime DWORD 03ffffedh, 03ffffffh, 03ffffffh, 03ffffffh
        DWORD 03ffffffh, 00000000h, 00000000h, 00000000h
        DWORD 03ffffffh, 03ffffffh, 03ffffffh, 03ffffffh
        DWORD 001fffffh, 00000000h, 00000000h, 00000000h
ptr_L_fe_invert_nct_avx2_prime QWORD L_fe_invert_nct_avx2_prime
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_fe_invert_nct_avx2_one QWORD 0000000000000001h, 0000000000000000h
        QWORD 0000000000000000h, 0000000000000000h
ptr_L_fe_invert_nct_avx2_one QWORD L_fe_invert_nct_avx2_one
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_fe_invert_nct_avx2_all_one DWORD 00000001h, 00000001h, 00000001h, 00000001h
        DWORD 00000001h, 00000001h, 00000001h, 00000001h
ptr_L_fe_invert_nct_avx2_all_one QWORD L_fe_invert_nct_avx2_all_one
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_fe_invert_nct_avx2_mask01111 DWORD 00000000h, 00000001h, 00000001h, 00000001h
        DWORD 00000001h, 00000000h, 00000000h, 00000000h
ptr_L_fe_invert_nct_avx2_mask01111 QWORD L_fe_invert_nct_avx2_mask01111
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_fe_invert_nct_avx2_down_one_dword DWORD 00000001h, 00000002h, 00000003h, 00000004h
        DWORD 00000005h, 00000006h, 00000007h, 00000007h
ptr_L_fe_invert_nct_avx2_down_one_dword QWORD L_fe_invert_nct_avx2_down_one_dword
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_fe_invert_nct_avx2_neg DWORD 00000000h, 00000000h, 00000000h, 00000000h
        DWORD 80000000h, 00000000h, 00000000h, 00000000h
ptr_L_fe_invert_nct_avx2_neg QWORD L_fe_invert_nct_avx2_neg
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_fe_invert_nct_avx2_up_one_dword DWORD 00000007h, 00000000h, 00000001h, 00000002h
        DWORD 00000003h, 00000007h, 00000007h, 00000007h
ptr_L_fe_invert_nct_avx2_up_one_dword QWORD L_fe_invert_nct_avx2_up_one_dword
_DATA ENDS
_DATA SEGMENT
ALIGN 16
L_fe_invert_nct_avx2_mask26 DWORD 03ffffffh, 03ffffffh, 03ffffffh, 03ffffffh
        DWORD 03ffffffh, 00000000h, 00000000h, 00000000h
ptr_L_fe_invert_nct_avx2_mask26 QWORD L_fe_invert_nct_avx2_mask26
_DATA ENDS
; /* Non-constant time modular inversion.
;  *
;  * @param  [out]  r   Resulting number.
;  * @param  [in]   a   Number to invert.
;  * @param  [in]   m   Modulus.
;  * @return  MP_OKAY on success.
;  */
_TEXT SEGMENT READONLY PARA
fe_invert_nct_avx2 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        sub	rsp, 144
        vmovdqu	OWORD PTR [rsp], xmm6
        vmovdqu	OWORD PTR [rsp+16], xmm7
        vmovdqu	OWORD PTR [rsp+32], xmm8
        vmovdqu	OWORD PTR [rsp+48], xmm9
        vmovdqu	OWORD PTR [rsp+64], xmm10
        vmovdqu	OWORD PTR [rsp+80], xmm11
        vmovdqu	OWORD PTR [rsp+96], xmm12
        vmovdqu	OWORD PTR [rsp+112], xmm13
        vmovdqu	OWORD PTR [rsp+128], xmm14
        mov	r8, -19
        mov	r9, -1
        mov	r10, -1
        mov	r11, 9223372036854775807
        mov	r12, QWORD PTR [rdx]
        mov	r13, QWORD PTR [rdx+8]
        mov	r14, QWORD PTR [rdx+16]
        mov	r15, QWORD PTR [rdx+24]
        mov	rbx, QWORD PTR [ptr_L_fe_invert_nct_avx2_prime]
        vmovupd	ymm6, YMMWORD PTR [rbx]
        vmovupd	ymm7, YMMWORD PTR [rbx+32]
        mov	rbx, QWORD PTR [ptr_L_fe_invert_nct_avx2_one]
        vmovupd	ymm8, YMMWORD PTR [rbx]
        mov	rbx, QWORD PTR [ptr_L_fe_invert_nct_avx2_mask01111]
        vmovupd	ymm9, YMMWORD PTR [rbx]
        mov	rbx, QWORD PTR [ptr_L_fe_invert_nct_avx2_all_one]
        vmovupd	ymm10, YMMWORD PTR [rbx]
        mov	rbx, QWORD PTR [ptr_L_fe_invert_nct_avx2_down_one_dword]
        vmovupd	ymm11, YMMWORD PTR [rbx]
        mov	rbx, QWORD PTR [ptr_L_fe_invert_nct_avx2_neg]
        vmovupd	ymm12, YMMWORD PTR [rbx]
        mov	rbx, QWORD PTR [ptr_L_fe_invert_nct_avx2_up_one_dword]
        vmovupd	ymm13, YMMWORD PTR [rbx]
        mov	rbx, QWORD PTR [ptr_L_fe_invert_nct_avx2_mask26]
        vmovupd	ymm14, YMMWORD PTR [rbx]
        vpxor	xmm0, xmm0, xmm0
        vpxor	xmm1, xmm1, xmm1
        vmovdqu	ymm2, ymm8
        vpxor	xmm3, xmm3, xmm3
        test	r12b, 1
        jnz	L_fe_invert_nct_avx2_v_even_end
L_fe_invert_nct_avx2_v_even_start:
        shrd	r12, r13, 1
        shrd	r13, r14, 1
        shrd	r14, r15, 1
        shr	r15, 1
        vptest	ymm2, ymm8
        jz	L_fe_invert_nct_avx2_v_even_shr1
        vpaddd	ymm2, ymm2, ymm6
        vpaddd	ymm3, ymm3, ymm7
L_fe_invert_nct_avx2_v_even_shr1:
        vpand	ymm4, ymm2, ymm9
        vpand	ymm5, ymm3, ymm10
        vpermd	ymm4, ymm11, ymm4
        vpsrad	ymm2, ymm2, 1
        vpsrad	ymm3, ymm3, 1
        vpslld	ymm5, ymm5, 25
        vpslld	xmm4, xmm4, 25
        vpaddd	ymm2, ymm2, ymm5
        vpaddd	ymm3, ymm3, ymm4
        test	r12b, 1
        jz	L_fe_invert_nct_avx2_v_even_start
L_fe_invert_nct_avx2_v_even_end:
L_fe_invert_nct_avx2_uv_start:
        cmp	r11, r15
        jb	L_fe_invert_nct_avx2_uv_v
        ja	L_fe_invert_nct_avx2_uv_u
        cmp	r10, r14
        jb	L_fe_invert_nct_avx2_uv_v
        ja	L_fe_invert_nct_avx2_uv_u
        cmp	r9, r13
        jb	L_fe_invert_nct_avx2_uv_v
        ja	L_fe_invert_nct_avx2_uv_u
        cmp	r8, r12
        jb	L_fe_invert_nct_avx2_uv_v
L_fe_invert_nct_avx2_uv_u:
        sub	r8, r12
        sbb	r9, r13
        vpsubd	ymm0, ymm0, ymm2
        sbb	r10, r14
        vpsubd	ymm1, ymm1, ymm3
        sbb	r11, r15
        vptest	ymm1, ymm12
        jz	L_fe_invert_nct_avx2_usubv_done_neg
        vpaddd	ymm0, ymm0, ymm6
        vpaddd	ymm1, ymm1, ymm7
L_fe_invert_nct_avx2_usubv_done_neg:
L_fe_invert_nct_avx2_usubv_shr1:
        shrd	r8, r9, 1
        shrd	r9, r10, 1
        shrd	r10, r11, 1
        shr	r11, 1
        vptest	ymm0, ymm8
        jz	L_fe_invert_nct_avx2_usubv_sub_shr1
        vpaddd	ymm0, ymm0, ymm6
        vpaddd	ymm1, ymm1, ymm7
L_fe_invert_nct_avx2_usubv_sub_shr1:
        vpand	ymm4, ymm0, ymm9
        vpand	ymm5, ymm1, ymm10
        vpermd	ymm4, ymm11, ymm4
        vpsrad	ymm0, ymm0, 1
        vpsrad	ymm1, ymm1, 1
        vpslld	ymm5, ymm5, 25
        vpslld	xmm4, xmm4, 25
        vpaddd	ymm0, ymm0, ymm5
        vpaddd	ymm1, ymm1, ymm4
        test	r8b, 1
        jz	L_fe_invert_nct_avx2_usubv_shr1
        cmp	r8, 1
        jne	L_fe_invert_nct_avx2_uv_start
        mov	rax, r9
        or	rax, r10
        jne	L_fe_invert_nct_avx2_uv_start
        or	rax, r11
        jne	L_fe_invert_nct_avx2_uv_start
        vpextrd	r8d, xmm0, 0
        vpextrd	r10d, xmm0, 1
        vpextrd	r12d, xmm0, 2
        vpextrd	r14d, xmm0, 3
        vpextrd	r9d, xmm1, 0
        vpextrd	r11d, xmm1, 1
        vpextrd	r13d, xmm1, 2
        vpextrd	r15d, xmm1, 3
        vextracti128	xmm0, ymm0, 1
        vextracti128	xmm1, ymm1, 1
        vpextrd	edi, xmm0, 0
        vpextrd	esi, xmm1, 0
        jmp	L_fe_invert_nct_avx2_store_done
L_fe_invert_nct_avx2_uv_v:
        sub	r12, r8
        sbb	r13, r9
        vpsubd	ymm2, ymm2, ymm0
        sbb	r14, r10
        vpsubd	ymm3, ymm3, ymm1
        sbb	r15, r11
        vptest	ymm3, ymm12
        jz	L_fe_invert_nct_avx2_vsubu_done_neg
        vpaddd	ymm2, ymm2, ymm6
        vpaddd	ymm3, ymm3, ymm7
L_fe_invert_nct_avx2_vsubu_done_neg:
L_fe_invert_nct_avx2_vsubu_shr1:
        shrd	r12, r13, 1
        shrd	r13, r14, 1
        shrd	r14, r15, 1
        shr	r15, 1
        vptest	ymm2, ymm8
        jz	L_fe_invert_nct_avx2_vsubu_sub_shr1
        vpaddd	ymm2, ymm2, ymm6
        vpaddd	ymm3, ymm3, ymm7
L_fe_invert_nct_avx2_vsubu_sub_shr1:
        vpand	ymm4, ymm2, ymm9
        vpand	ymm5, ymm3, ymm10
        vpermd	ymm4, ymm11, ymm4
        vpsrad	ymm2, ymm2, 1
        vpsrad	ymm3, ymm3, 1
        vpslld	ymm5, ymm5, 25
        vpslld	xmm4, xmm4, 25
        vpaddd	ymm2, ymm2, ymm5
        vpaddd	ymm3, ymm3, ymm4
        test	r12b, 1
        jz	L_fe_invert_nct_avx2_vsubu_shr1
        cmp	r12, 1
        jne	L_fe_invert_nct_avx2_uv_start
        mov	rax, r13
        or	rax, r14
        jne	L_fe_invert_nct_avx2_uv_start
        or	rax, r15
        jne	L_fe_invert_nct_avx2_uv_start
        vpextrd	r8d, xmm2, 0
        vpextrd	r10d, xmm2, 1
        vpextrd	r12d, xmm2, 2
        vpextrd	r14d, xmm2, 3
        vpextrd	r9d, xmm3, 0
        vpextrd	r11d, xmm3, 1
        vpextrd	r13d, xmm3, 2
        vpextrd	r15d, xmm3, 3
        vextracti128	xmm2, ymm2, 1
        vextracti128	xmm3, ymm3, 1
        vpextrd	edi, xmm2, 0
        vpextrd	esi, xmm3, 0
L_fe_invert_nct_avx2_store_done:
        mov	eax, r8d
        and	r8d, 67108863
        sar	eax, 26
        add	r9d, eax
        mov	eax, r9d
        and	r9d, 67108863
        sar	eax, 26
        add	r10d, eax
        mov	eax, r10d
        and	r10d, 67108863
        sar	eax, 26
        add	r11d, eax
        mov	eax, r11d
        and	r11d, 67108863
        sar	eax, 26
        add	r12d, eax
        mov	eax, r12d
        and	r12d, 67108863
        sar	eax, 26
        add	r13d, eax
        mov	eax, r13d
        and	r13d, 67108863
        sar	eax, 26
        add	r14d, eax
        mov	eax, r14d
        and	r14d, 67108863
        sar	eax, 26
        add	r15d, eax
        mov	eax, r15d
        and	r15d, 67108863
        sar	eax, 26
        add	edi, eax
        mov	eax, edi
        and	edi, 67108863
        sar	eax, 26
        add	esi, eax
        movsxd	r9, r9d
        movsxd	r11, r11d
        movsxd	r13, r13d
        movsxd	r15, r15d
        movsxd	rsi, esi
        shl	r9, 26
        shl	r11, 26
        shl	r13, 26
        shl	r15, 26
        shl	rsi, 26
        movsxd	r8, r8d
        add	r8, r9
        movsxd	r10, r10d
        adc	r10, r11
        movsxd	r12, r12d
        adc	r12, r13
        movsxd	r14, r14d
        adc	r14, r15
        movsxd	rdi, edi
        adc	rdi, rsi
        jge	L_fe_invert_nct_avx2_uv_start_no_add_prime
        mov	r9, 4503599627370477
        mov	r11, 4503599627370495
        mov	r13, 4503599627370495
        mov	r15, 4503599627370495
        mov	rsi, 140737488355327
        add	r8, r9
        add	r10, r11
        add	r12, r13
        add	r14, r15
        add	rdi, rsi
        mov	rax, 4503599627370495
        mov	r9, r8
        and	r8, rax
        sar	r9, 52
        add	r10, r9
        mov	r11, r10
        and	r10, rax
        sar	r11, 52
        add	r12, r11
        mov	r13, r12
        and	r12, rax
        sar	r13, 52
        add	r14, r13
        mov	r15, r14
        and	r14, rax
        sar	r15, 52
        add	rdi, r15
L_fe_invert_nct_avx2_uv_start_no_add_prime:
        mov	r9, r10
        mov	r11, r12
        mov	r13, r14
        shl	r9, 52
        sar	r10, 12
        shl	r11, 40
        sar	r12, 24
        shl	r13, 28
        sar	r14, 36
        shl	rdi, 16
        add	r8, r9
        adc	r10, r11
        adc	r12, r13
        adc	r14, rdi
        mov	QWORD PTR [rcx], r8
        mov	QWORD PTR [rcx+8], r10
        mov	QWORD PTR [rcx+16], r12
        mov	QWORD PTR [rcx+24], r14
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
        add	rsp, 144
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
fe_invert_nct_avx2 ENDP
_TEXT ENDS
ENDIF
ENDIF
END
