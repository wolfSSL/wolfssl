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

IFNDEF NO_AVX512_SUPPORT
IFNDEF NO_AVX512_IFMA_SUPPORT
IFNDEF HAVE_INTEL_AVX512_IFMA
HAVE_INTEL_AVX512_IFMA = 1
ENDIF
ENDIF
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
IFDEF HAVE_INTEL_AVX512_IFMA
        mov	eax, DWORD PTR [intelFlags]
        and	eax, 198656
        cmp	eax, 198656
        jne	L_fe_init_flags_done
        lea	rax, [curve25519_avx512_ifma]
        mov	QWORD PTR [curve25519_p], rax
IFDEF WOLFSSL_CURVE25519_NOT_USE_ED25519
        lea	rax, [curve25519_base_avx512_ifma]
        mov	QWORD PTR [curve25519_base_p], rax
ENDIF
        mov	eax, DWORD PTR [intelFlags]
        and	eax, 468992
        cmp	eax, 468992
        jne	L_fe_init_flags_done
        lea	rax, [curve25519_avx512_ifma_dq]
        mov	QWORD PTR [curve25519_p], rax
IFDEF WOLFSSL_CURVE25519_NOT_USE_ED25519
        lea	rax, [curve25519_base_avx512_ifma_dq]
        mov	QWORD PTR [curve25519_base_p], rax
ENDIF
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
        sub	rsp, 152
        ; Invert
        mov	QWORD PTR [rsp+128], rcx
        mov	QWORD PTR [rsp+136], rdx
        mov	rcx, rsp
        mov	rdx, QWORD PTR [rsp+136]
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        mov	rdx, rsp
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        mov	rdx, QWORD PTR [rsp+136]
        lea	r8, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_mul_x64
        add	rsp, 32
        mov	rcx, rsp
        mov	rdx, rsp
        lea	r8, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_mul_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        mov	rdx, rsp
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        lea	r8, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_mul_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        mov	r8, 4
        sub	rsp, 32
        call	fe_sq_n_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+64]
        lea	r8, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_mul_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        mov	r8, 9
        sub	rsp, 32
        call	fe_sq_n_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        lea	r8, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_mul_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 19
        sub	rsp, 32
        call	fe_sq_n_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_mul_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        mov	r8, 9
        sub	rsp, 32
        call	fe_sq_n_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+64]
        lea	r8, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_mul_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        mov	r8, 49
        sub	rsp, 32
        call	fe_sq_n_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        lea	r8, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_mul_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 99
        sub	rsp, 32
        call	fe_sq_n_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_mul_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        mov	r8, 49
        sub	rsp, 32
        call	fe_sq_n_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+64]
        lea	r8, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_mul_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, 4
        sub	rsp, 32
        call	fe_sq_n_x64
        add	rsp, 32
        mov	rcx, QWORD PTR [rsp+128]
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, rsp
        sub	rsp, 32
        call	fe_mul_x64
        add	rsp, 32
        mov	rdx, QWORD PTR [rsp+136]
        mov	rcx, QWORD PTR [rsp+128]
        add	rsp, 152
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
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        mov	rdx, rsp
        lea	r8, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_mul_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        lea	r8, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_mul_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        lea	r8, QWORD PTR [rsp+96]
        sub	rsp, 32
        call	fe_mul_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 4
        sub	rsp, 32
        call	fe_sq_n_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_mul_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 9
        sub	rsp, 32
        call	fe_sq_n_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_mul_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+128]
        lea	rdx, QWORD PTR [rsp+96]
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+128]
        lea	rdx, QWORD PTR [rsp+128]
        mov	r8, 19
        sub	rsp, 32
        call	fe_sq_n_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+128]
        lea	r8, QWORD PTR [rsp+96]
        sub	rsp, 32
        call	fe_mul_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 9
        sub	rsp, 32
        call	fe_sq_n_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_mul_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 49
        sub	rsp, 32
        call	fe_sq_n_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_mul_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+128]
        lea	rdx, QWORD PTR [rsp+96]
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+128]
        lea	rdx, QWORD PTR [rsp+128]
        mov	r8, 99
        sub	rsp, 32
        call	fe_sq_n_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+128]
        lea	r8, QWORD PTR [rsp+96]
        sub	rsp, 32
        call	fe_mul_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 49
        sub	rsp, 32
        call	fe_sq_n_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_mul_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        mov	r8, 4
        sub	rsp, 32
        call	fe_sq_n_x64
        add	rsp, 32
        mov	rcx, rsp
        lea	rdx, QWORD PTR [rsp+64]
        lea	r8, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_mul_x64
        add	rsp, 32
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
        sub	rsp, 184
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
        mov	rbp, 9223372036854775807
        mov	rax, r13
        sar	rax, 63
        and	rax, 19
        and	r13, rbp
        add	rcx, rax
        adc	r11, 0
        adc	r12, 0
        adc	r13, 0
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
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        mov	rdx, rsp
        lea	r8, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_mul_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        lea	r8, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_mul_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        lea	r8, QWORD PTR [rsp+96]
        sub	rsp, 32
        call	fe_mul_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 4
        sub	rsp, 32
        call	fe_sq_n_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_mul_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 9
        sub	rsp, 32
        call	fe_sq_n_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_mul_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+128]
        lea	rdx, QWORD PTR [rsp+96]
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+128]
        lea	rdx, QWORD PTR [rsp+128]
        mov	r8, 19
        sub	rsp, 32
        call	fe_sq_n_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+128]
        lea	r8, QWORD PTR [rsp+96]
        sub	rsp, 32
        call	fe_mul_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 9
        sub	rsp, 32
        call	fe_sq_n_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_mul_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 49
        sub	rsp, 32
        call	fe_sq_n_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_mul_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+128]
        lea	rdx, QWORD PTR [rsp+96]
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+128]
        lea	rdx, QWORD PTR [rsp+128]
        mov	r8, 99
        sub	rsp, 32
        call	fe_sq_n_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+128]
        lea	r8, QWORD PTR [rsp+96]
        sub	rsp, 32
        call	fe_mul_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 49
        sub	rsp, 32
        call	fe_sq_n_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_mul_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        mov	r8, 4
        sub	rsp, 32
        call	fe_sq_n_x64
        add	rsp, 32
        mov	rcx, rsp
        lea	rdx, QWORD PTR [rsp+64]
        lea	r8, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_mul_x64
        add	rsp, 32
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
        add	rsp, 184
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
        sub	rsp, 120
        ; pow22523
        mov	QWORD PTR [rsp+96], rcx
        mov	QWORD PTR [rsp+104], rdx
        mov	rcx, rsp
        mov	rdx, QWORD PTR [rsp+104]
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        mov	rdx, rsp
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        mov	rdx, QWORD PTR [rsp+104]
        lea	r8, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_mul_x64
        add	rsp, 32
        mov	rcx, rsp
        mov	rdx, rsp
        lea	r8, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_mul_x64
        add	rsp, 32
        mov	rcx, rsp
        mov	rdx, rsp
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        mov	rcx, rsp
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, rsp
        sub	rsp, 32
        call	fe_mul_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        mov	rdx, rsp
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, 4
        sub	rsp, 32
        call	fe_sq_n_x64
        add	rsp, 32
        mov	rcx, rsp
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, rsp
        sub	rsp, 32
        call	fe_mul_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        mov	rdx, rsp
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, 9
        sub	rsp, 32
        call	fe_sq_n_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, rsp
        sub	rsp, 32
        call	fe_mul_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        mov	r8, 19
        sub	rsp, 32
        call	fe_sq_n_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+64]
        lea	r8, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_mul_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, 9
        sub	rsp, 32
        call	fe_sq_n_x64
        add	rsp, 32
        mov	rcx, rsp
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, rsp
        sub	rsp, 32
        call	fe_mul_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        mov	rdx, rsp
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, 49
        sub	rsp, 32
        call	fe_sq_n_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, rsp
        sub	rsp, 32
        call	fe_mul_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        mov	r8, 99
        sub	rsp, 32
        call	fe_sq_n_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+64]
        lea	r8, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_mul_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, 49
        sub	rsp, 32
        call	fe_sq_n_x64
        add	rsp, 32
        mov	rcx, rsp
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, rsp
        sub	rsp, 32
        call	fe_mul_x64
        add	rsp, 32
        mov	rcx, rsp
        mov	rdx, rsp
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        mov	rcx, rsp
        mov	rdx, rsp
        sub	rsp, 32
        call	fe_sq_x64
        add	rsp, 32
        mov	rcx, QWORD PTR [rsp+96]
        mov	rdx, rsp
        mov	r8, QWORD PTR [rsp+104]
        sub	rsp, 32
        call	fe_mul_x64
        add	rsp, 32
        mov	rdx, QWORD PTR [rsp+104]
        mov	rcx, QWORD PTR [rsp+96]
        add	rsp, 120
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
        sub	rsp, 520
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
        add	rsp, 520
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
        vmovd	xmm7, ebx
        mov	rbx, 1
        vmovq	xmm9, rbx
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
        sub	rsp, 152
        ; Invert
        mov	QWORD PTR [rsp+128], rcx
        mov	QWORD PTR [rsp+136], rdx
        mov	rcx, rsp
        mov	rdx, QWORD PTR [rsp+136]
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        mov	rdx, rsp
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        mov	rdx, QWORD PTR [rsp+136]
        lea	r8, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        mov	rcx, rsp
        mov	rdx, rsp
        lea	r8, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        mov	rdx, rsp
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        lea	r8, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        mov	r8, 4
        sub	rsp, 32
        call	fe_sq_n_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+64]
        lea	r8, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        mov	r8, 9
        sub	rsp, 32
        call	fe_sq_n_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        lea	r8, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 19
        sub	rsp, 32
        call	fe_sq_n_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        mov	r8, 9
        sub	rsp, 32
        call	fe_sq_n_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+64]
        lea	r8, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        mov	r8, 49
        sub	rsp, 32
        call	fe_sq_n_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        lea	r8, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 99
        sub	rsp, 32
        call	fe_sq_n_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        mov	r8, 49
        sub	rsp, 32
        call	fe_sq_n_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+64]
        lea	r8, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, 4
        sub	rsp, 32
        call	fe_sq_n_avx2
        add	rsp, 32
        mov	rcx, QWORD PTR [rsp+128]
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, rsp
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        mov	rdx, QWORD PTR [rsp+136]
        mov	rcx, QWORD PTR [rsp+128]
        add	rsp, 152
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
        sub	rsp, 184
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
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        mov	rdx, rsp
        lea	r8, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        lea	r8, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        lea	r8, QWORD PTR [rsp+96]
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 4
        sub	rsp, 32
        call	fe_sq_n_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 9
        sub	rsp, 32
        call	fe_sq_n_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+128]
        lea	rdx, QWORD PTR [rsp+96]
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+128]
        lea	rdx, QWORD PTR [rsp+128]
        mov	r8, 19
        sub	rsp, 32
        call	fe_sq_n_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+128]
        lea	r8, QWORD PTR [rsp+96]
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 9
        sub	rsp, 32
        call	fe_sq_n_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 49
        sub	rsp, 32
        call	fe_sq_n_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+128]
        lea	rdx, QWORD PTR [rsp+96]
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+128]
        lea	rdx, QWORD PTR [rsp+128]
        mov	r8, 99
        sub	rsp, 32
        call	fe_sq_n_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+128]
        lea	r8, QWORD PTR [rsp+96]
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 49
        sub	rsp, 32
        call	fe_sq_n_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        mov	r8, 4
        sub	rsp, 32
        call	fe_sq_n_avx2
        add	rsp, 32
        mov	rcx, rsp
        lea	rdx, QWORD PTR [rsp+64]
        lea	r8, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
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
        mov	rcx, 9223372036854775807
        mov	rdx, r14
        sar	rdx, 63
        and	rdx, 19
        and	r14, rcx
        add	r11, rdx
        adc	r12, 0
        adc	r13, 0
        adc	r14, 0
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
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        mov	rdx, rsp
        lea	r8, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        lea	r8, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        lea	r8, QWORD PTR [rsp+96]
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 4
        sub	rsp, 32
        call	fe_sq_n_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 9
        sub	rsp, 32
        call	fe_sq_n_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+128]
        lea	rdx, QWORD PTR [rsp+96]
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+128]
        lea	rdx, QWORD PTR [rsp+128]
        mov	r8, 19
        sub	rsp, 32
        call	fe_sq_n_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+128]
        lea	r8, QWORD PTR [rsp+96]
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 9
        sub	rsp, 32
        call	fe_sq_n_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 49
        sub	rsp, 32
        call	fe_sq_n_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+128]
        lea	rdx, QWORD PTR [rsp+96]
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+128]
        lea	rdx, QWORD PTR [rsp+128]
        mov	r8, 99
        sub	rsp, 32
        call	fe_sq_n_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+128]
        lea	r8, QWORD PTR [rsp+96]
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+96]
        lea	rdx, QWORD PTR [rsp+96]
        mov	r8, 49
        sub	rsp, 32
        call	fe_sq_n_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+96]
        lea	r8, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        mov	r8, 4
        sub	rsp, 32
        call	fe_sq_n_avx2
        add	rsp, 32
        mov	rcx, rsp
        lea	rdx, QWORD PTR [rsp+64]
        lea	r8, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
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
        sub	rsp, 120
        ; pow22523
        mov	QWORD PTR [rsp+96], rcx
        mov	QWORD PTR [rsp+104], rdx
        mov	rcx, rsp
        mov	rdx, QWORD PTR [rsp+104]
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        mov	rdx, rsp
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        mov	rdx, QWORD PTR [rsp+104]
        lea	r8, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        mov	rcx, rsp
        mov	rdx, rsp
        lea	r8, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        mov	rcx, rsp
        mov	rdx, rsp
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        mov	rcx, rsp
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, rsp
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        mov	rdx, rsp
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, 4
        sub	rsp, 32
        call	fe_sq_n_avx2
        add	rsp, 32
        mov	rcx, rsp
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, rsp
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        mov	rdx, rsp
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, 9
        sub	rsp, 32
        call	fe_sq_n_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, rsp
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        mov	r8, 19
        sub	rsp, 32
        call	fe_sq_n_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+64]
        lea	r8, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, 9
        sub	rsp, 32
        call	fe_sq_n_avx2
        add	rsp, 32
        mov	rcx, rsp
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, rsp
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        mov	rdx, rsp
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, 49
        sub	rsp, 32
        call	fe_sq_n_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, rsp
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+64]
        lea	rdx, QWORD PTR [rsp+64]
        mov	r8, 99
        sub	rsp, 32
        call	fe_sq_n_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+64]
        lea	r8, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        lea	rcx, QWORD PTR [rsp+32]
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, 49
        sub	rsp, 32
        call	fe_sq_n_avx2
        add	rsp, 32
        mov	rcx, rsp
        lea	rdx, QWORD PTR [rsp+32]
        mov	r8, rsp
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        mov	rcx, rsp
        mov	rdx, rsp
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        mov	rcx, rsp
        mov	rdx, rsp
        sub	rsp, 32
        call	fe_sq_avx2
        add	rsp, 32
        mov	rcx, QWORD PTR [rsp+96]
        mov	rdx, rsp
        mov	r8, QWORD PTR [rsp+104]
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        mov	rdx, QWORD PTR [rsp+104]
        mov	rcx, QWORD PTR [rsp+96]
        add	rsp, 120
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
        sub	rsp, 24
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
        sub	rsp, 24
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
        sub	rsp, 24
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
IFDEF HAVE_INTEL_AVX512_IFMA
_DATA SEGMENT
ALIGN 16
L_x25519_ifma_consts QWORD 0007ffffffffffffh, 000fffffffffffdah
        QWORD 000ffffffffffffeh, 0000000000000013h
        QWORD 000000000001db41h
ptr_L_x25519_ifma_consts QWORD L_x25519_ifma_consts
_DATA ENDS
IFDEF WOLFSSL_CURVE25519_NOT_USE_ED25519
_TEXT SEGMENT READONLY PARA
curve25519_base_avx512_ifma PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        mov	r15, rcx
        mov	rdi, rdx
        sub	rsp, 896
        vmovdqu	OWORD PTR [rsp+736], xmm6
        vmovdqu	OWORD PTR [rsp+752], xmm7
        vmovdqu	OWORD PTR [rsp+768], xmm8
        vmovdqu	OWORD PTR [rsp+784], xmm9
        vmovdqu	OWORD PTR [rsp+800], xmm10
        vmovdqu	OWORD PTR [rsp+816], xmm11
        vmovdqu	OWORD PTR [rsp+832], xmm12
        vmovdqu	OWORD PTR [rsp+848], xmm13
        vmovdqu	OWORD PTR [rsp+864], xmm14
        vmovdqu	OWORD PTR [rsp+880], xmm15
        mov	QWORD PTR [rsp+712], r15
        mov	r13, 2251799813685247
        mov	r10, 9
        mov	QWORD PTR [rsp], r10
        mov	QWORD PTR [rsp+8], r10
        mov	QWORD PTR [rsp+16], r10
        mov	QWORD PTR [rsp+24], r10
        mov	QWORD PTR [rsp+480], 1
        mov	QWORD PTR [rsp+488], 0
        mov	QWORD PTR [rsp+496], r10
        mov	QWORD PTR [rsp+504], 1
        mov	r10, 0
        mov	QWORD PTR [rsp+32], r10
        mov	QWORD PTR [rsp+40], r10
        mov	QWORD PTR [rsp+48], r10
        mov	QWORD PTR [rsp+56], r10
        mov	QWORD PTR [rsp+512], 0
        mov	QWORD PTR [rsp+520], 0
        mov	QWORD PTR [rsp+528], r10
        mov	QWORD PTR [rsp+536], 0
        mov	QWORD PTR [rsp+64], r10
        mov	QWORD PTR [rsp+72], r10
        mov	QWORD PTR [rsp+80], r10
        mov	QWORD PTR [rsp+88], r10
        mov	QWORD PTR [rsp+544], 0
        mov	QWORD PTR [rsp+552], 0
        mov	QWORD PTR [rsp+560], r10
        mov	QWORD PTR [rsp+568], 0
        mov	QWORD PTR [rsp+96], r10
        mov	QWORD PTR [rsp+104], r10
        mov	QWORD PTR [rsp+112], r10
        mov	QWORD PTR [rsp+120], r10
        mov	QWORD PTR [rsp+576], 0
        mov	QWORD PTR [rsp+584], 0
        mov	QWORD PTR [rsp+592], r10
        mov	QWORD PTR [rsp+600], 0
        mov	QWORD PTR [rsp+128], r10
        mov	QWORD PTR [rsp+136], r10
        mov	QWORD PTR [rsp+144], r10
        mov	QWORD PTR [rsp+152], r10
        mov	QWORD PTR [rsp+608], 0
        mov	QWORD PTR [rsp+616], 0
        mov	QWORD PTR [rsp+624], r10
        mov	QWORD PTR [rsp+632], 0
        mov	r11, QWORD PTR [ptr_L_x25519_ifma_consts]
        vpbroadcastq	ymm28, QWORD PTR [r11]
        vpbroadcastq	ymm29, QWORD PTR [r11+8]
        vpbroadcastq	ymm30, QWORD PTR [r11+16]
        vpbroadcastq	ymm31, QWORD PTR [r11+24]
        mov	r10d, 10
        kmovw	k1, r10d
        mov	r10d, 5
        kmovw	k2, r10d
        mov	r10d, 4
        kmovw	k3, r10d
        mov	r10d, 8
        kmovw	k4, r10d
        mov	r10d, 2
        kmovw	k5, r10d
        mov	r10d, 6
        kmovw	k7, r10d
        vmovdqu64	ymm18, YMMWORD PTR [rsp+480]
        vmovdqu64	ymm19, YMMWORD PTR [rsp+512]
        vmovdqu64	ymm20, YMMWORD PTR [rsp+544]
        vmovdqu64	ymm21, YMMWORD PTR [rsp+576]
        vmovdqu64	ymm22, YMMWORD PTR [rsp+608]
        mov	r8, 0
        mov	rdx, 254
L_curve25519_base_avx512_ifma_bits:
        ; Conditionally swap (x2, z2) with (x3, z3)
        mov	QWORD PTR [rsp+704], rdx
        mov	rcx, rdx
        and	rcx, 63
        shr	rdx, 6
        mov	rax, QWORD PTR [rdi+8*rdx]
        shr	rax, cl
        and	rax, 1
        mov	r9, rax
        xor	r8, rax
        neg	r8
        and	r8, 15
        kmovw	k6, r8d
        mov	r8, r9
        vpermq	ymm18{k6}, ymm18, 78
        vpermq	ymm19{k6}, ymm19, 78
        vpermq	ymm20{k6}, ymm20, 78
        vpermq	ymm21{k6}, ymm21, 78
        vpermq	ymm22{k6}, ymm22, 78
        ; A = x2 + z2, B = x2 - z2, C = x3 + z3, D = x3 - z3
        vpermq	ymm0, ymm18, 177
        vpermq	ymm1, ymm19, 177
        vpermq	ymm2, ymm20, 177
        vpermq	ymm3, ymm21, 177
        vpermq	ymm4, ymm22, 177
        vpaddq	ymm23, ymm0, ymm18
        vpaddq	ymm24, ymm1, ymm19
        vpaddq	ymm25, ymm2, ymm20
        vpaddq	ymm26, ymm3, ymm21
        vpaddq	ymm27, ymm4, ymm22
        vpaddq	ymm0{k1}, ymm0, ymm29
        vpaddq	ymm1{k1}, ymm1, ymm30
        vpaddq	ymm2{k1}, ymm2, ymm30
        vpaddq	ymm3{k1}, ymm3, ymm30
        vpaddq	ymm4{k1}, ymm4, ymm30
        vpsubq	ymm23{k1}, ymm0, ymm18
        vpsubq	ymm24{k1}, ymm1, ymm19
        vpsubq	ymm25{k1}, ymm2, ymm20
        vpsubq	ymm26{k1}, ymm3, ymm21
        vpsubq	ymm27{k1}, ymm4, ymm22
        vpsrlq	ymm5, ymm23, 51
        vpandq	ymm23, ymm23, ymm28
        vpsrlq	ymm6, ymm24, 51
        vpandq	ymm24, ymm24, ymm28
        vpsrlq	ymm7, ymm25, 51
        vpandq	ymm25, ymm25, ymm28
        vpsrlq	ymm8, ymm26, 51
        vpandq	ymm26, ymm26, ymm28
        vpsrlq	ymm9, ymm27, 51
        vpandq	ymm27, ymm27, ymm28
        vpmadd52luq	ymm23, ymm9, ymm31
        vpaddq	ymm24, ymm24, ymm5
        vpaddq	ymm25, ymm25, ymm6
        vpaddq	ymm26, ymm26, ymm7
        vpaddq	ymm27, ymm27, ymm8
        ; [AA, BB, CB, DA] = [A, B, C, D] * [A, B, B, A]
        vpermq	ymm18, ymm23, 20
        vpermq	ymm19, ymm24, 20
        vpermq	ymm20, ymm25, 20
        vpermq	ymm21, ymm26, 20
        vpermq	ymm22, ymm27, 20
        ; Multiply 4 field elements
        vpxorq	ymm0, ymm0, ymm0
        vpxorq	ymm9, ymm9, ymm9
        vpxorq	ymm1, ymm1, ymm1
        vpxorq	ymm10, ymm10, ymm10
        vpxorq	ymm2, ymm2, ymm2
        vpxorq	ymm11, ymm11, ymm11
        vpxorq	ymm3, ymm3, ymm3
        vpxorq	ymm12, ymm12, ymm12
        vpxorq	ymm4, ymm4, ymm4
        vpxorq	ymm13, ymm13, ymm13
        vpxorq	ymm5, ymm5, ymm5
        vpxorq	ymm14, ymm14, ymm14
        vpxorq	ymm6, ymm6, ymm6
        vpxorq	ymm15, ymm15, ymm15
        vpxorq	ymm7, ymm7, ymm7
        vpxorq	ymm16, ymm16, ymm16
        vpxorq	ymm8, ymm8, ymm8
        vpxorq	ymm17, ymm17, ymm17
        vpmadd52luq	ymm0, ymm18, ymm23
        vpmadd52huq	ymm9, ymm18, ymm23
        vpmadd52luq	ymm1, ymm18, ymm24
        vpmadd52huq	ymm10, ymm18, ymm24
        vpmadd52luq	ymm2, ymm18, ymm25
        vpmadd52huq	ymm11, ymm18, ymm25
        vpmadd52luq	ymm3, ymm18, ymm26
        vpmadd52huq	ymm12, ymm18, ymm26
        vpmadd52luq	ymm4, ymm18, ymm27
        vpmadd52huq	ymm13, ymm18, ymm27
        vpmadd52luq	ymm1, ymm19, ymm23
        vpmadd52huq	ymm10, ymm19, ymm23
        vpmadd52luq	ymm2, ymm19, ymm24
        vpmadd52huq	ymm11, ymm19, ymm24
        vpmadd52luq	ymm3, ymm19, ymm25
        vpmadd52huq	ymm12, ymm19, ymm25
        vpmadd52luq	ymm4, ymm19, ymm26
        vpmadd52huq	ymm13, ymm19, ymm26
        vpmadd52luq	ymm5, ymm19, ymm27
        vpmadd52huq	ymm14, ymm19, ymm27
        vpmadd52luq	ymm2, ymm20, ymm23
        vpmadd52huq	ymm11, ymm20, ymm23
        vpmadd52luq	ymm3, ymm20, ymm24
        vpmadd52huq	ymm12, ymm20, ymm24
        vpmadd52luq	ymm4, ymm20, ymm25
        vpmadd52huq	ymm13, ymm20, ymm25
        vpmadd52luq	ymm5, ymm20, ymm26
        vpmadd52huq	ymm14, ymm20, ymm26
        vpmadd52luq	ymm6, ymm20, ymm27
        vpmadd52huq	ymm15, ymm20, ymm27
        vpmadd52luq	ymm3, ymm21, ymm23
        vpmadd52huq	ymm12, ymm21, ymm23
        vpmadd52luq	ymm4, ymm21, ymm24
        vpmadd52huq	ymm13, ymm21, ymm24
        vpmadd52luq	ymm5, ymm21, ymm25
        vpmadd52huq	ymm14, ymm21, ymm25
        vpmadd52luq	ymm6, ymm21, ymm26
        vpmadd52huq	ymm15, ymm21, ymm26
        vpmadd52luq	ymm7, ymm21, ymm27
        vpmadd52huq	ymm16, ymm21, ymm27
        vpmadd52luq	ymm4, ymm22, ymm23
        vpmadd52huq	ymm13, ymm22, ymm23
        vpmadd52luq	ymm5, ymm22, ymm24
        vpmadd52huq	ymm14, ymm22, ymm24
        vpmadd52luq	ymm6, ymm22, ymm25
        vpmadd52huq	ymm15, ymm22, ymm25
        vpmadd52luq	ymm7, ymm22, ymm26
        vpmadd52huq	ymm16, ymm22, ymm26
        vpmadd52luq	ymm8, ymm22, ymm27
        vpmadd52huq	ymm17, ymm22, ymm27
        vpaddq	ymm9, ymm9, ymm9
        vpaddq	ymm1, ymm1, ymm9
        vpaddq	ymm10, ymm10, ymm10
        vpaddq	ymm2, ymm2, ymm10
        vpaddq	ymm11, ymm11, ymm11
        vpaddq	ymm3, ymm3, ymm11
        vpaddq	ymm12, ymm12, ymm12
        vpaddq	ymm4, ymm4, ymm12
        vpaddq	ymm13, ymm13, ymm13
        vpaddq	ymm5, ymm5, ymm13
        vpaddq	ymm14, ymm14, ymm14
        vpaddq	ymm6, ymm6, ymm14
        vpaddq	ymm15, ymm15, ymm15
        vpaddq	ymm7, ymm7, ymm15
        vpaddq	ymm16, ymm16, ymm16
        vpaddq	ymm8, ymm8, ymm16
        vpaddq	ymm17, ymm17, ymm17
        ; Reduce
        vpsllq	ymm9, ymm5, 4
        vpsllq	ymm10, ymm5, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm5
        vpaddq	ymm0, ymm0, ymm9
        vpsllq	ymm9, ymm6, 4
        vpsllq	ymm10, ymm6, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm6
        vpaddq	ymm1, ymm1, ymm9
        vpsllq	ymm9, ymm7, 4
        vpsllq	ymm10, ymm7, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm7
        vpaddq	ymm2, ymm2, ymm9
        vpsllq	ymm9, ymm8, 4
        vpsllq	ymm10, ymm8, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm8
        vpaddq	ymm3, ymm3, ymm9
        vpsllq	ymm9, ymm17, 4
        vpsllq	ymm10, ymm17, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm17
        vpaddq	ymm4, ymm4, ymm9
        vpsrlq	ymm23, ymm0, 51
        vpandq	ymm0, ymm0, ymm28
        vpsrlq	ymm24, ymm1, 51
        vpandq	ymm1, ymm1, ymm28
        vpsrlq	ymm25, ymm2, 51
        vpandq	ymm2, ymm2, ymm28
        vpsrlq	ymm26, ymm3, 51
        vpandq	ymm3, ymm3, ymm28
        vpsrlq	ymm27, ymm4, 51
        vpandq	ymm4, ymm4, ymm28
        vmovdqa64	ymm18, ymm0
        vpmadd52luq	ymm18, ymm27, ymm31
        vpaddq	ymm19, ymm1, ymm23
        vpaddq	ymm20, ymm2, ymm24
        vpaddq	ymm21, ymm3, ymm25
        vpaddq	ymm22, ymm4, ymm26
        ; U = [AA, DA-CB, DA+CB, AA-BB], V = [BB, DA-CB, DA+CB, a24]
        vpermq	ymm23, ymm18, 105
        vpermq	ymm24, ymm19, 105
        vpermq	ymm25, ymm20, 105
        vpermq	ymm26, ymm21, 105
        vpermq	ymm27, ymm22, 105
        vpermq	ymm18, ymm18, 60
        vpermq	ymm19, ymm19, 60
        vpermq	ymm20, ymm20, 60
        vpermq	ymm21, ymm21, 60
        vpermq	ymm22, ymm22, 60
        vpaddq	ymm18{k3}, ymm18, ymm23
        vpaddq	ymm19{k3}, ymm19, ymm24
        vpaddq	ymm20{k3}, ymm20, ymm25
        vpaddq	ymm21{k3}, ymm21, ymm26
        vpaddq	ymm22{k3}, ymm22, ymm27
        vpaddq	ymm18{k1}, ymm18, ymm29
        vpaddq	ymm19{k1}, ymm19, ymm30
        vpaddq	ymm20{k1}, ymm20, ymm30
        vpaddq	ymm21{k1}, ymm21, ymm30
        vpaddq	ymm22{k1}, ymm22, ymm30
        vpsubq	ymm18{k1}, ymm18, ymm23
        vpsubq	ymm19{k1}, ymm19, ymm24
        vpsubq	ymm20{k1}, ymm20, ymm25
        vpsubq	ymm21{k1}, ymm21, ymm26
        vpsubq	ymm22{k1}, ymm22, ymm27
        vpsrlq	ymm0, ymm18, 51
        vpandq	ymm18, ymm18, ymm28
        vpsrlq	ymm1, ymm19, 51
        vpandq	ymm19, ymm19, ymm28
        vpsrlq	ymm2, ymm20, 51
        vpandq	ymm20, ymm20, ymm28
        vpsrlq	ymm3, ymm21, 51
        vpandq	ymm21, ymm21, ymm28
        vpsrlq	ymm4, ymm22, 51
        vpandq	ymm22, ymm22, ymm28
        vpmadd52luq	ymm18, ymm4, ymm31
        vpaddq	ymm19, ymm19, ymm0
        vpaddq	ymm20, ymm20, ymm1
        vpaddq	ymm21, ymm21, ymm2
        vpaddq	ymm22, ymm22, ymm3
        vmovdqu64	YMMWORD PTR [rsp+160], ymm18
        vmovdqu64	YMMWORD PTR [rsp+192], ymm19
        vmovdqu64	YMMWORD PTR [rsp+224], ymm20
        vmovdqu64	YMMWORD PTR [rsp+256], ymm21
        vmovdqu64	YMMWORD PTR [rsp+288], ymm22
        vmovdqa64	ymm23{k7}, ymm18
        vmovdqa64	ymm24{k7}, ymm19
        vmovdqa64	ymm25{k7}, ymm20
        vmovdqa64	ymm26{k7}, ymm21
        vmovdqa64	ymm27{k7}, ymm22
        vpbroadcastq	ymm23{k4}, QWORD PTR [r11+32]
        vpxorq	ymm24{k4}, ymm24, ymm24
        vpxorq	ymm25{k4}, ymm25, ymm25
        vpxorq	ymm26{k4}, ymm26, ymm26
        vpxorq	ymm27{k4}, ymm27, ymm27
        ; [AA.BB, GG, FF, a24.E] = U * V
        ; Multiply 4 field elements
        vpxorq	ymm0, ymm0, ymm0
        vpxorq	ymm9, ymm9, ymm9
        vpxorq	ymm1, ymm1, ymm1
        vpxorq	ymm10, ymm10, ymm10
        vpxorq	ymm2, ymm2, ymm2
        vpxorq	ymm11, ymm11, ymm11
        vpxorq	ymm3, ymm3, ymm3
        vpxorq	ymm12, ymm12, ymm12
        vpxorq	ymm4, ymm4, ymm4
        vpxorq	ymm13, ymm13, ymm13
        vpxorq	ymm5, ymm5, ymm5
        vpxorq	ymm14, ymm14, ymm14
        vpxorq	ymm6, ymm6, ymm6
        vpxorq	ymm15, ymm15, ymm15
        vpxorq	ymm7, ymm7, ymm7
        vpxorq	ymm16, ymm16, ymm16
        vpxorq	ymm8, ymm8, ymm8
        vpxorq	ymm17, ymm17, ymm17
        vpmadd52luq	ymm0, ymm18, ymm23
        vpmadd52huq	ymm9, ymm18, ymm23
        vpmadd52luq	ymm1, ymm18, ymm24
        vpmadd52huq	ymm10, ymm18, ymm24
        vpmadd52luq	ymm2, ymm18, ymm25
        vpmadd52huq	ymm11, ymm18, ymm25
        vpmadd52luq	ymm3, ymm18, ymm26
        vpmadd52huq	ymm12, ymm18, ymm26
        vpmadd52luq	ymm4, ymm18, ymm27
        vpmadd52huq	ymm13, ymm18, ymm27
        vpmadd52luq	ymm1, ymm19, ymm23
        vpmadd52huq	ymm10, ymm19, ymm23
        vpmadd52luq	ymm2, ymm19, ymm24
        vpmadd52huq	ymm11, ymm19, ymm24
        vpmadd52luq	ymm3, ymm19, ymm25
        vpmadd52huq	ymm12, ymm19, ymm25
        vpmadd52luq	ymm4, ymm19, ymm26
        vpmadd52huq	ymm13, ymm19, ymm26
        vpmadd52luq	ymm5, ymm19, ymm27
        vpmadd52huq	ymm14, ymm19, ymm27
        vpmadd52luq	ymm2, ymm20, ymm23
        vpmadd52huq	ymm11, ymm20, ymm23
        vpmadd52luq	ymm3, ymm20, ymm24
        vpmadd52huq	ymm12, ymm20, ymm24
        vpmadd52luq	ymm4, ymm20, ymm25
        vpmadd52huq	ymm13, ymm20, ymm25
        vpmadd52luq	ymm5, ymm20, ymm26
        vpmadd52huq	ymm14, ymm20, ymm26
        vpmadd52luq	ymm6, ymm20, ymm27
        vpmadd52huq	ymm15, ymm20, ymm27
        vpmadd52luq	ymm3, ymm21, ymm23
        vpmadd52huq	ymm12, ymm21, ymm23
        vpmadd52luq	ymm4, ymm21, ymm24
        vpmadd52huq	ymm13, ymm21, ymm24
        vpmadd52luq	ymm5, ymm21, ymm25
        vpmadd52huq	ymm14, ymm21, ymm25
        vpmadd52luq	ymm6, ymm21, ymm26
        vpmadd52huq	ymm15, ymm21, ymm26
        vpmadd52luq	ymm7, ymm21, ymm27
        vpmadd52huq	ymm16, ymm21, ymm27
        vpmadd52luq	ymm4, ymm22, ymm23
        vpmadd52huq	ymm13, ymm22, ymm23
        vpmadd52luq	ymm5, ymm22, ymm24
        vpmadd52huq	ymm14, ymm22, ymm24
        vpmadd52luq	ymm6, ymm22, ymm25
        vpmadd52huq	ymm15, ymm22, ymm25
        vpmadd52luq	ymm7, ymm22, ymm26
        vpmadd52huq	ymm16, ymm22, ymm26
        vpmadd52luq	ymm8, ymm22, ymm27
        vpmadd52huq	ymm17, ymm22, ymm27
        vpaddq	ymm9, ymm9, ymm9
        vpaddq	ymm1, ymm1, ymm9
        vpaddq	ymm10, ymm10, ymm10
        vpaddq	ymm2, ymm2, ymm10
        vpaddq	ymm11, ymm11, ymm11
        vpaddq	ymm3, ymm3, ymm11
        vpaddq	ymm12, ymm12, ymm12
        vpaddq	ymm4, ymm4, ymm12
        vpaddq	ymm13, ymm13, ymm13
        vpaddq	ymm5, ymm5, ymm13
        vpaddq	ymm14, ymm14, ymm14
        vpaddq	ymm6, ymm6, ymm14
        vpaddq	ymm15, ymm15, ymm15
        vpaddq	ymm7, ymm7, ymm15
        vpaddq	ymm16, ymm16, ymm16
        vpaddq	ymm8, ymm8, ymm16
        vpaddq	ymm17, ymm17, ymm17
        ; Reduce
        vpsllq	ymm9, ymm5, 4
        vpsllq	ymm10, ymm5, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm5
        vpaddq	ymm0, ymm0, ymm9
        vpsllq	ymm9, ymm6, 4
        vpsllq	ymm10, ymm6, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm6
        vpaddq	ymm1, ymm1, ymm9
        vpsllq	ymm9, ymm7, 4
        vpsllq	ymm10, ymm7, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm7
        vpaddq	ymm2, ymm2, ymm9
        vpsllq	ymm9, ymm8, 4
        vpsllq	ymm10, ymm8, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm8
        vpaddq	ymm3, ymm3, ymm9
        vpsllq	ymm9, ymm17, 4
        vpsllq	ymm10, ymm17, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm17
        vpaddq	ymm4, ymm4, ymm9
        vpsrlq	ymm23, ymm0, 51
        vpandq	ymm0, ymm0, ymm28
        vpsrlq	ymm24, ymm1, 51
        vpandq	ymm1, ymm1, ymm28
        vpsrlq	ymm25, ymm2, 51
        vpandq	ymm2, ymm2, ymm28
        vpsrlq	ymm26, ymm3, 51
        vpandq	ymm3, ymm3, ymm28
        vpsrlq	ymm27, ymm4, 51
        vpandq	ymm4, ymm4, ymm28
        vmovdqa64	ymm18, ymm0
        vpmadd52luq	ymm18, ymm27, ymm31
        vpaddq	ymm19, ymm1, ymm23
        vpaddq	ymm20, ymm2, ymm24
        vpaddq	ymm21, ymm3, ymm25
        vpaddq	ymm22, ymm4, ymm26
        ; U3 = [E, E, E, x1], V3 = [aE, AA + a24.E, T, T]
        vpermq	ymm23, ymm18, 95
        vpermq	ymm24, ymm19, 95
        vpermq	ymm25, ymm20, 95
        vpermq	ymm26, ymm21, 95
        vpermq	ymm27, ymm22, 95
        vmovdqu64	YMMWORD PTR [rsp+320], ymm18
        vmovdqu64	YMMWORD PTR [rsp+352], ymm19
        vmovdqu64	YMMWORD PTR [rsp+384], ymm20
        vmovdqu64	YMMWORD PTR [rsp+416], ymm21
        vmovdqu64	YMMWORD PTR [rsp+448], ymm22
        vpbroadcastq	ymm5, QWORD PTR [rsp+160]
        vpbroadcastq	ymm6, QWORD PTR [rsp+192]
        vpbroadcastq	ymm7, QWORD PTR [rsp+224]
        vpbroadcastq	ymm8, QWORD PTR [rsp+256]
        vpbroadcastq	ymm9, QWORD PTR [rsp+288]
        vpaddq	ymm23{k5}, ymm23, ymm5
        vpaddq	ymm24{k5}, ymm24, ymm6
        vpaddq	ymm25{k5}, ymm25, ymm7
        vpaddq	ymm26{k5}, ymm26, ymm8
        vpaddq	ymm27{k5}, ymm27, ymm9
        vpsrlq	ymm10, ymm23, 51
        vpandq	ymm23, ymm23, ymm28
        vpsrlq	ymm11, ymm24, 51
        vpandq	ymm24, ymm24, ymm28
        vpsrlq	ymm12, ymm25, 51
        vpandq	ymm25, ymm25, ymm28
        vpsrlq	ymm13, ymm26, 51
        vpandq	ymm26, ymm26, ymm28
        vpsrlq	ymm14, ymm27, 51
        vpandq	ymm27, ymm27, ymm28
        vpmadd52luq	ymm23, ymm14, ymm31
        vpaddq	ymm24, ymm24, ymm10
        vpaddq	ymm25, ymm25, ymm11
        vpaddq	ymm26, ymm26, ymm12
        vpaddq	ymm27, ymm27, ymm13
        vpbroadcastq	ymm18, QWORD PTR [rsp+184]
        vpbroadcastq	ymm19, QWORD PTR [rsp+216]
        vpbroadcastq	ymm20, QWORD PTR [rsp+248]
        vpbroadcastq	ymm21, QWORD PTR [rsp+280]
        vpbroadcastq	ymm22, QWORD PTR [rsp+312]
        vmovdqu64	ymm18{k4}, YMMWORD PTR [rsp]
        vmovdqu64	ymm19{k4}, YMMWORD PTR [rsp+32]
        vmovdqu64	ymm20{k4}, YMMWORD PTR [rsp+64]
        vmovdqu64	ymm21{k4}, YMMWORD PTR [rsp+96]
        vmovdqu64	ymm22{k4}, YMMWORD PTR [rsp+128]
        ; [-, E.H, -, x1.T] = U3 * V3
        ; Multiply 4 field elements
        vpxorq	ymm0, ymm0, ymm0
        vpxorq	ymm9, ymm9, ymm9
        vpxorq	ymm1, ymm1, ymm1
        vpxorq	ymm10, ymm10, ymm10
        vpxorq	ymm2, ymm2, ymm2
        vpxorq	ymm11, ymm11, ymm11
        vpxorq	ymm3, ymm3, ymm3
        vpxorq	ymm12, ymm12, ymm12
        vpxorq	ymm4, ymm4, ymm4
        vpxorq	ymm13, ymm13, ymm13
        vpxorq	ymm5, ymm5, ymm5
        vpxorq	ymm14, ymm14, ymm14
        vpxorq	ymm6, ymm6, ymm6
        vpxorq	ymm15, ymm15, ymm15
        vpxorq	ymm7, ymm7, ymm7
        vpxorq	ymm16, ymm16, ymm16
        vpxorq	ymm8, ymm8, ymm8
        vpxorq	ymm17, ymm17, ymm17
        vpmadd52luq	ymm0, ymm18, ymm23
        vpmadd52huq	ymm9, ymm18, ymm23
        vpmadd52luq	ymm1, ymm18, ymm24
        vpmadd52huq	ymm10, ymm18, ymm24
        vpmadd52luq	ymm2, ymm18, ymm25
        vpmadd52huq	ymm11, ymm18, ymm25
        vpmadd52luq	ymm3, ymm18, ymm26
        vpmadd52huq	ymm12, ymm18, ymm26
        vpmadd52luq	ymm4, ymm18, ymm27
        vpmadd52huq	ymm13, ymm18, ymm27
        vpmadd52luq	ymm1, ymm19, ymm23
        vpmadd52huq	ymm10, ymm19, ymm23
        vpmadd52luq	ymm2, ymm19, ymm24
        vpmadd52huq	ymm11, ymm19, ymm24
        vpmadd52luq	ymm3, ymm19, ymm25
        vpmadd52huq	ymm12, ymm19, ymm25
        vpmadd52luq	ymm4, ymm19, ymm26
        vpmadd52huq	ymm13, ymm19, ymm26
        vpmadd52luq	ymm5, ymm19, ymm27
        vpmadd52huq	ymm14, ymm19, ymm27
        vpmadd52luq	ymm2, ymm20, ymm23
        vpmadd52huq	ymm11, ymm20, ymm23
        vpmadd52luq	ymm3, ymm20, ymm24
        vpmadd52huq	ymm12, ymm20, ymm24
        vpmadd52luq	ymm4, ymm20, ymm25
        vpmadd52huq	ymm13, ymm20, ymm25
        vpmadd52luq	ymm5, ymm20, ymm26
        vpmadd52huq	ymm14, ymm20, ymm26
        vpmadd52luq	ymm6, ymm20, ymm27
        vpmadd52huq	ymm15, ymm20, ymm27
        vpmadd52luq	ymm3, ymm21, ymm23
        vpmadd52huq	ymm12, ymm21, ymm23
        vpmadd52luq	ymm4, ymm21, ymm24
        vpmadd52huq	ymm13, ymm21, ymm24
        vpmadd52luq	ymm5, ymm21, ymm25
        vpmadd52huq	ymm14, ymm21, ymm25
        vpmadd52luq	ymm6, ymm21, ymm26
        vpmadd52huq	ymm15, ymm21, ymm26
        vpmadd52luq	ymm7, ymm21, ymm27
        vpmadd52huq	ymm16, ymm21, ymm27
        vpmadd52luq	ymm4, ymm22, ymm23
        vpmadd52huq	ymm13, ymm22, ymm23
        vpmadd52luq	ymm5, ymm22, ymm24
        vpmadd52huq	ymm14, ymm22, ymm24
        vpmadd52luq	ymm6, ymm22, ymm25
        vpmadd52huq	ymm15, ymm22, ymm25
        vpmadd52luq	ymm7, ymm22, ymm26
        vpmadd52huq	ymm16, ymm22, ymm26
        vpmadd52luq	ymm8, ymm22, ymm27
        vpmadd52huq	ymm17, ymm22, ymm27
        vpaddq	ymm9, ymm9, ymm9
        vpaddq	ymm1, ymm1, ymm9
        vpaddq	ymm10, ymm10, ymm10
        vpaddq	ymm2, ymm2, ymm10
        vpaddq	ymm11, ymm11, ymm11
        vpaddq	ymm3, ymm3, ymm11
        vpaddq	ymm12, ymm12, ymm12
        vpaddq	ymm4, ymm4, ymm12
        vpaddq	ymm13, ymm13, ymm13
        vpaddq	ymm5, ymm5, ymm13
        vpaddq	ymm14, ymm14, ymm14
        vpaddq	ymm6, ymm6, ymm14
        vpaddq	ymm15, ymm15, ymm15
        vpaddq	ymm7, ymm7, ymm15
        vpaddq	ymm16, ymm16, ymm16
        vpaddq	ymm8, ymm8, ymm16
        vpaddq	ymm17, ymm17, ymm17
        ; Reduce
        vpsllq	ymm9, ymm5, 4
        vpsllq	ymm10, ymm5, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm5
        vpaddq	ymm0, ymm0, ymm9
        vpsllq	ymm9, ymm6, 4
        vpsllq	ymm10, ymm6, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm6
        vpaddq	ymm1, ymm1, ymm9
        vpsllq	ymm9, ymm7, 4
        vpsllq	ymm10, ymm7, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm7
        vpaddq	ymm2, ymm2, ymm9
        vpsllq	ymm9, ymm8, 4
        vpsllq	ymm10, ymm8, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm8
        vpaddq	ymm3, ymm3, ymm9
        vpsllq	ymm9, ymm17, 4
        vpsllq	ymm10, ymm17, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm17
        vpaddq	ymm4, ymm4, ymm9
        vpsrlq	ymm23, ymm0, 51
        vpandq	ymm0, ymm0, ymm28
        vpsrlq	ymm24, ymm1, 51
        vpandq	ymm1, ymm1, ymm28
        vpsrlq	ymm25, ymm2, 51
        vpandq	ymm2, ymm2, ymm28
        vpsrlq	ymm26, ymm3, 51
        vpandq	ymm3, ymm3, ymm28
        vpsrlq	ymm27, ymm4, 51
        vpandq	ymm4, ymm4, ymm28
        vmovdqa64	ymm18, ymm0
        vpmadd52luq	ymm18, ymm27, ymm31
        vpaddq	ymm19, ymm1, ymm23
        vpaddq	ymm20, ymm2, ymm24
        vpaddq	ymm21, ymm3, ymm25
        vpaddq	ymm22, ymm4, ymm26
        ; [x2, z2, x3, z3] = [AA.BB, E.H, FF, x1.T]
        vmovdqu64	ymm0, YMMWORD PTR [rsp+320]
        vmovdqu64	ymm1, YMMWORD PTR [rsp+352]
        vmovdqu64	ymm2, YMMWORD PTR [rsp+384]
        vmovdqu64	ymm3, YMMWORD PTR [rsp+416]
        vmovdqu64	ymm4, YMMWORD PTR [rsp+448]
        vmovdqa64	ymm18{k2}, ymm0
        vmovdqa64	ymm19{k2}, ymm1
        vmovdqa64	ymm20{k2}, ymm2
        vmovdqa64	ymm21{k2}, ymm3
        vmovdqa64	ymm22{k2}, ymm4
        mov	rdx, QWORD PTR [rsp+704]
        dec	rdx
        jge	L_curve25519_base_avx512_ifma_bits
        vmovdqu64	YMMWORD PTR [rsp+480], ymm18
        vmovdqu64	YMMWORD PTR [rsp+512], ymm19
        vmovdqu64	YMMWORD PTR [rsp+544], ymm20
        vmovdqu64	YMMWORD PTR [rsp+576], ymm21
        vmovdqu64	YMMWORD PTR [rsp+608], ymm22
        vzeroupper
        ; Convert to 4 x 64-bit field elements
        mov	r13, 2251799813685247
        mov	rdx, QWORD PTR [rsp+480]
        mov	rax, QWORD PTR [rsp+512]
        mov	r8, QWORD PTR [rsp+544]
        mov	r9, QWORD PTR [rsp+576]
        mov	r10, QWORD PTR [rsp+608]
        mov	r11, rdx
        shr	r11, 51
        and	rdx, r13
        add	rax, r11
        mov	r11, rax
        shr	r11, 51
        and	rax, r13
        add	r8, r11
        mov	r11, r8
        shr	r11, 51
        and	r8, r13
        add	r9, r11
        mov	r11, r9
        shr	r11, 51
        and	r9, r13
        add	r10, r11
        mov	r11, r10
        shr	r11, 51
        and	r10, r13
        imul	r11, r11, 19
        add	rdx, r11
        mov	r11, rax
        shl	r11, 51
        mov	r12, rax
        shr	r12, 13
        add	rdx, r11
        adc	r12, 0
        mov	QWORD PTR [rsp+640], rdx
        mov	r11, r8
        shl	r11, 38
        mov	rdx, r8
        shr	rdx, 26
        add	r12, r11
        adc	rdx, 0
        mov	QWORD PTR [rsp+648], r12
        mov	r11, r9
        shl	r11, 25
        mov	r12, r9
        shr	r12, 39
        add	rdx, r11
        adc	r12, 0
        mov	QWORD PTR [rsp+656], rdx
        mov	r11, r10
        shl	r11, 12
        add	r12, r11
        mov	QWORD PTR [rsp+664], r12
        mov	rdx, QWORD PTR [rsp+488]
        mov	rax, QWORD PTR [rsp+520]
        mov	r8, QWORD PTR [rsp+552]
        mov	r9, QWORD PTR [rsp+584]
        mov	r10, QWORD PTR [rsp+616]
        mov	r11, rdx
        shr	r11, 51
        and	rdx, r13
        add	rax, r11
        mov	r11, rax
        shr	r11, 51
        and	rax, r13
        add	r8, r11
        mov	r11, r8
        shr	r11, 51
        and	r8, r13
        add	r9, r11
        mov	r11, r9
        shr	r11, 51
        and	r9, r13
        add	r10, r11
        mov	r11, r10
        shr	r11, 51
        and	r10, r13
        imul	r11, r11, 19
        add	rdx, r11
        mov	r11, rax
        shl	r11, 51
        mov	r12, rax
        shr	r12, 13
        add	rdx, r11
        adc	r12, 0
        mov	QWORD PTR [rsp+672], rdx
        mov	r11, r8
        shl	r11, 38
        mov	rdx, r8
        shr	rdx, 26
        add	r12, r11
        adc	rdx, 0
        mov	QWORD PTR [rsp+680], r12
        mov	r11, r9
        shl	r11, 25
        mov	r12, r9
        shr	r12, 39
        add	rdx, r11
        adc	r12, 0
        mov	QWORD PTR [rsp+688], rdx
        mov	r11, r10
        shl	r11, 12
        add	r12, r11
        mov	QWORD PTR [rsp+696], r12
        ; z2 = 1 / z2
        lea	rcx, QWORD PTR [rsp+672]
        lea	rdx, QWORD PTR [rsp+672]
        sub	rsp, 32
        call	fe_invert_avx2
        add	rsp, 32
        ; x2 = x2 * z2
        lea	rcx, QWORD PTR [rsp+640]
        lea	rdx, QWORD PTR [rsp+640]
        lea	r8, QWORD PTR [rsp+672]
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        ; Store fully reduced result
        mov	rcx, QWORD PTR [rsp+712]
        lea	rdx, QWORD PTR [rsp+640]
        sub	rsp, 32
        call	fe_tobytes
        add	rsp, 32
        xor	rax, rax
        vmovdqu	xmm6, OWORD PTR [rsp+736]
        vmovdqu	xmm7, OWORD PTR [rsp+752]
        vmovdqu	xmm8, OWORD PTR [rsp+768]
        vmovdqu	xmm9, OWORD PTR [rsp+784]
        vmovdqu	xmm10, OWORD PTR [rsp+800]
        vmovdqu	xmm11, OWORD PTR [rsp+816]
        vmovdqu	xmm12, OWORD PTR [rsp+832]
        vmovdqu	xmm13, OWORD PTR [rsp+848]
        vmovdqu	xmm14, OWORD PTR [rsp+864]
        vmovdqu	xmm15, OWORD PTR [rsp+880]
        add	rsp, 896
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
curve25519_base_avx512_ifma ENDP
_TEXT ENDS
ENDIF
_TEXT SEGMENT READONLY PARA
curve25519_avx512_ifma PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        mov	r15, rcx
        mov	rdi, rdx
        mov	rsi, r8
        sub	rsp, 904
        vmovdqu	OWORD PTR [rsp+744], xmm6
        vmovdqu	OWORD PTR [rsp+760], xmm7
        vmovdqu	OWORD PTR [rsp+776], xmm8
        vmovdqu	OWORD PTR [rsp+792], xmm9
        vmovdqu	OWORD PTR [rsp+808], xmm10
        vmovdqu	OWORD PTR [rsp+824], xmm11
        vmovdqu	OWORD PTR [rsp+840], xmm12
        vmovdqu	OWORD PTR [rsp+856], xmm13
        vmovdqu	OWORD PTR [rsp+872], xmm14
        vmovdqu	OWORD PTR [rsp+888], xmm15
        mov	QWORD PTR [rsp+712], r15
        mov	r13, 2251799813685247
        mov	rdx, QWORD PTR [rsi]
        mov	rax, QWORD PTR [rsi+8]
        mov	r8, QWORD PTR [rsi+16]
        mov	r9, QWORD PTR [rsi+24]
        mov	r10, r9
        shr	r10, 63
        imul	r10, r10, 19
        shl	r9, 1
        shr	r9, 1
        mov	r12, rdx
        and	r12, r13
        add	r12, r10
        mov	QWORD PTR [rsp], r12
        mov	QWORD PTR [rsp+8], r12
        mov	QWORD PTR [rsp+16], r12
        mov	QWORD PTR [rsp+24], r12
        mov	QWORD PTR [rsp+480], 1
        mov	QWORD PTR [rsp+488], 0
        mov	QWORD PTR [rsp+496], r12
        mov	QWORD PTR [rsp+504], 1
        shrd	rdx, rax, 51
        mov	r10, rdx
        and	r10, r13
        mov	QWORD PTR [rsp+32], r10
        mov	QWORD PTR [rsp+40], r10
        mov	QWORD PTR [rsp+48], r10
        mov	QWORD PTR [rsp+56], r10
        mov	QWORD PTR [rsp+512], 0
        mov	QWORD PTR [rsp+520], 0
        mov	QWORD PTR [rsp+528], r10
        mov	QWORD PTR [rsp+536], 0
        shrd	rax, r8, 38
        mov	r10, rax
        and	r10, r13
        mov	QWORD PTR [rsp+64], r10
        mov	QWORD PTR [rsp+72], r10
        mov	QWORD PTR [rsp+80], r10
        mov	QWORD PTR [rsp+88], r10
        mov	QWORD PTR [rsp+544], 0
        mov	QWORD PTR [rsp+552], 0
        mov	QWORD PTR [rsp+560], r10
        mov	QWORD PTR [rsp+568], 0
        shrd	r8, r9, 25
        mov	r10, r8
        and	r10, r13
        mov	QWORD PTR [rsp+96], r10
        mov	QWORD PTR [rsp+104], r10
        mov	QWORD PTR [rsp+112], r10
        mov	QWORD PTR [rsp+120], r10
        mov	QWORD PTR [rsp+576], 0
        mov	QWORD PTR [rsp+584], 0
        mov	QWORD PTR [rsp+592], r10
        mov	QWORD PTR [rsp+600], 0
        shr	r9, 12
        mov	QWORD PTR [rsp+128], r9
        mov	QWORD PTR [rsp+136], r9
        mov	QWORD PTR [rsp+144], r9
        mov	QWORD PTR [rsp+152], r9
        mov	QWORD PTR [rsp+608], 0
        mov	QWORD PTR [rsp+616], 0
        mov	QWORD PTR [rsp+624], r9
        mov	QWORD PTR [rsp+632], 0
        mov	r11, QWORD PTR [ptr_L_x25519_ifma_consts]
        vpbroadcastq	ymm28, QWORD PTR [r11]
        vpbroadcastq	ymm29, QWORD PTR [r11+8]
        vpbroadcastq	ymm30, QWORD PTR [r11+16]
        vpbroadcastq	ymm31, QWORD PTR [r11+24]
        mov	r10d, 10
        kmovw	k1, r10d
        mov	r10d, 5
        kmovw	k2, r10d
        mov	r10d, 4
        kmovw	k3, r10d
        mov	r10d, 8
        kmovw	k4, r10d
        mov	r10d, 2
        kmovw	k5, r10d
        mov	r10d, 6
        kmovw	k7, r10d
        vmovdqu64	ymm18, YMMWORD PTR [rsp+480]
        vmovdqu64	ymm19, YMMWORD PTR [rsp+512]
        vmovdqu64	ymm20, YMMWORD PTR [rsp+544]
        vmovdqu64	ymm21, YMMWORD PTR [rsp+576]
        vmovdqu64	ymm22, YMMWORD PTR [rsp+608]
        mov	r8, 0
        mov	rdx, 254
L_curve25519_avx512_ifma_bits:
        ; Conditionally swap (x2, z2) with (x3, z3)
        mov	QWORD PTR [rsp+704], rdx
        mov	rcx, rdx
        and	rcx, 63
        shr	rdx, 6
        mov	rax, QWORD PTR [rdi+8*rdx]
        shr	rax, cl
        and	rax, 1
        mov	r9, rax
        xor	r8, rax
        neg	r8
        and	r8, 15
        kmovw	k6, r8d
        mov	r8, r9
        vpermq	ymm18{k6}, ymm18, 78
        vpermq	ymm19{k6}, ymm19, 78
        vpermq	ymm20{k6}, ymm20, 78
        vpermq	ymm21{k6}, ymm21, 78
        vpermq	ymm22{k6}, ymm22, 78
        ; A = x2 + z2, B = x2 - z2, C = x3 + z3, D = x3 - z3
        vpermq	ymm0, ymm18, 177
        vpermq	ymm1, ymm19, 177
        vpermq	ymm2, ymm20, 177
        vpermq	ymm3, ymm21, 177
        vpermq	ymm4, ymm22, 177
        vpaddq	ymm23, ymm0, ymm18
        vpaddq	ymm24, ymm1, ymm19
        vpaddq	ymm25, ymm2, ymm20
        vpaddq	ymm26, ymm3, ymm21
        vpaddq	ymm27, ymm4, ymm22
        vpaddq	ymm0{k1}, ymm0, ymm29
        vpaddq	ymm1{k1}, ymm1, ymm30
        vpaddq	ymm2{k1}, ymm2, ymm30
        vpaddq	ymm3{k1}, ymm3, ymm30
        vpaddq	ymm4{k1}, ymm4, ymm30
        vpsubq	ymm23{k1}, ymm0, ymm18
        vpsubq	ymm24{k1}, ymm1, ymm19
        vpsubq	ymm25{k1}, ymm2, ymm20
        vpsubq	ymm26{k1}, ymm3, ymm21
        vpsubq	ymm27{k1}, ymm4, ymm22
        vpsrlq	ymm5, ymm23, 51
        vpandq	ymm23, ymm23, ymm28
        vpsrlq	ymm6, ymm24, 51
        vpandq	ymm24, ymm24, ymm28
        vpsrlq	ymm7, ymm25, 51
        vpandq	ymm25, ymm25, ymm28
        vpsrlq	ymm8, ymm26, 51
        vpandq	ymm26, ymm26, ymm28
        vpsrlq	ymm9, ymm27, 51
        vpandq	ymm27, ymm27, ymm28
        vpmadd52luq	ymm23, ymm9, ymm31
        vpaddq	ymm24, ymm24, ymm5
        vpaddq	ymm25, ymm25, ymm6
        vpaddq	ymm26, ymm26, ymm7
        vpaddq	ymm27, ymm27, ymm8
        ; [AA, BB, CB, DA] = [A, B, C, D] * [A, B, B, A]
        vpermq	ymm18, ymm23, 20
        vpermq	ymm19, ymm24, 20
        vpermq	ymm20, ymm25, 20
        vpermq	ymm21, ymm26, 20
        vpermq	ymm22, ymm27, 20
        ; Multiply 4 field elements
        vpxorq	ymm0, ymm0, ymm0
        vpxorq	ymm9, ymm9, ymm9
        vpxorq	ymm1, ymm1, ymm1
        vpxorq	ymm10, ymm10, ymm10
        vpxorq	ymm2, ymm2, ymm2
        vpxorq	ymm11, ymm11, ymm11
        vpxorq	ymm3, ymm3, ymm3
        vpxorq	ymm12, ymm12, ymm12
        vpxorq	ymm4, ymm4, ymm4
        vpxorq	ymm13, ymm13, ymm13
        vpxorq	ymm5, ymm5, ymm5
        vpxorq	ymm14, ymm14, ymm14
        vpxorq	ymm6, ymm6, ymm6
        vpxorq	ymm15, ymm15, ymm15
        vpxorq	ymm7, ymm7, ymm7
        vpxorq	ymm16, ymm16, ymm16
        vpxorq	ymm8, ymm8, ymm8
        vpxorq	ymm17, ymm17, ymm17
        vpmadd52luq	ymm0, ymm18, ymm23
        vpmadd52huq	ymm9, ymm18, ymm23
        vpmadd52luq	ymm1, ymm18, ymm24
        vpmadd52huq	ymm10, ymm18, ymm24
        vpmadd52luq	ymm2, ymm18, ymm25
        vpmadd52huq	ymm11, ymm18, ymm25
        vpmadd52luq	ymm3, ymm18, ymm26
        vpmadd52huq	ymm12, ymm18, ymm26
        vpmadd52luq	ymm4, ymm18, ymm27
        vpmadd52huq	ymm13, ymm18, ymm27
        vpmadd52luq	ymm1, ymm19, ymm23
        vpmadd52huq	ymm10, ymm19, ymm23
        vpmadd52luq	ymm2, ymm19, ymm24
        vpmadd52huq	ymm11, ymm19, ymm24
        vpmadd52luq	ymm3, ymm19, ymm25
        vpmadd52huq	ymm12, ymm19, ymm25
        vpmadd52luq	ymm4, ymm19, ymm26
        vpmadd52huq	ymm13, ymm19, ymm26
        vpmadd52luq	ymm5, ymm19, ymm27
        vpmadd52huq	ymm14, ymm19, ymm27
        vpmadd52luq	ymm2, ymm20, ymm23
        vpmadd52huq	ymm11, ymm20, ymm23
        vpmadd52luq	ymm3, ymm20, ymm24
        vpmadd52huq	ymm12, ymm20, ymm24
        vpmadd52luq	ymm4, ymm20, ymm25
        vpmadd52huq	ymm13, ymm20, ymm25
        vpmadd52luq	ymm5, ymm20, ymm26
        vpmadd52huq	ymm14, ymm20, ymm26
        vpmadd52luq	ymm6, ymm20, ymm27
        vpmadd52huq	ymm15, ymm20, ymm27
        vpmadd52luq	ymm3, ymm21, ymm23
        vpmadd52huq	ymm12, ymm21, ymm23
        vpmadd52luq	ymm4, ymm21, ymm24
        vpmadd52huq	ymm13, ymm21, ymm24
        vpmadd52luq	ymm5, ymm21, ymm25
        vpmadd52huq	ymm14, ymm21, ymm25
        vpmadd52luq	ymm6, ymm21, ymm26
        vpmadd52huq	ymm15, ymm21, ymm26
        vpmadd52luq	ymm7, ymm21, ymm27
        vpmadd52huq	ymm16, ymm21, ymm27
        vpmadd52luq	ymm4, ymm22, ymm23
        vpmadd52huq	ymm13, ymm22, ymm23
        vpmadd52luq	ymm5, ymm22, ymm24
        vpmadd52huq	ymm14, ymm22, ymm24
        vpmadd52luq	ymm6, ymm22, ymm25
        vpmadd52huq	ymm15, ymm22, ymm25
        vpmadd52luq	ymm7, ymm22, ymm26
        vpmadd52huq	ymm16, ymm22, ymm26
        vpmadd52luq	ymm8, ymm22, ymm27
        vpmadd52huq	ymm17, ymm22, ymm27
        vpaddq	ymm9, ymm9, ymm9
        vpaddq	ymm1, ymm1, ymm9
        vpaddq	ymm10, ymm10, ymm10
        vpaddq	ymm2, ymm2, ymm10
        vpaddq	ymm11, ymm11, ymm11
        vpaddq	ymm3, ymm3, ymm11
        vpaddq	ymm12, ymm12, ymm12
        vpaddq	ymm4, ymm4, ymm12
        vpaddq	ymm13, ymm13, ymm13
        vpaddq	ymm5, ymm5, ymm13
        vpaddq	ymm14, ymm14, ymm14
        vpaddq	ymm6, ymm6, ymm14
        vpaddq	ymm15, ymm15, ymm15
        vpaddq	ymm7, ymm7, ymm15
        vpaddq	ymm16, ymm16, ymm16
        vpaddq	ymm8, ymm8, ymm16
        vpaddq	ymm17, ymm17, ymm17
        ; Reduce
        vpsllq	ymm9, ymm5, 4
        vpsllq	ymm10, ymm5, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm5
        vpaddq	ymm0, ymm0, ymm9
        vpsllq	ymm9, ymm6, 4
        vpsllq	ymm10, ymm6, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm6
        vpaddq	ymm1, ymm1, ymm9
        vpsllq	ymm9, ymm7, 4
        vpsllq	ymm10, ymm7, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm7
        vpaddq	ymm2, ymm2, ymm9
        vpsllq	ymm9, ymm8, 4
        vpsllq	ymm10, ymm8, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm8
        vpaddq	ymm3, ymm3, ymm9
        vpsllq	ymm9, ymm17, 4
        vpsllq	ymm10, ymm17, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm17
        vpaddq	ymm4, ymm4, ymm9
        vpsrlq	ymm23, ymm0, 51
        vpandq	ymm0, ymm0, ymm28
        vpsrlq	ymm24, ymm1, 51
        vpandq	ymm1, ymm1, ymm28
        vpsrlq	ymm25, ymm2, 51
        vpandq	ymm2, ymm2, ymm28
        vpsrlq	ymm26, ymm3, 51
        vpandq	ymm3, ymm3, ymm28
        vpsrlq	ymm27, ymm4, 51
        vpandq	ymm4, ymm4, ymm28
        vmovdqa64	ymm18, ymm0
        vpmadd52luq	ymm18, ymm27, ymm31
        vpaddq	ymm19, ymm1, ymm23
        vpaddq	ymm20, ymm2, ymm24
        vpaddq	ymm21, ymm3, ymm25
        vpaddq	ymm22, ymm4, ymm26
        ; U = [AA, DA-CB, DA+CB, AA-BB], V = [BB, DA-CB, DA+CB, a24]
        vpermq	ymm23, ymm18, 105
        vpermq	ymm24, ymm19, 105
        vpermq	ymm25, ymm20, 105
        vpermq	ymm26, ymm21, 105
        vpermq	ymm27, ymm22, 105
        vpermq	ymm18, ymm18, 60
        vpermq	ymm19, ymm19, 60
        vpermq	ymm20, ymm20, 60
        vpermq	ymm21, ymm21, 60
        vpermq	ymm22, ymm22, 60
        vpaddq	ymm18{k3}, ymm18, ymm23
        vpaddq	ymm19{k3}, ymm19, ymm24
        vpaddq	ymm20{k3}, ymm20, ymm25
        vpaddq	ymm21{k3}, ymm21, ymm26
        vpaddq	ymm22{k3}, ymm22, ymm27
        vpaddq	ymm18{k1}, ymm18, ymm29
        vpaddq	ymm19{k1}, ymm19, ymm30
        vpaddq	ymm20{k1}, ymm20, ymm30
        vpaddq	ymm21{k1}, ymm21, ymm30
        vpaddq	ymm22{k1}, ymm22, ymm30
        vpsubq	ymm18{k1}, ymm18, ymm23
        vpsubq	ymm19{k1}, ymm19, ymm24
        vpsubq	ymm20{k1}, ymm20, ymm25
        vpsubq	ymm21{k1}, ymm21, ymm26
        vpsubq	ymm22{k1}, ymm22, ymm27
        vpsrlq	ymm0, ymm18, 51
        vpandq	ymm18, ymm18, ymm28
        vpsrlq	ymm1, ymm19, 51
        vpandq	ymm19, ymm19, ymm28
        vpsrlq	ymm2, ymm20, 51
        vpandq	ymm20, ymm20, ymm28
        vpsrlq	ymm3, ymm21, 51
        vpandq	ymm21, ymm21, ymm28
        vpsrlq	ymm4, ymm22, 51
        vpandq	ymm22, ymm22, ymm28
        vpmadd52luq	ymm18, ymm4, ymm31
        vpaddq	ymm19, ymm19, ymm0
        vpaddq	ymm20, ymm20, ymm1
        vpaddq	ymm21, ymm21, ymm2
        vpaddq	ymm22, ymm22, ymm3
        vmovdqu64	YMMWORD PTR [rsp+160], ymm18
        vmovdqu64	YMMWORD PTR [rsp+192], ymm19
        vmovdqu64	YMMWORD PTR [rsp+224], ymm20
        vmovdqu64	YMMWORD PTR [rsp+256], ymm21
        vmovdqu64	YMMWORD PTR [rsp+288], ymm22
        vmovdqa64	ymm23{k7}, ymm18
        vmovdqa64	ymm24{k7}, ymm19
        vmovdqa64	ymm25{k7}, ymm20
        vmovdqa64	ymm26{k7}, ymm21
        vmovdqa64	ymm27{k7}, ymm22
        vpbroadcastq	ymm23{k4}, QWORD PTR [r11+32]
        vpxorq	ymm24{k4}, ymm24, ymm24
        vpxorq	ymm25{k4}, ymm25, ymm25
        vpxorq	ymm26{k4}, ymm26, ymm26
        vpxorq	ymm27{k4}, ymm27, ymm27
        ; [AA.BB, GG, FF, a24.E] = U * V
        ; Multiply 4 field elements
        vpxorq	ymm0, ymm0, ymm0
        vpxorq	ymm9, ymm9, ymm9
        vpxorq	ymm1, ymm1, ymm1
        vpxorq	ymm10, ymm10, ymm10
        vpxorq	ymm2, ymm2, ymm2
        vpxorq	ymm11, ymm11, ymm11
        vpxorq	ymm3, ymm3, ymm3
        vpxorq	ymm12, ymm12, ymm12
        vpxorq	ymm4, ymm4, ymm4
        vpxorq	ymm13, ymm13, ymm13
        vpxorq	ymm5, ymm5, ymm5
        vpxorq	ymm14, ymm14, ymm14
        vpxorq	ymm6, ymm6, ymm6
        vpxorq	ymm15, ymm15, ymm15
        vpxorq	ymm7, ymm7, ymm7
        vpxorq	ymm16, ymm16, ymm16
        vpxorq	ymm8, ymm8, ymm8
        vpxorq	ymm17, ymm17, ymm17
        vpmadd52luq	ymm0, ymm18, ymm23
        vpmadd52huq	ymm9, ymm18, ymm23
        vpmadd52luq	ymm1, ymm18, ymm24
        vpmadd52huq	ymm10, ymm18, ymm24
        vpmadd52luq	ymm2, ymm18, ymm25
        vpmadd52huq	ymm11, ymm18, ymm25
        vpmadd52luq	ymm3, ymm18, ymm26
        vpmadd52huq	ymm12, ymm18, ymm26
        vpmadd52luq	ymm4, ymm18, ymm27
        vpmadd52huq	ymm13, ymm18, ymm27
        vpmadd52luq	ymm1, ymm19, ymm23
        vpmadd52huq	ymm10, ymm19, ymm23
        vpmadd52luq	ymm2, ymm19, ymm24
        vpmadd52huq	ymm11, ymm19, ymm24
        vpmadd52luq	ymm3, ymm19, ymm25
        vpmadd52huq	ymm12, ymm19, ymm25
        vpmadd52luq	ymm4, ymm19, ymm26
        vpmadd52huq	ymm13, ymm19, ymm26
        vpmadd52luq	ymm5, ymm19, ymm27
        vpmadd52huq	ymm14, ymm19, ymm27
        vpmadd52luq	ymm2, ymm20, ymm23
        vpmadd52huq	ymm11, ymm20, ymm23
        vpmadd52luq	ymm3, ymm20, ymm24
        vpmadd52huq	ymm12, ymm20, ymm24
        vpmadd52luq	ymm4, ymm20, ymm25
        vpmadd52huq	ymm13, ymm20, ymm25
        vpmadd52luq	ymm5, ymm20, ymm26
        vpmadd52huq	ymm14, ymm20, ymm26
        vpmadd52luq	ymm6, ymm20, ymm27
        vpmadd52huq	ymm15, ymm20, ymm27
        vpmadd52luq	ymm3, ymm21, ymm23
        vpmadd52huq	ymm12, ymm21, ymm23
        vpmadd52luq	ymm4, ymm21, ymm24
        vpmadd52huq	ymm13, ymm21, ymm24
        vpmadd52luq	ymm5, ymm21, ymm25
        vpmadd52huq	ymm14, ymm21, ymm25
        vpmadd52luq	ymm6, ymm21, ymm26
        vpmadd52huq	ymm15, ymm21, ymm26
        vpmadd52luq	ymm7, ymm21, ymm27
        vpmadd52huq	ymm16, ymm21, ymm27
        vpmadd52luq	ymm4, ymm22, ymm23
        vpmadd52huq	ymm13, ymm22, ymm23
        vpmadd52luq	ymm5, ymm22, ymm24
        vpmadd52huq	ymm14, ymm22, ymm24
        vpmadd52luq	ymm6, ymm22, ymm25
        vpmadd52huq	ymm15, ymm22, ymm25
        vpmadd52luq	ymm7, ymm22, ymm26
        vpmadd52huq	ymm16, ymm22, ymm26
        vpmadd52luq	ymm8, ymm22, ymm27
        vpmadd52huq	ymm17, ymm22, ymm27
        vpaddq	ymm9, ymm9, ymm9
        vpaddq	ymm1, ymm1, ymm9
        vpaddq	ymm10, ymm10, ymm10
        vpaddq	ymm2, ymm2, ymm10
        vpaddq	ymm11, ymm11, ymm11
        vpaddq	ymm3, ymm3, ymm11
        vpaddq	ymm12, ymm12, ymm12
        vpaddq	ymm4, ymm4, ymm12
        vpaddq	ymm13, ymm13, ymm13
        vpaddq	ymm5, ymm5, ymm13
        vpaddq	ymm14, ymm14, ymm14
        vpaddq	ymm6, ymm6, ymm14
        vpaddq	ymm15, ymm15, ymm15
        vpaddq	ymm7, ymm7, ymm15
        vpaddq	ymm16, ymm16, ymm16
        vpaddq	ymm8, ymm8, ymm16
        vpaddq	ymm17, ymm17, ymm17
        ; Reduce
        vpsllq	ymm9, ymm5, 4
        vpsllq	ymm10, ymm5, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm5
        vpaddq	ymm0, ymm0, ymm9
        vpsllq	ymm9, ymm6, 4
        vpsllq	ymm10, ymm6, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm6
        vpaddq	ymm1, ymm1, ymm9
        vpsllq	ymm9, ymm7, 4
        vpsllq	ymm10, ymm7, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm7
        vpaddq	ymm2, ymm2, ymm9
        vpsllq	ymm9, ymm8, 4
        vpsllq	ymm10, ymm8, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm8
        vpaddq	ymm3, ymm3, ymm9
        vpsllq	ymm9, ymm17, 4
        vpsllq	ymm10, ymm17, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm17
        vpaddq	ymm4, ymm4, ymm9
        vpsrlq	ymm23, ymm0, 51
        vpandq	ymm0, ymm0, ymm28
        vpsrlq	ymm24, ymm1, 51
        vpandq	ymm1, ymm1, ymm28
        vpsrlq	ymm25, ymm2, 51
        vpandq	ymm2, ymm2, ymm28
        vpsrlq	ymm26, ymm3, 51
        vpandq	ymm3, ymm3, ymm28
        vpsrlq	ymm27, ymm4, 51
        vpandq	ymm4, ymm4, ymm28
        vmovdqa64	ymm18, ymm0
        vpmadd52luq	ymm18, ymm27, ymm31
        vpaddq	ymm19, ymm1, ymm23
        vpaddq	ymm20, ymm2, ymm24
        vpaddq	ymm21, ymm3, ymm25
        vpaddq	ymm22, ymm4, ymm26
        ; U3 = [E, E, E, x1], V3 = [aE, AA + a24.E, T, T]
        vpermq	ymm23, ymm18, 95
        vpermq	ymm24, ymm19, 95
        vpermq	ymm25, ymm20, 95
        vpermq	ymm26, ymm21, 95
        vpermq	ymm27, ymm22, 95
        vmovdqu64	YMMWORD PTR [rsp+320], ymm18
        vmovdqu64	YMMWORD PTR [rsp+352], ymm19
        vmovdqu64	YMMWORD PTR [rsp+384], ymm20
        vmovdqu64	YMMWORD PTR [rsp+416], ymm21
        vmovdqu64	YMMWORD PTR [rsp+448], ymm22
        vpbroadcastq	ymm5, QWORD PTR [rsp+160]
        vpbroadcastq	ymm6, QWORD PTR [rsp+192]
        vpbroadcastq	ymm7, QWORD PTR [rsp+224]
        vpbroadcastq	ymm8, QWORD PTR [rsp+256]
        vpbroadcastq	ymm9, QWORD PTR [rsp+288]
        vpaddq	ymm23{k5}, ymm23, ymm5
        vpaddq	ymm24{k5}, ymm24, ymm6
        vpaddq	ymm25{k5}, ymm25, ymm7
        vpaddq	ymm26{k5}, ymm26, ymm8
        vpaddq	ymm27{k5}, ymm27, ymm9
        vpsrlq	ymm10, ymm23, 51
        vpandq	ymm23, ymm23, ymm28
        vpsrlq	ymm11, ymm24, 51
        vpandq	ymm24, ymm24, ymm28
        vpsrlq	ymm12, ymm25, 51
        vpandq	ymm25, ymm25, ymm28
        vpsrlq	ymm13, ymm26, 51
        vpandq	ymm26, ymm26, ymm28
        vpsrlq	ymm14, ymm27, 51
        vpandq	ymm27, ymm27, ymm28
        vpmadd52luq	ymm23, ymm14, ymm31
        vpaddq	ymm24, ymm24, ymm10
        vpaddq	ymm25, ymm25, ymm11
        vpaddq	ymm26, ymm26, ymm12
        vpaddq	ymm27, ymm27, ymm13
        vpbroadcastq	ymm18, QWORD PTR [rsp+184]
        vpbroadcastq	ymm19, QWORD PTR [rsp+216]
        vpbroadcastq	ymm20, QWORD PTR [rsp+248]
        vpbroadcastq	ymm21, QWORD PTR [rsp+280]
        vpbroadcastq	ymm22, QWORD PTR [rsp+312]
        vmovdqu64	ymm18{k4}, YMMWORD PTR [rsp]
        vmovdqu64	ymm19{k4}, YMMWORD PTR [rsp+32]
        vmovdqu64	ymm20{k4}, YMMWORD PTR [rsp+64]
        vmovdqu64	ymm21{k4}, YMMWORD PTR [rsp+96]
        vmovdqu64	ymm22{k4}, YMMWORD PTR [rsp+128]
        ; [-, E.H, -, x1.T] = U3 * V3
        ; Multiply 4 field elements
        vpxorq	ymm0, ymm0, ymm0
        vpxorq	ymm9, ymm9, ymm9
        vpxorq	ymm1, ymm1, ymm1
        vpxorq	ymm10, ymm10, ymm10
        vpxorq	ymm2, ymm2, ymm2
        vpxorq	ymm11, ymm11, ymm11
        vpxorq	ymm3, ymm3, ymm3
        vpxorq	ymm12, ymm12, ymm12
        vpxorq	ymm4, ymm4, ymm4
        vpxorq	ymm13, ymm13, ymm13
        vpxorq	ymm5, ymm5, ymm5
        vpxorq	ymm14, ymm14, ymm14
        vpxorq	ymm6, ymm6, ymm6
        vpxorq	ymm15, ymm15, ymm15
        vpxorq	ymm7, ymm7, ymm7
        vpxorq	ymm16, ymm16, ymm16
        vpxorq	ymm8, ymm8, ymm8
        vpxorq	ymm17, ymm17, ymm17
        vpmadd52luq	ymm0, ymm18, ymm23
        vpmadd52huq	ymm9, ymm18, ymm23
        vpmadd52luq	ymm1, ymm18, ymm24
        vpmadd52huq	ymm10, ymm18, ymm24
        vpmadd52luq	ymm2, ymm18, ymm25
        vpmadd52huq	ymm11, ymm18, ymm25
        vpmadd52luq	ymm3, ymm18, ymm26
        vpmadd52huq	ymm12, ymm18, ymm26
        vpmadd52luq	ymm4, ymm18, ymm27
        vpmadd52huq	ymm13, ymm18, ymm27
        vpmadd52luq	ymm1, ymm19, ymm23
        vpmadd52huq	ymm10, ymm19, ymm23
        vpmadd52luq	ymm2, ymm19, ymm24
        vpmadd52huq	ymm11, ymm19, ymm24
        vpmadd52luq	ymm3, ymm19, ymm25
        vpmadd52huq	ymm12, ymm19, ymm25
        vpmadd52luq	ymm4, ymm19, ymm26
        vpmadd52huq	ymm13, ymm19, ymm26
        vpmadd52luq	ymm5, ymm19, ymm27
        vpmadd52huq	ymm14, ymm19, ymm27
        vpmadd52luq	ymm2, ymm20, ymm23
        vpmadd52huq	ymm11, ymm20, ymm23
        vpmadd52luq	ymm3, ymm20, ymm24
        vpmadd52huq	ymm12, ymm20, ymm24
        vpmadd52luq	ymm4, ymm20, ymm25
        vpmadd52huq	ymm13, ymm20, ymm25
        vpmadd52luq	ymm5, ymm20, ymm26
        vpmadd52huq	ymm14, ymm20, ymm26
        vpmadd52luq	ymm6, ymm20, ymm27
        vpmadd52huq	ymm15, ymm20, ymm27
        vpmadd52luq	ymm3, ymm21, ymm23
        vpmadd52huq	ymm12, ymm21, ymm23
        vpmadd52luq	ymm4, ymm21, ymm24
        vpmadd52huq	ymm13, ymm21, ymm24
        vpmadd52luq	ymm5, ymm21, ymm25
        vpmadd52huq	ymm14, ymm21, ymm25
        vpmadd52luq	ymm6, ymm21, ymm26
        vpmadd52huq	ymm15, ymm21, ymm26
        vpmadd52luq	ymm7, ymm21, ymm27
        vpmadd52huq	ymm16, ymm21, ymm27
        vpmadd52luq	ymm4, ymm22, ymm23
        vpmadd52huq	ymm13, ymm22, ymm23
        vpmadd52luq	ymm5, ymm22, ymm24
        vpmadd52huq	ymm14, ymm22, ymm24
        vpmadd52luq	ymm6, ymm22, ymm25
        vpmadd52huq	ymm15, ymm22, ymm25
        vpmadd52luq	ymm7, ymm22, ymm26
        vpmadd52huq	ymm16, ymm22, ymm26
        vpmadd52luq	ymm8, ymm22, ymm27
        vpmadd52huq	ymm17, ymm22, ymm27
        vpaddq	ymm9, ymm9, ymm9
        vpaddq	ymm1, ymm1, ymm9
        vpaddq	ymm10, ymm10, ymm10
        vpaddq	ymm2, ymm2, ymm10
        vpaddq	ymm11, ymm11, ymm11
        vpaddq	ymm3, ymm3, ymm11
        vpaddq	ymm12, ymm12, ymm12
        vpaddq	ymm4, ymm4, ymm12
        vpaddq	ymm13, ymm13, ymm13
        vpaddq	ymm5, ymm5, ymm13
        vpaddq	ymm14, ymm14, ymm14
        vpaddq	ymm6, ymm6, ymm14
        vpaddq	ymm15, ymm15, ymm15
        vpaddq	ymm7, ymm7, ymm15
        vpaddq	ymm16, ymm16, ymm16
        vpaddq	ymm8, ymm8, ymm16
        vpaddq	ymm17, ymm17, ymm17
        ; Reduce
        vpsllq	ymm9, ymm5, 4
        vpsllq	ymm10, ymm5, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm5
        vpaddq	ymm0, ymm0, ymm9
        vpsllq	ymm9, ymm6, 4
        vpsllq	ymm10, ymm6, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm6
        vpaddq	ymm1, ymm1, ymm9
        vpsllq	ymm9, ymm7, 4
        vpsllq	ymm10, ymm7, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm7
        vpaddq	ymm2, ymm2, ymm9
        vpsllq	ymm9, ymm8, 4
        vpsllq	ymm10, ymm8, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm8
        vpaddq	ymm3, ymm3, ymm9
        vpsllq	ymm9, ymm17, 4
        vpsllq	ymm10, ymm17, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm17
        vpaddq	ymm4, ymm4, ymm9
        vpsrlq	ymm23, ymm0, 51
        vpandq	ymm0, ymm0, ymm28
        vpsrlq	ymm24, ymm1, 51
        vpandq	ymm1, ymm1, ymm28
        vpsrlq	ymm25, ymm2, 51
        vpandq	ymm2, ymm2, ymm28
        vpsrlq	ymm26, ymm3, 51
        vpandq	ymm3, ymm3, ymm28
        vpsrlq	ymm27, ymm4, 51
        vpandq	ymm4, ymm4, ymm28
        vmovdqa64	ymm18, ymm0
        vpmadd52luq	ymm18, ymm27, ymm31
        vpaddq	ymm19, ymm1, ymm23
        vpaddq	ymm20, ymm2, ymm24
        vpaddq	ymm21, ymm3, ymm25
        vpaddq	ymm22, ymm4, ymm26
        ; [x2, z2, x3, z3] = [AA.BB, E.H, FF, x1.T]
        vmovdqu64	ymm0, YMMWORD PTR [rsp+320]
        vmovdqu64	ymm1, YMMWORD PTR [rsp+352]
        vmovdqu64	ymm2, YMMWORD PTR [rsp+384]
        vmovdqu64	ymm3, YMMWORD PTR [rsp+416]
        vmovdqu64	ymm4, YMMWORD PTR [rsp+448]
        vmovdqa64	ymm18{k2}, ymm0
        vmovdqa64	ymm19{k2}, ymm1
        vmovdqa64	ymm20{k2}, ymm2
        vmovdqa64	ymm21{k2}, ymm3
        vmovdqa64	ymm22{k2}, ymm4
        mov	rdx, QWORD PTR [rsp+704]
        dec	rdx
        jge	L_curve25519_avx512_ifma_bits
        vmovdqu64	YMMWORD PTR [rsp+480], ymm18
        vmovdqu64	YMMWORD PTR [rsp+512], ymm19
        vmovdqu64	YMMWORD PTR [rsp+544], ymm20
        vmovdqu64	YMMWORD PTR [rsp+576], ymm21
        vmovdqu64	YMMWORD PTR [rsp+608], ymm22
        vzeroupper
        ; Convert to 4 x 64-bit field elements
        mov	r13, 2251799813685247
        mov	rdx, QWORD PTR [rsp+480]
        mov	rax, QWORD PTR [rsp+512]
        mov	r8, QWORD PTR [rsp+544]
        mov	r9, QWORD PTR [rsp+576]
        mov	r10, QWORD PTR [rsp+608]
        mov	r11, rdx
        shr	r11, 51
        and	rdx, r13
        add	rax, r11
        mov	r11, rax
        shr	r11, 51
        and	rax, r13
        add	r8, r11
        mov	r11, r8
        shr	r11, 51
        and	r8, r13
        add	r9, r11
        mov	r11, r9
        shr	r11, 51
        and	r9, r13
        add	r10, r11
        mov	r11, r10
        shr	r11, 51
        and	r10, r13
        imul	r11, r11, 19
        add	rdx, r11
        mov	r11, rax
        shl	r11, 51
        mov	r12, rax
        shr	r12, 13
        add	rdx, r11
        adc	r12, 0
        mov	QWORD PTR [rsp+640], rdx
        mov	r11, r8
        shl	r11, 38
        mov	rdx, r8
        shr	rdx, 26
        add	r12, r11
        adc	rdx, 0
        mov	QWORD PTR [rsp+648], r12
        mov	r11, r9
        shl	r11, 25
        mov	r12, r9
        shr	r12, 39
        add	rdx, r11
        adc	r12, 0
        mov	QWORD PTR [rsp+656], rdx
        mov	r11, r10
        shl	r11, 12
        add	r12, r11
        mov	QWORD PTR [rsp+664], r12
        mov	rdx, QWORD PTR [rsp+488]
        mov	rax, QWORD PTR [rsp+520]
        mov	r8, QWORD PTR [rsp+552]
        mov	r9, QWORD PTR [rsp+584]
        mov	r10, QWORD PTR [rsp+616]
        mov	r11, rdx
        shr	r11, 51
        and	rdx, r13
        add	rax, r11
        mov	r11, rax
        shr	r11, 51
        and	rax, r13
        add	r8, r11
        mov	r11, r8
        shr	r11, 51
        and	r8, r13
        add	r9, r11
        mov	r11, r9
        shr	r11, 51
        and	r9, r13
        add	r10, r11
        mov	r11, r10
        shr	r11, 51
        and	r10, r13
        imul	r11, r11, 19
        add	rdx, r11
        mov	r11, rax
        shl	r11, 51
        mov	r12, rax
        shr	r12, 13
        add	rdx, r11
        adc	r12, 0
        mov	QWORD PTR [rsp+672], rdx
        mov	r11, r8
        shl	r11, 38
        mov	rdx, r8
        shr	rdx, 26
        add	r12, r11
        adc	rdx, 0
        mov	QWORD PTR [rsp+680], r12
        mov	r11, r9
        shl	r11, 25
        mov	r12, r9
        shr	r12, 39
        add	rdx, r11
        adc	r12, 0
        mov	QWORD PTR [rsp+688], rdx
        mov	r11, r10
        shl	r11, 12
        add	r12, r11
        mov	QWORD PTR [rsp+696], r12
        ; z2 = 1 / z2
        lea	rcx, QWORD PTR [rsp+672]
        lea	rdx, QWORD PTR [rsp+672]
        sub	rsp, 32
        call	fe_invert_avx2
        add	rsp, 32
        ; x2 = x2 * z2
        lea	rcx, QWORD PTR [rsp+640]
        lea	rdx, QWORD PTR [rsp+640]
        lea	r8, QWORD PTR [rsp+672]
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        ; Store fully reduced result
        mov	rcx, QWORD PTR [rsp+712]
        lea	rdx, QWORD PTR [rsp+640]
        sub	rsp, 32
        call	fe_tobytes
        add	rsp, 32
        xor	rax, rax
        vmovdqu	xmm6, OWORD PTR [rsp+744]
        vmovdqu	xmm7, OWORD PTR [rsp+760]
        vmovdqu	xmm8, OWORD PTR [rsp+776]
        vmovdqu	xmm9, OWORD PTR [rsp+792]
        vmovdqu	xmm10, OWORD PTR [rsp+808]
        vmovdqu	xmm11, OWORD PTR [rsp+824]
        vmovdqu	xmm12, OWORD PTR [rsp+840]
        vmovdqu	xmm13, OWORD PTR [rsp+856]
        vmovdqu	xmm14, OWORD PTR [rsp+872]
        vmovdqu	xmm15, OWORD PTR [rsp+888]
        add	rsp, 904
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
curve25519_avx512_ifma ENDP
_TEXT ENDS
IFDEF WOLFSSL_CURVE25519_NOT_USE_ED25519
_TEXT SEGMENT READONLY PARA
curve25519_base_avx512_ifma_dq PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        mov	r15, rcx
        mov	rdi, rdx
        sub	rsp, 896
        vmovdqu	OWORD PTR [rsp+736], xmm6
        vmovdqu	OWORD PTR [rsp+752], xmm7
        vmovdqu	OWORD PTR [rsp+768], xmm8
        vmovdqu	OWORD PTR [rsp+784], xmm9
        vmovdqu	OWORD PTR [rsp+800], xmm10
        vmovdqu	OWORD PTR [rsp+816], xmm11
        vmovdqu	OWORD PTR [rsp+832], xmm12
        vmovdqu	OWORD PTR [rsp+848], xmm13
        vmovdqu	OWORD PTR [rsp+864], xmm14
        vmovdqu	OWORD PTR [rsp+880], xmm15
        mov	QWORD PTR [rsp+712], r15
        mov	r13, 2251799813685247
        mov	r10, 9
        mov	QWORD PTR [rsp], r10
        mov	QWORD PTR [rsp+8], r10
        mov	QWORD PTR [rsp+16], r10
        mov	QWORD PTR [rsp+24], r10
        mov	QWORD PTR [rsp+480], 1
        mov	QWORD PTR [rsp+488], 0
        mov	QWORD PTR [rsp+496], r10
        mov	QWORD PTR [rsp+504], 1
        mov	r10, 0
        mov	QWORD PTR [rsp+32], r10
        mov	QWORD PTR [rsp+40], r10
        mov	QWORD PTR [rsp+48], r10
        mov	QWORD PTR [rsp+56], r10
        mov	QWORD PTR [rsp+512], 0
        mov	QWORD PTR [rsp+520], 0
        mov	QWORD PTR [rsp+528], r10
        mov	QWORD PTR [rsp+536], 0
        mov	QWORD PTR [rsp+64], r10
        mov	QWORD PTR [rsp+72], r10
        mov	QWORD PTR [rsp+80], r10
        mov	QWORD PTR [rsp+88], r10
        mov	QWORD PTR [rsp+544], 0
        mov	QWORD PTR [rsp+552], 0
        mov	QWORD PTR [rsp+560], r10
        mov	QWORD PTR [rsp+568], 0
        mov	QWORD PTR [rsp+96], r10
        mov	QWORD PTR [rsp+104], r10
        mov	QWORD PTR [rsp+112], r10
        mov	QWORD PTR [rsp+120], r10
        mov	QWORD PTR [rsp+576], 0
        mov	QWORD PTR [rsp+584], 0
        mov	QWORD PTR [rsp+592], r10
        mov	QWORD PTR [rsp+600], 0
        mov	QWORD PTR [rsp+128], r10
        mov	QWORD PTR [rsp+136], r10
        mov	QWORD PTR [rsp+144], r10
        mov	QWORD PTR [rsp+152], r10
        mov	QWORD PTR [rsp+608], 0
        mov	QWORD PTR [rsp+616], 0
        mov	QWORD PTR [rsp+624], r10
        mov	QWORD PTR [rsp+632], 0
        mov	r11, QWORD PTR [ptr_L_x25519_ifma_consts]
        vpbroadcastq	ymm28, QWORD PTR [r11]
        vpbroadcastq	ymm29, QWORD PTR [r11+8]
        vpbroadcastq	ymm30, QWORD PTR [r11+16]
        vpbroadcastq	ymm31, QWORD PTR [r11+24]
        mov	r10d, 10
        kmovw	k1, r10d
        mov	r10d, 5
        kmovw	k2, r10d
        mov	r10d, 4
        kmovw	k3, r10d
        mov	r10d, 8
        kmovw	k4, r10d
        mov	r10d, 2
        kmovw	k5, r10d
        mov	r10d, 6
        kmovw	k7, r10d
        vmovdqu64	ymm18, YMMWORD PTR [rsp+480]
        vmovdqu64	ymm19, YMMWORD PTR [rsp+512]
        vmovdqu64	ymm20, YMMWORD PTR [rsp+544]
        vmovdqu64	ymm21, YMMWORD PTR [rsp+576]
        vmovdqu64	ymm22, YMMWORD PTR [rsp+608]
        mov	r8, 0
        mov	rdx, 254
L_curve25519_base_avx512_ifma_dq_bits:
        ; Conditionally swap (x2, z2) with (x3, z3)
        mov	QWORD PTR [rsp+704], rdx
        mov	rcx, rdx
        and	rcx, 63
        shr	rdx, 6
        mov	rax, QWORD PTR [rdi+8*rdx]
        shr	rax, cl
        and	rax, 1
        mov	r9, rax
        xor	r8, rax
        neg	r8
        and	r8, 15
        kmovw	k6, r8d
        mov	r8, r9
        vpermq	ymm18{k6}, ymm18, 78
        vpermq	ymm19{k6}, ymm19, 78
        vpermq	ymm20{k6}, ymm20, 78
        vpermq	ymm21{k6}, ymm21, 78
        vpermq	ymm22{k6}, ymm22, 78
        ; A = x2 + z2, B = x2 - z2, C = x3 + z3, D = x3 - z3
        vpermq	ymm0, ymm18, 177
        vpermq	ymm1, ymm19, 177
        vpermq	ymm2, ymm20, 177
        vpermq	ymm3, ymm21, 177
        vpermq	ymm4, ymm22, 177
        vpaddq	ymm23, ymm0, ymm18
        vpaddq	ymm24, ymm1, ymm19
        vpaddq	ymm25, ymm2, ymm20
        vpaddq	ymm26, ymm3, ymm21
        vpaddq	ymm27, ymm4, ymm22
        vpaddq	ymm0{k1}, ymm0, ymm29
        vpaddq	ymm1{k1}, ymm1, ymm30
        vpaddq	ymm2{k1}, ymm2, ymm30
        vpaddq	ymm3{k1}, ymm3, ymm30
        vpaddq	ymm4{k1}, ymm4, ymm30
        vpsubq	ymm23{k1}, ymm0, ymm18
        vpsubq	ymm24{k1}, ymm1, ymm19
        vpsubq	ymm25{k1}, ymm2, ymm20
        vpsubq	ymm26{k1}, ymm3, ymm21
        vpsubq	ymm27{k1}, ymm4, ymm22
        vpsrlq	ymm5, ymm23, 51
        vpandq	ymm23, ymm23, ymm28
        vpsrlq	ymm6, ymm24, 51
        vpandq	ymm24, ymm24, ymm28
        vpsrlq	ymm7, ymm25, 51
        vpandq	ymm25, ymm25, ymm28
        vpsrlq	ymm8, ymm26, 51
        vpandq	ymm26, ymm26, ymm28
        vpsrlq	ymm9, ymm27, 51
        vpandq	ymm27, ymm27, ymm28
        vpmadd52luq	ymm23, ymm9, ymm31
        vpaddq	ymm24, ymm24, ymm5
        vpaddq	ymm25, ymm25, ymm6
        vpaddq	ymm26, ymm26, ymm7
        vpaddq	ymm27, ymm27, ymm8
        ; [AA, BB, CB, DA] = [A, B, C, D] * [A, B, B, A]
        vpermq	ymm18, ymm23, 20
        vpermq	ymm19, ymm24, 20
        vpermq	ymm20, ymm25, 20
        vpermq	ymm21, ymm26, 20
        vpermq	ymm22, ymm27, 20
        ; Multiply 4 field elements
        vpxorq	ymm0, ymm0, ymm0
        vpxorq	ymm9, ymm9, ymm9
        vpxorq	ymm1, ymm1, ymm1
        vpxorq	ymm10, ymm10, ymm10
        vpxorq	ymm2, ymm2, ymm2
        vpxorq	ymm11, ymm11, ymm11
        vpxorq	ymm3, ymm3, ymm3
        vpxorq	ymm12, ymm12, ymm12
        vpxorq	ymm4, ymm4, ymm4
        vpxorq	ymm13, ymm13, ymm13
        vpxorq	ymm5, ymm5, ymm5
        vpxorq	ymm14, ymm14, ymm14
        vpxorq	ymm6, ymm6, ymm6
        vpxorq	ymm15, ymm15, ymm15
        vpxorq	ymm7, ymm7, ymm7
        vpxorq	ymm16, ymm16, ymm16
        vpxorq	ymm8, ymm8, ymm8
        vpxorq	ymm17, ymm17, ymm17
        vpmadd52luq	ymm0, ymm18, ymm23
        vpmadd52huq	ymm9, ymm18, ymm23
        vpmadd52luq	ymm1, ymm18, ymm24
        vpmadd52huq	ymm10, ymm18, ymm24
        vpmadd52luq	ymm2, ymm18, ymm25
        vpmadd52huq	ymm11, ymm18, ymm25
        vpmadd52luq	ymm3, ymm18, ymm26
        vpmadd52huq	ymm12, ymm18, ymm26
        vpmadd52luq	ymm4, ymm18, ymm27
        vpmadd52huq	ymm13, ymm18, ymm27
        vpmadd52luq	ymm1, ymm19, ymm23
        vpmadd52huq	ymm10, ymm19, ymm23
        vpmadd52luq	ymm2, ymm19, ymm24
        vpmadd52huq	ymm11, ymm19, ymm24
        vpmadd52luq	ymm3, ymm19, ymm25
        vpmadd52huq	ymm12, ymm19, ymm25
        vpmadd52luq	ymm4, ymm19, ymm26
        vpmadd52huq	ymm13, ymm19, ymm26
        vpmadd52luq	ymm5, ymm19, ymm27
        vpmadd52huq	ymm14, ymm19, ymm27
        vpmadd52luq	ymm2, ymm20, ymm23
        vpmadd52huq	ymm11, ymm20, ymm23
        vpmadd52luq	ymm3, ymm20, ymm24
        vpmadd52huq	ymm12, ymm20, ymm24
        vpmadd52luq	ymm4, ymm20, ymm25
        vpmadd52huq	ymm13, ymm20, ymm25
        vpmadd52luq	ymm5, ymm20, ymm26
        vpmadd52huq	ymm14, ymm20, ymm26
        vpmadd52luq	ymm6, ymm20, ymm27
        vpmadd52huq	ymm15, ymm20, ymm27
        vpmadd52luq	ymm3, ymm21, ymm23
        vpmadd52huq	ymm12, ymm21, ymm23
        vpmadd52luq	ymm4, ymm21, ymm24
        vpmadd52huq	ymm13, ymm21, ymm24
        vpmadd52luq	ymm5, ymm21, ymm25
        vpmadd52huq	ymm14, ymm21, ymm25
        vpmadd52luq	ymm6, ymm21, ymm26
        vpmadd52huq	ymm15, ymm21, ymm26
        vpmadd52luq	ymm7, ymm21, ymm27
        vpmadd52huq	ymm16, ymm21, ymm27
        vpmadd52luq	ymm4, ymm22, ymm23
        vpmadd52huq	ymm13, ymm22, ymm23
        vpmadd52luq	ymm5, ymm22, ymm24
        vpmadd52huq	ymm14, ymm22, ymm24
        vpmadd52luq	ymm6, ymm22, ymm25
        vpmadd52huq	ymm15, ymm22, ymm25
        vpmadd52luq	ymm7, ymm22, ymm26
        vpmadd52huq	ymm16, ymm22, ymm26
        vpmadd52luq	ymm8, ymm22, ymm27
        vpmadd52huq	ymm17, ymm22, ymm27
        vpaddq	ymm9, ymm9, ymm9
        vpaddq	ymm1, ymm1, ymm9
        vpaddq	ymm10, ymm10, ymm10
        vpaddq	ymm2, ymm2, ymm10
        vpaddq	ymm11, ymm11, ymm11
        vpaddq	ymm3, ymm3, ymm11
        vpaddq	ymm12, ymm12, ymm12
        vpaddq	ymm4, ymm4, ymm12
        vpaddq	ymm13, ymm13, ymm13
        vpaddq	ymm5, ymm5, ymm13
        vpaddq	ymm14, ymm14, ymm14
        vpaddq	ymm6, ymm6, ymm14
        vpaddq	ymm15, ymm15, ymm15
        vpaddq	ymm7, ymm7, ymm15
        vpaddq	ymm16, ymm16, ymm16
        vpaddq	ymm8, ymm8, ymm16
        vpaddq	ymm17, ymm17, ymm17
        ; Reduce
        vpmullq	ymm9, ymm5, ymm31
        vpaddq	ymm0, ymm0, ymm9
        vpmullq	ymm9, ymm6, ymm31
        vpaddq	ymm1, ymm1, ymm9
        vpmullq	ymm9, ymm7, ymm31
        vpaddq	ymm2, ymm2, ymm9
        vpmullq	ymm9, ymm8, ymm31
        vpaddq	ymm3, ymm3, ymm9
        vpmullq	ymm9, ymm17, ymm31
        vpaddq	ymm4, ymm4, ymm9
        vpsrlq	ymm23, ymm0, 51
        vpandq	ymm0, ymm0, ymm28
        vpsrlq	ymm24, ymm1, 51
        vpandq	ymm1, ymm1, ymm28
        vpsrlq	ymm25, ymm2, 51
        vpandq	ymm2, ymm2, ymm28
        vpsrlq	ymm26, ymm3, 51
        vpandq	ymm3, ymm3, ymm28
        vpsrlq	ymm27, ymm4, 51
        vpandq	ymm4, ymm4, ymm28
        vmovdqa64	ymm18, ymm0
        vpmadd52luq	ymm18, ymm27, ymm31
        vpaddq	ymm19, ymm1, ymm23
        vpaddq	ymm20, ymm2, ymm24
        vpaddq	ymm21, ymm3, ymm25
        vpaddq	ymm22, ymm4, ymm26
        ; U = [AA, DA-CB, DA+CB, AA-BB], V = [BB, DA-CB, DA+CB, a24]
        vpermq	ymm23, ymm18, 105
        vpermq	ymm24, ymm19, 105
        vpermq	ymm25, ymm20, 105
        vpermq	ymm26, ymm21, 105
        vpermq	ymm27, ymm22, 105
        vpermq	ymm18, ymm18, 60
        vpermq	ymm19, ymm19, 60
        vpermq	ymm20, ymm20, 60
        vpermq	ymm21, ymm21, 60
        vpermq	ymm22, ymm22, 60
        vpaddq	ymm18{k3}, ymm18, ymm23
        vpaddq	ymm19{k3}, ymm19, ymm24
        vpaddq	ymm20{k3}, ymm20, ymm25
        vpaddq	ymm21{k3}, ymm21, ymm26
        vpaddq	ymm22{k3}, ymm22, ymm27
        vpaddq	ymm18{k1}, ymm18, ymm29
        vpaddq	ymm19{k1}, ymm19, ymm30
        vpaddq	ymm20{k1}, ymm20, ymm30
        vpaddq	ymm21{k1}, ymm21, ymm30
        vpaddq	ymm22{k1}, ymm22, ymm30
        vpsubq	ymm18{k1}, ymm18, ymm23
        vpsubq	ymm19{k1}, ymm19, ymm24
        vpsubq	ymm20{k1}, ymm20, ymm25
        vpsubq	ymm21{k1}, ymm21, ymm26
        vpsubq	ymm22{k1}, ymm22, ymm27
        vpsrlq	ymm0, ymm18, 51
        vpandq	ymm18, ymm18, ymm28
        vpsrlq	ymm1, ymm19, 51
        vpandq	ymm19, ymm19, ymm28
        vpsrlq	ymm2, ymm20, 51
        vpandq	ymm20, ymm20, ymm28
        vpsrlq	ymm3, ymm21, 51
        vpandq	ymm21, ymm21, ymm28
        vpsrlq	ymm4, ymm22, 51
        vpandq	ymm22, ymm22, ymm28
        vpmadd52luq	ymm18, ymm4, ymm31
        vpaddq	ymm19, ymm19, ymm0
        vpaddq	ymm20, ymm20, ymm1
        vpaddq	ymm21, ymm21, ymm2
        vpaddq	ymm22, ymm22, ymm3
        vmovdqu64	YMMWORD PTR [rsp+160], ymm18
        vmovdqu64	YMMWORD PTR [rsp+192], ymm19
        vmovdqu64	YMMWORD PTR [rsp+224], ymm20
        vmovdqu64	YMMWORD PTR [rsp+256], ymm21
        vmovdqu64	YMMWORD PTR [rsp+288], ymm22
        vmovdqa64	ymm23{k7}, ymm18
        vmovdqa64	ymm24{k7}, ymm19
        vmovdqa64	ymm25{k7}, ymm20
        vmovdqa64	ymm26{k7}, ymm21
        vmovdqa64	ymm27{k7}, ymm22
        vpbroadcastq	ymm23{k4}, QWORD PTR [r11+32]
        vpxorq	ymm24{k4}, ymm24, ymm24
        vpxorq	ymm25{k4}, ymm25, ymm25
        vpxorq	ymm26{k4}, ymm26, ymm26
        vpxorq	ymm27{k4}, ymm27, ymm27
        ; [AA.BB, GG, FF, a24.E] = U * V
        ; Multiply 4 field elements
        vpxorq	ymm0, ymm0, ymm0
        vpxorq	ymm9, ymm9, ymm9
        vpxorq	ymm1, ymm1, ymm1
        vpxorq	ymm10, ymm10, ymm10
        vpxorq	ymm2, ymm2, ymm2
        vpxorq	ymm11, ymm11, ymm11
        vpxorq	ymm3, ymm3, ymm3
        vpxorq	ymm12, ymm12, ymm12
        vpxorq	ymm4, ymm4, ymm4
        vpxorq	ymm13, ymm13, ymm13
        vpxorq	ymm5, ymm5, ymm5
        vpxorq	ymm14, ymm14, ymm14
        vpxorq	ymm6, ymm6, ymm6
        vpxorq	ymm15, ymm15, ymm15
        vpxorq	ymm7, ymm7, ymm7
        vpxorq	ymm16, ymm16, ymm16
        vpxorq	ymm8, ymm8, ymm8
        vpxorq	ymm17, ymm17, ymm17
        vpmadd52luq	ymm0, ymm18, ymm23
        vpmadd52huq	ymm9, ymm18, ymm23
        vpmadd52luq	ymm1, ymm18, ymm24
        vpmadd52huq	ymm10, ymm18, ymm24
        vpmadd52luq	ymm2, ymm18, ymm25
        vpmadd52huq	ymm11, ymm18, ymm25
        vpmadd52luq	ymm3, ymm18, ymm26
        vpmadd52huq	ymm12, ymm18, ymm26
        vpmadd52luq	ymm4, ymm18, ymm27
        vpmadd52huq	ymm13, ymm18, ymm27
        vpmadd52luq	ymm1, ymm19, ymm23
        vpmadd52huq	ymm10, ymm19, ymm23
        vpmadd52luq	ymm2, ymm19, ymm24
        vpmadd52huq	ymm11, ymm19, ymm24
        vpmadd52luq	ymm3, ymm19, ymm25
        vpmadd52huq	ymm12, ymm19, ymm25
        vpmadd52luq	ymm4, ymm19, ymm26
        vpmadd52huq	ymm13, ymm19, ymm26
        vpmadd52luq	ymm5, ymm19, ymm27
        vpmadd52huq	ymm14, ymm19, ymm27
        vpmadd52luq	ymm2, ymm20, ymm23
        vpmadd52huq	ymm11, ymm20, ymm23
        vpmadd52luq	ymm3, ymm20, ymm24
        vpmadd52huq	ymm12, ymm20, ymm24
        vpmadd52luq	ymm4, ymm20, ymm25
        vpmadd52huq	ymm13, ymm20, ymm25
        vpmadd52luq	ymm5, ymm20, ymm26
        vpmadd52huq	ymm14, ymm20, ymm26
        vpmadd52luq	ymm6, ymm20, ymm27
        vpmadd52huq	ymm15, ymm20, ymm27
        vpmadd52luq	ymm3, ymm21, ymm23
        vpmadd52huq	ymm12, ymm21, ymm23
        vpmadd52luq	ymm4, ymm21, ymm24
        vpmadd52huq	ymm13, ymm21, ymm24
        vpmadd52luq	ymm5, ymm21, ymm25
        vpmadd52huq	ymm14, ymm21, ymm25
        vpmadd52luq	ymm6, ymm21, ymm26
        vpmadd52huq	ymm15, ymm21, ymm26
        vpmadd52luq	ymm7, ymm21, ymm27
        vpmadd52huq	ymm16, ymm21, ymm27
        vpmadd52luq	ymm4, ymm22, ymm23
        vpmadd52huq	ymm13, ymm22, ymm23
        vpmadd52luq	ymm5, ymm22, ymm24
        vpmadd52huq	ymm14, ymm22, ymm24
        vpmadd52luq	ymm6, ymm22, ymm25
        vpmadd52huq	ymm15, ymm22, ymm25
        vpmadd52luq	ymm7, ymm22, ymm26
        vpmadd52huq	ymm16, ymm22, ymm26
        vpmadd52luq	ymm8, ymm22, ymm27
        vpmadd52huq	ymm17, ymm22, ymm27
        vpaddq	ymm9, ymm9, ymm9
        vpaddq	ymm1, ymm1, ymm9
        vpaddq	ymm10, ymm10, ymm10
        vpaddq	ymm2, ymm2, ymm10
        vpaddq	ymm11, ymm11, ymm11
        vpaddq	ymm3, ymm3, ymm11
        vpaddq	ymm12, ymm12, ymm12
        vpaddq	ymm4, ymm4, ymm12
        vpaddq	ymm13, ymm13, ymm13
        vpaddq	ymm5, ymm5, ymm13
        vpaddq	ymm14, ymm14, ymm14
        vpaddq	ymm6, ymm6, ymm14
        vpaddq	ymm15, ymm15, ymm15
        vpaddq	ymm7, ymm7, ymm15
        vpaddq	ymm16, ymm16, ymm16
        vpaddq	ymm8, ymm8, ymm16
        vpaddq	ymm17, ymm17, ymm17
        ; Reduce
        vpmullq	ymm9, ymm5, ymm31
        vpaddq	ymm0, ymm0, ymm9
        vpmullq	ymm9, ymm6, ymm31
        vpaddq	ymm1, ymm1, ymm9
        vpmullq	ymm9, ymm7, ymm31
        vpaddq	ymm2, ymm2, ymm9
        vpmullq	ymm9, ymm8, ymm31
        vpaddq	ymm3, ymm3, ymm9
        vpmullq	ymm9, ymm17, ymm31
        vpaddq	ymm4, ymm4, ymm9
        vpsrlq	ymm23, ymm0, 51
        vpandq	ymm0, ymm0, ymm28
        vpsrlq	ymm24, ymm1, 51
        vpandq	ymm1, ymm1, ymm28
        vpsrlq	ymm25, ymm2, 51
        vpandq	ymm2, ymm2, ymm28
        vpsrlq	ymm26, ymm3, 51
        vpandq	ymm3, ymm3, ymm28
        vpsrlq	ymm27, ymm4, 51
        vpandq	ymm4, ymm4, ymm28
        vmovdqa64	ymm18, ymm0
        vpmadd52luq	ymm18, ymm27, ymm31
        vpaddq	ymm19, ymm1, ymm23
        vpaddq	ymm20, ymm2, ymm24
        vpaddq	ymm21, ymm3, ymm25
        vpaddq	ymm22, ymm4, ymm26
        ; U3 = [E, E, E, x1], V3 = [aE, AA + a24.E, T, T]
        vpermq	ymm23, ymm18, 95
        vpermq	ymm24, ymm19, 95
        vpermq	ymm25, ymm20, 95
        vpermq	ymm26, ymm21, 95
        vpermq	ymm27, ymm22, 95
        vmovdqu64	YMMWORD PTR [rsp+320], ymm18
        vmovdqu64	YMMWORD PTR [rsp+352], ymm19
        vmovdqu64	YMMWORD PTR [rsp+384], ymm20
        vmovdqu64	YMMWORD PTR [rsp+416], ymm21
        vmovdqu64	YMMWORD PTR [rsp+448], ymm22
        vpbroadcastq	ymm5, QWORD PTR [rsp+160]
        vpbroadcastq	ymm6, QWORD PTR [rsp+192]
        vpbroadcastq	ymm7, QWORD PTR [rsp+224]
        vpbroadcastq	ymm8, QWORD PTR [rsp+256]
        vpbroadcastq	ymm9, QWORD PTR [rsp+288]
        vpaddq	ymm23{k5}, ymm23, ymm5
        vpaddq	ymm24{k5}, ymm24, ymm6
        vpaddq	ymm25{k5}, ymm25, ymm7
        vpaddq	ymm26{k5}, ymm26, ymm8
        vpaddq	ymm27{k5}, ymm27, ymm9
        vpsrlq	ymm10, ymm23, 51
        vpandq	ymm23, ymm23, ymm28
        vpsrlq	ymm11, ymm24, 51
        vpandq	ymm24, ymm24, ymm28
        vpsrlq	ymm12, ymm25, 51
        vpandq	ymm25, ymm25, ymm28
        vpsrlq	ymm13, ymm26, 51
        vpandq	ymm26, ymm26, ymm28
        vpsrlq	ymm14, ymm27, 51
        vpandq	ymm27, ymm27, ymm28
        vpmadd52luq	ymm23, ymm14, ymm31
        vpaddq	ymm24, ymm24, ymm10
        vpaddq	ymm25, ymm25, ymm11
        vpaddq	ymm26, ymm26, ymm12
        vpaddq	ymm27, ymm27, ymm13
        vpbroadcastq	ymm18, QWORD PTR [rsp+184]
        vpbroadcastq	ymm19, QWORD PTR [rsp+216]
        vpbroadcastq	ymm20, QWORD PTR [rsp+248]
        vpbroadcastq	ymm21, QWORD PTR [rsp+280]
        vpbroadcastq	ymm22, QWORD PTR [rsp+312]
        vmovdqu64	ymm18{k4}, YMMWORD PTR [rsp]
        vmovdqu64	ymm19{k4}, YMMWORD PTR [rsp+32]
        vmovdqu64	ymm20{k4}, YMMWORD PTR [rsp+64]
        vmovdqu64	ymm21{k4}, YMMWORD PTR [rsp+96]
        vmovdqu64	ymm22{k4}, YMMWORD PTR [rsp+128]
        ; [-, E.H, -, x1.T] = U3 * V3
        ; Multiply 4 field elements
        vpxorq	ymm0, ymm0, ymm0
        vpxorq	ymm9, ymm9, ymm9
        vpxorq	ymm1, ymm1, ymm1
        vpxorq	ymm10, ymm10, ymm10
        vpxorq	ymm2, ymm2, ymm2
        vpxorq	ymm11, ymm11, ymm11
        vpxorq	ymm3, ymm3, ymm3
        vpxorq	ymm12, ymm12, ymm12
        vpxorq	ymm4, ymm4, ymm4
        vpxorq	ymm13, ymm13, ymm13
        vpxorq	ymm5, ymm5, ymm5
        vpxorq	ymm14, ymm14, ymm14
        vpxorq	ymm6, ymm6, ymm6
        vpxorq	ymm15, ymm15, ymm15
        vpxorq	ymm7, ymm7, ymm7
        vpxorq	ymm16, ymm16, ymm16
        vpxorq	ymm8, ymm8, ymm8
        vpxorq	ymm17, ymm17, ymm17
        vpmadd52luq	ymm0, ymm18, ymm23
        vpmadd52huq	ymm9, ymm18, ymm23
        vpmadd52luq	ymm1, ymm18, ymm24
        vpmadd52huq	ymm10, ymm18, ymm24
        vpmadd52luq	ymm2, ymm18, ymm25
        vpmadd52huq	ymm11, ymm18, ymm25
        vpmadd52luq	ymm3, ymm18, ymm26
        vpmadd52huq	ymm12, ymm18, ymm26
        vpmadd52luq	ymm4, ymm18, ymm27
        vpmadd52huq	ymm13, ymm18, ymm27
        vpmadd52luq	ymm1, ymm19, ymm23
        vpmadd52huq	ymm10, ymm19, ymm23
        vpmadd52luq	ymm2, ymm19, ymm24
        vpmadd52huq	ymm11, ymm19, ymm24
        vpmadd52luq	ymm3, ymm19, ymm25
        vpmadd52huq	ymm12, ymm19, ymm25
        vpmadd52luq	ymm4, ymm19, ymm26
        vpmadd52huq	ymm13, ymm19, ymm26
        vpmadd52luq	ymm5, ymm19, ymm27
        vpmadd52huq	ymm14, ymm19, ymm27
        vpmadd52luq	ymm2, ymm20, ymm23
        vpmadd52huq	ymm11, ymm20, ymm23
        vpmadd52luq	ymm3, ymm20, ymm24
        vpmadd52huq	ymm12, ymm20, ymm24
        vpmadd52luq	ymm4, ymm20, ymm25
        vpmadd52huq	ymm13, ymm20, ymm25
        vpmadd52luq	ymm5, ymm20, ymm26
        vpmadd52huq	ymm14, ymm20, ymm26
        vpmadd52luq	ymm6, ymm20, ymm27
        vpmadd52huq	ymm15, ymm20, ymm27
        vpmadd52luq	ymm3, ymm21, ymm23
        vpmadd52huq	ymm12, ymm21, ymm23
        vpmadd52luq	ymm4, ymm21, ymm24
        vpmadd52huq	ymm13, ymm21, ymm24
        vpmadd52luq	ymm5, ymm21, ymm25
        vpmadd52huq	ymm14, ymm21, ymm25
        vpmadd52luq	ymm6, ymm21, ymm26
        vpmadd52huq	ymm15, ymm21, ymm26
        vpmadd52luq	ymm7, ymm21, ymm27
        vpmadd52huq	ymm16, ymm21, ymm27
        vpmadd52luq	ymm4, ymm22, ymm23
        vpmadd52huq	ymm13, ymm22, ymm23
        vpmadd52luq	ymm5, ymm22, ymm24
        vpmadd52huq	ymm14, ymm22, ymm24
        vpmadd52luq	ymm6, ymm22, ymm25
        vpmadd52huq	ymm15, ymm22, ymm25
        vpmadd52luq	ymm7, ymm22, ymm26
        vpmadd52huq	ymm16, ymm22, ymm26
        vpmadd52luq	ymm8, ymm22, ymm27
        vpmadd52huq	ymm17, ymm22, ymm27
        vpaddq	ymm9, ymm9, ymm9
        vpaddq	ymm1, ymm1, ymm9
        vpaddq	ymm10, ymm10, ymm10
        vpaddq	ymm2, ymm2, ymm10
        vpaddq	ymm11, ymm11, ymm11
        vpaddq	ymm3, ymm3, ymm11
        vpaddq	ymm12, ymm12, ymm12
        vpaddq	ymm4, ymm4, ymm12
        vpaddq	ymm13, ymm13, ymm13
        vpaddq	ymm5, ymm5, ymm13
        vpaddq	ymm14, ymm14, ymm14
        vpaddq	ymm6, ymm6, ymm14
        vpaddq	ymm15, ymm15, ymm15
        vpaddq	ymm7, ymm7, ymm15
        vpaddq	ymm16, ymm16, ymm16
        vpaddq	ymm8, ymm8, ymm16
        vpaddq	ymm17, ymm17, ymm17
        ; Reduce
        vpmullq	ymm9, ymm5, ymm31
        vpaddq	ymm0, ymm0, ymm9
        vpmullq	ymm9, ymm6, ymm31
        vpaddq	ymm1, ymm1, ymm9
        vpmullq	ymm9, ymm7, ymm31
        vpaddq	ymm2, ymm2, ymm9
        vpmullq	ymm9, ymm8, ymm31
        vpaddq	ymm3, ymm3, ymm9
        vpmullq	ymm9, ymm17, ymm31
        vpaddq	ymm4, ymm4, ymm9
        vpsrlq	ymm23, ymm0, 51
        vpandq	ymm0, ymm0, ymm28
        vpsrlq	ymm24, ymm1, 51
        vpandq	ymm1, ymm1, ymm28
        vpsrlq	ymm25, ymm2, 51
        vpandq	ymm2, ymm2, ymm28
        vpsrlq	ymm26, ymm3, 51
        vpandq	ymm3, ymm3, ymm28
        vpsrlq	ymm27, ymm4, 51
        vpandq	ymm4, ymm4, ymm28
        vmovdqa64	ymm18, ymm0
        vpmadd52luq	ymm18, ymm27, ymm31
        vpaddq	ymm19, ymm1, ymm23
        vpaddq	ymm20, ymm2, ymm24
        vpaddq	ymm21, ymm3, ymm25
        vpaddq	ymm22, ymm4, ymm26
        ; [x2, z2, x3, z3] = [AA.BB, E.H, FF, x1.T]
        vmovdqu64	ymm0, YMMWORD PTR [rsp+320]
        vmovdqu64	ymm1, YMMWORD PTR [rsp+352]
        vmovdqu64	ymm2, YMMWORD PTR [rsp+384]
        vmovdqu64	ymm3, YMMWORD PTR [rsp+416]
        vmovdqu64	ymm4, YMMWORD PTR [rsp+448]
        vmovdqa64	ymm18{k2}, ymm0
        vmovdqa64	ymm19{k2}, ymm1
        vmovdqa64	ymm20{k2}, ymm2
        vmovdqa64	ymm21{k2}, ymm3
        vmovdqa64	ymm22{k2}, ymm4
        mov	rdx, QWORD PTR [rsp+704]
        dec	rdx
        jge	L_curve25519_base_avx512_ifma_dq_bits
        vmovdqu64	YMMWORD PTR [rsp+480], ymm18
        vmovdqu64	YMMWORD PTR [rsp+512], ymm19
        vmovdqu64	YMMWORD PTR [rsp+544], ymm20
        vmovdqu64	YMMWORD PTR [rsp+576], ymm21
        vmovdqu64	YMMWORD PTR [rsp+608], ymm22
        vzeroupper
        ; Convert to 4 x 64-bit field elements
        mov	r13, 2251799813685247
        mov	rdx, QWORD PTR [rsp+480]
        mov	rax, QWORD PTR [rsp+512]
        mov	r8, QWORD PTR [rsp+544]
        mov	r9, QWORD PTR [rsp+576]
        mov	r10, QWORD PTR [rsp+608]
        mov	r11, rdx
        shr	r11, 51
        and	rdx, r13
        add	rax, r11
        mov	r11, rax
        shr	r11, 51
        and	rax, r13
        add	r8, r11
        mov	r11, r8
        shr	r11, 51
        and	r8, r13
        add	r9, r11
        mov	r11, r9
        shr	r11, 51
        and	r9, r13
        add	r10, r11
        mov	r11, r10
        shr	r11, 51
        and	r10, r13
        imul	r11, r11, 19
        add	rdx, r11
        mov	r11, rax
        shl	r11, 51
        mov	r12, rax
        shr	r12, 13
        add	rdx, r11
        adc	r12, 0
        mov	QWORD PTR [rsp+640], rdx
        mov	r11, r8
        shl	r11, 38
        mov	rdx, r8
        shr	rdx, 26
        add	r12, r11
        adc	rdx, 0
        mov	QWORD PTR [rsp+648], r12
        mov	r11, r9
        shl	r11, 25
        mov	r12, r9
        shr	r12, 39
        add	rdx, r11
        adc	r12, 0
        mov	QWORD PTR [rsp+656], rdx
        mov	r11, r10
        shl	r11, 12
        add	r12, r11
        mov	QWORD PTR [rsp+664], r12
        mov	rdx, QWORD PTR [rsp+488]
        mov	rax, QWORD PTR [rsp+520]
        mov	r8, QWORD PTR [rsp+552]
        mov	r9, QWORD PTR [rsp+584]
        mov	r10, QWORD PTR [rsp+616]
        mov	r11, rdx
        shr	r11, 51
        and	rdx, r13
        add	rax, r11
        mov	r11, rax
        shr	r11, 51
        and	rax, r13
        add	r8, r11
        mov	r11, r8
        shr	r11, 51
        and	r8, r13
        add	r9, r11
        mov	r11, r9
        shr	r11, 51
        and	r9, r13
        add	r10, r11
        mov	r11, r10
        shr	r11, 51
        and	r10, r13
        imul	r11, r11, 19
        add	rdx, r11
        mov	r11, rax
        shl	r11, 51
        mov	r12, rax
        shr	r12, 13
        add	rdx, r11
        adc	r12, 0
        mov	QWORD PTR [rsp+672], rdx
        mov	r11, r8
        shl	r11, 38
        mov	rdx, r8
        shr	rdx, 26
        add	r12, r11
        adc	rdx, 0
        mov	QWORD PTR [rsp+680], r12
        mov	r11, r9
        shl	r11, 25
        mov	r12, r9
        shr	r12, 39
        add	rdx, r11
        adc	r12, 0
        mov	QWORD PTR [rsp+688], rdx
        mov	r11, r10
        shl	r11, 12
        add	r12, r11
        mov	QWORD PTR [rsp+696], r12
        ; z2 = 1 / z2
        lea	rcx, QWORD PTR [rsp+672]
        lea	rdx, QWORD PTR [rsp+672]
        sub	rsp, 32
        call	fe_invert_avx2
        add	rsp, 32
        ; x2 = x2 * z2
        lea	rcx, QWORD PTR [rsp+640]
        lea	rdx, QWORD PTR [rsp+640]
        lea	r8, QWORD PTR [rsp+672]
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        ; Store fully reduced result
        mov	rcx, QWORD PTR [rsp+712]
        lea	rdx, QWORD PTR [rsp+640]
        sub	rsp, 32
        call	fe_tobytes
        add	rsp, 32
        xor	rax, rax
        vmovdqu	xmm6, OWORD PTR [rsp+736]
        vmovdqu	xmm7, OWORD PTR [rsp+752]
        vmovdqu	xmm8, OWORD PTR [rsp+768]
        vmovdqu	xmm9, OWORD PTR [rsp+784]
        vmovdqu	xmm10, OWORD PTR [rsp+800]
        vmovdqu	xmm11, OWORD PTR [rsp+816]
        vmovdqu	xmm12, OWORD PTR [rsp+832]
        vmovdqu	xmm13, OWORD PTR [rsp+848]
        vmovdqu	xmm14, OWORD PTR [rsp+864]
        vmovdqu	xmm15, OWORD PTR [rsp+880]
        add	rsp, 896
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
curve25519_base_avx512_ifma_dq ENDP
_TEXT ENDS
ENDIF
_TEXT SEGMENT READONLY PARA
curve25519_avx512_ifma_dq PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        mov	r15, rcx
        mov	rdi, rdx
        mov	rsi, r8
        sub	rsp, 904
        vmovdqu	OWORD PTR [rsp+744], xmm6
        vmovdqu	OWORD PTR [rsp+760], xmm7
        vmovdqu	OWORD PTR [rsp+776], xmm8
        vmovdqu	OWORD PTR [rsp+792], xmm9
        vmovdqu	OWORD PTR [rsp+808], xmm10
        vmovdqu	OWORD PTR [rsp+824], xmm11
        vmovdqu	OWORD PTR [rsp+840], xmm12
        vmovdqu	OWORD PTR [rsp+856], xmm13
        vmovdqu	OWORD PTR [rsp+872], xmm14
        vmovdqu	OWORD PTR [rsp+888], xmm15
        mov	QWORD PTR [rsp+712], r15
        mov	r13, 2251799813685247
        mov	rdx, QWORD PTR [rsi]
        mov	rax, QWORD PTR [rsi+8]
        mov	r8, QWORD PTR [rsi+16]
        mov	r9, QWORD PTR [rsi+24]
        mov	r10, r9
        shr	r10, 63
        imul	r10, r10, 19
        shl	r9, 1
        shr	r9, 1
        mov	r12, rdx
        and	r12, r13
        add	r12, r10
        mov	QWORD PTR [rsp], r12
        mov	QWORD PTR [rsp+8], r12
        mov	QWORD PTR [rsp+16], r12
        mov	QWORD PTR [rsp+24], r12
        mov	QWORD PTR [rsp+480], 1
        mov	QWORD PTR [rsp+488], 0
        mov	QWORD PTR [rsp+496], r12
        mov	QWORD PTR [rsp+504], 1
        shrd	rdx, rax, 51
        mov	r10, rdx
        and	r10, r13
        mov	QWORD PTR [rsp+32], r10
        mov	QWORD PTR [rsp+40], r10
        mov	QWORD PTR [rsp+48], r10
        mov	QWORD PTR [rsp+56], r10
        mov	QWORD PTR [rsp+512], 0
        mov	QWORD PTR [rsp+520], 0
        mov	QWORD PTR [rsp+528], r10
        mov	QWORD PTR [rsp+536], 0
        shrd	rax, r8, 38
        mov	r10, rax
        and	r10, r13
        mov	QWORD PTR [rsp+64], r10
        mov	QWORD PTR [rsp+72], r10
        mov	QWORD PTR [rsp+80], r10
        mov	QWORD PTR [rsp+88], r10
        mov	QWORD PTR [rsp+544], 0
        mov	QWORD PTR [rsp+552], 0
        mov	QWORD PTR [rsp+560], r10
        mov	QWORD PTR [rsp+568], 0
        shrd	r8, r9, 25
        mov	r10, r8
        and	r10, r13
        mov	QWORD PTR [rsp+96], r10
        mov	QWORD PTR [rsp+104], r10
        mov	QWORD PTR [rsp+112], r10
        mov	QWORD PTR [rsp+120], r10
        mov	QWORD PTR [rsp+576], 0
        mov	QWORD PTR [rsp+584], 0
        mov	QWORD PTR [rsp+592], r10
        mov	QWORD PTR [rsp+600], 0
        shr	r9, 12
        mov	QWORD PTR [rsp+128], r9
        mov	QWORD PTR [rsp+136], r9
        mov	QWORD PTR [rsp+144], r9
        mov	QWORD PTR [rsp+152], r9
        mov	QWORD PTR [rsp+608], 0
        mov	QWORD PTR [rsp+616], 0
        mov	QWORD PTR [rsp+624], r9
        mov	QWORD PTR [rsp+632], 0
        mov	r11, QWORD PTR [ptr_L_x25519_ifma_consts]
        vpbroadcastq	ymm28, QWORD PTR [r11]
        vpbroadcastq	ymm29, QWORD PTR [r11+8]
        vpbroadcastq	ymm30, QWORD PTR [r11+16]
        vpbroadcastq	ymm31, QWORD PTR [r11+24]
        mov	r10d, 10
        kmovw	k1, r10d
        mov	r10d, 5
        kmovw	k2, r10d
        mov	r10d, 4
        kmovw	k3, r10d
        mov	r10d, 8
        kmovw	k4, r10d
        mov	r10d, 2
        kmovw	k5, r10d
        mov	r10d, 6
        kmovw	k7, r10d
        vmovdqu64	ymm18, YMMWORD PTR [rsp+480]
        vmovdqu64	ymm19, YMMWORD PTR [rsp+512]
        vmovdqu64	ymm20, YMMWORD PTR [rsp+544]
        vmovdqu64	ymm21, YMMWORD PTR [rsp+576]
        vmovdqu64	ymm22, YMMWORD PTR [rsp+608]
        mov	r8, 0
        mov	rdx, 254
L_curve25519_avx512_ifma_dq_bits:
        ; Conditionally swap (x2, z2) with (x3, z3)
        mov	QWORD PTR [rsp+704], rdx
        mov	rcx, rdx
        and	rcx, 63
        shr	rdx, 6
        mov	rax, QWORD PTR [rdi+8*rdx]
        shr	rax, cl
        and	rax, 1
        mov	r9, rax
        xor	r8, rax
        neg	r8
        and	r8, 15
        kmovw	k6, r8d
        mov	r8, r9
        vpermq	ymm18{k6}, ymm18, 78
        vpermq	ymm19{k6}, ymm19, 78
        vpermq	ymm20{k6}, ymm20, 78
        vpermq	ymm21{k6}, ymm21, 78
        vpermq	ymm22{k6}, ymm22, 78
        ; A = x2 + z2, B = x2 - z2, C = x3 + z3, D = x3 - z3
        vpermq	ymm0, ymm18, 177
        vpermq	ymm1, ymm19, 177
        vpermq	ymm2, ymm20, 177
        vpermq	ymm3, ymm21, 177
        vpermq	ymm4, ymm22, 177
        vpaddq	ymm23, ymm0, ymm18
        vpaddq	ymm24, ymm1, ymm19
        vpaddq	ymm25, ymm2, ymm20
        vpaddq	ymm26, ymm3, ymm21
        vpaddq	ymm27, ymm4, ymm22
        vpaddq	ymm0{k1}, ymm0, ymm29
        vpaddq	ymm1{k1}, ymm1, ymm30
        vpaddq	ymm2{k1}, ymm2, ymm30
        vpaddq	ymm3{k1}, ymm3, ymm30
        vpaddq	ymm4{k1}, ymm4, ymm30
        vpsubq	ymm23{k1}, ymm0, ymm18
        vpsubq	ymm24{k1}, ymm1, ymm19
        vpsubq	ymm25{k1}, ymm2, ymm20
        vpsubq	ymm26{k1}, ymm3, ymm21
        vpsubq	ymm27{k1}, ymm4, ymm22
        vpsrlq	ymm5, ymm23, 51
        vpandq	ymm23, ymm23, ymm28
        vpsrlq	ymm6, ymm24, 51
        vpandq	ymm24, ymm24, ymm28
        vpsrlq	ymm7, ymm25, 51
        vpandq	ymm25, ymm25, ymm28
        vpsrlq	ymm8, ymm26, 51
        vpandq	ymm26, ymm26, ymm28
        vpsrlq	ymm9, ymm27, 51
        vpandq	ymm27, ymm27, ymm28
        vpmadd52luq	ymm23, ymm9, ymm31
        vpaddq	ymm24, ymm24, ymm5
        vpaddq	ymm25, ymm25, ymm6
        vpaddq	ymm26, ymm26, ymm7
        vpaddq	ymm27, ymm27, ymm8
        ; [AA, BB, CB, DA] = [A, B, C, D] * [A, B, B, A]
        vpermq	ymm18, ymm23, 20
        vpermq	ymm19, ymm24, 20
        vpermq	ymm20, ymm25, 20
        vpermq	ymm21, ymm26, 20
        vpermq	ymm22, ymm27, 20
        ; Multiply 4 field elements
        vpxorq	ymm0, ymm0, ymm0
        vpxorq	ymm9, ymm9, ymm9
        vpxorq	ymm1, ymm1, ymm1
        vpxorq	ymm10, ymm10, ymm10
        vpxorq	ymm2, ymm2, ymm2
        vpxorq	ymm11, ymm11, ymm11
        vpxorq	ymm3, ymm3, ymm3
        vpxorq	ymm12, ymm12, ymm12
        vpxorq	ymm4, ymm4, ymm4
        vpxorq	ymm13, ymm13, ymm13
        vpxorq	ymm5, ymm5, ymm5
        vpxorq	ymm14, ymm14, ymm14
        vpxorq	ymm6, ymm6, ymm6
        vpxorq	ymm15, ymm15, ymm15
        vpxorq	ymm7, ymm7, ymm7
        vpxorq	ymm16, ymm16, ymm16
        vpxorq	ymm8, ymm8, ymm8
        vpxorq	ymm17, ymm17, ymm17
        vpmadd52luq	ymm0, ymm18, ymm23
        vpmadd52huq	ymm9, ymm18, ymm23
        vpmadd52luq	ymm1, ymm18, ymm24
        vpmadd52huq	ymm10, ymm18, ymm24
        vpmadd52luq	ymm2, ymm18, ymm25
        vpmadd52huq	ymm11, ymm18, ymm25
        vpmadd52luq	ymm3, ymm18, ymm26
        vpmadd52huq	ymm12, ymm18, ymm26
        vpmadd52luq	ymm4, ymm18, ymm27
        vpmadd52huq	ymm13, ymm18, ymm27
        vpmadd52luq	ymm1, ymm19, ymm23
        vpmadd52huq	ymm10, ymm19, ymm23
        vpmadd52luq	ymm2, ymm19, ymm24
        vpmadd52huq	ymm11, ymm19, ymm24
        vpmadd52luq	ymm3, ymm19, ymm25
        vpmadd52huq	ymm12, ymm19, ymm25
        vpmadd52luq	ymm4, ymm19, ymm26
        vpmadd52huq	ymm13, ymm19, ymm26
        vpmadd52luq	ymm5, ymm19, ymm27
        vpmadd52huq	ymm14, ymm19, ymm27
        vpmadd52luq	ymm2, ymm20, ymm23
        vpmadd52huq	ymm11, ymm20, ymm23
        vpmadd52luq	ymm3, ymm20, ymm24
        vpmadd52huq	ymm12, ymm20, ymm24
        vpmadd52luq	ymm4, ymm20, ymm25
        vpmadd52huq	ymm13, ymm20, ymm25
        vpmadd52luq	ymm5, ymm20, ymm26
        vpmadd52huq	ymm14, ymm20, ymm26
        vpmadd52luq	ymm6, ymm20, ymm27
        vpmadd52huq	ymm15, ymm20, ymm27
        vpmadd52luq	ymm3, ymm21, ymm23
        vpmadd52huq	ymm12, ymm21, ymm23
        vpmadd52luq	ymm4, ymm21, ymm24
        vpmadd52huq	ymm13, ymm21, ymm24
        vpmadd52luq	ymm5, ymm21, ymm25
        vpmadd52huq	ymm14, ymm21, ymm25
        vpmadd52luq	ymm6, ymm21, ymm26
        vpmadd52huq	ymm15, ymm21, ymm26
        vpmadd52luq	ymm7, ymm21, ymm27
        vpmadd52huq	ymm16, ymm21, ymm27
        vpmadd52luq	ymm4, ymm22, ymm23
        vpmadd52huq	ymm13, ymm22, ymm23
        vpmadd52luq	ymm5, ymm22, ymm24
        vpmadd52huq	ymm14, ymm22, ymm24
        vpmadd52luq	ymm6, ymm22, ymm25
        vpmadd52huq	ymm15, ymm22, ymm25
        vpmadd52luq	ymm7, ymm22, ymm26
        vpmadd52huq	ymm16, ymm22, ymm26
        vpmadd52luq	ymm8, ymm22, ymm27
        vpmadd52huq	ymm17, ymm22, ymm27
        vpaddq	ymm9, ymm9, ymm9
        vpaddq	ymm1, ymm1, ymm9
        vpaddq	ymm10, ymm10, ymm10
        vpaddq	ymm2, ymm2, ymm10
        vpaddq	ymm11, ymm11, ymm11
        vpaddq	ymm3, ymm3, ymm11
        vpaddq	ymm12, ymm12, ymm12
        vpaddq	ymm4, ymm4, ymm12
        vpaddq	ymm13, ymm13, ymm13
        vpaddq	ymm5, ymm5, ymm13
        vpaddq	ymm14, ymm14, ymm14
        vpaddq	ymm6, ymm6, ymm14
        vpaddq	ymm15, ymm15, ymm15
        vpaddq	ymm7, ymm7, ymm15
        vpaddq	ymm16, ymm16, ymm16
        vpaddq	ymm8, ymm8, ymm16
        vpaddq	ymm17, ymm17, ymm17
        ; Reduce
        vpmullq	ymm9, ymm5, ymm31
        vpaddq	ymm0, ymm0, ymm9
        vpmullq	ymm9, ymm6, ymm31
        vpaddq	ymm1, ymm1, ymm9
        vpmullq	ymm9, ymm7, ymm31
        vpaddq	ymm2, ymm2, ymm9
        vpmullq	ymm9, ymm8, ymm31
        vpaddq	ymm3, ymm3, ymm9
        vpmullq	ymm9, ymm17, ymm31
        vpaddq	ymm4, ymm4, ymm9
        vpsrlq	ymm23, ymm0, 51
        vpandq	ymm0, ymm0, ymm28
        vpsrlq	ymm24, ymm1, 51
        vpandq	ymm1, ymm1, ymm28
        vpsrlq	ymm25, ymm2, 51
        vpandq	ymm2, ymm2, ymm28
        vpsrlq	ymm26, ymm3, 51
        vpandq	ymm3, ymm3, ymm28
        vpsrlq	ymm27, ymm4, 51
        vpandq	ymm4, ymm4, ymm28
        vmovdqa64	ymm18, ymm0
        vpmadd52luq	ymm18, ymm27, ymm31
        vpaddq	ymm19, ymm1, ymm23
        vpaddq	ymm20, ymm2, ymm24
        vpaddq	ymm21, ymm3, ymm25
        vpaddq	ymm22, ymm4, ymm26
        ; U = [AA, DA-CB, DA+CB, AA-BB], V = [BB, DA-CB, DA+CB, a24]
        vpermq	ymm23, ymm18, 105
        vpermq	ymm24, ymm19, 105
        vpermq	ymm25, ymm20, 105
        vpermq	ymm26, ymm21, 105
        vpermq	ymm27, ymm22, 105
        vpermq	ymm18, ymm18, 60
        vpermq	ymm19, ymm19, 60
        vpermq	ymm20, ymm20, 60
        vpermq	ymm21, ymm21, 60
        vpermq	ymm22, ymm22, 60
        vpaddq	ymm18{k3}, ymm18, ymm23
        vpaddq	ymm19{k3}, ymm19, ymm24
        vpaddq	ymm20{k3}, ymm20, ymm25
        vpaddq	ymm21{k3}, ymm21, ymm26
        vpaddq	ymm22{k3}, ymm22, ymm27
        vpaddq	ymm18{k1}, ymm18, ymm29
        vpaddq	ymm19{k1}, ymm19, ymm30
        vpaddq	ymm20{k1}, ymm20, ymm30
        vpaddq	ymm21{k1}, ymm21, ymm30
        vpaddq	ymm22{k1}, ymm22, ymm30
        vpsubq	ymm18{k1}, ymm18, ymm23
        vpsubq	ymm19{k1}, ymm19, ymm24
        vpsubq	ymm20{k1}, ymm20, ymm25
        vpsubq	ymm21{k1}, ymm21, ymm26
        vpsubq	ymm22{k1}, ymm22, ymm27
        vpsrlq	ymm0, ymm18, 51
        vpandq	ymm18, ymm18, ymm28
        vpsrlq	ymm1, ymm19, 51
        vpandq	ymm19, ymm19, ymm28
        vpsrlq	ymm2, ymm20, 51
        vpandq	ymm20, ymm20, ymm28
        vpsrlq	ymm3, ymm21, 51
        vpandq	ymm21, ymm21, ymm28
        vpsrlq	ymm4, ymm22, 51
        vpandq	ymm22, ymm22, ymm28
        vpmadd52luq	ymm18, ymm4, ymm31
        vpaddq	ymm19, ymm19, ymm0
        vpaddq	ymm20, ymm20, ymm1
        vpaddq	ymm21, ymm21, ymm2
        vpaddq	ymm22, ymm22, ymm3
        vmovdqu64	YMMWORD PTR [rsp+160], ymm18
        vmovdqu64	YMMWORD PTR [rsp+192], ymm19
        vmovdqu64	YMMWORD PTR [rsp+224], ymm20
        vmovdqu64	YMMWORD PTR [rsp+256], ymm21
        vmovdqu64	YMMWORD PTR [rsp+288], ymm22
        vmovdqa64	ymm23{k7}, ymm18
        vmovdqa64	ymm24{k7}, ymm19
        vmovdqa64	ymm25{k7}, ymm20
        vmovdqa64	ymm26{k7}, ymm21
        vmovdqa64	ymm27{k7}, ymm22
        vpbroadcastq	ymm23{k4}, QWORD PTR [r11+32]
        vpxorq	ymm24{k4}, ymm24, ymm24
        vpxorq	ymm25{k4}, ymm25, ymm25
        vpxorq	ymm26{k4}, ymm26, ymm26
        vpxorq	ymm27{k4}, ymm27, ymm27
        ; [AA.BB, GG, FF, a24.E] = U * V
        ; Multiply 4 field elements
        vpxorq	ymm0, ymm0, ymm0
        vpxorq	ymm9, ymm9, ymm9
        vpxorq	ymm1, ymm1, ymm1
        vpxorq	ymm10, ymm10, ymm10
        vpxorq	ymm2, ymm2, ymm2
        vpxorq	ymm11, ymm11, ymm11
        vpxorq	ymm3, ymm3, ymm3
        vpxorq	ymm12, ymm12, ymm12
        vpxorq	ymm4, ymm4, ymm4
        vpxorq	ymm13, ymm13, ymm13
        vpxorq	ymm5, ymm5, ymm5
        vpxorq	ymm14, ymm14, ymm14
        vpxorq	ymm6, ymm6, ymm6
        vpxorq	ymm15, ymm15, ymm15
        vpxorq	ymm7, ymm7, ymm7
        vpxorq	ymm16, ymm16, ymm16
        vpxorq	ymm8, ymm8, ymm8
        vpxorq	ymm17, ymm17, ymm17
        vpmadd52luq	ymm0, ymm18, ymm23
        vpmadd52huq	ymm9, ymm18, ymm23
        vpmadd52luq	ymm1, ymm18, ymm24
        vpmadd52huq	ymm10, ymm18, ymm24
        vpmadd52luq	ymm2, ymm18, ymm25
        vpmadd52huq	ymm11, ymm18, ymm25
        vpmadd52luq	ymm3, ymm18, ymm26
        vpmadd52huq	ymm12, ymm18, ymm26
        vpmadd52luq	ymm4, ymm18, ymm27
        vpmadd52huq	ymm13, ymm18, ymm27
        vpmadd52luq	ymm1, ymm19, ymm23
        vpmadd52huq	ymm10, ymm19, ymm23
        vpmadd52luq	ymm2, ymm19, ymm24
        vpmadd52huq	ymm11, ymm19, ymm24
        vpmadd52luq	ymm3, ymm19, ymm25
        vpmadd52huq	ymm12, ymm19, ymm25
        vpmadd52luq	ymm4, ymm19, ymm26
        vpmadd52huq	ymm13, ymm19, ymm26
        vpmadd52luq	ymm5, ymm19, ymm27
        vpmadd52huq	ymm14, ymm19, ymm27
        vpmadd52luq	ymm2, ymm20, ymm23
        vpmadd52huq	ymm11, ymm20, ymm23
        vpmadd52luq	ymm3, ymm20, ymm24
        vpmadd52huq	ymm12, ymm20, ymm24
        vpmadd52luq	ymm4, ymm20, ymm25
        vpmadd52huq	ymm13, ymm20, ymm25
        vpmadd52luq	ymm5, ymm20, ymm26
        vpmadd52huq	ymm14, ymm20, ymm26
        vpmadd52luq	ymm6, ymm20, ymm27
        vpmadd52huq	ymm15, ymm20, ymm27
        vpmadd52luq	ymm3, ymm21, ymm23
        vpmadd52huq	ymm12, ymm21, ymm23
        vpmadd52luq	ymm4, ymm21, ymm24
        vpmadd52huq	ymm13, ymm21, ymm24
        vpmadd52luq	ymm5, ymm21, ymm25
        vpmadd52huq	ymm14, ymm21, ymm25
        vpmadd52luq	ymm6, ymm21, ymm26
        vpmadd52huq	ymm15, ymm21, ymm26
        vpmadd52luq	ymm7, ymm21, ymm27
        vpmadd52huq	ymm16, ymm21, ymm27
        vpmadd52luq	ymm4, ymm22, ymm23
        vpmadd52huq	ymm13, ymm22, ymm23
        vpmadd52luq	ymm5, ymm22, ymm24
        vpmadd52huq	ymm14, ymm22, ymm24
        vpmadd52luq	ymm6, ymm22, ymm25
        vpmadd52huq	ymm15, ymm22, ymm25
        vpmadd52luq	ymm7, ymm22, ymm26
        vpmadd52huq	ymm16, ymm22, ymm26
        vpmadd52luq	ymm8, ymm22, ymm27
        vpmadd52huq	ymm17, ymm22, ymm27
        vpaddq	ymm9, ymm9, ymm9
        vpaddq	ymm1, ymm1, ymm9
        vpaddq	ymm10, ymm10, ymm10
        vpaddq	ymm2, ymm2, ymm10
        vpaddq	ymm11, ymm11, ymm11
        vpaddq	ymm3, ymm3, ymm11
        vpaddq	ymm12, ymm12, ymm12
        vpaddq	ymm4, ymm4, ymm12
        vpaddq	ymm13, ymm13, ymm13
        vpaddq	ymm5, ymm5, ymm13
        vpaddq	ymm14, ymm14, ymm14
        vpaddq	ymm6, ymm6, ymm14
        vpaddq	ymm15, ymm15, ymm15
        vpaddq	ymm7, ymm7, ymm15
        vpaddq	ymm16, ymm16, ymm16
        vpaddq	ymm8, ymm8, ymm16
        vpaddq	ymm17, ymm17, ymm17
        ; Reduce
        vpmullq	ymm9, ymm5, ymm31
        vpaddq	ymm0, ymm0, ymm9
        vpmullq	ymm9, ymm6, ymm31
        vpaddq	ymm1, ymm1, ymm9
        vpmullq	ymm9, ymm7, ymm31
        vpaddq	ymm2, ymm2, ymm9
        vpmullq	ymm9, ymm8, ymm31
        vpaddq	ymm3, ymm3, ymm9
        vpmullq	ymm9, ymm17, ymm31
        vpaddq	ymm4, ymm4, ymm9
        vpsrlq	ymm23, ymm0, 51
        vpandq	ymm0, ymm0, ymm28
        vpsrlq	ymm24, ymm1, 51
        vpandq	ymm1, ymm1, ymm28
        vpsrlq	ymm25, ymm2, 51
        vpandq	ymm2, ymm2, ymm28
        vpsrlq	ymm26, ymm3, 51
        vpandq	ymm3, ymm3, ymm28
        vpsrlq	ymm27, ymm4, 51
        vpandq	ymm4, ymm4, ymm28
        vmovdqa64	ymm18, ymm0
        vpmadd52luq	ymm18, ymm27, ymm31
        vpaddq	ymm19, ymm1, ymm23
        vpaddq	ymm20, ymm2, ymm24
        vpaddq	ymm21, ymm3, ymm25
        vpaddq	ymm22, ymm4, ymm26
        ; U3 = [E, E, E, x1], V3 = [aE, AA + a24.E, T, T]
        vpermq	ymm23, ymm18, 95
        vpermq	ymm24, ymm19, 95
        vpermq	ymm25, ymm20, 95
        vpermq	ymm26, ymm21, 95
        vpermq	ymm27, ymm22, 95
        vmovdqu64	YMMWORD PTR [rsp+320], ymm18
        vmovdqu64	YMMWORD PTR [rsp+352], ymm19
        vmovdqu64	YMMWORD PTR [rsp+384], ymm20
        vmovdqu64	YMMWORD PTR [rsp+416], ymm21
        vmovdqu64	YMMWORD PTR [rsp+448], ymm22
        vpbroadcastq	ymm5, QWORD PTR [rsp+160]
        vpbroadcastq	ymm6, QWORD PTR [rsp+192]
        vpbroadcastq	ymm7, QWORD PTR [rsp+224]
        vpbroadcastq	ymm8, QWORD PTR [rsp+256]
        vpbroadcastq	ymm9, QWORD PTR [rsp+288]
        vpaddq	ymm23{k5}, ymm23, ymm5
        vpaddq	ymm24{k5}, ymm24, ymm6
        vpaddq	ymm25{k5}, ymm25, ymm7
        vpaddq	ymm26{k5}, ymm26, ymm8
        vpaddq	ymm27{k5}, ymm27, ymm9
        vpsrlq	ymm10, ymm23, 51
        vpandq	ymm23, ymm23, ymm28
        vpsrlq	ymm11, ymm24, 51
        vpandq	ymm24, ymm24, ymm28
        vpsrlq	ymm12, ymm25, 51
        vpandq	ymm25, ymm25, ymm28
        vpsrlq	ymm13, ymm26, 51
        vpandq	ymm26, ymm26, ymm28
        vpsrlq	ymm14, ymm27, 51
        vpandq	ymm27, ymm27, ymm28
        vpmadd52luq	ymm23, ymm14, ymm31
        vpaddq	ymm24, ymm24, ymm10
        vpaddq	ymm25, ymm25, ymm11
        vpaddq	ymm26, ymm26, ymm12
        vpaddq	ymm27, ymm27, ymm13
        vpbroadcastq	ymm18, QWORD PTR [rsp+184]
        vpbroadcastq	ymm19, QWORD PTR [rsp+216]
        vpbroadcastq	ymm20, QWORD PTR [rsp+248]
        vpbroadcastq	ymm21, QWORD PTR [rsp+280]
        vpbroadcastq	ymm22, QWORD PTR [rsp+312]
        vmovdqu64	ymm18{k4}, YMMWORD PTR [rsp]
        vmovdqu64	ymm19{k4}, YMMWORD PTR [rsp+32]
        vmovdqu64	ymm20{k4}, YMMWORD PTR [rsp+64]
        vmovdqu64	ymm21{k4}, YMMWORD PTR [rsp+96]
        vmovdqu64	ymm22{k4}, YMMWORD PTR [rsp+128]
        ; [-, E.H, -, x1.T] = U3 * V3
        ; Multiply 4 field elements
        vpxorq	ymm0, ymm0, ymm0
        vpxorq	ymm9, ymm9, ymm9
        vpxorq	ymm1, ymm1, ymm1
        vpxorq	ymm10, ymm10, ymm10
        vpxorq	ymm2, ymm2, ymm2
        vpxorq	ymm11, ymm11, ymm11
        vpxorq	ymm3, ymm3, ymm3
        vpxorq	ymm12, ymm12, ymm12
        vpxorq	ymm4, ymm4, ymm4
        vpxorq	ymm13, ymm13, ymm13
        vpxorq	ymm5, ymm5, ymm5
        vpxorq	ymm14, ymm14, ymm14
        vpxorq	ymm6, ymm6, ymm6
        vpxorq	ymm15, ymm15, ymm15
        vpxorq	ymm7, ymm7, ymm7
        vpxorq	ymm16, ymm16, ymm16
        vpxorq	ymm8, ymm8, ymm8
        vpxorq	ymm17, ymm17, ymm17
        vpmadd52luq	ymm0, ymm18, ymm23
        vpmadd52huq	ymm9, ymm18, ymm23
        vpmadd52luq	ymm1, ymm18, ymm24
        vpmadd52huq	ymm10, ymm18, ymm24
        vpmadd52luq	ymm2, ymm18, ymm25
        vpmadd52huq	ymm11, ymm18, ymm25
        vpmadd52luq	ymm3, ymm18, ymm26
        vpmadd52huq	ymm12, ymm18, ymm26
        vpmadd52luq	ymm4, ymm18, ymm27
        vpmadd52huq	ymm13, ymm18, ymm27
        vpmadd52luq	ymm1, ymm19, ymm23
        vpmadd52huq	ymm10, ymm19, ymm23
        vpmadd52luq	ymm2, ymm19, ymm24
        vpmadd52huq	ymm11, ymm19, ymm24
        vpmadd52luq	ymm3, ymm19, ymm25
        vpmadd52huq	ymm12, ymm19, ymm25
        vpmadd52luq	ymm4, ymm19, ymm26
        vpmadd52huq	ymm13, ymm19, ymm26
        vpmadd52luq	ymm5, ymm19, ymm27
        vpmadd52huq	ymm14, ymm19, ymm27
        vpmadd52luq	ymm2, ymm20, ymm23
        vpmadd52huq	ymm11, ymm20, ymm23
        vpmadd52luq	ymm3, ymm20, ymm24
        vpmadd52huq	ymm12, ymm20, ymm24
        vpmadd52luq	ymm4, ymm20, ymm25
        vpmadd52huq	ymm13, ymm20, ymm25
        vpmadd52luq	ymm5, ymm20, ymm26
        vpmadd52huq	ymm14, ymm20, ymm26
        vpmadd52luq	ymm6, ymm20, ymm27
        vpmadd52huq	ymm15, ymm20, ymm27
        vpmadd52luq	ymm3, ymm21, ymm23
        vpmadd52huq	ymm12, ymm21, ymm23
        vpmadd52luq	ymm4, ymm21, ymm24
        vpmadd52huq	ymm13, ymm21, ymm24
        vpmadd52luq	ymm5, ymm21, ymm25
        vpmadd52huq	ymm14, ymm21, ymm25
        vpmadd52luq	ymm6, ymm21, ymm26
        vpmadd52huq	ymm15, ymm21, ymm26
        vpmadd52luq	ymm7, ymm21, ymm27
        vpmadd52huq	ymm16, ymm21, ymm27
        vpmadd52luq	ymm4, ymm22, ymm23
        vpmadd52huq	ymm13, ymm22, ymm23
        vpmadd52luq	ymm5, ymm22, ymm24
        vpmadd52huq	ymm14, ymm22, ymm24
        vpmadd52luq	ymm6, ymm22, ymm25
        vpmadd52huq	ymm15, ymm22, ymm25
        vpmadd52luq	ymm7, ymm22, ymm26
        vpmadd52huq	ymm16, ymm22, ymm26
        vpmadd52luq	ymm8, ymm22, ymm27
        vpmadd52huq	ymm17, ymm22, ymm27
        vpaddq	ymm9, ymm9, ymm9
        vpaddq	ymm1, ymm1, ymm9
        vpaddq	ymm10, ymm10, ymm10
        vpaddq	ymm2, ymm2, ymm10
        vpaddq	ymm11, ymm11, ymm11
        vpaddq	ymm3, ymm3, ymm11
        vpaddq	ymm12, ymm12, ymm12
        vpaddq	ymm4, ymm4, ymm12
        vpaddq	ymm13, ymm13, ymm13
        vpaddq	ymm5, ymm5, ymm13
        vpaddq	ymm14, ymm14, ymm14
        vpaddq	ymm6, ymm6, ymm14
        vpaddq	ymm15, ymm15, ymm15
        vpaddq	ymm7, ymm7, ymm15
        vpaddq	ymm16, ymm16, ymm16
        vpaddq	ymm8, ymm8, ymm16
        vpaddq	ymm17, ymm17, ymm17
        ; Reduce
        vpmullq	ymm9, ymm5, ymm31
        vpaddq	ymm0, ymm0, ymm9
        vpmullq	ymm9, ymm6, ymm31
        vpaddq	ymm1, ymm1, ymm9
        vpmullq	ymm9, ymm7, ymm31
        vpaddq	ymm2, ymm2, ymm9
        vpmullq	ymm9, ymm8, ymm31
        vpaddq	ymm3, ymm3, ymm9
        vpmullq	ymm9, ymm17, ymm31
        vpaddq	ymm4, ymm4, ymm9
        vpsrlq	ymm23, ymm0, 51
        vpandq	ymm0, ymm0, ymm28
        vpsrlq	ymm24, ymm1, 51
        vpandq	ymm1, ymm1, ymm28
        vpsrlq	ymm25, ymm2, 51
        vpandq	ymm2, ymm2, ymm28
        vpsrlq	ymm26, ymm3, 51
        vpandq	ymm3, ymm3, ymm28
        vpsrlq	ymm27, ymm4, 51
        vpandq	ymm4, ymm4, ymm28
        vmovdqa64	ymm18, ymm0
        vpmadd52luq	ymm18, ymm27, ymm31
        vpaddq	ymm19, ymm1, ymm23
        vpaddq	ymm20, ymm2, ymm24
        vpaddq	ymm21, ymm3, ymm25
        vpaddq	ymm22, ymm4, ymm26
        ; [x2, z2, x3, z3] = [AA.BB, E.H, FF, x1.T]
        vmovdqu64	ymm0, YMMWORD PTR [rsp+320]
        vmovdqu64	ymm1, YMMWORD PTR [rsp+352]
        vmovdqu64	ymm2, YMMWORD PTR [rsp+384]
        vmovdqu64	ymm3, YMMWORD PTR [rsp+416]
        vmovdqu64	ymm4, YMMWORD PTR [rsp+448]
        vmovdqa64	ymm18{k2}, ymm0
        vmovdqa64	ymm19{k2}, ymm1
        vmovdqa64	ymm20{k2}, ymm2
        vmovdqa64	ymm21{k2}, ymm3
        vmovdqa64	ymm22{k2}, ymm4
        mov	rdx, QWORD PTR [rsp+704]
        dec	rdx
        jge	L_curve25519_avx512_ifma_dq_bits
        vmovdqu64	YMMWORD PTR [rsp+480], ymm18
        vmovdqu64	YMMWORD PTR [rsp+512], ymm19
        vmovdqu64	YMMWORD PTR [rsp+544], ymm20
        vmovdqu64	YMMWORD PTR [rsp+576], ymm21
        vmovdqu64	YMMWORD PTR [rsp+608], ymm22
        vzeroupper
        ; Convert to 4 x 64-bit field elements
        mov	r13, 2251799813685247
        mov	rdx, QWORD PTR [rsp+480]
        mov	rax, QWORD PTR [rsp+512]
        mov	r8, QWORD PTR [rsp+544]
        mov	r9, QWORD PTR [rsp+576]
        mov	r10, QWORD PTR [rsp+608]
        mov	r11, rdx
        shr	r11, 51
        and	rdx, r13
        add	rax, r11
        mov	r11, rax
        shr	r11, 51
        and	rax, r13
        add	r8, r11
        mov	r11, r8
        shr	r11, 51
        and	r8, r13
        add	r9, r11
        mov	r11, r9
        shr	r11, 51
        and	r9, r13
        add	r10, r11
        mov	r11, r10
        shr	r11, 51
        and	r10, r13
        imul	r11, r11, 19
        add	rdx, r11
        mov	r11, rax
        shl	r11, 51
        mov	r12, rax
        shr	r12, 13
        add	rdx, r11
        adc	r12, 0
        mov	QWORD PTR [rsp+640], rdx
        mov	r11, r8
        shl	r11, 38
        mov	rdx, r8
        shr	rdx, 26
        add	r12, r11
        adc	rdx, 0
        mov	QWORD PTR [rsp+648], r12
        mov	r11, r9
        shl	r11, 25
        mov	r12, r9
        shr	r12, 39
        add	rdx, r11
        adc	r12, 0
        mov	QWORD PTR [rsp+656], rdx
        mov	r11, r10
        shl	r11, 12
        add	r12, r11
        mov	QWORD PTR [rsp+664], r12
        mov	rdx, QWORD PTR [rsp+488]
        mov	rax, QWORD PTR [rsp+520]
        mov	r8, QWORD PTR [rsp+552]
        mov	r9, QWORD PTR [rsp+584]
        mov	r10, QWORD PTR [rsp+616]
        mov	r11, rdx
        shr	r11, 51
        and	rdx, r13
        add	rax, r11
        mov	r11, rax
        shr	r11, 51
        and	rax, r13
        add	r8, r11
        mov	r11, r8
        shr	r11, 51
        and	r8, r13
        add	r9, r11
        mov	r11, r9
        shr	r11, 51
        and	r9, r13
        add	r10, r11
        mov	r11, r10
        shr	r11, 51
        and	r10, r13
        imul	r11, r11, 19
        add	rdx, r11
        mov	r11, rax
        shl	r11, 51
        mov	r12, rax
        shr	r12, 13
        add	rdx, r11
        adc	r12, 0
        mov	QWORD PTR [rsp+672], rdx
        mov	r11, r8
        shl	r11, 38
        mov	rdx, r8
        shr	rdx, 26
        add	r12, r11
        adc	rdx, 0
        mov	QWORD PTR [rsp+680], r12
        mov	r11, r9
        shl	r11, 25
        mov	r12, r9
        shr	r12, 39
        add	rdx, r11
        adc	r12, 0
        mov	QWORD PTR [rsp+688], rdx
        mov	r11, r10
        shl	r11, 12
        add	r12, r11
        mov	QWORD PTR [rsp+696], r12
        ; z2 = 1 / z2
        lea	rcx, QWORD PTR [rsp+672]
        lea	rdx, QWORD PTR [rsp+672]
        sub	rsp, 32
        call	fe_invert_avx2
        add	rsp, 32
        ; x2 = x2 * z2
        lea	rcx, QWORD PTR [rsp+640]
        lea	rdx, QWORD PTR [rsp+640]
        lea	r8, QWORD PTR [rsp+672]
        sub	rsp, 32
        call	fe_mul_avx2
        add	rsp, 32
        ; Store fully reduced result
        mov	rcx, QWORD PTR [rsp+712]
        lea	rdx, QWORD PTR [rsp+640]
        sub	rsp, 32
        call	fe_tobytes
        add	rsp, 32
        xor	rax, rax
        vmovdqu	xmm6, OWORD PTR [rsp+744]
        vmovdqu	xmm7, OWORD PTR [rsp+760]
        vmovdqu	xmm8, OWORD PTR [rsp+776]
        vmovdqu	xmm9, OWORD PTR [rsp+792]
        vmovdqu	xmm10, OWORD PTR [rsp+808]
        vmovdqu	xmm11, OWORD PTR [rsp+824]
        vmovdqu	xmm12, OWORD PTR [rsp+840]
        vmovdqu	xmm13, OWORD PTR [rsp+856]
        vmovdqu	xmm14, OWORD PTR [rsp+872]
        vmovdqu	xmm15, OWORD PTR [rsp+888]
        add	rsp, 904
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
curve25519_avx512_ifma_dq ENDP
_TEXT ENDS
IFDEF HAVE_ED25519
_DATA SEGMENT
ALIGN 16
L_ge_ifma_consts QWORD 0007ffffffffffffh, 000fffffffffffdah
        QWORD 000ffffffffffffeh, 0000000000000013h
        QWORD 0000000000000001h, 0000000000000001h
        QWORD 00069b9426b2f159h, 0000000000000001h
        QWORD 0000000000000000h, 0000000000000000h
        QWORD 00035050762add7ah, 0000000000000000h
        QWORD 0000000000000000h, 0000000000000000h
        QWORD 0003cf44c0038052h, 0000000000000000h
        QWORD 0000000000000000h, 0000000000000000h
        QWORD 0006738cc7407977h, 0000000000000000h
        QWORD 0000000000000000h, 0000000000000000h
        QWORD 0002406d9dc56dffh, 0000000000000000h
ptr_L_ge_ifma_consts QWORD L_ge_ifma_consts
_DATA ENDS
_TEXT SEGMENT READONLY PARA
ge_double_scalarmult_vartime_avx512_ifma PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        push	rbp
        mov	r14, rcx
        mov	r15, rdx
        mov	rdi, r8
        mov	rsi, r9
        mov	rbx, QWORD PTR [rsp+104]
        mov	rbp, QWORD PTR [rsp+112]
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
        ; Window digits of the scalar multiplying A
        ; One digit per bit of the scalar
        xor	rdx, rdx
        xor	r11, r11
L_ge_dsm_a_avx512_ifma_slide_bytes:
        movzx	rax, BYTE PTR [r15+r11]
        mov	rcx, rax
        and	rcx, 1
        mov	BYTE PTR [rbp+rdx+1920], cl
        shr	rax, 1
        inc	rdx
        mov	rcx, rax
        and	rcx, 1
        mov	BYTE PTR [rbp+rdx+1920], cl
        shr	rax, 1
        inc	rdx
        mov	rcx, rax
        and	rcx, 1
        mov	BYTE PTR [rbp+rdx+1920], cl
        shr	rax, 1
        inc	rdx
        mov	rcx, rax
        and	rcx, 1
        mov	BYTE PTR [rbp+rdx+1920], cl
        shr	rax, 1
        inc	rdx
        mov	rcx, rax
        and	rcx, 1
        mov	BYTE PTR [rbp+rdx+1920], cl
        shr	rax, 1
        inc	rdx
        mov	rcx, rax
        and	rcx, 1
        mov	BYTE PTR [rbp+rdx+1920], cl
        shr	rax, 1
        inc	rdx
        mov	rcx, rax
        and	rcx, 1
        mov	BYTE PTR [rbp+rdx+1920], cl
        shr	rax, 1
        inc	rdx
        mov	rcx, rax
        and	rcx, 1
        mov	BYTE PTR [rbp+rdx+1920], cl
        shr	rax, 1
        inc	rdx
        inc	r11
        cmp	r11, 32
        jne	L_ge_dsm_a_avx512_ifma_slide_bytes
        ; Fold each run of digits down to one odd digit
        xor	r11, r11
L_ge_dsm_a_avx512_ifma_slide_digit:
        movsx	rcx, BYTE PTR [rbp+r11+1920]
        test	rcx, rcx
        je	L_ge_dsm_a_avx512_ifma_slide_next_digit
        mov	r12, 1
L_ge_dsm_a_avx512_ifma_slide_window:
        mov	rdx, r11
        add	rdx, r12
        cmp	rdx, 256
        jge	L_ge_dsm_a_avx512_ifma_slide_next_digit
        movsx	r8, BYTE PTR [rbp+rdx+1920]
        test	r8, r8
        je	L_ge_dsm_a_avx512_ifma_slide_next_window
        ; Weight of the digit at i + b, relative to the one at i
        mov	r9, r8
        mov	r8, r12
L_ge_dsm_a_avx512_ifma_slide_shift:
        add	r9, r9
        dec	r8
        jne	L_ge_dsm_a_avx512_ifma_slide_shift
        movsx	r9, r9b
        ; Fold it in if the digit at i stays within range
        mov	r10, rcx
        add	r10, r9
        cmp	r10, 15
        jg	L_ge_dsm_a_avx512_ifma_slide_sub
        mov	rcx, r10
        mov	BYTE PTR [rbp+r11+1920], cl
        mov	BYTE PTR [rbp+rdx+1920], 0
        jmp	L_ge_dsm_a_avx512_ifma_slide_next_window
L_ge_dsm_a_avx512_ifma_slide_sub:
        mov	r10, rcx
        sub	r10, r9
        cmp	r10, -15
        jl	L_ge_dsm_a_avx512_ifma_slide_next_digit
        mov	rcx, r10
        mov	BYTE PTR [rbp+r11+1920], cl
        ; Subtracting it borrows from the digits above
L_ge_dsm_a_avx512_ifma_slide_carry:
        cmp	rdx, 256
        jge	L_ge_dsm_a_avx512_ifma_slide_next_window
        movsx	r10, BYTE PTR [rbp+rdx+1920]
        test	r10, r10
        je	L_ge_dsm_a_avx512_ifma_slide_set
        mov	BYTE PTR [rbp+rdx+1920], 0
        inc	rdx
        jmp	L_ge_dsm_a_avx512_ifma_slide_carry
L_ge_dsm_a_avx512_ifma_slide_set:
        mov	BYTE PTR [rbp+rdx+1920], 1
L_ge_dsm_a_avx512_ifma_slide_next_window:
        inc	r12
        cmp	r12, 6
        jle	L_ge_dsm_a_avx512_ifma_slide_window
L_ge_dsm_a_avx512_ifma_slide_next_digit:
        inc	r11
        cmp	r11, 256
        jl	L_ge_dsm_a_avx512_ifma_slide_digit
        ; Window digits of the base point scalar
        ; One digit per bit of the scalar
        xor	rdx, rdx
        xor	r11, r11
L_ge_dsm_b_avx512_ifma_slide_bytes:
        movzx	rax, BYTE PTR [rsi+r11]
        mov	rcx, rax
        and	rcx, 1
        mov	BYTE PTR [rbp+rdx+2176], cl
        shr	rax, 1
        inc	rdx
        mov	rcx, rax
        and	rcx, 1
        mov	BYTE PTR [rbp+rdx+2176], cl
        shr	rax, 1
        inc	rdx
        mov	rcx, rax
        and	rcx, 1
        mov	BYTE PTR [rbp+rdx+2176], cl
        shr	rax, 1
        inc	rdx
        mov	rcx, rax
        and	rcx, 1
        mov	BYTE PTR [rbp+rdx+2176], cl
        shr	rax, 1
        inc	rdx
        mov	rcx, rax
        and	rcx, 1
        mov	BYTE PTR [rbp+rdx+2176], cl
        shr	rax, 1
        inc	rdx
        mov	rcx, rax
        and	rcx, 1
        mov	BYTE PTR [rbp+rdx+2176], cl
        shr	rax, 1
        inc	rdx
        mov	rcx, rax
        and	rcx, 1
        mov	BYTE PTR [rbp+rdx+2176], cl
        shr	rax, 1
        inc	rdx
        mov	rcx, rax
        and	rcx, 1
        mov	BYTE PTR [rbp+rdx+2176], cl
        shr	rax, 1
        inc	rdx
        inc	r11
        cmp	r11, 32
        jne	L_ge_dsm_b_avx512_ifma_slide_bytes
        ; Fold each run of digits down to one odd digit
        xor	r11, r11
L_ge_dsm_b_avx512_ifma_slide_digit:
        movsx	rcx, BYTE PTR [rbp+r11+2176]
        test	rcx, rcx
        je	L_ge_dsm_b_avx512_ifma_slide_next_digit
        mov	r12, 1
L_ge_dsm_b_avx512_ifma_slide_window:
        mov	rdx, r11
        add	rdx, r12
        cmp	rdx, 256
        jge	L_ge_dsm_b_avx512_ifma_slide_next_digit
        movsx	r8, BYTE PTR [rbp+rdx+2176]
        test	r8, r8
        je	L_ge_dsm_b_avx512_ifma_slide_next_window
        ; Weight of the digit at i + b, relative to the one at i
        mov	r9, r8
        mov	r8, r12
L_ge_dsm_b_avx512_ifma_slide_shift:
        add	r9, r9
        dec	r8
        jne	L_ge_dsm_b_avx512_ifma_slide_shift
        movsx	r9, r9b
        ; Fold it in if the digit at i stays within range
        mov	r10, rcx
        add	r10, r9
        cmp	r10, 63
        jg	L_ge_dsm_b_avx512_ifma_slide_sub
        mov	rcx, r10
        mov	BYTE PTR [rbp+r11+2176], cl
        mov	BYTE PTR [rbp+rdx+2176], 0
        jmp	L_ge_dsm_b_avx512_ifma_slide_next_window
L_ge_dsm_b_avx512_ifma_slide_sub:
        mov	r10, rcx
        sub	r10, r9
        cmp	r10, -63
        jl	L_ge_dsm_b_avx512_ifma_slide_next_digit
        mov	rcx, r10
        mov	BYTE PTR [rbp+r11+2176], cl
        ; Subtracting it borrows from the digits above
L_ge_dsm_b_avx512_ifma_slide_carry:
        cmp	rdx, 256
        jge	L_ge_dsm_b_avx512_ifma_slide_next_window
        movsx	r10, BYTE PTR [rbp+rdx+2176]
        test	r10, r10
        je	L_ge_dsm_b_avx512_ifma_slide_set
        mov	BYTE PTR [rbp+rdx+2176], 0
        inc	rdx
        jmp	L_ge_dsm_b_avx512_ifma_slide_carry
L_ge_dsm_b_avx512_ifma_slide_set:
        mov	BYTE PTR [rbp+rdx+2176], 1
L_ge_dsm_b_avx512_ifma_slide_next_window:
        inc	r12
        cmp	r12, 6
        jle	L_ge_dsm_b_avx512_ifma_slide_window
L_ge_dsm_b_avx512_ifma_slide_next_digit:
        inc	r11
        cmp	r11, 256
        jl	L_ge_dsm_b_avx512_ifma_slide_digit
        mov	rsi, QWORD PTR [ptr_L_ge_ifma_consts]
        vpbroadcastq	ymm28, QWORD PTR [rsi]
        vpbroadcastq	ymm29, QWORD PTR [rsi+8]
        vpbroadcastq	ymm30, QWORD PTR [rsi+16]
        vpbroadcastq	ymm31, QWORD PTR [rsi+24]
        mov	r9d, 8
        kmovw	k1, r9d
        mov	r9d, 12
        kmovw	k2, r9d
        mov	r9d, 9
        kmovw	k3, r9d
        mov	r9d, 6
        kmovw	k4, r9d
        mov	r9d, 1
        kmovw	k5, r9d
        mov	r9d, 2
        kmovw	k6, r9d
        mov	r9d, 4
        kmovw	k7, r9d
        ; Odd multiples of A, cached and in limb form
        mov	r10, 2251799813685247
        ; A in limb form: [X, Y, Z, T]
        mov	rdx, QWORD PTR [rdi]
        mov	rax, QWORD PTR [rdi+8]
        mov	rcx, QWORD PTR [rdi+16]
        mov	r8, QWORD PTR [rdi+24]
        mov	r9, r8
        shr	r9, 63
        imul	r9, r9, 19
        shl	r8, 1
        shr	r8, 1
        mov	r13, rdx
        and	r13, r10
        add	r13, r9
        mov	QWORD PTR [rbp+1440], r13
        shrd	rdx, rax, 51
        mov	r9, rdx
        and	r9, r10
        mov	QWORD PTR [rbp+1472], r9
        shrd	rax, rcx, 38
        mov	r9, rax
        and	r9, r10
        mov	QWORD PTR [rbp+1504], r9
        shrd	rcx, r8, 25
        mov	r9, rcx
        and	r9, r10
        mov	QWORD PTR [rbp+1536], r9
        shr	r8, 12
        mov	QWORD PTR [rbp+1568], r8
        mov	rdx, QWORD PTR [rdi+32]
        mov	rax, QWORD PTR [rdi+40]
        mov	rcx, QWORD PTR [rdi+48]
        mov	r8, QWORD PTR [rdi+56]
        mov	r9, r8
        shr	r9, 63
        imul	r9, r9, 19
        shl	r8, 1
        shr	r8, 1
        mov	r13, rdx
        and	r13, r10
        add	r13, r9
        mov	QWORD PTR [rbp+1448], r13
        shrd	rdx, rax, 51
        mov	r9, rdx
        and	r9, r10
        mov	QWORD PTR [rbp+1480], r9
        shrd	rax, rcx, 38
        mov	r9, rax
        and	r9, r10
        mov	QWORD PTR [rbp+1512], r9
        shrd	rcx, r8, 25
        mov	r9, rcx
        and	r9, r10
        mov	QWORD PTR [rbp+1544], r9
        shr	r8, 12
        mov	QWORD PTR [rbp+1576], r8
        mov	rdx, QWORD PTR [rdi+64]
        mov	rax, QWORD PTR [rdi+72]
        mov	rcx, QWORD PTR [rdi+80]
        mov	r8, QWORD PTR [rdi+88]
        mov	r9, r8
        shr	r9, 63
        imul	r9, r9, 19
        shl	r8, 1
        shr	r8, 1
        mov	r13, rdx
        and	r13, r10
        add	r13, r9
        mov	QWORD PTR [rbp+1456], r13
        shrd	rdx, rax, 51
        mov	r9, rdx
        and	r9, r10
        mov	QWORD PTR [rbp+1488], r9
        shrd	rax, rcx, 38
        mov	r9, rax
        and	r9, r10
        mov	QWORD PTR [rbp+1520], r9
        shrd	rcx, r8, 25
        mov	r9, rcx
        and	r9, r10
        mov	QWORD PTR [rbp+1552], r9
        shr	r8, 12
        mov	QWORD PTR [rbp+1584], r8
        mov	rdx, QWORD PTR [rdi+96]
        mov	rax, QWORD PTR [rdi+104]
        mov	rcx, QWORD PTR [rdi+112]
        mov	r8, QWORD PTR [rdi+120]
        mov	r9, r8
        shr	r9, 63
        imul	r9, r9, 19
        shl	r8, 1
        shr	r8, 1
        mov	r13, rdx
        and	r13, r10
        add	r13, r9
        mov	QWORD PTR [rbp+1464], r13
        shrd	rdx, rax, 51
        mov	r9, rdx
        and	r9, r10
        mov	QWORD PTR [rbp+1496], r9
        shrd	rax, rcx, 38
        mov	r9, rax
        and	r9, r10
        mov	QWORD PTR [rbp+1528], r9
        shrd	rcx, r8, 25
        mov	r9, rcx
        and	r9, r10
        mov	QWORD PTR [rbp+1560], r9
        shr	r8, 12
        mov	QWORD PTR [rbp+1592], r8
        ; Ai[0] = A
        vmovdqu64	ymm18, YMMWORD PTR [rbp+1440]
        vmovdqu64	ymm19, YMMWORD PTR [rbp+1472]
        vmovdqu64	ymm20, YMMWORD PTR [rbp+1504]
        vmovdqu64	ymm21, YMMWORD PTR [rbp+1536]
        vmovdqu64	ymm22, YMMWORD PTR [rbp+1568]
        ; To cached
        vpermq	ymm23, ymm18, 176
        vpermq	ymm24, ymm19, 176
        vpermq	ymm25, ymm20, 176
        vpermq	ymm26, ymm21, 176
        vpermq	ymm27, ymm22, 176
        vpermq	ymm18, ymm18, 181
        vpermq	ymm19, ymm19, 181
        vpermq	ymm20, ymm20, 181
        vpermq	ymm21, ymm21, 181
        vpermq	ymm22, ymm22, 181
        vpaddq	ymm18{k5}, ymm18, ymm23
        vpaddq	ymm19{k5}, ymm19, ymm24
        vpaddq	ymm20{k5}, ymm20, ymm25
        vpaddq	ymm21{k5}, ymm21, ymm26
        vpaddq	ymm22{k5}, ymm22, ymm27
        vpaddq	ymm18{k6}, ymm18, ymm29
        vpaddq	ymm19{k6}, ymm19, ymm30
        vpaddq	ymm20{k6}, ymm20, ymm30
        vpaddq	ymm21{k6}, ymm21, ymm30
        vpaddq	ymm22{k6}, ymm22, ymm30
        vpsubq	ymm18{k6}, ymm18, ymm23
        vpsubq	ymm19{k6}, ymm19, ymm24
        vpsubq	ymm20{k6}, ymm20, ymm25
        vpsubq	ymm21{k6}, ymm21, ymm26
        vpsubq	ymm22{k6}, ymm22, ymm27
        vpsrlq	ymm0, ymm18, 51
        vpandq	ymm18, ymm18, ymm28
        vpsrlq	ymm1, ymm19, 51
        vpandq	ymm19, ymm19, ymm28
        vpsrlq	ymm2, ymm20, 51
        vpandq	ymm20, ymm20, ymm28
        vpsrlq	ymm3, ymm21, 51
        vpandq	ymm21, ymm21, ymm28
        vpsrlq	ymm4, ymm22, 51
        vpandq	ymm22, ymm22, ymm28
        vpmadd52luq	ymm18, ymm4, ymm31
        vpaddq	ymm19, ymm19, ymm0
        vpaddq	ymm20, ymm20, ymm1
        vpaddq	ymm21, ymm21, ymm2
        vpaddq	ymm22, ymm22, ymm3
        vmovdqu64	ymm23, YMMWORD PTR [rsi+32]
        vmovdqu64	ymm24, YMMWORD PTR [rsi+64]
        vmovdqu64	ymm25, YMMWORD PTR [rsi+96]
        vmovdqu64	ymm26, YMMWORD PTR [rsi+128]
        vmovdqu64	ymm27, YMMWORD PTR [rsi+160]
        ; Multiply 4 field elements
        vpxorq	ymm0, ymm0, ymm0
        vpxorq	ymm9, ymm9, ymm9
        vpxorq	ymm1, ymm1, ymm1
        vpxorq	ymm10, ymm10, ymm10
        vpxorq	ymm2, ymm2, ymm2
        vpxorq	ymm11, ymm11, ymm11
        vpxorq	ymm3, ymm3, ymm3
        vpxorq	ymm12, ymm12, ymm12
        vpxorq	ymm4, ymm4, ymm4
        vpxorq	ymm13, ymm13, ymm13
        vpxorq	ymm5, ymm5, ymm5
        vpxorq	ymm14, ymm14, ymm14
        vpxorq	ymm6, ymm6, ymm6
        vpxorq	ymm15, ymm15, ymm15
        vpxorq	ymm7, ymm7, ymm7
        vpxorq	ymm16, ymm16, ymm16
        vpxorq	ymm8, ymm8, ymm8
        vpxorq	ymm17, ymm17, ymm17
        vpmadd52luq	ymm0, ymm18, ymm23
        vpmadd52huq	ymm9, ymm18, ymm23
        vpmadd52luq	ymm1, ymm18, ymm24
        vpmadd52huq	ymm10, ymm18, ymm24
        vpmadd52luq	ymm2, ymm18, ymm25
        vpmadd52huq	ymm11, ymm18, ymm25
        vpmadd52luq	ymm3, ymm18, ymm26
        vpmadd52huq	ymm12, ymm18, ymm26
        vpmadd52luq	ymm4, ymm18, ymm27
        vpmadd52huq	ymm13, ymm18, ymm27
        vpmadd52luq	ymm1, ymm19, ymm23
        vpmadd52huq	ymm10, ymm19, ymm23
        vpmadd52luq	ymm2, ymm19, ymm24
        vpmadd52huq	ymm11, ymm19, ymm24
        vpmadd52luq	ymm3, ymm19, ymm25
        vpmadd52huq	ymm12, ymm19, ymm25
        vpmadd52luq	ymm4, ymm19, ymm26
        vpmadd52huq	ymm13, ymm19, ymm26
        vpmadd52luq	ymm5, ymm19, ymm27
        vpmadd52huq	ymm14, ymm19, ymm27
        vpmadd52luq	ymm2, ymm20, ymm23
        vpmadd52huq	ymm11, ymm20, ymm23
        vpmadd52luq	ymm3, ymm20, ymm24
        vpmadd52huq	ymm12, ymm20, ymm24
        vpmadd52luq	ymm4, ymm20, ymm25
        vpmadd52huq	ymm13, ymm20, ymm25
        vpmadd52luq	ymm5, ymm20, ymm26
        vpmadd52huq	ymm14, ymm20, ymm26
        vpmadd52luq	ymm6, ymm20, ymm27
        vpmadd52huq	ymm15, ymm20, ymm27
        vpmadd52luq	ymm3, ymm21, ymm23
        vpmadd52huq	ymm12, ymm21, ymm23
        vpmadd52luq	ymm4, ymm21, ymm24
        vpmadd52huq	ymm13, ymm21, ymm24
        vpmadd52luq	ymm5, ymm21, ymm25
        vpmadd52huq	ymm14, ymm21, ymm25
        vpmadd52luq	ymm6, ymm21, ymm26
        vpmadd52huq	ymm15, ymm21, ymm26
        vpmadd52luq	ymm7, ymm21, ymm27
        vpmadd52huq	ymm16, ymm21, ymm27
        vpmadd52luq	ymm4, ymm22, ymm23
        vpmadd52huq	ymm13, ymm22, ymm23
        vpmadd52luq	ymm5, ymm22, ymm24
        vpmadd52huq	ymm14, ymm22, ymm24
        vpmadd52luq	ymm6, ymm22, ymm25
        vpmadd52huq	ymm15, ymm22, ymm25
        vpmadd52luq	ymm7, ymm22, ymm26
        vpmadd52huq	ymm16, ymm22, ymm26
        vpmadd52luq	ymm8, ymm22, ymm27
        vpmadd52huq	ymm17, ymm22, ymm27
        vpaddq	ymm9, ymm9, ymm9
        vpaddq	ymm1, ymm1, ymm9
        vpaddq	ymm10, ymm10, ymm10
        vpaddq	ymm2, ymm2, ymm10
        vpaddq	ymm11, ymm11, ymm11
        vpaddq	ymm3, ymm3, ymm11
        vpaddq	ymm12, ymm12, ymm12
        vpaddq	ymm4, ymm4, ymm12
        vpaddq	ymm13, ymm13, ymm13
        vpaddq	ymm5, ymm5, ymm13
        vpaddq	ymm14, ymm14, ymm14
        vpaddq	ymm6, ymm6, ymm14
        vpaddq	ymm15, ymm15, ymm15
        vpaddq	ymm7, ymm7, ymm15
        vpaddq	ymm16, ymm16, ymm16
        vpaddq	ymm8, ymm8, ymm16
        vpaddq	ymm17, ymm17, ymm17
        ; Reduce
        vpsllq	ymm9, ymm5, 4
        vpsllq	ymm10, ymm5, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm5
        vpaddq	ymm0, ymm0, ymm9
        vpsllq	ymm9, ymm6, 4
        vpsllq	ymm10, ymm6, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm6
        vpaddq	ymm1, ymm1, ymm9
        vpsllq	ymm9, ymm7, 4
        vpsllq	ymm10, ymm7, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm7
        vpaddq	ymm2, ymm2, ymm9
        vpsllq	ymm9, ymm8, 4
        vpsllq	ymm10, ymm8, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm8
        vpaddq	ymm3, ymm3, ymm9
        vpsllq	ymm9, ymm17, 4
        vpsllq	ymm10, ymm17, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm17
        vpaddq	ymm4, ymm4, ymm9
        vpsrlq	ymm23, ymm0, 51
        vpandq	ymm0, ymm0, ymm28
        vpsrlq	ymm24, ymm1, 51
        vpandq	ymm1, ymm1, ymm28
        vpsrlq	ymm25, ymm2, 51
        vpandq	ymm2, ymm2, ymm28
        vpsrlq	ymm26, ymm3, 51
        vpandq	ymm3, ymm3, ymm28
        vpsrlq	ymm27, ymm4, 51
        vpandq	ymm4, ymm4, ymm28
        vmovdqa64	ymm18, ymm0
        vpmadd52luq	ymm18, ymm27, ymm31
        vpaddq	ymm19, ymm1, ymm23
        vpaddq	ymm20, ymm2, ymm24
        vpaddq	ymm21, ymm3, ymm25
        vpaddq	ymm22, ymm4, ymm26
        vmovdqu64	YMMWORD PTR [rbp], ymm18
        vmovdqu64	YMMWORD PTR [rbp+32], ymm19
        vmovdqu64	YMMWORD PTR [rbp+64], ymm20
        vmovdqu64	YMMWORD PTR [rbp+96], ymm21
        vmovdqu64	YMMWORD PTR [rbp+128], ymm22
        ; A2 = 2.A
        vmovdqu64	ymm18, YMMWORD PTR [rbp+1440]
        vmovdqu64	ymm19, YMMWORD PTR [rbp+1472]
        vmovdqu64	ymm20, YMMWORD PTR [rbp+1504]
        vmovdqu64	ymm21, YMMWORD PTR [rbp+1536]
        vmovdqu64	ymm22, YMMWORD PTR [rbp+1568]
        ; Double
        vpermq	ymm23, ymm18, 100
        vpermq	ymm24, ymm19, 100
        vpermq	ymm25, ymm20, 100
        vpermq	ymm26, ymm21, 100
        vpermq	ymm27, ymm22, 100
        vpermq	ymm18, ymm18, 36
        vpermq	ymm19, ymm19, 36
        vpermq	ymm20, ymm20, 36
        vpermq	ymm21, ymm21, 36
        vpermq	ymm22, ymm22, 36
        vpaddq	ymm18{k1}, ymm18, ymm23
        vpaddq	ymm19{k1}, ymm19, ymm24
        vpaddq	ymm20{k1}, ymm20, ymm25
        vpaddq	ymm21{k1}, ymm21, ymm26
        vpaddq	ymm22{k1}, ymm22, ymm27
        vpsrlq	ymm0, ymm18, 51
        vpandq	ymm18, ymm18, ymm28
        vpsrlq	ymm1, ymm19, 51
        vpandq	ymm19, ymm19, ymm28
        vpsrlq	ymm2, ymm20, 51
        vpandq	ymm20, ymm20, ymm28
        vpsrlq	ymm3, ymm21, 51
        vpandq	ymm21, ymm21, ymm28
        vpsrlq	ymm4, ymm22, 51
        vpandq	ymm22, ymm22, ymm28
        vpmadd52luq	ymm18, ymm4, ymm31
        vpaddq	ymm19, ymm19, ymm0
        vpaddq	ymm20, ymm20, ymm1
        vpaddq	ymm21, ymm21, ymm2
        vpaddq	ymm22, ymm22, ymm3
        vmovdqa64	ymm23, ymm18
        vmovdqa64	ymm24, ymm19
        vmovdqa64	ymm25, ymm20
        vmovdqa64	ymm26, ymm21
        vmovdqa64	ymm27, ymm22
        ; Multiply 4 field elements
        vpxorq	ymm0, ymm0, ymm0
        vpxorq	ymm9, ymm9, ymm9
        vpxorq	ymm1, ymm1, ymm1
        vpxorq	ymm10, ymm10, ymm10
        vpxorq	ymm2, ymm2, ymm2
        vpxorq	ymm11, ymm11, ymm11
        vpxorq	ymm3, ymm3, ymm3
        vpxorq	ymm12, ymm12, ymm12
        vpxorq	ymm4, ymm4, ymm4
        vpxorq	ymm13, ymm13, ymm13
        vpxorq	ymm5, ymm5, ymm5
        vpxorq	ymm14, ymm14, ymm14
        vpxorq	ymm6, ymm6, ymm6
        vpxorq	ymm15, ymm15, ymm15
        vpxorq	ymm7, ymm7, ymm7
        vpxorq	ymm16, ymm16, ymm16
        vpxorq	ymm8, ymm8, ymm8
        vpxorq	ymm17, ymm17, ymm17
        vpmadd52luq	ymm0, ymm18, ymm23
        vpmadd52huq	ymm9, ymm18, ymm23
        vpmadd52luq	ymm1, ymm18, ymm24
        vpmadd52huq	ymm10, ymm18, ymm24
        vpmadd52luq	ymm2, ymm18, ymm25
        vpmadd52huq	ymm11, ymm18, ymm25
        vpmadd52luq	ymm3, ymm18, ymm26
        vpmadd52huq	ymm12, ymm18, ymm26
        vpmadd52luq	ymm4, ymm18, ymm27
        vpmadd52huq	ymm13, ymm18, ymm27
        vpmadd52luq	ymm1, ymm19, ymm23
        vpmadd52huq	ymm10, ymm19, ymm23
        vpmadd52luq	ymm2, ymm19, ymm24
        vpmadd52huq	ymm11, ymm19, ymm24
        vpmadd52luq	ymm3, ymm19, ymm25
        vpmadd52huq	ymm12, ymm19, ymm25
        vpmadd52luq	ymm4, ymm19, ymm26
        vpmadd52huq	ymm13, ymm19, ymm26
        vpmadd52luq	ymm5, ymm19, ymm27
        vpmadd52huq	ymm14, ymm19, ymm27
        vpmadd52luq	ymm2, ymm20, ymm23
        vpmadd52huq	ymm11, ymm20, ymm23
        vpmadd52luq	ymm3, ymm20, ymm24
        vpmadd52huq	ymm12, ymm20, ymm24
        vpmadd52luq	ymm4, ymm20, ymm25
        vpmadd52huq	ymm13, ymm20, ymm25
        vpmadd52luq	ymm5, ymm20, ymm26
        vpmadd52huq	ymm14, ymm20, ymm26
        vpmadd52luq	ymm6, ymm20, ymm27
        vpmadd52huq	ymm15, ymm20, ymm27
        vpmadd52luq	ymm3, ymm21, ymm23
        vpmadd52huq	ymm12, ymm21, ymm23
        vpmadd52luq	ymm4, ymm21, ymm24
        vpmadd52huq	ymm13, ymm21, ymm24
        vpmadd52luq	ymm5, ymm21, ymm25
        vpmadd52huq	ymm14, ymm21, ymm25
        vpmadd52luq	ymm6, ymm21, ymm26
        vpmadd52huq	ymm15, ymm21, ymm26
        vpmadd52luq	ymm7, ymm21, ymm27
        vpmadd52huq	ymm16, ymm21, ymm27
        vpmadd52luq	ymm4, ymm22, ymm23
        vpmadd52huq	ymm13, ymm22, ymm23
        vpmadd52luq	ymm5, ymm22, ymm24
        vpmadd52huq	ymm14, ymm22, ymm24
        vpmadd52luq	ymm6, ymm22, ymm25
        vpmadd52huq	ymm15, ymm22, ymm25
        vpmadd52luq	ymm7, ymm22, ymm26
        vpmadd52huq	ymm16, ymm22, ymm26
        vpmadd52luq	ymm8, ymm22, ymm27
        vpmadd52huq	ymm17, ymm22, ymm27
        vpaddq	ymm9, ymm9, ymm9
        vpaddq	ymm1, ymm1, ymm9
        vpaddq	ymm10, ymm10, ymm10
        vpaddq	ymm2, ymm2, ymm10
        vpaddq	ymm11, ymm11, ymm11
        vpaddq	ymm3, ymm3, ymm11
        vpaddq	ymm12, ymm12, ymm12
        vpaddq	ymm4, ymm4, ymm12
        vpaddq	ymm13, ymm13, ymm13
        vpaddq	ymm5, ymm5, ymm13
        vpaddq	ymm14, ymm14, ymm14
        vpaddq	ymm6, ymm6, ymm14
        vpaddq	ymm15, ymm15, ymm15
        vpaddq	ymm7, ymm7, ymm15
        vpaddq	ymm16, ymm16, ymm16
        vpaddq	ymm8, ymm8, ymm16
        vpaddq	ymm17, ymm17, ymm17
        ; Reduce
        vpsllq	ymm9, ymm5, 4
        vpsllq	ymm10, ymm5, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm5
        vpaddq	ymm0, ymm0, ymm9
        vpsllq	ymm9, ymm6, 4
        vpsllq	ymm10, ymm6, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm6
        vpaddq	ymm1, ymm1, ymm9
        vpsllq	ymm9, ymm7, 4
        vpsllq	ymm10, ymm7, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm7
        vpaddq	ymm2, ymm2, ymm9
        vpsllq	ymm9, ymm8, 4
        vpsllq	ymm10, ymm8, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm8
        vpaddq	ymm3, ymm3, ymm9
        vpsllq	ymm9, ymm17, 4
        vpsllq	ymm10, ymm17, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm17
        vpaddq	ymm4, ymm4, ymm9
        vpsrlq	ymm23, ymm0, 51
        vpandq	ymm0, ymm0, ymm28
        vpsrlq	ymm24, ymm1, 51
        vpandq	ymm1, ymm1, ymm28
        vpsrlq	ymm25, ymm2, 51
        vpandq	ymm2, ymm2, ymm28
        vpsrlq	ymm26, ymm3, 51
        vpandq	ymm3, ymm3, ymm28
        vpsrlq	ymm27, ymm4, 51
        vpandq	ymm4, ymm4, ymm28
        vmovdqa64	ymm18, ymm0
        vpmadd52luq	ymm18, ymm27, ymm31
        vpaddq	ymm19, ymm1, ymm23
        vpaddq	ymm20, ymm2, ymm24
        vpaddq	ymm21, ymm3, ymm25
        vpaddq	ymm22, ymm4, ymm26
        ; Y3 = YY + XX, Z3 = YY - XX
        vpermq	ymm23, ymm18, 85
        vpermq	ymm24, ymm19, 85
        vpermq	ymm25, ymm20, 85
        vpermq	ymm26, ymm21, 85
        vpermq	ymm27, ymm22, 85
        vpermq	ymm0, ymm18, 0
        vpermq	ymm1, ymm19, 0
        vpermq	ymm2, ymm20, 0
        vpermq	ymm3, ymm21, 0
        vpermq	ymm4, ymm22, 0
        vpaddq	ymm5, ymm23, ymm0
        vpaddq	ymm6, ymm24, ymm1
        vpaddq	ymm7, ymm25, ymm2
        vpaddq	ymm8, ymm26, ymm3
        vpaddq	ymm9, ymm27, ymm4
        vpaddq	ymm23{k2}, ymm23, ymm29
        vpaddq	ymm24{k2}, ymm24, ymm30
        vpaddq	ymm25{k2}, ymm25, ymm30
        vpaddq	ymm26{k2}, ymm26, ymm30
        vpaddq	ymm27{k2}, ymm27, ymm30
        vpsubq	ymm5{k2}, ymm23, ymm0
        vpsubq	ymm6{k2}, ymm24, ymm1
        vpsubq	ymm7{k2}, ymm25, ymm2
        vpsubq	ymm8{k2}, ymm26, ymm3
        vpsubq	ymm9{k2}, ymm27, ymm4
        vpsrlq	ymm23, ymm5, 51
        vpandq	ymm5, ymm5, ymm28
        vpsrlq	ymm24, ymm6, 51
        vpandq	ymm6, ymm6, ymm28
        vpsrlq	ymm25, ymm7, 51
        vpandq	ymm7, ymm7, ymm28
        vpsrlq	ymm26, ymm8, 51
        vpandq	ymm8, ymm8, ymm28
        vpsrlq	ymm27, ymm9, 51
        vpandq	ymm9, ymm9, ymm28
        vpmadd52luq	ymm5, ymm27, ymm31
        vpaddq	ymm6, ymm6, ymm23
        vpaddq	ymm7, ymm7, ymm24
        vpaddq	ymm8, ymm8, ymm25
        vpaddq	ymm9, ymm9, ymm26
        ; X3 = AA - Y3, T3 = 2.ZZ - Z3
        vpermq	ymm23, ymm18, 175
        vpermq	ymm24, ymm19, 175
        vpermq	ymm25, ymm20, 175
        vpermq	ymm26, ymm21, 175
        vpermq	ymm27, ymm22, 175
        vpaddq	ymm23{k2}, ymm23, ymm23
        vpaddq	ymm24{k2}, ymm24, ymm24
        vpaddq	ymm25{k2}, ymm25, ymm25
        vpaddq	ymm26{k2}, ymm26, ymm26
        vpaddq	ymm27{k2}, ymm27, ymm27
        vpaddq	ymm23{k3}, ymm23, ymm29
        vpaddq	ymm24{k3}, ymm24, ymm30
        vpaddq	ymm25{k3}, ymm25, ymm30
        vpaddq	ymm26{k3}, ymm26, ymm30
        vpaddq	ymm27{k3}, ymm27, ymm30
        vpsubq	ymm23{k3}, ymm23, ymm5
        vpsubq	ymm24{k3}, ymm24, ymm6
        vpsubq	ymm25{k3}, ymm25, ymm7
        vpsubq	ymm26{k3}, ymm26, ymm8
        vpsubq	ymm27{k3}, ymm27, ymm9
        vpsrlq	ymm0, ymm23, 51
        vpandq	ymm23, ymm23, ymm28
        vpsrlq	ymm1, ymm24, 51
        vpandq	ymm24, ymm24, ymm28
        vpsrlq	ymm2, ymm25, 51
        vpandq	ymm25, ymm25, ymm28
        vpsrlq	ymm3, ymm26, 51
        vpandq	ymm26, ymm26, ymm28
        vpsrlq	ymm4, ymm27, 51
        vpandq	ymm27, ymm27, ymm28
        vpmadd52luq	ymm23, ymm4, ymm31
        vpaddq	ymm24, ymm24, ymm0
        vpaddq	ymm25, ymm25, ymm1
        vpaddq	ymm26, ymm26, ymm2
        vpaddq	ymm27, ymm27, ymm3
        vmovdqa64	ymm23{k4}, ymm5
        vmovdqa64	ymm24{k4}, ymm6
        vmovdqa64	ymm25{k4}, ymm7
        vmovdqa64	ymm26{k4}, ymm8
        vmovdqa64	ymm27{k4}, ymm9
        ; To p3
        vpermq	ymm18, ymm23, 36
        vpermq	ymm19, ymm24, 36
        vpermq	ymm20, ymm25, 36
        vpermq	ymm21, ymm26, 36
        vpermq	ymm22, ymm27, 36
        vpermq	ymm23, ymm23, 123
        vpermq	ymm24, ymm24, 123
        vpermq	ymm25, ymm25, 123
        vpermq	ymm26, ymm26, 123
        vpermq	ymm27, ymm27, 123
        ; Multiply 4 field elements
        vpxorq	ymm0, ymm0, ymm0
        vpxorq	ymm9, ymm9, ymm9
        vpxorq	ymm1, ymm1, ymm1
        vpxorq	ymm10, ymm10, ymm10
        vpxorq	ymm2, ymm2, ymm2
        vpxorq	ymm11, ymm11, ymm11
        vpxorq	ymm3, ymm3, ymm3
        vpxorq	ymm12, ymm12, ymm12
        vpxorq	ymm4, ymm4, ymm4
        vpxorq	ymm13, ymm13, ymm13
        vpxorq	ymm5, ymm5, ymm5
        vpxorq	ymm14, ymm14, ymm14
        vpxorq	ymm6, ymm6, ymm6
        vpxorq	ymm15, ymm15, ymm15
        vpxorq	ymm7, ymm7, ymm7
        vpxorq	ymm16, ymm16, ymm16
        vpxorq	ymm8, ymm8, ymm8
        vpxorq	ymm17, ymm17, ymm17
        vpmadd52luq	ymm0, ymm18, ymm23
        vpmadd52huq	ymm9, ymm18, ymm23
        vpmadd52luq	ymm1, ymm18, ymm24
        vpmadd52huq	ymm10, ymm18, ymm24
        vpmadd52luq	ymm2, ymm18, ymm25
        vpmadd52huq	ymm11, ymm18, ymm25
        vpmadd52luq	ymm3, ymm18, ymm26
        vpmadd52huq	ymm12, ymm18, ymm26
        vpmadd52luq	ymm4, ymm18, ymm27
        vpmadd52huq	ymm13, ymm18, ymm27
        vpmadd52luq	ymm1, ymm19, ymm23
        vpmadd52huq	ymm10, ymm19, ymm23
        vpmadd52luq	ymm2, ymm19, ymm24
        vpmadd52huq	ymm11, ymm19, ymm24
        vpmadd52luq	ymm3, ymm19, ymm25
        vpmadd52huq	ymm12, ymm19, ymm25
        vpmadd52luq	ymm4, ymm19, ymm26
        vpmadd52huq	ymm13, ymm19, ymm26
        vpmadd52luq	ymm5, ymm19, ymm27
        vpmadd52huq	ymm14, ymm19, ymm27
        vpmadd52luq	ymm2, ymm20, ymm23
        vpmadd52huq	ymm11, ymm20, ymm23
        vpmadd52luq	ymm3, ymm20, ymm24
        vpmadd52huq	ymm12, ymm20, ymm24
        vpmadd52luq	ymm4, ymm20, ymm25
        vpmadd52huq	ymm13, ymm20, ymm25
        vpmadd52luq	ymm5, ymm20, ymm26
        vpmadd52huq	ymm14, ymm20, ymm26
        vpmadd52luq	ymm6, ymm20, ymm27
        vpmadd52huq	ymm15, ymm20, ymm27
        vpmadd52luq	ymm3, ymm21, ymm23
        vpmadd52huq	ymm12, ymm21, ymm23
        vpmadd52luq	ymm4, ymm21, ymm24
        vpmadd52huq	ymm13, ymm21, ymm24
        vpmadd52luq	ymm5, ymm21, ymm25
        vpmadd52huq	ymm14, ymm21, ymm25
        vpmadd52luq	ymm6, ymm21, ymm26
        vpmadd52huq	ymm15, ymm21, ymm26
        vpmadd52luq	ymm7, ymm21, ymm27
        vpmadd52huq	ymm16, ymm21, ymm27
        vpmadd52luq	ymm4, ymm22, ymm23
        vpmadd52huq	ymm13, ymm22, ymm23
        vpmadd52luq	ymm5, ymm22, ymm24
        vpmadd52huq	ymm14, ymm22, ymm24
        vpmadd52luq	ymm6, ymm22, ymm25
        vpmadd52huq	ymm15, ymm22, ymm25
        vpmadd52luq	ymm7, ymm22, ymm26
        vpmadd52huq	ymm16, ymm22, ymm26
        vpmadd52luq	ymm8, ymm22, ymm27
        vpmadd52huq	ymm17, ymm22, ymm27
        vpaddq	ymm9, ymm9, ymm9
        vpaddq	ymm1, ymm1, ymm9
        vpaddq	ymm10, ymm10, ymm10
        vpaddq	ymm2, ymm2, ymm10
        vpaddq	ymm11, ymm11, ymm11
        vpaddq	ymm3, ymm3, ymm11
        vpaddq	ymm12, ymm12, ymm12
        vpaddq	ymm4, ymm4, ymm12
        vpaddq	ymm13, ymm13, ymm13
        vpaddq	ymm5, ymm5, ymm13
        vpaddq	ymm14, ymm14, ymm14
        vpaddq	ymm6, ymm6, ymm14
        vpaddq	ymm15, ymm15, ymm15
        vpaddq	ymm7, ymm7, ymm15
        vpaddq	ymm16, ymm16, ymm16
        vpaddq	ymm8, ymm8, ymm16
        vpaddq	ymm17, ymm17, ymm17
        ; Reduce
        vpsllq	ymm9, ymm5, 4
        vpsllq	ymm10, ymm5, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm5
        vpaddq	ymm0, ymm0, ymm9
        vpsllq	ymm9, ymm6, 4
        vpsllq	ymm10, ymm6, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm6
        vpaddq	ymm1, ymm1, ymm9
        vpsllq	ymm9, ymm7, 4
        vpsllq	ymm10, ymm7, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm7
        vpaddq	ymm2, ymm2, ymm9
        vpsllq	ymm9, ymm8, 4
        vpsllq	ymm10, ymm8, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm8
        vpaddq	ymm3, ymm3, ymm9
        vpsllq	ymm9, ymm17, 4
        vpsllq	ymm10, ymm17, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm17
        vpaddq	ymm4, ymm4, ymm9
        vpsrlq	ymm23, ymm0, 51
        vpandq	ymm0, ymm0, ymm28
        vpsrlq	ymm24, ymm1, 51
        vpandq	ymm1, ymm1, ymm28
        vpsrlq	ymm25, ymm2, 51
        vpandq	ymm2, ymm2, ymm28
        vpsrlq	ymm26, ymm3, 51
        vpandq	ymm3, ymm3, ymm28
        vpsrlq	ymm27, ymm4, 51
        vpandq	ymm4, ymm4, ymm28
        vmovdqa64	ymm18, ymm0
        vpmadd52luq	ymm18, ymm27, ymm31
        vpaddq	ymm19, ymm1, ymm23
        vpaddq	ymm20, ymm2, ymm24
        vpaddq	ymm21, ymm3, ymm25
        vpaddq	ymm22, ymm4, ymm26
        vmovdqu64	YMMWORD PTR [rbp+1280], ymm18
        vmovdqu64	YMMWORD PTR [rbp+1312], ymm19
        vmovdqu64	YMMWORD PTR [rbp+1344], ymm20
        vmovdqu64	YMMWORD PTR [rbp+1376], ymm21
        vmovdqu64	YMMWORD PTR [rbp+1408], ymm22
        ; Ai[j] = A2 + Ai[j-1]
        lea	r12, QWORD PTR [rbp]
        mov	r11, 7
L_ge_dsm_avx512_ifma_table:
        vmovdqu64	ymm18, YMMWORD PTR [rbp+1280]
        vmovdqu64	ymm19, YMMWORD PTR [rbp+1312]
        vmovdqu64	ymm20, YMMWORD PTR [rbp+1344]
        vmovdqu64	ymm21, YMMWORD PTR [rbp+1376]
        vmovdqu64	ymm22, YMMWORD PTR [rbp+1408]
        ; Add
        vpermq	ymm23, ymm18, 176
        vpermq	ymm24, ymm19, 176
        vpermq	ymm25, ymm20, 176
        vpermq	ymm26, ymm21, 176
        vpermq	ymm27, ymm22, 176
        vpermq	ymm18, ymm18, 181
        vpermq	ymm19, ymm19, 181
        vpermq	ymm20, ymm20, 181
        vpermq	ymm21, ymm21, 181
        vpermq	ymm22, ymm22, 181
        vpaddq	ymm18{k5}, ymm18, ymm23
        vpaddq	ymm19{k5}, ymm19, ymm24
        vpaddq	ymm20{k5}, ymm20, ymm25
        vpaddq	ymm21{k5}, ymm21, ymm26
        vpaddq	ymm22{k5}, ymm22, ymm27
        vpaddq	ymm18{k6}, ymm18, ymm29
        vpaddq	ymm19{k6}, ymm19, ymm30
        vpaddq	ymm20{k6}, ymm20, ymm30
        vpaddq	ymm21{k6}, ymm21, ymm30
        vpaddq	ymm22{k6}, ymm22, ymm30
        vpsubq	ymm18{k6}, ymm18, ymm23
        vpsubq	ymm19{k6}, ymm19, ymm24
        vpsubq	ymm20{k6}, ymm20, ymm25
        vpsubq	ymm21{k6}, ymm21, ymm26
        vpsubq	ymm22{k6}, ymm22, ymm27
        vpsrlq	ymm0, ymm18, 51
        vpandq	ymm18, ymm18, ymm28
        vpsrlq	ymm1, ymm19, 51
        vpandq	ymm19, ymm19, ymm28
        vpsrlq	ymm2, ymm20, 51
        vpandq	ymm20, ymm20, ymm28
        vpsrlq	ymm3, ymm21, 51
        vpandq	ymm21, ymm21, ymm28
        vpsrlq	ymm4, ymm22, 51
        vpandq	ymm22, ymm22, ymm28
        vpmadd52luq	ymm18, ymm4, ymm31
        vpaddq	ymm19, ymm19, ymm0
        vpaddq	ymm20, ymm20, ymm1
        vpaddq	ymm21, ymm21, ymm2
        vpaddq	ymm22, ymm22, ymm3
        vmovdqu64	ymm23, YMMWORD PTR [r12]
        vmovdqu64	ymm24, YMMWORD PTR [r12+32]
        vmovdqu64	ymm25, YMMWORD PTR [r12+64]
        vmovdqu64	ymm26, YMMWORD PTR [r12+96]
        vmovdqu64	ymm27, YMMWORD PTR [r12+128]
        ; Multiply 4 field elements
        vpxorq	ymm0, ymm0, ymm0
        vpxorq	ymm9, ymm9, ymm9
        vpxorq	ymm1, ymm1, ymm1
        vpxorq	ymm10, ymm10, ymm10
        vpxorq	ymm2, ymm2, ymm2
        vpxorq	ymm11, ymm11, ymm11
        vpxorq	ymm3, ymm3, ymm3
        vpxorq	ymm12, ymm12, ymm12
        vpxorq	ymm4, ymm4, ymm4
        vpxorq	ymm13, ymm13, ymm13
        vpxorq	ymm5, ymm5, ymm5
        vpxorq	ymm14, ymm14, ymm14
        vpxorq	ymm6, ymm6, ymm6
        vpxorq	ymm15, ymm15, ymm15
        vpxorq	ymm7, ymm7, ymm7
        vpxorq	ymm16, ymm16, ymm16
        vpxorq	ymm8, ymm8, ymm8
        vpxorq	ymm17, ymm17, ymm17
        vpmadd52luq	ymm0, ymm18, ymm23
        vpmadd52huq	ymm9, ymm18, ymm23
        vpmadd52luq	ymm1, ymm18, ymm24
        vpmadd52huq	ymm10, ymm18, ymm24
        vpmadd52luq	ymm2, ymm18, ymm25
        vpmadd52huq	ymm11, ymm18, ymm25
        vpmadd52luq	ymm3, ymm18, ymm26
        vpmadd52huq	ymm12, ymm18, ymm26
        vpmadd52luq	ymm4, ymm18, ymm27
        vpmadd52huq	ymm13, ymm18, ymm27
        vpmadd52luq	ymm1, ymm19, ymm23
        vpmadd52huq	ymm10, ymm19, ymm23
        vpmadd52luq	ymm2, ymm19, ymm24
        vpmadd52huq	ymm11, ymm19, ymm24
        vpmadd52luq	ymm3, ymm19, ymm25
        vpmadd52huq	ymm12, ymm19, ymm25
        vpmadd52luq	ymm4, ymm19, ymm26
        vpmadd52huq	ymm13, ymm19, ymm26
        vpmadd52luq	ymm5, ymm19, ymm27
        vpmadd52huq	ymm14, ymm19, ymm27
        vpmadd52luq	ymm2, ymm20, ymm23
        vpmadd52huq	ymm11, ymm20, ymm23
        vpmadd52luq	ymm3, ymm20, ymm24
        vpmadd52huq	ymm12, ymm20, ymm24
        vpmadd52luq	ymm4, ymm20, ymm25
        vpmadd52huq	ymm13, ymm20, ymm25
        vpmadd52luq	ymm5, ymm20, ymm26
        vpmadd52huq	ymm14, ymm20, ymm26
        vpmadd52luq	ymm6, ymm20, ymm27
        vpmadd52huq	ymm15, ymm20, ymm27
        vpmadd52luq	ymm3, ymm21, ymm23
        vpmadd52huq	ymm12, ymm21, ymm23
        vpmadd52luq	ymm4, ymm21, ymm24
        vpmadd52huq	ymm13, ymm21, ymm24
        vpmadd52luq	ymm5, ymm21, ymm25
        vpmadd52huq	ymm14, ymm21, ymm25
        vpmadd52luq	ymm6, ymm21, ymm26
        vpmadd52huq	ymm15, ymm21, ymm26
        vpmadd52luq	ymm7, ymm21, ymm27
        vpmadd52huq	ymm16, ymm21, ymm27
        vpmadd52luq	ymm4, ymm22, ymm23
        vpmadd52huq	ymm13, ymm22, ymm23
        vpmadd52luq	ymm5, ymm22, ymm24
        vpmadd52huq	ymm14, ymm22, ymm24
        vpmadd52luq	ymm6, ymm22, ymm25
        vpmadd52huq	ymm15, ymm22, ymm25
        vpmadd52luq	ymm7, ymm22, ymm26
        vpmadd52huq	ymm16, ymm22, ymm26
        vpmadd52luq	ymm8, ymm22, ymm27
        vpmadd52huq	ymm17, ymm22, ymm27
        vpaddq	ymm9, ymm9, ymm9
        vpaddq	ymm1, ymm1, ymm9
        vpaddq	ymm10, ymm10, ymm10
        vpaddq	ymm2, ymm2, ymm10
        vpaddq	ymm11, ymm11, ymm11
        vpaddq	ymm3, ymm3, ymm11
        vpaddq	ymm12, ymm12, ymm12
        vpaddq	ymm4, ymm4, ymm12
        vpaddq	ymm13, ymm13, ymm13
        vpaddq	ymm5, ymm5, ymm13
        vpaddq	ymm14, ymm14, ymm14
        vpaddq	ymm6, ymm6, ymm14
        vpaddq	ymm15, ymm15, ymm15
        vpaddq	ymm7, ymm7, ymm15
        vpaddq	ymm16, ymm16, ymm16
        vpaddq	ymm8, ymm8, ymm16
        vpaddq	ymm17, ymm17, ymm17
        ; Reduce
        vpsllq	ymm9, ymm5, 4
        vpsllq	ymm10, ymm5, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm5
        vpaddq	ymm0, ymm0, ymm9
        vpsllq	ymm9, ymm6, 4
        vpsllq	ymm10, ymm6, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm6
        vpaddq	ymm1, ymm1, ymm9
        vpsllq	ymm9, ymm7, 4
        vpsllq	ymm10, ymm7, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm7
        vpaddq	ymm2, ymm2, ymm9
        vpsllq	ymm9, ymm8, 4
        vpsllq	ymm10, ymm8, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm8
        vpaddq	ymm3, ymm3, ymm9
        vpsllq	ymm9, ymm17, 4
        vpsllq	ymm10, ymm17, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm17
        vpaddq	ymm4, ymm4, ymm9
        vpsrlq	ymm23, ymm0, 51
        vpandq	ymm0, ymm0, ymm28
        vpsrlq	ymm24, ymm1, 51
        vpandq	ymm1, ymm1, ymm28
        vpsrlq	ymm25, ymm2, 51
        vpandq	ymm2, ymm2, ymm28
        vpsrlq	ymm26, ymm3, 51
        vpandq	ymm3, ymm3, ymm28
        vpsrlq	ymm27, ymm4, 51
        vpandq	ymm4, ymm4, ymm28
        vmovdqa64	ymm18, ymm0
        vpmadd52luq	ymm18, ymm27, ymm31
        vpaddq	ymm19, ymm1, ymm23
        vpaddq	ymm20, ymm2, ymm24
        vpaddq	ymm21, ymm3, ymm25
        vpaddq	ymm22, ymm4, ymm26
        ; X3 = B - A, Y3 = B + A, Z3 = D + C, T3 = D - C
        vpermq	ymm23, ymm18, 240
        vpermq	ymm24, ymm19, 240
        vpermq	ymm25, ymm20, 240
        vpermq	ymm26, ymm21, 240
        vpermq	ymm27, ymm22, 240
        vpaddq	ymm23{k2}, ymm23, ymm23
        vpaddq	ymm24{k2}, ymm24, ymm24
        vpaddq	ymm25{k2}, ymm25, ymm25
        vpaddq	ymm26{k2}, ymm26, ymm26
        vpaddq	ymm27{k2}, ymm27, ymm27
        vpermq	ymm0, ymm18, 165
        vpermq	ymm1, ymm19, 165
        vpermq	ymm2, ymm20, 165
        vpermq	ymm3, ymm21, 165
        vpermq	ymm4, ymm22, 165
        vpaddq	ymm18, ymm23, ymm0
        vpaddq	ymm19, ymm24, ymm1
        vpaddq	ymm20, ymm25, ymm2
        vpaddq	ymm21, ymm26, ymm3
        vpaddq	ymm22, ymm27, ymm4
        vpaddq	ymm23{k3}, ymm23, ymm29
        vpaddq	ymm24{k3}, ymm24, ymm30
        vpaddq	ymm25{k3}, ymm25, ymm30
        vpaddq	ymm26{k3}, ymm26, ymm30
        vpaddq	ymm27{k3}, ymm27, ymm30
        vpsubq	ymm18{k3}, ymm23, ymm0
        vpsubq	ymm19{k3}, ymm24, ymm1
        vpsubq	ymm20{k3}, ymm25, ymm2
        vpsubq	ymm21{k3}, ymm26, ymm3
        vpsubq	ymm22{k3}, ymm27, ymm4
        vpsrlq	ymm5, ymm18, 51
        vpandq	ymm18, ymm18, ymm28
        vpsrlq	ymm6, ymm19, 51
        vpandq	ymm19, ymm19, ymm28
        vpsrlq	ymm7, ymm20, 51
        vpandq	ymm20, ymm20, ymm28
        vpsrlq	ymm8, ymm21, 51
        vpandq	ymm21, ymm21, ymm28
        vpsrlq	ymm9, ymm22, 51
        vpandq	ymm22, ymm22, ymm28
        vpmadd52luq	ymm18, ymm9, ymm31
        vpaddq	ymm19, ymm19, ymm5
        vpaddq	ymm20, ymm20, ymm6
        vpaddq	ymm21, ymm21, ymm7
        vpaddq	ymm22, ymm22, ymm8
        vmovdqa64	ymm23, ymm18
        vmovdqa64	ymm24, ymm19
        vmovdqa64	ymm25, ymm20
        vmovdqa64	ymm26, ymm21
        vmovdqa64	ymm27, ymm22
        ; To p3
        vpermq	ymm18, ymm23, 36
        vpermq	ymm19, ymm24, 36
        vpermq	ymm20, ymm25, 36
        vpermq	ymm21, ymm26, 36
        vpermq	ymm22, ymm27, 36
        vpermq	ymm23, ymm23, 123
        vpermq	ymm24, ymm24, 123
        vpermq	ymm25, ymm25, 123
        vpermq	ymm26, ymm26, 123
        vpermq	ymm27, ymm27, 123
        ; Multiply 4 field elements
        vpxorq	ymm0, ymm0, ymm0
        vpxorq	ymm9, ymm9, ymm9
        vpxorq	ymm1, ymm1, ymm1
        vpxorq	ymm10, ymm10, ymm10
        vpxorq	ymm2, ymm2, ymm2
        vpxorq	ymm11, ymm11, ymm11
        vpxorq	ymm3, ymm3, ymm3
        vpxorq	ymm12, ymm12, ymm12
        vpxorq	ymm4, ymm4, ymm4
        vpxorq	ymm13, ymm13, ymm13
        vpxorq	ymm5, ymm5, ymm5
        vpxorq	ymm14, ymm14, ymm14
        vpxorq	ymm6, ymm6, ymm6
        vpxorq	ymm15, ymm15, ymm15
        vpxorq	ymm7, ymm7, ymm7
        vpxorq	ymm16, ymm16, ymm16
        vpxorq	ymm8, ymm8, ymm8
        vpxorq	ymm17, ymm17, ymm17
        vpmadd52luq	ymm0, ymm18, ymm23
        vpmadd52huq	ymm9, ymm18, ymm23
        vpmadd52luq	ymm1, ymm18, ymm24
        vpmadd52huq	ymm10, ymm18, ymm24
        vpmadd52luq	ymm2, ymm18, ymm25
        vpmadd52huq	ymm11, ymm18, ymm25
        vpmadd52luq	ymm3, ymm18, ymm26
        vpmadd52huq	ymm12, ymm18, ymm26
        vpmadd52luq	ymm4, ymm18, ymm27
        vpmadd52huq	ymm13, ymm18, ymm27
        vpmadd52luq	ymm1, ymm19, ymm23
        vpmadd52huq	ymm10, ymm19, ymm23
        vpmadd52luq	ymm2, ymm19, ymm24
        vpmadd52huq	ymm11, ymm19, ymm24
        vpmadd52luq	ymm3, ymm19, ymm25
        vpmadd52huq	ymm12, ymm19, ymm25
        vpmadd52luq	ymm4, ymm19, ymm26
        vpmadd52huq	ymm13, ymm19, ymm26
        vpmadd52luq	ymm5, ymm19, ymm27
        vpmadd52huq	ymm14, ymm19, ymm27
        vpmadd52luq	ymm2, ymm20, ymm23
        vpmadd52huq	ymm11, ymm20, ymm23
        vpmadd52luq	ymm3, ymm20, ymm24
        vpmadd52huq	ymm12, ymm20, ymm24
        vpmadd52luq	ymm4, ymm20, ymm25
        vpmadd52huq	ymm13, ymm20, ymm25
        vpmadd52luq	ymm5, ymm20, ymm26
        vpmadd52huq	ymm14, ymm20, ymm26
        vpmadd52luq	ymm6, ymm20, ymm27
        vpmadd52huq	ymm15, ymm20, ymm27
        vpmadd52luq	ymm3, ymm21, ymm23
        vpmadd52huq	ymm12, ymm21, ymm23
        vpmadd52luq	ymm4, ymm21, ymm24
        vpmadd52huq	ymm13, ymm21, ymm24
        vpmadd52luq	ymm5, ymm21, ymm25
        vpmadd52huq	ymm14, ymm21, ymm25
        vpmadd52luq	ymm6, ymm21, ymm26
        vpmadd52huq	ymm15, ymm21, ymm26
        vpmadd52luq	ymm7, ymm21, ymm27
        vpmadd52huq	ymm16, ymm21, ymm27
        vpmadd52luq	ymm4, ymm22, ymm23
        vpmadd52huq	ymm13, ymm22, ymm23
        vpmadd52luq	ymm5, ymm22, ymm24
        vpmadd52huq	ymm14, ymm22, ymm24
        vpmadd52luq	ymm6, ymm22, ymm25
        vpmadd52huq	ymm15, ymm22, ymm25
        vpmadd52luq	ymm7, ymm22, ymm26
        vpmadd52huq	ymm16, ymm22, ymm26
        vpmadd52luq	ymm8, ymm22, ymm27
        vpmadd52huq	ymm17, ymm22, ymm27
        vpaddq	ymm9, ymm9, ymm9
        vpaddq	ymm1, ymm1, ymm9
        vpaddq	ymm10, ymm10, ymm10
        vpaddq	ymm2, ymm2, ymm10
        vpaddq	ymm11, ymm11, ymm11
        vpaddq	ymm3, ymm3, ymm11
        vpaddq	ymm12, ymm12, ymm12
        vpaddq	ymm4, ymm4, ymm12
        vpaddq	ymm13, ymm13, ymm13
        vpaddq	ymm5, ymm5, ymm13
        vpaddq	ymm14, ymm14, ymm14
        vpaddq	ymm6, ymm6, ymm14
        vpaddq	ymm15, ymm15, ymm15
        vpaddq	ymm7, ymm7, ymm15
        vpaddq	ymm16, ymm16, ymm16
        vpaddq	ymm8, ymm8, ymm16
        vpaddq	ymm17, ymm17, ymm17
        ; Reduce
        vpsllq	ymm9, ymm5, 4
        vpsllq	ymm10, ymm5, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm5
        vpaddq	ymm0, ymm0, ymm9
        vpsllq	ymm9, ymm6, 4
        vpsllq	ymm10, ymm6, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm6
        vpaddq	ymm1, ymm1, ymm9
        vpsllq	ymm9, ymm7, 4
        vpsllq	ymm10, ymm7, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm7
        vpaddq	ymm2, ymm2, ymm9
        vpsllq	ymm9, ymm8, 4
        vpsllq	ymm10, ymm8, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm8
        vpaddq	ymm3, ymm3, ymm9
        vpsllq	ymm9, ymm17, 4
        vpsllq	ymm10, ymm17, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm17
        vpaddq	ymm4, ymm4, ymm9
        vpsrlq	ymm23, ymm0, 51
        vpandq	ymm0, ymm0, ymm28
        vpsrlq	ymm24, ymm1, 51
        vpandq	ymm1, ymm1, ymm28
        vpsrlq	ymm25, ymm2, 51
        vpandq	ymm2, ymm2, ymm28
        vpsrlq	ymm26, ymm3, 51
        vpandq	ymm3, ymm3, ymm28
        vpsrlq	ymm27, ymm4, 51
        vpandq	ymm4, ymm4, ymm28
        vmovdqa64	ymm18, ymm0
        vpmadd52luq	ymm18, ymm27, ymm31
        vpaddq	ymm19, ymm1, ymm23
        vpaddq	ymm20, ymm2, ymm24
        vpaddq	ymm21, ymm3, ymm25
        vpaddq	ymm22, ymm4, ymm26
        add	r12, 160
        ; To cached
        vpermq	ymm23, ymm18, 176
        vpermq	ymm24, ymm19, 176
        vpermq	ymm25, ymm20, 176
        vpermq	ymm26, ymm21, 176
        vpermq	ymm27, ymm22, 176
        vpermq	ymm18, ymm18, 181
        vpermq	ymm19, ymm19, 181
        vpermq	ymm20, ymm20, 181
        vpermq	ymm21, ymm21, 181
        vpermq	ymm22, ymm22, 181
        vpaddq	ymm18{k5}, ymm18, ymm23
        vpaddq	ymm19{k5}, ymm19, ymm24
        vpaddq	ymm20{k5}, ymm20, ymm25
        vpaddq	ymm21{k5}, ymm21, ymm26
        vpaddq	ymm22{k5}, ymm22, ymm27
        vpaddq	ymm18{k6}, ymm18, ymm29
        vpaddq	ymm19{k6}, ymm19, ymm30
        vpaddq	ymm20{k6}, ymm20, ymm30
        vpaddq	ymm21{k6}, ymm21, ymm30
        vpaddq	ymm22{k6}, ymm22, ymm30
        vpsubq	ymm18{k6}, ymm18, ymm23
        vpsubq	ymm19{k6}, ymm19, ymm24
        vpsubq	ymm20{k6}, ymm20, ymm25
        vpsubq	ymm21{k6}, ymm21, ymm26
        vpsubq	ymm22{k6}, ymm22, ymm27
        vpsrlq	ymm0, ymm18, 51
        vpandq	ymm18, ymm18, ymm28
        vpsrlq	ymm1, ymm19, 51
        vpandq	ymm19, ymm19, ymm28
        vpsrlq	ymm2, ymm20, 51
        vpandq	ymm20, ymm20, ymm28
        vpsrlq	ymm3, ymm21, 51
        vpandq	ymm21, ymm21, ymm28
        vpsrlq	ymm4, ymm22, 51
        vpandq	ymm22, ymm22, ymm28
        vpmadd52luq	ymm18, ymm4, ymm31
        vpaddq	ymm19, ymm19, ymm0
        vpaddq	ymm20, ymm20, ymm1
        vpaddq	ymm21, ymm21, ymm2
        vpaddq	ymm22, ymm22, ymm3
        vmovdqu64	ymm23, YMMWORD PTR [rsi+32]
        vmovdqu64	ymm24, YMMWORD PTR [rsi+64]
        vmovdqu64	ymm25, YMMWORD PTR [rsi+96]
        vmovdqu64	ymm26, YMMWORD PTR [rsi+128]
        vmovdqu64	ymm27, YMMWORD PTR [rsi+160]
        ; Multiply 4 field elements
        vpxorq	ymm0, ymm0, ymm0
        vpxorq	ymm9, ymm9, ymm9
        vpxorq	ymm1, ymm1, ymm1
        vpxorq	ymm10, ymm10, ymm10
        vpxorq	ymm2, ymm2, ymm2
        vpxorq	ymm11, ymm11, ymm11
        vpxorq	ymm3, ymm3, ymm3
        vpxorq	ymm12, ymm12, ymm12
        vpxorq	ymm4, ymm4, ymm4
        vpxorq	ymm13, ymm13, ymm13
        vpxorq	ymm5, ymm5, ymm5
        vpxorq	ymm14, ymm14, ymm14
        vpxorq	ymm6, ymm6, ymm6
        vpxorq	ymm15, ymm15, ymm15
        vpxorq	ymm7, ymm7, ymm7
        vpxorq	ymm16, ymm16, ymm16
        vpxorq	ymm8, ymm8, ymm8
        vpxorq	ymm17, ymm17, ymm17
        vpmadd52luq	ymm0, ymm18, ymm23
        vpmadd52huq	ymm9, ymm18, ymm23
        vpmadd52luq	ymm1, ymm18, ymm24
        vpmadd52huq	ymm10, ymm18, ymm24
        vpmadd52luq	ymm2, ymm18, ymm25
        vpmadd52huq	ymm11, ymm18, ymm25
        vpmadd52luq	ymm3, ymm18, ymm26
        vpmadd52huq	ymm12, ymm18, ymm26
        vpmadd52luq	ymm4, ymm18, ymm27
        vpmadd52huq	ymm13, ymm18, ymm27
        vpmadd52luq	ymm1, ymm19, ymm23
        vpmadd52huq	ymm10, ymm19, ymm23
        vpmadd52luq	ymm2, ymm19, ymm24
        vpmadd52huq	ymm11, ymm19, ymm24
        vpmadd52luq	ymm3, ymm19, ymm25
        vpmadd52huq	ymm12, ymm19, ymm25
        vpmadd52luq	ymm4, ymm19, ymm26
        vpmadd52huq	ymm13, ymm19, ymm26
        vpmadd52luq	ymm5, ymm19, ymm27
        vpmadd52huq	ymm14, ymm19, ymm27
        vpmadd52luq	ymm2, ymm20, ymm23
        vpmadd52huq	ymm11, ymm20, ymm23
        vpmadd52luq	ymm3, ymm20, ymm24
        vpmadd52huq	ymm12, ymm20, ymm24
        vpmadd52luq	ymm4, ymm20, ymm25
        vpmadd52huq	ymm13, ymm20, ymm25
        vpmadd52luq	ymm5, ymm20, ymm26
        vpmadd52huq	ymm14, ymm20, ymm26
        vpmadd52luq	ymm6, ymm20, ymm27
        vpmadd52huq	ymm15, ymm20, ymm27
        vpmadd52luq	ymm3, ymm21, ymm23
        vpmadd52huq	ymm12, ymm21, ymm23
        vpmadd52luq	ymm4, ymm21, ymm24
        vpmadd52huq	ymm13, ymm21, ymm24
        vpmadd52luq	ymm5, ymm21, ymm25
        vpmadd52huq	ymm14, ymm21, ymm25
        vpmadd52luq	ymm6, ymm21, ymm26
        vpmadd52huq	ymm15, ymm21, ymm26
        vpmadd52luq	ymm7, ymm21, ymm27
        vpmadd52huq	ymm16, ymm21, ymm27
        vpmadd52luq	ymm4, ymm22, ymm23
        vpmadd52huq	ymm13, ymm22, ymm23
        vpmadd52luq	ymm5, ymm22, ymm24
        vpmadd52huq	ymm14, ymm22, ymm24
        vpmadd52luq	ymm6, ymm22, ymm25
        vpmadd52huq	ymm15, ymm22, ymm25
        vpmadd52luq	ymm7, ymm22, ymm26
        vpmadd52huq	ymm16, ymm22, ymm26
        vpmadd52luq	ymm8, ymm22, ymm27
        vpmadd52huq	ymm17, ymm22, ymm27
        vpaddq	ymm9, ymm9, ymm9
        vpaddq	ymm1, ymm1, ymm9
        vpaddq	ymm10, ymm10, ymm10
        vpaddq	ymm2, ymm2, ymm10
        vpaddq	ymm11, ymm11, ymm11
        vpaddq	ymm3, ymm3, ymm11
        vpaddq	ymm12, ymm12, ymm12
        vpaddq	ymm4, ymm4, ymm12
        vpaddq	ymm13, ymm13, ymm13
        vpaddq	ymm5, ymm5, ymm13
        vpaddq	ymm14, ymm14, ymm14
        vpaddq	ymm6, ymm6, ymm14
        vpaddq	ymm15, ymm15, ymm15
        vpaddq	ymm7, ymm7, ymm15
        vpaddq	ymm16, ymm16, ymm16
        vpaddq	ymm8, ymm8, ymm16
        vpaddq	ymm17, ymm17, ymm17
        ; Reduce
        vpsllq	ymm9, ymm5, 4
        vpsllq	ymm10, ymm5, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm5
        vpaddq	ymm0, ymm0, ymm9
        vpsllq	ymm9, ymm6, 4
        vpsllq	ymm10, ymm6, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm6
        vpaddq	ymm1, ymm1, ymm9
        vpsllq	ymm9, ymm7, 4
        vpsllq	ymm10, ymm7, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm7
        vpaddq	ymm2, ymm2, ymm9
        vpsllq	ymm9, ymm8, 4
        vpsllq	ymm10, ymm8, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm8
        vpaddq	ymm3, ymm3, ymm9
        vpsllq	ymm9, ymm17, 4
        vpsllq	ymm10, ymm17, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm17
        vpaddq	ymm4, ymm4, ymm9
        vpsrlq	ymm23, ymm0, 51
        vpandq	ymm0, ymm0, ymm28
        vpsrlq	ymm24, ymm1, 51
        vpandq	ymm1, ymm1, ymm28
        vpsrlq	ymm25, ymm2, 51
        vpandq	ymm2, ymm2, ymm28
        vpsrlq	ymm26, ymm3, 51
        vpandq	ymm3, ymm3, ymm28
        vpsrlq	ymm27, ymm4, 51
        vpandq	ymm4, ymm4, ymm28
        vmovdqa64	ymm18, ymm0
        vpmadd52luq	ymm18, ymm27, ymm31
        vpaddq	ymm19, ymm1, ymm23
        vpaddq	ymm20, ymm2, ymm24
        vpaddq	ymm21, ymm3, ymm25
        vpaddq	ymm22, ymm4, ymm26
        vmovdqu64	YMMWORD PTR [r12], ymm18
        vmovdqu64	YMMWORD PTR [r12+32], ymm19
        vmovdqu64	YMMWORD PTR [r12+64], ymm20
        vmovdqu64	YMMWORD PTR [r12+96], ymm21
        vmovdqu64	YMMWORD PTR [r12+128], ymm22
        dec	r11
        jne	L_ge_dsm_avx512_ifma_table
        ; R = identity: X = 0, Y = 1, Z = 1, T = 0
        mov	r9, 1
        mov	QWORD PTR [rbp+1608], r9
        mov	r9, 0
        mov	QWORD PTR [rbp+1640], r9
        mov	QWORD PTR [rbp+1672], r9
        mov	QWORD PTR [rbp+1704], r9
        mov	QWORD PTR [rbp+1736], r9
        mov	r9, 1
        mov	QWORD PTR [rbp+1616], r9
        mov	r9, 0
        mov	QWORD PTR [rbp+1648], r9
        mov	QWORD PTR [rbp+1680], r9
        mov	QWORD PTR [rbp+1712], r9
        mov	QWORD PTR [rbp+1744], r9
        mov	r9, 0
        mov	QWORD PTR [rbp+1600], r9
        mov	QWORD PTR [rbp+1624], r9
        mov	QWORD PTR [rbp+1632], r9
        mov	QWORD PTR [rbp+1656], r9
        mov	QWORD PTR [rbp+1664], r9
        mov	QWORD PTR [rbp+1688], r9
        mov	QWORD PTR [rbp+1696], r9
        mov	QWORD PTR [rbp+1720], r9
        mov	QWORD PTR [rbp+1728], r9
        mov	QWORD PTR [rbp+1752], r9
        mov	r10, 2251799813685247
        vmovdqu64	ymm18, YMMWORD PTR [rbp+1600]
        vmovdqu64	ymm19, YMMWORD PTR [rbp+1632]
        vmovdqu64	ymm20, YMMWORD PTR [rbp+1664]
        vmovdqu64	ymm21, YMMWORD PTR [rbp+1696]
        vmovdqu64	ymm22, YMMWORD PTR [rbp+1728]
        mov	r11, 255
L_ge_dsm_avx512_ifma_bits:
        ; Double
        vpermq	ymm23, ymm18, 100
        vpermq	ymm24, ymm19, 100
        vpermq	ymm25, ymm20, 100
        vpermq	ymm26, ymm21, 100
        vpermq	ymm27, ymm22, 100
        vpermq	ymm18, ymm18, 36
        vpermq	ymm19, ymm19, 36
        vpermq	ymm20, ymm20, 36
        vpermq	ymm21, ymm21, 36
        vpermq	ymm22, ymm22, 36
        vpaddq	ymm18{k1}, ymm18, ymm23
        vpaddq	ymm19{k1}, ymm19, ymm24
        vpaddq	ymm20{k1}, ymm20, ymm25
        vpaddq	ymm21{k1}, ymm21, ymm26
        vpaddq	ymm22{k1}, ymm22, ymm27
        vpsrlq	ymm0, ymm18, 51
        vpandq	ymm18, ymm18, ymm28
        vpsrlq	ymm1, ymm19, 51
        vpandq	ymm19, ymm19, ymm28
        vpsrlq	ymm2, ymm20, 51
        vpandq	ymm20, ymm20, ymm28
        vpsrlq	ymm3, ymm21, 51
        vpandq	ymm21, ymm21, ymm28
        vpsrlq	ymm4, ymm22, 51
        vpandq	ymm22, ymm22, ymm28
        vpmadd52luq	ymm18, ymm4, ymm31
        vpaddq	ymm19, ymm19, ymm0
        vpaddq	ymm20, ymm20, ymm1
        vpaddq	ymm21, ymm21, ymm2
        vpaddq	ymm22, ymm22, ymm3
        vmovdqa64	ymm23, ymm18
        vmovdqa64	ymm24, ymm19
        vmovdqa64	ymm25, ymm20
        vmovdqa64	ymm26, ymm21
        vmovdqa64	ymm27, ymm22
        ; Multiply 4 field elements
        vpxorq	ymm0, ymm0, ymm0
        vpxorq	ymm9, ymm9, ymm9
        vpxorq	ymm1, ymm1, ymm1
        vpxorq	ymm10, ymm10, ymm10
        vpxorq	ymm2, ymm2, ymm2
        vpxorq	ymm11, ymm11, ymm11
        vpxorq	ymm3, ymm3, ymm3
        vpxorq	ymm12, ymm12, ymm12
        vpxorq	ymm4, ymm4, ymm4
        vpxorq	ymm13, ymm13, ymm13
        vpxorq	ymm5, ymm5, ymm5
        vpxorq	ymm14, ymm14, ymm14
        vpxorq	ymm6, ymm6, ymm6
        vpxorq	ymm15, ymm15, ymm15
        vpxorq	ymm7, ymm7, ymm7
        vpxorq	ymm16, ymm16, ymm16
        vpxorq	ymm8, ymm8, ymm8
        vpxorq	ymm17, ymm17, ymm17
        vpmadd52luq	ymm0, ymm18, ymm23
        vpmadd52huq	ymm9, ymm18, ymm23
        vpmadd52luq	ymm1, ymm18, ymm24
        vpmadd52huq	ymm10, ymm18, ymm24
        vpmadd52luq	ymm2, ymm18, ymm25
        vpmadd52huq	ymm11, ymm18, ymm25
        vpmadd52luq	ymm3, ymm18, ymm26
        vpmadd52huq	ymm12, ymm18, ymm26
        vpmadd52luq	ymm4, ymm18, ymm27
        vpmadd52huq	ymm13, ymm18, ymm27
        vpmadd52luq	ymm1, ymm19, ymm23
        vpmadd52huq	ymm10, ymm19, ymm23
        vpmadd52luq	ymm2, ymm19, ymm24
        vpmadd52huq	ymm11, ymm19, ymm24
        vpmadd52luq	ymm3, ymm19, ymm25
        vpmadd52huq	ymm12, ymm19, ymm25
        vpmadd52luq	ymm4, ymm19, ymm26
        vpmadd52huq	ymm13, ymm19, ymm26
        vpmadd52luq	ymm5, ymm19, ymm27
        vpmadd52huq	ymm14, ymm19, ymm27
        vpmadd52luq	ymm2, ymm20, ymm23
        vpmadd52huq	ymm11, ymm20, ymm23
        vpmadd52luq	ymm3, ymm20, ymm24
        vpmadd52huq	ymm12, ymm20, ymm24
        vpmadd52luq	ymm4, ymm20, ymm25
        vpmadd52huq	ymm13, ymm20, ymm25
        vpmadd52luq	ymm5, ymm20, ymm26
        vpmadd52huq	ymm14, ymm20, ymm26
        vpmadd52luq	ymm6, ymm20, ymm27
        vpmadd52huq	ymm15, ymm20, ymm27
        vpmadd52luq	ymm3, ymm21, ymm23
        vpmadd52huq	ymm12, ymm21, ymm23
        vpmadd52luq	ymm4, ymm21, ymm24
        vpmadd52huq	ymm13, ymm21, ymm24
        vpmadd52luq	ymm5, ymm21, ymm25
        vpmadd52huq	ymm14, ymm21, ymm25
        vpmadd52luq	ymm6, ymm21, ymm26
        vpmadd52huq	ymm15, ymm21, ymm26
        vpmadd52luq	ymm7, ymm21, ymm27
        vpmadd52huq	ymm16, ymm21, ymm27
        vpmadd52luq	ymm4, ymm22, ymm23
        vpmadd52huq	ymm13, ymm22, ymm23
        vpmadd52luq	ymm5, ymm22, ymm24
        vpmadd52huq	ymm14, ymm22, ymm24
        vpmadd52luq	ymm6, ymm22, ymm25
        vpmadd52huq	ymm15, ymm22, ymm25
        vpmadd52luq	ymm7, ymm22, ymm26
        vpmadd52huq	ymm16, ymm22, ymm26
        vpmadd52luq	ymm8, ymm22, ymm27
        vpmadd52huq	ymm17, ymm22, ymm27
        vpaddq	ymm9, ymm9, ymm9
        vpaddq	ymm1, ymm1, ymm9
        vpaddq	ymm10, ymm10, ymm10
        vpaddq	ymm2, ymm2, ymm10
        vpaddq	ymm11, ymm11, ymm11
        vpaddq	ymm3, ymm3, ymm11
        vpaddq	ymm12, ymm12, ymm12
        vpaddq	ymm4, ymm4, ymm12
        vpaddq	ymm13, ymm13, ymm13
        vpaddq	ymm5, ymm5, ymm13
        vpaddq	ymm14, ymm14, ymm14
        vpaddq	ymm6, ymm6, ymm14
        vpaddq	ymm15, ymm15, ymm15
        vpaddq	ymm7, ymm7, ymm15
        vpaddq	ymm16, ymm16, ymm16
        vpaddq	ymm8, ymm8, ymm16
        vpaddq	ymm17, ymm17, ymm17
        ; Reduce
        vpsllq	ymm9, ymm5, 4
        vpsllq	ymm10, ymm5, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm5
        vpaddq	ymm0, ymm0, ymm9
        vpsllq	ymm9, ymm6, 4
        vpsllq	ymm10, ymm6, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm6
        vpaddq	ymm1, ymm1, ymm9
        vpsllq	ymm9, ymm7, 4
        vpsllq	ymm10, ymm7, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm7
        vpaddq	ymm2, ymm2, ymm9
        vpsllq	ymm9, ymm8, 4
        vpsllq	ymm10, ymm8, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm8
        vpaddq	ymm3, ymm3, ymm9
        vpsllq	ymm9, ymm17, 4
        vpsllq	ymm10, ymm17, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm17
        vpaddq	ymm4, ymm4, ymm9
        vpsrlq	ymm23, ymm0, 51
        vpandq	ymm0, ymm0, ymm28
        vpsrlq	ymm24, ymm1, 51
        vpandq	ymm1, ymm1, ymm28
        vpsrlq	ymm25, ymm2, 51
        vpandq	ymm2, ymm2, ymm28
        vpsrlq	ymm26, ymm3, 51
        vpandq	ymm3, ymm3, ymm28
        vpsrlq	ymm27, ymm4, 51
        vpandq	ymm4, ymm4, ymm28
        vmovdqa64	ymm18, ymm0
        vpmadd52luq	ymm18, ymm27, ymm31
        vpaddq	ymm19, ymm1, ymm23
        vpaddq	ymm20, ymm2, ymm24
        vpaddq	ymm21, ymm3, ymm25
        vpaddq	ymm22, ymm4, ymm26
        ; Y3 = YY + XX, Z3 = YY - XX
        vpermq	ymm23, ymm18, 85
        vpermq	ymm24, ymm19, 85
        vpermq	ymm25, ymm20, 85
        vpermq	ymm26, ymm21, 85
        vpermq	ymm27, ymm22, 85
        vpermq	ymm0, ymm18, 0
        vpermq	ymm1, ymm19, 0
        vpermq	ymm2, ymm20, 0
        vpermq	ymm3, ymm21, 0
        vpermq	ymm4, ymm22, 0
        vpaddq	ymm5, ymm23, ymm0
        vpaddq	ymm6, ymm24, ymm1
        vpaddq	ymm7, ymm25, ymm2
        vpaddq	ymm8, ymm26, ymm3
        vpaddq	ymm9, ymm27, ymm4
        vpaddq	ymm23{k2}, ymm23, ymm29
        vpaddq	ymm24{k2}, ymm24, ymm30
        vpaddq	ymm25{k2}, ymm25, ymm30
        vpaddq	ymm26{k2}, ymm26, ymm30
        vpaddq	ymm27{k2}, ymm27, ymm30
        vpsubq	ymm5{k2}, ymm23, ymm0
        vpsubq	ymm6{k2}, ymm24, ymm1
        vpsubq	ymm7{k2}, ymm25, ymm2
        vpsubq	ymm8{k2}, ymm26, ymm3
        vpsubq	ymm9{k2}, ymm27, ymm4
        vpsrlq	ymm23, ymm5, 51
        vpandq	ymm5, ymm5, ymm28
        vpsrlq	ymm24, ymm6, 51
        vpandq	ymm6, ymm6, ymm28
        vpsrlq	ymm25, ymm7, 51
        vpandq	ymm7, ymm7, ymm28
        vpsrlq	ymm26, ymm8, 51
        vpandq	ymm8, ymm8, ymm28
        vpsrlq	ymm27, ymm9, 51
        vpandq	ymm9, ymm9, ymm28
        vpmadd52luq	ymm5, ymm27, ymm31
        vpaddq	ymm6, ymm6, ymm23
        vpaddq	ymm7, ymm7, ymm24
        vpaddq	ymm8, ymm8, ymm25
        vpaddq	ymm9, ymm9, ymm26
        ; X3 = AA - Y3, T3 = 2.ZZ - Z3
        vpermq	ymm23, ymm18, 175
        vpermq	ymm24, ymm19, 175
        vpermq	ymm25, ymm20, 175
        vpermq	ymm26, ymm21, 175
        vpermq	ymm27, ymm22, 175
        vpaddq	ymm23{k2}, ymm23, ymm23
        vpaddq	ymm24{k2}, ymm24, ymm24
        vpaddq	ymm25{k2}, ymm25, ymm25
        vpaddq	ymm26{k2}, ymm26, ymm26
        vpaddq	ymm27{k2}, ymm27, ymm27
        vpaddq	ymm23{k3}, ymm23, ymm29
        vpaddq	ymm24{k3}, ymm24, ymm30
        vpaddq	ymm25{k3}, ymm25, ymm30
        vpaddq	ymm26{k3}, ymm26, ymm30
        vpaddq	ymm27{k3}, ymm27, ymm30
        vpsubq	ymm23{k3}, ymm23, ymm5
        vpsubq	ymm24{k3}, ymm24, ymm6
        vpsubq	ymm25{k3}, ymm25, ymm7
        vpsubq	ymm26{k3}, ymm26, ymm8
        vpsubq	ymm27{k3}, ymm27, ymm9
        vpsrlq	ymm0, ymm23, 51
        vpandq	ymm23, ymm23, ymm28
        vpsrlq	ymm1, ymm24, 51
        vpandq	ymm24, ymm24, ymm28
        vpsrlq	ymm2, ymm25, 51
        vpandq	ymm25, ymm25, ymm28
        vpsrlq	ymm3, ymm26, 51
        vpandq	ymm26, ymm26, ymm28
        vpsrlq	ymm4, ymm27, 51
        vpandq	ymm27, ymm27, ymm28
        vpmadd52luq	ymm23, ymm4, ymm31
        vpaddq	ymm24, ymm24, ymm0
        vpaddq	ymm25, ymm25, ymm1
        vpaddq	ymm26, ymm26, ymm2
        vpaddq	ymm27, ymm27, ymm3
        vmovdqa64	ymm23{k4}, ymm5
        vmovdqa64	ymm24{k4}, ymm6
        vmovdqa64	ymm25{k4}, ymm7
        vmovdqa64	ymm26{k4}, ymm8
        vmovdqa64	ymm27{k4}, ymm9
        ; Add the multiple of A selected by this window digit
        movsx	r12, BYTE PTR [rbp+r11+1920]
        test	r12, r12
        je	L_ge_dsm_avx512_ifma_skip_a
        mov	r15, r12
        sar	r15, 63
        xor	r12, r15
        sub	r12, r15
        shr	r12, 1
        imul	r12, r12, 160
        lea	rdi, QWORD PTR [rbp]
        add	rdi, r12
        vmovdqu64	ymm18, YMMWORD PTR [rdi]
        vmovdqu64	ymm19, YMMWORD PTR [rdi+32]
        vmovdqu64	ymm20, YMMWORD PTR [rdi+64]
        vmovdqu64	ymm21, YMMWORD PTR [rdi+96]
        vmovdqu64	ymm22, YMMWORD PTR [rdi+128]
        test	r15, r15
        je	L_ge_dsm_avx512_ifma_noswap_a
        vpermq	ymm18, ymm18, 225
        vpermq	ymm19, ymm19, 225
        vpermq	ymm20, ymm20, 225
        vpermq	ymm21, ymm21, 225
        vpermq	ymm22, ymm22, 225
L_ge_dsm_avx512_ifma_noswap_a:
        vmovdqu64	YMMWORD PTR [rbp+1760], ymm18
        vmovdqu64	YMMWORD PTR [rbp+1792], ymm19
        vmovdqu64	YMMWORD PTR [rbp+1824], ymm20
        vmovdqu64	YMMWORD PTR [rbp+1856], ymm21
        vmovdqu64	YMMWORD PTR [rbp+1888], ymm22
        ; To p3
        vpermq	ymm18, ymm23, 36
        vpermq	ymm19, ymm24, 36
        vpermq	ymm20, ymm25, 36
        vpermq	ymm21, ymm26, 36
        vpermq	ymm22, ymm27, 36
        vpermq	ymm23, ymm23, 123
        vpermq	ymm24, ymm24, 123
        vpermq	ymm25, ymm25, 123
        vpermq	ymm26, ymm26, 123
        vpermq	ymm27, ymm27, 123
        ; Multiply 4 field elements
        vpxorq	ymm0, ymm0, ymm0
        vpxorq	ymm9, ymm9, ymm9
        vpxorq	ymm1, ymm1, ymm1
        vpxorq	ymm10, ymm10, ymm10
        vpxorq	ymm2, ymm2, ymm2
        vpxorq	ymm11, ymm11, ymm11
        vpxorq	ymm3, ymm3, ymm3
        vpxorq	ymm12, ymm12, ymm12
        vpxorq	ymm4, ymm4, ymm4
        vpxorq	ymm13, ymm13, ymm13
        vpxorq	ymm5, ymm5, ymm5
        vpxorq	ymm14, ymm14, ymm14
        vpxorq	ymm6, ymm6, ymm6
        vpxorq	ymm15, ymm15, ymm15
        vpxorq	ymm7, ymm7, ymm7
        vpxorq	ymm16, ymm16, ymm16
        vpxorq	ymm8, ymm8, ymm8
        vpxorq	ymm17, ymm17, ymm17
        vpmadd52luq	ymm0, ymm18, ymm23
        vpmadd52huq	ymm9, ymm18, ymm23
        vpmadd52luq	ymm1, ymm18, ymm24
        vpmadd52huq	ymm10, ymm18, ymm24
        vpmadd52luq	ymm2, ymm18, ymm25
        vpmadd52huq	ymm11, ymm18, ymm25
        vpmadd52luq	ymm3, ymm18, ymm26
        vpmadd52huq	ymm12, ymm18, ymm26
        vpmadd52luq	ymm4, ymm18, ymm27
        vpmadd52huq	ymm13, ymm18, ymm27
        vpmadd52luq	ymm1, ymm19, ymm23
        vpmadd52huq	ymm10, ymm19, ymm23
        vpmadd52luq	ymm2, ymm19, ymm24
        vpmadd52huq	ymm11, ymm19, ymm24
        vpmadd52luq	ymm3, ymm19, ymm25
        vpmadd52huq	ymm12, ymm19, ymm25
        vpmadd52luq	ymm4, ymm19, ymm26
        vpmadd52huq	ymm13, ymm19, ymm26
        vpmadd52luq	ymm5, ymm19, ymm27
        vpmadd52huq	ymm14, ymm19, ymm27
        vpmadd52luq	ymm2, ymm20, ymm23
        vpmadd52huq	ymm11, ymm20, ymm23
        vpmadd52luq	ymm3, ymm20, ymm24
        vpmadd52huq	ymm12, ymm20, ymm24
        vpmadd52luq	ymm4, ymm20, ymm25
        vpmadd52huq	ymm13, ymm20, ymm25
        vpmadd52luq	ymm5, ymm20, ymm26
        vpmadd52huq	ymm14, ymm20, ymm26
        vpmadd52luq	ymm6, ymm20, ymm27
        vpmadd52huq	ymm15, ymm20, ymm27
        vpmadd52luq	ymm3, ymm21, ymm23
        vpmadd52huq	ymm12, ymm21, ymm23
        vpmadd52luq	ymm4, ymm21, ymm24
        vpmadd52huq	ymm13, ymm21, ymm24
        vpmadd52luq	ymm5, ymm21, ymm25
        vpmadd52huq	ymm14, ymm21, ymm25
        vpmadd52luq	ymm6, ymm21, ymm26
        vpmadd52huq	ymm15, ymm21, ymm26
        vpmadd52luq	ymm7, ymm21, ymm27
        vpmadd52huq	ymm16, ymm21, ymm27
        vpmadd52luq	ymm4, ymm22, ymm23
        vpmadd52huq	ymm13, ymm22, ymm23
        vpmadd52luq	ymm5, ymm22, ymm24
        vpmadd52huq	ymm14, ymm22, ymm24
        vpmadd52luq	ymm6, ymm22, ymm25
        vpmadd52huq	ymm15, ymm22, ymm25
        vpmadd52luq	ymm7, ymm22, ymm26
        vpmadd52huq	ymm16, ymm22, ymm26
        vpmadd52luq	ymm8, ymm22, ymm27
        vpmadd52huq	ymm17, ymm22, ymm27
        vpaddq	ymm9, ymm9, ymm9
        vpaddq	ymm1, ymm1, ymm9
        vpaddq	ymm10, ymm10, ymm10
        vpaddq	ymm2, ymm2, ymm10
        vpaddq	ymm11, ymm11, ymm11
        vpaddq	ymm3, ymm3, ymm11
        vpaddq	ymm12, ymm12, ymm12
        vpaddq	ymm4, ymm4, ymm12
        vpaddq	ymm13, ymm13, ymm13
        vpaddq	ymm5, ymm5, ymm13
        vpaddq	ymm14, ymm14, ymm14
        vpaddq	ymm6, ymm6, ymm14
        vpaddq	ymm15, ymm15, ymm15
        vpaddq	ymm7, ymm7, ymm15
        vpaddq	ymm16, ymm16, ymm16
        vpaddq	ymm8, ymm8, ymm16
        vpaddq	ymm17, ymm17, ymm17
        ; Reduce
        vpsllq	ymm9, ymm5, 4
        vpsllq	ymm10, ymm5, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm5
        vpaddq	ymm0, ymm0, ymm9
        vpsllq	ymm9, ymm6, 4
        vpsllq	ymm10, ymm6, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm6
        vpaddq	ymm1, ymm1, ymm9
        vpsllq	ymm9, ymm7, 4
        vpsllq	ymm10, ymm7, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm7
        vpaddq	ymm2, ymm2, ymm9
        vpsllq	ymm9, ymm8, 4
        vpsllq	ymm10, ymm8, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm8
        vpaddq	ymm3, ymm3, ymm9
        vpsllq	ymm9, ymm17, 4
        vpsllq	ymm10, ymm17, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm17
        vpaddq	ymm4, ymm4, ymm9
        vpsrlq	ymm23, ymm0, 51
        vpandq	ymm0, ymm0, ymm28
        vpsrlq	ymm24, ymm1, 51
        vpandq	ymm1, ymm1, ymm28
        vpsrlq	ymm25, ymm2, 51
        vpandq	ymm2, ymm2, ymm28
        vpsrlq	ymm26, ymm3, 51
        vpandq	ymm3, ymm3, ymm28
        vpsrlq	ymm27, ymm4, 51
        vpandq	ymm4, ymm4, ymm28
        vmovdqa64	ymm18, ymm0
        vpmadd52luq	ymm18, ymm27, ymm31
        vpaddq	ymm19, ymm1, ymm23
        vpaddq	ymm20, ymm2, ymm24
        vpaddq	ymm21, ymm3, ymm25
        vpaddq	ymm22, ymm4, ymm26
        ; Add
        vpermq	ymm23, ymm18, 176
        vpermq	ymm24, ymm19, 176
        vpermq	ymm25, ymm20, 176
        vpermq	ymm26, ymm21, 176
        vpermq	ymm27, ymm22, 176
        vpermq	ymm18, ymm18, 181
        vpermq	ymm19, ymm19, 181
        vpermq	ymm20, ymm20, 181
        vpermq	ymm21, ymm21, 181
        vpermq	ymm22, ymm22, 181
        vpaddq	ymm18{k5}, ymm18, ymm23
        vpaddq	ymm19{k5}, ymm19, ymm24
        vpaddq	ymm20{k5}, ymm20, ymm25
        vpaddq	ymm21{k5}, ymm21, ymm26
        vpaddq	ymm22{k5}, ymm22, ymm27
        vpaddq	ymm18{k6}, ymm18, ymm29
        vpaddq	ymm19{k6}, ymm19, ymm30
        vpaddq	ymm20{k6}, ymm20, ymm30
        vpaddq	ymm21{k6}, ymm21, ymm30
        vpaddq	ymm22{k6}, ymm22, ymm30
        vpsubq	ymm18{k6}, ymm18, ymm23
        vpsubq	ymm19{k6}, ymm19, ymm24
        vpsubq	ymm20{k6}, ymm20, ymm25
        vpsubq	ymm21{k6}, ymm21, ymm26
        vpsubq	ymm22{k6}, ymm22, ymm27
        vpsrlq	ymm0, ymm18, 51
        vpandq	ymm18, ymm18, ymm28
        vpsrlq	ymm1, ymm19, 51
        vpandq	ymm19, ymm19, ymm28
        vpsrlq	ymm2, ymm20, 51
        vpandq	ymm20, ymm20, ymm28
        vpsrlq	ymm3, ymm21, 51
        vpandq	ymm21, ymm21, ymm28
        vpsrlq	ymm4, ymm22, 51
        vpandq	ymm22, ymm22, ymm28
        vpmadd52luq	ymm18, ymm4, ymm31
        vpaddq	ymm19, ymm19, ymm0
        vpaddq	ymm20, ymm20, ymm1
        vpaddq	ymm21, ymm21, ymm2
        vpaddq	ymm22, ymm22, ymm3
        vmovdqu64	ymm23, YMMWORD PTR [rbp+1760]
        vmovdqu64	ymm24, YMMWORD PTR [rbp+1792]
        vmovdqu64	ymm25, YMMWORD PTR [rbp+1824]
        vmovdqu64	ymm26, YMMWORD PTR [rbp+1856]
        vmovdqu64	ymm27, YMMWORD PTR [rbp+1888]
        ; Multiply 4 field elements
        vpxorq	ymm0, ymm0, ymm0
        vpxorq	ymm9, ymm9, ymm9
        vpxorq	ymm1, ymm1, ymm1
        vpxorq	ymm10, ymm10, ymm10
        vpxorq	ymm2, ymm2, ymm2
        vpxorq	ymm11, ymm11, ymm11
        vpxorq	ymm3, ymm3, ymm3
        vpxorq	ymm12, ymm12, ymm12
        vpxorq	ymm4, ymm4, ymm4
        vpxorq	ymm13, ymm13, ymm13
        vpxorq	ymm5, ymm5, ymm5
        vpxorq	ymm14, ymm14, ymm14
        vpxorq	ymm6, ymm6, ymm6
        vpxorq	ymm15, ymm15, ymm15
        vpxorq	ymm7, ymm7, ymm7
        vpxorq	ymm16, ymm16, ymm16
        vpxorq	ymm8, ymm8, ymm8
        vpxorq	ymm17, ymm17, ymm17
        vpmadd52luq	ymm0, ymm18, ymm23
        vpmadd52huq	ymm9, ymm18, ymm23
        vpmadd52luq	ymm1, ymm18, ymm24
        vpmadd52huq	ymm10, ymm18, ymm24
        vpmadd52luq	ymm2, ymm18, ymm25
        vpmadd52huq	ymm11, ymm18, ymm25
        vpmadd52luq	ymm3, ymm18, ymm26
        vpmadd52huq	ymm12, ymm18, ymm26
        vpmadd52luq	ymm4, ymm18, ymm27
        vpmadd52huq	ymm13, ymm18, ymm27
        vpmadd52luq	ymm1, ymm19, ymm23
        vpmadd52huq	ymm10, ymm19, ymm23
        vpmadd52luq	ymm2, ymm19, ymm24
        vpmadd52huq	ymm11, ymm19, ymm24
        vpmadd52luq	ymm3, ymm19, ymm25
        vpmadd52huq	ymm12, ymm19, ymm25
        vpmadd52luq	ymm4, ymm19, ymm26
        vpmadd52huq	ymm13, ymm19, ymm26
        vpmadd52luq	ymm5, ymm19, ymm27
        vpmadd52huq	ymm14, ymm19, ymm27
        vpmadd52luq	ymm2, ymm20, ymm23
        vpmadd52huq	ymm11, ymm20, ymm23
        vpmadd52luq	ymm3, ymm20, ymm24
        vpmadd52huq	ymm12, ymm20, ymm24
        vpmadd52luq	ymm4, ymm20, ymm25
        vpmadd52huq	ymm13, ymm20, ymm25
        vpmadd52luq	ymm5, ymm20, ymm26
        vpmadd52huq	ymm14, ymm20, ymm26
        vpmadd52luq	ymm6, ymm20, ymm27
        vpmadd52huq	ymm15, ymm20, ymm27
        vpmadd52luq	ymm3, ymm21, ymm23
        vpmadd52huq	ymm12, ymm21, ymm23
        vpmadd52luq	ymm4, ymm21, ymm24
        vpmadd52huq	ymm13, ymm21, ymm24
        vpmadd52luq	ymm5, ymm21, ymm25
        vpmadd52huq	ymm14, ymm21, ymm25
        vpmadd52luq	ymm6, ymm21, ymm26
        vpmadd52huq	ymm15, ymm21, ymm26
        vpmadd52luq	ymm7, ymm21, ymm27
        vpmadd52huq	ymm16, ymm21, ymm27
        vpmadd52luq	ymm4, ymm22, ymm23
        vpmadd52huq	ymm13, ymm22, ymm23
        vpmadd52luq	ymm5, ymm22, ymm24
        vpmadd52huq	ymm14, ymm22, ymm24
        vpmadd52luq	ymm6, ymm22, ymm25
        vpmadd52huq	ymm15, ymm22, ymm25
        vpmadd52luq	ymm7, ymm22, ymm26
        vpmadd52huq	ymm16, ymm22, ymm26
        vpmadd52luq	ymm8, ymm22, ymm27
        vpmadd52huq	ymm17, ymm22, ymm27
        vpaddq	ymm9, ymm9, ymm9
        vpaddq	ymm1, ymm1, ymm9
        vpaddq	ymm10, ymm10, ymm10
        vpaddq	ymm2, ymm2, ymm10
        vpaddq	ymm11, ymm11, ymm11
        vpaddq	ymm3, ymm3, ymm11
        vpaddq	ymm12, ymm12, ymm12
        vpaddq	ymm4, ymm4, ymm12
        vpaddq	ymm13, ymm13, ymm13
        vpaddq	ymm5, ymm5, ymm13
        vpaddq	ymm14, ymm14, ymm14
        vpaddq	ymm6, ymm6, ymm14
        vpaddq	ymm15, ymm15, ymm15
        vpaddq	ymm7, ymm7, ymm15
        vpaddq	ymm16, ymm16, ymm16
        vpaddq	ymm8, ymm8, ymm16
        vpaddq	ymm17, ymm17, ymm17
        ; Reduce
        vpsllq	ymm9, ymm5, 4
        vpsllq	ymm10, ymm5, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm5
        vpaddq	ymm0, ymm0, ymm9
        vpsllq	ymm9, ymm6, 4
        vpsllq	ymm10, ymm6, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm6
        vpaddq	ymm1, ymm1, ymm9
        vpsllq	ymm9, ymm7, 4
        vpsllq	ymm10, ymm7, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm7
        vpaddq	ymm2, ymm2, ymm9
        vpsllq	ymm9, ymm8, 4
        vpsllq	ymm10, ymm8, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm8
        vpaddq	ymm3, ymm3, ymm9
        vpsllq	ymm9, ymm17, 4
        vpsllq	ymm10, ymm17, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm17
        vpaddq	ymm4, ymm4, ymm9
        vpsrlq	ymm23, ymm0, 51
        vpandq	ymm0, ymm0, ymm28
        vpsrlq	ymm24, ymm1, 51
        vpandq	ymm1, ymm1, ymm28
        vpsrlq	ymm25, ymm2, 51
        vpandq	ymm2, ymm2, ymm28
        vpsrlq	ymm26, ymm3, 51
        vpandq	ymm3, ymm3, ymm28
        vpsrlq	ymm27, ymm4, 51
        vpandq	ymm4, ymm4, ymm28
        vmovdqa64	ymm18, ymm0
        vpmadd52luq	ymm18, ymm27, ymm31
        vpaddq	ymm19, ymm1, ymm23
        vpaddq	ymm20, ymm2, ymm24
        vpaddq	ymm21, ymm3, ymm25
        vpaddq	ymm22, ymm4, ymm26
        ; X3 = B - A, Y3 = B + A, Z3 = D + C, T3 = D - C
        vpermq	ymm23, ymm18, 240
        vpermq	ymm24, ymm19, 240
        vpermq	ymm25, ymm20, 240
        vpermq	ymm26, ymm21, 240
        vpermq	ymm27, ymm22, 240
        vpaddq	ymm23{k2}, ymm23, ymm23
        vpaddq	ymm24{k2}, ymm24, ymm24
        vpaddq	ymm25{k2}, ymm25, ymm25
        vpaddq	ymm26{k2}, ymm26, ymm26
        vpaddq	ymm27{k2}, ymm27, ymm27
        vpermq	ymm0, ymm18, 165
        vpermq	ymm1, ymm19, 165
        vpermq	ymm2, ymm20, 165
        vpermq	ymm3, ymm21, 165
        vpermq	ymm4, ymm22, 165
        vpaddq	ymm18, ymm23, ymm0
        vpaddq	ymm19, ymm24, ymm1
        vpaddq	ymm20, ymm25, ymm2
        vpaddq	ymm21, ymm26, ymm3
        vpaddq	ymm22, ymm27, ymm4
        vpaddq	ymm23{k3}, ymm23, ymm29
        vpaddq	ymm24{k3}, ymm24, ymm30
        vpaddq	ymm25{k3}, ymm25, ymm30
        vpaddq	ymm26{k3}, ymm26, ymm30
        vpaddq	ymm27{k3}, ymm27, ymm30
        vpsubq	ymm18{k3}, ymm23, ymm0
        vpsubq	ymm19{k3}, ymm24, ymm1
        vpsubq	ymm20{k3}, ymm25, ymm2
        vpsubq	ymm21{k3}, ymm26, ymm3
        vpsubq	ymm22{k3}, ymm27, ymm4
        vpsrlq	ymm5, ymm18, 51
        vpandq	ymm18, ymm18, ymm28
        vpsrlq	ymm6, ymm19, 51
        vpandq	ymm19, ymm19, ymm28
        vpsrlq	ymm7, ymm20, 51
        vpandq	ymm20, ymm20, ymm28
        vpsrlq	ymm8, ymm21, 51
        vpandq	ymm21, ymm21, ymm28
        vpsrlq	ymm9, ymm22, 51
        vpandq	ymm22, ymm22, ymm28
        vpmadd52luq	ymm18, ymm9, ymm31
        vpaddq	ymm19, ymm19, ymm5
        vpaddq	ymm20, ymm20, ymm6
        vpaddq	ymm21, ymm21, ymm7
        vpaddq	ymm22, ymm22, ymm8
        test	r15, r15
        je	L_ge_dsm_avx512_ifma_nores_a
        vpermq	ymm18, ymm18, 180
        vpermq	ymm19, ymm19, 180
        vpermq	ymm20, ymm20, 180
        vpermq	ymm21, ymm21, 180
        vpermq	ymm22, ymm22, 180
L_ge_dsm_avx512_ifma_nores_a:
        vmovdqa64	ymm23, ymm18
        vmovdqa64	ymm24, ymm19
        vmovdqa64	ymm25, ymm20
        vmovdqa64	ymm26, ymm21
        vmovdqa64	ymm27, ymm22
L_ge_dsm_avx512_ifma_skip_a:
        ; Add the multiple of the base point
        movsx	r12, BYTE PTR [rbp+r11+2176]
        test	r12, r12
        je	L_ge_dsm_avx512_ifma_skip_b
        mov	r15, r12
        sar	r15, 63
        xor	r12, r15
        sub	r12, r15
        shr	r12, 1
        imul	r12, r12, 96
        mov	rdi, rbx
        add	rdi, r12
        mov	rdx, QWORD PTR [rdi]
        mov	rax, QWORD PTR [rdi+8]
        mov	rcx, QWORD PTR [rdi+16]
        mov	r8, QWORD PTR [rdi+24]
        mov	r9, r8
        shr	r9, 63
        imul	r9, r9, 19
        shl	r8, 1
        shr	r8, 1
        mov	r13, rdx
        and	r13, r10
        add	r13, r9
        mov	QWORD PTR [rbp+1760], r13
        shrd	rdx, rax, 51
        mov	r9, rdx
        and	r9, r10
        mov	QWORD PTR [rbp+1792], r9
        shrd	rax, rcx, 38
        mov	r9, rax
        and	r9, r10
        mov	QWORD PTR [rbp+1824], r9
        shrd	rcx, r8, 25
        mov	r9, rcx
        and	r9, r10
        mov	QWORD PTR [rbp+1856], r9
        shr	r8, 12
        mov	QWORD PTR [rbp+1888], r8
        mov	rdx, QWORD PTR [rdi+32]
        mov	rax, QWORD PTR [rdi+40]
        mov	rcx, QWORD PTR [rdi+48]
        mov	r8, QWORD PTR [rdi+56]
        mov	r9, r8
        shr	r9, 63
        imul	r9, r9, 19
        shl	r8, 1
        shr	r8, 1
        mov	r13, rdx
        and	r13, r10
        add	r13, r9
        mov	QWORD PTR [rbp+1768], r13
        shrd	rdx, rax, 51
        mov	r9, rdx
        and	r9, r10
        mov	QWORD PTR [rbp+1800], r9
        shrd	rax, rcx, 38
        mov	r9, rax
        and	r9, r10
        mov	QWORD PTR [rbp+1832], r9
        shrd	rcx, r8, 25
        mov	r9, rcx
        and	r9, r10
        mov	QWORD PTR [rbp+1864], r9
        shr	r8, 12
        mov	QWORD PTR [rbp+1896], r8
        mov	rdx, QWORD PTR [rdi+64]
        mov	rax, QWORD PTR [rdi+72]
        mov	rcx, QWORD PTR [rdi+80]
        mov	r8, QWORD PTR [rdi+88]
        mov	r9, r8
        shr	r9, 63
        imul	r9, r9, 19
        shl	r8, 1
        shr	r8, 1
        mov	r13, rdx
        and	r13, r10
        add	r13, r9
        mov	QWORD PTR [rbp+1776], r13
        shrd	rdx, rax, 51
        mov	r9, rdx
        and	r9, r10
        mov	QWORD PTR [rbp+1808], r9
        shrd	rax, rcx, 38
        mov	r9, rax
        and	r9, r10
        mov	QWORD PTR [rbp+1840], r9
        shrd	rcx, r8, 25
        mov	r9, rcx
        and	r9, r10
        mov	QWORD PTR [rbp+1872], r9
        shr	r8, 12
        mov	QWORD PTR [rbp+1904], r8
        mov	rdx, 1
        mov	QWORD PTR [rbp+1784], rdx
        mov	rdx, 0
        mov	QWORD PTR [rbp+1816], rdx
        mov	QWORD PTR [rbp+1848], rdx
        mov	QWORD PTR [rbp+1880], rdx
        mov	QWORD PTR [rbp+1912], rdx
        test	r15, r15
        je	L_ge_dsm_avx512_ifma_noswap_b
        vmovdqu64	ymm18, YMMWORD PTR [rbp+1760]
        vmovdqu64	ymm19, YMMWORD PTR [rbp+1792]
        vmovdqu64	ymm20, YMMWORD PTR [rbp+1824]
        vmovdqu64	ymm21, YMMWORD PTR [rbp+1856]
        vmovdqu64	ymm22, YMMWORD PTR [rbp+1888]
        vpermq	ymm18, ymm18, 225
        vpermq	ymm19, ymm19, 225
        vpermq	ymm20, ymm20, 225
        vpermq	ymm21, ymm21, 225
        vpermq	ymm22, ymm22, 225
        vmovdqu64	YMMWORD PTR [rbp+1760], ymm18
        vmovdqu64	YMMWORD PTR [rbp+1792], ymm19
        vmovdqu64	YMMWORD PTR [rbp+1824], ymm20
        vmovdqu64	YMMWORD PTR [rbp+1856], ymm21
        vmovdqu64	YMMWORD PTR [rbp+1888], ymm22
L_ge_dsm_avx512_ifma_noswap_b:
        ; To p3
        vpermq	ymm18, ymm23, 36
        vpermq	ymm19, ymm24, 36
        vpermq	ymm20, ymm25, 36
        vpermq	ymm21, ymm26, 36
        vpermq	ymm22, ymm27, 36
        vpermq	ymm23, ymm23, 123
        vpermq	ymm24, ymm24, 123
        vpermq	ymm25, ymm25, 123
        vpermq	ymm26, ymm26, 123
        vpermq	ymm27, ymm27, 123
        ; Multiply 4 field elements
        vpxorq	ymm0, ymm0, ymm0
        vpxorq	ymm9, ymm9, ymm9
        vpxorq	ymm1, ymm1, ymm1
        vpxorq	ymm10, ymm10, ymm10
        vpxorq	ymm2, ymm2, ymm2
        vpxorq	ymm11, ymm11, ymm11
        vpxorq	ymm3, ymm3, ymm3
        vpxorq	ymm12, ymm12, ymm12
        vpxorq	ymm4, ymm4, ymm4
        vpxorq	ymm13, ymm13, ymm13
        vpxorq	ymm5, ymm5, ymm5
        vpxorq	ymm14, ymm14, ymm14
        vpxorq	ymm6, ymm6, ymm6
        vpxorq	ymm15, ymm15, ymm15
        vpxorq	ymm7, ymm7, ymm7
        vpxorq	ymm16, ymm16, ymm16
        vpxorq	ymm8, ymm8, ymm8
        vpxorq	ymm17, ymm17, ymm17
        vpmadd52luq	ymm0, ymm18, ymm23
        vpmadd52huq	ymm9, ymm18, ymm23
        vpmadd52luq	ymm1, ymm18, ymm24
        vpmadd52huq	ymm10, ymm18, ymm24
        vpmadd52luq	ymm2, ymm18, ymm25
        vpmadd52huq	ymm11, ymm18, ymm25
        vpmadd52luq	ymm3, ymm18, ymm26
        vpmadd52huq	ymm12, ymm18, ymm26
        vpmadd52luq	ymm4, ymm18, ymm27
        vpmadd52huq	ymm13, ymm18, ymm27
        vpmadd52luq	ymm1, ymm19, ymm23
        vpmadd52huq	ymm10, ymm19, ymm23
        vpmadd52luq	ymm2, ymm19, ymm24
        vpmadd52huq	ymm11, ymm19, ymm24
        vpmadd52luq	ymm3, ymm19, ymm25
        vpmadd52huq	ymm12, ymm19, ymm25
        vpmadd52luq	ymm4, ymm19, ymm26
        vpmadd52huq	ymm13, ymm19, ymm26
        vpmadd52luq	ymm5, ymm19, ymm27
        vpmadd52huq	ymm14, ymm19, ymm27
        vpmadd52luq	ymm2, ymm20, ymm23
        vpmadd52huq	ymm11, ymm20, ymm23
        vpmadd52luq	ymm3, ymm20, ymm24
        vpmadd52huq	ymm12, ymm20, ymm24
        vpmadd52luq	ymm4, ymm20, ymm25
        vpmadd52huq	ymm13, ymm20, ymm25
        vpmadd52luq	ymm5, ymm20, ymm26
        vpmadd52huq	ymm14, ymm20, ymm26
        vpmadd52luq	ymm6, ymm20, ymm27
        vpmadd52huq	ymm15, ymm20, ymm27
        vpmadd52luq	ymm3, ymm21, ymm23
        vpmadd52huq	ymm12, ymm21, ymm23
        vpmadd52luq	ymm4, ymm21, ymm24
        vpmadd52huq	ymm13, ymm21, ymm24
        vpmadd52luq	ymm5, ymm21, ymm25
        vpmadd52huq	ymm14, ymm21, ymm25
        vpmadd52luq	ymm6, ymm21, ymm26
        vpmadd52huq	ymm15, ymm21, ymm26
        vpmadd52luq	ymm7, ymm21, ymm27
        vpmadd52huq	ymm16, ymm21, ymm27
        vpmadd52luq	ymm4, ymm22, ymm23
        vpmadd52huq	ymm13, ymm22, ymm23
        vpmadd52luq	ymm5, ymm22, ymm24
        vpmadd52huq	ymm14, ymm22, ymm24
        vpmadd52luq	ymm6, ymm22, ymm25
        vpmadd52huq	ymm15, ymm22, ymm25
        vpmadd52luq	ymm7, ymm22, ymm26
        vpmadd52huq	ymm16, ymm22, ymm26
        vpmadd52luq	ymm8, ymm22, ymm27
        vpmadd52huq	ymm17, ymm22, ymm27
        vpaddq	ymm9, ymm9, ymm9
        vpaddq	ymm1, ymm1, ymm9
        vpaddq	ymm10, ymm10, ymm10
        vpaddq	ymm2, ymm2, ymm10
        vpaddq	ymm11, ymm11, ymm11
        vpaddq	ymm3, ymm3, ymm11
        vpaddq	ymm12, ymm12, ymm12
        vpaddq	ymm4, ymm4, ymm12
        vpaddq	ymm13, ymm13, ymm13
        vpaddq	ymm5, ymm5, ymm13
        vpaddq	ymm14, ymm14, ymm14
        vpaddq	ymm6, ymm6, ymm14
        vpaddq	ymm15, ymm15, ymm15
        vpaddq	ymm7, ymm7, ymm15
        vpaddq	ymm16, ymm16, ymm16
        vpaddq	ymm8, ymm8, ymm16
        vpaddq	ymm17, ymm17, ymm17
        ; Reduce
        vpsllq	ymm9, ymm5, 4
        vpsllq	ymm10, ymm5, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm5
        vpaddq	ymm0, ymm0, ymm9
        vpsllq	ymm9, ymm6, 4
        vpsllq	ymm10, ymm6, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm6
        vpaddq	ymm1, ymm1, ymm9
        vpsllq	ymm9, ymm7, 4
        vpsllq	ymm10, ymm7, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm7
        vpaddq	ymm2, ymm2, ymm9
        vpsllq	ymm9, ymm8, 4
        vpsllq	ymm10, ymm8, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm8
        vpaddq	ymm3, ymm3, ymm9
        vpsllq	ymm9, ymm17, 4
        vpsllq	ymm10, ymm17, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm17
        vpaddq	ymm4, ymm4, ymm9
        vpsrlq	ymm23, ymm0, 51
        vpandq	ymm0, ymm0, ymm28
        vpsrlq	ymm24, ymm1, 51
        vpandq	ymm1, ymm1, ymm28
        vpsrlq	ymm25, ymm2, 51
        vpandq	ymm2, ymm2, ymm28
        vpsrlq	ymm26, ymm3, 51
        vpandq	ymm3, ymm3, ymm28
        vpsrlq	ymm27, ymm4, 51
        vpandq	ymm4, ymm4, ymm28
        vmovdqa64	ymm18, ymm0
        vpmadd52luq	ymm18, ymm27, ymm31
        vpaddq	ymm19, ymm1, ymm23
        vpaddq	ymm20, ymm2, ymm24
        vpaddq	ymm21, ymm3, ymm25
        vpaddq	ymm22, ymm4, ymm26
        ; Add
        vpermq	ymm23, ymm18, 176
        vpermq	ymm24, ymm19, 176
        vpermq	ymm25, ymm20, 176
        vpermq	ymm26, ymm21, 176
        vpermq	ymm27, ymm22, 176
        vpermq	ymm18, ymm18, 181
        vpermq	ymm19, ymm19, 181
        vpermq	ymm20, ymm20, 181
        vpermq	ymm21, ymm21, 181
        vpermq	ymm22, ymm22, 181
        vpaddq	ymm18{k5}, ymm18, ymm23
        vpaddq	ymm19{k5}, ymm19, ymm24
        vpaddq	ymm20{k5}, ymm20, ymm25
        vpaddq	ymm21{k5}, ymm21, ymm26
        vpaddq	ymm22{k5}, ymm22, ymm27
        vpaddq	ymm18{k6}, ymm18, ymm29
        vpaddq	ymm19{k6}, ymm19, ymm30
        vpaddq	ymm20{k6}, ymm20, ymm30
        vpaddq	ymm21{k6}, ymm21, ymm30
        vpaddq	ymm22{k6}, ymm22, ymm30
        vpsubq	ymm18{k6}, ymm18, ymm23
        vpsubq	ymm19{k6}, ymm19, ymm24
        vpsubq	ymm20{k6}, ymm20, ymm25
        vpsubq	ymm21{k6}, ymm21, ymm26
        vpsubq	ymm22{k6}, ymm22, ymm27
        vpsrlq	ymm0, ymm18, 51
        vpandq	ymm18, ymm18, ymm28
        vpsrlq	ymm1, ymm19, 51
        vpandq	ymm19, ymm19, ymm28
        vpsrlq	ymm2, ymm20, 51
        vpandq	ymm20, ymm20, ymm28
        vpsrlq	ymm3, ymm21, 51
        vpandq	ymm21, ymm21, ymm28
        vpsrlq	ymm4, ymm22, 51
        vpandq	ymm22, ymm22, ymm28
        vpmadd52luq	ymm18, ymm4, ymm31
        vpaddq	ymm19, ymm19, ymm0
        vpaddq	ymm20, ymm20, ymm1
        vpaddq	ymm21, ymm21, ymm2
        vpaddq	ymm22, ymm22, ymm3
        vmovdqu64	ymm23, YMMWORD PTR [rbp+1760]
        vmovdqu64	ymm24, YMMWORD PTR [rbp+1792]
        vmovdqu64	ymm25, YMMWORD PTR [rbp+1824]
        vmovdqu64	ymm26, YMMWORD PTR [rbp+1856]
        vmovdqu64	ymm27, YMMWORD PTR [rbp+1888]
        ; Multiply 4 field elements
        vpxorq	ymm0, ymm0, ymm0
        vpxorq	ymm9, ymm9, ymm9
        vpxorq	ymm1, ymm1, ymm1
        vpxorq	ymm10, ymm10, ymm10
        vpxorq	ymm2, ymm2, ymm2
        vpxorq	ymm11, ymm11, ymm11
        vpxorq	ymm3, ymm3, ymm3
        vpxorq	ymm12, ymm12, ymm12
        vpxorq	ymm4, ymm4, ymm4
        vpxorq	ymm13, ymm13, ymm13
        vpxorq	ymm5, ymm5, ymm5
        vpxorq	ymm14, ymm14, ymm14
        vpxorq	ymm6, ymm6, ymm6
        vpxorq	ymm15, ymm15, ymm15
        vpxorq	ymm7, ymm7, ymm7
        vpxorq	ymm16, ymm16, ymm16
        vpxorq	ymm8, ymm8, ymm8
        vpxorq	ymm17, ymm17, ymm17
        vpmadd52luq	ymm0, ymm18, ymm23
        vpmadd52huq	ymm9, ymm18, ymm23
        vpmadd52luq	ymm1, ymm18, ymm24
        vpmadd52huq	ymm10, ymm18, ymm24
        vpmadd52luq	ymm2, ymm18, ymm25
        vpmadd52huq	ymm11, ymm18, ymm25
        vpmadd52luq	ymm3, ymm18, ymm26
        vpmadd52huq	ymm12, ymm18, ymm26
        vpmadd52luq	ymm4, ymm18, ymm27
        vpmadd52huq	ymm13, ymm18, ymm27
        vpmadd52luq	ymm1, ymm19, ymm23
        vpmadd52huq	ymm10, ymm19, ymm23
        vpmadd52luq	ymm2, ymm19, ymm24
        vpmadd52huq	ymm11, ymm19, ymm24
        vpmadd52luq	ymm3, ymm19, ymm25
        vpmadd52huq	ymm12, ymm19, ymm25
        vpmadd52luq	ymm4, ymm19, ymm26
        vpmadd52huq	ymm13, ymm19, ymm26
        vpmadd52luq	ymm5, ymm19, ymm27
        vpmadd52huq	ymm14, ymm19, ymm27
        vpmadd52luq	ymm2, ymm20, ymm23
        vpmadd52huq	ymm11, ymm20, ymm23
        vpmadd52luq	ymm3, ymm20, ymm24
        vpmadd52huq	ymm12, ymm20, ymm24
        vpmadd52luq	ymm4, ymm20, ymm25
        vpmadd52huq	ymm13, ymm20, ymm25
        vpmadd52luq	ymm5, ymm20, ymm26
        vpmadd52huq	ymm14, ymm20, ymm26
        vpmadd52luq	ymm6, ymm20, ymm27
        vpmadd52huq	ymm15, ymm20, ymm27
        vpmadd52luq	ymm3, ymm21, ymm23
        vpmadd52huq	ymm12, ymm21, ymm23
        vpmadd52luq	ymm4, ymm21, ymm24
        vpmadd52huq	ymm13, ymm21, ymm24
        vpmadd52luq	ymm5, ymm21, ymm25
        vpmadd52huq	ymm14, ymm21, ymm25
        vpmadd52luq	ymm6, ymm21, ymm26
        vpmadd52huq	ymm15, ymm21, ymm26
        vpmadd52luq	ymm7, ymm21, ymm27
        vpmadd52huq	ymm16, ymm21, ymm27
        vpmadd52luq	ymm4, ymm22, ymm23
        vpmadd52huq	ymm13, ymm22, ymm23
        vpmadd52luq	ymm5, ymm22, ymm24
        vpmadd52huq	ymm14, ymm22, ymm24
        vpmadd52luq	ymm6, ymm22, ymm25
        vpmadd52huq	ymm15, ymm22, ymm25
        vpmadd52luq	ymm7, ymm22, ymm26
        vpmadd52huq	ymm16, ymm22, ymm26
        vpmadd52luq	ymm8, ymm22, ymm27
        vpmadd52huq	ymm17, ymm22, ymm27
        vpaddq	ymm9, ymm9, ymm9
        vpaddq	ymm1, ymm1, ymm9
        vpaddq	ymm10, ymm10, ymm10
        vpaddq	ymm2, ymm2, ymm10
        vpaddq	ymm11, ymm11, ymm11
        vpaddq	ymm3, ymm3, ymm11
        vpaddq	ymm12, ymm12, ymm12
        vpaddq	ymm4, ymm4, ymm12
        vpaddq	ymm13, ymm13, ymm13
        vpaddq	ymm5, ymm5, ymm13
        vpaddq	ymm14, ymm14, ymm14
        vpaddq	ymm6, ymm6, ymm14
        vpaddq	ymm15, ymm15, ymm15
        vpaddq	ymm7, ymm7, ymm15
        vpaddq	ymm16, ymm16, ymm16
        vpaddq	ymm8, ymm8, ymm16
        vpaddq	ymm17, ymm17, ymm17
        ; Reduce
        vpsllq	ymm9, ymm5, 4
        vpsllq	ymm10, ymm5, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm5
        vpaddq	ymm0, ymm0, ymm9
        vpsllq	ymm9, ymm6, 4
        vpsllq	ymm10, ymm6, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm6
        vpaddq	ymm1, ymm1, ymm9
        vpsllq	ymm9, ymm7, 4
        vpsllq	ymm10, ymm7, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm7
        vpaddq	ymm2, ymm2, ymm9
        vpsllq	ymm9, ymm8, 4
        vpsllq	ymm10, ymm8, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm8
        vpaddq	ymm3, ymm3, ymm9
        vpsllq	ymm9, ymm17, 4
        vpsllq	ymm10, ymm17, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm17
        vpaddq	ymm4, ymm4, ymm9
        vpsrlq	ymm23, ymm0, 51
        vpandq	ymm0, ymm0, ymm28
        vpsrlq	ymm24, ymm1, 51
        vpandq	ymm1, ymm1, ymm28
        vpsrlq	ymm25, ymm2, 51
        vpandq	ymm2, ymm2, ymm28
        vpsrlq	ymm26, ymm3, 51
        vpandq	ymm3, ymm3, ymm28
        vpsrlq	ymm27, ymm4, 51
        vpandq	ymm4, ymm4, ymm28
        vmovdqa64	ymm18, ymm0
        vpmadd52luq	ymm18, ymm27, ymm31
        vpaddq	ymm19, ymm1, ymm23
        vpaddq	ymm20, ymm2, ymm24
        vpaddq	ymm21, ymm3, ymm25
        vpaddq	ymm22, ymm4, ymm26
        ; X3 = B - A, Y3 = B + A, Z3 = D + C, T3 = D - C
        vpermq	ymm23, ymm18, 240
        vpermq	ymm24, ymm19, 240
        vpermq	ymm25, ymm20, 240
        vpermq	ymm26, ymm21, 240
        vpermq	ymm27, ymm22, 240
        vpaddq	ymm23{k2}, ymm23, ymm23
        vpaddq	ymm24{k2}, ymm24, ymm24
        vpaddq	ymm25{k2}, ymm25, ymm25
        vpaddq	ymm26{k2}, ymm26, ymm26
        vpaddq	ymm27{k2}, ymm27, ymm27
        vpermq	ymm0, ymm18, 165
        vpermq	ymm1, ymm19, 165
        vpermq	ymm2, ymm20, 165
        vpermq	ymm3, ymm21, 165
        vpermq	ymm4, ymm22, 165
        vpaddq	ymm18, ymm23, ymm0
        vpaddq	ymm19, ymm24, ymm1
        vpaddq	ymm20, ymm25, ymm2
        vpaddq	ymm21, ymm26, ymm3
        vpaddq	ymm22, ymm27, ymm4
        vpaddq	ymm23{k3}, ymm23, ymm29
        vpaddq	ymm24{k3}, ymm24, ymm30
        vpaddq	ymm25{k3}, ymm25, ymm30
        vpaddq	ymm26{k3}, ymm26, ymm30
        vpaddq	ymm27{k3}, ymm27, ymm30
        vpsubq	ymm18{k3}, ymm23, ymm0
        vpsubq	ymm19{k3}, ymm24, ymm1
        vpsubq	ymm20{k3}, ymm25, ymm2
        vpsubq	ymm21{k3}, ymm26, ymm3
        vpsubq	ymm22{k3}, ymm27, ymm4
        vpsrlq	ymm5, ymm18, 51
        vpandq	ymm18, ymm18, ymm28
        vpsrlq	ymm6, ymm19, 51
        vpandq	ymm19, ymm19, ymm28
        vpsrlq	ymm7, ymm20, 51
        vpandq	ymm20, ymm20, ymm28
        vpsrlq	ymm8, ymm21, 51
        vpandq	ymm21, ymm21, ymm28
        vpsrlq	ymm9, ymm22, 51
        vpandq	ymm22, ymm22, ymm28
        vpmadd52luq	ymm18, ymm9, ymm31
        vpaddq	ymm19, ymm19, ymm5
        vpaddq	ymm20, ymm20, ymm6
        vpaddq	ymm21, ymm21, ymm7
        vpaddq	ymm22, ymm22, ymm8
        test	r15, r15
        je	L_ge_dsm_avx512_ifma_nores_b
        vpermq	ymm18, ymm18, 180
        vpermq	ymm19, ymm19, 180
        vpermq	ymm20, ymm20, 180
        vpermq	ymm21, ymm21, 180
        vpermq	ymm22, ymm22, 180
L_ge_dsm_avx512_ifma_nores_b:
        vmovdqa64	ymm23, ymm18
        vmovdqa64	ymm24, ymm19
        vmovdqa64	ymm25, ymm20
        vmovdqa64	ymm26, ymm21
        vmovdqa64	ymm27, ymm22
L_ge_dsm_avx512_ifma_skip_b:
        ; To p3
        vpermq	ymm18, ymm23, 36
        vpermq	ymm19, ymm24, 36
        vpermq	ymm20, ymm25, 36
        vpermq	ymm21, ymm26, 36
        vpermq	ymm22, ymm27, 36
        vpermq	ymm23, ymm23, 123
        vpermq	ymm24, ymm24, 123
        vpermq	ymm25, ymm25, 123
        vpermq	ymm26, ymm26, 123
        vpermq	ymm27, ymm27, 123
        ; Multiply 4 field elements
        vpxorq	ymm0, ymm0, ymm0
        vpxorq	ymm9, ymm9, ymm9
        vpxorq	ymm1, ymm1, ymm1
        vpxorq	ymm10, ymm10, ymm10
        vpxorq	ymm2, ymm2, ymm2
        vpxorq	ymm11, ymm11, ymm11
        vpxorq	ymm3, ymm3, ymm3
        vpxorq	ymm12, ymm12, ymm12
        vpxorq	ymm4, ymm4, ymm4
        vpxorq	ymm13, ymm13, ymm13
        vpxorq	ymm5, ymm5, ymm5
        vpxorq	ymm14, ymm14, ymm14
        vpxorq	ymm6, ymm6, ymm6
        vpxorq	ymm15, ymm15, ymm15
        vpxorq	ymm7, ymm7, ymm7
        vpxorq	ymm16, ymm16, ymm16
        vpxorq	ymm8, ymm8, ymm8
        vpxorq	ymm17, ymm17, ymm17
        vpmadd52luq	ymm0, ymm18, ymm23
        vpmadd52huq	ymm9, ymm18, ymm23
        vpmadd52luq	ymm1, ymm18, ymm24
        vpmadd52huq	ymm10, ymm18, ymm24
        vpmadd52luq	ymm2, ymm18, ymm25
        vpmadd52huq	ymm11, ymm18, ymm25
        vpmadd52luq	ymm3, ymm18, ymm26
        vpmadd52huq	ymm12, ymm18, ymm26
        vpmadd52luq	ymm4, ymm18, ymm27
        vpmadd52huq	ymm13, ymm18, ymm27
        vpmadd52luq	ymm1, ymm19, ymm23
        vpmadd52huq	ymm10, ymm19, ymm23
        vpmadd52luq	ymm2, ymm19, ymm24
        vpmadd52huq	ymm11, ymm19, ymm24
        vpmadd52luq	ymm3, ymm19, ymm25
        vpmadd52huq	ymm12, ymm19, ymm25
        vpmadd52luq	ymm4, ymm19, ymm26
        vpmadd52huq	ymm13, ymm19, ymm26
        vpmadd52luq	ymm5, ymm19, ymm27
        vpmadd52huq	ymm14, ymm19, ymm27
        vpmadd52luq	ymm2, ymm20, ymm23
        vpmadd52huq	ymm11, ymm20, ymm23
        vpmadd52luq	ymm3, ymm20, ymm24
        vpmadd52huq	ymm12, ymm20, ymm24
        vpmadd52luq	ymm4, ymm20, ymm25
        vpmadd52huq	ymm13, ymm20, ymm25
        vpmadd52luq	ymm5, ymm20, ymm26
        vpmadd52huq	ymm14, ymm20, ymm26
        vpmadd52luq	ymm6, ymm20, ymm27
        vpmadd52huq	ymm15, ymm20, ymm27
        vpmadd52luq	ymm3, ymm21, ymm23
        vpmadd52huq	ymm12, ymm21, ymm23
        vpmadd52luq	ymm4, ymm21, ymm24
        vpmadd52huq	ymm13, ymm21, ymm24
        vpmadd52luq	ymm5, ymm21, ymm25
        vpmadd52huq	ymm14, ymm21, ymm25
        vpmadd52luq	ymm6, ymm21, ymm26
        vpmadd52huq	ymm15, ymm21, ymm26
        vpmadd52luq	ymm7, ymm21, ymm27
        vpmadd52huq	ymm16, ymm21, ymm27
        vpmadd52luq	ymm4, ymm22, ymm23
        vpmadd52huq	ymm13, ymm22, ymm23
        vpmadd52luq	ymm5, ymm22, ymm24
        vpmadd52huq	ymm14, ymm22, ymm24
        vpmadd52luq	ymm6, ymm22, ymm25
        vpmadd52huq	ymm15, ymm22, ymm25
        vpmadd52luq	ymm7, ymm22, ymm26
        vpmadd52huq	ymm16, ymm22, ymm26
        vpmadd52luq	ymm8, ymm22, ymm27
        vpmadd52huq	ymm17, ymm22, ymm27
        vpaddq	ymm9, ymm9, ymm9
        vpaddq	ymm1, ymm1, ymm9
        vpaddq	ymm10, ymm10, ymm10
        vpaddq	ymm2, ymm2, ymm10
        vpaddq	ymm11, ymm11, ymm11
        vpaddq	ymm3, ymm3, ymm11
        vpaddq	ymm12, ymm12, ymm12
        vpaddq	ymm4, ymm4, ymm12
        vpaddq	ymm13, ymm13, ymm13
        vpaddq	ymm5, ymm5, ymm13
        vpaddq	ymm14, ymm14, ymm14
        vpaddq	ymm6, ymm6, ymm14
        vpaddq	ymm15, ymm15, ymm15
        vpaddq	ymm7, ymm7, ymm15
        vpaddq	ymm16, ymm16, ymm16
        vpaddq	ymm8, ymm8, ymm16
        vpaddq	ymm17, ymm17, ymm17
        ; Reduce
        vpsllq	ymm9, ymm5, 4
        vpsllq	ymm10, ymm5, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm5
        vpaddq	ymm0, ymm0, ymm9
        vpsllq	ymm9, ymm6, 4
        vpsllq	ymm10, ymm6, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm6
        vpaddq	ymm1, ymm1, ymm9
        vpsllq	ymm9, ymm7, 4
        vpsllq	ymm10, ymm7, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm7
        vpaddq	ymm2, ymm2, ymm9
        vpsllq	ymm9, ymm8, 4
        vpsllq	ymm10, ymm8, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm8
        vpaddq	ymm3, ymm3, ymm9
        vpsllq	ymm9, ymm17, 4
        vpsllq	ymm10, ymm17, 1
        vpaddq	ymm9, ymm9, ymm10
        vpaddq	ymm9, ymm9, ymm17
        vpaddq	ymm4, ymm4, ymm9
        vpsrlq	ymm23, ymm0, 51
        vpandq	ymm0, ymm0, ymm28
        vpsrlq	ymm24, ymm1, 51
        vpandq	ymm1, ymm1, ymm28
        vpsrlq	ymm25, ymm2, 51
        vpandq	ymm2, ymm2, ymm28
        vpsrlq	ymm26, ymm3, 51
        vpandq	ymm3, ymm3, ymm28
        vpsrlq	ymm27, ymm4, 51
        vpandq	ymm4, ymm4, ymm28
        vmovdqa64	ymm18, ymm0
        vpmadd52luq	ymm18, ymm27, ymm31
        vpaddq	ymm19, ymm1, ymm23
        vpaddq	ymm20, ymm2, ymm24
        vpaddq	ymm21, ymm3, ymm25
        vpaddq	ymm22, ymm4, ymm26
        dec	r11
        jge	L_ge_dsm_avx512_ifma_bits
        vmovdqu64	YMMWORD PTR [rbp+1600], ymm18
        vmovdqu64	YMMWORD PTR [rbp+1632], ymm19
        vmovdqu64	YMMWORD PTR [rbp+1664], ymm20
        vmovdqu64	YMMWORD PTR [rbp+1696], ymm21
        vmovdqu64	YMMWORD PTR [rbp+1728], ymm22
        vzeroupper
        ; Convert X, Y and Z back to 4 x 64-bit field elements
        mov	r10, 2251799813685247
        mov	rdx, QWORD PTR [rbp+1600]
        mov	rax, QWORD PTR [rbp+1632]
        mov	rcx, QWORD PTR [rbp+1664]
        mov	r8, QWORD PTR [rbp+1696]
        mov	r9, QWORD PTR [rbp+1728]
        mov	r11, rdx
        shr	r11, 51
        and	rdx, r10
        add	rax, r11
        mov	r11, rax
        shr	r11, 51
        and	rax, r10
        add	rcx, r11
        mov	r11, rcx
        shr	r11, 51
        and	rcx, r10
        add	r8, r11
        mov	r11, r8
        shr	r11, 51
        and	r8, r10
        add	r9, r11
        mov	r11, r9
        shr	r11, 51
        and	r9, r10
        imul	r11, r11, 19
        add	rdx, r11
        mov	r11, rax
        shl	r11, 51
        mov	r12, rax
        shr	r12, 13
        add	rdx, r11
        adc	r12, 0
        mov	QWORD PTR [r14], rdx
        mov	r11, rcx
        shl	r11, 38
        mov	rdx, rcx
        shr	rdx, 26
        add	r12, r11
        adc	rdx, 0
        mov	QWORD PTR [r14+8], r12
        mov	r11, r8
        shl	r11, 25
        mov	r12, r8
        shr	r12, 39
        add	rdx, r11
        adc	r12, 0
        mov	QWORD PTR [r14+16], rdx
        mov	r11, r9
        shl	r11, 12
        add	r12, r11
        mov	QWORD PTR [r14+24], r12
        mov	rdx, QWORD PTR [rbp+1608]
        mov	rax, QWORD PTR [rbp+1640]
        mov	rcx, QWORD PTR [rbp+1672]
        mov	r8, QWORD PTR [rbp+1704]
        mov	r9, QWORD PTR [rbp+1736]
        mov	r11, rdx
        shr	r11, 51
        and	rdx, r10
        add	rax, r11
        mov	r11, rax
        shr	r11, 51
        and	rax, r10
        add	rcx, r11
        mov	r11, rcx
        shr	r11, 51
        and	rcx, r10
        add	r8, r11
        mov	r11, r8
        shr	r11, 51
        and	r8, r10
        add	r9, r11
        mov	r11, r9
        shr	r11, 51
        and	r9, r10
        imul	r11, r11, 19
        add	rdx, r11
        mov	r11, rax
        shl	r11, 51
        mov	r12, rax
        shr	r12, 13
        add	rdx, r11
        adc	r12, 0
        mov	QWORD PTR [r14+32], rdx
        mov	r11, rcx
        shl	r11, 38
        mov	rdx, rcx
        shr	rdx, 26
        add	r12, r11
        adc	rdx, 0
        mov	QWORD PTR [r14+40], r12
        mov	r11, r8
        shl	r11, 25
        mov	r12, r8
        shr	r12, 39
        add	rdx, r11
        adc	r12, 0
        mov	QWORD PTR [r14+48], rdx
        mov	r11, r9
        shl	r11, 12
        add	r12, r11
        mov	QWORD PTR [r14+56], r12
        mov	rdx, QWORD PTR [rbp+1616]
        mov	rax, QWORD PTR [rbp+1648]
        mov	rcx, QWORD PTR [rbp+1680]
        mov	r8, QWORD PTR [rbp+1712]
        mov	r9, QWORD PTR [rbp+1744]
        mov	r11, rdx
        shr	r11, 51
        and	rdx, r10
        add	rax, r11
        mov	r11, rax
        shr	r11, 51
        and	rax, r10
        add	rcx, r11
        mov	r11, rcx
        shr	r11, 51
        and	rcx, r10
        add	r8, r11
        mov	r11, r8
        shr	r11, 51
        and	r8, r10
        add	r9, r11
        mov	r11, r9
        shr	r11, 51
        and	r9, r10
        imul	r11, r11, 19
        add	rdx, r11
        mov	r11, rax
        shl	r11, 51
        mov	r12, rax
        shr	r12, 13
        add	rdx, r11
        adc	r12, 0
        mov	QWORD PTR [r14+64], rdx
        mov	r11, rcx
        shl	r11, 38
        mov	rdx, rcx
        shr	rdx, 26
        add	r12, r11
        adc	rdx, 0
        mov	QWORD PTR [r14+72], r12
        mov	r11, r8
        shl	r11, 25
        mov	r12, r8
        shr	r12, 39
        add	rdx, r11
        adc	r12, 0
        mov	QWORD PTR [r14+80], rdx
        mov	r11, r9
        shl	r11, 12
        add	r12, r11
        mov	QWORD PTR [r14+88], r12
        xor	rax, rax
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
        pop	rbp
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
ge_double_scalarmult_vartime_avx512_ifma ENDP
_TEXT ENDS
_TEXT SEGMENT READONLY PARA
ge_double_scalarmult_vartime_avx512_ifma_dq PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        push	rbp
        mov	r14, rcx
        mov	r15, rdx
        mov	rdi, r8
        mov	rsi, r9
        mov	rbx, QWORD PTR [rsp+104]
        mov	rbp, QWORD PTR [rsp+112]
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
        ; Window digits of the scalar multiplying A
        ; One digit per bit of the scalar
        xor	rdx, rdx
        xor	r11, r11
L_ge_dsm_dq_a_avx512_ifma_slide_bytes:
        movzx	rax, BYTE PTR [r15+r11]
        mov	rcx, rax
        and	rcx, 1
        mov	BYTE PTR [rbp+rdx+1920], cl
        shr	rax, 1
        inc	rdx
        mov	rcx, rax
        and	rcx, 1
        mov	BYTE PTR [rbp+rdx+1920], cl
        shr	rax, 1
        inc	rdx
        mov	rcx, rax
        and	rcx, 1
        mov	BYTE PTR [rbp+rdx+1920], cl
        shr	rax, 1
        inc	rdx
        mov	rcx, rax
        and	rcx, 1
        mov	BYTE PTR [rbp+rdx+1920], cl
        shr	rax, 1
        inc	rdx
        mov	rcx, rax
        and	rcx, 1
        mov	BYTE PTR [rbp+rdx+1920], cl
        shr	rax, 1
        inc	rdx
        mov	rcx, rax
        and	rcx, 1
        mov	BYTE PTR [rbp+rdx+1920], cl
        shr	rax, 1
        inc	rdx
        mov	rcx, rax
        and	rcx, 1
        mov	BYTE PTR [rbp+rdx+1920], cl
        shr	rax, 1
        inc	rdx
        mov	rcx, rax
        and	rcx, 1
        mov	BYTE PTR [rbp+rdx+1920], cl
        shr	rax, 1
        inc	rdx
        inc	r11
        cmp	r11, 32
        jne	L_ge_dsm_dq_a_avx512_ifma_slide_bytes
        ; Fold each run of digits down to one odd digit
        xor	r11, r11
L_ge_dsm_dq_a_avx512_ifma_slide_digit:
        movsx	rcx, BYTE PTR [rbp+r11+1920]
        test	rcx, rcx
        je	L_ge_dsm_dq_a_avx512_ifma_slide_next_digit
        mov	r12, 1
L_ge_dsm_dq_a_avx512_ifma_slide_window:
        mov	rdx, r11
        add	rdx, r12
        cmp	rdx, 256
        jge	L_ge_dsm_dq_a_avx512_ifma_slide_next_digit
        movsx	r8, BYTE PTR [rbp+rdx+1920]
        test	r8, r8
        je	L_ge_dsm_dq_a_avx512_ifma_slide_next_window
        ; Weight of the digit at i + b, relative to the one at i
        mov	r9, r8
        mov	r8, r12
L_ge_dsm_dq_a_avx512_ifma_slide_shift:
        add	r9, r9
        dec	r8
        jne	L_ge_dsm_dq_a_avx512_ifma_slide_shift
        movsx	r9, r9b
        ; Fold it in if the digit at i stays within range
        mov	r10, rcx
        add	r10, r9
        cmp	r10, 15
        jg	L_ge_dsm_dq_a_avx512_ifma_slide_sub
        mov	rcx, r10
        mov	BYTE PTR [rbp+r11+1920], cl
        mov	BYTE PTR [rbp+rdx+1920], 0
        jmp	L_ge_dsm_dq_a_avx512_ifma_slide_next_window
L_ge_dsm_dq_a_avx512_ifma_slide_sub:
        mov	r10, rcx
        sub	r10, r9
        cmp	r10, -15
        jl	L_ge_dsm_dq_a_avx512_ifma_slide_next_digit
        mov	rcx, r10
        mov	BYTE PTR [rbp+r11+1920], cl
        ; Subtracting it borrows from the digits above
L_ge_dsm_dq_a_avx512_ifma_slide_carry:
        cmp	rdx, 256
        jge	L_ge_dsm_dq_a_avx512_ifma_slide_next_window
        movsx	r10, BYTE PTR [rbp+rdx+1920]
        test	r10, r10
        je	L_ge_dsm_dq_a_avx512_ifma_slide_set
        mov	BYTE PTR [rbp+rdx+1920], 0
        inc	rdx
        jmp	L_ge_dsm_dq_a_avx512_ifma_slide_carry
L_ge_dsm_dq_a_avx512_ifma_slide_set:
        mov	BYTE PTR [rbp+rdx+1920], 1
L_ge_dsm_dq_a_avx512_ifma_slide_next_window:
        inc	r12
        cmp	r12, 6
        jle	L_ge_dsm_dq_a_avx512_ifma_slide_window
L_ge_dsm_dq_a_avx512_ifma_slide_next_digit:
        inc	r11
        cmp	r11, 256
        jl	L_ge_dsm_dq_a_avx512_ifma_slide_digit
        ; Window digits of the base point scalar
        ; One digit per bit of the scalar
        xor	rdx, rdx
        xor	r11, r11
L_ge_dsm_dq_b_avx512_ifma_slide_bytes:
        movzx	rax, BYTE PTR [rsi+r11]
        mov	rcx, rax
        and	rcx, 1
        mov	BYTE PTR [rbp+rdx+2176], cl
        shr	rax, 1
        inc	rdx
        mov	rcx, rax
        and	rcx, 1
        mov	BYTE PTR [rbp+rdx+2176], cl
        shr	rax, 1
        inc	rdx
        mov	rcx, rax
        and	rcx, 1
        mov	BYTE PTR [rbp+rdx+2176], cl
        shr	rax, 1
        inc	rdx
        mov	rcx, rax
        and	rcx, 1
        mov	BYTE PTR [rbp+rdx+2176], cl
        shr	rax, 1
        inc	rdx
        mov	rcx, rax
        and	rcx, 1
        mov	BYTE PTR [rbp+rdx+2176], cl
        shr	rax, 1
        inc	rdx
        mov	rcx, rax
        and	rcx, 1
        mov	BYTE PTR [rbp+rdx+2176], cl
        shr	rax, 1
        inc	rdx
        mov	rcx, rax
        and	rcx, 1
        mov	BYTE PTR [rbp+rdx+2176], cl
        shr	rax, 1
        inc	rdx
        mov	rcx, rax
        and	rcx, 1
        mov	BYTE PTR [rbp+rdx+2176], cl
        shr	rax, 1
        inc	rdx
        inc	r11
        cmp	r11, 32
        jne	L_ge_dsm_dq_b_avx512_ifma_slide_bytes
        ; Fold each run of digits down to one odd digit
        xor	r11, r11
L_ge_dsm_dq_b_avx512_ifma_slide_digit:
        movsx	rcx, BYTE PTR [rbp+r11+2176]
        test	rcx, rcx
        je	L_ge_dsm_dq_b_avx512_ifma_slide_next_digit
        mov	r12, 1
L_ge_dsm_dq_b_avx512_ifma_slide_window:
        mov	rdx, r11
        add	rdx, r12
        cmp	rdx, 256
        jge	L_ge_dsm_dq_b_avx512_ifma_slide_next_digit
        movsx	r8, BYTE PTR [rbp+rdx+2176]
        test	r8, r8
        je	L_ge_dsm_dq_b_avx512_ifma_slide_next_window
        ; Weight of the digit at i + b, relative to the one at i
        mov	r9, r8
        mov	r8, r12
L_ge_dsm_dq_b_avx512_ifma_slide_shift:
        add	r9, r9
        dec	r8
        jne	L_ge_dsm_dq_b_avx512_ifma_slide_shift
        movsx	r9, r9b
        ; Fold it in if the digit at i stays within range
        mov	r10, rcx
        add	r10, r9
        cmp	r10, 63
        jg	L_ge_dsm_dq_b_avx512_ifma_slide_sub
        mov	rcx, r10
        mov	BYTE PTR [rbp+r11+2176], cl
        mov	BYTE PTR [rbp+rdx+2176], 0
        jmp	L_ge_dsm_dq_b_avx512_ifma_slide_next_window
L_ge_dsm_dq_b_avx512_ifma_slide_sub:
        mov	r10, rcx
        sub	r10, r9
        cmp	r10, -63
        jl	L_ge_dsm_dq_b_avx512_ifma_slide_next_digit
        mov	rcx, r10
        mov	BYTE PTR [rbp+r11+2176], cl
        ; Subtracting it borrows from the digits above
L_ge_dsm_dq_b_avx512_ifma_slide_carry:
        cmp	rdx, 256
        jge	L_ge_dsm_dq_b_avx512_ifma_slide_next_window
        movsx	r10, BYTE PTR [rbp+rdx+2176]
        test	r10, r10
        je	L_ge_dsm_dq_b_avx512_ifma_slide_set
        mov	BYTE PTR [rbp+rdx+2176], 0
        inc	rdx
        jmp	L_ge_dsm_dq_b_avx512_ifma_slide_carry
L_ge_dsm_dq_b_avx512_ifma_slide_set:
        mov	BYTE PTR [rbp+rdx+2176], 1
L_ge_dsm_dq_b_avx512_ifma_slide_next_window:
        inc	r12
        cmp	r12, 6
        jle	L_ge_dsm_dq_b_avx512_ifma_slide_window
L_ge_dsm_dq_b_avx512_ifma_slide_next_digit:
        inc	r11
        cmp	r11, 256
        jl	L_ge_dsm_dq_b_avx512_ifma_slide_digit
        mov	rsi, QWORD PTR [ptr_L_ge_ifma_consts]
        vpbroadcastq	ymm28, QWORD PTR [rsi]
        vpbroadcastq	ymm29, QWORD PTR [rsi+8]
        vpbroadcastq	ymm30, QWORD PTR [rsi+16]
        vpbroadcastq	ymm31, QWORD PTR [rsi+24]
        mov	r9d, 8
        kmovw	k1, r9d
        mov	r9d, 12
        kmovw	k2, r9d
        mov	r9d, 9
        kmovw	k3, r9d
        mov	r9d, 6
        kmovw	k4, r9d
        mov	r9d, 1
        kmovw	k5, r9d
        mov	r9d, 2
        kmovw	k6, r9d
        mov	r9d, 4
        kmovw	k7, r9d
        ; Odd multiples of A, cached and in limb form
        mov	r10, 2251799813685247
        ; A in limb form: [X, Y, Z, T]
        mov	rdx, QWORD PTR [rdi]
        mov	rax, QWORD PTR [rdi+8]
        mov	rcx, QWORD PTR [rdi+16]
        mov	r8, QWORD PTR [rdi+24]
        mov	r9, r8
        shr	r9, 63
        imul	r9, r9, 19
        shl	r8, 1
        shr	r8, 1
        mov	r13, rdx
        and	r13, r10
        add	r13, r9
        mov	QWORD PTR [rbp+1440], r13
        shrd	rdx, rax, 51
        mov	r9, rdx
        and	r9, r10
        mov	QWORD PTR [rbp+1472], r9
        shrd	rax, rcx, 38
        mov	r9, rax
        and	r9, r10
        mov	QWORD PTR [rbp+1504], r9
        shrd	rcx, r8, 25
        mov	r9, rcx
        and	r9, r10
        mov	QWORD PTR [rbp+1536], r9
        shr	r8, 12
        mov	QWORD PTR [rbp+1568], r8
        mov	rdx, QWORD PTR [rdi+32]
        mov	rax, QWORD PTR [rdi+40]
        mov	rcx, QWORD PTR [rdi+48]
        mov	r8, QWORD PTR [rdi+56]
        mov	r9, r8
        shr	r9, 63
        imul	r9, r9, 19
        shl	r8, 1
        shr	r8, 1
        mov	r13, rdx
        and	r13, r10
        add	r13, r9
        mov	QWORD PTR [rbp+1448], r13
        shrd	rdx, rax, 51
        mov	r9, rdx
        and	r9, r10
        mov	QWORD PTR [rbp+1480], r9
        shrd	rax, rcx, 38
        mov	r9, rax
        and	r9, r10
        mov	QWORD PTR [rbp+1512], r9
        shrd	rcx, r8, 25
        mov	r9, rcx
        and	r9, r10
        mov	QWORD PTR [rbp+1544], r9
        shr	r8, 12
        mov	QWORD PTR [rbp+1576], r8
        mov	rdx, QWORD PTR [rdi+64]
        mov	rax, QWORD PTR [rdi+72]
        mov	rcx, QWORD PTR [rdi+80]
        mov	r8, QWORD PTR [rdi+88]
        mov	r9, r8
        shr	r9, 63
        imul	r9, r9, 19
        shl	r8, 1
        shr	r8, 1
        mov	r13, rdx
        and	r13, r10
        add	r13, r9
        mov	QWORD PTR [rbp+1456], r13
        shrd	rdx, rax, 51
        mov	r9, rdx
        and	r9, r10
        mov	QWORD PTR [rbp+1488], r9
        shrd	rax, rcx, 38
        mov	r9, rax
        and	r9, r10
        mov	QWORD PTR [rbp+1520], r9
        shrd	rcx, r8, 25
        mov	r9, rcx
        and	r9, r10
        mov	QWORD PTR [rbp+1552], r9
        shr	r8, 12
        mov	QWORD PTR [rbp+1584], r8
        mov	rdx, QWORD PTR [rdi+96]
        mov	rax, QWORD PTR [rdi+104]
        mov	rcx, QWORD PTR [rdi+112]
        mov	r8, QWORD PTR [rdi+120]
        mov	r9, r8
        shr	r9, 63
        imul	r9, r9, 19
        shl	r8, 1
        shr	r8, 1
        mov	r13, rdx
        and	r13, r10
        add	r13, r9
        mov	QWORD PTR [rbp+1464], r13
        shrd	rdx, rax, 51
        mov	r9, rdx
        and	r9, r10
        mov	QWORD PTR [rbp+1496], r9
        shrd	rax, rcx, 38
        mov	r9, rax
        and	r9, r10
        mov	QWORD PTR [rbp+1528], r9
        shrd	rcx, r8, 25
        mov	r9, rcx
        and	r9, r10
        mov	QWORD PTR [rbp+1560], r9
        shr	r8, 12
        mov	QWORD PTR [rbp+1592], r8
        ; Ai[0] = A
        vmovdqu64	ymm18, YMMWORD PTR [rbp+1440]
        vmovdqu64	ymm19, YMMWORD PTR [rbp+1472]
        vmovdqu64	ymm20, YMMWORD PTR [rbp+1504]
        vmovdqu64	ymm21, YMMWORD PTR [rbp+1536]
        vmovdqu64	ymm22, YMMWORD PTR [rbp+1568]
        ; To cached
        vpermq	ymm23, ymm18, 176
        vpermq	ymm24, ymm19, 176
        vpermq	ymm25, ymm20, 176
        vpermq	ymm26, ymm21, 176
        vpermq	ymm27, ymm22, 176
        vpermq	ymm18, ymm18, 181
        vpermq	ymm19, ymm19, 181
        vpermq	ymm20, ymm20, 181
        vpermq	ymm21, ymm21, 181
        vpermq	ymm22, ymm22, 181
        vpaddq	ymm18{k5}, ymm18, ymm23
        vpaddq	ymm19{k5}, ymm19, ymm24
        vpaddq	ymm20{k5}, ymm20, ymm25
        vpaddq	ymm21{k5}, ymm21, ymm26
        vpaddq	ymm22{k5}, ymm22, ymm27
        vpaddq	ymm18{k6}, ymm18, ymm29
        vpaddq	ymm19{k6}, ymm19, ymm30
        vpaddq	ymm20{k6}, ymm20, ymm30
        vpaddq	ymm21{k6}, ymm21, ymm30
        vpaddq	ymm22{k6}, ymm22, ymm30
        vpsubq	ymm18{k6}, ymm18, ymm23
        vpsubq	ymm19{k6}, ymm19, ymm24
        vpsubq	ymm20{k6}, ymm20, ymm25
        vpsubq	ymm21{k6}, ymm21, ymm26
        vpsubq	ymm22{k6}, ymm22, ymm27
        vpsrlq	ymm0, ymm18, 51
        vpandq	ymm18, ymm18, ymm28
        vpsrlq	ymm1, ymm19, 51
        vpandq	ymm19, ymm19, ymm28
        vpsrlq	ymm2, ymm20, 51
        vpandq	ymm20, ymm20, ymm28
        vpsrlq	ymm3, ymm21, 51
        vpandq	ymm21, ymm21, ymm28
        vpsrlq	ymm4, ymm22, 51
        vpandq	ymm22, ymm22, ymm28
        vpmadd52luq	ymm18, ymm4, ymm31
        vpaddq	ymm19, ymm19, ymm0
        vpaddq	ymm20, ymm20, ymm1
        vpaddq	ymm21, ymm21, ymm2
        vpaddq	ymm22, ymm22, ymm3
        vmovdqu64	ymm23, YMMWORD PTR [rsi+32]
        vmovdqu64	ymm24, YMMWORD PTR [rsi+64]
        vmovdqu64	ymm25, YMMWORD PTR [rsi+96]
        vmovdqu64	ymm26, YMMWORD PTR [rsi+128]
        vmovdqu64	ymm27, YMMWORD PTR [rsi+160]
        ; Multiply 4 field elements
        vpxorq	ymm0, ymm0, ymm0
        vpxorq	ymm9, ymm9, ymm9
        vpxorq	ymm1, ymm1, ymm1
        vpxorq	ymm10, ymm10, ymm10
        vpxorq	ymm2, ymm2, ymm2
        vpxorq	ymm11, ymm11, ymm11
        vpxorq	ymm3, ymm3, ymm3
        vpxorq	ymm12, ymm12, ymm12
        vpxorq	ymm4, ymm4, ymm4
        vpxorq	ymm13, ymm13, ymm13
        vpxorq	ymm5, ymm5, ymm5
        vpxorq	ymm14, ymm14, ymm14
        vpxorq	ymm6, ymm6, ymm6
        vpxorq	ymm15, ymm15, ymm15
        vpxorq	ymm7, ymm7, ymm7
        vpxorq	ymm16, ymm16, ymm16
        vpxorq	ymm8, ymm8, ymm8
        vpxorq	ymm17, ymm17, ymm17
        vpmadd52luq	ymm0, ymm18, ymm23
        vpmadd52huq	ymm9, ymm18, ymm23
        vpmadd52luq	ymm1, ymm18, ymm24
        vpmadd52huq	ymm10, ymm18, ymm24
        vpmadd52luq	ymm2, ymm18, ymm25
        vpmadd52huq	ymm11, ymm18, ymm25
        vpmadd52luq	ymm3, ymm18, ymm26
        vpmadd52huq	ymm12, ymm18, ymm26
        vpmadd52luq	ymm4, ymm18, ymm27
        vpmadd52huq	ymm13, ymm18, ymm27
        vpmadd52luq	ymm1, ymm19, ymm23
        vpmadd52huq	ymm10, ymm19, ymm23
        vpmadd52luq	ymm2, ymm19, ymm24
        vpmadd52huq	ymm11, ymm19, ymm24
        vpmadd52luq	ymm3, ymm19, ymm25
        vpmadd52huq	ymm12, ymm19, ymm25
        vpmadd52luq	ymm4, ymm19, ymm26
        vpmadd52huq	ymm13, ymm19, ymm26
        vpmadd52luq	ymm5, ymm19, ymm27
        vpmadd52huq	ymm14, ymm19, ymm27
        vpmadd52luq	ymm2, ymm20, ymm23
        vpmadd52huq	ymm11, ymm20, ymm23
        vpmadd52luq	ymm3, ymm20, ymm24
        vpmadd52huq	ymm12, ymm20, ymm24
        vpmadd52luq	ymm4, ymm20, ymm25
        vpmadd52huq	ymm13, ymm20, ymm25
        vpmadd52luq	ymm5, ymm20, ymm26
        vpmadd52huq	ymm14, ymm20, ymm26
        vpmadd52luq	ymm6, ymm20, ymm27
        vpmadd52huq	ymm15, ymm20, ymm27
        vpmadd52luq	ymm3, ymm21, ymm23
        vpmadd52huq	ymm12, ymm21, ymm23
        vpmadd52luq	ymm4, ymm21, ymm24
        vpmadd52huq	ymm13, ymm21, ymm24
        vpmadd52luq	ymm5, ymm21, ymm25
        vpmadd52huq	ymm14, ymm21, ymm25
        vpmadd52luq	ymm6, ymm21, ymm26
        vpmadd52huq	ymm15, ymm21, ymm26
        vpmadd52luq	ymm7, ymm21, ymm27
        vpmadd52huq	ymm16, ymm21, ymm27
        vpmadd52luq	ymm4, ymm22, ymm23
        vpmadd52huq	ymm13, ymm22, ymm23
        vpmadd52luq	ymm5, ymm22, ymm24
        vpmadd52huq	ymm14, ymm22, ymm24
        vpmadd52luq	ymm6, ymm22, ymm25
        vpmadd52huq	ymm15, ymm22, ymm25
        vpmadd52luq	ymm7, ymm22, ymm26
        vpmadd52huq	ymm16, ymm22, ymm26
        vpmadd52luq	ymm8, ymm22, ymm27
        vpmadd52huq	ymm17, ymm22, ymm27
        vpaddq	ymm9, ymm9, ymm9
        vpaddq	ymm1, ymm1, ymm9
        vpaddq	ymm10, ymm10, ymm10
        vpaddq	ymm2, ymm2, ymm10
        vpaddq	ymm11, ymm11, ymm11
        vpaddq	ymm3, ymm3, ymm11
        vpaddq	ymm12, ymm12, ymm12
        vpaddq	ymm4, ymm4, ymm12
        vpaddq	ymm13, ymm13, ymm13
        vpaddq	ymm5, ymm5, ymm13
        vpaddq	ymm14, ymm14, ymm14
        vpaddq	ymm6, ymm6, ymm14
        vpaddq	ymm15, ymm15, ymm15
        vpaddq	ymm7, ymm7, ymm15
        vpaddq	ymm16, ymm16, ymm16
        vpaddq	ymm8, ymm8, ymm16
        vpaddq	ymm17, ymm17, ymm17
        ; Reduce
        vpmullq	ymm9, ymm5, ymm31
        vpaddq	ymm0, ymm0, ymm9
        vpmullq	ymm9, ymm6, ymm31
        vpaddq	ymm1, ymm1, ymm9
        vpmullq	ymm9, ymm7, ymm31
        vpaddq	ymm2, ymm2, ymm9
        vpmullq	ymm9, ymm8, ymm31
        vpaddq	ymm3, ymm3, ymm9
        vpmullq	ymm9, ymm17, ymm31
        vpaddq	ymm4, ymm4, ymm9
        vpsrlq	ymm23, ymm0, 51
        vpandq	ymm0, ymm0, ymm28
        vpsrlq	ymm24, ymm1, 51
        vpandq	ymm1, ymm1, ymm28
        vpsrlq	ymm25, ymm2, 51
        vpandq	ymm2, ymm2, ymm28
        vpsrlq	ymm26, ymm3, 51
        vpandq	ymm3, ymm3, ymm28
        vpsrlq	ymm27, ymm4, 51
        vpandq	ymm4, ymm4, ymm28
        vmovdqa64	ymm18, ymm0
        vpmadd52luq	ymm18, ymm27, ymm31
        vpaddq	ymm19, ymm1, ymm23
        vpaddq	ymm20, ymm2, ymm24
        vpaddq	ymm21, ymm3, ymm25
        vpaddq	ymm22, ymm4, ymm26
        vmovdqu64	YMMWORD PTR [rbp], ymm18
        vmovdqu64	YMMWORD PTR [rbp+32], ymm19
        vmovdqu64	YMMWORD PTR [rbp+64], ymm20
        vmovdqu64	YMMWORD PTR [rbp+96], ymm21
        vmovdqu64	YMMWORD PTR [rbp+128], ymm22
        ; A2 = 2.A
        vmovdqu64	ymm18, YMMWORD PTR [rbp+1440]
        vmovdqu64	ymm19, YMMWORD PTR [rbp+1472]
        vmovdqu64	ymm20, YMMWORD PTR [rbp+1504]
        vmovdqu64	ymm21, YMMWORD PTR [rbp+1536]
        vmovdqu64	ymm22, YMMWORD PTR [rbp+1568]
        ; Double
        vpermq	ymm23, ymm18, 100
        vpermq	ymm24, ymm19, 100
        vpermq	ymm25, ymm20, 100
        vpermq	ymm26, ymm21, 100
        vpermq	ymm27, ymm22, 100
        vpermq	ymm18, ymm18, 36
        vpermq	ymm19, ymm19, 36
        vpermq	ymm20, ymm20, 36
        vpermq	ymm21, ymm21, 36
        vpermq	ymm22, ymm22, 36
        vpaddq	ymm18{k1}, ymm18, ymm23
        vpaddq	ymm19{k1}, ymm19, ymm24
        vpaddq	ymm20{k1}, ymm20, ymm25
        vpaddq	ymm21{k1}, ymm21, ymm26
        vpaddq	ymm22{k1}, ymm22, ymm27
        vpsrlq	ymm0, ymm18, 51
        vpandq	ymm18, ymm18, ymm28
        vpsrlq	ymm1, ymm19, 51
        vpandq	ymm19, ymm19, ymm28
        vpsrlq	ymm2, ymm20, 51
        vpandq	ymm20, ymm20, ymm28
        vpsrlq	ymm3, ymm21, 51
        vpandq	ymm21, ymm21, ymm28
        vpsrlq	ymm4, ymm22, 51
        vpandq	ymm22, ymm22, ymm28
        vpmadd52luq	ymm18, ymm4, ymm31
        vpaddq	ymm19, ymm19, ymm0
        vpaddq	ymm20, ymm20, ymm1
        vpaddq	ymm21, ymm21, ymm2
        vpaddq	ymm22, ymm22, ymm3
        vmovdqa64	ymm23, ymm18
        vmovdqa64	ymm24, ymm19
        vmovdqa64	ymm25, ymm20
        vmovdqa64	ymm26, ymm21
        vmovdqa64	ymm27, ymm22
        ; Multiply 4 field elements
        vpxorq	ymm0, ymm0, ymm0
        vpxorq	ymm9, ymm9, ymm9
        vpxorq	ymm1, ymm1, ymm1
        vpxorq	ymm10, ymm10, ymm10
        vpxorq	ymm2, ymm2, ymm2
        vpxorq	ymm11, ymm11, ymm11
        vpxorq	ymm3, ymm3, ymm3
        vpxorq	ymm12, ymm12, ymm12
        vpxorq	ymm4, ymm4, ymm4
        vpxorq	ymm13, ymm13, ymm13
        vpxorq	ymm5, ymm5, ymm5
        vpxorq	ymm14, ymm14, ymm14
        vpxorq	ymm6, ymm6, ymm6
        vpxorq	ymm15, ymm15, ymm15
        vpxorq	ymm7, ymm7, ymm7
        vpxorq	ymm16, ymm16, ymm16
        vpxorq	ymm8, ymm8, ymm8
        vpxorq	ymm17, ymm17, ymm17
        vpmadd52luq	ymm0, ymm18, ymm23
        vpmadd52huq	ymm9, ymm18, ymm23
        vpmadd52luq	ymm1, ymm18, ymm24
        vpmadd52huq	ymm10, ymm18, ymm24
        vpmadd52luq	ymm2, ymm18, ymm25
        vpmadd52huq	ymm11, ymm18, ymm25
        vpmadd52luq	ymm3, ymm18, ymm26
        vpmadd52huq	ymm12, ymm18, ymm26
        vpmadd52luq	ymm4, ymm18, ymm27
        vpmadd52huq	ymm13, ymm18, ymm27
        vpmadd52luq	ymm1, ymm19, ymm23
        vpmadd52huq	ymm10, ymm19, ymm23
        vpmadd52luq	ymm2, ymm19, ymm24
        vpmadd52huq	ymm11, ymm19, ymm24
        vpmadd52luq	ymm3, ymm19, ymm25
        vpmadd52huq	ymm12, ymm19, ymm25
        vpmadd52luq	ymm4, ymm19, ymm26
        vpmadd52huq	ymm13, ymm19, ymm26
        vpmadd52luq	ymm5, ymm19, ymm27
        vpmadd52huq	ymm14, ymm19, ymm27
        vpmadd52luq	ymm2, ymm20, ymm23
        vpmadd52huq	ymm11, ymm20, ymm23
        vpmadd52luq	ymm3, ymm20, ymm24
        vpmadd52huq	ymm12, ymm20, ymm24
        vpmadd52luq	ymm4, ymm20, ymm25
        vpmadd52huq	ymm13, ymm20, ymm25
        vpmadd52luq	ymm5, ymm20, ymm26
        vpmadd52huq	ymm14, ymm20, ymm26
        vpmadd52luq	ymm6, ymm20, ymm27
        vpmadd52huq	ymm15, ymm20, ymm27
        vpmadd52luq	ymm3, ymm21, ymm23
        vpmadd52huq	ymm12, ymm21, ymm23
        vpmadd52luq	ymm4, ymm21, ymm24
        vpmadd52huq	ymm13, ymm21, ymm24
        vpmadd52luq	ymm5, ymm21, ymm25
        vpmadd52huq	ymm14, ymm21, ymm25
        vpmadd52luq	ymm6, ymm21, ymm26
        vpmadd52huq	ymm15, ymm21, ymm26
        vpmadd52luq	ymm7, ymm21, ymm27
        vpmadd52huq	ymm16, ymm21, ymm27
        vpmadd52luq	ymm4, ymm22, ymm23
        vpmadd52huq	ymm13, ymm22, ymm23
        vpmadd52luq	ymm5, ymm22, ymm24
        vpmadd52huq	ymm14, ymm22, ymm24
        vpmadd52luq	ymm6, ymm22, ymm25
        vpmadd52huq	ymm15, ymm22, ymm25
        vpmadd52luq	ymm7, ymm22, ymm26
        vpmadd52huq	ymm16, ymm22, ymm26
        vpmadd52luq	ymm8, ymm22, ymm27
        vpmadd52huq	ymm17, ymm22, ymm27
        vpaddq	ymm9, ymm9, ymm9
        vpaddq	ymm1, ymm1, ymm9
        vpaddq	ymm10, ymm10, ymm10
        vpaddq	ymm2, ymm2, ymm10
        vpaddq	ymm11, ymm11, ymm11
        vpaddq	ymm3, ymm3, ymm11
        vpaddq	ymm12, ymm12, ymm12
        vpaddq	ymm4, ymm4, ymm12
        vpaddq	ymm13, ymm13, ymm13
        vpaddq	ymm5, ymm5, ymm13
        vpaddq	ymm14, ymm14, ymm14
        vpaddq	ymm6, ymm6, ymm14
        vpaddq	ymm15, ymm15, ymm15
        vpaddq	ymm7, ymm7, ymm15
        vpaddq	ymm16, ymm16, ymm16
        vpaddq	ymm8, ymm8, ymm16
        vpaddq	ymm17, ymm17, ymm17
        ; Reduce
        vpmullq	ymm9, ymm5, ymm31
        vpaddq	ymm0, ymm0, ymm9
        vpmullq	ymm9, ymm6, ymm31
        vpaddq	ymm1, ymm1, ymm9
        vpmullq	ymm9, ymm7, ymm31
        vpaddq	ymm2, ymm2, ymm9
        vpmullq	ymm9, ymm8, ymm31
        vpaddq	ymm3, ymm3, ymm9
        vpmullq	ymm9, ymm17, ymm31
        vpaddq	ymm4, ymm4, ymm9
        vpsrlq	ymm23, ymm0, 51
        vpandq	ymm0, ymm0, ymm28
        vpsrlq	ymm24, ymm1, 51
        vpandq	ymm1, ymm1, ymm28
        vpsrlq	ymm25, ymm2, 51
        vpandq	ymm2, ymm2, ymm28
        vpsrlq	ymm26, ymm3, 51
        vpandq	ymm3, ymm3, ymm28
        vpsrlq	ymm27, ymm4, 51
        vpandq	ymm4, ymm4, ymm28
        vmovdqa64	ymm18, ymm0
        vpmadd52luq	ymm18, ymm27, ymm31
        vpaddq	ymm19, ymm1, ymm23
        vpaddq	ymm20, ymm2, ymm24
        vpaddq	ymm21, ymm3, ymm25
        vpaddq	ymm22, ymm4, ymm26
        ; Y3 = YY + XX, Z3 = YY - XX
        vpermq	ymm23, ymm18, 85
        vpermq	ymm24, ymm19, 85
        vpermq	ymm25, ymm20, 85
        vpermq	ymm26, ymm21, 85
        vpermq	ymm27, ymm22, 85
        vpermq	ymm0, ymm18, 0
        vpermq	ymm1, ymm19, 0
        vpermq	ymm2, ymm20, 0
        vpermq	ymm3, ymm21, 0
        vpermq	ymm4, ymm22, 0
        vpaddq	ymm5, ymm23, ymm0
        vpaddq	ymm6, ymm24, ymm1
        vpaddq	ymm7, ymm25, ymm2
        vpaddq	ymm8, ymm26, ymm3
        vpaddq	ymm9, ymm27, ymm4
        vpaddq	ymm23{k2}, ymm23, ymm29
        vpaddq	ymm24{k2}, ymm24, ymm30
        vpaddq	ymm25{k2}, ymm25, ymm30
        vpaddq	ymm26{k2}, ymm26, ymm30
        vpaddq	ymm27{k2}, ymm27, ymm30
        vpsubq	ymm5{k2}, ymm23, ymm0
        vpsubq	ymm6{k2}, ymm24, ymm1
        vpsubq	ymm7{k2}, ymm25, ymm2
        vpsubq	ymm8{k2}, ymm26, ymm3
        vpsubq	ymm9{k2}, ymm27, ymm4
        vpsrlq	ymm23, ymm5, 51
        vpandq	ymm5, ymm5, ymm28
        vpsrlq	ymm24, ymm6, 51
        vpandq	ymm6, ymm6, ymm28
        vpsrlq	ymm25, ymm7, 51
        vpandq	ymm7, ymm7, ymm28
        vpsrlq	ymm26, ymm8, 51
        vpandq	ymm8, ymm8, ymm28
        vpsrlq	ymm27, ymm9, 51
        vpandq	ymm9, ymm9, ymm28
        vpmadd52luq	ymm5, ymm27, ymm31
        vpaddq	ymm6, ymm6, ymm23
        vpaddq	ymm7, ymm7, ymm24
        vpaddq	ymm8, ymm8, ymm25
        vpaddq	ymm9, ymm9, ymm26
        ; X3 = AA - Y3, T3 = 2.ZZ - Z3
        vpermq	ymm23, ymm18, 175
        vpermq	ymm24, ymm19, 175
        vpermq	ymm25, ymm20, 175
        vpermq	ymm26, ymm21, 175
        vpermq	ymm27, ymm22, 175
        vpaddq	ymm23{k2}, ymm23, ymm23
        vpaddq	ymm24{k2}, ymm24, ymm24
        vpaddq	ymm25{k2}, ymm25, ymm25
        vpaddq	ymm26{k2}, ymm26, ymm26
        vpaddq	ymm27{k2}, ymm27, ymm27
        vpaddq	ymm23{k3}, ymm23, ymm29
        vpaddq	ymm24{k3}, ymm24, ymm30
        vpaddq	ymm25{k3}, ymm25, ymm30
        vpaddq	ymm26{k3}, ymm26, ymm30
        vpaddq	ymm27{k3}, ymm27, ymm30
        vpsubq	ymm23{k3}, ymm23, ymm5
        vpsubq	ymm24{k3}, ymm24, ymm6
        vpsubq	ymm25{k3}, ymm25, ymm7
        vpsubq	ymm26{k3}, ymm26, ymm8
        vpsubq	ymm27{k3}, ymm27, ymm9
        vpsrlq	ymm0, ymm23, 51
        vpandq	ymm23, ymm23, ymm28
        vpsrlq	ymm1, ymm24, 51
        vpandq	ymm24, ymm24, ymm28
        vpsrlq	ymm2, ymm25, 51
        vpandq	ymm25, ymm25, ymm28
        vpsrlq	ymm3, ymm26, 51
        vpandq	ymm26, ymm26, ymm28
        vpsrlq	ymm4, ymm27, 51
        vpandq	ymm27, ymm27, ymm28
        vpmadd52luq	ymm23, ymm4, ymm31
        vpaddq	ymm24, ymm24, ymm0
        vpaddq	ymm25, ymm25, ymm1
        vpaddq	ymm26, ymm26, ymm2
        vpaddq	ymm27, ymm27, ymm3
        vmovdqa64	ymm23{k4}, ymm5
        vmovdqa64	ymm24{k4}, ymm6
        vmovdqa64	ymm25{k4}, ymm7
        vmovdqa64	ymm26{k4}, ymm8
        vmovdqa64	ymm27{k4}, ymm9
        ; To p3
        vpermq	ymm18, ymm23, 36
        vpermq	ymm19, ymm24, 36
        vpermq	ymm20, ymm25, 36
        vpermq	ymm21, ymm26, 36
        vpermq	ymm22, ymm27, 36
        vpermq	ymm23, ymm23, 123
        vpermq	ymm24, ymm24, 123
        vpermq	ymm25, ymm25, 123
        vpermq	ymm26, ymm26, 123
        vpermq	ymm27, ymm27, 123
        ; Multiply 4 field elements
        vpxorq	ymm0, ymm0, ymm0
        vpxorq	ymm9, ymm9, ymm9
        vpxorq	ymm1, ymm1, ymm1
        vpxorq	ymm10, ymm10, ymm10
        vpxorq	ymm2, ymm2, ymm2
        vpxorq	ymm11, ymm11, ymm11
        vpxorq	ymm3, ymm3, ymm3
        vpxorq	ymm12, ymm12, ymm12
        vpxorq	ymm4, ymm4, ymm4
        vpxorq	ymm13, ymm13, ymm13
        vpxorq	ymm5, ymm5, ymm5
        vpxorq	ymm14, ymm14, ymm14
        vpxorq	ymm6, ymm6, ymm6
        vpxorq	ymm15, ymm15, ymm15
        vpxorq	ymm7, ymm7, ymm7
        vpxorq	ymm16, ymm16, ymm16
        vpxorq	ymm8, ymm8, ymm8
        vpxorq	ymm17, ymm17, ymm17
        vpmadd52luq	ymm0, ymm18, ymm23
        vpmadd52huq	ymm9, ymm18, ymm23
        vpmadd52luq	ymm1, ymm18, ymm24
        vpmadd52huq	ymm10, ymm18, ymm24
        vpmadd52luq	ymm2, ymm18, ymm25
        vpmadd52huq	ymm11, ymm18, ymm25
        vpmadd52luq	ymm3, ymm18, ymm26
        vpmadd52huq	ymm12, ymm18, ymm26
        vpmadd52luq	ymm4, ymm18, ymm27
        vpmadd52huq	ymm13, ymm18, ymm27
        vpmadd52luq	ymm1, ymm19, ymm23
        vpmadd52huq	ymm10, ymm19, ymm23
        vpmadd52luq	ymm2, ymm19, ymm24
        vpmadd52huq	ymm11, ymm19, ymm24
        vpmadd52luq	ymm3, ymm19, ymm25
        vpmadd52huq	ymm12, ymm19, ymm25
        vpmadd52luq	ymm4, ymm19, ymm26
        vpmadd52huq	ymm13, ymm19, ymm26
        vpmadd52luq	ymm5, ymm19, ymm27
        vpmadd52huq	ymm14, ymm19, ymm27
        vpmadd52luq	ymm2, ymm20, ymm23
        vpmadd52huq	ymm11, ymm20, ymm23
        vpmadd52luq	ymm3, ymm20, ymm24
        vpmadd52huq	ymm12, ymm20, ymm24
        vpmadd52luq	ymm4, ymm20, ymm25
        vpmadd52huq	ymm13, ymm20, ymm25
        vpmadd52luq	ymm5, ymm20, ymm26
        vpmadd52huq	ymm14, ymm20, ymm26
        vpmadd52luq	ymm6, ymm20, ymm27
        vpmadd52huq	ymm15, ymm20, ymm27
        vpmadd52luq	ymm3, ymm21, ymm23
        vpmadd52huq	ymm12, ymm21, ymm23
        vpmadd52luq	ymm4, ymm21, ymm24
        vpmadd52huq	ymm13, ymm21, ymm24
        vpmadd52luq	ymm5, ymm21, ymm25
        vpmadd52huq	ymm14, ymm21, ymm25
        vpmadd52luq	ymm6, ymm21, ymm26
        vpmadd52huq	ymm15, ymm21, ymm26
        vpmadd52luq	ymm7, ymm21, ymm27
        vpmadd52huq	ymm16, ymm21, ymm27
        vpmadd52luq	ymm4, ymm22, ymm23
        vpmadd52huq	ymm13, ymm22, ymm23
        vpmadd52luq	ymm5, ymm22, ymm24
        vpmadd52huq	ymm14, ymm22, ymm24
        vpmadd52luq	ymm6, ymm22, ymm25
        vpmadd52huq	ymm15, ymm22, ymm25
        vpmadd52luq	ymm7, ymm22, ymm26
        vpmadd52huq	ymm16, ymm22, ymm26
        vpmadd52luq	ymm8, ymm22, ymm27
        vpmadd52huq	ymm17, ymm22, ymm27
        vpaddq	ymm9, ymm9, ymm9
        vpaddq	ymm1, ymm1, ymm9
        vpaddq	ymm10, ymm10, ymm10
        vpaddq	ymm2, ymm2, ymm10
        vpaddq	ymm11, ymm11, ymm11
        vpaddq	ymm3, ymm3, ymm11
        vpaddq	ymm12, ymm12, ymm12
        vpaddq	ymm4, ymm4, ymm12
        vpaddq	ymm13, ymm13, ymm13
        vpaddq	ymm5, ymm5, ymm13
        vpaddq	ymm14, ymm14, ymm14
        vpaddq	ymm6, ymm6, ymm14
        vpaddq	ymm15, ymm15, ymm15
        vpaddq	ymm7, ymm7, ymm15
        vpaddq	ymm16, ymm16, ymm16
        vpaddq	ymm8, ymm8, ymm16
        vpaddq	ymm17, ymm17, ymm17
        ; Reduce
        vpmullq	ymm9, ymm5, ymm31
        vpaddq	ymm0, ymm0, ymm9
        vpmullq	ymm9, ymm6, ymm31
        vpaddq	ymm1, ymm1, ymm9
        vpmullq	ymm9, ymm7, ymm31
        vpaddq	ymm2, ymm2, ymm9
        vpmullq	ymm9, ymm8, ymm31
        vpaddq	ymm3, ymm3, ymm9
        vpmullq	ymm9, ymm17, ymm31
        vpaddq	ymm4, ymm4, ymm9
        vpsrlq	ymm23, ymm0, 51
        vpandq	ymm0, ymm0, ymm28
        vpsrlq	ymm24, ymm1, 51
        vpandq	ymm1, ymm1, ymm28
        vpsrlq	ymm25, ymm2, 51
        vpandq	ymm2, ymm2, ymm28
        vpsrlq	ymm26, ymm3, 51
        vpandq	ymm3, ymm3, ymm28
        vpsrlq	ymm27, ymm4, 51
        vpandq	ymm4, ymm4, ymm28
        vmovdqa64	ymm18, ymm0
        vpmadd52luq	ymm18, ymm27, ymm31
        vpaddq	ymm19, ymm1, ymm23
        vpaddq	ymm20, ymm2, ymm24
        vpaddq	ymm21, ymm3, ymm25
        vpaddq	ymm22, ymm4, ymm26
        vmovdqu64	YMMWORD PTR [rbp+1280], ymm18
        vmovdqu64	YMMWORD PTR [rbp+1312], ymm19
        vmovdqu64	YMMWORD PTR [rbp+1344], ymm20
        vmovdqu64	YMMWORD PTR [rbp+1376], ymm21
        vmovdqu64	YMMWORD PTR [rbp+1408], ymm22
        ; Ai[j] = A2 + Ai[j-1]
        lea	r12, QWORD PTR [rbp]
        mov	r11, 7
L_ge_dsm_dq_avx512_ifma_table:
        vmovdqu64	ymm18, YMMWORD PTR [rbp+1280]
        vmovdqu64	ymm19, YMMWORD PTR [rbp+1312]
        vmovdqu64	ymm20, YMMWORD PTR [rbp+1344]
        vmovdqu64	ymm21, YMMWORD PTR [rbp+1376]
        vmovdqu64	ymm22, YMMWORD PTR [rbp+1408]
        ; Add
        vpermq	ymm23, ymm18, 176
        vpermq	ymm24, ymm19, 176
        vpermq	ymm25, ymm20, 176
        vpermq	ymm26, ymm21, 176
        vpermq	ymm27, ymm22, 176
        vpermq	ymm18, ymm18, 181
        vpermq	ymm19, ymm19, 181
        vpermq	ymm20, ymm20, 181
        vpermq	ymm21, ymm21, 181
        vpermq	ymm22, ymm22, 181
        vpaddq	ymm18{k5}, ymm18, ymm23
        vpaddq	ymm19{k5}, ymm19, ymm24
        vpaddq	ymm20{k5}, ymm20, ymm25
        vpaddq	ymm21{k5}, ymm21, ymm26
        vpaddq	ymm22{k5}, ymm22, ymm27
        vpaddq	ymm18{k6}, ymm18, ymm29
        vpaddq	ymm19{k6}, ymm19, ymm30
        vpaddq	ymm20{k6}, ymm20, ymm30
        vpaddq	ymm21{k6}, ymm21, ymm30
        vpaddq	ymm22{k6}, ymm22, ymm30
        vpsubq	ymm18{k6}, ymm18, ymm23
        vpsubq	ymm19{k6}, ymm19, ymm24
        vpsubq	ymm20{k6}, ymm20, ymm25
        vpsubq	ymm21{k6}, ymm21, ymm26
        vpsubq	ymm22{k6}, ymm22, ymm27
        vpsrlq	ymm0, ymm18, 51
        vpandq	ymm18, ymm18, ymm28
        vpsrlq	ymm1, ymm19, 51
        vpandq	ymm19, ymm19, ymm28
        vpsrlq	ymm2, ymm20, 51
        vpandq	ymm20, ymm20, ymm28
        vpsrlq	ymm3, ymm21, 51
        vpandq	ymm21, ymm21, ymm28
        vpsrlq	ymm4, ymm22, 51
        vpandq	ymm22, ymm22, ymm28
        vpmadd52luq	ymm18, ymm4, ymm31
        vpaddq	ymm19, ymm19, ymm0
        vpaddq	ymm20, ymm20, ymm1
        vpaddq	ymm21, ymm21, ymm2
        vpaddq	ymm22, ymm22, ymm3
        vmovdqu64	ymm23, YMMWORD PTR [r12]
        vmovdqu64	ymm24, YMMWORD PTR [r12+32]
        vmovdqu64	ymm25, YMMWORD PTR [r12+64]
        vmovdqu64	ymm26, YMMWORD PTR [r12+96]
        vmovdqu64	ymm27, YMMWORD PTR [r12+128]
        ; Multiply 4 field elements
        vpxorq	ymm0, ymm0, ymm0
        vpxorq	ymm9, ymm9, ymm9
        vpxorq	ymm1, ymm1, ymm1
        vpxorq	ymm10, ymm10, ymm10
        vpxorq	ymm2, ymm2, ymm2
        vpxorq	ymm11, ymm11, ymm11
        vpxorq	ymm3, ymm3, ymm3
        vpxorq	ymm12, ymm12, ymm12
        vpxorq	ymm4, ymm4, ymm4
        vpxorq	ymm13, ymm13, ymm13
        vpxorq	ymm5, ymm5, ymm5
        vpxorq	ymm14, ymm14, ymm14
        vpxorq	ymm6, ymm6, ymm6
        vpxorq	ymm15, ymm15, ymm15
        vpxorq	ymm7, ymm7, ymm7
        vpxorq	ymm16, ymm16, ymm16
        vpxorq	ymm8, ymm8, ymm8
        vpxorq	ymm17, ymm17, ymm17
        vpmadd52luq	ymm0, ymm18, ymm23
        vpmadd52huq	ymm9, ymm18, ymm23
        vpmadd52luq	ymm1, ymm18, ymm24
        vpmadd52huq	ymm10, ymm18, ymm24
        vpmadd52luq	ymm2, ymm18, ymm25
        vpmadd52huq	ymm11, ymm18, ymm25
        vpmadd52luq	ymm3, ymm18, ymm26
        vpmadd52huq	ymm12, ymm18, ymm26
        vpmadd52luq	ymm4, ymm18, ymm27
        vpmadd52huq	ymm13, ymm18, ymm27
        vpmadd52luq	ymm1, ymm19, ymm23
        vpmadd52huq	ymm10, ymm19, ymm23
        vpmadd52luq	ymm2, ymm19, ymm24
        vpmadd52huq	ymm11, ymm19, ymm24
        vpmadd52luq	ymm3, ymm19, ymm25
        vpmadd52huq	ymm12, ymm19, ymm25
        vpmadd52luq	ymm4, ymm19, ymm26
        vpmadd52huq	ymm13, ymm19, ymm26
        vpmadd52luq	ymm5, ymm19, ymm27
        vpmadd52huq	ymm14, ymm19, ymm27
        vpmadd52luq	ymm2, ymm20, ymm23
        vpmadd52huq	ymm11, ymm20, ymm23
        vpmadd52luq	ymm3, ymm20, ymm24
        vpmadd52huq	ymm12, ymm20, ymm24
        vpmadd52luq	ymm4, ymm20, ymm25
        vpmadd52huq	ymm13, ymm20, ymm25
        vpmadd52luq	ymm5, ymm20, ymm26
        vpmadd52huq	ymm14, ymm20, ymm26
        vpmadd52luq	ymm6, ymm20, ymm27
        vpmadd52huq	ymm15, ymm20, ymm27
        vpmadd52luq	ymm3, ymm21, ymm23
        vpmadd52huq	ymm12, ymm21, ymm23
        vpmadd52luq	ymm4, ymm21, ymm24
        vpmadd52huq	ymm13, ymm21, ymm24
        vpmadd52luq	ymm5, ymm21, ymm25
        vpmadd52huq	ymm14, ymm21, ymm25
        vpmadd52luq	ymm6, ymm21, ymm26
        vpmadd52huq	ymm15, ymm21, ymm26
        vpmadd52luq	ymm7, ymm21, ymm27
        vpmadd52huq	ymm16, ymm21, ymm27
        vpmadd52luq	ymm4, ymm22, ymm23
        vpmadd52huq	ymm13, ymm22, ymm23
        vpmadd52luq	ymm5, ymm22, ymm24
        vpmadd52huq	ymm14, ymm22, ymm24
        vpmadd52luq	ymm6, ymm22, ymm25
        vpmadd52huq	ymm15, ymm22, ymm25
        vpmadd52luq	ymm7, ymm22, ymm26
        vpmadd52huq	ymm16, ymm22, ymm26
        vpmadd52luq	ymm8, ymm22, ymm27
        vpmadd52huq	ymm17, ymm22, ymm27
        vpaddq	ymm9, ymm9, ymm9
        vpaddq	ymm1, ymm1, ymm9
        vpaddq	ymm10, ymm10, ymm10
        vpaddq	ymm2, ymm2, ymm10
        vpaddq	ymm11, ymm11, ymm11
        vpaddq	ymm3, ymm3, ymm11
        vpaddq	ymm12, ymm12, ymm12
        vpaddq	ymm4, ymm4, ymm12
        vpaddq	ymm13, ymm13, ymm13
        vpaddq	ymm5, ymm5, ymm13
        vpaddq	ymm14, ymm14, ymm14
        vpaddq	ymm6, ymm6, ymm14
        vpaddq	ymm15, ymm15, ymm15
        vpaddq	ymm7, ymm7, ymm15
        vpaddq	ymm16, ymm16, ymm16
        vpaddq	ymm8, ymm8, ymm16
        vpaddq	ymm17, ymm17, ymm17
        ; Reduce
        vpmullq	ymm9, ymm5, ymm31
        vpaddq	ymm0, ymm0, ymm9
        vpmullq	ymm9, ymm6, ymm31
        vpaddq	ymm1, ymm1, ymm9
        vpmullq	ymm9, ymm7, ymm31
        vpaddq	ymm2, ymm2, ymm9
        vpmullq	ymm9, ymm8, ymm31
        vpaddq	ymm3, ymm3, ymm9
        vpmullq	ymm9, ymm17, ymm31
        vpaddq	ymm4, ymm4, ymm9
        vpsrlq	ymm23, ymm0, 51
        vpandq	ymm0, ymm0, ymm28
        vpsrlq	ymm24, ymm1, 51
        vpandq	ymm1, ymm1, ymm28
        vpsrlq	ymm25, ymm2, 51
        vpandq	ymm2, ymm2, ymm28
        vpsrlq	ymm26, ymm3, 51
        vpandq	ymm3, ymm3, ymm28
        vpsrlq	ymm27, ymm4, 51
        vpandq	ymm4, ymm4, ymm28
        vmovdqa64	ymm18, ymm0
        vpmadd52luq	ymm18, ymm27, ymm31
        vpaddq	ymm19, ymm1, ymm23
        vpaddq	ymm20, ymm2, ymm24
        vpaddq	ymm21, ymm3, ymm25
        vpaddq	ymm22, ymm4, ymm26
        ; X3 = B - A, Y3 = B + A, Z3 = D + C, T3 = D - C
        vpermq	ymm23, ymm18, 240
        vpermq	ymm24, ymm19, 240
        vpermq	ymm25, ymm20, 240
        vpermq	ymm26, ymm21, 240
        vpermq	ymm27, ymm22, 240
        vpaddq	ymm23{k2}, ymm23, ymm23
        vpaddq	ymm24{k2}, ymm24, ymm24
        vpaddq	ymm25{k2}, ymm25, ymm25
        vpaddq	ymm26{k2}, ymm26, ymm26
        vpaddq	ymm27{k2}, ymm27, ymm27
        vpermq	ymm0, ymm18, 165
        vpermq	ymm1, ymm19, 165
        vpermq	ymm2, ymm20, 165
        vpermq	ymm3, ymm21, 165
        vpermq	ymm4, ymm22, 165
        vpaddq	ymm18, ymm23, ymm0
        vpaddq	ymm19, ymm24, ymm1
        vpaddq	ymm20, ymm25, ymm2
        vpaddq	ymm21, ymm26, ymm3
        vpaddq	ymm22, ymm27, ymm4
        vpaddq	ymm23{k3}, ymm23, ymm29
        vpaddq	ymm24{k3}, ymm24, ymm30
        vpaddq	ymm25{k3}, ymm25, ymm30
        vpaddq	ymm26{k3}, ymm26, ymm30
        vpaddq	ymm27{k3}, ymm27, ymm30
        vpsubq	ymm18{k3}, ymm23, ymm0
        vpsubq	ymm19{k3}, ymm24, ymm1
        vpsubq	ymm20{k3}, ymm25, ymm2
        vpsubq	ymm21{k3}, ymm26, ymm3
        vpsubq	ymm22{k3}, ymm27, ymm4
        vpsrlq	ymm5, ymm18, 51
        vpandq	ymm18, ymm18, ymm28
        vpsrlq	ymm6, ymm19, 51
        vpandq	ymm19, ymm19, ymm28
        vpsrlq	ymm7, ymm20, 51
        vpandq	ymm20, ymm20, ymm28
        vpsrlq	ymm8, ymm21, 51
        vpandq	ymm21, ymm21, ymm28
        vpsrlq	ymm9, ymm22, 51
        vpandq	ymm22, ymm22, ymm28
        vpmadd52luq	ymm18, ymm9, ymm31
        vpaddq	ymm19, ymm19, ymm5
        vpaddq	ymm20, ymm20, ymm6
        vpaddq	ymm21, ymm21, ymm7
        vpaddq	ymm22, ymm22, ymm8
        vmovdqa64	ymm23, ymm18
        vmovdqa64	ymm24, ymm19
        vmovdqa64	ymm25, ymm20
        vmovdqa64	ymm26, ymm21
        vmovdqa64	ymm27, ymm22
        ; To p3
        vpermq	ymm18, ymm23, 36
        vpermq	ymm19, ymm24, 36
        vpermq	ymm20, ymm25, 36
        vpermq	ymm21, ymm26, 36
        vpermq	ymm22, ymm27, 36
        vpermq	ymm23, ymm23, 123
        vpermq	ymm24, ymm24, 123
        vpermq	ymm25, ymm25, 123
        vpermq	ymm26, ymm26, 123
        vpermq	ymm27, ymm27, 123
        ; Multiply 4 field elements
        vpxorq	ymm0, ymm0, ymm0
        vpxorq	ymm9, ymm9, ymm9
        vpxorq	ymm1, ymm1, ymm1
        vpxorq	ymm10, ymm10, ymm10
        vpxorq	ymm2, ymm2, ymm2
        vpxorq	ymm11, ymm11, ymm11
        vpxorq	ymm3, ymm3, ymm3
        vpxorq	ymm12, ymm12, ymm12
        vpxorq	ymm4, ymm4, ymm4
        vpxorq	ymm13, ymm13, ymm13
        vpxorq	ymm5, ymm5, ymm5
        vpxorq	ymm14, ymm14, ymm14
        vpxorq	ymm6, ymm6, ymm6
        vpxorq	ymm15, ymm15, ymm15
        vpxorq	ymm7, ymm7, ymm7
        vpxorq	ymm16, ymm16, ymm16
        vpxorq	ymm8, ymm8, ymm8
        vpxorq	ymm17, ymm17, ymm17
        vpmadd52luq	ymm0, ymm18, ymm23
        vpmadd52huq	ymm9, ymm18, ymm23
        vpmadd52luq	ymm1, ymm18, ymm24
        vpmadd52huq	ymm10, ymm18, ymm24
        vpmadd52luq	ymm2, ymm18, ymm25
        vpmadd52huq	ymm11, ymm18, ymm25
        vpmadd52luq	ymm3, ymm18, ymm26
        vpmadd52huq	ymm12, ymm18, ymm26
        vpmadd52luq	ymm4, ymm18, ymm27
        vpmadd52huq	ymm13, ymm18, ymm27
        vpmadd52luq	ymm1, ymm19, ymm23
        vpmadd52huq	ymm10, ymm19, ymm23
        vpmadd52luq	ymm2, ymm19, ymm24
        vpmadd52huq	ymm11, ymm19, ymm24
        vpmadd52luq	ymm3, ymm19, ymm25
        vpmadd52huq	ymm12, ymm19, ymm25
        vpmadd52luq	ymm4, ymm19, ymm26
        vpmadd52huq	ymm13, ymm19, ymm26
        vpmadd52luq	ymm5, ymm19, ymm27
        vpmadd52huq	ymm14, ymm19, ymm27
        vpmadd52luq	ymm2, ymm20, ymm23
        vpmadd52huq	ymm11, ymm20, ymm23
        vpmadd52luq	ymm3, ymm20, ymm24
        vpmadd52huq	ymm12, ymm20, ymm24
        vpmadd52luq	ymm4, ymm20, ymm25
        vpmadd52huq	ymm13, ymm20, ymm25
        vpmadd52luq	ymm5, ymm20, ymm26
        vpmadd52huq	ymm14, ymm20, ymm26
        vpmadd52luq	ymm6, ymm20, ymm27
        vpmadd52huq	ymm15, ymm20, ymm27
        vpmadd52luq	ymm3, ymm21, ymm23
        vpmadd52huq	ymm12, ymm21, ymm23
        vpmadd52luq	ymm4, ymm21, ymm24
        vpmadd52huq	ymm13, ymm21, ymm24
        vpmadd52luq	ymm5, ymm21, ymm25
        vpmadd52huq	ymm14, ymm21, ymm25
        vpmadd52luq	ymm6, ymm21, ymm26
        vpmadd52huq	ymm15, ymm21, ymm26
        vpmadd52luq	ymm7, ymm21, ymm27
        vpmadd52huq	ymm16, ymm21, ymm27
        vpmadd52luq	ymm4, ymm22, ymm23
        vpmadd52huq	ymm13, ymm22, ymm23
        vpmadd52luq	ymm5, ymm22, ymm24
        vpmadd52huq	ymm14, ymm22, ymm24
        vpmadd52luq	ymm6, ymm22, ymm25
        vpmadd52huq	ymm15, ymm22, ymm25
        vpmadd52luq	ymm7, ymm22, ymm26
        vpmadd52huq	ymm16, ymm22, ymm26
        vpmadd52luq	ymm8, ymm22, ymm27
        vpmadd52huq	ymm17, ymm22, ymm27
        vpaddq	ymm9, ymm9, ymm9
        vpaddq	ymm1, ymm1, ymm9
        vpaddq	ymm10, ymm10, ymm10
        vpaddq	ymm2, ymm2, ymm10
        vpaddq	ymm11, ymm11, ymm11
        vpaddq	ymm3, ymm3, ymm11
        vpaddq	ymm12, ymm12, ymm12
        vpaddq	ymm4, ymm4, ymm12
        vpaddq	ymm13, ymm13, ymm13
        vpaddq	ymm5, ymm5, ymm13
        vpaddq	ymm14, ymm14, ymm14
        vpaddq	ymm6, ymm6, ymm14
        vpaddq	ymm15, ymm15, ymm15
        vpaddq	ymm7, ymm7, ymm15
        vpaddq	ymm16, ymm16, ymm16
        vpaddq	ymm8, ymm8, ymm16
        vpaddq	ymm17, ymm17, ymm17
        ; Reduce
        vpmullq	ymm9, ymm5, ymm31
        vpaddq	ymm0, ymm0, ymm9
        vpmullq	ymm9, ymm6, ymm31
        vpaddq	ymm1, ymm1, ymm9
        vpmullq	ymm9, ymm7, ymm31
        vpaddq	ymm2, ymm2, ymm9
        vpmullq	ymm9, ymm8, ymm31
        vpaddq	ymm3, ymm3, ymm9
        vpmullq	ymm9, ymm17, ymm31
        vpaddq	ymm4, ymm4, ymm9
        vpsrlq	ymm23, ymm0, 51
        vpandq	ymm0, ymm0, ymm28
        vpsrlq	ymm24, ymm1, 51
        vpandq	ymm1, ymm1, ymm28
        vpsrlq	ymm25, ymm2, 51
        vpandq	ymm2, ymm2, ymm28
        vpsrlq	ymm26, ymm3, 51
        vpandq	ymm3, ymm3, ymm28
        vpsrlq	ymm27, ymm4, 51
        vpandq	ymm4, ymm4, ymm28
        vmovdqa64	ymm18, ymm0
        vpmadd52luq	ymm18, ymm27, ymm31
        vpaddq	ymm19, ymm1, ymm23
        vpaddq	ymm20, ymm2, ymm24
        vpaddq	ymm21, ymm3, ymm25
        vpaddq	ymm22, ymm4, ymm26
        add	r12, 160
        ; To cached
        vpermq	ymm23, ymm18, 176
        vpermq	ymm24, ymm19, 176
        vpermq	ymm25, ymm20, 176
        vpermq	ymm26, ymm21, 176
        vpermq	ymm27, ymm22, 176
        vpermq	ymm18, ymm18, 181
        vpermq	ymm19, ymm19, 181
        vpermq	ymm20, ymm20, 181
        vpermq	ymm21, ymm21, 181
        vpermq	ymm22, ymm22, 181
        vpaddq	ymm18{k5}, ymm18, ymm23
        vpaddq	ymm19{k5}, ymm19, ymm24
        vpaddq	ymm20{k5}, ymm20, ymm25
        vpaddq	ymm21{k5}, ymm21, ymm26
        vpaddq	ymm22{k5}, ymm22, ymm27
        vpaddq	ymm18{k6}, ymm18, ymm29
        vpaddq	ymm19{k6}, ymm19, ymm30
        vpaddq	ymm20{k6}, ymm20, ymm30
        vpaddq	ymm21{k6}, ymm21, ymm30
        vpaddq	ymm22{k6}, ymm22, ymm30
        vpsubq	ymm18{k6}, ymm18, ymm23
        vpsubq	ymm19{k6}, ymm19, ymm24
        vpsubq	ymm20{k6}, ymm20, ymm25
        vpsubq	ymm21{k6}, ymm21, ymm26
        vpsubq	ymm22{k6}, ymm22, ymm27
        vpsrlq	ymm0, ymm18, 51
        vpandq	ymm18, ymm18, ymm28
        vpsrlq	ymm1, ymm19, 51
        vpandq	ymm19, ymm19, ymm28
        vpsrlq	ymm2, ymm20, 51
        vpandq	ymm20, ymm20, ymm28
        vpsrlq	ymm3, ymm21, 51
        vpandq	ymm21, ymm21, ymm28
        vpsrlq	ymm4, ymm22, 51
        vpandq	ymm22, ymm22, ymm28
        vpmadd52luq	ymm18, ymm4, ymm31
        vpaddq	ymm19, ymm19, ymm0
        vpaddq	ymm20, ymm20, ymm1
        vpaddq	ymm21, ymm21, ymm2
        vpaddq	ymm22, ymm22, ymm3
        vmovdqu64	ymm23, YMMWORD PTR [rsi+32]
        vmovdqu64	ymm24, YMMWORD PTR [rsi+64]
        vmovdqu64	ymm25, YMMWORD PTR [rsi+96]
        vmovdqu64	ymm26, YMMWORD PTR [rsi+128]
        vmovdqu64	ymm27, YMMWORD PTR [rsi+160]
        ; Multiply 4 field elements
        vpxorq	ymm0, ymm0, ymm0
        vpxorq	ymm9, ymm9, ymm9
        vpxorq	ymm1, ymm1, ymm1
        vpxorq	ymm10, ymm10, ymm10
        vpxorq	ymm2, ymm2, ymm2
        vpxorq	ymm11, ymm11, ymm11
        vpxorq	ymm3, ymm3, ymm3
        vpxorq	ymm12, ymm12, ymm12
        vpxorq	ymm4, ymm4, ymm4
        vpxorq	ymm13, ymm13, ymm13
        vpxorq	ymm5, ymm5, ymm5
        vpxorq	ymm14, ymm14, ymm14
        vpxorq	ymm6, ymm6, ymm6
        vpxorq	ymm15, ymm15, ymm15
        vpxorq	ymm7, ymm7, ymm7
        vpxorq	ymm16, ymm16, ymm16
        vpxorq	ymm8, ymm8, ymm8
        vpxorq	ymm17, ymm17, ymm17
        vpmadd52luq	ymm0, ymm18, ymm23
        vpmadd52huq	ymm9, ymm18, ymm23
        vpmadd52luq	ymm1, ymm18, ymm24
        vpmadd52huq	ymm10, ymm18, ymm24
        vpmadd52luq	ymm2, ymm18, ymm25
        vpmadd52huq	ymm11, ymm18, ymm25
        vpmadd52luq	ymm3, ymm18, ymm26
        vpmadd52huq	ymm12, ymm18, ymm26
        vpmadd52luq	ymm4, ymm18, ymm27
        vpmadd52huq	ymm13, ymm18, ymm27
        vpmadd52luq	ymm1, ymm19, ymm23
        vpmadd52huq	ymm10, ymm19, ymm23
        vpmadd52luq	ymm2, ymm19, ymm24
        vpmadd52huq	ymm11, ymm19, ymm24
        vpmadd52luq	ymm3, ymm19, ymm25
        vpmadd52huq	ymm12, ymm19, ymm25
        vpmadd52luq	ymm4, ymm19, ymm26
        vpmadd52huq	ymm13, ymm19, ymm26
        vpmadd52luq	ymm5, ymm19, ymm27
        vpmadd52huq	ymm14, ymm19, ymm27
        vpmadd52luq	ymm2, ymm20, ymm23
        vpmadd52huq	ymm11, ymm20, ymm23
        vpmadd52luq	ymm3, ymm20, ymm24
        vpmadd52huq	ymm12, ymm20, ymm24
        vpmadd52luq	ymm4, ymm20, ymm25
        vpmadd52huq	ymm13, ymm20, ymm25
        vpmadd52luq	ymm5, ymm20, ymm26
        vpmadd52huq	ymm14, ymm20, ymm26
        vpmadd52luq	ymm6, ymm20, ymm27
        vpmadd52huq	ymm15, ymm20, ymm27
        vpmadd52luq	ymm3, ymm21, ymm23
        vpmadd52huq	ymm12, ymm21, ymm23
        vpmadd52luq	ymm4, ymm21, ymm24
        vpmadd52huq	ymm13, ymm21, ymm24
        vpmadd52luq	ymm5, ymm21, ymm25
        vpmadd52huq	ymm14, ymm21, ymm25
        vpmadd52luq	ymm6, ymm21, ymm26
        vpmadd52huq	ymm15, ymm21, ymm26
        vpmadd52luq	ymm7, ymm21, ymm27
        vpmadd52huq	ymm16, ymm21, ymm27
        vpmadd52luq	ymm4, ymm22, ymm23
        vpmadd52huq	ymm13, ymm22, ymm23
        vpmadd52luq	ymm5, ymm22, ymm24
        vpmadd52huq	ymm14, ymm22, ymm24
        vpmadd52luq	ymm6, ymm22, ymm25
        vpmadd52huq	ymm15, ymm22, ymm25
        vpmadd52luq	ymm7, ymm22, ymm26
        vpmadd52huq	ymm16, ymm22, ymm26
        vpmadd52luq	ymm8, ymm22, ymm27
        vpmadd52huq	ymm17, ymm22, ymm27
        vpaddq	ymm9, ymm9, ymm9
        vpaddq	ymm1, ymm1, ymm9
        vpaddq	ymm10, ymm10, ymm10
        vpaddq	ymm2, ymm2, ymm10
        vpaddq	ymm11, ymm11, ymm11
        vpaddq	ymm3, ymm3, ymm11
        vpaddq	ymm12, ymm12, ymm12
        vpaddq	ymm4, ymm4, ymm12
        vpaddq	ymm13, ymm13, ymm13
        vpaddq	ymm5, ymm5, ymm13
        vpaddq	ymm14, ymm14, ymm14
        vpaddq	ymm6, ymm6, ymm14
        vpaddq	ymm15, ymm15, ymm15
        vpaddq	ymm7, ymm7, ymm15
        vpaddq	ymm16, ymm16, ymm16
        vpaddq	ymm8, ymm8, ymm16
        vpaddq	ymm17, ymm17, ymm17
        ; Reduce
        vpmullq	ymm9, ymm5, ymm31
        vpaddq	ymm0, ymm0, ymm9
        vpmullq	ymm9, ymm6, ymm31
        vpaddq	ymm1, ymm1, ymm9
        vpmullq	ymm9, ymm7, ymm31
        vpaddq	ymm2, ymm2, ymm9
        vpmullq	ymm9, ymm8, ymm31
        vpaddq	ymm3, ymm3, ymm9
        vpmullq	ymm9, ymm17, ymm31
        vpaddq	ymm4, ymm4, ymm9
        vpsrlq	ymm23, ymm0, 51
        vpandq	ymm0, ymm0, ymm28
        vpsrlq	ymm24, ymm1, 51
        vpandq	ymm1, ymm1, ymm28
        vpsrlq	ymm25, ymm2, 51
        vpandq	ymm2, ymm2, ymm28
        vpsrlq	ymm26, ymm3, 51
        vpandq	ymm3, ymm3, ymm28
        vpsrlq	ymm27, ymm4, 51
        vpandq	ymm4, ymm4, ymm28
        vmovdqa64	ymm18, ymm0
        vpmadd52luq	ymm18, ymm27, ymm31
        vpaddq	ymm19, ymm1, ymm23
        vpaddq	ymm20, ymm2, ymm24
        vpaddq	ymm21, ymm3, ymm25
        vpaddq	ymm22, ymm4, ymm26
        vmovdqu64	YMMWORD PTR [r12], ymm18
        vmovdqu64	YMMWORD PTR [r12+32], ymm19
        vmovdqu64	YMMWORD PTR [r12+64], ymm20
        vmovdqu64	YMMWORD PTR [r12+96], ymm21
        vmovdqu64	YMMWORD PTR [r12+128], ymm22
        dec	r11
        jne	L_ge_dsm_dq_avx512_ifma_table
        ; R = identity: X = 0, Y = 1, Z = 1, T = 0
        mov	r9, 1
        mov	QWORD PTR [rbp+1608], r9
        mov	r9, 0
        mov	QWORD PTR [rbp+1640], r9
        mov	QWORD PTR [rbp+1672], r9
        mov	QWORD PTR [rbp+1704], r9
        mov	QWORD PTR [rbp+1736], r9
        mov	r9, 1
        mov	QWORD PTR [rbp+1616], r9
        mov	r9, 0
        mov	QWORD PTR [rbp+1648], r9
        mov	QWORD PTR [rbp+1680], r9
        mov	QWORD PTR [rbp+1712], r9
        mov	QWORD PTR [rbp+1744], r9
        mov	r9, 0
        mov	QWORD PTR [rbp+1600], r9
        mov	QWORD PTR [rbp+1624], r9
        mov	QWORD PTR [rbp+1632], r9
        mov	QWORD PTR [rbp+1656], r9
        mov	QWORD PTR [rbp+1664], r9
        mov	QWORD PTR [rbp+1688], r9
        mov	QWORD PTR [rbp+1696], r9
        mov	QWORD PTR [rbp+1720], r9
        mov	QWORD PTR [rbp+1728], r9
        mov	QWORD PTR [rbp+1752], r9
        mov	r10, 2251799813685247
        vmovdqu64	ymm18, YMMWORD PTR [rbp+1600]
        vmovdqu64	ymm19, YMMWORD PTR [rbp+1632]
        vmovdqu64	ymm20, YMMWORD PTR [rbp+1664]
        vmovdqu64	ymm21, YMMWORD PTR [rbp+1696]
        vmovdqu64	ymm22, YMMWORD PTR [rbp+1728]
        mov	r11, 255
L_ge_dsm_dq_avx512_ifma_bits:
        ; Double
        vpermq	ymm23, ymm18, 100
        vpermq	ymm24, ymm19, 100
        vpermq	ymm25, ymm20, 100
        vpermq	ymm26, ymm21, 100
        vpermq	ymm27, ymm22, 100
        vpermq	ymm18, ymm18, 36
        vpermq	ymm19, ymm19, 36
        vpermq	ymm20, ymm20, 36
        vpermq	ymm21, ymm21, 36
        vpermq	ymm22, ymm22, 36
        vpaddq	ymm18{k1}, ymm18, ymm23
        vpaddq	ymm19{k1}, ymm19, ymm24
        vpaddq	ymm20{k1}, ymm20, ymm25
        vpaddq	ymm21{k1}, ymm21, ymm26
        vpaddq	ymm22{k1}, ymm22, ymm27
        vpsrlq	ymm0, ymm18, 51
        vpandq	ymm18, ymm18, ymm28
        vpsrlq	ymm1, ymm19, 51
        vpandq	ymm19, ymm19, ymm28
        vpsrlq	ymm2, ymm20, 51
        vpandq	ymm20, ymm20, ymm28
        vpsrlq	ymm3, ymm21, 51
        vpandq	ymm21, ymm21, ymm28
        vpsrlq	ymm4, ymm22, 51
        vpandq	ymm22, ymm22, ymm28
        vpmadd52luq	ymm18, ymm4, ymm31
        vpaddq	ymm19, ymm19, ymm0
        vpaddq	ymm20, ymm20, ymm1
        vpaddq	ymm21, ymm21, ymm2
        vpaddq	ymm22, ymm22, ymm3
        vmovdqa64	ymm23, ymm18
        vmovdqa64	ymm24, ymm19
        vmovdqa64	ymm25, ymm20
        vmovdqa64	ymm26, ymm21
        vmovdqa64	ymm27, ymm22
        ; Multiply 4 field elements
        vpxorq	ymm0, ymm0, ymm0
        vpxorq	ymm9, ymm9, ymm9
        vpxorq	ymm1, ymm1, ymm1
        vpxorq	ymm10, ymm10, ymm10
        vpxorq	ymm2, ymm2, ymm2
        vpxorq	ymm11, ymm11, ymm11
        vpxorq	ymm3, ymm3, ymm3
        vpxorq	ymm12, ymm12, ymm12
        vpxorq	ymm4, ymm4, ymm4
        vpxorq	ymm13, ymm13, ymm13
        vpxorq	ymm5, ymm5, ymm5
        vpxorq	ymm14, ymm14, ymm14
        vpxorq	ymm6, ymm6, ymm6
        vpxorq	ymm15, ymm15, ymm15
        vpxorq	ymm7, ymm7, ymm7
        vpxorq	ymm16, ymm16, ymm16
        vpxorq	ymm8, ymm8, ymm8
        vpxorq	ymm17, ymm17, ymm17
        vpmadd52luq	ymm0, ymm18, ymm23
        vpmadd52huq	ymm9, ymm18, ymm23
        vpmadd52luq	ymm1, ymm18, ymm24
        vpmadd52huq	ymm10, ymm18, ymm24
        vpmadd52luq	ymm2, ymm18, ymm25
        vpmadd52huq	ymm11, ymm18, ymm25
        vpmadd52luq	ymm3, ymm18, ymm26
        vpmadd52huq	ymm12, ymm18, ymm26
        vpmadd52luq	ymm4, ymm18, ymm27
        vpmadd52huq	ymm13, ymm18, ymm27
        vpmadd52luq	ymm1, ymm19, ymm23
        vpmadd52huq	ymm10, ymm19, ymm23
        vpmadd52luq	ymm2, ymm19, ymm24
        vpmadd52huq	ymm11, ymm19, ymm24
        vpmadd52luq	ymm3, ymm19, ymm25
        vpmadd52huq	ymm12, ymm19, ymm25
        vpmadd52luq	ymm4, ymm19, ymm26
        vpmadd52huq	ymm13, ymm19, ymm26
        vpmadd52luq	ymm5, ymm19, ymm27
        vpmadd52huq	ymm14, ymm19, ymm27
        vpmadd52luq	ymm2, ymm20, ymm23
        vpmadd52huq	ymm11, ymm20, ymm23
        vpmadd52luq	ymm3, ymm20, ymm24
        vpmadd52huq	ymm12, ymm20, ymm24
        vpmadd52luq	ymm4, ymm20, ymm25
        vpmadd52huq	ymm13, ymm20, ymm25
        vpmadd52luq	ymm5, ymm20, ymm26
        vpmadd52huq	ymm14, ymm20, ymm26
        vpmadd52luq	ymm6, ymm20, ymm27
        vpmadd52huq	ymm15, ymm20, ymm27
        vpmadd52luq	ymm3, ymm21, ymm23
        vpmadd52huq	ymm12, ymm21, ymm23
        vpmadd52luq	ymm4, ymm21, ymm24
        vpmadd52huq	ymm13, ymm21, ymm24
        vpmadd52luq	ymm5, ymm21, ymm25
        vpmadd52huq	ymm14, ymm21, ymm25
        vpmadd52luq	ymm6, ymm21, ymm26
        vpmadd52huq	ymm15, ymm21, ymm26
        vpmadd52luq	ymm7, ymm21, ymm27
        vpmadd52huq	ymm16, ymm21, ymm27
        vpmadd52luq	ymm4, ymm22, ymm23
        vpmadd52huq	ymm13, ymm22, ymm23
        vpmadd52luq	ymm5, ymm22, ymm24
        vpmadd52huq	ymm14, ymm22, ymm24
        vpmadd52luq	ymm6, ymm22, ymm25
        vpmadd52huq	ymm15, ymm22, ymm25
        vpmadd52luq	ymm7, ymm22, ymm26
        vpmadd52huq	ymm16, ymm22, ymm26
        vpmadd52luq	ymm8, ymm22, ymm27
        vpmadd52huq	ymm17, ymm22, ymm27
        vpaddq	ymm9, ymm9, ymm9
        vpaddq	ymm1, ymm1, ymm9
        vpaddq	ymm10, ymm10, ymm10
        vpaddq	ymm2, ymm2, ymm10
        vpaddq	ymm11, ymm11, ymm11
        vpaddq	ymm3, ymm3, ymm11
        vpaddq	ymm12, ymm12, ymm12
        vpaddq	ymm4, ymm4, ymm12
        vpaddq	ymm13, ymm13, ymm13
        vpaddq	ymm5, ymm5, ymm13
        vpaddq	ymm14, ymm14, ymm14
        vpaddq	ymm6, ymm6, ymm14
        vpaddq	ymm15, ymm15, ymm15
        vpaddq	ymm7, ymm7, ymm15
        vpaddq	ymm16, ymm16, ymm16
        vpaddq	ymm8, ymm8, ymm16
        vpaddq	ymm17, ymm17, ymm17
        ; Reduce
        vpmullq	ymm9, ymm5, ymm31
        vpaddq	ymm0, ymm0, ymm9
        vpmullq	ymm9, ymm6, ymm31
        vpaddq	ymm1, ymm1, ymm9
        vpmullq	ymm9, ymm7, ymm31
        vpaddq	ymm2, ymm2, ymm9
        vpmullq	ymm9, ymm8, ymm31
        vpaddq	ymm3, ymm3, ymm9
        vpmullq	ymm9, ymm17, ymm31
        vpaddq	ymm4, ymm4, ymm9
        vpsrlq	ymm23, ymm0, 51
        vpandq	ymm0, ymm0, ymm28
        vpsrlq	ymm24, ymm1, 51
        vpandq	ymm1, ymm1, ymm28
        vpsrlq	ymm25, ymm2, 51
        vpandq	ymm2, ymm2, ymm28
        vpsrlq	ymm26, ymm3, 51
        vpandq	ymm3, ymm3, ymm28
        vpsrlq	ymm27, ymm4, 51
        vpandq	ymm4, ymm4, ymm28
        vmovdqa64	ymm18, ymm0
        vpmadd52luq	ymm18, ymm27, ymm31
        vpaddq	ymm19, ymm1, ymm23
        vpaddq	ymm20, ymm2, ymm24
        vpaddq	ymm21, ymm3, ymm25
        vpaddq	ymm22, ymm4, ymm26
        ; Y3 = YY + XX, Z3 = YY - XX
        vpermq	ymm23, ymm18, 85
        vpermq	ymm24, ymm19, 85
        vpermq	ymm25, ymm20, 85
        vpermq	ymm26, ymm21, 85
        vpermq	ymm27, ymm22, 85
        vpermq	ymm0, ymm18, 0
        vpermq	ymm1, ymm19, 0
        vpermq	ymm2, ymm20, 0
        vpermq	ymm3, ymm21, 0
        vpermq	ymm4, ymm22, 0
        vpaddq	ymm5, ymm23, ymm0
        vpaddq	ymm6, ymm24, ymm1
        vpaddq	ymm7, ymm25, ymm2
        vpaddq	ymm8, ymm26, ymm3
        vpaddq	ymm9, ymm27, ymm4
        vpaddq	ymm23{k2}, ymm23, ymm29
        vpaddq	ymm24{k2}, ymm24, ymm30
        vpaddq	ymm25{k2}, ymm25, ymm30
        vpaddq	ymm26{k2}, ymm26, ymm30
        vpaddq	ymm27{k2}, ymm27, ymm30
        vpsubq	ymm5{k2}, ymm23, ymm0
        vpsubq	ymm6{k2}, ymm24, ymm1
        vpsubq	ymm7{k2}, ymm25, ymm2
        vpsubq	ymm8{k2}, ymm26, ymm3
        vpsubq	ymm9{k2}, ymm27, ymm4
        vpsrlq	ymm23, ymm5, 51
        vpandq	ymm5, ymm5, ymm28
        vpsrlq	ymm24, ymm6, 51
        vpandq	ymm6, ymm6, ymm28
        vpsrlq	ymm25, ymm7, 51
        vpandq	ymm7, ymm7, ymm28
        vpsrlq	ymm26, ymm8, 51
        vpandq	ymm8, ymm8, ymm28
        vpsrlq	ymm27, ymm9, 51
        vpandq	ymm9, ymm9, ymm28
        vpmadd52luq	ymm5, ymm27, ymm31
        vpaddq	ymm6, ymm6, ymm23
        vpaddq	ymm7, ymm7, ymm24
        vpaddq	ymm8, ymm8, ymm25
        vpaddq	ymm9, ymm9, ymm26
        ; X3 = AA - Y3, T3 = 2.ZZ - Z3
        vpermq	ymm23, ymm18, 175
        vpermq	ymm24, ymm19, 175
        vpermq	ymm25, ymm20, 175
        vpermq	ymm26, ymm21, 175
        vpermq	ymm27, ymm22, 175
        vpaddq	ymm23{k2}, ymm23, ymm23
        vpaddq	ymm24{k2}, ymm24, ymm24
        vpaddq	ymm25{k2}, ymm25, ymm25
        vpaddq	ymm26{k2}, ymm26, ymm26
        vpaddq	ymm27{k2}, ymm27, ymm27
        vpaddq	ymm23{k3}, ymm23, ymm29
        vpaddq	ymm24{k3}, ymm24, ymm30
        vpaddq	ymm25{k3}, ymm25, ymm30
        vpaddq	ymm26{k3}, ymm26, ymm30
        vpaddq	ymm27{k3}, ymm27, ymm30
        vpsubq	ymm23{k3}, ymm23, ymm5
        vpsubq	ymm24{k3}, ymm24, ymm6
        vpsubq	ymm25{k3}, ymm25, ymm7
        vpsubq	ymm26{k3}, ymm26, ymm8
        vpsubq	ymm27{k3}, ymm27, ymm9
        vpsrlq	ymm0, ymm23, 51
        vpandq	ymm23, ymm23, ymm28
        vpsrlq	ymm1, ymm24, 51
        vpandq	ymm24, ymm24, ymm28
        vpsrlq	ymm2, ymm25, 51
        vpandq	ymm25, ymm25, ymm28
        vpsrlq	ymm3, ymm26, 51
        vpandq	ymm26, ymm26, ymm28
        vpsrlq	ymm4, ymm27, 51
        vpandq	ymm27, ymm27, ymm28
        vpmadd52luq	ymm23, ymm4, ymm31
        vpaddq	ymm24, ymm24, ymm0
        vpaddq	ymm25, ymm25, ymm1
        vpaddq	ymm26, ymm26, ymm2
        vpaddq	ymm27, ymm27, ymm3
        vmovdqa64	ymm23{k4}, ymm5
        vmovdqa64	ymm24{k4}, ymm6
        vmovdqa64	ymm25{k4}, ymm7
        vmovdqa64	ymm26{k4}, ymm8
        vmovdqa64	ymm27{k4}, ymm9
        ; Add the multiple of A selected by this window digit
        movsx	r12, BYTE PTR [rbp+r11+1920]
        test	r12, r12
        je	L_ge_dsm_dq_avx512_ifma_skip_a
        mov	r15, r12
        sar	r15, 63
        xor	r12, r15
        sub	r12, r15
        shr	r12, 1
        imul	r12, r12, 160
        lea	rdi, QWORD PTR [rbp]
        add	rdi, r12
        vmovdqu64	ymm18, YMMWORD PTR [rdi]
        vmovdqu64	ymm19, YMMWORD PTR [rdi+32]
        vmovdqu64	ymm20, YMMWORD PTR [rdi+64]
        vmovdqu64	ymm21, YMMWORD PTR [rdi+96]
        vmovdqu64	ymm22, YMMWORD PTR [rdi+128]
        test	r15, r15
        je	L_ge_dsm_dq_avx512_ifma_noswap_a
        vpermq	ymm18, ymm18, 225
        vpermq	ymm19, ymm19, 225
        vpermq	ymm20, ymm20, 225
        vpermq	ymm21, ymm21, 225
        vpermq	ymm22, ymm22, 225
L_ge_dsm_dq_avx512_ifma_noswap_a:
        vmovdqu64	YMMWORD PTR [rbp+1760], ymm18
        vmovdqu64	YMMWORD PTR [rbp+1792], ymm19
        vmovdqu64	YMMWORD PTR [rbp+1824], ymm20
        vmovdqu64	YMMWORD PTR [rbp+1856], ymm21
        vmovdqu64	YMMWORD PTR [rbp+1888], ymm22
        ; To p3
        vpermq	ymm18, ymm23, 36
        vpermq	ymm19, ymm24, 36
        vpermq	ymm20, ymm25, 36
        vpermq	ymm21, ymm26, 36
        vpermq	ymm22, ymm27, 36
        vpermq	ymm23, ymm23, 123
        vpermq	ymm24, ymm24, 123
        vpermq	ymm25, ymm25, 123
        vpermq	ymm26, ymm26, 123
        vpermq	ymm27, ymm27, 123
        ; Multiply 4 field elements
        vpxorq	ymm0, ymm0, ymm0
        vpxorq	ymm9, ymm9, ymm9
        vpxorq	ymm1, ymm1, ymm1
        vpxorq	ymm10, ymm10, ymm10
        vpxorq	ymm2, ymm2, ymm2
        vpxorq	ymm11, ymm11, ymm11
        vpxorq	ymm3, ymm3, ymm3
        vpxorq	ymm12, ymm12, ymm12
        vpxorq	ymm4, ymm4, ymm4
        vpxorq	ymm13, ymm13, ymm13
        vpxorq	ymm5, ymm5, ymm5
        vpxorq	ymm14, ymm14, ymm14
        vpxorq	ymm6, ymm6, ymm6
        vpxorq	ymm15, ymm15, ymm15
        vpxorq	ymm7, ymm7, ymm7
        vpxorq	ymm16, ymm16, ymm16
        vpxorq	ymm8, ymm8, ymm8
        vpxorq	ymm17, ymm17, ymm17
        vpmadd52luq	ymm0, ymm18, ymm23
        vpmadd52huq	ymm9, ymm18, ymm23
        vpmadd52luq	ymm1, ymm18, ymm24
        vpmadd52huq	ymm10, ymm18, ymm24
        vpmadd52luq	ymm2, ymm18, ymm25
        vpmadd52huq	ymm11, ymm18, ymm25
        vpmadd52luq	ymm3, ymm18, ymm26
        vpmadd52huq	ymm12, ymm18, ymm26
        vpmadd52luq	ymm4, ymm18, ymm27
        vpmadd52huq	ymm13, ymm18, ymm27
        vpmadd52luq	ymm1, ymm19, ymm23
        vpmadd52huq	ymm10, ymm19, ymm23
        vpmadd52luq	ymm2, ymm19, ymm24
        vpmadd52huq	ymm11, ymm19, ymm24
        vpmadd52luq	ymm3, ymm19, ymm25
        vpmadd52huq	ymm12, ymm19, ymm25
        vpmadd52luq	ymm4, ymm19, ymm26
        vpmadd52huq	ymm13, ymm19, ymm26
        vpmadd52luq	ymm5, ymm19, ymm27
        vpmadd52huq	ymm14, ymm19, ymm27
        vpmadd52luq	ymm2, ymm20, ymm23
        vpmadd52huq	ymm11, ymm20, ymm23
        vpmadd52luq	ymm3, ymm20, ymm24
        vpmadd52huq	ymm12, ymm20, ymm24
        vpmadd52luq	ymm4, ymm20, ymm25
        vpmadd52huq	ymm13, ymm20, ymm25
        vpmadd52luq	ymm5, ymm20, ymm26
        vpmadd52huq	ymm14, ymm20, ymm26
        vpmadd52luq	ymm6, ymm20, ymm27
        vpmadd52huq	ymm15, ymm20, ymm27
        vpmadd52luq	ymm3, ymm21, ymm23
        vpmadd52huq	ymm12, ymm21, ymm23
        vpmadd52luq	ymm4, ymm21, ymm24
        vpmadd52huq	ymm13, ymm21, ymm24
        vpmadd52luq	ymm5, ymm21, ymm25
        vpmadd52huq	ymm14, ymm21, ymm25
        vpmadd52luq	ymm6, ymm21, ymm26
        vpmadd52huq	ymm15, ymm21, ymm26
        vpmadd52luq	ymm7, ymm21, ymm27
        vpmadd52huq	ymm16, ymm21, ymm27
        vpmadd52luq	ymm4, ymm22, ymm23
        vpmadd52huq	ymm13, ymm22, ymm23
        vpmadd52luq	ymm5, ymm22, ymm24
        vpmadd52huq	ymm14, ymm22, ymm24
        vpmadd52luq	ymm6, ymm22, ymm25
        vpmadd52huq	ymm15, ymm22, ymm25
        vpmadd52luq	ymm7, ymm22, ymm26
        vpmadd52huq	ymm16, ymm22, ymm26
        vpmadd52luq	ymm8, ymm22, ymm27
        vpmadd52huq	ymm17, ymm22, ymm27
        vpaddq	ymm9, ymm9, ymm9
        vpaddq	ymm1, ymm1, ymm9
        vpaddq	ymm10, ymm10, ymm10
        vpaddq	ymm2, ymm2, ymm10
        vpaddq	ymm11, ymm11, ymm11
        vpaddq	ymm3, ymm3, ymm11
        vpaddq	ymm12, ymm12, ymm12
        vpaddq	ymm4, ymm4, ymm12
        vpaddq	ymm13, ymm13, ymm13
        vpaddq	ymm5, ymm5, ymm13
        vpaddq	ymm14, ymm14, ymm14
        vpaddq	ymm6, ymm6, ymm14
        vpaddq	ymm15, ymm15, ymm15
        vpaddq	ymm7, ymm7, ymm15
        vpaddq	ymm16, ymm16, ymm16
        vpaddq	ymm8, ymm8, ymm16
        vpaddq	ymm17, ymm17, ymm17
        ; Reduce
        vpmullq	ymm9, ymm5, ymm31
        vpaddq	ymm0, ymm0, ymm9
        vpmullq	ymm9, ymm6, ymm31
        vpaddq	ymm1, ymm1, ymm9
        vpmullq	ymm9, ymm7, ymm31
        vpaddq	ymm2, ymm2, ymm9
        vpmullq	ymm9, ymm8, ymm31
        vpaddq	ymm3, ymm3, ymm9
        vpmullq	ymm9, ymm17, ymm31
        vpaddq	ymm4, ymm4, ymm9
        vpsrlq	ymm23, ymm0, 51
        vpandq	ymm0, ymm0, ymm28
        vpsrlq	ymm24, ymm1, 51
        vpandq	ymm1, ymm1, ymm28
        vpsrlq	ymm25, ymm2, 51
        vpandq	ymm2, ymm2, ymm28
        vpsrlq	ymm26, ymm3, 51
        vpandq	ymm3, ymm3, ymm28
        vpsrlq	ymm27, ymm4, 51
        vpandq	ymm4, ymm4, ymm28
        vmovdqa64	ymm18, ymm0
        vpmadd52luq	ymm18, ymm27, ymm31
        vpaddq	ymm19, ymm1, ymm23
        vpaddq	ymm20, ymm2, ymm24
        vpaddq	ymm21, ymm3, ymm25
        vpaddq	ymm22, ymm4, ymm26
        ; Add
        vpermq	ymm23, ymm18, 176
        vpermq	ymm24, ymm19, 176
        vpermq	ymm25, ymm20, 176
        vpermq	ymm26, ymm21, 176
        vpermq	ymm27, ymm22, 176
        vpermq	ymm18, ymm18, 181
        vpermq	ymm19, ymm19, 181
        vpermq	ymm20, ymm20, 181
        vpermq	ymm21, ymm21, 181
        vpermq	ymm22, ymm22, 181
        vpaddq	ymm18{k5}, ymm18, ymm23
        vpaddq	ymm19{k5}, ymm19, ymm24
        vpaddq	ymm20{k5}, ymm20, ymm25
        vpaddq	ymm21{k5}, ymm21, ymm26
        vpaddq	ymm22{k5}, ymm22, ymm27
        vpaddq	ymm18{k6}, ymm18, ymm29
        vpaddq	ymm19{k6}, ymm19, ymm30
        vpaddq	ymm20{k6}, ymm20, ymm30
        vpaddq	ymm21{k6}, ymm21, ymm30
        vpaddq	ymm22{k6}, ymm22, ymm30
        vpsubq	ymm18{k6}, ymm18, ymm23
        vpsubq	ymm19{k6}, ymm19, ymm24
        vpsubq	ymm20{k6}, ymm20, ymm25
        vpsubq	ymm21{k6}, ymm21, ymm26
        vpsubq	ymm22{k6}, ymm22, ymm27
        vpsrlq	ymm0, ymm18, 51
        vpandq	ymm18, ymm18, ymm28
        vpsrlq	ymm1, ymm19, 51
        vpandq	ymm19, ymm19, ymm28
        vpsrlq	ymm2, ymm20, 51
        vpandq	ymm20, ymm20, ymm28
        vpsrlq	ymm3, ymm21, 51
        vpandq	ymm21, ymm21, ymm28
        vpsrlq	ymm4, ymm22, 51
        vpandq	ymm22, ymm22, ymm28
        vpmadd52luq	ymm18, ymm4, ymm31
        vpaddq	ymm19, ymm19, ymm0
        vpaddq	ymm20, ymm20, ymm1
        vpaddq	ymm21, ymm21, ymm2
        vpaddq	ymm22, ymm22, ymm3
        vmovdqu64	ymm23, YMMWORD PTR [rbp+1760]
        vmovdqu64	ymm24, YMMWORD PTR [rbp+1792]
        vmovdqu64	ymm25, YMMWORD PTR [rbp+1824]
        vmovdqu64	ymm26, YMMWORD PTR [rbp+1856]
        vmovdqu64	ymm27, YMMWORD PTR [rbp+1888]
        ; Multiply 4 field elements
        vpxorq	ymm0, ymm0, ymm0
        vpxorq	ymm9, ymm9, ymm9
        vpxorq	ymm1, ymm1, ymm1
        vpxorq	ymm10, ymm10, ymm10
        vpxorq	ymm2, ymm2, ymm2
        vpxorq	ymm11, ymm11, ymm11
        vpxorq	ymm3, ymm3, ymm3
        vpxorq	ymm12, ymm12, ymm12
        vpxorq	ymm4, ymm4, ymm4
        vpxorq	ymm13, ymm13, ymm13
        vpxorq	ymm5, ymm5, ymm5
        vpxorq	ymm14, ymm14, ymm14
        vpxorq	ymm6, ymm6, ymm6
        vpxorq	ymm15, ymm15, ymm15
        vpxorq	ymm7, ymm7, ymm7
        vpxorq	ymm16, ymm16, ymm16
        vpxorq	ymm8, ymm8, ymm8
        vpxorq	ymm17, ymm17, ymm17
        vpmadd52luq	ymm0, ymm18, ymm23
        vpmadd52huq	ymm9, ymm18, ymm23
        vpmadd52luq	ymm1, ymm18, ymm24
        vpmadd52huq	ymm10, ymm18, ymm24
        vpmadd52luq	ymm2, ymm18, ymm25
        vpmadd52huq	ymm11, ymm18, ymm25
        vpmadd52luq	ymm3, ymm18, ymm26
        vpmadd52huq	ymm12, ymm18, ymm26
        vpmadd52luq	ymm4, ymm18, ymm27
        vpmadd52huq	ymm13, ymm18, ymm27
        vpmadd52luq	ymm1, ymm19, ymm23
        vpmadd52huq	ymm10, ymm19, ymm23
        vpmadd52luq	ymm2, ymm19, ymm24
        vpmadd52huq	ymm11, ymm19, ymm24
        vpmadd52luq	ymm3, ymm19, ymm25
        vpmadd52huq	ymm12, ymm19, ymm25
        vpmadd52luq	ymm4, ymm19, ymm26
        vpmadd52huq	ymm13, ymm19, ymm26
        vpmadd52luq	ymm5, ymm19, ymm27
        vpmadd52huq	ymm14, ymm19, ymm27
        vpmadd52luq	ymm2, ymm20, ymm23
        vpmadd52huq	ymm11, ymm20, ymm23
        vpmadd52luq	ymm3, ymm20, ymm24
        vpmadd52huq	ymm12, ymm20, ymm24
        vpmadd52luq	ymm4, ymm20, ymm25
        vpmadd52huq	ymm13, ymm20, ymm25
        vpmadd52luq	ymm5, ymm20, ymm26
        vpmadd52huq	ymm14, ymm20, ymm26
        vpmadd52luq	ymm6, ymm20, ymm27
        vpmadd52huq	ymm15, ymm20, ymm27
        vpmadd52luq	ymm3, ymm21, ymm23
        vpmadd52huq	ymm12, ymm21, ymm23
        vpmadd52luq	ymm4, ymm21, ymm24
        vpmadd52huq	ymm13, ymm21, ymm24
        vpmadd52luq	ymm5, ymm21, ymm25
        vpmadd52huq	ymm14, ymm21, ymm25
        vpmadd52luq	ymm6, ymm21, ymm26
        vpmadd52huq	ymm15, ymm21, ymm26
        vpmadd52luq	ymm7, ymm21, ymm27
        vpmadd52huq	ymm16, ymm21, ymm27
        vpmadd52luq	ymm4, ymm22, ymm23
        vpmadd52huq	ymm13, ymm22, ymm23
        vpmadd52luq	ymm5, ymm22, ymm24
        vpmadd52huq	ymm14, ymm22, ymm24
        vpmadd52luq	ymm6, ymm22, ymm25
        vpmadd52huq	ymm15, ymm22, ymm25
        vpmadd52luq	ymm7, ymm22, ymm26
        vpmadd52huq	ymm16, ymm22, ymm26
        vpmadd52luq	ymm8, ymm22, ymm27
        vpmadd52huq	ymm17, ymm22, ymm27
        vpaddq	ymm9, ymm9, ymm9
        vpaddq	ymm1, ymm1, ymm9
        vpaddq	ymm10, ymm10, ymm10
        vpaddq	ymm2, ymm2, ymm10
        vpaddq	ymm11, ymm11, ymm11
        vpaddq	ymm3, ymm3, ymm11
        vpaddq	ymm12, ymm12, ymm12
        vpaddq	ymm4, ymm4, ymm12
        vpaddq	ymm13, ymm13, ymm13
        vpaddq	ymm5, ymm5, ymm13
        vpaddq	ymm14, ymm14, ymm14
        vpaddq	ymm6, ymm6, ymm14
        vpaddq	ymm15, ymm15, ymm15
        vpaddq	ymm7, ymm7, ymm15
        vpaddq	ymm16, ymm16, ymm16
        vpaddq	ymm8, ymm8, ymm16
        vpaddq	ymm17, ymm17, ymm17
        ; Reduce
        vpmullq	ymm9, ymm5, ymm31
        vpaddq	ymm0, ymm0, ymm9
        vpmullq	ymm9, ymm6, ymm31
        vpaddq	ymm1, ymm1, ymm9
        vpmullq	ymm9, ymm7, ymm31
        vpaddq	ymm2, ymm2, ymm9
        vpmullq	ymm9, ymm8, ymm31
        vpaddq	ymm3, ymm3, ymm9
        vpmullq	ymm9, ymm17, ymm31
        vpaddq	ymm4, ymm4, ymm9
        vpsrlq	ymm23, ymm0, 51
        vpandq	ymm0, ymm0, ymm28
        vpsrlq	ymm24, ymm1, 51
        vpandq	ymm1, ymm1, ymm28
        vpsrlq	ymm25, ymm2, 51
        vpandq	ymm2, ymm2, ymm28
        vpsrlq	ymm26, ymm3, 51
        vpandq	ymm3, ymm3, ymm28
        vpsrlq	ymm27, ymm4, 51
        vpandq	ymm4, ymm4, ymm28
        vmovdqa64	ymm18, ymm0
        vpmadd52luq	ymm18, ymm27, ymm31
        vpaddq	ymm19, ymm1, ymm23
        vpaddq	ymm20, ymm2, ymm24
        vpaddq	ymm21, ymm3, ymm25
        vpaddq	ymm22, ymm4, ymm26
        ; X3 = B - A, Y3 = B + A, Z3 = D + C, T3 = D - C
        vpermq	ymm23, ymm18, 240
        vpermq	ymm24, ymm19, 240
        vpermq	ymm25, ymm20, 240
        vpermq	ymm26, ymm21, 240
        vpermq	ymm27, ymm22, 240
        vpaddq	ymm23{k2}, ymm23, ymm23
        vpaddq	ymm24{k2}, ymm24, ymm24
        vpaddq	ymm25{k2}, ymm25, ymm25
        vpaddq	ymm26{k2}, ymm26, ymm26
        vpaddq	ymm27{k2}, ymm27, ymm27
        vpermq	ymm0, ymm18, 165
        vpermq	ymm1, ymm19, 165
        vpermq	ymm2, ymm20, 165
        vpermq	ymm3, ymm21, 165
        vpermq	ymm4, ymm22, 165
        vpaddq	ymm18, ymm23, ymm0
        vpaddq	ymm19, ymm24, ymm1
        vpaddq	ymm20, ymm25, ymm2
        vpaddq	ymm21, ymm26, ymm3
        vpaddq	ymm22, ymm27, ymm4
        vpaddq	ymm23{k3}, ymm23, ymm29
        vpaddq	ymm24{k3}, ymm24, ymm30
        vpaddq	ymm25{k3}, ymm25, ymm30
        vpaddq	ymm26{k3}, ymm26, ymm30
        vpaddq	ymm27{k3}, ymm27, ymm30
        vpsubq	ymm18{k3}, ymm23, ymm0
        vpsubq	ymm19{k3}, ymm24, ymm1
        vpsubq	ymm20{k3}, ymm25, ymm2
        vpsubq	ymm21{k3}, ymm26, ymm3
        vpsubq	ymm22{k3}, ymm27, ymm4
        vpsrlq	ymm5, ymm18, 51
        vpandq	ymm18, ymm18, ymm28
        vpsrlq	ymm6, ymm19, 51
        vpandq	ymm19, ymm19, ymm28
        vpsrlq	ymm7, ymm20, 51
        vpandq	ymm20, ymm20, ymm28
        vpsrlq	ymm8, ymm21, 51
        vpandq	ymm21, ymm21, ymm28
        vpsrlq	ymm9, ymm22, 51
        vpandq	ymm22, ymm22, ymm28
        vpmadd52luq	ymm18, ymm9, ymm31
        vpaddq	ymm19, ymm19, ymm5
        vpaddq	ymm20, ymm20, ymm6
        vpaddq	ymm21, ymm21, ymm7
        vpaddq	ymm22, ymm22, ymm8
        test	r15, r15
        je	L_ge_dsm_dq_avx512_ifma_nores_a
        vpermq	ymm18, ymm18, 180
        vpermq	ymm19, ymm19, 180
        vpermq	ymm20, ymm20, 180
        vpermq	ymm21, ymm21, 180
        vpermq	ymm22, ymm22, 180
L_ge_dsm_dq_avx512_ifma_nores_a:
        vmovdqa64	ymm23, ymm18
        vmovdqa64	ymm24, ymm19
        vmovdqa64	ymm25, ymm20
        vmovdqa64	ymm26, ymm21
        vmovdqa64	ymm27, ymm22
L_ge_dsm_dq_avx512_ifma_skip_a:
        ; Add the multiple of the base point
        movsx	r12, BYTE PTR [rbp+r11+2176]
        test	r12, r12
        je	L_ge_dsm_dq_avx512_ifma_skip_b
        mov	r15, r12
        sar	r15, 63
        xor	r12, r15
        sub	r12, r15
        shr	r12, 1
        imul	r12, r12, 96
        mov	rdi, rbx
        add	rdi, r12
        mov	rdx, QWORD PTR [rdi]
        mov	rax, QWORD PTR [rdi+8]
        mov	rcx, QWORD PTR [rdi+16]
        mov	r8, QWORD PTR [rdi+24]
        mov	r9, r8
        shr	r9, 63
        imul	r9, r9, 19
        shl	r8, 1
        shr	r8, 1
        mov	r13, rdx
        and	r13, r10
        add	r13, r9
        mov	QWORD PTR [rbp+1760], r13
        shrd	rdx, rax, 51
        mov	r9, rdx
        and	r9, r10
        mov	QWORD PTR [rbp+1792], r9
        shrd	rax, rcx, 38
        mov	r9, rax
        and	r9, r10
        mov	QWORD PTR [rbp+1824], r9
        shrd	rcx, r8, 25
        mov	r9, rcx
        and	r9, r10
        mov	QWORD PTR [rbp+1856], r9
        shr	r8, 12
        mov	QWORD PTR [rbp+1888], r8
        mov	rdx, QWORD PTR [rdi+32]
        mov	rax, QWORD PTR [rdi+40]
        mov	rcx, QWORD PTR [rdi+48]
        mov	r8, QWORD PTR [rdi+56]
        mov	r9, r8
        shr	r9, 63
        imul	r9, r9, 19
        shl	r8, 1
        shr	r8, 1
        mov	r13, rdx
        and	r13, r10
        add	r13, r9
        mov	QWORD PTR [rbp+1768], r13
        shrd	rdx, rax, 51
        mov	r9, rdx
        and	r9, r10
        mov	QWORD PTR [rbp+1800], r9
        shrd	rax, rcx, 38
        mov	r9, rax
        and	r9, r10
        mov	QWORD PTR [rbp+1832], r9
        shrd	rcx, r8, 25
        mov	r9, rcx
        and	r9, r10
        mov	QWORD PTR [rbp+1864], r9
        shr	r8, 12
        mov	QWORD PTR [rbp+1896], r8
        mov	rdx, QWORD PTR [rdi+64]
        mov	rax, QWORD PTR [rdi+72]
        mov	rcx, QWORD PTR [rdi+80]
        mov	r8, QWORD PTR [rdi+88]
        mov	r9, r8
        shr	r9, 63
        imul	r9, r9, 19
        shl	r8, 1
        shr	r8, 1
        mov	r13, rdx
        and	r13, r10
        add	r13, r9
        mov	QWORD PTR [rbp+1776], r13
        shrd	rdx, rax, 51
        mov	r9, rdx
        and	r9, r10
        mov	QWORD PTR [rbp+1808], r9
        shrd	rax, rcx, 38
        mov	r9, rax
        and	r9, r10
        mov	QWORD PTR [rbp+1840], r9
        shrd	rcx, r8, 25
        mov	r9, rcx
        and	r9, r10
        mov	QWORD PTR [rbp+1872], r9
        shr	r8, 12
        mov	QWORD PTR [rbp+1904], r8
        mov	rdx, 1
        mov	QWORD PTR [rbp+1784], rdx
        mov	rdx, 0
        mov	QWORD PTR [rbp+1816], rdx
        mov	QWORD PTR [rbp+1848], rdx
        mov	QWORD PTR [rbp+1880], rdx
        mov	QWORD PTR [rbp+1912], rdx
        test	r15, r15
        je	L_ge_dsm_dq_avx512_ifma_noswap_b
        vmovdqu64	ymm18, YMMWORD PTR [rbp+1760]
        vmovdqu64	ymm19, YMMWORD PTR [rbp+1792]
        vmovdqu64	ymm20, YMMWORD PTR [rbp+1824]
        vmovdqu64	ymm21, YMMWORD PTR [rbp+1856]
        vmovdqu64	ymm22, YMMWORD PTR [rbp+1888]
        vpermq	ymm18, ymm18, 225
        vpermq	ymm19, ymm19, 225
        vpermq	ymm20, ymm20, 225
        vpermq	ymm21, ymm21, 225
        vpermq	ymm22, ymm22, 225
        vmovdqu64	YMMWORD PTR [rbp+1760], ymm18
        vmovdqu64	YMMWORD PTR [rbp+1792], ymm19
        vmovdqu64	YMMWORD PTR [rbp+1824], ymm20
        vmovdqu64	YMMWORD PTR [rbp+1856], ymm21
        vmovdqu64	YMMWORD PTR [rbp+1888], ymm22
L_ge_dsm_dq_avx512_ifma_noswap_b:
        ; To p3
        vpermq	ymm18, ymm23, 36
        vpermq	ymm19, ymm24, 36
        vpermq	ymm20, ymm25, 36
        vpermq	ymm21, ymm26, 36
        vpermq	ymm22, ymm27, 36
        vpermq	ymm23, ymm23, 123
        vpermq	ymm24, ymm24, 123
        vpermq	ymm25, ymm25, 123
        vpermq	ymm26, ymm26, 123
        vpermq	ymm27, ymm27, 123
        ; Multiply 4 field elements
        vpxorq	ymm0, ymm0, ymm0
        vpxorq	ymm9, ymm9, ymm9
        vpxorq	ymm1, ymm1, ymm1
        vpxorq	ymm10, ymm10, ymm10
        vpxorq	ymm2, ymm2, ymm2
        vpxorq	ymm11, ymm11, ymm11
        vpxorq	ymm3, ymm3, ymm3
        vpxorq	ymm12, ymm12, ymm12
        vpxorq	ymm4, ymm4, ymm4
        vpxorq	ymm13, ymm13, ymm13
        vpxorq	ymm5, ymm5, ymm5
        vpxorq	ymm14, ymm14, ymm14
        vpxorq	ymm6, ymm6, ymm6
        vpxorq	ymm15, ymm15, ymm15
        vpxorq	ymm7, ymm7, ymm7
        vpxorq	ymm16, ymm16, ymm16
        vpxorq	ymm8, ymm8, ymm8
        vpxorq	ymm17, ymm17, ymm17
        vpmadd52luq	ymm0, ymm18, ymm23
        vpmadd52huq	ymm9, ymm18, ymm23
        vpmadd52luq	ymm1, ymm18, ymm24
        vpmadd52huq	ymm10, ymm18, ymm24
        vpmadd52luq	ymm2, ymm18, ymm25
        vpmadd52huq	ymm11, ymm18, ymm25
        vpmadd52luq	ymm3, ymm18, ymm26
        vpmadd52huq	ymm12, ymm18, ymm26
        vpmadd52luq	ymm4, ymm18, ymm27
        vpmadd52huq	ymm13, ymm18, ymm27
        vpmadd52luq	ymm1, ymm19, ymm23
        vpmadd52huq	ymm10, ymm19, ymm23
        vpmadd52luq	ymm2, ymm19, ymm24
        vpmadd52huq	ymm11, ymm19, ymm24
        vpmadd52luq	ymm3, ymm19, ymm25
        vpmadd52huq	ymm12, ymm19, ymm25
        vpmadd52luq	ymm4, ymm19, ymm26
        vpmadd52huq	ymm13, ymm19, ymm26
        vpmadd52luq	ymm5, ymm19, ymm27
        vpmadd52huq	ymm14, ymm19, ymm27
        vpmadd52luq	ymm2, ymm20, ymm23
        vpmadd52huq	ymm11, ymm20, ymm23
        vpmadd52luq	ymm3, ymm20, ymm24
        vpmadd52huq	ymm12, ymm20, ymm24
        vpmadd52luq	ymm4, ymm20, ymm25
        vpmadd52huq	ymm13, ymm20, ymm25
        vpmadd52luq	ymm5, ymm20, ymm26
        vpmadd52huq	ymm14, ymm20, ymm26
        vpmadd52luq	ymm6, ymm20, ymm27
        vpmadd52huq	ymm15, ymm20, ymm27
        vpmadd52luq	ymm3, ymm21, ymm23
        vpmadd52huq	ymm12, ymm21, ymm23
        vpmadd52luq	ymm4, ymm21, ymm24
        vpmadd52huq	ymm13, ymm21, ymm24
        vpmadd52luq	ymm5, ymm21, ymm25
        vpmadd52huq	ymm14, ymm21, ymm25
        vpmadd52luq	ymm6, ymm21, ymm26
        vpmadd52huq	ymm15, ymm21, ymm26
        vpmadd52luq	ymm7, ymm21, ymm27
        vpmadd52huq	ymm16, ymm21, ymm27
        vpmadd52luq	ymm4, ymm22, ymm23
        vpmadd52huq	ymm13, ymm22, ymm23
        vpmadd52luq	ymm5, ymm22, ymm24
        vpmadd52huq	ymm14, ymm22, ymm24
        vpmadd52luq	ymm6, ymm22, ymm25
        vpmadd52huq	ymm15, ymm22, ymm25
        vpmadd52luq	ymm7, ymm22, ymm26
        vpmadd52huq	ymm16, ymm22, ymm26
        vpmadd52luq	ymm8, ymm22, ymm27
        vpmadd52huq	ymm17, ymm22, ymm27
        vpaddq	ymm9, ymm9, ymm9
        vpaddq	ymm1, ymm1, ymm9
        vpaddq	ymm10, ymm10, ymm10
        vpaddq	ymm2, ymm2, ymm10
        vpaddq	ymm11, ymm11, ymm11
        vpaddq	ymm3, ymm3, ymm11
        vpaddq	ymm12, ymm12, ymm12
        vpaddq	ymm4, ymm4, ymm12
        vpaddq	ymm13, ymm13, ymm13
        vpaddq	ymm5, ymm5, ymm13
        vpaddq	ymm14, ymm14, ymm14
        vpaddq	ymm6, ymm6, ymm14
        vpaddq	ymm15, ymm15, ymm15
        vpaddq	ymm7, ymm7, ymm15
        vpaddq	ymm16, ymm16, ymm16
        vpaddq	ymm8, ymm8, ymm16
        vpaddq	ymm17, ymm17, ymm17
        ; Reduce
        vpmullq	ymm9, ymm5, ymm31
        vpaddq	ymm0, ymm0, ymm9
        vpmullq	ymm9, ymm6, ymm31
        vpaddq	ymm1, ymm1, ymm9
        vpmullq	ymm9, ymm7, ymm31
        vpaddq	ymm2, ymm2, ymm9
        vpmullq	ymm9, ymm8, ymm31
        vpaddq	ymm3, ymm3, ymm9
        vpmullq	ymm9, ymm17, ymm31
        vpaddq	ymm4, ymm4, ymm9
        vpsrlq	ymm23, ymm0, 51
        vpandq	ymm0, ymm0, ymm28
        vpsrlq	ymm24, ymm1, 51
        vpandq	ymm1, ymm1, ymm28
        vpsrlq	ymm25, ymm2, 51
        vpandq	ymm2, ymm2, ymm28
        vpsrlq	ymm26, ymm3, 51
        vpandq	ymm3, ymm3, ymm28
        vpsrlq	ymm27, ymm4, 51
        vpandq	ymm4, ymm4, ymm28
        vmovdqa64	ymm18, ymm0
        vpmadd52luq	ymm18, ymm27, ymm31
        vpaddq	ymm19, ymm1, ymm23
        vpaddq	ymm20, ymm2, ymm24
        vpaddq	ymm21, ymm3, ymm25
        vpaddq	ymm22, ymm4, ymm26
        ; Add
        vpermq	ymm23, ymm18, 176
        vpermq	ymm24, ymm19, 176
        vpermq	ymm25, ymm20, 176
        vpermq	ymm26, ymm21, 176
        vpermq	ymm27, ymm22, 176
        vpermq	ymm18, ymm18, 181
        vpermq	ymm19, ymm19, 181
        vpermq	ymm20, ymm20, 181
        vpermq	ymm21, ymm21, 181
        vpermq	ymm22, ymm22, 181
        vpaddq	ymm18{k5}, ymm18, ymm23
        vpaddq	ymm19{k5}, ymm19, ymm24
        vpaddq	ymm20{k5}, ymm20, ymm25
        vpaddq	ymm21{k5}, ymm21, ymm26
        vpaddq	ymm22{k5}, ymm22, ymm27
        vpaddq	ymm18{k6}, ymm18, ymm29
        vpaddq	ymm19{k6}, ymm19, ymm30
        vpaddq	ymm20{k6}, ymm20, ymm30
        vpaddq	ymm21{k6}, ymm21, ymm30
        vpaddq	ymm22{k6}, ymm22, ymm30
        vpsubq	ymm18{k6}, ymm18, ymm23
        vpsubq	ymm19{k6}, ymm19, ymm24
        vpsubq	ymm20{k6}, ymm20, ymm25
        vpsubq	ymm21{k6}, ymm21, ymm26
        vpsubq	ymm22{k6}, ymm22, ymm27
        vpsrlq	ymm0, ymm18, 51
        vpandq	ymm18, ymm18, ymm28
        vpsrlq	ymm1, ymm19, 51
        vpandq	ymm19, ymm19, ymm28
        vpsrlq	ymm2, ymm20, 51
        vpandq	ymm20, ymm20, ymm28
        vpsrlq	ymm3, ymm21, 51
        vpandq	ymm21, ymm21, ymm28
        vpsrlq	ymm4, ymm22, 51
        vpandq	ymm22, ymm22, ymm28
        vpmadd52luq	ymm18, ymm4, ymm31
        vpaddq	ymm19, ymm19, ymm0
        vpaddq	ymm20, ymm20, ymm1
        vpaddq	ymm21, ymm21, ymm2
        vpaddq	ymm22, ymm22, ymm3
        vmovdqu64	ymm23, YMMWORD PTR [rbp+1760]
        vmovdqu64	ymm24, YMMWORD PTR [rbp+1792]
        vmovdqu64	ymm25, YMMWORD PTR [rbp+1824]
        vmovdqu64	ymm26, YMMWORD PTR [rbp+1856]
        vmovdqu64	ymm27, YMMWORD PTR [rbp+1888]
        ; Multiply 4 field elements
        vpxorq	ymm0, ymm0, ymm0
        vpxorq	ymm9, ymm9, ymm9
        vpxorq	ymm1, ymm1, ymm1
        vpxorq	ymm10, ymm10, ymm10
        vpxorq	ymm2, ymm2, ymm2
        vpxorq	ymm11, ymm11, ymm11
        vpxorq	ymm3, ymm3, ymm3
        vpxorq	ymm12, ymm12, ymm12
        vpxorq	ymm4, ymm4, ymm4
        vpxorq	ymm13, ymm13, ymm13
        vpxorq	ymm5, ymm5, ymm5
        vpxorq	ymm14, ymm14, ymm14
        vpxorq	ymm6, ymm6, ymm6
        vpxorq	ymm15, ymm15, ymm15
        vpxorq	ymm7, ymm7, ymm7
        vpxorq	ymm16, ymm16, ymm16
        vpxorq	ymm8, ymm8, ymm8
        vpxorq	ymm17, ymm17, ymm17
        vpmadd52luq	ymm0, ymm18, ymm23
        vpmadd52huq	ymm9, ymm18, ymm23
        vpmadd52luq	ymm1, ymm18, ymm24
        vpmadd52huq	ymm10, ymm18, ymm24
        vpmadd52luq	ymm2, ymm18, ymm25
        vpmadd52huq	ymm11, ymm18, ymm25
        vpmadd52luq	ymm3, ymm18, ymm26
        vpmadd52huq	ymm12, ymm18, ymm26
        vpmadd52luq	ymm4, ymm18, ymm27
        vpmadd52huq	ymm13, ymm18, ymm27
        vpmadd52luq	ymm1, ymm19, ymm23
        vpmadd52huq	ymm10, ymm19, ymm23
        vpmadd52luq	ymm2, ymm19, ymm24
        vpmadd52huq	ymm11, ymm19, ymm24
        vpmadd52luq	ymm3, ymm19, ymm25
        vpmadd52huq	ymm12, ymm19, ymm25
        vpmadd52luq	ymm4, ymm19, ymm26
        vpmadd52huq	ymm13, ymm19, ymm26
        vpmadd52luq	ymm5, ymm19, ymm27
        vpmadd52huq	ymm14, ymm19, ymm27
        vpmadd52luq	ymm2, ymm20, ymm23
        vpmadd52huq	ymm11, ymm20, ymm23
        vpmadd52luq	ymm3, ymm20, ymm24
        vpmadd52huq	ymm12, ymm20, ymm24
        vpmadd52luq	ymm4, ymm20, ymm25
        vpmadd52huq	ymm13, ymm20, ymm25
        vpmadd52luq	ymm5, ymm20, ymm26
        vpmadd52huq	ymm14, ymm20, ymm26
        vpmadd52luq	ymm6, ymm20, ymm27
        vpmadd52huq	ymm15, ymm20, ymm27
        vpmadd52luq	ymm3, ymm21, ymm23
        vpmadd52huq	ymm12, ymm21, ymm23
        vpmadd52luq	ymm4, ymm21, ymm24
        vpmadd52huq	ymm13, ymm21, ymm24
        vpmadd52luq	ymm5, ymm21, ymm25
        vpmadd52huq	ymm14, ymm21, ymm25
        vpmadd52luq	ymm6, ymm21, ymm26
        vpmadd52huq	ymm15, ymm21, ymm26
        vpmadd52luq	ymm7, ymm21, ymm27
        vpmadd52huq	ymm16, ymm21, ymm27
        vpmadd52luq	ymm4, ymm22, ymm23
        vpmadd52huq	ymm13, ymm22, ymm23
        vpmadd52luq	ymm5, ymm22, ymm24
        vpmadd52huq	ymm14, ymm22, ymm24
        vpmadd52luq	ymm6, ymm22, ymm25
        vpmadd52huq	ymm15, ymm22, ymm25
        vpmadd52luq	ymm7, ymm22, ymm26
        vpmadd52huq	ymm16, ymm22, ymm26
        vpmadd52luq	ymm8, ymm22, ymm27
        vpmadd52huq	ymm17, ymm22, ymm27
        vpaddq	ymm9, ymm9, ymm9
        vpaddq	ymm1, ymm1, ymm9
        vpaddq	ymm10, ymm10, ymm10
        vpaddq	ymm2, ymm2, ymm10
        vpaddq	ymm11, ymm11, ymm11
        vpaddq	ymm3, ymm3, ymm11
        vpaddq	ymm12, ymm12, ymm12
        vpaddq	ymm4, ymm4, ymm12
        vpaddq	ymm13, ymm13, ymm13
        vpaddq	ymm5, ymm5, ymm13
        vpaddq	ymm14, ymm14, ymm14
        vpaddq	ymm6, ymm6, ymm14
        vpaddq	ymm15, ymm15, ymm15
        vpaddq	ymm7, ymm7, ymm15
        vpaddq	ymm16, ymm16, ymm16
        vpaddq	ymm8, ymm8, ymm16
        vpaddq	ymm17, ymm17, ymm17
        ; Reduce
        vpmullq	ymm9, ymm5, ymm31
        vpaddq	ymm0, ymm0, ymm9
        vpmullq	ymm9, ymm6, ymm31
        vpaddq	ymm1, ymm1, ymm9
        vpmullq	ymm9, ymm7, ymm31
        vpaddq	ymm2, ymm2, ymm9
        vpmullq	ymm9, ymm8, ymm31
        vpaddq	ymm3, ymm3, ymm9
        vpmullq	ymm9, ymm17, ymm31
        vpaddq	ymm4, ymm4, ymm9
        vpsrlq	ymm23, ymm0, 51
        vpandq	ymm0, ymm0, ymm28
        vpsrlq	ymm24, ymm1, 51
        vpandq	ymm1, ymm1, ymm28
        vpsrlq	ymm25, ymm2, 51
        vpandq	ymm2, ymm2, ymm28
        vpsrlq	ymm26, ymm3, 51
        vpandq	ymm3, ymm3, ymm28
        vpsrlq	ymm27, ymm4, 51
        vpandq	ymm4, ymm4, ymm28
        vmovdqa64	ymm18, ymm0
        vpmadd52luq	ymm18, ymm27, ymm31
        vpaddq	ymm19, ymm1, ymm23
        vpaddq	ymm20, ymm2, ymm24
        vpaddq	ymm21, ymm3, ymm25
        vpaddq	ymm22, ymm4, ymm26
        ; X3 = B - A, Y3 = B + A, Z3 = D + C, T3 = D - C
        vpermq	ymm23, ymm18, 240
        vpermq	ymm24, ymm19, 240
        vpermq	ymm25, ymm20, 240
        vpermq	ymm26, ymm21, 240
        vpermq	ymm27, ymm22, 240
        vpaddq	ymm23{k2}, ymm23, ymm23
        vpaddq	ymm24{k2}, ymm24, ymm24
        vpaddq	ymm25{k2}, ymm25, ymm25
        vpaddq	ymm26{k2}, ymm26, ymm26
        vpaddq	ymm27{k2}, ymm27, ymm27
        vpermq	ymm0, ymm18, 165
        vpermq	ymm1, ymm19, 165
        vpermq	ymm2, ymm20, 165
        vpermq	ymm3, ymm21, 165
        vpermq	ymm4, ymm22, 165
        vpaddq	ymm18, ymm23, ymm0
        vpaddq	ymm19, ymm24, ymm1
        vpaddq	ymm20, ymm25, ymm2
        vpaddq	ymm21, ymm26, ymm3
        vpaddq	ymm22, ymm27, ymm4
        vpaddq	ymm23{k3}, ymm23, ymm29
        vpaddq	ymm24{k3}, ymm24, ymm30
        vpaddq	ymm25{k3}, ymm25, ymm30
        vpaddq	ymm26{k3}, ymm26, ymm30
        vpaddq	ymm27{k3}, ymm27, ymm30
        vpsubq	ymm18{k3}, ymm23, ymm0
        vpsubq	ymm19{k3}, ymm24, ymm1
        vpsubq	ymm20{k3}, ymm25, ymm2
        vpsubq	ymm21{k3}, ymm26, ymm3
        vpsubq	ymm22{k3}, ymm27, ymm4
        vpsrlq	ymm5, ymm18, 51
        vpandq	ymm18, ymm18, ymm28
        vpsrlq	ymm6, ymm19, 51
        vpandq	ymm19, ymm19, ymm28
        vpsrlq	ymm7, ymm20, 51
        vpandq	ymm20, ymm20, ymm28
        vpsrlq	ymm8, ymm21, 51
        vpandq	ymm21, ymm21, ymm28
        vpsrlq	ymm9, ymm22, 51
        vpandq	ymm22, ymm22, ymm28
        vpmadd52luq	ymm18, ymm9, ymm31
        vpaddq	ymm19, ymm19, ymm5
        vpaddq	ymm20, ymm20, ymm6
        vpaddq	ymm21, ymm21, ymm7
        vpaddq	ymm22, ymm22, ymm8
        test	r15, r15
        je	L_ge_dsm_dq_avx512_ifma_nores_b
        vpermq	ymm18, ymm18, 180
        vpermq	ymm19, ymm19, 180
        vpermq	ymm20, ymm20, 180
        vpermq	ymm21, ymm21, 180
        vpermq	ymm22, ymm22, 180
L_ge_dsm_dq_avx512_ifma_nores_b:
        vmovdqa64	ymm23, ymm18
        vmovdqa64	ymm24, ymm19
        vmovdqa64	ymm25, ymm20
        vmovdqa64	ymm26, ymm21
        vmovdqa64	ymm27, ymm22
L_ge_dsm_dq_avx512_ifma_skip_b:
        ; To p3
        vpermq	ymm18, ymm23, 36
        vpermq	ymm19, ymm24, 36
        vpermq	ymm20, ymm25, 36
        vpermq	ymm21, ymm26, 36
        vpermq	ymm22, ymm27, 36
        vpermq	ymm23, ymm23, 123
        vpermq	ymm24, ymm24, 123
        vpermq	ymm25, ymm25, 123
        vpermq	ymm26, ymm26, 123
        vpermq	ymm27, ymm27, 123
        ; Multiply 4 field elements
        vpxorq	ymm0, ymm0, ymm0
        vpxorq	ymm9, ymm9, ymm9
        vpxorq	ymm1, ymm1, ymm1
        vpxorq	ymm10, ymm10, ymm10
        vpxorq	ymm2, ymm2, ymm2
        vpxorq	ymm11, ymm11, ymm11
        vpxorq	ymm3, ymm3, ymm3
        vpxorq	ymm12, ymm12, ymm12
        vpxorq	ymm4, ymm4, ymm4
        vpxorq	ymm13, ymm13, ymm13
        vpxorq	ymm5, ymm5, ymm5
        vpxorq	ymm14, ymm14, ymm14
        vpxorq	ymm6, ymm6, ymm6
        vpxorq	ymm15, ymm15, ymm15
        vpxorq	ymm7, ymm7, ymm7
        vpxorq	ymm16, ymm16, ymm16
        vpxorq	ymm8, ymm8, ymm8
        vpxorq	ymm17, ymm17, ymm17
        vpmadd52luq	ymm0, ymm18, ymm23
        vpmadd52huq	ymm9, ymm18, ymm23
        vpmadd52luq	ymm1, ymm18, ymm24
        vpmadd52huq	ymm10, ymm18, ymm24
        vpmadd52luq	ymm2, ymm18, ymm25
        vpmadd52huq	ymm11, ymm18, ymm25
        vpmadd52luq	ymm3, ymm18, ymm26
        vpmadd52huq	ymm12, ymm18, ymm26
        vpmadd52luq	ymm4, ymm18, ymm27
        vpmadd52huq	ymm13, ymm18, ymm27
        vpmadd52luq	ymm1, ymm19, ymm23
        vpmadd52huq	ymm10, ymm19, ymm23
        vpmadd52luq	ymm2, ymm19, ymm24
        vpmadd52huq	ymm11, ymm19, ymm24
        vpmadd52luq	ymm3, ymm19, ymm25
        vpmadd52huq	ymm12, ymm19, ymm25
        vpmadd52luq	ymm4, ymm19, ymm26
        vpmadd52huq	ymm13, ymm19, ymm26
        vpmadd52luq	ymm5, ymm19, ymm27
        vpmadd52huq	ymm14, ymm19, ymm27
        vpmadd52luq	ymm2, ymm20, ymm23
        vpmadd52huq	ymm11, ymm20, ymm23
        vpmadd52luq	ymm3, ymm20, ymm24
        vpmadd52huq	ymm12, ymm20, ymm24
        vpmadd52luq	ymm4, ymm20, ymm25
        vpmadd52huq	ymm13, ymm20, ymm25
        vpmadd52luq	ymm5, ymm20, ymm26
        vpmadd52huq	ymm14, ymm20, ymm26
        vpmadd52luq	ymm6, ymm20, ymm27
        vpmadd52huq	ymm15, ymm20, ymm27
        vpmadd52luq	ymm3, ymm21, ymm23
        vpmadd52huq	ymm12, ymm21, ymm23
        vpmadd52luq	ymm4, ymm21, ymm24
        vpmadd52huq	ymm13, ymm21, ymm24
        vpmadd52luq	ymm5, ymm21, ymm25
        vpmadd52huq	ymm14, ymm21, ymm25
        vpmadd52luq	ymm6, ymm21, ymm26
        vpmadd52huq	ymm15, ymm21, ymm26
        vpmadd52luq	ymm7, ymm21, ymm27
        vpmadd52huq	ymm16, ymm21, ymm27
        vpmadd52luq	ymm4, ymm22, ymm23
        vpmadd52huq	ymm13, ymm22, ymm23
        vpmadd52luq	ymm5, ymm22, ymm24
        vpmadd52huq	ymm14, ymm22, ymm24
        vpmadd52luq	ymm6, ymm22, ymm25
        vpmadd52huq	ymm15, ymm22, ymm25
        vpmadd52luq	ymm7, ymm22, ymm26
        vpmadd52huq	ymm16, ymm22, ymm26
        vpmadd52luq	ymm8, ymm22, ymm27
        vpmadd52huq	ymm17, ymm22, ymm27
        vpaddq	ymm9, ymm9, ymm9
        vpaddq	ymm1, ymm1, ymm9
        vpaddq	ymm10, ymm10, ymm10
        vpaddq	ymm2, ymm2, ymm10
        vpaddq	ymm11, ymm11, ymm11
        vpaddq	ymm3, ymm3, ymm11
        vpaddq	ymm12, ymm12, ymm12
        vpaddq	ymm4, ymm4, ymm12
        vpaddq	ymm13, ymm13, ymm13
        vpaddq	ymm5, ymm5, ymm13
        vpaddq	ymm14, ymm14, ymm14
        vpaddq	ymm6, ymm6, ymm14
        vpaddq	ymm15, ymm15, ymm15
        vpaddq	ymm7, ymm7, ymm15
        vpaddq	ymm16, ymm16, ymm16
        vpaddq	ymm8, ymm8, ymm16
        vpaddq	ymm17, ymm17, ymm17
        ; Reduce
        vpmullq	ymm9, ymm5, ymm31
        vpaddq	ymm0, ymm0, ymm9
        vpmullq	ymm9, ymm6, ymm31
        vpaddq	ymm1, ymm1, ymm9
        vpmullq	ymm9, ymm7, ymm31
        vpaddq	ymm2, ymm2, ymm9
        vpmullq	ymm9, ymm8, ymm31
        vpaddq	ymm3, ymm3, ymm9
        vpmullq	ymm9, ymm17, ymm31
        vpaddq	ymm4, ymm4, ymm9
        vpsrlq	ymm23, ymm0, 51
        vpandq	ymm0, ymm0, ymm28
        vpsrlq	ymm24, ymm1, 51
        vpandq	ymm1, ymm1, ymm28
        vpsrlq	ymm25, ymm2, 51
        vpandq	ymm2, ymm2, ymm28
        vpsrlq	ymm26, ymm3, 51
        vpandq	ymm3, ymm3, ymm28
        vpsrlq	ymm27, ymm4, 51
        vpandq	ymm4, ymm4, ymm28
        vmovdqa64	ymm18, ymm0
        vpmadd52luq	ymm18, ymm27, ymm31
        vpaddq	ymm19, ymm1, ymm23
        vpaddq	ymm20, ymm2, ymm24
        vpaddq	ymm21, ymm3, ymm25
        vpaddq	ymm22, ymm4, ymm26
        dec	r11
        jge	L_ge_dsm_dq_avx512_ifma_bits
        vmovdqu64	YMMWORD PTR [rbp+1600], ymm18
        vmovdqu64	YMMWORD PTR [rbp+1632], ymm19
        vmovdqu64	YMMWORD PTR [rbp+1664], ymm20
        vmovdqu64	YMMWORD PTR [rbp+1696], ymm21
        vmovdqu64	YMMWORD PTR [rbp+1728], ymm22
        vzeroupper
        ; Convert X, Y and Z back to 4 x 64-bit field elements
        mov	r10, 2251799813685247
        mov	rdx, QWORD PTR [rbp+1600]
        mov	rax, QWORD PTR [rbp+1632]
        mov	rcx, QWORD PTR [rbp+1664]
        mov	r8, QWORD PTR [rbp+1696]
        mov	r9, QWORD PTR [rbp+1728]
        mov	r11, rdx
        shr	r11, 51
        and	rdx, r10
        add	rax, r11
        mov	r11, rax
        shr	r11, 51
        and	rax, r10
        add	rcx, r11
        mov	r11, rcx
        shr	r11, 51
        and	rcx, r10
        add	r8, r11
        mov	r11, r8
        shr	r11, 51
        and	r8, r10
        add	r9, r11
        mov	r11, r9
        shr	r11, 51
        and	r9, r10
        imul	r11, r11, 19
        add	rdx, r11
        mov	r11, rax
        shl	r11, 51
        mov	r12, rax
        shr	r12, 13
        add	rdx, r11
        adc	r12, 0
        mov	QWORD PTR [r14], rdx
        mov	r11, rcx
        shl	r11, 38
        mov	rdx, rcx
        shr	rdx, 26
        add	r12, r11
        adc	rdx, 0
        mov	QWORD PTR [r14+8], r12
        mov	r11, r8
        shl	r11, 25
        mov	r12, r8
        shr	r12, 39
        add	rdx, r11
        adc	r12, 0
        mov	QWORD PTR [r14+16], rdx
        mov	r11, r9
        shl	r11, 12
        add	r12, r11
        mov	QWORD PTR [r14+24], r12
        mov	rdx, QWORD PTR [rbp+1608]
        mov	rax, QWORD PTR [rbp+1640]
        mov	rcx, QWORD PTR [rbp+1672]
        mov	r8, QWORD PTR [rbp+1704]
        mov	r9, QWORD PTR [rbp+1736]
        mov	r11, rdx
        shr	r11, 51
        and	rdx, r10
        add	rax, r11
        mov	r11, rax
        shr	r11, 51
        and	rax, r10
        add	rcx, r11
        mov	r11, rcx
        shr	r11, 51
        and	rcx, r10
        add	r8, r11
        mov	r11, r8
        shr	r11, 51
        and	r8, r10
        add	r9, r11
        mov	r11, r9
        shr	r11, 51
        and	r9, r10
        imul	r11, r11, 19
        add	rdx, r11
        mov	r11, rax
        shl	r11, 51
        mov	r12, rax
        shr	r12, 13
        add	rdx, r11
        adc	r12, 0
        mov	QWORD PTR [r14+32], rdx
        mov	r11, rcx
        shl	r11, 38
        mov	rdx, rcx
        shr	rdx, 26
        add	r12, r11
        adc	rdx, 0
        mov	QWORD PTR [r14+40], r12
        mov	r11, r8
        shl	r11, 25
        mov	r12, r8
        shr	r12, 39
        add	rdx, r11
        adc	r12, 0
        mov	QWORD PTR [r14+48], rdx
        mov	r11, r9
        shl	r11, 12
        add	r12, r11
        mov	QWORD PTR [r14+56], r12
        mov	rdx, QWORD PTR [rbp+1616]
        mov	rax, QWORD PTR [rbp+1648]
        mov	rcx, QWORD PTR [rbp+1680]
        mov	r8, QWORD PTR [rbp+1712]
        mov	r9, QWORD PTR [rbp+1744]
        mov	r11, rdx
        shr	r11, 51
        and	rdx, r10
        add	rax, r11
        mov	r11, rax
        shr	r11, 51
        and	rax, r10
        add	rcx, r11
        mov	r11, rcx
        shr	r11, 51
        and	rcx, r10
        add	r8, r11
        mov	r11, r8
        shr	r11, 51
        and	r8, r10
        add	r9, r11
        mov	r11, r9
        shr	r11, 51
        and	r9, r10
        imul	r11, r11, 19
        add	rdx, r11
        mov	r11, rax
        shl	r11, 51
        mov	r12, rax
        shr	r12, 13
        add	rdx, r11
        adc	r12, 0
        mov	QWORD PTR [r14+64], rdx
        mov	r11, rcx
        shl	r11, 38
        mov	rdx, rcx
        shr	rdx, 26
        add	r12, r11
        adc	rdx, 0
        mov	QWORD PTR [r14+72], r12
        mov	r11, r8
        shl	r11, 25
        mov	r12, r8
        shr	r12, 39
        add	rdx, r11
        adc	r12, 0
        mov	QWORD PTR [r14+80], rdx
        mov	r11, r9
        shl	r11, 12
        add	r12, r11
        mov	QWORD PTR [r14+88], r12
        xor	rax, rax
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
        pop	rbp
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        ret
ge_double_scalarmult_vartime_avx512_ifma_dq ENDP
_TEXT ENDS
ENDIF
ENDIF
ENDIF
END
