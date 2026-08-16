; /* aes_xts_x86_asm
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

IFDEF WOLFSSL_AES_XTS
IFDEF WOLFSSL_X86_BUILD
        ; 32-bit (i386) AES-NI AES-XTS: single-block ports of the x86_64
        ; AES_XTS_*_aesni routines (xmm0-7, cdecl ABI); GF const on stack for PIC.
        ; void AES_XTS_init_aesni(unsigned char* i, const unsigned char* tweak_key,
        ;                         int tweak_nr);
_TEXT SEGMENT READONLY PARA
AES_XTS_init_aesni PROC
        mov	eax, DWORD PTR [esp+4]
        movdqu	xmm2, OWORD PTR [eax]
        mov	ecx, DWORD PTR [esp+8]
        pxor	xmm2, [ecx]
        movdqu	xmm0, OWORD PTR [ecx+16]
        aesenc	xmm2, xmm0
        movdqu	xmm0, OWORD PTR [ecx+32]
        aesenc	xmm2, xmm0
        movdqu	xmm0, OWORD PTR [ecx+48]
        aesenc	xmm2, xmm0
        movdqu	xmm0, OWORD PTR [ecx+64]
        aesenc	xmm2, xmm0
        movdqu	xmm0, OWORD PTR [ecx+80]
        aesenc	xmm2, xmm0
        movdqu	xmm0, OWORD PTR [ecx+96]
        aesenc	xmm2, xmm0
        movdqu	xmm0, OWORD PTR [ecx+112]
        aesenc	xmm2, xmm0
        movdqu	xmm0, OWORD PTR [ecx+128]
        aesenc	xmm2, xmm0
        movdqu	xmm0, OWORD PTR [ecx+144]
        aesenc	xmm2, xmm0
        cmp	DWORD PTR [esp+12], 11
        movdqu	xmm0, OWORD PTR [ecx+160]
        jl	L_AES_XTS_init_aesni_enclast_1
        aesenc	xmm2, xmm0
        movdqu	xmm1, OWORD PTR [ecx+176]
        aesenc	xmm2, xmm1
        cmp	DWORD PTR [esp+12], 13
        movdqu	xmm0, OWORD PTR [ecx+192]
        jl	L_AES_XTS_init_aesni_enclast_1
        aesenc	xmm2, xmm0
        movdqu	xmm1, OWORD PTR [ecx+208]
        aesenc	xmm2, xmm1
        movdqu	xmm0, OWORD PTR [ecx+224]
L_AES_XTS_init_aesni_enclast_1:
        aesenclast	xmm2, xmm0
        movdqu	OWORD PTR [eax], xmm2
        ret
AES_XTS_init_aesni ENDP
_TEXT ENDS
        ; void AES_XTS_encrypt_aesni(const unsigned char* in, unsigned char* out,
        ;     word32 sz, const unsigned char* i, const unsigned char* key,
        ;     const unsigned char* key2, int nr);
_TEXT SEGMENT READONLY PARA
AES_XTS_encrypt_aesni PROC
        push	edi
        push	ebx
        sub	esp, 16
        mov	DWORD PTR [esp], 135
        mov	DWORD PTR [esp+4], 1
        mov	DWORD PTR [esp+8], 1
        mov	DWORD PTR [esp+12], 1
        movdqu	xmm6, OWORD PTR [esp]
        mov	eax, DWORD PTR [esp+40]
        movdqu	xmm2, OWORD PTR [eax]
        mov	ecx, DWORD PTR [esp+48]
        pxor	xmm2, [ecx]
        movdqu	xmm0, OWORD PTR [ecx+16]
        aesenc	xmm2, xmm0
        movdqu	xmm0, OWORD PTR [ecx+32]
        aesenc	xmm2, xmm0
        movdqu	xmm0, OWORD PTR [ecx+48]
        aesenc	xmm2, xmm0
        movdqu	xmm0, OWORD PTR [ecx+64]
        aesenc	xmm2, xmm0
        movdqu	xmm0, OWORD PTR [ecx+80]
        aesenc	xmm2, xmm0
        movdqu	xmm0, OWORD PTR [ecx+96]
        aesenc	xmm2, xmm0
        movdqu	xmm0, OWORD PTR [ecx+112]
        aesenc	xmm2, xmm0
        movdqu	xmm0, OWORD PTR [ecx+128]
        aesenc	xmm2, xmm0
        movdqu	xmm0, OWORD PTR [ecx+144]
        aesenc	xmm2, xmm0
        cmp	DWORD PTR [esp+52], 11
        movdqu	xmm0, OWORD PTR [ecx+160]
        jl	L_AES_XTS_encrypt_aesni_enclast_2
        aesenc	xmm2, xmm0
        movdqu	xmm1, OWORD PTR [ecx+176]
        aesenc	xmm2, xmm1
        cmp	DWORD PTR [esp+52], 13
        movdqu	xmm0, OWORD PTR [ecx+192]
        jl	L_AES_XTS_encrypt_aesni_enclast_2
        aesenc	xmm2, xmm0
        movdqu	xmm1, OWORD PTR [ecx+208]
        aesenc	xmm2, xmm1
        movdqu	xmm0, OWORD PTR [ecx+224]
L_AES_XTS_encrypt_aesni_enclast_2:
        aesenclast	xmm2, xmm0
        xor	edi, edi
        mov	edx, DWORD PTR [esp+36]
        and	edx, 4294967280
L_AES_XTS_encrypt_aesni_loop:
        cmp	edi, edx
        jae	L_AES_XTS_encrypt_aesni_loop_done
        mov	eax, DWORD PTR [esp+28]
        movdqu	xmm3, OWORD PTR [eax+edi]
        pxor	xmm3, xmm2
        mov	ecx, DWORD PTR [esp+44]
        pxor	xmm3, [ecx]
        movdqu	xmm0, OWORD PTR [ecx+16]
        aesenc	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+32]
        aesenc	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+48]
        aesenc	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+64]
        aesenc	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+80]
        aesenc	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+96]
        aesenc	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+112]
        aesenc	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+128]
        aesenc	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+144]
        aesenc	xmm3, xmm0
        cmp	DWORD PTR [esp+52], 11
        movdqu	xmm0, OWORD PTR [ecx+160]
        jl	L_AES_XTS_encrypt_aesni_enclast_3
        aesenc	xmm3, xmm0
        movdqu	xmm1, OWORD PTR [ecx+176]
        aesenc	xmm3, xmm1
        cmp	DWORD PTR [esp+52], 13
        movdqu	xmm0, OWORD PTR [ecx+192]
        jl	L_AES_XTS_encrypt_aesni_enclast_3
        aesenc	xmm3, xmm0
        movdqu	xmm1, OWORD PTR [ecx+208]
        aesenc	xmm3, xmm1
        movdqu	xmm0, OWORD PTR [ecx+224]
L_AES_XTS_encrypt_aesni_enclast_3:
        aesenclast	xmm3, xmm0
        pxor	xmm3, xmm2
        mov	eax, DWORD PTR [esp+32]
        movdqu	OWORD PTR [eax+edi], xmm3
        movdqa	xmm4, xmm2
        psrad	xmm4, 31
        pslld	xmm2, 1
        pshufd	xmm4, xmm4, 147
        pand	xmm4, xmm6
        pxor	xmm2, xmm4
        add	edi, 16
        jmp	L_AES_XTS_encrypt_aesni_loop
L_AES_XTS_encrypt_aesni_loop_done:
        mov	eax, DWORD PTR [esp+36]
        cmp	edi, eax
        je	L_AES_XTS_encrypt_aesni_done
        sub	edi, 16
        mov	eax, DWORD PTR [esp+32]
        movdqu	xmm5, OWORD PTR [eax+edi]
        add	edi, 16
        movdqu	OWORD PTR [esp], xmm5
        xor	edx, edx
L_AES_XTS_encrypt_aesni_cts:
        movzx	ecx, BYTE PTR [esp+edx]
        mov	eax, DWORD PTR [esp+28]
        movzx	ebx, BYTE PTR [eax+edi]
        mov	eax, DWORD PTR [esp+32]
        mov	BYTE PTR [eax+edi], cl
        mov	BYTE PTR [esp+edx], bl
        inc	edi
        inc	edx
        mov	eax, DWORD PTR [esp+36]
        cmp	edi, eax
        jb	L_AES_XTS_encrypt_aesni_cts
        sub	edi, edx
        movdqu	xmm3, OWORD PTR [esp]
        sub	edi, 16
        pxor	xmm3, xmm2
        mov	ecx, DWORD PTR [esp+44]
        pxor	xmm3, [ecx]
        movdqu	xmm0, OWORD PTR [ecx+16]
        aesenc	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+32]
        aesenc	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+48]
        aesenc	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+64]
        aesenc	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+80]
        aesenc	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+96]
        aesenc	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+112]
        aesenc	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+128]
        aesenc	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+144]
        aesenc	xmm3, xmm0
        cmp	DWORD PTR [esp+52], 11
        movdqu	xmm0, OWORD PTR [ecx+160]
        jl	L_AES_XTS_encrypt_aesni_enclast_4
        aesenc	xmm3, xmm0
        movdqu	xmm1, OWORD PTR [ecx+176]
        aesenc	xmm3, xmm1
        cmp	DWORD PTR [esp+52], 13
        movdqu	xmm0, OWORD PTR [ecx+192]
        jl	L_AES_XTS_encrypt_aesni_enclast_4
        aesenc	xmm3, xmm0
        movdqu	xmm1, OWORD PTR [ecx+208]
        aesenc	xmm3, xmm1
        movdqu	xmm0, OWORD PTR [ecx+224]
L_AES_XTS_encrypt_aesni_enclast_4:
        aesenclast	xmm3, xmm0
        pxor	xmm3, xmm2
        mov	eax, DWORD PTR [esp+32]
        movdqu	OWORD PTR [eax+edi], xmm3
L_AES_XTS_encrypt_aesni_done:
        add	esp, 16
        pop	ebx
        pop	edi
        ret
AES_XTS_encrypt_aesni ENDP
_TEXT ENDS
        ; void AES_XTS_encrypt_update_aesni(const unsigned char* in,
        ;     unsigned char* out, word32 sz, const unsigned char* key,
        ;     unsigned char* i, int nr);  Tweak is read (already encrypted) from *i
        ;     and the advanced tweak written back to *i.
_TEXT SEGMENT READONLY PARA
AES_XTS_encrypt_update_aesni PROC
        push	edi
        push	ebx
        sub	esp, 16
        mov	DWORD PTR [esp], 135
        mov	DWORD PTR [esp+4], 1
        mov	DWORD PTR [esp+8], 1
        mov	DWORD PTR [esp+12], 1
        movdqu	xmm6, OWORD PTR [esp]
        mov	eax, DWORD PTR [esp+44]
        movdqu	xmm2, OWORD PTR [eax]
        xor	edi, edi
        mov	edx, DWORD PTR [esp+36]
        and	edx, 4294967280
L_AES_XTS_encrypt_update_aesni_loop:
        cmp	edi, edx
        jae	L_AES_XTS_encrypt_update_aesni_loop_done
        mov	eax, DWORD PTR [esp+28]
        movdqu	xmm3, OWORD PTR [eax+edi]
        pxor	xmm3, xmm2
        mov	ecx, DWORD PTR [esp+40]
        pxor	xmm3, [ecx]
        movdqu	xmm0, OWORD PTR [ecx+16]
        aesenc	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+32]
        aesenc	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+48]
        aesenc	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+64]
        aesenc	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+80]
        aesenc	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+96]
        aesenc	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+112]
        aesenc	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+128]
        aesenc	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+144]
        aesenc	xmm3, xmm0
        cmp	DWORD PTR [esp+48], 11
        movdqu	xmm0, OWORD PTR [ecx+160]
        jl	L_AES_XTS_encrypt_update_aesni_enclast_5
        aesenc	xmm3, xmm0
        movdqu	xmm1, OWORD PTR [ecx+176]
        aesenc	xmm3, xmm1
        cmp	DWORD PTR [esp+48], 13
        movdqu	xmm0, OWORD PTR [ecx+192]
        jl	L_AES_XTS_encrypt_update_aesni_enclast_5
        aesenc	xmm3, xmm0
        movdqu	xmm1, OWORD PTR [ecx+208]
        aesenc	xmm3, xmm1
        movdqu	xmm0, OWORD PTR [ecx+224]
L_AES_XTS_encrypt_update_aesni_enclast_5:
        aesenclast	xmm3, xmm0
        pxor	xmm3, xmm2
        mov	eax, DWORD PTR [esp+32]
        movdqu	OWORD PTR [eax+edi], xmm3
        movdqa	xmm4, xmm2
        psrad	xmm4, 31
        pslld	xmm2, 1
        pshufd	xmm4, xmm4, 147
        pand	xmm4, xmm6
        pxor	xmm2, xmm4
        add	edi, 16
        jmp	L_AES_XTS_encrypt_update_aesni_loop
L_AES_XTS_encrypt_update_aesni_loop_done:
        mov	eax, DWORD PTR [esp+36]
        cmp	edi, eax
        je	L_AES_XTS_encrypt_update_aesni_done
        sub	edi, 16
        mov	eax, DWORD PTR [esp+32]
        movdqu	xmm5, OWORD PTR [eax+edi]
        add	edi, 16
        movdqu	OWORD PTR [esp], xmm5
        xor	edx, edx
L_AES_XTS_encrypt_update_aesni_cts:
        movzx	ecx, BYTE PTR [esp+edx]
        mov	eax, DWORD PTR [esp+28]
        movzx	ebx, BYTE PTR [eax+edi]
        mov	eax, DWORD PTR [esp+32]
        mov	BYTE PTR [eax+edi], cl
        mov	BYTE PTR [esp+edx], bl
        inc	edi
        inc	edx
        mov	eax, DWORD PTR [esp+36]
        cmp	edi, eax
        jb	L_AES_XTS_encrypt_update_aesni_cts
        sub	edi, edx
        movdqu	xmm3, OWORD PTR [esp]
        sub	edi, 16
        pxor	xmm3, xmm2
        mov	ecx, DWORD PTR [esp+40]
        pxor	xmm3, [ecx]
        movdqu	xmm0, OWORD PTR [ecx+16]
        aesenc	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+32]
        aesenc	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+48]
        aesenc	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+64]
        aesenc	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+80]
        aesenc	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+96]
        aesenc	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+112]
        aesenc	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+128]
        aesenc	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+144]
        aesenc	xmm3, xmm0
        cmp	DWORD PTR [esp+48], 11
        movdqu	xmm0, OWORD PTR [ecx+160]
        jl	L_AES_XTS_encrypt_update_aesni_enclast_6
        aesenc	xmm3, xmm0
        movdqu	xmm1, OWORD PTR [ecx+176]
        aesenc	xmm3, xmm1
        cmp	DWORD PTR [esp+48], 13
        movdqu	xmm0, OWORD PTR [ecx+192]
        jl	L_AES_XTS_encrypt_update_aesni_enclast_6
        aesenc	xmm3, xmm0
        movdqu	xmm1, OWORD PTR [ecx+208]
        aesenc	xmm3, xmm1
        movdqu	xmm0, OWORD PTR [ecx+224]
L_AES_XTS_encrypt_update_aesni_enclast_6:
        aesenclast	xmm3, xmm0
        pxor	xmm3, xmm2
        mov	eax, DWORD PTR [esp+32]
        movdqu	OWORD PTR [eax+edi], xmm3
L_AES_XTS_encrypt_update_aesni_done:
        mov	eax, DWORD PTR [esp+44]
        movdqu	OWORD PTR [eax], xmm2
        add	esp, 16
        pop	ebx
        pop	edi
        ret
AES_XTS_encrypt_update_aesni ENDP
_TEXT ENDS
        ; void AES_XTS_decrypt_aesni(const unsigned char* in, unsigned char* out,
        ;     word32 sz, const unsigned char* i, const unsigned char* key,
        ;     const unsigned char* key2, int nr);
_TEXT SEGMENT READONLY PARA
AES_XTS_decrypt_aesni PROC
        push	edi
        push	ebx
        sub	esp, 16
        mov	DWORD PTR [esp], 135
        mov	DWORD PTR [esp+4], 1
        mov	DWORD PTR [esp+8], 1
        mov	DWORD PTR [esp+12], 1
        movdqu	xmm6, OWORD PTR [esp]
        mov	eax, DWORD PTR [esp+40]
        movdqu	xmm2, OWORD PTR [eax]
        mov	ecx, DWORD PTR [esp+48]
        pxor	xmm2, [ecx]
        movdqu	xmm0, OWORD PTR [ecx+16]
        aesenc	xmm2, xmm0
        movdqu	xmm0, OWORD PTR [ecx+32]
        aesenc	xmm2, xmm0
        movdqu	xmm0, OWORD PTR [ecx+48]
        aesenc	xmm2, xmm0
        movdqu	xmm0, OWORD PTR [ecx+64]
        aesenc	xmm2, xmm0
        movdqu	xmm0, OWORD PTR [ecx+80]
        aesenc	xmm2, xmm0
        movdqu	xmm0, OWORD PTR [ecx+96]
        aesenc	xmm2, xmm0
        movdqu	xmm0, OWORD PTR [ecx+112]
        aesenc	xmm2, xmm0
        movdqu	xmm0, OWORD PTR [ecx+128]
        aesenc	xmm2, xmm0
        movdqu	xmm0, OWORD PTR [ecx+144]
        aesenc	xmm2, xmm0
        cmp	DWORD PTR [esp+52], 11
        movdqu	xmm0, OWORD PTR [ecx+160]
        jl	L_AES_XTS_decrypt_aesni_enclast_7
        aesenc	xmm2, xmm0
        movdqu	xmm1, OWORD PTR [ecx+176]
        aesenc	xmm2, xmm1
        cmp	DWORD PTR [esp+52], 13
        movdqu	xmm0, OWORD PTR [ecx+192]
        jl	L_AES_XTS_decrypt_aesni_enclast_7
        aesenc	xmm2, xmm0
        movdqu	xmm1, OWORD PTR [ecx+208]
        aesenc	xmm2, xmm1
        movdqu	xmm0, OWORD PTR [ecx+224]
L_AES_XTS_decrypt_aesni_enclast_7:
        aesenclast	xmm2, xmm0
        xor	edi, edi
        mov	eax, DWORD PTR [esp+36]
        mov	edx, eax
        and	edx, 4294967280
        cmp	edx, eax
        je	L_AES_XTS_decrypt_aesni_bound
        sub	edx, 16
L_AES_XTS_decrypt_aesni_bound:
L_AES_XTS_decrypt_aesni_loop:
        cmp	edi, edx
        jae	L_AES_XTS_decrypt_aesni_loop_done
        mov	eax, DWORD PTR [esp+28]
        movdqu	xmm3, OWORD PTR [eax+edi]
        pxor	xmm3, xmm2
        mov	ecx, DWORD PTR [esp+44]
        pxor	xmm3, [ecx]
        movdqu	xmm0, OWORD PTR [ecx+16]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+32]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+48]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+64]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+80]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+96]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+112]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+128]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+144]
        aesdec	xmm3, xmm0
        cmp	DWORD PTR [esp+52], 11
        movdqu	xmm0, OWORD PTR [ecx+160]
        jl	L_AES_XTS_decrypt_aesni_declast_8
        aesdec	xmm3, xmm0
        movdqu	xmm1, OWORD PTR [ecx+176]
        aesdec	xmm3, xmm1
        cmp	DWORD PTR [esp+52], 13
        movdqu	xmm0, OWORD PTR [ecx+192]
        jl	L_AES_XTS_decrypt_aesni_declast_8
        aesdec	xmm3, xmm0
        movdqu	xmm1, OWORD PTR [ecx+208]
        aesdec	xmm3, xmm1
        movdqu	xmm0, OWORD PTR [ecx+224]
L_AES_XTS_decrypt_aesni_declast_8:
        aesdeclast	xmm3, xmm0
        pxor	xmm3, xmm2
        mov	eax, DWORD PTR [esp+32]
        movdqu	OWORD PTR [eax+edi], xmm3
        movdqa	xmm4, xmm2
        psrad	xmm4, 31
        pslld	xmm2, 1
        pshufd	xmm4, xmm4, 147
        pand	xmm4, xmm6
        pxor	xmm2, xmm4
        add	edi, 16
        jmp	L_AES_XTS_decrypt_aesni_loop
L_AES_XTS_decrypt_aesni_loop_done:
        mov	eax, DWORD PTR [esp+36]
        cmp	edi, eax
        je	L_AES_XTS_decrypt_aesni_done
        movdqa	xmm4, xmm2
        movdqa	xmm5, xmm2
        psrad	xmm4, 31
        pslld	xmm5, 1
        pshufd	xmm4, xmm4, 147
        pand	xmm4, xmm6
        pxor	xmm5, xmm4
        mov	eax, DWORD PTR [esp+28]
        movdqu	xmm3, OWORD PTR [eax+edi]
        pxor	xmm3, xmm5
        mov	ecx, DWORD PTR [esp+44]
        pxor	xmm3, [ecx]
        movdqu	xmm0, OWORD PTR [ecx+16]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+32]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+48]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+64]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+80]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+96]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+112]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+128]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+144]
        aesdec	xmm3, xmm0
        cmp	DWORD PTR [esp+52], 11
        movdqu	xmm0, OWORD PTR [ecx+160]
        jl	L_AES_XTS_decrypt_aesni_declast_9
        aesdec	xmm3, xmm0
        movdqu	xmm1, OWORD PTR [ecx+176]
        aesdec	xmm3, xmm1
        cmp	DWORD PTR [esp+52], 13
        movdqu	xmm0, OWORD PTR [ecx+192]
        jl	L_AES_XTS_decrypt_aesni_declast_9
        aesdec	xmm3, xmm0
        movdqu	xmm1, OWORD PTR [ecx+208]
        aesdec	xmm3, xmm1
        movdqu	xmm0, OWORD PTR [ecx+224]
L_AES_XTS_decrypt_aesni_declast_9:
        aesdeclast	xmm3, xmm0
        pxor	xmm3, xmm5
        movdqu	OWORD PTR [esp], xmm3
        add	edi, 16
        xor	edx, edx
L_AES_XTS_decrypt_aesni_cts:
        movzx	ecx, BYTE PTR [esp+edx]
        mov	eax, DWORD PTR [esp+28]
        movzx	ebx, BYTE PTR [eax+edi]
        mov	eax, DWORD PTR [esp+32]
        mov	BYTE PTR [eax+edi], cl
        mov	BYTE PTR [esp+edx], bl
        inc	edi
        inc	edx
        mov	eax, DWORD PTR [esp+36]
        cmp	edi, eax
        jb	L_AES_XTS_decrypt_aesni_cts
        sub	edi, edx
        movdqu	xmm3, OWORD PTR [esp]
        pxor	xmm3, xmm2
        mov	ecx, DWORD PTR [esp+44]
        pxor	xmm3, [ecx]
        movdqu	xmm0, OWORD PTR [ecx+16]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+32]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+48]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+64]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+80]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+96]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+112]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+128]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+144]
        aesdec	xmm3, xmm0
        cmp	DWORD PTR [esp+52], 11
        movdqu	xmm0, OWORD PTR [ecx+160]
        jl	L_AES_XTS_decrypt_aesni_declast_10
        aesdec	xmm3, xmm0
        movdqu	xmm1, OWORD PTR [ecx+176]
        aesdec	xmm3, xmm1
        cmp	DWORD PTR [esp+52], 13
        movdqu	xmm0, OWORD PTR [ecx+192]
        jl	L_AES_XTS_decrypt_aesni_declast_10
        aesdec	xmm3, xmm0
        movdqu	xmm1, OWORD PTR [ecx+208]
        aesdec	xmm3, xmm1
        movdqu	xmm0, OWORD PTR [ecx+224]
L_AES_XTS_decrypt_aesni_declast_10:
        aesdeclast	xmm3, xmm0
        pxor	xmm3, xmm2
        sub	edi, 16
        mov	eax, DWORD PTR [esp+32]
        movdqu	OWORD PTR [eax+edi], xmm3
L_AES_XTS_decrypt_aesni_done:
        add	esp, 16
        pop	ebx
        pop	edi
        ret
AES_XTS_decrypt_aesni ENDP
_TEXT ENDS
        ; void AES_XTS_decrypt_update_aesni(const unsigned char* in,
        ;     unsigned char* out, word32 sz, const unsigned char* key,
        ;     unsigned char* i, int nr);  Tweak is read from *i and the advanced
        ;     tweak written back to *i.
_TEXT SEGMENT READONLY PARA
AES_XTS_decrypt_update_aesni PROC
        push	edi
        push	ebx
        sub	esp, 16
        mov	DWORD PTR [esp], 135
        mov	DWORD PTR [esp+4], 1
        mov	DWORD PTR [esp+8], 1
        mov	DWORD PTR [esp+12], 1
        movdqu	xmm6, OWORD PTR [esp]
        mov	eax, DWORD PTR [esp+44]
        movdqu	xmm2, OWORD PTR [eax]
        xor	edi, edi
        mov	eax, DWORD PTR [esp+36]
        mov	edx, eax
        and	edx, 4294967280
        cmp	edx, eax
        je	L_AES_XTS_decrypt_update_aesni_bound
        sub	edx, 16
L_AES_XTS_decrypt_update_aesni_bound:
L_AES_XTS_decrypt_update_aesni_loop:
        cmp	edi, edx
        jae	L_AES_XTS_decrypt_update_aesni_loop_done
        mov	eax, DWORD PTR [esp+28]
        movdqu	xmm3, OWORD PTR [eax+edi]
        pxor	xmm3, xmm2
        mov	ecx, DWORD PTR [esp+40]
        pxor	xmm3, [ecx]
        movdqu	xmm0, OWORD PTR [ecx+16]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+32]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+48]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+64]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+80]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+96]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+112]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+128]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+144]
        aesdec	xmm3, xmm0
        cmp	DWORD PTR [esp+48], 11
        movdqu	xmm0, OWORD PTR [ecx+160]
        jl	L_AES_XTS_decrypt_update_aesni_declast_11
        aesdec	xmm3, xmm0
        movdqu	xmm1, OWORD PTR [ecx+176]
        aesdec	xmm3, xmm1
        cmp	DWORD PTR [esp+48], 13
        movdqu	xmm0, OWORD PTR [ecx+192]
        jl	L_AES_XTS_decrypt_update_aesni_declast_11
        aesdec	xmm3, xmm0
        movdqu	xmm1, OWORD PTR [ecx+208]
        aesdec	xmm3, xmm1
        movdqu	xmm0, OWORD PTR [ecx+224]
L_AES_XTS_decrypt_update_aesni_declast_11:
        aesdeclast	xmm3, xmm0
        pxor	xmm3, xmm2
        mov	eax, DWORD PTR [esp+32]
        movdqu	OWORD PTR [eax+edi], xmm3
        movdqa	xmm4, xmm2
        psrad	xmm4, 31
        pslld	xmm2, 1
        pshufd	xmm4, xmm4, 147
        pand	xmm4, xmm6
        pxor	xmm2, xmm4
        add	edi, 16
        jmp	L_AES_XTS_decrypt_update_aesni_loop
L_AES_XTS_decrypt_update_aesni_loop_done:
        mov	eax, DWORD PTR [esp+36]
        cmp	edi, eax
        je	L_AES_XTS_decrypt_update_aesni_done
        movdqa	xmm4, xmm2
        movdqa	xmm5, xmm2
        psrad	xmm4, 31
        pslld	xmm5, 1
        pshufd	xmm4, xmm4, 147
        pand	xmm4, xmm6
        pxor	xmm5, xmm4
        mov	eax, DWORD PTR [esp+28]
        movdqu	xmm3, OWORD PTR [eax+edi]
        pxor	xmm3, xmm5
        mov	ecx, DWORD PTR [esp+40]
        pxor	xmm3, [ecx]
        movdqu	xmm0, OWORD PTR [ecx+16]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+32]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+48]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+64]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+80]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+96]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+112]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+128]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+144]
        aesdec	xmm3, xmm0
        cmp	DWORD PTR [esp+48], 11
        movdqu	xmm0, OWORD PTR [ecx+160]
        jl	L_AES_XTS_decrypt_update_aesni_declast_12
        aesdec	xmm3, xmm0
        movdqu	xmm1, OWORD PTR [ecx+176]
        aesdec	xmm3, xmm1
        cmp	DWORD PTR [esp+48], 13
        movdqu	xmm0, OWORD PTR [ecx+192]
        jl	L_AES_XTS_decrypt_update_aesni_declast_12
        aesdec	xmm3, xmm0
        movdqu	xmm1, OWORD PTR [ecx+208]
        aesdec	xmm3, xmm1
        movdqu	xmm0, OWORD PTR [ecx+224]
L_AES_XTS_decrypt_update_aesni_declast_12:
        aesdeclast	xmm3, xmm0
        pxor	xmm3, xmm5
        movdqu	OWORD PTR [esp], xmm3
        add	edi, 16
        xor	edx, edx
L_AES_XTS_decrypt_update_aesni_cts:
        movzx	ecx, BYTE PTR [esp+edx]
        mov	eax, DWORD PTR [esp+28]
        movzx	ebx, BYTE PTR [eax+edi]
        mov	eax, DWORD PTR [esp+32]
        mov	BYTE PTR [eax+edi], cl
        mov	BYTE PTR [esp+edx], bl
        inc	edi
        inc	edx
        mov	eax, DWORD PTR [esp+36]
        cmp	edi, eax
        jb	L_AES_XTS_decrypt_update_aesni_cts
        sub	edi, edx
        movdqu	xmm3, OWORD PTR [esp]
        pxor	xmm3, xmm2
        mov	ecx, DWORD PTR [esp+40]
        pxor	xmm3, [ecx]
        movdqu	xmm0, OWORD PTR [ecx+16]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+32]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+48]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+64]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+80]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+96]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+112]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+128]
        aesdec	xmm3, xmm0
        movdqu	xmm0, OWORD PTR [ecx+144]
        aesdec	xmm3, xmm0
        cmp	DWORD PTR [esp+48], 11
        movdqu	xmm0, OWORD PTR [ecx+160]
        jl	L_AES_XTS_decrypt_update_aesni_declast_13
        aesdec	xmm3, xmm0
        movdqu	xmm1, OWORD PTR [ecx+176]
        aesdec	xmm3, xmm1
        cmp	DWORD PTR [esp+48], 13
        movdqu	xmm0, OWORD PTR [ecx+192]
        jl	L_AES_XTS_decrypt_update_aesni_declast_13
        aesdec	xmm3, xmm0
        movdqu	xmm1, OWORD PTR [ecx+208]
        aesdec	xmm3, xmm1
        movdqu	xmm0, OWORD PTR [ecx+224]
L_AES_XTS_decrypt_update_aesni_declast_13:
        aesdeclast	xmm3, xmm0
        pxor	xmm3, xmm2
        sub	edi, 16
        mov	eax, DWORD PTR [esp+32]
        movdqu	OWORD PTR [eax+edi], xmm3
L_AES_XTS_decrypt_update_aesni_done:
        mov	eax, DWORD PTR [esp+44]
        movdqu	OWORD PTR [eax], xmm2
        add	esp, 16
        pop	ebx
        pop	edi
        ret
AES_XTS_decrypt_update_aesni ENDP
_TEXT ENDS
ENDIF
ENDIF
END
