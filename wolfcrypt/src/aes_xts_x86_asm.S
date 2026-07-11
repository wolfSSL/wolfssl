/* aes_xts_x86_asm
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifdef WOLFSSL_USER_SETTINGS
#include "wolfssl/wolfcrypt/settings.h"
#endif

#ifndef HAVE_INTEL_AVX1
#define HAVE_INTEL_AVX1
#endif /* HAVE_INTEL_AVX1 */
#ifndef NO_AVX2_SUPPORT
#ifndef HAVE_INTEL_AVX2
#define HAVE_INTEL_AVX2
#endif /* HAVE_INTEL_AVX2 */
#endif /* NO_AVX2_SUPPORT */

#ifdef WOLFSSL_AES_XTS
#ifdef WOLFSSL_X86_BUILD
        # 32-bit (i386) AES-NI AES-XTS: single-block ports of the x86_64
        # AES_XTS_*_aesni routines (xmm0-7, cdecl ABI); GF const on stack for PIC.
        # void AES_XTS_init_aesni(unsigned char* i, const unsigned char* tweak_key,
        #                         int tweak_nr);
.text
.globl	AES_XTS_init_aesni
.type	AES_XTS_init_aesni,@function
.align	16
AES_XTS_init_aesni:
        movl	4(%esp), %eax
        movdqu	(%eax), %xmm2
        movl	8(%esp), %ecx
        pxor	(%ecx), %xmm2
        movdqu	16(%ecx), %xmm0
        aesenc	%xmm0, %xmm2
        movdqu	32(%ecx), %xmm0
        aesenc	%xmm0, %xmm2
        movdqu	48(%ecx), %xmm0
        aesenc	%xmm0, %xmm2
        movdqu	64(%ecx), %xmm0
        aesenc	%xmm0, %xmm2
        movdqu	80(%ecx), %xmm0
        aesenc	%xmm0, %xmm2
        movdqu	96(%ecx), %xmm0
        aesenc	%xmm0, %xmm2
        movdqu	112(%ecx), %xmm0
        aesenc	%xmm0, %xmm2
        movdqu	128(%ecx), %xmm0
        aesenc	%xmm0, %xmm2
        movdqu	144(%ecx), %xmm0
        aesenc	%xmm0, %xmm2
        cmpl	$11, 12(%esp)
        movdqu	160(%ecx), %xmm0
        jl	L_AES_XTS_init_aesni_enclast_1
        aesenc	%xmm0, %xmm2
        movdqu	176(%ecx), %xmm1
        aesenc	%xmm1, %xmm2
        cmpl	$13, 12(%esp)
        movdqu	192(%ecx), %xmm0
        jl	L_AES_XTS_init_aesni_enclast_1
        aesenc	%xmm0, %xmm2
        movdqu	208(%ecx), %xmm1
        aesenc	%xmm1, %xmm2
        movdqu	224(%ecx), %xmm0
L_AES_XTS_init_aesni_enclast_1:
        aesenclast	%xmm0, %xmm2
        movdqu	%xmm2, (%eax)
        ret
.size	AES_XTS_init_aesni,.-AES_XTS_init_aesni
        # void AES_XTS_encrypt_aesni(const unsigned char* in, unsigned char* out,
        #     word32 sz, const unsigned char* i, const unsigned char* key,
        #     const unsigned char* key2, int nr);
.text
.globl	AES_XTS_encrypt_aesni
.type	AES_XTS_encrypt_aesni,@function
.align	16
AES_XTS_encrypt_aesni:
        pushl	%edi
        pushl	%ebx
        subl	$16, %esp
        movl	$0x87, (%esp)
        movl	$0x01, 4(%esp)
        movl	$0x01, 8(%esp)
        movl	$0x01, 12(%esp)
        movdqu	(%esp), %xmm6
        movl	40(%esp), %eax
        movdqu	(%eax), %xmm2
        movl	48(%esp), %ecx
        pxor	(%ecx), %xmm2
        movdqu	16(%ecx), %xmm0
        aesenc	%xmm0, %xmm2
        movdqu	32(%ecx), %xmm0
        aesenc	%xmm0, %xmm2
        movdqu	48(%ecx), %xmm0
        aesenc	%xmm0, %xmm2
        movdqu	64(%ecx), %xmm0
        aesenc	%xmm0, %xmm2
        movdqu	80(%ecx), %xmm0
        aesenc	%xmm0, %xmm2
        movdqu	96(%ecx), %xmm0
        aesenc	%xmm0, %xmm2
        movdqu	112(%ecx), %xmm0
        aesenc	%xmm0, %xmm2
        movdqu	128(%ecx), %xmm0
        aesenc	%xmm0, %xmm2
        movdqu	144(%ecx), %xmm0
        aesenc	%xmm0, %xmm2
        cmpl	$11, 52(%esp)
        movdqu	160(%ecx), %xmm0
        jl	L_AES_XTS_encrypt_aesni_enclast_2
        aesenc	%xmm0, %xmm2
        movdqu	176(%ecx), %xmm1
        aesenc	%xmm1, %xmm2
        cmpl	$13, 52(%esp)
        movdqu	192(%ecx), %xmm0
        jl	L_AES_XTS_encrypt_aesni_enclast_2
        aesenc	%xmm0, %xmm2
        movdqu	208(%ecx), %xmm1
        aesenc	%xmm1, %xmm2
        movdqu	224(%ecx), %xmm0
L_AES_XTS_encrypt_aesni_enclast_2:
        aesenclast	%xmm0, %xmm2
        xorl	%edi, %edi
        movl	36(%esp), %edx
        andl	$0xfffffff0, %edx
L_AES_XTS_encrypt_aesni_loop:
        cmpl	%edx, %edi
        jge	L_AES_XTS_encrypt_aesni_loop_done
        movl	28(%esp), %eax
        movdqu	(%eax,%edi,1), %xmm3
        pxor	%xmm2, %xmm3
        movl	44(%esp), %ecx
        pxor	(%ecx), %xmm3
        movdqu	16(%ecx), %xmm0
        aesenc	%xmm0, %xmm3
        movdqu	32(%ecx), %xmm0
        aesenc	%xmm0, %xmm3
        movdqu	48(%ecx), %xmm0
        aesenc	%xmm0, %xmm3
        movdqu	64(%ecx), %xmm0
        aesenc	%xmm0, %xmm3
        movdqu	80(%ecx), %xmm0
        aesenc	%xmm0, %xmm3
        movdqu	96(%ecx), %xmm0
        aesenc	%xmm0, %xmm3
        movdqu	112(%ecx), %xmm0
        aesenc	%xmm0, %xmm3
        movdqu	128(%ecx), %xmm0
        aesenc	%xmm0, %xmm3
        movdqu	144(%ecx), %xmm0
        aesenc	%xmm0, %xmm3
        cmpl	$11, 52(%esp)
        movdqu	160(%ecx), %xmm0
        jl	L_AES_XTS_encrypt_aesni_enclast_3
        aesenc	%xmm0, %xmm3
        movdqu	176(%ecx), %xmm1
        aesenc	%xmm1, %xmm3
        cmpl	$13, 52(%esp)
        movdqu	192(%ecx), %xmm0
        jl	L_AES_XTS_encrypt_aesni_enclast_3
        aesenc	%xmm0, %xmm3
        movdqu	208(%ecx), %xmm1
        aesenc	%xmm1, %xmm3
        movdqu	224(%ecx), %xmm0
L_AES_XTS_encrypt_aesni_enclast_3:
        aesenclast	%xmm0, %xmm3
        pxor	%xmm2, %xmm3
        movl	32(%esp), %eax
        movdqu	%xmm3, (%eax,%edi,1)
        movdqa	%xmm2, %xmm4
        psrad	$31, %xmm4
        pslld	$0x01, %xmm2
        pshufd	$0x93, %xmm4, %xmm4
        pand	%xmm6, %xmm4
        pxor	%xmm4, %xmm2
        addl	$16, %edi
        jmp	L_AES_XTS_encrypt_aesni_loop
L_AES_XTS_encrypt_aesni_loop_done:
        movl	36(%esp), %eax
        cmpl	%eax, %edi
        je	L_AES_XTS_encrypt_aesni_done
        subl	$16, %edi
        movl	32(%esp), %eax
        movdqu	(%eax,%edi,1), %xmm5
        addl	$16, %edi
        movdqu	%xmm5, (%esp)
        xorl	%edx, %edx
L_AES_XTS_encrypt_aesni_cts:
        movzbl	(%esp,%edx,1), %ecx
        movl	28(%esp), %eax
        movzbl	(%eax,%edi,1), %ebx
        movl	32(%esp), %eax
        movb	%cl, (%eax,%edi,1)
        movb	%bl, (%esp,%edx,1)
        incl	%edi
        incl	%edx
        movl	36(%esp), %eax
        cmpl	%eax, %edi
        jl	L_AES_XTS_encrypt_aesni_cts
        subl	%edx, %edi
        movdqu	(%esp), %xmm3
        subl	$16, %edi
        pxor	%xmm2, %xmm3
        movl	44(%esp), %ecx
        pxor	(%ecx), %xmm3
        movdqu	16(%ecx), %xmm0
        aesenc	%xmm0, %xmm3
        movdqu	32(%ecx), %xmm0
        aesenc	%xmm0, %xmm3
        movdqu	48(%ecx), %xmm0
        aesenc	%xmm0, %xmm3
        movdqu	64(%ecx), %xmm0
        aesenc	%xmm0, %xmm3
        movdqu	80(%ecx), %xmm0
        aesenc	%xmm0, %xmm3
        movdqu	96(%ecx), %xmm0
        aesenc	%xmm0, %xmm3
        movdqu	112(%ecx), %xmm0
        aesenc	%xmm0, %xmm3
        movdqu	128(%ecx), %xmm0
        aesenc	%xmm0, %xmm3
        movdqu	144(%ecx), %xmm0
        aesenc	%xmm0, %xmm3
        cmpl	$11, 52(%esp)
        movdqu	160(%ecx), %xmm0
        jl	L_AES_XTS_encrypt_aesni_enclast_4
        aesenc	%xmm0, %xmm3
        movdqu	176(%ecx), %xmm1
        aesenc	%xmm1, %xmm3
        cmpl	$13, 52(%esp)
        movdqu	192(%ecx), %xmm0
        jl	L_AES_XTS_encrypt_aesni_enclast_4
        aesenc	%xmm0, %xmm3
        movdqu	208(%ecx), %xmm1
        aesenc	%xmm1, %xmm3
        movdqu	224(%ecx), %xmm0
L_AES_XTS_encrypt_aesni_enclast_4:
        aesenclast	%xmm0, %xmm3
        pxor	%xmm2, %xmm3
        movl	32(%esp), %eax
        movdqu	%xmm3, (%eax,%edi,1)
L_AES_XTS_encrypt_aesni_done:
        addl	$16, %esp
        popl	%ebx
        popl	%edi
        ret
.size	AES_XTS_encrypt_aesni,.-AES_XTS_encrypt_aesni
        # void AES_XTS_encrypt_update_aesni(const unsigned char* in,
        #     unsigned char* out, word32 sz, const unsigned char* key,
        #     unsigned char* i, int nr);  Tweak is read (already encrypted) from *i
        #     and the advanced tweak written back to *i.
.text
.globl	AES_XTS_encrypt_update_aesni
.type	AES_XTS_encrypt_update_aesni,@function
.align	16
AES_XTS_encrypt_update_aesni:
        pushl	%edi
        pushl	%ebx
        subl	$16, %esp
        movl	$0x87, (%esp)
        movl	$0x01, 4(%esp)
        movl	$0x01, 8(%esp)
        movl	$0x01, 12(%esp)
        movdqu	(%esp), %xmm6
        movl	44(%esp), %eax
        movdqu	(%eax), %xmm2
        xorl	%edi, %edi
        movl	36(%esp), %edx
        andl	$0xfffffff0, %edx
L_AES_XTS_encrypt_update_aesni_loop:
        cmpl	%edx, %edi
        jge	L_AES_XTS_encrypt_update_aesni_loop_done
        movl	28(%esp), %eax
        movdqu	(%eax,%edi,1), %xmm3
        pxor	%xmm2, %xmm3
        movl	40(%esp), %ecx
        pxor	(%ecx), %xmm3
        movdqu	16(%ecx), %xmm0
        aesenc	%xmm0, %xmm3
        movdqu	32(%ecx), %xmm0
        aesenc	%xmm0, %xmm3
        movdqu	48(%ecx), %xmm0
        aesenc	%xmm0, %xmm3
        movdqu	64(%ecx), %xmm0
        aesenc	%xmm0, %xmm3
        movdqu	80(%ecx), %xmm0
        aesenc	%xmm0, %xmm3
        movdqu	96(%ecx), %xmm0
        aesenc	%xmm0, %xmm3
        movdqu	112(%ecx), %xmm0
        aesenc	%xmm0, %xmm3
        movdqu	128(%ecx), %xmm0
        aesenc	%xmm0, %xmm3
        movdqu	144(%ecx), %xmm0
        aesenc	%xmm0, %xmm3
        cmpl	$11, 48(%esp)
        movdqu	160(%ecx), %xmm0
        jl	L_AES_XTS_encrypt_update_aesni_enclast_5
        aesenc	%xmm0, %xmm3
        movdqu	176(%ecx), %xmm1
        aesenc	%xmm1, %xmm3
        cmpl	$13, 48(%esp)
        movdqu	192(%ecx), %xmm0
        jl	L_AES_XTS_encrypt_update_aesni_enclast_5
        aesenc	%xmm0, %xmm3
        movdqu	208(%ecx), %xmm1
        aesenc	%xmm1, %xmm3
        movdqu	224(%ecx), %xmm0
L_AES_XTS_encrypt_update_aesni_enclast_5:
        aesenclast	%xmm0, %xmm3
        pxor	%xmm2, %xmm3
        movl	32(%esp), %eax
        movdqu	%xmm3, (%eax,%edi,1)
        movdqa	%xmm2, %xmm4
        psrad	$31, %xmm4
        pslld	$0x01, %xmm2
        pshufd	$0x93, %xmm4, %xmm4
        pand	%xmm6, %xmm4
        pxor	%xmm4, %xmm2
        addl	$16, %edi
        jmp	L_AES_XTS_encrypt_update_aesni_loop
L_AES_XTS_encrypt_update_aesni_loop_done:
        movl	36(%esp), %eax
        cmpl	%eax, %edi
        je	L_AES_XTS_encrypt_update_aesni_done
        subl	$16, %edi
        movl	32(%esp), %eax
        movdqu	(%eax,%edi,1), %xmm5
        addl	$16, %edi
        movdqu	%xmm5, (%esp)
        xorl	%edx, %edx
L_AES_XTS_encrypt_update_aesni_cts:
        movzbl	(%esp,%edx,1), %ecx
        movl	28(%esp), %eax
        movzbl	(%eax,%edi,1), %ebx
        movl	32(%esp), %eax
        movb	%cl, (%eax,%edi,1)
        movb	%bl, (%esp,%edx,1)
        incl	%edi
        incl	%edx
        movl	36(%esp), %eax
        cmpl	%eax, %edi
        jl	L_AES_XTS_encrypt_update_aesni_cts
        subl	%edx, %edi
        movdqu	(%esp), %xmm3
        subl	$16, %edi
        pxor	%xmm2, %xmm3
        movl	40(%esp), %ecx
        pxor	(%ecx), %xmm3
        movdqu	16(%ecx), %xmm0
        aesenc	%xmm0, %xmm3
        movdqu	32(%ecx), %xmm0
        aesenc	%xmm0, %xmm3
        movdqu	48(%ecx), %xmm0
        aesenc	%xmm0, %xmm3
        movdqu	64(%ecx), %xmm0
        aesenc	%xmm0, %xmm3
        movdqu	80(%ecx), %xmm0
        aesenc	%xmm0, %xmm3
        movdqu	96(%ecx), %xmm0
        aesenc	%xmm0, %xmm3
        movdqu	112(%ecx), %xmm0
        aesenc	%xmm0, %xmm3
        movdqu	128(%ecx), %xmm0
        aesenc	%xmm0, %xmm3
        movdqu	144(%ecx), %xmm0
        aesenc	%xmm0, %xmm3
        cmpl	$11, 48(%esp)
        movdqu	160(%ecx), %xmm0
        jl	L_AES_XTS_encrypt_update_aesni_enclast_6
        aesenc	%xmm0, %xmm3
        movdqu	176(%ecx), %xmm1
        aesenc	%xmm1, %xmm3
        cmpl	$13, 48(%esp)
        movdqu	192(%ecx), %xmm0
        jl	L_AES_XTS_encrypt_update_aesni_enclast_6
        aesenc	%xmm0, %xmm3
        movdqu	208(%ecx), %xmm1
        aesenc	%xmm1, %xmm3
        movdqu	224(%ecx), %xmm0
L_AES_XTS_encrypt_update_aesni_enclast_6:
        aesenclast	%xmm0, %xmm3
        pxor	%xmm2, %xmm3
        movl	32(%esp), %eax
        movdqu	%xmm3, (%eax,%edi,1)
L_AES_XTS_encrypt_update_aesni_done:
        movl	44(%esp), %eax
        movdqu	%xmm2, (%eax)
        addl	$16, %esp
        popl	%ebx
        popl	%edi
        ret
.size	AES_XTS_encrypt_update_aesni,.-AES_XTS_encrypt_update_aesni
        # void AES_XTS_decrypt_aesni(const unsigned char* in, unsigned char* out,
        #     word32 sz, const unsigned char* i, const unsigned char* key,
        #     const unsigned char* key2, int nr);
.text
.globl	AES_XTS_decrypt_aesni
.type	AES_XTS_decrypt_aesni,@function
.align	16
AES_XTS_decrypt_aesni:
        pushl	%edi
        pushl	%ebx
        subl	$16, %esp
        movl	$0x87, (%esp)
        movl	$0x01, 4(%esp)
        movl	$0x01, 8(%esp)
        movl	$0x01, 12(%esp)
        movdqu	(%esp), %xmm6
        movl	40(%esp), %eax
        movdqu	(%eax), %xmm2
        movl	48(%esp), %ecx
        pxor	(%ecx), %xmm2
        movdqu	16(%ecx), %xmm0
        aesenc	%xmm0, %xmm2
        movdqu	32(%ecx), %xmm0
        aesenc	%xmm0, %xmm2
        movdqu	48(%ecx), %xmm0
        aesenc	%xmm0, %xmm2
        movdqu	64(%ecx), %xmm0
        aesenc	%xmm0, %xmm2
        movdqu	80(%ecx), %xmm0
        aesenc	%xmm0, %xmm2
        movdqu	96(%ecx), %xmm0
        aesenc	%xmm0, %xmm2
        movdqu	112(%ecx), %xmm0
        aesenc	%xmm0, %xmm2
        movdqu	128(%ecx), %xmm0
        aesenc	%xmm0, %xmm2
        movdqu	144(%ecx), %xmm0
        aesenc	%xmm0, %xmm2
        cmpl	$11, 52(%esp)
        movdqu	160(%ecx), %xmm0
        jl	L_AES_XTS_decrypt_aesni_enclast_7
        aesenc	%xmm0, %xmm2
        movdqu	176(%ecx), %xmm1
        aesenc	%xmm1, %xmm2
        cmpl	$13, 52(%esp)
        movdqu	192(%ecx), %xmm0
        jl	L_AES_XTS_decrypt_aesni_enclast_7
        aesenc	%xmm0, %xmm2
        movdqu	208(%ecx), %xmm1
        aesenc	%xmm1, %xmm2
        movdqu	224(%ecx), %xmm0
L_AES_XTS_decrypt_aesni_enclast_7:
        aesenclast	%xmm0, %xmm2
        xorl	%edi, %edi
        movl	36(%esp), %eax
        movl	%eax, %edx
        andl	$0xfffffff0, %edx
        cmpl	%eax, %edx
        je	L_AES_XTS_decrypt_aesni_bound
        subl	$16, %edx
L_AES_XTS_decrypt_aesni_bound:
L_AES_XTS_decrypt_aesni_loop:
        cmpl	%edx, %edi
        jge	L_AES_XTS_decrypt_aesni_loop_done
        movl	28(%esp), %eax
        movdqu	(%eax,%edi,1), %xmm3
        pxor	%xmm2, %xmm3
        movl	44(%esp), %ecx
        pxor	(%ecx), %xmm3
        movdqu	16(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	32(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	48(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	64(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	80(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	96(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	112(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	128(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	144(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        cmpl	$11, 52(%esp)
        movdqu	160(%ecx), %xmm0
        jl	L_AES_XTS_decrypt_aesni_declast_8
        aesdec	%xmm0, %xmm3
        movdqu	176(%ecx), %xmm1
        aesdec	%xmm1, %xmm3
        cmpl	$13, 52(%esp)
        movdqu	192(%ecx), %xmm0
        jl	L_AES_XTS_decrypt_aesni_declast_8
        aesdec	%xmm0, %xmm3
        movdqu	208(%ecx), %xmm1
        aesdec	%xmm1, %xmm3
        movdqu	224(%ecx), %xmm0
L_AES_XTS_decrypt_aesni_declast_8:
        aesdeclast	%xmm0, %xmm3
        pxor	%xmm2, %xmm3
        movl	32(%esp), %eax
        movdqu	%xmm3, (%eax,%edi,1)
        movdqa	%xmm2, %xmm4
        psrad	$31, %xmm4
        pslld	$0x01, %xmm2
        pshufd	$0x93, %xmm4, %xmm4
        pand	%xmm6, %xmm4
        pxor	%xmm4, %xmm2
        addl	$16, %edi
        jmp	L_AES_XTS_decrypt_aesni_loop
L_AES_XTS_decrypt_aesni_loop_done:
        movl	36(%esp), %eax
        cmpl	%eax, %edi
        je	L_AES_XTS_decrypt_aesni_done
        movdqa	%xmm2, %xmm4
        movdqa	%xmm2, %xmm5
        psrad	$31, %xmm4
        pslld	$0x01, %xmm5
        pshufd	$0x93, %xmm4, %xmm4
        pand	%xmm6, %xmm4
        pxor	%xmm4, %xmm5
        movl	28(%esp), %eax
        movdqu	(%eax,%edi,1), %xmm3
        pxor	%xmm5, %xmm3
        movl	44(%esp), %ecx
        pxor	(%ecx), %xmm3
        movdqu	16(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	32(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	48(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	64(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	80(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	96(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	112(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	128(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	144(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        cmpl	$11, 52(%esp)
        movdqu	160(%ecx), %xmm0
        jl	L_AES_XTS_decrypt_aesni_declast_9
        aesdec	%xmm0, %xmm3
        movdqu	176(%ecx), %xmm1
        aesdec	%xmm1, %xmm3
        cmpl	$13, 52(%esp)
        movdqu	192(%ecx), %xmm0
        jl	L_AES_XTS_decrypt_aesni_declast_9
        aesdec	%xmm0, %xmm3
        movdqu	208(%ecx), %xmm1
        aesdec	%xmm1, %xmm3
        movdqu	224(%ecx), %xmm0
L_AES_XTS_decrypt_aesni_declast_9:
        aesdeclast	%xmm0, %xmm3
        pxor	%xmm5, %xmm3
        movdqu	%xmm3, (%esp)
        addl	$16, %edi
        xorl	%edx, %edx
L_AES_XTS_decrypt_aesni_cts:
        movzbl	(%esp,%edx,1), %ecx
        movl	28(%esp), %eax
        movzbl	(%eax,%edi,1), %ebx
        movl	32(%esp), %eax
        movb	%cl, (%eax,%edi,1)
        movb	%bl, (%esp,%edx,1)
        incl	%edi
        incl	%edx
        movl	36(%esp), %eax
        cmpl	%eax, %edi
        jl	L_AES_XTS_decrypt_aesni_cts
        subl	%edx, %edi
        movdqu	(%esp), %xmm3
        pxor	%xmm2, %xmm3
        movl	44(%esp), %ecx
        pxor	(%ecx), %xmm3
        movdqu	16(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	32(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	48(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	64(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	80(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	96(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	112(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	128(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	144(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        cmpl	$11, 52(%esp)
        movdqu	160(%ecx), %xmm0
        jl	L_AES_XTS_decrypt_aesni_declast_10
        aesdec	%xmm0, %xmm3
        movdqu	176(%ecx), %xmm1
        aesdec	%xmm1, %xmm3
        cmpl	$13, 52(%esp)
        movdqu	192(%ecx), %xmm0
        jl	L_AES_XTS_decrypt_aesni_declast_10
        aesdec	%xmm0, %xmm3
        movdqu	208(%ecx), %xmm1
        aesdec	%xmm1, %xmm3
        movdqu	224(%ecx), %xmm0
L_AES_XTS_decrypt_aesni_declast_10:
        aesdeclast	%xmm0, %xmm3
        pxor	%xmm2, %xmm3
        subl	$16, %edi
        movl	32(%esp), %eax
        movdqu	%xmm3, (%eax,%edi,1)
L_AES_XTS_decrypt_aesni_done:
        addl	$16, %esp
        popl	%ebx
        popl	%edi
        ret
.size	AES_XTS_decrypt_aesni,.-AES_XTS_decrypt_aesni
        # void AES_XTS_decrypt_update_aesni(const unsigned char* in,
        #     unsigned char* out, word32 sz, const unsigned char* key,
        #     unsigned char* i, int nr);  Tweak is read from *i and the advanced
        #     tweak written back to *i.
.text
.globl	AES_XTS_decrypt_update_aesni
.type	AES_XTS_decrypt_update_aesni,@function
.align	16
AES_XTS_decrypt_update_aesni:
        pushl	%edi
        pushl	%ebx
        subl	$16, %esp
        movl	$0x87, (%esp)
        movl	$0x01, 4(%esp)
        movl	$0x01, 8(%esp)
        movl	$0x01, 12(%esp)
        movdqu	(%esp), %xmm6
        movl	44(%esp), %eax
        movdqu	(%eax), %xmm2
        xorl	%edi, %edi
        movl	36(%esp), %eax
        movl	%eax, %edx
        andl	$0xfffffff0, %edx
        cmpl	%eax, %edx
        je	L_AES_XTS_decrypt_update_aesni_bound
        subl	$16, %edx
L_AES_XTS_decrypt_update_aesni_bound:
L_AES_XTS_decrypt_update_aesni_loop:
        cmpl	%edx, %edi
        jge	L_AES_XTS_decrypt_update_aesni_loop_done
        movl	28(%esp), %eax
        movdqu	(%eax,%edi,1), %xmm3
        pxor	%xmm2, %xmm3
        movl	40(%esp), %ecx
        pxor	(%ecx), %xmm3
        movdqu	16(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	32(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	48(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	64(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	80(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	96(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	112(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	128(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	144(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        cmpl	$11, 48(%esp)
        movdqu	160(%ecx), %xmm0
        jl	L_AES_XTS_decrypt_update_aesni_declast_11
        aesdec	%xmm0, %xmm3
        movdqu	176(%ecx), %xmm1
        aesdec	%xmm1, %xmm3
        cmpl	$13, 48(%esp)
        movdqu	192(%ecx), %xmm0
        jl	L_AES_XTS_decrypt_update_aesni_declast_11
        aesdec	%xmm0, %xmm3
        movdqu	208(%ecx), %xmm1
        aesdec	%xmm1, %xmm3
        movdqu	224(%ecx), %xmm0
L_AES_XTS_decrypt_update_aesni_declast_11:
        aesdeclast	%xmm0, %xmm3
        pxor	%xmm2, %xmm3
        movl	32(%esp), %eax
        movdqu	%xmm3, (%eax,%edi,1)
        movdqa	%xmm2, %xmm4
        psrad	$31, %xmm4
        pslld	$0x01, %xmm2
        pshufd	$0x93, %xmm4, %xmm4
        pand	%xmm6, %xmm4
        pxor	%xmm4, %xmm2
        addl	$16, %edi
        jmp	L_AES_XTS_decrypt_update_aesni_loop
L_AES_XTS_decrypt_update_aesni_loop_done:
        movl	36(%esp), %eax
        cmpl	%eax, %edi
        je	L_AES_XTS_decrypt_update_aesni_done
        movdqa	%xmm2, %xmm4
        movdqa	%xmm2, %xmm5
        psrad	$31, %xmm4
        pslld	$0x01, %xmm5
        pshufd	$0x93, %xmm4, %xmm4
        pand	%xmm6, %xmm4
        pxor	%xmm4, %xmm5
        movl	28(%esp), %eax
        movdqu	(%eax,%edi,1), %xmm3
        pxor	%xmm5, %xmm3
        movl	40(%esp), %ecx
        pxor	(%ecx), %xmm3
        movdqu	16(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	32(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	48(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	64(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	80(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	96(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	112(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	128(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	144(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        cmpl	$11, 48(%esp)
        movdqu	160(%ecx), %xmm0
        jl	L_AES_XTS_decrypt_update_aesni_declast_12
        aesdec	%xmm0, %xmm3
        movdqu	176(%ecx), %xmm1
        aesdec	%xmm1, %xmm3
        cmpl	$13, 48(%esp)
        movdqu	192(%ecx), %xmm0
        jl	L_AES_XTS_decrypt_update_aesni_declast_12
        aesdec	%xmm0, %xmm3
        movdqu	208(%ecx), %xmm1
        aesdec	%xmm1, %xmm3
        movdqu	224(%ecx), %xmm0
L_AES_XTS_decrypt_update_aesni_declast_12:
        aesdeclast	%xmm0, %xmm3
        pxor	%xmm5, %xmm3
        movdqu	%xmm3, (%esp)
        addl	$16, %edi
        xorl	%edx, %edx
L_AES_XTS_decrypt_update_aesni_cts:
        movzbl	(%esp,%edx,1), %ecx
        movl	28(%esp), %eax
        movzbl	(%eax,%edi,1), %ebx
        movl	32(%esp), %eax
        movb	%cl, (%eax,%edi,1)
        movb	%bl, (%esp,%edx,1)
        incl	%edi
        incl	%edx
        movl	36(%esp), %eax
        cmpl	%eax, %edi
        jl	L_AES_XTS_decrypt_update_aesni_cts
        subl	%edx, %edi
        movdqu	(%esp), %xmm3
        pxor	%xmm2, %xmm3
        movl	40(%esp), %ecx
        pxor	(%ecx), %xmm3
        movdqu	16(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	32(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	48(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	64(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	80(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	96(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	112(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	128(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        movdqu	144(%ecx), %xmm0
        aesdec	%xmm0, %xmm3
        cmpl	$11, 48(%esp)
        movdqu	160(%ecx), %xmm0
        jl	L_AES_XTS_decrypt_update_aesni_declast_13
        aesdec	%xmm0, %xmm3
        movdqu	176(%ecx), %xmm1
        aesdec	%xmm1, %xmm3
        cmpl	$13, 48(%esp)
        movdqu	192(%ecx), %xmm0
        jl	L_AES_XTS_decrypt_update_aesni_declast_13
        aesdec	%xmm0, %xmm3
        movdqu	208(%ecx), %xmm1
        aesdec	%xmm1, %xmm3
        movdqu	224(%ecx), %xmm0
L_AES_XTS_decrypt_update_aesni_declast_13:
        aesdeclast	%xmm0, %xmm3
        pxor	%xmm2, %xmm3
        subl	$16, %edi
        movl	32(%esp), %eax
        movdqu	%xmm3, (%eax,%edi,1)
L_AES_XTS_decrypt_update_aesni_done:
        movl	44(%esp), %eax
        movdqu	%xmm2, (%eax)
        addl	$16, %esp
        popl	%ebx
        popl	%edi
        ret
.size	AES_XTS_decrypt_update_aesni,.-AES_XTS_decrypt_update_aesni
#endif /* WOLFSSL_X86_BUILD */
#endif /* WOLFSSL_AES_XTS */

#if defined(__linux__) && defined(__ELF__)
.section	.note.GNU-stack,"",%progbits
#endif
