/* cavium_octeon_sync.h
 *
 * Copyright (C) 2006-2019 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef _CAVIUM_OCTEON_SYNC_H_
#define _CAVIUM_OCTEON_SYNC_H_

#ifdef HAVE_CAVIUM_OCTEON_SYNC

#ifndef NO_DES3
    #include <wolfssl/wolfcrypt/des3.h>
#endif
#ifndef NO_AES
    #include <wolfssl/wolfcrypt/aes.h>
#endif

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "cvmx.h"
#include "cvmx-asm.h"
#include "cvmx-key.h"
#include "cvmx-swap.h"


#ifdef WOLF_CRYPTO_CB
WOLFSSL_API int wc_CryptoCb_InitOcteon(void* unused);
WOLFSSL_API void wc_CryptoCb_CleanupOcteon(int* id, void* unused);
#endif /* WOLF_CRYPTO_CB */


#ifndef NO_DES3
WOLFSSL_LOCAL int Octeon_Des3_CbcEncrypt(Des3 *key,
        uint64_t *inp64, uint64_t *outp64, size_t inl);
WOLFSSL_LOCAL int Octeon_Des3_CbcDecrypt(Des3 *key,
        uint64_t *inp64, uint64_t *outp64, size_t inl);
#endif /* !NO_DES3 */


#ifndef NO_AES

#ifdef WOLFSSL_AES_DIRECT
WOLFSSL_LOCAL int Octeon_AesEcb_Encrypt(Aes *aes,
        const unsigned char *in, unsigned char *out);
WOLFSSL_LOCAL int Octeon_AesEcb_Decrypt(Aes *aes,
        const unsigned char *in, unsigned char *out);
#endif

#ifdef HAVE_AES_CBC
WOLFSSL_LOCAL int Octeon_AesCbc_Encrypt(Aes *aes,
        uint64_t *inp64, uint64_t *outp64, size_t inl);
WOLFSSL_LOCAL int Octeon_AesCbc_Decrypt(Aes *aes,
        uint64_t *inp64, uint64_t *outp64, size_t inl);
#endif

#ifdef HAVE_AESGCM
WOLFSSL_LOCAL int Octeon_AesGcm_Encrypt(Aes* aes,
        byte* in, byte* out, word32 inSz,
        byte* iv, word32 ivSz, byte* aad, word32 aadSz, byte* tag);
WOLFSSL_LOCAL int Octeon_AesGcm_Decrypt(Aes* aes,
        byte* in, byte* out, word32 inSz,
        byte* iv, word32 ivSz, byte* aad, word32 aadSz, byte* tag);
#endif /* HAVE_AESGCM */

#endif /* !NO_AES */

#endif /* HAVE_CAVIUM_OCTEON_SYNC */
#endif /* _CAVIUM_OCTEON_SYNC_H_ */
