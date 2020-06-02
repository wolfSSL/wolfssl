/* psoc6_crypto.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#if defined(WOLFSSL_PSOC6_CRYPTO)

#include <wolfssl/wolfcrypt/port/cypress/psoc6_crypto.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <stdint.h>

static CRYPTO_Type *crypto_base = PSOC6_CRYPTO_BASE;

/* Hook for device specific initialization */
int psoc6_crypto_port_init(void)
{
    Cy_Crypto_Core_Enable(crypto_base);
    return 0;
}

#ifdef WOLFSSL_SHA512
int wc_InitSha512(wc_Sha512* sha)
{
    cy_en_crypto_status_t res;
    if (!sha)
        return BAD_FUNC_ARG;
    Cy_Crypto_Core_MemSet(crypto_base, sha, 0, sizeof(sha));
    res = Cy_Crypto_Core_Sha_Init(crypto_base, &sha->hash_state, CY_CRYPTO_MODE_SHA512, &sha->sha_buffers);
    if (res != CY_CRYPTO_SUCCESS)
       return (int)res;
    return (int) Cy_Crypto_Core_Sha_Start(crypto_base, &sha->hash_state);
}

int wc_Sha512Update(wc_Sha512* sha, const byte* in, word32 sz)
{
    if ((!sha) || (!in))
        return BAD_FUNC_ARG;
    if (sz == 0)
        return 0;

    return (int)Cy_Crypto_Core_Sha_Update(crypto_base, &sha->hash_state, in, sz);
}

int wc_Sha512Final(wc_Sha512* sha, byte* hash)
{
    if ((!sha) || (!hash))
        return BAD_FUNC_ARG;
    return (int)Cy_Crypto_Core_Sha_Finish(crypto_base, &sha->hash_state, hash);
}

int wc_Sha512GetHash(wc_Sha512* sha, byte* hash)
{
    if ((!sha) || (!hash))
        return BAD_FUNC_ARG;
    Cy_Crypto_Core_MemCpy(crypto_base, hash, sha->hash_state.hash, WC_SHA512_DIGEST_SIZE);
    return 0;
}

int wc_Sha512Copy(wc_Sha512* src, wc_Sha512* dst)
{
    cy_en_crypto_status_t res;
    if ((!dst) || (!src))
        return BAD_FUNC_ARG;
    Cy_Crypto_Core_MemCpy(crypto_base, dst, src, sizeof(wc_Sha512));
    return (int)Cy_Crypto_Core_Sha_Init(crypto_base, &dst->hash_state, CY_CRYPTO_MODE_SHA512, &dst->sha_buffers);
}

void wc_Sha512Free(wc_Sha512* sha)
{
    if (sha)
        Cy_Crypto_Core_Sha_Free(crypto_base, &sha->hash_state);
}

#endif

#ifndef NO_SHA256


int wc_InitSha256(wc_Sha256* sha)
{
    cy_en_crypto_status_t res;
    if (!sha)
        return BAD_FUNC_ARG;
    Cy_Crypto_Core_MemSet(crypto_base, sha, 0, sizeof(sha));
    res = Cy_Crypto_Core_Sha_Init(crypto_base, &sha->hash_state, CY_CRYPTO_MODE_SHA256, &sha->sha_buffers);
    if (res != CY_CRYPTO_SUCCESS)
       return (int)res;
    return (int) Cy_Crypto_Core_Sha_Start(crypto_base, &sha->hash_state);
}

int wc_Sha256Update(wc_Sha256* sha, const byte* in, word32 sz)
{
    if ((!sha) || (!in))
        return BAD_FUNC_ARG;
    if (sz == 0)
        return 0;

    return (int)Cy_Crypto_Core_Sha_Update(crypto_base, &sha->hash_state, in, sz);
}

int wc_Sha256Final(wc_Sha256* sha, byte* hash)
{
    if ((!sha) || (!hash))
        return BAD_FUNC_ARG;
    return (int)Cy_Crypto_Core_Sha_Finish(crypto_base, &sha->hash_state, hash);
}

int wc_Sha256GetHash(wc_Sha256* sha, byte* hash)
{
    if ((!sha) || (!hash))
        return BAD_FUNC_ARG;
    Cy_Crypto_Core_MemCpy(crypto_base, hash, sha->hash_state.hash, WC_SHA256_DIGEST_SIZE);
    return 0;
}

int wc_Sha256Copy(wc_Sha256* src, wc_Sha256* dst)
{
    cy_en_crypto_status_t res;
    if ((!dst) || (!src))
        return BAD_FUNC_ARG;
    Cy_Crypto_Core_MemCpy(crypto_base, dst, src, sizeof(wc_Sha256));
    return (int)Cy_Crypto_Core_Sha_Init(crypto_base, &dst->hash_state, CY_CRYPTO_MODE_SHA256, &dst->sha_buffers);
}

void wc_Sha256Free(wc_Sha256* sha)
{
    if (sha)
        Cy_Crypto_Core_Sha_Free(crypto_base, &sha->hash_state);
}
#endif /* NO_SHA256 */

#endif /* defined(WOLFSSL_PSOC6_CRYPTO) */

