/* psoc6_crypto.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

#include <stdint.h>
#include <string.h>

#include <wolfssl/wolfcrypt/port/cypress/psoc6_crypto.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

#include "cy_crypto_core_hw_v2.h"
#include "cy_crypto_core_mem.h"

#ifdef HAVE_ECC
#include <wolfssl/wolfcrypt/ecc.h>
#endif

#if defined(PSOC6_HASH_SHA3)

/* Number of bits in a byte */
#define BITS_IN_BYTE 8U

/* Number of bytes of SHA3 to store in 1st partition of register buffer
 * (reg_buff[1023:0]) */
#define PSOC6_CRYPTO_SHA3_RB_LOWER 128U

/* Number of bytes of SHA3 to store in 2nd partition of register buffer
 * (reg_buff[2047:1024]) */
#define PSOC6_CRYPTO_SHA3_RB_UPPER 72U

#endif /* PSOC6_HASH_SHA3 */

static CRYPTO_Type* crypto_base = PSOC6_CRYPTO_BASE;

/* Hook for device specific initialization */
int psoc6_crypto_port_init(void)
{
    Cy_Crypto_Core_Enable(crypto_base);
    return 0;
}

/* Initialize the PSoC6 hardware crypto engine for SHA-1, SHA-2, or SHA-512
 * operation.
 *
 * sha       Pointer to hash context structure (wc_Sha, wc_Sha224, wc_Sha256,
 * wc_Sha384, wc_Sha512). hash_mode Hash mode selector (WC_PSOC6_SHA1,
 * WC_PSOC6_SHA224, WC_PSOC6_SHA256, etc.). init_hash If 1, initializes the hash
 * state; if 0, does not initialize. returns   0 on success, BAD_FUNC_ARG or
 * hardware error code on failure.
 */
int wc_Psoc6_Sha1_Sha2_Init(void* sha, wc_psoc6_hash_sha1_sha2_t hash_mode,
                            int init_hash)
{
    cy_en_crypto_status_t res;
    if (sha == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Enable CRYPTO block if not enabled */
    if (!Cy_Crypto_Core_IsEnabled(crypto_base)) {
        Cy_Crypto_Core_Enable(crypto_base);
    }

    switch (hash_mode) {
#if !defined(NO_SHA) && defined(PSOC6_HASH_SHA1)
        case WC_PSOC6_SHA1:
            /* Initialize the PSoC6 hash state and configure the SHA mode */
            res = Cy_Crypto_Core_Sha_Init(
                crypto_base, &((wc_Sha*)sha)->hash_state, CY_CRYPTO_MODE_SHA1,
                &((wc_Sha*)sha)->sha_buffers);
            /* Initialize the hash state to the SHA1 initial values if requested
             * (init_hash set to 1) */
            if ((res == CY_CRYPTO_SUCCESS) && (init_hash == 1))
                res = Cy_Crypto_Core_Sha_Start(crypto_base,
                                               &((wc_Sha*)sha)->hash_state);
            break;
#endif
#if defined(PSOC6_HASH_SHA2)

#if !defined(NO_SHA256)
#if defined(WOLFSSL_SHA224)
        case WC_PSOC6_SHA224:
            res = Cy_Crypto_Core_Sha_Init(
                crypto_base, &((wc_Sha224*)sha)->hash_state,
                CY_CRYPTO_MODE_SHA224, &((wc_Sha224*)sha)->sha_buffers);
            if ((res == CY_CRYPTO_SUCCESS) && (init_hash == 1))
                res = Cy_Crypto_Core_Sha_Start(crypto_base,
                                               &((wc_Sha224*)sha)->hash_state);
            break;
#endif /* WOLFSSL_SHA224 */
        case WC_PSOC6_SHA256:
            res = Cy_Crypto_Core_Sha_Init(
                crypto_base, &((wc_Sha256*)sha)->hash_state,
                CY_CRYPTO_MODE_SHA256, &((wc_Sha256*)sha)->sha_buffers);
            if ((res == CY_CRYPTO_SUCCESS) && (init_hash == 1))
                res = Cy_Crypto_Core_Sha_Start(crypto_base,
                                               &((wc_Sha256*)sha)->hash_state);
            break;
#endif /* !NO_SHA256 */

#if defined(WOLFSSL_SHA384)
        case WC_PSOC6_SHA384:
            res = Cy_Crypto_Core_Sha_Init(
                crypto_base, &((wc_Sha384*)sha)->hash_state,
                CY_CRYPTO_MODE_SHA384, &((wc_Sha384*)sha)->sha_buffers);
            if ((res == CY_CRYPTO_SUCCESS) && (init_hash == 1))
                res = Cy_Crypto_Core_Sha_Start(crypto_base,
                                               &((wc_Sha384*)sha)->hash_state);
            break;
#endif /* WOLFSSL_SHA384 */

#if defined(WOLFSSL_SHA512)
        case WC_PSOC6_SHA512:
            res = Cy_Crypto_Core_Sha_Init(
                crypto_base, &((wc_Sha512*)sha)->hash_state,
                CY_CRYPTO_MODE_SHA512, &((wc_Sha512*)sha)->sha_buffers);
            if ((res == CY_CRYPTO_SUCCESS) && (init_hash == 1))
                res = Cy_Crypto_Core_Sha_Start(crypto_base,
                                               &((wc_Sha512*)sha)->hash_state);
            break;
#if !defined(WOLFSSL_NOSHA512_224)

        case WC_PSOC6_SHA512_224:
            res = Cy_Crypto_Core_Sha_Init(
                crypto_base, &((wc_Sha512*)sha)->hash_state,
                CY_CRYPTO_MODE_SHA512_224, &((wc_Sha512*)sha)->sha_buffers);
            if ((res == CY_CRYPTO_SUCCESS) && (init_hash == 1))
                res = Cy_Crypto_Core_Sha_Start(crypto_base,
                                               &((wc_Sha512*)sha)->hash_state);
            break;
#endif /* WOLFSSL_SHA512_224 */

#if !defined(WOLFSSL_NOSHA512_256)
        case WC_PSOC6_SHA512_256:
            res = Cy_Crypto_Core_Sha_Init(
                crypto_base, &((wc_Sha512*)sha)->hash_state,
                CY_CRYPTO_MODE_SHA512_256, &((wc_Sha512*)sha)->sha_buffers);
            if ((res == CY_CRYPTO_SUCCESS) && (init_hash == 1))
                res = Cy_Crypto_Core_Sha_Start(crypto_base,
                                               &((wc_Sha512*)sha)->hash_state);
            break;
#endif /* WOLFSSL_SHA512_256 */

#endif /* WOLFSSL_SHA512 */

#endif /* PSOC6_HASH_SHA2 */
        default:
            return BAD_FUNC_ARG;
    }

    return res;
}

/* Free resources and clear the register buffer for the PSoC6 hardware crypto
 * engine.
 *
 * No parameters.
 * No return value.
 */
void wc_Psoc6_Sha_Free(void)
{
    /* Clear the register buffer */
    Cy_Crypto_Core_V2_RBClear(crypto_base);

    /* Wait until the instruction is complete */
    Cy_Crypto_Core_V2_Sync(crypto_base);
}

/* SHA */
#if !defined(NO_SHA) && defined(PSOC6_HASH_SHA1)

int wc_InitSha_ex(wc_Sha* sha, void* heap, int devid)
{
    int ret;
    if (sha == NULL)
        return BAD_FUNC_ARG;

    (void)heap;
    XMEMSET(sha, 0, sizeof(wc_Sha));
    /* Lock the mutex to perform crypto operations */
    ret = wolfSSL_CryptHwMutexLock();
    if (ret == 0) {
        /* Initialize the PSoC6 hash buffers for SHA1 */
        ret = wc_Psoc6_Sha1_Sha2_Init(sha, WC_PSOC6_SHA1, 1);
        /* Release the lock */
        wolfSSL_CryptHwMutexUnLock();
    }
    return ret;
}

int wc_ShaUpdate(wc_Sha* sha, const byte* in, word32 sz)
{
    int ret;
    if (sha == NULL || (in == NULL && sz > 0)) {
        return BAD_FUNC_ARG;
    }

    if (in == NULL && sz == 0) {
        /* valid, but do nothing */
        return 0;
    }

    /* Lock the mutex to perform crypto operations */
    ret = wolfSSL_CryptHwMutexLock();
    if (ret == 0) {
        /* Perform the SHA calculation input data */
        ret = Cy_Crypto_Core_Sha_Update(crypto_base, &sha->hash_state, in, sz);
        /* Release the lock */
        wolfSSL_CryptHwMutexUnLock();
    }
    return ret;
}

int wc_ShaFinal(wc_Sha* sha, byte* hash)
{
    int ret;

    if (sha == NULL || hash == NULL)
        return BAD_FUNC_ARG;

    /* Lock the mutex to perform crypto operations */
    ret = wolfSSL_CryptHwMutexLock();
    if (ret == 0) {
        /* Complete the SHA calculation */
        ret =
            (int)Cy_Crypto_Core_Sha_Finish(crypto_base, &sha->hash_state, hash);
        /* Release the lock */
        wolfSSL_CryptHwMutexUnLock();
    }

    if (ret != 0)
        return ret;

    /* Reset state */
    return wc_InitSha(sha);
}

#endif /* !NO_SHA && PSOC6_HASH_SHA1 */

/* SHA2 */
#if defined(PSOC6_HASH_SHA2)

/* Sha-256 */
#if !defined(NO_SHA256)

int wc_InitSha256_ex(wc_Sha256* sha, void* heap, int devid)
{
    int ret;
    if (sha == NULL)
        return BAD_FUNC_ARG;

    (void)heap;
    (void)devid;
    XMEMSET(sha, 0, sizeof(wc_Sha256));
    /* Lock the mutex to perform crypto operations */
    ret = wolfSSL_CryptHwMutexLock();
    if (ret == 0) {
        /* Initialize the PSoC6 hash buffers for SHA256 */
        ret = wc_Psoc6_Sha1_Sha2_Init(sha, WC_PSOC6_SHA256, 1);
        /* Release the lock */
        wolfSSL_CryptHwMutexUnLock();
    }
    return ret;
}

int wc_Sha256Update(wc_Sha256* sha, const byte* in, word32 sz)
{
    int ret;
    if (sha == NULL || (in == NULL && sz > 0)) {
        return BAD_FUNC_ARG;
    }

    if (in == NULL && sz == 0) {
        /* valid, but do nothing */
        return 0;
    }

    /* Lock the mutex to perform crypto operations */
    ret = wolfSSL_CryptHwMutexLock();
    if (ret == 0) {
        /* Perform the SHA calculation input data */
        ret = Cy_Crypto_Core_Sha_Update(crypto_base, &sha->hash_state, in, sz);
        /* Release the lock */
        wolfSSL_CryptHwMutexUnLock();
    }

    return ret;
}

int wc_Sha256Final(wc_Sha256* sha, byte* hash)
{
    int ret;
    if (sha == NULL || hash == NULL)
        return BAD_FUNC_ARG;

    /* Lock the mutex to perform crypto operations */
    ret = wolfSSL_CryptHwMutexLock();
    if (ret == 0) {
        /* Complete the SHA calculation */
        ret =
            (int)Cy_Crypto_Core_Sha_Finish(crypto_base, &sha->hash_state, hash);
        /* Release the lock */
        wolfSSL_CryptHwMutexUnLock();
    }

    if (ret != 0)
        return ret;

    /* Reset state */
    return wc_InitSha256(sha);
}

/* Sha-224 */
#if defined(WOLFSSL_SHA224)

int wc_InitSha224_ex(wc_Sha224* sha, void* heap, int devid)
{
    int ret;
    if (sha == NULL)
        return BAD_FUNC_ARG;

    (void)heap;
    (void)devid;
    XMEMSET(sha, 0, sizeof(wc_Sha224));
    /* Lock the mutex to perform crypto operations */
    ret = wolfSSL_CryptHwMutexLock();
    if (ret == 0) {
        /* Initialize the PSoC6 hash buffers for SHA224 */
        ret = wc_Psoc6_Sha1_Sha2_Init(sha, WC_PSOC6_SHA224, 1);
        /* Release the lock */
        wolfSSL_CryptHwMutexUnLock();
    }
    return ret;
}

int wc_Sha224Update(wc_Sha224* sha, const byte* in, word32 sz)
{
    int ret;
    if (sha == NULL || (in == NULL && sz > 0)) {
        return BAD_FUNC_ARG;
    }

    if (in == NULL && sz == 0) {
        /* valid, but do nothing */
        return 0;
    }

    /* Lock the mutex to perform crypto operations */
    ret = wolfSSL_CryptHwMutexLock();
    if (ret == 0) {
        /* Perform the SHA calculation input data */
        ret = Cy_Crypto_Core_Sha_Update(crypto_base, &sha->hash_state, in, sz);
        /* Release the lock */
        wolfSSL_CryptHwMutexUnLock();
    }

    return ret;
}

int wc_Sha224Final(wc_Sha224* sha, byte* hash)
{
    int ret;
    if (sha == NULL || hash == NULL)
        return BAD_FUNC_ARG;

    /* Lock the mutex to perform crypto operations */
    ret = wolfSSL_CryptHwMutexLock();
    if (ret == 0) {
        /* Complete the SHA calculation */
        ret =
            (int)Cy_Crypto_Core_Sha_Finish(crypto_base, &sha->hash_state, hash);
        /* Release the lock */
        wolfSSL_CryptHwMutexUnLock();
    }

    if (ret != 0)
        return ret;

    /* Reset state */
    return wc_InitSha224(sha);
}

#endif /* #if !NO_SHA224 */
#endif /* #if !NO_SHA256 */

/* SHA-384 */
#if defined(WOLFSSL_SHA384)

int wc_InitSha384_ex(wc_Sha384* sha, void* heap, int devid)
{
    int ret;
    if (sha == NULL)
        return BAD_FUNC_ARG;

    (void)heap;
    (void)devid;
    XMEMSET(sha, 0, sizeof(wc_Sha384));
    /* Lock the mutex to perform crypto operations */
    ret = wolfSSL_CryptHwMutexLock();
    if (ret == 0) {
        /* Initialize the PSoC6 hash buffers for SHA384 */
        ret = wc_Psoc6_Sha1_Sha2_Init(sha, WC_PSOC6_SHA384, 1);
        /* Release the lock */
        wolfSSL_CryptHwMutexUnLock();
    }
    return ret;
}

int wc_Sha384Update(wc_Sha384* sha, const byte* in, word32 sz)
{
    int ret;
    if (sha == NULL || (in == NULL && sz > 0)) {
        return BAD_FUNC_ARG;
    }

    if (in == NULL && sz == 0) {
        /* valid, but do nothing */
        return 0;
    }

    /* Lock the mutex to perform crypto operations */
    ret = wolfSSL_CryptHwMutexLock();
    if (ret == 0) {
        /* Perform the SHA calculation input data */
        ret = Cy_Crypto_Core_Sha_Update(crypto_base, &sha->hash_state, in, sz);
        /* Release the lock */
        wolfSSL_CryptHwMutexUnLock();
    }
    return ret;
}

int wc_Sha384Final(wc_Sha384* sha, byte* hash)
{
    int ret;

    if (sha == NULL || hash == NULL)
        return BAD_FUNC_ARG;

    /* Lock the mutex to perform crypto operations */
    ret = wolfSSL_CryptHwMutexLock();
    if (ret == 0) {
        /* Complete the SHA calculation */
        ret =
            (int)Cy_Crypto_Core_Sha_Finish(crypto_base, &sha->hash_state, hash);
        /* Release the lock */
        wolfSSL_CryptHwMutexUnLock();
    }

    if (ret != 0)
        return ret;

    /* Reset state */
    return wc_InitSha384(sha);
}

#endif /* WOLFSSL_SHA384 */

/* Sha-512 */
#if defined(WOLFSSL_SHA512)

int wc_InitSha512_ex(wc_Sha512* sha, void* heap, int devid)
{
    int ret;
    (void)heap;
    (void)devid;
    XMEMSET(sha, 0, sizeof(wc_Sha512));
    /* Lock the mutex to perform crypto operations */
    ret = wolfSSL_CryptHwMutexLock();
    if (ret == 0) {
        /* Initialize the PSoC6 hash buffers for SHA512 */
        ret = wc_Psoc6_Sha1_Sha2_Init(sha, WC_PSOC6_SHA512, 1);
        /* Release the lock */
        wolfSSL_CryptHwMutexUnLock();
    }
    return ret;
}

int wc_Sha512Update(wc_Sha512* sha, const byte* in, word32 sz)
{
    int ret;
    if (sha == NULL || (in == NULL && sz > 0)) {
        return BAD_FUNC_ARG;
    }

    if (in == NULL && sz == 0) {
        /* valid, but do nothing */
        return 0;
    }

    /* Lock the mutex to perform crypto operations */
    ret = wolfSSL_CryptHwMutexLock();
    if (ret == 0) {
        /* Perform the SHA calculation input data */
        ret = Cy_Crypto_Core_Sha_Update(crypto_base, &sha->hash_state, in, sz);
        /* Release the lock */
        wolfSSL_CryptHwMutexUnLock();
    }
    return ret;
}

int wc_Sha512Final(wc_Sha512* sha, byte* hash)
{
    int ret;
    if (sha == NULL || hash == NULL)
        return BAD_FUNC_ARG;

    /* Lock the mutex to perform crypto operations */
    ret = wolfSSL_CryptHwMutexLock();
    if (ret == 0) {
        /* Complete the SHA calculation */
        ret =
            (int)Cy_Crypto_Core_Sha_Finish(crypto_base, &sha->hash_state, hash);
        /* Release the lock */
        wolfSSL_CryptHwMutexUnLock();
    }

    if (ret != 0)
        return ret;

    /* Reset state */
    return wc_InitSha512(sha);
}

/* SHA-512_224 */

#ifndef WOLFSSL_NOSHA512_224

int wc_InitSha512_224_ex(wc_Sha512* sha, void* heap, int devid)
{
    int ret;
    if (sha == NULL)
        return BAD_FUNC_ARG;

    (void)heap;
    (void)devid;
    XMEMSET(sha, 0, sizeof(wc_Sha512));
    /* Lock the mutex to perform crypto operations */
    ret = wolfSSL_CryptHwMutexLock();
    if (ret == 0) {
        /* Initialize the PSoC6 hash buffers for SHA512_224 */
        ret = wc_Psoc6_Sha1_Sha2_Init(sha, WC_PSOC6_SHA512_224, 1);
        /* Release the lock */
        wolfSSL_CryptHwMutexUnLock();
    }
    return ret;
}

int wc_Sha512_224Update(wc_Sha512* sha, const byte* in, word32 sz)
{
    return wc_Sha512Update(sha, in, sz);
}

int wc_Sha512_224Final(wc_Sha512* sha, byte* hash)
{
    int ret;

    if (sha == NULL || hash == NULL)
        return BAD_FUNC_ARG;

    /* Lock the mutex to perform crypto operations */
    ret = wolfSSL_CryptHwMutexLock();
    if (ret == 0) {
        /* Complete the SHA calculation */
        ret =
            (int)Cy_Crypto_Core_Sha_Finish(crypto_base, &sha->hash_state, hash);
        /* Release the lock */
        wolfSSL_CryptHwMutexUnLock();
    }

    /* Reset state */
    return wc_InitSha512_224(sha);
}

#endif /* !WOLFSSL_NOSHA512_224 */

/* SHA-512_256 */

#ifndef WOLFSSL_NOSHA512_256

int wc_InitSha512_256_ex(wc_Sha512* sha, void* heap, int devid)
{
    int ret;
    if (sha == NULL)
        return BAD_FUNC_ARG;

    (void)heap;
    (void)devid;
    XMEMSET(sha, 0, sizeof(wc_Sha512));
    /* Lock the mutex to perform crypto operations */
    ret = wolfSSL_CryptHwMutexLock();
    if (ret == 0) {
        /* Initialize the PSoC6 hash buffers for SHA512_256 */
        ret = wc_Psoc6_Sha1_Sha2_Init(sha, WC_PSOC6_SHA512_256, 1);
        /* Release the lock */
        wolfSSL_CryptHwMutexUnLock();
    }
    return ret;
}

int wc_Sha512_256Update(wc_Sha512* sha, const byte* in, word32 sz)
{
    return wc_Sha512Update(sha, in, sz);
}

int wc_Sha512_256Final(wc_Sha512* sha, byte* hash)
{
    int ret;

    if (sha == NULL || hash == NULL)
        return BAD_FUNC_ARG;

    /* Lock the mutex to perform crypto operations */
    ret = wolfSSL_CryptHwMutexLock();
    if (ret == 0) {
        /* Complete the SHA calculation */
        ret =
            (int)Cy_Crypto_Core_Sha_Finish(crypto_base, &sha->hash_state, hash);
        /* Release the lock */
        wolfSSL_CryptHwMutexUnLock();
    }
    if (ret != 0)
        return ret;

    /* Reset state */
    return wc_InitSha512_256(sha);
}

#endif /* !WOLFSSL_NOSHA512_256 */
#endif /* WOLFSSL_SHA512 */
#endif /* PSOC6_HASH_SHA2 */

/* SHA3 */
#if defined(WOLFSSL_SHA3) && defined(PSOC6_HASH_SHA3)

/* Initialize the state for a SHA-3 hash operation using the PSoC6 hardware
 * crypto engine.
 *
 * sha3   wc_Sha3 object holding state.
 * returns 0 on success.
 */
int wc_Psoc6_Sha3_Init(void* sha3)
{
    wc_Sha3* sha3_ctx = (wc_Sha3*)sha3;

    /* Enable CRYPTO block if not enabled */
    if (!Cy_Crypto_Core_IsEnabled(crypto_base)) {
        Cy_Crypto_Core_Enable(crypto_base);
    }

    /* Clear the data in sha3 structure */
    Cy_Crypto_Core_MemSet(crypto_base, sha3, 0, sizeof(wc_Sha3));

    /* Initialise the hash pointer in hash_state structure */
    sha3_ctx->hash_state.hash =
        (uint8_t*)((cy_stc_crypto_v2_sha3_buffers_t*)&sha3_ctx->sha_buffers)
            ->hash;

    /* Set the SHA mode to SHA3 */
    sha3_ctx->hash_state.modeHw = (uint32_t)CY_CRYPTO_V2_SHA3_OPC;

    /* Initialize the hashsize to 0 */
    sha3_ctx->hash_state.hashSize = 0;

    /* Set the init_done flag to false. It will be updated in */
    /* Sha3Update once the mode and blockSize are updated */
    sha3_ctx->init_done = false;

    return 0;
}

/* Update the SHA-3 hash state with input data using the PSoC6 hardware crypto
 * engine.
 *
 * sha3   wc_Sha3 object holding state.
 * data   Input data buffer.
 * len    Length of input data.
 * p      SHA-3 parameter (block size/count).
 * returns 0 on success, BAD_FUNC_ARG or hardware error code on failure.
 */
int wc_Psoc6_Sha3_Update(void* sha3, const byte* data, word32 len, byte p)
{
    wc_Sha3* sha3_ctx = (wc_Sha3*)sha3;

    /* If the initialization is not done, set it up */
    if (!sha3_ctx->init_done) {
        /* Set the SHA mode, blockSize and digestSize (for applicable ones) */
        switch (p) {
            case WC_SHA3_128_COUNT:
                /* For SHAKE-128 Cy_Crypto_Core_Sha_Update requires mode to be
                 * valid (SHA3_224 fits) */
                sha3_ctx->hash_state.mode = CY_CRYPTO_MODE_SHA3_224;
                sha3_ctx->hash_state.blockSize =
                    WC_SHA3_128_COUNT * BITS_IN_BYTE;
                break;
            case WC_SHA3_224_COUNT:
                sha3_ctx->hash_state.mode       = CY_CRYPTO_MODE_SHA3_224;
                sha3_ctx->hash_state.blockSize  = CY_CRYPTO_SHA3_224_BLOCK_SIZE;
                sha3_ctx->hash_state.digestSize = CY_CRYPTO_SHA224_DIGEST_SIZE;
                break;
            case WC_SHA3_256_COUNT:
                sha3_ctx->hash_state.mode       = CY_CRYPTO_MODE_SHA3_256;
                sha3_ctx->hash_state.blockSize  = CY_CRYPTO_SHA3_256_BLOCK_SIZE;
                sha3_ctx->hash_state.digestSize = CY_CRYPTO_SHA256_DIGEST_SIZE;
                break;
            case WC_SHA3_384_COUNT:
                sha3_ctx->hash_state.mode       = CY_CRYPTO_MODE_SHA3_384;
                sha3_ctx->hash_state.blockSize  = CY_CRYPTO_SHA3_384_BLOCK_SIZE;
                sha3_ctx->hash_state.digestSize = CY_CRYPTO_SHA384_DIGEST_SIZE;
                break;
            case WC_SHA3_512_COUNT:
                sha3_ctx->hash_state.mode       = CY_CRYPTO_MODE_SHA3_512;
                sha3_ctx->hash_state.blockSize  = CY_CRYPTO_SHA3_512_BLOCK_SIZE;
                sha3_ctx->hash_state.digestSize = CY_CRYPTO_SHA512_DIGEST_SIZE;
                break;
            default:
                return BAD_FUNC_ARG;
        }

        /* Update the init_done flag */
        sha3_ctx->init_done = true;
    }

    /* Perform the SHA calculation input data */
    return Cy_Crypto_Core_Sha_Update(crypto_base, &sha3_ctx->hash_state, data,
                                     len);
}

/* Finalize the SHA-3 hash operation and produce the digest using the PSoC6
 * hardware crypto engine.
 *
 * sha3    wc_Sha3 object holding state.
 * padChar Padding character for SHA-3.
 * hash    Output buffer for hash result.
 * p       SHA-3 parameter (block size/count).
 * l       Output length.
 * returns 0 on success, BAD_FUNC_ARG or hardware error code on failure.
 */
int wc_Psoc6_Sha3_Final(void* sha3, byte padChar, byte* hash, byte p, word32 l)
{
    word32 rate = p * BITS_IN_BYTE;
    word32 offset;
    wc_Sha3* sha3_ctx = (wc_Sha3*)sha3;

    /* For KECCCAK256 specific padding */
#ifdef WOLFSSL_HASH_FLAGS
    if ((p == WC_SHA3_256_COUNT) && (sha3_ctx->flags & WC_HASH_SHA3_KECCAK256))
        padChar = 0x01;
#endif

    /* Apply padding */
    sha3_ctx->hash_state.hash[sha3_ctx->hash_state.blockIdx] ^= padChar;
    sha3_ctx->hash_state.hash[rate - 1] ^= 0x80;

    /* Clear the register buffer */
    Cy_Crypto_Core_V2_RBClear(crypto_base);

    /* Wait until the instruction is complete */
    Cy_Crypto_Core_V2_Sync(crypto_base);

    /* Start streaming data in sha3_ctx->sha_buffers.hash into LOAD_FIFO0 */
    Cy_Crypto_Core_V2_FFStart(crypto_base, CY_CRYPTO_V2_RB_FF_LOAD0,
                              sha3_ctx->sha_buffers.hash,
                              CY_CRYPTO_SHA3_STATE_SIZE);

    /* XOR data present in lower register buffer partition with data streamed
     * from LOAD0_FIF0 */
    Cy_Crypto_Core_V2_RBXor(crypto_base, 0U, PSOC6_CRYPTO_SHA3_RB_LOWER);

    /* Swap the data present in the two register buffer partitions
     * (swap(reg_buff[1023:0], reg_buff[2047:1024])) */
    Cy_Crypto_Core_V2_RBSwap(crypto_base);

    /* XOR data present in upper register buffer partition with data streamed
     * from LOAD0_FIF0 */
    Cy_Crypto_Core_V2_RBXor(crypto_base, 0U, PSOC6_CRYPTO_SHA3_RB_UPPER);

    /* Swap the data present in the two register buffer partitions. The recently
     * XOR'ed data will be now present in 2nd partition */
    Cy_Crypto_Core_V2_RBSwap(crypto_base);

    /* Wait until the instruction is complete */
    Cy_Crypto_Core_V2_Sync(crypto_base);

    /* Process full blocks and write output to hash buffer */
    for (offset = 0; l - offset >= rate; offset += rate) {
        /* Perform SHA3 on current state. */
        Cy_Crypto_Core_V2_Run(crypto_base, sha3_ctx->hash_state.modeHw);

        /* Wait until the instruction is complete */
        Cy_Crypto_Core_V2_Sync(crypto_base);

        /* If the rate is more than 128, then we have to copy the data in 2nd
         * partition of register buffer as well */
        if (rate > PSOC6_CRYPTO_SHA3_RB_LOWER) {
            /* Start streaming data in 1st partition of register buffer into
             * hash buffer */
            Cy_Crypto_Core_V2_FFStart(crypto_base, CY_CRYPTO_V2_RB_FF_STORE,
                                      hash + offset,
                                      PSOC6_CRYPTO_SHA3_RB_LOWER);

            /* Copy the data in register buffer lower partition into hash buffer
             */
            Cy_Crypto_Core_V2_RBStore(crypto_base, 0U,
                                      PSOC6_CRYPTO_SHA3_RB_LOWER);

            /* Wait until FF_STORE operation is completed */
            Cy_Crypto_Core_V2_FFStoreSync(crypto_base);

            /* Swap the data present in the two register buffer partitions
             * (swap(reg_buff[1023:0], reg_buff[2047:1024])) */
            Cy_Crypto_Core_V2_RBSwap(crypto_base);

            /* Wait until the instruction is complete */
            Cy_Crypto_Core_V2_Sync(crypto_base);

            /* Now the 1st partition have 2nd partition data, start streaming
             * remaining extra data in register buffer into hash buffer */
            Cy_Crypto_Core_V2_FFStart(crypto_base, CY_CRYPTO_V2_RB_FF_STORE,
                                      hash + offset +
                                          PSOC6_CRYPTO_SHA3_RB_LOWER,
                                      (rate - PSOC6_CRYPTO_SHA3_RB_LOWER));

            /* Copy the remaining data in register buffer lower partition into
             * hash buffer */
            Cy_Crypto_Core_V2_RBStore(crypto_base, 0U,
                                      (rate - PSOC6_CRYPTO_SHA3_RB_LOWER));

            /* Wait until FF_STORE operation is completed */
            Cy_Crypto_Core_V2_FFStoreSync(crypto_base);

            /* Swap back the register buffer partitions */
            Cy_Crypto_Core_V2_RBSwap(crypto_base);
        }
        else {
            /* Start streaming data in 1st partition of register buffer into
             * hash buffer */
            Cy_Crypto_Core_V2_FFStart(crypto_base, CY_CRYPTO_V2_RB_FF_STORE,
                                      hash + offset, rate);

            /* Copy the remaining data in register buffer lower partition into
             * hash buffer */
            Cy_Crypto_Core_V2_RBStore(crypto_base, 0U, rate);

            /* Wait until FF_STORE operation is completed */
            Cy_Crypto_Core_V2_FFStoreSync(crypto_base);
        }
    }

    /* If more data need to be processed */
    if (offset != l) {
        /* Perform SHA3 on current state. */
        Cy_Crypto_Core_V2_Run(crypto_base, sha3_ctx->hash_state.modeHw);

        /* Wait until the instruction is complete */
        Cy_Crypto_Core_V2_Sync(crypto_base);

        /* If amount of data to be copied is more than length of register buffer
         * partition (128), */
        /* then we have to copy the data in 2nd partition of register buffer as
         * well */
        if ((l - offset) > PSOC6_CRYPTO_SHA3_RB_LOWER) {
            /* Start streaming data in 1st partition of register buffer into
             * hash buffer */
            Cy_Crypto_Core_V2_FFStart(crypto_base, CY_CRYPTO_V2_RB_FF_STORE,
                                      hash + offset,
                                      PSOC6_CRYPTO_SHA3_RB_LOWER);

            /* Copy the data in register buffer lower partition into hash buffer
             */
            Cy_Crypto_Core_V2_RBStore(crypto_base, 0U,
                                      PSOC6_CRYPTO_SHA3_RB_LOWER);

            /* Wait until FF_STORE operation is completed */
            Cy_Crypto_Core_V2_FFStoreSync(crypto_base);

            /* Swap the data present in the two register buffer partitions
             * (swap(reg_buff[1023:0], reg_buff[2047:1024])) */
            Cy_Crypto_Core_V2_RBSwap(crypto_base);

            /* Wait until the instruction is complete */
            Cy_Crypto_Core_V2_Sync(crypto_base);

            /* Now the 1st partition have 2nd partition data, start streaming
             * remaining extra data in register buffer into hash buffer */
            Cy_Crypto_Core_V2_FFStart(
                crypto_base, CY_CRYPTO_V2_RB_FF_STORE,
                hash + offset + PSOC6_CRYPTO_SHA3_RB_LOWER,
                ((l - offset) - PSOC6_CRYPTO_SHA3_RB_LOWER));

            /* Copy the remaining data in register buffer lower partition into
             * hash buffer */
            Cy_Crypto_Core_V2_RBStore(
                crypto_base, 0U, ((l - offset) - PSOC6_CRYPTO_SHA3_RB_LOWER));

            /* Wait until FF_STORE operation is completed */
            Cy_Crypto_Core_V2_FFStoreSync(crypto_base);
        }
        else {
            /* Start streaming data in 1st partition of register buffer into
             * hash buffer */
            Cy_Crypto_Core_V2_FFStart(crypto_base, CY_CRYPTO_V2_RB_FF_STORE,
                                      hash + offset, l - offset);

            /* Copy the data in register buffer lower partition into hash buffer
             */
            Cy_Crypto_Core_V2_RBStore(crypto_base, 0U, l - offset);

            /* Wait until FF_STORE operation is completed */
            Cy_Crypto_Core_V2_FFStoreSync(crypto_base);
        }
    }

    return 0;
}

#if defined(WOLFSSL_SHAKE128) || defined(WOLFSSL_SHAKE256)

/* Squeeze output blocks from a SHAKE state using the PSoC6 hardware crypto
 * engine.
 *
 * shake    wc_Shake object holding state.
 * out      Output buffer for squeezed blocks.
 * blockCnt Number of blocks to squeeze.
 * returns 0 on success, BAD_FUNC_ARG or hardware error code on failure.
 */
int wc_Psoc6_Shake_SqueezeBlocks(void* shake, byte* out, word32 blockCnt)
{
    wc_Shake* shake_ctx = (wc_Shake*)shake;

    for (; (blockCnt > 0); blockCnt--) {
        /* Perform SHA3 on the current state */
        Cy_Crypto_Core_V2_Run(crypto_base, shake_ctx->hash_state.modeHw);

        /* Wait until the instruction is complete */
        Cy_Crypto_Core_V2_Sync(crypto_base);

        /* Start streaming data in 1st partition of register buffer into hash
         * buffer */
        Cy_Crypto_Core_V2_FFStart(crypto_base, CY_CRYPTO_V2_RB_FF_STORE, out,
                                  PSOC6_CRYPTO_SHA3_RB_LOWER);

        /* Copy the data in register buffer lower partition into hash buffer */
        Cy_Crypto_Core_V2_RBStore(crypto_base, 0U, PSOC6_CRYPTO_SHA3_RB_LOWER);

        /* Wait until FF_STORE operation is completed */
        Cy_Crypto_Core_V2_FFStoreSync(crypto_base);

        /* Swap the data present in the two register buffer partitions
         * (swap(reg_buff[1023:0], reg_buff[2047:1024])) */
        Cy_Crypto_Core_V2_RBSwap(crypto_base);

        /* Wait until the instruction is complete */
        Cy_Crypto_Core_V2_Sync(crypto_base);

        /* Now the 1st partition have 2nd partition data, start streaming
         * remaining extra data in register buffer into hash buffer */
        Cy_Crypto_Core_V2_FFStart(crypto_base, CY_CRYPTO_V2_RB_FF_STORE,
                                  out + PSOC6_CRYPTO_SHA3_RB_LOWER,
                                  shake_ctx->hash_state.blockSize -
                                      PSOC6_CRYPTO_SHA3_RB_LOWER);

        /* Copy the remaining data in register buffer lower partition into hash
         * buffer */
        Cy_Crypto_Core_V2_RBStore(crypto_base, 0U,
                                  shake_ctx->hash_state.blockSize -
                                      PSOC6_CRYPTO_SHA3_RB_LOWER);

        /* Wait until FF_STORE operation is completed */
        Cy_Crypto_Core_V2_FFStoreSync(crypto_base);

        /* Swap back the register buffer partitions */
        Cy_Crypto_Core_V2_RBSwap(crypto_base);

        /* Move to the next block */
        out += shake_ctx->hash_state.blockSize;
    }

    return 0;
}

#endif /* WOLFSSL_SHAKE128 || WOLFSSL_SHAKE256 */

#endif /* WOLFSSL_SHA3 && PSOC6_HASH_SHA3 */

/* ECDSA */
#ifdef HAVE_ECC

#define MAX_ECC_KEYSIZE 66 /* Supports up to secp521r1 */
static cy_en_crypto_ecc_curve_id_t psoc6_get_curve_id(int size)
{
    switch (size) {
        case 24:
            return CY_CRYPTO_ECC_ECP_SECP192R1;
        case 28:
            return CY_CRYPTO_ECC_ECP_SECP224R1;
        case 32:
            return CY_CRYPTO_ECC_ECP_SECP256R1;
        case 48:
            return CY_CRYPTO_ECC_ECP_SECP384R1;
        case 66:
            return CY_CRYPTO_ECC_ECP_SECP521R1;
        default:
            return CY_CRYPTO_ECC_ECP_NONE;
    }
}

int psoc6_ecc_verify_hash_ex(MATH_INT_T* r, MATH_INT_T* s, const byte* hash,
                             word32 hashlen, int* verif_res,
                             struct ecc_key* key)
{
    uint8_t signature_buf[MAX_ECC_KEYSIZE * 2] = { 0 };
    cy_stc_crypto_ecc_key ecc_key;
    bool loadPublicKey = false;
    uint8_t stat       = 0;
    int res            = -1;
    int keySz;
    int rSz, sSz, qxSz, qySz;
    uint8_t x[MAX_ECC_KEYSIZE] = { 0 };
    uint8_t y[MAX_ECC_KEYSIZE] = { 0 };
    uint8_t k[MAX_ECC_KEYSIZE] = { 0 };

    if (!key || !verif_res || !r || !s || !hash)
        return -BAD_FUNC_ARG;

    /* Enable CRYPTO block if not enabled */
    if (!Cy_Crypto_Core_IsEnabled(crypto_base)) {
        Cy_Crypto_Core_Enable(crypto_base);
    }

    keySz = wc_ecc_size(key);
    rSz   = mp_unsigned_bin_size(r);
    sSz   = mp_unsigned_bin_size(s);

    if (keySz > MAX_ECC_KEYSIZE)
        return -BAD_FUNC_ARG;

    /* Prepare ECC key */
    ecc_key.type     = PK_PUBLIC;
    ecc_key.curveID  = psoc6_get_curve_id(keySz);
    ecc_key.k        = NULL;
    ecc_key.pubkey.x = x;
    ecc_key.pubkey.y = y;

    /* If the key is private only, generate the public key before */
    if (key->type == ECC_PRIVATEKEY_ONLY) {
        /* Get the private key as bytes */
        res = mp_to_unsigned_bin(ecc_get_k(key), k);
        if (res == MP_OKAY) {
            /* Convert the private key into little endian */
            Cy_Crypto_Core_InvertEndianness(k, keySz);

            /* Make the public key from the private key */
            res = Cy_Crypto_Core_ECC_MakePublicKey(crypto_base, ecc_key.curveID,
                                                   k, &ecc_key);

            /* Load the public key into the key structure. */
            if (res == CY_RSLT_SUCCESS) {
                loadPublicKey = true;
            }
        }

        if (res != CY_RSLT_SUCCESS) {
            return WC_FAILURE;
        }
    }
    else {
        qxSz = mp_unsigned_bin_size(key->pubkey.x);
        qySz = mp_unsigned_bin_size(key->pubkey.y);

        res = mp_to_unsigned_bin(key->pubkey.x, x);
        if (res == MP_OKAY) {
            res = mp_to_unsigned_bin(key->pubkey.y, y);
            if (res == MP_OKAY) {
                Cy_Crypto_Core_InvertEndianness(x, qxSz);
                Cy_Crypto_Core_InvertEndianness(y, qySz);
            }
        }
    }

    /* Note: keySz is used for the offset of the s component in signature_buf
     * because the hardware expects r and s to be packed as [r (keySz bytes)][s
     * (keySz bytes)]. However, rSz and sSz are used for endianness conversion
     * since they represent the actual sizes of the r and s values as produced
     * by mp_to_unsigned_bin.
     */
    if (res == MP_OKAY) {
        /* Copy r component */
        res = mp_to_unsigned_bin(r, signature_buf);
        if (res == MP_OKAY) {
            /* Copy s component. */
            res = mp_to_unsigned_bin(s, signature_buf + keySz);
            if (res == MP_OKAY) {
                /* Convert to little endian */
                Cy_Crypto_Core_InvertEndianness(signature_buf, rSz);
                Cy_Crypto_Core_InvertEndianness(signature_buf + keySz, sSz);
            }
        }
    }

    /* perform HW ECDSA */
    if (res == MP_OKAY) {
        res = Cy_Crypto_Core_ECC_VerifyHash(crypto_base, signature_buf, hash,
                                            hashlen, &stat, &ecc_key);
        if (res == CY_RSLT_SUCCESS) {
            *verif_res = stat;

            if (loadPublicKey == true) {
                Cy_Crypto_Core_InvertEndianness(ecc_key.pubkey.x, keySz);
                Cy_Crypto_Core_InvertEndianness(ecc_key.pubkey.y, keySz);
                res = mp_read_unsigned_bin(key->pubkey.x, ecc_key.pubkey.x,
                                           keySz);
                if (res == MP_OKAY) {
                    res = mp_read_unsigned_bin(key->pubkey.y, ecc_key.pubkey.y,
                                               keySz);
                }

                if (res == MP_OKAY) {
                    key->type = ECC_PRIVATEKEY;
                }
            }
        }
        else {
            res = WC_FAILURE;
        }
        return res;
    }

    return WC_FAILURE;
}
#endif /* HAVE_ECC */

#endif /* defined(WOLFSSL_PSOC6_CRYPTO) */
