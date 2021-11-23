/* se050_port.h
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
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

#ifndef _SE050_PORT_H_
#define _SE050_PORT_H_

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/visibility.h>
#include <wolfssl/wolfcrypt/asn_public.h>

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wundef"
#pragma GCC diagnostic ignored "-Wredundant-decls"
#endif

#include "fsl_sss_se05x_types.h"
#include "fsl_sss_se05x_apis.h"

#if (SSS_HAVE_SSS > 1)
#include "fsl_sss_api.h"
#endif

#ifdef WOLFSSL_SE050
    /* NXP SE050 - Disable SHA512 224/256 support */
    #ifndef WOLFSSL_NOSHA512_224
    #define WOLFSSL_NOSHA512_224
    #endif
    #ifndef WOLFSSL_NOSHA512_256
    #define WOLFSSL_NOSHA512_256
    #endif
#endif

#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif


/* Default key ID's */
#ifndef SE050_KEYSTOREID_AES
#define SE050_KEYSTOREID_AES     55
#endif
#ifndef SE050_KEYSTOREID_ED25519
#define SE050_KEYSTOREID_ED25519 58
#endif
#ifndef SE050_KEYSTOREID_ECC
#define SE050_KEYSTOREID_ECC     60
#endif
#ifndef SE050_KEYSTOREID_CURVE25519
#define SE050_KEYSTOREID_CURVE25519 59
#endif

enum {
    SSS_BLOCK_SIZE = 512,

    SSS_MAX_ECC_BITS = 521
};

enum SE050KeyType {
    SE050_ANY_KEY,
    SE050_AES_KEY,
    SE050_ECC_KEY,
    SE050_ED25519_KEY,
    SE050_CURVE25519_KEY
};


typedef struct {
    void*  heap;
    byte*  msg;
    word32 used;
    word32 len;
} SE050_HASH_Context;

/* Public Functions */
WOLFSSL_API int wc_se050_set_config(sss_session_t *pSession,
    sss_key_store_t *pHostKeyStore, sss_key_store_t *pKeyStore);
#ifdef WOLFSSL_SE050_INIT
WOLFSSL_API int wc_se050_init(const char* portName);
#endif

/* Private Functions */
WOLFSSL_LOCAL int se050_allocate_key(int keyType);
WOLFSSL_LOCAL int se050_get_random_number(uint32_t count, uint8_t* rand_out);

WOLFSSL_LOCAL int se050_hash_init(SE050_HASH_Context* se050Ctx, void* heap);
WOLFSSL_LOCAL int se050_hash_update(SE050_HASH_Context* se050Ctx,
    const byte* data, word32 len);
WOLFSSL_LOCAL int se050_hash_final(SE050_HASH_Context* se050Ctx, byte* hash,
    size_t digestLen, word32 algo);
WOLFSSL_LOCAL void se050_hash_free(SE050_HASH_Context* se050Ctx);

struct Aes;
WOLFSSL_LOCAL int se050_aes_set_key(struct Aes* aes, const byte* key,
    word32 len, const byte* iv, int dir);
WOLFSSL_LOCAL int se050_aes_crypt(struct Aes* aes, const byte* in, byte* out,
    word32 sz, int dir, sss_algorithm_t algorithm);
WOLFSSL_LOCAL void se050_aes_free(struct Aes* aes);


struct ecc_key;
struct WC_RNG;
#ifdef WOLFSSL_SP_MATH
    struct sp_int;
    #define MATH_INT_T struct sp_int
#elif defined(USE_FAST_MATH)
    struct fp_int;
    #define MATH_INT_T struct fp_int
#else
    struct mp_int;
	#define MATH_INT_T struct mp_int
#endif

WOLFSSL_LOCAL int se050_ecc_sign_hash_ex(const byte* in, word32 inLen,
    byte* out, word32 *outLen, struct ecc_key* key);

WOLFSSL_LOCAL int se050_ecc_verify_hash_ex(const byte* hash, word32 hashlen,
    byte* sigRS, word32 sigRSLen, struct ecc_key* key, int* res);

WOLFSSL_LOCAL int se050_ecc_create_key(struct ecc_key* key, int curve_id, int keySize);
WOLFSSL_LOCAL int se050_ecc_shared_secret(struct ecc_key* private_key,
    struct ecc_key* public_key, byte* out, word32* outlen);
WOLFSSL_LOCAL void se050_ecc_free_key(struct ecc_key* key);

struct ed25519_key;
WOLFSSL_LOCAL int se050_ed25519_create_key(struct ed25519_key* key);
WOLFSSL_LOCAL void se050_ed25519_free_key(struct ed25519_key* key);
WOLFSSL_LOCAL int se050_ed25519_sign_msg(const byte* in, word32 inLen,
    byte* out, word32 *outLen, struct ed25519_key* key);

WOLFSSL_LOCAL int se050_ed25519_verify_msg(const byte* signature,
    word32 signatureLen, const byte* msg, word32 msgLen,
    struct ed25519_key* key, int* res);

struct curve25519_key;
struct ECPoint;
WOLFSSL_LOCAL int se050_curve25519_create_key(struct curve25519_key* key, int keySize);
WOLFSSL_LOCAL int se050_curve25519_shared_secret(struct curve25519_key* private_key,
    struct curve25519_key* public_key, struct ECPoint* out);
WOLFSSL_LOCAL void se050_curve25519_free_key(struct curve25519_key* key);
#endif /* _SE050_PORT_H_ */
