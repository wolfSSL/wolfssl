/* se050_port.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <stdint.h>

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_SE050

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/logging.h>

#include <wolfssl/wolfcrypt/port/nxp/se050_port.h>

#ifdef WOLFSSL_SE050_INIT
    #ifndef SE050_DEFAULT_PORT
    #define SE050_DEFAULT_PORT "/dev/i2c-1"
    #endif

    #include "ex_sss_boot.h"
#endif

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
struct ecc_key;
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn_public.h>

#ifndef SE050_ECC_DER_MAX
#define SE050_ECC_DER_MAX 256
#endif

/* Global variables */
static sss_session_t *cfg_se050_i2c_pi;
static sss_key_store_t *hostKeyStore;
static sss_key_store_t *keyStore;

int wc_se050_set_config(sss_session_t *pSession, sss_key_store_t *pHostKeyStore,
    sss_key_store_t *pKeyStore)
{
    WOLFSSL_MSG("Setting SE050 session configuration");

    cfg_se050_i2c_pi = pSession;
    hostKeyStore = pHostKeyStore;
    keyStore = pKeyStore;

    return 0;
}

#ifdef WOLFSSL_SE050_INIT
int wc_se050_init(const char* portName)
{
    int ret;
    sss_status_t status;
    static ex_sss_boot_ctx_t pCtx;

    if (portName == NULL) {
        portName = SE050_DEFAULT_PORT;
    }

    status = ex_sss_boot_open(&pCtx, portName);
    if (status == kStatus_SSS_Success) {
        ret = wc_se050_set_config(&pCtx.session,
        #if SSS_HAVE_HOSTCRYPTO_ANY
            &pCtx.host_ks,
        #else
            NULL,
        #endif
            &pCtx.ks);
    }
    else {
        ret = WC_HW_E;
    }
    return ret;
}
#endif

int se050_allocate_key(int keyType)
{
    int keyId = 0;
    static int keyId_allocator = 100;
    switch (keyType) {
        case SE050_AES_KEY:
        case SE050_ECC_KEY:
        case SE050_ED25519_KEY:
        case SE050_ANY_KEY:
            keyId = keyId_allocator++;
            break;
    }
    return keyId;
}

#ifndef WC_NO_RNG
int se050_get_random_number(uint32_t count, uint8_t* rand_out)
{
    int ret = 0;
    sss_status_t status;
    sss_rng_context_t rng;

    if (cfg_se050_i2c_pi == NULL) {
        return WC_HW_E;
    }

    if (wolfSSL_CryptHwMutexLock() != 0) {
        return BAD_MUTEX_E;
    }
    status = sss_rng_context_init(&rng, cfg_se050_i2c_pi);
    if (status == kStatus_SSS_Success) {
        status = sss_rng_get_random(&rng, rand_out, count);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_rng_context_free(&rng);
    }
    if (status != kStatus_SSS_Success) {
        ret = RNG_FAILURE_E;
    }

    wolfSSL_CryptHwMutexUnLock();

    return ret;
}
#endif /* !WC_NO_RNG */

/* Used for sha/sha224/sha384/sha512 */
int se050_hash_init(SE050_HASH_Context* se050Ctx, void* heap)
{
    se050Ctx->heap = heap;
    se050Ctx->len  = 0;
    se050Ctx->used = 0;
    se050Ctx->msg  = NULL;
    return 0;
}

int se050_hash_update(SE050_HASH_Context* se050Ctx, const byte* data, word32 len)
{
    if (se050Ctx == NULL || (len > 0 && data == NULL)) {
        return BAD_FUNC_ARG;
    }

    if (se050Ctx->len < se050Ctx->used + len) {
        if (se050Ctx->msg == NULL) {
            se050Ctx->msg = (byte*)XMALLOC(se050Ctx->used + len,
                se050Ctx->heap, DYNAMIC_TYPE_TMP_BUFFER);
        }
        else {
            se050Ctx->msg = (byte*)XREALLOC(se050Ctx->msg, se050Ctx->used + len,
                se050Ctx->heap, DYNAMIC_TYPE_TMP_BUFFER);
        }
        if (se050Ctx->msg == NULL) {
            return MEMORY_E;
        }
        se050Ctx->len = se050Ctx->used + len;
    }

    XMEMCPY(se050Ctx->msg + se050Ctx->used, data , len);
    se050Ctx->used += len;

    return 0;
}

int se050_hash_final(SE050_HASH_Context* se050Ctx, byte* hash, size_t digestLen,
    sss_algorithm_t algo)
{
    int          ret;
    sss_status_t status;
    sss_digest_t digest_ctx;
    const byte*  data = se050Ctx->msg;
    int          size = (se050Ctx->len) / SSS_BLOCK_SIZE;
    int          leftover = (se050Ctx->len) % SSS_BLOCK_SIZE;
    const byte*  blocks = data;

    if (cfg_se050_i2c_pi == NULL) {
        return WC_HW_E;
    }

    if (wolfSSL_CryptHwMutexLock() != 0) {
        return BAD_MUTEX_E;
    }

    status = sss_digest_context_init(&digest_ctx, cfg_se050_i2c_pi, algo,
        kMode_SSS_Digest);
    if (status == kStatus_SSS_Success) {
        status = sss_digest_init(&digest_ctx);
    }
    if (status == kStatus_SSS_Success) {
        /* used to send chunks of size 512 */
        while (status == kStatus_SSS_Success && size--) {
            status = sss_digest_update(&digest_ctx, blocks, SSS_BLOCK_SIZE);
            blocks += SSS_BLOCK_SIZE;
        }
        if (status == kStatus_SSS_Success && leftover) {
            status = sss_digest_update(&digest_ctx, blocks, leftover);
        }
        if (status == kStatus_SSS_Success) {
            status = sss_digest_finish(&digest_ctx, hash, &digestLen);
        }
        sss_digest_context_free(&digest_ctx);
    }

    ret = (status == kStatus_SSS_Success) ? 0 : WC_HW_E;

    wolfSSL_CryptHwMutexUnLock();

    return ret;
}

void se050_hash_free(SE050_HASH_Context* se050Ctx)
{
    (void)se050Ctx;
}

#ifndef NO_AES
int se050_aes_set_key(Aes* aes, const byte* key, word32 keylen,
                                        const byte* iv, int dir)
{
    int ret = 0;
    sss_status_t status;
    sss_object_t newKey;
    sss_key_store_t host_keystore;
    int keyId;
    int keyCreated = 0;

    if (cfg_se050_i2c_pi == NULL) {
        return WC_HW_E;
    }

    if (wolfSSL_CryptHwMutexLock() != 0) {
        return BAD_MUTEX_E;
    }

    (void)dir;
    (void)iv;

    aes->rounds = keylen/4 + 6;

    status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_allocate(&host_keystore, SE050_KEYSTOREID_AES);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&newKey, &host_keystore);
    }
    if (status == kStatus_SSS_Success) {
        keyId = se050_allocate_key(SE050_AES_KEY);
        status = sss_key_object_allocate_handle(&newKey, keyId,
            kSSS_KeyPart_Default, kSSS_CipherType_AES, keylen,
            kKeyObject_Mode_Transient);
    }
    if (status == kStatus_SSS_Success) {
        keyCreated = 1;
        status = sss_key_store_set_key(&host_keystore, &newKey, key, keylen,
                                    keylen * 8, NULL, 0);
    }

    if (status == kStatus_SSS_Success) {
        aes->keyId = keyId;
        ret = 0;
    }
    else {
        if (keyCreated) {
            sss_key_object_free(&newKey);
        }
        ret = WC_HW_E;
    }

    wolfSSL_CryptHwMutexUnLock();

    return ret;
}

int se050_aes_crypt(Aes* aes, const byte* in, byte* out, word32 sz, int dir,
    sss_algorithm_t algorithm)
{
    int             ret = 0;
    sss_status_t    status;
    sss_object_t    keyObject;
    sss_key_store_t host_keystore;

    if (cfg_se050_i2c_pi == NULL) {
        return WC_HW_E;
    }
    if (aes->keyId <= 0) {
        return BAD_FUNC_ARG;
    }

    if (wolfSSL_CryptHwMutexLock() != 0) {
        return BAD_MUTEX_E;
    }

    status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_allocate(&host_keystore, SE050_KEYSTOREID_AES);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&keyObject, &host_keystore);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_get_handle(&keyObject, aes->keyId);
    }

    /* The first call to this function needs an initialization call,
        * subsequent calls just need to call update */
    if (status == kStatus_SSS_Success && aes->ctxInitDone == 0) {
        sss_mode_t      mode;

        XMEMSET(&mode, 0, sizeof(mode));
        if (dir == AES_DECRYPTION)
            mode = kMode_SSS_Decrypt;
        else if (dir == AES_ENCRYPTION)
            mode = kMode_SSS_Encrypt;

        if (status == kStatus_SSS_Success) {
            status = sss_symmetric_context_init(&aes->aes_ctx,
                cfg_se050_i2c_pi, &keyObject, algorithm, mode);
        }
        if (status == kStatus_SSS_Success) {
            aes->ctxInitDone = 1;
            status = sss_cipher_init(&aes->aes_ctx, (uint8_t*)aes->reg,
                sizeof(aes->reg));
        }
    }
    if (status == kStatus_SSS_Success) {
        size_t outSz = (size_t)sz;
        status = sss_cipher_update(&aes->aes_ctx, in, sz, out, &outSz);
    }

    ret = (status == kStatus_SSS_Success) ? 0 : WC_HW_E;

    wolfSSL_CryptHwMutexUnLock();

    return ret;
}

void se050_aes_free(Aes* aes)
{
    sss_status_t    status;
    sss_key_store_t host_keystore;
    sss_object_t    keyObject;

    if (cfg_se050_i2c_pi == NULL) {
        return;
    }
    if (aes->keyId <= 0) {
        return;
    }

    if (wolfSSL_CryptHwMutexLock() != 0) {
        return;
    }

    if (aes->ctxInitDone) {
        sss_symmetric_context_free(&aes->aes_ctx);

        /* sets back to zero to indicate that a free has been called */
        aes->ctxInitDone = 0;
    }

    status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_allocate(&host_keystore, SE050_KEYSTOREID_AES);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&keyObject, &host_keystore);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_get_handle(&keyObject, aes->keyId);
        aes->keyId = 0;
    }
    sss_key_object_free(&keyObject);

    wolfSSL_CryptHwMutexUnLock();
}

#endif /* !NO_AES */

#ifdef HAVE_ECC

static sss_cipher_type_t se050_map_curve(int curve_id)
{
    sss_cipher_type_t curve_type;
    switch (curve_id) {
        case ECC_SECP160K1:
        case ECC_SECP192K1:
        case ECC_SECP224K1:
        case ECC_SECP256K1:
            curve_type = kSSS_CipherType_EC_NIST_K;
            break;
        case ECC_BRAINPOOLP160R1:
        case ECC_BRAINPOOLP192R1:
        case ECC_BRAINPOOLP224R1:
        case ECC_BRAINPOOLP256R1:
        case ECC_BRAINPOOLP320R1:
        case ECC_BRAINPOOLP384R1:
        case ECC_BRAINPOOLP512R1:
            curve_type = kSSS_CipherType_EC_BRAINPOOL;
            break;
        case ECC_CURVE_DEF:
        case ECC_SECP160R1:
        case ECC_SECP192R1:
        case ECC_SECP224R1:
        case ECC_SECP256R1:
        case ECC_SECP384R1:
        case ECC_SECP521R1:
        default:
            curve_type = kSSS_CipherType_EC_NIST_P;
            break;
    }
    return curve_type;
}

int se050_ecc_sign_hash_ex(const byte* in, word32 inLen, byte* out,
                         word32 *outLen, struct ecc_key* key)
{
    int                 ret = 0;
    sss_status_t        status;
    sss_asymmetric_t    ctx_asymm;
    sss_key_store_t     host_keystore;
    sss_object_t        newKey;
    sss_algorithm_t     algorithm = kAlgorithm_None;
    int                 keySize;
    int                 keySizeBits;

    if (cfg_se050_i2c_pi == NULL) {
        return WC_HW_E;
    }
    if (key->keyId <= 0) {
        return BAD_FUNC_ARG;
    }

    if (wolfSSL_CryptHwMutexLock() != 0) {
        return BAD_MUTEX_E;
    }

    /* truncate if digest is larger than 64 */
    if (inLen > 64)
        inLen = 64;

    keySize = key->dp->size;
    keySizeBits = keySize * 8;
    if (keySizeBits > SSS_MAX_ECC_BITS)
        keySizeBits = SSS_MAX_ECC_BITS;

    if (inLen == 20)
        algorithm = kAlgorithm_SSS_SHA1;
    else if (inLen == 28)
        algorithm = kAlgorithm_SSS_SHA224;
    else if (inLen == 32)
        algorithm = kAlgorithm_SSS_SHA256;
    else if (inLen == 48)
        algorithm = kAlgorithm_SSS_SHA384;
    else if (inLen == 64)
        algorithm = kAlgorithm_SSS_SHA512;

    status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_allocate(&host_keystore, SE050_KEYSTOREID_ECC);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&newKey, &host_keystore);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_get_handle(&newKey, key->keyId);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_asymmetric_context_init(&ctx_asymm, cfg_se050_i2c_pi,
            &newKey, algorithm, kMode_SSS_Sign);
        if (status == kStatus_SSS_Success) {
            size_t outLenSz = (size_t)*outLen;
            status = sss_asymmetric_sign_digest(&ctx_asymm, (uint8_t *)in,
                inLen, out, &outLenSz);
            *outLen = (word32)outLenSz;
        }
        sss_asymmetric_context_free(&ctx_asymm);
    }

    if (status != kStatus_SSS_Success) {
        ret = WC_HW_E;
    }

    wolfSSL_CryptHwMutexUnLock();

    return ret;
}

int se050_ecc_verify_hash_ex(const byte* hash, word32 hashLen, byte* signature,
                             word32 signatureLen, struct ecc_key* key, int* res)
{
    int                 ret = 0;
    sss_status_t        status;
    sss_asymmetric_t    ctx_asymm;
    sss_object_t        newKey;
    sss_key_store_t     host_keystore;
    sss_algorithm_t     algorithm = kAlgorithm_None;
    int                 keySize;
    int                 keySizeBits;
    sss_cipher_type_t   curveType;
    int                 keyCreated = 0;

    *res = 0;

    if (cfg_se050_i2c_pi == NULL) {
        return WC_HW_E;
    }

    if (wolfSSL_CryptHwMutexLock() != 0) {
        return BAD_MUTEX_E;
    }

    if (hashLen > 64)
        hashLen = 64;

    if (hashLen == 20)
        algorithm = kAlgorithm_SSS_SHA1;
    else if (hashLen == 28)
        algorithm = kAlgorithm_SSS_SHA224;
    else if (hashLen == 32)
        algorithm = kAlgorithm_SSS_SHA256;
    else if (hashLen == 48)
        algorithm = kAlgorithm_SSS_SHA384;
    else if (hashLen == 64)
        algorithm = kAlgorithm_SSS_SHA512;

    keySize = key->dp->size;
    keySizeBits = keySize * 8;
    if (keySizeBits > SSS_MAX_ECC_BITS)
        keySizeBits = SSS_MAX_ECC_BITS;
    curveType = se050_map_curve(key->dp->id);

    status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_allocate(&host_keystore, SE050_KEYSTOREID_ECC);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&newKey, &host_keystore);
    }

    /* this is run when a key was not generated and was instead passed in */
    if (status == kStatus_SSS_Success) {
        if (key->keyId == 0) {
            byte derBuf[SE050_ECC_DER_MAX];
            word32 derSz;

            ret = wc_EccPublicKeyToDer(key, derBuf, (word32)sizeof(derBuf), 1);
            if (ret >= 0) {
                derSz = ret;
            }
            else {
                status = kStatus_SSS_Fail;
            }
            if (status == kStatus_SSS_Success) {
                key->keyId = se050_allocate_key(SE050_ECC_KEY);
                status = sss_key_object_allocate_handle(&newKey, key->keyId,
                    kSSS_KeyPart_Public, curveType, keySize,
                    kKeyObject_Mode_Transient);
            }
            if (status == kStatus_SSS_Success) {
                keyCreated = 1;
                status = sss_key_store_set_key(&host_keystore, &newKey, derBuf,
                                                derSz, keySizeBits, NULL, 0);
            }
        }
        else {
            status = sss_key_object_get_handle(&newKey, key->keyId);
        }
    }

    if (status == kStatus_SSS_Success) {
        status = sss_asymmetric_context_init(&ctx_asymm, cfg_se050_i2c_pi,
                                    &newKey, algorithm, kMode_SSS_Verify);
        if (status == kStatus_SSS_Success) {
            status = sss_asymmetric_verify_digest(&ctx_asymm, (uint8_t *)hash,
                                            hashLen, signature, signatureLen);
        }

        sss_asymmetric_context_free(&ctx_asymm);
    }

    if (status == kStatus_SSS_Success) {
        *res = 1;
        ret = 0;
    }
    else {
        if (keyCreated) {
            sss_key_object_free(&newKey);
            key->keyId = 0;
        }
        if (ret == 0)
            ret = WC_HW_E;
    }

    wolfSSL_CryptHwMutexUnLock();

    return ret;
}


void se050_ecc_free_key(struct ecc_key* key)
{
    sss_status_t    status = kStatus_SSS_Success;
    sss_object_t    keyObject;
    sss_key_store_t host_keystore;

    if (cfg_se050_i2c_pi == NULL) {
        return;
    }
    if (key->keyId <= 0) {
        return;
    }

    if (wolfSSL_CryptHwMutexLock() != 0) {
        return;
    }

    status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_allocate(&host_keystore, SE050_KEYSTOREID_ECC);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&keyObject, &host_keystore);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_get_handle(&keyObject, key->keyId);
    }
    if (status == kStatus_SSS_Success) {
        sss_key_object_free(&keyObject);
        key->keyId = 0;
    }
    wolfSSL_CryptHwMutexUnLock();
}

int se050_ecc_create_key(struct ecc_key* key, int curve_id, int keySize)
{
    int               ret = 0;
    sss_status_t      status = kStatus_SSS_Success;
    sss_object_t      keyPair;
    sss_key_store_t   host_keystore;
    uint8_t           derBuf[SE050_ECC_DER_MAX];
    size_t            derSz = sizeof(derBuf);
    size_t            derSzBits = derSz * 8;
    int               keyId;
    int               keySizeBits;
    sss_cipher_type_t curveType;
    int               keyCreated = 0;

    if (cfg_se050_i2c_pi == NULL) {
        return WC_HW_E;
    }

    if (wolfSSL_CryptHwMutexLock() != 0) {
        return BAD_MUTEX_E;
    }

    curveType = se050_map_curve(curve_id);
    keySizeBits = keySize * 8;
    if (keySizeBits > SSS_MAX_ECC_BITS)
        keySizeBits = SSS_MAX_ECC_BITS;

    status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_allocate(&host_keystore, SE050_KEYSTOREID_ECC);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&keyPair, &host_keystore);
    }
    if (status == kStatus_SSS_Success) {
        keyId = se050_allocate_key(SE050_ECC_KEY);
        status = sss_key_object_allocate_handle(&keyPair, keyId,
            kSSS_KeyPart_Pair, curveType, keySizeBits,
            kKeyObject_Mode_None);
    }
    if (status == kStatus_SSS_Success) {
        keyCreated = 1;
        status = sss_key_store_generate_key(&host_keystore, &keyPair,
            keySizeBits, NULL);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_get_key(&host_keystore, &keyPair,
            derBuf, &derSz, &derSzBits);
    }
    if (status == kStatus_SSS_Success) {
        word32 idx = 0;
        ret = wc_EccPublicKeyDecode(derBuf, &idx, key, (word32)derSz);
        if (ret != 0) {
            status = kStatus_SSS_Fail;
        }
    }
    if (status == kStatus_SSS_Success) {
        key->keyId = keyId;
        ret = 0;
    }
    else {
        if (keyCreated) {
            sss_key_object_free(&keyPair);
        }
        if (ret == 0)
            ret = WC_HW_E;
    }

    wolfSSL_CryptHwMutexUnLock();

    return ret;
}


int se050_ecc_shared_secret(ecc_key* private_key, ecc_key* public_key,
    byte* out, word32* outlen)
{
    int                 ret;
    sss_status_t        status = kStatus_SSS_Success;
    sss_key_store_t     host_keystore;
    sss_object_t        ref_private_key;
    sss_object_t        ref_public_key;
    sss_object_t        deriveKey;
    sss_derive_key_t    ctx_derive_key;
    int                 keyId;
    int                 keySize;
    size_t              keySizeBits;
    sss_cipher_type_t   curveType;
    int                 keyCreated = 0;
    int                 deriveKeyCreated = 0;

    if (cfg_se050_i2c_pi == NULL) {
        return WC_HW_E;
    }
    if (private_key->keyId <= 0) {
        return BAD_FUNC_ARG;
    }

    if (wolfSSL_CryptHwMutexLock() != 0) {
        return BAD_MUTEX_E;
    }

    keySize = private_key->dp->size;
    keySizeBits = keySize * 8;
    if (keySizeBits > SSS_MAX_ECC_BITS)
        keySizeBits = SSS_MAX_ECC_BITS;
    curveType = se050_map_curve(private_key->dp->id);

    status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_allocate(&host_keystore, SE050_KEYSTOREID_ECC);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&ref_public_key, &host_keystore);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&ref_private_key, &host_keystore);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_get_handle(&ref_private_key, private_key->keyId);
    }

    if (status == kStatus_SSS_Success) {
        if (public_key->keyId <= 0) {
            byte derBuf[256];
            word32 derSz;

            ret = wc_EccPublicKeyToDer(public_key, derBuf,
                (word32)sizeof(derBuf), 1);
            if (ret >= 0) {
                derSz = ret;
            }
            else {
                status = kStatus_SSS_Fail;
            }
            if (status == kStatus_SSS_Success) {
                keyId = se050_allocate_key(SE050_ECC_KEY);
                status = sss_key_object_allocate_handle(&ref_public_key,
                    keyId, kSSS_KeyPart_Public, curveType, keySize,
                    kKeyObject_Mode_Transient);
            }
            if (status == kStatus_SSS_Success) {
                keyCreated = 1;
                status = sss_key_store_set_key(&host_keystore, &ref_public_key,
                    derBuf, derSz, keySizeBits, NULL, 0);
            }
        }
        else {
            status = sss_key_object_get_handle(&ref_public_key,
                public_key->keyId);
        }
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&deriveKey, hostKeyStore);
    }
    if (status == kStatus_SSS_Success) {
        int keyIdAes = se050_allocate_key(SE050_AES_KEY);
        deriveKeyCreated = 1;
        status = sss_key_object_allocate_handle(&deriveKey,
            keyIdAes,
            kSSS_KeyPart_Default,
            kSSS_CipherType_AES,
            keySize,
            kKeyObject_Mode_Transient);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_derive_key_context_init(&ctx_derive_key, cfg_se050_i2c_pi,
                                    &ref_private_key, kAlgorithm_SSS_ECDH,
                                    kMode_SSS_ComputeSharedSecret);
        if (status == kStatus_SSS_Success) {
            status = sss_derive_key_dh(&ctx_derive_key, &ref_public_key,
                &deriveKey);
        }
        if (status == kStatus_SSS_Success) {
            size_t outlenSz = (size_t)*outlen;
            /* derived key export */
            status = sss_key_store_get_key(hostKeyStore, &deriveKey, out,
                &outlenSz, &keySizeBits);
            *outlen = (word32)outlenSz;
        }

        sss_derive_key_context_free(&ctx_derive_key);
    }
    if (deriveKeyCreated) {
        sss_key_object_free(&deriveKey);
    }

    if (status == kStatus_SSS_Success) {
        ret = 0;
    }
    else {
        if (keyCreated) {
            sss_key_object_free(&public_key);
            public_key->keyId = 0;
        }
        if (ret == 0)
            ret = WC_HW_E;
    }

    wolfSSL_CryptHwMutexUnLock();

    return ret;
}
#endif /* HAVE_ECC */

#ifdef HAVE_ED25519

int se050_ed25519_create_key(ed25519_key* key)
{
    int             ret = 0;
    sss_status_t    status;
    sss_key_store_t host_keystore;
    sss_object_t    newKey;
    int             keyId;
    int             keySize = ED25519_KEY_SIZE;
    int             keyCreated = 0;

    if (cfg_se050_i2c_pi == NULL) {
        return WC_HW_E;
    }

    if (wolfSSL_CryptHwMutexLock() != 0) {
        return BAD_MUTEX_E;
    }

    status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_allocate(&host_keystore, SE050_KEYSTOREID_ED25519);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&newKey, &host_keystore);
    }
    if (status == kStatus_SSS_Success) {
        keyId = se050_allocate_key(SE050_ED25519_KEY);
        status = sss_key_object_allocate_handle(&newKey, keyId,
            kSSS_KeyPart_Pair, kSSS_CipherType_EC_TWISTED_ED, keySize,
            kKeyObject_Mode_Transient);
    }
    if (status == kStatus_SSS_Success) {
        keyCreated = 1;
        status = sss_key_store_generate_key(&host_keystore, &newKey,
            keySize * 8, NULL);
    }

    if (status == kStatus_SSS_Success) {
        key->keyId = keyId;
        ret = 0;
    }
    else {
        if (keyCreated) {
            sss_key_object_free(&newKey);
        }
        ret = WC_HW_E;
    }

    wolfSSL_CryptHwMutexUnLock();

    return ret;
}

void se050_ed25519_free_key(ed25519_key* key)
{
    sss_status_t status;
    sss_object_t newKey;
    sss_key_store_t host_keystore;

    if (cfg_se050_i2c_pi == NULL) {
        return;
    }
    if (key->keyId <= 0) {
        return;
    }

    if (wolfSSL_CryptHwMutexLock() != 0) {
        return;
    }

    status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);

    if (status == kStatus_SSS_Success) {
        status = sss_key_store_allocate(&host_keystore, SE050_KEYSTOREID_ED25519);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&newKey, &host_keystore);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_get_handle(&newKey, key->keyId);
    }
    if (status == kStatus_SSS_Success) {
        sss_key_object_free(&newKey);
        key->keyId = 0;
    }
    wolfSSL_CryptHwMutexUnLock();
}

int se050_ed25519_sign_msg(const byte* in, word32 inLen, byte* out,
                         word32 *outLen, ed25519_key* key)
{
    int                 ret = 0;
    sss_status_t        status = kStatus_SSS_Success;
    sss_asymmetric_t    ctx_asymm;
    sss_key_store_t     host_keystore;
    sss_object_t        newKey;

    inLen = 64;
    *outLen = 64;

    if (cfg_se050_i2c_pi == NULL) {
        return WC_HW_E;
    }
    if (key->keyId <= 0) {
        return BAD_FUNC_ARG;
    }

    if (wolfSSL_CryptHwMutexLock() != 0) {
        return BAD_MUTEX_E;
    }

    status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_allocate(&host_keystore, SE050_KEYSTOREID_ED25519);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&newKey, &host_keystore);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_get_handle(&newKey, key->keyId);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_asymmetric_context_init(&ctx_asymm, cfg_se050_i2c_pi,
                            &newKey, kAlgorithm_SSS_SHA512, kMode_SSS_Sign);
        if (status == kStatus_SSS_Success) {
            size_t outlenSz = (size_t)*outLen;
            status = sss_se05x_asymmetric_sign((sss_se05x_asymmetric_t *)&ctx_asymm,
                                            (uint8_t *)in, inLen, out, &outlenSz);
            *outLen = (word32)outlenSz;
        }

        sss_asymmetric_context_free(&ctx_asymm);
    }

    if (status != kStatus_SSS_Success) {
        ret = WC_HW_E;
    }

    wolfSSL_CryptHwMutexUnLock();

    return ret;
}


int se050_ed25519_verify_msg(const byte* signature, word32 signatureLen,
    const byte* msg, word32 msgLen, struct ed25519_key* key, int* res)
{
    int                 ret = 0;
    sss_status_t        status = kStatus_SSS_Success;
    sss_asymmetric_t    ctx_asymm;
    sss_object_t        newKey;
    sss_key_store_t     host_keystore;
    int                 keyId;
    int                 keySize = ED25519_KEY_SIZE;
    int                 keyCreated = 0;

    if (cfg_se050_i2c_pi == NULL) {
        return WC_HW_E;
    }

    if (wolfSSL_CryptHwMutexLock() != 0) {
        return BAD_MUTEX_E;
    }

    status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);
    if (status == kStatus_SSS_Success) {
        status = sss_key_store_allocate(&host_keystore, SE050_KEYSTOREID_ED25519);
    }
    if (status == kStatus_SSS_Success) {
        status = sss_key_object_init(&newKey, &host_keystore);
    }
    if (status == kStatus_SSS_Success) {
        if (key->keyId == 0) {
            byte derBuf[48];
            word32 derSz = 0, idx = 0;

            ret = wc_Ed25519PublicKeyDecode(derBuf, &idx, key,
                (word32)sizeof(derBuf));
            if (ret >= 0) {
                derSz = ret;
            }
            else {
                status = kStatus_SSS_Fail;
            }
            if (status == kStatus_SSS_Success) {
                keyId = se050_allocate_key(SE050_ED25519_KEY);
                status = sss_key_object_allocate_handle(&newKey, keyId,
                    kSSS_KeyPart_Pair, kSSS_CipherType_EC_TWISTED_ED, keySize,
                    kKeyObject_Mode_Transient);
            }
            if (status == kStatus_SSS_Success) {
                keyCreated = 1;
                status = sss_key_store_set_key(&host_keystore, &newKey, derBuf,
                                                derSz, keySize * 8, NULL, 0);
            }
        }
        else {
            status = sss_key_object_get_handle(&newKey, key->keyId);
        }
    }

    if (status == kStatus_SSS_Success) {
        status = sss_asymmetric_context_init(&ctx_asymm, cfg_se050_i2c_pi,
                    &newKey, kAlgorithm_SSS_SHA512, kMode_SSS_Verify);
    }

    if (status == kStatus_SSS_Success) {
        status = sss_se05x_asymmetric_verify(
                (sss_se05x_asymmetric_t*)&ctx_asymm, (uint8_t*)msg, msgLen,
                (uint8_t*)signature, (size_t)signatureLen);
    }

    sss_asymmetric_context_free(&ctx_asymm);

    if (status == kStatus_SSS_Success) {
        key->keyId = keyId;
        *res = 1;
        ret = 0;
    }
    else {
        if (keyCreated) {
            sss_key_object_free(&newKey);
        }
        if (ret == 0)
            ret = WC_HW_E;
    }

    wolfSSL_CryptHwMutexUnLock();

    return ret;
}

#endif /* HAVE_ED25519 */

#endif /* WOLFSSL_SE050 */
