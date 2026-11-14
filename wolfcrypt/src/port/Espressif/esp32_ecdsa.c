/* esp32_ecdsa.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_ESPIDF) && defined(HAVE_ECC)

#include <wolfssl/wolfcrypt/port/Espressif/esp32-crypt.h>

#if defined(WOLFSSL_ESP32_CRYPT_ECDSA_OPAQUE)

#include <wolfssl/wolfcrypt/port/Espressif/esp32-ecdsa.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <psa/crypto.h>
#include <psa_crypto_driver_esp_ecdsa.h>

#define ESP32_ECDSA_CTX_TAG     0x45434453 /* "ECDS" */
#define ESP32_ECDSA_MAX_SIG     96
#define ESP32_ECDSA_MAX_PUBKEY  97

enum {
    ESP32_ECDSA_SOURCE_EFUSE = 1,
    ESP32_ECDSA_SOURCE_KM = 2
};

typedef struct {
    word32 tag;
    int source;
    int curveId;
    int keySize;
    esp_ecdsa_curve_t curve;
    psa_algorithm_t hashAlg;
    esp_ecdsa_opaque_key_t opaque;
    psa_key_attributes_t attrs;
    byte* driverKeyBuffer;
    size_t driverKeyBufferSz;
    size_t driverKeyBufferLen;
#if defined(SOC_KEY_MANAGER_SUPPORTED)
    esp_key_mgr_key_recovery_info_t recovery;
#endif
} WcEsp32EcdsaKeyCtx;

static int esp32_ecdsa_curve_info(int curveId, esp_ecdsa_curve_t* curve,
    int* keySize, psa_algorithm_t* hashAlg)
{
    if (curve == NULL || keySize == NULL || hashAlg == NULL) {
        return ECC_BAD_ARG_E;
    }

    if (curveId == ECC_SECP192R1) {
        *curve = ESP_ECDSA_CURVE_SECP192R1;
        *keySize = 24;
        *hashAlg = PSA_ALG_SHA_256;
    }
    else if (curveId == ECC_SECP256R1) {
        *curve = ESP_ECDSA_CURVE_SECP256R1;
        *keySize = 32;
        *hashAlg = PSA_ALG_SHA_256;
    }
    else if (curveId == ECC_SECP384R1) {
        *curve = ESP_ECDSA_CURVE_SECP384R1;
        *keySize = 48;
        *hashAlg = PSA_ALG_SHA_384;
    }
    else {
        return NOT_COMPILED_IN;
    }
    return MP_OKAY;
}

int wc_esp32_ecdsa_is_opaque(ecc_key* key)
{
    WcEsp32EcdsaKeyCtx* ctx;

    if (key == NULL || key->esp32EcdsaCtx == NULL) {
        return 0;
    }
    ctx = (WcEsp32EcdsaKeyCtx*)key->esp32EcdsaCtx;
    return ctx->tag == ESP32_ECDSA_CTX_TAG;
}

int wc_esp32_ecdsa_free(ecc_key* key)
{
    WcEsp32EcdsaKeyCtx* ctx;

    if (!wc_esp32_ecdsa_is_opaque(key)) {
        if (key != NULL) {
            key->esp32EcdsaCtx = NULL;
        }
        return MP_OKAY;
    }

    ctx = (WcEsp32EcdsaKeyCtx*)key->esp32EcdsaCtx;
    if (ctx->driverKeyBuffer != NULL) {
        ForceZero(ctx->driverKeyBuffer, ctx->driverKeyBufferSz);
        XFREE(ctx->driverKeyBuffer, key->heap, DYNAMIC_TYPE_ECC);
    }
    ForceZero(ctx, sizeof(*ctx));
    XFREE(ctx, key->heap, DYNAMIC_TYPE_ECC);
    key->esp32EcdsaCtx = NULL;
    return MP_OKAY;
}

static void esp32_ecdsa_ctx_free(WcEsp32EcdsaKeyCtx* ctx, void* heap)
{
    if (ctx != NULL) {
        if (ctx->driverKeyBuffer != NULL) {
            ForceZero(ctx->driverKeyBuffer, ctx->driverKeyBufferSz);
            XFREE(ctx->driverKeyBuffer, heap, DYNAMIC_TYPE_ECC);
        }
        ForceZero(ctx, sizeof(*ctx));
        XFREE(ctx, heap, DYNAMIC_TYPE_ECC);
    }
}

static int esp32_ecdsa_bind(ecc_key* key, WcEsp32EcdsaKeyCtx* ctx)
{
    psa_status_t status;
    psa_key_type_t keyType;
    byte publicKey[ESP32_ECDSA_MAX_PUBKEY];
    size_t publicKeyLen = 0;
    size_t required;
    size_t bits = 0;
    int ret;

    keyType = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
    psa_set_key_type(&ctx->attrs, keyType);
    psa_set_key_bits(&ctx->attrs, (size_t)ctx->keySize * 8);
    psa_set_key_lifetime(&ctx->attrs, PSA_KEY_LIFETIME_ESP_ECDSA);
    psa_set_key_usage_flags(&ctx->attrs, PSA_KEY_USAGE_SIGN_HASH |
        PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&ctx->attrs, PSA_ALG_ECDSA(ctx->hashAlg));

    required = esp_ecdsa_opaque_size_function(&ctx->attrs, keyType,
        (const uint8_t*)&ctx->opaque, sizeof(ctx->opaque));
    if (required == 0) {
        return ECC_BAD_ARG_E;
    }

    ctx->driverKeyBuffer = (byte*)XMALLOC(required, key->heap,
        DYNAMIC_TYPE_ECC);
    if (ctx->driverKeyBuffer == NULL) {
        return MEMORY_E;
    }
    ctx->driverKeyBufferSz = required;

    status = esp_ecdsa_opaque_import_key(&ctx->attrs,
        (const uint8_t*)&ctx->opaque, sizeof(ctx->opaque),
        ctx->driverKeyBuffer, ctx->driverKeyBufferSz,
        &ctx->driverKeyBufferLen, &bits);
    if (status != PSA_SUCCESS) {
        return ECC_BAD_ARG_E;
    }

    status = esp_ecdsa_opaque_export_public_key(&ctx->attrs,
        ctx->driverKeyBuffer, ctx->driverKeyBufferLen, publicKey,
        sizeof(publicKey), &publicKeyLen);
    if (status != PSA_SUCCESS || publicKeyLen != (size_t)ctx->keySize * 2 + 1 ||
        publicKey[0] != 0x04) {
        return WC_HW_E;
    }

    ret = mp_read_unsigned_bin(key->pubkey.x, publicKey + 1, ctx->keySize);
    if (ret == MP_OKAY) {
        ret = mp_read_unsigned_bin(key->pubkey.y,
            publicKey + 1 + ctx->keySize, ctx->keySize);
    }
    if (ret == MP_OKAY) {
        ret = mp_set(key->pubkey.z, 1);
    }
    if (ret == MP_OKAY) {
        /* A reused ecc_key must not retain a software private scalar after
         * binding an opaque key. Otherwise legacy ECDH paths could consume
         * that stale scalar instead of failing closed. */
        mp_forcezero(key->k);
    #ifdef WOLFSSL_ECC_BLIND_K
        mp_forcezero(key->kb);
        mp_forcezero(key->ku);
    #endif
        ctx->tag = ESP32_ECDSA_CTX_TAG;
        key->esp32EcdsaCtx = ctx;
        key->type = ECC_PRIVATEKEY;
    }
    ForceZero(publicKey, sizeof(publicKey));
    return ret;
}

int wc_esp32_ecdsa_use_efuse_key(ecc_key* key, int curveId,
    int lowBlock, int highBlock)
{
    WcEsp32EcdsaKeyCtx* ctx;
    int ret;

    if (key == NULL || lowBlock < 0 || lowBlock > 15 || highBlock >= 16) {
        return ECC_BAD_ARG_E;
    }
    if (highBlock >= 0 && lowBlock == highBlock) {
        return ECC_BAD_ARG_E;
    }

    ctx = (WcEsp32EcdsaKeyCtx*)XMALLOC(sizeof(*ctx), key->heap,
        DYNAMIC_TYPE_ECC);
    if (ctx == NULL) {
        return MEMORY_E;
    }
    XMEMSET(ctx, 0, sizeof(*ctx));
    ctx->source = ESP32_ECDSA_SOURCE_EFUSE;
    ctx->curveId = curveId;
    ret = esp32_ecdsa_curve_info(curveId, &ctx->curve, &ctx->keySize,
        &ctx->hashAlg);
    if (ret == MP_OKAY && curveId != ECC_SECP384R1 && highBlock >= 0) {
        ret = ECC_BAD_ARG_E;
    }
    if (ret != MP_OKAY) {
        esp32_ecdsa_ctx_free(ctx, key->heap);
        return ret;
    }

    ret = wc_ecc_set_curve(key, ctx->keySize, curveId);
    if (ret != MP_OKAY) {
        esp32_ecdsa_ctx_free(ctx, key->heap);
        return ret;
    }
    (void)wc_esp32_ecdsa_free(key);

    ctx->opaque.curve = ctx->curve;
    ctx->opaque.efuse_block = (uint8_t)lowBlock;
    if (curveId == ECC_SECP384R1) {
        if (highBlock < 0) {
            esp32_ecdsa_ctx_free(ctx, key->heap);
            return ECC_BAD_ARG_E;
        }
        ctx->opaque.efuse_block |= (uint8_t)(highBlock << 4);
    }

    ret = esp32_ecdsa_bind(key, ctx);
    if (ret != MP_OKAY) {
        esp32_ecdsa_ctx_free(ctx, key->heap);
    }
    return ret;
}

int wc_esp32_ecdsa_use_km_key(ecc_key* key, int curveId,
    const esp_key_mgr_key_recovery_info_t* recovery)
{
#if defined(SOC_KEY_MANAGER_SUPPORTED)
    WcEsp32EcdsaKeyCtx* ctx;
    int ret;

    if (key == NULL || recovery == NULL) {
        return ECC_BAD_ARG_E;
    }

    ctx = (WcEsp32EcdsaKeyCtx*)XMALLOC(sizeof(*ctx), key->heap,
        DYNAMIC_TYPE_ECC);
    if (ctx == NULL) {
        return MEMORY_E;
    }
    XMEMSET(ctx, 0, sizeof(*ctx));
    ctx->source = ESP32_ECDSA_SOURCE_KM;
    ctx->curveId = curveId;
    ret = esp32_ecdsa_curve_info(curveId, &ctx->curve, &ctx->keySize,
        &ctx->hashAlg);
    if (ret != MP_OKAY) {
        esp32_ecdsa_ctx_free(ctx, key->heap);
        return ret;
    }

    ret = wc_ecc_set_curve(key, ctx->keySize, curveId);
    if (ret != MP_OKAY) {
        esp32_ecdsa_ctx_free(ctx, key->heap);
        return ret;
    }
    (void)wc_esp32_ecdsa_free(key);

    XMEMCPY(&ctx->recovery, recovery, sizeof(ctx->recovery));
    ctx->opaque.curve = ctx->curve;
    ctx->opaque.key_recovery_info = &ctx->recovery;

    ret = esp32_ecdsa_bind(key, ctx);
    if (ret != MP_OKAY) {
        esp32_ecdsa_ctx_free(ctx, key->heap);
    }
    return ret;
#else
    (void)key;
    (void)curveId;
    (void)recovery;
    return NOT_COMPILED_IN;
#endif
}

int wc_esp32_ecdsa_copy(ecc_key* src, ecc_key* dst)
{
    WcEsp32EcdsaKeyCtx* srcCtx;
    WcEsp32EcdsaKeyCtx* dstCtx;

    if (src == NULL || dst == NULL) {
        return ECC_BAD_ARG_E;
    }
    if (src == dst) {
        return MP_OKAY;
    }
    (void)wc_esp32_ecdsa_free(dst);
    if (!wc_esp32_ecdsa_is_opaque(src)) {
        return MP_OKAY;
    }

    srcCtx = (WcEsp32EcdsaKeyCtx*)src->esp32EcdsaCtx;
    dstCtx = (WcEsp32EcdsaKeyCtx*)XMALLOC(sizeof(*dstCtx), dst->heap,
        DYNAMIC_TYPE_ECC);
    if (dstCtx == NULL) {
        return MEMORY_E;
    }
    XMEMCPY(dstCtx, srcCtx, sizeof(*dstCtx));
    dstCtx->driverKeyBuffer = NULL;
    dstCtx->driverKeyBufferSz = 0;
    dstCtx->driverKeyBufferLen = 0;
#if defined(SOC_KEY_MANAGER_SUPPORTED)
    if (srcCtx->source == ESP32_ECDSA_SOURCE_KM) {
        dstCtx->opaque.key_recovery_info = &dstCtx->recovery;
    }
#endif

    dstCtx->driverKeyBuffer = (byte*)XMALLOC(
        srcCtx->driverKeyBufferSz, dst->heap, DYNAMIC_TYPE_ECC);
    if (dstCtx->driverKeyBuffer == NULL) {
        esp32_ecdsa_ctx_free(dstCtx, dst->heap);
        return MEMORY_E;
    }
    dstCtx->driverKeyBufferSz = srcCtx->driverKeyBufferSz;
    dstCtx->driverKeyBufferLen = srcCtx->driverKeyBufferLen;
    XMEMCPY(dstCtx->driverKeyBuffer, srcCtx->driverKeyBuffer,
        srcCtx->driverKeyBufferSz);
    dst->esp32EcdsaCtx = dstCtx;
    return MP_OKAY;
}

int wc_esp32_ecdsa_sign_hash(const byte* in, word32 inLen,
    ecc_key* key, mp_int* r, mp_int* s)
{
    WcEsp32EcdsaKeyCtx* ctx;
    psa_status_t status;
    byte signature[ESP32_ECDSA_MAX_SIG];
    size_t signatureLen = 0;
    psa_algorithm_t alg = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
    int ret;

    if (in == NULL || key == NULL || r == NULL || s == NULL) {
        return ECC_BAD_ARG_E;
    }
    if (!wc_esp32_ecdsa_is_opaque(key)) {
        return NOT_COMPILED_IN;
    }

    ctx = (WcEsp32EcdsaKeyCtx*)key->esp32EcdsaCtx;
    alg = PSA_ALG_ECDSA(ctx->hashAlg);
    if ((ctx->keySize == 48 && inLen != 48) ||
        (ctx->keySize != 48 && inLen != 32)) {
        return BAD_LENGTH_E;
    }

#if defined(WOLFSSL_ECDSA_SET_K) || defined(WOLFSSL_ECDSA_SET_K_ONE_LOOP)
    if (key->sign_k_set) {
        return ECC_BAD_ARG_E;
    }
#endif
#if defined(WOLFSSL_ECDSA_DETERMINISTIC_K) || \
    defined(WOLFSSL_ECDSA_DETERMINISTIC_K_VARIANT)
    if (key->deterministic) {
        alg = PSA_ALG_DETERMINISTIC_ECDSA(ctx->hashAlg);
    }
#endif

    XMEMSET(signature, 0, sizeof(signature));
    status = esp_ecdsa_opaque_sign_hash(&ctx->attrs, ctx->driverKeyBuffer,
        ctx->driverKeyBufferLen, alg, in, inLen,
        signature, sizeof(signature), &signatureLen);
    if (status != PSA_SUCCESS || signatureLen != (size_t)ctx->keySize * 2) {
        ForceZero(signature, sizeof(signature));
        return WC_HW_E;
    }

    ret = mp_read_unsigned_bin(r, signature, ctx->keySize);
    if (ret == MP_OKAY) {
        ret = mp_read_unsigned_bin(s, signature + ctx->keySize, ctx->keySize);
    }
    ForceZero(signature, sizeof(signature));
    if (ret == MP_OKAY && (mp_iszero(r) || mp_iszero(s))) {
        ret = WC_HW_E;
    }
    return ret;
}

#endif /* WOLFSSL_ESP32_CRYPT_ECDSA_OPAQUE */
#endif /* WOLFSSL_ESPIDF && HAVE_ECC */
