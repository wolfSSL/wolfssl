/* silabs_key.c
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

/* Secure Vault key management for the Silicon Labs crypto callback port:
 * wrapped keys (encrypted to a device-unique key, usable by the SE but never
 * readable by the application) and the SE built-in key slots. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_SILABS_CRYPTOCB

#include <wolfssl/wolfcrypt/error-crypt.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif
#include <wolfssl/wolfcrypt/port/silabs/silabs_cryptocb.h>
/* pulls em_device.h or the host shim, so the Vault feature macro is visible */
#include <wolfssl/wolfcrypt/port/silabs/silabs_hash.h>

#if !defined(NO_AES) && defined(WOLFSSL_SILABS_CRYPTOCB_CIPHER)
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/port/silabs/silabs_aes.h>
#endif

#if defined(HAVE_ECC) && defined(WOLFSSL_SILABS_CRYPTOCB_ECC)
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/port/silabs/silabs_ecc.h>
#endif

#ifndef WOLFSSL_SILABS_HOST_TEST
    #include <sl_se_manager_key_handling.h>
#endif

/* Wrapped keys are a Secure Vault High feature. On a Vault Mid part the SE has
 * no wrapped-key storage; the built-in slots are still reachable. */
#if defined(_SILICON_LABS_SECURITY_FEATURE) && \
    (_SILICON_LABS_SECURITY_FEATURE == _SILICON_LABS_SECURITY_FEATURE_VAULT)
    #define WOLFSSL_SILABS_WRAPPED_KEYS
#endif

/* Map a key-bit count to the SE AES key type. */
#if !defined(NO_AES) && defined(WOLFSSL_SILABS_CRYPTOCB_CIPHER)
static int silabs_key_aes_type(int keyBits, sl_se_key_type_t* type)
{
    switch (keyBits) {
    case 128:
        *type = SL_SE_KEY_TYPE_AES_128;
        break;
#ifdef WOLFSSL_AES_192
    case 192:
        *type = SL_SE_KEY_TYPE_AES_192;
        break;
#endif
#ifdef WOLFSSL_AES_256
    case 256:
        *type = SL_SE_KEY_TYPE_AES_256;
        break;
#endif
    default:
        return BAD_FUNC_ARG;
    }

    return 0;
}
#endif /* !NO_AES && WOLFSSL_SILABS_CRYPTOCB_CIPHER */

#if defined(HAVE_ECC) && defined(WOLFSSL_SILABS_CRYPTOCB_ECC)
/* Map a wolfCrypt curve id to the SE ECC key type. Mirrors the curves the
 * callback port offloads. */
static int silabs_key_ecc_type(int curveId, sl_se_key_type_t* type,
    word32* keySz)
{
    int sz;

    switch (curveId) {
#ifdef SL_SE_KEY_TYPE_ECC_P192
    case ECC_SECP192R1:
        *type = SL_SE_KEY_TYPE_ECC_P192;
        break;
#endif
    case ECC_SECP256R1:
        *type = SL_SE_KEY_TYPE_ECC_P256;
        break;
#ifdef SL_SE_KEY_TYPE_ECC_P384
    case ECC_SECP384R1:
        *type = SL_SE_KEY_TYPE_ECC_P384;
        break;
#endif
#ifdef SL_SE_KEY_TYPE_ECC_P521
    case ECC_SECP521R1:
        *type = SL_SE_KEY_TYPE_ECC_P521;
        break;
#endif
    default:
        return BAD_FUNC_ARG;
    }

    /* Let wolfCrypt supply the coordinate size rather than restating it. */
    sz = wc_ecc_get_curve_size_from_id(curveId);
    if (sz <= 0) {
        return BAD_FUNC_ARG;
    }
    *keySz = (word32)sz;

    return 0;
}
#endif /* HAVE_ECC && WOLFSSL_SILABS_CRYPTOCB_ECC */

#if !defined(NO_AES) && defined(WOLFSSL_SILABS_WRAPPED_KEYS) && \
    defined(WOLFSSL_SILABS_CRYPTOCB_CIPHER)

int wc_SilabsSe_AesGetWrappedKeySize(int keyBits, word32* outSz)
{
    sl_se_key_descriptor_t desc;
    sl_se_key_type_t type;
    uint32_t sz = 0;
    int ret;

    if (outSz == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = silabs_key_aes_type(keyBits, &type);
    if (ret != 0) {
        return ret;
    }

    XMEMSET(&desc, 0, sizeof(desc));
    desc.type = type;
    desc.flags = SL_SE_KEY_FLAG_NON_EXPORTABLE;
    desc.storage.method = SL_SE_KEY_STORAGE_EXTERNAL_WRAPPED;

    ret = silabs_cb_status((int)sl_se_get_storage_size(&desc, &sz));
    if (ret == 0) {
        *outSz = (word32)sz;
    }

    return ret;
}

int wc_SilabsSe_AesGenerateWrappedKey(int keyBits, byte* out, word32* outSz)
{
    sl_se_command_context_t cmd = SL_SE_COMMAND_CONTEXT_INIT;
    sl_se_key_descriptor_t desc;
    sl_se_key_type_t type;
    word32 need = 0;
    int ret;

    if (out == NULL || outSz == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = wc_SilabsSe_AesGetWrappedKeySize(keyBits, &need);
    if (ret != 0) {
        return ret;
    }
    if (*outSz < need) {
        *outSz = need;
        return BUFFER_E;
    }

    ret = silabs_key_aes_type(keyBits, &type);
    if (ret != 0) {
        return ret;
    }

    XMEMSET(&desc, 0, sizeof(desc));
    desc.type = type;
    desc.flags = SL_SE_KEY_FLAG_NON_EXPORTABLE;
    desc.size = (uint32_t)(keyBits / 8);
    desc.storage.method = SL_SE_KEY_STORAGE_EXTERNAL_WRAPPED;
    desc.storage.location.buffer.pointer = out;
    desc.storage.location.buffer.size = need;

    ret = silabs_cb_status((int)sl_se_generate_key(&cmd, &desc));
    if (ret == 0) {
        *outSz = need;
    }

    return ret;
}

int wc_SilabsSe_AesUseWrappedKey(Aes* aes, const byte* wrapped,
    word32 wrappedSz, int keyBits)
{
    sl_se_command_context_t cc = SL_SE_COMMAND_CONTEXT_INIT;
    sl_se_key_type_t type;
    word32 need = 0;
    int ret;

    if (aes == NULL || wrapped == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = wc_SilabsSe_AesGetWrappedKeySize(keyBits, &need);
    if (ret != 0) {
        return ret;
    }
    if (wrappedSz != need) {
        return BAD_LENGTH_E;
    }

    ret = silabs_key_aes_type(keyBits, &type);
    if (ret != 0) {
        return ret;
    }

    aes->ctx.cmd_ctx = cc;
    XMEMSET(&(aes->ctx.key), 0, sizeof(sl_se_key_descriptor_t));
    aes->ctx.key.type = type;
    aes->ctx.key.flags = SL_SE_KEY_FLAG_NON_EXPORTABLE;
    aes->ctx.key.size = (uint32_t)(keyBits / 8);
    aes->ctx.key.storage.method = SL_SE_KEY_STORAGE_EXTERNAL_WRAPPED;
    /* The descriptor references the caller's blob, which must outlive the
     * Aes. Nothing is copied: that is the point of a wrapped key. */
    aes->ctx.key.storage.location.buffer.pointer = (uint8_t*)wrapped;
    aes->ctx.key.storage.location.buffer.size = wrappedSz;
    /* Scrub any plaintext key this object was carrying. The Secure Element
     * holds the key from here on, and leaving software material behind would
     * let a path that never consults ctx.keySet encrypt with the old key. */
    ForceZero(aes->devKey, sizeof(aes->devKey));
    ForceZero(aes->key, sizeof(aes->key));
    aes->ctx.keySet = 1;

    /* wolfCrypt sizes its own state from keylen even when it never sees the
     * key material. */
    aes->keylen = keyBits / 8;
    aes->rounds = (word32)(aes->keylen / 4 + 6);

    return 0;
}

#endif /* !NO_AES && WOLFSSL_SILABS_WRAPPED_KEYS */

#if !defined(NO_AES) && defined(WOLFSSL_SILABS_CRYPTOCB_CIPHER)
int wc_SilabsSe_AesUseBuiltInKey(Aes* aes, int slot, int keyBits)
{
    sl_se_command_context_t cc = SL_SE_COMMAND_CONTEXT_INIT;
    sl_se_key_type_t type;
    int ret;

    if (aes == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = silabs_key_aes_type(keyBits, &type);
    if (ret != 0) {
        return ret;
    }

    aes->ctx.cmd_ctx = cc;
    XMEMSET(&(aes->ctx.key), 0, sizeof(sl_se_key_descriptor_t));
    aes->ctx.key.type = type;
    aes->ctx.key.flags = SL_SE_KEY_FLAG_NON_EXPORTABLE;
    aes->ctx.key.size = (uint32_t)(keyBits / 8);
    aes->ctx.key.storage.method = SL_SE_KEY_STORAGE_INTERNAL_IMMUTABLE;
    aes->ctx.key.storage.location.slot = (uint32_t)slot;
    /* Scrub any plaintext key this object was carrying. The Secure Element
     * holds the key from here on, and leaving software material behind would
     * let a path that never consults ctx.keySet encrypt with the old key. */
    ForceZero(aes->devKey, sizeof(aes->devKey));
    ForceZero(aes->key, sizeof(aes->key));
    aes->ctx.keySet = 1;

    aes->keylen = keyBits / 8;
    aes->rounds = (word32)(aes->keylen / 4 + 6);

    return 0;
}
#endif /* !NO_AES && WOLFSSL_SILABS_CRYPTOCB_CIPHER */

#if defined(HAVE_ECC) && defined(WOLFSSL_SILABS_CRYPTOCB_ECC)

#ifdef WOLFSSL_SILABS_WRAPPED_KEYS
int wc_SilabsSe_EccGetWrappedKeySize(int curveId, word32* outSz)
{
    sl_se_key_descriptor_t desc;
    sl_se_key_type_t type;
    word32 keySz = 0;
    uint32_t sz = 0;
    int ret;

    if (outSz == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = silabs_key_ecc_type(curveId, &type, &keySz);
    if (ret != 0) {
        return ret;
    }

    XMEMSET(&desc, 0, sizeof(desc));
    desc.type = type;
    desc.flags = SL_SE_KEY_FLAG_ASYMMETRIC_BUFFER_HAS_PRIVATE_KEY |
                 SL_SE_KEY_FLAG_NON_EXPORTABLE;
    desc.size = keySz;
    desc.storage.method = SL_SE_KEY_STORAGE_EXTERNAL_WRAPPED;

    ret = silabs_cb_status((int)sl_se_get_storage_size(&desc, &sz));
    if (ret == 0) {
        *outSz = (word32)sz;
    }

    return ret;
}

int wc_SilabsSe_EccGenerateWrappedKey(int curveId, byte* wrapped,
    word32* wrappedSz, byte* pubOut, word32* pubOutSz)
{
    sl_se_command_context_t cmd = SL_SE_COMMAND_CONTEXT_INIT;
    sl_se_key_descriptor_t desc;
    sl_se_key_descriptor_t pubDesc;
    sl_se_key_type_t type;
    word32 keySz = 0;
    word32 need = 0;
    int ret;

    if (wrapped == NULL || wrappedSz == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = silabs_key_ecc_type(curveId, &type, &keySz);
    if (ret != 0) {
        return ret;
    }
    ret = wc_SilabsSe_EccGetWrappedKeySize(curveId, &need);
    if (ret != 0) {
        return ret;
    }
    if (*wrappedSz < need) {
        *wrappedSz = need;
        return BUFFER_E;
    }
    /* The public point is X||Y, two coordinates of the curve size. */
    if (pubOut != NULL && (pubOutSz == NULL || *pubOutSz < (keySz * 2))) {
        if (pubOutSz != NULL) {
            *pubOutSz = keySz * 2;
        }
        return BUFFER_E;
    }

    XMEMSET(&desc, 0, sizeof(desc));
    desc.type = type;
    desc.flags = SL_SE_KEY_FLAG_ASYMMETRIC_BUFFER_HAS_PRIVATE_KEY |
                 SL_SE_KEY_FLAG_NON_EXPORTABLE;
    desc.size = keySz;
    desc.storage.method = SL_SE_KEY_STORAGE_EXTERNAL_WRAPPED;
    desc.storage.location.buffer.pointer = wrapped;
    desc.storage.location.buffer.size = need;

    ret = silabs_cb_status((int)sl_se_generate_key(&cmd, &desc));
    if (ret != 0) {
        return ret;
    }
    *wrappedSz = need;

    if (pubOut != NULL) {
        XMEMSET(&pubDesc, 0, sizeof(pubDesc));
        pubDesc.type = type;
        pubDesc.flags = SL_SE_KEY_FLAG_ASYMMETRIC_BUFFER_HAS_PUBLIC_KEY;
        pubDesc.size = keySz;
        pubDesc.storage.method = SL_SE_KEY_STORAGE_EXTERNAL_PLAINTEXT;
        pubDesc.storage.location.buffer.pointer = pubOut;
        pubDesc.storage.location.buffer.size = keySz * 2;

        ret = silabs_cb_status(
            (int)sl_se_export_public_key(&cmd, &desc, &pubDesc));
        if (ret == 0) {
            *pubOutSz = keySz * 2;
        }
    }

    return ret;
}

int wc_SilabsSe_EccUseWrappedKey(ecc_key* key, const byte* wrapped,
    word32 wrappedSz, int curveId)
{
    sl_se_command_context_t cc = SL_SE_COMMAND_CONTEXT_INIT;
    sl_se_key_type_t type;
    word32 keySz = 0;
    word32 need = 0;
    int ret;

    if (key == NULL || wrapped == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = silabs_key_ecc_type(curveId, &type, &keySz);
    if (ret != 0) {
        return ret;
    }
    ret = wc_SilabsSe_EccGetWrappedKeySize(curveId, &need);
    if (ret != 0) {
        return ret;
    }
    if (wrappedSz != need) {
        return BAD_LENGTH_E;
    }

    /* Give wolfCrypt the curve so sizes and signature encoding are right,
     * even though it never sees the private scalar. */
    ret = wc_ecc_set_curve(key, (int)keySz, curveId);
    if (ret != 0) {
        return ret;
    }
    key->type = ECC_PRIVATEKEY;

    key->cmd_ctx = cc;
    XMEMSET(&(key->key), 0, sizeof(sl_se_key_descriptor_t));
    key->key.type = type;
    key->key.flags = SL_SE_KEY_FLAG_ASYMMETRIC_BUFFER_HAS_PRIVATE_KEY |
                     SL_SE_KEY_FLAG_NON_EXPORTABLE;
    key->key.size = keySz;
    key->key.storage.method = SL_SE_KEY_STORAGE_EXTERNAL_WRAPPED;
    key->key.storage.location.buffer.pointer = (uint8_t*)wrapped;
    key->key.storage.location.buffer.size = wrappedSz;
    /* Drop any software key material: the SE holds this key, and a stale
     * scalar or public point would otherwise outlive the binding. */
    ForceZero(key->key_raw, sizeof(key->key_raw));
    key->silabsKeySet = 1;

    return 0;
}
#endif /* WOLFSSL_SILABS_WRAPPED_KEYS */

int wc_SilabsSe_EccUseBuiltInKey(ecc_key* key, int slot, int curveId)
{
    sl_se_command_context_t cc = SL_SE_COMMAND_CONTEXT_INIT;
    sl_se_key_type_t type;
    word32 keySz = 0;
    int ret;

    if (key == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = silabs_key_ecc_type(curveId, &type, &keySz);
    if (ret != 0) {
        return ret;
    }

    ret = wc_ecc_set_curve(key, (int)keySz, curveId);
    if (ret != 0) {
        return ret;
    }
    key->type = ECC_PRIVATEKEY;

    key->cmd_ctx = cc;
    XMEMSET(&(key->key), 0, sizeof(sl_se_key_descriptor_t));
    key->key.type = type;
    key->key.flags = SL_SE_KEY_FLAG_ASYMMETRIC_BUFFER_HAS_PRIVATE_KEY |
                     SL_SE_KEY_FLAG_NON_EXPORTABLE;
    key->key.size = keySz;
    key->key.storage.method = SL_SE_KEY_STORAGE_INTERNAL_IMMUTABLE;
    key->key.storage.location.slot = (uint32_t)slot;
    /* Drop any software key material: the SE holds this key, and a stale
     * scalar or public point would otherwise outlive the binding. */
    ForceZero(key->key_raw, sizeof(key->key_raw));
    key->silabsKeySet = 1;

    return 0;
}

#endif /* HAVE_ECC && WOLFSSL_SILABS_CRYPTOCB_ECC */

#endif /* WOLFSSL_SILABS_CRYPTOCB */
