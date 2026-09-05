/* silabs_cb_kdf.c
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

#if defined(WOLFSSL_SILABS_CRYPTOCB) && defined(WOLFSSL_SILABS_CRYPTOCB_KDF)

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/port/silabs/silabs_cryptocb.h>
/* for the SE types and _SILICON_LABS_SECURITY_FEATURE */
#include <wolfssl/wolfcrypt/port/silabs/silabs_hash.h>

/* The SE key derivation commands are a Secure Vault High feature. On a Vault
 * Mid part they do not exist and both KDFs stay in software (where HKDF still
 * benefits from the offloaded HMAC/SHA path). */
#if defined(_SILICON_LABS_SECURITY_FEATURE) && \
    (_SILICON_LABS_SECURITY_FEATURE == _SILICON_LABS_SECURITY_FEATURE_VAULT)
    #define WOLFSSL_SILABS_KDF_HW
#endif

#ifdef WOLFSSL_SILABS_KDF_HW

#ifndef WOLFSSL_SILABS_HOST_TEST
    #include <sl_se_manager_key_derivation.h>
#endif

/* Describe a plaintext symmetric key held in a caller buffer. */
static void silabs_kdf_plain_key(sl_se_key_descriptor_t* desc, const void* buf,
    word32 sz)
{
    XMEMSET(desc, 0, sizeof(*desc));
    desc->type = SL_SE_KEY_TYPE_SYMMETRIC;
    desc->size = sz;
    desc->storage.method = SL_SE_KEY_STORAGE_EXTERNAL_PLAINTEXT;
    desc->storage.location.buffer.pointer = (void*)buf;
    desc->storage.location.buffer.size = sz;
}

#if defined(HAVE_HKDF) && !defined(NO_HMAC)
static int silabs_kdf_hkdf(wc_CryptoInfo* info)
{
    sl_se_command_context_t cmd = SL_SE_COMMAND_CONTEXT_INIT;
    sl_se_key_descriptor_t inKey;
    sl_se_key_descriptor_t outKey;
    sl_status_t status;
    int seHash;

    if (info->kdf.hkdf.out == NULL) {
        return BAD_FUNC_ARG;
    }
    /* wc_HKDF accepts zero-length input keying material with a NULL pointer.
     * The SE key descriptor cannot express an empty key, but the callback runs
     * before the software path, so decline instead of rejecting a call the
     * public API considers valid. A NULL pointer with a non-zero length is a
     * genuine argument error. */
    if (info->kdf.hkdf.inKey == NULL) {
        if (info->kdf.hkdf.inKeySz != 0) {
            return BAD_FUNC_ARG;
        }
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    seHash = silabs_cb_hash_type(info->kdf.hkdf.hashType, NULL);
    if (seHash == SL_SE_HASH_NONE) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    silabs_kdf_plain_key(&inKey, info->kdf.hkdf.inKey, info->kdf.hkdf.inKeySz);
    silabs_kdf_plain_key(&outKey, info->kdf.hkdf.out, info->kdf.hkdf.outSz);

    status = sl_se_derive_key_hkdf(&cmd, &inKey,
        (sl_se_hash_type_t)seHash,
        info->kdf.hkdf.salt, info->kdf.hkdf.saltSz,
        info->kdf.hkdf.info, info->kdf.hkdf.infoSz,
        &outKey);

    return silabs_cb_status((int)status);
}
#endif /* HAVE_HKDF && !NO_HMAC */

#if defined(HAVE_PBKDF2) && !defined(NO_HMAC) && !defined(NO_PWDBASED)
static int silabs_kdf_pbkdf2(wc_CryptoInfo* info)
{
    sl_se_command_context_t cmd = SL_SE_COMMAND_CONTEXT_INIT;
    sl_se_key_descriptor_t inKey;
    sl_se_key_descriptor_t outKey;
    sl_status_t status;
    int seHash;

    if (info->kdf.pbkdf2.output == NULL) {
        return BAD_FUNC_ARG;
    }
    if (info->kdf.pbkdf2.passwd == NULL && info->kdf.pbkdf2.pLen != 0) {
        return BAD_FUNC_ARG;
    }
    /* kLen == 0 is not an error for the software API, only for this engine. */
    if (info->kdf.pbkdf2.pLen < 0 || info->kdf.pbkdf2.sLen < 0 ||
        info->kdf.pbkdf2.kLen < 0 || info->kdf.pbkdf2.iterations <= 0) {
        return BAD_FUNC_ARG;
    }
    /* An empty password or a zero-length result are both accepted by
     * wc_PBKDF2_ex but cannot be handed to the SE; decline so software keeps
     * the existing contract. */
    if (info->kdf.pbkdf2.passwd == NULL || info->kdf.pbkdf2.kLen == 0) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    seHash = silabs_cb_hash_type(info->kdf.pbkdf2.hashType, NULL);
    if (seHash == SL_SE_HASH_NONE) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    silabs_kdf_plain_key(&inKey, info->kdf.pbkdf2.passwd,
        (word32)info->kdf.pbkdf2.pLen);
    silabs_kdf_plain_key(&outKey, info->kdf.pbkdf2.output,
        (word32)info->kdf.pbkdf2.kLen);

    status = sl_se_derive_key_pbkdf2(&cmd, &inKey,
        (sl_se_pbkdf2_prf_type_t)seHash,
        info->kdf.pbkdf2.salt, (size_t)info->kdf.pbkdf2.sLen,
        (uint32_t)info->kdf.pbkdf2.iterations,
        &outKey);

    return silabs_cb_status((int)status);
}
#endif /* HAVE_PBKDF2 && !NO_HMAC && !NO_PWDBASED */

#endif /* WOLFSSL_SILABS_KDF_HW */

/* WC_ALGO_TYPE_KDF. */
int wc_SilabsKdf(wc_CryptoInfo* info)
{
    int ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);

    if (info == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_SILABS_KDF_HW
    switch (info->kdf.type) {
#if defined(HAVE_HKDF) && !defined(NO_HMAC)
    case WC_KDF_TYPE_HKDF:
        /* The SE command is the full extract-then-expand HKDF; the separate
         * extract and expand steps have no SE equivalent and stay in
         * software. */
        ret = silabs_kdf_hkdf(info);
        break;
#endif
#if defined(HAVE_PBKDF2) && !defined(NO_HMAC) && !defined(NO_PWDBASED)
    case WC_KDF_TYPE_PBKDF2:
        ret = silabs_kdf_pbkdf2(info);
        break;
#endif
    default:
        break;
    }
#endif /* WOLFSSL_SILABS_KDF_HW */

    return ret;
}

#endif /* WOLFSSL_SILABS_CRYPTOCB && WOLFSSL_SILABS_CRYPTOCB_KDF */
