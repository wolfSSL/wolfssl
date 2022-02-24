/* kcapi_dh.c
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

#if defined(WOLFSSL_KCAPI_DH)

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/port/kcapi/wc_kcapi.h>
#include <wolfssl/wolfcrypt/port/kcapi/kcapi_dh.h>
#include <wolfssl/wolfcrypt/dh.h>
#include <wolfssl/wolfcrypt/asn.h>

static const char WC_NAME_DH[] = "dh";

void KcapiDh_Free(DhKey* key)
{
    if (key->handle != NULL) {
        kcapi_kpp_destroy(key->handle);
        key->handle = NULL;
    }
}

static int KcapiDh_SetParams(DhKey* key)
{
#if defined(HAVE_FIPS) && \
        (!defined(HAVE_FIPS_VERSION) || (HAVE_FIPS_VERSION < 2))
    int ret = 0;
    unsigned char* pkcs3 = NULL;
    word32 len = 0, idx = 0, len2;

    len  = MAX_SEQ_SZ;                  /* Sequence */
    len += ASN_TAG_SZ + MAX_LENGTH_SZ;  /* Integer */
    len += mp_leading_bit(&key->p) ? 1 : 0;
    len += mp_unsigned_bin_size(&key->p);
    len += ASN_TAG_SZ + MAX_LENGTH_SZ;  /* Integer */
    len += mp_leading_bit(&key->g) ? 1 : 0;
    len += mp_unsigned_bin_size(&key->g);

    pkcs3 = (unsigned char*)XMALLOC(len, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (pkcs3 == NULL) {
        ret = MEMORY_E;
    }

    if (ret == 0) {
        idx = len;
        len2 = mp_unsigned_bin_size(&key->g);
        idx -= len2;
        ret = mp_to_unsigned_bin(&key->g, pkcs3 + idx);
    }
    if (ret >= 0) {
        if (mp_leading_bit(&key->g)) {
            pkcs3[--idx] = 0x00;
            len2++;
        }
        idx -= SetLength(len2, NULL);
        SetLength(len2, pkcs3 + idx);
        pkcs3[--idx] = ASN_INTEGER;

        len2 = mp_unsigned_bin_size(&key->p);
        idx -= len2;
        ret = mp_to_unsigned_bin(&key->p, pkcs3 + idx);
    }
    if (ret >= 0) {
        if (mp_leading_bit(&key->p)) {
            pkcs3[--idx] = 0x00;
            len2++;
        }
        idx -= SetLength(len2, NULL);
        SetLength(len2, pkcs3 + idx);
        pkcs3[--idx] = ASN_INTEGER;

        len2 = len - idx;
        idx -= SetSequence(len2, NULL);
        SetSequence(len2, pkcs3 + idx);

        ret = kcapi_kpp_dh_setparam_pkcs3(key->handle, pkcs3 + idx, len - idx);
        if (ret != 0) {
            WOLFSSL_MSG("KcapiDh_SetParams: Failed to set");
        }
    }

    if (pkcs3 != NULL) {
        XFREE(pkcs3, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
    return ret;
#else
    int ret;
    unsigned char* pkcs3 = NULL;
    word32 len;

    ret = wc_DhParamsToDer(key, NULL, &len);
    if (ret == LENGTH_ONLY_E) {
        ret = 0;
        pkcs3 = (unsigned char*)XMALLOC(len, key->heap,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
        if (pkcs3 == NULL) {
            ret = MEMORY_E;
        }
    }
    if (ret == 0) {
        ret = wc_DhParamsToDer(key, pkcs3, &len);
    }
    if (ret == 0) {
        ret = kcapi_kpp_dh_setparam_pkcs3(key->handle, pkcs3, len);
        if (ret != 0) {
            WOLFSSL_MSG("KcapiDh_SetParams: Failed to set");
        }
    }

    if (pkcs3 != NULL) {
        XFREE(pkcs3, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
    return ret;
#endif
}

int KcapiDh_MakeKey(DhKey* key, byte* pub, word32* pubSz)
{
    int ret = 0;

    if (key->handle != NULL) {
        kcapi_kpp_destroy(key->handle);
        key->handle = NULL;
    }
    if (ret == 0) {
        ret = kcapi_kpp_init(&key->handle, WC_NAME_DH, 0);
        if (ret != 0) {
            WOLFSSL_MSG("KcapiDh_MakeKey: Failed to initialization");
        }
    }

    if (ret == 0) {
        ret = KcapiDh_SetParams(key);
    }
    if (ret == 0) {
        ret = kcapi_kpp_keygen(key->handle, pub, *pubSz,
                               KCAPI_ACCESS_HEURISTIC);
    }

    return ret;
}

int KcapiDh_SharedSecret(DhKey* private_key, const byte* pub, word32 pubSz,
                         byte* out, word32* outlen)
{
    int ret;

    ret = kcapi_kpp_ssgen(private_key->handle, pub, pubSz, out, *outlen,
                          KCAPI_ACCESS_HEURISTIC);
    if (ret >= 0) {
        *outlen = ret;
        ret = 0;
    }

    return ret;
}

#endif /* WOLFSSL_KCAPI_DH */
