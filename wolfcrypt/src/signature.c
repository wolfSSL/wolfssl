/* signature.c
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/signature.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifdef HAVE_ECC
#include <wolfssl/wolfcrypt/ecc.h>
#endif
#ifndef NO_RSA
#include <wolfssl/wolfcrypt/rsa.h>
#endif


word32 wc_SignatureGetSize(enum wc_SignatureType sig_type,
    const void* key, word32 key_len)
{
    word32 sig_len = 0;

    switch(sig_type) {
#ifdef HAVE_ECC
        case WC_SIGNATURE_TYPE_ECC:
        {
            if (key_len < sizeof(ecc_key)) {
                return BAD_FUNC_ARG;
            }
            sig_len = wc_ecc_sig_size((ecc_key*)key);
            break;
        }
#endif
#ifndef NO_RSA
        case WC_SIGNATURE_TYPE_RSA:
            if (key_len < sizeof(RsaKey)) {
                return BAD_FUNC_ARG;
            }
            sig_len = wc_RsaEncryptSize((RsaKey*)key);
            break;
#endif

        case WC_SIGNATURE_TYPE_NONE:
        default:
            break;
    }
    return sig_len;
}

int wc_SignatureVerify(
    enum wc_HashType hash_type, enum wc_SignatureType sig_type,
    const byte* data, word32 data_len,
    const byte* sig, word32 sig_len,
    const void* key, word32 key_len)
{
    int ret, hash_len;
    byte *hash_data = NULL;

    /* Validate hash size */
    hash_len = wc_HashGetDigestSize(hash_type);
    if (hash_len <= 0) {
        return BAD_FUNC_ARG;
    }

    /* Allocate temporary buffer for hash data */
    hash_data = XMALLOC(hash_len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (hash_data == NULL) {
        return MEMORY_E;
    }

    /* Perform hash of data */
    ret = wc_Hash(hash_type, data, data_len, hash_data, hash_len);
    if(ret != 0) {
        goto exit;
    }

    /* Verify signature using hash as data */
    switch(sig_type) {
#ifdef HAVE_ECC
        case WC_SIGNATURE_TYPE_ECC:
        {
            int is_valid_sig = -1;

            /* Validate key size */
            if (key_len < sizeof(ecc_key)) {
                return BAD_FUNC_ARG;
            }
            /* Perform verification of signature using provided ECC key */
            ret = wc_ecc_verify_hash(sig, sig_len, hash_data, hash_len, &is_valid_sig, (ecc_key*)key);
            if (ret != 0 || is_valid_sig != 1) {
                ret = -1;
            }
            break;
        }
#endif
#ifndef NO_RSA
        case WC_SIGNATURE_TYPE_RSA:
            /* Validate key size */
            if (key_len < sizeof(ecc_key)) {
                return BAD_FUNC_ARG;
            }
            /* Perform verification of signature using provided RSA key */
            ret = wc_RsaSSL_Verify(sig, sig_len, hash_data, hash_len, (RsaKey*)key);
            break;
#endif

        case WC_SIGNATURE_TYPE_NONE:
        default:
            break;
    }

exit:
    if (hash_data) {
        XFREE(hash_data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    return ret;
}

int wc_SignatureGenerate(
    enum wc_HashType hash_type, enum wc_SignatureType sig_type,
    const byte* data, word32 data_len,
    byte* sig, word32 *sig_len,
    const void* key, word32 key_len, RNG* rng)
{
    int ret, hash_len;
    byte *hash_data = NULL;

    /* Validate hash size */
    hash_len = wc_HashGetDigestSize(hash_type);
    if (hash_len <= 0) {
        return BAD_FUNC_ARG;
    }

    /* Allocate temporary buffer for hash data */
    hash_data = XMALLOC(hash_len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (hash_data == NULL) {
        return MEMORY_E;
    }

    /* Perform hash of data */
    ret = wc_Hash(hash_type, data, data_len, hash_data, hash_len);
    if (ret != 0) {
        goto exit;
    }

    /* Create signature using hash as data */
    switch(sig_type) {
#ifdef HAVE_ECC
        case WC_SIGNATURE_TYPE_ECC:
        {
            /* Validate key size */
            if (key_len < sizeof(ecc_key)) {
                return BAD_FUNC_ARG;
            }
            /* Create signature using provided ECC key */
            ret = wc_ecc_sign_hash(hash_data, hash_len, sig, sig_len, rng, (ecc_key*)key);
            break;
        }
#endif
#ifndef NO_RSA
        case WC_SIGNATURE_TYPE_RSA:
            /* Validate key size */
            if (key_len < sizeof(RsaKey)) {
                return BAD_FUNC_ARG;
            }
            /* Create signature using provided RSA key */
            ret = wc_RsaSSL_Sign(hash_data, hash_len, sig, *sig_len, (RsaKey*)key, rng);
            if (ret > 0) {
                *sig_len = ret;
            }
            break;
#endif

        case WC_SIGNATURE_TYPE_NONE:
        default:
            break;
    }

exit:
    if (hash_data) {
        XFREE(hash_data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    return ret;
}
