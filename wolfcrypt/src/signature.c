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
#include <wolfssl/wolfcrypt/logging.h>

#ifdef HAVE_ECC
#include <wolfssl/wolfcrypt/ecc.h>
#endif
#ifndef NO_RSA
#include <wolfssl/wolfcrypt/rsa.h>
#endif

/* If ECC and RSA are disabled then disable signature wrapper */
#if !defined(HAVE_ECC) && defined(NO_RSA)
#undef NO_SIG_WRAPPER
#define NO_SIG_WRAPPER
#endif

/* Signature wrapper disabled check */
#ifndef NO_SIG_WRAPPER

int wc_SignatureGetSize(enum wc_SignatureType sig_type,
    const void* key, word32 key_len)
{
    int sig_len = BAD_FUNC_ARG;

    /* Supress possible unused args if all signature types are disabled */
    (void)key;
    (void)key_len;

    switch(sig_type) {
#ifdef HAVE_ECC
        case WC_SIGNATURE_TYPE_ECC:
        {
            if (key_len >= sizeof(ecc_key)) {
                sig_len = wc_ecc_sig_size((ecc_key*)key);
            }
            else {
                WOLFSSL_MSG("wc_SignatureGetSize: Invalid ECC key size");
            }
            break;
        }
#endif
#ifndef NO_RSA
        case WC_SIGNATURE_TYPE_RSA:
            if (key_len >= sizeof(RsaKey)) {
                sig_len = wc_RsaEncryptSize((RsaKey*)key);
            }
            else {
                WOLFSSL_MSG("wc_SignatureGetSize: Invalid RsaKey key size");
            }
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

    /* Check arguments */
    if (data == NULL || data_len <= 0 || sig == NULL || sig_len <= 0 ||
        key == NULL || key_len <= 0) {
        return BAD_FUNC_ARG;
    }

    /* Validate signature len (1 to max is okay) */
    if ((int)sig_len > wc_SignatureGetSize(sig_type, key, key_len)) {
        WOLFSSL_MSG("wc_SignatureVerify: Invalid sig type/len");
        return BAD_FUNC_ARG;
    }

    /* Validate hash size */
    hash_len = wc_HashGetDigestSize(hash_type);
    if (hash_len <= 0) {
        WOLFSSL_MSG("wc_SignatureVerify: Invalid hash type/len");
        return BAD_FUNC_ARG;
    }

    /* Allocate temporary buffer for hash data */
    hash_data = (byte*)XMALLOC(hash_len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (hash_data == NULL) {
        return MEMORY_E;
    }

    /* Perform hash of data */
    ret = wc_Hash(hash_type, data, data_len, hash_data, hash_len);
    if(ret == 0) {

        /* Verify signature using hash as data */
        switch(sig_type) {
#ifdef HAVE_ECC
            case WC_SIGNATURE_TYPE_ECC:
            {

                int is_valid_sig = 0;

                /* Perform verification of signature using provided ECC key */
                ret = wc_ecc_verify_hash(sig, sig_len, hash_data, hash_len, &is_valid_sig, (ecc_key*)key);
                if (ret != 0 || is_valid_sig != 1) {
                    ret = SIG_VERIFY_E;
                }
                break;
            }
#endif
#ifndef NO_RSA
            case WC_SIGNATURE_TYPE_RSA:
            {
                byte *plain_data = (byte*)XMALLOC(hash_len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                if (plain_data) {
                    /* Perform verification of signature using provided RSA key */
                    ret = wc_RsaSSL_Verify(sig, sig_len, plain_data, hash_len, (RsaKey*)key);
                    if (ret != hash_len || XMEMCMP(plain_data, hash_data, hash_len) != 0) {
                        ret = SIG_VERIFY_E;
                    }
                    XFREE(plain_data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                }
                else {
                    ret = MEMORY_E;
                }
                break;
            }
#endif

            case WC_SIGNATURE_TYPE_NONE:
            default:
                ret = BAD_FUNC_ARG;
                break;
        }
    }

    if (hash_data) {
        XFREE(hash_data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    return ret;
}

int wc_SignatureGenerate(
    enum wc_HashType hash_type, enum wc_SignatureType sig_type,
    const byte* data, word32 data_len,
    byte* sig, word32 *sig_len,
    const void* key, word32 key_len, WC_RNG* rng)
{
    int ret, hash_len;
    byte *hash_data = NULL;

    /* Supress possible unused arg if all signature types are disabled */
    (void)rng;
    
    /* Check arguments */
    if (data == NULL || data_len <= 0 || sig == NULL || sig_len == NULL ||
        *sig_len <= 0 || key == NULL || key_len <= 0) {
        return BAD_FUNC_ARG;
    }

    /* Validate signature len (needs to be at least max) */
    if ((int)*sig_len < wc_SignatureGetSize(sig_type, key, key_len)) {
        WOLFSSL_MSG("wc_SignatureGenerate: Invalid sig type/len");
        return BAD_FUNC_ARG;
    }

    /* Validate hash size */
    hash_len = wc_HashGetDigestSize(hash_type);
    if (hash_len <= 0) {
        WOLFSSL_MSG("wc_SignatureGenerate: Invalid hash type/len");
        return BAD_FUNC_ARG;
    }

    /* Allocate temporary buffer for hash data */
    hash_data = (byte*)XMALLOC(hash_len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (hash_data == NULL) {
        return MEMORY_E;
    }

    /* Perform hash of data */
    ret = wc_Hash(hash_type, data, data_len, hash_data, hash_len);
    if (ret == 0) {
        /* Create signature using hash as data */
        switch(sig_type) {
#ifdef HAVE_ECC
            case WC_SIGNATURE_TYPE_ECC:
            {
                /* Create signature using provided ECC key */
                ret = wc_ecc_sign_hash(hash_data, hash_len, sig, sig_len, rng, (ecc_key*)key);
                break;
            }
#endif
#ifndef NO_RSA
            case WC_SIGNATURE_TYPE_RSA:
                /* Create signature using provided RSA key */
                ret = wc_RsaSSL_Sign(hash_data, hash_len, sig, *sig_len, (RsaKey*)key, rng);
                if (ret > 0) {
                    *sig_len = ret;
                }
                break;
#endif

            case WC_SIGNATURE_TYPE_NONE:
            default:
                ret = BAD_FUNC_ARG;
                break;
        }
    }

    if (hash_data) {
        XFREE(hash_data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    return ret;
}

#endif /* NO_SIG_WRAPPER */
