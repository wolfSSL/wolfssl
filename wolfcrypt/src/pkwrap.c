/* pkwrap.c
 *
 * Copyright (C) 2006-2018 wolfSSL Inc.
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

/* only enable if ECC and/or RSA is enabled */
#if !defined(NO_PK_WRAPPER) && !defined(HAVE_ECC) && defined(NO_RSA)
    #define NO_PK_WRAPPER
#endif

#ifndef NO_PK_WRAPPER

#include <wolfssl/wolfcrypt/pkwrap.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifndef DER_TMP_BUFFER_LEN
    #define DER_TMP_BUFFER_LEN 2048
#endif

wc_pk_context* wc_pk_new_ex(void* heap, int devId)
{
    wc_pk_context* pk = (wc_pk_context*)XMALLOC(sizeof(wc_pk_context), heap,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (pk) {
        XMEMSET(pk, 0, sizeof(*pk));
        pk->heap = heap;
        pk->devId = devId;
    }
    return pk;
}

wc_pk_context* wc_pk_new(void)
{
    return wc_pk_new_ex(NULL, INVALID_DEVID);
}

wc_pk_type_t wc_pk_get_type(const wc_pk_context *pk)
{
    if (pk)
        return (wc_pk_type_t)pk->type;
    return WOLFSSL_PK_NONE;
}

word32 wc_pk_get_bitlen(const wc_pk_context *pk)
{
    if (pk)
        return pk->keyBits;
    return 0;
}

void* wc_pk_get_key(const wc_pk_context *pk)
{
    if (pk)
        return pk->key.ptr;
    return NULL;
}

int wc_pk_get_key_der(const wc_pk_context *pk, byte* der, word32* derLen)
{
    int ret = -1;
    if (pk && der && derLen) {
        if (*derLen >= pk->derLen)
            return BUFFER_E;
        XMEMCPY(der, pk->der, pk->derLen);
        *derLen = pk->derLen;
        ret = 0;
    }
    return ret;
}

void wc_pk_key_free(wc_pk_context *pk)
{
    /* cleanup keys */
    switch (pk->type) {
        case WOLFSSL_PK_RSA:
        case WOLFSSL_PK_RSASSA_PSS:
    #ifndef NO_RSA
            wc_FreeRsaKey(&pk->key.rsa);
    #endif
            break;
        case WOLFSSL_PK_ECKEY:
        case WOLFSSL_PK_ECKEY_DH:
        case WOLFSSL_PK_ECDSA:
    #ifdef HAVE_ECC
            wc_ecc_free(&pk->key.ecc);
    #endif
            break;

    }
}

int wc_pk_create_key(wc_pk_context *pk, wc_pk_type_t pk_type, int keySz, int curve_id)
{
    int ret = -1;
    WC_RNG rng;

    ret = wc_InitRng(&rng);
    if (ret != 0)
        return ret;

    pk->type = pk_type;
    switch (pk_type) {
        case WOLFSSL_PK_RSA:
        case WOLFSSL_PK_RSASSA_PSS:
        #if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)
            ret = wc_InitRsaKey_ex(&pk->key.rsa, pk->heap, pk->devId);
            if (ret == 0) {
                ret = wc_MakeRsaKey(&pk->key.rsa, keySz, WC_RSA_EXPONENT, &rng);
                if (ret == 0) {
                    pk->keyBits = keySz * 8;
                }
            }
        #endif
            break;
        case WOLFSSL_PK_ECKEY:
        case WOLFSSL_PK_ECKEY_DH:
        case WOLFSSL_PK_ECDSA:
        #ifdef HAVE_ECC
            ret = wc_ecc_init_ex(&pk->key.ecc, pk->heap, pk->devId);
            if (ret == 0) {
                ret = wc_ecc_make_key_ex(&rng, keySz, &pk->key.ecc, curve_id);
                if (ret == 0) {
                    pk->keyBits = keySz * 8;
                }
            }
        #endif
            break;
        case WOLFSSL_PK_NONE:
        default:
            ret = -1;
            break;
    }

    (void)curve_id;
    (void)keySz;

    wc_FreeRng(&rng);

    if (ret != 0) {
        wc_pk_key_free(pk);
    }

    return ret;

}

int wc_pk_load_key(wc_pk_context *pk,
                     const byte *der, word32 derlen)
{
    int ret = -1;
    word32 idx = 0;

    switch (pk->type) {
        case WOLFSSL_PK_RSA:
        case WOLFSSL_PK_RSASSA_PSS:
        #ifndef NO_RSA
            ret = wc_InitRsaKey_ex(&pk->key.rsa, pk->heap, pk->devId);
            if (ret == 0) {
                ret = wc_RsaPrivateKeyDecode(der, &idx, &pk->key.rsa, derlen);
                if (ret == 0) {
                    /* get key size */
                    ret = wc_RsaEncryptSize(&pk->key.rsa);
                    if (ret > 0) {
                        pk->keyBits = ret * 8;
                        ret = 0;
                    }
                    else {
                        ret = -1;
                    }
                }
            }
        #endif
            break;
        case WOLFSSL_PK_ECKEY:
        case WOLFSSL_PK_ECKEY_DH:
        case WOLFSSL_PK_ECDSA:
        #ifdef HAVE_ECC
            ret = wc_ecc_init_ex(&pk->key.ecc, pk->heap, pk->devId);
            if (ret == 0) {
                ret = wc_EccPrivateKeyDecode(der, &idx, &pk->key.ecc, derlen);
                if (ret == 0) {
                    /* get key size */
                    ret = wc_ecc_size(&pk->key.ecc);
                    if (ret > 0) {
                        pk->keyBits = ret * 8;
                        ret = 0;
                    }
                    else {
                        ret = -1;
                    }
                }
            }
        #endif
            break;
    }
    if (ret != 0) {
        wc_pk_key_free(pk);
    }
    return ret;
}

int wc_pk_parse_key(wc_pk_context *pk,
                    const byte *key, word32 keylen,
                    const byte *pwd, word32 pwdlen)
{
    int ret, derLen;
    byte derTmp[DER_TMP_BUFFER_LEN];
    byte* der = derTmp;

    (void)pwdlen;

    if (pk == NULL || key == NULL || keylen <= 0)
        return -1;

    /* convert PEM to der */
    ret = wc_KeyPemToDer(key, keylen, der, sizeof(derTmp), (const char*)pwd);
    if (ret <= 0) {
        /* try using it directly */
        der = (byte*)key;
        derLen = keylen;
    }
    else {
        derLen = ret;
    }

    pk->derLen = derLen;
    pk->der = (byte*)XMALLOC(derLen, pk->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (pk->der) {
        XMEMCPY(pk->der, der, derLen);
    }

    /* try RSA */
    pk->type = WOLFSSL_PK_RSA;
    ret = wc_pk_load_key(pk, der, derLen);
    if (ret != 0) {
        /* try ECC */
        pk->type = WOLFSSL_PK_ECDSA;
        ret = wc_pk_load_key(pk, der, derLen);
    }

    return ret;
}

int wc_pk_sign(wc_pk_context *pk,
               int hashType, int mgf,
               const byte * pucHash,
               unsigned int uiHashLen,
               byte * pucSig,
               word32 * pxSigLen,
               WC_RNG* pRng)
{
    int ret = -1;

    switch (pk->type) {
    #ifndef NO_RSA
        case WOLFSSL_PK_RSA:
        #ifdef WC_RSA_PSS
        case WOLFSSL_PK_RSASSA_PSS:
        #endif
        {
            if (pk->type == WOLFSSL_PK_RSA)
                ret = wc_RsaSSL_Sign(pucHash, uiHashLen, pucSig, *pxSigLen,
                    &pk->key.rsa, pRng);
        #ifdef WC_RSA_PSS
            else
                ret = wc_RsaPSS_Sign(pucHash, uiHashLen, pucSig, *pxSigLen,
                    (enum wc_HashType)hashType, mgf, &pk->key.rsa, pRng);
        #endif
            if (ret > 0) {
                *pxSigLen = ret;
                ret = 0;
            }
            else {
                ret = BAD_FUNC_ARG;
            }
            break;
        }
    #endif /* !NO_RSA */
    #ifdef HAVE_ECC
        case WOLFSSL_PK_ECKEY:
        case WOLFSSL_PK_ECKEY_DH:
        case WOLFSSL_PK_ECDSA:
            ret = wc_ecc_sign_hash(pucHash, uiHashLen, pucSig, pxSigLen, pRng, &pk->key.ecc);
            break;
    #endif /* HAVE_ECC */
        default:
            break;
    }

    (void)pk;
    (void)hashType;
    (void)pucHash;
    (void)uiHashLen;
    (void)pucSig;
    (void)pxSigLen;
    (void)pRng;
    (void)mgf;

    return ret;
}

int wc_pk_verify(wc_pk_context *pk,
                 int hashType, int mgf,
                 const byte * pucHash,
                 unsigned int uiHashLen,
                 const byte * pucSig,
                 word32 ulSigLen)
{
    int ret = -1;

    switch (pk->type) {
    #ifndef NO_RSA
        case WOLFSSL_PK_RSA:
        #ifdef WC_RSA_PSS
        case WOLFSSL_PK_RSASSA_PSS:
        #endif
        {
            byte* plain = (byte*)XMALLOC(ulSigLen, pk->heap,
                DYNAMIC_TYPE_TMP_BUFFER);
            if (plain == NULL)
                return MEMORY_E;

            if (pk->type == WOLFSSL_PK_RSA)
                ret = wc_RsaSSL_Verify(pucHash, uiHashLen, plain, ulSigLen,
                    &pk->key.rsa);
        #ifdef WC_RSA_PSS
            else
                ret = wc_RsaPSS_Verify((byte*)pucHash, uiHashLen, plain, ulSigLen,
                    (enum wc_HashType)hashType, mgf, &pk->key.rsa);
        #endif
            if ((int)ulSigLen == ret &&
                XMEMCMP(pucSig, plain, ret) == 0) {
                ret = 0;
            }
            else {
                ret = SIG_VERIFY_E;
            }
            XFREE(plain, pk->heap, DYNAMIC_TYPE_TMP_BUFFER);
            break;
        }
    #endif /* !NO_RSA */
    #ifdef HAVE_ECC
        case WOLFSSL_PK_ECKEY:
        case WOLFSSL_PK_ECKEY_DH:
        case WOLFSSL_PK_ECDSA:
        {
            int verify = 0;
            ret = wc_ecc_verify_hash(pucSig, ulSigLen, pucHash, uiHashLen,
                &verify, &pk->key.ecc);
            if (ret == 0 && verify == 1) {
                ret = 0;
            }
            else {
                ret = SIG_VERIFY_E;
            }
            break;
        }
    #endif /* HAVE_ECC */
        default:
            break;
    }

    (void)pk;
    (void)hashType;
    (void)pucHash;
    (void)uiHashLen;
    (void)pucSig;
    (void)ulSigLen;
    (void)mgf;

    return ret;
}


void wc_pk_free(wc_pk_context *pk)
{
    if (pk == NULL)
        return;

    /* cleanup keys */
    wc_pk_key_free(pk);

    if (pk->der) {
        XFREE(pk->der, pk->heap, DYNAMIC_TYPE_TMP_BUFFER);
        pk->der = NULL;
    }

    XFREE(pk, pk->heap, DYNAMIC_TYPE_TMP_BUFFER);
}

#endif /* NO_PK_WRAPPER */
