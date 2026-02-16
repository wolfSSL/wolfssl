/* ssl_api_pk.c
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

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#if !defined(WOLFSSL_SSL_API_PK_INCLUDED)
    #ifndef WOLFSSL_IGNORE_FILE_WARN
        #warning ssl_api_pk.c is not compiled separately from ssl.c
    #endif
#else

#ifndef NO_CERTS

#ifndef NO_CHECK_PRIVATE_KEY

#ifdef WOLF_PRIVATE_KEY_ID
/* Check priv against pub for match using external device with given devId
 *
 * @param [in] keyOID   Public key OID.
 * @param [in] privKey  Private key data.
 * @param [in] privSz   Length of private key data in bytes.
 * @param [in] pubKey   Public key data.
 * @param [in] pubSz    Length of public key data in bytes.
 * @param [in] label    Key data is a hardware label.
 * @param [in] id       Key data is a hardware id.
 * @param [in] heap     Heap hint for dynamic memory allocation.
 * @param [in] devId    Device Id.
 * @return  0 on success.
 * @return  MISSING_KEY when privKey is NULL.
 * @return  Other negative value on error.
 */
static int check_cert_key_dev(word32 keyOID, byte* privKey, word32 privSz,
    const byte* pubKey, word32 pubSz, int label, int id, void* heap, int devId)
{
    int ret = 0;
    int type = 0;
    void *pkey = NULL;

    if (privKey == NULL) {
        ret = MISSING_KEY;
    }
    else {
        switch (keyOID) {
    #ifndef NO_RSA
            case RSAk:
        #ifdef WC_RSA_PSS
            case RSAPSSk:
        #endif
                type = DYNAMIC_TYPE_RSA;
                break;
    #endif
        #ifdef HAVE_ECC
            case ECDSAk:
                type = DYNAMIC_TYPE_ECC;
                break;
        #endif
    #if defined(HAVE_DILITHIUM)
            case ML_DSA_LEVEL2k:
            case ML_DSA_LEVEL3k:
            case ML_DSA_LEVEL5k:
        #ifdef WOLFSSL_DILITHIUM_FIPS204_DRAFT
            case DILITHIUM_LEVEL2k:
            case DILITHIUM_LEVEL3k:
            case DILITHIUM_LEVEL5k:
        #endif
                type = DYNAMIC_TYPE_DILITHIUM;
                break;
    #endif
    #if defined(HAVE_FALCON)
            case FALCON_LEVEL1k:
            case FALCON_LEVEL5k:
                type = DYNAMIC_TYPE_FALCON;
                break;
    #endif
        }

        ret = CreateDevPrivateKey(&pkey, privKey, privSz, type, label, id, heap,
            devId);
    }
#ifdef WOLF_CRYPTO_CB
    if (ret == 0) {
        switch (keyOID) {
    #ifndef NO_RSA
            case RSAk:
        #ifdef WC_RSA_PSS
            case RSAPSSk:
        #endif
                ret = wc_CryptoCb_RsaCheckPrivKey((RsaKey*)pkey, pubKey, pubSz);
                break;
    #endif
    #ifdef HAVE_ECC
            case ECDSAk:
                ret = wc_CryptoCb_EccCheckPrivKey((ecc_key*)pkey, pubKey,
                    pubSz);
                break;
    #endif
    #if defined(HAVE_DILITHIUM)
            case ML_DSA_LEVEL2k:
            case ML_DSA_LEVEL3k:
            case ML_DSA_LEVEL5k:
        #ifdef WOLFSSL_DILITHIUM_FIPS204_DRAFT
            case DILITHIUM_LEVEL2k:
            case DILITHIUM_LEVEL3k:
            case DILITHIUM_LEVEL5k:
        #endif
                ret = wc_CryptoCb_PqcSignatureCheckPrivKey(pkey,
                    WC_PQC_SIG_TYPE_DILITHIUM, pubKey, pubSz);
                break;
    #endif
    #if defined(HAVE_FALCON)
            case FALCON_LEVEL1k:
            case FALCON_LEVEL5k:
                ret = wc_CryptoCb_PqcSignatureCheckPrivKey(pkey,
                    WC_PQC_SIG_TYPE_FALCON, pubKey, pubSz);
                break;
    #endif
            default:
                ret = 0;
        }
    }
#else
    /* devId was set, don't check, for now */
    /* TODO: Add callback for private key check? */
    (void) pubKey;
    (void) pubSz;
#endif

    switch (keyOID) {
    #ifndef NO_RSA
        case RSAk:
        #ifdef WC_RSA_PSS
        case RSAPSSk:
        #endif
            wc_FreeRsaKey((RsaKey*)pkey);
            break;
    #endif
    #ifdef HAVE_ECC
        case ECDSAk:
            wc_ecc_free((ecc_key*)pkey);
            break;
    #endif
    #if defined(HAVE_DILITHIUM)
        case ML_DSA_LEVEL2k:
        case ML_DSA_LEVEL3k:
        case ML_DSA_LEVEL5k:
        #ifdef WOLFSSL_DILITHIUM_FIPS204_DRAFT
        case DILITHIUM_LEVEL2k:
        case DILITHIUM_LEVEL3k:
        case DILITHIUM_LEVEL5k:
        #endif
            wc_dilithium_free((dilithium_key*)pkey);
            break;
    #endif
    #if defined(HAVE_FALCON)
        case FALCON_LEVEL1k:
        case FALCON_LEVEL5k:
            wc_falcon_free((falcon_key*)pkey);
            break;
    #endif
        default:
            WC_DO_NOTHING;
    }
    XFREE(pkey, heap, type);

    return ret;
}
#endif /* WOLF_PRIVATE_KEY_ID */

/* Check private against public in certificate for match.
 *
 * @param [in] cert           DER encoded certificate.
 * @param [in] key            DER encoded private key.
 * @param [in] altKey         Alternative DER encoded key.
 * @param [in] heap           Heap hint for dynamic memory allocation.
 * @param [in] devId          Device Id.
 * @param [in] isKeyLabel     Whether key is label.
 * @param [in] isKeyId        Whether key is an id.
 * @param [in] altDevId       Alternative key's device id.
 * @param [in] isAltKeyLabel  Is alternative key a label.
 * @param [in] isAltKeyId     Is alternative key an id.
 * @return  1 on success.
 * @return  0 on failure.
 * @return  MEMORY_E when memory allocation fails.
 */
static int check_cert_key(const DerBuffer* cert, const DerBuffer* key,
    const DerBuffer* altKey, void* heap, int devId, int isKeyLabel, int isKeyId,
    int altDevId, int isAltKeyLabel, int isAltKeyId)
{
    WC_DECLARE_VAR(der, DecodedCert, 1, 0);
    word32 size;
    byte*  buff;
    int    ret = 1;

    WOLFSSL_ENTER("check_cert_key");

    /* Validate parameters. */
    if ((cert == NULL) || (key == NULL)) {
        return 0;
    }
    if (ret == 1) {
        /* Make a decoded certificate object available. */
        WC_ALLOC_VAR_EX(der, DecodedCert, 1, heap, DYNAMIC_TYPE_DCERT,
            return MEMORY_E);
    }

    if (ret == 1) {
        /* Decode certificate. */
        InitDecodedCert_ex(der, cert->buffer, cert->length, heap, devId);
        /* Parse certificate. */
        if (ParseCertRelative(der, CERT_TYPE, NO_VERIFY, NULL, NULL) != 0) {
            WC_FREE_VAR_EX(der, heap, DYNAMIC_TYPE_DCERT);
            ret = 0;
        }
     }

     if (ret == 1) {
        buff = key->buffer;
        size = key->length;
    #ifdef WOLF_PRIVATE_KEY_ID
        if (devId != INVALID_DEVID) {
            ret = check_cert_key_dev(der->keyOID, buff, size, der->publicKey,
                der->pubKeySize, isKeyLabel, isKeyId, heap, devId);
            if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE)) {
                ret = (ret == 0) ? WOLFSSL_SUCCESS: WOLFSSL_FAILURE;
            }
        }
        else {
            /* fall through if unavailable */
            ret = CRYPTOCB_UNAVAILABLE;
        }

        if (ret == WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
    #endif /* WOLF_PRIVATE_KEY_ID */
        {
            ret = wc_CheckPrivateKeyCert(buff, size, der, 0, heap);
            if (ret != 1) {
                ret = 0;
            }
        }

    #ifdef WOLFSSL_DUAL_ALG_CERTS
        if ((ret == 1) && der->extSapkiSet && (der->sapkiDer != NULL)) {
            /* Certificate contains an alternative public key. Hence, we also
             * need an alternative private key. */
            if (altKey == NULL) {
                ret = MISSING_KEY;
                buff = NULL;
                size = 0;
            }
            else {
                size = altKey->length;
                buff = altKey->buffer;
            }
        #ifdef WOLF_PRIVATE_KEY_ID
            if (altDevId != INVALID_DEVID) {
                /* We have to decode the public key first */
                /* Default to max pub key size. */
                word32 pubKeyLen = MAX_PUBLIC_KEY_SZ;
                byte* decodedPubKey = (byte*)XMALLOC(pubKeyLen, heap,
                    DYNAMIC_TYPE_PUBLIC_KEY);
                if (decodedPubKey == NULL) {
                    ret = MEMORY_E;
                }
                if (ret == WOLFSSL_SUCCESS) {
                    if ((der->sapkiOID == RSAk) || (der->sapkiOID == ECDSAk)) {
                        /* Simply copy the data */
                        XMEMCPY(decodedPubKey, der->sapkiDer, der->sapkiLen);
                        pubKeyLen = der->sapkiLen;
                        ret = 0;
                    }
                    else {
                    #if defined(WC_ENABLE_ASYM_KEY_IMPORT)
                        word32 idx = 0;
                        ret = DecodeAsymKeyPublic(der->sapkiDer, &idx,
                                                  der->sapkiLen, decodedPubKey,
                                                  &pubKeyLen, der->sapkiOID);
                    #else
                        ret = NOT_COMPILED_IN;
                    #endif /* WC_ENABLE_ASYM_KEY_IMPORT */
                    }
                }
                if (ret == 0) {
                    ret = check_cert_key_dev(der->sapkiOID, buff, size,
                        decodedPubKey, pubKeyLen, isAltKeyLabel, isAltKeyId,
                        heap, altDevId);
                }
                XFREE(decodedPubKey, heap, DYNAMIC_TYPE_PUBLIC_KEY);
                if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE)) {
                    ret = (ret == 0) ? 1: 0;
                }
            }
            else {
                /* fall through if unavailable */
                ret = CRYPTOCB_UNAVAILABLE;
            }

            if (ret == WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
        #else
            if (ret == 1)
        #endif /* WOLF_PRIVATE_KEY_ID */
            {
                ret = wc_CheckPrivateKeyCert(buff, size, der, 1, heap);
                if (ret != 1) {
                    ret = 0;
                }
            }
        }
    #endif /* WOLFSSL_DUAL_ALG_CERTS */
    }

    FreeDecodedCert(der);
    WC_FREE_VAR_EX(der, heap, DYNAMIC_TYPE_DCERT);

    (void)devId;
    (void)isKeyLabel;
    (void)isKeyId;
    (void)altKey;
    (void)altDevId;
    (void)isAltKeyLabel;
    (void)isAltKeyId;

    return ret;
}

/* Check private against public in certificate for match
 *
 * @param [in] ctx  SSL/TLS context with a private key and certificate.
 *
 * @return  1 on good private key
 * @return  0 if mismatched.
 */
int wolfSSL_CTX_check_private_key(const WOLFSSL_CTX* ctx)
{
    int res = 1;
#ifdef WOLFSSL_BLIND_PRIVATE_KEY
    DerBuffer *privateKey;
#ifdef WOLFSSL_DUAL_ALG_CERTS
    DerBuffer *altPrivateKey;
#endif
#else
    const DerBuffer *privateKey;
#ifdef WOLFSSL_DUAL_ALG_CERTS
    const DerBuffer *altPrivateKey;
#endif
#endif

    /* Validate parameter. */
    if (ctx == NULL) {
        res = 0;
    }
    else {
#ifdef WOLFSSL_DUAL_ALG_CERTS
    #ifdef WOLFSSL_BLIND_PRIVATE_KEY
        /* Unblind private keys. */
        privateKey = wolfssl_priv_der_unblind(ctx->privateKey,
            ctx->privateKeyMask);
        if (privateKey == NULL) {
            res = 0;
        }
        if (ctx->altPrivateKey != NULL) {
            altPrivateKey = wolfssl_priv_der_unblind(ctx->altPrivateKey,
                ctx->altPrivateKeyMask);
            if (altPrivateKey == NULL) {
                res = 0;
            }
        }
        else {
            altPrivateKey = NULL;
        }
    #else
        privateKey = ctx->privateKey;
        altPrivateKey = ctx->altPrivateKey;
    #endif
        if (res == 1) {
            /* Check certificate and private keys. */
            res = check_cert_key(ctx->certificate, privateKey, altPrivateKey,
                ctx->heap, ctx->privateKeyDevId, ctx->privateKeyLabel,
                ctx->privateKeyId, ctx->altPrivateKeyDevId,
                ctx->altPrivateKeyLabel, ctx->altPrivateKeyId) != 0;
        }
    #ifdef WOLFSSL_BLIND_PRIVATE_KEY
        /* Dispose of the unblinded buffers. */
        wolfssl_priv_der_unblind_free(privateKey);
        wolfssl_priv_der_unblind_free(altPrivateKey);
    #endif
#else
    #ifdef WOLFSSL_BLIND_PRIVATE_KEY
        /* Unblind private key. */
        privateKey = wolfssl_priv_der_unblind(ctx->privateKey,
            ctx->privateKeyMask);
        if (privateKey == NULL) {
            res = 0;
        }
    #else
        privateKey = ctx->privateKey;
    #endif
        if (res == WOLFSSL_SUCCESS) {
            /* Check certificate and private key. */
            res = check_cert_key(ctx->certificate, privateKey, NULL, ctx->heap,
                ctx->privateKeyDevId, ctx->privateKeyLabel, ctx->privateKeyId,
                INVALID_DEVID, 0, 0);
        }
    #ifdef WOLFSSL_BLIND_PRIVATE_KEY
        /* Dispose of the unblinded buffer. */
        wolfssl_priv_der_unblind_free(privateKey);
    #endif
#endif
    }

    /* Place error into queue for Python port. */
    if (res != 1) {
        WOLFSSL_ERROR(WC_KEY_MISMATCH_E);
    }

    return res;
}

#ifdef OPENSSL_EXTRA
/* Check private against public in certificate for match.
 *
 * @param [in] ssl  SSL/TLS object with a private key and certificate.
 *
 * @return  1 on good private key
 * @return  0 if mismatched.
 */
int wolfSSL_check_private_key(const WOLFSSL* ssl)
{
    int res = 1;
#ifdef WOLFSSL_BLIND_PRIVATE_KEY
    DerBuffer *privateKey;
#ifdef WOLFSSL_DUAL_ALG_CERTS
    DerBuffer *altPrivateKey;
#endif
#else
    const DerBuffer *privateKey;
#ifdef WOLFSSL_DUAL_ALG_CERTS
    const DerBuffer *altPrivateKey;
#endif
#endif

    /* Validate parameter. */
    if (ssl == NULL) {
        res = 0;
    }
    else {
#ifdef WOLFSSL_DUAL_ALG_CERTS
    #ifdef WOLFSSL_BLIND_PRIVATE_KEY
        /* Unblind private keys. */
        privateKey = wolfssl_priv_der_unblind(ssl->buffers.key,
            ssl->buffers.keyMask);
        if (privateKey == NULL) {
            res = 0;
        }
        if (ssl->buffers.altKey != NULL) {
            altPrivateKey = wolfssl_priv_der_unblind(ssl->buffers.altKey,
                ssl->buffers.altKeyMask);
            if (altPrivateKey == NULL) {
                res = 0;
            }
        }
        else {
            altPrivateKey = NULL;
        }
    #else
        privateKey = ssl->buffers.key;
        altPrivateKey = ssl->buffers.altKey;
    #endif
        if (res == 1) {
            /* Check certificate and private keys. */
            res = check_cert_key(ssl->buffers.certificate, privateKey,
                altPrivateKey, ssl->heap, ssl->buffers.keyDevId,
                ssl->buffers.keyLabel, ssl->buffers.keyId,
                ssl->buffers.altKeyDevId, ssl->buffers.altKeyLabel,
                ssl->buffers.altKeyId);
        }
    #ifdef WOLFSSL_BLIND_PRIVATE_KEY
        /* Dispose of the unblinded buffers. */
        wolfssl_priv_der_unblind_free(privateKey);
        wolfssl_priv_der_unblind_free(altPrivateKey);
    #endif
#else
    #ifdef WOLFSSL_BLIND_PRIVATE_KEY
        /* Unblind private key. */
        privateKey = wolfssl_priv_der_unblind(ssl->buffers.key,
            ssl->buffers.keyMask);
        if (privateKey == NULL) {
            res = 0;
        }
    #else
        privateKey = ssl->buffers.key;
    #endif
        if (res == 1) {
            /* Check certificate and private key. */
            res = check_cert_key(ssl->buffers.certificate, privateKey, NULL,
                ssl->heap, ssl->buffers.keyDevId, ssl->buffers.keyLabel,
                ssl->buffers.keyId, INVALID_DEVID, 0, 0);
        }
    #ifdef WOLFSSL_BLIND_PRIVATE_KEY
        /* Dispose of the unblinded buffer. */
        wolfssl_priv_der_unblind_free(privateKey);
    #endif
#endif
    }

    return res;
}
#endif /* OPENSSL_EXTRA */
#endif /* !NO_CHECK_PRIVATE_KEY */


#ifdef OPENSSL_ALL
/**
 * Return the private key of the SSL/TLS context.
 *
 * The caller doesn *NOT*` free the returned object.
 *
 * Note, even though the supplied ctx pointer is designated const, on success
 * ctx->privateKeyPKey is changed by this call.  The change is done safely using
 * a hardware-synchronized store.
 *
 * @param [in] ctx  SSL/TLS context.
 * @return  A WOFLSSL_EVP_PKEY on success.
 * @return  NULL on error.
 */
WOLFSSL_EVP_PKEY* wolfSSL_CTX_get0_privatekey(const WOLFSSL_CTX* ctx)
{
    WOLFSSL_EVP_PKEY* res = NULL;
    const unsigned char *key;
    int type = WC_EVP_PKEY_NONE;

    WOLFSSL_ENTER("wolfSSL_CTX_get0_privatekey");

    if ((ctx == NULL) || (ctx->privateKey == NULL) ||
            (ctx->privateKey->buffer == NULL)) {
        WOLFSSL_MSG("Bad parameter or key not set");
    }
    else {
        switch (ctx->privateKeyType) {
    #ifndef NO_RSA
            case rsa_sa_algo:
                type = WC_EVP_PKEY_RSA;
                break;
    #endif
    #ifdef HAVE_ECC
            case ecc_dsa_sa_algo:
                type = WC_EVP_PKEY_EC;
                break;
    #endif
    #ifdef WOLFSSL_SM2
            case sm2_sa_algo:
                type = WC_EVP_PKEY_EC;
                break;
    #endif
            default:
                /* Other key types not supported either as ssl private keys
                 * or in the EVP layer */
                WOLFSSL_MSG("Unsupported key type");
        }
    }

    if (type != WC_EVP_PKEY_NONE) {
        if (ctx->privateKeyPKey != NULL) {
            res = ctx->privateKeyPKey;
        }
        else {
        #ifdef WOLFSSL_BLIND_PRIVATE_KEY
            DerBuffer* unblinded_privateKey = wolfssl_priv_der_unblind(
                ctx->privateKey, ctx->privateKeyMask);
            if (unblinded_privateKey != NULL) {
                key = unblinded_privateKey->buffer;
            }
            else {
                key = NULL;
            }
        #else
            key = ctx->privateKey->buffer;
        #endif
            if (key != NULL) {
                res = wolfSSL_d2i_PrivateKey(type, NULL, &key,
                    (long)ctx->privateKey->length);
            #ifdef WOLFSSL_BLIND_PRIVATE_KEY
                wolfssl_priv_der_unblind_free(unblinded_privateKey);
            #endif
            }
            if (res != NULL) {
            #ifdef WOLFSSL_ATOMIC_OPS
                WOLFSSL_EVP_PKEY *current_pkey = NULL;
                if (!wolfSSL_Atomic_Ptr_CompareExchange(
                        (void * volatile *)&ctx->privateKeyPKey,
                        (void **)&current_pkey, res)) {
                    wolfSSL_EVP_PKEY_free(res);
                    res = current_pkey;
                }
            #else
                ((WOLFSSL_CTX *)ctx)->privateKeyPKey = res;
            #endif
            }
        }
    }

    return res;
}
#endif /* OPENSSL_ALL */

#ifdef HAVE_ECC

/* Set size, in bytes, of temporary ECDHE key into SSL/TLS context.
 *
 * Values can be: 14 - 66 (112 - 521 bit)
 * Uses the private key length if sz is 0.
 *
 * @param [in] ctx  SSL/TLS context.
 * @param [in] sz   Size of EC key in bytes.
 * @return  1 on success.
 * @return  BAD_FUNC_ARG when ctx is NULL or sz is invalid.
 */
int wolfSSL_CTX_SetTmpEC_DHE_Sz(WOLFSSL_CTX* ctx, word16 sz)
{
    int ret = 0;

    WOLFSSL_ENTER("wolfSSL_CTX_SetTmpEC_DHE_Sz");

    /* Validate parameters. */
    if (ctx == NULL) {
        ret = BAD_FUNC_ARG;
    }
    /* If size is 0 then get value from loaded private key. */
    else if (sz == 0) {
        /* Applies only to ECDSA. */
        if (ctx->privateKeyType != ecc_dsa_sa_algo) {
            ret = 1;
        }
        /* Must have a key set. */
        else if (ctx->privateKeySz == 0) {
            WOLFSSL_MSG("Must set private key/cert first");
            ret = BAD_FUNC_ARG;
        }
        else {
            sz = (word16)ctx->privateKeySz;
        }
    }
    if (ret == 0) {
        /* Check size against bounds. */
    #if ECC_MIN_KEY_SZ > 0
        if (sz < ECC_MINSIZE) {
            ret = BAD_FUNC_ARG;
        }
        else
    #endif
        if (sz > ECC_MAXSIZE) {
            ret = BAD_FUNC_ARG;
        }
        else {
            /* Store the size requested. */
            ctx->eccTempKeySz = sz;
            ret = 1;
        }
    }

    return ret;
}


/* Set size, in bytes, of temporary ECDHE key into SSL/TLS object.
 *
 * Values can be: 14 - 66 (112 - 521 bit)
 * Uses the private key length if sz is 0.
 *
 * @param [in] ssl  SSL/TLS object.
 * @param [in] sz   Size of EC key in bytes.
 * @return  1 on success.
 * @return  BAD_FUNC_ARG when ssl is NULL or sz is invalid.
 */
int wolfSSL_SetTmpEC_DHE_Sz(WOLFSSL* ssl, word16 sz)
{
    int ret = 1;

    WOLFSSL_ENTER("wolfSSL_SetTmpEC_DHE_Sz");

    /* Validate parameters. */
    if (ssl == NULL) {
        ret = BAD_FUNC_ARG;
    }
    /* Check size against bounds. */
#if ECC_MIN_KEY_SZ > 0
    else if (sz < ECC_MINSIZE) {
        ret = BAD_FUNC_ARG;
    }
#endif
    else if (sz > ECC_MAXSIZE) {
        ret = BAD_FUNC_ARG;
    }
    else {
        /* Store the size requested. */
        ssl->eccTempKeySz = sz;
    }

    return ret;
}

#endif /* HAVE_ECC */

#ifdef  HAVE_PK_CALLBACKS

#ifdef HAVE_ECC
/* Set the ECC key generation callback into the SSL/TLS context.
 *
 * @param [in] ctx  SSL/TLS context.
 * @param [in] cb   ECC key generation callback.
 */
void  wolfSSL_CTX_SetEccKeyGenCb(WOLFSSL_CTX* ctx, CallbackEccKeyGen cb)
{
    if (ctx != NULL) {
        ctx->EccKeyGenCb = cb;
    }
}
/* Set the context for ECC key generation callback into the SSL/TLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @param [in] ctx  Context for ECC key generation callback.
 */
void  wolfSSL_SetEccKeyGenCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl != NULL) {
        ssl->EccKeyGenCtx = ctx;
    }
}
/* Get the context for ECC key generation callback from the SSL/TLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  Context for ECC key generation callback.
 * @return  NULL when ssl is NULL.
 */
void* wolfSSL_GetEccKeyGenCtx(WOLFSSL* ssl)
{
    void* ret;

    if (ssl == NULL) {
        ret = NULL;
    }
    else {
        ret = ssl->EccKeyGenCtx;
    }

    return ret;
}
/* Set the context for ECC sign callback into the SSL/TLS context.
 *
 * @param [in] ctx  SSL/TLS context.
 * @param [in] userCtx  Context for ECC sign callback.
 */
void  wolfSSL_CTX_SetEccSignCtx(WOLFSSL_CTX* ctx, void *userCtx)
{
    if (ctx != NULL) {
        ctx->EccSignCtx = userCtx;
    }
}
/* Get the context for ECC sign callback from the SSL/TLS context.
 *
 * @param [in] ctx  SSL/TLS context.
 * @return  Context for ECC sign for callback.
 * @return  NULL when ctx is NULL.
 */
void* wolfSSL_CTX_GetEccSignCtx(WOLFSSL_CTX* ctx)
{
    void* ret;

    if (ctx == NULL) {
        ret = NULL;
    }
    else {
        ret = ctx->EccSignCtx;
    }

    return ret;
}

/* Set the ECC sign callback into the SSL/TLS context.
 *
 * @param [in] ctx  SSL/TLS context.
 * @param [in] cb   ECC sign callback.
 */
WOLFSSL_ABI void wolfSSL_CTX_SetEccSignCb(WOLFSSL_CTX* ctx, CallbackEccSign cb)
{
    if (ctx != NULL) {
        ctx->EccSignCb = cb;
    }
}
/* Set the context for ECC sign callback into the SSL/TLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @param [in] ctx  Context for ECC sign callback.
 */
void wolfSSL_SetEccSignCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl != NULL) {
        ssl->EccSignCtx = ctx;
    }
}
/* Get the context for ECC sign callback from the SSL/TLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  Context for ECC sign for callback.
 * @return  NULL when ssl is NULL.
 */
void* wolfSSL_GetEccSignCtx(WOLFSSL* ssl)
{
    void* ret;

    if (ssl == NULL) {
        ret = NULL;
    }
    else {
        ret = ssl->EccSignCtx;
    }

    return ret;
}

/* Set the ECC verify callback into the SSL/TLS context.
 *
 * @param [in] ctx  SSL/TLS context.
 * @param [in] cb   ECC verify callback.
 */
void  wolfSSL_CTX_SetEccVerifyCb(WOLFSSL_CTX* ctx, CallbackEccVerify cb)
{
    if (ctx != NULL) {
        ctx->EccVerifyCb = cb;
    }
}
/* Set the context for ECC verify callback into the SSL/TLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @param [in] ctx  Context for ECC verify callback.
 */
void  wolfSSL_SetEccVerifyCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl != NULL) {
        ssl->EccVerifyCtx = ctx;
    }
}
/* Get the context for ECC verify callback from the SSL/TLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  Context for ECC verify for callback.
 * @return  NULL when ssl is NULL.
 */
void* wolfSSL_GetEccVerifyCtx(WOLFSSL* ssl)
{
    void* ret;

    if (ssl == NULL) {
        ret = NULL;
    }
    else {
        ret = ssl->EccVerifyCtx;
    }

    return ret;
}

/* Set the ECC shared secret callback into the SSL/TLS context.
 *
 * @param [in] ctx  SSL/TLS context.
 * @param [in] cb   ECC shared secret callback.
 */
void wolfSSL_CTX_SetEccSharedSecretCb(WOLFSSL_CTX* ctx,
    CallbackEccSharedSecret cb)
{
    if (ctx != NULL) {
        ctx->EccSharedSecretCb = cb;
    }
}
/* Set the context for ECC shared secret callback into the SSL/TLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @param [in] ctx  Context for ECC shared secret callback.
 */
void  wolfSSL_SetEccSharedSecretCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl != NULL) {
        ssl->EccSharedSecretCtx = ctx;
    }
}
/* Get the context for ECC shared secret callback from the SSL/TLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  Context for ECC shared secret callback.
 * @return  NULL when ssl is NULL.
 */
void* wolfSSL_GetEccSharedSecretCtx(WOLFSSL* ssl)
{
    void* ret;

    if (ssl == NULL) {
        ret = NULL;
    }
    else {
        ret = ssl->EccSharedSecretCtx;
    }

    return ret;
}
#endif /* HAVE_ECC */

#ifdef HAVE_ED25519
/* Set the Ed25519 sign callback into the SSL/TLS context.
 *
 * @param [in] ctx  SSL/TLS context.
 * @param [in] cb   Ed25519 sign callback.
 */
void  wolfSSL_CTX_SetEd25519SignCb(WOLFSSL_CTX* ctx, CallbackEd25519Sign cb)
{
    if (ctx != NULL) {
        ctx->Ed25519SignCb = cb;
    }
}
/* Set the context for Ed25519 sign callback into the SSL/TLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @param [in] ctx  Context for Ed25519 sign callback.
 */
void  wolfSSL_SetEd25519SignCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl != NULL) {
        ssl->Ed25519SignCtx = ctx;
    }
}
/* Get the context for Ed25519 sign callback from the SSL/TLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  Context for Ed25519 sign callback.
 * @return  NULL when ssl is NULL.
 */
void* wolfSSL_GetEd25519SignCtx(WOLFSSL* ssl)
{
    void* ret;

    if (ssl == NULL) {
        ret = NULL;
    }
    else {
        ret = ssl->Ed25519SignCtx;
    }

    return ret;
}

/* Set the Ed25519 verify callback into the SSL/TLS context.
 *
 * @param [in] ctx  SSL/TLS context.
 * @param [in] cb   Ed25519 verify callback.
 */
void  wolfSSL_CTX_SetEd25519VerifyCb(WOLFSSL_CTX* ctx, CallbackEd25519Verify cb)
{
    if (ctx != NULL) {
        ctx->Ed25519VerifyCb = cb;
    }
}
/* Set the context for Ed25519 verify callback into the SSL/TLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @param [in] ctx  Context for Ed25519 verify callback.
 */
void  wolfSSL_SetEd25519VerifyCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl != NULL) {
        ssl->Ed25519VerifyCtx = ctx;
    }
}
/* Get the context for Ed25519 verify callback from the SSL/TLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  Context for Ed25519 verify callback.
 * @return  NULL when ssl is NULL.
 */
void* wolfSSL_GetEd25519VerifyCtx(WOLFSSL* ssl)
{
    void* ret;

    if (ssl == NULL) {
        ret = NULL;
    }
    else {
        ret = ssl->Ed25519VerifyCtx;
    }

    return ret;
}
#endif /* HAVE_ED25519 */

#ifdef HAVE_CURVE25519
/* Set the X25519 key generation callback into the SSL/TLS context.
 *
 * @param [in] ctx  SSL/TLS context.
 * @param [in] cb   X25519 key generation callback.
 */
void wolfSSL_CTX_SetX25519KeyGenCb(WOLFSSL_CTX* ctx, CallbackX25519KeyGen cb)
{
    if (ctx != NULL) {
        ctx->X25519KeyGenCb = cb;
    }
}
/* Set the context for X25519 key generation callback into the SSL/TLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @param [in] ctx  Context for X25519 key generation callback.
 */
void  wolfSSL_SetX25519KeyGenCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl != NULL) {
        ssl->X25519KeyGenCtx = ctx;
    }
}
/* Get the context for X25519 key generation callback from the SSL/TLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  Context for X25519 key generation callback.
 * @return  NULL when ssl is NULL.
 */
void* wolfSSL_GetX25519KeyGenCtx(WOLFSSL* ssl)
{
    void* ret;

    if (ssl == NULL) {
        ret = NULL;
    }
    else {
        ret = ssl->X25519KeyGenCtx;
    }

    return ret;
}

/* Set the X25519 shared secret callback into the SSL/TLS context.
 *
 * @param [in] ctx  SSL/TLS context.
 * @param [in] cb   X25519 shared secret callback.
 */
void wolfSSL_CTX_SetX25519SharedSecretCb(WOLFSSL_CTX* ctx,
    CallbackX25519SharedSecret cb)
{
    if (ctx != NULL) {
        ctx->X25519SharedSecretCb = cb;
    }
}
/* Set the context for X25519 shared secret callback into the SSL/TLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @param [in] ctx  Context for X25519 shared secret callback.
 */
void  wolfSSL_SetX25519SharedSecretCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl != NULL) {
        ssl->X25519SharedSecretCtx = ctx;
    }
}
/* Get the context for X25519 shared secret callback from the SSL/TLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  Context for X25519 shared secret callback.
 * @return  NULL when ssl is NULL.
 */
void* wolfSSL_GetX25519SharedSecretCtx(WOLFSSL* ssl)
{
    void* ret;

    if (ssl == NULL) {
        ret = NULL;
    }
    else {
        ret = ssl->X25519SharedSecretCtx;
    }

    return ret;
}
#endif /* HAVE_CURVE25519 */

#ifdef HAVE_ED448
/* Set the Ed448 sign callback into the SSL/TLS context.
 *
 * @param [in] ctx  SSL/TLS context.
 * @param [in] cb   Ed448 sign callback.
 */
void wolfSSL_CTX_SetEd448SignCb(WOLFSSL_CTX* ctx, CallbackEd448Sign cb)
{
    if (ctx != NULL) {
        ctx->Ed448SignCb = cb;
    }
}
/* Set the context for Ed448 sign callback into the SSL/TLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @param [in] ctx  Context for Ed448 sign callback.
 */
void wolfSSL_SetEd448SignCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl != NULL) {
        ssl->Ed448SignCtx = ctx;
    }
}
/* Get the context for Ed448 sign callback from the SSL/TLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  Context for Ed448 sign callback.
 * @return  NULL when ssl is NULL.
 */
void* wolfSSL_GetEd448SignCtx(WOLFSSL* ssl)
{
    void* ret;

    if (ssl == NULL) {
        ret = NULL;
    }
    else {
        ret = ssl->Ed448SignCtx;
    }

    return ret;
}

/* Set the Ed448 verify callback into the SSL/TLS context.
 *
 * @param [in] ctx  SSL/TLS context.
 * @param [in] cb   Ed448 verify callback.
 */
void  wolfSSL_CTX_SetEd448VerifyCb(WOLFSSL_CTX* ctx, CallbackEd448Verify cb)
{
    if (ctx != NULL) {
        ctx->Ed448VerifyCb = cb;
    }
}
/* Set the context for Ed448 verify callback into the SSL/TLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @param [in] ctx  Context for Ed448 verify callback.
 */
void  wolfSSL_SetEd448VerifyCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl != NULL) {
        ssl->Ed448VerifyCtx = ctx;
    }
}
/* Get the context for Ed448 verify callback from the SSL/TLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  Context for Ed448 verify callback.
 * @return  NULL when ssl is NULL.
 */
void* wolfSSL_GetEd448VerifyCtx(WOLFSSL* ssl)
{
    void* ret;

    if (ssl == NULL) {
        ret = NULL;
    }
    else {
        ret = ssl->Ed448VerifyCtx;
    }

    return ret;
}
#endif /* HAVE_ED448 */

#ifdef HAVE_CURVE448
/* Set the X448 key generation callback into the SSL/TLS context.
 *
 * @param [in] ctx  SSL/TLS context.
 * @param [in] cb   X448 key generation callback.
 */
void wolfSSL_CTX_SetX448KeyGenCb(WOLFSSL_CTX* ctx,
        CallbackX448KeyGen cb)
{
    if (ctx != NULL) {
        ctx->X448KeyGenCb = cb;
    }
}
/* Set the context for X448 key generation callback into the SSL/TLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @param [in] ctx  Context for X448 key generation callback.
 */
void  wolfSSL_SetX448KeyGenCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl != NULL) {
        ssl->X448KeyGenCtx = ctx;
    }
}
/* Get the context for X448 key generation callback from the SSL/TLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  Context for X448 key generation callback.
 * @return  NULL when ssl is NULL.
 */
void* wolfSSL_GetX448KeyGenCtx(WOLFSSL* ssl)
{
    void* ret;

    if (ssl == NULL) {
        ret = NULL;
    }
    else {
        ret = ssl->X448KeyGenCtx;
    }

    return ret;
}

/* Set the X448 shared secret callback into the SSL/TLS context.
 *
 * @param [in] ctx  SSL/TLS context.
 * @param [in] cb   X448 shared secret callback.
 */
void wolfSSL_CTX_SetX448SharedSecretCb(WOLFSSL_CTX* ctx,
        CallbackX448SharedSecret cb)
{
    if (ctx != NULL) {
        ctx->X448SharedSecretCb = cb;
    }
}
/* Set the context for X448 shared secret callback into the SSL/TLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @param [in] ctx  Context for X448 shared secret callback.
 */
void  wolfSSL_SetX448SharedSecretCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl != NULL) {
        ssl->X448SharedSecretCtx = ctx;
    }
}
/* Get the context for X448 shared secret callback from the SSL/TLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  Context for X448 shared secret callback.
 * @return  NULL when ssl is NULL.
 */
void* wolfSSL_GetX448SharedSecretCtx(WOLFSSL* ssl)
{
    void* ret;

    if (ssl == NULL) {
        ret = NULL;
    }
    else {
        ret = ssl->X448SharedSecretCtx;
    }

    return ret;
}
#endif /* HAVE_CURVE448 */

#ifndef NO_RSA
/* Set the RSA sign callback into the SSL/TLS context.
 *
 * @param [in] ctx  SSL/TLS context.
 * @param [in] cb   RSA sign callback.
 */
void  wolfSSL_CTX_SetRsaSignCb(WOLFSSL_CTX* ctx, CallbackRsaSign cb)
{
    if (ctx != NULL) {
        ctx->RsaSignCb = cb;
    }
}
/* Set the RSA sign check callback into the SSL/TLS context.
 *
 * @param [in] ctx  SSL/TLS context.
 * @param [in] cb   RSA sign check callback.
 */
void  wolfSSL_CTX_SetRsaSignCheckCb(WOLFSSL_CTX* ctx, CallbackRsaVerify cb)
{
    if (ctx != NULL) {
        ctx->RsaSignCheckCb = cb;
    }
}
/* Set the context for RSA sign callback into the SSL/TLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @param [in] ctx  Context for RSA sign callback.
 */
void  wolfSSL_SetRsaSignCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl != NULL) {
        ssl->RsaSignCtx = ctx;
    }
}
/* Get the context for RSA sign callback from the SSL/TLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  Context for RSA sign callback.
 * @return  NULL when ssl is NULL.
 */
void* wolfSSL_GetRsaSignCtx(WOLFSSL* ssl)
{
    void* ret;

    if (ssl == NULL) {
        ret = NULL;
    }
    else {
        ret = ssl->RsaSignCtx;
    }

    return ret;
}

/* Set the RSA verify callback into the SSL/TLS context.
 *
 * @param [in] ctx  SSL/TLS context.
 * @param [in] cb   RSA verify callback.
 */
void  wolfSSL_CTX_SetRsaVerifyCb(WOLFSSL_CTX* ctx, CallbackRsaVerify cb)
{
    if (ctx != NULL) {
        ctx->RsaVerifyCb = cb;
    }
}
/* Set the context for RSA verify callback into the SSL/TLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @param [in] ctx  Context for RSA verify callback.
 */
void  wolfSSL_SetRsaVerifyCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl != NULL) {
        ssl->RsaVerifyCtx = ctx;
    }
}
/* Get the context for RSA verify callback from the SSL/TLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  Context for RSA verify callback.
 * @return  NULL when ssl is NULL.
 */
void* wolfSSL_GetRsaVerifyCtx(WOLFSSL* ssl)
{
    void* ret;

    if (ssl == NULL) {
        ret = NULL;
    }
    else {
        ret = ssl->RsaVerifyCtx;
    }

    return ret;
}

#ifdef WC_RSA_PSS
/* Set the RSA PSS sign callback into the SSL/TLS context.
 *
 * @param [in] ctx  SSL/TLS context.
 * @param [in] cb   RSA PSS sign callback.
 */
void  wolfSSL_CTX_SetRsaPssSignCb(WOLFSSL_CTX* ctx, CallbackRsaPssSign cb)
{
    if (ctx != NULL) {
        ctx->RsaPssSignCb = cb;
    }
}
/* Set the RSA PSS sign check callback into the SSL/TLS context.
 *
 * @param [in] ctx  SSL/TLS context.
 * @param [in] cb   RSA PSS sign check callback.
 */
void  wolfSSL_CTX_SetRsaPssSignCheckCb(WOLFSSL_CTX* ctx,
    CallbackRsaPssVerify cb)
{
    if (ctx != NULL) {
        ctx->RsaPssSignCheckCb = cb;
    }
}
/* Set the context for RSA PSS sign callback into the SSL/TLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @param [in] ctx  Context for RSA PSS sign callback.
 */
void  wolfSSL_SetRsaPssSignCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl != NULL) {
        ssl->RsaPssSignCtx = ctx;
    }
}
/* Get the context for RSA PSS sign callback from the SSL/TLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  Context for RSA PSS sign callback.
 * @return  NULL when ssl is NULL.
 */
void* wolfSSL_GetRsaPssSignCtx(WOLFSSL* ssl)
{
    void* ret;

    if (ssl == NULL) {
        ret = NULL;
    }
    else {
        ret = ssl->RsaPssSignCtx;
    }

    return ret;
}

/* Set the RSA PSS verify callback into the SSL/TLS context.
 *
 * @param [in] ctx  SSL/TLS context.
 * @param [in] cb   RSA PSS verify callback.
 */
void  wolfSSL_CTX_SetRsaPssVerifyCb(WOLFSSL_CTX* ctx, CallbackRsaPssVerify cb)
{
    if (ctx != NULL) {
        ctx->RsaPssVerifyCb = cb;
    }
}
/* Set the context for RSA PSS verify callback into the SSL/TLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @param [in] ctx  Context for RSA PSS verify callback.
 */
void  wolfSSL_SetRsaPssVerifyCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl != NULL) {
        ssl->RsaPssVerifyCtx = ctx;
    }
}
/* Get the context for RSA PSS verify callback from the SSL/TLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  Context for RSA PSS verify callback.
 * @return  NULL when ssl is NULL.
 */
void* wolfSSL_GetRsaPssVerifyCtx(WOLFSSL* ssl)
{
    void* ret;

    if (ssl == NULL) {
        ret = NULL;
    }
    else {
        ret = ssl->RsaPssVerifyCtx;
    }

    return ret;
}
#endif /* WC_RSA_PSS */

/* Set the RSA encrypt callback into the SSL/TLS context.
 *
 * @param [in] ctx  SSL/TLS context.
 * @param [in] cb   RSA encrypt callback.
 */
void  wolfSSL_CTX_SetRsaEncCb(WOLFSSL_CTX* ctx, CallbackRsaEnc cb)
{
    if (ctx != NULL) {
        ctx->RsaEncCb = cb;
    }
}
/* Set the context for RSA encrypt callback into the SSL/TLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @param [in] ctx  Context for RSA encrypt callback.
 */
void  wolfSSL_SetRsaEncCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl != NULL) {
        ssl->RsaEncCtx = ctx;
    }
}
/* Get the context for RSA encrypt callback from the SSL/TLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  Context for RSA encrypt callback.
 * @return  NULL when ssl is NULL.
 */
void* wolfSSL_GetRsaEncCtx(WOLFSSL* ssl)
{
    void* ret;

    if (ssl == NULL) {
        ret = NULL;
    }
    else {
        ret = ssl->RsaEncCtx;
    }

    return ret;
}

/* Set the RSA decrypt callback into the SSL/TLS context.
 *
 * @param [in] ctx  SSL/TLS context.
 * @param [in] cb   RSA decrypt callback.
 */
void  wolfSSL_CTX_SetRsaDecCb(WOLFSSL_CTX* ctx, CallbackRsaDec cb)
{
    if (ctx != NULL) {
        ctx->RsaDecCb = cb;
    }
}
/* Set the context for RSA decrypt callback into the SSL/TLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @param [in] ctx  Context for RSA decrypt callback.
 */
void  wolfSSL_SetRsaDecCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl != NULL) {
        ssl->RsaDecCtx = ctx;
    }
}
/* Get the context for RSA decrypt callback from the SSL/TLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  Context for RSA decrypt callback.
 * @return  NULL when ssl is NULL.
 */
void* wolfSSL_GetRsaDecCtx(WOLFSSL* ssl)
{
    void* ret;

    if (ssl == NULL) {
        ret = NULL;
    }
    else {
        ret = ssl->RsaDecCtx;
    }

    return ret;
}
#endif /* NO_RSA */

#endif /* HAVE_PK_CALLBACKS */

#endif /* !NO_CERTS */

#if defined(HAVE_PK_CALLBACKS) && !defined(NO_DH)
/* Set the DH key pair generation callback into the SSL/TLS context.
 *
 * @param [in] ctx  SSL/TLS context.
 * @param [in] cb   DH key pair generation callback.
 */
void wolfSSL_CTX_SetDhGenerateKeyPair(WOLFSSL_CTX* ctx,
    CallbackDhGenerateKeyPair cb)
{
    if (ctx != NULL) {
        ctx->DhGenerateKeyPairCb = cb;
    }
}
/* Set the DH key agree callback into the SSL/TLS context.
 *
 * @param [in] ctx  SSL/TLS context.
 * @param [in] cb   DH key agree callback.
 */
void wolfSSL_CTX_SetDhAgreeCb(WOLFSSL_CTX* ctx, CallbackDhAgree cb)
{
    if (ctx != NULL) {
        ctx->DhAgreeCb = cb;
    }
}
/* Set the context for DH key agree callback into the SSL/TLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @param [in] ctx  Context for DH key agree callback.
 */
void wolfSSL_SetDhAgreeCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl != NULL) {
        ssl->DhAgreeCtx = ctx;
    }
}
/* Get the context for DH key ageww callback from the SSL/TLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  Context for DH key agree callback.
 * @return  NULL when ssl is NULL.
 */
void* wolfSSL_GetDhAgreeCtx(WOLFSSL* ssl)
{
    void* ret;

    if (ssl == NULL) {
        ret = NULL;
    }
    else {
        ret = ssl->DhAgreeCtx;
    }

    return ret;
}
#endif /* HAVE_PK_CALLBACKS && !NO_DH */

#endif /* !WOLFSSL_SSL_API_PK_INCLUDED */
