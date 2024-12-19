/* ssl_load.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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

/*
 * WOLFSSL_SYS_CA_CERTS
 *     Enables ability to load system CA certs from the OS via
 *     wolfSSL_CTX_load_system_CA_certs.
 */

#ifdef WOLFSSL_SYS_CA_CERTS

#ifdef _WIN32
    #include <windows.h>
    #include <wincrypt.h>

    /* mingw gcc does not support pragma comment, and the
     * linking with crypt32 is handled in configure.ac */
    #if !defined(__MINGW32__) && !defined(__MINGW64__)
        #pragma comment(lib, "crypt32")
    #endif
#endif

#if defined(__APPLE__) && defined(HAVE_SECURITY_SECTRUSTSETTINGS_H)
#include <Security/SecTrustSettings.h>
#endif

#endif /* WOLFSSL_SYS_CA_CERTS */

#if !defined(WOLFSSL_SSL_LOAD_INCLUDED)
    #ifndef WOLFSSL_IGNORE_FILE_WARN
        #warning ssl_load.c does not need to be compiled separately from ssl.c
    #endif
#else

#if defined(HAVE_SESSION_TICKET) || !defined(NO_PSK)
    /* PSK field of context when it exists. */
    #define CTX_HAVE_PSK(ctx)   (ctx)->havePSK
    /* PSK field of ssl when it exists. */
    #define SSL_HAVE_PSK(ssl)   (ssl)->options.havePSK
#else
    /* Have PSK value when no field. */
    #define CTX_HAVE_PSK(ctx)   0
    /* Have PSK value when no field. */
    #define SSL_HAVE_PSK(ssl)   0
#endif
#ifdef NO_RSA
    /* Boolean for RSA available. */
    #define WOLFSSL_HAVE_RSA    0
#else
    /* Boolean for RSA available. */
    #define WOLFSSL_HAVE_RSA    1
#endif
#ifndef NO_CERTS
    /* Private key size from ssl. */
    #define SSL_KEY_SZ(ssl)     (ssl)->buffers.keySz
#else
    /* Private key size not available. */
    #define SSL_KEY_SZ(ssl)     0
#endif
#ifdef HAVE_ANON
    /* Anonymous ciphersuite allowed field in context. */
    #define CTX_USE_ANON(ctx)   (ctx)->useAnon
#else
    /* Anonymous ciphersuite allowed field not in context. */
    #define CTX_USE_ANON(ctx)   0
#endif

#ifdef HAVE_PK_CALLBACKS
    #define WOLFSSL_IS_PRIV_PK_SET(ctx, ssl)                            \
        wolfSSL_CTX_IsPrivatePkSet(((ssl) == NULL) ? (ctx) : (ssl)->ctx)
#else
    #define WOLFSSL_IS_PRIV_PK_SET(ctx, ssl)    0
#endif

/* Get the heap from the context or the ssl depending on which is available. */
#define WOLFSSL_HEAP(ctx, ssl)                                              \
    (((ctx) != NULL) ? (ctx)->heap : (((ssl) != NULL) ? (ssl)->heap : NULL))


#ifndef NO_CERTS

/* Get DER encoding from data in a buffer as a DerBuffer.
 *
 * @param [in]      buff    Buffer containing data.
 * @param [in]      len     Length of data in buffer.
 * @param [in]      format  Format of data:
 *                            WOLFSSL_FILETYPE_PEM or WOLFSSL_FILETYPE_ASN1.
 * @param [in]      type    Type of data:
 *                            CERT_TYPE, CA_TYPE, TRUSTED_PEER_TYPE,
 *                            PRIVATEKEY_TYPE or ALT_PRIVATEKEY_TYPE.
 * @param [in, out] info    Info for encryption.
 * @param [in]      heap    Dynamic memory allocation hint.
 * @param [out]     der     Holds DER encoded data.
 * @param [out]     algId   Algorithm identifier for private keys.
 * @return  0 on success.
 * @return  NOT_COMPILED_IN when format is PEM and PEM not supported.
 * @return  ASN_PARSE_E when format is ASN.1 and invalid DER encoding.
 * @return  MEMORY_E when dynamic memory allocation fails.
 */
static int DataToDerBuffer(const unsigned char* buff, word32 len, int format,
    int type, EncryptedInfo* info, void* heap, DerBuffer** der, int* algId)
{
    int ret;

    info->consumed = 0;

    /* Data in buffer has PEM format - extract DER data. */
    if (format == WOLFSSL_FILETYPE_PEM) {
    #ifdef WOLFSSL_PEM_TO_DER
        ret = PemToDer(buff, len, type, der, heap, info, algId);
        if (ret != 0) {
            FreeDer(der);
        }
    #else
        (void)algId;
        ret = NOT_COMPILED_IN;
    #endif
    }
    /* Data in buffer is ASN.1 format - get first SEQ or OCT into der. */
    else {
        /* Get length of SEQ including header. */
        if ((info->consumed = wolfssl_der_length(buff, (int)len)) > 0) {
            ret = 0;
        }
        else {
            ret = ASN_PARSE_E;
        }

        if (info->consumed > (int)len) {
            ret = ASN_PARSE_E;
        }
        if (ret == 0) {
            ret = AllocCopyDer(der, buff, (word32)info->consumed, type, heap);
        }
    }

    return ret;
}

/* Process a user's certificate.
 *
 * Puts the 3-byte length before certificate data as required for TLS.
 * CA certificates are added to the certificate manager.
 *
 * @param [in]      cm           Certificate manager.
 * @param [in, out] pDer         DER encoded data.
 * @param [in]      type         Type of data. Valid values:
 *                                 CERT_TYPE, CA_TYPE or TRUSTED_PEER_TYPE.
 * @param [in]      verify       How to verify certificate.
 * @param [out]     chainBuffer  Buffer to hold chain of certificates.
 * @param [in, out] pIdx         On in, current index into chainBuffer.
 *                               On out, index after certificate added.
 * @param [in]      bufferSz     Size of buffer in bytes.
 * @return  0 on success.
 * @return  BUFFER_E if chain buffer not big enough to hold certificate.
 */
static int ProcessUserCert(WOLFSSL_CERT_MANAGER* cm, DerBuffer** pDer,
    int type, int verify, byte* chainBuffer, word32* pIdx, word32 bufferSz)
{
    int ret = 0;
    word32 idx = *pIdx;
    DerBuffer* der = *pDer;

    /* Check there is space for certificate in chainBuffer. */
    if ((ret == 0) && ((idx + der->length + CERT_HEADER_SZ) > bufferSz)) {
        WOLFSSL_MSG("   Cert Chain bigger than buffer. "
                    "Consider increasing MAX_CHAIN_DEPTH");
        ret = BUFFER_E;
    }
    if (ret == 0) {
        /* 3-byte length. */
        c32to24(der->length, &chainBuffer[idx]);
        idx += CERT_HEADER_SZ;
        /* Add complete DER encoded certificate. */
        XMEMCPY(&chainBuffer[idx], der->buffer, der->length);
        idx += der->length;

        if (type == CA_TYPE) {
            /* Add CA to certificate manager */
            ret = AddCA(cm, pDer, WOLFSSL_USER_CA, verify);
            if (ret == 1) {
                ret = 0;
            }
        }
    }

    /* Update the index into chainBuffer. */
    *pIdx = idx;
    return ret;
}

/* Store the certificate chain buffer aganst WOLFSSL_CTX or WOLFSSL object.
 *
 * @param [in, out] ctx          SSL context object.
 * @param [in, out] ssl          SSL object.
 * @param [in]      chainBuffer  Buffer containing chain of certificates.
 * @param [in]      len          Length, in bytes, of data in buffer.
 * @param [in]      cnt          Number of certificates in chain.
 * @param [in]      type         Type of data. Valid values:
 *                                 CERT_TYPE, CA_TYPE or CHAIN_CERT_TYPE.
 * @param [in]      heap         Dynamic memory allocation hint.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails.
 */
static int ProcessUserChainRetain(WOLFSSL_CTX* ctx, WOLFSSL* ssl,
    const byte* chainBuffer, word32 len, int cnt, int type, void* heap)
{
    int ret = 0;

    (void)cnt;

    /* Store in SSL object if available. */
    if (ssl != NULL) {
        /* Dispose of old chain if not reference to context's. */
        if (ssl->buffers.weOwnCertChain) {
            FreeDer(&ssl->buffers.certChain);
        }
        /* Allocate and copy the buffer into SSL object. */
        ret = AllocCopyDer(&ssl->buffers.certChain, chainBuffer, len, type,
            heap);
        ssl->buffers.weOwnCertChain = (ret == 0);
    #ifdef WOLFSSL_TLS13
        /* Update count of certificates in chain. */
        ssl->buffers.certChainCnt = cnt;
    #endif
    }
    /* Store in SSL context object if available. */
    else if (ctx != NULL) {
        /* Dispose of old chain and allocate and copy in new chain. */
        FreeDer(&ctx->certChain);
        /* Allocate and copy the buffer into SSL context object. */
        ret = AllocCopyDer(&ctx->certChain, chainBuffer, len, type, heap);
    #ifdef WOLFSSL_TLS13
        /* Update count of certificates in chain. */
        ctx->certChainCnt = cnt;
    #endif
    }

    return ret;
}

/* Process user cert chain to pass during the TLS handshake.
 *
 * If not a certificate type then data is ignored.
 *
 * @param [in, out] ctx     SSL context object.
 * @param [in, out] ssl     SSL object.
 * @param [in]      buff    Buffer holding certificates.
 * @param [in]      sz      Length of data in buffer.
 * @param [in]      format  Format of the certificate:
 *                            WOLFSSL_FILETYPE_PEM or WOLFSSL_FILETYPE_ASN1
 * @param [in]      type    Type of certificate:
 *                            CA_TYPE, CERT_TYPE or CHAIN_CERT_TYPE
 * @param [out]     used    Number of bytes from buff used.
 * @param [in, out] info    Encryption information.
 * @param [in]      verify  How to verify certificate.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when type is CA_TYPE and ctx is NULL.
 * @return  MEMORY_E when dynamic memory allocation fails.
 */
static int ProcessUserChain(WOLFSSL_CTX* ctx, WOLFSSL* ssl,
    const unsigned char* buff, long sz, int format, int type, long* used,
    EncryptedInfo* info, int verify)
{
    int ret = 0;
    void* heap = WOLFSSL_HEAP(ctx, ssl);

    WOLFSSL_ENTER("ProcessUserChain");

    /* Check we haven't consumed all the data. */
    if (info->consumed >= sz) {
        WOLFSSL_MSG("Already consumed data");
    }
    else {
    #ifndef WOLFSSL_SMALL_STACK
        byte stackBuffer[FILE_BUFFER_SIZE];
    #endif
        StaticBuffer chain;
        long   consumed = info->consumed;
        word32 idx = 0;
        int    gotOne = 0;
        int    cnt = 0;
        /* Calculate max possible size, including max headers */
        long   maxSz = (sz - consumed) + (CERT_HEADER_SZ * MAX_CHAIN_DEPTH);

        /* Setup buffer to hold chain. */
    #ifdef WOLFSSL_SMALL_STACK
        static_buffer_init(&chain);
    #else
        static_buffer_init(&chain, stackBuffer, FILE_BUFFER_SIZE);
    #endif
        /* Make buffer big enough to support maximum size. */
        ret = static_buffer_set_size(&chain, (word32)maxSz, heap,
            DYNAMIC_TYPE_FILE);

        WOLFSSL_MSG("Processing Cert Chain");
        /* Keep parsing certificates will data available. */
        while ((ret == 0) && (consumed < sz)) {
            DerBuffer* part = NULL;

            /* Get a certificate as DER. */
            ret = DataToDerBuffer(buff + consumed, (word32)(sz - consumed),
                format, type, info, heap, &part, NULL);
            if (ret == 0) {
                /* Process the user certificate. */
                ret = ProcessUserCert(ctx->cm, &part, type, verify,
                   chain.buffer, &idx, (word32)maxSz);
            }
            /* PEM may have trailing data that can be ignored. */
            if ((ret == WC_NO_ERR_TRACE(ASN_NO_PEM_HEADER)) && gotOne) {
                WOLFSSL_MSG("We got one good cert, so stuff at end ok");
                ret = 0;
                break;
            }
            /* Certificate data handled. */
            FreeDer(&part);

            if (ret == 0) {
                /* Update consumed length. */
                consumed += info->consumed;
                WOLFSSL_MSG("   Consumed another Cert in Chain");
                /* Update whether we got a user certificate. */
                gotOne |= (type != CA_TYPE);
                /* Update count of certificates added to chain. */
                cnt++;
            }
        }
        if (used != NULL) {
            /* Return the total consumed length. */
            *used = consumed;
        }

        /* Check whether there is data in the chain buffer. */
        if ((ret == 0) && (idx > 0)) {
            /* Put the chain buffer against the SSL or SSL context object. */
            ret = ProcessUserChainRetain(ctx, ssl, chain.buffer, idx, cnt, type,
                heap);
        }

        /* Dispose of chain buffer. */
        static_buffer_free(&chain, heap, DYNAMIC_TYPE_FILE);
    }

    WOLFSSL_LEAVE("ProcessUserChain", ret);
    return ret;
}

#ifndef NO_RSA
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && \
    (HAVE_FIPS_VERSION > 2))
/* See if DER data is an RSA private key.
 *
 * Checks size meets minimum RSA key size.
 * This implementation uses less dynamic memory.
 *
 * @param [in, out] ctx        SSL context object.
 * @param [in, out] ssl        SSL object.
 * @param [in]      der        DER encoding.
 * @param [in, out] keyFormat  On in, expected format. 0 means unknown.
 * @param [in]      devId      Device identifier.
 * @param [out]     keyType    Type of key.
 * @param [out]     keySize    Size of key.
 * @return  0 on success or not an RSA key and format unknown.
 * @return  RSA_KEY_SIZE_E when key size doesn't meet minimum required.
 */
static int ProcessBufferTryDecodeRsa(WOLFSSL_CTX* ctx, WOLFSSL* ssl,
    DerBuffer* der, int* keyFormat, int devId, byte* keyType, int* keySize)
{
    int ret;
    word32 idx;
    int keySz = 0;

    (void)devId;

    /* Validate we have an RSA private key and get key size. */
    idx = 0;
    ret = wc_RsaPrivateKeyValidate(der->buffer, &idx, &keySz, der->length);
#ifdef WOLF_PRIVATE_KEY_ID
    /* If that didn't work then maybe a public key if device ID or callback. */
    if ((ret != 0) && ((devId != INVALID_DEVID) ||
            WOLFSSL_IS_PRIV_PK_SET(ctx, ssl))) {
        word32 nSz;

        /* Decode as an RSA public key. */
        idx = 0;
        ret = wc_RsaPublicKeyDecode_ex(der->buffer, &idx, der->length, NULL,
            &nSz, NULL, NULL);
        if (ret == 0) {
            keySz = (int)nSz;
        }
    }
#endif
    if (ret == 0) {
        /* Get the minimum RSA key size from SSL or SSL context object. */
        int minRsaSz = ssl ? ssl->options.minRsaKeySz : ctx->minRsaKeySz;

        /* Format, type and size are known. */
        *keyFormat = RSAk;
        *keyType = rsa_sa_algo;
        *keySize = keySz;

        /* Check that the size of the RSA key is enough. */
        if (keySz < minRsaSz) {
            WOLFSSL_MSG("Private Key size too small");
            ret = RSA_KEY_SIZE_E;
        }
         /* No static ECC key possible. */
        if ((ssl != NULL) && (ssl->options.side == WOLFSSL_SERVER_END)) {
             ssl->options.haveStaticECC = 0;
        }
    }
    /* Not an RSA key but check whether we know what it is. */
    else if (*keyFormat == 0) {
        WOLFSSL_MSG("Not an RSA key");
        /* Format unknown so keep trying. */
        ret = 0;
    }

    return ret;
}
#else
/* See if DER data is an RSA private key.
 *
 * Checks size meets minimum RSA key size.
 * This implementation uses more dynamic memory but supports older FIPS.
 *
 * @param [in, out] ctx        SSL context object.
 * @param [in, out] ssl        SSL object.
 * @param [in]      der        DER encoding.
 * @param [in, out] keyFormat  On in, expected format. 0 means unknown.
 * @param [in]      heap       Dynamic memory allocation hint.
 * @param [in]      devId      Device identifier.
 * @param [out]     keyType    Type of key.
 * @param [out]     keySize    Size of key.
 * @return  0 on success or not an RSA key and format unknown.
 * @return  RSA_KEY_SIZE_E when key size doesn't meet minimum required.
 */
static int ProcessBufferTryDecodeRsa(WOLFSSL_CTX* ctx, WOLFSSL* ssl,
    DerBuffer* der, int* keyFormat, void* heap, int devId, byte* keyType,
    int* keySize)
{
    int ret;
    word32 idx;
    /* make sure RSA key can be used */
#ifdef WOLFSSL_SMALL_STACK
    RsaKey* key;
#else
    RsaKey  key[1];
#endif

#ifdef WOLFSSL_SMALL_STACK
    /* Allocate an RSA key to parse into so we can get size. */
    key = (RsaKey*)XMALLOC(sizeof(RsaKey), heap, DYNAMIC_TYPE_RSA);
    if (key == NULL)
        return MEMORY_E;
#endif

    /* Initialize the RSA key. */
    ret = wc_InitRsaKey_ex(key, heap, devId);
    if (ret == 0) {
        /* Check we have an RSA private key. */
        idx = 0;
        ret = wc_RsaPrivateKeyDecode(der->buffer, &idx, key, der->length);
    #ifdef WOLF_PRIVATE_KEY_ID
        /* If that didn't work then maybe a public key if device ID or callback.
         */
        if ((ret != 0) && ((devId != INVALID_DEVID) ||
                WOLFSSL_IS_PRIV_PK_SET(ctx, ssl))) {
            /* If that didn't work then maybe a public key if device ID or
             * callback. */
            idx = 0;
            ret = wc_RsaPublicKeyDecode(der->buffer, &idx, key, der->length);
        }
    #endif
        if (ret == 0) {
            /* Get the minimum RSA key size from SSL or SSL context object. */
            int minRsaSz = ssl ? ssl->options.minRsaKeySz : ctx->minRsaKeySz;
            int keySz = wc_RsaEncryptSize((RsaKey*)key);

            /* Format is known. */
            *keyFormat = RSAk;
            *keyType = rsa_sa_algo;
            *keySize = keySz;

            /* Check that the size of the RSA key is enough. */
            if (keySz < minRsaSz) {
                WOLFSSL_MSG("Private Key size too small");
                ret = RSA_KEY_SIZE_E;
            }
            /* No static ECC key possible. */
            if ((ssl != NULL) && (ssl->options.side == WOLFSSL_SERVER_END)) {
                 ssl->options.haveStaticECC = 0;
            }
        }
        /* Not an RSA key but check whether we know what it is. */
        else if (*keyFormat == 0) {
            WOLFSSL_MSG("Not an RSA key");
            /* Format unknown so keep trying. */
            ret = 0;
        }

        /* Free dynamically allocated data in key. */
        wc_FreeRsaKey(key);
    }

#ifdef WOLFSSL_SMALL_STACK
    /* Dispose of allocated key. */
    XFREE(key, heap, DYNAMIC_TYPE_RSA);
#endif

    return ret;
}
#endif
#endif /* !NO_RSA */

#ifdef HAVE_ECC
/* See if DER data is an ECC private key.
 *
 * Checks size meets minimum ECC key size.
 *
 * @param [in, out] ctx        SSL context object.
 * @param [in, out] ssl        SSL object.
 * @param [in]      der        DER encoding.
 * @param [in, out] keyFormat  On in, expected format. 0 means unknown.
 * @param [in]      heap       Dynamic memory allocation hint.
 * @param [in]      devId      Device identifier.
 * @param [out]     keyType    Type of key.
 * @param [out]     keySize    Size of key.
 * @return  0 on success or not an ECC key and format unknown.
 * @return  ECC_KEY_SIZE_E when ECC key size doesn't meet minimum required.
 */
static int ProcessBufferTryDecodeEcc(WOLFSSL_CTX* ctx, WOLFSSL* ssl,
    DerBuffer* der, int* keyFormat, void* heap, int devId, byte* keyType,
    int* keySize)
{
    int ret = 0;
    word32 idx;
    /* make sure ECC key can be used */
#ifdef WOLFSSL_SMALL_STACK
    ecc_key* key;
#else
    ecc_key  key[1];
#endif

#ifdef WOLFSSL_SMALL_STACK
    /* Allocate an ECC key to parse into. */
    key = (ecc_key*)XMALLOC(sizeof(ecc_key), heap, DYNAMIC_TYPE_ECC);
    if (key == NULL)
        return MEMORY_E;
#endif

    /* Initialize ECC key. */
    if (wc_ecc_init_ex(key, heap, devId) == 0) {
        /* Decode as an ECC private key. */
        idx = 0;
        ret = wc_EccPrivateKeyDecode(der->buffer, &idx, key, der->length);
    #ifdef WOLF_PRIVATE_KEY_ID
        /* If that didn't work then maybe a public key if device ID or callback.
         */
        if ((ret != 0) && ((devId != INVALID_DEVID) ||
                WOLFSSL_IS_PRIV_PK_SET(ctx, ssl))) {
            /* Decode as an ECC public key. */
            idx = 0;
            ret = wc_EccPublicKeyDecode(der->buffer, &idx, key, der->length);
        }
    #endif
    #ifdef WOLFSSL_SM2
        if (*keyFormat == SM2k) {
            ret = wc_ecc_set_curve(key, WOLFSSL_SM2_KEY_BITS / 8,
                ECC_SM2P256V1);
        }
    #endif
        if (ret == 0) {
            /* Get the minimum ECC key size from SSL or SSL context object. */
            int minKeySz = ssl ? ssl->options.minEccKeySz : ctx->minEccKeySz;
            int keySz = wc_ecc_size(key);

            /* Format is known. */
            *keyFormat = ECDSAk;
        #ifdef WOLFSSL_SM2
            if (key->dp->id == ECC_SM2P256V1) {
                *keyType = sm2_sa_algo;
            }
            else
        #endif
            {
                *keyType = ecc_dsa_sa_algo;
            }
            *keySize = keySz;

            /* Check that the size of the ECC key is enough. */
            if (keySz < minKeySz) {
                WOLFSSL_MSG("ECC private key too small");
                ret = ECC_KEY_SIZE_E;
            }
            /* Static ECC key possible. */
            if (ssl) {
                ssl->options.haveStaticECC = 1;
            }
            else {
                ctx->haveStaticECC = 1;
            }
        }
        /* Not an ECC key but check whether we know what it is. */
        else if (*keyFormat == 0) {
            WOLFSSL_MSG("Not an ECC key");
            /* Format unknown so keep trying. */
            ret = 0;
        }

        /* Free dynamically allocated data in key. */
        wc_ecc_free(key);
    }

#ifdef WOLFSSL_SMALL_STACK
    /* Dispose of allocated key. */
    XFREE(key, heap, DYNAMIC_TYPE_ECC);
#endif
    return ret;
}
#endif /* HAVE_ECC */

#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_IMPORT)
/* See if DER data is an Ed25519 private key.
 *
 * Checks size meets minimum ECC key size.
 *
 * @param [in, out] ctx        SSL context object.
 * @param [in, out] ssl        SSL object.
 * @param [in]      der        DER encoding.
 * @param [in, out] keyFormat  On in, expected format. 0 means unknown.
 * @param [in]      heap       Dynamic memory allocation hint.
 * @param [in]      devId      Device identifier.
 * @param [out]     keyType    Type of key.
 * @param [out]     keySize    Size of key.
 * @return  0 on success or not an Ed25519 key and format unknown.
 * @return  ECC_KEY_SIZE_E when key size doesn't meet minimum required.
 */
static int ProcessBufferTryDecodeEd25519(WOLFSSL_CTX* ctx, WOLFSSL* ssl,
    DerBuffer* der, int* keyFormat, void* heap, int devId, byte* keyType,
    int* keySize)
{
    int ret;
    word32 idx;
    /* make sure Ed25519 key can be used */
#ifdef WOLFSSL_SMALL_STACK
    ed25519_key* key;
#else
    ed25519_key  key[1];
#endif

#ifdef WOLFSSL_SMALL_STACK
    /* Allocate an Ed25519 key to parse into. */
    key = (ed25519_key*)XMALLOC(sizeof(ed25519_key), heap,
        DYNAMIC_TYPE_ED25519);
    if (key == NULL)
        return MEMORY_E;
#endif

    /* Initialize Ed25519 key. */
    ret = wc_ed25519_init_ex(key, heap, devId);
    if (ret == 0) {
        /* Decode as an Ed25519 private key. */
        idx = 0;
        ret = wc_Ed25519PrivateKeyDecode(der->buffer, &idx, key, der->length);
    #ifdef WOLF_PRIVATE_KEY_ID
        /* If that didn't work then maybe a public key if device ID or callback.
         */
        if ((ret != 0) && ((devId != INVALID_DEVID) ||
                WOLFSSL_IS_PRIV_PK_SET(ctx, ssl))) {
            /* Decode as an Ed25519 public key. */
            idx = 0;
            ret = wc_Ed25519PublicKeyDecode(der->buffer, &idx, key,
                der->length);
        }
    #endif
        if (ret == 0) {
            /* Get the minimum ECC key size from SSL or SSL context object. */
            int minKeySz = ssl ? ssl->options.minEccKeySz : ctx->minEccKeySz;

            /* Format is known. */
            *keyFormat = ED25519k;
            *keyType = ed25519_sa_algo;
            *keySize = ED25519_KEY_SIZE;

            /* Check that the size of the ECC key is enough. */
            if (ED25519_KEY_SIZE < minKeySz) {
                WOLFSSL_MSG("ED25519 private key too small");
                ret = ECC_KEY_SIZE_E;
            }
            if (ssl != NULL) {
#if !defined(WOLFSSL_NO_CLIENT_AUTH) && !defined(NO_ED25519_CLIENT_AUTH)
                /* Ed25519 requires caching enabled for tracking message
                 * hash used in EdDSA_Update for signing */
                ssl->options.cacheMessages = 1;
#endif
            }
        }
        /* Not an Ed25519 key but check whether we know what it is. */
        else if (*keyFormat == 0) {
            WOLFSSL_MSG("Not an Ed25519 key");
            /* Format unknown so keep trying. */
            ret = 0;
        }

        /* Free dynamically allocated data in key. */
        wc_ed25519_free(key);
    }

#ifdef WOLFSSL_SMALL_STACK
    /* Dispose of allocated key. */
    XFREE(key, heap, DYNAMIC_TYPE_ED25519);
#endif
    return ret;
}
#endif /* HAVE_ED25519 && HAVE_ED25519_KEY_IMPORT */

#if defined(HAVE_ED448) && defined(HAVE_ED448_KEY_IMPORT)
/* See if DER data is an Ed448 private key.
 *
 * Checks size meets minimum ECC key size.
 *
 * @param [in, out] ctx        SSL context object.
 * @param [in, out] ssl        SSL object.
 * @param [in]      der        DER encoding.
 * @param [in, out] keyFormat  On in, expected format. 0 means unknown.
 * @param [in]      heap       Dynamic memory allocation hint.
 * @param [in]      devId      Device identifier.
 * @param [out]     keyType    Type of key.
 * @param [out]     keySize    Size of key.
 * @return  0 on success or not an Ed448 key and format unknown.
 * @return  ECC_KEY_SIZE_E when key size doesn't meet minimum required.
 */
static int ProcessBufferTryDecodeEd448(WOLFSSL_CTX* ctx, WOLFSSL* ssl,
    DerBuffer* der, int* keyFormat, void* heap, int devId, byte* keyType,
    int* keySize)
{
    int ret;
    word32 idx;
    /* make sure Ed448 key can be used */
#ifdef WOLFSSL_SMALL_STACK
    ed448_key* key = NULL;
#else
    ed448_key  key[1];
#endif

#ifdef WOLFSSL_SMALL_STACK
    /* Allocate an Ed448 key to parse into. */
    key = (ed448_key*)XMALLOC(sizeof(ed448_key), heap, DYNAMIC_TYPE_ED448);
    if (key == NULL)
        return MEMORY_E;
#endif

    /* Initialize Ed448 key. */
    ret = wc_ed448_init_ex(key, heap, devId);
    if (ret == 0) {
        /* Decode as an Ed448 private key. */
        idx = 0;
        ret = wc_Ed448PrivateKeyDecode(der->buffer, &idx, key, der->length);
    #ifdef WOLF_PRIVATE_KEY_ID
        /* If that didn't work then maybe a public key if device ID or callback.
         */
        if ((ret != 0) && ((devId != INVALID_DEVID) ||
                WOLFSSL_IS_PRIV_PK_SET(ctx, ssl))) {
            /* Decode as an Ed448 public key. */
            idx = 0;
            ret = wc_Ed448PublicKeyDecode(der->buffer, &idx, key, der->length);
        }
    #endif
        if (ret == 0) {
            /* Get the minimum ECC key size from SSL or SSL context object. */
            int minKeySz = ssl ? ssl->options.minEccKeySz : ctx->minEccKeySz;

            /* Format is known. */
            *keyFormat = ED448k;
            *keyType = ed448_sa_algo;
            *keySize = ED448_KEY_SIZE;

            /* Check that the size of the ECC key is enough. */
            if (ED448_KEY_SIZE < minKeySz) {
                WOLFSSL_MSG("ED448 private key too small");
                ret = ECC_KEY_SIZE_E;
            }
            if (ssl != NULL) {
                /* Ed448 requires caching enabled for tracking message
                 * hash used in EdDSA_Update for signing */
                ssl->options.cacheMessages = 1;
            }
        }
        /* Not an Ed448 key but check whether we know what it is. */
        else if (*keyFormat == 0) {
            WOLFSSL_MSG("Not an Ed448 key");
            /* Format unknown so keep trying. */
            ret = 0;
        }

        /* Free dynamically allocated data in key. */
        wc_ed448_free(key);
    }

#ifdef WOLFSSL_SMALL_STACK
    /* Dispose of allocated key. */
    XFREE(key, heap, DYNAMIC_TYPE_ED448);
#endif
    return ret;
}
#endif /* HAVE_ED448 && HAVE_ED448_KEY_IMPORT */

#if defined(HAVE_FALCON)
/* See if DER data is an Falcon private key.
 *
 * Checks size meets minimum Falcon key size.
 *
 * @param [in, out] ctx        SSL context object.
 * @param [in, out] ssl        SSL object.
 * @param [in]      der        DER encoding.
 * @param [in, out] keyFormat  On in, expected format. 0 means unknown.
 * @param [in]      heap       Dynamic memory allocation hint.
 * @param [in]      devId      Device identifier.
 * @param [out]     keyType    Type of key.
 * @param [out]     keySize    Size of key.
 * @return  0 on success or not an Falcon key and format unknown.
 * @return  FALCON_KEY_SIZE_E when key size doesn't meet minimum required.
 */
static int ProcessBufferTryDecodeFalcon(WOLFSSL_CTX* ctx, WOLFSSL* ssl,
    DerBuffer* der, int* keyFormat, void* heap, byte* keyType, int* keySize)
{
    int ret;
    falcon_key* key;

    /* Allocate a Falcon key to parse into. */
    key = (falcon_key*)XMALLOC(sizeof(falcon_key), heap, DYNAMIC_TYPE_FALCON);
    if (key == NULL) {
        return MEMORY_E;
    }

    /* Initialize Falcon key. */
    ret = wc_falcon_init(key);
    if (ret == 0) {
        /* Set up key to parse the format specified. */
        if ((*keyFormat == FALCON_LEVEL1k) || ((*keyFormat == 0) &&
                ((der->length == FALCON_LEVEL1_KEY_SIZE) ||
                 (der->length == FALCON_LEVEL1_PRV_KEY_SIZE)))) {
            ret = wc_falcon_set_level(key, 1);
        }
        else if ((*keyFormat == FALCON_LEVEL5k) || ((*keyFormat == 0) &&
                 ((der->length == FALCON_LEVEL5_KEY_SIZE) ||
                  (der->length == FALCON_LEVEL5_PRV_KEY_SIZE)))) {
            ret = wc_falcon_set_level(key, 5);
        }
        else {
            wc_falcon_free(key);
            ret = ALGO_ID_E;
        }
    }

    if (ret == 0) {
        /* Decode as a Falcon private key. */
        ret = wc_falcon_import_private_only(der->buffer, der->length, key);
        if (ret == 0) {
            /* Get the minimum Falcon key size from SSL or SSL context object.
             */
            int minKeySz = ssl ? ssl->options.minFalconKeySz :
                                 ctx->minFalconKeySz;

            /* Format is known. */
            if (*keyFormat == FALCON_LEVEL1k) {
                *keyType = falcon_level1_sa_algo;
                *keySize = FALCON_LEVEL1_KEY_SIZE;
            }
            else {
                *keyType = falcon_level5_sa_algo;
                *keySize = FALCON_LEVEL5_KEY_SIZE;
            }

            /* Check that the size of the Falcon key is enough. */
            if (*keySize < minKeySz) {
                WOLFSSL_MSG("Falcon private key too small");
                ret = FALCON_KEY_SIZE_E;
            }
        }
        /* Not a Falcon key but check whether we know what it is. */
        else if (*keyFormat == 0) {
            WOLFSSL_MSG("Not a Falcon key");
            /* Format unknown so keep trying. */
            ret = 0;
        }

        /* Free dynamically allocated data in key. */
        wc_falcon_free(key);
    }
    else if ((ret == WC_NO_ERR_TRACE(ALGO_ID_E)) && (*keyFormat == 0)) {
        WOLFSSL_MSG("Not a Falcon key");
        /* Format unknown so keep trying. */
        ret = 0;
    }

    /* Dispose of allocated key. */
    XFREE(key, heap, DYNAMIC_TYPE_FALCON);
    return ret;
}
#endif

#if defined(HAVE_DILITHIUM) && !defined(WOLFSSL_DILITHIUM_NO_SIGN) && \
    !defined(WOLFSSL_DILITHIUM_NO_ASN1)
/* See if DER data is an Dilithium private key.
 *
 * Checks size meets minimum Falcon key size.
 *
 * @param [in, out] ctx        SSL context object.
 * @param [in, out] ssl        SSL object.
 * @param [in]      der        DER encoding.
 * @param [in, out] keyFormat  On in, expected format. 0 means unknown.
 * @param [in]      heap       Dynamic memory allocation hint.
 * @param [in]      devId      Device identifier.
 * @param [out]     keyType    Type of key.
 * @param [out]     keySize    Size of key.
 * @return  0 on success or not a Dilithium key and format unknown.
 * @return  DILITHIUM_KEY_SIZE_E when key size doesn't meet minimum required.
 */
static int ProcessBufferTryDecodeDilithium(WOLFSSL_CTX* ctx, WOLFSSL* ssl,
    DerBuffer* der, int* keyFormat, void* heap, byte* keyType, int* keySize)
{
    int ret;
    word32 idx;
    dilithium_key* key;

    /* Allocate a Dilithium key to parse into. */
    key = (dilithium_key*)XMALLOC(sizeof(dilithium_key), heap,
        DYNAMIC_TYPE_DILITHIUM);
    if (key == NULL) {
        return MEMORY_E;
    }

    /* Initialize Dilithium key. */
    ret = wc_dilithium_init(key);
    if (ret == 0) {
        /* Set up key to parse the format specified. */
        if ((*keyFormat == DILITHIUM_LEVEL2k) || ((*keyFormat == 0) &&
            ((der->length == DILITHIUM_LEVEL2_KEY_SIZE) ||
             (der->length == DILITHIUM_LEVEL2_PRV_KEY_SIZE)))) {
            ret = wc_dilithium_set_level(key, 2);
        }
        else if ((*keyFormat == DILITHIUM_LEVEL3k) || ((*keyFormat == 0) &&
            ((der->length == DILITHIUM_LEVEL3_KEY_SIZE) ||
             (der->length == DILITHIUM_LEVEL3_PRV_KEY_SIZE)))) {
            ret = wc_dilithium_set_level(key, 3);
        }
        else if ((*keyFormat == DILITHIUM_LEVEL5k) || ((*keyFormat == 0) &&
            ((der->length == DILITHIUM_LEVEL5_KEY_SIZE) ||
             (der->length == DILITHIUM_LEVEL5_PRV_KEY_SIZE)))) {
            ret = wc_dilithium_set_level(key, 5);
        }
        else {
            wc_dilithium_free(key);
            ret = ALGO_ID_E;
        }
    }

    if (ret == 0) {
        /* Decode as a Dilithium private key. */
        idx = 0;
        ret = wc_Dilithium_PrivateKeyDecode(der->buffer, &idx, key, der->length);
        if (ret == 0) {
            /* Get the minimum Dilithium key size from SSL or SSL context
             * object. */
            int minKeySz = ssl ? ssl->options.minDilithiumKeySz :
                                 ctx->minDilithiumKeySz;

            /* Format is known. */
            if (*keyFormat == DILITHIUM_LEVEL2k) {
                *keyType = dilithium_level2_sa_algo;
                *keySize = DILITHIUM_LEVEL2_KEY_SIZE;
            }
            else if (*keyFormat == DILITHIUM_LEVEL3k) {
                *keyType = dilithium_level3_sa_algo;
                *keySize = DILITHIUM_LEVEL3_KEY_SIZE;
            }
            else if (*keyFormat == DILITHIUM_LEVEL5k) {
                *keyType = dilithium_level5_sa_algo;
                *keySize = DILITHIUM_LEVEL5_KEY_SIZE;
            }

            /* Check that the size of the Dilithium key is enough. */
            if (*keySize < minKeySz) {
                WOLFSSL_MSG("Dilithium private key too small");
                ret = DILITHIUM_KEY_SIZE_E;
            }
        }
        /* Not a Dilithium key but check whether we know what it is. */
        else if (*keyFormat == 0) {
            WOLFSSL_MSG("Not a Dilithium key");
            /* Format unknown so keep trying. */
            ret = 0;
        }

        /* Free dynamically allocated data in key. */
        wc_dilithium_free(key);
    }
    else if ((ret == WC_NO_ERR_TRACE(ALGO_ID_E)) && (*keyFormat == 0)) {
        WOLFSSL_MSG("Not a Dilithium key");
        /* Format unknown so keep trying. */
        ret = 0;
    }

    /* Dispose of allocated key. */
    XFREE(key, heap, DYNAMIC_TYPE_DILITHIUM);
    return ret;
}
#endif /* HAVE_DILITHIUM */

/* Try to decode DER data is a known private key.
 *
 * Checks size meets minimum for key type.
 *
 * @param [in, out] ctx        SSL context object.
 * @param [in, out] ssl        SSL object.
 * @param [in]      der        DER encoding.
 * @param [in, out] keyFormat  On in, expected format. 0 means unknown.
 * @param [in]      heap       Dynamic memory allocation hint.
 * @param [out]     type       Type of key:
 *                               PRIVATEKEY_TYPE or ALT_PRIVATEKEY_TYPE.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when der or keyFormat is NULL.
 * @return  BAD_FUNC_ARG when ctx and ssl are NULL.
 * @return  WOLFSSL_BAD_FILE when unable to identify the key format.
 */
static int ProcessBufferTryDecode(WOLFSSL_CTX* ctx, WOLFSSL* ssl,
    DerBuffer* der, int* keyFormat, void* heap, int type)
{
    int ret = 0;
    int devId = wolfSSL_CTX_GetDevId(ctx, ssl);
    byte* keyType = NULL;
    int* keySz = NULL;

    (void)heap;
    (void)devId;
    (void)type;

    /* Validate parameters. */
    if ((der == NULL) || (keyFormat == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* Must have an SSL context or SSL object to use. */
    if ((ret == 0) && (ctx == NULL) && (ssl == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Determine where to put key type and size in SSL or context object. */
    #ifdef WOLFSSL_DUAL_ALG_CERTS
        if (type == ALT_PRIVATEKEY_TYPE) {
            if (ssl != NULL) {
                keyType = &ssl->buffers.altKeyType;
                keySz = &ssl->buffers.altKeySz;
            }
            else {
                keyType = &ctx->altPrivateKeyType;
                keySz = &ctx->altPrivateKeySz;
            }
        }
        else
    #endif
        /* Type is PRIVATEKEY_TYPE. */
        if (ssl != NULL) {
            keyType = &ssl->buffers.keyType;
            keySz = &ssl->buffers.keySz;
        }
        else {
            keyType = &ctx->privateKeyType;
            keySz = &ctx->privateKeySz;
        }
    }

#ifndef NO_RSA
    /* Try RSA if key format is RSA or yet unknown. */
    if ((ret == 0) && ((*keyFormat == 0) || (*keyFormat == RSAk))) {
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && \
    (HAVE_FIPS_VERSION > 2))
        ret = ProcessBufferTryDecodeRsa(ctx, ssl, der, keyFormat, devId,
            keyType, keySz);
#else
        ret = ProcessBufferTryDecodeRsa(ctx, ssl, der, keyFormat, heap, devId,
            keyType, keySz);
#endif
    }
#endif
#ifdef HAVE_ECC
    /* Try ECC if key format is ECDSA or SM2, or yet unknown. */
    if ((ret == 0) && ((*keyFormat == 0) || (*keyFormat == ECDSAk)
    #ifdef WOLFSSL_SM2
        || (*keyFormat == SM2k)
    #endif
        )) {
        ret = ProcessBufferTryDecodeEcc(ctx, ssl, der, keyFormat, heap, devId,
            keyType, keySz);
    }
#endif /* HAVE_ECC */
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_IMPORT)
    /* Try Ed25519 if key format is Ed25519 or yet unknown. */
    if ((ret == 0) && ((*keyFormat == 0 || *keyFormat == ED25519k))) {
        ret = ProcessBufferTryDecodeEd25519(ctx, ssl, der, keyFormat, heap,
            devId, keyType, keySz);
    }
#endif /* HAVE_ED25519 && HAVE_ED25519_KEY_IMPORT */
#if defined(HAVE_ED448) && defined(HAVE_ED448_KEY_IMPORT)
    /* Try Ed448 if key format is Ed448 or yet unknown. */
    if ((ret == 0) && ((*keyFormat == 0 || *keyFormat == ED448k))) {
        ret = ProcessBufferTryDecodeEd448(ctx, ssl, der, keyFormat, heap, devId,
            keyType, keySz);
    }
#endif /* HAVE_ED448 && HAVE_ED448_KEY_IMPORT */
#if defined(HAVE_FALCON)
    /* Try Falcon if key format is Falcon level 1k or 5k or yet unknown. */
    if ((ret == 0) && ((*keyFormat == 0) || (*keyFormat == FALCON_LEVEL1k) ||
            (*keyFormat == FALCON_LEVEL5k))) {
        ret = ProcessBufferTryDecodeFalcon(ctx, ssl, der, keyFormat, heap,
            keyType, keySz);
    }
#endif /* HAVE_FALCON */
#if defined(HAVE_DILITHIUM) && !defined(WOLFSSL_DILITHIUM_NO_SIGN) && \
    !defined(WOLFSSL_DILITHIUM_NO_ASN1)
    /* Try Falcon if key format is Dilithium level 2k, 3k or 5k or yet unknown.
     */
    if ((ret == 0) && ((*keyFormat == 0) || (*keyFormat == DILITHIUM_LEVEL2k) ||
            (*keyFormat == DILITHIUM_LEVEL3k) ||
            (*keyFormat == DILITHIUM_LEVEL5k))) {
        ret = ProcessBufferTryDecodeDilithium(ctx, ssl, der, keyFormat, heap,
            keyType, keySz);
    }
#endif /* HAVE_DILITHIUM */

    /* Check we know the format. */
    if ((ret == 0) && (*keyFormat == 0)) {
        WOLFSSL_MSG("Not a supported key type");
        /* Not supported key format. */
        ret = WOLFSSL_BAD_FILE;
    }

    return ret;
}

#if defined(WOLFSSL_ENCRYPTED_KEYS) && !defined(NO_PWDBASED)
/* Decrypt PKCS#8 private key.
 *
 * @param [in] info   Encryption information.
 * @param [in] der    DER encoded data.
 * @param [in] heap   Dynamic memory allocation hint.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails.
 */
static int ProcessBufferPrivPkcs8Dec(EncryptedInfo* info, DerBuffer* der,
    void* heap)
{
    int ret = 0;
    word32 algId;
    int   passwordSz = NAME_SZ;
#ifndef WOLFSSL_SMALL_STACK
    char  password[NAME_SZ];
#else
    char* password;
#endif

    (void)heap;
#ifdef WOLFSSL_SMALL_STACK
    /* Allocate memory for password. */
    password = (char*)XMALLOC(passwordSz, heap, DYNAMIC_TYPE_STRING);
    if (password == NULL) {
        ret = MEMORY_E;
    }
#endif

    if (ret == 0) {
        /* Get password. */
        ret = info->passwd_cb(password, passwordSz, PEM_PASS_READ,
            info->passwd_userdata);
    }
    if (ret >= 0) {
        /* Returned value is password size. */
        passwordSz = ret;
    #ifdef WOLFSSL_CHECK_MEM_ZERO
        wc_MemZero_Add("ProcessBuffer password", password, passwordSz);
    #endif

        /* Decrypt PKCS#8 private key inline and get algorithm id. */
        ret = ToTraditionalEnc(der->buffer, der->length, password, passwordSz,
            &algId);
    }
    if (ret >= 0) {
        /* Zero out encrypted data not overwritten. */
        ForceZero(der->buffer + ret, der->length - ret);
        /* Set decrypted data length. */
        der->length = (word32)ret;
    }

#ifdef WOLFSSL_SMALL_STACK
    if (password != NULL)
#endif
    {
        /* Ensure password is zeroized. */
        ForceZero(password, (word32)passwordSz);
    }
#ifdef WOLFSSL_SMALL_STACK
    /* Dispose of password memory. */
    XFREE(password, heap, DYNAMIC_TYPE_STRING);
#elif defined(WOLFSSL_CHECK_MEM_ZERO)
    wc_MemZero_Check(password, NAME_SZ);
#endif
    return ret;
}
#endif /* WOLFSSL_ENCRYPTED_KEYS && !NO_PWDBASED */

/* Put the DER into the SSL or SSL context object.
 *
 * Precondition: ctx or ssl is not NULL.
 * Precondition: Must be a private key type.
 *
 * @param [in, out] ctx  SSL context object.
 * @param [in, out] ssl  SSL object.
 * @param [in]      der  DER encoding.
 * @return  0 on success.
 */
static int ProcessBufferPrivKeyHandleDer(WOLFSSL_CTX* ctx, WOLFSSL* ssl,
    DerBuffer** der, int type)
{
    int ret = 0;

    (void)type;

#ifdef WOLFSSL_DUAL_ALG_CERTS
    if (type == ALT_PRIVATEKEY_TYPE) {
        /* Put in alternate private key fields of objects. */
        if (ssl != NULL) {
            /* Dispose of previous key if not context's. */
            if (ssl->buffers.weOwnAltKey) {
                FreeDer(&ssl->buffers.altKey);
            #ifdef WOLFSSL_BLIND_PRIVATE_KEY
                FreeDer(&ssl->buffers.altKeyMask);
            #endif
            }
            ssl->buffers.altKeyId = 0;
            ssl->buffers.altKeyLabel = 0;
            ssl->buffers.altKeyDevId = INVALID_DEVID;
            /* Store key by reference and own it. */
            ssl->buffers.altKey = *der;
        #ifdef WOLFSSL_CHECK_MEM_ZERO
            wc_MemZero_Add("SSL Buffers key", (*der)->buffer, (*der)->length);
        #endif
            ssl->buffers.weOwnAltKey = 1;
        }
        else if (ctx != NULL) {
            /* Dispose of previous key. */
            FreeDer(&ctx->altPrivateKey);
            ctx->altPrivateKeyId = 0;
            ctx->altPrivateKeyLabel = 0;
            ctx->altPrivateKeyDevId = INVALID_DEVID;
            /* Store key by reference. */
            ctx->altPrivateKey = *der;
        #ifdef WOLFSSL_CHECK_MEM_ZERO
            wc_MemZero_Add("CTX private key", (*der)->buffer, (*der)->length);
        #endif
        }
    }
    else
#endif /* WOLFSSL_DUAL_ALG_CERTS */
    if (ssl != NULL) {
        /* Dispose of previous key if not context's. */
        if (ssl->buffers.weOwnKey) {
            FreeDer(&ssl->buffers.key);
        #ifdef WOLFSSL_BLIND_PRIVATE_KEY
            FreeDer(&ssl->buffers.keyMask);
        #endif
        }
        ssl->buffers.keyId = 0;
        ssl->buffers.keyLabel = 0;
        ssl->buffers.keyDevId = INVALID_DEVID;
        /* Store key by reference and own it. */
        ssl->buffers.key = *der;
    #ifdef WOLFSSL_CHECK_MEM_ZERO
        wc_MemZero_Add("SSL Buffers key", (*der)->buffer, (*der)->length);
    #endif
        ssl->buffers.weOwnKey = 1;
    }
    else if (ctx != NULL) {
        /* Dispose of previous key. */
        FreeDer(&ctx->privateKey);
        ctx->privateKeyId = 0;
        ctx->privateKeyLabel = 0;
        ctx->privateKeyDevId = INVALID_DEVID;
        /* Store key by reference. */
        ctx->privateKey = *der;
    #ifdef WOLFSSL_CHECK_MEM_ZERO
        wc_MemZero_Add("CTX private key", (*der)->buffer, (*der)->length);
    #endif
    }

    return ret;
}

/* Decode private key.
 *
 * Precondition: ctx or ssl is not NULL.
 * Precondition: Must be a private key type.
 *
 * @param [in, out] ctx     SSL context object.
 * @param [in, out] ssl     SSL object.
 * @param [in]      der     DER encoding.
 * @param [in]      format  Original format of data.
 * @param [in]      info    Encryption information.
 * @param [in]      heap    Dynamic memory allocation hint.
 * @param [in]      type    Type of data:
 *                            PRIVATEKEY_TYPE or ALT_PRIVATEKEY_TYPE.
 * @param [in]      algId   Algorithm id of key.
 * @return  0 on success.
 * @return  WOLFSSL_BAD_FILE when not able to decode.
 */
static int ProcessBufferPrivateKey(WOLFSSL_CTX* ctx, WOLFSSL* ssl,
    DerBuffer* der, int format, EncryptedInfo* info, void* heap, int type,
    int algId)
{
    int ret;

    (void)info;
    (void)format;

    /* Put the data into the SSL or SSL context object. */
    ret = ProcessBufferPrivKeyHandleDer(ctx, ssl, &der, type);
    if (ret == 0) {
        /* Try to decode the DER data. */
        ret = ProcessBufferTryDecode(ctx, ssl, der, &algId, heap, type);
    }

#if defined(WOLFSSL_ENCRYPTED_KEYS) && !defined(NO_PWDBASED)
    /* If private key type PKCS8 header wasn't already removed (algId == 0). */
    if (((ret != 0) || (algId == 0)) && (format != WOLFSSL_FILETYPE_PEM) &&
            (info->passwd_cb != NULL) && (algId == 0)) {
        /* Try to decrypt DER data as a PKCS#8 private key. */
        ret = ProcessBufferPrivPkcs8Dec(info, der, heap);
        if (ret >= 0) {
            /* Try to decode decrypted data.  */
            ret = ProcessBufferTryDecode(ctx, ssl, der, &algId, heap, type);
        }
    }
#endif /* WOLFSSL_ENCRYPTED_KEYS && !NO_PWDBASED */

#ifdef WOLFSSL_BLIND_PRIVATE_KEY
#ifdef WOLFSSL_DUAL_ALG_CERTS
    if (type == ALT_PRIVATEKEY_TYPE) {
        if (ssl != NULL) {
            ret = wolfssl_priv_der_blind(ssl->rng, ssl->buffers.altKey,
                &ssl->buffers.altKeyMask);
        }
        else {
            ret = wolfssl_priv_der_blind(NULL, ctx->altPrivateKey,
                &ctx->altPrivateKeyMask);
        }
    }
    else
#endif
    if (ssl != NULL) {
        ret = wolfssl_priv_der_blind(ssl->rng, ssl->buffers.key,
            &ssl->buffers.keyMask);
    }
    else {
        ret = wolfssl_priv_der_blind(NULL, ctx->privateKey,
            &ctx->privateKeyMask);
    }
#endif

    /* Check if we were able to determine algorithm id. */
    if ((ret == 0) && (algId == 0)) {
    #ifdef OPENSSL_EXTRA
        /* Decryption password is probably wrong. */
        if (info->passwd_cb) {
            WOLFSSL_EVPerr(0, -WOLFSSL_EVP_R_BAD_DECRYPT_E);
        }
    #endif
        WOLFSSL_ERROR(WOLFSSL_BAD_FILE);
        /* Unable to decode DER data. */
        ret = WOLFSSL_BAD_FILE;
    }

    return ret;
}

/* Use the key OID to determine have options.
 *
 * @param [in, out] ctx     SSL context object.
 * @param [in, out] ssl     SSL object.
 * @param [in]      keyOID  OID for public/private key.
 */
static void wolfssl_set_have_from_key_oid(WOLFSSL_CTX* ctx, WOLFSSL* ssl,
    int keyOID)
{
    /* Set which private key algorithm available based on key OID. */
    switch (keyOID) {
        case ECDSAk:
    #if defined(WOLFSSL_SM2) && defined(WOLFSSL_SM3)
        case SM2k:
    #endif
    #ifdef HAVE_ED25519
        case ED25519k:
    #endif
    #ifdef HAVE_ED448
        case ED448k:
    #endif
            if (ssl != NULL) {
                ssl->options.haveECC = 1;
            }
            else {
                ctx->haveECC = 1;
            }
            break;
    #ifndef NO_RSA
        case RSAk:
        #ifdef WC_RSA_PSS
        case RSAPSSk:
        #endif
            if (ssl != NULL) {
                ssl->options.haveRSA = 1;
            }
            else {
                ctx->haveRSA = 1;
            }
            break;
    #endif
    #ifdef HAVE_FALCON
        case FALCON_LEVEL1k:
        case FALCON_LEVEL5k:
            if (ssl != NULL) {
                ssl->options.haveFalconSig = 1;
            }
            else {
                ctx->haveFalconSig = 1;
            }
            break;
    #endif /* HAVE_FALCON */
    #ifdef HAVE_DILITHIUM
        case DILITHIUM_LEVEL2k:
        case DILITHIUM_LEVEL3k:
        case DILITHIUM_LEVEL5k:
            if (ssl != NULL) {
                ssl->options.haveDilithiumSig = 1;
            }
            else {
                ctx->haveDilithiumSig = 1;
            }
            break;
    #endif /* HAVE_DILITHIUM */
        default:
            WOLFSSL_MSG("Cert key not supported");
            break;
        }
}

/* Set which private key algorithm we have against SSL or SSL context object.
 *
 * Precondition: ctx or ssl is not NULL.
 *
 * @param [in, out] ctx     SSL context object.
 * @param [in, out] ssl     SSL object.
 * @param [in]      cert    Decode certificate.
 */
static void ProcessBufferCertSetHave(WOLFSSL_CTX* ctx, WOLFSSL* ssl,
    DecodedCert* cert)
{
    if (ssl != NULL) {
        /* Reset signatures we have in SSL. */
        ssl->options.haveECDSAsig = 0;
        ssl->options.haveFalconSig = 0;
        ssl->options.haveDilithiumSig = 0;
    }

    /* Set which signature we have based on the type in the cert. */
    switch (cert->signatureOID) {
        case CTC_SHAwECDSA:
        case CTC_SHA256wECDSA:
        case CTC_SHA384wECDSA:
        case CTC_SHA512wECDSA:
    #ifdef HAVE_ED25519
        case CTC_ED25519:
    #endif
    #ifdef HAVE_ED448
        case CTC_ED448:
    #endif
    #if defined(WOLFSSL_SM2) && defined(WOLFSSL_SM3)
        case CTC_SM3wSM2:
    #endif
            WOLFSSL_MSG("ECDSA/ED25519/ED448 cert signature");
            if (ssl) {
                ssl->options.haveECDSAsig = 1;
            }
            else if (ctx) {
                ctx->haveECDSAsig = 1;
            }
            break;
    #ifdef HAVE_FALCON
        case CTC_FALCON_LEVEL1:
        case CTC_FALCON_LEVEL5:
            WOLFSSL_MSG("Falcon cert signature");
            if (ssl) {
                ssl->options.haveFalconSig = 1;
            }
            else if (ctx) {
                ctx->haveFalconSig = 1;
            }
            break;
    #endif
    #ifdef HAVE_DILITHIUM
        case CTC_DILITHIUM_LEVEL2:
        case CTC_DILITHIUM_LEVEL3:
        case CTC_DILITHIUM_LEVEL5:
            WOLFSSL_MSG("Dilithium cert signature");
            if (ssl) {
                ssl->options.haveDilithiumSig = 1;
            }
            else if (ctx) {
                ctx->haveDilithiumSig = 1;
            }
            break;
    #endif
        default:
            WOLFSSL_MSG("Cert signature not supported");
            break;
    }

#if defined(HAVE_ECC) || defined(HAVE_ED25519) || defined(HAVE_ED448) || \
    defined(HAVE_FALCON) || defined(HAVE_DILITHIUM) || !defined(NO_RSA)
    #if defined(HAVE_ECC) || defined(HAVE_ED25519) || defined(HAVE_ED448)
    /* Set the private key curve OID. */
    if (ssl != NULL) {
        ssl->pkCurveOID = cert->pkCurveOID;
    }
    else if (ctx) {
        ctx->pkCurveOID = cert->pkCurveOID;
    }
    #endif
#ifndef WC_STRICT_SIG
    if ((ctx != NULL) || (ssl != NULL)) {
        wolfssl_set_have_from_key_oid(ctx, ssl, (int)cert->keyOID);
    }
#else
    /* Set whether ECC is available based on signature available. */
    if (ssl != NULL) {
        ssl->options.haveECC = ssl->options.haveECDSAsig;
    }
    else if (ctx) {
        ctx->haveECC = ctx->haveECDSAsig;
    }
#endif /* !WC_STRICT_SIG */
#endif
}

/* Check key size is valid.
 *
 * Precondition: ctx or ssl is not NULL.
 *
 * @param [in] min    Minimum key size.
 * @param [in] max    Maximum key size.
 * @param [in] keySz  Key size.
 * @param [in] err    Error value to return when key size is invalid.
 * @return  0 on success.
 * @return  err when verifying and min is less than 0 or key size is invalid.
 */
#define CHECK_KEY_SZ(min, max, keySz, err)                                     \
    (((min) < 0) || ((keySz) < (min)) || ((keySz) > (max))) ? (err) : 0

/* Check public key in certificate.
 *
 * @param [in, out] ctx   SSL context object.
 * @param [in, out] ssl   SSL object.
 * @param [in]      cert  Certificate object.
 * @return  0 on success.
 * @return  Non-zero when an error occurred.
 */
static int ProcessBufferCertPublicKey(WOLFSSL_CTX* ctx, WOLFSSL* ssl,
    DecodedCert* cert, int checkKeySz)
{
    int ret = 0;
    byte keyType = 0;
    int keySz = 0;
#ifndef NO_RSA
    word32 idx;
#endif

    /* Get key size and check unless not verifying. */
    switch (cert->keyOID) {
#ifndef NO_RSA
    #ifdef WC_RSA_PSS
        case RSAPSSk:
    #endif
        case RSAk:
            keyType = rsa_sa_algo;
            /* Determine RSA key size by parsing public key */
            idx = 0;
            ret = wc_RsaPublicKeyDecode_ex(cert->publicKey, &idx,
                cert->pubKeySize, NULL, (word32*)&keySz, NULL, NULL);
            if ((ret == 0) && checkKeySz) {
                ret = CHECK_KEY_SZ(ssl ? ssl->options.minRsaKeySz :
                    ctx->minRsaKeySz, RSA_MAX_SIZE / 8, keySz, RSA_KEY_SIZE_E);
            }
            break;
#endif /* !NO_RSA */
    #ifdef HAVE_ECC
        case ECDSAk:
            keyType = ecc_dsa_sa_algo;
            /* Determine ECC key size based on curve */
        #ifdef WOLFSSL_CUSTOM_CURVES
            if ((cert->pkCurveOID == 0) && (cert->pkCurveSize != 0)) {
                keySz = cert->pkCurveSize;
            }
            else
        #endif
            {
                keySz = wc_ecc_get_curve_size_from_id(wc_ecc_get_oid(
                    cert->pkCurveOID, NULL, NULL));
            }

            if (checkKeySz) {
                ret = CHECK_KEY_SZ(ssl ? ssl->options.minEccKeySz :
                     ctx->minEccKeySz, (MAX_ECC_BITS + 7) / 8, keySz,
                     ECC_KEY_SIZE_E);
            }
            break;
    #endif /* HAVE_ECC */
    #if defined(WOLFSSL_SM2) && defined(WOLFSSL_SM3)
        case SM2k:
            keyType = sm2_sa_algo;
            /* Determine ECC key size based on curve */
            keySz = WOLFSSL_SM2_KEY_BITS / 8;
            if (checkKeySz) {
                ret = CHECK_KEY_SZ(ssl ? ssl->options.minEccKeySz :
                    ctx->minEccKeySz, (MAX_ECC_BITS + 7) / 8, keySz,
                    ECC_KEY_SIZE_E);
            }
            break;
    #endif /* HAVE_ED25519 */
    #ifdef HAVE_ED25519
        case ED25519k:
            keyType = ed25519_sa_algo;
            /* ED25519 is fixed key size */
            keySz = ED25519_KEY_SIZE;
            if (checkKeySz) {
                ret = CHECK_KEY_SZ(ssl ? ssl->options.minEccKeySz :
                    ctx->minEccKeySz, ED25519_KEY_SIZE, keySz, ECC_KEY_SIZE_E);
            }
            break;
    #endif /* HAVE_ED25519 */
    #ifdef HAVE_ED448
        case ED448k:
            keyType = ed448_sa_algo;
            /* ED448 is fixed key size */
            keySz = ED448_KEY_SIZE;
            if (checkKeySz) {
                ret = CHECK_KEY_SZ(ssl ? ssl->options.minEccKeySz :
                    ctx->minEccKeySz, ED448_KEY_SIZE, keySz, ECC_KEY_SIZE_E);
            }
            break;
    #endif /* HAVE_ED448 */
    #if defined(HAVE_FALCON)
        case FALCON_LEVEL1k:
            keyType = falcon_level1_sa_algo;
            /* Falcon is fixed key size */
            keySz = FALCON_LEVEL1_KEY_SIZE;
            if (checkKeySz) {
                ret = CHECK_KEY_SZ(ssl ? ssl->options.minFalconKeySz :
                    ctx->minFalconKeySz, FALCON_MAX_KEY_SIZE, keySz,
                    FALCON_KEY_SIZE_E);
            }
            break;
        case FALCON_LEVEL5k:
            keyType = falcon_level5_sa_algo;
            /* Falcon is fixed key size */
            keySz = FALCON_LEVEL5_KEY_SIZE;
            if (checkKeySz) {
                ret = CHECK_KEY_SZ(ssl ? ssl->options.minFalconKeySz :
                    ctx->minFalconKeySz, FALCON_MAX_KEY_SIZE, keySz,
                    FALCON_KEY_SIZE_E);
            }
            break;
    #endif /* HAVE_FALCON */
    #if defined(HAVE_DILITHIUM)
        case DILITHIUM_LEVEL2k:
            keyType = dilithium_level2_sa_algo;
            /* Dilithium is fixed key size */
            keySz = DILITHIUM_LEVEL2_KEY_SIZE;
            if (checkKeySz) {
                ret = CHECK_KEY_SZ(ssl ? ssl->options.minDilithiumKeySz :
                    ctx->minDilithiumKeySz, DILITHIUM_MAX_KEY_SIZE, keySz,
                    DILITHIUM_KEY_SIZE_E);
            }
            break;
        case DILITHIUM_LEVEL3k:
            keyType = dilithium_level3_sa_algo;
            /* Dilithium is fixed key size */
            keySz = DILITHIUM_LEVEL3_KEY_SIZE;
            if (checkKeySz) {
                ret = CHECK_KEY_SZ(ssl ? ssl->options.minDilithiumKeySz :
                    ctx->minDilithiumKeySz, DILITHIUM_MAX_KEY_SIZE, keySz,
                    DILITHIUM_KEY_SIZE_E);
            }
            break;
        case DILITHIUM_LEVEL5k:
            keyType = dilithium_level5_sa_algo;
            /* Dilithium is fixed key size */
            keySz = DILITHIUM_LEVEL5_KEY_SIZE;
            if (checkKeySz) {
                ret = CHECK_KEY_SZ(ssl ? ssl->options.minDilithiumKeySz :
                    ctx->minDilithiumKeySz, DILITHIUM_MAX_KEY_SIZE, keySz,
                    DILITHIUM_KEY_SIZE_E);
            }
            break;
    #endif /* HAVE_DILITHIUM */

        default:
            WOLFSSL_MSG("No key size check done on public key in certificate");
            break;
    }

    /* Store the type and key size as there may not be a private key set. */
    if (ssl != NULL) {
        ssl->buffers.keyType = keyType;
        ssl->buffers.keySz = keySz;
    }
    else {
        ctx->privateKeyType = keyType;
        ctx->privateKeySz = keySz;
    }

    return ret;
}

#ifdef WOLFSSL_DUAL_ALG_CERTS
static int ProcessBufferCertAltPublicKey(WOLFSSL_CTX* ctx, WOLFSSL* ssl,
    DecodedCert* cert, int checkKeySz)
{
    int ret = 0;
    void* heap = WOLFSSL_HEAP(ctx, ssl);
    byte keyType = 0;
    int keySz = 0;
#ifndef NO_RSA
    word32 idx;
#endif

    /* Check alternative key size of cert. */
    switch (cert->sapkiOID) {
        /* No OID set. */
        case 0:
            if (cert->sapkiLen != 0) {
                /* Have the alternative key data but no OID. */
                ret = NOT_COMPILED_IN;
            }
            break;

#ifndef NO_RSA
    #ifdef WC_RSA_PSS
        case RSAPSSk:
    #endif
        case RSAk:
            keyType = rsa_sa_algo;
            /* Determine RSA key size by parsing public key */
            idx = 0;
            ret = wc_RsaPublicKeyDecode_ex(cert->sapkiDer, &idx,
                cert->sapkiLen, NULL, (word32*)&keySz, NULL, NULL);
            if ((ret == 0) && checkKeySz) {
                ret = CHECK_KEY_SZ(ssl ? ssl->options.minRsaKeySz :
                    ctx->minRsaKeySz, RSA_MAX_SIZE / 8, keySz, RSA_KEY_SIZE_E);
            }
            break;
#endif /* !NO_RSA */
    #ifdef HAVE_ECC
        case ECDSAk:
        {
        #ifdef WOLFSSL_SMALL_STACK
            ecc_key* temp_key = NULL;
        #else
            ecc_key temp_key[1];
        #endif
            keyType = ecc_dsa_sa_algo;

        #ifdef WOLFSSL_SMALL_STACK
            temp_key = (ecc_key*)XMALLOC(sizeof(ecc_key), heap,
                DYNAMIC_TYPE_ECC);
            if (temp_key == NULL) {
                ret = MEMORY_E;
            }
        #endif

            /* Determine ECC key size. We have to decode the sapki for
             * that. */
            if (ret == 0) {
                ret = wc_ecc_init_ex(temp_key, heap, INVALID_DEVID);
                if (ret == 0) {
                    idx = 0;
                    ret = wc_EccPublicKeyDecode(cert->sapkiDer, &idx, temp_key,
                        cert->sapkiLen);
                    if (ret == 0) {
                        keySz = wc_ecc_size(temp_key);
                    }
                    wc_ecc_free(temp_key);
                }
            }
        #ifdef WOLFSSL_SMALL_STACK
            XFREE(temp_key, heap, DYNAMIC_TYPE_ECC);
        #endif

            if ((ret == 0) && checkKeySz) {
                ret = CHECK_KEY_SZ(ssl ? ssl->options.minEccKeySz :
                     ctx->minEccKeySz, (MAX_ECC_BITS + 7) / 8, keySz,
                     ECC_KEY_SIZE_E);
            }
            break;
        }
    #endif /* HAVE_ECC */
    #if defined(WOLFSSL_SM2) && defined(WOLFSSL_SM3)
        case SM2k:
            keyType = sm2_sa_algo;
            /* Determine ECC key size based on curve */
            keySz = WOLFSSL_SM2_KEY_BITS / 8;
            if (checkKeySz) {
                ret = CHECK_KEY_SZ(ssl ? ssl->options.minEccKeySz :
                    ctx->minEccKeySz, (MAX_ECC_BITS + 7) / 8, keySz,
                    ECC_KEY_SIZE_E);
            }
            break;
    #endif /* HAVE_ED25519 */
    #ifdef HAVE_ED25519
        case ED25519k:
            keyType = ed25519_sa_algo;
            /* ED25519 is fixed key size */
            keySz = ED25519_KEY_SIZE;
            if (checkKeySz) {
                ret = CHECK_KEY_SZ(ssl ? ssl->options.minEccKeySz :
                    ctx->minEccKeySz, ED25519_KEY_SIZE, keySz, ECC_KEY_SIZE_E);
            }
            break;
    #endif /* HAVE_ED25519 */
    #ifdef HAVE_ED448
        case ED448k:
            keyType = ed448_sa_algo;
            /* ED448 is fixed key size */
            keySz = ED448_KEY_SIZE;
            if (checkKeySz) {
                ret = CHECK_KEY_SZ(ssl ? ssl->options.minEccKeySz :
                    ctx->minEccKeySz, ED448_KEY_SIZE, keySz, ECC_KEY_SIZE_E);
            }
            break;
    #endif /* HAVE_ED448 */
    #if defined(HAVE_FALCON)
        case FALCON_LEVEL1k:
            keyType = falcon_level1_sa_algo;
            /* Falcon is fixed key size */
            keySz = FALCON_LEVEL1_KEY_SIZE;
            if (checkKeySz) {
                ret = CHECK_KEY_SZ(ssl ? ssl->options.minFalconKeySz :
                    ctx->minFalconKeySz, FALCON_MAX_KEY_SIZE, keySz,
                    FALCON_KEY_SIZE_E);
            }
            break;
        case FALCON_LEVEL5k:
            keyType = falcon_level5_sa_algo;
            /* Falcon is fixed key size */
            keySz = FALCON_LEVEL5_KEY_SIZE;
            if (checkKeySz) {
                ret = CHECK_KEY_SZ(ssl ? ssl->options.minFalconKeySz :
                    ctx->minFalconKeySz, FALCON_MAX_KEY_SIZE, keySz,
                    FALCON_KEY_SIZE_E);
            }
            break;
    #endif /* HAVE_FALCON */
    #if defined(HAVE_DILITHIUM)
        case DILITHIUM_LEVEL2k:
            keyType = dilithium_level2_sa_algo;
            /* Dilithium is fixed key size */
            keySz = DILITHIUM_LEVEL2_KEY_SIZE;
            if (checkKeySz) {
                ret = CHECK_KEY_SZ(ssl ? ssl->options.minDilithiumKeySz :
                    ctx->minDilithiumKeySz, DILITHIUM_MAX_KEY_SIZE, keySz,
                    DILITHIUM_KEY_SIZE_E);
            }
            break;
        case DILITHIUM_LEVEL3k:
            keyType = dilithium_level3_sa_algo;
            /* Dilithium is fixed key size */
            keySz = DILITHIUM_LEVEL3_KEY_SIZE;
            if (checkKeySz) {
                ret = CHECK_KEY_SZ(ssl ? ssl->options.minDilithiumKeySz :
                    ctx->minDilithiumKeySz, DILITHIUM_MAX_KEY_SIZE, keySz,
                    DILITHIUM_KEY_SIZE_E);
            }
            break;
        case DILITHIUM_LEVEL5k:
            keyType = dilithium_level5_sa_algo;
            /* Dilithium is fixed key size */
            keySz = DILITHIUM_LEVEL5_KEY_SIZE;
            if (checkKeySz) {
                ret = CHECK_KEY_SZ(ssl ? ssl->options.minDilithiumKeySz :
                    ctx->minDilithiumKeySz, DILITHIUM_MAX_KEY_SIZE, keySz,
                    DILITHIUM_KEY_SIZE_E);
            }
            break;
    #endif /* HAVE_DILITHIUM */

        default:
            /* In this case, there was an OID that we didn't recognize.
             * This is an error. Use not compiled in because likely the
             * given algorithm was not enabled. */
            ret = NOT_COMPILED_IN;
            WOLFSSL_MSG("No alt key size check done on certificate");
            break;
    }

    if (ssl != NULL) {
        ssl->buffers.altKeyType = (byte)keyType;
        ssl->buffers.altKeySz = keySz;
    }
    else if (ctx != NULL) {
        ctx->altPrivateKeyType = (byte)keyType;
        ctx->altPrivateKeySz = keySz;
    }

    return ret;
}
#endif /* WOLFSSL_DUAL_ALG_CERTS */

/* Parse the certificate and pull out information for TLS handshake.
 *
 * @param [in, out] ctx   SSL context object.
 * @param [in, out] ssl   SSL object.
 * @param [in]      der   DER encoded X509 certificate.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  WOLFSSL_BAD_FILE when decoding certificate fails.
 */
static int ProcessBufferCert(WOLFSSL_CTX* ctx, WOLFSSL* ssl, DerBuffer* der)
{
    int ret = 0;
    void* heap = WOLFSSL_HEAP(ctx, ssl);
#if defined(HAVE_RPK)
    RpkState* rpkState = ssl ? &ssl->options.rpkState : &ctx->rpkState;
#endif
#ifdef WOLFSSL_SMALL_STACK
    DecodedCert* cert;
#else
    DecodedCert  cert[1];
#endif

#ifdef WOLFSSL_SMALL_STACK
    /* Allocate memory for certificate to be decoded into. */
    cert = (DecodedCert*)XMALLOC(sizeof(DecodedCert), heap, DYNAMIC_TYPE_DCERT);
    if (cert == NULL) {
        ret = MEMORY_E;
    }

    if (ret == 0)
#endif
    {
        /* Get device id from SSL context or SSL object. */
        int devId = wolfSSL_CTX_GetDevId(ctx, ssl);

        WOLFSSL_MSG("Checking cert signature type");
        /* Initialize certificate object. */
        InitDecodedCert_ex(cert, der->buffer, der->length, heap, devId);

        /* Decode up to and including public key. */
        if (DecodeToKey(cert, 0) < 0) {
            WOLFSSL_MSG("Decode to key failed");
            ret = WOLFSSL_BAD_FILE;
        }
        if (ret == 0) {
            int checkKeySz = 1;

        #if defined(HAVE_RPK)
            /* Store whether the crtificate is a raw public key. */
            rpkState->isRPKLoaded = cert->isRPK;
        #endif /* HAVE_RPK */

            /* Set which private key algorithm we have. */
            ProcessBufferCertSetHave(ctx, ssl, cert);

            /* Don't check if verification is disabled for SSL. */
            if ((ssl != NULL) && ssl->options.verifyNone) {
                checkKeySz = 0;
            }
            /* Don't check if no SSL object verification is disabled for SSL
             * context. */
            else if ((ssl == NULL) && ctx->verifyNone) {
                checkKeySz = 0;
            }

            /* Check public key size. */
            ret = ProcessBufferCertPublicKey(ctx, ssl, cert, checkKeySz);
        #ifdef WOLFSSL_DUAL_ALG_CERTS
            if (ret == 0) {
                ret = ProcessBufferCertAltPublicKey(ctx, ssl, cert, checkKeySz);
            }
        #endif
        }
    }

    /* Dispose of dynamic memory in certificate object. */
    FreeDecodedCert(cert);
#ifdef WOLFSSL_SMALL_STACK
    /* Dispose of certificate object. */
    XFREE(cert, heap, DYNAMIC_TYPE_DCERT);
#endif
    return ret;
}

/* Handle storing the DER encoding of the certificate.
 *
 * Do not free der outside of this function.
 *
 * @param [in, out] ctx     SSL context object.
 * @param [in, out] ssl     SSL object.
 * @param [in]      der     DER encoded certificate.
 * @param [in]      type    Type of data:
 *                            CERT_TYPE, CA_TYPE or TRUSTED_PEER_TYPE.
 * @param [in]      verify  What verification to do.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when type is CA_TYPE and ctx is NULL.
 * @return  WOLFSSL_BAD_CERTTYPE when data type is not supported.
 */
static int ProcessBufferCertHandleDer(WOLFSSL_CTX* ctx, WOLFSSL* ssl,
    DerBuffer* der, int type, int verify)
{
    int ret = 0;

    /* CA certificate to verify with. */
    if (type == CA_TYPE) {
        /* verify CA unless user set to no verify */
        ret = AddCA(ctx->cm, &der, WOLFSSL_USER_CA, verify);
        if (ret == 1) {
            ret = 0;
        }
    }
#ifdef WOLFSSL_TRUST_PEER_CERT
    /* Trusted certificate to verify peer with. */
    else if (type == TRUSTED_PEER_TYPE) {
        WOLFSSL_CERT_MANAGER* cm;

        /* Get certificate manager to add certificate to. */
        if (ctx != NULL) {
            cm = ctx->cm;
        }
        else {
            SSL_CM_WARNING(ssl);
            cm = SSL_CM(ssl);
        }
        /* Add certificate as a trusted peer. */
        ret = AddTrustedPeer(cm, &der, verify);
        if (ret != 1) {
            WOLFSSL_MSG("Error adding trusted peer");
        }
    }
#endif /* WOLFSSL_TRUST_PEER_CERT */
    /* Leaf certificate - our certificate. */
    else if (type == CERT_TYPE) {
        if (ssl != NULL) {
            /* Free previous certificate if we own it. */
            if (ssl->buffers.weOwnCert) {
                FreeDer(&ssl->buffers.certificate);
            #ifdef KEEP_OUR_CERT
                /* Dispose of X509 version of certificate. */
                wolfSSL_X509_free(ssl->ourCert);
                ssl->ourCert = NULL;
            #endif
            }
            /* Store certificate as ours. */
            ssl->buffers.certificate = der;
        #ifdef KEEP_OUR_CERT
            ssl->keepCert = 1; /* hold cert for ssl lifetime */
        #endif
            /* We have to free the certificate buffer. */
            ssl->buffers.weOwnCert = 1;
            /* ourCert is created on demand. */
        }
        else if (ctx != NULL) {
            /* Free previous certificate. */
            FreeDer(&ctx->certificate); /* Make sure previous is free'd */
        #ifdef KEEP_OUR_CERT
            /* Dispose of X509 version of certificate if we own it. */
            if (ctx->ownOurCert) {
                wolfSSL_X509_free(ctx->ourCert);
            }
            ctx->ourCert = NULL;
        #endif
            /* Store certificate as ours. */
            ctx->certificate = der;
            /* ourCert is created on demand. */
        }
    }
    else {
        /* Dispose of DER buffer. */
        FreeDer(&der);
        /* Not a certificate type supported. */
        ret = WOLFSSL_BAD_CERTTYPE;
    }

    return ret;
}

/* Process certificate based on type.
 *
 * @param [in, out] ctx     SSL context object.
 * @param [in, out] ssl     SSL object.
 * @param [in]      buff    Buffer holding original data.
 * @param [in]      sz      Size of data in buffer.
 * @param [in]      der     DER encoding of certificate.
 * @param [in]      format  Format of data.
 * @param [in]      type    Type of data:
 *                            CERT_TYPE, CA_TYPE or TRUSTED_PEER_TYPE.
 * @param [in]      verify  What verification to do.
 * @return  0 on success.
 * @return  WOLFSSL_FATAL_ERROR on failure.
 */
static int ProcessBufferCertTypes(WOLFSSL_CTX* ctx, WOLFSSL* ssl,
    const unsigned char* buff, long sz, DerBuffer* der, int format, int type,
    int verify)
{
    int ret;

    (void)buff;
    (void)sz;
    (void)format;

    ret = ProcessBufferCertHandleDer(ctx, ssl, der, type, verify);
    if ((ret == 0) && (type == CERT_TYPE)) {
        /* Process leaf certificate. */
        ret = ProcessBufferCert(ctx, ssl, der);
    }
#if !defined(NO_WOLFSSL_CM_VERIFY) && (!defined(NO_WOLFSSL_CLIENT) || \
    !defined(WOLFSSL_NO_CLIENT_AUTH))
    /* Hand bad CA or user certificate to callback. */
    if ((ret < 0) && ((type == CA_TYPE) || (type == CERT_TYPE))) {
        /* Check for verification callback that may override error. */
        if ((ctx != NULL) && (ctx->cm != NULL) &&
                (ctx->cm->verifyCallback != NULL)) {
            /* Verify and use callback. */
            ret = CM_VerifyBuffer_ex(ctx->cm, buff, sz, format, ret);
            /* Convert error. */
            if (ret == 0) {
                ret = WOLFSSL_FATAL_ERROR;
            }
            if (ret == 1) {
                ret = 0;
            }
        }
    }
#endif /* NO_WOLFSSL_CM_VERIFY */

    return ret;
}

/* Reset the cipher suites based on updated private key or certificate.
 *
 * @param [in, out] ctx     SSL context object.
 * @param [in, out] ssl     SSL object.
 * @param [in]      type    Type of certificate.
 * @return  0 on success.
 * @return  WOLFSSL_FATAL_ERROR when allocation fails.
 */
static int ProcessBufferResetSuites(WOLFSSL_CTX* ctx, WOLFSSL* ssl, int type)
{
    int ret = 0;

    /* Reset suites of SSL object. */
    if (ssl != NULL) {
        if (ssl->options.side == WOLFSSL_SERVER_END) {
            /* Allocate memory for suites. */
            if (AllocateSuites(ssl) != 0) {
                ret = WOLFSSL_FATAL_ERROR;
            }
            else {
                /* Determine cipher suites based on what we have. */
                InitSuites(ssl->suites, ssl->version, ssl->buffers.keySz,
                    WOLFSSL_HAVE_RSA, SSL_HAVE_PSK(ssl), ssl->options.haveDH,
                    ssl->options.haveECDSAsig, ssl->options.haveECC, TRUE,
                    ssl->options.haveStaticECC,
                    ssl->options.useAnon, TRUE,
                    TRUE, TRUE, TRUE, ssl->options.side);
            }
        }
    }
    /* Reset suites of SSL context object. */
    else if ((type == CERT_TYPE) && (ctx->method->side == WOLFSSL_SERVER_END)) {
        /* Allocate memory for suites. */
        if (AllocateCtxSuites(ctx) != 0) {
            ret = WOLFSSL_FATAL_ERROR;
        }
        else {
            /* Determine cipher suites based on what we have. */
            InitSuites(ctx->suites, ctx->method->version, ctx->privateKeySz,
                WOLFSSL_HAVE_RSA, CTX_HAVE_PSK(ctx), ctx->haveDH,
                ctx->haveECDSAsig, ctx->haveECC, TRUE, ctx->haveStaticECC,
                CTX_USE_ANON(ctx),
                TRUE, TRUE, TRUE, TRUE, ctx->method->side);
        }
    }

    return ret;
}

#ifndef WOLFSSL_DUAL_ALG_CERTS
    /* Determine whether the type is for a private key. */
    #define IS_PRIVKEY_TYPE(type) ((type) == PRIVATEKEY_TYPE)
#else
    /* Determine whether the type is for a private key. */
    #define IS_PRIVKEY_TYPE(type) (((type) == PRIVATEKEY_TYPE) ||   \
                                   ((type) == ALT_PRIVATEKEY_TYPE))
#endif

/* Process a buffer of data.
 *
 * Data type is a private key or a certificate.
 * The format can be ASN.1 (DER) or PEM.
 *
 * @param [in, out] ctx        SSL context object.
 * @param [in]      buff       Buffer holding data.
 * @param [in]      sz         Size of data in buffer.
 * @param [in]      format     Format of data:
 *                               WOLFSSL_FILETYPE_PEM or WOLFSSL_FILETYPE_ASN1.
 * @param [in]      type       Type of data:
 *                               CERT_TYPE, CA_TYPE, TRUSTED_PEER_TYPE,
 *                               PRIVATEKEY_TYPE or ALT_PRIVATEKEY_TYPE.
 * @param [in, out] ssl        SSL object.
 * @param [out]     used       Number of bytes consumed.
 * @param [in[      userChain  Whether this certificate is for user's chain.
 * @param [in]      verify     How to verify certificate.
 * @return  1 on success.
 * @return  Less than 1 on failure.
 */
int ProcessBuffer(WOLFSSL_CTX* ctx, const unsigned char* buff, long sz,
    int format, int type, WOLFSSL* ssl, long* used, int userChain, int verify)
{
    DerBuffer*    der = NULL;
    int           ret = 0;
    void*         heap = WOLFSSL_HEAP(ctx, ssl);
#ifdef WOLFSSL_SMALL_STACK
    EncryptedInfo* info = NULL;
#else
    EncryptedInfo  info[1];
#endif
    int           algId = 0;

    WOLFSSL_ENTER("ProcessBuffer");

    /* Check data format is supported. */
    if ((format != WOLFSSL_FILETYPE_ASN1) && (format != WOLFSSL_FILETYPE_PEM)) {
        ret = WOLFSSL_BAD_FILETYPE;
    }
    /* Need an object to store certificate into. */
    if ((ret == 0) && (ctx == NULL) && (ssl == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* CA certificates go into the SSL context object. */
    if ((ret == 0) && (ctx == NULL) && (type == CA_TYPE)) {
        ret = BAD_FUNC_ARG;
    }
    /* This API does not handle CHAIN_CERT_TYPE */
    if ((ret == 0) && (type == CHAIN_CERT_TYPE)) {
        ret = BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_SMALL_STACK
    if (ret == 0) {
        /* Allocate memory for encryption information. */
        info = (EncryptedInfo*)XMALLOC(sizeof(EncryptedInfo), heap,
            DYNAMIC_TYPE_ENCRYPTEDINFO);
        if (info == NULL) {
            ret = MEMORY_E;
        }
    }
#endif
    if (ret == 0) {
        /* Initialize encryption information. */
        XMEMSET(info, 0, sizeof(EncryptedInfo));
    #if defined(WOLFSSL_ENCRYPTED_KEYS) && !defined(NO_PWDBASED)
        if (ctx != NULL) {
            info->passwd_cb       = ctx->passwd_cb;
            info->passwd_userdata = ctx->passwd_userdata;
        }
    #endif

        /* Get the DER data for a private key or certificate. */
        ret = DataToDerBuffer(buff, (word32)sz, format, type, info, heap, &der,
            &algId);
        if (used != NULL) {
            /* Update to amount used/consumed. */
            *used = info->consumed;
        }
    #ifdef WOLFSSL_SMALL_STACK
        if (ret != 0) {
             /* Info no longer needed as loading failed. */
             XFREE(info, heap, DYNAMIC_TYPE_ENCRYPTEDINFO);
        }
    #endif
    }

    if ((ret == 0) && IS_PRIVKEY_TYPE(type)) {
        /* Process the private key. */
        ret = ProcessBufferPrivateKey(ctx, ssl, der, format, info, heap, type,
            algId);
    #ifdef WOLFSSL_SMALL_STACK
        /* Info no longer needed - keep max memory usage down. */
        XFREE(info, heap, DYNAMIC_TYPE_ENCRYPTEDINFO);
    #endif
    }
    else if (ret == 0) {
        /* Processing a certificate. */
        if (userChain) {
            /* Take original buffer and add to user chain to send in TLS
             * handshake. */
            ret = ProcessUserChain(ctx, ssl, buff, sz, format, type, used, info,
                verify);
            /* Additional chain is optional */
            if (ret == WC_NO_ERR_TRACE(ASN_NO_PEM_HEADER)) {
                unsigned long pemErr = 0;
                CLEAR_ASN_NO_PEM_HEADER_ERROR(pemErr);
                ret = 0;
            }
        }

    #ifdef WOLFSSL_SMALL_STACK
        /* Info no longer needed - keep max memory usage down. */
        XFREE(info, heap, DYNAMIC_TYPE_ENCRYPTEDINFO);
    #endif

        if (ret == 0) {
            /* Process the different types of certificates. */
            ret = ProcessBufferCertTypes(ctx, ssl, buff, sz, der, format, type,
                verify);
        }
        else {
            FreeDer(&der);
        }
    }

    /* Reset suites if this is a private key or user certificate. */
    if ((ret == 0) && ((type == PRIVATEKEY_TYPE) || (type == CERT_TYPE))) {
        ret = ProcessBufferResetSuites(ctx, ssl, type);
    }

    /* Convert return code. */
    if (ret == 0) {
        ret = 1;
    }
    else if (ret == WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)) {
        ret = 0;
    }
    WOLFSSL_LEAVE("ProcessBuffer", ret);
    return ret;
}

#if defined(WOLFSSL_WPAS) && defined(HAVE_CRL)
/* Try to parse data as a PEM CRL.
 *
 * @param [in]  ctx       SSL context object.
 * @param [in]  buff      Buffer containing potential CRL in PEM format.
 * @param [in]  sz        Amount of data in buffer remaining.
 * @param [out] consumed  Number of bytes in buffer was the CRL.
 * @return  0 on success.
 */
static int ProcessChainBufferCRL(WOLFSSL_CTX* ctx, const unsigned char* buff,
    long sz, long* consumed)
{
    int           ret;
    DerBuffer*    der = NULL;
    EncryptedInfo info;

    WOLFSSL_MSG("Trying a CRL");
    ret = PemToDer(buff, sz, CRL_TYPE, &der, NULL, &info, NULL);
    if (ret == 0) {
        WOLFSSL_MSG("   Processed a CRL");
        wolfSSL_CertManagerLoadCRLBuffer(ctx->cm, der->buffer, der->length,
            WOLFSSL_FILETYPE_ASN1);
        FreeDer(&der);
        *consumed = info.consumed;
    }

    return ret;
}
#endif

/* Process all chain certificates (and CRLs) in the PEM data.
 *
 * @param [in, out] ctx     SSL context object.
 * @param [in, out] ssl     SSL object.
 * @param [in]      buff    Buffer containing PEM data.
 * @param [in]      sz      Size of data in buffer.
 * @param [in]      type    Type of data.
 * @param [in]      verify  How to verify certificate.
 * @return  1 on success.
 * @return  0 on failure.
 * @return  MEMORY_E when dynamic memory allocation fails.
 */
static int ProcessChainBuffer(WOLFSSL_CTX* ctx, WOLFSSL* ssl,
    const unsigned char* buff, long sz, int type, int verify)
{
    int  ret    = 0;
    long used   = 0;
    int  gotOne = 0;

    WOLFSSL_MSG("Processing CA PEM file");
    /* Keep processing file while no errors and data to parse. */
    while ((ret >= 0) && (used < sz)) {
        long consumed = 0;

        /* Process the buffer. */
        ret = ProcessBuffer(ctx, buff + used, sz - used, WOLFSSL_FILETYPE_PEM,
            type, ssl, &consumed, 0, verify);
        /* Memory allocation failure is fatal. */
        if (ret == WC_NO_ERR_TRACE(MEMORY_E)) {
            gotOne = 0;
        }
        /* Other error parsing. */
        else if (ret < 0) {
#if defined(WOLFSSL_WPAS) && defined(HAVE_CRL)
            /* Try parsing a CRL. */
            if (ProcessChainBufferCRL(ctx, buff + used, sz - used,
                    &consumed) == 0) {
                ret = 0;
            }
            else
#endif
            /* Check whether we made progress. */
            if (consumed > 0) {
                WOLFSSL_ERROR(ret);
                WOLFSSL_MSG("CA Parse failed, with progress in file.");
                WOLFSSL_MSG("Search for other certs in file");
                /* Check if we have more data to parse to recover. */
                if (used + consumed < sz) {
                    ret = 0;
                }
            }
            else {
                /* No progress in parsing being made - stop here. */
                WOLFSSL_MSG("CA Parse failed, no progress in file.");
                WOLFSSL_MSG("Do not continue search for other certs in file");
            }
        }
        else {
            /* Got a certificate out. */
            WOLFSSL_MSG("   Processed a CA");
            gotOne = 1;
        }
        /* Update used count. */
        used += consumed;
    }

    /* May have other unparsable data but did we get a certificate? */
    if (gotOne) {
        WOLFSSL_MSG("Processed at least one valid CA. Other stuff OK");
        ret = 1;
    }
    return ret;
}


/* Get verify settings for AddCA from SSL context. */
#define GET_VERIFY_SETTING_CTX(ctx) \
    ((ctx) && (ctx)->verifyNone ? NO_VERIFY : VERIFY)
/* Get verify settings for AddCA from SSL. */
#define GET_VERIFY_SETTING_SSL(ssl) \
    ((ssl)->options.verifyNone ? NO_VERIFY : VERIFY)

#ifndef NO_FILESYSTEM

/* Process data from a file as private keys, CRL or certificates.
 *
 * @param [in, out] ctx        SSL context object.
 * @param [in]      fname      Name of file to read.
 * @param [in]      format     Format of data:
 *                               WOLFSSL_FILETYPE_PEM or WOLFSSL_FILETYPE_ASN1.
 * @param [in]      type       Type of data:
 *                               CERT_TYPE, CA_TYPE, TRUSTED_PEER_TYPE,
 *                               PRIVATEKEY_TYPE or ALT_PRIVATEKEY_TYPE.
 * @param [in, out] ssl        SSL object.
 * @param [in]      userChain  Whether file contains chain of certificates.
 * @param [in, out] crl        CRL object to load data into.
 * @param [in]      verify     How to verify certificates.
 * @return  1 on success.
 * @return  WOLFSSL_BAD_FILE when reading the file fails.
 * @return  WOLFSSL_BAD_CERTTYPE when unable to detect certificate type.
 */
int ProcessFile(WOLFSSL_CTX* ctx, const char* fname, int format, int type,
    WOLFSSL* ssl, int userChain, WOLFSSL_CRL* crl, int verify)
{
    int    ret = 0;
#ifndef WOLFSSL_SMALL_STACK
    byte   stackBuffer[FILE_BUFFER_SIZE];
#endif
    StaticBuffer content;
    long   sz = 0;
    void*  heap = WOLFSSL_HEAP(ctx, ssl);

    (void)crl;
    (void)heap;

#ifdef WOLFSSL_SMALL_STACK
    static_buffer_init(&content);
#else
    static_buffer_init(&content, stackBuffer, FILE_BUFFER_SIZE);
#endif

    /* Read file into static buffer. */
    ret = wolfssl_read_file_static(fname, &content, heap, DYNAMIC_TYPE_FILE,
        &sz);
    if ((ret == 0) && (type == DETECT_CERT_TYPE) &&
            (format != WOLFSSL_FILETYPE_PEM)) {
        WOLFSSL_MSG("Cannot detect certificate type when not PEM");
        ret = WOLFSSL_BAD_CERTTYPE;
    }
    /* Try to detect type by parsing cert header and footer. */
    if ((ret == 0) && (type == DETECT_CERT_TYPE)) {
#if !defined(NO_CODING) && !defined(WOLFSSL_NO_PEM)
        const char* header = NULL;
        const char* footer = NULL;

        /* Look for CA header and footer - same as CERT_TYPE. */
        if (wc_PemGetHeaderFooter(CA_TYPE, &header, &footer) == 0 &&
                (XSTRNSTR((char*)content.buffer, header, (word32)sz) != NULL)) {
            type = CA_TYPE;
        }
#ifdef HAVE_CRL
        /* Look for CRL header and footer. */
        else if (wc_PemGetHeaderFooter(CRL_TYPE, &header, &footer) == 0 &&
                (XSTRNSTR((char*)content.buffer, header, (word32)sz) != NULL)) {
            type = CRL_TYPE;
        }
#endif
        /* Look for cert header and footer - same as CA_TYPE. */
        else if (wc_PemGetHeaderFooter(CERT_TYPE, &header, &footer) == 0 &&
                (XSTRNSTR((char*)content.buffer, header, (word32)sz) !=
                    NULL)) {
            type = CERT_TYPE;
        }
        else
#endif
        {
            /* Not a header that we support. */
            WOLFSSL_MSG("Failed to detect certificate type");
            ret = WOLFSSL_BAD_CERTTYPE;
        }
    }
    if (ret == 0) {
        /* When CA or trusted peer and PEM - process as a chain buffer. */
        if (((type == CA_TYPE) || (type == TRUSTED_PEER_TYPE)) &&
                (format == WOLFSSL_FILETYPE_PEM)) {
            ret = ProcessChainBuffer(ctx, ssl, content.buffer, sz, type,
                verify);
        }
#ifdef HAVE_CRL
        else if (type == CRL_TYPE) {
            /* Load the CRL. */
            ret = BufferLoadCRL(crl, content.buffer, sz, format, verify);
        }
#endif
#ifdef WOLFSSL_DUAL_ALG_CERTS
        else if (type == PRIVATEKEY_TYPE) {
            /* When support for dual algorithm certificates is enabled, the
             * private key file may contain both the primary and the
             * alternative private key. Hence, we have to parse both of them.
             */
            long consumed = 0;

            ret = ProcessBuffer(ctx, content.buffer, sz, format, type, ssl,
                &consumed, userChain, verify);
            if ((ret == 1) && (consumed < sz)) {
                ret = ProcessBuffer(ctx, content.buffer + consumed,
                    sz - consumed, format, ALT_PRIVATEKEY_TYPE, ssl, NULL, 0,
                    verify);
            }
        }
#endif
        else {
            /* Load all other certificate types. */
            ret = ProcessBuffer(ctx, content.buffer, sz, format, type, ssl,
                NULL, userChain, verify);
        }
    }

    /* Dispose of dynamically allocated data. */
    static_buffer_free(&content, heap, DYNAMIC_TYPE_FILE);
    return ret;
}

#ifndef NO_WOLFSSL_DIR
/* Load file when filename is in the path.
 *
 * @param [in, out] ctx           SSL context object.
 * @param [in]      name          Name of file.
 * @param [in]      verify        How to verify a certificate.
 * @param [in]      flags         Flags representing options for loading.
 * @param [in, out] failCount     Number of files that failed to load.
 * @param [in, out] successCount  Number of files successfully loaded.
 * @return  1 on success.
 * @return  Not 1 when loading PEM certificate failed.
 */
static int wolfssl_ctx_load_path_file(WOLFSSL_CTX* ctx, const char* name,
    int verify, int flags, int* failCount, int* successCount)
{
    int ret;

    /* Attempt to load file as a CA. */
    ret = ProcessFile(ctx, name, WOLFSSL_FILETYPE_PEM, CA_TYPE, NULL, 0, NULL,
        verify);
    if (ret != 1) {
        /* When ignoring errors or loading PEM only and no PEM. don't fail. */
        if ((flags & WOLFSSL_LOAD_FLAG_IGNORE_ERR) ||
                ((flags & WOLFSSL_LOAD_FLAG_PEM_CA_ONLY) &&
                 (ret == WC_NO_ERR_TRACE(ASN_NO_PEM_HEADER)))) {
            unsigned long err = 0;
            CLEAR_ASN_NO_PEM_HEADER_ERROR(err);
        #if defined(WOLFSSL_QT)
            ret = 1;
        #endif
        }
        else {
            WOLFSSL_ERROR(ret);
            WOLFSSL_MSG("Load CA file failed, continuing");
            /* Add to fail count. */
            (*failCount)++;
        }
    }
    else {
    #if defined(WOLFSSL_TRUST_PEER_CERT) && defined(OPENSSL_COMPATIBLE_DEFAULTS)
        /* Try loading as a trusted peer certificate. */
        ret = wolfSSL_CTX_trust_peer_cert(ctx, name, WOLFSSL_FILETYPE_PEM);
        if (ret != 1) {
            WOLFSSL_MSG("wolfSSL_CTX_trust_peer_cert error. "
                        "Ignoring this error.");
        }
    #endif
        /* Add to success count. */
        (*successCount)++;
    }

    return ret;
}

/* Load PEM formatted CA files from a path.
 *
 * @param [in, out] ctx           SSL context object.
 * @param [in]      path          Path to directory to read.
 * @param [in]      flags         Flags representing options for loading.
 * @param [in]      verify        How to verify a certificate.
 * @param [in]      successCount  Number of files successfully loaded.
 * @return  1 on success.
 * @return  0 on failure.
 * @return  MEMORY_E when dynamic memory allocation fails.
 */
static int wolfssl_ctx_load_path(WOLFSSL_CTX* ctx, const char* path,
    word32 flags, int verify, int successCount)
{
    int ret = 1;
    char* name = NULL;
    int fileRet;
    int failCount = 0;
#ifdef WOLFSSL_SMALL_STACK
    ReadDirCtx* readCtx;
#else
    ReadDirCtx readCtx[1];
#endif

#ifdef WOLFSSL_SMALL_STACK
    /* Allocate memory for directory reading context. */
    readCtx = (ReadDirCtx*)XMALLOC(sizeof(ReadDirCtx), ctx->heap,
        DYNAMIC_TYPE_DIRCTX);
    if (readCtx == NULL) {
        ret = MEMORY_E;
    }
#endif

    if (ret == 1) {
        /* Get name of first file in path. */
        fileRet = wc_ReadDirFirst(readCtx, path, &name);
        /* While getting filename doesn't fail and name returned, process file.
         */
        while ((fileRet == 0) && (name != NULL)) {
            WOLFSSL_MSG(name);
            /* Load file. */
            ret = wolfssl_ctx_load_path_file(ctx, name, verify, (int)flags,
                &failCount, &successCount);
            /* Get next filename. */
            fileRet = wc_ReadDirNext(readCtx, path, &name);
        }
        /* Cleanup directory reading context. */
        wc_ReadDirClose(readCtx);

        /* When not WOLFSSL_QT, ret is always overwritten. */
        (void)ret;

        /* Return real directory read failure error codes. */
        if (fileRet != WC_READDIR_NOFILE) {
            ret = fileRet;
        #if defined(WOLFSSL_QT) || defined(WOLFSSL_IGNORE_BAD_CERT_PATH)
            /* Ignore bad path error when flag set. */
            if ((ret == WC_NO_ERR_TRACE(BAD_PATH_ERROR)) &&
                    (flags & WOLFSSL_LOAD_FLAG_IGNORE_BAD_PATH_ERR)) {
               /* QSslSocket always loads certs in system folder
                * when it is initialized.
                * Compliant with OpenSSL when flag set.
                */
                ret = 1;
            }
            else {
                /* qssl socket wants to know errors. */
                WOLFSSL_ERROR(ret);
            }
        #endif
        }
        /* Report failure if no files successfully loaded or there were
         * failures. */
        else if ((successCount == 0) || (failCount > 0)) {
            /* Use existing error code if exists. */
        #if defined(WOLFSSL_QT)
            /* Compliant with OpenSSL when flag set. */
            if (!(flags & WOLFSSL_LOAD_FLAG_IGNORE_ZEROFILE))
        #endif
            {
                /* Return 0 when no files loaded. */
                ret = 0;
            }
        }
        else {
            /* We loaded something so it is a success. */
            ret = 1;
        }

    #ifdef WOLFSSL_SMALL_STACK
        /* Dispose of dynamically allocated memory. */
        XFREE(readCtx, ctx->heap, DYNAMIC_TYPE_DIRCTX);
    #endif
    }

    return ret;
}
#endif

/* Load a file and/or files in path
 *
 * No c_rehash.
 *
 * @param [in, out] ctx    SSL context object.
 * @param [in]      file   Name of file to load. May be NULL.
 * @param [in]      path   Path to directory containing PEM CA files.
 *                         May be NULL.
 * @param [in]      flags  Flags representing options for loading.
 * @return  1 on success.
 * @return  0 on failure.
 * @return  NOT_COMPILED_IN when directory reading not supported and path is
 *          not NULL.
 * @return  Other negative on error.
 */
int wolfSSL_CTX_load_verify_locations_ex(WOLFSSL_CTX* ctx, const char* file,
    const char* path, word32 flags)
{
    int ret = 1;
#ifndef NO_WOLFSSL_DIR
    int successCount = 0;
#endif
    int verify = WOLFSSL_VERIFY_DEFAULT;

    WOLFSSL_MSG("wolfSSL_CTX_load_verify_locations_ex");

    /* Validate parameters. */
    if ((ctx == NULL) || ((file == NULL) && (path == NULL))) {
        ret = 0;
    }

    if (ret == 1) {
        /* Get setting on how to verify certificates. */
        verify = GET_VERIFY_SETTING_CTX(ctx);
        /* Overwrite setting when flag set. */
        if (flags & WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY) {
            verify = VERIFY_SKIP_DATE;
        }

        if (file != NULL) {
            /* Load the PEM formatted CA file. */
            ret = ProcessFile(ctx, file, WOLFSSL_FILETYPE_PEM, CA_TYPE, NULL, 0,
                NULL, verify);
    #ifndef NO_WOLFSSL_DIR
            if (ret == 1) {
                /* Include success in overall count. */
                successCount++;
            }
    #endif
    #if defined(WOLFSSL_TRUST_PEER_CERT) && defined(OPENSSL_COMPATIBLE_DEFAULTS)
            /* Load CA as a trusted peer certificate. */
            ret = wolfSSL_CTX_trust_peer_cert(ctx, file, WOLFSSL_FILETYPE_PEM);
            if (ret != 1) {
                WOLFSSL_MSG("wolfSSL_CTX_trust_peer_cert error");
            }
    #endif
        }
    }

    if ((ret == 1) && (path != NULL)) {
#ifndef NO_WOLFSSL_DIR
        /* Load CA files form path. */
        ret = wolfssl_ctx_load_path(ctx, path, flags, verify, successCount);
#else
        /* Loading a path not supported. */
        ret = NOT_COMPILED_IN;
        (void)flags;
#endif
    }

    return ret;
}

/* Load a file and/or files in path
 *
 * No c_rehash.
 *
 * @param [in, out] ctx    SSL context object.
 * @param [in]      file   Name of file to load. May be NULL.
 * @param [in]      path   Path to directory containing PEM CA files.
 *                         May be NULL.
 * @return  1 on success.
 * @return  0 on failure.
 */
WOLFSSL_ABI
int wolfSSL_CTX_load_verify_locations(WOLFSSL_CTX* ctx, const char* file,
                                     const char* path)
{
    /* Load using default flags/options. */
    int ret = wolfSSL_CTX_load_verify_locations_ex(ctx, file, path,
        WOLFSSL_LOAD_VERIFY_DEFAULT_FLAGS);

    /* Return 1 on success or 0 on failure. */
    return WS_RETURN_CODE(ret, 0);
}

/* Load a file and/or files in path, with OpenSSL-compatible semantics.
 *
 * No c_rehash.
 *
 * @param [in, out] ctx    SSL context object.
 * @param [in]      file   Name of file to load. May be NULL.
 * @param [in]      path   Path to directory containing PEM CA files.
 *                         May be NULL.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_CTX_load_verify_locations_compat(WOLFSSL_CTX* ctx, const char* file,
                                     const char* path)
{
    /* We want to keep trying to load more CA certs even if one cert in the
     * directory is bad and can't be used (e.g. if one is expired), and we
     * want to return success if any were successfully loaded (mimicking
     * OpenSSL SSL_CTX_load_verify_locations() semantics), so we use
     * WOLFSSL_LOAD_FLAG_IGNORE_ERR.  OpenSSL (as of v3.3.2) actually
     * returns success even if no certs are loaded (e.g. because the
     * supplied "path" doesn't exist or access is prohibited), and only
     * returns failure if the "file" is non-null and fails to load.
     *
     * Note that if a file is supplied and can't be successfully loaded, the
     * overall call fails and the path is never even evaluated.  This is
     * consistent with OpenSSL behavior.
     */

    int ret = wolfSSL_CTX_load_verify_locations_ex(ctx, file, path,
        WOLFSSL_LOAD_VERIFY_DEFAULT_FLAGS | WOLFSSL_LOAD_FLAG_IGNORE_ERR);

    /* Return 1 on success or 0 on failure. */
    return WS_RETURN_CODE(ret, 0);
}

#ifdef WOLFSSL_SYS_CA_CERTS

#ifdef USE_WINDOWS_API

/* Load CA certificate from Windows store.
 *
 * Assumes loaded is 0.
 *
 * @param [in, out] ctx     SSL context object.
 * @param [out]     loaded  Whether CA certificates were loaded.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int LoadSystemCaCertsWindows(WOLFSSL_CTX* ctx, byte* loaded)
{
    int ret = 1;
    word32 i;
    HANDLE handle = NULL;
    PCCERT_CONTEXT certCtx = NULL;
    LPCSTR storeNames[2] = {"ROOT", "CA"};
    HCRYPTPROV_LEGACY hProv = (HCRYPTPROV_LEGACY)NULL;

    if ((ctx == NULL) || (loaded == NULL)) {
        ret = 0;
    }

    for (i = 0; (ret == 1) && (i < sizeof(storeNames)/sizeof(*storeNames));
         ++i) {
        handle = CertOpenSystemStoreA(hProv, storeNames[i]);
        if (handle != NULL) {
            while ((certCtx = CertEnumCertificatesInStore(handle, certCtx))
                   != NULL) {
                if (certCtx->dwCertEncodingType == X509_ASN_ENCODING) {
                    if (ProcessBuffer(ctx, certCtx->pbCertEncoded,
                          certCtx->cbCertEncoded, WOLFSSL_FILETYPE_ASN1,
                          CA_TYPE, NULL, NULL, 0,
                          GET_VERIFY_SETTING_CTX(ctx)) == 1) {
                        /*
                         * Set "loaded" as long as we've loaded one CA
                         * cert.
                         */
                        *loaded = 1;
                    }
                }
            }
        }
        else {
            WOLFSSL_MSG_EX("Failed to open cert store %s.", storeNames[i]);
        }

        if (handle != NULL && !CertCloseStore(handle, 0)) {
            WOLFSSL_MSG_EX("Failed to close cert store %s.", storeNames[i]);
            ret = 0;
        }
    }

    return ret;
}

#elif defined(__APPLE__)

#if defined(HAVE_SECURITY_SECTRUSTSETTINGS_H) \
  && !defined(WOLFSSL_APPLE_NATIVE_CERT_VALIDATION)
/* Manually obtains certificates from the system trust store and loads them
 * directly into wolfSSL "the old way".
 *
 * As of MacOS 14.0 we are still able to use this method to access system
 * certificates. Accessibility of this API is indicated by the presence of the
 * Security/SecTrustSettings.h header. In the likely event that Apple removes
 * access to this API on Macs, this function should be removed and the
 * DoAppleNativeCertValidation() routine should be used for all devices.
 *
 * Assumes loaded is 0.
 *
 * @param [in, out] ctx     SSL context object.
 * @param [out]     loaded  Whether CA certificates were loaded.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int LoadSystemCaCertsMac(WOLFSSL_CTX* ctx, byte* loaded)
{
    int ret = 1;
    word32 i;
    const unsigned int trustDomains[] = {
        kSecTrustSettingsDomainUser,
        kSecTrustSettingsDomainAdmin,
        kSecTrustSettingsDomainSystem
    };
    CFArrayRef certs;
    OSStatus stat;
    CFIndex numCerts;
    CFDataRef der;
    CFIndex j;

    if ((ctx == NULL) || (loaded == NULL)) {
        ret = 0;
    }

    for (i = 0; (ret == 1) && (i < sizeof(trustDomains)/sizeof(*trustDomains));
         ++i) {
        stat = SecTrustSettingsCopyCertificates(
            (SecTrustSettingsDomain)trustDomains[i], &certs);
        if (stat == errSecSuccess) {
            numCerts = CFArrayGetCount(certs);
            for (j = 0; j < numCerts; ++j) {
                der = SecCertificateCopyData((SecCertificateRef)
                          CFArrayGetValueAtIndex(certs, j));
                if (der != NULL) {
                    if (ProcessBuffer(ctx, CFDataGetBytePtr(der),
                          CFDataGetLength(der), WOLFSSL_FILETYPE_ASN1,
                          CA_TYPE, NULL, NULL, 0,
                          GET_VERIFY_SETTING_CTX(ctx)) == 1) {
                        /*
                         * Set "loaded" as long as we've loaded one CA
                         * cert.
                         */
                        *loaded = 1;
                    }

                    CFRelease(der);
                }
            }

            CFRelease(certs);
        }
        else if (stat == errSecNoTrustSettings) {
            WOLFSSL_MSG_EX("No trust settings for domain %d, moving to next "
                "domain.", trustDomains[i]);
        }
        else {
            WOLFSSL_MSG_EX("SecTrustSettingsCopyCertificates failed with"
                " status %d.", stat);
            ret = 0;
            break;
        }
    }

    return ret;
}
#endif /* defined(HAVE_SECURITY_SECTRUSTSETTINGS_H) */

#else

/* Potential system CA certs directories on Linux/Unix distros. */
static const char* systemCaDirs[] = {
#if defined(__ANDROID__) || defined(ANDROID)
    "/system/etc/security/cacerts"      /* Android */
#else
    "/etc/ssl/certs",                   /* Debian, Ubuntu, Gentoo, others */
    "/etc/pki/ca-trust/source/anchors", /* Fedora, RHEL */
    "/etc/pki/tls/certs"                /* Older RHEL */
#endif
};

/* Get CA directory list.
 *
 * @param [out] num  Number of CA directories.
 * @return  CA directory list.
 * @return  NULL when num is NULL.
 */
const char** wolfSSL_get_system_CA_dirs(word32* num)
{
    const char** ret;

    /* Validate parameters. */
    if (num == NULL) {
        ret = NULL;
    }
    else {
        ret = systemCaDirs;
        *num = sizeof(systemCaDirs)/sizeof(*systemCaDirs);
    }

    return ret;
}

/* Load CA certificate from default system directories.
 *
 * Assumes loaded is 0.
 *
 * @param [in, out] ctx     SSL context object.
 * @param [out]     loaded  Whether CA certificates were loaded.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int LoadSystemCaCertsNix(WOLFSSL_CTX* ctx, byte* loaded) {
    int ret = 1;
    word32 i;

    if ((ctx == NULL) || (loaded == NULL)) {
        ret = 0;
    }

    for (i = 0; (ret == 1) && (i < sizeof(systemCaDirs)/sizeof(*systemCaDirs));
         ++i) {
        WOLFSSL_MSG_EX("Attempting to load system CA certs from %s.",
            systemCaDirs[i]);
        /*
         * We want to keep trying to load more CA certs even if one cert in
         * the directory is bad and can't be used (e.g. if one is expired),
         * so we use WOLFSSL_LOAD_FLAG_IGNORE_ERR.
         */
        if (wolfSSL_CTX_load_verify_locations_ex(ctx, NULL, systemCaDirs[i],
                WOLFSSL_LOAD_FLAG_IGNORE_ERR) != 1) {
            WOLFSSL_MSG_EX("Failed to load CA certs from %s, trying "
                "next possible location.", systemCaDirs[i]);
        }
        else {
            WOLFSSL_MSG_EX("Loaded CA certs from %s.",
                systemCaDirs[i]);
            *loaded = 1;
            /* Stop searching after we've loaded one directory. */
            break;
        }
    }

    return ret;
}

#endif

/* Load CA certificates from system defined locations.
 *
 * @param [in, out] ctx  SSL context object.
 * @return  1 on success.
 * @return  0 on failure.
 * @return  WOLFSSL_BAD_PATH when no error but no certificates loaded.
 */
int wolfSSL_CTX_load_system_CA_certs(WOLFSSL_CTX* ctx)
{
    int ret;
    byte loaded = 0;

    WOLFSSL_ENTER("wolfSSL_CTX_load_system_CA_certs");

#ifdef USE_WINDOWS_API

    ret = LoadSystemCaCertsWindows(ctx, &loaded);

#elif defined(__APPLE__)

#if defined(HAVE_SECURITY_SECTRUSTSETTINGS_H) \
  && !defined(WOLFSSL_APPLE_NATIVE_CERT_VALIDATION)
    /* As of MacOS 14.0 we are still able to access system certificates and
     * load them manually into wolfSSL "the old way". Accessibility of this API
     * is indicated by the presence of the Security/SecTrustSettings.h header */
    ret = LoadSystemCaCertsMac(ctx, &loaded);
#elif defined(WOLFSSL_APPLE_NATIVE_CERT_VALIDATION)
    /* For other Apple devices, Apple has removed the ability to obtain
     * certificates from the trust store, so we can't use wolfSSL's built-in
     * certificate validation mechanisms anymore. We instead must call into the
     * Security Framework APIs to authenticate peer certificates when received.
     * (see src/internal.c:DoAppleNativeCertValidation()).
     * Thus, there is no CA "loading" required, but to keep behavior consistent
     * with the current API (not using system CA certs unless this function has
     * been called), we simply set a flag indicating that the new apple trust
     * verification routine should be used later */
    ctx->doAppleNativeCertValidationFlag = 1;
    ret = 1;
    loaded = 1;

#if FIPS_VERSION_GE(2,0) /* Gate back to cert 3389 FIPS modules */
#warning "Cryptographic operations may occur outside the FIPS module boundary" \
         "Please review FIPS claims for cryptography on this Apple device"
#endif /* FIPS_VERSION_GE(2,0) */

#else
/* HAVE_SECURITY_SECXXX_H macros are set by autotools or CMake when searching
 * system for the required SDK headers. If building with user_settings.h, you
 * will need to manually define WOLFSSL_APPLE_NATIVE_CERT_VALIDATION
 * and ensure the appropriate Security.framework headers and libraries are
 * visible to your compiler */
#error "WOLFSSL_SYS_CA_CERTS on Apple devices requires Security.framework" \
       " header files to be detected, or a manual override with" \
       " WOLFSSL_APPLE_NATIVE_CERT_VALIDATION"
#endif

#else

    ret = LoadSystemCaCertsNix(ctx, &loaded);

#endif

    /* If we didn't fail but didn't load then we error out. */
    if ((ret == 1) && (!loaded)) {
        ret = WOLFSSL_BAD_PATH;
    }

    WOLFSSL_LEAVE("wolfSSL_CTX_load_system_CA_certs", ret);

    return ret;
}

#endif /* WOLFSSL_SYS_CA_CERTS */

#ifdef WOLFSSL_TRUST_PEER_CERT
/* Load a trusted peer certificate into SSL context.
 *
 * @param [in, out] ctx     SSL context object.
 * @param [in]      file    Name of peer certificate file.
 * @param [in]      format  Format of data:
 *                            WOLFSSL_FILETYPE_PEM or WOLFSSL_FILETYPE_ASN1.
 * @return  1 on success.
 * @return  0 when ctx or file is NULL.
 */
int wolfSSL_CTX_trust_peer_cert(WOLFSSL_CTX* ctx, const char* file, int format)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_CTX_trust_peer_cert");

    /* Validate parameters. */
    if ((ctx == NULL) || (file == NULL)) {
        ret = 0;
    }
    else {
        ret = ProcessFile(ctx, file, format, TRUSTED_PEER_TYPE, NULL, 0, NULL,
            GET_VERIFY_SETTING_CTX(ctx));
    }

    return ret;
}

/* Load a trusted peer certificate into SSL.
 *
 * @param [in, out] ssl     SSL object.
 * @param [in]      file    Name of peer certificate file.
 * @param [in]      format  Format of data:
 *                            WOLFSSL_FILETYPE_PEM or WOLFSSL_FILETYPE_ASN1.
 * @return  1 on success.
 * @return  0 when ssl or file is NULL.
 */
int wolfSSL_trust_peer_cert(WOLFSSL* ssl, const char* file, int format)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_trust_peer_cert");

    /* Validate parameters. */
    if ((ssl == NULL) || (file == NULL)) {
        ret = 0;
    }
    else {
        ret = ProcessFile(NULL, file, format, TRUSTED_PEER_TYPE, ssl, 0, NULL,
            GET_VERIFY_SETTING_SSL(ssl));
    }

    return ret;
}
#endif /* WOLFSSL_TRUST_PEER_CERT */


#ifdef WOLFSSL_DER_LOAD

/* Load a CA certificate into SSL context.
 *
 * @param [in, out] ctx     SSL context object.
 * @param [in]      file    Name of peer certificate file.
 * @param [in]      format  Format of data:
 *                            WOLFSSL_FILETYPE_PEM or WOLFSSL_FILETYPE_ASN1.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_CTX_der_load_verify_locations(WOLFSSL_CTX* ctx, const char* file,
    int format)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_CTX_der_load_verify_locations");

    /* Validate parameters. */
    if ((ctx == NULL) || (file == NULL)) {
        ret = 0;
    }
    else {
        ret = ProcessFile(ctx, file, format, CA_TYPE, NULL, 0, NULL,
            GET_VERIFY_SETTING_CTX(ctx));
    }

    /* Return 1 on success or 0 on failure. */
    return WS_RC(ret);
}

#endif /* WOLFSSL_DER_LOAD */


/* Load a user certificate into SSL context.
 *
 * @param [in, out] ctx     SSL context object.
 * @param [in]      file    Name of user certificate file.
 * @param [in]      format  Format of data:
 *                            WOLFSSL_FILETYPE_PEM or WOLFSSL_FILETYPE_ASN1.
 * @return  1 on success.
 * @return  0 on failure.
 */
WOLFSSL_ABI
int wolfSSL_CTX_use_certificate_file(WOLFSSL_CTX* ctx, const char* file,
    int format)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_CTX_use_certificate_file");

    ret = ProcessFile(ctx, file, format, CERT_TYPE, NULL, 0, NULL,
        GET_VERIFY_SETTING_CTX(ctx));

    /* Return 1 on success or 0 on failure. */
    return WS_RC(ret);
}


/* Load a private key into SSL context.
 *
 * @param [in, out] ctx     SSL context object.
 * @param [in]      file    Name of private key file.
 * @param [in]      format  Format of data:
 *                            WOLFSSL_FILETYPE_PEM or WOLFSSL_FILETYPE_ASN1.
 * @return  1 on success.
 * @return  0 on failure.
 */
WOLFSSL_ABI
int wolfSSL_CTX_use_PrivateKey_file(WOLFSSL_CTX* ctx, const char* file,
    int format)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_CTX_use_PrivateKey_file");

    ret = ProcessFile(ctx, file, format, PRIVATEKEY_TYPE, NULL, 0, NULL,
        GET_VERIFY_SETTING_CTX(ctx));

    /* Return 1 on success or 0 on failure. */
    return WS_RC(ret);
}

#ifdef WOLFSSL_DUAL_ALG_CERTS
/* Load an alternative private key into SSL context.
 *
 * @param [in, out] ctx     SSL context object.
 * @param [in]      file    Name of private key file.
 * @param [in]      format  Format of data:
 *                            WOLFSSL_FILETYPE_PEM or WOLFSSL_FILETYPE_ASN1.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_CTX_use_AltPrivateKey_file(WOLFSSL_CTX* ctx, const char* file,
    int format)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_CTX_use_AltPrivateKey_file");

    ret = ProcessFile(ctx, file, format, ALT_PRIVATEKEY_TYPE, NULL, 0, NULL,
        GET_VERIFY_SETTING_CTX(ctx));

    /* Return 1 on success or 0 on failure. */
    return WS_RC(ret);
}
#endif /* WOLFSSL_DUAL_ALG_CERTS */


/* Load a PEM certificate chain into SSL context.
 *
 * @param [in, out] ctx     SSL context object.
 * @param [in]      file    Name of PEM certificate chain file.
 * @return  1 on success.
 * @return  0 on failure.
 */
WOLFSSL_ABI
int wolfSSL_CTX_use_certificate_chain_file(WOLFSSL_CTX* ctx, const char* file)
{
    int ret;

    /* process up to MAX_CHAIN_DEPTH plus subject cert */
    WOLFSSL_ENTER("wolfSSL_CTX_use_certificate_chain_file");

    ret = ProcessFile(ctx, file, WOLFSSL_FILETYPE_PEM, CERT_TYPE, NULL, 1, NULL,
        GET_VERIFY_SETTING_CTX(ctx));

    /* Return 1 on success or 0 on failure. */
    return WS_RC(ret);
}

/* Load certificate chain into SSL context.
 *
 * Processes up to MAX_CHAIN_DEPTH plus subject cert.
 *
 * @param [in, out] ctx     SSL context object.
 * @param [in]      file    Name of private key file.
 * @param [in]      format  Format of data:
 *                            WOLFSSL_FILETYPE_PEM or WOLFSSL_FILETYPE_ASN1.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_CTX_use_certificate_chain_file_format(WOLFSSL_CTX* ctx,
     const char* file, int format)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_CTX_use_certificate_chain_file_format");

    ret = ProcessFile(ctx, file, format, CERT_TYPE, NULL, 1, NULL,
        GET_VERIFY_SETTING_CTX(ctx));

    /* Return 1 on success or 0 on failure. */
    return WS_RC(ret);
}

#endif /* NO_FILESYSTEM */

#ifdef OPENSSL_EXTRA

/* Load a private key into SSL.
 *
 * @param [in, out] ssl   SSL object.
 * @param [in]      pkey  EVP private key.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_use_PrivateKey(WOLFSSL* ssl, WOLFSSL_EVP_PKEY* pkey)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_use_PrivateKey");

    /* Validate parameters. */
    if ((ssl == NULL) || (pkey == NULL)) {
        ret = 0;
    }
    else {
        /* Get DER encoded key data from EVP private key. */
        ret = wolfSSL_use_PrivateKey_buffer(ssl, (unsigned char*)pkey->pkey.ptr,
            pkey->pkey_sz, WOLFSSL_FILETYPE_ASN1);
    }

    return ret;
}

/* Load a DER encoded private key in a buffer into SSL.
 *
 * @param [in]      pri    Indicates type of private key. Ignored.
 * @param [in, out] ssl    SSL object.
 * @param [in]      der    Buffer holding DER encoded private key.
 * @param [in]      derSz  Size of data in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_use_PrivateKey_ASN1(int pri, WOLFSSL* ssl, const unsigned char* der,
    long derSz)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_use_PrivateKey_ASN1");

    (void)pri;

    /* Validate parameters. */
    if ((ssl == NULL) || (der == NULL)) {
        ret = 0;
    }
    else {
        ret = wolfSSL_use_PrivateKey_buffer(ssl, der, derSz,
            WOLFSSL_FILETYPE_ASN1);
    }

    return ret;
}

/* Load a DER encoded private key in a buffer into SSL context.
 *
 * @param [in]      pri    Indicates type of private key. Ignored.
 * @param [in, out] ctx    SSL context object.
 * @param [in]      der    Buffer holding DER encoded private key.
 * @param [in]      derSz  Size of data in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_CTX_use_PrivateKey_ASN1(int pri, WOLFSSL_CTX* ctx,
    unsigned char* der, long derSz)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_CTX_use_PrivateKey_ASN1");

    (void)pri;

    /* Validate parameters. */
    if ((ctx == NULL) || (der == NULL)) {
        ret = 0;
    }
    else {
        ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx, der, derSz,
            WOLFSSL_FILETYPE_ASN1);
    }

    return ret;
}


#ifndef NO_RSA
/* Load a DER encoded RSA private key in a buffer into SSL.
 *
 * @param [in, out] ssl    SSL object.
 * @param [in]      der    Buffer holding DER encoded RSA private key.
 * @param [in]      derSz  Size of data in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_use_RSAPrivateKey_ASN1(WOLFSSL* ssl, unsigned char* der, long derSz)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_use_RSAPrivateKey_ASN1");

    /* Validate parameters. */
    if ((ssl == NULL) || (der == NULL)) {
        ret = 0;
    }
    else {
        ret = wolfSSL_use_PrivateKey_buffer(ssl, der, derSz,
            WOLFSSL_FILETYPE_ASN1);
    }

    return ret;
}
#endif

/* Load a certificate into SSL.
 *
 * @param [in, out] ssl   SSL object.
 * @param [in]      x509  X509 certificate object.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_use_certificate(WOLFSSL* ssl, WOLFSSL_X509* x509)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_use_certificate");

    /* Validate parameters. */
    if ((ssl == NULL) || (x509 == NULL) || (x509->derCert == NULL)) {
        ret = 0;
    }
    else {
        long idx = 0;

        /* Get DER encoded certificate data from X509 object. */
        ret = ProcessBuffer(NULL, x509->derCert->buffer, x509->derCert->length,
            WOLFSSL_FILETYPE_ASN1, CERT_TYPE, ssl, &idx, 0,
            GET_VERIFY_SETTING_SSL(ssl));
    }

    /* Return 1 on success or 0 on failure. */
    return WS_RC(ret);
}

#endif /* OPENSSL_EXTRA */

/* Load a DER encoded certificate in a buffer into SSL.
 *
 * @param [in, out] ssl    SSL object.
 * @param [in]      der    Buffer holding DER encoded certificate.
 * @param [in]      derSz  Size of data in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_use_certificate_ASN1(WOLFSSL* ssl, const unsigned char* der,
    int derSz)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_use_certificate_ASN1");

    /* Validate parameters. */
    if ((ssl == NULL) || (der == NULL)) {
        ret = 0;
    }
    else {
        long idx = 0;

        ret = ProcessBuffer(NULL, der, derSz, WOLFSSL_FILETYPE_ASN1, CERT_TYPE,
            ssl, &idx, 0, GET_VERIFY_SETTING_SSL(ssl));
    }

    /* Return 1 on success or 0 on failure. */
    return WS_RC(ret);
}

#ifndef NO_FILESYSTEM

/* Load a certificate from a file into SSL.
 *
 * @param [in, out] ssl     SSL object.
 * @param [in]      file    Name of file.
 * @param [in]      format  Format of data:
 *                            WOLFSSL_FILETYPE_PEM or WOLFSSL_FILETYPE_ASN1.
 * @return  1 on success.
 * @return  0 on failure.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 */
WOLFSSL_ABI
int wolfSSL_use_certificate_file(WOLFSSL* ssl, const char* file, int format)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_use_certificate_file");

    /* Validate parameters. */
    if (ssl == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = ProcessFile(ssl->ctx, file, format, CERT_TYPE, ssl, 0, NULL,
            GET_VERIFY_SETTING_SSL(ssl));
        /* Return 1 on success or 0 on failure. */
        ret = WS_RC(ret);
    }

    return ret;
}


/* Load a private key from a file into SSL.
 *
 * @param [in, out] ssl     SSL object.
 * @param [in]      file    Name of file.
 * @param [in]      format  Format of data:
 *                            WOLFSSL_FILETYPE_PEM or WOLFSSL_FILETYPE_ASN1.
 * @return  1 on success.
 * @return  0 on failure.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 */
WOLFSSL_ABI
int wolfSSL_use_PrivateKey_file(WOLFSSL* ssl, const char* file, int format)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_use_PrivateKey_file");

    /* Validate parameters. */
    if (ssl == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = ProcessFile(ssl->ctx, file, format, PRIVATEKEY_TYPE, ssl, 0, NULL,
            GET_VERIFY_SETTING_SSL(ssl));
        /* Return 1 on success or 0 on failure. */
        ret = WS_RC(ret);
    }

    return ret;
}


/* Load a PEM encoded certificate chain from a file into SSL.
 *
 * Process up to MAX_CHAIN_DEPTH plus subject cert.
 *
 * @param [in, out] ssl     SSL object.
 * @param [in]      file    Name of file.
 * @return  1 on success.
 * @return  0 on failure.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 */
WOLFSSL_ABI
int wolfSSL_use_certificate_chain_file(WOLFSSL* ssl, const char* file)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_use_certificate_chain_file");

    /* Validate parameters. */
    if (ssl == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = ProcessFile(ssl->ctx, file, WOLFSSL_FILETYPE_PEM, CERT_TYPE, ssl,
            1, NULL, GET_VERIFY_SETTING_SSL(ssl));
        /* Return 1 on success or 0 on failure. */
        ret = WS_RC(ret);
    }

   return ret;
}

/* Load a certificate chain from a file into SSL.
 *
 * @param [in, out] ssl     SSL object.
 * @param [in]      file    Name of file.
 * @param [in]      format  Format of data:
 *                            WOLFSSL_FILETYPE_PEM or WOLFSSL_FILETYPE_ASN1.
 * @return  1 on success.
 * @return  0 on failure.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 */
int wolfSSL_use_certificate_chain_file_format(WOLFSSL* ssl, const char* file,
    int format)
{
    int ret;

    /* process up to MAX_CHAIN_DEPTH plus subject cert */
    WOLFSSL_ENTER("wolfSSL_use_certificate_chain_file_format");

    /* Validate parameters. */
    if (ssl == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = ProcessFile(ssl->ctx, file, format, CERT_TYPE, ssl, 1, NULL,
            GET_VERIFY_SETTING_SSL(ssl));
        /* Return 1 on success or 0 on failure. */
        ret = WS_RC(ret);
    }

    return ret;
}

#endif /* !NO_FILESYSTEM */

#ifdef OPENSSL_EXTRA

#ifndef NO_FILESYSTEM
/* Load an RSA private key from a file into SSL context.
 *
 * @param [in, out] ctx     SSL context object.
 * @param [in]      file    Name of file.
 * @param [in]      format  Format of data:
 *                            WOLFSSL_FILETYPE_PEM or WOLFSSL_FILETYPE_ASN1.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_CTX_use_RSAPrivateKey_file(WOLFSSL_CTX* ctx,const char* file,
    int format)
{
    WOLFSSL_ENTER("wolfSSL_CTX_use_RSAPrivateKey_file");

    return wolfSSL_CTX_use_PrivateKey_file(ctx, file, format);
}

/* Load an RSA private key from a file into SSL.
 *
 * @param [in, out] ssl     SSL object.
 * @param [in]      file    Name of file.
 * @param [in]      format  Format of data:
 *                            WOLFSSL_FILETYPE_PEM or WOLFSSL_FILETYPE_ASN1.
 * @return  1 on success.
 * @return  0 on failure.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 */
int wolfSSL_use_RSAPrivateKey_file(WOLFSSL* ssl, const char* file, int format)
{
    WOLFSSL_ENTER("wolfSSL_use_RSAPrivateKey_file");

    return wolfSSL_use_PrivateKey_file(ssl, file, format);
}
#endif /* NO_FILESYSTEM */

#endif /* OPENSSL_EXTRA */

/* Load a buffer of certificate/s into SSL context.
 *
 * @param [in, out] ctx        SSL context object.
 * @param [in]      in         Buffer holding certificate or private key.
 * @param [in]      sz         Length of data in buffer in bytes.
 * @param [in]      format     Format of data:
 *                               WOLFSSL_FILETYPE_PEM or WOLFSSL_FILETYPE_ASN1.
 * @param [in]      userChain  Whether file contains chain of certificates.
 * @param [in]      flags      Flags representing options for loading.
 * @return  1 on success.
 * @return  0 on failure.
 * @return  Negative on error.
 */
int wolfSSL_CTX_load_verify_buffer_ex(WOLFSSL_CTX* ctx, const unsigned char* in,
    long sz, int format, int userChain, word32 flags)
{
    int ret;
    int verify;

    WOLFSSL_ENTER("wolfSSL_CTX_load_verify_buffer_ex");

    /* Get setting on how to verify certificates. */
    verify = GET_VERIFY_SETTING_CTX(ctx);
    /* Overwrite setting when flag set. */
    if (flags & WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY) {
        verify = VERIFY_SKIP_DATE;
    }

    /* When PEM, treat as certificate chain of CA certificates. */
    if (format == WOLFSSL_FILETYPE_PEM) {
        ret = ProcessChainBuffer(ctx, NULL, in, sz, CA_TYPE, verify);
    }
    /* When DER, load the CA certificate. */
    else {
        ret = ProcessBuffer(ctx, in, sz, format, CA_TYPE, NULL, NULL,
            userChain, verify);
    }
#if defined(WOLFSSL_TRUST_PEER_CERT) && defined(OPENSSL_COMPATIBLE_DEFAULTS)
    if (ret == 1) {
        /* Load certificate/s as trusted peer certificate. */
        ret = wolfSSL_CTX_trust_peer_buffer(ctx, in, sz, format);
    }
#endif

    WOLFSSL_LEAVE("wolfSSL_CTX_load_verify_buffer_ex", ret);
    return ret;
}

/* Load a buffer of certificate/s into SSL context.
 *
 * @param [in, out] ctx     SSL context object.
 * @param [in]      in      Buffer holding certificate or private key.
 * @param [in]      sz      Length of data in buffer in bytes.
 * @param [in]      format  Format of data:
 *                            WOLFSSL_FILETYPE_PEM or WOLFSSL_FILETYPE_ASN1.
 * @return  1 on success.
 * @return  0 on failure.
 * @return  Negative on error.
 */
int wolfSSL_CTX_load_verify_buffer(WOLFSSL_CTX* ctx, const unsigned char* in,
    long sz, int format)
{
    return wolfSSL_CTX_load_verify_buffer_ex(ctx, in, sz, format, 0,
        WOLFSSL_LOAD_VERIFY_DEFAULT_FLAGS);
}

/* Load a buffer of certificate chain into SSL context.
 *
 * @param [in, out] ctx     SSL context object.
 * @param [in]      in      Buffer holding certificate chain.
 * @param [in]      sz      Length of data in buffer in bytes.
 * @param [in]      format  Format of data:
 *                            WOLFSSL_FILETYPE_PEM or WOLFSSL_FILETYPE_ASN1.
 * @return  1 on success.
 * @return  0 on failure.
 * @return  Negative on error.
 */
int wolfSSL_CTX_load_verify_chain_buffer_format(WOLFSSL_CTX* ctx,
    const unsigned char* in, long sz, int format)
{
    return wolfSSL_CTX_load_verify_buffer_ex(ctx, in, sz, format, 1,
        WOLFSSL_LOAD_VERIFY_DEFAULT_FLAGS);
}


#ifdef WOLFSSL_TRUST_PEER_CERT
/* Load a buffer of certificate/s into SSL context.
 *
 * @param [in, out] ctx     SSL context object.
 * @param [in]      in      Buffer holding certificate/s.
 * @param [in]      sz      Length of data in buffer in bytes.
 * @param [in]      format  Format of data:
 *                            WOLFSSL_FILETYPE_PEM or WOLFSSL_FILETYPE_ASN1.
 * @return  1 on success.
 * @return  0 on failure.
 * @return  BAD_FUNC_ARG when ctx or in is NULL, or sz is less than zero.
 */
int wolfSSL_CTX_trust_peer_buffer(WOLFSSL_CTX* ctx, const unsigned char* in,
    long sz, int format)
{
    int ret;
    int verify;

    WOLFSSL_ENTER("wolfSSL_CTX_trust_peer_buffer");

    /* Validate parameters. */
    if ((ctx == NULL) || (in == NULL) || (sz < 0)) {
        ret = BAD_FUNC_ARG;
    }
    else {
    #if WOLFSSL_LOAD_VERIFY_DEFAULT_FLAGS & WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY
        verify = VERIFY_SKIP_DATE;
    #else
        verify = GET_VERIFY_SETTING_CTX(ctx);
    #endif

        /* When PEM, treat as certificate chain of trusted peer certificates. */
        if (format == WOLFSSL_FILETYPE_PEM) {
            ret = ProcessChainBuffer(ctx, NULL, in, sz, TRUSTED_PEER_TYPE,
                verify);
        }
        /* When DER, load the trusted peer certificate. */
        else {
            ret = ProcessBuffer(ctx, in, sz, format, TRUSTED_PEER_TYPE, NULL,
                NULL, 0, verify);
        }
    }

    return ret;
}
#endif /* WOLFSSL_TRUST_PEER_CERT */

/* Load a certificate in a buffer into SSL context.
 *
 * @param [in, out] ctx     SSL context object.
 * @param [in]      in      Buffer holding certificate.
 * @param [in]      sz      Size of data in bytes.
 * @param [in]      format  Format of data:
 *                            WOLFSSL_FILETYPE_PEM or WOLFSSL_FILETYPE_ASN1.
 * @return  1 on success.
 * @return  0 on failure.
 * @return  Negative on error.
 */
int wolfSSL_CTX_use_certificate_buffer(WOLFSSL_CTX* ctx,
    const unsigned char* in, long sz, int format)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_CTX_use_certificate_buffer");
    ret = ProcessBuffer(ctx, in, sz, format, CERT_TYPE, NULL, NULL, 0,
        GET_VERIFY_SETTING_CTX(ctx));
    WOLFSSL_LEAVE("wolfSSL_CTX_use_certificate_buffer", ret);

    return ret;
}

/* Load a private key in a buffer into SSL context.
 *
 * @param [in, out] ctx     SSL context object.
 * @param [in]      in      Buffer holding private key.
 * @param [in]      sz      Size of data in bytes.
 * @param [in]      format  Format of data:
 *                            WOLFSSL_FILETYPE_PEM or WOLFSSL_FILETYPE_ASN1.
 * @return  1 on success.
 * @return  0 on failure.
 * @return  Negative on error.
 */
int wolfSSL_CTX_use_PrivateKey_buffer(WOLFSSL_CTX* ctx, const unsigned char* in,
    long sz, int format)
{
    int ret;
    long consumed = 0;

    WOLFSSL_ENTER("wolfSSL_CTX_use_PrivateKey_buffer");

    ret = ProcessBuffer(ctx, in, sz, format, PRIVATEKEY_TYPE, NULL, &consumed,
        0, GET_VERIFY_SETTING_CTX(ctx));
#ifdef WOLFSSL_DUAL_ALG_CERTS
    if ((ret == 1) && (consumed < sz)) {
        /* When support for dual algorithm certificates is enabled, the
         * buffer may contain both the primary and the alternative
         * private key. Hence, we have to parse both of them.
         */
        ret = ProcessBuffer(ctx, in + consumed, sz - consumed, format,
            ALT_PRIVATEKEY_TYPE, NULL, NULL, 0, GET_VERIFY_SETTING_CTX(ctx));
    }
#endif

    (void)consumed;

    WOLFSSL_LEAVE("wolfSSL_CTX_use_PrivateKey_buffer", ret);
    return ret;
}

#ifdef WOLFSSL_DUAL_ALG_CERTS
int wolfSSL_CTX_use_AltPrivateKey_buffer(WOLFSSL_CTX* ctx,
    const unsigned char* in, long sz, int format)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_CTX_use_AltPrivateKey_buffer");
    ret = ProcessBuffer(ctx, in, sz, format, ALT_PRIVATEKEY_TYPE, NULL,
        NULL, 0, GET_VERIFY_SETTING_CTX(ctx));
    WOLFSSL_LEAVE("wolfSSL_CTX_use_AltPrivateKey_buffer", ret);

    return ret;
}
#endif /* WOLFSSL_DUAL_ALG_CERTS */

#ifdef WOLF_PRIVATE_KEY_ID
/* Load the id of a private key into SSL context.
 *
 * @param [in, out] ctx    SSL context object.
 * @param [in]      id     Buffer holding id.
 * @param [in]      sz     Size of data in bytes.
 * @param [in]      devId  Device identifier.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_CTX_use_PrivateKey_Id(WOLFSSL_CTX* ctx, const unsigned char* id,
    long sz, int devId)
{
    int ret = 1;

    /* Dispose of old private key and allocate and copy in id. */
    FreeDer(&ctx->privateKey);
    if (AllocCopyDer(&ctx->privateKey, id, (word32)sz, PRIVATEKEY_TYPE,
            ctx->heap) != 0) {
        ret = 0;
    }
    if (ret == 1) {
        /* Private key is an id. */
        ctx->privateKeyId = 1;
        ctx->privateKeyLabel = 0;
        /* Set private key device id to be one passed in or for SSL context. */
        if (devId != INVALID_DEVID) {
            ctx->privateKeyDevId = devId;
        }
        else {
            ctx->privateKeyDevId = ctx->devId;
        }

    #ifdef WOLFSSL_DUAL_ALG_CERTS
        /* Set the ID for the alternative key, too. User can still override that
         * afterwards. */
        ret = wolfSSL_CTX_use_AltPrivateKey_Id(ctx, id, sz, devId);
    #endif
    }

    return ret;
}

/* Load the id of a private key into SSL context and set key size.
 *
 * @param [in, out] ctx    SSL context object.
 * @param [in]      id     Buffer holding id.
 * @param [in]      sz     Size of data in bytes.
 * @param [in]      devId  Device identifier.
 * @param [in]      keySz  Size of key.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_CTX_use_PrivateKey_id(WOLFSSL_CTX* ctx, const unsigned char* id,
    long sz, int devId, long keySz)
{
    int ret = wolfSSL_CTX_use_PrivateKey_Id(ctx, id, sz, devId);
    if (ret == 1) {
        /* Set the key size which normally is calculated during decoding. */
        ctx->privateKeySz = (int)keySz;
    }

    return ret;
}

/* Load the label name of a private key into SSL context.
 *
 * @param [in, out] ctx    SSL context object.
 * @param [in]      label  Buffer holding label.
 * @param [in]      devId  Device identifier.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_CTX_use_PrivateKey_Label(WOLFSSL_CTX* ctx, const char* label,
    int devId)
{
    int ret = 1;
    word32 sz = (word32)XSTRLEN(label) + 1;

    /* Dispose of old private key and allocate and copy in label. */
    FreeDer(&ctx->privateKey);
    if (AllocCopyDer(&ctx->privateKey, (const byte*)label, (word32)sz,
            PRIVATEKEY_TYPE, ctx->heap) != 0) {
        ret = 0;
    }
    if (ret == 1) {
        /* Private key is a label. */
        ctx->privateKeyId = 0;
        ctx->privateKeyLabel = 1;
        /* Set private key device id to be one passed in or for SSL context. */
        if (devId != INVALID_DEVID) {
            ctx->privateKeyDevId = devId;
        }
        else {
            ctx->privateKeyDevId = ctx->devId;
        }

    #ifdef WOLFSSL_DUAL_ALG_CERTS
        /* Set the ID for the alternative key, too. User can still override that
         * afterwards. */
        ret = wolfSSL_CTX_use_AltPrivateKey_Label(ctx, label, devId);
    #endif
    }

    return ret;
}

#ifdef WOLFSSL_DUAL_ALG_CERTS
int wolfSSL_CTX_use_AltPrivateKey_Id(WOLFSSL_CTX* ctx, const unsigned char* id,
    long sz, int devId)
{
    int ret = 1;

    if ((ctx == NULL) || (id == NULL)) {
        ret = 0;
    }

    if (ret == 1) {
        FreeDer(&ctx->altPrivateKey);
        if (AllocDer(&ctx->altPrivateKey, (word32)sz, ALT_PRIVATEKEY_TYPE,
                ctx->heap) != 0) {
            ret = 0;
        }
    }
    if (ret == 1) {
        XMEMCPY(ctx->altPrivateKey->buffer, id, sz);
        ctx->altPrivateKeyId = 1;
        if (devId != INVALID_DEVID) {
            ctx->altPrivateKeyDevId = devId;
        }
        else {
            ctx->altPrivateKeyDevId = ctx->devId;
        }
    }

    return ret;
}

int wolfSSL_CTX_use_AltPrivateKey_id(WOLFSSL_CTX* ctx, const unsigned char* id,
    long sz, int devId, long keySz)
{
    int ret = wolfSSL_CTX_use_AltPrivateKey_Id(ctx, id, sz, devId);
    if (ret == 1) {
        ctx->altPrivateKeySz = (word32)keySz;
    }

    return ret;
}

int wolfSSL_CTX_use_AltPrivateKey_Label(WOLFSSL_CTX* ctx, const char* label,
    int devId)
{
    int ret = 1;
    word32 sz;

    if ((ctx == NULL) || (label == NULL)) {
        ret = 0;
    }

    if (ret == 1) {
        sz = (word32)XSTRLEN(label) + 1;
        FreeDer(&ctx->altPrivateKey);
        if (AllocDer(&ctx->altPrivateKey, (word32)sz, ALT_PRIVATEKEY_TYPE,
                ctx->heap) != 0) {
            ret = 0;
        }
    }
    if (ret == 1) {
        XMEMCPY(ctx->altPrivateKey->buffer, label, sz);
        ctx->altPrivateKeyLabel = 1;
        if (devId != INVALID_DEVID) {
            ctx->altPrivateKeyDevId = devId;
        }
        else {
            ctx->altPrivateKeyDevId = ctx->devId;
        }
    }

    return ret;
}
#endif /* WOLFSSL_DUAL_ALG_CERTS */
#endif /* WOLF_PRIVATE_KEY_ID */

#if defined(WOLF_CRYPTO_CB) && !defined(NO_CERTS)

static int wolfSSL_CTX_use_certificate_ex(WOLFSSL_CTX* ctx,
    const char *label, const unsigned char *id, int idLen, int devId)
{
    int ret;
    byte *certData = NULL;
    word32 certDataLen = 0;
    word32 labelLen = 0;
    int certFormat = 0;

    WOLFSSL_ENTER("wolfSSL_CTX_use_certificate_ex");

    if (label != NULL) {
        labelLen = (word32)XSTRLEN(label);
    }

    ret = wc_CryptoCb_GetCert(devId, label, labelLen, id, idLen,
        &certData, &certDataLen, &certFormat, ctx->heap);
    if (ret != 0) {
        ret = WOLFSSL_FAILURE;
        goto exit;
    }

    ret = ProcessBuffer(ctx, certData, certDataLen, certFormat,
        CERT_TYPE, NULL, NULL, 0, GET_VERIFY_SETTING_CTX(ctx));

exit:
    XFREE(certData, ctx->heap, DYNAMIC_TYPE_CERT);
    return ret;
}

/* Load the label name of a certificate into the SSL context.
 *
 * @param [in, out] ctx    SSL context object.
 * @param [in]      label  Buffer holding label.
 * @param [in]      devId  Device identifier.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_CTX_use_certificate_label(WOLFSSL_CTX* ctx,
    const char *label, int devId)
{
    if ((ctx == NULL) || (label == NULL)) {
        return WOLFSSL_FAILURE;
    }

    return wolfSSL_CTX_use_certificate_ex(ctx, label, NULL, 0, devId);
}

/* Load the id of a certificate into SSL context.
 *
 * @param [in, out] ctx    SSL context object.
 * @param [in]      id     Buffer holding id.
 * @param [in]      idLen  Size of data in bytes.
 * @param [in]      devId  Device identifier.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_CTX_use_certificate_id(WOLFSSL_CTX* ctx,
    const unsigned char *id, int idLen, int devId)
{
    if ((ctx == NULL) || (id == NULL) || (idLen <= 0)) {
        return WOLFSSL_FAILURE;
    }

    return wolfSSL_CTX_use_certificate_ex(ctx, NULL, id, idLen, devId);
}

#endif /* if defined(WOLF_CRYPTO_CB) && !defined(NO_CERTS) */

/* Load a certificate chain in a buffer into SSL context.
 *
 * @param [in, out] ctx     SSL context object.
 * @param [in]      in      Buffer holding DER encoded certificate chain.
 * @param [in]      sz      Size of data in bytes.
 * @param [in]      format  Format of data:
 *                            WOLFSSL_FILETYPE_PEM or WOLFSSL_FILETYPE_ASN1.
 * @return  1 on success.
 * @return  0 on failure.
 * @return  Negative on error.
 */
int wolfSSL_CTX_use_certificate_chain_buffer_format(WOLFSSL_CTX* ctx,
    const unsigned char* in, long sz, int format)
{
    WOLFSSL_ENTER("wolfSSL_CTX_use_certificate_chain_buffer_format");
    return ProcessBuffer(ctx, in, sz, format, CERT_TYPE, NULL, NULL, 1,
        GET_VERIFY_SETTING_CTX(ctx));
}

/* Load a PEM encoded certificate chain in a buffer into SSL context.
 *
 * @param [in, out] ctx     SSL context object.
 * @param [in]      in      Buffer holding DER encoded certificate chain.
 * @param [in]      sz      Size of data in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 * @return  Negative on error.
 */
int wolfSSL_CTX_use_certificate_chain_buffer(WOLFSSL_CTX* ctx,
    const unsigned char* in, long sz)
{
    return wolfSSL_CTX_use_certificate_chain_buffer_format(ctx, in, sz,
        WOLFSSL_FILETYPE_PEM);
}

/* Load a user certificate in a buffer into SSL.
 *
 * @param [in, out] ssl     SSL object.
 * @param [in]      in      Buffer holding user certificate.
 * @param [in]      sz      Size of data in bytes.
 * @param [in]      format  Format of data:
 *                            WOLFSSL_FILETYPE_PEM or WOLFSSL_FILETYPE_ASN1.
 * @return  1 on success.
 * @return  0 on failure.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 */
int wolfSSL_use_certificate_buffer(WOLFSSL* ssl, const unsigned char* in,
    long sz, int format)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_use_certificate_buffer");

    /* Validate parameters. */
    if (ssl == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = ProcessBuffer(ssl->ctx, in, sz, format, CERT_TYPE, ssl, NULL, 0,
            GET_VERIFY_SETTING_SSL(ssl));
    }

    return ret;
}

/* Load a private key in a buffer into SSL.
 *
 * @param [in, out] ssl     SSL object.
 * @param [in]      in      Buffer holding private key.
 * @param [in]      sz      Size of data in bytes.
 * @param [in]      format  Format of data:
 *                            WOLFSSL_FILETYPE_PEM or WOLFSSL_FILETYPE_ASN1.
 * @return  1 on success.
 * @return  0 on failure.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 */
int wolfSSL_use_PrivateKey_buffer(WOLFSSL* ssl, const unsigned char* in,
    long sz, int format)
{
    int ret;
    long consumed = 0;

    WOLFSSL_ENTER("wolfSSL_use_PrivateKey_buffer");

    /* Validate parameters. */
    if (ssl == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = ProcessBuffer(ssl->ctx, in, sz, format, PRIVATEKEY_TYPE, ssl,
            &consumed, 0, GET_VERIFY_SETTING_SSL(ssl));
    #ifdef WOLFSSL_DUAL_ALG_CERTS
        if ((ret == 1) && (consumed < sz)) {
            /* When support for dual algorithm certificates is enabled, the
             * buffer may contain both the primary and the alternative
             * private key. Hence, we have to parse both of them.
             */
            ret = ProcessBuffer(ssl->ctx, in + consumed, sz - consumed, format,
                ALT_PRIVATEKEY_TYPE, ssl, NULL, 0, GET_VERIFY_SETTING_SSL(ssl));
        }
    #endif
    }

    return ret;
}

#ifdef WOLFSSL_DUAL_ALG_CERTS
int wolfSSL_use_AltPrivateKey_buffer(WOLFSSL* ssl, const unsigned char* in,
    long sz, int format)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_use_AltPrivateKey_buffer");
    ret = ProcessBuffer(ssl->ctx, in, sz, format, ALT_PRIVATEKEY_TYPE, ssl,
        NULL, 0, GET_VERIFY_SETTING_SSL(ssl));
    WOLFSSL_LEAVE("wolfSSL_use_AltPrivateKey_buffer", ret);

    return ret;
}
#endif /* WOLFSSL_DUAL_ALG_CERTS */

#ifdef WOLF_PRIVATE_KEY_ID
/* Load the id of a private key into SSL.
 *
 * @param [in, out] ssl    SSL object.
 * @param [in]      id     Buffer holding id.
 * @param [in]      sz     Size of data in bytes.
 * @param [in]      devId  Device identifier.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_use_PrivateKey_Id(WOLFSSL* ssl, const unsigned char* id,
                              long sz, int devId)
{
    int ret = 1;

    /* Dispose of old private key if owned and allocate and copy in id. */
    if (ssl->buffers.weOwnKey) {
        FreeDer(&ssl->buffers.key);
    #ifdef WOLFSSL_BLIND_PRIVATE_KEY
        FreeDer(&ssl->buffers.keyMask);
    #endif
    }
    if (AllocCopyDer(&ssl->buffers.key, id, (word32)sz, PRIVATEKEY_TYPE,
            ssl->heap) != 0) {
        ret = 0;
    }
    if (ret == 1) {
        /* Buffer now ours. */
        ssl->buffers.weOwnKey = 1;
        /* Private key is an id. */
        ssl->buffers.keyId = 1;
        ssl->buffers.keyLabel = 0;
        /* Set private key device id to be one passed in or for SSL. */
        if (devId != INVALID_DEVID) {
            ssl->buffers.keyDevId = devId;
        }
        else {
            ssl->buffers.keyDevId = ssl->devId;
        }

    #ifdef WOLFSSL_DUAL_ALG_CERTS
        /* Set the ID for the alternative key, too. User can still override that
         * afterwards. */
        ret = wolfSSL_use_AltPrivateKey_Id(ssl, id, sz, devId);
    #endif
    }

    return ret;
}

/* Load the id of a private key into SSL and set key size.
 *
 * @param [in, out] ssl    SSL object.
 * @param [in]      id     Buffer holding id.
 * @param [in]      sz     Size of data in bytes.
 * @param [in]      devId  Device identifier.
 * @param [in]      keySz  Size of key.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_use_PrivateKey_id(WOLFSSL* ssl, const unsigned char* id,
    long sz, int devId, long keySz)
{
    int ret = wolfSSL_use_PrivateKey_Id(ssl, id, sz, devId);
    if (ret == 1) {
        /* Set the key size which normally is calculated during decoding. */
        ssl->buffers.keySz = (int)keySz;
    }

    return ret;
}

/* Load the label name of a private key into SSL.
 *
 * @param [in, out] ssl    SSL object.
 * @param [in]      label  Buffer holding label.
 * @param [in]      devId  Device identifier.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_use_PrivateKey_Label(WOLFSSL* ssl, const char* label, int devId)
{
    int ret = 1;
    word32 sz = (word32)XSTRLEN(label) + 1;

    /* Dispose of old private key if owned and allocate and copy in label. */
    if (ssl->buffers.weOwnKey) {
        FreeDer(&ssl->buffers.key);
    #ifdef WOLFSSL_BLIND_PRIVATE_KEY
        FreeDer(&ssl->buffers.keyMask);
    #endif
    }
    if (AllocCopyDer(&ssl->buffers.key, (const byte*)label, (word32)sz,
            PRIVATEKEY_TYPE, ssl->heap) != 0) {
        ret = 0;
    }
    if (ret == 1) {
        /* Buffer now ours. */
        ssl->buffers.weOwnKey = 1;
        /* Private key is a label. */
        ssl->buffers.keyId = 0;
        ssl->buffers.keyLabel = 1;
        /* Set private key device id to be one passed in or for SSL. */
        if (devId != INVALID_DEVID) {
            ssl->buffers.keyDevId = devId;
        }
        else {
            ssl->buffers.keyDevId = ssl->devId;
        }

    #ifdef WOLFSSL_DUAL_ALG_CERTS
        /* Set the label for the alternative key, too. User can still override
         * that afterwards. */
        ret = wolfSSL_use_AltPrivateKey_Label(ssl, label, devId);
    #endif
    }

    return ret;
}

#ifdef WOLFSSL_DUAL_ALG_CERTS
int wolfSSL_use_AltPrivateKey_Id(WOLFSSL* ssl, const unsigned char* id, long sz,
    int devId)
{
    int ret = 1;

    if ((ssl == NULL) || (id == NULL)) {
        ret = 0;
    }

    if (ret == 1) {
        if (ssl->buffers.weOwnAltKey) {
            FreeDer(&ssl->buffers.altKey);
        #ifdef WOLFSSL_BLIND_PRIVATE_KEY
            FreeDer(&ssl->buffers.altKeyMask);
        #endif
        }
        if (AllocDer(&ssl->buffers.altKey, (word32)sz, ALT_PRIVATEKEY_TYPE,
                ssl->heap) == 0) {
            ret = 0;
        }
    }
    if (ret == 1) {
        XMEMCPY(ssl->buffers.altKey->buffer, id, sz);
        ssl->buffers.weOwnAltKey = 1;
        ssl->buffers.altKeyId = 1;
        if (devId != INVALID_DEVID) {
            ssl->buffers.altKeyDevId = devId;
        }
        else {
            ssl->buffers.altKeyDevId = ssl->devId;
        }
    }

    return ret;
}

int wolfSSL_use_AltPrivateKey_id(WOLFSSL* ssl, const unsigned char* id, long sz,
    int devId, long keySz)
{
    int ret = wolfSSL_use_AltPrivateKey_Id(ssl, id, sz, devId);
    if (ret == 1) {
        ssl->buffers.altKeySz = (word32)keySz;
    }

    return ret;
}

int wolfSSL_use_AltPrivateKey_Label(WOLFSSL* ssl, const char* label, int devId)
{
    int ret = 1;
    word32 sz;

    if ((ssl == NULL) || (label == NULL)) {
        ret = 0;
    }

    if (ret == 1) {
        sz = (word32)XSTRLEN(label) + 1;
        if (ssl->buffers.weOwnAltKey) {
            FreeDer(&ssl->buffers.altKey);
        #ifdef WOLFSSL_BLIND_PRIVATE_KEY
            FreeDer(&ssl->buffers.altKeyMask);
        #endif
        }
        if (AllocDer(&ssl->buffers.altKey, (word32)sz, ALT_PRIVATEKEY_TYPE,
                ssl->heap) == 0) {
            ret = 0;
        }
    }
    if (ret == 1) {
        XMEMCPY(ssl->buffers.altKey->buffer, label, sz);
        ssl->buffers.weOwnAltKey = 1;
        ssl->buffers.altKeyLabel = 1;
        if (devId != INVALID_DEVID) {
            ssl->buffers.altKeyDevId = devId;
        }
        else {
            ssl->buffers.altKeyDevId = ssl->devId;
        }
    }

    return ret;
}
#endif /* WOLFSSL_DUAL_ALG_CERTS */
#endif /* WOLF_PRIVATE_KEY_ID */

/* Load a certificate chain in a buffer into SSL.
 *
 * @param [in, out] ssl     SSL object.
 * @param [in]      in      Buffer holding DER encoded certificate chain.
 * @param [in]      sz      Size of data in bytes.
 * @param [in]      format  Format of data:
 *                            WOLFSSL_FILETYPE_PEM or WOLFSSL_FILETYPE_ASN1.
 * @return  1 on success.
 * @return  0 on failure.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 */
int wolfSSL_use_certificate_chain_buffer_format(WOLFSSL* ssl,
    const unsigned char* in, long sz, int format)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_use_certificate_chain_buffer_format");

    /* Validate parameters. */
    if (ssl == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = ProcessBuffer(ssl->ctx, in, sz, format, CERT_TYPE, ssl, NULL, 1,
            GET_VERIFY_SETTING_SSL(ssl));
    }

    return ret;
}

/* Load a PEM encoded certificate chain in a buffer into SSL.
 *
 * @param [in, out] ssl     SSL object.
 * @param [in]      in      Buffer holding DER encoded certificate chain.
 * @param [in]      sz      Size of data in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 * @return  Negative on error.
 */
int wolfSSL_use_certificate_chain_buffer(WOLFSSL* ssl, const unsigned char* in,
    long sz)
{
    return wolfSSL_use_certificate_chain_buffer_format(ssl, in, sz,
        WOLFSSL_FILETYPE_PEM);
}

#if defined(OPENSSL_EXTRA) || defined(HAVE_LIGHTY) || \
    defined(WOLFSSL_MYSQL_COMPATIBLE) || defined(HAVE_STUNNEL) || \
    defined(WOLFSSL_NGINX) || defined(HAVE_POCO_LIB) || \
    defined(WOLFSSL_HAPROXY)
/* Add certificate to chain.
 *
 * @param [in, out] chain   Buffer holding encoded certificate for TLS.
 * @param [in]      weOwn   Indicates we need to free chain if repleced.
 * @param [in]      cert    Buffer holding DER encoded certificate.
 * @param [in]      certSz  Size of DER encoded certificate in bytes.
 * @param [in]      heap    Dynamic memory allocation hint.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wolfssl_add_to_chain(DerBuffer** chain, int weOwn, const byte* cert,
    word32 certSz, void* heap)
{
    int res = 1;
    int ret;
    DerBuffer* oldChain = *chain;
    DerBuffer* newChain = NULL;
    word32 len = 0;

    if (oldChain != NULL) {
        /* Get length of previous chain. */
        len = oldChain->length;
    }
    /* Allocate DER buffer bug enough to hold old and new certificates. */
    ret = AllocDer(&newChain, len + CERT_HEADER_SZ + certSz, CERT_TYPE, heap);
    if (ret != 0) {
        WOLFSSL_MSG("AllocDer error");
        res = 0;
    }

    if (res == 1) {
        if (oldChain != NULL) {
            /* Place old chain in new buffer. */
            XMEMCPY(newChain->buffer, oldChain->buffer, len);
        }
        /* Append length and DER encoded certificate. */
        c32to24(certSz, newChain->buffer + len);
        XMEMCPY(newChain->buffer + len + CERT_HEADER_SZ, cert, certSz);

        /* Dispose of old chain if we own it. */
        if (weOwn) {
            FreeDer(chain);
        }
        /* Replace chain. */
        *chain = newChain;
    }

    return res;
}
#endif

#ifdef OPENSSL_EXTRA

/* Add a certificate to end of chain sent in TLS handshake.
 *
 * @param [in, out] ctx    SSL context.
 * @param [in]      der    Buffer holding DER encoded certificate.
 * @param [in]      derSz  Size of data in buffer.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wolfssl_ctx_add_to_chain(WOLFSSL_CTX* ctx, const byte* der,
    int derSz)
{
    int res = 1;
    int ret;
    DerBuffer* derBuffer = NULL;

    /* Create a DER buffer from DER encoding. */
    ret = AllocCopyDer(&derBuffer, der, (word32)derSz, CERT_TYPE, ctx->heap);
    if (ret != 0) {
        WOLFSSL_MSG("Memory Error");
        res = 0;
    }
    if (res == 1) {
        /* Add a user CA certificate to the certificate manager. */
        res = AddCA(ctx->cm, &derBuffer, WOLFSSL_USER_CA,
            GET_VERIFY_SETTING_CTX(ctx));
        if (res != 1) {
            res = 0;
        }
    }

    if (res == 1) {
         /* Add chain to DER buffer. */
         res = wolfssl_add_to_chain(&ctx->certChain, 1, der, (word32)derSz, ctx->heap);
    #ifdef WOLFSSL_TLS13
        /* Update count of certificates. */
        ctx->certChainCnt++;
    #endif
    }

    return res;
}

/* Add a certificate to chain sent in TLS handshake.
 *
 * @param [in, out] ctx   SSL context.
 * @param [in]      x509  X509 certificate object.
 * @return  1 on success.
 * @return  0 on failure.
 */
long wolfSSL_CTX_add_extra_chain_cert(WOLFSSL_CTX* ctx, WOLFSSL_X509* x509)
{
    int   ret = 1;
    int   derSz = 0;
    const byte* der = NULL;

    WOLFSSL_ENTER("wolfSSL_CTX_add_extra_chain_cert");

    /* Validate parameters. */
    if ((ctx == NULL) || (x509 == NULL)) {
        WOLFSSL_MSG("Bad Argument");
        ret = 0;
    }

    if (ret == 1) {
        /* Get the DER encoding of the certificate from the X509 object. */
        der = wolfSSL_X509_get_der(x509, &derSz);
        /* Validate buffer. */
        if ((der == NULL) || (derSz <= 0)) {
            WOLFSSL_MSG("Error getting X509 DER");
            ret = 0;
        }
    }

    if ((ret == 1) && (ctx->certificate == NULL)) {
        WOLFSSL_ENTER("wolfSSL_use_certificate_chain_buffer_format");

        /* Process buffer makes first certificate the leaf. */
        ret = ProcessBuffer(ctx, der, derSz, WOLFSSL_FILETYPE_ASN1, CERT_TYPE,
            NULL, NULL, 1, GET_VERIFY_SETTING_CTX(ctx));
        if (ret != 1) {
            ret = 0;
        }
    }
    else if (ret == 1) {
        /* Add certificate to existing chain. */
        ret = wolfssl_ctx_add_to_chain(ctx, der, derSz);
    }

    if (ret == 1) {
        /* On success WOLFSSL_X509 memory is responsibility of SSL context. */
        wolfSSL_X509_free(x509);
    }

    WOLFSSL_LEAVE("wolfSSL_CTX_add_extra_chain_cert", ret);
    return ret;
}

#endif /* OPENSSL_EXTRA */

#if defined(OPENSSL_EXTRA) || defined(HAVE_LIGHTY) || \
    defined(WOLFSSL_MYSQL_COMPATIBLE) || defined(HAVE_STUNNEL) || \
    defined(WOLFSSL_NGINX) || defined(HAVE_POCO_LIB) || \
    defined(WOLFSSL_HAPROXY)
/* Load a certificate into SSL context.
 *
 * @param [in, out] ctx   SSL context object.
 * @param [in]      x509  X509 certificate object.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_CTX_use_certificate(WOLFSSL_CTX *ctx, WOLFSSL_X509 *x)
{
    int res = 1;
    int ret;

    WOLFSSL_ENTER("wolfSSL_CTX_use_certificate");

    /* Validate parameters. */
    if ((ctx == NULL) || (x == NULL) || (x->derCert == NULL)) {
        WOLFSSL_MSG("Bad parameter");
        res = 0;
    }

    if (res == 1) {
        /* Replace certificate buffer with one holding the new certificate. */
        FreeDer(&ctx->certificate);
        ret = AllocCopyDer(&ctx->certificate, x->derCert->buffer,
            x->derCert->length, CERT_TYPE, ctx->heap);
        if (ret != 0) {
            res = 0;
        }
    }

#ifdef KEEP_OUR_CERT
    if (res == 1) {
        /* Dispose of our certificate if it is ours. */
        if ((ctx->ourCert != NULL) && ctx->ownOurCert) {
            wolfSSL_X509_free(ctx->ourCert);
        }
    #ifndef WOLFSSL_X509_STORE_CERTS
        /* Keep a reference to the new certificate. */
        ctx->ourCert = x;
        if (wolfSSL_X509_up_ref(x) != 1) {
            res = 0;
        }
    #else
        /* Keep a copy of the new certificate. */
        ctx->ourCert = wolfSSL_X509_d2i_ex(NULL, x->derCert->buffer,
            x->derCert->length, ctx->heap);
        if (ctx->ourCert == NULL) {
            res = 0;
        }
    #endif
        /* Now own our certificate. */
        ctx->ownOurCert = 1;
    }
#endif

    if (res == 1) {
        /* Set have options based on public key OID. */
        wolfssl_set_have_from_key_oid(ctx, NULL, x->pubKeyOID);
    }

    return res;
}

/* Add the certificate to the chain in the SSL context and own the X509 object.
 *
 * @param [in, out] ctx   SSL context object.
 * @param [in]      x509  X509 certificate object.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_CTX_add0_chain_cert(WOLFSSL_CTX* ctx, WOLFSSL_X509* x509)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_CTX_add0_chain_cert");

    /* Add certificate to chain and copy or up reference it. */
    ret = wolfSSL_CTX_add1_chain_cert(ctx, x509);
    if (ret == 1) {
        /* Down reference or free original now as we own certificate. */
        wolfSSL_X509_free(x509);
    }

    return ret;
}

/* Add the certificate to the chain in the SSL context.
 *
 * X509 object copied or up referenced.
 *
 * @param [in, out] ctx   SSL context object.
 * @param [in]      x509  X509 certificate object.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_CTX_add1_chain_cert(WOLFSSL_CTX* ctx, WOLFSSL_X509* x509)
{
    int ret = 1;

    WOLFSSL_ENTER("wolfSSL_CTX_add1_chain_cert");

    /* Validate parameters. */
    if ((ctx == NULL) || (x509 == NULL) || (x509->derCert == NULL)) {
        ret = 0;
    }

    /* Check if we already have set a certificate. */
    if ((ret == 1) && (ctx->certificate == NULL)) {
        /* Use the certificate. */
        ret = wolfSSL_CTX_use_certificate(ctx, x509);
    }
    /* Increase reference count as we will store it. */
    else if ((ret == 1) && ((ret = wolfSSL_X509_up_ref(x509)) == 1)) {
        /* Load the DER encoding. */
        ret = wolfSSL_CTX_load_verify_buffer(ctx, x509->derCert->buffer,
            x509->derCert->length, WOLFSSL_FILETYPE_ASN1);
        if (ret == 1) {
            /* Add DER encoding to chain. */
            ret = wolfssl_add_to_chain(&ctx->certChain, 1,
                x509->derCert->buffer, x509->derCert->length, ctx->heap);
        }
        /* Store cert in stack to free it later. */
        if ((ret == 1) && (ctx->x509Chain == NULL)) {
            /* Create a stack for certificates. */
            ctx->x509Chain = wolfSSL_sk_X509_new_null();
            if (ctx->x509Chain == NULL) {
                WOLFSSL_MSG("wolfSSL_sk_X509_new_null error");
                ret = 0;
            }
        }
        if (ret == 1) {
            /* Push the X509 object onto stack. */
            ret = wolfSSL_sk_X509_push(ctx->x509Chain, x509) > 0
                    ? WOLFSSL_SUCCESS : WOLFSSL_FAILURE;
        }

        if (ret != 1) {
            /* Decrease reference count on error as we didn't store it. */
            wolfSSL_X509_free(x509);
        }
    }

    return WS_RC(ret);
}

#ifdef KEEP_OUR_CERT
/* Add the certificate to the chain in the SSL and own the X509 object.
 *
 * @param [in, out] ssl   SSL object.
 * @param [in]      x509  X509 certificate object.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_add0_chain_cert(WOLFSSL* ssl, WOLFSSL_X509* x509)
{
    int ret = 1;

    WOLFSSL_ENTER("wolfSSL_add0_chain_cert");

    /* Validate parameters. */
    if ((ssl == NULL) || (x509 == NULL) || (x509->derCert == NULL)) {
        ret = 0;
    }

    /* Check if we already have set a certificate. */
    if ((ret == 1) && (ssl->buffers.certificate == NULL)) {
        /* Use the certificate. */
        ret = wolfSSL_use_certificate(ssl, x509);
        if (ret == 1) {
            /* Dispose of old certificate if we own it. */
            if (ssl->buffers.weOwnCert) {
                wolfSSL_X509_free(ssl->ourCert);
            }
            /* Store cert to free it later. */
            ssl->ourCert = x509;
            ssl->buffers.weOwnCert = 1;
        }
    }
    else if (ret == 1) {
        /* Add DER encoding to chain. */
        ret = wolfssl_add_to_chain(&ssl->buffers.certChain,
            ssl->buffers.weOwnCertChain, x509->derCert->buffer,
            x509->derCert->length, ssl->heap);
        if (ret == 1) {
            /* We now own cert chain. */
            ssl->buffers.weOwnCertChain = 1;
            /* Create a stack to put certificate into. */
            if (ssl->ourCertChain == NULL) {
                ssl->ourCertChain = wolfSSL_sk_X509_new_null();
                if (ssl->ourCertChain == NULL) {
                    WOLFSSL_MSG("wolfSSL_sk_X509_new_null error");
                    ret = 0;
                }
            }
        }
        if (ret == 1) {
            /* Push X509 object onto stack to be freed. */
            ret = wolfSSL_sk_X509_push(ssl->ourCertChain, x509) > 0
                    ? WOLFSSL_SUCCESS : WOLFSSL_FAILURE;
            if (ret != 1) {
                /* Free it now on error. */
                wolfSSL_X509_free(x509);
            }
        }
    }
    return WS_RC(ret);
}

/* Add the certificate to the chain in the SSL.
 *
 * X509 object is up referenced.
 *
 * @param [in, out] ssl   SSL object.
 * @param [in]      x509  X509 certificate object.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_add1_chain_cert(WOLFSSL* ssl, WOLFSSL_X509* x509)
{
    int ret = 1;

    WOLFSSL_ENTER("wolfSSL_add1_chain_cert");

    /* Validate parameters. */
    if ((ssl == NULL) || (x509 == NULL) || (x509->derCert == NULL)) {
        ret = 0;
    }

    /* Increase reference count on X509 object before adding. */
    if ((ret == 1) && ((ret == wolfSSL_X509_up_ref(x509)) == 1)) {
        /* Add this to the chain. */
        if ((ret = wolfSSL_add0_chain_cert(ssl, x509)) != 1) {
            /* Decrease reference count on error as not stored. */
            wolfSSL_X509_free(x509);
        }
    }

    return ret;
}
#endif /* KEEP_OUR_CERT */
#endif /* OPENSSL_EXTRA, HAVE_LIGHTY, WOLFSSL_MYSQL_COMPATIBLE, HAVE_STUNNEL,
          WOLFSSL_NGINX, HAVE_POCO_LIB, WOLFSSL_HAPROXY */

#ifdef OPENSSL_EXTRA

/* Load a private key into SSL context.
 *
 * @param [in, out] ctx   SSL context object.
 * @param [in]      pkey  EVP private key.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_CTX_use_PrivateKey(WOLFSSL_CTX *ctx, WOLFSSL_EVP_PKEY *pkey)
{
    int ret = 1;

    WOLFSSL_ENTER("wolfSSL_CTX_use_PrivateKey");

    /* Validate parameters. */
    if ((ctx == NULL) || (pkey == NULL) || (pkey->pkey.ptr == NULL)) {
        ret = 0;
    }

    if (ret == 1) {
        switch (pkey->type) {
    #if defined(WOLFSSL_KEY_GEN) && !defined(NO_RSA)
        case WC_EVP_PKEY_RSA:
            WOLFSSL_MSG("populating RSA key");
            ret = PopulateRSAEvpPkeyDer(pkey);
            break;
    #endif /* (WOLFSSL_KEY_GEN || OPENSSL_EXTRA) && !NO_RSA */
    #if !defined(HAVE_SELFTEST) && (defined(WOLFSSL_KEY_GEN) || \
            defined(WOLFSSL_CERT_GEN)) && !defined(NO_DSA)
        case WC_EVP_PKEY_DSA:
            break;
    #endif /* !HAVE_SELFTEST && (WOLFSSL_KEY_GEN || WOLFSSL_CERT_GEN) &&
            * !NO_DSA */
    #ifdef HAVE_ECC
        case WC_EVP_PKEY_EC:
            WOLFSSL_MSG("populating ECC key");
            ret = ECC_populate_EVP_PKEY(pkey, pkey->ecc);
            break;
    #endif
        default:
            ret = 0;
        }
    }

    if (ret == 1) {
        /* ptr for WOLFSSL_EVP_PKEY struct is expected to be DER format */
        ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx,
            (const unsigned char*)pkey->pkey.ptr, pkey->pkey_sz,
            WOLFSSL_FILETYPE_ASN1);
    }

    return ret;
}

#endif /* OPENSSL_EXTRA */

#if defined(OPENSSL_ALL) || defined(WOLFSSL_ASIO) || \
    defined(WOLFSSL_HAPROXY) || defined(WOLFSSL_NGINX) || defined(WOLFSSL_QT)
/* Load a DER encoded certificate in a buffer into SSL context.
 *
 * @param [in, out] ctx    SSL context object.
 * @param [in]      der    Buffer holding DER encoded certificate.
 * @param [in]      derSz  Size of data in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_CTX_use_certificate_ASN1(WOLFSSL_CTX *ctx, int derSz,
    const unsigned char *der)
{
    int ret = 1;

    WOLFSSL_ENTER("wolfSSL_CTX_use_certificate_ASN1");

    /* Validate parameters. */
    if ((ctx == NULL) || (der == NULL)) {
        ret = 0;
    }
    /* Load DER encoded certificate into SSL context. */
    if ((ret == 1) && (wolfSSL_CTX_use_certificate_buffer(ctx, der, derSz,
            WOLFSSL_FILETYPE_ASN1) != 1)) {
        ret = 0;
    }

    return ret;
}

#if defined(WOLFSSL_KEY_GEN) && !defined(NO_RSA)
/* Load an RSA private key into SSL context.
 *
 * @param [in, out] ctx   SSL context object.
 * @param [in]      rsa   RSA private key.
 * @return  1 on success.
 * @return  0 on failure.
 * @return  BAD_FUNC_ARG when ctx or rsa is NULL.
 * @return  MEMORY_E when dynamic memory allocation fails.
 */
int wolfSSL_CTX_use_RSAPrivateKey(WOLFSSL_CTX* ctx, WOLFSSL_RSA* rsa)
{
    int ret = 1;
    int derSize = 0;
    unsigned char* der = NULL;
    unsigned char* p;

    WOLFSSL_ENTER("wolfSSL_CTX_use_RSAPrivateKey");

    /* Validate parameters. */
    if ((ctx == NULL) || (rsa == NULL)) {
        WOLFSSL_MSG("one or more inputs were NULL");
        ret = BAD_FUNC_ARG;
    }

    /* Get DER encoding size. */
    if ((ret == 1) && ((derSize = wolfSSL_i2d_RSAPrivateKey(rsa, NULL)) <= 0)) {
        ret = 0;
    }

    if (ret == 1) {
        /* Allocate memory to hold DER encoding.. */
        der = (unsigned char*)XMALLOC(derSize, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (der == NULL) {
            WOLFSSL_MSG("Malloc failure");
            ret = MEMORY_E;
        }
    }

    if (ret == 1) {
        /* Pointer passed in is modified.. */
        p = der;
        /* Encode the RSA key as DER into buffer and get size. */
        if ((derSize = wolfSSL_i2d_RSAPrivateKey(rsa, &p)) <= 0) {
            WOLFSSL_MSG("wolfSSL_i2d_RSAPrivateKey() failure");
            ret = 0;
        }
    }

    if (ret == 1) {
        /* Load DER encoded certificate into SSL context. */
        ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx, der, derSize,
            SSL_FILETYPE_ASN1);
        if (ret != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("wolfSSL_CTX_USE_PrivateKey_buffer() failure");
            ret = 0;
        }
    }

    /* Dispos of dynamically allocated data. */
    XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}
#endif /* WOLFSSL_KEY_GEN && !NO_RSA */

#endif /* OPENSSL_ALL || WOLFSSL_ASIO || WOLFSSL_HAPROXY || WOLFSSL_QT */

#endif /* !NO_CERTS */

#ifdef OPENSSL_EXTRA

/* Use the default paths to look for CA certificate.
 *
 * This is an OpenSSL compatibility layer function, but it doesn't mirror
 * the exact functionality of its OpenSSL counterpart. We don't support the
 * notion of an "OpenSSL directory". This function will attempt to load the
 * environment variables SSL_CERT_DIR and SSL_CERT_FILE, if either are
 * found, they will be loaded. Otherwise, it will act as a wrapper around
 * our native wolfSSL_CTX_load_system_CA_certs function. This function does
 * conform to OpenSSL's return value conventions.
 *
 * @param [in] ctx  SSL context object.
 * @return  1 on success.
 * @return  0 on failure.
 * @return  WOLFSSL_FATAL_ERROR when using a filesystem is not supported.
 */
int wolfSSL_CTX_set_default_verify_paths(WOLFSSL_CTX* ctx)
{
    int ret;
#if defined(XGETENV) && !defined(NO_GETENV)
    char* certDir = NULL;
    char* certFile = NULL;
    word32 flags = 0;
#elif !defined(WOLFSSL_SYS_CA_CERTS)
    (void)ctx;
#endif

    WOLFSSL_ENTER("wolfSSL_CTX_set_default_verify_paths");

#if defined(XGETENV) && !defined(NO_GETENV)
    /* // NOLINTBEGIN(concurrency-mt-unsafe) */
    certDir = wc_strdup_ex(XGETENV("SSL_CERT_DIR"), DYNAMIC_TYPE_TMP_BUFFER);
    certFile = wc_strdup_ex(XGETENV("SSL_CERT_FILE"), DYNAMIC_TYPE_TMP_BUFFER);
    flags = WOLFSSL_LOAD_FLAG_PEM_CA_ONLY;

    if ((certDir != NULL) || (certFile != NULL)) {
        if (certDir != NULL) {
           /* We want to keep trying to load more CA certs even if one cert in
            * the directory is bad and can't be used (e.g. if one is
            * expired), so we use WOLFSSL_LOAD_FLAG_IGNORE_ERR.
            */
            flags |= WOLFSSL_LOAD_FLAG_IGNORE_ERR;
        }

        /* Load CA certificates from environment variable locations. */
        ret = wolfSSL_CTX_load_verify_locations_ex(ctx, certFile, certDir,
            flags);
        if (ret != 1) {
            WOLFSSL_MSG_EX("Failed to load CA certs from SSL_CERT_FILE: %s"
                            " SSL_CERT_DIR: %s. Error: %d", certFile,
                            certDir, ret);
            ret = 0;
        }
    }
    /* // NOLINTEND(concurrency-mt-unsafe) */
    else
#endif

    {
    #ifdef NO_FILESYSTEM
        WOLFSSL_MSG("wolfSSL_CTX_set_default_verify_paths not supported"
                    " with NO_FILESYSTEM enabled");
        ret = WOLFSSL_FATAL_ERROR;
    #elif defined(WOLFSSL_SYS_CA_CERTS)
        /* Load the system CA certificates. */
        ret = wolfSSL_CTX_load_system_CA_certs(ctx);
        if (ret == WC_NO_ERR_TRACE(WOLFSSL_BAD_PATH)) {
            /* OpenSSL doesn't treat the lack of a system CA cert directory as a
             * failure. We do the same here.
             */
            ret = 1;
        }
    #else
        /* OpenSSL's implementation of this API does not require loading the
           system CA cert directory.  Allow skipping this without erroring out. */
        ret = 1;
    #endif
    }

#if defined(XGETENV) && !defined(NO_GETENV)
    XFREE(certFile, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(certDir, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    WOLFSSL_LEAVE("wolfSSL_CTX_set_default_verify_paths", ret);

    return ret;
}

#endif /* OPENSSL_EXTRA */

#ifndef NO_DH

/* Set the temporary DH parameters against the SSL.
 *
 * @param [in, out] ssl   SSL object.
 * @param [in]      p     Buffer holding prime.
 * @param [in]      pSz   Length of prime in bytes.
 * @param [in]      g     Buffer holding generator.
 * @param [in]      gSz   Length of generator in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 * @return  DH_KEY_SIZE_E when the prime is too short or long.
 * @return  SIDE_ERROR when the SSL is for a client.
 */
static int wolfssl_set_tmp_dh(WOLFSSL* ssl, unsigned char* p, int pSz,
    unsigned char* g, int gSz)
{
    int ret = 1;

    /* Check the size of the prime meets the requirements of the SSL. */
    if (((word16)pSz < ssl->options.minDhKeySz) ||
            ((word16)pSz > ssl->options.maxDhKeySz)) {
        ret = DH_KEY_SIZE_E;
    }
    /* Only able to set DH parameters on server. */
    if ((ret == 1) && (ssl->options.side == WOLFSSL_CLIENT_END)) {
        ret = SIDE_ERROR;
    }

    if (ret == 1) {
    #if !defined(WOLFSSL_OLD_PRIME_CHECK) && !defined(HAVE_FIPS) && \
        !defined(HAVE_SELFTEST)
        /* New DH parameters not tested for validity. */
        ssl->options.dhKeyTested = 0;
        /* New DH parameters must be tested for validity before use. */
        ssl->options.dhDoKeyTest = 1;
    #endif

        /* Dispose of old DH parameters if we own it. */
        if (ssl->buffers.weOwnDH) {
            XFREE(ssl->buffers.serverDH_P.buffer, ssl->heap,
                DYNAMIC_TYPE_PUBLIC_KEY);
            XFREE(ssl->buffers.serverDH_G.buffer, ssl->heap,
                DYNAMIC_TYPE_PUBLIC_KEY);
        }

        /* Assign the buffers and lengths to SSL. */
        ssl->buffers.serverDH_P.buffer = p;
        ssl->buffers.serverDH_G.buffer = g;
        ssl->buffers.serverDH_P.length = (unsigned int)pSz;
        ssl->buffers.serverDH_G.length = (unsigned int)gSz;
        /* We own the buffers. */
        ssl->buffers.weOwnDH = 1;
        /* We have a DH parameters to use. */
        ssl->options.haveDH = 1;
    }

    /* Allocate space for cipher suites. */
    if ((ret == 1) && (AllocateSuites(ssl) != 0)) {
        ssl->buffers.serverDH_P.buffer = NULL;
        ssl->buffers.serverDH_G.buffer = NULL;
        ret = 0;
    }
    if (ret == 1) {
        /* Reset the cipher suites based on having a DH parameters now. */
        InitSuites(ssl->suites, ssl->version, SSL_KEY_SZ(ssl),
            WOLFSSL_HAVE_RSA, SSL_HAVE_PSK(ssl), ssl->options.haveDH,
            ssl->options.haveECDSAsig, ssl->options.haveECC, TRUE,
            ssl->options.haveStaticECC,
            ssl->options.useAnon, TRUE,
            TRUE, TRUE, TRUE, ssl->options.side);
    }

    return ret;
}

/* Set the temporary DH parameters against the SSL.
 *
 * @param [in, out] ssl   SSL object.
 * @param [in]      p     Buffer holding prime.
 * @param [in]      pSz   Length of prime in bytes.
 * @param [in]      g     Buffer holding generator.
 * @param [in]      gSz   Length of generator in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 * @return  DH_KEY_SIZE_E when the prime is too short or long.
 * @return  SIDE_ERROR when the SSL is for a client.
 * @return  MEMORY_E when dynamic memory allocation fails.
 */
int wolfSSL_SetTmpDH(WOLFSSL* ssl, const unsigned char* p, int pSz,
    const unsigned char* g, int gSz)
{
    int ret = 1;
    byte* pAlloc = NULL;
    byte* gAlloc = NULL;

    WOLFSSL_ENTER("wolfSSL_SetTmpDH");

    /* Validate parameters. */
    if ((ssl == NULL) || (p == NULL) || (g == NULL)) {
        ret = 0;
    }

    if (ret == 1) {
        /* Allocate buffers for p and g to be assigned into SSL. */
        pAlloc = (byte*)XMALLOC((size_t)pSz, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
        gAlloc = (byte*)XMALLOC((size_t)gSz, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
        if ((pAlloc == NULL) || (gAlloc == NULL)) {
            /* Memory will be freed below in the (ret != 1) block */
            ret = MEMORY_E;
        }
    }
    if (ret == 1) {
        /* Copy p and g into allocated buffers. */
        XMEMCPY(pAlloc, p, pSz);
        XMEMCPY(gAlloc, g, gSz);
        /* Set the buffers into SSL. */
        ret = wolfssl_set_tmp_dh(ssl, pAlloc, pSz, gAlloc, gSz);
    }

    if (ret != 1 && ssl != NULL) {
        /* Free the allocated buffers if not assigned into SSL. */
        XFREE(pAlloc, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
        XFREE(gAlloc, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
    }

    WOLFSSL_LEAVE("wolfSSL_SetTmpDH", ret);
    return ret;
}

#if !defined(WOLFSSL_OLD_PRIME_CHECK) && !defined(HAVE_FIPS) && \
    !defined(HAVE_SELFTEST)
/* Check the DH parameters is valid.
 *
 * @param [in]      p     Buffer holding prime.
 * @param [in]      pSz   Length of prime in bytes.
 * @param [in]      g     Buffer holding generator.
 * @param [in]      gSz   Length of generator in bytes.
 * @return  1 on success.
 * @return  DH_CHECK_PUB_E when p is not a prime.
 * @return  BAD_FUNC_ARG when p or g is NULL, or pSz or gSz is 0.
 * @return  MEMORY_E when dynamic memory allocation fails.
 */
static int wolfssl_check_dh_key(unsigned char* p, int pSz, unsigned char* g,
    int gSz)
{
    WC_RNG rng;
    int ret = 0;
#ifndef WOLFSSL_SMALL_STACK
    DhKey checkKey[1];
#else
    DhKey *checkKey;
#endif

#ifdef WOLFSSL_SMALL_STACK
    checkKey = (DhKey*)XMALLOC(sizeof(DhKey), NULL, DYNAMIC_TYPE_DH);
    if (checkKey == NULL) {
        ret = MEMORY_E;
    }
#endif
    /* Initialize a new random number generator. */
    if ((ret == 0) && ((ret = wc_InitRng(&rng)) == 0)) {
        /* Initialize a DH object. */
        if ((ret = wc_InitDhKey(checkKey)) == 0) {
            /* Check DH parameters. */
            ret = wc_DhSetCheckKey(checkKey, p, (word32)pSz, g, (word32)gSz, NULL, 0, 0, &rng);
            /* Dispose of DH object. */
            wc_FreeDhKey(checkKey);
        }
        /* Dispose of random number generator. */
        wc_FreeRng(&rng);
    }

#ifdef WOLFSSL_SMALL_STACK
    /* Dispose of dynamically allocated data. */
    XFREE(checkKey, NULL, DYNAMIC_TYPE_DH);
#endif
    /* Convert wolfCrypt return code to 1 on success and ret on failure. */
    return WC_TO_WS_RC(ret);
}
#endif

/* Set the temporary DH parameters against the SSL context.
 *
 * @param [in, out] ctx   SSL context object.
 * @param [in]      p     Buffer holding prime.
 * @param [in]      pSz   Length of prime in bytes.
 * @param [in]      g     Buffer holding generator.
 * @param [in]      gSz   Length of generator in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 * @return  DH_KEY_SIZE_E when the prime is too short or long.
 * @return  SIDE_ERROR when the SSL is for a client.
 * @return  BAD_FUNC_ARG when ctx, p or g is NULL.
 * @return  DH_CHECK_PUB_E when p is not a prime.
 * @return  MEMORY_E when dynamic memory allocation fails.
 */
static int wolfssl_ctx_set_tmp_dh(WOLFSSL_CTX* ctx, unsigned char* p, int pSz,
    unsigned char* g, int gSz)
{
    int ret = 1;

    WOLFSSL_ENTER("wolfSSL_CTX_SetTmpDH");

    /* Check the size of the prime meets the requirements of the SSL context. */
    if (((word16)pSz < ctx->minDhKeySz) || ((word16)pSz > ctx->maxDhKeySz)) {
        ret = DH_KEY_SIZE_E;
    }

#if !defined(WOLFSSL_OLD_PRIME_CHECK) && !defined(HAVE_FIPS) && \
    !defined(HAVE_SELFTEST)
    if (ret == 1) {
        /* Test DH parameters for validity. */
        ret = wolfssl_check_dh_key(p, pSz, g, gSz);
        /* Record as whether tested based on result of validity test. */
        ctx->dhKeyTested = (ret == 1);
    }
#endif

    if (ret == 1) {
        /* Dispose of old DH parameters. */
        XFREE(ctx->serverDH_P.buffer, ctx->heap, DYNAMIC_TYPE_PUBLIC_KEY);
        XFREE(ctx->serverDH_G.buffer, ctx->heap, DYNAMIC_TYPE_PUBLIC_KEY);
        /* Assign the buffers and lengths to SSL context. */
        ctx->serverDH_P.buffer = p;
        ctx->serverDH_G.buffer = g;
        ctx->serverDH_P.length = (unsigned int)pSz;
        ctx->serverDH_G.length = (unsigned int)gSz;
        /* We have a DH parameters to use. */
        ctx->haveDH = 1;
    }

    WOLFSSL_LEAVE("wolfSSL_CTX_SetTmpDH", 0);
    return ret;
}

/* Set the temporary DH parameters against the SSL context.
 *
 * @param [in, out] ctx   SSL context object.
 * @param [in]      p     Buffer holding prime.
 * @param [in]      pSz   Length of prime in bytes.
 * @param [in]      g     Buffer holding generator.
 * @param [in]      gSz   Length of generator in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 * @return  DH_KEY_SIZE_E when the prime is too short or long.
 * @return  SIDE_ERROR when the SSL is for a client.
 * @return  BAD_FUNC_ARG when ctx, p or g is NULL.
 * @return  DH_CHECK_PUB_E when p is not a prime.
 */
int wolfSSL_CTX_SetTmpDH(WOLFSSL_CTX* ctx, const unsigned char* p, int pSz,
                         const unsigned char* g, int gSz)
{
    int ret = 1;
    byte* pAlloc = NULL;
    byte* gAlloc = NULL;

    /* Validate parameters. */
    if ((ctx == NULL) || (p == NULL) || (g == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 1) {
        /* Allocate buffers for p and g to be assigned into SSL context. */
        pAlloc = (byte*)XMALLOC((size_t)pSz, ctx->heap, DYNAMIC_TYPE_PUBLIC_KEY);
        gAlloc = (byte*)XMALLOC((size_t)gSz, ctx->heap, DYNAMIC_TYPE_PUBLIC_KEY);
        if ((pAlloc == NULL) || (gAlloc == NULL)) {
            ret = MEMORY_E;
        }
    }

    if (ret == 1) {
        /* Copy p and g into allocated buffers. */
        XMEMCPY(pAlloc, p, pSz);
        XMEMCPY(gAlloc, g, gSz);
        /* Set the buffers into SSL context. */
        ret = wolfssl_ctx_set_tmp_dh(ctx, pAlloc, pSz, gAlloc, gSz);
    }

    if ((ret != 1) && (ctx != NULL)) {
        /* Free the allocated buffers if not assigned into SSL context. */
        XFREE(pAlloc, ctx->heap, DYNAMIC_TYPE_PUBLIC_KEY);
        XFREE(gAlloc, ctx->heap, DYNAMIC_TYPE_PUBLIC_KEY);
    }
    return ret;
}

#ifdef OPENSSL_EXTRA
/* Set the temporary DH parameters against the SSL.
 *
 * @param [in, out] ssl  SSL object.
 * @param [in]      dh   DH object.
 * @return  1 on success.
 * @return  0 on failure.
 * @return  WOLFSSL_FATAL_ERROR on failure.
 * @return  BAD_FUNC_ARG when ssl or dh is NULL.
 * @return  DH_KEY_SIZE_E when the prime is too short or long.
 * @return  SIDE_ERROR when the SSL is for a client.
 */
long wolfSSL_set_tmp_dh(WOLFSSL *ssl, WOLFSSL_DH *dh)
{
    int ret = 1;
    byte* p = NULL;
    byte* g = NULL;
    int pSz = 0;
    int gSz = 0;

    WOLFSSL_ENTER("wolfSSL_set_tmp_dh");

    /* Validate parameters. */
    if ((ssl == NULL) || (dh == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 1) {
        /* Get sizes of p and g. */
        pSz = wolfSSL_BN_bn2bin(dh->p, NULL);
        gSz = wolfSSL_BN_bn2bin(dh->g, NULL);
        /* Validate p and g size. */
        if ((pSz <= 0) || (gSz <= 0)) {
            ret = WOLFSSL_FATAL_ERROR;
        }
    }

    if (ret == 1) {
        /* Allocate buffers for p and g to be assigned into SSL. */
        p = (byte*)XMALLOC(pSz, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
        g = (byte*)XMALLOC(gSz, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
        if ((p == NULL) || (g == NULL)) {
            ret = MEMORY_E;
        }
    }
    if (ret == 1) {
        /* Encode p and g and get sizes. */
        pSz = wolfSSL_BN_bn2bin(dh->p, p);
        gSz = wolfSSL_BN_bn2bin(dh->g, g);
        /* Check encoding worked. */
        if ((pSz <= 0) || (gSz <= 0)) {
            ret = WOLFSSL_FATAL_ERROR;
        }
    }
    if (ret == 1) {
        /* Set the buffers into SSL. */
        ret = wolfssl_set_tmp_dh(ssl, p, pSz, g, gSz);
    }

    if ((ret != 1) && (ssl != NULL)) {
        /* Free the allocated buffers if not assigned into SSL. */
        XFREE(p, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
        XFREE(g, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
    }
    return ret;
}

/* Set the temporary DH parameters object against the SSL context.
 *
 * @param [in, out] ctx     SSL context object.
 * @param [in]      dh      DH object.
 * @return  1 on success.
 * @return  0 on failure.
 * @return  DH_KEY_SIZE_E when the prime is too short or long.
 * @return  SIDE_ERROR when the SSL is for a client.
 * @return  BAD_FUNC_ARG when ctx, p or g is NULL.
 * @return  DH_CHECK_PUB_E when p is not a prime.
 */
long wolfSSL_CTX_set_tmp_dh(WOLFSSL_CTX* ctx, WOLFSSL_DH* dh)
{
    int ret = 1;
    int pSz = 0;
    int gSz = 0;
    byte* p = NULL;
    byte* g = NULL;

    WOLFSSL_ENTER("wolfSSL_CTX_set_tmp_dh");

    /* Validate parameters. */
    if ((ctx == NULL) || (dh == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 1) {
        /* Get sizes of p and g. */
        pSz = wolfSSL_BN_bn2bin(dh->p, NULL);
        gSz = wolfSSL_BN_bn2bin(dh->g, NULL);
        /* Validate p and g size. */
        if ((pSz <= 0) || (gSz <= 0)) {
            ret = WOLFSSL_FATAL_ERROR;
        }
    }

    if (ret == 1) {
        /* Allocate buffers for p and g to be assigned into SSL. */
        p = (byte*)XMALLOC(pSz, ctx->heap, DYNAMIC_TYPE_PUBLIC_KEY);
        g = (byte*)XMALLOC(gSz, ctx->heap, DYNAMIC_TYPE_PUBLIC_KEY);
        if ((p == NULL) || (g == NULL)) {
            ret = MEMORY_E;
        }
    }

    if (ret == 1) {
        /* Encode p and g and get sizes. */
        pSz = wolfSSL_BN_bn2bin(dh->p, p);
        gSz = wolfSSL_BN_bn2bin(dh->g, g);
        /* Check encoding worked. */
        if ((pSz < 0) && (gSz < 0)) {
            ret = WOLFSSL_FATAL_ERROR;
        }
    }
    if (ret == 1) {
        /* Set the buffers into SSL context. */
        ret = wolfssl_ctx_set_tmp_dh(ctx, p, pSz, g, gSz);
    }

    if ((ret != 1) && (ctx != NULL)) {
        /* Free the allocated buffers if not assigned into SSL. */
        XFREE(p, ctx->heap, DYNAMIC_TYPE_PUBLIC_KEY);
        XFREE(g, ctx->heap, DYNAMIC_TYPE_PUBLIC_KEY);
    }
    return ret;
}

#endif /* OPENSSL_EXTRA */

#ifndef NO_CERTS

/* Set the temporary DH parameters against the SSL context or SSL.
 *
 * @param [in, out] ctx     SSL context object.
 * @param [in, out] ssl     SSL object.
 * @param [in]      buf     Buffer holding encoded DH parameters.
 * @param [in]      sz      Size of encoded DH parameters.
 * @param [in]      format  Format of data:
 *                            WOLFSSL_FILETYPE_PEM or WOLFSSL_FILETYPE_ASN1.
 * @return  1 on success.
 * @return  0 on failure.
 * @return  BAD_FUNC_ARG when ctx and ssl NULL or buf is NULL.
 * @return  NOT_COMPLED_IN when format is PEM but PEM is not supported.
 * @return  WOLFSSL_BAD_FILETYPE if format is not supported.
 */
static int ws_ctx_ssl_set_tmp_dh(WOLFSSL_CTX* ctx, WOLFSSL* ssl,
    const unsigned char* buf, long sz, int format)
{
    DerBuffer* der = NULL;
    int res = 1;
    int ret;
    /* p and g size to allocate set to maximum valid size. */
    word32 pSz = MAX_DH_SIZE;
    word32 gSz = MAX_DH_SIZE;
    byte* p = NULL;
    byte* g = NULL;
    void* heap = WOLFSSL_HEAP(ctx, ssl);

    /* Validate parameters. */
    if (((ctx == NULL) && (ssl == NULL)) || (buf == NULL)) {
        res = BAD_FUNC_ARG;
    }
    /* Check format is supported. */
    if ((res == 1) && (format != WOLFSSL_FILETYPE_ASN1)) {
        if (format != WOLFSSL_FILETYPE_PEM) {
            res = WOLFSSL_BAD_FILETYPE;
        }
    #ifndef WOLFSSL_PEM_TO_DER
        else {
            res = NOT_COMPILED_IN;
        }
    #endif
    }

    /* PemToDer allocates its own DER buffer. */
    if ((res == 1) && (format != WOLFSSL_FILETYPE_PEM)) {
        /* Create an empty DER buffer. */
        ret = AllocDer(&der, 0, DH_PARAM_TYPE, heap);
        if (ret == 0) {
            /* Assign encoded DH parameters to DER buffer. */
            der->buffer = (byte*)buf;
            der->length = (word32)sz;
        }
        else {
            res = ret;
        }
    }

    if (res == 1) {
        /* Allocate enough memory to p and g to support valid use cases. */
        p = (byte*)XMALLOC(pSz, heap, DYNAMIC_TYPE_PUBLIC_KEY);
        g = (byte*)XMALLOC(gSz, heap, DYNAMIC_TYPE_PUBLIC_KEY);
        if ((p == NULL) || (g == NULL)) {
            res = MEMORY_E;
        }
    }

#ifdef WOLFSSL_PEM_TO_DER
    if ((res == 1) && (format == WOLFSSL_FILETYPE_PEM)) {
        /* Convert from PEM to DER. */
        /* Try converting DH parameters from PEM to DER. */
        ret = PemToDer(buf, sz, DH_PARAM_TYPE, &der, heap, NULL, NULL);
        if (ret < 0) {
            /* Otherwise, try converting X9.43 format DH parameters. */
            ret = PemToDer(buf, sz, X942_PARAM_TYPE, &der, heap, NULL, NULL);
        }
    #if defined(WOLFSSL_WPAS) && !defined(NO_DSA)
        if (ret < 0) {
            /* Otherwise, try converting DSA parameters. */
            ret = PemToDer(buf, sz, DSA_PARAM_TYPE, &der, heap, NULL, NULL);
        }
    #endif /* WOLFSSL_WPAS && !NO_DSA */
       if (ret < 0) {
           /* Return error from conversion. */
           res = ret;
       }
    }
#endif /* WOLFSSL_PEM_TO_DER */

    if (res == 1) {
        /* Get the p and g from the DER encoded parameters. */
        if (wc_DhParamsLoad(der->buffer, der->length, p, &pSz, g, &gSz) < 0) {
            res = WOLFSSL_BAD_FILETYPE;
        }
        else if (ssl != NULL) {
            /* Set p and g into SSL. */
            res = wolfssl_set_tmp_dh(ssl, p, (int)pSz, g, (int)gSz);
        }
        else {
            /* Set p and g into SSL context. */
            res = wolfssl_ctx_set_tmp_dh(ctx, p, (int)pSz, g, (int)gSz);
        }
    }

    /* Dispose of the DER buffer. */
    FreeDer(&der);
    if (res != 1) {
        /* Free the allocated buffers if not assigned into SSL or context. */
        XFREE(p, heap, DYNAMIC_TYPE_PUBLIC_KEY);
        XFREE(g, heap, DYNAMIC_TYPE_PUBLIC_KEY);
    }
    return res;
}


/* Set the temporary DH parameters against the SSL.
 *
 * @param [in, out] ssl     SSL object.
 * @param [in]      buf     Buffer holding encoded DH parameters.
 * @param [in]      sz      Size of encoded DH parameters.
 * @param [in]      format  Format of data:
 *                            WOLFSSL_FILETYPE_PEM or WOLFSSL_FILETYPE_ASN1.
 * @return  1 on success.
 * @return  BAD_FUNC_ARG when ssl or buf is NULL.
 * @return  NOT_COMPLED_IN when format is PEM but PEM is not supported.
 * @return  WOLFSSL_BAD_FILETYPE if format is not supported.
 */
int wolfSSL_SetTmpDH_buffer(WOLFSSL* ssl, const unsigned char* buf, long sz,
    int format)
{
    return ws_ctx_ssl_set_tmp_dh(NULL, ssl, buf, sz, format);
}


/* Set the temporary DH parameters against the SSL context.
 *
 * @param [in, out] ctx     SSL context object.
 * @param [in]      buf     Buffer holding encoded DH parameters.
 * @param [in]      sz      Size of encoded DH parameters.
 * @param [in]      format  Format of data:
 *                            WOLFSSL_FILETYPE_PEM or WOLFSSL_FILETYPE_ASN1.
 * @return  1 on success.
 * @return  BAD_FUNC_ARG when ctx or buf is NULL.
 * @return  NOT_COMPLED_IN when format is PEM but PEM is not supported.
 * @return  WOLFSSL_BAD_FILETYPE if format is not supported.
 */
int wolfSSL_CTX_SetTmpDH_buffer(WOLFSSL_CTX* ctx, const unsigned char* buf,
    long sz, int format)
{
    return ws_ctx_ssl_set_tmp_dh(ctx, NULL, buf, sz, format);
}

#ifndef NO_FILESYSTEM

/* Set the temporary DH parameters file against the SSL context or SSL.
 *
 * @param [in, out] ctx     SSL context object.
 * @param [in, out] ssl     SSL object.
 * @param [in]      fname   Name of file to load.
 * @param [in]      format  Format of data:
 *                            WOLFSSL_FILETYPE_PEM or WOLFSSL_FILETYPE_ASN1.
 * @return  1 on success.
 * @return  BAD_FUNC_ARG when ctx and ssl NULL or fname is NULL.
 * @return  NOT_COMPLED_IN when format is PEM but PEM is not supported.
 * @return  WOLFSSL_BAD_FILETYPE if format is not supported.
 */
static int ws_ctx_ssl_set_tmp_dh_file(WOLFSSL_CTX* ctx, WOLFSSL* ssl,
    const char* fname, int format)
{
    int    res = 1;
    int    ret;
#ifndef WOLFSSL_SMALL_STACK
    byte   stackBuffer[FILE_BUFFER_SIZE];
#endif
    StaticBuffer dhFile;
    long   sz = 0;
    void*  heap = WOLFSSL_HEAP(ctx, ssl);

    /* Setup buffer to hold file contents. */
#ifdef WOLFSSL_SMALL_STACK
    static_buffer_init(&dhFile);
#else
    static_buffer_init(&dhFile, stackBuffer, FILE_BUFFER_SIZE);
#endif

    /* Validate parameters. */
    if (((ctx == NULL) && (ssl == NULL)) || (fname == NULL)) {
        res = BAD_FUNC_ARG;
    }

    if (res == 1) {
        /* Read file into static buffer. */
        ret = wolfssl_read_file_static(fname, &dhFile, heap, DYNAMIC_TYPE_FILE,
            &sz);
        if (ret != 0) {
            res = ret;
        }
    }
    if (res == 1) {
        if (ssl != NULL) {
            /* Set encoded DH parameters into SSL. */
            res = wolfSSL_SetTmpDH_buffer(ssl, dhFile.buffer, sz, format);
        }
        else {
            /* Set encoded DH parameters into SSL context. */
            res = wolfSSL_CTX_SetTmpDH_buffer(ctx, dhFile.buffer, sz, format);
        }
    }

    /* Dispose of any dynamically allocated data. */
    static_buffer_free(&dhFile, heap, DYNAMIC_TYPE_FILE);
    return res;
}

/* Set the temporary DH parameters file against the SSL.
 *
 * @param [in, out] ssl     SSL object.
 * @param [in]      fname   Name of file to load.
 * @param [in]      format  Format of data:
 *                            WOLFSSL_FILETYPE_PEM or WOLFSSL_FILETYPE_ASN1.
 * @return  1 on success.
 * @return  BAD_FUNC_ARG when ssl or fname is NULL.
 * @return  NOT_COMPLED_IN when format is PEM but PEM is not supported.
 * @return  WOLFSSL_BAD_FILETYPE if format is not supported.
 */
int wolfSSL_SetTmpDH_file(WOLFSSL* ssl, const char* fname, int format)
{
    return ws_ctx_ssl_set_tmp_dh_file(NULL, ssl, fname, format);
}


/* Set the temporary DH parameters file against the SSL context.
 *
 * @param [in, out] ctx     SSL context object.
 * @param [in]      fname   Name of file to load.
 * @param [in]      format  Format of data:
 *                            WOLFSSL_FILETYPE_PEM or WOLFSSL_FILETYPE_ASN1.
 * @return  1 on success.
 * @return  BAD_FUNC_ARG when ctx or fname is NULL.
 * @return  NOT_COMPLED_IN when format is PEM but PEM is not supported.
 * @return  WOLFSSL_BAD_FILETYPE if format is not supported.
 */
int wolfSSL_CTX_SetTmpDH_file(WOLFSSL_CTX* ctx, const char* fname, int format)
{
    return ws_ctx_ssl_set_tmp_dh_file(ctx, NULL, fname, format);
}

#endif /* NO_FILESYSTEM */

#endif /* NO_CERTS */

#endif /* !NO_DH */

#endif /* !WOLFSSL_SSL_LOAD_INCLUDED */

