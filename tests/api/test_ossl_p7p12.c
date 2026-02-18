/* test_ossl_p7p12.c
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

#include <tests/unit.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/openssl/pkcs7.h>
#include <wolfssl/openssl/pkcs12.h>
#include <wolfssl/openssl/pem.h>
#include <wolfssl/internal.h>
#include <tests/api/api.h>
#include <tests/api/test_ossl_p7p12.h>

int test_wolfssl_PKCS7(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && defined(HAVE_PKCS7) && !defined(NO_BIO) && \
    !defined(NO_RSA)
    PKCS7* pkcs7 = NULL;
    byte   data[FOURK_BUF];
    word32 len = sizeof(data);
    const byte*  p = data;
    byte   content[] = "Test data to encode.";
#if !defined(NO_RSA) & defined(USE_CERT_BUFFERS_2048)
    BIO*   bio = NULL;
    byte   key[sizeof(client_key_der_2048)];
    word32 keySz = (word32)sizeof(key);
    byte*  out = NULL;
#endif

    ExpectIntGT((len = (word32)CreatePKCS7SignedData(data, (int)len, content,
        (word32)sizeof(content), 0, 0, 0, RSA_TYPE)), 0);

    ExpectNull(pkcs7 = d2i_PKCS7(NULL, NULL, (int)len));
    ExpectNull(pkcs7 = d2i_PKCS7(NULL, &p, 0));
    ExpectNotNull(pkcs7 = d2i_PKCS7(NULL, &p, (int)len));
    ExpectIntEQ(wolfSSL_PKCS7_verify(NULL, NULL, NULL, NULL, NULL,
        PKCS7_NOVERIFY), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    PKCS7_free(pkcs7);
    pkcs7 = NULL;

    /* fail case, without PKCS7_NOVERIFY */
    p = data;
    ExpectNotNull(pkcs7 = d2i_PKCS7(NULL, &p, (int)len));
    ExpectIntEQ(wolfSSL_PKCS7_verify(pkcs7, NULL, NULL, NULL, NULL,
        0), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    PKCS7_free(pkcs7);
    pkcs7 = NULL;

    /* success case, with PKCS7_NOVERIFY */
    p = data;
    ExpectNotNull(pkcs7 = d2i_PKCS7(NULL, &p, (int)len));
    ExpectIntEQ(wolfSSL_PKCS7_verify(pkcs7, NULL, NULL, NULL, NULL,
        PKCS7_NOVERIFY), WOLFSSL_SUCCESS);

#if !defined(NO_RSA) & defined(USE_CERT_BUFFERS_2048)
    /* test i2d */
    XMEMCPY(key, client_key_der_2048, keySz);
    if (pkcs7 != NULL) {
        pkcs7->privateKey = key;
        pkcs7->privateKeySz = (word32)sizeof(key);
        pkcs7->encryptOID = RSAk;
    #ifdef NO_SHA
        pkcs7->hashOID = SHA256h;
    #else
        pkcs7->hashOID = SHAh;
    #endif
    }
    ExpectNotNull(bio = BIO_new(BIO_s_mem()));
    ExpectIntEQ(i2d_PKCS7_bio(bio, pkcs7), 1);
#ifndef NO_ASN_TIME
    ExpectIntEQ(i2d_PKCS7(pkcs7, &out), 655);
#else
    ExpectIntEQ(i2d_PKCS7(pkcs7, &out), 625);
#endif
    XFREE(out, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    BIO_free(bio);
#endif

    PKCS7_free(NULL);
    PKCS7_free(pkcs7);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_PKCS7_certs(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && !defined(NO_CERTS) && !defined(NO_BIO) && \
   !defined(NO_FILESYSTEM) && !defined(NO_RSA) && defined(HAVE_PKCS7)
    STACK_OF(X509)* sk = NULL;
    STACK_OF(X509_INFO)* info_sk = NULL;
    PKCS7 *p7 = NULL;
    BIO* bio = NULL;
    const byte* p = NULL;
    int buflen = 0;
    int i;

    /* Test twice. Once with d2i and once without to test
     * that everything is free'd correctly. */
    for (i = 0; i < 2; i++) {
        ExpectNotNull(p7 = PKCS7_new());
        if (p7 != NULL) {
            p7->version = 1;
        #ifdef NO_SHA
            p7->hashOID = SHA256h;
        #else
            p7->hashOID = SHAh;
        #endif
        }
        ExpectNotNull(bio = BIO_new(BIO_s_file()));
        ExpectIntGT(BIO_read_filename(bio, svrCertFile), 0);
        ExpectNotNull(info_sk = PEM_X509_INFO_read_bio(bio, NULL, NULL, NULL));
        ExpectIntEQ(sk_X509_INFO_num(info_sk), 2);
        ExpectNotNull(sk = sk_X509_new_null());
        while (EXPECT_SUCCESS() && (sk_X509_INFO_num(info_sk) > 0)) {
            X509_INFO* info = NULL;
            ExpectNotNull(info = sk_X509_INFO_shift(info_sk));
            if (EXPECT_SUCCESS() && info != NULL) {
                ExpectIntGT(sk_X509_push(sk, info->x509), 0);
                info->x509 = NULL;
            }
            X509_INFO_free(info);
        }
        sk_X509_INFO_pop_free(info_sk, X509_INFO_free);
        info_sk = NULL;
        BIO_free(bio);
        bio = NULL;
        ExpectNotNull(bio = BIO_new(BIO_s_mem()));
        ExpectIntEQ(wolfSSL_PKCS7_encode_certs(p7, sk, bio), 1);
        if ((sk != NULL) && ((p7 == NULL) || (bio == NULL))) {
            sk_X509_pop_free(sk, X509_free);
        }
        sk = NULL;
        ExpectIntGT((buflen = BIO_get_mem_data(bio, &p)), 0);

        if (i == 0) {
            PKCS7_free(p7);
            p7 = NULL;
            ExpectNotNull(d2i_PKCS7(&p7, &p, buflen));
            if (p7 != NULL) {
                /* Reset certs to force wolfSSL_PKCS7_to_stack to regenerate
                 * them */
                ((WOLFSSL_PKCS7*)p7)->certs = NULL;
            }
            /* PKCS7_free free's the certs */
            ExpectNotNull(wolfSSL_PKCS7_to_stack(p7));
        }

        BIO_free(bio);
        bio = NULL;
        PKCS7_free(p7);
        p7 = NULL;
    }
#endif /* defined(OPENSSL_ALL) && !defined(NO_CERTS) && \
         !defined(NO_FILESYSTEM) && !defined(NO_RSA) && defined(HAVE_PKCS7) */
    return EXPECT_RESULT();
}

int test_wolfSSL_PKCS7_sign(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && defined(HAVE_PKCS7) && !defined(NO_BIO) && \
    !defined(NO_FILESYSTEM) && !defined(NO_RSA)

    PKCS7* p7 = NULL;
    PKCS7* p7Ver = NULL;
    byte* out = NULL;
    byte* tmpPtr = NULL;
    int outLen = 0;
    int flags = 0;
    byte data[] = "Test data to encode.";

    const char* cert = "./certs/server-cert.pem";
    const char* key  = "./certs/server-key.pem";
    const char* ca   = "./certs/ca-cert.pem";

    WOLFSSL_BIO* certBio = NULL;
    WOLFSSL_BIO* keyBio = NULL;
    WOLFSSL_BIO* caBio = NULL;
    WOLFSSL_BIO* inBio = NULL;
    X509* signCert = NULL;
    EVP_PKEY* signKey = NULL;
    X509* caCert = NULL;
    X509_STORE* store = NULL;
#ifndef NO_PKCS7_STREAM
    int z;
    int ret;
#endif /* !NO_PKCS7_STREAM */

    /* read signer cert/key into BIO */
    ExpectNotNull(certBio = BIO_new_file(cert, "r"));
    ExpectNotNull(keyBio = BIO_new_file(key, "r"));
    ExpectNotNull(signCert = PEM_read_bio_X509(certBio, NULL, 0, NULL));
    ExpectNotNull(signKey = PEM_read_bio_PrivateKey(keyBio, NULL, 0, NULL));

    /* read CA cert into store (for verify) */
    ExpectNotNull(caBio = BIO_new_file(ca, "r"));
    ExpectNotNull(caCert = PEM_read_bio_X509(caBio, NULL, 0, NULL));
    ExpectNotNull(store = X509_STORE_new());
    ExpectIntEQ(X509_STORE_add_cert(store, caCert), 1);

    /* data to be signed into BIO */
    ExpectNotNull(inBio = BIO_new(BIO_s_mem()));
    ExpectIntGT(BIO_write(inBio, data, sizeof(data)), 0);

    /* PKCS7_sign, bad args: signer NULL */
    ExpectNull(p7 = PKCS7_sign(NULL, signKey, NULL, inBio, 0));
    /* PKCS7_sign, bad args: signer key NULL */
    ExpectNull(p7 = PKCS7_sign(signCert, NULL, NULL, inBio, 0));
    /* PKCS7_sign, bad args: in data NULL without PKCS7_STREAM */
    ExpectNull(p7 = PKCS7_sign(signCert, signKey, NULL, NULL, 0));
    /* PKCS7_sign, bad args: PKCS7_NOCERTS flag not supported */
    ExpectNull(p7 = PKCS7_sign(signCert, signKey, NULL, inBio, PKCS7_NOCERTS));
    /* PKCS7_sign, bad args: PKCS7_PARTIAL flag not supported */
    ExpectNull(p7 = PKCS7_sign(signCert, signKey, NULL, inBio, PKCS7_PARTIAL));

    /* TEST SUCCESS: Not detached, not streaming, not MIME */
    {
        flags = PKCS7_BINARY;
        ExpectNotNull(p7 = PKCS7_sign(signCert, signKey, NULL, inBio, flags));
        ExpectIntGT((outLen = i2d_PKCS7(p7, &out)), 0);

        /* verify with d2i_PKCS7 */
        tmpPtr = out;
        ExpectNotNull(p7Ver = d2i_PKCS7(NULL, (const byte**)&tmpPtr, outLen));
        ExpectIntEQ(PKCS7_verify(p7Ver, NULL, store, NULL, NULL, flags), 1);
        PKCS7_free(p7Ver);
        p7Ver = NULL;

        /* verify with wc_PKCS7_VerifySignedData */
        ExpectNotNull(p7Ver = wc_PKCS7_New(HEAP_HINT, testDevId));
        ExpectIntEQ(wc_PKCS7_Init(p7Ver, HEAP_HINT, INVALID_DEVID), 0);
        ExpectIntEQ(wc_PKCS7_VerifySignedData(p7Ver, out, (word32)outLen), 0);

    #ifndef NO_PKCS7_STREAM
        /* verify with wc_PKCS7_VerifySignedData streaming */
        wc_PKCS7_Free(p7Ver);
        p7Ver = NULL;
        ExpectNotNull(p7Ver = wc_PKCS7_New(HEAP_HINT, testDevId));
        ExpectIntEQ(wc_PKCS7_Init(p7Ver, HEAP_HINT, INVALID_DEVID), 0);
        /* test for streaming */
        ret = -1;
        for (z = 0; z < outLen && ret != 0; z++) {
            ret = wc_PKCS7_VerifySignedData(p7Ver, out + z, 1);
            if (ret < 0){
                ExpectIntEQ(ret, WC_NO_ERR_TRACE(WC_PKCS7_WANT_READ_E));
            }
        }
        ExpectIntEQ(ret, 0);
    #endif /* !NO_PKCS7_STREAM */

        /* compare the signer found to expected signer */
        ExpectIntNE(p7Ver->verifyCertSz, 0);
        tmpPtr = NULL;
        ExpectIntEQ(i2d_X509(signCert, &tmpPtr), p7Ver->verifyCertSz);
        ExpectIntEQ(XMEMCMP(tmpPtr, p7Ver->verifyCert, p7Ver->verifyCertSz), 0);
        XFREE(tmpPtr, NULL, DYNAMIC_TYPE_OPENSSL);
        tmpPtr = NULL;

        wc_PKCS7_Free(p7Ver);
        p7Ver = NULL;

        ExpectNotNull(out);
        XFREE(out, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        out = NULL;
        PKCS7_free(p7);
        p7 = NULL;
    }

    /* TEST SUCCESS: Not detached, streaming, not MIME. Also bad arg
     * tests for PKCS7_final() while we have a PKCS7 pointer to use */
    {
        /* re-populate input BIO, may have been consumed */
        BIO_free(inBio);
        inBio = NULL;
        ExpectNotNull(inBio = BIO_new(BIO_s_mem()));
        ExpectIntGT(BIO_write(inBio, data, sizeof(data)), 0);

        flags = PKCS7_BINARY | PKCS7_STREAM;
        ExpectNotNull(p7 = PKCS7_sign(signCert, signKey, NULL, inBio, flags));
        ExpectIntEQ(PKCS7_final(p7, inBio, flags), 1);
        ExpectIntGT((outLen = i2d_PKCS7(p7, &out)), 0);

        /* PKCS7_final, bad args: PKCS7 null */
        ExpectIntEQ(PKCS7_final(NULL, inBio, 0), 0);
        /* PKCS7_final, bad args: PKCS7 null */
        ExpectIntEQ(PKCS7_final(p7, NULL, 0), 0);

        tmpPtr = out;
        ExpectNotNull(p7Ver = d2i_PKCS7(NULL, (const byte**)&tmpPtr, outLen));
        ExpectIntEQ(PKCS7_verify(p7Ver, NULL, store, NULL, NULL, flags), 1);
        PKCS7_free(p7Ver);
        p7Ver = NULL;

        ExpectNotNull(out);
        XFREE(out, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        out = NULL;
        PKCS7_free(p7);
        p7 = NULL;
    }

    /* TEST SUCCESS: Detached, not streaming, not MIME */
    {
        /* re-populate input BIO, may have been consumed */
        BIO_free(inBio);
        inBio = NULL;
        ExpectNotNull(inBio = BIO_new(BIO_s_mem()));
        ExpectIntGT(BIO_write(inBio, data, sizeof(data)), 0);

        flags = PKCS7_BINARY | PKCS7_DETACHED;
        ExpectNotNull(p7 = PKCS7_sign(signCert, signKey, NULL, inBio, flags));
        ExpectIntGT((outLen = i2d_PKCS7(p7, &out)), 0);
        ExpectNotNull(out);

        /* verify with wolfCrypt, d2i_PKCS7 does not support detached content */
        ExpectNotNull(p7Ver = wc_PKCS7_New(HEAP_HINT, testDevId));
        if (p7Ver != NULL) {
            p7Ver->content = data;
            p7Ver->contentSz = sizeof(data);
        }
        ExpectIntEQ(wc_PKCS7_VerifySignedData(p7Ver, out, (word32)outLen), 0);
        wc_PKCS7_Free(p7Ver);
        p7Ver = NULL;

    #ifndef NO_PKCS7_STREAM
        /* verify with wc_PKCS7_VerifySignedData streaming */
        ExpectNotNull(p7Ver = wc_PKCS7_New(HEAP_HINT, testDevId));
        if (p7Ver != NULL) {
            p7Ver->content = data;
            p7Ver->contentSz = sizeof(data);
        }
        /* test for streaming */
        if (EXPECT_SUCCESS()) {
            ret = -1;
            for (z = 0; z < outLen && ret != 0; z++) {
                ret = wc_PKCS7_VerifySignedData(p7Ver, out + z, 1);
                if (ret < 0){
                    ExpectIntEQ(ret, WC_NO_ERR_TRACE(WC_PKCS7_WANT_READ_E));
                }
            }
            ExpectIntEQ(ret, 0);
        }
        wc_PKCS7_Free(p7Ver);
        p7Ver = NULL;
    #endif /* !NO_PKCS7_STREAM */

        /* verify expected failure (NULL return) from d2i_PKCS7, it does not
         * yet support detached content */
        tmpPtr = out;
        ExpectNull(p7Ver = d2i_PKCS7(NULL, (const byte**)&tmpPtr, outLen));
        PKCS7_free(p7Ver);
        p7Ver = NULL;

        XFREE(out, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        out = NULL;
        PKCS7_free(p7);
        p7 = NULL;
    }

    /* TEST SUCCESS: Detached, streaming, not MIME */
    {
        /* re-populate input BIO, may have been consumed */
        BIO_free(inBio);
        inBio = NULL;
        ExpectNotNull(inBio = BIO_new(BIO_s_mem()));
        ExpectIntGT(BIO_write(inBio, data, sizeof(data)), 0);

        flags = PKCS7_BINARY | PKCS7_DETACHED | PKCS7_STREAM;
        ExpectNotNull(p7 = PKCS7_sign(signCert, signKey, NULL, inBio, flags));
        ExpectIntEQ(PKCS7_final(p7, inBio, flags), 1);
        ExpectIntGT((outLen = i2d_PKCS7(p7, &out)), 0);

        /* verify with wolfCrypt, d2i_PKCS7 does not support detached content */
        ExpectNotNull(p7Ver = wc_PKCS7_New(HEAP_HINT, testDevId));
        if (p7Ver != NULL) {
            p7Ver->content = data;
            p7Ver->contentSz = sizeof(data);
        }
        ExpectIntEQ(wc_PKCS7_VerifySignedData(p7Ver, out, (word32)outLen), 0);
        wc_PKCS7_Free(p7Ver);
        p7Ver = NULL;

        ExpectNotNull(out);

    #ifndef NO_PKCS7_STREAM
        /* verify with wc_PKCS7_VerifySignedData streaming */
        ExpectNotNull(p7Ver = wc_PKCS7_New(HEAP_HINT, testDevId));
        if (p7Ver != NULL) {
            p7Ver->content = data;
            p7Ver->contentSz = sizeof(data);
        }
        /* test for streaming */
        if (EXPECT_SUCCESS()) {
            ret = -1;
            for (z = 0; z < outLen && ret != 0; z++) {
                ret = wc_PKCS7_VerifySignedData(p7Ver, out + z, 1);
                if (ret < 0){
                    ExpectIntEQ(ret, WC_NO_ERR_TRACE(WC_PKCS7_WANT_READ_E));
                }
            }
            ExpectIntEQ(ret, 0);
        }
        wc_PKCS7_Free(p7Ver);
        p7Ver = NULL;
    #endif /* !NO_PKCS7_STREAM */

        XFREE(out, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        PKCS7_free(p7);
        p7 = NULL;
    }

    X509_STORE_free(store);
    X509_free(caCert);
    X509_free(signCert);
    EVP_PKEY_free(signKey);
    BIO_free(inBio);
    BIO_free(keyBio);
    BIO_free(certBio);
    BIO_free(caBio);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_PKCS7_SIGNED_new(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && defined(HAVE_PKCS7)
    PKCS7_SIGNED* pkcs7 = NULL;

    ExpectNotNull(pkcs7 = PKCS7_SIGNED_new());
    ExpectIntEQ(pkcs7->contentOID, SIGNED_DATA);

    PKCS7_SIGNED_free(pkcs7);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_PEM_write_bio_PKCS7(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && defined(HAVE_PKCS7) && !defined(NO_FILESYSTEM) && \
    !defined(NO_BIO)
    PKCS7* pkcs7 = NULL;
    BIO* bio = NULL;
    const byte* cert_buf = NULL;
    int ret = 0;
    WC_RNG rng;
    const byte data[] = { /* Hello World */
        0x48,0x65,0x6c,0x6c,0x6f,0x20,0x57,0x6f,
        0x72,0x6c,0x64
    };
#ifndef NO_RSA
    #if defined(USE_CERT_BUFFERS_2048)
        byte        key[sizeof(client_key_der_2048)];
        byte        cert[sizeof(client_cert_der_2048)];
        word32      keySz = (word32)sizeof(key);
        word32      certSz = (word32)sizeof(cert);
        XMEMSET(key, 0, keySz);
        XMEMSET(cert, 0, certSz);
        XMEMCPY(key, client_key_der_2048, keySz);
        XMEMCPY(cert, client_cert_der_2048, certSz);
    #elif defined(USE_CERT_BUFFERS_1024)
        byte        key[sizeof_client_key_der_1024];
        byte        cert[sizeof(sizeof_client_cert_der_1024)];
        word32      keySz = (word32)sizeof(key);
        word32      certSz = (word32)sizeof(cert);
        XMEMSET(key, 0, keySz);
        XMEMSET(cert, 0, certSz);
        XMEMCPY(key, client_key_der_1024, keySz);
        XMEMCPY(cert, client_cert_der_1024, certSz);
    #else
        unsigned char   cert[ONEK_BUF];
        unsigned char   key[ONEK_BUF];
        XFILE           fp = XBADFILE;
        int             certSz;
        int             keySz;

        ExpectTrue((fp = XFOPEN("./certs/1024/client-cert.der", "rb")) !=
            XBADFILE);
        ExpectIntGT(certSz = (int)XFREAD(cert, 1, sizeof_client_cert_der_1024,
            fp), 0);
        if (fp != XBADFILE) {
            XFCLOSE(fp);
            fp = XBADFILE;
        }

        ExpectTrue((fp = XFOPEN("./certs/1024/client-key.der", "rb")) !=
            XBADFILE);
        ExpectIntGT(keySz = (int)XFREAD(key, 1, sizeof_client_key_der_1024, fp),
            0);
        if (fp != XBADFILE) {
            XFCLOSE(fp);
            fp = XBADFILE;
        }
    #endif
#elif defined(HAVE_ECC)
    #if defined(USE_CERT_BUFFERS_256)
        unsigned char    cert[sizeof(cliecc_cert_der_256)];
        unsigned char    key[sizeof(ecc_clikey_der_256)];
        int              certSz = (int)sizeof(cert);
        int              keySz = (int)sizeof(key);
        XMEMSET(cert, 0, certSz);
        XMEMSET(key, 0, keySz);
        XMEMCPY(cert, cliecc_cert_der_256, sizeof_cliecc_cert_der_256);
        XMEMCPY(key, ecc_clikey_der_256, sizeof_ecc_clikey_der_256);
    #else
        unsigned char   cert[ONEK_BUF];
        unsigned char   key[ONEK_BUF];
        XFILE           fp = XBADFILE;
        int             certSz, keySz;

        ExpectTrue((fp = XFOPEN("./certs/client-ecc-cert.der", "rb")) !=
            XBADFILE);
        ExpectIntGT(certSz = (int)XFREAD(cert, 1, sizeof_cliecc_cert_der_256,
            fp), 0);
        if (fp != XBADFILE) {
            XFCLOSE(fp);
            fp = XBADFILE;
        }

        ExpectTrue((fp = XFOPEN("./certs/client-ecc-key.der", "rb")) !=
            XBADFILE);
        ExpectIntGT(keySz = (int)XFREAD(key, 1, sizeof_ecc_clikey_der_256, fp),
            0);
        if (fp != XBADFILE) {
            XFCLOSE(fp);
            fp = XBADFILE;
        }
    #endif
#else
    #error PKCS7 requires ECC or RSA
#endif

    ExpectNotNull(pkcs7 = wc_PKCS7_New(HEAP_HINT, testDevId));
    /* initialize with DER encoded cert */
    ExpectIntEQ(wc_PKCS7_InitWithCert(pkcs7, (byte*)cert, (word32)certSz), 0);

    /* init rng */
    XMEMSET(&rng, 0, sizeof(WC_RNG));
    ExpectIntEQ(wc_InitRng(&rng), 0);

    if (pkcs7 != NULL) {
        pkcs7->rng = &rng;
        pkcs7->content   = (byte*)data; /* not used for ex */
        pkcs7->contentSz = (word32)sizeof(data);
        pkcs7->contentOID = SIGNED_DATA;
        pkcs7->privateKey = key;
        pkcs7->privateKeySz = (word32)sizeof(key);
        pkcs7->encryptOID = RSAk;
    #ifdef NO_SHA
        pkcs7->hashOID = SHA256h;
    #else
        pkcs7->hashOID = SHAh;
    #endif
        pkcs7->signedAttribs   = NULL;
        pkcs7->signedAttribsSz = 0;
    }

    ExpectNotNull(bio = BIO_new(BIO_s_mem()));
    /* Write PKCS#7 PEM to BIO, the function converts the DER to PEM cert*/
    ExpectIntEQ(PEM_write_bio_PKCS7(bio, pkcs7), WOLFSSL_SUCCESS);

    /* Read PKCS#7 PEM from BIO */
    ret = wolfSSL_BIO_get_mem_data(bio, &cert_buf);
    ExpectIntGE(ret, 0);

    BIO_free(bio);
    wc_PKCS7_Free(pkcs7);
    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_PEM_write_bio_encryptedKey(void)
{
    EXPECT_DECLS;
#if (defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL)) && \
    defined(WOLFSSL_KEY_GEN) && !defined(NO_RSA) && \
    defined(WOLFSSL_ENCRYPTED_KEYS) && \
    (defined(WOLFSSL_PEM_TO_DER) || defined(WOLFSSL_DER_TO_PEM)) && \
    !defined(NO_FILESYSTEM) && !defined(NO_BIO) && !defined(NO_CERTS) && \
    !defined(NO_DES3)
    RSA* rsaKey = NULL;
    RSA* retKey = NULL;
    const EVP_CIPHER *cipher = NULL;
    BIO* bio = NULL;
    BIO* retbio = NULL;
    byte* out;
    const char* password = "wolfssl";
    word32 passwordSz =(word32)XSTRLEN((char*)password);
    int membufSz = 0;

#if defined(USE_CERT_BUFFERS_2048)
    const byte* key = client_key_der_2048;
    word32      keySz = sizeof_client_key_der_2048;
#elif defined(USE_CERT_BUFFERS_1024)
    const byte* key = client_key_der_1024;
    word32      keySz = sizeof_client_key_der_1024;
#endif
    /* Import Rsa Key */
    ExpectNotNull(rsaKey = wolfSSL_RSA_new());
    ExpectIntEQ(wolfSSL_RSA_LoadDer_ex(rsaKey, key, keySz,
                                        WOLFSSL_RSA_LOAD_PRIVATE), 1);

    ExpectNotNull(cipher = EVP_des_ede3_cbc());
    ExpectNotNull(bio = BIO_new(BIO_s_mem()));
    ExpectIntEQ(PEM_write_bio_RSAPrivateKey(bio, rsaKey, cipher,
                                (byte*)password, passwordSz, NULL, NULL), 1);
    ExpectIntGT((membufSz = BIO_get_mem_data(bio, &out)), 0);
    ExpectNotNull(retbio = BIO_new_mem_buf(out, membufSz));
    ExpectNotNull((retKey = PEM_read_bio_RSAPrivateKey(retbio, NULL,
                                NULL, (void*)password)));
    if (bio != NULL) {
        BIO_free(bio);
    }
    if (retbio != NULL) {
        BIO_free(retbio);
    }
    if (retKey != NULL) {
        RSA_free(retKey);
    }
    if (rsaKey != NULL) {
        RSA_free(rsaKey);
    }
#endif
    return EXPECT_RESULT();
}

/* // NOLINTBEGIN(clang-analyzer-unix.Stream) */
int test_wolfSSL_SMIME_read_PKCS7(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && defined(HAVE_PKCS7) && !defined(NO_FILESYSTEM) && \
    !defined(NO_RSA) && !defined(NO_BIO) && defined(HAVE_SMIME)
    PKCS7* pkcs7 = NULL;
    BIO* bio = NULL;
    BIO* bcont = NULL;
    BIO* out = NULL;
    const byte* outBuf = NULL;
    int outBufLen = 0;
    static const char contTypeText[] = "Content-Type: text/plain\r\n\r\n";
    XFILE smimeTestFile = XBADFILE;

    ExpectTrue((smimeTestFile = XFOPEN("./certs/test/smime-test.p7s", "rb")) !=
        XBADFILE);

    /* smime-test.p7s */
    bio = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
    ExpectNotNull(bio);
    ExpectIntEQ(wolfSSL_BIO_set_fp(bio, smimeTestFile, BIO_CLOSE), SSL_SUCCESS);
    pkcs7 = wolfSSL_SMIME_read_PKCS7(bio, &bcont);
    ExpectNotNull(pkcs7);
    ExpectIntEQ(wolfSSL_PKCS7_verify(pkcs7, NULL, NULL, bcont, NULL,
        PKCS7_NOVERIFY), SSL_SUCCESS);
    if (smimeTestFile != XBADFILE) {
        XFCLOSE(smimeTestFile);
        smimeTestFile = XBADFILE;
    }
    if (bcont) BIO_free(bcont);
    bcont = NULL;
    wolfSSL_PKCS7_free(pkcs7);
    pkcs7 = NULL;

    /* smime-test-multipart.p7s */
    smimeTestFile = XFOPEN("./certs/test/smime-test-multipart.p7s", "rb");
    ExpectFalse(smimeTestFile == XBADFILE);
    ExpectIntEQ(wolfSSL_BIO_set_fp(bio, smimeTestFile, BIO_CLOSE), SSL_SUCCESS);
    pkcs7 = wolfSSL_SMIME_read_PKCS7(bio, &bcont);
    ExpectNotNull(pkcs7);
    ExpectIntEQ(wolfSSL_PKCS7_verify(pkcs7, NULL, NULL, bcont, NULL,
        PKCS7_NOVERIFY), SSL_SUCCESS);
    if (smimeTestFile != XBADFILE) {
        XFCLOSE(smimeTestFile);
        smimeTestFile = XBADFILE;
    }
    if (bcont) BIO_free(bcont);
    bcont = NULL;
    wolfSSL_PKCS7_free(pkcs7);
    pkcs7 = NULL;

    /* smime-test-multipart-badsig.p7s */
    smimeTestFile = XFOPEN("./certs/test/smime-test-multipart-badsig.p7s",
        "rb");
    ExpectFalse(smimeTestFile == XBADFILE);
    ExpectIntEQ(wolfSSL_BIO_set_fp(bio, smimeTestFile, BIO_CLOSE), SSL_SUCCESS);
    pkcs7 = wolfSSL_SMIME_read_PKCS7(bio, &bcont);
    ExpectNotNull(pkcs7); /* can read in the unverified smime bundle */
    ExpectIntEQ(wolfSSL_PKCS7_verify(pkcs7, NULL, NULL, bcont, NULL,
        PKCS7_NOVERIFY), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    if (smimeTestFile != XBADFILE) {
        XFCLOSE(smimeTestFile);
        smimeTestFile = XBADFILE;
    }
    if (bcont) BIO_free(bcont);
    bcont = NULL;
    wolfSSL_PKCS7_free(pkcs7);
    pkcs7 = NULL;

    /* smime-test-canon.p7s */
    smimeTestFile = XFOPEN("./certs/test/smime-test-canon.p7s", "rb");
    ExpectFalse(smimeTestFile == XBADFILE);
    ExpectIntEQ(wolfSSL_BIO_set_fp(bio, smimeTestFile, BIO_CLOSE), SSL_SUCCESS);
    pkcs7 = wolfSSL_SMIME_read_PKCS7(bio, &bcont);
    ExpectNotNull(pkcs7);
    ExpectIntEQ(wolfSSL_PKCS7_verify(pkcs7, NULL, NULL, bcont, NULL,
        PKCS7_NOVERIFY), SSL_SUCCESS);
    if (smimeTestFile != XBADFILE) {
        XFCLOSE(smimeTestFile);
        smimeTestFile = XBADFILE;
    }
    if (bcont) BIO_free(bcont);
   bcont = NULL;
    wolfSSL_PKCS7_free(pkcs7);
    pkcs7 = NULL;

    /* Test PKCS7_TEXT, PKCS7_verify() should remove Content-Type: text/plain */
    smimeTestFile = XFOPEN("./certs/test/smime-test-canon.p7s", "rb");
    ExpectFalse(smimeTestFile == XBADFILE);
    ExpectIntEQ(wolfSSL_BIO_set_fp(bio, smimeTestFile, BIO_CLOSE), SSL_SUCCESS);
    pkcs7 = wolfSSL_SMIME_read_PKCS7(bio, &bcont);
    ExpectNotNull(pkcs7);
    out = wolfSSL_BIO_new(BIO_s_mem());
    ExpectNotNull(out);
    ExpectIntEQ(wolfSSL_PKCS7_verify(pkcs7, NULL, NULL, bcont, out,
        PKCS7_NOVERIFY | PKCS7_TEXT), SSL_SUCCESS);
    ExpectIntGT((outBufLen = BIO_get_mem_data(out, &outBuf)), 0);
    /* Content-Type should not show up at beginning of output buffer */
    ExpectIntGT(outBufLen, XSTRLEN(contTypeText));
    ExpectIntGT(XMEMCMP(outBuf, contTypeText, XSTRLEN(contTypeText)), 0);

    BIO_free(out);
    BIO_free(bio);
    if (bcont) BIO_free(bcont);
    wolfSSL_PKCS7_free(pkcs7);
#endif
    return EXPECT_RESULT();
}
/* // NOLINTEND(clang-analyzer-unix.Stream) */

int test_wolfSSL_SMIME_write_PKCS7(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && defined(HAVE_PKCS7) && !defined(NO_RSA) && \
    !defined(NO_BIO) && defined(HAVE_SMIME)
    PKCS7* p7 = NULL;
    PKCS7* p7Ver = NULL;
    int flags = 0;
    byte data[] = "Test data to encode.";

    const char* cert = "./certs/server-cert.pem";
    const char* key  = "./certs/server-key.pem";
    const char* ca   = "./certs/ca-cert.pem";

    WOLFSSL_BIO* certBio = NULL;
    WOLFSSL_BIO* keyBio  = NULL;
    WOLFSSL_BIO* caBio   = NULL;
    WOLFSSL_BIO* inBio   = NULL;
    WOLFSSL_BIO* outBio  = NULL;
    WOLFSSL_BIO* content = NULL;
    X509* signCert = NULL;
    EVP_PKEY* signKey = NULL;
    X509* caCert = NULL;
    X509_STORE* store = NULL;

    /* read signer cert/key into BIO */
    ExpectNotNull(certBio = BIO_new_file(cert, "r"));
    ExpectNotNull(keyBio = BIO_new_file(key, "r"));
    ExpectNotNull(signCert = PEM_read_bio_X509(certBio, NULL, 0, NULL));
    ExpectNotNull(signKey = PEM_read_bio_PrivateKey(keyBio, NULL, 0, NULL));

    /* read CA cert into store (for verify) */
    ExpectNotNull(caBio = BIO_new_file(ca, "r"));
    ExpectNotNull(caCert = PEM_read_bio_X509(caBio, NULL, 0, NULL));
    ExpectNotNull(store = X509_STORE_new());
    ExpectIntEQ(X509_STORE_add_cert(store, caCert), 1);


    /* generate and verify SMIME: not detached */
    {
        ExpectNotNull(inBio = BIO_new(BIO_s_mem()));
        ExpectIntGT(BIO_write(inBio, data, sizeof(data)), 0);

        flags = PKCS7_STREAM;
        ExpectNotNull(p7 = PKCS7_sign(signCert, signKey, NULL, inBio, flags));
        ExpectNotNull(outBio = BIO_new(BIO_s_mem()));
        ExpectIntEQ(SMIME_write_PKCS7(outBio, p7, inBio, flags), 1);

        /* bad arg: out NULL */
        ExpectIntEQ(SMIME_write_PKCS7(NULL, p7, inBio, flags), 0);
        /* bad arg: pkcs7 NULL */
        ExpectIntEQ(SMIME_write_PKCS7(outBio, NULL, inBio, flags), 0);

        ExpectNotNull(p7Ver = SMIME_read_PKCS7(outBio, &content));
        ExpectIntEQ(PKCS7_verify(p7Ver, NULL, store, NULL, NULL, flags), 1);

        BIO_free(content);
        content = NULL;
        BIO_free(inBio);
        inBio = NULL;
        BIO_free(outBio);
        outBio = NULL;
        PKCS7_free(p7Ver);
        p7Ver = NULL;
        PKCS7_free(p7);
        p7 = NULL;
    }

    /* generate and verify SMIME: not detached, add Content-Type */
    {
        ExpectNotNull(inBio = BIO_new(BIO_s_mem()));
        ExpectIntGT(BIO_write(inBio, data, sizeof(data)), 0);

        flags = PKCS7_STREAM | PKCS7_TEXT;
        ExpectNotNull(p7 = PKCS7_sign(signCert, signKey, NULL, inBio, flags));
        ExpectNotNull(outBio = BIO_new(BIO_s_mem()));
        ExpectIntEQ(SMIME_write_PKCS7(outBio, p7, inBio, flags), 1);

        ExpectNotNull(p7Ver = SMIME_read_PKCS7(outBio, &content));
        ExpectIntEQ(PKCS7_verify(p7Ver, NULL, store, NULL, NULL, flags), 1);

        BIO_free(content);
        content = NULL;
        BIO_free(inBio);
        inBio = NULL;
        BIO_free(outBio);
        outBio = NULL;
        PKCS7_free(p7Ver);
        p7Ver = NULL;
        PKCS7_free(p7);
        p7 = NULL;
    }

    /* generate and verify SMIME: detached */
    {
        ExpectNotNull(inBio = BIO_new(BIO_s_mem()));
        ExpectIntGT(BIO_write(inBio, data, sizeof(data)), 0);

        flags = PKCS7_DETACHED | PKCS7_STREAM;
        ExpectNotNull(p7 = PKCS7_sign(signCert, signKey, NULL, inBio, flags));
        ExpectNotNull(outBio = BIO_new(BIO_s_mem()));
        ExpectIntEQ(SMIME_write_PKCS7(outBio, p7, inBio, flags), 1);

        ExpectNotNull(p7Ver = SMIME_read_PKCS7(outBio, &content));
        ExpectIntEQ(PKCS7_verify(p7Ver, NULL, store, content, NULL, flags), 1);

        BIO_free(content);
        content = NULL;
        BIO_free(inBio);
        inBio = NULL;
        BIO_free(outBio);
        outBio = NULL;
        PKCS7_free(p7Ver);
        p7Ver = NULL;
        PKCS7_free(p7);
        p7 = NULL;
    }

    /* generate and verify SMIME: PKCS7_TEXT to add Content-Type header */
    {
        ExpectNotNull(inBio = BIO_new(BIO_s_mem()));
        ExpectIntGT(BIO_write(inBio, data, sizeof(data)), 0);

        flags = PKCS7_STREAM | PKCS7_DETACHED | PKCS7_TEXT;
        ExpectNotNull(p7 = PKCS7_sign(signCert, signKey, NULL, inBio, flags));
        ExpectNotNull(outBio = BIO_new(BIO_s_mem()));
        ExpectIntEQ(SMIME_write_PKCS7(outBio, p7, inBio, flags), 1);

        ExpectNotNull(p7Ver = SMIME_read_PKCS7(outBio, &content));
        ExpectIntEQ(PKCS7_verify(p7Ver, NULL, store, content, NULL, flags), 1);

        BIO_free(content);
        content = NULL;
        BIO_free(inBio);
        inBio = NULL;
        BIO_free(outBio);
        outBio = NULL;
        PKCS7_free(p7Ver);
        p7Ver = NULL;
        PKCS7_free(p7);
        p7 = NULL;
    }

    X509_STORE_free(store);
    X509_free(caCert);
    X509_free(signCert);
    EVP_PKEY_free(signKey);
    BIO_free(keyBio);
    BIO_free(certBio);
    BIO_free(caBio);
#endif
    return EXPECT_RESULT();
}

/* Testing functions dealing with PKCS12 parsing out X509 certs */
int test_wolfSSL_PKCS12(void)
{
    EXPECT_DECLS;
    /* .p12 file is encrypted with DES3 */
#ifndef HAVE_FIPS /* Password used in cert "wolfSSL test" is only 12-bytes
                   * (96-bit) FIPS mode requires Minimum of 14-byte (112-bit)
                   * Password Key
                   */
#if defined(OPENSSL_EXTRA) && !defined(NO_DES3) && !defined(NO_FILESYSTEM) && \
    !defined(NO_STDIO_FILESYSTEM) && !defined(NO_TLS) && \
    !defined(NO_ASN) && !defined(NO_PWDBASED) && !defined(NO_RSA) && \
    !defined(NO_SHA) && defined(HAVE_PKCS12) && !defined(NO_BIO) && \
    defined(WOLFSSL_AES_256)
    byte buf[6000];
    char file[] = "./certs/test-servercert.p12";
    char order[] = "./certs/ecc-rsa-server.p12";
#ifdef WC_RC2
    char rc2p12[] = "./certs/test-servercert-rc2.p12";
#endif
    char pass[] = "a password";
    const char goodPsw[] = "wolfSSL test";
    const char badPsw[] = "bad";
#ifdef HAVE_ECC
    WOLFSSL_X509_NAME *subject = NULL;
    WOLFSSL_X509      *x509 = NULL;
#endif
    XFILE f = XBADFILE;
    int  bytes = 0, ret = 0, goodPswLen = 0, badPswLen = 0;
    WOLFSSL_BIO      *bio = NULL;
    WOLFSSL_EVP_PKEY *pkey = NULL;
    WC_PKCS12        *pkcs12 = NULL;
    WC_PKCS12        *pkcs12_2 = NULL;
    WOLFSSL_X509     *cert = NULL;
    WOLFSSL_X509     *tmp = NULL;
    WOLF_STACK_OF(WOLFSSL_X509) *ca = NULL;
#if (defined(OPENSSL_ALL) || defined(WOLFSSL_ASIO) || defined(WOLFSSL_HAPROXY) \
    || defined(WOLFSSL_NGINX)) && defined(SESSION_CERTS)
    WOLFSSL_CTX      *ctx = NULL;
    WOLFSSL          *ssl = NULL;
    WOLF_STACK_OF(WOLFSSL_X509) *tmp_ca = NULL;
#endif

    ExpectTrue((f = XFOPEN(file, "rb")) != XBADFILE);
    ExpectIntGT(bytes = (int)XFREAD(buf, 1, sizeof(buf), f), 0);
    if (f != XBADFILE) {
        XFCLOSE(f);
        f = XBADFILE;
    }

    goodPswLen = (int)XSTRLEN(goodPsw);
    badPswLen = (int)XSTRLEN(badPsw);

    ExpectNotNull(bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem()));

    ExpectIntEQ(BIO_write(bio, buf, bytes), bytes); /* d2i consumes BIO */
    ExpectNotNull(d2i_PKCS12_bio(bio, &pkcs12));
    ExpectNotNull(pkcs12);
    BIO_free(bio);
    bio = NULL;

    /* check verify MAC directly */
    ExpectIntEQ(ret = PKCS12_verify_mac(pkcs12, goodPsw, goodPswLen), 1);

    /* check verify MAC fail case directly */
    ExpectIntEQ(ret = PKCS12_verify_mac(pkcs12, badPsw, badPswLen), 0);

    /* check verify MAC fail case */
    ExpectIntEQ(ret = PKCS12_parse(pkcs12, "bad", &pkey, &cert, NULL), 0);
    ExpectNull(pkey);
    ExpectNull(cert);

    /* check parse with no extra certs kept */
    ExpectIntEQ(ret = PKCS12_parse(pkcs12, "wolfSSL test", &pkey, &cert, NULL),
        1);
    ExpectNotNull(pkey);
    ExpectNotNull(cert);

    wolfSSL_EVP_PKEY_free(pkey);
    pkey = NULL;
    wolfSSL_X509_free(cert);
    cert = NULL;

    /* check parse with extra certs kept */
    ExpectIntEQ(ret = PKCS12_parse(pkcs12, "wolfSSL test", &pkey, &cert, &ca),
        1);
    ExpectNotNull(pkey);
    ExpectNotNull(cert);
    ExpectNotNull(ca);

#if (defined(OPENSSL_ALL) || defined(WOLFSSL_ASIO) || defined(WOLFSSL_HAPROXY) \
    || defined(WOLFSSL_NGINX)) && defined(SESSION_CERTS)

    /* Check that SSL_CTX_set0_chain correctly sets the certChain buffer */
#if !defined(NO_WOLFSSL_CLIENT) || !defined(NO_WOLFSSL_SERVER)
#if !defined(NO_WOLFSSL_CLIENT) && defined(SESSION_CERTS)
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
#else
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_server_method()));
#endif
    /* Copy stack structure */
    ExpectNotNull(tmp_ca = X509_chain_up_ref(ca));
    ExpectIntEQ(SSL_CTX_set0_chain(ctx, tmp_ca), 1);
    /* CTX now owns the tmp_ca stack structure */
    tmp_ca = NULL;
    ExpectIntEQ(wolfSSL_CTX_get_extra_chain_certs(ctx, &tmp_ca), 1);
    ExpectNotNull(tmp_ca);
    ExpectIntEQ(sk_X509_num(tmp_ca), sk_X509_num(ca));
    /* Check that the main cert is also set */
    ExpectNotNull(SSL_CTX_get0_certificate(ctx));
    ExpectNotNull(ssl = SSL_new(ctx));
    ExpectNotNull(SSL_get_certificate(ssl));
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    ctx = NULL;
#endif
#endif /* !NO_WOLFSSL_CLIENT || !NO_WOLFSSL_SERVER */
    /* should be 2 other certs on stack */
    ExpectNotNull(tmp = sk_X509_pop(ca));
    X509_free(tmp);
    ExpectNotNull(tmp = sk_X509_pop(ca));
    X509_free(tmp);
    ExpectNull(sk_X509_pop(ca));

    EVP_PKEY_free(pkey);
    pkey = NULL;
    X509_free(cert);
    cert = NULL;
    sk_X509_pop_free(ca, X509_free);
    ca = NULL;

    /* check PKCS12_create */
    ExpectNull(PKCS12_create(pass, NULL, NULL, NULL, NULL, -1, -1, -1, -1,0));
    ExpectIntEQ(PKCS12_parse(pkcs12, "wolfSSL test", &pkey, &cert, &ca),
            SSL_SUCCESS);
    ExpectNotNull((pkcs12_2 = PKCS12_create(pass, NULL, pkey, cert, ca,
                    -1, -1, 100, -1, 0)));
    EVP_PKEY_free(pkey);
    pkey = NULL;
    X509_free(cert);
    cert = NULL;
    sk_X509_pop_free(ca, NULL);
    ca = NULL;

    ExpectIntEQ(PKCS12_parse(pkcs12_2, "a password", &pkey, &cert, &ca),
            SSL_SUCCESS);
    PKCS12_free(pkcs12_2);
    pkcs12_2 = NULL;
    ExpectNotNull((pkcs12_2 = PKCS12_create(pass, NULL, pkey, cert, ca,
             NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
             NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
             2000, 1, 0)));
    EVP_PKEY_free(pkey);
    pkey = NULL;
    X509_free(cert);
    cert = NULL;
    sk_X509_pop_free(ca, NULL);
    ca = NULL;

    /* convert to DER then back and parse */
    ExpectNotNull(bio = BIO_new(BIO_s_mem()));
    ExpectIntEQ(i2d_PKCS12_bio(bio, pkcs12_2), SSL_SUCCESS);
    PKCS12_free(pkcs12_2);
    pkcs12_2 = NULL;

    ExpectNotNull(pkcs12_2 = d2i_PKCS12_bio(bio, NULL));
    BIO_free(bio);
    bio = NULL;
    ExpectIntEQ(PKCS12_parse(pkcs12_2, "a password", &pkey, &cert, &ca),
            SSL_SUCCESS);

    /* should be 2 other certs on stack */
    ExpectNotNull(tmp = sk_X509_pop(ca));
    X509_free(tmp);
    ExpectNotNull(tmp = sk_X509_pop(ca));
    X509_free(tmp);
    ExpectNull(sk_X509_pop(ca));


#ifndef NO_RC4
    PKCS12_free(pkcs12_2);
    pkcs12_2 = NULL;
    ExpectNotNull((pkcs12_2 = PKCS12_create(pass, NULL, pkey, cert, NULL,
             NID_pbe_WithSHA1And128BitRC4,
             NID_pbe_WithSHA1And128BitRC4,
             2000, 1, 0)));
    EVP_PKEY_free(pkey);
    pkey = NULL;
    X509_free(cert);
    cert = NULL;
    sk_X509_pop_free(ca, NULL);
    ca = NULL;

    ExpectIntEQ(PKCS12_parse(pkcs12_2, "a password", &pkey, &cert, &ca),
            SSL_SUCCESS);

#endif /* NO_RC4 */

    EVP_PKEY_free(pkey);
    pkey = NULL;
    X509_free(cert);
    cert = NULL;
    PKCS12_free(pkcs12);
    pkcs12 = NULL;
    PKCS12_free(pkcs12_2);
    pkcs12_2 = NULL;
    sk_X509_pop_free(ca, NULL);
    ca = NULL;

#ifdef HAVE_ECC
    /* test order of parsing */
    ExpectTrue((f = XFOPEN(order, "rb")) != XBADFILE);
    ExpectIntGT(bytes = (int)XFREAD(buf, 1, sizeof(buf), f), 0);
    if (f != XBADFILE) {
        XFCLOSE(f);
        f = XBADFILE;
    }

    ExpectNotNull(bio = BIO_new_mem_buf((void*)buf, bytes));
    ExpectNotNull(pkcs12 = d2i_PKCS12_bio(bio, NULL));
    ExpectIntEQ((ret = PKCS12_parse(pkcs12, "", &pkey, &cert, &ca)),
            WOLFSSL_SUCCESS);

    /* check use of pkey after parse */
#if (defined(OPENSSL_ALL) || defined(WOLFSSL_ASIO) || defined(WOLFSSL_HAPROXY) \
    || defined(WOLFSSL_NGINX)) && defined(SESSION_CERTS)
#if !defined(NO_WOLFSSL_CLIENT) || !defined(NO_WOLFSSL_SERVER)
#if !defined(NO_WOLFSSL_CLIENT) && defined(SESSION_CERTS)
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
#else
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_server_method()));
#endif
    ExpectIntEQ(SSL_CTX_use_PrivateKey(ctx, pkey), WOLFSSL_SUCCESS);
    SSL_CTX_free(ctx);
#endif /* !NO_WOLFSSL_CLIENT || !NO_WOLFSSL_SERVER */
#endif

    ExpectNotNull(pkey);
    ExpectNotNull(cert);
    ExpectNotNull(ca);

    /* compare subject lines of certificates */
    ExpectNotNull(subject = wolfSSL_X509_get_subject_name(cert));
    ExpectNotNull(x509 = wolfSSL_X509_load_certificate_file(eccRsaCertFile,
                SSL_FILETYPE_PEM));
    ExpectIntEQ(wolfSSL_X509_NAME_cmp((const WOLFSSL_X509_NAME*)subject,
            (const WOLFSSL_X509_NAME*)wolfSSL_X509_get_subject_name(x509)), 0);
    X509_free(x509);
    x509 = NULL;

    /* test expected fail case */
    ExpectNotNull(x509 = wolfSSL_X509_load_certificate_file(eccCertFile,
                SSL_FILETYPE_PEM));
    ExpectIntNE(wolfSSL_X509_NAME_cmp((const WOLFSSL_X509_NAME*)subject,
            (const WOLFSSL_X509_NAME*)wolfSSL_X509_get_subject_name(x509)), 0);
    X509_free(x509);
    x509 = NULL;
    X509_free(cert);
    cert = NULL;

    /* get subject line from ca stack */
    ExpectNotNull(cert = sk_X509_pop(ca));
    ExpectNotNull(subject = wolfSSL_X509_get_subject_name(cert));

    /* compare subject from certificate in ca to expected */
    ExpectNotNull(x509 = wolfSSL_X509_load_certificate_file(eccCertFile,
                SSL_FILETYPE_PEM));
    ExpectIntEQ(wolfSSL_X509_NAME_cmp((const WOLFSSL_X509_NAME*)subject,
            (const WOLFSSL_X509_NAME*)wolfSSL_X509_get_subject_name(x509)), 0);

    /* modify case and compare subject from certificate in ca to expected.
     * The first bit of the name is:
     * /C=US/ST=Washington
     * So we'll change subject->name[1] to 'c' (lower case) */
    if (subject != NULL) {
        subject->name[1] = 'c';
        ExpectIntEQ(wolfSSL_X509_NAME_cmp((const WOLFSSL_X509_NAME*)subject,
            (const WOLFSSL_X509_NAME*)wolfSSL_X509_get_subject_name(x509)), 0);
    }

    EVP_PKEY_free(pkey);
    pkey = NULL;
    X509_free(x509);
    x509 = NULL;
    X509_free(cert);
    cert = NULL;
    BIO_free(bio);
    bio = NULL;
    PKCS12_free(pkcs12);
    pkcs12 = NULL;
    sk_X509_pop_free(ca, NULL); /* TEST d2i_PKCS12_fp */
    ca = NULL;

    /* test order of parsing */
    ExpectTrue((f = XFOPEN(file, "rb")) != XBADFILE);
    ExpectNotNull(pkcs12 = d2i_PKCS12_fp(f, NULL));
    if (f != XBADFILE) {
        XFCLOSE(f);
        f = XBADFILE;
    }

    /* check verify MAC fail case */
    ExpectIntEQ(ret = PKCS12_parse(pkcs12, "bad", &pkey, &cert, NULL), 0);
    ExpectNull(pkey);
    ExpectNull(cert);

    /* check parse with no extra certs kept */
    ExpectIntEQ(ret = PKCS12_parse(pkcs12, "wolfSSL test", &pkey, &cert, NULL),
        1);
    ExpectNotNull(pkey);
    ExpectNotNull(cert);

    wolfSSL_EVP_PKEY_free(pkey);
    pkey = NULL;
    wolfSSL_X509_free(cert);
    cert = NULL;

    /* check parse with extra certs kept */
    ExpectIntEQ(ret = PKCS12_parse(pkcs12, "wolfSSL test", &pkey, &cert, &ca),
        1);
    ExpectNotNull(pkey);
    ExpectNotNull(cert);
    ExpectNotNull(ca);

    wolfSSL_EVP_PKEY_free(pkey);
    pkey = NULL;
    wolfSSL_X509_free(cert);
    cert = NULL;
    sk_X509_pop_free(ca, NULL);
    ca = NULL;

    PKCS12_free(pkcs12);
    pkcs12 = NULL;
#endif /* HAVE_ECC */

#ifdef WC_RC2
    /* test PKCS#12 with RC2 encryption */
    ExpectTrue((f = XFOPEN(rc2p12, "rb")) != XBADFILE);
    ExpectIntGT(bytes = (int)XFREAD(buf, 1, sizeof(buf), f), 0);
    if (f != XBADFILE) {
        XFCLOSE(f);
        f = XBADFILE;
    }

    ExpectNotNull(bio = BIO_new_mem_buf((void*)buf, bytes));
    ExpectNotNull(pkcs12 = d2i_PKCS12_bio(bio, NULL));

    /* check verify MAC fail case */
    ExpectIntEQ(ret = PKCS12_parse(pkcs12, "bad", &pkey, &cert, NULL), 0);
    ExpectNull(pkey);
    ExpectNull(cert);

    /* check parse with not extra certs kept */
    ExpectIntEQ(ret = PKCS12_parse(pkcs12, "wolfSSL test", &pkey, &cert, NULL),
        WOLFSSL_SUCCESS);
    ExpectNotNull(pkey);
    ExpectNotNull(cert);

    wolfSSL_EVP_PKEY_free(pkey);
    pkey = NULL;
    wolfSSL_X509_free(cert);
    cert = NULL;

    /* check parse with extra certs kept */
    ExpectIntEQ(ret = PKCS12_parse(pkcs12, "wolfSSL test", &pkey, &cert, &ca),
        WOLFSSL_SUCCESS);
    ExpectNotNull(pkey);
    ExpectNotNull(cert);
    ExpectNotNull(ca);

    wolfSSL_EVP_PKEY_free(pkey);
    wolfSSL_X509_free(cert);
    sk_X509_pop_free(ca, NULL);

    BIO_free(bio);
    bio = NULL;
    PKCS12_free(pkcs12);
    pkcs12 = NULL;
#endif /* WC_RC2 */

    /* Test i2d_PKCS12_bio */
    ExpectTrue((f = XFOPEN(file, "rb")) != XBADFILE);
    ExpectNotNull(pkcs12 = d2i_PKCS12_fp(f, NULL));
    if (f != XBADFILE)
        XFCLOSE(f);

    ExpectNotNull(bio = BIO_new(BIO_s_mem()));

    ExpectIntEQ(ret = i2d_PKCS12_bio(bio, pkcs12), 1);

    ExpectIntEQ(ret = i2d_PKCS12_bio(NULL, pkcs12), 0);

    ExpectIntEQ(ret = i2d_PKCS12_bio(bio, NULL), 0);

    PKCS12_free(pkcs12);
    BIO_free(bio);

    (void)order;
#endif /* OPENSSL_EXTRA */
#endif /* HAVE_FIPS */
    return EXPECT_RESULT();
}

