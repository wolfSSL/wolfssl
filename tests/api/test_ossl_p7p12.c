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

/* Regression test for CMS SignedData signer-identity forgery.
 *
 * The embedded DER is a CMS SignedData message crafted so that the
 * certificates SET contains two certificates:
 *   cert[0] = certs/ca-cert.pem (trusted wolfSSL CA; attacker does NOT hold
 *             its private key)
 *   cert[1] = a self-signed "attacker" P-256 certificate (attacker holds
 *             the private key)
 * The signerInfo sid names the attacker certificate, and the signature
 * was produced with the attacker's key over "Hello World".
 *
 * The bug that was present: wolfSSL_PKCS7_verify() iterated all bundled
 * certificates trying each public key against the signature. When the
 * attacker's key verified, it still reported cert[0] (the trusted CA cert,
 * via singleCert) as the signer, and chain validation therefore succeeded
 * on an unrelated trusted cert - a full signer-identity forgery.
 *
 * The expected, correct behavior: the CMS message is rejected because the
 * signer certificate named by the sid (the attacker cert) does not chain
 * to any certificate in the trust store. */
int test_wolfSSL_PKCS7_verify_signer_forgery(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && defined(HAVE_PKCS7) && !defined(NO_BIO) && \
    !defined(NO_FILESYSTEM) && !defined(NO_RSA) && defined(HAVE_ECC)
    static const byte forgedSignedData[] = {
        0x30, 0x82, 0x07, 0x9c, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
        0x01, 0x07, 0x02, 0xa0, 0x82, 0x07, 0x8d, 0x30, 0x82, 0x07, 0x89, 0x02,
        0x01, 0x01, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
        0x65, 0x03, 0x04, 0x02, 0x01, 0x30, 0x1b, 0x06, 0x09, 0x2a, 0x86, 0x48,
        0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, 0xa0, 0x0e, 0x04, 0x0c, 0x48, 0x65,
        0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x0a, 0xa0, 0x82,
        0x06, 0xab, 0x30, 0x82, 0x04, 0xff, 0x30, 0x82, 0x03, 0xe7, 0xa0, 0x03,
        0x02, 0x01, 0x02, 0x02, 0x14, 0x3f, 0x29, 0x11, 0x20, 0x57, 0x71, 0xe7,
        0x8e, 0xf9, 0x18, 0x0d, 0xca, 0x70, 0x4d, 0x5b, 0x15, 0x2a, 0x43, 0xd6,
        0x24, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
        0x01, 0x0b, 0x05, 0x00, 0x30, 0x81, 0x94, 0x31, 0x0b, 0x30, 0x09, 0x06,
        0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x10, 0x30, 0x0e,
        0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x07, 0x4d, 0x6f, 0x6e, 0x74, 0x61,
        0x6e, 0x61, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c,
        0x07, 0x42, 0x6f, 0x7a, 0x65, 0x6d, 0x61, 0x6e, 0x31, 0x11, 0x30, 0x0f,
        0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x08, 0x53, 0x61, 0x77, 0x74, 0x6f,
        0x6f, 0x74, 0x68, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0b,
        0x0c, 0x0a, 0x43, 0x6f, 0x6e, 0x73, 0x75, 0x6c, 0x74, 0x69, 0x6e, 0x67,
        0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0f, 0x77,
        0x77, 0x77, 0x2e, 0x77, 0x6f, 0x6c, 0x66, 0x73, 0x73, 0x6c, 0x2e, 0x63,
        0x6f, 0x6d, 0x31, 0x1f, 0x30, 0x1d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x10, 0x69, 0x6e, 0x66, 0x6f, 0x40,
        0x77, 0x6f, 0x6c, 0x66, 0x73, 0x73, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x30,
        0x1e, 0x17, 0x0d, 0x32, 0x35, 0x31, 0x31, 0x31, 0x33, 0x32, 0x30, 0x34,
        0x31, 0x31, 0x31, 0x5a, 0x17, 0x0d, 0x32, 0x38, 0x30, 0x38, 0x30, 0x39,
        0x32, 0x30, 0x34, 0x31, 0x31, 0x31, 0x5a, 0x30, 0x81, 0x94, 0x31, 0x0b,
        0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31,
        0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x07, 0x4d, 0x6f,
        0x6e, 0x74, 0x61, 0x6e, 0x61, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55,
        0x04, 0x07, 0x0c, 0x07, 0x42, 0x6f, 0x7a, 0x65, 0x6d, 0x61, 0x6e, 0x31,
        0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x08, 0x53, 0x61,
        0x77, 0x74, 0x6f, 0x6f, 0x74, 0x68, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03,
        0x55, 0x04, 0x0b, 0x0c, 0x0a, 0x43, 0x6f, 0x6e, 0x73, 0x75, 0x6c, 0x74,
        0x69, 0x6e, 0x67, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03,
        0x0c, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x77, 0x6f, 0x6c, 0x66, 0x73, 0x73,
        0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x31, 0x1f, 0x30, 0x1d, 0x06, 0x09, 0x2a,
        0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x10, 0x69, 0x6e,
        0x66, 0x6f, 0x40, 0x77, 0x6f, 0x6c, 0x66, 0x73, 0x73, 0x6c, 0x2e, 0x63,
        0x6f, 0x6d, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86,
        0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01,
        0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xbf,
        0x0c, 0xca, 0x2d, 0x14, 0xb2, 0x1e, 0x84, 0x42, 0x5b, 0xcd, 0x38, 0x1f,
        0x4a, 0xf2, 0x4d, 0x75, 0x10, 0xf1, 0xb6, 0x35, 0x9f, 0xdf, 0xca, 0x7d,
        0x03, 0x98, 0xd3, 0xac, 0xde, 0x03, 0x66, 0xee, 0x2a, 0xf1, 0xd8, 0xb0,
        0x7d, 0x6e, 0x07, 0x54, 0x0b, 0x10, 0x98, 0x21, 0x4d, 0x80, 0xcb, 0x12,
        0x20, 0xe7, 0xcc, 0x4f, 0xde, 0x45, 0x7d, 0xc9, 0x72, 0x77, 0x32, 0xea,
        0xca, 0x90, 0xbb, 0x69, 0x52, 0x10, 0x03, 0x2f, 0xa8, 0xf3, 0x95, 0xc5,
        0xf1, 0x8b, 0x62, 0x56, 0x1b, 0xef, 0x67, 0x6f, 0xa4, 0x10, 0x41, 0x95,
        0xad, 0x0a, 0x9b, 0xe3, 0xa5, 0xc0, 0xb0, 0xd2, 0x70, 0x76, 0x50, 0x30,
        0x5b, 0xa8, 0xe8, 0x08, 0x2c, 0x7c, 0xed, 0xa7, 0xa2, 0x7a, 0x8d, 0x38,
        0x29, 0x1c, 0xac, 0xc7, 0xed, 0xf2, 0x7c, 0x95, 0xb0, 0x95, 0x82, 0x7d,
        0x49, 0x5c, 0x38, 0xcd, 0x77, 0x25, 0xef, 0xbd, 0x80, 0x75, 0x53, 0x94,
        0x3c, 0x3d, 0xca, 0x63, 0x5b, 0x9f, 0x15, 0xb5, 0xd3, 0x1d, 0x13, 0x2f,
        0x19, 0xd1, 0x3c, 0xdb, 0x76, 0x3a, 0xcc, 0xb8, 0x7d, 0xc9, 0xe5, 0xc2,
        0xd7, 0xda, 0x40, 0x6f, 0xd8, 0x21, 0xdc, 0x73, 0x1b, 0x42, 0x2d, 0x53,
        0x9c, 0xfe, 0x1a, 0xfc, 0x7d, 0xab, 0x7a, 0x36, 0x3f, 0x98, 0xde, 0x84,
        0x7c, 0x05, 0x67, 0xce, 0x6a, 0x14, 0x38, 0x87, 0xa9, 0xf1, 0x8c, 0xb5,
        0x68, 0xcb, 0x68, 0x7f, 0x71, 0x20, 0x2b, 0xf5, 0xa0, 0x63, 0xf5, 0x56,
        0x2f, 0xa3, 0x26, 0xd2, 0xb7, 0x6f, 0xb1, 0x5a, 0x17, 0xd7, 0x38, 0x99,
        0x08, 0xfe, 0x93, 0x58, 0x6f, 0xfe, 0xc3, 0x13, 0x49, 0x08, 0x16, 0x0b,
        0xa7, 0x4d, 0x67, 0x00, 0x52, 0x31, 0x67, 0x23, 0x4e, 0x98, 0xed, 0x51,
        0x45, 0x1d, 0xb9, 0x04, 0xd9, 0x0b, 0xec, 0xd8, 0x28, 0xb3, 0x4b, 0xbd,
        0xed, 0x36, 0x79, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x82, 0x01, 0x45,
        0x30, 0x82, 0x01, 0x41, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04,
        0x16, 0x04, 0x14, 0x27, 0x8e, 0x67, 0x11, 0x74, 0xc3, 0x26, 0x1d, 0x3f,
        0xed, 0x33, 0x63, 0xb3, 0xa4, 0xd8, 0x1d, 0x30, 0xe5, 0xe8, 0xd5, 0x30,
        0x81, 0xd4, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x81, 0xcc, 0x30, 0x81,
        0xc9, 0x80, 0x14, 0x27, 0x8e, 0x67, 0x11, 0x74, 0xc3, 0x26, 0x1d, 0x3f,
        0xed, 0x33, 0x63, 0xb3, 0xa4, 0xd8, 0x1d, 0x30, 0xe5, 0xe8, 0xd5, 0xa1,
        0x81, 0x9a, 0xa4, 0x81, 0x97, 0x30, 0x81, 0x94, 0x31, 0x0b, 0x30, 0x09,
        0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x10, 0x30,
        0x0e, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x07, 0x4d, 0x6f, 0x6e, 0x74,
        0x61, 0x6e, 0x61, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x07,
        0x0c, 0x07, 0x42, 0x6f, 0x7a, 0x65, 0x6d, 0x61, 0x6e, 0x31, 0x11, 0x30,
        0x0f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x08, 0x53, 0x61, 0x77, 0x74,
        0x6f, 0x6f, 0x74, 0x68, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04,
        0x0b, 0x0c, 0x0a, 0x43, 0x6f, 0x6e, 0x73, 0x75, 0x6c, 0x74, 0x69, 0x6e,
        0x67, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0f,
        0x77, 0x77, 0x77, 0x2e, 0x77, 0x6f, 0x6c, 0x66, 0x73, 0x73, 0x6c, 0x2e,
        0x63, 0x6f, 0x6d, 0x31, 0x1f, 0x30, 0x1d, 0x06, 0x09, 0x2a, 0x86, 0x48,
        0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x10, 0x69, 0x6e, 0x66, 0x6f,
        0x40, 0x77, 0x6f, 0x6c, 0x66, 0x73, 0x73, 0x6c, 0x2e, 0x63, 0x6f, 0x6d,
        0x82, 0x14, 0x3f, 0x29, 0x11, 0x20, 0x57, 0x71, 0xe7, 0x8e, 0xf9, 0x18,
        0x0d, 0xca, 0x70, 0x4d, 0x5b, 0x15, 0x2a, 0x43, 0xd6, 0x24, 0x30, 0x0c,
        0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff,
        0x30, 0x1c, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x15, 0x30, 0x13, 0x82,
        0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
        0x87, 0x04, 0x7f, 0x00, 0x00, 0x01, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d,
        0x25, 0x04, 0x16, 0x30, 0x14, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05,
        0x07, 0x03, 0x01, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03,
        0x02, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
        0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x0f, 0xae, 0x89,
        0xd5, 0x68, 0xe4, 0x41, 0xf8, 0x9b, 0xe0, 0xc5, 0x61, 0x06, 0x57, 0xff,
        0xa0, 0x92, 0x0f, 0xb2, 0xed, 0xd3, 0x99, 0x5b, 0x99, 0x5e, 0x32, 0x7e,
        0x97, 0xc7, 0xaf, 0x6c, 0xfe, 0x8c, 0xa6, 0xae, 0x32, 0xa1, 0x0d, 0xca,
        0xcd, 0xfc, 0x18, 0xe5, 0xd1, 0xf8, 0x20, 0x5b, 0x5a, 0x38, 0x81, 0x46,
        0x5b, 0x48, 0x87, 0xa5, 0x3f, 0x3b, 0x7b, 0xc7, 0xea, 0xf5, 0x35, 0x29,
        0x31, 0x15, 0x39, 0x38, 0x5d, 0x48, 0xe6, 0x01, 0x81, 0x5c, 0x5e, 0x7c,
        0x10, 0xf5, 0x16, 0xe3, 0x59, 0xaf, 0x44, 0xc8, 0xb5, 0x8d, 0xc1, 0x32,
        0x23, 0xb3, 0xb8, 0x12, 0x6e, 0x5c, 0x8d, 0xe6, 0xc2, 0xd2, 0x41, 0x03,
        0xeb, 0x17, 0x42, 0xe2, 0x7f, 0xbc, 0x00, 0x5d, 0xa5, 0x31, 0xef, 0xc6,
        0x48, 0xee, 0xdb, 0xcc, 0xe0, 0xf1, 0x56, 0xf5, 0xd4, 0xca, 0x45, 0xa1,
        0x59, 0xb5, 0xe4, 0xd7, 0x60, 0x9c, 0x57, 0xe0, 0xa7, 0x5a, 0xf2, 0x35,
        0x1e, 0xa0, 0x22, 0xdb, 0x5e, 0x1c, 0x0c, 0x61, 0xbd, 0xa1, 0xc5, 0x7b,
        0x9f, 0x69, 0xf2, 0xd5, 0x95, 0xe2, 0xbc, 0x52, 0xb9, 0x1d, 0x9c, 0x2c,
        0xda, 0xb6, 0x73, 0x75, 0x4a, 0x84, 0xe5, 0x94, 0xb8, 0x19, 0x4d, 0xdd,
        0x70, 0xbd, 0x7f, 0x4c, 0xb9, 0x17, 0x6a, 0x58, 0x16, 0x89, 0x22, 0x44,
        0x37, 0x57, 0x55, 0x26, 0x42, 0xe3, 0xb7, 0xe5, 0xc7, 0x2b, 0x40, 0x0c,
        0xe9, 0xe4, 0x7f, 0x52, 0x75, 0xdf, 0x06, 0xc9, 0xfb, 0x01, 0x44, 0x34,
        0xac, 0x20, 0x3c, 0xb4, 0xbe, 0x2b, 0x3e, 0xef, 0x85, 0x38, 0x96, 0x5b,
        0x9b, 0x1e, 0x25, 0x86, 0x18, 0x4c, 0xa4, 0x06, 0x70, 0x06, 0x6a, 0xc8,
        0x4b, 0x6f, 0x5f, 0xc4, 0x05, 0x1f, 0x03, 0x62, 0x30, 0x11, 0x61, 0xbc,
        0xc1, 0x40, 0x31, 0x66, 0xdc, 0x64, 0xf0, 0x4f, 0x6b, 0xb9, 0xec, 0xc8,
        0x29, 0x30, 0x82, 0x01, 0xa4, 0x30, 0x82, 0x01, 0x49, 0xa0, 0x03, 0x02,
        0x01, 0x02, 0x02, 0x14, 0x62, 0x4d, 0x11, 0x9c, 0xcf, 0x5d, 0xe5, 0x71,
        0xa2, 0x82, 0xd9, 0x8f, 0xe0, 0x04, 0xb8, 0x5f, 0x0e, 0x4d, 0x07, 0xad,
        0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
        0x30, 0x27, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
        0x08, 0x61, 0x74, 0x74, 0x61, 0x63, 0x6b, 0x65, 0x72, 0x31, 0x12, 0x30,
        0x10, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x09, 0x75, 0x6e, 0x74, 0x72,
        0x75, 0x73, 0x74, 0x65, 0x64, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30,
        0x34, 0x32, 0x31, 0x31, 0x31, 0x31, 0x36, 0x32, 0x38, 0x5a, 0x17, 0x0d,
        0x33, 0x36, 0x30, 0x34, 0x31, 0x38, 0x31, 0x31, 0x31, 0x36, 0x32, 0x38,
        0x5a, 0x30, 0x27, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x03,
        0x0c, 0x08, 0x61, 0x74, 0x74, 0x61, 0x63, 0x6b, 0x65, 0x72, 0x31, 0x12,
        0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x09, 0x75, 0x6e, 0x74,
        0x72, 0x75, 0x73, 0x74, 0x65, 0x64, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xae, 0xdb, 0xf7,
        0x3b, 0x7e, 0x82, 0x88, 0xfc, 0x1a, 0xfb, 0x86, 0x56, 0x83, 0x03, 0xdd,
        0x05, 0x14, 0x79, 0x51, 0x0f, 0x3c, 0x86, 0x85, 0x2d, 0xeb, 0x18, 0x17,
        0x20, 0x3b, 0x37, 0x6f, 0x7f, 0x78, 0x19, 0x3b, 0xf6, 0x71, 0xad, 0xc9,
        0x65, 0x81, 0x7e, 0xe0, 0xa9, 0x29, 0xdd, 0xfd, 0xf0, 0xff, 0x04, 0x7d,
        0x5a, 0x59, 0xd6, 0x6c, 0xe2, 0xde, 0xc5, 0xd5, 0xb6, 0x1f, 0x69, 0xd9,
        0x33, 0xa3, 0x53, 0x30, 0x51, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e,
        0x04, 0x16, 0x04, 0x14, 0xf7, 0xab, 0x3f, 0x49, 0xcf, 0x7d, 0x48, 0x9c,
        0x04, 0x49, 0x1a, 0xac, 0x8f, 0x26, 0x16, 0x09, 0xa8, 0x2a, 0x74, 0xf5,
        0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80,
        0x14, 0xf7, 0xab, 0x3f, 0x49, 0xcf, 0x7d, 0x48, 0x9c, 0x04, 0x49, 0x1a,
        0xac, 0x8f, 0x26, 0x16, 0x09, 0xa8, 0x2a, 0x74, 0xf5, 0x30, 0x0f, 0x06,
        0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01,
        0x01, 0xff, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04,
        0x03, 0x02, 0x03, 0x49, 0x00, 0x30, 0x46, 0x02, 0x21, 0x00, 0x8d, 0xbf,
        0x36, 0xe5, 0x51, 0x9a, 0xde, 0xf4, 0x7f, 0xbf, 0xbd, 0x7f, 0x71, 0x66,
        0xc1, 0x67, 0xfa, 0x71, 0x0d, 0x79, 0xc6, 0x60, 0x3a, 0x6c, 0xeb, 0x43,
        0xc3, 0xf2, 0x5e, 0xe8, 0x74, 0xb6, 0x02, 0x21, 0x00, 0xfa, 0xdb, 0x40,
        0x47, 0x72, 0xf0, 0x15, 0x52, 0xc1, 0x78, 0x11, 0x6b, 0x76, 0xc5, 0x1f,
        0xcf, 0xb6, 0x09, 0x6d, 0x8f, 0xcb, 0x92, 0x2f, 0x1b, 0x3c, 0xc3, 0x28,
        0x48, 0x61, 0x0f, 0x60, 0x71, 0x31, 0x81, 0xa8, 0x30, 0x81, 0xa5, 0x02,
        0x01, 0x01, 0x30, 0x3f, 0x30, 0x27, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03,
        0x55, 0x04, 0x03, 0x0c, 0x08, 0x61, 0x74, 0x74, 0x61, 0x63, 0x6b, 0x65,
        0x72, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x09,
        0x75, 0x6e, 0x74, 0x72, 0x75, 0x73, 0x74, 0x65, 0x64, 0x02, 0x14, 0x62,
        0x4d, 0x11, 0x9c, 0xcf, 0x5d, 0xe5, 0x71, 0xa2, 0x82, 0xd9, 0x8f, 0xe0,
        0x04, 0xb8, 0x5f, 0x0e, 0x4d, 0x07, 0xad, 0x30, 0x0b, 0x06, 0x09, 0x60,
        0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x30, 0x0a, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x04, 0x46, 0x30, 0x44,
        0x02, 0x20, 0x22, 0x4a, 0x99, 0xb1, 0xbc, 0xa9, 0xee, 0x24, 0x60, 0x81,
        0xb9, 0x64, 0xba, 0x86, 0x00, 0xae, 0xb5, 0xd7, 0xb8, 0x72, 0xb9, 0x8c,
        0xb3, 0xe7, 0x78, 0x29, 0xdb, 0xa8, 0x27, 0xf7, 0x30, 0xf0, 0x02, 0x20,
        0x19, 0x2d, 0xd3, 0x17, 0x9a, 0xc1, 0xf9, 0xd2, 0x63, 0x92, 0x8e, 0x78,
        0xcc, 0xa4, 0x0b, 0x91, 0x12, 0xa5, 0xb2, 0xbc, 0x35, 0x87, 0x8e, 0x33,
        0xa7, 0xe0, 0x5e, 0xab, 0x95, 0xb2, 0x2a, 0xf4
    };
    PKCS7* p7 = NULL;
    X509_STORE* store = NULL;
    X509* caCert = NULL;
    WOLFSSL_BIO* caBio = NULL;
    const byte* p = forgedSignedData;
    const char* ca = "./certs/ca-cert.pem";

    /* Load the same CA into the trust store that the attacker bundled at
     * cert[0] in the forged message. */
    ExpectNotNull(caBio = BIO_new_file(ca, "r"));
    ExpectNotNull(caCert = PEM_read_bio_X509(caBio, NULL, 0, NULL));
    ExpectNotNull(store = X509_STORE_new());
    ExpectIntEQ(X509_STORE_add_cert(store, caCert), 1);

    /* Parse the forged message. d2i_PKCS7 internally runs
     * wc_PKCS7_VerifySignedData, which must NOT accept the attacker's
     * signature under any bundled cert other than the one named by the
     * signerInfo sid. Since the sid names the attacker cert (which does
     * not chain to the trusted CA), the parse may succeed but verification
     * against the trust store must fail. */
    ExpectNotNull(p7 = d2i_PKCS7(NULL, &p, (int)sizeof(forgedSignedData)));

    /* PKCS7_verify() MUST fail: the only certificate in the trust store
     * is the wolfSSL CA - it is bundled at cert[0] but did NOT sign this
     * message. The actual signer (the attacker's self-signed cert at
     * cert[1]) cannot chain to any trust anchor. */
    ExpectIntEQ(PKCS7_verify(p7, NULL, store, NULL, NULL, 0),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

    PKCS7_free(p7);
    X509_STORE_free(store);
    X509_free(caCert);
    BIO_free(caBio);
#endif
    return EXPECT_RESULT();
}

/* Exercise the SignerInfo-sid binding enforcement end-to-end.
 *
 * For both supported sid encodings (v1 = IssuerAndSerialNumber, v3 =
 * SubjectKeyIdentifier), this builds a valid CMS SignedData message with
 * two certificates in the bundle:
 *   cert[0] = ca-cert (extra, non-signing)
 *   cert[1] = server-cert (actual signer)
 * and checks that:
 *   - parsing + signature verification succeeds,
 *   - chain validation against a trust store containing ca-cert succeeds,
 *   - PKCS7_get0_signers() returns the *signer* (server-cert), not the
 *     extra cert at cert[0] - which would be the pre-fix behavior and the
 *     core of the signer-identity forgery bug. */
int test_wolfSSL_PKCS7_verify_sid_binding(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && defined(HAVE_PKCS7) && !defined(NO_BIO) && \
    !defined(NO_FILESYSTEM) && !defined(NO_RSA)
    const char* signerCertFile = "./certs/server-cert.pem";
    const char* signerKeyFile  = "./certs/server-key.pem";
    const char* caFile         = "./certs/ca-cert.pem";
    const byte  content[] = "sid-binding test content";
    /* Build both variants: default v1 (IssuerAndSerialNumber) and v3
     * (SubjectKeyIdentifier). */
    const int   sidTypes[2] = { CMS_ISSUER_AND_SERIAL_NUMBER, CMS_SKID };
    int         variant;

    BIO* signerCertBio = NULL;
    BIO* caBio = NULL;
    X509* signerCertX509 = NULL;
    X509* caX509 = NULL;
    byte* signerCertDer = NULL;
    byte* caDer = NULL;
    byte* signerKey = NULL;
    int   signerCertDerSz = 0;
    int   caDerSz = 0;
    size_t signerKeySz = 0;
    XFILE keyFile = XBADFILE;
    WC_RNG rng;
    int rngInited = 0;

    /* ---- Load signer cert + key and the CA cert. ---- */
    ExpectNotNull(signerCertBio = BIO_new_file(signerCertFile, "r"));
    ExpectNotNull(signerCertX509 = PEM_read_bio_X509(signerCertBio, NULL, 0,
                                                    NULL));
    ExpectIntGT(signerCertDerSz = i2d_X509(signerCertX509, &signerCertDer), 0);

    ExpectNotNull(caBio = BIO_new_file(caFile, "r"));
    ExpectNotNull(caX509 = PEM_read_bio_X509(caBio, NULL, 0, NULL));
    ExpectIntGT(caDerSz = i2d_X509(caX509, &caDer), 0);

    /* Slurp the DER private key straight from a PEM->DER round-trip via
     * wc_KeyPemToDer. The test only needs the bytes in a form
     * wc_PKCS7_EncodeSignedData can consume. */
    {
        long   filePemLen = 0;
        byte*  keyPem = NULL;
        int    derLen = 0;

        ExpectTrue((keyFile = XFOPEN(signerKeyFile, "rb")) != XBADFILE);
        if (keyFile != XBADFILE) {
            (void)XFSEEK(keyFile, 0, XSEEK_END);
            filePemLen = XFTELL(keyFile);
            (void)XFSEEK(keyFile, 0, XSEEK_SET);
            ExpectIntGT(filePemLen, 0);
            keyPem = (byte*)XMALLOC((size_t)filePemLen, NULL,
                                    DYNAMIC_TYPE_TMP_BUFFER);
            ExpectNotNull(keyPem);
            if (keyPem != NULL) {
                ExpectIntEQ(XFREAD(keyPem, 1, (size_t)filePemLen, keyFile),
                            (size_t)filePemLen);
                /* First call sizes the output buffer. */
                derLen = wc_KeyPemToDer(keyPem, (word32)filePemLen, NULL, 0,
                                        NULL);
                ExpectIntGT(derLen, 0);
                if (derLen > 0) {
                    signerKey = (byte*)XMALLOC((size_t)derLen, NULL,
                                               DYNAMIC_TYPE_TMP_BUFFER);
                    ExpectNotNull(signerKey);
                    if (signerKey != NULL) {
                        derLen = wc_KeyPemToDer(keyPem, (word32)filePemLen,
                                                signerKey, (word32)derLen,
                                                NULL);
                        ExpectIntGT(derLen, 0);
                        signerKeySz = (size_t)derLen;
                    }
                }
            }
            XFREE(keyPem, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFCLOSE(keyFile);
            keyFile = XBADFILE;
        }
    }

    ExpectIntEQ(wc_InitRng(&rng), 0);
    if (EXPECT_SUCCESS())
        rngInited = 1;

    for (variant = 0; variant < 2; variant++) {
        wc_PKCS7* p7Enc = NULL;
        byte      encoded[4096];
        int       encodedSz = 0;
        PKCS7*    p7Ver = NULL;
        X509_STORE* store = NULL;
        const byte* encodedPtr = NULL;
        STACK_OF(X509)* signers = NULL;
        X509* reportedSigner = NULL;
        byte* reportedSignerDer = NULL;
        int   reportedSignerDerSz = 0;
        X509* caForStore = NULL;
        BIO*  caForStoreBio = NULL;

        /* ---- Encode: signer=server-cert, extra bundle cert=ca. ---- */
        ExpectNotNull(p7Enc = wc_PKCS7_New(HEAP_HINT, INVALID_DEVID));
        ExpectIntEQ(wc_PKCS7_Init(p7Enc, HEAP_HINT, INVALID_DEVID), 0);
        ExpectIntEQ(wc_PKCS7_InitWithCert(p7Enc, signerCertDer,
                                          (word32)signerCertDerSz), 0);
        /* wc_PKCS7_AddCertificate prepends to the cert list - the encoded
         * SET therefore ends up [ca, signer], putting the actual signer
         * at index 1 and exercising the sid-selection path (cert[0] is
         * NOT the signer and must be skipped). */
        ExpectIntEQ(wc_PKCS7_AddCertificate(p7Enc, caDer, (word32)caDerSz), 0);

        if (p7Enc != NULL) {
            p7Enc->content      = (byte*)content;
            p7Enc->contentSz    = (word32)sizeof(content);
            p7Enc->encryptOID   = RSAk;
            p7Enc->hashOID      = SHA256h;
            p7Enc->privateKey   = signerKey;
            p7Enc->privateKeySz = (word32)signerKeySz;
            p7Enc->rng          = &rng;
        }

        ExpectIntEQ(wc_PKCS7_SetSignerIdentifierType(p7Enc, sidTypes[variant]),
                    0);

        ExpectIntGT((encodedSz = wc_PKCS7_EncodeSignedData(p7Enc, encoded,
                                                           sizeof(encoded))),
                    0);
        wc_PKCS7_Free(p7Enc);
        p7Enc = NULL;

        /* ---- Parse + verify through the OpenSSL compat layer. ---- */
        encodedPtr = encoded;
        ExpectNotNull(p7Ver = d2i_PKCS7(NULL, &encodedPtr, encodedSz));

        /* Trust store holds only ca-cert. Reload it rather than reusing
         * caX509, since X509_STORE_free takes ownership-like semantics. */
        ExpectNotNull(caForStoreBio = BIO_new_file(caFile, "r"));
        ExpectNotNull(caForStore = PEM_read_bio_X509(caForStoreBio, NULL, 0,
                                                    NULL));
        ExpectNotNull(store = X509_STORE_new());
        ExpectIntEQ(X509_STORE_add_cert(store, caForStore), 1);

        ExpectIntEQ(PKCS7_verify(p7Ver, NULL, store, NULL, NULL, 0), 1);

        /* Snapshot the singleCert / verifyCert pointers and sizes after
         * PKCS7_verify has finished re-parsing the message. A buggy
         * implementation that passes &p7->pkcs7.singleCert (or verifyCert)
         * directly to wolfSSL_d2i_X509 permanently advances the struct
         * field, which corrupts it for any subsequent use - producing a
         * heap-OOB read on the next call since the size isn't advanced.
         * These pointers must stay exactly where they are across repeated
         * get0_signers calls. */
        if (p7Ver != NULL) {
            wc_PKCS7* wcP7 = &((WOLFSSL_PKCS7*)p7Ver)->pkcs7;
            byte*  singleBefore    = wcP7->singleCert;
            word32 singleSzBefore  = wcP7->singleCertSz;
            byte*  verifyBefore    = wcP7->verifyCert;
            word32 verifySzBefore  = wcP7->verifyCertSz;
            int    i;

            /* Call get0_signers repeatedly. Each invocation must return
             * the correct cert and must not mutate singleCert/verifyCert.
             * Three iterations so the "second call reads past the end"
             * pattern (the exact OOB the reporter hit) is exercised. */
            for (i = 0; i < 3; i++) {
                ExpectNotNull(signers = PKCS7_get0_signers(p7Ver, NULL, 0));
                ExpectIntEQ(sk_X509_num(signers), 1);
                ExpectNotNull(reportedSigner = sk_X509_value(signers, 0));
                ExpectIntGT(reportedSignerDerSz = i2d_X509(reportedSigner,
                                                      &reportedSignerDer), 0);
                /* DER-compare: reportedSigner must equal server-cert and
                 * must NOT equal ca-cert (the pre-fix signer-confusion
                 * outcome). */
                ExpectIntEQ(reportedSignerDerSz, signerCertDerSz);
                if (reportedSignerDer != NULL && signerCertDer != NULL) {
                    ExpectIntEQ(XMEMCMP(reportedSignerDer, signerCertDer,
                                        (size_t)signerCertDerSz), 0);
                    if (reportedSignerDerSz == caDerSz) {
                        ExpectIntNE(XMEMCMP(reportedSignerDer, caDer,
                                            (size_t)caDerSz), 0);
                    }
                }
                XFREE(reportedSignerDer, NULL, DYNAMIC_TYPE_OPENSSL);
                reportedSignerDer = NULL;
                sk_X509_pop_free(signers, NULL);
                signers = NULL;

                /* Struct fields must survive every call unchanged. */
                ExpectPtrEq(wcP7->singleCert,   singleBefore);
                ExpectIntEQ(wcP7->singleCertSz, singleSzBefore);
                ExpectPtrEq(wcP7->verifyCert,   verifyBefore);
                ExpectIntEQ(wcP7->verifyCertSz, verifySzBefore);
            }
        }

        PKCS7_free(p7Ver);
        X509_STORE_free(store);
        X509_free(caForStore);
        BIO_free(caForStoreBio);
    }

    if (rngInited)
        wc_FreeRng(&rng);

    XFREE(signerKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(signerCertDer, NULL, DYNAMIC_TYPE_OPENSSL);
    XFREE(caDer, NULL, DYNAMIC_TYPE_OPENSSL);
    X509_free(signerCertX509);
    X509_free(caX509);
    BIO_free(signerCertBio);
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

