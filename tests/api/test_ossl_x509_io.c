/* test_ossl_x509_io.c
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

#include <wolfssl/ssl.h>
#include <wolfssl/internal.h>
#ifdef OPENSSL_EXTRA
    #include <wolfssl/openssl/pem.h>
#endif
#include <tests/api/api.h>
#include <tests/api/test_ossl_x509_io.h>

int test_wolfSSL_i2d_X509(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(USE_CERT_BUFFERS_2048) && !defined(NO_RSA)
    const unsigned char* cert_buf = server_cert_der_2048;
    unsigned char* out = NULL;
    unsigned char* tmp = NULL;
    const unsigned char* nullPtr = NULL;
    const unsigned char notCert[2] = { 0x30, 0x00 };
    const unsigned char* notCertPtr = notCert;
    X509* cert = NULL;

    ExpectNull(d2i_X509(NULL, NULL, sizeof_server_cert_der_2048));
    ExpectNull(d2i_X509(NULL, &nullPtr, sizeof_server_cert_der_2048));
    ExpectNull(d2i_X509(NULL, &cert_buf, 0));
    ExpectNull(d2i_X509(NULL, &notCertPtr, sizeof(notCert)));
    ExpectNotNull(d2i_X509(&cert, &cert_buf, sizeof_server_cert_der_2048));
    /* Pointer should be advanced */
    ExpectPtrGT(cert_buf, server_cert_der_2048);
    ExpectIntGT(i2d_X509(cert, &out), 0);
    ExpectNotNull(out);
    tmp = out;
    ExpectIntGT(i2d_X509(cert, &tmp), 0);
    ExpectPtrGT(tmp, out);
#if defined(WOLFSSL_CERT_GEN) && !defined(NO_BIO) && !defined(NO_FILESYSTEM)
    ExpectIntEQ(wolfSSL_PEM_write_X509(XBADFILE, NULL), 0);
    ExpectIntEQ(wolfSSL_PEM_write_X509(XBADFILE, cert), 0);
    ExpectIntEQ(wolfSSL_PEM_write_X509(stderr, cert), 1);
#endif

    XFREE(out, NULL, DYNAMIC_TYPE_OPENSSL);
    X509_free(cert);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_PEM_read_X509(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_CRL) && !defined(NO_FILESYSTEM) && \
    !defined(NO_RSA)
    X509 *x509 = NULL;
    XFILE fp = XBADFILE;

    ExpectTrue((fp = XFOPEN(svrCertFile, "rb")) != XBADFILE);
    ExpectNotNull(x509 = (X509 *)PEM_read_X509(fp, (X509 **)NULL, NULL, NULL));
    X509_free(x509);
    if (fp != XBADFILE)
        XFCLOSE(fp);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_PEM_write_bio_X509(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(OPENSSL_ALL) && \
    defined(WOLFSSL_AKID_NAME) && defined(WOLFSSL_CERT_EXT) && \
    defined(WOLFSSL_CERT_GEN) && !defined(NO_BIO) && !defined(NO_RSA) && \
    !defined(NO_FILESYSTEM)
    /* This test contains the hard coded expected
     * lengths. Update if necessary */
    XFILE fp = XBADFILE;
    WOLFSSL_EVP_PKEY *priv = NULL;

    BIO* input = NULL;
    BIO* output = NULL;
    X509* x509a = NULL;
    X509* x509b = NULL;
    X509* empty = NULL;

    ASN1_TIME* notBeforeA = NULL;
    ASN1_TIME* notAfterA  = NULL;
#ifndef NO_ASN_TIME
    ASN1_TIME* notBeforeB = NULL;
    ASN1_TIME* notAfterB  = NULL;
#endif
    int expectedLen;

    ExpectTrue((fp = XFOPEN("certs/server-key.pem", "rb")) != XBADFILE);
    ExpectNotNull(priv = wolfSSL_PEM_read_PrivateKey(fp, NULL, NULL, NULL));
    if (fp != XBADFILE) {
        XFCLOSE(fp);
        fp = XBADFILE;
    }

    ExpectNotNull(input = BIO_new_file("certs/test/cert-ext-multiple.pem",
        "rb"));
    ExpectIntEQ(wolfSSL_BIO_get_len(input), 2000);

    /* read PEM into X509 struct, get notBefore / notAfter to verify against */
    ExpectNotNull(PEM_read_bio_X509(input, &x509a, NULL, NULL));
    ExpectNotNull(notBeforeA = X509_get_notBefore(x509a));
    ExpectNotNull(notAfterA = X509_get_notAfter(x509a));

    /* write X509 back to PEM BIO; no need to sign as nothing changed. */
    ExpectNotNull(output = BIO_new(wolfSSL_BIO_s_mem()));
    ExpectNotNull(empty = wolfSSL_X509_new());
    ExpectIntEQ(PEM_write_bio_X509(NULL, NULL), WOLFSSL_FAILURE);
    ExpectIntEQ(PEM_write_bio_X509(output, NULL), WOLFSSL_FAILURE);
    ExpectIntEQ(PEM_write_bio_X509(NULL, x509a), WOLFSSL_FAILURE);
    ExpectIntEQ(PEM_write_bio_X509(output, empty), WOLFSSL_FAILURE);
    ExpectIntEQ(PEM_write_bio_X509(output, x509a), WOLFSSL_SUCCESS);
    /* compare length against expected */
    expectedLen = 2000;
    ExpectIntEQ(wolfSSL_BIO_get_len(output), expectedLen);
    wolfSSL_X509_free(empty);

#ifndef NO_ASN_TIME
    /* read exported X509 PEM back into struct, sanity check on export,
     * make sure notBefore/notAfter are the same and certs are identical. */
    ExpectNotNull(PEM_read_bio_X509(output, &x509b, NULL, NULL));
    ExpectNotNull(notBeforeB = X509_get_notBefore(x509b));
    ExpectNotNull(notAfterB = X509_get_notAfter(x509b));
    ExpectIntEQ(ASN1_TIME_compare(notBeforeA, notBeforeB), 0);
    ExpectIntEQ(ASN1_TIME_compare(notAfterA, notAfterB), 0);
    ExpectIntEQ(0, wolfSSL_X509_cmp(x509a, x509b));
    X509_free(x509b);
    x509b = NULL;
#endif

    /* Reset output buffer */
    BIO_free(output);
    output = NULL;
    ExpectNotNull(output = BIO_new(wolfSSL_BIO_s_mem()));

    /* Test forcing the AKID to be generated just from KeyIdentifier */
    if (EXPECT_SUCCESS() && x509a->authKeyIdSrc != NULL) {
        XMEMMOVE(x509a->authKeyIdSrc, x509a->authKeyId, x509a->authKeyIdSz);
        x509a->authKeyId = x509a->authKeyIdSrc;
        x509a->authKeyIdSrc = NULL;
        x509a->authKeyIdSrcSz = 0;
    }

    /* Resign to re-generate the der */
    ExpectIntGT(wolfSSL_X509_sign(x509a, priv, EVP_sha256()), 0);

    ExpectIntEQ(PEM_write_bio_X509(output, x509a), WOLFSSL_SUCCESS);

    /* Check that we generate a smaller output since the AKID will
     * only contain the KeyIdentifier without any additional
     * information */

    /* Here we copy the validity struct from the original */
    expectedLen = 1688;
    ExpectIntEQ(wolfSSL_BIO_get_len(output), expectedLen);

    /* Reset buffers and x509 */
    BIO_free(input);
    input = NULL;
    BIO_free(output);
    output = NULL;
    X509_free(x509a);
    x509a = NULL;

    /* test CA and basicConstSet values are encoded when
     * the cert is a CA */
    ExpectNotNull(input = BIO_new_file("certs/server-cert.pem", "rb"));

    /* read PEM into X509 struct */
    ExpectNotNull(PEM_read_bio_X509(input, &x509a, NULL, NULL));

    /* write X509 back to PEM BIO; no need to sign as nothing changed */
    ExpectNotNull(output = BIO_new(wolfSSL_BIO_s_mem()));
    ExpectIntEQ(PEM_write_bio_X509(output, x509a), WOLFSSL_SUCCESS);

    /* read exported X509 PEM back into struct, ensure isCa and basicConstSet
     * values are maintained and certs are identical.*/
    ExpectNotNull(PEM_read_bio_X509(output, &x509b, NULL, NULL));
    ExpectIntEQ(x509b->isCa, 1);
    ExpectIntEQ(x509b->basicConstSet, 1);
    ExpectIntEQ(0, wolfSSL_X509_cmp(x509a, x509b));

    X509_free(x509a);
    x509a = NULL;
    X509_free(x509b);
    x509b = NULL;
    BIO_free(input);
    input = NULL;
    BIO_free(output);
    output = NULL;

    /* test CA and basicConstSet values are encoded when
     * the cert is not CA */
    ExpectNotNull(input = BIO_new_file("certs/client-uri-cert.pem", "rb"));

    /* read PEM into X509 struct */
    ExpectNotNull(PEM_read_bio_X509(input, &x509a, NULL, NULL));

    /* write X509 back to PEM BIO; no need to sign as nothing changed */
    ExpectNotNull(output = BIO_new(wolfSSL_BIO_s_mem()));
    ExpectIntEQ(PEM_write_bio_X509(output, x509a), WOLFSSL_SUCCESS);

    /* read exported X509 PEM back into struct, ensure isCa and
     * basicConstSet values are maintained and certs are identical */
    ExpectNotNull(PEM_read_bio_X509(output, &x509b, NULL, NULL));
    ExpectIntEQ(x509b->isCa, 0);
    ExpectIntEQ(x509b->basicConstSet, 1);
    ExpectIntEQ(0, wolfSSL_X509_cmp(x509a, x509b));

    wolfSSL_EVP_PKEY_free(priv);
    X509_free(x509a);
    X509_free(x509b);
    BIO_free(input);
    BIO_free(output);
#endif
    return EXPECT_RESULT();
}

