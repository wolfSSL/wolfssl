/* test_ossl_rsa.c
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

#include <tests/unit.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/openssl/rsa.h>
#include <wolfssl/openssl/pem.h>
#include <wolfssl/internal.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_ossl_rsa.h>

/*******************************************************************************
 * RSA OpenSSL compatibility API Testing
 ******************************************************************************/

int test_wolfSSL_RSA(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)
    RSA* rsa = NULL;
    const BIGNUM *n = NULL;
    const BIGNUM *e = NULL;
    const BIGNUM *d = NULL;
    const BIGNUM *p = NULL;
    const BIGNUM *q = NULL;
    const BIGNUM *dmp1 = NULL;
    const BIGNUM *dmq1 = NULL;
    const BIGNUM *iqmp = NULL;

    ExpectNotNull(rsa = RSA_new());
    ExpectIntEQ(RSA_size(NULL), 0);
    ExpectIntEQ(RSA_size(rsa), 0);
    ExpectIntEQ(RSA_set0_key(rsa, NULL, NULL, NULL), 0);
    ExpectIntEQ(RSA_set0_crt_params(rsa, NULL, NULL, NULL), 0);
    ExpectIntEQ(RSA_set0_factors(rsa, NULL, NULL), 0);
#ifdef WOLFSSL_RSA_KEY_CHECK
    ExpectIntEQ(RSA_check_key(rsa), 0);
#endif

    RSA_free(rsa);
    rsa = NULL;
    ExpectNotNull(rsa = RSA_generate_key(2048, 3, NULL, NULL));
    ExpectIntEQ(RSA_size(rsa), 256);

#if (!defined(HAVE_FIPS) || FIPS_VERSION3_GT(6,0,0)) && !defined(HAVE_SELFTEST)
    {
        /* Test setting only subset of parameters */
        RSA *rsa2 = NULL;
        unsigned char hash[SHA256_DIGEST_LENGTH];
        unsigned char signature[2048/8];
        unsigned int signatureLen = 0;
        BIGNUM* n2 = NULL;
        BIGNUM* e2 = NULL;
        BIGNUM* d2 = NULL;
        BIGNUM* p2 = NULL;
        BIGNUM* q2 = NULL;
        BIGNUM* dmp12 = NULL;
        BIGNUM* dmq12 = NULL;
        BIGNUM* iqmp2 = NULL;

        XMEMSET(hash, 0, sizeof(hash));
        RSA_get0_key(rsa, &n, &e, &d);
        RSA_get0_factors(rsa, &p, &q);
        RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);

        ExpectIntEQ(RSA_sign(NID_sha256, hash, sizeof(hash), signature,
            &signatureLen, rsa), 1);
        /* Quick sanity check */
        ExpectIntEQ(RSA_verify(NID_sha256, hash, sizeof(hash), signature,
            signatureLen, rsa), 1);

        /* Verifying */
        ExpectNotNull(n2 = BN_dup(n));
        ExpectNotNull(e2 = BN_dup(e));
        ExpectNotNull(p2 = BN_dup(p));
        ExpectNotNull(q2 = BN_dup(q));
        ExpectNotNull(dmp12 = BN_dup(dmp1));
        ExpectNotNull(dmq12 = BN_dup(dmq1));
        ExpectNotNull(iqmp2 = BN_dup(iqmp));

        ExpectNotNull(rsa2 = RSA_new());
        ExpectIntEQ(RSA_set0_key(rsa2, n2, e2, NULL), 1);
        if (EXPECT_SUCCESS()) {
            n2 = NULL;
            e2 = NULL;
        }
        ExpectIntEQ(RSA_verify(NID_sha256, hash, sizeof(hash), signature,
            signatureLen, rsa2), 1);
        ExpectIntEQ(RSA_set0_factors(rsa2, p2, q2), 1);
        if (EXPECT_SUCCESS()) {
            p2 = NULL;
            q2 = NULL;
        }
        ExpectIntEQ(RSA_verify(NID_sha256, hash, sizeof(hash), signature,
            signatureLen, rsa2), 1);
        ExpectIntEQ(RSA_set0_crt_params(rsa2, dmp12, dmq12, iqmp2), 1);
        if (EXPECT_SUCCESS()) {
            dmp12 = NULL;
            dmq12 = NULL;
            iqmp2 = NULL;
        }
        ExpectIntEQ(RSA_verify(NID_sha256, hash, sizeof(hash), signature,
            signatureLen, rsa2), 1);
        RSA_free(rsa2);
        rsa2 = NULL;

        BN_free(iqmp2);
        iqmp2 = NULL;
        BN_free(dmq12);
        dmq12 = NULL;
        BN_free(dmp12);
        dmp12 = NULL;
        BN_free(q2);
        q2 = NULL;
        BN_free(p2);
        p2 = NULL;
        BN_free(e2);
        e2 = NULL;
        BN_free(n2);
        n2 = NULL;

        ExpectNotNull(n2 = BN_dup(n));
        ExpectNotNull(e2 = BN_dup(e));
        ExpectNotNull(d2 = BN_dup(d));
        ExpectNotNull(p2 = BN_dup(p));
        ExpectNotNull(q2 = BN_dup(q));
        ExpectNotNull(dmp12 = BN_dup(dmp1));
        ExpectNotNull(dmq12 = BN_dup(dmq1));
        ExpectNotNull(iqmp2 = BN_dup(iqmp));

        /* Signing */
        XMEMSET(signature, 0, sizeof(signature));
        ExpectNotNull(rsa2 = RSA_new());
        ExpectIntEQ(RSA_set0_key(rsa2, n2, e2, d2), 1);
        if (EXPECT_SUCCESS()) {
            n2 = NULL;
            e2 = NULL;
            d2 = NULL;
        }
#if defined(WOLFSSL_SP_MATH) && !defined(RSA_LOW_MEM)
        /* SP is not support signing without CRT parameters. */
        ExpectIntEQ(RSA_sign(NID_sha256, hash, sizeof(hash), signature,
            &signatureLen, rsa2), 0);
        ExpectIntEQ(RSA_set0_factors(rsa2, p2, q2), 1);
        if (EXPECT_SUCCESS()) {
            p2 = NULL;
            q2 = NULL;
        }
        ExpectIntEQ(RSA_sign(NID_sha256, hash, sizeof(hash), signature,
            &signatureLen, rsa2), 0);
#else
        ExpectIntEQ(RSA_sign(NID_sha256, hash, sizeof(hash), signature,
            &signatureLen, rsa2), 1);
        ExpectIntEQ(RSA_verify(NID_sha256, hash, sizeof(hash), signature,
            signatureLen, rsa), 1);
        ExpectIntEQ(RSA_set0_factors(rsa2, p2, q2), 1);
        if (EXPECT_SUCCESS()) {
            p2 = NULL;
            q2 = NULL;
        }
        XMEMSET(signature, 0, sizeof(signature));
        ExpectIntEQ(RSA_sign(NID_sha256, hash, sizeof(hash), signature,
            &signatureLen, rsa2), 1);
        ExpectIntEQ(RSA_verify(NID_sha256, hash, sizeof(hash), signature,
            signatureLen, rsa), 1);
#endif
        ExpectIntEQ(RSA_set0_crt_params(rsa2, dmp12, dmq12, iqmp2), 1);
        if (EXPECT_SUCCESS()) {
            dmp12 = NULL;
            dmq12 = NULL;
            iqmp2 = NULL;
        }
        ExpectIntEQ(RSA_sign(NID_sha256, hash, sizeof(hash), signature,
            &signatureLen, rsa2), 1);
        ExpectIntEQ(RSA_verify(NID_sha256, hash, sizeof(hash), signature,
            signatureLen, rsa), 1);
        RSA_free(rsa2);
        rsa2 = NULL;

        BN_free(iqmp2);
        BN_free(dmq12);
        BN_free(dmp12);
        BN_free(q2);
        BN_free(p2);
        BN_free(d2);
        BN_free(e2);
        BN_free(n2);
    }
#endif

#ifdef WOLFSSL_RSA_KEY_CHECK
    ExpectIntEQ(RSA_check_key(NULL), 0);
    ExpectIntEQ(RSA_check_key(rsa), 1);
#endif

    /* sanity check */
    ExpectIntEQ(RSA_bits(NULL), 0);

    /* key */
    ExpectIntEQ(RSA_bits(rsa), 2048);
    RSA_get0_key(rsa, &n, &e, &d);
    ExpectPtrEq(rsa->n, n);
    ExpectPtrEq(rsa->e, e);
    ExpectPtrEq(rsa->d, d);
    n = NULL;
    e = NULL;
    d = NULL;
    ExpectNotNull(n = BN_new());
    ExpectNotNull(e = BN_new());
    ExpectNotNull(d = BN_new());
    ExpectIntEQ(RSA_set0_key(rsa, (BIGNUM*)n, (BIGNUM*)e, (BIGNUM*)d), 1);
    if (EXPECT_FAIL()) {
        BN_free((BIGNUM*)n);
        BN_free((BIGNUM*)e);
        BN_free((BIGNUM*)d);
    }
    ExpectPtrEq(rsa->n, n);
    ExpectPtrEq(rsa->e, e);
    ExpectPtrEq(rsa->d, d);
    ExpectIntEQ(RSA_set0_key(rsa, NULL, NULL, NULL), 1);
    ExpectIntEQ(RSA_set0_key(NULL, (BIGNUM*)n, (BIGNUM*)e, (BIGNUM*)d), 0);

    /* crt_params */
    RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);
    ExpectPtrEq(rsa->dmp1, dmp1);
    ExpectPtrEq(rsa->dmq1, dmq1);
    ExpectPtrEq(rsa->iqmp, iqmp);
    dmp1 = NULL;
    dmq1 = NULL;
    iqmp = NULL;
    ExpectNotNull(dmp1 = BN_new());
    ExpectNotNull(dmq1 = BN_new());
    ExpectNotNull(iqmp = BN_new());
    ExpectIntEQ(RSA_set0_crt_params(rsa, (BIGNUM*)dmp1, (BIGNUM*)dmq1,
        (BIGNUM*)iqmp), 1);
    if (EXPECT_FAIL()) {
        BN_free((BIGNUM*)dmp1);
        BN_free((BIGNUM*)dmq1);
        BN_free((BIGNUM*)iqmp);
    }
    ExpectPtrEq(rsa->dmp1, dmp1);
    ExpectPtrEq(rsa->dmq1, dmq1);
    ExpectPtrEq(rsa->iqmp, iqmp);
    ExpectIntEQ(RSA_set0_crt_params(rsa, NULL, NULL, NULL), 1);
    ExpectIntEQ(RSA_set0_crt_params(NULL, (BIGNUM*)dmp1, (BIGNUM*)dmq1,
        (BIGNUM*)iqmp), 0);
    RSA_get0_crt_params(NULL, NULL, NULL, NULL);
    RSA_get0_crt_params(rsa, NULL, NULL, NULL);
    RSA_get0_crt_params(NULL, &dmp1, &dmq1, &iqmp);
    ExpectNull(dmp1);
    ExpectNull(dmq1);
    ExpectNull(iqmp);

    /* factors */
    RSA_get0_factors(rsa, NULL, NULL);
    RSA_get0_factors(rsa, &p, &q);
    ExpectPtrEq(rsa->p, p);
    ExpectPtrEq(rsa->q, q);
    p = NULL;
    q = NULL;
    ExpectNotNull(p = BN_new());
    ExpectNotNull(q = BN_new());
    ExpectIntEQ(RSA_set0_factors(rsa, (BIGNUM*)p, (BIGNUM*)q), 1);
    if (EXPECT_FAIL()) {
        BN_free((BIGNUM*)p);
        BN_free((BIGNUM*)q);
    }
    ExpectPtrEq(rsa->p, p);
    ExpectPtrEq(rsa->q, q);
    ExpectIntEQ(RSA_set0_factors(rsa, NULL, NULL), 1);
    ExpectIntEQ(RSA_set0_factors(NULL, (BIGNUM*)p, (BIGNUM*)q), 0);
    RSA_get0_factors(NULL, NULL, NULL);
    RSA_get0_factors(NULL, &p, &q);
    ExpectNull(p);
    ExpectNull(q);

    ExpectIntEQ(BN_hex2bn(&rsa->n, "1FFFFF"), 1);
    ExpectIntEQ(RSA_bits(rsa), 21);
    RSA_free(rsa);
    rsa = NULL;

#if !defined(USE_FAST_MATH) || (FP_MAX_BITS >= (3072*2))
    ExpectNotNull(rsa = RSA_generate_key(3072, 17, NULL, NULL));
    ExpectIntEQ(RSA_size(rsa), 384);
    ExpectIntEQ(RSA_bits(rsa), 3072);
    RSA_free(rsa);
    rsa = NULL;
#endif

    /* remove for now with odd key size until adjusting rsa key size check with
       wc_MakeRsaKey()
    ExpectNotNull(rsa = RSA_generate_key(2999, 65537, NULL, NULL));
    RSA_free(rsa);
    rsa = NULL;
    */

    ExpectNull(RSA_generate_key(-1, 3, NULL, NULL));
    ExpectNull(RSA_generate_key(RSA_MIN_SIZE - 1, 3, NULL, NULL));
    ExpectNull(RSA_generate_key(RSA_MAX_SIZE + 1, 3, NULL, NULL));
    ExpectNull(RSA_generate_key(2048, 0, NULL, NULL));


#if !defined(NO_FILESYSTEM) && !defined(NO_ASN)
    {
        byte buff[FOURK_BUF];
        byte der[FOURK_BUF];
        const char PrivKeyPemFile[] = "certs/client-keyEnc.pem";

        XFILE f = XBADFILE;
        int bytes = 0;

        /* test loading encrypted RSA private pem w/o password */
        ExpectTrue((f = XFOPEN(PrivKeyPemFile, "rb")) != XBADFILE);
        ExpectIntGT(bytes = (int)XFREAD(buff, 1, sizeof(buff), f), 0);
        if (f != XBADFILE)
            XFCLOSE(f);
        XMEMSET(der, 0, sizeof(der));
        /* test that error value is returned with no password */
        ExpectIntLT(wc_KeyPemToDer(buff, bytes, der, (word32)sizeof(der), ""),
            0);
    }
#endif
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_RSA_DER(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_KEY_GEN) && !defined(NO_RSA) && defined(OPENSSL_EXTRA)
    RSA *rsa = NULL;
    int i;
    const unsigned char *buff = NULL;
    unsigned char *newBuff = NULL;

    struct tbl_s
    {
        const unsigned char *der;
        int sz;
    } tbl[] = {

#ifdef USE_CERT_BUFFERS_1024
        {client_key_der_1024, sizeof_client_key_der_1024},
        {server_key_der_1024, sizeof_server_key_der_1024},
#endif
#ifdef USE_CERT_BUFFERS_2048
        {client_key_der_2048, sizeof_client_key_der_2048},
        {server_key_der_2048, sizeof_server_key_der_2048},
#endif
        {NULL, 0}
    };

    /* Public Key DER */
    struct tbl_s pub[] = {
#ifdef USE_CERT_BUFFERS_1024
        {client_keypub_der_1024, sizeof_client_keypub_der_1024},
#endif
#ifdef USE_CERT_BUFFERS_2048
        {client_keypub_der_2048, sizeof_client_keypub_der_2048},
#endif
        {NULL, 0}
    };

    ExpectNull(d2i_RSAPublicKey(&rsa, NULL, pub[0].sz));
    buff = pub[0].der;
    ExpectNull(d2i_RSAPublicKey(&rsa, &buff, 1));
    ExpectNull(d2i_RSAPrivateKey(&rsa, NULL, tbl[0].sz));
    buff = tbl[0].der;
    ExpectNull(d2i_RSAPrivateKey(&rsa, &buff, 1));

    ExpectIntEQ(i2d_RSAPublicKey(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    rsa = RSA_new();
    ExpectIntEQ(i2d_RSAPublicKey(rsa, NULL), 0);
    RSA_free(rsa);
    rsa = NULL;

    for (i = 0; tbl[i].der != NULL; i++)
    {
        /* Passing in pointer results in pointer moving. */
        buff = tbl[i].der;
        ExpectNotNull(d2i_RSAPublicKey(&rsa, &buff, tbl[i].sz));
        ExpectNotNull(rsa);
        RSA_free(rsa);
        rsa = NULL;
    }
    for (i = 0; tbl[i].der != NULL; i++)
    {
        /* Passing in pointer results in pointer moving. */
        buff = tbl[i].der;
        ExpectNotNull(d2i_RSAPrivateKey(&rsa, &buff, tbl[i].sz));
        ExpectNotNull(rsa);
        RSA_free(rsa);
        rsa = NULL;
    }

    for (i = 0; pub[i].der != NULL; i++)
    {
        buff = pub[i].der;
        ExpectNotNull(d2i_RSAPublicKey(&rsa, &buff, pub[i].sz));
        ExpectNotNull(rsa);
        ExpectIntEQ(i2d_RSAPublicKey(rsa, NULL), pub[i].sz);
        newBuff = NULL;
        ExpectIntEQ(i2d_RSAPublicKey(rsa, &newBuff), pub[i].sz);
        ExpectNotNull(newBuff);
        ExpectIntEQ(XMEMCMP((void *)newBuff, (void *)pub[i].der, pub[i].sz), 0);
        XFREE((void *)newBuff, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        RSA_free(rsa);
        rsa = NULL;
    }
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_RSA_print(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_FILESYSTEM) && \
   !defined(NO_STDIO_FILESYSTEM) && \
   !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN) && \
   !defined(NO_BIO) && defined(XFPRINTF)
    BIO *bio = NULL;
    WOLFSSL_RSA* rsa = NULL;

    ExpectNotNull(bio = BIO_new_fd(STDERR_FILENO, BIO_NOCLOSE));
    ExpectNotNull(rsa = RSA_new());

    ExpectIntEQ(RSA_print(NULL, rsa, 0), -1);
    ExpectIntEQ(RSA_print_fp(XBADFILE, rsa, 0), 0);
    ExpectIntEQ(RSA_print(bio, NULL, 0), -1);
    ExpectIntEQ(RSA_print_fp(stderr, NULL, 0), 0);
    /* Some very large number of indent spaces. */
    ExpectIntEQ(RSA_print(bio, rsa, 128), -1);
    /* RSA is empty. */
    ExpectIntEQ(RSA_print(bio, rsa, 0), 0);
    ExpectIntEQ(RSA_print_fp(stderr, rsa, 0), 0);

    RSA_free(rsa);
    rsa = NULL;
    ExpectNotNull(rsa = RSA_generate_key(2048, 3, NULL, NULL));

    ExpectIntEQ(RSA_print(bio, rsa, 0), 1);
    ExpectIntEQ(RSA_print(bio, rsa, 4), 1);
    ExpectIntEQ(RSA_print(bio, rsa, -1), 1);
    ExpectIntEQ(RSA_print_fp(stderr, rsa, 0), 1);
    ExpectIntEQ(RSA_print_fp(stderr, rsa, 4), 1);
    ExpectIntEQ(RSA_print_fp(stderr, rsa, -1), 1);

    BIO_free(bio);
    RSA_free(rsa);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_RSA_padding_add_PKCS1_PSS(void)
{
    EXPECT_DECLS;
#ifndef NO_RSA
#if defined(OPENSSL_ALL) && defined(WC_RSA_PSS) && !defined(WC_NO_RNG)
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2))
    RSA *rsa = NULL;
    const unsigned char *derBuf = client_key_der_2048;
    unsigned char em[256] = {0}; /* len = 2048/8 */
    /* Random data simulating a hash */
    const unsigned char mHash[WC_SHA256_DIGEST_SIZE] = {
        0x28, 0x6e, 0xfd, 0xf8, 0x76, 0xc7, 0x00, 0x3d, 0x91, 0x4e, 0x59, 0xe4,
        0x8e, 0xb7, 0x40, 0x7b, 0xd1, 0x0c, 0x98, 0x4b, 0xe3, 0x3d, 0xb3, 0xeb,
        0x6f, 0x8a, 0x3c, 0x42, 0xab, 0x21, 0xad, 0x28
    };

    ExpectNotNull(d2i_RSAPrivateKey(&rsa, &derBuf, sizeof_client_key_der_2048));
    ExpectIntEQ(RSA_padding_add_PKCS1_PSS(NULL, em, mHash, EVP_sha256(),
        RSA_PSS_SALTLEN_DIGEST), 0);
    ExpectIntEQ(RSA_padding_add_PKCS1_PSS(rsa, NULL, mHash, EVP_sha256(),
        RSA_PSS_SALTLEN_DIGEST), 0);
    ExpectIntEQ(RSA_padding_add_PKCS1_PSS(rsa, em, NULL, EVP_sha256(),
        RSA_PSS_SALTLEN_DIGEST), 0);
    ExpectIntEQ(RSA_padding_add_PKCS1_PSS(rsa, em, mHash, NULL,
        RSA_PSS_SALTLEN_DIGEST), 0);
    ExpectIntEQ(RSA_padding_add_PKCS1_PSS(rsa, em, mHash, EVP_sha256(), -5), 0);

    ExpectIntEQ(RSA_verify_PKCS1_PSS(NULL, mHash, EVP_sha256(), em,
        RSA_PSS_SALTLEN_MAX_SIGN), 0);
    ExpectIntEQ(RSA_verify_PKCS1_PSS(rsa, NULL, EVP_sha256(), em,
        RSA_PSS_SALTLEN_MAX_SIGN), 0);
    ExpectIntEQ(RSA_verify_PKCS1_PSS(rsa, mHash, NULL, em,
        RSA_PSS_SALTLEN_MAX_SIGN), 0);
    ExpectIntEQ(RSA_verify_PKCS1_PSS(rsa, mHash, EVP_sha256(), NULL,
        RSA_PSS_SALTLEN_MAX_SIGN), 0);
    ExpectIntEQ(RSA_verify_PKCS1_PSS(rsa, mHash, EVP_sha256(), em,
        RSA_PSS_SALTLEN_MAX_SIGN), 0);
    ExpectIntEQ(RSA_verify_PKCS1_PSS(rsa, mHash, EVP_sha256(), em, -5), 0);

    ExpectIntEQ(RSA_padding_add_PKCS1_PSS(rsa, em, mHash, EVP_sha256(),
        RSA_PSS_SALTLEN_DIGEST), 1);
    ExpectIntEQ(RSA_verify_PKCS1_PSS(rsa, mHash, EVP_sha256(), em,
        RSA_PSS_SALTLEN_DIGEST), 1);

    ExpectIntEQ(RSA_padding_add_PKCS1_PSS(rsa, em, mHash, EVP_sha256(),
        RSA_PSS_SALTLEN_MAX_SIGN), 1);
    ExpectIntEQ(RSA_verify_PKCS1_PSS(rsa, mHash, EVP_sha256(), em,
        RSA_PSS_SALTLEN_MAX_SIGN), 1);

    ExpectIntEQ(RSA_padding_add_PKCS1_PSS(rsa, em, mHash, EVP_sha256(),
        RSA_PSS_SALTLEN_MAX), 1);
    ExpectIntEQ(RSA_verify_PKCS1_PSS(rsa, mHash, EVP_sha256(), em,
        RSA_PSS_SALTLEN_MAX), 1);

    ExpectIntEQ(RSA_padding_add_PKCS1_PSS(rsa, em, mHash, EVP_sha256(), 10), 1);
    ExpectIntEQ(RSA_verify_PKCS1_PSS(rsa, mHash, EVP_sha256(), em, 10), 1);

    RSA_free(rsa);
#endif /* !HAVE_FIPS || HAVE_FIPS_VERSION > 2 */
#endif /* OPENSSL_ALL && WC_RSA_PSS && !WC_NO_RNG*/
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_RSA_sign_sha3(void)
{
    EXPECT_DECLS;
#if !defined(NO_RSA) && defined(WOLFSSL_SHA3) && !defined(WOLFSSL_NOSHA3_256)
#if defined(OPENSSL_ALL) && defined(WC_RSA_PSS) && !defined(WC_NO_RNG)
    RSA* rsa = NULL;
    const unsigned char *derBuf = client_key_der_2048;
    unsigned char sigRet[256] = {0};
    unsigned int sigLen = sizeof(sigRet);
    /* Random data simulating a hash */
    const unsigned char mHash[WC_SHA3_256_DIGEST_SIZE] = {
        0x28, 0x6e, 0xfd, 0xf8, 0x76, 0xc7, 0x00, 0x3d, 0x91, 0x4e, 0x59, 0xe4,
        0x8e, 0xb7, 0x40, 0x7b, 0xd1, 0x0c, 0x98, 0x4b, 0xe3, 0x3d, 0xb3, 0xeb,
        0x6f, 0x8a, 0x3c, 0x42, 0xab, 0x21, 0xad, 0x28
    };

    ExpectNotNull(d2i_RSAPrivateKey(&rsa, &derBuf, sizeof_client_key_der_2048));
    ExpectIntEQ(RSA_sign(NID_sha3_256, mHash, sizeof(mHash), sigRet, &sigLen,
        rsa), 1);

    RSA_free(rsa);
#endif /* OPENSSL_ALL && WC_RSA_PSS && !WC_NO_RNG*/
#endif /* !NO_RSA && WOLFSSL_SHA3 && !WOLFSSL_NOSHA3_256*/
    return EXPECT_RESULT();
}

int test_wolfSSL_RSA_get0_key(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA)
    RSA *rsa = NULL;
    const BIGNUM* n = NULL;
    const BIGNUM* e = NULL;
    const BIGNUM* d = NULL;

    const unsigned char* der;
    int derSz;

#ifdef USE_CERT_BUFFERS_1024
    der = client_key_der_1024;
    derSz = sizeof_client_key_der_1024;
#elif defined(USE_CERT_BUFFERS_2048)
    der = client_key_der_2048;
    derSz = sizeof_client_key_der_2048;
#else
    der = NULL;
    derSz = 0;
#endif

    if (der != NULL) {
        RSA_get0_key(NULL, NULL, NULL, NULL);
        RSA_get0_key(rsa, NULL, NULL, NULL);
        RSA_get0_key(NULL, &n, &e, &d);
        ExpectNull(n);
        ExpectNull(e);
        ExpectNull(d);

        ExpectNotNull(d2i_RSAPrivateKey(&rsa, &der, derSz));
        ExpectNotNull(rsa);

        RSA_get0_key(rsa, NULL, NULL, NULL);
        RSA_get0_key(rsa, &n, NULL, NULL);
        ExpectNotNull(n);
        RSA_get0_key(rsa, NULL, &e, NULL);
        ExpectNotNull(e);
        RSA_get0_key(rsa, NULL, NULL, &d);
        ExpectNotNull(d);
        RSA_get0_key(rsa, &n, &e, &d);
        ExpectNotNull(n);
        ExpectNotNull(e);
        ExpectNotNull(d);

        RSA_free(rsa);
    }
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_RSA_meth(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA)
    RSA *rsa = NULL;
    RSA_METHOD *rsa_meth = NULL;

#ifdef WOLFSSL_KEY_GEN
    ExpectNotNull(rsa = RSA_generate_key(2048, 3, NULL, NULL));
    RSA_free(rsa);
    rsa = NULL;
#else
    ExpectNull(rsa = RSA_generate_key(2048, 3, NULL, NULL));
#endif

    ExpectNotNull(RSA_get_default_method());

    wolfSSL_RSA_meth_free(NULL);

    ExpectNull(wolfSSL_RSA_meth_new(NULL, 0));

    ExpectNotNull(rsa_meth = RSA_meth_new("placeholder RSA method",
        RSA_METHOD_FLAG_NO_CHECK));

#ifndef NO_WOLFSSL_STUB
    ExpectIntEQ(RSA_meth_set_pub_enc(rsa_meth, NULL), 1);
    ExpectIntEQ(RSA_meth_set_pub_dec(rsa_meth, NULL), 1);
    ExpectIntEQ(RSA_meth_set_priv_enc(rsa_meth, NULL), 1);
    ExpectIntEQ(RSA_meth_set_priv_dec(rsa_meth, NULL), 1);
    ExpectIntEQ(RSA_meth_set_init(rsa_meth, NULL), 1);
    ExpectIntEQ(RSA_meth_set_finish(rsa_meth, NULL), 1);
    ExpectIntEQ(RSA_meth_set0_app_data(rsa_meth, NULL), 1);
#endif

    ExpectIntEQ(RSA_flags(NULL), 0);
    RSA_set_flags(NULL, RSA_FLAG_CACHE_PUBLIC);
    RSA_clear_flags(NULL, RSA_FLAG_CACHE_PUBLIC);
    ExpectIntEQ(RSA_test_flags(NULL, RSA_FLAG_CACHE_PUBLIC), 0);

    ExpectNotNull(rsa = RSA_new());
    /* No method set. */
    ExpectIntEQ(RSA_flags(rsa), 0);
    RSA_set_flags(rsa, RSA_FLAG_CACHE_PUBLIC);
    RSA_clear_flags(rsa, RSA_FLAG_CACHE_PUBLIC);
    ExpectIntEQ(RSA_test_flags(rsa, RSA_FLAG_CACHE_PUBLIC), 0);

    ExpectIntEQ(RSA_set_method(NULL, rsa_meth), 1);
    ExpectIntEQ(RSA_set_method(rsa, rsa_meth), 1);
    if (EXPECT_FAIL()) {
        wolfSSL_RSA_meth_free(rsa_meth);
    }
    ExpectNull(RSA_get_method(NULL));
    ExpectPtrEq(RSA_get_method(rsa), rsa_meth);
    ExpectIntEQ(RSA_flags(rsa), RSA_METHOD_FLAG_NO_CHECK);
    RSA_set_flags(rsa, RSA_FLAG_CACHE_PUBLIC);
    ExpectIntNE(RSA_test_flags(rsa, RSA_FLAG_CACHE_PUBLIC), 0);
    ExpectIntEQ(RSA_flags(rsa), RSA_FLAG_CACHE_PUBLIC |
                                RSA_METHOD_FLAG_NO_CHECK);
    RSA_clear_flags(rsa, RSA_FLAG_CACHE_PUBLIC);
    ExpectIntEQ(RSA_test_flags(rsa, RSA_FLAG_CACHE_PUBLIC), 0);
    ExpectIntNE(RSA_flags(rsa), RSA_FLAG_CACHE_PUBLIC);

    /* rsa_meth is freed here */
    RSA_free(rsa);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_RSA_verify(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && !defined(NO_FILESYSTEM)
#ifndef NO_BIO
    XFILE fp = XBADFILE;
    RSA *pKey = NULL;
    RSA *pubKey = NULL;
    X509 *cert = NULL;
    const char *text = "Hello wolfSSL !";
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned char signature[2048/8];
    unsigned int signatureLength;
    byte *buf = NULL;
    BIO *bio = NULL;
    SHA256_CTX c;
    EVP_PKEY *evpPkey = NULL;
    EVP_PKEY *evpPubkey = NULL;
    long lsz = 0;
    size_t sz;

    /* generate hash */
    SHA256_Init(&c);
    SHA256_Update(&c, text, strlen(text));
    SHA256_Final(hash, &c);
#ifdef WOLFSSL_SMALL_STACK_CACHE
    /* workaround for small stack cache case */
    wc_Sha256Free((wc_Sha256*)&c);
#endif

    /* read private key file */
    ExpectTrue((fp = XFOPEN(svrKeyFile, "rb")) != XBADFILE);
    ExpectIntEQ(XFSEEK(fp, 0, XSEEK_END), 0);
    ExpectTrue((lsz = XFTELL(fp)) > 0);
    sz = (size_t)lsz;
    ExpectIntEQ(XFSEEK(fp, 0, XSEEK_SET), 0);
    ExpectNotNull(buf = (byte*)XMALLOC(sz, NULL, DYNAMIC_TYPE_FILE));
    ExpectIntEQ(XFREAD(buf, 1, sz, fp), sz);
    if (fp != XBADFILE) {
        XFCLOSE(fp);
        fp = XBADFILE;
    }

    /* read private key and sign hash data */
    ExpectNotNull(bio = BIO_new_mem_buf(buf, (int)sz));
    ExpectNotNull(evpPkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL));
    ExpectNotNull(pKey = EVP_PKEY_get1_RSA(evpPkey));
    ExpectIntEQ(RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH,
        signature, &signatureLength, pKey), SSL_SUCCESS);

    /* read public key and verify signed data */
    ExpectTrue((fp = XFOPEN(svrCertFile,"rb")) != XBADFILE);
    ExpectNotNull(cert = PEM_read_X509(fp, 0, 0, 0 ));
    if (fp != XBADFILE)
        XFCLOSE(fp);
    ExpectNull(X509_get_pubkey(NULL));
    ExpectNotNull(evpPubkey = X509_get_pubkey(cert));
    ExpectNotNull(pubKey = EVP_PKEY_get1_RSA(evpPubkey));
    ExpectIntEQ(RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature,
        signatureLength, pubKey), SSL_SUCCESS);

    ExpectIntEQ(RSA_verify(NID_sha256, NULL, SHA256_DIGEST_LENGTH, NULL,
        signatureLength, NULL), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(RSA_verify(NID_sha256, NULL, SHA256_DIGEST_LENGTH, signature,
        signatureLength, pubKey), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, NULL,
        signatureLength, pubKey), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature,
        signatureLength, NULL), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));


    RSA_free(pKey);
    EVP_PKEY_free(evpPkey);
    RSA_free(pubKey);
    EVP_PKEY_free(evpPubkey);
    X509_free(cert);
    BIO_free(bio);
    XFREE(buf, NULL, DYNAMIC_TYPE_FILE);
#endif
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_RSA_sign(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA)
    RSA *rsa;
    unsigned char hash[SHA256_DIGEST_LENGTH];
#ifdef USE_CERT_BUFFERS_1024
    const unsigned char* privDer = client_key_der_1024;
    size_t privDerSz = sizeof_client_key_der_1024;
    const unsigned char* pubDer = client_keypub_der_1024;
    size_t pubDerSz = sizeof_client_keypub_der_1024;
    unsigned char signature[1024/8];
#else
    const unsigned char* privDer = client_key_der_2048;
    size_t privDerSz = sizeof_client_key_der_2048;
    const unsigned char* pubDer = client_keypub_der_2048;
    size_t pubDerSz = sizeof_client_keypub_der_2048;
    unsigned char signature[2048/8];
#endif
    unsigned int signatureLen;
    const unsigned char* der;

    XMEMSET(hash, 0, sizeof(hash));

    der = privDer;
    rsa = NULL;
    ExpectNotNull(d2i_RSAPrivateKey(&rsa, &der, privDerSz));

    /* Invalid parameters. */
    ExpectIntEQ(RSA_sign(NID_rsaEncryption, NULL, 0, NULL, NULL, NULL), 0);
    ExpectIntEQ(RSA_sign(NID_rsaEncryption, hash, sizeof(hash), signature,
        &signatureLen, rsa), 0);
    ExpectIntEQ(RSA_sign(NID_sha256, NULL, sizeof(hash), signature,
        &signatureLen, rsa), 0);
    ExpectIntEQ(RSA_sign(NID_sha256, hash, sizeof(hash), NULL,
        &signatureLen, rsa), 0);
    ExpectIntEQ(RSA_sign(NID_sha256, hash, sizeof(hash), signature,
        NULL, rsa), 0);
    ExpectIntEQ(RSA_sign(NID_sha256, hash, sizeof(hash), signature,
        &signatureLen, NULL), 0);

    ExpectIntEQ(RSA_sign(NID_sha256, hash, sizeof(hash), signature,
        &signatureLen, rsa), 1);

    RSA_free(rsa);
    der = pubDer;
    rsa = NULL;
    ExpectNotNull(d2i_RSAPublicKey(&rsa, &der, pubDerSz));

    ExpectIntEQ(RSA_verify(NID_sha256, hash, sizeof(hash), signature,
        signatureLen, rsa), 1);

    RSA_free(rsa);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_RSA_sign_ex(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA)
    RSA *rsa = NULL;
    unsigned char hash[SHA256_DIGEST_LENGTH];
#ifdef USE_CERT_BUFFERS_1024
    const unsigned char* privDer = client_key_der_1024;
    size_t privDerSz = sizeof_client_key_der_1024;
    const unsigned char* pubDer = client_keypub_der_1024;
    size_t pubDerSz = sizeof_client_keypub_der_1024;
    unsigned char signature[1024/8];
#else
    const unsigned char* privDer = client_key_der_2048;
    size_t privDerSz = sizeof_client_key_der_2048;
    const unsigned char* pubDer = client_keypub_der_2048;
    size_t pubDerSz = sizeof_client_keypub_der_2048;
    unsigned char signature[2048/8];
#endif
    unsigned int signatureLen;
    const unsigned char* der;
    unsigned char encodedHash[51];
    unsigned int encodedHashLen;
    const unsigned char expEncHash[] = {
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
        0x00, 0x04, 0x20,
        /* Hash data */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    XMEMSET(hash, 0, sizeof(hash));

    ExpectNotNull(rsa = wolfSSL_RSA_new());
    ExpectIntEQ(wolfSSL_RSA_sign_ex(NID_sha256, hash, sizeof(hash), signature,
        &signatureLen, rsa, 1), 0);
    wolfSSL_RSA_free(rsa);

    der = privDer;
    rsa = NULL;
    ExpectNotNull(d2i_RSAPrivateKey(&rsa, &der, privDerSz));

    ExpectIntEQ(wolfSSL_RSA_sign_ex(NID_rsaEncryption,NULL, 0, NULL, NULL, NULL,
        -1), 0);
    ExpectIntEQ(wolfSSL_RSA_sign_ex(NID_rsaEncryption, hash, sizeof(hash),
        signature, &signatureLen, rsa, 1), 0);
    ExpectIntEQ(wolfSSL_RSA_sign_ex(NID_sha256, NULL, sizeof(hash), signature,
        &signatureLen, rsa, 1), 0);
    ExpectIntEQ(wolfSSL_RSA_sign_ex(NID_sha256, hash, sizeof(hash), NULL,
        &signatureLen, rsa, 1), 0);
    ExpectIntEQ(wolfSSL_RSA_sign_ex(NID_sha256, hash, sizeof(hash), signature,
        NULL, rsa, 1), 0);
    ExpectIntEQ(wolfSSL_RSA_sign_ex(NID_sha256, hash, sizeof(hash), signature,
        &signatureLen, NULL, 1), 0);
    ExpectIntEQ(wolfSSL_RSA_sign_ex(NID_sha256, hash, sizeof(hash), signature,
        &signatureLen, rsa, -1), 0);
    ExpectIntEQ(wolfSSL_RSA_sign_ex(NID_sha256, NULL, sizeof(hash), signature,
        &signatureLen, rsa, 0), 0);
    ExpectIntEQ(wolfSSL_RSA_sign_ex(NID_sha256, hash, sizeof(hash), NULL,
        &signatureLen, rsa, 0), 0);
    ExpectIntEQ(wolfSSL_RSA_sign_ex(NID_sha256, hash, sizeof(hash), signature,
        NULL, rsa, 0), 0);

    ExpectIntEQ(wolfSSL_RSA_sign_ex(NID_sha256, hash, sizeof(hash), signature,
        &signatureLen, rsa, 1), 1);
    /* Test returning encoded hash. */
    ExpectIntEQ(wolfSSL_RSA_sign_ex(NID_sha256, hash, sizeof(hash), encodedHash,
        &encodedHashLen, rsa, 0), 1);
    ExpectIntEQ(encodedHashLen, sizeof(expEncHash));
    ExpectIntEQ(XMEMCMP(encodedHash, expEncHash, sizeof(expEncHash)), 0);

    RSA_free(rsa);
    der = pubDer;
    rsa = NULL;
    ExpectNotNull(d2i_RSAPublicKey(&rsa, &der, pubDerSz));

    ExpectIntEQ(RSA_verify(NID_sha256, hash, sizeof(hash), signature,
        signatureLen, rsa), 1);

    RSA_free(rsa);
#endif
    return EXPECT_RESULT();
}


int test_wolfSSL_RSA_public_decrypt(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA)
    RSA *rsa;
    unsigned char msg[SHA256_DIGEST_LENGTH];
#ifdef USE_CERT_BUFFERS_1024
    const unsigned char* pubDer = client_keypub_der_1024;
    size_t pubDerSz = sizeof_client_keypub_der_1024;
    unsigned char decMsg[1024/8];
    const unsigned char encMsg[] = {
        0x45, 0x8e, 0x6e, 0x7a, 0x9c, 0xe1, 0x67, 0x36,
        0x72, 0xfc, 0x9d, 0x05, 0xdf, 0xc2, 0xaf, 0x54,
        0xc5, 0x2f, 0x94, 0xb8, 0xc7, 0x82, 0x40, 0xfa,
        0xa7, 0x8c, 0xb1, 0x89, 0x40, 0xc3, 0x59, 0x5a,
        0x77, 0x08, 0x54, 0x93, 0x43, 0x7f, 0xc4, 0xb7,
        0xc4, 0x78, 0xf1, 0xf8, 0xab, 0xbf, 0xc2, 0x81,
        0x5d, 0x97, 0xea, 0x7a, 0x60, 0x90, 0x51, 0xb7,
        0x47, 0x78, 0x48, 0x1e, 0x88, 0x6b, 0x89, 0xde,
        0xce, 0x41, 0x41, 0xae, 0x49, 0xf6, 0xfd, 0x2d,
        0x2d, 0x9c, 0x70, 0x7d, 0xf9, 0xcf, 0x77, 0x5f,
        0x06, 0xc7, 0x20, 0xe3, 0x57, 0xd4, 0xd8, 0x1a,
        0x96, 0xa2, 0x39, 0xb0, 0x6e, 0x8e, 0x68, 0xf8,
        0x57, 0x7b, 0x26, 0x88, 0x17, 0xc4, 0xb7, 0xf1,
        0x59, 0xfa, 0xb6, 0x95, 0xdd, 0x1e, 0xe8, 0xd8,
        0x4e, 0xbd, 0xcd, 0x41, 0xad, 0xc7, 0xe2, 0x39,
        0xb8, 0x00, 0xca, 0xf5, 0x59, 0xdf, 0xf8, 0x43
    };
#if !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && HAVE_FIPS_VERSION > 2)) && \
    defined(WC_RSA_NO_PADDING)
    const unsigned char encMsgNoPad[] = {
        0x0d, 0x41, 0x5a, 0xc7, 0x60, 0xd7, 0xbe, 0xb6,
        0x42, 0xd1, 0x65, 0xb1, 0x7e, 0x59, 0x54, 0xcc,
        0x76, 0x62, 0xd0, 0x2f, 0x4d, 0xe3, 0x23, 0x62,
        0xc8, 0x14, 0xfe, 0x5e, 0xa1, 0xc7, 0x05, 0xee,
        0x9e, 0x28, 0x2e, 0xf5, 0xfd, 0xa4, 0xc0, 0x43,
        0x55, 0xa2, 0x6b, 0x6b, 0x16, 0xa7, 0x63, 0x06,
        0xa7, 0x78, 0x4f, 0xda, 0xae, 0x10, 0x6d, 0xd1,
        0x2e, 0x1d, 0xbb, 0xbc, 0xc4, 0x1d, 0x82, 0xe4,
        0xc6, 0x76, 0x77, 0xa6, 0x0a, 0xef, 0xd2, 0x89,
        0xff, 0x30, 0x85, 0x22, 0xa0, 0x68, 0x88, 0x54,
        0xa3, 0xd1, 0x92, 0xd1, 0x3f, 0x57, 0xe4, 0xc7,
        0x43, 0x5a, 0x8b, 0xb3, 0x86, 0xaf, 0xd5, 0x6d,
        0x07, 0xe1, 0xa0, 0x5f, 0xe1, 0x9a, 0x06, 0xba,
        0x56, 0xd2, 0xb0, 0x73, 0xf5, 0xb3, 0xd0, 0x5f,
        0xc0, 0xbf, 0x22, 0x4c, 0x54, 0x4e, 0x11, 0xe2,
        0xc5, 0xf8, 0x66, 0x39, 0x9d, 0x70, 0x90, 0x31
    };
#endif
#else
    const unsigned char* pubDer = client_keypub_der_2048;
    size_t pubDerSz = sizeof_client_keypub_der_2048;
    unsigned char decMsg[2048/8];
    const unsigned char encMsg[] = {
        0x16, 0x5d, 0xbb, 0x00, 0x38, 0x73, 0x01, 0x34,
        0xca, 0x59, 0xc6, 0x8b, 0x64, 0x70, 0x89, 0xf5,
        0x50, 0x2d, 0x1d, 0x69, 0x1f, 0x07, 0x1e, 0x31,
        0xae, 0x9b, 0xa6, 0x6e, 0xee, 0x80, 0xd9, 0x9e,
        0x59, 0x33, 0x70, 0x30, 0x28, 0x42, 0x7d, 0x24,
        0x36, 0x95, 0x6b, 0xf9, 0x0a, 0x23, 0xcb, 0xce,
        0x66, 0xa5, 0x07, 0x5e, 0x11, 0xa7, 0xdc, 0xfb,
        0xd9, 0xc2, 0x51, 0xf0, 0x05, 0xc9, 0x39, 0xb3,
        0xae, 0xff, 0xfb, 0xe9, 0xb1, 0x9a, 0x54, 0xac,
        0x1d, 0xca, 0x42, 0x1a, 0xfd, 0x7c, 0x97, 0xa0,
        0x60, 0x2b, 0xcd, 0xb6, 0x36, 0x33, 0xfc, 0x44,
        0x69, 0xf7, 0x2e, 0x8c, 0x3b, 0x5f, 0xb4, 0x9f,
        0xa7, 0x02, 0x8f, 0x6d, 0x6b, 0x79, 0x10, 0x32,
        0x7d, 0xf4, 0x5d, 0xa1, 0x63, 0x22, 0x59, 0xc4,
        0x44, 0x8e, 0x44, 0x24, 0x8b, 0x14, 0x9d, 0x2b,
        0xb5, 0xd3, 0xad, 0x9a, 0x87, 0x0d, 0xe7, 0x70,
        0x6d, 0xe9, 0xae, 0xaa, 0x52, 0xbf, 0x1a, 0x9b,
        0xc8, 0x3d, 0x45, 0x7c, 0xd1, 0x90, 0xe3, 0xd9,
        0x57, 0xcf, 0xc3, 0x29, 0x69, 0x05, 0x07, 0x96,
        0x2e, 0x46, 0x74, 0x0a, 0xa7, 0x76, 0x8b, 0xc0,
        0x1c, 0x04, 0x80, 0x08, 0xa0, 0x94, 0x7e, 0xbb,
        0x2d, 0x99, 0xe9, 0xab, 0x18, 0x4d, 0x48, 0x2d,
        0x94, 0x5e, 0x50, 0x21, 0x42, 0xdf, 0xf5, 0x61,
        0x42, 0x7d, 0x86, 0x5d, 0x9e, 0x89, 0xc9, 0x5b,
        0x24, 0xab, 0xa1, 0xd8, 0x20, 0x45, 0xcb, 0x81,
        0xcf, 0xc5, 0x25, 0x7d, 0x11, 0x6e, 0xbd, 0x80,
        0xac, 0xba, 0xdc, 0xef, 0xb9, 0x05, 0x9c, 0xd5,
        0xc2, 0x26, 0x57, 0x69, 0x8b, 0x08, 0x27, 0xc7,
        0xea, 0xbe, 0xaf, 0x52, 0x21, 0x95, 0x9f, 0xa0,
        0x2f, 0x2f, 0x53, 0x7c, 0x2f, 0xa3, 0x0b, 0x79,
        0x39, 0x01, 0xa3, 0x37, 0x46, 0xa8, 0xc4, 0x34,
        0x41, 0x20, 0x7c, 0x3f, 0x70, 0x9a, 0x47, 0xe8
    };
#if !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && HAVE_FIPS_VERSION > 2)) && \
    defined(WC_RSA_NO_PADDING)
    const unsigned char encMsgNoPad[] = {
        0x79, 0x69, 0xdc, 0x0d, 0xff, 0x09, 0xeb, 0x91,
        0xbc, 0xda, 0xe4, 0xd3, 0xcd, 0xd5, 0xd3, 0x1c,
        0xb9, 0x66, 0xa8, 0x02, 0xf3, 0x75, 0x40, 0xf1,
        0x38, 0x4a, 0x37, 0x7b, 0x19, 0xc8, 0xcd, 0xea,
        0x79, 0xa8, 0x51, 0x32, 0x00, 0x3f, 0x4c, 0xde,
        0xaa, 0xe5, 0xe2, 0x7c, 0x10, 0xcd, 0x6e, 0x00,
        0xc6, 0xc4, 0x63, 0x98, 0x58, 0x9b, 0x38, 0xca,
        0xf0, 0x5d, 0xc8, 0xf0, 0x57, 0xf6, 0x21, 0x50,
        0x3f, 0x63, 0x05, 0x9f, 0xbf, 0xb6, 0x3b, 0x50,
        0x85, 0x06, 0x34, 0x08, 0x57, 0xb9, 0x44, 0xce,
        0xe4, 0x66, 0xbf, 0x0c, 0xfe, 0x36, 0xa4, 0x5b,
        0xed, 0x2d, 0x7d, 0xed, 0xf1, 0xbd, 0xda, 0x3e,
        0x19, 0x1f, 0x99, 0xc8, 0xe4, 0xc2, 0xbb, 0xb5,
        0x6c, 0x83, 0x22, 0xd1, 0xe7, 0x57, 0xcf, 0x1b,
        0x91, 0x0c, 0xa5, 0x47, 0x06, 0x71, 0x8f, 0x93,
        0xf3, 0xad, 0xdb, 0xe3, 0xf8, 0xa0, 0x0b, 0xcd,
        0x89, 0x4e, 0xa5, 0xb5, 0x03, 0x68, 0x61, 0x89,
        0x0b, 0xe2, 0x03, 0x8b, 0x1f, 0x54, 0xae, 0x0f,
        0xfa, 0xf0, 0xb7, 0x0f, 0x8c, 0x84, 0x35, 0x13,
        0x8d, 0x65, 0x1f, 0x2c, 0xd5, 0xce, 0xc4, 0x6c,
        0x98, 0x67, 0xe4, 0x1a, 0x85, 0x67, 0x69, 0x17,
        0x17, 0x5a, 0x5d, 0xfd, 0x23, 0xdd, 0x03, 0x3f,
        0x6d, 0x7a, 0xb6, 0x8b, 0x99, 0xc0, 0xb6, 0x70,
        0x86, 0xac, 0xf6, 0x02, 0xc2, 0x28, 0x42, 0xed,
        0x06, 0xcf, 0xca, 0x3d, 0x07, 0x16, 0xf0, 0x0e,
        0x04, 0x55, 0x1e, 0x59, 0x3f, 0x32, 0xc7, 0x12,
        0xc5, 0x0d, 0x9d, 0x64, 0x7d, 0x2e, 0xd4, 0xbc,
        0x8c, 0x24, 0x42, 0x94, 0x2b, 0xf6, 0x11, 0x7f,
        0xb1, 0x1c, 0x09, 0x12, 0x6f, 0x5e, 0x2e, 0x7a,
        0xc6, 0x01, 0xe0, 0x98, 0x31, 0xb7, 0x13, 0x03,
        0xce, 0x29, 0xe1, 0xef, 0x9d, 0xdf, 0x9b, 0xa5,
        0xba, 0x0b, 0xad, 0xf2, 0xeb, 0x2f, 0xf9, 0xd1
    };
#endif
#endif
    const unsigned char* der;
#if !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && HAVE_FIPS_VERSION > 2)) && \
    defined(WC_RSA_NO_PADDING)
    int i;
#endif

    XMEMSET(msg, 0, sizeof(msg));

    der = pubDer;
    rsa = NULL;
    ExpectNotNull(d2i_RSAPublicKey(&rsa, &der, pubDerSz));

    ExpectIntEQ(RSA_public_decrypt(0, NULL, NULL, NULL, 0), -1);
    ExpectIntEQ(RSA_public_decrypt(-1, encMsg, decMsg, rsa,
        RSA_PKCS1_PADDING), -1);
    ExpectIntEQ(RSA_public_decrypt(sizeof(encMsg), NULL, decMsg, rsa,
        RSA_PKCS1_PADDING), -1);
    ExpectIntEQ(RSA_public_decrypt(sizeof(encMsg), encMsg, NULL, rsa,
        RSA_PKCS1_PADDING), -1);
    ExpectIntEQ(RSA_public_decrypt(sizeof(encMsg), encMsg, decMsg, NULL,
        RSA_PKCS1_PADDING), -1);
    ExpectIntEQ(RSA_public_decrypt(sizeof(encMsg), encMsg, decMsg, rsa,
        RSA_PKCS1_PSS_PADDING), -1);

    ExpectIntEQ(RSA_public_decrypt(sizeof(encMsg), encMsg, decMsg, rsa,
        RSA_PKCS1_PADDING), 32);
    ExpectIntEQ(XMEMCMP(decMsg, msg, sizeof(msg)), 0);

#if !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && HAVE_FIPS_VERSION > 2)) && \
    defined(WC_RSA_NO_PADDING)
    ExpectIntEQ(RSA_public_decrypt(sizeof(encMsgNoPad), encMsgNoPad, decMsg,
        rsa, RSA_NO_PADDING), sizeof(decMsg));
    /* Zeros before actual data. */
    for (i = 0; i < (int)(sizeof(decMsg) - sizeof(msg)); i += sizeof(msg)) {
        ExpectIntEQ(XMEMCMP(decMsg + i, msg, sizeof(msg)), 0);
    }
    /* Check actual data. */
    XMEMSET(msg, 0x01, sizeof(msg));
    ExpectIntEQ(XMEMCMP(decMsg + i, msg, sizeof(msg)), 0);
#endif

    RSA_free(rsa);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_RSA_private_encrypt(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA)
    RSA *rsa;
    unsigned char msg[SHA256_DIGEST_LENGTH];
#ifdef USE_CERT_BUFFERS_1024
    const unsigned char* privDer = client_key_der_1024;
    size_t privDerSz = sizeof_client_key_der_1024;
    unsigned char encMsg[1024/8];
    const unsigned char expEncMsg[] = {
        0x45, 0x8e, 0x6e, 0x7a, 0x9c, 0xe1, 0x67, 0x36,
        0x72, 0xfc, 0x9d, 0x05, 0xdf, 0xc2, 0xaf, 0x54,
        0xc5, 0x2f, 0x94, 0xb8, 0xc7, 0x82, 0x40, 0xfa,
        0xa7, 0x8c, 0xb1, 0x89, 0x40, 0xc3, 0x59, 0x5a,
        0x77, 0x08, 0x54, 0x93, 0x43, 0x7f, 0xc4, 0xb7,
        0xc4, 0x78, 0xf1, 0xf8, 0xab, 0xbf, 0xc2, 0x81,
        0x5d, 0x97, 0xea, 0x7a, 0x60, 0x90, 0x51, 0xb7,
        0x47, 0x78, 0x48, 0x1e, 0x88, 0x6b, 0x89, 0xde,
        0xce, 0x41, 0x41, 0xae, 0x49, 0xf6, 0xfd, 0x2d,
        0x2d, 0x9c, 0x70, 0x7d, 0xf9, 0xcf, 0x77, 0x5f,
        0x06, 0xc7, 0x20, 0xe3, 0x57, 0xd4, 0xd8, 0x1a,
        0x96, 0xa2, 0x39, 0xb0, 0x6e, 0x8e, 0x68, 0xf8,
        0x57, 0x7b, 0x26, 0x88, 0x17, 0xc4, 0xb7, 0xf1,
        0x59, 0xfa, 0xb6, 0x95, 0xdd, 0x1e, 0xe8, 0xd8,
        0x4e, 0xbd, 0xcd, 0x41, 0xad, 0xc7, 0xe2, 0x39,
        0xb8, 0x00, 0xca, 0xf5, 0x59, 0xdf, 0xf8, 0x43
    };
#ifdef WC_RSA_NO_PADDING
    const unsigned char expEncMsgNoPad[] = {
        0x0d, 0x41, 0x5a, 0xc7, 0x60, 0xd7, 0xbe, 0xb6,
        0x42, 0xd1, 0x65, 0xb1, 0x7e, 0x59, 0x54, 0xcc,
        0x76, 0x62, 0xd0, 0x2f, 0x4d, 0xe3, 0x23, 0x62,
        0xc8, 0x14, 0xfe, 0x5e, 0xa1, 0xc7, 0x05, 0xee,
        0x9e, 0x28, 0x2e, 0xf5, 0xfd, 0xa4, 0xc0, 0x43,
        0x55, 0xa2, 0x6b, 0x6b, 0x16, 0xa7, 0x63, 0x06,
        0xa7, 0x78, 0x4f, 0xda, 0xae, 0x10, 0x6d, 0xd1,
        0x2e, 0x1d, 0xbb, 0xbc, 0xc4, 0x1d, 0x82, 0xe4,
        0xc6, 0x76, 0x77, 0xa6, 0x0a, 0xef, 0xd2, 0x89,
        0xff, 0x30, 0x85, 0x22, 0xa0, 0x68, 0x88, 0x54,
        0xa3, 0xd1, 0x92, 0xd1, 0x3f, 0x57, 0xe4, 0xc7,
        0x43, 0x5a, 0x8b, 0xb3, 0x86, 0xaf, 0xd5, 0x6d,
        0x07, 0xe1, 0xa0, 0x5f, 0xe1, 0x9a, 0x06, 0xba,
        0x56, 0xd2, 0xb0, 0x73, 0xf5, 0xb3, 0xd0, 0x5f,
        0xc0, 0xbf, 0x22, 0x4c, 0x54, 0x4e, 0x11, 0xe2,
        0xc5, 0xf8, 0x66, 0x39, 0x9d, 0x70, 0x90, 0x31
    };
#endif
#else
    const unsigned char* privDer = client_key_der_2048;
    size_t privDerSz = sizeof_client_key_der_2048;
    unsigned char encMsg[2048/8];
    const unsigned char expEncMsg[] = {
        0x16, 0x5d, 0xbb, 0x00, 0x38, 0x73, 0x01, 0x34,
        0xca, 0x59, 0xc6, 0x8b, 0x64, 0x70, 0x89, 0xf5,
        0x50, 0x2d, 0x1d, 0x69, 0x1f, 0x07, 0x1e, 0x31,
        0xae, 0x9b, 0xa6, 0x6e, 0xee, 0x80, 0xd9, 0x9e,
        0x59, 0x33, 0x70, 0x30, 0x28, 0x42, 0x7d, 0x24,
        0x36, 0x95, 0x6b, 0xf9, 0x0a, 0x23, 0xcb, 0xce,
        0x66, 0xa5, 0x07, 0x5e, 0x11, 0xa7, 0xdc, 0xfb,
        0xd9, 0xc2, 0x51, 0xf0, 0x05, 0xc9, 0x39, 0xb3,
        0xae, 0xff, 0xfb, 0xe9, 0xb1, 0x9a, 0x54, 0xac,
        0x1d, 0xca, 0x42, 0x1a, 0xfd, 0x7c, 0x97, 0xa0,
        0x60, 0x2b, 0xcd, 0xb6, 0x36, 0x33, 0xfc, 0x44,
        0x69, 0xf7, 0x2e, 0x8c, 0x3b, 0x5f, 0xb4, 0x9f,
        0xa7, 0x02, 0x8f, 0x6d, 0x6b, 0x79, 0x10, 0x32,
        0x7d, 0xf4, 0x5d, 0xa1, 0x63, 0x22, 0x59, 0xc4,
        0x44, 0x8e, 0x44, 0x24, 0x8b, 0x14, 0x9d, 0x2b,
        0xb5, 0xd3, 0xad, 0x9a, 0x87, 0x0d, 0xe7, 0x70,
        0x6d, 0xe9, 0xae, 0xaa, 0x52, 0xbf, 0x1a, 0x9b,
        0xc8, 0x3d, 0x45, 0x7c, 0xd1, 0x90, 0xe3, 0xd9,
        0x57, 0xcf, 0xc3, 0x29, 0x69, 0x05, 0x07, 0x96,
        0x2e, 0x46, 0x74, 0x0a, 0xa7, 0x76, 0x8b, 0xc0,
        0x1c, 0x04, 0x80, 0x08, 0xa0, 0x94, 0x7e, 0xbb,
        0x2d, 0x99, 0xe9, 0xab, 0x18, 0x4d, 0x48, 0x2d,
        0x94, 0x5e, 0x50, 0x21, 0x42, 0xdf, 0xf5, 0x61,
        0x42, 0x7d, 0x86, 0x5d, 0x9e, 0x89, 0xc9, 0x5b,
        0x24, 0xab, 0xa1, 0xd8, 0x20, 0x45, 0xcb, 0x81,
        0xcf, 0xc5, 0x25, 0x7d, 0x11, 0x6e, 0xbd, 0x80,
        0xac, 0xba, 0xdc, 0xef, 0xb9, 0x05, 0x9c, 0xd5,
        0xc2, 0x26, 0x57, 0x69, 0x8b, 0x08, 0x27, 0xc7,
        0xea, 0xbe, 0xaf, 0x52, 0x21, 0x95, 0x9f, 0xa0,
        0x2f, 0x2f, 0x53, 0x7c, 0x2f, 0xa3, 0x0b, 0x79,
        0x39, 0x01, 0xa3, 0x37, 0x46, 0xa8, 0xc4, 0x34,
        0x41, 0x20, 0x7c, 0x3f, 0x70, 0x9a, 0x47, 0xe8
    };
#ifdef WC_RSA_NO_PADDING
    const unsigned char expEncMsgNoPad[] = {
        0x79, 0x69, 0xdc, 0x0d, 0xff, 0x09, 0xeb, 0x91,
        0xbc, 0xda, 0xe4, 0xd3, 0xcd, 0xd5, 0xd3, 0x1c,
        0xb9, 0x66, 0xa8, 0x02, 0xf3, 0x75, 0x40, 0xf1,
        0x38, 0x4a, 0x37, 0x7b, 0x19, 0xc8, 0xcd, 0xea,
        0x79, 0xa8, 0x51, 0x32, 0x00, 0x3f, 0x4c, 0xde,
        0xaa, 0xe5, 0xe2, 0x7c, 0x10, 0xcd, 0x6e, 0x00,
        0xc6, 0xc4, 0x63, 0x98, 0x58, 0x9b, 0x38, 0xca,
        0xf0, 0x5d, 0xc8, 0xf0, 0x57, 0xf6, 0x21, 0x50,
        0x3f, 0x63, 0x05, 0x9f, 0xbf, 0xb6, 0x3b, 0x50,
        0x85, 0x06, 0x34, 0x08, 0x57, 0xb9, 0x44, 0xce,
        0xe4, 0x66, 0xbf, 0x0c, 0xfe, 0x36, 0xa4, 0x5b,
        0xed, 0x2d, 0x7d, 0xed, 0xf1, 0xbd, 0xda, 0x3e,
        0x19, 0x1f, 0x99, 0xc8, 0xe4, 0xc2, 0xbb, 0xb5,
        0x6c, 0x83, 0x22, 0xd1, 0xe7, 0x57, 0xcf, 0x1b,
        0x91, 0x0c, 0xa5, 0x47, 0x06, 0x71, 0x8f, 0x93,
        0xf3, 0xad, 0xdb, 0xe3, 0xf8, 0xa0, 0x0b, 0xcd,
        0x89, 0x4e, 0xa5, 0xb5, 0x03, 0x68, 0x61, 0x89,
        0x0b, 0xe2, 0x03, 0x8b, 0x1f, 0x54, 0xae, 0x0f,
        0xfa, 0xf0, 0xb7, 0x0f, 0x8c, 0x84, 0x35, 0x13,
        0x8d, 0x65, 0x1f, 0x2c, 0xd5, 0xce, 0xc4, 0x6c,
        0x98, 0x67, 0xe4, 0x1a, 0x85, 0x67, 0x69, 0x17,
        0x17, 0x5a, 0x5d, 0xfd, 0x23, 0xdd, 0x03, 0x3f,
        0x6d, 0x7a, 0xb6, 0x8b, 0x99, 0xc0, 0xb6, 0x70,
        0x86, 0xac, 0xf6, 0x02, 0xc2, 0x28, 0x42, 0xed,
        0x06, 0xcf, 0xca, 0x3d, 0x07, 0x16, 0xf0, 0x0e,
        0x04, 0x55, 0x1e, 0x59, 0x3f, 0x32, 0xc7, 0x12,
        0xc5, 0x0d, 0x9d, 0x64, 0x7d, 0x2e, 0xd4, 0xbc,
        0x8c, 0x24, 0x42, 0x94, 0x2b, 0xf6, 0x11, 0x7f,
        0xb1, 0x1c, 0x09, 0x12, 0x6f, 0x5e, 0x2e, 0x7a,
        0xc6, 0x01, 0xe0, 0x98, 0x31, 0xb7, 0x13, 0x03,
        0xce, 0x29, 0xe1, 0xef, 0x9d, 0xdf, 0x9b, 0xa5,
        0xba, 0x0b, 0xad, 0xf2, 0xeb, 0x2f, 0xf9, 0xd1
    };
#endif
#endif
    const unsigned char* der;

    XMEMSET(msg, 0x00, sizeof(msg));

    der = privDer;
    rsa = NULL;
    ExpectNotNull(d2i_RSAPrivateKey(&rsa, &der, privDerSz));

    ExpectIntEQ(RSA_private_encrypt(0, NULL, NULL, NULL, 0), -1);
    ExpectIntEQ(RSA_private_encrypt(0, msg, encMsg, rsa, RSA_PKCS1_PADDING),
        -1);
    ExpectIntEQ(RSA_private_encrypt(sizeof(msg), NULL, encMsg, rsa,
        RSA_PKCS1_PADDING), -1);
    ExpectIntEQ(RSA_private_encrypt(sizeof(msg), msg, NULL, rsa,
        RSA_PKCS1_PADDING), -1);
    ExpectIntEQ(RSA_private_encrypt(sizeof(msg), msg, encMsg, NULL,
         RSA_PKCS1_PADDING), -1);
    ExpectIntEQ(RSA_private_encrypt(sizeof(msg), msg, encMsg, rsa,
         RSA_PKCS1_PSS_PADDING), -1);

    ExpectIntEQ(RSA_private_encrypt(sizeof(msg), msg, encMsg, rsa,
         RSA_PKCS1_PADDING), sizeof(encMsg));
    ExpectIntEQ(XMEMCMP(encMsg, expEncMsg, sizeof(expEncMsg)), 0);

#ifdef WC_RSA_NO_PADDING
    /* Non-zero message. */
    XMEMSET(msg, 0x01, sizeof(msg));
    ExpectIntEQ(RSA_private_encrypt(sizeof(msg), msg, encMsg, rsa,
         RSA_NO_PADDING), sizeof(encMsg));
    ExpectIntEQ(XMEMCMP(encMsg, expEncMsgNoPad, sizeof(expEncMsgNoPad)), 0);
#endif

    RSA_free(rsa);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_RSA_public_encrypt(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA)
    RSA* rsa = NULL;
    const unsigned char msg[2048/8] = { 0 };
    unsigned char encMsg[2048/8];

    ExpectNotNull(rsa = RSA_new());

    ExpectIntEQ(RSA_public_encrypt(-1, msg, encMsg, rsa,
        RSA_PKCS1_PADDING), -1);
    ExpectIntEQ(RSA_public_encrypt(sizeof(msg), NULL, encMsg, rsa,
        RSA_PKCS1_PADDING), -1);
    ExpectIntEQ(RSA_public_encrypt(sizeof(msg), msg, NULL, rsa,
        RSA_PKCS1_PADDING), -1);
    ExpectIntEQ(RSA_public_encrypt(sizeof(msg), msg, encMsg, NULL,
        RSA_PKCS1_PADDING), -1);
    ExpectIntEQ(RSA_public_encrypt(sizeof(msg), msg, encMsg, rsa,
        RSA_PKCS1_PSS_PADDING), -1);
    /* Empty RSA key. */
    ExpectIntEQ(RSA_public_encrypt(sizeof(msg), msg, encMsg, rsa,
        RSA_PKCS1_PADDING), -1);

    RSA_free(rsa);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_RSA_private_decrypt(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA)
    RSA* rsa = NULL;
    unsigned char msg[2048/8];
    const unsigned char encMsg[2048/8] = { 0 };

    ExpectNotNull(rsa = RSA_new());

    ExpectIntEQ(RSA_private_decrypt(-1, encMsg, msg, rsa,
        RSA_PKCS1_PADDING), -1);
    ExpectIntEQ(RSA_private_decrypt(sizeof(encMsg), NULL, msg, rsa,
        RSA_PKCS1_PADDING), -1);
    ExpectIntEQ(RSA_private_decrypt(sizeof(encMsg), encMsg, NULL, rsa,
        RSA_PKCS1_PADDING), -1);
    ExpectIntEQ(RSA_private_decrypt(sizeof(encMsg), encMsg, msg, NULL,
        RSA_PKCS1_PADDING), -1);
    ExpectIntEQ(RSA_private_decrypt(sizeof(encMsg), encMsg, msg, rsa,
        RSA_PKCS1_PSS_PADDING), -1);
    /* Empty RSA key. */
    ExpectIntEQ(RSA_private_decrypt(sizeof(encMsg), encMsg, msg, rsa,
        RSA_PKCS1_PADDING), -1);

    RSA_free(rsa);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_RSA_GenAdd(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA)
    RSA *rsa;
#ifdef USE_CERT_BUFFERS_1024
    const unsigned char* privDer = client_key_der_1024;
    size_t privDerSz = sizeof_client_key_der_1024;
    const unsigned char* pubDer = client_keypub_der_1024;
    size_t pubDerSz = sizeof_client_keypub_der_1024;
#else
    const unsigned char* privDer = client_key_der_2048;
    size_t privDerSz = sizeof_client_key_der_2048;
    const unsigned char* pubDer = client_keypub_der_2048;
    size_t pubDerSz = sizeof_client_keypub_der_2048;
#endif
    const unsigned char* der;

    der = privDer;
    rsa = NULL;
    ExpectNotNull(d2i_RSAPrivateKey(&rsa, &der, privDerSz));

    ExpectIntEQ(wolfSSL_RSA_GenAdd(NULL), -1);
#if defined(WOLFSSL_KEY_GEN) || defined(OPENSSL_EXTRA) || \
    !defined(RSA_LOW_MEM)
    ExpectIntEQ(wolfSSL_RSA_GenAdd(rsa), 1);
#else
    /* dmp1 and dmq1 are not set (allocated) in this config */
    ExpectIntEQ(wolfSSL_RSA_GenAdd(rsa), -1);
#endif

    RSA_free(rsa);
    der = pubDer;
    rsa = NULL;
    ExpectNotNull(d2i_RSAPublicKey(&rsa, &der, pubDerSz));
    /* Need private values. */
    ExpectIntEQ(wolfSSL_RSA_GenAdd(rsa), -1);

    RSA_free(rsa);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_RSA_blinding_on(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && !defined(NO_WOLFSSL_STUB)
    RSA *rsa;
    WOLFSSL_BN_CTX *bnCtx = NULL;
#ifdef USE_CERT_BUFFERS_1024
    const unsigned char* privDer = client_key_der_1024;
    size_t privDerSz = sizeof_client_key_der_1024;
#else
    const unsigned char* privDer = client_key_der_2048;
    size_t privDerSz = sizeof_client_key_der_2048;
#endif
    const unsigned char* der;

    der = privDer;
    rsa = NULL;
    ExpectNotNull(d2i_RSAPrivateKey(&rsa, &der, privDerSz));
    ExpectNotNull(bnCtx = wolfSSL_BN_CTX_new());

    /* Does nothing so all parameters are valid. */
    ExpectIntEQ(wolfSSL_RSA_blinding_on(NULL, NULL), 1);
    ExpectIntEQ(wolfSSL_RSA_blinding_on(rsa, NULL), 1);
    ExpectIntEQ(wolfSSL_RSA_blinding_on(NULL, bnCtx), 1);
    ExpectIntEQ(wolfSSL_RSA_blinding_on(rsa, bnCtx), 1);

    wolfSSL_BN_CTX_free(bnCtx);
    RSA_free(rsa);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_RSA_ex_data(void)
{
    EXPECT_DECLS;
#if !defined(NO_RSA) && defined(OPENSSL_EXTRA)
    RSA* rsa = NULL;
    unsigned char data[1];

    ExpectNotNull(rsa = RSA_new());

    ExpectNull(wolfSSL_RSA_get_ex_data(NULL, 0));
    ExpectNull(wolfSSL_RSA_get_ex_data(rsa, 0));
#ifdef MAX_EX_DATA
    ExpectNull(wolfSSL_RSA_get_ex_data(rsa, MAX_EX_DATA));
    ExpectIntEQ(wolfSSL_RSA_set_ex_data(rsa, MAX_EX_DATA, data), 0);
#endif
    ExpectIntEQ(wolfSSL_RSA_set_ex_data(NULL, 0, NULL), 0);
    ExpectIntEQ(wolfSSL_RSA_set_ex_data(NULL, 0, data), 0);

#ifdef HAVE_EX_DATA
    ExpectIntEQ(wolfSSL_RSA_set_ex_data(rsa, 0, NULL), 1);
    ExpectIntEQ(wolfSSL_RSA_set_ex_data(rsa, 0, data), 1);
    ExpectPtrEq(wolfSSL_RSA_get_ex_data(rsa, 0), data);
#else
    ExpectIntEQ(wolfSSL_RSA_set_ex_data(rsa, 0, NULL), 0);
    ExpectIntEQ(wolfSSL_RSA_set_ex_data(rsa, 0, data), 0);
    ExpectNull(wolfSSL_RSA_get_ex_data(rsa, 0));
#endif

    RSA_free(rsa);
#endif /* !NO_RSA && OPENSSL_EXTRA */
    return EXPECT_RESULT();
}

int test_wolfSSL_RSA_LoadDer(void)
{
    EXPECT_DECLS;
#if !defined(NO_RSA) && (defined(OPENSSL_EXTRA) || \
    defined(OPENSSL_EXTRA_X509_SMALL))
    RSA *rsa = NULL;
#ifdef USE_CERT_BUFFERS_1024
    const unsigned char* privDer = client_key_der_1024;
    size_t privDerSz = sizeof_client_key_der_1024;
#else
    const unsigned char* privDer = client_key_der_2048;
    size_t privDerSz = sizeof_client_key_der_2048;
#endif

    ExpectNotNull(rsa = RSA_new());

    ExpectIntEQ(wolfSSL_RSA_LoadDer(NULL, privDer, (int)privDerSz), -1);
    ExpectIntEQ(wolfSSL_RSA_LoadDer(rsa, NULL, (int)privDerSz), -1);
    ExpectIntEQ(wolfSSL_RSA_LoadDer(rsa, privDer, 0), -1);

    ExpectIntEQ(wolfSSL_RSA_LoadDer(rsa, privDer, (int)privDerSz), 1);

    RSA_free(rsa);
#endif /* !NO_RSA && OPENSSL_EXTRA */
    return EXPECT_RESULT();
}

/* Local API. */
int test_wolfSSL_RSA_To_Der(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_TEST_STATIC_BUILD
#if defined(WOLFSSL_KEY_GEN) && defined(OPENSSL_EXTRA) && !defined(NO_RSA)
    RSA* rsa;
#ifdef USE_CERT_BUFFERS_1024
    const unsigned char* privDer = client_key_der_1024;
    size_t privDerSz = sizeof_client_key_der_1024;
    const unsigned char* pubDer = client_keypub_der_1024;
    size_t pubDerSz = sizeof_client_keypub_der_1024;
    unsigned char out[sizeof(client_key_der_1024)];
#else
    const unsigned char* privDer = client_key_der_2048;
    size_t privDerSz = sizeof_client_key_der_2048;
    const unsigned char* pubDer = client_keypub_der_2048;
    size_t pubDerSz = sizeof_client_keypub_der_2048;
    unsigned char out[sizeof(client_key_der_2048)];
#endif
    const unsigned char* der;
    unsigned char* outDer = NULL;

    der = privDer;
    rsa = NULL;
    ExpectNotNull(wolfSSL_d2i_RSAPrivateKey(&rsa, &der, privDerSz));

    ExpectIntEQ(wolfSSL_RSA_To_Der(NULL, &outDer, 0, HEAP_HINT), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_RSA_To_Der(rsa, &outDer, 2, HEAP_HINT), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wolfSSL_RSA_To_Der(rsa, NULL, 0, HEAP_HINT), privDerSz);
    outDer = out;
    ExpectIntEQ(wolfSSL_RSA_To_Der(rsa, &outDer, 0, HEAP_HINT), privDerSz);
    ExpectIntEQ(XMEMCMP(out, privDer, privDerSz), 0);
    outDer = NULL;
    ExpectIntEQ(wolfSSL_RSA_To_Der(rsa, &outDer, 0, HEAP_HINT), privDerSz);
    ExpectNotNull(outDer);
    ExpectIntEQ(XMEMCMP(outDer, privDer, privDerSz), 0);
    XFREE(outDer, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    ExpectIntEQ(wolfSSL_RSA_To_Der(rsa, NULL, 1, HEAP_HINT), pubDerSz);
    outDer = out;
    ExpectIntEQ(wolfSSL_RSA_To_Der(rsa, &outDer, 1, HEAP_HINT), pubDerSz);
    ExpectIntEQ(XMEMCMP(out, pubDer, pubDerSz), 0);

    RSA_free(rsa);

    ExpectNotNull(rsa = RSA_new());
    ExpectIntEQ(wolfSSL_RSA_To_Der(rsa, &outDer, 0, HEAP_HINT), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_RSA_To_Der(rsa, &outDer, 1, HEAP_HINT), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    RSA_free(rsa);

    der = pubDer;
    rsa = NULL;
    ExpectNotNull(wolfSSL_d2i_RSAPublicKey(&rsa, &der, pubDerSz));
    ExpectIntEQ(wolfSSL_RSA_To_Der(rsa, &outDer, 0, HEAP_HINT), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    RSA_free(rsa);
#endif
#endif
    return EXPECT_RESULT();
}

/* wolfSSL_PEM_read_RSAPublicKey is a stub function. */
int test_wolfSSL_PEM_read_RSAPublicKey(void)
{
    EXPECT_DECLS;
#if !defined(NO_RSA) && defined(OPENSSL_EXTRA) && !defined(NO_FILESYSTEM)
    XFILE file = XBADFILE;
    const char* fname = "./certs/server-keyPub.pem";
    RSA *rsa = NULL;

    ExpectNull(wolfSSL_PEM_read_RSAPublicKey(XBADFILE, NULL, NULL, NULL));

    ExpectTrue((file = XFOPEN(fname, "rb")) != XBADFILE);
    ExpectNotNull(rsa = PEM_read_RSA_PUBKEY(file, NULL, NULL, NULL));
    ExpectIntEQ(RSA_size(rsa), 256);
    RSA_free(rsa);
    if (file != XBADFILE)
        XFCLOSE(file);
#endif
    return EXPECT_RESULT();
}

/* wolfSSL_PEM_read_RSAPublicKey is a stub function. */
int test_wolfSSL_PEM_write_RSA_PUBKEY(void)
{
    EXPECT_DECLS;
#if !defined(NO_RSA) && defined(OPENSSL_EXTRA) && !defined(NO_FILESYSTEM) && \
    defined(WOLFSSL_KEY_GEN)
    RSA* rsa = NULL;

    ExpectIntEQ(wolfSSL_PEM_write_RSA_PUBKEY(XBADFILE, NULL), 0);
    ExpectIntEQ(wolfSSL_PEM_write_RSA_PUBKEY(stderr, NULL), 0);
    /* Valid but stub so returns 0. */
    ExpectIntEQ(wolfSSL_PEM_write_RSA_PUBKEY(stderr, rsa), 0);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_PEM_write_RSAPrivateKey(void)
{
    EXPECT_DECLS;
#if !defined(NO_RSA) && defined(OPENSSL_EXTRA) && defined(WOLFSSL_KEY_GEN) && \
    (defined(WOLFSSL_PEM_TO_DER) || defined(WOLFSSL_DER_TO_PEM)) && \
    !defined(NO_FILESYSTEM)
    RSA* rsa = NULL;
#ifdef USE_CERT_BUFFERS_1024
    const unsigned char* privDer = client_key_der_1024;
    size_t privDerSz = sizeof_client_key_der_1024;
#else
    const unsigned char* privDer = client_key_der_2048;
    size_t privDerSz = sizeof_client_key_der_2048;
#endif
    const unsigned char* der;
#ifndef NO_AES
    unsigned char passwd[] = "password";
#endif

    ExpectNotNull(rsa = RSA_new());
    ExpectIntEQ(wolfSSL_PEM_write_RSAPrivateKey(stderr, rsa, NULL, NULL, 0,
        NULL, NULL), 0);
    RSA_free(rsa);

    der = privDer;
    rsa = NULL;
    ExpectNotNull(wolfSSL_d2i_RSAPrivateKey(&rsa, &der, privDerSz));

    ExpectIntEQ(wolfSSL_PEM_write_RSAPrivateKey(XBADFILE, rsa, NULL, NULL, 0,
        NULL, NULL), 0);
    ExpectIntEQ(wolfSSL_PEM_write_RSAPrivateKey(stderr, NULL, NULL, NULL, 0,
        NULL, NULL), 0);

    ExpectIntEQ(wolfSSL_PEM_write_RSAPrivateKey(stderr, rsa, NULL, NULL, 0,
        NULL, NULL), 1);
#if !defined(NO_AES) && defined(HAVE_AES_CBC)
    ExpectIntEQ(wolfSSL_PEM_write_RSAPrivateKey(stderr, rsa, EVP_aes_128_cbc(),
        NULL, 0, NULL, NULL), 1);
    ExpectIntEQ(wolfSSL_PEM_write_RSAPrivateKey(stderr, rsa, EVP_aes_128_cbc(),
        passwd, sizeof(passwd) - 1, NULL, NULL), 1);
#endif

    RSA_free(rsa);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_PEM_write_mem_RSAPrivateKey(void)
{
    EXPECT_DECLS;
#if !defined(NO_RSA) && defined(OPENSSL_EXTRA) && defined(WOLFSSL_KEY_GEN) && \
    (defined(WOLFSSL_PEM_TO_DER) || defined(WOLFSSL_DER_TO_PEM))
    RSA* rsa = NULL;
#ifdef USE_CERT_BUFFERS_1024
    const unsigned char* privDer = client_key_der_1024;
    size_t privDerSz = sizeof_client_key_der_1024;
#else
    const unsigned char* privDer = client_key_der_2048;
    size_t privDerSz = sizeof_client_key_der_2048;
#endif
    const unsigned char* der;
#ifndef NO_AES
    unsigned char passwd[] = "password";
#endif
    unsigned char* pem = NULL;
    int plen;

    ExpectNotNull(rsa = RSA_new());
    ExpectIntEQ(wolfSSL_PEM_write_mem_RSAPrivateKey(rsa, NULL, NULL, 0, &pem,
        &plen), 0);
    RSA_free(rsa);

    der = privDer;
    rsa = NULL;
    ExpectNotNull(wolfSSL_d2i_RSAPrivateKey(&rsa, &der, privDerSz));

    ExpectIntEQ(wolfSSL_PEM_write_mem_RSAPrivateKey(NULL, NULL, NULL, 0, &pem,
        &plen), 0);
    ExpectIntEQ(wolfSSL_PEM_write_mem_RSAPrivateKey(rsa, NULL, NULL, 0, NULL,
        &plen), 0);
    ExpectIntEQ(wolfSSL_PEM_write_mem_RSAPrivateKey(rsa, NULL, NULL, 0, &pem,
        NULL), 0);

    ExpectIntEQ(wolfSSL_PEM_write_mem_RSAPrivateKey(rsa, NULL, NULL, 0, &pem,
        &plen), 1);
    XFREE(pem, NULL, DYNAMIC_TYPE_KEY);
    pem = NULL;
#if !defined(NO_AES) && defined(HAVE_AES_CBC)
    ExpectIntEQ(wolfSSL_PEM_write_mem_RSAPrivateKey(rsa, EVP_aes_128_cbc(),
        NULL, 0, &pem, &plen), 1);
    XFREE(pem, NULL, DYNAMIC_TYPE_KEY);
    pem = NULL;
    ExpectIntEQ(wolfSSL_PEM_write_mem_RSAPrivateKey(rsa, EVP_aes_128_cbc(),
        passwd, sizeof(passwd) - 1, &pem, &plen), 1);
    XFREE(pem, NULL, DYNAMIC_TYPE_KEY);
#endif

    RSA_free(rsa);
#endif
    return EXPECT_RESULT();
}

