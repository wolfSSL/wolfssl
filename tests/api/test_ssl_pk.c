/* test_ssl_pk.c
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
#include <wolfssl/openssl/ec.h>

#include <tests/utils.h>
#include <tests/api/api.h>
#include <tests/api/test_ssl_pk.h>

/* Tests for the public-key APIs in src/ssl_api_pk.c (moved from ssl.c). */

int test_wolfSSL_CTX_SetMinEccKey_Sz(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC) && !defined(NO_WOLFSSL_SERVER) && !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_server_method()));

    /* NULL context and negative size are rejected. */
    ExpectIntEQ(wolfSSL_CTX_SetMinEccKey_Sz(NULL, 256),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CTX_SetMinEccKey_Sz(ctx, -1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Multiple-of-8 and non-multiple-of-8 bit sizes both succeed. */
    ExpectIntEQ(wolfSSL_CTX_SetMinEccKey_Sz(ctx, 256), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_SetMinEccKey_Sz(ctx, 255), WOLFSSL_SUCCESS);

    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_SetMinEccKey_Sz(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC) && !defined(NO_WOLFSSL_SERVER) && \
    (defined(NO_CERTS) || !defined(NO_RSA)) && !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_server_method()));
#ifndef NO_CERTS
    /* A server WOLFSSL needs a key and certificate set on the context. */
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKeyFile, CERT_FILETYPE),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_certificate_file(ctx, svrCertFile,
        CERT_FILETYPE), WOLFSSL_SUCCESS);
#endif
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* NULL object and negative size are rejected. */
    ExpectIntEQ(wolfSSL_SetMinEccKey_Sz(NULL, 256),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_SetMinEccKey_Sz(ssl, -1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Multiple-of-8 and non-multiple-of-8 bit sizes both succeed. */
    ExpectIntEQ(wolfSSL_SetMinEccKey_Sz(ssl, 256), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_SetMinEccKey_Sz(ssl, 255), WOLFSSL_SUCCESS);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_CTX_SetMinRsaKey_Sz(void)
{
    EXPECT_DECLS;
#if !defined(NO_RSA) && !defined(NO_WOLFSSL_SERVER) && !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_server_method()));

    /* NULL context, negative size and non-multiple-of-8 size are rejected. */
    ExpectIntEQ(wolfSSL_CTX_SetMinRsaKey_Sz(NULL, 2048),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CTX_SetMinRsaKey_Sz(ctx, -8),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CTX_SetMinRsaKey_Sz(ctx, 1001),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wolfSSL_CTX_SetMinRsaKey_Sz(ctx, 2048), WOLFSSL_SUCCESS);

    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_SetMinRsaKey_Sz(void)
{
    EXPECT_DECLS;
#if !defined(NO_RSA) && !defined(NO_WOLFSSL_SERVER) && !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_server_method()));
#ifndef NO_CERTS
    /* A server WOLFSSL needs a key and certificate set on the context. */
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKeyFile, CERT_FILETYPE),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_certificate_file(ctx, svrCertFile,
        CERT_FILETYPE), WOLFSSL_SUCCESS);
#endif
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* NULL object, negative size and non-multiple-of-8 size are rejected. */
    ExpectIntEQ(wolfSSL_SetMinRsaKey_Sz(NULL, 2048),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_SetMinRsaKey_Sz(ssl, -8),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_SetMinRsaKey_Sz(ssl, 1001),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wolfSSL_SetMinRsaKey_Sz(ssl, 2048), WOLFSSL_SUCCESS);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_SetEnableDhKeyTest(void)
{
    EXPECT_DECLS;
#if !defined(NO_DH) && !defined(WOLFSSL_OLD_PRIME_CHECK) && \
    !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST) && \
    !defined(NO_WOLFSSL_SERVER) && (defined(NO_CERTS) || !defined(NO_RSA)) && \
    !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_server_method()));
#ifndef NO_CERTS
    /* A server WOLFSSL needs a key and certificate set on the context. */
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKeyFile, CERT_FILETYPE),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_certificate_file(ctx, svrCertFile,
        CERT_FILETYPE), WOLFSSL_SUCCESS);
#endif
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* NULL object is rejected. */
    ExpectIntEQ(wolfSSL_SetEnableDhKeyTest(NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Disable then enable the prime test. */
    ExpectIntEQ(wolfSSL_SetEnableDhKeyTest(ssl, 0), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_SetEnableDhKeyTest(ssl, 1), WOLFSSL_SUCCESS);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_CTX_SetMinDhKey_Sz(void)
{
    EXPECT_DECLS;
#if !defined(NO_DH) && !defined(NO_WOLFSSL_SERVER) && \
    (defined(NO_CERTS) || !defined(NO_RSA)) && !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_server_method()));

    /* NULL context, oversized and non-multiple-of-8 sizes are rejected. */
    ExpectIntEQ(wolfSSL_CTX_SetMinDhKey_Sz(NULL, 1024),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CTX_SetMinDhKey_Sz(ctx, 16008),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CTX_SetMinDhKey_Sz(ctx, 1001),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wolfSSL_CTX_SetMinDhKey_Sz(ctx, 1024), WOLFSSL_SUCCESS);

    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_SetMinDhKey_Sz(void)
{
    EXPECT_DECLS;
#if !defined(NO_DH) && !defined(NO_WOLFSSL_SERVER) && \
    (defined(NO_CERTS) || !defined(NO_RSA)) && !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_server_method()));
#ifndef NO_CERTS
    /* A server WOLFSSL needs a key and certificate set on the context. */
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKeyFile, CERT_FILETYPE),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_certificate_file(ctx, svrCertFile,
        CERT_FILETYPE), WOLFSSL_SUCCESS);
#endif
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* NULL object, oversized and non-multiple-of-8 sizes are rejected. */
    ExpectIntEQ(wolfSSL_SetMinDhKey_Sz(NULL, 1024),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_SetMinDhKey_Sz(ssl, 16008),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_SetMinDhKey_Sz(ssl, 1001),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wolfSSL_SetMinDhKey_Sz(ssl, 1024), WOLFSSL_SUCCESS);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* The largest ceiling every build accepts: 4096 bits where the math reaches
 * it, otherwise what this build's math tops out at. */
#define TEST_MAX_DHKEY_BITS \
    ((MAX_DHKEY_SZ >= (4096 / 8)) ? 4096 : (MAX_DHKEY_SZ * 8))

int test_wolfSSL_CTX_SetMaxDhKey_Sz(void)
{
    EXPECT_DECLS;
#if !defined(NO_DH) && !defined(NO_WOLFSSL_SERVER) && !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_server_method()));

    /* NULL context, oversized and non-multiple-of-8 sizes are rejected. */
    ExpectIntEQ(wolfSSL_CTX_SetMaxDhKey_Sz(NULL, 4096),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CTX_SetMaxDhKey_Sz(ctx, 16008),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CTX_SetMaxDhKey_Sz(ctx, 1001),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Driven off MAX_DHKEY_SZ rather than a fixed 4096: a build whose math
     * tops out below that refuses the larger value, by design. */
    ExpectIntEQ(wolfSSL_CTX_SetMaxDhKey_Sz(ctx, (word16)TEST_MAX_DHKEY_BITS),
        WOLFSSL_SUCCESS);
    /* The value asked for is the value stored, not a silently reduced one. */
    ExpectIntEQ(ctx->maxDhKeySz, TEST_MAX_DHKEY_BITS / 8);

    /* A ceiling above what the build's math supports cannot be honoured, so
     * it is refused rather than accepted and quietly lowered. */
    if (MAX_DHKEY_SZ < (16000 / 8)) {
        ExpectIntEQ(wolfSSL_CTX_SetMaxDhKey_Sz(ctx,
            (word16)((MAX_DHKEY_SZ + 1) * 8)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* The refused call left the previous ceiling alone. */
        ExpectIntEQ(ctx->maxDhKeySz, TEST_MAX_DHKEY_BITS / 8);
    }

    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_SetMaxDhKey_Sz(void)
{
    EXPECT_DECLS;
#if !defined(NO_DH) && !defined(NO_WOLFSSL_SERVER) && \
    (defined(NO_CERTS) || !defined(NO_RSA)) && !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_server_method()));
#ifndef NO_CERTS
    /* A server WOLFSSL needs a key and certificate set on the context. */
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKeyFile, CERT_FILETYPE),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_certificate_file(ctx, svrCertFile,
        CERT_FILETYPE), WOLFSSL_SUCCESS);
#endif
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* NULL object, oversized and non-multiple-of-8 sizes are rejected. */
    ExpectIntEQ(wolfSSL_SetMaxDhKey_Sz(NULL, 4096),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_SetMaxDhKey_Sz(ssl, 16008),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_SetMaxDhKey_Sz(ssl, 1001),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Driven off MAX_DHKEY_SZ rather than a fixed 4096: a build whose math
     * tops out below that refuses the larger value, by design. */
    ExpectIntEQ(wolfSSL_SetMaxDhKey_Sz(ssl, (word16)TEST_MAX_DHKEY_BITS),
        WOLFSSL_SUCCESS);
    /* The value asked for is the value stored, not a silently reduced one. */
    ExpectIntEQ(ssl->options.maxDhKeySz, TEST_MAX_DHKEY_BITS / 8);

    /* A ceiling above what the build's math supports cannot be honoured, so
     * it is refused rather than accepted and quietly lowered. */
    if (MAX_DHKEY_SZ < (16000 / 8)) {
        ExpectIntEQ(wolfSSL_SetMaxDhKey_Sz(ssl,
            (word16)((MAX_DHKEY_SZ + 1) * 8)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* The refused call left the previous ceiling alone. */
        ExpectIntEQ(ssl->options.maxDhKeySz, TEST_MAX_DHKEY_BITS / 8);
    }

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_GetDhKey_Sz(void)
{
    EXPECT_DECLS;
#if !defined(NO_DH) && !defined(NO_WOLFSSL_SERVER) && \
    (defined(NO_CERTS) || !defined(NO_RSA)) && !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_server_method()));
#ifndef NO_CERTS
    /* A server WOLFSSL needs a key and certificate set on the context. */
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKeyFile, CERT_FILETYPE),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_certificate_file(ctx, svrCertFile,
        CERT_FILETYPE), WOLFSSL_SUCCESS);
#endif
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* NULL object is rejected. */
    ExpectIntEQ(wolfSSL_GetDhKey_Sz(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Valid object returns the negotiated size (0 before a handshake). */
    ExpectIntGE(wolfSSL_GetDhKey_Sz(ssl), 0);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_get_privatekey(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_WOLFSSL_STUB)
    /* Stub for OpenSSL compatibility - always returns NULL. */
    ExpectNull(wolfSSL_get_privatekey(NULL));
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_get_signature_nid(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_WOLFSSL_SERVER) && \
    (defined(NO_CERTS) || !defined(NO_RSA)) && !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    int nid = 0;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_server_method()));
#ifndef NO_CERTS
    /* A server WOLFSSL needs a key and certificate set on the context. */
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKeyFile, CERT_FILETYPE),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_certificate_file(ctx, svrCertFile,
        CERT_FILETYPE), WOLFSSL_SUCCESS);
#endif
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* NULL object or output pointer is rejected. */
    ExpectIntEQ(wolfSSL_get_signature_nid(NULL, &nid), WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_get_signature_nid(ssl, NULL), WOLFSSL_FAILURE);

    /* Valid object maps the hash algorithm to a NID. */
    ExpectIntEQ(wolfSSL_get_signature_nid(ssl, &nid), WOLFSSL_SUCCESS);

    /* Drive every hash-algorithm case (HashToNid). */
    if (EXPECT_SUCCESS()) {
        static const byte hashAlgos[] = {
            no_mac, md5_mac, sha_mac, sha224_mac, sha256_mac, sha384_mac,
            sha512_mac, rmd_mac, blake2b_mac, sm3_mac
        };
        size_t i;

        for (i = 0; i < sizeof(hashAlgos) / sizeof(hashAlgos[0]); i++) {
            ssl->options.hashAlgo = hashAlgos[i];
            ExpectIntEQ(wolfSSL_get_signature_nid(ssl, &nid), WOLFSSL_SUCCESS);
        }
        /* An unknown hash algorithm is rejected. */
        ssl->options.hashAlgo = 0xFF;
        ExpectIntEQ(wolfSSL_get_signature_nid(ssl, &nid), WOLFSSL_FAILURE);
    }

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_get_signature_type_nid(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_WOLFSSL_SERVER) && \
    (defined(NO_CERTS) || !defined(NO_RSA)) && !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    int nid = 0;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_server_method()));
#ifndef NO_CERTS
    /* A server WOLFSSL needs a key and certificate set on the context. */
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKeyFile, CERT_FILETYPE),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_certificate_file(ctx, svrCertFile,
        CERT_FILETYPE), WOLFSSL_SUCCESS);
#endif
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* NULL object or output pointer is rejected. */
    ExpectIntEQ(wolfSSL_get_signature_type_nid(NULL, &nid), WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_get_signature_type_nid(ssl, NULL), WOLFSSL_FAILURE);

    /* Valid object maps the signature algorithm to a NID. */
    ExpectIntEQ(wolfSSL_get_signature_type_nid(ssl, &nid), WOLFSSL_SUCCESS);

    /* Drive every signature-algorithm case (SaToNid). */
    if (EXPECT_SUCCESS()) {
        static const byte okAlgos[] = {
            anonymous_sa_algo, rsa_sa_algo, dsa_sa_algo, ecc_dsa_sa_algo,
            ecc_brainpool_sa_algo, rsa_pss_sa_algo, rsa_pss_pss_algo,
            falcon_level1_sa_algo, falcon_level5_sa_algo, mldsa_44_sa_algo,
            mldsa_65_sa_algo, mldsa_87_sa_algo,
            slhdsa_sha2_128s_sa_algo, slhdsa_sha2_128f_sa_algo,
            slhdsa_sha2_192s_sa_algo, slhdsa_sha2_192f_sa_algo,
            slhdsa_sha2_256s_sa_algo, slhdsa_sha2_256f_sa_algo,
            slhdsa_shake_128s_sa_algo, slhdsa_shake_128f_sa_algo,
            slhdsa_shake_192s_sa_algo, slhdsa_shake_192f_sa_algo,
            slhdsa_shake_256s_sa_algo, slhdsa_shake_256f_sa_algo,
            sm2_sa_algo
        };
        static const byte failAlgos[] = { invalid_sa_algo, any_sa_algo };
        size_t i;

        for (i = 0; i < sizeof(okAlgos) / sizeof(okAlgos[0]); i++) {
            ssl->options.sigAlgo = okAlgos[i];
            ExpectIntEQ(wolfSSL_get_signature_type_nid(ssl, &nid),
                WOLFSSL_SUCCESS);
        }
        /* Ed25519/Ed448 mappings depend on build configuration. */
        ssl->options.sigAlgo = ed25519_sa_algo;
    #ifdef HAVE_ED25519
        ExpectIntEQ(wolfSSL_get_signature_type_nid(ssl, &nid), WOLFSSL_SUCCESS);
    #else
        ExpectIntEQ(wolfSSL_get_signature_type_nid(ssl, &nid), WOLFSSL_FAILURE);
    #endif
        ssl->options.sigAlgo = ed448_sa_algo;
    #ifdef HAVE_ED448
        ExpectIntEQ(wolfSSL_get_signature_type_nid(ssl, &nid), WOLFSSL_SUCCESS);
    #else
        ExpectIntEQ(wolfSSL_get_signature_type_nid(ssl, &nid), WOLFSSL_FAILURE);
    #endif
        /* Unknown/placeholder algorithms are rejected. */
        for (i = 0; i < sizeof(failAlgos) / sizeof(failAlgos[0]); i++) {
            ssl->options.sigAlgo = failAlgos[i];
            ExpectIntEQ(wolfSSL_get_signature_type_nid(ssl, &nid),
                WOLFSSL_FAILURE);
        }
    }

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_get_peer_signature_nid(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_WOLFSSL_SERVER) && \
    (defined(NO_CERTS) || !defined(NO_RSA)) && !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    int nid = 0;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_server_method()));
#ifndef NO_CERTS
    /* A server WOLFSSL needs a key and certificate set on the context. */
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKeyFile, CERT_FILETYPE),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_certificate_file(ctx, svrCertFile,
        CERT_FILETYPE), WOLFSSL_SUCCESS);
#endif
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* NULL object or output pointer is rejected. */
    ExpectIntEQ(wolfSSL_get_peer_signature_nid(NULL, &nid), WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_get_peer_signature_nid(ssl, NULL), WOLFSSL_FAILURE);

    /* Valid object maps the peer's hash algorithm to a NID. */
    ExpectIntEQ(wolfSSL_get_peer_signature_nid(ssl, &nid), WOLFSSL_SUCCESS);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_get_peer_signature_type_nid(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_WOLFSSL_SERVER) && \
    (defined(NO_CERTS) || !defined(NO_RSA)) && !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    int nid = 0;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_server_method()));
#ifndef NO_CERTS
    /* A server WOLFSSL needs a key and certificate set on the context. */
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKeyFile, CERT_FILETYPE),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_certificate_file(ctx, svrCertFile,
        CERT_FILETYPE), WOLFSSL_SUCCESS);
#endif
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* NULL object or output pointer is rejected. */
    ExpectIntEQ(wolfSSL_get_peer_signature_type_nid(NULL, &nid),
        WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_get_peer_signature_type_nid(ssl, NULL),
        WOLFSSL_FAILURE);

    /* Valid object maps the peer's signature algorithm to a NID. */
    ExpectIntEQ(wolfSSL_get_peer_signature_type_nid(ssl, &nid),
        WOLFSSL_SUCCESS);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_SSL_CTX_set_tmp_ecdh(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_ECC) && !defined(NO_WOLFSSL_SERVER) \
    && !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL_EC_KEY* ecdh = NULL;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_server_method()));
    ExpectNotNull(ecdh = wolfSSL_EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));

    /* NULL context or key is rejected. */
    ExpectIntEQ(wolfSSL_SSL_CTX_set_tmp_ecdh(NULL, ecdh),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_SSL_CTX_set_tmp_ecdh(ctx, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Valid key sets the curve. */
    ExpectIntEQ(wolfSSL_SSL_CTX_set_tmp_ecdh(ctx, ecdh), WOLFSSL_SUCCESS);

    wolfSSL_EC_KEY_free(ecdh);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_CTX_set_dh_auto(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_WOLFSSL_SERVER) && !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_server_method()));

    /* Compatibility stub - always succeeds. */
    ExpectIntEQ(wolfSSL_CTX_set_dh_auto(ctx, 0), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_set_dh_auto(ctx, 1), WOLFSSL_SUCCESS);

    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

#if defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_STATIC_EPHEMERAL) && defined(WOLFSSL_TLS13) && \
    defined(HAVE_ECC) && defined(HAVE_ECC_KEY_EXPORT) && \
    defined(USE_CERT_BUFFERS_256) && defined(HAVE_ECC_KEY_IMPORT) && \
    !defined(NO_ECC256) && !defined(NO_ECC_SECP)
    #define TEST_STATIC_EPHEMERAL_PRIV_ONLY

/* SEC1 encoding without public point. */
static byte staticEphPrivOnlyDer[128];
static int  staticEphPrivOnlyDerSz = 0;

static int test_static_eph_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;
    static const int group = WOLFSSL_ECC_SECP256R1;

    ExpectIntEQ(wolfSSL_CTX_set_ephemeral_key(ctx, WC_PK_TYPE_ECDH,
        (const char*)staticEphPrivOnlyDer,
        (unsigned int)staticEphPrivOnlyDerSz, WOLFSSL_FILETYPE_ASN1), 0);
    ExpectIntEQ(wolfSSL_CTX_set_groups(ctx, (int*)&group, 1), WOLFSSL_SUCCESS);
    return EXPECT_RESULT();
}

/* The peer uses an ordinary generated ephemeral key, so the two shared
 * secrets agree only if the derived point really is d*G. */
static int test_static_eph_peer_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;
    static const int group = WOLFSSL_ECC_SECP256R1;

    ExpectIntEQ(wolfSSL_CTX_set_groups(ctx, (int*)&group, 1), WOLFSSL_SUCCESS);
    return EXPECT_RESULT();
}
#endif

/* Decoding a SEC1 ECDH key without a public point must still produce a
 * usable key share. */
int test_wolfSSL_StaticEphemeralKeyLoad_priv_only(void)
{
    EXPECT_DECLS;
#ifdef TEST_STATIC_EPHEMERAL_PRIV_ONLY
    ecc_key      key;
    word32       idx = 0;
    byte         expectedPub[65];
    word32       expectedPubSz = (word32)sizeof(expectedPub);
    test_ssl_cbf client_cbf;
    test_ssl_cbf server_cbf;
    int          canDerive = test_ecc_can_derive_pub();

    if (canDerive == 0) {
        return TEST_SKIPPED;
    }
    ExpectIntEQ(canDerive, 1);

    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(&client_cbf, 0, sizeof(client_cbf));
    XMEMSET(&server_cbf, 0, sizeof(server_cbf));

    /* wc_EccPrivateKeyToDer() emits SEC1 that may omit publicKey. */
    ExpectIntEQ(wc_ecc_init(&key), 0);
    ExpectIntEQ(wc_EccPrivateKeyDecode(ecc_clikey_der_256, &idx, &key,
        (word32)sizeof_ecc_clikey_der_256), 0);
    ExpectIntGT(staticEphPrivOnlyDerSz = wc_EccPrivateKeyToDer(&key,
        staticEphPrivOnlyDer, (word32)sizeof(staticEphPrivOnlyDer)), 0);
    /* The point the key share must carry. */
    PRIVATE_KEY_UNLOCK();
    ExpectIntEQ(wc_ecc_export_x963(&key, expectedPub, &expectedPubSz), 0);
    PRIVATE_KEY_LOCK();
    ExpectIntEQ(expectedPubSz, (word32)sizeof(expectedPub));
    wc_ecc_free(&key);

    ExpectIntEQ(wc_ecc_init(&key), 0);
    idx = 0;
    ExpectIntEQ(wc_EccPrivateKeyDecode(staticEphPrivOnlyDer, &idx, &key,
        (word32)staticEphPrivOnlyDerSz), 0);
    ExpectIntEQ(key.type, ECC_PRIVATEKEY_ONLY);
    wc_ecc_free(&key);

    /* The point is derived per handshake, so the stored key is the one
     * that was set. */
    {
        WOLFSSL_CTX*         ctx = NULL;
        const unsigned char* stored = NULL;
        unsigned int         storedSz = 0;

        ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
        ExpectIntEQ(wolfSSL_CTX_set_ephemeral_key(ctx, WC_PK_TYPE_ECDH,
            (const char*)staticEphPrivOnlyDer,
            (unsigned int)staticEphPrivOnlyDerSz, WOLFSSL_FILETYPE_ASN1), 0);
        ExpectIntEQ(wolfSSL_CTX_get_ephemeral_key(ctx, WC_PK_TYPE_ECDH,
            &stored, &storedSz), 0);
        ExpectIntEQ(storedSz, (unsigned int)staticEphPrivOnlyDerSz);
        ExpectNotNull(stored);
        if (stored != NULL) {
            ExpectBufEQ(stored, staticEphPrivOnlyDer, storedSz);
        }
        wolfSSL_CTX_free(ctx);
    }

    /* The ClientHello key share must carry the point derived from the static
     * scalar. A handshake alone cannot show this: any load error sends
     * TLSX_KeyShare_GenEccKey() off to generate a fresh key, and the
     * handshake then succeeds without the configured key. */
    {
        struct test_memio_ctx test_ctx;
        WOLFSSL_CTX* ctx_c = NULL;
        WOLFSSL_CTX* ctx_s = NULL;
        WOLFSSL*     ssl_c = NULL;
        WOLFSSL*     ssl_s = NULL;
        int          found = 0;
        int          i;

        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);
        ExpectIntEQ(wolfSSL_set_ephemeral_key(ssl_c, WC_PK_TYPE_ECDH,
            (const char*)staticEphPrivOnlyDer,
            (unsigned int)staticEphPrivOnlyDerSz, WOLFSSL_FILETYPE_ASN1), 0);
        ExpectIntEQ(wolfSSL_UseKeyShare(ssl_c, WOLFSSL_ECC_SECP256R1),
            WOLFSSL_SUCCESS);

        /* First flight only - the ClientHello lands in the server buffer. */
        ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_get_error(ssl_c, WC_NO_ERR_TRACE(
            WOLFSSL_FATAL_ERROR)), WOLFSSL_ERROR_WANT_READ);
        ExpectIntGT(test_ctx.s_len, (int)expectedPubSz);

        for (i = 0; i + (int)expectedPubSz <= test_ctx.s_len; i++) {
            if (XMEMCMP(test_ctx.s_buff + i, expectedPub, expectedPubSz) == 0) {
                found = 1;
                break;
            }
        }
        ExpectIntEQ(found, 1);

        wolfSSL_free(ssl_c);
        wolfSSL_free(ssl_s);
        wolfSSL_CTX_free(ctx_c);
        wolfSSL_CTX_free(ctx_s);
    }

    /* Only the client loads the private-only static key. The server keeps a
     * generated ephemeral, so the handshake completes only if the client's
     * derived point matches the scalar it holds. */
    client_cbf.method = wolfTLSv1_3_client_method;
    client_cbf.ctx_ready = test_static_eph_ctx_ready;
    server_cbf.method = wolfTLSv1_3_server_method;
    server_cbf.ctx_ready = test_static_eph_peer_ctx_ready;

    ExpectIntEQ(test_wolfSSL_client_server_nofail_memio(&client_cbf,
        &server_cbf, NULL), TEST_SUCCESS);
#endif
    return EXPECT_RESULT();
}

#if defined(TEST_STATIC_EPHEMERAL_PRIV_ONLY) && defined(WOLF_CRYPTO_CB) && \
    !defined(WOLF_CRYPTO_CB_ONLY_ECC)
    #define TEST_STATIC_EPHEMERAL_NO_DERIVE
    #include <wolfssl/wolfcrypt/cryptocb.h>

#define TEST_STATIC_EPH_NO_DERIVE_DEVID 0x5345504B /* "SEPK" */

static int staticEphMakePubDeclined = 0;
/* What the first make-pub returns. Later ones fall through to software, so a
 * load error would be hidden by the generated key. */
static int staticEphMakePubResult = NO_VALID_DEVID;

/* Fails the first make-pub and leaves everything else to software. */
static int test_static_eph_no_derive_cb(int devId, wc_CryptoInfo* info,
    void* ctx)
{
    (void)ctx;

    if ((devId == TEST_STATIC_EPH_NO_DERIVE_DEVID) &&
            (info->algo_type == WC_ALGO_TYPE_PK) &&
            (info->pk.type == WC_PK_TYPE_EC_MAKE_PUB) &&
            (staticEphMakePubDeclined == 0)) {
        staticEphMakePubDeclined = 1;
        return staticEphMakePubResult;
    }
    return CRYPTOCB_UNAVAILABLE;
}
#endif

/* A static ECDH key whose point cannot be derived must fail the handshake,
 * not silently fall back to a fresh key. */
int test_wolfSSL_StaticEphemeralKeyLoad_no_derive(void)
{
    EXPECT_DECLS;
#ifdef TEST_STATIC_EPHEMERAL_NO_DERIVE
    ecc_key      key;
    word32       idx = 0;
    byte         der[128];
    int          derSz = 0;
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL*     ssl_c = NULL;
    WOLFSSL*     ssl_s = NULL;
    int          canDerive = test_ecc_can_derive_pub();

    /* NO_VALID_DEVID is a device with no derivation. MEMORY_E is a multiply
     * that failed outright; import already rejects an out-of-range scalar,
     * so this is the error the load must not turn into a generated key. */
    static const int makePubResult[] = { NO_VALID_DEVID, MEMORY_E };
    int r;

    XMEMSET(&key, 0, sizeof(key));
    ExpectIntGE(canDerive, 0);

    ExpectIntEQ(wc_ecc_init(&key), 0);
    ExpectIntEQ(wc_EccPrivateKeyDecode(ecc_clikey_der_256, &idx, &key,
        (word32)sizeof_ecc_clikey_der_256), 0);
    ExpectIntGT(derSz = wc_EccPrivateKeyToDer(&key, der, (word32)sizeof(der)),
        0);
    wc_ecc_free(&key);

    ExpectIntEQ(wc_CryptoCb_RegisterDevice(TEST_STATIC_EPH_NO_DERIVE_DEVID,
        test_static_eph_no_derive_cb, NULL), 0);

    for (r = 0; r < (int)(sizeof(makePubResult) / sizeof(makePubResult[0]));
            r++) {
        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        staticEphMakePubDeclined = 0;
        staticEphMakePubResult = makePubResult[r];
        ctx_c = NULL;
        ctx_s = NULL;
        ssl_c = NULL;
        ssl_s = NULL;

        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);
        ExpectIntEQ(wolfSSL_SetDevId(ssl_c, TEST_STATIC_EPH_NO_DERIVE_DEVID),
            WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_set_ephemeral_key(ssl_c, WC_PK_TYPE_ECDH,
            (const char*)der, (unsigned int)derSz, WOLFSSL_FILETYPE_ASN1), 0);
        /* The key share is built here, from the private-only static key. */
        ExpectIntEQ(wolfSSL_UseKeyShare(ssl_c, WOLFSSL_ECC_SECP256R1),
            WC_NO_ERR_TRACE(ECC_EXPORT_ERROR));
        /* A build without derivation never asks the device. */
        if (canDerive == 1) {
            ExpectIntEQ(staticEphMakePubDeclined, 1);
        }

        wolfSSL_free(ssl_c);
        wolfSSL_free(ssl_s);
        wolfSSL_CTX_free(ctx_c);
        wolfSSL_CTX_free(ctx_s);
    }
    wc_CryptoCb_UnRegisterDevice(TEST_STATIC_EPH_NO_DERIVE_DEVID);
#endif
    return EXPECT_RESULT();
}
