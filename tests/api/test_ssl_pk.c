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

    ExpectIntEQ(wolfSSL_CTX_SetMaxDhKey_Sz(ctx, 4096), WOLFSSL_SUCCESS);

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

    ExpectIntEQ(wolfSSL_SetMaxDhKey_Sz(ssl, 4096), WOLFSSL_SUCCESS);

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
            mldsa_65_sa_algo, mldsa_87_sa_algo, sm2_sa_algo
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
