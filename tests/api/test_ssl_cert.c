/* test_ssl_cert.c
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

#include <tests/utils.h>
#include <tests/api/test_ssl_cert.h>

/* Tests for the certificate APIs in src/ssl_api_cert.c (moved from ssl.c). */

int test_wolfSSL_get_verify_mode(void)
{
    EXPECT_DECLS;
#if (defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA) || defined(HAVE_STUNNEL) || \
     defined(WOLFSSL_MYSQL_COMPATIBLE) || defined(WOLFSSL_NGINX)) && \
    !defined(NO_CERTS) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    int mode;

    ExpectIntEQ(wolfSSL_get_verify_mode(NULL), WOLFSSL_FAILURE);

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    wolfSSL_set_verify(ssl, WOLFSSL_VERIFY_NONE, NULL);
    ExpectIntEQ(wolfSSL_get_verify_mode(ssl), WOLFSSL_VERIFY_NONE);

    wolfSSL_set_verify(ssl, WOLFSSL_VERIFY_PEER, NULL);
    ExpectIntEQ(wolfSSL_get_verify_mode(ssl), WOLFSSL_VERIFY_PEER);

    wolfSSL_set_verify(ssl, WOLFSSL_VERIFY_PEER |
        WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    ExpectIntEQ(wolfSSL_get_verify_mode(ssl),
        WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT);

    /* Exercise the fail-except-PSK option. */
    wolfSSL_set_verify(ssl, WOLFSSL_VERIFY_FAIL_EXCEPT_PSK, NULL);
    mode = wolfSSL_get_verify_mode(ssl);
    ExpectIntEQ(mode & WOLFSSL_VERIFY_FAIL_EXCEPT_PSK,
        WOLFSSL_VERIFY_FAIL_EXCEPT_PSK);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_CTX_get_verify_mode(void)
{
    EXPECT_DECLS;
#if (defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA) || defined(HAVE_STUNNEL) || \
     defined(WOLFSSL_MYSQL_COMPATIBLE) || defined(WOLFSSL_NGINX)) && \
    !defined(NO_CERTS) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;
    int mode;

    ExpectIntEQ(wolfSSL_CTX_get_verify_mode(NULL), WOLFSSL_FAILURE);

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
    ExpectIntEQ(wolfSSL_CTX_get_verify_mode(ctx), WOLFSSL_VERIFY_NONE);

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER |
        WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    ExpectIntEQ(wolfSSL_CTX_get_verify_mode(ctx),
        WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT);

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_FAIL_EXCEPT_PSK, NULL);
    mode = wolfSSL_CTX_get_verify_mode(ctx);
    ExpectIntEQ(mode & WOLFSSL_VERIFY_FAIL_EXCEPT_PSK,
        WOLFSSL_VERIFY_FAIL_EXCEPT_PSK);

#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_POST_HANDSHAKE_AUTH)
    /* Exercise the post-handshake auth option. */
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER |
        WOLFSSL_VERIFY_POST_HANDSHAKE, NULL);
    mode = wolfSSL_CTX_get_verify_mode(ctx);
    ExpectIntEQ(mode & WOLFSSL_VERIFY_POST_HANDSHAKE,
        WOLFSSL_VERIFY_POST_HANDSHAKE);
#endif

    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

#if defined(OPENSSL_ALL) && !defined(NO_CERTS) && !defined(NO_WOLFSSL_CLIENT) \
    && !defined(NO_TLS)
static int test_cert_verify_cb(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    (void)store;
    return preverify;
}
#endif

int test_wolfSSL_get_verify_callback(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && !defined(NO_CERTS) && !defined(NO_WOLFSSL_CLIENT) \
    && !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    /* CTX verify callback getter. */
    ExpectNull(wolfSSL_CTX_get_verify_callback(NULL));
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNull(wolfSSL_CTX_get_verify_callback(ctx));
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, test_cert_verify_cb);
    ExpectTrue(wolfSSL_CTX_get_verify_callback(ctx) == test_cert_verify_cb);

    /* SSL verify callback getter. */
    ExpectNull(wolfSSL_get_verify_callback(NULL));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    wolfSSL_set_verify(ssl, WOLFSSL_VERIFY_PEER, test_cert_verify_cb);
    ExpectTrue(wolfSSL_get_verify_callback(ssl) == test_cert_verify_cb);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_CTX_get_extra_chain_certs(void)
{
    EXPECT_DECLS;
#if (defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY) || \
     defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL)) && \
    !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && !defined(NO_RSA) && \
    !defined(NO_WOLFSSL_SERVER) && !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;
    WOLF_STACK_OF(WOLFSSL_X509)* sk = NULL;

    /* NULL arguments fail. */
    ExpectIntEQ(wolfSSL_CTX_get_extra_chain_certs(NULL, &sk), WOLFSSL_FAILURE);

    /* No certificate chain loaded: succeeds with an empty (NULL) stack. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_server_method()));
    sk = NULL;
    ExpectIntEQ(wolfSSL_CTX_get_extra_chain_certs(ctx, &sk), WOLFSSL_SUCCESS);
    ExpectNull(sk);
    wolfSSL_CTX_free(ctx);
    ctx = NULL;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_server_method()));
    /* server-cert.pem holds a 2-cert chain, so the CA goes into certChain. */
    ExpectIntEQ(wolfSSL_CTX_use_certificate_chain_file(ctx, svrCertFile),
        WOLFSSL_SUCCESS);

    /* Builds a stack of X509 from the stored chain. */
    sk = NULL;
    ExpectIntEQ(wolfSSL_CTX_get_extra_chain_certs(ctx, &sk), WOLFSSL_SUCCESS);
    ExpectNotNull(sk);

    /* get0 returns the same (cached) chain. */
    sk = NULL;
    ExpectIntEQ(wolfSSL_CTX_get0_chain_certs(ctx, &sk), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_get0_chain_certs(NULL, &sk), WOLFSSL_FAILURE);

    wolfSSL_CTX_free(ctx);
    ctx = NULL;

    /* A longer chain (leaf + 2 certs) exercises appending past the first
     * node, building a multi-element stack. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_server_method()));
    ExpectIntEQ(wolfSSL_CTX_use_certificate_chain_file(ctx,
        "certs/intermediate/server-chain.pem"), WOLFSSL_SUCCESS);
    sk = NULL;
    ExpectIntEQ(wolfSSL_CTX_get_extra_chain_certs(ctx, &sk), WOLFSSL_SUCCESS);
    ExpectNotNull(sk);
    ExpectIntGE(wolfSSL_sk_X509_num(sk), 2);

#if (defined(OPENSSL_ALL) || defined(WOLFSSL_ASIO) || \
     defined(WOLFSSL_HAPROXY) || defined(WOLFSSL_NGINX) || \
     defined(WOLFSSL_QT)) && !defined(NO_WOLFSSL_STUB)
    /* Stub: returns via the control command. */
    wolfSSL_CTX_clear_extra_chain_certs(ctx);
#endif

    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_get_peer_chain(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(SESSION_CERTS) && \
    !defined(WOLFSSL_NO_TLS12) && !defined(NO_RSA)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    WOLFSSL_X509_CHAIN* chain = NULL;

    /* NULL / not-yet-populated cases. */
    ExpectNull(wolfSSL_get_peer_chain(NULL));
    ExpectIntEQ(wolfSSL_get_chain_count(NULL), 0);
    ExpectIntEQ(wolfSSL_get_chain_length(NULL, 0), 0);
    ExpectNull(wolfSSL_get_chain_cert(NULL, 0));

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* The client now holds the server's certificate chain. */
    ExpectNotNull(chain = wolfSSL_get_peer_chain(ssl_c));
    ExpectIntGT(wolfSSL_get_chain_count(chain), 0);
    ExpectIntGT(wolfSSL_get_chain_length(chain, 0), 0);
    ExpectNotNull(wolfSSL_get_chain_cert(chain, 0));

#ifdef WOLFSSL_ALT_CERT_CHAINS
    ExpectNull(wolfSSL_get_peer_alt_chain(NULL));
    ExpectNotNull(wolfSSL_get_peer_alt_chain(ssl_c));
#endif

#if (defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY) || \
     defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL)) && defined(KEEP_OUR_CERT)
    {
        WOLF_STACK_OF(WOLFSSL_X509)* osk = NULL;
        ExpectIntEQ(wolfSSL_get0_chain_certs(NULL, &osk), WOLFSSL_FAILURE);
        ExpectIntEQ(wolfSSL_get0_chain_certs(ssl_c, &osk), WOLFSSL_SUCCESS);
    }
#endif

    wolfSSL_free(ssl_s);
    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_s);
    wolfSSL_CTX_free(ctx_c);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_get_chain_X509(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(SESSION_CERTS) && \
    !defined(WOLFSSL_NO_TLS12) && !defined(NO_RSA)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    WOLFSSL_X509_CHAIN* chain = NULL;
    WOLFSSL_X509* x509 = NULL;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    ExpectNotNull(chain = wolfSSL_get_peer_chain(ssl_c));

    /* A valid index returns a parseable certificate. */
    ExpectNotNull(x509 = wolfSSL_get_chain_X509(chain, 0));
    wolfSSL_X509_free(x509);
    x509 = NULL;
    /* NULL chain and an index past MAX_CHAIN_DEPTH return NULL up front. */
    ExpectNull(wolfSSL_get_chain_X509(NULL, 0));
    ExpectNull(wolfSSL_get_chain_X509(chain, MAX_CHAIN_DEPTH));
    /* An index past the populated certs exercises the parse-failure path. */
    ExpectNull(wolfSSL_get_chain_X509(chain, wolfSSL_get_chain_count(chain)));

    wolfSSL_free(ssl_s);
    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_s);
    wolfSSL_CTX_free(ctx_c);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_get_chain_cert_pem(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(SESSION_CERTS) && \
    !defined(WOLFSSL_NO_TLS12) && !defined(NO_RSA) && !defined(NO_TLS)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    WOLFSSL_X509_CHAIN* chain = NULL;
    byte pem[4096];
    int pemSz = 0;
    int needed = 0;
    int chainLen = 0;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    ExpectNotNull(chain = wolfSSL_get_peer_chain(ssl_c));

    /* Successful PEM conversion. */
    pemSz = (int)sizeof(pem);
    ExpectIntEQ(wolfSSL_get_chain_cert_pem(chain, 0, pem, (int)sizeof(pem),
        &pemSz), WOLFSSL_SUCCESS);
    ExpectIntGT(pemSz, 0);

    /* Argument validation. */
    pemSz = (int)sizeof(pem);
    ExpectIntEQ(wolfSSL_get_chain_cert_pem(NULL, 0, pem, (int)sizeof(pem),
        &pemSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_get_chain_cert_pem(chain, -1, pem, (int)sizeof(pem),
        &pemSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_get_chain_cert_pem(chain, 99, pem, (int)sizeof(pem),
        &pemSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_get_chain_cert_pem(chain, 0, pem, (int)sizeof(pem),
        NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* NULL buffer returns the size needed (length-only query). */
    needed = 0;
    ExpectIntEQ(wolfSSL_get_chain_cert_pem(chain, 0, NULL, 0, &needed),
        WC_NO_ERR_TRACE(LENGTH_ONLY_E));
    ExpectIntGT(needed, 0);
    ExpectIntLE(needed, (int)sizeof(pem));

    /* A buffer shorter than the DER certificate fails up front. */
    pemSz = (int)sizeof(pem);
    ExpectIntEQ(wolfSSL_get_chain_cert_pem(chain, 0, pem, 1, &pemSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* One byte short of the full size leaves no room for the footer. */
    pemSz = (int)sizeof(pem);
    ExpectIntEQ(wolfSSL_get_chain_cert_pem(chain, 0, pem, needed - 1, &pemSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Room for the DER length but not the base64-expanded body: the encoder
     * reports an error (negative return). */
    chainLen = wolfSSL_get_chain_length(chain, 0);
    pemSz = (int)sizeof(pem);
    ExpectIntLT(wolfSSL_get_chain_cert_pem(chain, 0, pem, chainLen + 100,
        &pemSz), 0);

    wolfSSL_free(ssl_s);
    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_s);
    wolfSSL_CTX_free(ctx_c);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_cmp_peer_cert_to_file(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(OPENSSL_EXTRA) && \
    defined(KEEP_PEER_CERT) && defined(HAVE_EX_DATA) && \
    !defined(NO_FILESYSTEM) && !defined(WOLFSSL_NO_TLS12) && !defined(NO_RSA) \
    && !defined(NO_TLS)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* NULL arguments report failure. */
    ExpectIntEQ(wolfSSL_cmp_peer_cert_to_file(NULL, svrCertFile),
        WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_cmp_peer_cert_to_file(ssl_c, NULL),
        WOLFSSL_FATAL_ERROR);

    /* The peer (server) certificate matches the file it was loaded from. */
    ExpectIntEQ(wolfSSL_cmp_peer_cert_to_file(ssl_c, svrCertFile), 0);
    /* A different certificate does not match. */
    ExpectIntEQ(wolfSSL_cmp_peer_cert_to_file(ssl_c, caCertFile),
        WOLFSSL_FATAL_ERROR);
    /* A missing file reports a file error. */
    ExpectIntEQ(wolfSSL_cmp_peer_cert_to_file(ssl_c,
        "certs/does-not-exist.pem"), WC_NO_ERR_TRACE(WOLFSSL_BAD_FILE));
    /* A readable file that is not PEM-encoded fails conversion. */
    ExpectIntEQ(wolfSSL_cmp_peer_cert_to_file(ssl_c, cliCertDerFile),
        WOLFSSL_FATAL_ERROR);

    wolfSSL_free(ssl_s);
    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_s);
    wolfSSL_CTX_free(ctx_c);
#endif
    return EXPECT_RESULT();
}
