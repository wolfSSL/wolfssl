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

/* Test reading back the verification mode from an object.
 *
 * @return  TEST_SUCCESS on success.
 */
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

/* Test reading back the verification mode from a context.
 *
 * @return  TEST_SUCCESS on success.
 */
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

/* Test reading back the verification callback.
 *
 * The object inherits the context's callback until one is set on it.
 *
 * @return  TEST_SUCCESS on success.
 */
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

/* Test getting the extra certificates loaded with the chain.
 *
 * The stack is only present once a chain file has been loaded.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_CTX_get_extra_chain_certs(void)
{
    EXPECT_DECLS;
#if (defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY) || \
     defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL)) && \
    !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && !defined(NO_RSA) && \
    !defined(NO_WOLFSSL_SERVER) && !defined(NO_TLS) && \
    defined(WOLFSSL_PEM_TO_DER)
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

/* Test walking the peer's certificate chain by index.
 *
 * Covers the count, the per-certificate length and DER accessors, and the
 * alternative chain used with alternative certificates.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_get_peer_chain(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(SESSION_CERTS) && \
    !defined(WOLFSSL_NO_TLS12) && !defined(NO_RSA)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    WOLFSSL_X509_CHAIN* chain = NULL;
#if (defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY) || \
     defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL)) && defined(KEEP_OUR_CERT)
    WOLF_STACK_OF(WOLFSSL_X509)* osk = NULL;
#endif

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
    ExpectIntEQ(wolfSSL_get0_chain_certs(NULL, &osk), WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_get0_chain_certs(ssl_c, &osk), WOLFSSL_SUCCESS);
#endif

    wolfSSL_free(ssl_s);
    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_s);
    wolfSSL_CTX_free(ctx_c);
#endif
    return EXPECT_RESULT();
}

/* Test getting a peer chain certificate as an X509 object.
 *
 * The object returned is owned by the caller and must be freed.
 *
 * @return  TEST_SUCCESS on success.
 */
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

/* Test converting a peer chain certificate to PEM.
 *
 * A NULL buffer reports the length needed rather than converting.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_get_chain_cert_pem(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(SESSION_CERTS) && \
    !defined(WOLFSSL_NO_TLS12) && !defined(NO_RSA) && !defined(NO_TLS) && \
    (defined(WOLFSSL_DER_TO_PEM) || defined(WOLFSSL_PEM_TO_DER))
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
    /* A negative buffer length is rejected. */
    ExpectIntEQ(wolfSSL_get_chain_cert_pem(chain, 0, pem, -1, &pemSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
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

/* Test comparing the peer's certificate against one in a file.
 *
 * The file is parsed as PEM, so it must be the PEM form of the same certificate
 * to match.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_cmp_peer_cert_to_file(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(OPENSSL_EXTRA) && \
    defined(KEEP_PEER_CERT) && defined(HAVE_EX_DATA) && \
    !defined(NO_FILESYSTEM) && !defined(WOLFSSL_NO_TLS12) && !defined(NO_RSA) \
    && !defined(NO_TLS) && defined(WOLFSSL_PEM_TO_DER)
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

/* Guarded to match its only caller, test_wolfSSL_CTX_set_client_cert_cb(),
 * which needs OPENSSL_EXTRA for the ctx->CBClientCert field. */
#if defined(WOLFSSL_CERT_SETUP_CB) && defined(OPENSSL_EXTRA) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    !defined(WOLFSSL_NO_TLS12)
/* Client certificate callback that supplies nothing.
 *
 * @param [in]  ssl   SSL/TLS object. Unused.
 * @param [out] x509  Certificate to use. Unused.
 * @param [out] pkey  Private key to use. Unused.
 * @return  0 to indicate no certificate was supplied.
 */
static int test_ssl_cert_client_cert_cb(WOLFSSL* ssl, WOLFSSL_X509** x509,
    WOLFSSL_EVP_PKEY** pkey)
{
    (void)ssl;
    (void)x509;
    (void)pkey;
    return 0;
}
#endif

/* Test setting the client certificate callback on a context.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_CTX_set_client_cert_cb(void)
{
    EXPECT_DECLS;
/* Reads ctx->CBClientCert, which the structure only has under
 * OPENSSL_EXTRA, so this is narrower than the setter's own guard. */
#if defined(WOLFSSL_CERT_SETUP_CB) && defined(OPENSSL_EXTRA) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx = NULL;

    /* A NULL context is ignored rather than faulting. */
    wolfSSL_CTX_set_client_cert_cb(NULL, test_ssl_cert_client_cert_cb);

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    if (ctx != NULL) {
        wolfSSL_CTX_set_client_cert_cb(ctx, test_ssl_cert_client_cert_cb);
        ExpectTrue(ctx->CBClientCert == test_ssl_cert_client_cert_cb);

        /* The callback can be cleared again. */
        wolfSSL_CTX_set_client_cert_cb(ctx, NULL);
        ExpectNull(ctx->CBClientCert);
    }
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* Guarded to cover both callers: test_wolfSSL_CTX_set_cert_cb() needs a
 * server, and test_wolfSSL_cert_setup_cb_ret() needs a memio handshake. The
 * counters move with the callback so they cannot go unused either. */
#if defined(WOLFSSL_CERT_SETUP_CB) && !defined(NO_TLS) && \
    !defined(WOLFSSL_NO_TLS12) && (!defined(NO_WOLFSSL_SERVER) || \
    (defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && !defined(NO_RSA)))
static int test_ssl_cert_setup_ret = 1;
static int test_ssl_cert_setup_calls = 0;

/* Certificate setup callback returning a value chosen by the test.
 *
 * @param [in] ssl  SSL/TLS object. Unused.
 * @param [in] arg  Context passed when the callback was set. Unused.
 * @return  The value in test_ssl_cert_setup_ret.
 */
static int test_ssl_cert_setup_cb(WOLFSSL* ssl, void* arg)
{
    (void)ssl;
    (void)arg;
    test_ssl_cert_setup_calls++;
    return test_ssl_cert_setup_ret;
}
#endif

/* Test setting the certificate setup callback on a context.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_CTX_set_cert_cb(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_CERT_SETUP_CB) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(NO_TLS) && !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx = NULL;
    int arg = 0;

    /* A NULL context is ignored rather than faulting. */
    wolfSSL_CTX_set_cert_cb(NULL, test_ssl_cert_setup_cb, &arg);

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method()));
    if (ctx != NULL) {
        wolfSSL_CTX_set_cert_cb(ctx, test_ssl_cert_setup_cb, &arg);
        ExpectTrue(ctx->certSetupCb == test_ssl_cert_setup_cb);
        ExpectPtrEq(ctx->certSetupCbArg, &arg);

        /* Both the callback and its context can be cleared. */
        wolfSSL_CTX_set_cert_cb(ctx, NULL, NULL);
        ExpectNull(ctx->certSetupCb);
        ExpectNull(ctx->certSetupCbArg);
    }
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* Test how the return value of the certificate setup callback is handled.
 *
 * The callback is called on the server while the ClientHello is processed, so
 * each return value is observed as the outcome of the handshake.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_cert_setup_cb_ret(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_CERT_SETUP_CB) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(WOLFSSL_NO_TLS12) && !defined(NO_RSA) && !defined(NO_TLS)
    /* cbRet is what the callback returns. err is the error the server then
     * reports: 0 means the handshake is expected to complete, and -1 means
     * only that it must fail.
     *
     * A negative callback return makes the wrapper report
     * WOLFSSL_ERROR_WANT_X509_LOOKUP, which is a positive value and so does
     * not reach wolfSSL_get_error(). Only the failure is checked for that
     * case rather than the code that happens to surface. */
    static const struct {
        int cbRet;
        int err;
    } cases[] = {
        { 1, 0 },
        { 0, WC_NO_ERR_TRACE(CLIENT_CERT_CB_ERROR) },
        { -1, -1 },
        { 2, WC_NO_ERR_TRACE(CLIENT_CERT_CB_ERROR) }
    };
    int i;

    for (i = 0; i < (int)(sizeof(cases) / sizeof(cases[0])); i++) {
        WOLFSSL_CTX* ctx_c = NULL;
        WOLFSSL_CTX* ctx_s = NULL;
        WOLFSSL* ssl_c = NULL;
        WOLFSSL* ssl_s = NULL;
        struct test_memio_ctx test_ctx;

        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);

        test_ssl_cert_setup_ret = cases[i].cbRet;
        test_ssl_cert_setup_calls = 0;
        wolfSSL_CTX_set_cert_cb(ctx_s, test_ssl_cert_setup_cb, NULL);

        if (cases[i].err == 0) {
            ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
        }
        else {
            /* Drive one step at a time so the error the server reports is the
             * one the callback caused, not a later I/O failure. */
            ExpectIntEQ(wolfSSL_connect(ssl_c),
                WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
            ExpectIntEQ(wolfSSL_get_error(ssl_c, 0), WOLFSSL_ERROR_WANT_READ);
            ExpectIntEQ(wolfSSL_accept(ssl_s),
                WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
            if (cases[i].err != -1) {
                ExpectIntEQ(wolfSSL_get_error(ssl_s, 0), cases[i].err);
            }
            else {
                ExpectIntNE(wolfSSL_get_error(ssl_s, 0), 0);
            }
        }
        /* The callback ran regardless of what it reported. */
        ExpectIntGT(test_ssl_cert_setup_calls, 0);

        wolfSSL_free(ssl_c);
        wolfSSL_free(ssl_s);
        wolfSSL_CTX_free(ctx_c);
        wolfSSL_CTX_free(ctx_s);
    }
    test_ssl_cert_setup_ret = 1;
#endif
    return EXPECT_RESULT();
}

/* Test getting the stack of the peer's certificates.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_get_peer_cert_chain(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(SESSION_CERTS) && \
    defined(OPENSSL_EXTRA) && !defined(WOLFSSL_NO_TLS12) && !defined(NO_RSA) \
    && !defined(NO_TLS)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    WOLF_STACK_OF(WOLFSSL_X509)* sk = NULL;

    ExpectNull(wolfSSL_get_peer_cert_chain(NULL));

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);

    /* Nothing has been received yet, so there is no chain to build. */
    ExpectNull(wolfSSL_get_peer_cert_chain(ssl_c));

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* The client now holds the server's chain. */
    ExpectNotNull(sk = wolfSSL_get_peer_cert_chain(ssl_c));
    ExpectIntGT(wolfSSL_sk_X509_num(sk), 0);
    /* The stack is owned by the object, so asking again returns the same one
     * rather than building another. */
    ExpectPtrEq(wolfSSL_get_peer_cert_chain(ssl_c), sk);

    wolfSSL_free(ssl_s);
    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_s);
    wolfSSL_CTX_free(ctx_c);
#endif
    return EXPECT_RESULT();
}

/* Test building the stack of the peer's certificates.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_set_peer_cert_chain(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(SESSION_CERTS) && \
    defined(OPENSSL_EXTRA) && !defined(WOLFSSL_NO_TLS12) && !defined(NO_RSA) \
    && !defined(NO_TLS) && !defined(NO_FILESYSTEM) && \
    defined(WOLFSSL_PEM_TO_DER)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    WOLF_STACK_OF(WOLFSSL_X509)* sk = NULL;

    ExpectNull(wolfSSL_set_peer_cert_chain(NULL));

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);

    /* An empty session chain has nothing to build from. */
    ExpectNull(wolfSSL_set_peer_cert_chain(ssl_c));

    /* Ask for a client certificate so the server also ends up with a chain.
     * The credentials go on the object because test_memio_setup() has already
     * created it from the context. WOLFSSL_NO_CLIENT_AUTH compiles out the
     * client's Certificate message, so there is nothing to ask for. */
#ifndef WOLFSSL_NO_CLIENT_AUTH
    ExpectIntEQ(wolfSSL_use_certificate_file(ssl_c, cliCertFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_use_PrivateKey_file(ssl_c, cliKeyFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx_s, cliCertFile, NULL),
        WOLFSSL_SUCCESS);
    wolfSSL_set_verify(ssl_s, WOLFSSL_VERIFY_PEER, NULL);
#endif

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* Client side: the chain is stored on the object. */
    ExpectNotNull(sk = wolfSSL_set_peer_cert_chain(ssl_c));
    if (ssl_c != NULL) {
        ExpectPtrEq(ssl_c->peerCertChain, sk);
    }
    /* Called again the old chain is released and a new one stored. */
    ExpectNotNull(sk = wolfSSL_set_peer_cert_chain(ssl_c));
    if (ssl_c != NULL) {
        ExpectPtrEq(ssl_c->peerCertChain, sk);
    }

#ifndef WOLFSSL_NO_CLIENT_AUTH
    /* Server side: the leaf is moved out of the stack into the session. */
    ExpectNotNull(wolfSSL_set_peer_cert_chain(ssl_s));
    if (ssl_s != NULL) {
        ExpectNotNull(ssl_s->session->peer);
    }
    /* Building it again releases the peer stored by the previous call. */
    ExpectNotNull(wolfSSL_set_peer_cert_chain(ssl_s));
    if (ssl_s != NULL) {
        ExpectNotNull(ssl_s->session->peer);
    }
#else
    /* With no client certificate the server has no chain to build. */
    ExpectNull(wolfSSL_set_peer_cert_chain(ssl_s));
#endif

    wolfSSL_free(ssl_s);
    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_s);
    wolfSSL_CTX_free(ctx_c);
#endif
    return EXPECT_RESULT();
}

/* Test getting the verified certificate chain.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_get0_verified_chain(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(SESSION_CERTS) && \
    defined(OPENSSL_EXTRA) && defined(KEEP_PEER_CERT) && \
    !defined(WOLFSSL_NO_TLS12) && !defined(NO_RSA) && !defined(NO_TLS)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    WOLF_STACK_OF(WOLFSSL_X509)* chain = NULL;

    ExpectNull(wolfSSL_get0_verified_chain(NULL));

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);

    /* Without a peer certificate there is nothing to verify. */
    ExpectNull(wolfSSL_get0_verified_chain(ssl_c));

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* The server's chain verifies against the CA the client loaded. */
    ExpectNotNull(chain = wolfSSL_get0_verified_chain(ssl_c));
    ExpectIntGT(wolfSSL_sk_X509_num(chain), 0);
    if (ssl_c != NULL) {
        ExpectPtrEq(ssl_c->verifiedChain, chain);
    }
    /* Called again the previous chain is released and a new one stored. */
    ExpectNotNull(chain = wolfSSL_get0_verified_chain(ssl_c));
    if (ssl_c != NULL) {
        ExpectPtrEq(ssl_c->verifiedChain, chain);
    }

    wolfSSL_free(ssl_s);
    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_s);
    wolfSSL_CTX_free(ctx_c);
#endif
    return EXPECT_RESULT();
}

/* Test adding certificate subject names to the CA name lists.
 *
 * Covers the context and object variants of both the client-CA list and the
 * general CA list, and the shared helper that appends to a list.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_CA_list_add(void)
{
    EXPECT_DECLS;
#if !defined(NO_CERTS) && !defined(WOLFSSL_NO_CA_NAMES) && \
    !defined(NO_FILESYSTEM) && !defined(NO_RSA) && !defined(NO_TLS) && \
    !defined(WOLFSSL_NO_TLS12) && !defined(NO_WOLFSSL_SERVER) && \
    defined(WOLFSSL_PEM_TO_DER)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    WOLFSSL_X509* x509 = NULL;

    ExpectNotNull(x509 = wolfSSL_X509_load_certificate_file(caCertFile,
        WOLFSSL_FILETYPE_PEM));

    /* Both arguments are required. */
    ExpectIntEQ(wolfSSL_CTX_add_client_CA(NULL, x509), 0);
    ExpectIntEQ(wolfSSL_add_client_CA(NULL, x509), 0);
    ExpectIntEQ(wolfSSL_CTX_add1_to_CA_list(NULL, x509), 0);
    ExpectIntEQ(wolfSSL_add1_to_CA_list(NULL, x509), 0);

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method()));
    ExpectIntEQ(wolfSSL_CTX_use_certificate_file(ctx, svrCertFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKeyFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    ExpectIntEQ(wolfSSL_CTX_add_client_CA(ctx, NULL), 0);
    ExpectIntEQ(wolfSSL_add_client_CA(ssl, NULL), 0);
    ExpectIntEQ(wolfSSL_CTX_add1_to_CA_list(ctx, NULL), 0);
    ExpectIntEQ(wolfSSL_add1_to_CA_list(ssl, NULL), 0);

    /* The first call creates the list, the second appends to it. The object's
     * lists are filled first as, while empty, they resolve to the context's. */
    ExpectNull(wolfSSL_get_client_CA_list(ssl));
    ExpectIntEQ(wolfSSL_add_client_CA(ssl, x509), 1);
    ExpectIntEQ(wolfSSL_sk_X509_NAME_num(wolfSSL_get_client_CA_list(ssl)), 1);
    ExpectIntEQ(wolfSSL_add_client_CA(ssl, x509), 1);
    ExpectIntEQ(wolfSSL_sk_X509_NAME_num(wolfSSL_get_client_CA_list(ssl)), 2);

    ExpectNull(wolfSSL_CTX_get_client_CA_list(ctx));
    ExpectIntEQ(wolfSSL_CTX_add_client_CA(ctx, x509), 1);
    ExpectIntEQ(wolfSSL_sk_X509_NAME_num(
        wolfSSL_CTX_get_client_CA_list(ctx)), 1);
    ExpectIntEQ(wolfSSL_CTX_add_client_CA(ctx, x509), 1);
    ExpectIntEQ(wolfSSL_sk_X509_NAME_num(
        wolfSSL_CTX_get_client_CA_list(ctx)), 2);

    ExpectNull(wolfSSL_get0_CA_list(ssl));
    ExpectIntEQ(wolfSSL_add1_to_CA_list(ssl, x509), 1);
    ExpectIntEQ(wolfSSL_sk_X509_NAME_num(wolfSSL_get0_CA_list(ssl)), 1);
    ExpectIntEQ(wolfSSL_add1_to_CA_list(ssl, x509), 1);
    ExpectIntEQ(wolfSSL_sk_X509_NAME_num(wolfSSL_get0_CA_list(ssl)), 2);

    ExpectNull(wolfSSL_CTX_get0_CA_list(ctx));
    ExpectIntEQ(wolfSSL_CTX_add1_to_CA_list(ctx, x509), 1);
    ExpectIntEQ(wolfSSL_sk_X509_NAME_num(wolfSSL_CTX_get0_CA_list(ctx)), 1);
    ExpectIntEQ(wolfSSL_CTX_add1_to_CA_list(ctx, x509), 1);
    ExpectIntEQ(wolfSSL_sk_X509_NAME_num(wolfSSL_CTX_get0_CA_list(ctx)), 2);

    wolfSSL_X509_free(x509);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* Test retrieving the CA name lists.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_CA_list_get(void)
{
    EXPECT_DECLS;
#if !defined(NO_CERTS) && !defined(WOLFSSL_NO_CA_NAMES) && \
    !defined(NO_FILESYSTEM) && !defined(NO_RSA) && !defined(NO_TLS) && \
    !defined(WOLFSSL_NO_TLS12) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(NO_WOLFSSL_CLIENT) && \
    defined(WOLFSSL_PEM_TO_DER)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    WOLFSSL_X509* x509 = NULL;

    /* A NULL object has no list. */
    ExpectNull(wolfSSL_CTX_get_client_CA_list(NULL));
    ExpectNull(wolfSSL_get_client_CA_list(NULL));
    ExpectNull(wolfSSL_CTX_get0_CA_list(NULL));
    ExpectNull(wolfSSL_get0_CA_list(NULL));
    ExpectNull(wolfSSL_get0_peer_CA_list(NULL));

    ExpectNotNull(x509 = wolfSSL_X509_load_certificate_file(caCertFile,
        WOLFSSL_FILETYPE_PEM));

    /* Server side: the client CA names are the object's own list. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method()));
    ExpectIntEQ(wolfSSL_CTX_use_certificate_file(ctx, svrCertFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKeyFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* Nothing added yet. */
    ExpectNull(wolfSSL_CTX_get0_CA_list(ctx));
    ExpectNull(wolfSSL_get0_CA_list(ssl));
    /* No hello has been received, so there are no peer names. */
    ExpectNull(wolfSSL_get0_peer_CA_list(ssl));

    ExpectIntEQ(wolfSSL_CTX_add_client_CA(ctx, x509), 1);
    ExpectIntEQ(wolfSSL_CTX_add1_to_CA_list(ctx, x509), 1);
    ExpectIntEQ(wolfSSL_add_client_CA(ssl, x509), 1);
    ExpectIntEQ(wolfSSL_add1_to_CA_list(ssl, x509), 1);

    ExpectNotNull(wolfSSL_CTX_get_client_CA_list(ctx));
    ExpectNotNull(wolfSSL_get_client_CA_list(ssl));
    ExpectNotNull(wolfSSL_CTX_get0_CA_list(ctx));
    ExpectNotNull(wolfSSL_get0_CA_list(ssl));

    wolfSSL_free(ssl);
    ssl = NULL;
    wolfSSL_CTX_free(ctx);
    ctx = NULL;

    /* Client side: the client CA names come from the peer instead. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectNull(wolfSSL_get_client_CA_list(ssl));

    wolfSSL_X509_free(x509);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* Test reading a list of CA names from a file.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_load_client_CA_file(void)
{
    EXPECT_DECLS;
#if !defined(NO_CERTS) && !defined(WOLFSSL_NO_CA_NAMES) && \
    !defined(NO_BIO) && defined(OPENSSL_EXTRA) && !defined(NO_FILESYSTEM) && \
    !defined(NO_RSA) && defined(WOLFSSL_PEM_TO_DER)
    WOLF_STACK_OF(WOLFSSL_X509_NAME)* names = NULL;

    /* A file that cannot be opened reports no names. */
    ExpectNull(names = wolfSSL_load_client_CA_file("does/not/exist.pem"));
    wolfSSL_sk_X509_NAME_pop_free(names, NULL);
    names = NULL;

    /* Every certificate in the file contributes its subject name. */
    ExpectNotNull(names = wolfSSL_load_client_CA_file(caCertFile));
    ExpectIntGT(wolfSSL_sk_X509_NAME_num(names), 0);
    wolfSSL_sk_X509_NAME_pop_free(names, NULL);
#endif
    return EXPECT_RESULT();
}

/* Test requiring mutual authentication.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_mutual_auth(void)
{
    EXPECT_DECLS;
#if !defined(NO_CERTS) && !defined(NO_TLS) && !defined(WOLFSSL_NO_TLS12) && \
    !defined(NO_WOLFSSL_SERVER) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(NO_FILESYSTEM) && !defined(NO_RSA) && \
    defined(WOLFSSL_PEM_TO_DER)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    ExpectIntEQ(wolfSSL_CTX_mutual_auth(NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_mutual_auth(NULL, 1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Mutual authentication is a server-only setting. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(wolfSSL_CTX_mutual_auth(ctx, 1), WC_NO_ERR_TRACE(SIDE_ERROR));
    ExpectIntEQ(wolfSSL_mutual_auth(ssl, 1), WC_NO_ERR_TRACE(SIDE_ERROR));
    wolfSSL_free(ssl);
    ssl = NULL;
    wolfSSL_CTX_free(ctx);
    ctx = NULL;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method()));
    ExpectIntEQ(wolfSSL_CTX_use_certificate_file(ctx, svrCertFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKeyFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    ExpectIntEQ(wolfSSL_CTX_mutual_auth(ctx, 1), 0);
    ExpectIntEQ(wolfSSL_mutual_auth(ssl, 1), 0);
    /* The setting can be turned back off. */
    ExpectIntEQ(wolfSSL_CTX_mutual_auth(ctx, 0), 0);
    ExpectIntEQ(wolfSSL_mutual_auth(ssl, 0), 0);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* Test enabling post-handshake authentication.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_post_handshake_auth(void)
{
    EXPECT_DECLS;
#if !defined(NO_CERTS) && defined(OPENSSL_EXTRA) && defined(WOLFSSL_TLS13) && \
    defined(WOLFSSL_POST_HANDSHAKE_AUTH) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(NO_WOLFSSL_SERVER) && !defined(NO_TLS) && \
    !defined(NO_FILESYSTEM) && !defined(NO_RSA) && \
    defined(WOLFSSL_PEM_TO_DER)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    /* A TLS 1.3 client may ask to be authenticated after the handshake. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(wolfSSL_CTX_set_post_handshake_auth(ctx, 1), 1);
    ExpectIntEQ(wolfSSL_set_post_handshake_auth(ssl, 1), 1);
    /* And can turn it back off. */
    ExpectIntEQ(wolfSSL_CTX_set_post_handshake_auth(ctx, 0), 1);
    ExpectIntEQ(wolfSSL_set_post_handshake_auth(ssl, 0), 1);
    wolfSSL_free(ssl);
    ssl = NULL;
    wolfSSL_CTX_free(ctx);
    ctx = NULL;

    /* A server cannot request it of itself. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method()));
    ExpectIntEQ(wolfSSL_CTX_use_certificate_file(ctx, svrCertFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKeyFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(wolfSSL_CTX_set_post_handshake_auth(ctx, 1), 0);
    ExpectIntEQ(wolfSSL_set_post_handshake_auth(ssl, 1), 0);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* Test setting the certificate store used for verification.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_verify_cert_store(void)
{
    EXPECT_DECLS;
#if !defined(NO_CERTS) && defined(OPENSSL_ALL) && !defined(NO_TLS) && \
    !defined(WOLFSSL_NO_TLS12) && !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    WOLFSSL_X509_STORE* store = NULL;
    WOLFSSL_X509_STORE* store2 = NULL;
    WOLFSSL_X509_STORE* store3 = NULL;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* The object being set is required. */
    ExpectIntEQ(wolfSSL_CTX_set1_verify_cert_store(NULL, NULL), 0);
    ExpectIntEQ(wolfSSL_set0_verify_cert_store(NULL, NULL), 0);
    ExpectIntEQ(wolfSSL_set1_verify_cert_store(NULL, NULL), 0);

    /* On an object a NULL store clears, so clearing when none is set
     * succeeds and does nothing. The context form refuses it - see the note
     * on wolfSSL_CTX_set1_verify_cert_store(). */
    ExpectIntEQ(wolfSSL_CTX_set1_verify_cert_store(ctx, NULL), 0);
    ExpectIntEQ(wolfSSL_set0_verify_cert_store(ssl, NULL), 1);
    ExpectIntEQ(wolfSSL_set1_verify_cert_store(ssl, NULL), 1);

    /* The store a context owns is not reference counted - its lifetime is
     * the context's. Taking a reference on it succeeds without touching a
     * count that was never initialized, and releasing it does nothing. */
    ExpectIntEQ(wolfSSL_X509_STORE_up_ref(wolfSSL_CTX_get_cert_store(ctx)), 1);
    wolfSSL_X509_STORE_free(wolfSSL_CTX_get_cert_store(ctx));
    ExpectNotNull(wolfSSL_CTX_get_cert_store(ctx));
    /* There is no store to take a reference on. */
    ExpectIntEQ(wolfSSL_X509_STORE_up_ref(NULL), 0);

    /* Setting the store already in use is accepted and changes nothing, both
     * for the context and for an object handed the store the context owns. */
    ExpectIntEQ(wolfSSL_CTX_set1_verify_cert_store(ctx,
        wolfSSL_CTX_get_cert_store(ctx)), 1);
    ExpectIntEQ(wolfSSL_set1_verify_cert_store(ssl,
        wolfSSL_CTX_get_cert_store(ctx)), 1);

    /* A different store is taken with a reference. */
    ExpectNotNull(store = wolfSSL_X509_STORE_new());
    ExpectIntEQ(wolfSSL_CTX_set1_verify_cert_store(ctx, store), 1);

    /* Give the object a store of its own, then hand it the context's store:
     * it drops its own and goes back to using the context's. */
    ExpectNotNull(store2 = wolfSSL_X509_STORE_new());
    ExpectIntEQ(wolfSSL_set1_verify_cert_store(ssl, store2), 1);
    ExpectIntEQ(wolfSSL_set1_verify_cert_store(ssl, store), 1);

    /* set0 hands a reference over and consumes it by keeping it, so the
     * caller must own one for every call that gives the object a store of
     * its own. */
    ExpectNotNull(store3 = wolfSSL_X509_STORE_new());
    ExpectIntEQ(wolfSSL_set0_verify_cert_store(ssl, store3), 1);

    /* Setting the store the object already holds changes no reference at all,
     * either way round. Consuming one would destroy the store when the caller
     * handed over a pointer it did not own, and a dangling x509_store_pt is
     * worse than the reference this leaks instead. */
    ExpectIntEQ(wolfSSL_set0_verify_cert_store(ssl, store3), 1);
    ExpectIntEQ(wolfSSL_set1_verify_cert_store(ssl, store3), 1);
    /* Still alive and still the object's, so a reference can be taken. */
    ExpectIntEQ(wolfSSL_X509_STORE_up_ref(store3), 1);
    wolfSSL_X509_STORE_free(store3);

    /* Handing over the context's store drops the object's own and reverts it
     * to the context's. No reference is consumed: the context owns that store
     * and releasing it here would leave ctx->x509_store_pt pointing at memory
     * freed a second time by wolfSSL_CTX_free(). */
    ExpectIntEQ(wolfSSL_set0_verify_cert_store(ssl,
        wolfSSL_CTX_get_cert_store(ctx)), 1);
    ExpectPtrEq(wolfSSL_CTX_get_cert_store(ctx), store);
    /* Still alive and still the context's, so a reference can be taken. */
    ExpectIntEQ(wolfSSL_X509_STORE_up_ref(store), 1);
    wolfSSL_X509_STORE_free(store);

    /* Repeating it with the object already on the context's store takes the
     * early exit instead, and must leave the references alone the same way.
     * This is the shape that freed the context's store: an object with no
     * store of its own, handed the context's with set0. */
    ExpectIntEQ(wolfSSL_set0_verify_cert_store(ssl,
        wolfSSL_CTX_get_cert_store(ctx)), 1);
    ExpectPtrEq(wolfSSL_CTX_get_cert_store(ctx), store);
    ExpectIntEQ(wolfSSL_X509_STORE_up_ref(store), 1);
    wolfSSL_X509_STORE_free(store);

    /* The object is back on the context's store, so setting that same store
     * with set1 takes no reference and releases none. */
    ExpectIntEQ(wolfSSL_set1_verify_cert_store(ssl, store), 1);
    ExpectPtrEq(wolfSSL_CTX_get_cert_store(ctx), store);

    /* Give the object a store of its own again and clear it: the object
     * releases its reference and reverts to the context's store. The store
     * itself is still alive, so a reference can still be taken on it. */
    ExpectIntEQ(wolfSSL_set1_verify_cert_store(ssl, store2), 1);
    ExpectIntEQ(wolfSSL_set1_verify_cert_store(ssl, NULL), 1);
    ExpectIntEQ(wolfSSL_X509_STORE_up_ref(store2), 1);
    wolfSSL_X509_STORE_free(store2);

    /* set0 clears the same way - no reference is handed over with a NULL
     * store, so there is none to consume. */
    ExpectIntEQ(wolfSSL_set1_verify_cert_store(ssl, store2), 1);
    ExpectIntEQ(wolfSSL_set0_verify_cert_store(ssl, NULL), 1);

    /* A NULL store is refused and changes nothing: the one field here holds
     * what OpenSSL keeps as two, so releasing it would throw away the store
     * given to wolfSSL_CTX_set_cert_store().  Refusing keeps the unsupported
     * request visible to the caller. */
    ExpectIntEQ(wolfSSL_CTX_set1_verify_cert_store(ctx, NULL), 0);
    ExpectPtrEq(wolfSSL_CTX_get_cert_store(ctx), store);

    /* Release the references this test created. */
    wolfSSL_X509_STORE_free(store);
    wolfSSL_X509_STORE_free(store2);

    /* A NULL context has no store. */
    ExpectNull(wolfSSL_CTX_get_cert_store(NULL));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* Test which store an object uses for verification.
 *
 * An object with no store of its own uses the context's, and keeps no pointer
 * to it, so it follows the context when the context's store changes. A store
 * set on the object takes precedence until cleared.
 *
 * Each store has its own certificate manager, and only one of them is given
 * the CA that signed the CRL. Loading a CRL through the object goes to the
 * manager of the store the object resolves to, so whether the load succeeds
 * says which store that is.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_verify_cert_store_follows_ctx(void)
{
    EXPECT_DECLS;
/* wolfSSL_X509_STORE_load_locations(), used below, is compiled only when the
 * directory API is available - see the guard in src/x509_str.c. */
#if !defined(NO_CERTS) && defined(OPENSSL_ALL) && !defined(NO_TLS) && \
    !defined(WOLFSSL_NO_TLS12) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(NO_RSA) && defined(HAVE_CRL) && !defined(NO_FILESYSTEM) && \
    !defined(NO_WOLFSSL_DIR) && defined(WOLFSSL_PEM_TO_DER)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    WOLFSSL_X509_STORE* noCa = NULL;
    WOLFSSL_X509_STORE* noCa2 = NULL;
    WOLFSSL_X509_STORE* withCa = NULL;
    WOLFSSL_X509_STORE* withCa2 = NULL;
    /* Two CRLs from the same CA. A manager keeps the CRLs tried against it,
     * whether or not they verified, so no manager below is asked for the same
     * CRL twice - a second attempt would find the cached one and succeed. */
    const char* crlPem = "./certs/crl/crl.pem";
    const char* crlPem2 = "./certs/crl/crl.revoked";

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    ExpectNotNull(noCa = wolfSSL_X509_STORE_new());
    ExpectNotNull(noCa2 = wolfSSL_X509_STORE_new());
    ExpectNotNull(withCa = wolfSSL_X509_STORE_new());
    ExpectNotNull(withCa2 = wolfSSL_X509_STORE_new());
    ExpectIntEQ(wolfSSL_X509_STORE_load_locations(withCa, caCertFile, NULL), 1);
    ExpectIntEQ(wolfSSL_X509_STORE_load_locations(withCa2, caCertFile, NULL),
        1);

    /* Hand the object the store the context is using while that is the store
     * the context owns: no pointer to it is kept either. */
    ExpectIntEQ(wolfSSL_set1_verify_cert_store(ssl,
        wolfSSL_CTX_get_cert_store(ctx)), 1);
    /* So the object follows the context onto a store that has the CA. Were
     * the context's own store pinned to the object instead, the manager in
     * use would still be the context's, which has no CA. */
    ExpectIntEQ(wolfSSL_CTX_set1_verify_cert_store(ctx, withCa), 1);
    ExpectIntEQ(wolfSSL_LoadCRLFile(ssl, crlPem, WOLFSSL_FILETYPE_PEM), 1);

    /* Same again for a store the context was given rather than owns. */
    ExpectIntEQ(wolfSSL_CTX_set1_verify_cert_store(ctx, noCa), 1);
    ExpectIntEQ(wolfSSL_set1_verify_cert_store(ssl, noCa), 1);
    /* That store has no CA to verify the CRL against. */
    ExpectIntNE(wolfSSL_LoadCRLFile(ssl, crlPem2, WOLFSSL_FILETYPE_PEM), 1);
    /* Changing the context's store changes the one the object uses. Were the
     * store above pinned to the object instead, it would still be in use. */
    ExpectIntEQ(wolfSSL_CTX_set1_verify_cert_store(ctx, withCa2), 1);
    ExpectIntEQ(wolfSSL_LoadCRLFile(ssl, crlPem, WOLFSSL_FILETYPE_PEM), 1);

    /* A store set on the object is used ahead of the context's. */
    ExpectIntEQ(wolfSSL_set1_verify_cert_store(ssl, noCa2), 1);
    ExpectIntNE(wolfSSL_LoadCRLFile(ssl, crlPem, WOLFSSL_FILETYPE_PEM), 1);

    /* Clearing it puts the object back on the context's store. */
    ExpectIntEQ(wolfSSL_set1_verify_cert_store(ssl, NULL), 1);
    ExpectIntEQ(wolfSSL_LoadCRLFile(ssl, crlPem2, WOLFSSL_FILETYPE_PEM), 1);

    /* Release the references this test created. */
    wolfSSL_X509_STORE_free(noCa);
    wolfSSL_X509_STORE_free(noCa2);
    wolfSSL_X509_STORE_free(withCa);
    wolfSSL_X509_STORE_free(withCa2);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* Test that releasing a store the certificate manager is paired with does not
 * leave the manager pointing at it.
 *
 * wolfSSL_CTX_set_cert_store() takes the store handed to it and has the
 * manager keep a pointer back to it. Releasing that store - by clearing or by
 * setting another - must not leave that pointer behind: it is used without a
 * further check when looking up a certificate by issuer (see src/crl.c).
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_CTX_cert_store_manager_link(void)
{
    EXPECT_DECLS;
#if !defined(NO_CERTS) && defined(OPENSSL_ALL) && !defined(NO_TLS) && \
    !defined(WOLFSSL_NO_TLS12) && !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL_X509_STORE* store = NULL;
    WOLFSSL_X509_STORE* store3 = NULL;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));

    /* The context starts out paired with the store it owns. */
    if (ctx != NULL) {
        ExpectNotNull(ctx->cm);
        ExpectPtrEq(ctx->cm->x509_store_p, &ctx->x509_store);
    }

    /* Handing a store over pairs the manager with that store instead. The
     * context takes the caller's reference rather than adding one. */
    ExpectNotNull(store = wolfSSL_X509_STORE_new());
    wolfSSL_CTX_set_cert_store(ctx, store);
    if (ctx != NULL) {
        ExpectPtrEq(wolfSSL_CTX_get_cert_store(ctx), store);
        ExpectPtrEq(ctx->cm->x509_store_p, store);
    }

    /* A NULL store is refused and changes nothing, so the pairing is
     * untouched. */
    ExpectIntEQ(wolfSSL_CTX_set1_verify_cert_store(ctx, NULL), 0);
    if (ctx != NULL) {
        ExpectPtrEq(ctx->cm->x509_store_p, store);
    }

    /* Replacing the paired store does release it, and that is where the
     * manager would be left pointing at freed memory. */
    ExpectNotNull(store3 = wolfSSL_X509_STORE_new());
    ExpectIntEQ(wolfSSL_CTX_set1_verify_cert_store(ctx, store3), 1);
    if (ctx != NULL) {
        /* store has been released - the manager keeps its own store, which
         * is the one it shares a manager with. */
        ExpectPtrEq(ctx->cm->x509_store_p, &ctx->x509_store);
    }

    /* store was released above. store3 is referenced by both this test and
     * the context. */
    wolfSSL_X509_STORE_free(store3);

    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* Guarded to match its only caller, test_wolfSSL_cert_cb_ctx(). */
#if !defined(NO_CERTS) && !defined(NO_TLS) && !defined(WOLFSSL_NO_TLS12) && \
    !defined(NO_WOLFSSL_CLIENT)
/* CA cache addition callback that does nothing.
 *
 * @param [in] der   DER encoded certificate. Unused.
 * @param [in] sz    Length of the certificate. Unused.
 * @param [in] type  Type of the certificate. Unused.
 */
static void test_ssl_cert_ca_cache_cb(unsigned char* der, int sz, int type)
{
    (void)der;
    (void)sz;
    (void)type;
}
#endif

/* Test storing the user contexts and callbacks used during verification.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_cert_cb_ctx(void)
{
    EXPECT_DECLS;
#if !defined(NO_CERTS) && !defined(NO_TLS) && !defined(WOLFSSL_NO_TLS12) && \
    !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    int userCtx = 0;

    /* NULL objects are ignored rather than faulting. */
    wolfSSL_CTX_SetCertCbCtx(NULL, &userCtx);
    wolfSSL_SetCertCbCtx(NULL, &userCtx);
    wolfSSL_CTX_SetCACb(NULL, test_ssl_cert_ca_cache_cb);

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    wolfSSL_CTX_SetCertCbCtx(ctx, &userCtx);
    wolfSSL_SetCertCbCtx(ssl, &userCtx);
    if (ctx != NULL) {
        ExpectPtrEq(ctx->verifyCbCtx, &userCtx);
    }
    if (ssl != NULL) {
        ExpectPtrEq(ssl->verifyCbCtx, &userCtx);
    }

    wolfSSL_CTX_SetCACb(ctx, test_ssl_cert_ca_cache_cb);
    if ((ctx != NULL) && (ctx->cm != NULL)) {
        ExpectTrue(ctx->cm->caCacheCallback == test_ssl_cert_ca_cache_cb);
    }

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* Test getting the certificate the object will present.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_get_certificate_api(void)
{
    EXPECT_DECLS;
#if !defined(NO_CERTS) && \
    (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)) && \
    defined(KEEP_OUR_CERT) && !defined(NO_TLS) && !defined(WOLFSSL_NO_TLS12) \
    && !defined(NO_WOLFSSL_SERVER) && !defined(NO_FILESYSTEM) && \
    !defined(NO_RSA) && \
    defined(WOLFSSL_PEM_TO_DER)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    ExpectNull(wolfSSL_get_certificate(NULL));

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method()));
    ExpectIntEQ(wolfSSL_CTX_use_certificate_file(ctx, svrCertFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKeyFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* The object borrows the context's certificate. */
    ExpectNotNull(wolfSSL_get_certificate(ssl));

    /* Loading a certificate onto the object makes it own one instead. */
    ExpectIntEQ(wolfSSL_use_certificate_file(ssl, svrCertFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectNotNull(wolfSSL_get_certificate(ssl));
    /* Asked again the cached object is returned. */
    ExpectNotNull(wolfSSL_get_certificate(ssl));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* Test the certificate unload and cache-size APIs.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_cert_unload(void)
{
    EXPECT_DECLS;
#if !defined(NO_CERTS) && !defined(NO_TLS) && !defined(WOLFSSL_NO_TLS12) && \
    !defined(NO_WOLFSSL_SERVER) && !defined(NO_FILESYSTEM) && !defined(NO_RSA) \
    && defined(WOLFSSL_PEM_TO_DER)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_TLS13) && \
    defined(WOLFSSL_POST_HANDSHAKE_AUTH) && !defined(NO_WOLFSSL_SERVER)
    /* Requesting a certificate of nothing fails, and is reported as a general
     * error rather than as a protocol version problem. */
    ExpectIntEQ(wolfSSL_verify_client_post_handshake(NULL), 0);
#endif
#ifdef PERSIST_CERT_CACHE
    ExpectIntEQ(wolfSSL_CTX_get_cert_cache_memsize(NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif

    /* A NULL object reports a bad argument rather than a depth. */
    ExpectIntEQ(wolfSSL_CTX_get_verify_depth(NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_get_verify_depth(NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method()));
    ExpectIntEQ(wolfSSL_CTX_use_certificate_file(ctx, svrCertFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKeyFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx, caCertFile, NULL),
        WOLFSSL_SUCCESS);
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* The loaded CAs can be released without freeing the context. */
    ExpectIntEQ(wolfSSL_CTX_UnloadCAs(ctx), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_UnloadCAs(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* So can the object's own certificates and keys. */
    ExpectIntEQ(wolfSSL_UnloadCertsKeys(ssl), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UnloadCertsKeys(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wolfSSL_CTX_UnloadIntermediateCerts(NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

#if !defined(NO_CERTS) && !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT)

/* One row of the verify-mode mapping table: the mode handed to
 * wolfSSL_[CTX_]set_verify() and the option bits it must produce.
 * WOLFSSL_VERIFY_POST_HANDSHAKE is not covered here because its option is
 * conditionally compiled; it is checked separately below. */
typedef struct {
    const char* desc;
    int mode;
    int verifyNone;
    int verifyPeer;
    int failNoCert;
    int failNoCertxPSK;
} VerifyModeCase;

/* Callback used only to check that set_verify() stores and clears it. */
static int test_verify_mode_cb(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    (void)store;
    return preverify;
}

static const VerifyModeCase verifyModeCases[] = {
    /* VERIFY_NONE is the only mode that sets verifyNone. */
    { "NONE", WOLFSSL_VERIFY_NONE, 1, 0, 0, 0 },
    { "PEER", WOLFSSL_VERIFY_PEER, 0, 1, 0, 0 },
    { "PEER|FAIL_IF_NO_PEER_CERT",
      WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT,
      0, 1, 1, 0 },
    { "PEER|FAIL_EXCEPT_PSK",
      WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_EXCEPT_PSK,
      0, 1, 0, 1 },
    /* The two fail-on-no-cert flags are independent bits and may both be
     * recorded; the PSK exception is applied first at the handshake. */
    { "PEER|FAIL_IF_NO_PEER_CERT|FAIL_EXCEPT_PSK",
      WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT |
          WOLFSSL_VERIFY_FAIL_EXCEPT_PSK,
      0, 1, 1, 1 },
    /* FAIL_IF_NO_PEER_CERT on its own is recorded even though a server that
     * never requests a certificate cannot act on it. */
    { "FAIL_IF_NO_PEER_CERT", WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT,
      0, 0, 1, 0 },
    /* VERIFY_DEFAULT clears every option instead of setting one. That is
     * why it does not round-trip through get_verify_mode(). */
    { "DEFAULT", WOLFSSL_VERIFY_DEFAULT, 0, 0, 0, 0 },
    /* VERIFY_NONE is matched by equality, not as a bit: OR-ing anything else
     * in means the peer IS verified. */
    { "NONE|PEER", WOLFSSL_VERIFY_NONE | WOLFSSL_VERIFY_PEER, 0, 1, 0, 0 },
    /* CLIENT_ONCE is accepted and ignored: on its own it leaves every option
     * clear, and it never disturbs the flags it is OR-ed with. */
    { "CLIENT_ONCE", WOLFSSL_VERIFY_CLIENT_ONCE, 0, 0, 0, 0 },
    { "PEER|CLIENT_ONCE",
      WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_CLIENT_ONCE, 0, 1, 0, 0 },
    { "PEER|FAIL_IF_NO_PEER_CERT|CLIENT_ONCE",
      WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT |
          WOLFSSL_VERIFY_CLIENT_ONCE,
      0, 1, 1, 0 }
};

#endif /* !NO_CERTS && !NO_TLS && !NO_WOLFSSL_CLIENT */

/* Test that every verify mode flag maps onto the expected internal options.
 *
 * Unlike test_wolfSSL_get_verify_mode(), this reads the options directly and
 * so also runs in builds without the OpenSSL compatibility layer, where
 * wolfSSL_get_verify_mode() is not compiled in.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_verify_mode_options(void)
{
    EXPECT_DECLS;
#if !defined(NO_CERTS) && !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    size_t i;

    /* A NULL object is ignored rather than dereferenced. */
    wolfSSL_CTX_set_verify(NULL, WOLFSSL_VERIFY_PEER, NULL);
    wolfSSL_set_verify(NULL, WOLFSSL_VERIFY_PEER, NULL);

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    for (i = 0; i < XELEM_CNT(verifyModeCases) && EXPECT_SUCCESS(); i++) {
        const VerifyModeCase* c = &verifyModeCases[i];

        wolfSSL_CTX_set_verify(ctx, c->mode, NULL);
        ExpectIntEQ(ctx->verifyNone, c->verifyNone);
        ExpectIntEQ(ctx->verifyPeer, c->verifyPeer);
        ExpectIntEQ(ctx->failNoCert, c->failNoCert);
        ExpectIntEQ(ctx->failNoCertxPSK, c->failNoCertxPSK);

        wolfSSL_set_verify(ssl, c->mode, NULL);
        ExpectIntEQ(ssl->options.verifyNone, c->verifyNone);
        ExpectIntEQ(ssl->options.verifyPeer, c->verifyPeer);
        ExpectIntEQ(ssl->options.failNoCert, c->failNoCert);
        ExpectIntEQ(ssl->options.failNoCertxPSK, c->failNoCertxPSK);

        if (!EXPECT_SUCCESS()) {
            fprintf(stderr, "\nverify mode case failed: %s\n", c->desc);
        }
    }

#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_POST_HANDSHAKE_AUTH)
    /* Post-handshake auth is an ordinary bit alongside the others. */
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER |
        WOLFSSL_VERIFY_POST_HANDSHAKE, NULL);
    ExpectIntEQ(ctx->verifyPeer, 1);
    ExpectIntEQ(ctx->verifyPostHandshake, 1);
    wolfSSL_set_verify(ssl, WOLFSSL_VERIFY_PEER |
        WOLFSSL_VERIFY_POST_HANDSHAKE, NULL);
    ExpectIntEQ(ssl->options.verifyPeer, 1);
    ExpectIntEQ(ssl->options.verifyPostHandshake, 1);

    /* VERIFY_NONE clears it along with everything else. */
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
    ExpectIntEQ(ctx->verifyPostHandshake, 0);
    wolfSSL_set_verify(ssl, WOLFSSL_VERIFY_NONE, NULL);
    ExpectIntEQ(ssl->options.verifyPostHandshake, 0);

    /* So does CLIENT_ONCE on its own, which is to say it selects nothing. */
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER |
        WOLFSSL_VERIFY_POST_HANDSHAKE, NULL);
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_CLIENT_ONCE, NULL);
    ExpectIntEQ(ctx->verifyPostHandshake, 0);
#endif

    /* Setting a mode replaces the previous one rather than accumulating. */
    wolfSSL_set_verify(ssl, WOLFSSL_VERIFY_PEER |
        WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    wolfSSL_set_verify(ssl, WOLFSSL_VERIFY_PEER, NULL);
    ExpectIntEQ(ssl->options.verifyPeer, 1);
    ExpectIntEQ(ssl->options.failNoCert, 0);

    /* The verify callback is stored and cleared alongside the mode. */
    wolfSSL_set_verify(ssl, WOLFSSL_VERIFY_PEER, test_verify_mode_cb);
    ExpectTrue(ssl->verifyCallback == test_verify_mode_cb);
    wolfSSL_set_verify(ssl, WOLFSSL_VERIFY_PEER, NULL);
    ExpectTrue(ssl->verifyCallback == NULL);

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, test_verify_mode_cb);
    ExpectTrue(ctx->verifyCallback == test_verify_mode_cb);
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    ExpectTrue(ctx->verifyCallback == NULL);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* Test that WOLFSSL_VERIFY_CLIENT_ONCE is accepted and ignored.
 *
 * The flag exists for source compatibility with OpenSSL. wolfSSL stores no
 * option for it, so it must neither change the other flags it is OR-ed with
 * nor be reported back by get_verify_mode().
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_verify_client_once_ignored(void)
{
    EXPECT_DECLS;
#if !defined(NO_CERTS) && !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* Adding CLIENT_ONCE to a mode leaves that mode's options untouched. */
    wolfSSL_set_verify(ssl, WOLFSSL_VERIFY_PEER |
        WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    ExpectIntEQ(ssl->options.verifyPeer, 1);
    ExpectIntEQ(ssl->options.failNoCert, 1);
    ExpectIntEQ(ssl->options.verifyNone, 0);

    wolfSSL_set_verify(ssl, WOLFSSL_VERIFY_PEER |
        WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT | WOLFSSL_VERIFY_CLIENT_ONCE,
        NULL);
    ExpectIntEQ(ssl->options.verifyPeer, 1);
    ExpectIntEQ(ssl->options.failNoCert, 1);
    ExpectIntEQ(ssl->options.verifyNone, 0);

    /* On its own it selects nothing at all - the same state as
     * WOLFSSL_VERIFY_DEFAULT, not the same as WOLFSSL_VERIFY_NONE. */
    wolfSSL_set_verify(ssl, WOLFSSL_VERIFY_CLIENT_ONCE, NULL);
    ExpectIntEQ(ssl->options.verifyNone, 0);
    ExpectIntEQ(ssl->options.verifyPeer, 0);
    ExpectIntEQ(ssl->options.failNoCert, 0);
    ExpectIntEQ(ssl->options.failNoCertxPSK, 0);

    /* CLIENT_ONCE does not turn VERIFY_NONE into something else either:
     * VERIFY_NONE is matched by equality, so the pair verifies the peer. */
    wolfSSL_set_verify(ssl, WOLFSSL_VERIFY_NONE | WOLFSSL_VERIFY_CLIENT_ONCE,
        NULL);
    ExpectIntEQ(ssl->options.verifyNone, 0);

#if defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA) || \
    defined(HAVE_STUNNEL) || defined(WOLFSSL_MYSQL_COMPATIBLE) || \
    defined(WOLFSSL_NGINX)
    /* The bit is never reported back, on the object or on the context. */
    wolfSSL_set_verify(ssl, WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_CLIENT_ONCE,
        NULL);
    ExpectIntEQ(wolfSSL_get_verify_mode(ssl), WOLFSSL_VERIFY_PEER);

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER |
        WOLFSSL_VERIFY_CLIENT_ONCE, NULL);
    ExpectIntEQ(wolfSSL_CTX_get_verify_mode(ctx), WOLFSSL_VERIFY_PEER);

    /* WOLFSSL_VERIFY_DEFAULT does not round-trip either: it clears every
     * option, so the mode reads back as 0. */
    wolfSSL_set_verify(ssl, WOLFSSL_VERIFY_DEFAULT, NULL);
    ExpectIntEQ(wolfSSL_get_verify_mode(ssl), 0);
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_DEFAULT, NULL);
    ExpectIntEQ(wolfSSL_CTX_get_verify_mode(ctx), 0);
#endif

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* Test that the context's verify mode is inherited by objects made from it,
 * and that overriding on an object leaves the context alone.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_verify_mode_ctx_inherit(void)
{
    EXPECT_DECLS;
#if !defined(NO_CERTS) && !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    WOLFSSL* ssl2 = NULL;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));

    /* An object created after the context is configured inherits the mode. */
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER |
        WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT | WOLFSSL_VERIFY_FAIL_EXCEPT_PSK,
        NULL);
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(ssl->options.verifyPeer, 1);
    ExpectIntEQ(ssl->options.failNoCert, 1);
    ExpectIntEQ(ssl->options.failNoCertxPSK, 1);
    ExpectIntEQ(ssl->options.verifyNone, 0);

    /* Overriding on the object does not write back to the context. */
    wolfSSL_set_verify(ssl, WOLFSSL_VERIFY_NONE, NULL);
    ExpectIntEQ(ssl->options.verifyNone, 1);
    ExpectIntEQ(ssl->options.verifyPeer, 0);
    ExpectIntEQ(ssl->options.failNoCert, 0);
    ExpectIntEQ(ssl->options.failNoCertxPSK, 0);
    ExpectIntEQ(ctx->verifyNone, 0);
    ExpectIntEQ(ctx->verifyPeer, 1);
    ExpectIntEQ(ctx->failNoCert, 1);
    ExpectIntEQ(ctx->failNoCertxPSK, 1);

    /* So a later object still picks up the context's unchanged mode. */
    ExpectNotNull(ssl2 = wolfSSL_new(ctx));
    ExpectIntEQ(ssl2->options.verifyPeer, 1);
    ExpectIntEQ(ssl2->options.failNoCert, 1);
    ExpectIntEQ(ssl2->options.failNoCertxPSK, 1);
    ExpectIntEQ(ssl2->options.verifyNone, 0);

    wolfSSL_free(ssl2);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* Test that WOLFSSL_VERIFY_NONE really does disable peer verification.
 *
 * The client has no CA loaded, so the server's certificate cannot be chained.
 * Verifying must fail and WOLFSSL_VERIFY_NONE must succeed - the second half
 * alone would pass even if verification never ran. The mode is always set
 * explicitly because the default depends on the build: with
 * OPENSSL_COMPATIBLE_DEFAULTS a new context starts at WOLFSSL_VERIFY_NONE.
 *
 * The last case pins the behavior of the equality match on WOLFSSL_VERIFY_NONE:
 * OR-ing it with WOLFSSL_VERIFY_PEER verifies the peer, it does not disable
 * verification.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_verify_none_accepts_untrusted(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(WOLFSSL_NO_TLS12) && !defined(NO_RSA)
    static const struct {
        const char* desc;
        int mode;
        int expectFail;
    } cases[] = {
        { "PEER", WOLFSSL_VERIFY_PEER, 1 },
        { "NONE", WOLFSSL_VERIFY_NONE, 0 },
        { "NONE|PEER", WOLFSSL_VERIFY_NONE | WOLFSSL_VERIFY_PEER, 1 }
    };
    size_t i;

    for (i = 0; i < XELEM_CNT(cases) && EXPECT_SUCCESS(); i++) {
        WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
        WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
        struct test_memio_ctx test_ctx;

        XMEMSET(&test_ctx, 0, sizeof(test_ctx));

        /* Build the client context here so that test_memio_setup() leaves it
         * alone and no CA is loaded into it. */
        ExpectNotNull(ctx_c = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
        if (ctx_c != NULL) {
            wolfSSL_SetIORecv(ctx_c, test_memio_read_cb);
            wolfSSL_SetIOSend(ctx_c, test_memio_write_cb);
        }

        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);

        wolfSSL_set_verify(ssl_c, cases[i].mode, NULL);

        if (cases[i].expectFail) {
            /* Verifying, with no CA: the chain has no signer. */
            ExpectIntNE(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
            ExpectIntEQ(wolfSSL_get_error(ssl_c,
                WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
                WC_NO_ERR_TRACE(ASN_NO_SIGNER_E));
        }
        else {
            /* Not verifying: the same untrusted certificate is accepted. */
            ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
        }

        wolfSSL_free(ssl_c);
        wolfSSL_free(ssl_s);
        wolfSSL_CTX_free(ctx_c);
        wolfSSL_CTX_free(ctx_s);

        if (!EXPECT_SUCCESS()) {
            fprintf(stderr, "\nverify none case failed: %s\n", cases[i].desc);
        }
    }
#endif
    return EXPECT_RESULT();
}

/* TLS 1.2 PSK suite to use for the FAIL_EXCEPT_PSK exception, if this build
 * has one. The static-PSK suites (PSK-*) are gated on WOLFSSL_STATIC_PSK,
 * which --enable-psk alone does not set, so they cannot be the first choice:
 * naming one unconditionally compiles the PSK half of the test away in every
 * ordinary PSK build. */
#if !defined(NO_PSK) && !defined(WOLFSSL_NO_TLS12)
    #if defined(BUILD_TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256)
        #define TEST_VFY_PSK_SUITE "ECDHE-PSK-AES128-GCM-SHA256"
    #elif defined(BUILD_TLS_DHE_PSK_WITH_AES_128_GCM_SHA256)
        #define TEST_VFY_PSK_SUITE "DHE-PSK-AES128-GCM-SHA256"
    #elif defined(BUILD_TLS_PSK_WITH_AES_128_GCM_SHA256)
        #define TEST_VFY_PSK_SUITE "PSK-AES128-GCM-SHA256"
    #endif
#endif

/* Test the WOLFSSL_VERIFY_FAIL_EXCEPT_PSK exception on a TLS 1.2 server.
 *
 * The client never sends a certificate. The server must accept that on a PSK
 * suite and reject it on a certificate suite, which is the only difference
 * between this mode and WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_verify_fail_except_psk(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(WOLFSSL_NO_TLS12) && !defined(NO_RSA) && \
    !defined(WOLFSSL_NO_CLIENT_AUTH)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;

#ifdef TEST_VFY_PSK_SUITE
    /* A PSK suite is the exception: no peer certificate is required. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);

    wolfSSL_set_verify(ssl_s, WOLFSSL_VERIFY_PEER |
        WOLFSSL_VERIFY_FAIL_EXCEPT_PSK, NULL);
    wolfSSL_set_psk_client_callback(ssl_c, my_psk_client_cb);
    wolfSSL_set_psk_server_callback(ssl_s, my_psk_server_cb);
    ExpectIntEQ(wolfSSL_set_cipher_list(ssl_c, TEST_VFY_PSK_SUITE),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_cipher_list(ssl_s, TEST_VFY_PSK_SUITE),
        WOLFSSL_SUCCESS);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectIntEQ(ssl_s->options.usingPSK_cipher, 1);

    wolfSSL_free(ssl_c);
    ssl_c = NULL;
    wolfSSL_free(ssl_s);
    ssl_s = NULL;
    wolfSSL_CTX_free(ctx_c);
    ctx_c = NULL;
    wolfSSL_CTX_free(ctx_s);
    ctx_s = NULL;
#endif /* TEST_VFY_PSK_SUITE */

    /* A certificate suite is not the exception: the same mode and the same
     * cert-less client are now rejected. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);

    wolfSSL_set_verify(ssl_s, WOLFSSL_VERIFY_PEER |
        WOLFSSL_VERIFY_FAIL_EXCEPT_PSK, NULL);

    ExpectIntNE(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectIntEQ(wolfSSL_get_error(ssl_s,
        WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WC_NO_ERR_TRACE(NO_PEER_CERT));

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(WOLFSSL_NO_CLIENT_AUTH) && !defined(NO_RSA)

/* Run one handshake where the server demands a client certificate and the
 * client has none, and check the server rejects it with NO_PEER_CERT.
 *
 * The rejection happens in a different place per protocol version, which is
 * why this is run over several of them: TLS 1.3 rejects after Finished, TLS
 * 1.2 on the empty Certificate message, and TLS 1.1 and below only reach the
 * check in DoClientKeyExchange (the empty-Certificate check there is gated on
 * IsAtLeastTLSv1_2).
 *
 * @return  TEST_SUCCESS on success.
 */
static int test_vfy_no_client_cert(method_provider method_c,
    method_provider method_s, int rounds)
{
    EXPECT_DECLS;
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        method_c, method_s), 0);

    wolfSSL_set_verify(ssl_s, WOLFSSL_VERIFY_PEER |
        WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    /* The client has no certificate loaded, so it answers the server's
     * request with an empty Certificate message. */
    ExpectIntNE(test_memio_do_handshake(ssl_c, ssl_s, rounds, NULL), 0);
    ExpectIntEQ(wolfSSL_get_error(ssl_s,
        WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WC_NO_ERR_TRACE(NO_PEER_CERT));
    ExpectIntEQ(ssl_s->options.havePeerCert, 0);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);

    return EXPECT_RESULT();
}

/* Run one handshake where the server does not verify the peer and the client
 * does have a certificate, and check the server never asks for it.
 *
 * WOLFSSL_VERIFY_NONE on a server means "send no CertificateRequest", which
 * is only observable from the client: it is never asked, so it never sends
 * the certificate it holds.
 *
 * @return  TEST_SUCCESS on success.
 */
static int test_vfy_none_server_no_request(method_provider method_c,
    method_provider method_s, int rounds)
{
    EXPECT_DECLS;
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        method_c, method_s), 0);

    wolfSSL_set_verify(ssl_s, WOLFSSL_VERIFY_NONE, NULL);

    /* Give the client a certificate it could present if it were asked.
     * CERT_FILETYPE tracks the cliCertFile/cliKeyFile paths, which are DER
     * rather than PEM in a build without WOLFSSL_PEM_TO_DER. */
    ExpectIntEQ(wolfSSL_use_certificate_file(ssl_c, cliCertFile,
        CERT_FILETYPE), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_use_PrivateKey_file(ssl_c, cliKeyFile,
        CERT_FILETYPE), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx_s, cliCertFile, NULL),
        WOLFSSL_SUCCESS);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, rounds, NULL), 0);

    /* No CertificateRequest arrived, so the client sent no certificate and
     * the server holds none. */
    ExpectIntEQ(ssl_c->options.sendVerify, 0);
    ExpectIntEQ(ssl_s->options.havePeerCert, 0);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);

    return EXPECT_RESULT();
}

#endif /* HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES && !WOLFSSL_NO_CLIENT_AUTH */

/* Test that a server requiring a client certificate rejects a client that has
 * none, on every protocol version the build supports.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_verify_no_client_cert(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(WOLFSSL_NO_CLIENT_AUTH) && !defined(NO_RSA)

#if defined(WOLFSSL_TLS13)
    /* TLS 1.3: rejected when the server processes the client's Finished. */
    ExpectIntEQ(test_vfy_no_client_cert(wolfTLSv1_3_client_method,
        wolfTLSv1_3_server_method, 10), TEST_SUCCESS);
#endif
#if !defined(WOLFSSL_NO_TLS12)
    /* TLS 1.2: rejected on the empty Certificate message. */
    ExpectIntEQ(test_vfy_no_client_cert(wolfTLSv1_2_client_method,
        wolfTLSv1_2_server_method, 10), TEST_SUCCESS);
#endif
#if !defined(NO_OLD_TLS)
    /* TLS 1.1: the empty-Certificate check does not apply below TLS 1.2, so
     * this is rejected later, in DoClientKeyExchange. */
    ExpectIntEQ(test_vfy_no_client_cert(wolfTLSv1_1_client_method,
        wolfTLSv1_1_server_method, 10), TEST_SUCCESS);
#endif
#if defined(WOLFSSL_DTLS) && !defined(WOLFSSL_NO_TLS12)
    /* DTLS 1.2 over the same TLS 1.2 code path, but across a cookie
     * exchange and a retransmittable flight. */
    ExpectIntEQ(test_vfy_no_client_cert(wolfDTLSv1_2_client_method,
        wolfDTLSv1_2_server_method, 20), TEST_SUCCESS);
#endif
#if defined(WOLFSSL_DTLS13) && defined(WOLFSSL_TLS13)
    ExpectIntEQ(test_vfy_no_client_cert(wolfDTLSv1_3_client_method,
        wolfDTLSv1_3_server_method, 20), TEST_SUCCESS);
#endif

#endif
    return EXPECT_RESULT();
}

/* Test that WOLFSSL_VERIFY_NONE on a server suppresses the certificate
 * request, on every protocol version the build supports.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_verify_none_server_no_request(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(WOLFSSL_NO_CLIENT_AUTH) && !defined(NO_RSA) && \
    !defined(NO_FILESYSTEM)

#if defined(WOLFSSL_TLS13)
    ExpectIntEQ(test_vfy_none_server_no_request(wolfTLSv1_3_client_method,
        wolfTLSv1_3_server_method, 10), TEST_SUCCESS);
#endif
#if !defined(WOLFSSL_NO_TLS12)
    ExpectIntEQ(test_vfy_none_server_no_request(wolfTLSv1_2_client_method,
        wolfTLSv1_2_server_method, 10), TEST_SUCCESS);
#endif
#if defined(WOLFSSL_DTLS) && !defined(WOLFSSL_NO_TLS12)
    ExpectIntEQ(test_vfy_none_server_no_request(wolfDTLSv1_2_client_method,
        wolfDTLSv1_2_server_method, 20), TEST_SUCCESS);
#endif

#endif
    return EXPECT_RESULT();
}

/* Test that a TLS 1.3 server set to WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT
 * without WOLFSSL_VERIFY_PEER still refuses a client that has no
 * certificate.
 *
 * The CertificateRequest is sent only for WOLFSSL_VERIFY_PEER, so nothing
 * asks the client for a certificate and nothing notices it is missing until
 * DoTls13Finished checks at the end of the handshake.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_verify_tls13_failnocert_only(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_TLS13) && \
    !defined(WOLFSSL_NO_CLIENT_AUTH) && !defined(NO_RSA)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);

    wolfSSL_set_verify(ssl_s, WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    ExpectIntEQ(ssl_s->options.verifyPeer, 0);
    ExpectIntEQ(ssl_s->options.failNoCert, 1);

    ExpectIntNE(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectIntEQ(wolfSSL_get_error(ssl_s,
        WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WC_NO_ERR_TRACE(NO_PEER_CERT));
    /* The client was never asked, so it never sent one. */
    ExpectIntEQ(ssl_s->msgsReceived.got_certificate, 0);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(WOLFSSL_NO_TLS12) && !defined(NO_RSA)

/* Replace one whole record in a memio buffer with a supplied one.
 *
 * Used to put a message on the wire that no conforming wolfSSL peer would
 * send. Only safe before the cipher spec changes: an encrypted record cannot
 * be substituted without also re-doing the AEAD.
 *
 * The records of one flight may arrive as a single memio message or as one
 * message each, depending on whether the build groups handshake messages, so
 * the buffer is walked by record and the containing message resized after.
 *
 * @param [in,out] ctx     memio context.
 * @param [in]     client  1 for the client's inbound buffer (what the server
 *                         wrote), 0 for the server's inbound buffer.
 * @param [in]     hsType  handshake type of the record to replace.
 * @param [in]     rec     replacement record, including its record header.
 * @param [in]     recSz   length of rec.
 * @return  0 on success, -1 when no such record is present.
 */
static int test_vfy_replace_record(struct test_memio_ctx* ctx, int client,
    byte hsType, const byte* rec, int recSz)
{
    byte* buff;
    int*  len;
    int*  msgSizes;
    int   msgCount;
    int   off = 0;
    int   target = -1;
    int   targetSz = 0;
    int   delta;
    int   msgOff;
    int   i;

    if (client) {
        buff = ctx->c_buff; len = &ctx->c_len;
        msgSizes = ctx->c_msg_sizes; msgCount = ctx->c_msg_count;
    }
    else {
        buff = ctx->s_buff; len = &ctx->s_len;
        msgSizes = ctx->s_msg_sizes; msgCount = ctx->s_msg_count;
    }

    /* A plaintext record: content type, two version bytes, a two byte
     * length, then the body - whose first byte is the handshake type. */
    while (off + RECORD_HEADER_SZ <= *len) {
        int recLen = (buff[off + 3] << 8) | buff[off + 4];

        if (off + RECORD_HEADER_SZ + recLen > *len) {
            break;
        }
        if (buff[off] == handshake && recLen > 0 &&
                buff[off + RECORD_HEADER_SZ] == hsType) {
            target = off;
            targetSz = RECORD_HEADER_SZ + recLen;
            break;
        }
        off += RECORD_HEADER_SZ + recLen;
    }
    if (target < 0) {
        return -1;
    }

    delta = recSz - targetSz;
    if (*len + delta > TEST_MEMIO_BUF_SZ) {
        return -1;
    }

    XMEMMOVE(buff + target + recSz, buff + target + targetSz,
        (size_t)(*len - target - targetSz));
    XMEMCPY(buff + target, rec, (size_t)recSz);
    *len += delta;

    /* Resize whichever message holds the record that was replaced. */
    msgOff = 0;
    for (i = 0; i < msgCount; i++) {
        if (target < msgOff + msgSizes[i]) {
            msgSizes[i] += delta;
            break;
        }
        msgOff += msgSizes[i];
    }

    return 0;
}

#endif /* HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES && !WOLFSSL_NO_TLS12 &&
        * !NO_RSA */

/* Test that a client rejects an empty Certificate message from the server.
 *
 * No conforming server sends one - a server with no certificate cannot use a
 * certificate cipher suite at all - so the server's Certificate record is
 * substituted on the wire. This is the client-side half of the empty
 * certificate check, which is otherwise never reached.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_verify_empty_server_cert(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(WOLFSSL_NO_TLS12) && !defined(NO_RSA)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    /* Handshake record holding a Certificate message with an empty
     * certificate_list: record type 22, TLS 1.2, 7 bytes of payload; then
     * handshake type 11 with a 3 byte body; then a zero list length. */
    static const byte emptyCert[] = {
        0x16, 0x03, 0x03, 0x00, 0x07,
        0x0b, 0x00, 0x00, 0x03,
        0x00, 0x00, 0x00
    };

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);

    wolfSSL_set_verify(ssl_c, WOLFSSL_VERIFY_PEER, NULL);

    /* Client sends its hello. */
    ExpectIntEQ(wolfSSL_connect(ssl_c), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WOLFSSL_FATAL_ERROR),
        WOLFSSL_ERROR_WANT_READ);
    /* Server replies with its flight, still in the clear. */
    ExpectIntEQ(wolfSSL_accept(ssl_s), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WOLFSSL_FATAL_ERROR),
        WOLFSSL_ERROR_WANT_READ);

    /* Swap the server's Certificate for one carrying no certificates. */
    ExpectIntEQ(test_vfy_replace_record(&test_ctx, 1, certificate,
        emptyCert, (int)sizeof(emptyCert)), 0);

    ExpectIntEQ(wolfSSL_connect(ssl_c), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WOLFSSL_FATAL_ERROR),
        WC_NO_ERR_TRACE(NO_PEER_CERT));
    ExpectIntEQ(ssl_c->options.havePeerCert, 0);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* Test that WOLFSSL_VERIFY_POST_HANDSHAKE defers client authentication past
 * the initial handshake.
 *
 * The CertificateRequest is suppressed during the initial handshake when
 * post-handshake auth is selected, so a client with no certificate completes
 * the handshake instead of being rejected. This is the one configuration that
 * reaches the post-handshake arm of the Finished sanity check with no
 * request outstanding.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_verify_post_handshake_defers(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_TLS13) && \
    defined(WOLFSSL_POST_HANDSHAKE_AUTH) && !defined(WOLFSSL_NO_CLIENT_AUTH) \
    && !defined(NO_RSA)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);

    wolfSSL_set_verify(ssl_s, WOLFSSL_VERIFY_PEER |
        WOLFSSL_VERIFY_POST_HANDSHAKE, NULL);
    ExpectIntEQ(ssl_s->options.verifyPeer, 1);
    ExpectIntEQ(ssl_s->options.verifyPostHandshake, 1);

    /* The client has no certificate, and is never asked for one during the
     * initial handshake, so the handshake completes. */
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectIntEQ(ssl_s->msgsReceived.got_certificate, 0);
    ExpectIntEQ(ssl_s->options.havePeerCert, 0);
    ExpectNull(ssl_s->certReqCtx);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}
