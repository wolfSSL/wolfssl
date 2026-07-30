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
    ExpectNull(wolfSSL_load_client_CA_file("does/not/exist.pem"));

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
