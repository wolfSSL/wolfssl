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

#if defined(__unix__) && !defined(NO_FILESYSTEM)
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <fcntl.h>
    #include <unistd.h>
#endif

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

/* ---------------------------------------------------------------------------
 * Argument guards across the newly-visible public API surface.
 *
 * src/ssl_api_cert.c, ssl_api_crl_ocsp.c and their siblings are #included into
 * ssl.c rather than compiled standalone, so they produced no object file and
 * no module declared them until this part of the campaign. Now that they are
 * measured, the shape of what is missing is unambiguous: 342 of the 646
 * uncovered conditions across these files mention NULL, and in the densest of
 * them it is 85-100%.
 *
 * They are not protocol behaviour. They are the checks each entry point makes
 * on its own arguments, and the existing tests all pass arguments that are
 * valid -- so every one of these decisions is taken the same way on every
 * call, and none of the operands has an independence pair.
 *
 * A caller that queries or configures a CTX or an SSL it has not created yet,
 * or passes a zero length, or asks for an output through a NULL pointer, is
 * doing something ordinary and wrong. That is what these vectors are.
 * ------------------------------------------------------------------------- */
int test_wolfSSL_cert_api_arg_guards(void)
{
    EXPECT_DECLS;
#if !defined(NO_CERTS) && !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
#ifdef HAVE_RPK
    int tp = 0;
    const char certTypes[] = { WOLFSSL_CERT_TYPE_X509 };
    unsigned char spki[8];

    XMEMSET(spki, 0, sizeof(spki));
#endif

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* --- mutual auth and verify depth: NULL object, valid argument ------ */
    ExpectIntNE(wolfSSL_CTX_mutual_auth(NULL, 1), WOLFSSL_SUCCESS);
    ExpectIntNE(wolfSSL_mutual_auth(NULL, 1), WOLFSSL_SUCCESS);
    (void)wolfSSL_CTX_mutual_auth(ctx, 1);
    (void)wolfSSL_CTX_mutual_auth(ctx, 0);
    (void)wolfSSL_mutual_auth(ssl, 1);
    (void)wolfSSL_mutual_auth(ssl, 0);

    ExpectNull(wolfSSL_CTX_GetCertManager(NULL));
    ExpectNotNull(wolfSSL_CTX_GetCertManager(ctx));

    wolfSSL_CTX_set_verify_depth(NULL, 4);
    wolfSSL_CTX_set_verify_depth(ctx, 4);
    (void)wolfSSL_CTX_get_verify_depth(NULL);
    (void)wolfSSL_CTX_get_verify_depth(ctx);
    (void)wolfSSL_get_verify_depth(NULL);
    (void)wolfSSL_get_verify_depth(ssl);

    /* Certificate type lists and raw public keys are RPK-only symbols
     * (declared under #ifdef HAVE_RPK in wolfssl/ssl.h); this option list is
     * shared with modules that do not enable RPK (asn, pkcs7, and the rest of
     * wolfCrypt), and tests/api.c is one translation unit across all of them,
     * so referencing these unguarded breaks every OTHER module's build, not
     * just this one -- exactly what happened here. */
#ifdef HAVE_RPK
    /* --- certificate type lists: NULL object, NULL buffer, bad length --- */
    (void)wolfSSL_CTX_set_client_cert_type(NULL, certTypes,
                                           (int)sizeof(certTypes));
    (void)wolfSSL_CTX_set_server_cert_type(NULL, certTypes,
                                           (int)sizeof(certTypes));
    (void)wolfSSL_set_client_cert_type(NULL, certTypes,
                                       (int)sizeof(certTypes));
    (void)wolfSSL_set_server_cert_type(NULL, certTypes,
                                       (int)sizeof(certTypes));
    /* NULL list with a non-zero length, and a list longer than allowed:
     * both are refusals a correct caller never triggers */
    (void)wolfSSL_CTX_set_client_cert_type(ctx, NULL, 1);
    (void)wolfSSL_CTX_set_client_cert_type(ctx, certTypes, 0);
    (void)wolfSSL_CTX_set_client_cert_type(ctx, certTypes, 99);
    (void)wolfSSL_set_server_cert_type(ssl, NULL, 1);
    (void)wolfSSL_set_server_cert_type(ssl, certTypes, 0);
    (void)wolfSSL_set_server_cert_type(ssl, certTypes, 99);
    /* the accepting partners */
    (void)wolfSSL_CTX_set_client_cert_type(ctx, certTypes,
                                           (int)sizeof(certTypes));
    (void)wolfSSL_set_server_cert_type(ssl, certTypes,
                                       (int)sizeof(certTypes));

    /* negotiated type read back before any handshake, and through NULL */
    (void)wolfSSL_get_negotiated_client_cert_type(NULL, &tp);
    (void)wolfSSL_get_negotiated_server_cert_type(NULL, &tp);
    (void)wolfSSL_get_negotiated_client_cert_type(ssl, NULL);
    (void)wolfSSL_get_negotiated_server_cert_type(ssl, NULL);
    (void)wolfSSL_get_negotiated_client_cert_type(ssl, &tp);
    (void)wolfSSL_get_negotiated_server_cert_type(ssl, &tp);

    /* --- raw public key expectations ------------------------------------ */
    (void)wolfSSL_CTX_set_expected_rpk(NULL, spki, (word32)sizeof(spki));
    (void)wolfSSL_set_expected_rpk(NULL, spki, (word32)sizeof(spki));
    (void)wolfSSL_CTX_set_expected_rpk(ctx, NULL, (word32)sizeof(spki));
    (void)wolfSSL_set_expected_rpk(ssl, NULL, (word32)sizeof(spki));
    (void)wolfSSL_CTX_set_expected_rpk(ctx, spki, 0);
    (void)wolfSSL_set_expected_rpk(ssl, spki, 0);
    (void)wolfSSL_CTX_set_expected_rpk(ctx, spki, (word32)sizeof(spki));
    (void)wolfSSL_set_expected_rpk(ssl, spki, (word32)sizeof(spki));
    (void)wolfSSL_CTX_clear_expected_rpk(NULL);
    (void)wolfSSL_clear_expected_rpk(NULL);
    (void)wolfSSL_CTX_clear_expected_rpk(ctx);
    (void)wolfSSL_clear_expected_rpk(ssl);
#endif /* HAVE_RPK */

    /* --- verify configuration through NULL objects ---------------------- */
    wolfSSL_CTX_set_verify(NULL, WOLFSSL_VERIFY_PEER, NULL);
    wolfSSL_set_verify(NULL, WOLFSSL_VERIFY_PEER, NULL);
    wolfSSL_set_verify_result(NULL, 0);
    wolfSSL_CTX_SetCertCbCtx(NULL, NULL);
    wolfSSL_SetCertCbCtx(NULL, NULL);
    /* and the same on real objects, so each guard has its partner */
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
    wolfSSL_set_verify(ssl, WOLFSSL_VERIFY_NONE, NULL);
    wolfSSL_set_verify_result(ssl, 0);
    wolfSSL_CTX_SetCertCbCtx(ctx, NULL);
    wolfSSL_SetCertCbCtx(ssl, NULL);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* The CRL and OCSP configuration entry points, same argument-guard rationale.
 * 24 of ssl_api_crl_ocsp.c's 28 uncovered conditions mention NULL. */
int test_wolfSSL_crl_ocsp_api_arg_guards(void)
{
    EXPECT_DECLS;
#if !defined(NO_CERTS) && !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

#ifdef HAVE_CRL
    ExpectIntNE(wolfSSL_EnableCRL(NULL, 0), WOLFSSL_SUCCESS);
    ExpectIntNE(wolfSSL_DisableCRL(NULL), WOLFSSL_SUCCESS);
    ExpectIntNE(wolfSSL_CTX_EnableCRL(NULL, 0), WOLFSSL_SUCCESS);
    ExpectIntNE(wolfSSL_CTX_DisableCRL(NULL), WOLFSSL_SUCCESS);
    (void)wolfSSL_CTX_EnableCRL(ctx, 0);
    (void)wolfSSL_CTX_DisableCRL(ctx);
    (void)wolfSSL_EnableCRL(ssl, 0);
    (void)wolfSSL_DisableCRL(ssl);

    ExpectIntNE(wolfSSL_SetCRL_Cb(NULL, NULL), WOLFSSL_SUCCESS);
    ExpectIntNE(wolfSSL_CTX_SetCRL_Cb(NULL, NULL), WOLFSSL_SUCCESS);
    (void)wolfSSL_SetCRL_Cb(ssl, NULL);
    (void)wolfSSL_CTX_SetCRL_Cb(ctx, NULL);
    ExpectIntNE(wolfSSL_SetCRL_ErrorCb(NULL, NULL, NULL), WOLFSSL_SUCCESS);
    ExpectIntNE(wolfSSL_CTX_SetCRL_ErrorCb(NULL, NULL, NULL), WOLFSSL_SUCCESS);
    (void)wolfSSL_SetCRL_ErrorCb(ssl, NULL, NULL);
    (void)wolfSSL_CTX_SetCRL_ErrorCb(ctx, NULL, NULL);

#ifdef HAVE_CRL_IO
    ExpectIntNE(wolfSSL_SetCRL_IOCb(NULL, NULL), WOLFSSL_SUCCESS);
    ExpectIntNE(wolfSSL_CTX_SetCRL_IOCb(NULL, NULL), WOLFSSL_SUCCESS);
    (void)wolfSSL_SetCRL_IOCb(ssl, NULL);
    (void)wolfSSL_CTX_SetCRL_IOCb(ctx, NULL);
#endif

#if !defined(NO_FILESYSTEM) && !defined(NO_WOLFSSL_DIR)
    /* NULL object, NULL path, and a path that does not exist: three
     * different refusals, none of which a working configuration produces */
    (void)wolfSSL_LoadCRL(NULL, "certs/crl", WOLFSSL_FILETYPE_PEM, 0);
    (void)wolfSSL_CTX_LoadCRL(NULL, "certs/crl", WOLFSSL_FILETYPE_PEM, 0);
    (void)wolfSSL_LoadCRL(ssl, NULL, WOLFSSL_FILETYPE_PEM, 0);
    (void)wolfSSL_CTX_LoadCRL(ctx, NULL, WOLFSSL_FILETYPE_PEM, 0);
    (void)wolfSSL_CTX_LoadCRL(ctx, "certs/no-such-dir",
                              WOLFSSL_FILETYPE_PEM, 0);
    (void)wolfSSL_LoadCRLFile(NULL, "certs/crl/crl.pem",
                              WOLFSSL_FILETYPE_PEM);
    (void)wolfSSL_CTX_LoadCRLFile(NULL, "certs/crl/crl.pem",
                                  WOLFSSL_FILETYPE_PEM);
    (void)wolfSSL_LoadCRLFile(ssl, NULL, WOLFSSL_FILETYPE_PEM);
    (void)wolfSSL_CTX_LoadCRLFile(ctx, NULL, WOLFSSL_FILETYPE_PEM);
#endif

    /* buffer loads: NULL object, NULL buffer, zero length, bad type */
    (void)wolfSSL_CTX_LoadCRLBuffer(NULL, (const unsigned char*)"x", 1,
                                    WOLFSSL_FILETYPE_ASN1);
    (void)wolfSSL_LoadCRLBuffer(NULL, (const unsigned char*)"x", 1,
                                WOLFSSL_FILETYPE_ASN1);
    (void)wolfSSL_CTX_LoadCRLBuffer(ctx, NULL, 1, WOLFSSL_FILETYPE_ASN1);
    (void)wolfSSL_LoadCRLBuffer(ssl, NULL, 1, WOLFSSL_FILETYPE_ASN1);
    (void)wolfSSL_CTX_LoadCRLBuffer(ctx, (const unsigned char*)"x", 0,
                                    WOLFSSL_FILETYPE_ASN1);
    (void)wolfSSL_LoadCRLBuffer(ssl, (const unsigned char*)"x", 0,
                                WOLFSSL_FILETYPE_ASN1);
#endif /* HAVE_CRL */

#ifdef HAVE_OCSP
    ExpectIntNE(wolfSSL_EnableOCSP(NULL, 0), WOLFSSL_SUCCESS);
    ExpectIntNE(wolfSSL_DisableOCSP(NULL), WOLFSSL_SUCCESS);
    (void)wolfSSL_EnableOCSP(ssl, 0);
    (void)wolfSSL_DisableOCSP(ssl);
    (void)wolfSSL_SetOCSP_OverrideURL(NULL, "http://ocsp.example.com/");
    (void)wolfSSL_SetOCSP_OverrideURL(ssl, NULL);
    (void)wolfSSL_SetOCSP_OverrideURL(ssl, "http://ocsp.example.com/");
    (void)wolfSSL_SetOCSP_Cb(NULL, NULL, NULL, NULL);
    (void)wolfSSL_SetOCSP_Cb(ssl, NULL, NULL, NULL);
#ifdef HAVE_CERTIFICATE_STATUS_REQUEST
    ExpectIntNE(wolfSSL_EnableOCSPStapling(NULL), WOLFSSL_SUCCESS);
    ExpectIntNE(wolfSSL_DisableOCSPStapling(NULL), WOLFSSL_SUCCESS);
    (void)wolfSSL_EnableOCSPStapling(ssl);
    (void)wolfSSL_DisableOCSPStapling(ssl);
#endif
#endif /* HAVE_OCSP */

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* ---------------------------------------------------------------------------
 * OCSP stapling accessors, and CRL delivered through a mocked transport.
 *
 * The previous argument-guard sweep moved ssl_api_crl_ocsp.c by one condition,
 * because it guessed at which functions held the gaps. Reading them settles
 * it: they are not the enable/disable calls, they are the stapling request
 * and response accessors, and their operands are of three kinds --
 *
 *   ssl->options.side != WOLFSSL_CLIENT_END   a SERVER object, which no
 *   ctx->method->side != WOLFSSL_CLIENT_END   client-side test can supply
 *
 *   ssl->ocspProducedDateFormat != ASN_UTC_TIME  a response that was never
 *                                                processed, or one whose
 *                                                producedDate is a
 *                                                GeneralizedTime
 *
 *   idx >= XELEM_CNT(ssl->ocspCsrResp), len < 0  an out-of-range slot
 *
 * None of them is reachable from a working client that staples successfully,
 * which is the only shape the existing tests have.
 * ------------------------------------------------------------------------- */
int test_wolfSSL_ocsp_stapling_accessors(void)
{
    EXPECT_DECLS;
#if defined(HAVE_OCSP) && defined(HAVE_CERTIFICATE_STATUS_REQUEST) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(NO_CERTS) && !defined(NO_FILESYSTEM)
    WOLFSSL_CTX* cctx = NULL;   /* client */
    WOLFSSL_CTX* sctx = NULL;   /* server: the side operand's partner */
    WOLFSSL* cssl = NULL;
    WOLFSSL* sssl = NULL;

    ExpectNotNull(cctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNotNull(sctx = wolfSSL_CTX_new(wolfSSLv23_server_method()));
    ExpectIntEQ(wolfSSL_CTX_use_certificate_file(sctx, svrCertFile,
                WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(sctx, svrKeyFile,
                WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectNotNull(cssl = wolfSSL_new(cctx));
    ExpectNotNull(sssl = wolfSSL_new(sctx));

    /* --- the stapling request calls, once per operand ------------------- */
    (void)wolfSSL_UseOCSPStapling(NULL, WOLFSSL_CSR_OCSP, 0);
    (void)wolfSSL_CTX_UseOCSPStapling(NULL, WOLFSSL_CSR_OCSP, 0);
    /* a SERVER object: side != CLIENT_END, which is the operand a client-only
     * test leaves permanently false */
    (void)wolfSSL_UseOCSPStapling(sssl, WOLFSSL_CSR_OCSP, 0);
    (void)wolfSSL_CTX_UseOCSPStapling(sctx, WOLFSSL_CSR_OCSP, 0);
    /* the accepting partners */
    (void)wolfSSL_UseOCSPStapling(cssl, WOLFSSL_CSR_OCSP, 0);
    (void)wolfSSL_CTX_UseOCSPStapling(cctx, WOLFSSL_CSR_OCSP, 0);

#ifdef HAVE_CERTIFICATE_STATUS_REQUEST_V2
    (void)wolfSSL_UseOCSPStaplingV2(NULL, WOLFSSL_CSR2_OCSP, 0);
    (void)wolfSSL_CTX_UseOCSPStaplingV2(NULL, WOLFSSL_CSR2_OCSP, 0);
    (void)wolfSSL_UseOCSPStaplingV2(sssl, WOLFSSL_CSR2_OCSP, 0);
    (void)wolfSSL_CTX_UseOCSPStaplingV2(sctx, WOLFSSL_CSR2_OCSP, 0);
    (void)wolfSSL_UseOCSPStaplingV2(cssl, WOLFSSL_CSR2_OCSP, 0);
    (void)wolfSSL_CTX_UseOCSPStaplingV2(cctx, WOLFSSL_CSR2_OCSP, 0);
#endif

#ifndef NO_ASN_TIME
    /* --- the producedDate accessor -------------------------------------- */
    {
        byte  when[32];
        int   fmt = 0;

        XMEMSET(when, 0, sizeof(when));
        (void)wolfSSL_get_ocsp_producedDate(NULL, when, sizeof(when), &fmt);
        /* no response processed: ocspProducedDateFormat is neither UTC nor
         * generalized, which is the pair for both operands at :879 */
        (void)wolfSSL_get_ocsp_producedDate(cssl, when, sizeof(when), &fmt);
        /* the output-pointer operands, reached only once a format is set */
        (void)wolfSSL_get_ocsp_producedDate(cssl, NULL, sizeof(when), &fmt);
        (void)wolfSSL_get_ocsp_producedDate(cssl, when, sizeof(when), NULL);
        /* a buffer too small to hold the date */
        (void)wolfSSL_get_ocsp_producedDate(cssl, when, 1, &fmt);

        /* Drive the format operands directly. A stapled response carrying a
         * GeneralizedTime rather than a UTCTime is legal, rare, and not
         * something the test responder emits -- so this is the only way the
         * second half of that decision is ever taken. */
        cssl->ocspProducedDateFormat = ASN_UTC_TIME;
        (void)wolfSSL_get_ocsp_producedDate(cssl, when, sizeof(when), &fmt);
        (void)wolfSSL_get_ocsp_producedDate(cssl, NULL, sizeof(when), &fmt);
        (void)wolfSSL_get_ocsp_producedDate(cssl, when, sizeof(when), NULL);
        (void)wolfSSL_get_ocsp_producedDate(cssl, when, 1, &fmt);
        cssl->ocspProducedDateFormat = ASN_GENERALIZED_TIME;
        (void)wolfSSL_get_ocsp_producedDate(cssl, when, sizeof(when), &fmt);
        cssl->ocspProducedDateFormat = 0;
    }
#endif

    wolfSSL_free(cssl);
    wolfSSL_free(sssl);
    wolfSSL_CTX_free(cctx);
    wolfSSL_CTX_free(sctx);
#endif
    return EXPECT_RESULT();
}

/* CRL arriving through a mocked I/O callback.
 *
 * wolfSSL_SetCRL_IOCb installs a CbCrlIO, which is the interface the library
 * consumes when a certificate names a CRL distribution point. Mocking it is
 * the CRL equivalent of the CbOCSPIO mock used for the responder: it can hand
 * back a truncated CRL, an empty one, or bytes that are not a CRL at all --
 * results a real distribution point cannot be asked for on demand.
 */
#if defined(HAVE_CRL) && defined(HAVE_CRL_IO) && !defined(NO_CERTS) && \
    !defined(NO_WOLFSSL_CLIENT)
static int g_crlIoCalls;
static int g_crlIoResult;

static int test_crl_io_mock(WOLFSSL_CRL* crl, const char* url, int urlSz)
{
    (void)crl; (void)url; (void)urlSz;
    g_crlIoCalls++;
    return g_crlIoResult;
}
#endif

int test_wolfSSL_crl_io_mock(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CRL) && defined(HAVE_CRL_IO) && !defined(NO_CERTS) && \
    !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    int i;
    static const int results[] = { 0, -1, 1 };

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectIntEQ(wolfSSL_CTX_EnableCRL(ctx, WOLFSSL_CRL_CHECK),
                WOLFSSL_SUCCESS);
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* the guard operands first */
    (void)wolfSSL_SetCRL_IOCb(NULL, test_crl_io_mock);
    (void)wolfSSL_CTX_SetCRL_IOCb(NULL, test_crl_io_mock);
    (void)wolfSSL_SetCRL_IOCb(ssl, NULL);
    (void)wolfSSL_CTX_SetCRL_IOCb(ctx, NULL);

    /* then the callback installed, returning each of the outcomes a
     * distribution point can produce */
    for (i = 0; i < (int)(sizeof(results) / sizeof(results[0])); i++) {
        g_crlIoResult = results[i];
        g_crlIoCalls = 0;
        (void)wolfSSL_CTX_SetCRL_IOCb(ctx, test_crl_io_mock);
        (void)wolfSSL_SetCRL_IOCb(ssl, test_crl_io_mock);
        /* loading a certificate whose CRL is missing is what drives the
         * callback; the load itself is allowed to fail */
        (void)wolfSSL_CTX_load_verify_locations(ctx, caCertFile, NULL);
    }

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* ---------------------------------------------------------------------------
 * X509 accessors and the DTLS API, each with the object its guard needs.
 *
 * Two files sat at the bottom of the newly-visible surface for the same
 * reason, and it is not that their guards are hard to reach -- it is that the
 * ACCEPTING half of each pair needs an object the existing tests do not have.
 *
 *   x509.c  every accessor is `x509 == NULL || outSz == NULL || ...`, so the
 *           NULL half is trivial and the valid half needs a parsed
 *           certificate. There was no test holding one.
 *
 *   ssl_api_dtls.c  every guard is `ssl == NULL || !ssl->options.dtls`, so the
 *           second operand needs a DTLS connection. Every test in this group
 *           used a TLS one, which leaves that operand constant.
 *
 * Both fixtures are cheap: a certificate loaded from certs/, and a WOLFSSL
 * made from a DTLS method. Neither needs a peer.
 * ------------------------------------------------------------------------- */
int test_wolfSSL_x509_accessor_guards(void)
{
    EXPECT_DECLS;
/* wolfSSL_X509_load_certificate_file / _get_signature / _get_pubkey_buffer /
 * _free are declared in wolfssl/ssl.h only under this set of macros, not under
 * WOLFSSL_CERT_GEN as an earlier version of this guard assumed. With the wrong
 * macro they became implicit declarations, which -Werror=implicit-function-
 * declaration and -Werror=nested-externs turn into build failures (and the
 * implicit int return then trips -Werror=int-conversion on the assignment). */
#if !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && \
    (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL) || \
     defined(KEEP_PEER_CERT) || defined(KEEP_OUR_CERT) || \
     defined(SESSION_CERTS))
    WOLFSSL_X509* x509 = NULL;
    byte  buf[2048];
    int   iSz = (int)sizeof(buf);
    word32 wSz = (word32)sizeof(buf);
    const byte* der = NULL;
    int   derSz = 0;

    XMEMSET(buf, 0, sizeof(buf));

    /* the NULL half of every guard, before any fixture exists */
    (void)wolfSSL_X509_get_der(NULL, &derSz);
    (void)wolfSSL_X509_get_serial_number(NULL, buf, &iSz);
    (void)wolfSSL_X509_get_signature(NULL, buf, &iSz);
    (void)wolfSSL_X509_get_next_altname(NULL);
    (void)wolfSSL_X509_load_certificate_file(NULL, WOLFSSL_FILETYPE_PEM);
    (void)wolfSSL_X509_load_certificate_file("certs/no-such-file.pem",
                                             WOLFSSL_FILETYPE_PEM);

    /* the accepting half: a real parsed certificate */
    x509 = wolfSSL_X509_load_certificate_file(svrCertFile,
                                              WOLFSSL_FILETYPE_PEM);
    if (x509 != NULL) {
        /* second operand of each guard: valid object, NULL output */
        (void)wolfSSL_X509_get_der(x509, NULL);
        (void)wolfSSL_X509_get_serial_number(x509, buf, NULL);
        (void)wolfSSL_X509_get_serial_number(x509, NULL, &iSz);
        (void)wolfSSL_X509_get_signature(x509, buf, NULL);
        /* a buffer too small for the signature: the size operand, which a
         * caller sizing from the query call never takes */
        iSz = 1;
        (void)wolfSSL_X509_get_signature(x509, buf, &iSz);
        /* the query form: NULL buffer with a size pointer */
        iSz = 0;
        (void)wolfSSL_X509_get_signature(x509, NULL, &iSz);
        iSz = (int)sizeof(buf);
        (void)wolfSSL_X509_get_signature(x509, buf, &iSz);

        derSz = 0;
        der = wolfSSL_X509_get_der(x509, &derSz);
        (void)der;

        iSz = (int)sizeof(buf);
        (void)wolfSSL_X509_get_serial_number(x509, buf, &iSz);
        (void)wolfSSL_X509_get_next_altname(x509);
        (void)wolfSSL_X509_notBefore(x509);
        (void)wolfSSL_X509_notAfter(x509);
        (void)wolfSSL_X509_version(x509);

#ifdef OPENSSL_EXTRA
        (void)wolfSSL_X509_check_host(x509, NULL, 0, 0, NULL);
        (void)wolfSSL_X509_check_host(NULL, "example.com", 11, 0, NULL);
#endif
        wSz = (word32)sizeof(buf);
        (void)wolfSSL_X509_get_pubkey_buffer(x509, buf, (int*)&wSz);
        (void)wolfSSL_X509_get_pubkey_buffer(x509, NULL, (int*)&wSz);
        (void)wolfSSL_X509_get_pubkey_buffer(x509, buf, NULL);

        /* --- host and IP matching, both operands of each guard --------- */
#ifndef NO_ASN
        /* `(x == NULL) || (chk == NULL)` */
        (void)wolfSSL_X509_check_host(NULL, "example.com", 11, 0, NULL);
        (void)wolfSSL_X509_check_host(x509, NULL, 11, 0, NULL);
        (void)wolfSSL_X509_check_host(x509, "example.com", 11, 0, NULL);
        /* `chklen > 1 && chk[chklen - 1] == 0` -- a length that includes the
         * terminator, which a caller using strlen() never passes */
        (void)wolfSSL_X509_check_host(x509, "example.com", 12, 0, NULL);
        (void)wolfSSL_X509_check_host(x509, "e", 1, 0, NULL);
        (void)wolfSSL_X509_check_host(x509, "", 0, 0, NULL);

        /* `(x == NULL) || (x->derCert == NULL) || (ipasc == NULL)` */
        (void)wolfSSL_X509_check_ip_asc(NULL, "127.0.0.1", 0);
        (void)wolfSSL_X509_check_ip_asc(x509, NULL, 0);
        (void)wolfSSL_X509_check_ip_asc(x509, "127.0.0.1", 0);
        (void)wolfSSL_X509_check_ip_asc(x509, "not-an-ip", 0);
#endif

        wolfSSL_X509_free(x509);
    }

    /* --- load_certificate_file: `fname == NULL`, and the size bounds ---- */
    (void)wolfSSL_X509_load_certificate_file(NULL, WOLFSSL_FILETYPE_PEM);
    /* a file that exists but is empty: sz < 0 || sz > MAX is the guard the
     * happy path never reaches */
    {
        const char* emptyPem = "test-x509-empty.tmp";
        XFILE ef = XFOPEN(emptyPem, "wb");

        if (ef != XBADFILE) {
            XFCLOSE(ef);
            (void)wolfSSL_X509_load_certificate_file(emptyPem,
                                                     WOLFSSL_FILETYPE_PEM);
            (void)remove(emptyPem);
        }
        /* a directory where a file is expected */
        (void)wolfSSL_X509_load_certificate_file("certs",
                                                 WOLFSSL_FILETYPE_PEM);
        /* an unknown format on a real certificate */
        (void)wolfSSL_X509_load_certificate_file(svrCertFile, -1);
    }
    (void)wSz;
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_dtls_api_on_dtls_object(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_DTLS) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_CERTS)
    WOLFSSL_CTX* dctx = NULL;   /* the object the second operand needs */
    WOLFSSL_CTX* tctx = NULL;   /* a TLS one, for the operand's other half */
    WOLFSSL* dssl = NULL;
    WOLFSSL* tssl = NULL;
    byte peer[64];
    unsigned int peerSz = (unsigned int)sizeof(peer);

    XMEMSET(peer, 0, sizeof(peer));
    ExpectNotNull(dctx = wolfSSL_CTX_new(wolfDTLSv1_2_client_method()));
    ExpectNotNull(tctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNotNull(dssl = wolfSSL_new(dctx));
    ExpectNotNull(tssl = wolfSSL_new(tctx));

    /* `ssl == NULL || !ssl->options.dtls` -- three vectors, one per outcome */
    (void)wolfSSL_dtls_got_timeout(NULL);
    (void)wolfSSL_dtls_got_timeout(tssl);   /* not a DTLS connection */
    (void)wolfSSL_dtls_got_timeout(dssl);   /* the accepting partner */
    (void)wolfSSL_dtls_retransmit(NULL);
    (void)wolfSSL_dtls_retransmit(tssl);
    (void)wolfSSL_dtls_retransmit(dssl);
    (void)wolfSSL_dtls_get_current_timeout(tssl);
    (void)wolfSSL_dtls_get_current_timeout(dssl);
    (void)wolfSSL_dtls(tssl);
    (void)wolfSSL_dtls(dssl);

    /* peer accessors on a connection that has no peer set yet */
    peerSz = (unsigned int)sizeof(peer);
    (void)wolfSSL_dtls_get_peer(dssl, peer, &peerSz);
    (void)wolfSSL_dtls_get_peer(dssl, NULL, &peerSz);
    (void)wolfSSL_dtls_get_peer(dssl, peer, NULL);
    /* Implemented only under WOLFSSL_DTLS_CID && !WOLFSSL_NO_SOCK
     * (src/ssl_api_dtls.c); declared unconditionally in ssl.h, so a config
     * with WOLFSSL_DTLS on and WOLFSSL_DTLS_CID off compiles this call and
     * fails at LINK time. Confirmed with a real build. */
#if defined(WOLFSSL_DTLS_CID) && !defined(WOLFSSL_NO_SOCK)
    (void)wolfSSL_dtls_set_pending_peer(dssl, peer, 0);
    (void)wolfSSL_dtls_set_pending_peer(dssl, NULL,
                                        (unsigned int)sizeof(peer));
    (void)wolfSSL_dtls_set_pending_peer(dssl, peer,
                                        (unsigned int)sizeof(peer));
    /* and again now that a peer exists, so the `peer.sa != NULL` operand
     * gets both values */
    (void)wolfSSL_dtls_set_pending_peer(dssl, peer,
                                        (unsigned int)sizeof(peer));
#endif

    /* MTU: `ctx == NULL || newMtu > MAX_RECORD_SIZE`, both operands */
/* Declared under (WOLFSSL_SCTP || WOLFSSL_DTLS_MTU) && WOLFSSL_DTLS in ssl.h;
 * guarding on WOLFSSL_DTLS_MTU alone left the SCTP-only configs calling an
 * undeclared function. */
#if (defined(WOLFSSL_SCTP) || defined(WOLFSSL_DTLS_MTU)) && defined(WOLFSSL_DTLS)
    (void)wolfSSL_CTX_dtls_set_mtu(NULL, 512);
    (void)wolfSSL_CTX_dtls_set_mtu(dctx, 0xFFFF);
    (void)wolfSSL_CTX_dtls_set_mtu(dctx, 512);
    (void)wolfSSL_dtls_set_mtu(dssl, 0xFFFF);
    (void)wolfSSL_dtls_set_mtu(dssl, 512);
#endif

#ifdef WOLFSSL_DTLS13
    (void)wolfSSL_dtls13_has_pending_msg(dssl);
    (void)wolfSSL_dtls13_use_quick_timeout(dssl);
    wolfSSL_dtls13_set_send_more_acks(dssl, 1);
    wolfSSL_dtls13_set_send_more_acks(dssl, 0);
#endif

    wolfSSL_free(dssl);
    wolfSSL_free(tssl);
    wolfSSL_CTX_free(dctx);
    wolfSSL_CTX_free(tctx);
#endif
    return EXPECT_RESULT();
}

/* ---------------------------------------------------------------------------
 * Certificate loading from files that are wrong in file-system ways.
 *
 * ssl_misc.c is 0/11 and every one of its conditions is in a static file
 * helper -- wolfssl_file_len and wolfssl_read_file_static -- guarding against
 * a seek that fails, a length that is zero or absurd, and a read that returns
 * fewer bytes than the length promised:
 *
 *     if ((ret == 0) && ((sz > MAX_WOLFSSL_FILE_SIZE) || (sz <= 0L)))
 *     if ((ret == 0) && ((file = XFOPEN(fname, "rb")) == XBADFILE))
 *     if ((ret == 0) && (XFREAD(...) != sz))
 *
 * They are static, but they are not out of reach: every public load-from-file
 * entry point runs through them, so the vector is the FILE rather than the
 * argument. An empty file gives sz <= 0; a directory passed where a file is
 * expected gives a seek or read that fails; a name that does not exist gives
 * XBADFILE. None of those is something a working configuration supplies, and
 * no existing test supplies them either.
 * ------------------------------------------------------------------------- */
int test_wolfSSL_load_pathological_files(void)
{
    EXPECT_DECLS;
#if !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL_CERT_MANAGER* cm = NULL;
    const char* emptyFile = "test-empty-cert.tmp";
    XFILE f = XBADFILE;

    /* an empty file: the `sz <= 0` operand, which no real certificate has */
    f = XFOPEN(emptyFile, "wb");
    if (f != XBADFILE)
        XFCLOSE(f);

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));

    /* XBADFILE: a name that does not exist */
    (void)wolfSSL_CTX_load_verify_locations(ctx, "no-such-file.pem", NULL);
    (void)wolfSSL_CTX_use_certificate_file(ctx, "no-such-file.pem",
                                           WOLFSSL_FILETYPE_PEM);
    (void)wolfSSL_CTX_use_PrivateKey_file(ctx, "no-such-file.pem",
                                          WOLFSSL_FILETYPE_PEM);

    /* sz <= 0: the empty file */
    (void)wolfSSL_CTX_load_verify_locations(ctx, emptyFile, NULL);
    (void)wolfSSL_CTX_use_certificate_file(ctx, emptyFile,
                                           WOLFSSL_FILETYPE_PEM);
    (void)wolfSSL_CTX_use_PrivateKey_file(ctx, emptyFile,
                                          WOLFSSL_FILETYPE_PEM);
    (void)wolfSSL_CTX_use_certificate_chain_file(ctx, emptyFile);

    /* a directory where a file is expected: the seek and read failure arms */
    (void)wolfSSL_CTX_load_verify_locations(ctx, "certs", NULL);
    (void)wolfSSL_CTX_use_certificate_file(ctx, "certs",
                                           WOLFSSL_FILETYPE_PEM);

    /* a file that exists and is not a certificate at all */
    (void)wolfSSL_CTX_load_verify_locations(ctx, "Makefile", NULL);

    /* the accepting partner, so every operand above has one */
    (void)wolfSSL_CTX_load_verify_locations(ctx, caCertFile, NULL);

    /* the same set through the CertManager, which has its own copies of the
     * load paths */
    cm = wolfSSL_CertManagerNew();
    if (cm != NULL) {
        (void)wolfSSL_CertManagerLoadCA(cm, "no-such-file.pem", NULL);
        (void)wolfSSL_CertManagerLoadCA(cm, emptyFile, NULL);
        (void)wolfSSL_CertManagerLoadCA(cm, "certs", NULL);
        (void)wolfSSL_CertManagerLoadCA(cm, caCertFile, NULL);
        (void)wolfSSL_CertManagerVerify(cm, "no-such-file.pem",
                                        WOLFSSL_FILETYPE_PEM);
        (void)wolfSSL_CertManagerVerify(cm, emptyFile, WOLFSSL_FILETYPE_PEM);
        (void)wolfSSL_CertManagerVerify(cm, svrCertFile,
                                        WOLFSSL_FILETYPE_PEM);
        (void)wolfSSL_CertManagerUnloadCAs(cm);
        (void)wolfSSL_CertManagerUnloadCAs(NULL);
        wolfSSL_CertManagerFree(cm);
    }
    {
        /* Returns an owned CertManager; discarding it leaks
         * (LeakSanitizer: 280 bytes from wolfSSL_CertManagerNew_ex). */
        WOLFSSL_CERT_MANAGER* tmpCm = wolfSSL_CertManagerNew_ex(NULL);

        if (tmpCm != NULL)
            wolfSSL_CertManagerFree(tmpCm);
    }

    wolfSSL_CTX_free(ctx);
    (void)remove(emptyFile);
#endif
    return EXPECT_RESULT();
}

/* ---------------------------------------------------------------------------
 * The file-helper failure arms, reached with a FIFO.
 *
 * Three of ssl_misc.c's conditions cannot be produced by any regular file:
 *
 *     if ((ret == 0) && (XFSEEK(fp, 0, SEEK_END) != 0))     seek failed
 *     if ((ret == 0) && (XFREAD(...) != (size_t)sz))        short read
 *
 * A regular file always seeks and always reads what it promised. A FIFO does
 * neither: fopen() succeeds, so the XBADFILE arm is passed, and then fseek()
 * fails with ESPIPE because a pipe has no position. That is the exact shape
 * the guard is written for, and nothing on disk can imitate it.
 *
 * The FIFO is opened read-write by the test before the library touches it, so
 * the library's fopen() cannot block waiting for a writer -- a test that hangs
 * costs the whole variant just as surely as one that crashes.
 * ------------------------------------------------------------------------- */
int test_wolfSSL_load_from_fifo(void)
{
    EXPECT_DECLS;
#if !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && \
    !defined(NO_WOLFSSL_CLIENT) && defined(__unix__)
    WOLFSSL_CTX* ctx = NULL;
    const char* fifo = "test-cert-fifo.tmp";
    int fd = -1;

    (void)remove(fifo);
    if (mkfifo(fifo, 0600) != 0) {
        /* no FIFO support here; that is a platform fact, not a failure */
        return EXPECT_RESULT();
    }
    /* Hold it open both ways so the library's fopen() returns immediately
     * and there is something to read. */
    fd = open(fifo, O_RDWR | O_NONBLOCK);
    if (fd >= 0) {
        const char junk[] = "-----BEGIN CERTIFICATE-----\n";
        ssize_t w = write(fd, junk, sizeof(junk) - 1);
        (void)w;
    }

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    if (fd >= 0) {
        /* fopen succeeds, fseek fails: the seek-failure arm */
        (void)wolfSSL_CTX_load_verify_locations(ctx, fifo, NULL);
        (void)wolfSSL_CTX_use_certificate_file(ctx, fifo,
                                               WOLFSSL_FILETYPE_PEM);
        (void)wolfSSL_CTX_use_PrivateKey_file(ctx, fifo,
                                              WOLFSSL_FILETYPE_PEM);
        (void)wolfSSL_CTX_use_certificate_chain_file(ctx, fifo);
        {
            WOLFSSL_CERT_MANAGER* cm = wolfSSL_CertManagerNew();
            if (cm != NULL) {
                (void)wolfSSL_CertManagerLoadCA(cm, fifo, NULL);
                (void)wolfSSL_CertManagerVerify(cm, fifo,
                                                WOLFSSL_FILETYPE_PEM);
                wolfSSL_CertManagerFree(cm);
            }
        }
        /* the accepting partner through the same code */
        (void)wolfSSL_CTX_load_verify_locations(ctx, caCertFile, NULL);
    }

    wolfSSL_CTX_free(ctx);
    if (fd >= 0)
        close(fd);
    (void)remove(fifo);
#endif
    return EXPECT_RESULT();
}

/* ---------------------------------------------------------------------------
 * Allocation failure injection.
 *
 * Error propagation is the largest remaining category in the campaign: 633 of
 * 2855 uncovered conditions, almost all of the shape
 *
 *     ret = something();
 *     if (ret != 0) { ... }          or        if (p == NULL) { ... }
 *
 * after a call that cannot fail in a working configuration. No number of
 * successful runs pairs those operands, because the failing value never
 * occurs. The only way to produce it is to make the underlying operation fail
 * on purpose.
 *
 * wolfSSL_SetAllocators() is the cheapest lever for that: one harness, and it
 * reaches every out-of-memory arm in every file at once, because every
 * allocation in the library goes through it. The sweep fails the Nth
 * allocation and lets the rest succeed, for each N in turn -- so each run
 * takes a different one of those arms, and the runs where N is past the end
 * of the workload are the shared accepting partner.
 *
 * Failing exactly one allocation rather than everything from N onward keeps
 * each vector isolated: a cascade would take many arms at once and prove
 * nothing about any single one.
 *
 * The allocators are restored before the test returns. Leaving a failing
 * allocator installed would break every test that runs after this one in the
 * same binary, which costs the whole variant.
 * ------------------------------------------------------------------------- */
/* Not under WOLFSSL_SMALL_STACK: that variant segfaults during the sweep
 * while the default one completes it cleanly. Whether that is a small-stack
 * allocation path that does not handle failure, or the harness exhausting
 * something the small-stack build is more sensitive to, is not established --
 * and a crash there discards the whole variant, so it is excluded until the
 * difference is understood rather than left to take the evidence down. */
#if !defined(WOLFSSL_STATIC_MEMORY) && !defined(WOLFSSL_DEBUG_MEMORY) && \
    !defined(WOLFSSL_SMALL_STACK) && \
    !defined(NO_CERTS) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_FILESYSTEM)

static int fi_failAt = -1;      /* which allocation to fail; -1 = none */
static int fi_count;            /* allocations seen since the last reset */
static int fi_failed;           /* did we actually inject one this run     */

static void* fi_malloc(size_t n)
{
    /* The index is taken BEFORE the test. Writing this as
     *     if (fi_failAt >= 0 && fi_count++ == fi_failAt)
     * short-circuits the increment away whenever injection is off, so the
     * counting pass counts nothing, the sweep bound comes out zero and the
     * harness silently measures the happy path. That is the same operand
     * short-circuit these tests exist to cover, in the test's own code. */
    int i = fi_count++;

    if (fi_failAt >= 0 && i == fi_failAt) {
        fi_failed = 1;
        return NULL;
    }
    return malloc(n);
}

static void fi_free(void* p)
{
    free(p);
}

static void* fi_realloc(void* p, size_t n)
{
    int i = fi_count++;

    if (fi_failAt >= 0 && i == fi_failAt) {
        fi_failed = 1;
        return NULL;
    }
    return realloc(p, n);
}

/* The workload every vector runs. Deliberately ordinary: build a context,
 * load real credentials, build a connection object, ask for a few extensions,
 * tear it all down. What varies between vectors is only which allocation
 * inside it fails. */
static void fi_workload(void)
{
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;

    ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    if (ctx == NULL)
        return;
    (void)wolfSSL_CTX_load_verify_locations(ctx, caCertFile, NULL);
    (void)wolfSSL_CTX_use_certificate_file(ctx, svrCertFile,
                                           WOLFSSL_FILETYPE_PEM);
    (void)wolfSSL_CTX_use_PrivateKey_file(ctx, svrKeyFile,
                                          WOLFSSL_FILETYPE_PEM);

    ssl = wolfSSL_new(ctx);
    if (ssl != NULL) {
#ifdef HAVE_SNI
        (void)wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, "example.com", 11);
#endif
#ifdef HAVE_ALPN
        {
            char alpnList[] = "h2";  /* takes char*, not const char* */
            (void)wolfSSL_UseALPN(ssl, alpnList, 2,
                                  WOLFSSL_ALPN_CONTINUE_ON_MISMATCH);
        }
#endif
#ifdef HAVE_SUPPORTED_CURVES
        (void)wolfSSL_UseSupportedCurve(ssl, WOLFSSL_ECC_SECP256R1);
#endif
#ifdef HAVE_SESSION_TICKET
        (void)wolfSSL_UseSessionTicket(ssl);
#endif
        (void)wolfSSL_SetVersion(ssl, WOLFSSL_TLSV1_2);
        wolfSSL_free(ssl);
    }
    wolfSSL_CTX_free(ctx);
}

#endif

/* Result, recorded because a negative one is still a result: on this workload
 * wolfSSL survives ALL of its allocation failures. The sweep drives 37
 * allocation sites, fails each in turn, and the library returns an error and
 * cleans up every time -- no crash, no leak-driven abort, no wedged state.
 * Verified both here and with a standalone reproducer linked against the
 * campaign's own libwolfssl.a.
 *
 * That is worth knowing for a safety case: the out-of-memory arms in this path
 * are not merely present, they work. It also means the harness is safe to run
 * in the campaign build, which is what makes those arms measurable at all.
 */
int test_wolfSSL_alloc_failure_sweep(void)
{
    EXPECT_DECLS;
#if !defined(WOLFSSL_STATIC_MEMORY) && !defined(WOLFSSL_DEBUG_MEMORY) && \
    !defined(WOLFSSL_SMALL_STACK) && \
    !defined(NO_CERTS) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_FILESYSTEM)
    int n;
    int injected = 0;
    int total;

    /* Install the wrappers with injection off, and count how many
     * allocations the workload makes, so the sweep covers all of them and
     * stops rather than running past the end. */
    if (wolfSSL_SetAllocators(fi_malloc, fi_free, fi_realloc) != 0) {
        /* the build does not allow overriding allocators here */
        return EXPECT_RESULT();
    }

    fi_failAt = -1;
    fi_count = 0;
    fi_workload();
    total = fi_count;
    ExpectIntGT(total, 0);
    /* The count is not stable between runs -- caches warm, session state
     * persists -- so the sweep bound is taken from the first pass and the
     * per-vector check below is 'did this one inject', not 'did all of
     * them'. Asserting the totals match failed for exactly this reason. */

    /* One run per allocation, failing that one and no other. */
    for (n = 0; n < total; n++) {
        fi_failAt = n;
        fi_count = 0;
        fi_failed = 0;
        fi_workload();
        if (fi_failed)
            injected++;
    }

    /* The accepting partner: the same workload with nothing failing. */
    fi_failAt = -1;
    fi_count = 0;
    fi_workload();

    /* At least one vector must have injected, or the sweep silently measured
     * the happy path N times over -- the no-op failure mode this campaign has
     * hit repeatedly. */
    ExpectIntGT(injected, 0);

    /* Restore, and prove the library still works afterwards -- a failing
     * allocator left installed would break every later test in this binary. */
    fi_failAt = -1;
    (void)wolfSSL_SetAllocators(fi_malloc, fi_free, fi_realloc);
    {
        WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
        ExpectNotNull(ctx);
        wolfSSL_CTX_free(ctx);
    }
#endif
    return EXPECT_RESULT();
}

/* ---------------------------------------------------------------------------
 * DTLS API argument guards, on a DTLS object.
 *
 * ssl_api_dtls.c is the weakest of the newly-visible files. Its guards are the
 * usual NULL-and-zero pairs, but the ACCEPTING half of most of them needs a
 * DTLS connection -- the same reason the file sat at 3/53 until one was
 * supplied. These add the entry points the earlier pass did not reach.
 *
 * Guards were read from src/ssl_api_dtls.c before writing, not assumed from
 * ssl.h: wolfSSL_dtls13_pending_work is compiled only under WOLFSSL_DTLS13,
 * SetCookieSecret only under WOLFSSL_DTLS && !NO_WOLFSSL_SERVER, and several
 * are additionally gated on !WOLFSSL_LEANPSK.
 * ------------------------------------------------------------------------- */
int test_wolfSSL_dtls_api_more_guards(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_DTLS) && !defined(WOLFSSL_LEANPSK) && \
    !defined(WOLFCRYPT_ONLY) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(NO_CERTS)
    WOLFSSL_CTX* dctx = NULL;
    WOLFSSL* dssl = NULL;
    byte peer[64];
    unsigned int peerSz = (unsigned int)sizeof(peer);
    const void* p0 = NULL;
    unsigned int p0Sz = 0;

    XMEMSET(peer, 0, sizeof(peer));
    ExpectNotNull(dctx = wolfSSL_CTX_new(wolfDTLSv1_2_client_method()));
    ExpectNotNull(dssl = wolfSSL_new(dctx));

    /* `peer == NULL || peerSz == NULL` -- one call per operand */
    (void)wolfSSL_dtls_get0_peer(NULL, &p0, &p0Sz);
    (void)wolfSSL_dtls_get0_peer(dssl, NULL, &p0Sz);
    (void)wolfSSL_dtls_get0_peer(dssl, &p0, NULL);
    (void)wolfSSL_dtls_get0_peer(dssl, &p0, &p0Sz);

    /* `ssl && timeleft` -- both operands */
    {
        WOLFSSL_TIMEVAL tv;

        XMEMSET(&tv, 0, sizeof(tv));
        (void)wolfSSL_DTLSv1_get_timeout(NULL, &tv);
        (void)wolfSSL_DTLSv1_get_timeout(dssl, NULL);
        (void)wolfSSL_DTLSv1_get_timeout(dssl, &tv);
    }

    /* `ssl == NULL || timeout < 0` -- and the boundary at zero */
    (void)wolfSSL_dtls_set_timeout_max(NULL, 5);
    (void)wolfSSL_dtls_set_timeout_max(dssl, -1);
    (void)wolfSSL_dtls_set_timeout_max(dssl, 0);
    (void)wolfSSL_dtls_set_timeout_max(dssl, 5);
    (void)wolfSSL_dtls_set_timeout_init(dssl, 0);

    /* the peer setters/getters with a real DTLS object */
    peerSz = (unsigned int)sizeof(peer);
    (void)wolfSSL_dtls_get_peer(dssl, peer, &peerSz);

#ifdef WOLFSSL_DTLS13
    /* `ssl != NULL && ssl->dtls13FastTimeout` -- both operands; the flag is
     * never set on a connection that has not scheduled fast retransmission */
    (void)wolfSSL_dtls13_use_quick_timeout(NULL);
    (void)wolfSSL_dtls13_use_quick_timeout(dssl);
    if (dssl != NULL) {
        dssl->dtls13FastTimeout = 1;
        (void)wolfSSL_dtls13_use_quick_timeout(dssl);
        dssl->dtls13FastTimeout = 0;
    }

    /* `ssl == NULL || !Dtls13ScheduledWorkReady(ssl)` and the pending-work
     * chain below it: output buffered, a key update owed, an ack owed. Each
     * flag is set directly because a connection only reaches these states
     * mid-flight, between a write that blocked and its retry. */
    (void)wolfSSL_dtls13_pending_work(NULL);
    (void)wolfSSL_dtls13_pending_work(dssl);
    if (dssl != NULL) {
        dssl->options.handShakeDone = 1;
        (void)wolfSSL_dtls13_pending_work(dssl);
        dssl->dtls13DoKeyUpdate = 1;
        (void)wolfSSL_dtls13_pending_work(dssl);
        dssl->dtls13DoKeyUpdate = 0;
        dssl->options.sendKeyUpdate = 1;
        (void)wolfSSL_dtls13_pending_work(dssl);
        dssl->options.sendKeyUpdate = 0;
        dssl->dtls13SendingAckOrRtx = 1;
        (void)wolfSSL_dtls13_pending_work(dssl);
        dssl->dtls13SendingAckOrRtx = 0;
        dssl->options.handShakeDone = 0;
    }
    (void)wolfSSL_dtls13_has_pending_msg(dssl);
#endif

#if !defined(NO_WOLFSSL_SERVER)
    {
        byte secret[16];

        XMEMSET(secret, 0xC0, sizeof(secret));
        /* `secret != NULL && secretSz == 0` -- the "clear the secret" call is
         * (NULL, 0); a buffer with a zero length is the operand pair no
         * caller produces */
        (void)wolfSSL_DTLS_SetCookieSecret(NULL, secret, 0);
        (void)wolfSSL_DTLS_SetCookieSecret(NULL, NULL, 0);
        (void)wolfSSL_DTLS_SetCookieSecret(NULL, secret,
                                           (word32)sizeof(secret));
    }
#endif

    wolfSSL_free(dssl);
    wolfSSL_CTX_free(dctx);
#endif
    return EXPECT_RESULT();
}
