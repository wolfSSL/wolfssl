/* test_ssl_hs.c
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
#include <wolfssl/wolfio.h>

#include <tests/utils.h>
#include <tests/api/test_ssl_hs.h>

/* Tests for the handshake APIs in src/ssl_api_hs.c (moved from ssl.c). These
 * cover functions not already exercised elsewhere in api.c. */

/* Test wolfSSL_state_string_long() over a live handshake.
 *
 * Covers the NULL case, the unknown-protocol case and sampling the state
 * before, during and after a handshake.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_state_string_long(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) \
    && !defined(NO_TLS) && !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    /* A NULL object has no state to report. */
    ExpectNull(wolfSSL_state_string_long(NULL));

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);

    /* Before the handshake both sides report the initial state, named for the
     * method's version rather than a negotiated one. */
    ExpectStrEQ(wolfSSL_state_string_long(ssl_c), "TLSv1_2 Initialization");
    ExpectStrEQ(wolfSSL_state_string_long(ssl_s), "TLSv1_2 Initialization");

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* After the handshake each side reports the last message it handled,
     * prefixed with the negotiated protocol. Both have finished, so neither
     * is still reporting the initial state. */
    ExpectIntEQ(XSTRNCMP(wolfSSL_state_string_long(ssl_c), "TLSv1_2 ", 8), 0);
    ExpectIntEQ(XSTRNCMP(wolfSSL_state_string_long(ssl_s), "TLSv1_2 ", 8), 0);
    ExpectStrNE(wolfSSL_state_string_long(ssl_c), "TLSv1_2 Initialization");
    ExpectStrNE(wolfSSL_state_string_long(ssl_s), "TLSv1_2 Initialization");

    /* The completed state has one string for both directions, unlike the
     * per-message states which name the direction. */
    if (ssl_c != NULL) {
        ssl_c->cbmode = WOLFSSL_CB_MODE_WRITE;
        ssl_c->options.clientState = HANDSHAKE_DONE;
        ExpectStrEQ(wolfSSL_state_string_long(ssl_c), "TLSv1_2 Handshake Done");
        ssl_c->cbmode = WOLFSSL_CB_MODE_READ;
        ssl_c->cbtype = server_hello;
        ExpectStrEQ(wolfSSL_state_string_long(ssl_c),
            "TLSv1_2 read Server Hello");
    }

    /* An unrecognized protocol version reports an empty string. */
    if (ssl_c != NULL) {
        ProtocolVersion saved = ssl_c->version;

        ssl_c->version.major = 0x7f;
        ExpectStrEQ(wolfSSL_state_string_long(ssl_c), "");
        ssl_c->version = saved;
    }

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* Test wolfSSL_state_string_long() across the states it can report.
 *
 * The reported string is chosen from the callback mode, the handshake message
 * type when reading, and the connection state when writing. Walk each of those
 * so every arm of the translation is taken.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_state_string_long_states(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_WOLFSSL_CLIENT) \
    && !defined(NO_TLS) && !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    /* Handshake message types reported while reading, with the string each
     * maps to. Only one side sends these, so the object's own side does not
     * come into it. */
    static const struct {
        int type;
        const char* str;
    } readStates[] = {
        { hello_request,        "TLSv1_2 read Server Hello Request" },
        { hello_verify_request, "TLSv1_2 read Server Hello Verify Request" },
        { session_ticket,       "TLSv1_2 read Server Session Ticket" },
        { end_of_early_data,    "TLSv1_2 read Client End Of Early Data" },
        { hello_retry_request,  "TLSv1_2 read Server Hello Retry Request" },
        { client_hello,         "TLSv1_2 read Client Hello" },
        { server_hello,         "TLSv1_2 read Server Hello" },
        { encrypted_extensions, "TLSv1_2 read Server Encrypted Extensions" },
        { server_key_exchange,  "TLSv1_2 read Server Key Exchange" },
        { certificate_request,  "TLSv1_2 read Server Certificate Request" },
        { server_hello_done,    "TLSv1_2 read Server Hello Done" },
        { certificate_verify,   "TLSv1_2 read Client Certificate Verify" },
        { client_key_exchange,  "TLSv1_2 read Client Key Exchange" },
        { certificate_status,   "TLSv1_2 read Server Certificate Status" },
        /* An unrecognized type reports the null state. */
        { 0x7f,                 "TLSv1_2 Initialization" }
    };
    /* Message types both sides send. The string names the side that sent the
     * message, which is the peer - the opposite of the object's own side. */
    static const struct {
        int type;
        const char* asClient;
        const char* asServer;
    } sidedStates[] = {
        { certificate,
          "TLSv1_2 read Server Cert",
          "TLSv1_2 read Client Cert" },
        { finished,
          "TLSv1_2 read Server Finished",
          "TLSv1_2 read Client Finished" },
        { key_update,
          "TLSv1_2 read server Key Update",
          "TLSv1_2 read Client Key Update" },
        { change_cipher_hs,
          "TLSv1_2 read Server Change CipherSpec",
          "TLSv1_2 read Client Change CipherSpec" }
    };
    /* Connection states reported while writing. Every state from the first
     * to HANDSHAKE_DONE is listed, so the walk below covers the range. */
    static const struct {
        int state;
        const char* str;
    } writeStates[] = {
        { NULL_STATE,
          "TLSv1_2 Initialization" },
        { SERVER_HELLOVERIFYREQUEST_COMPLETE,
          "TLSv1_2 write Server Hello Verify Request" },
        { SERVER_HELLO_RETRY_REQUEST_COMPLETE,
          "TLSv1_2 write Server Hello Retry Request" },
        { SERVER_HELLO_COMPLETE,
          "TLSv1_2 write Server Hello" },
        { SERVER_ENCRYPTED_EXTENSIONS_COMPLETE,
          "TLSv1_2 write Server Encrypted Extensions" },
        { SERVER_CERT_COMPLETE,
          "TLSv1_2 write Server Cert" },
        /* Has no string of its own, so reports the null state. */
        { SERVER_CERT_VERIFY_COMPLETE,
          "TLSv1_2 Initialization" },
        { SERVER_KEYEXCHANGE_COMPLETE,
          "TLSv1_2 write Server Key Exchange" },
        { SERVER_HELLODONE_COMPLETE,
          "TLSv1_2 write Server Hello Done" },
        { SERVER_CHANGECIPHERSPEC_COMPLETE,
          "TLSv1_2 write Server Change CipherSpec" },
        { SERVER_FINISHED_COMPLETE,
          "TLSv1_2 write Server Finished" },
        { CLIENT_HELLO_RETRY,
          "TLSv1_2 write Client Hello" },
        { CLIENT_HELLO_COMPLETE,
          "TLSv1_2 write Client Hello" },
        { CLIENT_KEYEXCHANGE_COMPLETE,
          "TLSv1_2 write Client Key Exchange" },
        { CLIENT_CHANGECIPHERSPEC_COMPLETE,
          "TLSv1_2 write Client Change CipherSpec" },
        { CLIENT_FINISHED_COMPLETE,
          "TLSv1_2 write Client Finished" },
        { HANDSHAKE_DONE,
          "TLSv1_2 Handshake Done" }
    };
    /* Each protocol version has its own set of strings. */
    static const struct {
        int major;
        int minor;
        const char* str;
    } protocols[] = {
        { SSLv3_MAJOR, SSLv3_MINOR,    "SSLv3 read Server Hello" },
        { SSLv3_MAJOR, TLSv1_MINOR,    "TLSv1 read Server Hello" },
        { SSLv3_MAJOR, TLSv1_1_MINOR,  "TLSv1_1 read Server Hello" },
        { SSLv3_MAJOR, TLSv1_2_MINOR,  "TLSv1_2 read Server Hello" },
        { SSLv3_MAJOR, TLSv1_3_MINOR,  "TLSv1_3 read Server Hello" },
        { DTLS_MAJOR,  DTLS_MINOR,     "DTLSv1 read Server Hello" },
        { DTLS_MAJOR,  DTLSv1_2_MINOR, "DTLSv1_2 read Server Hello" },
        { DTLS_MAJOR,  DTLSv1_3_MINOR, "DTLSv1_3 read Server Hello" },
        /* An unrecognized minor version of either major reports no string. */
        { SSLv3_MAJOR, 0x7f,           "" },
        { DTLS_MAJOR,  0x7f,           "" }
    };
    int i;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    if (ssl != NULL) {
        /* Reading: every message type maps to a state string. */
        ssl->cbmode = WOLFSSL_CB_MODE_READ;
        for (i = 0; i < (int)XELEM_CNT(readStates); i++) {
            ssl->cbtype = readStates[i].type;
            ExpectStrEQ(wolfSSL_state_string_long(ssl), readStates[i].str);
        }

        /* The messages both sides send name their sender, so the string
         * follows the side of the object that read them. */
        for (i = 0; i < (int)XELEM_CNT(sidedStates); i++) {
            ssl->cbtype = sidedStates[i].type;
            ssl->options.side = WOLFSSL_CLIENT_END;
            ExpectStrEQ(wolfSSL_state_string_long(ssl),
                sidedStates[i].asClient);
            ssl->options.side = WOLFSSL_SERVER_END;
            ExpectStrEQ(wolfSSL_state_string_long(ssl),
                sidedStates[i].asServer);
            /* With no side established the sender cannot be named. */
            ssl->options.side = WOLFSSL_NEITHER_END;
            ExpectStrEQ(wolfSSL_state_string_long(ssl),
                "TLSv1_2 Initialization");
        }
        ssl->options.side = WOLFSSL_CLIENT_END;

        /* Writing: the connection state is reported instead. */
        ssl->cbmode = WOLFSSL_CB_MODE_WRITE;
        for (i = 0; i < (int)XELEM_CNT(writeStates); i++) {
            ssl->options.clientState = (byte)writeStates[i].state;
            ExpectStrEQ(wolfSSL_state_string_long(ssl), writeStates[i].str);
        }

        /* Which state is reported follows the side: a server reports its own
         * rather than the client's. */
        ssl->options.serverState = SERVER_HELLO_COMPLETE;
        ssl->options.clientState = CLIENT_FINISHED_COMPLETE;
        ssl->options.side = WOLFSSL_SERVER_END;
        ExpectStrEQ(wolfSSL_state_string_long(ssl),
            "TLSv1_2 write Server Hello");
        ssl->options.side = WOLFSSL_CLIENT_END;
        ExpectStrEQ(wolfSSL_state_string_long(ssl),
            "TLSv1_2 write Client Finished");

        /* Neither reading nor writing: the string carries no direction. */
        ssl->cbmode = 0;
        ssl->options.clientState = SERVER_HELLO_COMPLETE;
        ExpectStrEQ(wolfSSL_state_string_long(ssl), "TLSv1_2 Server Hello");

        /* Each protocol version has its own set of strings, and one that is
         * not recognized has none. */
        ssl->cbmode = WOLFSSL_CB_MODE_READ;
        ssl->cbtype = server_hello;
        for (i = 0; i < (int)XELEM_CNT(protocols); i++) {
            ssl->version.major = (byte)protocols[i].major;
            ssl->version.minor = (byte)protocols[i].minor;
            ExpectStrEQ(wolfSSL_state_string_long(ssl), protocols[i].str);
        }
    }

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* Test wolfSSL_set_connect_state() and wolfSSL_set_accept_state().
 *
 * Each switches the side the object will act as.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_set_connect_accept_state(void)
{
    EXPECT_DECLS;
#if (defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)) \
    && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) \
    && !defined(NO_TLS) && !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    /* A NULL object is ignored by both. */
    wolfSSL_set_connect_state(NULL);
    wolfSSL_set_accept_state(NULL);

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* Created from a client method. */
    ExpectIntEQ(wolfSSL_is_server(ssl), 0);

    /* Switch to acting as a server, then back. */
    wolfSSL_set_accept_state(ssl);
    ExpectIntEQ(wolfSSL_is_server(ssl), 1);
    wolfSSL_set_connect_state(ssl);
    ExpectIntEQ(wolfSSL_is_server(ssl), 0);

    /* Setting the same side again is harmless. */
    wolfSSL_set_connect_state(ssl);
    ExpectIntEQ(wolfSSL_is_server(ssl), 0);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* Test wolfSSL_SSL_do_handshake().
 *
 * Drives a handshake through the OpenSSL-compatibility entry point, which
 * dispatches to connect or accept based on the side of the object.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_SSL_do_handshake(void)
{
    EXPECT_DECLS;
#if (defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA)) \
    && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && !defined(NO_TLS) \
    && !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    int i;
    int cRet = WOLFSSL_FATAL_ERROR;
    int sRet = WOLFSSL_FATAL_ERROR;

    /* A NULL object is rejected. */
    ExpectIntEQ(wolfSSL_SSL_do_handshake(NULL), WOLFSSL_FAILURE);

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);

    /* Alternate the two sides until both report the handshake is complete. */
    for (i = 0; i < 10; i++) {
        if (cRet != WOLFSSL_SUCCESS) {
            cRet = wolfSSL_SSL_do_handshake(ssl_c);
        }
        if (sRet != WOLFSSL_SUCCESS) {
            sRet = wolfSSL_SSL_do_handshake(ssl_s);
        }
        if ((cRet == WOLFSSL_SUCCESS) && (sRet == WOLFSSL_SUCCESS)) {
            break;
        }
    }
    ExpectIntEQ(cRet, WOLFSSL_SUCCESS);
    ExpectIntEQ(sRet, WOLFSSL_SUCCESS);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* Test wolfSSL_SSL_in_init(), wolfSSL_SSL_in_before() and
 * wolfSSL_SSL_in_connect_init().
 *
 * The three report where in the handshake the object is.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_SSL_in_init_hs(void)
{
    EXPECT_DECLS;
#if (defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA)) \
    && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && !defined(NO_TLS) \
    && !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    /* NULL objects report no state. */
    ExpectIntEQ(wolfSSL_SSL_in_before(NULL), WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_SSL_in_connect_init(NULL), WOLFSSL_FAILURE);

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);

    /* Nothing has happened yet. */
    ExpectIntEQ(wolfSSL_SSL_in_before(ssl_c), 1);
    ExpectIntEQ(wolfSSL_SSL_in_init(ssl_c), 1);
    ExpectIntEQ(wolfSSL_SSL_in_connect_init(ssl_c), 0);

    /* A partial handshake leaves the client mid-connect. */
    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_SSL_in_connect_init(ssl_c), 1);
    ExpectIntEQ(wolfSSL_SSL_in_before(ssl_c), 1);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* Once complete, none of the in-progress states hold. */
    ExpectIntEQ(wolfSSL_SSL_in_init(ssl_c), 0);
    ExpectIntEQ(wolfSSL_SSL_in_before(ssl_c), 0);
    ExpectIntEQ(wolfSSL_SSL_in_connect_init(ssl_c), 0);
    ExpectIntEQ(wolfSSL_SSL_in_init(ssl_s), 0);
    ExpectIntEQ(wolfSSL_SSL_in_connect_init(ssl_s), 0);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* Test wolfSSL_is_init_finished().
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_is_init_finished(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && !defined(NO_TLS) \
    && !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    /* A NULL object has not finished. */
    ExpectIntEQ(wolfSSL_is_init_finished(NULL), 0);

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);

    ExpectIntEQ(wolfSSL_is_init_finished(ssl_c), 0);
    ExpectIntEQ(wolfSSL_is_init_finished(ssl_s), 0);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    ExpectIntEQ(wolfSSL_is_init_finished(ssl_c), 1);
    ExpectIntEQ(wolfSSL_is_init_finished(ssl_s), 1);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_HANDSHAKE_DONE_CB) && !defined(NO_TLS) && \
    !defined(WOLFSSL_NO_TLS12)
/* Count of handshake-done callback invocations. */
static int test_ssl_hs_done_calls = 0;

/* Handshake-done callback recording that it ran.
 *
 * @param [in] ssl       SSL/TLS object. Unused.
 * @param [in] user_ctx  User context; expected to be &test_ssl_hs_done_calls.
 * @return  0 to let the handshake complete.
 */
static int test_ssl_hs_done_cb(WOLFSSL* ssl, void* user_ctx)
{
    (void)ssl;

    if (user_ctx == &test_ssl_hs_done_calls) {
        test_ssl_hs_done_calls++;
    }

    return 0;
}
#endif

/* Test wolfSSL_SetHsDoneCb().
 *
 * The registered callback must run when the handshake completes.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_SetHsDoneCb(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) \
    && !defined(NO_HANDSHAKE_DONE_CB) && !defined(NO_TLS) \
    && !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    /* A NULL object is rejected. */
    ExpectIntEQ(wolfSSL_SetHsDoneCb(NULL, test_ssl_hs_done_cb, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);

    test_ssl_hs_done_calls = 0;
    ExpectIntEQ(wolfSSL_SetHsDoneCb(ssl_c, test_ssl_hs_done_cb,
        &test_ssl_hs_done_calls), WOLFSSL_SUCCESS);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* The client's callback ran; the server had none registered. */
    ExpectIntEQ(test_ssl_hs_done_calls, 1);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* Test the public-key callback context accessors.
 *
 * Each Set/Get pair stores and returns an opaque application pointer, and each
 * accessor tolerates a NULL object.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_pk_callback_ctx(void)
{
    EXPECT_DECLS;
#if defined(HAVE_PK_CALLBACKS) && !defined(NO_CERTS) \
    && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) \
    && !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    int marker = 0;
    void* p = &marker;

    /* NULL objects are tolerated by every accessor. */
    ExpectNull(wolfSSL_GetGenPreMasterCtx(NULL));
    ExpectNull(wolfSSL_GetGenMasterSecretCtx(NULL));
    ExpectNull(wolfSSL_GetGenSessionKeyCtx(NULL));
    ExpectNull(wolfSSL_GetEncryptKeysCtx(NULL));
    ExpectNull(wolfSSL_GetTlsFinishedCtx(NULL));
    /* The VerifyMac accessors only exist when a MAC is used, so an AEAD-only
     * build does not have them. */
#if !defined(WOLFSSL_NO_TLS12) && !defined(WOLFSSL_AEAD_ONLY)
    ExpectNull(wolfSSL_GetVerifyMacCtx(NULL));
#endif
    wolfSSL_SetGenPreMasterCtx(NULL, p);
    wolfSSL_SetGenMasterSecretCtx(NULL, p);
    wolfSSL_SetGenSessionKeyCtx(NULL, p);
    wolfSSL_SetEncryptKeysCtx(NULL, p);
    wolfSSL_SetTlsFinishedCtx(NULL, p);
#if !defined(WOLFSSL_NO_TLS12) && !defined(WOLFSSL_AEAD_ONLY)
    wolfSSL_SetVerifyMacCtx(NULL, p);
#endif
    wolfSSL_CTX_SetGenPreMasterCb(NULL, NULL);
    wolfSSL_CTX_SetGenMasterSecretCb(NULL, NULL);
    wolfSSL_CTX_SetGenSessionKeyCb(NULL, NULL);
    wolfSSL_CTX_SetEncryptKeysCb(NULL, NULL);
    wolfSSL_CTX_SetTlsFinishedCb(NULL, NULL);
#if !defined(WOLFSSL_NO_TLS12) && !defined(WOLFSSL_AEAD_ONLY)
    wolfSSL_CTX_SetVerifyMacCb(NULL, NULL);
#endif

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* Nothing stored yet. */
    ExpectNull(wolfSSL_GetGenPreMasterCtx(ssl));
    ExpectNull(wolfSSL_GetGenMasterSecretCtx(ssl));
    ExpectNull(wolfSSL_GetGenSessionKeyCtx(ssl));
    ExpectNull(wolfSSL_GetEncryptKeysCtx(ssl));
    ExpectNull(wolfSSL_GetTlsFinishedCtx(ssl));
#if !defined(WOLFSSL_NO_TLS12) && !defined(WOLFSSL_AEAD_ONLY)
    ExpectNull(wolfSSL_GetVerifyMacCtx(ssl));
#endif

    /* Each pair round-trips the pointer it was given. */
    wolfSSL_SetGenPreMasterCtx(ssl, p);
    ExpectPtrEq(wolfSSL_GetGenPreMasterCtx(ssl), p);
    wolfSSL_SetGenMasterSecretCtx(ssl, p);
    ExpectPtrEq(wolfSSL_GetGenMasterSecretCtx(ssl), p);
    wolfSSL_SetGenSessionKeyCtx(ssl, p);
    ExpectPtrEq(wolfSSL_GetGenSessionKeyCtx(ssl), p);
    wolfSSL_SetEncryptKeysCtx(ssl, p);
    ExpectPtrEq(wolfSSL_GetEncryptKeysCtx(ssl), p);
    wolfSSL_SetTlsFinishedCtx(ssl, p);
    ExpectPtrEq(wolfSSL_GetTlsFinishedCtx(ssl), p);
#if !defined(WOLFSSL_NO_TLS12) && !defined(WOLFSSL_AEAD_ONLY)
    wolfSSL_SetVerifyMacCtx(ssl, p);
    ExpectPtrEq(wolfSSL_GetVerifyMacCtx(ssl), p);
#endif

    /* The context-level callback setters accept a NULL callback. */
    wolfSSL_CTX_SetGenPreMasterCb(ctx, NULL);
    wolfSSL_CTX_SetGenMasterSecretCb(ctx, NULL);
    wolfSSL_CTX_SetGenSessionKeyCb(ctx, NULL);
    wolfSSL_CTX_SetEncryptKeysCb(ctx, NULL);
    wolfSSL_CTX_SetTlsFinishedCb(ctx, NULL);
#if !defined(WOLFSSL_NO_TLS12) && !defined(WOLFSSL_AEAD_ONLY)
    wolfSSL_CTX_SetVerifyMacCb(ctx, NULL);
#endif

    /* Not guarded on HAVE_EXTENDED_MASTER: these three are defined for the
     * whole of HAVE_PK_CALLBACKS and back onto fields that are unconditional
     * too, so they are reachable whether or not the extended master secret
     * is built in. */
    ExpectNull(wolfSSL_GetGenExtMasterSecretCtx(NULL));
    wolfSSL_SetGenExtMasterSecretCtx(NULL, p);
    wolfSSL_CTX_SetGenExtMasterSecretCb(NULL, NULL);
    ExpectNull(wolfSSL_GetGenExtMasterSecretCtx(ssl));
    wolfSSL_SetGenExtMasterSecretCtx(ssl, p);
    ExpectPtrEq(wolfSSL_GetGenExtMasterSecretCtx(ssl), p);
    wolfSSL_CTX_SetGenExtMasterSecretCb(ctx, NULL);

#ifdef WOLFSSL_TLS13
    ExpectNull(wolfSSL_GetHKDFExtractCtx(NULL));
    wolfSSL_SetHKDFExtractCtx(NULL, p);
    wolfSSL_CTX_SetHKDFExtractCb(NULL, NULL);
    ExpectNull(wolfSSL_GetHKDFExtractCtx(ssl));
    wolfSSL_SetHKDFExtractCtx(ssl, p);
    ExpectPtrEq(wolfSSL_GetHKDFExtractCtx(ssl), p);
    wolfSSL_CTX_SetHKDFExtractCb(ctx, NULL);
    wolfSSL_CTX_SetHKDFExpandLabelCb(NULL, NULL);
    wolfSSL_CTX_SetHKDFExpandLabelCb(ctx, NULL);
#endif

#ifdef WOLFSSL_PUBLIC_ASN
    wolfSSL_CTX_SetProcessPeerCertCb(NULL, NULL);
    wolfSSL_CTX_SetProcessPeerCertCb(ctx, NULL);
#endif
    wolfSSL_CTX_SetProcessServerSigKexCb(NULL, NULL);
    wolfSSL_CTX_SetProcessServerSigKexCb(ctx, NULL);
    wolfSSL_CTX_SetPerformTlsRecordProcessingCb(NULL, NULL);
    wolfSSL_CTX_SetPerformTlsRecordProcessingCb(ctx, NULL);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* Test that a static ECC key survives wolfSSL_set_accept_state().
 *
 * The check that the key is an EC key decodes it, so under
 * WOLFSSL_BLIND_PRIVATE_KEY it has to be unmasked first. Decoding the masked
 * bytes always fails, which silently withdrew the ECC capabilities for a key
 * that was perfectly good.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_set_accept_state_static_ecc(void)
{
    EXPECT_DECLS;
#if (defined(OPENSSL_EXTRA) || defined(WOLFSSL_EXTRA) || \
     defined(WOLFSSL_WPAS_SMALL)) && \
    defined(HAVE_ECC) && !defined(NO_TLS) && !defined(WOLFSSL_NO_TLS12) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && \
    defined(WOLFSSL_PEM_TO_DER)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    /* The key is only re-checked when a client object is switched to being a
     * server, so start from a client. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectIntEQ(wolfSSL_CTX_use_certificate_file(ctx, eccCertFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx, eccKeyFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        ssl->options.haveStaticECC = 1;
        ssl->options.haveECC = 1;
        ssl->options.haveECDSAsig = 1;

        wolfSSL_set_accept_state(ssl);

        /* The key really is an EC key, so nothing may be withdrawn. Without
         * unmasking, the decode fails and all three are cleared. */
        ExpectIntEQ(ssl->options.haveStaticECC, 1);
        ExpectIntEQ(ssl->options.haveECC, 1);
        ExpectIntEQ(ssl->options.haveECDSAsig, 1);
    }

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* Test the client-to-server switch in wolfSSL_set_accept_state().
 *
 * Switching a client object to act as a server re-checks a static ECC key and
 * adopts any DH parameters the context has since acquired. A key that is not
 * an EC key must clear the ECC capability flags rather than be trusted.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_set_accept_state_reinit(void)
{
    EXPECT_DECLS;
#if (defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)) \
    && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) \
    && !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && !defined(NO_TLS) \
    && !defined(WOLFSSL_NO_TLS12) && \
    defined(WOLFSSL_PEM_TO_DER)
/* Declared only when at least one of the cases below is built. */
#if defined(HAVE_ECC) || (!defined(NO_DH) && !defined(NO_RSA))
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
#endif

#if defined(HAVE_ECC) && !defined(NO_RSA)
    /* An RSA key cannot be decoded as an EC key, so the static ECC
     * capability must be withdrawn. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKeyFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    if (ssl != NULL) {
        ExpectNotNull(ssl->buffers.key);
        ssl->options.haveStaticECC = 1;
        ssl->options.haveECC = 1;
        ssl->options.haveECDSAsig = 1;

        wolfSSL_set_accept_state(ssl);

        ExpectIntEQ(ssl->options.haveStaticECC, 0);
        ExpectIntEQ(ssl->options.haveECC, 0);
        ExpectIntEQ(ssl->options.haveECDSAsig, 0);
        ExpectIntEQ(wolfSSL_is_server(ssl), 1);
    }

    wolfSSL_free(ssl);
    ssl = NULL;
    wolfSSL_CTX_free(ctx);
    ctx = NULL;
#endif /* HAVE_ECC && !NO_RSA */

#ifdef HAVE_ECC
    /* A real EC key decodes, so the flags are left alone. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx, eccKeyFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    if (ssl != NULL) {
        ssl->options.haveStaticECC = 1;
        ssl->options.haveECC = 1;

        wolfSSL_set_accept_state(ssl);

        ExpectIntEQ(ssl->options.haveStaticECC, 1);
        ExpectIntEQ(ssl->options.haveECC, 1);
    }

    wolfSSL_free(ssl);
    ssl = NULL;
    wolfSSL_CTX_free(ctx);
    ctx = NULL;
#endif /* HAVE_ECC */

#if !defined(NO_DH) && (!defined(NO_RSA) || defined(HAVE_ECC))
    /* DH parameters added to the context after the object was created are
     * picked up when the object becomes a server. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* Not inherited at creation time - the context had none then. */
    if (ssl != NULL) {
        ExpectIntEQ(ssl->options.haveDH, 0);
    }

    ExpectIntEQ(wolfSSL_CTX_SetTmpDH_file(ctx, dhParamFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);

    wolfSSL_set_accept_state(ssl);

    /* Picked up as the object's own copy, not the context's buffers. */
    if ((ssl != NULL) && (ctx != NULL)) {
        ExpectIntEQ(ssl->options.haveDH, 1);
        ExpectNotNull(ssl->buffers.serverDH_P.buffer);
        ExpectNotNull(ssl->buffers.serverDH_G.buffer);
        ExpectPtrNE(ssl->buffers.serverDH_P.buffer, ctx->serverDH_P.buffer);
        ExpectPtrNE(ssl->buffers.serverDH_G.buffer, ctx->serverDH_G.buffer);
        ExpectIntEQ(ssl->buffers.serverDH_P.length, ctx->serverDH_P.length);
        ExpectIntEQ(ssl->buffers.serverDH_G.length, ctx->serverDH_G.length);
        ExpectBufEQ(ssl->buffers.serverDH_P.buffer, ctx->serverDH_P.buffer,
            ctx->serverDH_P.length);
        ExpectBufEQ(ssl->buffers.serverDH_G.buffer, ctx->serverDH_G.buffer,
            ctx->serverDH_G.length);
    }

    wolfSSL_free(ssl);
    ssl = NULL;
    wolfSSL_CTX_free(ctx);
    ctx = NULL;
#endif /* !NO_DH */
#endif
    return EXPECT_RESULT();
}

/* Test the argument checks of wolfSSL_negotiate() and wolfSSL_connect_cert().
 *
 * Both reject a NULL object, each with its own failure code.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_negotiate_bad_args(void)
{
    EXPECT_DECLS;
#ifndef NO_TLS
    ExpectIntEQ(wolfSSL_negotiate(NULL), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
#if !defined(NO_WOLFSSL_CLIENT)
    ExpectIntEQ(wolfSSL_connect_cert(NULL), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
#endif
#endif
    return EXPECT_RESULT();
}

#if defined(WOLFSSL_QUIC) && defined(WOLFSSL_TLS13) && \
    (defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA)) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
/* QUIC callbacks that do nothing. wolfSSL_SSL_do_handshake() only needs the
 * method to be set so that the object counts as a QUIC one. */

/* QUIC callback that takes the traffic secrets and does nothing with them.
 *
 * @param [in] ssl    SSL/TLS object. Unused.
 * @param [in] level  Encryption level. Unused.
 * @param [in] rx     Secret for reading. Unused.
 * @param [in] tx     Secret for writing. Unused.
 * @param [in] len    Length of each secret. Unused.
 * @return  1 always.
 */
static int test_ssl_hs_quic_secrets(WOLFSSL* ssl,
    WOLFSSL_ENCRYPTION_LEVEL level, const uint8_t* rx, const uint8_t* tx,
    size_t len)
{
    (void)ssl;
    (void)level;
    (void)rx;
    (void)tx;
    (void)len;

    return 1;
}

/* QUIC callback that accepts handshake data and does nothing with it.
 *
 * @param [in] ssl    SSL/TLS object. Unused.
 * @param [in] level  Encryption level. Unused.
 * @param [in] data   Handshake data. Unused.
 * @param [in] len    Length of the data. Unused.
 * @return  1 always.
 */
static int test_ssl_hs_quic_add_data(WOLFSSL* ssl,
    WOLFSSL_ENCRYPTION_LEVEL level, const uint8_t* data, size_t len)
{
    (void)ssl;
    (void)level;
    (void)data;
    (void)len;

    return 1;
}

/* QUIC callback that reports the data as flushed without doing anything.
 *
 * @param [in] ssl  SSL/TLS object. Unused.
 * @return  1 always.
 */
static int test_ssl_hs_quic_flush(WOLFSSL* ssl)
{
    (void)ssl;

    return 1;
}

/* QUIC callback that accepts an alert and does nothing with it.
 *
 * @param [in] ssl    SSL/TLS object. Unused.
 * @param [in] level  Encryption level. Unused.
 * @param [in] err    Alert to send. Unused.
 * @return  1 always.
 */
static int test_ssl_hs_quic_alert(WOLFSSL* ssl,
    WOLFSSL_ENCRYPTION_LEVEL level, uint8_t err)
{
    (void)ssl;
    (void)level;
    (void)err;

    return 1;
}

static WOLFSSL_QUIC_METHOD test_ssl_hs_quic_method = {
    test_ssl_hs_quic_secrets,
    test_ssl_hs_quic_add_data,
    test_ssl_hs_quic_flush,
    test_ssl_hs_quic_alert
};
#endif

/* Test that wolfSSL_SSL_do_handshake() dispatches QUIC objects to the QUIC
 * handshake rather than to connect or accept.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_SSL_do_handshake_quic(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_QUIC) && defined(WOLFSSL_TLS13) && \
    (defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA)) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* Not a QUIC object yet. */
    if (ssl != NULL) {
        ExpectNull(ssl->quic.method);
    }

    ExpectIntEQ(wolfSSL_set_quic_method(ssl, &test_ssl_hs_quic_method),
        WOLFSSL_SUCCESS);
    if (ssl != NULL) {
        ExpectNotNull(ssl->quic.method);
    }

    /* The QUIC handshake is attempted. With no transport parameters set and
     * nothing to read it cannot complete, so only the dispatch is checked. */
    ExpectIntNE(wolfSSL_SSL_do_handshake(ssl), WOLFSSL_SUCCESS);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* Test that wolfSSL_set_connect_state() discards server DH parameters.
 *
 * A client generates its own DH parameters, so any server ones are dropped.
 * The object holds its own copy either way, whether set on it directly or
 * taken from the context, so the context is left untouched.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_set_connect_state_dh(void)
{
    EXPECT_DECLS;
#if (defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)) \
    && !defined(NO_DH) && !defined(NO_WOLFSSL_SERVER) \
    && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_FILESYSTEM) \
    && !defined(NO_CERTS) && !defined(NO_TLS) && !defined(NO_RSA) \
    && !defined(WOLFSSL_NO_TLS12) && \
    defined(WOLFSSL_PEM_TO_DER)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    WOLFSSL* ssl2 = NULL;

    /* Parameters owned by the object are freed. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method()));
    ExpectIntEQ(wolfSSL_CTX_use_certificate_file(ctx, svrCertFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKeyFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    ExpectIntEQ(wolfSSL_SetTmpDH_file(ssl, dhParamFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    if (ssl != NULL) {
        ExpectNotNull(ssl->buffers.serverDH_P.buffer);
        ExpectNotNull(ssl->buffers.serverDH_G.buffer);
        ExpectIntEQ(ssl->buffers.weOwnDH, 1);
    }

    wolfSSL_set_connect_state(ssl);

    /* Freed and unlinked; the object is now a client. */
    if (ssl != NULL) {
        ExpectNull(ssl->buffers.serverDH_P.buffer);
        ExpectNull(ssl->buffers.serverDH_G.buffer);
    }
    ExpectIntEQ(wolfSSL_is_server(ssl), 0);

    wolfSSL_free(ssl);
    ssl = NULL;
    wolfSSL_CTX_free(ctx);
    ctx = NULL;

    /* Parameters taken from the context are a copy the object owns. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method()));
    ExpectIntEQ(wolfSSL_CTX_use_certificate_file(ctx, svrCertFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKeyFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_SetTmpDH_file(ctx, dhParamFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* Copied from the context, so owned here. */
    if ((ssl != NULL) && (ctx != NULL)) {
        ExpectNotNull(ssl->buffers.serverDH_P.buffer);
        ExpectPtrNE(ssl->buffers.serverDH_P.buffer, ctx->serverDH_P.buffer);
        ExpectIntEQ(ssl->buffers.serverDH_P.length, ctx->serverDH_P.length);
        ExpectBufEQ(ssl->buffers.serverDH_P.buffer, ctx->serverDH_P.buffer,
            ctx->serverDH_P.length);
        ExpectIntEQ(ssl->buffers.weOwnDH, 1);
    }

    wolfSSL_set_connect_state(ssl);

    if (ssl != NULL) {
        ExpectNull(ssl->buffers.serverDH_P.buffer);
        ExpectNull(ssl->buffers.serverDH_G.buffer);
    }
    /* The context kept its own copy, so it can still be used. */
    if (ctx != NULL) {
        ExpectNotNull(ctx->serverDH_P.buffer);
        ExpectNotNull(ctx->serverDH_G.buffer);
    }
    ExpectNotNull(ssl2 = wolfSSL_new(ctx));
    if ((ssl2 != NULL) && (ctx != NULL)) {
        ExpectNotNull(ssl2->buffers.serverDH_P.buffer);
        ExpectPtrNE(ssl2->buffers.serverDH_P.buffer, ctx->serverDH_P.buffer);
        ExpectIntEQ(ssl2->buffers.serverDH_P.length, ctx->serverDH_P.length);
        ExpectBufEQ(ssl2->buffers.serverDH_P.buffer, ctx->serverDH_P.buffer,
            ctx->serverDH_P.length);
    }

    wolfSSL_free(ssl2);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* DH parameters taken from the context are the object's own copy, and they
 * last as long as the object does.
 *
 * The copy is what lets the context replace its parameters while sessions are
 * running. Since the session then holds the only copy it will ever have, the
 * end of a handshake must not take it away: a reused object needs it again.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_dh_ctx_params_reuse(void)
{
    EXPECT_DECLS;
/* Handing the object a second connection needs its certificate and key to
 * outlast the first handshake, which only these builds arrange. */
#if (defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(BUILD_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256) && \
    !defined(WOLFSSL_NO_TLS12) && !defined(NO_DH) && !defined(NO_RSA) && \
    !defined(NO_FILESYSTEM) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(NO_WOLFSSL_CLIENT)
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    const byte* startP = NULL;
    const byte* startG = NULL;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    test_ctx.c_ciphers = test_ctx.s_ciphers = "DHE-RSA-AES128-GCM-SHA256";

    /* The parameters go on the context before any session takes them. A
     * context made here is used as-is, so it gets the credentials and the
     * memio wiring that test_memio_setup would otherwise have given it. */
    ExpectNotNull(ctx_s = wolfSSL_CTX_new(wolfTLSv1_2_server_method()));
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx_s, svrKeyFile,
        CERT_FILETYPE), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_certificate_file(ctx_s, svrCertFile,
        CERT_FILETYPE), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_set_cipher_list(ctx_s, test_ctx.s_ciphers),
        WOLFSSL_SUCCESS);
    wolfSSL_SetIORecv(ctx_s, test_memio_read_cb);
    wolfSSL_SetIOSend(ctx_s, test_memio_write_cb);
    ExpectIntEQ(wolfSSL_CTX_SetTmpDH_file(ctx_s, dhParamFile, CERT_FILETYPE),
        WOLFSSL_SUCCESS);

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);

    /* test_memio_setup puts its own parameters on the server session, which
     * would stand in for the ones under test. Take a fresh session from the
     * same context so the parameters really are the context's. */
    wolfSSL_free(ssl_s);
    ssl_s = NULL;
    ExpectNotNull(ssl_s = wolfSSL_new(ctx_s));
    wolfSSL_SetIOWriteCtx(ssl_s, &test_ctx);
    wolfSSL_SetIOReadCtx(ssl_s, &test_ctx);

    /* Its own copy, matching the context's but not the same buffers. */
    if ((ssl_s != NULL) && (ctx_s != NULL)) {
        ExpectNotNull(ssl_s->buffers.serverDH_P.buffer);
        ExpectNotNull(ssl_s->buffers.serverDH_G.buffer);
        ExpectPtrNE(ssl_s->buffers.serverDH_P.buffer, ctx_s->serverDH_P.buffer);
        ExpectPtrNE(ssl_s->buffers.serverDH_G.buffer, ctx_s->serverDH_G.buffer);
        ExpectIntEQ(ssl_s->buffers.serverDH_P.length, ctx_s->serverDH_P.length);
        ExpectIntEQ(ssl_s->buffers.serverDH_G.length, ctx_s->serverDH_G.length);
        ExpectBufEQ(ssl_s->buffers.serverDH_P.buffer, ctx_s->serverDH_P.buffer,
            ctx_s->serverDH_P.length);
        ExpectBufEQ(ssl_s->buffers.serverDH_G.buffer, ctx_s->serverDH_G.buffer,
            ctx_s->serverDH_G.length);
        ExpectIntEQ(ssl_s->buffers.weOwnDH, 1);
        startP = ssl_s->buffers.serverDH_P.buffer;
        startG = ssl_s->buffers.serverDH_G.buffer;
    }

    /* Offering no FFDHE group keeps the server on the parameters it was
     * given, rather than switching to a named group and dropping them. A build
     * without supported curves sends no groups at all, so there is nothing to
     * narrow down. */
#ifdef HAVE_SUPPORTED_CURVES
    ExpectIntEQ(wolfSSL_UseSupportedCurve(ssl_c, WOLFSSL_ECC_SECP256R1),
        WOLFSSL_SUCCESS);
#endif

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* The handshake used them and the cleanup after it left them alone. */
    if (ssl_s != NULL) {
        ExpectPtrEq(ssl_s->buffers.serverDH_P.buffer, startP);
        ExpectPtrEq(ssl_s->buffers.serverDH_G.buffer, startG);
    }

    /* So the object can be handed a second connection. */
    ExpectIntEQ(wolfSSL_clear(ssl_s), WOLFSSL_SUCCESS);
    wolfSSL_free(ssl_c);
    ssl_c = NULL;
    ExpectNotNull(ssl_c = wolfSSL_new(ctx_c));
    wolfSSL_SetIOWriteCtx(ssl_c, &test_ctx);
    wolfSSL_SetIOReadCtx(ssl_c, &test_ctx);
#ifdef HAVE_SUPPORTED_CURVES
    ExpectIntEQ(wolfSSL_UseSupportedCurve(ssl_c, WOLFSSL_ECC_SECP256R1),
        WOLFSSL_SUCCESS);
#endif
    test_memio_clear_buffer(&test_ctx, 0);
    test_memio_clear_buffer(&test_ctx, 1);

    /* The second handshake ran on the parameters the first one left behind. */
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    if (ssl_s != NULL) {
        ExpectPtrEq(ssl_s->buffers.serverDH_P.buffer, startP);
        ExpectPtrEq(ssl_s->buffers.serverDH_G.buffer, startG);
    }

    /* And the context still has its own to hand out. */
    if (ctx_s != NULL) {
        ExpectNotNull(ctx_s->serverDH_P.buffer);
        ExpectNotNull(ctx_s->serverDH_G.buffer);
    }

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}


#if (defined(OPENSSL_EXTRA) || defined(WOLFSSL_EXTRA) || \
     defined(WOLFSSL_WPAS_SMALL)) && \
    !defined(NO_DH) && !defined(NO_RSA) && !defined(NO_FILESYSTEM) && \
    !defined(NO_CERTS) && !defined(NO_TLS) && !defined(WOLFSSL_NO_TLS12) && \
    !defined(NO_WOLFSSL_CLIENT) && defined(USE_WOLFSSL_MEMORY) && \
    !defined(WOLFSSL_NO_MALLOC) && !defined(WOLFSSL_STATIC_MEMORY)
#define TEST_DH_OOM

/* Makes every allocation fail, so the DH copy is certain to run out of
 * memory whichever allocations a build makes. */
static int dhOomFailAll = 0;
static int dhOomFailed = 0;

#ifdef WOLFSSL_DEBUG_MEMORY
static void* dhOomMalloc(size_t size, const char* func, unsigned int line)
{
    (void)func;
    (void)line;
#else
static void* dhOomMalloc(size_t size)
{
#endif
    if (dhOomFailAll) {
        dhOomFailed = 1;
        return NULL;
    }
    return malloc(size);
}

#ifdef WOLFSSL_DEBUG_MEMORY
static void dhOomFree(void* ptr, const char* func, unsigned int line)
{
    (void)func;
    (void)line;
#else
static void dhOomFree(void* ptr)
{
#endif
    free(ptr);
}

#ifdef WOLFSSL_DEBUG_MEMORY
static void* dhOomRealloc(void* ptr, size_t size, const char* func,
    unsigned int line)
{
    (void)func;
    (void)line;
#else
static void* dhOomRealloc(void* ptr, size_t size)
{
#endif
    if (dhOomFailAll) {
        dhOomFailed = 1;
        return NULL;
    }
    return realloc(ptr, size);
}
#endif /* TEST_DH_OOM */

/* Running out of memory while copying the context's DH parameters.
 *
 * wolfSSL_set_accept_state has nothing to report a failure through, so it
 * must leave the object without DH rather than claim parameters it does not
 * hold. Every allocation fails here rather than a chosen one: the call
 * reaches the copy whatever else runs out of memory, and only the copy
 * failing can leave haveDH clear.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_dh_ctx_params_oom(void)
{
    EXPECT_DECLS;
#ifdef TEST_DH_OOM
    wolfSSL_Malloc_cb  prevM = NULL;
    wolfSSL_Free_cb    prevF = NULL;
    wolfSSL_Realloc_cb prevR = NULL;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    /* The parameters reach the context after the object is made, so the
     * object has none of its own to lose. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectIntEQ(wolfSSL_CTX_use_certificate_file(ctx, svrCertFile,
        CERT_FILETYPE), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKeyFile,
        CERT_FILETYPE), WOLFSSL_SUCCESS);
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(wolfSSL_CTX_SetTmpDH_file(ctx, dhParamFile, CERT_FILETYPE),
        WOLFSSL_SUCCESS);
    if (ssl != NULL) {
        ExpectIntEQ(ssl->options.haveDH, 0);
        ExpectNull(ssl->buffers.serverDH_P.buffer);
    }

    ExpectIntEQ(wolfSSL_GetAllocators(&prevM, &prevF, &prevR), 0);
    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(wolfSSL_SetAllocators(dhOomMalloc, dhOomFree,
            dhOomRealloc), 0);
        dhOomFailed = 0;
        dhOomFailAll = 1;
        wolfSSL_set_accept_state(ssl);
        dhOomFailAll = 0;
        (void)wolfSSL_SetAllocators(prevM, prevF, prevR);
    }

    ExpectIntEQ(dhOomFailed, 1);
    if (ssl != NULL) {
        ExpectIntEQ(ssl->options.haveDH, 0);
        ExpectNull(ssl->buffers.serverDH_P.buffer);
        ExpectNull(ssl->buffers.serverDH_G.buffer);
    }
    /* The context kept its own, so a later object still gets them. */
    if (ctx != NULL) {
        ExpectNotNull(ctx->serverDH_P.buffer);
        ExpectNotNull(ctx->serverDH_G.buffer);
    }

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* The helpers below only install I/O callbacks, so they need nothing beyond
 * TLS 1.2 itself. The guard is nevertheless the union of their six callers'
 * guards, so the block is neither compiled without a caller nor missing when
 * one is present. The first term covers the five callers that drive a
 * handshake with real credentials; the second covers the memio caller, which
 * runs without RSA when raw public keys are enabled. */
#if !defined(NO_TLS) && !defined(WOLFSSL_NO_TLS12) && \
    ((!defined(NO_CERTS) && !defined(NO_FILESYSTEM) && !defined(NO_RSA) && \
      defined(WOLFSSL_PEM_TO_DER)) || \
     (defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
      !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER)))
/* Transport send callback that always fails.
 *
 * Makes every handshake message send fail so that the error handling of each
 * step of wolfSSL_connect()/wolfSSL_accept() can be reached.
 *
 * @param [in] ssl  SSL/TLS object. Unused.
 * @param [in] buf  Data to send. Unused.
 * @param [in] sz   Length of data. Unused.
 * @param [in] ctx  I/O context. Unused.
 * @return  WOLFSSL_CBIO_ERR_GENERAL always.
 */
static int test_ssl_hs_send_fail(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    (void)ssl;
    (void)buf;
    (void)sz;
    (void)ctx;

    return WOLFSSL_CBIO_ERR_GENERAL;
}

#if !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && !defined(NO_RSA) && \
    defined(WOLFSSL_PEM_TO_DER)
/* Fail every send, recording the content type of the first record offered.
 *
 * The first byte of a TLS record is its content type, so this reports what
 * the object tried to send first: 'alert' when a pending alert was retried,
 * 'handshake' when it went straight on with the handshake instead. Without
 * this the two are indistinguishable - both fail the send and both record
 * SOCKET_ERROR_E.
 *
 * @param [in]      ssl  SSL/TLS object. Unused.
 * @param [in]      buf  Record being sent.
 * @param [in]      sz   Length of buf in bytes.
 * @param [in, out] ctx  int holding the first content type seen. Must be set
 *                       to a value no content type uses before the call.
 * @return  WOLFSSL_CBIO_ERR_GENERAL always.
 */
static int test_ssl_hs_send_fail_record(WOLFSSL* ssl, char* buf, int sz,
    void* ctx)
{
    int* first = (int*)ctx;

    (void)ssl;

    if ((first != NULL) && (*first < 0) && (sz > 0)) {
        *first = (int)(unsigned char)buf[0];
    }

    return WOLFSSL_CBIO_ERR_GENERAL;
}
#endif /* !NO_CERTS && !NO_FILESYSTEM && !NO_RSA && WOLFSSL_PEM_TO_DER */

/* Transport receive callback that always fails.
 *
 * @param [in] ssl  SSL/TLS object. Unused.
 * @param [in] buf  Buffer to fill. Unused.
 * @param [in] sz   Size of buffer. Unused.
 * @param [in] ctx  I/O context. Unused.
 * @return  WOLFSSL_CBIO_ERR_GENERAL always.
 */
static int test_ssl_hs_recv_fail(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    (void)ssl;
    (void)buf;
    (void)sz;
    (void)ctx;

    return WOLFSSL_CBIO_ERR_GENERAL;
}

/* Require server credentials so that the checks in wolfSSL_accept() are made.
 *
 * Anonymous cipher suites are available by default in some builds and they let
 * a server run without a certificate, which skips the credential checks.
 *
 * Only used by the tests that need server credentials, so it is guarded to
 * match them rather than the callbacks above.
 *
 * @param [in, out] ssl  SSL/TLS object.
 */
#if !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    defined(WOLFSSL_PEM_TO_DER) && !defined(NO_CERTS) && \
    !defined(NO_FILESYSTEM) && !defined(NO_RSA)
static void test_ssl_hs_need_creds(WOLFSSL* ssl)
{
    if (ssl != NULL) {
    #ifdef HAVE_ANON
        ssl->options.useAnon = 0;
    #endif
    #ifndef NO_PSK
        ssl->options.havePSK = 0;
    #endif
    #ifdef WOLFSSL_MULTICAST
        ssl->options.haveMcast = 0;
    #endif
    }
}
#endif

/* Replace the transport of an object with one that always fails.
 *
 * Lets a handshake step be driven to its error handling without a peer and
 * without blocking on a socket.
 *
 * @param [in, out] ssl  SSL/TLS object.
 */
static void test_ssl_hs_break_io(WOLFSSL* ssl)
{
    if (ssl != NULL) {
        wolfSSL_SSLSetIOSend(ssl, test_ssl_hs_send_fail);
        wolfSSL_SSLSetIORecv(ssl, test_ssl_hs_recv_fail);
    }
}
#endif

/* Test the argument and side checks of wolfSSL_connect().
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_connect_bad_args(void)
{
    EXPECT_DECLS;
#if !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(NO_WOLFSSL_SERVER) && !defined(WOLFSSL_NO_TLS12) && \
    !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && !defined(NO_RSA) && \
    defined(WOLFSSL_PEM_TO_DER)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    /* A NULL object is rejected. */
    ExpectIntEQ(wolfSSL_connect(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Connecting with a server object is a side error. Credentials are loaded
     * because a server object cannot be created without them when there are no
     * anonymous cipher suites. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method()));
    ExpectIntEQ(wolfSSL_CTX_use_certificate_file(ctx, svrCertFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKeyFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    test_ssl_hs_break_io(ssl);
    ExpectIntEQ(wolfSSL_connect(ssl), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    ExpectIntEQ(wolfSSL_get_error(ssl, 0), WC_NO_ERR_TRACE(SIDE_ERROR));
    wolfSSL_free(ssl);
    ssl = NULL;
    wolfSSL_CTX_free(ctx);
    ctx = NULL;

    /* An unrecognized connect state is rejected. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    test_ssl_hs_break_io(ssl);
    if (ssl != NULL) {
        ssl->options.connectState = 0x7f;
        ExpectIntEQ(wolfSSL_connect(ssl), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    }

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* Test the argument, side and credential checks of wolfSSL_accept().
 *
 * A server needs both a certificate and a private key unless a certificate
 * setup callback is installed to supply them later.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_accept_bad_args(void)
{
    EXPECT_DECLS;
#if !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(NO_WOLFSSL_SERVER) && !defined(NO_CERTS) && \
    !defined(NO_FILESYSTEM) && !defined(NO_RSA) && !defined(WOLFSSL_NO_TLS12) \
    && defined(WOLFSSL_PEM_TO_DER)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    /* A NULL object is rejected. */
    ExpectIntEQ(wolfSSL_accept(NULL), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));

    /* Accepting with a client object is a side error. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    test_ssl_hs_break_io(ssl);
    ExpectIntEQ(wolfSSL_accept(ssl), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    ExpectIntEQ(wolfSSL_get_error(ssl, 0), WC_NO_ERR_TRACE(SIDE_ERROR));
    wolfSSL_free(ssl);
    ssl = NULL;
    wolfSSL_CTX_free(ctx);
    ctx = NULL;

    /* No certificate. It is hidden from the SSL object rather than left
     * unloaded, because a server object cannot be created without credentials
     * when there are no anonymous cipher suites. The pointer is put back
     * afterwards so that the object still disposes of it: depending on the
     * build the object owns this buffer rather than the context. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method()));
    ExpectIntEQ(wolfSSL_CTX_use_certificate_file(ctx, svrCertFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKeyFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    test_ssl_hs_break_io(ssl);
    test_ssl_hs_need_creds(ssl);
    if (ssl != NULL) {
        DerBuffer* savedCert = ssl->buffers.certificate;

        ssl->buffers.certificate = NULL;
        ExpectIntEQ(wolfSSL_accept(ssl), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
        ExpectIntEQ(wolfSSL_get_error(ssl, 0), WC_NO_ERR_TRACE(NO_PRIVATE_KEY));
        ssl->buffers.certificate = savedCert;
    }
    wolfSSL_free(ssl);
    ssl = NULL;
    wolfSSL_CTX_free(ctx);
    ctx = NULL;

    /* Certificate present but no private key. The key is dropped from the SSL
     * object rather than left unloaded so that the certificate check above is
     * passed first; the context still owns the real key. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method()));
    ExpectIntEQ(wolfSSL_CTX_use_certificate_file(ctx, svrCertFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKeyFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    test_ssl_hs_break_io(ssl);
    test_ssl_hs_need_creds(ssl);
    if (ssl != NULL) {
        DerBuffer* savedKey = ssl->buffers.key;
        int savedDevId = ssl->devId;

        ExpectNotNull(ssl->buffers.certificate);
        ssl->buffers.key = NULL;
        ssl->devId = INVALID_DEVID;
        ExpectIntEQ(wolfSSL_accept(ssl), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
        ExpectIntEQ(wolfSSL_get_error(ssl, 0), WC_NO_ERR_TRACE(NO_PRIVATE_KEY));
        /* Put both back so the object disposes of it as it would have. */
        ssl->buffers.key = savedKey;
        ssl->devId = savedDevId;
    }
    wolfSSL_free(ssl);
    ssl = NULL;
    wolfSSL_CTX_free(ctx);
    ctx = NULL;

    /* An unrecognized accept state is rejected. Credentials are loaded so the
     * checks above are passed. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method()));
    ExpectIntEQ(wolfSSL_CTX_use_certificate_file(ctx, svrCertFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKeyFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    test_ssl_hs_break_io(ssl);
    if (ssl != NULL) {
        ssl->options.acceptState = 0x7f;
        ExpectIntEQ(wolfSSL_accept(ssl), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    }

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* Test that each step of wolfSSL_connect() copes with a failing transport.
 *
 * The object is placed in each connect state in turn with a transport that
 * always fails, so that every step is entered. The call must reach a
 * definite outcome rather than hang; which error arm ran is not
 * observable from here. The object is
 * discarded after each attempt because a failed handshake is not resumable.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_connect_step_failures(void)
{
    EXPECT_DECLS;
#if !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(WOLFSSL_NO_TLS12) && !defined(NO_CERTS) && \
    !defined(NO_FILESYSTEM) && !defined(NO_RSA) && \
    defined(WOLFSSL_PEM_TO_DER)
    /* Each connect state, paired with whether it still has something to send.
     * One that does must fail on the broken transport; one that does not may
     * report success. Pairing them here rather than splitting the list at an
     * index means adding a state forces its expectation to be written down,
     * instead of silently shifting the boundary for its neighbours. */
    static const struct {
        int state;
        int sends;
    } states[] = {
        { CONNECT_BEGIN,        1 },
        { CLIENT_HELLO_SENT,    1 },
        { HELLO_AGAIN,          1 },
        { HELLO_AGAIN_REPLY,    1 },
        { FIRST_REPLY_DONE,     1 },
        { FIRST_REPLY_FIRST,    1 },
        { FIRST_REPLY_SECOND,   1 },
        { FIRST_REPLY_THIRD,    1 },
        { FIRST_REPLY_FOURTH,   1 },
        { FINISHED_DONE,        1 },
        { SECOND_REPLY_DONE,    0 }
    };
    int i;

    for (i = 0; i < (int)(sizeof(states) / sizeof(states[0])); i++) {
        WOLFSSL_CTX* ctx = NULL;
        WOLFSSL* ssl = NULL;
        int ret = 0;

        ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
        ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx, caCertFile, NULL),
            WOLFSSL_SUCCESS);
        ExpectNotNull(ssl = wolfSSL_new(ctx));
        test_ssl_hs_break_io(ssl);

        if (ssl != NULL) {
            /* Pretend the handshake reached this step, and that the peer was
             * authenticated so the fail-safe check is passed. A client
             * certificate is requested so the certificate steps are taken. */
            ssl->options.connectState = (byte)states[i].state;
            ssl->options.peerAuthGood = 1;
            ssl->options.sendVerify = SEND_CERT;
            ssl->options.resuming = 0;

            ret = wolfSSL_connect(ssl);

            /* A step that sends must fail on the broken transport; only a
             * state with nothing left to send may report success. Both arms
             * are cast as they come from different enumerations, which a C++
             * compiler will not mix in a conditional. */
            ExpectIntEQ(ret, states[i].sends ?
                (int)WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR) :
                (int)WOLFSSL_SUCCESS);
        }

        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
    }
#endif
    return EXPECT_RESULT();
}

/* Test that each step of wolfSSL_accept() copes with a failing transport.
 *
 * The object is placed in each accept state in turn with a transport that
 * always fails, so that every step is entered. The call must reach a
 * definite outcome rather than hang; which error arm ran is not
 * observable from here.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_accept_step_failures(void)
{
    EXPECT_DECLS;
#if !defined(NO_TLS) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(WOLFSSL_NO_TLS12) && !defined(NO_CERTS) && \
    !defined(NO_FILESYSTEM) && !defined(NO_RSA) && \
    defined(WOLFSSL_PEM_TO_DER)
    /* As in test_wolfSSL_connect_step_failures(): each state paired with
     * whether it still has something to send, so that adding one cannot
     * silently change what is expected of another. Only states the TLS 1.2
     * accept switch has a case for are listed - ACCEPT_HELLO_RETRY_REQUEST_DONE
     * and CERT_VERIFY_SENT belong to the TLS 1.3 machine and would exercise
     * the unrecognized-state path, which test_wolfSSL_accept_bad_args covers
     * directly. */
    static const struct {
        int state;
        int sends;
    } states[] = {
        { ACCEPT_BEGIN,                    1 },
        /* These two have a case only when their feature is built in.
         * Without it the state is unrecognized, which returns the same
         * value for a different reason, so they are left out rather than
         * appearing to cover a step that is not there. */
    #ifdef HAVE_SECURE_RENEGOTIATION
        { ACCEPT_BEGIN_RENEG,              1 },
    #endif
    #ifdef WOLFSSL_TLS13
        { ACCEPT_CLIENT_HELLO_DONE,        1 },
    #endif
        { ACCEPT_FIRST_REPLY_DONE,         1 },
        { SERVER_HELLO_SENT,               1 },
        { CERT_SENT,                       1 },
        { CERT_STATUS_SENT,                1 },
        { KEY_EXCHANGE_SENT,               1 },
        { CERT_REQ_SENT,                   1 },
        { SERVER_HELLO_DONE,               1 },
        { ACCEPT_SECOND_REPLY_DONE,        1 },
        { TICKET_SENT,                     1 },
        { CHANGE_CIPHER_SENT,              1 },
        { ACCEPT_FINISHED_DONE,            0 },
        { ACCEPT_THIRD_REPLY_DONE,         0 }
    };
    int i;

    for (i = 0; i < (int)(sizeof(states) / sizeof(states[0])); i++) {
        WOLFSSL_CTX* ctx = NULL;
        WOLFSSL* ssl = NULL;
        int ret = 0;

        ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method()));
        ExpectIntEQ(wolfSSL_CTX_use_certificate_file(ctx, svrCertFile,
            WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKeyFile,
            WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
        ExpectNotNull(ssl = wolfSSL_new(ctx));
        test_ssl_hs_break_io(ssl);

        if (ssl != NULL) {
            ssl->options.acceptState = (byte)states[i].state;
            /* Ask for a client certificate so the certificate request and
             * verify steps are taken. */
            ssl->options.verifyPeer = 1;
            ssl->options.sendVerify = SEND_CERT;
            /* Claim the client was authenticated so the fail-safe checks are
             * passed and the steps after them are reached. */
            ssl->options.peerAuthGood = 1;
        #ifdef HAVE_SESSION_TICKET
            /* Ask for a session ticket so that step is taken too. */
            ssl->options.createTicket = 1;
            ssl->options.noTicketTls12 = 0;
        #endif

            ret = wolfSSL_accept(ssl);

            /* A step that sends fails on the broken transport. The states at
             * the end of the handshake have nothing left to send and so
             * report success. Both arms are cast as they come from different
             * enumerations, which a C++ compiler will not mix in a
             * conditional. */
            ExpectIntEQ(ret, states[i].sends ?
                (int)WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR) :
                (int)WOLFSSL_SUCCESS);
        }

        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
    }
#endif
    return EXPECT_RESULT();
}

/* Test that a failure to flush the output buffer is reported.
 *
 * A send that reports "want write" leaves the message in the output buffer.
 * Failing the send on the next call makes the flush at the start of
 * wolfSSL_connect() and wolfSSL_accept() fail.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_hs_send_buffered_fail(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && !defined(NO_TLS) && \
    !defined(WOLFSSL_NO_TLS12) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(NO_WOLFSSL_SERVER)
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    /* Client: the ClientHello is left unsent. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    test_memio_simulate_want_write(&test_ctx, 1, 1);
    ExpectIntEQ(wolfSSL_connect(ssl_c), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    ExpectIntEQ(wolfSSL_get_error(ssl_c, 0), WOLFSSL_ERROR_WANT_WRITE);
    if (ssl_c != NULL) {
        ExpectIntGT(ssl_c->buffers.outputBuffer.length, 0);
    }
    /* The retry now fails outright. */
    test_ssl_hs_break_io(ssl_c);
    ExpectIntEQ(wolfSSL_connect(ssl_c), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    ExpectIntEQ(wolfSSL_get_error(ssl_c, 0), WC_NO_ERR_TRACE(SOCKET_ERROR_E));

    wolfSSL_free(ssl_c);
    ssl_c = NULL;
    wolfSSL_free(ssl_s);
    ssl_s = NULL;
    wolfSSL_CTX_free(ctx_c);
    ctx_c = NULL;
    wolfSSL_CTX_free(ctx_s);
    ctx_s = NULL;

    /* Server: the ClientHello is delivered so the server has a reply to send,
     * and that reply is left unsent. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(wolfSSL_connect(ssl_c), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    ExpectIntEQ(wolfSSL_get_error(ssl_c, 0), WOLFSSL_ERROR_WANT_READ);
    test_memio_simulate_want_write(&test_ctx, 0, 1);
    ExpectIntEQ(wolfSSL_accept(ssl_s), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    ExpectIntEQ(wolfSSL_get_error(ssl_s, 0), WOLFSSL_ERROR_WANT_WRITE);
    if (ssl_s != NULL) {
        ExpectIntGT(ssl_s->buffers.outputBuffer.length, 0);
    }
    test_ssl_hs_break_io(ssl_s);
    ExpectIntEQ(wolfSSL_accept(ssl_s), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    ExpectIntEQ(wolfSSL_get_error(ssl_s, 0), WC_NO_ERR_TRACE(SOCKET_ERROR_E));

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* Test that flushing a buffered message advances the handshake state.
 *
 * A send that reports "want write" leaves the message in the output buffer and
 * the state where it was, before the send. The flush at the start of the next
 * wolfSSL_connect() or wolfSSL_accept() gets the message out and steps the
 * state past that send, so the message is not built and sent a second time.
 * This is the success side of the failures covered by
 * test_wolfSSL_hs_send_buffered_fail().
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_hs_send_buffered_advance(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && !defined(NO_TLS) && \
    !defined(WOLFSSL_NO_TLS12) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(NO_WOLFSSL_SERVER)
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    int acceptState = -1;

    /* Client: the ClientHello is left unsent. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    test_memio_simulate_want_write(&test_ctx, 1, 1);
    ExpectIntEQ(wolfSSL_connect(ssl_c), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    ExpectIntEQ(wolfSSL_get_error(ssl_c, 0), WOLFSSL_ERROR_WANT_WRITE);
    if (ssl_c != NULL) {
        ExpectIntGT(ssl_c->buffers.outputBuffer.length, 0);
        /* The send did not complete, so the state is still before it. */
        ExpectIntEQ(ssl_c->options.connectState, CONNECT_BEGIN);
    }
    /* Nothing reached the peer. */
    ExpectIntEQ(test_ctx.s_msg_count, 0);

    /* With the transport working again the flush sends what was buffered and
     * steps the state past the send. */
    test_memio_simulate_want_write(&test_ctx, 1, 0);
    ExpectIntEQ(wolfSSL_connect(ssl_c), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    ExpectIntEQ(wolfSSL_get_error(ssl_c, 0), WOLFSSL_ERROR_WANT_READ);
    if (ssl_c != NULL) {
        ExpectIntEQ(ssl_c->options.connectState, CLIENT_HELLO_SENT);
        ExpectIntEQ(ssl_c->buffers.outputBuffer.length, 0);
    }
    /* Exactly one ClientHello was written: the state moved past the send, so
     * the message was not built again. Without the advance there would be
     * two. */
    ExpectIntEQ(test_ctx.s_msg_count, 1);

    /* The handshake carries on from there. */
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_c);
    ssl_c = NULL;
    wolfSSL_free(ssl_s);
    ssl_s = NULL;
    wolfSSL_CTX_free(ctx_c);
    ctx_c = NULL;
    wolfSSL_CTX_free(ctx_s);
    ctx_s = NULL;

    /* Server: the ClientHello is delivered so the server has a reply to send,
     * and that reply is left unsent. The accept side is the one where the
     * state to advance is chosen before the flush rather than after it. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(wolfSSL_connect(ssl_c), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    ExpectIntEQ(wolfSSL_get_error(ssl_c, 0), WOLFSSL_ERROR_WANT_READ);
    test_memio_simulate_want_write(&test_ctx, 0, 1);
    ExpectIntEQ(wolfSSL_accept(ssl_s), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    ExpectIntEQ(wolfSSL_get_error(ssl_s, 0), WOLFSSL_ERROR_WANT_WRITE);
    if (ssl_s != NULL) {
        ExpectIntGT(ssl_s->buffers.outputBuffer.length, 0);
        /* The send did not complete, so the state is still before it. How
         * far into its flight the server got before reaching the transport
         * depends on the build, so the state is recorded rather than
         * named. */
        acceptState = ssl_s->options.acceptState;
    }
    ExpectIntEQ(test_ctx.c_msg_count, 0);

    /* The flush sends what was buffered and steps the state past that send.
     * The rest of the flight follows, and the server then waits on the
     * client. */
    test_memio_simulate_want_write(&test_ctx, 0, 0);
    ExpectIntEQ(wolfSSL_accept(ssl_s), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    ExpectIntEQ(wolfSSL_get_error(ssl_s, 0), WOLFSSL_ERROR_WANT_READ);
    if (ssl_s != NULL) {
        ExpectIntGT(ssl_s->options.acceptState, acceptState);
    }

    /* Not advancing would rebuild and resend the message the flush had
     * already sent, leaving the client with a duplicate - which is what
     * completing the handshake here rules out. */
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

#if defined(WOLFSSL_CALLBACKS) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(NO_TLS) && !defined(WOLFSSL_NO_TLS12)
/* Timeout callback that does nothing.
 *
 * Supplying one is what makes wolfSSL_ex_wrapper() set up the timer.
 *
 * @param [in] info  Timeout information. Unused.
 * @return  0 always.
 */
static int test_ssl_hs_to_cb(TimeoutInfo* info)
{
    (void)info;
    return 0;
}
#endif

/* Test that connecting with no side established is reported as a failure.
 *
 * wolfSSL_ex_wrapper() dispatches on the side and leaves its result alone
 * when neither the client nor the server branch runs, so the failure it was
 * seeded with has to survive the timer setup that precedes the dispatch.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_connect_ex_no_side(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_CALLBACKS) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(NO_TLS) && !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    WOLFSSL_TIMEVAL timeout;

    /* Long enough that it cannot fire while the test runs. */
    timeout.tv_sec  = 60;
    timeout.tv_usec = 0;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        /* With a timeout callback the timer is set up first. Its success must
         * not be mistaken for the handshake's. */
        ssl->options.side = WOLFSSL_NEITHER_END;
        ExpectIntEQ(wolfSSL_connect_ex(ssl, NULL, test_ssl_hs_to_cb, timeout),
            WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
        /* And without one, where no timer is set up at all. */
        ssl->options.side = WOLFSSL_NEITHER_END;
        ExpectIntEQ(wolfSSL_connect_ex(ssl, NULL, NULL, timeout),
            WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    }

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* Test that a failure to send a pending alert is reported.
 *
 * An alert that could not be sent earlier is retried at the start of
 * wolfSSL_connect() and wolfSSL_accept().
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_hs_retry_alert_fail(void)
{
    EXPECT_DECLS;
#if !defined(NO_TLS) && !defined(WOLFSSL_NO_TLS12) && !defined(NO_CERTS) && \
    !defined(NO_FILESYSTEM) && !defined(NO_RSA) && \
    defined(WOLFSSL_PEM_TO_DER)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    int firstType;

#ifndef NO_WOLFSSL_CLIENT
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx, caCertFile, NULL),
        WOLFSSL_SUCCESS);
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    test_ssl_hs_break_io(ssl);
    firstType = -1;
    wolfSSL_SSLSetIOSend(ssl, test_ssl_hs_send_fail_record);
    wolfSSL_SetIOWriteCtx(ssl, &firstType);
    if (ssl != NULL) {
        ssl->pendingAlert.code = unexpected_message;
        ssl->pendingAlert.level = alert_fatal;
        ExpectIntEQ(wolfSSL_connect(ssl), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
        ExpectIntEQ(wolfSSL_get_error(ssl, 0),
            WC_NO_ERR_TRACE(SOCKET_ERROR_E));
        /* The pending alert is what it tried to send, not a ClientHello.
         * Both fail with SOCKET_ERROR_E, so only this separates them. */
        ExpectIntEQ(firstType, alert);
    }
    wolfSSL_free(ssl);
    ssl = NULL;
    wolfSSL_CTX_free(ctx);
    ctx = NULL;
#endif

#ifndef NO_WOLFSSL_SERVER
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method()));
    ExpectIntEQ(wolfSSL_CTX_use_certificate_file(ctx, svrCertFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKeyFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    test_ssl_hs_break_io(ssl);
    firstType = -1;
    wolfSSL_SSLSetIOSend(ssl, test_ssl_hs_send_fail_record);
    wolfSSL_SetIOWriteCtx(ssl, &firstType);
    if (ssl != NULL) {
        ssl->pendingAlert.code = unexpected_message;
        ssl->pendingAlert.level = alert_fatal;
        ExpectIntEQ(wolfSSL_accept(ssl), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
        ExpectIntEQ(wolfSSL_get_error(ssl, 0),
            WC_NO_ERR_TRACE(SOCKET_ERROR_E));
        ExpectIntEQ(firstType, alert);
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
#endif
    return EXPECT_RESULT();
}

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_HANDSHAKE_DONE_CB) && !defined(NO_TLS) && \
    !defined(WOLFSSL_NO_TLS12)
/* Handshake done callback that refuses to let the handshake complete.
 *
 * @param [in] ssl       SSL object. Unused.
 * @param [in] user_ctx  User context. Unused.
 * @return  A negative value to stop the handshake.
 */
static int test_ssl_hs_done_cb_fail(WOLFSSL* ssl, void* user_ctx)
{
    (void)ssl;
    (void)user_ctx;
    return -4242;
}
#endif

/* Test that a handshake done callback reporting an error stops the handshake.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_hs_done_cb_error(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_HANDSHAKE_DONE_CB) && !defined(NO_TLS) && \
    !defined(WOLFSSL_NO_TLS12)
    int i;

    /* Register the callback on the client and then on the server. */
    for (i = 0; i < 2; i++) {
        WOLFSSL_CTX* ctx_c = NULL;
        WOLFSSL_CTX* ctx_s = NULL;
        WOLFSSL* ssl_c = NULL;
        WOLFSSL* ssl_s = NULL;
        struct test_memio_ctx test_ctx;

        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
        ExpectIntEQ(wolfSSL_SetHsDoneCb((i == 0) ? ssl_c : ssl_s,
            test_ssl_hs_done_cb_fail, NULL), WOLFSSL_SUCCESS);

        /* The handshake cannot complete because the callback fails. */
        ExpectIntNE(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
        ExpectIntEQ(wolfSSL_get_error((i == 0) ? ssl_c : ssl_s, 0), -4242);

        wolfSSL_free(ssl_c);
        wolfSSL_free(ssl_s);
        wolfSSL_CTX_free(ctx_c);
        wolfSSL_CTX_free(ctx_s);
    }
#endif
    return EXPECT_RESULT();
}

#if defined(OPENSSL_EXTRA) && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_TLS) && !defined(WOLFSSL_NO_TLS12)
static int test_ssl_hs_info_calls_c = 0;
static int test_ssl_hs_info_calls_s = 0;

/* Information callback for the client, recording that it was called.
 *
 * @param [in] ssl   SSL object. Unused.
 * @param [in] type  Type of event. Unused.
 * @param [in] val   Value associated with event. Unused.
 */
static void test_ssl_hs_info_cb_c(const WOLFSSL* ssl, int type, int val)
{
    (void)ssl;
    (void)type;
    (void)val;
    test_ssl_hs_info_calls_c++;
}

/* Information callback for the server, recording that it was called.
 *
 * @param [in] ssl   SSL object. Unused.
 * @param [in] type  Type of event. Unused.
 * @param [in] val   Value associated with event. Unused.
 */
static void test_ssl_hs_info_cb_s(const WOLFSSL* ssl, int type, int val)
{
    (void)ssl;
    (void)type;
    (void)val;
    test_ssl_hs_info_calls_s++;
}
#endif

/* Test that the information callback is called when a handshake starts.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_hs_info_cb(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_TLS) && !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);

    test_ssl_hs_info_calls_c = 0;
    test_ssl_hs_info_calls_s = 0;
    wolfSSL_set_info_callback(ssl_c, test_ssl_hs_info_cb_c);
    wolfSSL_set_info_callback(ssl_s, test_ssl_hs_info_cb_s);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* Each side reported against its own callback. */
    ExpectIntGT(test_ssl_hs_info_calls_c, 0);
    ExpectIntGT(test_ssl_hs_info_calls_s, 0);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}
