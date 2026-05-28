/* test_session.c
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
#include <wolfssl/error-ssl.h>
#include <tests/api/api.h>
#include <tests/utils.h>
#include <tests/api/test_session.h>

/*----------------------------------------------------------------------------*/
/* WOLFSSL_CTX_add_session / session resumption                               */
/*----------------------------------------------------------------------------*/

#if defined(HAVE_IO_TESTS_DEPENDENCIES) && defined(HAVE_EXT_CACHE) && \
    !defined(SINGLE_THREADED) && defined(WOLFSSL_TLS13) && \
    !defined(NO_SESSION_CACHE)

/* Sessions to restore/store */
static WOLFSSL_SESSION* test_wolfSSL_CTX_add_session_client_sess;
static WOLFSSL_SESSION* test_wolfSSL_CTX_add_session_server_sess;
static WOLFSSL_CTX*     test_wolfSSL_CTX_add_session_server_ctx;

static void test_wolfSSL_CTX_add_session_ctx_ready(WOLFSSL_CTX* ctx)
{
    /* Don't store sessions. Lookup is still enabled. */
    AssertIntEQ(wolfSSL_CTX_set_session_cache_mode(ctx,
            WOLFSSL_SESS_CACHE_NO_INTERNAL_STORE), WOLFSSL_SUCCESS);
#ifdef OPENSSL_EXTRA
    AssertIntEQ(wolfSSL_CTX_get_session_cache_mode(ctx) &
            WOLFSSL_SESS_CACHE_NO_INTERNAL_STORE,
            WOLFSSL_SESS_CACHE_NO_INTERNAL_STORE);
#endif
    /* Require both peers to provide certs */
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
}

static void test_wolfSSL_CTX_add_session_on_result(WOLFSSL* ssl)
{
    WOLFSSL_SESSION** sess;
#ifdef WOLFSSL_MUTEX_INITIALIZER
    static wolfSSL_Mutex m = WOLFSSL_MUTEX_INITIALIZER(m);

    (void)wc_LockMutex(&m);
#endif
    if (wolfSSL_is_server(ssl))
        sess = &test_wolfSSL_CTX_add_session_server_sess;
    else
        sess = &test_wolfSSL_CTX_add_session_client_sess;
    if (*sess == NULL) {
#ifdef NO_SESSION_CACHE_REF
        *sess = wolfSSL_get1_session(ssl);
        AssertNotNull(*sess);
#else
        /* Test for backwards compatibility */
        if (wolfSSL_is_server(ssl)) {
            *sess = wolfSSL_get1_session(ssl);
            AssertNotNull(*sess);
        }
        else {
            *sess = wolfSSL_get_session(ssl);
            AssertNotNull(*sess);
        }
#endif
        /* Now save the session in the internal store to make it available
         * for lookup. For TLS 1.3, we can't save the session without
         * WOLFSSL_TICKET_HAVE_ID because there is no way to retrieve the
         * session from cache. */
        if (wolfSSL_is_server(ssl)
#ifndef WOLFSSL_TICKET_HAVE_ID
                && wolfSSL_version(ssl) != TLS1_3_VERSION
#endif
                )
            AssertIntEQ(wolfSSL_CTX_add_session(wolfSSL_get_SSL_CTX(ssl),
                    *sess), WOLFSSL_SUCCESS);
    }
    else {
        /* If we have a session retrieved then remaining connections should be
         * resuming on that session */
        AssertIntEQ(wolfSSL_session_reused(ssl), 1);
    }
#ifdef WOLFSSL_MUTEX_INITIALIZER
    wc_UnLockMutex(&m);
#endif

    /* Save CTX to be able to decrypt tickets */
    if (wolfSSL_is_server(ssl) &&
            test_wolfSSL_CTX_add_session_server_ctx == NULL) {
        test_wolfSSL_CTX_add_session_server_ctx = wolfSSL_get_SSL_CTX(ssl);
        AssertNotNull(test_wolfSSL_CTX_add_session_server_ctx);
        AssertIntEQ(wolfSSL_CTX_up_ref(wolfSSL_get_SSL_CTX(ssl)),
                WOLFSSL_SUCCESS);
    }
#if defined(SESSION_CERTS) && !defined(WOLFSSL_NO_CLIENT_AUTH)
#ifndef WOLFSSL_TICKET_HAVE_ID
    if (wolfSSL_version(ssl) != TLS1_3_VERSION &&
            wolfSSL_session_reused(ssl))
#endif
    {
        /* With WOLFSSL_TICKET_HAVE_ID the peer certs should be available
         * for all connections. TLS 1.3 only has tickets so if we don't
         * include the session id in the ticket then the certificates
         * will not be available on resumption. */
    #ifdef KEEP_PEER_CERT
        WOLFSSL_X509* peer = wolfSSL_get_peer_certificate(ssl);
        AssertNotNull(peer);
        wolfSSL_X509_free(peer);
    #endif
        AssertNotNull(wolfSSL_SESSION_get_peer_chain(*sess));
    #ifdef OPENSSL_EXTRA
        AssertNotNull(SSL_SESSION_get0_peer(*sess));
    #endif
    }
#endif /* SESSION_CERTS && !WOLFSSL_NO_CLIENT_AUTH */
}

static void test_wolfSSL_CTX_add_session_ssl_ready(WOLFSSL* ssl)
{
    /* Set the session to reuse for the client */
    AssertIntEQ(wolfSSL_set_session(ssl,
            test_wolfSSL_CTX_add_session_client_sess), WOLFSSL_SUCCESS);
}
#endif

int test_wolfSSL_CTX_add_session(void)
{
    EXPECT_DECLS;
#if defined(HAVE_IO_TESTS_DEPENDENCIES) && defined(HAVE_EXT_CACHE) && \
    !defined(SINGLE_THREADED) && defined(WOLFSSL_TLS13) && \
    !defined(NO_SESSION_CACHE)
    tcp_ready ready;
    func_args client_args;
    func_args server_args;
    THREAD_TYPE serverThread;
    callback_functions client_cb;
    callback_functions server_cb;
    method_provider methods[][2] = {
#if !defined(NO_OLD_TLS) && ((!defined(NO_AES) && !defined(NO_AES_CBC)) || \
        !defined(NO_DES3))
        /* Without AES there are almost no ciphersuites available. This leads
         * to no ciphersuites being available and an error. */
        { wolfTLSv1_1_client_method, wolfTLSv1_1_server_method },
#endif
#ifndef WOLFSSL_NO_TLS12
        { wolfTLSv1_2_client_method, wolfTLSv1_2_server_method },
#endif
        /* Needs the default ticket callback since it is tied to the
         * connection context and this makes it easy to carry over the ticket
         * crypto context between connections */
#if defined(WOLFSSL_TLS13) && !defined(WOLFSSL_NO_DEF_TICKET_ENC_CB) && \
    defined(HAVE_SESSION_TICKET)
        { wolfTLSv1_3_client_method, wolfTLSv1_3_server_method },
#endif
    };
    const size_t methodsLen = sizeof(methods)/sizeof(*methods);
    size_t i, j;

    for (i = 0; i < methodsLen; i++) {
        /* First run creates a connection while the second+ run will attempt
         * to resume the connection. The trick is that the internal cache
         * is turned off. wolfSSL_CTX_add_session should put the session in
         * the cache anyway. */
        test_wolfSSL_CTX_add_session_client_sess = NULL;
        test_wolfSSL_CTX_add_session_server_sess = NULL;
        test_wolfSSL_CTX_add_session_server_ctx = NULL;

#ifdef NO_SESSION_CACHE_REF
        for (j = 0; j < 4; j++) {
#else
        /* The session may be overwritten in this case. Do only one resumption
         * to stop this test from failing intermittently. */
        for (j = 0; j < 2; j++) {
#endif
#ifdef WOLFSSL_TIRTOS
            fdOpenSession(Task_self());
#endif

            StartTCP();
            InitTcpReady(&ready);

            XMEMSET(&client_args, 0, sizeof(func_args));
            XMEMSET(&server_args, 0, sizeof(func_args));

            XMEMSET(&client_cb, 0, sizeof(callback_functions));
            XMEMSET(&server_cb, 0, sizeof(callback_functions));
            client_cb.method  = methods[i][0];
            server_cb.method  = methods[i][1];

            server_args.signal    = &ready;
            server_args.callbacks = &server_cb;
            client_args.signal    = &ready;
            client_args.callbacks = &client_cb;

            if (test_wolfSSL_CTX_add_session_server_ctx != NULL) {
                server_cb.ctx = test_wolfSSL_CTX_add_session_server_ctx;
                server_cb.isSharedCtx = 1;
            }
            server_cb.ctx_ready = test_wolfSSL_CTX_add_session_ctx_ready;
            client_cb.ctx_ready = test_wolfSSL_CTX_add_session_ctx_ready;
            if (j != 0)
                client_cb.ssl_ready = test_wolfSSL_CTX_add_session_ssl_ready;
            server_cb.on_result = test_wolfSSL_CTX_add_session_on_result;
            client_cb.on_result = test_wolfSSL_CTX_add_session_on_result;
            server_cb.ticNoInit = 1; /* Use default builtin */

            start_thread(test_server_nofail, &server_args, &serverThread);
            wait_tcp_ready(&server_args);
            test_client_nofail(&client_args, NULL);
            join_thread(serverThread);

            ExpectTrue(client_args.return_code);
            ExpectTrue(server_args.return_code);

            FreeTcpReady(&ready);

            if (EXPECT_FAIL())
                break;
        }
        wolfSSL_SESSION_free(test_wolfSSL_CTX_add_session_client_sess);
        wolfSSL_SESSION_free(test_wolfSSL_CTX_add_session_server_sess);
        wolfSSL_CTX_free(test_wolfSSL_CTX_add_session_server_ctx);

        if (EXPECT_FAIL())
            break;
    }
#endif

    return EXPECT_RESULT();
}
#if defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) && defined(HAVE_EXT_CACHE) && \
     defined(WOLFSSL_TLS13) && !defined(NO_SESSION_CACHE) && \
     defined(OPENSSL_EXTRA) && defined(SESSION_CERTS) && \
     defined(HAVE_SESSION_TICKET) && \
    !defined(TITAN_SESSION_CACHE) && \
    !defined(HUGE_SESSION_CACHE) && \
    !defined(BIG_SESSION_CACHE) && \
    !defined(MEDIUM_SESSION_CACHE)

/* twcase - prefix for test_wolfSSL_CTX_add_session_ext */
/* Sessions to restore/store */
static WOLFSSL_SESSION* twcase_server_first_session_ptr;
static WOLFSSL_SESSION* twcase_client_first_session_ptr;
static WOLFSSL_CTX*     twcase_server_current_ctx_ptr;
static int twcase_new_session_called    = 0;
static int twcase_remove_session_called = 0;
static int twcase_get_session_called    = 0;

/* Test default, SESSIONS_PER_ROW*SESSION_ROWS = 3*11, see ssl.c */
#define SESSION_CACHE_SIZE 33

typedef struct {
    const byte* key;  /* key, altSessionID, session ID, NULL if empty */
    WOLFSSL_SESSION* value;
} hashTable_entry;

typedef struct {
    hashTable_entry entries[SESSION_CACHE_SIZE];  /* hash slots */
    size_t capacity;                     /* size of entries */
    size_t length;                       /* number of items in the hash table */
    wolfSSL_Mutex htLock;                /* lock */
}hashTable;

static hashTable server_sessionCache;

static int twcase_new_sessionCb(WOLFSSL *ssl, WOLFSSL_SESSION *sess)
{
    int i;
    unsigned int len;
    (void)ssl;

    /*
     * This example uses a hash table.
     * Steps you should take for a non-demo code:
     * - acquire a lock for the file named according to the session id
     * - open the file
     * - encrypt and write the SSL_SESSION object to the file
     * - release the lock
     *
     * Return:
     *  0: The callback does not wish to hold a reference of the sess
     *  1: The callback wants to hold a reference of the sess. The callback is
     *     now also responsible for calling wolfSSL_SESSION_free() on sess.
     */
    if (sess == NULL)
        return 0;

    if (wc_LockMutex(&server_sessionCache.htLock) != 0) {
        return 0;
    }
    for (i = 0; i < SESSION_CACHE_SIZE; i++) {
        if (server_sessionCache.entries[i].value == NULL) {
            server_sessionCache.entries[i].key = SSL_SESSION_get_id(sess, &len);
            server_sessionCache.entries[i].value = sess;
            server_sessionCache.length++;
            break;
        }
    }
    ++twcase_new_session_called;
    wc_UnLockMutex(&server_sessionCache.htLock);
    fprintf(stderr, "\t\ttwcase_new_session_called %d\n",
            twcase_new_session_called);
    return 1;
}

static void twcase_remove_sessionCb(WOLFSSL_CTX *ctx, WOLFSSL_SESSION *sess)
{
    int i;
    (void)ctx;
    (void)sess;

    if (sess == NULL)
        return;
    /*
     * This example uses a hash table.
     * Steps you should take for a non-demo code:
     * - acquire a lock for the file named according to the session id
     * - remove the file
     * - release the lock
     */
    if (wc_LockMutex(&server_sessionCache.htLock) != 0) {
        return;
    }
    for (i = 0; i < SESSION_CACHE_SIZE; i++) {
        if (server_sessionCache.entries[i].key != NULL &&
           XMEMCMP(server_sessionCache.entries[i].key,
                   sess->sessionID, SSL_MAX_SSL_SESSION_ID_LENGTH) == 0) {
            wolfSSL_SESSION_free(server_sessionCache.entries[i].value);
            server_sessionCache.entries[i].value = NULL;
            server_sessionCache.entries[i].key = NULL;
            server_sessionCache.length--;
            break;
        }
    }
    ++twcase_remove_session_called;
    wc_UnLockMutex(&server_sessionCache.htLock);
    fprintf(stderr, "\t\ttwcase_remove_session_called %d\n",
            twcase_remove_session_called);
}

static WOLFSSL_SESSION *twcase_get_sessionCb(WOLFSSL *ssl,
                                  const unsigned char *id, int len, int *ref)
{
    int i;
    (void)ssl;
    (void)id;
    (void)len;

    /*
     * This example uses a hash table.
     * Steps you should take for a non-demo code:
     * - acquire a lock for the file named according to the session id in the
     *   2nd arg
     * - read and decrypt contents of file and create a new SSL_SESSION
     * - object release the lock
     * - return the new session object
     */
    fprintf(stderr, "\t\ttwcase_get_session_called %d\n",
            ++twcase_get_session_called);
    /* This callback want to retain a copy of the object. If we want wolfSSL to
     * be responsible for the pointer then set to 0. */
    *ref = 1;

    for (i = 0; i < SESSION_CACHE_SIZE; i++) {
        if (server_sessionCache.entries[i].key != NULL &&
           XMEMCMP(server_sessionCache.entries[i].key, id,
                   SSL_MAX_SSL_SESSION_ID_LENGTH) == 0) {
           return server_sessionCache.entries[i].value;
        }
    }
    return NULL;
}
static int twcase_get_sessionCb_cleanup(void)
{
    int i;
    int cnt = 0;

    /* If  twcase_get_sessionCb sets *ref = 1, the application is responsible
     * for freeing sessions */

    for (i = 0; i < SESSION_CACHE_SIZE; i++) {
        if (server_sessionCache.entries[i].value != NULL) {
            wolfSSL_SESSION_free(server_sessionCache.entries[i].value);
            cnt++;
        }
    }

    fprintf(stderr, "\t\ttwcase_get_sessionCb_cleanup freed %d sessions\n",
            cnt);

    return TEST_SUCCESS;
}

static int twcase_cache_intOff_extOff(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;
    /* off - Disable internal cache */
    ExpectIntEQ(wolfSSL_CTX_set_session_cache_mode(ctx,
            WOLFSSL_SESS_CACHE_NO_INTERNAL_STORE), WOLFSSL_SUCCESS);
#ifdef OPENSSL_EXTRA
    ExpectIntEQ(wolfSSL_CTX_get_session_cache_mode(ctx) &
            WOLFSSL_SESS_CACHE_NO_INTERNAL_STORE,
            WOLFSSL_SESS_CACHE_NO_INTERNAL_STORE);
#endif
    /* off - Do not setup external cache */

    /* Require both peers to provide certs */
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    return EXPECT_RESULT();
}

static int twcase_cache_intOn_extOff(WOLFSSL_CTX* ctx)
{
    /* on - internal cache is on by default */
    /* off - Do not setup external cache */
    /* Require both peers to provide certs */
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    return TEST_SUCCESS;
}

static int twcase_cache_intOff_extOn(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;
    /* off - Disable internal cache */
    ExpectIntEQ(wolfSSL_CTX_set_session_cache_mode(ctx,
            WOLFSSL_SESS_CACHE_NO_INTERNAL_STORE), WOLFSSL_SUCCESS);
#ifdef OPENSSL_EXTRA
    ExpectIntEQ(wolfSSL_CTX_get_session_cache_mode(ctx) &
            WOLFSSL_SESS_CACHE_NO_INTERNAL_STORE,
            WOLFSSL_SESS_CACHE_NO_INTERNAL_STORE);
#endif
    /* on - Enable external cache */
    wolfSSL_CTX_sess_set_new_cb(ctx, twcase_new_sessionCb);
    wolfSSL_CTX_sess_set_remove_cb(ctx, twcase_remove_sessionCb);
    wolfSSL_CTX_sess_set_get_cb(ctx, twcase_get_sessionCb);

    /* Require both peers to provide certs */
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    return EXPECT_RESULT();
}

static int twcase_cache_intOn_extOn(WOLFSSL_CTX* ctx)
{
    /* on - internal cache is on by default */
    /* on - Enable external cache */
    wolfSSL_CTX_sess_set_new_cb(ctx, twcase_new_sessionCb);
    wolfSSL_CTX_sess_set_remove_cb(ctx, twcase_remove_sessionCb);
    wolfSSL_CTX_sess_set_get_cb(ctx, twcase_get_sessionCb);

    /* Require both peers to provide certs */
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    return TEST_SUCCESS;
}
static int twcase_cache_intOn_extOn_noTicket(WOLFSSL_CTX* ctx)
{
    /* on - internal cache is on by default */
    /* on - Enable external cache */
    wolfSSL_CTX_sess_set_new_cb(ctx, twcase_new_sessionCb);
    wolfSSL_CTX_sess_set_remove_cb(ctx, twcase_remove_sessionCb);
    wolfSSL_CTX_sess_set_get_cb(ctx, twcase_get_sessionCb);

    wolfSSL_CTX_set_options(ctx, WOLFSSL_OP_NO_TICKET);
    /* Require both peers to provide certs */
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    return TEST_SUCCESS;
}
static int twcase_server_sess_ctx_pre_shutdown(WOLFSSL* ssl)
{
    EXPECT_DECLS;
    WOLFSSL_SESSION** sess;
    if (wolfSSL_is_server(ssl))
        sess = &twcase_server_first_session_ptr;
    else
        return TEST_SUCCESS;

    if (*sess == NULL) {
        ExpectNotNull(*sess = wolfSSL_get1_session(ssl));
        /* Now save the session in the internal store to make it available
         * for lookup. For TLS 1.3, we can't save the session without
         * WOLFSSL_TICKET_HAVE_ID because there is no way to retrieve the
         * session from cache. */
        if (wolfSSL_is_server(ssl)
#ifndef WOLFSSL_TICKET_HAVE_ID
                && wolfSSL_version(ssl) != TLS1_3_VERSION
                && wolfSSL_version(ssl) != DTLS1_3_VERSION
#endif
                ) {
            ExpectIntEQ(wolfSSL_CTX_add_session(wolfSSL_get_SSL_CTX(ssl),
                    *sess), WOLFSSL_SUCCESS);
        }
    }
    /* Save CTX to be able to decrypt tickets */
    if (twcase_server_current_ctx_ptr == NULL) {
        ExpectNotNull(twcase_server_current_ctx_ptr = wolfSSL_get_SSL_CTX(ssl));
        ExpectIntEQ(wolfSSL_CTX_up_ref(wolfSSL_get_SSL_CTX(ssl)),
                    WOLFSSL_SUCCESS);
    }
#if defined(SESSION_CERTS) && !defined(WOLFSSL_NO_CLIENT_AUTH)
#ifndef WOLFSSL_TICKET_HAVE_ID
    if (wolfSSL_version(ssl) != TLS1_3_VERSION &&
            wolfSSL_session_reused(ssl))
#endif
    {
        /* With WOLFSSL_TICKET_HAVE_ID the peer certs should be available
         * for all connections. TLS 1.3 only has tickets so if we don't
         * include the session id in the ticket then the certificates
         * will not be available on resumption. */
    #ifdef KEEP_PEER_CERT
        WOLFSSL_X509* peer = NULL;
        ExpectNotNull(peer = wolfSSL_get_peer_certificate(ssl));
        wolfSSL_X509_free(peer);
    #endif
        ExpectNotNull(wolfSSL_SESSION_get_peer_chain(*sess));
    }
#endif
    return EXPECT_RESULT();
}

static int twcase_client_sess_ctx_pre_shutdown(WOLFSSL* ssl)
{
    EXPECT_DECLS;
    WOLFSSL_SESSION** sess;
    sess = &twcase_client_first_session_ptr;
    if (*sess == NULL) {
        ExpectNotNull(*sess = wolfSSL_get1_session(ssl));
    }
    else {
        /* If we have a session retrieved then remaining connections should be
         * resuming on that session */
        ExpectIntEQ(wolfSSL_session_reused(ssl), 1);
    }

#if defined(SESSION_CERTS) && !defined(WOLFSSL_NO_CLIENT_AUTH)
#ifndef WOLFSSL_TICKET_HAVE_ID
    if (wolfSSL_version(ssl) != TLS1_3_VERSION &&
            wolfSSL_session_reused(ssl))
#endif
    {
    #ifdef KEEP_PEER_CERT
        WOLFSSL_X509* peer = wolfSSL_get_peer_certificate(ssl);
        ExpectNotNull(peer);
        wolfSSL_X509_free(peer);
    #endif
        ExpectNotNull(wolfSSL_SESSION_get_peer_chain(*sess));
#ifdef OPENSSL_EXTRA
        ExpectNotNull(wolfSSL_SESSION_get0_peer(*sess));
#endif
    }
#endif
    return EXPECT_RESULT();
}
static int twcase_client_set_sess_ssl_ready(WOLFSSL* ssl)
{
    EXPECT_DECLS;
    /* Set the session to reuse for the client */
    ExpectNotNull(ssl);
    ExpectNotNull(twcase_client_first_session_ptr);
    ExpectIntEQ(wolfSSL_set_session(ssl,twcase_client_first_session_ptr),
                WOLFSSL_SUCCESS);
    return EXPECT_RESULT();
}

struct test_add_session_ext_params {
    method_provider client_meth;
    method_provider server_meth;
    const char* tls_version;
};

/* Marked WC_MAYBE_UNUSED: each registered test_wolfSSL_CTX_add_session_ext_*
 * variant below calls this helper, but each variant is gated on a specific
 * TLS/DTLS version combination. In builds where no version combination is
 * enabled, the helper is defined but unused. */
static WC_MAYBE_UNUSED int test_wolfSSL_CTX_add_session_ext(
    struct test_add_session_ext_params* param)
{
    EXPECT_DECLS;
    /* Test the default 33 sessions */
    int j;

    /* Clear cache before starting */
    wolfSSL_CTX_flush_sessions(NULL, -1);

    XMEMSET(&server_sessionCache, 0, sizeof(hashTable));
    if (wc_InitMutex(&server_sessionCache.htLock) != 0)
        return BAD_MUTEX_E;
    server_sessionCache.capacity = SESSION_CACHE_SIZE;

    fprintf(stderr, "\tBegin %s\n", param->tls_version);
    for (j = 0; j < 5; j++) {
        int tls13 = XSTRSTR(param->tls_version, "TLSv1_3") != NULL;
        int dtls = XSTRSTR(param->tls_version, "DTLS") != NULL;
        test_ssl_cbf client_cb;
        test_ssl_cbf server_cb;

        (void)dtls;

        /* Test five cache configurations */
        twcase_client_first_session_ptr = NULL;
        twcase_server_first_session_ptr = NULL;
        twcase_server_current_ctx_ptr = NULL;
        twcase_new_session_called    = 0;
        twcase_remove_session_called = 0;
        twcase_get_session_called    = 0;

        /* connection 1 - first connection */
        fprintf(stderr, "\tconnect: %s: j=%d\n", param->tls_version, j);

        XMEMSET(&client_cb, 0, sizeof(client_cb));
        XMEMSET(&server_cb, 0, sizeof(server_cb));
        client_cb.method  = param->client_meth;
        server_cb.method  = param->server_meth;

        if (dtls)
            client_cb.doUdp = server_cb.doUdp = 1;

        /* Setup internal and external cache */
        switch (j) {
            case 0:
                /* SSL_OP_NO_TICKET stateful ticket case */
                server_cb.ctx_ready = twcase_cache_intOn_extOn_noTicket;
                break;
            case 1:
                server_cb.ctx_ready = twcase_cache_intOn_extOn;
                break;
            case 2:
                server_cb.ctx_ready = twcase_cache_intOff_extOn;
                break;
            case 3:
                server_cb.ctx_ready = twcase_cache_intOn_extOff;
                break;
            case 4:
                server_cb.ctx_ready = twcase_cache_intOff_extOff;
                break;
        }
        client_cb.ctx_ready = twcase_cache_intOff_extOff;

        /* Add session to internal cache and save SSL session for testing */
        server_cb.on_result = twcase_server_sess_ctx_pre_shutdown;
        /* Save client SSL session for testing */
        client_cb.on_result = twcase_client_sess_ctx_pre_shutdown;
        server_cb.ticNoInit = 1; /* Use default builtin */
        /* Don't free/release ctx */
        server_cb.ctx = twcase_server_current_ctx_ptr;
        server_cb.isSharedCtx = 1;

        ExpectIntEQ(test_wolfSSL_client_server_nofail_memio(&client_cb,
            &server_cb, NULL), TEST_SUCCESS);

        ExpectIntEQ(twcase_get_session_called, 0);
        if (EXPECT_FAIL()) {
            wolfSSL_SESSION_free(twcase_client_first_session_ptr);
            wolfSSL_SESSION_free(twcase_server_first_session_ptr);
            wolfSSL_CTX_free(twcase_server_current_ctx_ptr);
            break;
        }

        switch (j) {
            case 0:
            case 1:
            case 2:
                /* cache cannot be searched with out a connection */
                /* Add a new session */
                ExpectIntEQ(twcase_new_session_called, 1);
                /* In twcase_server_sess_ctx_pre_shutdown
                 * wolfSSL_CTX_add_session which evicts the existing session
                 * in cache and adds it back in */
                ExpectIntLE(twcase_remove_session_called, 1);
                break;
            case 3:
            case 4:
                /* no external cache  */
                ExpectIntEQ(twcase_new_session_called, 0);
                ExpectIntEQ(twcase_remove_session_called, 0);
                break;
        }

        /* connection 2 - session resume */
        fprintf(stderr, "\tresume: %s: j=%d\n", param->tls_version, j);
        twcase_new_session_called    = 0;
        twcase_remove_session_called = 0;
        twcase_get_session_called    = 0;
        server_cb.on_result = 0;
        client_cb.on_result = 0;
        server_cb.ticNoInit = 1; /* Use default builtin */

        server_cb.ctx = twcase_server_current_ctx_ptr;

        /* try session resumption */
        client_cb.ssl_ready = twcase_client_set_sess_ssl_ready;

        ExpectIntEQ(test_wolfSSL_client_server_nofail_memio(&client_cb,
            &server_cb, NULL), TEST_SUCCESS);

        /* Clear cache before checking */
        wolfSSL_CTX_flush_sessions(NULL, -1);

        switch (j) {
            case 0:
                if (tls13) {
                    /* (D)TLSv1.3 stateful case */
                    /* cache hit */
                    /* DTLS accesses cache once for stateless parsing and
                     * once for stateful parsing */
                    ExpectIntEQ(twcase_get_session_called, !dtls ? 1 : 2);

                    /* (D)TLSv1.3 creates a new ticket,
                     * updates both internal and external cache */
                    ExpectIntEQ(twcase_new_session_called, 1);
                    /* A new session ID is created for a new ticket */
                    ExpectIntEQ(twcase_remove_session_called, 2);

                }
                else {
                    /* non (D)TLSv1.3 case, no update */
                    /* DTLS accesses cache once for stateless parsing and
                     * once for stateful parsing */
#ifdef WOLFSSL_DTLS_NO_HVR_ON_RESUME
                    ExpectIntEQ(twcase_get_session_called, !dtls ? 1 : 2);
#else
                    ExpectIntEQ(twcase_get_session_called, 1);
#endif
                    ExpectIntEQ(twcase_new_session_called, 0);
                    /* Called on session added in
                     * twcase_server_sess_ctx_pre_shutdown */
                    ExpectIntEQ(twcase_remove_session_called, 1);
                }
                break;
            case 1:
                if (tls13) {
                    /* (D)TLSv1.3 case */
                    /* cache hit */
                    ExpectIntEQ(twcase_get_session_called, 1);
                    /* (D)TLSv1.3 creates a new ticket,
                     * updates both internal and external cache */
                    ExpectIntEQ(twcase_new_session_called, 1);
                    /* Called on session added in
                     * twcase_server_sess_ctx_pre_shutdown and by wolfSSL */
                    ExpectIntEQ(twcase_remove_session_called, 1);
                }
                else {
                    /* non (D)TLSv1.3 case */
                    /* cache hit */
                    /* DTLS accesses cache once for stateless parsing and
                     * once for stateful parsing */
#ifdef WOLFSSL_DTLS_NO_HVR_ON_RESUME
                    ExpectIntEQ(twcase_get_session_called, !dtls ? 1 : 2);
#else
                    ExpectIntEQ(twcase_get_session_called, 1);
#endif
                    ExpectIntEQ(twcase_new_session_called, 0);
                    /* Called on session added in
                     * twcase_server_sess_ctx_pre_shutdown */
                    ExpectIntEQ(twcase_remove_session_called, 1);
                }
                break;
            case 2:
                if (tls13) {
                    /* (D)TLSv1.3 case */
                    /* cache hit */
                    ExpectIntEQ(twcase_get_session_called, 1);
                    /* (D)TLSv1.3 creates a new ticket,
                     * updates both internal and external cache */
                    ExpectIntEQ(twcase_new_session_called, 1);
                    /* Called on session added in
                     * twcase_server_sess_ctx_pre_shutdown and by wolfSSL */
                    ExpectIntEQ(twcase_remove_session_called, 1);
                }
                else {
                    /* non (D)TLSv1.3 case */
                    /* cache hit */
                    /* DTLS accesses cache once for stateless parsing and
                     * once for stateful parsing */
#ifdef WOLFSSL_DTLS_NO_HVR_ON_RESUME
                    ExpectIntEQ(twcase_get_session_called, !dtls ? 1 : 2);
#else
                    ExpectIntEQ(twcase_get_session_called, 1);
#endif
                    ExpectIntEQ(twcase_new_session_called, 0);
                    /* Called on session added in
                     * twcase_server_sess_ctx_pre_shutdown */
                    ExpectIntEQ(twcase_remove_session_called, 1);
                }
                break;
            case 3:
            case 4:
                /* no external cache */
                ExpectIntEQ(twcase_get_session_called, 0);
                ExpectIntEQ(twcase_new_session_called, 0);
                ExpectIntEQ(twcase_remove_session_called, 0);
                break;
        }
        wolfSSL_SESSION_free(twcase_client_first_session_ptr);
        wolfSSL_SESSION_free(twcase_server_first_session_ptr);
        wolfSSL_CTX_free(twcase_server_current_ctx_ptr);

        if (EXPECT_FAIL())
            break;
    }
    twcase_get_sessionCb_cleanup();
    XMEMSET(&server_sessionCache.entries, 0,
            sizeof(server_sessionCache.entries));
    fprintf(stderr, "\tEnd %s\n", param->tls_version);

    wc_FreeMutex(&server_sessionCache.htLock);

    return EXPECT_RESULT();
}
#endif

int test_wolfSSL_CTX_add_session_ext_tls13(void)
{
    EXPECT_DECLS;
#if defined(HAVE_IO_TESTS_DEPENDENCIES) && defined(HAVE_EXT_CACHE) && \
     defined(WOLFSSL_TLS13) && !defined(NO_SESSION_CACHE) && \
     defined(OPENSSL_EXTRA) && defined(SESSION_CERTS) && \
     defined(HAVE_SESSION_TICKET) && \
    !defined(TITAN_SESSION_CACHE) && \
    !defined(HUGE_SESSION_CACHE) && \
    !defined(BIG_SESSION_CACHE) && \
    !defined(MEDIUM_SESSION_CACHE)
#if defined(WOLFSSL_TLS13) && !defined(WOLFSSL_NO_DEF_TICKET_ENC_CB) && \
    defined(HAVE_SESSION_TICKET) && defined(WOLFSSL_TICKET_HAVE_ID)
    struct test_add_session_ext_params param[1] =  {
        { wolfTLSv1_3_client_method, wolfTLSv1_3_server_method, "TLSv1_3" }
    };
    ExpectIntEQ(test_wolfSSL_CTX_add_session_ext(param), TEST_SUCCESS);
#endif
#endif
    return EXPECT_RESULT();
}
int test_wolfSSL_CTX_add_session_ext_dtls13(void)
{
    EXPECT_DECLS;
#if defined(HAVE_IO_TESTS_DEPENDENCIES) && defined(HAVE_EXT_CACHE) && \
     defined(WOLFSSL_TLS13) && !defined(NO_SESSION_CACHE) && \
     defined(OPENSSL_EXTRA) && defined(SESSION_CERTS) && \
     defined(HAVE_SESSION_TICKET) && \
    !defined(TITAN_SESSION_CACHE) && \
    !defined(HUGE_SESSION_CACHE) && \
    !defined(BIG_SESSION_CACHE) && \
    !defined(MEDIUM_SESSION_CACHE)
#if defined(WOLFSSL_TLS13) && !defined(WOLFSSL_NO_DEF_TICKET_ENC_CB) && \
    defined(HAVE_SESSION_TICKET) && defined(WOLFSSL_TICKET_HAVE_ID)
#ifdef WOLFSSL_DTLS13
    struct test_add_session_ext_params param[1] =  {
        { wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method, "DTLSv1_3" }
    };
    ExpectIntEQ(test_wolfSSL_CTX_add_session_ext(param), TEST_SUCCESS);
#endif
#endif
#endif
    return EXPECT_RESULT();
}
int test_wolfSSL_CTX_add_session_ext_tls12(void)
{
    EXPECT_DECLS;
#if defined(HAVE_IO_TESTS_DEPENDENCIES) && defined(HAVE_EXT_CACHE) && \
     defined(WOLFSSL_TLS13) && !defined(NO_SESSION_CACHE) && \
     defined(OPENSSL_EXTRA) && defined(SESSION_CERTS) && \
     defined(HAVE_SESSION_TICKET) && \
    !defined(TITAN_SESSION_CACHE) && \
    !defined(HUGE_SESSION_CACHE) && \
    !defined(BIG_SESSION_CACHE) && \
    !defined(MEDIUM_SESSION_CACHE)
#ifndef WOLFSSL_NO_TLS12
    struct test_add_session_ext_params param[1] =  {
        { wolfTLSv1_2_client_method, wolfTLSv1_2_server_method, "TLSv1_2" }
    };
    ExpectIntEQ(test_wolfSSL_CTX_add_session_ext(param), TEST_SUCCESS);
#endif
#endif
    return EXPECT_RESULT();
}
int test_wolfSSL_CTX_add_session_ext_dtls12(void)
{
    EXPECT_DECLS;
#if defined(HAVE_IO_TESTS_DEPENDENCIES) && defined(HAVE_EXT_CACHE) && \
     defined(WOLFSSL_TLS13) && !defined(NO_SESSION_CACHE) && \
     defined(OPENSSL_EXTRA) && defined(SESSION_CERTS) && \
     defined(HAVE_SESSION_TICKET) && \
    !defined(TITAN_SESSION_CACHE) && \
    !defined(HUGE_SESSION_CACHE) && \
    !defined(BIG_SESSION_CACHE) && \
    !defined(MEDIUM_SESSION_CACHE)
#ifndef WOLFSSL_NO_TLS12
#ifdef WOLFSSL_DTLS
    struct test_add_session_ext_params param[1] =  {
        { wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method, "DTLSv1_2" }
    };
    ExpectIntEQ(test_wolfSSL_CTX_add_session_ext(param), TEST_SUCCESS);
#endif
#endif
#endif
    return EXPECT_RESULT();
}
int test_wolfSSL_CTX_add_session_ext_tls11(void)
{
    EXPECT_DECLS;
#if defined(HAVE_IO_TESTS_DEPENDENCIES) && defined(HAVE_EXT_CACHE) && \
     defined(WOLFSSL_TLS13) && !defined(NO_SESSION_CACHE) && \
     defined(OPENSSL_EXTRA) && defined(SESSION_CERTS) && \
     defined(HAVE_SESSION_TICKET) && \
    !defined(TITAN_SESSION_CACHE) && \
    !defined(HUGE_SESSION_CACHE) && \
    !defined(BIG_SESSION_CACHE) && \
    !defined(MEDIUM_SESSION_CACHE)
#if !defined(NO_OLD_TLS) && ((!defined(NO_AES) && !defined(NO_AES_CBC)) || \
        !defined(NO_DES3))
    struct test_add_session_ext_params param[1] =  {
        { wolfTLSv1_1_client_method, wolfTLSv1_1_server_method, "TLSv1_1" }
    };
    ExpectIntEQ(test_wolfSSL_CTX_add_session_ext(param), TEST_SUCCESS);
#endif
#endif
    return EXPECT_RESULT();
}
int test_wolfSSL_CTX_add_session_ext_dtls1(void)
{
    EXPECT_DECLS;
#if defined(HAVE_IO_TESTS_DEPENDENCIES) && defined(HAVE_EXT_CACHE) && \
     defined(WOLFSSL_TLS13) && !defined(NO_SESSION_CACHE) && \
     defined(OPENSSL_EXTRA) && defined(SESSION_CERTS) && \
     defined(HAVE_SESSION_TICKET) && \
    !defined(TITAN_SESSION_CACHE) && \
    !defined(HUGE_SESSION_CACHE) && \
    !defined(BIG_SESSION_CACHE) && \
    !defined(MEDIUM_SESSION_CACHE)
#if !defined(NO_OLD_TLS) && ((!defined(NO_AES) && !defined(NO_AES_CBC)) || \
        !defined(NO_DES3))
#ifdef WOLFSSL_DTLS
    struct test_add_session_ext_params param[1] =  {
        { wolfDTLSv1_client_method, wolfDTLSv1_server_method, "DTLSv1_0" }
    };
    ExpectIntEQ(test_wolfSSL_CTX_add_session_ext(param), TEST_SUCCESS);
#endif
#endif
#endif
    return EXPECT_RESULT();
}

/*----------------------------------------------------------------------------*/
/* WOLFSSL_SESSION, ticket keys and session removal callbacks                 */
/*----------------------------------------------------------------------------*/

int test_wolfSSL_SESSION(void)
{
    EXPECT_DECLS;
#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && \
    !defined(NO_RSA) && !defined(NO_SHA256) && \
    defined(HAVE_IO_TESTS_DEPENDENCIES) && !defined(NO_SESSION_CACHE)
    WOLFSSL*     ssl = NULL;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL_SESSION* sess = NULL;
    WOLFSSL_SESSION* sess_copy = NULL;
#ifdef OPENSSL_EXTRA
#ifdef HAVE_EXT_CACHE
    unsigned char* sessDer = NULL;
    unsigned char* ptr     = NULL;
    int sz = 0;
#endif
    const unsigned char context[] = "user app context";
    unsigned int contextSz = (unsigned int)sizeof(context);
#endif
    int ret = 0, err = 0;
    SOCKET_T sockfd;
    tcp_ready ready;
    func_args server_args;
    THREAD_TYPE serverThread;
    char msg[80];
    const char* sendGET = "GET";

    /* TLS v1.3 requires session tickets */
    /* CHACHA and POLY1305 required for myTicketEncCb */
#if !defined(WOLFSSL_NO_TLS12) && (!defined(WOLFSSL_TLS13) || \
    !(defined(HAVE_SESSION_TICKET) && ((defined(HAVE_CHACHA) && \
            defined(HAVE_POLY1305)) || defined(HAVE_AESGCM))))
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
#else
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
#endif

    ExpectTrue(wolfSSL_CTX_use_certificate_file(ctx, cliCertFile,
        CERT_FILETYPE));
    ExpectTrue(wolfSSL_CTX_use_PrivateKey_file(ctx, cliKeyFile,
        CERT_FILETYPE));
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx, caCertFile, 0),
        WOLFSSL_SUCCESS);
#ifdef WOLFSSL_ENCRYPTED_KEYS
    wolfSSL_CTX_set_default_passwd_cb(ctx, PasswordCallBack);
#endif
#ifdef HAVE_SESSION_TICKET
    /* Use session tickets, for ticket tests below */
    ExpectIntEQ(wolfSSL_CTX_UseSessionTicket(ctx), WOLFSSL_SUCCESS);
#endif

    XMEMSET(&server_args, 0, sizeof(func_args));
#ifdef WOLFSSL_TIRTOS
    fdOpenSession(Task_self());
#endif

    StartTCP();
    InitTcpReady(&ready);

    server_args.signal = &ready;
    start_thread(test_server_nofail, &server_args, &serverThread);
    wait_tcp_ready(&server_args);

    /* client connection */
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    tcp_connect(&sockfd, wolfSSLIP, ready.port, 0, 0, ssl);
    ExpectIntEQ(wolfSSL_set_fd(ssl, sockfd), WOLFSSL_SUCCESS);

    WOLFSSL_ASYNC_WHILE_PENDING(ret = wolfSSL_connect(ssl),
                                ret != WOLFSSL_SUCCESS);
    ExpectIntEQ(ret, WOLFSSL_SUCCESS);

    WOLFSSL_ASYNC_WHILE_PENDING(
        ret = wolfSSL_write(ssl, sendGET, (int)XSTRLEN(sendGET)),
        ret <= 0);
    ExpectIntEQ(ret, (int)XSTRLEN(sendGET));

    WOLFSSL_ASYNC_WHILE_PENDING(ret = wolfSSL_read(ssl, msg, sizeof(msg)),
                                ret != 23);
    ExpectIntEQ(ret, 23);

    ExpectPtrNE((sess = wolfSSL_get1_session(ssl)), NULL); /* ref count 1 */
    ExpectPtrNE((sess_copy = wolfSSL_get1_session(ssl)), NULL); /* ref count 2 */
    ExpectIntEQ(wolfSSL_SessionIsSetup(sess), 1);
#ifdef HAVE_EXT_CACHE
    ExpectPtrEq(sess, sess_copy); /* they should be the same pointer but without
                                   * HAVE_EXT_CACHE we get new objects each time */
#endif
    wolfSSL_SESSION_free(sess_copy); sess_copy = NULL;
    wolfSSL_SESSION_free(sess);      sess = NULL; /* free session ref */

    sess = wolfSSL_get_session(ssl);

#ifdef OPENSSL_EXTRA
    ExpectIntEQ(SSL_SESSION_is_resumable(NULL), 0);
    ExpectIntEQ(SSL_SESSION_is_resumable(sess), 1);

    ExpectIntEQ(wolfSSL_SESSION_has_ticket(NULL), 0);
    ExpectIntEQ(wolfSSL_SESSION_get_ticket_lifetime_hint(NULL), 0);
    #ifdef HAVE_SESSION_TICKET
    ExpectIntEQ(wolfSSL_SESSION_has_ticket(sess), 1);
    ExpectIntEQ(wolfSSL_SESSION_get_ticket_lifetime_hint(sess),
                SESSION_TICKET_HINT_DEFAULT);
    #else
    ExpectIntEQ(wolfSSL_SESSION_has_ticket(sess), 0);
    #endif
#else
    (void)sess;
#endif /* OPENSSL_EXTRA */

    /* Retain copy of the session for later testing */
    ExpectNotNull(sess = wolfSSL_get1_session(ssl));

    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl); ssl = NULL;

    CloseSocket(sockfd);

    join_thread(serverThread);

    FreeTcpReady(&ready);

#ifdef WOLFSSL_TIRTOS
    fdOpenSession(Task_self());
#endif

#if defined(SESSION_CERTS) && defined(OPENSSL_EXTRA)
    {
        X509 *x509 = NULL;
        char buf[30];
        int  bufSz = 0;

        ExpectNotNull(x509 = SSL_SESSION_get0_peer(sess));
        ExpectIntGT((bufSz = X509_NAME_get_text_by_NID(
            X509_get_subject_name(x509), NID_organizationalUnitName, buf,
            sizeof(buf))), 0);
        ExpectIntNE((bufSz == 7 || bufSz == 16), 0); /* should be one of these*/
        if (bufSz == 7) {
            ExpectIntEQ(XMEMCMP(buf, "Support", bufSz), 0);
        }
        if (bufSz == 16) {
            ExpectIntEQ(XMEMCMP(buf, "Programming-2048", bufSz), 0);
        }
    }
#endif

#ifdef HAVE_EXT_CACHE
    ExpectNotNull(sess_copy = wolfSSL_SESSION_dup(sess));
    wolfSSL_SESSION_free(sess_copy); sess_copy = NULL;
    sess_copy = NULL;
#endif

#if defined(OPENSSL_EXTRA) && defined(HAVE_EXT_CACHE)
    /* get session from DER and update the timeout */
    ExpectIntEQ(wolfSSL_i2d_SSL_SESSION(NULL, &sessDer), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntGT((sz = wolfSSL_i2d_SSL_SESSION(sess, &sessDer)), 0);
    wolfSSL_SESSION_free(sess); sess = NULL;
    sess = NULL;
    ptr = sessDer;
    ExpectNull(sess = wolfSSL_d2i_SSL_SESSION(NULL, NULL, sz));
    ExpectNotNull(sess = wolfSSL_d2i_SSL_SESSION(NULL,
                (const unsigned char**)&ptr, sz));
    XFREE(sessDer, NULL, DYNAMIC_TYPE_OPENSSL);
    sessDer = NULL;

    ExpectIntGT(wolfSSL_SESSION_get_time(sess), 0);
    ExpectIntEQ(wolfSSL_SSL_SESSION_set_timeout(sess, 500), SSL_SUCCESS);
#endif

    /* successful set session test */
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(wolfSSL_set_session(ssl, sess), WOLFSSL_SUCCESS);

#ifdef HAVE_SESSION_TICKET
    /* Test set/get session ticket */
    {
        const char* ticket = "This is a session ticket";
        char buf[64] = {0};
        word32 bufSz = (word32)sizeof(buf);
        word32 retSz = 0;

        ExpectIntEQ(WOLFSSL_SUCCESS,
            wolfSSL_set_SessionTicket(ssl, (byte *)ticket,
                (word32)XSTRLEN(ticket)));
        ExpectIntEQ(WOLFSSL_SUCCESS,
            wolfSSL_get_SessionTicket(ssl, (byte *)buf, &bufSz));
        ExpectStrEQ(ticket, buf);

        /* return ticket length if buffer parameter is null */
        wolfSSL_get_SessionTicket(ssl, NULL, &retSz);
        ExpectIntEQ(bufSz, retSz);
    }
#endif

#ifdef OPENSSL_EXTRA
    /* session timeout case */
    /* make the session to be expired */
    ExpectIntEQ(SSL_SESSION_set_timeout(sess,1), SSL_SUCCESS);
    XSLEEP_MS(1200);

    /* SSL_set_session should reject specified session but return success
     * if WOLFSSL_ERROR_CODE_OPENSSL macro is defined for OpenSSL compatibility.
     */
#if defined(WOLFSSL_ERROR_CODE_OPENSSL)
    ExpectIntEQ(wolfSSL_set_session(ssl,sess), SSL_SUCCESS);
#else
    ExpectIntEQ(wolfSSL_set_session(ssl,sess), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
#endif
    ExpectIntEQ(wolfSSL_SSL_SESSION_set_timeout(sess, 500), SSL_SUCCESS);

#ifdef WOLFSSL_SESSION_ID_CTX
    /* fail case with miss match session context IDs (use compatibility API) */
    ExpectIntEQ(SSL_set_session_id_context(ssl, context, contextSz),
            SSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_session(ssl, sess), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    wolfSSL_free(ssl); ssl = NULL;

    ExpectIntEQ(SSL_CTX_set_session_id_context(NULL, context, contextSz),
            WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(SSL_CTX_set_session_id_context(ctx, context, contextSz),
            SSL_SUCCESS);
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(wolfSSL_set_session(ssl, sess), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
#endif
#endif /* OPENSSL_EXTRA */

    wolfSSL_free(ssl);
    wolfSSL_SESSION_free(sess);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && \
    !defined(NO_RSA) && defined(HAVE_IO_TESTS_DEPENDENCIES) && \
    !defined(NO_SESSION_CACHE) && defined(OPENSSL_EXTRA) && \
    !defined(WOLFSSL_NO_TLS12)
static WOLFSSL_SESSION* test_wolfSSL_SESSION_expire_sess = NULL;

static void test_wolfSSL_SESSION_expire_downgrade_ctx_ready(WOLFSSL_CTX* ctx)
{
    #ifdef WOLFSSL_ERROR_CODE_OPENSSL
    /* returns previous timeout value */
    AssertIntEQ(wolfSSL_CTX_set_timeout(ctx, 1), 500);
    #else
    AssertIntEQ(wolfSSL_CTX_set_timeout(ctx, 1), WOLFSSL_SUCCESS);
    #endif
}


/* set the session to timeout in a second */
static void test_wolfSSL_SESSION_expire_downgrade_ssl_ready(WOLFSSL* ssl)
{
    AssertIntEQ(wolfSSL_set_timeout(ssl, 2), 1);
}


/* store the client side session from the first successful connection */
static void test_wolfSSL_SESSION_expire_downgrade_ssl_result(WOLFSSL* ssl)
{
    AssertPtrNE((test_wolfSSL_SESSION_expire_sess = wolfSSL_get1_session(ssl)),
        NULL); /* ref count 1 */
}


/* wait till session is expired then set it in the WOLFSSL struct for use */
static void test_wolfSSL_SESSION_expire_downgrade_ssl_ready_wait(WOLFSSL* ssl)
{
    AssertIntEQ(wolfSSL_set_timeout(ssl, 1), 1);
    AssertIntEQ(wolfSSL_set_session(ssl, test_wolfSSL_SESSION_expire_sess),
        WOLFSSL_SUCCESS);
    XSLEEP_MS(2000); /* wait 2 seconds for session to expire */
}


/* set expired session in the WOLFSSL struct for use */
static void test_wolfSSL_SESSION_expire_downgrade_ssl_ready_set(WOLFSSL* ssl)
{
    XSLEEP_MS(1200); /* wait a second for session to expire */

    /* set the expired session, call to set session fails but continuing on
       after failure should be handled here */
#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_ERROR_CODE_OPENSSL)
    AssertIntEQ(wolfSSL_set_session(ssl, test_wolfSSL_SESSION_expire_sess),
        WOLFSSL_SUCCESS);
#else
    AssertIntNE(wolfSSL_set_session(ssl, test_wolfSSL_SESSION_expire_sess),
        WOLFSSL_SUCCESS);
#endif
}


/* check that the expired session was not reused */
static void test_wolfSSL_SESSION_expire_downgrade_ssl_result_reuse(WOLFSSL* ssl)
{
    /* since the session has expired it should not have been reused */
    AssertIntEQ(wolfSSL_session_reused(ssl), 0);
}
#endif

int test_wolfSSL_SESSION_expire_downgrade(void)
{
    EXPECT_DECLS;
#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && \
    !defined(NO_RSA) && defined(HAVE_IO_TESTS_DEPENDENCIES) && \
    !defined(NO_SESSION_CACHE) && defined(OPENSSL_EXTRA) && \
    !defined(WOLFSSL_NO_TLS12)
    callback_functions server_cbf, client_cbf;

    XMEMSET(&server_cbf, 0, sizeof(callback_functions));
    XMEMSET(&client_cbf, 0, sizeof(callback_functions));

    /* force server side to use TLS 1.2 */
    server_cbf.method = wolfTLSv1_2_server_method;

    client_cbf.method = wolfSSLv23_client_method;
    server_cbf.ctx_ready = test_wolfSSL_SESSION_expire_downgrade_ctx_ready;
    client_cbf.ssl_ready = test_wolfSSL_SESSION_expire_downgrade_ssl_ready;
    client_cbf.on_result = test_wolfSSL_SESSION_expire_downgrade_ssl_result;

    test_wolfSSL_client_server_nofail(&client_cbf, &server_cbf);
    ExpectIntEQ(client_cbf.return_code, TEST_SUCCESS);
    ExpectIntEQ(server_cbf.return_code, TEST_SUCCESS);

    client_cbf.method = wolfSSLv23_client_method;
    server_cbf.ctx_ready = test_wolfSSL_SESSION_expire_downgrade_ctx_ready;
    client_cbf.ssl_ready = test_wolfSSL_SESSION_expire_downgrade_ssl_ready_wait;
    client_cbf.on_result =
        test_wolfSSL_SESSION_expire_downgrade_ssl_result_reuse;

    test_wolfSSL_client_server_nofail(&client_cbf, &server_cbf);
    ExpectIntEQ(client_cbf.return_code, TEST_SUCCESS);
    ExpectIntEQ(server_cbf.return_code, TEST_SUCCESS);

    client_cbf.method = wolfSSLv23_client_method;
    server_cbf.ctx_ready = test_wolfSSL_SESSION_expire_downgrade_ctx_ready;
    client_cbf.ssl_ready = test_wolfSSL_SESSION_expire_downgrade_ssl_ready_set;
    client_cbf.on_result =
        test_wolfSSL_SESSION_expire_downgrade_ssl_result_reuse;

    test_wolfSSL_client_server_nofail(&client_cbf, &server_cbf);
    ExpectIntEQ(client_cbf.return_code, TEST_SUCCESS);
    ExpectIntEQ(server_cbf.return_code, TEST_SUCCESS);

    wolfSSL_SESSION_free(test_wolfSSL_SESSION_expire_sess);
#endif
    return EXPECT_RESULT();
}

#if defined(OPENSSL_EXTRA) && defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(HAVE_EX_DATA) && !defined(NO_SESSION_CACHE)
#ifdef WOLFSSL_ATOMIC_OPS
    typedef wolfSSL_Atomic_Int SessRemCounter_t;
#else
    typedef int SessRemCounter_t;
#endif
static SessRemCounter_t clientSessRemCountMalloc;
static SessRemCounter_t serverSessRemCountMalloc;
static SessRemCounter_t clientSessRemCountFree;
static SessRemCounter_t serverSessRemCountFree;

static WOLFSSL_CTX* serverSessCtx = NULL;
static WOLFSSL_SESSION* serverSess = NULL;
#if (defined(WOLFSSL_TLS13) && defined(HAVE_SESSION_TICKET)) || \
        !defined(NO_SESSION_CACHE_REF)
static WOLFSSL_CTX* clientSessCtx = NULL;
static WOLFSSL_SESSION* clientSess = NULL;
#endif
static int serverSessRemIdx = 3;
static int sessRemCtx_Server = WOLFSSL_SERVER_END;
static int sessRemCtx_Client = WOLFSSL_CLIENT_END;

static void SessRemCtxCb(WOLFSSL_CTX *ctx, WOLFSSL_SESSION *sess)
{
    int* side;

    (void)ctx;

    side = (int*)SSL_SESSION_get_ex_data(sess, serverSessRemIdx);
    if (side != NULL) {
        if (*side == WOLFSSL_CLIENT_END)
            (void)wolfSSL_Atomic_Int_FetchAdd(&clientSessRemCountFree, 1);
        else
            (void)wolfSSL_Atomic_Int_FetchAdd(&serverSessRemCountFree, 1);

        SSL_SESSION_set_ex_data(sess, serverSessRemIdx, NULL);
    }
}

static int SessRemCtxSetupCb(WOLFSSL_CTX* ctx)
{
    SSL_CTX_sess_set_remove_cb(ctx, SessRemCtxCb);
#if defined(WOLFSSL_TLS13) && !defined(HAVE_SESSION_TICKET) && \
        !defined(NO_SESSION_CACHE_REF)
    {
        EXPECT_DECLS;
        /* Allow downgrade, set min version, and disable TLS 1.3.
         * Do this because without NO_SESSION_CACHE_REF we will want to return a
         * reference to the session cache. But with WOLFSSL_TLS13 and without
         * HAVE_SESSION_TICKET we won't have a session ID to be able to place
         * the session in the cache. In this case we need to downgrade to
         * previous versions to just use the legacy session ID field. */
        ExpectIntEQ(SSL_CTX_set_min_proto_version(ctx, SSL3_VERSION),
            SSL_SUCCESS);
        ExpectIntEQ(SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION),
            SSL_SUCCESS);
        return EXPECT_RESULT();
    }
#else
    return TEST_SUCCESS;
#endif
}

static int SessRemSslSetupCb(WOLFSSL* ssl)
{
    EXPECT_DECLS;
    int* side;

    if (SSL_is_server(ssl)) {
        side = &sessRemCtx_Server;
        (void)wolfSSL_Atomic_Int_FetchAdd(&serverSessRemCountMalloc, 1);
        ExpectNotNull(serverSess = SSL_get1_session(ssl));
        ExpectIntEQ(SSL_CTX_up_ref(serverSessCtx = SSL_get_SSL_CTX(ssl)),
                SSL_SUCCESS);
    }
    else {
        side = &sessRemCtx_Client;
        (void)wolfSSL_Atomic_Int_FetchAdd(&clientSessRemCountMalloc, 1);
#if (defined(WOLFSSL_TLS13) && defined(HAVE_SESSION_TICKET)) || \
    !defined(NO_SESSION_CACHE_REF)
        ExpectNotNull(clientSess = SSL_get1_session(ssl));
        ExpectIntEQ(SSL_CTX_up_ref(clientSessCtx = SSL_get_SSL_CTX(ssl)),
                SSL_SUCCESS);
#endif
    }
    ExpectIntEQ(SSL_SESSION_set_ex_data(SSL_get_session(ssl),
        serverSessRemIdx, side), SSL_SUCCESS);

    return EXPECT_RESULT();
}
#endif

int test_wolfSSL_CTX_sess_set_remove_cb(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(HAVE_EX_DATA) && !defined(NO_SESSION_CACHE)
    /* Check that the remove callback gets called for external data in a
     * session object */
    test_ssl_cbf func_cb;

    wolfSSL_Atomic_Int_Init(&clientSessRemCountMalloc, 0);
    wolfSSL_Atomic_Int_Init(&serverSessRemCountMalloc, 0);
    wolfSSL_Atomic_Int_Init(&clientSessRemCountFree, 0);
    wolfSSL_Atomic_Int_Init(&serverSessRemCountFree, 0);

    XMEMSET(&func_cb, 0, sizeof(func_cb));
    func_cb.ctx_ready = SessRemCtxSetupCb;
    func_cb.on_result = SessRemSslSetupCb;

    ExpectIntEQ(test_wolfSSL_client_server_nofail_memio(&func_cb, &func_cb,
        NULL), TEST_SUCCESS);

    /* Both should have been allocated */
    ExpectIntEQ(clientSessRemCountMalloc, 1);
    ExpectIntEQ(serverSessRemCountMalloc, 1);

    /* This should not be called yet. Session wasn't evicted from cache yet. */
    ExpectIntEQ(clientSessRemCountFree, 0);
#if (defined(WOLFSSL_TLS13) && defined(HAVE_SESSION_TICKET)) || \
        !defined(NO_SESSION_CACHE_REF)
    /* Force a cache lookup */
    ExpectNotNull(SSL_SESSION_get_ex_data(clientSess, serverSessRemIdx));
    /* Force a cache update */
    ExpectNotNull(SSL_SESSION_set_ex_data(clientSess, serverSessRemIdx - 1, 0));
    /* This should set the timeout to 0 and call the remove callback from within
     * the session cache. Returns 1 per OpenSSL semantics (session was
     * present in the cache and removed). */
    ExpectIntEQ(SSL_CTX_remove_session(clientSessCtx, clientSess), 1);
    ExpectNull(SSL_SESSION_get_ex_data(clientSess, serverSessRemIdx));
    ExpectIntEQ(clientSessRemCountFree, 1);
#endif
    /* Server session is in the cache so ex_data isn't free'd with the SSL
     * object */
    ExpectIntEQ(serverSessRemCountFree, 0);
    /* Force a cache lookup */
    ExpectNotNull(SSL_SESSION_get_ex_data(serverSess, serverSessRemIdx));
    /* Force a cache update */
    ExpectNotNull(SSL_SESSION_set_ex_data(serverSess, serverSessRemIdx - 1, 0));
    /* This should set the timeout to 0 and call the remove callback from within
     * the session cache. Returns 1 per OpenSSL semantics (session was
     * present in the cache and removed). */
    ExpectIntEQ(SSL_CTX_remove_session(serverSessCtx, serverSess), 1);
    ExpectNull(SSL_SESSION_get_ex_data(serverSess, serverSessRemIdx));
    ExpectIntEQ(serverSessRemCountFree, 1);
    /* Need to free the references that we kept */
    SSL_CTX_free(serverSessCtx);
    SSL_SESSION_free(serverSess);
#if (defined(WOLFSSL_TLS13) && defined(HAVE_SESSION_TICKET)) || \
        !defined(NO_SESSION_CACHE_REF)
    SSL_CTX_free(clientSessCtx);
    SSL_SESSION_free(clientSess);
#endif
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_ticket_keys(void)
{
    EXPECT_DECLS;
#if defined(HAVE_SESSION_TICKET) && !defined(WOLFSSL_NO_DEF_TICKET_ENC_CB) && \
    !defined(NO_WOLFSSL_SERVER) && !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;
    byte keys[WOLFSSL_TICKET_KEYS_SZ];

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_server_method()));

    ExpectIntEQ(wolfSSL_CTX_get_tlsext_ticket_keys(NULL, NULL, 0),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_CTX_get_tlsext_ticket_keys(ctx, NULL, 0),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_CTX_get_tlsext_ticket_keys(ctx, keys, 0),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_CTX_get_tlsext_ticket_keys(NULL, keys, 0),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_CTX_get_tlsext_ticket_keys(NULL, NULL, sizeof(keys)),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_CTX_get_tlsext_ticket_keys(ctx, NULL, sizeof(keys)),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_CTX_get_tlsext_ticket_keys(NULL, keys, sizeof(keys)),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

    ExpectIntEQ(wolfSSL_CTX_set_tlsext_ticket_keys(NULL, NULL, 0),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_CTX_set_tlsext_ticket_keys(ctx, NULL, 0),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_CTX_set_tlsext_ticket_keys(ctx, keys, 0),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_CTX_set_tlsext_ticket_keys(NULL, keys, 0),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_CTX_set_tlsext_ticket_keys(NULL, NULL, sizeof(keys)),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_CTX_set_tlsext_ticket_keys(ctx, NULL, sizeof(keys)),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_CTX_set_tlsext_ticket_keys(NULL, keys, sizeof(keys)),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

    ExpectIntEQ(wolfSSL_CTX_get_tlsext_ticket_keys(ctx, keys, sizeof(keys)),
                WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_set_tlsext_ticket_keys(ctx, keys, sizeof(keys)),
                WOLFSSL_SUCCESS);

    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/*----------------------------------------------------------------------------*/
/* SESSION ex_data new index                                                  */
/*----------------------------------------------------------------------------*/

#if defined(HAVE_EX_DATA_CRYPTO) && defined(OPENSSL_EXTRA)

#define SESSION_NEW_IDX_LONG 0xDEADBEEF
#define SESSION_NEW_IDX_VAL  ((void*)0xAEADAEAD)
#define SESSION_DUP_IDX_VAL  ((void*)0xDEDEDEDE)
#define SESSION_NEW_IDX_PTR  "Testing"

static void test_wolfSSL_SESSION_get_ex_new_index_new_cb(void* p, void* ptr,
        CRYPTO_EX_DATA* a, int idx, long argValue, void* arg)
{
    AssertNotNull(p);
    AssertNull(ptr);
    AssertIntEQ(CRYPTO_set_ex_data(a, idx, SESSION_NEW_IDX_VAL), SSL_SUCCESS);
    AssertIntEQ(argValue, SESSION_NEW_IDX_LONG);
    AssertStrEQ(arg, SESSION_NEW_IDX_PTR);
}

static int test_wolfSSL_SESSION_get_ex_new_index_dup_cb(CRYPTO_EX_DATA* out,
        const CRYPTO_EX_DATA* in, void* inPtr, int idx, long argV,
        void* arg)
{
    EXPECT_DECLS;

    ExpectNotNull(out);
    ExpectNotNull(in);
    ExpectPtrEq(*(void**)inPtr, SESSION_NEW_IDX_VAL);
    ExpectPtrEq(CRYPTO_get_ex_data(in, idx), SESSION_NEW_IDX_VAL);
    ExpectPtrEq(CRYPTO_get_ex_data(out, idx), SESSION_NEW_IDX_VAL);
    ExpectIntEQ(argV, SESSION_NEW_IDX_LONG);
    ExpectStrEQ(arg, SESSION_NEW_IDX_PTR);
    *(void**)inPtr = SESSION_DUP_IDX_VAL;
    if (EXPECT_SUCCESS()) {
        return SSL_SUCCESS;
    }
    else {
        return SSL_FAILURE;
    }
}

static int test_wolfSSL_SESSION_get_ex_new_index_free_cb_called = 0;
static void test_wolfSSL_SESSION_get_ex_new_index_free_cb(void* p, void* ptr,
        CRYPTO_EX_DATA* a, int idx, long argValue, void* arg)
{
    EXPECT_DECLS;

    ExpectNotNull(p);
    ExpectNull(ptr);
    ExpectPtrNE(CRYPTO_get_ex_data(a, idx), 0);
    ExpectIntEQ(argValue, SESSION_NEW_IDX_LONG);
    ExpectStrEQ(arg, SESSION_NEW_IDX_PTR);
    if (EXPECT_SUCCESS()) {
        test_wolfSSL_SESSION_get_ex_new_index_free_cb_called++;
    }
}

int test_wolfSSL_SESSION_get_ex_new_index(void)
{
    EXPECT_DECLS;
    int idx = SSL_SESSION_get_ex_new_index(SESSION_NEW_IDX_LONG,
                (void*)SESSION_NEW_IDX_PTR,
                test_wolfSSL_SESSION_get_ex_new_index_new_cb,
                test_wolfSSL_SESSION_get_ex_new_index_dup_cb,
                test_wolfSSL_SESSION_get_ex_new_index_free_cb);
    SSL_SESSION* s = SSL_SESSION_new();
    SSL_SESSION* d = NULL;

    ExpectNotNull(s);
    ExpectPtrEq(SSL_SESSION_get_ex_data(s, idx), SESSION_NEW_IDX_VAL);
    ExpectNotNull(d = SSL_SESSION_dup(s));
    ExpectPtrEq(SSL_SESSION_get_ex_data(d, idx), SESSION_DUP_IDX_VAL);
    SSL_SESSION_free(s);
    ExpectIntEQ(test_wolfSSL_SESSION_get_ex_new_index_free_cb_called, 1);
    SSL_SESSION_free(d);
    ExpectIntEQ(test_wolfSSL_SESSION_get_ex_new_index_free_cb_called, 2);

    crypto_ex_cb_free(crypto_ex_cb_ctx_session);
    crypto_ex_cb_ctx_session = NULL;
    return EXPECT_RESULT();
}
#else
int test_wolfSSL_SESSION_get_ex_new_index(void)
{
    return TEST_SKIPPED;
}
#endif
