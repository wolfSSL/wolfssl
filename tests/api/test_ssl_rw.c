/* test_ssl_rw.c
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
#include <tests/api/test_ssl_rw.h>

/* Tests for the application read/write APIs in src/ssl_api_rw.c (moved from
 * ssl.c). These cover functions not already exercised elsewhere in api.c. */

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && !defined(NO_TLS) && \
    !defined(USE_WINDOWS_API) && !defined(_WIN32) && !defined(NO_WRITEV) && \
    !defined(WOLFSSL_NO_TLS12)
/* Read exactly want bytes of application data from ssl into out.
 *
 * wolfSSL_read() returns at most one record's worth, so a payload larger than
 * a record needs several calls.
 *
 * @param [in, out] ssl   SSL/TLS object to read from.
 * @param [out]     out   Buffer to hold the data read.
 * @param [in]      want  Number of bytes expected.
 * @return  want on success.
 * @return  -1 when a read fails or returns no data.
 */
static int test_ssl_rw_read_all(WOLFSSL* ssl, byte* out, int want)
{
    int ret = want;
    int got = 0;

    while (got < want) {
        int rd = wolfSSL_read(ssl, out + got, want - got);

        if (rd <= 0) {
            ret = -1;
            break;
        }
        got += rd;
    }

    return ret;
}
#endif

/* Test wolfSSL_send().
 *
 * Covers parameter validation, that data written with socket flags reaches
 * the peer, and that the caller's write flags are restored afterwards.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_send(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) \
    && !defined(WOLFSSL_LEANPSK) && !defined(NO_TLS) \
    && !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    char msg[] = "hello wolfssl send";
    char reply[64];

    /* NULL SSL object is rejected before anything is sent. */
    ExpectIntEQ(wolfSSL_send(NULL, msg, (int)sizeof(msg), 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* NULL data and a negative length are rejected. */
    ExpectIntEQ(wolfSSL_send(ssl_c, NULL, (int)sizeof(msg), 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_send(ssl_c, msg, -1, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Mark the write flags so the restore can be observed. The memio write
     * callback ignores them, so any value is safe here. */
    if (ssl_c != NULL) {
        ssl_c->wflags = 0x5a;
    }

    /* Data sent with flags reaches the peer unchanged. */
    ExpectIntEQ(wolfSSL_send(ssl_c, msg, (int)sizeof(msg), 0),
        (int)sizeof(msg));
    XMEMSET(reply, 0, sizeof(reply));
    ExpectIntEQ(wolfSSL_recv(ssl_s, reply, (int)sizeof(reply), 0),
        (int)sizeof(msg));
    ExpectBufEQ(reply, msg, sizeof(msg));

    /* The caller's write flags are put back after the send. */
    if (ssl_c != NULL) {
        ExpectIntEQ(ssl_c->wflags, 0x5a);
    }

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* Test wolfSSL_writev().
 *
 * Covers the length overflow check, the stack/static gather buffer path, the
 * heap gather buffer path taken when the total exceeds FILE_BUFFER_SIZE, and
 * an empty vector.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_writev(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && !defined(NO_TLS) \
    && !defined(USE_WINDOWS_API) && !defined(_WIN32) && !defined(NO_WRITEV) \
    && !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    /* Enough to push the total past FILE_BUFFER_SIZE and onto the heap. */
    byte  msg[FILE_BUFFER_SIZE + 64];
    byte  reply[FILE_BUFFER_SIZE + 64];
    struct iovec iov[3];
    int   i;
    int   small_sz;
    int   large_sz;

    for (i = 0; i < (int)sizeof(msg); i++) {
        msg[i] = (byte)(i * 7 + 13);
    }

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* A total length that overflows is rejected. The buffers are never read
     * so the bogus length is safe. */
    iov[0].iov_base = msg;
    iov[0].iov_len  = (size_t)-1;
    iov[1].iov_base = msg;
    iov[1].iov_len  = 2;
    ExpectIntEQ(wolfSSL_writev(ssl_c, iov, 2), WC_NO_ERR_TRACE(BUFFER_E));

    /* Arguments are validated before anything is read from the object. */
    ExpectIntEQ(wolfSSL_writev(NULL, iov, 1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_writev(ssl_c, NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_writev(ssl_c, iov, -1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* An empty vector writes nothing and is not an error, with or without a
     * vector array. */
    ExpectIntEQ(wolfSSL_writev(ssl_c, iov, 0), 0);
    ExpectIntEQ(wolfSSL_writev(ssl_c, NULL, 0), 0);

    /* Segments totalling less than FILE_BUFFER_SIZE use the static buffer. */
    small_sz = 96;
    iov[0].iov_base = msg;
    iov[0].iov_len  = 32;
    iov[1].iov_base = msg + 32;
    iov[1].iov_len  = 32;
    iov[2].iov_base = msg + 64;
    iov[2].iov_len  = 32;
    ExpectIntEQ(wolfSSL_writev(ssl_c, iov, 3), small_sz);
    XMEMSET(reply, 0, sizeof(reply));
    ExpectIntEQ(test_ssl_rw_read_all(ssl_s, reply, small_sz), small_sz);
    ExpectBufEQ(reply, msg, small_sz);

    /* Segments totalling more than FILE_BUFFER_SIZE allocate from the heap. */
    large_sz = (int)sizeof(msg);
    iov[0].iov_base = msg;
    iov[0].iov_len  = 64;
    iov[1].iov_base = msg + 64;
    iov[1].iov_len  = (size_t)large_sz - 64;
    ExpectIntEQ(wolfSSL_writev(ssl_c, iov, 2), large_sz);
    XMEMSET(reply, 0, sizeof(reply));
    ExpectIntEQ(test_ssl_rw_read_all(ssl_s, reply, large_sz), large_sz);
    ExpectBufEQ(reply, msg, large_sz);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* Test wolfSSL_get_shutdown().
 *
 * Covers the NULL object case and each stage of a bidirectional shutdown:
 * nothing exchanged, close_notify sent, close_notify received, and the
 * completed shutdown.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_get_shutdown(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && !defined(NO_TLS) \
    && !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    char reply[16];

    /* NULL object reports no shutdown state. */
    ExpectIntEQ(wolfSSL_get_shutdown(NULL), 0);

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* Nothing has been sent or received on an open connection. */
    ExpectIntEQ(wolfSSL_get_shutdown(ssl_c), 0);
    ExpectIntEQ(wolfSSL_get_shutdown(ssl_s), 0);

    /* The client sends its close_notify but has not seen the peer's. */
    ExpectIntEQ(wolfSSL_shutdown(ssl_c), WOLFSSL_SHUTDOWN_NOT_DONE);
    ExpectIntEQ(wolfSSL_get_shutdown(ssl_c), WOLFSSL_SENT_SHUTDOWN);

    /* The server reads the alert and reports it as received. */
    ExpectIntEQ(wolfSSL_read(ssl_s, reply, (int)sizeof(reply)), 0);
    ExpectIntEQ(wolfSSL_get_shutdown(ssl_s), WOLFSSL_RECEIVED_SHUTDOWN);

    /* The server replies, completing the exchange on its side. */
    ExpectIntEQ(wolfSSL_shutdown(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_shutdown(ssl_s),
        WOLFSSL_SENT_SHUTDOWN | WOLFSSL_RECEIVED_SHUTDOWN);

    /* The client processes the reply and is done too. */
    ExpectIntEQ(wolfSSL_shutdown(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_shutdown(ssl_c),
        WOLFSSL_SENT_SHUTDOWN | WOLFSSL_RECEIVED_SHUTDOWN);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* Test wolfSSL_want(), wolfSSL_want_read() and wolfSSL_want_write().
 *
 * Drives the SSL object into a WANT_READ state (read with nothing to read)
 * and a WANT_WRITE state (write with the transport blocked) and checks what
 * each accessor reports.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_want(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && !defined(NO_TLS) \
    && !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    char msg[] = "hello wolfssl want";
    char reply[64];

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* A completed handshake leaves nothing outstanding. */
    ExpectIntEQ(wolfSSL_want_read(ssl_c), 0);
    ExpectIntEQ(wolfSSL_want_write(ssl_c), 0);
#ifdef OPENSSL_EXTRA
    ExpectIntEQ(wolfSSL_want(NULL), WOLFSSL_NOTHING);
    ExpectIntEQ(wolfSSL_want(ssl_c), WOLFSSL_NOTHING);
    /* The per-direction variants take NULL too. */
    ExpectIntEQ(wolfSSL_want_read(NULL), 0);
    ExpectIntEQ(wolfSSL_want_write(NULL), 0);
#endif

    /* Reading with no record available reports a wanted read. */
    ExpectIntLT(wolfSSL_read(ssl_c, reply, (int)sizeof(reply)), 0);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, 0), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(wolfSSL_want_read(ssl_c), 1);
    ExpectIntEQ(wolfSSL_want_write(ssl_c), 0);
#ifdef OPENSSL_EXTRA
    ExpectIntEQ(wolfSSL_want(ssl_c), WOLFSSL_READING);
#endif

    /* Writing with the transport blocked reports a wanted write. */
    test_memio_simulate_want_write(&test_ctx, 1, 1);
    ExpectIntLT(wolfSSL_write(ssl_c, msg, (int)sizeof(msg)), 0);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, 0), WOLFSSL_ERROR_WANT_WRITE);
    ExpectIntEQ(wolfSSL_want_write(ssl_c), 1);
    ExpectIntEQ(wolfSSL_want_read(ssl_c), 0);
#ifdef OPENSSL_EXTRA
    ExpectIntEQ(wolfSSL_want(ssl_c), WOLFSSL_WRITING);
#endif
    test_memio_simulate_want_write(&test_ctx, 1, 0);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* Test wolfSSL_pending() and wolfSSL_has_pending().
 *
 * Leaves part of a record undelivered by reading less than was written and
 * checks that both report the buffered remainder, then that draining it
 * clears the report.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_pending_api(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && !defined(NO_TLS) \
    && !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    byte msg[32];
    byte reply[32];
    int i;

    for (i = 0; i < (int)sizeof(msg); i++) {
        msg[i] = (byte)i;
    }

    /* NULL object is rejected by both. */
    ExpectIntEQ(wolfSSL_pending(NULL), WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_has_pending(NULL), WOLFSSL_FAILURE);

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* Nothing buffered on an idle connection. */
    ExpectIntEQ(wolfSSL_pending(ssl_c), 0);
    ExpectIntEQ(wolfSSL_has_pending(ssl_c), 0);

    /* Read less than the record holds - the rest stays buffered. */
    ExpectIntEQ(wolfSSL_write(ssl_s, msg, (int)sizeof(msg)),
        (int)sizeof(msg));
    ExpectIntEQ(wolfSSL_read(ssl_c, reply, 8), 8);
    ExpectBufEQ(reply, msg, 8);
    ExpectIntEQ(wolfSSL_pending(ssl_c), (int)sizeof(msg) - 8);
    ExpectIntEQ(wolfSSL_has_pending(ssl_c), 1);

    /* Draining the remainder clears the buffered data. */
    ExpectIntEQ(wolfSSL_read(ssl_c, reply, (int)sizeof(msg) - 8),
        (int)sizeof(msg) - 8);
    ExpectBufEQ(reply, msg + 8, sizeof(msg) - 8);
    ExpectIntEQ(wolfSSL_pending(ssl_c), 0);
    ExpectIntEQ(wolfSSL_has_pending(ssl_c), 0);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* Test parameter validation across the read/write APIs.
 *
 * Every entry point in ssl_api_rw.c rejects a NULL object, a NULL buffer or a
 * negative length before touching the connection.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_rw_bad_args(void)
{
    EXPECT_DECLS;
/* wolfSSL_recv() below is only defined when WOLFSSL_LEANPSK is not, as in
 * test_wolfSSL_send(). */
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && !defined(NO_TLS) \
    && !defined(WOLFSSL_NO_TLS12) && !defined(WOLFSSL_LEANPSK)
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    char buf[16];
    size_t rd = 0;
    size_t wr = 0;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* wolfSSL_write() and wolfSSL_read(). */
    ExpectIntEQ(wolfSSL_write(NULL, buf, (int)sizeof(buf)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_write(ssl_c, NULL, (int)sizeof(buf)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_write(ssl_c, buf, -1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_read(NULL, buf, (int)sizeof(buf)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_read(ssl_c, NULL, (int)sizeof(buf)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_read(ssl_c, buf, -1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* wolfSSL_peek() shares the read path. */
    ExpectIntEQ(wolfSSL_peek(NULL, buf, (int)sizeof(buf)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_peek(ssl_c, buf, -1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* wolfSSL_recv() validates before setting the socket flags. */
    ExpectIntEQ(wolfSSL_recv(NULL, buf, (int)sizeof(buf), 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_recv(ssl_c, NULL, (int)sizeof(buf), 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_recv(ssl_c, buf, -1, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* wolfSSL_shutdown() and wolfSSL_SendUserCanceled() report their own
     * failure codes for a NULL object. */
    ExpectIntEQ(wolfSSL_shutdown(NULL), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    ExpectIntEQ(wolfSSL_SendUserCanceled(NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

    /* wolfSSL_inject() rejects a non-positive length as well. */
    ExpectIntEQ(wolfSSL_inject(NULL, buf, (int)sizeof(buf)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_inject(ssl_c, NULL, (int)sizeof(buf)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_inject(ssl_c, buf, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* The _ex variants report a write or read failure as 0, but a NULL object
     * is surfaced as an error code by both so it cannot be mistaken for one.
     * Seed the counts with a value neither call could produce, so what each
     * does to its own is visible. */
    wr = 0x5a5a;
    rd = 0x5a5a;
    /* write_ex clears the count before validating anything, so it reads as
     * zero even though nothing was written. */
    ExpectIntEQ(wolfSSL_write_ex(NULL, buf, sizeof(buf), &wr),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wr, 0);
    /* read_ex only sets the count when data was read, so it is left alone. */
    ExpectIntEQ(wolfSSL_read_ex(NULL, buf, sizeof(buf), &rd),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(rd, 0x5a5a);
    /* Neither writes through a NULL count. */
    ExpectIntEQ(wolfSSL_write_ex(NULL, buf, sizeof(buf), NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_read_ex(NULL, buf, sizeof(buf), NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && !defined(NO_TLS) && \
    defined(OPENSSL_EXTRA) && !defined(WOLFSSL_NO_TLS12)
/* Number of times the info callback below has been invoked. */
static int test_ssl_rw_info_calls = 0;
/* Type reported by the most recent info callback invocation. */
static int test_ssl_rw_info_type  = 0;

/* Info callback recording what the read/write APIs report.
 *
 * @param [in] ssl   SSL/TLS object reporting the state. Unused.
 * @param [in] type  State being reported.
 * @param [in] val   Value associated with the state. Unused.
 */
static void test_ssl_rw_info_cb(const WOLFSSL* ssl, int type, int val)
{
    (void)ssl;
    (void)val;

    test_ssl_rw_info_calls++;
    test_ssl_rw_info_type = type;
}
#endif

/* Test that the read/write APIs invoke the info callback.
 *
 * wolfSSL_write() reports WOLFSSL_CB_WRITE and wolfSSL_read()/wolfSSL_read_ex()
 * report WOLFSSL_CB_READ when an info callback is installed.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_rw_info_callback(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && !defined(NO_TLS) \
    && defined(OPENSSL_EXTRA) && !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    char msg[] = "hello wolfssl info cb";
    char reply[64];
    size_t rd = 0;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* Install after the handshake so only the data calls are counted. */
    test_ssl_rw_info_calls = 0;
    test_ssl_rw_info_type = 0;
    wolfSSL_set_info_callback(ssl_c, test_ssl_rw_info_cb);
    wolfSSL_set_info_callback(ssl_s, test_ssl_rw_info_cb);

    /* Writing reports WOLFSSL_CB_WRITE. */
    ExpectIntEQ(wolfSSL_write(ssl_c, msg, (int)sizeof(msg)),
        (int)sizeof(msg));
    ExpectIntEQ(test_ssl_rw_info_calls, 1);
    ExpectIntEQ(test_ssl_rw_info_type, WOLFSSL_CB_WRITE);

    /* Reading reports WOLFSSL_CB_READ. */
    XMEMSET(reply, 0, sizeof(reply));
    ExpectIntEQ(wolfSSL_read(ssl_s, reply, (int)sizeof(reply)),
        (int)sizeof(msg));
    ExpectBufEQ(reply, msg, sizeof(msg));
    ExpectIntEQ(test_ssl_rw_info_calls, 2);
    ExpectIntEQ(test_ssl_rw_info_type, WOLFSSL_CB_READ);

    /* wolfSSL_read_ex() reports it too. */
    ExpectIntEQ(wolfSSL_write(ssl_c, msg, (int)sizeof(msg)),
        (int)sizeof(msg));
    XMEMSET(reply, 0, sizeof(reply));
    ExpectIntEQ(wolfSSL_read_ex(ssl_s, reply, sizeof(reply), &rd), 1);
    ExpectIntEQ(rd, sizeof(msg));
    ExpectIntEQ(test_ssl_rw_info_calls, 4);
    ExpectIntEQ(test_ssl_rw_info_type, WOLFSSL_CB_READ);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* Test wolfSSL_write_ex() partial write handling.
 *
 * With partial writes enabled a zero-length write reports failure rather than
 * success; with them disabled a full write reports success.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_write_ex_partial(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && !defined(NO_TLS) \
    && !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    char msg[] = "hello wolfssl write_ex";
    size_t wr = 1;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* Writing everything reports success and the length written. */
    ExpectIntEQ(wolfSSL_write_ex(ssl_c, msg, sizeof(msg), &wr), 1);
    ExpectIntEQ(wr, sizeof(msg));

    /* With partial writes enabled, writing nothing is reported as a failure
     * even though no error occurred. */
    if (ssl_c != NULL) {
        ssl_c->options.partialWrite = 1;
    }
    wr = 1;
    ExpectIntEQ(wolfSSL_write_ex(ssl_c, msg, 0, &wr), 0);
    ExpectIntEQ(wr, 0);
    if (ssl_c != NULL) {
        ssl_c->options.partialWrite = 0;
    }

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* Test that wolfSSL_inject() refuses to grow the input buffer while decrypted
 * application data is still waiting to be read.
 *
 * Growing the input buffer would invalidate clearOutputBuffer, which points
 * into it, so the pending data must be drained first.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_inject_app_data_ready(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && !defined(NO_TLS) \
    && !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    byte msg[32];
    byte reply[32];
    int usedLength = 0;
    int maxLength = 0;
    int i;
    byte* big = NULL;

    for (i = 0; i < (int)sizeof(msg); i++) {
        msg[i] = (byte)i;
    }

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* Leave application data buffered by reading less than was written. */
    ExpectIntEQ(wolfSSL_write(ssl_s, msg, (int)sizeof(msg)),
        (int)sizeof(msg));
    ExpectIntEQ(wolfSSL_read(ssl_c, reply, 8), 8);
    ExpectIntGT(wolfSSL_pending(ssl_c), 0);

    /* Anything that needs more room than the input buffer has is refused
     * while data is pending. Back the length with a buffer of that size: the
     * call is expected to compare it and stop, but the test should not be
     * what keeps the read in bounds if it ever does not. */
    if (ssl_c != NULL) {
        usedLength = (int)(ssl_c->buffers.inputBuffer.length -
                           ssl_c->buffers.inputBuffer.idx);
        maxLength  = (int)(ssl_c->buffers.inputBuffer.bufferSize -
                           (word32)usedLength);
        ExpectNotNull(big = (byte*)XMALLOC((size_t)maxLength + 1, NULL,
            DYNAMIC_TYPE_TMP_BUFFER));
        if (big != NULL) {
            XMEMSET(big, 0, (size_t)maxLength + 1);
            ExpectIntEQ(wolfSSL_inject(ssl_c, big, maxLength + 1),
                WC_NO_ERR_TRACE(APP_DATA_READY));
        }
    }

    /* Once the pending data is drained the same call is accepted: the input
     * buffer can be grown now that nothing points into it. */
    ExpectIntEQ(wolfSSL_read(ssl_c, reply, (int)sizeof(msg) - 8),
        (int)sizeof(msg) - 8);
    ExpectIntEQ(wolfSSL_pending(ssl_c), 0);
    if ((ssl_c != NULL) && (big != NULL)) {
        ExpectIntEQ(wolfSSL_inject(ssl_c, big, maxLength + 1),
            WOLFSSL_SUCCESS);
    }

    XFREE(big, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

#if defined(WOLFSSL_QUIC) && defined(WOLFSSL_TLS13) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
/* QUIC secret callback. Only send_alert below matters to this test.
 *
 * @return  1 always, which the QUIC layer reads as success.
 */
static int test_ssl_rw_quic_secrets(WOLFSSL* ssl,
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

/* QUIC handshake data sink.
 *
 * @return  1 always, which the QUIC layer reads as success.
 */
static int test_ssl_rw_quic_add_hs(WOLFSSL* ssl,
    WOLFSSL_ENCRYPTION_LEVEL level, const uint8_t* data, size_t len)
{
    (void)ssl;
    (void)level;
    (void)data;
    (void)len;
    return 1;
}

/* QUIC flight flush.
 *
 * @return  1 always, which the QUIC layer reads as success.
 */
static int test_ssl_rw_quic_flush(WOLFSSL* ssl)
{
    (void)ssl;
    return 1;
}

/* QUIC alert send that refuses. SendAlert() negates this, so ssl->error
 * becomes a positive 1 - neither zero nor a negative error code.
 *
 * @return  0 always, which the QUIC layer reads as failure.
 */
static int test_ssl_rw_quic_send_alert_fail(WOLFSSL* ssl,
    WOLFSSL_ENCRYPTION_LEVEL level, uint8_t alertType)
{
    (void)ssl;
    (void)level;
    (void)alertType;
    return 0;
}

static const WOLFSSL_QUIC_METHOD test_ssl_rw_quic_method = {
    test_ssl_rw_quic_secrets,
    test_ssl_rw_quic_add_hs,
    test_ssl_rw_quic_flush,
    test_ssl_rw_quic_send_alert_fail
};
#endif

/* Test that a refused close_notify send does not undo a shutdown the peer
 * already completed.
 *
 * The peer's close_notify has arrived but this side has not sent one. The
 * QUIC send_alert callback refuses, which SendAlert() reports as a positive
 * value, so sentNotify stays clear while the shutdown is none the less
 * complete. The result must remain WOLFSSL_SUCCESS.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_shutdown_quic_alert_refused(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_QUIC) && defined(WOLFSSL_TLS13) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectIntEQ(wolfSSL_CTX_set_quic_method(ctx, &test_ssl_rw_quic_method),
        WOLFSSL_SUCCESS);
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        ssl->options.closeNotify = 1;
        ExpectIntEQ(wolfSSL_shutdown(ssl), WOLFSSL_SUCCESS);
        /* The exchange really did complete. */
        ExpectIntEQ(ssl->options.shutdownDone, 1);
    }

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* Test calling wolfSSL_shutdown() again after the shutdown has completed.
 *
 * The exchange is over, so there is nothing left to do and nothing has gone
 * wrong. The call reports failure all the same, and records no error for
 * wolfSSL_get_error() to return - the one case where a failing shutdown
 * leaves the caller without a reason. Only reachable where wolfSSL_clear()
 * is not compiled in to reset the flags after a successful shutdown.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_shutdown_repeat_after_done(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && !defined(NO_TLS) && \
    !defined(WOLFSSL_NO_TLS12) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(NO_WOLFSSL_SERVER) && !defined(WOLFSSL_SHUTDOWNONCE) && \
    !defined(OPENSSL_EXTRA) && !defined(WOLFSSL_WPAS_SMALL)
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* Complete the shutdown in both directions. */
    ExpectIntEQ(wolfSSL_shutdown(ssl_c), WOLFSSL_SHUTDOWN_NOT_DONE);
    ExpectIntEQ(wolfSSL_shutdown(ssl_s), WOLFSSL_SHUTDOWN_NOT_DONE);
    ExpectIntEQ(wolfSSL_shutdown(ssl_c), WOLFSSL_SUCCESS);
    if (ssl_c != NULL) {
        ExpectIntEQ(ssl_c->options.sentNotify, 1);
        ExpectIntEQ(ssl_c->options.closeNotify, 1);
    }

    /* Calling again reports failure with no error recorded. */
    ExpectIntEQ(wolfSSL_shutdown(ssl_c), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    if (ssl_c != NULL) {
        ExpectIntEQ(ssl_c->error, WOLFSSL_ERROR_NONE);
    }

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* Test that a shutdown which flushes a buffered write but can never send
 * close_notify still reports failure.
 *
 * A write that hit WANT_WRITE leaves data buffered without setting
 * sentNotify. If the connection is closed before the shutdown runs, the
 * buffered data flushes successfully but no close_notify can follow, so the
 * exchange can never complete. This used to report the flush's success as
 * the shutdown's, returning 0 - which is WOLFSSL_SHUTDOWN_NOT_DONE under
 * WOLFSSL_ERROR_CODE_OPENSSL, so a caller looping while the result is 0
 * never terminated.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_shutdown_flush_no_notify(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && !defined(NO_TLS) && \
    !defined(WOLFSSL_NO_TLS12) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(NO_WOLFSSL_SERVER) && !defined(WOLFSSL_SHUTDOWNONCE)
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    char msg[] = "buffered by a failed write";

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* Leave application data in the output buffer. sentNotify stays clear
     * because no close_notify has been attempted. */
    test_memio_simulate_want_write(&test_ctx, 1, 1);
    ExpectIntEQ(wolfSSL_write(ssl_c, msg, (int)sizeof(msg)),
        WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    ExpectIntEQ(wolfSSL_get_error(ssl_c, 0), WOLFSSL_ERROR_WANT_WRITE);
    if (ssl_c != NULL) {
        ExpectIntGT(ssl_c->buffers.outputBuffer.length, 0);
        ExpectIntEQ(ssl_c->options.sentNotify, 0);
    }

    /* Let the flush succeed, but close the connection so no close_notify can
     * follow it. */
    test_memio_simulate_want_write(&test_ctx, 1, 0);
    if (ssl_c != NULL) {
        ssl_c->options.isClosed = 1;

        ExpectIntEQ(wolfSSL_shutdown(ssl_c),
            WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
        /* The flush really did happen. */
        ExpectIntEQ(ssl_c->buffers.outputBuffer.length, 0);
        /* And the caller has a reason to query. */
        ExpectIntEQ(ssl_c->error, WC_NO_ERR_TRACE(SOCKET_PEER_CLOSED_E));
    }

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* Test that a shutdown which can never send close_notify reports why.
 *
 * When the connection is already closed no close_notify can be sent, so the
 * exchange can never complete. The call fails, and the reason must be
 * available from wolfSSL_get_error() rather than leaving the caller with a
 * failure and no error to query.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_shutdown_no_notify(void)
{
    EXPECT_DECLS;
#if !defined(NO_TLS) && !defined(WOLFSSL_NO_TLS12) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(WOLFSSL_SHUTDOWNONCE)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        /* The connection went away before a close_notify could be sent. */
        ssl->options.isClosed = 1;
        ssl->options.sentNotify = 0;
        ssl->error = WOLFSSL_ERROR_NONE;

        ExpectIntEQ(wolfSSL_shutdown(ssl),
            WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
        /* Check the recorded error rather than the value reported, which
         * wolfSSL_get_error() translates for OpenSSL compatibility. */
        ExpectIntEQ(ssl->error, WC_NO_ERR_TRACE(SOCKET_PEER_CLOSED_E));
        /* The caller is not left with a failure and nothing to query. */
        ExpectIntNE(wolfSSL_get_error(ssl, 0), 0);
    }
    wolfSSL_free(ssl);
    ssl = NULL;
    wolfSSL_CTX_free(ctx);
    ctx = NULL;

    /* An error already recorded is more specific, so it is kept. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        ssl->options.connReset = 1;
        ssl->options.sentNotify = 0;
        ssl->error = WC_NO_ERR_TRACE(SOCKET_ERROR_E);

        ExpectIntEQ(wolfSSL_shutdown(ssl),
            WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
        /* The more specific error already recorded is left in place. */
        ExpectIntEQ(ssl->error, WC_NO_ERR_TRACE(SOCKET_ERROR_E));
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* Test the paths wolfSSL_SendUserCanceled() takes once the alert is sent.
 *
 * The NULL case is covered by test_wolfSSL_rw_bad_args(). This drives the
 * rest: the alert goes out and the shutdown it delegates to then decides the
 * result, including the case where no close_notify can ever be sent.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_SendUserCanceled_paths(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && !defined(NO_TLS) && \
    !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    char reply[16];

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* The alert goes out and the shutdown starts, which cannot complete
     * until the peer replies. */
    ExpectIntEQ(wolfSSL_SendUserCanceled(ssl_c), WOLFSSL_SHUTDOWN_NOT_DONE);
    ExpectIntEQ(wolfSSL_get_shutdown(ssl_c), WOLFSSL_SENT_SHUTDOWN);

    /* The server reads both alerts; the close_notify is what it reports. */
    ExpectIntEQ(wolfSSL_read(ssl_s, reply, (int)sizeof(reply)), 0);
    ExpectIntEQ(wolfSSL_get_shutdown(ssl_s), WOLFSSL_RECEIVED_SHUTDOWN);

    /* The server replies and the exchange completes on both sides. */
    ExpectIntEQ(wolfSSL_shutdown(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_shutdown(ssl_c), WOLFSSL_SUCCESS);

    wolfSSL_free(ssl_c);
    ssl_c = NULL;
    wolfSSL_free(ssl_s);
    ssl_s = NULL;
    wolfSSL_CTX_free(ctx_c);
    ctx_c = NULL;
    wolfSSL_CTX_free(ctx_s);
    ctx_s = NULL;

#ifndef WOLFSSL_SHUTDOWNONCE
    /* With the connection already closed and no close_notify sent, the
     * shutdown can never complete, so the failure is reported rather than
     * the 0 an application could mistake for progress. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    if (ssl_c != NULL) {
        ssl_c->options.isClosed = 1;
        ssl_c->options.sentNotify = 0;
        ssl_c->error = WOLFSSL_ERROR_NONE;

        ExpectIntEQ(wolfSSL_SendUserCanceled(ssl_c),
            WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
        /* Check the recorded error rather than the value reported, which
         * wolfSSL_get_error() translates for OpenSSL compatibility. */
        ExpectIntEQ(ssl_c->error, WC_NO_ERR_TRACE(SOCKET_PEER_CLOSED_E));
    }

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
#endif
    return EXPECT_RESULT();
}

/* Test that quiet shutdown does not suppress the close_notify that the
 * user_canceled alert obliges wolfSSL to send.
 *
 * RFC 9846 Section 6.1 has a "close_notify" following "user_canceled" and has
 * the peer keep reading until it arrives. Quiet shutdown may drop the
 * close_notify that stands alone - that is what the option is for - but not
 * the one the peer has been told to wait for.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_SendUserCanceled_quiet_shutdown(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && !defined(NO_TLS) && \
    !defined(WOLFSSL_NO_TLS12) && (defined(OPENSSL_EXTRA) || \
    defined(OPENSSL_EXTRA_X509_SMALL) || defined(WOLFSSL_EXTRA) || \
    defined(WOLFSSL_WPAS_SMALL))
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    char reply[16];

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_set_quiet_shutdown(ssl_c, 1);
    /* Both alerts go out. Waiting for the peer's reply is what quiet shutdown
     * skips, so the shutdown is done as far as this side is concerned. */
    ExpectIntEQ(wolfSSL_SendUserCanceled(ssl_c), WOLFSSL_SUCCESS);

    /* The server reads the user_canceled and then the close_notify, which is
     * what it reports. Without the close_notify it would still be waiting. */
    ExpectIntEQ(wolfSSL_read(ssl_s, reply, (int)sizeof(reply)), 0);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, 0), WOLFSSL_ERROR_ZERO_RETURN);
    ExpectIntEQ(wolfSSL_get_shutdown(ssl_s), WOLFSSL_RECEIVED_SHUTDOWN);

    wolfSSL_free(ssl_c);
    ssl_c = NULL;
    wolfSSL_free(ssl_s);
    ssl_s = NULL;
    wolfSSL_CTX_free(ctx_c);
    ctx_c = NULL;
    wolfSSL_CTX_free(ctx_s);
    ctx_s = NULL;

    /* A quiet shutdown with no user_canceled behind it still sends nothing:
     * that is the whole point of the option. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_set_quiet_shutdown(ssl_c, 1);
    ExpectIntEQ(wolfSSL_shutdown(ssl_c), WOLFSSL_SUCCESS);

    /* Nothing arrived, so the server is still waiting for a record. */
    ExpectIntLT(wolfSSL_read(ssl_s, reply, (int)sizeof(reply)), 0);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(wolfSSL_get_shutdown(ssl_s), 0);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* Test that an error the read side recorded is the one the write reports.
 *
 * With a write duplicate in use the read side hands errors over through
 * ssl->dupWrite->dupErr. The write collects that under the lock and acts on
 * it once the lock is released, in preference to carrying on with the work
 * the read side delegated.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_write_dup_err(void)
{
    EXPECT_DECLS;
#if defined(HAVE_WRITE_DUP) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && !defined(NO_TLS) && \
    !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    WOLFSSL* ssl_w = NULL;
    struct test_memio_ctx test_ctx;
    const char msg[] = "hello";

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* The original becomes read only; the duplicate is the write side. */
    ExpectNotNull(ssl_w = wolfSSL_write_dup(ssl_c));

    /* Writing works while the read side has reported nothing. */
    ExpectIntEQ(wolfSSL_write(ssl_w, msg, (int)sizeof(msg)),
        (int)sizeof(msg));

    if (ssl_w != NULL) {
        /* The read side hands an error over. */
        ssl_w->dupWrite->dupErr = WC_NO_ERR_TRACE(DECRYPT_ERROR);

        ExpectIntEQ(wolfSSL_write(ssl_w, msg, (int)sizeof(msg)),
            WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
        /* Surfaced as the read side's error rather than one of the write's
         * own, and recorded so wolfSSL_get_error() can report it. */
        ExpectIntEQ(ssl_w->error, WC_NO_ERR_TRACE(DECRYPT_ERROR));
    }

    wolfSSL_free(ssl_w);
    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}
