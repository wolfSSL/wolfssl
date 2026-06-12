/* test_tls_ext.c
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

#include <wolfssl/internal.h>
#include <tests/utils.h>
#include <tests/api/test_tls_ext.h>

int test_tls_ems_downgrade(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && !defined(WOLFSSL_NO_TLS12) && \
        defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
        defined(HAVE_SESSION_TICKET) && !defined(WOLFSSL_NO_DEF_TICKET_ENC_CB)
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    WOLFSSL_SESSION* session = NULL;
    /* TLS EMS extension in binary form */
    const char ems_ext[] = { 0x00, 0x17, 0x00, 0x00 };
    char data = 0;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfTLS_client_method, wolfTLS_server_method), 0);

    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);

    /* Verify that the EMS extension is present in Client's message */
    ExpectNotNull(mymemmem(test_ctx.s_buff, test_ctx.s_len,
            ems_ext, sizeof(ems_ext)));

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectIntEQ(wolfSSL_version(ssl_c), TLS1_3_VERSION);

    /* Do a round of reads to exchange the ticket message */
    ExpectIntEQ(wolfSSL_read(ssl_s, &data, sizeof(data)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(wolfSSL_read(ssl_c, &data, sizeof(data)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);

    ExpectNotNull(session = wolfSSL_get1_session(ssl_c));
    ExpectTrue(session->haveEMS);

    wolfSSL_free(ssl_c);
    ssl_c = NULL;
    wolfSSL_free(ssl_s);
    ssl_s = NULL;

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfTLS_client_method, wolfTLS_server_method), 0);

    /* Resuming the connection */
    ExpectIntEQ(wolfSSL_set_session(ssl_c, session), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);

    /* Verify that the EMS extension is still present in the resumption CH
     * even though we used TLS 1.3 */
    ExpectNotNull(mymemmem(test_ctx.s_buff, test_ctx.s_len,
            ems_ext, sizeof(ems_ext)));

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectIntEQ(wolfSSL_version(ssl_c), TLS1_3_VERSION);

    wolfSSL_SESSION_free(session);
    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}


/* F-2915: resumption of an EMS session without EMS must abort with
 * EXT_MASTER_SECRET_NEEDED_E (RFC 7627 Section 5.3). */
int test_tls_ems_resumption_downgrade(void)
{
    EXPECT_DECLS;
#if !defined(WOLFSSL_NO_TLS12) && defined(HAVE_EXTENDED_MASTER) && \
        defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
        !defined(NO_SESSION_CACHE)
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    WOLFSSL_SESSION *session = NULL;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    ExpectNotNull(session = wolfSSL_get1_session(ssl_c));

    wolfSSL_free(ssl_c);
    ssl_c = NULL;
    wolfSSL_free(ssl_s);
    ssl_s = NULL;
    test_memio_clear_buffer(&test_ctx, 0);
    test_memio_clear_buffer(&test_ctx, 1);

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(wolfSSL_set_session(ssl_c, session), WOLFSSL_SUCCESS);
    /* Drop EMS from the resumption ClientHello to simulate a downgrade. */
    ExpectIntEQ(wolfSSL_DisableExtendedMasterSecret(ssl_c), WOLFSSL_SUCCESS);

    ExpectIntNE(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, 0),
            WC_NO_ERR_TRACE(EXT_MASTER_SECRET_NEEDED_E));

    wolfSSL_SESSION_free(session);
    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}


#if !defined(WOLFSSL_NO_TLS12) && defined(HAVE_EXTENDED_MASTER) && \
        defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
        !defined(NO_SESSION_CACHE)
/* Remove the extended_master_secret extension from the ServerHello record at
 * the head of the server-to-client memio buffer, patching up the record,
 * handshake and extension-block lengths so the message still parses.
 * Returns 0 on success. */
static int StripEmsFromServerHello(struct test_memio_ctx* test_ctx)
{
    byte* buf = test_ctx->c_buff;
    int   len = test_ctx->c_len;
    int   recLen;
    int   hsLen;
    int   extsLenIdx;
    int   extsLen;
    int   idx;
    int   extsEnd;

    /* Record header: type(1) version(2) length(2) */
    if (len < 5 || buf[0] != handshake)
        return -1;
    recLen = (buf[3] << 8) | buf[4];
    if (5 + recLen > len)
        return -1;
    /* Handshake header: type(1) length(3) */
    if (recLen < HANDSHAKE_HEADER_SZ || buf[5] != server_hello)
        return -1;
    hsLen = (buf[6] << 16) | (buf[7] << 8) | buf[8];
    /* Skip version(2), random(32) to the session ID length, then skip the
     * session ID, cipher suite(2) and compression(1) to the extensions
     * length. */
    extsLenIdx = 5 + HANDSHAKE_HEADER_SZ + OPAQUE16_LEN + RAN_LEN +
                 OPAQUE8_LEN + buf[5 + HANDSHAKE_HEADER_SZ + OPAQUE16_LEN +
                                    RAN_LEN] +
                 OPAQUE16_LEN + OPAQUE8_LEN;
    if (extsLenIdx + OPAQUE16_LEN > 5 + recLen)
        return -1;
    extsLen = (buf[extsLenIdx] << 8) | buf[extsLenIdx + 1];
    idx = extsLenIdx + OPAQUE16_LEN;
    extsEnd = idx + extsLen;
    if (extsEnd > 5 + recLen)
        return -1;
    while (idx + 4 <= extsEnd) {
        int extType = (buf[idx] << 8) | buf[idx + 1];
        int extLen = (buf[idx + 2] << 8) | buf[idx + 3];
        int rmLen = 4 + extLen;

        if (idx + rmLen > extsEnd)
            return -1;
        if (extType == HELLO_EXT_EXTMS) {
            XMEMMOVE(buf + idx, buf + idx + rmLen,
                     (size_t)(len - idx - rmLen));
            recLen -= rmLen;
            hsLen -= rmLen;
            extsLen -= rmLen;
            buf[3] = (byte)(recLen >> 8);
            buf[4] = (byte)recLen;
            buf[6] = (byte)(hsLen >> 16);
            buf[7] = (byte)(hsLen >> 8);
            buf[8] = (byte)hsLen;
            buf[extsLenIdx] = (byte)(extsLen >> 8);
            buf[extsLenIdx + 1] = (byte)extsLen;
            test_ctx->c_len -= rmLen;
            /* The ServerHello record sits wholly inside the first buffered
             * message. */
            test_ctx->c_msg_sizes[0] -= rmLen;
            return 0;
        }
        idx += rmLen;
    }
    return -1;
}

/* Full handshake with EMS, then resume and strip the EMS extension from the
 * ServerHello in transit. The client must catch the downgrade and abort
 * (RFC 7627 Section 5.3). useTicket selects session-ticket resumption
 * instead of session-ID resumption. */
static int test_tls_ems_resumption_server_downgrade_ex(int useTicket)
{
    EXPECT_DECLS;
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    WOLFSSL_SESSION *session = NULL;

#ifndef HAVE_SESSION_TICKET
    (void)useTicket;
#endif

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
#ifdef HAVE_SESSION_TICKET
    if (useTicket)
        ExpectIntEQ(wolfSSL_UseSessionTicket(ssl_c), WOLFSSL_SUCCESS);
#endif
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    ExpectNotNull(session = wolfSSL_get1_session(ssl_c));
    ExpectTrue(session->haveEMS);
#ifdef HAVE_SESSION_TICKET
    if (useTicket)
        ExpectIntGT(session->ticketLen, 0);
#endif

    wolfSSL_free(ssl_c);
    ssl_c = NULL;
    wolfSSL_free(ssl_s);
    ssl_s = NULL;
    test_memio_clear_buffer(&test_ctx, 0);
    test_memio_clear_buffer(&test_ctx, 1);

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(wolfSSL_set_session(ssl_c, session), WOLFSSL_SUCCESS);

    /* ClientHello */
    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* Server flight accepting the resumption */
    ExpectIntEQ(wolfSSL_accept(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    /* Drop EMS from the ServerHello to simulate a downgrading server. */
    ExpectIntEQ(StripEmsFromServerHello(&test_ctx), 0);
    /* The client must refuse to resume without EMS. */
    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1),
            WC_NO_ERR_TRACE(EXT_MASTER_SECRET_NEEDED_E));

    wolfSSL_SESSION_free(session);
    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
    return EXPECT_RESULT();
}
#endif

/* F-5807: a server that resumes an EMS session but omits the
 * extended_master_secret extension from its ServerHello must be rejected by
 * the client with EXT_MASTER_SECRET_NEEDED_E (RFC 7627 Section 5.3), on both
 * session-ID and session-ticket resumption. */
int test_tls_ems_resumption_server_downgrade(void)
{
    EXPECT_DECLS;
#if !defined(WOLFSSL_NO_TLS12) && defined(HAVE_EXTENDED_MASTER) && \
        defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
        !defined(NO_SESSION_CACHE)
    ExpectIntEQ(test_tls_ems_resumption_server_downgrade_ex(0), TEST_SUCCESS);
#if defined(HAVE_SESSION_TICKET) && !defined(WOLFSSL_NO_DEF_TICKET_ENC_CB)
    ExpectIntEQ(test_tls_ems_resumption_server_downgrade_ex(1), TEST_SUCCESS);
#endif
#endif
    return EXPECT_RESULT();
}


#if !defined(WOLFSSL_NO_TLS12) && \
        defined(BUILD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256) && \
        defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES)
static int test_chacha_bad_tag_trigger = 0;

static int test_chacha_bad_tag_io_recv(WOLFSSL* ssl, char* buf, int sz,
        void* ctx)
{
    int ret = test_memio_read_cb(ssl, buf, sz, ctx);
    /* Tamper with a byte from the encrypted record payload on the first
     * read that spans past the 5-byte TLS record header, so the Poly1305
     * authentication check no longer matches. */
    if (test_chacha_bad_tag_trigger && ret > 5) {
        buf[ret - 1] ^= 0xFF;
        test_chacha_bad_tag_trigger = 0;
    }
    return ret;
}
#endif

/* F-2921: TLS 1.2 ChaCha20-Poly1305 must surface VERIFY_MAC_ERROR when
 * the Poly1305 tag is corrupted. */
int test_tls12_chacha20_poly1305_bad_tag(void)
{
    EXPECT_DECLS;
#if !defined(WOLFSSL_NO_TLS12) && \
        defined(BUILD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256) && \
        defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES)
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    const char msg[] = "tamper me";
    char recvBuf[32];
    int ret;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    test_ctx.c_ciphers = test_ctx.s_ciphers =
        "ECDHE-RSA-CHACHA20-POLY1305";

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_SSLSetIORecv(ssl_s, test_chacha_bad_tag_io_recv);

    ExpectIntEQ(wolfSSL_write(ssl_c, msg, (int)XSTRLEN(msg)),
            (int)XSTRLEN(msg));

    test_chacha_bad_tag_trigger = 1;
    ret = wolfSSL_read(ssl_s, recvBuf, sizeof(recvBuf));
    ExpectIntLE(ret, 0);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, ret),
            WC_NO_ERR_TRACE(VERIFY_MAC_ERROR));

    test_chacha_bad_tag_trigger = 0;
    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}


#if defined(WOLFSSL_TLS13) && defined(HAVE_NULL_CIPHER) && \
        defined(BUILD_TLS_SHA256_SHA256) && \
        defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES)
static int test_tls13_null_bad_hmac_trigger = 0;

static int test_tls13_null_bad_hmac_io_recv(WOLFSSL* ssl, char* buf, int sz,
        void* ctx)
{
    int ret = test_memio_read_cb(ssl, buf, sz, ctx);
    /* Tamper with a byte from the encrypted record payload on the first
     * read that spans past the 5-byte TLS record header, so the HMAC tag
     * check in Tls13IntegrityOnly_Decrypt no longer matches. */
    if (test_tls13_null_bad_hmac_trigger && ret > 5) {
        buf[ret - 1] ^= 0xFF;
        test_tls13_null_bad_hmac_trigger = 0;
    }
    return ret;
}
#endif

/* F-2916: TLS 1.3 integrity-only decryption must surface DECRYPT_ERROR
 * when the HMAC tag is corrupted. */
int test_tls13_null_cipher_bad_hmac(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && defined(HAVE_NULL_CIPHER) && \
        defined(BUILD_TLS_SHA256_SHA256) && \
        defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES)
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    const char msg[] = "integrity only";
    char recvBuf[32];
    int ret;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    test_ctx.c_ciphers = test_ctx.s_ciphers = "TLS13-SHA256-SHA256";

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_SSLSetIORecv(ssl_s, test_tls13_null_bad_hmac_io_recv);

    ExpectIntEQ(wolfSSL_write(ssl_c, msg, (int)XSTRLEN(msg)),
            (int)XSTRLEN(msg));

    test_tls13_null_bad_hmac_trigger = 1;
    ret = wolfSSL_read(ssl_s, recvBuf, sizeof(recvBuf));
    ExpectIntLE(ret, 0);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, ret),
            WC_NO_ERR_TRACE(DECRYPT_ERROR));

    test_tls13_null_bad_hmac_trigger = 0;
    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}


/* F-2913 and F-2914: the TLSX_SecureRenegotiation_Parse
 * ConstantCompare against the cached Finished verify_data must reject
 * a mismatch on both the client and server sides. */
int test_scr_verify_data_mismatch(void)
{
    EXPECT_DECLS;
#if defined(HAVE_SECURE_RENEGOTIATION) && !defined(WOLFSSL_NO_TLS12) && \
        defined(BUILD_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) && \
        defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES)
    int side;

    for (side = 0; side < 2; side++) {
        struct test_memio_ctx test_ctx;
        WOLFSSL_CTX *ctx_c = NULL;
        WOLFSSL_CTX *ctx_s = NULL;
        WOLFSSL *ssl_c = NULL;
        WOLFSSL *ssl_s = NULL;
        WOLFSSL *failing;
        byte data;
        int ret;

        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        test_ctx.c_ciphers = test_ctx.s_ciphers =
                "ECDHE-RSA-AES128-GCM-SHA256";

        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c,
                &ssl_s, wolfTLSv1_2_client_method,
                wolfTLSv1_2_server_method), 0);
        ExpectIntEQ(wolfSSL_CTX_UseSecureRenegotiation(ctx_c),
                WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_CTX_UseSecureRenegotiation(ctx_s),
                WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_UseSecureRenegotiation(ssl_c), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_UseSecureRenegotiation(ssl_s), WOLFSSL_SUCCESS);

        ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

        /* side 0: corrupt the client's copy; side 1: corrupt the
         * server's copy. */
        if (side == 0) {
            if (ssl_c != NULL && ssl_c->secure_renegotiation != NULL)
                ssl_c->secure_renegotiation->server_verify_data[0] ^= 0xFF;
            failing = ssl_c;
        }
        else {
            if (ssl_s != NULL && ssl_s->secure_renegotiation != NULL)
                ssl_s->secure_renegotiation->client_verify_data[0] ^= 0xFF;
            failing = ssl_s;
        }

        ret = wolfSSL_Rehandshake(ssl_c);
        (void)ret;
        (void)wolfSSL_read(ssl_s, &data, 1);
        (void)wolfSSL_read(ssl_c, &data, 1);
        ExpectIntEQ(wolfSSL_get_error(failing, 0),
                WC_NO_ERR_TRACE(SECURE_RENEGOTIATION_E));

        wolfSSL_free(ssl_c);
        wolfSSL_free(ssl_s);
        wolfSSL_CTX_free(ctx_c);
        wolfSSL_CTX_free(ctx_s);
    }
#endif
    return EXPECT_RESULT();
}

/* F-4144: WOLFSSL_OP_NO_RENEGOTIATION on the server must refuse a
 * client-initiated renegotiation with a no_renegotiation *warning* while
 * keeping the established connection alive, rather than aborting it. */
int test_scr_no_renegotiation_option(void)
{
    EXPECT_DECLS;
#if defined(HAVE_SECURE_RENEGOTIATION) && !defined(WOLFSSL_NO_TLS12) && \
        defined(BUILD_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) && \
        defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES)
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    WOLFSSL_ALERT_HISTORY history;
    byte readBuf[16];
    int ret = WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR);
    int i;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    XMEMSET(&history, 0, sizeof(history));
    test_ctx.c_ciphers = test_ctx.s_ciphers = "ECDHE-RSA-AES128-GCM-SHA256";

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c,
            &ssl_s, wolfTLSv1_2_client_method,
            wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(wolfSSL_CTX_UseSecureRenegotiation(ctx_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_UseSecureRenegotiation(ctx_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UseSecureRenegotiation(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UseSecureRenegotiation(ssl_s), WOLFSSL_SUCCESS);

    /* Server opts into rejecting peer-initiated renegotiation. */
    wolfSSL_set_options(ssl_s, WOLFSSL_OP_NO_RENEGOTIATION);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* Client initiates renegotiation: it sends a ClientHello and waits for a
     * ServerHello that never comes. */
    ExpectIntLT(wolfSSL_Rehandshake(ssl_c), 0);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);

    /* Server processes the renegotiation ClientHello. It must refuse without
     * aborting: the read returns WANT_READ (connection still alive), not a
     * SECURE_RENEGOTIATION_E fatal error. */
    ExpectIntLT(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), 0);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);

    /* The refusal was a warning-level no_renegotiation alert. */
    ExpectIntEQ(wolfSSL_get_alert_history(ssl_s, &history), WOLFSSL_SUCCESS);
    ExpectIntEQ(history.last_tx.level, alert_warning);
    ExpectIntEQ(history.last_tx.code, no_renegotiation);

    /* The connection is still active and passes data: the server sends
     * application data which the client receives and decrypts correctly, even
     * though the client's renegotiation attempt was refused. The client
     * surfaces the data once it has processed the no_renegotiation warning. */
    ExpectIntEQ(wolfSSL_write(ssl_s, "hello", 5), 5);
    for (i = 0; i < 10 && ret != 5; i++)
        ret = wolfSSL_read(ssl_c, readBuf, sizeof(readBuf));
    ExpectIntEQ(ret, 5);
    ExpectIntEQ(XMEMCMP(readBuf, "hello", 5), 0);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* F-4144: WOLFSSL_OP_NO_RENEGOTIATION on the client must refuse a
 * server-initiated renegotiation (HelloRequest) with a no_renegotiation
 * *warning* while keeping the established connection alive, rather than
 * starting a secure renegotiation. */
int test_helloRequest_no_renegotiation_option(void)
{
    EXPECT_DECLS;
#if defined(HAVE_SECURE_RENEGOTIATION) && !defined(WOLFSSL_NO_TLS12) && \
        defined(BUILD_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) && \
        defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES)
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    WOLFSSL_ALERT_HISTORY history;
    byte readBuf[16];
    int ret = WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR);
    int i;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    XMEMSET(&history, 0, sizeof(history));
    test_ctx.c_ciphers = test_ctx.s_ciphers = "ECDHE-RSA-AES128-GCM-SHA256";

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c,
            &ssl_s, wolfTLSv1_2_client_method,
            wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(wolfSSL_CTX_UseSecureRenegotiation(ctx_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_UseSecureRenegotiation(ctx_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UseSecureRenegotiation(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UseSecureRenegotiation(ssl_s), WOLFSSL_SUCCESS);

    /* Client opts into rejecting peer-initiated renegotiation. */
    wolfSSL_set_options(ssl_c, WOLFSSL_OP_NO_RENEGOTIATION);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* Server asks the client to renegotiate by sending a HelloRequest, then
     * waits for the ClientHello that never comes. */
    ExpectIntLT(wolfSSL_Rehandshake(ssl_s), 0);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);

    /* Client processes the HelloRequest. It must refuse without starting a
     * renegotiation: the read returns WANT_READ (connection still alive). */
    ExpectIntLT(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), 0);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);

    /* The refusal was a warning-level no_renegotiation alert. */
    ExpectIntEQ(wolfSSL_get_alert_history(ssl_c, &history), WOLFSSL_SUCCESS);
    ExpectIntEQ(history.last_tx.level, alert_warning);
    ExpectIntEQ(history.last_tx.code, no_renegotiation);

    /* The connection is still active and passes data: the client sends
     * application data which the server receives and decrypts correctly, even
     * though its renegotiation request was refused. */
    ExpectIntEQ(wolfSSL_write(ssl_c, "hello", 5), 5);
    for (i = 0; i < 10 && ret != 5; i++)
        ret = wolfSSL_read(ssl_s, readBuf, sizeof(readBuf));
    ExpectIntEQ(ret, 5);
    ExpectIntEQ(XMEMCMP(readBuf, "hello", 5), 0);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* F-2126: DoTls13ClientHello must reject a second ClientHello whose
 * cipher suite does not match the server's HelloRetryRequest. The
 * client offers two suites in CH1 and only a different one in CH2. */
int test_tls13_hrr_cipher_suite_mismatch(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && \
        defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
        !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
        defined(BUILD_TLS_AES_128_GCM_SHA256) && \
        defined(BUILD_TLS_AES_256_GCM_SHA384)
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    int ret;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    /* Both suites supported on both ends; server prefers the first
     * offered suite, which will be the one committed in the HRR. */
    test_ctx.c_ciphers = test_ctx.s_ciphers =
            "TLS13-AES128-GCM-SHA256:TLS13-AES256-GCM-SHA384";

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);
    /* Force HRR by withholding key_share entries in CH1. */
    ExpectIntEQ(wolfSSL_NoKeyShares(ssl_c), WOLFSSL_SUCCESS);

    /* CH1 / HRR */
    ExpectIntEQ(wolfSSL_connect(ssl_c), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    ExpectIntEQ(wolfSSL_get_error(ssl_c, 0), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(wolfSSL_accept(ssl_s), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    ExpectIntEQ(wolfSSL_get_error(ssl_s, 0), WOLFSSL_ERROR_WANT_READ);

    /* Restrict the client to a different suite than the one the
     * server committed to in the HRR, so CH2 offers only that. */
    ExpectIntEQ(wolfSSL_set_cipher_list(ssl_c, "TLS13-AES256-GCM-SHA384"),
            WOLFSSL_SUCCESS);

    if (EXPECT_SUCCESS()) {
        /* CH2 */
        (void)wolfSSL_connect(ssl_c);
        (void)wolfSSL_accept(ssl_s);
        (void)wolfSSL_connect(ssl_c);
        /* The cipher-suite mismatch is caught server-side; the server's
         * alert reaches the client, so either peer can surface it. */
        ret = wolfSSL_get_error(ssl_s, 0);
        if (ret != WC_NO_ERR_TRACE(INVALID_PARAMETER))
            ret = wolfSSL_get_error(ssl_c, 0);
        ExpectIntEQ(ret, WC_NO_ERR_TRACE(INVALID_PARAMETER));
    }

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}


/* F-1824: DoClientTicketCheck must reject a PSK whose obfuscated age
 * falls outside the [-1000, MAX_TICKET_AGE_DIFF*1000+1000] ms window. */
int test_tls13_ticket_age_out_of_window(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && defined(HAVE_SESSION_TICKET) && \
        defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
        !defined(WOLFSSL_NO_DEF_TICKET_ENC_CB)
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    WOLFSSL_SESSION *session = NULL;
    byte tmp;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* Pump post-handshake reads so the NewSessionTicket reaches the
     * client. */
    (void)wolfSSL_read(ssl_c, &tmp, sizeof(tmp));
    (void)wolfSSL_read(ssl_s, &tmp, sizeof(tmp));
    (void)wolfSSL_read(ssl_c, &tmp, sizeof(tmp));

    ExpectNotNull(session = wolfSSL_get1_session(ssl_c));
    /* The test only exercises the age window check if the client actually
     * received a NewSessionTicket and the session carries ticket material. */
    ExpectIntGT(session->ticketLen, 0);

    /* Flip the high bit to push the unobfuscated age out of window. */
    if (session != NULL)
        session->ticketAdd ^= 0x80000000U;

    wolfSSL_free(ssl_c);
    ssl_c = NULL;
    wolfSSL_free(ssl_s);
    ssl_s = NULL;
    test_memio_clear_buffer(&test_ctx, 0);
    test_memio_clear_buffer(&test_ctx, 1);

    ExpectNotNull(ssl_c = wolfSSL_new(ctx_c));
    ExpectNotNull(ssl_s = wolfSSL_new(ctx_s));
    wolfSSL_SetIOReadCtx(ssl_c, &test_ctx);
    wolfSSL_SetIOWriteCtx(ssl_c, &test_ctx);
    wolfSSL_SetIOReadCtx(ssl_s, &test_ctx);
    wolfSSL_SetIOWriteCtx(ssl_s, &test_ctx);
    ExpectIntEQ(wolfSSL_set_session(ssl_c, session), WOLFSSL_SUCCESS);

    /* PSK rejected, full handshake must still succeed. */
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectIntEQ(wolfSSL_session_reused(ssl_s), 0);

    wolfSSL_SESSION_free(session);
    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}


int test_wolfSSL_DisableExtendedMasterSecret(void)
{
    EXPECT_DECLS;
#if defined(HAVE_EXTENDED_MASTER) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(NO_TLS)
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    WOLFSSL     *ssl = wolfSSL_new(ctx);

    ExpectNotNull(ctx);
    ExpectNotNull(ssl);

    /* error cases */
    ExpectIntNE(WOLFSSL_SUCCESS, wolfSSL_CTX_DisableExtendedMasterSecret(NULL));
    ExpectIntNE(WOLFSSL_SUCCESS, wolfSSL_DisableExtendedMasterSecret(NULL));

    /* success cases */
    ExpectIntEQ(WOLFSSL_SUCCESS, wolfSSL_CTX_DisableExtendedMasterSecret(ctx));
    ExpectIntEQ(WOLFSSL_SUCCESS, wolfSSL_DisableExtendedMasterSecret(ssl));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}


#if !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(WOLFSSL_NO_CA_NAMES) && !defined(NO_BIO) && \
    !defined(NO_CERTS) && !defined(NO_TLS) && (defined(OPENSSL_EXTRA) || \
    defined(OPENSSL_EXTRA_X509_SMALL)) && (defined(OPENSSL_ALL) || \
    defined(WOLFSSL_NGINX) || defined(HAVE_LIGHTY)) && \
    (defined(WOLFSSL_TLS13) || !defined(WOLFSSL_NO_TLS12)) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES)
struct client_cb_arg {
    WOLF_STACK_OF(X509_NAME) *names1;
    WOLF_STACK_OF(X509_NAME) *names2;
};

static int certificate_authorities_client_cb(WOLFSSL *ssl, void *_arg) {
    struct client_cb_arg *arg = (struct client_cb_arg *)_arg;
    arg->names1 = wolfSSL_get_client_CA_list(ssl);
    arg->names2 = wolfSSL_get0_peer_CA_list(ssl);

    if (!wolfSSL_use_certificate_file(ssl, cliCertFile, SSL_FILETYPE_PEM))
        return 0;
    if (!wolfSSL_use_PrivateKey_file(ssl, cliKeyFile, SSL_FILETYPE_PEM))
        return 0;
    return 1;
}
#endif

int test_certificate_authorities_certificate_request(void) {
    EXPECT_DECLS;
#if !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(WOLFSSL_NO_CA_NAMES) && !defined(NO_BIO) && \
    !defined(NO_CERTS) && !defined(NO_TLS) && (defined(OPENSSL_EXTRA) || \
    defined(OPENSSL_EXTRA_X509_SMALL)) && (defined(OPENSSL_ALL) || \
    defined(WOLFSSL_NGINX) || defined(HAVE_LIGHTY)) && \
    (defined(WOLFSSL_TLS13) || !defined(WOLFSSL_NO_TLS12)) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES)
    struct test_params {
        method_provider client_meth;
        method_provider server_meth;
        int             doUdp;
    } params[] = {
#ifdef WOLFSSL_TLS13
        /* TLS 1.3 uses certificate_authorities extension */
        {wolfTLSv1_3_client_method, wolfTLSv1_3_server_method, 0},
#endif
#if !defined(WOLFSSL_NO_TLS12) && (defined(OPENSSL_ALL) || \
            defined(WOLFSSL_NGINX) || defined(HAVE_LIGHTY))
        /* TLS 1.2 directly embeds CA names in CertificateRequest */
        {wolfTLSv1_2_client_method, wolfTLSv1_2_server_method, 0},
#endif
#ifdef WOLFSSL_DTLS13
        {wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method, 1},
#endif
#if defined(WOLFSSL_DTLS) && (defined(OPENSSL_ALL) || \
            defined(WOLFSSL_NGINX) || defined(HAVE_LIGHTY))
        {wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method, 1},
#endif
    };
    size_t i;

    for (i = 0; i < sizeof(params) / sizeof(*params); i++) {
        struct test_memio_ctx test_ctx;
        WOLFSSL_CTX *ctx_srv = NULL;
        WOLFSSL *ssl_srv = NULL;
        WOLFSSL_CTX *ctx_cli = NULL;
        WOLFSSL *ssl_cli = NULL;
        WOLF_STACK_OF(X509_NAME) *names1 = NULL, *names2 = NULL;
        X509_NAME *name = NULL;
        struct client_cb_arg cb_arg = { NULL, NULL };
        const char *expected_names[] = {
            "/C=US/ST=Montana/L=Bozeman/O=wolfSSL_2048/OU=Programming-2048"
                "/CN=www.wolfssl.com/emailAddress=info@wolfssl.com",
            "/C=US/ST=Montana/L=Bozeman/O=Sawtooth/OU=Consulting"
                "/CN=www.wolfssl.com/emailAddress=info@wolfssl.com"
        };

        if (EXPECT_FAIL())
            break;

        XMEMSET(&test_ctx, 0, sizeof(test_ctx));

        ExpectIntEQ(0, test_memio_setup(&test_ctx, &ctx_cli, &ctx_srv,
                    &ssl_cli, NULL, params[i].client_meth,
                    params[i].server_meth));

        wolfSSL_CTX_set_verify(ctx_srv,
                SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        ExpectIntEQ(WOLFSSL_SUCCESS,
                wolfSSL_CTX_load_verify_locations(ctx_srv, cliCertFile, NULL));

        ExpectNotNull(ssl_srv = wolfSSL_new(ctx_srv));
        wolfSSL_SetIOReadCtx(ssl_srv, &test_ctx);
        wolfSSL_SetIOWriteCtx(ssl_srv, &test_ctx);

        names1 = wolfSSL_load_client_CA_file(cliCertFile);
        ExpectNotNull(names1);
        names2 = wolfSSL_load_client_CA_file(caCertFile);
        ExpectNotNull(names2);
        ExpectNotNull(name = wolfSSL_sk_X509_NAME_value(names2, 0));
        ExpectIntEQ(2, wolfSSL_sk_X509_NAME_push(names1, name));
        if (EXPECT_FAIL()) {
            wolfSSL_X509_NAME_free(name);
            name = NULL;
        }
        wolfSSL_sk_X509_NAME_free(names2);
        names2 = wolfSSL_load_client_CA_file(caCertFile);
        ExpectNotNull(names2);

        /* Check that client_CA_list and CA_list are separate internally */
        wolfSSL_CTX_set_client_CA_list(ctx_srv, names1);
        wolfSSL_CTX_set0_CA_list(ctx_srv, names2);
        ExpectNotNull(names1 = wolfSSL_CTX_get_client_CA_list(ctx_srv));
        ExpectNotNull(names2 = wolfSSL_CTX_get0_CA_list(ctx_srv));
        ExpectIntEQ(2, wolfSSL_sk_X509_NAME_num(names1));
        ExpectIntEQ(1, wolfSSL_sk_X509_NAME_num(names2));

        /* Check that get_client_CA_list and get0_CA_list on ssl return same as
         * ctx when not set */
        ExpectNotNull(names1 = wolfSSL_get_client_CA_list(ssl_srv));
        ExpectNotNull(names2 = wolfSSL_get0_CA_list(ssl_srv));
        ExpectIntEQ(2, wolfSSL_sk_X509_NAME_num(names1));
        ExpectIntEQ(1, wolfSSL_sk_X509_NAME_num(names2));

        /* Same checks as before, but on ssl rather than ctx */
        names1 = wolfSSL_load_client_CA_file(cliCertFile);
        ExpectNotNull(names1);
        names2 = wolfSSL_load_client_CA_file(caCertFile);
        ExpectNotNull(names2);
        ExpectNotNull(name = wolfSSL_sk_X509_NAME_value(names2, 0));
        ExpectIntEQ(2, wolfSSL_sk_X509_NAME_push(names1, name));
        if (EXPECT_FAIL()) {
            wolfSSL_X509_NAME_free(name);
            name = NULL;
        }
        wolfSSL_sk_X509_NAME_free(names2);
        names2 = wolfSSL_load_client_CA_file(caCertFile);
        ExpectNotNull(names2);

        wolfSSL_set_client_CA_list(ssl_srv, names1);
        wolfSSL_set0_CA_list(ssl_srv, names2);
        ExpectNotNull(names1 = wolfSSL_get_client_CA_list(ssl_srv));
        ExpectNotNull(names2 = wolfSSL_get0_CA_list(ssl_srv));
        ExpectIntEQ(2, wolfSSL_sk_X509_NAME_num(names1));
        ExpectIntEQ(1, wolfSSL_sk_X509_NAME_num(names2));

#if !defined(NO_DH)
        SetDH(ssl_srv);
#endif

        /* Certs will be loaded in callback */
        wolfSSL_CTX_set_cert_cb(ctx_cli,
                certificate_authorities_client_cb, &cb_arg);

        ExpectIntEQ(0, test_memio_do_handshake(ssl_cli, ssl_srv, 10, NULL));

        ExpectNotNull(cb_arg.names1);
        ExpectNotNull(cb_arg.names2);
        ExpectIntEQ(2, wolfSSL_sk_X509_NAME_num(cb_arg.names1));
        ExpectIntEQ(2, wolfSSL_sk_X509_NAME_num(cb_arg.names2));

        if (EXPECT_SUCCESS()) {
            ExpectStrEQ(wolfSSL_sk_X509_NAME_value(cb_arg.names1, 0)->name,
                    expected_names[0]);
            ExpectStrEQ(wolfSSL_sk_X509_NAME_value(cb_arg.names1, 1)->name,
                    expected_names[1]);
        }

        wolfSSL_shutdown(ssl_cli);
        wolfSSL_free(ssl_cli);
        wolfSSL_CTX_free(ctx_cli);
        wolfSSL_free(ssl_srv);
        wolfSSL_CTX_free(ctx_srv);
    }
#endif
    return EXPECT_RESULT();
}


#if !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(WOLFSSL_NO_CA_NAMES) && !defined(NO_BIO) && \
    !defined(NO_CERTS) && (defined(OPENSSL_EXTRA) || \
    defined(OPENSSL_EXTRA_X509_SMALL)) && (defined(OPENSSL_ALL) || \
    defined(WOLFSSL_NGINX) || defined(HAVE_LIGHTY)) && \
    defined(WOLFSSL_TLS13) && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES)
static int certificate_authorities_server_cb(WOLFSSL *ssl, void *_arg) {
    WOLF_STACK_OF(X509_NAME) **names_out = (WOLF_STACK_OF(X509_NAME) **)_arg;
    WOLF_STACK_OF(X509_NAME) *names = wolfSSL_get0_peer_CA_list(ssl);
    *names_out = names;
    if (!wolfSSL_use_certificate_file(ssl, svrCertFile, SSL_FILETYPE_PEM))
        return 0;
    if (!wolfSSL_use_PrivateKey_file(ssl, svrKeyFile, SSL_FILETYPE_PEM))
        return 0;
    return 1;
}
#endif

#if defined(HAVE_TRUSTED_CA) && !defined(NO_SHA) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_WOLFSSL_SERVER) && !defined(NO_WOLFSSL_CLIENT)
/* Walk the TLSX list to find an extension by type. Avoids calling the
 * WOLFSSL_LOCAL TLSX_Find which is not available in shared library builds. */
static TLSX* test_TLSX_find_ext(TLSX* list, TLSX_Type type)
{
    while (list) {
        if (list->type == type)
            return list;
        list = list->next;
    }
    return NULL;
}
#endif

int test_TLSX_TCA_Find(void)
{
    EXPECT_DECLS;
#if defined(HAVE_TRUSTED_CA) && !defined(NO_SHA) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_WOLFSSL_SERVER) && !defined(NO_WOLFSSL_CLIENT)
    /* Two different 20-byte SHA1 ids */
    byte id_A[WC_SHA_DIGEST_SIZE];
    byte id_B[WC_SHA_DIGEST_SIZE];
    TLSX* ext;

    XMEMSET(id_A, 0xAA, sizeof(id_A));
    XMEMSET(id_B, 0xBB, sizeof(id_B));

    /* Test 1: Exact match - same type and same id should match */
    {
        struct test_memio_ctx test_ctx;
        WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
        WOLFSSL *ssl_c = NULL, *ssl_s = NULL;

        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c,
            &ssl_s, wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);

        /* Server has KEY_SHA1 with id_A */
        ExpectIntEQ(wolfSSL_UseTrustedCA(ssl_s, WOLFSSL_TRUSTED_CA_KEY_SHA1,
            id_A, sizeof(id_A)), WOLFSSL_SUCCESS);
        /* Client sends KEY_SHA1 with id_A (same) */
        ExpectIntEQ(wolfSSL_UseTrustedCA(ssl_c, WOLFSSL_TRUSTED_CA_KEY_SHA1,
            id_A, sizeof(id_A)), WOLFSSL_SUCCESS);

        ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

        /* Server should have found a match and responded */
        ext = test_TLSX_find_ext(ssl_c ? ssl_c->extensions : NULL,
            TLSX_TRUSTED_CA_KEYS);
        ExpectNotNull(ext);
        if (EXPECT_SUCCESS())
            ExpectIntEQ(ext->resp, 1);

        wolfSSL_free(ssl_c);
        wolfSSL_free(ssl_s);
        wolfSSL_CTX_free(ctx_c);
        wolfSSL_CTX_free(ctx_s);
    }

    /* Test 2: Same type, different id - should NOT match.
     * This is the key test that exposes the logic bug in TLSX_TCA_Find
     * where matching on type alone (without checking id content) causes
     * a false positive. */
    {
        struct test_memio_ctx test_ctx;
        WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
        WOLFSSL *ssl_c = NULL, *ssl_s = NULL;

        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c,
            &ssl_s, wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);

        /* Server has KEY_SHA1 with id_A */
        ExpectIntEQ(wolfSSL_UseTrustedCA(ssl_s, WOLFSSL_TRUSTED_CA_KEY_SHA1,
            id_A, sizeof(id_A)), WOLFSSL_SUCCESS);
        /* Client sends KEY_SHA1 with id_B (different!) */
        ExpectIntEQ(wolfSSL_UseTrustedCA(ssl_c, WOLFSSL_TRUSTED_CA_KEY_SHA1,
            id_B, sizeof(id_B)), WOLFSSL_SUCCESS);

        ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

        /* Server should NOT have found a match - ids differ */
        ext = test_TLSX_find_ext(ssl_c ? ssl_c->extensions : NULL,
            TLSX_TRUSTED_CA_KEYS);
        ExpectNotNull(ext);
        if (EXPECT_SUCCESS())
            ExpectIntEQ(ext->resp, 0);

        wolfSSL_free(ssl_c);
        wolfSSL_free(ssl_s);
        wolfSSL_CTX_free(ctx_c);
        wolfSSL_CTX_free(ctx_s);
    }

    /* Test 3: PRE_AGREED should match any server entry */
    {
        struct test_memio_ctx test_ctx;
        WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
        WOLFSSL *ssl_c = NULL, *ssl_s = NULL;

        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c,
            &ssl_s, wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);

        /* Server has KEY_SHA1 with id_A */
        ExpectIntEQ(wolfSSL_UseTrustedCA(ssl_s, WOLFSSL_TRUSTED_CA_KEY_SHA1,
            id_A, sizeof(id_A)), WOLFSSL_SUCCESS);
        /* Client sends PRE_AGREED (no id needed) */
        ExpectIntEQ(wolfSSL_UseTrustedCA(ssl_c, WOLFSSL_TRUSTED_CA_PRE_AGREED,
            NULL, 0), WOLFSSL_SUCCESS);

        ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

        /* Server should have matched (PRE_AGREED matches anything) */
        ext = test_TLSX_find_ext(ssl_c ? ssl_c->extensions : NULL,
            TLSX_TRUSTED_CA_KEYS);
        ExpectNotNull(ext);
        if (EXPECT_SUCCESS())
            ExpectIntEQ(ext->resp, 1);

        wolfSSL_free(ssl_c);
        wolfSSL_free(ssl_s);
        wolfSSL_CTX_free(ctx_c);
        wolfSSL_CTX_free(ctx_s);
    }
#endif
    return EXPECT_RESULT();
}

int test_certificate_authorities_client_hello(void) {
    EXPECT_DECLS;
#if !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(WOLFSSL_NO_CA_NAMES) && !defined(NO_BIO) && \
    !defined(NO_CERTS) && (defined(OPENSSL_EXTRA) || \
    defined(OPENSSL_EXTRA_X509_SMALL)) && (defined(OPENSSL_ALL) || \
    defined(WOLFSSL_NGINX) || defined(HAVE_LIGHTY)) && \
    defined(WOLFSSL_TLS13) && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES)

    struct test_params {
        method_provider client_meth;
        method_provider server_meth;
        int             doUdp;
    } params[] = {
    /* TLS >= 1.3 only */
#ifdef WOLFSSL_TLS13
        {wolfTLSv1_3_client_method, wolfTLSv1_3_server_method, 0},
#endif
#ifdef WOLFSSL_DTLS13
        {wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method, 1},
#endif
    };
    size_t i;

    for (i = 0; i < sizeof(params) / sizeof(*params); i++) {
        struct test_memio_ctx test_ctx;
        WOLFSSL_CTX *ctx_srv = NULL;
        WOLFSSL *ssl_srv = NULL;
        WOLFSSL_CTX *ctx_cli = NULL;
        WOLFSSL *ssl_cli = NULL;
        WOLF_STACK_OF(X509_NAME) *cb_arg = NULL;
        WOLF_STACK_OF(X509_NAME) *names1 = NULL, *names2 = NULL;
        X509_NAME *name = NULL;
        const char *expected_names[] = {
            "/C=US/ST=Montana/L=Bozeman/O=Sawtooth/OU=Consulting"
                "/CN=www.wolfssl.com/emailAddress=info@wolfssl.com",
            "/C=US/ST=Montana/L=Bozeman/O=wolfSSL_2048/OU=Programming-2048"
                "/CN=www.wolfssl.com/emailAddress=info@wolfssl.com"
        };

        if (EXPECT_FAIL())
            break;

        XMEMSET(&test_ctx, 0, sizeof(test_ctx));

        ExpectIntEQ(0, test_memio_setup(&test_ctx, &ctx_cli, &ctx_srv,
                    &ssl_cli, &ssl_srv, params[i].client_meth,
                    params[i].server_meth));

        wolfSSL_CTX_set_cert_cb(ctx_srv, certificate_authorities_server_cb,
                &cb_arg);

        names1 = wolfSSL_load_client_CA_file(caCertFile);
        ExpectNotNull(names1);
        names2 = wolfSSL_load_client_CA_file(cliCertFile);
        ExpectNotNull(names2);
        ExpectNotNull(name = wolfSSL_sk_X509_NAME_value(names2, 0));
        ExpectIntEQ(2, wolfSSL_sk_X509_NAME_push(names1, name));
        if (EXPECT_FAIL()) {
            wolfSSL_X509_NAME_free(name);
            name = NULL;
        }
        wolfSSL_sk_X509_NAME_free(names2);
        names2 = wolfSSL_load_client_CA_file(cliCertFile);
        ExpectNotNull(names2);

        /* verify that set0_CA_list takes precedence */
        wolfSSL_set0_CA_list(ssl_cli, names1);
        wolfSSL_CTX_set0_CA_list(ctx_cli, names2);

        ExpectIntEQ(0, test_memio_do_handshake(ssl_cli, ssl_srv, 10, NULL));

        ExpectIntEQ(wolfSSL_sk_X509_NAME_num(cb_arg), 2);

        if (EXPECT_SUCCESS()) {
            ExpectStrEQ(wolfSSL_sk_X509_NAME_value(cb_arg, 0)->name,
                    expected_names[0]);
            ExpectStrEQ(wolfSSL_sk_X509_NAME_value(cb_arg, 1)->name,
                    expected_names[1]);
        }

        wolfSSL_shutdown(ssl_cli);
        wolfSSL_free(ssl_cli);
        wolfSSL_CTX_free(ctx_cli);
        wolfSSL_free(ssl_srv);
        wolfSSL_CTX_free(ctx_srv);
    }
#endif
    return EXPECT_RESULT();
}

/* Test that the SNI size calculation returns 0 on overflow instead of
 * wrapping around to a small value (integer overflow vulnerability). */
int test_TLSX_SNI_GetSize_overflow(void)
{
    EXPECT_DECLS;
#if defined(HAVE_SNI) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    TLSX* sni_ext = NULL;
    SNI* head = NULL;
    SNI* sni = NULL;
    int i;
    /* Each SNI adds ENUM_LEN(1) + OPAQUE16_LEN(2) + hostname_len to the size.
     * With a 1-byte hostname, each entry adds 4 bytes. Starting from
     * OPAQUE16_LEN(2) base, we need enough entries to exceed UINT16_MAX. */
    const int num_sni = (0xFFFF / 4) + 2;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* Add initial SNI via public API */
    ExpectIntEQ(WOLFSSL_SUCCESS,
                wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, "a", 1));

    /* Find the SNI extension and manually build a long chain */
    if (EXPECT_SUCCESS()) {
        sni_ext = TLSX_Find(ssl->extensions, TLSX_SERVER_NAME);
        ExpectNotNull(sni_ext);
    }

    if (EXPECT_SUCCESS()) {
        head = (SNI*)sni_ext->data;
        ExpectNotNull(head);
    }

    /* Append many SNI nodes to force overflow in the size calculation */
    for (i = 1; EXPECT_SUCCESS() && i < num_sni; i++) {
        sni = (SNI*)XMALLOC(sizeof(SNI), NULL, DYNAMIC_TYPE_TLSX);
        ExpectNotNull(sni);
        if (sni != NULL) {
            XMEMSET(sni, 0, sizeof(SNI));
            sni->type = WOLFSSL_SNI_HOST_NAME;
            sni->data.host_name = (char*)XMALLOC(2, NULL, DYNAMIC_TYPE_TLSX);
            ExpectNotNull(sni->data.host_name);
            if (sni->data.host_name != NULL) {
                sni->data.host_name[0] = 'a';
                sni->data.host_name[1] = '\0';
            }
            sni->next = head->next;
            head->next = sni;
        }
    }

    if (EXPECT_SUCCESS()) {
        /* The fixed calculation should return 0 (overflow detected) */
        ExpectIntEQ(TLSX_SNI_GetSize((SNI*)sni_ext->data), 0);
    }

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* ECH is only valid in ClientHello, EncryptedExtensions, or
 * HelloRetryRequest per RFC 9460. Feeding it in a Finished message must
 * be rejected with EXT_NOT_ALLOWED rather than being silently accepted. */
int test_TLSX_ECH_msg_type_validation(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && defined(HAVE_ECH) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    /* type = TLSX_ECH (0xfe0d), size = 0x0000 */
    const byte extBytes[] = { 0xfe, 0x0d, 0x00, 0x00 };

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    ExpectIntEQ(TLSX_Parse(ssl, extBytes, (word16)sizeof(extBytes),
                           finished, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* use_srtp is only valid in ClientHello/ServerHello (pre-TLS 1.3) or
 * ClientHello/EncryptedExtensions (TLS 1.3) per RFC 5764. Feeding it in a
 * Finished message must be rejected with EXT_NOT_ALLOWED. */
int test_TLSX_SRTP_msg_type_validation(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SRTP) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    /* type = TLSX_USE_SRTP (0x000e), size = 0x0000 */
    const byte extBytes[] = { 0x00, 0x0e, 0x00, 0x00 };

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    ExpectIntEQ(TLSX_Parse(ssl, extBytes, (word16)sizeof(extBytes),
                           finished, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* RFC 7301 Section 3.1: the server's ProtocolNameList in its ALPN response
 * MUST contain exactly one ProtocolName. A ServerHello carrying two entries
 * must be rejected rather than silently accepted. */
int test_TLSX_ALPN_server_response_count(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ALPN) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    /* ServerHello-style ALPN extension whose ProtocolNameList contains
     * two entries ("h2" and "http/1.1"). */
    static const byte extBytes[] = {
        0x00, 0x10,                         /* extension type = ALPN (16) */
        0x00, 0x0E,                         /* extension length = 14    */
        0x00, 0x0C,                         /* ProtocolNameList length  */
        0x02, 'h', '2',                     /* entry 1: "h2"            */
        0x08, 'h', 't', 't', 'p', '/', '1', '.', '1' /* entry 2         */
    };
    static char alpn_h2[] = "h2";

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    ExpectIntEQ(wolfSSL_UseALPN(ssl, alpn_h2, (unsigned int)XSTRLEN(alpn_h2),
                                WOLFSSL_ALPN_FAILED_ON_MISMATCH),
                WOLFSSL_SUCCESS);

    ExpectIntEQ(TLSX_Parse(ssl, extBytes, (word16)sizeof(extBytes),
                           server_hello, NULL),
                WC_NO_ERR_TRACE(BUFFER_ERROR));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* Regression test for the supported_groups (a.k.a. supported curves) parsing.
 *
 * A client that explicitly sends a supported_groups extension restricts the
 * groups the server may use. An empty list, or a list that contains only
 * groups the server does not support, must NOT be silently treated as if the
 * extension was absent (which would impose no restriction and let the server
 * pick an ECDHE suite/curve the client never advertised).
 *
 *  - An empty named group list is malformed and must be rejected.
 *  - A list of only-unsupported groups must still leave a supported_groups
 *    node behind so suite selection sees the restriction.
 */
int test_TLSX_SupportedCurve_empty_or_unsupported(void)
{
    EXPECT_DECLS;
#if !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    defined(HAVE_SUPPORTED_CURVES) && !defined(WOLFSSL_NO_TLS12) && \
    (!defined(NO_WOLFSSL_SERVER) || (defined(WOLFSSL_TLS13) && \
                                     !defined(WOLFSSL_NO_SERVER_GROUPS_EXT)))
    /* This exercises the server's parsing of a received ClientHello: the
     * relevant code path (TLSX_SupportedCurve_Parse) is selected by the
     * message type passed to TLSX_Parse (client_hello => isRequest), not by
     * the side of the WOLFSSL object. A client-side WOLFSSL is used purely as
     * the parse vehicle because creating a server-side WOLFSSL would require a
     * certificate to be loaded first (NO_PRIVATE_KEY otherwise). */
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    Suites* suites = NULL;
    /* supported_groups (0x000a), ext len 0x0002, named_group_list len 0x0000 */
    const byte emptyList[] = { 0x00, 0x0a, 0x00, 0x02, 0x00, 0x00 };
    /* supported_groups (0x000a), ext len 0x0004, list len 0x0002,
     * group 0xeeee (private-use value we do not support) */
    const byte unsupportedOnly[] = { 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02,
                                     0xee, 0xee };

    /* An empty named group list is malformed and must be rejected. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL)
        suites = (Suites*)WOLFSSL_SUITES(ssl);
    ExpectIntEQ(TLSX_Parse(ssl, emptyList, (word16)sizeof(emptyList),
                           client_hello, suites),
                WC_NO_ERR_TRACE(BUFFER_ERROR));
    wolfSSL_free(ssl);
    ssl = NULL;

    /* A list with only unsupported groups must still record a supported_groups
     * node so that ECC/ECDHE suite selection sees the (now empty) restriction
     * instead of treating the extension as absent. */
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL)
        suites = (Suites*)WOLFSSL_SUITES(ssl);
    /* Precondition: server has not preconfigured supported groups. */
    ExpectNull(TLSX_Find(ssl->extensions, TLSX_SUPPORTED_GROUPS));
    ExpectIntEQ(TLSX_Parse(ssl, unsupportedOnly, (word16)sizeof(unsupportedOnly),
                           client_hello, suites), 0);
    /* The fix records an (empty) supported_groups node. */
    ExpectNotNull(TLSX_Find(ssl->extensions, TLSX_SUPPORTED_GROUPS));
    wolfSSL_free(ssl);
    ssl = NULL;

    wolfSSL_CTX_free(ctx);

#if defined(WOLFSSL_TLS13) && !defined(NO_WOLFSSL_CLIENT)
    /* An empty named group list is equally malformed in a TLS 1.3
     * EncryptedExtensions message (named_group_list<2..2^16-1>) and must be
     * rejected with the same decode_error (BUFFER_ERROR), not silently
     * accepted as the server advertising no groups. */
    {
        WOLFSSL_CTX* ctx13 = NULL;
        WOLFSSL* ssl13 = NULL;
        const byte emptyListEE[] = { 0x00, 0x0a, 0x00, 0x02, 0x00, 0x00 };

        ExpectNotNull(ctx13 = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
        ExpectNotNull(ssl13 = wolfSSL_new(ctx13));
        /* Ensure the connection is treated as TLS 1.3 so EncryptedExtensions
         * is a valid context for the extension. */
        if (ssl13 != NULL) {
            ssl13->version.major = SSLv3_MAJOR;
            ssl13->version.minor = TLSv1_3_MINOR;
        }
        ExpectIntEQ(TLSX_Parse(ssl13, emptyListEE, (word16)sizeof(emptyListEE),
                               encrypted_extensions, NULL),
                    WC_NO_ERR_TRACE(BUFFER_ERROR));
        wolfSSL_free(ssl13);
        wolfSSL_CTX_free(ctx13);
    }
#endif
#endif
    return EXPECT_RESULT();
}

/* RFC 8422 Section 5.1.2: a client that sends the ec_point_formats extension
 * MUST include the uncompressed (0) point format. When the uncompressed format
 * is omitted the server records this (ssl->options.peerNoUncompPF) during
 * parsing so the handshake can be aborted with an illegal_parameter alert if
 * the client also advertised ECC named groups.
 *
 *  - A list that contains the uncompressed format must clear the flag.
 *  - A list that omits the uncompressed format must set the flag.
 */
int test_TLSX_PointFormat_uncompressed_required(void)
{
    EXPECT_DECLS;
#if !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(NO_TLS) && defined(HAVE_SUPPORTED_CURVES) && \
    defined(HAVE_TLS_EXTENSIONS) && !defined(WOLFSSL_NO_TLS12)
    /* This exercises the server's parsing of a received ClientHello: the
     * relevant code path (TLSX_PointFormat_Parse) is selected by the message
     * type passed to TLSX_Parse (client_hello => isRequest), not by the side
     * of the WOLFSSL object. A client-side WOLFSSL is used purely as the parse
     * vehicle because creating a server-side WOLFSSL would require a
     * certificate to be loaded first (NO_PRIVATE_KEY otherwise). The server
     * build is required because TLSX_PointFormat_Parse (the PF_PARSE dispatch
     * macro) is compiled to a no-op when NO_WOLFSSL_SERVER is defined. */
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    Suites* suites = NULL;
    /* ec_point_formats (0x000b), ext len 0x0002, list len 0x01,
     * format 0x00 (uncompressed) */
    const byte withUncomp[]  = { 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00 };
    /* ec_point_formats (0x000b), ext len 0x0002, list len 0x01,
     * format 0x01 (ansiX962_compressed_prime, uncompressed omitted) */
    const byte noUncomp[]    = { 0x00, 0x0b, 0x00, 0x02, 0x01, 0x01 };
    /* As above but with two compressed formats and no uncompressed. */
    const byte noUncomp2[]   = { 0x00, 0x0b, 0x00, 0x03, 0x02, 0x01, 0x02 };

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));

    /* A list containing the uncompressed format leaves the flag clear and
     * still adds the uncompressed format to the response. */
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL)
        suites = (Suites*)WOLFSSL_SUITES(ssl);
    ExpectIntEQ(TLSX_Parse(ssl, withUncomp, (word16)sizeof(withUncomp),
                           client_hello, suites), 0);
    if (ssl != NULL)
        ExpectIntEQ(ssl->options.peerNoUncompPF, 0);
    ExpectNotNull(TLSX_Find(ssl->extensions, TLSX_EC_POINT_FORMATS));
    wolfSSL_free(ssl);
    ssl = NULL;

    /* A single-entry list that omits the uncompressed format sets the flag. */
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL)
        suites = (Suites*)WOLFSSL_SUITES(ssl);
    ExpectIntEQ(TLSX_Parse(ssl, noUncomp, (word16)sizeof(noUncomp),
                           client_hello, suites), 0);
    if (ssl != NULL)
        ExpectIntEQ(ssl->options.peerNoUncompPF, 1);
    wolfSSL_free(ssl);
    ssl = NULL;

    /* A multi-entry list that omits the uncompressed format sets the flag. */
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL)
        suites = (Suites*)WOLFSSL_SUITES(ssl);
    ExpectIntEQ(TLSX_Parse(ssl, noUncomp2, (word16)sizeof(noUncomp2),
                           client_hello, suites), 0);
    if (ssl != NULL)
        ExpectIntEQ(ssl->options.peerNoUncompPF, 1);
    wolfSSL_free(ssl);
    ssl = NULL;

    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}
