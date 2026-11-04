/* test_ecjpake.c
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
#include <tests/api/api.h>
#include <tests/api/test_ecjpake.h>

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_DTLS_ECJPAKE) && defined(WOLFSSL_DTLS) && \
    !defined(WOLFSSL_NO_TLS12) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(NO_WOLFSSL_SERVER)

#define ECJPAKE_SUITE   "ECJPAKE-AES128-CCM-8"

static const unsigned char ecjpakePw[] = "J01NME";
static const unsigned char ecjpakeOtherPw[] = "J01NMF";

/* ecjpake_key_kp_pair extension header: type 0x0100, length 330 */
static const byte ecjpakeExtHdr[] = { 0x01, 0x00, 0x01, 0x4a };
/* ServerECJPAKEParams: secp256r1 ECParameters, then ECPoint X */
static const byte ecjpakeSkeHdr[] = { 0x03, 0x00, 0x17, 0x41, 0x04 };
/* supported_groups with secp256r1 only */
static const byte ecjpakeGroups[] = {
    0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x17
};
/* ec_point_formats with uncompressed only */
static const byte ecjpakePointFormats[] = { 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00 };
/* ClientKeyExchange handshake header: type, 24-bit length 165 */
static const byte ecjpakeCkeHdr[] = { client_key_exchange, 0x00, 0x00, 0xa5 };

/* Index of the last octet of the first proof's r in an ECJPAKEKeyKP. */
#define ECJPAKE_KKP_R_LAST  (WC_ECJPAKE_KKP_SZ - 1)

static int ecjpake_find(const byte* buf, int len, const byte* pat, int patSz)
{
    int i;

    for (i = 0; i + patSz <= len; i++) {
        if (XMEMCMP(buf + i, pat, (size_t)patSz) == 0)
            return i;
    }
    return -1;
}

/* DTLS 1.2 client, given a password when cPw is not NULL, and a
 * certificate-less server with a password on its context. */
static int ecjpake_setup(struct test_memio_ctx* test_ctx, WOLFSSL_CTX** ctx_c,
                         WOLFSSL_CTX** ctx_s, WOLFSSL** ssl_c, WOLFSSL** ssl_s,
                         const unsigned char* cPw, const unsigned char* sPw)
{
    EXPECT_DECLS;

    XMEMSET(test_ctx, 0, sizeof(*test_ctx));
    ExpectNotNull(*ctx_s = wolfSSL_CTX_new(wolfDTLSv1_2_server_method()));
    if (*ctx_s != NULL) {
        wolfSSL_SetIORecv(*ctx_s, test_memio_read_cb);
        wolfSSL_SetIOSend(*ctx_s, test_memio_write_cb);
    }
    ExpectIntEQ(wolfSSL_CTX_set_ecjpake_password(*ctx_s, sPw,
                    (unsigned int)XSTRLEN((const char*)sPw)),
                WOLFSSL_SUCCESS);
    ExpectIntEQ(test_memio_setup(test_ctx, ctx_c, ctx_s, ssl_c, ssl_s,
                    wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method),
                0);
    if (cPw != NULL) {
        ExpectIntEQ(wolfSSL_set_ecjpake_password(*ssl_c, cPw,
                        (unsigned int)XSTRLEN((const char*)cPw)),
                    WOLFSSL_SUCCESS);
    }

    return EXPECT_RESULT();
}

static void ecjpake_cleanup(WOLFSSL_CTX* ctx_c, WOLFSSL_CTX* ctx_s,
                            WOLFSSL* ssl_c, WOLFSSL* ssl_s)
{
    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
}

/* Runs the handshake up to the server's first flight after the cookie
 * exchange: ServerHello, ServerKeyExchange and ServerHelloDone are left in
 * the client's buffer. */
static int ecjpake_to_server_flight(struct test_memio_ctx* test_ctx,
                                    WOLFSSL* ssl_c, WOLFSSL* ssl_s)
{
    EXPECT_DECLS;

    ExpectIntEQ(wolfSSL_connect(ssl_c), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WOLFSSL_FATAL_ERROR),
                WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(wolfSSL_accept(ssl_s), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_connect(ssl_c), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_accept(ssl_s), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WOLFSSL_FATAL_ERROR),
                WOLFSSL_ERROR_WANT_READ);
    ExpectIntGT(test_ctx->c_len, 0);

    return EXPECT_RESULT();
}

/* Has the client read the server's pending alert and checks that it was a
 * fatal handshake_failure. */
static int ecjpake_client_got_handshake_failure(WOLFSSL* ssl_c)
{
    EXPECT_DECLS;
    WOLFSSL_ALERT_HISTORY h;

    ExpectIntEQ(wolfSSL_connect(ssl_c), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_get_alert_history(ssl_c, &h), WOLFSSL_SUCCESS);
    ExpectIntEQ(h.last_rx.level, alert_fatal);
    ExpectIntEQ(h.last_rx.code, handshake_failure);

    return EXPECT_RESULT();
}

/* Checks that ssl received a fatal handshake_failure alert. */
static int ecjpake_got_handshake_failure(WOLFSSL* ssl)
{
    EXPECT_DECLS;
    WOLFSSL_ALERT_HISTORY h;

    ExpectIntEQ(wolfSSL_get_alert_history(ssl, &h), WOLFSSL_SUCCESS);
    ExpectIntEQ(h.last_rx.level, alert_fatal);
    ExpectIntEQ(h.last_rx.code, handshake_failure);

    return EXPECT_RESULT();
}
#endif /* HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES && WOLFSSL_DTLS_ECJPAKE */

/* Full DTLS 1.2 handshake with a cookie exchange, the ClientHello sent again
 * carrying the same round one message, the hello extensions of Section 7.2.1,
 * and application data both ways. */
int test_wolfSSL_ecjpake_dtls12(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_DTLS_ECJPAKE) && defined(WOLFSSL_DTLS) && \
    !defined(WOLFSSL_NO_TLS12) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(NO_WOLFSSL_SERVER)
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    byte ch1[TEST_MEMIO_BUF_SZ];
    int ch1Sz = 0;
    int off1 = -1, off2 = -1;
    char buf[16];

    ExpectIntEQ(ecjpake_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    ecjpakePw, ecjpakePw), TEST_SUCCESS);

    /* ClientHello, HelloVerifyRequest, ClientHello with cookie */
    ExpectIntEQ(wolfSSL_connect(ssl_c), WOLFSSL_FATAL_ERROR);
    if (EXPECT_SUCCESS()) {
        ch1Sz = test_ctx.s_len;
        XMEMCPY(ch1, test_ctx.s_buff, (size_t)ch1Sz);
    }
    ExpectIntEQ(wolfSSL_accept(ssl_s), WOLFSSL_FATAL_ERROR);
    ExpectIntGT(test_ctx.c_len, DTLS_RECORD_HEADER_SZ);
    ExpectIntEQ(test_ctx.c_buff[DTLS_RECORD_HEADER_SZ], hello_verify_request);
    ExpectIntEQ(wolfSSL_connect(ssl_c), WOLFSSL_FATAL_ERROR);

    ExpectIntGE(off1 = ecjpake_find(ch1, ch1Sz, ecjpakeExtHdr,
                                    sizeof(ecjpakeExtHdr)), 0);
    ExpectIntGE(off2 = ecjpake_find(test_ctx.s_buff, test_ctx.s_len,
                                    ecjpakeExtHdr, sizeof(ecjpakeExtHdr)), 0);
    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(XMEMCMP(ch1 + off1, test_ctx.s_buff + off2,
                            sizeof(ecjpakeExtHdr) + WC_ECJPAKE_ROUND1_SZ), 0);
    }
    ExpectIntGE(ecjpake_find(test_ctx.s_buff, test_ctx.s_len, ecjpakeGroups,
                             sizeof(ecjpakeGroups)), 0);
    ExpectIntGE(ecjpake_find(test_ctx.s_buff, test_ctx.s_len,
                    ecjpakePointFormats, sizeof(ecjpakePointFormats)), 0);

    /* ServerHello */
    ExpectIntEQ(wolfSSL_accept(ssl_s), WOLFSSL_FATAL_ERROR);
    ExpectIntGE(ecjpake_find(test_ctx.c_buff, test_ctx.c_len, ecjpakeExtHdr,
                             sizeof(ecjpakeExtHdr)), 0);
    ExpectIntGE(ecjpake_find(test_ctx.c_buff, test_ctx.c_len,
                    ecjpakePointFormats, sizeof(ecjpakePointFormats)), 0);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectStrEQ(wolfSSL_get_cipher_name(ssl_c), ECJPAKE_SUITE);
    ExpectStrEQ(wolfSSL_get_cipher_name(ssl_s), ECJPAKE_SUITE);
    ExpectIntEQ(wolfSSL_write(ssl_c, "ping", 4), 4);
    ExpectIntEQ(wolfSSL_read(ssl_s, buf, sizeof(buf)), 4);
    ExpectIntEQ(XMEMCMP(buf, "ping", 4), 0);
    ExpectIntEQ(wolfSSL_write(ssl_s, "pong", 4), 4);
    ExpectIntEQ(wolfSSL_read(ssl_c, buf, sizeof(buf)), 4);
    ExpectIntEQ(XMEMCMP(buf, "pong", 4), 0);
    ExpectNull(ssl_c == NULL ? NULL : ssl_c->ecJpake);
    ExpectNull(ssl_s == NULL ? NULL : ssl_s->ecJpake);

    ecjpake_cleanup(ctx_c, ctx_s, ssl_c, ssl_s);
#endif
    return EXPECT_RESULT();
}

/* Different passwords complete the key exchange with different secrets, so
 * the Finished messages never verify and neither side finishes. */
int test_wolfSSL_ecjpake_wrong_password(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_DTLS_ECJPAKE) && defined(WOLFSSL_DTLS) && \
    !defined(WOLFSSL_NO_TLS12) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(NO_WOLFSSL_SERVER)
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;

    ExpectIntEQ(ecjpake_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    ecjpakePw, ecjpakeOtherPw), TEST_SUCCESS);
    ExpectIntNE(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectFalse(wolfSSL_is_init_finished(ssl_c));
    ExpectFalse(wolfSSL_is_init_finished(ssl_s));

    ecjpake_cleanup(ctx_c, ctx_s, ssl_c, ssl_s);
#endif
    return EXPECT_RESULT();
}

/* A client offering the suite without the extension or without secp256r1,
 * or a server without a password, fails with handshake_failure (Section 6). */
int test_wolfSSL_ecjpake_negotiation(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_DTLS_ECJPAKE) && defined(WOLFSSL_DTLS) && \
    !defined(WOLFSSL_NO_TLS12) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(NO_WOLFSSL_SERVER)
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;

    /* Suite offered without the extension. */
    ExpectIntEQ(ecjpake_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    NULL, ecjpakePw), TEST_SUCCESS);
    ExpectIntEQ(wolfSSL_set_cipher_list(ssl_c, ECJPAKE_SUITE),
                WOLFSSL_SUCCESS);
    ExpectIntNE(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectIntEQ(ecjpake_client_got_handshake_failure(ssl_c),
                TEST_SUCCESS);
    ecjpake_cleanup(ctx_c, ctx_s, ssl_c, ssl_s);
    ctx_c = NULL; ctx_s = NULL; ssl_c = NULL; ssl_s = NULL;

#if defined(HAVE_SUPPORTED_CURVES) && \
    (defined(HAVE_ECC384) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 384
    /* Client supported groups without secp256r1. */
    ExpectIntEQ(ecjpake_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    NULL, ecjpakePw), TEST_SUCCESS);
    ExpectIntEQ(wolfSSL_UseSupportedCurve(ssl_c, WOLFSSL_ECC_SECP384R1),
                WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_ecjpake_password(ssl_c, ecjpakePw,
                    (unsigned int)XSTRLEN((const char*)ecjpakePw)),
                WOLFSSL_SUCCESS);
    ExpectIntNE(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectIntEQ(ecjpake_client_got_handshake_failure(ssl_c),
                TEST_SUCCESS);
    ecjpake_cleanup(ctx_c, ctx_s, ssl_c, ssl_s);
    ctx_c = NULL; ctx_s = NULL; ssl_c = NULL; ssl_s = NULL;
#endif

    /* Certificate server without a password. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method),
                0);
    ExpectIntEQ(wolfSSL_set_ecjpake_password(ssl_c, ecjpakePw,
                    (unsigned int)XSTRLEN((const char*)ecjpakePw)),
                WOLFSSL_SUCCESS);
    ExpectIntNE(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
#ifdef WOLFSSL_EXTRA_ALERTS
    ExpectIntEQ(ecjpake_client_got_handshake_failure(ssl_c),
                TEST_SUCCESS);
#endif
    ecjpake_cleanup(ctx_c, ctx_s, ssl_c, ssl_s);
    ctx_c = NULL; ctx_s = NULL; ssl_c = NULL; ssl_s = NULL;

#ifndef WOLFSSL_NO_TLS12
    /* The suite is not selected over TLS even when both sides list it. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    test_ctx.c_ciphers = ECJPAKE_SUITE;
    test_ctx.s_ciphers = ECJPAKE_SUITE;
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    ExpectIntNE(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
#ifdef WOLFSSL_EXTRA_ALERTS
    ExpectIntEQ(ecjpake_client_got_handshake_failure(ssl_c),
                TEST_SUCCESS);
#endif
    ecjpake_cleanup(ctx_c, ctx_s, ssl_c, ssl_s);
#endif
#endif
    return EXPECT_RESULT();
}

/* A corrupted proof in any of the three EC-JPAKE messages ends the handshake
 * with handshake_failure from the side that checked it. */
int test_wolfSSL_ecjpake_bad_proof(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_DTLS_ECJPAKE) && defined(WOLFSSL_DTLS) && \
    !defined(WOLFSSL_NO_TLS12) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(NO_WOLFSSL_SERVER)
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    int off = -1;

    /* Server round one in ServerHello. */
    ExpectIntEQ(ecjpake_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    ecjpakePw, ecjpakePw), TEST_SUCCESS);
    ExpectIntEQ(ecjpake_to_server_flight(&test_ctx, ssl_c, ssl_s),
                TEST_SUCCESS);
    ExpectIntGE(off = ecjpake_find(test_ctx.c_buff, test_ctx.c_len,
                    ecjpakeExtHdr, sizeof(ecjpakeExtHdr)), 0);
    if (EXPECT_SUCCESS())
        test_ctx.c_buff[off + sizeof(ecjpakeExtHdr) + ECJPAKE_KKP_R_LAST] ^= 1;
    ExpectIntEQ(wolfSSL_connect(ssl_c), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WOLFSSL_FATAL_ERROR),
                WC_NO_ERR_TRACE(SIG_VERIFY_E));
    ExpectIntEQ(wolfSSL_accept(ssl_s), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(ecjpake_got_handshake_failure(ssl_s), TEST_SUCCESS);
    ecjpake_cleanup(ctx_c, ctx_s, ssl_c, ssl_s);
    ctx_c = NULL; ctx_s = NULL; ssl_c = NULL; ssl_s = NULL;

    /* Server round two in ServerKeyExchange. */
    ExpectIntEQ(ecjpake_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    ecjpakePw, ecjpakePw), TEST_SUCCESS);
    ExpectIntEQ(ecjpake_to_server_flight(&test_ctx, ssl_c, ssl_s),
                TEST_SUCCESS);
    ExpectIntGE(off = ecjpake_find(test_ctx.c_buff, test_ctx.c_len,
                    ecjpakeSkeHdr, sizeof(ecjpakeSkeHdr)), 0);
    if (EXPECT_SUCCESS()) {
        test_ctx.c_buff[off + WC_ECJPAKE_ECPARAMS_SZ +
                        ECJPAKE_KKP_R_LAST] ^= 1;
    }
    ExpectIntEQ(wolfSSL_connect(ssl_c), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WOLFSSL_FATAL_ERROR),
                WC_NO_ERR_TRACE(SIG_VERIFY_E));
    ExpectIntEQ(wolfSSL_accept(ssl_s), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(ecjpake_got_handshake_failure(ssl_s), TEST_SUCCESS);
    ecjpake_cleanup(ctx_c, ctx_s, ssl_c, ssl_s);
    ctx_c = NULL; ctx_s = NULL; ssl_c = NULL; ssl_s = NULL;

    /* Client round two in ClientKeyExchange. */
    ExpectIntEQ(ecjpake_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    ecjpakePw, ecjpakePw), TEST_SUCCESS);
    ExpectIntEQ(ecjpake_to_server_flight(&test_ctx, ssl_c, ssl_s),
                TEST_SUCCESS);
    ExpectIntEQ(wolfSSL_connect(ssl_c), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WOLFSSL_FATAL_ERROR),
                WOLFSSL_ERROR_WANT_READ);
    ExpectIntGE(off = ecjpake_find(test_ctx.s_buff, test_ctx.s_len,
                    ecjpakeCkeHdr, sizeof(ecjpakeCkeHdr)), 0);
    if (EXPECT_SUCCESS()) {
        test_ctx.s_buff[off + DTLS_HANDSHAKE_HEADER_SZ +
                        ECJPAKE_KKP_R_LAST] ^= 1;
    }
    ExpectIntEQ(wolfSSL_accept(ssl_s), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WOLFSSL_FATAL_ERROR),
                WC_NO_ERR_TRACE(SIG_VERIFY_E));
    ExpectIntEQ(wolfSSL_connect(ssl_c), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(ecjpake_got_handshake_failure(ssl_c), TEST_SUCCESS);
    ecjpake_cleanup(ctx_c, ctx_s, ssl_c, ssl_s);
#endif
    return EXPECT_RESULT();
}

/* Arguments, the DTLS 1.2 method requirement, and objects inheriting the
 * context's password. */
int test_wolfSSL_ecjpake_set_password(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_DTLS_ECJPAKE) && defined(WOLFSSL_DTLS) && \
    !defined(WOLFSSL_NO_TLS12) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(NO_WOLFSSL_SERVER)
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx = NULL, *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl = NULL, *ssl_c = NULL, *ssl_s = NULL;

    ExpectIntEQ(wolfSSL_set_ecjpake_password(NULL, ecjpakePw, 1),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CTX_set_ecjpake_password(NULL, ecjpakePw, 1),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfDTLSv1_2_server_method()));
    ExpectIntEQ(wolfSSL_CTX_set_ecjpake_password(ctx, NULL, 1),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CTX_set_ecjpake_password(ctx, ecjpakePw, 0),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* A server with no certificate is created from a password context. */
    ExpectIntEQ(wolfSSL_CTX_set_ecjpake_password(ctx, ecjpakePw, 1),
                WOLFSSL_SUCCESS);
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectNotNull(ssl == NULL ? NULL : ssl->ecJpakePw);
    ExpectIntEQ(ssl == NULL ? 0 : (int)ssl->ecJpakePwSz, 1);
    wolfSSL_free(ssl);
    ssl = NULL;
    wolfSSL_CTX_free(ctx);
    ctx = NULL;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfDTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(wolfSSL_set_ecjpake_password(ssl, NULL, 1),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_set_ecjpake_password(ssl, ecjpakePw, 0),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_set_ecjpake_password(ssl, ecjpakePw, 1),
                WOLFSSL_SUCCESS);
    /* Setting it again replaces the password. */
    ExpectIntEQ(wolfSSL_set_ecjpake_password(ssl, ecjpakeOtherPw, 2),
                WOLFSSL_SUCCESS);
    wolfSSL_free(ssl);
    ssl = NULL;
    wolfSSL_CTX_free(ctx);
    ctx = NULL;

    /* The password cannot change once the ClientHello carries round one. */
    ExpectIntEQ(ecjpake_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    ecjpakePw, ecjpakePw), TEST_SUCCESS);
    ExpectIntEQ(wolfSSL_connect(ssl_c), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_set_ecjpake_password(ssl_c, ecjpakeOtherPw,
                    (unsigned int)XSTRLEN((const char*)ecjpakeOtherPw)),
                WC_NO_ERR_TRACE(BAD_STATE_E));
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ecjpake_cleanup(ctx_c, ctx_s, ssl_c, ssl_s);
    ctx_c = NULL; ctx_s = NULL; ssl_c = NULL; ssl_s = NULL;

    /* Clearing an unfinished handshake allows a new password. */
    ExpectIntEQ(ecjpake_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    ecjpakeOtherPw, ecjpakePw), TEST_SUCCESS);
    ExpectIntEQ(wolfSSL_connect(ssl_c), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_clear(ssl_c), WOLFSSL_SUCCESS);
    ExpectNull(ssl_c == NULL ? NULL : ssl_c->ecJpake);
    test_memio_clear_buffer(&test_ctx, 0);
    ExpectIntEQ(wolfSSL_set_ecjpake_password(ssl_c, ecjpakePw,
                    (unsigned int)XSTRLEN((const char*)ecjpakePw)),
                WOLFSSL_SUCCESS);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ecjpake_cleanup(ctx_c, ctx_s, ssl_c, ssl_s);

    /* A version-flexible DTLS method could negotiate DTLS 1.3. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfDTLS_client_method()));
    ExpectIntEQ(wolfSSL_CTX_set_ecjpake_password(ctx, ecjpakePw, 1),
                WC_NO_ERR_TRACE(VERSION_ERROR));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(wolfSSL_set_ecjpake_password(ssl, ecjpakePw, 1),
                WC_NO_ERR_TRACE(VERSION_ERROR));
    wolfSSL_free(ssl);
    ssl = NULL;
    wolfSSL_CTX_free(ctx);
    ctx = NULL;

#ifndef WOLFSSL_NO_TLS12
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectIntEQ(wolfSSL_CTX_set_ecjpake_password(ctx, ecjpakePw, 1),
                WC_NO_ERR_TRACE(VERSION_ERROR));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(wolfSSL_set_ecjpake_password(ssl, ecjpakePw, 1),
                WC_NO_ERR_TRACE(VERSION_ERROR));
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
#endif
    return EXPECT_RESULT();
}
