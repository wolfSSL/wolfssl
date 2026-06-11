/* test_tls.c
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

#include <tests/utils.h>
#include <tests/api/test_tls.h>
#include <wolfssl/internal.h>
#include <wolfssl/ssl.h>


int test_utils_memio_move_message(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfTLS_client_method, wolfTLS_server_method), 0);
    wolfSSL_set_verify(ssl_s, WOLFSSL_VERIFY_PEER, NULL);
    ExpectIntEQ(wolfSSL_clear_group_messages(ssl_s), 1);
    /* start handshake, send first ClientHello */
    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* send server's flight */
    ExpectIntEQ(wolfSSL_accept(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    /* If the server responded with a HelloRetryRequest it is waiting on a new
     * ClientHello, so the buffered flight is just the HRR rather than the real
     * ServerHello flight. Drive another connect/accept round so the message
     * moving below operates on the real flight. */
    if (EXPECT_SUCCESS() && test_memio_msg_is_hello_retry_request(&test_ctx)) {
        /* client processes HRR and sends second ClientHello */
        ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
        ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
        /* server processes second ClientHello and sends its flight */
        ExpectIntEQ(wolfSSL_accept(ssl_s), -1);
        ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    }
    /* Move messages around but they should be the same at the end */
    ExpectIntEQ(test_memio_move_message(&test_ctx, 1, 1, 2), 0);
    ExpectIntEQ(test_memio_move_message(&test_ctx, 1, 2, 1), 0);
    ExpectIntEQ(test_memio_move_message(&test_ctx, 1, 1, 3), 0);
    ExpectIntEQ(test_memio_move_message(&test_ctx, 1, 3, 1), 0);
    ExpectIntEQ(test_memio_move_message(&test_ctx, 1, 0, 2), 0);
    ExpectIntEQ(test_memio_move_message(&test_ctx, 1, 2, 0), 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

int test_tls12_unexpected_ccs(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && !defined(WOLFSSL_NO_TLS12)
    const byte ccs[] = {
        0x14, /* ccs type */
        0x03, 0x03, /* version */
        0x00, 0x01, /* length */
        0x01, /* ccs value */
    };
    const byte badccs[] = {
        0x14, /* ccs type */
        0x03, 0x03, /* version */
        0x00, 0x01, /* length */
        0x99, /* wrong ccs value */
    };
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    /* ccs in the wrong place */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    /* inject SH */
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 0,
            (const char*)ccs, sizeof(ccs)), 0);
    ExpectIntEQ(test_memio_setup(&test_ctx, NULL, &ctx_s, NULL, &ssl_s,
                    NULL, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(wolfSSL_accept(ssl_s), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WOLFSSL_FATAL_ERROR),
            OUT_OF_ORDER_E);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
    ctx_s = NULL;
    ssl_s = NULL;

    /* malformed ccs */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 0,
            (const char*)badccs, sizeof(badccs)), 0);
    ExpectIntEQ(test_memio_setup(&test_ctx, NULL, &ctx_s, NULL, &ssl_s,
                    NULL, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(wolfSSL_accept(ssl_s), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WOLFSSL_FATAL_ERROR),
            LENGTH_ERROR);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

int test_tls13_unexpected_ccs(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_TLS13)
    const byte ccs[] = {
        0x14, /* ccs type */
        0x03, 0x03, /* version */
        0x00, 0x01, /* length */
        0x01, /* ccs value */
    };
    const byte badccs[] = {
        0x14, /* ccs type */
        0x03, 0x03, /* version */
        0x00, 0x01, /* length */
        0x99, /* wrong ccs value */
    };
    const byte unexpectedAlert[] = {
        0x15, /* alert type */
        0x03, 0x03, /* version */
        0x00, 0x02, /* length */
        0x02, /* level: fatal */
        0x0a /* protocol version */
    };
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    /* ccs can't appear before a CH */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 0,
            (const char*)ccs, sizeof(ccs)), 0);
    ExpectIntEQ(test_memio_setup(&test_ctx, NULL, &ctx_s, NULL, &ssl_s,
                    NULL, wolfTLSv1_3_server_method), 0);
    ExpectIntEQ(wolfSSL_accept(ssl_s), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WOLFSSL_FATAL_ERROR),
            UNKNOWN_RECORD_TYPE);
    ExpectIntEQ(test_ctx.c_len, sizeof(unexpectedAlert));
    ExpectBufEQ(test_ctx.c_buff, unexpectedAlert, sizeof(unexpectedAlert));
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
    ctx_s = NULL;
    ssl_s = NULL;

    /* malformed ccs */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 0,
            (const char*)badccs, sizeof(badccs)), 0);
    ExpectIntEQ(test_memio_setup(&test_ctx, NULL, &ctx_s, NULL, &ssl_s,
                    NULL, wolfTLSv1_3_server_method), 0);
    ExpectIntEQ(wolfSSL_accept(ssl_s), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WOLFSSL_FATAL_ERROR),
            UNKNOWN_RECORD_TYPE);
    ExpectIntEQ(test_ctx.c_len, sizeof(unexpectedAlert));
    ExpectBufEQ(test_ctx.c_buff, unexpectedAlert, sizeof(unexpectedAlert));
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}
int test_tls12_curve_intersection(void) {
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(WOLFSSL_NO_TLS12) && defined(HAVE_ECC) && \
    defined(HAVE_CURVE25519)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    int ret;
    const char* curve_name;
    int test1[] = {WOLFSSL_ECC_SECP256R1};
    int test2[] = {WOLFSSL_ECC_SECP384R1};
    int test3[] = {WOLFSSL_ECC_SECP256R1, WOLFSSL_ECC_SECP384R1};
    int test4[] = {WOLFSSL_ECC_SECP384R1, WOLFSSL_ECC_SECP256R1};
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(wolfSSL_set_groups(ssl_c,
                    test1, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* Fix: Get curve name and compare with string comparison or use curve
     * ID function */
    curve_name = wolfSSL_get_curve_name(ssl_s);
    /* or use appropriate string comparison */
    ExpectStrEQ(curve_name, "SECP256R1");
    curve_name = wolfSSL_get_curve_name(ssl_c);
    ExpectStrEQ(curve_name, "SECP256R1");

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
    ssl_c = NULL;
    ssl_s = NULL;
    ctx_c = NULL;
    ctx_s = NULL;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(wolfSSL_set_groups(ssl_c,
                   test2, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_groups(ssl_s,
                    test1, 1), WOLFSSL_SUCCESS);
    ExpectIntNE(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ret = wolfSSL_get_error(ssl_s, WOLFSSL_FATAL_ERROR);

    /* Fix: Use proper constant or define HANDSHAKE_FAILURE */
    ExpectTrue(ret == WC_NO_ERR_TRACE(ECC_CURVE_ERROR));

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
    ssl_c = NULL;
    ssl_s = NULL;
    ctx_c = NULL;
    ctx_s = NULL;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(wolfSSL_set_groups(ssl_c,
                    test3, 2),
                    WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_groups(ssl_s,
                    test4, 2),
                    WOLFSSL_SUCCESS);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    curve_name = wolfSSL_get_curve_name(ssl_s);
    ExpectStrEQ(curve_name, "SECP256R1");
    curve_name = wolfSSL_get_curve_name(ssl_c);
    ExpectStrEQ(curve_name, "SECP256R1");

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

int test_tls12_dhe_rsa_pss_sigalg(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(WOLFSSL_NO_TLS12) && !defined(NO_DH) && !defined(NO_RSA) && \
    defined(WC_RSA_PSS) && !defined(NO_SHA256) && defined(HAVE_AESGCM) && \
    !defined(WOLFSSL_HARDEN_TLS) && defined(OPENSSL_EXTRA)
    /* Regression test for S1: SendServerKeyExchange had an inverted guard
     * (#ifndef WC_RSA_PSS) that compiled out the rsa_pss_sa_algo case in the
     * server-side signature self-check for the DHE key exchange path. This
     * test drives a DHE-RSA handshake restricted to RSA-PSS+SHA256 so the
     * server exercises that code path. The bug did not cause the handshake
     * to fail, so we verify by asserting the negotiated sig algorithm. */
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);

    ExpectIntEQ(wolfSSL_set_cipher_list(ssl_c, "DHE-RSA-AES128-GCM-SHA256"),
                    WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_cipher_list(ssl_s, "DHE-RSA-AES128-GCM-SHA256"),
                    WOLFSSL_SUCCESS);

    ExpectIntEQ(wolfSSL_set1_sigalgs_list(ssl_c, "RSA-PSS+SHA256"), 1);
    ExpectIntEQ(wolfSSL_set1_sigalgs_list(ssl_s, "RSA-PSS+SHA256"), 1);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    ExpectIntEQ(ssl_s->options.sigAlgo, rsa_pss_sa_algo);
    ExpectIntEQ(ssl_c->options.peerSigAlgo, rsa_pss_sa_algo);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

int test_tls13_curve_intersection(void) {
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_TLS13) && defined(HAVE_ECC) && defined(HAVE_CURVE25519)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    const char* curve_name;
    int test1[] ={WOLFSSL_ECC_SECP256R1};

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);
    ExpectIntEQ(wolfSSL_set_groups(ssl_c,
                    test1, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    curve_name = wolfSSL_get_curve_name(ssl_s);
    ExpectStrEQ(curve_name, "SECP256R1");
    curve_name = wolfSSL_get_curve_name(ssl_c);
    ExpectStrEQ(curve_name, "SECP256R1");

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}


int test_tls_certreq_order(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(WOLFSSL_NO_TLS12) && defined(HAVE_AESGCM) && \
    defined(WOLFSSL_AES_256) && defined(WOLFSSL_SHA384) && !defined(NO_RSA) && \
    defined(HAVE_ECC)
    /* This test checks that a certificate request message
     * received before server certificate message is properly detected.
     */
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    int i = 0;
    const char* msg = NULL;
    int msgSz = 0;
    int certIdx = 0;
    int certReqIdx = 0;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    wolfSSL_set_verify(ssl_s, WOLFSSL_VERIFY_PEER, NULL);
    ExpectIntEQ(wolfSSL_clear_group_messages(ssl_s), 1);

    /* start handshake, send first ClientHello */
    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* send server's flight */
    ExpectIntEQ(wolfSSL_accept(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    for (i = 0; test_memio_get_message(&test_ctx, 1, &msg, &msgSz, i) == 0; i++) {
        if (msg[5] == 11) /* cert */
            certIdx = i;
        if (msg[5] == 13) /* certreq */
            certReqIdx = i;
    }
    ExpectIntNE(certIdx, 0);
    ExpectIntNE(certReqIdx, 0);
    ExpectIntEQ(test_memio_move_message(&test_ctx, 1, certReqIdx, certIdx), 0);
    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), OUT_OF_ORDER_E);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* A TLS 1.2 CertificateRequest carrying a supported_signature_algorithms
 * vector whose length is not a multiple of the 2-byte element size must be
 * rejected. We run a real handshake, locate the server's CertificateRequest
 * in the memio queue and make the sig-algs length odd before the client parses
 * it. The vector is shrunk by one byte and the
 * record, handshake and sig-algs length fields are all decremented so the
 * message stays self-consistent (only the sig-algs length parity is wrong).
 * Without the fix the client would silently ignore the odd trailing byte and
 * accept the message; with the fix it is rejected with BUFFER_ERROR. */
int test_tls12_certreq_odd_sigalgs(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(WOLFSSL_NO_TLS12) && !defined(NO_RSA) && defined(HAVE_ECC) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    const char* msg = NULL;
    int msgSz = 0;
    int i = 0;
    int certReqIdx = -1;
    int certTypesCnt = 0;
    int sigAlgsLenOff = 0;
    int sigAlgsLen = 0;
    int recAbs = 0;
    int removeAbs = 0;
    word32 val = 0;
    byte* b = NULL;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    /* Make the server send a CertificateRequest. */
    wolfSSL_set_verify(ssl_s, WOLFSSL_VERIFY_PEER, NULL);
    /* Send each handshake message in its own record so the CertificateRequest
     * can be located and tampered with individually. */
    ExpectIntEQ(wolfSSL_clear_group_messages(ssl_s), 1);

    /* Client sends ClientHello. */
    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* Server sends ServerHello..CertificateRequest..ServerHelloDone. */
    ExpectIntEQ(wolfSSL_accept(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);

    /* Locate the CertificateRequest record in the server->client queue. */
    for (i = 0; test_memio_get_message(&test_ctx, 1, &msg, &msgSz, i) == 0;
            i++) {
        if (msgSz > 12 && (byte)msg[5] == certificate_request) {
            certReqIdx = i;
            break;
        }
    }
    ExpectIntGE(certReqIdx, 0);

    if (EXPECT_SUCCESS()) {
        /* Layout: record hdr[5] | hs hdr[4] | certTypesCount[1] | certTypes |
         * sigAlgsLen[2] | certTypes... The sig-algs length is even; shrink the
         * vector by one byte to make it odd while keeping all length fields
         * consistent. */
        certTypesCnt = (byte)msg[9];
        sigAlgsLenOff = 10 + certTypesCnt;
        ExpectIntLT(sigAlgsLenOff + 2, msgSz);
        if (EXPECT_SUCCESS()) {
            sigAlgsLen = ((byte)msg[sigAlgsLenOff] << 8) |
                          (byte)msg[sigAlgsLenOff + 1];
            /* Need at least two pairs so a valid pair remains after shrinking. */
            ExpectIntGE(sigAlgsLen, 2 * HELLO_EXT_SIGALGO_SZ);
        }
        if (EXPECT_SUCCESS()) {
            b = (byte*)msg;
            /* Decrement record length (bytes 3..4). */
            val = ((word32)b[3] << 8) | b[4];
            val--;
            b[3] = (byte)(val >> 8); b[4] = (byte)val;
            /* Decrement handshake length (bytes 6..8). */
            val = ((word32)b[6] << 16) | ((word32)b[7] << 8) | b[8];
            val--;
            b[6] = (byte)(val >> 16); b[7] = (byte)(val >> 8); b[8] = (byte)val;
            /* Decrement sig-algs length, making it odd. */
            val = (word32)sigAlgsLen - 1;
            b[sigAlgsLenOff] = (byte)(val >> 8);
            b[sigAlgsLenOff + 1] = (byte)val;
            /* Drop the last byte of the sig-algs vector from the buffer. */
            recAbs = (int)((const byte*)msg - test_ctx.c_buff);
            removeAbs = recAbs + 12 + certTypesCnt + sigAlgsLen - 1;
            ExpectIntEQ(test_memio_remove_from_buffer(&test_ctx, 1, removeAbs,
                1), 0);
        }
    }

    /* Client must reject the malformed CertificateRequest. */
    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WC_NO_ERR_TRACE(BUFFER_ERROR));

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

#if !defined(WOLFSSL_NO_TLS12) && !defined(NO_RSA) && defined(HAVE_ECC) && \
    !defined(NO_WOLFSSL_SERVER) && !defined(WOLFSSL_NO_CLIENT_AUTH) && \
    !defined(NO_FILESYSTEM)
/* Called when writing. */
static int CsSend(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    (void)ssl;
    (void)buf;
    (void)ctx;

    return sz;
}
/* Called when reading. */
static int CsRecv(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    WOLFSSL_BUFFER_INFO* msg = (WOLFSSL_BUFFER_INFO*)ctx;
    int len = (int)msg->length;

    (void)ssl;
    (void)sz;

    /* Pass back as much of message as will fit in buffer. */
    if (len > sz)
        len = sz;
    XMEMCPY(buf, msg->buffer, len);
    /* Move over returned data. */
    msg->buffer += len;
    msg->length -= len;

    /* Amount actually copied. */
    return len;
}
#endif

int test_tls12_bad_cv_sig_alg(void)
{
    EXPECT_DECLS;
#if !defined(WOLFSSL_NO_TLS12) && !defined(NO_RSA) && defined(HAVE_ECC) && \
    !defined(NO_WOLFSSL_SERVER) && !defined(WOLFSSL_NO_CLIENT_AUTH) && \
    !defined(NO_FILESYSTEM)
    byte clientMsgs[] = {
        /* Client Hello */
        0x16, 0x03, 0x03, 0x00, 0xe7,
        0x01, 0x00, 0x00, 0xe3, 0x03, 0x03, 0x65, 0x27,
        0x41, 0xdf, 0xd9, 0x17, 0xdb, 0x02, 0x5c, 0x2e,
        0xf8, 0x4b, 0x77, 0x86, 0x5a, 0x20, 0x57, 0x7f,
        0xc0, 0xe7, 0xef, 0x8f, 0x56, 0xef, 0xfa, 0x71,
        0x36, 0xec, 0x55, 0x1d, 0x4e, 0xa2, 0x00, 0x00,
        0x64, 0xc0, 0x2c, 0xc0, 0x2b, 0xc0, 0x30, 0xc0,
        0x2f, 0x00, 0x9f, 0x00, 0x9e, 0x00, 0xab, 0x00,
        0x34, 0x00, 0xa7, 0x00, 0xaa, 0xcc, 0xa9, 0xcc,
        0xa8, 0xcc, 0xaa, 0xc0, 0x27, 0xc0, 0x23, 0xc0,
        0x28, 0xc0, 0x24, 0xc0, 0x0a, 0xc0, 0x09, 0xc0,
        0x07, 0xc0, 0x14, 0xc0, 0x13, 0xc0, 0x11, 0xc0,
        0xac, 0xc0, 0xae, 0xc0, 0xaf, 0x00, 0x6b, 0x00,
        0x67, 0x00, 0x39, 0x00, 0x33, 0xcc, 0x14, 0xcc,
        0x13, 0xcc, 0x15, 0xc0, 0x06, 0x00, 0xb3, 0x00,
        0xb2, 0xc0, 0xa6, 0xc0, 0xa7, 0xcc, 0xab, 0xcc,
        0xac, 0xcc, 0xad, 0xc0, 0x37, 0xd0, 0x01, 0x00,
        0xb5, 0xc0, 0x3a, 0x00, 0xb4, 0x00, 0x45, 0x00,
        0x88, 0x00, 0xbe, 0x00, 0xc4, 0x01, 0x00, 0x00,
        0x56, 0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06,
        0x03, 0x05, 0x03, 0x04, 0x03, 0x08, 0x07, 0x08,
        0x08, 0x08, 0x06, 0x08, 0x0b, 0x08, 0x05, 0x08,
        0x0a, 0x08, 0x04, 0x08, 0x09, 0x06, 0x01, 0x05,
        0x01, 0x04, 0x01, 0x03, 0x01, 0x00, 0x0b, 0x00,
        0x02, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x1c, 0x00,
        0x1a, 0x00, 0x19, 0x00, 0x1c, 0x00, 0x18, 0x00,
        0x1b, 0x00, 0x1e, 0x00, 0x17, 0x00, 0x16, 0x00,
        0x1a, 0x00, 0x1d, 0x00, 0x15, 0x00, 0x14, 0x01,
        0x01, 0x01, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00,
        0x23, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00,
        /* Certificate */
        0x16, 0x03, 0x03, 0x05, 0x2b,
        0x0b, 0x00, 0x05, 0x27, 0x00, 0x05, 0x24, 0x00,
        0x05, 0x21, 0x30, 0x82, 0x05, 0x1d, 0x30, 0x82,
        0x04, 0x05, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02,
        0x14, 0x4f, 0x0d, 0x8c, 0xc5, 0xfa, 0xee, 0xa2,
        0x9b, 0xb7, 0x35, 0x9e, 0xe9, 0x4a, 0x17, 0x99,
        0xf0, 0xcc, 0x23, 0xf2, 0xec, 0x30, 0x0d, 0x06,
        0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
        0x01, 0x0b, 0x05, 0x00, 0x30, 0x81, 0x9e, 0x31,
        0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06,
        0x13, 0x02, 0x55, 0x53, 0x31, 0x10, 0x30, 0x0e,
        0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x07, 0x4d,
        0x6f, 0x6e, 0x74, 0x61, 0x6e, 0x61, 0x31, 0x10,
        0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c,
        0x07, 0x42, 0x6f, 0x7a, 0x65, 0x6d, 0x61, 0x6e,
        0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04,
        0x0a, 0x0c, 0x0c, 0x77, 0x6f, 0x6c, 0x66, 0x53,
        0x53, 0x4c, 0x5f, 0x32, 0x30, 0x34, 0x38, 0x31,
        0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x0b,
        0x0c, 0x10, 0x50, 0x72, 0x6f, 0x67, 0x72, 0x61,
        0x6d, 0x6d, 0x69, 0x6e, 0x67, 0x2d, 0x32, 0x30,
        0x34, 0x38, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03,
        0x55, 0x04, 0x03, 0x0c, 0x0f, 0x77, 0x77, 0x77,
        0x2e, 0x77, 0x6f, 0x6c, 0x66, 0x73, 0x73, 0x6c,
        0x2e, 0x63, 0x6f, 0x6d, 0x31, 0x1f, 0x30, 0x1d,
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
        0x01, 0x09, 0x01, 0x16, 0x10, 0x69, 0x6e, 0x66,
        0x6f, 0x40, 0x77, 0x6f, 0x6c, 0x66, 0x73, 0x73,
        0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x1e, 0x17,
        0x0d, 0x32, 0x34, 0x31, 0x32, 0x31, 0x38, 0x32,
        0x31, 0x32, 0x35, 0x32, 0x39, 0x5a, 0x17, 0x0d,
        0x32, 0x37, 0x30, 0x39, 0x31, 0x34, 0x32, 0x31,
        0x32, 0x35, 0x32, 0x39, 0x5a, 0x30, 0x81, 0x9e,
        0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
        0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x10, 0x30,
        0x0e, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x07,
        0x4d, 0x6f, 0x6e, 0x74, 0x61, 0x6e, 0x61, 0x31,
        0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x07,
        0x0c, 0x07, 0x42, 0x6f, 0x7a, 0x65, 0x6d, 0x61,
        0x6e, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55,
        0x04, 0x0a, 0x0c, 0x0c, 0x77, 0x6f, 0x6c, 0x66,
        0x53, 0x53, 0x4c, 0x5f, 0x32, 0x30, 0x34, 0x38,
        0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04,
        0x0b, 0x0c, 0x10, 0x50, 0x72, 0x6f, 0x67, 0x72,
        0x61, 0x6d, 0x6d, 0x69, 0x6e, 0x67, 0x2d, 0x32,
        0x30, 0x34, 0x38, 0x31, 0x18, 0x30, 0x16, 0x06,
        0x03, 0x55, 0x04, 0x03, 0x0c, 0x0f, 0x77, 0x77,
        0x77, 0x2e, 0x77, 0x6f, 0x6c, 0x66, 0x73, 0x73,
        0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x31, 0x1f, 0x30,
        0x1d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
        0x0d, 0x01, 0x09, 0x01, 0x16, 0x10, 0x69, 0x6e,
        0x66, 0x6f, 0x40, 0x77, 0x6f, 0x6c, 0x66, 0x73,
        0x73, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x82,
        0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86,
        0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
        0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82,
        0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xc3,
        0x03, 0xd1, 0x2b, 0xfe, 0x39, 0xa4, 0x32, 0x45,
        0x3b, 0x53, 0xc8, 0x84, 0x2b, 0x2a, 0x7c, 0x74,
        0x9a, 0xbd, 0xaa, 0x2a, 0x52, 0x07, 0x47, 0xd6,
        0xa6, 0x36, 0xb2, 0x07, 0x32, 0x8e, 0xd0, 0xba,
        0x69, 0x7b, 0xc6, 0xc3, 0x44, 0x9e, 0xd4, 0x81,
        0x48, 0xfd, 0x2d, 0x68, 0xa2, 0x8b, 0x67, 0xbb,
        0xa1, 0x75, 0xc8, 0x36, 0x2c, 0x4a, 0xd2, 0x1b,
        0xf7, 0x8b, 0xba, 0xcf, 0x0d, 0xf9, 0xef, 0xec,
        0xf1, 0x81, 0x1e, 0x7b, 0x9b, 0x03, 0x47, 0x9a,
        0xbf, 0x65, 0xcc, 0x7f, 0x65, 0x24, 0x69, 0xa6,
        0xe8, 0x14, 0x89, 0x5b, 0xe4, 0x34, 0xf7, 0xc5,
        0xb0, 0x14, 0x93, 0xf5, 0x67, 0x7b, 0x3a, 0x7a,
        0x78, 0xe1, 0x01, 0x56, 0x56, 0x91, 0xa6, 0x13,
        0x42, 0x8d, 0xd2, 0x3c, 0x40, 0x9c, 0x4c, 0xef,
        0xd1, 0x86, 0xdf, 0x37, 0x51, 0x1b, 0x0c, 0xa1,
        0x3b, 0xf5, 0xf1, 0xa3, 0x4a, 0x35, 0xe4, 0xe1,
        0xce, 0x96, 0xdf, 0x1b, 0x7e, 0xbf, 0x4e, 0x97,
        0xd0, 0x10, 0xe8, 0xa8, 0x08, 0x30, 0x81, 0xaf,
        0x20, 0x0b, 0x43, 0x14, 0xc5, 0x74, 0x67, 0xb4,
        0x32, 0x82, 0x6f, 0x8d, 0x86, 0xc2, 0x88, 0x40,
        0x99, 0x36, 0x83, 0xba, 0x1e, 0x40, 0x72, 0x22,
        0x17, 0xd7, 0x52, 0x65, 0x24, 0x73, 0xb0, 0xce,
        0xef, 0x19, 0xcd, 0xae, 0xff, 0x78, 0x6c, 0x7b,
        0xc0, 0x12, 0x03, 0xd4, 0x4e, 0x72, 0x0d, 0x50,
        0x6d, 0x3b, 0xa3, 0x3b, 0xa3, 0x99, 0x5e, 0x9d,
        0xc8, 0xd9, 0x0c, 0x85, 0xb3, 0xd9, 0x8a, 0xd9,
        0x54, 0x26, 0xdb, 0x6d, 0xfa, 0xac, 0xbb, 0xff,
        0x25, 0x4c, 0xc4, 0xd1, 0x79, 0xf4, 0x71, 0xd3,
        0x86, 0x40, 0x18, 0x13, 0xb0, 0x63, 0xb5, 0x72,
        0x4e, 0x30, 0xc4, 0x97, 0x84, 0x86, 0x2d, 0x56,
        0x2f, 0xd7, 0x15, 0xf7, 0x7f, 0xc0, 0xae, 0xf5,
        0xfc, 0x5b, 0xe5, 0xfb, 0xa1, 0xba, 0xd3, 0x02,
        0x03, 0x01, 0x00, 0x01, 0xa3, 0x82, 0x01, 0x4f,
        0x30, 0x82, 0x01, 0x4b, 0x30, 0x1d, 0x06, 0x03,
        0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x33,
        0xd8, 0x45, 0x66, 0xd7, 0x68, 0x87, 0x18, 0x7e,
        0x54, 0x0d, 0x70, 0x27, 0x91, 0xc7, 0x26, 0xd7,
        0x85, 0x65, 0xc0, 0x30, 0x81, 0xde, 0x06, 0x03,
        0x55, 0x1d, 0x23, 0x04, 0x81, 0xd6, 0x30, 0x81,
        0xd3, 0x80, 0x14, 0x33, 0xd8, 0x45, 0x66, 0xd7,
        0x68, 0x87, 0x18, 0x7e, 0x54, 0x0d, 0x70, 0x27,
        0x91, 0xc7, 0x26, 0xd7, 0x85, 0x65, 0xc0, 0xa1,
        0x81, 0xa4, 0xa4, 0x81, 0xa1, 0x30, 0x81, 0x9e,
        0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
        0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x10, 0x30,
        0x0e, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x07,
        0x4d, 0x6f, 0x6e, 0x74, 0x61, 0x6e, 0x61, 0x31,
        0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x07,
        0x0c, 0x07, 0x42, 0x6f, 0x7a, 0x65, 0x6d, 0x61,
        0x6e, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55,
        0x04, 0x0a, 0x0c, 0x0c, 0x77, 0x6f, 0x6c, 0x66,
        0x53, 0x53, 0x4c, 0x5f, 0x32, 0x30, 0x34, 0x38,
        0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04,
        0x0b, 0x0c, 0x10, 0x50, 0x72, 0x6f, 0x67, 0x72,
        0x61, 0x6d, 0x6d, 0x69, 0x6e, 0x67, 0x2d, 0x32,
        0x30, 0x34, 0x38, 0x31, 0x18, 0x30, 0x16, 0x06,
        0x03, 0x55, 0x04, 0x03, 0x0c, 0x0f, 0x77, 0x77,
        0x77, 0x2e, 0x77, 0x6f, 0x6c, 0x66, 0x73, 0x73,
        0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x31, 0x1f, 0x30,
        0x1d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
        0x0d, 0x01, 0x09, 0x01, 0x16, 0x10, 0x69, 0x6e,
        0x66, 0x6f, 0x40, 0x77, 0x6f, 0x6c, 0x66, 0x73,
        0x73, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x14,
        0x4f, 0x0d, 0x8c, 0xc5, 0xfa, 0xee, 0xa2, 0x9b,
        0xb7, 0x35, 0x9e, 0xe9, 0x4a, 0x17, 0x99, 0xf0,
        0xcc, 0x23, 0xf2, 0xec, 0x30, 0x0c, 0x06, 0x03,
        0x55, 0x1d, 0x13, 0x04, 0x05, 0x30, 0x03, 0x01,
        0x01, 0xff, 0x30, 0x1c, 0x06, 0x03, 0x55, 0x1d,
        0x11, 0x04, 0x15, 0x30, 0x13, 0x82, 0x0b, 0x65,
        0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63,
        0x6f, 0x6d, 0x87, 0x04, 0x7f, 0x00, 0x00, 0x01,
        0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04,
        0x16, 0x30, 0x14, 0x06, 0x08, 0x2b, 0x06, 0x01,
        0x05, 0x05, 0x07, 0x03, 0x01, 0x06, 0x08, 0x2b,
        0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02, 0x30,
        0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
        0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82,
        0x01, 0x01, 0x00, 0x46, 0xab, 0xe4, 0x6d, 0xae,
        0x49, 0x5b, 0x6a, 0x0b, 0xa9, 0x87, 0xe1, 0x95,
        0x32, 0xa6, 0xd7, 0xae, 0xde, 0x28, 0xdc, 0xc7,
        0x99, 0x68, 0xe2, 0x5f, 0xc9, 0x5a, 0x4c, 0x64,
        0xb8, 0xf5, 0x28, 0x42, 0x5a, 0xe8, 0x5c, 0x59,
        0x32, 0xfe, 0xd0, 0x1f, 0x0b, 0x55, 0x89, 0xdb,
        0x67, 0xe7, 0x78, 0xf3, 0x70, 0xcf, 0x18, 0x51,
        0x57, 0x8b, 0xf3, 0x2b, 0xa4, 0x66, 0x0b, 0xf6,
        0x03, 0x6e, 0x11, 0xac, 0x83, 0x52, 0x16, 0x7e,
        0xa2, 0x7c, 0x36, 0x77, 0xf6, 0xbb, 0x13, 0x19,
        0x40, 0x2c, 0xb8, 0x8c, 0xca, 0xd6, 0x7e, 0x79,
        0x7d, 0xf4, 0x14, 0x8d, 0xb5, 0xa4, 0x09, 0xf6,
        0x2d, 0x4c, 0xe7, 0xf9, 0xb8, 0x25, 0x41, 0x15,
        0x78, 0xf4, 0xca, 0x80, 0x41, 0xea, 0x3a, 0x05,
        0x08, 0xf6, 0xb5, 0x5b, 0xa1, 0x3b, 0x5b, 0x48,
        0xa8, 0x4b, 0x8c, 0x19, 0x8d, 0x6c, 0x87, 0x31,
        0x76, 0x74, 0x02, 0x16, 0x8b, 0xdd, 0x7f, 0xd1,
        0x11, 0x62, 0x27, 0x42, 0x39, 0xe0, 0x9a, 0x63,
        0x26, 0x31, 0x19, 0xce, 0x3d, 0x41, 0xd5, 0x24,
        0x47, 0x32, 0x0f, 0x76, 0xd6, 0x41, 0x37, 0x44,
        0xad, 0x73, 0xf1, 0xb8, 0xec, 0x2b, 0x6e, 0x9c,
        0x4f, 0x84, 0xc4, 0x4e, 0xd7, 0x92, 0x10, 0x7e,
        0x23, 0x32, 0xa0, 0x75, 0x6a, 0xe7, 0xfe, 0x55,
        0x95, 0x9f, 0x0a, 0xad, 0xdf, 0xf9, 0x2a, 0xa2,
        0x1a, 0x59, 0xd5, 0x82, 0x63, 0xd6, 0x5d, 0x7d,
        0x79, 0xf4, 0xa7, 0x2d, 0xdc, 0x8c, 0x04, 0xcd,
        0x98, 0xb0, 0x42, 0x0e, 0x84, 0xfa, 0x86, 0x50,
        0x10, 0x61, 0xac, 0x73, 0xcd, 0x79, 0x45, 0x30,
        0xe8, 0x42, 0xa1, 0x6a, 0xf6, 0x77, 0x55, 0xec,
        0x07, 0xdb, 0x52, 0x29, 0xca, 0x7a, 0xc8, 0xa2,
        0xda, 0xe9, 0xf5, 0x98, 0x33, 0x6a, 0xe8, 0xbc,
        0x89, 0xed, 0x01, 0xe2, 0xfe, 0x44, 0x86, 0x86,
        0x80, 0x39, 0xec,
        /* ClientKeyExchange */
        0x16, 0x03, 0x03, 0x00, 0x46,
        0x10, 0x00, 0x00, 0x42, 0x41, 0x04, 0xc5, 0xb9,
        0x0f, 0xbc, 0x84, 0xe6, 0x0c, 0x02, 0xa6, 0x8d,
        0x34, 0xa6, 0x3e, 0x1e, 0xb7, 0x88, 0xb8, 0x68,
        0x29, 0x2b, 0x85, 0x67, 0xe2, 0x62, 0x4d, 0xd9,
        0xa4, 0x38, 0xb3, 0xec, 0x33, 0xa1, 0xe5, 0xe1,
        0xae, 0xe9, 0x07, 0xd1, 0xea, 0x1b, 0xec, 0xa6,
        0xaf, 0x1f, 0x80, 0x87, 0x7c, 0x53, 0x80, 0x04,
        0xee, 0x20, 0xeb, 0x64, 0x0d, 0xa0, 0xf7, 0x62,
        0xb1, 0xcc, 0x73, 0x97, 0xf5, 0x80,
        /* CertificateVerify */
        0x16, 0x03, 0x03, 0x01, 0x08,
        /*                            0x04 - sha256, changed to 0x02 - sha1 */
        0x0f, 0x00, 0x01, 0x04, 0x08, 0x02, 0x01, 0x00,
        0x8b, 0x09, 0xa4, 0x58, 0x8d, 0x68, 0xd9, 0xc9,
        0xef, 0xe9, 0xa5, 0x98, 0x7f, 0xa3, 0xa9, 0x7b,
        0x56, 0xf7, 0xaa, 0x5f, 0x8f, 0x47, 0x7f, 0xd0,
        0x7b, 0xcf, 0x4f, 0x84, 0xe1, 0xa9, 0x0e, 0xa8,
        0x83, 0x19, 0xd8, 0xb3, 0x97, 0x23, 0x98, 0xc5,
        0x2b, 0x56, 0x82, 0x66, 0x94, 0xcc, 0xd7, 0x23,
        0xe6, 0x6e, 0x60, 0x83, 0x78, 0xfb, 0xaf, 0x8e,
        0x8b, 0xae, 0x1f, 0x3c, 0x34, 0x96, 0x3b, 0xd5,
        0x8d, 0x1e, 0xaf, 0x98, 0x1d, 0x27, 0x86, 0x97,
        0x42, 0xd4, 0xfc, 0x62, 0xbc, 0x43, 0x94, 0x98,
        0x19, 0x26, 0x87, 0xb0, 0x8c, 0xb5, 0x22, 0xa7,
        0x6a, 0x5e, 0x56, 0x73, 0x0a, 0x75, 0xc9, 0xb9,
        0x0e, 0xf7, 0x49, 0x4f, 0xa2, 0x0f, 0xfb, 0xdf,
        0x3e, 0xe4, 0xc8, 0x31, 0x26, 0xc5, 0x5c, 0x83,
        0x9f, 0x13, 0xcb, 0x4c, 0xdc, 0x21, 0xe6, 0x24,
        0x2d, 0xd3, 0xe8, 0x18, 0x04, 0xaf, 0x5c, 0x42,
        0x03, 0xa3, 0x0a, 0xb5, 0xfc, 0xb9, 0xbc, 0x8e,
        0xd3, 0xe0, 0x78, 0xdc, 0xef, 0xb9, 0x91, 0x9f,
        0x5b, 0xdc, 0xe3, 0x84, 0xd2, 0xca, 0x32, 0x33,
        0x00, 0x7c, 0x13, 0xd3, 0x2d, 0x85, 0x65, 0x00,
        0xc0, 0xb0, 0xde, 0x85, 0x37, 0x38, 0x18, 0xd2,
        0x81, 0xd4, 0x35, 0xeb, 0xf1, 0xfb, 0x9f, 0x6c,
        0x96, 0x95, 0xf5, 0xaa, 0xfd, 0x22, 0xca, 0x20,
        0xfd, 0x3b, 0xa9, 0xa7, 0xb6, 0x5a, 0x26, 0x02,
        0xb6, 0x0e, 0xdd, 0xaa, 0x0f, 0xa8, 0x96, 0x18,
        0xaa, 0xb1, 0x79, 0x9c, 0x17, 0xb0, 0x7e, 0xa7,
        0x4f, 0xc0, 0x98, 0x27, 0xbe, 0xac, 0x00, 0xda,
        0x3b, 0x2e, 0xd4, 0x11, 0x41, 0x54, 0x34, 0x53,
        0x5f, 0xc5, 0xcd, 0x72, 0xd7, 0x36, 0x04, 0xe1,
        0x7f, 0xcf, 0x1e, 0x01, 0x97, 0xec, 0xeb, 0xad,
        0x1c, 0xc6, 0x7f, 0x2d, 0x8c, 0x68, 0x29, 0xd1,
        0x93, 0x47, 0x59, 0xc0, 0xe2, 0x4a, 0x36, 0x6c
    };
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    WOLFSSL_BUFFER_INFO msg;

    /* Set up wolfSSL context. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method()));
    ExpectTrue(wolfSSL_CTX_use_certificate_file(ctx, svrCertFile,
        CERT_FILETYPE));
    ExpectTrue(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKeyFile,
        CERT_FILETYPE));
    if (EXPECT_SUCCESS()) {
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
    }
    /* Read from 'msg'. */
    wolfSSL_SetIORecv(ctx, CsRecv);
    /* No where to send to - dummy sender. */
    wolfSSL_SetIOSend(ctx, CsSend);

    ExpectNotNull(ssl = wolfSSL_new(ctx));
    msg.buffer = clientMsgs;
    msg.length = (unsigned int)sizeof(clientMsgs);
    if (EXPECT_SUCCESS()) {
        wolfSSL_SetIOReadCtx(ssl, &msg);
    }
    /* Read all message  include CertificateVerify with invalid signature
     * algorithm. */
    ExpectIntEQ(wolfSSL_accept(ssl), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    /* Expect an invalid parameter error. */
    ExpectIntEQ(wolfSSL_get_error(ssl, WOLFSSL_FATAL_ERROR), -425);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_tls12_no_null_compression(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && !defined(WOLFSSL_NO_TLS12)
    /* ClientHello with compression list missing the required null method (RFC
     * 5246 7.4.1.2: the list MUST include the null compression method). */
    const byte badClientHello[] = {
        /* record header */
        0x16, 0x03, 0x03, 0x00, 0x2d,
        /* handshake header: ClientHello, length 41 */
        0x01, 0x00, 0x00, 0x29,
        /* client version: TLS 1.2 */
        0x03, 0x03,
        /* random: 32 bytes */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        /* session id length: 0 */
        0x00,
        /* cipher suites length: 2, TLS_RSA_WITH_AES_128_CBC_SHA */
        0x00, 0x02, 0x00, 0x2f,
        /* compression methods: 1 entry, ZLIB only (null is absent) */
        0x01, 0xdd,
    };
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 0,
            (const char*)badClientHello, sizeof(badClientHello)), 0);
    ExpectIntEQ(test_memio_setup(&test_ctx, NULL, &ctx_s, NULL, &ssl_s,
                    NULL, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(wolfSSL_accept(ssl_s), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WOLFSSL_FATAL_ERROR),
            WC_NO_ERR_TRACE(COMPRESSION_ERROR));
#ifdef WOLFSSL_EXTRA_ALERTS
    {
        const byte illegalParamAlert[] = {
            0x15,             /* alert content type */
            0x03, 0x03,       /* version: TLS 1.2 */
            0x00, 0x02,       /* length: 2 */
            0x02,             /* level: fatal */
            0x2f,             /* description: illegal_parameter (47) */
        };
        ExpectIntEQ(test_ctx.c_len, (int)sizeof(illegalParamAlert));
        ExpectBufEQ(test_ctx.c_buff, illegalParamAlert,
                sizeof(illegalParamAlert));
    }
#endif
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* RFC 8422 Section 5.1.2: a client that sends an ec_point_formats extension
 * omitting the uncompressed (0) format while negotiating an ECC suite must be
 * rejected by the server with a fatal illegal_parameter alert. This drives a
 * real handshake all the way through DoClientHello so the abort path (not just
 * the parse-time detection) is exercised.
 *
 * Rather than hand-craft a ClientHello (which would pin the cipher suite, named
 * group and exact byte offsets, making the test fragile as extension handling
 * evolves), the client builds its own ClientHello and we only suppress the
 * uncompressed point format: TLSX_PopulateExtensions() adds the default
 * uncompressed format only when no ec_point_formats extension already exists,
 * so pre-seeding the client with a compressed-only list makes it advertise
 * exactly that. The curve is negotiated normally, so the test is independent of
 * which named groups are enabled. */
int test_tls12_ec_point_formats_no_uncompressed(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && !defined(WOLFSSL_NO_TLS12) \
    && defined(HAVE_ECC) && defined(HAVE_SUPPORTED_CURVES) \
    && defined(BUILD_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA)
    /* Pin an ECDHE (ECC) suite so the server negotiates an ECC key exchange;
     * gating on the BUILD_ macro skips the test in builds where the suite is
     * unavailable (e.g. --disable-aescbc) instead of failing with
     * MATCH_SUITE_ERROR. */
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(wolfSSL_set_cipher_list(ssl_c, "ECDHE-RSA-AES128-SHA"),
            WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_cipher_list(ssl_s, "ECDHE-RSA-AES128-SHA"),
            WOLFSSL_SUCCESS);
    /* Make the client advertise only the compressed point format (1 ==
     * ansiX962_compressed_prime), i.e. omit the uncompressed (0) format. */
    ExpectIntEQ(TLSX_UsePointFormat(&ssl_c->extensions, 1, ssl_c->heap),
            WOLFSSL_SUCCESS);
    /* The server must reject the handshake with a fatal illegal_parameter
     * alert (surfaced as INVALID_PARAMETER), not complete it. */
    ExpectIntNE(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WOLFSSL_FATAL_ERROR),
            WC_NO_ERR_TRACE(INVALID_PARAMETER));

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* RFC 8422 Section 5.1.2 ties the missing-uncompressed-format abort to the
 * server actually negotiating an ECC cipher suite. A client that omits the
 * uncompressed point format but negotiates a NON-ECC suite (here DHE_RSA) must
 * NOT be rejected - the handshake completes. This is the complement of
 * test_tls12_ec_point_formats_no_uncompressed and guards against regressing
 * back to an advertised-groups (parse-time) abort.
 *
 * As in that test the client builds a real ClientHello and we only suppress the
 * uncompressed point format (see the comment there); the suite is pinned to a
 * DHE (non-ECC) suite. */
int test_tls12_ec_point_formats_no_uncompressed_non_ecc(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && !defined(WOLFSSL_NO_TLS12) \
    && defined(HAVE_SUPPORTED_CURVES) && !defined(NO_DH) && defined(HAVE_FFDHE) \
    && !defined(NO_RSA) && defined(BUILD_TLS_DHE_RSA_WITH_AES_128_CBC_SHA)
    /* The negotiated suite must be non-ECC for the missing format to be
     * irrelevant. RFC 9325 / WOLFSSL_HARDEN_TLS disables all TLS_DHE_* suites
     * (NO_TLS_DH); gating on the BUILD_ macro skips the test there rather than
     * failing with MATCH_SUITE_ERROR. */
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(wolfSSL_set_cipher_list(ssl_c, "DHE-RSA-AES128-SHA"),
            WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_cipher_list(ssl_s, "DHE-RSA-AES128-SHA"),
            WOLFSSL_SUCCESS);
    /* Make the client advertise only the compressed point format (1 ==
     * ansiX962_compressed_prime), i.e. omit the uncompressed (0) format. */
    ExpectIntEQ(TLSX_UsePointFormat(&ssl_c->extensions, 1, ssl_c->heap),
            WOLFSSL_SUCCESS);
    /* The handshake must complete: the missing uncompressed format is
     * irrelevant for a non-ECC (DHE) suite. */
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    /* Sanity: the server really did observe a point-format list without the
     * uncompressed format, yet proceeded. */
    ExpectIntEQ(ssl_s->options.peerNoUncompPF, 1);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* Test that set_curves_list correctly resolves ECC curve names that fall
 * through the kNistCurves table and reach the wc_ecc_get_curve_idx_from_name
 * fallback path.  The kNistCurves lookup uses a case-sensitive XSTRNCMP, so
 * uppercase names like "SECP384R1" do not match the lowercase "secp384r1"
 * entry; they fall through to the wolfCrypt ECC look-up which uses
 * XSTRCASECMP. */
/* Regression test for the encrypt-then-MAC silent-disable bug.
 *
 * Before the fix, when a client sent a 32-byte session ID in its ClientHello
 * (so the server set ssl->options.resuming = 1) but the server's session
 * cache did not contain that session, DoClientHello would run an
 * encrypt_then_mac decision *before* MatchSuite/SetCipherSpecs had populated
 * ssl->specs.cipher_type.  Because cipher_type was zero-initialized
 * (== stream, not block), the ETM block cleared encThenMac to 0, and the
 * post-MatchSuite block could not re-enable it.  The connection then
 * silently negotiated MAC-then-encrypt instead of encrypt-then-MAC.
 *
 * This test forces a stale-resumption ClientHello against a server with an
 * empty session cache, using a CBC-mode cipher suite, and asserts that the
 * server still negotiates encrypt-then-MAC. */
int test_tls12_etm_failed_resumption(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(WOLFSSL_NO_TLS12) && defined(HAVE_ENCRYPT_THEN_MAC) && \
    !defined(WOLFSSL_AEAD_ONLY) && !defined(NO_RSA) && !defined(NO_AES) && \
    defined(HAVE_AES_CBC) && !defined(NO_SHA256) && \
    defined(HAVE_SESSION_TICKET) && defined(HAVE_ECC)
    /* TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 - a CBC suite, where ETM applies. */
    const char* cbcSuite = "ECDHE-RSA-AES128-SHA256";
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    WOLFSSL_SESSION *sess = NULL;
    struct test_memio_ctx test_ctx;

    /* First handshake: establish a session-ID-based session on the client.
     * Disable TLS 1.2 session tickets on both sides so resumption uses the
     * session ID path (not tickets), which is the path the bug lives on. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(wolfSSL_NoTicketTLSv12(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_NoTicketTLSv12(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_cipher_list(ssl_c, cbcSuite), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_cipher_list(ssl_s, cbcSuite), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    /* Sanity: the first handshake itself must use ETM. */
    ExpectIntEQ(ssl_s->options.encThenMac, 1);
    ExpectNotNull(sess = wolfSSL_get1_session(ssl_c));

    wolfSSL_free(ssl_c); ssl_c = NULL;
    wolfSSL_free(ssl_s); ssl_s = NULL;
    wolfSSL_CTX_free(ctx_c); ctx_c = NULL;
    wolfSSL_CTX_free(ctx_s); ctx_s = NULL;

    /* Second handshake against a *fresh* server context (empty cache).  The
     * client offers the saved session, so the server's ClientHello parser
     * sets options.resuming = 1, but HandleTlsResumption then fails to find
     * the session and clears resuming.  Pre-fix, ETM was silently dropped
     * here. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    /* The internal session cache is process-global, so the saved session is
     * still findable via the cache.  Disable lookups on this server SSL
     * directly so that HandleTlsResumption hits its "session lookup failed"
     * path - exactly the scenario the bug fix targets. */
    if (ssl_s != NULL)
        ssl_s->options.sessionCacheOff = 1;
    ExpectIntEQ(wolfSSL_NoTicketTLSv12(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_NoTicketTLSv12(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_cipher_list(ssl_c, cbcSuite), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_cipher_list(ssl_s, cbcSuite), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_session(ssl_c, sess), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    if (ssl_s != NULL) {
        /* The server should NOT have actually resumed (fresh ctx, empty
         * cache). */
        ExpectIntEQ(ssl_s->options.resuming, 0);
        /* And - the regression check - encrypt-then-MAC must still be
         * active. */
        ExpectIntEQ(ssl_s->options.encThenMac, 1);
    }
    if (ssl_c != NULL)
        ExpectIntEQ(ssl_c->options.encThenMac, 1);

    wolfSSL_SESSION_free(sess);
    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* RFC 5246 7.4.1.3: a server resuming a TLS 1.2 session ticket MUST reuse the
 * session's cipher suite. The ticket is opaque to the client, so the client
 * cannot rely on the suite being bound inside it and must compare the
 * ServerHello suite against the suite retained in the cached session (F-5811
 * does this for session-ID resumption; it must hold for tickets too). This
 * test establishes a ticket-based session, rewrites the cached session's suite
 * to emulate a server that resumes the ticket under a different suite, and
 * asserts the client aborts the resumption with MATCH_SUITE_ERROR. The same
 * server CTX is reused for the second handshake so its ticket key persists. */
int test_tls12_resume_ticket_wrong_suite(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(WOLFSSL_NO_TLS12) && defined(HAVE_SESSION_TICKET) && \
    !defined(WOLFSSL_NO_DEF_TICKET_ENC_CB) && \
    !defined(NO_RESUME_SUITE_CHECK) && !defined(NO_RSA) && defined(HAVE_ECC) && \
    !defined(NO_AES) && defined(HAVE_AESGCM) && !defined(NO_SHA256) && \
    defined(BUILD_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
    const char* suite = "ECDHE-RSA-AES128-GCM-SHA256";
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    WOLFSSL *ssl_c2 = NULL, *ssl_s2 = NULL;
    WOLFSSL *ssl_c3 = NULL, *ssl_s3 = NULL;
    WOLFSSL_SESSION *sess = NULL;
    struct test_memio_ctx test_ctx;
    struct test_memio_ctx test_ctx2;
    struct test_memio_ctx test_ctx3;
    int ret;

    /* First handshake: establish a ticket-based TLS 1.2 session. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(wolfSSL_set_cipher_list(ssl_c, suite), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_cipher_list(ssl_s, suite), WOLFSSL_SUCCESS);
    /* Opt the client into TLS 1.2 session tickets so the server issues one. */
    ExpectIntEQ(wolfSSL_UseSessionTicket(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectNotNull(sess = wolfSSL_get1_session(ssl_c));
    /* Must be a ticket session to exercise the ticket path. */
    ExpectIntGT(sess->ticketLen, 0);

    /* Case 1 - downgrading server: change the cached suite so it no longer
     * matches the suite the server reuses from the ticket, but keep it
     * non-zero so it still counts as a retained suite. The value only feeds
     * the comparison (the real keys come from the ServerHello suite), so
     * flipping it is sufficient and safe. The client must reject the
     * resumption against the same server CTX (ticket key persists). */
    if (sess != NULL)
        sess->cipherSuite = (byte)(sess->cipherSuite ^ 0xFF);

    XMEMSET(&test_ctx2, 0, sizeof(test_ctx2));
    ExpectIntEQ(test_memio_setup(&test_ctx2, &ctx_c, &ctx_s, &ssl_c2, &ssl_s2,
                    wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(wolfSSL_set_cipher_list(ssl_c2, suite), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_cipher_list(ssl_s2, suite), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UseSessionTicket(ssl_c2), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_session(ssl_c2, sess), WOLFSSL_SUCCESS);
    ret = test_memio_do_handshake(ssl_c2, ssl_s2, 10, NULL);
    ExpectIntNE(ret, 0);
    ExpectIntEQ(ssl_c2->error, WC_NO_ERR_TRACE(MATCH_SUITE_ERROR));

    /* Case 2 - session that retained no suite (cipherSuite0/cipherSuite both
     * zero), as for an EAP-FAST PAC whose keys come from the session-secret
     * callback. There is nothing to compare against, so the check must be
     * skipped and the resumption must still succeed. */
    if (sess != NULL) {
        sess->cipherSuite0 = 0;
        sess->cipherSuite  = 0;
    }

    XMEMSET(&test_ctx3, 0, sizeof(test_ctx3));
    ExpectIntEQ(test_memio_setup(&test_ctx3, &ctx_c, &ctx_s, &ssl_c3, &ssl_s3,
                    wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(wolfSSL_set_cipher_list(ssl_c3, suite), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_cipher_list(ssl_s3, suite), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UseSessionTicket(ssl_c3), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_session(ssl_c3, sess), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_memio_do_handshake(ssl_c3, ssl_s3, 10, NULL), 0);
    ExpectIntEQ(wolfSSL_session_reused(ssl_c3), 1);

    wolfSSL_SESSION_free(sess);
    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_free(ssl_c2);
    wolfSSL_free(ssl_s2);
    wolfSSL_free(ssl_c3);
    wolfSSL_free(ssl_s3);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* A ticket the server can't honor must fall back to a full handshake (RFC 5077
 * 3.4), even under a different suite than the cached ticket session - the
 * F-5811 suite check must not abort it. The second handshake uses a fresh
 * server CTX (new ticket key -> decline) offering only suite B while the client
 * offers B and the session's suite A. */
int test_tls12_resume_ticket_decline_fallback(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(WOLFSSL_NO_TLS12) && defined(HAVE_SESSION_TICKET) && \
    !defined(WOLFSSL_NO_DEF_TICKET_ENC_CB) && !defined(NO_SESSION_CACHE) && \
    !defined(NO_RESUME_SUITE_CHECK) && !defined(NO_RSA) && defined(HAVE_ECC) && \
    !defined(NO_AES) && defined(HAVE_AESGCM) && !defined(NO_SHA256) && \
    defined(BUILD_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) && \
    defined(BUILD_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
    const char* suiteA  = "ECDHE-RSA-AES128-GCM-SHA256";
    const char* suiteB  = "ECDHE-RSA-AES256-GCM-SHA384";
    const char* suiteBA =
        "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256";
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL, *ctx_s2 = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    WOLFSSL *ssl_c2 = NULL, *ssl_s2 = NULL;
    WOLFSSL_SESSION *sess = NULL;
    struct test_memio_ctx test_ctx;
    struct test_memio_ctx test_ctx2;

    /* First handshake: establish a ticket-based TLS 1.2 session on suite A. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(wolfSSL_set_cipher_list(ssl_c, suiteA), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_cipher_list(ssl_s, suiteA), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UseSessionTicket(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectNotNull(sess = wolfSSL_get1_session(ssl_c));
    ExpectIntGT(sess->ticketLen, 0);

    /* Second handshake: fresh server CTX (NULL ctx_s2 -> new ticket key) so the
     * ticket is declined and the server does a full handshake on suite B. */
    XMEMSET(&test_ctx2, 0, sizeof(test_ctx2));
    ExpectIntEQ(test_memio_setup(&test_ctx2, &ctx_c, &ctx_s2, &ssl_c2, &ssl_s2,
                    wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(wolfSSL_set_cipher_list(ssl_c2, suiteBA), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_cipher_list(ssl_s2, suiteB), WOLFSSL_SUCCESS);
    /* Session cache off so the declining server emits an empty session ID and
     * the client takes the graceful full-handshake fallback (set on the SSL as
     * the flag is copied from the CTX at wolfSSL_new() time). */
    if (ssl_s2 != NULL)
        ssl_s2->options.sessionCacheOff = 1;
    ExpectIntEQ(wolfSSL_UseSessionTicket(ssl_c2), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_session(ssl_c2, sess), WOLFSSL_SUCCESS);
    /* Fallback must succeed (no MATCH_SUITE_ERROR), not resume, and use B. */
    ExpectIntEQ(test_memio_do_handshake(ssl_c2, ssl_s2, 10, NULL), 0);
    ExpectIntEQ(wolfSSL_session_reused(ssl_c2), 0);
    ExpectStrEQ(wolfSSL_get_cipher_name(ssl_c2), suiteB);

    wolfSSL_SESSION_free(sess);
    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_free(ssl_c2);
    wolfSSL_free(ssl_s2);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
    wolfSSL_CTX_free(ctx_s2);
#endif
    return EXPECT_RESULT();
}

/* wolfSSL_set_session() must reject a TLS 1.2 session when minDowngrade is
 * set to TLS 1.3. */
int test_tls_set_session_min_downgrade(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(WOLFSSL_NO_TLS12) && defined(WOLFSSL_TLS13) && \
    defined(HAVE_SESSION_TICKET)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    WOLFSSL_SESSION *sess = NULL;
    struct test_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectNotNull(sess = wolfSSL_get1_session(ssl_c));

    wolfSSL_free(ssl_c); ssl_c = NULL;
    wolfSSL_free(ssl_s); ssl_s = NULL;
    wolfSSL_CTX_free(ctx_c); ctx_c = NULL;
    wolfSSL_CTX_free(ctx_s); ctx_s = NULL;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLS_client_method, wolfTLS_server_method), 0);
    ExpectIntEQ(wolfSSL_SetMinVersion(ssl_c, WOLFSSL_TLSV1_3),
                WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_session(ssl_c, sess), WOLFSSL_FAILURE);
    if (ssl_c != NULL)
        ExpectIntEQ(ssl_c->options.resuming, 0);

    wolfSSL_SESSION_free(sess);
    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    (!defined(WOLFSSL_NO_TLS12) || defined(WOLFSSL_TLS13)) && \
    defined(HAVE_SNI) && defined(HAVE_SESSION_TICKET) && \
    !defined(NO_SESSION_CACHE)
/* Accept-all SNI callback. */
static int accept_any_sni_cb(WOLFSSL* ssl, int* ret, void* arg)
{
    (void)ssl; (void)ret; (void)arg;
    return 0; /* accept */
}
#endif

/* TLS resumption must proceed with full handshake to establish new session if
 * SNI/ALPN does not match previously established session. */
int test_tls12_session_id_resumption_sni_mismatch(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(WOLFSSL_NO_TLS12) && defined(HAVE_SNI) && \
    defined(HAVE_SESSION_TICKET) && !defined(NO_SESSION_CACHE)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    WOLFSSL_SESSION *sess = NULL;
    struct test_memio_ctx test_ctx;
    const char* sniA = "public.example";
    const char* sniB = "admin.example";

    /* Step 1: full TLS 1.2 handshake under SNI=public.example, with the
     * session ticket path disabled so resumption can only happen via the
     * server's session-ID cache. The server-side SNI callback ensures
     * ssl->extensions retains the client's SNI in builds that don't
     * compile in WOLFSSL_ALWAYS_KEEP_SNI. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    wolfSSL_CTX_set_servername_callback(ctx_s, accept_any_sni_cb);
    ExpectIntEQ(wolfSSL_NoTicketTLSv12(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_NoTicketTLSv12(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UseSNI(ssl_c, WOLFSSL_SNI_HOST_NAME,
                    sniA, (word16)XSTRLEN(sniA)), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    /* Sanity: the first handshake was not a resumption. */
    ExpectIntEQ(wolfSSL_session_reused(ssl_s), 0);
    ExpectNotNull(sess = wolfSSL_get1_session(ssl_c));

    wolfSSL_free(ssl_c); ssl_c = NULL;
    wolfSSL_free(ssl_s); ssl_s = NULL;

    /* Step 2: new SSL objects on the SAME WOLFSSL_CTX (so the server's
     * session cache still holds the entry from step 1). The client offers
     * the saved session but advertises a *different* SNI. The server's
     * cache lookup will match by session ID, but per RFC 6066 Section 3 the
     * server MUST NOT resume because the SNI differs from the original. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectNotNull(ssl_c = wolfSSL_new(ctx_c));
    wolfSSL_SetIOReadCtx(ssl_c, &test_ctx);
    wolfSSL_SetIOWriteCtx(ssl_c, &test_ctx);
    ExpectNotNull(ssl_s = wolfSSL_new(ctx_s));
    wolfSSL_SetIOReadCtx(ssl_s, &test_ctx);
    wolfSSL_SetIOWriteCtx(ssl_s, &test_ctx);
    ExpectIntEQ(wolfSSL_NoTicketTLSv12(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_NoTicketTLSv12(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UseSNI(ssl_c, WOLFSSL_SNI_HOST_NAME,
                    sniB, (word16)XSTRLEN(sniB)), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_session(ssl_c, sess), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* Post-fix expected behavior: server falls back to a full handshake
     * because the SNI in the ClientHello does not match the SNI bound to
     * the cached session. Pre-fix, the server silently resumes - which is
     * the bug. Both sides should report no resumption. */
    ExpectIntEQ(wolfSSL_session_reused(ssl_s), 0);
    ExpectIntEQ(wolfSSL_session_reused(ssl_c), 0);

    wolfSSL_SESSION_free(sess);
    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* TLS 1.3 PSK resumption must fall back to a full handshake if the SNI in
 * the resumed ClientHello does not match the SNI bound to the original
 * session (RFC 6066 Section 3 / RFC 8446 Section 4.6.1). */
int test_tls13_session_resumption_sni_mismatch(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_TLS13) && \
    defined(HAVE_SNI) && defined(HAVE_SESSION_TICKET) && \
    !defined(NO_SESSION_CACHE)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    WOLFSSL_SESSION *sess = NULL;
    struct test_memio_ctx test_ctx;
    const char* sniA = "public.example";
    const char* sniB = "admin.example";
    byte readBuf[16];

    /* Step 1: full TLS 1.3 handshake under SNI=public.example to obtain a
     * session ticket. The server-side SNI callback ensures ssl->extensions
     * retains the client's SNI in builds that don't compile in
     * WOLFSSL_ALWAYS_KEEP_SNI. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);
    wolfSSL_CTX_set_servername_callback(ctx_s, accept_any_sni_cb);
    ExpectIntEQ(wolfSSL_UseSNI(ssl_c, WOLFSSL_SNI_HOST_NAME,
                    sniA, (word16)XSTRLEN(sniA)), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    /* Sanity: the first handshake was not a resumption. */
    ExpectIntEQ(wolfSSL_session_reused(ssl_s), 0);
    /* Drive the post-handshake NewSessionTicket through to the client so
     * the saved session is a real resumption ticket. */
    ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectNotNull(sess = wolfSSL_get1_session(ssl_c));

    wolfSSL_free(ssl_c); ssl_c = NULL;
    wolfSSL_free(ssl_s); ssl_s = NULL;

    /* Step 2: new SSL objects on the SAME WOLFSSL_CTX (so the server's
     * ticket key still matches). The client offers the saved session but
     * advertises a *different* SNI. The server MUST NOT resume because the
     * SNI differs from the original. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectNotNull(ssl_c = wolfSSL_new(ctx_c));
    wolfSSL_SetIOReadCtx(ssl_c, &test_ctx);
    wolfSSL_SetIOWriteCtx(ssl_c, &test_ctx);
    ExpectNotNull(ssl_s = wolfSSL_new(ctx_s));
    wolfSSL_SetIOReadCtx(ssl_s, &test_ctx);
    wolfSSL_SetIOWriteCtx(ssl_s, &test_ctx);
    ExpectIntEQ(wolfSSL_UseSNI(ssl_c, WOLFSSL_SNI_HOST_NAME,
                    sniB, (word16)XSTRLEN(sniB)), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_session(ssl_c, sess), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* Desired behavior: server falls back to a full handshake because the
     * SNI in the ClientHello does not match the SNI bound to the cached
     * ticket. Both sides should report no resumption. */
    ExpectIntEQ(wolfSSL_session_reused(ssl_s), 0);
    ExpectIntEQ(wolfSSL_session_reused(ssl_c), 0);

    wolfSSL_SESSION_free(sess);
    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* Regression test for the post-ALPN_Select PSK-head check.
 * When ALPN_Select runs before CheckPreSharedKeys (so the per-PSK
 * binding check has the negotiated ALPN available), TLSX_SetALPN
 * prepends a new ALPN entry to ssl->extensions, displacing the PSK
 * extension from the head of the list. The "PSK was last in
 * ClientHello" check therefore must run right after TLSX_Parse,
 * not inside CheckPreSharedKeys. This test exercises that path
 * (TLS 1.3 PSK resumption with ALPN, no SNI callback -- the grpc
 * server scenario). */
int test_tls13_resumption_with_alpn(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_TLS13) && \
    defined(HAVE_SNI) && defined(HAVE_ALPN) && defined(HAVE_SESSION_TICKET) && \
    !defined(NO_SESSION_CACHE)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    WOLFSSL_SESSION *sess = NULL;
    struct test_memio_ctx test_ctx;
    const char* sni = "foo.test.google.fr";
    const char alpn[] = "h2";
    byte readBuf[16];

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);
    ExpectIntEQ(wolfSSL_UseSNI(ssl_c, WOLFSSL_SNI_HOST_NAME,
                    sni, (word16)XSTRLEN(sni)), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UseALPN(ssl_c, (char*)alpn, (word32)XSTRLEN(alpn),
                    WOLFSSL_ALPN_FAILED_ON_MISMATCH), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UseALPN(ssl_s, (char*)alpn, (word32)XSTRLEN(alpn),
                    WOLFSSL_ALPN_FAILED_ON_MISMATCH), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectIntEQ(wolfSSL_session_reused(ssl_s), 0);
    ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectNotNull(sess = wolfSSL_get1_session(ssl_c));

    wolfSSL_free(ssl_c); ssl_c = NULL;
    wolfSSL_free(ssl_s); ssl_s = NULL;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectNotNull(ssl_c = wolfSSL_new(ctx_c));
    wolfSSL_SetIOReadCtx(ssl_c, &test_ctx);
    wolfSSL_SetIOWriteCtx(ssl_c, &test_ctx);
    ExpectNotNull(ssl_s = wolfSSL_new(ctx_s));
    wolfSSL_SetIOReadCtx(ssl_s, &test_ctx);
    wolfSSL_SetIOWriteCtx(ssl_s, &test_ctx);
    ExpectIntEQ(wolfSSL_UseSNI(ssl_c, WOLFSSL_SNI_HOST_NAME,
                    sni, (word16)XSTRLEN(sni)), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UseALPN(ssl_c, (char*)alpn, (word32)XSTRLEN(alpn),
                    WOLFSSL_ALPN_FAILED_ON_MISMATCH), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UseALPN(ssl_s, (char*)alpn, (word32)XSTRLEN(alpn),
                    WOLFSSL_ALPN_FAILED_ON_MISMATCH), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_session(ssl_c, sess), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    ExpectIntEQ(wolfSSL_session_reused(ssl_s), 1);
    ExpectIntEQ(wolfSSL_session_reused(ssl_c), 1);

    wolfSSL_SESSION_free(sess);
    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* TLS 1.2 stateful (session-ID) resumption must fall back to a full
 * handshake if the ALPN protocol negotiated for the resumed connection
 * does not match the ALPN bound to the original session. Mirrors
 * test_tls12_session_id_resumption_sni_mismatch but varies ALPN instead
 * of SNI. */
int test_tls12_session_id_resumption_alpn_mismatch(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(WOLFSSL_NO_TLS12) && defined(HAVE_ALPN) && \
    defined(HAVE_SESSION_TICKET) && !defined(NO_SESSION_CACHE)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    WOLFSSL_SESSION *sess = NULL;
    struct test_memio_ctx test_ctx;
    const char alpnA[] = "h2";
    const char alpnB[] = "http/1.1";

    /* Step 1: full TLS 1.2 handshake negotiating ALPN=h2, with the
     * session ticket path disabled so resumption can only happen via the
     * server's session-ID cache. The negotiated ALPN is retained on
     * ssl->extensions by ALPN_Select, so SetupSession binds its hash to
     * the cached session. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(wolfSSL_NoTicketTLSv12(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_NoTicketTLSv12(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UseALPN(ssl_c, (char*)alpnA, (word32)XSTRLEN(alpnA),
                    WOLFSSL_ALPN_FAILED_ON_MISMATCH), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UseALPN(ssl_s, (char*)alpnA, (word32)XSTRLEN(alpnA),
                    WOLFSSL_ALPN_FAILED_ON_MISMATCH), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    /* Sanity: the first handshake was not a resumption. */
    ExpectIntEQ(wolfSSL_session_reused(ssl_s), 0);
    ExpectNotNull(sess = wolfSSL_get1_session(ssl_c));

    wolfSSL_free(ssl_c); ssl_c = NULL;
    wolfSSL_free(ssl_s); ssl_s = NULL;

    /* Step 2: new SSL objects on the SAME WOLFSSL_CTX (so the server's
     * session cache still holds the entry from step 1). The client offers
     * the saved session but both sides now advertise a *different* ALPN
     * (http/1.1), so the handshake negotiates http/1.1. The server's cache
     * lookup matches by session ID, but the server MUST NOT resume because
     * the negotiated ALPN differs from the one bound to the original
     * session. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectNotNull(ssl_c = wolfSSL_new(ctx_c));
    wolfSSL_SetIOReadCtx(ssl_c, &test_ctx);
    wolfSSL_SetIOWriteCtx(ssl_c, &test_ctx);
    ExpectNotNull(ssl_s = wolfSSL_new(ctx_s));
    wolfSSL_SetIOReadCtx(ssl_s, &test_ctx);
    wolfSSL_SetIOWriteCtx(ssl_s, &test_ctx);
    ExpectIntEQ(wolfSSL_NoTicketTLSv12(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_NoTicketTLSv12(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UseALPN(ssl_c, (char*)alpnB, (word32)XSTRLEN(alpnB),
                    WOLFSSL_ALPN_FAILED_ON_MISMATCH), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UseALPN(ssl_s, (char*)alpnB, (word32)XSTRLEN(alpnB),
                    WOLFSSL_ALPN_FAILED_ON_MISMATCH), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_session(ssl_c, sess), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* Expected behavior: server falls back to a full handshake because the
     * negotiated ALPN does not match the ALPN bound to the cached session.
     * Both sides should report no resumption. */
    ExpectIntEQ(wolfSSL_session_reused(ssl_s), 0);
    ExpectIntEQ(wolfSSL_session_reused(ssl_c), 0);

    wolfSSL_SESSION_free(sess);
    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* TLS 1.3 PSK resumption must fall back to a full handshake if the ALPN
 * protocol negotiated for the resumed connection does not match the ALPN
 * bound to the original session. Mirrors
 * test_tls13_session_resumption_sni_mismatch but varies ALPN instead of
 * SNI. */
int test_tls13_session_resumption_alpn_mismatch(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_TLS13) && \
    defined(HAVE_ALPN) && defined(HAVE_SESSION_TICKET) && \
    !defined(NO_SESSION_CACHE)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    WOLFSSL_SESSION *sess = NULL;
    struct test_memio_ctx test_ctx;
    const char alpnA[] = "h2";
    const char alpnB[] = "http/1.1";
    byte readBuf[16];

    /* Step 1: full TLS 1.3 handshake negotiating ALPN=h2 to obtain a
     * session ticket. The negotiated ALPN is retained on ssl->extensions
     * by ALPN_Select and bound to the ticket. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);
    ExpectIntEQ(wolfSSL_UseALPN(ssl_c, (char*)alpnA, (word32)XSTRLEN(alpnA),
                    WOLFSSL_ALPN_FAILED_ON_MISMATCH), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UseALPN(ssl_s, (char*)alpnA, (word32)XSTRLEN(alpnA),
                    WOLFSSL_ALPN_FAILED_ON_MISMATCH), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    /* Sanity: the first handshake was not a resumption. */
    ExpectIntEQ(wolfSSL_session_reused(ssl_s), 0);
    /* Drive the post-handshake NewSessionTicket through to the client so
     * the saved session is a real resumption ticket. */
    ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectNotNull(sess = wolfSSL_get1_session(ssl_c));

    wolfSSL_free(ssl_c); ssl_c = NULL;
    wolfSSL_free(ssl_s); ssl_s = NULL;

    /* Step 2: new SSL objects on the SAME WOLFSSL_CTX (so the server's
     * ticket key still matches). The client offers the saved session but
     * both sides now advertise a *different* ALPN (http/1.1). The server
     * MUST NOT resume because the negotiated ALPN differs from the one
     * bound to the original ticket. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectNotNull(ssl_c = wolfSSL_new(ctx_c));
    wolfSSL_SetIOReadCtx(ssl_c, &test_ctx);
    wolfSSL_SetIOWriteCtx(ssl_c, &test_ctx);
    ExpectNotNull(ssl_s = wolfSSL_new(ctx_s));
    wolfSSL_SetIOReadCtx(ssl_s, &test_ctx);
    wolfSSL_SetIOWriteCtx(ssl_s, &test_ctx);
    ExpectIntEQ(wolfSSL_UseALPN(ssl_c, (char*)alpnB, (word32)XSTRLEN(alpnB),
                    WOLFSSL_ALPN_FAILED_ON_MISMATCH), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UseALPN(ssl_s, (char*)alpnB, (word32)XSTRLEN(alpnB),
                    WOLFSSL_ALPN_FAILED_ON_MISMATCH), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_session(ssl_c, sess), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* Expected behavior: server falls back to a full handshake because the
     * negotiated ALPN does not match the ALPN bound to the cached ticket.
     * Both sides should report no resumption. */
    ExpectIntEQ(wolfSSL_session_reused(ssl_s), 0);
    ExpectIntEQ(wolfSSL_session_reused(ssl_c), 0);

    wolfSSL_SESSION_free(sess);
    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

int test_tls_set_curves_list_ecc_fallback(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && defined(HAVE_ECC) && \
    (defined(OPENSSL_EXTRA) || defined(HAVE_CURL)) && \
    !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST) && \
    (defined(HAVE_ECC384) || defined(HAVE_ALL_CURVES)) && \
    ECC_MIN_KEY_SZ <= 384
#ifndef NO_WOLFSSL_CLIENT
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL*     ssl = NULL;

    /* "SECP384R1" (uppercase) is NOT in kNistCurves (case-sensitive table),
     * so set_curves_list must use the wc_ecc_get_curve_idx_from_name fallback.
     */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));

    /* CTX-level: set single curve via its wolfCrypt name (uppercase) */
    ExpectIntEQ(wolfSSL_CTX_set1_curves_list(ctx, "SECP384R1"),
                WOLFSSL_SUCCESS);

    /* Verify the correct curve was stored, not ecc_sets[0] */
    ExpectIntEQ(ctx->numGroups, 1);
    ExpectIntEQ(ctx->group[0], WOLFSSL_ECC_SECP384R1);

    /* SSL-level: same check via wolfSSL_set1_curves_list */
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(wolfSSL_set1_curves_list(ssl, "SECP384R1"), WOLFSSL_SUCCESS);
    ExpectIntEQ(ssl->numGroups, 1);
    ExpectIntEQ(ssl->group[0], WOLFSSL_ECC_SECP384R1);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif /* NO_WOLFSSL_CLIENT */
#endif
    return EXPECT_RESULT();
}

#if !defined(WOLFSSL_NO_TLS12) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER)
static int test_tls12_find_client_finished(const struct test_memio_ctx* test_ctx,
    int* finishedMsgPos, int* finishedOffInMsg, int* finishedLen)
{
    int i;
    const char* msg = NULL;
    int msgSz = 0;
    int ccsPos = -1;

    *finishedMsgPos = -1;
    *finishedOffInMsg = -1;
    *finishedLen = 0;

    for (i = 0; i < test_ctx->s_msg_count; i++) {
        if (test_memio_get_message(test_ctx, 0, &msg, &msgSz, i) != 0 ||
                msgSz < RECORD_HEADER_SZ) {
            return -1;
        }

        if ((byte)msg[0] == change_cipher_spec) {
            ccsPos = i;
            break;
        }
    }

    if (ccsPos >= 0 &&
            test_memio_get_message(test_ctx, 0, &msg, &msgSz, ccsPos + 1) == 0 &&
            msgSz >= RECORD_HEADER_SZ && (byte)msg[0] == handshake) {
        *finishedMsgPos = ccsPos + 1;
        *finishedOffInMsg = 0;
        *finishedLen = msgSz;
        return 0;
    }

    if (test_ctx->s_msg_count == 1) {
        int off = 0;

        while (off + RECORD_HEADER_SZ <= test_ctx->s_len) {
            word16 recLen;
            int totalLen;

            ato16(test_ctx->s_buff + off + 3, &recLen);
            totalLen = RECORD_HEADER_SZ + recLen;
            if (off + totalLen > test_ctx->s_len) {
                return -1;
            }

            if (test_ctx->s_buff[off] == change_cipher_spec) {
                int nextOff = off + totalLen;

                if (nextOff + RECORD_HEADER_SZ > test_ctx->s_len ||
                        test_ctx->s_buff[nextOff] != handshake) {
                    return -1;
                }

                ato16(test_ctx->s_buff + nextOff + 3, &recLen);
                totalLen = RECORD_HEADER_SZ + recLen;
                if (nextOff + totalLen > test_ctx->s_len) {
                    return -1;
                }

                *finishedMsgPos = 0;
                *finishedOffInMsg = nextOff;
                *finishedLen = totalLen;
                return 0;
            }

            off += totalLen;
        }
    }

    return -1;
}
#endif

/* Test that a corrupted TLS 1.2 Finished verify_data is properly rejected
 * with VERIFY_FINISHED_ERROR. We let the client queue its second flight,
 * remove the Finished record from the memio queue, allow the server to
 * process up through CCS, then inject a corrupted Finished record. */
int test_tls12_corrupted_finished(void)
{
    EXPECT_DECLS;
#if !defined(WOLFSSL_NO_TLS12) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER)
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    char finishedMsg[1024];
    int finishedSz = (int)sizeof(finishedMsg);
    int finishedMsgPos = -1;
    int finishedOffInMsg = -1;
    int finishedLen = 0;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);

    /* Step 1: Client sends ClientHello */
    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WOLFSSL_FATAL_ERROR),
        WOLFSSL_ERROR_WANT_READ);

    /* Step 2: Server sends ServerHello..ServerHelloDone */
    ExpectIntNE(wolfSSL_accept(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WOLFSSL_FATAL_ERROR),
        WOLFSSL_ERROR_WANT_READ);

    /* Step 3: Client processes server flight and queues its second flight. */
    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WOLFSSL_FATAL_ERROR),
        WOLFSSL_ERROR_WANT_READ);

    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(test_tls12_find_client_finished(&test_ctx, &finishedMsgPos,
            &finishedOffInMsg, &finishedLen), 0);
        ExpectIntGT(finishedLen, 0);

        if (finishedOffInMsg == 0) {
            ExpectIntEQ(test_memio_copy_message(&test_ctx, 0, finishedMsg,
                &finishedSz, finishedMsgPos), 0);
            ExpectIntEQ(test_memio_drop_message(&test_ctx, 0, finishedMsgPos), 0);
        }
        else {
            ExpectIntGE(finishedSz, finishedLen);
            XMEMCPY(finishedMsg, test_ctx.s_buff + finishedOffInMsg, finishedLen);
            finishedSz = finishedLen;
            ExpectIntEQ(test_memio_modify_message_len(&test_ctx, 0,
                finishedMsgPos, finishedOffInMsg), 0);
        }
    }

    /* Step 4: Server processes up through CCS but blocks waiting for Finished. */
    ExpectIntNE(wolfSSL_accept(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WOLFSSL_FATAL_ERROR),
        WOLFSSL_ERROR_WANT_READ);

    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(ssl_s->msgsReceived.got_change_cipher, 1);
        ExpectNotNull(ssl_s->hsHashes);
        XMEMSET(&ssl_s->hsHashes->verifyHashes, 0xA5,
            sizeof(ssl_s->hsHashes->verifyHashes));
        ExpectIntEQ(test_memio_inject_message(&test_ctx, 0, finishedMsg,
            finishedSz), 0);
    }

    /* Step 5: Server processes corrupted Finished and must reject it. */
    ExpectIntNE(wolfSSL_accept(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WOLFSSL_FATAL_ERROR),
        WC_NO_ERR_TRACE(VERIFY_FINISHED_ERROR));

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_alert_type_string(void)
{
    EXPECT_DECLS;
#if !defined(NO_TLS) && defined(OPENSSL_EXTRA)
    ExpectStrEQ(wolfSSL_alert_type_string(alert_warning), "W");
    ExpectStrEQ(wolfSSL_alert_type_string(alert_fatal), "F");
    ExpectStrEQ(wolfSSL_alert_type_string(0), "U");
    ExpectStrEQ(wolfSSL_alert_type_string(-1), "U");
    ExpectStrEQ(wolfSSL_alert_type_string(99), "U");
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_get_shared_ciphers(void)
{
    EXPECT_DECLS;
#if !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL*     ssl = NULL;
    char         buf[32];

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    ExpectNull(wolfSSL_get_shared_ciphers(NULL, buf, sizeof(buf)));
    ExpectNull(wolfSSL_get_shared_ciphers(ssl, NULL, sizeof(buf)));
    ExpectNull(wolfSSL_get_shared_ciphers(ssl, buf, 0));
#ifndef NO_ERROR_STRINGS
    ExpectPtrEq(wolfSSL_get_shared_ciphers(ssl, buf, sizeof(buf)), buf);
#else
    ExpectNull(wolfSSL_get_shared_ciphers(ssl, buf, sizeof(buf)));
#endif

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* Test the TLS 1.2 peerAuthGood fail-safe checks directly on both sides.
 * The client branch sets NO_PEER_VERIFY; the server branch returns a generic
 * fatal error from TICKET_SENT before sending its Finished. */
int test_tls12_peerauth_failsafe(void)
{
    EXPECT_DECLS;
#if !defined(WOLFSSL_NO_TLS12) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER)
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    int ret;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);

    if (EXPECT_SUCCESS()) {
        ssl_c->options.connectState = FIRST_REPLY_SECOND;
        ssl_c->options.peerAuthGood = 0;
        ssl_c->options.sendVerify = 0;
        ret = wolfSSL_connect(ssl_c);
        ExpectIntEQ(ret, WOLFSSL_FATAL_ERROR);
        ExpectIntEQ(wolfSSL_get_error(ssl_c, ret),
            WC_NO_ERR_TRACE(NO_PEER_VERIFY));
        ExpectIntEQ(ssl_c->options.connectState, FIRST_REPLY_SECOND);
    }

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ctx_c = NULL;
    ctx_s = NULL;
    ssl_c = NULL;
    ssl_s = NULL;
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);

    if (EXPECT_SUCCESS()) {
        ssl_s->options.acceptState = TICKET_SENT;
        ssl_s->options.peerAuthGood = 0;
        ret = wolfSSL_accept(ssl_s);
        ExpectIntEQ(ret, WOLFSSL_FATAL_ERROR);
        ExpectIntEQ(ssl_s->options.acceptState, TICKET_SENT);
    }

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* TLS 1.2 mutual auth: an ECDHE-ECDSA server (ECDSA certificate) accepting an
 * RSA client certificate. */
int test_tls12_ecdhe_ecdsa_rsa_client_cert(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && !defined(WOLFSSL_NO_TLS12) \
    && defined(HAVE_ECC) && !defined(NO_RSA) && !defined(NO_SHA256) \
    && defined(HAVE_AESGCM) && defined(KEEP_PEER_CERT) \
    && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) \
    && !defined(WOLFSSL_NO_CLIENT_AUTH) \
    && !defined(NO_FILESYSTEM) && !defined(NO_CERTS)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    WOLFSSL_X509* peer = NULL;
    const char* cipher = "ECDHE-ECDSA-AES128-GCM-SHA256";

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);

    /* Server: ECDSA certificate (=> ECDHE-ECDSA suite), require client
     * authentication, and trust the (self-signed) RSA client certificate. */
    ExpectIntEQ(wolfSSL_use_certificate_file(ssl_s, eccCertFile,
                    WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_use_PrivateKey_file(ssl_s, eccKeyFile,
                    WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx_s, cliCertFile, NULL),
                    WOLFSSL_SUCCESS);
    wolfSSL_set_verify(ssl_s, WOLFSSL_VERIFY_PEER |
                    WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    ExpectIntEQ(wolfSSL_set_cipher_list(ssl_s, cipher), WOLFSSL_SUCCESS);

    /* Client: RSA certificate/key, and trust the ECC CA that signed the
     * server's ECDSA certificate. */
    ExpectIntEQ(wolfSSL_use_certificate_file(ssl_c, cliCertFile,
                    WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_use_PrivateKey_file(ssl_c, cliKeyFile,
                    WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx_c, caEccCertFile, NULL),
                    WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_cipher_list(ssl_c, cipher), WOLFSSL_SUCCESS);

    /* Mutual authentication completes and the server obtains the client's
     * RSA certificate even though the negotiated suite is ECDHE-ECDSA. */
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectStrEQ(wolfSSL_get_cipher_name(ssl_c), cipher);
    ExpectNotNull(peer = wolfSSL_get_peer_certificate(ssl_s));
    wolfSSL_X509_free(peer);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* TLS 1.2 mutual auth: an ECDHE-RSA server (RSA certificate) accepting an
 * ECDSA client certificate. */
int test_tls12_ecdhe_rsa_ecdsa_client_cert(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && !defined(WOLFSSL_NO_TLS12) \
    && defined(HAVE_ECC) && !defined(NO_RSA) && !defined(NO_SHA256) \
    && defined(HAVE_AESGCM) && defined(KEEP_PEER_CERT) \
    && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) \
    && !defined(WOLFSSL_NO_CLIENT_AUTH) \
    && !defined(NO_FILESYSTEM) && !defined(NO_CERTS)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    WOLFSSL_X509* peer = NULL;
    const char* cipher = "ECDHE-RSA-AES128-GCM-SHA256";

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);

    /* Server: default RSA certificate (=> ECDHE-RSA), require client
     * authentication, and trust the (self-signed) ECDSA client certificate. */
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx_s, cliEccCertFile, NULL),
                    WOLFSSL_SUCCESS);
    wolfSSL_set_verify(ssl_s, WOLFSSL_VERIFY_PEER |
                    WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    ExpectIntEQ(wolfSSL_set_cipher_list(ssl_s, cipher), WOLFSSL_SUCCESS);

    /* Client: ECDSA certificate/key. The default client CTX already trusts
     * the RSA CA that signed the server's certificate. */
    ExpectIntEQ(wolfSSL_use_certificate_file(ssl_c, cliEccCertFile,
                    WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_use_PrivateKey_file(ssl_c, cliEccKeyFile,
                    WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_cipher_list(ssl_c, cipher), WOLFSSL_SUCCESS);

    /* Mutual authentication completes and the server obtains the client's
     * ECDSA certificate even though the negotiated suite is ECDHE-RSA. */
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectStrEQ(wolfSSL_get_cipher_name(ssl_c), cipher);
    ExpectNotNull(peer = wolfSSL_get_peer_certificate(ssl_s));
    wolfSSL_X509_free(peer);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_alert_desc_string(void)
{
    EXPECT_DECLS;
#if !defined(NO_TLS) && defined(OPENSSL_EXTRA)
    ExpectStrEQ(wolfSSL_alert_desc_string(close_notify), "CN");
    ExpectStrEQ(wolfSSL_alert_desc_string(unexpected_message), "UM");
    ExpectStrEQ(wolfSSL_alert_desc_string(bad_record_mac), "BM");
    ExpectStrEQ(wolfSSL_alert_desc_string(record_overflow), "RO");
    ExpectStrEQ(wolfSSL_alert_desc_string(decompression_failure), "DF");
    ExpectStrEQ(wolfSSL_alert_desc_string(handshake_failure), "HF");
    ExpectStrEQ(wolfSSL_alert_desc_string(no_certificate), "NC");
    ExpectStrEQ(wolfSSL_alert_desc_string(bad_certificate), "BC");
    ExpectStrEQ(wolfSSL_alert_desc_string(unsupported_certificate), "UC");
    ExpectStrEQ(wolfSSL_alert_desc_string(certificate_revoked), "CR");
    ExpectStrEQ(wolfSSL_alert_desc_string(certificate_expired), "CE");
    ExpectStrEQ(wolfSSL_alert_desc_string(certificate_unknown), "CU");
    ExpectStrEQ(wolfSSL_alert_desc_string(illegal_parameter), "IP");
    ExpectStrEQ(wolfSSL_alert_desc_string(unknown_ca), "CA");
    ExpectStrEQ(wolfSSL_alert_desc_string(access_denied), "AD");
    ExpectStrEQ(wolfSSL_alert_desc_string(decode_error), "DE");
    ExpectStrEQ(wolfSSL_alert_desc_string(decrypt_error), "DC");
    ExpectStrEQ(wolfSSL_alert_desc_string(wolfssl_alert_protocol_version), "PV");
    ExpectStrEQ(wolfSSL_alert_desc_string(insufficient_security), "IS");
    ExpectStrEQ(wolfSSL_alert_desc_string(internal_error), "IE");
    ExpectStrEQ(wolfSSL_alert_desc_string(inappropriate_fallback), "IF");
    ExpectStrEQ(wolfSSL_alert_desc_string(user_canceled), "US");
    ExpectStrEQ(wolfSSL_alert_desc_string(no_renegotiation), "NR");
    ExpectStrEQ(wolfSSL_alert_desc_string(missing_extension), "ME");
    ExpectStrEQ(wolfSSL_alert_desc_string(unsupported_extension), "UE");
    ExpectStrEQ(wolfSSL_alert_desc_string(unrecognized_name), "UN");
    ExpectStrEQ(wolfSSL_alert_desc_string(bad_certificate_status_response), "BR");
    ExpectStrEQ(wolfSSL_alert_desc_string(unknown_psk_identity), "UP");
    ExpectStrEQ(wolfSSL_alert_desc_string(certificate_required), "CQ");
    ExpectStrEQ(wolfSSL_alert_desc_string(no_application_protocol), "AP");
    /* Unknown alert description returns "UK" */
    ExpectStrEQ(wolfSSL_alert_desc_string(255), "UK");
#endif
    return EXPECT_RESULT();
}

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES)
/* Cipher-name substrings that need extra setup (PSK callback, ECDSA cert,
 * SRP, etc.) which the default test_memio_setup() doesn't provide. */
static int record_size_skip_cipher(const char *name)
{
    /* "ECDH-" matches static-ECDH ciphers ("ECDH-RSA-*", "ECDH-ECDSA-*")
     * and not ECDHE-* because of the trailing '-'. RENEGOTIATION-INFO is the
     * TLS_EMPTY_RENEGOTIATION_INFO_SCSV signaling value, not a real cipher. */
    static const char* const deny[] = {
        "PSK", "SRP", "ANON", "NULL", "ECDSA", "ECDH-", "SM",
        "RENEGOTIATION-INFO"
    };
    size_t i;
    for (i = 0; i < XELEM_CNT(deny); i++) {
        if (XSTRSTR(name, deny[i]) != NULL)
            return 1;
    }
    return 0;
}

/* Cross-check wolfssl_local_GetRecordSize() against BuildMessage(sizeOnly=1)
 * with the cache cold, then call it a second time and assert both calls
 * return the same size - that exercises the cached path for AEAD ciphers
 * without duplicating the BuildMessage arithmetic. */
static int record_size_check_ssl(WOLFSSL *ssl)
{
    EXPECT_DECLS;
    static const int payloads[] = { 1, 16, 256, 1300, 4096 };
    size_t k;

    for (k = 0; k < XELEM_CNT(payloads); k++) {
        int payloadSz = payloads[k];
        int expectedSz = BuildMessage(ssl, NULL, 0, NULL, payloadSz,
            application_data, 0, 1, 0, CUR_ORDER);
        int firstSz, secondSz;

        ssl->recordSzOverhead = 0;
        firstSz = wolfssl_local_GetRecordSize(ssl, payloadSz, 1);
        secondSz = wolfssl_local_GetRecordSize(ssl, payloadSz, 1);
        ExpectIntEQ(firstSz, expectedSz);
        ExpectIntEQ(secondSz, expectedSz);
    }
    return EXPECT_RESULT();
}

/* Returns 1 if `suite` is selectable for the given client/server method
 * pair, 0 otherwise. wolfSSL rejects some ciphers for DTLS at
 * set_cipher_list time (e.g. RFC 7465 forbids RC4 in DTLS); skip those
 * silently rather than failing the cross-check. */
static int record_size_cipher_selectable(method_provider client_method,
        method_provider server_method, const char *suite)
{
    WOLFSSL_CTX *ctx_c = wolfSSL_CTX_new(client_method());
    WOLFSSL_CTX *ctx_s = wolfSSL_CTX_new(server_method());
    int ok = (ctx_c != NULL && ctx_s != NULL &&
              wolfSSL_CTX_set_cipher_list(ctx_c, suite) == WOLFSSL_SUCCESS &&
              wolfSSL_CTX_set_cipher_list(ctx_s, suite) == WOLFSSL_SUCCESS);
    if (ctx_c) wolfSSL_CTX_free(ctx_c);
    if (ctx_s) wolfSSL_CTX_free(ctx_s);
    return ok;
}

/* Run the cross-check on a memio pair using the given (de)multiplexing
 * methods and cipher suite. Optionally enable DTLS-CID with peer CIDs of
 * different sizes so the test covers CID-extended record framing. */
static int record_size_run_pair(method_provider client_method,
        method_provider server_method, const char *suite, int useCid)
{
    EXPECT_DECLS;
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    (void)useCid;
    if (!record_size_cipher_selectable(client_method, server_method, suite))
        return TEST_SUCCESS; /* not valid for this protocol -- skip */

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    test_ctx.c_ciphers = test_ctx.s_ciphers = suite;
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            client_method, server_method), 0);
#ifdef WOLFSSL_DTLS_CID
    if (useCid) {
        /* Different sizes on each side to exercise asymmetric framing. */
        static unsigned char client_cid[] = { 1, 2, 3, 4, 5, 6 };
        static unsigned char server_cid[] = { 7, 8, 9 };
        ExpectIntEQ(wolfSSL_dtls_cid_use(ssl_c), 1);
        ExpectIntEQ(wolfSSL_dtls_cid_set(ssl_c, server_cid,
                sizeof(server_cid)), 1);
        ExpectIntEQ(wolfSSL_dtls_cid_use(ssl_s), 1);
        ExpectIntEQ(wolfSSL_dtls_cid_set(ssl_s, client_cid,
                sizeof(client_cid)), 1);
    }
#endif
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 30, NULL), 0);
    ExpectIntEQ(record_size_check_ssl(ssl_c), TEST_SUCCESS);
    ExpectIntEQ(record_size_check_ssl(ssl_s), TEST_SUCCESS);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
    return EXPECT_RESULT();
}
#endif /* HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES */

int test_record_size_matches_build_message(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES)
    const CipherSuiteInfo *suites = GetCipherNames();
    int n = GetCipherNamesSize();
    int i;

    for (i = 0; i < n; i++) {
        const char *name = suites[i].name;
        /* Names prefixed "TLS13-" are TLS 1.3 suites regardless of
         * cipherSuite0, which may be either TLS13_BYTE or ECC_BYTE (for
         * the integrity-only TLS_SHA*_SHA* suites). */
        int isTls13 = (XSTRNCMP(name, "TLS13-", 6) == 0);
        if (record_size_skip_cipher(name))
            continue;

        if (isTls13) {
#ifdef WOLFSSL_TLS13
            ExpectIntEQ(record_size_run_pair(wolfTLSv1_3_client_method,
                    wolfTLSv1_3_server_method, name, 0), TEST_SUCCESS);
#endif
#ifdef WOLFSSL_DTLS13
            ExpectIntEQ(record_size_run_pair(wolfDTLSv1_3_client_method,
                    wolfDTLSv1_3_server_method, name, 0), TEST_SUCCESS);
#if defined(WOLFSSL_DTLS_CID)
            ExpectIntEQ(record_size_run_pair(wolfDTLSv1_3_client_method,
                    wolfDTLSv1_3_server_method, name, 1), TEST_SUCCESS);
#endif
#endif
        }
        else {
#ifndef WOLFSSL_NO_TLS12
            ExpectIntEQ(record_size_run_pair(wolfTLSv1_2_client_method,
                    wolfTLSv1_2_server_method, name, 0), TEST_SUCCESS);
#endif
#if defined(WOLFSSL_DTLS) && !defined(WOLFSSL_NO_TLS12)
            ExpectIntEQ(record_size_run_pair(wolfDTLSv1_2_client_method,
                    wolfDTLSv1_2_server_method, name, 0), TEST_SUCCESS);
#if defined(WOLFSSL_DTLS_CID)
            ExpectIntEQ(record_size_run_pair(wolfDTLSv1_2_client_method,
                    wolfDTLSv1_2_server_method, name, 1), TEST_SUCCESS);
#endif
#endif
        }
    }
#endif /* HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES */
    return EXPECT_RESULT();
}

int test_record_size_cache_invalidated_on_renegotiation(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
        defined(HAVE_SECURE_RENEGOTIATION) && !defined(WOLFSSL_NO_TLS12) && \
        defined(BUILD_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    byte readBuf[16];
    int sz;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(wolfSSL_UseSecureRenegotiation(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UseSecureRenegotiation(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    sz = wolfssl_local_GetRecordSize(ssl_c, 256, 1);
    ExpectIntEQ(sz, BuildMessage(ssl_c, NULL, 0, NULL, 256,
            application_data, 0, 1, 0, CUR_ORDER));
    ExpectIntNE(ssl_c->recordSzOverhead, 0);

    ExpectIntEQ(wolfSSL_Rehandshake(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* SetKeysSide() during renegotiation must have cleared the cache. */
    sz = wolfssl_local_GetRecordSize(ssl_c, 256, 1);
    ExpectIntEQ(sz, BuildMessage(ssl_c, NULL, 0, NULL, 256,
            application_data, 0, 1, 0, CUR_ORDER));

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}
