/* test_dtls.c
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
#include <tests/api/test_dtls.h>

/* Cast used to make send()/recv() buffer arguments portable between
 * Windows (char*) and POSIX (void*). Mirrors the private macro in
 * tests/api.c so the DTLS plaintext/fragments tests moved out of api.c
 * still build here. */
#ifdef USE_WINDOWS_API
    #define MESSAGE_TYPE_CAST char*
#else
    #define MESSAGE_TYPE_CAST void*
#endif

int test_dtls12_basic_connection_id(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS_CID)
    unsigned char client_cid[] = { 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
    unsigned char server_cid[] = { 0, 1, 2, 3, 4, 5 };
    unsigned char readBuf[40];
    void *        cid = NULL;
    const char* params[] = {
#ifndef NO_RSA
#ifndef NO_SHA256
#if defined(WOLFSSL_AES_128) && defined(WOLFSSL_STATIC_RSA)
        "AES128-SHA256",
#ifdef HAVE_AESCCM
        "AES128-CCM8",
#endif
#endif /* WOLFSSL_AES_128 && WOLFSSL_STATIC_RSA */
#if defined(WOLFSSL_AES_128)
        "DHE-RSA-AES128-SHA256",
        "ECDHE-RSA-AES128-SHA256",
#ifdef HAVE_AESGCM
        "DHE-RSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
#endif
#endif /* WOLFSSL_AES_128 */
#endif /* NO_SHA256 */
#endif /* NO_RSA */
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305) && !defined(HAVE_FIPS)
        "DHE-RSA-CHACHA20-POLY1305",
        "DHE-RSA-CHACHA20-POLY1305-OLD",
        "ECDHE-RSA-CHACHA20-POLY1305",
        "ECDHE-RSA-CHACHA20-POLY1305-OLD",
#endif
#ifndef NO_PSK
        "DHE-PSK-AES128-CBC-SHA256",
    #ifdef WOLFSSL_AES_256
        "DHE-PSK-AES256-GCM-SHA384",
    #endif
#ifdef HAVE_NULL_CIPHER
        "DHE-PSK-NULL-SHA256",
#endif
        "DHE-PSK-AES128-CCM",
#endif
    };
    size_t i;
    struct {
        byte drop:1;
        byte changeCID:1;
    } run_params[] = {
        { .drop = 0, .changeCID = 0 },
        { .drop = 1, .changeCID = 0 },
        { .drop = 0, .changeCID = 1 },
    };

    /* We check if the side included the CID in their output */
#define CLIENT_CID() mymemmem(test_ctx.s_buff, test_ctx.s_len, \
                              client_cid, sizeof(client_cid))
#define SERVER_CID() mymemmem(test_ctx.c_buff, test_ctx.c_len, \
                              server_cid, sizeof(server_cid))
#define RESET_CID(cid) if ((cid) != NULL) { \
                           ((char*)(cid))[0] = -1; \
                       }


    printf("\n");
    for (i = 0; i < XELEM_CNT(params) && EXPECT_SUCCESS(); i++) {
        size_t j;
        for (j = 0; j < XELEM_CNT(run_params); j++) {
            WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
            WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
            struct test_memio_ctx test_ctx;

            printf("Testing %s run #%ld ... ", params[i], (long int)j);

            XMEMSET(&test_ctx, 0, sizeof(test_ctx));

            ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c,
                &ssl_s, wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method),
                0);

            ExpectIntEQ(wolfSSL_set_cipher_list(ssl_c, params[i]), 1);
            ExpectIntEQ(wolfSSL_set_cipher_list(ssl_s, params[i]), 1);

            ExpectIntEQ(wolfSSL_dtls_cid_use(ssl_c), 1);
            ExpectIntEQ(wolfSSL_dtls_cid_set(ssl_c, server_cid,
                    sizeof(server_cid)), 1);
            ExpectIntEQ(wolfSSL_dtls_cid_use(ssl_s), 1);
            ExpectIntEQ(wolfSSL_dtls_cid_set(ssl_s, client_cid,
                    sizeof(client_cid)), 1);

#ifndef NO_PSK
            if (XSTRSTR(params[i], "-PSK-") != NULL) {
                wolfSSL_set_psk_client_callback(ssl_c, my_psk_client_cb);
                wolfSSL_set_psk_server_callback(ssl_s, my_psk_server_cb);
            }
#endif

#ifdef HAVE_SECURE_RENEGOTIATION
            ExpectIntEQ(wolfSSL_UseSecureRenegotiation(ssl_c), 1);
            ExpectIntEQ(wolfSSL_UseSecureRenegotiation(ssl_s), 1);
#endif

            /* CH1 */
            wolfSSL_SetLoggingPrefix("client");
            ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
            ExpectNull(CLIENT_CID());
            if (run_params[j].drop) {
                test_memio_clear_buffer(&test_ctx, 0);
                test_memio_clear_buffer(&test_ctx, 1);
                ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_c), 1);
                ExpectNull(CLIENT_CID());
            }
            /* HVR */
            wolfSSL_SetLoggingPrefix("server");
            ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
            ExpectNull(SERVER_CID());
            /* No point dropping HVR */
            /* CH2 */
            wolfSSL_SetLoggingPrefix("client");
            ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
            ExpectNull(CLIENT_CID());
            if (run_params[j].drop) {
                test_memio_clear_buffer(&test_ctx, 0);
                test_memio_clear_buffer(&test_ctx, 1);
                ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_c), 1);
                ExpectNull(CLIENT_CID());
            }
            /* Server first flight */
            wolfSSL_SetLoggingPrefix("server");
            ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
            ExpectNull(SERVER_CID());
            if (run_params[j].drop) {
                test_memio_clear_buffer(&test_ctx, 0);
                test_memio_clear_buffer(&test_ctx, 1);
                ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_s), 1);
                ExpectNull(SERVER_CID());
            }
            /* Client second flight */
            wolfSSL_SetLoggingPrefix("client");
            ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
            ExpectNotNull(CLIENT_CID());
            if (run_params[j].drop) {
                test_memio_clear_buffer(&test_ctx, 0);
                test_memio_clear_buffer(&test_ctx, 1);
                ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_c), 1);
                ExpectNotNull(CLIENT_CID());
            }
            /* Server second flight */
            wolfSSL_SetLoggingPrefix("server");
            ExpectIntEQ(wolfSSL_negotiate(ssl_s), 1);
            ExpectNotNull(SERVER_CID());
            if (run_params[j].drop) {
                test_memio_clear_buffer(&test_ctx, 0);
                test_memio_clear_buffer(&test_ctx, 1);
                ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_s), 1);
                ExpectNotNull(SERVER_CID());
            }
            /* Client complete connection */
            wolfSSL_SetLoggingPrefix("client");
            ExpectIntEQ(wolfSSL_negotiate(ssl_c), 1);
            ExpectNull(CLIENT_CID());

            /* Write some data */
            wolfSSL_SetLoggingPrefix("client");
            ExpectIntEQ(wolfSSL_write(ssl_c, params[i],
                    (int)XSTRLEN(params[i])), XSTRLEN(params[i]));
            ExpectNotNull(CLIENT_CID());
            wolfSSL_SetLoggingPrefix("server");
            ExpectIntEQ(wolfSSL_write(ssl_s, params[i],
                    (int)XSTRLEN(params[i])), XSTRLEN(params[i]));
            ExpectNotNull(SERVER_CID());
            /* Read the data */
            wolfSSL_SetLoggingPrefix("client");
            XMEMSET(readBuf, 0, sizeof(readBuf));
            ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)),
                    XSTRLEN(params[i]));
            ExpectStrEQ(readBuf, params[i]);
            XMEMSET(readBuf, 0, sizeof(readBuf));
            wolfSSL_SetLoggingPrefix("server");
            ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)),
                    XSTRLEN(params[i]));
            ExpectStrEQ(readBuf, params[i]);
            /* Write short data */
            wolfSSL_SetLoggingPrefix("client");
            ExpectIntEQ(wolfSSL_write(ssl_c, params[i], 1), 1);
            ExpectNotNull(CLIENT_CID());
            wolfSSL_SetLoggingPrefix("server");
            ExpectIntEQ(wolfSSL_write(ssl_s, params[i], 1), 1);
            ExpectNotNull(SERVER_CID());
            /* Read the short data */
            XMEMSET(readBuf, 0, sizeof(readBuf));
            wolfSSL_SetLoggingPrefix("client");
            ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), 1);
            ExpectIntEQ(readBuf[0], params[i][0]);
            XMEMSET(readBuf, 0, sizeof(readBuf));
            wolfSSL_SetLoggingPrefix("server");
            ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), 1);
            ExpectIntEQ(readBuf[0], params[i][0]);
            /* Write some data but with wrong CID */
            wolfSSL_SetLoggingPrefix("client");
            ExpectIntEQ(wolfSSL_write(ssl_c, params[i],
                    (int)XSTRLEN(params[i])), XSTRLEN(params[i]));
            /* Reset client cid. */
            ExpectNotNull(cid = CLIENT_CID());
            RESET_CID(cid);
            wolfSSL_SetLoggingPrefix("server");
            ExpectIntEQ(wolfSSL_write(ssl_s, params[i],
                    (int)XSTRLEN(params[i])), XSTRLEN(params[i]));
            /* Reset server cid. */
            ExpectNotNull(cid = SERVER_CID());
            RESET_CID(cid);
            /* Try to read the data but it shouldn't be there */
            wolfSSL_SetLoggingPrefix("client");
            ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
            wolfSSL_SetLoggingPrefix("server");
            ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);

#ifdef HAVE_SECURE_RENEGOTIATION
            /* do two SCR's */
            wolfSSL_SetLoggingPrefix("client");
            ExpectIntEQ(wolfSSL_Rehandshake(ssl_c), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
            ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
            ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
            /* SCR's after the first one have extra internal logic */
            wolfSSL_SetLoggingPrefix("client");
            ExpectIntEQ(wolfSSL_Rehandshake(ssl_c), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
            ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
            ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

            if (run_params[j].changeCID) {
                ExpectIntEQ(wolfSSL_dtls_cid_set(ssl_c, client_cid,
                        sizeof(client_cid)), 0);
                /* Forcefully change the CID */
                ssl_c->dtlsCidInfo->rx->id[0] = -1;
                /* We need to init the rehandshake from the client, otherwise
                 * we won't be able to test changing the CID. It would be
                 * rejected by the record CID matching code. */
                wolfSSL_SetLoggingPrefix("client");
                ExpectIntEQ(wolfSSL_Rehandshake(ssl_c), -1);
                ExpectIntEQ(wolfSSL_get_error(ssl_c, -1),
                        WOLFSSL_ERROR_WANT_READ);
                ExpectNotNull(CLIENT_CID());
                ExpectIntEQ(wolfSSL_SSL_renegotiate_pending(ssl_c), 1);
                /* Server first flight */
                wolfSSL_SetLoggingPrefix("server");
                ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
                /* We expect the server to reject the CID change. */
                ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), DTLS_CID_ERROR);
                goto loop_exit;
            }
            /* Server init'd SCR */
            /* Server request */
            wolfSSL_SetLoggingPrefix("server");
            ExpectIntEQ(wolfSSL_Rehandshake(ssl_s), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
            ExpectNotNull(SERVER_CID());
            ExpectIntEQ(wolfSSL_SSL_renegotiate_pending(ssl_s), 1);
            if (run_params[j].drop) {
                test_memio_clear_buffer(&test_ctx, 0);
                test_memio_clear_buffer(&test_ctx, 1);
                ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_s), 1);
                ExpectNotNull(SERVER_CID());
            }
            /* Init SCR on client side with the server's request */
            /* CH no HVR on SCR */
            XMEMSET(readBuf, 0, sizeof(readBuf));
            wolfSSL_SetLoggingPrefix("client");
            ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
            ExpectNotNull(CLIENT_CID());
            ExpectIntEQ(wolfSSL_SSL_renegotiate_pending(ssl_c), 1);
            if (run_params[j].drop) {
                test_memio_clear_buffer(&test_ctx, 0);
                test_memio_clear_buffer(&test_ctx, 1);
                ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_c), 1);
                ExpectNotNull(CLIENT_CID());
            }
            /* Server first flight */
            wolfSSL_SetLoggingPrefix("server");
            ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
            ExpectNotNull(SERVER_CID());
            if (run_params[j].drop) {
                test_memio_clear_buffer(&test_ctx, 0);
                test_memio_clear_buffer(&test_ctx, 1);
                ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_s), 1);
                ExpectNotNull(SERVER_CID());
            }
            /* Client second flight */
            wolfSSL_SetLoggingPrefix("client");
            ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
            ExpectNotNull(CLIENT_CID());
            if (run_params[j].drop) {
                test_memio_clear_buffer(&test_ctx, 0);
                test_memio_clear_buffer(&test_ctx, 1);
                ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_c), 1);
                ExpectNotNull(CLIENT_CID());
            }
            ExpectIntEQ(wolfSSL_write(ssl_c, params[i],
                    (int)XSTRLEN(params[i])), XSTRLEN(params[i]));
            /* Server second flight */
            wolfSSL_SetLoggingPrefix("server");
            ExpectIntEQ(wolfSSL_negotiate(ssl_s), 1);
            XMEMSET(readBuf, 0, sizeof(readBuf));
            ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)),
                    XSTRLEN(params[i]));
            ExpectStrEQ(readBuf, params[i]);
            if (!run_params[j].drop) {
                ExpectIntEQ(wolfSSL_write(ssl_s, params[i],
                        (int)XSTRLEN(params[i])), XSTRLEN(params[i]));
            }
            /* Test loading old epoch */
            /* Client complete connection */
            wolfSSL_SetLoggingPrefix("client");
            if (!run_params[j].drop) {
                ExpectIntEQ(wolfSSL_negotiate(ssl_c), 1);
                XMEMSET(readBuf, 0, sizeof(readBuf));
                ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)),
                        XSTRLEN(params[i]));
                ExpectStrEQ(readBuf, params[i]);
            }
            ExpectIntEQ(wolfSSL_negotiate(ssl_c), 1);
            ExpectNull(CLIENT_CID());
            ExpectIntEQ(wolfSSL_SSL_renegotiate_pending(ssl_c), 0);
            ExpectIntEQ(wolfSSL_SSL_renegotiate_pending(ssl_s), 0);
#endif
            /* Close connection */
            wolfSSL_SetLoggingPrefix("client");
            ExpectIntEQ(wolfSSL_shutdown(ssl_c), WOLFSSL_SHUTDOWN_NOT_DONE);
            ExpectNotNull(CLIENT_CID());
            wolfSSL_SetLoggingPrefix("server");
            ExpectIntEQ(wolfSSL_shutdown(ssl_s), WOLFSSL_SHUTDOWN_NOT_DONE);
            ExpectNotNull(SERVER_CID());
            wolfSSL_SetLoggingPrefix("client");
            ExpectIntEQ(wolfSSL_shutdown(ssl_c), 1);
            wolfSSL_SetLoggingPrefix("server");
            ExpectIntEQ(wolfSSL_shutdown(ssl_s), 1);

#ifdef HAVE_SECURE_RENEGOTIATION
loop_exit:
#endif
            wolfSSL_SetLoggingPrefix(NULL);
            wolfSSL_free(ssl_c);
            wolfSSL_CTX_free(ctx_c);
            wolfSSL_free(ssl_s);
            wolfSSL_CTX_free(ctx_s);

            if (EXPECT_SUCCESS())
                printf("ok\n");
            else
                printf("failed\n");
        }

    }

#undef CLIENT_CID
#undef SERVER_CID
#undef RESET_CID
#endif
    return EXPECT_RESULT();
}


/** Test DTLS 1.3 behavior when server hits WANT_WRITE during HRR
 * The test sets up a DTLS 1.3 connection where the server is forced to
 * return WANT_WRITE when sending the HelloRetryRequest. After the handshake,
 * application data is exchanged in both directions to verify the connection
 * works as expected.
 */

/** Test DTLS 1.3 behavior when every other write returns WANT_WRITE
 * The test sets up a DTLS 1.3 connection where both client and server
 * alternate between WANT_WRITE and successful writes. After the handshake,
 * application data is exchanged in both directions to verify the connection
 * works as expected.
 *
 * Data exchanged after the handshake is also tested with simulated WANT_WRITE
 * conditions to ensure the connection remains functional.
 */

int test_wolfSSL_dtls_cid_parse(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_DTLS) && defined(WOLFSSL_DTLS_CID)
    /* Taken from Wireshark. Right-click -> copy -> ... as escaped string */
    /* Plaintext ServerHelloDone. No CID. */
    byte noCid[] =
            "\x16\xfe\xfd\x00\x00\x00\x00\x00\x00\x00\x04\x00\x0c\x0e\x00\x00" \
            "\x00\x00\x04\x00\x00\x00\x00\x00\x00";
    /* 1.2 app data containing CID */
    byte cid12[] =
            "\x19\xfe\xfd\x00\x01\x00\x00\x00\x00\x00\x01\x77\xa3\x79\x34\xb3" \
            "\xf1\x1f\x34\x00\x1f\xdb\x8c\x28\x25\x9f\xe1\x02\x26\x77\x1c\x3a" \
            "\x50\x1b\x50\x99\xd0\xb5\x20\xd8\x2c\x2e\xaa\x36\x36\xe0\xb7\xb7" \
            "\xf7\x7d\xff\xb0";
#ifdef WOLFSSL_DTLS13
    /* 1.3 app data containing CID */
    byte cid13[] =
            "\x3f\x70\x64\x04\xc6\xfb\x97\x21\xd9\x28\x27\x00\x17\xc1\x01\x86" \
            "\xe7\x23\x2c\xad\x65\x83\xa8\xf4\xbf\xbf\x7b\x25\x16\x80\x19\xc3" \
            "\x81\xda\xf5\x3f";
#endif

    ExpectPtrEq(wolfSSL_dtls_cid_parse(noCid, sizeof(noCid), 8), NULL);
    ExpectPtrEq(wolfSSL_dtls_cid_parse(cid12, sizeof(cid12), 8), cid12 + 11);
#ifdef WOLFSSL_DTLS13
    ExpectPtrEq(wolfSSL_dtls_cid_parse(cid13, sizeof(cid13), 8), cid13 + 1);
#endif
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_dtls_set_pending_peer(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_DTLS) && defined(WOLFSSL_DTLS_CID)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    unsigned char peer[10];
    unsigned int peerSz;
    unsigned char readBuf[10];
    unsigned char client_cid[] = { 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
    unsigned char server_cid[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    /* Setup DTLS contexts */
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfDTLS_client_method, wolfDTLS_server_method), 0);

    ExpectIntEQ(wolfSSL_dtls_cid_use(ssl_c), 1);
    ExpectIntEQ(wolfSSL_dtls_cid_set(ssl_c, server_cid,
            sizeof(server_cid)), 1);
    ExpectIntEQ(wolfSSL_dtls_cid_use(ssl_s), 1);
    ExpectIntEQ(wolfSSL_dtls_cid_set(ssl_s, client_cid,
            sizeof(client_cid)), 1);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    peerSz = sizeof(peer);
    /* Fail since no peer set */
    ExpectIntEQ(wolfSSL_dtls_get_peer(ssl_s, peer, &peerSz), 0);
    ExpectIntEQ(wolfSSL_dtls_set_pending_peer(ssl_s, (void*)"123", 4), 1);
    ExpectIntEQ(wolfSSL_write(ssl_c, "test", 5), 5);
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), 5);
    ExpectStrEQ(readBuf, "test");
    peerSz = sizeof(peer);
    ExpectIntEQ(wolfSSL_dtls_get_peer(ssl_s, peer, &peerSz), 1);
    ExpectIntEQ(peerSz, 4);
    ExpectStrEQ(peer, "123");

    wolfSSL_free(ssl_s);
    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_s);
    wolfSSL_CTX_free(ctx_c);
#endif

#if defined(WOLFSSL_DTLS) && defined(WOLFSSL_DTLS_CID) && \
    !defined(WOLFSSL_NO_SOCK) && defined(XINET_PTON) && \
    defined(HAVE_SOCKADDR) && !defined(WOLFSSL_NO_TLS12) && \
    !defined(NO_WOLFSSL_CLIENT)
    {
        /* Exercise the "already the current peer" branch, which needs real
         * AF_INET addresses (sockAddrEqual() validates the sockaddr). */
        WOLFSSL_CTX* ctx = NULL;
        WOLFSSL* ssl = NULL;
        void* cur = NULL;
        void* other = NULL;
        unsigned int addrSz = (unsigned int)sizeof(SOCKADDR_IN);

        ExpectNotNull(ctx = wolfSSL_CTX_new(wolfDTLSv1_2_client_method()));
        ExpectNotNull(ssl = wolfSSL_new(ctx));
        ExpectNotNull(cur =
            wolfSSL_dtls_create_peer(11111, (char*)"127.0.0.1"));
        ExpectNotNull(other =
            wolfSSL_dtls_create_peer(22222, (char*)"127.0.0.1"));

        /* NULL object fails. */
        ExpectIntEQ(wolfSSL_dtls_set_pending_peer(NULL, cur, addrSz),
            WOLFSSL_FAILURE);

        /* Make 'cur' the current peer. */
        ExpectIntEQ(wolfSSL_dtls_set_peer(ssl, cur, addrSz), WOLFSSL_SUCCESS);

        /* A different address goes to the pending slot (SockAddrSet path). */
        ExpectIntEQ(wolfSSL_dtls_set_pending_peer(ssl, other, addrSz),
            WOLFSSL_SUCCESS);
        /* The current address matches: the staged pending peer is cleared. */
        ExpectIntEQ(wolfSSL_dtls_set_pending_peer(ssl, cur, addrSz),
            WOLFSSL_SUCCESS);
        /* Matches again with no pending peer left to clear. */
        ExpectIntEQ(wolfSSL_dtls_set_pending_peer(ssl, cur, addrSz),
            WOLFSSL_SUCCESS);

        wolfSSL_dtls_free_peer(cur);
        wolfSSL_dtls_free_peer(other);
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
    }
#endif
    return EXPECT_RESULT();
}


int test_dtls_version_checking(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method),
        0);

    /* CH */
    ExpectIntEQ(wolfSSL_connect(ssl_c), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WOLFSSL_FATAL_ERROR),
        WOLFSSL_ERROR_WANT_READ);

    /* modify CH DTLS header to have version 1.1 (0xfe, 0xfe) */
    ExpectIntGE(test_ctx.s_len, 3);
    if (EXPECT_SUCCESS()) {
        test_ctx.s_buff[1] = 0xfe;
        test_ctx.s_buff[2] = 0xfe;
    }

    ExpectIntEQ(wolfSSL_accept(ssl_s), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WOLFSSL_FATAL_ERROR),
        WOLFSSL_ERROR_WANT_READ);
    /* server should drop the message */
    ExpectIntEQ(test_ctx.c_len, 0);

    wolfSSL_free(ssl_c);
    ssl_c = wolfSSL_new(ctx_c);
    ExpectNotNull(ssl_c);
    wolfSSL_SetIOWriteCtx(ssl_c, &test_ctx);
    wolfSSL_SetIOReadCtx(ssl_c, &test_ctx);

    /* try again */
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif /* HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES && WOLFSSL_DTLS */
    return EXPECT_RESULT();
}

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS)
static int test_dtls_shutdown(WOLFSSL *s, WOLFSSL *c, WOLFSSL_CTX *cc, WOLFSSL_CTX *cs)
{
    EXPECT_DECLS;
    /* Cleanup */
    wolfSSL_SetLoggingPrefix("client");
    ExpectIntEQ(wolfSSL_shutdown(c), WOLFSSL_SHUTDOWN_NOT_DONE);
    wolfSSL_SetLoggingPrefix("server");
    ExpectIntEQ(wolfSSL_shutdown(s), WOLFSSL_SHUTDOWN_NOT_DONE);
    wolfSSL_SetLoggingPrefix("client");
    ExpectIntEQ(wolfSSL_shutdown(c), 1);
    wolfSSL_SetLoggingPrefix("server");
    ExpectIntEQ(wolfSSL_shutdown(s), 1);

    wolfSSL_SetLoggingPrefix(NULL);
    wolfSSL_free(c);
    wolfSSL_CTX_free(cc);
    wolfSSL_free(s);
    wolfSSL_CTX_free(cs);
    return EXPECT_RESULT();
}

static int test_dtls_communication(WOLFSSL *s, WOLFSSL *c)
{
    EXPECT_DECLS;
    unsigned char readBuf[50];

    wolfSSL_SetLoggingPrefix("client");
    ExpectIntEQ(wolfSSL_write(c, "client message", 14), 14);

    wolfSSL_SetLoggingPrefix("server");
    XMEMSET(readBuf, 0, sizeof(readBuf));
    ExpectIntEQ(wolfSSL_read(s, readBuf, sizeof(readBuf)), 14);
    ExpectStrEQ(readBuf, "client message");

    wolfSSL_SetLoggingPrefix("server");
    ExpectIntEQ(wolfSSL_write(s, "server message", 14), 14);

    wolfSSL_SetLoggingPrefix("client");
    XMEMSET(readBuf, 0, sizeof(readBuf));
    ExpectIntEQ(wolfSSL_read(c, readBuf, sizeof(readBuf)), 14);
    ExpectStrEQ(readBuf, "server message");

    /* this extra round is consuming newSessionTicket and acks */
    wolfSSL_SetLoggingPrefix("client");
    ExpectIntEQ(wolfSSL_write(c, "client message 2", 16), 16);

    wolfSSL_SetLoggingPrefix("server");
    XMEMSET(readBuf, 0, sizeof(readBuf));
    ExpectIntEQ(wolfSSL_read(s, readBuf, sizeof(readBuf)), 16);
    ExpectStrEQ(readBuf, "client message 2");

    wolfSSL_SetLoggingPrefix("server");
    ExpectIntEQ(wolfSSL_write(s, "server message 2", 16), 16);

    wolfSSL_SetLoggingPrefix("client");
    XMEMSET(readBuf, 0, sizeof(readBuf));
    ExpectIntEQ(wolfSSL_read(c, readBuf, sizeof(readBuf)), 16);
    ExpectStrEQ(readBuf, "server message 2");

    return EXPECT_RESULT();
}

#if defined(WOLFSSL_DTLS13) && !defined(WOLFSSL_DTLS_RECORDS_CAN_SPAN_DATAGRAMS)
int test_dtls13_longer_length(void)
{
    EXPECT_DECLS;
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    unsigned char readBuf[50];
    int seq16bit = 0;
    int ret;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    /* Setup DTLS contexts */
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method),
        0);

    /* Complete handshake */
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* Create good record with length mismatch */
    wolfSSL_SetLoggingPrefix("client");
    ExpectIntEQ(wolfSSL_write(ssl_c, "client message", 14), 14);

    /* check client wrote the record */
    ExpectIntGT(test_ctx.s_len, 14);
    /* check length is included  in the record header */
    ExpectIntGT(test_ctx.s_buff[0x0] & (1 << 2), 0);
    seq16bit = (test_ctx.s_buff[0x0] & (1 << 3)) != 0;
    /* big endian, modify LSB byte */
    seq16bit *= 2;
    /* modify length to be bigger */
    test_ctx.s_buff[0x2 + seq16bit] = 0xff;

    /* Try to read the malformed record */
    wolfSSL_SetLoggingPrefix("server");
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(test_ctx.s_len, 0);

    ExpectIntEQ(test_dtls_communication(ssl_s, ssl_c), TEST_SUCCESS);
    ret = test_dtls_shutdown(ssl_s, ssl_c, ctx_c, ctx_s);
    ExpectIntEQ(ret, TEST_SUCCESS);

    return EXPECT_RESULT();
}
#else
int test_dtls13_longer_length(void)
{
    return TEST_SKIPPED;
}
#endif /* WOLFSSL_DTLS13 && !defined(WOLFSSL_DTLS_RECORDS_CAN_SPAN_DATAGRAMS) */

#if defined(WOLFSSL_DTLS13) && !defined(WOLFSSL_DTLS_RECORDS_CAN_SPAN_DATAGRAMS)
int test_dtls13_short_read(void)
{
    EXPECT_DECLS;
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    unsigned char readBuf[50];
    int i;
    int ret;

    /* we setup two test, in the first one the server reads just two bytes of
     * the header, in the second one it reads just the header (5) */
    for (i = 0; i < 2; i++) {
        XMEMSET(&test_ctx, 0, sizeof(test_ctx));

        /* Setup DTLS contexts */
        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method),
            0);

        /* Complete handshake */
        ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

        /* create a good record in the buffer */
        wolfSSL_SetLoggingPrefix("client");
        ExpectIntEQ(wolfSSL_write(ssl_c, "client message", 14), 14);

        /* check client wrote the record */
        ExpectIntGT(test_ctx.s_len, 14);
        /* return less data */
        ExpectIntEQ(
            test_memio_modify_message_len(&test_ctx, 0, 0, i == 0 ? 2 : 5), 0);
        /* Try to read the malformed record */
        wolfSSL_SetLoggingPrefix("server");
        ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
        ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
        ExpectIntEQ(test_ctx.s_len, 0);

        ExpectIntEQ(test_dtls_communication(ssl_s, ssl_c), TEST_SUCCESS);
        ret = test_dtls_shutdown(ssl_s, ssl_c, ctx_c, ctx_s);
        ExpectIntEQ(ret, TEST_SUCCESS);
        ssl_c = ssl_s = NULL;
        ctx_c = ctx_s = NULL;
    }

    return EXPECT_RESULT();
}
#else
int test_dtls13_short_read(void)
{
    return TEST_SKIPPED;
}
#endif /* WOLFSSL_DTLS13 && !defined(WOLFSSL_DTLS_RECORDS_CAN_SPAN_DATAGRAMS) */

#if !defined(WOLFSSL_DTLS_RECORDS_CAN_SPAN_DATAGRAMS)
int test_dtls12_short_read(void)
{
    EXPECT_DECLS;
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    unsigned char readBuf[50];
    int i;
    int ret;

    for (i = 0; i < 3; i++) {
        XMEMSET(&test_ctx, 0, sizeof(test_ctx));

        /* Setup DTLS contexts */
        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                        wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method),
            0);
        /* Complete handshake */
        ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

        /* create a good record in the buffer */
        wolfSSL_SetLoggingPrefix("client");
        ExpectIntEQ(wolfSSL_write(ssl_c, "bad", 3), 3);

        /* check client wrote the record */
        ExpectIntGT(test_ctx.s_len, 13 + 3);
        /* return less data */
        switch (i) {
        case 0:
            ExpectIntEQ(test_memio_modify_message_len(&test_ctx, 0, 0, 2), 0);
            break;
        case 1:
            ExpectIntEQ(test_memio_modify_message_len(&test_ctx, 0, 0, 13), 0);
            break;
        case 2:
            ExpectIntEQ(test_memio_modify_message_len(&test_ctx, 0, 0, 15), 0);
            break;
        }

        /* Try to read the malformed record */
        wolfSSL_SetLoggingPrefix("server");
        ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
        ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
        ExpectIntEQ(test_ctx.s_len, 0);

        ExpectIntEQ(test_dtls_communication(ssl_s, ssl_c), TEST_SUCCESS);
        ret = test_dtls_shutdown(ssl_s, ssl_c, ctx_c, ctx_s);
        ExpectIntEQ(ret, TEST_SUCCESS);
        ssl_c = ssl_s = NULL;
        ctx_c = ctx_s = NULL;
    }

    return EXPECT_RESULT();
}
#else
int test_dtls12_short_read(void)
{
    return TEST_SKIPPED;
}
#endif /* !defined(WOLFSSL_DTLS_RECORDS_CAN_SPAN_DATAGRAMS) */

#if !defined(WOLFSSL_DTLS_RECORDS_CAN_SPAN_DATAGRAMS)
int test_dtls12_record_length_mismatch(void)
{
    EXPECT_DECLS;
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    unsigned char readBuf[50];
    int ret;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    /* Setup DTLS contexts */
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method),
        0);

    /* Complete handshake */
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* write a message from client */
    ExpectIntEQ(wolfSSL_write(ssl_c, "bad", 3), 3);

    /* check that the message is written in the buffer */
    ExpectIntGT(test_ctx.s_len, 14);
    /* modify the length field to be bigger than the content */
    test_ctx.s_buff[12] = 0xff;

    /* Try to read the malformed record */
    wolfSSL_SetLoggingPrefix("server");
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(test_ctx.s_len, 0);

    ExpectIntEQ(test_dtls_communication(ssl_s, ssl_c), TEST_SUCCESS);
    ret = test_dtls_shutdown(ssl_s, ssl_c, ctx_c, ctx_s);
    ExpectIntEQ(ret, TEST_SUCCESS);

    return EXPECT_RESULT();
}

int test_dtls_record_cross_boundaries(void)
{
    EXPECT_DECLS;
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    unsigned char readBuf[256];
    int rec0_len, rec1_len;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    /* Setup DTLS contexts */
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method),
        0);

    /* Complete handshake */
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* create a first record in the buffer */
    wolfSSL_SetLoggingPrefix("client");
    ExpectIntEQ(wolfSSL_write(ssl_c, "test0", 5), 5);
    rec0_len = test_ctx.s_msg_sizes[0];

    /* create a second record in the buffer */
    ExpectIntEQ(wolfSSL_write(ssl_c, "test1", 5), 5);
    rec1_len = test_ctx.s_msg_sizes[1];

    ExpectIntLE(rec0_len + rec1_len, sizeof(readBuf));
    if (EXPECT_SUCCESS())
        XMEMCPY(readBuf, test_ctx.s_buff, rec0_len + rec1_len);

    /* clear buffer */
    test_memio_clear_buffer(&test_ctx, 0);

    /* inject first record + 1 bytes of second record */
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 0, (const char*)readBuf,
                    rec0_len + 1),
        0);

    /* inject second record */
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 0,
                    (const char*)readBuf + rec0_len + 1, rec1_len - 1),
        0);
    ExpectIntEQ(test_ctx.s_len, rec0_len + rec1_len);

    /* reading the record should return just the first message*/
    wolfSSL_SetLoggingPrefix("server");
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), 5);
    ExpectBufEQ(readBuf, "test0", 5);

    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)),
        WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);

    /* cleanup */
    wolfSSL_free(ssl_s);
    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_s);
    wolfSSL_CTX_free(ctx_c);

    return EXPECT_RESULT();
}
#else
int test_dtls12_record_length_mismatch(void)
{
    return TEST_SKIPPED;
}
int test_dtls_record_cross_boundaries(void)
{
    return TEST_SKIPPED;
}
#endif /* !defined(WOLFSSL_DTLS_RECORDS_CAN_SPAN_DATAGRAMS) */

int test_dtls_short_ciphertext(void)
{
    EXPECT_DECLS;
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    unsigned char readBuf[50];
    int ret;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    /* Setup DTLS contexts */
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method),
        0);

    /* Complete handshake */
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* Create a message, that looks encrypted but shorter than minimum ciphertext length */
    /* create the data in the buffer */
    ExpectIntEQ(wolfSSL_write(ssl_c, "bad", 3), 3);

    /* check client wrote the record */
    ExpectIntGT(test_ctx.s_len, 14);

    /* modify the length field to be smaller than the content */
    test_ctx.s_buff[11] = 0x00;
    test_ctx.s_buff[12] = 0x02;
    /* modify the amount of data to send */
    ExpectIntEQ(test_memio_modify_message_len(&test_ctx, 0, 0, 15), 0);

    /* Try to read the malformed record */
    wolfSSL_SetLoggingPrefix("server");
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(test_ctx.s_len, 0);

    ExpectIntEQ(test_dtls_communication(ssl_s, ssl_c), TEST_SUCCESS);

    ret = test_dtls_shutdown(ssl_s, ssl_c, ctx_c, ctx_s);
    ExpectIntEQ(ret, TEST_SUCCESS);

    return EXPECT_RESULT();
}
#else
int test_dtls_short_ciphertext(void)
{
    return TEST_SKIPPED;
}
int test_dtls12_record_length_mismatch(void)
{
    return TEST_SKIPPED;
}
int test_dtls12_short_read(void)
{
    return TEST_SKIPPED;
}
int test_dtls13_short_read(void)
{
    return TEST_SKIPPED;
}
int test_dtls13_longer_length(void)
{
    return TEST_SKIPPED;
}
int test_dtls_record_cross_boundaries(void)
{
    return TEST_SKIPPED;
}
#endif /* defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS) */

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(WOLFSSL_NO_TLS12) && !defined(NO_SHA256)
/* This test that the DTLS record boundary check doesn't interfere with TLS
 * records processing */
int test_records_span_network_boundaries(void)
{
    EXPECT_DECLS;
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    unsigned char readBuf[256];
    int record_len;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    /* Setup DTLS contexts */
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_2_client_method, wolfTLSv1_2_server_method),
        0);

    /* Complete handshake */
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* create a good record in the buffer */
    wolfSSL_SetLoggingPrefix("client");
    ExpectIntEQ(wolfSSL_write(ssl_c, "test", 4), 4);
    ExpectIntLE(test_ctx.s_len, sizeof(readBuf));
    ExpectIntGT(test_ctx.s_len, 10);
    record_len = test_ctx.s_len;
    if (EXPECT_SUCCESS())
        XMEMCPY(readBuf, test_ctx.s_buff, record_len);

    /* drop record and simulate a split write */
    ExpectIntEQ(test_memio_drop_message(&test_ctx, 0, 0), 0);
    ExpectIntEQ(test_ctx.s_msg_count, 0);

    /* inject first record header */
    ExpectIntEQ(
        test_memio_inject_message(&test_ctx, 0, (const char*)readBuf, 5), 0);
    ExpectIntEQ(test_ctx.s_msg_count, 1);
    ExpectIntEQ(test_ctx.s_msg_sizes[0], 5);

    /* inject another 5 bytes of the record */
    ExpectIntEQ(
        test_memio_inject_message(&test_ctx, 0, (const char*)readBuf + 5, 5),
        0);
    ExpectIntEQ(test_ctx.s_msg_count, 2);
    ExpectIntEQ(test_ctx.s_msg_sizes[1], 5);

    /* inject the rest of the record */
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 0,
                    (const char*)readBuf + 10, record_len - 10),
        0);
    ExpectIntEQ(test_ctx.s_msg_count, 3);
    ExpectIntEQ(test_ctx.s_msg_sizes[2], record_len - 10);

    /* read the record */
    wolfSSL_SetLoggingPrefix("server");
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), 4);
    ExpectIntEQ(test_ctx.s_len, 0);

    ExpectBufEQ(readBuf, "test", 4);

    wolfSSL_free(ssl_s);
    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_s);
    wolfSSL_CTX_free(ctx_c);

    return EXPECT_RESULT();
}
#else
int test_records_span_network_boundaries(void)
{
    return TEST_SKIPPED;
}
#endif /* defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) &&                     \
          !defined(WOLFSSL_NO_TLS12) */

int test_dtls_mtu_fragment_headroom(void)
{
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) &&                           \
    defined(WOLFSSL_DTLS_MTU) && defined(HAVE_AESGCM) && defined(HAVE_ECC) &&  \
    !defined(WOLFSSL_NO_DTLS_SIZE_CHECK)
    EXPECT_DECLS;
    struct {
        method_provider client_meth;
        method_provider server_meth;
        const char* cipher;
        int use_cid;
    } params[] = {
#if defined(WOLFSSL_DTLS13) && defined(WOLFSSL_TLS13)
        { wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method,
          "TLS13-AES128-GCM-SHA256", 0 },
#ifdef WOLFSSL_DTLS_CID
        { wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method,
          "TLS13-AES128-GCM-SHA256", 1 },
#endif
#endif
#if defined(WOLFSSL_DTLS) && !defined(WOLFSSL_NO_TLS12)
        { wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method,
          "ECDHE-RSA-AES128-GCM-SHA256", 0 },
#ifdef WOLFSSL_DTLS_CID
        { wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method,
          "ECDHE-RSA-AES128-GCM-SHA256", 1 },
#endif
#if !defined(WOLFSSL_AEAD_ONLY) && !defined(NO_AES) && !defined(NO_SHA)
        { wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method,
          "ECDHE-RSA-AES128-SHA", 0 },
#ifdef WOLFSSL_DTLS_CID
        { wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method,
          "ECDHE-RSA-AES128-SHA", 1 },
#endif
#endif
#endif
    };
    size_t i;

    for (i = 0; i < XELEM_CNT(params) && EXPECT_SUCCESS(); i++) {
        WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
        WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
        struct test_memio_ctx test_ctx;
        unsigned char payload[33];
        word16 mtu;
        int recordLen;
        int overhead;
        int ret;

        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        XMEMSET(payload, 'A', sizeof(payload));

        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                        params[i].client_meth, params[i].server_meth),
            0);

        ExpectIntEQ(wolfSSL_set_cipher_list(ssl_c, params[i].cipher), 1);
        ExpectIntEQ(wolfSSL_set_cipher_list(ssl_s, params[i].cipher), 1);

#ifdef WOLFSSL_DTLS_CID
        if (params[i].use_cid) {
            unsigned char cid_c[] = { 0,1,2,3 };
            unsigned char cid_s[] = { 4,5,6,7,8,9 };
            ExpectIntEQ(wolfSSL_dtls_cid_use(ssl_c), 1);
            ExpectIntEQ(wolfSSL_dtls_cid_use(ssl_s), 1);
            ExpectIntEQ(wolfSSL_dtls_cid_set(ssl_c, cid_s, (int)sizeof(cid_s)),
                1);
            ExpectIntEQ(wolfSSL_dtls_cid_set(ssl_s, cid_c, (int)sizeof(cid_c)),
                1);
        }
#endif

        /* Complete handshake and clear any leftover records. */
        ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
        test_memio_clear_buffer(&test_ctx, 1);
        test_memio_clear_buffer(&test_ctx, 0);

        /* Measure application-data record overhead. */
        ExpectIntEQ(wolfSSL_write(ssl_c, payload, 32), 32);
        ExpectIntEQ(test_ctx.s_msg_count, 1);
        recordLen = test_ctx.s_len;
        ExpectIntGT(recordLen, 32);
        overhead = recordLen - 32;

        /* Reset buffers before MTU-limited send. */
        test_memio_clear_buffer(&test_ctx, 0);
        test_memio_clear_buffer(&test_ctx, 1);

        /* Set MTU to overhead + 32 bytes of payload. */
        mtu = (word16)(overhead + 32);
        ExpectIntEQ(wolfSSL_dtls_set_mtu(ssl_c, mtu), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_dtls_set_mtu(ssl_s, mtu), WOLFSSL_SUCCESS);

        /* With the tightened MTU, we should still be able to send 32 bytes. */
        ExpectIntEQ(wolfSSL_write(ssl_c, payload, 32), 32);
        ExpectIntEQ(test_ctx.s_msg_count, 1);
        recordLen = test_ctx.s_len;
        ExpectIntEQ(recordLen, overhead + 32);
        ExpectIntLE(recordLen, mtu);

        /* Underestimation: drop MTU by 1 and expect DTLS_SIZE_ERROR. */
        test_memio_clear_buffer(&test_ctx, 0);
        test_memio_clear_buffer(&test_ctx, 1);
        ExpectIntEQ(wolfSSL_dtls_set_mtu(ssl_c, mtu - 1), WOLFSSL_SUCCESS);
        ret = wolfSSL_write(ssl_c, payload, 32);
        ExpectIntNE(ret, 32);
        ExpectIntEQ(wolfSSL_get_error(ssl_c, ret), DTLS_SIZE_ERROR);

        wolfSSL_free(ssl_c);
        wolfSSL_CTX_free(ctx_c);
        wolfSSL_free(ssl_s);
        wolfSSL_CTX_free(ctx_s);
    }
    return EXPECT_RESULT();
#else
    return TEST_SKIPPED;
#endif
}

int test_dtls_rtx_across_epoch_change(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) &&                           \
    defined(WOLFSSL_DTLS13) && defined(WOLFSSL_DTLS)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
#if defined(WOLFSSL_HAVE_MLKEM)
    /* When ML-KEM is used in the key share, the hello messages are fragmented
     *into two messages */
    int helloMsgCount = 2;
    int groups[2] = {
    #if defined(HAVE_CURVE25519) && defined(WOLFSSL_PQC_HYBRIDS) && \
        !defined(WOLFSSL_NO_ML_KEM) && !defined(WOLFSSL_NO_ML_KEM_768)
        WOLFSSL_X25519MLKEM768,
    #elif defined(HAVE_ECC) && defined(WOLFSSL_PQC_HYBRIDS) && \
        !defined(WOLFSSL_NO_ML_KEM) && !defined(WOLFSSL_NO_ML_KEM_768)
        WOLFSSL_SECP256R1MLKEM768,
    #elif defined(HAVE_ECC) && defined(WOLFSSL_PQC_HYBRIDS) && \
        !defined(WOLFSSL_NO_ML_KEM) && !defined(WOLFSSL_NO_ML_KEM_1024)
        WOLFSSL_SECP384R1MLKEM1024,
    #elif !defined(WOLFSSL_NO_ML_KEM_1024) && !defined(WOLFSSL_NO_ML_KEM) && \
                                       !defined(WOLFSSL_TLS_NO_MLKEM_STANDALONE)
        WOLFSSL_ML_KEM_1024,
    #elif !defined(WOLFSSL_NO_ML_KEM_768) && !defined(WOLFSSL_NO_ML_KEM) && \
                                       !defined(WOLFSSL_TLS_NO_MLKEM_STANDALONE)
        WOLFSSL_ML_KEM_768,
    #elif !defined(WOLFSSL_NO_ML_KEM_512) && \
                                       !defined(WOLFSSL_TLS_NO_MLKEM_STANDALONE)
        WOLFSSL_ML_KEM_512,
    #elif defined(WOLFSSL_MLKEM_KYBER) && !defined(WOLFSSL_NO_KYBER1024)
        WOLFSSL_KYBER_LEVEL5,
    #elif defined(WOLFSSL_MLKEM_KYBER) && !defined(WOLFSSL_NO_KYBER768)
        WOLFSSL_KYBER_LEVEL3,
    #elif defined(WOLFSSL_MLKEM_KYBER) && !defined(WOLFSSL_NO_KYBER512)
        WOLFSSL_KYBER_LEVEL1,
    #endif
        WOLFSSL_ECC_SECP256R1,
    };
#else
    /* When ECC is used in the key share, the hello messages are not
     * fragmented */
    int helloMsgCount = 1;
#endif

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    /* Setup DTLS contexts */
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method),
        0);

#if defined(WOLFSSL_HAVE_MLKEM)
    ExpectIntEQ(wolfSSL_set_groups(ssl_c, groups, 2), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_groups(ssl_s, groups, 2), WOLFSSL_SUCCESS);
#endif

    /* CH0 */
    wolfSSL_SetLoggingPrefix("client:");
    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), SSL_ERROR_WANT_READ);

    /* HRR */
    wolfSSL_SetLoggingPrefix("server:");
    ExpectIntEQ(wolfSSL_accept(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), SSL_ERROR_WANT_READ);

    /* CH1 */
    wolfSSL_SetLoggingPrefix("client:");
    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), SSL_ERROR_WANT_READ);

    /* SH ... FINISHED */
    wolfSSL_SetLoggingPrefix("server:");
    ExpectIntEQ(wolfSSL_accept(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), SSL_ERROR_WANT_READ);

    /* we should have now SH ... FINISHED messages in the buffer*/
    ExpectIntGE(test_ctx.c_msg_count, 2);

    /* drop everything but the SH */
    while (test_ctx.c_msg_count > helloMsgCount && EXPECT_SUCCESS()) {
        ExpectIntEQ(test_memio_drop_message(&test_ctx, 1, test_ctx.c_msg_count - 1), 0);
    }

    /* Read the SH */
    wolfSSL_SetLoggingPrefix("client:");
    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), SSL_ERROR_WANT_READ);

    /* trigger client timeout */
    ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_c), WOLFSSL_SUCCESS);
    /* this should have triggered a rtx */
    ExpectIntGT(test_ctx.s_msg_count, 0);

    /* finish the handshake */
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* Test communication works correctly */
    ExpectIntEQ(test_dtls_communication(ssl_s, ssl_c), TEST_SUCCESS);

    /* Cleanup */
    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif /* defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) &&                     \
          defined(WOLFSSL_DTLS13) */
    return EXPECT_RESULT();
}




int test_dtls_drop_client_ack(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) &&                           \
    defined(WOLFSSL_DTLS13) && defined(WOLFSSL_DTLS)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    char data[32];

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    /* Setup DTLS contexts */
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method),
        0);

    /* disable new session ticket to simplify testing */
    ExpectIntEQ(wolfSSL_no_ticket_TLSv13(ssl_s), 0);

    /* CH0 */
    wolfSSL_SetLoggingPrefix("client:");
    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);

    /* HRR */
    wolfSSL_SetLoggingPrefix("server:");
    ExpectIntEQ(wolfSSL_accept(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);

    /* CH1 */
    wolfSSL_SetLoggingPrefix("client:");
    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);

    /* SH ... FINISHED */
    wolfSSL_SetLoggingPrefix("server:");
    ExpectIntEQ(wolfSSL_accept(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);

    /* ... FINISHED */
    wolfSSL_SetLoggingPrefix("client:");
    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);

    /* init is finished should return false at this point */
    ExpectFalse(wolfSSL_is_init_finished(ssl_c));

    /* ACK */
    ExpectIntEQ(wolfSSL_accept(ssl_s), WOLFSSL_SUCCESS);
    /* Drop the ack */
    test_memio_clear_buffer(&test_ctx, 1);

    /* trigger client timeout, finished should be rtx */
    ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_c), WOLFSSL_SUCCESS);
    /* this should have triggered a rtx */
    ExpectIntGT(test_ctx.s_msg_count, 0);

    /* this should re-send the ack immediately */
    ExpectIntEQ(wolfSSL_read(ssl_s, data, 32), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(test_ctx.c_msg_count, 1);

    /* This should advance the connection on the client */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), WOLFSSL_SUCCESS);

    /* Test communication works correctly */
    ExpectIntEQ(test_dtls_communication(ssl_s, ssl_c), TEST_SUCCESS);

    /* Cleanup */
    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif /* defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) &&                     \
          defined(WOLFSSL_DTLS13) */
    return EXPECT_RESULT();
}

int test_dtls_bogus_finished_epoch_zero(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS) && \
    !defined(WOLFSSL_NO_TLS12) && defined(HAVE_AES_CBC) && \
    defined(WOLFSSL_AES_128) && !defined(NO_SHA256)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    int error;

    /* bogus Finished message bytes from the original bug report (epoch 0)
     * https://github.com/wolfSSL/wolfssl/issues/9188 */
    static const unsigned char bogus_finished[] = {
        0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x18, 0x14, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0xd9, 0xc6, 0xe3, 0x01, 0x59, 0xf2, 0xc2, 0x4f, 0xfa, 0xfd, 0x20,
        0xd7
    };

    /* serverHelloDone message bytes */
    static const unsigned char server_hello_done_message[] = {
        0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x0c, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00
    };

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    /* setting up dtls 1.2 contexts */
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method), 0);

    /* start handshake, send first ClientHelloDone */
    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);

    /* clearing server buffer to inject the wrong Finished packet */
    test_memio_clear_buffer(&test_ctx, 1);
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 1,
            (const char*)bogus_finished, sizeof(bogus_finished)), 0);

    /* continue client handshake to process it */
    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);

    /* client should terminate with dtls sequence error */
    error = wolfSSL_get_error(ssl_c, -1);

    /* check if the error is SEQUENCE_ERROR, handshake should not
     * expect a finished packet in that moment, in particular should not
     * be in epoch = 0 (should be epoch = 1) */
    ExpectTrue(error == WC_NO_ERR_TRACE(SEQUENCE_ERROR) ||
               error == WC_NO_ERR_TRACE(WOLFSSL_ERROR_WANT_READ));

    /* forcing injection ServerHelloDone to test if client would replay
     * ClientHello */
    test_memio_clear_buffer(&test_ctx, 0);
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 1,
            (const char*)server_hello_done_message, sizeof(server_hello_done_message)), 0);
    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);

    /* verifying no ClientHello replay occurred,
     * buffer should empty since we exit early on
     * because of the bogus finished packet */
    ExpectIntLE(test_ctx.s_len, 0);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

int test_dtls_replay(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS)
    size_t i;
    struct {
        method_provider client_meth;
        method_provider server_meth;
        const char* tls_version;
    } params[] = {
#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_DTLS13)
        { wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method, "DTLSv1_3" },
#endif
#if !defined(WOLFSSL_NO_TLS12) && defined(WOLFSSL_DTLS)
        { wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method, "DTLSv1_2" },
#endif
#if !defined(NO_OLD_TLS) && defined(WOLFSSL_DTLS)
        { wolfDTLSv1_client_method, wolfDTLSv1_server_method, "DTLSv1_0" },
#endif
    };
    for (i = 0; i < XELEM_CNT(params) && !EXPECT_FAIL(); i++) {
        WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
        WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
        struct test_memio_ctx test_ctx;

        char msg_buf[256];
        int msg_len = sizeof(msg_buf);
        byte app_data[8];

        XMEMSET(&test_ctx, 0, sizeof(test_ctx));

        /* Setup DTLS contexts */
        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                params[i].client_meth, params[i].server_meth), 0);
        ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

        ExpectIntEQ(wolfSSL_write(ssl_c, "test", 4), 4);
        ExpectIntEQ(test_memio_copy_message(&test_ctx, 0, msg_buf, &msg_len, 0), 0);
        ExpectIntEQ(wolfSSL_read(ssl_s, app_data, sizeof(app_data)), 4);
        ExpectIntEQ(test_memio_inject_message(&test_ctx, 0, msg_buf, msg_len), 0);
        ExpectIntEQ(wolfSSL_read(ssl_s, app_data, sizeof(app_data)), -1);
        ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);

        wolfSSL_free(ssl_c);
        wolfSSL_CTX_free(ctx_c);
        wolfSSL_free(ssl_s);
        wolfSSL_CTX_free(ctx_s);
    }
#endif
    return EXPECT_RESULT();
}


int test_dtls_timeout(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS)
    size_t i;
    struct {
        method_provider client_meth;
        method_provider server_meth;
    } params[] = {
#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_DTLS13)
        { wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method },
#endif
#if !defined(WOLFSSL_NO_TLS12) && defined(WOLFSSL_DTLS)
        { wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method },
#endif
#if !defined(NO_OLD_TLS) && defined(WOLFSSL_DTLS)
        { wolfDTLSv1_client_method, wolfDTLSv1_server_method },
#endif
    };

    for (i = 0; i < XELEM_CNT(params) && !EXPECT_FAIL(); i++) {
        WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
        WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
        struct test_memio_ctx test_ctx;

        XMEMSET(&test_ctx, 0, sizeof(test_ctx));

        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                params[i].client_meth, params[i].server_meth), 0);
        ExpectIntEQ(wolfSSL_dtls_set_timeout_max(ssl_c, 2), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
        ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_DTLS13)
        /* will return 0 when not 1.3 */
        if (wolfSSL_dtls13_use_quick_timeout(ssl_c))
            ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_c), WOLFSSL_SUCCESS);
#endif
        ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_c), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_dtls_get_current_timeout(ssl_c), 2);
        ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
        ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
        ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
        ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
        ExpectIntEQ(wolfSSL_dtls_get_current_timeout(ssl_c), 1);
#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_DTLS13)
        /* will return 0 when not 1.3 */
        if (wolfSSL_dtls13_use_quick_timeout(ssl_c))
            ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_c), WOLFSSL_SUCCESS);
#endif
        ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_c), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_dtls_get_current_timeout(ssl_c), 2);
        ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

        wolfSSL_free(ssl_s);
        wolfSSL_free(ssl_c);
        wolfSSL_CTX_free(ctx_s);
        wolfSSL_CTX_free(ctx_c);
    }
#endif
    return EXPECT_RESULT();
}

int test_dtls_certreq_order(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS) && \
    !defined(WOLFSSL_NO_TLS12) && defined(HAVE_AESGCM) && \
    defined(WOLFSSL_AES_128) && !defined(NO_SHA256) && !defined(NO_RSA) && \
    !defined(NO_DH)
    /* This test checks that a certificate request message
     * received before server certificate message is properly detected.
     * The binary is taken from https://github.com/wolfSSL/wolfssl/issues/9198
     */
    static const unsigned char certreq_before_cert_bin[] = {
      0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x39, 0x02, 0x00, 0x00, 0x2d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x2d, 0xfe, 0xfd, 0x48, 0xc0, 0xd5, 0xf2, 0x60, 0xb4, 0x20, 0xbb, 0x38,
      0x51, 0xd9, 0xd4, 0x7a, 0xcb, 0x93, 0x3d, 0xbe, 0x70, 0x39, 0x9b, 0xf6,
      0xc9, 0x2d, 0xa3, 0x3a, 0xf0, 0x1d, 0x4f, 0xb7, 0x70, 0xe9, 0x8c, 0x00,
      0x00, 0x9e, 0x00, 0x00, 0x05, 0x00, 0x0f, 0x00, 0x01, 0x01, 0x16, 0xfe,
      0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x3a, 0x0d,
      0x00, 0x00, 0x2e, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2e, 0x01,
      0x01, 0x00, 0x28, 0x02, 0x02, 0x03, 0x02, 0x04, 0x02, 0x05, 0x02, 0x06,
      0x02, 0x01, 0x01, 0x02, 0x01, 0x03, 0x01, 0x04, 0x01, 0x05, 0x01, 0x06,
      0x01, 0x02, 0x03, 0x03, 0x03, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08,
      0x04, 0x08, 0x05, 0x08, 0x06, 0x07, 0x08, 0x00, 0x00, 0x16, 0xfe, 0xfd,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x2b, 0x0b, 0x00,
      0x03, 0x1f, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x03, 0x1f, 0x00, 0x03,
      0x1c, 0x00, 0x03, 0x19, 0x30, 0x82, 0x03, 0x15, 0x30, 0x82, 0x01, 0xfd,
      0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x40, 0xe7, 0x6e, 0x85, 0x66,
      0x7c, 0x3f, 0x04, 0x87, 0x4c, 0x3f, 0x94, 0x21, 0x6d, 0x21, 0x65, 0xa5,
      0x28, 0xa7, 0x38, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
      0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x1a, 0x31, 0x18, 0x30, 0x16,
      0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0f, 0x64, 0x74, 0x6c, 0x73, 0x2d,
      0x66, 0x75, 0x7a, 0x7a, 0x65, 0x72, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x1e,
      0x17, 0x0d, 0x32, 0x34, 0x30, 0x36, 0x30, 0x36, 0x31, 0x32, 0x31, 0x33,
      0x30, 0x33, 0x5a, 0x17, 0x0d, 0x33, 0x38, 0x30, 0x32, 0x31, 0x33, 0x31,
      0x32, 0x31, 0x33, 0x30, 0x33, 0x5a, 0x30, 0x1a, 0x31, 0x18, 0x30, 0x16,
      0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0f, 0x64, 0x74, 0x6c, 0x73, 0x2d,
      0x66, 0x75, 0x7a, 0x7a, 0x65, 0x72, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x82,
      0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
      0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82,
      0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xbb, 0x2a, 0x06, 0xfa, 0xaf,
      0x9c, 0xb7, 0xeb, 0x33, 0xce, 0xde, 0xf6, 0xb6, 0x0a, 0x93, 0xb3, 0x97,
      0x7a, 0x36, 0x55, 0x89, 0xc2, 0xf5, 0x45, 0x84, 0x6d, 0x45, 0x25, 0x5c,
      0x4f, 0xa8, 0x8a, 0x41, 0x29, 0x5b, 0x71, 0x98, 0x6c, 0x63, 0xe7, 0xcf,
      0x7f, 0xb4, 0x9d, 0x06, 0x76, 0x60, 0x8c, 0x6a, 0x26, 0x47, 0x65, 0x5d,
      0x74, 0x7a, 0xb5, 0x40, 0x33, 0x61, 0xe0, 0x28, 0xed, 0xa6, 0x66, 0x6a,
      0x4b, 0x97, 0xaf, 0xae, 0x6c, 0xa1, 0xf2, 0xfc, 0xd0, 0xf1, 0x61, 0x98,
      0x05, 0x2a, 0x02, 0x42, 0x13, 0x06, 0x7c, 0x4a, 0x7e, 0x53, 0x01, 0x87,
      0x27, 0x6c, 0x41, 0xe8, 0xed, 0x6e, 0xb2, 0x45, 0x90, 0xe8, 0x93, 0xc0,
      0x20, 0xff, 0x64, 0xdf, 0x48, 0x57, 0xb9, 0x62, 0x8c, 0x14, 0x88, 0xc9,
      0x4a, 0x56, 0x3f, 0x5d, 0x9f, 0xeb, 0x1d, 0x79, 0x75, 0xfd, 0x24, 0xad,
      0xb6, 0x65, 0x1d, 0x53, 0x81, 0x5c, 0x67, 0xbe, 0x3a, 0x9d, 0xcd, 0xe1,
      0x47, 0xab, 0x8d, 0xd4, 0xa5, 0xbd, 0xa6, 0xd7, 0x60, 0xf9, 0x5c, 0x32,
      0x51, 0x65, 0x7e, 0x8b, 0xd6, 0xa1, 0x5b, 0xa2, 0xf5, 0x60, 0xaf, 0x29,
      0xff, 0x9f, 0x3a, 0xa4, 0xd0, 0x5d, 0x6e, 0x96, 0x09, 0xe8, 0xcf, 0xc3,
      0xe1, 0xe8, 0x5a, 0x82, 0xce, 0x9a, 0x3c, 0xc6, 0xbb, 0xe5, 0x4c, 0xa8,
      0xa4, 0xb0, 0xfd, 0x86, 0x06, 0x8b, 0x3f, 0x7e, 0x38, 0xe4, 0x06, 0xdf,
      0xf7, 0x9c, 0xc6, 0x8b, 0x1d, 0xb5, 0xad, 0x7a, 0x91, 0x5f, 0x64, 0xa5,
      0x69, 0xc8, 0x7b, 0x77, 0x32, 0x71, 0x8f, 0x73, 0x82, 0xd2, 0x21, 0xe8,
      0xa8, 0x81, 0xfe, 0x76, 0x7f, 0x20, 0xd1, 0xb6, 0x42, 0x9e, 0xaf, 0x60,
      0x85, 0x47, 0xf5, 0xfe, 0x9f, 0x85, 0xbf, 0xb0, 0x11, 0xb7, 0xf7, 0x83,
      0x0d, 0x80, 0x63, 0xa0, 0xf7, 0x0c, 0x2c, 0x83, 0x12, 0xa9, 0x0f, 0x02,
      0x03, 0x01, 0x00, 0x01, 0xa3, 0x53, 0x30, 0x51, 0x30, 0x1d, 0x06, 0x03,
      0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x2a, 0xb5, 0x00, 0x45, 0x06,
      0x08, 0xef, 0xe5, 0xfa, 0x78, 0x19, 0x47, 0x5b, 0x04, 0x40, 0x18, 0xf3,
      0xeb, 0xab, 0x99, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18,
      0x30, 0x16, 0x80, 0x14, 0x2a, 0xb5, 0x00, 0x45, 0x06, 0x08, 0xef, 0xe5,
      0xfa, 0x78, 0x19, 0x47, 0x5b, 0x04, 0x40, 0x18, 0xf3, 0xeb, 0xab, 0x99,
      0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05,
      0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
      0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01,
      0x00, 0xa7, 0x58, 0x65, 0xfc, 0x60, 0x3e, 0xb7, 0x34, 0x82, 0xde, 0x04,
      0x06, 0x3d, 0x69, 0x62, 0x8a, 0x4c, 0xcc, 0xd6, 0x54, 0x72, 0x81, 0xcb,
      0x31, 0xdf, 0x63, 0xaf, 0x84, 0x27, 0x62, 0xbf, 0xe8, 0x6b, 0xf9, 0x81,
      0xd4, 0x5a, 0x98, 0x88, 0xae, 0x05, 0x5b, 0x2c, 0xa3, 0xf8, 0xb0, 0xde,
      0x9b, 0x44, 0xc7, 0x1d, 0x19, 0x52, 0x02, 0x02, 0xd9, 0x0e, 0x66, 0x7b,
      0x25, 0xdf, 0x95, 0x03, 0x5e, 0x4b, 0x15, 0xef, 0xda, 0x86, 0x2e, 0x8b,
      0xc4, 0xe7, 0x2d, 0x3f, 0x5f, 0xea, 0x1f, 0x13, 0x81, 0x2e, 0x6e, 0xf8,
      0x7f, 0x0b, 0x3b, 0x95, 0x4f, 0xb6, 0xb3, 0x91, 0xcf, 0x89, 0x52, 0xdb,
      0xb7, 0xb1, 0x5d, 0x79, 0xdf, 0x3a, 0xf3, 0xe2, 0x46, 0xc4, 0x04, 0xf3,
      0xf4, 0xf1, 0xc3, 0xf3, 0xa4, 0x98, 0x47, 0xae, 0x46, 0x99, 0x43, 0x4b,
      0x20, 0xba, 0x33, 0xaa, 0x7e, 0x2e, 0x80, 0x88, 0x25, 0x84, 0x73, 0x6d,
      0x44, 0x5f, 0x48, 0x57, 0x0a, 0xc4, 0x4a, 0x4d, 0xc4, 0xd1, 0x47, 0x5f,
      0x4f, 0xd5, 0xdb, 0x3e, 0x90, 0xbd, 0xe1, 0x6a, 0xcb, 0xe4, 0xf3, 0xe6,
      0x64, 0x26, 0xbd, 0xb6, 0x0b, 0x95, 0x6f, 0x4e, 0x1b, 0x09, 0x25, 0x68,
      0x93, 0xb6, 0xd0, 0xc2, 0xfc, 0xce, 0x8f, 0x64, 0xf5, 0x75, 0x50, 0x58,
      0xe5, 0x3e, 0x00, 0x01, 0xfd, 0x62, 0x37, 0xe1, 0x37, 0x1e, 0x9f, 0x97,
      0x88, 0xb1, 0xa9, 0x6f, 0xad, 0x93, 0x41, 0x01, 0xfb, 0x38, 0x24, 0xc8,
      0x08, 0xa0, 0x68, 0x4b, 0x34, 0x8b, 0x76, 0xea, 0x01, 0x62, 0x9d, 0xfa,
      0xdc, 0x91, 0x50, 0x47, 0x98, 0xec, 0x0c, 0x44, 0x58, 0xb6, 0x16, 0xa0,
      0x05, 0xf2, 0x94, 0x34, 0x6d, 0xcb, 0xbc, 0xe4, 0x58, 0xd6, 0x97, 0x9d,
      0x57, 0xa5, 0x5a, 0x65, 0xfa, 0xab, 0x94, 0x24, 0xbf, 0x06, 0x64, 0xc0,
      0xe5, 0x89, 0xe4, 0x2e, 0x46, 0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x03, 0x03, 0x17, 0x0c, 0x00, 0x03, 0x0b, 0x00, 0x03,
      0x00, 0x00, 0x00, 0x00, 0x03, 0x0b, 0x01, 0x00, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xad, 0xf8, 0x54, 0x58, 0xa2, 0xbb, 0x4a, 0x9a,
      0xaf, 0xdc, 0x56, 0x20, 0x27, 0x3d, 0x3c, 0xf1, 0xd8, 0xb9, 0xc5, 0x83,
      0xce, 0x2d, 0x36, 0x95, 0xa9, 0xe1, 0x36, 0x41, 0x14, 0x64, 0x33, 0xfb,
      0xcc, 0x93, 0x9d, 0xce, 0x24, 0x9b, 0x3e, 0xf9, 0x7d, 0x2f, 0xe3, 0x63,
      0x63, 0x0c, 0x75, 0xd8, 0xf6, 0x81, 0xb2, 0x02, 0xae, 0xc4, 0x61, 0x7a,
      0xd3, 0xdf, 0x1e, 0xd5, 0xd5, 0xfd, 0x65, 0x61, 0x24, 0x33, 0xf5, 0x1f,
      0x5f, 0x06, 0x6e, 0xd0, 0x85, 0x63, 0x65, 0x55, 0x3d, 0xed, 0x1a, 0xf3,
      0xb5, 0x57, 0x13, 0x5e, 0x7f, 0x57, 0xc9, 0x35, 0x98, 0x4f, 0x0c, 0x70,
      0xe0, 0xe6, 0x8b, 0x77, 0xe2, 0xa6, 0x89, 0xda, 0xf3, 0xef, 0xe8, 0x72,
      0x1d, 0xf1, 0x58, 0xa1, 0x36, 0xad, 0xe7, 0x35, 0x30, 0xac, 0xca, 0x4f,
      0x48, 0x3a, 0x79, 0x7a, 0xbc, 0x0a, 0xb1, 0x82, 0xb3, 0x24, 0xfb, 0x61,
      0xd1, 0x08, 0xa9, 0x4b, 0xb2, 0xc8, 0xe3, 0xfb, 0xb9, 0x6a, 0xda, 0xb7,
      0x60, 0xd7, 0xf4, 0x68, 0x1d, 0x4f, 0x42, 0xa3, 0xde, 0x39, 0x4d, 0xf4,
      0xae, 0x56, 0xed, 0xe7, 0x63, 0x72, 0xbb, 0x19, 0x0b, 0x07, 0xa7, 0xc8,
      0xee, 0x0a, 0x6d, 0x70, 0x9e, 0x02, 0xfc, 0xe1, 0xcd, 0xf7, 0xe2, 0xec,
      0xc0, 0x34, 0x04, 0xcd, 0x28, 0x34, 0x2f, 0x61, 0x91, 0x72, 0xfe, 0x9c,
      0xe9, 0x85, 0x83, 0xff, 0x8e, 0x4f, 0x12, 0x32, 0xee, 0xf2, 0x81, 0x83,
      0xc3, 0xfe, 0x3b, 0x1b, 0x4c, 0x6f, 0xad, 0x73, 0x3b, 0xb5, 0xfc, 0xbc,
      0x2e, 0xc2, 0x20, 0x05, 0xc5, 0x8e, 0xf1, 0x83, 0x7d, 0x16, 0x83, 0xb2,
      0xc6, 0xf3, 0x4a, 0x26, 0xc1, 0xb2, 0xef, 0xfa, 0x88, 0x6b, 0x42, 0x38,
      0x61, 0x28, 0x5c, 0x97, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0x00, 0x01, 0x02, 0x01, 0x00, 0xea, 0x10, 0x0e, 0xb8, 0xc4, 0xc9, 0xc9,
      0x9a, 0x8c, 0x03, 0x04, 0x56, 0x4f, 0x3d, 0x2d, 0x64, 0x51, 0xc9, 0x1e,
      0xf7, 0x63, 0x06, 0x81, 0xca, 0x89, 0x5c, 0x81, 0xb9, 0x78, 0xe0, 0xf5,
      0x43, 0xe4, 0x47, 0x40, 0x8f, 0x0e, 0xab, 0x0e, 0xd0, 0xb4, 0x43, 0x92,
      0x2a, 0x03, 0x4a, 0x1f, 0x69, 0x7b, 0xc3, 0x0c, 0x13, 0x0d, 0xf3, 0xd8,
      0xaa, 0xd7, 0x1e, 0x0e, 0xf5, 0x09, 0x7d, 0xda, 0xc9, 0x7c, 0x16, 0xfd,
      0xe6, 0xbb, 0x2d, 0xc1, 0x12, 0x20, 0xad, 0x8f, 0x1b, 0x64, 0x79, 0xb9,
      0xbc, 0x26, 0x11, 0xec, 0x3d, 0x20, 0xa6, 0x18, 0x6c, 0xb3, 0x27, 0xbe,
      0x86, 0xde, 0x0e, 0x49, 0x8f, 0xc2, 0x0e, 0x86, 0x8b, 0x2a, 0xc7, 0x4c,
      0xb5, 0x09, 0xed, 0x94, 0x6d, 0xb6, 0x50, 0xfb, 0xc1, 0x8e, 0xd7, 0xce,
      0x58, 0xf8, 0xb0, 0x68, 0xbc, 0xcf, 0x28, 0xc5, 0x1c, 0xf3, 0x99, 0x17,
      0x22, 0xaa, 0x40, 0x28, 0x90, 0x78, 0x34, 0xe2, 0x0f, 0x28, 0x0d, 0x22,
      0xe1, 0x55, 0xcd, 0x90, 0x26, 0x84, 0xa0, 0xd8, 0xea, 0xd9, 0xe8, 0x83,
      0x43, 0x24, 0xef, 0x66, 0xa6, 0x7f, 0x9f, 0x56, 0x10, 0x6f, 0xc9, 0x13,
      0x2f, 0xb1, 0x00, 0x49, 0xc7, 0x88, 0x8d, 0xec, 0x55, 0xc1, 0xdb, 0x39,
      0xa2, 0x5e, 0xbd, 0xde, 0xb6, 0x0a, 0x1c, 0x1f, 0xa4, 0x1a, 0x93, 0xc2,
      0xee, 0x9c, 0x63, 0x3b, 0x09, 0xcf, 0xf6, 0x93, 0x83, 0xfe, 0xd7, 0x4d,
      0x35, 0xd3, 0x15, 0x74, 0x23, 0x5a, 0x33, 0xdc, 0x64, 0x9d, 0xba, 0x2a,
      0xb0, 0x63, 0x26, 0x17, 0x44, 0xe2, 0xfa, 0x41, 0xb1, 0xb2, 0xf2, 0x63,
      0xb2, 0x51, 0x50, 0xfc, 0x31, 0xc2, 0xd6, 0xda, 0x01, 0x18, 0xcf, 0xe8,
      0x9b, 0xed, 0x4c, 0x69, 0x38, 0xe1, 0xe2, 0x69, 0x53, 0xdc, 0x85, 0x40,
      0x4e, 0x9a, 0x1d, 0xe8, 0x2a, 0xe1, 0x27, 0xad, 0x8e, 0x03, 0x01, 0x01,
      0x00, 0xad, 0x55, 0xc0, 0xac, 0xbb, 0x32, 0x93, 0x86, 0xc6, 0xdf, 0x5d,
      0x58, 0x94, 0xba, 0x35, 0x81, 0x32, 0x54, 0x98, 0xdc, 0x85, 0x6f, 0x1e,
      0x41, 0xe4, 0x3d, 0x1e, 0x0d, 0x37, 0x85, 0x05, 0xd1, 0xf7, 0xb2, 0x3a,
      0xd5, 0xb1, 0x8c, 0x93, 0x20, 0x8a, 0x42, 0xf0, 0xc9, 0x86, 0xcc, 0xf4,
      0xa1, 0x17, 0x8d, 0x65, 0xd0, 0xea, 0x23, 0x9f, 0xf7, 0xcf, 0x3e, 0x7b,
      0x51, 0x55, 0xfe, 0x3d, 0x6c, 0x9e, 0x3e, 0x51, 0x39, 0xd8, 0xa0, 0xa0,
      0x8a, 0x6b, 0xd8, 0x4d, 0x41, 0x7f, 0x97, 0x5c, 0x8e, 0x25, 0x7b, 0x24,
      0x72, 0x1a, 0x46, 0xac, 0x8f, 0x8e, 0xd7, 0xe8, 0xa6, 0x31, 0x1e, 0x7c,
      0xd0, 0xa9, 0x31, 0x84, 0xa6, 0x60, 0x73, 0xb3, 0xb9, 0x26, 0xa3, 0x4e,
      0xd5, 0x03, 0x3f, 0xef, 0xaa, 0x5a, 0x41, 0x8d, 0x1f, 0x0b, 0xb6, 0x37,
      0x63, 0x9b, 0xa1, 0xfe, 0x43, 0x5b, 0x73, 0xa2, 0x5b, 0xce, 0x53, 0x61,
      0x05, 0x1f, 0x75, 0x35, 0xf1, 0x71, 0x5b, 0xf6, 0x60, 0x1e, 0xcc, 0x62,
      0xae, 0xca, 0xe3, 0x4f, 0xc0, 0xc0, 0xfd, 0xe1, 0x42, 0xc3, 0xbc, 0x29,
      0x84, 0x74, 0x30, 0x0a, 0x22, 0x69, 0x10, 0x3d, 0xb6, 0x7c, 0x54, 0xc7,
      0x54, 0xe2, 0xaf, 0x3a, 0xee, 0xa3, 0x05, 0xd4, 0x89, 0xa2, 0xc3, 0xa1,
      0x51, 0x45, 0x25, 0x8e, 0xc5, 0x5a, 0xc8, 0x75, 0x50, 0xd9, 0x98, 0x67,
      0x3c, 0xd2, 0xfa, 0x96, 0x6a, 0xaa, 0x1b, 0x0a, 0x29, 0x15, 0xfe, 0xd0,
      0xbb, 0x1a, 0xf5, 0xa4, 0xcd, 0xbe, 0xce, 0xa2, 0x3e, 0x0c, 0x03, 0x9c,
      0xab, 0x3a, 0x34, 0xe2, 0x0e, 0x0e, 0xa0, 0xb3, 0x9a, 0x2a, 0x3f, 0xa2,
      0x1e, 0xd3, 0x33, 0x38, 0x42, 0x6e, 0x65, 0xf8, 0xda, 0xfa, 0x90, 0x73,
      0xa5, 0x66, 0x84, 0xe0, 0xfe, 0x99, 0xe9, 0xc1, 0x94, 0x24, 0x04, 0x7f,
      0x05, 0xda, 0xc7, 0xcd, 0xce, 0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x04, 0x00, 0x0c, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x04,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL *ssl_c = NULL;
    struct test_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, NULL, &ssl_c, NULL,
            wolfDTLSv1_2_client_method, NULL), 0);

    /* start handshake, send first ClientHello */
    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 1,
            (const char*)certreq_before_cert_bin,
            sizeof(certreq_before_cert_bin)), 0);
    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), OUT_OF_ORDER_E);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
#endif
    return EXPECT_RESULT();
}

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS)
struct {
    struct test_memio_ctx* test_ctx;
    WOLFSSL* ssl_s;
    int fd;
    SOCKADDR_S peer_addr;
} test_memio_wolfio_ctx;

static ssize_t test_memio_wolfio_recvfrom(int sockfd, void* buf,
        size_t len, int flags, void* src_addr, void* addrlen)
{
    int ret;
    (void)flags;
    if (sockfd != test_memio_wolfio_ctx.fd) {
        errno = EINVAL;
        return -1;
    }
    ret = test_memio_read_cb(test_memio_wolfio_ctx.ssl_s,
            (char*)buf, (int)len, test_memio_wolfio_ctx.test_ctx);
    if (ret <= 0) {
        if (ret == WC_NO_ERR_TRACE(WOLFSSL_CBIO_ERR_WANT_READ))
            errno = EAGAIN;
        else
            errno = EINVAL;
        return -1;
    }
    XMEMCPY(src_addr, &test_memio_wolfio_ctx.peer_addr,
            MIN(sizeof(test_memio_wolfio_ctx.peer_addr),
                *(word32*)addrlen));
    *(word32*)addrlen = sizeof(test_memio_wolfio_ctx.peer_addr);
    return ret;
}

static ssize_t test_memio_wolfio_sendto(int sockfd, const void* buf,
        size_t len, int flags, const void* dest_addr, word32 addrlen)
{
    int ret;
    (void) flags;
    (void) dest_addr;
    (void) addrlen;
    if (sockfd != test_memio_wolfio_ctx.fd) {
        errno = EINVAL;
        return -1;
    }
    if (dest_addr != NULL && addrlen != 0 &&
            (sizeof(test_memio_wolfio_ctx.peer_addr) != addrlen ||
            XMEMCMP(dest_addr, &test_memio_wolfio_ctx.peer_addr,
                    addrlen) != 0)) {
        errno = EINVAL;
        return -1;
    }
    ret = test_memio_write_cb(test_memio_wolfio_ctx.ssl_s, (char*)buf,
            (int)len, test_memio_wolfio_ctx.test_ctx);
    if (ret <= 0) {
        if (ret == WC_NO_ERR_TRACE(WOLFSSL_CBIO_ERR_WANT_WRITE))
            errno = EAGAIN;
        else
            errno = EINVAL;
        return -1;
    }
    return ret;
}
#endif

/* Test stateless API with wolfio */
int test_dtls_memio_wolfio(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS)
    size_t i;
    struct {
        method_provider client_meth;
        method_provider server_meth;
    } params[] = {
#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_DTLS13)
        { wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method },
#endif
#if !defined(WOLFSSL_NO_TLS12) && defined(WOLFSSL_DTLS)
        { wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method },
#endif
#if !defined(NO_OLD_TLS) && defined(WOLFSSL_DTLS)
        { wolfDTLSv1_client_method, wolfDTLSv1_server_method },
#endif
    };
    XMEMSET(&test_memio_wolfio_ctx, 0, sizeof(test_memio_wolfio_ctx));
    for (i = 0; i < XELEM_CNT(params) && !EXPECT_FAIL(); i++) {
        WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
        WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
        struct test_memio_ctx test_ctx;

        XMEMSET(&test_ctx, 0, sizeof(test_ctx));

        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                params[i].client_meth, params[i].server_meth), 0);

        test_memio_wolfio_ctx.test_ctx = &test_ctx;
        test_memio_wolfio_ctx.ssl_s = ssl_s;
        /* Large number to error out if any syscalls are called with it */
        test_memio_wolfio_ctx.fd = 6000;
        XMEMSET(&test_memio_wolfio_ctx.peer_addr, 0,
                sizeof(test_memio_wolfio_ctx.peer_addr));
        test_memio_wolfio_ctx.peer_addr.ss_family = AF_INET;

        wolfSSL_dtls_set_using_nonblock(ssl_s, 1);
        wolfSSL_SetRecvFrom(ssl_s, test_memio_wolfio_recvfrom);
        wolfSSL_SetSendTo(ssl_s, test_memio_wolfio_sendto);
        /* Restore default functions */
        wolfSSL_SSLSetIORecv(ssl_s, EmbedReceiveFrom);
        wolfSSL_SSLSetIOSend(ssl_s, EmbedSendTo);
        ExpectIntEQ(wolfSSL_set_fd(ssl_s, test_memio_wolfio_ctx.fd),
                    WOLFSSL_SUCCESS);

        ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

        wolfSSL_free(ssl_s);
        wolfSSL_free(ssl_c);
        wolfSSL_CTX_free(ctx_s);
        wolfSSL_CTX_free(ctx_c);
    }
#endif
    return EXPECT_RESULT();
}

/* DTLS using stateless API handling new addresses with wolfio */
int test_dtls_memio_wolfio_stateless(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS)
    size_t i, j;
    struct {
        method_provider client_meth;
        method_provider server_meth;
    } params[] = {
#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_DTLS13)
        { wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method },
#endif
#if !defined(WOLFSSL_NO_TLS12) && defined(WOLFSSL_DTLS)
        { wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method },
#endif
#if !defined(NO_OLD_TLS) && defined(WOLFSSL_DTLS)
        { wolfDTLSv1_client_method, wolfDTLSv1_server_method },
#endif
    };
    XMEMSET(&test_memio_wolfio_ctx, 0, sizeof(test_memio_wolfio_ctx));
    for (i = 0; i < XELEM_CNT(params) && !EXPECT_FAIL(); i++) {
        WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
        WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
        struct test_memio_ctx test_ctx;
        char chBuf[1000];
        int chSz = sizeof(chBuf);

        XMEMSET(&test_ctx, 0, sizeof(test_ctx));

        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                params[i].client_meth, params[i].server_meth), 0);

        test_memio_wolfio_ctx.test_ctx = &test_ctx;
        test_memio_wolfio_ctx.ssl_s = ssl_s;
        /* Large number to error out if any syscalls are called with it */
        test_memio_wolfio_ctx.fd = 6000;
        XMEMSET(&test_memio_wolfio_ctx.peer_addr, 0,
                sizeof(test_memio_wolfio_ctx.peer_addr));
        test_memio_wolfio_ctx.peer_addr.ss_family = AF_INET;

        wolfSSL_dtls_set_using_nonblock(ssl_s, 1);
        wolfSSL_SetRecvFrom(ssl_s, test_memio_wolfio_recvfrom);
        /* Restore default functions */
        wolfSSL_SSLSetIORecv(ssl_s, EmbedReceiveFrom);
        ExpectIntEQ(wolfSSL_set_read_fd(ssl_s, test_memio_wolfio_ctx.fd),
                    WOLFSSL_SUCCESS);

        /* start handshake, send first ClientHello */
        ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
        ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
        ExpectIntEQ(test_memio_copy_message(&test_ctx, 0, chBuf, &chSz, 0), 0);
        ExpectIntGT(chSz, 0);
        test_memio_clear_buffer(&test_ctx, 0);

        /* Send CH from different addresses */
        for (j = 0; j < 10 && !EXPECT_FAIL(); j++,
            (((SOCKADDR_IN*)&test_memio_wolfio_ctx.peer_addr))->sin_port++) {
            const char* hrrBuf = NULL;
            int hrrSz = 0;
            ExpectIntEQ(test_memio_inject_message(&test_ctx, 0, chBuf, chSz), 0);
            ExpectIntEQ(wolfDTLS_accept_stateless(ssl_s), 0);
            ExpectIntEQ(test_memio_get_message(&test_ctx, 1, &hrrBuf, &hrrSz, 0), 0);
            ExpectNotNull(hrrBuf);
            ExpectIntGT(hrrSz, 0);
            test_memio_clear_buffer(&test_ctx, 0);
        }
        test_memio_clear_buffer(&test_ctx, 1);
        ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_c), 1);
        ExpectIntEQ(wolfDTLS_accept_stateless(ssl_s), 0);
        ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
        ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
        ExpectIntEQ(wolfDTLS_accept_stateless(ssl_s), 1);

        ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

        wolfSSL_free(ssl_s);
        wolfSSL_free(ssl_c);
        wolfSSL_CTX_free(ctx_s);
        wolfSSL_CTX_free(ctx_c);
    }
#endif
    return EXPECT_RESULT();
}

int test_dtls_mtu_split_messages(void)
{
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_DTLS_MTU) && defined(WOLFSSL_NO_DTLS_SIZE_CHECK) && \
    defined(HAVE_AESGCM) && defined(HAVE_ECC)
    EXPECT_DECLS;
    struct {
        method_provider client_meth;
        method_provider server_meth;
        const char* cipher;
    } params[] = {
#if defined(WOLFSSL_DTLS13) && defined(WOLFSSL_TLS13)
        { wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method,
          "TLS13-AES128-GCM-SHA256" },
#endif
#if defined(WOLFSSL_DTLS) && !defined(WOLFSSL_NO_TLS12)
        { wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method,
          "ECDHE-RSA-AES128-GCM-SHA256" },
#if !defined(WOLFSSL_AEAD_ONLY) && !defined(NO_AES) && !defined(NO_SHA)
        /* Block cipher test */
        { wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method,
          "ECDHE-RSA-AES128-SHA" },
#endif
#endif
    };
    size_t i;

    for (i = 0; i < XELEM_CNT(params) && EXPECT_SUCCESS(); i++) {
        WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
        WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
        struct test_memio_ctx test_ctx;
        /* Payload larger than typical MTU to force splitting */
        unsigned char payload[200];
        unsigned char readBuf[200];
        word16 mtu;
        int recordLen;
        int overhead;
        int totalRead;
        int ret;
        int j;

        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        XMEMSET(payload, 'A', sizeof(payload));

        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                        params[i].client_meth, params[i].server_meth),
            0);

        ExpectIntEQ(wolfSSL_set_cipher_list(ssl_c, params[i].cipher), 1);
        ExpectIntEQ(wolfSSL_set_cipher_list(ssl_s, params[i].cipher), 1);

        /* Complete handshake and clear any leftover records. */
        ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
        test_memio_clear_buffer(&test_ctx, 1);
        test_memio_clear_buffer(&test_ctx, 0);

        /* Measure application-data record overhead with small payload. */
        ExpectIntEQ(wolfSSL_write(ssl_c, payload, 32), 32);
        ExpectIntEQ(test_ctx.s_msg_count, 1);
        recordLen = test_ctx.s_len;
        ExpectIntGT(recordLen, 32);
        overhead = recordLen - 32;

        /* Reset buffers before MTU-limited send. */
        test_memio_clear_buffer(&test_ctx, 0);
        test_memio_clear_buffer(&test_ctx, 1);

        /* Set MTU to allow only ~50 bytes of payload per record.
         * This ensures a 200-byte payload must be split into multiple msgs. */
        mtu = (word16)(overhead + 50);
        ExpectIntEQ(wolfSSL_dtls_set_mtu(ssl_c, mtu), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_dtls_set_mtu(ssl_s, mtu), WOLFSSL_SUCCESS);

        /* Write payload larger than MTU allows in single record.
         * With WOLFSSL_NO_DTLS_SIZE_CHECK, this should split into multiple
         * messages instead of returning DTLS_SIZE_ERROR. */
        ExpectIntEQ(wolfSSL_write(ssl_c, payload, (int)sizeof(payload)),
            (int)sizeof(payload));

        /* Verify multiple messages were sent */
        ExpectIntGT(test_ctx.s_msg_count, 1);

        /* Each record should fit within MTU */
        for (j = 0; j < test_ctx.s_msg_count && EXPECT_SUCCESS(); j++) {
            ExpectIntLE(test_ctx.s_msg_sizes[j], mtu);
        }

        /* Read all data on server side and verify it matches */
        totalRead = 0;
        while (totalRead < (int)sizeof(payload) && EXPECT_SUCCESS()) {
            ret = wolfSSL_read(ssl_s, readBuf + totalRead,
                (int)sizeof(readBuf) - totalRead);
            if (ret > 0) {
                totalRead += ret;
            }
            else {
                break;
            }
        }
        ExpectIntEQ(totalRead, (int)sizeof(payload));
        ExpectIntEQ(XMEMCMP(payload, readBuf, sizeof(payload)), 0);

        wolfSSL_free(ssl_c);
        wolfSSL_CTX_free(ctx_c);
        wolfSSL_free(ssl_s);
        wolfSSL_CTX_free(ctx_s);
    }
    return EXPECT_RESULT();
#else
    return TEST_SKIPPED;
#endif
}

/* Test DTLS 1.3 minimum retransmission interval. This test calls
 * wolfSSL_dtls_got_timeout() to simulate timeouts and verify that
 * retransmissions are spaced at least DTLS13_MIN_RTX_INTERVAL apart.
 * This tests relies on timing of the retransmission logic so it may be
 * flaky on very slow systems.
 */

/* RFC 9147 Section 5.3: DTLS 1.3 ServerHello must have empty
 * legacy_session_id_echo, even if the ClientHello had a non-empty
 * legacy_session_id. */

/* Test that a server built with WOLFSSL_DTLS13_ECHO_LEGACY_SESSION_ID echoes the
 * client's legacy_session_id in both the direct ServerHello path and the
 * stateless HRR path (which also exercises RestartHandshakeHashWithCookie). */

/* Test that a DTLS 1.3 handshake with an oversized certificate chain does
 * not crash or cause out-of-bounds access in SendTls13Certificate. */

/* DTLS counterpart to test_tls_set_session_min_downgrade. Exercises the
 * inverted DTLS minor-version comparison (DTLS 1.2 minor 0xFD is "below"
 * floor 0xFC = DTLS 1.3). */
int test_dtls_set_session_min_downgrade(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS) && \
    defined(WOLFSSL_DTLS13) && defined(HAVE_SESSION_TICKET)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    WOLFSSL_SESSION *sess = NULL;
    struct test_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method), 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectNotNull(sess = wolfSSL_get1_session(ssl_c));

    wolfSSL_free(ssl_c); ssl_c = NULL;
    wolfSSL_free(ssl_s); ssl_s = NULL;
    wolfSSL_CTX_free(ctx_c); ctx_c = NULL;
    wolfSSL_CTX_free(ctx_s); ctx_s = NULL;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfDTLS_client_method, wolfDTLS_server_method), 0);
    ExpectIntEQ(wolfSSL_SetMinVersion(ssl_c, WOLFSSL_DTLSV1_3),
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

/*----------------------------------------------------------------------------*/
/* DTLS session export / import                                               */
/*----------------------------------------------------------------------------*/

#if defined(WOLFSSL_DTLS) && defined(WOLFSSL_SESSION_EXPORT)
/* canned export of a session using older version 3 */
static unsigned char version_3[] = {
    0xA5, 0xA3, 0x01, 0x88, 0x00, 0x3c, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x80, 0x0C, 0x00, 0x00, 0x00,
    0x00, 0x80, 0x00, 0x1C, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x30,
    0x05, 0x09, 0x0A, 0x01, 0x01, 0x00, 0x0D, 0x05,
    0xFE, 0xFD, 0x01, 0x25, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x06, 0x00, 0x05, 0x00, 0x06, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x06, 0x00, 0x01, 0x00, 0x07, 0x00, 0x00,
    0x00, 0x30, 0x00, 0x00, 0x00, 0x10, 0x01, 0x01,
    0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x3F,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x05,
    0x12, 0xCF, 0x22, 0xA1, 0x9F, 0x1C, 0x39, 0x1D,
    0x31, 0x11, 0x12, 0x1D, 0x11, 0x18, 0x0D, 0x0B,
    0xF3, 0xE1, 0x4D, 0xDC, 0xB1, 0xF1, 0x39, 0x98,
    0x91, 0x6C, 0x48, 0xE5, 0xED, 0x11, 0x12, 0xA0,
    0x00, 0xF2, 0x25, 0x4C, 0x09, 0x26, 0xD1, 0x74,
    0xDF, 0x23, 0x40, 0x15, 0x6A, 0x42, 0x2A, 0x26,
    0xA5, 0xAC, 0x56, 0xD5, 0x4A, 0x20, 0xB7, 0xE9,
    0xEF, 0xEB, 0xAF, 0xA8, 0x1E, 0x23, 0x7C, 0x04,
    0xAA, 0xA1, 0x6D, 0x92, 0x79, 0x7B, 0xFA, 0x80,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x0C, 0x79, 0x7B, 0xFA, 0x80, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0xAA, 0xA1, 0x6D,
    0x92, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x10, 0x00, 0x20, 0x00, 0x04, 0x00,
    0x10, 0x00, 0x10, 0x08, 0x02, 0x05, 0x08, 0x01,
    0x30, 0x28, 0x00, 0x00, 0x0F, 0x00, 0x02, 0x00,
    0x09, 0x31, 0x32, 0x37, 0x2E, 0x30, 0x2E, 0x30,
    0x2E, 0x31, 0xED, 0x4F
};
#endif /* defined(WOLFSSL_DTLS) && defined(WOLFSSL_SESSION_EXPORT) */

int test_wolfSSL_dtls_export(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_DTLS) && defined(WOLFSSL_SESSION_EXPORT)
    tcp_ready ready;
    func_args client_args;
    func_args server_args;
    THREAD_TYPE serverThread;
    callback_functions server_cbf;
    callback_functions client_cbf;
#ifdef WOLFSSL_TIRTOS
    fdOpenSession(Task_self());
#endif

    InitTcpReady(&ready);

    /* set using dtls */
    XMEMSET(&client_args, 0, sizeof(func_args));
    XMEMSET(&server_args, 0, sizeof(func_args));
    XMEMSET(&server_cbf, 0, sizeof(callback_functions));
    XMEMSET(&client_cbf, 0, sizeof(callback_functions));
    server_cbf.method = wolfDTLSv1_2_server_method;
    client_cbf.method = wolfDTLSv1_2_client_method;
    server_args.callbacks = &server_cbf;
    client_args.callbacks = &client_cbf;

    server_args.signal = &ready;
    client_args.signal = &ready;

    start_thread(run_wolfssl_server, &server_args, &serverThread);
    wait_tcp_ready(&server_args);
    run_wolfssl_client(&client_args);
    join_thread(serverThread);

    ExpectTrue(client_args.return_code);
    ExpectTrue(server_args.return_code);

    FreeTcpReady(&ready);

#ifdef WOLFSSL_TIRTOS
    fdOpenSession(Task_self());
#endif

    if (EXPECT_SUCCESS()) {
        SOCKET_T sockfd = 0;
        WOLFSSL_CTX* ctx = NULL;
        WOLFSSL*     ssl = NULL;
        char msg[64] = "hello wolfssl!";
        char reply[1024];
        int  msgSz = (int)XSTRLEN(msg);
        byte *session, *window;
        unsigned int sessionSz = 0;
        unsigned int windowSz = 0;

#ifndef TEST_IPV6
        struct sockaddr_in peerAddr;
#else
        struct sockaddr_in6 peerAddr;
#endif /* TEST_IPV6 */

        int i;


        /* Set ctx to DTLS 1.2 */
        ExpectNotNull(ctx = wolfSSL_CTX_new(wolfDTLSv1_2_server_method()));
        ExpectNotNull(ssl = wolfSSL_new(ctx));

        /* test importing version 3 */
        ExpectIntGE(wolfSSL_dtls_import(ssl, version_3, sizeof(version_3)), 0);

        /* test importing bad length and bad version */
        version_3[2]++;
        ExpectIntLT(wolfSSL_dtls_import(ssl, version_3, sizeof(version_3)), 0);
        version_3[2]--; version_3[1] = 0XA0;
        ExpectIntLT(wolfSSL_dtls_import(ssl, version_3, sizeof(version_3)), 0);
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);


    /* check storing client state after connection and storing window only */
#ifdef WOLFSSL_TIRTOS
    fdOpenSession(Task_self());
#endif

    InitTcpReady(&ready);

    /* set using dtls */
    XMEMSET(&server_args, 0, sizeof(func_args));
    XMEMSET(&server_cbf, 0, sizeof(callback_functions));
    server_cbf.method = wolfDTLSv1_2_server_method;
    server_cbf.doUdp = 1;
    server_args.callbacks = &server_cbf;
    server_args.argc = 3; /* set loop_count to 3 */


    server_args.signal = &ready;
    start_thread(test_server_nofail, &server_args, &serverThread);
    wait_tcp_ready(&server_args);

    /* create and connect with client */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfDTLSv1_2_client_method()));
    ExpectIntEQ(WOLFSSL_SUCCESS,
            wolfSSL_CTX_load_verify_locations(ctx, caCertFile, 0));
    ExpectIntEQ(WOLFSSL_SUCCESS,
          wolfSSL_CTX_use_certificate_file(ctx, cliCertFile, SSL_FILETYPE_PEM));
    ExpectIntEQ(WOLFSSL_SUCCESS,
            wolfSSL_CTX_use_PrivateKey_file(ctx, cliKeyFile, SSL_FILETYPE_PEM));
    tcp_connect(&sockfd, wolfSSLIP, server_args.signal->port, 1, 0, NULL);
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(wolfSSL_set_fd(ssl, sockfd), WOLFSSL_SUCCESS);

    /* store server information connected too */
    XMEMSET(&peerAddr, 0, sizeof(peerAddr));
#ifndef TEST_IPV6
    peerAddr.sin_family = AF_INET;
    ExpectIntEQ(XINET_PTON(AF_INET, wolfSSLIP, &peerAddr.sin_addr),1);
    peerAddr.sin_port = XHTONS(server_args.signal->port);
#else
    peerAddr.sin6_family = AF_INET6;
    ExpectIntEQ(
        XINET_PTON(AF_INET6, wolfSSLIP, &peerAddr.sin6_addr),1);
    peerAddr.sin6_port = XHTONS(server_args.signal->port);
#endif

    ExpectIntEQ(wolfSSL_dtls_set_peer(ssl, &peerAddr, sizeof(peerAddr)),
                    WOLFSSL_SUCCESS);

    ExpectIntEQ(wolfSSL_connect(ssl), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_dtls_export(ssl, NULL, &sessionSz), 0);
    session = (byte*)XMALLOC(sessionSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectIntGT(wolfSSL_dtls_export(ssl, session, &sessionSz), 0);
    ExpectIntEQ(wolfSSL_write(ssl, msg, msgSz), msgSz);
    ExpectIntGT(wolfSSL_read(ssl, reply, sizeof(reply)), 0);
    ExpectIntEQ(wolfSSL_dtls_export_state_only(ssl, NULL, &windowSz), 0);
    window = (byte*)XMALLOC(windowSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectIntGT(wolfSSL_dtls_export_state_only(ssl, window, &windowSz), 0);
    wolfSSL_free(ssl);

    for (i = 1; EXPECT_SUCCESS() && i < server_args.argc; i++) {
        /* restore state */
        ExpectNotNull(ssl = wolfSSL_new(ctx));
        ExpectIntGT(wolfSSL_dtls_import(ssl, session, sessionSz), 0);
        ExpectIntGT(wolfSSL_dtls_import(ssl, window, windowSz), 0);
        ExpectIntEQ(wolfSSL_set_fd(ssl, sockfd), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_dtls_set_peer(ssl, &peerAddr, sizeof(peerAddr)),
                    WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_write(ssl, msg, msgSz), msgSz);
        ExpectIntGE(wolfSSL_read(ssl, reply, sizeof(reply)), 0);
        ExpectIntGT(wolfSSL_dtls_export_state_only(ssl, window, &windowSz), 0);
        wolfSSL_free(ssl);
    }
    XFREE(session, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(window, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    wolfSSL_CTX_free(ctx);

    fprintf(stderr, "done and waiting for server\n");
    join_thread(serverThread);
    ExpectIntEQ(server_args.return_code, TEST_SUCCESS);

    FreeTcpReady(&ready);

#ifdef WOLFSSL_TIRTOS
    fdOpenSession(Task_self());
#endif
    }
#endif

    return EXPECT_RESULT();
}

#if defined(WOLFSSL_DTLS) && defined(WOLFSSL_SESSION_EXPORT) && \
    defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES)
/* Dummy peer functions to satisfy the exporter/importer */
static int test_wolfSSL_dtls_export_peers_get_peer(WOLFSSL* ssl, char* ip,
        int* ipSz, unsigned short* port, int* fam)
{
    (void)ssl;
    ip[0] = -1;
    *ipSz = 1;
    *port = 1;
    *fam = 2;
    return 1;
}

static int test_wolfSSL_dtls_export_peers_set_peer(WOLFSSL* ssl, char* ip,
        int ipSz, unsigned short port, int fam)
{
    (void)ssl;
    if (ip[0] != -1 || ipSz != 1 || port != 1 || fam != 2)
        return 0;
    return 1;
}

static int test_wolfSSL_dtls_export_peers_on_handshake(WOLFSSL_CTX **ctx,
        WOLFSSL **ssl)
{
    EXPECT_DECLS;
    unsigned char* sessionBuf = NULL;
    unsigned int sessionSz = 0;
    void* ioWriteCtx = wolfSSL_GetIOWriteCtx(*ssl);
    void* ioReadCtx = wolfSSL_GetIOReadCtx(*ssl);

    wolfSSL_CTX_SetIOGetPeer(*ctx, test_wolfSSL_dtls_export_peers_get_peer);
    wolfSSL_CTX_SetIOSetPeer(*ctx, test_wolfSSL_dtls_export_peers_set_peer);
    ExpectIntGE(wolfSSL_dtls_export(*ssl, NULL, &sessionSz), 0);
    ExpectNotNull(sessionBuf =
        (unsigned char*)XMALLOC(sessionSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER));
    ExpectIntGE(wolfSSL_dtls_export(*ssl, sessionBuf, &sessionSz), 0);
    wolfSSL_free(*ssl);
    *ssl = NULL;
    ExpectNotNull(*ssl = wolfSSL_new(*ctx));
    ExpectIntGE(wolfSSL_dtls_import(*ssl, sessionBuf, sessionSz), 0);
    wolfSSL_SetIOWriteCtx(*ssl, ioWriteCtx);
    wolfSSL_SetIOReadCtx(*ssl, ioReadCtx);

    XFREE(sessionBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    return EXPECT_RESULT();
}
#endif

int test_wolfSSL_dtls_export_peers(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_DTLS) && defined(WOLFSSL_SESSION_EXPORT) && \
    defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES)
    test_ssl_cbf client_cbf;
    test_ssl_cbf server_cbf;
    size_t i, j;
    struct test_params {
        method_provider client_meth;
        method_provider server_meth;
        const char* dtls_version;
    } params[] = {
#ifndef NO_OLD_TLS
        {wolfDTLSv1_client_method, wolfDTLSv1_server_method, "1.0"},
#endif
        {wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method, "1.2"},
        /* TODO DTLS 1.3 exporting not supported
#ifdef WOLFSSL_DTLS13
        {wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method, "1.3"},
#endif
         */
    };

    for (i = 0; i < sizeof(params)/sizeof(*params); i++) {
        for (j = 0; j <= 3; j++) {
            XMEMSET(&client_cbf, 0, sizeof(client_cbf));
            XMEMSET(&server_cbf, 0, sizeof(server_cbf));

            printf("\n\tTesting DTLS %s connection;", params[i].dtls_version);

            client_cbf.method = params[i].client_meth;
            server_cbf.method = params[i].server_meth;

            if (j & 0x1) {
                client_cbf.on_handshake =
                        test_wolfSSL_dtls_export_peers_on_handshake;
                printf(" With client export;");
            }
            if (j & 0x2) {
                server_cbf.on_handshake =
                        test_wolfSSL_dtls_export_peers_on_handshake;
                printf(" With server export;");
            }

            printf("\n");

            ExpectIntEQ(test_wolfSSL_client_server_nofail_memio(&client_cbf,
                &server_cbf, NULL), TEST_SUCCESS);
            if (!EXPECT_SUCCESS())
                break;
        }
    }
#endif
    return EXPECT_RESULT();
}

/* Test that ImportKeyState correctly skips extra window words when importing
 * state from a peer compiled with a larger WOLFSSL_DTLS_WINDOW_WORDS. */
int test_wolfSSL_dtls_import_state_extra_window_words(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_DTLS) && defined(WOLFSSL_SESSION_EXPORT)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL*     ssl = NULL;
    unsigned int stateSz = 0;
    byte*        state = NULL;
    byte*        modified = NULL;
    unsigned int modifiedSz;
    word16       origKeyLen;
    word16       origTotalLen;
    /* Offset from start of key state data to the first wordCount field.
     * Layout: 4 sequence numbers (16 bytes) + DTLS-specific fields (42 bytes) +
     * encryptSz(4) + padSz(4) + encryptionOn(1) + decryptedCur(1) = 68 */
    const int keyStateWindowOffset = 68;
    /* Buffer header: 2 proto + 2 total_len + 2 key_len = 6 */
    const int headerSz = 6;
    int idx, modIdx;
    int extraPerWindow = 2 * (int)sizeof(word32); /* 8 bytes extra per window */
    int totalExtra = extraPerWindow * 2; /* 16 bytes extra total */

    /* Create DTLS context and SSL object */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfDTLSv1_2_server_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* Get required buffer size and export state-only */
    ExpectIntEQ(wolfSSL_dtls_export_state_only(ssl, NULL, &stateSz), 0);
    ExpectIntGT((int)stateSz, 0);
    state = (byte*)XMALLOC(stateSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(state);
    ExpectIntGT(wolfSSL_dtls_export_state_only(ssl, state, &stateSz), 0);

    /* Build a modified buffer that simulates a peer with
     * WOLFSSL_DTLS_WINDOW_WORDS = WOLFSSL_DTLS_WINDOW_WORDS + 2.
     * Each window section gets 2 extra word32 values (8 bytes).
     * Two windows => 16 extra bytes total. */
    modifiedSz = stateSz + totalExtra;
    modified = (byte*)XMALLOC(modifiedSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(modified);

    if (EXPECT_SUCCESS()) {
        int windowWords = WOLFSSL_DTLS_WINDOW_WORDS;
        int windowDataSz = windowWords * (int)sizeof(word32);

        XMEMSET(modified, 0, modifiedSz);

        /* Copy protocol/version bytes (first 2 bytes) */
        XMEMCPY(modified, state, 2);

        /* Read original total length and key state length */
        ato16(state + 2, &origTotalLen);
        ato16(state + 4, &origKeyLen);

        /* Write updated total length and key state length */
        c16toa((word16)(origTotalLen + totalExtra), modified + 2);
        c16toa((word16)(origKeyLen + totalExtra), modified + 4);

        /* Copy key state data up to first window section */
        idx = headerSz;
        modIdx = headerSz;
        XMEMCPY(modified + modIdx, state + idx, keyStateWindowOffset);
        idx += keyStateWindowOffset;
        modIdx += keyStateWindowOffset;

        /* First window: write increased wordCount */
        c16toa((word16)(windowWords + 2), modified + modIdx);
        idx += OPAQUE16_LEN;
        modIdx += OPAQUE16_LEN;

        /* Copy original window data */
        XMEMCPY(modified + modIdx, state + idx, windowDataSz);
        idx += windowDataSz;
        modIdx += windowDataSz;

        /* Insert 2 extra word32 padding values */
        XMEMSET(modified + modIdx, 0, extraPerWindow);
        modIdx += extraPerWindow;

        /* Second window (prevWindow): same transformation */
        c16toa((word16)(windowWords + 2), modified + modIdx);
        idx += OPAQUE16_LEN;
        modIdx += OPAQUE16_LEN;

        XMEMCPY(modified + modIdx, state + idx, windowDataSz);
        idx += windowDataSz;
        modIdx += windowDataSz;

        XMEMSET(modified + modIdx, 0, extraPerWindow);
        modIdx += extraPerWindow;

        /* Copy remainder of key state (after both windows) */
        XMEMCPY(modified + modIdx, state + idx, stateSz - idx);
    }

    /* Import the modified state - should succeed with the fix */
    wolfSSL_free(ssl);
    ssl = NULL;
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntGT(wolfSSL_dtls_import(ssl, modified, modifiedSz), 0);

    XFREE(state, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(modified, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/*----------------------------------------------------------------------------*/
/* DTLS either-side method and cookie generation                              */
/*----------------------------------------------------------------------------*/

int test_wolfSSL_DTLS_either_side(void)
{
    EXPECT_DECLS;
#if (defined(OPENSSL_EXTRA) || defined(WOLFSSL_EITHER_SIDE)) && \
    defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS)
    test_ssl_cbf client_cb;
    test_ssl_cbf server_cb;

    XMEMSET(&client_cb, 0, sizeof(client_cb));
    XMEMSET(&server_cb, 0, sizeof(server_cb));

    /* Use different CTX for client and server */
    client_cb.ctx = wolfSSL_CTX_new(wolfDTLS_method());
    ExpectNotNull(client_cb.ctx);
    server_cb.ctx = wolfSSL_CTX_new(wolfDTLS_method());
    ExpectNotNull(server_cb.ctx);
    /* we are responsible for free'ing WOLFSSL_CTX */
    server_cb.isSharedCtx = client_cb.isSharedCtx = 1;

    ExpectIntEQ(test_wolfSSL_client_server_nofail_memio(&client_cb,
        &server_cb, NULL), TEST_SUCCESS);

    wolfSSL_CTX_free(client_cb.ctx);
    wolfSSL_CTX_free(server_cb.ctx);
#endif
    return EXPECT_RESULT();
}

int test_generate_cookie(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_DTLS) && defined(OPENSSL_EXTRA) && defined(USE_WOLFSSL_IO)
    SSL_CTX* ctx = NULL;
    SSL* ssl = NULL;
    byte    buf[FOURK_BUF] = {0};

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfDTLS_method()));
    ExpectNotNull(ssl = SSL_new(ctx));

    /* Test unconnected */
    ExpectIntEQ(EmbedGenerateCookie(ssl, buf, FOURK_BUF, NULL), WC_NO_ERR_TRACE(GEN_COOKIE_E));

    wolfSSL_CTX_SetGenCookie(ctx, EmbedGenerateCookie);

    wolfSSL_SetCookieCtx(ssl, ctx);

    ExpectNotNull(wolfSSL_GetCookieCtx(ssl));

    ExpectNull(wolfSSL_GetCookieCtx(NULL));

    SSL_free(ssl);
    SSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/*----------------------------------------------------------------------------*/
/* DTLS handshake: MTU, plaintext, fragments, bad records, AEAD, stateless    */
/*----------------------------------------------------------------------------*/

int test_wolfSSL_dtls_set_mtu(void)
{
    EXPECT_DECLS;
#if (defined(WOLFSSL_DTLS_MTU) || defined(WOLFSSL_SCTP)) && \
    !defined(NO_WOLFSSL_SERVER) && defined(WOLFSSL_DTLS) && \
    !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL*     ssl = NULL;
    const char* testCertFile;
    const char* testKeyFile;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfDTLSv1_2_server_method()));
#ifndef NO_RSA
        testCertFile = svrCertFile;
        testKeyFile = svrKeyFile;
#elif defined(HAVE_ECC)
        testCertFile = eccCertFile;
        testKeyFile = eccKeyFile;
#endif
    if  (testCertFile != NULL && testKeyFile != NULL) {
        ExpectTrue(wolfSSL_CTX_use_certificate_file(ctx, testCertFile,
                                                    WOLFSSL_FILETYPE_PEM));
        ExpectTrue(wolfSSL_CTX_use_PrivateKey_file(ctx, testKeyFile,
                                                   WOLFSSL_FILETYPE_PEM));
    }
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    ExpectIntEQ(wolfSSL_CTX_dtls_set_mtu(NULL, 1488), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_dtls_set_mtu(NULL, 1488), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CTX_dtls_set_mtu(ctx, 20000), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_dtls_set_mtu(ssl, 20000), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_get_error(ssl, WC_NO_ERR_TRACE(WOLFSSL_FAILURE)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CTX_dtls_set_mtu(ctx, 1488), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_dtls_set_mtu(ssl, 1488), WOLFSSL_SUCCESS);

#ifdef OPENSSL_EXTRA
    ExpectIntEQ(SSL_set_mtu(ssl, 1488), WOLFSSL_SUCCESS);
#endif

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif

    return EXPECT_RESULT();
}

#if defined(HAVE_IO_TESTS_DEPENDENCIES) && !defined(SINGLE_THREADED) && \
    defined(WOLFSSL_DTLS) && !defined(WOLFSSL_NO_TLS12)

static WC_INLINE void generateDTLSMsg(byte* out, int outSz, word32 seq,
        enum HandShakeType hsType, word16 length)
{
    size_t idx = 0;
    byte* l;

    /* record layer */
    /* handshake type */
    out[idx++] = handshake;
    /* protocol version */
    out[idx++] = 0xfe;
    out[idx++] = 0xfd; /* DTLS 1.2 */
    /* epoch 0 */
    XMEMSET(out + idx, 0, 2);
    idx += 2;
    /* sequence number */
    XMEMSET(out + idx, 0, 6);
    c32toa(seq, out + idx + 2);
    idx += 6;
    /* length in BE */
    if (length)
        c16toa(length, out + idx);
    else
        c16toa(outSz - idx - 2, out + idx);
    idx += 2;

    /* handshake layer */
    /* handshake type */
    out[idx++] = (byte)hsType;
    /* length */
    l = out + idx;
    idx += 3;
    /* message seq */
    c16toa(0, out + idx);
    idx += 2;
    /* frag offset */
    c32to24(0, out + idx);
    idx += 3;
    /* frag length */
    c32to24((word32)outSz - (word32)idx - 3, l);
    c32to24((word32)outSz - (word32)idx - 3, out + idx);
    idx += 3;
    XMEMSET(out + idx, 0, outSz - idx);
}

static void test_wolfSSL_dtls_plaintext_server(WOLFSSL* ssl)
{
    byte msg[] = "This is a msg for the client";
    byte reply[40];
    AssertIntGT(wolfSSL_read(ssl, reply, sizeof(reply)),0);
    reply[sizeof(reply) - 1] = '\0';
    fprintf(stderr, "Client message: %s\n", reply);
    AssertIntEQ(wolfSSL_write(ssl, msg, sizeof(msg)), sizeof(msg));
}

static void test_wolfSSL_dtls_plaintext_client(WOLFSSL* ssl)
{
    byte ch[50];
    int fd = wolfSSL_get_wfd(ssl);
    byte msg[] = "This is a msg for the server";
    byte reply[40];

    AssertIntGE(fd, 0);
    generateDTLSMsg(ch, sizeof(ch), 20, client_hello, 0);
    /* Server should ignore this datagram */
    AssertIntEQ(send(fd, (MESSAGE_TYPE_CAST)ch, sizeof(ch), 0), sizeof(ch));
    generateDTLSMsg(ch, sizeof(ch), 20, client_hello, 10000);
    /* Server should ignore this datagram */
    AssertIntEQ(send(fd, (MESSAGE_TYPE_CAST)ch, sizeof(ch), 0), sizeof(ch));

    AssertIntEQ(wolfSSL_write(ssl, msg, sizeof(msg)), sizeof(msg));
    AssertIntGT(wolfSSL_read(ssl, reply, sizeof(reply)),0);
    reply[sizeof(reply) - 1] = '\0';
    fprintf(stderr, "Server response: %s\n", reply);
}

int test_wolfSSL_dtls_plaintext(void)
{
    callback_functions func_cb_client;
    callback_functions func_cb_server;
    size_t i;
    struct test_params {
        method_provider client_meth;
        method_provider server_meth;
        ssl_callback on_result_server;
        ssl_callback on_result_client;
    } params[] = {
        {wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method,
                test_wolfSSL_dtls_plaintext_server,
                test_wolfSSL_dtls_plaintext_client},
    };

    for (i = 0; i < sizeof(params)/sizeof(*params); i++) {
        XMEMSET(&func_cb_client, 0, sizeof(callback_functions));
        XMEMSET(&func_cb_server, 0, sizeof(callback_functions));

        func_cb_client.doUdp = func_cb_server.doUdp = 1;
        func_cb_server.method = params[i].server_meth;
        func_cb_client.method = params[i].client_meth;
        func_cb_client.on_result = params[i].on_result_client;
        func_cb_server.on_result = params[i].on_result_server;

        test_wolfSSL_client_server_nofail(&func_cb_client, &func_cb_server);

        if (!func_cb_client.return_code)
            return TEST_FAIL;
        if (!func_cb_server.return_code)
            return TEST_FAIL;
    }

    return TEST_RES_CHECK(1);
}
#else
int test_wolfSSL_dtls_plaintext(void)
{
    return TEST_SKIPPED;
}
#endif

#if defined(HAVE_IO_TESTS_DEPENDENCIES) && !defined(SINGLE_THREADED) && \
    defined(WOLFSSL_DTLS) && !defined(WOLFSSL_NO_TLS12)

static void test_wolfSSL_dtls12_fragments_spammer(WOLFSSL* ssl)
{
    byte b[1100]; /* buffer for the messages to send */
    size_t idx = 0;
    size_t seq_offset = 0;
    size_t msg_offset = 0;
    int i;
    int fd = wolfSSL_get_wfd(ssl);
    int ret = wolfSSL_connect_cert(ssl); /* This gets us past the cookie */
    word32 seq_number = 100; /* start high so server definitely reads this */
    word16 msg_number = 50; /* start high so server has to buffer this */
    AssertIntEQ(ret, 1);
    /* Now let's start spamming the peer with fragments it needs to store */
    XMEMSET(b, -1, sizeof(b));

    /* record layer */
    /* handshake type */
    b[idx++] = 22;
    /* protocol version */
    b[idx++] = 0xfe;
    b[idx++] = 0xfd; /* DTLS 1.2 */
    /* epoch 0 */
    XMEMSET(b + idx, 0, 2);
    idx += 2;
    /* sequence number */
    XMEMSET(b + idx, 0, 6);
    seq_offset = idx + 2; /* increment only the low 32 bits */
    idx += 6;
    /* static length in BE */
    c16toa(42, b + idx);
    idx += 2;

    /* handshake layer */
    /* cert type */
    b[idx++] = 11;
    /* length */
    c32to24(1000, b + idx);
    idx += 3;
    /* message seq */
    c16toa(0, b + idx);
    msg_offset = idx;
    idx += 2;
    /* frag offset */
    c32to24(500, b + idx);
    idx += 3;
    /* frag length */
    c32to24(30, b + idx);
    idx += 3;
    (void)idx; /* inhibit clang-analyzer-deadcode.DeadStores */

    for (i = 0; i < DTLS_POOL_SZ * 2 && ret > 0;
            seq_number++, msg_number++, i++) {
        struct timespec delay;
        XMEMSET(&delay, 0, sizeof(delay));
        delay.tv_nsec = 10000000; /* wait 0.01 seconds */
        c32toa(seq_number, b + seq_offset);
        c16toa(msg_number, b + msg_offset);
        ret = (int)send(fd, (MESSAGE_TYPE_CAST)b, 55, 0);
        nanosleep(&delay, NULL);
    }
}

#ifdef WOLFSSL_DTLS13
static void test_wolfSSL_dtls13_fragments_spammer(WOLFSSL* ssl)
{
    const word16 sendCountMax = 100;
    byte b[150]; /* buffer for the messages to send */
    size_t idx = 0;
    size_t msg_offset = 0;
    int fd = wolfSSL_get_wfd(ssl);
    word16 msg_number = 10; /* start high so server has to buffer this */
    int ret = wolfSSL_connect_cert(ssl); /* This gets us past the cookie */
    AssertIntEQ(ret, 1);
    /* Now let's start spamming the peer with fragments it needs to store */
    XMEMSET(b, -1, sizeof(b));

    /* handshake type */
    b[idx++] = 11;
    /* length */
    c32to24(10000, b + idx);
    idx += 3;
    /* message_seq */
    msg_offset = idx;
    idx += 2;
    /* fragment_offset */
    c32to24(5000, b + idx);
    idx += 3;
    /* fragment_length */
    c32to24(100, b + idx);
    idx += 3;
    /* fragment contents */
    idx += 100;

    for (; ret > 0 && msg_number < sendCountMax; msg_number++) {
        byte sendBuf[150];
        int sendSz = sizeof(sendBuf);
        struct timespec delay;
        XMEMSET(&delay, 0, sizeof(delay));
        delay.tv_nsec = 10000000; /* wait 0.01 seconds */
        c16toa(msg_number, b + msg_offset);
        ret = sendSz = BuildTls13Message(ssl, sendBuf, sendSz, b,
            (int)idx, handshake, 0, 0, 0);
        if (sendSz > 0)
            ret = (int)send(fd, (MESSAGE_TYPE_CAST)sendBuf, (size_t)sendSz, 0);
        nanosleep(&delay, NULL);
    }
}
#endif

int test_wolfSSL_dtls_fragments(void)
{
    EXPECT_DECLS;
    callback_functions func_cb_client;
    callback_functions func_cb_server;
    size_t i;
    struct test_params {
        method_provider client_meth;
        method_provider server_meth;
        ssl_callback spammer;
    } params[] = {
#if !defined(WOLFSSL_NO_TLS12)
        {wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method,
                test_wolfSSL_dtls12_fragments_spammer},
#endif
#ifdef WOLFSSL_DTLS13
        {wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method,
                test_wolfSSL_dtls13_fragments_spammer},
#endif
    };

    for (i = 0; i < sizeof(params)/sizeof(*params); i++) {
        XMEMSET(&func_cb_client, 0, sizeof(callback_functions));
        XMEMSET(&func_cb_server, 0, sizeof(callback_functions));

        func_cb_client.doUdp = func_cb_server.doUdp = 1;
        func_cb_server.method = params[i].server_meth;
        func_cb_client.method = params[i].client_meth;
        func_cb_client.ssl_ready = params[i].spammer;

        test_wolfSSL_client_server_nofail(&func_cb_client, &func_cb_server);

        /* If the client failed, check that the error it encountered was from
         * the server aborting, resulting in a socket error, fatal error or
         * reading a close notify alert.
         *
         * Under slow execution (e.g. valgrind + noasm), the server may
         * still be processing fragments when the client completes its
         * handshake and write, so the client may succeed -- in that
         * case return_code is TEST_SUCCESS and these checks don't apply.
         */
        if (func_cb_client.return_code == TEST_FAIL) {
            if (func_cb_client.last_err != WC_NO_ERR_TRACE(SOCKET_ERROR_E) &&
                    func_cb_client.last_err != WOLFSSL_ERROR_ZERO_RETURN &&
                    func_cb_client.last_err != WC_NO_ERR_TRACE(FATAL_ERROR)) {
                ExpectIntEQ(func_cb_client.last_err, WC_NO_ERR_TRACE(SOCKET_ERROR_E));
            }
        }
        /* Check the server returned an error indicating the msg buffer
         * was full.
         *
         * Under slow execution (e.g. valgrind + noasm), the real handshake
         * from wolfSSL_negotiate() may complete before enough spam fragments
         * accumulate to trigger DTLS_TOO_MANY_FRAGMENTS_E. Accept both
         * outcomes: server hit the fragment limit, or completed normally.
         */
        if (func_cb_server.return_code == TEST_FAIL) {
            ExpectIntEQ(func_cb_server.last_err, WC_NO_ERR_TRACE(DTLS_TOO_MANY_FRAGMENTS_E));
        }

        if (EXPECT_FAIL())
            break;
    }

    return EXPECT_RESULT();
}

static void test_wolfSSL_dtls_send_alert(WOLFSSL* ssl)
{
    int fd, ret;
    byte alert_msg[] = {
        0x15, /* alert type */
        0xfe, 0xfd, /* version */
        0x00, 0x00, /* epoch */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, /* seq number */
        0x00, 0x02, /* length */
        0x02, /* level: fatal */
        0x46 /* protocol version */
    };

    fd = wolfSSL_get_wfd(ssl);
    AssertIntGE(fd, 0);
    ret = (int)send(fd, (MESSAGE_TYPE_CAST)alert_msg, sizeof(alert_msg), 0);
    AssertIntGT(ret, 0);
}

static int _test_wolfSSL_ignore_alert_before_cookie(byte version12)
{
    callback_functions client_cbs, server_cbs;

    XMEMSET(&client_cbs, 0, sizeof(client_cbs));
    XMEMSET(&server_cbs, 0, sizeof(server_cbs));
    client_cbs.doUdp = server_cbs.doUdp = 1;
    if (version12) {
#if !defined(WOLFSSL_NO_TLS12)
        client_cbs.method = wolfDTLSv1_2_client_method;
        server_cbs.method = wolfDTLSv1_2_server_method;
#else
        return TEST_SKIPPED;
#endif
    }
    else
    {
#ifdef WOLFSSL_DTLS13
        client_cbs.method = wolfDTLSv1_3_client_method;
        server_cbs.method = wolfDTLSv1_3_server_method;
#else
        return TEST_SKIPPED;
#endif /* WOLFSSL_DTLS13 */
    }

    client_cbs.ssl_ready = test_wolfSSL_dtls_send_alert;
    test_wolfSSL_client_server_nofail(&client_cbs, &server_cbs);

    if (!client_cbs.return_code)
        return TEST_FAIL;
    if (!server_cbs.return_code)
        return TEST_FAIL;

    return TEST_SUCCESS;
}

int test_wolfSSL_ignore_alert_before_cookie(void)
{
    int ret;
    ret =_test_wolfSSL_ignore_alert_before_cookie(0);
    if (ret != 0)
        return ret;
    ret =_test_wolfSSL_ignore_alert_before_cookie(1);
    if (ret != 0)
        return ret;
    return 0;
}

static void test_wolfSSL_send_bad_record(WOLFSSL* ssl)
{
    int ret;
    int fd;

    byte bad_msg[] = {
        0x17, /* app data  */
        0xaa, 0xfd, /* bad version */
        0x00, 0x01, /* epoch 1 */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x55, /* not seen seq number */
        0x00, 0x26, /* length: 38 bytes */
        0xae, 0x30, 0x31, 0xb1, 0xf1, 0xb9, 0x6f, 0xda, 0x17, 0x19, 0xd9, 0x57,
        0xa9, 0x9d, 0x5c, 0x51, 0x9b, 0x53, 0x63, 0xa5, 0x24, 0x70, 0xa1,
        0xae, 0xdf, 0x1c, 0xb9, 0xfc, 0xe3, 0xd7, 0x77, 0x6d, 0xb6, 0x89, 0x0f,
        0x03, 0x18, 0x72
    };

    fd = wolfSSL_get_wfd(ssl);
    AssertIntGE(fd, 0);
    ret = (int)send(fd, (MESSAGE_TYPE_CAST)bad_msg, sizeof(bad_msg), 0);
    AssertIntEQ(ret, sizeof(bad_msg));
    ret = wolfSSL_write(ssl, "badrecordtest", sizeof("badrecordtest"));
    AssertIntEQ(ret, sizeof("badrecordtest"));
}

static void test_wolfSSL_read_string(WOLFSSL* ssl)
{
    byte buf[100];
    int ret;

    ret = wolfSSL_read(ssl, buf, sizeof(buf));
    AssertIntGT(ret, 0);
    AssertIntEQ(strcmp((char*)buf, "badrecordtest"), 0);
}

static int _test_wolfSSL_dtls_bad_record(
    method_provider client_method, method_provider server_method)
{
    callback_functions client_cbs, server_cbs;

    XMEMSET(&client_cbs, 0, sizeof(client_cbs));
    XMEMSET(&server_cbs, 0, sizeof(server_cbs));
    client_cbs.doUdp = server_cbs.doUdp = 1;
    client_cbs.method = client_method;
    server_cbs.method = server_method;

    client_cbs.on_result = test_wolfSSL_send_bad_record;
    server_cbs.on_result = test_wolfSSL_read_string;

    test_wolfSSL_client_server_nofail(&client_cbs, &server_cbs);

    if (!client_cbs.return_code)
        return TEST_FAIL;
    if (!server_cbs.return_code)
        return TEST_FAIL;

    return TEST_SUCCESS;
}

int test_wolfSSL_dtls_bad_record(void)
{
    int ret = TEST_SUCCESS;
#if !defined(WOLFSSL_NO_TLS12)
    ret = _test_wolfSSL_dtls_bad_record(wolfDTLSv1_2_client_method,
        wolfDTLSv1_2_server_method);
#endif
#ifdef WOLFSSL_DTLS13
    if (ret == TEST_SUCCESS) {
        ret = _test_wolfSSL_dtls_bad_record(wolfDTLSv1_3_client_method,
        wolfDTLSv1_3_server_method);
    }
#endif /* WOLFSSL_DTLS13 */
    return ret;

}

#else
int test_wolfSSL_dtls_fragments(void)
{
    return TEST_SKIPPED;
}
int test_wolfSSL_ignore_alert_before_cookie(void)
{
    return TEST_SKIPPED;
}
int test_wolfSSL_dtls_bad_record(void)
{
    return TEST_SKIPPED;
}
#endif

#if defined(WOLFSSL_DTLS13) && !defined(WOLFSSL_TLS13_IGNORE_AEAD_LIMITS) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    defined(HAVE_IO_TESTS_DEPENDENCIES)
static volatile int test_AEAD_seq_num = 0;
#ifdef WOLFSSL_NO_ATOMICS
static volatile int test_AEAD_done = 0;
#else
wolfSSL_Atomic_Int test_AEAD_done = WOLFSSL_ATOMIC_INITIALIZER(0);
#endif
#ifdef WOLFSSL_MUTEX_INITIALIZER
static wolfSSL_Mutex test_AEAD_mutex = WOLFSSL_MUTEX_INITIALIZER(test_AEAD_mutex);
#endif

static int test_AEAD_fail_decryption = 0;
static int test_AEAD_cbiorecv(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    int fd = wolfSSL_get_fd(ssl);
    int ret = -1;
    if (fd >= 0 && (ret = (int)recv(fd, buf, sz, 0)) > 0) {
        if (test_AEAD_fail_decryption) {
            /* Modify the packet to trigger a decryption failure */
            buf[ret/2] ^= 0xFF;
            if (test_AEAD_fail_decryption == 1)
                test_AEAD_fail_decryption = 0;
        }
    }
    (void)ctx;
    return ret;
}

static void test_AEAD_get_limits(WOLFSSL* ssl, w64wrapper* hardLimit,
        w64wrapper* keyUpdateLimit, w64wrapper* sendLimit)
{
    if (sendLimit)
        w64Zero(sendLimit);
    switch (ssl->specs.bulk_cipher_algorithm) {
        case wolfssl_aes_gcm:
            if (sendLimit)
                *sendLimit = AEAD_AES_LIMIT;
            FALL_THROUGH;
        case wolfssl_chacha:
            if (hardLimit)
                *hardLimit = DTLS_AEAD_AES_GCM_CHACHA_FAIL_LIMIT;
            if (keyUpdateLimit)
                *keyUpdateLimit = DTLS_AEAD_AES_GCM_CHACHA_FAIL_KU_LIMIT;
            break;
        case wolfssl_aes_ccm:
            if (sendLimit)
                *sendLimit = DTLS_AEAD_AES_CCM_LIMIT;
            if (ssl->specs.aead_mac_size == AES_CCM_8_AUTH_SZ) {
                if (hardLimit)
                    *hardLimit = DTLS_AEAD_AES_CCM_8_FAIL_LIMIT;
                if (keyUpdateLimit)
                    *keyUpdateLimit = DTLS_AEAD_AES_CCM_8_FAIL_KU_LIMIT;
            }
            else {
                if (hardLimit)
                    *hardLimit = DTLS_AEAD_AES_CCM_FAIL_LIMIT;
                if (keyUpdateLimit)
                    *keyUpdateLimit = DTLS_AEAD_AES_CCM_FAIL_KU_LIMIT;
            }
            break;
        default:
            fprintf(stderr, "Unrecognized bulk cipher");
            AssertFalse(1);
            break;
    }
}

static void test_AEAD_limit_client(WOLFSSL* ssl)
{
    int ret;
    int i;
    int didReKey = 0;
    char msgBuf[20];
    w64wrapper hardLimit;
    w64wrapper keyUpdateLimit;
    w64wrapper counter;
    w64wrapper sendLimit;

    test_AEAD_get_limits(ssl, &hardLimit, &keyUpdateLimit, &sendLimit);

    w64Zero(&counter);
    AssertTrue(w64Equal(Dtls13GetEpoch(ssl, ssl->dtls13Epoch)->dropCount, counter));

    wolfSSL_SSLSetIORecv(ssl, test_AEAD_cbiorecv);

    for (i = 0; i < 10; i++) {
        /* Test some failed decryptions */
        test_AEAD_fail_decryption = 1;
        w64Increment(&counter);
        ret = wolfSSL_read(ssl, msgBuf, sizeof(msgBuf));
        /* Should succeed since decryption failures are dropped */
        AssertIntGT(ret, 0);
        AssertTrue(w64Equal(Dtls13GetEpoch(ssl, ssl->dtls13PeerEpoch)->dropCount, counter));
    }

    test_AEAD_fail_decryption = 1;
    Dtls13GetEpoch(ssl, ssl->dtls13PeerEpoch)->dropCount = keyUpdateLimit;
    w64Increment(&Dtls13GetEpoch(ssl, ssl->dtls13PeerEpoch)->dropCount);
    /* 100 read calls should be enough to complete the key update */
    w64Zero(&counter);
    for (i = 0; i < 100; i++) {
        /* Key update should be sent and negotiated */
        ret = wolfSSL_read(ssl, msgBuf, sizeof(msgBuf));
        AssertIntGT(ret, 0);
        /* Epoch after one key update is 4 */
        if (w64Equal(ssl->dtls13PeerEpoch, w64From32(0, 4)) &&
                w64Equal(Dtls13GetEpoch(ssl, ssl->dtls13PeerEpoch)->dropCount, counter)) {
            didReKey = 1;
            break;
        }
    }
    AssertTrue(didReKey);

    if (!w64IsZero(sendLimit)) {
        /* Test the sending limit for AEAD ciphers */
#ifdef WOLFSSL_MUTEX_INITIALIZER
        (void)wc_LockMutex(&test_AEAD_mutex);
#endif
        Dtls13GetEpoch(ssl, ssl->dtls13Epoch)->nextSeqNumber = sendLimit;
        test_AEAD_seq_num = 1;
        XMEMSET(msgBuf, 0, sizeof(msgBuf));
        ret = wolfSSL_write(ssl, msgBuf, sizeof(msgBuf));
        AssertIntGT(ret, 0);
        didReKey = 0;
        w64Zero(&counter);
#ifdef WOLFSSL_MUTEX_INITIALIZER
        wc_UnLockMutex(&test_AEAD_mutex);
#endif
        /* 100 read calls should be enough to complete the key update */
        for (i = 0; i < 100; i++) {
            /* Key update should be sent and negotiated */
            ret = wolfSSL_read(ssl, msgBuf, sizeof(msgBuf));
            AssertIntGT(ret, 0);
            /* Epoch after another key update is 5 */
            if (w64Equal(ssl->dtls13Epoch, w64From32(0, 5)) &&
                    w64Equal(Dtls13GetEpoch(ssl, ssl->dtls13Epoch)->dropCount, counter)) {
                didReKey = 1;
                break;
            }
        }
        AssertTrue(didReKey);
    }

    test_AEAD_fail_decryption = 2;
    Dtls13GetEpoch(ssl, ssl->dtls13PeerEpoch)->dropCount = hardLimit;
    w64Decrement(&Dtls13GetEpoch(ssl, ssl->dtls13PeerEpoch)->dropCount);
    /* Connection should fail with a DECRYPT_ERROR */
    ret = wolfSSL_read(ssl, msgBuf, sizeof(msgBuf));
    AssertIntEQ(ret, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    AssertIntEQ(wolfSSL_get_error(ssl, ret), WC_NO_ERR_TRACE(DECRYPT_ERROR));

#ifdef WOLFSSL_ATOMIC_INITIALIZER
    WOLFSSL_ATOMIC_STORE(test_AEAD_done, 1);
#else
    test_AEAD_done = 1;
#endif
}

int counter = 0;
static void test_AEAD_limit_server(WOLFSSL* ssl)
{
    char msgBuf[] = "Sending data";
    int ret = WOLFSSL_SUCCESS;
    w64wrapper sendLimit;
    SOCKET_T fd = wolfSSL_get_fd(ssl);
    struct timespec delay;
    XMEMSET(&delay, 0, sizeof(delay));
    delay.tv_nsec = 100000000; /* wait 0.1 seconds */
    tcp_set_nonblocking(&fd); /* So that read doesn't block */
    wolfSSL_dtls_set_using_nonblock(ssl, 1);
    test_AEAD_get_limits(ssl, NULL, NULL, &sendLimit);
    while (!
    #ifdef WOLFSSL_ATOMIC_INITIALIZER
           WOLFSSL_ATOMIC_LOAD(test_AEAD_done)
    #else
           test_AEAD_done
    #endif
           && ret > 0)
    {
        counter++;
#ifdef WOLFSSL_MUTEX_INITIALIZER
        (void)wc_LockMutex(&test_AEAD_mutex);
#endif
        if (test_AEAD_seq_num) {
            /* We need to update the seq number so that we can understand the
             * peer. Otherwise we will incorrectly interpret the seq number. */
            Dtls13Epoch* e = Dtls13GetEpoch(ssl, ssl->dtls13PeerEpoch);
            AssertNotNull(e);
            e->nextPeerSeqNumber = sendLimit;
            test_AEAD_seq_num = 0;
        }
#ifdef WOLFSSL_MUTEX_INITIALIZER
        wc_UnLockMutex(&test_AEAD_mutex);
#endif
        (void)wolfSSL_read(ssl, msgBuf, sizeof(msgBuf));
        ret = wolfSSL_write(ssl, msgBuf, sizeof(msgBuf));
        nanosleep(&delay, NULL);
    }
}

int test_wolfSSL_dtls_AEAD_limit(void)
{
    callback_functions func_cb_client;
    callback_functions func_cb_server;
    XMEMSET(&func_cb_client, 0, sizeof(callback_functions));
    XMEMSET(&func_cb_server, 0, sizeof(callback_functions));

    func_cb_client.doUdp = func_cb_server.doUdp = 1;
    func_cb_server.method = wolfDTLSv1_3_server_method;
    func_cb_client.method = wolfDTLSv1_3_client_method;
    func_cb_server.on_result = test_AEAD_limit_server;
    func_cb_client.on_result = test_AEAD_limit_client;

    test_wolfSSL_client_server_nofail(&func_cb_client, &func_cb_server);

    if (!func_cb_client.return_code)
        return TEST_FAIL;
    if (!func_cb_server.return_code)
        return TEST_FAIL;

    return TEST_SUCCESS;
}
#else
int test_wolfSSL_dtls_AEAD_limit(void)
{
    return TEST_SKIPPED;
}
#endif

#if defined(WOLFSSL_DTLS) && \
    defined(HAVE_IO_TESTS_DEPENDENCIES) && !defined(SINGLE_THREADED) && \
    !defined(DEBUG_VECTOR_REGISTER_ACCESS_FUZZING)
static void test_wolfSSL_dtls_send_ch(WOLFSSL* ssl)
{
    int fd, ret;
    byte ch_msg[] = {
        0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0xfa, 0x01, 0x00, 0x01, 0xee, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0xee, 0xfe, 0xfd, 0xc0, 0xca, 0xb5, 0x6f, 0x3d, 0x23, 0xcc, 0x53, 0x9a,
        0x67, 0x17, 0x70, 0xd3, 0xfb, 0x23, 0x16, 0x9e, 0x4e, 0xd6, 0x7e, 0x29,
        0xab, 0xfa, 0x4c, 0xa5, 0x84, 0x95, 0xc3, 0xdb, 0x21, 0x9a, 0x52, 0x00,
        0x00, 0x00, 0x36, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2c, 0xc0,
        0x2b, 0xc0, 0x30, 0xc0, 0x2f, 0x00, 0x9f, 0x00, 0x9e, 0xcc, 0xa9, 0xcc,
        0xa8, 0xcc, 0xaa, 0xc0, 0x27, 0xc0, 0x23, 0xc0, 0x28, 0xc0, 0x24, 0xc0,
        0x0a, 0xc0, 0x09, 0xc0, 0x14, 0xc0, 0x13, 0x00, 0x6b, 0x00, 0x67, 0x00,
        0x39, 0x00, 0x33, 0xcc, 0x14, 0xcc, 0x13, 0xcc, 0x15, 0x01, 0x00, 0x01,
        0x8e, 0x00, 0x2b, 0x00, 0x03, 0x02, 0xfe, 0xfc, 0x00, 0x0d, 0x00, 0x20,
        0x00, 0x1e, 0x06, 0x03, 0x05, 0x03, 0x04, 0x03, 0x02, 0x03, 0x08, 0x06,
        0x08, 0x0b, 0x08, 0x05, 0x08, 0x0a, 0x08, 0x04, 0x08, 0x09, 0x06, 0x01,
        0x05, 0x01, 0x04, 0x01, 0x03, 0x01, 0x02, 0x01, 0x00, 0x0a, 0x00, 0x0c,
        0x00, 0x0a, 0x00, 0x19, 0x00, 0x18, 0x00, 0x17, 0x00, 0x15, 0x01, 0x00,
        0x00, 0x16, 0x00, 0x00, 0x00, 0x33, 0x01, 0x4b, 0x01, 0x49, 0x00, 0x17,
        0x00, 0x41, 0x04, 0x96, 0xcb, 0x2e, 0x4e, 0xd9, 0x88, 0x71, 0xc7, 0xf3,
        0x1a, 0x16, 0xdd, 0x7a, 0x7c, 0xf7, 0x67, 0x8a, 0x5d, 0x9a, 0x55, 0xa6,
        0x4a, 0x90, 0xd9, 0xfb, 0xc7, 0xfb, 0xbe, 0x09, 0xa9, 0x8a, 0xb5, 0x7a,
        0xd1, 0xde, 0x83, 0x74, 0x27, 0x31, 0x1c, 0xaa, 0xae, 0xef, 0x58, 0x43,
        0x13, 0x7d, 0x15, 0x4d, 0x7f, 0x68, 0xf6, 0x8a, 0x38, 0xef, 0x0e, 0xb3,
        0xcf, 0xb8, 0x4a, 0xa9, 0xb4, 0xd7, 0xcb, 0x01, 0x00, 0x01, 0x00, 0x1d,
        0x0a, 0x22, 0x8a, 0xd1, 0x78, 0x85, 0x1e, 0x5a, 0xe1, 0x1d, 0x1e, 0xb7,
        0x2d, 0xbc, 0x5f, 0x52, 0xbc, 0x97, 0x5d, 0x8b, 0x6a, 0x8b, 0x9d, 0x1e,
        0xb1, 0xfc, 0x8a, 0xb2, 0x56, 0xcd, 0xed, 0x4b, 0xfb, 0x66, 0x3f, 0x59,
        0x3f, 0x15, 0x5d, 0x09, 0x9e, 0x2f, 0x60, 0x5b, 0x31, 0x81, 0x27, 0xf0,
        0x1c, 0xda, 0xcd, 0x48, 0x66, 0xc6, 0xbb, 0x25, 0xf0, 0x5f, 0xda, 0x4c,
        0xcf, 0x1d, 0x88, 0xc8, 0xda, 0x1b, 0x53, 0xea, 0xbd, 0xce, 0x6d, 0xf6,
        0x4a, 0x76, 0xdb, 0x75, 0x99, 0xaf, 0xcf, 0x76, 0x4a, 0xfb, 0xe3, 0xef,
        0xb2, 0xcb, 0xae, 0x4a, 0xc0, 0xe8, 0x63, 0x1f, 0xd6, 0xe8, 0xe6, 0x45,
        0xf9, 0xea, 0x0d, 0x06, 0x19, 0xfc, 0xb1, 0xfd, 0x5d, 0x92, 0x89, 0x7b,
        0xc7, 0x9f, 0x1a, 0xb3, 0x2b, 0xc7, 0xad, 0x0e, 0xfb, 0x13, 0x41, 0x83,
        0x84, 0x58, 0x3a, 0x25, 0xb9, 0x49, 0x35, 0x1c, 0x23, 0xcb, 0xd6, 0xe7,
        0xc2, 0x8c, 0x4b, 0x2a, 0x73, 0xa1, 0xdf, 0x4f, 0x73, 0x9b, 0xb3, 0xd2,
        0xb2, 0x95, 0x00, 0x3c, 0x26, 0x09, 0x89, 0x71, 0x05, 0x39, 0xc8, 0x98,
        0x8f, 0xed, 0x32, 0x15, 0x78, 0xcd, 0xd3, 0x7e, 0xfb, 0x5a, 0x78, 0x2a,
        0xdc, 0xca, 0x20, 0x09, 0xb5, 0x14, 0xf9, 0xd4, 0x58, 0xf6, 0x69, 0xf8,
        0x65, 0x9f, 0xb7, 0xe4, 0x93, 0xf1, 0xa3, 0x84, 0x7e, 0x1b, 0x23, 0x5d,
        0xea, 0x59, 0x3e, 0x4d, 0xca, 0xfd, 0xa5, 0x55, 0xdd, 0x99, 0xb5, 0x02,
        0xf8, 0x0d, 0xe5, 0xf4, 0x06, 0xb0, 0x43, 0x9e, 0x2e, 0xbf, 0x05, 0x33,
        0x65, 0x7b, 0x13, 0x8c, 0xf9, 0x16, 0x4d, 0xc5, 0x15, 0x0b, 0x40, 0x2f,
        0x66, 0x94, 0xf2, 0x43, 0x95, 0xe7, 0xa9, 0xb6, 0x39, 0x99, 0x73, 0xb3,
        0xb0, 0x06, 0xfe, 0x52, 0x9e, 0x57, 0xba, 0x75, 0xfd, 0x76, 0x7b, 0x20,
        0x31, 0x68, 0x4c
    };

    fd = wolfSSL_get_wfd(ssl);
    AssertIntGE(fd, 0);
    ret = (int)send(fd, (MESSAGE_TYPE_CAST)ch_msg, sizeof(ch_msg), 0);
    AssertIntGT(ret, 0);
    /* consume the HRR otherwise handshake will fail */
    ret = (int)recv(fd, (MESSAGE_TYPE_CAST)ch_msg, sizeof(ch_msg), 0);
    AssertIntGT(ret, 0);
}

#if defined(WOLFSSL_DTLS13) && defined(WOLFSSL_SEND_HRR_COOKIE)
static void test_wolfSSL_dtls_send_ch_with_invalid_cookie(WOLFSSL* ssl)
{
    int fd, ret;
    byte ch_msh_invalid_cookie[] = {
      0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02,
      0x4e, 0x01, 0x00, 0x02, 0x42, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02,
      0x42, 0xfe, 0xfd, 0x69, 0xca, 0x77, 0x60, 0x6f, 0xfc, 0xd1, 0x5b, 0x60,
      0x5d, 0xf1, 0xa6, 0x5c, 0x44, 0x71, 0xae, 0xca, 0x62, 0x19, 0x0c, 0xb6,
      0xf7, 0x2c, 0xa6, 0xd5, 0xd2, 0x99, 0x9d, 0x18, 0xae, 0xac, 0x11, 0x00,
      0x00, 0x00, 0x36, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2c, 0xc0,
      0x2b, 0xc0, 0x30, 0xc0, 0x2f, 0x00, 0x9f, 0x00, 0x9e, 0xcc, 0xa9, 0xcc,
      0xa8, 0xcc, 0xaa, 0xc0, 0x27, 0xc0, 0x23, 0xc0, 0x28, 0xc0, 0x24, 0xc0,
      0x0a, 0xc0, 0x09, 0xc0, 0x14, 0xc0, 0x13, 0x00, 0x6b, 0x00, 0x67, 0x00,
      0x39, 0x00, 0x33, 0xcc, 0x14, 0xcc, 0x13, 0xcc, 0x15, 0x01, 0x00, 0x01,
      0xe2, 0x00, 0x2b, 0x00, 0x03, 0x02, 0xfe, 0xfc, 0x00, 0x0d, 0x00, 0x20,
      0x00, 0x1e, 0x06, 0x03, 0x05, 0x03, 0x04, 0x03, 0x02, 0x03, 0x08, 0x06,
      0x08, 0x0b, 0x08, 0x05, 0x08, 0x0a, 0x08, 0x04, 0x08, 0x09, 0x06, 0x01,
      0x05, 0x01, 0x04, 0x01, 0x03, 0x01, 0x02, 0x01, 0x00, 0x2c, 0x00, 0x45,
      0x00, 0x43, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x2d, 0x00,
      0x03, 0x02, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x19,
      0x00, 0x18, 0x00, 0x17, 0x00, 0x15, 0x01, 0x00, 0x00, 0x16, 0x00, 0x00,
      0x00, 0x33, 0x01, 0x4b, 0x01, 0x49, 0x00, 0x17, 0x00, 0x41, 0x04, 0x7c,
      0x5a, 0xc2, 0x5a, 0xfd, 0xcd, 0x2b, 0x08, 0xb2, 0xeb, 0x8e, 0xc0, 0x02,
      0x03, 0x9d, 0xb1, 0xc1, 0x0d, 0x7b, 0x7f, 0x46, 0x43, 0xdf, 0xf3, 0xee,
      0x2b, 0x78, 0x0e, 0x29, 0x8c, 0x42, 0x11, 0x2c, 0xde, 0xd7, 0x41, 0x0f,
      0x28, 0x94, 0x80, 0x41, 0x70, 0xc4, 0x17, 0xfd, 0x6d, 0xfa, 0xee, 0x9a,
      0xf2, 0xc4, 0x15, 0x4c, 0x5f, 0x54, 0xb6, 0x78, 0x6e, 0xf9, 0x63, 0x27,
      0x33, 0xb8, 0x7b, 0x01, 0x00, 0x01, 0x00, 0xd4, 0x46, 0x62, 0x9c, 0xbf,
      0x8f, 0x1b, 0x65, 0x9b, 0xf0, 0x29, 0x64, 0xd8, 0x50, 0x0e, 0x74, 0xf1,
      0x58, 0x10, 0xc9, 0xd9, 0x82, 0x5b, 0xd9, 0xbe, 0x14, 0xdf, 0xde, 0x86,
      0xb4, 0x2e, 0x15, 0xee, 0x4f, 0xf6, 0x74, 0x9e, 0x59, 0x11, 0x36, 0x2d,
      0xb9, 0x67, 0xaa, 0x5a, 0x09, 0x9b, 0x45, 0xf1, 0x01, 0x4c, 0x4e, 0xf6,
      0xda, 0x6a, 0xae, 0xa7, 0x73, 0x7b, 0x2e, 0xb6, 0x24, 0x89, 0x99, 0xb7,
      0x52, 0x16, 0x62, 0x0a, 0xab, 0x58, 0xf8, 0x3f, 0x10, 0x5b, 0x83, 0xfd,
      0x7b, 0x81, 0x77, 0x81, 0x8d, 0xef, 0x24, 0x56, 0x6d, 0xba, 0x49, 0xd4,
      0x8b, 0xb5, 0xa0, 0xb1, 0xc9, 0x8c, 0x32, 0x95, 0x1c, 0x5e, 0x0a, 0x4b,
      0xf6, 0x00, 0x50, 0x0a, 0x87, 0x99, 0x59, 0xcf, 0x6f, 0x9d, 0x02, 0xd0,
      0x1b, 0xa1, 0x96, 0x45, 0x28, 0x76, 0x40, 0x33, 0x28, 0xc9, 0xa1, 0xfd,
      0x46, 0xab, 0x2c, 0x9e, 0x5e, 0xc6, 0x74, 0x19, 0x9a, 0xf5, 0x9b, 0x51,
      0x11, 0x4f, 0xc8, 0xb9, 0x99, 0x6b, 0x4e, 0x3e, 0x31, 0x64, 0xb4, 0x92,
      0xf4, 0x0d, 0x41, 0x4b, 0x2c, 0x65, 0x23, 0xf7, 0x47, 0xe3, 0xa5, 0x2e,
      0xe4, 0x9c, 0x2b, 0xc9, 0x41, 0x22, 0x83, 0x8a, 0x23, 0xef, 0x29, 0x7e,
      0x4f, 0x3f, 0xa3, 0xbf, 0x73, 0x2b, 0xd7, 0xcc, 0xc8, 0xc6, 0xe9, 0xbc,
      0x01, 0xb7, 0x32, 0x63, 0xd4, 0x7e, 0x7f, 0x9a, 0xaf, 0x5f, 0x05, 0x31,
      0x53, 0xd6, 0x1f, 0xa2, 0xd0, 0xdf, 0x67, 0x56, 0xf1, 0x9c, 0x4a, 0x9d,
      0x83, 0xb4, 0xef, 0xb3, 0xf2, 0xcc, 0xf1, 0x91, 0x6c, 0x47, 0xc3, 0x8b,
      0xd0, 0x92, 0x79, 0x3d, 0xa0, 0xc0, 0x3a, 0x57, 0x26, 0x6d, 0x0a, 0xad,
      0x5f, 0xad, 0xb4, 0x74, 0x48, 0x4a, 0x51, 0xe1, 0xb5, 0x82, 0x0a, 0x4c,
      0x4f, 0x9d, 0xaf, 0xee, 0x5a, 0xa2, 0x4d, 0x4d, 0x5f, 0xe0, 0x17, 0x00,
      0x23, 0x00, 0x00
    };
    byte alert_reply[50];
    byte expected_alert_reply[] = {
        0x15, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x02, 0x02, 0x2f
    };

    fd = wolfSSL_get_wfd(ssl);
    if (fd >= 0) {
        ret = (int)send(fd, (MESSAGE_TYPE_CAST)ch_msh_invalid_cookie,
                sizeof(ch_msh_invalid_cookie), 0);
        AssertIntGT(ret, 0);
        /* should reply with an illegal_parameter reply */
        ret = (int)recv(fd, (MESSAGE_TYPE_CAST)alert_reply, sizeof(alert_reply), 0);
        AssertIntEQ(ret, sizeof(expected_alert_reply));
        AssertIntEQ(XMEMCMP(alert_reply, expected_alert_reply,
                sizeof(expected_alert_reply)), 0);
    }
}
#endif

static word32 test_wolfSSL_dtls_stateless_HashWOLFSSL(const WOLFSSL* ssl)
{
#ifndef NO_MD5
    enum wc_HashType hashType = WC_HASH_TYPE_MD5;
#elif !defined(NO_SHA)
    enum wc_HashType hashType = WC_HASH_TYPE_SHA;
#elif !defined(NO_SHA256)
    enum wc_HashType hashType = WC_HASH_TYPE_SHA256;
#else
    #error "We need a digest to hash the WOLFSSL object"
#endif
    byte hashBuf[WC_MAX_DIGEST_SIZE];
    wc_HashAlg hash;
    const TLSX* exts = ssl->extensions;
    WOLFSSL sslCopy; /* Use a copy to omit certain fields */
#ifndef WOLFSSL_SMALL_STACK_CACHE
    HS_Hashes* hsHashes = ssl->hsHashes; /* Is re-allocated in
                                          * InitHandshakeHashes */
#endif

    XMEMCPY(&sslCopy, ssl, sizeof(*ssl));
    XMEMSET(hashBuf, 0, sizeof(hashBuf));

    /* Following fields are not important to compare */
    XMEMSET(sslCopy.buffers.inputBuffer.staticBuffer, 0, STATIC_BUFFER_LEN);
    sslCopy.buffers.inputBuffer.buffer = NULL;
    sslCopy.buffers.inputBuffer.bufferSize = 0;
    sslCopy.buffers.inputBuffer.dynamicFlag = 0;
    sslCopy.buffers.inputBuffer.offset = 0;
    XMEMSET(sslCopy.buffers.outputBuffer.staticBuffer, 0, STATIC_BUFFER_LEN);
    sslCopy.buffers.outputBuffer.buffer = NULL;
    sslCopy.buffers.outputBuffer.bufferSize = 0;
    sslCopy.buffers.outputBuffer.dynamicFlag = 0;
    sslCopy.buffers.outputBuffer.offset = 0;
    sslCopy.error = 0;
    sslCopy.curSize = 0;
    sslCopy.curStartIdx = 0;
    sslCopy.keys.curSeq_lo = 0;
    XMEMSET(&sslCopy.curRL, 0, sizeof(sslCopy.curRL));
#ifdef WOLFSSL_DTLS13
    XMEMSET(&sslCopy.keys.curSeq, 0, sizeof(sslCopy.keys.curSeq));
    sslCopy.dtls13FastTimeout = 0;
#endif
    sslCopy.keys.dtls_peer_handshake_number = 0;
    XMEMSET(&sslCopy.alert_history, 0, sizeof(sslCopy.alert_history));
    sslCopy.hsHashes = NULL;
#if !defined(WOLFSSL_NO_CLIENT_AUTH) && \
    ((defined(WOLFSSL_SM2) && defined(WOLFSSL_SM3)) || \
     (defined(HAVE_ED25519) && !defined(NO_ED25519_CLIENT_AUTH)) || \
     (defined(HAVE_ED448) && !defined(NO_ED448_CLIENT_AUTH)))
    sslCopy.options.cacheMessages = 0;
#endif
#ifdef WOLFSSL_ASYNC_IO
#ifdef WOLFSSL_ASYNC_CRYPT
    sslCopy.asyncDev = NULL;
#endif
    sslCopy.async = NULL;
#endif

    AssertIntEQ(wc_HashInit(&hash, hashType), 0);
    AssertIntEQ(wc_HashUpdate(&hash, hashType, (byte*)&sslCopy, sizeof(sslCopy)), 0);
    /* hash extension list */
    while (exts != NULL) {
        AssertIntEQ(wc_HashUpdate(&hash, hashType, (byte*)exts, sizeof(*exts)), 0);
        exts = exts->next;
    }
    /* Hash suites */
    if (sslCopy.suites != NULL) {
        AssertIntEQ(wc_HashUpdate(&hash, hashType, (byte*)sslCopy.suites,
                sizeof(struct Suites)), 0);
    }

#ifdef WOLFSSL_SMALL_STACK_CACHE
    /* with WOLFSSL_SMALL_STACK_CACHE, the SHA-2 objects always differ after
     * initialization because of cached W and (for SHA512) X buffers.
     */
#else
    /* Hash hsHashes */
    AssertIntEQ(wc_HashUpdate(&hash, hashType, (byte*)hsHashes,
            sizeof(*hsHashes)), 0);
#endif

    AssertIntEQ(wc_HashFinal(&hash, hashType, hashBuf), 0);
    AssertIntEQ(wc_HashFree(&hash, hashType), 0);

    return MakeWordFromHash(hashBuf);
}

static CallbackIORecv test_wolfSSL_dtls_compare_stateless_cb;
static int test_wolfSSL_dtls_compare_stateless_cb_call_once;
static int test_wolfSSL_dtls_compare_stateless_read_cb_once(WOLFSSL *ssl,
        char *buf, int sz, void *ctx)
{
    if (test_wolfSSL_dtls_compare_stateless_cb_call_once) {
        test_wolfSSL_dtls_compare_stateless_cb_call_once = 0;
        return test_wolfSSL_dtls_compare_stateless_cb(ssl, buf, sz, ctx);
    }
    else {
        return WOLFSSL_CBIO_ERR_WANT_READ;
    }
}

static void test_wolfSSL_dtls_compare_stateless(WOLFSSL* ssl)
{
    /* Compare the ssl object before and after one ClientHello msg */
    SOCKET_T fd = wolfSSL_get_fd(ssl);
    int res;
    int err;
    word32 initHash;

    test_wolfSSL_dtls_compare_stateless_cb = ssl->CBIORecv;
    test_wolfSSL_dtls_compare_stateless_cb_call_once = 1;
    wolfSSL_dtls_set_using_nonblock(ssl, 1);
    ssl->CBIORecv = test_wolfSSL_dtls_compare_stateless_read_cb_once;

    initHash = test_wolfSSL_dtls_stateless_HashWOLFSSL(ssl);
    (void)initHash;

    res = tcp_select(fd, 5);
    /* We are expecting a msg. A timeout indicates failure. */
    AssertIntEQ(res, TEST_RECV_READY);

    res = wolfSSL_accept(ssl);
    err = wolfSSL_get_error(ssl, res);
    AssertIntEQ(res, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    AssertIntEQ(err, WOLFSSL_ERROR_WANT_READ);

    AssertIntEQ(initHash, test_wolfSSL_dtls_stateless_HashWOLFSSL(ssl));

    wolfSSL_dtls_set_using_nonblock(ssl, 0);
    ssl->CBIORecv = test_wolfSSL_dtls_compare_stateless_cb;

}

#if defined(WOLFSSL_DTLS13) && defined(WOLFSSL_SEND_HRR_COOKIE)
static void test_wolfSSL_dtls_enable_hrrcookie(WOLFSSL* ssl)
{
    int ret;
    ret = wolfSSL_send_hrr_cookie(ssl, NULL, 0);
    AssertIntEQ(ret, WOLFSSL_SUCCESS);
    test_wolfSSL_dtls_compare_stateless(ssl);
}
#endif

int test_wolfSSL_dtls_stateless(void)
{
    callback_functions client_cbs, server_cbs;
    size_t i;
    struct {
        method_provider client_meth;
        method_provider server_meth;
        ssl_callback client_ssl_ready;
        ssl_callback server_ssl_ready;
    } test_params[] = {
#if !defined(WOLFSSL_NO_TLS12)
        {wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method,
                test_wolfSSL_dtls_send_ch, test_wolfSSL_dtls_compare_stateless},
#endif
#if defined(WOLFSSL_DTLS13) && defined(WOLFSSL_SEND_HRR_COOKIE)
        {wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method,
                test_wolfSSL_dtls_send_ch, test_wolfSSL_dtls_enable_hrrcookie},
        {wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method,
                test_wolfSSL_dtls_send_ch_with_invalid_cookie, test_wolfSSL_dtls_enable_hrrcookie},
#endif
    };

    if (0 == sizeof(test_params)){
        return TEST_SKIPPED;
    }

    for (i = 0; i < sizeof(test_params)/sizeof(*test_params); i++) {
        XMEMSET(&client_cbs, 0, sizeof(client_cbs));
        XMEMSET(&server_cbs, 0, sizeof(server_cbs));
        client_cbs.doUdp = server_cbs.doUdp = 1;
        client_cbs.method = test_params[i].client_meth;
        server_cbs.method = test_params[i].server_meth;

        client_cbs.ssl_ready = test_params[i].client_ssl_ready;
        server_cbs.ssl_ready = test_params[i].server_ssl_ready;
        test_wolfSSL_client_server_nofail(&client_cbs, &server_cbs);

        if (!client_cbs.return_code)
            return TEST_FAIL;
        if (!server_cbs.return_code)
            return TEST_FAIL;
    }

    return TEST_SUCCESS;
}

/* DTLS stateless API handling multiple CHs with different HRR groups */
int test_wolfSSL_dtls_stateless_hrr_group(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SEND_HRR_COOKIE)
    size_t i;
    word32 initHash = 0;
    struct {
        method_provider client_meth;
        method_provider server_meth;
    } params[] = {
#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_DTLS13)
        { wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method },
#endif
#if !defined(WOLFSSL_NO_TLS12) && defined(WOLFSSL_DTLS)
        { wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method },
#endif
    };
    for (i = 0; i < XELEM_CNT(params) && !EXPECT_FAIL(); i++) {
        WOLFSSL_CTX *ctx_s = NULL, *ctx_c = NULL;
        WOLFSSL *ssl_s = NULL, *ssl_c = NULL, *ssl_c2 = NULL;
        struct test_memio_ctx test_ctx;
        int groups_1[] = {
            WOLFSSL_ECC_SECP256R1,
            WOLFSSL_ECC_SECP384R1,
            WOLFSSL_ECC_SECP521R1
        };
        int groups_2[] = {
            WOLFSSL_ECC_SECP384R1,
            WOLFSSL_ECC_SECP521R1
        };
        char hrrBuf[1000];
        int hrrSz = sizeof(hrrBuf);

        XMEMSET(&test_ctx, 0, sizeof(test_ctx));

        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                params[i].client_meth, params[i].server_meth), 0);

        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, NULL, &ssl_c2, NULL,
                params[i].client_meth, params[i].server_meth), 0);


        wolfSSL_SetLoggingPrefix("server");
        wolfSSL_dtls_set_using_nonblock(ssl_s, 1);

        if (EXPECT_SUCCESS()) {
            initHash = test_wolfSSL_dtls_stateless_HashWOLFSSL(ssl_s);
        }

        /* Set groups and disable key shares. This ensures that only the given
         * groups are in the SupportedGroups extension and that an empty key
         * share extension is sent in the initial ClientHello of each session.
         * This triggers the server to send a HelloRetryRequest with the first
         * group in the SupportedGroups extension selected. */
        wolfSSL_SetLoggingPrefix("client1");
        ExpectIntEQ(wolfSSL_set_groups(ssl_c, groups_1, 3), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_NoKeyShares(ssl_c), WOLFSSL_SUCCESS);

        wolfSSL_SetLoggingPrefix("client2");
        ExpectIntEQ(wolfSSL_set_groups(ssl_c2, groups_2, 2), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_NoKeyShares(ssl_c2), WOLFSSL_SUCCESS);

        /* Start handshake, send first ClientHello */
        wolfSSL_SetLoggingPrefix("client1");
        ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
        ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);

        /* Read first ClientHello, send HRR with WOLFSSL_ECC_SECP256R1 */
        wolfSSL_SetLoggingPrefix("server");
        ExpectIntEQ(wolfDTLS_accept_stateless(ssl_s), 0);
        ExpectIntEQ(test_memio_copy_message(&test_ctx, 1, hrrBuf, &hrrSz, 0), 0);
        ExpectIntGT(hrrSz, 0);
        ExpectIntEQ(initHash, test_wolfSSL_dtls_stateless_HashWOLFSSL(ssl_s));
        test_memio_clear_buffer(&test_ctx, 1);

        /* Send second ClientHello */
        wolfSSL_SetLoggingPrefix("client2");
        ExpectIntEQ(wolfSSL_connect(ssl_c2), -1);
        ExpectIntEQ(wolfSSL_get_error(ssl_c2, -1), WOLFSSL_ERROR_WANT_READ);

        /* Read second ClientHello, send HRR now with WOLFSSL_ECC_SECP384R1 */
        wolfSSL_SetLoggingPrefix("server");
        ExpectIntEQ(wolfDTLS_accept_stateless(ssl_s), 0);
        ExpectIntEQ(initHash, test_wolfSSL_dtls_stateless_HashWOLFSSL(ssl_s));
        test_memio_clear_buffer(&test_ctx, 1);

        /* Complete first handshake with WOLFSSL_ECC_SECP256R1 */
        wolfSSL_SetLoggingPrefix("client1");
        ExpectIntEQ(test_memio_inject_message(&test_ctx, 1, hrrBuf, hrrSz), 0);
        ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
        ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);

        wolfSSL_SetLoggingPrefix("server");
        ExpectIntEQ(wolfDTLS_accept_stateless(ssl_s), WOLFSSL_SUCCESS);

        ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

        wolfSSL_free(ssl_s);
        wolfSSL_free(ssl_c);
        wolfSSL_free(ssl_c2);
        wolfSSL_CTX_free(ctx_s);
        wolfSSL_CTX_free(ctx_c);
    }
#endif /* WOLFSSL_SEND_HRR_COOKIE */
    return EXPECT_RESULT();
}
#else
int test_wolfSSL_dtls_stateless(void)
{
    return TEST_SKIPPED;
}

int test_wolfSSL_dtls_stateless_hrr_group(void)
{
    return TEST_SKIPPED;
}
#endif /* WOLFSSL_DTLS13 && WOLFSSL_SEND_HRR_COOKIE &&
        * HAVE_IO_TESTS_DEPENDENCIES && !SINGLE_THREADED */

/*----------------------------------------------------------------------------*/
/* DTLS window updates, fragment buckets, stateless resume/downgrade, alerts  */
/*----------------------------------------------------------------------------*/

#ifdef WOLFSSL_DTLS

/* Prints out the current window */
static void DUW_TEST_print_window_binary(word32 h, word32 l, word32* w) {
#ifdef WOLFSSL_DEBUG_DTLS_WINDOW
    int i;
    for (i = WOLFSSL_DTLS_WINDOW_WORDS - 1; i >= 0; i--) {
        word32 b = w[i];
        int j;
        /* Prints out a 32 bit binary number in big endian order */
        for (j = 0; j < 32; j++, b <<= 1) {
            if (b & (((word32)1) << 31))
                fprintf(stderr, "1");
            else
                fprintf(stderr, "0");
        }
        fprintf(stderr, " ");
    }
    fprintf(stderr, "cur_hi %u cur_lo %u\n", h, l);
#else
    (void)h;
    (void)l;
    (void)w;
#endif
}

/* a - cur_hi
 * b - cur_lo
 * c - next_hi
 * d - next_lo
 * e - window
 * f - expected next_hi
 * g - expected next_lo
 * h - expected window[1]
 * i - expected window[0]
 */
#define DUW_TEST(a,b,c,d,e,f,g,h,i) do { \
    ExpectIntEQ(wolfSSL_DtlsUpdateWindow((a), (b), &(c), &(d), (e)), 1); \
    DUW_TEST_print_window_binary((a), (b), (e)); \
    ExpectIntEQ((c), (f)); \
    ExpectIntEQ((d), (g)); \
    ExpectIntEQ((e)[1], (h)); \
    ExpectIntEQ((e)[0], (i)); \
} while (0)

int test_wolfSSL_DtlsUpdateWindow(void)
{
    EXPECT_DECLS;
    word32 window[WOLFSSL_DTLS_WINDOW_WORDS];
    word32 next_lo = 0;
    word16 next_hi = 0;

#ifdef WOLFSSL_DEBUG_DTLS_WINDOW
    fprintf(stderr, "\n");
#endif

    XMEMSET(window, 0, sizeof window);
    DUW_TEST(0, 0, next_hi, next_lo, window, 0, 1, 0, 0x01);
    DUW_TEST(0, 1, next_hi, next_lo, window, 0, 2, 0, 0x03);
    DUW_TEST(0, 5, next_hi, next_lo, window, 0, 6, 0, 0x31);
    DUW_TEST(0, 4, next_hi, next_lo, window, 0, 6, 0, 0x33);
    DUW_TEST(0, 100, next_hi, next_lo, window, 0, 101, 0, 0x01);
    DUW_TEST(0, 101, next_hi, next_lo, window, 0, 102, 0, 0x03);
    DUW_TEST(0, 133, next_hi, next_lo, window, 0, 134, 0x03, 0x01);
    DUW_TEST(0, 200, next_hi, next_lo, window, 0, 201, 0, 0x01);
    DUW_TEST(0, 264, next_hi, next_lo, window, 0, 265, 0, 0x01);
    DUW_TEST(0, 0xFFFFFFFF, next_hi, next_lo, window, 1, 0, 0, 0x01);
    DUW_TEST(0, 0xFFFFFFFD, next_hi, next_lo, window, 1, 0, 0, 0x05);
    DUW_TEST(0, 0xFFFFFFFE, next_hi, next_lo, window, 1, 0, 0, 0x07);
    DUW_TEST(1, 3, next_hi, next_lo, window, 1, 4, 0, 0x71);
    DUW_TEST(1, 0, next_hi, next_lo, window, 1, 4, 0, 0x79);
    DUW_TEST(1, 0xFFFFFFFF, next_hi, next_lo, window, 2, 0, 0, 0x01);
    DUW_TEST(2, 3, next_hi, next_lo, window, 2, 4, 0, 0x11);
    DUW_TEST(2, 0, next_hi, next_lo, window, 2, 4, 0, 0x19);
    DUW_TEST(2, 25, next_hi, next_lo, window, 2, 26, 0, 0x6400001);
    DUW_TEST(2, 27, next_hi, next_lo, window, 2, 28, 0, 0x19000005);
    DUW_TEST(2, 29, next_hi, next_lo, window, 2, 30, 0, 0x64000015);
    DUW_TEST(2, 33, next_hi, next_lo, window, 2, 34, 6, 0x40000151);
    DUW_TEST(2, 60, next_hi, next_lo, window, 2, 61, 0x3200000A, 0x88000001);
    DUW_TEST(1, 0xFFFFFFF0, next_hi, next_lo, window, 2, 61, 0x3200000A, 0x88000001);
    DUW_TEST(2, 0xFFFFFFFD, next_hi, next_lo, window, 2, 0xFFFFFFFE, 0, 0x01);
    DUW_TEST(3, 1, next_hi, next_lo, window, 3, 2, 0, 0x11);
    DUW_TEST(99, 66, next_hi, next_lo, window, 99, 67, 0, 0x01);
    DUW_TEST(50, 66, next_hi, next_lo, window, 99, 67, 0, 0x01);
    DUW_TEST(100, 68, next_hi, next_lo, window, 100, 69, 0, 0x01);
    DUW_TEST(99, 50, next_hi, next_lo, window, 100, 69, 0, 0x01);
    DUW_TEST(99, 0xFFFFFFFF, next_hi, next_lo, window, 100, 69, 0, 0x01);
    DUW_TEST(150, 0xFFFFFFFF, next_hi, next_lo, window, 151, 0, 0, 0x01);
    DUW_TEST(152, 0xFFFFFFFF, next_hi, next_lo, window, 153, 0, 0, 0x01);

    return EXPECT_RESULT();
}
#else
int test_wolfSSL_DtlsUpdateWindow(void)
{
    return TEST_SKIPPED;
}
#endif /* WOLFSSL_DTLS */

#ifdef WOLFSSL_DTLS
static int DFB_TEST(WOLFSSL* ssl, word32 seq, word32 len, word32 f_offset,
        word32 f_len, word32 f_count, byte ready, word32 bytesReceived)
{
    EXPECT_DECLS;
    DtlsMsg* cur = NULL;
    static byte msg[100];
    static byte msgInit = 0;

    if (!msgInit) {
        int i;
        for (i = 0; i < 100; i++)
            msg[i] = i + 1;
        msgInit = 1;
    }

    /* Sanitize test parameters */
    ExpectIntLE(len, sizeof(msg));
    ExpectIntLE(f_offset + f_len, sizeof(msg));

    if (EXPECT_SUCCESS())
        DtlsMsgStore(ssl, 0, seq, msg + f_offset, len, certificate, f_offset, f_len, NULL);

    ExpectNotNull(ssl->dtls_rx_msg_list);

    ExpectNotNull(cur = DtlsMsgFind(ssl->dtls_rx_msg_list, 0, seq));
    ExpectIntEQ(cur->fragBucketListCount, f_count);
    ExpectIntEQ(cur->ready, ready);
    ExpectIntEQ(cur->bytesReceived, bytesReceived);
    if (ready) {
        ExpectNull(cur->fragBucketList);
        ExpectBufEQ(cur->fullMsg, msg, cur->sz);
    }
    else {
        DtlsFragBucket* fb;
        ExpectNotNull(cur->fragBucketList);
        for (fb = cur != NULL ? cur->fragBucketList : NULL;
                EXPECT_SUCCESS() && fb != NULL; fb = fb->m.m.next)
            ExpectBufEQ(fb->buf, msg + fb->m.m.offset, fb->m.m.sz);
    }
    if (EXPECT_FAIL()) {
        printf("Test parameters: seq %u len %u f_offset %u f_len %u f_count %u ready %u bytesReceived %u\n",
                                 seq, len, f_offset, f_len, f_count, ready, bytesReceived);
    }
    return EXPECT_RESULT();
}

int test_wolfSSL_DTLS_fragment_buckets(void)
{
    EXPECT_DECLS;
    WOLFSSL ssl[1];

    XMEMSET(ssl, 0, sizeof(*ssl));

    EXPECT_TEST(DFB_TEST(ssl, 0, 100, 0, 100, 0, 1, 100)); /*  0-100 */

    EXPECT_TEST(DFB_TEST(ssl, 1, 100,  0, 20, 1, 0,  20)); /*  0-20  */
    EXPECT_TEST(DFB_TEST(ssl, 1, 100, 20, 20, 1, 0,  40)); /* 20-40  */
    EXPECT_TEST(DFB_TEST(ssl, 1, 100, 40, 20, 1, 0,  60)); /* 40-60  */
    EXPECT_TEST(DFB_TEST(ssl, 1, 100, 60, 20, 1, 0,  80)); /* 60-80  */
    EXPECT_TEST(DFB_TEST(ssl, 1, 100, 80, 20, 0, 1, 100)); /* 80-100 */

    /* Test all permutations of 3 regions */
    /* 1 2 3 */
    EXPECT_TEST(DFB_TEST(ssl, 2, 100,  0, 30, 1, 0,  30)); /*  0-30  */
    EXPECT_TEST(DFB_TEST(ssl, 2, 100, 30, 30, 1, 0,  60)); /* 30-60  */
    EXPECT_TEST(DFB_TEST(ssl, 2, 100, 60, 40, 0, 1, 100)); /* 60-100 */
    /* 1 3 2 */
    EXPECT_TEST(DFB_TEST(ssl, 3, 100,  0, 30, 1, 0,  30)); /*  0-30  */
    EXPECT_TEST(DFB_TEST(ssl, 3, 100, 60, 40, 2, 0,  70)); /* 60-100 */
    EXPECT_TEST(DFB_TEST(ssl, 3, 100, 30, 30, 0, 1, 100)); /* 30-60  */
    /* 2 1 3 */
    EXPECT_TEST(DFB_TEST(ssl, 4, 100, 30, 30, 1, 0,  30)); /* 30-60  */
    EXPECT_TEST(DFB_TEST(ssl, 4, 100,  0, 30, 1, 0,  60)); /*  0-30  */
    EXPECT_TEST(DFB_TEST(ssl, 4, 100, 60, 40, 0, 1, 100)); /* 60-100 */
    /* 2 3 1 */
    EXPECT_TEST(DFB_TEST(ssl, 5, 100, 30, 30, 1, 0,  30)); /* 30-60  */
    EXPECT_TEST(DFB_TEST(ssl, 5, 100, 60, 40, 1, 0,  70)); /* 60-100 */
    EXPECT_TEST(DFB_TEST(ssl, 5, 100,  0, 30, 0, 1, 100)); /*  0-30  */
    /* 3 1 2 */
    EXPECT_TEST(DFB_TEST(ssl, 6, 100, 60, 40, 1, 0,  40)); /* 60-100 */
    EXPECT_TEST(DFB_TEST(ssl, 6, 100,  0, 30, 2, 0,  70)); /*  0-30  */
    EXPECT_TEST(DFB_TEST(ssl, 6, 100, 30, 30, 0, 1, 100)); /* 30-60  */
    /* 3 2 1 */
    EXPECT_TEST(DFB_TEST(ssl, 7, 100, 60, 40, 1, 0,  40)); /* 60-100 */
    EXPECT_TEST(DFB_TEST(ssl, 7, 100, 30, 30, 1, 0,  70)); /* 30-60  */
    EXPECT_TEST(DFB_TEST(ssl, 7, 100,  0, 30, 0, 1, 100)); /*  0-30  */

    /* Test overlapping regions */
    EXPECT_TEST(DFB_TEST(ssl, 8, 100,  0, 30, 1, 0,  30)); /*  0-30  */
    EXPECT_TEST(DFB_TEST(ssl, 8, 100, 20, 10, 1, 0,  30)); /* 20-30  */
    EXPECT_TEST(DFB_TEST(ssl, 8, 100, 70, 10, 2, 0,  40)); /* 70-80  */
    EXPECT_TEST(DFB_TEST(ssl, 8, 100, 20, 30, 2, 0,  60)); /* 20-50  */
    EXPECT_TEST(DFB_TEST(ssl, 8, 100, 40, 60, 0, 1, 100)); /* 40-100 */

    /* Test overlapping multiple regions */
    EXPECT_TEST(DFB_TEST(ssl, 9, 100,  0, 20, 1, 0,  20)); /*  0-20  */
    EXPECT_TEST(DFB_TEST(ssl, 9, 100, 30,  5, 2, 0,  25)); /* 30-35  */
    EXPECT_TEST(DFB_TEST(ssl, 9, 100, 40,  5, 3, 0,  30)); /* 40-45  */
    EXPECT_TEST(DFB_TEST(ssl, 9, 100, 50,  5, 4, 0,  35)); /* 50-55  */
    EXPECT_TEST(DFB_TEST(ssl, 9, 100, 60,  5, 5, 0,  40)); /* 60-65  */
    EXPECT_TEST(DFB_TEST(ssl, 9, 100, 70,  5, 6, 0,  45)); /* 70-75  */
    EXPECT_TEST(DFB_TEST(ssl, 9, 100, 30, 25, 4, 0,  55)); /* 30-55  */
    EXPECT_TEST(DFB_TEST(ssl, 9, 100, 55, 15, 2, 0,  65)); /* 55-70  */
    EXPECT_TEST(DFB_TEST(ssl, 9, 100, 75, 25, 2, 0,  90)); /* 75-100 */
    EXPECT_TEST(DFB_TEST(ssl, 9, 100, 10, 25, 0, 1, 100)); /* 10-35 */

    EXPECT_TEST(DFB_TEST(ssl,10, 100,  0, 20, 1, 0,  20)); /*  0-20  */
    EXPECT_TEST(DFB_TEST(ssl,10, 100, 30, 20, 2, 0,  40)); /* 30-50  */
    EXPECT_TEST(DFB_TEST(ssl,10, 100,  0, 40, 1, 0,  50)); /*  0-40  */
    EXPECT_TEST(DFB_TEST(ssl,10, 100, 50, 50, 0, 1, 100)); /* 50-100 */

    /* Test region between other regions */
    EXPECT_TEST(DFB_TEST(ssl,11, 100,  0, 20, 1, 0,  20)); /*  0-20  */
    EXPECT_TEST(DFB_TEST(ssl,11, 100, 80, 20, 2, 0,  40)); /* 80-100 */
    EXPECT_TEST(DFB_TEST(ssl,11, 100, 40, 20, 3, 0,  60)); /* 40-60  */
    EXPECT_TEST(DFB_TEST(ssl,11, 100, 20, 20, 2, 0,  80)); /* 20-40  */
    EXPECT_TEST(DFB_TEST(ssl,11, 100, 60, 20, 0, 1, 100)); /* 60-80  */

    /* Test gap before first bucket (prev==NULL in gap-before branch) */
    EXPECT_TEST(DFB_TEST(ssl,12, 100, 50, 20, 1, 0,  20)); /* 50-70  */
    EXPECT_TEST(DFB_TEST(ssl,12, 100,  0, 20, 2, 0,  40)); /*  0-20  gap before first */
    EXPECT_TEST(DFB_TEST(ssl,12, 100, 20, 30, 1, 0,  70)); /* 20-50  bridges gap */
    EXPECT_TEST(DFB_TEST(ssl,12, 100, 70, 30, 0, 1, 100)); /* 70-100 */

    /* Test fragment after message is already complete (ready early return) */
    EXPECT_TEST(DFB_TEST(ssl,13, 100,  0,100, 0, 1, 100)); /*  0-100 complete */
    EXPECT_TEST(DFB_TEST(ssl,13, 100,  0, 50, 0, 1, 100)); /*  0-50  dup on ready */

    /* Test combine where next bucket is larger than cur (chosenBucket=&next) */
    EXPECT_TEST(DFB_TEST(ssl,14, 100,  0, 10, 1, 0,  10)); /*  0-10  */
    EXPECT_TEST(DFB_TEST(ssl,14, 100, 30, 50, 2, 0,  60)); /* 30-80  */
    EXPECT_TEST(DFB_TEST(ssl,14, 100,  5, 30, 1, 0,  80)); /*  5-35  next>cur */
    EXPECT_TEST(DFB_TEST(ssl,14, 100, 80, 20, 0, 1, 100)); /* 80-100 */

    /* Test super fragment covering all existing buckets */
    EXPECT_TEST(DFB_TEST(ssl,15, 100, 10, 10, 1, 0,  10)); /* 10-20  */
    EXPECT_TEST(DFB_TEST(ssl,15, 100, 30, 10, 2, 0,  20)); /* 30-40  */
    EXPECT_TEST(DFB_TEST(ssl,15, 100, 60, 10, 3, 0,  30)); /* 60-70  */
    EXPECT_TEST(DFB_TEST(ssl,15, 100,  0,100, 0, 1, 100)); /*  0-100 super frag */

    /* Test exact duplicate fragment */
    EXPECT_TEST(DFB_TEST(ssl,16, 100, 20, 40, 1, 0,  40)); /* 20-60  */
    EXPECT_TEST(DFB_TEST(ssl,16, 100, 20, 40, 1, 0,  40)); /* 20-60  exact dup */
    EXPECT_TEST(DFB_TEST(ssl,16, 100,  0, 20, 1, 0,  60)); /*  0-20  */
    EXPECT_TEST(DFB_TEST(ssl,16, 100, 60, 40, 0, 1, 100)); /* 60-100 */

    /* Test combine bridging two buckets (combineNext, cur->data) */
    EXPECT_TEST(DFB_TEST(ssl,17, 100,  0, 30, 1, 0,  30)); /*  0-30  */
    EXPECT_TEST(DFB_TEST(ssl,17, 100, 60, 20, 2, 0,  50)); /* 60-80  */
    EXPECT_TEST(DFB_TEST(ssl,17, 100, 20, 45, 1, 0,  80)); /* 20-65  bridge */
    EXPECT_TEST(DFB_TEST(ssl,17, 100, 80, 20, 0, 1, 100)); /* 80-100 */

    /* Test progressive left-extension with partial overlaps */
    EXPECT_TEST(DFB_TEST(ssl,18, 100, 70, 30, 1, 0,  30)); /* 70-100 */
    EXPECT_TEST(DFB_TEST(ssl,18, 100, 50, 30, 1, 0,  50)); /* 50-80  extend left */
    EXPECT_TEST(DFB_TEST(ssl,18, 100, 30, 30, 1, 0,  70)); /* 30-60  extend left */
    EXPECT_TEST(DFB_TEST(ssl,18, 100,  0, 40, 0, 1, 100)); /*  0-40  complete left */

    DtlsMsgListDelete(ssl->dtls_rx_msg_list, ssl->heap);
    ssl->dtls_rx_msg_list = NULL;
    ssl->dtls_rx_msg_list_sz = 0;
    return EXPECT_RESULT();
}

#else
int test_wolfSSL_DTLS_fragment_buckets(void)
{
    return TEST_SKIPPED;
}
#endif


#if !defined(NO_FILESYSTEM) && \
     defined(WOLFSSL_DTLS) && !defined(WOLFSSL_NO_TLS12) && \
     defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && !defined(NO_RSA)

int test_wolfSSL_dtls_stateless2(void)
{
    EXPECT_DECLS;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_c2 = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method), 0);
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, NULL, &ssl_c2, NULL,
        wolfDTLSv1_2_client_method, NULL), 0);
    ExpectFalse(wolfSSL_is_stateful(ssl_s));
    /* send CH */
    ExpectTrue((wolfSSL_connect(ssl_c2) == WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)) &&
        (ssl_c2->error == WC_NO_ERR_TRACE(WANT_READ)));
    ExpectIntEQ(wolfDTLS_accept_stateless(ssl_s), WOLFSSL_FAILURE);
    ExpectFalse(wolfSSL_is_stateful(ssl_s));
    ExpectIntNE(test_ctx.c_len, 0);
    /* consume HRR */
    test_memio_clear_buffer(&test_ctx, 1);
    /* send CH1 */
    ExpectIntEQ(wolfSSL_connect(ssl_c), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WOLFSSL_FATAL_ERROR),
            WOLFSSL_ERROR_WANT_READ);
    /* send HRR */
    ExpectIntEQ(wolfDTLS_accept_stateless(ssl_s), WOLFSSL_FAILURE);
    /* send CH2 */
    ExpectIntEQ(wolfSSL_connect(ssl_c), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WOLFSSL_FATAL_ERROR),
            WOLFSSL_ERROR_WANT_READ);
    /* send HRR */
    ExpectIntEQ(wolfDTLS_accept_stateless(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectTrue(wolfSSL_is_stateful(ssl_s));

    wolfSSL_free(ssl_c2);
    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
    return EXPECT_RESULT();
}

int test_wolfSSL_dtls_stateless_maxfrag(void)
{
    EXPECT_DECLS;
#ifdef HAVE_MAX_FRAGMENT
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_c2 = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    word16 max_fragment = 0;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method), 0);
    ExpectNotNull(ssl_s);
    ExpectNotNull(ssl_c2 = wolfSSL_new(ctx_c));
    ExpectIntEQ(wolfSSL_UseMaxFragment(ssl_c2, WOLFSSL_MFL_2_8),
        WOLFSSL_SUCCESS);
    wolfSSL_SetIOWriteCtx(ssl_c2, &test_ctx);
    wolfSSL_SetIOReadCtx(ssl_c2, &test_ctx);
    if (EXPECT_SUCCESS()) {
        max_fragment = ssl_s->max_fragment;
    }
    /* send CH */
    ExpectTrue((wolfSSL_connect(ssl_c2) == WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)) &&
        (ssl_c2->error == WC_NO_ERR_TRACE(WANT_READ)));
    ExpectTrue((wolfSSL_accept(ssl_s) == WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)) &&
        (ssl_s->error == WC_NO_ERR_TRACE(WANT_READ)));
    /* CH without cookie shouldn't change state */
    ExpectIntEQ(ssl_s->max_fragment, max_fragment);
    ExpectIntNE(test_ctx.c_len, 0);

    /* consume HRR from buffer */
    test_memio_clear_buffer(&test_ctx, 1);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_c2);
    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif /* HAVE_MAX_FRAGMENT */
    return EXPECT_RESULT();
}

#if defined(WOLFSSL_DTLS_NO_HVR_ON_RESUME)
#define ROUNDS_WITH_HVR 4
#define ROUNDS_WITHOUT_HVR 2
#define HANDSHAKE_TYPE_OFFSET DTLS_RECORD_HEADER_SZ
static int buf_is_hvr(const byte *data, int len)
{
    if (len < DTLS_RECORD_HEADER_SZ + DTLS_HANDSHAKE_HEADER_SZ)
        return 0;
    return data[HANDSHAKE_TYPE_OFFSET] == hello_verify_request;
}

static int _test_wolfSSL_dtls_stateless_resume(byte useticket, byte bad)
{
    EXPECT_DECLS;
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    WOLFSSL_SESSION *sess = NULL;
    int round_trips;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c,
        &ssl_s, wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method), 0);
#ifdef HAVE_SESSION_TICKET
    if (useticket) {
        ExpectIntEQ(wolfSSL_UseSessionTicket(ssl_c), WOLFSSL_SUCCESS);
    }
#endif
    round_trips = ROUNDS_WITH_HVR;
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, round_trips,
        &round_trips), 0);
    ExpectIntEQ(round_trips, ROUNDS_WITH_HVR);
    ExpectNotNull(sess = wolfSSL_get1_session(ssl_c));
    wolfSSL_shutdown(ssl_c);
    wolfSSL_shutdown(ssl_s);
    wolfSSL_free(ssl_c);
    ssl_c = NULL;
    wolfSSL_free(ssl_s);
    ssl_s = NULL;

    test_memio_clear_buffer(&test_ctx, 1);
    test_memio_clear_buffer(&test_ctx, 0);
    /* make resumption invalid */
    if (bad && (sess != NULL)) {
        if (useticket) {
#ifdef HAVE_SESSION_TICKET
            if (sess->ticket != NULL) {
                sess->ticket[0] = !sess->ticket[0];
            }
#endif /* HAVE_SESSION_TICKET */
        }
        else {
            sess->sessionID[0] = !sess->sessionID[0];
        }
    }
    ExpectNotNull(ssl_c = wolfSSL_new(ctx_c));
    ExpectNotNull(ssl_s = wolfSSL_new(ctx_s));
    wolfSSL_SetIOWriteCtx(ssl_c, &test_ctx);
    wolfSSL_SetIOReadCtx(ssl_c, &test_ctx);
    wolfSSL_SetIOWriteCtx(ssl_s, &test_ctx);
    wolfSSL_SetIOReadCtx(ssl_s, &test_ctx);
    ExpectIntEQ(wolfSSL_set_session(ssl_c, sess), WOLFSSL_SUCCESS);
    ExpectTrue((wolfSSL_connect(ssl_c) == WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)) &&
        (ssl_c->error == WC_NO_ERR_TRACE(WANT_READ)));
    ExpectTrue((wolfSSL_accept(ssl_s) == WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)) &&
        (ssl_s->error == WC_NO_ERR_TRACE(WANT_READ)));
    ExpectFalse(bad && !buf_is_hvr(test_ctx.c_buff, test_ctx.c_len));
    ExpectFalse(!bad && buf_is_hvr(test_ctx.c_buff, test_ctx.c_len));
    if (!useticket) {
        ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, &round_trips), 0);
        ExpectFalse(bad && round_trips != ROUNDS_WITH_HVR - 1);
        ExpectFalse(!bad && round_trips != ROUNDS_WITHOUT_HVR - 1);
    }
    wolfSSL_SESSION_free(sess);
    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
    return EXPECT_RESULT();
}

int test_wolfSSL_dtls_stateless_resume(void)
{
    EXPECT_DECLS;
#ifdef HAVE_SESSION_TICKET
    ExpectIntEQ(_test_wolfSSL_dtls_stateless_resume(1, 0), TEST_SUCCESS);
    ExpectIntEQ(_test_wolfSSL_dtls_stateless_resume(1, 1), TEST_SUCCESS);
#endif /* HAVE_SESION_TICKET */
    ExpectIntEQ(_test_wolfSSL_dtls_stateless_resume(0, 0), TEST_SUCCESS);
    ExpectIntEQ(_test_wolfSSL_dtls_stateless_resume(0, 1), TEST_SUCCESS);
    return EXPECT_RESULT();
}
#else
int test_wolfSSL_dtls_stateless_resume(void)
{
    return TEST_SKIPPED;
}
#endif /* WOLFSSL_DTLS_NO_HVR_ON_RESUME */

int test_wolfSSL_dtls_stateless_downgrade(void)
{
    EXPECT_DECLS;
#if !defined(NO_OLD_TLS)
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_c2 = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_c2 = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method), 0);
    ExpectIntEQ(wolfSSL_CTX_SetMinVersion(ctx_s, WOLFSSL_DTLSV1),
        WOLFSSL_SUCCESS);
    ExpectNotNull(ctx_c2 = wolfSSL_CTX_new(wolfDTLSv1_client_method()));
    wolfSSL_SetIORecv(ctx_c2, test_memio_read_cb);
    wolfSSL_SetIOSend(ctx_c2, test_memio_write_cb);
    ExpectNotNull(ssl_c2 = wolfSSL_new(ctx_c2));
    wolfSSL_SetIOWriteCtx(ssl_c2, &test_ctx);
    wolfSSL_SetIOReadCtx(ssl_c2, &test_ctx);
    /* send CH */
    ExpectTrue((wolfSSL_connect(ssl_c2) == WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)) &&
        (ssl_c2->error == WC_NO_ERR_TRACE(WANT_READ)));
    ExpectTrue((wolfSSL_accept(ssl_s) == WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)) &&
        (ssl_s->error == WC_NO_ERR_TRACE(WANT_READ)));
    ExpectIntNE(test_ctx.c_len, 0);
    /* consume HRR */
    test_memio_clear_buffer(&test_ctx, 1);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_c2);
    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_c2);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

#else /* outer wrap: WOLFSSL_DTLS && !WOLFSSL_NO_TLS12 && client/server && !NO_RSA */
int test_wolfSSL_dtls_stateless2(void)
{
    return TEST_SKIPPED;
}
int test_wolfSSL_dtls_stateless_maxfrag(void)
{
    return TEST_SKIPPED;
}
int test_wolfSSL_dtls_stateless_resume(void)
{
    return TEST_SKIPPED;
}
int test_wolfSSL_dtls_stateless_downgrade(void)
{
    return TEST_SKIPPED;
}
#endif /* defined(WOLFSSL_DTLS) && !defined(WOLFSSL_NO_TLS12) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER)*/

#if defined(WOLFSSL_DTLS) && !defined(WOLFSSL_NO_TLS12) && \
    !defined(NO_OLD_TLS) && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES)
int test_WOLFSSL_dtls_version_alert(void)
{
    EXPECT_DECLS;
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_2_client_method, wolfDTLSv1_server_method), 0);

    /* client hello */
    ExpectTrue((wolfSSL_connect(ssl_c) == WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)) &&
        (ssl_c->error == WC_NO_ERR_TRACE(WANT_READ)));
    /* hrr */
    ExpectTrue((wolfSSL_accept(ssl_s) == WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)) &&
        (ssl_s->error == WC_NO_ERR_TRACE(WANT_READ)));
    /* client hello 1 */
    ExpectTrue((wolfSSL_connect(ssl_c) == WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)) &&
        (ssl_c->error == WC_NO_ERR_TRACE(WANT_READ)));
    /* server hello */
    ExpectTrue((wolfSSL_accept(ssl_s) == WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)) &&
        (ssl_s->error == WC_NO_ERR_TRACE(WANT_READ)));
    /* should fail */
    ExpectTrue((wolfSSL_connect(ssl_c) == WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)) &&
        (ssl_c->error == WC_NO_ERR_TRACE(VERSION_ERROR)));
    /* shuould fail */
    ExpectTrue((wolfSSL_accept(ssl_s) == WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)) &&
        (ssl_s->error == WC_NO_ERR_TRACE(VERSION_ERROR) || ssl_s->error == WC_NO_ERR_TRACE(FATAL_ERROR)));

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);

    return EXPECT_RESULT();
}
#else
int test_WOLFSSL_dtls_version_alert(void)
{
    return TEST_SKIPPED;
}
#endif /* defined(WOLFSSL_DTLS) && !defined(WOLFSSL_NO_TLS12) &&
        * !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) &&
        * !defined(NO_OLD_TLS) && !defined(NO_RSA)
        */

/*----------------------------------------------------------------------------*/
/* Remaining DTLS tests moved out of api.c (msg, ipv6, downgrade, ccs, etc.)  */
/*----------------------------------------------------------------------------*/

/*-- msg_helpers_and_from_other_peer (api.c lines 30572,30671) ---*/
#if defined(WOLFSSL_DTLS) && !defined(WOLFSSL_NO_TLS12) &&          \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) &&   \
    !defined(SINGLE_THREADED) && !defined(NO_RSA)

static int test_dtls_msg_get_connected_port(int fd, word16 *port)
{
    SOCKADDR_S peer;
    XSOCKLENT len;
    int ret;

    XMEMSET((byte*)&peer, 0, sizeof(peer));
    len = sizeof(peer);
    ret = getpeername(fd,  (SOCKADDR*)&peer, &len);
    if (ret != 0 || len > (XSOCKLENT)sizeof(peer))
        return -1;
    switch (peer.ss_family) {
#ifdef WOLFSSL_IPV6
    case WOLFSSL_IP6: {
        *port = ntohs(((SOCKADDR_IN6*)&peer)->sin6_port);
        break;
    }
#endif /* WOLFSSL_IPV6 */
    case WOLFSSL_IP4:
        *port = ntohs(((SOCKADDR_IN*)&peer)->sin_port);
        break;
    default:
        return -1;
    }
    return 0;
}

static int test_dtls_msg_from_other_peer_cb(WOLFSSL_CTX *ctx, WOLFSSL *ssl)
{
    char buf[1] = {'t'};
    SOCKADDR_IN_T addr;
    int sock_fd;
    word16 port;
    int err;

    (void)ssl;
    (void)ctx;

    if (ssl == NULL)
        return -1;

    err = test_dtls_msg_get_connected_port(wolfSSL_get_fd(ssl), &port);
    if (err != 0)
        return -1;

    sock_fd = socket(AF_INET_V, SOCK_DGRAM, 0);
    if (sock_fd == -1)
        return -1;
    build_addr(&addr, wolfSSLIP, port, 1, 0);

    /* send a packet to the server. Being another socket, the kernel will ensure
     * the source port will be different. */
    err = (int)sendto(sock_fd, buf, sizeof(buf), 0, (SOCKADDR*)&addr,
        sizeof(addr));

    close(sock_fd);
    if (err == -1)
        return -1;

    return 0;
}

/* setup a SSL session but just after the handshake send a packet to the server
 * with a source address different than the one of the connected client. The I/O
 * callback EmbedRecvFrom should just ignore the packet. Sending of the packet
 * is done in test_dtls_msg_from_other_peer_cb */
int test_dtls_msg_from_other_peer(void)
{
    EXPECT_DECLS;
    callback_functions client_cbs;
    callback_functions server_cbs;

    XMEMSET((byte*)&client_cbs, 0, sizeof(client_cbs));
    XMEMSET((byte*)&server_cbs, 0, sizeof(server_cbs));

    client_cbs.method = wolfDTLSv1_2_client_method;
    server_cbs.method = wolfDTLSv1_2_server_method;
    client_cbs.doUdp = 1;
    server_cbs.doUdp = 1;

    test_wolfSSL_client_server_nofail_ex(&client_cbs, &server_cbs,
        test_dtls_msg_from_other_peer_cb);

    ExpectIntEQ(client_cbs.return_code, WOLFSSL_SUCCESS);
    ExpectIntEQ(server_cbs.return_code, WOLFSSL_SUCCESS);

    return EXPECT_RESULT();
}
#else
int test_dtls_msg_from_other_peer(void)
{
    return TEST_SKIPPED;
}
#endif /* defined(WOLFSSL_DTLS) && !defined(WOLFSSL_NO_TLS12) &&          \
        *  !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) &&  \
        *  !defined(SINGLE_THREADED) && !defined(NO_RSA) */

/*-- ipv6_check (api.c lines 30672,30730) ---*/
#if defined(WOLFSSL_DTLS) && !defined(WOLFSSL_IPV6) &&               \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) &&   \
    defined(HAVE_IO_TESTS_DEPENDENCIES) && !defined(WOLFSSL_NO_TLS12) \
    && !defined(USE_WINDOWS_API)
int test_dtls_ipv6_check(void)
{
    EXPECT_DECLS;
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    SOCKADDR_IN fake_addr6;
    int sockfd = -1;

    ExpectNotNull(ctx_c = wolfSSL_CTX_new(wolfDTLSv1_2_client_method()));
    ExpectNotNull(ssl_c  = wolfSSL_new(ctx_c));
    ExpectNotNull(ctx_s = wolfSSL_CTX_new(wolfDTLSv1_2_server_method()));
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx_s, svrKeyFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_certificate_file(ctx_s, svrCertFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectNotNull(ssl_s  = wolfSSL_new(ctx_s));
    XMEMSET((byte*)&fake_addr6, 0, sizeof(fake_addr6));
    /* mimic a sockaddr_in6 struct, this way we can't test without
     *  WOLFSSL_IPV6 */
    fake_addr6.sin_family = WOLFSSL_IP6;
    ExpectIntNE(sockfd = socket(AF_INET, SOCK_DGRAM, 0), -1);
    ExpectIntEQ(wolfSSL_set_fd(ssl_c, sockfd), WOLFSSL_SUCCESS);
    /* can't return error here, as the peer is opaque for wolfssl library at
     * this point */
    ExpectIntEQ(wolfSSL_dtls_set_peer(ssl_c, &fake_addr6, sizeof(fake_addr6)),
        WOLFSSL_SUCCESS);
    ExpectIntNE(fcntl(sockfd, F_SETFL, O_NONBLOCK), -1);
    wolfSSL_dtls_set_using_nonblock(ssl_c, 1);
    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(ssl_c->error, WC_NO_ERR_TRACE(SOCKET_ERROR_E));

    ExpectIntEQ(wolfSSL_dtls_set_peer(ssl_s, &fake_addr6, sizeof(fake_addr6)),
        WOLFSSL_SUCCESS);
    /* reuse the socket */
    ExpectIntEQ(wolfSSL_set_fd(ssl_c, sockfd), WOLFSSL_SUCCESS);
    wolfSSL_dtls_set_using_nonblock(ssl_s, 1);
    ExpectIntNE(wolfSSL_accept(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(ssl_s->error, WC_NO_ERR_TRACE(SOCKET_ERROR_E));
    if (sockfd != -1)
        close(sockfd);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
    return EXPECT_RESULT();
}
#else
int test_dtls_ipv6_check(void)
{
    return TEST_SKIPPED;
}
#endif

/*-- no_extensions (api.c lines 30824,30913) ---*/
int test_dtls_no_extensions(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_DTLS) && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(WOLFSSL_NO_TLS12)
    WOLFSSL *ssl_s = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    struct test_memio_ctx test_ctx;
    const byte chNoExtensions[] = {
        /* Handshake type */
        0x16,
        /* Version */
        0xfe, 0xff,
        /* Epoch */
        0x00, 0x00,
        /* Seq number */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        /* Length */
        0x00, 0x40,
        /* CH type */
        0x01,
        /* Length */
        0x00, 0x00, 0x34,
        /* Msg Seq */
        0x00, 0x00,
        /* Frag offset */
        0x00, 0x00, 0x00,
        /* Frag length */
        0x00, 0x00, 0x34,
        /* Version */
        0xfe, 0xff,
        /* Random */
        0x62, 0xfe, 0xbc, 0xfe, 0x2b, 0xfe, 0x3f, 0xeb, 0x03, 0xc4, 0xea, 0x37,
        0xe7, 0x47, 0x7e, 0x8a, 0xd9, 0xbf, 0x77, 0x0f, 0x6c, 0xb6, 0x77, 0x0b,
        0x03, 0x3f, 0x82, 0x2b, 0x21, 0x64, 0x57, 0x1d,
        /* Session Length */
        0x00,
        /* Cookie Length */
        0x00,
        /* CS Length */
        0x00, 0x0c,
        /* CS */
        0xc0, 0x0a, 0xc0, 0x09, 0xc0, 0x14, 0xc0, 0x13, 0x00, 0x39, 0x00, 0x33,
        /* Comp Meths Length */
        0x01,
        /* Comp Meths */
        0x00
        /* And finally... no extensions */
    };
    int i;
#ifdef OPENSSL_EXTRA
    int repeats = 2;
#else
    int repeats = 1;
#endif

    for (i = 0; i < repeats; i++) {
        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        ssl_s = NULL;
        ctx_s = NULL;

        ExpectIntEQ(test_memio_setup(&test_ctx, NULL, &ctx_s, NULL, &ssl_s,
            NULL, wolfDTLS_server_method), 0);

        test_memio_clear_buffer(&test_ctx, 0);
        ExpectIntEQ(
            test_memio_inject_message(&test_ctx, 1,
                (const char *)chNoExtensions, sizeof(chNoExtensions)), 0);


#ifdef OPENSSL_EXTRA
        if (i > 0) {
            ExpectIntEQ(wolfSSL_set_max_proto_version(ssl_s, DTLS1_2_VERSION),
                        WOLFSSL_SUCCESS);
        }
#endif

        ExpectIntEQ(wolfSSL_accept(ssl_s), -1);
        ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);

        /* Expecting a handshake msg. Either HVR or SH. */
        ExpectIntGT(test_ctx.c_len, 0);
        ExpectIntEQ(test_ctx.c_buff[0], 0x16);

        wolfSSL_free(ssl_s);
        wolfSSL_CTX_free(ctx_s);
    }
#endif
    return EXPECT_RESULT();
}

/*-- dtls_1_0_hvr_downgrade (api.c lines 31038,31073) ---*/
#if defined(WOLFSSL_DTLS) && !defined(WOLFSSL_NO_TLS12) && \
    defined(HAVE_IO_TESTS_DEPENDENCIES)
static void test_dtls_1_0_hvr_downgrade_ctx_ready(WOLFSSL_CTX* ctx)
{
    AssertIntEQ(wolfSSL_CTX_SetMinVersion(ctx, WOLFSSL_DTLSV1_2),
                WOLFSSL_SUCCESS);
}

int test_dtls_1_0_hvr_downgrade(void)
{
    EXPECT_DECLS;
    callback_functions func_cb_client;
    callback_functions func_cb_server;

    XMEMSET(&func_cb_client, 0, sizeof(callback_functions));
    XMEMSET(&func_cb_server, 0, sizeof(callback_functions));

    func_cb_client.doUdp = func_cb_server.doUdp = 1;
    func_cb_client.method = wolfDTLS_client_method;
    func_cb_server.method = wolfDTLSv1_2_server_method;
    func_cb_client.ctx_ready = test_dtls_1_0_hvr_downgrade_ctx_ready;

    test_wolfSSL_client_server_nofail(&func_cb_client, &func_cb_server);

    ExpectIntEQ(func_cb_client.return_code, TEST_SUCCESS);
    ExpectIntEQ(func_cb_server.return_code, TEST_SUCCESS);

    return EXPECT_RESULT();
}
#else
int test_dtls_1_0_hvr_downgrade(void)
{
    EXPECT_DECLS;
    return EXPECT_RESULT();
}
#endif

/*-- downgrade_scr_server (api.c lines 31230,31293) ---*/
#if defined(WOLFSSL_DTLS) && !defined(WOLFSSL_NO_TLS12) && \
    defined(HAVE_IO_TESTS_DEPENDENCIES) && defined(HAVE_SECURE_RENEGOTIATION)
static void test_dtls_downgrade_scr_server_ctx_ready_server(WOLFSSL_CTX* ctx)
{
    AssertIntEQ(wolfSSL_CTX_SetMinVersion(ctx, WOLFSSL_DTLSV1_2),
                WOLFSSL_SUCCESS);
    AssertIntEQ(wolfSSL_CTX_UseSecureRenegotiation(ctx), WOLFSSL_SUCCESS);
}

static void test_dtls_downgrade_scr_server_ctx_ready(WOLFSSL_CTX* ctx)
{
    AssertIntEQ(wolfSSL_CTX_UseSecureRenegotiation(ctx), WOLFSSL_SUCCESS);
}

static void test_dtls_downgrade_scr_server_on_result(WOLFSSL* ssl)
{
    char testMsg[] = "Message after SCR";
    char msgBuf[sizeof(testMsg)];
    if (wolfSSL_is_server(ssl)) {
        AssertIntEQ(wolfSSL_Rehandshake(ssl), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
        AssertIntEQ(wolfSSL_get_error(ssl, -1), WC_NO_ERR_TRACE(APP_DATA_READY));
        AssertIntEQ(wolfSSL_read(ssl, msgBuf, sizeof(msgBuf)), sizeof(msgBuf));
        AssertIntEQ(wolfSSL_Rehandshake(ssl), WOLFSSL_SUCCESS);
        AssertIntEQ(wolfSSL_write(ssl, testMsg, sizeof(testMsg)),
                    sizeof(testMsg));
    }
    else {
        AssertIntEQ(wolfSSL_write(ssl, testMsg, sizeof(testMsg)),
                    sizeof(testMsg));
        AssertIntEQ(wolfSSL_read(ssl, msgBuf, sizeof(msgBuf)), sizeof(msgBuf));
    }
}

int test_dtls_downgrade_scr_server(void)
{
    EXPECT_DECLS;
    callback_functions func_cb_client;
    callback_functions func_cb_server;

    XMEMSET(&func_cb_client, 0, sizeof(callback_functions));
    XMEMSET(&func_cb_server, 0, sizeof(callback_functions));

    func_cb_client.doUdp = func_cb_server.doUdp = 1;
    func_cb_client.method = wolfDTLSv1_2_client_method;
    func_cb_server.method = wolfDTLS_server_method;
    func_cb_client.ctx_ready = test_dtls_downgrade_scr_server_ctx_ready;
    func_cb_server.ctx_ready = test_dtls_downgrade_scr_server_ctx_ready_server;
    func_cb_client.on_result = test_dtls_downgrade_scr_server_on_result;
    func_cb_server.on_result = test_dtls_downgrade_scr_server_on_result;

    test_wolfSSL_client_server_nofail(&func_cb_client, &func_cb_server);

    ExpectIntEQ(func_cb_client.return_code, TEST_SUCCESS);
    ExpectIntEQ(func_cb_server.return_code, TEST_SUCCESS);

    return EXPECT_RESULT();
}
#else
int test_dtls_downgrade_scr_server(void)
{
    EXPECT_DECLS;
    return EXPECT_RESULT();
}
#endif

/*-- downgrade_scr (api.c lines 31295,31352) ---*/
#if defined(WOLFSSL_DTLS) && !defined(WOLFSSL_NO_TLS12) && \
    defined(HAVE_IO_TESTS_DEPENDENCIES) && defined(HAVE_SECURE_RENEGOTIATION)
static void test_dtls_downgrade_scr_ctx_ready(WOLFSSL_CTX* ctx)
{
    AssertIntEQ(wolfSSL_CTX_SetMinVersion(ctx, WOLFSSL_DTLSV1_2),
                WOLFSSL_SUCCESS);
    AssertIntEQ(wolfSSL_CTX_UseSecureRenegotiation(ctx), WOLFSSL_SUCCESS);
}

static void test_dtls_downgrade_scr_on_result(WOLFSSL* ssl)
{
    char testMsg[] = "Message after SCR";
    char msgBuf[sizeof(testMsg)];
    if (wolfSSL_is_server(ssl)) {
        AssertIntEQ(wolfSSL_Rehandshake(ssl), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
        AssertIntEQ(wolfSSL_get_error(ssl, -1), WC_NO_ERR_TRACE(APP_DATA_READY));
        AssertIntEQ(wolfSSL_read(ssl, msgBuf, sizeof(msgBuf)), sizeof(msgBuf));
        AssertIntEQ(wolfSSL_Rehandshake(ssl), WOLFSSL_SUCCESS);
        AssertIntEQ(wolfSSL_write(ssl, testMsg, sizeof(testMsg)),
                    sizeof(testMsg));
    }
    else {
        AssertIntEQ(wolfSSL_write(ssl, testMsg, sizeof(testMsg)),
                    sizeof(testMsg));
        AssertIntEQ(wolfSSL_read(ssl, msgBuf, sizeof(msgBuf)), sizeof(msgBuf));
    }
}

int test_dtls_downgrade_scr(void)
{
    EXPECT_DECLS;
    callback_functions func_cb_client;
    callback_functions func_cb_server;

    XMEMSET(&func_cb_client, 0, sizeof(callback_functions));
    XMEMSET(&func_cb_server, 0, sizeof(callback_functions));

    func_cb_client.doUdp = func_cb_server.doUdp = 1;
    func_cb_client.method = wolfDTLS_client_method;
    func_cb_server.method = wolfDTLSv1_2_server_method;
    func_cb_client.ctx_ready = test_dtls_downgrade_scr_ctx_ready;
    func_cb_client.on_result = test_dtls_downgrade_scr_on_result;
    func_cb_server.on_result = test_dtls_downgrade_scr_on_result;

    test_wolfSSL_client_server_nofail(&func_cb_client, &func_cb_server);

    ExpectIntEQ(func_cb_client.return_code, TEST_SUCCESS);
    ExpectIntEQ(func_cb_server.return_code, TEST_SUCCESS);

    return EXPECT_RESULT();
}
#else
int test_dtls_downgrade_scr(void)
{
    EXPECT_DECLS;
    return EXPECT_RESULT();
}
#endif

/*-- client_hello_timeout_downgrade_with_helper (api.c lines 31354,31490) ---*/
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && !defined(WOLFSSL_NO_TLS12)

static int test_dtls_client_hello_timeout_downgrade_read_cb(WOLFSSL *ssl,
        char *data, int sz, void *ctx)
{
    static int call_counter = 0;
    call_counter++;
    (void)ssl;
    (void)data;
    (void)sz;
    (void)ctx;
    switch (call_counter) {
        case 1:
        case 2:
            return WOLFSSL_CBIO_ERR_TIMEOUT;
        case 3:
            return WOLFSSL_CBIO_ERR_WANT_READ;
        default:
            AssertIntLE(call_counter, 3);
            return -1;
    }
}
#endif

/* Make sure we don't send acks before getting a server hello */
int test_dtls_client_hello_timeout_downgrade(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && !defined(WOLFSSL_NO_TLS12)

    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    DtlsRecordLayerHeader* dtlsRH;
    size_t len;
    byte sequence_number[8];
    int i;

    for (i = 0; i < 2; i++) {
        XMEMSET(&test_ctx, 0, sizeof(test_ctx));

        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfDTLS_client_method, wolfDTLSv1_2_server_method), 0);

        if (i == 0) {
            /* First time simulate timeout in IO layer */
            /* CH1 */
            ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
            /* HVR */
            ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
            /* CH2 */
            ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
            /* SH flight */
            ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
            /* Drop the SH */
            if (EXPECT_SUCCESS()) {
                ExpectIntEQ(test_memio_drop_message(&test_ctx, 1, 0), 0);
            }
            /* Read the remainder of the flight */
            ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
            wolfSSL_SSLSetIORecv(ssl_c,
                    test_dtls_client_hello_timeout_downgrade_read_cb);
            /* CH3 */
            ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
            wolfSSL_SSLSetIORecv(ssl_c, test_memio_read_cb);
        }
        else {
            /* Second time call wolfSSL_dtls_got_timeout */
            /* CH1 */
            ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
            /* HVR */
            ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
            /* CH2 */
            ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
            /* SH flight */
            ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
            /* Drop the SH */
            if (EXPECT_SUCCESS()) {
                ExpectIntEQ(test_memio_drop_message(&test_ctx, 1, 0), 0);
            }
            /* Read the remainder of the flight */
            ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
            /* Quick timeout should be set as we received at least one msg */
            ExpectIntEQ(wolfSSL_dtls13_use_quick_timeout(ssl_c), 1);
            ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_c), WOLFSSL_SUCCESS);
            /* Quick timeout should be cleared after a quick timeout */
            /* CH3 */
            ExpectIntEQ(wolfSSL_dtls13_use_quick_timeout(ssl_c), 0);
            ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_c), WOLFSSL_SUCCESS);
        }

        /* Parse out to make sure we got exactly one ClientHello message */
        XMEMSET(&sequence_number, 0, sizeof(sequence_number));
        /* Second ClientHello after HVR */
        sequence_number[7] = 2;
        dtlsRH = (DtlsRecordLayerHeader*)test_ctx.s_buff;
        ExpectIntEQ(dtlsRH->type, handshake);
        ExpectIntEQ(dtlsRH->pvMajor, DTLS_MAJOR);
        ExpectIntEQ(dtlsRH->pvMinor, DTLSv1_2_MINOR);
        ExpectIntEQ(XMEMCMP(sequence_number, dtlsRH->sequence_number,
                sizeof(sequence_number)), 0);
        len = (size_t)((dtlsRH->length[0] << 8) | dtlsRH->length[1]);
        ExpectIntEQ(sizeof(DtlsRecordLayerHeader) + len, test_ctx.s_len);

        /* Connection should be able to continue */
        ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

        wolfSSL_free(ssl_c);
        wolfSSL_free(ssl_s);
        wolfSSL_CTX_free(ctx_c);
        wolfSSL_CTX_free(ctx_s);
        ssl_c = NULL;
        ssl_s = NULL;
        ctx_c = NULL;
        ctx_s = NULL;
        if (!EXPECT_SUCCESS())
            break;
    }

#endif
    return EXPECT_RESULT();
}

/*-- client_hello_timeout_with_helper (api.c lines 31492,31581) ---*/
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13)
static int test_dtls_client_hello_timeout_read_cb(WOLFSSL *ssl, char *data,
        int sz, void *ctx)
{
    static int call_counter = 0;
    call_counter++;
    (void)ssl;
    (void)data;
    (void)sz;
    (void)ctx;
    switch (call_counter) {
        case 1:
            return WOLFSSL_CBIO_ERR_TIMEOUT;
        case 2:
            return WOLFSSL_CBIO_ERR_WANT_READ;
        default:
            AssertIntLE(call_counter, 2);
            return -1;
    }
}
#endif

/* Make sure we don't send acks before getting a server hello */
int test_dtls_client_hello_timeout(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13)
    WOLFSSL *ssl_c = NULL;
    WOLFSSL_CTX *ctx_c = NULL;
    struct test_memio_ctx test_ctx;
    DtlsRecordLayerHeader* dtlsRH;
    size_t idx;
    size_t len;
    byte sequence_number[8];
    int i;

    for (i = 0; i < 2; i++) {
        XMEMSET(&test_ctx, 0, sizeof(test_ctx));

        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, NULL, &ssl_c, NULL,
            wolfDTLSv1_3_client_method, NULL), 0);

        if (i == 0) {
            /* First time simulate timeout in IO layer */
            wolfSSL_SSLSetIORecv(ssl_c, test_dtls_client_hello_timeout_read_cb);
            ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
        }
        else {
            /* Second time call wolfSSL_dtls_got_timeout */
            ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
            ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_c), WOLFSSL_SUCCESS);
        }

        /* Parse out to make sure we got exactly two ClientHello messages */
        idx = 0;
        XMEMSET(&sequence_number, 0, sizeof(sequence_number));
        /* First ClientHello */
        dtlsRH = (DtlsRecordLayerHeader*)(test_ctx.s_buff + idx);
        ExpectIntEQ(dtlsRH->type, handshake);
        ExpectIntEQ(dtlsRH->pvMajor, DTLS_MAJOR);
        ExpectIntEQ(dtlsRH->pvMinor, DTLSv1_2_MINOR);
        ExpectIntEQ(XMEMCMP(sequence_number, dtlsRH->sequence_number,
                sizeof(sequence_number)), 0);
        len = (size_t)((dtlsRH->length[0] << 8) | dtlsRH->length[1]);
        ExpectIntLT(idx + sizeof(DtlsRecordLayerHeader) + len, test_ctx.s_len);
        idx += sizeof(DtlsRecordLayerHeader) + len;
        /* Second ClientHello */
        sequence_number[7] = 1;
        dtlsRH = (DtlsRecordLayerHeader*)(test_ctx.s_buff + idx);
        ExpectIntEQ(dtlsRH->type, handshake);
        ExpectIntEQ(dtlsRH->pvMajor, DTLS_MAJOR);
        ExpectIntEQ(dtlsRH->pvMinor, DTLSv1_2_MINOR);
        ExpectIntEQ(XMEMCMP(sequence_number, dtlsRH->sequence_number,
                sizeof(sequence_number)), 0);
        len = (size_t)((dtlsRH->length[0] << 8) | dtlsRH->length[1]);
        ExpectIntEQ(idx + sizeof(DtlsRecordLayerHeader) + len, test_ctx.s_len);

        wolfSSL_free(ssl_c);
        wolfSSL_CTX_free(ctx_c);
        ssl_c = NULL;
        ctx_c = NULL;
        if (!EXPECT_SUCCESS())
            break;
    }

#endif
    return EXPECT_RESULT();
}

/*-- dropped_ccs (api.c lines 31584,31648) ---*/
int test_dtls_dropped_ccs(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS) \
    && !defined(WOLFSSL_NO_TLS12)

    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    DtlsRecordLayerHeader* dtlsRH;
    size_t len;
    byte data[1];


    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method), 0);

    /* CH1 */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* HVR */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    /* CH2 */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* Server first flight */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    /* Client flight */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* Server ccs + finished */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), 1);

    /* Drop the ccs */
    dtlsRH = (DtlsRecordLayerHeader*)test_ctx.c_buff;
    len = (size_t)((dtlsRH->length[0] << 8) | dtlsRH->length[1]);
    ExpectIntEQ(len, 1);
    ExpectIntEQ(dtlsRH->type, change_cipher_spec);
    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(test_memio_drop_message(&test_ctx, 1, 0), 0);
    }

    /* Client rtx flight */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_c), WOLFSSL_SUCCESS);
    /* Server ccs + finished rtx */
    ExpectIntEQ(wolfSSL_read(ssl_s, data, sizeof(data)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    /* Client processes finished */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), 1);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/*-- seq_num_downgrade_with_helper (api.c lines 31650,31722) ---*/
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS) \
    && !defined(WOLFSSL_NO_TLS12)
static int test_dtls_seq_num_downgrade_check_num(byte* ioBuf, int ioBufLen,
        byte seq_num)
{
    EXPECT_DECLS;
    DtlsRecordLayerHeader* dtlsRH;
    byte sequence_number[8];

    XMEMSET(&sequence_number, 0, sizeof(sequence_number));

    ExpectIntGE(ioBufLen, sizeof(*dtlsRH));
    dtlsRH = (DtlsRecordLayerHeader*)ioBuf;
    ExpectIntEQ(dtlsRH->type, handshake);
    ExpectIntEQ(dtlsRH->pvMajor, DTLS_MAJOR);
    ExpectIntEQ(dtlsRH->pvMinor, DTLSv1_2_MINOR);
    sequence_number[7] = seq_num;
    ExpectIntEQ(XMEMCMP(sequence_number, dtlsRH->sequence_number,
            sizeof(sequence_number)), 0);

    return EXPECT_RESULT();
}
#endif

/*
 * Make sure that we send the correct sequence number after a HelloVerifyRequest
 * and after a HelloRetryRequest. This is testing the server side as it is
 * operating statelessly and should copy the sequence number of the ClientHello.
 */
int test_dtls_seq_num_downgrade(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS) \
    && !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_2_client_method, wolfDTLS_server_method), 0);

    /* CH1 */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(test_dtls_seq_num_downgrade_check_num(test_ctx.s_buff,
            test_ctx.s_len, 0), TEST_SUCCESS);
    /* HVR */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(test_dtls_seq_num_downgrade_check_num(test_ctx.c_buff,
            test_ctx.c_len, 0), TEST_SUCCESS);
    /* CH2 */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(test_dtls_seq_num_downgrade_check_num(test_ctx.s_buff,
            test_ctx.s_len, 1), TEST_SUCCESS);
    /* Server first flight */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(test_dtls_seq_num_downgrade_check_num(test_ctx.c_buff,
            test_ctx.c_len, 1), TEST_SUCCESS);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/*-- old_seq_number (api.c lines 31953,32005) ---*/
int test_dtls_old_seq_number(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS) && \
    !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method), 0);

    /* CH1 */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* HVR */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    /* CH2 */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* Server first flight */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    /* Client second flight */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* Modify the sequence number */
    {
        DtlsRecordLayerHeader* dtlsRH = (DtlsRecordLayerHeader*)test_ctx.s_buff;
        XMEMSET(dtlsRH->sequence_number, 0, sizeof(dtlsRH->sequence_number));
    }
    /* Server second flight */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    /* Server should not do anything as a pkt was dropped */
    ExpectIntEQ(test_ctx.c_len, 0);
    ExpectIntEQ(test_ctx.s_len, 0);
    /* Trigger rtx */
    ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_c), WOLFSSL_SUCCESS);

    /* Complete connection */
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/*-- dtls12_missing_finished (api.c lines 32007,32068) ---*/
int test_dtls12_missing_finished(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS) && \
    !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    const char test_str[] = "test string";
    char test_buf[sizeof(test_str)];

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method), 0);

    /* CH1 */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* HVR */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    /* CH2 */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* Server first flight */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    /* Client second flight with finished */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* Server second flight with finished */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), 1);
    /* Let's clear the output */
    test_memio_clear_buffer(&test_ctx, 1);
    /* Let's send some app data */
    ExpectIntEQ(wolfSSL_write(ssl_s, test_str, sizeof(test_str)),
                sizeof(test_str));
    /* Client should not error out on a missing finished */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* Server rtx second flight with finished */
    ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_s), 1);
    /* Client process rest of handshake */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), 1);

    /* Let's send some app data */
    ExpectIntEQ(wolfSSL_write(ssl_s, test_str, sizeof(test_str)),
                sizeof(test_str));
    ExpectIntEQ(wolfSSL_read(ssl_c, test_buf, sizeof(test_buf)),
                sizeof(test_str));
    ExpectBufEQ(test_buf, test_str, sizeof(test_str));

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS) && \
    defined(WOLFSSL_SESSION_EXPORT) && defined(HAVE_ENCRYPT_THEN_MAC) && \
    !defined(WOLFSSL_AEAD_ONLY) && !defined(WOLFSSL_NO_TLS12) && \
    !defined(NO_RSA) && !defined(NO_AES) && defined(HAVE_AES_CBC) && \
    !defined(NO_SHA256) && defined(HAVE_ECC)
/* Dummy peer callbacks so the DTLS exporter/importer has peer information to
 * work with (the library requires these unless built with
 * WOLFSSL_SESSION_EXPORT_NOPEER). */
static int test_dtls_export_etm_get_peer(WOLFSSL* ssl, char* ip, int* ipSz,
        unsigned short* port, int* fam)
{
    (void)ssl;
    ip[0] = -1;
    *ipSz = 1;
    *port = 1;
    *fam = 2;
    return 1;
}

static int test_dtls_export_etm_set_peer(WOLFSSL* ssl, char* ip, int ipSz,
        unsigned short port, int fam)
{
    (void)ssl;
    if (ip[0] != -1 || ipSz != 1 || port != 1 || fam != 2)
        return 0;
    return 1;
}
#endif

/* Regression test for DTLS session export/import dropping the Encrypt-Then-MAC
 * options. Historically the ETM option fields were only serialized for TLS, so
 * a re-imported DTLS session lost the negotiated ETM state and broke the record
 * layer. Establish a DTLS 1.2 connection with a CBC cipher suite (where ETM
 * applies), export the session, re-import it into a fresh WOLFSSL, and confirm
 * the ETM option fields survive the round trip. */
int test_dtls12_export_import_etm(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS) && \
    defined(WOLFSSL_SESSION_EXPORT) && defined(HAVE_ENCRYPT_THEN_MAC) && \
    !defined(WOLFSSL_AEAD_ONLY) && !defined(WOLFSSL_NO_TLS12) && \
    !defined(NO_RSA) && !defined(NO_AES) && defined(HAVE_AES_CBC) && \
    !defined(NO_SHA256) && defined(HAVE_ECC)
    /* TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 - a CBC suite, where ETM applies. */
    const char* cbcSuite = "ECDHE-RSA-AES128-SHA256";
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    WOLFSSL *ssl_imp = NULL;
    struct test_memio_ctx test_ctx;
    unsigned char* session = NULL;
    unsigned int sessionSz = 0;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method), 0);
    ExpectIntEQ(wolfSSL_set_cipher_list(ssl_c, cbcSuite), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_cipher_list(ssl_s, cbcSuite), WOLFSSL_SUCCESS);

    /* The exporter/importer needs peer info callbacks. */
    wolfSSL_CTX_SetIOGetPeer(ctx_s, test_dtls_export_etm_get_peer);
    wolfSSL_CTX_SetIOSetPeer(ctx_s, test_dtls_export_etm_set_peer);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* Sanity: the handshake itself negotiated ETM on both sides. */
    if (ssl_c != NULL)
        ExpectIntEQ(ssl_c->options.encThenMac, 1);
    if (ssl_s != NULL)
        ExpectIntEQ(ssl_s->options.encThenMac, 1);

    /* Export the server's DTLS session. */
    ExpectIntGE(wolfSSL_dtls_export(ssl_s, NULL, &sessionSz), 0);
    ExpectIntGT(sessionSz, 0);
    ExpectNotNull(session = (unsigned char*)XMALLOC(sessionSz, NULL,
                    DYNAMIC_TYPE_TMP_BUFFER));
    ExpectIntGE(wolfSSL_dtls_export(ssl_s, session, &sessionSz), 0);

    /* Import into a fresh WOLFSSL and confirm the ETM state survived. */
    ExpectNotNull(ssl_imp = wolfSSL_new(ctx_s));
    ExpectIntGE(wolfSSL_dtls_import(ssl_imp, session, sessionSz), 0);
    if (ssl_imp != NULL) {
        /* Regression check: pre-fix these were all reset to 0 for DTLS. */
        ExpectIntEQ(ssl_imp->options.encThenMac, 1);
        ExpectIntEQ(ssl_imp->options.startedETMRead, 1);
        ExpectIntEQ(ssl_imp->options.startedETMWrite, 1);
        ExpectIntEQ(ssl_imp->options.disallowEncThenMac, 0);
    }

    XFREE(session, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    wolfSSL_free(ssl_imp);
    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}


/* ----------------------------------------------------------------------------
 * Coverage tests for DTLS APIs in src/ssl_api_dtls.c
 * ------------------------------------------------------------------------- */

int test_wolfSSL_dtls_create_free_peer(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_DTLS) && defined(XINET_PTON) && \
    !defined(WOLFSSL_NO_SOCK) && defined(HAVE_SOCKADDR)
    void* peer = NULL;

    /* Valid IPv4 address and port. */
    ExpectNotNull(peer = wolfSSL_dtls_create_peer(11111, (char*)"127.0.0.1"));
    ExpectIntEQ(wolfSSL_dtls_free_peer(peer), WOLFSSL_SUCCESS);

    /* Invalid address string returns NULL. */
    ExpectNull(wolfSSL_dtls_create_peer(11111, (char*)"not-an-ip-address"));
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_dtls_get0_peer(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_DTLS) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    const void* peer = NULL;
    unsigned int peerSz = 0;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfDTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    ExpectIntEQ(wolfSSL_dtls_set_peer(ssl, (void*)"1234", 5), WOLFSSL_SUCCESS);
#ifndef WOLFSSL_RW_THREADED
    /* NULL arguments fail. */
    ExpectIntEQ(wolfSSL_dtls_get0_peer(NULL, &peer, &peerSz), WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_dtls_get0_peer(ssl, NULL, &peerSz), WOLFSSL_FAILURE);
    /* Returns a pointer to the stored peer address and its size. */
    ExpectIntEQ(wolfSSL_dtls_get0_peer(ssl, &peer, &peerSz), WOLFSSL_SUCCESS);
    ExpectIntEQ(peerSz, 5);
    ExpectNotNull(peer);
#else
    ExpectIntEQ(wolfSSL_dtls_get0_peer(ssl, &peer, &peerSz),
        WOLFSSL_NOT_IMPLEMENTED);
#endif

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_dtls_set_timeout_init(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_DTLS) && !defined(WOLFSSL_LEANPSK) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfDTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    ExpectIntEQ(wolfSSL_dtls_set_timeout_init(NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_dtls_set_timeout_init(ssl, -1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_dtls_set_timeout_max(ssl, 5), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_dtls_set_timeout_init(ssl, 3), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_dtls_get_current_timeout(ssl), 3);
    /* Initial timeout greater than maximum fails. */
    ExpectIntEQ(wolfSSL_dtls_set_timeout_init(ssl, 10),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_dtls_retransmit(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS) && \
    !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method), 0);

    /* NULL fails. */
    ExpectIntEQ(wolfSSL_dtls_retransmit(NULL), WOLFSSL_FATAL_ERROR);
    /* Send the ClientHello flight, then retransmit it (DTLS 1.2 path). */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(wolfSSL_dtls_retransmit(ssl_c), WOLFSSL_SUCCESS);

    /* Resending fails when the transport reports want-write, exercising the
     * error path (sets ssl->error and returns WOLFSSL_FATAL_ERROR). */
    test_memio_simulate_want_write(&test_ctx, 1, 1);
    ExpectIntEQ(wolfSSL_dtls_retransmit(ssl_c), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_WRITE);
    test_memio_simulate_want_write(&test_ctx, 1, 0);

    /* After the handshake completes, retransmit is a no-op success. */
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectIntEQ(wolfSSL_dtls_retransmit(ssl_c), WOLFSSL_SUCCESS);

    wolfSSL_free(ssl_s);
    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_s);
    wolfSSL_CTX_free(ctx_c);
#endif
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_DTLS13) && defined(WOLFSSL_TLS13)
    {
        /* DTLS 1.3 exercises the Dtls13DoScheduledWork() branch. */
        WOLFSSL_CTX *ctx_c13 = NULL, *ctx_s13 = NULL;
        WOLFSSL *ssl_c13 = NULL, *ssl_s13 = NULL;
        struct test_memio_ctx test_ctx13;

        XMEMSET(&test_ctx13, 0, sizeof(test_ctx13));
        ExpectIntEQ(test_memio_setup(&test_ctx13, &ctx_c13, &ctx_s13, &ssl_c13,
            &ssl_s13, wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method),
            0);
        ExpectIntEQ(wolfSSL_negotiate(ssl_c13), -1);
        ExpectIntEQ(wolfSSL_get_error(ssl_c13, -1), WOLFSSL_ERROR_WANT_READ);
        ExpectIntEQ(wolfSSL_dtls_retransmit(ssl_c13), WOLFSSL_SUCCESS);

        wolfSSL_free(ssl_s13);
        wolfSSL_free(ssl_c13);
        wolfSSL_CTX_free(ctx_s13);
        wolfSSL_CTX_free(ctx_c13);
    }
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_DTLSv1_compat_timeouts(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_DTLS) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    WOLFSSL_TIMEVAL tv;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfDTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    XMEMSET(&tv, 0, sizeof(tv));
    ExpectIntEQ(wolfSSL_DTLSv1_get_timeout(ssl, &tv), 0);
    /* NULL arguments are tolerated. */
    ExpectIntEQ(wolfSSL_DTLSv1_get_timeout(NULL, NULL), 0);
#ifndef NO_WOLFSSL_STUB
    ExpectIntEQ(wolfSSL_DTLSv1_handle_timeout(ssl), 0);
    wolfSSL_DTLSv1_set_initial_timeout_duration(ssl, 1000);
#endif

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_dtls13_set_send_more_acks(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_DTLS13) && defined(WOLFSSL_TLS13) && \
    !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfDTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* Toggle the send-more-acks option (void return). */
    wolfSSL_dtls13_set_send_more_acks(ssl, 1);
    wolfSSL_dtls13_set_send_more_acks(ssl, 0);
    /* NULL is tolerated. */
    wolfSSL_dtls13_set_send_more_acks(NULL, 1);
    /* Quick-timeout flag defaults to off. */
    ExpectIntEQ(wolfSSL_dtls13_use_quick_timeout(ssl), 0);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_dtls_srtp_keying_material(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS) && \
    defined(WOLFSSL_SRTP) && defined(HAVE_KEYING_MATERIAL) && \
    !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    const WOLFSSL_SRTP_PROTECTION_PROFILE* profile = NULL;
    unsigned char keyMaterial[64];
    size_t olen = 0;
    const char* profileStr = "SRTP_AES128_CM_SHA1_80";

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method), 0);

    /* No profile selected before the handshake. */
    ExpectNull(wolfSSL_get_selected_srtp_profile(NULL));

    /* NULL arguments fail. */
    olen = sizeof(keyMaterial);
    ExpectIntEQ(wolfSSL_export_dtls_srtp_keying_material(NULL, keyMaterial,
        &olen), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Exporting before SRTP is negotiated reports a missing extension. */
    ExpectIntEQ(wolfSSL_export_dtls_srtp_keying_material(ssl_c, keyMaterial,
        &olen), WC_NO_ERR_TRACE(EXT_MISSING));

    /* Request SRTP on both ends (0 == success, OpenSSL convention). */
    ExpectIntEQ(wolfSSL_set_tlsext_use_srtp(ssl_c, profileStr), 0);
    ExpectIntEQ(wolfSSL_set_tlsext_use_srtp(ssl_s, profileStr), 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* A profile is now selected. */
    ExpectNotNull(profile = wolfSSL_get_selected_srtp_profile(ssl_c));

    /* Length-only query (out == NULL). */
    olen = 0;
    ExpectIntEQ(wolfSSL_export_dtls_srtp_keying_material(ssl_c, NULL, &olen),
        WC_NO_ERR_TRACE(LENGTH_ONLY_E));
    ExpectIntGT((int)olen, 0);
    ExpectIntLE((int)olen, (int)sizeof(keyMaterial));
    /* A buffer smaller than the keying material reports BUFFER_E. */
    olen = 1;
    ExpectIntEQ(wolfSSL_export_dtls_srtp_keying_material(ssl_c, keyMaterial,
        &olen), WC_NO_ERR_TRACE(BUFFER_E));
    /* Export the keying material into a large enough buffer. */
    olen = sizeof(keyMaterial);
#ifdef WOLFSSL_OPENVPN
    ExpectIntEQ(wolfSSL_export_dtls_srtp_keying_material(ssl_c, keyMaterial,
        &olen), WOLFSSL_SUCCESS);
#else
    /* Arrays aren't saved without WOLFSSL_OPENVPN. */
    ExpectIntEQ(wolfSSL_export_dtls_srtp_keying_material(ssl_c, keyMaterial,
        &olen), WOLFSSL_FAILURE);
#endif

#ifndef NO_WOLFSSL_STUB
    /* Stub returns NULL. */
    ExpectNull(wolfSSL_get_srtp_profiles(ssl_c));
#endif

    wolfSSL_free(ssl_s);
    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_s);
    wolfSSL_CTX_free(ctx_c);
#endif
    return EXPECT_RESULT();
}

#if defined(WOLFSSL_DTLS) && defined(WOLFSSL_MULTICAST) && \
    (defined(WOLFSSL_TLS13) || defined(WOLFSSL_SNIFFER)) && \
    !defined(NO_WOLFSSL_CLIENT)
static int test_dtls_mcast_highwater_cb(unsigned short peerId,
    unsigned int maxSeq, unsigned int curSeq, void* ctx)
{
    (void)peerId;
    (void)maxSeq;
    (void)curSeq;
    (void)ctx;
    return 0;
}
#endif

int test_wolfSSL_mcast_peers(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_DTLS) && defined(WOLFSSL_MULTICAST) && \
    (defined(WOLFSSL_TLS13) || defined(WOLFSSL_SNIFFER)) && \
    !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    int hwCtx = 0;

    ExpectIntGT(wolfSSL_mcast_get_max_peers(), 0);

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfDTLSv1_2_client_method()));
    ExpectIntEQ(wolfSSL_CTX_mcast_set_member_id(ctx, 0), WOLFSSL_SUCCESS);

    /* Highwater callback argument validation. */
    ExpectIntEQ(wolfSSL_CTX_mcast_set_highwater_cb(NULL, 320, 100, 200,
        test_dtls_mcast_highwater_cb), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CTX_mcast_set_highwater_cb(ctx, 320, 100, 200, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CTX_mcast_set_highwater_cb(ctx, 320, 100, 200,
        test_dtls_mcast_highwater_cb), WOLFSSL_SUCCESS);

    ExpectNotNull(ssl = wolfSSL_new(ctx));

    ExpectIntEQ(wolfSSL_mcast_set_highwater_ctx(NULL, &hwCtx),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_mcast_set_highwater_ctx(ssl, &hwCtx), WOLFSSL_SUCCESS);

    /* Add, query and remove a multicast peer. */
    ExpectIntEQ(wolfSSL_mcast_peer_add(NULL, 1, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_mcast_peer_add(ssl, 1, 0), WOLFSSL_SUCCESS);
    /* Known peer that has not sent data yet -> 0. */
    ExpectIntEQ(wolfSSL_mcast_peer_known(ssl, 1), 0);
    /* Unknown peer -> 0. */
    ExpectIntEQ(wolfSSL_mcast_peer_known(ssl, 2), 0);
    ExpectIntEQ(wolfSSL_mcast_peer_known(NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Once the peer has received data (non-zero sequence number) it is
     * reported as known. */
    if (ssl != NULL) {
        int j;
        for (j = 0; j < WOLFSSL_DTLS_PEERSEQ_SZ; j++) {
            if (ssl->keys.peerSeq[j].peerId == 1) {
                ssl->keys.peerSeq[j].nextSeq_lo = 1;
                break;
            }
        }
    }
    ExpectIntEQ(wolfSSL_mcast_peer_known(ssl, 1), 1);
    /* Remove the peer (sub = 1). */
    ExpectIntEQ(wolfSSL_mcast_peer_add(ssl, 1, 1), WOLFSSL_SUCCESS);

    /* Re-adding a peer that is already present reports an error. */
    ExpectIntEQ(wolfSSL_mcast_peer_add(ssl, 5, 0), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_mcast_peer_add(ssl, 5, 0), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_mcast_peer_add(ssl, 5, 1), WOLFSSL_SUCCESS);

    /* Filling every peer slot then adding another peer overflows the list. */
#if WOLFSSL_DTLS_PEERSEQ_SZ <= 255
    {
        int idx;
        for (idx = 0; idx < WOLFSSL_DTLS_PEERSEQ_SZ && !EXPECT_FAIL(); idx++) {
            ExpectIntEQ(wolfSSL_mcast_peer_add(ssl, (word16)idx, 0),
                WOLFSSL_SUCCESS);
        }
        ExpectIntEQ(wolfSSL_mcast_peer_add(ssl,
            (word16)WOLFSSL_DTLS_PEERSEQ_SZ, 0), WOLFSSL_FATAL_ERROR);
    }
#endif

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_set_dtls_fd_connected(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_DTLS) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    ExpectIntEQ(wolfSSL_set_dtls_fd_connected(NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfDTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(wolfSSL_set_dtls_fd_connected(ssl, 1), WOLFSSL_SUCCESS);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_dtls_get_peer(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_DTLS) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    unsigned char peer[16];
    unsigned int peerSz = (unsigned int)sizeof(peer);

    ExpectIntEQ(wolfSSL_dtls_get_peer(NULL, peer, &peerSz), WOLFSSL_FAILURE);

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfDTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* No peer set yet. */
    peerSz = (unsigned int)sizeof(peer);
    ExpectIntEQ(wolfSSL_dtls_get_peer(ssl, peer, &peerSz), WOLFSSL_FAILURE);

    /* Set then retrieve the peer. */
    ExpectIntEQ(wolfSSL_dtls_set_peer(ssl, (void*)"1234", 5), WOLFSSL_SUCCESS);
    peerSz = (unsigned int)sizeof(peer);
    ExpectIntEQ(wolfSSL_dtls_get_peer(ssl, peer, &peerSz), WOLFSSL_SUCCESS);
    ExpectIntEQ(peerSz, 5);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_dtls_set_peer(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_DTLS) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    unsigned char peer[16];
    unsigned int peerSz = (unsigned int)sizeof(peer);

    ExpectIntEQ(wolfSSL_dtls_set_peer(NULL, (void*)"1234", 5), WOLFSSL_FAILURE);

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfDTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* Set a peer then read it back. */
    ExpectIntEQ(wolfSSL_dtls_set_peer(ssl, (void*)"1234", 5), WOLFSSL_SUCCESS);
    peerSz = (unsigned int)sizeof(peer);
    ExpectIntEQ(wolfSSL_dtls_get_peer(ssl, peer, &peerSz), WOLFSSL_SUCCESS);
    ExpectIntEQ(peerSz, 5);

    /* A larger peer grows the buffer, freeing the previous one. */
    ExpectIntEQ(wolfSSL_dtls_set_peer(ssl, (void*)"123456789012", 12),
        WOLFSSL_SUCCESS);
    peerSz = (unsigned int)sizeof(peer);
    ExpectIntEQ(wolfSSL_dtls_get_peer(ssl, peer, &peerSz), WOLFSSL_SUCCESS);
    ExpectIntEQ(peerSz, 12);

    /* Clearing the peer with NULL/0 frees the stored address. */
    ExpectIntEQ(wolfSSL_dtls_set_peer(ssl, NULL, 0), WOLFSSL_SUCCESS);
    peerSz = (unsigned int)sizeof(peer);
    ExpectIntEQ(wolfSSL_dtls_get_peer(ssl, peer, &peerSz), WOLFSSL_FAILURE);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_GetDtlsMacSecret(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_DTLS) && !defined(WOLFSSL_AEAD_ONLY)
    /* NULL ssl returns NULL. */
    ExpectNull(wolfSSL_GetDtlsMacSecret(NULL, 0, 0));
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_dtls_get_using_nonblock(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_DTLS) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    ExpectIntEQ(wolfSSL_dtls_get_using_nonblock(NULL), WOLFSSL_FAILURE);

    /* DTLS object: default is off. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfDTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(wolfSSL_dtls_get_using_nonblock(ssl), 0);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    ssl = NULL;
    ctx = NULL;

#ifndef WOLFSSL_NO_TLS12
    /* Non-DTLS object takes the deprecated-use branch and returns 0. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(wolfSSL_dtls_get_using_nonblock(ssl), 0);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_dtls_set_using_nonblock(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_DTLS) && !defined(WOLFSSL_LEANPSK) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    /* NULL is a no-op (must not crash). */
    wolfSSL_dtls_set_using_nonblock(NULL, 1);

    /* DTLS object: value is stored and read back. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfDTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    wolfSSL_dtls_set_using_nonblock(ssl, 1);
    ExpectIntEQ(wolfSSL_dtls_get_using_nonblock(ssl), 1);
    wolfSSL_dtls_set_using_nonblock(ssl, 0);
    ExpectIntEQ(wolfSSL_dtls_get_using_nonblock(ssl), 0);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    ssl = NULL;
    ctx = NULL;

#ifndef WOLFSSL_NO_TLS12
    /* Non-DTLS object takes the deprecated-use branch. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    wolfSSL_dtls_set_using_nonblock(ssl, 1);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_set_mtu_compat(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_DTLS) && defined(OPENSSL_EXTRA) && \
    (defined(WOLFSSL_SCTP) || defined(WOLFSSL_DTLS_MTU)) && \
    !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfDTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* A reasonable MTU succeeds. */
    ExpectIntEQ(wolfSSL_set_mtu_compat(ssl, 1500), WOLFSSL_SUCCESS);
    /* An MTU larger than a record fails. */
    ExpectIntEQ(wolfSSL_set_mtu_compat(ssl, 0xFFFF), WOLFSSL_FAILURE);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_dtls_set_timeout_max(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_DTLS) && !defined(WOLFSSL_LEANPSK) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    ExpectIntEQ(wolfSSL_dtls_set_timeout_max(NULL, 5),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfDTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* Negative timeout fails. */
    ExpectIntEQ(wolfSSL_dtls_set_timeout_max(ssl, -1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Valid maximum succeeds. */
    ExpectIntEQ(wolfSSL_dtls_set_timeout_max(ssl, 5), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_dtls_set_timeout_init(ssl, 3), WOLFSSL_SUCCESS);
    /* Maximum less than the initial timeout fails. */
    ExpectIntEQ(wolfSSL_dtls_set_timeout_max(ssl, 2),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_CTX_mcast_set_member_id(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_DTLS) && defined(WOLFSSL_MULTICAST) && \
    (defined(WOLFSSL_TLS13) || defined(WOLFSSL_SNIFFER)) && \
    !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL_CTX* ctx = NULL;

    ExpectIntEQ(wolfSSL_CTX_mcast_set_member_id(NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfDTLSv1_2_client_method()));
    /* Member id out of range (> 8-bit) fails. */
    ExpectIntEQ(wolfSSL_CTX_mcast_set_member_id(ctx, 256),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Valid member id succeeds. */
    ExpectIntEQ(wolfSSL_CTX_mcast_set_member_id(ctx, 0), WOLFSSL_SUCCESS);

    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_mcast_read(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_DTLS) && defined(WOLFSSL_MULTICAST) && \
    (defined(WOLFSSL_TLS13) || defined(WOLFSSL_SNIFFER)) && \
    !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    word16 id = 0;
    byte buf[16];

    ExpectIntEQ(wolfSSL_mcast_read(NULL, &id, buf, (int)sizeof(buf)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfDTLSv1_2_client_method()));
    ExpectIntEQ(wolfSSL_CTX_mcast_set_member_id(ctx, 0), WOLFSSL_SUCCESS);
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* Negative size fails. */
    ExpectIntEQ(wolfSSL_mcast_read(ssl, &id, buf, -1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_dtls_got_timeout(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_DTLS) && !defined(WOLFSSL_LEANPSK) && \
    !defined(NO_WOLFSSL_CLIENT)
    /* NULL object fails. */
    ExpectIntEQ(wolfSSL_dtls_got_timeout(NULL), WOLFSSL_FATAL_ERROR);
#ifndef WOLFSSL_NO_TLS12
    {
        /* A non-DTLS object also fails. */
        WOLFSSL_CTX* ctx = NULL;
        WOLFSSL* ssl = NULL;

        ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
        ExpectNotNull(ssl = wolfSSL_new(ctx));
        ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl), WOLFSSL_FATAL_ERROR);
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
    }
#endif
#endif

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS) && \
    !defined(WOLFSSL_LEANPSK) && !defined(WOLFSSL_NO_TLS12)
    {
        /* With a DTLS 1.2 flight buffered, a transport that reports want-write
         * makes the timeout handler take the pool-send error path. */
        WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
        WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
        struct test_memio_ctx test_ctx;

        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method), 0);

        /* Buffer the ClientHello flight. */
        ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
        ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);

        /* Resending the flight fails -> error path, returns FATAL_ERROR. */
        test_memio_simulate_want_write(&test_ctx, 1, 1);
        ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_c), WOLFSSL_FATAL_ERROR);
        ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_WRITE);

        /* With the transport unblocked the resend succeeds. */
        test_memio_simulate_want_write(&test_ctx, 1, 0);
        ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_c), WOLFSSL_SUCCESS);

        wolfSSL_free(ssl_s);
        wolfSSL_free(ssl_c);
        wolfSSL_CTX_free(ctx_s);
        wolfSSL_CTX_free(ctx_c);
    }
#endif

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_DTLS13) && defined(WOLFSSL_TLS13)
    {
        /* DTLS 1.3: a want-write while retransmitting takes the
         * Dtls13RtxTimeout() error branch. */
        WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
        WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
        struct test_memio_ctx test_ctx;

        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);

        /* Buffer the ClientHello flight. */
        ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
        ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);

        /* Retransmit under want-write fails. */
        test_memio_simulate_want_write(&test_ctx, 1, 1);
        ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_c), WOLFSSL_FATAL_ERROR);
        ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_WRITE);
        test_memio_simulate_want_write(&test_ctx, 1, 0);

        wolfSSL_free(ssl_s);
        wolfSSL_free(ssl_c);
        wolfSSL_CTX_free(ctx_s);
        wolfSSL_CTX_free(ctx_c);
    }
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_DTLS_SetCookieSecret(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_DTLS) && !defined(NO_WOLFSSL_SERVER) && \
    (defined(NO_CERTS) || !defined(NO_RSA))
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte secret1[32];
    byte secret2[16];

    XMEMSET(secret1, 0xA5, sizeof(secret1));
    XMEMSET(secret2, 0x5A, sizeof(secret2));

    /* NULL object fails. */
    ExpectIntEQ(wolfSSL_DTLS_SetCookieSecret(NULL, secret1, sizeof(secret1)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfDTLSv1_2_server_method()));
#ifndef NO_CERTS
    /* A server WOLFSSL needs a key and certificate set on the context. */
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKeyFile, CERT_FILETYPE),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_certificate_file(ctx, svrCertFile,
        CERT_FILETYPE), WOLFSSL_SUCCESS);
#endif
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* A non-NULL secret with zero size fails. */
    ExpectIntEQ(wolfSSL_DTLS_SetCookieSecret(ssl, secret1, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Set an explicit secret (copy path). */
    ExpectIntEQ(wolfSSL_DTLS_SetCookieSecret(ssl, secret1, sizeof(secret1)), 0);
    /* A different size frees the old buffer and reallocates. */
    ExpectIntEQ(wolfSSL_DTLS_SetCookieSecret(ssl, secret2, sizeof(secret2)), 0);
    /* The same size keeps the existing buffer (no reallocation). */
    ExpectIntEQ(wolfSSL_DTLS_SetCookieSecret(ssl, secret2, sizeof(secret2)), 0);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_set_secret(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_DTLS) && defined(WOLFSSL_MULTICAST) && \
    (defined(WOLFSSL_TLS13) || defined(WOLFSSL_SNIFFER)) && \
    !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte preMasterSecret[16];
    byte clientRandom[32];
    byte serverRandom[32];
    byte suite[2] = { 0, 0xfe };  /* WDM_WITH_NULL_SHA256 */

    XMEMSET(preMasterSecret, 0x23, sizeof(preMasterSecret));
    XMEMSET(clientRandom, 0xA5, sizeof(clientRandom));
    XMEMSET(serverRandom, 0x5A, sizeof(serverRandom));

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfDTLSv1_2_client_method()));
    ExpectIntEQ(wolfSSL_CTX_mcast_set_member_id(ctx, 0), WOLFSSL_SUCCESS);
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* Invalid arguments take the error path and return WOLFSSL_FATAL_ERROR. */
    ExpectIntEQ(wolfSSL_set_secret(ssl, 23, NULL, sizeof(preMasterSecret),
        clientRandom, serverRandom, suite), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_set_secret(ssl, 23, preMasterSecret, 0,
        clientRandom, serverRandom, suite), WOLFSSL_FATAL_ERROR);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

