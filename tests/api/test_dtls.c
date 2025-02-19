/* test_dtls.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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
#include <tests/api/test_dtls.h>

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
        "DHE-RSA-AES128-SHA256",
        "ECDHE-RSA-AES128-SHA256",
#ifdef HAVE_AESGCM
        "DHE-RSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
#endif
#endif /* WOLFSSL_AES_128 && WOLFSSL_STATIC_RSA */
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
        "DHE-PSK-AES256-GCM-SHA384",
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
                test_ctx.c_len = test_ctx.s_len = 0;
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
                test_ctx.c_len = test_ctx.s_len = 0;
                ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_c), 1);
                ExpectNull(CLIENT_CID());
            }
            /* Server first flight */
            wolfSSL_SetLoggingPrefix("server");
            ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
            ExpectNull(SERVER_CID());
            if (run_params[j].drop) {
                test_ctx.c_len = test_ctx.s_len = 0;
                ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_s), 1);
                ExpectNull(SERVER_CID());
            }
            /* Client second flight */
            wolfSSL_SetLoggingPrefix("client");
            ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
            ExpectNotNull(CLIENT_CID());
            if (run_params[j].drop) {
                test_ctx.c_len = test_ctx.s_len = 0;
                ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_c), 1);
                ExpectNotNull(CLIENT_CID());
            }
            /* Server second flight */
            wolfSSL_SetLoggingPrefix("server");
            ExpectIntEQ(wolfSSL_negotiate(ssl_s), 1);
            ExpectNotNull(SERVER_CID());
            if (run_params[j].drop) {
                test_ctx.c_len = test_ctx.s_len = 0;
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
                test_ctx.c_len = test_ctx.s_len = 0;
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
                test_ctx.c_len = test_ctx.s_len = 0;
                ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_c), 1);
                ExpectNotNull(CLIENT_CID());
            }
            /* Server first flight */
            wolfSSL_SetLoggingPrefix("server");
            ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
            ExpectNotNull(SERVER_CID());
            if (run_params[j].drop) {
                test_ctx.c_len = test_ctx.s_len = 0;
                ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_s), 1);
                ExpectNotNull(SERVER_CID());
            }
            /* Client second flight */
            wolfSSL_SetLoggingPrefix("client");
            ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
            ExpectNotNull(CLIENT_CID());
            if (run_params[j].drop) {
                test_ctx.c_len = test_ctx.s_len = 0;
                ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_c), 1);
                ExpectNotNull(CLIENT_CID());
            }
            ExpectIntEQ(wolfSSL_write(ssl_c, params[i],
                    (int)XSTRLEN(params[i])), XSTRLEN(params[i]));
            /* Server second flight */
            wolfSSL_SetLoggingPrefix("server");
            ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), APP_DATA_READY);
            XMEMSET(readBuf, 0, sizeof(readBuf));
            ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)),
                    XSTRLEN(params[i]));
            ExpectStrEQ(readBuf, params[i]);
            if (!run_params[j].drop) {
                ExpectIntEQ(wolfSSL_write(ssl_s, params[i],
                        (int)XSTRLEN(params[i])), XSTRLEN(params[i]));
            }
            ExpectIntEQ(wolfSSL_negotiate(ssl_s), 1);
            ExpectNotNull(SERVER_CID());
            if (run_params[j].drop) {
                test_ctx.c_len = test_ctx.s_len = 0;
                ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_s), 1);
                ExpectNotNull(SERVER_CID());
            }
            /* Test loading old epoch */
            /* Client complete connection */
            wolfSSL_SetLoggingPrefix("client");
            if (!run_params[j].drop) {
                ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
                ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), APP_DATA_READY);
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

int test_dtls13_basic_connection_id(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CID)
    unsigned char client_cid[] = { 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
    unsigned char server_cid[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    unsigned char readBuf[50];
    void *        cid = NULL;
    const char* params[] = {
#ifndef NO_SHA256
#ifdef WOLFSSL_AES_128
#ifdef HAVE_AESGCM
        "TLS13-AES128-GCM-SHA256",
#endif
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
        "TLS13-CHACHA20-POLY1305-SHA256",
#endif
#ifdef HAVE_AESCCM
        "TLS13-AES128-CCM-8-SHA256",
        "TLS13-AES128-CCM-SHA256",
#endif
#endif
#ifdef HAVE_NULL_CIPHER
        "TLS13-SHA256-SHA256",
#endif
#endif
    };
    size_t i;

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
        WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
        WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
        struct test_memio_ctx test_ctx;

        printf("Testing %s ... ", params[i]);

        XMEMSET(&test_ctx, 0, sizeof(test_ctx));

        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);

        ExpectIntEQ(wolfSSL_set_cipher_list(ssl_c, params[i]), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_set_cipher_list(ssl_s, params[i]), WOLFSSL_SUCCESS);

        ExpectIntEQ(wolfSSL_dtls_cid_use(ssl_c), 1);
        ExpectIntEQ(wolfSSL_dtls_cid_set(ssl_c, server_cid, sizeof(server_cid)),
                1);
        ExpectIntEQ(wolfSSL_dtls_cid_use(ssl_s), 1);
        ExpectIntEQ(wolfSSL_dtls_cid_set(ssl_s, client_cid, sizeof(client_cid)),
                1);

        /* CH1 */
        ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
        ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
        ExpectNull(CLIENT_CID());
        /* HRR */
        ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
        ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
        ExpectNull(SERVER_CID());
        /* CH2 */
        ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
        ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
        ExpectNull(CLIENT_CID());
        /* Server first flight */
        ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
        ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
        ExpectNotNull(SERVER_CID());
        /* Client second flight */
        ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
        ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
        ExpectNotNull(CLIENT_CID());
        /* Server process flight */
        ExpectIntEQ(wolfSSL_negotiate(ssl_s), 1);
        /* Client process flight */
        ExpectIntEQ(wolfSSL_negotiate(ssl_c), 1);

        /* Write some data */
        ExpectIntEQ(wolfSSL_write(ssl_c, params[i], (int)XSTRLEN(params[i])),
                XSTRLEN(params[i]));
        ExpectNotNull(CLIENT_CID());
        ExpectIntEQ(wolfSSL_write(ssl_s, params[i], (int)XSTRLEN(params[i])),
                XSTRLEN(params[i]));
        ExpectNotNull(SERVER_CID());
        /* Read the data */
        XMEMSET(readBuf, 0, sizeof(readBuf));
        ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)),
                XSTRLEN(params[i]));
        ExpectStrEQ(readBuf, params[i]);
        XMEMSET(readBuf, 0, sizeof(readBuf));
        ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)),
                XSTRLEN(params[i]));
        ExpectStrEQ(readBuf, params[i]);
        /* Write short data */
        ExpectIntEQ(wolfSSL_write(ssl_c, params[i], 1), 1);
        ExpectNotNull(CLIENT_CID());
        ExpectIntEQ(wolfSSL_write(ssl_s, params[i], 1), 1);
        ExpectNotNull(SERVER_CID());
        /* Read the short data */
        XMEMSET(readBuf, 0, sizeof(readBuf));
        ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), 1);
        ExpectIntEQ(readBuf[0], params[i][0]);
        XMEMSET(readBuf, 0, sizeof(readBuf));
        ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), 1);
        ExpectIntEQ(readBuf[0], params[i][0]);
        /* Write some data but with wrong CID */
        ExpectIntEQ(wolfSSL_write(ssl_c, params[i], (int)XSTRLEN(params[i])),
                XSTRLEN(params[i]));
        /* Reset client cid. */
        ExpectNotNull(cid = CLIENT_CID());
        RESET_CID(cid);
        ExpectIntEQ(wolfSSL_write(ssl_s, params[i], (int)XSTRLEN(params[i])),
                XSTRLEN(params[i]));
        /* Reset server cid. */
        ExpectNotNull(cid = SERVER_CID());
        RESET_CID(cid);
        /* Try to read the data but it shouldn't be there */
        ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
        ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
        ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
        ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);

        /* Close connection */
        ExpectIntEQ(wolfSSL_shutdown(ssl_c), WOLFSSL_SHUTDOWN_NOT_DONE);
        ExpectNotNull(CLIENT_CID());
        ExpectIntEQ(wolfSSL_shutdown(ssl_s), WOLFSSL_SHUTDOWN_NOT_DONE);
        ExpectNotNull(SERVER_CID());
        ExpectIntEQ(wolfSSL_shutdown(ssl_c), 1);
        ExpectIntEQ(wolfSSL_shutdown(ssl_s), 1);

        if (EXPECT_SUCCESS())
            printf("ok\n");
        else
            printf("failed\n");

        wolfSSL_free(ssl_c);
        wolfSSL_CTX_free(ctx_c);
        wolfSSL_free(ssl_s);
        wolfSSL_CTX_free(ctx_s);
    }

#undef CLIENT_CID
#undef SERVER_CID
#undef RESET_CID

#endif
    return EXPECT_RESULT();
}

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
