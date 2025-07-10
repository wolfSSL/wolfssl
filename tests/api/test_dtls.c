/* test_dtls.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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
    return EXPECT_RESULT();
}

int test_dtls13_epochs(void) {
    EXPECT_DECLS;
#if defined(WOLFSSL_DTLS13) && !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte input[20];
    word32 inOutIdx = 0;

    XMEMSET(input, 0, sizeof(input));

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfDTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    /* Some manual setup to enter the epoch check */
    ExpectTrue(ssl->options.tls1_3 = 1);

    inOutIdx = 0;
    if (ssl != NULL) ssl->keys.curEpoch64 = w64From32(0x0, 0x0);
    ExpectIntEQ(DoApplicationData(ssl, input, &inOutIdx, 0), SANITY_MSG_E);
    inOutIdx = 0;
    if (ssl != NULL) ssl->keys.curEpoch64 = w64From32(0x0, 0x2);
    ExpectIntEQ(DoApplicationData(ssl, input, &inOutIdx, 0), SANITY_MSG_E);

    if (ssl != NULL) ssl->keys.curEpoch64 = w64From32(0x0, 0x1);
    ExpectIntEQ(Dtls13CheckEpoch(ssl, client_hello), SANITY_MSG_E);
    ExpectIntEQ(Dtls13CheckEpoch(ssl, server_hello), SANITY_MSG_E);
    ExpectIntEQ(Dtls13CheckEpoch(ssl, hello_verify_request), SANITY_MSG_E);
    ExpectIntEQ(Dtls13CheckEpoch(ssl, hello_retry_request), SANITY_MSG_E);
    ExpectIntEQ(Dtls13CheckEpoch(ssl, hello_request), SANITY_MSG_E);
    ExpectIntEQ(Dtls13CheckEpoch(ssl, encrypted_extensions), SANITY_MSG_E);
    ExpectIntEQ(Dtls13CheckEpoch(ssl, server_key_exchange), SANITY_MSG_E);
    ExpectIntEQ(Dtls13CheckEpoch(ssl, server_hello_done), SANITY_MSG_E);
    ExpectIntEQ(Dtls13CheckEpoch(ssl, client_key_exchange), SANITY_MSG_E);
    ExpectIntEQ(Dtls13CheckEpoch(ssl, certificate_request), SANITY_MSG_E);
    ExpectIntEQ(Dtls13CheckEpoch(ssl, certificate), SANITY_MSG_E);
    ExpectIntEQ(Dtls13CheckEpoch(ssl, certificate_verify), SANITY_MSG_E);
    ExpectIntEQ(Dtls13CheckEpoch(ssl, finished), SANITY_MSG_E);
    ExpectIntEQ(Dtls13CheckEpoch(ssl, certificate_status), SANITY_MSG_E);
    ExpectIntEQ(Dtls13CheckEpoch(ssl, change_cipher_hs), SANITY_MSG_E);
    ExpectIntEQ(Dtls13CheckEpoch(ssl, key_update), SANITY_MSG_E);
    ExpectIntEQ(Dtls13CheckEpoch(ssl, session_ticket), SANITY_MSG_E);
    ExpectIntEQ(Dtls13CheckEpoch(ssl, end_of_early_data), SANITY_MSG_E);
    ExpectIntEQ(Dtls13CheckEpoch(ssl, message_hash), SANITY_MSG_E);
    ExpectIntEQ(Dtls13CheckEpoch(ssl, no_shake), SANITY_MSG_E);

    wolfSSL_CTX_free(ctx);
    wolfSSL_free(ssl);
#endif
    return EXPECT_RESULT();
}

int test_dtls13_ack_order(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    unsigned char readBuf[50];
    word32 length = 0;
    /* struct {
     *     uint64 epoch;
     *     uint64 sequence_number;
     * } RecordNumber;
     * Big endian */
    static const unsigned char expected_output[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
    };

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    /* Get a populated DTLS object */
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
    /* Clear the buffer of any extra messages */
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(test_ctx.c_len, 0);
    ExpectIntEQ(test_ctx.s_len, 0);

    /* Add seen records */
    ExpectIntEQ(Dtls13RtxAddAck(ssl_c, w64From32(0, 3), w64From32(0, 2)), 0);
    ExpectIntEQ(Dtls13RtxAddAck(ssl_c, w64From32(0, 3), w64From32(0, 0)), 0);
    ExpectIntEQ(Dtls13RtxAddAck(ssl_c, w64From32(0, 3), w64From32(0, 1)), 0);
    ExpectIntEQ(Dtls13RtxAddAck(ssl_c, w64From32(0, 3), w64From32(0, 4)), 0);
    ExpectIntEQ(Dtls13RtxAddAck(ssl_c, w64From32(0, 2), w64From32(0, 0)), 0);
    ExpectIntEQ(Dtls13RtxAddAck(ssl_c, w64From32(0, 3), w64From32(0, 6)), 0);
    ExpectIntEQ(Dtls13RtxAddAck(ssl_c, w64From32(0, 3), w64From32(0, 6)), 0);
    ExpectIntEQ(Dtls13RtxAddAck(ssl_c, w64From32(0, 2), w64From32(0, 1)), 0);
    ExpectIntEQ(Dtls13RtxAddAck(ssl_c, w64From32(0, 2), w64From32(0, 2)), 0);
    ExpectIntEQ(Dtls13RtxAddAck(ssl_c, w64From32(0, 2), w64From32(0, 2)), 0);
    ExpectIntEQ(Dtls13WriteAckMessage(ssl_c, ssl_c->dtls13Rtx.seenRecords,
            &length), 0);

    /* must zero the span reserved for the header to avoid read of uninited
     * data.
     */
    XMEMSET(ssl_c->buffers.outputBuffer.buffer, 0,
            5 /* DTLS13_UNIFIED_HEADER_SIZE */);
    /* N * RecordNumber + 2 extra bytes for length */
    ExpectIntEQ(length, sizeof(expected_output) + 2);
    ExpectNotNull(mymemmem(ssl_c->buffers.outputBuffer.buffer,
            ssl_c->buffers.outputBuffer.bufferSize, expected_output,
            sizeof(expected_output)));

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
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

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && !defined(WOLFSSL_NO_TLS12)
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

int test_dtls_rtx_across_epoch_change(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) &&                           \
    defined(WOLFSSL_DTLS13) && defined(WOLFSSL_DTLS)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    /* Setup DTLS contexts */
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method),
        0);

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
    while (test_ctx.c_msg_count > 1 && EXPECT_SUCCESS()) {
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
