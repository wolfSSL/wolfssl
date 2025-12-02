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

/** Test DTLS 1.3 behavior when server hits WANT_WRITE during HRR
 * The test sets up a DTLS 1.3 connection where the server is forced to
 * return WANT_WRITE when sending the HelloRetryRequest. After the handshake,
 * application data is exchanged in both directions to verify the connection
 * works as expected.
 */
int test_dtls13_hrr_want_write(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    const char msg[] = "hello";
    const int msgLen = sizeof(msg);
    struct test_memio_ctx test_ctx;
    char readBuf[sizeof(msg)];

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method),
        0);

    /* Client sends first ClientHello */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);

    /* Force server to hit WANT_WRITE when producing the HRR */
    test_memio_simulate_want_write(&test_ctx, 0, 1);
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_WRITE);

    /* Allow the server to flush the HRR and proceed */
    test_memio_simulate_want_write(&test_ctx, 0, 0);
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);

    /* Resume the DTLS 1.3 handshake */
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* Verify post-handshake application data in both directions */
    XMEMSET(readBuf, 0, sizeof(readBuf));
    ExpectIntEQ(wolfSSL_write(ssl_c, msg, msgLen), msgLen);
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), msgLen);
    ExpectStrEQ(readBuf, msg);

    XMEMSET(readBuf, 0, sizeof(readBuf));
    ExpectIntEQ(wolfSSL_write(ssl_s, msg, msgLen), msgLen);
    ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), msgLen);
    ExpectStrEQ(readBuf, msg);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13)
struct test_dtls13_wwrite_ctx {
    int want_write;
    struct test_memio_ctx *text_ctx;
};
static int test_dtls13_want_write_send_cb(WOLFSSL *ssl, char *data, int sz, void *ctx)
{
    struct test_dtls13_wwrite_ctx *wwctx = (struct test_dtls13_wwrite_ctx *)ctx;
    wwctx->want_write = !wwctx->want_write;
    if (wwctx->want_write) {
        return WOLFSSL_CBIO_ERR_WANT_WRITE;
    }
    return test_memio_write_cb(ssl, data, sz, wwctx->text_ctx);
}
#endif
/** Test DTLS 1.3 behavior when every other write returns WANT_WRITE
 * The test sets up a DTLS 1.3 connection where both client and server
 * alternate between WANT_WRITE and successful writes. After the handshake,
 * application data is exchanged in both directions to verify the connection
 * works as expected.
 *
 * Data exchanged after the handshake is also tested with simulated WANT_WRITE
 * conditions to ensure the connection remains functional.
 */
int test_dtls13_every_write_want_write(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    const char msg[] = "want-write";
    const int msgLen = sizeof(msg);
    char readBuf[sizeof(msg)];
    struct test_dtls13_wwrite_ctx wwctx_c;
    struct test_dtls13_wwrite_ctx wwctx_s;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method),
        0);

    wwctx_c.want_write = 0;
    wwctx_c.text_ctx = &test_ctx;
    wolfSSL_SetIOWriteCtx(ssl_c, &wwctx_c);
    wolfSSL_SSLSetIOSend(ssl_c, test_dtls13_want_write_send_cb);
    wwctx_s.want_write = 0;
    wwctx_s.text_ctx = &test_ctx;
    wolfSSL_SetIOWriteCtx(ssl_s, &wwctx_s);
    wolfSSL_SSLSetIOSend(ssl_s, test_dtls13_want_write_send_cb);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 20, NULL), 0);

    ExpectTrue(wolfSSL_is_init_finished(ssl_c));
    ExpectTrue(wolfSSL_is_init_finished(ssl_s));

    test_memio_simulate_want_write(&test_ctx, 0, 0);
    test_memio_simulate_want_write(&test_ctx, 1, 0);

    wolfSSL_SetIOWriteCtx(ssl_c, &test_ctx);
    wolfSSL_SSLSetIOSend(ssl_c, test_memio_write_cb);
    wolfSSL_SetIOWriteCtx(ssl_s, &test_ctx);
    wolfSSL_SSLSetIOSend(ssl_s, test_memio_write_cb);

    XMEMSET(readBuf, 0, sizeof(readBuf));
    ExpectIntEQ(wolfSSL_write(ssl_c, msg, msgLen), msgLen);
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), msgLen);
    ExpectStrEQ(readBuf, msg);

    XMEMSET(readBuf, 0, sizeof(readBuf));
    ExpectIntEQ(wolfSSL_write(ssl_s, msg, msgLen), msgLen);
    ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), msgLen);
    ExpectStrEQ(readBuf, msg);

    test_memio_simulate_want_write(&test_ctx, 0, 1);
    XMEMSET(readBuf, 0, sizeof(readBuf));
    ExpectIntEQ(wolfSSL_write(ssl_s, msg, msgLen), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_WRITE);
    test_memio_simulate_want_write(&test_ctx, 0, 0);
    ExpectIntEQ(wolfSSL_write(ssl_s, msg, msgLen), msgLen);
    ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), msgLen);
    ExpectStrEQ(readBuf, msg);

    XMEMSET(readBuf, 0, sizeof(readBuf));
    test_memio_simulate_want_write(&test_ctx, 1, 1);
    ExpectIntEQ(wolfSSL_write(ssl_c, msg, msgLen), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_WRITE);
    test_memio_simulate_want_write(&test_ctx, 1, 0);
    ExpectIntEQ(wolfSSL_write(ssl_c, msg, msgLen), msgLen);
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), msgLen);
    ExpectStrEQ(readBuf, msg);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
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

#if defined(WOLFSSL_DTLS13) && defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_SRTP)
static int test_dtls_srtp_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;
    ExpectIntEQ(wolfSSL_CTX_set_tlsext_use_srtp(ctx, "SRTP_AEAD_AES_256_GCM:"
         "SRTP_AEAD_AES_128_GCM:SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32"),
          0);
    return EXPECT_RESULT();
}

int test_dtls_srtp(void)
{
    EXPECT_DECLS;
    test_ssl_cbf client_cbf;
    test_ssl_cbf server_cbf;

    XMEMSET(&client_cbf, 0, sizeof(client_cbf));
    XMEMSET(&server_cbf, 0, sizeof(server_cbf));

    client_cbf.method = wolfDTLSv1_3_client_method;
    client_cbf.ctx_ready = test_dtls_srtp_ctx_ready;
    server_cbf.method = wolfDTLSv1_3_server_method;
    server_cbf.ctx_ready = test_dtls_srtp_ctx_ready;

    ExpectIntEQ(test_wolfSSL_client_server_nofail_memio(&client_cbf,
        &server_cbf, NULL), TEST_SUCCESS);

    return EXPECT_RESULT();
}
#else
int test_dtls_srtp(void)
{
    EXPECT_DECLS;
    return EXPECT_RESULT();
}
#endif

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
