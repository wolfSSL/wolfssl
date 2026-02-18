/* async_server.c
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

/* TLS server demonstrating asynchronous cryptography features and non-blocking
 * operation using WOLFSSL_USER_IO callbacks. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

/* std */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

/* socket */
#ifndef NET_USER_HEADER
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#define HAVE_SIGNAL
#ifdef HAVE_SIGNAL
#include <signal.h> /* for catching ctrl+c */
#endif

/* wolfSSL */
#ifdef WOLFSSL_USER_SETTINGS
    #include "user_settings.h"
#else
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfio.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/certs_test.h>
#include "examples/async/async_tls.h"

#if ASYNC_ECC_ONLY
    #ifndef HAVE_ECC
        #error ASYNC_ECC_ONLY requires HAVE_ECC
    #endif
#else
    #ifndef NO_RSA
        #error RSA not supported in this example configuration
    #endif
#endif

static int mSockfd = SOCKET_INVALID;
static int mConnd = SOCKET_INVALID;
static int mShutdown = 0;

#ifdef HAVE_SIGNAL
static void sig_handler(const int sig)
{
#ifdef DEBUG_WOLFSSL
    fprintf(stderr, "SIGINT handled = %d.\n", sig);
#else
    (void)sig;
#endif

    mShutdown = 1;
    if (mConnd != SOCKET_INVALID) {
        NET_CLOSE(mConnd);
        mConnd = SOCKET_INVALID;
    }
    if (mSockfd != SOCKET_INVALID) {
        NET_CLOSE(mSockfd);
        mSockfd = SOCKET_INVALID;
    }
}
#endif

/* ------------------------------------------------------------------ */
/* POSIX transport helpers (replace with your BSP/port layer).         */
/* ------------------------------------------------------------------ */
#ifndef NET_USER_HEADER
static int posix_set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}
#endif

/* ------------------------------------------------------------------ */
/* WOLFSSL_USER_IO callbacks.                                          */
/* ------------------------------------------------------------------ */
static void usage(const char* prog)
{
    printf("usage: %s [--ecc|--x25519] [--mutual] [--tls12] [port]\n", prog);
}

static const char* group_name(word16 group)
{
    switch (group) {
        case WOLFSSL_ECC_SECP256R1:
            return "secp256r1";
        case WOLFSSL_ECC_X25519:
            return "x25519";
        default:
            return "unknown";
    }
}

static int parse_server_args(int argc, char** argv, int* port, word16* group,
    int* mutual, int* tls12)
{
    int i;
    int port_set = 0;

    *port = DEFAULT_PORT;
    *group = WOLFSSL_ECC_SECP256R1;
    *mutual = 0;
    *tls12 = 0;

    for (i = 1; i < argc; i++) {
        if (XSTRCMP(argv[i], "--ecc") == 0) {
            *group = WOLFSSL_ECC_SECP256R1;
        }
        else if (XSTRCMP(argv[i], "--x25519") == 0) {
            *group = WOLFSSL_ECC_X25519;
        }
        else if (XSTRCMP(argv[i], "--mutual") == 0) {
            *mutual = 1;
        }
        else if (XSTRCMP(argv[i], "--tls12") == 0) {
            *tls12 = 1;
        }
        else if (XSTRCMP(argv[i], "--help") == 0) {
            return -1;
        }
        else if (!port_set) {
            *port = atoi(argv[i]);
            port_set = 1;
        }
        else {
            return -1;
        }
    }

    return 0;
}

int server_async_test(int argc, char** argv)
{
    int ret = -1;
    struct sockaddr_in servAddr;
    struct sockaddr_in clientAddr;
    socklen_t          size = sizeof(clientAddr);
    char               buff[TEST_BUF_SZ];
    size_t             len;
    const char*        reply = "I hear ya fa shizzle!\n";
    int                on;
    int                port = DEFAULT_PORT;
    word16             group = WOLFSSL_ECC_SECP256R1;
    int                err = 0;
    const char*        mode = NULL;
    int                mutual = 0;
    int                tls12 = 0;
#ifdef WOLFSSL_ASYNC_CRYPT
    int devId = INVALID_DEVID;
#endif
#ifdef WOLFSSL_DEBUG_NONBLOCK
    int wouldblock_count = 0;
    int pending_count = 0;
#endif
#ifdef WOLFSSL_STATIC_MEMORY
    static byte memory[300000];
    static byte memoryIO[34500];
    #if !defined(WOLFSSL_STATIC_MEMORY_LEAN)
    WOLFSSL_MEM_CONN_STATS ssl_stats;
    #endif
#endif

    /* declare wolfSSL objects */
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL*     ssl = NULL;

#ifdef HAVE_SIGNAL
    if ((signal(SIGINT, sig_handler)) == SIG_ERR) {
        fprintf(stderr, "ERROR: failed to listen to SIGINT (errno: %d)\n",errno);
        goto exit;
    }
#endif

    if (parse_server_args(argc, argv, &port, &group, &mutual, &tls12) != 0) {
        usage(argv[0]);
        return 0;
    }
    mode = group_name(group);
    printf("Async server mode: %s, TLS %s%s\n", mode,
        tls12 ? "1.2" : "1.3", mutual ? ", mutual auth" : "");

    /* Initialize the server address struct with zeros */
    memset(&servAddr, 0, sizeof(servAddr));

    /* Fill in the server address */
    servAddr.sin_family      = AF_INET;         /* using IPv4      */
    servAddr.sin_port        = htons(port);
    servAddr.sin_addr.s_addr = INADDR_ANY;      /* from anywhere   */

    /* Create a socket that uses an internet IPv4 address,
     * Sets the socket to be stream based (TCP),
     * 0 means choose the default protocol. */
    if ((mSockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "ERROR: failed to create the socket\n");
        goto exit;
    }

    /* make sure server is setup for reuse addr/port */
    on = 1;
    if (setsockopt(mSockfd, SOL_SOCKET, SO_REUSEADDR,
            (char*)&on, (socklen_t)sizeof(on)) != 0) {
        fprintf(stderr, "ERROR: failed to set SO_REUSEADDR (errno: %d)\n",errno);
        goto exit;
    }
#ifdef SO_REUSEPORT
    if (setsockopt(mSockfd, SOL_SOCKET, SO_REUSEPORT,
               (char*)&on, (socklen_t)sizeof(on)) != 0) {
        fprintf(stderr, "ERROR: failed to set SO_REUSEPORT (errno: %d)\n",errno);
        goto exit;
    }
#endif

    /* Bind the server socket to our port */
    if (bind(mSockfd, (struct sockaddr*)&servAddr, sizeof(servAddr)) == -1) {
        fprintf(stderr, "ERROR: failed to bind\n");
        goto exit;
    }

    /* Listen for a new connection, allow 5 pending connections */
    if (listen(mSockfd, 5) == -1) {
        fprintf(stderr, "ERROR: failed to listen\n");
        goto exit;
    }
    {
        const char* ready = getenv(WOLFSSL_ASYNC_READYFILE_ENV);
        if (ready != NULL) {
            (void)async_readyfile_touch(ready);
        }
    }

    /*---------------------------------*/
    /* Start of wolfSSL initialization and configuration */
    /*---------------------------------*/
#ifdef DEBUG_WOLFSSL
    wolfSSL_Debugging_ON();
#endif

    /* Initialize wolfSSL */
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to initialize the library\n");
        goto exit;
    }
#ifdef WOLFSSL_ASYNC_CRYPT
    if (wolfAsync_DevOpenThread(&devId, NULL) != 0) {
        goto exit;
    }
#endif

    /* Create and initialize WOLFSSL_CTX */
#ifdef WOLFSSL_STATIC_MEMORY
    {
        wolfSSL_method_func method;
    #ifndef WOLFSSL_NO_TLS12
        if (tls12)
            method = wolfTLSv1_2_server_method_ex;
        else
    #endif
            method = wolfSSLv23_server_method_ex;
        if (wolfSSL_CTX_load_static_memory(&ctx, method, memory,
                sizeof(memory), 0, 1) != WOLFSSL_SUCCESS) {
            fprintf(stderr, "ERROR: unable to load static memory\n");
            goto exit;
        }
        if (wolfSSL_CTX_load_static_memory(&ctx, NULL, memoryIO,
                sizeof(memoryIO),
                WOLFMEM_IO_POOL_FIXED | WOLFMEM_TRACK_STATS, 1)
                != WOLFSSL_SUCCESS) {
            fprintf(stderr, "ERROR: unable to load static IO memory\n");
            goto exit;
        }
    }
#else
    #ifndef WOLFSSL_NO_TLS12
    if (tls12)
        ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method());
    else
    #endif
        ctx = wolfSSL_CTX_new(wolfSSLv23_server_method());
#endif /* WOLFSSL_STATIC_MEMORY */
    if (ctx == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL_CTX\n");
        ret = -1;
        goto exit;
    }
#ifdef WOLFSSL_ASYNC_CRYPT
    wolfSSL_CTX_SetDevId(ctx, devId);
#endif

    wolfSSL_SetIORecv(ctx, NET_IO_RECV_CB);
    wolfSSL_SetIOSend(ctx, NET_IO_SEND_CB);

    if (group == WOLFSSL_ECC_X25519) {
    #ifdef HAVE_ED25519
        ret = wolfSSL_CTX_use_certificate_buffer(ctx, server_ed25519_cert,
            sizeof_server_ed25519_cert, WOLFSSL_FILETYPE_ASN1);
        if (ret != WOLFSSL_SUCCESS) {
            fprintf(stderr,
                "ERROR: failed to load ED25519 server cert buffer.\n");
            goto exit;
        }

        ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx, server_ed25519_key,
            sizeof_server_ed25519_key, WOLFSSL_FILETYPE_ASN1);
        if (ret != WOLFSSL_SUCCESS) {
            fprintf(stderr,
                "ERROR: failed to load ED25519 server key buffer.\n");
            goto exit;
        }

        if (mutual) {
            /* client-ed25519 is self-signed, so load it as its own CA */
            ret = wolfSSL_CTX_load_verify_buffer(ctx, client_ed25519_cert,
                sizeof_client_ed25519_cert, WOLFSSL_FILETYPE_ASN1);
            if (ret != WOLFSSL_SUCCESS) {
                fprintf(stderr,
                    "ERROR: failed to load ED25519 client CA cert.\n");
                goto exit;
            }
        }
    #else
        fprintf(stderr, "ERROR: --x25519 requires HAVE_ED25519 for certs\n");
        goto exit;
    #endif
    }
    else {
        ret = wolfSSL_CTX_use_certificate_buffer(ctx, serv_ecc_der_256,
            sizeof_serv_ecc_der_256, WOLFSSL_FILETYPE_ASN1);
        if (ret != WOLFSSL_SUCCESS) {
            fprintf(stderr, "ERROR: failed to load ECC server cert buffer.\n");
            goto exit;
        }

        ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx, ecc_key_der_256,
            sizeof_ecc_key_der_256, WOLFSSL_FILETYPE_ASN1);
        if (ret != WOLFSSL_SUCCESS) {
            fprintf(stderr, "ERROR: failed to load ECC server key buffer.\n");
            goto exit;
        }

        if (mutual) {
            /* client-ecc-cert is self-signed, so load it as its own CA */
            ret = wolfSSL_CTX_load_verify_buffer(ctx, cliecc_cert_der_256,
                sizeof_cliecc_cert_der_256, WOLFSSL_FILETYPE_ASN1);
            if (ret != WOLFSSL_SUCCESS) {
                fprintf(stderr,
                    "ERROR: failed to load ECC client CA cert.\n");
                goto exit;
            }
        }
    }

    if (mutual) {
        wolfSSL_CTX_set_verify(ctx,
            WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    }
    else {
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
    }

    /* Continue to accept clients until mShutdown is issued */
    while (!mShutdown) {
        printf("Waiting for a connection...\n");

        /* Accept client connections */
        if ((mConnd = NET_ACCEPT(mSockfd,
            (struct sockaddr*)&clientAddr, &size))
            == -1) {
            fprintf(stderr, "ERROR: failed to accept the connection\n\n");
            ret = -1; goto exit;
        }
        if (NET_SET_NONBLOCKING(mConnd) != 0) {
            fprintf(stderr, "ERROR: failed to set non-blocking socket\n");
            ret = -1; goto exit;
        }

        /* Create a WOLFSSL object */
        if ((ssl = wolfSSL_new(ctx)) == NULL) {
            fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
            ret = -1; goto exit;
        }

        wolfSSL_SetIOReadCtx(ssl, (void*)(intptr_t)mConnd);
        wolfSSL_SetIOWriteCtx(ssl, (void*)(intptr_t)mConnd);

        /* UseKeyShare is TLS 1.3 only */
        if (!tls12) {
            for (;;) {
                ret = wolfSSL_UseKeyShare(ssl, group);
                if (ret == WOLFSSL_SUCCESS) {
                    break;
                }
                if (ret == WC_NO_ERR_TRACE(WC_PENDING_E)) {
#ifdef WOLFSSL_DEBUG_NONBLOCK
                    pending_count++;
#endif
#ifdef WOLFSSL_ASYNC_CRYPT
                    if (wolfSSL_AsyncPoll(ssl, WOLF_POLL_FLAG_CHECK_HW) < 0) {
                        goto exit;
                    }
#endif
                    continue;
                }
                goto exit;
            }
        }

        /* Establish TLS connection */
        for (;;) {
            ret = wolfSSL_accept(ssl);
            if (ret == WOLFSSL_SUCCESS) {
                break;
            }
            err = wolfSSL_get_error(ssl, 0);
            if (err == WC_NO_ERR_TRACE(WC_PENDING_E) ||
                err == WOLFSSL_ERROR_WANT_READ ||
                err == WOLFSSL_ERROR_WANT_WRITE) {
                if (err == WC_NO_ERR_TRACE(WC_PENDING_E)) {
#ifdef WOLFSSL_DEBUG_NONBLOCK
                    pending_count++;
#endif
#ifdef WOLFSSL_ASYNC_CRYPT
                    if (wolfSSL_AsyncPoll(ssl, WOLF_POLL_FLAG_CHECK_HW) < 0) {
                        goto exit;
                    }
#endif
                }
                else {
#ifdef WOLFSSL_DEBUG_NONBLOCK
                    wouldblock_count++;
#endif
                }
                continue;
            }
            fprintf(stderr, "ERROR: wolfSSL_accept failed: %d (%s)\n",
                err, wolfSSL_ERR_reason_error_string(err));
            goto exit;
        }

        {
            const char* cipher = wolfSSL_get_cipher_name(ssl);
            const char* curve = wolfSSL_get_curve_name(ssl);
            printf("Negotiated cipher: %s\n",
                cipher != NULL ? cipher : "unknown");
            printf("Negotiated group: %s\n",
                curve != NULL ? curve : "unknown");
        }
        printf("Client connected successfully\n");

        /* Read the client data into our buff array */
        memset(buff, 0, sizeof(buff));
        for (;;) {
            ret = wolfSSL_read(ssl, buff, sizeof(buff) - 1);
            if (ret > 0) {
                break;
            }
            err = wolfSSL_get_error(ssl, 0);
            if (err == WC_NO_ERR_TRACE(WC_PENDING_E) ||
                err == WOLFSSL_ERROR_WANT_READ ||
                err == WOLFSSL_ERROR_WANT_WRITE) {
                if (err == WC_NO_ERR_TRACE(WC_PENDING_E)) {
#ifdef WOLFSSL_DEBUG_NONBLOCK
                    pending_count++;
#endif
#ifdef WOLFSSL_ASYNC_CRYPT
                    if (wolfSSL_AsyncPoll(ssl, WOLF_POLL_FLAG_CHECK_HW) < 0) {
                        goto exit;
                    }
#endif
                }
                else {
#ifdef WOLFSSL_DEBUG_NONBLOCK
                    wouldblock_count++;
#endif
                }
                continue;
            }
            goto exit;
        }

        /* Print to stdout any data the client sends */
        printf("Client: %s\n", buff);

        /* Check for server shutdown command */
        if (strncmp(buff, "shutdown", 8) == 0) {
            printf("Shutdown command issued!\n");
            mShutdown = 1;
        }

        /* Write our reply into buff */
        memset(buff, 0, sizeof(buff));
        memcpy(buff, reply, strlen(reply));
        len = strnlen(buff, sizeof(buff));

        /* Reply back to the client */
        for (;;) {
            ret = wolfSSL_write(ssl, buff, (int)len);
            if (ret > 0) {
                break;
            }
            err = wolfSSL_get_error(ssl, 0);
            if (err == WC_NO_ERR_TRACE(WC_PENDING_E) ||
                err == WOLFSSL_ERROR_WANT_READ ||
                err == WOLFSSL_ERROR_WANT_WRITE) {
                if (err == WC_NO_ERR_TRACE(WC_PENDING_E)) {
#ifdef WOLFSSL_DEBUG_NONBLOCK
                    pending_count++;
#endif
#ifdef WOLFSSL_ASYNC_CRYPT
                    if (wolfSSL_AsyncPoll(ssl, WOLF_POLL_FLAG_CHECK_HW) < 0) {
                        goto exit;
                    }
#endif
                }
                else {
#ifdef WOLFSSL_DEBUG_NONBLOCK
                    wouldblock_count++;
#endif
                }
                continue;
            }
            goto exit;
        }

#ifdef WOLFSSL_DEBUG_NONBLOCK
        printf("WANT_READ/WRITE count: %d\n", wouldblock_count);
        printf("WC_PENDING_E count: %d\n", pending_count);
#endif

        /* Cleanup after this connection */
#if defined(WOLFSSL_STATIC_MEMORY) && !defined(WOLFSSL_STATIC_MEMORY_LEAN)
        if (ssl != NULL &&
                wolfSSL_is_static_memory(ssl, &ssl_stats) == 1) {
            fprintf(stderr, "peak connection memory = %d\n",
                ssl_stats.peakMem);
            fprintf(stderr, "current memory in use  = %d\n",
                ssl_stats.curMem);
            fprintf(stderr, "peak connection allocs = %d\n",
                ssl_stats.peakAlloc);
            fprintf(stderr, "total connection allocs   = %d\n",
                ssl_stats.totalAlloc);
            fprintf(stderr, "total connection frees    = %d\n",
                ssl_stats.totalFr);
        }
#endif
        wolfSSL_shutdown(ssl);
        if (ssl) {
            wolfSSL_free(ssl);
            ssl = NULL;
        }
        if (mConnd != SOCKET_INVALID) {
            NET_CLOSE(mConnd);
            mConnd = SOCKET_INVALID;
        }
    }

    printf("Shutdown complete\n");
#ifdef WOLFSSL_DEBUG_NONBLOCK
    printf("WANT_READ/WRITE count: %d\n", wouldblock_count);
    printf("WC_PENDING_E count: %d\n", pending_count);
#endif
    ret = 0;

exit:
    /* Cleanup and return */
    if (ssl)
        wolfSSL_free(ssl);
    if (mConnd != SOCKET_INVALID) {
        NET_CLOSE(mConnd);
        mConnd = SOCKET_INVALID;
    }
    if (mSockfd != SOCKET_INVALID) {
        NET_CLOSE(mSockfd);
        mSockfd = SOCKET_INVALID;
    }
    if (ctx)
        wolfSSL_CTX_free(ctx);
#ifdef WOLFSSL_ASYNC_CRYPT
    if (devId != INVALID_DEVID) {
        wolfAsync_DevClose(&devId);
    }
#endif
    {
        const char* ready = getenv(WOLFSSL_ASYNC_READYFILE_ENV);
        if (ready != NULL) {
            async_readyfile_clear(ready);
        }
    }
    wolfSSL_Cleanup();

    return ret;
}

#ifndef NO_MAIN_DRIVER
int main(int argc, char** argv)
{
    return server_async_test(argc, argv);
}
#endif /* !NO_MAIN_DRIVER */
