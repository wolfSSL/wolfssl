/* async_server.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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

/* TLS server demonstrating asynchronous cryptography features and optionally
 * using the crypto or PK callbacks */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

/* std */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* socket */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#define HAVE_SIGNAL
#ifdef HAVE_SIGNAL
#include <signal.h> /* for catching ctrl+c */
#endif

/* wolfSSL */
#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/ssl.h>
#include <wolfssl/wolfio.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include "examples/async/async_tls.h"

/* Test certificates and keys for RSA and ECC */
#ifndef NO_RSA
    #define CERT_FILE "./certs/server-cert.pem"
    #define KEY_FILE  "./certs/server-key.pem"
    #define CA_FILE   "./certs/client-cert.pem"
#elif defined(HAVE_ECC)
    #define CERT_FILE "./certs/server-ecc.pem"
    #define KEY_FILE  "./certs/ecc-key.pem"
    #define CA_FILE   "./certs/client-ecc-cert.pem"
#else
    #error No authentication algorithm (ECC/RSA)
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
        close(mConnd);           /* Close the connection to the client   */
        mConnd = SOCKET_INVALID;
    }
    if (mSockfd != SOCKET_INVALID) {
        close(mSockfd);          /* Close the socket listening for clients   */
        mSockfd = SOCKET_INVALID;
    }
}
#endif

int server_async_test(int argc, char** argv)
{
    int ret = 0;
    struct sockaddr_in servAddr;
    struct sockaddr_in clientAddr;
    socklen_t          size = sizeof(clientAddr);
    char               buff[TEST_BUF_SZ];
    size_t             len;
    const char*        reply = "I hear ya fa shizzle!\n";
    int                on;
    int                devId = 1; /* anything besides -2 (INVALID_DEVID) */
#ifdef WOLF_CRYPTO_CB
    AsyncTlsCryptoCbCtx      myCtx;
#endif
    int  err;
    char errBuff[WOLFSSL_MAX_ERROR_SZ];

    /* declare wolfSSL objects */
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL*     ssl = NULL;

#ifdef HAVE_SIGNAL
    if ((signal(SIGINT, sig_handler)) == SIG_ERR) {
        fprintf(stderr, "ERROR: failed to listen to SIGINT (errno: %d)\n",errno);
        goto exit;
    }
#endif

    /* Initialize the server address struct with zeros */
    memset(&servAddr, 0, sizeof(servAddr));

    /* Fill in the server address */
    servAddr.sin_family      = AF_INET;             /* using IPv4      */
    servAddr.sin_port        = htons(DEFAULT_PORT); /* on DEFAULT_PORT */
    servAddr.sin_addr.s_addr = INADDR_ANY;          /* from anywhere   */


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

    /*---------------------------------*/
    /* Start of wolfSSL initialization and configuration */
    /*---------------------------------*/
#ifdef DEBUG_WOLFSSL
    wolfSSL_Debugging_ON();
#endif

    /* Initialize wolfSSL */
    if ((ret = wolfSSL_Init()) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to initialize the library\n");
        goto exit;
    }

    /* Create and initialize WOLFSSL_CTX */
    if ((ctx = wolfSSL_CTX_new(wolfSSLv23_server_method())) == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL_CTX\n");
        ret = -1;
        goto exit;
    }

#ifdef WOLF_CRYPTO_CB
    XMEMSET(&myCtx, 0, sizeof(myCtx));
    /* register a devID for crypto callbacks */
    ret = wc_CryptoCb_RegisterDevice(devId, AsyncTlsCryptoCb, &myCtx);
    if (ret != 0) {
        fprintf(stderr, "wc_CryptoCb_RegisterDevice: error %d", ret);
        goto exit;
    }
#endif

    /* register a devID for crypto callbacks */
    wolfSSL_CTX_SetDevId(ctx, devId);

    /* Require mutual authentication */
    wolfSSL_CTX_set_verify(ctx,
        WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    /* Load server certificates into WOLFSSL_CTX */
    if ((ret = wolfSSL_CTX_use_certificate_file(ctx, CERT_FILE,
                                    WOLFSSL_FILETYPE_PEM)) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load %s, please check the file.\n",
                CERT_FILE);
        goto exit;
    }

    /* Load server key into WOLFSSL_CTX */
    if ((ret = wolfSSL_CTX_use_PrivateKey_file(ctx, KEY_FILE,
                                    WOLFSSL_FILETYPE_PEM)) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load %s, please check the file.\n",
                KEY_FILE);
        goto exit;
    }

    /* Load client certificate as "trusted" into WOLFSSL_CTX */
    if ((ret = wolfSSL_CTX_load_verify_locations(ctx, CA_FILE, NULL))
         != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load %s, please check the file.\n",
                CA_FILE);
        goto exit;
    }

    /* Continue to accept clients until mShutdown is issued */
    while (!mShutdown) {
        printf("Waiting for a connection...\n");

        /* Accept client connections */
        if ((mConnd = accept(mSockfd, (struct sockaddr*)&clientAddr, &size))
            == -1) {
            fprintf(stderr, "ERROR: failed to accept the connection\n\n");
            ret = -1; goto exit;
        }

        /* Create a WOLFSSL object */
        if ((ssl = wolfSSL_new(ctx)) == NULL) {
            fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
            ret = -1; goto exit;
        }

        /* Attach wolfSSL to the socket */
        wolfSSL_set_fd(ssl, mConnd);

        /* Establish TLS connection */
    #ifdef WOLFSSL_ASYNC_CRYPT
        err = 0; /* Reset error */
    #endif
        do {
        #ifdef WOLFSSL_ASYNC_CRYPT
            if (err == WC_NO_ERR_TRACE(WC_PENDING_E)) {
                ret = wolfSSL_AsyncPoll(ssl, WOLF_POLL_FLAG_CHECK_HW);
                if (ret < 0)
                    break;
            }
        #endif
            ret = wolfSSL_accept(ssl);
            err = wolfSSL_get_error(ssl, 0);
        } while (err == WC_NO_ERR_TRACE(WC_PENDING_E));
        if (ret != WOLFSSL_SUCCESS) {
            fprintf(stderr, "wolfSSL_accept error %d: %s\n",
                err, wolfSSL_ERR_error_string(err, errBuff));
            goto exit;
        }


        printf("Client connected successfully\n");

        /* Read the client data into our buff array */
        memset(buff, 0, sizeof(buff));
    #ifdef WOLFSSL_ASYNC_CRYPT
        err = 0; /* Reset error */
    #endif
        do {
        #ifdef WOLFSSL_ASYNC_CRYPT
            if (err == WC_NO_ERR_TRACE(WC_PENDING_E)) {
                ret = wolfSSL_AsyncPoll(ssl, WOLF_POLL_FLAG_CHECK_HW);
                if (ret < 0)
                    break;
            }
        #endif
            ret = wolfSSL_read(ssl, buff, sizeof(buff)-1);
            err = wolfSSL_get_error(ssl, 0);
        } while (err == WC_NO_ERR_TRACE(WC_PENDING_E));
        if (ret < 0) {
            fprintf(stderr, "wolfSSL_read error %d: %s\n",
                    err, wolfSSL_ERR_error_string(err, errBuff));
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
    #ifdef WOLFSSL_ASYNC_CRYPT
        err = 0; /* Reset error */
    #endif
        do {
        #ifdef WOLFSSL_ASYNC_CRYPT
            if (err == WC_NO_ERR_TRACE(WC_PENDING_E)) {
                ret = wolfSSL_AsyncPoll(ssl, WOLF_POLL_FLAG_CHECK_HW);
                if (ret < 0)
                    break;
            }
        #endif
            ret = wolfSSL_write(ssl, buff, (int)len);
            err = wolfSSL_get_error(ssl, 0);
        } while (err == WC_NO_ERR_TRACE(WC_PENDING_E));
        if (ret != (int)len) {
            fprintf(stderr, "wolfSSL_write error %d: %s\n",
                    err, wolfSSL_ERR_error_string(err, errBuff));
            goto exit;
        }

        /* Cleanup after this connection */
        wolfSSL_shutdown(ssl);
        if (ssl) {
            wolfSSL_free(ssl);    /* Free the wolfSSL object                */
            ssl = NULL;
        }
        if (mConnd != SOCKET_INVALID) {
            close(mConnd);        /* Close the connection to the client     */
            mConnd = SOCKET_INVALID;
        }
    }

    printf("Shutdown complete\n");

exit:
    /* Cleanup and return */
    if (ssl)
        wolfSSL_free(ssl);        /* Free the wolfSSL object                */
    if (mConnd != SOCKET_INVALID) {
        close(mConnd);            /* Close the connection to the client     */
        mConnd = SOCKET_INVALID;
    }
    if (mSockfd != SOCKET_INVALID) {
        close(mSockfd);           /* Close the socket listening for clients */
        mSockfd = SOCKET_INVALID;
    }
    if (ctx)
        wolfSSL_CTX_free(ctx);    /* Free the wolfSSL context object        */
    wolfSSL_Cleanup();            /* Cleanup the wolfSSL environment        */

    (void)argc;
    (void)argv;

    return ret;
}

#ifndef NO_MAIN_DRIVER
int main(int argc, char** argv)
{
    return server_async_test(argc, argv);
}
#endif /* !NO_MAIN_DRIVER */
