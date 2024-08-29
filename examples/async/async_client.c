/* async_client.c
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

/* TLS client demonstrating asynchronous cryptography features and optionally
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
    #define CERT_FILE "./certs/client-cert.pem"
    #define KEY_FILE  "./certs/client-key.pem"
    #define CA_FILE   "./certs/ca-cert.pem"
#elif defined(HAVE_ECC)
    #define CERT_FILE "./certs/client-ecc-cert.pem"
    #define KEY_FILE  "./certs/ecc-client-key.pem"
    #define CA_FILE   "./certs/ca-ecc-cert.pem"
#else
    #error No authentication algorithm (ECC/RSA)
#endif

int client_async_test(int argc, char** argv)
{
    int ret = 0;
    int                sockfd = SOCKET_INVALID;
    struct sockaddr_in servAddr;
    char               buff[TEST_BUF_SZ];
    size_t             len;
    int                devId = 1; /* anything besides -2 (INVALID_DEVID) */
#ifdef WOLF_CRYPTO_CB
    AsyncTlsCryptoCbCtx      myCtx;
#endif
    int  err;
    char errBuff[WOLFSSL_MAX_ERROR_SZ];

    /* declare wolfSSL objects */
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL*     ssl = NULL;

    /* Check for proper calling convention */
    if (argc != 2) {
        printf("usage: %s <IPv4 address>\n", argv[0]);
        return 0;
    }

    /* Create a socket that uses an internet IPv4 address,
     * Sets the socket to be stream based (TCP),
     * 0 means choose the default protocol. */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "ERROR: failed to create the socket\n");
        ret = -1; goto exit;
    }

    /* Initialize the server address struct with zeros */
    memset(&servAddr, 0, sizeof(servAddr));

    /* Fill in the server address */
    servAddr.sin_family = AF_INET;             /* using IPv4      */
    servAddr.sin_port   = htons(DEFAULT_PORT); /* on DEFAULT_PORT */

    /* Get the server IPv4 address from the command line call */
    if (inet_pton(AF_INET, argv[1], &servAddr.sin_addr) != 1) {
        fprintf(stderr, "ERROR: invalid address\n");
        ret = -1; goto exit;
    }

    /* Connect to the server */
    if ((ret = connect(sockfd, (struct sockaddr*) &servAddr, sizeof(servAddr)))
         == -1) {
        fprintf(stderr, "ERROR: failed to connect\n");
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
    if ((ctx = wolfSSL_CTX_new(wolfSSLv23_client_method())) == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL_CTX\n");
        ret = -1; goto exit;
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

    /* Load client certificate into WOLFSSL_CTX */
    if ((ret = wolfSSL_CTX_use_certificate_file(ctx, CERT_FILE, WOLFSSL_FILETYPE_PEM))
        != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load %s, please check the file.\n",
                CERT_FILE);
        goto exit;
    }

    /* Load client key into WOLFSSL_CTX */
    if ((ret = wolfSSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, WOLFSSL_FILETYPE_PEM))
        != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load %s, please check the file.\n",
                KEY_FILE);
        goto exit;
    }

    /* Load CA certificate into WOLFSSL_CTX */
    if ((ret = wolfSSL_CTX_load_verify_locations(ctx, CA_FILE, NULL))
         != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load %s, please check the file.\n",
                CA_FILE);
        goto exit;
    }

    /* Create a WOLFSSL object */
    if ((ssl = wolfSSL_new(ctx)) == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
        ret = -1; goto exit;
    }

    /* Attach wolfSSL to the socket */
    if ((ret = wolfSSL_set_fd(ssl, sockfd)) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to set the file descriptor\n");
        goto exit;
    }

    /* Connect to wolfSSL on the server side */
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
        ret = wolfSSL_connect(ssl);
        err = wolfSSL_get_error(ssl, 0);
    } while (err == WC_NO_ERR_TRACE(WC_PENDING_E));
    if (ret != WOLFSSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_connect error %d: %s\n",
                err, wolfSSL_ERR_error_string(err, errBuff));
        goto exit;
    }

    /* Get a message for the server from stdin */
    printf("Message for server: ");
    memset(buff, 0, sizeof(buff));
    if (fgets(buff, sizeof(buff), stdin) == NULL) {
        fprintf(stderr, "ERROR: failed to get message for server\n");
        ret = -1; goto exit;
    }
    len = strnlen(buff, sizeof(buff));

    /* Send the message to the server */
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

    /* Read the server data into our buff array */
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

    /* Print to stdout any data the server sends */
    printf("Server: %s\n", buff);

    /* Return reporting a success */
    ret = 0;

exit:
    /* Cleanup and return */
    if (sockfd != SOCKET_INVALID)
        close(sockfd);          /* Close the connection to the server       */
    if (ssl)
        wolfSSL_free(ssl);      /* Free the wolfSSL object                  */
    if (ctx)
        wolfSSL_CTX_free(ctx);  /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();          /* Cleanup the wolfSSL environment          */

    (void)argc;
    (void)argv;

    return ret;
}

#ifndef NO_MAIN_DRIVER
int main(int argc, char** argv)
{
    return client_async_test(argc, argv);
}
#endif /* !NO_MAIN_DRIVER */
