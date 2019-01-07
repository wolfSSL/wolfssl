/* client-tls-callback.c
 *
 * Copyright (C) 2006-2018 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */
/* the usual suspects */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

/* ESP specific */
#include "wifi_connect.h"

/* socket includes */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

/* wolfSSL */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/certs_test.h>

#ifdef WOLFSSL_TRACK_MEMORY
    #include <wolfssl/wolfcrypt/mem_track.h>
#endif

const char *TAG = "tls_client";

void tls_smp_client_task()
{
    int ret;
    int sockfd;
    struct sockaddr_in servAddr;
    char buff[256];
    size_t len;

    /* declare wolfSSL objects */
    WOLFSSL_CTX *ctx;
    WOLFSSL *ssl;

   WOLFSSL_ENTER("tls_smp_client_task");

#ifdef DEBUG_WOLFSSL
   WOLFSSL_MSG("Debug ON");
   wolfSSL_Debugging_ON();
#endif
    /* Initialize wolfSSL */
    wolfSSL_Init();

    /* Create a socket that uses an internet IPv4 address,
     * Sets the socket to be stream based (TCP),
     * 0 means choose the default protocol. */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        printf("ERROR: failed to create the socket\n");
    }
    /* Create and initialize WOLFSSL_CTX */
    if ((ctx = wolfSSL_CTX_new(wolfSSLv23_client_method())) == NULL) {
        printf("ERROR: failed to create WOLFSSL_CTX\n");
    }
    WOLFSSL_MSG("Loading...cert");
    /* Load client certificates into WOLFSSL_CTX */
    if ((ret = wolfSSL_CTX_load_verify_buffer(ctx, ca_cert_der_2048,
        sizeof_ca_cert_der_2048, WOLFSSL_FILETYPE_ASN1)) != SSL_SUCCESS) {
        printf("ERROR: failed to load %d, please check the file.\n",ret);
    }

    /* Initialize the server address struct with zeros */
    memset(&servAddr, 0, sizeof(servAddr));

    /* Fill in the server address */
    servAddr.sin_family = AF_INET;           /* using IPv4      */
    servAddr.sin_port = htons(DEFAULT_PORT); /* on DEFAULT_PORT */

    /* Get the server IPv4 address from the command line call */
    WOLFSSL_MSG("inet_pton");
    if ((ret = inet_pton(AF_INET, TLS_SMP_TARGET_HOST,
             &servAddr.sin_addr)) != 1) {
        printf("ERROR: invalid address ret=%d\n", ret);
    }

    /* Connect to the server */
    sprintf(buff, "Connecting to server....%s(port:%d)", TLS_SMP_TARGET_HOST
                                                      , DEFAULT_PORT);
    WOLFSSL_MSG(buff);
    if ((ret = connect(sockfd, (struct sockaddr *)&servAddr,
                                    sizeof(servAddr))) == -1){
        printf("ERROR: failed to connect ret=%d\n", ret);
    }

    WOLFSSL_MSG("Create a WOLFSSL object");
    /* Create a WOLFSSL object */
    if ((ssl = wolfSSL_new(ctx)) == NULL) {
        printf("ERROR: failed to create WOLFSSL object\n");
    }

    /* Attach wolfSSL to the socket */
    wolfSSL_set_fd(ssl, sockfd);

    WOLFSSL_MSG("Connect to wolfSSL on the server side");
    /* Connect to wolfSSL on the server side */
    if (wolfSSL_connect(ssl) != SSL_SUCCESS) {
        printf("ERROR: failed to connect to wolfSSL\n");
    }

    /* Get a message for the server from stdin */
    WOLFSSL_MSG("Message for server: ");
    memset(buff, 0, sizeof(buff));
    sprintf(buff, "message from client\n");
    len = strnlen(buff, sizeof(buff));
    /* Send the message to the server */
    if (wolfSSL_write(ssl, buff, len) != len) {
        printf("ERROR: failed to write\n");
    }

    /* Read the server data into our buff array */
    memset(buff, 0, sizeof(buff));
    if (wolfSSL_read(ssl, buff, sizeof(buff) - 1) == -1) {
        printf("ERROR: failed to read\n");
    }

    /* Print to stdout any data the server sends */
    WOLFSSL_MSG("Server:");
    WOLFSSL_MSG(buff);
    /* Cleanup and return */
    wolfSSL_free(ssl);     /* Free the wolfSSL object                  */
    wolfSSL_CTX_free(ctx); /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();     /* Cleanup the wolfSSL environment          */
    close(sockfd);         /* Close the connection to the server       */
    
    vTaskDelete(NULL);

    return;                /* Return reporting a success               */
}
