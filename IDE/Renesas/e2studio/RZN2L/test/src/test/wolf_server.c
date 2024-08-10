/* wolf_server.c
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
#include "wolfssl_demo.h"

#if defined(TLS_SERVER)

#include <stdio.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/ssl.h"
#include "wolfssl/certs_test.h"
#include "wolfssl_demo.h"

WOLFSSL_CTX *server_ctx = NULL;

void wolfSSL_TLS_server_init()
{

    int ret;

    #if defined(USE_CERT_BUFFERS_256)
        const unsigned char *cert       = serv_ecc_der_256;
        #define  sizeof_cert sizeof_serv_ecc_der_256
        const unsigned char *key        = ecc_key_der_256;
        #define  sizeof_key  sizeof_serv_ecc_der_256
        const unsigned char *clientCert = cliecc_cert_der_256;
        #define  sizeof_clicert sizeof_cliecc_cert_der_256
    #else
        const unsigned char *cert       = server_cert_der_2048;
        #define sizeof_cert sizeof_server_cert_der_2048
        const unsigned char *key        = server_key_der_2048;
        #define  sizeof_key sizeof_server_key_der_2048
        const unsigned char *clientCert = client_cert_der_2048;
        #define  sizeof_clicert sizeof_client_cert_der_2048
    #endif

    wolfSSL_Init();

    #ifdef DEBUG_WOLFSSL
        wolfSSL_Debugging_ON();
    #endif

    /* Create and initialize WOLFSSL_CTX */
    if ((server_ctx = wolfSSL_CTX_new(
            wolfSSLv23_server_method_ex((void *)NULL))) == NULL) {
        printf("ERROR: failed to create WOLFSSL_CTX\n");
        return;
    }

    ret = wolfSSL_CTX_use_certificate_buffer(server_ctx, cert,
                                         sizeof_cert, SSL_FILETYPE_ASN1);
    if (ret != SSL_SUCCESS) {
        printf("Error %d loading server-cert!\n", ret);
        return;
    }

    /* Load server key into WOLFSSL_CTX */
    ret = wolfSSL_CTX_use_PrivateKey_buffer(server_ctx, key, sizeof_key,
                                                    SSL_FILETYPE_ASN1);
    if (ret != SSL_SUCCESS) {
        printf("Error %d loading server-key!\n", ret);
        return;
    }

    if (1) {
        wolfSSL_CTX_set_verify(server_ctx, WOLFSSL_VERIFY_PEER |
                            WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);
        if (wolfSSL_CTX_load_verify_buffer(server_ctx, clientCert,
                                           sizeof_clicert,
                                           SSL_FILETYPE_ASN1) != SSL_SUCCESS)
            printf("can't load ca file, Please run from wolfSSL home dir\n");
   }
}

int wolfSSL_TLS_server_do(void *pvParam)
{
    int ret;
    WOLFSSL *ssl = NULL;
    word32  len;
    #define BUFF_SIZE 256
    char buff[BUFF_SIZE];

    TestInfo* p = (TestInfo*)pvParam;
    WOLFSSL_CTX *ctx = (WOLFSSL_CTX *)p->ctx;;

    /* FreeRTOS+TCP parameters and objects */
    struct freertos_sockaddr xClient, xBindAddress;
    Socket_t xListeningSocket, xConnectedSocket;
    socklen_t xSize = sizeof(xClient);
    const BaseType_t xBacklog = 1; /* Max number of connections */
    static const TickType_t xReceiveTimeOut = portMAX_DELAY;

    /* Send/Receive Message */
    const char *reply = "I hear ya fa shizzle!\n";
    len = (word32)XSTRLEN(*reply);

    /* Attempt to open the socket. */
    xListeningSocket = FreeRTOS_socket(FREERTOS_AF_INET,
                                    FREERTOS_SOCK_STREAM,
                                    FREERTOS_IPPROTO_TCP);
    configASSERT(xListeningSocket != FREERTOS_INVALID_SOCKET);

    /* Set a time out so accept() will just wait for a connection. */
    FreeRTOS_setsockopt(xListeningSocket, 0,
    FREERTOS_SO_RCVTIMEO, &xReceiveTimeOut, sizeof(xReceiveTimeOut));

    xBindAddress.sin_port = (uint16_t) DEFAULT_PORT;
    xBindAddress.sin_port = FreeRTOS_htons(xBindAddress.sin_port);

    configASSERT(xListeningSocket != FREERTOS_INVALID_SOCKET);

    ret = FreeRTOS_bind(xListeningSocket, &xBindAddress, sizeof(xBindAddress));
    if (ret == FR_SOCKET_SUCCESS)
        ret = FreeRTOS_listen(xListeningSocket, xBacklog);

    if (ret != FR_SOCKET_SUCCESS) {
        printf("Error [%d]: FreeRTOS_bind.\n",ret);
        goto out;
    }

     while (1) {
        ret = WOLFSSL_FAILURE;
        xConnectedSocket = FreeRTOS_accept(xListeningSocket, &xClient, &xSize);
        configASSERT(xConnectedSocket != FREERTOS_INVALID_SOCKET);

        if((ssl = wolfSSL_new(ctx)) == NULL) {
            printf("ERROR: failed wolfSSL_new\n");
            goto out;
        }
        /* Attach wolfSSL to the socket */
        ret = wolfSSL_set_fd(ssl, (int) xConnectedSocket);
        /* Establish TLS connection */
        if (ret != WOLFSSL_SUCCESS) {
            printf("Error [%d]: wolfSSL_set_fd.\n",ret);
            goto out;
        }

        if (wolfSSL_accept(ssl) < 0) {
            printf("ERROR: SSL Accept(%d)\n", wolfSSL_get_error(ssl, 0));
            goto out;
        }


        if ((len = wolfSSL_read(ssl, buff, sizeof(buff) - 1)) < 0) {
            printf("ERROR: SSL Read(%d)\n", wolfSSL_get_error(ssl, 0));
            goto out;
        }

        buff[len] = '\0';
        printf("Received: %s\n", buff);

        /* Write our reply into buff */
        memset(buff, 0, sizeof(buff));
        memcpy(buff, reply, len);

        /* Reply back to the client */
        if (wolfSSL_write(ssl, buff, len) != len) {
            printf("ERROR: SSL Write(%d)\n", wolfSSL_get_error(ssl, 0));
        }

        /* Cleanup after this connection */
        printf("Cleaning up socket and wolfSSL objects.\n");
        if (xConnectedSocket != NULL)
            FreeRTOS_closesocket(xConnectedSocket);
        if (ssl != NULL)
            wolfSSL_free(ssl);

        printf("Waiting connection....");
    }

out:
    if (ssl) {
        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
    }

    /* clean up socket */
    if (xConnectedSocket) {
        FreeRTOS_shutdown(xConnectedSocket, FREERTOS_SHUT_RDWR);
        FreeRTOS_closesocket(xConnectedSocket);
        xConnectedSocket = NULL;
    }
    if (xListeningSocket) {
        FreeRTOS_shutdown(xListeningSocket, FREERTOS_SHUT_RDWR);
        FreeRTOS_closesocket(xListeningSocket);
        xListeningSocket = NULL;
    }

    return ret;
}
#endif /* TLS_SERVER */
