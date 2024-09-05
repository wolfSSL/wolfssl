/* wolf_client.c
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

#if defined(TLS_CLIENT)

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/ssl.h"
#include "wolfssl/certs_test.h"

WOLFSSL_CTX *client_ctx = NULL;

void wolfSSL_TLS_client_init()
{
    #ifndef NO_FILESYSTEM
        #ifdef USE_ECC_CERT
        char *cert       = "./certs/ca-ecc-cert.pem";
        #else
        char *cert       = "./certs/ca-cert.pem";
        #endif
    #else
        #ifdef USE_CERT_BUFFERS_256
        const unsigned char *cert       = ca_ecc_cert_der_256;
        #define  SIZEOF_CERT sizeof_ca_ecc_cert_der_256
        #else
        const unsigned char *cert       = ca_cert_der_2048;
        #define  SIZEOF_CERT sizeof_ca_cert_der_2048
        #endif
    #endif

    wolfSSL_Init();

    /* Create and initialize WOLFSSL_CTX */
    if ((client_ctx = wolfSSL_CTX_new(
                        wolfSSLv23_client_method_ex((void *)NULL))) == NULL) {
        printf("ERROR: failed to create WOLFSSL_CTX\n");
        return;
    }

    #if !defined(NO_FILESYSTEM)
    if (wolfSSL_CTX_load_verify_locations(client_ctx, cert, 0) != SSL_SUCCESS) {
        printf("ERROR: can't load \"%s\"\n", cert);
        return NULL;
    }
    #else
    if (wolfSSL_CTX_load_verify_buffer(client_ctx, cert, SIZEOF_CERT,
                                            SSL_FILETYPE_ASN1) != SSL_SUCCESS){
           printf("ERROR: can't load certificate data\n");
       return;
    }
    #endif
}

int wolfSSL_TLS_client_do(void *pvParam)
{

    int ret;

    TestInfo* p = (TestInfo*)pvParam;
    /* FreeRTOS+TCP Objects */
    socklen_t xSize = sizeof(struct freertos_sockaddr);
    xSocket_t xClientSocket = NULL;
    struct freertos_sockaddr xRemoteAddress;

    WOLFSSL_CTX *ctx = (WOLFSSL_CTX *)p->ctx;
    WOLFSSL *ssl = NULL;

    #define BUFF_SIZE 256
    static const char sendBuff[]= "Hello Server\n" ;

    char    rcvBuff[BUFF_SIZE] = {0};

    /* Client Socket Setup */
    xRemoteAddress.sin_port = FreeRTOS_htons(p->port);
    xRemoteAddress.sin_addr = FreeRTOS_inet_addr(SERVER_IP);

     /* Create a FreeRTOS TCP Socket and connect */
     xClientSocket = FreeRTOS_socket(FREERTOS_AF_INET,
                                             FREERTOS_SOCK_STREAM,
                                             FREERTOS_IPPROTO_TCP);

     configASSERT(xClientSocket != FREERTOS_INVALID_SOCKET);

     FreeRTOS_bind(xClientSocket, NULL, sizeof(xSize));

     /* Client Socket Connect */
     ret = FreeRTOS_connect(xClientSocket,
                                 &xRemoteAddress,
                                 sizeof(xRemoteAddress));

     if (ret != FR_SOCKET_SUCCESS) {
         printf(" Error [%d]: FreeRTOS_connect.\n", ret);
         goto out;
     }

     printf(" Start to connect to the server.\n");

     if((ssl = wolfSSL_new(ctx)) == NULL) {
          printf(" ERROR wolfSSL_new: %d\n", wolfSSL_get_error(ssl, 0));
          goto out;
     }

     /* Attach wolfSSL to the socket */
     ret = wolfSSL_set_fd(ssl, (int) xClientSocket);
     if (ret != WOLFSSL_SUCCESS) {
         printf(" Error [%d]: wolfSSL_set_fd.\n",ret);
     }

     printf("  Cipher : %s\n",
                                    (p->cipher == NULL) ? "NULL" : p->cipher);
     /* use specific cipher */
     if (p->cipher != NULL && wolfSSL_set_cipher_list(ssl, p->cipher)
                                                           != WOLFSSL_SUCCESS) {
          printf(" client can't set cipher list 1");
          goto out;
     }

     #ifdef DEBUG_WOLFSSL
     wolfSSL_Debugging_ON();
     #endif

     if(wolfSSL_connect(ssl) != SSL_SUCCESS) {
        printf(" ERROR SSL connect: %d\n",  wolfSSL_get_error(ssl, 0));
        goto out;
     }

     #ifdef DEBUG_WOLFSSL
     wolfSSL_Debugging_OFF();
     #endif

     if (wolfSSL_write(ssl, sendBuff, (int)strlen(sendBuff))
                                                    != (int)strlen(sendBuff)) {
        printf(" ERROR SSL write: %d\n", wolfSSL_get_error(ssl, 0));
        goto out;
     }

     if ((ret=wolfSSL_read(ssl, rcvBuff, BUFF_SIZE)) < 0) {
         printf(" ERROR SSL read: %d\n", wolfSSL_get_error(ssl, 0));
         goto out;
     }

     rcvBuff[ret] = '\0' ;
     printf(" Received: %s\n\n", rcvBuff);

 out:
    if (ssl) {
        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
        ssl = NULL;
        /* need to reset callback */
    }
    /* clean up socket */
    if (xClientSocket) {
        FreeRTOS_shutdown(xClientSocket, FREERTOS_SHUT_RDWR);
        FreeRTOS_closesocket(xClientSocket);
        xClientSocket = NULL;
    }

    return ret;
}

#endif /* TLS_CLIENT */
