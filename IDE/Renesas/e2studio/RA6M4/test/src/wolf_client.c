/* wolf_client.c
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
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

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/ssl.h"
#include "wolfssl/certs_test.h"

uint32_t g_encrypted_root_public_key[140];
static WOLFSSL_CTX *client_ctx;

extern uint8_t g_ether0_mac_address[6];
typedef struct user_EccPKCbInfo;
extern struct user_PKCbInfo guser_PKCbInfo;
static const byte ucIPAddress[4]          = { 192, 168, 11, 241 };
static const byte ucNetMask[4]            = { 255, 255, 255, 0 };
static const byte ucGatewayAddress[4]     = { 192, 168, 11, 1 };
static const byte ucDNSServerAddress[4]   = { 192, 168, 11, 1 };

/* Client connects to the server with these details. */
#define SERVER_IP    "192.168.11.40"
#define DEFAULT_PORT 11111

#define FR_SOCKET_SUCCESS 0

void TCPInit( )
{
   BaseType_t fr_status;
  
   /* FreeRTOS+TCP Ethernet and IP Setup */
   fr_status = FreeRTOS_IPInit(ucIPAddress,
                               ucNetMask,
                               ucGatewayAddress,
                               ucDNSServerAddress,
                               g_ether0_mac_address);
   if (pdPASS != fr_status) {
       printf("Error [%ld]: FreeRTOS_IPInit.\n",fr_status);
   }
}

void wolfSSL_TLS_client_init(const char* cipherlist)
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
    #ifdef DEBUG_WOLFSSL
        wolfSSL_Debugging_ON();
    #endif

    /* Create and initialize WOLFSSL_CTX */
    if ((client_ctx = wolfSSL_CTX_new(wolfSSLv23_client_method_ex((void *)NULL))) == NULL) {
        printf("ERROR: failed to create WOLFSSL_CTX\n");
        return;
    }
    #if defined(WOLFSSL_RENESAS_SCEPROTECT)
    /* set callback functions for ECC */
    wc_sce_set_callbacks(client_ctx);
    #endif
    
    #if !defined(NO_FILESYSTEM)
    if (wolfSSL_CTX_load_verify_locations(client_ctx, cert, 0) != SSL_SUCCESS) {
        printf("ERROR: can't load \"%s\"\n", cert);
        return NULL;
    }
    #else
    if (wolfSSL_CTX_load_verify_buffer(client_ctx, cert, SIZEOF_CERT, SSL_FILETYPE_ASN1) != SSL_SUCCESS){
           printf("ERROR: can't load certificate data\n");
       return;
    }
    #endif

    /* use specific cipher */
    if (cipherlist != NULL && wolfSSL_CTX_set_cipher_list(client_ctx, cipherlist) != WOLFSSL_SUCCESS) {
        wolfSSL_CTX_free(client_ctx); client_ctx = NULL;
        printf("client can't set cipher list 1");
    }
}

void wolfSSL_TLS_client( )
{
    int ret;
    /* FreeRTOS+TCP Objects */
    socklen_t xSize = sizeof(struct freertos_sockaddr);
    xSocket_t xClientSocket = NULL;
    struct freertos_sockaddr xRemoteAddress;
    
    WOLFSSL_CTX *ctx = (WOLFSSL_CTX *)client_ctx;
    WOLFSSL *ssl;

    #define BUFF_SIZE 256
    static const char sendBuff[]= "Hello Server\n" ;
    
    char    rcvBuff[BUFF_SIZE] = {0};
    
    /* Client Socket Setup */
    xRemoteAddress.sin_port = FreeRTOS_htons(DEFAULT_PORT);
    xRemoteAddress.sin_addr = FreeRTOS_inet_addr(SERVER_IP);

    /* Create a FreeRTOS TCP Socket and connect */
    xClientSocket = FreeRTOS_socket(FREERTOS_AF_INET,
                                    FREERTOS_SOCK_STREAM,
                                    FREERTOS_IPPROTO_TCP);
    configASSERT(xClientSocket != FREERTOS_INVALID_SOCKET);
    FreeRTOS_bind(xClientSocket, &xRemoteAddress, sizeof(xSize));

    /* Client Socket Connect */
    ret = FreeRTOS_connect(xClientSocket,
                           &xRemoteAddress,
                           sizeof(xRemoteAddress));
    if (ret != FR_SOCKET_SUCCESS) {
        printf("Error [%d]: FreeRTOS_connect.\n",ret);
        util_inf_loop(xClientSocket, ctx, ssl);
    }
    
    if((ssl = wolfSSL_new(ctx)) == NULL) {
        printf("ERROR wolfSSL_new: %d\n", wolfSSL_get_error(ssl, 0));
        return;
    }
    #if defined(WOLFSSL_RENESAS_SCEPROTECT)
    /* set callback ctx */
    wc_sce_set_callback_ctx(ssl, (void*)&guser_PKCbInfo);
    #endif
    /* Attach wolfSSL to the socket */
    ret = wolfSSL_set_fd(ssl, (int) xClientSocket);
    if (ret != WOLFSSL_SUCCESS) {
        printf("Error [%d]: wolfSSL_set_fd.\n",ret);
        util_inf_loop(xClientSocket, ctx, ssl);
    }

    if(wolfSSL_connect(ssl) != SSL_SUCCESS) {
        printf("ERROR SSL connect: %d\n",  wolfSSL_get_error(ssl, 0));
        return;
    }

    if (wolfSSL_write(ssl, sendBuff, strlen(sendBuff)) != strlen(sendBuff)) {
        printf("ERROR SSL write: %d\n", wolfSSL_get_error(ssl, 0));
        return;
    }

    if ((ret=wolfSSL_read(ssl, rcvBuff, BUFF_SIZE)) < 0) {
        printf("ERROR SSL read: %d\n", wolfSSL_get_error(ssl, 0));
        return;
    }

    rcvBuff[ret] = '\0' ;
    printf("Received: %s\n\n", rcvBuff);

    /* frees all data before client termination */
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
}
