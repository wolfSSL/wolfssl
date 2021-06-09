/*
 * client-dtls.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
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
 *
 *=============================================================================
 *
 * Bare-bones example of a DTLS client for instructional/learning purposes.
 */

#include <wolfssl/options.h>
#include <unistd.h>
#include <wolfssl/ssl.h>
#include <netdb.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Deal with parameters that are not used when DTLS is disabled */
#define UNUSED(x) (void)(x)

#define MAXLINE   4096
#define SERV_PORT 11111

int main (int argc, char** argv)
{
#ifdef WOLFSSL_DTLS
#ifndef NO_WOLFSSL_CLIENT    
    /* standard variables used in a dtls client*/
    int             n = 0;
    int             sockfd = 0;
    int             err1;
    int             readErr;
    struct          sockaddr_in servAddr;
    WOLFSSL*        ssl = 0;
    WOLFSSL_CTX*    ctx = 0;
    char            cert_array[]  = "../../certs/ca-cert.pem";
    char*           certs = cert_array;   
    char            sendLine[MAXLINE];
    char            recvLine[MAXLINE - 1];

    /* Program argument checking */
    if (argc != 2) {
        printf("usage: udpcli <IP address>\n");
        return 1;
    }

    /* Initialize wolfSSL before assigning ctx */
    wolfSSL_Init();
  
    /* wolfSSL_Debugging_ON(); */

    if ( (ctx = wolfSSL_CTX_new(wolfDTLSv1_2_client_method())) == NULL) {
        fprintf(stderr, "wolfSSL_CTX_new error.\n");
        return 1;
    }

    /* Load certificates into ctx variable */
    if (wolfSSL_CTX_load_verify_locations(ctx, certs, 0)
	    != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Error loading %s, please check the file.\n", certs);
        return 1;
    }

    /* Assign ssl variable */
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        printf("unable to get ssl object");
        return 1;
    }

    /* servAddr setup */
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(SERV_PORT);
    if (inet_pton(AF_INET, argv[1], &servAddr.sin_addr) < 1) {
        printf("Error and/or invalid IP address");
        return 1;
    }

    wolfSSL_dtls_set_peer(ssl, &servAddr, sizeof(servAddr));

    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        printf("cannot create a socket.");
        return 1;
    }

    /* Set the file descriptor for ssl and connect with ssl variable */
    wolfSSL_set_fd(ssl, sockfd);
    if (wolfSSL_connect(ssl) != WOLFSSL_SUCCESS) {
	    err1 = wolfSSL_get_error(ssl, 0);
	    printf("err = %d, %s\n", err1, wolfSSL_ERR_reason_error_string(err1));
	    printf("SSL_connect failed");
        return 1;
    }

/*****************************************************************************/
/*                  Code for sending datagram to server                      */
    /* Loop until the user is finished */
    if (fgets(sendLine, MAXLINE, stdin) != NULL) {

        /* Send sendLine to the server */
        if ((size_t) (wolfSSL_write(ssl, sendLine, (int) strlen(sendLine)))
                != strlen(sendLine)) {
            printf("SSL_write failed");
        }

        /* n is the # of bytes received */
        n = wolfSSL_read(ssl, recvLine, sizeof(recvLine)-1);

        if (n < 0) {
            readErr = wolfSSL_get_error(ssl, 0);
            if (readErr != SSL_ERROR_WANT_READ) {
                printf("wolfSSL_read failed");
            }
        }

        /* Add a terminating character to the generic server message */
        recvLine[n] = '\0';
        fputs(recvLine, stdout);
    }
/*                End code for sending datagram to server                    */
/*****************************************************************************/

    /* Housekeeping */
    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    close(sockfd);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    return 0;
#endif
#endif

    UNUSED(argc);
    UNUSED(argv);
 
#ifndef WOLFSSL_DTLS 
    /* Inform user to enable WOLFSSL_DTLS */
    printf("Please enable DTLS to run client-dtls.c \n");
    return -1;    
#endif

#ifdef NO_WOLFSSL_CLIENT     
     /* Inform user to enable WOLFSSL_CLIENT */             
     printf("Please enable WOLFSSL_CLIENT to run client-dtls.c \n");
     return -1;
#endif

}
