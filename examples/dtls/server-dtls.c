/* server-dtls.c
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
 * Bare-bones example of a DTLS server for instructional/learning purposes.
 * Utilizes DTLS 1.2.
 */

#include <wolfssl/options.h>
#include <stdio.h>                  /* standard in/out procedures */
#include <stdlib.h>                 /* defines system calls */
#include <string.h>                 /* necessary for memset */
#include <netdb.h>
#include <sys/socket.h>             /* used for all socket calls */
#include <netinet/in.h>             /* used for sockaddr_in */
#include <arpa/inet.h>
#include <wolfssl/ssl.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>

/* Deal with parameters that are not used when DTLS is disabled */
#define UNUSED(x) (void)(x)

#define SERV_PORT   11111           /* define our server port number */
#define MSGLEN      4096

static int cleanup = 0;                 /* To handle shutdown */
struct sockaddr_in servAddr;        /* our server's address */
struct sockaddr_in cliaddr;         /* the client's address */

void sig_handler(const int sig);

int main(int argc, char** argv)
{
#ifdef WOLFSSL_DTLS
#ifndef NO_WOLFSSL_SERVER
    /* Loc short for "location" */
    char        caCertLoc[] = "../../certs/ca-cert.pem";
    char        servCertLoc[] = "../../certs/server-cert.pem";
    char        servKeyLoc[] = "../../certs/server-key.pem";
    WOLFSSL_CTX* ctx;
    /* Variables for awaiting datagram */
    int           on = 1;
    int           res = 1;
    int           connfd = 0;
    int           recvLen = 0;    /* length of message */
    int           listenfd = 0;   /* Initialize our socket */
    WOLFSSL*      ssl = NULL;
    socklen_t     cliLen;
    socklen_t     len = sizeof(int);
    unsigned char b[MSGLEN];      /* watch for incoming messages */
    char          buff[MSGLEN];   /* the incoming message */
    char          ack[] = "I hear you fashizzle!\n";

    /* "./config --enable-debug" and uncomment next line for debugging */
    /* wolfSSL_Debugging_ON(); */

    /* Initialize wolfSSL */
    wolfSSL_Init();

    /* Set ctx to DTLS 1.2 */
    if ((ctx = wolfSSL_CTX_new(wolfDTLSv1_2_server_method())) == NULL) {
        printf("wolfSSL_CTX_new error.\n");
        return 1;
    }
    /* Load CA certificates */
    if (wolfSSL_CTX_load_verify_locations(ctx, caCertLoc, 0) !=
            WOLFSSL_SUCCESS) {
        printf("Error loading %s, please check the file.\n", caCertLoc);
        return 1;
    }
    /* Load server certificates */
    if (wolfSSL_CTX_use_certificate_file(ctx, servCertLoc, WOLFSSL_FILETYPE_PEM) != 
                                                                 WOLFSSL_SUCCESS) {
        printf("Error loading %s, please check the file.\n", servCertLoc);
        return 1;
    }
    /* Load server Keys */
    if (wolfSSL_CTX_use_PrivateKey_file(ctx, servKeyLoc,
                WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        printf("Error loading %s, please check the file.\n", servKeyLoc);
        return 1;
    }

    /* Await Datagram */
    ;

    while (cleanup != 1) {
        /* Create a UDP/IP socket */
        if ((listenfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
            printf("Cannot create socket.\n");
            break;
        }
        printf("Socket allocated\n");

        /* clear servAddr each loop */
        memset((char *)&servAddr, 0, sizeof(servAddr));

        /* host-to-network-long conversion (htonl) */
        /* host-to-network-short conversion (htons) */
        servAddr.sin_family      = AF_INET;
        servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
        servAddr.sin_port        = htons(SERV_PORT);

        /* Eliminate socket already in use error */
        res = setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &on, len);
        if (res < 0) {
            printf("Setsockopt SO_REUSEADDR failed.\n");
            break;
        }

        /*Bind Socket*/
        if (bind(listenfd, (struct sockaddr*)&servAddr, sizeof(servAddr)) < 0) {
            printf("Bind failed.\n");
            break;
        }

        printf("Awaiting client connection on port %d\n", SERV_PORT);

        cliLen = sizeof(cliaddr);
        connfd = (int)recvfrom(listenfd, (char *)&b, sizeof(b), MSG_PEEK,
                (struct sockaddr*)&cliaddr, &cliLen);

        if (connfd < 0) {
            printf("No clients in que, enter idle state\n");
            close(listenfd);
            continue;
        }
        else if (connfd > 0) {
            if (connect(listenfd, (const struct sockaddr *)&cliaddr,
                        sizeof(cliaddr)) != 0) {
                printf("Udp connect failed.\n");
                break;
            }
        }
        else {
            printf("Recvfrom failed.\n");
            break;
        }
        printf("Connected!\n");

        /* Create the WOLFSSL Object */
        if ((ssl = wolfSSL_new(ctx)) == NULL) {
            printf("wolfSSL_new error.\n");
            break;
        }

#ifdef WOLFSSL_DTLS_SET_PEER
        /* Alternative to UDP connect */
        wolfSSL_dtls_set_peer(ssl, &cliaddr, cliLen);
#endif

        /* set the session ssl to client connection port */
        wolfSSL_set_fd(ssl, listenfd);

        if (wolfSSL_accept(ssl) != WOLFSSL_SUCCESS) {

            int e = wolfSSL_get_error(ssl, 0);

            printf("error = %d, %s\n", e, wolfSSL_ERR_reason_error_string(e));
            printf("SSL_accept failed.\n");
            break;
        }
        if ((recvLen = wolfSSL_read(ssl, buff, sizeof(buff)-1)) > 0) {
            printf("heard %d bytes\n", recvLen);

            buff[recvLen] = 0;
            printf("I heard this: \"%s\"\n", buff);
        }
        else if (recvLen < 0) {
            int readErr = wolfSSL_get_error(ssl, 0);
            if(readErr != SSL_ERROR_WANT_READ) {
                printf("SSL_read failed.\n");
                break;
            }
        }
        if (wolfSSL_write(ssl, ack, (int) sizeof(ack)) < 0) {
            printf("wolfSSL_write fail.\n");
            break;
        }
        else {
            printf("Sending reply.\n");
        }

        printf("reply sent \"%s\"\n", ack);

        wolfSSL_set_fd(ssl, 0);
        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
        close(listenfd);
        cleanup = 0;

        printf("Client left cont to idle state\n");
    }
    
    /* With the "continue" keywords, it is possible for the loop to exit *
     * without changing the value of cont                                */
    if (cleanup == 1) {
        wolfSSL_set_fd(ssl, 0);
        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
        close(listenfd);
    }

    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    return 0;
#endif
#endif

    UNUSED(argc);
    UNUSED(argv);
    UNUSED(cleanup);

#ifndef WOLFSSL_DTLS 
    /* Inform user to enable WOLFSSL_DTLS */
    printf("Please enable DTLS to run server-dtls.c \n");
    return -1;
#endif

#ifdef NO_WOLFSSL_SERVER
     /* Inform user to enable WOLFSSL_SERVER */             
     printf("Please enable WOLFSSL_SERVER to run server-dtls.c \n");
     return -1;
#endif

}
