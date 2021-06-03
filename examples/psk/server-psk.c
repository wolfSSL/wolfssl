/* server-psk.c
 * A server ecample using a TCP connection with PSK security.
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
 */

#include <wolfssl/options.h> /* included for options sync */
#include <wolfssl/ssl.h>     /* include wolfSSL security */

#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>

#define MAXLINE     4096
#define LISTENQ     1024
#define SERV_PORT   11111
#define PSK_KEY_LEN 4
#define dhParamFile    "../certs/dh2048.pem"

/*
 * Identify which psk key to use.
 */
static unsigned int my_psk_server_cb(WOLFSSL* ssl, const char* identity,
                           unsigned char* key, unsigned int key_max_len)
{
    (void)ssl;
    (void)key_max_len;

    if (strncmp(identity, "Client_identity", 15) != 0) {
        return 0;
    }

    key[0] = 26;
    key[1] = 43;
    key[2] = 60;
    key[3] = 77;

    return PSK_KEY_LEN;
}

int main()
{
    int  n;              /* length of string read */
    int                 listenfd, connfd, ret;
    int                 opt;
    char                buff[MAXLINE];
    char buf[MAXLINE];   /* string read from client */
    char response[] = "I hear ya for shizzle";
    char suites[]   =
#ifdef WOLFSSL_STATIC_PSK
                      "PSK-AES256-GCM-SHA384:"
                      "PSK-AES128-GCM-SHA256:"
                      "PSK-AES256-CBC-SHA384:"
                      "PSK-AES128-CBC-SHA256:"
                      "PSK-AES128-CBC-SHA:"
                      "PSK-AES256-CBC-SHA:"
                      "PSK-CHACHA20-POLY1305:"
#endif
#if defined(WOLFSSL_TLS13_DRAFT18) || defined(WOLFSSL_TLS13_DRAFT22) || \
    defined(WOLFSSL_TLS13_DRAFT23) || defined(WOLFSSL_TLS13_DRAFT26) || \
    defined(WOLFSSL_TLS13)
                      "TLS13-AES128-GCM-SHA256:"
                      "TLS13-AES256-GCM-SHA384:"
                      "TLS13-CHACHA20-POLY1305-SHA256:"
#endif
#ifndef NO_DH
                      "DHE-PSK-AES256-GCM-SHA384:"
                      "DHE-PSK-AES128-GCM-SHA256:"
                      "DHE-PSK-AES256-CBC-SHA384:"
                      "DHE-PSK-AES128-CBC-SHA256:"
                      "DHE-PSK-CHACHA20-POLY1305"
#endif
                      "ECDHE-PSK-AES128-CBC-SHA256:"
                      "ECDHE-PSK-CHACHA20-POLY1305:";

    struct sockaddr_in  cliAddr, servAddr;
    socklen_t           cliLen;
    WOLFSSL_CTX*         ctx;



    /* set up server address and port */
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family      = AF_INET;
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port        = htons(SERV_PORT);

    /* find a socket */
    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0) {
        printf("Fatal error : socket error\n");
        return 1;
    }

    /* bind to a socket */
    opt = 1;
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&opt,
               sizeof(int)) != 0) {
        printf("Fatal error : setsockopt error\n");
        return 1;
    }
    if (bind(listenfd, (struct sockaddr *) &servAddr, sizeof(servAddr)) < 0) {
        printf("Fatal error : bind error\n");
        return 1;
    }

    /* listen to the socket */
    if (listen(listenfd, LISTENQ) < 0) {
        printf("Fatal error : listen error\n");
        return 1;
    }

    wolfSSL_Init();
    /* create ctx and configure certificates */
    if ((ctx = wolfSSL_CTX_new(wolfSSLv23_server_method())) == NULL) {
        printf("Fatal error : wolfSSL_CTX_new error\n");
        return 1;
    }

    /* use psk suite for security */
    wolfSSL_CTX_set_psk_server_callback(ctx, my_psk_server_cb);

    if ((ret = wolfSSL_CTX_use_psk_identity_hint(ctx, "wolfssl server"))
         != WOLFSSL_SUCCESS) {
        printf("Fatal error : ctx use psk identity hint returned %d\n", ret);
        return ret;
    }

    if ((ret = wolfSSL_CTX_set_cipher_list(ctx, suites)) != WOLFSSL_SUCCESS) {
        printf("Fatal error : server set cipher list returned %d\n", ret);
        return ret;
    }

#ifndef NO_DH
    if ((ret = wolfSSL_CTX_SetTmpDH_file(ctx, dhParamFile, WOLFSSL_FILETYPE_PEM)
        ) != WOLFSSL_SUCCESS) {
        printf("Fatal error: server set temp DH params returned %d\n", ret);
        return ret;
    }
#endif

    /* main loop for accepting and responding to clients */
    for ( ; ; ) {
        WOLFSSL* ssl;

        cliLen = sizeof(cliAddr);
        connfd = accept(listenfd, (struct sockaddr *) &cliAddr, &cliLen);
        if (connfd < 0) {
            printf("Fatal error : accept error\n");
            return 1;
        }
        else {
            printf("Connection from %s, port %d\n",
                   inet_ntop(AF_INET, &cliAddr.sin_addr, buff, sizeof(buff)),
                   ntohs(cliAddr.sin_port));

            /* create WOLFSSL object and respond */
            if ((ssl = wolfSSL_new(ctx)) == NULL) {
                printf("Fatal error : wolfSSL_new error\n");
                return 1;
            }

            /* sets the file descriptor of the socket for the ssl session */
            wolfSSL_set_fd(ssl, connfd);

            /* making sure buffered to store data sent from client is empty */
            memset(buf, 0, MAXLINE);

            /* reads and displays data sent by client if no errors occur */
            n = wolfSSL_read(ssl, buf, MAXLINE);
            if (n > 0) {
                printf("%s\n", buf);
                /* server response */
                if (wolfSSL_write(ssl, response, strlen(response)) >
                    strlen(response)) {
                    printf("Fatal error : respond: write error\n");
                    return 1;
                }
            }
            if (n < 0) {
                printf("Fatal error :respond: read error\n");
                return 1;
            }

            /* closes the connections after responding */
            wolfSSL_shutdown(ssl);
            wolfSSL_free(ssl);

            if (close(connfd) == -1) {
                printf("Fatal error : close error\n");
                return 1;
            }
        }
    }
    /* free up memory used by wolfSSL */
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();

    return 0;
}

