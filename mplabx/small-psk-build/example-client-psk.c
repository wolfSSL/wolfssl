/* example-client-psk.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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
 **/

#include <wolfssl/ssl.h>     /* must include this to use wolfSSL security */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <signal.h>
#include <unistd.h>

#define     MAXLINE 256      /* max text line length */
#define     SERV_PORT 11111  /* default port*/
#define     PSK_KEY_LEN 4
#define     DEFAULT_IP "127.0.0.1"
static int sockfd = SOCKET_INVALID;

static int cannedLen = 0;
static byte canned[4096];
static int cannedIdx = 0;

#ifndef NO_PSK
/*
 *psk client set up.
 */
static inline unsigned int My_Psk_Client_Cb(WOLFSSL* ssl, const char* hint,
        char* identity, unsigned int id_max_len, unsigned char* key,
        unsigned int key_max_len)
{
    (void)ssl;
    (void)hint;
    (void)key_max_len;

    /* identity is OpenSSL testing default for openssl s_client, keep same*/
    strncpy(identity, "Client_identity", id_max_len);

    /* test key n hex is 0x1a2b3c4d , in decimal 439,041,101, we're using
     * unsigned binary */
    key[0] = 26;
    key[1] = 43;
    key[2] = 60;
    key[3] = 77;

    return PSK_KEY_LEN;
}
#endif

int my_IORecv(WOLFSSL* ssl, char* buff, int sz, void* ctx)
{
    /* By default, ctx will be a pointer to the file descriptor to read from.
     * This can be changed by calling wolfSSL_SetIOReadCtx(). */
    int recvd;


    if (cannedLen > 0) {
        recvd = (sz < (cannedLen - cannedIdx))? sz : cannedLen - cannedIdx;
        memcpy(buff, canned + cannedIdx, recvd);
        cannedIdx += recvd;
        if (recvd == 0) {
            fprintf(stderr, "ran out of input\n");
            return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        }
    }
    else {
    /* Receive message from socket */
    if ((recvd = recv(sockfd, buff, sz, 0)) == -1) {
        /* error encountered. Be responsible and report it in wolfSSL terms */

        fprintf(stderr, "IO RECEIVE ERROR: ");
        switch (errno) {
        #if EAGAIN != EWOULDBLOCK
        case EAGAIN: /* EAGAIN == EWOULDBLOCK on some systems, but not others */
        #endif
        case EWOULDBLOCK:
            fprintf(stderr, "would block\n");
            return WOLFSSL_CBIO_ERR_WANT_READ;
        case ECONNRESET:
            fprintf(stderr, "connection reset\n");
            return WOLFSSL_CBIO_ERR_CONN_RST;
        case EINTR:
            fprintf(stderr, "socket interrupted\n");
            return WOLFSSL_CBIO_ERR_ISR;
        case ECONNREFUSED:
            fprintf(stderr, "connection refused\n");
            return WOLFSSL_CBIO_ERR_WANT_READ;
        case ECONNABORTED:
            fprintf(stderr, "connection aborted\n");
            return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        default:
            fprintf(stderr, "general error\n");
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
    }
    else if (recvd == 0) {
        printf("Connection closed\n");
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    }

#if 0
        {
            FILE* f;
            char fname[200];

            sprintf(fname, "%d-recv.out", getpid());
            f=fopen(fname, "ab");
            fwrite(buff, 1, recvd, f);
            fclose(f);
        }
#endif
    }
    /* successful receive */
    printf("my_IORecv: received %d bytes\n", sz);
    return recvd;
}


int my_IOSend(WOLFSSL* ssl, char* buff, int sz, void* ctx)
{
    /* By default, ctx will be a pointer to the file descriptor to write to.
     * This can be changed by calling wolfSSL_SetIOWriteCtx(). */
    int sent;


    if (cannedLen > 0) {
        sent = sz;
    }
    else {
    /* Receive message from socket */
    if ((sent = send(sockfd, buff, sz, 0)) == -1) {
        /* error encountered. Be responsible and report it in wolfSSL terms */

        fprintf(stderr, "IO SEND ERROR: ");
        switch (errno) {
        #if EAGAIN != EWOULDBLOCK
        case EAGAIN: /* EAGAIN == EWOULDBLOCK on some systems, but not others */
        #endif
        case EWOULDBLOCK:
            fprintf(stderr, "would block\n");
            return WOLFSSL_CBIO_ERR_WANT_WRITE;
        case ECONNRESET:
            fprintf(stderr, "connection reset\n");
            return WOLFSSL_CBIO_ERR_CONN_RST;
        case EINTR:
            fprintf(stderr, "socket interrupted\n");
            return WOLFSSL_CBIO_ERR_ISR;
        case EPIPE:
            fprintf(stderr, "socket EPIPE\n");
            return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        default:
            fprintf(stderr, "general error\n");
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
    }
    else if (sent == 0) {
        printf("Connection closed\n");
        return 0;
    }
    }
    /* successful send */
    printf("my_IOSend: sent %d bytes\n", sz);
    return sent;
}

#define CIPHER_BYTE 0x00
#define TLS_PSK_WITH_AES_128_CBC_SHA256 0xAE

#define SUITE0 CIPHER_BYTE
#define SUITE1 TLS_PSK_WITH_AES_128_CBC_SHA256
#define TLS_RANDOM_SIZE 48
#ifndef USE_LIBFUZZER
int main(int argc, char **argv)
#else
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t sz)
#endif
{
    int ret, read = 0;
    char recvline[MAXLINE]="Hello Server"; /* string to send to the server */
    struct sockaddr_in servaddr;;
    byte ran[TLS_RANDOM_SIZE];
    byte *ptr;
    WOLFSSL_METHOD* meth = NULL;

    WOLFSSL* ssl = NULL;

    memset(ran, 0, sizeof(ran));
#ifndef USE_LIBFUZZER
    if (argc == 2) {
        FILE* f = fopen(argv[1], "rb");

        if (f == NULL) {
            printf("Unable to open file %s\n", argv[1]);
            return 1;
        }
        else {
            cannedLen = fread(canned, 1, 4096, f);
            fclose(f);
        }
    }
    else {
        /* create a stream socket using tcp,internet protocal IPv4,
         * full-duplex stream */
        sockfd = socket(AF_INET, SOCK_STREAM, 0);

        /* places n zero-valued bytes in the address servaddr */
        memset(&servaddr, 0, sizeof(servaddr));

        servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons(SERV_PORT);

        /* converts IPv4 addresses from text to binary form */
        ret = inet_pton(AF_INET, DEFAULT_IP, &servaddr.sin_addr);
        if (ret != 1) {
            printf("inet_pton error\n");
            ret = -1;
            goto exit;
        }

        /* attempts to make a connection on a socket */
        ret = connect(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr));
        if (ret != 0) {
            printf("Connection Error\n");
            ret = -1;
            goto exit;
        }
    }
#else
    cannedLen = sz;
    memcpy(canned, data, cannedLen);
#endif
    wolfSSL_Init();  /* initialize wolfSSL */

    meth = wolfTLSv1_2_client_method();
    /* creat wolfssl object after each tcp connect */
    if ( (ssl = wolfSSL_new_leanpsk(meth, SUITE0, SUITE1, ran,
            TLS_RANDOM_SIZE)) == NULL) {
        fprintf(stderr, "wolfSSL_new_leanpsk error.\n");
        ret = -1;
        goto exit;
    }
    wolfSSL_set_psk_client_callback(ssl, My_Psk_Client_Cb);
    wolfSSL_SSLSetIORecv(ssl, my_IORecv);
    wolfSSL_SSLSetIOSend(ssl, my_IOSend);

    ret = wolfSSL_connect(ssl);
    printf("ret of connect = %d\n", ret);

    /* write string to the server */
    if (wolfSSL_write_inline(ssl, recvline, strlen(recvline), MAXLINE) < 0) {
        printf("Write Error to Server\n");
        ret = -1;
        goto exit;
    }

    /* check if server ended before client could read a response  */
    if ((read = wolfSSL_read_inline(ssl, recvline, MAXLINE, (void**)&ptr,
            MAXLINE)) < 0 ) {
        printf("Client: Server Terminated Prematurely!\n");
        ret = -1;
        goto exit;
    }

    /* show message from the server */
    ptr[read] = '\0';
    printf("Server Message: %s\n", ptr);

    ret = 0;

exit:
    /* Cleanup and return */
    if (ssl)
        wolfSSL_free(ssl);      /* Free the wolfSSL object              */
    if (sockfd != SOCKET_INVALID)
        close(sockfd);          /* Close the socket   */
    if (meth)
        free(meth);
    wolfSSL_Cleanup();          /* Cleanup the wolfSSL environment          */

    return ret;                 /* Return reporting a success               */
}
