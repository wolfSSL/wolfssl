/* echoserver.c
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/ssl.h> /* name change portability layer */
#include <wolfssl/wolfcrypt/settings.h>
#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/ecc.h>   /* ecc_fp_free */
#endif

#if defined(WOLFSSL_MDK_ARM)
        #include <stdio.h>
        #include <string.h>

        #if defined(WOLFSSL_MDK5)
            #include "cmsis_os.h"
            #include "rl_fs.h" 
            #include "rl_net.h" 
        #else
            #include "rtl.h"
        #endif

        #include "wolfssl_MDK_ARM.h"
#endif

#include <wolfssl/ssl.h>
#include <wolfssl/test.h>

#ifndef NO_MAIN_DRIVER
    #define ECHO_OUT
#endif

#include "examples/echoserver/echoserver.h"

#define SVR_COMMAND_SIZE 256

static void SignalReady(void* args, word16 port)
{
#if defined(_POSIX_THREADS) && defined(NO_MAIN_DRIVER) && !defined(__MINGW32__)
    /* signal ready to tcp_accept */
    func_args* server_args = (func_args*)args;
    tcp_ready* ready = server_args->signal;
    pthread_mutex_lock(&ready->mutex);
    ready->ready = 1;
    ready->port = port;
    pthread_cond_signal(&ready->cond);
    pthread_mutex_unlock(&ready->mutex);
#endif
    (void)args;
    (void)port;
}


THREAD_RETURN WOLFSSL_THREAD echoserver_test(void* args)
{
    SOCKET_T       sockfd = 0;
    WOLFSSL_METHOD* method = 0;
    WOLFSSL_CTX*    ctx    = 0;

    int    doDTLS = 0;
    int    doPSK = 0;
    int    outCreated = 0;
    int    shutDown = 0;
    int    useAnyAddr = 0;
    word16 port = wolfSSLPort;
    int    argc = ((func_args*)args)->argc;
    char** argv = ((func_args*)args)->argv;

#if defined(ECHO_OUT) && !defined(NO_FILESYSTEM)
    FILE* fout = stdout;
    if (argc >= 2) {
        fout = fopen(argv[1], "w");
        outCreated = 1;
    }
    if (!fout) err_sys("can't open output file");
#endif
    (void)outCreated;
    (void)argc;
    (void)argv;

    ((func_args*)args)->return_code = -1; /* error state */

#ifdef WOLFSSL_DTLS
    doDTLS  = 1;
#endif

#ifdef WOLFSSL_LEANPSK
    doPSK = 1;
#endif

#if defined(NO_RSA) && !defined(HAVE_ECC)
    doPSK = 1;
#endif

    #if defined(NO_MAIN_DRIVER) && !defined(USE_WINDOWS_API) && \
        !defined(WOLFSSL_SNIFFER) && !defined(WOLFSSL_MDK_SHELL) && \
        !defined(WOLFSSL_TIRTOS)
        port = 0;
    #endif
    #if defined(USE_ANY_ADDR)
        useAnyAddr = 1;
    #endif

#ifdef WOLFSSL_TIRTOS
    fdOpenSession(Task_self());
#endif

    tcp_listen(&sockfd, &port, useAnyAddr, doDTLS);

#if defined(WOLFSSL_DTLS)
    method  = wolfDTLSv1_2_server_method();
#elif  !defined(NO_TLS)
    method = wolfSSLv23_server_method();
#elif defined(WOLFSSL_ALLOW_SSLV3)
    method = wolfSSLv3_server_method();
#else
    #error "no valid server method built in"
#endif
    ctx    = wolfSSL_CTX_new(method);
    /* wolfSSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF); */

#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER)
    wolfSSL_CTX_set_default_passwd_cb(ctx, PasswordCallBack);
#endif

#if defined(HAVE_SESSION_TICKET) && defined(HAVE_CHACHA) && \
                                    defined(HAVE_POLY1305)
    if (TicketInit() != 0)
        err_sys("unable to setup Session Ticket Key context");
    wolfSSL_CTX_set_TicketEncCb(ctx, myTicketEncCb);
#endif

#ifndef NO_FILESYSTEM
    if (doPSK == 0) {
    #ifdef HAVE_NTRU
        /* ntru */
        if (wolfSSL_CTX_use_certificate_file(ctx, ntruCert, SSL_FILETYPE_PEM)
                != SSL_SUCCESS)
            err_sys("can't load ntru cert file, "
                    "Please run from wolfSSL home dir");

        if (wolfSSL_CTX_use_NTRUPrivateKey_file(ctx, ntruKey)
                != SSL_SUCCESS)
            err_sys("can't load ntru key file, "
                    "Please run from wolfSSL home dir");
    #elif defined(HAVE_ECC) && !defined(WOLFSSL_SNIFFER)
        /* ecc */
        if (wolfSSL_CTX_use_certificate_file(ctx, eccCert, SSL_FILETYPE_PEM)
                != SSL_SUCCESS)
            err_sys("can't load server cert file, "
                    "Please run from wolfSSL home dir");

        if (wolfSSL_CTX_use_PrivateKey_file(ctx, eccKey, SSL_FILETYPE_PEM)
                != SSL_SUCCESS)
            err_sys("can't load server key file, "
                    "Please run from wolfSSL home dir");
    #elif defined(NO_CERTS)
        /* do nothing, just don't load cert files */
    #else
        /* normal */
        if (wolfSSL_CTX_use_certificate_file(ctx, svrCert, SSL_FILETYPE_PEM)
                != SSL_SUCCESS)
            err_sys("can't load server cert file, "
                    "Please run from wolfSSL home dir");

        if (wolfSSL_CTX_use_PrivateKey_file(ctx, svrKey, SSL_FILETYPE_PEM)
                != SSL_SUCCESS)
            err_sys("can't load server key file, "
                    "Please run from wolfSSL home dir");
    #endif
    } /* doPSK */
#elif !defined(NO_CERTS)
    if (!doPSK) {
        load_buffer(ctx, svrCert, WOLFSSL_CERT);
        load_buffer(ctx, svrKey,  WOLFSSL_KEY);
    }
#endif

#if defined(WOLFSSL_SNIFFER)
    /* don't use EDH, can't sniff tmp keys */
    wolfSSL_CTX_set_cipher_list(ctx, "AES256-SHA");
#endif

    if (doPSK) {
#ifndef NO_PSK
        const char *defaultCipherList;

        wolfSSL_CTX_set_psk_server_callback(ctx, my_psk_server_cb);
        wolfSSL_CTX_use_psk_identity_hint(ctx, "wolfssl server");
        #ifdef HAVE_NULL_CIPHER
            defaultCipherList = "PSK-NULL-SHA256";
        #elif defined(HAVE_AESGCM) && !defined(NO_DH)
            defaultCipherList = "DHE-PSK-AES128-GCM-SHA256";
        #else
            defaultCipherList = "PSK-AES128-CBC-SHA256";
        #endif
        if (wolfSSL_CTX_set_cipher_list(ctx, defaultCipherList) != SSL_SUCCESS)
            err_sys("server can't set cipher list 2");
#endif
    }

    SignalReady(args, port);

    while (!shutDown) {
        WOLFSSL* ssl = 0;
        char    command[SVR_COMMAND_SIZE+1];
        int     echoSz = 0;
        int     clientfd;
        int     firstRead = 1;
        int     gotFirstG = 0;

#ifndef WOLFSSL_DTLS
        SOCKADDR_IN_T client;
        socklen_t     client_len = sizeof(client);
        clientfd = accept(sockfd, (struct sockaddr*)&client,
                         (ACCEPT_THIRD_T)&client_len);
#else
        clientfd = udp_read_connect(sockfd);
#endif
        if (clientfd == -1) err_sys("tcp accept failed");

        ssl = wolfSSL_new(ctx);
        if (ssl == NULL) err_sys("SSL_new failed");
        wolfSSL_set_fd(ssl, clientfd);
        #if !defined(NO_FILESYSTEM) && !defined(NO_DH) && !defined(NO_ASN)
            wolfSSL_SetTmpDH_file(ssl, dhParam, SSL_FILETYPE_PEM);
        #elif !defined(NO_DH)
            SetDH(ssl);  /* will repick suites with DHE, higher than PSK */
        #endif
        if (wolfSSL_accept(ssl) != SSL_SUCCESS) {
            printf("SSL_accept failed\n");
            wolfSSL_free(ssl);
            CloseSocket(clientfd);
            continue;
        }
#if defined(PEER_INFO)
        showPeer(ssl);
#endif

        while ( (echoSz = wolfSSL_read(ssl, command, sizeof(command)-1)) > 0) {

            if (firstRead == 1) {
                firstRead = 0;  /* browser may send 1 byte 'G' to start */
                if (echoSz == 1 && command[0] == 'G') {
                    gotFirstG = 1;
                    continue;
                }
            }
            else if (gotFirstG == 1 && strncmp(command, "ET /", 4) == 0) {
                strncpy(command, "GET", 4);
                /* fall through to normal GET */
            }
           
            if ( strncmp(command, "quit", 4) == 0) {
                printf("client sent quit command: shutting down!\n");
                shutDown = 1;
                break;
            }
            if ( strncmp(command, "break", 5) == 0) {
                printf("client sent break command: closing session!\n");
                break;
            }
#ifdef PRINT_SESSION_STATS
            if ( strncmp(command, "printstats", 10) == 0) {
                wolfSSL_PrintSessionStats();
                break;
            }
#endif
            if ( strncmp(command, "GET", 3) == 0) {
                char type[]   = "HTTP/1.0 200 ok\r\nContent-type:"
                                " text/html\r\n\r\n";
                char header[] = "<html><body BGCOLOR=\"#ffffff\">\n<pre>\n";
                char body[]   = "greetings from wolfSSL\n";
                char footer[] = "</body></html>\r\n\r\n";
            
                strncpy(command, type, sizeof(type));
                echoSz = sizeof(type) - 1;

                strncpy(&command[echoSz], header, sizeof(header));
                echoSz += (int)sizeof(header) - 1;
                strncpy(&command[echoSz], body, sizeof(body));
                echoSz += (int)sizeof(body) - 1;
                strncpy(&command[echoSz], footer, sizeof(footer));
                echoSz += (int)sizeof(footer);

                if (wolfSSL_write(ssl, command, echoSz) != echoSz)
                    err_sys("SSL_write failed");
                break;
            }
            command[echoSz] = 0;

            #ifdef ECHO_OUT
                fputs(command, fout);
            #endif

            if (wolfSSL_write(ssl, command, echoSz) != echoSz)
                err_sys("SSL_write failed");
        }
#ifndef WOLFSSL_DTLS
        wolfSSL_shutdown(ssl);
#endif
        wolfSSL_free(ssl);
        CloseSocket(clientfd);
#ifdef WOLFSSL_DTLS
        tcp_listen(&sockfd, &port, useAnyAddr, doDTLS);
        SignalReady(args, port);
#endif
    }

    CloseSocket(sockfd);
    wolfSSL_CTX_free(ctx);

#ifdef ECHO_OUT
    if (outCreated)
        fclose(fout);
#endif

    ((func_args*)args)->return_code = 0;

#if defined(NO_MAIN_DRIVER) && defined(HAVE_ECC) && defined(FP_ECC) \
                            && defined(HAVE_THREAD_LS)
    ecc_fp_free();  /* free per thread cache */
#endif

#ifdef WOLFSSL_TIRTOS
    fdCloseSession(Task_self());
#endif

#if defined(HAVE_SESSION_TICKET) && defined(HAVE_CHACHA) && \
                                    defined(HAVE_POLY1305)
    TicketCleanup();
#endif

#ifndef WOLFSSL_TIRTOS
    return 0;
#endif
}


/* so overall tests can pull in test function */
#ifndef NO_MAIN_DRIVER

    int main(int argc, char** argv)
    {
        func_args args;

#ifdef HAVE_CAVIUM
        int ret = OpenNitroxDevice(CAVIUM_DIRECT, CAVIUM_DEV_ID);
        if (ret != 0)
            err_sys("Cavium OpenNitroxDevice failed");
#endif /* HAVE_CAVIUM */

        StartTCP();

        args.argc = argc;
        args.argv = argv;

        wolfSSL_Init();
#if defined(DEBUG_WOLFSSL) && !defined(WOLFSSL_MDK_SHELL)
        wolfSSL_Debugging_ON();
#endif
        if (CurrentDir("echoserver"))
            ChangeDirBack(2);
        else if (CurrentDir("Debug") || CurrentDir("Release"))
            ChangeDirBack(3);
        echoserver_test(&args);
        wolfSSL_Cleanup();

#ifdef HAVE_CAVIUM
        CspShutdown(CAVIUM_DEV_ID);
#endif
        return args.return_code;
    }

        
#endif /* NO_MAIN_DRIVER */

