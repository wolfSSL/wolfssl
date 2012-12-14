/* client.c
 *
 * Copyright (C) 2006-2012 Sawtooth Consulting Ltd.
 *
 * This file is part of CyaSSL.
 *
 * CyaSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * CyaSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <cyassl/ssl.h>
#include <cyassl/test.h>

#include "examples/client/client.h"


#ifdef CYASSL_CALLBACKS
    int handShakeCB(HandShakeInfo*);
    int timeoutCB(TimeoutInfo*);
    Timeval timeout;
#endif

static void NonBlockingSSL_Connect(CYASSL* ssl)
{
#ifndef CYASSL_CALLBACKS
    int ret = CyaSSL_connect(ssl);
#else
    int ret = CyaSSL_connect_ex(ssl, handShakeCB, timeoutCB, timeout);
#endif
    int error = CyaSSL_get_error(ssl, 0);
    SOCKET_T sockfd = (SOCKET_T)CyaSSL_get_fd(ssl);
    int select_ret;

    while (ret != SSL_SUCCESS && (error == SSL_ERROR_WANT_READ ||
                                  error == SSL_ERROR_WANT_WRITE)) {
        if (error == SSL_ERROR_WANT_READ)
            printf("... client would read block\n");
        else
            printf("... client would write block\n");

        if (CyaSSL_dtls(ssl))
            select_ret = tcp_select(sockfd,
                                    CyaSSL_dtls_get_current_timeout(ssl));
        else
            select_ret = tcp_select(sockfd, 1);

        if ((select_ret == TEST_RECV_READY) ||
                                        (select_ret == TEST_ERROR_READY)) {
            #ifndef CYASSL_CALLBACKS
                    ret = CyaSSL_connect(ssl);
            #else
                ret = CyaSSL_connect_ex(ssl,handShakeCB,timeoutCB,timeout);
            #endif
            error = CyaSSL_get_error(ssl, 0);
        }
        else if (select_ret == TEST_TIMEOUT &&
                    (!CyaSSL_dtls(ssl) ||
                    (CyaSSL_dtls_got_timeout(ssl) >= 0))) {
            error = SSL_ERROR_WANT_READ;
        }
        else {
            error = SSL_FATAL_ERROR;
        }
    }
    if (ret != SSL_SUCCESS)
        err_sys("SSL_connect failed");
}


static void Usage(void)
{
    printf("client "    LIBCYASSL_VERSION_STRING
           " NOTE: All files relative to CyaSSL home dir\n");
    printf("-?          Help, print this usage\n");
    printf("-h <host>   Host to connect to, default %s\n", yasslIP);
    printf("-p <num>    Port to connect on, default %d\n", yasslPort);
    printf("-v <num>    SSL version [0-3], SSLv3(0) - TLS1.2(3)), default %d\n",
                                 CLIENT_DEFAULT_VERSION);
    printf("-l <str>    Cipher list\n");
    printf("-c <file>   Certificate file,           default %s\n", cliCert);
    printf("-k <file>   Key file,                   default %s\n", cliKey);
    printf("-A <file>   Certificate Authority file, default %s\n", caCert);
    printf("-b <num>    Benchmark <num> connections and print stats\n");
    printf("-s          Use pre Shared keys\n");
    printf("-d          Disable peer checks\n");
    printf("-g          Send server HTTP GET\n");
    printf("-u          Use UDP DTLS\n");
    printf("-m          Match domain name in cert\n");
    printf("-N          Use Non-blocking sockets\n");
    printf("-r          Resume session\n");
}


void client_test(void* args)
{
    SOCKET_T sockfd = 0;

    CYASSL_METHOD*  method  = 0;
    CYASSL_CTX*     ctx     = 0;
    CYASSL*         ssl     = 0;
    
    CYASSL*         sslResume = 0;
    CYASSL_SESSION* session = 0;
    char         resumeMsg[] = "resuming cyassl!";
    int          resumeSz    = sizeof(resumeMsg);

    char msg[64] = "hello cyassl!";
    char reply[1024];
    int  input;
    int  msgSz = (int)strlen(msg);

    int   port   = yasslPort;
    char* host   = (char*)yasslIP;
    char* domain = (char*)"www.yassl.com";

    int    ch;
    int    version = CLIENT_DEFAULT_VERSION;
    int    usePsk   = 0;
    int    sendGET  = 0;
    int    benchmark = 0;
    int    doDTLS    = 0;
    int    matchName = 0;
    int    doPeerCheck = 1;
    int    nonBlocking = 0;
    int    resumeSession = 0;
    char*  cipherList = NULL;
    char*  verifyCert = (char*)caCert;
    char*  ourCert    = (char*)cliCert;
    char*  ourKey     = (char*)cliKey;

    int     argc = ((func_args*)args)->argc;
    char**  argv = ((func_args*)args)->argv;

    ((func_args*)args)->return_code = -1; /* error state */

    while ((ch = mygetopt(argc, argv, "?gdusmNrh:p:v:l:A:c:k:b:")) != -1) {
        switch (ch) {
            case '?' :
                Usage();
                exit(EXIT_SUCCESS);

            case 'g' :
                sendGET = 1;
                break;

            case 'd' :
                doPeerCheck = 0;
                break;

            case 'u' :
                doDTLS  = 1;
                version = -1;  /* DTLS flag */
                break;

            case 's' :
                usePsk = 1;
                break;

            case 'm' :
                matchName = 1;
                break;

            case 'h' :
                host   = myoptarg;
                domain = myoptarg;
                break;

            case 'p' :
                port = atoi(myoptarg);
                break;

            case 'v' :
                version = atoi(myoptarg);
                if (version < 0 || version > 3) {
                    Usage();
                    exit(MY_EX_USAGE);
                }
                if (doDTLS)
                    version = -1;   /* DTLS flag */
                break;

            case 'l' :
                cipherList = myoptarg;
                break;

            case 'A' :
                verifyCert = myoptarg;
                break;

            case 'c' :
                ourCert = myoptarg;
                break;

            case 'k' :
                ourKey = myoptarg;
                break;

            case 'b' :
                benchmark = atoi(myoptarg);
                if (benchmark < 0 || benchmark > 1000000) {
                    Usage();
                    exit(MY_EX_USAGE);
                }
                break;

            case 'N' :
                nonBlocking = 1;
                break;

            case 'r' :
                resumeSession = 1;
                break;

            default:
                Usage();
                exit(MY_EX_USAGE);
        }
    }

    myoptind = 0;      /* reset for test cases */

    switch (version) {
#ifndef NO_OLD_TLS
        case 0:
            method = CyaSSLv3_client_method();
            break;

        case 1:
            method = CyaTLSv1_client_method();
            break;

        case 2:
            method = CyaTLSv1_1_client_method();
            break;
#endif

        case 3:
            method = CyaTLSv1_2_client_method();
            break;

#ifdef CYASSL_DTLS
        case -1:
            method = CyaDTLSv1_client_method();
            break;
#endif

        default:
            err_sys("Bad SSL version");
    }

    if (method == NULL)
        err_sys("unable to get method");

    ctx = CyaSSL_CTX_new(method);
    if (ctx == NULL)
        err_sys("unable to get ctx");

    if (cipherList)
        if (CyaSSL_CTX_set_cipher_list(ctx, cipherList) != SSL_SUCCESS)
            err_sys("can't set cipher list");

#ifdef CYASSL_LEANPSK
    usePsk = 1;
#endif

    if (usePsk) {
#ifndef NO_PSK
        CyaSSL_CTX_set_psk_client_callback(ctx, my_psk_client_cb);
        if (cipherList == NULL) {
            const char *defaultCipherList;
            #ifdef HAVE_NULL_CIPHER
                defaultCipherList = "PSK-NULL-SHA";
            #else
                defaultCipherList = "PSK-AES256-CBC-SHA";
            #endif
            if (CyaSSL_CTX_set_cipher_list(ctx,defaultCipherList) !=SSL_SUCCESS)
                err_sys("can't set cipher list");
        }
#endif
    }

#ifdef OPENSSL_EXTRA
    CyaSSL_CTX_set_default_passwd_cb(ctx, PasswordCallBack);
#endif

#if defined(CYASSL_SNIFFER) && !defined(HAVE_NTRU) && !defined(HAVE_ECC)
    if (cipherList == NULL) {
        /* don't use EDH, can't sniff tmp keys */
        if (CyaSSL_CTX_set_cipher_list(ctx, "AES256-SHA") != SSL_SUCCESS) {
            err_sys("can't set cipher list");
        }
    }
#endif

#ifdef USER_CA_CB
    CyaSSL_CTX_SetCACb(ctx, CaCb);
#endif

#ifdef VERIFY_CALLBACK
    CyaSSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, myVerify);
#endif
#ifndef NO_FILESYSTEM   
    if (!usePsk){
        if (CyaSSL_CTX_use_certificate_file(ctx, ourCert, SSL_FILETYPE_PEM)
                                     != SSL_SUCCESS)
            err_sys("can't load client cert file, check file and run from"
                    " CyaSSL home dir");

        if (CyaSSL_CTX_use_PrivateKey_file(ctx, ourKey, SSL_FILETYPE_PEM)
                                         != SSL_SUCCESS)
            err_sys("can't load client cert file, check file and run from"
                    " CyaSSL home dir");    

        if (CyaSSL_CTX_load_verify_locations(ctx, verifyCert, 0) != SSL_SUCCESS)
                err_sys("can't load ca file, Please run from CyaSSL home dir");
    }
#endif
    if (!usePsk && doPeerCheck == 0)
        CyaSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);

    if (benchmark) {
        /* time passed in number of connects give average */
        int times = benchmark;
        int i = 0;

        double start = current_time(), avg;

        for (i = 0; i < times; i++) {
            tcp_connect(&sockfd, host, port, doDTLS);
            ssl = CyaSSL_new(ctx);
            CyaSSL_set_fd(ssl, sockfd);
            if (CyaSSL_connect(ssl) != SSL_SUCCESS)
                err_sys("SSL_connect failed");

            CyaSSL_shutdown(ssl);
            CyaSSL_free(ssl);
            CloseSocket(sockfd);
        }
        avg = current_time() - start;
        avg /= times;
        avg *= 1000;   /* milliseconds */
        printf("CyaSSL_connect avg took: %8.3f milliseconds\n", avg);

        CyaSSL_CTX_free(ctx);
        ((func_args*)args)->return_code = 0;

        exit(EXIT_SUCCESS);
    }

    ssl = CyaSSL_new(ctx);
    if (ssl == NULL)
        err_sys("unable to get SSL object");
    if (doDTLS) {
        SOCKADDR_IN_T addr;
        build_addr(&addr, host, port);
        CyaSSL_dtls_set_peer(ssl, &addr, sizeof(addr));
        tcp_socket(&sockfd, 1);
    }
    else {
        tcp_connect(&sockfd, host, port, 0);
    }
    CyaSSL_set_fd(ssl, sockfd);
#ifdef HAVE_CRL
    if (CyaSSL_EnableCRL(ssl, CYASSL_CRL_CHECKALL) != SSL_SUCCESS)
        err_sys("can't enable crl check");
    if (CyaSSL_LoadCRL(ssl, crlPemDir, SSL_FILETYPE_PEM, 0) != SSL_SUCCESS)
        err_sys("can't load crl, check crlfile and date validity");
    if (CyaSSL_SetCRL_Cb(ssl, CRL_CallBack) != SSL_SUCCESS)
        err_sys("can't set crl callback");
#endif
    if (matchName && doPeerCheck)
        CyaSSL_check_domain_name(ssl, domain);
#ifndef CYASSL_CALLBACKS
    if (nonBlocking) {
        CyaSSL_set_using_nonblock(ssl, 1);
        tcp_set_nonblocking(&sockfd);
        NonBlockingSSL_Connect(ssl);
    }
    else if (CyaSSL_connect(ssl) != SSL_SUCCESS) {
        /* see note at top of README */
        int  err = CyaSSL_get_error(ssl, 0);
        char buffer[80];
        printf("err = %d, %s\n", err,
                                CyaSSL_ERR_error_string(err, buffer));
        err_sys("SSL_connect failed");
        /* if you're getting an error here  */
    }
#else
    timeout.tv_sec  = 2;
    timeout.tv_usec = 0;
    NonBlockingSSL_Connect(ssl);  /* will keep retrying on timeout */
#endif
    showPeer(ssl);

    if (sendGET) {
        printf("SSL connect ok, sending GET...\n");
        msgSz = 28;
        strncpy(msg, "GET /index.html HTTP/1.0\r\n\r\n", msgSz);
    }
    if (CyaSSL_write(ssl, msg, msgSz) != msgSz)
        err_sys("SSL_write failed");

    input = CyaSSL_read(ssl, reply, sizeof(reply));
    if (input > 0) {
        reply[input] = 0;
        printf("Server response: %s\n", reply);

        if (sendGET) {  /* get html */
            while (1) {
                input = CyaSSL_read(ssl, reply, sizeof(reply));
                if (input > 0) {
                    reply[input] = 0;
                    printf("%s\n", reply);
                }
                else
                    break;
            }
        }
    }

    if (resumeSession) {
        if (doDTLS) {
            strncpy(msg, "break", 6);
            msgSz = (int)strlen(msg);
            /* try to send session close */
            CyaSSL_write(ssl, msg, msgSz);
        }
        session   = CyaSSL_get_session(ssl);
        sslResume = CyaSSL_new(ctx);
    }

    if (doDTLS == 0)            /* don't send alert after "break" command */
        CyaSSL_shutdown(ssl);  /* echoserver will interpret as new conn */
    CyaSSL_free(ssl);
    CloseSocket(sockfd);

    if (resumeSession) {
        if (doDTLS) {
            SOCKADDR_IN_T addr;
            #ifdef USE_WINDOWS_API 
                Sleep(500);
            #else
                sleep(1);
            #endif
            build_addr(&addr, host, port);
            CyaSSL_dtls_set_peer(sslResume, &addr, sizeof(addr));
            tcp_socket(&sockfd, 1);
        }
        else {
            tcp_connect(&sockfd, host, port, 0);
        }
        CyaSSL_set_fd(sslResume, sockfd);
        CyaSSL_set_session(sslResume, session);
       
        showPeer(sslResume);
#ifndef CYASSL_CALLBACKS
        if (nonBlocking) {
            CyaSSL_set_using_nonblock(sslResume, 1);
            tcp_set_nonblocking(&sockfd);
            NonBlockingSSL_Connect(sslResume);
        }
        else if (CyaSSL_connect(sslResume) != SSL_SUCCESS)
            err_sys("SSL resume failed");
#else
        timeout.tv_sec  = 2;
        timeout.tv_usec = 0;
        NonBlockingSSL_Connect(ssl);  /* will keep retrying on timeout */
#endif

#ifdef OPENSSL_EXTRA
        if (CyaSSL_session_reused(sslResume))
            printf("reused session id\n");
        else
            printf("didn't reuse session id!!!\n");
#endif
      
        if (CyaSSL_write(sslResume, resumeMsg, resumeSz) != resumeSz)
            err_sys("SSL_write failed");

        if (nonBlocking) {
            /* give server a chance to bounce a message back to client */
            #ifdef USE_WINDOWS_API
                Sleep(500);
            #else
                sleep(1);
            #endif
        }

        input = CyaSSL_read(sslResume, reply, sizeof(reply));
        if (input > 0) {
            reply[input] = 0;
            printf("Server resume response: %s\n", reply);
        }

        /* try to send session break */
        CyaSSL_write(sslResume, msg, msgSz); 

        CyaSSL_shutdown(sslResume);
        CyaSSL_free(sslResume);
    }

    CyaSSL_CTX_free(ctx);
    CloseSocket(sockfd);

    ((func_args*)args)->return_code = 0;
}


/* so overall tests can pull in test function */
#ifndef NO_MAIN_DRIVER

    int main(int argc, char** argv)
    {
        func_args args;

        StartTCP();

        args.argc = argc;
        args.argv = argv;

        CyaSSL_Init();
#ifdef DEBUG_CYASSL
        CyaSSL_Debugging_ON();
#endif
        if (CurrentDir("client") || CurrentDir("build"))
            ChangeDirBack(2);
   
        client_test(&args);
        CyaSSL_Cleanup();

        return args.return_code;
    }

    int myoptind = 0;
    char* myoptarg = NULL;

#endif /* NO_MAIN_DRIVER */



#ifdef CYASSL_CALLBACKS

    int handShakeCB(HandShakeInfo* info)
    {

        return 0;
    }


    int timeoutCB(TimeoutInfo* info)
    {

        return 0;
    }

#endif


