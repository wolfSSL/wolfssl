/* server.c
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
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


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#include <cyassl/ssl.h> /* name change portability layer */

#include <cyassl/ctaocrypt/settings.h>
#ifdef HAVE_ECC
    #include <cyassl/ctaocrypt/ecc.h>   /* ecc_fp_free */
#endif

#if !defined(WOLFSSL_TRACK_MEMORY) && !defined(NO_MAIN_DRIVER)
    /* in case memory tracker wants stats */
    #define WOLFSSL_TRACK_MEMORY
#endif

#if defined(WOLFSSL_MDK_ARM) || defined(WOLFSSL_KEIL_TCP_NET)
        #include <stdio.h>
        #include <string.h>

        #if  !defined(WOLFSSL_MDK_ARM)
            #include "cmsis_os.h"
            #include "rl_fs.h"
            #include "rl_net.h"
        #else
            #include "rtl.h"
            #include "wolfssl_MDK_ARM.h"
        #endif


#endif
#include <cyassl/openssl/ssl.h>
#include <cyassl/test.h>

#include "examples/server/server.h"

/* Note on using port 0: if the server uses port 0 to bind an ephemeral port
 * number and is using the ready file for scripted testing, the code in
 * test.h will write the actual port number into the ready file for use
 * by the client. */

#ifdef CYASSL_CALLBACKS
    int srvHandShakeCB(HandShakeInfo*);
    int srvTimeoutCB(TimeoutInfo*);
    Timeval srvTo;
#endif

#ifndef NO_HANDSHAKE_DONE_CB
    int myHsDoneCb(WOLFSSL* ssl, void* user_ctx);
#endif



static void NonBlockingSSL_Accept(SSL* ssl)
{
#ifndef CYASSL_CALLBACKS
    int ret = SSL_accept(ssl);
#else
    int ret = CyaSSL_accept_ex(ssl, srvHandShakeCB, srvTimeoutCB, srvTo);
#endif
    int error = SSL_get_error(ssl, 0);
    SOCKET_T sockfd = (SOCKET_T)CyaSSL_get_fd(ssl);
    int select_ret;

    while (ret != SSL_SUCCESS && (error == SSL_ERROR_WANT_READ ||
                                  error == SSL_ERROR_WANT_WRITE)) {
        int currTimeout = 1;

        if (error == SSL_ERROR_WANT_READ) {
            /* printf("... server would read block\n"); */
        } else {
            /* printf("... server would write block\n"); */
        }

#ifdef CYASSL_DTLS
        currTimeout = CyaSSL_dtls_get_current_timeout(ssl);
#endif
        select_ret = tcp_select(sockfd, currTimeout);

        if ((select_ret == TEST_RECV_READY) ||
                                        (select_ret == TEST_ERROR_READY)) {
            #ifndef CYASSL_CALLBACKS
                ret = SSL_accept(ssl);
            #else
                ret = CyaSSL_accept_ex(ssl,
                                    srvHandShakeCB, srvTimeoutCB, srvTo);
            #endif
            error = SSL_get_error(ssl, 0);
        }
        else if (select_ret == TEST_TIMEOUT && !CyaSSL_dtls(ssl)) {
            error = SSL_ERROR_WANT_READ;
        }
#ifdef CYASSL_DTLS
        else if (select_ret == TEST_TIMEOUT && CyaSSL_dtls(ssl) &&
                                            CyaSSL_dtls_got_timeout(ssl) >= 0) {
            error = SSL_ERROR_WANT_READ;
        }
#endif
        else {
            error = SSL_FATAL_ERROR;
        }
    }
    if (ret != SSL_SUCCESS)
        err_sys("SSL_accept failed");
}

/* Echo number of bytes specified by -e arg */
int ServerEchoData(SSL* ssl, int clientfd, int echoData, int throughput)
{
    int ret = 0;
    char* buffer = (char*)malloc(TEST_BUFFER_SIZE);
    if(buffer) {
        double start = 0, rx_time = 0, tx_time = 0;
        int xfer_bytes = 0;
        while((echoData && throughput == 0) || (!echoData && xfer_bytes < throughput)) {
            int select_ret = tcp_select(clientfd, 1); /* Timeout=1 second */
            if (select_ret == TEST_RECV_READY) {
                int len = min(TEST_BUFFER_SIZE, throughput - xfer_bytes);
                int rx_pos = 0;
                if(throughput) {
                    start = current_time();
                }
                while(rx_pos < len) {
                    ret = SSL_read(ssl, &buffer[rx_pos], len - rx_pos);
                    if (ret <= 0) {
                        int readErr = SSL_get_error(ssl, 0);
                        if (readErr != SSL_ERROR_WANT_READ) {
                            printf("SSL_read error %d!\n", readErr);
                            err_sys("SSL_read failed");
                        }
                    }
                    else {
                        rx_pos += ret;
                    }
                }
                if(throughput) {
                    rx_time += current_time() - start;
                    start = current_time();
                }
                if (SSL_write(ssl, buffer, len) != len) {
                    err_sys("SSL_write failed");
                }
                if(throughput) {
                    tx_time += current_time() - start;
                }

                xfer_bytes += len;
            }
        }
        free(buffer);

        if(throughput) {
            printf("wolfSSL Server Benchmark %d bytes\n"
                "\tRX      %8.3f ms (%8.3f MBps)\n"
                "\tTX      %8.3f ms (%8.3f MBps)\n",
                throughput,
                tx_time * 1000, throughput / tx_time / 1024 / 1024,
                rx_time * 1000, throughput / rx_time / 1024 / 1024
            );
        }
    }
    else {
        err_sys("Server buffer malloc failed");
    }

    return EXIT_SUCCESS;
}


static void Usage(void)
{
    printf("server "    LIBCYASSL_VERSION_STRING
           " NOTE: All files relative to wolfSSL home dir\n");
    printf("-?          Help, print this usage\n");
    printf("-p <num>    Port to listen on, not 0, default %d\n", yasslPort);
    printf("-v <num>    SSL version [0-3], SSLv3(0) - TLS1.2(3)), default %d\n",
                                 SERVER_DEFAULT_VERSION);
    printf("-l <str>    Cipher suite list (: delimited)\n");
    printf("-c <file>   Certificate file,           default %s\n", svrCert);
    printf("-k <file>   Key file,                   default %s\n", svrKey);
    printf("-A <file>   Certificate Authority file, default %s\n", cliCert);
    printf("-R <file>   Create Ready file for external monitor default none\n");
#ifndef NO_DH
    printf("-D <file>   Diffie-Hellman Params file, default %s\n", dhParam);
    printf("-Z <num>    Minimum DH key bits,        default %d\n",
                                 DEFAULT_MIN_DHKEY_BITS);
#endif
#ifdef HAVE_ALPN
    printf("-L <str>    Application-Layer Protocol Negotiation ({C,F}:<list>)\n");
#endif
    printf("-d          Disable client cert check\n");
    printf("-b          Bind to any interface instead of localhost only\n");
    printf("-s          Use pre Shared keys\n");
    printf("-t          Track wolfSSL memory use\n");
    printf("-u          Use UDP DTLS,"
           " add -v 2 for DTLSv1, -v 3 for DTLSv1.2 (default)\n");
    printf("-f          Fewer packets/group messages\n");
    printf("-r          Allow one client Resumption\n");
    printf("-N          Use Non-blocking sockets\n");
    printf("-S <str>    Use Host Name Indication\n");
    printf("-w          Wait for bidirectional shutdown\n");
#ifdef HAVE_OCSP
    printf("-o          Perform OCSP lookup on peer certificate\n");
    printf("-O <url>    Perform OCSP lookup using <url> as responder\n");
#endif
#ifdef HAVE_PK_CALLBACKS
    printf("-P          Public Key Callbacks\n");
#endif
#ifdef HAVE_ANON
    printf("-a          Anonymous server\n");
#endif
#ifndef NO_PSK
    printf("-I          Do not send PSK identity hint\n");
#endif
    printf("-i          Loop indefinitely (allow repeated connections)\n");
    printf("-e          Echo data mode (return raw bytes received)\n");
#ifdef HAVE_NTRU
    printf("-n          Use NTRU key (needed for NTRU suites)\n");
#endif
    printf("-B <num>    Benchmark throughput using <num> bytes and print stats\n");
#ifdef WOLFSSL_TRUST_PEER_CERT
    printf("-E <file>   Path to load trusted peer cert\n");
#endif
}

THREAD_RETURN CYASSL_THREAD server_test(void* args)
{
    SOCKET_T sockfd   = WOLFSSL_SOCKET_INVALID;
    SOCKET_T clientfd = WOLFSSL_SOCKET_INVALID;

    SSL_METHOD* method = 0;
    SSL_CTX*    ctx    = 0;
    SSL*        ssl    = 0;

    const char msg[] = "I hear you fa shizzle!";
    char   input[80];
    int    ch;
    int    version = SERVER_DEFAULT_VERSION;
    int    doCliCertCheck = 1;
    int    useAnyAddr = 0;
    word16 port = wolfSSLPort;
    int    usePsk = 0;
    int    usePskPlus = 0;
    int    useAnon = 0;
    int    doDTLS = 0;
    int    needDH = 0;
    int    useNtruKey   = 0;
    int    nonBlocking  = 0;
    int    trackMemory  = 0;
    int    fewerPackets = 0;
    int    pkCallbacks  = 0;
    int    wc_shutdown     = 0;
    int    resume = 0;
    int    resumeCount = 0;
    int    loopIndefinitely = 0;
    int    echoData = 0;
    int    throughput = 0;
    int    minDhKeyBits = DEFAULT_MIN_DHKEY_BITS;
    int    doListen = 1;
    int    crlFlags = 0;
    int    ret;
    char*  serverReadyFile = NULL;
    char*  alpnList = NULL;
    unsigned char alpn_opt = 0;
    char*  cipherList = NULL;
    const char* verifyCert = cliCert;
    const char* ourCert    = svrCert;
    const char* ourKey     = svrKey;
    const char* ourDhParam = dhParam;
    tcp_ready*  readySignal = NULL;
    int    argc = ((func_args*)args)->argc;
    char** argv = ((func_args*)args)->argv;

#ifdef WOLFSSL_TRUST_PEER_CERT
    const char* trustCert  = NULL;
#endif

#ifndef NO_PSK
    int sendPskIdentityHint = 1;
#endif

#ifdef HAVE_SNI
    char*  sniHostName = NULL;
#endif

#ifdef HAVE_OCSP
    int    useOcsp  = 0;
    char*  ocspUrl  = NULL;
#endif

    ((func_args*)args)->return_code = -1; /* error state */

#ifdef NO_RSA
    verifyCert = (char*)cliEccCert;
    ourCert    = (char*)eccCert;
    ourKey     = (char*)eccKey;
#endif
    (void)trackMemory;
    (void)pkCallbacks;
    (void)needDH;
    (void)ourKey;
    (void)ourCert;
    (void)ourDhParam;
    (void)verifyCert;
    (void)useNtruKey;
    (void)doCliCertCheck;
    (void)minDhKeyBits;
    (void)alpnList;
    (void)alpn_opt;
    (void)crlFlags;
    (void)readySignal;

#ifdef CYASSL_TIRTOS
    fdOpenSession(Task_self());
#endif

#ifdef WOLFSSL_VXWORKS
    useAnyAddr = 1;
#else
    while ((ch = mygetopt(argc, argv, "?jdbstnNufrawPIR:p:v:l:A:c:k:Z:S:oO:D:L:ieB:E:"))
                         != -1) {
        switch (ch) {
            case '?' :
                Usage();
                exit(EXIT_SUCCESS);

            case 'd' :
                doCliCertCheck = 0;
                break;

            case 'b' :
                useAnyAddr = 1;
                break;

            case 's' :
                usePsk = 1;
                break;

            case 'j' :
                usePskPlus = 1;
                break;

            case 't' :
            #ifdef USE_WOLFSSL_MEMORY
                trackMemory = 1;
            #endif
                break;

            case 'n' :
                useNtruKey = 1;
                break;

            case 'u' :
                doDTLS  = 1;
                break;

            case 'f' :
                fewerPackets = 1;
                break;

            case 'R' :
                serverReadyFile = myoptarg;
                break;

            case 'r' :
                #ifndef NO_SESSION_CACHE
                    resume = 1;
                #endif
                break;

            case 'P' :
            #ifdef HAVE_PK_CALLBACKS
                pkCallbacks = 1;
            #endif
                break;

            case 'p' :
                port = (word16)atoi(myoptarg);
                #if defined(USE_WINDOWS_API)
                    if (port == 0)
                        err_sys("port number cannot be 0");
                #endif
                break;

            case 'w' :
                wc_shutdown = 1;
                break;

            case 'v' :
                version = atoi(myoptarg);
                if (version < 0 || version > 3) {
                    Usage();
                    exit(MY_EX_USAGE);
                }
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

            case 'D' :
                #ifndef NO_DH
                    ourDhParam = myoptarg;
                #endif
                break;

            case 'Z' :
                #ifndef NO_DH
                    minDhKeyBits = atoi(myoptarg);
                    if (minDhKeyBits <= 0 || minDhKeyBits > 16000) {
                        Usage();
                        exit(MY_EX_USAGE);
                    }
                #endif
                break;

            case 'N':
                nonBlocking = 1;
                break;

            case 'S' :
                #ifdef HAVE_SNI
                    sniHostName = myoptarg;
                #endif
                break;

            case 'o' :
                #ifdef HAVE_OCSP
                    useOcsp = 1;
                #endif
                break;

            case 'O' :
                #ifdef HAVE_OCSP
                    useOcsp = 1;
                    ocspUrl = myoptarg;
                #endif
                break;

            case 'a' :
                #ifdef HAVE_ANON
                    useAnon = 1;
                #endif
                break;
            case 'I':
                #ifndef NO_PSK
                    sendPskIdentityHint = 0;
                #endif
                break;

            case 'L' :
                #ifdef HAVE_ALPN
                    alpnList = myoptarg;

                    if (alpnList[0] == 'C' && alpnList[1] == ':')
                        alpn_opt = WOLFSSL_ALPN_CONTINUE_ON_MISMATCH;
                    else if (alpnList[0] == 'F' && alpnList[1] == ':')
                        alpn_opt = WOLFSSL_ALPN_FAILED_ON_MISMATCH;
                    else {
                        Usage();
                        exit(MY_EX_USAGE);
                    }

                    alpnList += 2;

                #endif
                break;

            case 'i' :
                loopIndefinitely = 1;
                break;

            case 'e' :
                echoData = 1;
                break;

            case 'B':
                throughput = atoi(myoptarg);
                if (throughput <= 0) {
                    Usage();
                    exit(MY_EX_USAGE);
                }
                break;

            #ifdef WOLFSSL_TRUST_PEER_CERT
            case 'E' :
                 trustCert = myoptarg;
                break;
            #endif

            default:
                Usage();
                exit(MY_EX_USAGE);
        }
    }

    myoptind = 0;      /* reset for test cases */
#endif /* !WOLFSSL_VXWORKS */

    /* sort out DTLS versus TLS versions */
    if (version == CLIENT_INVALID_VERSION) {
        if (doDTLS)
            version = CLIENT_DTLS_DEFAULT_VERSION;
        else
            version = CLIENT_DEFAULT_VERSION;
    }
    else {
        if (doDTLS) {
            if (version == 3)
                version = -2;
            else
                version = -1;
        }
    }

#ifdef USE_CYASSL_MEMORY
    if (trackMemory)
        InitMemoryTracker();
#endif

    switch (version) {
#ifndef NO_OLD_TLS
    #ifdef WOLFSSL_ALLOW_SSLV3
        case 0:
            method = SSLv3_server_method();
            break;
    #endif

    #ifndef NO_TLS
        case 1:
            method = TLSv1_server_method();
            break;


        case 2:
            method = TLSv1_1_server_method();
            break;

        #endif
#endif

#ifndef NO_TLS
        case 3:
            method = TLSv1_2_server_method();
            break;
#endif

#ifdef CYASSL_DTLS
    #ifndef NO_OLD_TLS
        case -1:
            method = DTLSv1_server_method();
            break;
    #endif

        case -2:
            method = DTLSv1_2_server_method();
            break;
#endif

        default:
            err_sys("Bad SSL version");
    }

    if (method == NULL)
        err_sys("unable to get method");

    ctx = SSL_CTX_new(method);
    if (ctx == NULL)
        err_sys("unable to get ctx");

#if defined(HAVE_SESSION_TICKET) && defined(HAVE_CHACHA) && \
                                    defined(HAVE_POLY1305)
    if (TicketInit() != 0)
        err_sys("unable to setup Session Ticket Key context");
    wolfSSL_CTX_set_TicketEncCb(ctx, myTicketEncCb);
#endif

    if (cipherList)
        if (SSL_CTX_set_cipher_list(ctx, cipherList) != SSL_SUCCESS)
            err_sys("server can't set cipher list 1");

#ifdef CYASSL_LEANPSK
    usePsk = 1;
#endif

#if defined(NO_RSA) && !defined(HAVE_ECC)
    usePsk = 1;
#endif

    if (fewerPackets)
        CyaSSL_CTX_set_group_messages(ctx);

#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER)
    SSL_CTX_set_default_passwd_cb(ctx, PasswordCallBack);
#endif

#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS)
    if ((!usePsk || usePskPlus) && !useAnon) {
        if (SSL_CTX_use_certificate_chain_file(ctx, ourCert)
                                         != SSL_SUCCESS)
            err_sys("can't load server cert file, check file and run from"
                    " wolfSSL home dir");
    }
#endif

#ifndef NO_DH
    wolfSSL_CTX_SetMinDhKey_Sz(ctx, (word16)minDhKeyBits);
#endif

#ifdef HAVE_NTRU
    if (useNtruKey) {
        if (CyaSSL_CTX_use_NTRUPrivateKey_file(ctx, ourKey)
                                != SSL_SUCCESS)
            err_sys("can't load ntru key file, "
                    "Please run from wolfSSL home dir");
    }
#endif
#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS)
    if (!useNtruKey && (!usePsk || usePskPlus) && !useAnon) {
        if (SSL_CTX_use_PrivateKey_file(ctx, ourKey, SSL_FILETYPE_PEM)
                                         != SSL_SUCCESS)
            err_sys("can't load server private key file, check file and run "
                "from wolfSSL home dir");
    }
#endif

    if (usePsk || usePskPlus) {
#ifndef NO_PSK
        SSL_CTX_set_psk_server_callback(ctx, my_psk_server_cb);

        if (sendPskIdentityHint == 1)
            SSL_CTX_use_psk_identity_hint(ctx, "cyassl server");

        if (cipherList == NULL && !usePskPlus) {
            const char *defaultCipherList;
            #if defined(HAVE_AESGCM) && !defined(NO_DH)
                defaultCipherList = "DHE-PSK-AES128-GCM-SHA256";
                needDH = 1;
            #elif defined(HAVE_NULL_CIPHER)
                defaultCipherList = "PSK-NULL-SHA256";
            #else
                defaultCipherList = "PSK-AES128-CBC-SHA256";
            #endif
            if (SSL_CTX_set_cipher_list(ctx, defaultCipherList) != SSL_SUCCESS)
                err_sys("server can't set cipher list 2");
        }
#endif
    }

    if (useAnon) {
#ifdef HAVE_ANON
        CyaSSL_CTX_allow_anon_cipher(ctx);
        if (cipherList == NULL) {
            if (SSL_CTX_set_cipher_list(ctx, "ADH-AES128-SHA") != SSL_SUCCESS)
                err_sys("server can't set cipher list 4");
        }
#endif
    }

#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS)
    /* if not using PSK, verify peer with certs
       if using PSK Plus then verify peer certs except PSK suites */
    if (doCliCertCheck && (usePsk == 0 || usePskPlus) && useAnon == 0) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER |
                                ((usePskPlus)? SSL_VERIFY_FAIL_EXCEPT_PSK :
                                SSL_VERIFY_FAIL_IF_NO_PEER_CERT),0);
        if (SSL_CTX_load_verify_locations(ctx, verifyCert, 0) != SSL_SUCCESS)
            err_sys("can't load ca file, Please run from wolfSSL home dir");
        #ifdef WOLFSSL_TRUST_PEER_CERT
        if (trustCert) {
            if ((ret = wolfSSL_CTX_trust_peer_cert(ctx, trustCert,
                                            SSL_FILETYPE_PEM)) != SSL_SUCCESS) {
                err_sys("can't load trusted peer cert file");
            }
        }
        #endif /* WOLFSSL_TRUST_PEER_CERT */
   }
#endif

#if defined(CYASSL_SNIFFER)
    /* don't use EDH, can't sniff tmp keys */
    if (cipherList == NULL) {
        if (SSL_CTX_set_cipher_list(ctx, "AES128-SHA") != SSL_SUCCESS)
            err_sys("server can't set cipher list 3");
    }
#endif

#ifdef HAVE_SNI
    if (sniHostName)
        if (CyaSSL_CTX_UseSNI(ctx, CYASSL_SNI_HOST_NAME, sniHostName,
                                           XSTRLEN(sniHostName)) != SSL_SUCCESS)
            err_sys("UseSNI failed");
#endif

    while (1) {
        /* allow resume option */
        if(resumeCount > 1) {
            if (doDTLS == 0) {
                SOCKADDR_IN_T client;
                socklen_t client_len = sizeof(client);
                clientfd = accept(sockfd, (struct sockaddr*)&client,
                                 (ACCEPT_THIRD_T)&client_len);
            } else {
                tcp_listen(&sockfd, &port, useAnyAddr, doDTLS);
                clientfd = sockfd;
            }
            if(WOLFSSL_SOCKET_IS_INVALID(clientfd)) {
                err_sys("tcp accept failed");
            }
        }

        ssl = SSL_new(ctx);
        if (ssl == NULL)
            err_sys("unable to get SSL");

#ifndef NO_HANDSHAKE_DONE_CB
        wolfSSL_SetHsDoneCb(ssl, myHsDoneCb, NULL);
#endif
#ifdef HAVE_CRL
#ifdef HAVE_CRL_MONITOR
        crlFlags = CYASSL_CRL_MONITOR | CYASSL_CRL_START_MON;
#endif
        if (CyaSSL_EnableCRL(ssl, 0) != SSL_SUCCESS)
            err_sys("unable to enable CRL");
        if (CyaSSL_LoadCRL(ssl, crlPemDir, SSL_FILETYPE_PEM, crlFlags)
                                                                 != SSL_SUCCESS)
            err_sys("unable to load CRL");
        if (CyaSSL_SetCRL_Cb(ssl, CRL_CallBack) != SSL_SUCCESS)
            err_sys("unable to set CRL callback url");
#endif
#ifdef HAVE_OCSP
        if (useOcsp) {
            if (ocspUrl != NULL) {
                CyaSSL_CTX_SetOCSP_OverrideURL(ctx, ocspUrl);
                CyaSSL_CTX_EnableOCSP(ctx, CYASSL_OCSP_NO_NONCE
                                                        | CYASSL_OCSP_URL_OVERRIDE);
            }
            else
                CyaSSL_CTX_EnableOCSP(ctx, CYASSL_OCSP_NO_NONCE);
        }
#endif
#if defined(HAVE_CERTIFICATE_STATUS_REQUEST) \
 || defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2)
        if (wolfSSL_CTX_EnableOCSPStapling(ctx) != SSL_SUCCESS)
            err_sys("can't enable OCSP Stapling Certificate Manager");
        if (SSL_CTX_load_verify_locations(ctx, "certs/ocsp/intermediate1-ca-cert.pem", 0) != SSL_SUCCESS)
            err_sys("can't load ca file, Please run from wolfSSL home dir");
        if (SSL_CTX_load_verify_locations(ctx, "certs/ocsp/intermediate2-ca-cert.pem", 0) != SSL_SUCCESS)
            err_sys("can't load ca file, Please run from wolfSSL home dir");
        if (SSL_CTX_load_verify_locations(ctx, "certs/ocsp/intermediate3-ca-cert.pem", 0) != SSL_SUCCESS)
            err_sys("can't load ca file, Please run from wolfSSL home dir");
#endif
#ifdef HAVE_PK_CALLBACKS
        if (pkCallbacks)
            SetupPkCallbacks(ctx, ssl);
#endif

        /* do accept */
        readySignal = ((func_args*)args)->signal;
        if (readySignal) {
            readySignal->srfName = serverReadyFile;
        }
        tcp_accept(&sockfd, &clientfd, (func_args*)args, port, useAnyAddr,
                       doDTLS, serverReadyFile ? 1 : 0, doListen);
        doListen = 0; /* Don't listen next time */

        SSL_set_fd(ssl, clientfd);

#ifdef HAVE_ALPN
        if (alpnList != NULL) {
            printf("ALPN accepted protocols list : %s\n", alpnList);
            wolfSSL_UseALPN(ssl, alpnList, (word32)XSTRLEN(alpnList), alpn_opt);
        }
#endif

#ifdef WOLFSSL_DTLS
        if (doDTLS) {
            SOCKADDR_IN_T cliaddr;
            byte          b[1500];
            int           n;
            socklen_t     len = sizeof(cliaddr);

            /* For DTLS, peek at the next datagram so we can get the client's
             * address and set it into the ssl object later to generate the
             * cookie. */
            n = (int)recvfrom(sockfd, (char*)b, sizeof(b), MSG_PEEK,
                              (struct sockaddr*)&cliaddr, &len);
            if (n <= 0)
                err_sys("recvfrom failed");

            wolfSSL_dtls_set_peer(ssl, &cliaddr, len);
        }
#endif
        if ((usePsk == 0 || usePskPlus) || useAnon == 1 || cipherList != NULL
                                                               || needDH == 1) {
            #if !defined(NO_FILESYSTEM) && !defined(NO_DH) && !defined(NO_ASN)
                CyaSSL_SetTmpDH_file(ssl, ourDhParam, SSL_FILETYPE_PEM);
            #elif !defined(NO_DH)
                SetDH(ssl);  /* repick suites with DHE, higher priority than PSK */
            #endif
        }

#ifndef CYASSL_CALLBACKS
        if (nonBlocking) {
            CyaSSL_set_using_nonblock(ssl, 1);
            tcp_set_nonblocking(&clientfd);
            NonBlockingSSL_Accept(ssl);
        } else if (SSL_accept(ssl) != SSL_SUCCESS) {
            int err = SSL_get_error(ssl, 0);
            char buffer[CYASSL_MAX_ERROR_SZ];
            printf("error = %d, %s\n", err, ERR_error_string(err, buffer));
            err_sys("SSL_accept failed");
        }
#else
        NonBlockingSSL_Accept(ssl);
#endif
        showPeer(ssl);

#ifdef HAVE_ALPN
        if (alpnList != NULL) {
            int err;
            char *protocol_name = NULL, *list = NULL;
            word16 protocol_nameSz = 0, listSz = 0;

            err = wolfSSL_ALPN_GetProtocol(ssl, &protocol_name, &protocol_nameSz);
            if (err == SSL_SUCCESS)
                printf("Sent ALPN protocol : %s (%d)\n",
                       protocol_name, protocol_nameSz);
            else if (err == SSL_ALPN_NOT_FOUND)
                printf("No ALPN response sent (no match)\n");
            else
                printf("Getting ALPN protocol name failed\n");

            err = wolfSSL_ALPN_GetPeerProtocol(ssl, &list, &listSz);
            if (err == SSL_SUCCESS)
                printf("List of protocol names sent by Client: %s (%d)\n",
                       list, listSz);
            else
                printf("Get list of client's protocol name failed\n");

            free(list);
        }
#endif
        if(echoData == 0 && throughput == 0) {
            ret = SSL_read(ssl, input, sizeof(input)-1);
            if (ret > 0) {
                input[ret] = 0;
                printf("Client message: %s\n", input);

            }
            else if (ret < 0) {
                int readErr = SSL_get_error(ssl, 0);
                if (readErr != SSL_ERROR_WANT_READ)
                    err_sys("SSL_read failed");
            }

            if (SSL_write(ssl, msg, sizeof(msg)) != sizeof(msg))
                err_sys("SSL_write failed");
        }
        else {
            ServerEchoData(ssl, clientfd, echoData, throughput);
        }

#if defined(WOLFSSL_MDK_SHELL) && defined(HAVE_MDK_RTX)
        os_dly_wait(500) ;
#elif defined (CYASSL_TIRTOS)
        Task_yield();
#endif

        if (doDTLS == 0) {
            ret = SSL_shutdown(ssl);
            if (wc_shutdown && ret == SSL_SHUTDOWN_NOT_DONE)
                SSL_shutdown(ssl);    /* bidirectional shutdown */
        }
        SSL_free(ssl);

        CloseSocket(clientfd);

        if (resume == 1 && resumeCount == 0) {
            resumeCount++;           /* only do one resume for testing */
            continue;
        }
        resumeCount = 0;

        if(!loopIndefinitely) {
            break;  /* out of while loop, done with normal and resume option */
        }
    } /* while(1) */

    CloseSocket(sockfd);
    SSL_CTX_free(ctx);

    ((func_args*)args)->return_code = 0;


#if defined(NO_MAIN_DRIVER) && defined(HAVE_ECC) && defined(FP_ECC) \
                            && defined(HAVE_THREAD_LS)
    ecc_fp_free();  /* free per thread cache */
#endif

#ifdef USE_WOLFSSL_MEMORY
    if (trackMemory)
        ShowMemoryTracker();
#endif

#ifdef CYASSL_TIRTOS
    fdCloseSession(Task_self());
#endif

#if defined(HAVE_SESSION_TICKET) && defined(HAVE_CHACHA) && \
                                    defined(HAVE_POLY1305)
    TicketCleanup();
#endif

#ifndef CYASSL_TIRTOS
    return 0;
#endif
}


/* so overall tests can pull in test function */
#ifndef NO_MAIN_DRIVER

    int main(int argc, char** argv)
    {
        func_args args;
        tcp_ready ready;

#ifdef HAVE_CAVIUM
        int ret = OpenNitroxDevice(CAVIUM_DIRECT, CAVIUM_DEV_ID);
        if (ret != 0)
            err_sys("Cavium OpenNitroxDevice failed");
#endif /* HAVE_CAVIUM */

        StartTCP();

        args.argc = argc;
        args.argv = argv;
        args.signal = &ready;
        InitTcpReady(&ready);

        CyaSSL_Init();
#if defined(DEBUG_CYASSL) && !defined(WOLFSSL_MDK_SHELL)
        CyaSSL_Debugging_ON();
#endif
        ChangeToWolfRoot();

#ifdef HAVE_STACK_SIZE
        StackSizeCheck(&args, server_test);
#else
        server_test(&args);
#endif
        CyaSSL_Cleanup();
        FreeTcpReady(&ready);

#ifdef HAVE_CAVIUM
        CspShutdown(CAVIUM_DEV_ID);
#endif
        return args.return_code;
    }

    int myoptind = 0;
    char* myoptarg = NULL;

#endif /* NO_MAIN_DRIVER */


#ifdef CYASSL_CALLBACKS

    int srvHandShakeCB(HandShakeInfo* info)
    {
        (void)info;
        return 0;
    }


    int srvTimeoutCB(TimeoutInfo* info)
    {
        (void)info;
        return 0;
    }

#endif

#ifndef NO_HANDSHAKE_DONE_CB
    int myHsDoneCb(WOLFSSL* ssl, void* user_ctx)
    {
        (void)user_ctx;
        (void)ssl;

        /* printf("Notified HandShake done\n"); */

        /* return negative number to end TLS connection now */
        return 0;
    }
#endif
