/* client.c
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

#include <wolfssl/ssl.h>

#if defined(WOLFSSL_MDK_ARM) || defined(WOLFSSL_KEIL_TCP_NET)
        #include <stdio.h>
        #include <string.h>

        #if !defined(WOLFSSL_MDK_ARM)
            #include "cmsis_os.h"
            #include "rl_fs.h"
            #include "rl_net.h"
        #else
            #include "rtl.h"
            #include "wolfssl_MDK_ARM.h"
        #endif
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if !defined(WOLFSSL_TRACK_MEMORY) && !defined(NO_MAIN_DRIVER)
    /* in case memory tracker wants stats */
    #define WOLFSSL_TRACK_MEMORY
#endif

#include <wolfssl/ssl.h>

#include <wolfssl/test.h>

#include "examples/client/client.h"

#ifdef WOLFSSL_ASYNC_CRYPT
    static int devId = INVALID_DEVID;
#endif

/* Note on using port 0: the client standalone example doesn't utilize the
 * port 0 port sharing; that is used by (1) the server in external control
 * test mode and (2) the testsuite which uses this code and sets up the correct
 * port numbers when the internal thread using the server code using port 0. */

#ifdef WOLFSSL_CALLBACKS
    int handShakeCB(HandShakeInfo*);
    int timeoutCB(TimeoutInfo*);
    Timeval timeout;
#endif

#ifdef HAVE_SESSION_TICKET
    int sessionTicketCB(WOLFSSL*, const unsigned char*, int, void*);
#endif


static void NonBlockingSSL_Connect(WOLFSSL* ssl)
{
#ifndef WOLFSSL_CALLBACKS
    int ret = wolfSSL_connect(ssl);
#else
    int ret = wolfSSL_connect_ex(ssl, handShakeCB, timeoutCB, timeout);
#endif
    int error = wolfSSL_get_error(ssl, 0);
    SOCKET_T sockfd = (SOCKET_T)wolfSSL_get_fd(ssl);
    int select_ret = 0;

    while (ret != SSL_SUCCESS && (error == SSL_ERROR_WANT_READ ||
                                  error == SSL_ERROR_WANT_WRITE ||
                                  error == WC_PENDING_E)) {
        int currTimeout = 1;

        if (error == SSL_ERROR_WANT_READ)
            printf("... client would read block\n");
        else if (error == SSL_ERROR_WANT_WRITE)
            printf("... client would write block\n");
#ifdef WOLFSSL_ASYNC_CRYPT
        else if (error == WC_PENDING_E) {
            ret = wolfSSL_AsyncPoll(ssl, WOLF_POLL_FLAG_CHECK_HW);
            if (ret < 0) { break; } else if (ret == 0) { continue; }
        }
#endif

        if (error != WC_PENDING_E) {
    #ifdef WOLFSSL_DTLS
            currTimeout = wolfSSL_dtls_get_current_timeout(ssl);
    #endif
            select_ret = tcp_select(sockfd, currTimeout);
        }

        if ((select_ret == TEST_RECV_READY) ||
                                        (select_ret == TEST_ERROR_READY)) {
        #ifndef WOLFSSL_CALLBACKS
            ret = wolfSSL_connect(ssl);
        #else
            ret = wolfSSL_connect_ex(ssl,handShakeCB,timeoutCB,timeout);
        #endif
            error = wolfSSL_get_error(ssl, 0);
        }
        else if (select_ret == TEST_TIMEOUT && !wolfSSL_dtls(ssl)) {
            error = SSL_ERROR_WANT_READ;
        }
#ifdef WOLFSSL_DTLS
        else if (select_ret == TEST_TIMEOUT && wolfSSL_dtls(ssl) &&
                                        wolfSSL_dtls_got_timeout(ssl) >= 0) {
            error = SSL_ERROR_WANT_READ;
        }
#endif
        else {
            error = SSL_FATAL_ERROR;
        }
    }
    if (ret != SSL_SUCCESS)
        err_sys("SSL_connect failed");
}


static void ShowCiphers(void)
{
    char ciphers[4096];

    int ret = wolfSSL_get_ciphers(ciphers, (int)sizeof(ciphers));

    if (ret == SSL_SUCCESS)
        printf("%s\n", ciphers);
}

/* Shows which versions are valid */
static void ShowVersions(void)
{
#ifndef NO_OLD_TLS
#ifdef WOLFSSL_ALLOW_SSLV3
    printf("0:");
#endif /* WOLFSSL_ALLOW_SSLV3 */
    printf("1:2:");
#endif /* NO_OLD_TLS */
    printf("3\n");
}

/* Measures average time to create, connect and disconnect a connection (TPS).
Benchmark = number of connections. */
static int ClientBenchmarkConnections(WOLFSSL_CTX* ctx, char* host, word16 port,
    int dtlsUDP, int dtlsSCTP, int benchmark, int resumeSession)
{
    /* time passed in number of connects give average */
    int times = benchmark;
    int loops = resumeSession ? 2 : 1;
    int i = 0;    
#ifndef NO_SESSION_CACHE
    WOLFSSL_SESSION* benchSession = NULL;
#endif
    (void)resumeSession;

    while (loops--) {
    #ifndef NO_SESSION_CACHE
        int benchResume = resumeSession && loops == 0;
    #endif
        double start = current_time(1), avg;

        for (i = 0; i < times; i++) {
            SOCKET_T sockfd;
            WOLFSSL* ssl = wolfSSL_new(ctx);
            if (ssl == NULL)
                err_sys("unable to get SSL object");

            tcp_connect(&sockfd, host, port, dtlsUDP, dtlsSCTP, ssl);

    #ifndef NO_SESSION_CACHE
            if (benchResume)
                wolfSSL_set_session(ssl, benchSession);
    #endif
            if (wolfSSL_set_fd(ssl, sockfd) != SSL_SUCCESS) {
                err_sys("error in setting fd");
            }
            if (wolfSSL_connect(ssl) != SSL_SUCCESS)
                err_sys("SSL_connect failed");

            wolfSSL_shutdown(ssl);
    #ifndef NO_SESSION_CACHE
            if (i == (times-1) && resumeSession) {
                benchSession = wolfSSL_get_session(ssl);
            }
    #endif
            wolfSSL_free(ssl);
            CloseSocket(sockfd);
        }
        avg = current_time(0) - start;
        avg /= times;
        avg *= 1000;   /* milliseconds */
    #ifndef NO_SESSION_CACHE
        if (benchResume)
            printf("wolfSSL_resume  avg took: %8.3f milliseconds\n", avg);
        else
    #endif
            printf("wolfSSL_connect avg took: %8.3f milliseconds\n", avg);
    }

    return EXIT_SUCCESS;
}

/* Measures throughput in kbps. Throughput = number of bytes */
static int ClientBenchmarkThroughput(WOLFSSL_CTX* ctx, char* host, word16 port,
    int dtlsUDP, int dtlsSCTP, int throughput)
{
    double start, conn_time = 0, tx_time = 0, rx_time = 0;
    SOCKET_T sockfd;
    WOLFSSL* ssl;
    int ret;

    start = current_time(1);
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL)
        err_sys("unable to get SSL object");
    tcp_connect(&sockfd, host, port, dtlsUDP, dtlsSCTP, ssl);
    if (wolfSSL_set_fd(ssl, sockfd) != SSL_SUCCESS) {
        err_sys("error in setting fd");
    }
    if (wolfSSL_connect(ssl) == SSL_SUCCESS) {
        /* Perform throughput test */
        char *tx_buffer, *rx_buffer;

        /* Record connection time */
        conn_time = current_time(0) - start;

        /* Allocate TX/RX buffers */
        tx_buffer = (char*)malloc(TEST_BUFFER_SIZE);
        rx_buffer = (char*)malloc(TEST_BUFFER_SIZE);
        if(tx_buffer && rx_buffer) {
            WC_RNG rng;

            /* Startup the RNG */
            ret = wc_InitRng(&rng);
            if(ret == 0) {
                int xfer_bytes;

                /* Generate random data to send */
                ret = wc_RNG_GenerateBlock(&rng, (byte*)tx_buffer, TEST_BUFFER_SIZE);
                wc_FreeRng(&rng);
                if(ret != 0) {
                    err_sys("wc_RNG_GenerateBlock failed");
                }

                /* Perform TX and RX of bytes */
                xfer_bytes = 0;
                while(throughput > xfer_bytes) {
                    int len, rx_pos, select_ret;

                    /* Determine packet size */
                    len = min(TEST_BUFFER_SIZE, throughput - xfer_bytes);

                    /* Perform TX */
                    start = current_time(1);
                    if (wolfSSL_write(ssl, tx_buffer, len) != len) {
                        int writeErr = wolfSSL_get_error(ssl, 0);
                        printf("wolfSSL_write error %d!\n", writeErr);
                        err_sys("wolfSSL_write failed");
                    }
                    tx_time += current_time(0) - start;

                    /* Perform RX */
                    select_ret = tcp_select(sockfd, 1); /* Timeout=1 second */
                    if (select_ret == TEST_RECV_READY) {
                        start = current_time(1);
                        rx_pos = 0;
                        while(rx_pos < len) {
                            ret = wolfSSL_read(ssl, &rx_buffer[rx_pos], len - rx_pos);
                            if(ret <= 0) {
                                int readErr = wolfSSL_get_error(ssl, 0);
                                if (readErr != SSL_ERROR_WANT_READ) {
                                    printf("wolfSSL_read error %d!\n", readErr);
                                    err_sys("wolfSSL_read failed");
                                }
                            }
                            else {
                                rx_pos += ret;
                            }
                        }
                        rx_time += current_time(0) - start;
                    }

                    /* Compare TX and RX buffers */
                    if(XMEMCMP(tx_buffer, rx_buffer, len) != 0) {
                        err_sys("Compare TX and RX buffers failed");
                    }

                    /* Update overall position */
                    xfer_bytes += len;
                }
            }
            else {
                err_sys("wc_InitRng failed");
            }
        }
        else {
            err_sys("Client buffer malloc failed");
        }
        if(tx_buffer) free(tx_buffer);
        if(rx_buffer) free(rx_buffer);
    }
    else {
        err_sys("wolfSSL_connect failed");
    }

    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    CloseSocket(sockfd);

    printf("wolfSSL Client Benchmark %d bytes\n"
        "\tConnect %8.3f ms\n"
        "\tTX      %8.3f ms (%8.3f MBps)\n"
        "\tRX      %8.3f ms (%8.3f MBps)\n",
        throughput,
        conn_time * 1000,
        tx_time * 1000, throughput / tx_time / 1024 / 1024,
        rx_time * 1000, throughput / rx_time / 1024 / 1024
    );

    return EXIT_SUCCESS;
}

const char* starttlsCmd[6] = {
    "220",
    "EHLO mail.example.com\r\n",
    "250",
    "STARTTLS\r\n",
    "220",
    "QUIT\r\n",
};

/* Initiates the STARTTLS command sequence over TCP */
static int StartTLS_Init(SOCKET_T* sockfd)
{
    char tmpBuf[256];

    if (sockfd == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(tmpBuf, 0, sizeof(tmpBuf));

    /* S: 220 <host> SMTP service ready */
    if (recv(*sockfd, tmpBuf, sizeof(tmpBuf), 0) < 0)
        err_sys("failed to read STARTTLS command\n");

    if (!XSTRNCMP(tmpBuf, starttlsCmd[0], XSTRLEN(starttlsCmd[0]))) {
        printf("%s\n", tmpBuf);
        XMEMSET(tmpBuf, 0, sizeof(tmpBuf));
    } else {
        err_sys("incorrect STARTTLS command received");
    }

    /* C: EHLO mail.example.com */
    if (send(*sockfd, starttlsCmd[1], (int)XSTRLEN(starttlsCmd[1]), 0) !=
              (int)XSTRLEN(starttlsCmd[1]))
        err_sys("failed to send STARTTLS EHLO command\n");

    /* S: 250 <host> offers a warm hug of welcome */
    if (recv(*sockfd, tmpBuf, sizeof(tmpBuf), 0) < 0)
        err_sys("failed to read STARTTLS command\n");

    if (!XSTRNCMP(tmpBuf, starttlsCmd[2], XSTRLEN(starttlsCmd[2]))) {
        printf("%s\n", tmpBuf);
        XMEMSET(tmpBuf, 0, sizeof(tmpBuf));
    } else {
        err_sys("incorrect STARTTLS command received");
    }

    /* C: STARTTLS */
    if (send(*sockfd, starttlsCmd[3], (int)XSTRLEN(starttlsCmd[3]), 0) !=
              (int)XSTRLEN(starttlsCmd[3])) {
        err_sys("failed to send STARTTLS command\n");
    }

    /* S: 220 Go ahead */
    if (recv(*sockfd, tmpBuf, sizeof(tmpBuf), 0) < 0)
        err_sys("failed to read STARTTLS command\n");

    if (!XSTRNCMP(tmpBuf, starttlsCmd[4], XSTRLEN(starttlsCmd[4]))) {
        printf("%s\n", tmpBuf);
        XMEMSET(tmpBuf, 0, sizeof(tmpBuf));
    } else {
        err_sys("incorrect STARTTLS command received, expected 220");
    }

    return SSL_SUCCESS;
}

/* Closes down the SMTP connection */
static int SMTP_Shutdown(WOLFSSL* ssl, int wc_shutdown)
{
    int ret;
    char tmpBuf[256];

    if (ssl == NULL)
        return BAD_FUNC_ARG;

    printf("\nwolfSSL client shutting down SMTP connection\n");

    XMEMSET(tmpBuf, 0, sizeof(tmpBuf));

    /* C: QUIT */
    if (wolfSSL_write(ssl, starttlsCmd[5], (int)XSTRLEN(starttlsCmd[5])) !=
                      (int)XSTRLEN(starttlsCmd[5]))
        err_sys("failed to send SMTP QUIT command\n");

    /* S: 221 2.0.0 Service closing transmission channel */
    if (wolfSSL_read(ssl, tmpBuf, sizeof(tmpBuf)) < 0)
        err_sys("failed to read SMTP closing down response\n");

    printf("%s\n", tmpBuf);

    ret = wolfSSL_shutdown(ssl);
    if (wc_shutdown && ret == SSL_SHUTDOWN_NOT_DONE)
        wolfSSL_shutdown(ssl);    /* bidirectional shutdown */

    return SSL_SUCCESS;
}


static void Usage(void)
{
    printf("client "    LIBWOLFSSL_VERSION_STRING
           " NOTE: All files relative to wolfSSL home dir\n");
    printf("-?          Help, print this usage\n");
    printf("-h <host>   Host to connect to, default %s\n", wolfSSLIP);
    printf("-p <num>    Port to connect on, not 0, default %d\n", wolfSSLPort);
    printf("-v <num>    SSL version [0-3], SSLv3(0) - TLS1.2(3)), default %d\n",
                                 CLIENT_DEFAULT_VERSION);
    printf("-V          Prints valid ssl version numbers, SSLv3(0) - TLS1.2(3)\n");
    printf("-l <str>    Cipher suite list (: delimited)\n");
    printf("-c <file>   Certificate file,           default %s\n", cliCert);
    printf("-k <file>   Key file,                   default %s\n", cliKey);
    printf("-A <file>   Certificate Authority file, default %s\n", caCert);
#ifndef NO_DH
    printf("-Z <num>    Minimum DH key bits,        default %d\n",
                                 DEFAULT_MIN_DHKEY_BITS);
#endif
    printf("-b <num>    Benchmark <num> connections and print stats\n");
#ifdef HAVE_ALPN
    printf("-L <str>    Application-Layer Protocol Negotiation ({C,F}:<list>)\n");
#endif
    printf("-B <num>    Benchmark throughput using <num> bytes and print stats\n");
    printf("-s          Use pre Shared keys\n");
    printf("-t          Track wolfSSL memory use\n");
    printf("-d          Disable peer checks\n");
    printf("-D          Override Date Errors example\n");
    printf("-e          List Every cipher suite available, \n");
    printf("-g          Send server HTTP GET\n");
    printf("-u          Use UDP DTLS,"
           " add -v 2 for DTLSv1, -v 3 for DTLSv1.2 (default)\n");
#ifdef WOLFSSL_SCTP
    printf("-G          Use SCTP DTLS,"
           " add -v 2 for DTLSv1, -v 3 for DTLSv1.2 (default)\n");
#endif
    printf("-m          Match domain name in cert\n");
    printf("-N          Use Non-blocking sockets\n");
    printf("-r          Resume session\n");
    printf("-w          Wait for bidirectional shutdown\n");
    printf("-M <prot>   Use STARTTLS, using <prot> protocol (smtp)\n");
#ifdef HAVE_SECURE_RENEGOTIATION
    printf("-R          Allow Secure Renegotiation\n");
    printf("-i          Force client Initiated Secure Renegotiation\n");
#endif
    printf("-f          Fewer packets/group messages\n");
    printf("-x          Disable client cert/key loading\n");
    printf("-X          Driven by eXternal test case\n");
#ifdef SHOW_SIZES
    printf("-z          Print structure sizes\n");
#endif
#ifdef HAVE_SNI
    printf("-S <str>    Use Host Name Indication\n");
#endif
#ifdef HAVE_MAX_FRAGMENT
    printf("-F <num>    Use Maximum Fragment Length [1-5]\n");
#endif
#ifdef HAVE_TRUNCATED_HMAC
    printf("-T          Use Truncated HMAC\n");
#endif
#ifdef HAVE_EXTENDED_MASTER
    printf("-n          Disable Extended Master Secret\n");
#endif
#ifdef HAVE_OCSP
    printf("-o          Perform OCSP lookup on peer certificate\n");
    printf("-O <url>    Perform OCSP lookup using <url> as responder\n");
#endif
#if defined(HAVE_CERTIFICATE_STATUS_REQUEST) \
 || defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2)
    printf("-W          Use OCSP Stapling\n");
#endif
#ifdef ATOMIC_USER
    printf("-U          Atomic User Record Layer Callbacks\n");
#endif
#ifdef HAVE_PK_CALLBACKS
    printf("-P          Public Key Callbacks\n");
#endif
#ifdef HAVE_ANON
    printf("-a          Anonymous client\n");
#endif
#ifdef HAVE_CRL
    printf("-C          Disable CRL\n");
#endif
#ifdef WOLFSSL_TRUST_PEER_CERT
    printf("-E <file>   Path to load trusted peer cert\n");
#endif
#ifdef HAVE_WNR
    printf("-q <file>   Whitewood config file,      default %s\n", wnrConfig);
#endif
}

THREAD_RETURN WOLFSSL_THREAD client_test(void* args)
{
    SOCKET_T sockfd = WOLFSSL_SOCKET_INVALID;

    WOLFSSL_METHOD*  method  = 0;
    WOLFSSL_CTX*     ctx     = 0;
    WOLFSSL*         ssl     = 0;

    WOLFSSL*         sslResume = 0;
    WOLFSSL_SESSION* session = 0;

#ifndef WOLFSSL_ALT_TEST_STRINGS
    char msg[32] = "hello wolfssl!";   /* GET may make bigger */
    char resumeMsg[32] = "resuming wolfssl!";
#else
    char msg[32] = "hello wolfssl!\n";
    char resumeMsg[32] = "resuming wolfssl!\n";
#endif

    char reply[80];
    int  input;
    int  msgSz = (int)XSTRLEN(msg);
    int  resumeSz = (int)XSTRLEN(resumeMsg);

    word16 port   = wolfSSLPort;
    char* host   = (char*)wolfSSLIP;
    const char* domain = "localhost";  /* can't default to www.wolfssl.com
                                          because can't tell if we're really
                                          going there to detect old chacha-poly
                                       */
    int    ch;
    int    version = CLIENT_INVALID_VERSION;
    int    usePsk   = 0;
    int    useAnon  = 0;
    int    sendGET  = 0;
    int    benchmark = 0;
    int    throughput = 0;
    int    doDTLS    = 0;
    int    dtlsUDP   = 0;
    int    dtlsSCTP  = 0;
    int    matchName = 0;
    int    doPeerCheck = 1;
    int    nonBlocking = 0;
    int    resumeSession = 0;
    int    wc_shutdown   = 0;
    int    disableCRL    = 0;
    int    externalTest  = 0;
    int    ret;
#ifndef WOLFSSL_CALLBACKS
    int    err           = 0;
#endif
    int    scr           = 0;    /* allow secure renegotiation */
    int    forceScr      = 0;    /* force client initiaed scr */
    int    trackMemory   = 0;
    int    useClientCert = 1;
    int    fewerPackets  = 0;
    int    atomicUser    = 0;
    int    pkCallbacks   = 0;
    int    overrideDateErrors = 0;
    int    minDhKeyBits  = DEFAULT_MIN_DHKEY_BITS;
    char*  alpnList = NULL;
    unsigned char alpn_opt = 0;
    char*  cipherList = NULL;
    const char* verifyCert = caCert;
    const char* ourCert    = cliCert;
    const char* ourKey     = cliKey;

    int   doSTARTTLS    = 0;
    char* starttlsProt = NULL;

#ifdef WOLFSSL_TRUST_PEER_CERT
    const char* trustCert  = NULL;
#endif

#ifdef HAVE_SNI
    char*  sniHostName = NULL;
#endif
#ifdef HAVE_MAX_FRAGMENT
    byte maxFragment = 0;
#endif
#ifdef HAVE_TRUNCATED_HMAC
    byte truncatedHMAC = 0;
#endif
#if defined(HAVE_CERTIFICATE_STATUS_REQUEST) \
 || defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2)
    byte statusRequest = 0;
#endif
#ifdef HAVE_EXTENDED_MASTER
    byte disableExtMasterSecret = 0;
#endif


#ifdef HAVE_OCSP
    int    useOcsp  = 0;
    char*  ocspUrl  = NULL;
#endif

#ifdef HAVE_WNR
    const char* wnrConfigFile = wnrConfig;
#endif

    int     argc = ((func_args*)args)->argc;
    char**  argv = ((func_args*)args)->argv;

    ((func_args*)args)->return_code = -1; /* error state */

#ifdef NO_RSA
    verifyCert = (char*)eccCert;
    ourCert    = (char*)cliEccCert;
    ourKey     = (char*)cliEccKey;
#endif
    (void)resumeSz;
    (void)session;
    (void)sslResume;
    (void)atomicUser;
    (void)pkCallbacks;
    (void)scr;
    (void)forceScr;
    (void)ourKey;
    (void)ourCert;
    (void)verifyCert;
    (void)useClientCert;
    (void)overrideDateErrors;
    (void)disableCRL;
    (void)minDhKeyBits;
    (void)alpnList;
    (void)alpn_opt;

    StackTrap();

#ifndef WOLFSSL_VXWORKS
    while ((ch = mygetopt(argc, argv,
          "?gdeDuGsmNrwRitfxXUPCVh:p:v:l:A:c:k:Z:b:zS:F:L:TnoO:aB:W:E:M:q:"))
            != -1) {
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

            case 'e' :
                ShowCiphers();
                exit(EXIT_SUCCESS);

            case 'D' :
                overrideDateErrors = 1;
                break;

            case 'C' :
                #ifdef HAVE_CRL
                    disableCRL = 1;
                #endif
                break;

            case 'u' :
                doDTLS = 1;
                dtlsUDP = 1;
                break;

            case 'G' :
            #ifdef WOLFSSL_SCTP
                doDTLS = 1;
                dtlsSCTP = 1;
            #endif
                break;

            case 's' :
                usePsk = 1;
                break;

            case 't' :
            #ifdef USE_WOLFSSL_MEMORY
                trackMemory = 1;
            #endif
                break;

            #ifdef WOLFSSL_TRUST_PEER_CERT
            case 'E' :
                trustCert = myoptarg;
                break;
            #endif

            case 'm' :
                matchName = 1;
                break;

            case 'x' :
                useClientCert = 0;
                break;

            case 'X' :
                externalTest = 1;
                break;

            case 'f' :
                fewerPackets = 1;
                break;

            case 'U' :
            #ifdef ATOMIC_USER
                atomicUser = 1;
            #endif
                break;

            case 'P' :
            #ifdef HAVE_PK_CALLBACKS
                pkCallbacks = 1;
            #endif
                break;

            case 'h' :
                host   = myoptarg;
                domain = myoptarg;
                break;

            case 'p' :
                port = (word16)atoi(myoptarg);
                #if !defined(NO_MAIN_DRIVER) || defined(USE_WINDOWS_API)
                    if (port == 0)
                        err_sys("port number cannot be 0");
                #endif
                break;

            case 'v' :
                version = atoi(myoptarg);
                if (version < 0 || version > 3) {
                    Usage();
                    exit(MY_EX_USAGE);
                }
                break;

            case 'V' :
                ShowVersions();
                exit(EXIT_SUCCESS);

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

            case 'Z' :
                #ifndef NO_DH
                    minDhKeyBits = atoi(myoptarg);
                    if (minDhKeyBits <= 0 || minDhKeyBits > 16000) {
                        Usage();
                        exit(MY_EX_USAGE);
                    }
                #endif
                break;

            case 'b' :
                benchmark = atoi(myoptarg);
                if (benchmark < 0 || benchmark > 1000000) {
                    Usage();
                    exit(MY_EX_USAGE);
                }
                break;

            case 'B' :
                throughput = atoi(myoptarg);
                if (throughput <= 0) {
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

            case 'w' :
                wc_shutdown = 1;
                break;

            case 'R' :
                #ifdef HAVE_SECURE_RENEGOTIATION
                    scr = 1;
                #endif
                break;

            case 'i' :
                #ifdef HAVE_SECURE_RENEGOTIATION
                    scr      = 1;
                    forceScr = 1;
                #endif
                break;

            case 'z' :
                #ifndef WOLFSSL_LEANPSK
                    wolfSSL_GetObjectSize();
                #endif
                break;

            case 'S' :
                #ifdef HAVE_SNI
                    sniHostName = myoptarg;
                #endif
                break;

            case 'F' :
                #ifdef HAVE_MAX_FRAGMENT
                    maxFragment = atoi(myoptarg);
                    if (maxFragment < WOLFSSL_MFL_2_9 ||
                                                maxFragment > WOLFSSL_MFL_2_13) {
                        Usage();
                        exit(MY_EX_USAGE);
                    }
                #endif
                break;

            case 'T' :
                #ifdef HAVE_TRUNCATED_HMAC
                    truncatedHMAC = 1;
                #endif
                break;

            case 'n' :
                #ifdef HAVE_EXTENDED_MASTER
                    disableExtMasterSecret = 1;
                #endif
                break;

            case 'W' :
                #if defined(HAVE_CERTIFICATE_STATUS_REQUEST) \
                 || defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2)
                    statusRequest = atoi(myoptarg);
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

            case 'M' :
                doSTARTTLS = 1;
                starttlsProt = myoptarg;

                if (XSTRNCMP(starttlsProt, "smtp", 4) != 0) {
                    Usage();
                    exit(MY_EX_USAGE);
                }

                break;

            case 'q' :
                #ifdef HAVE_WNR
                    wnrConfigFile = myoptarg;
                #endif
                break;

            default:
                Usage();
                exit(MY_EX_USAGE);
        }
    }

    myoptind = 0;      /* reset for test cases */
#endif /* !WOLFSSL_VXWORKS */

    if (externalTest) {
        /* detect build cases that wouldn't allow test against wolfssl.com */
        int done = 0;

        #ifdef NO_RSA
            done += 1;
        #endif

        /* www.globalsign.com does not respond to ipv6 ocsp requests */
        #if defined(TEST_IPV6) && defined(HAVE_OCSP)
            done += 1;
        #endif

        /* www.globalsign.com has limited supported cipher suites */
        #if defined(NO_AES) && defined(HAVE_OCSP)
            done += 1;
        #endif

        /* www.globalsign.com only supports static RSA or ECDHE with AES */
        /* We cannot expect users to have on static RSA so test for ECC only
         * as some users will most likely be on 32-bit systems where ECC
         * is not enabled by default */
        #if defined(HAVE_OCSP) && !defined(HAVE_ECC)
            done += 1;
        #endif

        #ifndef NO_PSK
            done += 1;
        #endif

        #ifdef NO_SHA
            done += 1;  /* external cert chain most likely has SHA */
        #endif

        #if !defined(HAVE_ECC) && !defined(WOLFSSL_STATIC_RSA) \
            || ( defined(HAVE_ECC) && !defined(HAVE_SUPPORTED_CURVES) \
                  && !defined(WOLFSSL_STATIC_RSA) )
            /* google needs ECDHE+Supported Curves or static RSA */
            if (!XSTRNCMP(domain, "www.google.com", 14))
                done += 1;
        #endif

        #if !defined(HAVE_ECC) && !defined(WOLFSSL_STATIC_RSA)
            /* wolfssl needs ECDHE or static RSA */
            if (!XSTRNCMP(domain, "www.wolfssl.com", 15))
                done += 1;
        #endif

        #if !defined(WOLFSSL_SHA384)
            if (!XSTRNCMP(domain, "www.wolfssl.com", 15)) {
                /* wolfssl need sha384 for cert chain verify */
                done += 1;
            }
        #endif

        #if !defined(HAVE_AESGCM) && defined(NO_AES) && \
            !(defined(HAVE_CHACHA) && defined(HAVE_POLY1305))
            /* need at least on of these for external tests */
            done += 1;
        #endif

        if (done) {
            printf("external test can't be run in this mode");

            ((func_args*)args)->return_code = 0;
            exit(EXIT_SUCCESS);
        }
    }

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

#if defined(USE_WOLFSSL_MEMORY) && !defined(WOLFSSL_STATIC_MEMORY)
    if (trackMemory)
        InitMemoryTracker();
#endif

#ifdef HAVE_WNR
    if (wc_InitNetRandom(wnrConfigFile, NULL, 5000) != 0)
        err_sys("can't load whitewood net random config file");
#endif

    switch (version) {
#ifndef NO_OLD_TLS
    #ifdef WOLFSSL_ALLOW_SSLV3
        case 0:
            method = wolfSSLv3_client_method();
            break;
    #endif

    #ifndef NO_TLS
        case 1:
            method = wolfTLSv1_client_method();
            break;

        case 2:
            method = wolfTLSv1_1_client_method();
            break;
    #endif /* NO_TLS */

#endif  /* NO_OLD_TLS */

#ifndef NO_TLS
        case 3:
            method = wolfTLSv1_2_client_method();
            break;
#endif

#ifdef WOLFSSL_DTLS
        #ifndef NO_OLD_TLS
        case -1:
            method = wolfDTLSv1_client_method();
            break;
        #endif

        case -2:
            method = wolfDTLSv1_2_client_method();
            break;
#endif

        default:
            err_sys("Bad SSL version");
            break;
    }

    if (method == NULL)
        err_sys("unable to get method");

    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL)
        err_sys("unable to get ctx");

#ifdef SINGLE_THREADED
    if (wolfSSL_CTX_new_rng(ctx) != SSL_SUCCESS) {
        err_sys("Single Threaded new rng at CTX failed");
    }
#endif

    if (cipherList) {
        if (wolfSSL_CTX_set_cipher_list(ctx, cipherList) != SSL_SUCCESS)
            err_sys("client can't set cipher list 1");
    }

#ifdef WOLFSSL_LEANPSK
    if (!usePsk) {
        usePsk = 1;
    }
#endif

#if defined(NO_RSA) && !defined(HAVE_ECC)
    if (!usePsk) {
        usePsk = 1;
    }
#endif

    if (fewerPackets)
        wolfSSL_CTX_set_group_messages(ctx);

#ifndef NO_DH
    wolfSSL_CTX_SetMinDhKey_Sz(ctx, (word16)minDhKeyBits);
#endif

    if (usePsk) {
#ifndef NO_PSK
        wolfSSL_CTX_set_psk_client_callback(ctx, my_psk_client_cb);
        if (cipherList == NULL) {
            const char *defaultCipherList;
            #if defined(HAVE_AESGCM) && !defined(NO_DH)
                defaultCipherList = "DHE-PSK-AES128-GCM-SHA256";
            #elif defined(HAVE_NULL_CIPHER)
                defaultCipherList = "PSK-NULL-SHA256";
            #else
                defaultCipherList = "PSK-AES128-CBC-SHA256";
            #endif
            if (wolfSSL_CTX_set_cipher_list(ctx,defaultCipherList)
                                                                  !=SSL_SUCCESS)
                err_sys("client can't set cipher list 2");
        }
#endif
        if (useClientCert) {
            useClientCert = 0;
        }
    }

    if (useAnon) {
#ifdef HAVE_ANON
        if (cipherList == NULL) {
            wolfSSL_CTX_allow_anon_cipher(ctx);
            if (wolfSSL_CTX_set_cipher_list(ctx,"ADH-AES128-SHA") != SSL_SUCCESS)
                err_sys("client can't set cipher list 4");
        }
#endif
        if (useClientCert) {
            useClientCert = 0;
        }
    }

#ifdef WOLFSSL_SCTP
    if (dtlsSCTP)
        wolfSSL_CTX_dtls_set_sctp(ctx);
#endif

#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER)
    wolfSSL_CTX_set_default_passwd_cb(ctx, PasswordCallBack);
#endif

#if defined(WOLFSSL_SNIFFER)
    if (cipherList == NULL) {
        /* don't use EDH, can't sniff tmp keys */
        if (wolfSSL_CTX_set_cipher_list(ctx, "AES128-SHA") != SSL_SUCCESS) {
            err_sys("client can't set cipher list 3");
        }
    }
#endif

#ifdef HAVE_OCSP
    if (useOcsp) {
        if (ocspUrl != NULL) {
            wolfSSL_CTX_SetOCSP_OverrideURL(ctx, ocspUrl);
            wolfSSL_CTX_EnableOCSP(ctx, WOLFSSL_OCSP_NO_NONCE
                                                    | WOLFSSL_OCSP_URL_OVERRIDE);
        }
        else
            wolfSSL_CTX_EnableOCSP(ctx, 0);
    }
#endif

#ifdef USER_CA_CB
    wolfSSL_CTX_SetCACb(ctx, CaCb);
#endif

#ifdef VERIFY_CALLBACK
    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, myVerify);
#endif
#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS)
    if (useClientCert){
        if (wolfSSL_CTX_use_certificate_chain_file(ctx, ourCert) != SSL_SUCCESS)
            err_sys("can't load client cert file, check file and run from"
                    " wolfSSL home dir");

        if (wolfSSL_CTX_use_PrivateKey_file(ctx, ourKey, SSL_FILETYPE_PEM)
                                         != SSL_SUCCESS)
            err_sys("can't load client private key file, check file and run "
                    "from wolfSSL home dir");
    }

    if (!usePsk && !useAnon) {
        if (wolfSSL_CTX_load_verify_locations(ctx, verifyCert,0) != SSL_SUCCESS)
            err_sys("can't load ca file, Please run from wolfSSL home dir");
#ifdef HAVE_ECC
        /* load ecc verify too, echoserver uses it by default w/ ecc */
        if (wolfSSL_CTX_load_verify_locations(ctx, eccCert, 0) != SSL_SUCCESS)
            err_sys("can't load ecc ca file, Please run from wolfSSL home dir");
#endif /* HAVE_ECC */
#ifdef WOLFSSL_TRUST_PEER_CERT
        if (trustCert) {
            if ((ret = wolfSSL_CTX_trust_peer_cert(ctx, trustCert,
                                            SSL_FILETYPE_PEM)) != SSL_SUCCESS) {
                err_sys("can't load trusted peer cert file");
            }
        }
#endif /* WOLFSSL_TRUST_PEER_CERT */
    }
#endif /* !NO_FILESYSTEM && !NO_CERTS */
#if !defined(NO_CERTS)
    if (!usePsk && !useAnon && doPeerCheck == 0)
        wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);
    if (!usePsk && !useAnon && overrideDateErrors == 1)
        wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, myDateCb);
#endif

#ifdef WOLFSSL_ASYNC_CRYPT
    ret = wolfAsync_DevOpen(&devId);
    if (ret != 0) {
        err_sys("Async device open failed");
    }
    wolfSSL_CTX_UseAsync(ctx, devId);
#endif /* WOLFSSL_ASYNC_CRYPT */

#ifdef HAVE_SNI
    if (sniHostName)
        if (wolfSSL_CTX_UseSNI(ctx, 0, sniHostName, XSTRLEN(sniHostName))
                                                                 != SSL_SUCCESS)
            err_sys("UseSNI failed");
#endif
#ifdef HAVE_MAX_FRAGMENT
    if (maxFragment)
        if (wolfSSL_CTX_UseMaxFragment(ctx, maxFragment) != SSL_SUCCESS)
            err_sys("UseMaxFragment failed");
#endif
#ifdef HAVE_TRUNCATED_HMAC
    if (truncatedHMAC)
        if (wolfSSL_CTX_UseTruncatedHMAC(ctx) != SSL_SUCCESS)
            err_sys("UseTruncatedHMAC failed");
#endif
#ifdef HAVE_SESSION_TICKET
    if (wolfSSL_CTX_UseSessionTicket(ctx) != SSL_SUCCESS)
        err_sys("UseSessionTicket failed");
#endif
#ifdef HAVE_EXTENDED_MASTER
    if (disableExtMasterSecret)
        if (wolfSSL_CTX_DisableExtendedMasterSecret(ctx) != SSL_SUCCESS)
            err_sys("DisableExtendedMasterSecret failed");
#endif

    if (benchmark) {
        ((func_args*)args)->return_code =
            ClientBenchmarkConnections(ctx, host, port, dtlsUDP, dtlsSCTP,
                                       benchmark, resumeSession);
        wolfSSL_CTX_free(ctx);
        exit(EXIT_SUCCESS);
    }

    if(throughput) {
        ((func_args*)args)->return_code =
            ClientBenchmarkThroughput(ctx, host, port, dtlsUDP, dtlsSCTP,
                                      throughput);
        wolfSSL_CTX_free(ctx);
        exit(EXIT_SUCCESS);
    }

    #if defined(WOLFSSL_MDK_ARM)
    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);
    #endif

    ssl = wolfSSL_new(ctx);
    if (ssl == NULL)
        err_sys("unable to get SSL object");

    #ifdef HAVE_SUPPORTED_CURVES /* add curves to supported curves extension */
        if (wolfSSL_UseSupportedCurve(ssl, WOLFSSL_ECC_SECP256R1)
                != SSL_SUCCESS) {
            err_sys("unable to set curve secp256r1");
        }
        if (wolfSSL_UseSupportedCurve(ssl, WOLFSSL_ECC_SECP384R1)
                != SSL_SUCCESS) {
            err_sys("unable to set curve secp384r1");
        }
        if (wolfSSL_UseSupportedCurve(ssl, WOLFSSL_ECC_SECP521R1)
                != SSL_SUCCESS) {
            err_sys("unable to set curve secp521r1");
        }
        if (wolfSSL_UseSupportedCurve(ssl, WOLFSSL_ECC_SECP224R1)
                != SSL_SUCCESS) {
            err_sys("unable to set curve secp224r1");
        }
        if (wolfSSL_UseSupportedCurve(ssl, WOLFSSL_ECC_SECP192R1)
                != SSL_SUCCESS) {
            err_sys("unable to set curve secp192r1");
        }
        if (wolfSSL_UseSupportedCurve(ssl, WOLFSSL_ECC_SECP160R1)
                != SSL_SUCCESS) {
            err_sys("unable to set curve secp160r1");
        }
    #endif

    #ifdef HAVE_SESSION_TICKET
    wolfSSL_set_SessionTicket_cb(ssl, sessionTicketCB, (void*)"initial session");
    #endif

#ifdef HAVE_ALPN
    if (alpnList != NULL) {
       printf("ALPN accepted protocols list : %s\n", alpnList);
       wolfSSL_UseALPN(ssl, alpnList, (word32)XSTRLEN(alpnList), alpn_opt);
    }
#endif
#ifdef HAVE_CERTIFICATE_STATUS_REQUEST
    if (statusRequest) {
        switch (statusRequest) {
            case WOLFSSL_CSR_OCSP:
                if (wolfSSL_UseOCSPStapling(ssl, WOLFSSL_CSR_OCSP,
                                     WOLFSSL_CSR_OCSP_USE_NONCE) != SSL_SUCCESS)
                    err_sys("UseCertificateStatusRequest failed");

            break;
        }

        wolfSSL_CTX_EnableOCSP(ctx, 0);
    }
#endif
#ifdef HAVE_CERTIFICATE_STATUS_REQUEST_V2
    if (statusRequest) {
        switch (statusRequest) {
            case WOLFSSL_CSR2_OCSP:
                if (wolfSSL_UseOCSPStaplingV2(ssl,
                    WOLFSSL_CSR2_OCSP, WOLFSSL_CSR2_OCSP_USE_NONCE)
                                                                 != SSL_SUCCESS)
                    err_sys("UseCertificateStatusRequest failed");
            break;
            case WOLFSSL_CSR2_OCSP_MULTI:
                if (wolfSSL_UseOCSPStaplingV2(ssl,
                    WOLFSSL_CSR2_OCSP_MULTI, 0)
                                                                 != SSL_SUCCESS)
                    err_sys("UseCertificateStatusRequest failed");
            break;

        }

        wolfSSL_CTX_EnableOCSP(ctx, 0);
    }
#endif

    tcp_connect(&sockfd, host, port, dtlsUDP, dtlsSCTP, ssl);
    if (wolfSSL_set_fd(ssl, sockfd) != SSL_SUCCESS) {
        err_sys("error in setting fd");
    }

    /* STARTTLS */
    if (doSTARTTLS) {
        if (StartTLS_Init(&sockfd) != SSL_SUCCESS) {
            err_sys("error during STARTTLS protocol");
        }
    }

#ifdef HAVE_CRL
    if (disableCRL == 0) {
        if (wolfSSL_EnableCRL(ssl, WOLFSSL_CRL_CHECKALL) != SSL_SUCCESS)
            err_sys("can't enable crl check");
        if (wolfSSL_LoadCRL(ssl, crlPemDir, SSL_FILETYPE_PEM, 0) != SSL_SUCCESS)
            err_sys("can't load crl, check crlfile and date validity");
        if (wolfSSL_SetCRL_Cb(ssl, CRL_CallBack) != SSL_SUCCESS)
            err_sys("can't set crl callback");
    }
#endif
#ifdef HAVE_SECURE_RENEGOTIATION
    if (scr) {
        if (wolfSSL_UseSecureRenegotiation(ssl) != SSL_SUCCESS)
            err_sys("can't enable secure renegotiation");
    }
#endif
#ifdef ATOMIC_USER
    if (atomicUser)
        SetupAtomicUser(ctx, ssl);
#endif
#ifdef HAVE_PK_CALLBACKS
    if (pkCallbacks)
        SetupPkCallbacks(ctx, ssl);
#endif
    if (matchName && doPeerCheck)
        wolfSSL_check_domain_name(ssl, domain);
#ifndef WOLFSSL_CALLBACKS
    if (nonBlocking) {
        wolfSSL_set_using_nonblock(ssl, 1);
        tcp_set_nonblocking(&sockfd);
        NonBlockingSSL_Connect(ssl);
    }
    else {
        do {
#ifdef WOLFSSL_ASYNC_CRYPT
            if (err == WC_PENDING_E) {
                ret = wolfSSL_AsyncPoll(ssl, WOLF_POLL_FLAG_CHECK_HW);
                if (ret < 0) { break; } else if (ret == 0) { continue; }
            }
#endif
            err = 0; /* Reset error */
            ret = wolfSSL_connect(ssl);
            if (ret != SSL_SUCCESS) {
                err = wolfSSL_get_error(ssl, 0);
            }
        } while (ret != SSL_SUCCESS && err == WC_PENDING_E);

        if (ret != SSL_SUCCESS) {
            char buffer[WOLFSSL_MAX_ERROR_SZ];
            printf("err = %d, %s\n", err, wolfSSL_ERR_error_string(err, buffer));
            err_sys("wolfSSL_connect failed");
            /* see note at top of README */
            /* if you're getting an error here  */
        }
    }
#else
    timeout.tv_sec  = 2;
    timeout.tv_usec = 0;
    NonBlockingSSL_Connect(ssl);  /* will keep retrying on timeout */
#endif
    showPeer(ssl);

    if (doSTARTTLS) {
        if (XSTRNCMP(starttlsProt, "smtp", 4) == 0) {
            if (SMTP_Shutdown(ssl, wc_shutdown) != SSL_SUCCESS) {
                err_sys("error closing STARTTLS connection");
            }
        }

        wolfSSL_free(ssl);
        CloseSocket(sockfd);

        wolfSSL_CTX_free(ctx);

        ((func_args*)args)->return_code = 0;
        return 0;
    }

#ifdef HAVE_ALPN
    if (alpnList != NULL) {
        char *protocol_name = NULL;
        word16 protocol_nameSz = 0;

        err = wolfSSL_ALPN_GetProtocol(ssl, &protocol_name, &protocol_nameSz);
        if (err == SSL_SUCCESS)
            printf("Received ALPN protocol : %s (%d)\n",
                   protocol_name, protocol_nameSz);
        else if (err == SSL_ALPN_NOT_FOUND)
            printf("No ALPN response received (no match with server)\n");
        else
            printf("Getting ALPN protocol name failed\n");
    }
#endif

#ifdef HAVE_SECURE_RENEGOTIATION
    if (scr && forceScr) {
        if (nonBlocking) {
            printf("not doing secure renegotiation on example with"
                   " nonblocking yet");
        } else {
            if (wolfSSL_Rehandshake(ssl) != SSL_SUCCESS) {
                char buffer[WOLFSSL_MAX_ERROR_SZ];
                err = wolfSSL_get_error(ssl, 0);
                printf("err = %d, %s\n", err,
                                wolfSSL_ERR_error_string(err, buffer));
                err_sys("wolfSSL_Rehandshake failed");
            }
        }
    }
#endif /* HAVE_SECURE_RENEGOTIATION */

    if (sendGET) {
        printf("SSL connect ok, sending GET...\n");
        msgSz = 28;
        strncpy(msg, "GET /index.html HTTP/1.0\r\n\r\n", msgSz);
        msg[msgSz] = '\0';

        resumeSz = msgSz;
        strncpy(resumeMsg, "GET /index.html HTTP/1.0\r\n\r\n", resumeSz);
        resumeMsg[resumeSz] = '\0';
    }

/* allow some time for exporting the session */
#ifdef WOLFSSL_SESSION_EXPORT_DEBUG
    #ifdef USE_WINDOWS_API
            Sleep(500);
    #elif defined(WOLFSSL_TIRTOS)
            Task_sleep(1);
    #else
            sleep(1);
    #endif
#endif /* WOLFSSL_SESSION_EXPORT_DEBUG */
    if (wolfSSL_write(ssl, msg, msgSz) != msgSz)
        err_sys("SSL_write failed");

    input = wolfSSL_read(ssl, reply, sizeof(reply)-1);
    if (input > 0) {
        reply[input] = 0;
        printf("Server response: %s\n", reply);

        if (sendGET) {  /* get html */
            while (1) {
                input = wolfSSL_read(ssl, reply, sizeof(reply)-1);
                if (input > 0) {
                    reply[input] = 0;
                    printf("%s\n", reply);
                }
                else
                    break;
            }
        }
    }
    else if (input < 0) {
        int readErr = wolfSSL_get_error(ssl, 0);
        if (readErr != SSL_ERROR_WANT_READ)
            err_sys("wolfSSL_read failed");
    }

#ifndef NO_SESSION_CACHE
    if (resumeSession) {
        session   = wolfSSL_get_session(ssl);
        sslResume = wolfSSL_new(ctx);
        if (sslResume == NULL)
            err_sys("unable to get SSL object");
    }
#endif

    if (dtlsUDP == 0) {           /* don't send alert after "break" command */
        ret = wolfSSL_shutdown(ssl);
        if (wc_shutdown && ret == SSL_SHUTDOWN_NOT_DONE)
            wolfSSL_shutdown(ssl);    /* bidirectional shutdown */
    }
#ifdef ATOMIC_USER
    if (atomicUser)
        FreeAtomicUser(ssl);
#endif
    wolfSSL_free(ssl);
    CloseSocket(sockfd);

#ifndef NO_SESSION_CACHE
    if (resumeSession) {
        if (dtlsUDP) {
#ifdef USE_WINDOWS_API
            Sleep(500);
#elif defined(WOLFSSL_TIRTOS)
            Task_sleep(1);
#else
            sleep(1);
#endif
        }
        tcp_connect(&sockfd, host, port, dtlsUDP, dtlsSCTP, sslResume);
        if (wolfSSL_set_fd(sslResume, sockfd) != SSL_SUCCESS) {
            err_sys("error in setting fd");
        }
#ifdef HAVE_ALPN
        if (alpnList != NULL) {
            printf("ALPN accepted protocols list : %s\n", alpnList);
            wolfSSL_UseALPN(sslResume, alpnList, (word32)XSTRLEN(alpnList),
                            alpn_opt);
        }
#endif
#ifdef HAVE_SECURE_RENEGOTIATION
        if (scr) {
            if (wolfSSL_UseSecureRenegotiation(sslResume) != SSL_SUCCESS)
                err_sys("can't enable secure renegotiation");
        }
#endif
        wolfSSL_set_session(sslResume, session);
#ifdef HAVE_SESSION_TICKET
        wolfSSL_set_SessionTicket_cb(sslResume, sessionTicketCB,
                                    (void*)"resumed session");
#endif
    #ifdef HAVE_SUPPORTED_CURVES /* add curves to supported curves extension */
        if (wolfSSL_UseSupportedCurve(sslResume, WOLFSSL_ECC_SECP256R1)
                != SSL_SUCCESS) {
            err_sys("unable to set curve secp256r1");
        }
        if (wolfSSL_UseSupportedCurve(sslResume, WOLFSSL_ECC_SECP384R1)
                != SSL_SUCCESS) {
            err_sys("unable to set curve secp384r1");
        }
        if (wolfSSL_UseSupportedCurve(sslResume, WOLFSSL_ECC_SECP521R1)
                != SSL_SUCCESS) {
            err_sys("unable to set curve secp521r1");
        }
        if (wolfSSL_UseSupportedCurve(sslResume, WOLFSSL_ECC_SECP224R1)
                != SSL_SUCCESS) {
            err_sys("unable to set curve secp224r1");
        }
        if (wolfSSL_UseSupportedCurve(sslResume, WOLFSSL_ECC_SECP192R1)
                != SSL_SUCCESS) {
            err_sys("unable to set curve secp192r1");
        }
        if (wolfSSL_UseSupportedCurve(sslResume, WOLFSSL_ECC_SECP160R1)
                != SSL_SUCCESS) {
            err_sys("unable to set curve secp160r1");
        }
    #endif

#ifndef WOLFSSL_CALLBACKS
        if (nonBlocking) {
            wolfSSL_set_using_nonblock(sslResume, 1);
            tcp_set_nonblocking(&sockfd);
            NonBlockingSSL_Connect(sslResume);
        }
        else if (wolfSSL_connect(sslResume) != SSL_SUCCESS)
            err_sys("SSL resume failed");
#else
        timeout.tv_sec  = 2;
        timeout.tv_usec = 0;
        NonBlockingSSL_Connect(ssl);  /* will keep retrying on timeout */
#endif
        showPeer(sslResume);

        if (wolfSSL_session_reused(sslResume))
            printf("reused session id\n");
        else
            printf("didn't reuse session id!!!\n");

#ifdef HAVE_ALPN
        if (alpnList != NULL) {
            char *protocol_name = NULL;
            word16 protocol_nameSz = 0;

            printf("Sending ALPN accepted list : %s\n", alpnList);
            err = wolfSSL_ALPN_GetProtocol(sslResume, &protocol_name,
                                           &protocol_nameSz);
            if (err == SSL_SUCCESS)
                printf("Received ALPN protocol : %s (%d)\n",
                       protocol_name, protocol_nameSz);
            else if (err == SSL_ALPN_NOT_FOUND)
                printf("Not received ALPN response (no match with server)\n");
            else
                printf("Getting ALPN protocol name failed\n");
        }
#endif

    /* allow some time for exporting the session */
    #ifdef WOLFSSL_SESSION_EXPORT_DEBUG
        #ifdef USE_WINDOWS_API
            Sleep(500);
        #elif defined(WOLFSSL_TIRTOS)
            Task_sleep(1);
        #else
            sleep(1);
        #endif
    #endif /* WOLFSSL_SESSION_EXPORT_DEBUG */

        if (wolfSSL_write(sslResume, resumeMsg, resumeSz) != resumeSz)
            err_sys("SSL_write failed");

        if (nonBlocking) {
            /* give server a chance to bounce a message back to client */
            #ifdef USE_WINDOWS_API
                Sleep(500);
            #elif defined(WOLFSSL_TIRTOS)
                Task_sleep(1);
            #else
                sleep(1);
            #endif
        }

    input = wolfSSL_read(sslResume, reply, sizeof(reply)-1);

    if (input > 0) {
        reply[input] = 0;
        printf("Server resume response: %s\n", reply);

        if (sendGET) {  /* get html */
            while (1) {
                input = wolfSSL_read(sslResume, reply, sizeof(reply)-1);
                if (input > 0) {
                    reply[input] = 0;
                    printf("%s\n", reply);
                }
                else
                    break;
            }
        }
    } else if (input < 0) {
        int readErr = wolfSSL_get_error(ssl, 0);
        if (readErr != SSL_ERROR_WANT_READ)
            err_sys("wolfSSL_read failed");
    }

        /* try to send session break */
        wolfSSL_write(sslResume, msg, msgSz);

        ret = wolfSSL_shutdown(sslResume);
        if (wc_shutdown && ret == SSL_SHUTDOWN_NOT_DONE)
            wolfSSL_shutdown(sslResume);    /* bidirectional shutdown */

        wolfSSL_free(sslResume);
        CloseSocket(sockfd);
    }
#endif /* NO_SESSION_CACHE */

    wolfSSL_CTX_free(ctx);

    ((func_args*)args)->return_code = 0;

#ifdef WOLFSSL_ASYNC_CRYPT
    wolfAsync_DevClose(&devId);
#endif

#if defined(USE_WOLFSSL_MEMORY) && !defined(WOLFSSL_STATIC_MEMORY)
    if (trackMemory)
        ShowMemoryTracker();
#endif /* USE_WOLFSSL_MEMORY */

    /* There are use cases  when these assignments are not read. To avoid
     * potential confusion those warnings have been handled here.
     */
    (void) overrideDateErrors;
    (void) useClientCert;
    (void) verifyCert;
    (void) ourCert;
    (void) ourKey;
    (void) trackMemory;

#if !defined(WOLFSSL_TIRTOS)
    return 0;
#endif
}


/* so overall tests can pull in test function */
#ifndef NO_MAIN_DRIVER

    int main(int argc, char** argv)
    {
        func_args args;


        StartTCP();

        args.argc = argc;
        args.argv = argv;

#if defined(DEBUG_WOLFSSL) && !defined(WOLFSSL_MDK_SHELL) && !defined(STACK_TRAP)
        wolfSSL_Debugging_ON();
#endif
        wolfSSL_Init();
        ChangeToWolfRoot();

#ifdef HAVE_STACK_SIZE
        StackSizeCheck(&args, client_test);
#else
        client_test(&args);
#endif
        wolfSSL_Cleanup();

#ifdef HAVE_WNR
    if (wc_FreeNetRandom() < 0)
        err_sys("Failed to free netRandom context");
#endif /* HAVE_WNR */

        return args.return_code;
    }

    int myoptind = 0;
    char* myoptarg = NULL;

#endif /* NO_MAIN_DRIVER */



#ifdef WOLFSSL_CALLBACKS

    int handShakeCB(HandShakeInfo* info)
    {
        (void)info;
        return 0;
    }


    int timeoutCB(TimeoutInfo* info)
    {
        (void)info;
        return 0;
    }

#endif


#ifdef HAVE_SESSION_TICKET

    int sessionTicketCB(WOLFSSL* ssl,
                        const unsigned char* ticket, int ticketSz,
                        void* ctx)
    {
        (void)ssl;
        (void)ticket;
        printf("Session Ticket CB: ticketSz = %d, ctx = %s\n",
               ticketSz, (char*)ctx);
        return 0;
    }

#endif
