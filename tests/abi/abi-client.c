/* abi-client.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/ecc.h>

#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <pthread.h>
#include <fcntl.h>
#include <signal.h>

typedef struct sockaddr_in  SOCKADDR_IN_T;
#define SOCKET_T int
#define AF_INET_V    AF_INET


const char* caCert = "./certs/test/server-localhost.pem";
const char* clientCert = "./certs/client-cert.pem";
const char* clientKey = "./certs/client-key.pem";


static inline WC_NORETURN void
err_sys(const char* msg)
{
    printf("wolfSSL error: %s\n", msg);

    exit(EXIT_FAILURE);
}


static inline
void build_addr(SOCKADDR_IN_T* addr, const char* peer, unsigned short port)
{
    int useLookup = 0;
    (void)useLookup;

    if (addr == NULL)
        err_sys("invalid argument to build_addr, addr is NULL");

    memset(addr, 0, sizeof(SOCKADDR_IN_T));

#ifndef TEST_IPV6
    /* peer could be in human readable form */
    if ( ((size_t)peer != INADDR_ANY) && isalpha((int)peer[0])) {
    #ifndef WOLFSSL_USE_GETADDRINFO
        #if defined(WOLFSSL_MDK_ARM) || defined(WOLFSSL_KEIL_TCP_NET)
            int err;
            struct hostent* entry = gethostbyname(peer, &err);
        #elif defined(WOLFSSL_TIRTOS)
            struct hostent* entry = DNSGetHostByName(peer);
        #elif defined(WOLFSSL_VXWORKS)
            struct hostent* entry = (struct hostent*)hostGetByName((char*)peer);
        #else
            struct hostent* entry = gethostbyname(peer);
        #endif

        if (entry) {
            memcpy(&addr->sin_addr.s_addr, entry->h_addr_list[0],
                   entry->h_length);
            useLookup = 1;
        }
    #else
        struct zsock_addrinfo hints, *addrInfo;
        char portStr[6];
        XSNPRINTF(portStr, sizeof(portStr), "%d", port);
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = udp ? SOCK_DGRAM : SOCK_STREAM;
        hints.ai_protocol = udp ? IPPROTO_UDP : IPPROTO_TCP;
        if (getaddrinfo((char*)peer, portStr, &hints, &addrInfo) == 0) {
            XMEMCPY(addr, addrInfo->ai_addr, sizeof(*addr));
            useLookup = 1;
        }
    #endif
        else
            err_sys("no entry for host");
    }
#endif


#ifndef TEST_IPV6
    #if defined(WOLFSSL_MDK_ARM) || defined(WOLFSSL_KEIL_TCP_NET)
        addr->sin_family = PF_INET;
    #else
        addr->sin_family = AF_INET_V;
    #endif
    addr->sin_port = htons(port);
    if ((size_t)peer == INADDR_ANY)
        addr->sin_addr.s_addr = INADDR_ANY;
    else {
        if (!useLookup)
            addr->sin_addr.s_addr = inet_addr(peer);
    }
#else
    addr->sin6_family = AF_INET_V;
    addr->sin6_port = XHTONS(port);
    if ((size_t)peer == INADDR_ANY) {
        addr->sin6_addr = in6addr_any;
    }
    else {
        #if defined(HAVE_GETADDRINFO) || defined(WOLF_C99)
            struct addrinfo  hints;
            struct addrinfo* answer = NULL;
            int    ret;
            char   strPort[80];

            XMEMSET(&hints, 0, sizeof(hints));

            hints.ai_family   = AF_INET_V;
            if (udp) {
                hints.ai_socktype = SOCK_DGRAM;
                hints.ai_protocol = IPPROTO_UDP;
            }
        #ifdef WOLFSSL_SCTP
            else if (sctp) {
                hints.ai_socktype = SOCK_STREAM;
                hints.ai_protocol = IPPROTO_SCTP;
            }
        #endif
            else {
                hints.ai_socktype = SOCK_STREAM;
                hints.ai_protocol = IPPROTO_TCP;
            }

            SNPRINTF(strPort, sizeof(strPort), "%d", port);
            strPort[79] = '\0';

            ret = getaddrinfo(peer, strPort, &hints, &answer);
            if (ret < 0 || answer == NULL)
                err_sys("getaddrinfo failed");

            XMEMCPY(addr, answer->ai_addr, answer->ai_addrlen);
            freeaddrinfo(answer);
        #else
            printf("no ipv6 getaddrinfo, loopback only tests/examples\n");
            addr->sin6_addr = in6addr_loopback;
        #endif
    }
#endif
}


static inline
void tcp_socket(SOCKET_T* sockfd)
{
    *sockfd = socket(AF_INET_V, SOCK_STREAM, IPPROTO_TCP);

    if(*sockfd < 0) {
        err_sys("socket failed\n");
    }

    signal(SIGPIPE, SIG_IGN);
}


static inline
void tcp_connect(SOCKET_T* sockfd, const char* ip, unsigned short port)
{
    SOCKADDR_IN_T addr;
    build_addr(&addr, ip, port);
    tcp_socket(sockfd);

    if (connect(*sockfd, (const struct sockaddr*)&addr, sizeof(addr)) != 0)
        err_sys("tcp connect failed");
}


static
int print_time(const char* desc, const unsigned char* time)
{
    int length;
    unsigned char flatTime[64];
    unsigned char type;

    type = time[0];
    length = (int)time[1];

    memcpy(flatTime, &time[2], length);
    flatTime[length] = '\0';

    printf("  %12s: (%u) %s\n", desc, type, flatTime);

    return 0;
}


static
int print_cert(const char* desc, WOLFSSL_X509* cert)
{
    WOLFSSL_X509_NAME* xName;
    const unsigned char* xTime;
    char* nameP;
    char name[256];

    printf("%s\n", desc);
    xName = wolfSSL_X509_get_issuer_name(cert);
    nameP = wolfSSL_X509_NAME_oneline(xName, name, (int)sizeof(name));
    printf("  %12s: %s\n", "issuer name", nameP);

    xName = wolfSSL_X509_get_subject_name(cert);
    nameP = wolfSSL_X509_NAME_oneline(xName, name, (int)sizeof(name));
    printf("  %12s: %s\n", "subject name", nameP);

    do {
        nameP = wolfSSL_X509_get_next_altname(cert);
        if (nameP != NULL) {
            printf("%12s: %s\n", "altname", nameP);
        }
    } while (nameP != NULL);

    xTime = wolfSSL_X509_notBefore(cert);
    print_time("notBefore", xTime);

    xTime = wolfSSL_X509_notAfter(cert);
    print_time("notAfter", xTime);

    return 0;
}


static
int test_cert_file(void)
{
    WOLFSSL_X509* cert;
    cert = wolfSSL_X509_load_certificate_file(caCert, SSL_FILETYPE_PEM);
    printf("wolfSSL_X509_load_certificate_file() = %p\n", cert);
    if (cert != NULL)
        print_cert("wolfSSL_X509_load_certificate_file()", cert);
    wolfSSL_X509_free(cert);

    return 0;
}


static
int test_ecc_key(void)
{
    WC_RNG* rng = NULL;
    ecc_key* ecc = NULL;
    byte nonce[32];
    byte digest[32];
    byte sig[72];
    int ret = 0;
    word32 digestSz = sizeof(digest), sigSz = sizeof(sig);

    memset(nonce, 0, sizeof(nonce));

    rng = wc_rng_new(nonce, (word32)sizeof(nonce), NULL);
    if (rng == NULL) {
        printf("Couldn't get a random number generator.\n");
        goto doExit;
    }

    wc_RNG_GenerateBlock(rng, digest, digestSz);

    ecc = wc_ecc_key_new(NULL);
    if (ecc == NULL) {
        printf("Couldn't allocate ECC key.\n");
        goto doExit;
    }

    ret = wc_ecc_init_ex(ecc, NULL, INVALID_DEVID);
    if (ret != 0) {
        printf("Couldn't initialize ECC key. (%d)\n", ret);
        goto doExit;
    }
    ret = wc_ecc_make_key_ex(rng, 32, ecc, ECC_SECP256R1);
    if (ret != 0) {
        printf("Couldn't generate ECC key. (%d)\n", ret);
        goto doExit;
    }
    ret = wc_ecc_sign_hash(digest, digestSz, sig, &sigSz, rng, ecc);
    if (ret != 0) {
        printf("Couldn't sign hash. (%d)\n", ret);
        goto doExit;
    }

doExit:
    if (ecc != NULL) {
        wc_ecc_free(ecc);
        wc_ecc_key_free(ecc);
    }
    if (rng != NULL)
        wc_rng_free(rng);

    return ret;
}


static
int test_ecc_sign_cb(WOLFSSL* ssl,
       const unsigned char* in, unsigned int inSz,
       unsigned char* out, word32* outSz,
       const unsigned char* keyDer, unsigned int keySz,
       void* ctx)
{
    int ret = 0;
    ecc_key* ecc = NULL;

    (void)ctx;
    printf("EccSignCb\n");

    ret = wc_ecc_init_ex(ecc, NULL, INVALID_DEVID);
    if (ret != 0)
        printf("Couldn't initialize ECC key. (%d)\n", ret);
    else
    ret = wc_ecc_import_x963(keyDer, keySz, ecc);

    if (ret != 0)
        printf("Couldn't import ECC key. (%d)\n", ret);
    else
        ret = wc_ecc_sign_hash(in, inSz, out, outSz, wolfSSL_GetRNG(ssl), ecc);

    if (ret != 0)
        printf("Couldn't sign the hash. (%d)\n", ret);

    wc_ecc_free(ecc);
    wc_ecc_key_free(ecc);

    return ret;
}


static
int test_connection(int ver, int port)
{
    WOLFSSL_METHOD* method;
    const char* sni;
    int ret;
    long mode;

    printf("test_connection(%d, %d)\n", ver, port);
    switch (ver) {
        case 3:
            method = wolfTLSv1_3_client_method();
            ver = /* TLSv1_3_MINOR */ 4;
            break;
        default:
            method = wolfTLSv1_2_client_method();
            ver = /* TLSv1_2_MINOR */ 3;
    }

    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    if (ctx) printf("got a good ctx\n");

    ret = wolfSSL_CTX_SetMinVersion(ctx, ver);
    if (ret != SSL_SUCCESS)
        printf("Couldn't set the minimum TLS version on context.\n");
    ret = wolfSSL_CTX_load_verify_locations(ctx, caCert, 0);
    printf("load verify ret = %d\n", ret);

    ret = wolfSSL_CTX_SetDevId(ctx, 42);
    if (ret != SSL_SUCCESS)
        printf("couldn't set CTX's device ID\n");
    if (wolfSSL_CTX_GetDevId(ctx, NULL) != 42)
        printf("couldn't verify the CTX's new device ID\n");

    wolfSSL_CTX_SetEccSignCb(ctx, test_ecc_sign_cb);
    mode = wolfSSL_CTX_set_session_cache_mode(ctx,
            SSL_SESS_CACHE_NO_AUTO_CLEAR);
    printf("CTX_set_session_cache_mode ret = %lu\n", mode);

    WOLFSSL* ssl = wolfSSL_new(ctx);
    if (ssl)
        printf("got a good ssl\n");

    if (wolfSSL_CTX_GetDevId(NULL, ssl) != 42)
        printf("couldn't verify the new session's device ID\n");
    ret = wolfSSL_SetDevId(ssl, INVALID_DEVID);
    if (ret != SSL_SUCCESS)
        printf("couldn't set session's device ID\n");
    if (wolfSSL_CTX_GetDevId(NULL, ssl) != INVALID_DEVID)
        printf("couldn't verify the session's new device ID\n");
    sni = "badname";
    ret = wolfSSL_CTX_UseSNI(ctx, 0, sni, (word32)strlen(sni));
    printf("CTX_UseSNI ret = %d\n", ret);
    ret = wolfSSL_CTX_set_timeout(ctx, 1000);
    printf("CTX_set_timeout ret = %d\n", ret);

    SOCKET_T sfd;

    tcp_connect(&sfd, "localhost", port);

    wolfSSL_set_fd(ssl, sfd);
    ret = wolfSSL_check_domain_name(ssl, "localhost");
    if (ret != SSL_SUCCESS)
        printf("Couldn't set check domain name\n");

    char alpnList[] = "C:";
    ret = wolfSSL_UseALPN(ssl, alpnList, (word32)strlen(alpnList),
            WOLFSSL_ALPN_CONTINUE_ON_MISMATCH);
    printf("UseALPN ret = %d\n", ret);
    sni = "localhost";
    ret = wolfSSL_UseSNI(ssl, 0, sni, (word32)strlen(sni));
    printf("UseSNI ret = %d\n", ret);
    ret = wolfSSL_set_timeout(ssl, 300);
    printf("set_timeout ret = %d\n", ret);

    ret = wolfSSL_connect(ssl);

    printf("ssl connect ret = %d\n", ret);
    if (ret < 0) {
        int err = wolfSSL_get_error(ssl, 0);
        printf("err = %d\n", err);
    }

    WOLFSSL_X509* cert = wolfSSL_get_peer_certificate(ssl);
    if (cert == NULL)
        printf("the peer certificate is missing\n");
    else {
        print_cert("wolfSSL_get_peer_certificate()", cert);
        wolfSSL_X509_free(cert);
    }

    ret = wolfSSL_write(ssl, "hi there", 9);
    printf("write ret = %d\n", ret);
    ret = wolfSSL_pending(ssl);
    printf("pending ret = %d\n", ret);

    char buffer[128];
    memset(buffer, 0, sizeof(buffer));
    ret = wolfSSL_read(ssl, buffer, sizeof(buffer));
    printf("read ret = %d\n", ret);
    printf("read %s\n", buffer);

    printf("bye\n");

    wolfSSL_shutdown(ssl);

    WOLFSSL_SESSION* session = wolfSSL_get_session(ssl);
    printf("get_session = %p\n", session);

    const byte* sessionId = wolfSSL_get_sessionID(session);
    printf("sessionID = %p\n", sessionId);

    ret = wolfSSL_set_session(ssl, session);
    printf("set_session ret = %d\n", ret);

    wolfSSL_flush_sessions(ctx, 0);

    close(sfd);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    return 0;
}


static int
test_cert_use(void)
{
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    int ret;

    ret = wolfSSL_CTX_use_certificate_chain_file(ctx, clientCert);
    printf("CTX_use_certificate_chain_file ret = %d\n", ret);
    ret = wolfSSL_CTX_use_certificate_file(ctx, clientCert, SSL_FILETYPE_PEM);
    printf("CTX_use_certificate_file ret = %d\n", ret);
    ret = wolfSSL_CTX_use_PrivateKey_file(ctx, clientKey, SSL_FILETYPE_PEM);
    printf("CTX_use_PrivateKey_file ret = %d\n", ret);

    WOLFSSL* ssl = wolfSSL_new(ctx);

    ret = wolfSSL_use_certificate_chain_file(ssl, clientCert);
    printf("use_certificate_chain_file ret = %d\n", ret);
    ret = wolfSSL_use_certificate_file(ssl, clientCert, SSL_FILETYPE_PEM);
    printf("use_certificate_file ret = %d\n", ret);
    ret = wolfSSL_use_PrivateKey_file(ssl, clientKey, SSL_FILETYPE_PEM);
    printf("use_PrivateKey_file ret = %d\n", ret);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    return 0;
}


int main(int argc, char* argv[])
{
    int port = 11111;
    int ret;

    if (argc > 1) {
        port = atoi(argv[1]);
        if (port == 0) {
            printf("bad port number (%s)\n", argv[1]);
            return 1;
        }
    }

    printf("hello\n");

    ret = wolfSSL_Init();
    if (ret != SSL_SUCCESS)
        printf("init = %d\n", ret);

    test_cert_file();
    test_cert_use();
    test_ecc_key();

    test_connection(2, port);
    test_connection(3, port);

    wolfSSL_Cleanup();
    printf("bye\n");

    return 0;
}
