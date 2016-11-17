/* tcp-conn-nb.h
 *
 * Copyright (C) 2006-2014 wolfSSL Inc.
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifndef TCP_CONN_NB_H
#define TCP_CONN_NB_H

/* Options for LwIP native socket client example */
    #define NO_MAIN_DRIVER
    #define NO_SESSION_CACHE
    #define NO_PSK
    #define NO_BENCHMARK
    #undef USE_WOLFSSL_MEMORY
/******/

    #include <wolfssl/wolfcrypt/types.h>
    #include <string.h>
    #include "lwip/tcp.h"
    #include "lwip/sockets.h"
    #include "lwip/inet.h"
    #include "lwip/ip_addr.h"
    
    #define THREAD_RETURN int
    #define WOLFSSL_THREAD
    #define SOCKET_T struct tcp_pcb *
    #define SOCKADDR_IN_T int
    //#define ip_addr_t char * 
    #define err_sys(msg) puts(msg)
    #define exit(code) return(code) ; 
    void tcp_connect_init(void) ;
    int tcp_connect_nb(struct tcp_pcb **pcb, const char* ip, word16 port,
                               int udp) ; 
    void tcp_close_nb(void) ;
enum TCP_stat  {
    TCP_BEGIN, 
    TCP_CONNECTING, /* return code */
    TCP_CONNECTED,  /* return code */
    TCP_WAITING,
    TCP_CLOSE,
    TCP_IDLE,
    TCP_ERROR,
} ;



/*** from test.h ***/
    #define WOLFSSL_MAX_ERROR_SZ 128
    #define CLIENT_DEFAULT_VERSION 3
    #define CLIENT_DTLS_DEFAULT_VERSION (-2)
    #define CLIENT_INVALID_VERSION (-99)
    static const char* const yasslIP   = "127.0.0.1";
    static const word16      yasslPort = 11111;
    #define caCert     "./certs/ca-cert.pem"
    #define cliCert    "./certs/client-cert.pem"
    #define cliKey     "./certs/client-key.pem"
    #define MY_EX_USAGE 2
    #define StackTrap(a)
    #define InitMemoryTracker(a)

    typedef struct func_args {
        int    argc;
        char** argv;
        int    return_code;
    } func_args;
    
    extern int   myoptind;
    extern char* myoptarg;

    void build_addr(int *addr, char *host, int port, int mode) ;
    void tcp_socket(SOCKET_T *s, int flag) ;
        
enum {
    TEST_SELECT_FAIL,
    TEST_TIMEOUT,
    TEST_RECV_READY,
    TEST_ERROR_READY
};
    
    static INLINE void tcp_set_nonblocking(SOCKET_T* sockfd){ }
    
    
static INLINE int mygetopt(int argc, char** argv, const char* optstring)
{
    static char* next = NULL;

    char  c;
    char* cp;

    if (myoptind == 0)
        next = NULL;   /* we're starting new/over */

    if (next == NULL || *next == '\0') {
        if (myoptind == 0)
            myoptind++;

        if (myoptind >= argc || argv[myoptind][0] != '-' ||
                                argv[myoptind][1] == '\0') {
            myoptarg = NULL;
            if (myoptind < argc)
                myoptarg = argv[myoptind];

            return -1;
        }

        if (strcmp(argv[myoptind], "--") == 0) {
            myoptind++;
            myoptarg = NULL;

            if (myoptind < argc)
                myoptarg = argv[myoptind];

            return -1;
        }

        next = argv[myoptind];
        next++;                  /* skip - */
        myoptind++;
    }

    c  = *next++;
    /* The C++ strchr can return a different value */
    cp = (char*)strchr(optstring, c);

    if (cp == NULL || c == ':') 
        return '?';

    cp++;

    if (*cp == ':') {
        if (*next != '\0') {
            myoptarg = next;
            next     = NULL;
        }
        else if (myoptind < argc) {
            myoptarg = argv[myoptind];
            myoptind++;
        }
        else 
            return '?';
    }

    return c;
}

static INLINE void showPeer(WOLFSSL* ssl)
{

    WOLFSSL_CIPHER* cipher;
#ifdef KEEP_PEER_CERT
    WOLFSSL_X509* peer = wolfSSL_get_peer_certificate(ssl);
    if (peer)
        ShowX509(peer, "peer's cert info:");
    else
        printf("peer has no cert!\n");
#endif
    printf("SSL version is %s\n", wolfSSL_get_version(ssl));

    cipher = wolfSSL_get_current_cipher(ssl);
    printf("SSL cipher suite is %s\n", wolfSSL_CIPHER_get_name(cipher));

#if defined(SESSION_CERTS) && defined(SHOW_CERTS)
    {
        WOLFSSL_X509_CHAIN* chain = wolfSSL_get_peer_chain(ssl);
        int                count = wolfSSL_get_chain_count(chain);
        int i;

        for (i = 0; i < count; i++) {
            int length;
            unsigned char buffer[3072];
            WOLFSSL_X509* chainX509;

            wolfSSL_get_chain_cert_pem(chain,i,buffer, sizeof(buffer), &length);
            buffer[length] = 0;
            printf("cert %d has length %d data = \n%s\n", i, length, buffer);

            chainX509 = wolfSSL_get_chain_X509(chain, i);
            if (chainX509)
                ShowX509(chainX509, "session cert info:");
            else
                printf("get_chain_X509 failed\n");
            wolfSSL_FreeX509(chainX509);
        }
    }
#endif
  (void)ssl;
}

#endif
