/* test.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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
/*!
    \file ../wolfssl/test.h
    \brief Header file containing test inline functions
*/

/* Testing functions */

#ifndef wolfSSL_TEST_H
#define wolfSSL_TEST_H

#include <wolfssl/wolfcrypt/settings.h>

#undef TEST_OPENSSL_COEXIST /* can't use this option with this example */
#if defined(OPENSSL_EXTRA) && defined(OPENSSL_COEXIST)
    #error "Example apps built with OPENSSL_EXTRA can't also be built with OPENSSL_COEXIST."
#endif

#include <wolfssl/wolfcrypt/wc_port.h>

#ifdef FUSION_RTOS
    #include <fclstdio.h>
    #include <fclstdlib.h>
#else
    #include <stdio.h>
    #include <stdlib.h>
#endif
#include <assert.h>
#include <ctype.h>
#ifdef HAVE_ERRNO_H
    #include <errno.h>
#endif
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/mem_track.h>
#include <wolfssl/wolfio.h>
#include <wolfssl/wolfcrypt/asn.h>

#ifdef ATOMIC_USER
    #include <wolfssl/wolfcrypt/aes.h>
    #include <wolfssl/wolfcrypt/arc4.h>
    #include <wolfssl/wolfcrypt/hmac.h>
#endif
#ifdef HAVE_PK_CALLBACKS
    #ifndef NO_RSA
        #include <wolfssl/wolfcrypt/rsa.h>
    #endif
    #ifdef HAVE_ECC
        #include <wolfssl/wolfcrypt/ecc.h>
    #endif /* HAVE_ECC */
    #ifndef NO_DH
        #include <wolfssl/wolfcrypt/dh.h>
    #endif /* !NO_DH */
    #ifdef HAVE_ED25519
        #include <wolfssl/wolfcrypt/ed25519.h>
    #endif /* HAVE_ED25519 */
    #ifdef HAVE_CURVE25519
        #include <wolfssl/wolfcrypt/curve25519.h>
    #endif /* HAVE_ECC */
    #ifdef HAVE_ED448
        #include <wolfssl/wolfcrypt/ed448.h>
    #endif /* HAVE_ED448 */
    #ifdef HAVE_CURVE448
        #include <wolfssl/wolfcrypt/curve448.h>
    #endif /* HAVE_ECC */
#endif /*HAVE_PK_CALLBACKS */

#ifdef USE_WINDOWS_API
    #include <winsock2.h>
    #include <process.h>
    #ifdef TEST_IPV6            /* don't require newer SDK for IPV4 */
        #include <ws2tcpip.h>
        #include <wspiapi.h>
    #endif
    #define SOCKET_T SOCKET
    #define SNPRINTF _snprintf
    #define XSLEEP_MS(t) Sleep(t)
#elif defined(WOLFSSL_MDK_ARM) || defined(WOLFSSL_KEIL_TCP_NET)
    #include <string.h>
    #include "rl_net.h"
    #define SOCKET_T int
    typedef int socklen_t ;
    #define inet_addr wolfSSL_inet_addr
    static unsigned long wolfSSL_inet_addr(const char *cp)
    {
        unsigned int a[4] ; unsigned long ret ;
        sscanf(cp, "%u.%u.%u.%u", &a[0], &a[1], &a[2], &a[3]) ;
        ret = ((a[3]<<24) + (a[2]<<16) + (a[1]<<8) + a[0]) ;
        return(ret) ;
    }
    #if defined(HAVE_KEIL_RTX)
        #define XSLEEP_MS(t)  os_dly_wait(t)
    #elif defined(WOLFSSL_CMSIS_RTOS) || defined(WOLFSSL_CMSIS_RTOSv2)
        #define XSLEEP_MS(t)  osDelay(t)
    #endif
#elif defined(WOLFSSL_TIRTOS)
    #include <string.h>
    #include <netdb.h>
    #if !defined(__ti__) /* conflicts with sys/socket.h */
        #include <sys/types.h>
    #endif
    #include <arpa/inet.h>
    #include <sys/socket.h>
    #include <ti/sysbios/knl/Task.h>
    struct hostent {
        char *h_name; /* official name of host */
        char **h_aliases; /* alias list */
        int h_addrtype; /* host address type */
        int h_length; /* length of address */
        char **h_addr_list; /* list of addresses from name server */
    };
    #define SOCKET_T int
    #define XSLEEP_MS(t) Task_sleep(t/1000)
#elif defined(WOLFSSL_VXWORKS)
    #include <hostLib.h>
    #include <sockLib.h>
    #include <arpa/inet.h>
    #include <string.h>
    #include <selectLib.h>
    #include <sys/types.h>
    #include <netinet/in.h>
    #include <fcntl.h>
    #ifdef WOLFSSL_VXWORKS_6_x
        #include <time.h>
    #else
        #include <sys/time.h>
    #endif
    #include <netdb.h>
    #include <pthread.h>
    #define SOCKET_T int
#elif defined(WOLFSSL_ZEPHYR)
    #include <version.h>
    #include <string.h>
    #include <sys/types.h>
    #if KERNEL_VERSION_NUMBER >= 0x30100
        #include <zephyr/net/socket.h>
        #ifdef CONFIG_POSIX_API
            #include <zephyr/posix/poll.h>
            #include <zephyr/posix/netdb.h>
            #include <zephyr/posix/sys/socket.h>
            #include <zephyr/posix/sys/select.h>
        #endif
    #else
        #include <net/socket.h>
        #ifdef CONFIG_POSIX_API
            #include <posix/poll.h>
            #include <posix/netdb.h>
            #include <posix/sys/socket.h>
            #include <posix/sys/select.h>
        #endif
    #endif
    #define SOCKET_T int
    #define SOL_SOCKET 1
    #define WOLFSSL_USE_GETADDRINFO

    static unsigned long inet_addr(const char *cp)
    {
        unsigned int a[4]; unsigned long ret;
        int i, j;
        for (i=0, j=0; i<4; i++) {
            a[i] = 0;
            while (cp[j] != '.' && cp[j] != '\0') {
                a[i] *= 10;
                a[i] += cp[j] - '0';
                j++;
            }
        }
        ret = ((a[3]<<24) + (a[2]<<16) + (a[1]<<8) + a[0]) ;
        return(ret) ;
    }
#elif defined(NETOS)
    #include <string.h>
    #include <sys/types.h>
    struct hostent {
        char* h_name;        /* official name of host */
        char** h_aliases;    /* alias list */
        int h_addrtype;      /* host address type */
        int h_length;        /* length of address */
        char** h_addr_list;  /* list of addresses from the name server */
    };
#elif defined(ARDUINO)
    /* TODO, define board-specific */
#else
    #include <string.h>
    #include <sys/types.h>
#ifndef WOLFSSL_LEANPSK
    #include <unistd.h>
    #include <netdb.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <arpa/inet.h>
    #ifndef WOLFSSL_NDS
        #include <sys/ioctl.h>
    #endif
    #include <sys/time.h>
    #include <sys/socket.h>
    #ifdef HAVE_PTHREAD
        #include <pthread.h>
    #endif
    #include <fcntl.h>
    #ifdef TEST_IPV6
        #include <netdb.h>
    #endif
#endif
    #ifdef FREESCALE_MQX
        typedef int socklen_t ;
    #endif
    #define SOCKET_T int
    #ifndef SO_NOSIGPIPE
        #include <signal.h>  /* ignore SIGPIPE */
    #endif
    #define SNPRINTF snprintf

    #define XSELECT_WAIT(x,y) do { \
        struct timeval tv = {((x) + ((y) / 1000000)),((y) % 1000000)}; \
        if ((select(0, NULL, NULL, NULL, &tv) < 0) && (errno != EINTR)) \
            err_sys("select for XSELECT_WAIT failed."); \
    } while (0)
    #define XSLEEP_US(u) XSELECT_WAIT(0,u)
    #define XSLEEP_MS(m) XSELECT_WAIT(0,(m)*1000)
#endif /* USE_WINDOWS_API */

#ifndef XSLEEP_MS
    #define XSLEEP_MS(t) sleep(t/1000)
#endif

#ifdef WOLFSSL_ASYNC_CRYPT
    #include <wolfssl/wolfcrypt/async.h>
#endif
#ifdef HAVE_CAVIUM
    #include <wolfssl/wolfcrypt/port/cavium/cavium_nitrox.h>
#endif
#ifdef _MSC_VER
    /* disable conversion warning */
    /* 4996 warning to use MS extensions e.g., strcpy_s instead of strncpy */
    #pragma warning(disable:4244 4996)
#endif

#ifndef WOLFSSL_CIPHER_LIST_MAX_SIZE
    #define WOLFSSL_CIPHER_LIST_MAX_SIZE 4096
#endif
/* Buffer for benchmark tests */
#ifndef TEST_BUFFER_SIZE
    #define TEST_BUFFER_SIZE 16384
#endif

#ifndef WOLFSSL_HAVE_MIN
    #define WOLFSSL_HAVE_MIN
    #ifdef NO_INLINE
        #define min no_inline_min
    #endif
    static WC_INLINE word32 min(word32 a, word32 b)
    {
        return a > b ? b : a;
    }
#endif /* WOLFSSL_HAVE_MIN */

/* Socket Handling */
#ifndef WOLFSSL_SOCKET_INVALID
#ifdef USE_WINDOWS_API
    #define WOLFSSL_SOCKET_INVALID  ((SOCKET_T)INVALID_SOCKET)
#elif defined(WOLFSSL_TIRTOS)
    #define WOLFSSL_SOCKET_INVALID  ((SOCKET_T)-1)
#else
    #define WOLFSSL_SOCKET_INVALID  (SOCKET_T)(-1)
#endif
#endif /* WOLFSSL_SOCKET_INVALID */

#ifndef WOLFSSL_SOCKET_IS_INVALID
#if defined(USE_WINDOWS_API) || defined(WOLFSSL_TIRTOS)
    #define WOLFSSL_SOCKET_IS_INVALID(s)  ((SOCKET_T)(s) == WOLFSSL_SOCKET_INVALID)
#else
    #define WOLFSSL_SOCKET_IS_INVALID(s)  ((SOCKET_T)(s) < WOLFSSL_SOCKET_INVALID)
#endif
#endif /* WOLFSSL_SOCKET_IS_INVALID */

#if defined(__MACH__) || defined(USE_WINDOWS_API)
    #ifndef _SOCKLEN_T
        typedef int socklen_t;
    #endif
#endif


/* HPUX doesn't use socklent_t for third parameter to accept, unless
   _XOPEN_SOURCE_EXTENDED is defined */
#if !defined(__hpux__) && !defined(WOLFSSL_MDK_ARM) && !defined(WOLFSSL_IAR_ARM)\
 && !defined(WOLFSSL_ROWLEY_ARM)  && !defined(WOLFSSL_KEIL_TCP_NET)
    typedef socklen_t* ACCEPT_THIRD_T;
#else
    #if defined _XOPEN_SOURCE_EXTENDED
        typedef socklen_t* ACCEPT_THIRD_T;
    #else
        typedef int*       ACCEPT_THIRD_T;
    #endif
#endif


#if defined(DEBUG_PK_CB) || defined(TEST_PK_PRIVKEY) || defined(TEST_PK_PSK)
    #define WOLFSSL_PKMSG(...) printf(__VA_ARGS__)
#else
    #define WOLFSSL_PKMSG(...) WC_DO_NOTHING
#endif


#ifndef MY_EX_USAGE
#define MY_EX_USAGE 2
#endif

#ifndef EXIT_FAILURE
#define EXIT_FAILURE 1
#endif

#if defined(WOLFSSL_FORCE_MALLOC_FAIL_TEST) || defined(WOLFSSL_ZEPHYR)
    #ifndef EXIT_SUCCESS
        #define EXIT_SUCCESS   0
    #endif
    #define XEXIT(rc)   return rc
    #define XEXIT_T(rc) return (THREAD_RETURN)rc
#else
    #define XEXIT(rc)   exit((int)(rc))
    #define XEXIT_T(rc) exit((int)(rc))
#endif

static WC_INLINE
#if defined(WOLFSSL_FORCE_MALLOC_FAIL_TEST) || defined(WOLFSSL_ZEPHYR)
THREAD_RETURN
#else
WC_NORETURN void
#endif
err_sys(const char* msg)
{
#if !defined(__GNUC__)
    /* scan-build (which pretends to be gnuc) can get confused and think the
     * msg pointer can be null even when hardcoded and then it won't exit,
     * making null pointer checks above the err_sys() call useless.
     * We could just always exit() but some compilers will complain about no
     * possible return, with gcc we know the attribute to handle that with
     * WC_NORETURN. */
    if (msg)
#endif
    {
        fprintf(stderr, "wolfSSL error: %s\n", msg);
    }
    XEXIT_T(EXIT_FAILURE);
}

static WC_INLINE
#if defined(WOLFSSL_FORCE_MALLOC_FAIL_TEST) || defined(WOLFSSL_ZEPHYR)
THREAD_RETURN
#else
WC_NORETURN void
#endif
err_sys_with_errno(const char* msg)
{
#if !defined(__GNUC__)
    /* scan-build (which pretends to be gnuc) can get confused and think the
     * msg pointer can be null even when hardcoded and then it won't exit,
     * making null pointer checks above the err_sys() call useless.
     * We could just always exit() but some compilers will complain about no
     * possible return, with gcc we know the attribute to handle that with
     * WC_NORETURN. */
    if (msg)
#endif
    {
#if defined(HAVE_STRING_H) && defined(HAVE_ERRNO_H)
        fprintf(stderr, "wolfSSL error: %s: %s\n", msg, strerror(errno));
#else
        fprintf(stderr, "wolfSSL error: %s\n", msg);
#endif
    }
    XEXIT_T(EXIT_FAILURE);
}

#define LIBCALL_CHECK_RET(...) do {                                  \
        int _libcall_ret = (__VA_ARGS__);                            \
        if (_libcall_ret < 0) {                                      \
            fprintf(stderr, "%s L%d error %d for \"%s\"\n",          \
                    __FILE__, __LINE__, errno, #__VA_ARGS__);        \
            err_sys("library/system call failed");                   \
        }                                                            \
    } while(0)

#define THREAD_CHECK_RET(...) do {                                   \
        int _thread_ret = (__VA_ARGS__);                             \
        if (_thread_ret != 0) {                                      \
            errno = _thread_ret;                                     \
            fprintf(stderr, "%s L%d error %d for \"%s\"\n",          \
                    __FILE__, __LINE__, _thread_ret, #__VA_ARGS__);  \
            err_sys("thread call failed");                           \
        }                                                            \
    } while(0)


#ifndef WOLFSSL_NO_TLS12
#define SERVER_DEFAULT_VERSION 3
#else
#define SERVER_DEFAULT_VERSION 4
#endif
#define SERVER_DTLS_DEFAULT_VERSION (-2)
#define SERVER_INVALID_VERSION (-99)
#define SERVER_DOWNGRADE_VERSION (-98)
#ifndef WOLFSSL_NO_TLS12
#define CLIENT_DEFAULT_VERSION 3
#else
#define CLIENT_DEFAULT_VERSION 4
#endif
#define CLIENT_DTLS_DEFAULT_VERSION (-2)
#define CLIENT_INVALID_VERSION (-99)
#define CLIENT_DOWNGRADE_VERSION (-98)
#define EITHER_DOWNGRADE_VERSION (-97)
#if !defined(NO_FILESYSTEM) && defined(WOLFSSL_MAX_STRENGTH)
    #define DEFAULT_MIN_DHKEY_BITS 2048
    #define DEFAULT_MAX_DHKEY_BITS 3072
#else
    #define DEFAULT_MIN_DHKEY_BITS 1024
    #define DEFAULT_MAX_DHKEY_BITS 2048
#endif
#if !defined(NO_FILESYSTEM) && defined(WOLFSSL_MAX_STRENGTH)
    #define DEFAULT_MIN_RSAKEY_BITS 2048
#else
    #ifndef DEFAULT_MIN_RSAKEY_BITS
    #define DEFAULT_MIN_RSAKEY_BITS 1024
    #endif
#endif
#if !defined(NO_FILESYSTEM) && defined(WOLFSSL_MAX_STRENGTH)
    #define DEFAULT_MIN_ECCKEY_BITS 256
#else
    #ifndef DEFAULT_MIN_ECCKEY_BITS
    #define DEFAULT_MIN_ECCKEY_BITS 224
    #endif
#endif

#ifndef DEFAULT_TIMEOUT_SEC
#define DEFAULT_TIMEOUT_SEC 2
#endif

/* all certs relative to wolfSSL home directory now */
#if defined(WOLFSSL_NO_CURRDIR) || defined(WOLFSSL_MDK_SHELL)
#define caCertFile        "certs/ca-cert.pem"
#define eccCertFile       "certs/server-ecc.pem"
#define eccKeyFile        "certs/ecc-key.pem"
#define eccKeyPubFile     "certs/ecc-keyPub.pem"
#define eccRsaCertFile    "certs/server-ecc-rsa.pem"
#define svrCertFile       "certs/server-cert.pem"
#define svrKeyFile        "certs/server-key.pem"
#define svrKeyPubFile     "certs/server-keyPub.pem"
#define cliCertFile       "certs/client-cert.pem"
#define cliCertDerFile    "certs/client-cert.der"
#define cliCertFileExt    "certs/client-cert-ext.pem"
#define cliCertDerFileExt "certs/client-cert-ext.der"
#define cliKeyFile        "certs/client-key.pem"
#define cliKeyPubFile     "certs/client-keyPub.pem"
#define dhParamFile       "certs/dh2048.pem"
#define cliEccKeyFile     "certs/ecc-client-key.pem"
#define cliEccKeyPubFile  "certs/ecc-client-keyPub.pem"
#define cliEccCertFile    "certs/client-ecc-cert.pem"
#define caEccCertFile     "certs/ca-ecc-cert.pem"
#define crlPemDir         "certs/crl"
#define edCertFile        "certs/ed25519/server-ed25519-cert.pem"
#define edKeyFile         "certs/ed25519/server-ed25519-priv.pem"
#define edKeyPubFile      "certs/ed25519/server-ed25519-key.pem"
#define cliEdCertFile     "certs/ed25519/client-ed25519.pem"
#define cliEdKeyFile      "certs/ed25519/client-ed25519-priv.pem"
#define cliEdKeyPubFile   "certs/ed25519/client-ed25519-key.pem"
#define caEdCertFile      "certs/ed25519/ca-ed25519.pem"
#define ed448CertFile     "certs/ed448/server-ed448-cert.pem"
#define ed448KeyFile      "certs/ed448/server-ed448-priv.pem"
#define cliEd448CertFile  "certs/ed448/client-ed448.pem"
#define cliEd448KeyFile   "certs/ed448/client-ed448-priv.pem"
#define caEd448CertFile   "certs/ed448/ca-ed448.pem"
#define caCertFolder      "certs/"
#ifdef HAVE_WNR
    /* Whitewood netRandom default config file */
    #define wnrConfig     "wnr-example.conf"
#endif
#elif defined(NETOS) && defined(HAVE_FIPS)
    /* These defines specify the file system volume and root directory used by
     * the FTP server used in the only supported NETOS FIPS solution (at this
     * time), these can be tailored in the event a future FIPS solution is added
     * for an alternate NETOS use-case */
    #define FS_VOLUME1     "FLASH0"
    #define FS_VOLUME1_DIR FS_VOLUME1 "/"
    #define caCertFile     FS_VOLUME1_DIR "certs/ca-cert.pem"
    #define eccCertFile    FS_VOLUME1_DIR "certs/server-ecc.pem"
    #define eccKeyFile     FS_VOLUME1_DIR "certs/ecc-key.pem"
    #define svrCertFile    FS_VOLUME1_DIR "certs/server-cert.pem"
    #define svrKeyFile     FS_VOLUME1_DIR "certs/server-key.pem"
    #define cliCertFile    FS_VOLUME1_DIR "certs/client-cert.pem"
    #define cliKeyFile     FS_VOLUME1_DIR "certs/client-key.pem"
    #define ntruCertFile   FS_VOLUME1_DIR "certs/ntru-cert.pem"
    #define ntruKeyFile    FS_VOLUME1_DIR "certs/ntru-key.raw"
    #define dhParamFile    FS_VOLUME1_DIR "certs/dh2048.pem"
    #define cliEccKeyFile  FS_VOLUME1_DIR "certs/ecc-client-key.pem"
    #define cliEccCertFile FS_VOLUME1_DIR "certs/client-ecc-cert.pem"
    #define caEccCertFile  FS_VOLUME1_DIR "certs/ca-ecc-cert/pem"
    #define crlPemDir      FS_VOLUME1_DIR "certs/crl"
    #ifdef HAVE_WNR
        /* Whitewood netRandom default config file */
        #define wnrConfig  "wnr-example.conf"
    #endif
#else
#define caCertFile        "./certs/ca-cert.pem"
#define eccCertFile       "./certs/server-ecc.pem"
#define eccKeyFile        "./certs/ecc-key.pem"
#define eccKeyPubFile     "./certs/ecc-keyPub.pem"
#define eccRsaCertFile    "./certs/server-ecc-rsa.pem"
#define svrCertFile       "./certs/server-cert.pem"
#define svrKeyFile        "./certs/server-key.pem"
#define svrKeyPubFile     "./certs/server-keyPub.pem"
#define cliCertFile       "./certs/client-cert.pem"
#define cliCertDerFile    "./certs/client-cert.der"
#define cliCertFileExt    "./certs/client-cert-ext.pem"
#define cliCertDerFileExt "./certs/client-cert-ext.der"
#define cliKeyFile        "./certs/client-key.pem"
#define cliKeyPubFile     "./certs/client-keyPub.pem"
#define dhParamFile       "./certs/dh2048.pem"
#define cliEccKeyFile     "./certs/ecc-client-key.pem"
#define cliEccKeyPubFile  "./certs/ecc-client-keyPub.pem"
#define cliEccCertFile    "./certs/client-ecc-cert.pem"
#define caEccCertFile     "./certs/ca-ecc-cert.pem"
#define crlPemDir         "./certs/crl"
#define edCertFile        "./certs/ed25519/server-ed25519-cert.pem"
#define edKeyFile         "./certs/ed25519/server-ed25519-priv.pem"
#define edKeyPubFile      "./certs/ed25519/server-ed25519-key.pem"
#define cliEdCertFile     "./certs/ed25519/client-ed25519.pem"
#define cliEdKeyFile      "./certs/ed25519/client-ed25519-priv.pem"
#define cliEdKeyPubFile   "./certs/ed25519/client-ed25519-key.pem"
#define caEdCertFile      "./certs/ed25519/ca-ed25519.pem"
#define ed448CertFile     "./certs/ed448/server-ed448-cert.pem"
#define ed448KeyFile      "./certs/ed448/server-ed448-priv.pem"
#define cliEd448CertFile  "./certs/ed448/client-ed448.pem"
#define cliEd448KeyFile   "./certs/ed448/client-ed448-priv.pem"
#define caEd448CertFile   "./certs/ed448/ca-ed448.pem"
#define caCertFolder      "./certs/"
#ifdef HAVE_WNR
    /* Whitewood netRandom default config file */
    #define wnrConfig     "./wnr-example.conf"
#endif
#endif


#ifdef TEST_IPV6
    typedef struct sockaddr_in6 SOCKADDR_IN_T;
    #define AF_INET_V    AF_INET6
#else
    typedef struct sockaddr_in  SOCKADDR_IN_T;
    #define AF_INET_V    AF_INET
#endif

typedef struct tcp_ready {
    word16 ready;              /* predicate */
    word16 port;
    char*  srfName;     /* server ready file name */
#ifndef SINGLE_THREADED
#ifdef WOLFSSL_COND
    wolfSSL_Mutex mutex;
    COND_TYPE     cond;
#else /* No signaling available, rely only on the mutex */
    wolfSSL_Mutex mutex;
#endif
#endif
} tcp_ready;

static WC_INLINE void InitTcpReady(tcp_ready* ready)
{
    ready->ready = 0;
    ready->port = 0;
    ready->srfName = NULL;

#ifndef SINGLE_THREADED
    THREAD_CHECK_RET(wc_InitMutex(&ready->mutex));
    #ifdef WOLFSSL_COND
    THREAD_CHECK_RET(wolfSSL_CondInit(&ready->cond));
    #endif
#endif
}

#ifdef NETOS
    struct hostent* gethostbyname(const char* name);
#endif

static WC_INLINE void FreeTcpReady(tcp_ready* ready)
{
#ifndef SINGLE_THREADED
    THREAD_CHECK_RET(wc_FreeMutex(&ready->mutex));
#ifdef WOLFSSL_COND
    THREAD_CHECK_RET(wolfSSL_CondFree(&ready->cond));
#endif
#else
    (void)ready;
#endif
}

typedef WOLFSSL_METHOD* (*method_provider)(void);
typedef void (*ctx_callback)(WOLFSSL_CTX* ctx);
typedef void (*ssl_callback)(WOLFSSL* ssl);

typedef struct callback_functions {
    method_provider method;
    ctx_callback ctx_ready;
    ssl_callback ssl_ready;
    ssl_callback on_result;
    ssl_callback on_cleanup;
    WOLFSSL_CTX* ctx;
    const char* caPemFile;
    const char* certPemFile;
    const char* keyPemFile;
    const char* crlPemFile;
#ifdef WOLFSSL_STATIC_MEMORY
    byte*               mem;
    word32              memSz;
    wolfSSL_method_func method_ex;
#endif
    int devId;
    int return_code;
    int last_err;
    unsigned char isSharedCtx:1;
    unsigned char loadToSSL:1;
    unsigned char ticNoInit:1;
    unsigned char doUdp:1;
} callback_functions;

#if defined(WOLFSSL_SRTP) && defined(WOLFSSL_COND)
typedef struct srtp_test_helper {
    wolfSSL_Mutex mutex;
    COND_TYPE     cond;
    uint8_t* server_srtp_ekm;
    size_t   server_srtp_ekm_size;
} srtp_test_helper;
#endif /* WOLFSSL_SRTP WOLFSSL_COND */

typedef struct func_args {
    int    argc;
    char** argv;
    int    return_code;
    tcp_ready* signal;
    callback_functions *callbacks;
#if defined(WOLFSSL_SRTP) && defined(WOLFSSL_COND)
    srtp_test_helper* srtp_helper;
#endif
} func_args;

#ifdef NETOS
    int dc_log_printf(char* format, ...);
    #undef printf
    #define printf dc_log_printf
#endif

void wait_tcp_ready(func_args* args);

#ifndef SINGLE_THREADED
void start_thread(THREAD_CB fun, func_args* args, THREAD_TYPE* thread);
void join_thread(THREAD_TYPE thread);
#endif

typedef int (*cbType)(WOLFSSL_CTX *ctx, WOLFSSL *ssl);

void test_wolfSSL_client_server_nofail_ex(callback_functions* client_cb,
    callback_functions* server_cb, cbType client_on_handshake);
void test_wolfSSL_client_server_nofail(callback_functions* client_cb,
                                       callback_functions* server_cb);

/* Return
 *   tmpDir on success
 *   NULL on failure */
char* create_tmp_dir(char* tmpDir, int len);
/* Remaining functions return
 * 0 on success
 * -1 on failure */
int rem_dir(const char* dirName);
int rem_file(const char* fileName);
int copy_file(const char* in, const char* out);

#if defined(__MACH__) || defined(__FreeBSD__)
    int link_file(const char* in, const char* out);
    #define STAGE_FILE(x,y) link_file((x),(y))
#else
    #define STAGE_FILE(x,y) copy_file((x),(y))
#endif

void signal_ready(tcp_ready* ready);

/* wolfSSL */
#ifndef TEST_IPV6
    static const char* const wolfSSLIP   = "127.0.0.1";
#else
    static const char* const wolfSSLIP   = "::1";
#endif
static const word16      wolfSSLPort = 11111;


extern int   myoptind;
extern char* myoptarg;

#if defined(WOLFSSL_SRTP) && defined(WOLFSSL_COND)

static WC_INLINE void srtp_helper_init(srtp_test_helper *srtp)
{
    srtp->server_srtp_ekm_size = 0;
    srtp->server_srtp_ekm = NULL;

    THREAD_CHECK_RET(wc_InitMutex(&srtp->mutex));
    THREAD_CHECK_RET(wolfSSL_CondInit(&srtp->cond));
}

/**
 * strp_helper_get_ekm() - get exported key material of other peer
 * @srtp: srtp_test_helper struct shared with other peer [in]
 * @ekm: where to store the shared buffer pointer [out]
 * @size: size of the shared buffer returned [out]
 *
 * This function wait that the other peer calls strp_helper_set_ekm() and then
 * store the buffer pointer/size in @ekm and @size.
 */
static WC_INLINE void srtp_helper_get_ekm(srtp_test_helper *srtp,
                                          uint8_t **ekm, size_t *size)
{
    THREAD_CHECK_RET(wolfSSL_CondStart(&srtp->cond));
    if (srtp->server_srtp_ekm == NULL) {
        THREAD_CHECK_RET(wolfSSL_CondWait(&srtp->cond));
    }
    *ekm = srtp->server_srtp_ekm;
    *size = srtp->server_srtp_ekm_size;

    /* reset */
    srtp->server_srtp_ekm = NULL;
    srtp->server_srtp_ekm_size = 0;
    THREAD_CHECK_RET(wolfSSL_CondEnd(&srtp->cond));
}

/**
 * strp_helper_set_ekm() - set exported key material of other peer
 * @srtp: srtp_test_helper struct shared with other peer [in]
 * @ekm: pointer to the shared buffer [in]
 * @size: size of the shared buffer [in]
 *
 * This function set the @ekm and wakes up a peer waiting in
 * srtp_helper_get_ekm().
 *
 * used in client_srtp_test()/server_srtp_test()
 */
static WC_INLINE void srtp_helper_set_ekm(srtp_test_helper *srtp,
                                          uint8_t *ekm, size_t size)
{
    THREAD_CHECK_RET(wolfSSL_CondStart(&srtp->cond));
    srtp->server_srtp_ekm_size = size;
    srtp->server_srtp_ekm = ekm;
    THREAD_CHECK_RET(wolfSSL_CondSignal(&srtp->cond));
    THREAD_CHECK_RET(wolfSSL_CondEnd(&srtp->cond));
}

static WC_INLINE void srtp_helper_free(srtp_test_helper *srtp)
{
    THREAD_CHECK_RET(wc_FreeMutex(&srtp->mutex));
    THREAD_CHECK_RET(wolfSSL_CondFree(&srtp->cond));
}

#endif /* WOLFSSL_SRTP && WOLFSSL_COND */


/**
 *
 * @param argc Number of argv strings
 * @param argv Array of string arguments
 * @param optstring String containing the supported alphanumeric arguments.
 *                  A ':' following a character means that it requires a
 *                  value in myoptarg to be set. A ';' means that the
 *                  myoptarg is optional. myoptarg is set to "" if not
 *                  present.
 * @return Option letter in argument
 */
static WC_INLINE int mygetopt(int argc, char** argv, const char* optstring)
{
    static char* next = NULL;

    char  c;
    char* cp;

    /* Added sanity check because scan-build complains argv[myoptind] access
     * results in a null pointer dereference. */
    if (argv == NULL)  {
        myoptarg = NULL;
        return -1;
    }

    if (myoptind == 0)
        next = NULL;   /* we're starting new/over */

    if (next == NULL || *next == '\0') {
        if (myoptind == 0)
            myoptind++;

        if (myoptind >= argc || argv[myoptind] == NULL ||
                argv[myoptind][0] != '-' || argv[myoptind][1] == '\0') {
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

    if (cp == NULL || c == ':' || c == ';')
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
    else if (*cp == ';') {
        myoptarg = (char*)"";
        if (*next != '\0') {
            myoptarg = next;
            next     = NULL;
        }
        else if (myoptind < argc) {
            /* Check if next argument is not a parameter argument */
            if (argv[myoptind] && argv[myoptind][0] != '-') {
                myoptarg = argv[myoptind];
                myoptind++;
            }
        }
    }

    return c;
}

struct mygetopt_long_config {
    const char *name;
    int takes_arg; /* 0=no arg, 1=required arg, 2=optional arg */
    int value;
};

/**
 *
 * @param argc Number of argv strings
 * @param argv Array of string arguments
 * @param optstring String containing the supported alphanumeric arguments.
 *                  A ':' following a character means that it requires a
 *                  value in myoptarg to be set. A ';' means that the
 *                  myoptarg is optional. myoptarg is set to "" if not
 *                  present.
 * @return Option letter in argument
 */
static WC_INLINE int mygetopt_long(int argc, char** argv, const char* optstring,
    const struct mygetopt_long_config *longopts, int *longindex)
{
    static char* next = NULL;

    int  c;
    char* cp;

    /* Added sanity check because scan-build complains argv[myoptind] access
     * results in a null pointer dereference. */
    if (argv == NULL)  {
        myoptarg = NULL;
        return -1;
    }

    if (myoptind == 0)
        next = NULL;   /* we're starting new/over */

    if (next == NULL || *next == '\0') {
        if (myoptind == 0)
            myoptind++;

        if (myoptind >= argc || argv[myoptind] == NULL ||
                argv[myoptind][0] != '-' || argv[myoptind][1] == '\0') {
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

        if (strncmp(argv[myoptind], "--", 2) == 0) {
            const struct mygetopt_long_config *i;
            c = -1;
            myoptarg = NULL;
            for (i = longopts; i->name; ++i) {
                if (! strcmp(argv[myoptind] + 2, i->name)) {
                    c = i->value;
                    myoptind++;
                    if (longindex)
                        *longindex = (int)((size_t)(i - longopts) / sizeof i[0]);
                    if (i->takes_arg) {
                        if (myoptind < argc) {
                            if (i->takes_arg == 1 || argv[myoptind][0] != '-') {
                                myoptarg = argv[myoptind];
                                myoptind++;
                            }
                        } else if (i->takes_arg != 2) {
                            return -1;
                        }
                    }
                    break;
                }
            }

            return c;
        }

        next = argv[myoptind];
        next++;                  /* skip - */
        myoptind++;
    }

    c  = (int)(unsigned char)*next++;
    /* The C++ strchr can return a different value */
    cp = (char*)strchr(optstring, c);

    if (cp == NULL || c == ':' || c == ';')
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
    else if (*cp == ';') {
        myoptarg = (char*)"";
        if (*next != '\0') {
            myoptarg = next;
            next     = NULL;
        }
        else if (myoptind < argc) {
            /* Check if next argument is not a parameter argument */
            if (argv[myoptind] && argv[myoptind][0] != '-') {
                myoptarg = argv[myoptind];
                myoptind++;
            }
        }
    }

    return c;
}


#ifdef WOLFSSL_ENCRYPTED_KEYS

static WC_INLINE int PasswordCallBack(char* passwd, int sz, int rw, void* userdata)
{
    (void)rw;
    (void)userdata;
    if (userdata != NULL) {
        strncpy(passwd, (char*)userdata, (size_t) sz);
        return (int)XSTRLEN((char*)userdata);
    }
    else {
        strncpy(passwd, "yassl123", (size_t) sz);
        return 8;
    }
}

#endif

static const char* client_showpeer_msg[][9] = {
    /* English */
    {
        "SSL version is",
        "SSL cipher suite is",
        "SSL signature algorithm is",
        "SSL curve name is",
        "SSL DH size is",
        "SSL reused session",
        "Alternate cert chain used",
        "peer's cert info:",
        NULL
    },
#ifndef NO_MULTIBYTE_PRINT
    /* Japanese */
    {
        "SSL バージョンは",
        "SSL 暗号スイートは",
        "SSL signature algorithm is",
        "SSL 曲線名は",
        "SSL DH サイズは",
        "SSL 再利用セッション",
        "代替証明チェーンを使用",
        "相手方証明書情報",
        NULL
    },
#endif
};

#if defined(KEEP_PEER_CERT) || defined(KEEP_OUR_CERT) || defined(SESSION_CERTS)
static const char* client_showx509_msg[][5] = {
    /* English */
    {
        "issuer",
        "subject",
        "altname",
        "serial number",
        NULL
    },
#ifndef NO_MULTIBYTE_PRINT
    /* Japanese */
    {
        "発行者",
        "サブジェクト",
        "代替名",
        "シリアル番号",
        NULL
    },
#endif
};

/* lng_index is to specify the language for displaying message.              */
/* 0:English, 1:Japanese                                                     */
static WC_INLINE void ShowX509Ex(WOLFSSL_X509* x509, const char* hdr,
                                                                 int lng_index)
{
    char* altName;
    char* issuer;
    char* subject;
    byte  serial[32];
    int   ret;
    int   sz = sizeof(serial);
    const char** words = client_showx509_msg[lng_index];

    if (x509 == NULL) {
        fprintf(stderr, "%s No Cert\n", hdr);
        return;
    }

    issuer  = wolfSSL_X509_NAME_oneline(
                                      wolfSSL_X509_get_issuer_name(x509), 0, 0);
    subject = wolfSSL_X509_NAME_oneline(
                                     wolfSSL_X509_get_subject_name(x509), 0, 0);

    printf("%s\n %s : %s\n %s: %s\n", hdr, words[0], issuer, words[1], subject);

    while ( (altName = wolfSSL_X509_get_next_altname(x509)) != NULL)
        printf(" %s = %s\n", words[2], altName);

    ret = wolfSSL_X509_get_serial_number(x509, serial, &sz);
    if (ret == WOLFSSL_SUCCESS) {
        int  i;
        int  strLen;
        char serialMsg[80];

        /* testsuite has multiple threads writing to stdout, get output
         * message ready to write once */
        strLen = XSNPRINTF(serialMsg, sizeof(serialMsg), " %s", words[3]);
        for (i = 0; i < sz; i++)
            strLen = XSNPRINTF(serialMsg + strLen,
                sizeof(serialMsg) - (size_t)strLen, ":%02x ", serial[i]);
        printf("%s\n", serialMsg);
    }

    XFREE(subject, 0, DYNAMIC_TYPE_OPENSSL);
    XFREE(issuer,  0, DYNAMIC_TYPE_OPENSSL);

#if defined(SHOW_CERTS) && defined(OPENSSL_EXTRA)
    {
        WOLFSSL_BIO* bio;
        char buf[WC_ASN_NAME_MAX];
        int  textSz;

        /* print out domain component if certificate has it */
        textSz = wolfSSL_X509_NAME_get_text_by_NID(
                wolfSSL_X509_get_subject_name(x509), NID_domainComponent,
                buf, sizeof(buf));
        if (textSz > 0) {
            printf("Domain Component = %s\n", buf);
        }

        bio = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
        if (bio != NULL) {
            wolfSSL_BIO_set_fp(bio, stdout, BIO_NOCLOSE);
            wolfSSL_X509_print(bio, x509);
            wolfSSL_BIO_free(bio);
        }
    }
#endif /* SHOW_CERTS && OPENSSL_EXTRA */
}
/* original ShowX509 to maintain compatibility */
static WC_INLINE void ShowX509(WOLFSSL_X509* x509, const char* hdr)
{
    ShowX509Ex(x509, hdr, 0);
}

#endif /* KEEP_PEER_CERT || KEEP_OUR_CERT || SESSION_CERTS */

#if defined(SHOW_CERTS) && defined(SESSION_CERTS) && \
    (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL))
static WC_INLINE void ShowX509Chain(WOLFSSL_X509_CHAIN* chain, int count,
    const char* hdr)
{
    int i;
    int length;
    unsigned char buffer[3072];
    WOLFSSL_X509* chainX509;

    for (i = 0; i < count; i++) {
        wolfSSL_get_chain_cert_pem(chain, i, buffer, sizeof(buffer), &length);
        buffer[length] = 0;
        printf("\n%s: %d has length %d data = \n%s\n", hdr, i, length, buffer);

        chainX509 = wolfSSL_get_chain_X509(chain, i);
        if (chainX509)
            ShowX509(chainX509, hdr);
        else
            fprintf(stderr, "get_chain_X509 failed\n");
        wolfSSL_FreeX509(chainX509);
    }
}
#endif /* SHOW_CERTS && SESSION_CERTS */

/* lng_index is to specify the language for displaying message.              */
/* 0:English, 1:Japanese                                                     */
static WC_INLINE void showPeerEx(WOLFSSL* ssl, int lng_index)
{
    WOLFSSL_CIPHER* cipher;
    const char** words = client_showpeer_msg[lng_index];

#if defined(HAVE_ECC) || defined(HAVE_CURVE25519) || defined(HAVE_CURVE448) || \
                                                                 !defined(NO_DH)
    const char *name;
#endif
#ifndef NO_DH
    int bits;
#endif
#if defined(OPENSSL_EXTRA) && !defined(WOLFCRYPT_ONLY)
    int nid;
#endif
#ifdef KEEP_PEER_CERT
    WOLFSSL_X509* peer = wolfSSL_get_peer_certificate(ssl);
    if (peer)
        ShowX509Ex(peer, words[6], lng_index);
    else
        fprintf(stderr, "peer has no cert!\n");
    wolfSSL_FreeX509(peer);
#endif
#if defined(SHOW_CERTS) && defined(KEEP_OUR_CERT) && \
    (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL))
    ShowX509(wolfSSL_get_certificate(ssl), "our cert info:");
    printf("Peer verify result = %lu\n", wolfSSL_get_verify_result(ssl));
#endif /* SHOW_CERTS && KEEP_OUR_CERT */
    printf("%s %s\n", words[0], wolfSSL_get_version(ssl));

    cipher = wolfSSL_get_current_cipher(ssl);
    printf("%s %s\n", words[1], wolfSSL_CIPHER_get_name(cipher));
#if defined(OPENSSL_EXTRA) && !defined(WOLFCRYPT_ONLY)
    if (wolfSSL_get_signature_nid(ssl, &nid) == WOLFSSL_SUCCESS) {
        printf("%s %s\n", words[2], OBJ_nid2sn(nid));
    }
#endif
#if defined(HAVE_ECC) || defined(HAVE_CURVE25519) || defined(HAVE_CURVE448) || \
                                                                 !defined(NO_DH)
    if ((name = wolfSSL_get_curve_name(ssl)) != NULL)
        printf("%s %s\n", words[3], name);
#endif
#ifndef NO_DH
    else if ((bits = wolfSSL_GetDhKey_Sz(ssl)) > 0)
        printf("%s %d bits\n", words[4], bits);
#endif
    if (wolfSSL_session_reused(ssl))
        printf("%s\n", words[5]);
#ifdef WOLFSSL_ALT_CERT_CHAINS
    if (wolfSSL_is_peer_alt_cert_chain(ssl))
        printf("%s\n", words[6]);
#endif

#if defined(SHOW_CERTS) && defined(SESSION_CERTS) && \
    (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL))
    {
        WOLFSSL_X509_CHAIN* chain;

        chain = wolfSSL_get_peer_chain(ssl);
        ShowX509Chain(chain, wolfSSL_get_chain_count(chain), "session cert");

    #ifdef WOLFSSL_ALT_CERT_CHAINS
        if (wolfSSL_is_peer_alt_cert_chain(ssl)) {
            chain = wolfSSL_get_peer_alt_chain(ssl);
            ShowX509Chain(chain, wolfSSL_get_chain_count(chain), "alt cert");
        }
    #endif
    }
#endif /* SHOW_CERTS && SESSION_CERTS */
  (void)ssl;
}
/* original showPeer to maintain compatibility */
static WC_INLINE void showPeer(WOLFSSL* ssl)
{
    showPeerEx(ssl, 0);
}

static WC_INLINE void build_addr(SOCKADDR_IN_T* addr, const char* peer,
                              word16 port, int udp, int sctp)
{
    int useLookup = 0;
    (void)useLookup;
    (void)udp;
    (void)sctp;

    if (addr == NULL) {
        err_sys("invalid argument to build_addr, addr is NULL");
        return;
    }

    XMEMSET(addr, 0, sizeof(SOCKADDR_IN_T));

#ifndef TEST_IPV6
    /* peer could be in human readable form */
    if ( ((size_t)peer != INADDR_ANY) && isalpha((unsigned char)peer[0])) {
    #ifdef WOLFSSL_USE_POPEN_HOST
        char host_ipaddr[4] = { 127, 0, 0, 1 };
        int found = 1;

        if ((XSTRCMP(peer, "localhost") != 0) &&
            (XSTRCMP(peer, "127.0.0.1") != 0)) {
            FILE* fp;
            char cmd[100];

            XSTRNCPY(cmd, "host ", 6);
            XSTRNCAT(cmd, peer, 99 - XSTRLEN(cmd));
            found = 0;
            fp = popen(cmd, "r");
            if (fp != NULL) {
                char host_out[100];
                while (fgets(host_out, sizeof(host_out), fp) != NULL) {
                    int i;
                    int j = 0;
                    for (j = 0; host_out[j] != '\0'; j++) {
                        if ((host_out[j] >= '0') && (host_out[j] <= '9')) {
                            break;
                        }
                    }
                    found = (host_out[j] >= '0') && (host_out[j] <= '9');
                    if (!found) {
                        continue;
                    }

                    for (i = 0; i < 4; i++) {
                        host_ipaddr[i] = atoi(host_out + j);
                        while ((host_out[j] >= '0') && (host_out[j] <= '9')) {
                            j++;
                        }
                        if (host_out[j] == '.') {
                            j++;
                            found &= (i != 3);
                        }
                        else {
                            found &= (i == 3);
                            break;
                        }
                    }
                    if (found) {
                        break;
                    }
                }
                pclose(fp);
            }
        }
        if (found) {
            XMEMCPY(&addr->sin_addr.s_addr, host_ipaddr, sizeof(host_ipaddr));
            useLookup = 1;
        }
    #elif !defined(WOLFSSL_USE_GETADDRINFO)
        #if defined(WOLFSSL_MDK_ARM) || defined(WOLFSSL_KEIL_TCP_NET)
            int err;
            struct hostent* entry = gethostbyname(peer, &err);
        #elif defined(WOLFSSL_TIRTOS)
            struct hostent* entry = (struct hostent*)DNSGetHostByName(peer);
        #elif defined(WOLFSSL_VXWORKS)
            struct hostent* entry = (struct hostent*)hostGetByName((char*)peer);
        #else
            struct hostent* entry = gethostbyname(peer);
        #endif

        if (entry) {
            XMEMCPY(&addr->sin_addr.s_addr, entry->h_addr_list[0],
                   (size_t) entry->h_length);
            useLookup = 1;
        }
    #else
        struct zsock_addrinfo hints, *addrInfo;
        char portStr[6];
        XSNPRINTF(portStr, sizeof(portStr), "%d", port);
        XMEMSET(&hints, 0, sizeof(hints));
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
    addr->sin_port = XHTONS(port);
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
        #if defined(HAVE_GETADDRINFO)
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

            (void)SNPRINTF(strPort, sizeof(strPort), "%d", port);
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


static WC_INLINE void tcp_socket(SOCKET_T* sockfd, int udp, int sctp)
{
    (void)sctp;

    if (udp)
        *sockfd = socket(AF_INET_V, SOCK_DGRAM, IPPROTO_UDP);
#ifdef WOLFSSL_SCTP
    else if (sctp)
        *sockfd = socket(AF_INET_V, SOCK_STREAM, IPPROTO_SCTP);
#endif
    else
        *sockfd = socket(AF_INET_V, SOCK_STREAM, IPPROTO_TCP);

    if(WOLFSSL_SOCKET_IS_INVALID(*sockfd)) {
        err_sys_with_errno("socket failed\n");
    }

#ifndef USE_WINDOWS_API
#ifdef SO_NOSIGPIPE
    {
        int       on = 1;
        socklen_t len = sizeof(on);
        int       res = setsockopt(*sockfd, SOL_SOCKET, SO_NOSIGPIPE, &on, len);
        if (res < 0)
            err_sys_with_errno("setsockopt SO_NOSIGPIPE failed\n");
    }
#elif defined(WOLFSSL_MDK_ARM) || defined (WOLFSSL_TIRTOS) ||\
                        defined(WOLFSSL_KEIL_TCP_NET) || defined(WOLFSSL_ZEPHYR)
    /* nothing to define */
#elif defined(NETOS)
    /* TODO: signal(SIGPIPE, SIG_IGN); */
#else  /* no S_NOSIGPIPE */
    signal(SIGPIPE, SIG_IGN);
#endif /* S_NOSIGPIPE */

#if defined(TCP_NODELAY)
    if (!udp && !sctp)
    {
        int       on = 1;
        socklen_t len = sizeof(on);
        int       res = setsockopt(*sockfd, IPPROTO_TCP, TCP_NODELAY, &on, len);
        if (res < 0)
            err_sys_with_errno("setsockopt TCP_NODELAY failed\n");
    }
#endif
#endif  /* USE_WINDOWS_API */
}

#if defined(WOLFSSL_WOLFSENTRY_HOOKS) && defined(WOLFSENTRY_H)

#include <wolfsentry/wolfssl_test.h>

#else /* !WOLFSSL_WOLFSENTRY_HOOKS */

static WC_INLINE void tcp_connect(SOCKET_T* sockfd, const char* ip, word16 port,
                               int udp, int sctp, WOLFSSL* ssl)
{
    SOCKADDR_IN_T addr;
    build_addr(&addr, ip, port, udp, sctp);
    if (udp) {
        wolfSSL_dtls_set_peer(ssl, &addr, sizeof(addr));
    }
    tcp_socket(sockfd, udp, sctp);

    if (!udp) {
        if (connect(*sockfd, (const struct sockaddr*)&addr, sizeof(addr)) != 0)
            err_sys_with_errno("tcp connect failed");
    }
}

#endif /* WOLFSSL_WOLFSENTRY_HOOKS */


static WC_INLINE void udp_connect(SOCKET_T* sockfd, const char* ip, word16 port)
{
    SOCKADDR_IN_T addr;
    build_addr(&addr, ip, port, 1, 0);
    if (connect(*sockfd, (const struct sockaddr*)&addr, sizeof(addr)) != 0)
        err_sys_with_errno("tcp connect failed");
}


enum {
    TEST_SELECT_FAIL,
    TEST_TIMEOUT,
    TEST_RECV_READY,
    TEST_SEND_READY,
    TEST_ERROR_READY
};


#if !defined(WOLFSSL_MDK_ARM) && !defined(WOLFSSL_KEIL_TCP_NET) && \
                                 !defined(WOLFSSL_TIRTOS)
static WC_INLINE int tcp_select_ex(SOCKET_T socketfd, int to_sec, int rx)
{
    fd_set fds, errfds;
    fd_set* recvfds = NULL;
    fd_set* sendfds = NULL;
    SOCKET_T nfds = socketfd + 1;
#if !defined(__INTEGRITY)
    struct timeval timeout = {(to_sec > 0) ? to_sec : 0, 0};
#else
    struct timeval timeout;
#endif
    int result;

    FD_ZERO(&fds);
    FD_SET(socketfd, &fds);
    FD_ZERO(&errfds);
    FD_SET(socketfd, &errfds);

    if (rx)
        recvfds = &fds;
    else
        sendfds = &fds;

#if defined(__INTEGRITY)
    timeout.tv_sec = (long long)(to_sec > 0) ? to_sec : 0, 0;
#endif
    result = select(nfds, recvfds, sendfds, &errfds, &timeout);

    if (result == 0)
        return TEST_TIMEOUT;
    else if (result > 0) {
        if (FD_ISSET(socketfd, &fds)) {
            if (rx)
                return TEST_RECV_READY;
            else
                return TEST_SEND_READY;
        }
        else if(FD_ISSET(socketfd, &errfds))
            return TEST_ERROR_READY;
    }

    return TEST_SELECT_FAIL;
}

static WC_INLINE int tcp_select(SOCKET_T socketfd, int to_sec)
{
    return tcp_select_ex(socketfd, to_sec, 1);
}

static WC_INLINE int tcp_select_tx(SOCKET_T socketfd, int to_sec)
{
    return tcp_select_ex(socketfd, to_sec, 0);
}

#elif defined(WOLFSSL_TIRTOS) || defined(WOLFSSL_KEIL_TCP_NET)
static WC_INLINE int tcp_select(SOCKET_T socketfd, int to_sec)
{
    return TEST_RECV_READY;
}
static WC_INLINE int tcp_select_tx(SOCKET_T socketfd, int to_sec)
{
    return TEST_SEND_READY;
}
#endif /* !WOLFSSL_MDK_ARM */


static WC_INLINE void tcp_listen(SOCKET_T* sockfd, word16* port, int useAnyAddr,
                              int udp, int sctp)
{
    SOCKADDR_IN_T addr;

    /* don't use INADDR_ANY by default, firewall may block, make user switch
       on */
    build_addr(&addr, (useAnyAddr ? (const char*)INADDR_ANY : wolfSSLIP),
        *port, udp, sctp);
    tcp_socket(sockfd, udp, sctp);

#if !defined(USE_WINDOWS_API) && !defined(WOLFSSL_MDK_ARM)\
                   && !defined(WOLFSSL_KEIL_TCP_NET) && !defined(WOLFSSL_ZEPHYR)
    {
        int       res, on  = 1;
        socklen_t len = sizeof(on);
        res = setsockopt(*sockfd, SOL_SOCKET, SO_REUSEADDR, &on, len);
        if (res < 0)
            err_sys_with_errno("setsockopt SO_REUSEADDR failed\n");
    }
#ifdef SO_REUSEPORT
    {
        int       res, on  = 1;
        socklen_t len = sizeof(on);
        res = setsockopt(*sockfd, SOL_SOCKET, SO_REUSEPORT, &on, len);
        if (res < 0)
            err_sys_with_errno("setsockopt SO_REUSEPORT failed\n");
    }
#endif
#endif

    if (bind(*sockfd, (const struct sockaddr*)&addr, sizeof(addr)) != 0)
        err_sys_with_errno("tcp bind failed");
    if (!udp) {
        #ifdef WOLFSSL_KEIL_TCP_NET
            #define SOCK_LISTEN_MAX_QUEUE 1
        #else
            #define SOCK_LISTEN_MAX_QUEUE 5
        #endif
        if (listen(*sockfd, SOCK_LISTEN_MAX_QUEUE) != 0)
                err_sys_with_errno("tcp listen failed");
    }
    #if !defined(USE_WINDOWS_API) && !defined(WOLFSSL_TIRTOS) \
                                                     && !defined(WOLFSSL_ZEPHYR)
        if (*port == 0) {
            socklen_t len = sizeof(addr);
            if (getsockname(*sockfd, (struct sockaddr*)&addr, &len) == 0) {
                #ifndef TEST_IPV6
                    *port = XNTOHS(addr.sin_port);
                #else
                    *port = XNTOHS(addr.sin6_port);
                #endif
            }
        }
    #endif
}


#if 0
static WC_INLINE int udp_read_connect(SOCKET_T sockfd)
{
    SOCKADDR_IN_T cliaddr;
    byte          b[1500];
    int           n;
    socklen_t     len = sizeof(cliaddr);

    n = (int)recvfrom(sockfd, (char*)b, sizeof(b), MSG_PEEK,
                      (struct sockaddr*)&cliaddr, &len);
    if (n > 0) {
        if (connect(sockfd, (const struct sockaddr*)&cliaddr,
                    sizeof(cliaddr)) != 0)
            err_sys("udp connect failed");
    }
    else
        err_sys("recvfrom failed");

    return sockfd;
}
#endif

static WC_INLINE void udp_accept(SOCKET_T* sockfd, SOCKET_T* clientfd,
                              int useAnyAddr, word16 port, func_args* args)
{
    SOCKADDR_IN_T addr;

    (void)args;
    build_addr(&addr, (useAnyAddr ? (const char*)INADDR_ANY : wolfSSLIP),
        port, 1, 0);
    tcp_socket(sockfd, 1, 0);


#if !defined(USE_WINDOWS_API) && !defined(WOLFSSL_MDK_ARM) \
                   && !defined(WOLFSSL_KEIL_TCP_NET) && !defined(WOLFSSL_ZEPHYR)
    {
        int       res, on  = 1;
        socklen_t len = sizeof(on);
        res = setsockopt(*sockfd, SOL_SOCKET, SO_REUSEADDR, &on, len);
        if (res < 0)
            err_sys_with_errno("setsockopt SO_REUSEADDR failed\n");
    }
#ifdef SO_REUSEPORT
    {
        int       res, on  = 1;
        socklen_t len = sizeof(on);
        res = setsockopt(*sockfd, SOL_SOCKET, SO_REUSEPORT, &on, len);
        if (res < 0)
            err_sys_with_errno("setsockopt SO_REUSEPORT failed\n");
    }
#endif
#endif

    if (bind(*sockfd, (const struct sockaddr*)&addr, sizeof(addr)) != 0)
        err_sys_with_errno("tcp bind failed");

    #if !defined(USE_WINDOWS_API) && !defined(WOLFSSL_TIRTOS) && \
           !defined(SINGLE_THREADED)
        if (port == 0) {
            socklen_t len = sizeof(addr);
            if (getsockname(*sockfd, (struct sockaddr*)&addr, &len) == 0) {
                #ifndef TEST_IPV6
                    port = XNTOHS(addr.sin_port);
                #else
                    port = XNTOHS(addr.sin6_port);
                #endif
            }
        }
    #else
        (void)port;
    #endif

    if (args != NULL && args->signal != NULL) {
#ifndef SINGLE_THREADED
        tcp_ready* ready = args->signal;
    #ifdef WOLFSSL_COND
        THREAD_CHECK_RET(wolfSSL_CondStart(&ready->cond));
    #endif
        ready->ready = 1;
        ready->port = port;
    #ifdef WOLFSSL_COND
        /* signal ready to accept data */
        THREAD_CHECK_RET(wolfSSL_CondSignal(&ready->cond));
        THREAD_CHECK_RET(wolfSSL_CondEnd(&ready->cond));
    #endif
#endif /* !SINGLE_THREADED */
    }
    else {
        fprintf(stderr, "args or args->signal was NULL. Not setting ready info.");
    }

    *clientfd = *sockfd;
}

static WC_INLINE void tcp_accept(SOCKET_T* sockfd, SOCKET_T* clientfd,
                              func_args* args, word16 port, int useAnyAddr,
                              int udp, int sctp, int ready_file, int do_listen,
                              SOCKADDR_IN_T *client_addr, socklen_t *client_len)
{
    tcp_ready* ready = NULL;

    (void) ready; /* Account for case when "ready" is not used */

    if (udp) {
        udp_accept(sockfd, clientfd, useAnyAddr, port, args);
        return;
    }

    if(do_listen) {
        tcp_listen(sockfd, &port, useAnyAddr, udp, sctp);

#ifndef SINGLE_THREADED
        /* signal ready to tcp_accept */
        if (args)
            ready = args->signal;
        if (ready) {
        #ifdef WOLFSSL_COND
            THREAD_CHECK_RET(wolfSSL_CondStart(&ready->cond));
        #endif
            ready->ready = 1;
            ready->port = port;
        #ifdef WOLFSSL_COND
            THREAD_CHECK_RET(wolfSSL_CondSignal(&ready->cond));
            THREAD_CHECK_RET(wolfSSL_CondEnd(&ready->cond));
        #endif
        }
#endif /* !SINGLE_THREADED */

        if (ready_file) {
        #if !defined(NO_FILESYSTEM) || defined(FORCE_BUFFER_TEST) && \
            !defined(NETOS)
            XFILE srf = (XFILE)NULL;
            if (args)
                ready = args->signal;

            if (ready) {
                srf = XFOPEN(ready->srfName, "w");

                if (srf) {
                    /* let's write port sever is listening on to ready file
                       external monitor can then do ephemeral ports by passing
                       -p 0 to server on supported platforms with -R ready_file
                       client can then wait for existence of ready_file and see
                       which port the server is listening on. */
                    LIBCALL_CHECK_RET(fprintf(srf, "%d\n", (int)port));
                    fclose(srf);
                }
            }
        #endif
        }
    }

    *clientfd = accept(*sockfd, (struct sockaddr*)client_addr,
                      (ACCEPT_THIRD_T)client_len);
    if(WOLFSSL_SOCKET_IS_INVALID(*clientfd)) {
        err_sys_with_errno("tcp accept failed");
    }
}


static WC_INLINE void tcp_set_nonblocking(SOCKET_T* sockfd)
{
    #if defined(USE_WINDOWS_API) || defined(EBSNET)
        unsigned long blocking = 1;
        int ret = ioctlsocket(*sockfd, FIONBIO, &blocking);
        if (ret == SOCKET_ERROR)
            err_sys_with_errno("ioctlsocket failed");
    #elif defined(WOLFSSL_MDK_ARM) || defined(WOLFSSL_KEIL_TCP_NET) \
        || defined (WOLFSSL_TIRTOS)|| defined(WOLFSSL_VXWORKS) \
        || defined(WOLFSSL_ZEPHYR)
         /* non blocking not supported, for now */
    #else
        int flags = fcntl(*sockfd, F_GETFL, 0);
        if (flags < 0)
            err_sys_with_errno("fcntl get failed");
        flags = fcntl(*sockfd, F_SETFL, flags | O_NONBLOCK);
        if (flags < 0)
            err_sys_with_errno("fcntl set failed");
    #endif
}

static WC_INLINE void tcp_set_blocking(SOCKET_T* sockfd)
{
    #ifdef USE_WINDOWS_API
        unsigned long blocking = 0;
        int ret = ioctlsocket(*sockfd, FIONBIO, &blocking);
        if (ret == SOCKET_ERROR)
            err_sys_with_errno("ioctlsocket failed");
    #elif defined(WOLFSSL_MDK_ARM) || defined(WOLFSSL_KEIL_TCP_NET) \
        || defined (WOLFSSL_TIRTOS)|| defined(WOLFSSL_VXWORKS) \
        || defined(WOLFSSL_ZEPHYR)
         /* non blocking not supported, for now */
    #else
        int flags = fcntl(*sockfd, F_GETFL, 0);
        if (flags < 0)
            err_sys_with_errno("fcntl get failed");
        flags = fcntl(*sockfd, F_SETFL, flags & (~O_NONBLOCK));
        if (flags < 0)
            err_sys_with_errno("fcntl set failed");
    #endif
}

#ifndef NO_PSK

/* identity is OpenSSL testing default for openssl s_client, keep same */
static const char* kIdentityStr = "Client_identity";

static WC_INLINE unsigned int my_psk_client_cb(WOLFSSL* ssl, const char* hint,
        char* identity, unsigned int id_max_len, unsigned char* key,
        unsigned int key_max_len)
{
    unsigned int ret;

    (void)ssl;
    (void)hint;
    (void)key_max_len;

    /* see internal.h MAX_PSK_ID_LEN for PSK identity limit */
    XSTRNCPY(identity, kIdentityStr, id_max_len);

    if (wolfSSL_GetVersion(ssl) != WOLFSSL_TLSV1_3 &&
            wolfSSL_GetVersion(ssl) != WOLFSSL_DTLSV1_3) {
        /* test key in hex is 0x1a2b3c4d , in decimal 439,041,101 , we're using
         * unsigned binary */
        key[0] = 0x1a;
        key[1] = 0x2b;
        key[2] = 0x3c;
        key[3] = 0x4d;

        ret = 4;   /* length of key in octets or 0 for error */
    }
    else {
        int i;
        int b = 0x01;

        for (i = 0; i < 32; i++, b += 0x22) {
            if (b >= 0x100)
                b = 0x01;
            key[i] = (unsigned char) b;
        }

        ret = 32;   /* length of key in octets or 0 for error */
    }

#if defined(HAVE_PK_CALLBACKS) && defined(TEST_PK_PSK)
    WOLFSSL_PKMSG("PSK Client using HW (Len %d, Hint %s)\n", ret, hint);
    ret = (unsigned int)USE_HW_PSK;
#endif

    return ret;
}


static WC_INLINE unsigned int my_psk_server_cb(WOLFSSL* ssl, const char* identity,
        unsigned char* key, unsigned int key_max_len)
{
    unsigned int ret;

    (void)ssl;
    (void)key_max_len;

    /* see internal.h MAX_PSK_ID_LEN for PSK identity limit */
    if (XSTRCMP(identity, kIdentityStr) != 0)
        return 0;

    if (wolfSSL_GetVersion(ssl) != WOLFSSL_TLSV1_3 &&
            wolfSSL_GetVersion(ssl) != WOLFSSL_DTLSV1_3) {
        /* test key in hex is 0x1a2b3c4d , in decimal 439,041,101 , we're using
         * unsigned binary */
        key[0] = 0x1a;
        key[1] = 0x2b;
        key[2] = 0x3c;
        key[3] = 0x4d;

        ret = 4;   /* length of key in octets or 0 for error */
    }
    else {
        int i;
        int b = 0x01;

        for (i = 0; i < 32; i++, b += 0x22) {
            if (b >= 0x100)
                b = 0x01;
            key[i] = (unsigned char) b;
        }

        ret = 32;   /* length of key in octets or 0 for error */
    }
#if defined(HAVE_PK_CALLBACKS) && defined(TEST_PK_PSK)
    WOLFSSL_PKMSG("PSK Server using HW (Len %d, Hint %s)\n", ret, identity);
    ret = (unsigned int)USE_HW_PSK;
#endif

    return ret;
}

#ifdef WOLFSSL_TLS13
static WC_INLINE unsigned int my_psk_client_tls13_cb(WOLFSSL* ssl,
        const char* hint, char* identity, unsigned int id_max_len,
        unsigned char* key, unsigned int key_max_len, const char** ciphersuite)
{
    unsigned int ret;
    int i;
    int b = 0x01;
    const char* userCipher = (const char*)wolfSSL_get_psk_callback_ctx(ssl);

    (void)ssl;
    (void)hint;
    (void)key_max_len;

    /* see internal.h MAX_PSK_ID_LEN for PSK identity limit */
    XSTRNCPY(identity, kIdentityStr, id_max_len);

    for (i = 0; i < 32; i++, b += 0x22) {
        if (b >= 0x100)
            b = 0x01;
        key[i] = (unsigned char) b;
    }

#if defined(WOLFSSL_SHA384) && defined(WOLFSSL_AES_256)
    *ciphersuite = userCipher ? userCipher : "TLS13-AES256-GCM-SHA384";
#else
    *ciphersuite = userCipher ? userCipher : "TLS13-AES128-GCM-SHA256";
#endif

    ret = 32;   /* length of key in octets or 0 for error */

#if defined(HAVE_PK_CALLBACKS) && defined(TEST_PK_PSK)
    WOLFSSL_PKMSG("PSK Client TLS 1.3 using HW (Len %d, Hint %s)\n", ret, hint);
    ret = (unsigned int)USE_HW_PSK;
#endif

    return ret;
}


static WC_INLINE unsigned int my_psk_server_tls13_cb(WOLFSSL* ssl,
        const char* identity, unsigned char* key, unsigned int key_max_len,
        const char** ciphersuite)
{
    unsigned int ret;
    int i;
    int b = 0x01;
    size_t kIdLen = XSTRLEN(kIdentityStr);
    const char* userCipher = (const char*)wolfSSL_get_psk_callback_ctx(ssl);

    (void)ssl;
    (void)key_max_len;

    /* see internal.h MAX_PSK_ID_LEN for PSK identity limit */
    if (XSTRNCMP(identity, kIdentityStr, kIdLen) != 0)
        return 0;
    if (identity[kIdLen] != '\0') {
        userCipher = wolfSSL_get_cipher_name_by_hash(ssl, identity + kIdLen);
    }

    for (i = 0; i < 32; i++, b += 0x22) {
        if (b >= 0x100)
            b = 0x01;
        key[i] = (unsigned char) b;
    }

#if defined(WOLFSSL_SHA384) && defined(WOLFSSL_AES_256)
    *ciphersuite = userCipher ? userCipher : "TLS13-AES256-GCM-SHA384";
#else
    *ciphersuite = userCipher ? userCipher : "TLS13-AES128-GCM-SHA256";
#endif

    ret = 32;   /* length of key in octets or 0 for error */

#if defined(HAVE_PK_CALLBACKS) && defined(TEST_PK_PSK)
    WOLFSSL_PKMSG("PSK Server TLS 1.3 using HW (Len %d, Hint %s)\n",
        ret, identity);
    ret = (unsigned int)USE_HW_PSK;
#endif

    return ret;
}
#endif

#ifdef OPENSSL_EXTRA
static WC_INLINE int my_psk_use_session_cb(WOLFSSL* ssl,
            const WOLFSSL_EVP_MD* md, const unsigned char **id,
            size_t* idlen,  WOLFSSL_SESSION **sess)
{
#if defined(OPENSSL_ALL) && !defined(NO_CERTS) && !defined(NO_FILESYSTEM)
    static unsigned char local_psk[32];
    int i;
    WOLFSSL_SESSION* lsess;
    char buf[256];
    const char* cipher_id = "TLS13-AES128-GCM-SHA256";
    const SSL_CIPHER* cipher = NULL;
    STACK_OF(SSL_CIPHER) *supportedCiphers = NULL;
    int numCiphers = 0;
    (void)ssl;
    (void)md;

    printf("use psk session callback \n");

    lsess = SSL_SESSION_new();
    if (lsess == NULL) {
        return 0;
    }
    supportedCiphers = SSL_get_ciphers(ssl);
    numCiphers = sk_num(supportedCiphers);

    for (i = 0; i < numCiphers; ++i) {

        if ((cipher = (const WOLFSSL_CIPHER*)sk_value(supportedCiphers, i))) {
            SSL_CIPHER_description(cipher, buf, sizeof(buf));
        }

        if (XMEMCMP(cipher_id, buf, XSTRLEN(cipher_id)) == 0) {
            break;
        }
    }

    if (i != numCiphers) {
        int b = 0x01;
        SSL_SESSION_set_cipher(lsess, cipher);
        for (i = 0; i < 32; i++, b += 0x22) {
            if (b >= 0x100)
                b = 0x01;
            local_psk[i] = (unsigned char) b;
        }

        *id = local_psk;
        *idlen = 32;
        *sess = lsess;

        return 1;
    }
    else {
        *id = NULL;
        *idlen = 0;
        *sess = NULL;
        SSL_SESSION_free(lsess);
        return 0;
    }
#else
    (void)ssl;
    (void)md;
    (void)id;
    (void)idlen;
    (void)sess;

    return 0;
#endif
}
#endif /* OPENSSL_EXTRA */

static WC_INLINE unsigned int my_psk_client_cs_cb(WOLFSSL* ssl,
        const char* hint, char* identity, unsigned int id_max_len,
        unsigned char* key, unsigned int key_max_len, const char* ciphersuite)
{
    int i;
    int b = 0x01;

    (void)ssl;
    (void)hint;
    (void)key_max_len;

#ifdef WOLFSSL_PSK_MULTI_ID_PER_CS
    /* Multiple calls for each cipher suite. First identity byte indicates the
     * number of identities seen so far for cipher suite. */
    if (identity[0] != 0) {
        return 0;
    }
#endif

    /* see internal.h MAX_PSK_ID_LEN for PSK identity limit */
    XSTRNCPY(identity, kIdentityStr, id_max_len);
    XSTRNCAT(identity, ciphersuite + XSTRLEN(ciphersuite) - 6, id_max_len);

    for (i = 0; i < 32; i++, b += 0x22) {
        if (b >= 0x100)
            b = 0x01;
        key[i] = (unsigned char) b;
    }

    return 32;   /* length of key in octets or 0 for error */
}

#endif /* !NO_PSK */


#if defined(WOLFSSL_USER_CURRTIME)
    extern   double current_time(int reset);

#elif defined(USE_WINDOWS_API)

    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>

    static WC_INLINE double current_time(int reset)
    {
        static int init = 0;
        static LARGE_INTEGER freq;

        LARGE_INTEGER count;

        if (!init) {
            QueryPerformanceFrequency(&freq);
            init = 1;
        }

        QueryPerformanceCounter(&count);

        (void)reset;
        return (double)count.QuadPart / freq.QuadPart;
    }

#elif defined(WOLFSSL_TIRTOS)
    extern double current_time();
#elif defined(WOLFSSL_ZEPHYR)
    extern double current_time();
#else

#if !defined(WOLFSSL_MDK_ARM) && !defined(WOLFSSL_KEIL_TCP_NET) && !defined(WOLFSSL_CHIBIOS)
    #ifndef NETOS
        #include <sys/time.h>
    #endif

    static WC_INLINE double current_time(int reset)
    {
        struct timeval tv;
        if (gettimeofday(&tv, NULL) < 0)
            err_sys_with_errno("gettimeofday");
        (void)reset;

        return (double)tv.tv_sec + (double)tv.tv_usec / 1000000;
    }
#else
    extern double current_time(int reset);
#endif
#endif /* USE_WINDOWS_API */

#ifdef WOLFSSL_CALLBACKS
/* only for debug use! */
static WC_INLINE void msgDebugCb(int write_p, int version, int content_type,
    const void *buf, size_t len, WOLFSSL *ssl, void *arg)
{
    size_t z;
    byte* pt;

    printf("Version %02X, content type = %d\n", version, content_type);
    printf("%s ", (write_p)? "WRITING" : "READING");
    pt = (byte*)buf;
    printf("DATA [%zu]: ", len);
    for (z = 0; z < len; z++)
        printf("%02X", pt[z]);
    printf("\n");

    (void)arg;
    (void)ssl;
}
#endif /* WOLFSSL_CALLBACKS */

#if defined(HAVE_OCSP) && defined(WOLFSSL_NONBLOCK_OCSP)
static WC_INLINE int OCSPIOCb(void* ioCtx, const char* url, int urlSz,
    unsigned char* request, int requestSz, unsigned char** response)
{
#ifdef TEST_NONBLOCK_CERTS
    static int ioCbCnt = 0;
#endif

    (void)ioCtx;
    (void)url;
    (void)urlSz;
    (void)request;
    (void)requestSz;
    (void)response;

#ifdef TEST_NONBLOCK_CERTS
    if (ioCbCnt) {
        ioCbCnt = 0;
        return EmbedOcspLookup(ioCtx, url, urlSz, request, requestSz, response);
    }
    else {
        ioCbCnt = 1;
        return WOLFSSL_CBIO_ERR_WANT_READ;
    }
#else
    return EmbedOcspLookup(ioCtx, url, urlSz, request, requestSz, response);
#endif
}

static WC_INLINE void OCSPRespFreeCb(void* ioCtx, unsigned char* response)
{
    EmbedOcspRespFree(ioCtx, response);
}
#endif

#if !defined(NO_CERTS)
    #if !defined(NO_FILESYSTEM) || \
        (defined(NO_FILESYSTEM) && defined(FORCE_BUFFER_TEST)) && \
        !defined(NETOS)

    /* reads file size, allocates buffer, reads into buffer, returns buffer */
    static WC_INLINE int load_file(const char* fname, byte** buf, size_t* bufLen)
    {
        int ret;
        long int fileSz;
        XFILE lFile;

        if (fname == NULL || buf == NULL || bufLen == NULL)
            return BAD_FUNC_ARG;

        /* set defaults */
        *buf = NULL;
        *bufLen = 0;

        /* open file (read-only binary) */
        lFile = XFOPEN(fname, "rb");
        if (!lFile) {
            fprintf(stderr, "Error loading %s\n", fname);
            return BAD_PATH_ERROR;
        }

        LIBCALL_CHECK_RET(XFSEEK(lFile, 0, XSEEK_END));
        fileSz = (int)ftell(lFile);
        LIBCALL_CHECK_RET(XFSEEK(lFile, 0, XSEEK_SET));
        if (fileSz  > 0) {
            *bufLen = (size_t)fileSz;
            *buf = (byte*)malloc(*bufLen);
            if (*buf == NULL) {
                ret = MEMORY_E;
                fprintf(stderr,
                        "Error allocating %lu bytes\n", (unsigned long)*bufLen);
            }
            else {
                size_t readLen = fread(*buf, *bufLen, 1, lFile);

                /* check response code */
                ret = (readLen > 0) ? 0 : -1;
            }
        }
        else {
            ret = BUFFER_E;
        }
        fclose(lFile);

        return ret;
    }

    enum {
        WOLFSSL_CA   = 1,
        WOLFSSL_CERT = 2,
        WOLFSSL_KEY  = 3,
        WOLFSSL_CERT_CHAIN = 4,
    };

    static WC_INLINE void load_buffer(WOLFSSL_CTX* ctx, const char* fname, int type)
    {
        int format = WOLFSSL_FILETYPE_PEM;
        byte* buff = NULL;
        size_t sz = 0;

        if (load_file(fname, &buff, &sz) != 0) {
            err_sys("can't open file for buffer load "
                    "Please run from wolfSSL home directory if not");
        }

        /* determine format */
        if (strstr(fname, ".der"))
            format = WOLFSSL_FILETYPE_ASN1;

        if (type == WOLFSSL_CA) {
            if (wolfSSL_CTX_load_verify_buffer(ctx, buff, (long)sz, format)
                                              != WOLFSSL_SUCCESS)
                err_sys("can't load buffer ca file");
        }
        else if (type == WOLFSSL_CERT) {
            if (wolfSSL_CTX_use_certificate_buffer(ctx, buff, (long)sz,
                        format) != WOLFSSL_SUCCESS)
                err_sys("can't load buffer cert file");
        }
        else if (type == WOLFSSL_KEY) {
            if (wolfSSL_CTX_use_PrivateKey_buffer(ctx, buff, (long)sz,
                        format) != WOLFSSL_SUCCESS)
                err_sys("can't load buffer key file");
        }
        else if (type == WOLFSSL_CERT_CHAIN) {
            if (wolfSSL_CTX_use_certificate_chain_buffer_format(ctx, buff,
                    (long)sz, format) != WOLFSSL_SUCCESS)
                err_sys("can't load cert chain buffer");
        }

        if (buff)
            free(buff);
    }

    static WC_INLINE void load_ssl_buffer(WOLFSSL* ssl, const char* fname, int type)
    {
        int format = WOLFSSL_FILETYPE_PEM;
        byte* buff = NULL;
        size_t sz = 0;

        if (load_file(fname, &buff, &sz) != 0) {
            err_sys("can't open file for buffer load "
                    "Please run from wolfSSL home directory if not");
        }

        /* determine format */
        if (strstr(fname, ".der"))
            format = WOLFSSL_FILETYPE_ASN1;

        if (type == WOLFSSL_CA) {
            /* verify certs (CA's) use the shared ctx->cm (WOLFSSL_CERT_MANAGER) */
            WOLFSSL_CTX* ctx = wolfSSL_get_SSL_CTX(ssl);
            if (wolfSSL_CTX_load_verify_buffer(ctx, buff, (long)sz, format)
                                              != WOLFSSL_SUCCESS)
                err_sys("can't load buffer ca file");
        }
        else if (type == WOLFSSL_CERT) {
            if (wolfSSL_use_certificate_buffer(ssl, buff, (long)sz,
                        format) != WOLFSSL_SUCCESS)
                err_sys("can't load buffer cert file");
        }
        else if (type == WOLFSSL_KEY) {
            if (wolfSSL_use_PrivateKey_buffer(ssl, buff, (long)sz,
                        format) != WOLFSSL_SUCCESS)
                err_sys("can't load buffer key file");
        }
        else if (type == WOLFSSL_CERT_CHAIN) {
            if (wolfSSL_use_certificate_chain_buffer_format(ssl, buff,
                    (long)sz, format) != WOLFSSL_SUCCESS)
                err_sys("can't load cert chain buffer");
        }

        if (buff)
            free(buff);
    }

    #ifdef TEST_PK_PRIVKEY
    static WC_INLINE int load_key_file(const char* fname, byte** derBuf, word32* derLen)
    {
        int ret;
        byte* buf = NULL;
        size_t bufLen;

        ret = load_file(fname, &buf, &bufLen);
        if (ret != 0)
            return ret;

        *derBuf = (byte*)malloc(bufLen);
        if (*derBuf == NULL) {
            free(buf);
            return MEMORY_E;
        }

        ret = wc_KeyPemToDer(buf, (word32)bufLen, *derBuf, (word32)bufLen, NULL);
        if (ret < 0) {
            free(buf);
            free(*derBuf);
            return ret;
        }
        *derLen = ret;
        free(buf);

        return 0;
    }
    #endif /* TEST_PK_PRIVKEY */

    #endif /* !NO_FILESYSTEM || (NO_FILESYSTEM && FORCE_BUFFER_TEST) */
#endif /* !NO_CERTS */

enum {
    VERIFY_OVERRIDE_ERROR,
    VERIFY_FORCE_FAIL,
    VERIFY_USE_PREVERIFY,
    VERIFY_OVERRIDE_DATE_ERR,
};
static THREAD_LS_T int myVerifyAction = VERIFY_OVERRIDE_ERROR;

/* The verify callback is called for every certificate only when
 * --enable-opensslextra is defined because it sets WOLFSSL_ALWAYS_VERIFY_CB and
 * WOLFSSL_VERIFY_CB_ALL_CERTS.
 * Normal cases of the verify callback only occur on certificate failures when the
 * wolfSSL_set_verify(ssl, SSL_VERIFY_PEER, myVerify); is called
*/

static WC_INLINE int myVerify(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    char buffer[WOLFSSL_MAX_ERROR_SZ];
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
    WOLFSSL_X509* peer;
#if defined(SHOW_CERTS) && !defined(NO_FILESYSTEM) && \
    !defined(OPENSSL_EXTRA_X509_SMALL)
    WOLFSSL_BIO* bio = NULL;
    WOLFSSL_STACK* sk = NULL;
    X509* x509 = NULL;
#endif
#endif

    /* Verify Callback Arguments:
     * preverify:           1=Verify Okay, 0=Failure
     * store->error:        Failure error code (0 indicates no failure)
     * store->current_cert: Current WOLFSSL_X509 object (only with OPENSSL_EXTRA)
     * store->error_depth:  Current Index
     * store->domain:       Subject CN as string (null term)
     * store->totalCerts:   Number of certs presented by peer
     * store->certs[i]:     A `WOLFSSL_BUFFER_INFO` with plain DER for each cert
     * store->store:        WOLFSSL_X509_STORE with CA cert chain
     * store->store->cm:    WOLFSSL_CERT_MANAGER
     * store->ex_data:      The WOLFSSL object pointer
     * store->discardSessionCerts: When set to non-zero value session certs
        will be discarded (only with SESSION_CERTS)
     */

    fprintf(stderr, "In verification callback, error = %d, %s\n", store->error,
                                 wolfSSL_ERR_error_string((unsigned long) store->error, buffer));
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
    peer = store->current_cert;
    if (peer) {
        char* issuer  = wolfSSL_X509_NAME_oneline(
                                       wolfSSL_X509_get_issuer_name(peer), 0, 0);
        char* subject = wolfSSL_X509_NAME_oneline(
                                      wolfSSL_X509_get_subject_name(peer), 0, 0);
        printf("\tPeer's cert info:\n issuer : %s\n subject: %s\n",
               issuer ? issuer : "[none]",
               subject ? subject : "[none]");
#if defined(OPENSSL_ALL) || defined(WOLFSSL_QT)
        if (issuer != NULL && subject != NULL) {
            /* preverify needs to be self-signer error for Qt compat.
             * Should be ASN_SELF_SIGNED_E */
            if (XSTRCMP(issuer, subject) == 0 && preverify == ASN_NO_SIGNER_E)
                return 0;
        }
#endif

        XFREE(subject, 0, DYNAMIC_TYPE_OPENSSL);
        XFREE(issuer,  0, DYNAMIC_TYPE_OPENSSL);
#if defined(SHOW_CERTS) && !defined(NO_FILESYSTEM) && \
    !defined(OPENSSL_EXTRA_X509_SMALL)
        /* avoid printing duplicate certs */
        if (store->depth == 1) {
            int i;
            /* retrieve x509 certs and display them on stdout */
            sk = wolfSSL_X509_STORE_GetCerts(store);

            for (i = 0; i < wolfSSL_sk_X509_num(sk); i++) {
                x509 = wolfSSL_sk_X509_value(sk, i);
                bio = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
                if (bio != NULL) {
                    wolfSSL_BIO_set_fp(bio, stdout, BIO_NOCLOSE);
                    wolfSSL_X509_print(bio, x509);
                    wolfSSL_BIO_free(bio);
                }
            }
            wolfSSL_sk_X509_pop_free(sk, NULL);
        }
#endif
    }
    else
        fprintf(stderr, "\tPeer has no cert!\n");
#else
    printf("\tPeer certs: %d\n", store->totalCerts);
    #ifdef SHOW_CERTS
    {   int i;
        for (i=0; i<store->totalCerts; i++) {
            WOLFSSL_BUFFER_INFO* cert = &store->certs[i];
            printf("\t\tCert %d: Ptr %p, Len %u\n", i, cert->buffer, cert->length);
        }
    }
    #endif /* SHOW_CERTS */
#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */

    printf("\tSubject's domain name at %d is %s\n", store->error_depth, store->domain);

    /* Testing forced fail case by return zero */
    if (myVerifyAction == VERIFY_FORCE_FAIL) {
        return 0; /* test failure case */
    }

    if (myVerifyAction == VERIFY_OVERRIDE_DATE_ERR &&
        (store->error == ASN_BEFORE_DATE_E || store->error == ASN_AFTER_DATE_E)) {
        printf("Overriding cert date error as example for bad clock testing\n");
        return 1;
    }

    /* If error indicate we are overriding it for testing purposes */
    if (store->error != 0 && myVerifyAction == VERIFY_OVERRIDE_ERROR) {
        printf("\tAllowing failed certificate check, testing only "
            "(shouldn't do this in production)\n");
    }

    /* A non-zero return code indicates failure override */
    return (myVerifyAction == VERIFY_OVERRIDE_ERROR) ? 1 : preverify;
}


#ifdef HAVE_EXT_CACHE

static WC_INLINE WOLFSSL_SESSION* mySessGetCb(WOLFSSL* ssl,
        const unsigned char* id, int id_len, int* copy)
{
    (void)ssl;
    (void)id;
    (void)id_len;
    (void)copy;

    /* using internal cache, this is for testing only */
    return NULL;
}

static WC_INLINE int mySessNewCb(WOLFSSL* ssl, WOLFSSL_SESSION* session)
{
    (void)ssl;
    (void)session;

    /* using internal cache, this is for testing only */
    return 0;
}

static WC_INLINE void mySessRemCb(WOLFSSL_CTX* ctx, WOLFSSL_SESSION* session)
{
    (void)ctx;
    (void)session;

    /* using internal cache, this is for testing only */
}

#endif /* HAVE_EXT_CACHE */


#ifdef HAVE_CRL

static WC_INLINE void CRL_CallBack(const char* url)
{
    printf("CRL callback url = %s\n", url);
}

#endif

#ifndef NO_DH
#if defined(WOLFSSL_SP_MATH) && !defined(WOLFSSL_SP_MATH_ALL)
    /* dh2048 p */
    static const unsigned char test_dh_p[] =
    {
        0xD3, 0xB2, 0x99, 0x84, 0x5C, 0x0A, 0x4C, 0xE7, 0x37, 0xCC, 0xFC, 0x18,
        0x37, 0x01, 0x2F, 0x5D, 0xC1, 0x4C, 0xF4, 0x5C, 0xC9, 0x82, 0x8D, 0xB7,
        0xF3, 0xD4, 0xA9, 0x8A, 0x9D, 0x34, 0xD7, 0x76, 0x57, 0xE5, 0xE5, 0xC3,
        0xE5, 0x16, 0x85, 0xCA, 0x4D, 0xD6, 0x5B, 0xC1, 0xF8, 0xCF, 0x89, 0x26,
        0xD0, 0x38, 0x8A, 0xEE, 0xF3, 0xCD, 0x33, 0xE5, 0x56, 0xBB, 0x90, 0x83,
        0x9F, 0x97, 0x8E, 0x71, 0xFB, 0x27, 0xE4, 0x35, 0x15, 0x45, 0x86, 0x09,
        0x71, 0xA8, 0x9A, 0xB9, 0x3E, 0x0F, 0x51, 0x8A, 0xC2, 0x75, 0x51, 0x23,
        0x12, 0xFB, 0x94, 0x31, 0x44, 0xBF, 0xCE, 0xF6, 0xED, 0xA6, 0x3A, 0xB7,
        0x92, 0xCE, 0x16, 0xA9, 0x14, 0xB3, 0x88, 0xB7, 0x13, 0x81, 0x71, 0x83,
        0x88, 0xCD, 0xB1, 0xA2, 0x37, 0xE1, 0x59, 0x5C, 0xD0, 0xDC, 0xCA, 0x82,
        0x87, 0xFA, 0x43, 0x44, 0xDD, 0x78, 0x3F, 0xCA, 0x27, 0x7E, 0xE1, 0x6B,
        0x93, 0x19, 0x7C, 0xD9, 0xA6, 0x96, 0x47, 0x0D, 0x12, 0xC1, 0x13, 0xD7,
        0xB9, 0x0A, 0x40, 0xD9, 0x1F, 0xFF, 0xB8, 0xB4, 0x00, 0xC8, 0xAA, 0x5E,
        0xD2, 0x66, 0x4A, 0x05, 0x8E, 0x9E, 0xF5, 0x34, 0xE7, 0xD7, 0x09, 0x7B,
        0x15, 0x49, 0x1D, 0x76, 0x31, 0xD6, 0x71, 0xEC, 0x13, 0x4E, 0x89, 0x8C,
        0x09, 0x22, 0xD8, 0xE7, 0xA3, 0xE9, 0x7D, 0x21, 0x51, 0x26, 0x6E, 0x9F,
        0x30, 0x8A, 0xBB, 0xBC, 0x74, 0xC1, 0xC3, 0x27, 0x6A, 0xCE, 0xA3, 0x12,
        0x60, 0x68, 0x01, 0xD2, 0x34, 0x07, 0x80, 0xCC, 0x2D, 0x7F, 0x5C, 0xAE,
        0xA2, 0x97, 0x40, 0xC8, 0x3C, 0xAC, 0xDB, 0x6F, 0xFE, 0x6C, 0x6D, 0xD2,
        0x06, 0x1C, 0x43, 0xA2, 0xB2, 0x2B, 0x82, 0xB7, 0xD0, 0xAB, 0x3F, 0x2C,
        0xE7, 0x9C, 0x19, 0x16, 0xD1, 0x5E, 0x26, 0x86, 0xC7, 0x92, 0xF9, 0x16,
        0x0B, 0xFA, 0x66, 0x83
    };

    /* dh2048 g */
    static const unsigned char test_dh_g[] =
    {
      0x02,
    };
#else
    /* dh1024 p */
    static const unsigned char test_dh_p[] =
    {
        0xE6, 0x96, 0x9D, 0x3D, 0x49, 0x5B, 0xE3, 0x2C, 0x7C, 0xF1, 0x80, 0xC3,
        0xBD, 0xD4, 0x79, 0x8E, 0x91, 0xB7, 0x81, 0x82, 0x51, 0xBB, 0x05, 0x5E,
        0x2A, 0x20, 0x64, 0x90, 0x4A, 0x79, 0xA7, 0x70, 0xFA, 0x15, 0xA2, 0x59,
        0xCB, 0xD5, 0x23, 0xA6, 0xA6, 0xEF, 0x09, 0xC4, 0x30, 0x48, 0xD5, 0xA2,
        0x2F, 0x97, 0x1F, 0x3C, 0x20, 0x12, 0x9B, 0x48, 0x00, 0x0E, 0x6E, 0xDD,
        0x06, 0x1C, 0xBC, 0x05, 0x3E, 0x37, 0x1D, 0x79, 0x4E, 0x53, 0x27, 0xDF,
        0x61, 0x1E, 0xBB, 0xBE, 0x1B, 0xAC, 0x9B, 0x5C, 0x60, 0x44, 0xCF, 0x02,
        0x3D, 0x76, 0xE0, 0x5E, 0xEA, 0x9B, 0xAD, 0x99, 0x1B, 0x13, 0xA6, 0x3C,
        0x97, 0x4E, 0x9E, 0xF1, 0x83, 0x9E, 0xB5, 0xDB, 0x12, 0x51, 0x36, 0xF7,
        0x26, 0x2E, 0x56, 0xA8, 0x87, 0x15, 0x38, 0xDF, 0xD8, 0x23, 0xC6, 0x50,
        0x50, 0x85, 0xE2, 0x1F, 0x0D, 0xD5, 0xC8, 0x6B,
    };

    /* dh1024 g */
    static const unsigned char test_dh_g[] =
    {
      0x02,
    };
#endif

static WC_INLINE void SetDH(WOLFSSL* ssl)
{
    wolfSSL_SetTmpDH(ssl, test_dh_p, sizeof(test_dh_p), test_dh_g,
        sizeof(test_dh_g));
}

static WC_INLINE void SetDHCtx(WOLFSSL_CTX* ctx)
{
    wolfSSL_CTX_SetTmpDH(ctx, test_dh_p, sizeof(test_dh_p), test_dh_g,
        sizeof(test_dh_g));
}
#endif /* NO_DH */

#ifndef NO_CERTS

static WC_INLINE void CaCb(unsigned char* der, int sz, int type)
{
    (void)der;
    printf("Got CA cache add callback, derSz = %d, type = %d\n", sz, type);
}

#endif /* !NO_CERTS */


/* Wolf Root Directory Helper */
/* KEIL-RL File System does not support relative directory */
#if !defined(WOLFSSL_MDK_ARM) && !defined(WOLFSSL_KEIL_FS) && !defined(WOLFSSL_TIRTOS)
    /* Maximum depth to search for WolfSSL root */
    #define MAX_WOLF_ROOT_DEPTH 5

    static WC_INLINE int ChangeToWolfRoot(void)
    {
        #if !defined(NO_FILESYSTEM) || defined(FORCE_BUFFER_TEST) && \
            !defined(NETOS)
            int depth;
            for(depth = 0; depth <= MAX_WOLF_ROOT_DEPTH; depth++) {
                int res;
                XFILE keyFile = XFOPEN(dhParamFile, "rb");
                if (keyFile != NULL) {
                    fclose(keyFile);
                    return depth;
                }
            #ifdef USE_WINDOWS_API
                res = SetCurrentDirectoryA("..\\");
            #elif defined(NETOS)
                return 0;
            #else
                res = chdir("../");
            #endif
                if (res < 0) {
                    printf("chdir to ../ failed!\n");
                    break;
                }
            }

            err_sys("wolf root not found");
            return -1;
        #else
            return 0;
        #endif
    }
#endif /* !defined(WOLFSSL_MDK_ARM) && !defined(WOLFSSL_KEIL_FS) && !defined(WOLFSSL_TIRTOS) */


#if defined(ATOMIC_USER) && !defined(WOLFSSL_AEAD_ONLY)

/* Atomic Encrypt Context example */
typedef struct AtomicEncCtx {
    int  keySetup;           /* have we done key setup yet */
    Aes  aes;                /* for aes example */
} AtomicEncCtx;


/* Atomic Decrypt Context example */
typedef struct AtomicDecCtx {
    int  keySetup;           /* have we done key setup yet */
    Aes  aes;                /* for aes example */
} AtomicDecCtx;

#if !defined(NO_HMAC) && !defined(NO_AES) && defined(HAVE_AES_CBC)
static WC_INLINE int myMacEncryptCb(WOLFSSL* ssl, unsigned char* macOut,
       const unsigned char* macIn, unsigned int macInSz, int macContent,
       int macVerify, unsigned char* encOut, const unsigned char* encIn,
       unsigned int encSz, void* ctx)
{
    int  ret;
    Hmac hmac;
    byte myInner[WOLFSSL_TLS_HMAC_INNER_SZ];
    AtomicEncCtx* encCtx = (AtomicEncCtx*)ctx;
    const char* tlsStr = "TLS";

    /* example supports (d)tls aes */
    if (wolfSSL_GetBulkCipher(ssl) != wolfssl_aes) {
        printf("myMacEncryptCb not using AES\n");
        return -1;
    }

    if (strstr(wolfSSL_get_version(ssl), tlsStr) == NULL) {
        printf("myMacEncryptCb not using (D)TLS\n");
        return -1;
    }

    /* hmac, not needed if aead mode */
    wolfSSL_SetTlsHmacInner(ssl, myInner, macInSz, macContent, macVerify);

    ret = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
    if (ret != 0)
        return ret;
    ret = wc_HmacSetKey(&hmac, wolfSSL_GetHmacType(ssl),
               wolfSSL_GetMacSecret(ssl, macVerify), (word32) wolfSSL_GetHmacSize(ssl));
    if (ret != 0)
        return ret;
    ret = wc_HmacUpdate(&hmac, myInner, sizeof(myInner));
    if (ret != 0)
        return ret;
    ret = wc_HmacUpdate(&hmac, macIn, macInSz);
    if (ret != 0)
        return ret;
    ret = wc_HmacFinal(&hmac, macOut);
    if (ret != 0)
        return ret;


    /* encrypt setup on first time */
    if (encCtx->keySetup == 0) {
        int   keyLen = wolfSSL_GetKeySize(ssl);
        const byte* key;
        const byte* iv;

        if (wolfSSL_GetSide(ssl) == WOLFSSL_CLIENT_END) {
            key = wolfSSL_GetClientWriteKey(ssl);
            iv  = wolfSSL_GetClientWriteIV(ssl);
        }
        else {
            key = wolfSSL_GetServerWriteKey(ssl);
            iv  = wolfSSL_GetServerWriteIV(ssl);
        }

        ret = wc_AesInit(&encCtx->aes, NULL, INVALID_DEVID);
        if (ret != 0) {
            fprintf(stderr, "AesInit failed in myMacEncryptCb\n");
            return ret;
        }
        ret = wc_AesSetKey(&encCtx->aes, key, (word32) keyLen, iv, AES_ENCRYPTION);
        if (ret != 0) {
            fprintf(stderr, "AesSetKey failed in myMacEncryptCb\n");
            return ret;
        }
        encCtx->keySetup = 1;
    }

    /* encrypt */
    return wc_AesCbcEncrypt(&encCtx->aes, encOut, encIn, encSz);
}

static WC_INLINE int myDecryptVerifyCb(WOLFSSL* ssl,
       unsigned char* decOut, const unsigned char* decIn,
       unsigned int decSz, int macContent, int macVerify,
       unsigned int* padSz, void* ctx)
{
    AtomicDecCtx* decCtx = (AtomicDecCtx*)ctx;
    int ret      = 0;
    unsigned int macInSz  = 0;
    int ivExtra  = 0;
    int digestSz = wolfSSL_GetHmacSize(ssl);
    unsigned int pad     = 0;
    unsigned int padByte = 0;
    Hmac hmac;
    byte myInner[WOLFSSL_TLS_HMAC_INNER_SZ];
    byte verify[WC_MAX_DIGEST_SIZE];
    const char* tlsStr = "TLS";

    /* example supports (d)tls aes */
    if (wolfSSL_GetBulkCipher(ssl) != wolfssl_aes) {
        printf("myMacEncryptCb not using AES\n");
        return -1;
    }

    if (strstr(wolfSSL_get_version(ssl), tlsStr) == NULL) {
        printf("myMacEncryptCb not using (D)TLS\n");
        return -1;
    }

    /*decrypt */
    if (decCtx->keySetup == 0) {
        int   keyLen = wolfSSL_GetKeySize(ssl);
        const byte* key;
        const byte* iv;

        /* decrypt is from other side (peer) */
        if (wolfSSL_GetSide(ssl) == WOLFSSL_SERVER_END) {
            key = wolfSSL_GetClientWriteKey(ssl);
            iv  = wolfSSL_GetClientWriteIV(ssl);
        }
        else {
            key = wolfSSL_GetServerWriteKey(ssl);
            iv  = wolfSSL_GetServerWriteIV(ssl);
        }

        ret = wc_AesInit(&decCtx->aes, NULL, INVALID_DEVID);
        if (ret != 0) {
            fprintf(stderr, "AesInit failed in myDecryptVerifyCb\n");
            return ret;
        }
        ret = wc_AesSetKey(&decCtx->aes, key, (word32) keyLen, iv, AES_DECRYPTION);
        if (ret != 0) {
            fprintf(stderr, "AesSetKey failed in myDecryptVerifyCb\n");
            return ret;
        }
        decCtx->keySetup = 1;
    }

    /* decrypt */
    ret = wc_AesCbcDecrypt(&decCtx->aes, decOut, decIn, decSz);
    if (ret != 0)
        return ret;

    if (wolfSSL_GetCipherType(ssl) == WOLFSSL_AEAD_TYPE) {
        *padSz = (unsigned int)wolfSSL_GetAeadMacSize(ssl);
        return 0; /* hmac, not needed if aead mode */
    }

    if (wolfSSL_GetCipherType(ssl) == WOLFSSL_BLOCK_TYPE) {
        pad     = *(decOut + decSz - 1);
        padByte = 1;
        if (wolfSSL_IsTLSv1_1(ssl))
            ivExtra = wolfSSL_GetCipherBlockSize(ssl);
    }

    *padSz  = (unsigned int)wolfSSL_GetHmacSize(ssl) + pad + padByte;
    macInSz = decSz - (unsigned int)ivExtra - (unsigned int)digestSz - pad - padByte;

    wolfSSL_SetTlsHmacInner(ssl, myInner, macInSz, macContent, macVerify);

    ret = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
    if (ret != 0)
        return ret;
    ret = wc_HmacSetKey(&hmac, wolfSSL_GetHmacType(ssl),
               wolfSSL_GetMacSecret(ssl, macVerify), (unsigned int) digestSz);
    if (ret != 0)
        return ret;
    ret = wc_HmacUpdate(&hmac, myInner, sizeof(myInner));
    if (ret != 0)
        return ret;
    ret = wc_HmacUpdate(&hmac, decOut + ivExtra, macInSz);
    if (ret != 0)
        return ret;
    ret = wc_HmacFinal(&hmac, verify);
    if (ret != 0)
        return ret;

    if (XMEMCMP(verify, decOut + decSz - digestSz - pad - padByte,
               (size_t) digestSz) != 0) {
        printf("myDecryptVerify verify failed\n");
        return -1;
    }

    return ret;
}

#ifdef HAVE_ENCRYPT_THEN_MAC

static WC_INLINE int myEncryptMacCb(WOLFSSL* ssl, unsigned char* macOut,
       int content, int macVerify, unsigned char* encOut,
       const unsigned char* encIn, unsigned int encSz, void* ctx)
{
    int  ret;
    Hmac hmac;
    AtomicEncCtx* encCtx = (AtomicEncCtx*)ctx;
    byte myInner[WOLFSSL_TLS_HMAC_INNER_SZ];
    const char* tlsStr = "TLS";

    /* example supports (d)tls aes */
    if (wolfSSL_GetBulkCipher(ssl) != wolfssl_aes) {
        printf("myMacEncryptCb not using AES\n");
        return -1;
    }

    if (strstr(wolfSSL_get_version(ssl), tlsStr) == NULL) {
        printf("myMacEncryptCb not using (D)TLS\n");
        return -1;
    }

    /* encrypt setup on first time */
    if (encCtx->keySetup == 0) {
        int   keyLen = wolfSSL_GetKeySize(ssl);
        const byte* key;
        const byte* iv;

        if (wolfSSL_GetSide(ssl) == WOLFSSL_CLIENT_END) {
            key = wolfSSL_GetClientWriteKey(ssl);
            iv  = wolfSSL_GetClientWriteIV(ssl);
        }
        else {
            key = wolfSSL_GetServerWriteKey(ssl);
            iv  = wolfSSL_GetServerWriteIV(ssl);
        }

        ret = wc_AesInit(&encCtx->aes, NULL, INVALID_DEVID);
        if (ret != 0) {
            fprintf(stderr, "AesInit failed in myMacEncryptCb\n");
            return ret;
        }
        ret = wc_AesSetKey(&encCtx->aes, key, (word32) keyLen, iv, AES_ENCRYPTION);
        if (ret != 0) {
            fprintf(stderr, "AesSetKey failed in myMacEncryptCb\n");
            return ret;
        }
        encCtx->keySetup = 1;
    }

    /* encrypt */
    ret = wc_AesCbcEncrypt(&encCtx->aes, encOut, encIn, encSz);
    if (ret != 0)
        return ret;

    /* Reconstruct record header. */
    wolfSSL_SetTlsHmacInner(ssl, myInner, encSz, content, macVerify);

    ret = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
    if (ret != 0)
        return ret;
    ret = wc_HmacSetKey(&hmac, wolfSSL_GetHmacType(ssl),
               wolfSSL_GetMacSecret(ssl, macVerify), (word32) wolfSSL_GetHmacSize(ssl));
    if (ret != 0)
        return ret;
    ret = wc_HmacUpdate(&hmac, myInner, sizeof(myInner));
    if (ret != 0)
        return ret;
    ret = wc_HmacUpdate(&hmac, encOut, encSz);
    if (ret != 0)
        return ret;
    return wc_HmacFinal(&hmac, macOut);
}


static WC_INLINE int myVerifyDecryptCb(WOLFSSL* ssl,
       unsigned char* decOut, const unsigned char* decIn,
       unsigned int decSz, int content, int macVerify,
       unsigned int* padSz, void* ctx)
{
    AtomicDecCtx* decCtx = (AtomicDecCtx*)ctx;
    int ret      = 0;
    int digestSz = wolfSSL_GetHmacSize(ssl);
    Hmac hmac;
    byte myInner[WOLFSSL_TLS_HMAC_INNER_SZ];
    byte verify[WC_MAX_DIGEST_SIZE];
    const char* tlsStr = "TLS";

    /* example supports (d)tls aes */
    if (wolfSSL_GetBulkCipher(ssl) != wolfssl_aes) {
        printf("myMacEncryptCb not using AES\n");
        return -1;
    }

    if (strstr(wolfSSL_get_version(ssl), tlsStr) == NULL) {
        printf("myMacEncryptCb not using (D)TLS\n");
        return -1;
    }

    /* Reconstruct record header. */
    wolfSSL_SetTlsHmacInner(ssl, myInner, decSz, content, macVerify);

    ret = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
    if (ret != 0)
        return ret;
    ret = wc_HmacSetKey(&hmac, wolfSSL_GetHmacType(ssl),
               wolfSSL_GetMacSecret(ssl, macVerify), (word32) digestSz);
    if (ret != 0)
        return ret;
    ret = wc_HmacUpdate(&hmac, myInner, sizeof(myInner));
    if (ret != 0)
        return ret;
    ret = wc_HmacUpdate(&hmac, decIn, decSz);
    if (ret != 0)
        return ret;
    ret = wc_HmacFinal(&hmac, verify);
    if (ret != 0)
        return ret;

    if (XMEMCMP(verify, decOut + decSz, (size_t) digestSz) != 0) {
        printf("myDecryptVerify verify failed\n");
        return -1;
    }

    /* decrypt */
    if (decCtx->keySetup == 0) {
        int   keyLen = wolfSSL_GetKeySize(ssl);
        const byte* key;
        const byte* iv;

        /* decrypt is from other side (peer) */
        if (wolfSSL_GetSide(ssl) == WOLFSSL_SERVER_END) {
            key = wolfSSL_GetClientWriteKey(ssl);
            iv  = wolfSSL_GetClientWriteIV(ssl);
        }
        else {
            key = wolfSSL_GetServerWriteKey(ssl);
            iv  = wolfSSL_GetServerWriteIV(ssl);
        }

        ret = wc_AesInit(&decCtx->aes, NULL, INVALID_DEVID);
        if (ret != 0) {
            fprintf(stderr, "AesInit failed in myDecryptVerifyCb\n");
            return ret;
        }
        ret = wc_AesSetKey(&decCtx->aes, key, (word32) keyLen, iv, AES_DECRYPTION);
        if (ret != 0) {
            fprintf(stderr, "AesSetKey failed in myDecryptVerifyCb\n");
            return ret;
        }
        decCtx->keySetup = 1;
    }

    /* decrypt */
    ret = wc_AesCbcDecrypt(&decCtx->aes, decOut, decIn, decSz);
    if (ret != 0)
        return ret;

    *padSz  = *(decOut + decSz - 1) + 1;

    return 0;
}

#endif /* HAVE_ENCRYPT_THEN_MAC */
#endif /* !NO_HMAC && !NO_AES && HAVE_AES_CBC */


static WC_INLINE void SetupAtomicUser(WOLFSSL_CTX* ctx, WOLFSSL* ssl)
{
#if !defined(NO_HMAC) && !defined(NO_AES) && defined(HAVE_AES_CBC)
    AtomicEncCtx* encCtx;
    AtomicDecCtx* decCtx;

    encCtx = (AtomicEncCtx*)malloc(sizeof(AtomicEncCtx));
    if (encCtx == NULL)
        err_sys_with_errno("AtomicEncCtx malloc failed");
    XMEMSET(encCtx, 0, sizeof(AtomicEncCtx));

    decCtx = (AtomicDecCtx*)malloc(sizeof(AtomicDecCtx));
    if (decCtx == NULL) {
        free(encCtx);
        err_sys_with_errno("AtomicDecCtx malloc failed");
    }
    XMEMSET(decCtx, 0, sizeof(AtomicDecCtx));

    wolfSSL_CTX_SetMacEncryptCb(ctx, myMacEncryptCb);
    wolfSSL_SetMacEncryptCtx(ssl, encCtx);

    wolfSSL_CTX_SetDecryptVerifyCb(ctx, myDecryptVerifyCb);
    wolfSSL_SetDecryptVerifyCtx(ssl, decCtx);

    #ifdef HAVE_ENCRYPT_THEN_MAC
    wolfSSL_CTX_SetEncryptMacCb(ctx, myEncryptMacCb);
    wolfSSL_SetEncryptMacCtx(ssl, encCtx);

    wolfSSL_CTX_SetVerifyDecryptCb(ctx, myVerifyDecryptCb);
    wolfSSL_SetVerifyDecryptCtx(ssl, decCtx);
    #endif
#else
    (void)ctx;
    (void)ssl;
#endif
}


static WC_INLINE void FreeAtomicUser(WOLFSSL* ssl)
{
    AtomicEncCtx* encCtx = (AtomicEncCtx*)wolfSSL_GetMacEncryptCtx(ssl);
    AtomicDecCtx* decCtx = (AtomicDecCtx*)wolfSSL_GetDecryptVerifyCtx(ssl);

    /* Encrypt-Then-MAC callbacks use same contexts. */

    if (encCtx != NULL) {
        if (encCtx->keySetup  == 1)
            wc_AesFree(&encCtx->aes);
        free(encCtx);
    }
    if (decCtx != NULL) {
        if (decCtx->keySetup  == 1)
            wc_AesFree(&decCtx->aes);
        free(decCtx);
    }
}

#endif /* ATOMIC_USER */

#if defined(WOLFSSL_STATIC_MEMORY) && !defined(WOLFSSL_STATIC_MEMORY_LEAN)
static WC_INLINE int wolfSSL_PrintStats(WOLFSSL_MEM_STATS* stats)
{
    word16 i;

    if (stats == NULL) {
        return 0;
    }

    /* print to stderr so is on the same pipe as WOLFSSL_DEBUG */
    fprintf(stderr, "Total mallocs   = %d\n", stats->totalAlloc);
    fprintf(stderr, "Total frees     = %d\n", stats->totalFr);
    fprintf(stderr, "Current mallocs = %d\n", stats->curAlloc);
    fprintf(stderr, "Available IO    = %d\n", stats->avaIO);
    fprintf(stderr, "Max con. handshakes  = %d\n", stats->maxHa);
    fprintf(stderr, "Max con. IO          = %d\n", stats->maxIO);
    fprintf(stderr, "State of memory blocks: size   : available \n");
    for (i = 0; i < WOLFMEM_MAX_BUCKETS; i++) {
       fprintf(stderr, "                      : %d\t : %d\n", stats->blockSz[i],
                                                            stats->avaBlock[i]);
    }

    return 1;
}

static WC_INLINE int wolfSSL_PrintStatsConn(WOLFSSL_MEM_CONN_STATS* stats)
{
    if (stats == NULL) {
        return 0;
    }

    fprintf(stderr, "peak connection memory = %d\n", stats->peakMem);
    fprintf(stderr, "current memory in use  = %d\n", stats->curMem);
    fprintf(stderr, "peak connection allocs = %d\n", stats->peakAlloc);
    fprintf(stderr, "current connection allocs = %d\n",stats->curAlloc);
    fprintf(stderr, "total connection allocs   = %d\n", stats->totalAlloc);
    fprintf(stderr, "total connection frees    = %d\n\n", stats->totalFr);

    return 1;
}
#endif /* WOLFSSL_STATIC_MEMORY */

#ifdef HAVE_PK_CALLBACKS

typedef struct PkCbInfo {
    const char* ourKey;
#ifdef TEST_PK_PRIVKEY
    union {
    #ifdef HAVE_ECC
        /* only ECC PK callback with TLS v1.2 needs this */
        ecc_key ecc;
    #endif
    } keyGen;
    int hasKeyGen;
#endif
} PkCbInfo;

#ifdef HAVE_ECC

static WC_INLINE int myEccKeyGen(WOLFSSL* ssl, ecc_key* key, word32 keySz,
    int ecc_curve, void* ctx)
{
    int       ret;
    PkCbInfo* cbInfo = (PkCbInfo*)ctx;
    ecc_key*  new_key;

#ifdef TEST_PK_PRIVKEY
    new_key = cbInfo ? &cbInfo->keyGen.ecc : key;
#else
    new_key = key;
#endif

    (void)ssl;
    (void)cbInfo;

    WOLFSSL_PKMSG("PK ECC KeyGen: keySz %u, Curve ID %d\n", keySz, ecc_curve);

    ret = wc_ecc_init(new_key);
    if (ret == 0) {
        WC_RNG *rng = wolfSSL_GetRNG(ssl);

        /* create new key */
        ret = wc_ecc_make_key_ex(rng, (int) keySz, new_key, ecc_curve);

    #ifdef TEST_PK_PRIVKEY
        if (ret == 0 && new_key != key) {
            byte qx[MAX_ECC_BYTES], qy[MAX_ECC_BYTES];
            word32 qxLen = sizeof(qx), qyLen = sizeof(qy);

            /* extract public portion from new key into `key` arg */
            ret = wc_ecc_export_public_raw(new_key, qx, &qxLen, qy, &qyLen);
            if (ret == 0) {
                /* load public portion only into key */
                ret = wc_ecc_import_unsigned(key, qx, qy, NULL, ecc_curve);
            }
            (void)qxLen;
            (void)qyLen;
        }
        if (ret == 0 && cbInfo != NULL) {
            cbInfo->hasKeyGen = 1;
        }
    #endif
    }

    WOLFSSL_PKMSG("PK ECC KeyGen: ret %d\n", ret);

    return ret;
}

static WC_INLINE int myEccSign(WOLFSSL* ssl, const byte* in, word32 inSz,
        byte* out, word32* outSz, const byte* key, word32 keySz, void* ctx)
{
    int       ret;
    word32    idx = 0;
    ecc_key   myKey;
    byte*     keyBuf = (byte*)key;
    PkCbInfo* cbInfo = (PkCbInfo*)ctx;

    (void)ssl;
    (void)cbInfo;

    WOLFSSL_PKMSG("PK ECC Sign: inSz %u, keySz %u\n", inSz, keySz);

#ifdef TEST_PK_PRIVKEY
    ret = load_key_file(cbInfo->ourKey, &keyBuf, &keySz);
    if (ret != 0)
        return ret;
#endif

    ret = wc_ecc_init(&myKey);
    if (ret == 0) {
        ret = wc_EccPrivateKeyDecode(keyBuf, &idx, &myKey, keySz);
        if (ret == 0) {
            WC_RNG *rng = wolfSSL_GetRNG(ssl);

            WOLFSSL_PKMSG("PK ECC Sign: Curve ID %d\n", myKey.dp->id);
            ret = wc_ecc_sign_hash(in, inSz, out, outSz, rng, &myKey);
        }
        wc_ecc_free(&myKey);
    }

#ifdef TEST_PK_PRIVKEY
    free(keyBuf);
#endif

    WOLFSSL_PKMSG("PK ECC Sign: ret %d outSz %u\n", ret, *outSz);

    return ret;
}


static WC_INLINE int myEccVerify(WOLFSSL* ssl, const byte* sig, word32 sigSz,
        const byte* hash, word32 hashSz, const byte* key, word32 keySz,
        int* result, void* ctx)
{
    int       ret;
    word32    idx = 0;
    ecc_key   myKey;
    PkCbInfo* cbInfo = (PkCbInfo*)ctx;

    (void)ssl;
    (void)cbInfo;

    WOLFSSL_PKMSG("PK ECC Verify: sigSz %u, hashSz %u, keySz %u\n", sigSz, hashSz, keySz);

    ret = wc_ecc_init(&myKey);
    if (ret == 0) {
        ret = wc_EccPublicKeyDecode(key, &idx, &myKey, keySz);
        if (ret == 0)
            ret = wc_ecc_verify_hash(sig, sigSz, hash, hashSz, result, &myKey);
        wc_ecc_free(&myKey);
    }

    WOLFSSL_PKMSG("PK ECC Verify: ret %d, result %d\n", ret, *result);

    return ret;
}

static WC_INLINE int myEccSharedSecret(WOLFSSL* ssl, ecc_key* otherKey,
        unsigned char* pubKeyDer, unsigned int* pubKeySz,
        unsigned char* out, unsigned int* outlen,
        int side, void* ctx)
{
    int       ret;
    ecc_key*  privKey = NULL;
    ecc_key*  pubKey = NULL;
    ecc_key   tmpKey;
    PkCbInfo* cbInfo = (PkCbInfo*)ctx;

    (void)ssl;
    (void)cbInfo;

    WOLFSSL_PKMSG("PK ECC PMS: Side %s, Peer Curve %d\n",
        side == WOLFSSL_CLIENT_END ? "client" : "server", otherKey->dp->id);

    ret = wc_ecc_init(&tmpKey);
    if (ret != 0) {
        return ret;
    }

    /* for client: create and export public key */
    if (side == WOLFSSL_CLIENT_END) {
    #ifdef TEST_PK_PRIVKEY
        privKey = cbInfo ? &cbInfo->keyGen.ecc : &tmpKey;
    #else
        privKey = &tmpKey;
    #endif
        pubKey = otherKey;

        /* TLS v1.2 and older we must generate a key here for the client only.
         * TLS v1.3 calls key gen early with key share */
        if (wolfSSL_GetVersion(ssl) < WOLFSSL_TLSV1_3) {
            ret = myEccKeyGen(ssl, privKey, 0, otherKey->dp->id, ctx);
            if (ret == 0) {
                ret = wc_ecc_export_x963(privKey, pubKeyDer, pubKeySz);
            }
        }
    }

    /* for server: import public key */
    else if (side == WOLFSSL_SERVER_END) {
    #ifdef TEST_PK_PRIVKEY
        privKey = cbInfo ? &cbInfo->keyGen.ecc : otherKey;
    #else
        privKey = otherKey;
    #endif
        pubKey = &tmpKey;

        ret = wc_ecc_import_x963_ex(pubKeyDer, *pubKeySz, pubKey,
            otherKey->dp->id);
    }
    else {
        ret = BAD_FUNC_ARG;
    }

    if (privKey == NULL || pubKey == NULL) {
        ret = BAD_FUNC_ARG;
    }

#if defined(ECC_TIMING_RESISTANT) && (!defined(HAVE_FIPS) || \
    (!defined(HAVE_FIPS_VERSION) || (HAVE_FIPS_VERSION != 2))) && \
    !defined(HAVE_SELFTEST)
    if (ret == 0) {
        ret = wc_ecc_set_rng(privKey, wolfSSL_GetRNG(ssl));
    }
#endif

    /* generate shared secret and return it */
    if (ret == 0) {
        ret = wc_ecc_shared_secret(privKey, pubKey, out, outlen);

    #ifdef WOLFSSL_ASYNC_CRYPT
        if (ret == WC_PENDING_E) {
            ret = wc_AsyncWait(ret, &privKey->asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
        }
    #endif
    }

#ifdef TEST_PK_PRIVKEY
    if (cbInfo && cbInfo->hasKeyGen) {
        wc_ecc_free(&cbInfo->keyGen.ecc);
        cbInfo->hasKeyGen = 0;
    }
#endif

    wc_ecc_free(&tmpKey);

    WOLFSSL_PKMSG("PK ECC PMS: ret %d, PubKeySz %u, OutLen %u\n", ret, *pubKeySz, *outlen);

    return ret;
}

#endif /* HAVE_ECC */

#if defined(HAVE_HKDF) && !defined(NO_HMAC)
static WC_INLINE int myHkdfExtract(byte* prk, const byte* salt, word32 saltLen,
       byte* ikm, word32 ikmLen, int digest, void* ctx)
{
    int ret;
    word32 len = 0;

    switch (digest) {
#ifndef NO_SHA256
        case WC_SHA256:
            len = WC_SHA256_DIGEST_SIZE;
            break;
#endif

#ifdef WOLFSSL_SHA384
        case WC_SHA384:
            len = WC_SHA384_DIGEST_SIZE;
            break;
#endif

#ifdef WOLFSSL_TLS13_SHA512
        case WC_SHA512:
            len = WC_SHA512_DIGEST_SIZE;
            break;
#endif
        default:
            return BAD_FUNC_ARG;
    }

    /* When length is 0 then use zeroed data of digest length. */
    if (ikmLen == 0) {
        ikmLen = len;
        XMEMSET(ikm, 0, len);
    }

    (void)ctx;
    ret = wc_HKDF_Extract(digest, salt, saltLen, ikm, ikmLen, prk);
    WOLFSSL_PKMSG("PK HKDF Extract: ret %d saltLen %d ikmLen %d\n", ret, saltLen,
            ikmLen);
    return ret;
}
#endif /* HAVE_HKDF && !NO_HMAC */

#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_IMPORT)
#ifdef HAVE_ED25519_SIGN
static WC_INLINE int myEd25519Sign(WOLFSSL* ssl, const byte* in, word32 inSz,
        byte* out, word32* outSz, const byte* key, word32 keySz, void* ctx)
{
    int         ret;
    word32      idx = 0;
    ed25519_key myKey;
    byte*       keyBuf = (byte*)key;
    PkCbInfo*   cbInfo = (PkCbInfo*)ctx;

    (void)ssl;
    (void)cbInfo;

    WOLFSSL_PKMSG("PK 25519 Sign: inSz %d, keySz %d\n", inSz, keySz);

#ifdef TEST_PK_PRIVKEY
    ret = load_key_file(cbInfo->ourKey, &keyBuf, &keySz);
    if (ret != 0)
        return ret;
#endif

    ret = wc_ed25519_init(&myKey);
    if (ret == 0) {
        ret = wc_Ed25519PrivateKeyDecode(keyBuf, &idx, &myKey, keySz);
        if (ret == 0) {
            ret = wc_ed25519_make_public(&myKey, myKey.p, ED25519_PUB_KEY_SIZE);
        }
        if (ret == 0) {
            myKey.pubKeySet = 1;
            ret = wc_ed25519_sign_msg(in, inSz, out, outSz, &myKey);
        }
        wc_ed25519_free(&myKey);
    }

#ifdef TEST_PK_PRIVKEY
    free(keyBuf);
#endif

    WOLFSSL_PKMSG("PK 25519 Sign: ret %d, outSz %d\n", ret, *outSz);

    return ret;
}
#endif /* HAVE_ED25519_SIGN */


#ifdef HAVE_ED25519_VERIFY
static WC_INLINE int myEd25519Verify(WOLFSSL* ssl, const byte* sig, word32 sigSz,
        const byte* msg, word32 msgSz, const byte* key, word32 keySz,
        int* result, void* ctx)
{
    int         ret;
    ed25519_key myKey;
    PkCbInfo* cbInfo = (PkCbInfo*)ctx;

    (void)ssl;
    (void)cbInfo;

    WOLFSSL_PKMSG("PK 25519 Verify: sigSz %d, msgSz %d, keySz %d\n", sigSz, msgSz, keySz);

    ret = wc_ed25519_init(&myKey);
    if (ret == 0) {
        ret = wc_ed25519_import_public(key, keySz, &myKey);
        if (ret == 0) {
            ret = wc_ed25519_verify_msg(sig, sigSz, msg, msgSz, result, &myKey);
        }
        wc_ed25519_free(&myKey);
    }

    WOLFSSL_PKMSG("PK 25519 Verify: ret %d, result %d\n", ret, *result);

    return ret;
}
#endif /* HAVE_ED25519_VERIFY */
#endif /* HAVE_ED25519 && HAVE_ED25519_KEY_IMPORT */

#ifdef HAVE_CURVE25519
static WC_INLINE int myX25519KeyGen(WOLFSSL* ssl, curve25519_key* key,
    unsigned int keySz, void* ctx)
{
    int       ret;
    WC_RNG    rng;
    PkCbInfo* cbInfo = (PkCbInfo*)ctx;

    (void)ssl;
    (void)cbInfo;

    WOLFSSL_PKMSG("PK 25519 KeyGen: keySz %u\n", keySz);

    ret = wc_InitRng(&rng);
    if (ret != 0)
        return ret;

    ret = wc_curve25519_make_key(&rng, (int) keySz, key);

    wc_FreeRng(&rng);

    WOLFSSL_PKMSG("PK 25519 KeyGen: ret %d\n", ret);

    return ret;
}

static WC_INLINE int myX25519SharedSecret(WOLFSSL* ssl, curve25519_key* otherKey,
        unsigned char* pubKeyDer, unsigned int* pubKeySz,
        unsigned char* out, unsigned int* outlen,
        int side, void* ctx)
{
    int      ret;
    curve25519_key* privKey = NULL;
    curve25519_key* pubKey = NULL;
    curve25519_key  tmpKey;
    PkCbInfo* cbInfo = (PkCbInfo*)ctx;

    (void)ssl;
    (void)cbInfo;

    WOLFSSL_PKMSG("PK 25519 PMS: side %s\n",
        side == WOLFSSL_CLIENT_END ? "client" : "server");

    ret = wc_curve25519_init(&tmpKey);
    if (ret != 0) {
        return ret;
    }

    /* for client: create and export public key */
    if (side == WOLFSSL_CLIENT_END) {
        WC_RNG rng;

        privKey = &tmpKey;
        pubKey = otherKey;

        ret = wc_InitRng(&rng);
        if (ret == 0) {
            ret = wc_curve25519_make_key(&rng, CURVE25519_KEYSIZE, privKey);
            if (ret == 0) {
                ret = wc_curve25519_export_public_ex(privKey, pubKeyDer,
                    pubKeySz, EC25519_LITTLE_ENDIAN);
            }
            wc_FreeRng(&rng);
        }
    }

    /* for server: import public key */
    else if (side == WOLFSSL_SERVER_END) {
        privKey = otherKey;
        pubKey = &tmpKey;

        ret = wc_curve25519_import_public_ex(pubKeyDer, *pubKeySz, pubKey,
            EC25519_LITTLE_ENDIAN);
    }
    else {
        ret = BAD_FUNC_ARG;
    }

    /* generate shared secret and return it */
    if (ret == 0) {
        ret = wc_curve25519_shared_secret_ex(privKey, pubKey, out, outlen,
            EC25519_LITTLE_ENDIAN);
    }

    wc_curve25519_free(&tmpKey);

    WOLFSSL_PKMSG("PK 25519 PMS: ret %d, pubKeySz %u, outLen %u\n",
        ret, *pubKeySz, *outlen);

    return ret;
}
#endif /* HAVE_CURVE25519 */

#if defined(HAVE_ED448) && defined(HAVE_ED448_KEY_IMPORT)
#ifdef HAVE_ED448_SIGN
static WC_INLINE int myEd448Sign(WOLFSSL* ssl, const byte* in, word32 inSz,
        byte* out, word32* outSz, const byte* key, word32 keySz, void* ctx)
{
    int         ret;
    word32      idx = 0;
    ed448_key   myKey;
    byte*       keyBuf = (byte*)key;
    PkCbInfo*   cbInfo = (PkCbInfo*)ctx;

    (void)ssl;
    (void)cbInfo;

    WOLFSSL_PKMSG("PK 448 Sign: inSz %u, keySz %u\n", inSz, keySz);

#ifdef TEST_PK_PRIVKEY
    ret = load_key_file(cbInfo->ourKey, &keyBuf, &keySz);
    if (ret != 0)
        return ret;
#endif

    ret = wc_ed448_init(&myKey);
    if (ret == 0) {
        ret = wc_Ed448PrivateKeyDecode(keyBuf, &idx, &myKey, keySz);
        if (ret == 0) {
            ret = wc_ed448_make_public(&myKey, myKey.p, ED448_PUB_KEY_SIZE);
        }
        if (ret == 0) {
            myKey.pubKeySet = 1;
            ret = wc_ed448_sign_msg(in, inSz, out, outSz, &myKey, NULL, 0);
        }
        wc_ed448_free(&myKey);
    }

#ifdef TEST_PK_PRIVKEY
    free(keyBuf);
#endif

    WOLFSSL_PKMSG("PK 448 Sign: ret %d, outSz %u\n", ret, *outSz);

    return ret;
}
#endif /* HAVE_ED448_SIGN */


#ifdef HAVE_ED448_VERIFY
static WC_INLINE int myEd448Verify(WOLFSSL* ssl, const byte* sig, word32 sigSz,
        const byte* msg, word32 msgSz, const byte* key, word32 keySz,
        int* result, void* ctx)
{
    int         ret;
    ed448_key   myKey;
    PkCbInfo*   cbInfo = (PkCbInfo*)ctx;

    (void)ssl;
    (void)cbInfo;

    WOLFSSL_PKMSG("PK 448 Verify: sigSz %u, msgSz %u, keySz %u\n", sigSz, msgSz,
                  keySz);

    ret = wc_ed448_init(&myKey);
    if (ret == 0) {
        ret = wc_ed448_import_public(key, keySz, &myKey);
        if (ret == 0) {
            ret = wc_ed448_verify_msg(sig, sigSz, msg, msgSz, result, &myKey,
                                                                       NULL, 0);
        }
        wc_ed448_free(&myKey);
    }

    WOLFSSL_PKMSG("PK 448 Verify: ret %d, result %d\n", ret, *result);

    return ret;
}
#endif /* HAVE_ED448_VERIFY */
#endif /* HAVE_ED448 && HAVE_ED448_KEY_IMPORT */

#ifdef HAVE_CURVE448
static WC_INLINE int myX448KeyGen(WOLFSSL* ssl, curve448_key* key,
    unsigned int keySz, void* ctx)
{
    int       ret;
    WC_RNG    rng;
    PkCbInfo* cbInfo = (PkCbInfo*)ctx;

    (void)ssl;
    (void)cbInfo;

    WOLFSSL_PKMSG("PK 448 KeyGen: keySz %u\n", keySz);

    ret = wc_InitRng(&rng);
    if (ret != 0)
        return ret;

    ret = wc_curve448_make_key(&rng, (int) keySz, key);

    wc_FreeRng(&rng);

    WOLFSSL_PKMSG("PK 448 KeyGen: ret %d\n", ret);

    return ret;
}

static WC_INLINE int myX448SharedSecret(WOLFSSL* ssl, curve448_key* otherKey,
        unsigned char* pubKeyDer, unsigned int* pubKeySz,
        unsigned char* out, unsigned int* outlen,
        int side, void* ctx)
{
    int           ret;
    curve448_key* privKey = NULL;
    curve448_key* pubKey = NULL;
    curve448_key  tmpKey;
    PkCbInfo*     cbInfo = (PkCbInfo*)ctx;

    (void)ssl;
    (void)cbInfo;

    WOLFSSL_PKMSG("PK 448 PMS: side %s\n",
        side == WOLFSSL_CLIENT_END ? "client" : "server");

    ret = wc_curve448_init(&tmpKey);
    if (ret != 0) {
        return ret;
    }

    /* for client: create and export public key */
    if (side == WOLFSSL_CLIENT_END) {
        WC_RNG rng;

        privKey = &tmpKey;
        pubKey = otherKey;

        ret = wc_InitRng(&rng);
        if (ret == 0) {
            ret = wc_curve448_make_key(&rng, CURVE448_KEY_SIZE, privKey);
            if (ret == 0) {
                ret = wc_curve448_export_public_ex(privKey, pubKeyDer,
                    pubKeySz, EC448_LITTLE_ENDIAN);
            }
            wc_FreeRng(&rng);
        }
    }

    /* for server: import public key */
    else if (side == WOLFSSL_SERVER_END) {
        privKey = otherKey;
        pubKey = &tmpKey;

        ret = wc_curve448_import_public_ex(pubKeyDer, *pubKeySz, pubKey,
            EC448_LITTLE_ENDIAN);
    }
    else {
        ret = BAD_FUNC_ARG;
    }

    /* generate shared secret and return it */
    if (ret == 0) {
        ret = wc_curve448_shared_secret_ex(privKey, pubKey, out, outlen,
            EC448_LITTLE_ENDIAN);
    }

    wc_curve448_free(&tmpKey);

    WOLFSSL_PKMSG("PK 448 PMS: ret %d, pubKeySz %u, outLen %u\n",
        ret, *pubKeySz, *outlen);

    return ret;
}
#endif /* HAVE_CURVE448 */

#ifndef NO_DH
static WC_INLINE int myDhCallback(WOLFSSL* ssl, struct DhKey* key,
        const unsigned char* priv, unsigned int privSz,
        const unsigned char* pubKeyDer, unsigned int pubKeySz,
        unsigned char* out, unsigned int* outlen,
        void* ctx)
{
    int ret;
    PkCbInfo* cbInfo = (PkCbInfo*)ctx;

    (void)ssl;
    (void)cbInfo;

    /* return 0 on success */
    ret = wc_DhAgree(key, out, outlen, priv, privSz, pubKeyDer, pubKeySz);

    WOLFSSL_PKMSG("PK ED Agree: ret %d, privSz %u, pubKeySz %u, outlen %u\n",
        ret, privSz, pubKeySz, *outlen);

    return ret;
}

#endif /* !NO_DH */

#ifndef NO_RSA

static WC_INLINE int myRsaSign(WOLFSSL* ssl, const byte* in, word32 inSz,
        byte* out, word32* outSz, const byte* key, word32 keySz, void* ctx)
{
    WC_RNG  rng;
    int     ret;
    word32  idx = 0;
    RsaKey  myKey;
    byte*   keyBuf = (byte*)key;
    PkCbInfo* cbInfo = (PkCbInfo*)ctx;

    (void)ssl;
    (void)cbInfo;

    WOLFSSL_PKMSG("PK RSA Sign: inSz %u, keySz %u\n", inSz, keySz);

#ifdef TEST_PK_PRIVKEY
    ret = load_key_file(cbInfo->ourKey, &keyBuf, &keySz);
    if (ret != 0)
        return ret;
#endif

    ret = wc_InitRng(&rng);
    if (ret != 0)
        return ret;

    ret = wc_InitRsaKey(&myKey, NULL);
    if (ret == 0) {
        ret = wc_RsaPrivateKeyDecode(keyBuf, &idx, &myKey, keySz);
        if (ret == 0)
            ret = wc_RsaSSL_Sign(in, inSz, out, *outSz, &myKey, &rng);
        if (ret > 0) {  /* save and convert to 0 success */
            *outSz = (word32) ret;
            ret = 0;
        }
        wc_FreeRsaKey(&myKey);
    }
    wc_FreeRng(&rng);

#ifdef TEST_PK_PRIVKEY
    free(keyBuf);
#endif

    WOLFSSL_PKMSG("PK RSA Sign: ret %d, outSz %u\n", ret, *outSz);

    return ret;
}


static WC_INLINE int myRsaVerify(WOLFSSL* ssl, byte* sig, word32 sigSz,
        byte** out, const byte* key, word32 keySz, void* ctx)
{
    int     ret;
    word32  idx = 0;
    RsaKey  myKey;
    PkCbInfo* cbInfo = (PkCbInfo*)ctx;

    (void)ssl;
    (void)cbInfo;

    WOLFSSL_PKMSG("PK RSA Verify: sigSz %u, keySz %u\n", sigSz, keySz);

    ret = wc_InitRsaKey(&myKey, NULL);
    if (ret == 0) {
        ret = wc_RsaPublicKeyDecode(key, &idx, &myKey, keySz);
        if (ret == 0)
            ret = wc_RsaSSL_VerifyInline(sig, sigSz, out, &myKey);
        wc_FreeRsaKey(&myKey);
    }

    WOLFSSL_PKMSG("PK RSA Verify: ret %d\n", ret);

    return ret;
}

static WC_INLINE int myRsaSignCheck(WOLFSSL* ssl, byte* sig, word32 sigSz,
        byte** out, const byte* key, word32 keySz, void* ctx)
{
    int     ret;
    word32  idx = 0;
    RsaKey  myKey;
    byte*   keyBuf = (byte*)key;
    PkCbInfo* cbInfo = (PkCbInfo*)ctx;

    (void)ssl;
    (void)cbInfo;

    WOLFSSL_PKMSG("PK RSA SignCheck: sigSz %u, keySz %u\n", sigSz, keySz);

#ifdef TEST_PK_PRIVKEY
    ret = load_key_file(cbInfo->ourKey, &keyBuf, &keySz);
    if (ret != 0)
        return ret;
#endif

    ret = wc_InitRsaKey(&myKey, NULL);
    if (ret == 0) {
        ret = wc_RsaPrivateKeyDecode(keyBuf, &idx, &myKey, keySz);
        if (ret == 0)
            ret = wc_RsaSSL_VerifyInline(sig, sigSz, out, &myKey);
        wc_FreeRsaKey(&myKey);
    }
#ifdef TEST_PK_PRIVKEY
    free(keyBuf);
#endif

    WOLFSSL_PKMSG("PK RSA SignCheck: ret %d\n", ret);

    return ret;
}

#ifdef WC_RSA_PSS
static WC_INLINE int myRsaPssSign(WOLFSSL* ssl, const byte* in, word32 inSz,
        byte* out, word32* outSz, int hash, int mgf, const byte* key,
        word32 keySz, void* ctx)
{
    enum wc_HashType hashType = WC_HASH_TYPE_NONE;
    WC_RNG           rng;
    int              ret = 0;
    word32           idx = 0;
    RsaKey           myKey;
    byte*            inBuf = (byte*)in;
    word32           inBufSz = inSz;
    byte*            keyBuf = (byte*)key;
    PkCbInfo* cbInfo = (PkCbInfo*)ctx;

    (void)ssl;
    (void)cbInfo;

    WOLFSSL_PKMSG("PK RSA PSS Sign: inSz %u, hash %d, mgf %d, keySz %u\n",
        inSz, hash, mgf, keySz);

#ifdef TEST_PK_PRIVKEY
    ret = load_key_file(cbInfo->ourKey, &keyBuf, &keySz);
    if (ret != 0)
        return ret;
#endif

    switch (hash) {
#ifndef NO_SHA256
        case SHA256h:
            hashType = WC_HASH_TYPE_SHA256;
            break;
#endif
#ifdef WOLFSSL_SHA384
        case SHA384h:
            hashType = WC_HASH_TYPE_SHA384;
            break;
#endif
#ifdef WOLFSSL_SHA512
        case SHA512h:
            hashType = WC_HASH_TYPE_SHA512;
            break;
#endif
    }

    ret = wc_InitRng(&rng);
    if (ret != 0)
        return ret;

    #ifdef TLS13_RSA_PSS_SIGN_CB_NO_PREHASH
        /* With this defined, RSA-PSS sign callback when used from TLS 1.3
         * does not hash data before giving to this callback. User must
         * compute hash themselves. */
        if (wolfSSL_GetVersion(ssl) == WOLFSSL_TLSV1_3) {
            inBufSz = wc_HashGetDigestSize(hashType);
            inBuf = (byte*)XMALLOC(inBufSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (inBuf == NULL) {
                ret = MEMORY_E;
            }
            if (ret == 0) {
                ret = wc_Hash(hashType, in, inSz, inBuf, inBufSz);
            }
        }
    #endif

    if (ret == 0) {
        ret = wc_InitRsaKey(&myKey, NULL);
    }
    if (ret == 0) {
        ret = wc_RsaPrivateKeyDecode(keyBuf, &idx, &myKey, keySz);
        if (ret == 0) {
            ret = wc_RsaPSS_Sign(inBuf, inBufSz, out, *outSz, hashType, mgf,
                                 &myKey, &rng);
        }
        if (ret > 0) {  /* save and convert to 0 success */
            *outSz = (word32) ret;
            ret = 0;
        }
    #ifdef TLS13_RSA_PSS_SIGN_CB_NO_PREHASH
        if ((inBuf != NULL) && (wolfSSL_GetVersion(ssl) == WOLFSSL_TLSV1_3)) {
            XFREE(inBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
    #endif
        wc_FreeRsaKey(&myKey);
    }
    wc_FreeRng(&rng);

#ifdef TEST_PK_PRIVKEY
    free(keyBuf);
#endif

    WOLFSSL_PKMSG("PK RSA PSS Sign: ret %d, outSz %u\n", ret, *outSz);

    return ret;
}


static WC_INLINE int myRsaPssVerify(WOLFSSL* ssl, byte* sig, word32 sigSz,
        byte** out, int hash, int mgf, const byte* key, word32 keySz, void* ctx)
{
    int       ret;
    word32    idx = 0;
    RsaKey    myKey;
    PkCbInfo* cbInfo = (PkCbInfo*)ctx;
    enum wc_HashType hashType = WC_HASH_TYPE_NONE;

    (void)ssl;
    (void)cbInfo;

    WOLFSSL_PKMSG("PK RSA PSS Verify: sigSz %u, hash %d, mgf %d, keySz %u\n",
        sigSz, hash, mgf, keySz);

    switch (hash) {
#ifndef NO_SHA256
        case SHA256h:
            hashType = WC_HASH_TYPE_SHA256;
            break;
#endif
#ifdef WOLFSSL_SHA384
        case SHA384h:
            hashType = WC_HASH_TYPE_SHA384;
            break;
#endif
#ifdef WOLFSSL_SHA512
        case SHA512h:
            hashType = WC_HASH_TYPE_SHA512;
            break;
#endif
    }

    ret = wc_InitRsaKey(&myKey, NULL);
    if (ret == 0) {
        ret = wc_RsaPublicKeyDecode(key, &idx, &myKey, keySz);
        if (ret == 0) {
            ret = wc_RsaPSS_VerifyInline(sig, sigSz, out, hashType, mgf,
                                         &myKey);
            }
        wc_FreeRsaKey(&myKey);
    }

    WOLFSSL_PKMSG("PK RSA PSS Verify: ret %d\n", ret);

    return ret;
}

static WC_INLINE int myRsaPssSignCheck(WOLFSSL* ssl, byte* sig, word32 sigSz,
        byte** out, int hash, int mgf, const byte* key, word32 keySz, void* ctx)
{
    int       ret;
    word32    idx = 0;
    RsaKey    myKey;
    byte*     keyBuf = (byte*)key;
    PkCbInfo* cbInfo = (PkCbInfo*)ctx;
    enum wc_HashType hashType = WC_HASH_TYPE_NONE;

    (void)ssl;
    (void)cbInfo;

    WOLFSSL_PKMSG("PK RSA PSS SignCheck: sigSz %u, hash %d, mgf %d, keySz %u\n",
        sigSz, hash, mgf, keySz);

#ifdef TEST_PK_PRIVKEY
    ret = load_key_file(cbInfo->ourKey, &keyBuf, &keySz);
    if (ret != 0)
        return ret;
#endif

    switch (hash) {
#ifndef NO_SHA256
        case SHA256h:
            hashType = WC_HASH_TYPE_SHA256;
            break;
#endif
#ifdef WOLFSSL_SHA384
        case SHA384h:
            hashType = WC_HASH_TYPE_SHA384;
            break;
#endif
#ifdef WOLFSSL_SHA512
        case SHA512h:
            hashType = WC_HASH_TYPE_SHA512;
            break;
#endif
    }

    ret = wc_InitRsaKey(&myKey, NULL);
    if (ret == 0) {
        ret = wc_RsaPrivateKeyDecode(keyBuf, &idx, &myKey, keySz);
        if (ret == 0) {
            ret = wc_RsaPSS_VerifyInline(sig, sigSz, out, hashType, mgf,
                                         &myKey);
            }
        wc_FreeRsaKey(&myKey);
    }

#ifdef TEST_PK_PRIVKEY
    free(keyBuf);
#endif

    WOLFSSL_PKMSG("PK RSA PSS SignCheck: ret %d\n", ret);

    return ret;
}
#endif


static WC_INLINE int myRsaEnc(WOLFSSL* ssl, const byte* in, word32 inSz,
                           byte* out, word32* outSz, const byte* key,
                           word32 keySz, void* ctx)
{
    int       ret;
    word32    idx = 0;
    RsaKey    myKey;
    WC_RNG    rng;
    PkCbInfo* cbInfo = (PkCbInfo*)ctx;

    (void)ssl;
    (void)cbInfo;

    WOLFSSL_PKMSG("PK RSA Enc: inSz %u, keySz %u\n", inSz, keySz);

    ret = wc_InitRng(&rng);
    if (ret != 0)
        return ret;

    ret = wc_InitRsaKey(&myKey, NULL);
    if (ret == 0) {
        ret = wc_RsaPublicKeyDecode(key, &idx, &myKey, keySz);
        if (ret == 0) {
            ret = wc_RsaPublicEncrypt(in, inSz, out, *outSz, &myKey, &rng);
            if (ret > 0) {
                *outSz = (word32) ret;
                ret = 0;  /* reset to success */
            }
        }
        wc_FreeRsaKey(&myKey);
    }
    wc_FreeRng(&rng);

    WOLFSSL_PKMSG("PK RSA Enc: ret %d, outSz %u\n", ret, *outSz);

    return ret;
}

static WC_INLINE int myRsaDec(WOLFSSL* ssl, byte* in, word32 inSz,
                           byte** out,
                           const byte* key, word32 keySz, void* ctx)
{
    int       ret;
    word32    idx = 0;
    RsaKey    myKey;
    byte*     keyBuf = (byte*)key;
    PkCbInfo* cbInfo = (PkCbInfo*)ctx;

    (void)ssl;
    (void)cbInfo;

    WOLFSSL_PKMSG("PK RSA Dec: inSz %u, keySz %u\n", inSz, keySz);

#ifdef TEST_PK_PRIVKEY
    ret = load_key_file(cbInfo->ourKey, &keyBuf, &keySz);
    if (ret != 0)
        return ret;
#endif

    ret = wc_InitRsaKey(&myKey, NULL);
    if (ret == 0) {
        ret = wc_RsaPrivateKeyDecode(keyBuf, &idx, &myKey, keySz);
        if (ret == 0) {
            #ifdef WC_RSA_BLINDING
                ret = wc_RsaSetRNG(&myKey, wolfSSL_GetRNG(ssl));
                if (ret != 0) {
                    wc_FreeRsaKey(&myKey);
                    return ret;
                }
            #endif
            ret = wc_RsaPrivateDecryptInline(in, inSz, out, &myKey);
        }
        wc_FreeRsaKey(&myKey);
    }

#ifdef TEST_PK_PRIVKEY
    free(keyBuf);
#endif

    WOLFSSL_PKMSG("PK RSA Dec: ret %d\n", ret);

    return ret;
}

#endif /* NO_RSA */

static WC_INLINE int myGenMaster(WOLFSSL* ssl, void* ctx)
{
    int       ret;
    PkCbInfo* cbInfo = (PkCbInfo*)ctx;

    (void)ssl;
    (void)cbInfo;

    WOLFSSL_PKMSG("Gen Master");
    /* fall through to original routine */
    ret = PROTOCOLCB_UNAVAILABLE;
    WOLFSSL_PKMSG("Gen Master: ret %d\n", ret);

    return ret;
}

static WC_INLINE int myGenExtMaster(WOLFSSL* ssl, byte* hash, word32 hashSz,
                                        void* ctx)
{
    int       ret;
    PkCbInfo* cbInfo = (PkCbInfo*)ctx;

    (void)ssl;
    (void)cbInfo;
    (void)hash;
    (void)hashSz;

    WOLFSSL_PKMSG("Gen Extended Master");
    /* fall through to original routine */
    ret = PROTOCOLCB_UNAVAILABLE;
    WOLFSSL_PKMSG("Gen Extended Master: ret %d\n", ret);

    return ret;
}

static WC_INLINE int myGenPreMaster(WOLFSSL* ssl, byte *premaster,
                                                  word32 preSz, void* ctx)
{
    int       ret;
    PkCbInfo* cbInfo = (PkCbInfo*)ctx;

    (void) ssl;
    (void) cbInfo;
    (void) premaster;
    (void) preSz;

    WOLFSSL_PKMSG("Gen Pre-Master Cb");
    /* fall through to original routine */
    ret = PROTOCOLCB_UNAVAILABLE;
    WOLFSSL_PKMSG("Gen Pre-Master Cb: ret %d\n", ret);

    return ret;
}

static WC_INLINE int myGenSessionKey(WOLFSSL* ssl, void* ctx)
{
    int       ret;
    PkCbInfo* cbInfo = (PkCbInfo*)ctx;

    (void)ssl;
    (void)cbInfo;

    WOLFSSL_PKMSG("Gen Master Cb");
    /* fall through to original routine */
    ret = PROTOCOLCB_UNAVAILABLE;
    WOLFSSL_PKMSG("Gen Master Cb: ret %d\n", ret);

    return ret;
}

static WC_INLINE int mySetEncryptKeys(WOLFSSL* ssl, void* ctx)
{
    int       ret;
    PkCbInfo* cbInfo = (PkCbInfo*)ctx;

    (void)ssl;
    (void)cbInfo;

    WOLFSSL_PKMSG("Set Encrypt Keys Cb");
    /* fall through to original routine */
    ret = PROTOCOLCB_UNAVAILABLE;
    WOLFSSL_PKMSG("Set Encrypt Keys Cb: ret %d\n", ret);

    return ret;
}

#if !defined(WOLFSSL_NO_TLS12) && !defined(WOLFSSL_AEAD_ONLY)
static WC_INLINE int myVerifyMac(WOLFSSL *ssl, const byte* message,
                    word32 messageSz, word32 macSz, word32 content, void* ctx)
{
    int       ret;
    PkCbInfo* cbInfo = (PkCbInfo*)ctx;

    (void)ssl;
    (void)message;
    (void)messageSz;
    (void)macSz;
    (void)content;
    (void)cbInfo;

    WOLFSSL_PKMSG("Verify Mac Cb");
    /* fall through to original routine */
    ret = PROTOCOLCB_UNAVAILABLE;
    WOLFSSL_PKMSG("Verify Mac Cb: ret %d\n", ret);

    return ret;
}
#endif

static WC_INLINE int myTlsFinished(WOLFSSL* ssl,
                            const byte *side,
                            const byte *handshake_hash, word32 hashSz,
                            byte *hashes, void* ctx)
{
    int       ret;
    PkCbInfo* cbInfo = (PkCbInfo*)ctx;

    (void)ssl;
    (void)cbInfo;
    (void)side;
    (void)handshake_hash;
    (void)hashSz;
    (void)hashes;

    WOLFSSL_PKMSG("Tls Finished Cb");
    /* fall through to original routine */
    ret = PROTOCOLCB_UNAVAILABLE;
    WOLFSSL_PKMSG("Tls Finished Cb: ret %d\n", ret);

    return ret;
}

static WC_INLINE void SetupPkCallbacks(WOLFSSL_CTX* ctx)
{
    (void)ctx;

    #ifdef HAVE_ECC
        wolfSSL_CTX_SetEccKeyGenCb(ctx, myEccKeyGen);
        wolfSSL_CTX_SetEccSignCb(ctx, myEccSign);
        wolfSSL_CTX_SetEccVerifyCb(ctx, myEccVerify);
        wolfSSL_CTX_SetEccSharedSecretCb(ctx, myEccSharedSecret);
    #endif /* HAVE_ECC */
    #if defined(HAVE_HKDF) && !defined(NO_HMAC)
        wolfSSL_CTX_SetHKDFExtractCb(ctx, myHkdfExtract);
    #endif /* HAVE_HKDF && !NO_HMAC */
    #ifndef NO_DH
        wolfSSL_CTX_SetDhAgreeCb(ctx, myDhCallback);
    #endif
    #if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_IMPORT)
        #ifdef HAVE_ED25519_SIGN
        wolfSSL_CTX_SetEd25519SignCb(ctx, myEd25519Sign);
        #endif
        #ifdef HAVE_ED25519_VERIFY
        wolfSSL_CTX_SetEd25519VerifyCb(ctx, myEd25519Verify);
        #endif
    #endif
    #ifdef HAVE_CURVE25519
        wolfSSL_CTX_SetX25519KeyGenCb(ctx, myX25519KeyGen);
        wolfSSL_CTX_SetX25519SharedSecretCb(ctx, myX25519SharedSecret);
    #endif
    #if defined(HAVE_ED448) && defined(HAVE_ED448_KEY_IMPORT)
        #if defined(HAVE_ED448_SIGN)
        wolfSSL_CTX_SetEd448SignCb(ctx, myEd448Sign);
        #endif
        #if defined(HAVE_ED448_VERIFY)
        wolfSSL_CTX_SetEd448VerifyCb(ctx, myEd448Verify);
        #endif
    #endif
    #ifdef HAVE_CURVE448
        wolfSSL_CTX_SetX448KeyGenCb(ctx, myX448KeyGen);
        wolfSSL_CTX_SetX448SharedSecretCb(ctx, myX448SharedSecret);
    #endif
    #ifndef NO_RSA
        wolfSSL_CTX_SetRsaSignCb(ctx, myRsaSign);
        wolfSSL_CTX_SetRsaVerifyCb(ctx, myRsaVerify);
        wolfSSL_CTX_SetRsaSignCheckCb(ctx, myRsaSignCheck);
        #ifdef WC_RSA_PSS
            wolfSSL_CTX_SetRsaPssSignCb(ctx, myRsaPssSign);
            wolfSSL_CTX_SetRsaPssVerifyCb(ctx, myRsaPssVerify);
            wolfSSL_CTX_SetRsaPssSignCheckCb(ctx, myRsaPssSignCheck);
        #endif
        wolfSSL_CTX_SetRsaEncCb(ctx, myRsaEnc);
        wolfSSL_CTX_SetRsaDecCb(ctx, myRsaDec);
    #endif /* NO_RSA */

    #ifndef NO_CERTS
    wolfSSL_CTX_SetGenMasterSecretCb(ctx, myGenMaster);
    wolfSSL_CTX_SetGenExtMasterSecretCb(ctx, myGenExtMaster);
    wolfSSL_CTX_SetGenPreMasterCb(ctx, myGenPreMaster);
    wolfSSL_CTX_SetGenSessionKeyCb(ctx, myGenSessionKey);
    wolfSSL_CTX_SetEncryptKeysCb(ctx, mySetEncryptKeys);

    #if !defined(WOLFSSL_NO_TLS12) && !defined(WOLFSSL_AEAD_ONLY)
    wolfSSL_CTX_SetVerifyMacCb(ctx, myVerifyMac);
    #endif

    wolfSSL_CTX_SetTlsFinishedCb(ctx, myTlsFinished);
    #endif /* NO_CERTS */
}

static WC_INLINE void SetupPkCallbackContexts(WOLFSSL* ssl, void* myCtx)
{
    #ifdef HAVE_ECC
        wolfSSL_SetEccKeyGenCtx(ssl, myCtx);
        wolfSSL_SetEccSignCtx(ssl, myCtx);
        wolfSSL_SetEccVerifyCtx(ssl, myCtx);
        wolfSSL_SetEccSharedSecretCtx(ssl, myCtx);
    #endif /* HAVE_ECC */
    #ifdef HAVE_HKDF
        wolfSSL_SetHKDFExtractCtx(ssl, myCtx);
    #endif /* HAVE_HKDF */
    #ifndef NO_DH
        wolfSSL_SetDhAgreeCtx(ssl, myCtx);
    #endif
    #ifdef HAVE_ED25519
        wolfSSL_SetEd25519SignCtx(ssl, myCtx);
        wolfSSL_SetEd25519VerifyCtx(ssl, myCtx);
    #endif
    #ifdef HAVE_CURVE25519
        wolfSSL_SetX25519KeyGenCtx(ssl, myCtx);
        wolfSSL_SetX25519SharedSecretCtx(ssl, myCtx);
    #endif
    #ifdef HAVE_ED448
        wolfSSL_SetEd448SignCtx(ssl, myCtx);
        wolfSSL_SetEd448VerifyCtx(ssl, myCtx);
    #endif
    #ifdef HAVE_CURVE448
        wolfSSL_SetX448KeyGenCtx(ssl, myCtx);
        wolfSSL_SetX448SharedSecretCtx(ssl, myCtx);
    #endif
    #ifndef NO_RSA
        wolfSSL_SetRsaSignCtx(ssl, myCtx);
        wolfSSL_SetRsaVerifyCtx(ssl, myCtx);
        #ifdef WC_RSA_PSS
            wolfSSL_SetRsaPssSignCtx(ssl, myCtx);
            wolfSSL_SetRsaPssVerifyCtx(ssl, myCtx);
        #endif
        wolfSSL_SetRsaEncCtx(ssl, myCtx);
        wolfSSL_SetRsaDecCtx(ssl, myCtx);
    #endif /* NO_RSA */

    #ifndef NO_CERTS
    wolfSSL_SetGenMasterSecretCtx(ssl, myCtx);
    wolfSSL_SetGenExtMasterSecretCtx(ssl, myCtx);
    wolfSSL_SetGenPreMasterCtx(ssl, myCtx);
    wolfSSL_SetGenSessionKeyCtx(ssl, myCtx);
    wolfSSL_SetEncryptKeysCtx(ssl, myCtx);

    #if !defined(WOLFSSL_NO_TLS12) && !defined(WOLFSSL_AEAD_ONLY)
    wolfSSL_SetVerifyMacCtx(ssl, myCtx);
    #endif

    wolfSSL_SetTlsFinishedCtx(ssl, myCtx);
    #endif
}

#endif /* HAVE_PK_CALLBACKS */

#ifdef USE_WOLFSSL_IO
static WC_INLINE int SimulateWantWriteIOSendCb(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    static int wantWriteFlag = 1;

    int sd = *(int*)ctx;

    (void)ssl;

    if (!wantWriteFlag)
    {
        int sent;
        wantWriteFlag = 1;

        sent = wolfIO_Send(sd, buf, sz, 0);
        if (sent < 0) {
            int err = errno;

            if (err == SOCKET_EWOULDBLOCK || err == SOCKET_EAGAIN) {
                return WOLFSSL_CBIO_ERR_WANT_WRITE;
            }
            else if (err == SOCKET_ECONNRESET) {
                return WOLFSSL_CBIO_ERR_CONN_RST;
            }
            else if (err == SOCKET_EINTR) {
                return WOLFSSL_CBIO_ERR_ISR;
            }
            else if (err == SOCKET_EPIPE) {
                return WOLFSSL_CBIO_ERR_CONN_CLOSE;
            }
            else {
                return WOLFSSL_CBIO_ERR_GENERAL;
            }
        }

        return sent;
    }
    else
    {
        wantWriteFlag = 0;
        return WOLFSSL_CBIO_ERR_WANT_WRITE;
    }
}
#endif /* USE_WOLFSSL_IO */

#if defined(__hpux__) || defined(__MINGW32__) || defined (WOLFSSL_TIRTOS) \
                      || defined(_MSC_VER)

/* HP/UX doesn't have strsep, needed by test/suites.c */
static WC_INLINE char* strsep(char **stringp, const char *delim)
{
    char* start;
    char* end;

    start = *stringp;
    if (start == NULL)
        return NULL;

    if ((end = strpbrk(start, delim))) {
        *end++ = '\0';
        *stringp = end;
    } else {
        *stringp = NULL;
    }

    return start;
}

#endif /* __hpux__ and others */

/* Create unique filename, len is length of tempfn name, assuming
   len does not include null terminating character,
   num is number of characters in tempfn name to randomize */
static WC_INLINE const char* mymktemp(char *tempfn, int len, int num)
{
    int x, size;
    static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                   "abcdefghijklmnopqrstuvwxyz";
    WC_RNG rng;
    byte   out = 0;

    if (tempfn == NULL || len < 1 || num < 1 || len <= num) {
        fprintf(stderr, "Bad input\n");
        return NULL;
    }

    size = len - 1;

    if (wc_InitRng(&rng) != 0) {
        fprintf(stderr, "InitRng failed\n");
        return NULL;
    }

    for (x = size; x > size - num; x--) {
        if (wc_RNG_GenerateBlock(&rng,(byte*)&out, sizeof(out)) != 0) {
            fprintf(stderr, "RNG_GenerateBlock failed\n");
            return NULL;
        }
        tempfn[x] = alphanum[out % (sizeof(alphanum) - 1)];
    }
    tempfn[len] = '\0';

    wc_FreeRng(&rng);
    (void)rng; /* for WC_NO_RNG case */

    return tempfn;
}



#if defined(HAVE_SESSION_TICKET) && defined(WOLFSSL_NO_DEF_TICKET_ENC_CB) && \
    ((defined(HAVE_CHACHA) && defined(HAVE_POLY1305)) || \
      defined(HAVE_AESGCM))

#define HAVE_TEST_SESSION_TICKET

#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    #include <wolfssl/wolfcrypt/chacha20_poly1305.h>
    #define WOLFSSL_TICKET_KEY_SZ CHACHA20_POLY1305_AEAD_KEYSIZE
#elif defined(HAVE_AESGCM)
    #include <wolfssl/wolfcrypt/aes.h>
    #include <wolfssl/wolfcrypt/wc_encrypt.h> /* AES IV sizes in FIPS mode */
    #define WOLFSSL_TICKET_KEY_SZ AES_256_KEY_SIZE
#endif

typedef struct key_ctx {
    byte name[WOLFSSL_TICKET_NAME_SZ]; /* name for this context */
    byte key[WOLFSSL_TICKET_KEY_SZ];   /* cipher key */
} key_ctx;

static THREAD_LS_T key_ctx myKey_ctx;
static THREAD_LS_T WC_RNG myKey_rng;

static WC_INLINE int TicketInit(void)
{
    int ret = wc_InitRng(&myKey_rng);
    if (ret == 0) {
        ret = wc_RNG_GenerateBlock(&myKey_rng, myKey_ctx.key,
            sizeof(myKey_ctx.key));
    }
    if (ret == 0) {
        ret = wc_RNG_GenerateBlock(&myKey_rng, myKey_ctx.name,
            sizeof(myKey_ctx.name));
    }
    return ret;
}

static WC_INLINE void TicketCleanup(void)
{
    wc_FreeRng(&myKey_rng);
}

typedef enum MyTicketState {
    MY_TICKET_STATE_NONE,
    MY_TICKET_STATE_INIT,
    MY_TICKET_STATE_RNG,
    MY_TICKET_STATE_CIPHER_SETUP,
    MY_TICKET_STATE_CIPHER,
    MY_TICKET_STATE_FINAL
} MyTicketState;
typedef struct MyTicketCtx {
    MyTicketState state;
    byte aad[WOLFSSL_TICKET_NAME_SZ + WOLFSSL_TICKET_IV_SZ + 2];
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    /* chahca20/poly1305 */
#elif defined(HAVE_AESGCM)
    Aes aes;
#endif
} MyTicketCtx;

static WC_INLINE int myTicketEncCb(WOLFSSL* ssl,
                            byte key_name[WOLFSSL_TICKET_NAME_SZ],
                            byte iv[WOLFSSL_TICKET_IV_SZ],
                            byte mac[WOLFSSL_TICKET_MAC_SZ],
                            int enc, byte* ticket, int inLen, int* outLen,
                            void* userCtx)
{
    int ret = 0;
    MyTicketCtx tickCtx_lcl;
    MyTicketCtx* tickCtx = (MyTicketCtx*)userCtx;

    (void)ssl;

    if (tickCtx == NULL) {
        /* for test cases where userCtx is not set use local stack for context */
        XMEMSET(&tickCtx_lcl, 0, sizeof(tickCtx_lcl));
        tickCtx = &tickCtx_lcl;
    }

    switch (tickCtx->state) {
    case MY_TICKET_STATE_NONE:
    case MY_TICKET_STATE_INIT:
    {
        /* encrypt */
        if (enc) {
            XMEMCPY(key_name, myKey_ctx.name, WOLFSSL_TICKET_NAME_SZ);
        }
        else {
            /* see if we know this key */
            if (XMEMCMP(key_name, myKey_ctx.name, WOLFSSL_TICKET_NAME_SZ) != 0) {
                printf("client presented unknown ticket key name %s\n", key_name);
                return WOLFSSL_TICKET_RET_FATAL;
            }
        }
        tickCtx->state = MY_TICKET_STATE_RNG;
    }
    FALL_THROUGH;
    case MY_TICKET_STATE_RNG:
    {
        if (enc) {
            ret = wc_RNG_GenerateBlock(&myKey_rng, iv, WOLFSSL_TICKET_IV_SZ);
            if (ret != 0)
                break;
        }
        tickCtx->state = MY_TICKET_STATE_CIPHER_SETUP;
    }
    FALL_THROUGH;
    case MY_TICKET_STATE_CIPHER_SETUP:
    {
        byte* tmp = tickCtx->aad;
        word16 sLen = XHTONS(inLen);

        /* build aad from key name, iv, and length */
        XMEMCPY(tmp, key_name, WOLFSSL_TICKET_NAME_SZ);
        tmp += WOLFSSL_TICKET_NAME_SZ;
        XMEMCPY(tmp, iv, WOLFSSL_TICKET_IV_SZ);
        tmp += WOLFSSL_TICKET_IV_SZ;
        XMEMCPY(tmp, &sLen, sizeof(sLen));

    #if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    #elif defined(HAVE_AESGCM)
        ret = wc_AesInit(&tickCtx->aes, NULL, INVALID_DEVID);
        if (ret == 0) {
            ret = wc_AesGcmSetKey(&tickCtx->aes, myKey_ctx.key,
                sizeof(myKey_ctx.key));
        }
        if (ret != 0)
            break;
    #endif
        tickCtx->state = MY_TICKET_STATE_CIPHER;
    }
    FALL_THROUGH;
    case MY_TICKET_STATE_CIPHER:
    {
        int aadSz = (int)sizeof(tickCtx->aad);

        /* encrypt */
        if (enc) {
        #if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
            ret = wc_ChaCha20Poly1305_Encrypt(myKey_ctx.key, iv,
                                              tickCtx->aad, aadSz,
                                              ticket, inLen,
                                              ticket,
                                              mac);
        #elif defined(HAVE_AESGCM)
            ret = wc_AesGcmEncrypt(&tickCtx->aes, ticket, ticket, inLen,
                                   iv, GCM_NONCE_MID_SZ, mac, WC_AES_BLOCK_SIZE,
                                   tickCtx->aad, aadSz);
        #endif
        }
        /* decrypt */
        else {
        #if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
            ret = wc_ChaCha20Poly1305_Decrypt(myKey_ctx.key, iv,
                                              tickCtx->aad, aadSz,
                                              ticket, inLen,
                                              mac,
                                              ticket);
        #elif defined(HAVE_AESGCM)
            ret = wc_AesGcmDecrypt(&tickCtx->aes, ticket, ticket, inLen,
                                   iv, GCM_NONCE_MID_SZ, mac, WC_AES_BLOCK_SIZE,
                                   tickCtx->aad, aadSz);
        #endif
        }
        if (ret != 0) {
            break;
        }
        tickCtx->state = MY_TICKET_STATE_FINAL;
    }
    FALL_THROUGH;
    case MY_TICKET_STATE_FINAL:
        *outLen = inLen;  /* no padding in this mode */
        break;
    } /* switch */

#ifdef WOLFSSL_ASYNC_CRYPT
    if (ret == WC_PENDING_E) {
        return ret;
    }
#endif

    /* cleanup */
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
#elif defined(HAVE_AESGCM)
    wc_AesFree(&tickCtx->aes);
#endif

    /* reset context */
    XMEMSET(tickCtx, 0, sizeof(MyTicketCtx));

    return (ret == 0) ? WOLFSSL_TICKET_RET_OK : WOLFSSL_TICKET_RET_REJECT;
}

#endif /* HAVE_SESSION_TICKET && ((HAVE_CHACHA && HAVE_POLY1305) || HAVE_AESGCM) */


static WC_INLINE word16 GetRandomPort(void)
{
    word16 port = 0;

    /* Generate random port for testing */
    WC_RNG rng;
    if (wc_InitRng(&rng) == 0) {
        if (wc_RNG_GenerateBlock(&rng, (byte*)&port, sizeof(port)) == 0) {
            port |= 0xC000; /* Make sure its in the 49152 - 65535 range */
        }
        wc_FreeRng(&rng);
    }
    (void)rng; /* for WC_NO_RNG case */
    return port;
}

#ifdef WOLFSSL_EARLY_DATA
static WC_INLINE void EarlyDataStatus(WOLFSSL* ssl)
{
    int earlyData_status;
#ifdef OPENSSL_EXTRA
    earlyData_status = SSL_get_early_data_status(ssl);
#else
    earlyData_status = wolfSSL_get_early_data_status(ssl);
#endif
    if (earlyData_status < 0) return;

    printf("Early Data was ");

    switch(earlyData_status) {
        case WOLFSSL_EARLY_DATA_NOT_SENT:
                printf("not sent.\n");
                break;
        case WOLFSSL_EARLY_DATA_REJECTED:
                printf("rejected.\n");
                break;
        case WOLFSSL_EARLY_DATA_ACCEPTED:
                printf("accepted\n");
                break;
        default:
                printf("unknown...\n");
    }
}
#endif /* WOLFSSL_EARLY_DATA */

#if defined(HAVE_SESSION_TICKET) || defined (WOLFSSL_DTLS13)
static WC_INLINE int process_handshake_messages(WOLFSSL* ssl, int blocking,
    int* zero_return)
{
    char foo[1];
    int ret = 0;
    int dtls;

    if (zero_return == NULL || ssl == NULL)
        return -1;

    dtls = wolfSSL_dtls(ssl);
    (void)dtls;
    *zero_return = 0;

    if (!blocking) {
        int timeout = DEFAULT_TIMEOUT_SEC;

#ifdef WOLFSSL_DTLS
        if (dtls) {
            timeout = wolfSSL_dtls_get_current_timeout(ssl);

#ifdef WOLFSSL_DTLS13
            if (timeout > 4 && wolfSSL_dtls13_use_quick_timeout(ssl))
                timeout /= 4;
#endif /* WOLFSSL_DTLS13 */
        }
#endif /* WOLFSSL_DTLS */

        ret = tcp_select(wolfSSL_get_fd(ssl), timeout);
        if (ret == TEST_ERROR_READY) {
            err_sys("tcp_select error");
            return -1;
        }

        if (ret == TEST_TIMEOUT) {
#ifdef WOLFSSL_DTLS
            if (dtls) {
                ret = wolfSSL_dtls_got_timeout(ssl);
                if (ret != WOLFSSL_SUCCESS && !wolfSSL_want_write(ssl) &&
                    !wolfSSL_want_read(ssl)) {
                    err_sys("got timeout error");
                    return -1;
                }
            }
#endif /* WOLFSSL_DTLS */
            /* do the peek to detect if the peer closed the connection*/
        }
    }

    ret = wolfSSL_peek(ssl, foo, 0);
    if (ret < 0 && !wolfSSL_want_read(ssl) && !wolfSSL_want_write(ssl)) {
        ret = wolfSSL_get_error(ssl, ret);
        if (ret == WOLFSSL_ERROR_ZERO_RETURN)
            *zero_return = 1;
        return -1;
    }

    return 0;
}
#endif /* HAVE_SESSION_TICKET || WOLFSSL_DTLS13 */

static WC_INLINE void printBuffer(const byte *buf, int size)
{
    int i;
    for (i = 0; i < size; i++)
        printf("%x", buf[i]);
}

#if !defined(NO_FILESYSTEM) && defined(OPENSSL_EXTRA) && \
    defined(DEBUG_UNIT_TEST_CERTS)
void DEBUG_WRITE_CERT_X509(WOLFSSL_X509* x509, const char* fileName);
void DEBUG_WRITE_DER(const byte* der, int derSz, const char* fileName);
#endif

#define DTLS_CID_BUFFER_SIZE 256

static WC_MAYBE_UNUSED void *mymemmem(const void *haystack, size_t haystacklen,
                                      const void *needle, size_t needlelen)
{
    size_t i, j;
    const char* h = (const char*)haystack;
    const char* n = (const char*)needle;
    if (needlelen > haystacklen)
        return NULL;
    for (i = 0; i <= haystacklen - needlelen; i++) {
        for (j = 0; j < needlelen; j++) {
            if (h[i + j] != n[j])
                break;
        }
        if (j == needlelen)
            return (void*)(h + i);
    }
    return NULL;
}

#endif /* wolfSSL_TEST_H */
