/* internal.h
 *
 * Copyright (C) 2006-2013 wolfSSL Inc.
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


#ifndef CYASSL_INT_H
#define CYASSL_INT_H


#include <cyassl/ctaocrypt/types.h>
#include <cyassl/ssl.h>
#include <cyassl/crl.h>
#include <cyassl/ctaocrypt/random.h>
#include <cyassl/ctaocrypt/des3.h>
#include <cyassl/ctaocrypt/hc128.h>
#include <cyassl/ctaocrypt/rabbit.h>
#include <cyassl/ctaocrypt/asn.h>
#include <cyassl/ctaocrypt/md5.h>
#include <cyassl/ctaocrypt/sha.h>
#include <cyassl/ctaocrypt/aes.h>
#include <cyassl/ctaocrypt/camellia.h>
#include <cyassl/ctaocrypt/logging.h>
#ifndef NO_RC4
    #include <cyassl/ctaocrypt/arc4.h>
#endif
#ifdef HAVE_ECC
    #include <cyassl/ctaocrypt/ecc.h>
#endif
#ifndef NO_SHA256
    #include <cyassl/ctaocrypt/sha256.h>
#endif
#ifdef HAVE_OCSP
    #include <cyassl/ocsp.h>
#endif
#ifdef CYASSL_SHA512
    #include <cyassl/ctaocrypt/sha512.h>
#endif

#ifdef HAVE_AESGCM
    #include <cyassl/ctaocrypt/sha512.h>
#endif

#ifdef CYASSL_RIPEMD
    #include <cyassl/ctaocrypt/ripemd.h>
#endif

#ifdef CYASSL_CALLBACKS
    #include <cyassl/callbacks.h>
    #include <signal.h>
#endif

#ifdef USE_WINDOWS_API 
    #ifdef CYASSL_GAME_BUILD
        #include "system/xtl.h"
    #else
        #if defined(_WIN32_WCE) || defined(WIN32_LEAN_AND_MEAN)
            /* On WinCE winsock2.h must be included before windows.h */
            #include <winsock2.h>
        #endif
        #include <windows.h>
    #endif
#elif defined(THREADX)
    #ifndef SINGLE_THREADED
        #include "tx_api.h"
    #endif
#elif defined(MICRIUM)
    /* do nothing, just don't pick Unix */
#elif defined(FREERTOS) || defined(CYASSL_SAFERTOS)
    /* do nothing */
#elif defined(EBSNET)
    /* do nothing */
#elif defined(FREESCALE_MQX)
    /* do nothing */
#elif defined(CYASSL_MDK_ARM)
    #include <rtl.h>
#else
    #ifndef SINGLE_THREADED
        #define CYASSL_PTHREADS
        #include <pthread.h>
    #endif
    #if defined(OPENSSL_EXTRA) || defined(GOAHEAD_WS)
        #include <unistd.h>      /* for close of BIO */
    #endif
#endif

#ifdef HAVE_LIBZ
    #include "zlib.h"
#endif

#ifdef _MSC_VER
    /* 4996 warning to use MS extensions e.g., strcpy_s instead of strncpy */
    #pragma warning(disable: 4996)
#endif

#ifdef NO_AES
    #if !defined (ALIGN16)
        #define ALIGN16
    #endif
#endif

#ifdef NO_SHA
    #define SHA_DIGEST_SIZE 20 
#endif

#ifdef NO_SHA256
    #define SHA256_DIGEST_SIZE 32 
#endif


#ifdef __cplusplus
    extern "C" {
#endif


#ifdef USE_WINDOWS_API 
    typedef unsigned int SOCKET_T;
#else
    typedef int SOCKET_T;
#endif


typedef byte word24[3];

/* used by ssl.c and cyassl_int.c */
void c32to24(word32 in, word24 out);

/* Define or comment out the cipher suites you'd like to be compiled in
   make sure to use at least one BUILD_SSL_xxx or BUILD_TLS_xxx is defined

   When adding cipher suites, add name to cipher_names, idx to cipher_name_idx
*/
#if !defined(NO_RSA) && !defined(NO_RC4)
  #if !defined(NO_SHA)
    #define BUILD_SSL_RSA_WITH_RC4_128_SHA
  #endif
    #if !defined(NO_MD5)
        #define BUILD_SSL_RSA_WITH_RC4_128_MD5
    #endif
    #if !defined(NO_TLS) && defined(HAVE_NTRU) && !defined(NO_SHA)
        #define BUILD_TLS_NTRU_RSA_WITH_RC4_128_SHA
    #endif
#endif

#if !defined(NO_RSA) && !defined(NO_DES3)
  #if !defined(NO_SHA)
    #define BUILD_SSL_RSA_WITH_3DES_EDE_CBC_SHA
    #if !defined(NO_TLS) && defined(HAVE_NTRU)
        #define BUILD_TLS_NTRU_RSA_WITH_3DES_EDE_CBC_SHA
    #endif
  #endif
#endif

#if !defined(NO_RSA) && !defined(NO_AES) && !defined(NO_TLS)
  #if !defined(NO_SHA)
    #define BUILD_TLS_RSA_WITH_AES_128_CBC_SHA
    #define BUILD_TLS_RSA_WITH_AES_256_CBC_SHA
    #if defined(HAVE_NTRU)
        #define BUILD_TLS_NTRU_RSA_WITH_AES_128_CBC_SHA
        #define BUILD_TLS_NTRU_RSA_WITH_AES_256_CBC_SHA
    #endif
  #endif
    #if !defined (NO_SHA256)
        #define BUILD_TLS_RSA_WITH_AES_128_CBC_SHA256
        #define BUILD_TLS_RSA_WITH_AES_256_CBC_SHA256
    #endif
    #if defined (HAVE_AESGCM)
        #define BUILD_TLS_RSA_WITH_AES_128_GCM_SHA256
        #if defined (CYASSL_SHA384)
            #define BUILD_TLS_RSA_WITH_AES_256_GCM_SHA384
        #endif
    #endif
    #if defined (HAVE_AESCCM)
        #define BUILD_TLS_RSA_WITH_AES_128_CCM_8
        #define BUILD_TLS_RSA_WITH_AES_256_CCM_8
    #endif
#endif

#if defined(HAVE_CAMELLIA) && !defined(NO_TLS)
    #ifndef NO_RSA
      #if !defined(NO_SHA)
        #define BUILD_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
        #define BUILD_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
      #endif
        #ifndef NO_SHA256
            #define BUILD_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256
            #define BUILD_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256
        #endif
        #if !defined(NO_DH) && defined(OPENSSL_EXTRA)
          #if !defined(NO_SHA)
            #define BUILD_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
            #define BUILD_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
          #endif
            #ifndef NO_SHA256
                #define BUILD_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
                #define BUILD_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256
            #endif
        #endif
    #endif
#endif

#if !defined(NO_PSK) && !defined(NO_AES) && !defined(NO_TLS)
  #if !defined(NO_SHA)
    #define BUILD_TLS_PSK_WITH_AES_128_CBC_SHA
    #define BUILD_TLS_PSK_WITH_AES_256_CBC_SHA
  #endif
    #ifndef NO_SHA256
        #define BUILD_TLS_PSK_WITH_AES_128_CBC_SHA256
        #ifdef HAVE_AESCCM
            #define BUILD_TLS_PSK_WITH_AES_128_CCM_8
            #define BUILD_TLS_PSK_WITH_AES_256_CCM_8
        #endif
    #endif
#endif

#if !defined(NO_TLS) && defined(HAVE_NULL_CIPHER)
    #if !defined(NO_RSA)
      #if !defined(NO_SHA)
        #define BUILD_TLS_RSA_WITH_NULL_SHA
      #endif
      #ifndef NO_SHA256
        #define BUILD_TLS_RSA_WITH_NULL_SHA256
      #endif
    #endif
    #if !defined(NO_PSK)
      #if !defined(NO_SHA)
        #define BUILD_TLS_PSK_WITH_NULL_SHA
      #endif
        #ifndef NO_SHA256
            #define BUILD_TLS_PSK_WITH_NULL_SHA256
        #endif
    #endif
#endif

#if !defined(NO_HC128) && !defined(NO_RSA) && !defined(NO_TLS)
    #define BUILD_TLS_RSA_WITH_HC_128_CBC_MD5
  #if !defined(NO_SHA)
    #define BUILD_TLS_RSA_WITH_HC_128_CBC_SHA
  #endif
#endif

#if !defined(NO_RABBIT) && !defined(NO_TLS) && !defined(NO_RSA)
  #if !defined(NO_SHA)
    #define BUILD_TLS_RSA_WITH_RABBIT_CBC_SHA
  #endif
#endif

#if !defined(NO_DH) && !defined(NO_AES) && !defined(NO_TLS) && \
    !defined(NO_RSA) && defined(OPENSSL_EXTRA)
  #if !defined(NO_SHA)
    #define BUILD_TLS_DHE_RSA_WITH_AES_128_CBC_SHA
    #define BUILD_TLS_DHE_RSA_WITH_AES_256_CBC_SHA
  #endif
    #if !defined (NO_SHA256)
        #define BUILD_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
        #define BUILD_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
        #if defined (HAVE_AESGCM)
            #define BUILD_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
            #if defined (CYASSL_SHA384)
                #define BUILD_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
            #endif
        #endif
    #endif
#endif

#if defined(HAVE_ECC) && !defined(NO_TLS)
    #if !defined(NO_AES)
        #if !defined(NO_SHA)
            #if !defined(NO_RSA)
                #define BUILD_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
                #define BUILD_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
                #define BUILD_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
                #define BUILD_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
            #endif
    
            #define BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
            #define BUILD_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
    
            #define BUILD_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
            #define BUILD_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
        #endif /* NO_SHA */
        #ifndef NO_SHA256
            #if !defined(NO_RSA)
                #define BUILD_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
                #define BUILD_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
            #endif
            #define BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
            #define BUILD_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
        #endif

        #ifdef CYASSL_SHA384
            #if !defined(NO_RSA)
                #define BUILD_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
                #define BUILD_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
            #endif
            #define BUILD_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
            #define BUILD_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
        #endif

        #if defined (HAVE_AESGCM)
            #if !defined(NO_RSA)
                #define BUILD_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                #define BUILD_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
                #if defined(CYASSL_SHA384)
                    #define BUILD_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                    #define BUILD_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
                #endif
            #endif

            #define BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            #define BUILD_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
            
            #if defined(CYASS_SHA384)
                #define BUILD_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                #define BUILD_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
            #endif
        #endif
        #if defined (HAVE_AESCCM)
            #define BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8
            #define BUILD_TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8
        #endif
    #endif /* NO_AES */
    #if !defined(NO_RC4)
        #if !defined(NO_SHA)
            #if !defined(NO_RSA)
                #define BUILD_TLS_ECDHE_RSA_WITH_RC4_128_SHA
                #define BUILD_TLS_ECDH_RSA_WITH_RC4_128_SHA
            #endif

            #define BUILD_TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
            #define BUILD_TLS_ECDH_ECDSA_WITH_RC4_128_SHA
        #endif
    #endif
    #if !defined(NO_DES3)
        #if !defined(NO_RSA)
            #define BUILD_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
            #define BUILD_TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
        #endif

        #define BUILD_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
        #define BUILD_TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
    #endif
#endif


#if defined(BUILD_SSL_RSA_WITH_RC4_128_SHA) || \
    defined(BUILD_SSL_RSA_WITH_RC4_128_MD5)
    #define BUILD_ARC4
#endif

#if defined(BUILD_SSL_RSA_WITH_3DES_EDE_CBC_SHA)
    #define BUILD_DES3
#endif

#if defined(BUILD_TLS_RSA_WITH_AES_128_CBC_SHA) || \
    defined(BUILD_TLS_RSA_WITH_AES_256_CBC_SHA) || \
    defined(BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
    #undef  BUILD_AES
    #define BUILD_AES
#endif

#if defined(BUILD_TLS_RSA_WITH_AES_128_GCM_SHA256) || \
    defined(BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
    #define BUILD_AESGCM
#endif

#if defined(BUILD_TLS_RSA_WITH_HC_128_CBC_SHA) || \
    defined(BUILD_TLS_RSA_WITH_HC_128_CBC_MD5)
    #define BUILD_HC128
#endif

#if defined(BUILD_TLS_RSA_WITH_RABBIT_CBC_SHA)
    #define BUILD_RABBIT
#endif

#ifdef NO_DES3
    #define DES_BLOCK_SIZE 8
#else
    #undef  BUILD_DES3
    #define BUILD_DES3
#endif

#ifdef NO_AES
    #define AES_BLOCK_SIZE 16
#else
    #undef  BUILD_AES
    #define BUILD_AES
#endif

#ifndef NO_RC4
    #undef  BUILD_ARC4
    #define BUILD_ARC4
#endif



#if defined(BUILD_AESGCM) || defined(HAVE_AESCCM)
    #define HAVE_AEAD
#endif


/* actual cipher values, 2nd byte */
enum {
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA  = 0x39,
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA  = 0x33,
    TLS_RSA_WITH_AES_256_CBC_SHA      = 0x35,
    TLS_RSA_WITH_AES_128_CBC_SHA      = 0x2F,
    TLS_RSA_WITH_NULL_SHA             = 0x02,
    TLS_PSK_WITH_AES_256_CBC_SHA      = 0x8d,
    TLS_PSK_WITH_AES_128_CBC_SHA256   = 0xae,
    TLS_PSK_WITH_AES_128_CBC_SHA      = 0x8c,
    TLS_PSK_WITH_NULL_SHA256          = 0xb0,
    TLS_PSK_WITH_NULL_SHA             = 0x2c,
    SSL_RSA_WITH_RC4_128_SHA          = 0x05,
    SSL_RSA_WITH_RC4_128_MD5          = 0x04,
    SSL_RSA_WITH_3DES_EDE_CBC_SHA     = 0x0A,

    /* ECC suites, first byte is 0xC0 (ECC_BYTE) */
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA    = 0x14,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA    = 0x13,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA  = 0x0A,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA  = 0x09,
    TLS_ECDHE_RSA_WITH_RC4_128_SHA        = 0x11,
    TLS_ECDHE_ECDSA_WITH_RC4_128_SHA      = 0x07,
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA   = 0x12,
    TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA = 0x08,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256   = 0x27,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0x23,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384   = 0x28,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = 0x24,

    /* static ECDH, first byte is 0xC0 (ECC_BYTE) */
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA    = 0x0F,
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA    = 0x0E,
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA  = 0x05,
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA  = 0x04,
    TLS_ECDH_RSA_WITH_RC4_128_SHA        = 0x0C,
    TLS_ECDH_ECDSA_WITH_RC4_128_SHA      = 0x02,
    TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA   = 0x0D,
    TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA = 0x03,
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256   = 0x29,
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 = 0x25,
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384   = 0x2A,
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 = 0x26,

    /* CyaSSL extension - eSTREAM */
    TLS_RSA_WITH_HC_128_CBC_MD5       = 0xFB,
    TLS_RSA_WITH_HC_128_CBC_SHA       = 0xFC,
    TLS_RSA_WITH_RABBIT_CBC_SHA       = 0xFD,

    /* CyaSSL extension - NTRU */
    TLS_NTRU_RSA_WITH_RC4_128_SHA      = 0xe5,
    TLS_NTRU_RSA_WITH_3DES_EDE_CBC_SHA = 0xe6,
    TLS_NTRU_RSA_WITH_AES_128_CBC_SHA  = 0xe7,  /* clases w/ official SHA-256 */
    TLS_NTRU_RSA_WITH_AES_256_CBC_SHA  = 0xe8,

    /* SHA256 */
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = 0x6b,
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = 0x67,
    TLS_RSA_WITH_AES_256_CBC_SHA256     = 0x3d,
    TLS_RSA_WITH_AES_128_CBC_SHA256     = 0x3c,
    TLS_RSA_WITH_NULL_SHA256            = 0x3b,

    /* AES-GCM */
    TLS_RSA_WITH_AES_128_GCM_SHA256          = 0x9c,
    TLS_RSA_WITH_AES_256_GCM_SHA384          = 0x9d,
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256      = 0x9e,
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384      = 0x9f,

    /* ECC AES-GCM, first byte is 0xC0 (ECC_BYTE) */
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256  = 0x2b,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384  = 0x2c,
    TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256   = 0x2d,
    TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384   = 0x2e,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256    = 0x2f,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384    = 0x30,
    TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256     = 0x31,
    TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384     = 0x32,

    /* AES-CCM, first byte is 0xC0 but isn't ECC,
     * also, in some of the other AES-CCM suites
     * there will be second byte number conflicts
     * with non-ECC AES-GCM */
    TLS_RSA_WITH_AES_128_CCM_8         = 0xa0,
    TLS_RSA_WITH_AES_256_CCM_8         = 0xa1,
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 = 0xc6, /* Still TBD, made up */
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 = 0xc7, /* Still TBD, made up */
    TLS_PSK_WITH_AES_128_CCM           = 0xa4,
    TLS_PSK_WITH_AES_256_CCM           = 0xa5,
    TLS_PSK_WITH_AES_128_CCM_8         = 0xa8,
    TLS_PSK_WITH_AES_256_CCM_8         = 0xa9,

    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA        = 0x41,
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA        = 0x84,
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256     = 0xba,
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256     = 0xc0,
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA    = 0x45,
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA    = 0x88,
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xbe,
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 0xc4

};


#if defined(CYASSL_SHA384)
    #define MAX_DIGEST_SIZE SHA384_DIGEST_SIZE
#elif !defined(NO_SHA256)
    #define MAX_DIGEST_SIZE SHA256_DIGEST_SIZE
#elif !defined(NO_MD5) && !defined(NO_SHA)
    #define MAX_DIGEST_SIZE (SHA_DIGEST_SIZE + MD5_DIGEST_SIZE)
#else
    #error "You have configured the build so there isn't any hashing."
#endif


enum Misc {
    SERVER_END = 0,
    CLIENT_END,

    ECC_BYTE =  0xC0,           /* ECC first cipher suite byte */

    SEND_CERT       = 1,
    SEND_BLANK_CERT = 2,

    DTLS_MAJOR      = 0xfe,     /* DTLS major version number */
    DTLS_MINOR      = 0xff,     /* DTLS minor version number */
    DTLSv1_2_MINOR  = 0xfd,     /* DTLS minor version number */
    SSLv3_MAJOR     = 3,        /* SSLv3 and TLSv1+  major version number */
    SSLv3_MINOR     = 0,        /* TLSv1   minor version number */
    TLSv1_MINOR     = 1,        /* TLSv1   minor version number */
    TLSv1_1_MINOR   = 2,        /* TLSv1_1 minor version number */
    TLSv1_2_MINOR   = 3,        /* TLSv1_2 minor version number */
    INVALID_BYTE    = 0xff,     /* Used to initialize cipher specs values */
    NO_COMPRESSION  =  0,
    ZLIB_COMPRESSION = 221,     /* CyaSSL zlib compression */
    HELLO_EXT_SIG_ALGO = 13,    /* ID for the sig_algo hello extension */
    SECRET_LEN      = 48,       /* pre RSA and all master */
    ENCRYPT_LEN     = 512,      /* allow 4096 bit static buffer */
    SIZEOF_SENDER   =  4,       /* clnt or srvr           */
    FINISHED_SZ     = 36,       /* MD5_DIGEST_SIZE + SHA_DIGEST_SIZE */
    MAX_RECORD_SIZE = 16384,    /* 2^14, max size by standard */
    MAX_MSG_EXTRA   = 38 + MAX_DIGEST_SIZE,
                                /* max added to msg, mac + pad  from */
                                /* RECORD_HEADER_SZ + BLOCK_SZ (pad) + Max
                                   digest sz + BLOC_SZ (iv) + pad byte (1) */
    MAX_COMP_EXTRA  = 1024,     /* max compression extra */
    MAX_MTU         = 1500,     /* max expected MTU */
    MAX_UDP_SIZE    = 8192 - 100, /* was MAX_MTU - 100 */
    MAX_DH_SZ       = 612,      /* 2240 p, pub, g + 2 byte size for each */
    MAX_STR_VERSION = 8,        /* string rep of protocol version */

    PAD_MD5        = 48,       /* pad length for finished */
    PAD_SHA        = 40,       /* pad length for finished */
    MAX_PAD_SIZE   = 256,      /* maximum length of padding */
    COMPRESS_DUMMY_SIZE = 64,  /* compression dummy round size */
    COMPRESS_CONSTANT   = 13,  /* compression calc constant */
    COMPRESS_UPPER      = 55,  /* compression calc numerator */
    COMPRESS_LOWER      = 64,  /* compression calc denominator */

    PEM_LINE_LEN   = 80,       /* PEM line max + fudge */
    LENGTH_SZ      =  2,       /* length field for HMAC, data only */
    VERSION_SZ     =  2,       /* length of proctocol version */
    SEQ_SZ         =  8,       /* 64 bit sequence number  */
    BYTE3_LEN      =  3,       /* up to 24 bit byte lengths */
    ALERT_SIZE     =  2,       /* level + description     */
    REQUEST_HEADER =  2,       /* always use 2 bytes      */
    VERIFY_HEADER  =  2,       /* always use 2 bytes      */
    EXT_ID_SZ      =  2,       /* always use 2 bytes      */
    MAX_DH_SIZE    = 513,      /* 4096 bit plus possible leading 0 */

    MAX_SUITE_SZ = 200,        /* 100 suites for now! */
    RAN_LEN      = 32,         /* random length           */
    SEED_LEN     = RAN_LEN * 2, /* tls prf seed length    */
    ID_LEN       = 32,         /* session id length       */
    MAX_COOKIE_LEN = 32,       /* max dtls cookie size    */
    COOKIE_SZ    = 20,         /* use a 20 byte cookie    */
    SUITE_LEN    =  2,         /* cipher suite sz length  */
    ENUM_LEN     =  1,         /* always a byte           */
    OPAQUE16_LEN =  2,         /* always 2 bytes          */
    COMP_LEN     =  1,         /* compression length      */
    CURVE_LEN    =  2,         /* ecc named curve length  */
    SERVER_ID_LEN = 20,        /* server session id length  */
    
    HANDSHAKE_HEADER_SZ   = 4,  /* type + length(3)        */
    RECORD_HEADER_SZ      = 5,  /* type + version + len(2) */
    CERT_HEADER_SZ        = 3,  /* always 3 bytes          */
    REQ_HEADER_SZ         = 2,  /* cert request header sz  */
    HINT_LEN_SZ           = 2,  /* length of hint size field */
    HELLO_EXT_TYPE_SZ     = 2,  /* length of a hello extension type */
    HELLO_EXT_SZ          = 8,  /* total length of the lazy hello extensions */
    HELLO_EXT_LEN         = 6,  /* length of the lazy hello extensions */
    HELLO_EXT_SIGALGO_SZ  = 2,  /* length of signature algo extension  */
    HELLO_EXT_SIGALGO_MAX = 32, /* number of items in the signature algo list */

    DTLS_HANDSHAKE_HEADER_SZ = 12, /* normal + seq(2) + offset(3) + length(3) */
    DTLS_RECORD_HEADER_SZ    = 13, /* normal + epoch(2) + seq_num(6) */
    DTLS_HANDSHAKE_EXTRA     = 8,  /* diff from normal */
    DTLS_RECORD_EXTRA        = 8,  /* diff from normal */
    DTLS_HANDSHAKE_SEQ_SZ    = 2,  /* handshake header sequence number */
    DTLS_HANDSHAKE_FRAG_SZ   = 3,  /* fragment offset and length are 24 bit */
    DTLS_POOL_SZ             = 5,  /* buffers to hold in the retry pool */

    FINISHED_LABEL_SZ   = 15,  /* TLS finished label size */
    TLS_FINISHED_SZ     = 12,  /* TLS has a shorter size  */
    MASTER_LABEL_SZ     = 13,  /* TLS master secret label sz */
    KEY_LABEL_SZ        = 13,  /* TLS key block expansion sz */
    MAX_PRF_HALF        = 128, /* Maximum half secret len */
    MAX_PRF_LABSEED     = 128, /* Maximum label + seed len */
    MAX_PRF_DIG         = 224, /* Maximum digest len      */
    MAX_REQUEST_SZ      = 256, /* Maximum cert req len (no auth yet */
    SESSION_FLUSH_COUNT = 256, /* Flush session cache unless user turns off */ 

    RC4_KEY_SIZE        = 16,  /* always 128bit           */
    DES_KEY_SIZE        =  8,  /* des                     */
    DES3_KEY_SIZE       = 24,  /* 3 des ede               */
    DES_IV_SIZE         = DES_BLOCK_SIZE,
    AES_256_KEY_SIZE    = 32,  /* for 256 bit             */
    AES_192_KEY_SIZE    = 24,  /* for 192 bit             */
    AES_IV_SIZE         = 16,  /* always block size       */
    AES_128_KEY_SIZE    = 16,  /* for 128 bit             */

    AEAD_SEQ_OFFSET     = 4,        /* Auth Data: Sequence number */
    AEAD_TYPE_OFFSET    = 8,        /* Auth Data: Type            */
    AEAD_VMAJ_OFFSET    = 9,        /* Auth Data: Major Version   */
    AEAD_VMIN_OFFSET    = 10,       /* Auth Data: Minor Version   */
    AEAD_LEN_OFFSET     = 11,       /* Auth Data: Length          */
    AEAD_AUTH_DATA_SZ   = 13,       /* Size of the data to authenticate */
    AEAD_IMP_IV_SZ      = 4,        /* Size of the implicit IV     */
    AEAD_EXP_IV_SZ      = 8,        /* Size of the explicit IV     */
    AEAD_NONCE_SZ       = AEAD_EXP_IV_SZ + AEAD_IMP_IV_SZ,

    AES_GCM_AUTH_SZ     = 16, /* AES-GCM Auth Tag length    */
    AES_CCM_16_AUTH_SZ  = 16, /* AES-CCM-16 Auth Tag length */
    AES_CCM_8_AUTH_SZ   = 8,  /* AES-CCM-8 Auth Tag Length  */

    CAMELLIA_128_KEY_SIZE = 16, /* for 128 bit */
    CAMELLIA_192_KEY_SIZE = 24, /* for 192 bit */
    CAMELLIA_256_KEY_SIZE = 32, /* for 256 bit */
    CAMELLIA_IV_SIZE      = 16, /* always block size */

    HC_128_KEY_SIZE     = 16,  /* 128 bits                */
    HC_128_IV_SIZE      = 16,  /* also 128 bits           */

    RABBIT_KEY_SIZE     = 16,  /* 128 bits                */
    RABBIT_IV_SIZE      =  8,  /* 64 bits for iv          */

    EVP_SALT_SIZE       =  8,  /* evp salt size 64 bits   */

    ECDHE_SIZE          = 32,  /* ECHDE server size defaults to 256 bit */
    MAX_EXPORT_ECC_SZ   = 256, /* Export ANS X9.62 max future size */

    MAX_HELLO_SZ       = 128,  /* max client or server hello */
    MAX_CERT_VERIFY_SZ = 1024, /* max   */
    CLIENT_HELLO_FIRST =  35,  /* Protocol + RAN_LEN + sizeof(id_len) */
    MAX_SUITE_NAME     =  48,  /* maximum length of cipher suite string */
    DEFAULT_TIMEOUT    = 500,  /* default resumption timeout in seconds */

    DTLS_TIMEOUT_INIT       =  1, /* default timeout init for DTLS receive  */
    DTLS_TIMEOUT_MAX        = 64, /* default max timeout for DTLS receive */
    DTLS_TIMEOUT_MULTIPLIER =  2, /* default timeout multiplier for DTLS recv */

    MAX_PSK_ID_LEN     = 128,  /* max psk identity/hint supported */
    MAX_PSK_KEY_LEN    =  64,  /* max psk key supported */

    MAX_CYASSL_FILE_SIZE = 1024 * 1024 * 4,  /* 4 mb file size alloc limit */

#ifdef FORTRESS
    MAX_EX_DATA        =   3,  /* allow for three items of ex_data */
#endif

    MAX_X509_SIZE      = 2048, /* max static x509 buffer size */
    CERT_MIN_SIZE      =  256, /* min PEM cert size with header/footer */
    MAX_FILENAME_SZ    =  256, /* max file name length */
    FILE_BUFFER_SIZE   = 1024, /* default static file buffer size for input,
                                  will use dynamic buffer if not big enough */

    MAX_NTRU_PUB_KEY_SZ = 1027, /* NTRU max for now */
    MAX_NTRU_ENCRYPT_SZ = 1027, /* NTRU max for now */
    MAX_NTRU_BITS       =  256, /* max symmetric bit strength */
    NO_SNIFF           =   0,  /* not sniffing */
    SNIFF              =   1,  /* currently sniffing */

    HASH_SIG_SIZE      =   2,  /* default SHA1 RSA */

    NO_CAVIUM_DEVICE   =  -2,  /* invalid cavium device id */

    NO_COPY            =   0,  /* should we copy static buffer for write */
    COPY               =   1   /* should we copy static buffer for write */
};


/* max cert chain peer depth */
#ifndef MAX_CHAIN_DEPTH
    #define MAX_CHAIN_DEPTH 9
#endif


/* don't use extra 3/4k stack space unless need to */
#ifdef HAVE_NTRU
    #define MAX_ENCRYPT_SZ MAX_NTRU_ENCRYPT_SZ
#else
    #define MAX_ENCRYPT_SZ ENCRYPT_LEN
#endif


/* states */
enum states {
    NULL_STATE = 0,

    SERVER_HELLOVERIFYREQUEST_COMPLETE,
    SERVER_HELLO_COMPLETE,
    SERVER_CERT_COMPLETE,
    SERVER_KEYEXCHANGE_COMPLETE,
    SERVER_HELLODONE_COMPLETE,
    SERVER_FINISHED_COMPLETE,

    CLIENT_HELLO_COMPLETE,
    CLIENT_KEYEXCHANGE_COMPLETE,
    CLIENT_FINISHED_COMPLETE,

    HANDSHAKE_DONE
};


#if defined(__GNUC__)
    #define CYASSL_PACK __attribute__ ((packed))
#else
    #define CYASSL_PACK
#endif

/* SSL Version */
typedef struct ProtocolVersion {
    byte major;
    byte minor;
} CYASSL_PACK ProtocolVersion;


CYASSL_LOCAL ProtocolVersion MakeSSLv3(void);
CYASSL_LOCAL ProtocolVersion MakeTLSv1(void);
CYASSL_LOCAL ProtocolVersion MakeTLSv1_1(void);
CYASSL_LOCAL ProtocolVersion MakeTLSv1_2(void);

#ifdef CYASSL_DTLS
    CYASSL_LOCAL ProtocolVersion MakeDTLSv1(void);
    CYASSL_LOCAL ProtocolVersion MakeDTLSv1_2(void);
#endif


enum BIO_TYPE {
    BIO_BUFFER = 1,
    BIO_SOCKET = 2,
    BIO_SSL    = 3,
    BIO_MEMORY = 4
};


/* CyaSSL BIO_METHOD type */
struct CYASSL_BIO_METHOD {
    byte type;               /* method type */
};


/* CyaSSL BIO type */
struct CYASSL_BIO {
    byte        type;          /* method type */
    byte        close;         /* close flag */
    byte        eof;           /* eof flag */
    CYASSL*     ssl;           /* possible associated ssl */
    byte*       mem;           /* memory buffer */
    int         memLen;        /* memory buffer length */
    int         fd;            /* possible file descriptor */
    CYASSL_BIO* prev;          /* previous in chain */
    CYASSL_BIO* next;          /* next in chain */
};


/* CyaSSL method type */
struct CYASSL_METHOD {
    ProtocolVersion version;
    byte            side;         /* connection side, server or client */
    byte            downgrade;    /* whether to downgrade version, default no */
};


/* defautls to client */
CYASSL_LOCAL void InitSSL_Method(CYASSL_METHOD*, ProtocolVersion);

/* for sniffer */
CYASSL_LOCAL int DoFinished(CYASSL* ssl, const byte* input, word32* inOutIdx,
                            int sniff);
CYASSL_LOCAL int DoApplicationData(CYASSL* ssl, byte* input, word32* inOutIdx);


/* CyaSSL buffer type */
typedef struct buffer {
    word32 length;
    byte*  buffer;
} buffer;


enum {
    FORCED_FREE = 1,
    NO_FORCED_FREE = 0
};


/* only use compression extra if using compression */
#ifdef HAVE_LIBZ
    #define COMP_EXTRA MAX_COMP_EXTRA
#else
    #define COMP_EXTRA 0
#endif

/* only the sniffer needs space in the buffer for extra MTU record(s) */
#ifdef CYASSL_SNIFFER
    #define MTU_EXTRA MAX_MTU * 3 
#else
    #define MTU_EXTRA 0
#endif


/* embedded callbacks require large static buffers, make sure on */
#ifdef CYASSL_CALLBACKS
    #undef  LARGE_STATIC_BUFFERS
    #define LARGE_STATIC_BUFFERS
#endif


/* give user option to use 16K static buffers */
#if defined(LARGE_STATIC_BUFFERS)
    #define RECORD_SIZE MAX_RECORD_SIZE
#else
    #ifdef CYASSL_DTLS
        #define RECORD_SIZE MAX_MTU 
    #else
        #define RECORD_SIZE 128 
    #endif
#endif


/* user option to turn off 16K output option */
/* if using small static buffers (default) and SSL_write tries to write data
   larger than the record we have, dynamically get it, unless user says only
   write in static buffer chuncks  */
#ifndef STATIC_CHUNKS_ONLY
    #define OUTPUT_RECORD_SIZE MAX_RECORD_SIZE
#else
    #define OUTPUT_RECORD_SIZE RECORD_SIZE
#endif

/* CyaSSL input buffer

   RFC 2246:

   length
       The length (in bytes) of the following TLSPlaintext.fragment.
       The length should not exceed 2^14.
*/
#if defined(LARGE_STATIC_BUFFERS)
    #define STATIC_BUFFER_LEN RECORD_HEADER_SZ + RECORD_SIZE + COMP_EXTRA + \
             MTU_EXTRA + MAX_MSG_EXTRA
#else
    /* zero length arrays may not be supported */
    #define STATIC_BUFFER_LEN 1
#endif

typedef struct {
    word32 length;       /* total buffer length used */
    word32 idx;          /* idx to part of length already consumed */
    byte*  buffer;       /* place holder for static or dynamic buffer */
    word32 bufferSize;   /* current buffer size */
    ALIGN16 byte staticBuffer[STATIC_BUFFER_LEN];
    byte   dynamicFlag;  /* dynamic memory currently in use */
    byte   offset;       /* alignment offset attempt */
} bufferStatic;

/* Cipher Suites holder */
typedef struct Suites {
    int    setSuites;               /* user set suites from default */
    byte   suites[MAX_SUITE_SZ];  
    word16 suiteSz;                 /* suite length in bytes        */
    byte   hashSigAlgo[HELLO_EXT_SIGALGO_MAX]; /* sig/algo to offer */
    word16 hashSigAlgoSz;           /* SigAlgo extension length in bytes */
    byte   hashAlgo;                /* selected hash algorithm */
    byte   sigAlgo;                 /* selected sig algorithm */
} Suites;


CYASSL_LOCAL
void InitSuites(Suites*, ProtocolVersion,
                                     byte, byte, byte, byte, byte, byte, int);
CYASSL_LOCAL
int  SetCipherList(Suites*, const char* list);

#ifndef PSK_TYPES_DEFINED
    typedef unsigned int (*psk_client_callback)(CYASSL*, const char*, char*,
                          unsigned int, unsigned char*, unsigned int);
    typedef unsigned int (*psk_server_callback)(CYASSL*, const char*,
                          unsigned char*, unsigned int);
#endif /* PSK_TYPES_DEFINED */


#ifndef CYASSL_USER_IO
    /* default IO callbacks */
    CYASSL_LOCAL
    int EmbedReceive(CYASSL *ssl, char *buf, int sz, void *ctx);
    CYASSL_LOCAL 
    int EmbedSend(CYASSL *ssl, char *buf, int sz, void *ctx);

    #ifdef HAVE_OCSP
        CYASSL_LOCAL
        int EmbedOcspLookup(void*, const char*, int, byte*, int, byte**);
        CYASSL_LOCAL
        void EmbedOcspRespFree(void*, byte*);
    #endif

    #ifdef CYASSL_DTLS
        CYASSL_LOCAL
        int EmbedReceiveFrom(CYASSL *ssl, char *buf, int sz, void *ctx);
        CYASSL_LOCAL 
        int EmbedSendTo(CYASSL *ssl, char *buf, int sz, void *ctx);
        CYASSL_LOCAL
        int EmbedGenerateCookie(CYASSL* ssl, byte *buf, int sz, void *ctx);
        CYASSL_LOCAL
        int IsUDP(void*);
    #endif /* CYASSL_DTLS */
#endif /* CYASSL_USER_IO */


/* CyaSSL Cipher type just points back to SSL */
struct CYASSL_CIPHER {
    CYASSL* ssl;
};


#ifdef SINGLE_THREADED
    typedef int CyaSSL_Mutex;
#else /* MULTI_THREADED */
    /* FREERTOS comes first to enable use of FreeRTOS Windows simulator only */
    #ifdef FREERTOS
        typedef xSemaphoreHandle CyaSSL_Mutex;
    #elif defined(CYASSL_SAFERTOS)
        typedef struct CyaSSL_Mutex {
            signed char mutexBuffer[portQUEUE_OVERHEAD_BYTES];
            xSemaphoreHandle mutex;
        } CyaSSL_Mutex;
    #elif defined(USE_WINDOWS_API)
        typedef CRITICAL_SECTION CyaSSL_Mutex;
    #elif defined(CYASSL_PTHREADS)
        typedef pthread_mutex_t CyaSSL_Mutex;
    #elif defined(THREADX)
        typedef TX_MUTEX CyaSSL_Mutex;
    #elif defined(MICRIUM)
        typedef OS_MUTEX CyaSSL_Mutex;
    #elif defined(EBSNET)
        typedef RTP_MUTEX CyaSSL_Mutex;
    #elif defined(FREESCALE_MQX)
        typedef MUTEX_STRUCT CyaSSL_Mutex;
    #elif defined(CYASSL_MDK_ARM)
        typedef OS_MUT CyaSSL_Mutex;
    #else
        #error Need a mutex type in multithreaded mode
    #endif /* USE_WINDOWS_API */
#endif /* SINGLE_THREADED */

CYASSL_LOCAL int InitMutex(CyaSSL_Mutex*);
CYASSL_LOCAL int FreeMutex(CyaSSL_Mutex*);
CYASSL_LOCAL int LockMutex(CyaSSL_Mutex*);
CYASSL_LOCAL int UnLockMutex(CyaSSL_Mutex*);

typedef struct OCSP_Entry OCSP_Entry;

#ifdef SHA_DIGEST_SIZE
    #define OCSP_DIGEST_SIZE SHA_DIGEST_SIZE
#else
    #define OCSP_DIGEST_SIZE 160
#endif

#ifdef NO_ASN 
    /* no_asn won't have */
    typedef struct CertStatus CertStatus;
#endif

struct OCSP_Entry {
    OCSP_Entry* next;                       /* next entry             */
    byte    issuerHash[OCSP_DIGEST_SIZE];    /* issuer hash            */ 
    byte    issuerKeyHash[OCSP_DIGEST_SIZE]; /* issuer public key hash */
    CertStatus* status;                     /* OCSP response list     */
    int         totalStatus;                /* number on list         */
};


/* CyaSSL OCSP controller */
struct CYASSL_OCSP {
    byte enabled;
    byte useOverrideUrl;
    byte useNonce;
    char overrideUrl[80];
    OCSP_Entry* ocspList;
    void* IOCB_OcspCtx;
    CallbackIOOcsp CBIOOcsp;
    CallbackIOOcspRespFree CBIOOcspRespFree;
};

#ifndef MAX_DATE_SIZE
#define MAX_DATE_SIZE 32
#endif

typedef struct CRL_Entry CRL_Entry;

#ifdef SHA_DIGEST_SIZE
    #define CRL_DIGEST_SIZE SHA_DIGEST_SIZE
#else
    #define CRL_DIGEST_SIZE 160
#endif

#ifdef NO_ASN 
    typedef struct RevokedCert RevokedCert;
#endif

/* Complete CRL */
struct CRL_Entry {
    CRL_Entry* next;                      /* next entry */
    byte    issuerHash[CRL_DIGEST_SIZE];  /* issuer hash                 */ 
    /* byte    crlHash[CRL_DIGEST_SIZE];      raw crl data hash           */ 
    /* restore the hash here if needed for optimized comparisons */
    byte    lastDate[MAX_DATE_SIZE]; /* last date updated  */
    byte    nextDate[MAX_DATE_SIZE]; /* next update date   */
    byte    lastDateFormat;          /* last date format */
    byte    nextDateFormat;          /* next date format */
    RevokedCert* certs;              /* revoked cert list  */
    int          totalCerts;         /* number on list     */
};


typedef struct CRL_Monitor CRL_Monitor;

/* CRL directory monitor */
struct CRL_Monitor {
    char* path;      /* full dir path, if valid pointer we're using */
    int   type;      /* PEM or ASN1 type */
};


#ifndef HAVE_CRL
    typedef struct CYASSL_CRL CYASSL_CRL;
#endif

/* CyaSSL CRL controller */
struct CYASSL_CRL {
    CYASSL_CERT_MANAGER* cm;            /* pointer back to cert manager */
    CRL_Entry*           crlList;       /* our CRL list */
    CyaSSL_Mutex         crlLock;       /* CRL list lock */
    CRL_Monitor          monitors[2];   /* PEM and DER possible */
#ifdef HAVE_CRL_MONITOR
    pthread_t            tid;           /* monitoring thread */
#endif
};


#ifdef NO_ASN 
    typedef struct Signer Signer;
#endif


#ifndef CA_TABLE_SIZE
    #define CA_TABLE_SIZE 11
#endif

/* CyaSSL Certificate Manager */
struct CYASSL_CERT_MANAGER {
    Signer*         caTable[CA_TABLE_SIZE]; /* the CA signer table */
    CyaSSL_Mutex    caLock;             /* CA list lock */
    CallbackCACache caCacheCallback;    /* CA cache addition callback */
    void*           heap;               /* heap helper */
    CYASSL_CRL*     crl;                /* CRL checker */
    byte            crlEnabled;         /* is CRL on ? */
    byte            crlCheckAll;        /* always leaf, but all ? */
    CbMissingCRL    cbMissingCRL;       /* notify through cb of missing crl */
};

CYASSL_LOCAL int CM_SaveCertCache(CYASSL_CERT_MANAGER*, const char*);
CYASSL_LOCAL int CM_RestoreCertCache(CYASSL_CERT_MANAGER*, const char*);
CYASSL_LOCAL int CM_MemSaveCertCache(CYASSL_CERT_MANAGER*, void*, int, int*);
CYASSL_LOCAL int CM_MemRestoreCertCache(CYASSL_CERT_MANAGER*, const void*, int);
CYASSL_LOCAL int CM_GetCertCacheMemSize(CYASSL_CERT_MANAGER*);

/* CyaSSL Sock Addr */
struct CYASSL_SOCKADDR {
    unsigned int sz; /* sockaddr size */
    void*        sa; /* pointer to the sockaddr_in or sockaddr_in6 */
};

typedef struct CYASSL_DTLS_CTX {
    CYASSL_SOCKADDR peer;
    int fd;
} CYASSL_DTLS_CTX;

/* RFC 6066 TLS Extensions */
#ifdef HAVE_TLS_EXTENSIONS

typedef enum {
    SERVER_NAME_INDICATION =  0,/*
    MAX_FRAGMENT_LENGTH    =  1,
    CLIENT_CERTIFICATE_URL =  2,
    TRUSTED_CA_KEYS        =  3,
    TRUNCATED_HMAC         =  4,
    STATUS_REQUEST         =  5,
    SIGNATURE_ALGORITHMS   = 13,*/
} TLSX_Type;

typedef struct TLSX {
    TLSX_Type    type; /* Extension Type  */
    void*        data; /* Extension Data  */
    byte         resp; /* IsResponse Flag */
    struct TLSX* next; /* List Behavior   */
} TLSX;

CYASSL_LOCAL TLSX* TLSX_Find(TLSX* list, TLSX_Type type);
CYASSL_LOCAL void TLSX_FreeAll(TLSX* list);

#ifndef NO_CYASSL_CLIENT
CYASSL_LOCAL word16 TLSX_GetRequestSize(CYASSL* ssl);
CYASSL_LOCAL word16 TLSX_WriteRequest(CYASSL* ssl, byte* output);
#endif

#ifndef NO_CYASSL_SERVER
CYASSL_LOCAL word16 TLSX_GetResponseSize(CYASSL* ssl);
CYASSL_LOCAL word16 TLSX_WriteResponse(CYASSL* ssl, byte* output);
#endif

CYASSL_LOCAL int    TLSX_Parse(CYASSL* ssl, byte* input, word16 length,
                                                byte isRequest, Suites *suites);

/* Server Name Indication */
#ifdef HAVE_SNI

typedef struct SNI {
    byte                       type;    /* SNI Type          */
    union { char* host_name; } data;    /* SNI Data          */
    struct SNI*                next;    /* List Behavior     */
#ifndef NO_CYASSL_SERVER
    byte                       options; /* Behaviour options */
    byte                       matched; /* Matching result   */
#endif
} SNI;

CYASSL_LOCAL int TLSX_UseSNI(TLSX** extensions, byte type, const void* data,
                                                                   word16 size);

#ifndef NO_CYASSL_SERVER
CYASSL_LOCAL byte TLSX_SNI_Matched(TLSX* extensions, byte type);
CYASSL_LOCAL void TLSX_SNI_SetOptions(TLSX* extensions, byte type,
                                                                  byte options);
#endif

#endif /* HAVE_SNI */

#endif /* HAVE_TLS_EXTENSIONS */

/* CyaSSL context type */
struct CYASSL_CTX {
    CYASSL_METHOD* method;
    CyaSSL_Mutex   countMutex;    /* reference count mutex */
    int         refCount;         /* reference count */
#ifndef NO_CERTS
    buffer      certificate;
    buffer      certChain;
                 /* chain after self, in DER, with leading size for each cert */
    buffer      privateKey;
    buffer      serverDH_P;
    buffer      serverDH_G;
    CYASSL_CERT_MANAGER* cm;      /* our cert manager, ctx owns SSL will use */
#endif
    Suites      suites;
    void*       heap;             /* for user memory overrides */
    byte        verifyPeer;
    byte        verifyNone;
    byte        failNoCert;
    byte        sessionCacheOff;
    byte        sessionCacheFlushOff;
    byte        sendVerify;       /* for client side */
    byte        haveRSA;          /* RSA available */
    byte        haveDH;           /* server DH parms set by user */
    byte        haveNTRU;         /* server private NTRU  key loaded */
    byte        haveECDSAsig;     /* server cert signed w/ ECDSA */
    byte        haveStaticECC;    /* static server ECC private key */
    byte        partialWrite;     /* only one msg per write call */
    byte        quietShutdown;    /* don't send close notify */
    byte        groupMessages;    /* group handshake messages before sending */
    CallbackIORecv CBIORecv;
    CallbackIOSend CBIOSend;
#ifdef CYASSL_DTLS
    CallbackGenCookie CBIOCookie;       /* gen cookie callback */
#endif
    VerifyCallback  verifyCallback;     /* cert verification callback */
    word32          timeout;            /* session timeout */
#ifdef HAVE_ECC
    word16          eccTempKeySz;       /* in octets 20 - 66 */
#endif
#ifndef NO_PSK
    byte        havePSK;                /* psk key set by user */
    psk_client_callback client_psk_cb;  /* client callback */
    psk_server_callback server_psk_cb;  /* server callback */
    char        server_hint[MAX_PSK_ID_LEN];
#endif /* NO_PSK */
#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER)
    pem_password_cb passwd_cb;
    void*            userdata;
#endif /* OPENSSL_EXTRA */
#ifdef HAVE_OCSP
    CYASSL_OCSP      ocsp;
#endif
#ifdef HAVE_CAVIUM
    int              devId;            /* cavium device id to use */
#endif
#ifdef HAVE_TLS_EXTENSIONS
    TLSX* extensions;                  /* RFC 6066 TLS Extensions data */
#endif
};


CYASSL_LOCAL
int InitSSL_Ctx(CYASSL_CTX*, CYASSL_METHOD*);
CYASSL_LOCAL
void FreeSSL_Ctx(CYASSL_CTX*);
CYASSL_LOCAL
void SSL_CtxResourceFree(CYASSL_CTX*);

CYASSL_LOCAL
int DeriveTlsKeys(CYASSL* ssl);
CYASSL_LOCAL
int ProcessOldClientHello(CYASSL* ssl, const byte* input, word32* inOutIdx,
                          word32 inSz, word16 sz);
#ifndef NO_CERTS
    CYASSL_LOCAL
    int AddCA(CYASSL_CERT_MANAGER* ctx, buffer der, int type, int verify);
    CYASSL_LOCAL
    int AlreadySigner(CYASSL_CERT_MANAGER* cm, byte* hash);
#endif

/* All cipher suite related info */
typedef struct CipherSpecs {
    byte bulk_cipher_algorithm;
    byte cipher_type;               /* block, stream, or aead */
    byte mac_algorithm;
    byte kea;                       /* key exchange algo */
    byte sig_algo;
    byte hash_size;
    byte pad_size;
    byte static_ecdh;
    word16 key_size;
    word16 iv_size;
    word16 block_size;
    word16 aead_mac_size;
} CipherSpecs;


void InitCipherSpecs(CipherSpecs* cs);


/* Supported Ciphers from page 43  */
enum BulkCipherAlgorithm { 
    cipher_null,
    rc4,
    rc2,
    des,
    triple_des,             /* leading 3 (3des) not valid identifier */
    des40,
    idea,
    aes,
    aes_gcm,
    aes_ccm,
    camellia,
    hc128,                  /* CyaSSL extensions */
    rabbit
};


/* Supported Message Authentication Codes from page 43 */
enum MACAlgorithm { 
    no_mac,
    md5_mac,
    sha_mac,
    sha224_mac,
    sha256_mac,
    sha384_mac,
    sha512_mac,
    rmd_mac
};


/* Supported Key Exchange Protocols */
enum KeyExchangeAlgorithm { 
    no_kea,
    rsa_kea, 
    diffie_hellman_kea, 
    fortezza_kea,
    psk_kea,
    ntru_kea,
    ecc_diffie_hellman_kea,
    ecc_static_diffie_hellman_kea       /* for verify suite only */
};


/* Supported Authentication Schemes */
enum SignatureAlgorithm {
    anonymous_sa_algo,
    rsa_sa_algo,
    dsa_sa_algo,
    ecc_dsa_sa_algo
};


/* Supprted ECC Curve Types */
enum EccCurves {
    named_curve = 3
};


/* Supprted ECC Named Curves */
enum EccNamedCurves {
    secp256r1 = 0x17,         /* default, OpenSSL also calls it prime256v1 */
    secp384r1 = 0x18,
    secp521r1 = 0x19,

    secp160r1 = 0x10,
    secp192r1 = 0x13,        /*           Openssl also call it prime192v1 */
    secp224r1 = 0x15
};


/* Valid client certificate request types from page 27 */
enum ClientCertificateType {    
    rsa_sign            = 1, 
    dss_sign            = 2,
    rsa_fixed_dh        = 3,
    dss_fixed_dh        = 4,
    rsa_ephemeral_dh    = 5,
    dss_ephemeral_dh    = 6,
    fortezza_kea_cert   = 20
};


enum CipherType { stream, block, aead };


/* keys and secrets */
typedef struct Keys {
    byte client_write_MAC_secret[MAX_DIGEST_SIZE];   /* max sizes */
    byte server_write_MAC_secret[MAX_DIGEST_SIZE]; 
    byte client_write_key[AES_256_KEY_SIZE];         /* max sizes */
    byte server_write_key[AES_256_KEY_SIZE]; 
    byte client_write_IV[AES_IV_SIZE];               /* max sizes */
    byte server_write_IV[AES_IV_SIZE];
#ifdef HAVE_AEAD
    byte aead_exp_IV[AEAD_EXP_IV_SZ];
    byte aead_enc_imp_IV[AEAD_IMP_IV_SZ];
    byte aead_dec_imp_IV[AEAD_IMP_IV_SZ];
#endif

    word32 peer_sequence_number;
    word32 sequence_number;
    
#ifdef CYASSL_DTLS
    word32 dtls_sequence_number;
    word32 dtls_peer_sequence_number;
    word32 dtls_expected_peer_sequence_number;
    word16 dtls_handshake_number;
    word16 dtls_peer_handshake_number;
    word16 dtls_expected_peer_handshake_number;
    word16 dtls_epoch;
    word16 dtls_peer_epoch;
    word16 dtls_expected_peer_epoch;
#endif

    word32 encryptSz;             /* last size of encrypted data   */
    byte   encryptionOn;          /* true after change cipher spec */
    byte   decryptedCur;          /* only decrypt current record once */
} Keys;


/* cipher for now */
typedef struct Ciphers {
#ifdef BUILD_ARC4
    Arc4*   arc4;
#endif
#ifdef BUILD_DES3
    Des3*   des3;
#endif
#if defined(BUILD_AES) || defined(BUILD_AESGCM)
    Aes*    aes;
#endif
#ifdef HAVE_CAMELLIA
    Camellia* cam;
#endif
#ifdef HAVE_HC128
    HC128*  hc128;
#endif
#ifdef BUILD_RABBIT
    Rabbit* rabbit;
#endif
    byte    setup;       /* have we set it up flag for detection */
} Ciphers;


CYASSL_LOCAL void InitCiphers(CYASSL* ssl);
CYASSL_LOCAL void FreeCiphers(CYASSL* ssl);


/* hashes type */
typedef struct Hashes {
    #ifndef NO_OLD_TLS
        byte md5[MD5_DIGEST_SIZE];
    #endif
    byte sha[SHA_DIGEST_SIZE];
    #ifndef NO_SHA256
        byte sha256[SHA256_DIGEST_SIZE];
    #endif
    #ifdef CYASSL_SHA384
        byte sha384[SHA384_DIGEST_SIZE];
    #endif
} Hashes;


/* Static x509 buffer */
typedef struct x509_buffer {
    int  length;                  /* actual size */
    byte buffer[MAX_X509_SIZE];   /* max static cert size */
} x509_buffer;


/* CyaSSL X509_CHAIN, for no dynamic memory SESSION_CACHE */
struct CYASSL_X509_CHAIN {
    int         count;                    /* total number in chain */
    x509_buffer certs[MAX_CHAIN_DEPTH];   /* only allow max depth 4 for now */
};


/* CyaSSL session type */
struct CYASSL_SESSION {
    byte         sessionID[ID_LEN];             /* id for protocol */
    byte         masterSecret[SECRET_LEN];      /* stored secret */
    word32       bornOn;                        /* create time in seconds   */
    word32       timeout;                       /* timeout in seconds       */
#ifdef SESSION_CERTS
    CYASSL_X509_CHAIN chain;                    /* peer cert chain, static  */
    ProtocolVersion version;                    /* which version was used */
    byte            cipherSuite0;               /* first byte, normally 0 */
    byte            cipherSuite;                /* 2nd byte, actual suite */
#endif
#ifndef NO_CLIENT_CACHE
    byte         serverID[SERVER_ID_LEN];       /* for easier client lookup */
    word16       idLen;                         /* serverID length */
#endif
};


CYASSL_LOCAL
CYASSL_SESSION* GetSession(CYASSL*, byte*);
CYASSL_LOCAL
int          SetSession(CYASSL*, CYASSL_SESSION*);

typedef void (*hmacfp) (CYASSL*, byte*, const byte*, word32, int, int);

#ifndef NO_CLIENT_CACHE
    CYASSL_SESSION* GetSessionClient(CYASSL*, const byte*, int);
#endif

/* client connect state for nonblocking restart */
enum ConnectState {
    CONNECT_BEGIN = 0,
    CLIENT_HELLO_SENT,
    HELLO_AGAIN,               /* HELLO_AGAIN s for DTLS case */
    HELLO_AGAIN_REPLY,
    FIRST_REPLY_DONE,
    FIRST_REPLY_FIRST,
    FIRST_REPLY_SECOND,
    FIRST_REPLY_THIRD,
    FIRST_REPLY_FOURTH,
    FINISHED_DONE,
    SECOND_REPLY_DONE
};


/* server accept state for nonblocking restart */
enum AcceptState {
    ACCEPT_BEGIN = 0,
    ACCEPT_CLIENT_HELLO_DONE,
    HELLO_VERIFY_SENT,
    ACCEPT_FIRST_REPLY_DONE,
    SERVER_HELLO_SENT,
    CERT_SENT,
    KEY_EXCHANGE_SENT,
    CERT_REQ_SENT,
    SERVER_HELLO_DONE,
    ACCEPT_SECOND_REPLY_DONE,
    CHANGE_CIPHER_SENT,
    ACCEPT_FINISHED_DONE,
    ACCEPT_THIRD_REPLY_DONE
};


typedef struct Buffers {
#ifndef NO_CERTS
    buffer          certificate;            /* CYASSL_CTX owns, unless we own */
    buffer          key;                    /* CYASSL_CTX owns, unless we own */
    buffer          certChain;              /* CYASSL_CTX owns */
                 /* chain after self, in DER, with leading size for each cert */
    buffer          serverDH_P;             /* CYASSL_CTX owns, unless we own */
    buffer          serverDH_G;             /* CYASSL_CTX owns, unless we own */
    buffer          serverDH_Pub;
    buffer          serverDH_Priv;
#endif
    buffer          domainName;             /* for client check */
    bufferStatic    inputBuffer;
    bufferStatic    outputBuffer;
    buffer          clearOutputBuffer;
    int             prevSent;              /* previous plain text bytes sent
                                              when got WANT_WRITE            */
    int             plainSz;               /* plain text bytes in buffer to send
                                              when got WANT_WRITE            */
    byte            weOwnCert;             /* SSL own cert flag */
    byte            weOwnKey;              /* SSL own key  flag */
    byte            weOwnDH;               /* SSL own dh (p,g)  flag */
#ifdef CYASSL_DTLS
    CYASSL_DTLS_CTX dtlsCtx;               /* DTLS connection context */
#endif
} Buffers;

typedef struct Options {
    byte            sessionCacheOff;
    byte            sessionCacheFlushOff;
    byte            cipherSuite0;           /* first byte, normally 0 */
    byte            cipherSuite;            /* second byte, actual suite */
    byte            serverState;
    byte            clientState;
    byte            handShakeState;
    byte            side;               /* client or server end */
    byte            verifyPeer;
    byte            verifyNone;
    byte            failNoCert;
    byte            downgrade;          /* allow downgrade of versions */
    byte            sendVerify;         /* false = 0, true = 1, sendBlank = 2 */
    byte            resuming;
    byte            haveSessionId;      /* server may not send */
    byte            tls;                /* using TLS ? */
    byte            tls1_1;             /* using TLSv1.1+ ? */
    byte            dtls;               /* using datagrams ? */
    byte            connReset;          /* has the peer reset */
    byte            isClosed;           /* if we consider conn closed */
    byte            closeNotify;        /* we've recieved a close notify */
    byte            sentNotify;         /* we've sent a close notify */
    byte            connectState;       /* nonblocking resume */
    byte            acceptState;        /* nonblocking resume */
    byte            usingCompression;   /* are we using compression */
    byte            haveRSA;            /* RSA available */
    byte            haveDH;             /* server DH parms set by user */
    byte            haveNTRU;           /* server NTRU  private key loaded */
    byte            haveECDSAsig;       /* server ECDSA signed cert */
    byte            haveStaticECC;      /* static server ECC private key */
    byte            havePeerCert;       /* do we have peer's cert */
    byte            havePeerVerify;     /* and peer's cert verify */
    byte            usingPSK_cipher;    /* whether we're using psk as cipher */
    byte            sendAlertState;     /* nonblocking resume */ 
    byte            processReply;       /* nonblocking resume */
    byte            partialWrite;       /* only one msg per write call */
    byte            quietShutdown;      /* don't send close notify */
    byte            certOnly;           /* stop once we get cert */
    byte            groupMessages;      /* group handshake messages */
    byte            usingNonblock;      /* set when using nonblocking socket */
    byte            saveArrays;         /* save array Memory for user get keys
                                           or psk */
#ifndef NO_PSK
    byte            havePSK;            /* psk key set by user */
    psk_client_callback client_psk_cb;
    psk_server_callback server_psk_cb;
#endif /* NO_PSK */
} Options;

typedef struct Arrays {
    byte            clientRandom[RAN_LEN];
    byte            serverRandom[RAN_LEN];
    byte            sessionID[ID_LEN];
    byte            preMasterSecret[ENCRYPT_LEN];
    byte            masterSecret[SECRET_LEN];
#ifdef CYASSL_DTLS
    byte            cookie[MAX_COOKIE_LEN];
    byte            cookieSz;
#endif
#ifndef NO_PSK
    char            client_identity[MAX_PSK_ID_LEN];
    char            server_hint[MAX_PSK_ID_LEN];
    byte            psk_key[MAX_PSK_KEY_LEN];
    word32          psk_keySz;          /* acutal size */
#endif
    word32          preMasterSz;        /* differs for DH, actual size */
} Arrays;

#ifndef ASN_NAME_MAX
#define ASN_NAME_MAX 256
#endif

struct CYASSL_X509_NAME {
    char  name[ASN_NAME_MAX];
    int   sz;
};

#ifndef EXTERNAL_SERIAL_SIZE
    #define EXTERNAL_SERIAL_SIZE 32
#endif

#ifdef NO_ASN 
    typedef struct DNS_entry DNS_entry;
#endif

struct CYASSL_X509 {
    CYASSL_X509_NAME issuer;
    CYASSL_X509_NAME subject;
    int              serialSz;
    byte             serial[EXTERNAL_SERIAL_SIZE];
    char             subjectCN[ASN_NAME_MAX];        /* common name short cut */
    buffer           derCert;                        /* may need  */
    DNS_entry*       altNames;                       /* alt names list */
    DNS_entry*       altNamesNext;                   /* hint for retrieval */
    byte             dynamicMemory;                  /* dynamic memory flag */
};


/* record layer header for PlainText, Compressed, and CipherText */
typedef struct RecordLayerHeader {
    byte            type;
    byte            pvMajor;
    byte            pvMinor;
    byte            length[2];
} RecordLayerHeader;


/* record layer header for DTLS PlainText, Compressed, and CipherText */
typedef struct DtlsRecordLayerHeader {
    byte            type;
    byte            pvMajor;
    byte            pvMinor;
    byte            epoch[2];             /* increment on cipher state change */
    byte            sequence_number[6];   /* per record */
    byte            length[2];
} DtlsRecordLayerHeader;


typedef struct DtlsPool {
    buffer          buf[DTLS_POOL_SZ];
    int             used;
} DtlsPool;

typedef struct DtlsMsg {
    struct DtlsMsg* next;
    word32          seq;       /* Handshake sequence number    */
    word32          sz;        /* Length of whole mesage       */
    word32          fragSz;    /* Length of fragments received */
    byte            type;
    byte*           buf;
    byte*           msg;
} DtlsMsg;


/* CyaSSL ssl type */
struct CYASSL {
    CYASSL_CTX*     ctx;
    int             error;
    ProtocolVersion version;            /* negotiated version */
    ProtocolVersion chVersion;          /* client hello version */
    Suites*         suites;             /* only need during handshake */
    Ciphers         encrypt;
    Ciphers         decrypt;
    CipherSpecs     specs;
    Keys            keys;
    int             rfd;                /* read  file descriptor */
    int             wfd;                /* write file descriptor */
    int             rflags;             /* user read  flags */
    int             wflags;             /* user write flags */
    CYASSL_BIO*     biord;              /* socket bio read  to free/close */
    CYASSL_BIO*     biowr;              /* socket bio write to free/close */
    void*           IOCB_ReadCtx;
    void*           IOCB_WriteCtx;
    RNG*            rng;
#ifndef NO_OLD_TLS
#ifndef NO_SHA
    Sha             hashSha;            /* sha hash of handshake msgs */
#endif
#ifndef NO_MD5
    Md5             hashMd5;            /* md5 hash of handshake msgs */
#endif
#endif
#ifndef NO_SHA256
    Sha256          hashSha256;         /* sha256 hash of handshake msgs */
#endif
#ifdef CYASSL_SHA384
    Sha384          hashSha384;         /* sha384 hash of handshake msgs */
#endif
    Hashes          verifyHashes;
    Hashes          certHashes;         /* for cert verify */
    Buffers         buffers;
    Options         options;
    Arrays*         arrays;
    CYASSL_SESSION  session;
    VerifyCallback  verifyCallback;      /* cert verification callback */
    void*           verifyCbCtx;         /* cert verify callback user ctx*/
#ifndef NO_RSA
    RsaKey*         peerRsaKey;
    byte            peerRsaKeyPresent;
#endif
#ifdef HAVE_NTRU
    word16          peerNtruKeyLen;
    byte            peerNtruKey[MAX_NTRU_PUB_KEY_SZ];
    byte            peerNtruKeyPresent;
#endif
#ifdef HAVE_ECC
    ecc_key*        peerEccKey;              /* peer's  ECDHE key */
    ecc_key*        peerEccDsaKey;           /* peer's  ECDSA key */
    ecc_key*        eccTempKey;              /* private ECDHE key */
    ecc_key*        eccDsaKey;               /* private ECDSA key */
    word16          eccTempKeySz;            /* in octets 20 - 66 */
    byte            peerEccKeyPresent;
    byte            peerEccDsaKeyPresent;
    byte            eccTempKeyPresent;
    byte            eccDsaKeyPresent;
#endif
    hmacfp          hmac;
    void*           heap;               /* for user overrides */
    RecordLayerHeader curRL;
    word16            curSize;
    word32          timeout;            /* session timeout */
    CYASSL_CIPHER   cipher;
#ifdef HAVE_LIBZ
    z_stream        c_stream;           /* compression   stream */
    z_stream        d_stream;           /* decompression stream */
    byte            didStreamInit;      /* for stream init and end */
#endif
#ifdef CYASSL_DTLS
    int             dtls_timeout_init;  /* starting timeout vaule */
    int             dtls_timeout_max;   /* maximum timeout value */
    int             dtls_timeout;       /* current timeout value, changes */
    DtlsPool*       dtls_pool;
    DtlsMsg*        dtls_msg_list;
    void*           IOCB_CookieCtx;     /* gen cookie ctx */
    word32          dtls_expected_rx;
#endif
#ifdef CYASSL_CALLBACKS
    HandShakeInfo   handShakeInfo;      /* info saved during handshake */
    TimeoutInfo     timeoutInfo;        /* info saved during handshake */
    byte            hsInfoOn;           /* track handshake info        */
    byte            toInfoOn;           /* track timeout   info        */
#endif
#ifdef KEEP_PEER_CERT
    CYASSL_X509     peerCert;           /* X509 peer cert */
#endif
#ifdef FORTRESS
    void*           ex_data[MAX_EX_DATA]; /* external data, for Fortress */
#endif
#ifdef HAVE_CAVIUM
    int              devId;            /* cavium device id to use */
#endif
#ifdef HAVE_TLS_EXTENSIONS
    TLSX* extensions;                  /* RFC 6066 TLS Extensions data */
#endif
    CYASSL_ALERT_HISTORY alert_history;
};


CYASSL_LOCAL
int  InitSSL(CYASSL*, CYASSL_CTX*);
CYASSL_LOCAL
void FreeSSL(CYASSL*);
CYASSL_API void SSL_ResourceFree(CYASSL*);   /* Micrium uses */


enum {
    IV_SZ   = 32,          /* max iv sz */
    NAME_SZ = 80          /* max one line */
};


typedef struct EncryptedInfo {
    char     name[NAME_SZ];    /* encryption name */
    byte     iv[IV_SZ];        /* encrypted IV */
    word32   ivSz;             /* encrypted IV size */
    long     consumed;         /* tracks PEM bytes consumed */
    byte     set;              /* if encryption set */
    CYASSL_CTX* ctx;              /* CTX owner */
} EncryptedInfo;


#ifndef NO_CERTS
    CYASSL_LOCAL int PemToDer(const unsigned char* buff, long sz, int type,
                              buffer* der, void* heap, EncryptedInfo* info,
                              int* eccKey);

    CYASSL_LOCAL int ProcessFile(CYASSL_CTX* ctx, const char* fname, int format,
                                 int type, CYASSL* ssl, int userChain,
                                CYASSL_CRL* crl);
#endif


#ifdef CYASSL_CALLBACKS
    CYASSL_LOCAL
    void InitHandShakeInfo(HandShakeInfo*);
    CYASSL_LOCAL 
    void FinishHandShakeInfo(HandShakeInfo*, const CYASSL*);
    CYASSL_LOCAL 
    void AddPacketName(const char*, HandShakeInfo*);

    CYASSL_LOCAL
    void InitTimeoutInfo(TimeoutInfo*);
    CYASSL_LOCAL 
    void FreeTimeoutInfo(TimeoutInfo*, void*);
    CYASSL_LOCAL 
    void AddPacketInfo(const char*, TimeoutInfo*, const byte*, int, void*);
    CYASSL_LOCAL 
    void AddLateName(const char*, TimeoutInfo*);
    CYASSL_LOCAL 
    void AddLateRecordHeader(const RecordLayerHeader* rl, TimeoutInfo* info);
#endif


/* Record Layer Header identifier from page 12 */
enum ContentType {
    no_type            = 0,
    change_cipher_spec = 20, 
    alert              = 21, 
    handshake          = 22, 
    application_data   = 23 
};


/* handshake header, same for each message type, pgs 20/21 */
typedef struct HandShakeHeader {
    byte            type;
    word24          length;
} HandShakeHeader;


/* DTLS handshake header, same for each message type */
typedef struct DtlsHandShakeHeader {
    byte            type;
    word24          length;
    byte            message_seq[2];    /* start at 0, restransmit gets same # */
    word24          fragment_offset;   /* bytes in previous fragments */
    word24          fragment_length;   /* length of this fragment */
} DtlsHandShakeHeader;


enum HandShakeType {
    no_shake            = -1,
    hello_request       = 0, 
    client_hello        = 1, 
    server_hello        = 2,
    hello_verify_request = 3,       /* DTLS addition */
    session_ticket      =  4,
    certificate         = 11, 
    server_key_exchange = 12,
    certificate_request = 13, 
    server_hello_done   = 14,
    certificate_verify  = 15, 
    client_key_exchange = 16,
    finished            = 20
};


/* Valid Alert types from page 16/17 */
enum AlertDescription {
    close_notify            = 0,
    unexpected_message      = 10,
    bad_record_mac          = 20,
    decompression_failure   = 30,
    handshake_failure       = 40,
    no_certificate          = 41,
    bad_certificate         = 42,
    unsupported_certificate = 43,
    certificate_revoked     = 44,
    certificate_expired     = 45,
    certificate_unknown     = 46,
    illegal_parameter       = 47,
    decrypt_error           = 51,
    protocol_version        = 70,
    no_renegotiation        = 100,
    unrecognized_name       = 112
};


enum AlertLevel { 
    alert_warning = 1, 
    alert_fatal = 2
};


static const byte client[SIZEOF_SENDER] = { 0x43, 0x4C, 0x4E, 0x54 };
static const byte server[SIZEOF_SENDER] = { 0x53, 0x52, 0x56, 0x52 };

static const byte tls_client[FINISHED_LABEL_SZ + 1] = "client finished";
static const byte tls_server[FINISHED_LABEL_SZ + 1] = "server finished";


/* internal functions */
CYASSL_LOCAL int SendChangeCipher(CYASSL*);
CYASSL_LOCAL int SendData(CYASSL*, const void*, int);
CYASSL_LOCAL int SendCertificate(CYASSL*);
CYASSL_LOCAL int SendCertificateRequest(CYASSL*);
CYASSL_LOCAL int SendServerKeyExchange(CYASSL*);
CYASSL_LOCAL int SendBuffered(CYASSL*);
CYASSL_LOCAL int ReceiveData(CYASSL*, byte*, int, int);
CYASSL_LOCAL int SendFinished(CYASSL*);
CYASSL_LOCAL int SendAlert(CYASSL*, int, int);
CYASSL_LOCAL int ProcessReply(CYASSL*);

CYASSL_LOCAL int SetCipherSpecs(CYASSL*);
CYASSL_LOCAL int MakeMasterSecret(CYASSL*);

CYASSL_LOCAL int  AddSession(CYASSL*);
CYASSL_LOCAL int  DeriveKeys(CYASSL* ssl);
CYASSL_LOCAL int  StoreKeys(CYASSL* ssl, const byte* keyData);

CYASSL_LOCAL int IsTLS(const CYASSL* ssl);
CYASSL_LOCAL int IsAtLeastTLSv1_2(const CYASSL* ssl);

CYASSL_LOCAL void FreeHandshakeResources(CYASSL* ssl);
CYASSL_LOCAL void ShrinkInputBuffer(CYASSL* ssl, int forcedFree);
CYASSL_LOCAL void ShrinkOutputBuffer(CYASSL* ssl);
#ifndef NO_CERTS
    CYASSL_LOCAL Signer* GetCA(void* cm, byte* hash);
    #ifndef NO_SKID
        CYASSL_LOCAL Signer* GetCAByName(void* cm, byte* hash);
    #endif
#endif
CYASSL_LOCAL void BuildTlsFinished(CYASSL* ssl, Hashes* hashes,
                                   const byte* sender);
CYASSL_LOCAL void FreeArrays(CYASSL* ssl, int keep);
CYASSL_LOCAL  int CheckAvailableSize(CYASSL *ssl, int size);
CYASSL_LOCAL  int GrowInputBuffer(CYASSL* ssl, int size, int usedLength);

#ifndef NO_TLS
    CYASSL_LOCAL int  MakeTlsMasterSecret(CYASSL*);
    CYASSL_LOCAL void TLS_hmac(CYASSL* ssl, byte* digest, const byte* in,
                               word32 sz, int content, int verify);
#endif

#ifndef NO_CYASSL_CLIENT
    CYASSL_LOCAL int SendClientHello(CYASSL*);
    CYASSL_LOCAL int SendClientKeyExchange(CYASSL*);
    CYASSL_LOCAL int SendCertificateVerify(CYASSL*);
#endif /* NO_CYASSL_CLIENT */

#ifndef NO_CYASSL_SERVER
    CYASSL_LOCAL int SendServerHello(CYASSL*);
    CYASSL_LOCAL int SendServerHelloDone(CYASSL*);
    #ifdef CYASSL_DTLS
        CYASSL_LOCAL int SendHelloVerifyRequest(CYASSL*);
    #endif
#endif /* NO_CYASSL_SERVER */

#ifdef CYASSL_DTLS
    CYASSL_LOCAL int  DtlsPoolInit(CYASSL*);
    CYASSL_LOCAL int  DtlsPoolSave(CYASSL*, const byte*, int);
    CYASSL_LOCAL int  DtlsPoolTimeout(CYASSL*);
    CYASSL_LOCAL int  DtlsPoolSend(CYASSL*);
    CYASSL_LOCAL void DtlsPoolReset(CYASSL*);

    CYASSL_LOCAL DtlsMsg* DtlsMsgNew(word32, void*);
    CYASSL_LOCAL void DtlsMsgDelete(DtlsMsg*, void*);
    CYASSL_LOCAL void DtlsMsgListDelete(DtlsMsg*, void*);
    CYASSL_LOCAL void DtlsMsgSet(DtlsMsg*, word32, const byte*, byte,
                                                             word32, word32);
    CYASSL_LOCAL DtlsMsg* DtlsMsgFind(DtlsMsg*, word32);
    CYASSL_LOCAL DtlsMsg* DtlsMsgStore(DtlsMsg*, word32, const byte*, word32,
                                                byte, word32, word32, void*);
    CYASSL_LOCAL DtlsMsg* DtlsMsgInsert(DtlsMsg*, DtlsMsg*);
#endif /* CYASSL_DTLS */

#ifndef NO_TLS
    

#endif /* NO_TLS */


CYASSL_LOCAL word32  LowResTimer(void);

CYASSL_LOCAL void InitX509(CYASSL_X509*, int);
CYASSL_LOCAL void FreeX509(CYASSL_X509*);
#ifndef NO_CERTS
    CYASSL_LOCAL int  CopyDecodedToX509(CYASSL_X509*, DecodedCert*);
#endif


#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* CyaSSL_INT_H */

